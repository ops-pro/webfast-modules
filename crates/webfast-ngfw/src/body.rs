//! The body for the `body` and `upload` phases: at most `max_inspect` bytes read from the stream
//! (whole frames, so nothing is copied unless the prefix spans several), parsed by type — a form
//! into its pairs, JSON into a value under a depth limit, multipart into its parts — and handed
//! on as the same frames followed by the rest of the stream. The same for a response's body in the
//! `response` phase.

use super::multipart::{self, Part};
use bytes::Bytes;
use http::HeaderMap;
use http_body::Frame;
use http_body_util::BodyExt;
use std::collections::VecDeque;
use std::pin::Pin;
use std::task::{Context, Poll};
use webfast_core::body::{Body, BoxError};

/// The start of a body, and the body to go on with (the same bytes).
pub struct Prefix {
    pub bytes: Bytes,
    /// The stream ended within the prefix.
    pub complete: bool,
    pub body: Body,
}

/// Reads frames of `body` until at least `max` bytes of data were seen, or the end.
pub async fn read_prefix(mut body: Body, max: usize) -> Result<Prefix, BoxError> {
    let mut frames: VecDeque<Frame<Bytes>> = VecDeque::new();
    let mut total = 0;
    let mut complete = false;
    loop {
        if total >= max {
            break;
        }
        match body.frame().await {
            Some(Ok(frame)) => {
                if let Some(data) = frame.data_ref() {
                    total += data.len();
                }
                frames.push_back(frame);
            }
            Some(Err(e)) => return Err(e),
            None => {
                complete = true;
                break;
            }
        }
    }
    let bytes = {
        let mut data = frames.iter().filter_map(Frame::data_ref);
        match (data.next(), data.next()) {
            (None, _) => Bytes::new(),
            (Some(only), None) => only.slice(..only.len().min(max)),
            (Some(first), Some(second)) => {
                let mut joined = Vec::with_capacity(total.min(max));
                for chunk in [first, second].into_iter().chain(data) {
                    let room = max - joined.len();
                    joined.extend_from_slice(&chunk[..chunk.len().min(room)]);
                    if joined.len() >= max {
                        break;
                    }
                }
                Bytes::from(joined)
            }
        }
    };
    let body = if complete && frames.len() <= 1 && frames.front().is_none_or(Frame::is_data) {
        webfast_core::body::full(frames.pop_front().and_then(|f| f.into_data().ok()).unwrap_or_default())
    } else {
        webfast_core::body::boxed(Chained {
            frames,
            rest: (!complete).then_some(body),
        })
    };
    Ok(Prefix { bytes, complete, body })
}

/// The frames read first, then the rest of the stream.
struct Chained {
    frames: VecDeque<Frame<Bytes>>,
    rest: Option<Body>,
}

impl http_body::Body for Chained {
    type Data = Bytes;
    type Error = BoxError;

    fn poll_frame(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Option<Result<Frame<Bytes>, BoxError>>> {
        if let Some(frame) = self.frames.pop_front() {
            return Poll::Ready(Some(Ok(frame)));
        }
        match self.rest.as_mut() {
            Some(rest) => Pin::new(rest).poll_frame(cx),
            None => Poll::Ready(None),
        }
    }

    fn is_end_stream(&self) -> bool {
        self.frames.is_empty() && self.rest.as_ref().is_none_or(http_body::Body::is_end_stream)
    }

    fn size_hint(&self) -> http_body::SizeHint {
        let held: u64 = self
            .frames
            .iter()
            .filter_map(Frame::data_ref)
            .map(|d| d.len() as u64)
            .sum();
        match &self.rest {
            Some(rest) => {
                let hint = rest.size_hint();
                let mut out = http_body::SizeHint::new();
                out.set_lower(hint.lower() + held);
                if let Some(upper) = hint.upper() {
                    out.set_upper(upper + held);
                }
                out
            }
            None => http_body::SizeHint::with_exact(held),
        }
    }
}

/// What kind of body the Content-Type declares, among those inspected.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Kind {
    Form,
    Json,
    Multipart {
        boundary: String,
    },
    /// XML and other text: the `body` target only.
    Text,
}

/// The Content-Type's media type, lowercased, without parameters.
pub fn media_type(headers: &HeaderMap) -> Option<String> {
    let value = headers.get(http::header::CONTENT_TYPE)?.to_str().ok()?;
    Some(value.split(';').next().unwrap_or("").trim().to_ascii_lowercase())
}

/// The kind of a body whose type is one of `types`; `None`: not inspected.
pub fn kind_of(headers: &HeaderMap, types: &[String]) -> Option<Kind> {
    let media = media_type(headers)?;
    if !types.iter().any(|t| t.eq_ignore_ascii_case(&media)) {
        return None;
    }
    Some(match media.as_str() {
        "application/x-www-form-urlencoded" => Kind::Form,
        "application/json" => Kind::Json,
        "multipart/form-data" => Kind::Multipart {
            boundary: multipart::boundary(headers.get(http::header::CONTENT_TYPE)?)?,
        },
        other if other.ends_with("+json") => Kind::Json,
        _ => Kind::Text,
    })
}

/// The inspected body, parsed.
pub struct BodyData {
    pub bytes: Bytes,
    text: Text,
    pub valid_utf8: bool,
    pub kind: Kind,
    /// A form's pairs, decoded into one buffer: the name fully, the value as sent but for `+` as
    /// a space (the rules' `url_decode` does the rest); `pairs` holds each pair's ranges in it.
    decoded: String,
    pairs: Vec<Pair>,
    pub json: Option<serde_json::Value>,
    /// Declared JSON, and not JSON.
    pub json_invalid: bool,
    pub json_too_deep: bool,
    /// Multipart: the parts seen in the prefix (one more than `max_parts` at most).
    pub parts: Vec<Part>,
    /// Multipart with no boundary line in the prefix.
    pub multipart_invalid: bool,
    pub complete: bool,
}

/// The `body` target's text: the bytes themselves when they are UTF-8, a lossy copy when not,
/// none for a multipart body (its parts are the `upload` targets; the file bytes are not text).
enum Text {
    Bytes,
    Lossy(String),
    None,
}

/// A form pair's name and value, as ranges in `BodyData::decoded`: the name is
/// `name_start..value_start`, the value `value_start..end`.
#[derive(Clone, Copy)]
struct Pair {
    name_start: u32,
    value_start: u32,
    end: u32,
}

/// Limits of the parsing (from the configuration).
pub struct Limits {
    pub json_max_depth: usize,
    pub multipart_max_parts: usize,
    pub upload_head: usize,
}

/// The nesting depth of a JSON text, counted over its brackets outside strings.
pub fn json_depth(bytes: &[u8]) -> usize {
    let (mut depth, mut deepest) = (0usize, 0usize);
    let mut in_string = false;
    let mut escaped = false;
    for &b in bytes {
        if in_string {
            match b {
                _ if escaped => escaped = false,
                b'\\' => escaped = true,
                b'"' => in_string = false,
                _ => {}
            }
            continue;
        }
        match b {
            b'"' => in_string = true,
            b'{' | b'[' => {
                depth += 1;
                deepest = deepest.max(depth);
            }
            b'}' | b']' => depth = depth.saturating_sub(1),
            _ => {}
        }
    }
    deepest
}

/// A form body's pairs in one pass: each name with its percent-escapes and `+` decoded, each
/// value with `+` as a space; an empty piece (`a=1&&b`) is no pair.
fn parse_form(body: &[u8]) -> (String, Vec<Pair>) {
    // Built as bytes: a value is copied up to its `&` and its `+` turned to spaces in place; a
    // name is decoded byte by byte. Each is checked to be UTF-8 (read lossily when not), so the
    // whole is at the end, and the ranges hold.
    let mut decoded: Vec<u8> = Vec::with_capacity(body.len());
    let mut pairs = Vec::with_capacity(body.len() / 16 + 1);
    let valid = std::str::from_utf8(body).is_ok();
    let mut name: Vec<u8> = Vec::new();
    let next = |from: usize, special: fn(u8) -> bool| {
        from + body[from..]
            .iter()
            .position(|&b| special(b))
            .unwrap_or(body.len() - from)
    };
    let mut i = 0;
    while i < body.len() {
        let name_start = decoded.len() as u32;
        name.clear();
        let mut has_value = false;
        while i < body.len() {
            let run = next(i, |b| matches!(b, b'&' | b'=' | b'%' | b'+'));
            name.extend_from_slice(&body[i..run]);
            i = run;
            if i == body.len() {
                break;
            }
            match body[i] {
                b'&' => break,
                b'=' => {
                    has_value = true;
                    i += 1;
                    break;
                }
                b'%' if i + 2 < body.len()
                    && let (Some(hi), Some(lo)) =
                        ((body[i + 1] as char).to_digit(16), (body[i + 2] as char).to_digit(16)) =>
                {
                    name.push((hi * 16 + lo) as u8);
                    i += 3;
                }
                b'+' => {
                    name.push(b' ');
                    i += 1;
                }
                b => {
                    name.push(b);
                    i += 1;
                }
            }
        }
        if name.is_empty() && !has_value {
            // An empty piece: `&&`, or a trailing `&`.
            i += 1;
            continue;
        }
        push_lossy_bytes(&name, &mut decoded);
        let value_start = decoded.len();
        let end = next(i, |b| b == b'&');
        if valid {
            decoded.extend_from_slice(&body[i..end]);
        } else {
            push_lossy_bytes(&body[i..end], &mut decoded);
        }
        for b in &mut decoded[value_start..] {
            if *b == b'+' {
                *b = b' ';
            }
        }
        pairs.push(Pair {
            name_start,
            value_start: value_start as u32,
            end: decoded.len() as u32,
        });
        i = end + 1;
    }
    match String::from_utf8(decoded) {
        Ok(decoded) => (decoded, pairs),
        // Not reached: every piece was checked. Nothing rather than ranges that do not hold.
        Err(_) => (String::new(), Vec::new()),
    }
}

/// `bytes` appended to `out` as UTF-8: as they are when valid, else with invalid sequences as
/// U+FFFD.
fn push_lossy_bytes(bytes: &[u8], out: &mut Vec<u8>) {
    if std::str::from_utf8(bytes).is_ok() {
        out.extend_from_slice(bytes);
        return;
    }
    for chunk in bytes.utf8_chunks() {
        out.extend_from_slice(chunk.valid().as_bytes());
        if !chunk.invalid().is_empty() {
            out.extend_from_slice(char::REPLACEMENT_CHARACTER.encode_utf8(&mut [0; 4]).as_bytes());
        }
    }
}

impl BodyData {
    pub async fn parse(bytes: Bytes, kind: Kind, complete: bool, limits: &Limits) -> BodyData {
        // A form is its pairs (the `args` targets), a multipart body its parts (the `upload`
        // targets): neither is a text for the `body` target.
        let parsed = matches!(kind, Kind::Multipart { .. } | Kind::Form);
        let valid_utf8 = std::str::from_utf8(&bytes).is_ok();
        let text = match (parsed, valid_utf8) {
            (true, _) => Text::None,
            (false, true) => Text::Bytes,
            (false, false) => Text::Lossy(String::from_utf8_lossy(&bytes).into_owned()),
        };
        let mut data = BodyData {
            bytes,
            text,
            valid_utf8,
            kind: kind.clone(),
            decoded: String::new(),
            pairs: Vec::new(),
            json: None,
            json_invalid: false,
            json_too_deep: false,
            parts: Vec::new(),
            multipart_invalid: false,
            complete,
        };
        match kind {
            Kind::Form => (data.decoded, data.pairs) = parse_form(&data.bytes),
            Kind::Json => {
                if json_depth(&data.bytes) > limits.json_max_depth {
                    data.json_too_deep = true;
                } else {
                    match serde_json::from_slice(&data.bytes) {
                        Ok(value) => data.json = Some(value),
                        // A prefix cut short is not a broken document.
                        Err(_) if !complete => {}
                        Err(_) => data.json_invalid = true,
                    }
                }
            }
            Kind::Multipart { boundary } => {
                match multipart::parts(
                    &boundary,
                    data.bytes.clone(),
                    limits.multipart_max_parts + 1,
                    limits.upload_head,
                )
                .await
                {
                    Ok(parts) => data.parts = parts,
                    Err(_) => data.multipart_invalid = true,
                }
            }
            Kind::Text => {}
        }
        data
    }

    /// The `body` target: the inspected bytes as text; none for a form or multipart body.
    pub fn text(&self) -> Option<&str> {
        match &self.text {
            // Validated when parsed.
            Text::Bytes => std::str::from_utf8(&self.bytes).ok(),
            Text::Lossy(text) => Some(text),
            Text::None => None,
        }
    }

    /// A form's pairs, name and value.
    pub fn form(&self) -> impl Iterator<Item = (&str, &str)> + '_ {
        self.pairs.iter().map(|p| {
            (
                &self.decoded[p.name_start as usize..p.value_start as usize],
                &self.decoded[p.value_start as usize..p.end as usize],
            )
        })
    }

    pub fn form_len(&self) -> usize {
        self.pairs.len()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::convert::Infallible;

    fn stream(chunks: &[&'static str]) -> Body {
        let frames: Vec<Result<Frame<Bytes>, Infallible>> = chunks
            .iter()
            .map(|c| Ok(Frame::data(Bytes::from_static(c.as_bytes()))))
            .collect();
        webfast_core::body::boxed(http_body_util::StreamBody::new(tokio_stream::iter(frames)))
    }

    #[tokio::test]
    async fn the_prefix_is_read_once_and_the_body_goes_on_whole() {
        let prefix = read_prefix(stream(&["abc", "def", "ghi", "jkl"]), 5).await.unwrap();
        assert_eq!(&prefix.bytes[..], b"abcde", "cut to the limit over two frames");
        assert!(!prefix.complete);
        assert_eq!(&prefix.body.collect().await.unwrap().to_bytes()[..], b"abcdefghijkl");

        let prefix = read_prefix(stream(&["abc"]), 64).await.unwrap();
        assert_eq!(&prefix.bytes[..], b"abc");
        assert!(prefix.complete);
        assert_eq!(http_body::Body::size_hint(&prefix.body).exact(), Some(3));
        assert_eq!(&prefix.body.collect().await.unwrap().to_bytes()[..], b"abc");

        let prefix = read_prefix(webfast_core::body::empty(), 64).await.unwrap();
        assert!(prefix.bytes.is_empty() && prefix.complete);
        assert!(http_body::Body::is_end_stream(&prefix.body));

        let prefix = read_prefix(stream(&["abcdefgh", "ij"]), 4).await.unwrap();
        assert_eq!(&prefix.bytes[..], b"abcd", "one frame, sliced without a copy");
        assert_eq!(http_body::Body::size_hint(&prefix.body).lower(), 8);
        assert_eq!(&prefix.body.collect().await.unwrap().to_bytes()[..], b"abcdefghij");
    }

    fn headers(content_type: &str) -> HeaderMap {
        let mut headers = HeaderMap::new();
        headers.insert(http::header::CONTENT_TYPE, content_type.parse().unwrap());
        headers
    }

    fn limits() -> Limits {
        Limits {
            json_max_depth: 3,
            multipart_max_parts: 4,
            upload_head: 8,
        }
    }

    #[tokio::test]
    async fn bodies_are_parsed_by_their_declared_type() {
        let types = super::super::config::BodyConfig::default().types;
        assert_eq!(
            kind_of(&headers("application/JSON; charset=utf-8"), &types),
            Some(Kind::Json)
        );
        assert_eq!(kind_of(&headers("text/xml"), &types), Some(Kind::Text));
        assert_eq!(kind_of(&headers("image/png"), &types), None);
        assert_eq!(kind_of(&HeaderMap::new(), &types), None);
        assert_eq!(
            kind_of(&headers("multipart/form-data; boundary=XX"), &types),
            Some(Kind::Multipart { boundary: "XX".into() })
        );

        let form = BodyData::parse(
            Bytes::from_static(b"a=1+2&&b%3Dc=x%27&d&e+f%ff=+g+&=z&"),
            Kind::Form,
            false,
            &limits(),
        )
        .await;
        assert_eq!(
            form.form().collect::<Vec<_>>(),
            [
                ("a", "1 2"),
                ("b=c", "x%27"),
                ("d", ""),
                ("e f\u{FFFD}", " g "),
                ("", "z")
            ]
        );
        assert_eq!(form.form_len(), 5);
        assert!(form.text().is_none(), "a form is its pairs, not a text");
        assert_eq!(
            BodyData::parse(Bytes::from_static(b"<a/>"), Kind::Text, true, &limits())
                .await
                .text(),
            Some("<a/>")
        );

        let json = BodyData::parse(
            Bytes::from_static(br#"{"user":{"name":"x\"y"}}"#),
            Kind::Json,
            true,
            &limits(),
        )
        .await;
        assert_eq!(json.json.as_ref().unwrap().pointer("/user/name").unwrap(), "x\"y");
        assert!(!json.json_invalid && !json.json_too_deep);
        let deep = BodyData::parse(Bytes::from_static(b"[[[[1]]]]"), Kind::Json, true, &limits()).await;
        assert!(deep.json_too_deep && deep.json.is_none());
        assert_eq!(json_depth(br#"{"a":"[[[","b":[1,{"c":2}]}"#), 3);
        let bad = BodyData::parse(Bytes::from_static(b"<html>"), Kind::Json, true, &limits()).await;
        assert!(bad.json_invalid);
        let cut = BodyData::parse(Bytes::from_static(b"{\"a\":\"long"), Kind::Json, false, &limits()).await;
        assert!(!cut.json_invalid, "a prefix cut mid-document is not invalid");

        let body = b"--XX\r\nContent-Disposition: form-data; name=\"f\"; filename=\"a.php.jpg\"\r\nContent-Type: image/jpeg\r\n\r\n<?php echo 1; ?>\r\n--XX--\r\n";
        let multipart = BodyData::parse(
            Bytes::from_static(body),
            Kind::Multipart { boundary: "XX".into() },
            true,
            &limits(),
        )
        .await;
        assert_eq!(multipart.parts.len(), 1);
        assert_eq!(multipart.parts[0].filename.as_deref(), Some("a.php.jpg"));
        assert_eq!(&multipart.parts[0].head[..], b"<?php ec");
        assert!(
            multipart.text().is_none() && multipart.valid_utf8,
            "a multipart body is its parts, not a text"
        );
        let invalid = BodyData::parse(Bytes::from_static(b"\xff\xfe"), Kind::Text, true, &limits()).await;
        assert!(!invalid.valid_utf8);
        assert_eq!(invalid.text(), Some("\u{FFFD}\u{FFFD}"));
    }
}
