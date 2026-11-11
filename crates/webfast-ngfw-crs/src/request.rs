//! The request as ModSecurity's variables see it: the head's (method, line, path, query
//! arguments, headers, cookies) made when the request comes, the body's (arguments of a form, a
//! JSON document or a multipart body, its files and part headers, `REQUEST_BODY`) when it is read,
//! by the body processor phase 1 left in place. Names and values are as sent but for the
//! arguments, whose names and values are URL-decoded (`+` a space) as ModSecurity's are.

use bytes::Bytes;
use std::net::IpAddr;

/// A name and its value.
#[derive(Debug, Clone)]
pub struct Pair {
    pub name: String,
    pub value: Vec<u8>,
}

#[derive(Debug, Default)]
pub struct Request {
    pub method: Vec<u8>,
    pub protocol: Vec<u8>,
    /// Path and query, as sent.
    pub uri: Vec<u8>,
    /// The request target as sent (with a scheme and host when it had them).
    pub uri_raw: Vec<u8>,
    pub line: Vec<u8>,
    /// The path, percent-decoded (as ModSecurity's `REQUEST_FILENAME`; `REQUEST_URI` keeps it as
    /// sent).
    pub filename: Vec<u8>,
    pub basename: Vec<u8>,
    pub query: Vec<u8>,
    pub headers: Vec<Pair>,
    pub cookies: Vec<Pair>,
    pub args_get: Vec<Pair>,
    pub args_post: Vec<Pair>,
    pub files: Vec<Pair>,
    pub files_sizes: Vec<Pair>,
    pub multipart_headers: Vec<Pair>,
    /// `REQUEST_BODY` (none for a multipart body, as ModSecurity's).
    pub body: Option<Bytes>,
    pub body_length: usize,
    pub remote_addr: Vec<u8>,
    pub server_name: Vec<u8>,
    /// `REQBODY_ERROR`: the body did not parse as its processor's.
    pub body_error: bool,
    /// An XML body (the `XML` processor): `XML:/*`, the document's text, and `XML://@*`, its
    /// attributes' values.
    pub xml_text: Option<Vec<u8>>,
    pub xml_attrs: Vec<Vec<u8>>,
}

/// The body processor ModSecurity's recommended configuration picks for a Content-Type.
pub fn processor_of(content_type: &[u8]) -> Option<&'static str> {
    let media = content_type.split(|&b| b == b';').next().unwrap_or(b"");
    let media = media.trim_ascii().to_ascii_lowercase();
    match media.as_slice() {
        b"application/x-www-form-urlencoded" => Some("URLENCODED"),
        b"multipart/form-data" => Some("MULTIPART"),
        b"application/json" => Some("JSON"),
        m if m.ends_with(b"/xml") || m.ends_with(b"+xml") => Some("XML"),
        _ => None,
    }
}

impl Request {
    pub fn head(parts: &http::request::Parts, ip: IpAddr) -> Request {
        let method = parts.method.as_str().as_bytes().to_vec();
        let protocol = match parts.version {
            http::Version::HTTP_09 => "HTTP/0.9",
            http::Version::HTTP_10 => "HTTP/1.0",
            http::Version::HTTP_2 => "HTTP/2.0",
            http::Version::HTTP_3 => "HTTP/3.0",
            _ => "HTTP/1.1",
        }
        .as_bytes()
        .to_vec();
        let path = parts.uri.path().as_bytes().to_vec();
        let query = parts.uri.query().unwrap_or("").as_bytes().to_vec();
        let uri = parts
            .uri
            .path_and_query()
            .map_or_else(|| path.clone(), |pq| pq.as_str().as_bytes().to_vec());
        let uri_raw = if parts.uri.scheme().is_some() {
            parts.uri.to_string().into_bytes()
        } else if parts.uri.path_and_query().is_none() {
            // CONNECT's authority form.
            parts.uri.to_string().into_bytes()
        } else {
            uri.clone()
        };
        let mut line = method.clone();
        line.push(b' ');
        line.extend_from_slice(&uri_raw);
        line.push(b' ');
        line.extend_from_slice(&protocol);
        let filename = percent_decode(&path);
        let basename = filename.rsplit(|&b| b == b'/').next().unwrap_or(b"").to_vec();
        let headers: Vec<Pair> = parts
            .headers
            .iter()
            .map(|(name, value)| Pair {
                name: name.as_str().to_string(),
                value: value.as_bytes().to_vec(),
            })
            .collect();
        let mut cookies = Vec::new();
        for value in parts.headers.get_all(http::header::COOKIE) {
            for piece in value.as_bytes().split(|&b| b == b';') {
                let piece = piece.trim_ascii();
                if piece.is_empty() {
                    continue;
                }
                let (name, value) = match piece.iter().position(|&b| b == b'=') {
                    Some(i) => (&piece[..i], &piece[i + 1..]),
                    None => (piece, &b""[..]),
                };
                cookies.push(Pair {
                    name: String::from_utf8_lossy(name.trim_ascii()).into_owned(),
                    value: value.to_vec(),
                });
            }
        }
        let server_name = parts
            .headers
            .get(http::header::HOST)
            .map(|h| h.as_bytes().to_vec())
            .or_else(|| parts.uri.host().map(|h| h.as_bytes().to_vec()))
            .unwrap_or_default();
        Request {
            args_get: url_pairs(&query),
            method,
            protocol,
            uri,
            uri_raw,
            line,
            filename,
            basename,
            query,
            headers,
            cookies,
            remote_addr: ip.to_string().into_bytes(),
            server_name,
            ..Request::default()
        }
    }

    /// The body read (`bytes`, possibly a prefix), parsed by `processor`. `REQUEST_BODY` is the
    /// body for `URLENCODED` and without a processor, and with `force` for the others but
    /// `MULTIPART` (`ctl:forceRequestBodyVariable`), as ModSecurity's.
    pub fn body(
        &mut self,
        bytes: &Bytes,
        processor: Option<&str>,
        content_type: &[u8],
        json_depth: usize,
        force: bool,
    ) {
        self.body_length = bytes.len();
        match processor {
            Some("URLENCODED") => {
                self.args_post = url_pairs(bytes);
                self.body = Some(bytes.clone());
            }
            Some("JSON") => {
                match serde_json::from_slice::<serde_json::Value>(bytes) {
                    Ok(value) => json_pairs(&value, "json", 0, json_depth, &mut self.args_post),
                    Err(_) => self.body_error = true,
                }
                if force {
                    self.body = Some(bytes.clone());
                }
            }
            Some("MULTIPART") => match boundary(content_type) {
                Some(boundary) => self.multipart(bytes, &boundary),
                None => self.body_error = true,
            },
            Some("XML") => {
                match xml(bytes) {
                    Some((text, attrs)) => {
                        self.xml_text = Some(text);
                        self.xml_attrs = attrs;
                    }
                    None => self.body_error = true,
                }
                if force {
                    self.body = Some(bytes.clone());
                }
            }
            _ => self.body = Some(bytes.clone()),
        }
    }

    fn multipart(&mut self, bytes: &[u8], boundary: &[u8]) {
        let mut delimiter = b"--".to_vec();
        delimiter.extend_from_slice(boundary);
        let Some(first) = find(bytes, &delimiter) else {
            self.body_error = true;
            return;
        };
        let mut at = first + delimiter.len();
        loop {
            // After a delimiter: `--` ends the body, else the line's end and a part.
            if bytes[at..].starts_with(b"--") {
                return;
            }
            let Some(eol) = find(&bytes[at..], b"\n") else { return };
            at += eol + 1;
            let head_end = match find(&bytes[at..], b"\r\n\r\n") {
                Some(i) => (i, 4),
                None => match find(&bytes[at..], b"\n\n") {
                    Some(i) => (i, 2),
                    None => return,
                },
            };
            let head = &bytes[at..at + head_end.0];
            let content_start = at + head_end.0 + head_end.1;
            let (content_end, next) = match find(&bytes[content_start..], &delimiter) {
                Some(i) => {
                    let at = content_start + i;
                    // The line break before the delimiter is the delimiter's: CRLF or LF alone.
                    let end = if bytes[content_start..at].ends_with(b"\r\n") {
                        at - 2
                    } else if bytes[content_start..at].ends_with(b"\n") {
                        at - 1
                    } else {
                        at
                    };
                    (end, at + delimiter.len())
                }
                // A prefix cut in the part: what there is of it.
                None => (bytes.len(), bytes.len()),
            };
            let content = &bytes[content_start..content_end.max(content_start)];
            let mut name = String::new();
            let mut filename = None;
            for line in head.split(|&b| b == b'\n') {
                let line = line.strip_suffix(b"\r").unwrap_or(line);
                if line.is_empty() {
                    continue;
                }
                let lower = line.to_ascii_lowercase();
                if lower.starts_with(b"content-disposition:") {
                    name = param(line, b"name")
                        .map(|v| String::from_utf8_lossy(&v).into_owned())
                        .unwrap_or_default();
                    filename = param(line, b"filename");
                }
                self.multipart_headers.push(Pair {
                    name: String::new(),
                    value: line.to_vec(),
                });
            }
            for pair in self.multipart_headers.iter_mut().rev() {
                if !pair.name.is_empty() {
                    break;
                }
                pair.name = name.clone();
            }
            match filename {
                Some(filename) => {
                    self.files.push(Pair {
                        name: name.clone(),
                        value: filename,
                    });
                    self.files_sizes.push(Pair {
                        name,
                        value: content.len().to_string().into_bytes(),
                    });
                }
                None => self.args_post.push(Pair {
                    name,
                    value: content.to_vec(),
                }),
            }
            if next >= bytes.len() {
                return;
            }
            at = next;
        }
    }
}

/// A `name=value&…` text into its pairs, each side URL-decoded with `+` a space.
pub fn url_pairs(text: &[u8]) -> Vec<Pair> {
    text.split(|&b| b == b'&')
        .filter(|p| !p.is_empty())
        .map(|p| {
            let (name, value) = match p.iter().position(|&b| b == b'=') {
                Some(i) => (&p[..i], &p[i + 1..]),
                None => (p, &b""[..]),
            };
            Pair {
                name: String::from_utf8_lossy(&url_decode(name)).into_owned(),
                value: url_decode(value),
            }
        })
        .collect()
}

/// `%XX` decoded, `+` left as it is (a path's).
fn percent_decode(text: &[u8]) -> Vec<u8> {
    if !text.contains(&b'%') {
        return text.to_vec();
    }
    let mut out = Vec::with_capacity(text.len());
    let mut i = 0;
    while i < text.len() {
        if text[i] == b'%' && i + 2 < text.len() && text[i + 1].is_ascii_hexdigit() && text[i + 2].is_ascii_hexdigit() {
            let h = |b: u8| (b as char).to_digit(16).unwrap_or(0) as u8;
            out.push(h(text[i + 1]) << 4 | h(text[i + 2]));
            i += 3;
        } else {
            out.push(text[i]);
            i += 1;
        }
    }
    out
}

fn url_decode(text: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(text.len());
    let mut i = 0;
    while i < text.len() {
        match text[i] {
            b'+' => out.push(b' '),
            b'%' if i + 2 < text.len() && text[i + 1].is_ascii_hexdigit() && text[i + 2].is_ascii_hexdigit() => {
                let h = |b: u8| (b as char).to_digit(16).unwrap_or(0) as u8;
                out.push(h(text[i + 1]) << 4 | h(text[i + 2]));
                i += 3;
                continue;
            }
            b => out.push(b),
        }
        i += 1;
    }
    out
}

/// A JSON document's leaves as `json.a.b` arguments; an array's items are named by the array
/// (`json.list`), as ModSecurity's JSON parser names them.
fn json_pairs(value: &serde_json::Value, prefix: &str, depth: usize, max: usize, out: &mut Vec<Pair>) {
    if depth > max {
        return;
    }
    match value {
        serde_json::Value::Object(map) => {
            for (k, v) in map {
                json_pairs(v, &format!("{prefix}.{k}"), depth + 1, max, out);
            }
        }
        serde_json::Value::Array(items) => {
            for v in items {
                json_pairs(v, prefix, depth + 1, max, out);
            }
        }
        serde_json::Value::String(s) => out.push(Pair {
            name: prefix.to_string(),
            value: s.as_bytes().to_vec(),
        }),
        serde_json::Value::Null => out.push(Pair {
            name: prefix.to_string(),
            value: Vec::new(),
        }),
        other => out.push(Pair {
            name: prefix.to_string(),
            value: other.to_string().into_bytes(),
        }),
    }
}

/// An XML document's text (the root element's string value: its text and CDATA, entities decoded)
/// and its attributes' values, by a scanner that reads tags, not a validating parser (no DTD, no
/// external entities); `None` when there is no element.
fn xml(bytes: &[u8]) -> Option<(Vec<u8>, Vec<Vec<u8>>)> {
    let mut text = Vec::new();
    let mut attrs = Vec::new();
    let mut depth = 0usize;
    let mut elements = 0usize;
    let mut i = 0;
    while i < bytes.len() {
        let Some(lt) = bytes[i..].iter().position(|&b| b == b'<') else {
            if depth > 0 {
                text.extend_from_slice(&entities(&bytes[i..]));
            }
            break;
        };
        if depth > 0 {
            text.extend_from_slice(&entities(&bytes[i..i + lt]));
        }
        i += lt;
        let rest = &bytes[i..];
        let skip_to = |end: &[u8]| find(rest, end).map(|k| k + end.len());
        if rest.starts_with(b"<?") {
            i += skip_to(b"?>").unwrap_or(rest.len());
        } else if rest.starts_with(b"<!--") {
            i += skip_to(b"-->").unwrap_or(rest.len());
        } else if rest.starts_with(b"<![CDATA[") {
            let end = find(rest, b"]]>").unwrap_or(rest.len());
            if depth > 0 {
                text.extend_from_slice(&rest[9..end.max(9)]);
            }
            i += (end + 3).min(rest.len());
        } else if rest.starts_with(b"<!") {
            i += skip_to(b">").unwrap_or(rest.len());
        } else if rest.starts_with(b"</") {
            depth = depth.saturating_sub(1);
            i += skip_to(b">").unwrap_or(rest.len());
        } else {
            // A start tag: its name, then `name="value"` attributes, `/>` or `>`.
            let mut j = 1;
            while j < rest.len() && !matches!(rest[j], b' ' | b'\t' | b'\r' | b'\n' | b'>' | b'/') {
                j += 1;
            }
            if j == 1 {
                // A lone `<`: text.
                if depth > 0 {
                    text.push(b'<');
                }
                i += 1;
                continue;
            }
            elements += 1;
            let mut closed = false;
            loop {
                while j < rest.len() && rest[j].is_ascii_whitespace() {
                    j += 1;
                }
                if j >= rest.len() {
                    break;
                }
                match rest[j] {
                    b'>' => {
                        j += 1;
                        break;
                    }
                    b'/' => {
                        closed = true;
                        j += 1;
                    }
                    _ => {
                        while j < rest.len() && !matches!(rest[j], b'=' | b'>' | b'/') && !rest[j].is_ascii_whitespace()
                        {
                            j += 1;
                        }
                        while j < rest.len() && rest[j].is_ascii_whitespace() {
                            j += 1;
                        }
                        if rest.get(j) != Some(&b'=') {
                            continue;
                        }
                        j += 1;
                        while j < rest.len() && rest[j].is_ascii_whitespace() {
                            j += 1;
                        }
                        if let Some(&q) = rest.get(j)
                            && (q == b'"' || q == b'\'')
                        {
                            let start = j + 1;
                            let end = rest[start..]
                                .iter()
                                .position(|&b| b == q)
                                .map_or(rest.len(), |k| start + k);
                            attrs.push(entities(&rest[start..end]));
                            j = (end + 1).min(rest.len());
                        }
                    }
                }
            }
            if !closed {
                depth += 1;
            }
            i += j;
        }
    }
    (elements > 0).then_some((text, attrs))
}

/// XML's entities decoded: the five named ones and character references.
fn entities(text: &[u8]) -> Vec<u8> {
    if !text.contains(&b'&') {
        return text.to_vec();
    }
    let mut out = Vec::with_capacity(text.len());
    let mut i = 0;
    while i < text.len() {
        if text[i] == b'&'
            && let Some(end) = text[i..].iter().take(12).position(|&b| b == b';')
        {
            let name = &text[i + 1..i + end];
            let decoded: Option<Vec<u8>> = match name {
                b"lt" => Some(b"<".to_vec()),
                b"gt" => Some(b">".to_vec()),
                b"amp" => Some(b"&".to_vec()),
                b"quot" => Some(b"\"".to_vec()),
                b"apos" => Some(b"'".to_vec()),
                _ if name.first() == Some(&b'#') => {
                    let digits = std::str::from_utf8(&name[1..]).ok();
                    let cp = digits.and_then(|d| match d.strip_prefix(['x', 'X']) {
                        Some(hex) => u32::from_str_radix(hex, 16).ok(),
                        None => d.parse().ok(),
                    });
                    cp.and_then(char::from_u32).map(|c| c.to_string().into_bytes())
                }
                _ => None,
            };
            if let Some(d) = decoded {
                out.extend_from_slice(&d);
                i += end + 1;
                continue;
            }
        }
        out.push(text[i]);
        i += 1;
    }
    out
}

/// The `boundary` parameter of a multipart Content-Type.
fn boundary(content_type: &[u8]) -> Option<Vec<u8>> {
    let b = param(content_type, b"boundary")?;
    (!b.is_empty()).then_some(b)
}

/// A header's `name=value` parameter (quoted or not); `name` not `filename` when looking for
/// `name`.
fn param(line: &[u8], name: &[u8]) -> Option<Vec<u8>> {
    let lower = line.to_ascii_lowercase();
    let mut from = 0;
    while let Some(i) = find(&lower[from..], name) {
        let at = from + i;
        let before_ok = at == 0 || matches!(lower[at - 1], b';' | b' ' | b'\t' | b':');
        let mut j = at + name.len();
        while j < line.len() && line[j] == b' ' {
            j += 1;
        }
        if before_ok && line.get(j) == Some(&b'=') {
            j += 1;
            while j < line.len() && line[j] == b' ' {
                j += 1;
            }
            if line.get(j) == Some(&b'"') {
                let rest = &line[j + 1..];
                let end = rest.iter().position(|&b| b == b'"').unwrap_or(rest.len());
                return Some(rest[..end].to_vec());
            }
            let rest = &line[j..];
            let end = rest.iter().position(|&b| b == b';').unwrap_or(rest.len());
            return Some(rest[..end].trim_ascii().to_vec());
        }
        from = at + 1;
    }
    None
}

fn find(hay: &[u8], needle: &[u8]) -> Option<usize> {
    memchr::memmem::find(hay, needle)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn head_variables() {
        let (parts, ()) = http::Request::get("/a/b.php?x=1+2&y=%27&z")
            .header("host", "example.com")
            .header("cookie", "a=1; b=2")
            .body(())
            .unwrap()
            .into_parts();
        let r = Request::head(&parts, "10.0.0.1".parse().unwrap());
        assert_eq!(r.line, b"GET /a/b.php?x=1+2&y=%27&z HTTP/1.1");
        assert_eq!(r.basename, b"b.php");
        assert_eq!(r.args_get.len(), 3);
        assert_eq!(r.args_get[0].value, b"1 2");
        assert_eq!(r.args_get[1].value, b"'");
        assert_eq!(r.cookies[1].name, "b");
        assert_eq!(r.server_name, b"example.com");
    }

    #[test]
    fn bodies() {
        let mut r = Request::default();
        r.body(&Bytes::from_static(b"a=1&b=%3c"), Some("URLENCODED"), b"", 20, false);
        assert_eq!(r.args_post[1].value, b"<");
        let mut r = Request::default();
        r.body(
            &Bytes::from_static(br#"{"a":{"b":"x"},"c":[1,null]}"#),
            Some("JSON"),
            b"",
            20,
            false,
        );
        let names: Vec<_> = r.args_post.iter().map(|p| p.name.as_str()).collect();
        assert_eq!(names, vec!["json.a.b", "json.c", "json.c"]);
        let body = b"--XX\r\nContent-Disposition: form-data; name=\"f\"; filename=\"a.php\"\r\nContent-Type: text/plain\r\n\r\n<?php\r\n--XX\r\nContent-Disposition: form-data; name=\"t\"\r\n\r\nhello\r\n--XX--\r\n";
        let mut r = Request::default();
        r.body(
            &Bytes::from_static(body),
            Some("MULTIPART"),
            b"multipart/form-data; boundary=XX",
            20,
            false,
        );
        assert_eq!(r.files[0].value, b"a.php");
        assert_eq!(r.files_sizes[0].value, b"5");
        assert_eq!(r.args_post[0].name, "t");
        assert_eq!(r.args_post[0].value, b"hello");
        assert_eq!(r.multipart_headers.len(), 3);
        assert_eq!(r.multipart_headers[1].name, "f");
        assert!(r.body.is_none());
        assert_eq!(processor_of(b"application/soap+xml; charset=utf-8"), Some("XML"));
        let mut r = Request::default();
        r.body(
            &Bytes::from_static(
                b"<?xml version=\"1.0\"?><!-- c --><root a='1 &lt; 2'><b x=\"y\">t&amp;u</b><![CDATA[<z>]]><c/></root>",
            ),
            Some("XML"),
            b"",
            20,
            false,
        );
        assert_eq!(r.xml_text.as_deref(), Some(&b"t&u<z>"[..]));
        assert_eq!(r.xml_attrs, vec![b"1 < 2".to_vec(), b"y".to_vec()]);
        let mut r = Request::default();
        r.body(&Bytes::from_static(b"not xml"), Some("XML"), b"", 20, false);
        assert!(r.body_error);
    }
}
