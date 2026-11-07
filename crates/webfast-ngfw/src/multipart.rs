//! The parts of a multipart body's inspected prefix (the `upload` phase, docs/ngfw.md): for each
//! part its name, file name, declared type, the first bytes and the size seen. Parsed here, in one
//! pass over the prefix: the boundary lines found, each part's few headers read, its data skipped
//! to the next boundary line; the head is a slice of the prefix. (multer did this before, at some
//! microseconds and dozens of allocations for a small upload.)
//!
//! The prefix is `body.max_inspect` bytes at most and may end anywhere: inside a part's data, inside
//! its headers, inside a boundary line. `cut_in` says where, so the parts before the cut come out
//! whole and the one it falls in is marked incomplete (or, cut in its headers, left out). Whatever
//! ends at the cut is the cut, not an error.

use bytes::Bytes;
use http::HeaderValue;
use memchr::memchr;
use memchr::memmem::{find, rfind};

/// One part of a `multipart/form-data` body.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Part {
    /// The `name` of its Content-Disposition; empty when it has none.
    pub name: String,
    pub filename: Option<String>,
    /// Its Content-Type as declared (`image/png`), lowercased, parameters dropped.
    pub content_type: Option<String>,
    /// Its first `head` bytes, fewer when the part or the prefix ended first.
    pub head: Bytes,
    /// Bytes of its data within the prefix.
    pub size: usize,
    /// Whether the prefix holds the whole part; `false` when the prefix was cut inside it.
    pub complete: bool,
}

/// The boundary of a `multipart/form-data` Content-Type: `multipart/form-data; boundary=...`, the
/// value quoted or not, the names in any case. `None` for any other type or a type without one.
pub fn boundary(content_type: &HeaderValue) -> Option<String> {
    let text = content_type.to_str().ok()?;
    let (media_type, parameters) = text.split_once(';')?;
    if !media_type.trim().eq_ignore_ascii_case("multipart/form-data") {
        return None;
    }
    for parameter in parameters.split(';') {
        let Some((name, value)) = parameter.split_once('=') else {
            continue;
        };
        if !name.trim().eq_ignore_ascii_case("boundary") {
            continue;
        }
        let value = value.trim();
        let value = match value.strip_prefix('"') {
            Some(quoted) => quoted.strip_suffix('"')?,
            None => value,
        };
        // RFC 2046: 1 to 70 characters of bchars; the last is not a space.
        let valid = (1..=70).contains(&value.len())
            && !value.ends_with(' ')
            && value
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || b"'()+_,-./:=? ".contains(&b));
        return valid.then(|| value.to_string());
    }
    None
}

/// The parts of `prefix` (the inspected start of a body, perhaps cut mid-part), at most
/// `max_parts`, each with its first `head` bytes. A prefix that is not multipart with this boundary
/// (no boundary line, a malformed header) is an error; a prefix that merely ends early is not.
pub async fn parts(boundary: &str, prefix: Bytes, max_parts: usize, head: usize) -> anyhow::Result<Vec<Part>> {
    let mut parts = Vec::new();
    if max_parts == 0 || prefix.is_empty() {
        return Ok(parts);
    }
    let (cut, keep) = cut_in(boundary, &prefix)?;
    let body = &prefix[..keep];
    let delimiter = format!("--{boundary}");
    let delimiter = delimiter.as_bytes();
    let Some(first) = boundary_line(body, delimiter, 0) else {
        // Cut inside the first boundary line (`cut_in` saw the start of one).
        return Ok(parts);
    };
    let mut pos = first + delimiter.len();
    loop {
        // After the delimiter: `--` closes the body, else the line ends and the headers follow.
        if body[pos..].starts_with(b"--") {
            break;
        }
        if !body[pos..].starts_with(b"\r\n") {
            if cut != Cut::No {
                break;
            }
            anyhow::bail!("the multipart body: a boundary line does not end");
        }
        pos += 2;
        let Some(headers_end) = find(&body[pos..], b"\r\n\r\n") else {
            if cut != Cut::No {
                break;
            }
            anyhow::bail!("the multipart body: a part's headers do not end");
        };
        let mut part = Part {
            name: String::new(),
            filename: None,
            content_type: None,
            head: Bytes::new(),
            size: 0,
            complete: true,
        };
        for line in body[pos..pos + headers_end].split(|&b| b == b'\n') {
            let line = line.strip_suffix(b"\r").unwrap_or(line);
            if line.is_empty() {
                continue;
            }
            let Some(colon) = line.iter().position(|&b| b == b':') else {
                anyhow::bail!("the multipart body: a part header without a colon");
            };
            let name = &line[..colon];
            let value = String::from_utf8_lossy(&line[colon + 1..]);
            if name.eq_ignore_ascii_case(b"content-disposition") {
                for parameter in value.split(';').skip(1) {
                    let Some((key, text)) = parameter.split_once('=') else {
                        continue;
                    };
                    let text = text.trim().trim_matches('"').to_string();
                    match key.trim().to_ascii_lowercase().as_str() {
                        "name" => part.name = text,
                        "filename" => part.filename = Some(text),
                        _ => {}
                    }
                }
            } else if name.eq_ignore_ascii_case(b"content-type") {
                part.content_type = Some(value.split(';').next().unwrap_or("").trim().to_ascii_lowercase());
            }
        }
        pos += headers_end + 4;
        // The data runs to the CRLF before the next boundary line; without one it ends at the
        // cut: inside the data (incomplete), or right after it, in the boundary line.
        let (data_end, next) = match boundary_line(body, delimiter, pos) {
            Some(at) => (at - 2, Some(at + delimiter.len())),
            None => {
                part.complete = cut == Cut::InDelimiter;
                (body.len(), None)
            }
        };
        part.size = data_end - pos;
        part.head = prefix.slice(pos..pos + head.min(part.size));
        parts.push(part);
        match next {
            Some(next) if parts.len() < max_parts => pos = next,
            _ => break,
        }
    }
    Ok(parts)
}

/// The next boundary line from `from`: the delimiter at the start of the body or after a CRLF.
fn boundary_line(body: &[u8], delimiter: &[u8], from: usize) -> Option<usize> {
    let mut at = from;
    while at < body.len() {
        at += memchr(b'-', &body[at..])?;
        if body[at..].starts_with(delimiter) && (at == 0 || body[..at].ends_with(b"\r\n")) {
            return Some(at);
        }
        at += 1;
    }
    None
}

/// Where the prefix ends.
#[derive(Clone, Copy, PartialEq, Eq)]
enum Cut {
    /// With the closing boundary: the whole body.
    No,
    /// Inside a part's data: the last part is incomplete.
    InData,
    /// Inside a boundary line or a part's headers: the parts before it are whole, the cut one is
    /// not there yet.
    InDelimiter,
}

/// Where `prefix` is cut, by the text after its last boundary line, and how much of it to keep
/// before the synthetic closing boundary: all of it, or, when it ends in the first bytes of a
/// boundary line, the data before that line. A prefix with no boundary line that is not the start
/// of one is not a body with this boundary: an error.
fn cut_in(boundary: &str, prefix: &[u8]) -> anyhow::Result<(Cut, usize)> {
    let delimiter = format!("--{boundary}");
    let delimiter = delimiter.as_bytes();
    // The last boundary line: `--boundary` at the start or after a CRLF.
    let mut from = prefix.len();
    let last = loop {
        let Some(at) = rfind(&prefix[..from], delimiter) else {
            if delimiter.starts_with(prefix) {
                // Cut inside the first boundary line.
                return Ok((Cut::InDelimiter, 0));
            }
            anyhow::bail!("the multipart body has no boundary line");
        };
        if at == 0 || prefix[..at].ends_with(b"\r\n") {
            break at;
        }
        from = at;
    };
    let after = &prefix[last + delimiter.len()..];
    if after.starts_with(b"--") {
        return Ok((Cut::No, prefix.len()));
    }
    // The part's headers end at the first empty line; data follows.
    let Some(headers_end) = find(after, b"\r\n\r\n") else {
        return Ok((Cut::InDelimiter, prefix.len()));
    };
    let data_start = last + delimiter.len() + headers_end + 4;
    let data = &prefix[data_start..];
    if let Some(crlf) = rfind(data, b"\r\n") {
        let rest = &data[crlf + 2..];
        let boundary_line = (!rest.is_empty() && delimiter.starts_with(rest)) || rest.starts_with(delimiter);
        if boundary_line {
            // The data ended; the boundary line after it is cut.
            return Ok((Cut::InDelimiter, data_start + crlf));
        }
    }
    Ok((Cut::InData, prefix.len()))
}

#[cfg(test)]
mod tests {
    use super::*;

    const BOUNDARY: &str = "----WebKitFormBoundary7MA4YWxkTrZu0gW";

    fn body() -> Vec<u8> {
        let mut body = Vec::new();
        for (headers, data) in [
            (
                "Content-Disposition: form-data; name=\"title\"\r\n",
                b"Holiday".as_slice(),
            ),
            (
                "Content-Disposition: form-data; name=\"photo\"; filename=\"shot.php.jpg\"\r\nContent-Type: image/jpeg\r\n",
                b"\xff\xd8\xff\xe0JFIF and then a lot of picture bytes".as_slice(),
            ),
            (
                "Content-Disposition: form-data; name=\"doc\"; filename=\"notes.txt\"\r\nContent-Type: text/plain; charset=utf-8\r\n",
                b"line one\r\nline two\r\n".as_slice(),
            ),
        ] {
            body.extend_from_slice(format!("--{BOUNDARY}\r\n{headers}\r\n").as_bytes());
            body.extend_from_slice(data);
            body.extend_from_slice(b"\r\n");
        }
        body.extend_from_slice(format!("--{BOUNDARY}--\r\n").as_bytes());
        body
    }

    fn run(boundary: &str, prefix: &[u8], max_parts: usize, head: usize) -> anyhow::Result<Vec<Part>> {
        tokio::runtime::Builder::new_current_thread()
            .build()
            .unwrap()
            .block_on(parts(boundary, Bytes::copy_from_slice(prefix), max_parts, head))
    }

    #[test]
    fn two_files_and_a_text_field() {
        let parts = run(BOUNDARY, &body(), 64, 4096).unwrap();
        assert_eq!(parts.len(), 3);
        assert_eq!(parts[0].name, "title");
        assert_eq!(parts[0].filename, None);
        assert_eq!(parts[0].content_type, None);
        assert_eq!(&parts[0].head[..], b"Holiday");
        assert_eq!(parts[0].size, 7);
        assert!(parts[0].complete);
        assert_eq!(parts[1].name, "photo");
        assert_eq!(parts[1].filename.as_deref(), Some("shot.php.jpg"));
        assert_eq!(parts[1].content_type.as_deref(), Some("image/jpeg"));
        assert!(parts[1].head.starts_with(b"\xff\xd8\xff\xe0JFIF"));
        assert_eq!(parts[1].size, parts[1].head.len());
        assert!(parts[1].complete);
        assert_eq!(parts[2].filename.as_deref(), Some("notes.txt"));
        assert_eq!(
            parts[2].content_type.as_deref(),
            Some("text/plain"),
            "parameters dropped"
        );
        assert_eq!(&parts[2].head[..], b"line one\r\nline two\r\n");
        assert!(parts[2].complete);
    }

    #[test]
    fn a_prefix_cut_mid_file() {
        let body = body();
        let cut = find(&body, b"picture bytes").unwrap() - 10;
        let parts = run(BOUNDARY, &body[..cut], 64, 4096).unwrap();
        assert_eq!(parts.len(), 2);
        assert!(parts[0].complete);
        assert_eq!(parts[1].name, "photo");
        assert!(!parts[1].complete, "cut inside the photo");
        assert!(parts[1].head.starts_with(b"\xff\xd8\xff\xe0JFIF"));
        assert_eq!(parts[1].size, parts[1].head.len());
        assert!(parts[1].size < 40);
    }

    #[test]
    fn a_prefix_cut_in_a_boundary_line_or_in_headers() {
        let body = body();
        // Right after the second part's data, inside the boundary line that ends it.
        let at = find(&body, b"picture bytes\r\n--").unwrap() + "picture bytes\r\n--".len() + 5;
        let parts = run(BOUNDARY, &body[..at], 64, 4096).unwrap();
        assert_eq!(parts.len(), 2);
        assert!(parts[1].complete, "the photo ended before the cut");
        // Inside the third part's headers.
        let at = find(&body, b"filename=\"notes").unwrap() + 3;
        let parts = run(BOUNDARY, &body[..at], 64, 4096).unwrap();
        assert_eq!(parts.len(), 2);
        assert!(parts[1].complete);
        // Exactly at the end of the second part's headers: a third part with no data yet.
        let at = find(&body, b"charset=utf-8\r\n\r\n").unwrap() + "charset=utf-8\r\n\r\n".len();
        let parts = run(BOUNDARY, &body[..at], 64, 4096).unwrap();
        assert_eq!(parts.len(), 3);
        assert_eq!(parts[2].size, 0);
        assert!(!parts[2].complete);
        // Inside the first boundary line: nothing yet.
        assert!(run(BOUNDARY, &body[..10], 64, 4096).unwrap().is_empty());
        // After the first boundary line and before its part's headers end: nothing yet.
        let at = find(&body, b"name=\"title\"").unwrap();
        assert!(run(BOUNDARY, &body[..at], 64, 4096).unwrap().is_empty());
    }

    #[test]
    fn a_part_over_head_and_the_part_limit() {
        let parts = run(BOUNDARY, &body(), 64, 8).unwrap();
        assert_eq!(&parts[1].head[..], b"\xff\xd8\xff\xe0JFIF");
        assert!(parts[1].size > 8, "the size is what was seen, the head what was kept");
        assert_eq!(&parts[0].head[..], b"Holiday", "a part under the head is whole");
        let parts = run(BOUNDARY, &body(), 2, 4096).unwrap();
        assert_eq!(parts.len(), 2, "stops at max_parts");
        assert!(run(BOUNDARY, &body(), 0, 4096).unwrap().is_empty());
        assert!(run(BOUNDARY, b"", 64, 4096).unwrap().is_empty());
    }

    #[test]
    fn boundaries_quoted_or_not() {
        let value = |text: &str| HeaderValue::from_str(text).unwrap();
        assert_eq!(
            boundary(&value("multipart/form-data; boundary=----WebKit7MA4")).as_deref(),
            Some("----WebKit7MA4")
        );
        assert_eq!(
            boundary(&value("Multipart/Form-Data; charset=utf-8; BOUNDARY=\"a b:c\"")).as_deref(),
            Some("a b:c")
        );
        assert_eq!(boundary(&value("multipart/mixed; boundary=x")), None);
        assert_eq!(boundary(&value("multipart/form-data")), None);
        assert_eq!(boundary(&value("multipart/form-data; boundary=")), None);
        assert_eq!(boundary(&value("multipart/form-data; boundary=\"unclosed")), None);
        assert_eq!(boundary(&value("multipart/form-data; boundary=a<b")), None);
        assert_eq!(boundary(&value("application/x-www-form-urlencoded")), None);
    }

    #[test]
    fn a_bad_boundary_is_an_error_and_a_bad_header_too() {
        let error = run("not-the-boundary", &body(), 64, 4096).unwrap_err().to_string();
        assert!(error.contains("no boundary line"), "{error}");
        assert!(run(BOUNDARY, b"not multipart at all", 64, 4096).is_err());
        let mut bad = format!("--{BOUNDARY}\r\nContent-Disposition form-data\r\n\r\n").into_bytes();
        bad.extend_from_slice(b"x\r\n");
        bad.extend_from_slice(format!("--{BOUNDARY}--\r\n").as_bytes());
        // A header without a colon is a failure of the body, not a cut.
        assert!(run(BOUNDARY, &bad, 64, 4096).is_err());
    }
}
