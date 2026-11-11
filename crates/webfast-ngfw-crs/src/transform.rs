//! The transformations (`t:`) as ModSecurity applies them: on bytes, each giving a new value from
//! the last. Decoded code points beyond a byte keep their low byte, as ModSecurity's do without a
//! Unicode map, but for the full-width ASCII forms (U+FF01–U+FF5E), which become their ASCII.

use anyhow::{Result, bail};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Transform {
    Lowercase,
    Uppercase,
    UrlDecode,
    UrlDecodeUni,
    HtmlEntityDecode,
    JsDecode,
    CssDecode,
    Utf8ToUnicode,
    RemoveNulls,
    ReplaceNulls,
    RemoveWhitespace,
    CompressWhitespace,
    ReplaceComments,
    RemoveComments,
    RemoveCommentsChar,
    CmdLine,
    NormalizePath,
    NormalizePathWin,
    EscapeSeqDecode,
    Length,
    Base64Decode,
    Base64DecodeExt,
    Base64Encode,
    HexDecode,
    HexEncode,
    Sha1,
    Md5,
    Trim,
    TrimLeft,
    TrimRight,
}

impl Transform {
    /// `t:` by name; `None` for `none` (which clears the list).
    pub fn parse(name: &str) -> Result<Option<Transform>> {
        Ok(Some(match name.to_ascii_lowercase().as_str() {
            "none" => return Ok(None),
            "lowercase" => Transform::Lowercase,
            "uppercase" => Transform::Uppercase,
            "urldecode" => Transform::UrlDecode,
            "urldecodeuni" => Transform::UrlDecodeUni,
            "htmlentitydecode" => Transform::HtmlEntityDecode,
            "jsdecode" => Transform::JsDecode,
            "cssdecode" => Transform::CssDecode,
            "utf8tounicode" => Transform::Utf8ToUnicode,
            "removenulls" => Transform::RemoveNulls,
            "replacenulls" => Transform::ReplaceNulls,
            "removewhitespace" => Transform::RemoveWhitespace,
            "compresswhitespace" => Transform::CompressWhitespace,
            "replacecomments" => Transform::ReplaceComments,
            "removecomments" => Transform::RemoveComments,
            "removecommentschar" => Transform::RemoveCommentsChar,
            "cmdline" => Transform::CmdLine,
            "normalizepath" | "normalisepath" => Transform::NormalizePath,
            "normalizepathwin" | "normalisepathwin" => Transform::NormalizePathWin,
            "escapeseqdecode" => Transform::EscapeSeqDecode,
            "length" => Transform::Length,
            "base64decode" => Transform::Base64Decode,
            "base64decodeext" => Transform::Base64DecodeExt,
            "base64encode" => Transform::Base64Encode,
            "hexdecode" => Transform::HexDecode,
            "hexencode" => Transform::HexEncode,
            "sha1" => Transform::Sha1,
            "md5" => Transform::Md5,
            "trim" => Transform::Trim,
            "trimleft" => Transform::TrimLeft,
            "trimright" => Transform::TrimRight,
            other => bail!("t:{other}: no such transformation"),
        }))
    }

    /// Whether the transformation may change `input`: `false` only when it surely gives it back
    /// as it is (no `%` for a URL decoding, no upper case for `lowercase`), so most values of a
    /// request go through a chain without a copy.
    pub fn changes(self, input: &[u8]) -> bool {
        let has = |b: u8| memchr::memchr(b, input).is_some();
        let has_seq = |s: &[u8]| memchr::memmem::find(input, s).is_some();
        match self {
            Transform::Lowercase => input.iter().any(u8::is_ascii_uppercase),
            Transform::Uppercase => input.iter().any(u8::is_ascii_lowercase),
            Transform::UrlDecode | Transform::UrlDecodeUni => memchr::memchr2(b'%', b'+', input).is_some(),
            Transform::HtmlEntityDecode => has(b'&'),
            Transform::JsDecode | Transform::CssDecode | Transform::EscapeSeqDecode => has(b'\\'),
            Transform::Utf8ToUnicode => !input.is_ascii(),
            Transform::RemoveNulls | Transform::ReplaceNulls => has(0),
            Transform::RemoveWhitespace => input.iter().any(|&b| is_space(b) || b == 0xa0),
            Transform::CompressWhitespace => {
                input.iter().any(|&b| (is_space(b) && b != b' ') || b == 0xa0) || has_seq(b"  ")
            }
            Transform::ReplaceComments => has_seq(b"/*"),
            Transform::RemoveComments => has_seq(b"/*") || has_seq(b"--") || has(b'#') || has_seq(b"<!--"),
            Transform::RemoveCommentsChar => {
                has_seq(b"/*") || has_seq(b"*/") || has_seq(b"--") || has(b'#') || has_seq(b"<!--")
            }
            Transform::CmdLine => input.iter().any(|&b| {
                b.is_ascii_uppercase() || is_space(b) || matches!(b, b'\\' | b'"' | b'\'' | b'^' | b',' | b';')
            }),
            Transform::NormalizePath => has_seq(b"/.") || has_seq(b"//") || input.first() == Some(&b'.'),
            Transform::NormalizePathWin => {
                has(b'\\') || has_seq(b"/.") || has_seq(b"//") || input.first() == Some(&b'.')
            }
            Transform::Trim => {
                input.first().is_some_and(|&b| is_space(b)) || input.last().is_some_and(|&b| is_space(b))
            }
            Transform::TrimLeft => input.first().is_some_and(|&b| is_space(b)),
            Transform::TrimRight => input.last().is_some_and(|&b| is_space(b)),
            _ => true,
        }
    }

    /// The value transformed.
    pub fn apply(self, input: &[u8]) -> Vec<u8> {
        match self {
            Transform::Lowercase => input.to_ascii_lowercase(),
            Transform::Uppercase => input.to_ascii_uppercase(),
            Transform::UrlDecode => url_decode(input, false),
            Transform::UrlDecodeUni => url_decode(input, true),
            Transform::HtmlEntityDecode => html_entity_decode(input),
            Transform::JsDecode => js_decode(input),
            Transform::CssDecode => css_decode(input),
            Transform::Utf8ToUnicode => utf8_to_unicode(input),
            Transform::RemoveNulls => input.iter().copied().filter(|&b| b != 0).collect(),
            Transform::ReplaceNulls => input.iter().map(|&b| if b == 0 { b' ' } else { b }).collect(),
            Transform::RemoveWhitespace => input.iter().copied().filter(|&b| !is_space(b) && b != 0xa0).collect(),
            Transform::CompressWhitespace => compress_whitespace(input),
            Transform::ReplaceComments => replace_comments(input),
            Transform::RemoveComments => remove_comments(input),
            Transform::RemoveCommentsChar => remove_comments_char(input),
            Transform::CmdLine => cmd_line(input),
            Transform::NormalizePath => normalize_path(input, false),
            Transform::NormalizePathWin => normalize_path(input, true),
            Transform::EscapeSeqDecode => escape_seq_decode(input),
            Transform::Length => input.len().to_string().into_bytes(),
            Transform::Base64Decode => base64_decode(input, false),
            Transform::Base64DecodeExt => base64_decode(input, true),
            Transform::Base64Encode => base64_encode(input),
            Transform::HexDecode => hex_decode(input),
            Transform::HexEncode => hex_encode(input),
            Transform::Sha1 => aws_lc_rs::digest::digest(&aws_lc_rs::digest::SHA1_FOR_LEGACY_USE_ONLY, input)
                .as_ref()
                .to_vec(),
            Transform::Md5 => md5(input),
            Transform::Trim => trim(input, true, true),
            Transform::TrimLeft => trim(input, true, false),
            Transform::TrimRight => trim(input, false, true),
        }
    }
}

/// ModSecurity's whitespace (C `isspace`).
fn is_space(b: u8) -> bool {
    matches!(b, b' ' | b'\t' | b'\n' | b'\r' | 0x0b | 0x0c)
}

fn hex(b: u8) -> Option<u8> {
    match b {
        b'0'..=b'9' => Some(b - b'0'),
        b'a'..=b'f' => Some(b - b'a' + 10),
        b'A'..=b'F' => Some(b - b'A' + 10),
        _ => None,
    }
}

fn hex2(a: u8, b: u8) -> Option<u8> {
    Some(hex(a)? << 4 | hex(b)?)
}

/// A `%uXXXX` code point as one byte, as ModSecurity's best-fit map folds it (bestfit.rs: `’` to
/// `'`, `«` to `<`, `①` to `1`); full-width ASCII becomes ASCII, the rest keeps its low byte.
fn best_fit(cp: u32) -> u8 {
    if let Ok(cp16) = u16::try_from(cp)
        && let Ok(i) = super::bestfit::BEST_FIT.binary_search_by_key(&cp16, |&(c, _)| c)
    {
        return super::bestfit::BEST_FIT[i].1;
    }
    code_point_byte(cp)
}

/// A decoded code point as one byte: full-width ASCII becomes ASCII, the rest keeps its low byte.
fn code_point_byte(cp: u32) -> u8 {
    if (0xff01..=0xff5e).contains(&cp) {
        (cp - 0xfee0) as u8
    } else {
        (cp & 0xff) as u8
    }
}

fn url_decode(input: &[u8], uni: bool) -> Vec<u8> {
    let mut out = Vec::with_capacity(input.len());
    let mut i = 0;
    while i < input.len() {
        let b = input[i];
        if b == b'%' {
            if uni
                && i + 5 < input.len()
                && (input[i + 1] == b'u' || input[i + 1] == b'U')
                && input[i + 2..i + 6].iter().all(|&c| hex(c).is_some())
            {
                let cp = input[i + 2..i + 6]
                    .iter()
                    .fold(0u32, |a, &c| a << 4 | hex(c).unwrap_or(0) as u32);
                out.push(best_fit(cp));
                i += 6;
                continue;
            }
            if i + 2 < input.len()
                && let Some(v) = hex2(input[i + 1], input[i + 2])
            {
                out.push(v);
                i += 3;
                continue;
            }
            out.push(b);
        } else if b == b'+' {
            out.push(b' ');
        } else {
            out.push(b);
        }
        i += 1;
    }
    out
}

fn html_entity_decode(input: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(input.len());
    let mut i = 0;
    while i < input.len() {
        if input[i] != b'&' {
            out.push(input[i]);
            i += 1;
            continue;
        }
        let rest = &input[i + 1..];
        // &#x41; &#65; (the semicolon optional)
        if rest.first() == Some(&b'#') {
            let (radix, start) = if matches!(rest.get(1), Some(b'x' | b'X')) {
                (16, 2)
            } else {
                (10, 1)
            };
            let digits = rest[start..]
                .iter()
                .take_while(|&&c| {
                    if radix == 16 {
                        hex(c).is_some()
                    } else {
                        c.is_ascii_digit()
                    }
                })
                .count();
            if digits > 0 {
                let text = std::str::from_utf8(&rest[start..start + digits]).unwrap_or("0");
                let cp = u32::from_str_radix(text, radix).unwrap_or(0);
                out.push(code_point_byte(cp));
                let mut used = 1 + start + digits;
                if rest.get(start + digits) == Some(&b';') {
                    used += 1;
                }
                i += used;
                continue;
            }
        }
        let names: [(&[u8], u8); 6] = [
            (b"quot", b'"'),
            (b"amp", b'&'),
            (b"lt", b'<'),
            (b"gt", b'>'),
            (b"nbsp", 0xa0),
            (b"apos", b'\''),
        ];
        let mut done = false;
        for (name, value) in names {
            if rest.len() >= name.len() && rest[..name.len()].eq_ignore_ascii_case(name) {
                out.push(value);
                let mut used = 1 + name.len();
                if rest.get(name.len()) == Some(&b';') {
                    used += 1;
                }
                i += used;
                done = true;
                break;
            }
        }
        if !done {
            out.push(b'&');
            i += 1;
        }
    }
    out
}

fn js_decode(input: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(input.len());
    let mut i = 0;
    while i < input.len() {
        let b = input[i];
        if b != b'\\' || i + 1 >= input.len() {
            out.push(b);
            i += 1;
            continue;
        }
        let n = input[i + 1];
        if (n == b'u' || n == b'U') && i + 5 < input.len() && input[i + 2..i + 6].iter().all(|&c| hex(c).is_some()) {
            let cp = input[i + 2..i + 6]
                .iter()
                .fold(0u32, |a, &c| a << 4 | hex(c).unwrap_or(0) as u32);
            out.push(code_point_byte(cp));
            i += 6;
        } else if (n == b'x' || n == b'X')
            && i + 3 < input.len()
            && let Some(v) = hex2(input[i + 2], input[i + 3])
        {
            out.push(v);
            i += 4;
        } else if (b'0'..=b'7').contains(&n) {
            let mut v: u32 = 0;
            let mut j = i + 1;
            while j < input.len() && j < i + 4 && (b'0'..=b'7').contains(&input[j]) {
                v = v * 8 + (input[j] - b'0') as u32;
                j += 1;
            }
            out.push((v & 0xff) as u8);
            i = j;
        } else {
            out.push(match n {
                b'a' => 7,
                b'b' => 8,
                b'f' => 0x0c,
                b'n' => b'\n',
                b'r' => b'\r',
                b't' => b'\t',
                b'v' => 0x0b,
                other => other,
            });
            i += 2;
        }
    }
    out
}

fn css_decode(input: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(input.len());
    let mut i = 0;
    while i < input.len() {
        let b = input[i];
        if b != b'\\' {
            out.push(b);
            i += 1;
            continue;
        }
        if i + 1 >= input.len() {
            // A trailing backslash is dropped.
            i += 1;
            continue;
        }
        let digits = input[i + 1..].iter().take(6).take_while(|&&c| hex(c).is_some()).count();
        if digits > 0 {
            let cp = input[i + 1..i + 1 + digits]
                .iter()
                .fold(0u32, |a, &c| a << 4 | hex(c).unwrap_or(0) as u32);
            out.push(code_point_byte(cp));
            i += 1 + digits;
            // One whitespace after the escape ends it and goes.
            if i < input.len() && is_space(input[i]) {
                i += 1;
            }
        } else if input[i + 1] == b'\n' {
            i += 2;
        } else {
            out.push(input[i + 1]);
            i += 2;
        }
    }
    out
}

/// Every multi-byte UTF-8 character as `%uHHHH`; the rest as it is.
fn utf8_to_unicode(input: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(input.len());
    for chunk in input.utf8_chunks() {
        for c in chunk.valid().chars() {
            if c.is_ascii() {
                out.push(c as u8);
            } else {
                out.extend_from_slice(format!("%u{:04x}", c as u32).as_bytes());
            }
        }
        out.extend_from_slice(chunk.invalid());
    }
    out
}

fn compress_whitespace(input: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(input.len());
    let mut in_space = false;
    for &b in input {
        if is_space(b) || b == 0xa0 {
            if !in_space {
                out.push(b' ');
            }
            in_space = true;
        } else {
            out.push(b);
            in_space = false;
        }
    }
    out
}

/// `/* … */` replaced by a space (an unclosed one to the end).
fn replace_comments(input: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(input.len());
    let mut i = 0;
    while i < input.len() {
        if input[i] == b'/' && input.get(i + 1) == Some(&b'*') {
            match find(&input[i + 2..], b"*/") {
                Some(end) => i += 2 + end + 2,
                None => i = input.len(),
            }
            out.push(b' ');
        } else {
            out.push(input[i]);
            i += 1;
        }
    }
    out
}

/// `/* … */`, `<!-- … -->`, and `--` or `#` to the end of the line removed.
fn remove_comments(input: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(input.len());
    let mut i = 0;
    while i < input.len() {
        let rest = &input[i..];
        if rest.starts_with(b"/*") {
            match find(&rest[2..], b"*/") {
                Some(end) => i += 2 + end + 2,
                None => i = input.len(),
            }
        } else if rest.starts_with(b"<!--") {
            match find(&rest[4..], b"-->") {
                Some(end) => i += 4 + end + 3,
                None => i = input.len(),
            }
        } else if rest.starts_with(b"--") || rest[0] == b'#' {
            match rest.iter().position(|&b| b == b'\n' || b == b'\r') {
                Some(end) => i += end,
                None => i = input.len(),
            }
        } else {
            out.push(input[i]);
            i += 1;
        }
    }
    out
}

/// The comment characters themselves removed: `/*`, `*/`, `--`, `#`, `<!--`, `-->`.
fn remove_comments_char(input: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(input.len());
    let mut i = 0;
    while i < input.len() {
        let rest = &input[i..];
        if rest.starts_with(b"<!--") {
            i += 4;
        } else if rest.starts_with(b"-->") {
            i += 3;
        } else if rest.starts_with(b"/*") || rest.starts_with(b"*/") || rest.starts_with(b"--") {
            i += 2;
        } else if rest[0] == b'#' {
            i += 1;
        } else {
            out.push(input[i]);
            i += 1;
        }
    }
    out
}

/// What a Windows or Unix shell would see of a command line: `\ " ' ^` gone, `,` and `;` spaces,
/// whitespace compressed, none before `/` or `(`, lower case.
fn cmd_line(input: &[u8]) -> Vec<u8> {
    let mut out: Vec<u8> = Vec::with_capacity(input.len());
    let mut space = false;
    for &b in input {
        match b {
            b'"' | b'\'' | b'\\' | b'^' => {}
            b' ' | b'\t' | b'\n' | b'\r' | 0x0b | 0x0c | b',' | b';' => {
                if !space {
                    out.push(b' ');
                    space = true;
                }
            }
            b'/' | b'(' => {
                if space {
                    out.pop();
                }
                space = false;
                out.push(b);
            }
            other => {
                space = false;
                out.push(other.to_ascii_lowercase());
            }
        }
    }
    out
}

/// `./` and `../` resolved, `//` collapsed (`\` read as `/` first for `win`).
fn normalize_path(input: &[u8], win: bool) -> Vec<u8> {
    let text: Vec<u8> = if win {
        input.iter().map(|&b| if b == b'\\' { b'/' } else { b }).collect()
    } else {
        input.to_vec()
    };
    if text.is_empty() {
        return text;
    }
    let absolute = text[0] == b'/';
    let trailing = text.len() > 1 && text.ends_with(b"/") || text.ends_with(b"/.") || text.ends_with(b"/..");
    let mut parts: Vec<&[u8]> = Vec::new();
    for part in text.split(|&b| b == b'/') {
        match part {
            b"" | b"." => {}
            b".." => {
                if parts.last().is_some_and(|p| *p != b"..") {
                    parts.pop();
                } else if !absolute {
                    parts.push(part);
                }
            }
            p => parts.push(p),
        }
    }
    let mut out = Vec::with_capacity(text.len());
    if absolute {
        out.push(b'/');
    }
    for (i, p) in parts.iter().enumerate() {
        if i > 0 {
            out.push(b'/');
        }
        out.extend_from_slice(p);
    }
    if trailing && !out.ends_with(b"/") {
        out.push(b'/');
    }
    out
}

fn escape_seq_decode(input: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(input.len());
    let mut i = 0;
    while i < input.len() {
        let b = input[i];
        if b != b'\\' || i + 1 >= input.len() {
            out.push(b);
            i += 1;
            continue;
        }
        let n = input[i + 1];
        match n {
            b'a' => out.push(7),
            b'b' => out.push(8),
            b'f' => out.push(0x0c),
            b'n' => out.push(b'\n'),
            b'r' => out.push(b'\r'),
            b't' => out.push(b'\t'),
            b'v' => out.push(0x0b),
            b'\\' | b'?' | b'\'' | b'"' => out.push(n),
            b'x' | b'X' if i + 3 < input.len() && hex2(input[i + 2], input[i + 3]).is_some() => {
                out.push(hex2(input[i + 2], input[i + 3]).unwrap_or(0));
                i += 4;
                continue;
            }
            b'0'..=b'7' => {
                let mut v: u32 = 0;
                let mut j = i + 1;
                while j < input.len() && j < i + 4 && (b'0'..=b'7').contains(&input[j]) {
                    v = v * 8 + (input[j] - b'0') as u32;
                    j += 1;
                }
                out.push((v & 0xff) as u8);
                i = j;
                continue;
            }
            _ => {
                out.push(b'\\');
                out.push(n);
            }
        }
        i += 2;
    }
    out
}

fn base64_value(b: u8) -> Option<u8> {
    match b {
        b'A'..=b'Z' => Some(b - b'A'),
        b'a'..=b'z' => Some(b - b'a' + 26),
        b'0'..=b'9' => Some(b - b'0' + 52),
        b'+' | b'-' => Some(62),
        b'/' | b'_' => Some(63),
        _ => None,
    }
}

/// Base64 decoded up to the first character that is not of it (`ext`: such characters skipped).
fn base64_decode(input: &[u8], ext: bool) -> Vec<u8> {
    let mut out = Vec::with_capacity(input.len() * 3 / 4);
    let mut acc: u32 = 0;
    let mut bits = 0;
    for &b in input {
        if b == b'=' {
            break;
        }
        match base64_value(b) {
            Some(v) => {
                acc = acc << 6 | v as u32;
                bits += 6;
                if bits >= 8 {
                    bits -= 8;
                    out.push((acc >> bits) as u8);
                }
            }
            None if ext => {}
            None => break,
        }
    }
    out
}

fn base64_encode(input: &[u8]) -> Vec<u8> {
    const T: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let mut out = Vec::with_capacity(input.len().div_ceil(3) * 4);
    for chunk in input.chunks(3) {
        let n = chunk.iter().fold(0u32, |a, &b| a << 8 | b as u32) << (8 * (3 - chunk.len()));
        for k in 0..4 {
            if k <= chunk.len() {
                out.push(T[(n >> (18 - 6 * k) & 63) as usize]);
            } else {
                out.push(b'=');
            }
        }
    }
    out
}

fn hex_decode(input: &[u8]) -> Vec<u8> {
    input
        .chunks(2)
        .filter_map(|p| if p.len() == 2 { hex2(p[0], p[1]) } else { None })
        .collect()
}

fn hex_encode(input: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(input.len() * 2);
    for &b in input {
        out.extend_from_slice(format!("{b:02x}").as_bytes());
    }
    out
}

fn trim(input: &[u8], left: bool, right: bool) -> Vec<u8> {
    let mut s = input;
    if left {
        while let [first, rest @ ..] = s {
            if is_space(*first) {
                s = rest;
            } else {
                break;
            }
        }
    }
    if right {
        while let [rest @ .., last] = s {
            if is_space(*last) {
                s = rest;
            } else {
                break;
            }
        }
    }
    s.to_vec()
}

fn find(hay: &[u8], needle: &[u8]) -> Option<usize> {
    hay.windows(needle.len()).position(|w| w == needle)
}

/// MD5 (RFC 1321), for `t:md5`: no other user of it here, so not a dependency.
fn md5(input: &[u8]) -> Vec<u8> {
    const S: [u32; 64] = [
        7, 12, 17, 22, 7, 12, 17, 22, 7, 12, 17, 22, 7, 12, 17, 22, 5, 9, 14, 20, 5, 9, 14, 20, 5, 9, 14, 20, 5, 9, 14,
        20, 4, 11, 16, 23, 4, 11, 16, 23, 4, 11, 16, 23, 4, 11, 16, 23, 6, 10, 15, 21, 6, 10, 15, 21, 6, 10, 15, 21, 6,
        10, 15, 21,
    ];
    let k: Vec<u32> = (0..64)
        .map(|i| ((i as f64 + 1.0).sin().abs() * 4294967296.0) as u32)
        .collect();
    let mut msg = input.to_vec();
    let bit_len = (input.len() as u64).wrapping_mul(8);
    msg.push(0x80);
    while msg.len() % 64 != 56 {
        msg.push(0);
    }
    msg.extend_from_slice(&bit_len.to_le_bytes());
    let (mut a0, mut b0, mut c0, mut d0): (u32, u32, u32, u32) = (0x67452301, 0xefcdab89, 0x98badcfe, 0x10325476);
    for chunk in msg.chunks(64) {
        let m: Vec<u32> = chunk
            .chunks(4)
            .map(|w| u32::from_le_bytes([w[0], w[1], w[2], w[3]]))
            .collect();
        let (mut a, mut b, mut c, mut d) = (a0, b0, c0, d0);
        for i in 0..64 {
            let (f, g) = match i / 16 {
                0 => ((b & c) | (!b & d), i),
                1 => ((d & b) | (!d & c), (5 * i + 1) % 16),
                2 => (b ^ c ^ d, (3 * i + 5) % 16),
                _ => (c ^ (b | !d), (7 * i) % 16),
            };
            let f = f.wrapping_add(a).wrapping_add(k[i]).wrapping_add(m[g]);
            a = d;
            d = c;
            c = b;
            b = b.wrapping_add(f.rotate_left(S[i]));
        }
        a0 = a0.wrapping_add(a);
        b0 = b0.wrapping_add(b);
        c0 = c0.wrapping_add(c);
        d0 = d0.wrapping_add(d);
    }
    [a0, b0, c0, d0].iter().flat_map(|v| v.to_le_bytes()).collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn t(name: &str, input: &str) -> String {
        String::from_utf8_lossy(&Transform::parse(name).unwrap().unwrap().apply(input.as_bytes())).into_owned()
    }

    #[test]
    fn decoders() {
        assert_eq!(t("urlDecodeUni", "a%20b+c%u0041%uff41%zz"), "a b cAa%zz");
        assert_eq!(t("urlDecodeUni", "%u2019%u00ab%u2460%u00e9"), "'<1e");
        assert_eq!(t("urlDecode", "%41%u0041"), "A%u0041");
        assert_eq!(t("htmlEntityDecode", "&lt;a&#x41;&#66&quot;&bogus;"), "<aAB\"&bogus;");
        assert_eq!(t("jsDecode", "\\x41\\u0042\\103\\n\\q"), "ABC\nq");
        assert_eq!(t("cssDecode", "\\41 b\\\nc\\z"), "Abcz");
        assert_eq!(t("utf8toUnicode", "aé"), "a%u00e9");
        assert_eq!(t("escapeSeqDecode", "\\x41\\n\\q"), "A\n\\q");
        assert_eq!(t("base64Decode", "QUJD"), "ABC");
        assert_eq!(t("base64DecodeExt", "QU.JD"), "ABC");
        assert_eq!(t("hexDecode", "414243"), "ABC");
    }

    #[test]
    fn rewriters() {
        assert_eq!(t("compressWhitespace", "a  \t b"), "a b");
        assert_eq!(t("removeWhitespace", " a b "), "ab");
        assert_eq!(t("replaceComments", "a/*x*/b/*"), "a b ");
        assert_eq!(t("removeComments", "a/*x*/b--c\nd#e"), "ab\nd");
        assert_eq!(t("removeCommentsChar", "a/*b*/c--d#e"), "abcde");
        assert_eq!(t("cmdLine", "C:\\\"W^in\" ,  /c (x);Y"), "c:win/c(x) y");
        assert_eq!(t("normalizePath", "/a/./b/../c//d"), "/a/c/d");
        assert_eq!(t("normalizePath", "/a/b/.."), "/a/");
        assert_eq!(t("normalizePathWin", "\\a\\..\\b"), "/b");
        assert_eq!(t("length", "abc"), "3");
        assert_eq!(t("trim", "  a  "), "a");
        assert_eq!(t("hexEncode", "AB"), "4142");
        assert_eq!(t("base64Encode", "ab"), "YWI=");
    }

    #[test]
    /// `changes` is `false` only where `apply` gives the value back as it is.
    fn no_change_is_no_change() {
        let all = [
            "lowercase",
            "uppercase",
            "urlDecode",
            "urlDecodeUni",
            "htmlEntityDecode",
            "jsDecode",
            "cssDecode",
            "utf8toUnicode",
            "removeNulls",
            "replaceNulls",
            "removeWhitespace",
            "compressWhitespace",
            "replaceComments",
            "removeComments",
            "removeCommentsChar",
            "cmdLine",
            "normalizePath",
            "normalizePathWin",
            "escapeSeqDecode",
            "trim",
            "trimLeft",
            "trimRight",
        ];
        let inputs: [&[u8]; 14] = [
            b"",
            b"abc",
            b"ABC",
            b"a b",
            b"a  b",
            b"a\tb",
            b"%41",
            b"a+b",
            b"&lt;",
            b"\\x41",
            b"/a/./b",
            b"a//b",
            b"./x",
            "caf\u{e9}".as_bytes(),
        ];
        for name in all {
            let t = Transform::parse(name).unwrap().unwrap();
            for input in inputs {
                if !t.changes(input) {
                    assert_eq!(t.apply(input), input, "{name} over {input:?}");
                }
            }
        }
    }

    #[test]
    fn hashes() {
        assert_eq!(
            hex_encode(&Transform::Md5.apply(b"abc")),
            b"900150983cd24fb0d6963f7d28e17f72"
        );
        assert_eq!(
            hex_encode(&Transform::Sha1.apply(b"abc")),
            b"a9993e364706816aba3e25717850c26c9cd0d89d"
        );
    }
}
