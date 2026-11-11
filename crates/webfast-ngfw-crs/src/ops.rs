//! The operators (`@rx`, `@pm`, `@within`, …) over a value's bytes. A regex is the regex crate's,
//! on bytes, Unicode off where the pattern allows it (PCRE in ModSecurity reads bytes); a phrase
//! list is one Aho-Corasick automaton ignoring ASCII case. An argument with a macro
//! (`@within %{tx.allowed_methods}`) is expanded per request (`run.rs`) and tested with `test_text`.

use super::macros::Macro;
use aho_corasick::{AhoCorasick, AhoCorasickBuilder, MatchKind};
use anyhow::{Context, Result, bail};
use ipnet::IpNet;
use regex::bytes::{Regex, RegexBuilder};
use std::net::IpAddr;

/// The operators known.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Kind {
    Rx,
    Pm,
    StrEq,
    Contains,
    ContainsWord,
    BeginsWith,
    EndsWith,
    Within,
    StrMatch,
    Eq,
    Ge,
    Gt,
    Le,
    Lt,
    ValidateByteRange,
    ValidateUrlEncoding,
    ValidateUtf8Encoding,
    IpMatch,
    DetectSqli,
    DetectXss,
    UnconditionalMatch,
    NoMatch,
}

/// An operator ready to test values.
pub struct Operator {
    pub kind: Kind,
    pub negated: bool,
    /// The argument; a macro when it has `%{…}` (expanded per request).
    pub arg: Macro,
    /// The argument's text when it has no macro, made once.
    pub fixed_arg: Option<Vec<u8>>,
    /// `@rx`: literals one of which every match starts with (ASCII lower case, the prefilter's;
    /// none when the regex gives no finite set).
    pub literals: Option<Vec<Vec<u8>>>,
    compiled: Compiled,
}

enum Compiled {
    None,
    Regex(Regex),
    Phrases(AhoCorasick, Vec<Vec<u8>>),
    Bytes(Box<[bool; 256]>),
    Nets(Vec<IpNet>),
}

/// What a match found: the text for `TX.0`, and the regex's groups for `TX.1`…`TX.9`.
#[derive(Debug, Default, Clone)]
pub struct Matched {
    pub captures: Vec<Vec<u8>>,
}

/// A data file's phrases: one per line, `#` lines and blank ones left out.
pub fn phrases_of(text: &str) -> Vec<String> {
    text.lines()
        .map(str::trim)
        .filter(|l| !l.is_empty() && !l.starts_with('#'))
        .map(str::to_string)
        .collect()
}

/// `\x{hh}` as `\xhh`: a byte in PCRE without UTF (the CRS matches UTF-8 sequences so, as
/// `\x{e2}\x80\x99`), a code point to the regex crate even with Unicode off.
fn bytes_escapes(pattern: &str) -> String {
    let mut out = String::with_capacity(pattern.len());
    let mut chars = pattern.char_indices().peekable();
    while let Some((i, c)) = chars.next() {
        if c != '\\' {
            out.push(c);
            continue;
        }
        let rest = &pattern[i + 1..];
        if let Some(inner) = rest.strip_prefix("x{")
            && let Some(end) = inner.find('}')
            && let Ok(v) = u32::from_str_radix(&inner[..end], 16)
            && v <= 0xff
        {
            out.push_str(&format!("\\x{v:02x}"));
            // `x{`, the digits and `}`.
            for _ in 0..end + 3 {
                chars.next();
            }
            continue;
        }
        out.push('\\');
        if let Some((_, next)) = chars.next() {
            out.push(next);
        }
    }
    out
}

/// The literals every match of `pattern` (as `regex` builds it, Unicode off) starts with, in
/// ASCII lower case, deduplicated; `None` when there is no finite set of them, one is empty (a
/// match may start anywhere), or the pattern needs Unicode.
pub fn prefix_literals(pattern: &str) -> Option<Vec<Vec<u8>>> {
    use regex_syntax::hir::literal::{ExtractKind, Extractor};
    let hir = regex_syntax::ParserBuilder::new()
        .unicode(false)
        .utf8(false)
        .build()
        .parse(&bytes_escapes(pattern))
        .ok()?;
    let mut extractor = Extractor::new();
    extractor
        .kind(ExtractKind::Prefix)
        .limit_class(64)
        .limit_repeat(8)
        .limit_literal_len(12)
        .limit_total(4096);
    let seq = extractor.extract(&hir);
    let literals = seq.literals()?;
    if literals.is_empty() || literals.iter().any(|l| l.as_bytes().is_empty()) {
        return None;
    }
    let mut out: Vec<Vec<u8>> = literals.iter().map(|l| l.as_bytes().to_ascii_lowercase()).collect();
    out.sort();
    out.dedup();
    Some(out)
}

/// A regex as ModSecurity's PCRE reads it: on bytes, without Unicode where the pattern allows.
pub fn regex(pattern: &str, case_insensitive: bool) -> Result<Regex> {
    let bytes = bytes_escapes(pattern);
    let build = |unicode: bool| {
        RegexBuilder::new(if unicode { pattern } else { &bytes })
            .unicode(unicode)
            .case_insensitive(case_insensitive)
            .size_limit(64 << 20)
            .dfa_size_limit(16 << 20)
            .build()
    };
    match build(false) {
        Ok(re) => Ok(re),
        Err(_) => build(true).with_context(|| format!("regex {pattern:?}")),
    }
}

impl Operator {
    /// `name` (`rx`, `pmFromFile`, …) with its argument; `data` reads a data file by name.
    pub fn new(name: &str, arg: &str, negated: bool, data: &dyn Fn(&str) -> Result<String>) -> Result<Operator> {
        let lower = name.to_ascii_lowercase();
        let kind = match lower.as_str() {
            "rx" => Kind::Rx,
            "pm" | "pmfromfile" | "pmf" => Kind::Pm,
            "streq" => Kind::StrEq,
            "contains" => Kind::Contains,
            "containsword" => Kind::ContainsWord,
            "beginswith" => Kind::BeginsWith,
            "endswith" => Kind::EndsWith,
            "within" => Kind::Within,
            "strmatch" => Kind::StrMatch,
            "eq" => Kind::Eq,
            "ge" => Kind::Ge,
            "gt" => Kind::Gt,
            "le" => Kind::Le,
            "lt" => Kind::Lt,
            "validatebyterange" => Kind::ValidateByteRange,
            "validateurlencoding" => Kind::ValidateUrlEncoding,
            "validateutf8encoding" => Kind::ValidateUtf8Encoding,
            "ipmatch" | "ipmatchfromfile" | "ipmatchf" => Kind::IpMatch,
            "detectsqli" => Kind::DetectSqli,
            "detectxss" => Kind::DetectXss,
            "unconditionalmatch" => Kind::UnconditionalMatch,
            "nomatch" => Kind::NoMatch,
            other => bail!("@{other}: no such operator here"),
        };
        let macro_arg = Macro::parse(arg)?;
        let from_file = matches!(lower.as_str(), "pmfromfile" | "pmf" | "ipmatchfromfile" | "ipmatchf");
        if macro_arg.is_dynamic()
            && !matches!(
                kind,
                Kind::StrEq
                    | Kind::Contains
                    | Kind::ContainsWord
                    | Kind::BeginsWith
                    | Kind::EndsWith
                    | Kind::Within
                    | Kind::StrMatch
                    | Kind::Eq
                    | Kind::Ge
                    | Kind::Gt
                    | Kind::Le
                    | Kind::Lt
            )
        {
            bail!("@{name}: a macro in its argument is not supported");
        }
        let compiled = match kind {
            Kind::Rx => Compiled::Regex(regex(arg, false)?),
            Kind::Pm => {
                let list: Vec<String> = if from_file {
                    let mut all = Vec::new();
                    for file in arg.split_whitespace() {
                        all.extend(phrases_of(&data(file)?));
                    }
                    all
                } else {
                    arg.split_whitespace().map(str::to_string).collect()
                };
                if list.is_empty() {
                    bail!("@{name} {arg}: no phrases");
                }
                let bytes: Vec<Vec<u8>> = list.into_iter().map(String::into_bytes).collect();
                let ac = AhoCorasickBuilder::new()
                    .ascii_case_insensitive(true)
                    .match_kind(MatchKind::LeftmostFirst)
                    .build(&bytes)
                    .context("@pm automaton")?;
                Compiled::Phrases(ac, bytes)
            }
            Kind::ValidateByteRange => Compiled::Bytes(byte_ranges(arg)?),
            Kind::IpMatch => {
                let text = if from_file { data(arg)? } else { arg.replace(',', "\n") };
                let mut nets = Vec::new();
                for item in text
                    .lines()
                    .map(str::trim)
                    .filter(|l| !l.is_empty() && !l.starts_with('#'))
                {
                    nets.push(net(item).with_context(|| format!("@ipMatch {item:?}"))?);
                }
                Compiled::Nets(nets)
            }
            Kind::DetectSqli | Kind::DetectXss | Kind::UnconditionalMatch | Kind::NoMatch => Compiled::None,
            _ => Compiled::None,
        };
        let fixed_arg = (!macro_arg.is_dynamic()).then(|| macro_arg.fixed().unwrap_or_default().into_bytes());
        // A prefilter only for a regex that builds without Unicode, as the literals are read so.
        let literals = match (&compiled, kind) {
            (Compiled::Regex(_), Kind::Rx) if RegexBuilder::new(&bytes_escapes(arg)).unicode(false).build().is_ok() => {
                prefix_literals(arg)
            }
            _ => None,
        };
        Ok(Operator {
            kind,
            negated,
            arg: macro_arg,
            fixed_arg,
            literals,
            compiled,
        })
    }

    /// Whether the operator holds for `value` (before the negation), the argument expanded to
    /// `arg` (its fixed text when it has no macro); `want_captures`: fill `matched`.
    pub fn test(&self, value: &[u8], arg: &[u8], want_captures: bool, matched: &mut Matched) -> bool {
        matched.captures.clear();
        match self.kind {
            Kind::Rx => {
                let Compiled::Regex(re) = &self.compiled else {
                    return false;
                };
                // The groups only for a value that matches: `is_match` runs the fast automata,
                // `captures` the slower engines that track groups.
                if want_captures {
                    if !re.is_match(value) {
                        return false;
                    }
                    match re.captures(value) {
                        Some(caps) => {
                            for i in 0..caps.len().min(10) {
                                matched
                                    .captures
                                    .push(caps.get(i).map(|m| m.as_bytes().to_vec()).unwrap_or_default());
                            }
                            true
                        }
                        None => false,
                    }
                } else {
                    re.is_match(value)
                }
            }
            Kind::Pm => {
                let Compiled::Phrases(ac, list) = &self.compiled else {
                    return false;
                };
                match ac.find(value) {
                    Some(m) => {
                        if want_captures {
                            matched.captures.push(value[m.range()].to_vec());
                        }
                        let _ = list;
                        true
                    }
                    None => false,
                }
            }
            Kind::StrEq => self.capture_if(value == arg, value, want_captures, matched),
            Kind::Contains => self.capture_if(find(value, arg).is_some(), arg, want_captures, matched),
            Kind::ContainsWord => self.capture_if(contains_word(value, arg), arg, want_captures, matched),
            Kind::BeginsWith => self.capture_if(value.starts_with(arg), arg, want_captures, matched),
            Kind::EndsWith => self.capture_if(value.ends_with(arg), arg, want_captures, matched),
            Kind::Within => self.capture_if(
                value.is_empty() || find(arg, value).is_some(),
                value,
                want_captures,
                matched,
            ),
            Kind::StrMatch => self.capture_if(find(value, arg).is_some(), arg, want_captures, matched),
            Kind::Eq | Kind::Ge | Kind::Gt | Kind::Le | Kind::Lt => {
                let (v, a) = (atoi(value), atoi(arg));
                let holds = match self.kind {
                    Kind::Eq => v == a,
                    Kind::Ge => v >= a,
                    Kind::Gt => v > a,
                    Kind::Le => v <= a,
                    _ => v < a,
                };
                self.capture_if(holds, value, want_captures, matched)
            }
            Kind::ValidateByteRange => {
                let Compiled::Bytes(allowed) = &self.compiled else {
                    return false;
                };
                match value.iter().find(|&&b| !allowed[b as usize]) {
                    Some(&b) => {
                        if want_captures {
                            matched.captures.push(vec![b]);
                        }
                        true
                    }
                    None => false,
                }
            }
            Kind::ValidateUrlEncoding => self.capture_if(!valid_url_encoding(value), value, want_captures, matched),
            Kind::ValidateUtf8Encoding => {
                self.capture_if(std::str::from_utf8(value).is_err(), value, want_captures, matched)
            }
            Kind::IpMatch => {
                let Compiled::Nets(nets) = &self.compiled else {
                    return false;
                };
                let ip = std::str::from_utf8(value)
                    .ok()
                    .and_then(|t| t.trim().parse::<IpAddr>().ok());
                let holds = ip.is_some_and(|ip| nets.iter().any(|n| n.contains(&ip)));
                self.capture_if(holds, value, want_captures, matched)
            }
            Kind::DetectSqli => {
                let result = libinjectionrs::detect_sqli(value);
                if result.is_injection() {
                    if want_captures {
                        let fingerprint = result.fingerprint.as_ref().map(|f| {
                            let text = f.as_bytes();
                            text[..text.iter().position(|&b| b == 0).unwrap_or(text.len())].to_vec()
                        });
                        matched.captures.push(fingerprint.unwrap_or_default());
                    }
                    true
                } else {
                    false
                }
            }
            Kind::DetectXss => self.capture_if(
                libinjectionrs::detect_xss(value).is_injection(),
                value,
                want_captures,
                matched,
            ),
            Kind::UnconditionalMatch => self.capture_if(true, value, want_captures, matched),
            Kind::NoMatch => false,
        }
    }

    fn capture_if(&self, holds: bool, text: &[u8], want: bool, matched: &mut Matched) -> bool {
        if holds && want {
            matched.captures.push(text.to_vec());
        }
        holds
    }
}

/// C's `atoi`: the leading whitespace skipped, a sign, the digits; 0 when there are none.
fn atoi(text: &[u8]) -> i64 {
    let mut i = 0;
    while i < text.len() && text[i].is_ascii_whitespace() {
        i += 1;
    }
    let mut negative = false;
    if i < text.len() && (text[i] == b'-' || text[i] == b'+') {
        negative = text[i] == b'-';
        i += 1;
    }
    let mut n: i64 = 0;
    while i < text.len() && text[i].is_ascii_digit() {
        n = n.saturating_mul(10).saturating_add((text[i] - b'0') as i64);
        i += 1;
    }
    if negative { -n } else { n }
}

fn find(hay: &[u8], needle: &[u8]) -> Option<usize> {
    if needle.is_empty() {
        return Some(0);
    }
    memchr::memmem::find(hay, needle)
}

fn contains_word(hay: &[u8], word: &[u8]) -> bool {
    if word.is_empty() {
        return true;
    }
    let is_word = |b: u8| b.is_ascii_alphanumeric() || b == b'_';
    let mut from = 0;
    while let Some(i) = find(&hay[from..], word) {
        let at = from + i;
        let end = at + word.len();
        let before = at == 0 || !is_word(hay[at - 1]);
        let after = end == hay.len() || !is_word(hay[end]);
        if before && after {
            return true;
        }
        from = at + 1;
    }
    false
}

/// Every `%` followed by two hex digits.
fn valid_url_encoding(value: &[u8]) -> bool {
    let mut i = 0;
    while i < value.len() {
        if value[i] == b'%' {
            if i + 2 >= value.len() || !value[i + 1].is_ascii_hexdigit() || !value[i + 2].is_ascii_hexdigit() {
                return false;
            }
            i += 3;
        } else {
            i += 1;
        }
    }
    true
}

/// `1-255` or `9,10,13,32-126`: the bytes allowed.
fn byte_ranges(arg: &str) -> Result<Box<[bool; 256]>> {
    let mut allowed = Box::new([false; 256]);
    for part in arg.split([',', ' ']).map(str::trim).filter(|p| !p.is_empty()) {
        let (lo, hi) = match part.split_once('-') {
            Some((lo, hi)) => (lo.trim().parse::<u8>()?, hi.trim().parse::<u8>()?),
            None => {
                let v = part.parse::<u8>()?;
                (v, v)
            }
        };
        if lo > hi {
            bail!("@validateByteRange {arg}: {lo} > {hi}");
        }
        for b in lo..=hi {
            allowed[b as usize] = true;
        }
    }
    Ok(allowed)
}

fn net(text: &str) -> Result<IpNet> {
    if let Ok(net) = text.parse::<IpNet>() {
        return Ok(net);
    }
    let ip: IpAddr = text.parse()?;
    Ok(IpNet::from(ip))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn op(name: &str, arg: &str) -> Operator {
        Operator::new(name, arg, false, &|_| Ok("one\n# comment\n\nTwo\n".into())).unwrap()
    }

    fn holds(o: &Operator, value: &str) -> bool {
        let arg = o.arg.fixed().unwrap_or_default();
        o.test(value.as_bytes(), arg.as_bytes(), true, &mut Matched::default())
    }

    #[test]
    fn each_operator() {
        let mut m = Matched::default();
        let rx = op("rx", "a(b+)c");
        assert!(rx.test(b"xabbc", b"", true, &mut m));
        assert_eq!(m.captures, vec![b"abbc".to_vec(), b"bb".to_vec()]);
        assert!(holds(&op("pm", "foo bar"), "xBARx"));
        assert!(holds(&op("pmFromFile", "f.data"), "xtwoX"));
        assert!(!holds(&op("pmFromFile", "f.data"), "comment"));
        assert!(holds(&op("streq", "GET"), "GET") && !holds(&op("streq", "GET"), "get"));
        assert!(holds(&op("within", "GET HEAD POST"), "HEAD") && !holds(&op("within", "GET"), "PUT"));
        assert!(holds(&op("containsWord", "or"), "a or b") && !holds(&op("containsWord", "or"), "for"));
        assert!(holds(&op("lt", "5"), "4") && !holds(&op("lt", "5"), "5") && holds(&op("eq", "0"), "x"));
        assert!(
            holds(&op("validateByteRange", "32-126"), "a\u{1}b") && !holds(&op("validateByteRange", "32-126"), "ab")
        );
        assert!(holds(&op("validateUrlEncoding", ""), "a%zz") && !holds(&op("validateUrlEncoding", ""), "a%41"));
        assert!(holds(&op("validateUrlEncoding", ""), "a%4"));
        assert!(
            holds(&op("ipMatch", "127.0.0.1,::1,10.0.0.0/8"), "10.1.2.3") && !holds(&op("ipMatch", "127.0.0.1"), "x")
        );
        assert!(holds(&op("detectSQLi", ""), "1' or '1'='1"));
        assert!(holds(&op("detectXSS", ""), "<script>alert(1)</script>"));
        assert!(holds(&op("unconditionalMatch", ""), "x") && !holds(&op("noMatch", ""), "x"));
        assert!(Operator::new("rx", "%{tx.x}", false, &|_| Ok(String::new())).is_err());
    }

    /// A regex's `\x{..}` is a byte, as PCRE's without UTF: the CRS matches UTF-8 sequences so.
    #[test]
    fn hex_escapes_are_bytes() {
        let re = regex(r"\x{e2}\x80[\x98\x99]|\x{c2}\x{b4}", false).unwrap();
        assert!(re.is_match("a\u{2019}b".as_bytes()));
        assert!(re.is_match("\u{b4}".as_bytes()));
        let re = regex(r"\x{bc}[^>\x{be}]*[>\x{be}]", false).unwrap();
        assert!(re.is_match(b"\xbcscript\xbe"));
        assert_eq!(bytes_escapes(r"a\x{41}\\x{42}\x{100}"), r"a\x41\\x{42}\x{100}");
    }

    /// The prefilter's literals: what every match starts with, lower case; none for a regex a
    /// match of which may start anywhere.
    #[test]
    fn prefix_literals_of_regexes() {
        // Case folded to lower: `SlEeP(` is found by `sleep(`.
        let words = prefix_literals("(?i)(?:sleep|benchmark)\\s*\\(").unwrap();
        assert!(words.contains(&b"sleep(".to_vec()) && words.contains(&b"benchmark ".to_vec()));
        assert!(
            words
                .iter()
                .all(|l| l.starts_with(b"sleep") || l.starts_with(b"benchmark"))
        );
        let short = prefix_literals("[;|&]\\s*cat").unwrap();
        assert!(short.iter().any(|l| l.starts_with(b";")) && short.iter().any(|l| l.starts_with(b"&")));
        assert_eq!(prefix_literals("x?y?"), None, "a match may be empty");
        assert_eq!(prefix_literals(".*x"), None);
    }
}
