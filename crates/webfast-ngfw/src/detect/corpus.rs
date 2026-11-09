//! The evaluation set of the detectors and their gates, read from the lists of tests/corpus/
//! (one value per line, the format of SecLists, ffuf and Burp Intruder; tests/corpus/README.md
//! says what each list holds): SQL injection and XSS payloads written by hand after the
//! well-known lists, benign values (names with apostrophes, prose with the keywords, URLs, JSON,
//! addresses, dates, numbers, browsers' User-Agents), and known WAF evasions the shipped sets must
//! keep refusing (a regression set, not a measure of the filter against evasion: CRS's own
//! regression tests are that). The built-in rules' tests run them through the engine
//! (engine.rs); the `gates_by_measurement` test prints what each candidate prefilter keeps and
//! costs; the go-ftw files of tests/ftw/corpus/ are written from them (src/ftw.rs).

use std::sync::LazyLock;

/// The values of a list: every line that is not empty, a `\r` before its end dropped.
pub(crate) fn lines(text: &'static str) -> Vec<&'static str> {
    text.split('\n')
        .map(|line| line.strip_suffix('\r').unwrap_or(line))
        .filter(|line| !line.is_empty())
        .collect()
}

/// The values of a `-urlencoded` list: each line percent-decoded (what a plain line cannot hold,
/// a newline in a value).
fn decoded(text: &'static str) -> Vec<&'static str> {
    lines(text)
        .into_iter()
        .map(|line| {
            let mut bytes = Vec::new();
            let raw = line.as_bytes();
            let mut i = 0;
            while i < raw.len() {
                let hex = |b: u8| (b as char).to_digit(16);
                if raw[i] == b'%'
                    && let (Some(h), Some(l)) = (
                        raw.get(i + 1).and_then(|b| hex(*b)),
                        raw.get(i + 2).and_then(|b| hex(*b)),
                    )
                {
                    bytes.push((h * 16 + l) as u8);
                    i += 3;
                    continue;
                }
                bytes.push(raw[i]);
                i += 1;
            }
            let text = String::from_utf8(bytes).unwrap_or_else(|_| panic!("not UTF-8 once decoded: {line}"));
            &*Box::leak(text.into_boxed_str())
        })
        .collect()
}

pub(crate) static SQLI: LazyLock<Vec<&'static str>> =
    LazyLock::new(|| lines(include_str!("../../tests/corpus/sqli.txt")));

pub(crate) static XSS: LazyLock<Vec<&'static str>> =
    LazyLock::new(|| lines(include_str!("../../tests/corpus/xss.txt")));

/// Known evasions, those of a plain line and those a line holds only percent-encoded.
pub(crate) static BYPASS: LazyLock<Vec<&'static str>> = LazyLock::new(|| {
    let mut values = lines(include_str!("../../tests/corpus/bypass.txt"));
    values.extend(decoded(include_str!("../../tests/corpus/bypass-urlencoded.txt")));
    values
});

/// Benign values of parameters, cookies and form fields.
pub(crate) static BENIGN: LazyLock<Vec<&'static str>> =
    LazyLock::new(|| lines(include_str!("../../tests/corpus/benign.txt")));

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_lists_read_as_written() {
        assert_eq!(SQLI.len(), 65);
        assert_eq!(XSS.len(), 50);
        assert_eq!(BYPASS.len(), 61);
        assert_eq!(BENIGN.len(), 104);
        assert!(BYPASS.contains(&"1'\nOR 1=1"), "the encoded list decoded");
        assert!(BYPASS.contains(&"1'\tor 1=1"), "a tab kept in a plain line");
        assert!(BENIGN.contains(&"Sinéad O'Connor"), "UTF-8 kept");
        assert_eq!(lines("a\r\n\nb\n"), ["a", "b"]);
    }
}
