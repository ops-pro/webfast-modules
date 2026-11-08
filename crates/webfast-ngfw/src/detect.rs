//! libinjection's detectors for the `detect_sqli` and `detect_xss` operators (docs/ngfw.md
//! "Operators"): the `libinjection` feature, the barbacane-libinjection crate (`libinjectionrs`).
//! Without the feature a rule with either operator does not load (compile.rs), so the functions
//! here are never reached; they say "no" then.
//!
//! A detector runs on a value only after one of its rule's `prefilter` literals was found in it
//! (the plan's automaton gates it, as it gates a regex), so a clean request does not call them.

/// The fingerprint libinjection gives an SQL injection (`s&sos`, `1UE`, ...): its token types,
/// at most 8 bytes.
#[derive(Clone, Copy, PartialEq, Eq)]
pub struct Fingerprint {
    bytes: [u8; 8],
    len: u8,
}

impl Fingerprint {
    pub fn as_str(&self) -> &str {
        std::str::from_utf8(&self.bytes[..self.len as usize]).unwrap_or("")
    }
}

impl std::fmt::Debug for Fingerprint {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.as_str())
    }
}

#[cfg(test)]
thread_local! {
    /// The detector calls on this thread (the tests' check that a gated-out value is not tested).
    pub(crate) static CALLS: std::cell::Cell<usize> = const { std::cell::Cell::new(0) };
}

#[cfg(test)]
fn counted() {
    CALLS.with(|c| c.set(c.get() + 1));
}

#[cfg(not(test))]
fn counted() {}

/// The fingerprint when `text` is SQL injection by libinjection.
#[cfg(feature = "libinjection")]
pub fn sqli(text: &str) -> Option<Fingerprint> {
    counted();
    let result = libinjectionrs::detect_sqli(text.as_bytes());
    if !result.is_injection() {
        return None;
    }
    let mut fingerprint = Fingerprint { bytes: [0; 8], len: 0 };
    if let Some(found) = &result.fingerprint {
        let text = found.as_bytes();
        let len = text.iter().position(|&b| b == 0).unwrap_or(text.len()).min(8);
        fingerprint.bytes[..len].copy_from_slice(&text[..len]);
        fingerprint.len = len as u8;
    }
    Some(fingerprint)
}

/// Whether `text` is XSS by libinjection.
#[cfg(feature = "libinjection")]
pub fn xss(text: &str) -> bool {
    counted();
    libinjectionrs::detect_xss(text.as_bytes()).is_injection()
}

#[cfg(not(feature = "libinjection"))]
pub fn sqli(_text: &str) -> Option<Fingerprint> {
    counted();
    None
}

#[cfg(not(feature = "libinjection"))]
pub fn xss(_text: &str) -> bool {
    counted();
    false
}

/// The calls made on this thread so far (tests).
#[cfg(all(test, feature = "libinjection"))]
pub(crate) fn calls() -> usize {
    CALLS.with(|c| c.get())
}

#[cfg(all(test, feature = "libinjection"))]
pub(crate) mod corpus;

#[cfg(all(test, feature = "libinjection"))]
pub(crate) mod tests {
    use super::corpus::{BENIGN, SQLI, XSS};
    use super::*;
    use crate::rule::Transform;
    use std::time::Instant;

    /// `value` through `chain`, one transformation after the other (the engine's own, engine.rs).
    pub(crate) fn through(chain: &[Transform], value: &str) -> String {
        let mut text = value.to_string();
        let (mut b1, mut b2, mut double) = (Vec::new(), Vec::new(), false);
        for &t in chain {
            let mut out = String::new();
            crate::engine::apply(t, &text, &mut out, &mut b1, &mut b2, &mut double);
            text = out;
        }
        text
    }

    /// As a browser puts a value in a query string: spaces as `+` or `%20`, the rest of what is
    /// not unreserved percent-encoded.
    pub(crate) fn query_encoded(value: &str, plus: bool) -> String {
        let mut out = String::new();
        for b in value.bytes() {
            match b {
                b'a'..=b'z' | b'A'..=b'Z' | b'0'..=b'9' | b'-' | b'.' | b'_' | b'~' => out.push(b as char),
                b' ' if plus => out.push('+'),
                _ => out.push_str(&format!("%{b:02X}")),
            }
        }
        out
    }

    fn gated(text: &str, gate: &[&str]) -> bool {
        let lower = text.to_lowercase();
        gate.is_empty() || gate.iter().any(|g| lower.contains(&g.to_lowercase()))
    }

    const SQLI_CHAIN: &[Transform] = &[
        Transform::UrlDecode,
        Transform::RemoveNulls,
        Transform::Lowercase,
        Transform::CompressWhitespace,
    ];
    const XSS_CHAIN: &[Transform] = &[
        Transform::UrlDecode,
        Transform::HtmlDecode,
        Transform::JsDecode,
        Transform::RemoveNulls,
        Transform::Lowercase,
        Transform::CompressWhitespace,
    ];

    /// Recall and false positives of each candidate gate, in each context a value comes in (a
    /// form or cookie value as it is; a query value with `%20` or `+` for its spaces), and the
    /// cost of one call. Run with `cargo test --release -p webfast-ngfw gates_by_measurement --
    /// --ignored --nocapture`.
    #[test]
    #[ignore]
    fn gates_by_measurement() {
        type Detector = fn(&str) -> bool;
        let sqli_gates: &[(&str, &[&str])] = &[
            ("none", &[]),
            ("quotes", &["'", "\"", "`"]),
            (
                "punctuation",
                &[
                    "'", "\"", "`", "=", "(", ")", ";", "--", "/*", "#", "||", "&&", "<", ">", "@",
                ],
            ),
            (
                "punctuation, no ( )",
                &["'", "\"", "`", "=", ";", "--", "/*", "#", "||", "&&", "<", ">", "@"],
            ),
            (
                "punctuation + keywords",
                &[
                    "'", "\"", "`", "=", "(", ")", ";", "--", "/*", "#", "||", "&&", "<", ">", "@", "union", "select",
                    "having", "order by", "group by", " or ", " and ", "sleep", "into ",
                ],
            ),
            (
                "punctuation + union/select",
                &[
                    "'", "\"", "`", "=", "(", ")", ";", "--", "/*", "#", "||", "&&", "<", ">", "@", "union", "select",
                ],
            ),
        ];
        let xss_gates: &[(&str, &[&str])] = &[
            ("none", &[]),
            ("<", &["<"]),
            ("< and quotes", &["<", "\"", "'", "`"]),
            (
                "< quotes schemes",
                &["<", "\"", "'", "`", "javascript:", "vbscript:", "data:", "expression("],
            ),
            (
                "< quotes schemes on",
                &[
                    "<",
                    "\"",
                    "'",
                    "`",
                    "javascript:",
                    "vbscript:",
                    "data:",
                    "expression(",
                    "on",
                ],
            ),
        ];
        let (rules, _) =
            crate::config::compose(&crate::config::RulesConfig::default(), std::path::Path::new(".")).unwrap();
        let prefilter = |id: &str| -> Vec<&str> {
            let rule = rules.iter().find(|r| r.rule.id == id).expect("the built-in rule");
            rule.rule.prefilter.iter().map(String::as_str).collect()
        };
        let (sqli_builtin, xss_builtin) = (prefilter("wf-942-170"), prefilter("wf-941-150"));
        let sqli_gates: Vec<(&str, &[&str])> = sqli_gates
            .iter()
            .copied()
            .chain([("built-in wf-942-170", &sqli_builtin[..])])
            .collect();
        let xss_gates: Vec<(&str, &[&str])> = xss_gates
            .iter()
            .copied()
            .chain([("built-in wf-941-150", &xss_builtin[..])])
            .collect();
        let sqli_detect: Detector = |t| sqli(t).is_some();
        let xss_detect: Detector = xss;
        for (what, payloads, chain, gates, detect) in [
            ("sqli", SQLI, SQLI_CHAIN, &sqli_gates[..], sqli_detect),
            ("xss", XSS, XSS_CHAIN, &xss_gates[..], xss_detect),
        ] {
            println!("\n{what}: {} payloads, {} benign values", payloads.len(), BENIGN.len());
            for context in ["as is", "query %20", "query +"] {
                let encode = |v: &str| match context {
                    "as is" => v.to_string(),
                    "query %20" => query_encoded(v, false),
                    // The engine reads a query's `+` as a space before any chain (engine.rs
                    // `prepare`), as a form body's.
                    _ => query_encoded(v, true).replace('+', " "),
                };
                for (name, gate) in gates {
                    let mut caught = 0;
                    let mut missed = Vec::new();
                    for p in payloads {
                        let text = through(chain, &encode(p));
                        if gated(&text, gate) && detect(&text) {
                            caught += 1;
                        } else {
                            missed.push(*p);
                        }
                    }
                    let (mut fired, mut false_positives) = (0, Vec::new());
                    for b in BENIGN {
                        let text = through(chain, &encode(b));
                        if gated(&text, gate) {
                            fired += 1;
                            if detect(&text) {
                                false_positives.push(*b);
                            }
                        }
                    }
                    println!(
                        "  {context:<10} gate {name:<28} recall {caught}/{} gate fires on {fired}/{} benign, false positives {:?}",
                        payloads.len(),
                        BENIGN.len(),
                        false_positives
                    );
                    if context == "as is" && !missed.is_empty() && name.starts_with("built-in") {
                        println!("      missed: {missed:?}");
                    }
                    if *name == "none" && !missed.is_empty() {
                        println!("      libinjection misses: {missed:?}");
                    }
                }
            }
        }
        // The cost of one call, on what a gate lets through.
        let prose = "Thanks for the quick reply, it's what we needed and the team agrees. ".repeat(15);
        let form = "user=alice&comment=hello world this is a comment&page=2&sort=name&".repeat(16);
        for (what, text) in [
            ("short benign O'Brien", "O'Brien"),
            ("short sqli", "1' or '1'='1"),
            ("short xss", "<img src=x onerror=alert(1)>"),
            ("1 KiB prose with apostrophes", prose.as_str()),
            ("1 KiB form text", form.as_str()),
        ] {
            for (name, detect) in [("sqli", sqli_detect), ("xss", xss_detect)] {
                let n = if text.len() > 100 { 20_000 } else { 200_000 };
                let t = Instant::now();
                let mut hits = 0;
                for _ in 0..n {
                    hits += usize::from(detect(std::hint::black_box(text)));
                }
                let ns = t.elapsed().as_nanos() as f64 / n as f64;
                println!(
                    "{name:>5} on {what} ({} B): {ns:.0} ns per call, {}",
                    text.len(),
                    hits > 0
                );
            }
        }
    }

    #[test]
    fn the_detectors_say_yes_and_no() {
        let found = sqli("1' or '1'='1").expect("sqli");
        assert!(!found.as_str().is_empty() && found.as_str().len() <= 8, "{found:?}");
        assert!(sqli("O'Brien").is_none());
        assert!(sqli("hello world").is_none());
        assert!(xss("<script>alert(1)</script>"));
        assert!(xss("<img src=x onerror=alert(1)>"));
        assert!(!xss("Tom & Jerry <3"));
        assert!(!xss("O'Brien"));
    }
}
