//! The module's event lines (docs/ngfw.md "The log"), through webfast_core::eventlog: the common head
//! with the country, ASN and User-Agent added to `request`, then the decision, status, scores,
//! phase and the hits with their matched text (already cut to `log.matched` by the engine, and
//! `REDACTED` where the JWT check hides a parameter).

use super::compile::Compiled;
use super::engine::Evaluation;
use super::rule::Refs;
use std::fmt::Write as _;
use std::net::IpAddr;
use webfast_core::accesslog::json_escape;
use webfast_core::eventlog::EventLog;

/// What a line says the request got.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Outcome {
    Block,
    Ban,
    /// Would have refused.
    LogOnly,
    /// Scored under the threshold (`log.passed`).
    Scored,
    /// Refused by `access`, with the reason.
    Access(&'static str),
    /// A response replaced in the `response` phase.
    Leak,
    /// A streamed response ended at a leak in its body (`decision` `leak` too).
    Cut,
    /// Answered with the browser challenge (docs/challenge.md); the reason when `access` asked
    /// (`country`, `asn`, `ban`), none for the rules.
    Challenge(Option<&'static str>),
    /// A challenge was due and the client had passed it: let through.
    ChallengePassed(Option<&'static str>),
}

impl Outcome {
    fn decision(self) -> &'static str {
        match self {
            Outcome::Block => "block",
            Outcome::Ban => "ban",
            Outcome::LogOnly => "log_only",
            Outcome::Scored => "scored",
            Outcome::Access(_) => "access",
            Outcome::Leak | Outcome::Cut => "leak",
            Outcome::Challenge(_) => "challenge",
            Outcome::ChallengePassed(_) => "challenge_passed",
        }
    }

    fn message(self) -> &'static str {
        match self {
            Outcome::Block | Outcome::Ban | Outcome::Access(_) => "request refused",
            Outcome::LogOnly => "request let through (log_only)",
            Outcome::Scored => "request scored",
            Outcome::Leak => "response replaced",
            Outcome::Cut => "response cut",
            Outcome::Challenge(_) => "request challenged",
            Outcome::ChallengePassed(_) => "request let through (challenge passed)",
        }
    }

    /// The `reason` field: `access`'s, or what asked for a challenge.
    fn reason(self) -> Option<&'static str> {
        match self {
            Outcome::Access(reason) => Some(reason),
            Outcome::Challenge(reason) | Outcome::ChallengePassed(reason) => reason,
            _ => None,
        }
    }
}

/// One event's facts.
pub struct Record<'a> {
    pub outcome: Outcome,
    /// The status answered, or that would have been.
    pub status: u16,
    pub threshold: u32,
    pub client_ip: IpAddr,
    pub country: Option<[u8; 2]>,
    pub asn: Option<u32>,
    pub parts: &'a http::request::Parts,
    pub evaluation: Option<&'a Evaluation>,
}

pub fn write(log: &EventLog, compiled: &Compiled, record: &Record<'_>) {
    let level = match record.outcome {
        Outcome::LogOnly | Outcome::Scored => "warn",
        _ => "info",
    };
    let request_fields = |line: &mut String| {
        line.push_str(r#","country":""#);
        line.push_str(
            record
                .country
                .as_ref()
                .and_then(|c| std::str::from_utf8(c).ok())
                .unwrap_or("--"),
        );
        let _ = write!(line, r#"","asn":{},"user_agent":""#, record.asn.unwrap_or(0));
        json_escape(
            line,
            record
                .parts
                .headers
                .get(http::header::USER_AGENT)
                .and_then(|v| v.to_str().ok())
                .unwrap_or(""),
        );
        line.push('"');
    };
    let fields = |line: &mut String| {
        let _ = write!(
            line,
            r#","builtin":"{}","decision":"{}","status":{}"#,
            super::rules::BUILTIN_VERSION,
            record.outcome.decision(),
            record.status
        );
        if let Some(reason) = record.outcome.reason() {
            let _ = write!(line, r#","reason":"{reason}""#);
        }
        if let Some(evaluation) = record.evaluation {
            let _ = write!(
                line,
                r#","score":{},"threshold":{},"phase":"{}","hits":["#,
                evaluation.score + evaluation.shadow,
                record.threshold,
                evaluation.phase.name()
            );
            for (i, hit) in evaluation.hits.iter().enumerate() {
                let rule = &compiled.rules[hit.rule as usize];
                if i > 0 {
                    line.push(',');
                }
                line.push_str(r#"{"id":""#);
                json_escape(line, &rule.id);
                line.push('"');
                if let Some(number) = rule.number {
                    // The rule by number, where test tools look for it (go-ftw's `ruleId`).
                    let _ = write!(line, r#","ruleId":{number}"#);
                }
                line.push_str(r#","set":""#);
                json_escape(line, &rule.set);
                let _ = write!(
                    line,
                    r#"","score":{},"severity":"{}""#,
                    rule.score,
                    rule.severity.name()
                );
                if let Some(confidence) = rule.confidence {
                    let _ = write!(line, r#","confidence":"{}""#, confidence.name());
                }
                line.push_str(r#","tags":"#);
                strings(line, &rule.tags);
                if !rule.refs.is_empty() {
                    refs(line, &rule.refs);
                }
                line.push_str(r#","target":""#);
                json_escape(line, &hit.target);
                line.push_str(r#"","matched":""#);
                json_escape(line, &hit.matched);
                line.push_str("\"}");
            }
            line.push(']');
        } else {
            let _ = write!(line, r#","threshold":{}"#, record.threshold);
        }
    };
    log.record_with(
        level,
        record.outcome.message(),
        record.client_ip,
        record.parts,
        &request_fields,
        &fields,
    );
}

/// A JSON array of strings, written into `line`.
fn strings<T: AsRef<str>>(line: &mut String, items: &[T]) {
    line.push('[');
    for (i, item) in items.iter().enumerate() {
        if i > 0 {
            line.push(',');
        }
        line.push('"');
        json_escape(line, item.as_ref());
        line.push('"');
    }
    line.push(']');
}

/// `,"refs":{...}` with the lists that are not empty.
fn refs(line: &mut String, refs: &Refs) {
    line.push_str(r#","refs":{"#);
    let mut first = true;
    let mut key = |line: &mut String, name: &str| {
        if !first {
            line.push(',');
        }
        first = false;
        let _ = write!(line, r#""{name}":"#);
    };
    for (name, list) in [("cwe", &refs.cwe), ("capec", &refs.capec)] {
        if !list.is_empty() {
            key(line, name);
            strings(line, list);
        }
    }
    if !refs.crs.is_empty() {
        key(line, "crs");
        line.push('[');
        for (i, id) in refs.crs.iter().enumerate() {
            if i > 0 {
                line.push(',');
            }
            let _ = write!(line, "{id}");
        }
        line.push(']');
    }
    for (name, list) in [("cve", &refs.cve), ("urls", &refs.urls)] {
        if !list.is_empty() {
            key(line, name);
            strings(line, list);
        }
    }
    line.push('}');
}

#[cfg(test)]
mod tests {
    use super::super::engine::Hit;
    use super::super::rule::{Mode, Phase};
    use super::*;

    #[test]
    fn the_line_has_the_spec_shape() {
        let dir = tempfile::tempdir().unwrap();
        let log = EventLog::new(
            "ngfw",
            Some(&webfast_core::eventlog::LogConfig {
                output: "ngfw.log".into(),
            }),
            dir.path(),
        );
        let compiled = super::super::engine::tests::compiled(
            "rules:\n  - {id: wf-960-110, set: upload, phase: upload, severity: critical, confidence: high, targets: [upload.ext], operator: {equals_any: [php]}, tags: [OWASP_A04, upload], refs: {cwe: [CWE-434], capec: [], crs: [933110]}}\n  - {id: plain, phase: upload, targets: [upload.ext], operator: {equals_any: [exe]}}\n",
            Mode::Block,
        );
        let (parts, ()) = http::Request::post("/upload?x=1")
            .header("host", "www.example.com")
            .header("user-agent", "Mozilla/5.0 \"quoted\"")
            .body(())
            .unwrap()
            .into_parts();
        let mut evaluation = Evaluation::new();
        evaluation.score = 9;
        evaluation.phase = Phase::Upload;
        evaluation.hits.push(Hit {
            rule: 0,
            target: "upload.ext".into(),
            matched: "php".into(),
        });
        evaluation.hits.push(Hit {
            rule: 1,
            target: "upload.ext".into(),
            matched: "exe".into(),
        });
        write(
            &log,
            &compiled,
            &Record {
                outcome: Outcome::Block,
                status: 403,
                threshold: 5,
                client_ip: "203.0.113.7".parse().unwrap(),
                country: Some(*b"NL"),
                asn: Some(1136),
                parts: &parts,
                evaluation: Some(&evaluation),
            },
        );
        write(
            &log,
            &compiled,
            &Record {
                outcome: Outcome::Access("country"),
                status: 403,
                threshold: 5,
                client_ip: "203.0.113.7".parse().unwrap(),
                country: None,
                asn: None,
                parts: &parts,
                evaluation: None,
            },
        );
        webfast_core::accesslog::flush_all(std::time::Duration::from_secs(2));
        let text = std::fs::read_to_string(dir.path().join("ngfw.log")).unwrap();
        let mut lines = text.lines();
        let line: serde_json::Value = serde_json::from_str(lines.next().unwrap()).unwrap();
        assert_eq!(line["logger"], "ngfw");
        assert_eq!(line["msg"], "request refused");
        assert_eq!(line["builtin"], super::super::rules::BUILTIN_VERSION);
        assert_eq!(line["request"]["client_ip"], "203.0.113.7");
        assert_eq!(line["request"]["country"], "NL");
        assert_eq!(line["request"]["asn"], 1136);
        assert_eq!(line["request"]["method"], "POST");
        assert_eq!(line["request"]["host"], "www.example.com");
        assert_eq!(line["request"]["uri"], "/upload?x=1");
        assert_eq!(line["request"]["user_agent"], "Mozilla/5.0 \"quoted\"");
        assert_eq!(line["decision"], "block");
        assert_eq!(line["status"], 403);
        assert_eq!(line["score"], 9);
        assert_eq!(line["threshold"], 5);
        assert_eq!(line["phase"], "upload");
        assert_eq!(
            line["hits"],
            serde_json::json!([
                {"id": "wf-960-110", "ruleId": 960110, "set": "upload", "score": 5, "severity": "critical", "confidence": "high",
                 "tags": ["OWASP_A04", "upload"], "refs": {"cwe": ["CWE-434"], "crs": [933110]},
                 "target": "upload.ext", "matched": "php"},
                {"id": "plain", "set": "site", "score": 3, "severity": "medium", "tags": [],
                 "target": "upload.ext", "matched": "exe"}
            ]),
            "the refs' empty lists left out, no refs, confidence or number when the rule has none"
        );
        let line: serde_json::Value = serde_json::from_str(lines.next().unwrap()).unwrap();
        assert_eq!(line["decision"], "access");
        assert_eq!(line["reason"], "country");
        assert_eq!(line["request"]["country"], "--");
        assert!(line.get("hits").is_none());
    }
}
