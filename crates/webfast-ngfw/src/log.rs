//! The module's event lines (docs/ngfw.md "The log"), through webfast_core::eventlog's events: the
//! common head with the country, ASN, JA4 and User-Agent added to `request`, then the decision,
//! status, scores, phase and the hits. A hit's matched text and data go with their source
//! (src/source.rs), so the log policy hides a credential a rule matched in, and the output's
//! privacy (`log.privacy`, `log.matched`) applies to them.

use super::compile::Compiled;
use super::engine::Evaluation;
use super::rule::Refs;
use std::net::IpAddr;
use webfast_core::eventlog::{EventKind, EventLog, Field, Fields, Level};
use webfast_core::privacy::Source;

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
    /// The client's TLS fingerprint, written when known.
    pub ja4: Option<webfast_core::ja4::Ja4>,
    pub parts: &'a http::request::Parts,
    pub evaluation: Option<&'a Evaluation>,
}

/// What the module adds inside `request`: where the client is, and what it says it is.
const REQUEST: &[Field] = &[
    Field::public("country"),
    Field::public("asn"),
    Field::personal("ja4"),
    Field::personal("user_agent"),
];

/// A hit's references (a built-in rule's).
const REFS: &[Field] = &[
    Field::public("cwe"),
    Field::public("capec"),
    Field::public("crs"),
    Field::public("cve"),
    Field::public("urls"),
];

/// A hit: the rule and what it decided are public; what it matched, and an engine's words on the
/// match (`data`, the CRS's `logdata`), are the request's, classed by where they came from.
const HIT: &[Field] = &[
    Field::public("id"),
    Field::public("ruleId"),
    Field::public("set"),
    Field::public("score"),
    Field::public("severity"),
    Field::public("confidence"),
    Field::public("tags"),
    Field::object("refs", REFS),
    Field::public("msg"),
    Field::payload("data"),
    Field::public("target"),
    Field::payload("matched"),
];

const FIELDS: &[Field] = &[
    Field::public("builtin"),
    Field::public("decision"),
    Field::public("status"),
    Field::public("reason"),
    Field::public("score"),
    Field::public("threshold"),
    Field::public("phase"),
    Field::list("hits", HIT),
];

macro_rules! kinds {
    ($($name:ident: $msg:literal;)*) => {
        $(static $name: EventKind = EventKind { msg: $msg, request: REQUEST, fields: FIELDS };)*
    };
}

kinds! {
    REFUSED: "request refused";
    LET_THROUGH: "request let through (log_only)";
    SCORED: "request scored";
    REPLACED: "response replaced";
    CUT: "response cut";
    CHALLENGED: "request challenged";
    CHALLENGE_PASSED: "request let through (challenge passed)";
}

/// go-ftw's marker line (`log.test_marker`): the header's name, and its value as the request has
/// it.
static TEST_MARKER: EventKind = EventKind {
    msg: "test marker",
    request: &[],
    fields: &[Field::public("marker_header"), Field::payload("marker")],
};

impl Outcome {
    fn kind(self) -> &'static EventKind {
        match self {
            Outcome::Block | Outcome::Ban | Outcome::Access(_) => &REFUSED,
            Outcome::LogOnly => &LET_THROUGH,
            Outcome::Scored => &SCORED,
            Outcome::Leak => &REPLACED,
            Outcome::Cut => &CUT,
            Outcome::Challenge(_) => &CHALLENGED,
            Outcome::ChallengePassed(_) => &CHALLENGE_PASSED,
        }
    }
}

/// The marker line of go-ftw's request (`log.test_marker`).
pub fn marker(log: &EventLog, parts: &http::request::Parts, client_ip: IpAddr, header: &str, value: &str) {
    log.event(&TEST_MARKER, Level::Info, parts, client_ip, |e| {
        e.str("marker_header", header);
        e.value("marker", Source::Header(header), value);
    });
}

pub fn write(log: &EventLog, compiled: &Compiled, record: &Record<'_>) {
    let level = match record.outcome {
        Outcome::LogOnly | Outcome::Scored => Level::Warn,
        _ => Level::Info,
    };
    let request = |e: &mut Fields<'_>| {
        e.str(
            "country",
            record
                .country
                .as_ref()
                .and_then(|c| std::str::from_utf8(c).ok())
                .unwrap_or("--"),
        );
        e.u64("asn", u64::from(record.asn.unwrap_or(0)));
        if let Some(ja4) = &record.ja4 {
            e.str("ja4", ja4.as_str());
        }
        e.str(
            "user_agent",
            record
                .parts
                .headers
                .get(http::header::USER_AGENT)
                .and_then(|v| v.to_str().ok())
                .unwrap_or(""),
        );
    };
    let fields = |e: &mut Fields<'_>| {
        e.str("builtin", super::rules::BUILTIN_VERSION);
        e.str("decision", record.outcome.decision());
        e.u64("status", u64::from(record.status));
        if let Some(reason) = record.outcome.reason() {
            e.str("reason", reason);
        }
        if let Some(evaluation) = record.evaluation {
            e.u64("score", u64::from(evaluation.score + evaluation.shadow));
            e.u64("threshold", u64::from(record.threshold));
            e.str("phase", evaluation.phase.name());
            e.list("hits", |l| {
                for hit in &evaluation.hits {
                    l.item(|h| match &hit.engine {
                        Some(rule) => engine_hit(h, rule, hit),
                        None => builtin_hit(h, &compiled.rules[hit.rule as usize], hit),
                    });
                }
            });
        } else {
            e.u64("threshold", u64::from(record.threshold));
        }
    };
    log.event_with(
        record.outcome.kind(),
        level,
        record.parts,
        record.client_ip,
        request,
        fields,
    );
}

/// A hit of a built-in rule.
fn builtin_hit(h: &mut Fields<'_>, rule: &super::compile::CompiledRule, hit: &super::engine::Hit) {
    h.str("id", &rule.id);
    if let Some(number) = rule.number {
        // The rule by number, where test tools look for it (go-ftw's `ruleId`).
        h.u64("ruleId", number);
    }
    h.str("set", &rule.set);
    h.u64("score", u64::from(rule.score));
    h.str("severity", rule.severity.name());
    if let Some(confidence) = rule.confidence {
        h.str("confidence", confidence.name());
    }
    h.strs("tags", &rule.tags);
    if !rule.refs.is_empty() {
        refs(h, &rule.refs);
    }
    target_matched(h, hit);
}

/// A hit of a rule engine's rule (src/plugin.rs): its message in place of the built-in rules'
/// references, and its words on the match.
fn engine_hit(h: &mut Fields<'_>, rule: &super::plugin::EngineRule, hit: &super::engine::Hit) {
    h.str("id", &rule.id);
    if let Some(number) = rule.number {
        h.u64("ruleId", u64::from(number));
    }
    h.str("set", &rule.set);
    h.u64("score", u64::from(hit.score));
    h.str("severity", rule.severity.name());
    h.strs("tags", &rule.tags);
    if !rule.msg.is_empty() {
        h.str("msg", &rule.msg);
    }
    if let Some(data) = &hit.data {
        let source = hit.data_source.source(h.policy());
        h.value("data", source, data);
    }
    target_matched(h, hit);
}

fn target_matched(h: &mut Fields<'_>, hit: &super::engine::Hit) {
    h.str("target", &hit.target);
    let source = hit.source.source(h.policy());
    h.value("matched", source, &hit.matched);
}

/// `refs` with the lists that are not empty.
fn refs(h: &mut Fields<'_>, refs: &Refs) {
    h.object("refs", |r| {
        for (name, list) in [("cwe", &refs.cwe), ("capec", &refs.capec)] {
            if !list.is_empty() {
                r.strs(name, list);
            }
        }
        if !refs.crs.is_empty() {
            r.numbers("crs", refs.crs.iter().map(|&n| u64::from(n)));
        }
        for (name, list) in [("cve", &refs.cve), ("urls", &refs.urls)] {
            if !list.is_empty() {
                r.strs(name, list);
            }
        }
    });
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
            engine: None,
            score: 0,
            data: None,
            target: "upload.ext".into(),
            matched: "php".into(),
            source: crate::source::HitSource::Payload,
            data_source: crate::source::HitSource::Payload,
        });
        evaluation.hits.push(Hit {
            rule: 1,
            engine: None,
            score: 0,
            data: None,
            target: "upload.ext".into(),
            matched: "exe".into(),
            source: crate::source::HitSource::Payload,
            data_source: crate::source::HitSource::Payload,
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
                ja4: Some(webfast_core::ja4::fingerprint(
                    &webfast_core::ja4::Hello {
                        version: 0x0304,
                        sni: true,
                        ciphers: vec![0x1301],
                        alpn: Some(b"h2".to_vec()),
                        ..Default::default()
                    },
                    false,
                )),
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
                ja4: None,
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
        assert_eq!(
            line["request"]["ja4"].as_str().map(str::len),
            Some(36),
            "the fingerprint when known"
        );
        assert!(line["request"]["ja4"].as_str().unwrap().starts_with("t13d0100h2_"));
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
        assert!(line["request"].get("ja4").is_none(), "no field when unknown");
        assert!(line.get("hits").is_none());
    }
}
