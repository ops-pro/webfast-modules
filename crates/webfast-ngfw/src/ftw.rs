//! The go-ftw files of tests/ftw/, written from their sources (ftw-tests-schema 2.3.0, the
//! `stages` form go-ftw 2.6.2 reads): each built-in rule's `examples` (rules/*.yaml) as
//! tests/ftw/rules/<set>/<number>.yaml, and the corpus lists (tests/corpus/*.txt) as
//! tests/ftw/corpus/<list>.yaml. `the_ftw_tests_are_current` keeps the files in step with the
//! sources; `UPDATE_FTW_TESTS=1 cargo test -p webfast-ngfw --lib ftw` writes them.
//!
//! A rule's example that is a value is put in each place a request has for the rule's targets
//! (a query parameter with a space as `%20` and as `+`, a cookie, a header, the path for a value
//! that starts with `/`, a form body, the raw body as text, a JSON body), each a stage of one test; an example written as a request is one stage, sent as
//! it is. A `hit` stage expects the rule's number in the log (`expect_ids`), a `pass` stage
//! expects it absent (`no_expect_ids`). A corpus value is a query parameter both ways and a cookie,
//! expecting 403 (payloads) or 200 (benign values) from the whole filter.

use super::detect::corpus::{BENIGN, BYPASS, SQLI, XSS};
use super::detect::tests::query_encoded;
use super::rule::{Example, ExampleRequest, Phase, Rule, RulesFile, Target, number_of};
use super::rules::SETS;
use std::collections::BTreeMap;
use std::fmt::Write;
use std::path::{Path, PathBuf};

/// What a browser sends besides the value, as the corpus test in engine.rs sends it: without
/// them the protocol set's notices on a missing User-Agent and Accept would add to every score.
const BROWSER: [(&str, &str); 2] = [
    (
        "user-agent",
        "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/130.0 Safari/537.36",
    ),
    ("accept", "text/html,application/xhtml+xml,*/*;q=0.8"),
];

const HOST: &str = "www.example.com";

/// The `rule_id` of the corpus files, about no one rule: section 999 has none.
const CORPUS: [(&str, u64, u16, &str); 4] = [
    (
        "benign",
        999002,
        200,
        "What honest clients send: the whole filter lets each value through.",
    ),
    (
        "bypass",
        999003,
        403,
        "Known WAF evasions: the built-in sets together refuse each one (a regression set).",
    ),
    (
        "sqli",
        999004,
        403,
        "SQL injection: the built-in sets together refuse each payload.",
    ),
    (
        "xss",
        999005,
        403,
        "Cross-site scripting: the built-in sets together refuse each payload.",
    ),
];

const GENERATED: &str = "# Written by src/ftw.rs from its source (a rule's `examples`, a list of tests/corpus/): edit\n# that, then `UPDATE_FTW_TESTS=1 cargo test -p webfast-ngfw --lib ftw`.\n";

/// One request of a stage.
struct Stage {
    place: String,
    method: String,
    uri: String,
    headers: Vec<(String, String)>,
    data: Option<String>,
    /// A raw request's bytes, base64 (go-ftw's `encoded_request`): sent in place of the fields.
    encoded: Option<String>,
    status: Option<u16>,
    expect: Vec<u64>,
    no_expect: Vec<u64>,
}

impl Stage {
    fn new(place: &str, method: &str, uri: String, headers: Vec<(String, String)>, data: Option<String>) -> Stage {
        let mut all = vec![("host".to_string(), HOST.to_string())];
        all.retain(|(k, _)| !headers.iter().any(|(h, _)| h.eq_ignore_ascii_case(k)));
        all.extend(headers);
        Stage {
            place: place.to_string(),
            method: method.to_string(),
            uri,
            headers: all,
            data,
            encoded: None,
            status: None,
            expect: Vec::new(),
            no_expect: Vec::new(),
        }
    }
}

struct Test {
    desc: String,
    stages: Vec<Stage>,
}

fn browser_with(extra: &[(&str, String)]) -> Vec<(String, String)> {
    let mut headers: Vec<(String, String)> = BROWSER
        .iter()
        .filter(|(k, _)| !extra.iter().any(|(e, _)| e.eq_ignore_ascii_case(k)))
        .map(|(k, v)| (k.to_string(), v.to_string()))
        .collect();
    headers.extend(extra.iter().map(|(k, v)| (k.to_string(), v.clone())));
    headers
}

fn form() -> Vec<(String, String)> {
    browser_with(&[("content-type", "application/x-www-form-urlencoded".to_string())])
}

/// The JSON object a pointer names, the value at its end: `/a/b` → `{"a":{"b":value}}`.
fn json_at(pointer: &str, value: &str) -> String {
    let mut json = serde_json::Value::String(value.to_string());
    for key in pointer
        .trim_start_matches('/')
        .split('/')
        .filter(|k| !k.is_empty())
        .rev()
    {
        let key = key.replace("~1", "/").replace("~0", "~");
        let mut object = serde_json::Map::new();
        object.insert(key, json);
        json = serde_json::Value::Object(object);
    }
    if !json.is_object() {
        let mut object = serde_json::Map::new();
        object.insert("v".to_string(), json);
        json = serde_json::Value::Object(object);
    }
    json.to_string()
}

/// The stages a value takes for the rule's targets; an error for a target a value has no place
/// for (the rule's examples are written as requests then).
fn value_stages(rule: &Rule, value: &str) -> Result<Vec<Stage>, String> {
    let control = value.chars().any(|c| c.is_control());
    let body_too = rule.phase == Phase::Body || rule.targets.iter().any(|t| matches!(t, Target::Body));
    let mut stages: Vec<Stage> = Vec::new();
    let mut push = |stage: Stage| {
        if !stages.iter().any(|s| s.place == stage.place) {
            stages.push(stage);
        }
    };
    for target in &rule.targets {
        match target {
            Target::Args | Target::Query | Target::Arg(_) => {
                let name = match target {
                    Target::Arg(n) => query_encoded(n, false),
                    _ => "v".to_string(),
                };
                for (place, plus) in [("query, spaces as %20", false), ("query, spaces as +", true)] {
                    push(Stage::new(
                        place,
                        "GET",
                        format!("/p?{name}={}", query_encoded(value, plus)),
                        browser_with(&[]),
                        None,
                    ));
                }
                if body_too {
                    push(Stage::new(
                        "form body",
                        "POST",
                        "/p".to_string(),
                        form(),
                        Some(format!("{name}={}", query_encoded(value, true))),
                    ));
                }
            }
            Target::ArgsNames => push(Stage::new(
                "query parameter name",
                "GET",
                format!("/p?{}=1", query_encoded(value, false)),
                browser_with(&[]),
                None,
            )),
            Target::Cookies | Target::Cookie(_) => {
                let name = match target {
                    Target::Cookie(n) => n.clone(),
                    _ => "c".to_string(),
                };
                push(Stage::new(
                    "cookie",
                    "GET",
                    "/p".to_string(),
                    browser_with(&[("cookie", format!("{name}={}", query_encoded(value, false)))]),
                    None,
                ));
            }
            Target::CookiesNames => push(Stage::new(
                "cookie name",
                "GET",
                "/p".to_string(),
                browser_with(&[("cookie", format!("{}=1", query_encoded(value, false)))]),
                None,
            )),
            Target::Headers | Target::Header(_) | Target::Ua | Target::Host if !control => {
                let name = match target {
                    Target::Header(n) => n.clone(),
                    Target::Ua => "user-agent".to_string(),
                    Target::Host => "host".to_string(),
                    _ => "x-example".to_string(),
                };
                push(Stage::new(
                    &format!("header {name}"),
                    "GET",
                    "/p".to_string(),
                    browser_with(&[(name.as_str(), value.to_string())]),
                    None,
                ));
            }
            Target::Headers | Target::Header(_) | Target::Ua | Target::Host => {}
            // A path is a value that starts with `/`; another value has no place there.
            Target::Path | Target::PathRaw if value.starts_with('/') && !control => {
                push(Stage::new("path", "GET", value.to_string(), browser_with(&[]), None));
            }
            Target::Path | Target::PathRaw => {}
            Target::Method => push(Stage::new("method", value, "/p".to_string(), browser_with(&[]), None)),
            // The body as text: the value itself, in a type the filter reads as text.
            Target::Body => push(Stage::new(
                "raw body",
                "POST",
                "/p".to_string(),
                browser_with(&[("content-type", "text/xml".to_string())]),
                Some(value.to_string()),
            )),
            Target::BodyJson | Target::BodyJsonPointer(_) => {
                let pointer = match target {
                    Target::BodyJsonPointer(p) => p.as_str(),
                    _ => "/v",
                };
                push(Stage::new(
                    "JSON body",
                    "POST",
                    "/p".to_string(),
                    browser_with(&[("content-type", "application/json".to_string())]),
                    Some(json_at(pointer, value)),
                ));
            }
            other => {
                return Err(format!(
                    "a value has no place for {other}: write the example as a request"
                ));
            }
        }
    }
    if stages.is_empty() {
        return Err("no target of the rule has a place for this value".to_string());
    }
    Ok(stages)
}

/// Standard base64 with padding, as go-ftw's `encoded_request` takes it.
pub(crate) fn base64(bytes: &[u8]) -> String {
    const ABC: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let mut out = String::with_capacity(bytes.len().div_ceil(3) * 4);
    for chunk in bytes.chunks(3) {
        let n = (u32::from(chunk[0]) << 16)
            | (u32::from(*chunk.get(1).unwrap_or(&0)) << 8)
            | u32::from(*chunk.get(2).unwrap_or(&0));
        for i in 0..4 {
            if i <= chunk.len() {
                out.push(ABC[((n >> (18 - 6 * i)) & 63) as usize] as char);
            } else {
                out.push('=');
            }
        }
    }
    out
}

/// The one stage of an example written as a request: its bytes as they are with `raw`; with
/// `response`, the request to the backend's `/reflect` that answers with it; with `status`, the
/// status expected.
fn request_stage(request: &ExampleRequest) -> Result<Stage, String> {
    let mut stage = if let Some(raw) = &request.raw {
        let only_raw = request.method == "GET"
            && request.uri == "/"
            && request.headers.is_empty()
            && request.body.is_none()
            && request.response.is_none();
        if !only_raw {
            return Err("a `raw` request has no method, uri, headers, body or response besides".to_string());
        }
        let mut stage = Stage::new("raw request", "GET", "/".to_string(), Vec::new(), None);
        stage.encoded = Some(base64(raw.as_bytes()));
        stage
    } else {
        fields_stage(request)
    };
    stage.status = request.status;
    Ok(stage)
}

fn fields_stage(request: &ExampleRequest) -> Stage {
    let headers: Vec<(String, String)> = request.headers.iter().map(|(k, v)| (k.clone(), v.clone())).collect();
    match &request.response {
        None => Stage::new(
            "request",
            &request.method,
            request.uri.clone(),
            headers,
            request.body.clone(),
        ),
        Some(response) => {
            let spec = serde_json::json!({
                "status": response.status,
                "headers": response.headers,
                "body": response.body,
            });
            let mut headers = headers;
            headers.push(("content-type".to_string(), "application/json".to_string()));
            Stage::new(
                "response from the backend",
                "POST",
                "/reflect".to_string(),
                headers,
                Some(spec.to_string()),
            )
        }
    }
}

fn rule_tests(rule: &Rule, number: u64) -> Result<Vec<Test>, String> {
    let mut tests = Vec::new();
    for (kind, examples) in [("hit", &rule.examples.hit), ("pass", &rule.examples.pass)] {
        for example in examples {
            // A fingerprint of the connection is the engine's test alone (`examples_on_the_connection`).
            if matches!(example, Example::Request(r) if r.ja4.is_some()) {
                continue;
            }
            let mut stages = match example {
                Example::Value(value) => value_stages(rule, value)?,
                Example::Request(request) => vec![request_stage(request)?],
            };
            for stage in &mut stages {
                if kind == "hit" {
                    stage.expect = vec![number];
                } else {
                    stage.no_expect = vec![number];
                }
            }
            let desc = match kind {
                "hit" => format!("{} matches", rule.id),
                _ => format!("{} lets it be", rule.id),
            };
            tests.push(Test { desc, stages });
        }
    }
    Ok(tests)
}

fn corpus_tests(values: &[&str], status: u16, what: &str) -> Vec<Test> {
    values
        .iter()
        .enumerate()
        .map(|(i, value)| {
            let stages = [("query, spaces as %20", false), ("query, spaces as +", true)]
                .into_iter()
                .map(|(place, plus)| {
                    Stage::new(
                        place,
                        "GET",
                        format!("/p?v={}", query_encoded(value, plus)),
                        browser_with(&[]),
                        None,
                    )
                })
                .chain([Stage::new(
                    "cookie",
                    "GET",
                    "/p".to_string(),
                    browser_with(&[("cookie", format!("c={}", query_encoded(value, false)))]),
                    None,
                )])
                .map(|mut s| {
                    s.status = Some(status);
                    s
                })
                .collect();
            Test {
                desc: format!("{what} {} of {}", i + 1, values.len()),
                stages,
            }
        })
        .collect()
}

/// A YAML string: JSON's double-quoted form, which YAML reads the same.
fn q(text: &str) -> String {
    serde_json::to_string(text).unwrap()
}

fn emit(name: &str, rule_id: u64, description: &str, tests: &[Test]) -> String {
    let mut out = String::from(GENERATED);
    let _ = writeln!(
        out,
        "meta:\n  author: \"webfast\"\n  description: {}\n  enabled: true\n  name: {}",
        q(description),
        q(name)
    );
    let _ = writeln!(out, "rule_id: {rule_id}\ntests:");
    for (i, test) in tests.iter().enumerate() {
        let _ = writeln!(out, "  - test_id: {}\n    desc: {}\n    stages:", i + 1, q(&test.desc));
        for s in &test.stages {
            let _ = writeln!(out, "      - description: {}\n        input:", q(&s.place));
            out.push_str("          dest_addr: \"127.0.0.1\"\n          port: 80\n");
            if let Some(encoded) = &s.encoded {
                let _ = writeln!(out, "          encoded_request: {}", q(encoded));
            } else {
                let _ = writeln!(
                    out,
                    "          method: {}\n          uri: {}\n          version: \"HTTP/1.1\"\n          headers:",
                    q(&s.method),
                    q(&s.uri)
                );
                for (k, v) in &s.headers {
                    let _ = writeln!(out, "            {}: {}", q(k), q(v));
                }
                if let Some(data) = &s.data {
                    let _ = writeln!(out, "          data: {}", q(data));
                }
            }
            out.push_str("        output:\n");
            if let Some(status) = s.status {
                let _ = writeln!(out, "          status: {status}");
            }
            if !s.expect.is_empty() || !s.no_expect.is_empty() {
                out.push_str("          log:\n");
                let ids = |v: &[u64]| v.iter().map(u64::to_string).collect::<Vec<_>>().join(", ");
                if !s.expect.is_empty() {
                    let _ = writeln!(out, "            expect_ids: [{}]", ids(&s.expect));
                }
                if !s.no_expect.is_empty() {
                    let _ = writeln!(out, "            no_expect_ids: [{}]", ids(&s.no_expect));
                }
            }
        }
    }
    out
}

/// The built-in rules, each with its set.
pub(crate) fn builtin_rules() -> Vec<(&'static str, Rule)> {
    SETS.iter()
        .flat_map(|(set, text)| {
            let file: RulesFile =
                webfast_core::yaml::from_str(text).unwrap_or_else(|e| panic!("rules/{set}.yaml: {e}"));
            file.rules.into_iter().map(move |rule| (*set, rule))
        })
        .collect()
}

/// Every file, by its path under tests/ftw/.
pub(crate) fn files() -> Result<BTreeMap<PathBuf, String>, String> {
    let mut files = BTreeMap::new();
    for (set, rule) in builtin_rules() {
        if rule.examples.is_empty() {
            continue;
        }
        let number = number_of(&rule.id).ok_or_else(|| format!("{}: a rule with examples has a number", rule.id))?;
        let tests = rule_tests(&rule, number).map_err(|e| format!("{}: {e}", rule.id))?;
        // Examples on the connection alone: nothing for go-ftw.
        if tests.is_empty() {
            continue;
        }
        let description = rule.msg.clone().unwrap_or_else(|| rule.id.clone());
        files.insert(
            Path::new("rules").join(set).join(format!("{number}.yaml")),
            emit(&rule.id, number, &description, &tests),
        );
    }
    for (name, number, status, description) in CORPUS {
        let values: &[&str] = match name {
            "benign" => &BENIGN,
            "bypass" => &BYPASS,
            "sqli" => &SQLI,
            _ => &XSS,
        };
        let what = if status == 200 { "Benign value" } else { "Payload" };
        files.insert(
            Path::new("corpus").join(format!("{name}.yaml")),
            emit(name, number, description, &corpus_tests(values, status, what)),
        );
    }
    Ok(files)
}

fn ftw_dir() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/ftw")
}

/// The YAML files under `dir`, by their path under it.
fn on_disk(dir: &Path) -> BTreeMap<PathBuf, String> {
    let mut found = BTreeMap::new();
    let mut stack = vec![dir.to_path_buf()];
    while let Some(d) = stack.pop() {
        let Ok(entries) = std::fs::read_dir(&d) else { continue };
        for entry in entries.flatten() {
            let path = entry.path();
            if path.is_dir() {
                stack.push(path);
            } else if path.extension().is_some_and(|e| e == "yaml") {
                let text = std::fs::read_to_string(&path).unwrap().replace("\r\n", "\n");
                found.insert(path.strip_prefix(dir).unwrap().to_path_buf(), text);
            }
        }
    }
    found
}

#[test]
fn the_ftw_tests_are_current() {
    let files = files().unwrap_or_else(|e| panic!("{e}"));
    let dir = ftw_dir();
    let disk = on_disk(&dir);
    if std::env::var_os("UPDATE_FTW_TESTS").is_some() {
        for path in disk.keys().filter(|p| !files.contains_key(*p)) {
            std::fs::remove_file(dir.join(path)).unwrap();
        }
        for (path, text) in &files {
            let target = dir.join(path);
            std::fs::create_dir_all(target.parent().unwrap()).unwrap();
            std::fs::write(target, text).unwrap();
        }
        return;
    }
    let mut wrong: Vec<String> = Vec::new();
    for (path, text) in &files {
        match disk.get(path) {
            None => wrong.push(format!("{} missing", path.display())),
            Some(t) if t != text => wrong.push(format!("{} differs", path.display())),
            _ => {}
        }
    }
    wrong.extend(
        disk.keys()
            .filter(|p| !files.contains_key(*p))
            .map(|p| format!("{} not from a source", p.display())),
    );
    assert!(
        wrong.is_empty(),
        "tests/ftw/ is out of date ({}): run `UPDATE_FTW_TESTS=1 cargo test -p webfast-ngfw --lib ftw`",
        wrong.join(", ")
    );
}

/// The files read back as YAML, each test with its stages; the numbers as the rules give them.
#[test]
fn the_written_files_read_back() {
    for (path, text) in files().unwrap() {
        let doc: serde_json::Value =
            webfast_core::yaml::from_str(&text).unwrap_or_else(|e| panic!("{}: {e}", path.display()));
        assert!(doc["rule_id"].as_u64().is_some_and(|n| n > 0), "{}", path.display());
        let tests = doc["tests"].as_array().unwrap();
        assert!(!tests.is_empty(), "{}", path.display());
        for test in tests {
            assert!(!test["stages"].as_array().unwrap().is_empty());
        }
    }
    assert_eq!(json_at("/a/b", "x"), r#"{"a":{"b":"x"}}"#);
    assert_eq!(base64(b""), "");
    assert_eq!(base64(b"f"), "Zg==");
    assert_eq!(base64(b"fo"), "Zm8=");
    assert_eq!(base64(b"foo"), "Zm9v");
    assert_eq!(base64(b"GET / HTTP/1.0\r\n\r\n"), "R0VUIC8gSFRUUC8xLjANCg0K");
}

/// The built-in rules that have no `hit` example yet: the debt this list keeps in sight. A rule
/// given one is taken off it (the test says which); a rule added without one fails.
///
/// Two have none to give over HTTP/1.1, their `pass` examples say why: wf-920-120 (a control
/// byte is a 400 from the server's parser first) and wf-920-170 (the parser settles a doubled
/// framing before the filter sees the headers).
const WITHOUT_EXAMPLES: &[&str] = &[
    "wf-920-120",
    "wf-920-170",
    "wf-913-100",
    "wf-913-200",
    "wf-913-210",
    "wf-913-220",
    "wf-913-230",
    "wf-920-100",
    "wf-920-130",
    "wf-920-140",
    "wf-920-150",
    "wf-920-160",
    "wf-920-180",
    "wf-920-190",
    "wf-920-200",
    "wf-920-210",
    "wf-920-220",
    "wf-920-230",
    "wf-920-300",
    "wf-920-310",
    "wf-920-400",
    "wf-920-410",
    "wf-920-440",
    "wf-920-520",
    "wf-930-100",
    "wf-930-110",
    "wf-930-120",
    "wf-931-100",
    "wf-931-110",
    "wf-932-100",
    "wf-932-110",
    "wf-932-120",
    "wf-933-100",
    "wf-933-110",
    "wf-933-115",
    "wf-933-120",
    "wf-933-130",
    "wf-933-140",
    "wf-933-150",
    "wf-941-100",
    "wf-941-110",
    "wf-941-120",
    "wf-941-130",
    "wf-941-140",
    "wf-941-150",
    "wf-941-160",
    "wf-941-170",
    "wf-942-100",
    "wf-942-110",
    "wf-942-120",
    "wf-942-130",
    "wf-942-140",
    "wf-942-150",
    "wf-942-160",
    "wf-942-170",
    "wf-942-180",
    "wf-942-190",
    "wf-942-200",
    "wf-944-100",
    "wf-944-110",
    "wf-944-120",
    "wf-950-100",
    "wf-950-110",
    "wf-950-120",
    "wf-950-130",
    "wf-950-140",
    "wf-950-150",
    "wf-950-900",
    "wf-960-100",
    "wf-960-105",
    "wf-960-110",
    "wf-960-120",
    "wf-960-130",
    "wf-960-140",
    "wf-960-150",
    "wf-960-160",
];

#[test]
fn every_built_in_rule_has_an_example_it_matches() {
    let rules = builtin_rules();
    let missing: Vec<&str> = rules
        .iter()
        .filter(|(_, r)| r.examples.hit.is_empty() && !WITHOUT_EXAMPLES.contains(&r.id.as_str()))
        .map(|(_, r)| r.id.as_str())
        .collect();
    assert!(missing.is_empty(), "rules without a `hit` example: {missing:?}");
    let paid: Vec<&str> = WITHOUT_EXAMPLES
        .iter()
        .copied()
        .filter(|id| rules.iter().any(|(_, r)| r.id == *id && !r.examples.hit.is_empty()))
        .collect();
    assert!(
        paid.is_empty(),
        "take these off WITHOUT_EXAMPLES, they have examples now: {paid:?}"
    );
    let unknown: Vec<&str> = WITHOUT_EXAMPLES
        .iter()
        .copied()
        .filter(|id| !rules.iter().any(|(_, r)| r.id == *id))
        .collect();
    assert!(unknown.is_empty(), "WITHOUT_EXAMPLES names no rule: {unknown:?}");
}

/// The examples that need the connection's TLS fingerprint, which go-ftw cannot choose: each
/// sent through the engine with every built-in set, its `ja4` as the connection's, and the rule
/// found among the hits (`hit`) or not (`pass`).
#[test]
fn the_examples_on_the_connection_hold() {
    use super::compile::compile;
    use super::config::{RulesConfig, compose};
    use super::engine::{Evaluation, Input};
    use super::rule::{Mode, Phase};
    let (rules, _) = compose(&RulesConfig::default(), Path::new("."), None).unwrap();
    let compiled = compile(&rules, Mode::Block, &[]).unwrap();
    let mut ran = 0;
    let mut wrong = Vec::new();
    for (_, rule) in builtin_rules() {
        for (hit, list) in [(true, &rule.examples.hit), (false, &rule.examples.pass)] {
            for example in list {
                let Example::Request(request) = example else { continue };
                let Some(text) = &request.ja4 else { continue };
                let ja4 = webfast_core::ja4::Ja4::parse(text).unwrap_or_else(|| panic!("{}: ja4 {text:?}", rule.id));
                let mut builder = http::Request::builder()
                    .method(request.method.as_str())
                    .uri(&request.uri);
                if !request.headers.keys().any(|k| k.eq_ignore_ascii_case("host")) {
                    builder = builder.header("host", HOST);
                }
                for (name, value) in &request.headers {
                    builder = builder.header(name, value);
                }
                let (parts, ()) = builder.body(()).unwrap().into_parts();
                let input = Input {
                    parts: &parts,
                    client_ip: "203.0.113.7".parse().unwrap(),
                    country: None,
                    asn: None,
                    sni: None,
                    ja4: Some(ja4),
                    body: None,
                    response: None,
                    hidden: &[],
                };
                let mut evaluation = Evaluation::new();
                evaluation.run_phase(&compiled, Phase::Connection, &input, 200);
                evaluation.run_phase(&compiled, Phase::Head, &input, 200);
                let found = evaluation
                    .hits
                    .iter()
                    .any(|h| compiled.rules[h.rule as usize].id == rule.id);
                ran += 1;
                if found != hit {
                    let what = if hit { "does not match" } else { "matches" };
                    wrong.push(format!(
                        "{} {what} {} {} over {text}",
                        rule.id, request.method, request.uri
                    ));
                }
            }
        }
    }
    assert!(ran > 0, "no example on the connection");
    assert!(wrong.is_empty(), "{}", wrong.join("\n"));
}
