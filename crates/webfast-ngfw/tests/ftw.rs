//! The go-ftw tests of tests/ftw/ run in process: what go-ftw does against a webfast binary in
//! CI (scripts/ftw-run.sh, ci/ftw/), here on a server booted by the core's test harness with the
//! filter loaded from ci/ftw's own filter files, and a backend that answers 200 to everything.
//!
//! Two passes, as in CI: `all` (ci/ftw/ngfw-all.yaml, every built-in set; the tests that
//! ci/ftw/ftw-all.yaml's `ignore` names are skipped) over every file, and `cve`
//! (ci/ftw/ngfw-cve.yaml, the cve set alone) over tests/ftw/rules/cve with nothing ignored.
//!
//! Each stage's request is sent as its `input` says (method, uri, headers, data; HTTP/1.1, on a
//! connection of its own) and its `output` checked: `status`, and `log.expect_ids` /
//! `log.no_expect_ids` against the `ruleId`s of the filter's log lines between two marker
//! requests (`X-CRS-Test`, the filter's `log.test_marker`), as go-ftw reads them.

use bytes::Bytes;
use http_body_util::{BodyExt, Full};
use hyper::body::Incoming;
use hyper_util::rt::TokioIo;
use regex::Regex;
use serde::Deserialize;
use std::collections::BTreeMap;
use std::convert::Infallible;
use std::net::SocketAddr;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Duration;
use tokio::net::TcpListener;
use webfast_core::config::Config;
use webfast_core::harness::{self, Server};
use webfast_core::module::{Composition, Module};
use webfast_ngfw::Ngfw;
use webfast_ngfw::response::NgfwResponses;

#[cfg(feature = "challenge")]
type ChallengeEndpoint = webfast_challenge::ChallengeEndpoint;
#[cfg(not(feature = "challenge"))]
type ChallengeEndpoint = ();

type Checks = (ChallengeEndpoint, (Option<Arc<Ngfw>>, ()));
type Inspectors = (NgfwResponses, ());

static MODULES: &[&dyn Module] = &[
    #[cfg(feature = "challenge")]
    &webfast_challenge::MODULE,
    &webfast_ngfw::MODULE,
];

fn hooks(config: &Config) -> (Checks, Inspectors) {
    (
        (
            #[cfg(feature = "challenge")]
            webfast_challenge::ChallengeEndpoint,
            #[cfg(not(feature = "challenge"))]
            (),
            (config.modules.get::<Ngfw>(), ()),
        ),
        (NgfwResponses, ()),
    )
}

fn composition() -> Composition<Checks, Inspectors> {
    Composition {
        modules: MODULES,
        hooks,
    }
}

/// The marker header, as ci/ftw's filter files and go-ftw's configuration name it.
const MARKER: &str = "X-CRS-Test";

// ------------------------------------------------------------------------ the format, as read

/// A go-ftw test file (ftw-tests-schema 2.3.0, the `stages` form); what it has beyond this is
/// left unread.
#[derive(Deserialize)]
struct File {
    rule_id: u64,
    tests: Vec<Test>,
}

#[derive(Deserialize)]
struct Test {
    test_id: u32,
    stages: Vec<Stage>,
}

#[derive(Deserialize)]
struct Stage {
    input: Input,
    #[serde(default)]
    output: Output,
}

#[derive(Deserialize)]
struct Input {
    #[serde(default = "get")]
    method: String,
    #[serde(default = "root")]
    uri: String,
    #[serde(default = "http11")]
    version: String,
    #[serde(default)]
    headers: BTreeMap<String, String>,
    #[serde(default)]
    data: Option<String>,
    #[serde(default)]
    encoded_request: Option<String>,
}

fn get() -> String {
    "GET".to_string()
}
fn root() -> String {
    "/".to_string()
}
fn http11() -> String {
    "HTTP/1.1".to_string()
}

#[derive(Deserialize, Default)]
struct Output {
    status: Option<u16>,
    #[serde(default)]
    log: Log,
}

#[derive(Deserialize, Default)]
struct Log {
    #[serde(default)]
    expect_ids: Vec<u64>,
    #[serde(default)]
    no_expect_ids: Vec<u64>,
}

#[cfg(feature = "libinjection")]
/// go-ftw's configuration, for its `testoverride.ignore`: test-id regexes and their reasons.
#[derive(Deserialize)]
struct FtwConfig {
    #[serde(default)]
    testoverride: TestOverride,
}

#[cfg(feature = "libinjection")]
#[derive(Deserialize, Default)]
struct TestOverride {
    #[serde(default)]
    ignore: BTreeMap<String, String>,
}

// ------------------------------------------------------------------------------ the server

fn crate_dir() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
}

/// The repository's ci/ftw, where the filter files and go-ftw's configurations are.
fn ci_ftw() -> PathBuf {
    crate_dir().join("../../ci/ftw")
}

/// A backend as albedo is: 200 with a short body to every request, and `POST /reflect` answers
/// as its JSON says (`status`, `headers`, `body`), for the examples of response rules.
async fn backend() -> SocketAddr {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move {
        while let Ok((stream, _)) = listener.accept().await {
            tokio::spawn(async move {
                let service = hyper::service::service_fn(|req: http::Request<Incoming>| async move {
                    if req.method() == http::Method::POST && req.uri().path() == "/reflect" {
                        let body = req
                            .into_body()
                            .collect()
                            .await
                            .map(|b| b.to_bytes())
                            .unwrap_or_default();
                        let spec: serde_json::Value = serde_json::from_slice(&body).unwrap_or_default();
                        let mut response = http::Response::builder().status(
                            spec["status"]
                                .as_u64()
                                .and_then(|s| u16::try_from(s).ok())
                                .unwrap_or(200),
                        );
                        if let Some(headers) = spec["headers"].as_object() {
                            for (name, value) in headers {
                                response = response.header(name.as_str(), value.as_str().unwrap_or(""));
                            }
                        }
                        let text = spec["body"].as_str().unwrap_or("").to_string();
                        return Ok::<_, Infallible>(response.body(Full::new(Bytes::from(text))).unwrap());
                    }
                    Ok(http::Response::new(Full::new(Bytes::from_static(b"ok"))))
                });
                let _ = hyper::server::conn::http1::Builder::new()
                    .serve_connection(TokioIo::new(stream), service)
                    .await;
            });
        }
    });
    addr
}

struct Pass {
    server: Server,
    log: PathBuf,
    _dir: tempfile::TempDir,
}

/// The server with the filter of `ci/ftw/ngfw-<pass>.yaml`, its log in a directory of its own
/// (the file's `log.output` is the container's path; here it is the directory's `ngfw.log`).
async fn start(pass: &str) -> Pass {
    let dir = tempfile::tempdir().unwrap();
    let text = std::fs::read_to_string(ci_ftw().join(format!("ngfw-{pass}.yaml"))).unwrap();
    assert!(
        text.contains("/var/log/web/ngfw.log"),
        "ngfw-{pass}.yaml: the log is not where it was"
    );
    let yaml = text.replace("/var/log/web/ngfw.log", "ngfw.log");
    let ngfw = Ngfw::load_str(&yaml, dir.path()).unwrap_or_else(|e| panic!("ngfw-{pass}.yaml: {e:#}"));
    let app = backend().await;
    let caddyfile = format!(
        "{{\n\tauto_https off\n\tadmin off\n}}\n\n:0 {{\n\treverse_proxy {app}\n\tlog {{\n\t\toutput discard\n\t}}\n}}\n"
    );
    let server = harness::start(composition(), &caddyfile, |config| {
        config.modules.insert(Arc::new(ngfw));
    })
    .await;
    Pass {
        server,
        log: dir.path().join("ngfw.log"),
        _dir: dir,
    }
}

// ------------------------------------------------------------------------------- the run

/// Every test file under `dir`, sorted by path.
fn files(dir: &Path) -> Vec<PathBuf> {
    let mut out = Vec::new();
    let mut stack = vec![dir.to_path_buf()];
    while let Some(d) = stack.pop() {
        for entry in std::fs::read_dir(&d).unwrap() {
            let path = entry.unwrap().path();
            if path.is_dir() {
                stack.push(path);
            } else if path.extension().is_some_and(|e| e == "yaml") {
                out.push(path);
            }
        }
    }
    out.sort();
    out
}

/// The `ruleId`s of the log's lines after the marker `start` up to the marker `end`.
fn ids_between(log: &str, start: &str, end: &str) -> Vec<u64> {
    let marker =
        |line: &serde_json::Value, value: &str| line["msg"] == "test marker" && line["marker"].as_str() == Some(value);
    let mut ids = Vec::new();
    let mut inside = false;
    for text in log.lines() {
        let Ok(line) = serde_json::from_str::<serde_json::Value>(text) else {
            continue;
        };
        if marker(&line, start) {
            inside = true;
            continue;
        }
        if marker(&line, end) {
            break;
        }
        if inside && let Some(hits) = line["hits"].as_array() {
            ids.extend(hits.iter().filter_map(|h| h["ruleId"].as_u64()));
        }
    }
    ids
}

/// Standard base64, padded or not; `None` for another character.
fn unbase64(text: &str) -> Option<Vec<u8>> {
    let value = |c: u8| match c {
        b'A'..=b'Z' => Some(c - b'A'),
        b'a'..=b'z' => Some(c - b'a' + 26),
        b'0'..=b'9' => Some(c - b'0' + 52),
        b'+' => Some(62),
        b'/' => Some(63),
        _ => None,
    };
    let mut out = Vec::new();
    let (mut bits, mut count) = (0u32, 0);
    for c in text.bytes().filter(|c| *c != b'=') {
        bits = (bits << 6) | u32::from(value(c)?);
        count += 6;
        if count >= 8 {
            count -= 8;
            out.push((bits >> count) as u8);
        }
    }
    Some(out)
}

/// The status of a raw response (`HTTP/1.x NNN`), 0 when the server answered nothing.
fn status_of(response: &[u8]) -> u16 {
    let line = response.split(|b| *b == b'\n').next().unwrap_or(&[]);
    std::str::from_utf8(line)
        .ok()
        .and_then(|l| l.split_whitespace().nth(1))
        .and_then(|s| s.parse().ok())
        .unwrap_or(0)
}

/// A request for a marker line: what go-ftw sends before and after a stage.
async fn mark(server: &Server, value: &str) {
    // A User-Agent and an Accept, so that the marker's own request scores nothing.
    let headers = [(MARKER, value), ("user-agent", "go-ftw marker"), ("accept", "*/*")];
    server.get("/status/200", &headers).await;
}

/// Runs every test of `dir` but the ignored ones; the failures, one line each.
async fn run(pass: &str, dir: &Path, ignore: &[(Regex, String)]) -> (usize, usize, Vec<String>) {
    let p = start(pass).await;
    let (mut ran, mut skipped, mut failed) = (0, 0, Vec::new());
    let mut mark_index = 0u32;
    for path in files(dir) {
        let name = path.strip_prefix(crate_dir()).unwrap_or(&path).display().to_string();
        let file: File = webfast_core::yaml::from_str(&std::fs::read_to_string(&path).unwrap())
            .unwrap_or_else(|e| panic!("{name}: {e}"));
        for test in &file.tests {
            let id = format!("{}-{}", file.rule_id, test.test_id);
            if ignore.iter().any(|(re, _)| re.is_match(&id)) {
                skipped += 1;
                continue;
            }
            ran += 1;
            for (n, stage) in test.stages.iter().enumerate() {
                let input = &stage.input;
                let at = format!("{name} {id} stage {}", n + 1);
                if input.encoded_request.is_none() {
                    assert_eq!(
                        input.version, "HTTP/1.1",
                        "{at}: only HTTP/1.1 is sent from the fields here"
                    );
                }
                let wants_log = !stage.output.log.expect_ids.is_empty() || !stage.output.log.no_expect_ids.is_empty();
                mark_index += 1;
                let (start, end) = (format!("{pass}-{mark_index}-start"), format!("{pass}-{mark_index}-end"));
                if wants_log {
                    mark(&p.server, &start).await;
                }
                let got = match &input.encoded_request {
                    // The bytes as they are, on a connection of their own; 0 for no answer.
                    Some(encoded) => {
                        let bytes = unbase64(encoded).unwrap_or_else(|| panic!("{at}: encoded_request is not base64"));
                        status_of(&harness::raw(p.server.addr, &bytes).await)
                    }
                    None => {
                        let headers: Vec<(&str, &str)> =
                            input.headers.iter().map(|(k, v)| (k.as_str(), v.as_str())).collect();
                        let body = input.data.as_deref().unwrap_or("").as_bytes();
                        p.server
                            .send(&input.method, &input.uri, &headers, body)
                            .await
                            .status
                            .as_u16()
                    }
                };
                if let Some(status) = stage.output.status
                    && got != status
                {
                    failed.push(format!("{at}: status {got} where {status} was expected"));
                }
                if wants_log {
                    mark(&p.server, &end).await;
                    let wanted = format!("\"marker\":\"{end}\"");
                    harness::wait_for_line(&p.log, Duration::from_secs(5), |l| l.contains(&wanted)).await;
                    let log = std::fs::read_to_string(&p.log).unwrap();
                    let ids = ids_between(&log, &start, &end);
                    for want in &stage.output.log.expect_ids {
                        if !ids.contains(want) {
                            failed.push(format!("{at}: no {want} in the log ({ids:?})"));
                        }
                    }
                    for not in &stage.output.log.no_expect_ids {
                        if ids.contains(not) {
                            failed.push(format!("{at}: {not} in the log"));
                        }
                    }
                }
            }
        }
    }
    p.server.shutdown().await;
    (ran, skipped, failed)
}

#[cfg(feature = "libinjection")]
fn ignored(pass: &str) -> Vec<(Regex, String)> {
    let text = std::fs::read_to_string(ci_ftw().join(format!("ftw-{pass}.yaml"))).unwrap();
    let config: FtwConfig = webfast_core::yaml::from_str(&text).unwrap();
    config
        .testoverride
        .ignore
        .into_iter()
        .map(|(re, reason)| {
            (
                Regex::new(&re).unwrap_or_else(|e| panic!("ftw-{pass}.yaml: {re}: {e}")),
                reason,
            )
        })
        .collect()
}

fn report(pass: &str, (ran, skipped, failed): (usize, usize, Vec<String>)) {
    assert!(ran > 0, "{pass}: no test ran");
    assert!(
        failed.is_empty(),
        "{pass}: {} of {ran} tests failed ({skipped} ignored):\n{}",
        failed.len(),
        failed.join("\n")
    );
}

/// Every built-in set, as the filter ships: every file of tests/ftw, ftw-all.yaml's ignores
/// skipped (each with its reason there).
#[cfg(feature = "libinjection")]
#[tokio::test(flavor = "multi_thread")]
async fn the_ftw_tests_pass_with_every_built_in_set() {
    let ignore = ignored("all");
    assert!(
        ignore.iter().all(|(_, reason)| !reason.trim().is_empty()),
        "an ignore without a reason"
    );
    report("all", run("all", &crate_dir().join("tests/ftw"), &ignore).await);
}

/// The cve set alone: its files, nothing ignored, so every cve rule fires on its case.
#[tokio::test(flavor = "multi_thread")]
async fn the_cve_ftw_tests_pass_with_the_cve_set_alone() {
    report("cve", run("cve", &crate_dir().join("tests/ftw/rules/cve"), &[]).await);
}
