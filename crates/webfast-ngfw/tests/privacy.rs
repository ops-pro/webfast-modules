//! The filter's lines under webfast's log policy (webfast's docs/logging.md, "How it is checked"):
//! requests carrying known secrets in the places a rule may match them, and what the lines show.
//! A test binary of its own: the policy is the process's, put in place by the server's start from
//! the Caddyfile's `log_policy`, which another test's server would replace.

use std::path::Path;
use std::sync::Arc;
use std::time::Duration;
use webfast_core::config::Config;
use webfast_core::harness::{self, Server};
use webfast_core::module::{Composition, Module};
use webfast_ngfw::Ngfw;
use webfast_ngfw::response::NgfwResponses;

type Checks = (Option<Arc<Ngfw>>, ());
type Inspectors = (NgfwResponses, ());

static MODULES: &[&dyn Module] = &[&webfast_ngfw::MODULE];

fn hooks(config: &Config) -> (Checks, Inspectors) {
    ((config.modules.get::<Ngfw>(), ()), (NgfwResponses, ()))
}

/// A browser-like User-Agent and Accept: the built-in rules for their absence stay out of it.
const BROWSER: [(&str, &str); 2] = [("user-agent", "Mozilla/5.0 (webfast test)"), ("accept", "*/*")];

async fn start(yaml: &str, base: &Path) -> Server {
    let ngfw = Ngfw::load_str(yaml, base).unwrap_or_else(|e| panic!("the module did not load: {e:#}"));
    let text = r#"{
	auto_https off
	admin off
	log_policy {
		secret_params canary_token
	}
}

:0 {
	respond "ok"
	log {
		output discard
	}
}
"#;
    let composition = Composition {
        modules: MODULES,
        hooks,
    };
    harness::start(composition, text, |config| {
        config.modules.insert(Arc::new(ngfw));
    })
    .await
}

async fn send(server: &Server, method: &str, path: &str, headers: &[(&str, &str)], body: &[u8]) {
    let mut all: Vec<(&str, &str)> = BROWSER.to_vec();
    all.extend_from_slice(headers);
    server.send(method, path, &all, body).await;
}

async fn line(path: &Path, matches: impl Fn(&str) -> bool) -> serde_json::Value {
    let line = harness::wait_for_line(path, Duration::from_secs(3), matches).await;
    serde_json::from_str(&line).unwrap_or_else(|e| panic!("not JSON ({e}): {line}"))
}

/// Each secret matched by a rule — a token's query parameter (alone, in the query string read
/// whole, in a `Referer`), `Authorization`, a cookie, a form's and a JSON body's password — is in
/// no line, nor in the URI of one; a value from a place that holds no secret is shown, and the
/// output's own privacy hashes what is personal.
#[tokio::test]
async fn a_secret_a_rule_matched_is_in_no_line() {
    let dir = tempfile::tempdir().unwrap();
    let rule = |id: &str, phase: &str, target: &str| {
        format!(
            "  - {{id: {id}, phase: {phase}, severity: high, targets: [{target}], operator: {{contains_any: [canary]}}, action: block}}\n"
        )
    };
    let mut rules = String::from("rules:\n");
    rules += &rule("canary-param", "head", "args.canary_token");
    rules += &rule("canary-headers", "head", "headers");
    rules += &rule("canary-cookie", "head", "cookies.sid");
    rules += &rule("canary-query", "head", "query");
    rules += &rule("canary-form", "body", "args");
    rules += &rule("canary-json", "body", "body.json");
    std::fs::write(dir.path().join("site.yaml"), rules).unwrap();
    let yaml =
        "mode: log_only\nrules:\n  include: [site.yaml]\nlog:\n  output: ngfw.log\n  privacy: { personal: hash }\n";
    let server = start(yaml, dir.path()).await;
    let log = dir.path().join("ngfw.log");

    send(&server, "GET", "/a?q=1&canary_token=canaryT1", &[], b"").await;
    line(&log, |l| l.contains("canary-param") && l.contains("canary-query")).await;
    send(&server, "GET", "/b", &[("authorization", "Bearer canaryA2")], b"").await;
    line(&log, |l| l.contains("\"/b\"")).await;
    send(&server, "GET", "/c", &[("cookie", "sid=canaryC3")], b"").await;
    line(&log, |l| l.contains("canary-cookie")).await;
    send(
        &server,
        "GET",
        "/d",
        &[("referer", "https://example.com/r?canary_token=canaryR4")],
        b"",
    )
    .await;
    line(&log, |l| l.contains("\"/d\"")).await;
    let form = [("content-type", "application/x-www-form-urlencoded")];
    send(&server, "POST", "/e", &form, b"user=a&password=canaryP5").await;
    line(&log, |l| l.contains("canary-form")).await;
    let json = [("content-type", "application/json")];
    send(
        &server,
        "POST",
        "/f",
        &json,
        br#"{"user":{"name":"a","password":"canaryJ6"}}"#,
    )
    .await;
    line(&log, |l| l.contains("canary-json")).await;
    // A value from a place that holds no secret: shown as matched.
    send(&server, "GET", "/g?q=canaryOK", &[], b"").await;
    let shown = line(&log, |l| l.contains("canaryOK")).await;
    server.shutdown().await;

    let text = std::fs::read_to_string(&log).unwrap();
    for secret in ["canaryT1", "canaryA2", "canaryC3", "canaryR4", "canaryP5", "canaryJ6"] {
        assert!(!text.contains(secret), "{secret} is in the log:\n{text}");
    }
    for line in text.lines().filter(|l| l.contains("canary-")) {
        let line: serde_json::Value = serde_json::from_str(line).unwrap();
        for hit in line["hits"].as_array().unwrap() {
            if hit["id"].as_str().unwrap().starts_with("canary-") && line["request"]["uri"] != "/g?q=canaryOK" {
                assert_eq!(hit["matched"], "REDACTED", "{line}");
            }
        }
    }
    let hit = shown["hits"]
        .as_array()
        .unwrap()
        .iter()
        .find(|h| h["id"] == "canary-query")
        .unwrap();
    assert_eq!(hit["matched"], "canary", "{shown}");
    assert_eq!(shown["request"]["uri"], "/g?q=canaryOK");
    // `personal: hash` in this output: the address and the User-Agent as hashes, the id kept.
    assert!(
        shown["request"]["client_ip"].as_str().unwrap().starts_with("h:"),
        "{shown}"
    );
    assert!(
        shown["request"]["user_agent"].as_str().unwrap().starts_with("h:"),
        "{shown}"
    );
    assert_eq!(shown["request"]["id"].as_str().map(str::len), Some(32), "{shown}");
}
