//! The NGFW request filter end to end (docs/ngfw.md, Tests): a server booted by the core's test
//! harness with the module's instance put on the configuration, as `Module::load` would from
//! WEB_NGFW_CONFIG, and a stub upstream that echoes the request's headers. Requests refused by the
//! built-in sets, let through, `log_only` writing its line, the access lists, honeypots and the ban
//! list, `action: header`, a leaking upstream response replaced through `handle_errors`, a site's
//! rule replacing a built-in one, 444, `match.hosts`; with the challenge built, `action: challenge`,
//! `mode: challenge` and `ban.then: challenge`.

use bytes::Bytes;
use http::Request;
use http_body_util::{BodyExt, Full};
use hyper::body::Incoming;
use hyper_util::rt::TokioIo;
use std::convert::Infallible;
use std::net::SocketAddr;
use std::path::Path;
use std::sync::Arc;
use std::time::Duration;
use tokio::net::TcpListener;
use webfast_core::config::Config;
use webfast_core::harness::{self, Response as Got, Server};
use webfast_core::module::{Composition, Module};
use webfast_ngfw::Ngfw;
use webfast_ngfw::response::NgfwResponses;

/// The composition the webfast binary has, as far as these tests go: the browser challenge's
/// endpoint first (when this crate is built with it), then the filter's instance from
/// `config.modules`; the filter's response phase on proxied responses.
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

/// A browser-like User-Agent and Accept, so that the two `notice` rules for their absence
/// (wf-920-300, wf-920-310) do not take part in what a test measures.
const UA: &str = "Mozilla/5.0 (webfast test)";
const SCANNER: &str = "Mozilla/5.0 nikto/2.1.6";
const LEAK: &str =
    "<html><body>Fatal error: Uncaught Error: Call to undefined function in /srv/app/x.php on line 3</body></html>";

fn site() -> tempfile::TempDir {
    harness::site(&[("en/index.html", "<!doctype html><title>Home</title>")])
}

/// Upstream stub: `/api/leak` answers a PHP error page with 200; everything else a JSON echo of
/// the request (`uri`, and every header under `headers`, lowercased names).
async fn upstream() -> SocketAddr {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move {
        loop {
            let Ok((stream, _)) = listener.accept().await else {
                break;
            };
            tokio::spawn(async move {
                let service = hyper::service::service_fn(|req: Request<Incoming>| async move {
                    if req.uri().path() == "/api/leak" {
                        let response = http::Response::builder()
                            .header("content-type", "text/html; charset=utf-8")
                            .header("server", "Apache/2.4.57 (Debian)")
                            .body(
                                Full::new(Bytes::from(LEAK))
                                    .map_err(|never| match never {})
                                    .boxed_unsync(),
                            )
                            .unwrap();
                        return Ok::<_, Infallible>(response);
                    }
                    let mut headers = serde_json::Map::new();
                    for (name, value) in req.headers() {
                        headers.insert(
                            name.as_str().to_string(),
                            serde_json::Value::String(value.to_str().unwrap_or("").to_string()),
                        );
                    }
                    let (parts, body) = req.into_parts();
                    let body = body.collect().await.map(|b| b.to_bytes().len()).unwrap_or(0);
                    let echo = serde_json::json!({
                        "method": parts.method.as_str(),
                        "uri": parts.uri.to_string(),
                        "body_len": body,
                        "headers": headers,
                    });
                    let response = http::Response::builder()
                        .header("content-type", "application/json")
                        .header("x-upstream", "1")
                        .body(
                            Full::new(Bytes::from(echo.to_string()))
                                .map_err(|never| match never {})
                                .boxed_unsync(),
                        )
                        .unwrap();
                    Ok(response)
                });
                let _ = hyper::server::conn::http1::Builder::new()
                    .serve_connection(TokioIo::new(stream), service)
                    .await;
            });
        }
    });
    addr
}

fn caddyfile(root: &Path, app: SocketAddr) -> String {
    format!(
        r#"{{
	auto_https off
	admin off
	servers {{
		trusted_proxies static private_ranges
		client_ip_headers X-Forwarded-For
	}}
}}

:0 {{
	root * {root}
	reverse_proxy /api/* {app}
	reverse_proxy /upload {app}
	file_server
	handle_errors 403 {{
		respond "refused {{err.status_code}}"
	}}
	handle_errors 5xx {{
		respond "leak {{err.status_code}}"
	}}
	log {{
		output discard
	}}
}}
"#,
        root = root.display().to_string().replace('\\', "/"),
    )
}

struct Harness {
    _site: tempfile::TempDir,
    server: Server,
}

fn module(yaml: &str, base: &Path) -> Ngfw {
    Ngfw::load_str(yaml, base).unwrap_or_else(|e| panic!("the module did not load: {e:#}\n{yaml}"))
}

/// The server with the module loaded from `yaml`, as WEB_NGFW_CONFIG would have it: the instance
/// goes into `config.modules`, where the composition takes it from.
async fn start(yaml: &str, base: &Path) -> Harness {
    let ngfw = module(yaml, base);
    let site = site();
    let app = upstream().await;
    let text = caddyfile(site.path(), app);
    let server = harness::start(composition(), &text, |config| {
        config.modules.insert(Arc::new(ngfw));
    })
    .await;
    Harness { _site: site, server }
}

/// What the upstream's echo says.
trait Echo {
    /// The value of a request header as the upstream saw it (`""`: absent).
    fn upstream_header(&self, name: &str) -> String;
}

impl Echo for Got {
    fn upstream_header(&self, name: &str) -> String {
        let json: serde_json::Value = serde_json::from_slice(&self.body)
            .unwrap_or_else(|_| panic!("not the upstream's echo: {} {}", self.status, self.text()));
        json["headers"][name].as_str().unwrap_or("").to_string()
    }
}

impl Harness {
    /// `headers` are added to a browser-like User-Agent and Accept unless they set their own.
    async fn send(&self, method: &str, path: &str, headers: &[(&str, &str)], body: &[u8]) -> Got {
        let mut all: Vec<(&str, &str)> = Vec::new();
        if !headers.iter().any(|(k, _)| k.eq_ignore_ascii_case("user-agent")) {
            all.push(("user-agent", UA));
        }
        if !headers.iter().any(|(k, _)| k.eq_ignore_ascii_case("accept")) {
            all.push(("accept", "*/*"));
        }
        all.extend_from_slice(headers);
        self.server.send(method, path, &all, body).await
    }

    async fn get(&self, path: &str, headers: &[(&str, &str)]) -> Got {
        self.send("GET", path, headers, b"").await
    }

    /// A multipart POST to `/upload` with one file part.
    async fn upload(&self, filename: &str, content_type: &str, data: &[u8]) -> Got {
        let mut body = Vec::new();
        body.extend_from_slice(b"------wf\r\n");
        body.extend_from_slice(
            format!("Content-Disposition: form-data; name=\"file\"; filename=\"{filename}\"\r\n").as_bytes(),
        );
        body.extend_from_slice(format!("Content-Type: {content_type}\r\n\r\n").as_bytes());
        body.extend_from_slice(data);
        body.extend_from_slice(b"\r\n------wf--\r\n");
        self.send(
            "POST",
            "/upload",
            &[("content-type", "multipart/form-data; boundary=----wf")],
            &body,
        )
        .await
    }

    async fn shutdown(self) {
        self.server.shutdown().await;
    }
}

fn header<'a>(got: &'a Got, name: &str) -> &'a str {
    got.header(name)
}

/// The first line of `path` that `matches`, within 3 s (the writer batches every 10 ms).
async fn log_line(path: &Path, matches: impl Fn(&str) -> bool) -> serde_json::Value {
    let line = harness::wait_for_line(path, Duration::from_secs(3), matches).await;
    serde_json::from_str(&line).unwrap_or_else(|e| panic!("not JSON ({e}): {line}"))
}

#[tokio::test]
async fn built_in_sets_refuse_scanners_probes_and_injection_and_let_clean_requests_through() {
    let dir = tempfile::tempdir().unwrap();
    let h = start("mode: block\n", dir.path()).await;

    // A clean page and a clean API request.
    let home = h.get("/en/", &[]).await;
    assert_eq!(home.status, 200, "{}", home.text());
    let hello = h.get("/api/echo?q=hello", &[]).await;
    assert_eq!(hello.status, 200, "{}", hello.text());
    assert_eq!(header(&hello, "x-upstream"), "1");

    // A scanner's User-Agent (wf-913-100, block).
    let scanner = h.get("/en/", &[("user-agent", SCANNER)]).await;
    assert_eq!(scanner.status, 403);
    assert_eq!(scanner.text(), "refused 403", "the refusal goes through handle_errors");

    // A probe for a dot-file (wf-913-210, block), with and without a file behind it.
    assert_eq!(h.get("/.env", &[]).await.status, 403);
    assert_eq!(h.get("/api/.env", &[]).await.status, 403);

    // SQL injection in the query (wf-942-100, critical: at the threshold).
    let sqli = h.get("/api/echo?q=1%20union%20select%20name%20from%20users", &[]).await;
    assert_eq!(sqli.status, 403, "{}", sqli.text());
    assert_eq!(sqli.text(), "refused 403");
    h.shutdown().await;
}

#[tokio::test]
async fn uploads_with_an_executable_extension_are_refused_and_images_pass() {
    let dir = tempfile::tempdir().unwrap();
    let h = start("mode: block\n", dir.path()).await;
    let png = b"\x89PNG\r\n\x1a\n\x00\x00\x00\x0dIHDR\x00\x00\x00\x01\x00\x00\x00\x01";

    // The double extension (wf-960-110, block), whatever the bytes and the declared type.
    let shell = h.upload("shot.php.jpg", "image/jpeg", png).await;
    assert_eq!(shell.status, 403, "{}", shell.text());
    assert_eq!(h.upload("shot.pHp", "image/png", png).await.status, 403, "case");
    assert_eq!(
        h.upload("shot.php;.jpg", "image/png", png).await.status,
        403,
        "a ; after the extension"
    );

    // An image whose bytes are an image goes through to the upstream, body intact.
    let image = h.upload("shot.jpg", "image/png", png).await;
    assert_eq!(image.status, 200, "{}", image.text());
    assert_eq!(header(&image, "x-upstream"), "1");
    let json: serde_json::Value = serde_json::from_slice(&image.body).unwrap();
    assert!(
        json["body_len"].as_u64().unwrap() > png.len() as u64,
        "the whole body reached the upstream"
    );

    // Declared an image, bytes a PHP script (wf-960-140 and wf-960-150 together pass the threshold).
    let polyglot = h
        .upload("shot.jpg", "image/jpeg", b"<?php system($_GET['c']); ?>")
        .await;
    assert_eq!(polyglot.status, 403, "{}", polyglot.text());
    h.shutdown().await;
}

#[tokio::test]
async fn log_only_lets_the_request_through_and_writes_the_line() {
    let dir = tempfile::tempdir().unwrap();
    let yaml = "mode: log_only\nlog:\n  output: ngfw.log\n  matched: 100\n";
    let h = start(yaml, dir.path()).await;

    let scanner = h.get("/api/echo?q=1", &[("user-agent", SCANNER)]).await;
    assert_eq!(scanner.status, 200, "{}", scanner.text());
    assert_eq!(header(&scanner, "x-upstream"), "1", "the request went on as it came");

    let line = log_line(&dir.path().join("ngfw.log"), |l| {
        l.contains("\"decision\":\"log_only\"")
    })
    .await;
    assert_eq!(line["logger"], "ngfw");
    assert_eq!(line["decision"], "log_only");
    assert_eq!(line["status"], 403, "what it would have got");
    assert_eq!(line["phase"], "head");
    assert_eq!(line["request"]["client_ip"], "127.0.0.1");
    assert_eq!(line["request"]["method"], "GET");
    assert_eq!(line["request"]["uri"], "/api/echo?q=1");
    assert_eq!(line["request"]["user_agent"], SCANNER);
    assert!(
        line["builtin"].as_str().is_some_and(|v| v.len() == 10),
        "the sets' version, a date: {line}"
    );
    let hits = line["hits"].as_array().unwrap();
    let hit = hits
        .iter()
        .find(|hit| hit["id"] == "wf-913-100")
        .unwrap_or_else(|| panic!("no hit of wf-913-100 in {line}"));
    assert_eq!(hit["set"], "scanners");
    assert_eq!(hit["target"], "ua");
    assert_eq!(hit["matched"], "nikto");
    h.shutdown().await;
}

#[tokio::test]
async fn an_allowed_address_passes_everything_and_a_denied_one_nothing() {
    let dir = tempfile::tempdir().unwrap();
    let h = start("access:\n  ip:\n    allow: [127.0.0.0/8]\n", dir.path()).await;
    let scanner = h.get("/.env", &[("user-agent", SCANNER)]).await;
    assert_eq!(
        scanner.status, 404,
        "allowed: the probe reaches file_server, which has no such file"
    );
    h.shutdown().await;

    let h = start("access:\n  ip:\n    deny: [127.0.0.1]\n", dir.path()).await;
    let clean = h.get("/en/", &[]).await;
    assert_eq!(clean.status, 403);
    assert_eq!(clean.text(), "refused 403");
    // Behind the trusted proxy, the client it names is the one judged.
    let other = h.get("/en/", &[("x-forwarded-for", "203.0.113.9")]).await;
    assert_eq!(other.status, 200, "{}", other.text());
    h.shutdown().await;
}

#[tokio::test]
async fn a_honeypot_path_bans_the_client() {
    let dir = tempfile::tempdir().unwrap();
    let yaml = "access:\n  ban:\n    honeypots: ['/honey/*']\n    for: 10m\n";
    let h = start(yaml, dir.path()).await;
    assert_eq!(h.get("/en/", &[]).await.status, 200);
    // One request to the honeypot: refused (it would have been a 404), and banned.
    let honey = h.get("/honey/pot", &[]).await;
    assert_eq!(honey.status, 403, "{}", honey.text());
    let banned = h.get("/en/", &[]).await;
    assert_eq!(
        banned.status,
        403,
        "the next clean request is refused: {}",
        banned.text()
    );
    assert_eq!(banned.text(), "refused 403");
    // Another client is not.
    assert_eq!(h.get("/en/", &[("x-forwarded-for", "203.0.113.9")]).await.status, 200);
    h.shutdown().await;
}

#[tokio::test]
async fn repeated_refusals_ban_the_client() {
    let dir = tempfile::tempdir().unwrap();
    let yaml = "access:\n  ban:\n    on_blocks: 3\n    window: 10m\n    for: 10m\n";
    let h = start(yaml, dir.path()).await;
    assert_eq!(h.get("/en/", &[("user-agent", SCANNER)]).await.status, 403);
    assert_eq!(h.get("/en/", &[]).await.status, 200, "two refusals: not banned yet");
    assert_eq!(h.get("/.env", &[]).await.status, 403);
    assert_eq!(h.get("/en/", &[]).await.status, 200, "two refusals: not banned yet");
    assert_eq!(h.get("/api/echo?q=1%20union%20select%201", &[]).await.status, 403);
    let banned = h.get("/en/", &[]).await;
    assert_eq!(
        banned.status, 403,
        "the third refusal within the window banned the client"
    );
    assert_eq!(h.get("/api/echo", &[]).await.status, 403, "and stays banned");
    h.shutdown().await;
}

#[tokio::test]
async fn a_header_action_marks_the_request_for_the_application() {
    let dir = tempfile::tempdir().unwrap();
    std::fs::write(
        dir.path().join("site.yaml"),
        "rules:
  - id: site-mark
    phase: head
    msg: \"marked by the site's rule\"
    severity: notice
    score: 1
    targets: [args.mark]
    transform: [lowercase]
    operator: { equals_any: ['yes'] }
    action: header
    header: { X-Threat: marked }
",
    )
    .unwrap();
    let h = start("rules:\n  include: [site.yaml]\n", dir.path()).await;

    let marked = h.get("/api/echo?mark=YES", &[]).await;
    assert_eq!(marked.status, 200, "{}", marked.text());
    assert_eq!(marked.upstream_header("x-threat"), "marked");

    // The header of a `header` action is taken off every request first: a client cannot set it.
    let spoofed = h.get("/api/echo?mark=no", &[("x-threat", "spoofed")]).await;
    assert_eq!(spoofed.status, 200);
    assert_eq!(spoofed.upstream_header("x-threat"), "");
    h.shutdown().await;
}

#[tokio::test]
async fn a_leaking_upstream_response_is_replaced_through_handle_errors() {
    let dir = tempfile::tempdir().unwrap();
    let yaml = "log:\n  output: ngfw.log\n";
    let h = start(yaml, dir.path()).await;

    let leak = h.get("/api/leak", &[]).await;
    assert_eq!(leak.status, 500);
    assert_eq!(
        leak.text(),
        "leak 500",
        "handle_errors 5xx rendered it; the upstream's body is gone"
    );
    assert!(header(&leak, "content-type").starts_with("text/plain"));

    let line = log_line(&dir.path().join("ngfw.log"), |l| l.contains("\"decision\":\"leak\"")).await;
    assert_eq!(line["phase"], "response");
    assert_eq!(line["status"], 500);
    let hits = line["hits"].as_array().unwrap();
    assert!(hits.iter().any(|hit| hit["id"] == "wf-950-100"), "{line}");
    assert!(
        hits.iter()
            .any(|hit| hit["id"] == "wf-950-100" && hit["matched"] == "Fatal error:"),
        "the matched text, case kept: {line}"
    );

    // A clean response is not touched.
    let clean = h.get("/api/echo?q=1", &[]).await;
    assert_eq!(clean.status, 200);
    assert_eq!(header(&clean, "x-upstream"), "1");
    h.shutdown().await;
}

#[tokio::test]
async fn a_site_rule_with_a_built_in_id_replaces_it() {
    let dir = tempfile::tempdir().unwrap();
    std::fs::write(
        dir.path().join("site.yaml"),
        "rules:
  - id: wf-913-100
    set: scanners
    phase: head
    msg: \"User-Agent of a vulnerability scanner (this site: seen, not refused)\"
    severity: critical
    targets: [ua]
    transform: [lowercase]
    operator: { contains_any: [nikto, sqlmap] }
    action: block
    mode: log_only
    tags: [OWASP_A05, scanner]
",
    )
    .unwrap();
    let yaml = "rules:\n  include: [site.yaml]\nlog:\n  output: ngfw.log\n";
    let h = start(yaml, dir.path()).await;

    // The scanner goes through: the replacing rule is log_only.
    let scanner = h.get("/api/echo?q=1", &[("user-agent", SCANNER)]).await;
    assert_eq!(scanner.status, 200, "{}", scanner.text());
    let line = log_line(&dir.path().join("ngfw.log"), |l| l.contains("wf-913-100")).await;
    assert_eq!(line["decision"], "log_only");

    // The rest of the set is untouched, and the replaced rule is the only wf-913-100.
    assert_eq!(h.get("/.env", &[]).await.status, 403);
    h.shutdown().await;
}

#[tokio::test]
async fn an_override_and_a_disable_change_the_built_in_rules() {
    let dir = tempfile::tempdir().unwrap();
    let yaml = "rules:\n  disable: [wf-913-21*]\n  override:\n    wf-913-100: { mode: log_only }\n";
    let h = start(yaml, dir.path()).await;
    assert_eq!(
        h.get("/.env", &[]).await.status,
        404,
        "wf-913-210 disabled by the mask: file_server's 404"
    );
    assert_eq!(
        h.get("/api/echo", &[("user-agent", SCANNER)]).await.status,
        200,
        "overridden to log_only"
    );
    assert_eq!(h.get("/wp-login.php", &[]).await.status, 403, "wf-913-200 stays");
    h.shutdown().await;
}

#[tokio::test]
async fn an_exclusion_takes_rules_off_a_path() {
    let dir = tempfile::tempdir().unwrap();
    let yaml = "rules:\n  exclusions:\n    - paths: ['/api/search']\n      rules: [wf-942-*]\n";
    let h = start(yaml, dir.path()).await;
    let excluded = h.get("/api/search?q=1%20union%20select%201", &[]).await;
    assert_eq!(
        excluded.status,
        200,
        "the sqli set does not run here: {}",
        excluded.text()
    );
    assert_eq!(
        h.get("/api/search?q=%3Cscript%3E", &[]).await.status,
        403,
        "the other sets do"
    );
    assert_eq!(
        h.get("/api/other?q=1%20union%20select%201", &[]).await.status,
        403,
        "elsewhere it runs"
    );
    h.shutdown().await;
}

#[tokio::test]
async fn status_444_closes_the_connection_without_an_answer() {
    let dir = tempfile::tempdir().unwrap();
    let h = start("response:\n  status: 444\n", dir.path()).await;
    let got = harness::raw(
        h.server.addr,
        format!("GET /en/ HTTP/1.1\r\nHost: 127.0.0.1\r\nUser-Agent: {SCANNER}\r\nAccept: */*\r\n\r\n").as_bytes(),
    )
    .await;
    assert!(got.is_empty(), "nothing is sent: {:?}", String::from_utf8_lossy(&got));

    // A clean request on a new connection is answered as usual.
    assert_eq!(h.get("/en/", &[]).await.status, 200);
    h.shutdown().await;
}

#[tokio::test]
async fn requests_outside_match_hosts_are_not_looked_at() {
    let dir = tempfile::tempdir().unwrap();
    let yaml = "match:\n  hosts: ['guarded.test']\n  except_paths: ['/api/open/*']\n";
    let h = start(yaml, dir.path()).await;
    let other = h
        .get("/api/echo", &[("host", "other.test"), ("user-agent", SCANNER)])
        .await;
    assert_eq!(other.status, 200, "another host: {}", other.text());
    let guarded = h
        .get("/api/echo", &[("host", "guarded.test"), ("user-agent", SCANNER)])
        .await;
    assert_eq!(guarded.status, 403);
    let excepted = h
        .get("/api/open/x", &[("host", "guarded.test"), ("user-agent", SCANNER)])
        .await;
    assert_eq!(excepted.status, 200, "an excepted path: {}", excepted.text());
    h.shutdown().await;
}

#[tokio::test]
async fn a_file_that_does_not_load_says_why() {
    let dir = tempfile::tempdir().unwrap();
    let including = "rules:\n  include: [site.yaml]\n";
    let site_rules = dir.path().join("site.yaml");

    assert!(
        Ngfw::load_str("mode: block\nthreshhold: 5\n", dir.path()).is_err(),
        "an unknown key"
    );
    assert!(
        Ngfw::load_str(including, dir.path()).is_err(),
        "an included file that is not there"
    );

    std::fs::write(
        &site_rules,
        "rules:\n  - id: Bad Id\n    phase: head\n    targets: [args]\n    operator: { contains_any: [x] }\n",
    )
    .unwrap();
    assert!(
        Ngfw::load_str(including, dir.path()).is_err(),
        "an id outside [a-z0-9-]+"
    );

    std::fs::write(
        &site_rules,
        "rules:\n  - id: no-op\n    phase: head\n    targets: [args]\n",
    )
    .unwrap();
    assert!(
        Ngfw::load_str(including, dir.path()).is_err(),
        "a rule without an operator"
    );

    std::fs::write(
        &site_rules,
        "rules:\n  - id: two-ops\n    phase: head\n    targets: [args]\n    operator: { contains_any: [x], exists: ~ }\n",
    )
    .unwrap();
    assert!(
        Ngfw::load_str(including, dir.path()).is_err(),
        "two operators on one rule"
    );

    assert!(
        Ngfw::load_str("{}\n", dir.path()).is_ok(),
        "an empty document: the defaults, every built-in set"
    );
    assert!(
        Ngfw::load_str("rules:\n  builtin: none\n", dir.path()).is_ok(),
        "no rules at all"
    );
}

/// The browser challenge from the filter (docs/challenge.md "From the request filter").
#[cfg(feature = "challenge")]
mod challenge {
    use super::*;
    use http::StatusCode;

    const ENDPOINT: &str = "/.well-known/c-wf";

    /// A site rule that challenges a request with `?ask=yes`.
    const ASKING: &str = "rules:
  - id: site-ask
    phase: head
    msg: \"asked by the site's rule\"
    severity: notice
    targets: [args.ask]
    operator: { equals_any: ['yes'] }
    action: challenge
";

    fn nonce_of(got: &Got) -> String {
        let body = got.text();
        let at = body.find("data-nonce=\"").expect("a nonce on the page") + "data-nonce=\"".len();
        let end = body[at..].find('"').unwrap() + at;
        body[at..end].to_string()
    }

    fn sha256_hex(text: &str) -> String {
        aws_lc_rs::digest::digest(&aws_lc_rs::digest::SHA256, text.as_bytes())
            .as_ref()
            .iter()
            .map(|b| format!("{b:02x}"))
            .collect()
    }

    /// The page is the answer: 503 with a nonce, not the site's error page.
    fn assert_page(got: &Got) {
        assert_eq!(got.status, StatusCode::SERVICE_UNAVAILABLE, "{}", got.text());
        assert_eq!(header(got, "retry-after"), "5");
        assert_eq!(header(got, "cache-control"), "no-store");
        assert!(header(got, "content-type").starts_with("text/html"));
        assert!(got.text().contains("data-nonce=\""), "{}", got.text());
        assert!(
            !got.text().contains("refused"),
            "not through handle_errors: {}",
            got.text()
        );
    }

    /// Answers the page's nonce at the endpoint; the cookie pair earned.
    async fn earn_cookie(h: &Harness, page: &Got) -> String {
        let nonce = nonce_of(page);
        let form = format!(
            "nonce={nonce}&answer={}&url=http%3A%2F%2Fexample%2F",
            sha256_hex(&nonce)
        );
        let passed = h
            .send(
                "POST",
                ENDPOINT,
                &[("content-type", "application/x-www-form-urlencoded")],
                form.as_bytes(),
            )
            .await;
        assert_eq!(passed.status, StatusCode::NO_CONTENT, "{}", passed.text());
        let set_cookie = header(&passed, "set-cookie");
        assert!(set_cookie.starts_with("__wf_c="), "{set_cookie:?}");
        set_cookie.split(';').next().unwrap().to_string()
    }

    #[tokio::test]
    async fn a_challenge_rule_answers_the_page_and_a_cookie_passes_it_as_challenge_passed() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(dir.path().join("site.yaml"), ASKING).unwrap();
        let yaml = "rules:\n  include: [site.yaml]\nlog:\n  output: ngfw.log\nresponse:\n  challenge: js\n  challenge_valid: 1h\n";
        let h = start(yaml, dir.path()).await;

        let clean = h.get("/api/echo?ask=no", &[]).await;
        assert_eq!(clean.status, 200, "{}", clean.text());
        let page = h.get("/api/echo?ask=yes", &[]).await;
        assert_page(&page);
        let line = log_line(&dir.path().join("ngfw.log"), |l| {
            l.contains("\"decision\":\"challenge\"")
        })
        .await;
        assert_eq!(line["status"], 503);
        assert!(line.get("reason").is_none(), "a rule, no access reason: {line}");
        assert!(
            line["hits"]
                .as_array()
                .unwrap()
                .iter()
                .any(|hit| hit["id"] == "site-ask"),
            "{line}"
        );

        // The cookie earned at the endpoint: the request goes on, the hit logged as passed.
        let cookie = earn_cookie(&h, &page).await;
        let passed = h.get("/api/echo?ask=yes", &[("cookie", &cookie)]).await;
        assert_eq!(passed.status, 200, "{}", passed.text());
        assert_eq!(header(&passed, "x-upstream"), "1");
        let line = log_line(&dir.path().join("ngfw.log"), |l| {
            l.contains("\"decision\":\"challenge_passed\"")
        })
        .await;
        assert_eq!(line["msg"], "request let through (challenge passed)");
        assert!(
            line["hits"]
                .as_array()
                .unwrap()
                .iter()
                .any(|hit| hit["id"] == "site-ask"),
            "{line}"
        );
        // The other rules still run on a passed client.
        assert_eq!(h.get("/.env?ask=yes", &[("cookie", &cookie)]).await.status, 403);
        h.shutdown().await;

        // `mode: challenge` on the module: every block by rule is the page instead.
        let h = start("mode: challenge\n", dir.path()).await;
        let scanner = h.get("/api/echo", &[("user-agent", SCANNER)]).await;
        assert_page(&scanner);
        let sqli = h.get("/api/echo?q=1%20union%20select%20name%20from%20users", &[]).await;
        assert_page(&sqli);
        assert_eq!(h.get("/api/echo", &[]).await.status, 200);
        h.shutdown().await;
    }

    #[tokio::test]
    async fn ban_then_challenge_asks_the_page_after_on_blocks_refusals() {
        let dir = tempfile::tempdir().unwrap();
        let yaml = "log:\n  output: ngfw.log\naccess:\n  ban:\n    on_blocks: 2\n    window: 10m\n    for: 10m\n    then: challenge\n";
        let h = start(yaml, dir.path()).await;
        assert_eq!(h.get("/en/", &[("user-agent", SCANNER)]).await.status, 403);
        assert_eq!(h.get("/en/", &[]).await.status, 200, "one refusal: nothing yet");
        let second = h.get("/.env", &[]).await;
        assert_eq!(second.status, 403, "the second refusal is still a 403");
        assert_eq!(second.text(), "refused 403");
        // Marked: the next clean request gets the page, not 403; the mark is not a ban.
        let page = h.get("/en/", &[]).await;
        assert_page(&page);
        let line = log_line(&dir.path().join("ngfw.log"), |l| {
            l.contains("\"decision\":\"challenge\"")
        })
        .await;
        assert_eq!(line["reason"], "ban");
        assert!(line.get("hits").is_none());
        // Passing lifts it for the cookie's holder; the rules still run.
        let cookie = earn_cookie(&h, &page).await;
        let home = h.get("/en/", &[("cookie", &cookie)]).await;
        assert_eq!(home.status, 200, "{}", home.text());
        assert_eq!(h.get("/.env", &[("cookie", &cookie)]).await.status, 403);
        // Another client is not marked.
        assert_eq!(h.get("/en/", &[("x-forwarded-for", "203.0.113.9")]).await.status, 200);
        h.shutdown().await;
    }

    #[test]
    fn the_challenge_keys_are_read_and_checked() {
        let dir = tempfile::tempdir().unwrap();
        let summary = Ngfw::load_str("mode: challenge\nresponse:\n  challenge: pow\n", dir.path())
            .unwrap()
            .summary();
        assert!(summary[0].contains("mode challenge"), "{summary:?}");
        assert!(Ngfw::load_str("response:\n  challenge: hard\n", dir.path()).is_err());
        assert!(Ngfw::load_str("response:\n  challenge_bind: subnet\n", dir.path()).is_err());
        assert!(Ngfw::load_str("response:\n  challenge_valid: 0s\n", dir.path()).is_err());
        assert!(
            Ngfw::load_str("response:\n  challenge: captcha\n", dir.path()).is_err(),
            "captcha without the provider"
        );
        assert!(
            Ngfw::load_str(
                "response:\n  challenge: captcha\n  captcha: {provider: turnstile, site_key: k, secret: 'env:WEBFAST_NGFW_UNSET_SECRET'}\n",
                dir.path()
            )
            .is_err(),
            "the variable is not set"
        );
        assert!(
            Ngfw::load_str(
                "response:\n  challenge: captcha\n  captcha: {provider: hcaptcha, site_key: k, secret: s}\n",
                dir.path()
            )
            .is_ok()
        );
        assert!(Ngfw::load_str("access:\n  ban:\n    then: challenge\n", dir.path()).is_ok());
    }
}

/// Needs a GeoLite2 (or DB-IP Lite) country database: `WEB_TEST_GEO_DB=/path/to/GeoLite2-Country.mmdb`.
#[tokio::test]
#[ignore = "needs a GeoLite2 database"]
async fn a_denied_country_is_refused_and_the_country_header_is_set() {
    let Ok(db) = std::env::var("WEB_TEST_GEO_DB") else {
        panic!("set WEB_TEST_GEO_DB to a GeoLite2-Country.mmdb file");
    };
    let dir = tempfile::tempdir().unwrap();
    let yaml = format!(
        "geo:\n  country_db: '{}'\n  header: X-Client-Country\naccess:\n  countries:\n    deny: [US]\n    except_paths: ['/en/*']\n",
        db.replace('\\', "/")
    );
    let h = start(&yaml, dir.path()).await;
    // 8.8.8.8 is in the United States in every database; the trusted proxy names the client.
    let denied = h.get("/api/echo", &[("x-forwarded-for", "8.8.8.8")]).await;
    assert_eq!(denied.status, 403, "{}", denied.text());
    assert_eq!(
        h.get("/en/", &[("x-forwarded-for", "8.8.8.8")]).await.status,
        200,
        "an excepted path"
    );
    let allowed = h.get("/api/echo", &[("x-forwarded-for", "1.1.1.1")]).await;
    assert_eq!(allowed.status, 200, "{}", allowed.text());
    let country = allowed.upstream_header("x-client-country");
    assert!(
        country.len() == 2 && country.chars().all(|c| c.is_ascii_uppercase()),
        "the ISO code on the request going on: {country:?}"
    );
    // Loopback is in no database: `--`, and not denied.
    let local = h.get("/api/echo", &[]).await;
    assert_eq!(local.status, 200);
    assert_eq!(local.upstream_header("x-client-country"), "--");
    h.shutdown().await;
}
