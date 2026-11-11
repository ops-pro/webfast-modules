//! The bundled CRS loads whole, and runs: a clean request matches nothing, a request outside the
//! CRS's policy (a method it does not allow, a scanner's User-Agent) is found by its rule with the
//! CRS's score, and the configuration (paranoia, `tx`, `remove`) changes what is found. CRS's own
//! regression tests (go-ftw, ci/ftw) are the measure of the rest.

use super::*;
use webfast_ngfw::engine::{Evaluation, Input};
use webfast_ngfw::rule::Mode;

fn engine(yaml: &str) -> CrsEngine {
    let value: serde_json::Value = if yaml.is_empty() {
        serde_json::Value::Null
    } else {
        webfast_core::yaml::from_str(yaml).unwrap()
    };
    let config: Config = if value.is_null() {
        Config::default()
    } else {
        serde_json::from_value(value).unwrap()
    };
    CrsEngine::new(&config, Path::new(".")).unwrap()
}

fn browser(method: &str, uri: &str, extra: &[(&str, &str)]) -> http::request::Parts {
    let mut builder = http::Request::builder()
        .method(http::Method::from_bytes(method.as_bytes()).unwrap())
        .uri(uri)
        .header("host", "www.example.com")
        .header(
            "user-agent",
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/130.0.0.0 Safari/537.36",
        )
        .header("accept", "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8")
        .header("accept-language", "en-US,en;q=0.9")
        .header("accept-encoding", "gzip, deflate, br");
    for (name, value) in extra {
        builder = builder.header(*name, *value);
    }
    builder.body(()).unwrap().into_parts().0
}

fn evaluate(engine: &CrsEngine, parts: &http::request::Parts) -> Evaluation {
    let input = Input {
        parts,
        client_ip: "203.0.113.7".parse().unwrap(),
        country: None,
        asn: None,
        sni: None,
        ja4: None,
        body: None,
        response: None,
    };
    webfast_ngfw::plugin::evaluate(engine, &[(Phase::Head, &input), (Phase::Body, &input)], Mode::Block)
}

fn ids(evaluation: &Evaluation) -> Vec<String> {
    evaluation
        .hits
        .iter()
        .filter_map(|h| h.engine.as_ref().map(|r| r.id.clone()))
        .collect()
}

#[test]
fn bundled_files_are_listed() {
    let dir = Path::new(env!("CARGO_MANIFEST_DIR")).join("crs/rules");
    let mut on_disk: Vec<String> = std::fs::read_dir(&dir)
        .unwrap()
        .map(|e| e.unwrap().file_name().to_string_lossy().into_owned())
        .collect();
    on_disk.sort();
    let mut listed: Vec<String> = bundled::RULES
        .iter()
        .chain(bundled::DATA)
        .map(|(n, _)| n.to_string())
        .collect();
    listed.sort();
    assert_eq!(on_disk, listed);
}

#[test]
fn the_bundled_crs_loads_whole() {
    let crs = engine("");
    // Every request rule of the release, its chains counted once, the response phases' left out.
    assert!(crs.program.count() > 400, "{} rules", crs.program.count());
    assert!(crs.program.ignored.is_empty(), "{:?}", crs.program.ignored);
    let summary = crs.summary().join("\n");
    assert!(summary.contains("OWASP CRS 4.30.0"), "{summary}");
}

#[test]
fn a_browsers_request_matches_nothing() {
    let crs = engine("");
    for uri in ["/", "/index.html", "/search?q=red+shoes&page=2", "/a/b/c.css?v=1"] {
        let evaluation = evaluate(&crs, &browser("GET", uri, &[("cookie", "session=abc123; theme=dark")]));
        assert!(evaluation.hits.is_empty(), "{uri}: {:?}", ids(&evaluation));
        assert_eq!(evaluation.score, 0);
    }
}

#[test]
fn a_method_outside_the_policy_and_a_scanner_are_found() {
    let crs = engine("");
    let evaluation = evaluate(&crs, &browser("PROPFIND", "/", &[]));
    assert!(
        ids(&evaluation).contains(&"911100".to_string()),
        "{:?}",
        ids(&evaluation)
    );
    assert_eq!(evaluation.score, 5);
    let hit = &evaluation.hits[0];
    assert_eq!(hit.target, "REQUEST_METHOD");
    assert_eq!(hit.matched, "PROPFIND");
    let rule = hit.engine.as_ref().unwrap();
    assert_eq!(rule.number, Some(911100));
    assert_eq!(rule.set, "crs-911");
    assert!(!rule.msg.is_empty());

    let evaluation = evaluate(&crs, &browser("GET", "/", &[("user-agent", "Nikto/2.5.0")]));
    assert!(
        ids(&evaluation).contains(&"913100".to_string()),
        "{:?}",
        ids(&evaluation)
    );
}

#[test]
fn the_configuration_changes_what_is_found() {
    let parts = browser("PROPFIND", "/", &[]);
    let allowed = engine("tx: { allowed_methods: 'GET HEAD POST OPTIONS PROPFIND' }");
    assert!(evaluate(&allowed, &parts).hits.is_empty());
    let removed = engine("remove: [911100]");
    assert!(evaluate(&removed, &parts).hits.is_empty());
    let ranged = engine("remove: ['911000-911999']");
    assert!(evaluate(&ranged, &parts).hits.is_empty());
    assert!(
        CrsEngine::new(
            &serde_json::from_value(serde_json::json!({"paranoia": 5})).unwrap(),
            Path::new(".")
        )
        .is_err()
    );
    assert!(
        CrsEngine::new(
            &serde_json::from_value(serde_json::json!({"paranoia": 2, "detection_paranoia": 1})).unwrap(),
            Path::new(".")
        )
        .is_err()
    );
    assert!(serde_json::from_value::<Config>(serde_json::json!({"bogus": 1})).is_err());
}

#[test]
fn site_files_before_and_after() {
    let dir = tempfile::tempdir().unwrap();
    std::fs::write(
        dir.path().join("before.conf"),
        "SecRule REQUEST_FILENAME \"@beginsWith /dav/\" \"id:1000,phase:1,pass,nolog,ctl:ruleRemoveById=911100\"\n",
    )
    .unwrap();
    std::fs::write(dir.path().join("after.conf"), "SecRuleRemoveById 913100\n").unwrap();
    let config: Config =
        serde_json::from_value(serde_json::json!({"before": ["before.conf"], "after": ["after.conf"]})).unwrap();
    let crs = CrsEngine::new(&config, dir.path()).unwrap();
    assert!(evaluate(&crs, &browser("PROPFIND", "/dav/x", &[])).hits.is_empty());
    assert!(!evaluate(&crs, &browser("PROPFIND", "/other", &[])).hits.is_empty());
    assert!(
        evaluate(&crs, &browser("GET", "/", &[("user-agent", "Nikto/2.5.0")]))
            .hits
            .is_empty()
    );
}

#[test]
fn a_higher_paranoia_scores_more_rules() {
    // The same request at paranoia 1 and 4: the higher level's rules add to it.
    let parts = browser("GET", "/?a=b%2520c", &[]);
    let one = evaluate(&engine(""), &parts);
    let four = evaluate(&engine("paranoia: 4"), &parts);
    assert!(four.score >= one.score);
    let detect = evaluate(&engine("detection_paranoia: 4"), &parts);
    assert_eq!(
        detect.score, one.score,
        "rules above the blocking level are written, not scored"
    );
}

/// What the CRS costs a request, on one core (`taskset -c 0 cargo test --release -p
/// webfast-ngfw-crs cost -- --ignored --nocapture`): a browser's GET, and a form POST, at
/// paranoia 1 and 4.
#[test]
#[ignore]
fn cost() {
    use std::time::Instant;
    let get = browser(
        "GET",
        "/products/list?category=shoes&sort=price&page=2",
        &[("cookie", "session=4f9a1c; theme=dark")],
    );
    let post = browser(
        "POST",
        "/account/profile",
        &[
            ("content-type", "application/x-www-form-urlencoded"),
            ("cookie", "session=4f9a1c"),
        ],
    );
    let limits = webfast_ngfw::body::Limits {
        json_max_depth: 20,
        multipart_max_parts: 64,
        upload_head: 4096,
    };
    let form =
        tokio::runtime::Builder::new_current_thread()
            .build()
            .unwrap()
            .block_on(webfast_ngfw::body::BodyData::parse(
                bytes::Bytes::from_static(
                    b"name=Jane+Doe&email=jane%40example.com&city=Riga&about=I+like+hiking+and+books",
                ),
                webfast_ngfw::body::Kind::Form,
                true,
                &limits,
            ));
    for paranoia in [1, 4] {
        let crs = engine(&format!("paranoia: {paranoia}"));
        for (what, parts, body) in [("GET", &get, None), ("POST", &post, Some(&form))] {
            let input = Input {
                parts,
                client_ip: "203.0.113.7".parse().unwrap(),
                country: None,
                asn: None,
                sni: None,
                ja4: None,
                body,
                response: None,
            };
            let phases = [(Phase::Head, &input), (Phase::Body, &input)];
            for _ in 0..200 {
                webfast_ngfw::plugin::evaluate(&crs, &phases, Mode::Block);
            }
            let n = 3000;
            let start = Instant::now();
            for _ in 0..n {
                std::hint::black_box(webfast_ngfw::plugin::evaluate(&crs, &phases, Mode::Block));
            }
            let each = start.elapsed().as_secs_f64() * 1e6 / n as f64;
            println!("paranoia {paranoia}, {what}: {each:.1} µs per request");
        }
    }
}

/// Registered, the engine is on in the filter: its line in the summary, the built-in sets but `cve`
/// off; `engines.crs: false` turns it off and the sets come back; a name not built is an error.
#[test]
fn registered_in_the_filter() {
    webfast_ngfw::plugin::register(&ENGINE);
    let dir = tempfile::tempdir().unwrap();
    let on = webfast_ngfw::Ngfw::load_str("log: { output: discard }\n", dir.path()).unwrap();
    let summary = on.summary().join("\n");
    assert!(summary.contains("engine crs: OWASP CRS"), "{summary}");
    assert!(summary.contains("(cve "), "{summary}");
    let paranoid = webfast_ngfw::Ngfw::load_str("engines: { crs: { paranoia: 3 } }\n", dir.path()).unwrap();
    assert!(paranoid.summary().join("\n").contains("paranoia 3"));
    let off = webfast_ngfw::Ngfw::load_str("engines: { crs: false }\n", dir.path()).unwrap();
    let summary = off.summary().join("\n");
    assert!(!summary.contains("engine crs"), "{summary}");
    assert!(summary.contains("sqli "), "{summary}");
    let both = webfast_ngfw::Ngfw::load_str("rules: { builtin: all }\n", dir.path()).unwrap();
    assert!(both.summary().join("\n").contains("sqli "));
    assert!(webfast_ngfw::Ngfw::load_str("engines: { bogus: {} }\n", dir.path()).is_err());
    assert!(
        webfast_ngfw::Ngfw::load_str("engines: { bogus: false }\n", dir.path()).is_ok(),
        "turning off an engine this webfast is not built with is no error"
    );
    assert!(webfast_ngfw::Ngfw::load_str("engines: { crs: { paranoia: 9 } }\n", dir.path()).is_err());
}

/// A hit carries the rule's `logdata` as ModSecurity expands it.
#[test]
fn a_hit_carries_its_logdata() {
    let crs = engine("");
    let evaluation = evaluate(&crs, &browser("PROPFIND", "/", &[]));
    let hit = &evaluation.hits[0];
    assert_eq!(hit.engine.as_ref().unwrap().id, "911100");
    assert!(
        hit.data.as_deref().is_some_and(|d| d.contains("PROPFIND")),
        "{:?}",
        hit.data
    );
}
