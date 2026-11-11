//! The CRS release's regression tests (go-ftw's files; `CRS_TESTS` names their directory), in
//! process: each stage's request built as go-ftw sends it (its `Content-Type` and `Connection`
//! completed), run through the engine at the tests' settings (ci/ftw/ngfw-crs.yaml's), its hits
//! against the stage's `expect_ids` and `no_expect_ids`. The blackbox run is scripts/ftw-run.sh's
//! `crs` pass; this one is for working on the engine:
//!
//! ```sh
//! CRS_TESTS=…/tests/regression/tests cargo test -p webfast-ngfw-crs crs_regression -- --ignored --nocapture
//! ```
//!
//! `CRS_ONLY=942` runs one file's (by the start of its name); `CRS_SKIPPED=1` lists what was not run.

use super::*;
use webfast_ngfw::engine::Input;
use webfast_ngfw::rule::Mode;

fn ids_of(value: &serde_json::Value) -> Vec<String> {
    value
        .as_array()
        .into_iter()
        .flatten()
        .map(|v| v.to_string().trim_matches('"').to_string())
        .collect()
}

fn walk(dir: &Path) -> Vec<PathBuf> {
    let mut out = Vec::new();
    for entry in std::fs::read_dir(dir).unwrap() {
        let path = entry.unwrap().path();
        if path.is_dir() {
            out.extend(walk(&path));
        } else if path.extension().is_some_and(|e| e == "yaml") {
            out.push(path);
        }
    }
    out
}

fn version_of(text: &str) -> Option<http::Version> {
    Some(match text {
        "HTTP/0.9" => http::Version::HTTP_09,
        "HTTP/1.0" => http::Version::HTTP_10,
        "HTTP/1.1" => http::Version::HTTP_11,
        "HTTP/2" | "HTTP/2.0" => http::Version::HTTP_2,
        _ => return None,
    })
}

/// A stage's request as go-ftw sends it: `encoded_request` as written, else the method, URI,
/// version, headers and `data`, with `Content-Type` (a form, for `data`) and `Connection: close`
/// completed unless `autocomplete_headers: false`.
fn request_of(input: &serde_json::Value) -> Option<(http::request::Parts, Option<Vec<u8>>)> {
    if let Some(encoded) = input["encoded_request"].as_str() {
        return raw_request(&base64(encoded)?);
    }
    let method = input["method"].as_str().unwrap_or("GET");
    let uri = input["uri"].as_str().unwrap_or("/");
    let version = version_of(input["version"].as_str().unwrap_or("HTTP/1.1"))?;
    let mut builder = http::Request::builder()
        .method(http::Method::from_bytes(method.as_bytes()).ok()?)
        .uri(uri)
        .version(version);
    let mut has_type = false;
    let mut has_connection = false;
    let mut has_length = false;
    if let Some(headers) = input["headers"].as_object() {
        for (name, value) in headers {
            let value = match value {
                serde_json::Value::String(s) => s.clone(),
                other => other.to_string(),
            };
            has_type |= name.eq_ignore_ascii_case("content-type");
            has_connection |= name.eq_ignore_ascii_case("connection");
            has_length |= name.eq_ignore_ascii_case("content-length") || name.eq_ignore_ascii_case("transfer-encoding");
            builder = builder.header(name.as_str(), http::HeaderValue::from_bytes(value.as_bytes()).ok()?);
        }
    }
    let data = input["data"].as_str().map(|d| d.as_bytes().to_vec());
    if input["autocomplete_headers"].as_bool() != Some(false) {
        if data.is_some() && !has_type {
            builder = builder.header("content-type", "application/x-www-form-urlencoded");
        }
        if !has_connection {
            builder = builder.header("connection", "close");
        }
        if let Some(d) = &data
            && !has_length
        {
            builder = builder.header("content-length", d.len());
        }
    }
    let parts = builder.body(()).ok()?.into_parts().0;
    Some((parts, data))
}

/// A raw HTTP/1 request (its line, headers and body) as the server's parser would take it.
fn raw_request(raw: &[u8]) -> Option<(http::request::Parts, Option<Vec<u8>>)> {
    let end = raw.windows(4).position(|w| w == b"\r\n\r\n")?;
    let head = std::str::from_utf8(&raw[..end]).ok()?;
    let mut lines = head.split("\r\n");
    let mut line = lines.next()?.split(' ');
    let (method, uri, version) = (line.next()?, line.next()?, line.next()?);
    let mut builder = http::Request::builder()
        .method(http::Method::from_bytes(method.as_bytes()).ok()?)
        .uri(uri)
        .version(version_of(version)?);
    for l in lines {
        let (name, value) = l.split_once(':')?;
        builder = builder.header(
            name.trim(),
            http::HeaderValue::from_bytes(value.trim().as_bytes()).ok()?,
        );
    }
    let body = raw[end + 4..].to_vec();
    Some((
        builder.body(()).ok()?.into_parts().0,
        (!body.is_empty()).then_some(body),
    ))
}

fn base64(text: &str) -> Option<Vec<u8>> {
    let mut out = Vec::new();
    let (mut acc, mut bits) = (0u32, 0);
    for b in text.bytes().filter(|b| !b.is_ascii_whitespace() && *b != b'=') {
        let v = match b {
            b'A'..=b'Z' => b - b'A',
            b'a'..=b'z' => b - b'a' + 26,
            b'0'..=b'9' => b - b'0' + 52,
            b'+' => 62,
            b'/' => 63,
            _ => return None,
        };
        acc = acc << 6 | v as u32;
        bits += 6;
        if bits >= 8 {
            bits -= 8;
            out.push((acc >> bits) as u8);
        }
    }
    Some(out)
}

#[test]
#[ignore]
fn crs_regression() {
    let Ok(dir) = std::env::var("CRS_TESTS") else {
        eprintln!("CRS_TESTS names the CRS's tests/regression/tests");
        return;
    };
    let only = std::env::var("CRS_ONLY").unwrap_or_default();
    let config: Config = serde_json::from_value(serde_json::json!({
        "paranoia": 4,
        "tx": {
            "max_num_args": 255, "arg_name_length": 100, "arg_length": 400, "total_arg_length": 6400,
            "max_file_size": 64100, "combined_file_sizes": 65535
        }
    }))
    .unwrap();
    let crs = CrsEngine::new(&config, Path::new(".")).unwrap();
    let types: Vec<String> = [
        "application/x-www-form-urlencoded",
        "application/json",
        "multipart/form-data",
        "text/xml",
        "application/xml",
        "text/plain",
    ]
    .iter()
    .map(|s| s.to_string())
    .collect();
    let limits = webfast_ngfw::body::Limits {
        json_max_depth: 20,
        multipart_max_parts: 64,
        upload_head: 4096,
    };
    let runtime = tokio::runtime::Builder::new_current_thread().build().unwrap();
    let mut files = walk(Path::new(&dir));
    files.sort();
    let (mut passed, mut failed, mut skipped) = (0, Vec::new(), Vec::new());
    for file in files {
        let name = file.file_name().unwrap().to_string_lossy().into_owned();
        let parent = file
            .parent()
            .unwrap()
            .file_name()
            .unwrap()
            .to_string_lossy()
            .into_owned();
        if !parent.starts_with("REQUEST-") || parent.starts_with("REQUEST-949") || !name.starts_with(&only) {
            continue;
        }
        let doc: serde_json::Value = webfast_core::yaml::from_str(&std::fs::read_to_string(&file).unwrap()).unwrap();
        let rule = doc["rule_id"].to_string();
        for test in doc["tests"].as_array().into_iter().flatten() {
            let id = format!("{rule}-{}", test["test_id"]);
            for stage in test["stages"].as_array().into_iter().flatten() {
                let log = &stage["output"]["log"];
                let expect = ids_of(&log["expect_ids"]);
                let forbid = ids_of(&log["no_expect_ids"]);
                if expect.is_empty() && forbid.is_empty() {
                    skipped.push(format!("{id}: no log expectation"));
                    continue;
                }
                let Some((parts, body)) = request_of(&stage["input"]) else {
                    skipped.push(format!("{id}: not a request the http crate builds"));
                    continue;
                };
                let data = body.and_then(|bytes| {
                    // As the filter reads it for an engine: a type not listed as text.
                    let kind = webfast_ngfw::body::kind_of(&parts.headers, &types).or_else(|| {
                        webfast_ngfw::body::has_body(&parts.headers).then_some(webfast_ngfw::body::Kind::Text)
                    })?;
                    Some(runtime.block_on(webfast_ngfw::body::BodyData::parse(
                        bytes::Bytes::from(bytes),
                        kind,
                        true,
                        &limits,
                    )))
                });
                let input = Input {
                    parts: &parts,
                    client_ip: "172.18.0.3".parse().unwrap(),
                    country: None,
                    asn: None,
                    sni: None,
                    ja4: None,
                    body: data.as_ref(),
                    response: None,
                    hidden: &[],
                };
                let evaluation = webfast_ngfw::plugin::evaluate(
                    &crs,
                    &[(Phase::Head, &input), (Phase::Body, &input)],
                    Mode::LogOnly,
                );
                let got: Vec<String> = evaluation
                    .hits
                    .iter()
                    .filter_map(|h| h.engine.as_ref().map(|r| r.id.clone()))
                    .collect();
                let missing: Vec<_> = expect.iter().filter(|e| !got.contains(e)).collect();
                let unwanted: Vec<_> = forbid.iter().filter(|e| got.contains(e)).collect();
                if missing.is_empty() && unwanted.is_empty() {
                    passed += 1;
                } else {
                    let desc = test["desc"]
                        .as_str()
                        .unwrap_or("")
                        .lines()
                        .next()
                        .unwrap_or("")
                        .to_string();
                    failed.push(format!(
                        "{id}: missing {missing:?}, unwanted {unwanted:?}; got {got:?} | {desc}"
                    ));
                }
            }
        }
    }
    for f in &failed {
        println!("FAIL {f}");
    }
    if std::env::var("CRS_SKIPPED").is_ok() {
        for s in &skipped {
            println!("SKIP {s}");
        }
    }
    println!("passed {passed}, failed {}, skipped {}", failed.len(), skipped.len());
}
