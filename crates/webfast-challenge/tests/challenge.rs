//! The browser challenge end to end (docs/challenge.md, Tests): a server booted by the core's test
//! harness with `challenge` directives at every level in `handle` blocks. No cookie → the 503 page
//! with a nonce; the js answer → 204 and a cookie → 200; the cookie level → 302 then 200; the pow
//! answer; `except` passes; `defer` lets a hundred pages through and asks for the 101st, assets
//! uncounted; a wrong answer → 400; a stale nonce → 403.

use aws_lc_rs::digest::{SHA256, digest};
use http::{HeaderMap, StatusCode};
use webfast_challenge::ChallengeEndpoint;
use webfast_core::harness::{self, Server};
use webfast_core::module::{Composition, Module};

/// The composition for these tests: this module alone, its answer endpoint the one request check.
static MODULES: &[&dyn Module] = &[&webfast_challenge::MODULE];

fn composition() -> Composition<(ChallengeEndpoint, ()), ()> {
    Composition {
        modules: MODULES,
        hooks: |_| ((ChallengeEndpoint, ()), ()),
    }
}

const UA: &str = "Mozilla/5.0 (webfast test)";
const ENDPOINT: &str = "/.well-known/c-wf";

const CADDYFILE: &str = r#"{
	auto_https off
	admin off
}

:0 {
	handle /js/* {
		challenge
		respond "ok js"
	}
	handle /cookie/* {
		challenge {
			level cookie
			valid 1h
		}
		respond "ok cookie"
	}
	handle /pow/* {
		challenge {
			level pow
			difficulty 12
			title "One moment"
		}
		respond "ok pow"
	}
	handle /defer/* {
		challenge {
			defer {
				events 100
				window 10m
			}
		}
		respond "ok defer"
	}
	handle /guarded/* {
		challenge {
			except {
				path /guarded/open*
			}
		}
		respond "ok guarded"
	}
	respond "open"
	log {
		output discard
	}
}
"#;

struct Harness {
    server: Server,
}

struct Got {
    status: StatusCode,
    headers: HeaderMap,
    body: String,
}

impl From<harness::Response> for Got {
    fn from(response: harness::Response) -> Got {
        Got {
            status: response.status,
            headers: response.headers,
            body: String::from_utf8_lossy(&response.body).into_owned(),
        }
    }
}

impl Got {
    fn header(&self, name: &str) -> &str {
        self.headers.get(name).map(|v| v.to_str().unwrap()).unwrap_or("")
    }

    /// The nonce the page carries.
    fn nonce(&self) -> String {
        let at = self.body.find("data-nonce=\"").expect("a nonce on the page") + "data-nonce=\"".len();
        let end = self.body[at..].find('"').unwrap() + at;
        self.body[at..end].to_string()
    }

    /// The cookie pair (`__wf_c=…`) of `Set-Cookie`.
    fn cookie(&self) -> String {
        let header = self.header("set-cookie");
        assert!(header.starts_with("__wf_c="), "{header:?}");
        assert!(header.contains("; Path=/; HttpOnly; SameSite=Lax"), "{header:?}");
        assert!(!header.contains("Secure"), "plain HTTP: no Secure");
        header.split(';').next().unwrap().to_string()
    }
}

/// The server, after `webfast validate`'s lines of the module said what the Caddyfile has.
async fn start() -> Harness {
    let server = harness::start(composition(), CADDYFILE, |config| {
        let lines = webfast_challenge::MODULE.validate(config);
        assert_eq!(lines.len(), 5, "{lines:?}");
        assert!(lines.iter().all(|l| l.starts_with("challenge :0: ")), "{lines:?}");
        assert!(lines.iter().any(|l| l.contains("level cookie")), "{lines:?}");
        assert!(
            lines.iter().any(|l| l.contains("defer 100 in 600s, pages")),
            "{lines:?}"
        );
    })
    .await;
    Harness { server }
}

impl Harness {
    async fn send(&self, method: &str, path: &str, headers: &[(&str, &str)], body: &str) -> Got {
        let mut all: Vec<(&str, &str)> = vec![("user-agent", UA)];
        if !headers.iter().any(|(k, _)| k.eq_ignore_ascii_case("accept")) {
            all.push(("accept", "text/html,*/*;q=0.8"));
        }
        all.extend_from_slice(headers);
        self.server.send(method, path, &all, body.as_bytes()).await.into()
    }

    async fn get(&self, path: &str, headers: &[(&str, &str)]) -> Got {
        self.send("GET", path, headers, "").await
    }

    /// The answer form posted to the endpoint.
    async fn answer(&self, nonce: &str, answer: &str) -> Got {
        let form = format!("nonce={nonce}&answer={answer}&url=http%3A%2F%2Fexample%2F");
        self.send(
            "POST",
            ENDPOINT,
            &[("content-type", "application/x-www-form-urlencoded")],
            &form,
        )
        .await
    }

    async fn shutdown(self) {
        self.server.shutdown().await;
    }
}

fn sha256_hex(text: &str) -> String {
    digest(&SHA256, text.as_bytes())
        .as_ref()
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect()
}

#[tokio::test]
async fn without_a_cookie_the_page_is_the_answer_and_the_js_answer_earns_the_cookie() {
    let h = start().await;
    let page = h.get("/js/home", &[]).await;
    assert_eq!(page.status, StatusCode::SERVICE_UNAVAILABLE, "{}", page.body);
    assert_eq!(page.header("retry-after"), "5");
    assert_eq!(page.header("cache-control"), "no-store");
    assert_eq!(page.header("content-type"), "text/html; charset=utf-8");
    assert_eq!(page.header("x-request-id").len(), 12);
    let csp = page.header("content-security-policy");
    assert!(csp.starts_with("default-src 'none'; script-src 'sha256-"), "{csp}");
    assert!(page.body.contains("data-level=\"js\""));
    assert!(page.body.contains("<h1>127.0.0.1</h1>"), "the host as heading");
    assert!(page.body.contains("Just a moment..."));
    assert!(page.body.contains(ENDPOINT));
    assert!(page.body.contains(&format!("Request {}", page.header("x-request-id"))));
    assert!(page.body.len() < 6 * 1024);
    let nonce = page.nonce();

    let wrong = h.answer(&nonce, "0000").await;
    assert_eq!(wrong.status, StatusCode::BAD_REQUEST);
    assert!(wrong.header("set-cookie").is_empty());
    let stale = h
        .answer("AQAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA", &sha256_hex("x"))
        .await;
    assert_eq!(stale.status, StatusCode::FORBIDDEN);
    let malformed = h.send("POST", ENDPOINT, &[], "nothing").await;
    assert_eq!(malformed.status, StatusCode::BAD_REQUEST);
    let not_post = h.get(ENDPOINT, &[]).await;
    assert_eq!(
        not_post.status,
        StatusCode::OK,
        "a GET of the endpoint reaches the routes"
    );
    assert_eq!(not_post.body, "open");

    let passed = h.answer(&nonce, &sha256_hex(&nonce)).await;
    assert_eq!(passed.status, StatusCode::NO_CONTENT, "{}", passed.body);
    let cookie = passed.cookie();
    assert!(passed.header("set-cookie").contains("Max-Age=604800"));
    let home = h.get("/js/home", &[("cookie", &cookie)]).await;
    assert_eq!(home.status, StatusCode::OK);
    assert_eq!(home.body, "ok js");
    // A pow ask is not satisfied by a js cookie.
    let pow = h.get("/pow/x", &[("cookie", &cookie)]).await;
    assert_eq!(pow.status, StatusCode::SERVICE_UNAVAILABLE);
    h.shutdown().await;
}

#[tokio::test]
async fn a_cookie_of_another_browser_is_not_good() {
    let h = start().await;
    let page = h.get("/js/home", &[]).await;
    let nonce = page.nonce();
    let passed = h.answer(&nonce, &sha256_hex(&nonce)).await;
    assert_eq!(passed.status, StatusCode::NO_CONTENT);
    let cookie = passed.cookie();
    let response = harness::request(
        h.server.addr,
        "GET",
        "/js/home",
        &[("user-agent", "curl/8"), ("cookie", &cookie)],
        b"",
    )
    .await;
    assert_eq!(
        response.status,
        StatusCode::SERVICE_UNAVAILABLE,
        "another User-Agent: asked again"
    );
    h.shutdown().await;
}

#[tokio::test]
async fn the_cookie_level_redirects_once() {
    let h = start().await;
    let redirect = h.get("/cookie/feed?page=2", &[]).await;
    assert_eq!(redirect.status, StatusCode::FOUND);
    assert_eq!(redirect.header("location"), "/cookie/feed?page=2");
    assert_eq!(redirect.header("cache-control"), "no-store");
    let cookie = redirect.cookie();
    assert!(redirect.header("set-cookie").contains("Max-Age=3600"));
    let feed = h.get("/cookie/feed?page=2", &[("cookie", &cookie)]).await;
    assert_eq!(feed.status, StatusCode::OK);
    assert_eq!(feed.body, "ok cookie");
    // A cookie-level cookie is not good where js is asked.
    let js = h.get("/js/x", &[("cookie", &cookie)]).await;
    assert_eq!(js.status, StatusCode::SERVICE_UNAVAILABLE);
    // A POST without the cookie gets the page, not a redirect.
    let post = h.send("POST", "/cookie/form", &[], "a=b").await;
    assert_eq!(post.status, StatusCode::SERVICE_UNAVAILABLE);
    assert!(post.body.contains("data-level=\"js\""));
    h.shutdown().await;
}

#[tokio::test]
async fn the_pow_answer_is_a_counter_with_the_bits() {
    let h = start().await;
    let page = h.get("/pow/x", &[]).await;
    assert_eq!(page.status, StatusCode::SERVICE_UNAVAILABLE);
    assert!(page.body.contains("data-level=\"pow\""));
    assert!(page.body.contains("data-difficulty=\"12\""));
    assert!(page.body.contains("<h2>One moment</h2>"));
    let nonce = page.nonce();
    let bits = |counter: u64| -> u32 {
        let hash = digest(&SHA256, format!("{nonce}:{counter}").as_bytes());
        let mut bits = 0;
        for byte in hash.as_ref() {
            if *byte == 0 {
                bits += 8;
            } else {
                return bits + byte.leading_zeros();
            }
        }
        bits
    };
    let short = (0u64..).find(|c| bits(*c) < 12).unwrap();
    assert_eq!(
        h.answer(&nonce, &short.to_string()).await.status,
        StatusCode::BAD_REQUEST
    );
    let counter = (0u64..).find(|c| bits(*c) >= 12).unwrap();
    let passed = h.answer(&nonce, &counter.to_string()).await;
    assert_eq!(passed.status, StatusCode::NO_CONTENT);
    let cookie = passed.cookie();
    assert_eq!(h.get("/pow/x", &[("cookie", &cookie)]).await.body, "ok pow");
    assert_eq!(
        h.get("/js/x", &[("cookie", &cookie)]).await.body,
        "ok js",
        "a pow cookie is good for js"
    );
    h.shutdown().await;
}

#[tokio::test]
async fn except_passes_and_defer_asks_the_hundred_and_first_page() {
    let h = start().await;
    assert_eq!(h.get("/guarded/open/x", &[]).await.body, "ok guarded");
    assert_eq!(h.get("/guarded/x", &[]).await.status, StatusCode::SERVICE_UNAVAILABLE);
    assert_eq!(h.get("/", &[]).await.body, "open", "no challenge outside the blocks");

    for i in 0..100 {
        let page = h.get(&format!("/defer/page/{i}"), &[]).await;
        assert_eq!(page.status, StatusCode::OK, "page {}", i + 1);
    }
    let asked = h.get("/defer/page/101", &[]).await;
    assert_eq!(asked.status, StatusCode::SERVICE_UNAVAILABLE, "the 101st page");
    // Assets are not counted and not asked.
    assert_eq!(h.get("/defer/style.css", &[]).await.body, "ok defer");
    assert_eq!(
        h.get("/defer/api", &[("accept", "application/json")]).await.body,
        "ok defer",
        "not a navigation"
    );
    // Passing the challenge ends the asking for this client.
    let nonce = asked.nonce();
    let cookie = h.answer(&nonce, &sha256_hex(&nonce)).await.cookie();
    assert_eq!(h.get("/defer/page/102", &[("cookie", &cookie)]).await.body, "ok defer");
    h.shutdown().await;
}
