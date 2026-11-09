//! The browser challenge (the `webfast-challenge` crate; the webfast binary's cargo feature
//! `challenge`; docs/challenge.md): a client proves it is a browser before a site answers it — by
//! accepting a cookie, by running a small script, by a proof-of-work, or by a CAPTCHA of an outside
//! provider — and carries a signed cookie that spares it the question until it expires. Who asks is
//! the `challenge` directive (directive.rs) or the request filter (the `webfast-ngfw` crate); this
//! module serves the page, checks the answer at `POST /.well-known/c-wf`, makes and verifies the
//! cookie, and keeps no state per client: the cookie is checked by its signature (token.rs), with
//! the keys derived from the seed the TLS tickets use, so every replica given the seed accepts the
//! others' cookies.
//!
//! A module of the core (`webfast_core::module`, webfast's docs/modules.md), written against its
//! public API alone: `MODULE` registers the directive, the environment and the seed;
//! `ChallengeEndpoint` is its request check, the first in the binary's composed checks;
//! `directive::ChallengeDirective` its route handler.
//!
//! One instance per process (`instance()`): the key schedule, the built-in page, the counters, and
//! the table of cookies that verified — 64 shards of their decoded bytes with the client's binding,
//! so a cookie any connection brought is one hash lookup afterwards, never a signature again; a
//! cookie that failed is not remembered, and the table is bounded (WEB_CHALLENGE_PASSED). The
//! module writes nothing per request; it counts what it asked, passed and failed per level and
//! logs the sums once a minute (defer.rs's sweeper).

pub mod captcha;
pub mod defer;
pub mod directive;
pub mod page;
pub mod pow;
pub mod token;

use captcha::Captcha;
use http::{HeaderValue, Method, Response, StatusCode, header};
use page::Page;
use rustc_hash::{FxBuildHasher, FxHashMap};
use std::hash::BuildHasher;
use std::net::IpAddr;
use std::sync::atomic::{AtomicU64, AtomicUsize, Ordering};
use std::sync::{Arc, LazyLock, Mutex, OnceLock, PoisonError};
use std::time::Duration;
use token::{COOKIE_LEN, COOKIE_NAME, CookieData, Keys, NONCE_TTL, NonceData, now_secs};
use webfast_core::body::Body;
use webfast_core::extensions::{Checked, Client};
use webfast_core::handler::ConnInfo;
use webfast_core::module::{Check, Directive, Head, Module, Order};

/// Where the page posts its answer, on every site.
pub const ENDPOINT: &str = "/.well-known/c-wf";
/// The default of WEB_CHALLENGE_PASSED: cookies the table of passed cookies holds at most.
pub const DEFAULT_PASSED: usize = 1_000_000;
/// What the answer endpoint reads of a body at most.
const MAX_ANSWER_BODY: usize = 8 * 1024;
const SHARDS: usize = 64;

/// WEB_CHALLENGE_PASSED.
static MAX_PASSED: AtomicUsize = AtomicUsize::new(DEFAULT_PASSED);

/// WEB_CHALLENGE_PASSED (a count of cookies; 0: no table, every request verifies its cookie).
pub fn configure_from_env() -> Result<(), String> {
    if let Ok(value) = std::env::var("WEB_CHALLENGE_PASSED") {
        match value.trim().parse::<usize>() {
            Ok(n) => MAX_PASSED.store(n, Ordering::Relaxed),
            Err(_) => return Err(format!("WEB_CHALLENGE_PASSED: a number of cookies, not {value:?}")),
        }
    }
    Ok(())
}

/// What a client must do.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum Level {
    Cookie = 0,
    Js = 1,
    Pow = 2,
    Captcha = 3,
}

impl Level {
    pub const ALL: [Level; 4] = [Level::Cookie, Level::Js, Level::Pow, Level::Captcha];

    pub fn name(self) -> &'static str {
        match self {
            Level::Cookie => "cookie",
            Level::Js => "js",
            Level::Pow => "pow",
            Level::Captcha => "captcha",
        }
    }

    pub fn parse(text: &str) -> Option<Level> {
        Some(match text {
            "cookie" => Level::Cookie,
            "js" => Level::Js,
            "pow" => Level::Pow,
            "captcha" => Level::Captcha,
            _ => return None,
        })
    }

    pub(crate) fn from_u8(byte: u8) -> Option<Level> {
        Level::ALL.get(usize::from(byte)).copied()
    }
}

/// What the cookie is bound to.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Bind {
    /// The client's `/24` or `/48`.
    Ip,
    None,
}

impl Bind {
    pub fn name(self) -> &'static str {
        match self {
            Bind::Ip => "ip",
            Bind::None => "none",
        }
    }
}

/// What a challenge is asked with.
#[derive(Debug, Clone)]
pub struct Asking {
    pub level: Level,
    pub difficulty: u8,
    pub valid: Duration,
    pub bind: Bind,
    pub title: Arc<str>,
    pub captcha: Option<Arc<Captcha>>,
    pub page: Option<Arc<Page>>,
}

impl Default for Asking {
    fn default() -> Asking {
        Asking {
            level: Level::Js,
            difficulty: pow::DEFAULT_DIFFICULTY,
            valid: Duration::from_secs(7 * 86_400),
            bind: Bind::Ip,
            title: Arc::from("Just a moment..."),
            captcha: None,
            page: None,
        }
    }
}

/// The seed given before the instance is made (`configure`).
static SEED: OnceLock<Option<Vec<u8>>> = OnceLock::new();

static INSTANCE: LazyLock<Challenge> = LazyLock::new(|| {
    let keys = match SEED.get_or_init(|| None) {
        Some(seed) => Keys::new(seed),
        None => Keys::random(),
    };
    Challenge {
        keys,
        passed: Passed::new(),
        asked: Default::default(),
        passed_count: Default::default(),
        failed: Default::default(),
    }
});

/// The seed the keys come from (the TLS tickets', `Module::seed`); `None`: one drawn now. Only the
/// first call before the instance is made counts.
pub fn configure(seed: Option<&[u8]>) {
    let _ = SEED.set(seed.map(<[u8]>::to_vec));
}

/// The one instance of the process.
pub fn instance() -> &'static Challenge {
    &INSTANCE
}

/// The module: the key schedule, the passed cookies, the counters.
pub struct Challenge {
    keys: Keys,
    passed: Passed,
    asked: [AtomicU64; 4],
    passed_count: [AtomicU64; 4],
    failed: [AtomicU64; 4],
}

/// A table entry: the cookie's decoded bytes and the client's binding (address block, a hash of
/// the User-Agent), so that a hit means "this cookie verified for this client".
type PassedKey = [u8; token::COOKIE_RAW + 6 + 8];

/// The cookies that verified, by their bytes and binding, in shards under their own locks.
struct Passed {
    hasher: ahash::RandomState,
    shards: Vec<Shard>,
}

#[repr(align(128))]
struct Shard(Mutex<FxHashMap<PassedKey, ()>>);

impl Passed {
    fn new() -> Passed {
        Passed {
            hasher: ahash::RandomState::new(),
            shards: (0..SHARDS).map(|_| Shard(Mutex::new(FxHashMap::default()))).collect(),
        }
    }

    fn shard(&self, key: &PassedKey) -> std::sync::MutexGuard<'_, FxHashMap<PassedKey, ()>> {
        let hash = self.hasher.hash_one(key);
        self.shards[(hash as usize) % SHARDS]
            .0
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
    }

    fn contains(&self, key: &PassedKey) -> bool {
        self.shard(key).contains_key(key)
    }

    /// Remembers a cookie that verified, unless the table is full.
    fn insert(&self, key: PassedKey) {
        let max = MAX_PASSED.load(Ordering::Relaxed);
        let mut shard = self.shard(&key);
        if shard.len() < max.div_ceil(SHARDS) {
            shard.insert(key, ());
        }
    }

    /// Drops the cookies expired at `now`; how many remain.
    fn sweep(&self, now: u64) -> usize {
        self.shards
            .iter()
            .map(|shard| {
                let mut shard = shard.0.lock().unwrap_or_else(PoisonError::into_inner);
                shard.retain(|key, ()| u64::from(u32::from_be_bytes([key[1], key[2], key[3], key[4]])) > now);
                shard.len()
            })
            .sum()
    }
}

impl Challenge {
    /// Whether the request carries a good cookie of `level` or above for the client at `ip`.
    pub fn passed(&self, conn: &ConnInfo, parts: &http::request::Parts, ip: IpAddr, level: Level) -> bool {
        let _ = conn;
        let Some(value) = cookie_value(&parts.headers) else {
            return false;
        };
        let ua = user_agent(parts);
        let mut key: PassedKey = [0; token::COOKIE_RAW + 6 + 8];
        let Some(cookie_level) = token::decode_cookie_head(value, &mut key[..token::COOKIE_RAW]) else {
            return false;
        };
        let bind = token::bind_of_cookie(&key[..token::COOKIE_RAW]);
        let at = token::COOKIE_RAW + token::prefix_into(ip, bind, &mut key[token::COOKIE_RAW..]);
        key[at..at + 8].copy_from_slice(&FxBuildHasher.hash_one(ua).to_le_bytes());
        let now = now_secs();
        if self.passed.contains(&key) {
            // The expiry is in the key: a hit is good until then.
            let expiry = u64::from(u32::from_be_bytes([key[1], key[2], key[3], key[4]]));
            return expiry > now && cookie_level >= level;
        }
        match self.keys.check_cookie(value, ip, ua, now) {
            Some(data) => {
                self.passed.insert(key);
                data.level >= level
            }
            None => false,
        }
    }

    /// The challenge as the answer to the request: the page (503) or, at level `cookie` for a GET
    /// or HEAD, the redirect that sets the cookie (302). `ErrorPage` is not set: this is the answer.
    pub fn ask(&self, conn: &ConnInfo, parts: &http::request::Parts, ip: IpAddr, asking: &Asking) -> Response<Body> {
        let mut level = asking.level;
        self.asked[level as usize].fetch_add(1, Ordering::Relaxed);
        let now = now_secs();
        if level == Level::Cookie {
            if parts.method == Method::GET || parts.method == Method::HEAD {
                let data = CookieData {
                    expiry: expiry(now, asking.valid),
                    level,
                    bind: asking.bind,
                };
                let cookie = self.keys.make_cookie(&data, ip, user_agent(parts));
                let mut response = Response::new(webfast_core::body::empty());
                *response.status_mut() = StatusCode::FOUND;
                let target = parts.uri.path_and_query().map_or("/", |pq| pq.as_str());
                if let Ok(location) = HeaderValue::from_str(target) {
                    response.headers_mut().insert(header::LOCATION, location);
                }
                set_cookie(&mut response, &cookie, asking.valid, conn.tls);
                self.passed_count[level as usize].fetch_add(1, Ordering::Relaxed);
                return response;
            }
            // A body cannot be replayed through a redirect: the script's way instead.
            level = Level::Js;
        }
        let provider = asking.captcha.as_deref().map_or(0, Captcha::index);
        let nonce = self.keys.make_nonce(
            &NonceData {
                expiry: expiry(now, NONCE_TTL),
                level,
                difficulty: asking.difficulty,
                provider,
                bind: asking.bind,
                valid: u32::try_from(asking.valid.as_secs()).unwrap_or(u32::MAX),
            },
            ip,
        );
        let request_id = request_id();
        let host = webfast_core::handler::strip_port(webfast_core::handler::hostport_of(parts));
        let page = asking.page.as_deref().unwrap_or_else(|| page::builtin());
        let body = page.render(&page::Values {
            nonce: std::str::from_utf8(&nonce).unwrap_or(""),
            level: level.name(),
            difficulty: asking.difficulty,
            title: &asking.title,
            host,
            request_id: &request_id,
            site_key: asking.captcha.as_deref().map_or("", |c| c.site_key.as_str()),
            provider: asking.captcha.as_deref().map_or("", |c| c.provider.name()),
        });
        let mut response = Response::new(webfast_core::body::full(body));
        *response.status_mut() = StatusCode::SERVICE_UNAVAILABLE;
        let headers = response.headers_mut();
        headers.insert(
            header::CONTENT_TYPE,
            HeaderValue::from_static("text/html; charset=utf-8"),
        );
        headers.insert(header::RETRY_AFTER, HeaderValue::from_static("5"));
        headers.insert(header::CACHE_CONTROL, HeaderValue::from_static("no-store"));
        if let Ok(id) = HeaderValue::from_str(&request_id) {
            headers.insert("x-request-id", id);
        }
        if page.hashed_script_only() {
            let provider = (level == Level::Captcha)
                .then(|| asking.captcha.as_deref().map(|c| c.provider.csp_origins()))
                .flatten();
            if let Ok(csp) = HeaderValue::from_str(&csp(provider)) {
                headers.insert(header::CONTENT_SECURITY_POLICY, csp);
            }
        }
        response
    }

    /// The answer endpoint: the form's `nonce` and `answer` checked, the cookie set (204), or 400
    /// for a wrong answer, 403 for a nonce that is stale or not ours, 503 when the CAPTCHA provider
    /// could not be asked.
    async fn answer(&self, conn: &ConnInfo, parts: &http::request::Parts, ip: IpAddr, form: &[u8]) -> Response<Body> {
        let (mut nonce, mut answer) = (None, None);
        for pair in form.split(|b| *b == b'&') {
            let (name, value) = match pair.iter().position(|b| *b == b'=') {
                Some(at) => (&pair[..at], &pair[at + 1..]),
                None => (pair, &[][..]),
            };
            match name {
                b"nonce" => nonce = Some(form_value(value)),
                b"answer" => answer = Some(form_value(value)),
                _ => {}
            }
        }
        let (Some(nonce), Some(answer)) = (nonce, answer) else {
            return status(StatusCode::BAD_REQUEST);
        };
        let now = now_secs();
        let Some(data) = self.keys.check_nonce(nonce.as_bytes(), ip, now) else {
            return status(StatusCode::FORBIDDEN);
        };
        let good = match data.level {
            // The length first: an answer that is no SHA-256 in hex is refused without the hash.
            Level::Cookie | Level::Js => {
                answer.len() == 64 && {
                    let expected = aws_lc_rs::digest::digest(&aws_lc_rs::digest::SHA256, nonce.as_bytes());
                    hex_equals(expected.as_ref(), answer.as_bytes())
                }
            }
            Level::Pow => pow::check(nonce.as_bytes(), answer.as_bytes(), data.difficulty),
            Level::Captcha => {
                let Some(captcha) = Captcha::by_index(data.provider) else {
                    return status(StatusCode::FORBIDDEN);
                };
                match captcha.verify(&answer, ip).await {
                    Ok(good) => good,
                    Err(e) => {
                        tracing::warn!(provider = captcha.provider.name(), error = %e, "CAPTCHA verification failed");
                        self.failed[data.level as usize].fetch_add(1, Ordering::Relaxed);
                        return status(StatusCode::SERVICE_UNAVAILABLE);
                    }
                }
            }
        };
        if !good {
            self.failed[data.level as usize].fetch_add(1, Ordering::Relaxed);
            return status(StatusCode::BAD_REQUEST);
        }
        let valid = Duration::from_secs(u64::from(data.valid));
        let cookie = self.keys.make_cookie(
            &CookieData {
                expiry: expiry(now, valid),
                level: data.level,
                bind: data.bind,
            },
            ip,
            user_agent(parts),
        );
        self.passed_count[data.level as usize].fetch_add(1, Ordering::Relaxed);
        let mut response = status(StatusCode::NO_CONTENT);
        set_cookie(&mut response, &cookie, valid, conn.tls);
        response
    }

    /// Drops the expired cookies of the table; how many remain (the sweeper's).
    fn sweep(&self) -> usize {
        self.passed.sweep(now_secs())
    }

    #[cfg(test)]
    fn keys(&self) -> &Keys {
        &self.keys
    }
}

/// Logs what was asked, passed and failed since the last time, per level (the sweeper's, once a
/// minute), and sweeps the table of passed cookies.
fn log_summary() {
    let this = instance();
    let remembered = this.sweep();
    for level in Level::ALL {
        let i = level as usize;
        let asked = this.asked[i].swap(0, Ordering::Relaxed);
        let passed = this.passed_count[i].swap(0, Ordering::Relaxed);
        let failed = this.failed[i].swap(0, Ordering::Relaxed);
        if asked + passed + failed > 0 {
            tracing::info!(level = level.name(), asked, passed, failed, remembered, "challenges");
        }
    }
}

/// The expiry `valid` from `now`, as the tokens carry it.
fn expiry(now: u64, valid: Duration) -> u32 {
    u32::try_from(now.saturating_add(valid.as_secs())).unwrap_or(u32::MAX)
}

/// `Set-Cookie` of `cookie` for `valid`, and `Cache-Control: no-store`.
fn set_cookie(response: &mut Response<Body>, cookie: &[u8; COOKIE_LEN], valid: Duration, tls: bool) {
    let mut value = String::with_capacity(96);
    value.push_str(COOKIE_NAME);
    value.push('=');
    value.push_str(std::str::from_utf8(cookie).unwrap_or(""));
    value.push_str("; Max-Age=");
    value.push_str(&valid.as_secs().to_string());
    value.push_str("; Path=/; HttpOnly; SameSite=Lax");
    if tls {
        value.push_str("; Secure");
    }
    if let Ok(value) = HeaderValue::from_str(&value) {
        response.headers_mut().append(header::SET_COOKIE, value);
    }
    response
        .headers_mut()
        .insert(header::CACHE_CONTROL, HeaderValue::from_static("no-store"));
}

fn status(status: StatusCode) -> Response<Body> {
    let mut response = Response::new(webfast_core::body::empty());
    *response.status_mut() = status;
    response
        .headers_mut()
        .insert(header::CACHE_CONTROL, HeaderValue::from_static("no-store"));
    response
}

/// The `Content-Security-Policy` of the page: the built-in script by its hash, inline styles, and
/// the CAPTCHA provider's origins when one is loaded.
fn csp(provider: Option<&str>) -> String {
    let hash = page::script_hash();
    match provider {
        Some(origins) => format!(
            "default-src 'none'; script-src '{hash}' {origins}; style-src 'unsafe-inline'; img-src data:; \
             connect-src 'self' {origins}; frame-src {origins}; worker-src blob:"
        ),
        None => format!(
            "default-src 'none'; script-src '{hash}'; style-src 'unsafe-inline'; img-src data:; \
             connect-src 'self'; worker-src blob:"
        ),
    }
}

/// The `__wf_c` cookie's value among the request's `Cookie` headers.
fn cookie_value(headers: &http::HeaderMap) -> Option<&[u8]> {
    for value in headers.get_all(header::COOKIE) {
        for pair in value.as_bytes().split(|b| *b == b';') {
            let pair = pair.trim_ascii();
            if let Some(rest) = pair.strip_prefix(COOKIE_NAME.as_bytes())
                && let Some(value) = rest.strip_prefix(b"=")
            {
                return Some(value.trim_ascii());
            }
        }
    }
    None
}

fn user_agent(parts: &http::request::Parts) -> &[u8] {
    parts
        .headers
        .get(header::USER_AGENT)
        .map_or(&[][..], HeaderValue::as_bytes)
}

/// A short random id for the page's footer and `X-Request-Id`.
fn request_id() -> String {
    let mut bytes = [0u8; 6];
    if aws_lc_rs::rand::fill(&mut bytes).is_err() {
        bytes.copy_from_slice(&now_secs().to_le_bytes()[..6]);
    }
    let mut text = String::with_capacity(12);
    for byte in bytes {
        text.push_str(&format!("{byte:02x}"));
    }
    text
}

/// Whether `hex` spells `bytes`, either case.
fn hex_equals(bytes: &[u8], hex: &[u8]) -> bool {
    if hex.len() != bytes.len() * 2 {
        return false;
    }
    let digit = |c: u8| -> Option<u8> {
        Some(match c {
            b'0'..=b'9' => c - b'0',
            b'a'..=b'f' => c - b'a' + 10,
            b'A'..=b'F' => c - b'A' + 10,
            _ => return None,
        })
    };
    let mut differ = 0u8;
    for (i, byte) in bytes.iter().enumerate() {
        let (Some(high), Some(low)) = (digit(hex[2 * i]), digit(hex[2 * i + 1])) else {
            return false;
        };
        differ |= byte ^ (high << 4 | low);
    }
    differ == 0
}

/// A form value decoded (`+` is a space).
fn form_value(value: &[u8]) -> String {
    let mut text = Vec::with_capacity(value.len());
    for &b in value {
        text.push(if b == b'+' { b' ' } else { b });
    }
    percent_encoding::percent_decode(&text).decode_utf8_lossy().into_owned()
}

/// The answer endpoint, served for every site before its routes (a request check,
/// `webfast_core::module::Check`, composed after the ACME answer and before the request filter).
/// Every request but a POST to the endpoint passes by synchronously.
#[derive(Debug, Clone, Copy)]
pub struct ChallengeEndpoint;

impl Check for ChallengeEndpoint {
    /// The head hands on nothing: the endpoint is the path and the method.
    type Pending = ();

    fn head(&self, req: &mut http::request::Parts, _: Client<'_>) -> Head {
        if req.uri.path() != ENDPOINT || req.method != Method::POST {
            Head::Pass
        } else {
            Head::Body(())
        }
    }

    async fn body<'a>(&'a self, _: (), req: &'a mut http::request::Parts, body: Body, client: Client<'a>) -> Checked {
        let form = match http_body_util::BodyExt::collect(http_body_util::Limited::new(body, MAX_ANSWER_BODY)).await {
            Ok(collected) => collected.to_bytes(),
            Err(_) => return Err(status(StatusCode::BAD_REQUEST)),
        };
        Err(instance().answer(client.conn, req, client.ip, &form).await)
    }
}

/// The module as the binary registers it (`webfast_core::module::Module`): the `challenge`
/// directive, WEB_CHALLENGE_PASSED, the keys from the TLS ticket seed.
pub struct ChallengeModule;

/// The one to register.
pub static MODULE: ChallengeModule = ChallengeModule;

static DIRECTIVES: [Directive; 1] = [Directive {
    name: "challenge",
    parse: directive::parse,
    // Where Caddy's order has `rate_limit`: the challenge before the rate limit, so a client that
    // is not a browser does not count against it.
    order: Order::Before("rate_limit"),
}];

impl Module for ChallengeModule {
    fn name(&self) -> &'static str {
        "challenge"
    }

    fn directives(&self) -> &'static [Directive] {
        &DIRECTIVES
    }

    fn configure_from_env(&self) -> Result<(), String> {
        configure_from_env()
    }

    fn seed(&self, seed: Option<&[u8]>) {
        configure(seed);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use http_body_util::BodyExt;
    use std::time::Instant;
    use webfast_core::extensions::At;

    fn conn() -> ConnInfo {
        ConnInfo {
            remote: "203.0.113.7:4000".parse().unwrap(),
            tls: true,
            trusted: false,
            sni: None,
            ja4: None,
        }
    }

    fn parts(method: &str, uri: &str, headers: &[(&str, &str)]) -> http::request::Parts {
        let mut builder = http::Request::builder()
            .method(method)
            .uri(uri)
            .header("host", "shop.example.com:8443");
        for (name, value) in headers {
            builder = builder.header(*name, *value);
        }
        builder.body(()).unwrap().into_parts().0
    }

    fn cookie_of(response: &Response<Body>) -> String {
        let header = response.headers()[header::SET_COOKIE].to_str().unwrap().to_string();
        assert!(header.ends_with("; Path=/; HttpOnly; SameSite=Lax; Secure"), "{header}");
        header.split(';').next().unwrap().to_string()
    }

    fn nonce_of(body: &str) -> String {
        let at = body.find("data-nonce=\"").unwrap() + "data-nonce=\"".len();
        body[at..at + token::NONCE_LEN].to_string()
    }

    #[test]
    fn the_cookie_level_redirects_and_the_cookie_then_passes() {
        let this = instance();
        let ip: IpAddr = "203.0.113.7".parse().unwrap();
        let asking = Asking {
            level: Level::Cookie,
            ..Asking::default()
        };
        let req = parts("GET", "/shop?x=1", &[("user-agent", "Mozilla/5.0")]);
        let response = this.ask(&conn(), &req, ip, &asking);
        assert_eq!(response.status(), StatusCode::FOUND);
        assert_eq!(response.headers()[header::LOCATION], "/shop?x=1");
        assert_eq!(response.headers()[header::CACHE_CONTROL], "no-store");
        let cookie = cookie_of(&response);
        let again = parts(
            "GET",
            "/shop?x=1",
            &[("user-agent", "Mozilla/5.0"), ("cookie", &cookie)],
        );
        assert!(this.passed(&conn(), &again, ip, Level::Cookie));
        assert!(
            !this.passed(&conn(), &again, ip, Level::Js),
            "a cookie-level cookie for a js ask"
        );
        let elsewhere: IpAddr = "198.51.100.1".parse().unwrap();
        assert!(!this.passed(&conn(), &again, elsewhere, Level::Cookie), "another block");
        let other_browser = parts("GET", "/", &[("user-agent", "curl/8"), ("cookie", &cookie)]);
        assert!(!this.passed(&conn(), &other_browser, ip, Level::Cookie));
        let among = format!("a=b; {cookie}; c=d");
        let with_others = parts("GET", "/", &[("user-agent", "Mozilla/5.0"), ("cookie", &among)]);
        assert!(this.passed(&conn(), &with_others, ip, Level::Cookie));
        // A POST at level cookie gets the js page.
        let post = parts("POST", "/form", &[("user-agent", "Mozilla/5.0")]);
        let response = this.ask(&conn(), &post, ip, &asking);
        assert_eq!(response.status(), StatusCode::SERVICE_UNAVAILABLE);
    }

    #[tokio::test]
    async fn the_js_page_and_its_answer_give_a_cookie() {
        let this = instance();
        let ip: IpAddr = "203.0.113.7".parse().unwrap();
        let req = parts("GET", "/", &[("user-agent", "Mozilla/5.0")]);
        let response = this.ask(&conn(), &req, ip, &Asking::default());
        assert_eq!(response.status(), StatusCode::SERVICE_UNAVAILABLE);
        assert_eq!(response.headers()[header::RETRY_AFTER], "5");
        assert_eq!(response.headers()[header::CACHE_CONTROL], "no-store");
        let csp = response.headers()[header::CONTENT_SECURITY_POLICY].to_str().unwrap();
        assert!(csp.starts_with("default-src 'none'; script-src 'sha256-"), "{csp}");
        assert!(csp.contains("connect-src 'self'"));
        assert!(!csp.contains("https://"), "no provider without a captcha");
        let id = response.headers()["x-request-id"].to_str().unwrap().to_string();
        assert_eq!(id.len(), 12);
        let body = response.into_body().collect().await.unwrap().to_bytes();
        let body = std::str::from_utf8(&body).unwrap();
        assert!(body.contains("<h1>shop.example.com</h1>"), "the host without its port");
        assert!(body.contains(&format!("Request {id}")));
        assert!(body.contains("data-level=\"js\""));
        let nonce = nonce_of(body);

        let answer =
            |nonce: &str, answer: &str| format!("nonce={nonce}&answer={answer}&url=https%3A%2F%2Fshop.example.com%2F");
        let digest = aws_lc_rs::digest::digest(&aws_lc_rs::digest::SHA256, nonce.as_bytes());
        let hex: String = digest.as_ref().iter().map(|b| format!("{b:02X}")).collect();
        let post = parts("POST", ENDPOINT, &[("user-agent", "Mozilla/5.0")]);
        let wrong = this.answer(&conn(), &post, ip, answer(&nonce, "00").as_bytes()).await;
        assert_eq!(wrong.status(), StatusCode::BAD_REQUEST);
        let stale = this.answer(&conn(), &post, ip, answer("AAAA", &hex).as_bytes()).await;
        assert_eq!(stale.status(), StatusCode::FORBIDDEN);
        let elsewhere: IpAddr = "198.51.100.1".parse().unwrap();
        let moved = this
            .answer(&conn(), &post, elsewhere, answer(&nonce, &hex).as_bytes())
            .await;
        assert_eq!(moved.status(), StatusCode::FORBIDDEN, "a nonce of another block");
        let good = this.answer(&conn(), &post, ip, answer(&nonce, &hex).as_bytes()).await;
        assert_eq!(good.status(), StatusCode::NO_CONTENT);
        let cookie = cookie_of(&good);
        assert!(
            cookie.contains("Max-Age=604800")
                || good.headers()[header::SET_COOKIE]
                    .to_str()
                    .unwrap()
                    .contains("Max-Age=604800")
        );
        let again = parts("GET", "/", &[("user-agent", "Mozilla/5.0"), ("cookie", &cookie)]);
        assert!(this.passed(&conn(), &again, ip, Level::Js));
        assert!(!this.passed(&conn(), &again, ip, Level::Pow));

        // Through the endpoint as a request check: other paths and methods pass by, synchronously.
        let c = conn();
        let client = Client {
            ip,
            conn: &c,
            at: At::Routes,
        };
        let mut other = parts("POST", "/other", &[]);
        assert!(matches!(ChallengeEndpoint.head(&mut other, client), Head::Pass));
        let mut get = parts("GET", ENDPOINT, &[]);
        assert!(matches!(ChallengeEndpoint.head(&mut get, client), Head::Pass));
        let mut bad = parts("POST", ENDPOINT, &[]);
        assert!(matches!(ChallengeEndpoint.head(&mut bad, client), Head::Body(())));
        let refused = ChallengeEndpoint
            .body((), &mut bad, webfast_core::body::full("nonce=x"), client)
            .await
            .expect_err("answered");
        assert_eq!(refused.status(), StatusCode::BAD_REQUEST);
        assert!(
            refused
                .extensions()
                .get::<webfast_core::extensions::ErrorPage>()
                .is_none()
        );
    }

    #[tokio::test]
    async fn the_pow_answer_is_checked_at_the_nonce_difficulty() {
        let this = instance();
        let ip: IpAddr = "203.0.113.7".parse().unwrap();
        let asking = Asking {
            level: Level::Pow,
            difficulty: 12,
            ..Asking::default()
        };
        let response = this.ask(&conn(), &parts("GET", "/", &[]), ip, &asking);
        let body = response.into_body().collect().await.unwrap().to_bytes();
        let body = std::str::from_utf8(&body).unwrap();
        assert!(body.contains("data-difficulty=\"12\""));
        let nonce = nonce_of(body);
        let counter = pow::search(nonce.as_bytes(), 12);
        let post = parts("POST", ENDPOINT, &[]);
        let form = format!("nonce={nonce}&answer={counter}");
        assert_eq!(
            this.answer(&conn(), &post, ip, form.as_bytes()).await.status(),
            StatusCode::NO_CONTENT
        );
        let short = (0u64..)
            .find(|c| !pow::check(nonce.as_bytes(), c.to_string().as_bytes(), 12))
            .unwrap();
        let form = format!("nonce={nonce}&answer={short}");
        assert_eq!(
            this.answer(&conn(), &post, ip, form.as_bytes()).await.status(),
            StatusCode::BAD_REQUEST
        );
    }

    #[tokio::test]
    async fn a_captcha_page_names_its_provider_in_the_csp() {
        let captcha = Captcha::new(captcha::Provider::Turnstile, "0x4AAA".into(), "secret".into()).register();
        let asking = Asking {
            level: Level::Captcha,
            captcha: Some(captcha),
            ..Asking::default()
        };
        let ip: IpAddr = "203.0.113.7".parse().unwrap();
        let response = instance().ask(&conn(), &parts("GET", "/", &[]), ip, &asking);
        let csp = response.headers()[header::CONTENT_SECURITY_POLICY]
            .to_str()
            .unwrap()
            .to_string();
        assert!(csp.contains("script-src 'sha256-"));
        assert!(csp.contains("https://challenges.cloudflare.com"), "{csp}");
        assert!(csp.contains("frame-src https://challenges.cloudflare.com"));
        let body = response.into_body().collect().await.unwrap().to_bytes();
        let body = std::str::from_utf8(&body).unwrap();
        assert!(body.contains("data-site-key=\"0x4AAA\""));
        assert!(body.contains("data-provider=\"turnstile\""));
        assert!(!body.contains("secret"));
        let nonce = nonce_of(body);
        let data = instance().keys().check_nonce(nonce.as_bytes(), ip, now_secs()).unwrap();
        assert_ne!(data.provider, 0, "the nonce names the provider");
        assert!(Captcha::by_index(data.provider).is_some());
    }

    #[test]
    fn a_site_page_without_the_built_in_script_alone_gets_no_csp() {
        let page = Arc::new(Page::parse("<html><script>x()</script>{challenge.nonce}</html>"));
        let asking = Asking {
            page: Some(page),
            ..Asking::default()
        };
        let response = instance().ask(
            &conn(),
            &parts("GET", "/", &[]),
            "203.0.113.7".parse().unwrap(),
            &asking,
        );
        assert!(response.headers().get(header::CONTENT_SECURITY_POLICY).is_none());
    }

    #[test]
    fn passing_is_fast() {
        let this = instance();
        let ip: IpAddr = "203.0.113.7".parse().unwrap();
        let asking = Asking {
            level: Level::Cookie,
            ..Asking::default()
        };
        const UA: &str = "Mozilla/5.0 (X11; Linux x86_64) Gecko/20100101 Firefox/130.0";
        let response = this.ask(&conn(), &parts("GET", "/", &[("user-agent", UA)]), ip, &asking);
        let cookie = cookie_of(&response);
        let req = parts("GET", "/", &[("user-agent", UA), ("cookie", &cookie)]);
        let c = conn();
        // The first: decode, verify, insert.
        let started = Instant::now();
        assert!(this.passed(&c, &req, ip, Level::Cookie));
        let verified = started.elapsed();
        // Then: decode, lookup.
        let rounds = 2000;
        let started = Instant::now();
        for _ in 0..rounds {
            assert!(this.passed(&c, &req, ip, Level::Cookie));
        }
        let hit = started.elapsed() / rounds;
        // Verification every time (the table holds this cookie, so measure the check itself).
        let ua = user_agent(&req);
        let value = cookie_value(&req.headers).unwrap();
        let started = Instant::now();
        for _ in 0..rounds {
            assert!(this.keys.check_cookie(value, ip, ua, now_secs()).is_some());
        }
        let verify = started.elapsed() / rounds;
        eprintln!("passed(): first (verify + insert) {verified:?}, table hit {hit:?}, verify alone {verify:?}");
        assert!(hit < Duration::from_micros(50), "a hit took {hit:?}");
        assert!(verify < Duration::from_micros(50), "a verification took {verify:?}");
    }

    #[test]
    fn the_table_forgets_expired_cookies_and_is_bounded() {
        let table = Passed::new();
        let mut key: PassedKey = [0; token::COOKIE_RAW + 6 + 8];
        key[1..5].copy_from_slice(&100u32.to_be_bytes());
        table.insert(key);
        assert!(table.contains(&key));
        assert_eq!(table.sweep(99), 1);
        assert_eq!(table.sweep(100), 0, "expired at its second");
        assert!(!table.contains(&key));
        assert_eq!(csp(None).matches("'sha256-").count(), 1);
        assert!(hex_equals(&[0xab, 0x01], b"AB01"));
        assert!(!hex_equals(&[0xab, 0x01], b"ab02"));
        assert!(!hex_equals(&[0xab], b"abc"));
        assert_eq!(form_value(b"a+b%26c"), "a b&c");
    }
}
