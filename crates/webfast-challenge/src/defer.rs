//! `defer`: the challenge asked only of a client over a rate. One GCRA cell per key (the time at
//! which the key is rested again, 8 bytes under its hash), in 64 shards each under its own lock on
//! cache lines of its own, the shape of webfast_core::ratelimit's zones: `events` requests may come in a
//! `window`, then the key is asked until it rests. `count pages` counts navigations only (GET or
//! HEAD, `Accept` with `text/html`, `Sec-Fetch-Mode` absent or `navigate`, no static extension),
//! so a page with sixty assets is one page; `count all` counts everything.
//!
//! The cells outlive a reload when the directive's place and limits stay (the identity is
//! `file:line|events|window|key|count`), as a zone's do. One sweeper thread drops the keys that
//! rested and logs, once a minute, what the module asked, passed and failed per level.

use http::Method;
use rustc_hash::FxHashMap;
use std::net::IpAddr;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, LazyLock, Mutex, PoisonError, Weak};
use std::time::{Duration, Instant};
use webfast_core::handler::Ctx;
use webfast_core::placeholder::{Sole, Template};

const SHARDS: usize = 64;
/// The keys a `defer` remembers at most (WEB_RATE_LIMIT_KEYS is the zones'; this is the same
/// figure, with no variable of its own).
const MAX_KEYS: usize = 1_000_000;
/// How often the cells are swept and the counters logged.
const SWEEP: Duration = Duration::from_secs(60);

/// Extensions of requests that are no page: not counted with `count pages`.
const STATIC_EXTENSIONS: &[&str] = &[
    "css",
    "js",
    "mjs",
    "map",
    "png",
    "jpg",
    "jpeg",
    "gif",
    "webp",
    "avif",
    "svg",
    "ico",
    "woff",
    "woff2",
    "ttf",
    "json",
    "xml",
    "txt",
    "webmanifest",
];

/// What `defer` counts.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Count {
    Pages,
    All,
}

impl Count {
    pub fn name(self) -> &'static str {
        match self {
            Count::Pages => "pages",
            Count::All => "all",
        }
    }
}

/// A `defer` block as parsed.
pub struct DeferSpec {
    pub events: u64,
    pub window: Duration,
    pub key: Template,
    pub count: Count,
    /// Where the directive stands (`file:line`): part of the cells' identity across reloads.
    pub at: String,
}

/// The deferred threshold of one directive.
pub struct Defer {
    key: Key,
    count: Count,
    events: u64,
    window: Duration,
    state: Arc<Cells>,
}

enum Key {
    Static,
    Address(Sole),
    Template(Template),
}

/// The cells of a `defer`, shared by the configurations that have it.
struct Cells {
    /// `window / events`, and the burst a rested key may make: `window - interval`.
    interval: u64,
    tolerance: u64,
    hasher: ahash::RandomState,
    shards: Vec<Shard>,
    identity: String,
    /// Requests asked by this `defer` since the last summary.
    asked: AtomicU64,
}

/// One shard, on cache lines of its own (see webfast_core::ratelimit).
#[repr(align(128))]
struct Shard(Mutex<FxHashMap<u64, u64>>);

impl Shard {
    fn lock(&self) -> std::sync::MutexGuard<'_, FxHashMap<u64, u64>> {
        self.0.lock().unwrap_or_else(PoisonError::into_inner)
    }
}

/// The cells alive, for the sweeper and for reloads to take over.
static CELLS: Mutex<Vec<Weak<Cells>>> = Mutex::new(Vec::new());

/// Monotonic nanoseconds since the first use.
fn now_nanos() -> u64 {
    static START: LazyLock<Instant> = LazyLock::new(Instant::now);
    START.elapsed().as_nanos() as u64
}

impl Defer {
    pub fn new(spec: DeferSpec) -> Defer {
        let key = match spec.key.sole_address() {
            Some(sole) => Key::Address(sole),
            None if spec.key.as_static().is_some() => Key::Static,
            None => Key::Template(spec.key.clone()),
        };
        let events = spec.events.max(1);
        let window = spec.window.as_nanos().min(u128::from(u64::MAX / 4)) as u64;
        let interval = (window / events).max(1);
        let identity = format!(
            "{}|{events}|{window}|{}|{}",
            spec.at,
            spec.key.source(),
            spec.count.name()
        );
        let state = Cells::find_or_make(identity, || Cells {
            interval,
            tolerance: window.saturating_sub(interval),
            hasher: ahash::RandomState::new(),
            shards: (0..SHARDS).map(|_| Shard(Mutex::new(FxHashMap::default()))).collect(),
            identity: String::new(),
            asked: AtomicU64::new(0),
        });
        start_sweeper();
        Defer {
            key,
            count: spec.count,
            events,
            window: spec.window,
            state,
        }
    }

    /// `events 100 window 10m, pages`, for `validate`.
    pub fn describe(&self) -> String {
        format!("defer {} in {:?}, {}", self.events, self.window, self.count.name())
    }

    /// Whether the request is one this `defer` counts (by its path alone, when `by_path`: what is
    /// known while answers are prepared, webfast_core::memo).
    pub fn counts(&self, ctx: &Ctx) -> bool {
        match self.count {
            Count::All => true,
            Count::Pages => is_page(ctx),
        }
    }

    /// Whether a request of `path` may be one this `defer` counts: with `count pages`, not an
    /// asset's.
    pub fn may_count_path(&self, path: &str) -> bool {
        self.count == Count::All || !static_extension(path)
    }

    /// Counts the request for its key: `true` when the key is over the rate and the client is to
    /// be asked.
    pub fn over(&self, ctx: &Ctx) -> bool {
        let hash = match &self.key {
            Key::Static => 0,
            Key::Address(sole) => self
                .state
                .hasher
                .hash_one(webfast_core::guard::address_key(address(sole, ctx))),
            Key::Template(template) => template.with_rendered(ctx, |text| match text.parse::<IpAddr>() {
                Ok(ip) => self.state.hasher.hash_one(webfast_core::guard::address_key(ip)),
                Err(_) => self.state.hasher.hash_one(text.as_bytes()),
            }),
        };
        let over = self.state.take(hash, now_nanos());
        if over {
            self.state.asked.fetch_add(1, Ordering::Relaxed);
        }
        over
    }
}

fn address(sole: &Sole, ctx: &Ctx) -> IpAddr {
    match sole {
        Sole::ClientIp => ctx.client_ip,
        Sole::RemoteHost => ctx.conn.remote.ip(),
    }
}

/// A navigation: GET or HEAD for HTML, not an asset.
fn is_page(ctx: &Ctx) -> bool {
    let req = &ctx.req;
    if req.method != Method::GET && req.method != Method::HEAD {
        return false;
    }
    let accepts_html = req
        .headers
        .get(http::header::ACCEPT)
        .and_then(|v| v.to_str().ok())
        .is_some_and(|accept| accept.contains("text/html"));
    if !accepts_html {
        return false;
    }
    let navigates = req
        .headers
        .get("sec-fetch-mode")
        .is_none_or(|mode| mode.as_bytes() == b"navigate");
    navigates && !static_extension(req.uri.path())
}

/// Whether the path's last segment ends in a static extension.
fn static_extension(path: &str) -> bool {
    let name = path.rsplit('/').next().unwrap_or(path);
    let Some(dot) = name.rfind('.') else {
        return false;
    };
    let extension = &name[dot + 1..];
    STATIC_EXTENSIONS
        .iter()
        .any(|known| known.eq_ignore_ascii_case(extension))
}

impl Cells {
    fn find_or_make(identity: String, make: impl FnOnce() -> Cells) -> Arc<Cells> {
        let mut all = CELLS.lock().unwrap_or_else(PoisonError::into_inner);
        all.retain(|cells| cells.strong_count() > 0);
        if let Some(found) = all.iter().filter_map(Weak::upgrade).find(|c| c.identity == identity) {
            return found;
        }
        let mut cells = make();
        cells.identity = identity;
        let cells = Arc::new(cells);
        all.push(Arc::downgrade(&cells));
        cells
    }

    /// One request of the key at `now`: `false` when it passes (and is counted), `true` when the
    /// key is over the rate (the request is not counted: the key rests meanwhile).
    fn take(&self, hash: u64, now: u64) -> bool {
        let mut shard = self.shards[(hash as usize) % SHARDS].lock();
        if shard.len() >= MAX_KEYS / SHARDS && !shard.contains_key(&hash) {
            shard.retain(|_, rested_at| *rested_at > now);
            if shard.len() >= MAX_KEYS / SHARDS {
                // Full of keys still counting: the new key is asked rather than let through
                // uncounted (as a full `rate_limit` zone refuses).
                return true;
            }
        }
        let rested_at = shard.entry(hash).or_insert(now);
        let at = (*rested_at).max(now);
        if at - now > self.tolerance {
            return true;
        }
        *rested_at = at + self.interval;
        false
    }

    /// Drops the keys fully rested; how many remain.
    fn sweep(&self, now: u64) -> usize {
        self.shards
            .iter()
            .map(|shard| {
                let mut shard = shard.lock();
                shard.retain(|_, rested_at| *rested_at > now);
                shard.len()
            })
            .sum()
    }
}

/// The sweeper (webfast_core::background `Worker`, without jobs): once a minute the cells are swept and
/// the module's counters logged.
static SWEEPER: LazyLock<webfast_core::background::Worker<std::convert::Infallible>> = LazyLock::new(|| {
    webfast_core::background::Worker::start(
        "web-challenge",
        1,
        0,
        SWEEP,
        |never| async move { match never {} },
        move |_| {
            let all: Vec<Arc<Cells>> = {
                let mut all = CELLS.lock().unwrap_or_else(PoisonError::into_inner);
                all.retain(|cells| cells.strong_count() > 0);
                all.iter().filter_map(Weak::upgrade).collect()
            };
            let now = now_nanos();
            for cells in all {
                let keys = cells.sweep(now);
                let asked = cells.asked.swap(0, Ordering::Relaxed);
                if asked > 0 {
                    tracing::info!(defer = %cells.identity, asked, keys, "clients over the rate were challenged");
                }
            }
            super::log_summary();
        },
    )
});

pub(super) fn start_sweeper() {
    LazyLock::force(&SWEEPER);
}

#[cfg(test)]
mod tests {
    use super::*;
    use webfast_core::handler::ConnInfo;

    fn cells(events: u64, window: Duration) -> Cells {
        let window = window.as_nanos() as u64;
        let interval = window / events;
        Cells {
            interval,
            tolerance: window - interval,
            hasher: ahash::RandomState::new(),
            shards: (0..SHARDS).map(|_| Shard(Mutex::new(FxHashMap::default()))).collect(),
            identity: String::new(),
            asked: AtomicU64::new(0),
        }
    }

    fn ctx(method: &str, path: &str, headers: &[(&str, &str)]) -> Ctx {
        let conn = Arc::new(ConnInfo {
            remote: "127.0.0.1:5000".parse().unwrap(),
            tls: false,
            trusted: false,
            sni: None,
        });
        let mut builder = http::Request::builder().method(method).uri(path);
        for (name, value) in headers {
            builder = builder.header(*name, *value);
        }
        let (parts, body) = builder.body(webfast_core::body::empty()).unwrap().into_parts();
        Ctx::new(conn, parts, body, "127.0.0.1".parse().unwrap())
    }

    #[test]
    fn the_hundred_and_first_page_in_the_window_is_asked_and_the_key_rests() {
        let cells = cells(100, Duration::from_secs(600));
        let second = 1_000_000_000;
        for i in 0..100 {
            assert!(!cells.take(7, 0), "page {}", i + 1);
        }
        assert!(cells.take(7, 0), "the 101st is asked");
        assert!(!cells.take(8, 0), "another key has its own count");
        // One interval (6 s) later one more passes, then asked again.
        assert!(!cells.take(7, 6 * second));
        assert!(cells.take(7, 6 * second));
        // Rested after the window: a hundred again.
        assert_eq!(cells.sweep(700 * second), 0);
        for _ in 0..100 {
            assert!(!cells.take(7, 700 * second));
        }
        assert!(cells.take(7, 700 * second));
    }

    #[test]
    fn assets_and_api_calls_are_not_pages() {
        let html = [("accept", "text/html,application/xhtml+xml,*/*;q=0.8")];
        assert!(is_page(&ctx("GET", "/", &html)));
        assert!(is_page(&ctx("HEAD", "/shop/item?id=3", &html)));
        assert!(is_page(&ctx("GET", "/docs/v1.2/", &html)));
        assert!(!is_page(&ctx("GET", "/app.js", &html)));
        assert!(!is_page(&ctx("GET", "/img/logo.PNG", &html)));
        assert!(!is_page(&ctx("GET", "/site.webmanifest", &html)));
        assert!(!is_page(&ctx("GET", "/api/items", &[("accept", "application/json")])));
        assert!(!is_page(&ctx("POST", "/form", &html)));
        assert!(!is_page(&ctx(
            "GET",
            "/fragment",
            &[("accept", "text/html"), ("sec-fetch-mode", "cors")]
        )));
        assert!(is_page(&ctx(
            "GET",
            "/page",
            &[("accept", "text/html"), ("sec-fetch-mode", "navigate")]
        )));
        assert!(!is_page(&ctx("GET", "/", &[])), "no Accept: not a browser's navigation");
        assert!(static_extension("/a/b.css"));
        assert!(!static_extension("/a.css/b"));
        assert!(!static_extension("/a/b.html"));
    }

    #[test]
    fn a_defer_counts_by_client_and_keeps_its_cells_across_configurations() {
        let spec = || DeferSpec {
            events: 2,
            window: Duration::from_secs(60),
            key: Template::parse("{client_ip}").unwrap(),
            count: Count::All,
            at: "Caddyfile:7".to_string(),
        };
        let defer = Defer::new(spec());
        let ctx = ctx("GET", "/", &[]);
        assert!(defer.counts(&ctx));
        assert!(!defer.over(&ctx));
        assert!(!defer.over(&ctx));
        assert!(defer.over(&ctx), "the third is asked");
        let reloaded = Defer::new(spec());
        assert!(
            Arc::ptr_eq(&defer.state, &reloaded.state),
            "the same cells after a reload"
        );
        assert!(reloaded.over(&ctx), "still over");
        let other = Defer::new(DeferSpec {
            at: "Caddyfile:9".to_string(),
            ..spec()
        });
        assert!(!Arc::ptr_eq(&defer.state, &other.state));
        assert!(!other.over(&ctx));
        assert!(defer.may_count_path("/page"));
        assert!(
            Defer::new(DeferSpec {
                count: Count::Pages,
                ..spec()
            })
            .may_count_path("/page")
        );
        assert!(
            !Defer::new(DeferSpec {
                count: Count::Pages,
                ..spec()
            })
            .may_count_path("/a.css")
        );
        assert!(defer.describe().starts_with("defer 2 in 60s"));
    }
}
