//! The request filter (the `webfast-ngfw` crate; the webfast binary's cargo feature `ngfw`; on when
//! `WEB_NGFW_CONFIG` names its YAML file, docs/ngfw.md): requests refused, marked or logged by
//! rules — protocol anomalies, scanners, injection, traversal, PHP and upload attacks, data leaking
//! in responses — and by where they come from: country, ASN, address lists, a dynamic ban list.
//!
//! A module of the core (`webfast_core::module`, webfast's docs/modules.md): `MODULE` is what the
//! binary's composition registers, and the loaded `Ngfw` (`Module::load` puts it into
//! `config.modules`) its slot among the composed checks, `Option<Arc<Ngfw>>`. It is a request check
//! (`module::Check`) after the ACME challenge answer and the browser challenge's endpoint (the
//! `connection`, `head`, `body` and `upload` phases; the head decides synchronously, the body is
//! read only when its type is listed and there are rules for it) and an inspector of proxied
//! responses (`module::Inspect`, `response::NgfwResponses`; the `response` phase, response.rs).
//! The file is composed into one rule list (config.rs) and compiled into automata per phase and
//! target (compile.rs); a request is evaluated in thread-local buffers (engine.rs) and allocates
//! nothing when it is clean. The loaded state is one `Arc` under `ArcSwap`, replaced whole by a
//! reload (SIGHUP, `reload`): a file that does not load keeps the old rules.
//!
//! With the browser challenge built (this crate's `challenge` feature, on by default: the
//! `webfast-challenge` crate, docs/challenge.md), a refusal may be the challenge instead:
//! `action: challenge` or `mode: challenge` on a rule, a set or the module,
//! `access.countries.challenge`, `access.asn.challenge`, and `access.ban.then: challenge`. The
//! module asks with one `Asking` built from `response.challenge` at load; a client that passed
//! (a good cookie) goes on with the hit logged as `challenge_passed`.
//!
//! With libinjection built (the `libinjection` feature, on by default: the barbacane-libinjection
//! crate, detect.rs), the `detect_sqli` and `detect_xss` operators run its detectors on the values
//! a rule's prefilter let through.
//!
//! What a clean GET costs: one `ArcSwap` load, the allow list and ban list lookups, the geo
//! lookups when databases are given, and one pass of each head group's automaton over its target.

pub mod ban;
pub mod body;
pub mod compile;
pub mod config;
pub mod detect;
pub mod engine;
pub mod geo;
pub mod iplist;
pub mod log;
pub mod multipart;
pub mod response;
pub mod rule;
pub mod rules;

use anyhow::{Context, Result, bail};
use arc_swap::{ArcSwap, ArcSwapOption};
use ban::Bans;
use compile::Compiled;
use config::{FileConfig, Loaded};
use engine::{Decision, Evaluation, Input};
use geo::Geo;
use http::{HeaderName, HeaderValue, Response, StatusCode};
use iplist::IpLists;
use log::{Outcome, Record};
use rule::{Mode, Phase};
use std::net::IpAddr;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::{Duration, Instant};
use webfast_core::body::Body;
use webfast_core::config::Config;
use webfast_core::extensions::{Checked, Client, ErrorPage};
use webfast_core::matcher::{PathPattern, host_matches};
use webfast_core::module::{Check, Head, Module};

/// How often the background task looks at what is due (file changes, feeds, the ban sweep).
const TICK: Duration = Duration::from_secs(60);

/// The module as loaded from its file; `Ngfw` keeps the current one and swaps it on reload.
pub struct State {
    mode: Mode,
    threshold: u32,
    status: StatusCode,
    leak_status: StatusCode,
    /// `response.stream`: a 200 is scanned as it streams (response.rs).
    response_stream: bool,
    /// What a streamed response carries across a frame boundary; `None`: no rule reads the
    /// response body.
    response_carry: Option<usize>,
    log: webfast_core::eventlog::EventLog,
    log_matched: usize,
    log_passed: bool,
    compiled: Compiled,
    loaded: Loaded,
    max_inspect: usize,
    body_types: Vec<String>,
    limits: body::Limits,
    geo: Option<Geo>,
    geo_reload: Duration,
    geo_header: Option<HeaderName>,
    lists: IpLists,
    bans: Bans,
    countries: Option<ListAccess<[u8; 2]>>,
    asn: Option<ListAccess<u32>>,
    /// `access.countries.challenge` / `access.asn.challenge`: asked, not refused.
    countries_challenge: Option<ListAccess<[u8; 2]>>,
    asn_challenge: Option<ListAccess<u32>>,
    honeypots: Vec<PathPattern>,
    matcher: Option<Match>,
    has_feeds: bool,
    /// What the challenges of this module are asked with (`response.challenge`).
    #[cfg(feature = "challenge")]
    asking: webfast_challenge::Asking,
}

/// `access.countries` / `access.asn`: an allow list (everything else refused, the unknown too) or
/// a deny list.
struct ListAccess<T> {
    allow: bool,
    items: Vec<T>,
    except: Vec<PathPattern>,
}

impl<T: PartialEq> ListAccess<T> {
    /// Whether a client with `value` (none: unknown) is refused.
    fn refuses(&self, value: Option<T>, match_path: &str) -> bool {
        if self.except.iter().any(|p| p.matches_path(match_path)) {
            return false;
        }
        match value {
            Some(value) => self.items.contains(&value) != self.allow,
            None => self.allow,
        }
    }
}

/// `match`: where the module runs at all.
struct Match {
    hosts: Vec<String>,
    except: Vec<PathPattern>,
}

impl Match {
    fn applies(&self, host: &str, match_path: &str) -> bool {
        (self.hosts.is_empty() || self.hosts.iter().any(|h| host_matches(h, host)))
            && !self.except.iter().any(|p| p.matches_path(match_path))
    }
}

pub struct Ngfw {
    /// The file, for a reload; `None` for one loaded from text.
    path: Option<PathBuf>,
    state: ArcSwap<State>,
    /// Query parameters the JWT check hides from the logs, told after both are loaded.
    hidden: ArcSwap<Vec<String>>,
}

/// The running instance, for a reload (`Module::reload` has no configuration to find it in): set
/// when the server starts (`Module::start`).
static INSTALLED: ArcSwapOption<Ngfw> = ArcSwapOption::const_empty();

/// What the head phase hands the body phase (`Check::Pending`, by value: `Head::Body`): the state
/// the head ran with, its evaluation so far, and the body's kind.
pub struct Pending {
    state: Arc<State>,
    evaluation: Evaluation,
    geo: (Option<[u8; 2]>, Option<u32>),
    hidden: Arc<Vec<String>>,
    kind: body::Kind,
}

/// The module as the binary registers it (`webfast_core::module::Module`): WEB_NGFW_CONFIG read
/// at `load`, the background work at `start`, the file read again on SIGHUP.
pub struct NgfwModule;

/// The one to register.
pub static MODULE: NgfwModule = NgfwModule;

impl Module for NgfwModule {
    fn name(&self) -> &'static str {
        "ngfw"
    }

    fn load(&self, config: &mut Config) -> Result<Vec<String>> {
        let Some(path) = std::env::var("WEB_NGFW_CONFIG")
            .ok()
            .map(|v| v.trim().to_string())
            .filter(|v| !v.is_empty())
        else {
            return Ok(Vec::new());
        };
        let ngfw = Ngfw::load(Path::new(&path))?;
        let mut loaded = Vec::new();
        let mut lines = ngfw.summary().into_iter();
        if let Some(first) = lines.next() {
            loaded.push(format!("NGFW: {path}, {first}"));
        }
        loaded.extend(lines.map(|line| format!("NGFW: {line}")));
        // The module logs before the JWT check runs: told which parameters to hide.
        ngfw.hide_params(config.hidden_params.clone());
        config.modules.insert(Arc::new(ngfw));
        Ok(loaded)
    }

    fn start(&self, config: &Config) -> Result<()> {
        let ngfw = config.modules.get::<Ngfw>();
        INSTALLED.store(ngfw.clone());
        match ngfw {
            Some(ngfw) => ngfw.start(),
            None => Ok(()),
        }
    }

    fn reload(&self) -> Vec<String> {
        let mut lines = Vec::new();
        if let Some(ngfw) = INSTALLED.load_full() {
            match ngfw.reload() {
                Ok(()) => lines.extend(ngfw.summary().into_iter().map(|line| format!("NGFW: {line}"))),
                Err(e) => lines.push(format!("NGFW: not reloaded, the running rules stay: {e:#}")),
            }
        }
        lines
    }
}

fn patterns(list: &[String]) -> Vec<PathPattern> {
    list.iter().map(|p| PathPattern::new(p)).collect()
}

fn country_codes(codes: &[String], what: &str) -> Result<Vec<[u8; 2]>> {
    codes
        .iter()
        .map(|code| {
            let bytes = code.as_bytes();
            if bytes.len() != 2 || !bytes.iter().all(u8::is_ascii_alphabetic) {
                bail!("{what}: {code:?} is not an ISO 3166-1 alpha-2 code");
            }
            Ok([bytes[0].to_ascii_uppercase(), bytes[1].to_ascii_uppercase()])
        })
        .collect()
}

/// A duration field, with the default where the struct was not deserialized (an empty string).
fn duration_or(text: &str, default: &str) -> Result<Duration> {
    config::duration(if text.trim().is_empty() { default } else { text })
}

fn status(code: u16, what: &str) -> Result<StatusCode> {
    StatusCode::from_u16(code).with_context(|| format!("{what}: not a status: {code}"))
}

/// The challenge's `Asking` from `response`: the level, how long a pass is good, the binding, the
/// CAPTCHA provider registered process-wide.
#[cfg(feature = "challenge")]
fn asking(response: &config::ResponseConfig) -> Result<webfast_challenge::Asking> {
    use webfast_challenge::captcha::{Captcha, Provider};
    use webfast_challenge::{Asking, Bind, Level};
    let mut asking = Asking::default();
    if let Some(level) = &response.challenge {
        asking.level = Level::parse(level)
            .ok_or_else(|| anyhow::anyhow!("response.challenge: cookie, js, pow or captcha, not {level:?}"))?;
    }
    if let Some(valid) = &response.challenge_valid {
        asking.valid = config::duration(valid).context("response.challenge_valid")?;
        if asking.valid.is_zero() {
            bail!("response.challenge_valid: a pass is good for some time");
        }
    }
    if let Some(bind) = &response.challenge_bind {
        asking.bind = match bind.as_str() {
            "ip" => Bind::Ip,
            "none" => Bind::None,
            other => bail!("response.challenge_bind: ip or none, not {other:?}"),
        };
    }
    if let Some(captcha) = &response.captcha {
        let provider = Provider::parse(&captcha.provider).ok_or_else(|| {
            anyhow::anyhow!(
                "response.captcha.provider: turnstile, hcaptcha or recaptcha, not {:?}",
                captcha.provider
            )
        })?;
        if captcha.site_key.trim().is_empty() {
            bail!("response.captcha: site_key is empty");
        }
        asking.captcha = Some(Captcha::new(provider, captcha.site_key.clone(), captcha.secret()?).register());
    }
    if asking.level == Level::Captcha && asking.captcha.is_none() {
        bail!("response.challenge: level captcha needs response.captcha with the provider and its keys");
    }
    Ok(asking)
}

impl State {
    fn new(file: FileConfig, base: &Path) -> Result<State> {
        if file.mode == Mode::Challenge {
            config::needs_challenge("mode: challenge")?;
        }
        if file.response.asks_challenge() {
            config::needs_challenge("response.challenge")?;
        }
        if file.access.ban.then == ban::Then::Challenge {
            config::needs_challenge("access.ban.then: challenge")?;
        }
        let (rules, loaded) = config::compose(&file.rules, base)?;
        let compiled = compile::compile(&rules, file.mode, &file.rules.exclusions)?;
        let geo = match &file.geo {
            Some(config) if config.country_db.is_some() || config.asn_db.is_some() => Some(Geo::open(config, base)?),
            _ => None,
        };
        let geo_reload =
            duration_or(file.geo.as_ref().map_or("", |g| g.reload.as_str()), "24h").context("geo.reload")?;
        let geo_header = match file.geo.as_ref().and_then(|g| g.header.as_deref()) {
            Some(name) => {
                Some(HeaderName::from_bytes(name.as_bytes()).with_context(|| format!("geo.header {name:?}"))?)
            }
            None => None,
        };
        let access = &file.access;
        let mut countries_challenge = None;
        let countries = match &access.countries {
            Some(c) => {
                if !c.allow.is_empty() && !c.deny.is_empty() {
                    bail!("access.countries: allow or deny, not both");
                }
                if geo.as_ref().is_none_or(|g| !g.has_country()) {
                    bail!("access.countries needs geo.country_db");
                }
                if !c.challenge.is_empty() {
                    config::needs_challenge("access.countries.challenge")?;
                    countries_challenge = Some(ListAccess {
                        allow: false,
                        items: country_codes(&c.challenge, "access.countries.challenge")?,
                        except: patterns(&c.except_paths),
                    });
                }
                let allow = !c.allow.is_empty();
                Some(ListAccess {
                    allow,
                    items: country_codes(if allow { &c.allow } else { &c.deny }, "access.countries")?,
                    except: patterns(&c.except_paths),
                })
            }
            None => None,
        };
        let asns = |list: &[String], what: &str| {
            list.iter()
                .map(|n| rule::parse_asn(n).map_err(anyhow::Error::msg))
                .collect::<Result<Vec<u32>>>()
                .context(what.to_string())
        };
        let mut asn_challenge = None;
        let asn = match &access.asn {
            Some(a) => {
                if !a.allow.is_empty() && !a.deny.is_empty() {
                    bail!("access.asn: allow or deny, not both");
                }
                if geo.as_ref().is_none_or(|g| !g.has_asn()) {
                    bail!("access.asn needs geo.asn_db");
                }
                if !a.challenge.is_empty() {
                    config::needs_challenge("access.asn.challenge")?;
                    asn_challenge = Some(ListAccess {
                        allow: false,
                        items: asns(&a.challenge, "access.asn.challenge")?,
                        except: Vec::new(),
                    });
                }
                let allow = !a.allow.is_empty();
                Some(ListAccess {
                    allow,
                    items: asns(if allow { &a.allow } else { &a.deny }, "access.asn")?,
                    except: Vec::new(),
                })
            }
            None => None,
        };
        let mut ban = access.ban.clone();
        if ban.window.trim().is_empty() {
            ban.window = "10m".to_string();
        }
        if ban.r#for.trim().is_empty() {
            ban.r#for = "1h".to_string();
        }
        let bans = Bans::new(&ban).context("access.ban")?;
        let lists = IpLists::new(&access.ip, base).context("access.ip")?;
        let log = webfast_core::eventlog::EventLog::new(
            "ngfw",
            file.log
                .as_ref()
                .map(|l| webfast_core::eventlog::LogConfig {
                    output: l.output.clone(),
                })
                .as_ref(),
            base,
        );
        if !matches!(file.response.status, 403 | 404 | 444) {
            bail!("response.status: 403, 404 or 444, not {}", file.response.status);
        }
        Ok(State {
            mode: file.mode,
            threshold: file.threshold,
            status: status(file.response.status, "response.status")?,
            leak_status: status(file.response.leak_status, "response.leak_status")?,
            response_stream: file.response.stream,
            response_carry: compiled.response_carry(response::WINDOW),
            log,
            log_matched: file.log.as_ref().map_or(200, |l| l.matched),
            log_passed: file.log.as_ref().is_some_and(|l| l.passed),
            compiled,
            loaded,
            max_inspect: config::size(&file.body.max_inspect).context("body.max_inspect")?,
            body_types: file.body.types.iter().map(|t| t.to_ascii_lowercase()).collect(),
            limits: body::Limits {
                json_max_depth: file.body.json_max_depth,
                multipart_max_parts: file.body.multipart_max_parts,
                upload_head: config::size(&file.body.upload_head).context("body.upload_head")?,
            },
            geo,
            geo_reload,
            geo_header,
            lists,
            bans,
            countries,
            asn,
            countries_challenge,
            asn_challenge,
            honeypots: patterns(&access.ban.honeypots),
            matcher: file.matcher.as_ref().map(|m| Match {
                hosts: m.hosts.iter().map(|h| h.to_ascii_lowercase()).collect(),
                except: patterns(&m.except_paths),
            }),
            has_feeds: !access.ip.feeds.is_empty(),
            #[cfg(feature = "challenge")]
            asking: asking(&file.response)?,
        })
    }

    /// The refusing response: `status`, no body, through the site's `handle_errors`; 444 is the
    /// last on its connection.
    fn refusal(&self, status: StatusCode) -> Response<Body> {
        let mut response = Response::new(webfast_core::body::empty());
        *response.status_mut() = status;
        response.extensions_mut().insert(ErrorPage);
        if status.as_u16() == 444 {
            response
                .headers_mut()
                .insert(http::header::CONNECTION, HeaderValue::from_static("close"));
        }
        response
    }

    /// `geo.header`: the client's country code on the request, `--` for none.
    fn set_geo_header(&self, parts: &mut http::request::Parts, geo: (Option<[u8; 2]>, Option<u32>)) {
        if let Some(name) = &self.geo_header {
            let code = geo.0.and_then(|c| HeaderValue::from_bytes(&c).ok());
            parts
                .headers
                .insert(name.clone(), code.unwrap_or_else(|| HeaderValue::from_static("--")));
        }
    }

    fn country(&self, ip: IpAddr) -> Option<[u8; 2]> {
        self.geo.as_ref().and_then(|g| g.country(ip))
    }

    fn asn(&self, ip: IpAddr) -> Option<u32> {
        self.geo.as_ref().and_then(|g| g.asn(ip))
    }
}

/// What the access decisions and `match` say before the rules run.
enum Pre {
    /// Not matched: nothing runs.
    Skip,
    Refuse(&'static str),
    Honeypot,
    /// The browser challenge is due (`access.*.challenge`, a `ban.then: challenge` mark), with
    /// the reason; the rules run when the client passed it.
    Challenge(&'static str),
    Go,
}

/// What a phase's end means for the request.
enum Settled {
    Go,
    /// A `pass` rule: nothing more is checked.
    Stop,
    Refuse(Response<Body>),
}

impl Ngfw {
    /// Reads the YAML file at `path`; its `include` files, lists, databases and `log.output` are
    /// relative to it.
    pub fn load(path: &Path) -> Result<Ngfw> {
        let text = std::fs::read_to_string(path).with_context(|| format!("reading {}", path.display()))?;
        let state = State::new(parse(&text)?, path.parent().unwrap_or(Path::new(".")))
            .with_context(|| format!("NGFW configuration {}", path.display()))?;
        Ok(Ngfw {
            path: Some(path.to_path_buf()),
            state: ArcSwap::from_pointee(state),
            hidden: ArcSwap::from_pointee(Vec::new()),
        })
    }

    /// From the file's text, with relative paths under `base` (tests).
    pub fn load_str(yaml: &str, base: &Path) -> Result<Ngfw> {
        let state = State::new(parse(yaml)?, base).context("NGFW configuration")?;
        Ok(Ngfw {
            path: None,
            state: ArcSwap::from_pointee(state),
            hidden: ArcSwap::from_pointee(Vec::new()),
        })
    }

    /// Reads the file again and puts the new rules in place; an error keeps the old ones. The
    /// ban list starts afresh with the new state.
    pub fn reload(&self) -> Result<()> {
        let Some(path) = &self.path else {
            return Ok(());
        };
        let text = std::fs::read_to_string(path).with_context(|| format!("reading {}", path.display()))?;
        let state = State::new(parse(&text)?, path.parent().unwrap_or(Path::new(".")))
            .with_context(|| format!("NGFW configuration {}", path.display()))?;
        self.state.store(Arc::new(state));
        Ok(())
    }

    /// Query parameters whose values the logs do not show (the JWT check's `from_params`).
    pub fn hide_params(&self, names: Vec<String>) {
        self.hidden.store(Arc::new(names));
    }

    /// Rules, sets (for the startup log).
    pub fn counts(&self) -> (usize, usize) {
        let state = self.state.load();
        (state.loaded.total(), state.loaded.counts.len())
    }

    /// The lines of `webfast validate` and the startup log: what was loaded, then every replaced,
    /// overridden and disabled id and every warning.
    pub fn summary(&self) -> Vec<String> {
        let state = self.state.load();
        let loaded = &state.loaded;
        let sets: Vec<String> = loaded.counts.iter().map(|(set, n)| format!("{set} {n}")).collect();
        let (allow, deny) = state.lists.counts();
        let mut lines = vec![format!(
            "{} rule(s) in {} set(s) ({}), mode {}, threshold {}, {} allowed and {} denied address(es){}{}",
            loaded.total(),
            loaded.counts.len(),
            sets.join(", "),
            match state.mode {
                Mode::Block => "block",
                Mode::LogOnly => "log_only",
                Mode::Challenge => "challenge",
            },
            state.threshold,
            allow,
            deny,
            if state.geo.as_ref().is_some_and(Geo::has_country) {
                ", countries"
            } else {
                ""
            },
            if state.geo.as_ref().is_some_and(Geo::has_asn) {
                ", ASNs"
            } else {
                ""
            },
        )];
        for (what, ids) in [
            ("replaced", &loaded.replaced),
            ("overridden", &loaded.overridden),
            ("disabled", &loaded.disabled),
        ] {
            if !ids.is_empty() {
                lines.push(format!("{what}: {}", ids.join(", ")));
            }
        }
        for warning in &loaded.warnings {
            lines.push(format!("warning: {warning}"));
        }
        lines
    }

    /// Starts the background work on the current tokio runtime: every minute, the ban list's
    /// sweep, the address files looked at for a change, the geo databases every `geo.reload`,
    /// and the feeds that are due.
    pub fn start(self: &Arc<Self>) -> Result<()> {
        let client = if self.state.load().has_feeds {
            Some(webfast_core::fetch::client()?)
        } else {
            None
        };
        let ngfw = self.clone();
        tokio::spawn(async move {
            let mut ticks = tokio::time::interval(TICK);
            ticks.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
            // The first tick is now: the feeds are read at start.
            let mut geo_checked = Instant::now();
            loop {
                ticks.tick().await;
                let state = ngfw.state.load_full();
                state.bans.sweep(Instant::now());
                match state.lists.refresh_files() {
                    Ok(true) => tracing::info!("ngfw: address lists read again"),
                    Ok(false) => {}
                    Err(e) => tracing::warn!(error = format!("{e:#}"), "ngfw: address lists not read again"),
                }
                if let Some(geo) = &state.geo
                    && geo_checked.elapsed() >= state.geo_reload
                {
                    geo_checked = Instant::now();
                    match geo.reload_if_changed() {
                        Ok(true) => tracing::info!("ngfw: geo databases read again"),
                        Ok(false) => {}
                        Err(e) => tracing::warn!(error = format!("{e:#}"), "ngfw: geo databases not read again"),
                    }
                }
                if let Some(client) = &client
                    && state.has_feeds
                {
                    match state.lists.fetch_feeds(client).await {
                        Ok(0) => {}
                        Ok(n) => tracing::info!(feeds = n, "ngfw: feeds read"),
                        Err(e) => tracing::warn!(error = format!("{e:#}"), "ngfw: a feed was not read"),
                    }
                }
            }
        });
        Ok(())
    }

    /// Writes the event and counts a refusal for the ban list; the response to answer with.
    #[allow(clippy::too_many_arguments)]
    fn refuse(
        &self,
        state: &State,
        outcome: Outcome,
        status: StatusCode,
        parts: &http::request::Parts,
        ip: IpAddr,
        geo: (Option<[u8; 2]>, Option<u32>),
        evaluation: Option<&Evaluation>,
    ) -> Response<Body> {
        let outcome = match outcome {
            // A refusal counted in the window: the one that reaches `on_blocks` bans, or with
            // `then: challenge` marks the address for the challenge (this one is still refused).
            Outcome::Block => match state.bans.refused(ip, Instant::now()) {
                Some(ban::Then::Ban) => Outcome::Ban,
                Some(ban::Then::Challenge) | None => Outcome::Block,
            },
            Outcome::Ban => {
                state.bans.ban(ip, Instant::now());
                Outcome::Ban
            }
            other => other,
        };
        log::write(
            &state.log,
            &state.compiled,
            &Record {
                outcome,
                status: status.as_u16(),
                threshold: state.threshold,
                client_ip: ip,
                country: geo.0,
                asn: geo.1,
                parts,
                evaluation,
            },
        );
        state.refusal(status)
    }

    /// The browser challenge is due for the request, from `access` (`reason`) or the rules
    /// (`evaluation`): when the client passed it already, the fact is written (`challenge_passed`)
    /// and the request goes on; else the challenge is the answer, written as `challenge`.
    #[cfg(feature = "challenge")]
    #[allow(clippy::too_many_arguments, clippy::result_large_err)]
    fn challenge(
        &self,
        state: &State,
        conn: &webfast_core::handler::ConnInfo,
        reason: Option<&'static str>,
        parts: &http::request::Parts,
        ip: IpAddr,
        geo: (Option<[u8; 2]>, Option<u32>),
        evaluation: Option<&Evaluation>,
    ) -> Result<(), Response<Body>> {
        let module = webfast_challenge::instance();
        let (outcome, status, response) = if module.passed(conn, parts, ip, state.asking.level) {
            (Outcome::ChallengePassed(reason), 0, None)
        } else {
            let response = module.ask(conn, parts, ip, &state.asking);
            (Outcome::Challenge(reason), response.status().as_u16(), Some(response))
        };
        log::write(
            &state.log,
            &state.compiled,
            &Record {
                outcome,
                status,
                threshold: state.threshold,
                client_ip: ip,
                country: geo.0,
                asn: geo.1,
                parts,
                evaluation,
            },
        );
        match response {
            Some(response) => Err(response),
            None => Ok(()),
        }
    }

    /// Without the module nothing asks for a challenge (the file does not load with one): a
    /// refusal, should it come to this.
    #[cfg(not(feature = "challenge"))]
    #[allow(clippy::too_many_arguments, clippy::result_large_err)]
    fn challenge(
        &self,
        state: &State,
        _conn: &webfast_core::handler::ConnInfo,
        reason: Option<&'static str>,
        parts: &http::request::Parts,
        ip: IpAddr,
        geo: (Option<[u8; 2]>, Option<u32>),
        evaluation: Option<&Evaluation>,
    ) -> Result<(), Response<Body>> {
        Err(self.refuse(
            state,
            Outcome::Access(reason.unwrap_or("rule")),
            state.status,
            parts,
            ip,
            geo,
            evaluation,
        ))
    }

    /// A phase ended: the decision applied.
    #[allow(clippy::too_many_arguments)]
    fn settle(
        &self,
        state: &State,
        evaluation: &mut Evaluation,
        conn: &webfast_core::handler::ConnInfo,
        parts: &http::request::Parts,
        ip: IpAddr,
        geo: (Option<[u8; 2]>, Option<u32>),
    ) -> Settled {
        let outcome = match evaluation.decision(state.threshold) {
            Decision::Continue => return Settled::Go,
            Decision::Pass => return Settled::Stop,
            Decision::Block => Outcome::Block,
            Decision::Ban => Outcome::Ban,
            Decision::Challenge => {
                return match self.challenge(state, conn, None, parts, ip, geo, Some(evaluation)) {
                    Ok(()) => {
                        evaluation.challenge_passed();
                        Settled::Go
                    }
                    Err(response) => Settled::Refuse(response),
                };
            }
            Decision::LogOnly => {
                log::write(
                    &state.log,
                    &state.compiled,
                    &Record {
                        outcome: Outcome::LogOnly,
                        status: state.status.as_u16(),
                        threshold: state.threshold,
                        client_ip: ip,
                        country: geo.0,
                        asn: geo.1,
                        parts,
                        evaluation: Some(evaluation),
                    },
                );
                return Settled::Go;
            }
        };
        Settled::Refuse(self.refuse(state, outcome, state.status, parts, ip, geo, Some(evaluation)))
    }

    /// The request through the phases: `access` first, then the rules of each phase, the body
    /// read only when the head did not decide — `check_head` and `check_body` in one, for the
    /// tests.
    #[allow(clippy::result_large_err)]
    pub async fn check(&self, parts: &mut http::request::Parts, body: Body, client: Client<'_>) -> Checked {
        match self.check_head(parts, client) {
            Head::Pass => Ok(body),
            Head::Refuse(response) => Err(response),
            Head::Body(pending) => self.check_body(pending, parts, body, client).await,
        }
    }

    /// The head: `access` first, then the `connection` and `head` phases, synchronously. `Body`
    /// when the body's type is listed, there are rules for it and the head let it on: what the
    /// body phase needs is handed to `check_body` (`Head::Body(Pending)`).
    fn check_head(&self, parts: &mut http::request::Parts, client: Client<'_>) -> Head<Pending> {
        let state = self.state.load_full();
        let compiled = &state.compiled;
        // The headers of `header` actions are the module's to set.
        for name in &compiled.header_names {
            parts.headers.remove(name);
        }
        if !compiled.header_names.is_empty() {
            webfast_core::proxy::remove_lookalikes(&mut parts.headers, &compiled.header_names);
        }
        let hidden = self.hidden.load_full();
        if !hidden.is_empty() && parts.extensions.get::<webfast_core::eventlog::HiddenParams>().is_none() {
            parts
                .extensions
                .insert(webfast_core::eventlog::HiddenParams(Arc::from(hidden.as_slice())));
        }
        let ip = client.ip;
        let geo = (state.country(ip), state.asn(ip));
        if state.lists.allowed(ip) {
            state.set_geo_header(parts, geo);
            return Head::Pass;
        }
        let mut evaluation = Evaluation::new();
        let pre = evaluation.with_request(parts, |fixed| {
            if state
                .matcher
                .as_ref()
                .is_some_and(|m| !m.applies(fixed.host, fixed.match_path))
            {
                return Pre::Skip;
            }
            let now = Instant::now();
            if state.bans.banned(ip, now) {
                return Pre::Refuse("ban");
            }
            let challenged = state.bans.challenged(ip, now);
            if state.lists.denied(ip) {
                return Pre::Refuse("ip");
            }
            if state
                .countries
                .as_ref()
                .is_some_and(|c| c.refuses(geo.0, fixed.match_path))
            {
                return Pre::Refuse("country");
            }
            if state.asn.as_ref().is_some_and(|a| a.refuses(geo.1, fixed.match_path)) {
                return Pre::Refuse("asn");
            }
            if state.honeypots.iter().any(|p| p.matches_path(fixed.match_path)) {
                return Pre::Honeypot;
            }
            if challenged {
                return Pre::Challenge("ban");
            }
            if state
                .countries_challenge
                .as_ref()
                .is_some_and(|c| c.refuses(geo.0, fixed.match_path))
            {
                return Pre::Challenge("country");
            }
            if state
                .asn_challenge
                .as_ref()
                .is_some_and(|a| a.refuses(geo.1, fixed.match_path))
            {
                return Pre::Challenge("asn");
            }
            Pre::Go
        });
        match pre {
            Pre::Skip => return Head::Pass,
            Pre::Refuse(reason) => {
                return Head::Refuse(self.refuse(&state, Outcome::Access(reason), state.status, parts, ip, geo, None));
            }
            Pre::Honeypot => {
                state.bans.ban(ip, Instant::now());
                return Head::Refuse(self.refuse(
                    &state,
                    Outcome::Access("honeypot"),
                    state.status,
                    parts,
                    ip,
                    geo,
                    None,
                ));
            }
            // Passed: the rules run as for anyone else.
            Pre::Challenge(reason) => {
                if let Err(response) = self.challenge(&state, client.conn, Some(reason), parts, ip, geo, None) {
                    return Head::Refuse(response);
                }
            }
            Pre::Go => {}
        }
        let mut stopped = false;
        {
            let input = Input {
                parts,
                client_ip: ip,
                country: geo.0,
                asn: geo.1,
                sni: client.conn.sni.as_deref(),
                body: None,
                response: None,
                hidden: &hidden,
            };
            evaluation.run_phase(compiled, Phase::Connection, &input, state.log_matched);
            if !matches!(evaluation.decision(state.threshold), Decision::Pass) {
                evaluation.run_phase(compiled, Phase::Head, &input, state.log_matched);
            }
            match self.settle(&state, &mut evaluation, client.conn, parts, ip, geo) {
                Settled::Go => {}
                Settled::Stop => stopped = true,
                Settled::Refuse(response) => return Head::Refuse(response),
            }
        }
        // The body, when its type is listed, there are rules for it, and the head let it on.
        let kind = if !stopped && (compiled.has_phase(Phase::Body) || compiled.has_phase(Phase::Upload)) {
            body::kind_of(&parts.headers, &state.body_types)
        } else {
            None
        };
        match kind {
            Some(kind) => Head::Body(Pending {
                state,
                evaluation,
                geo,
                hidden,
                kind,
            }),
            None => {
                self.finish(&state, &evaluation, parts, ip, geo);
                Head::Pass
            }
        }
    }

    /// The `body` and `upload` phases, after `check_head` asked for the body with what it handed
    /// on; the body is given back with the same bytes.
    #[allow(clippy::result_large_err)]
    async fn check_body(
        &self,
        pending: Pending,
        parts: &mut http::request::Parts,
        body: Body,
        client: Client<'_>,
    ) -> Checked {
        let Pending {
            state,
            mut evaluation,
            geo,
            hidden,
            kind,
        } = pending;
        let compiled = &state.compiled;
        let ip = client.ip;
        let prefix = match body::read_prefix(body, state.max_inspect).await {
            Ok(prefix) => prefix,
            Err(error) => {
                tracing::debug!(%error, "ngfw: the request body could not be read");
                return Err(state.refusal(StatusCode::BAD_REQUEST));
            }
        };
        let body = prefix.body;
        let multipart = matches!(kind, body::Kind::Multipart { .. });
        let data = body::BodyData::parse(prefix.bytes, kind, prefix.complete, &state.limits).await;
        let input = Input {
            parts,
            client_ip: ip,
            country: geo.0,
            asn: geo.1,
            sni: client.conn.sni.as_deref(),
            body: Some(&data),
            response: None,
            hidden: &hidden,
        };
        evaluation.run_phase(compiled, Phase::Body, &input, state.log_matched);
        if multipart && !matches!(evaluation.decision(state.threshold), Decision::Pass) {
            evaluation.run_phase(compiled, Phase::Upload, &input, state.log_matched);
        }
        if let Settled::Refuse(response) = self.settle(&state, &mut evaluation, client.conn, parts, ip, geo) {
            return Err(response);
        }
        self.finish(&state, &evaluation, parts, ip, geo);
        Ok(body)
    }

    /// A request let through: the headers of the `header` actions that hit, the geo header, and
    /// the `scored` line when it scored and `log.passed` is on.
    fn finish(
        &self,
        state: &State,
        evaluation: &Evaluation,
        parts: &mut http::request::Parts,
        ip: IpAddr,
        geo: (Option<[u8; 2]>, Option<u32>),
    ) {
        let compiled = &state.compiled;
        for &rule in &evaluation.header_rules {
            for (name, value) in &compiled.rules[rule as usize].headers {
                parts.headers.insert(name.clone(), value.clone());
            }
        }
        state.set_geo_header(parts, geo);
        if state.log_passed && (evaluation.score > 0 || evaluation.shadow > 0) && !evaluation.hits.is_empty() {
            log::write(
                &state.log,
                compiled,
                &Record {
                    outcome: Outcome::Scored,
                    status: 0,
                    threshold: state.threshold,
                    client_ip: ip,
                    country: geo.0,
                    asn: geo.1,
                    parts,
                    evaluation: Some(evaluation),
                },
            );
        }
    }

    /// The current state (response.rs).
    pub(crate) fn state(&self) -> Arc<State> {
        self.state.load_full()
    }
}

/// The file's text as its configuration; an empty file (or comments only) is the defaults.
fn parse(text: &str) -> Result<FileConfig> {
    Ok(webfast_core::yaml::from_str(text)?)
}

impl Check for Ngfw {
    type Pending = Pending;

    fn head(&self, req: &mut http::request::Parts, client: Client<'_>) -> Head<Pending> {
        self.check_head(req, client)
    }

    fn body<'a>(
        &'a self,
        pending: Pending,
        req: &'a mut http::request::Parts,
        body: Body,
        client: Client<'a>,
    ) -> impl Future<Output = Checked> + Send + 'a {
        self.check_body(pending, req, body, client)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use http_body::Body as _;
    use http_body_util::BodyExt;
    use webfast_core::handler::ConnInfo;

    pub(crate) fn conn() -> ConnInfo {
        ConnInfo {
            remote: "203.0.113.7:4000".parse().unwrap(),
            tls: false,
            trusted: false,
            sni: None,
        }
    }

    pub(crate) async fn run(
        ngfw: &Ngfw,
        method: &str,
        uri: &str,
        headers: &[(&str, &str)],
        body: &'static [u8],
    ) -> (http::request::Parts, Checked) {
        let mut builder = http::Request::builder()
            .method(method)
            .uri(uri)
            .header("host", "www.example.com");
        for (name, value) in headers {
            builder = builder.header(*name, *value);
        }
        let (mut parts, ()) = builder.body(()).unwrap().into_parts();
        let conn = conn();
        let client = Client {
            ip: conn.remote.ip(),
            conn: &conn,
            at: webfast_core::extensions::At::Routes,
        };
        let body = webfast_core::body::full(bytes::Bytes::from_static(body));
        let checked = Ngfw::check(ngfw, &mut parts, body, client).await;
        (parts, checked)
    }

    const SITE: &str = r#"
mode: block
threshold: 5
log: { output: discard }
response: { status: 403 }
rules:
  builtin: none
  include: [site.yaml]
access:
  ip:
    allow: [10.0.0.0/8]
    deny: [198.51.100.0/24]
  ban:
    on_blocks: 2
    window: 10m
    for: 1h
    honeypots: ['/wp-login.php']
match:
  except_paths: ['/internal/*']
"#;

    const SITE_RULES: &str = r#"
rules:
  - id: scanner
    phase: head
    targets: [ua]
    transform: [lowercase]
    operator: { contains_any: [nikto] }
    action: block
  - id: sqli
    phase: head
    severity: critical
    targets: [args, cookies, body]
    transform: [url_decode, lowercase]
    operator: { contains_any: ['union select'] }
  - id: mark
    phase: head
    targets: [args]
    operator: { equals_any: [marked] }
    action: header
    header: { X-Threat: marked }
  - id: ext
    phase: upload
    targets: [upload.ext]
    transform: [lowercase]
    operator: { equals_any: [php] }
    action: block
  - id: quiet
    phase: head
    severity: notice
    targets: [args]
    operator: { equals_any: [quiet] }
    mode: log_only
"#;

    fn site() -> (tempfile::TempDir, Ngfw) {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(dir.path().join("site.yaml"), SITE_RULES).unwrap();
        let ngfw = Ngfw::load_str(SITE, dir.path()).unwrap();
        (dir, ngfw)
    }

    #[tokio::test]
    async fn requests_are_refused_let_through_marked_and_banned() {
        let (_dir, ngfw) = site();
        assert_eq!(ngfw.counts(), (5, 1));
        let (_, clean) = run(&ngfw, "GET", "/en/?q=hello", &[("user-agent", "Mozilla")], b"").await;
        assert!(clean.is_ok());

        let (parts, marked) = run(
            &ngfw,
            "GET",
            "/?x=marked",
            &[("user-agent", "Mozilla"), ("x-threat", "forged")],
            b"",
        )
        .await;
        assert!(marked.is_ok());
        assert_eq!(
            parts.headers["x-threat"], "marked",
            "the client's own value is taken off first"
        );
        let (parts, plain) = run(
            &ngfw,
            "GET",
            "/",
            &[("x-threat", "forged"), ("x_threat", "forged")],
            b"",
        )
        .await;
        assert!(plain.is_ok());
        assert!(parts.headers.get("x-threat").is_none() && parts.headers.get("x_threat").is_none());

        let (_, skipped) = run(&ngfw, "GET", "/internal/x", &[("user-agent", "Nikto")], b"").await;
        assert!(skipped.is_ok(), "match.except_paths");

        // The first refusal.
        let (_, refused) = run(
            &ngfw,
            "GET",
            "/s?q=1%20UNION%20SELECT%202",
            &[("user-agent", "Mozilla")],
            b"",
        )
        .await;
        let response = refused.expect_err("critical: at the threshold");
        assert_eq!(response.status(), StatusCode::FORBIDDEN);
        assert!(response.extensions().get::<ErrorPage>().is_some());
        assert_eq!(response.body().size_hint().exact(), Some(0));

        // The second: `on_blocks: 2` bans the address, and the next request is refused before
        // any rule runs.
        let (_, quiet) = run(&ngfw, "GET", "/?x=quiet", &[("user-agent", "Nikto")], b"").await;
        assert!(quiet.is_err(), "a log_only rule does not shield the others");
        let (_, banned) = run(&ngfw, "GET", "/clean", &[("user-agent", "Mozilla")], b"").await;
        let response = banned.expect_err("banned after on_blocks refusals");
        assert_eq!(response.status(), StatusCode::FORBIDDEN);
    }

    #[tokio::test]
    async fn honeypots_ban_at_once_and_allowed_addresses_pass_everything() {
        let (_dir, ngfw) = site();
        let (_, pot) = run(&ngfw, "GET", "/wp-login.php", &[("user-agent", "Mozilla")], b"").await;
        assert!(pot.is_err());
        let (_, after) = run(&ngfw, "GET", "/", &[("user-agent", "Mozilla")], b"").await;
        assert!(after.is_err(), "banned");

        let (_dir, ngfw) = site();
        let conn = ConnInfo {
            remote: "10.1.2.3:4000".parse().unwrap(),
            tls: false,
            trusted: false,
            sni: None,
        };
        let client = Client {
            ip: conn.remote.ip(),
            conn: &conn,
            at: webfast_core::extensions::At::Routes,
        };
        let (mut parts, ()) = http::Request::get("/")
            .header("user-agent", "Nikto")
            .body(())
            .unwrap()
            .into_parts();
        assert!(
            Ngfw::check(&ngfw, &mut parts, webfast_core::body::empty(), client)
                .await
                .is_ok()
        );
        let conn = ConnInfo {
            remote: "198.51.100.9:4000".parse().unwrap(),
            ..conn
        };
        let client = Client {
            ip: conn.remote.ip(),
            conn: &conn,
            at: webfast_core::extensions::At::Routes,
        };
        assert!(
            Ngfw::check(&ngfw, &mut parts, webfast_core::body::empty(), client)
                .await
                .is_err(),
            "denied"
        );
    }

    #[tokio::test]
    async fn bodies_are_inspected_and_passed_on_whole() {
        let (_dir, ngfw) = site();
        let headers = [
            ("user-agent", "Mozilla"),
            ("content-type", "application/x-www-form-urlencoded"),
        ];
        let (_, refused) = run(&ngfw, "POST", "/login", &headers, b"user=a&pass=x+UNION+SELECT+1").await;
        assert!(refused.is_err(), "a head rule on args runs on the form body");
        let (_, passed) = run(&ngfw, "POST", "/login", &headers, b"user=a&pass=secret").await;
        let body = passed.unwrap().collect().await.unwrap().to_bytes();
        assert_eq!(&body[..], b"user=a&pass=secret", "the same bytes go on");

        let (_, image) = run(&ngfw, "POST", "/up", &[("content-type", "image/png")], b"UNION SELECT").await;
        assert!(image.is_ok(), "a type not listed is not read");

        let upload = b"--B\r\nContent-Disposition: form-data; name=\"f\"; filename=\"shell.PHP\"\r\nContent-Type: image/jpeg\r\n\r\nxx\r\n--B--\r\n";
        let (_, refused) = run(
            &ngfw,
            "POST",
            "/up",
            &[("content-type", "multipart/form-data; boundary=B")],
            upload,
        )
        .await;
        assert!(refused.is_err(), "upload phase");
    }

    #[test]
    fn the_file_is_validated_and_summarised() {
        let dir = tempfile::tempdir().unwrap();
        assert!(Ngfw::load_str("response: {status: 418}\n", dir.path()).is_err());
        assert!(
            Ngfw::load_str("access: {countries: {deny: [KP]}}\n", dir.path()).is_err(),
            "no database"
        );
        assert!(Ngfw::load_str("bogus: 1\n", dir.path()).is_err());
        let ngfw = Ngfw::load_str("# comments only\n", dir.path()).unwrap();
        let (rules, sets) = ngfw.counts();
        assert!(
            rules > 0 && sets == rules::SETS.len(),
            "the defaults: every built-in set"
        );
        let summary = ngfw.summary();
        assert!(summary[0].contains("mode block, threshold 5"), "{summary:?}");
        assert!(summary.iter().any(|l| l.starts_with("warning: the scanners set")));
        let ngfw = Ngfw::load_str(
            "mode: log_only\nrules:\n  builtin: [sqli]\n  disable: [wf-942-*]\n",
            dir.path(),
        )
        .unwrap();
        assert_eq!(ngfw.counts().0, 0);
        assert!(ngfw.summary().iter().any(|l| l.starts_with("disabled: wf-942-")));
    }

    #[tokio::test]
    async fn a_reload_keeps_the_old_rules_when_the_file_does_not_load() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("ngfw.yaml");
        std::fs::write(&path, "rules: {builtin: [scanners]}\nlog: {output: discard}\n").unwrap();
        let ngfw = Ngfw::load(&path).unwrap();
        let before = ngfw.counts();
        std::fs::write(&path, "rules: {builtin: [nothing]}\n").unwrap();
        assert!(ngfw.reload().is_err());
        assert_eq!(ngfw.counts(), before);
        std::fs::write(&path, "rules: {builtin: none}\n").unwrap();
        ngfw.reload().unwrap();
        assert_eq!(ngfw.counts().0, 0);
    }
}
