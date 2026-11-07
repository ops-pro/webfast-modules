//! The `challenge` directive: parsed from the Caddyfile (`parse`, registered by the module as a
//! `webfast_core::module::Directive`), run in the chain where it stands (`Handler::Extension`, a
//! `module::RouteHandler`), like `rate_limit`.
//!
//! ```caddyfile
//! challenge [<matcher>] {
//!     level js                 # cookie | js | pow | captcha
//!     difficulty 18            # pow: leading zero bits (12..=28)
//!     valid 7d                 # how long a passed client is not asked again
//!     bind ip                  # ip | none
//!     defer { events 100  window 10m  key {client_ip}  count pages }
//!     except { path /api/* }   # a matcher block: passed on without a look
//!     captcha turnstile { site_key …  secret {env.NAME} }
//!     page /srv/challenge.html
//!     title "Just a moment..."
//! }
//! ```
//!
//! A request `except` matches goes on; one with a good cookie of the level goes on; with `defer`,
//! one that is not counted or whose key is under the rate goes on; the rest get the challenge
//! (lib.rs `ask`). While answers are prepared (webfast_core::memo `Preparing`), a request
//! the directive would look at is marked `Unkept` so that no ready answer stands where the
//! challenge decides — with `defer`, only one that `count` could take, so assets stay ready.

use super::captcha::{Captcha, Provider};
use super::defer::{Count, Defer, DeferSpec};
use super::page::Page;
use super::{Asking, Bind, Level, pow};
use anyhow::{Result, bail};
use http::Response;
use std::sync::Arc;
use std::time::Duration;
use webfast_core::body::Body;
use webfast_core::caddyfile::{Line, Token};
use webfast_core::config::{
    Cx, Entry, Scope, SiteCx, add_matcher, at_err, entry, matcher_token, parse_duration, token_err,
};
use webfast_core::handler::{Ctx, Handler};
use webfast_core::matcher::MatcherSet;
use webfast_core::module::RouteHandler;
use webfast_core::placeholder::Template;

/// One `challenge` directive.
pub struct ChallengeDirective {
    asking: Asking,
    except: Option<MatcherSet>,
    defer: Option<Defer>,
}

impl std::fmt::Debug for ChallengeDirective {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ChallengeDirective")
            .field("asking", &self.asking)
            .field("except", &self.except)
            .field("defer", &self.defer.as_ref().map(Defer::describe))
            .finish()
    }
}

impl ChallengeDirective {
    pub fn asking(&self) -> &Asking {
        &self.asking
    }
}

impl RouteHandler for ChallengeDirective {
    fn directive(&self) -> &'static str {
        "challenge"
    }

    /// `None`: the chain goes on; `Some`: the challenge is the answer.
    fn run(&self, ctx: &mut Ctx) -> Option<Response<Body>> {
        if let Some(except) = &self.except
            && except.matches(ctx)
        {
            return None;
        }
        if ctx.req.extensions.get::<webfast_core::memo::Preparing>().is_some() {
            let decides = match &self.defer {
                None => true,
                Some(defer) => defer.may_count_path(ctx.req.uri.path()),
            };
            if decides {
                ctx.req.extensions.insert(webfast_core::memo::Unkept);
            }
            return None;
        }
        let module = super::instance();
        if module.passed(&ctx.conn, &ctx.req, ctx.client_ip, self.asking.level) {
            return None;
        }
        if let Some(defer) = &self.defer
            && (!defer.counts(ctx) || !defer.over(ctx))
        {
            return None;
        }
        Some(module.ask(&ctx.conn, &ctx.req, ctx.client_ip, &self.asking))
    }

    /// Whether ready answers stay right with this directive in front of them: `except` decides
    /// by the path, so the paths marked `Unkept` are the right ones (webfast_core::memo).
    fn decided_by_path(&self) -> bool {
        self.except.as_ref().is_none_or(MatcherSet::depends_on_path_only)
    }

    /// `level js, valid 7d, bind ip, defer 100 in 600s, pages`, for `validate`.
    fn describe(&self) -> String {
        let mut text = format!(
            "level {}, valid {:?}, bind {}",
            self.asking.level.name(),
            self.asking.valid,
            self.asking.bind.name()
        );
        if self.asking.level == Level::Pow {
            text.push_str(&format!(", difficulty {}", self.asking.difficulty));
        }
        if let Some(captcha) = &self.asking.captcha {
            text.push_str(&format!(", captcha {}", captcha.provider.name()));
        }
        if let Some(defer) = &self.defer {
            text.push_str(", ");
            text.push_str(&defer.describe());
        }
        if self.except.is_some() {
            text.push_str(", with except");
        }
        if self.asking.page.is_some() {
            text.push_str(", own page");
        }
        text
    }
}

/// `challenge [<matcher>] [{ … }]` (a `webfast_core::module::DirectiveParser`).
pub fn parse(line: &Line, scope: &Scope, cx: &mut Cx, site: &mut SiteCx) -> Result<Vec<Entry>> {
    let (matcher, start) = matcher_token(line, scope)?;
    if line.tokens.len() != start {
        bail!(at_err(&line.at, "challenge: `challenge [<matcher>] [{ … }]`"));
    }
    let mut asking = Asking::default();
    let mut except = None;
    let mut defer = None;
    let mut captcha: Option<(Provider, Option<String>, Option<String>)> = None;
    for sub in line.block.as_deref().unwrap_or(&[]) {
        let args = &sub.tokens[1..];
        let one = || -> Result<&Token> {
            match args {
                [value] if sub.block.is_none() => Ok(value),
                _ => Err(at_err(&sub.at, format!("challenge: `{} <value>`", sub.name()))),
            }
        };
        match sub.name() {
            "level" => {
                let value = one()?;
                asking.level = Level::parse(&value.text)
                    .ok_or_else(|| token_err(value, "challenge: level is cookie, js, pow or captcha"))?;
            }
            "difficulty" => {
                let value = one()?;
                asking.difficulty = value
                    .text
                    .parse::<u8>()
                    .ok()
                    .filter(|d| (pow::MIN_DIFFICULTY..=pow::MAX_DIFFICULTY).contains(d))
                    .ok_or_else(|| {
                        token_err(
                            value,
                            format!(
                                "challenge: difficulty is {}–{} leading zero bits",
                                pow::MIN_DIFFICULTY,
                                pow::MAX_DIFFICULTY
                            ),
                        )
                    })?;
            }
            "valid" => {
                let value = one()?;
                let valid = parse_duration(&value.text).map_err(|e| token_err(value, e))?;
                if valid < Duration::from_secs(60) || valid.as_secs() > u64::from(u32::MAX) {
                    bail!(token_err(value, "challenge: valid is at least 1m"));
                }
                asking.valid = valid;
            }
            "bind" => {
                let value = one()?;
                asking.bind = match value.text.as_str() {
                    "ip" => Bind::Ip,
                    "none" => Bind::None,
                    _ => bail!(token_err(value, "challenge: bind is ip or none")),
                };
            }
            "title" => asking.title = Arc::from(one()?.text.as_str()),
            "page" => {
                let value = one()?;
                let page = Page::from_file(std::path::Path::new(&value.text))
                    .map_err(|e| token_err(value, format!("challenge: page {}: {e}", value.text)))?;
                asking.page = Some(Arc::new(page));
            }
            "except" => {
                if !args.is_empty() {
                    bail!(at_err(&sub.at, "challenge: `except { <matchers> }`"));
                }
                let mut set: MatcherSet = except.take().unwrap_or_default();
                for m in sub.block.as_deref().unwrap_or(&[]) {
                    add_matcher(
                        &mut set,
                        m.name(),
                        &m.tokens[1..],
                        m.block.as_deref(),
                        &m.at,
                        "except",
                        cx,
                        site,
                    )?;
                }
                except = Some(set);
            }
            "defer" => {
                if !args.is_empty() {
                    bail!(at_err(&sub.at, "challenge: `defer { events … window … }`"));
                }
                defer = Some(parse_defer(sub, &line.at)?);
            }
            "captcha" => {
                let [provider] = args else {
                    bail!(at_err(
                        &sub.at,
                        "challenge: `captcha <provider> { site_key … secret … }`"
                    ));
                };
                let kind = Provider::parse(&provider.text)
                    .ok_or_else(|| token_err(provider, "challenge: captcha is turnstile, hcaptcha or recaptcha"))?;
                let (mut site_key, mut secret) = (None, None);
                for field in sub.block.as_deref().unwrap_or(&[]) {
                    let value = match &field.tokens[1..] {
                        [value] if field.block.is_none() => value,
                        _ => bail!(at_err(&field.at, format!("challenge: `{} <value>`", field.name()))),
                    };
                    match field.name() {
                        "site_key" => site_key = Some(value.text.clone()),
                        "secret" => secret = Some(resolve_env(value)?),
                        other => bail!(at_err(
                            &field.at,
                            format!("challenge: unsupported captcha option {other:?}")
                        )),
                    }
                }
                captcha = Some((kind, site_key, secret));
            }
            other => bail!(at_err(&sub.at, format!("challenge: unsupported option {other:?}"))),
        }
    }
    match captcha {
        Some((provider, Some(site_key), Some(secret))) if !site_key.is_empty() && !secret.is_empty() => {
            asking.captcha = Some(Captcha::new(provider, site_key, secret).register());
        }
        Some(_) => bail!(at_err(&line.at, "challenge: captcha needs both site_key and secret")),
        None if asking.level == Level::Captcha => bail!(at_err(
            &line.at,
            "challenge: level captcha needs a `captcha <provider> { site_key … secret … }` block"
        )),
        None => {}
    }
    let directive = ChallengeDirective { asking, except, defer };
    Ok(vec![entry(
        "challenge",
        matcher,
        Handler::Extension(Arc::new(directive)),
    )])
}

/// `defer { events <n> window <duration> key <placeholder> count pages|all }`.
fn parse_defer(block: &Line, at: &webfast_core::caddyfile::Location) -> Result<Defer> {
    let mut spec = DeferSpec {
        events: 0,
        window: Duration::ZERO,
        key: Template::parse("{client_ip}").map_err(|e| at_err(&block.at, e))?,
        count: Count::Pages,
        at: at.to_string(),
    };
    for field in block.block.as_deref().unwrap_or(&[]) {
        let value = match &field.tokens[1..] {
            [value] if field.block.is_none() => value,
            _ => bail!(at_err(&field.at, format!("challenge: `{} <value>`", field.name()))),
        };
        match field.name() {
            "events" => {
                spec.events = value
                    .text
                    .parse()
                    .ok()
                    .filter(|n| *n > 0)
                    .ok_or_else(|| token_err(value, "challenge: defer events is a positive number"))?;
            }
            "window" => spec.window = parse_duration(&value.text).map_err(|e| token_err(value, e))?,
            "key" => spec.key = Template::parse(&value.text).map_err(|e| token_err(value, e))?,
            "count" => {
                spec.count = match value.text.as_str() {
                    "pages" => Count::Pages,
                    "all" => Count::All,
                    _ => bail!(token_err(value, "challenge: defer count is pages or all")),
                };
            }
            other => bail!(at_err(
                &field.at,
                format!("challenge: unsupported defer option {other:?}")
            )),
        }
    }
    if spec.events == 0 || spec.window.is_zero() {
        bail!(at_err(&block.at, "challenge: defer needs both events and window"));
    }
    Ok(Defer::new(spec))
}

/// A value that may be `{env.NAME}`: the variable's value then (the Caddyfile's own `{$NAME}` is
/// expanded before this).
fn resolve_env(token: &Token) -> Result<String> {
    if let Some(name) = token.text.strip_prefix("{env.").and_then(|rest| rest.strip_suffix('}')) {
        return std::env::var(name)
            .map_err(|_| token_err(token, format!("challenge: {name} is not set in the environment")));
    }
    Ok(token.text.clone())
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The directive compiled in a site of its own (the module registered, as the binary's
    /// composition does: once per process, a second installation is ignored).
    fn directive(text: &str) -> Result<Arc<dyn RouteHandler>> {
        static MODULES: &[&dyn webfast_core::module::Module] = &[&crate::MODULE];
        let composition = webfast_core::module::Composition::<(), ()> {
            modules: MODULES,
            hooks: |_| ((), ()),
        };
        webfast_core::module::install(composition).expect("the challenge directive is the core's to add");
        let caddyfile = format!(":0 {{\n{text}\n}}\n");
        let file = webfast_core::caddyfile::parse_str(&caddyfile, std::path::Path::new("Caddyfile"))?;
        let config = webfast_core::load_parsed(&file, 1 << 20)?;
        match &config.servers[0].sites[0].routes[0].handler {
            Handler::Extension(handler) => Ok(handler.clone()),
            _ => panic!("not a challenge"),
        }
    }

    fn challenge(handler: &Arc<dyn RouteHandler>) -> &ChallengeDirective {
        handler.downcast_ref::<ChallengeDirective>().expect("a challenge")
    }

    #[test]
    fn every_option_parses() {
        let c = directive("challenge").unwrap();
        let c = challenge(&c);
        assert_eq!(c.asking.level, Level::Js);
        assert_eq!(c.asking.difficulty, 18);
        assert_eq!(c.asking.valid, Duration::from_secs(7 * 86_400));
        assert_eq!(c.asking.bind, Bind::Ip);
        assert_eq!(&*c.asking.title, "Just a moment...");
        assert!(c.except.is_none() && c.defer.is_none() && c.asking.captcha.is_none());
        assert!(c.decided_by_path());

        unsafe { std::env::set_var("WEBFAST_CHALLENGE_TEST_SECRET", "s3cret") };
        let c = directive(
            "challenge /shop/* {\n level pow\n difficulty 20\n valid 1d\n bind none\n title \"One moment\"\n \
             defer {\n events 100\n window 10m\n key {remote_host}\n count all\n }\n \
             except {\n path /api/* /.well-known/*\n }\n \
             captcha hcaptcha {\n site_key 10000000-ffff\n secret {env.WEBFAST_CHALLENGE_TEST_SECRET}\n }\n}",
        )
        .unwrap();
        let c = challenge(&c);
        assert_eq!(c.asking.level, Level::Pow);
        assert_eq!(c.asking.difficulty, 20);
        assert_eq!(c.asking.valid, Duration::from_secs(86_400));
        assert_eq!(c.asking.bind, Bind::None);
        assert_eq!(&*c.asking.title, "One moment");
        assert!(c.except.is_some());
        assert!(
            c.defer
                .as_ref()
                .unwrap()
                .describe()
                .starts_with("defer 100 in 600s, all")
        );
        let captcha = c.asking.captcha.as_ref().unwrap();
        assert_eq!(captcha.provider, Provider::Hcaptcha);
        assert_eq!(captcha.site_key, "10000000-ffff");
        assert!(c.decided_by_path());
        let described = c.describe();
        assert!(
            described.contains("level pow") && described.contains("captcha hcaptcha"),
            "{described}"
        );

        let c = directive("challenge {\n except {\n method POST\n }\n}").unwrap();
        assert!(!c.decided_by_path(), "an except by method: no ready answers");
        assert_eq!(c.directive(), "challenge");
    }

    #[test]
    fn the_errors_name_the_option() {
        let err = |text: &str| directive(text).err().map(|e| e.to_string()).unwrap_or_default();
        assert!(err("challenge {\n level fast\n}").contains("level is cookie, js, pow or captcha"));
        assert!(err("challenge {\n difficulty 40\n}").contains("difficulty is 12–28"));
        assert!(err("challenge {\n difficulty 11\n}").contains("difficulty is 12–28"));
        assert!(err("challenge {\n level captcha\n}").contains("level captcha needs a `captcha"));
        assert!(err("challenge {\n captcha turnstile {\n site_key k\n }\n}").contains("both site_key and secret"));
        assert!(err("challenge {\n captcha solvemedia {\n }\n}").contains("turnstile, hcaptcha or recaptcha"));
        assert!(err("challenge {\n bind subnet\n}").contains("bind is ip or none"));
        assert!(err("challenge {\n valid 5s\n}").contains("at least 1m"));
        assert!(err("challenge {\n defer {\n events 10\n }\n}").contains("both events and window"));
        assert!(err("challenge {\n defer {\n events 10\n window 1m\n count some\n }\n}").contains("pages or all"));
        assert!(err("challenge {\n colour red\n}").contains("unsupported option \"colour\""));
        assert!(err("challenge one two").contains("`challenge [<matcher>] [{ … }]`"));
        assert!(err("challenge {\n page /nonexistent/challenge.html\n}").contains("page /nonexistent/challenge.html"));
        assert!(
            err("challenge {\n captcha turnstile {\n site_key k\n secret {env.WEBFAST_CHALLENGE_UNSET_VAR}\n }\n}")
                .contains("is not set in the environment")
        );
    }
}
