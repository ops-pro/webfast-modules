//! The `response` phase: a proxied response's status, headers and the start of its body, looked
//! at before the cache sees it or the client gets it (`ProxyObserver::inspect`, called by the
//! proxy before `observe`). Only a response the leakage rules cover is read: status 200 or 5xx,
//! a text, JSON or XHTML type; of it at most `body.max_inspect` bytes, given back as the same
//! frames followed by the rest. A hit replaces the response by `response.leak_status`, through the
//! site's `handle_errors`, and is written to the log as `leak`.
//!
//! `NgfwResponses` is zero-sized (one constant for every proxy, like the cache's observer) and
//! finds the module among the server's composed hooks by its type (`Ctx::hook`).

use super::body;
use super::engine::{Decision, Evaluation, Input, ResponseData};
use super::log::{Outcome, Record};
use super::rule::Phase;
use http::{Response, StatusCode};
use webfast_core::body::Body;
use webfast_core::handler::{BoxFuture, Ctx};
use webfast_core::module::Inspect;

pub struct NgfwResponses;

/// Whether the leakage rules look at a response with this status and these headers.
fn covered(parts: &http::response::Parts) -> bool {
    let status = parts.status.as_u16();
    if status != 200 && !(500..600).contains(&status) {
        return false;
    }
    body::media_type(&parts.headers).is_some_and(|media| {
        media.starts_with("text/") || media == "application/json" || media == "application/xhtml+xml"
    })
}

impl super::Ngfw {
    /// The response phase on one proxied response (see the module doc).
    #[allow(clippy::result_large_err)]
    pub(crate) async fn inspect_response(
        &self,
        ctx: &mut Ctx,
        parts: &mut http::response::Parts,
        body: Body,
    ) -> Result<Body, Response<Body>> {
        let state = self.state();
        if !state.compiled.has_phase(Phase::Response) || !covered(parts) {
            return Ok(body);
        }
        let ip = ctx.client_ip;
        let mut evaluation = Evaluation::new();
        let applies = evaluation.with_request(&ctx.req, |fixed| {
            !state.lists.allowed(ip)
                && state
                    .matcher
                    .as_ref()
                    .is_none_or(|m| m.applies(fixed.host, fixed.match_path))
        });
        if !applies {
            return Ok(body);
        }
        let prefix = match body::read_prefix(body, state.max_inspect).await {
            Ok(prefix) => prefix,
            Err(error) => {
                tracing::debug!(%error, "ngfw: the upstream response body could not be read");
                return Err(state.refusal(StatusCode::BAD_GATEWAY));
            }
        };
        let text = String::from_utf8_lossy(&prefix.bytes);
        let geo = (state.country(ip), state.asn(ip));
        let hidden = self.hidden.load_full();
        let input = Input {
            parts: &ctx.req,
            client_ip: ip,
            country: geo.0,
            asn: geo.1,
            sni: ctx.conn.sni.as_deref(),
            body: None,
            response: Some(ResponseData {
                status: parts.status.as_u16(),
                headers: &parts.headers,
                body: &text,
            }),
            hidden: &hidden,
        };
        evaluation.run_phase(&state.compiled, Phase::Response, &input, state.log_matched);
        let outcome = match evaluation.decision(state.threshold) {
            // A response cannot be challenged: in this phase `mode: challenge` replaces as `block` does.
            Decision::Block | Decision::Ban | Decision::Challenge => Outcome::Leak,
            Decision::LogOnly => Outcome::LogOnly,
            Decision::Continue | Decision::Pass => return Ok(prefix.body),
        };
        super::log::write(
            &state.log,
            &state.compiled,
            &Record {
                outcome,
                status: state.leak_status.as_u16(),
                threshold: state.threshold,
                client_ip: ip,
                country: geo.0,
                asn: geo.1,
                parts: &ctx.req,
                evaluation: Some(&evaluation),
            },
        );
        if outcome == Outcome::LogOnly {
            return Ok(prefix.body);
        }
        // Nothing of the upstream's answer goes out: not its headers either.
        parts.headers.clear();
        Err(state.refusal(state.leak_status))
    }
}

impl Inspect for NgfwResponses {
    /// A module with response rules, and a response they look at.
    fn covers(&self, ctx: &Ctx, parts: &http::response::Parts) -> bool {
        ctx.hook::<super::Ngfw>()
            .is_some_and(|ngfw| ngfw.state().compiled.has_phase(Phase::Response) && covered(parts))
    }

    fn inspect<'a>(
        &'a self,
        ctx: &'a mut Ctx,
        parts: &'a mut http::response::Parts,
        body: Body,
    ) -> BoxFuture<'a, Result<Body, Response<Body>>> {
        match ctx.hook::<super::Ngfw>() {
            Some(ngfw) => Box::pin(ngfw.inspect_response(ctx, parts, body)),
            None => Box::pin(async { Ok(body) }),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use http_body_util::BodyExt;

    const FILE: &str = r#"
log: { output: discard }
response: { leak_status: 500 }
rules:
  builtin: none
  include: [leak.yaml]
"#;

    const RULES: &str = r#"
rules:
  - id: leak
    phase: response
    targets: [response.body]
    operator: { contains_any: ['Stack trace:'] }
    action: block
  - id: server
    phase: response
    targets: [response.headers.server]
    operator: { regex: 'Apache/\d+\.\d+\.\d+' }
    prefilter: ['Apache/']
    action: log
"#;

    fn ctx() -> Ctx {
        let conn = std::sync::Arc::new(super::super::tests::conn());
        let (parts, body) = http::Request::get("/page")
            .header("host", "www.example.com")
            .body(webfast_core::body::empty())
            .unwrap()
            .into_parts();
        let ip = conn.remote.ip();
        Ctx::new(conn, parts, body, ip)
    }

    fn response(status: u16, content_type: &str) -> http::response::Parts {
        http::Response::builder()
            .status(status)
            .header("content-type", content_type)
            .header("server", "Apache/2.4.57")
            .body(())
            .unwrap()
            .into_parts()
            .0
    }

    #[tokio::test]
    async fn a_leaking_response_is_replaced_and_a_clean_one_goes_on_whole() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(dir.path().join("leak.yaml"), RULES).unwrap();
        let ngfw = super::super::Ngfw::load_str(FILE, dir.path()).unwrap();
        let mut ctx = ctx();

        let mut parts = response(200, "text/html; charset=utf-8");
        let leaking = webfast_core::body::full("<html>Fatal: Stack trace: #0 /var/www/x.php");
        let replaced = ngfw
            .inspect_response(&mut ctx, &mut parts, leaking)
            .await
            .expect_err("replaced");
        assert_eq!(replaced.status(), StatusCode::INTERNAL_SERVER_ERROR);
        assert!(
            replaced
                .extensions()
                .get::<webfast_core::extensions::ErrorPage>()
                .is_some()
        );
        assert!(parts.headers.is_empty(), "the upstream's headers do not go out");

        let mut parts = response(200, "text/html");
        let clean = webfast_core::body::full("<html>hello</html>");
        let body = ngfw.inspect_response(&mut ctx, &mut parts, clean).await.unwrap();
        assert_eq!(&body.collect().await.unwrap().to_bytes()[..], b"<html>hello</html>");

        let mut parts = response(200, "image/png");
        let image = webfast_core::body::full("Stack trace: in an image");
        assert!(
            ngfw.inspect_response(&mut ctx, &mut parts, image).await.is_ok(),
            "not covered"
        );
        let mut parts = response(304, "text/html");
        assert!(
            ngfw.inspect_response(&mut ctx, &mut parts, webfast_core::body::empty())
                .await
                .is_ok()
        );
        let mut parts = response(502, "text/plain");
        let error = webfast_core::body::full("Stack trace: upstream");
        assert!(
            ngfw.inspect_response(&mut ctx, &mut parts, error).await.is_err(),
            "5xx is covered"
        );
    }
}
