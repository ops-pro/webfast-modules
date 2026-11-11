//! The `response` phase: a proxied response's status, headers and the start of its body, looked
//! at before the cache sees it or the client gets it (`module::Inspect`, called by the core's
//! proxy before its cache observes the response). Only a response the leakage rules cover is
//! looked at: status 200 or 5xx, a text, JSON or XHTML type; of its body at most
//! `body.max_inspect` bytes.
//!
//! - A 5xx (and a 200 with `response.stream: false`) is held: its body is read up to `max_inspect`
//!   bytes, scanned, and given back as the same frames followed by the rest — or, on a hit, the
//!   response is replaced by `response.leak_status`, through the site's `handle_errors`. Error
//!   pages are short, and are where leaks are.
//! - A 200 (`response.stream: true`, the default) goes out at once. Its status and header rules
//!   run first, before the body (a hit there replaces the response as above); the body is wrapped
//!   in `Scanning`, which scans each data frame as it passes: the body rules' automaton over the
//!   frame, and over a window across each frame boundary — the last `carry` bytes before it (at
//!   least the longest literal less one; `WINDOW` bytes when a body rule is a regex) and as many
//!   after it — so a literal split between frames is found, and a regex sees up to `WINDOW` bytes
//!   either side of the boundary as well as the whole frame. On a hit the frame is not forwarded:
//!   the body ends with an error, so the server gives up on the response (HTTP/1.1 closes the
//!   connection, HTTP/2 resets the stream, HTTP/3 stops it) and the client never has a complete
//!   one; the hit is written as `leak`. `log_only` writes it and lets the body through.
//!
//! A hit is written to the log as `leak` with the matched text.
//!
//! `NgfwResponses` is zero-sized (one constant for every proxy, like the cache's observer) and
//! finds the module among the server's composed hooks by its type (`Ctx::hook`).

use super::State;
use super::body;
use super::engine::{Decision, Evaluation, Input, Plans, ResponseData};
use super::log::{Outcome, Record};
use super::rule::Phase;
use bytes::Bytes;
use http::{HeaderMap, HeaderValue, Method, Response, StatusCode, Uri};
use http_body::Frame;
use std::net::IpAddr;
use std::pin::Pin;
use std::sync::{Arc, LazyLock};
use std::task::{Context, Poll};
use webfast_core::body::{Body, BoxError};
use webfast_core::handler::Ctx;
use webfast_core::module::Inspect;
use webfast_core::reqid::RequestId;

/// Bytes before (carried from the frames before) and after a frame boundary that a streamed
/// response's regex rules see across it; a match of at most this length is found wherever the
/// frames are cut.
pub const WINDOW: usize = 512;

/// The most a streamed response carries over a frame boundary: a literal longer than this plus
/// one, split between two frames, is not seen (no built-in literal comes near).
pub const MAX_CARRY: usize = 1024;

pub struct NgfwResponses;

/// Whether the leakage rules look at a response with this status and these headers.
fn covered(parts: &http::response::Parts) -> bool {
    let status = parts.status.as_u16();
    if status != 200 && !(500..600).contains(&status) {
        return false;
    }
    body::media_type(&parts.headers).is_some_and(|media| {
        body::starts_with_ignore_case(media, "text/")
            || media.eq_ignore_ascii_case("application/json")
            || media.eq_ignore_ascii_case("application/xhtml+xml")
    })
}

/// What a decision means for the response.
fn leaks(decision: Decision) -> Option<Outcome> {
    match decision {
        // A response cannot be challenged: in this phase `mode: challenge` replaces as `block` does.
        Decision::Block | Decision::Ban | Decision::Challenge => Some(Outcome::Leak),
        Decision::LogOnly => Some(Outcome::LogOnly),
        Decision::Continue | Decision::Pass => None,
    }
}

/// A response's line in the log.
fn write(
    state: &State,
    outcome: Outcome,
    status: u16,
    ip: IpAddr,
    ja4: Option<webfast_core::ja4::Ja4>,
    req: &http::request::Parts,
    evaluation: &Evaluation,
) {
    super::log::write(
        &state.log,
        &state.compiled,
        &Record {
            outcome,
            status,
            threshold: state.threshold,
            client_ip: ip,
            country: state.country(ip),
            asn: state.asn(ip),
            ja4,
            parts: req,
            evaluation: Some(evaluation),
        },
    );
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
        if parts.status == StatusCode::OK && state.response_stream {
            return self.stream_response(state, evaluation, ctx, parts, body);
        }
        let prefix = match body::read_prefix(body, state.max_inspect).await {
            Ok(prefix) => prefix,
            Err(error) => {
                tracing::debug!(%error, "ngfw: the upstream response body could not be read");
                return Err(state.refusal(StatusCode::BAD_GATEWAY));
            }
        };
        let text = String::from_utf8_lossy(&prefix.bytes);
        let input = Input {
            parts: &ctx.req,
            client_ip: ip,
            country: state.country(ip),
            asn: state.asn(ip),
            sni: ctx.conn.sni.as_deref(),
            ja4: ctx.conn.ja4,
            body: None,
            response: Some(ResponseData {
                status: parts.status.as_u16(),
                headers: &parts.headers,
                body: &text,
            }),
        };
        evaluation.run_phase(&state.compiled, Phase::Response, &input, state.log_matched);
        let Some(outcome) = leaks(evaluation.decision(state.threshold)) else {
            return Ok(prefix.body);
        };
        write(
            &state,
            outcome,
            state.leak_status.as_u16(),
            ip,
            ctx.conn.ja4,
            &ctx.req,
            &evaluation,
        );
        if outcome == Outcome::LogOnly {
            return Ok(prefix.body);
        }
        // Nothing of the upstream's answer goes out: not its headers either.
        parts.headers.clear();
        Err(state.refusal(state.leak_status))
    }

    /// A 200, streamed: the status and header rules now, the body rules frame by frame as the
    /// body goes out (`Scanning`).
    #[allow(clippy::result_large_err)]
    fn stream_response(
        &self,
        state: Arc<State>,
        mut evaluation: Evaluation,
        ctx: &Ctx,
        parts: &mut http::response::Parts,
        body: Body,
    ) -> Result<Body, Response<Body>> {
        let ip = ctx.client_ip;
        let status = parts.status.as_u16();
        let input = Input {
            parts: &ctx.req,
            client_ip: ip,
            country: state.country(ip),
            asn: state.asn(ip),
            sni: ctx.conn.sni.as_deref(),
            ja4: ctx.conn.ja4,
            body: None,
            response: Some(ResponseData {
                status,
                headers: &parts.headers,
                body: "",
            }),
        };
        evaluation.run_response(&state.compiled, &input, state.log_matched, Plans::ResponseHead);
        let decision = evaluation.decision(state.threshold);
        match leaks(decision) {
            Some(Outcome::LogOnly) | None => {}
            Some(outcome) => {
                write(
                    &state,
                    outcome,
                    state.leak_status.as_u16(),
                    ip,
                    ctx.conn.ja4,
                    &ctx.req,
                    &evaluation,
                );
                parts.headers.clear();
                return Err(state.refusal(state.leak_status));
            }
        }
        let carry = match state.response_carry {
            Some(carry) if decision != Decision::Pass && !http_body::Body::is_end_stream(&body) => carry,
            // No body rule, a `pass`, or no body: decided by the head.
            _ => {
                if decision == Decision::LogOnly {
                    write(
                        &state,
                        Outcome::LogOnly,
                        status,
                        ip,
                        ctx.conn.ja4,
                        &ctx.req,
                        &evaluation,
                    );
                }
                return Ok(body);
            }
        };
        Ok(webfast_core::body::boxed(Scanning {
            inner: body,
            scan: Some(Scan {
                left: state.max_inspect,
                state,
                evaluation,
                status,
                ip,
                ja4: ctx.conn.ja4,
                request: Request::of(&ctx.req),
                carry: carry.min(MAX_CARRY),
                tail: 0,
                buf: [0; 2 * MAX_CARRY],
                lossy: String::new(),
            }),
            cut: false,
        }))
    }
}

/// What the log needs of the request, kept for a streamed response's line (the request's head is
/// the handler's, gone by the time a frame passes). Clones of the head's parts: no copy of their
/// bytes.
struct Request {
    method: Method,
    uri: Uri,
    host: Option<HeaderValue>,
    user_agent: Option<HeaderValue>,
    /// The request's id (webfast_core::reqid), the same in the line as in the access log's.
    id: Option<RequestId>,
}

impl Request {
    fn of(parts: &http::request::Parts) -> Request {
        Request {
            method: parts.method.clone(),
            uri: parts.uri.clone(),
            host: parts.headers.get(http::header::HOST).cloned(),
            user_agent: parts.headers.get(http::header::USER_AGENT).cloned(),
            id: parts.extensions.get::<RequestId>().cloned(),
        }
    }

    /// The head again, for the log line (only a response that is written pays for it).
    fn parts(&self) -> http::request::Parts {
        let (mut parts, ()) = http::Request::new(()).into_parts();
        parts.method = self.method.clone();
        parts.uri = self.uri.clone();
        if let Some(host) = &self.host {
            parts.headers.insert(http::header::HOST, host.clone());
        }
        if let Some(user_agent) = &self.user_agent {
            parts.headers.insert(http::header::USER_AGENT, user_agent.clone());
        }
        if let Some(id) = &self.id {
            parts.extensions.insert(id.clone());
        }
        parts
    }
}

/// A streamed 200's body: the frames as they come, each scanned until `max_inspect` bytes were;
/// on a hit, an error in place of the frame that has it.
struct Scanning {
    inner: Body,
    /// `None` once the scan is over (`max_inspect` reached, a `pass`, the end, a hit).
    scan: Option<Scan>,
    /// A hit ended the body.
    cut: bool,
}

/// The scan of a streamed 200, one per response: everything it needs in one allocation with
/// the body (the window buffer inline), nothing allocated per frame.
struct Scan {
    state: Arc<State>,
    evaluation: Evaluation,
    status: u16,
    ip: IpAddr,
    ja4: Option<webfast_core::ja4::Ja4>,
    request: Request,
    /// Body bytes still to scan.
    left: usize,
    /// Bytes kept from the frames before for the window across the next boundary.
    carry: usize,
    /// `buf[..tail]`: the last `carry` bytes scanned (fewer at the start).
    tail: usize,
    /// The tail, then the start of the next frame: the window across a boundary.
    buf: [u8; 2 * MAX_CARRY],
    /// A window that is not UTF-8, made text (reused).
    lossy: String,
}

/// What a scanned window decided.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Verdict {
    Go,
    /// Nothing more to scan: `max_inspect` reached, or a `pass` rule.
    Done,
    /// A leak: the body ends here.
    Cut,
}

/// The error the body ends with on a leak.
#[derive(Debug)]
struct Leaked;

impl std::fmt::Display for Leaked {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("ngfw: the response body leaks; the response is cut")
    }
}

impl std::error::Error for Leaked {}

/// The request head the body rules are run with: they read the response alone.
static NO_REQUEST: LazyLock<http::request::Parts> = LazyLock::new(|| http::Request::new(()).into_parts().0);

/// `bytes` as text: a character cut at either end (a frame boundary: the window across it has it
/// whole) left out; bytes that are not UTF-8 replaced, in `lossy`.
fn as_text<'t>(bytes: &'t [u8], lossy: &'t mut String) -> &'t str {
    let start = bytes.iter().take(3).take_while(|&&b| b & 0xC0 == 0x80).count();
    let bytes = &bytes[start..];
    match std::str::from_utf8(bytes) {
        Ok(text) => text,
        Err(error) if error.error_len().is_none() => std::str::from_utf8(&bytes[..error.valid_up_to()]).unwrap_or(""),
        Err(_) => {
            lossy.clear();
            for chunk in bytes.utf8_chunks() {
                lossy.push_str(chunk.valid());
                if !chunk.invalid().is_empty() {
                    lossy.push(char::REPLACEMENT_CHARACTER);
                }
            }
            lossy
        }
    }
}

/// The body rules over one window of the body.
fn run(evaluation: &mut Evaluation, state: &State, status: u16, ip: IpAddr, text: &str) -> Verdict {
    if text.is_empty() {
        return Verdict::Go;
    }
    let headers = HeaderMap::new();
    let input = Input {
        parts: &NO_REQUEST,
        client_ip: ip,
        country: None,
        asn: None,
        sni: None,
        ja4: None,
        body: None,
        response: Some(ResponseData {
            status,
            headers: &headers,
            body: text,
        }),
    };
    evaluation.run_response(&state.compiled, &input, state.log_matched, Plans::ResponseBody);
    match evaluation.decision(state.threshold) {
        Decision::Block | Decision::Ban | Decision::Challenge => Verdict::Cut,
        Decision::Pass => Verdict::Done,
        Decision::LogOnly | Decision::Continue => Verdict::Go,
    }
}

impl Scan {
    /// One data frame: the window across the boundary before it, then the frame itself (when the
    /// window did not already hold all of it); then the tail kept for the next.
    fn frame(&mut self, data: &[u8]) -> Verdict {
        let take = data.len().min(self.left);
        if take == 0 {
            return if self.left == 0 { Verdict::Done } else { Verdict::Go };
        }
        let data = &data[..take];
        self.left -= take;
        let carry = self.carry;
        let head = take.min(carry);
        if self.tail > 0 {
            self.buf[self.tail..self.tail + head].copy_from_slice(&data[..head]);
            let text = as_text(&self.buf[..self.tail + head], &mut self.lossy);
            let verdict = run(&mut self.evaluation, &self.state, self.status, self.ip, text);
            if verdict != Verdict::Go {
                return verdict;
            }
        }
        if self.tail == 0 || take > carry {
            let text = as_text(data, &mut self.lossy);
            let verdict = run(&mut self.evaluation, &self.state, self.status, self.ip, text);
            if verdict != Verdict::Go {
                return verdict;
            }
        }
        if take >= carry {
            self.buf[..carry].copy_from_slice(&data[take - carry..]);
            self.tail = carry;
        } else {
            // The frame is in the buffer after the tail already (`head` is all of it), unless
            // there was no tail.
            if self.tail == 0 {
                self.buf[..take].copy_from_slice(data);
            }
            let total = self.tail + take;
            let keep = total.min(carry);
            self.buf.copy_within(total - keep..total, 0);
            self.tail = keep;
        }
        if self.left == 0 { Verdict::Done } else { Verdict::Go }
    }

    /// A hit: the line, as `leak` (the response's own status: it went out, and is cut).
    fn cut(&mut self) {
        write(
            &self.state,
            Outcome::Cut,
            self.status,
            self.ip,
            self.ja4,
            &self.request.parts(),
            &self.evaluation,
        );
        // Written: the drop has nothing to add.
        self.evaluation = Evaluation::new();
    }
}

impl Drop for Scan {
    /// The scan is over without a cut: a `log_only` hit is written now, once, with every hit the
    /// scan saw.
    fn drop(&mut self) {
        if self.evaluation.decision(self.state.threshold) == Decision::LogOnly {
            write(
                &self.state,
                Outcome::LogOnly,
                self.status,
                self.ip,
                self.ja4,
                &self.request.parts(),
                &self.evaluation,
            );
        }
    }
}

impl http_body::Body for Scanning {
    type Data = Bytes;
    type Error = BoxError;

    fn poll_frame(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Option<Result<Frame<Bytes>, BoxError>>> {
        let this = &mut *self;
        if this.cut {
            return Poll::Ready(None);
        }
        let frame = match Pin::new(&mut this.inner).poll_frame(cx) {
            Poll::Pending => return Poll::Pending,
            Poll::Ready(Some(Ok(frame))) => frame,
            end => {
                // The end, or the upstream's error: the scan is over.
                this.scan = None;
                return end;
            }
        };
        if let (Some(scan), Some(data)) = (this.scan.as_mut(), frame.data_ref()) {
            match scan.frame(data) {
                Verdict::Go => {}
                Verdict::Done => this.scan = None,
                Verdict::Cut => {
                    scan.cut();
                    this.scan = None;
                    this.cut = true;
                    return Poll::Ready(Some(Err(Box::new(Leaked))));
                }
            }
        }
        Poll::Ready(Some(Ok(frame)))
    }

    fn is_end_stream(&self) -> bool {
        self.cut || self.inner.is_end_stream()
    }

    fn size_hint(&self) -> http_body::SizeHint {
        self.inner.size_hint()
    }
}

impl Inspect for NgfwResponses {
    /// A module with response rules, and a response they look at.
    fn covers(&self, ctx: &Ctx, parts: &http::response::Parts) -> bool {
        ctx.hook::<super::Ngfw>()
            .is_some_and(|ngfw| ngfw.state().compiled.has_phase(Phase::Response) && covered(parts))
    }

    async fn inspect<'a>(
        &'a self,
        ctx: &'a mut Ctx,
        parts: &'a mut http::response::Parts,
        body: Body,
    ) -> Result<Body, Response<Body>> {
        match ctx.hook::<super::Ngfw>() {
            Some(ngfw) => ngfw.inspect_response(ctx, parts, body).await,
            None => Ok(body),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use http_body_util::BodyExt;
    use std::collections::VecDeque;

    const FILE: &str = r#"
log: { output: discard }
response: { leak_status: 500 }
body: { max_inspect: 4KiB }
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
  - id: oracle
    phase: response
    targets: [response.body]
    prefilter: ['ORA-']
    operator: { regex: 'ORA-\d{5}' }
    action: block
  - id: server
    phase: response
    targets: [response.headers.server]
    operator: { regex: 'Apache/\d+\.\d+\.\d+' }
    prefilter: ['Apache/']
    action: log
  - id: debug
    phase: response
    targets: [response.headers.x-debug-token]
    operator: { contains_any: ['secret'] }
    action: block
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

    fn ngfw(file: &str) -> (super::super::Ngfw, tempfile::TempDir) {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(dir.path().join("leak.yaml"), RULES).unwrap();
        (super::super::Ngfw::load_str(file, dir.path()).unwrap(), dir)
    }

    /// A body of the given frames, as an upstream's stream gives them.
    struct Frames(VecDeque<Bytes>);

    impl http_body::Body for Frames {
        type Data = Bytes;
        type Error = BoxError;

        fn poll_frame(mut self: Pin<&mut Self>, _: &mut Context<'_>) -> Poll<Option<Result<Frame<Bytes>, BoxError>>> {
            Poll::Ready(self.0.pop_front().map(|data| Ok(Frame::data(data))))
        }
    }

    fn frames(parts: &[&[u8]]) -> Body {
        webfast_core::body::boxed(Frames(parts.iter().map(|p| Bytes::copy_from_slice(p)).collect()))
    }

    /// The frames a body yields until its end or an error: the data, and whether it errored.
    async fn drain(mut body: Body) -> (Vec<Bytes>, bool) {
        let mut out = Vec::new();
        while let Some(frame) = body.frame().await {
            match frame {
                Ok(frame) => out.extend(frame.into_data().ok()),
                Err(_) => return (out, true),
            }
        }
        (out, false)
    }

    #[tokio::test]
    async fn a_leaking_response_is_replaced_and_a_clean_one_goes_on_whole() {
        let (ngfw, _dir) = ngfw(&FILE.replace("leak_status: 500", "leak_status: 500, stream: false"));
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
    }

    #[tokio::test]
    async fn a_5xx_is_held_and_replaced_whatever_the_stream_setting() {
        let (ngfw, _dir) = ngfw(FILE);
        let mut ctx = ctx();
        let mut parts = response(502, "text/plain");
        let error = frames(&[b"upstream says: ", b"Stack trace: #0"]);
        let replaced = ngfw
            .inspect_response(&mut ctx, &mut parts, error)
            .await
            .expect_err("5xx is covered");
        assert_eq!(replaced.status(), StatusCode::INTERNAL_SERVER_ERROR);
    }

    #[tokio::test]
    async fn a_streamed_200_is_cut_at_the_frame_with_the_leak() {
        let (ngfw, _dir) = ngfw(FILE);
        let mut ctx = ctx();

        // In the first frame: nothing of the body goes out.
        let mut parts = response(200, "text/html");
        let body = ngfw
            .inspect_response(
                &mut ctx,
                &mut parts,
                frames(&[b"<html>Fatal: Stack trace: #0", b"<p>rest</p>"]),
            )
            .await
            .expect("streamed: the head goes out");
        assert_eq!(
            drain(body).await,
            (vec![], true),
            "the frame with the hit is not forwarded"
        );

        // In a later frame: the ones before go out, then the error.
        let mut parts = response(200, "text/html");
        let body = ngfw
            .inspect_response(
                &mut ctx,
                &mut parts,
                frames(&[b"<html>clean", b"<p>Stack trace: #0</p>", b"tail"]),
            )
            .await
            .unwrap();
        assert_eq!(drain(body).await, (vec![Bytes::from_static(b"<html>clean")], true));
    }

    #[tokio::test]
    async fn a_leak_split_across_frames_is_found() {
        let (ngfw, _dir) = ngfw(FILE);
        let mut ctx = ctx();
        let cases: &[&[&[u8]]] = &[
            // A literal cut in two.
            &[b"<html>Fatal: Stack tr", b"ace: #0 /var/www", b"</html>"],
            // A regex whose prefilter literal is cut.
            &[b"error ORA-0", b"0942: table or view does not exist"],
            // A literal over many small frames.
            &[b"Sta", b"ck", b" ", b"tra", b"c", b"e:", b" #0"],
            // Behind a long frame: the window carries the end of it.
            &[&[b'a'; 3000], b"... Stack", b" trace: #0"],
        ];
        for frames_of in cases {
            let mut parts = response(200, "text/html");
            let body = ngfw
                .inspect_response(&mut ctx, &mut parts, frames(frames_of))
                .await
                .unwrap();
            let (passed, cut) = drain(body).await;
            assert!(cut, "found across frames: {frames_of:?}");
            assert!(
                passed.len() < frames_of.len(),
                "the frame that completes it is not forwarded"
            );
        }
        // Characters cut between frames do not hide a literal after them.
        let text = "Grüße aus München — Stack trace: #0".as_bytes();
        let at = 3; // inside "ü"
        let mut parts = response(200, "text/html; charset=utf-8");
        let body = ngfw
            .inspect_response(&mut ctx, &mut parts, frames(&[&text[..at], &text[at..]]))
            .await
            .unwrap();
        assert!(drain(body).await.1);
        // Nor do bytes that are not UTF-8.
        let mut parts = response(200, "text/html");
        let body = ngfw
            .inspect_response(
                &mut ctx,
                &mut parts,
                frames(&[b"\xff\xfe latin-1 \xe9t\xe9 Stack trace: #0"]),
            )
            .await
            .unwrap();
        assert!(drain(body).await.1);
    }

    #[tokio::test]
    async fn a_clean_200_streams_its_frames_as_they_are_and_a_leak_after_max_inspect_is_not_looked_at() {
        let (ngfw, _dir) = ngfw(FILE);
        let mut ctx = ctx();
        let sent: Vec<&[u8]> = vec![b"<html>", &[b'x'; 5000], b"<p>clean</p>", b"</html>"];
        let mut parts = response(200, "text/html");
        let body = ngfw
            .inspect_response(&mut ctx, &mut parts, frames(&sent))
            .await
            .unwrap();
        let (passed, cut) = drain(body).await;
        assert!(!cut);
        assert_eq!(
            passed,
            sent.iter().map(|f| Bytes::copy_from_slice(f)).collect::<Vec<_>>(),
            "the same frames"
        );

        // max_inspect is 4 KiB: a leak after it goes out.
        let late: Vec<&[u8]> = vec![&[b'x'; 4096], b"Stack trace: #0"];
        let mut parts = response(200, "text/html");
        let body = ngfw
            .inspect_response(&mut ctx, &mut parts, frames(&late))
            .await
            .unwrap();
        assert_eq!(drain(body).await.0.len(), 2, "not scanned past max_inspect");
        // ... and one that starts before it and ends after is not either (the scan stops at it).
        let across: Vec<&[u8]> = vec![&[b'x'; 4090], b"Stack trace: #0"];
        let mut parts = response(200, "text/html");
        let body = ngfw
            .inspect_response(&mut ctx, &mut parts, frames(&across))
            .await
            .unwrap();
        assert!(!drain(body).await.1);
    }

    #[tokio::test]
    async fn a_header_rule_replaces_a_streamed_200_before_any_byte() {
        let (ngfw, _dir) = ngfw(FILE);
        let mut ctx = ctx();
        let mut parts = response(200, "text/html");
        parts
            .headers
            .insert("x-debug-token", HeaderValue::from_static("secret-1234"));
        let replaced = ngfw
            .inspect_response(&mut ctx, &mut parts, frames(&[b"<html>clean</html>"]))
            .await
            .expect_err("replaced by the header rule");
        assert_eq!(replaced.status(), StatusCode::INTERNAL_SERVER_ERROR);
        assert!(parts.headers.is_empty());
    }

    #[tokio::test]
    async fn log_only_lets_a_streamed_leak_through_and_writes_it_once() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(dir.path().join("leak.yaml"), RULES).unwrap();
        let file = FILE
            .replace("log: { output: discard }", "mode: log_only\nlog: { output: ngfw.log }")
            .replace(
                "builtin: none",
                "builtin: none\n  override: { leak: { mode: log_only }, oracle: { mode: log_only } }",
            );
        let ngfw = super::super::Ngfw::load_str(&file, dir.path()).unwrap();
        let mut ctx = ctx();
        let sent: Vec<&[u8]> = vec![b"<html>Stack trace: #0", b" ORA-00942 ", b"</html>"];
        let mut parts = response(200, "text/html");
        let body = ngfw
            .inspect_response(&mut ctx, &mut parts, frames(&sent))
            .await
            .unwrap();
        let (passed, cut) = drain(body).await;
        assert!(!cut, "log_only never cuts");
        assert_eq!(passed.len(), 3);
        webfast_core::accesslog::flush_all(std::time::Duration::from_secs(2));
        let log = std::fs::read_to_string(dir.path().join("ngfw.log")).unwrap();
        let lines: Vec<serde_json::Value> = log.lines().map(|l| serde_json::from_str(l).unwrap()).collect();
        assert_eq!(lines.len(), 1, "one line for the response: {log}");
        assert_eq!(lines[0]["decision"], "log_only");
        assert_eq!(lines[0]["status"], 200);
        let ids: Vec<&str> = lines[0]["hits"]
            .as_array()
            .unwrap()
            .iter()
            .map(|h| h["id"].as_str().unwrap())
            .collect();
        assert!(ids.contains(&"leak") && ids.contains(&"oracle"), "{log}");
    }

    #[tokio::test]
    async fn a_cut_is_written_as_a_leak_with_the_matched_text() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(dir.path().join("leak.yaml"), RULES).unwrap();
        let ngfw =
            super::super::Ngfw::load_str(&FILE.replace("output: discard", "output: ngfw.log"), dir.path()).unwrap();
        let mut ctx = ctx();
        let mut parts = response(200, "text/html");
        let body = ngfw
            .inspect_response(&mut ctx, &mut parts, frames(&[b"<html>ok", b" Stack trace: #0"]))
            .await
            .unwrap();
        assert!(drain(body).await.1);
        webfast_core::accesslog::flush_all(std::time::Duration::from_secs(2));
        let log = std::fs::read_to_string(dir.path().join("ngfw.log")).unwrap();
        let line: serde_json::Value = serde_json::from_str(log.lines().next().unwrap()).unwrap();
        assert_eq!(line["decision"], "leak");
        assert_eq!(line["msg"], "response cut");
        assert_eq!(line["status"], 200);
        assert_eq!(line["phase"], "response");
        assert_eq!(line["request"]["uri"], "/page");
        assert_eq!(line["request"]["host"], "www.example.com");
        let hits = line["hits"].as_array().unwrap();
        assert!(
            hits.iter().any(|h| h["id"] == "leak" && h["matched"] == "Stack trace:"),
            "{line}"
        );
        assert!(
            hits.iter().any(|h| h["id"] == "server"),
            "the header rule's hit too: {line}"
        );
    }

    #[test]
    fn the_carry_is_the_longest_literal_or_the_regex_window() {
        let (ngfw, _dir) = ngfw(FILE);
        assert_eq!(ngfw.state().response_carry, Some(WINDOW), "a regex rule: the window");
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(
            dir.path().join("leak.yaml"),
            "rules:\n  - {id: a, phase: response, targets: [response.body], operator: {contains_any: ['Stack trace:']}, action: block}\n",
        )
        .unwrap();
        let literals = super::super::Ngfw::load_str(FILE, dir.path()).unwrap();
        assert_eq!(literals.state().response_carry, Some("Stack trace:".len() - 1));
        std::fs::write(
            dir.path().join("leak.yaml"),
            "rules:\n  - {id: h, phase: response, targets: [response.headers.server], operator: {contains_any: ['x']}, action: log}\n",
        )
        .unwrap();
        let headers = super::super::Ngfw::load_str(FILE, dir.path()).unwrap();
        assert_eq!(
            headers.state().response_carry,
            None,
            "no body rule: the body is not wrapped"
        );
    }

    #[test]
    fn text_is_taken_whole_characters_only() {
        let mut lossy = String::new();
        assert_eq!(as_text("abc".as_bytes(), &mut lossy), "abc");
        let word = "für".as_bytes();
        assert_eq!(
            as_text(&word[2..], &mut lossy),
            "r",
            "a continuation at the start left out"
        );
        assert_eq!(
            as_text(&word[..2], &mut lossy),
            "f",
            "a character cut at the end left out"
        );
        assert_eq!(as_text(b"a\xffb", &mut lossy), "a\u{fffd}b");
    }
}
