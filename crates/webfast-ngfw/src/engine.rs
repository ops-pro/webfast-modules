//! One request's evaluation: each target's values, every value put once through each
//! transformation chain of the target's rules into a thread-local buffer (or borrowed, when no
//! transformation changes it), the distinct texts searched by the target's one automaton; the
//! rules a literal led to checked further (regex, `when`/`unless`, exclusions); the scores and
//! the decision at a phase's end. A clean request allocates nothing: the buffers are
//! thread-local, the hit list and the matched set are empty vectors until a rule matches.
//!
//! A phase runs synchronously (`run_phase`), so the thread-local buffers are never held across
//! an await; what lasts across the phases (scores, hits, the matched set) is in `Evaluation`.
//! The head is prepared (path decoded, query and cookies split) once per request and thread: the
//! buffers carry a generation the evaluation remembers.

use super::body::BodyData;
use super::compile::{Compiled, CompiledRule, Magic, Matcher, Plan};
use super::rule::{Action, Measure, Mode, Phase, Target, Transform};
use super::source::HitSource;
use http::HeaderMap;
use std::cell::RefCell;
use std::io::Write as _;
use std::net::IpAddr;
use std::ops::Range;
use webfast_core::handler::{hostport_of, strip_port};
use webfast_core::matcher::{clean_path, needs_clean};

/// A `name=value` pair of the query or the cookies, as ranges in its text.
#[derive(Clone, Copy)]
struct Pair {
    name: (u32, u32),
    value: (u32, u32),
}

/// The decoded forms of a request's targets and the scratch of the transformations, one set per
/// thread.
#[derive(Default)]
pub(super) struct Buffers {
    /// Counts the requests prepared here; an evaluation re-prepares when it is not the last.
    generation: u64,
    /// The path percent-decoded and cleaned, case kept (the `path` target).
    path: String,
    /// `path` lowercased: what `path` matchers compare against (exclusions, `match`, honeypots).
    match_path: String,
    /// The Host, port stripped, lowercased.
    host: String,
    /// The query with each `+` read as the space it stands for (form encoding, as a form body is
    /// parsed): filled only when the query has a `+`; the pairs are then ranges in it.
    query_text: String,
    query_plus: bool,
    /// The query's pairs, as ranges in the query string (or in `query_text`).
    query_pairs: Vec<Pair>,
    /// The Cookie headers joined by `;`, and the pairs as ranges in that.
    cookie_text: String,
    cookie_pairs: Vec<Pair>,
    /// One output buffer per chain of the plan being run, and the scratch of a chain.
    outs: Vec<String>,
    tmp: String,
    bytes: Vec<u8>,
    bytes2: Vec<u8>,
    /// The distinct texts of a value and the chains that give each.
    distinct: Vec<Distinct>,
    /// Rules whose regex ran on the current text (not again for another prefilter hit in it).
    tested: Vec<u32>,
    /// A plan's clean values, a separator between them, and where each is (`run_concat`).
    concat: String,
    segments: Vec<Segment>,
    /// The name of the value a hit in `concat` was found in.
    name_buf: String,
}

/// One value's place in `Buffers::concat`, and which of the target's values it is.
#[derive(Clone, Copy)]
struct Segment {
    start: u32,
    end: u32,
    index: u32,
}

thread_local! {
    static BUFFERS: RefCell<Buffers> = RefCell::new(Buffers::default());
}

/// One text a value became, with the chains (by bit) that gave it: `None`, the value itself.
#[derive(Clone, Copy)]
struct Distinct {
    chains: u64,
    buffer: Option<usize>,
}

/// What a phase run has of the request once, read-only.
pub(super) struct Fixed<'a> {
    pub path: &'a str,
    pub match_path: &'a str,
    pub host: &'a str,
    query: &'a str,
    query_pairs: &'a [Pair],
    cookie_text: &'a str,
    cookie_pairs: &'a [Pair],
}

impl Fixed<'_> {
    /// The query's pairs as sent but for `+`, which is a space (not percent-decoded).
    fn query_pairs(&self) -> impl Iterator<Item = (&str, &str)> {
        self.query_pairs.iter().map(|p| {
            (
                &self.query[p.name.0 as usize..p.name.1 as usize],
                &self.query[p.value.0 as usize..p.value.1 as usize],
            )
        })
    }

    /// The cookies, name and value (quotes stripped).
    fn cookies(&self) -> impl Iterator<Item = (&str, &str)> {
        self.cookie_pairs.iter().map(|p| {
            (
                &self.cookie_text[p.name.0 as usize..p.name.1 as usize],
                &self.cookie_text[p.value.0 as usize..p.value.1 as usize],
            )
        })
    }
}

struct Scratch<'a> {
    outs: &'a mut Vec<String>,
    tmp: &'a mut String,
    bytes: &'a mut Vec<u8>,
    bytes2: &'a mut Vec<u8>,
    distinct: &'a mut Vec<Distinct>,
    tested: &'a mut Vec<u32>,
    concat: &'a mut String,
    segments: &'a mut Vec<Segment>,
    name_buf: &'a mut String,
}

/// `sub`, a slice of `whole`, as its range in `whole`.
fn span(whole: &str, sub: &str) -> (u32, u32) {
    let start = sub.as_ptr() as usize - whole.as_ptr() as usize;
    (start as u32, (start + sub.len()) as u32)
}

/// Fills the per-request buffers from the head, once per request and thread.
fn prepare(parts: &http::request::Parts, b: &mut Buffers) {
    b.generation += 1;
    b.path.clear();
    let raw = parts.uri.path();
    if raw.contains('%') {
        b.bytes.clear();
        percent_decode_into(raw, &mut b.bytes, false);
        push_lossy(&b.bytes, &mut b.path);
    } else {
        b.path.push_str(raw);
    }
    if needs_clean(&b.path) {
        let cleaned = clean_path(&b.path, true);
        b.path.clear();
        b.path.push_str(&cleaned);
    }
    b.match_path.clear();
    lowercase(&b.path, &mut b.match_path);
    b.host.clear();
    b.host.push_str(strip_port(hostport_of(parts)));
    b.host.make_ascii_lowercase();
    b.query_pairs.clear();
    b.query_text.clear();
    b.query_plus = false;
    if let Some(raw) = parts.uri.query() {
        // A `+` in a query is a space (an HTML form sent by GET writes its spaces so): the
        // values are read as a form body's are, `%2B` still being a `+` once url_decode runs.
        let query = if raw.contains('+') {
            b.query_text.extend(raw.chars().map(|c| if c == '+' { ' ' } else { c }));
            b.query_plus = true;
            b.query_text.as_str()
        } else {
            raw
        };
        for (name, value) in query_pairs(query) {
            b.query_pairs.push(Pair {
                name: span(query, name),
                value: span(query, value),
            });
        }
    }
    b.cookie_text.clear();
    b.cookie_pairs.clear();
    for value in parts.headers.get_all(http::header::COOKIE) {
        if let Ok(value) = value.to_str() {
            if !b.cookie_text.is_empty() {
                b.cookie_text.push(';');
            }
            b.cookie_text.push_str(value);
        }
    }
    if !b.cookie_text.is_empty() {
        let text = &b.cookie_text;
        b.cookie_pairs.extend(cookie_pairs_of(text).map(|(name, value)| Pair {
            name: span(text, name),
            value: span(text, value),
        }));
    }
}

/// `text` lowercased into `out`: ASCII in place, else character by character.
fn lowercase(text: &str, out: &mut String) {
    if text.is_ascii() {
        out.push_str(text);
        out.make_ascii_lowercase();
    } else {
        for c in text.chars() {
            out.extend(c.to_lowercase());
        }
    }
}

/// What a rule sees of the request and, in the later phases, of its body or the response.
pub struct Input<'a> {
    pub parts: &'a http::request::Parts,
    pub client_ip: IpAddr,
    pub country: Option<[u8; 2]>,
    pub asn: Option<u32>,
    pub sni: Option<&'a str>,
    /// The client's TLS fingerprint (the connection's), when known.
    pub ja4: Option<webfast_core::ja4::Ja4>,
    pub body: Option<&'a BodyData>,
    pub response: Option<ResponseData<'a>>,
}

/// Which plans of a phase run: all of them, or — for a streamed response (response.rs) — those
/// on the status and headers once, then those on the body over each window of it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Plans {
    All,
    /// Every plan but the `response.body` ones; the exclusions that apply to the request are
    /// found now, while its head is at hand.
    ResponseHead,
    /// The `response.body` plans alone, on a window of the body: the request's head is not
    /// looked at (the exclusions were found by `ResponseHead`).
    ResponseBody,
}

/// A proxied response, for the `response` phase.
pub struct ResponseData<'a> {
    pub status: u16,
    pub headers: &'a HeaderMap,
    pub body: &'a str,
}

/// One rule that matched.
#[derive(Debug, Clone)]
pub struct Hit {
    /// The built-in engine's rule (an index into `Compiled::rules`); unused for an engine's hit.
    pub rule: u32,
    /// The rule of a rule engine (src/plugin.rs) that matched.
    pub engine: Option<std::sync::Arc<super::plugin::EngineRule>>,
    /// An engine's hit: the score it gave (a built-in rule's is the rule's).
    pub score: u32,
    /// An engine's hit: the rule's words on the match (the CRS's `logdata`), cut to `log.matched`.
    pub data: Option<String>,
    pub target: String,
    /// Cut to `log.matched` bytes; the log shows it as its source lets it (src/source.rs).
    pub matched: String,
    /// Where `matched` came from.
    pub source: HitSource,
    /// Where `data` may have taken its values from: the most hidden of a chain's variables.
    pub data_source: HitSource,
}

/// What a phase's end decides.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Decision {
    Continue,
    Block,
    Ban,
    /// The browser challenge is due (a `challenge` action or mode): refused with it unless the
    /// client passed it.
    Challenge,
    /// Would have refused; the request goes on.
    LogOnly,
    /// A `pass` rule: nothing more is checked.
    Pass,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Blocked {
    Block,
    Ban,
    Challenge,
}

#[derive(Clone, Copy, Default)]
struct Anomalies {
    double_encoding: bool,
    json_too_deep: bool,
}

/// The state of one request across its phases.
#[derive(Default)]
pub struct Evaluation {
    pub score: u32,
    /// Scores of `log_only` rules: decide a `LogOnly` decision, never a refusal.
    pub shadow: u32,
    /// Of `score`: what rules in `mode: challenge` added. A sum over the threshold made of these
    /// alone is a challenge, not a block.
    pub challenge_score: u32,
    /// A challenge was due and the client had passed it: the request goes on, not asked again.
    passed_challenge: bool,
    pub hits: Vec<Hit>,
    /// Rules matched, by bit; allocated on the first hit.
    matched: Vec<u64>,
    blocked: Option<Blocked>,
    shadow_blocked: bool,
    passed: bool,
    /// A `url_decode` of this request needed a second pass.
    pub double_encoding: bool,
    /// Rules with `action: header` that matched.
    pub header_rules: Vec<u32>,
    /// Exclusions whose host and path apply to this request; found on the first hit.
    active_exclusions: Option<Vec<u32>>,
    /// The last phase run.
    pub phase: Phase,
    /// The buffers' generation when they were prepared for this request; 0: not yet (a prepared
    /// generation is 1 or more).
    prepared: u64,
    /// The rule engines' states of this request, by the engine's place in the file's list.
    pub(crate) engines: Vec<super::plugin::EngineState>,
}

/// What led to a rule's test: a literal of its own found at the range (decided), a prefilter
/// literal found (its regex decides), a per-value test that held at the range, or the target as a
/// whole.
enum Found {
    Hit(Range<usize>),
    Tested(Range<usize>),
    Whole,
}

impl Evaluation {
    pub fn new() -> Evaluation {
        Evaluation::default()
    }

    pub fn is_matched(&self, rule: u32) -> bool {
        self.matched
            .get(rule as usize / 64)
            .is_some_and(|word| word & (1 << (rule % 64)) != 0)
    }

    fn set_matched(&mut self, rule: u32, rules: usize) {
        if self.matched.is_empty() {
            self.matched.resize(rules.div_ceil(64).max(1), 0);
        }
        self.matched[rule as usize / 64] |= 1 << (rule % 64);
    }

    /// Nothing more runs: a `block`/`ban` action fired, or a `pass`.
    fn stopped(&self) -> bool {
        self.blocked.is_some() || self.passed
    }

    /// Whether the request is decided whatever runs next (a `block`, `ban`, `challenge` or `pass`).
    pub fn is_stopped(&self) -> bool {
        self.stopped()
    }

    /// A rule engine's hit (src/plugin.rs): written as the built-in engine's are, counted under the
    /// file's `mode`.
    #[allow(clippy::too_many_arguments)]
    pub(crate) fn engine_hit(
        &mut self,
        rule: std::sync::Arc<super::plugin::EngineRule>,
        target: &str,
        matched: String,
        data: Option<String>,
        (source, data_source): (HitSource, HitSource),
        score: u32,
        verdict: super::plugin::Verdict,
        mode: Mode,
    ) {
        use super::plugin::Verdict;
        self.hits.push(Hit {
            rule: u32::MAX,
            engine: Some(rule),
            score,
            data,
            target: target.to_string(),
            matched,
            source,
            data_source,
        });
        let action = match verdict {
            Verdict::Score => Action::Score,
            Verdict::Block => Action::Block,
            Verdict::Log => Action::Log,
            Verdict::Pass => Action::Pass,
        };
        self.count(action, mode, score);
    }

    /// A hit's action applied: its score added (to the shadow sum for `log_only`, to the
    /// challenge's for `challenge` too), or the request decided.
    fn count(&mut self, action: Action, mode: Mode, score: u32) {
        let counted = mode != Mode::LogOnly;
        let soft = mode == Mode::Challenge;
        match action {
            Action::Score | Action::Header => {
                if counted {
                    self.score += score;
                    if soft {
                        self.challenge_score += score;
                    }
                } else {
                    self.shadow += score;
                }
            }
            Action::Block => {
                if counted {
                    self.blocked = Some(if soft { Blocked::Challenge } else { Blocked::Block });
                } else {
                    self.shadow_blocked = true;
                }
            }
            Action::Challenge => {
                if counted {
                    self.blocked = Some(Blocked::Challenge);
                } else {
                    self.shadow_blocked = true;
                }
            }
            Action::Ban => {
                if counted {
                    self.blocked = Some(Blocked::Ban);
                } else {
                    self.shadow_blocked = true;
                }
            }
            Action::Log => {}
            Action::Pass => self.passed = true,
        }
    }

    /// The challenge the decision asked for was passed by the client already: the request goes on
    /// through the phases left, and its challenge-mode scores decide nothing more (a block-mode
    /// rule's still do).
    pub fn challenge_passed(&mut self) {
        if self.blocked == Some(Blocked::Challenge) {
            self.blocked = None;
        }
        self.passed_challenge = true;
    }

    pub fn decision(&self, threshold: u32) -> Decision {
        if self.passed {
            return Decision::Pass;
        }
        match self.blocked {
            Some(Blocked::Ban) => return Decision::Ban,
            Some(Blocked::Block) => return Decision::Block,
            Some(Blocked::Challenge) => return Decision::Challenge,
            None => {}
        }
        if self.score >= threshold {
            if self.challenge_score < self.score {
                Decision::Block
            } else if self.passed_challenge {
                Decision::Continue
            } else {
                Decision::Challenge
            }
        } else if self.shadow_blocked || (self.shadow > 0 && self.score + self.shadow >= threshold) {
            Decision::LogOnly
        } else {
            Decision::Continue
        }
    }

    /// Prepares the head in the thread's buffers (when not already for this request) and runs
    /// `f` with what every phase reads of it.
    pub(super) fn with_request<R>(&mut self, parts: &http::request::Parts, f: impl FnOnce(&Fixed<'_>) -> R) -> R {
        BUFFERS.with(|cell| {
            let mut buffers = cell.borrow_mut();
            if self.prepared == 0 || buffers.generation != self.prepared {
                prepare(parts, &mut buffers);
                self.prepared = buffers.generation;
            }
            let fixed = Fixed {
                path: &buffers.path,
                match_path: &buffers.match_path,
                host: &buffers.host,
                query: parts.uri.query().unwrap_or(""),
                query_pairs: &buffers.query_pairs,
                cookie_text: &buffers.cookie_text,
                cookie_pairs: &buffers.cookie_pairs,
            };
            f(&fixed)
        })
    }

    /// Runs the plans of `phase` over `input`; `log_matched`: bytes of matched text kept per
    /// hit.
    pub fn run_phase(&mut self, compiled: &Compiled, phase: Phase, input: &Input<'_>, log_matched: usize) {
        self.run_plans(compiled, phase, input, log_matched, Plans::All);
    }

    /// The `response` phase's plans that `plans` names (a streamed response: the head's once,
    /// then the body's per window).
    pub fn run_response(&mut self, compiled: &Compiled, input: &Input<'_>, log_matched: usize, plans: Plans) {
        self.run_plans(compiled, Phase::Response, input, log_matched, plans);
    }

    fn run_plans(&mut self, compiled: &Compiled, phase: Phase, input: &Input<'_>, log_matched: usize, which: Plans) {
        self.phase = phase;
        if !compiled.has_phase(phase) {
            return;
        }
        BUFFERS.with(|cell| {
            let mut buffers = cell.borrow_mut();
            // A body window reads no part of the request: the buffers are left as they are.
            if which != Plans::ResponseBody && (self.prepared == 0 || buffers.generation != self.prepared) {
                prepare(input.parts, &mut buffers);
                self.prepared = buffers.generation;
            }
            let Buffers {
                path,
                match_path,
                host,
                query_text,
                query_plus,
                query_pairs,
                cookie_text,
                cookie_pairs,
                outs,
                tmp,
                bytes,
                bytes2,
                distinct,
                tested,
                concat,
                segments,
                name_buf,
                ..
            } = &mut *buffers;
            let fixed = if which == Plans::ResponseBody {
                Fixed {
                    path: "",
                    match_path: "",
                    host: "",
                    query: "",
                    query_pairs: &[],
                    cookie_text: "",
                    cookie_pairs: &[],
                }
            } else {
                Fixed {
                    path,
                    match_path,
                    host,
                    query: if *query_plus {
                        query_text.as_str()
                    } else {
                        input.parts.uri.query().unwrap_or("")
                    },
                    query_pairs,
                    cookie_text,
                    cookie_pairs,
                }
            };
            if which == Plans::ResponseHead && !compiled.exclusions.is_empty() && self.active_exclusions.is_none() {
                self.active_exclusions = Some(active_exclusions(compiled, &fixed));
            }
            let keep = |plan: &Plan| match which {
                Plans::All => true,
                Plans::ResponseHead => plan.target != Target::ResponseBody,
                Plans::ResponseBody => plan.target == Target::ResponseBody,
            };
            let mut scratch = Scratch {
                outs,
                tmp,
                bytes,
                bytes2,
                distinct,
                tested,
                concat,
                segments,
                name_buf,
            };
            let plans = &compiled.phases[phase.index()];
            let (ordinary, anomalies) = plans.split_at(compiled.anomalies_from[phase.index()]);
            for &p in ordinary {
                if self.stopped() {
                    return;
                }
                if keep(&compiled.plans[p]) {
                    self.run_plan(compiled, &compiled.plans[p], input, &fixed, &mut scratch, log_matched);
                }
            }
            if !self.stopped() && which != Plans::ResponseBody {
                self.run_arg_plans(compiled, phase, input, &fixed, &mut scratch, log_matched);
            }
            for &p in anomalies {
                if self.stopped() {
                    return;
                }
                if keep(&compiled.plans[p]) {
                    self.run_plan(compiled, &compiled.plans[p], input, &fixed, &mut scratch, log_matched);
                }
            }
        });
    }

    /// The `args.<name>` plans of the phase in one walk of the parameters: each pair's name looked
    /// up, its plan run on the value.
    fn run_arg_plans(
        &mut self,
        c: &Compiled,
        phase: Phase,
        input: &Input<'_>,
        fixed: &Fixed<'_>,
        scratch: &mut Scratch<'_>,
        log_matched: usize,
    ) {
        let index = &c.arg_plans[phase.index()];
        if index.is_empty() {
            return;
        }
        let in_body = matches!(phase, Phase::Body | Phase::Upload);
        let mut double = self.double_encoding;
        if !in_body || index.values().any(|&p| c.plans[p].wants_query) {
            for (name, value) in fixed.query_pairs() {
                // The query's names are as sent: decoded only when they have an escape.
                let found = match index.get(name) {
                    Some(&p) => Some(p),
                    None if name.contains('%') => index
                        .get(percent_encoding::percent_decode_str(name).decode_utf8_lossy().as_ref())
                        .copied(),
                    None => None,
                };
                let Some(p) = found else { continue };
                let plan = &c.plans[p];
                if in_body && !plan.wants_query {
                    continue;
                }
                let mask = classify(value, plan.needs);
                self.run_value(
                    c,
                    plan,
                    input,
                    fixed,
                    scratch,
                    log_matched,
                    Some(name),
                    value,
                    mask,
                    &mut double,
                );
                if self.stopped() {
                    break;
                }
            }
        }
        if in_body
            && !self.stopped()
            && let Some(body) = input.body
        {
            for (name, value) in body.form() {
                let Some(&p) = index.get(name) else { continue };
                let plan = &c.plans[p];
                let mask = classify(value, plan.needs);
                self.run_value(
                    c,
                    plan,
                    input,
                    fixed,
                    scratch,
                    log_matched,
                    Some(name),
                    value,
                    mask,
                    &mut double,
                );
                if self.stopped() {
                    break;
                }
            }
        }
        self.double_encoding = double;
    }

    /// The plan's rules on its target: every value through the chains (`run_value`); the values no
    /// chain changes are gathered, a separator between them, for one automaton pass over all of
    /// them (`run_concat`); then the rules on the target as a whole.
    fn run_plan(
        &mut self,
        c: &Compiled,
        g: &Plan,
        input: &Input<'_>,
        fixed: &Fixed<'_>,
        scratch: &mut Scratch<'_>,
        log_matched: usize,
    ) {
        let anomalies = Anomalies {
            double_encoding: self.double_encoding,
            json_too_deep: input.body.is_some_and(|b| b.json_too_deep),
        };
        if !g.chains.is_empty() {
            let mut double = self.double_encoding;
            scratch.concat.clear();
            scratch.segments.clear();
            let mut index = 0u32;
            for_each_value(input, fixed, g, anomalies, &mut |name, value| {
                let k = index;
                index += 1;
                let mask = classify(value, g.needs);
                if g.needs != ANY && mask & g.needs == 0 && g.separator.is_some() {
                    // Clean: every chain gives the value itself. Its tests now, the search later.
                    let all = (1u64 << g.chains.len()) - 1;
                    self.tests(
                        c,
                        g,
                        value,
                        mask,
                        all,
                        name,
                        input,
                        fixed,
                        scratch.tmp,
                        scratch.tested,
                        log_matched,
                    );
                    if !scratch.concat.is_empty() {
                        scratch.concat.push(g.separator.unwrap_or(0) as char);
                    }
                    let start = scratch.concat.len() as u32;
                    scratch.concat.push_str(value);
                    scratch.segments.push(Segment {
                        start,
                        end: scratch.concat.len() as u32,
                        index: k,
                    });
                } else {
                    self.run_value(c, g, input, fixed, scratch, log_matched, name, value, mask, &mut double);
                }
                !self.stopped()
            });
            self.double_encoding = double;
            if !self.stopped() && !scratch.segments.is_empty() {
                self.run_concat(c, g, input, fixed, scratch, anomalies, log_matched);
            }
        }
        if !g.whole.is_empty() && !self.stopped() {
            let count = for_each_value(input, fixed, g, anomalies, &mut |_, _| true);
            for &rule in &g.whole {
                let matched = match &c.rules[rule as usize].matcher {
                    Matcher::Compare(Measure::Count, cmp, n) => {
                        cmp.holds(i64::try_from(count).unwrap_or(i64::MAX), *n).then_some("")
                    }
                    Matcher::Exists => (count > 0).then_some(""),
                    Matcher::Missing => (count == 0).then_some(""),
                    Matcher::Compare(Measure::Number, cmp, n) => numeric(input, fixed, &g.target)
                        .is_some_and(|v| cmp.holds(v, *n))
                        .then_some(""),
                    Matcher::NotValidJson => input
                        .body
                        .is_some_and(|b| b.json_invalid && matches!(g.target, Target::Body | Target::BodyJson))
                        .then_some(""),
                    Matcher::NotValidUtf8 => invalid_utf8(input, &g.target, scratch.bytes).then_some(""),
                    Matcher::MagicIs(types) => input
                        .body
                        .and_then(|b| {
                            b.parts
                                .iter()
                                .filter(|p| p.filename.is_some())
                                .find_map(|p| types.iter().copied().find(|t| t.detect(&p.head)))
                        })
                        .map(magic_name),
                    Matcher::MagicNot(types) => input
                        .body
                        .and_then(|b| {
                            b.parts.iter().filter(|p| p.filename.is_some()).find_map(|p| {
                                let declared = Magic::of_content_type(p.content_type.as_deref()?)?;
                                (types.contains(&declared) && !declared.detect(&p.head)).then_some(declared)
                            })
                        })
                        .map(magic_name),
                    _ => None,
                };
                if let Some(matched) = matched {
                    self.candidate(
                        c,
                        rule,
                        &g.target,
                        matched,
                        Found::Whole,
                        None,
                        input,
                        fixed,
                        scratch.tested,
                        log_matched,
                    );
                    if self.stopped() {
                        return;
                    }
                }
            }
        }
    }

    /// One value of the plan's target that some chain may change: through each chain once, the
    /// distinct texts searched by the automaton (a hit counts for the rules whose chain gave the
    /// text) and tested by the per-value rules of the chains that gave it.
    #[allow(clippy::too_many_arguments)]
    fn run_value(
        &mut self,
        c: &Compiled,
        g: &Plan,
        input: &Input<'_>,
        fixed: &Fixed<'_>,
        scratch: &mut Scratch<'_>,
        log_matched: usize,
        name: Option<&str>,
        value: &str,
        mask: u16,
        double: &mut bool,
    ) {
        while scratch.outs.len() < g.chains.len() {
            scratch.outs.push(String::new());
        }
        scratch.distinct.clear();
        for (i, chain) in g.chains.iter().enumerate() {
            let bit = 1u64 << i;
            let Scratch {
                outs,
                tmp,
                bytes,
                bytes2,
                distinct,
                ..
            } = &mut *scratch;
            let changed = (chain.needs == ANY || mask & chain.needs != 0)
                && run_chain(
                    &chain.transforms,
                    value,
                    mask,
                    g.case_insensitive,
                    &mut outs[i],
                    tmp,
                    bytes,
                    bytes2,
                    double,
                );
            let buffer = if changed && outs[i] != value { Some(i) } else { None };
            let same = distinct.iter_mut().find(|d| match (d.buffer, buffer) {
                (None, None) => true,
                (Some(a), Some(b)) => outs[a] == outs[b],
                _ => false,
            });
            match same {
                Some(d) => d.chains |= bit,
                None => distinct.push(Distinct { chains: bit, buffer }),
            }
        }
        let Scratch {
            outs,
            tmp,
            tested,
            distinct,
            ..
        } = &mut *scratch;
        for d in distinct.iter() {
            let text: &str = match d.buffer {
                Some(i) => &outs[i],
                None => value,
            };
            let text_mask = if d.buffer.is_some() {
                classify(text, UPPER | NON_ASCII)
            } else {
                mask
            };
            self.search(c, g, text, d.chains, name, input, fixed, tested, log_matched);
            if self.stopped() {
                return;
            }
            self.tests(
                c,
                g,
                text,
                text_mask,
                d.chains,
                name,
                input,
                fixed,
                tmp,
                tested,
                log_matched,
            );
            if self.stopped() {
                return;
            }
        }
    }

    /// The automaton over `text`, the text the chains in `chains` (by bit) gave: a hit counts for
    /// the rules of those chains.
    #[allow(clippy::too_many_arguments)]
    fn search(
        &mut self,
        c: &Compiled,
        g: &Plan,
        text: &str,
        chains: u64,
        name: Option<&str>,
        input: &Input<'_>,
        fixed: &Fixed<'_>,
        tested: &mut Vec<u32>,
        log_matched: usize,
    ) {
        let Some(automaton) = &g.automaton else { return };
        if text.len() < automaton.min_pattern_len() {
            return;
        }
        tested.clear();
        for found in automaton.find_overlapping_iter(text) {
            for &(chain, rule) in &g.pattern_rules[found.pattern().as_usize()] {
                if chains & (1 << chain) != 0 {
                    self.candidate(
                        c,
                        rule,
                        &g.target,
                        text,
                        Found::Hit(found.range()),
                        name,
                        input,
                        fixed,
                        tested,
                        log_matched,
                    );
                    if self.stopped() {
                        return;
                    }
                }
            }
        }
    }

    /// The per-value rules of the chains in `chains` (by bit) on `text`, the text those chains
    /// gave (of byte classes `text_mask`).
    #[allow(clippy::too_many_arguments)]
    fn tests(
        &mut self,
        c: &Compiled,
        g: &Plan,
        text: &str,
        text_mask: u16,
        chains: u64,
        name: Option<&str>,
        input: &Input<'_>,
        fixed: &Fixed<'_>,
        tmp: &mut String,
        tested: &mut Vec<u32>,
        log_matched: usize,
    ) {
        if !g.has_tests {
            return;
        }
        // A per-value test of a lowercasing chain in a case-insensitive plan gets the text
        // lowercased after all (its sets and lengths are of lowercase text).
        let mut lowered = false;
        for (i, chain) in g.chains.iter().enumerate() {
            if chains & (1 << i) == 0 || chain.per_value.is_empty() {
                continue;
            }
            let text: &str = if g.case_insensitive && chain.lowers && text_mask & (UPPER | NON_ASCII) != 0 {
                if !lowered {
                    tmp.clear();
                    lowercase(text, tmp);
                    lowered = true;
                }
                tmp
            } else {
                text
            };
            for &rule in &chain.per_value {
                if self.is_matched(rule) {
                    continue;
                }
                if let Some(range) = test_value(&c.rules[rule as usize].matcher, text) {
                    self.candidate(
                        c,
                        rule,
                        &g.target,
                        text,
                        Found::Tested(range),
                        name,
                        input,
                        fixed,
                        tested,
                        log_matched,
                    );
                    if self.stopped() {
                        return;
                    }
                }
            }
        }
    }

    /// The automaton once over the plan's clean values, gathered with a separator no pattern
    /// has: a hit is placed in its value, whose name is found again by walking to it (hits are
    /// rare; the walk is not).
    #[allow(clippy::too_many_arguments)]
    fn run_concat(
        &mut self,
        c: &Compiled,
        g: &Plan,
        input: &Input<'_>,
        fixed: &Fixed<'_>,
        scratch: &mut Scratch<'_>,
        anomalies: Anomalies,
        log_matched: usize,
    ) {
        let Some(automaton) = &g.automaton else { return };
        let Scratch {
            concat,
            segments,
            tested,
            name_buf,
            ..
        } = &mut *scratch;
        let all = (1u64 << g.chains.len()) - 1;
        let mut current: Option<u32> = None;
        for found in automaton.find_overlapping_iter(concat.as_str()) {
            let at = segments.partition_point(|s| (s.end as usize) < found.start());
            let segment = segments[at];
            let value = &concat[segment.start as usize..segment.end as usize];
            let range = found.start() - segment.start as usize..found.end() - segment.start as usize;
            if current != Some(segment.index) {
                current = Some(segment.index);
                tested.clear();
                name_buf.clear();
                let mut k = segment.index;
                for_each_value(input, fixed, g, anomalies, &mut |name, _| {
                    if k == 0 {
                        name_buf.push_str(name.unwrap_or(""));
                        name_buf.push('\0');
                        return false;
                    }
                    k -= 1;
                    true
                });
            }
            let name = name_buf.strip_suffix('\0');
            for &(chain, rule) in &g.pattern_rules[found.pattern().as_usize()] {
                if all & (1 << chain) != 0 {
                    self.candidate(
                        c,
                        rule,
                        &g.target,
                        value,
                        Found::Hit(range.clone()),
                        name,
                        input,
                        fixed,
                        tested,
                        log_matched,
                    );
                    if self.stopped() {
                        return;
                    }
                }
            }
        }
    }

    /// A rule whose literal (or test) hit on `text`: checked further and, if it holds, recorded
    /// once per request with its action applied.
    #[allow(clippy::too_many_arguments)]
    fn candidate(
        &mut self,
        c: &Compiled,
        index: u32,
        target: &Target,
        text: &str,
        found: Found,
        name: Option<&str>,
        input: &Input<'_>,
        fixed: &Fixed<'_>,
        tested: &mut Vec<u32>,
        log_matched: usize,
    ) {
        if self.is_matched(index) {
            return;
        }
        let rule = &c.rules[index as usize];
        if !rule.when.iter().all(|&w| self.is_matched(w)) || rule.unless.iter().any(|&u| self.is_matched(u)) {
            return;
        }
        let range = match (&rule.matcher, found) {
            // A prefilter literal was found: the regex decides, once per text however many
            // prefilter hits the text has.
            (Matcher::Regex(regex), Found::Hit(_)) => {
                if tested.contains(&index) {
                    return;
                }
                tested.push(index);
                match regex.find(text) {
                    Some(m) => m.range(),
                    None => return,
                }
            }
            // The same for libinjection's detectors, which decide on the whole text.
            (Matcher::DetectSqli | Matcher::DetectXss, Found::Hit(_)) => {
                if tested.contains(&index) {
                    return;
                }
                tested.push(index);
                if test_value(&rule.matcher, text).is_none() {
                    return;
                }
                0..text.len()
            }
            (_, Found::Hit(range) | Found::Tested(range)) => range,
            (_, Found::Whole) => 0..0,
        };
        if self.excluded(c, rule, target, name, fixed) {
            return;
        }
        self.set_matched(index, c.rules.len());
        let source = HitSource::of_target(
            target,
            name,
            text,
            range.clone(),
            input.parts,
            input.body.and_then(|b| b.json.as_ref()),
        );
        let matched = if matches!(rule.matcher, Matcher::DetectSqli) && log_matched > 0 {
            // libinjection's fingerprint before the value (`[s&sos] 1' or '1'='1`): what it saw.
            // Found again here, on a hit only.
            let fingerprint = super::detect::sqli(text);
            let shown = format!("[{}] {text}", fingerprint.as_ref().map_or("", |f| f.as_str()));
            cut(&shown, log_matched).to_string()
        } else {
            cut(text.get(range).unwrap_or(""), log_matched).to_string()
        };
        self.hits.push(Hit {
            rule: index,
            engine: None,
            score: 0,
            data: None,
            target: target.to_string(),
            matched,
            source,
            data_source: HitSource::Payload,
        });
        if rule.action == Action::Header {
            self.header_rules.push(index);
        }
        self.count(rule.action, rule.mode, rule.score);
    }

    fn excluded(
        &mut self,
        c: &Compiled,
        rule: &CompiledRule,
        target: &Target,
        name: Option<&str>,
        fixed: &Fixed<'_>,
    ) -> bool {
        if c.exclusions.is_empty() {
            return false;
        }
        let active = self
            .active_exclusions
            .get_or_insert_with(|| active_exclusions(c, fixed));
        active.iter().any(|&e| {
            rule.excluded_by.contains(&e)
                || c.exclusions[e as usize]
                    .targets
                    .iter()
                    .any(|excluded| excluded == target || names_value(excluded, target, name))
        })
    }
}

/// The exclusions whose host and path apply to the request.
fn active_exclusions(c: &Compiled, fixed: &Fixed<'_>) -> Vec<u32> {
    c.exclusions
        .iter()
        .enumerate()
        .filter(|(_, e)| e.applies(fixed.host, fixed.match_path))
        .map(|(i, _)| i as u32)
        .collect()
}

/// An exclusion of `args.q` also covers a hit of a rule on `args` (or `args_names`) at the
/// parameter `q`; the same for headers and cookies.
fn names_value(excluded: &Target, target: &Target, name: Option<&str>) -> bool {
    let Some(name) = name else { return false };
    match (excluded, target) {
        (Target::Arg(n), Target::Args | Target::ArgsNames) => {
            *n == percent_encoding::percent_decode_str(name).decode_utf8_lossy()
        }
        (Target::Header(n), Target::Headers | Target::HeadersNames) => n.eq_ignore_ascii_case(name),
        (Target::Cookie(n), Target::Cookies | Target::CookiesNames) => n == name,
        _ => false,
    }
}

fn magic_name(magic: Magic) -> &'static str {
    match magic {
        Magic::Png => "png",
        Magic::Jpeg => "jpeg",
        Magic::Gif => "gif",
        Magic::Webp => "webp",
        Magic::Pdf => "pdf",
        Magic::Zip => "zip",
        Magic::Gzip => "gzip",
        Magic::Bmp => "bmp",
        Magic::Ico => "ico",
        Magic::Svg => "svg",
        Magic::Php => "php",
        Magic::Script => "script",
    }
}

/// `text` cut to at most `max` bytes, on a character boundary.
pub fn cut(text: &str, max: usize) -> &str {
    if text.len() <= max {
        return text;
    }
    let mut end = max;
    while !text.is_char_boundary(end) {
        end -= 1;
    }
    &text[..end]
}

/// A per-value test of a rule's matcher: the matched range when it holds.
fn test_value(matcher: &Matcher, text: &str) -> Option<Range<usize>> {
    let whole = || Some(0..text.len());
    match matcher {
        Matcher::Regex(regex) => regex.find(text).map(|m| m.range()),
        Matcher::EqualsAny(set) => set.contains(text).then(whole).flatten(),
        Matcher::StartsWithAny(list) => list.iter().find(|p| text.starts_with(p.as_str())).map(|p| 0..p.len()),
        Matcher::EndsWithAny(list) => list
            .iter()
            .find(|s| text.ends_with(s.as_str()))
            .map(|s| text.len() - s.len()..text.len()),
        Matcher::Compare(Measure::Length, cmp, n) => cmp
            .holds(i64::try_from(text.len()).unwrap_or(i64::MAX), *n)
            .then(whole)
            .flatten(),
        Matcher::InSet(set) => set.contains(text).then(whole).flatten(),
        Matcher::IpIn(set) => text
            .trim()
            .parse::<IpAddr>()
            .ok()
            .is_some_and(|ip| set.contains(ip))
            .then(whole)
            .flatten(),
        Matcher::CountryIn(codes) => {
            let bytes = text.as_bytes();
            (bytes.len() == 2 && codes.contains(&[bytes[0].to_ascii_uppercase(), bytes[1].to_ascii_uppercase()]))
                .then(whole)
                .flatten()
        }
        Matcher::AsnIn(numbers) => super::rule::parse_asn(text)
            .is_ok_and(|n| numbers.contains(&n))
            .then(whole)
            .flatten(),
        Matcher::DetectSqli => super::detect::sqli(text).and(whole()),
        Matcher::DetectXss => super::detect::xss(text).then(whole).flatten(),
        _ => None,
    }
}

/// The number a numeric target is.
fn numeric(input: &Input<'_>, fixed: &Fixed<'_>, target: &Target) -> Option<i64> {
    match target {
        Target::ArgsCount => Some((fixed.query_pairs.len() + input.body.map_or(0, BodyData::form_len)) as i64),
        Target::UploadCount => input
            .body
            .map(|b| b.parts.iter().filter(|p| p.filename.is_some()).count() as i64),
        Target::ResponseStatus => input.response.as_ref().map(|r| i64::from(r.status)),
        Target::Asn => Some(input.asn.map_or(0, i64::from)),
        _ => None,
    }
}

/// Whether the target's raw bytes are not UTF-8 (percent-escapes decoded first).
fn invalid_utf8(input: &Input<'_>, target: &Target, bytes: &mut Vec<u8>) -> bool {
    let mut decoded_invalid = |text: &str, plus: bool| {
        if !text.contains('%') {
            return false;
        }
        bytes.clear();
        percent_decode_into(text, bytes, plus);
        std::str::from_utf8(bytes).is_err()
    };
    match target {
        Target::Headers => input.parts.headers.values().any(|v| v.to_str().is_err()),
        Target::Header(name) => input
            .parts
            .headers
            .get_all(name.as_str())
            .iter()
            .any(|v| v.to_str().is_err()),
        Target::PathRaw | Target::Path => decoded_invalid(input.parts.uri.path(), false),
        Target::Query => decoded_invalid(input.parts.uri.query().unwrap_or(""), true),
        Target::Body => input.body.is_some_and(|b| !b.valid_utf8),
        _ => false,
    }
}

/// `n` written on the stack, for the targets that are numbers.
fn with_text<R>(value: impl std::fmt::Display, f: impl FnOnce(&str) -> R) -> R {
    let mut buffer = [0u8; 64];
    let mut cursor = std::io::Cursor::new(&mut buffer[..]);
    let _ = write!(cursor, "{value}");
    let len = cursor.position() as usize;
    f(std::str::from_utf8(&buffer[..len]).unwrap_or(""))
}

/// The `name=value` pairs of a query string or form body as sent (undecoded); a pair without
/// `=` has an empty value.
pub(super) fn query_pairs(query: &str) -> impl Iterator<Item = (&str, &str)> {
    query
        .split('&')
        .filter(|p| !p.is_empty())
        // No `=`: the value is the empty slice at the pair's end, a range of the text as the
        // name is (`prepare` keeps both as ranges of it).
        .map(|p| p.split_once('=').unwrap_or((p, &p[p.len()..])))
}

/// The cookies of one or more Cookie header values joined by `;`: `name` and `value` (quotes
/// stripped).
fn cookie_pairs_of(text: &str) -> impl Iterator<Item = (&str, &str)> {
    text.split(';').filter_map(|pair| {
        let pair = pair.trim();
        if pair.is_empty() {
            return None;
        }
        // No `=`: an empty value at the pair's end, a range of `text` (see `query_pairs`).
        let (name, value) = pair.split_once('=').unwrap_or((pair, &pair[pair.len()..]));
        Some((name.trim(), value.trim().trim_matches('"')))
    })
}

/// The cookies of the request, `name` and `value` (quotes stripped).
#[cfg(test)]
pub(super) fn cookie_pairs(headers: &HeaderMap) -> impl Iterator<Item = (&str, &str)> {
    headers
        .get_all(http::header::COOKIE)
        .iter()
        .filter_map(|v| v.to_str().ok())
        .flat_map(cookie_pairs_of)
}

/// Every string of a JSON value, depth first.
fn json_strings(value: &serde_json::Value, f: &mut dyn FnMut(Option<&str>, &str) -> bool) -> bool {
    match value {
        serde_json::Value::String(s) => f(None, s),
        serde_json::Value::Array(items) => items.iter().all(|v| json_strings(v, f)),
        serde_json::Value::Object(map) => map.iter().all(|(k, v)| f(None, k) && json_strings(v, f)),
        _ => true,
    }
}

/// The suffixes of a file name after each dot, and each inner segment: `a.php.jpg` gives
/// `php.jpg`, `jpg` and `php`.
fn extensions(filename: &str, f: &mut dyn FnMut(Option<&str>, &str) -> bool) -> bool {
    let name = filename.rsplit(['/', '\\']).next().unwrap_or(filename);
    let dots: Vec<usize> = name.match_indices('.').map(|(i, _)| i).collect();
    for &dot in &dots {
        if !f(None, &name[dot + 1..]) {
            return false;
        }
    }
    for pair in dots.windows(2) {
        if !f(None, &name[pair[0] + 1..pair[1]]) {
            return false;
        }
    }
    true
}

/// Calls `f` with each value of the plan's target (with the parameter's or header's name where
/// there is one) until it returns `false`; how many values were visited. In the body phase the
/// `args` targets are the form's pairs (and the query's again only when the plan wants it).
fn for_each_value(
    input: &Input<'_>,
    fixed: &Fixed<'_>,
    plan: &Plan,
    anomalies: Anomalies,
    f: &mut dyn FnMut(Option<&str>, &str) -> bool,
) -> usize {
    let parts = input.parts;
    let mut count = 0;
    // Each value counted, `f` asked whether to go on.
    let mut each = |name: Option<&str>, value: &str| -> bool {
        count += 1;
        f(name, value)
    };
    let in_body = plan.phase == Phase::Body || plan.phase == Phase::Upload;
    let with_query = !in_body || plan.wants_query;
    let form = input.body.filter(|_| in_body);
    let form_pairs = || form.into_iter().flat_map(BodyData::form);
    let query_pairs = || fixed.query_pairs().filter(|_| with_query);
    match &plan.target {
        Target::Method => {
            each(None, parts.method.as_str());
        }
        Target::Version => {
            each(
                None,
                match parts.version {
                    http::Version::HTTP_09 => "0.9",
                    http::Version::HTTP_10 => "1.0",
                    http::Version::HTTP_11 => "1.1",
                    http::Version::HTTP_2 => "2",
                    _ => "3",
                },
            );
        }
        Target::Path => {
            each(None, fixed.path);
        }
        Target::PathRaw => {
            each(None, parts.uri.path());
        }
        Target::Query => {
            if let Some(query) = parts.uri.query() {
                each(None, query);
            }
        }
        Target::Args => {
            for (name, value) in query_pairs().chain(form_pairs()) {
                if !each(Some(name), value) {
                    return count;
                }
            }
        }
        Target::ArgsNames => {
            for (name, _) in query_pairs().chain(form_pairs()) {
                if !each(Some(name), name) {
                    return count;
                }
            }
        }
        Target::Arg(wanted) => {
            // The query's names are as sent: decoded only when they have an escape.
            for (name, value) in query_pairs() {
                let named = wanted == name
                    || (name.contains(['%', '+'])
                        && *wanted == percent_encoding::percent_decode_str(name).decode_utf8_lossy());
                if named && !each(Some(name), value) {
                    return count;
                }
            }
            for (name, value) in form_pairs() {
                if wanted == name && !each(Some(name), value) {
                    return count;
                }
            }
        }
        Target::ArgsCount => {
            let n = fixed.query_pairs.len() + form.map_or(0, BodyData::form_len);
            with_text(n, |text| each(None, text));
        }
        Target::Headers => {
            for (name, value) in parts.headers.iter() {
                if let Ok(value) = value.to_str()
                    && !each(Some(name.as_str()), value)
                {
                    return count;
                }
            }
        }
        Target::HeadersNames => {
            for name in parts.headers.keys() {
                if !each(Some(name.as_str()), name.as_str()) {
                    return count;
                }
            }
        }
        Target::Header(name) => {
            for value in parts.headers.get_all(name.as_str()) {
                if let Ok(value) = value.to_str()
                    && !each(Some(name), value)
                {
                    return count;
                }
            }
        }
        Target::Cookies => {
            for (name, value) in fixed.cookies() {
                if !each(Some(name), value) {
                    return count;
                }
            }
        }
        Target::CookiesNames => {
            for (name, _) in fixed.cookies() {
                if !each(Some(name), name) {
                    return count;
                }
            }
        }
        Target::Cookie(wanted) => {
            for (name, value) in fixed.cookies() {
                if name == wanted && !each(Some(name), value) {
                    return count;
                }
            }
        }
        Target::Ua => {
            if let Some(ua) = parts
                .headers
                .get(http::header::USER_AGENT)
                .and_then(|v| v.to_str().ok())
            {
                each(None, ua);
            }
        }
        Target::Host => {
            each(None, fixed.host);
        }
        Target::ClientIp => {
            with_text(input.client_ip, |text| each(None, text));
        }
        Target::Country => match input.country {
            Some(code) => {
                each(None, std::str::from_utf8(&code).unwrap_or("--"));
            }
            None => {
                each(None, "--");
            }
        },
        Target::Asn => {
            with_text(input.asn.unwrap_or(0), |text| each(None, text));
        }
        Target::Body => {
            if let Some(text) = input.body.and_then(BodyData::text) {
                each(None, text);
            }
        }
        Target::BodyJson => {
            if let Some(json) = input.body.and_then(|b| b.json.as_ref()) {
                json_strings(json, &mut each);
            }
        }
        Target::BodyJsonPointer(pointer) => {
            if let Some(value) = input
                .body
                .and_then(|b| b.json.as_ref())
                .and_then(|j| j.pointer(pointer))
            {
                match value {
                    serde_json::Value::String(s) => {
                        each(None, s);
                    }
                    serde_json::Value::Number(n) => {
                        with_text(n, |text| each(None, text));
                    }
                    serde_json::Value::Bool(b) => {
                        each(None, if *b { "true" } else { "false" });
                    }
                    other => {
                        json_strings(other, &mut each);
                    }
                }
            }
        }
        Target::UploadFilename => {
            for part in input.body.map(|b| b.parts.as_slice()).unwrap_or(&[]) {
                if let Some(filename) = &part.filename
                    && !each(Some(&part.name), filename)
                {
                    return count;
                }
            }
        }
        Target::UploadExt => {
            for part in input.body.map(|b| b.parts.as_slice()).unwrap_or(&[]) {
                if let Some(filename) = &part.filename
                    && !extensions(filename, &mut each)
                {
                    return count;
                }
            }
        }
        Target::UploadType => {
            for part in input.body.map(|b| b.parts.as_slice()).unwrap_or(&[]) {
                if part.filename.is_some()
                    && let Some(content_type) = &part.content_type
                    && !each(Some(&part.name), content_type)
                {
                    return count;
                }
            }
        }
        Target::UploadHead => {
            for part in input.body.map(|b| b.parts.as_slice()).unwrap_or(&[]) {
                if part.filename.is_some() {
                    // As text only for rules that read it; the magic rules read the bytes.
                    let head = if plan.chains.is_empty() {
                        std::borrow::Cow::Borrowed("")
                    } else {
                        String::from_utf8_lossy(&part.head)
                    };
                    if !each(Some(&part.name), &head) {
                        return count;
                    }
                }
            }
        }
        Target::UploadCount => {
            let n = input
                .body
                .map_or(0, |b| b.parts.iter().filter(|p| p.filename.is_some()).count());
            with_text(n, |text| each(None, text));
        }
        Target::TlsSni => {
            each(None, input.sni.unwrap_or("-"));
        }
        // No value without a fingerprint: absence matches nothing (but `missing`).
        Target::TlsJa4 => {
            if let Some(ja4) = &input.ja4 {
                each(None, ja4.as_str());
            }
        }
        Target::ResponseStatus => {
            if let Some(response) = &input.response {
                with_text(response.status, |text| each(None, text));
            }
        }
        Target::ResponseHeader(name) => {
            if let Some(response) = &input.response {
                for value in response.headers.get_all(name.as_str()) {
                    if let Ok(value) = value.to_str()
                        && !each(Some(name), value)
                    {
                        return count;
                    }
                }
            }
        }
        Target::ResponseBody => {
            if let Some(response) = &input.response {
                each(None, response.body);
            }
        }
        Target::AnomalyDoubleEncoding => {
            if anomalies.double_encoding {
                each(None, "1");
            }
        }
        Target::AnomalyJsonDepth => {
            if anomalies.json_too_deep {
                each(None, "1");
            }
        }
        Target::AnomalyDuplicateContentLength => {
            let lengths = parts.headers.get_all(http::header::CONTENT_LENGTH).iter().count();
            if lengths > 1 || (lengths == 1 && parts.headers.contains_key(http::header::TRANSFER_ENCODING)) {
                each(None, "1");
            }
        }
        Target::AnomalyHttp10WithoutHost => {
            if parts.version == http::Version::HTTP_10 && hostport_of(parts).is_empty() {
                each(None, "1");
            }
        }
        Target::AnomalyPostWithoutContentType => {
            let with_body = parts.headers.contains_key(http::header::TRANSFER_ENCODING)
                || parts
                    .headers
                    .get(http::header::CONTENT_LENGTH)
                    .and_then(|v| v.to_str().ok())
                    .is_some_and(|v| v.trim() != "0");
            if matches!(
                parts.method,
                http::Method::POST | http::Method::PUT | http::Method::PATCH
            ) && with_body
                && !parts.headers.contains_key(http::header::CONTENT_TYPE)
            {
                each(None, "1");
            }
        }
        Target::AnomalyBodyTypeMismatch => {
            if input.body.is_some_and(|b| b.json_invalid) {
                each(None, "1");
            }
        }
        Target::AnomalyTlsUaMismatch => {
            if input.ja4.is_some_and(|ja4| tls_ua_mismatch(parts, &ja4)) {
                each(None, "1");
            }
        }
    }
    count
}

/// Whether the User-Agent claims a current browser — Chrome, Edge and the other Chromium ones,
/// Firefox, Safari, at versions years past their TLS 1.3 — that would not have sent this
/// ClientHello: every such browser offers TLS 1.3, sends SNI for a host that is a name, and
/// offers `h2` first in ALPN. A bot's or crawler's UA, an older version, or none claims nothing.
pub(crate) fn tls_ua_mismatch(parts: &http::request::Parts, ja4: &webfast_core::ja4::Ja4) -> bool {
    let Some(ua) = parts
        .headers
        .get(http::header::USER_AGENT)
        .and_then(|v| v.to_str().ok())
    else {
        return false;
    };
    if !claims_current_browser(ua) {
        return false;
    }
    let a = ja4.a().as_bytes();
    let tls13 = &a[1..3] == b"13";
    let h2 = &a[8..10] == b"h2";
    let sni = a[3] == b'd';
    !tls13 || !h2 || (!sni && !host_is_address(parts))
}

/// The major version after `marker` in `ua` (`Chrome/131.0…` → 131).
fn major_after(ua: &str, marker: &str) -> Option<u32> {
    let at = ua.find(marker)? + marker.len();
    let digits: &str = &ua[at..][..ua[at..].bytes().take_while(u8::is_ascii_digit).count()];
    digits.parse().ok()
}

/// A User-Agent of a current browser, as browsers write theirs.
fn claims_current_browser(ua: &str) -> bool {
    if !ua.starts_with("Mozilla/5.0 (") {
        return false;
    }
    let lower_has = |words: &[&str]| {
        words.iter().any(|w| {
            ua.as_bytes()
                .windows(w.len())
                .any(|win| win.eq_ignore_ascii_case(w.as_bytes()))
        })
    };
    if lower_has(&["bot", "crawl", "spider", "slurp", "preview", "headless"]) {
        return false;
    }
    // Chromium (Chrome, Edge, Opera, Brave …) and Chrome on iOS; Firefox, on iOS too; Safari.
    let recent = |marker: &str, from: u32| major_after(ua, marker).is_some_and(|v| v >= from);
    if recent("Chrome/", 90) || recent("CriOS/", 90) || recent("Firefox/", 90) || recent("FxiOS/", 90) {
        return true;
    }
    ua.contains("Safari/") && !ua.contains("Chrome/") && !ua.contains("Chromium/") && recent("Version/", 15)
}

/// The request's host is an address (`203.0.113.7`, `[2001:db8::1]`), for which no client sends
/// SNI.
fn host_is_address(parts: &http::request::Parts) -> bool {
    let host = parts
        .uri
        .host()
        .or_else(|| parts.headers.get(http::header::HOST).and_then(|v| v.to_str().ok()))
        .unwrap_or("");
    let host = host.trim_start_matches('[');
    let host = host.split(']').next().unwrap_or(host);
    let host = if host.matches(':').count() == 1 {
        host.split(':').next().unwrap_or(host)
    } else {
        host
    };
    host.parse::<IpAddr>().is_ok()
}

// The transformations.

// The byte classes of a text (`classify`): a transformation whose classes are absent changes
// nothing and is skipped, so a clean value is searched where it is, without a copy.
/// `%`: url_decode.
const PERCENT: u16 = 1 << 0;
/// `&`: html_decode.
const AMP: u16 = 1 << 1;
/// `\`: js_decode, cmd_line, normalize_path.
const BACKSLASH: u16 = 1 << 2;
/// `A`–`Z`: lowercase.
const UPPER: u16 = 1 << 3;
/// A byte over 127: lowercase, compress_whitespace (Unicode spaces), utf8_to_unicode.
const NON_ASCII: u16 = 1 << 4;
/// A null: remove_nulls.
const NUL: u16 = 1 << 5;
/// Any ASCII whitespace: cmd_line.
const WS: u16 = 1 << 6;
/// Whitespace that is not a single space between others: compress_whitespace. The bit above
/// `WS`, so a run is `WS` of two bytes in a row shifted up (`classify`).
const WS_RUN: u16 = WS << 1;
/// `"`, `'`, `^`: cmd_line.
const QUOTE: u16 = 1 << 8;
/// `/*`, `--` or `#`: remove_comments.
const COMMENT: u16 = 1 << 9;
/// `//`, `/.` or a leading `.`: normalize_path.
const DOT_SEGMENT: u16 = 1 << 10;
// The bytes the digraphs above are made of, looked for only when they are there at all.
const SLASH: u16 = 1 << 11;
const DASH: u16 = 1 << 12;
const DOT: u16 = 1 << 13;

/// The classes of one byte, on its own.
static BYTE_CLASSES: [u16; 256] = {
    let mut table = [0u16; 256];
    let mut b = 0;
    while b < 256 {
        table[b] = match b as u8 {
            b'%' => PERCENT,
            b'&' => AMP,
            b'\\' => BACKSLASH,
            b'A'..=b'Z' => UPPER,
            0 => NUL,
            b' ' => WS,
            b'\t' | b'\n' | b'\r' | 0x0b | 0x0c => WS | WS_RUN,
            b'"' | b'\'' | b'^' => QUOTE,
            b'#' => COMMENT,
            b'/' => SLASH,
            b'-' => DASH,
            b'.' => DOT,
            128..=255 => NON_ASCII,
            _ => 0,
        };
        b += 1;
    }
    table
};

/// Every class: `needs_of` for a chain whose effect the classes do not tell (`base64_decode`).
const ANY: u16 = u16::MAX;

/// The byte classes present in `text`, among `wanted` (the classes some transformation of the
/// plan's chains needs; the two-byte ones are looked for only when wanted and their bytes are
/// there). `ANY` wants them all.
fn classify(text: &str, wanted: u16) -> u16 {
    if wanted == 0 {
        return 0;
    }
    let bytes = text.as_bytes();
    let mut mask = 0u16;
    let mut prev = 0u16;
    for &b in bytes {
        let class = BYTE_CLASSES[b as usize];
        // Two whitespace bytes in a row: `WS_RUN` is the bit above `WS`.
        mask |= class | ((class & prev & WS) << 1);
        prev = class;
    }
    let want_comment = wanted & COMMENT != 0 && mask & (SLASH | DASH) != 0;
    let want_dot = wanted & DOT_SEGMENT != 0 && mask & (SLASH | DOT) != 0;
    if want_comment || want_dot {
        if want_dot && bytes[0] == b'.' {
            mask |= DOT_SEGMENT;
        }
        for w in bytes.windows(2) {
            let (a, b) = (w[0], w[1]);
            match a {
                b'/' if want_comment && b == b'*' => mask |= COMMENT,
                b'/' if want_dot && (b == b'/' || b == b'.') => mask |= DOT_SEGMENT,
                b'-' if want_comment && b == b'-' => mask |= COMMENT,
                _ => {}
            }
        }
    }
    mask
}

/// The byte classes a transformation needs to change a text; `ANY` when the classes do not tell.
fn needs(transform: Transform) -> u16 {
    match transform {
        Transform::UrlDecode => PERCENT,
        Transform::HtmlDecode => AMP,
        Transform::Lowercase => UPPER | NON_ASCII,
        Transform::NormalizePath => BACKSLASH | DOT_SEGMENT,
        Transform::RemoveNulls => NUL,
        Transform::CompressWhitespace => WS_RUN | NON_ASCII,
        Transform::RemoveComments => COMMENT,
        // Decided by the text as a whole.
        Transform::Base64Decode => ANY,
        Transform::JsDecode => BACKSLASH,
        Transform::CmdLine => WS | QUOTE | BACKSLASH,
        Transform::Utf8ToUnicode => NON_ASCII,
    }
}

/// The byte classes a chain needs to change a text at all (compile.rs); `keep_case`: its
/// `lowercase` is left to the automaton.
pub(super) fn needs_of(chain: &[Transform], keep_case: bool) -> u16 {
    chain
        .iter()
        .filter(|&&t| !(keep_case && t == Transform::Lowercase))
        .fold(0, |mask, &t| mask | needs(t))
}

/// Whether `transform` can change a text with these byte classes.
fn may_change(transform: Transform, mask: u16) -> bool {
    let needs = needs(transform);
    needs == ANY || mask & needs != 0
}

/// `value` (of byte classes `mask`) through `chain`: `true` when a transformation was applied
/// and the result is in `out`; `false` when none could change it and `value` itself is the text.
/// `keep_case`: `lowercase` is left out (the automaton matches either case).
#[allow(clippy::too_many_arguments)]
fn run_chain(
    chain: &[Transform],
    value: &str,
    mask: u16,
    keep_case: bool,
    out: &mut String,
    tmp: &mut String,
    bytes: &mut Vec<u8>,
    bytes2: &mut Vec<u8>,
    double: &mut bool,
) -> bool {
    // Where the current text is.
    enum At {
        Value,
        Out,
        Tmp,
    }
    let mut at = At::Value;
    let mut mask = mask;
    for &transform in chain {
        if (keep_case && transform == Transform::Lowercase) || !may_change(transform, mask) {
            continue;
        }
        match at {
            At::Value => {
                out.clear();
                apply(transform, value, out, bytes, bytes2, double);
                at = At::Out;
            }
            At::Out => {
                tmp.clear();
                apply(transform, out, tmp, bytes, bytes2, double);
                at = At::Tmp;
            }
            At::Tmp => {
                out.clear();
                apply(transform, tmp, out, bytes, bytes2, double);
                at = At::Out;
            }
        }
        mask = classify(
            match at {
                At::Out => out,
                _ => tmp,
            },
            ANY,
        );
    }
    match at {
        At::Value => false,
        At::Out => true,
        At::Tmp => {
            std::mem::swap(out, tmp);
            true
        }
    }
}

/// One transformation of `input` into `out` (empty on entry).
pub(super) fn apply(
    transform: Transform,
    input: &str,
    out: &mut String,
    bytes: &mut Vec<u8>,
    bytes2: &mut Vec<u8>,
    double: &mut bool,
) {
    match transform {
        Transform::UrlDecode => url_decode(input, out, bytes, bytes2, double),
        Transform::HtmlDecode => html_decode(input, out),
        Transform::Lowercase => lowercase(input, out),
        Transform::NormalizePath => normalize_path(input, out),
        Transform::RemoveNulls => out.extend(input.chars().filter(|&c| c != '\0')),
        Transform::CompressWhitespace => compress_whitespace(input, out),
        Transform::RemoveComments => remove_comments(input, out),
        Transform::Base64Decode => {
            bytes.clear();
            if base64_decode(input, bytes) {
                push_lossy(bytes, out);
            } else {
                out.push_str(input);
            }
        }
        Transform::JsDecode => js_decode(input, out),
        Transform::CmdLine => cmd_line(input, out),
        Transform::Utf8ToUnicode => {
            for c in input.chars() {
                if c.is_ascii() {
                    out.push(c);
                } else {
                    let _ = std::fmt::Write::write_fmt(out, format_args!("%u{:04x}", c as u32));
                }
            }
        }
    }
}

fn hex(b: u8) -> Option<u8> {
    (b as char).to_digit(16).map(|d| d as u8)
}

/// Percent-escapes (and `+` as a space when `plus`) decoded into `bytes` (appended); whether
/// any escape was decoded.
fn percent_decode_into(text: &str, bytes: &mut Vec<u8>, plus: bool) -> bool {
    let input = text.as_bytes();
    let mut any = false;
    let mut i = 0;
    while i < input.len() {
        match input[i] {
            b'%' if i + 2 < input.len() => match (hex(input[i + 1]), hex(input[i + 2])) {
                (Some(hi), Some(lo)) => {
                    bytes.push(hi * 16 + lo);
                    any = true;
                    i += 3;
                }
                _ => {
                    bytes.push(b'%');
                    i += 1;
                }
            },
            b'+' if plus => {
                bytes.push(b' ');
                any = true;
                i += 1;
            }
            b => {
                bytes.push(b);
                i += 1;
            }
        }
    }
    any
}

/// Whether `bytes` still has a percent-escape.
fn has_escape(bytes: &[u8]) -> bool {
    bytes
        .windows(3)
        .any(|w| w[0] == b'%' && hex(w[1]).is_some() && hex(w[2]).is_some())
}

/// `bytes` as text, invalid sequences as U+FFFD, appended to `out` without allocating.
fn push_lossy(bytes: &[u8], out: &mut String) {
    for chunk in bytes.utf8_chunks() {
        out.push_str(chunk.valid());
        if !chunk.invalid().is_empty() {
            out.push(char::REPLACEMENT_CHARACTER);
        }
    }
}

/// Percent-escapes (`+` stays: a form body's are turned into spaces when it is parsed); a second
/// pass when the result still has escapes (noted in `double`, the `anomaly.double_encoding`
/// target).
fn url_decode(input: &str, out: &mut String, bytes: &mut Vec<u8>, bytes2: &mut Vec<u8>, double: &mut bool) {
    bytes.clear();
    percent_decode_into(input, bytes, false);
    if has_escape(bytes) {
        *double = true;
        bytes2.clear();
        // The first pass gave bytes, perhaps not UTF-8: decoded again as bytes.
        let mut i = 0;
        while i < bytes.len() {
            if bytes[i] == b'%'
                && i + 2 < bytes.len()
                && let (Some(hi), Some(lo)) = (hex(bytes[i + 1]), hex(bytes[i + 2]))
            {
                bytes2.push(hi * 16 + lo);
                i += 3;
            } else {
                bytes2.push(bytes[i]);
                i += 1;
            }
        }
        push_lossy(bytes2, out);
    } else {
        push_lossy(bytes, out);
    }
}

/// `&amp;`, `&lt;`, `&#NN;`, `&#xHH;` and the common named entities.
fn html_decode(input: &str, out: &mut String) {
    let mut rest = input;
    while let Some(at) = rest.find('&') {
        out.push_str(&rest[..at]);
        let after = &rest[at + 1..];
        let end = after.find(|c: char| !c.is_ascii_alphanumeric() && c != '#');
        let (entity, consumed) = match end {
            Some(end) if after[end..].starts_with(';') => (&after[..end], end + 2),
            // Browsers take `&lt` without the semicolon too.
            Some(end) => (&after[..end], end + 1),
            None => (after, after.len() + 1),
        };
        let decoded = match entity {
            "amp" => Some('&'),
            "lt" => Some('<'),
            "gt" => Some('>'),
            "quot" => Some('"'),
            "apos" => Some('\''),
            "nbsp" => Some(' '),
            "Tab" => Some('\t'),
            "NewLine" => Some('\n'),
            "sol" => Some('/'),
            "bsol" => Some('\\'),
            "lpar" => Some('('),
            "rpar" => Some(')'),
            "colon" => Some(':'),
            "semi" => Some(';'),
            "equals" => Some('='),
            "grave" => Some('`'),
            "num" => Some('#'),
            "percnt" => Some('%'),
            "lbrace" => Some('{'),
            "rbrace" => Some('}'),
            "lsqb" => Some('['),
            "rsqb" => Some(']'),
            _ => entity
                .strip_prefix('#')
                .and_then(|number| match number.strip_prefix(['x', 'X']) {
                    Some(hexadecimal) => u32::from_str_radix(hexadecimal, 16).ok(),
                    None => number.parse().ok(),
                })
                .and_then(char::from_u32),
        };
        match decoded {
            Some(c) if !entity.is_empty() => {
                out.push(c);
                rest = &after[consumed - 1..];
            }
            _ => {
                out.push('&');
                rest = after;
            }
        }
    }
    out.push_str(rest);
}

/// `.` and `..` segments resolved (`..` above the start stays, as the CRS does), repeated slashes
/// merged, backslashes as slashes.
fn normalize_path(input: &str, out: &mut String) {
    let leading = input.starts_with(['/', '\\']);
    let trailing = input.ends_with(['/', '\\']);
    for segment in input.split(['/', '\\']) {
        match segment {
            "" | "." => {}
            ".." => {
                let last_start = out.rfind('/').map_or(0, |i| i + 1);
                let last = &out[last_start..];
                if out.is_empty() || last == ".." {
                    if !out.is_empty() || leading {
                        out.push('/');
                    }
                    out.push_str("..");
                } else {
                    out.truncate(last_start.saturating_sub(1));
                    if out.is_empty() && leading && last_start > 0 {
                        // `/a/..` is the root, not an empty path.
                    }
                }
            }
            segment => {
                if !out.is_empty() || leading {
                    out.push('/');
                }
                out.push_str(segment);
            }
        }
    }
    if out.is_empty() {
        if leading {
            out.push('/');
        }
    } else if trailing && !out.ends_with('/') {
        out.push('/');
    }
}

fn compress_whitespace(input: &str, out: &mut String) {
    let mut space = false;
    for c in input.chars() {
        if c.is_whitespace() {
            if !space {
                out.push(' ');
                space = true;
            }
        } else {
            out.push(c);
            space = false;
        }
    }
}

/// `/* */` (unterminated: to the end), `--` and `#` to the line's end.
fn remove_comments(input: &str, out: &mut String) {
    let mut rest = input;
    loop {
        let block = rest.find("/*");
        let line = rest.find("--").into_iter().chain(rest.find('#')).min();
        match (block, line) {
            (Some(b), l) if l.is_none_or(|l| b < l) => {
                out.push_str(&rest[..b]);
                rest = match rest[b + 2..].find("*/") {
                    Some(end) => &rest[b + 2 + end + 2..],
                    None => "",
                };
            }
            (_, Some(l)) => {
                out.push_str(&rest[..l]);
                rest = match rest[l..].find('\n') {
                    Some(end) => &rest[l + end..],
                    None => "",
                };
            }
            (_, None) => break,
        }
    }
    out.push_str(rest);
}

/// `input` as base64 (standard or URL alphabet, padding optional) into `bytes`; `false` when it
/// is not base64 or too short to mean anything (under 8 characters).
fn base64_decode(input: &str, bytes: &mut Vec<u8>) -> bool {
    let text = input.trim_end_matches('=');
    if text.len() < 8 || input.len() % 4 == 1 {
        return false;
    }
    let value = |c: u8| -> Option<u32> {
        Some(match c {
            b'A'..=b'Z' => u32::from(c - b'A'),
            b'a'..=b'z' => u32::from(c - b'a') + 26,
            b'0'..=b'9' => u32::from(c - b'0') + 52,
            b'+' | b'-' => 62,
            b'/' | b'_' => 63,
            _ => return None,
        })
    };
    let mut accumulator: u32 = 0;
    let mut bits = 0;
    for c in text.bytes() {
        let Some(v) = value(c) else { return false };
        accumulator = (accumulator << 6) | v;
        bits += 6;
        if bits >= 8 {
            bits -= 8;
            bytes.push((accumulator >> bits) as u8);
            accumulator &= (1 << bits) - 1;
        }
    }
    true
}

/// `\xNN` and `\uNNNN` (surrogate pairs joined); other escapes stay.
fn js_decode(input: &str, out: &mut String) {
    let bytes = input.as_bytes();
    let mut i = 0;
    let mut pending_high: Option<u32> = None;
    let flush_high = |pending: &mut Option<u32>, out: &mut String| {
        if pending.take().is_some() {
            out.push(char::REPLACEMENT_CHARACTER);
        }
    };
    while i < bytes.len() {
        if bytes[i] == b'\\' && i + 1 < bytes.len() {
            let (digits, skip) = match bytes[i + 1] {
                b'x' => (2, 4),
                b'u' => (4, 6),
                _ => (0, 0),
            };
            if digits > 0
                && i + skip <= bytes.len()
                && let Ok(code) = u32::from_str_radix(&input[i + 2..i + skip], 16)
            {
                i += skip;
                match (pending_high.take(), code) {
                    (Some(high), 0xDC00..=0xDFFF) => {
                        let joined = 0x10000 + ((high - 0xD800) << 10) + (code - 0xDC00);
                        out.push(char::from_u32(joined).unwrap_or(char::REPLACEMENT_CHARACTER));
                    }
                    (high, 0xD800..=0xDBFF) => {
                        if high.is_some() {
                            out.push(char::REPLACEMENT_CHARACTER);
                        }
                        pending_high = Some(code);
                    }
                    (high, code) => {
                        if high.is_some() {
                            out.push(char::REPLACEMENT_CHARACTER);
                        }
                        out.push(char::from_u32(code).unwrap_or(char::REPLACEMENT_CHARACTER));
                    }
                }
                continue;
            }
        }
        flush_high(&mut pending_high, out);
        // The next character whole (it may be several bytes).
        let c = input[i..].chars().next().unwrap_or('\u{FFFD}');
        out.push(c);
        i += c.len_utf8();
    }
    flush_high(&mut pending_high, out);
}

/// Quotes, backslashes and `^` removed; spaces around `,` `;` `|` `&` and before `/` and `(`
/// removed; whitespace runs one space (the CRS `cmdLine` transformation, without its lowercasing).
fn cmd_line(input: &str, out: &mut String) {
    let mut space = false;
    for c in input.chars() {
        match c {
            '"' | '\'' | '\\' | '^' => {}
            c if c.is_whitespace() => space = true,
            ',' | ';' | '|' | '&' | '/' | '(' => {
                space = false;
                out.push(c);
                if matches!(c, ',' | ';' | '|' | '&') {
                    // Spaces after are dropped too: `; ls` is `;ls`.
                    space = false;
                }
            }
            c => {
                if space && !out.is_empty() && !out.ends_with([',', ';', '|', '&']) {
                    out.push(' ');
                }
                space = false;
                out.push(c);
            }
        }
    }
}

#[cfg(test)]
pub(crate) mod tests {
    use super::super::compile::compile;
    use super::super::config::Sourced;
    use super::*;
    use std::path::Path;

    fn run(transform: Transform, input: &str) -> (String, bool) {
        let mut out = String::new();
        let (mut b1, mut b2) = (Vec::new(), Vec::new());
        let mut double = false;
        apply(transform, input, &mut out, &mut b1, &mut b2, &mut double);
        (out, double)
    }

    fn t(transform: Transform, input: &str) -> String {
        run(transform, input).0
    }

    #[test]
    fn each_transformation() {
        assert_eq!(t(Transform::UrlDecode, "a%20b+c%zz%4"), "a b+c%zz%4");
        let (text, double) = run(Transform::UrlDecode, "%252e%252e/");
        assert_eq!((text.as_str(), double), ("../", true));
        assert!(!run(Transform::UrlDecode, "%2e%2e/").1);
        assert_eq!(t(Transform::UrlDecode, "%ff%fe"), "\u{FFFD}\u{FFFD}", "lossy");
        assert_eq!(
            t(Transform::HtmlDecode, "&lt;script&gt; &#60;b&#x3E; &amp;&amp &bogus; &"),
            "<script> <b> && &bogus; &"
        );
        assert_eq!(t(Transform::Lowercase, "ÀbC"), "àbc");
        assert_eq!(t(Transform::NormalizePath, "/a/./b//c/../d\\e"), "/a/b/d/e");
        assert_eq!(t(Transform::NormalizePath, "/a/../../etc/passwd"), "/../etc/passwd");
        assert_eq!(t(Transform::NormalizePath, "../x"), "../x");
        assert_eq!(t(Transform::NormalizePath, "a/b/"), "a/b/");
        assert_eq!(t(Transform::NormalizePath, "/a/.."), "/");
        assert_eq!(t(Transform::RemoveNulls, "a\0b"), "ab");
        assert_eq!(t(Transform::CompressWhitespace, "a  \t b\n\nc"), "a b c");
        assert_eq!(
            t(Transform::RemoveComments, "sel/*x*/ect 1 -- drop\nfrom #c"),
            "select 1 \nfrom "
        );
        assert_eq!(t(Transform::RemoveComments, "a/*unterminated"), "a");
        assert_eq!(t(Transform::Base64Decode, "PD9waHAgZWNobyAxOw=="), "<?php echo 1;");
        assert_eq!(
            t(Transform::Base64Decode, "PD9waHAgZWNobyAxOw"),
            "<?php echo 1;",
            "without padding"
        );
        assert_eq!(t(Transform::Base64Decode, "hello world"), "hello world", "not base64");
        assert_eq!(t(Transform::Base64Decode, "YWJj"), "YWJj", "too short");
        assert_eq!(
            t(Transform::JsDecode, "\\x3cscript\\u003e\\n\\ud83d\\ude00"),
            "<script>\\n\u{1F600}"
        );
        assert_eq!(
            t(Transform::JsDecode, "\\ud83d x"),
            "\u{FFFD} x",
            "a lone high surrogate"
        );
        assert_eq!(
            t(Transform::CmdLine, "c\"a\"t  /etc/passwd ; l^s , id |  whoami"),
            "cat/etc/passwd;ls,id|whoami"
        );
        assert_eq!(
            t(Transform::CmdLine, "wget  http://x -O  /tmp/a"),
            "wget http://x -O/tmp/a"
        );
        assert_eq!(t(Transform::Utf8ToUnicode, "a\u{e9}b\u{1F600}"), "a%u00e9b%u1f600");
    }

    /// A query parameter or a cookie without `=` (`?debug`, `Cookie: flag`) has an empty value
    /// that is a slice of its own text, as `prepare` keeps every pair as a range of that text.
    #[test]
    fn a_pair_without_a_value_is_a_range_of_its_text() {
        for query in ["debug", "a=1&debug", "debug&a=1+2", "a&&b"] {
            for (name, value) in query_pairs(query) {
                span(query, name);
                span(query, value);
            }
        }
        for text in ["flag", "a=1; flag", "flag ;a=1"] {
            for (name, value) in cookie_pairs_of(text) {
                span(text, name);
                span(text, value);
            }
        }
        let c = compiled(RULES, Mode::Block);
        for (uri, cookie) in [("/s?debug", "flag"), ("/s?a=1+2&debug&x=x1", "a=1; flag")] {
            let parts = request(uri, &[("user-agent", "Mozilla"), ("cookie", cookie)]);
            let input = input(&parts);
            let mut eval = Evaluation::new();
            eval.run_phase(&c, Phase::Head, &input, 200);
        }
    }

    #[test]
    fn pairs_and_extensions() {
        let pairs: Vec<_> = query_pairs("a=1&&b&c=x%3Dy&=z").collect();
        assert_eq!(pairs, [("a", "1"), ("b", ""), ("c", "x%3Dy"), ("", "z")]);
        let mut headers = HeaderMap::new();
        headers.insert(http::header::COOKIE, "a=1; b=\"two\"; c".parse().unwrap());
        headers.append(http::header::COOKIE, "d=4".parse().unwrap());
        let cookies: Vec<_> = cookie_pairs(&headers).collect();
        assert_eq!(cookies, [("a", "1"), ("b", "two"), ("c", ""), ("d", "4")]);
        let mut seen = Vec::new();
        extensions("dir/shot.php.jpg", &mut |_, e| {
            seen.push(e.to_string());
            true
        });
        assert_eq!(seen, ["php.jpg", "jpg", "php"]);
        assert_eq!(cut("héllo", 2), "h");
        assert_eq!(cut("héllo", 3), "hé");
    }

    pub(crate) fn compiled(yaml: &str, mode: Mode) -> Compiled {
        let file: super::super::rule::RulesFile = webfast_core::yaml::from_str(yaml).unwrap();
        let rules: Vec<Sourced> = file
            .rules
            .into_iter()
            .map(|rule| Sourced {
                rule,
                base: Path::new(".").to_path_buf(),
            })
            .collect();
        compile(&rules, mode, &[]).unwrap()
    }

    pub(crate) fn request(uri: &str, headers: &[(&str, &str)]) -> http::request::Parts {
        let mut builder = http::Request::get(uri).header("host", "www.example.com");
        for (name, value) in headers {
            builder = builder.header(*name, *value);
        }
        builder.body(()).unwrap().into_parts().0
    }

    pub(crate) fn input(parts: &http::request::Parts) -> Input<'_> {
        Input {
            parts,
            client_ip: "203.0.113.7".parse().unwrap(),
            country: Some(*b"NL"),
            asn: Some(1136),
            sni: None,
            ja4: None,
            body: None,
            response: None,
        }
    }

    const RULES: &str = r#"
rules:
  - id: sqli
    phase: head
    severity: critical
    targets: [args, cookies]
    transform: [url_decode, lowercase, compress_whitespace]
    operator: { contains_any: ['union select', 'sleep('] }
  - id: sqli-re
    phase: head
    targets: [args]
    transform: [url_decode, lowercase]
    operator: { regex: 'select\s+\w+\s+from' }
    prefilter: [select]
  - id: scanner
    phase: head
    targets: [ua]
    transform: [lowercase]
    operator: { contains_any: [nikto] }
    action: block
  - id: no-ua
    phase: head
    severity: notice
    targets: [ua]
    operator: missing
  - id: many-args
    phase: head
    targets: [args_count]
    operator: { gt: 3 }
  - id: double
    phase: head
    targets: [anomaly.double_encoding]
    operator: exists
  - id: follow
    phase: head
    targets: [args]
    operator: { contains_any: [x] }
    when: [sqli]
  - id: quiet
    phase: head
    targets: [args]
    operator: { contains_any: [x] }
    unless: [sqli]
  - id: monitor
    phase: head
    targets: [ua]
    operator: { equals_any: [monitor/1.0] }
    action: pass
  - id: mark
    phase: head
    targets: [args]
    operator: { starts_with_any: ['mark:'] }
    action: header
    header: { X-Threat: marked }
  - id: from-kp
    phase: connection
    operator: { country_in: [KP] }
    action: block
  - id: tls
    phase: head
    targets: [tls.sni]
    operator: { equals_any: ['evil.test'] }
    action: log
"#;

    fn evaluate(parts: &http::request::Parts) -> Evaluation {
        let c = compiled(RULES, Mode::Block);
        let input = input(parts);
        let mut eval = Evaluation::new();
        eval.run_phase(&c, Phase::Connection, &input, 200);
        eval.run_phase(&c, Phase::Head, &input, 200);
        eval
    }

    fn ids(c: &Compiled, eval: &Evaluation) -> Vec<String> {
        eval.hits.iter().map(|h| c.rules[h.rule as usize].id.clone()).collect()
    }

    /// Who claims a current browser, which host is an address, and when a fingerprint and a
    /// User-Agent disagree.
    #[test]
    fn a_browsers_user_agent_and_its_tls_fingerprint() {
        let chrome = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36";
        for (ua, claims) in [
            (chrome, true),
            (
                "Mozilla/5.0 (X11; Linux x86_64; rv:133.0) Gecko/20100101 Firefox/133.0",
                true,
            ),
            (
                "Mozilla/5.0 (iPhone; CPU iPhone OS 18_1 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/18.1 Mobile/15E148 Safari/604.1",
                true,
            ),
            (
                "Mozilla/5.0 (iPhone; CPU iPhone OS 18_1 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) CriOS/131.0.6778.73 Mobile/15E148 Safari/604.1",
                true,
            ),
            (
                "Mozilla/5.0 (Windows NT 6.1) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/49.0.2623.112 Safari/537.36",
                false,
            ),
            (
                "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_13_6) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/12.1 Safari/605.1.15",
                false,
            ),
            (
                "Mozilla/5.0 (compatible; bingbot/2.0; +http://www.bing.com/bingbot.htm)",
                false,
            ),
            (
                "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) HeadlessChrome/131.0.0.0 Safari/537.36",
                false,
            ),
            ("curl/8.5.0", false),
            ("python-requests/2.32.3", false),
            ("", false),
        ] {
            assert_eq!(claims_current_browser(ua), claims, "{ua}");
        }
        let parts = |host: &str| {
            let mut p = request("/", &[("user-agent", chrome)]);
            p.headers
                .insert(http::header::HOST, http::HeaderValue::from_str(host).unwrap());
            p
        };
        for (host, address) in [
            ("www.example.com", false),
            ("www.example.com:8443", false),
            ("203.0.113.5", true),
            ("203.0.113.5:8443", true),
            ("[2001:db8::1]", true),
            ("[2001:db8::1]:8443", true),
        ] {
            assert_eq!(host_is_address(&parts(host)), address, "{host}");
        }
        let ja4 = |text: &str| webfast_core::ja4::Ja4::parse(text).unwrap();
        let name = parts("www.example.com");
        let address = parts("203.0.113.5");
        assert!(!tls_ua_mismatch(&name, &ja4("t13d1516h2_8daaf6152771_e5627efa2ab1")));
        assert!(
            tls_ua_mismatch(&name, &ja4("t13d1516h1_8daaf6152771_e5627efa2ab1")),
            "no h2"
        );
        assert!(
            tls_ua_mismatch(&name, &ja4("t13d151600_8daaf6152771_e5627efa2ab1")),
            "no ALPN"
        );
        assert!(
            tls_ua_mismatch(&name, &ja4("t12d1516h2_8daaf6152771_e5627efa2ab1")),
            "TLS 1.2"
        );
        assert!(
            tls_ua_mismatch(&name, &ja4("t13i1516h2_8daaf6152771_e5627efa2ab1")),
            "no SNI for a name"
        );
        assert!(
            !tls_ua_mismatch(&address, &ja4("t13i1516h2_8daaf6152771_e5627efa2ab1")),
            "no SNI for an address"
        );
    }

    /// `gt`, `ge`, `lt`, `le`, `eq`, `ne` on a numeric target, and the same comparisons as
    /// `count_*` (the number of the target's values) and `length_*` (each value's length).
    #[test]
    fn comparisons_of_numbers_counts_and_lengths() {
        let c = compiled(
            r"
rules:
  - {id: n-ge, phase: head, targets: [args_count], operator: {ge: 2}}
  - {id: n-lt, phase: head, targets: [args_count], operator: {lt: 1}}
  - {id: n-le, phase: head, targets: [args_count], operator: {le: 1}}
  - {id: n-eq, phase: head, targets: [args_count], operator: {eq: 2}}
  - {id: n-ne, phase: head, targets: [args_count], operator: {ne: 2}}
  - {id: c-eq, phase: head, targets: [headers.x-a], operator: {count_eq: 0}}
  - {id: c-ge, phase: head, targets: [args], operator: {count_ge: 2}}
  - {id: c-lt, phase: head, targets: [cookies], operator: {count_lt: 2}}
  - {id: c-ne, phase: head, targets: [cookies], operator: {count_ne: 0}}
  - {id: l-ge, phase: head, targets: [args], operator: {length_ge: 5}}
  - {id: l-lt, phase: head, targets: [args], operator: {length_lt: 2}}
  - {id: l-le, phase: head, targets: [args], operator: {length_le: 1}}
  - {id: l-eq, phase: head, targets: [args], operator: {length_eq: 2}}
  - {id: l-ne, phase: head, targets: [ua], operator: {length_ne: 7}}
",
            Mode::Block,
        );
        let hits = |uri: &str, headers: &[(&str, &str)]| {
            let parts = request(uri, headers);
            let input = input(&parts);
            let mut eval = Evaluation::new();
            eval.run_phase(&c, Phase::Head, &input, 200);
            let mut ids = ids(&c, &eval);
            ids.sort_unstable();
            ids
        };
        // Two parameters, "1" and "22"; no x-a, no cookie; a User-Agent of seven bytes.
        assert_eq!(
            hits("/?a=1&bb=22", &[("user-agent", "Mozilla")]),
            ["c-eq", "c-ge", "c-lt", "l-eq", "l-le", "l-lt", "n-eq", "n-ge"]
        );
        // One parameter of five bytes, x-a, three cookies, another User-Agent.
        assert_eq!(
            hits(
                "/?abc=xyz12",
                &[("user-agent", "curl/8"), ("x-a", "1"), ("cookie", "k=v; k2=v2; k3=v3")]
            ),
            ["c-ne", "l-ge", "l-ne", "n-le", "n-ne"]
        );
        // None: no parameter at all.
        assert_eq!(
            hits("/", &[("user-agent", "Mozilla")]),
            ["c-eq", "c-lt", "n-le", "n-lt", "n-ne"]
        );
    }

    #[test]
    fn a_clean_request_matches_nothing_and_allocates_no_hit() {
        let parts = request("/en/contact?q=hello+world&page=2", &[("user-agent", "Mozilla/5.0")]);
        let eval = evaluate(&parts);
        assert!(eval.hits.is_empty() && eval.matched.is_empty());
        assert_eq!(eval.decision(5), Decision::Continue);
    }

    #[test]
    fn literals_regexes_and_scores_decide() {
        let c = compiled(RULES, Mode::Block);
        let parts = request(
            "/s?q=1%27%20UNION%20%20SELECT%20a%20FROM%20t&x=x1",
            &[("user-agent", "Mozilla")],
        );
        let eval = evaluate(&parts);
        assert_eq!(ids(&c, &eval), ["sqli", "sqli-re", "follow"]);
        assert_eq!(eval.hits[0].matched, "union select");
        assert_eq!(eval.hits[0].target, "args");
        assert_eq!(eval.hits[1].matched, "select a from");
        assert_eq!(eval.score, 5 + 3 + 3);
        assert_eq!(eval.decision(5), Decision::Block);
        assert_eq!(eval.decision(12), Decision::Continue);
        // `quiet` is held back by `unless`; `follow` ran because `sqli` matched.
        assert!(!ids(&c, &eval).contains(&"quiet".to_string()));
        let parts = request("/s?x=x1", &[("user-agent", "Mozilla")]);
        let eval = evaluate(&parts);
        assert_eq!(ids(&c, &eval), ["quiet"]);
    }

    #[test]
    fn a_plus_in_a_query_is_a_space_and_an_escaped_one_a_plus() {
        let c = compiled(RULES, Mode::Block);
        // An HTML form sent by GET: spaces as `+`.
        let parts = request("/s?q=1%27+UNION++SELECT+a+FROM+t&x=x1", &[("user-agent", "Mozilla")]);
        let eval = evaluate(&parts);
        assert_eq!(ids(&c, &eval), ["sqli", "sqli-re", "follow"]);
        assert_eq!(eval.hits[0].matched, "union select");
        // `%2B` is a `+` itself, not a space.
        let parts = request(
            "/s?q=1%27%2BUNION%2BSELECT%2Ba%2BFROM%2Bt&x=x1",
            &[("user-agent", "Mozilla")],
        );
        let eval = evaluate(&parts);
        assert!(!ids(&c, &eval).contains(&"sqli".to_string()), "{:?}", ids(&c, &eval));
        // A name with a `+` is the name with a space, as a form's.
        let mut buffers = Buffers::default();
        prepare(&request("/s?a+b=c+d&e=f", &[]), &mut buffers);
        assert!(buffers.query_plus);
        let fixed_pairs: Vec<(&str, &str)> = buffers
            .query_pairs
            .iter()
            .map(|p| {
                (
                    &buffers.query_text[p.name.0 as usize..p.name.1 as usize],
                    &buffers.query_text[p.value.0 as usize..p.value.1 as usize],
                )
            })
            .collect();
        assert_eq!(fixed_pairs, [("a b", "c d"), ("e", "f")]);
        prepare(&request("/s?e=f", &[]), &mut buffers);
        assert!(!buffers.query_plus && buffers.query_text.is_empty());
    }

    #[test]
    fn block_pass_header_missing_count_and_anomaly_actions() {
        let c = compiled(RULES, Mode::Block);
        let parts = request("/", &[("user-agent", "Nikto/2.1")]);
        let eval = evaluate(&parts);
        assert_eq!(eval.decision(5), Decision::Block);
        assert_eq!(ids(&c, &eval), ["scanner"], "stops at the block");

        let parts = request("/?a=1&b=2&c=3&d=4", &[]);
        let eval = evaluate(&parts);
        assert_eq!(ids(&c, &eval), ["no-ua", "many-args"]);
        assert_eq!(eval.score, 1 + 3);
        let parts = request("/", &[("user-agent", "Mozilla")]);
        let mut input = input(&parts);
        input.sni = Some("evil.test");
        let mut eval = Evaluation::new();
        eval.run_phase(&c, Phase::Head, &input, 200);
        assert_eq!(ids(&c, &eval), ["tls"]);
        assert_eq!(eval.score, 0, "a log action adds nothing");

        let parts = request("/?q=%252e", &[("user-agent", "Mozilla")]);
        let eval = evaluate(&parts);
        assert_eq!(
            ids(&c, &eval),
            ["double"],
            "the anomaly group runs after the decoding groups"
        );

        let parts = request("/?q=sleep(1)", &[("user-agent", "monitor/1.0")]);
        let eval = evaluate(&parts);
        assert_eq!(eval.decision(1), Decision::Pass);

        let parts = request("/?q=mark:1", &[("user-agent", "Mozilla")]);
        let eval = evaluate(&parts);
        assert_eq!(ids(&c, &eval), ["mark"]);
        assert_eq!(eval.header_rules, [c.rule_index("mark").unwrap() as u32]);
    }

    #[test]
    fn connection_rules_and_log_only_modes() {
        let c = compiled(RULES, Mode::Block);
        let parts = request("/", &[("user-agent", "Mozilla")]);
        let mut input = input(&parts);
        input.country = Some(*b"KP");
        let mut eval = Evaluation::new();
        eval.run_phase(&c, Phase::Connection, &input, 200);
        assert_eq!(eval.decision(5), Decision::Block);
        assert_eq!(eval.hits[0].target, "country");
        assert_eq!(eval.hits[0].matched, "KP");

        let c = compiled(RULES, Mode::LogOnly);
        let parts = request("/?q=sleep(1)", &[("user-agent", "Nikto")]);
        let input = super::tests::input(&parts);
        let mut eval = Evaluation::new();
        eval.run_phase(&c, Phase::Head, &input, 200);
        assert_eq!(eval.score, 0);
        assert_eq!(eval.shadow, 5);
        assert_eq!(eval.decision(5), Decision::LogOnly);
        assert!(
            eval.hits.len() >= 2,
            "log_only rules keep running after a would-be block"
        );
    }

    #[test]
    fn matched_text_is_cut_and_keeps_its_source() {
        let c = compiled(RULES, Mode::Block);
        let parts = request(
            "/?access_token=sleep(1)&q=sleep(1234567890)",
            &[("user-agent", "Mozilla")],
        );
        let input = input(&parts);
        let mut eval = Evaluation::new();
        eval.run_phase(&c, Phase::Head, &input, 3);
        // The log hides it by its source (src/log.rs), not the engine.
        assert_eq!(eval.hits[0].source, HitSource::Arg("access_token".into()));
        let mut eval = Evaluation::new();
        let parts = request("/?q=sleep(1234567890)", &[("user-agent", "Mozilla")]);
        let input = super::tests::input(&parts);
        eval.run_phase(&c, Phase::Head, &input, 3);
        assert_eq!(eval.hits[0].matched, "sle");
    }

    #[test]
    fn exclusions_by_path_host_target_set_and_rule() {
        let file: super::super::rule::RulesFile = webfast_core::yaml::from_str(RULES).unwrap();
        let rules: Vec<Sourced> = file
            .rules
            .into_iter()
            .map(|mut rule| {
                if rule.id == "sqli" {
                    rule.set = Some("sqli".into());
                }
                Sourced {
                    rule,
                    base: Path::new(".").to_path_buf(),
                }
            })
            .collect();
        let exclusions: Vec<super::super::config::ExclusionConfig> = webfast_core::yaml::from_str(
            r#"
- paths: ['/admin/*']
  rules: [sqli*]
- paths: ['/search']
  targets: [args.q]
- hosts: ['legacy.example.com']
  sets: [sqli]
- paths: ['/off']
"#,
        )
        .unwrap();
        let c = compile(&rules, Mode::Block, &exclusions).unwrap();
        let run = |uri: &str, host: &str| {
            let mut parts = request(uri, &[("user-agent", "Mozilla")]);
            parts.headers.insert("host", host.parse().unwrap());
            let input = input(&parts);
            let mut eval = Evaluation::new();
            eval.run_phase(&c, Phase::Head, &input, 200);
            ids(&c, &eval)
        };
        assert_eq!(run("/x?q=sleep(1)", "www.example.com"), ["sqli"]);
        assert!(
            run("/admin/x?q=sleep(1)", "www.example.com").is_empty(),
            "by rule mask and path"
        );
        assert!(
            run("/Admin/../admin/y?q=sleep(1)", "www.example.com").is_empty(),
            "cleaned, case-insensitive"
        );
        assert!(
            run("/search?q=sleep(1)", "www.example.com").is_empty(),
            "the parameter is not looked at"
        );
        assert_eq!(
            run("/search?r=sleep(1)", "www.example.com"),
            ["sqli"],
            "another parameter is"
        );
        assert!(run("/x?q=sleep(1)", "legacy.example.com").is_empty(), "by set and host");
        assert!(run("/x?q=sleep(1)", "LEGACY.example.com:8080").is_empty());
        assert!(run("/off?q=sleep(1)", "www.example.com").is_empty(), "everything");
    }

    #[cfg(feature = "libinjection")]
    mod libinjection {
        use super::super::super::config::{RulesConfig, compose};
        use super::super::super::detect::corpus::{BENIGN, BYPASS, SQLI, XSS};
        use super::super::super::detect::{self, tests::query_encoded};
        use super::*;

        const DETECTORS: &str = r#"
rules:
  - id: sqli
    phase: head
    severity: critical
    targets: [args, cookies]
    transform: [url_decode, lowercase]
    prefilter: ["'", '=']
    operator: detect_sqli
  - id: xss
    phase: head
    targets: [args]
    transform: [url_decode, html_decode]
    prefilter: ['<']
    operator: detect_xss
  - id: sqli-everywhere
    phase: head
    targets: [headers.x-raw]
    operator: detect_sqli
"#;

        fn run(c: &Compiled, uri: &str, headers: &[(&str, &str)]) -> Evaluation {
            let parts = request(uri, headers);
            let input = input(&parts);
            let mut eval = Evaluation::new();
            eval.run_phase(c, Phase::Head, &input, 200);
            eval
        }

        #[test]
        fn the_detectors_run_on_what_their_prefilter_lets_through() {
            let c = compiled(DETECTORS, Mode::Block);
            let eval = run(&c, "/?id=1%27%20or%20%271%27%3D%271&page=2", &[]);
            assert_eq!(ids(&c, &eval), ["sqli"]);
            assert_eq!(eval.score, 5);
            assert!(
                eval.hits[0].matched.starts_with('[') && eval.hits[0].matched.ends_with("] 1' or '1'='1"),
                "the fingerprint, then the value: {}",
                eval.hits[0].matched
            );
            let eval = run(&c, "/?q=%3Cimg%20src%3Dx%20onerror%3Dalert(1)%3E", &[]);
            assert!(ids(&c, &eval).contains(&"xss".to_string()), "{:?}", ids(&c, &eval));
            let eval = run(&c, "/?name=O%27Brien&page=2", &[("cookie", "session=abc; pref=a=b")]);
            assert!(eval.hits.is_empty(), "an apostrophe in a name is let through");
            // No prefilter literal: the detector is not called, though it would say yes.
            assert!(detect::sqli("1 union select password from users").is_some());
            let before = detect::calls();
            let eval = run(&c, "/?id=1%20union%20select%20password%20from%20users", &[]);
            assert!(eval.hits.is_empty());
            assert_eq!(detect::calls(), before, "gated out: libinjection never ran");
            // Clean values, gathered for one pass: not called either.
            let eval = run(
                &c,
                "/page?q=hello+world&id=42&sort=name",
                &[("cookie", "session=abc123")],
            );
            assert!(eval.hits.is_empty());
            assert_eq!(detect::calls(), before);
            // Without a prefilter it runs on every value.
            let eval = run(&c, "/", &[("x-raw", "1 union select password from users")]);
            assert_eq!(ids(&c, &eval), ["sqli-everywhere"]);
            assert!(detect::calls() > before);
            // Once per (rule, text) however many literals the text has.
            let before = detect::calls();
            let eval = run(&c, "/?a=x%27%3D%27%3D%27%3D", &[]);
            assert!(eval.hits.is_empty());
            assert_eq!(detect::calls(), before + 1);
        }

        fn builtin() -> Compiled {
            let (rules, _) = compose(&RulesConfig::default(), Path::new("."), None).unwrap();
            compile(&rules, Mode::Block, &[]).unwrap()
        }

        /// The built-in rules' hits for `value` as a query parameter (spaces as `%20`) and as a
        /// cookie.
        fn hits_of(c: &Compiled, value: &str, header: Option<&str>) -> Vec<String> {
            let encoded = query_encoded(value, false);
            let headers: Vec<(&str, &str)> = header.map(|h| vec![(h, value)]).unwrap_or_default();
            let uri = if header.is_some() {
                "/".to_string()
            } else {
                format!("/p?v={encoded}")
            };
            ids(c, &run(c, &uri, &headers))
        }

        #[test]
        fn the_built_in_rules_catch_the_payloads_and_let_the_benign_values_through() {
            let c = builtin();
            let sqli = |v: &str| hits_of(&c, v, None).iter().any(|id| id == "wf-942-170");
            let xss = |v: &str| hits_of(&c, v, None).iter().any(|id| id == "wf-941-150");
            for payload in [
                "' or '1'='1",
                "1' or '1'='1",
                "1 or 1=1",
                "admin'--",
                "1 UNION ALL SELECT username,password FROM users",
                "1 UnIoN/**/SeLeCt 1,2",
                "'||(select 1)||'",
                "1;drop table users",
                "1 AND (SELECT 1 FROM (SELECT SLEEP(5))a)",
            ] {
                assert!(sqli(payload), "{payload}");
            }
            let caught = SQLI.iter().filter(|p| sqli(p)).count();
            assert!(caught >= 60, "{caught} of {} SQL injections", SQLI.len());
            for payload in [
                "<script>alert(1)</script>",
                "<img src=x onerror=alert(1)>",
                "\"><svg/onload=alert(1)>",
                "\" onmouseover=\"alert(1)",
                "&lt;script&gt;alert(1)&lt;/script&gt;",
                "\\x3cscript\\x3ealert(1)\\x3c/script\\x3e",
            ] {
                assert!(xss(payload), "{payload}");
            }
            let caught = XSS.iter().filter(|p| xss(p)).count();
            // 47: here a double-encoded payload is percent-encoded once more, deeper than the two
            // passes of url_decode (it is caught as itself, and by wf-920-150 and wf-941-140).
            assert!(caught >= 47, "{caught} of {} XSS", XSS.len());
            // In a cookie too; in the User-Agent and Referer the XSS rule.
            let cookie = |v: &str| run(&c, "/", &[("cookie", &format!("c={v}"))]);
            assert!(ids(&c, &cookie("1'%20or%20'1'%3D'1")).contains(&"wf-942-170".to_string()));
            let ua = hits_of(&c, "Mozilla/5.0 <script>alert(1)</script>", Some("user-agent"));
            assert!(ua.contains(&"wf-941-150".to_string()), "{ua:?}");
            let referer = hits_of(&c, "https://x.test/?q=%3Csvg%20onload%3Dalert(1)%3E", Some("referer"));
            assert!(referer.contains(&"wf-941-150".to_string()), "{referer:?}");
            for value in BENIGN.iter() {
                let hits = hits_of(&c, value, None);
                assert!(
                    !hits.iter().any(|id| id == "wf-942-170" || id == "wf-941-150"),
                    "{value}: {hits:?}"
                );
            }
            for ua in BENIGN.iter().filter(|v| v.contains('/')) {
                let hits = hits_of(&c, ua, Some("user-agent"));
                assert!(!hits.iter().any(|id| id == "wf-941-150"), "{ua}: {hits:?}");
            }
        }

        /// What a browser sends besides the value: without them the protocol set's notices on a
        /// missing User-Agent and Accept would add to every score.
        const BROWSER: [(&str, &str); 2] = [
            (
                "user-agent",
                "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/130.0 Safari/537.36",
            ),
            ("accept", "text/html,application/xhtml+xml,*/*;q=0.8"),
        ];

        /// The whole filter on `value` in each place a browser puts one: a query parameter with
        /// its spaces as `%20` and as `+` (a form sent by GET), and a cookie. The score and the
        /// hits of each.
        fn evaluations(c: &Compiled, value: &str) -> [(&'static str, u32, Vec<String>); 3] {
            let cookie = format!("c={}", query_encoded(value, false));
            let mut cookie_headers = BROWSER.to_vec();
            cookie_headers.push(("cookie", &cookie));
            let run_all = |uri: &str, headers: &[(&str, &str)]| {
                let parts = request(uri, headers);
                let input = input(&parts);
                let mut eval = Evaluation::new();
                eval.run_phase(c, Phase::Connection, &input, 200);
                eval.run_phase(c, Phase::Head, &input, 200);
                (eval.score, ids(c, &eval))
            };
            let (a, ha) = run_all(&format!("/p?v={}", query_encoded(value, false)), &BROWSER);
            let (b, hb) = run_all(&format!("/p?v={}", query_encoded(value, true)), &BROWSER);
            let (d, hd) = run_all("/p", &cookie_headers);
            [("query %20", a, ha), ("query +", b, hb), ("cookie", d, hd)]
        }

        /// Every payload of the corpus is refused by the built-in sets together, in a query (both
        /// spellings of a space) and in a cookie; no benign value is hit by any rule. The corpus
        /// here is SQLI and XSS and BYPASS (known evasions the shipped sets must keep refusing).
        #[test]
        fn the_whole_filter_refuses_the_corpus_and_hits_no_benign_value() {
            let c = builtin();
            let mut passed = Vec::new();
            for payload in SQLI.iter().chain(XSS.iter()).chain(BYPASS.iter()) {
                for (place, score, hits) in evaluations(&c, payload) {
                    if score < 5 {
                        passed.push(format!("{place}: {payload:?} scored {score} {hits:?}"));
                    }
                }
            }
            assert!(passed.is_empty(), "let through:\n{}", passed.join("\n"));
            let mut hit = Vec::new();
            for value in BENIGN.iter() {
                for (place, score, hits) in evaluations(&c, value) {
                    if !hits.is_empty() {
                        hit.push(format!("{place}: {value:?} scored {score} {hits:?}"));
                    }
                }
            }
            assert!(hit.is_empty(), "benign values hit:\n{}", hit.join("\n"));
        }
    }
}
