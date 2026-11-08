//! The rules compiled for the request path: one plan per (phase, target) with the distinct
//! transformation chains of its rules, one Aho-Corasick automaton over every `contains_any`
//! literal and every regex `prefilter` of all those rules, each pattern mapped back to its rules
//! and the chain each reads; compiled regexes; literal sets; `when`/`unless` as rule indices;
//! exclusions as patterns.
//!
//! One automaton per target, not per chain: a value is put through each chain once (engine.rs),
//! and chains that leave it the same share one pass, which for a clean value is every chain. A
//! hit of a pattern counts for a rule only when the text searched is what the rule's chain gives
//! (the engine filters by chain). Where a chain lowercases, the literals are lowercased with it
//! (the text is lowercase by then). The automaton is `MatchKind::Standard` and searched for
//! overlapping matches: a rule's literal that lies inside another rule's (`select` in `union
//! select`) must still reach its rule, which leftmost-first matching would not give.

use super::config::{ExclusionConfig, Sourced};
use super::iplist::IpSet;
use super::rule::{Action, Confidence, IdPattern, Mode, Operator, Phase, Refs, Rule, Severity, Target, Transform};
use aho_corasick::{AhoCorasick, AhoCorasickBuilder, AhoCorasickKind, MatchKind};
use anyhow::{Context, Result, anyhow, bail};
use http::{HeaderName, HeaderValue};
use regex::Regex;
use rustc_hash::{FxHashMap, FxHashSet};
use std::collections::HashMap;
use webfast_core::matcher::PathPattern;

/// A rule ready to run.
pub struct CompiledRule {
    pub id: String,
    /// What the id stands for as a number (`rule::number_of`), written as the log's `ruleId`.
    pub number: Option<u64>,
    pub set: String,
    pub msg: String,
    pub phase: Phase,
    pub score: u32,
    pub action: Action,
    pub mode: Mode,
    pub matcher: Matcher,
    /// Rules that must have matched earlier in the request.
    pub when: Vec<u32>,
    /// Rules none of which may have matched.
    pub unless: Vec<u32>,
    /// With `action: header`.
    pub headers: Vec<(HeaderName, HeaderValue)>,
    /// Exclusions that name this rule (by id or mask), its set, or everything.
    pub excluded_by: Vec<u32>,
    /// What the log line's hit says of the rule besides its id, set and score.
    pub severity: Severity,
    pub tags: Vec<String>,
    /// As written; `None` (medium) is not logged.
    pub confidence: Option<Confidence>,
    pub refs: Refs,
}

/// How a rule decides, beyond the group's automaton.
pub enum Matcher {
    /// `contains_any`: the automaton alone decides.
    Literal,
    /// `regex`: runs after a `prefilter` literal was found, or on every value without one.
    Regex(Regex),
    EqualsAny(FxHashSet<String>),
    StartsWithAny(Vec<String>),
    EndsWithAny(Vec<String>),
    LengthGt(usize),
    CountGt(usize),
    Gt(i64),
    InSet(FxHashSet<String>),
    IpIn(IpSet),
    CountryIn(Vec<[u8; 2]>),
    AsnIn(Vec<u32>),
    MagicNot(Vec<Magic>),
    MagicIs(Vec<Magic>),
    NotValidUtf8,
    NotValidJson,
    Exists,
    Missing,
    /// `detect_sqli`, `detect_xss`: libinjection decides, after a `prefilter` literal was found
    /// (once per text, as a regex), or on every value without one.
    DetectSqli,
    DetectXss,
}

impl Matcher {
    /// Tested on the text after a `prefilter` literal led to it (a regex, a detector).
    pub fn is_gated(&self) -> bool {
        matches!(self, Matcher::Regex(_) | Matcher::DetectSqli | Matcher::DetectXss)
    }

    /// Decided on the target as a whole (its count, its number, its presence, its raw bytes), not
    /// per text value.
    fn is_whole(&self) -> bool {
        matches!(
            self,
            Matcher::CountGt(_)
                | Matcher::Gt(_)
                | Matcher::Exists
                | Matcher::Missing
                | Matcher::NotValidJson
                | Matcher::NotValidUtf8
                | Matcher::MagicIs(_)
                | Matcher::MagicNot(_)
        )
    }
}

/// A file type known by its first bytes (`magic_is`, `magic_not`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Magic {
    Png,
    Jpeg,
    Gif,
    Webp,
    Pdf,
    Zip,
    Gzip,
    Bmp,
    Ico,
    Svg,
    Php,
    Script,
}

impl Magic {
    pub fn parse(name: &str) -> Option<Magic> {
        Some(match name {
            "png" => Magic::Png,
            "jpeg" | "jpg" => Magic::Jpeg,
            "gif" => Magic::Gif,
            "webp" => Magic::Webp,
            "pdf" => Magic::Pdf,
            "zip" => Magic::Zip,
            "gzip" => Magic::Gzip,
            "bmp" => Magic::Bmp,
            "ico" => Magic::Ico,
            "svg" => Magic::Svg,
            "php" => Magic::Php,
            "script" => Magic::Script,
            _ => return None,
        })
    }

    /// The type a declared Content-Type names, if it is one known here.
    pub fn of_content_type(content_type: &str) -> Option<Magic> {
        let kind = content_type.split(';').next().unwrap_or("").trim();
        // A part's type is lowercased already (multipart.rs): a copy only for one that is not.
        let lowered;
        let kind = if kind.bytes().any(|b| b.is_ascii_uppercase()) {
            lowered = kind.to_ascii_lowercase();
            lowered.as_str()
        } else {
            kind
        };
        Some(match kind {
            "image/png" => Magic::Png,
            "image/jpeg" | "image/jpg" | "image/pjpeg" => Magic::Jpeg,
            "image/gif" => Magic::Gif,
            "image/webp" => Magic::Webp,
            "application/pdf" => Magic::Pdf,
            "application/zip" | "application/x-zip-compressed" => Magic::Zip,
            "application/gzip" | "application/x-gzip" => Magic::Gzip,
            "image/bmp" | "image/x-ms-bmp" => Magic::Bmp,
            "image/x-icon" | "image/vnd.microsoft.icon" => Magic::Ico,
            "image/svg+xml" => Magic::Svg,
            "application/x-php" | "application/x-httpd-php" | "text/x-php" => Magic::Php,
            "application/x-sh" | "text/x-shellscript" => Magic::Script,
            _ => return None,
        })
    }

    /// Whether `head` (the file's first bytes) is this type.
    pub fn detect(self, head: &[u8]) -> bool {
        fn has(head: &[u8], needle: &[u8]) -> bool {
            memchr::memmem::find(head, needle).is_some()
        }
        /// `<?php` or `<?=` anywhere: one scan for the `<`.
        fn has_php_tag(head: &[u8]) -> bool {
            let mut at = 0;
            while let Some(found) = memchr::memchr(b'<', &head[at..]) {
                at += found;
                if head[at..].starts_with(b"<?php") || head[at..].starts_with(b"<?=") {
                    return true;
                }
                at += 1;
            }
            false
        }
        match self {
            Magic::Png => head.starts_with(b"\x89PNG\r\n\x1a\n"),
            Magic::Jpeg => head.starts_with(b"\xFF\xD8\xFF"),
            Magic::Gif => head.starts_with(b"GIF87a") || head.starts_with(b"GIF89a"),
            Magic::Webp => head.len() >= 12 && head.starts_with(b"RIFF") && &head[8..12] == b"WEBP",
            Magic::Pdf => head.starts_with(b"%PDF"),
            Magic::Zip => head.starts_with(b"PK\x03\x04") || head.starts_with(b"PK\x05\x06"),
            Magic::Gzip => head.starts_with(b"\x1f\x8b"),
            Magic::Bmp => head.starts_with(b"BM"),
            Magic::Ico => head.starts_with(b"\x00\x00\x01\x00"),
            Magic::Svg => {
                let start = head.trim_ascii_start();
                (start.starts_with(b"<svg") || start.starts_with(b"<?xml")) && has(head, b"<svg")
            }
            Magic::Php => has_php_tag(head),
            Magic::Script => head.starts_with(b"#!"),
        }
    }
}

/// The rules of one phase and target.
pub struct Plan {
    pub phase: Phase,
    pub target: Target,
    /// The distinct transformation chains of the rules that read the target's values (at most
    /// 64); a rule decided on the whole target has none.
    pub chains: Vec<Chain>,
    /// Over the `contains_any` literals and `prefilter`s of every chain's rules; `None`: none.
    pub automaton: Option<AhoCorasick>,
    /// Pattern id → (index into `chains`, rule): the rules whose literal it is, each with the
    /// chain whose text it is searched in.
    pub pattern_rules: Vec<Vec<(u16, u32)>>,
    /// Rules tested on the target as a whole (its count, its number, its presence, its bytes).
    pub whole: Vec<u32>,
    /// In the body phase, the `args` targets also walk the query: a rule of the `body` phase
    /// itself is on them. Head rules run again on a body see the form's pairs only; the query's
    /// they saw in the head phase.
    pub wants_query: bool,
    /// The automaton matches ASCII letters in either case, and the chains' `lowercase` is not
    /// applied for it: every chain with a literal lowercases (and nothing after its `lowercase`
    /// depends on case), or the others' literals have no letters. The text searched is then the
    /// value's own case, and a per-value test of a lowercasing chain lowercases it itself.
    pub case_insensitive: bool,
    /// The byte classes (engine.rs) some chain needs to change a value: a value without them is
    /// searched as it is.
    pub needs: u16,
    /// Some chain has per-value rules.
    pub has_tests: bool,
    /// A byte no pattern has, to put between the clean values for one pass over all of them;
    /// `None`: every control byte is in some pattern, the values are searched one by one.
    pub separator: Option<u8>,
}

/// One transformation chain of a plan, with the rules tested on each value beyond the
/// automaton (a regex without a prefilter, `equals_any`, `length_gt`, ...).
pub struct Chain {
    pub transforms: Vec<Transform>,
    pub per_value: Vec<u32>,
    /// The chain has `lowercase`.
    pub lowers: bool,
    /// The byte classes the chain needs to change a value (engine.rs).
    pub needs: u16,
}

/// Whether a transformation gives the same text (but for case) on a text lowercased before it
/// as on the original: `lowercase` can then be left to the automaton.
fn case_independent(transform: Transform) -> bool {
    matches!(
        transform,
        Transform::UrlDecode
            | Transform::NormalizePath
            | Transform::RemoveNulls
            | Transform::CompressWhitespace
            | Transform::RemoveComments
            | Transform::CmdLine
            | Transform::Utf8ToUnicode
    )
}

/// Where rules do not apply, compiled.
pub struct Exclusion {
    pub hosts: Vec<String>,
    pub paths: Vec<PathPattern>,
    pub rules: Vec<IdPattern>,
    pub sets: Vec<String>,
    pub targets: Vec<Target>,
}

impl Exclusion {
    /// Names no rule, set or target: everything is excluded where it applies.
    fn everything(&self) -> bool {
        self.rules.is_empty() && self.sets.is_empty() && self.targets.is_empty()
    }

    /// Whether it applies to a request with this host (port stripped) and matcher path
    /// (lowercased, cleaned).
    pub fn applies(&self, host: &str, match_path: &str) -> bool {
        (self.hosts.is_empty() || self.hosts.iter().any(|h| webfast_core::matcher::host_matches(h, host)))
            && (self.paths.is_empty() || self.paths.iter().any(|p| p.matches_path(match_path)))
    }
}

pub struct Compiled {
    pub rules: Vec<CompiledRule>,
    pub plans: Vec<Plan>,
    /// Plan indices per phase (`Phase::index`), in run order; the `args.<name>` plans without
    /// whole-target rules are not here but in `arg_plans`, run in one walk of the parameters
    /// before the anomaly plans, which come last (from `anomalies_from`).
    pub phases: [Vec<usize>; 5],
    pub anomalies_from: [usize; 5],
    /// Per phase, parameter name → its `args.<name>` plan.
    pub arg_plans: [FxHashMap<String, usize>; 5],
    pub exclusions: Vec<Exclusion>,
    /// The headers of every `header` action: taken off every request first.
    pub header_names: Vec<HeaderName>,
}

impl Compiled {
    pub fn has_phase(&self, phase: Phase) -> bool {
        !self.phases[phase.index()].is_empty() || !self.arg_plans[phase.index()].is_empty()
    }

    pub fn rule_index(&self, id: &str) -> Option<usize> {
        self.rules.iter().position(|r| r.id == id)
    }

    /// For a response whose body is scanned as it streams: how many bytes to carry across a
    /// frame boundary — the longest `response.body` literal less one, and `window` where a rule
    /// is tested on the text beyond its literal (a regex, a per-value test); `None`: no rule reads
    /// the response body.
    pub fn response_carry(&self, window: usize) -> Option<usize> {
        let mut carry: Option<usize> = None;
        for &p in &self.phases[Phase::Response.index()] {
            let plan = &self.plans[p];
            if plan.target != Target::ResponseBody {
                continue;
            }
            let literal = plan.automaton.as_ref().map_or(0, |a| a.max_pattern_len());
            let tested = plan.chains.iter().any(|c| !c.per_value.is_empty())
                || plan
                    .pattern_rules
                    .iter()
                    .flatten()
                    .any(|&(_, rule)| self.rules[rule as usize].matcher.is_gated());
            let needed = literal.saturating_sub(1).max(if tested { window } else { 0 });
            carry = Some(carry.map_or(needed, |c| c.max(needed)));
        }
        carry
    }
}

fn set_of<T: AsRef<str>>(items: &[T], lowercase: bool) -> FxHashSet<String> {
    items
        .iter()
        .map(|s| {
            let s = s.as_ref();
            if lowercase { s.to_lowercase() } else { s.to_string() }
        })
        .collect()
}

fn lowered(items: &[String], lowercase: bool) -> Vec<String> {
    items
        .iter()
        .map(|s| if lowercase { s.to_lowercase() } else { s.clone() })
        .collect()
}

/// The matcher of a rule, and the literals that go into its group's automaton.
fn matcher(sourced: &Sourced, lowercase: bool) -> Result<(Matcher, Vec<String>)> {
    let rule = &sourced.rule;
    Ok(match &rule.operator {
        Operator::ContainsAny(literals) => {
            if literals.is_empty() {
                bail!("contains_any: no literals");
            }
            (Matcher::Literal, lowered(literals, lowercase))
        }
        Operator::EqualsAny(literals) => (Matcher::EqualsAny(set_of(literals, lowercase)), Vec::new()),
        Operator::StartsWithAny(literals) => (Matcher::StartsWithAny(lowered(literals, lowercase)), Vec::new()),
        Operator::EndsWithAny(literals) => (Matcher::EndsWithAny(lowered(literals, lowercase)), Vec::new()),
        Operator::Regex(pattern) => {
            // A rule that lowercases is written for lowercase text; case-insensitive, the regex
            // reads the same on text whose `lowercase` was left to the automaton.
            let regex = regex::RegexBuilder::new(pattern)
                .size_limit(1 << 20)
                .case_insensitive(lowercase)
                .build()
                .with_context(|| format!("regex {pattern:?}"))?;
            (Matcher::Regex(regex), lowered(&rule.prefilter, lowercase))
        }
        Operator::LengthGt(n) => (Matcher::LengthGt(*n), Vec::new()),
        Operator::CountGt(n) => (Matcher::CountGt(*n), Vec::new()),
        Operator::Gt(n) => (Matcher::Gt(*n), Vec::new()),
        Operator::InSet(file) => {
            let path = sourced.base.join(file);
            let text = std::fs::read_to_string(&path).with_context(|| format!("in_set {}", path.display()))?;
            let words: Vec<&str> = text
                .lines()
                .map(str::trim)
                .filter(|l| !l.is_empty() && !l.starts_with('#'))
                .collect();
            (Matcher::InSet(set_of(&words, lowercase)), Vec::new())
        }
        Operator::IpIn(nets) => {
            let mut set = IpSet::new();
            for net in nets {
                set.insert(super::iplist::parse_net(net).context("ip_in")?);
            }
            (Matcher::IpIn(set), Vec::new())
        }
        Operator::CountryIn(codes) => {
            let mut out = Vec::new();
            for code in codes {
                let bytes = code.as_bytes();
                if bytes.len() != 2 || !bytes.iter().all(u8::is_ascii_alphabetic) {
                    bail!("country_in: {code:?} is not an ISO 3166-1 alpha-2 code");
                }
                out.push([bytes[0].to_ascii_uppercase(), bytes[1].to_ascii_uppercase()]);
            }
            (Matcher::CountryIn(out), Vec::new())
        }
        Operator::AsnIn(numbers) => (Matcher::AsnIn(numbers.clone()), Vec::new()),
        Operator::MagicNot(names) => (Matcher::MagicNot(magics(names)?), Vec::new()),
        Operator::MagicIs(names) => (Matcher::MagicIs(magics(names)?), Vec::new()),
        Operator::NotValidUtf8 => (Matcher::NotValidUtf8, Vec::new()),
        Operator::NotValidJson => (Matcher::NotValidJson, Vec::new()),
        Operator::Exists => (Matcher::Exists, Vec::new()),
        Operator::Missing => (Matcher::Missing, Vec::new()),
        Operator::DetectSqli => {
            super::config::needs_libinjection("detect_sqli")?;
            (Matcher::DetectSqli, lowered(&rule.prefilter, lowercase))
        }
        Operator::DetectXss => {
            super::config::needs_libinjection("detect_xss")?;
            (Matcher::DetectXss, lowered(&rule.prefilter, lowercase))
        }
    })
}

fn magics(names: &[String]) -> Result<Vec<Magic>> {
    names
        .iter()
        .map(|name| {
            Magic::parse(name).ok_or_else(|| {
                anyhow!("unknown file type {name:?} (png jpeg gif webp pdf zip gzip bmp ico svg php script)")
            })
        })
        .collect()
}

/// The targets a rule runs on: those written, or for a `connection` rule the one its operator
/// implies.
fn targets_of(rule: &Rule) -> Result<Vec<Target>> {
    if !rule.targets.is_empty() {
        for target in &rule.targets {
            if !target.phases().contains(&rule.phase) {
                bail!("target {target} has no value in the {} phase", rule.phase.name());
            }
        }
        return Ok(rule.targets.clone());
    }
    if rule.phase == Phase::Connection {
        return Ok(vec![match rule.operator {
            Operator::IpIn(_) => Target::ClientIp,
            Operator::CountryIn(_) => Target::Country,
            Operator::AsnIn(_) => Target::Asn,
            _ => bail!("a connection rule without targets takes ip_in, country_in or asn_in"),
        }]);
    }
    bail!("no targets")
}

/// Compiles the composed rules; `mode`: the file's, for rules without their own.
pub fn compile(rules: &[Sourced], mode: Mode, exclusions: &[ExclusionConfig]) -> Result<Compiled> {
    let ids: Vec<&str> = rules.iter().map(|r| r.rule.id.as_str()).collect();
    let index_of = |id: &str, what: &str, of: &str| -> Result<u32> {
        ids.iter()
            .position(|i| *i == id)
            .map(|i| i as u32)
            .ok_or_else(|| anyhow!("rule {of}: {what} names no rule {id:?}"))
    };
    let exclusions: Vec<Exclusion> = exclusions
        .iter()
        .map(|e| Exclusion {
            hosts: e.hosts.iter().map(|h| h.to_ascii_lowercase()).collect(),
            paths: e.paths.iter().map(|p| PathPattern::new(p)).collect(),
            rules: e.rules.iter().map(|r| IdPattern::new(r)).collect(),
            sets: e.sets.clone(),
            targets: e.targets.clone(),
        })
        .collect();
    let mut compiled: Vec<CompiledRule> = Vec::with_capacity(rules.len());
    let mut plans: Vec<Plan> = Vec::new();
    // (phase, target) → plan, and per plan the literal → pattern id.
    let mut plan_index: HashMap<(Phase, Target), usize> = HashMap::new();
    let mut patterns: Vec<(Vec<String>, HashMap<String, usize>)> = Vec::new();
    let mut header_names: Vec<HeaderName> = Vec::new();
    for (index, sourced) in rules.iter().enumerate() {
        let rule = &sourced.rule;
        let of = &rule.id;
        rule.refs.check().map_err(|e| anyhow!("rule {of}: {e}"))?;
        let targets = targets_of(rule).with_context(|| format!("rule {of}"))?;
        let lowercase = rule.transform.contains(&Transform::Lowercase);
        let (matcher, literals) = matcher(sourced, lowercase).with_context(|| format!("rule {of}"))?;
        if matches!(matcher, Matcher::Gt(_)) && !targets.iter().all(Target::is_numeric) {
            bail!("rule {of}: gt takes a numeric target (args_count, upload.count, response.status, asn)");
        }
        if matches!(matcher, Matcher::MagicIs(_) | Matcher::MagicNot(_))
            && targets.iter().any(|t| *t != Target::UploadHead)
        {
            bail!("rule {of}: magic_is and magic_not look at upload.head");
        }
        if rule.action == Action::Header && rule.header.is_empty() {
            bail!("rule {of}: action header without `header`");
        }
        if rule.action == Action::Challenge {
            super::config::needs_challenge(&format!("rule {of}: action challenge"))?;
        }
        if rule.mode == Some(Mode::Challenge) {
            super::config::needs_challenge(&format!("rule {of}: mode challenge"))?;
        }
        let mut headers = Vec::new();
        for (name, value) in &rule.header {
            let name = HeaderName::from_bytes(name.as_bytes())
                .map_err(|_| anyhow!("rule {of}: invalid header name {name:?}"))?;
            let value =
                HeaderValue::from_str(value).map_err(|_| anyhow!("rule {of}: invalid header value {value:?}"))?;
            if !header_names.contains(&name) {
                header_names.push(name.clone());
            }
            headers.push((name, value));
        }
        let when = rule
            .when
            .iter()
            .map(|id| index_of(id, "when", of))
            .collect::<Result<Vec<_>>>()?;
        let unless = rule
            .unless
            .iter()
            .map(|id| index_of(id, "unless", of))
            .collect::<Result<Vec<_>>>()?;
        let set = rule.set.clone().unwrap_or_else(|| "site".to_string());
        let excluded_by = exclusions
            .iter()
            .enumerate()
            .filter(|(_, e)| e.everything() || e.rules.iter().any(|p| p.matches(&rule.id)) || e.sets.contains(&set))
            .map(|(i, _)| i as u32)
            .collect();
        let whole = matcher.is_whole();
        let needs_value_pass = match &matcher {
            Matcher::Literal => false,
            Matcher::Regex(_) | Matcher::DetectSqli | Matcher::DetectXss => literals.is_empty(),
            _ => !whole,
        };
        // A `head` rule runs in the head phase on what the head has, and again in the body phase
        // on the targets a body adds to (`args`, `body`); it scores once (engine.rs).
        let runs: Vec<(Phase, &Target)> = targets
            .iter()
            .flat_map(|target| {
                let head = (rule.phase == Phase::Head && !target.body_only()).then_some((Phase::Head, target));
                let body = (rule.phase == Phase::Head && target.body_phase_too()).then_some((Phase::Body, target));
                let own = (rule.phase != Phase::Head).then_some((rule.phase, target));
                head.into_iter().chain(body).chain(own)
            })
            .collect();
        for (phase, target) in runs {
            let key = (phase, target.clone());
            let plan = match plan_index.get(&key) {
                Some(&p) => p,
                None => {
                    plans.push(Plan {
                        phase,
                        target: target.clone(),
                        chains: Vec::new(),
                        automaton: None,
                        pattern_rules: Vec::new(),
                        whole: Vec::new(),
                        wants_query: false,
                        case_insensitive: false,
                        needs: 0,
                        has_tests: false,
                        separator: None,
                    });
                    patterns.push((Vec::new(), HashMap::new()));
                    plan_index.insert(key, plans.len() - 1);
                    plans.len() - 1
                }
            };
            if phase == Phase::Body && rule.phase == Phase::Body {
                plans[plan].wants_query = true;
            }
            if whole {
                plans[plan].whole.push(index as u32);
            }
            if literals.is_empty() && !needs_value_pass {
                continue;
            }
            let chain = match plans[plan].chains.iter().position(|c| c.transforms == rule.transform) {
                Some(c) => c,
                None => {
                    if plans[plan].chains.len() == 64 {
                        bail!("rule {of}: more than 64 transformation chains on {target}");
                    }
                    plans[plan].chains.push(Chain {
                        transforms: rule.transform.clone(),
                        per_value: Vec::new(),
                        lowers: lowercase,
                        needs: 0,
                    });
                    plans[plan].chains.len() - 1
                }
            };
            let (list, by_text) = &mut patterns[plan];
            for literal in &literals {
                let pattern = match by_text.get(literal) {
                    Some(&p) => p,
                    None => {
                        list.push(literal.clone());
                        plans[plan].pattern_rules.push(Vec::new());
                        by_text.insert(literal.clone(), list.len() - 1);
                        list.len() - 1
                    }
                };
                let entry = (chain as u16, index as u32);
                if !plans[plan].pattern_rules[pattern].contains(&entry) {
                    plans[plan].pattern_rules[pattern].push(entry);
                }
            }
            if needs_value_pass {
                plans[plan].chains[chain].per_value.push(index as u32);
            }
        }
        let number = crate::rule::number_of(&rule.id);
        if let Some(n) = number
            && let Some(other) = compiled.iter().find(|r| r.number == Some(n))
        {
            bail!("rules {} and {of} stand for the same number {n}", other.id);
        }
        compiled.push(CompiledRule {
            id: rule.id.clone(),
            number,
            set,
            msg: rule.msg.clone().unwrap_or_else(|| rule.id.clone()),
            phase: rule.phase,
            score: rule.score.unwrap_or_else(|| rule.severity.score()),
            action: rule.action,
            mode: rule.mode.unwrap_or(mode),
            matcher,
            when,
            unless,
            headers,
            excluded_by,
            severity: rule.severity,
            tags: rule.tags.clone(),
            confidence: rule.confidence,
            refs: rule.refs.clone(),
        });
    }
    for (plan, (list, _)) in plans.iter_mut().zip(patterns) {
        let lowers_for_search = |chain: &Chain| {
            chain
                .transforms
                .iter()
                .position(|&t| t == Transform::Lowercase)
                .is_some_and(|at| chain.transforms[at + 1..].iter().all(|&t| case_independent(t)))
        };
        plan.case_insensitive = !list.is_empty()
            && plan.chains.iter().any(|c| c.lowers)
            && plan.chains.iter().all(|c| !c.lowers || lowers_for_search(c))
            && list.iter().enumerate().all(|(p, literal)| {
                !literal.bytes().any(|b| b.is_ascii_alphabetic())
                    || plan.pattern_rules[p]
                        .iter()
                        .all(|&(chain, _)| plan.chains[chain as usize].lowers)
            });
        for chain in &mut plan.chains {
            chain.needs = super::engine::needs_of(&chain.transforms, plan.case_insensitive);
            plan.needs |= chain.needs;
            plan.has_tests |= !chain.per_value.is_empty();
        }
        if list.is_empty() {
            continue;
        }
        plan.separator = (0u8..0x20)
            .chain([0x7f])
            .find(|&b| !list.iter().any(|literal| literal.as_bytes().contains(&b)));
        // A DFA whatever the pattern count: the pass over a value is a table walk, and the
        // table's hot rows stay cached (the builder's own choice is an NFA over 100 patterns).
        plan.automaton = Some(
            AhoCorasickBuilder::new()
                .match_kind(MatchKind::Standard)
                .kind(Some(AhoCorasickKind::DFA))
                .ascii_case_insensitive(plan.case_insensitive)
                .build(&list)
                .map_err(|e| anyhow!("automaton for {}: {e}", plan.target))?,
        );
    }
    // Per phase, in the order the plans came; the `args.<name>` plans (without whole-target
    // rules) in one map, walked once; the anomaly targets last, since their values come from the
    // decoding of the others.
    let mut phases: [Vec<usize>; 5] = Default::default();
    let mut arg_plans: [FxHashMap<String, usize>; 5] = Default::default();
    for (i, plan) in plans.iter().enumerate() {
        match &plan.target {
            Target::Arg(name) if plan.whole.is_empty() => {
                arg_plans[plan.phase.index()].insert(name.clone(), i);
            }
            _ => phases[plan.phase.index()].push(i),
        }
    }
    let mut anomalies_from = [0usize; 5];
    for (list, from) in phases.iter_mut().zip(&mut anomalies_from) {
        let anomaly = |i: &usize| plans[*i].target.to_string().starts_with("anomaly.");
        list.sort_by_key(anomaly);
        *from = list.iter().position(anomaly).unwrap_or(list.len());
    }
    Ok(Compiled {
        rules: compiled,
        plans,
        phases,
        anomalies_from,
        arg_plans,
        exclusions,
        header_names,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::Path;

    pub(crate) fn sourced(yaml: &str) -> Vec<Sourced> {
        let file: super::super::rule::RulesFile = webfast_core::yaml::from_str(yaml).unwrap();
        file.rules
            .into_iter()
            .map(|rule| Sourced {
                rule,
                base: Path::new(".").to_path_buf(),
            })
            .collect()
    }

    #[test]
    fn literals_of_one_chain_share_an_automaton_mapped_back_to_their_rules() {
        let rules = sourced(
            r#"
rules:
  - id: a
    phase: head
    targets: [args, cookies]
    transform: [url_decode, lowercase]
    operator: { contains_any: ['UNION SELECT', 'sleep('] }
  - id: b
    phase: head
    targets: [args]
    transform: [url_decode, lowercase]
    operator: { regex: 'select\s+\w+\s+from' }
    prefilter: ['select']
  - id: c
    phase: head
    targets: [args]
    operator: { contains_any: ['<script'] }
  - id: d
    phase: head
    targets: [args]
    transform: [url_decode, lowercase]
    operator: { length_gt: 10 }
  - id: e
    phase: head
    targets: [args_count]
    operator: { gt: 3 }
    when: [a]
"#,
        );
        let compiled = compile(&rules, Mode::Block, &[]).unwrap();
        assert_eq!(compiled.rules.len(), 5);
        // Head: args, cookies, args_count; args and args_count again for the body phase.
        assert_eq!(compiled.plans.len(), 5);
        assert_eq!(compiled.phases[Phase::Head.index()].len(), 3);
        assert_eq!(compiled.phases[Phase::Body.index()].len(), 2);
        let args = compiled
            .plans
            .iter()
            .find(|p| p.phase == Phase::Head && p.target == Target::Args)
            .unwrap();
        // The chain of a, b and d, and c's empty one.
        assert_eq!(args.chains.len(), 2);
        assert_eq!(args.chains[0].transforms, [Transform::UrlDecode, Transform::Lowercase]);
        assert!(args.chains[1].transforms.is_empty());
        let ac = args.automaton.as_ref().unwrap();
        let text = "x union select sleep( select a from <script";
        let mut found: Vec<(usize, Vec<(u16, u32)>)> = ac
            .find_overlapping_iter(text)
            .map(|m| (m.start(), args.pattern_rules[m.pattern()].clone()))
            .collect();
        found.sort();
        assert_eq!(
            found,
            [
                (2, vec![(0, 0)]),
                (8, vec![(0, 1)]),
                (15, vec![(0, 0)]),
                (22, vec![(0, 1)]),
                (36, vec![(1, 2)])
            ],
            "lowercased literals, overlapping, each with its chain"
        );
        assert_eq!(args.chains[0].per_value, [3], "length_gt is tested on each value");
        assert!(args.chains[1].per_value.is_empty());
        assert!(args.whole.is_empty());
        assert!(!args.wants_query);
        let count = compiled
            .plans
            .iter()
            .find(|p| p.phase == Phase::Head && p.target == Target::ArgsCount)
            .unwrap();
        assert_eq!(count.whole, [4]);
        assert!(count.automaton.is_none() && count.chains.is_empty());
        assert_eq!(compiled.rules[4].when, [0]);
        assert_eq!(compiled.rules[0].score, 3, "medium by default");
        assert!(matches!(compiled.rules[1].matcher, Matcher::Regex(_)));
    }

    #[test]
    fn compile_refuses_what_cannot_run() {
        let bad = [
            (
                "rules:\n  - {id: a, phase: head, targets: [upload.ext], operator: exists}\n",
                "no value in the head phase",
            ),
            ("rules:\n  - {id: a, phase: head, operator: exists}\n", "no targets"),
            (
                "rules:\n  - {id: a, phase: head, targets: [ua], operator: {gt: 1}}\n",
                "numeric",
            ),
            (
                "rules:\n  - {id: a, phase: head, targets: [ua], operator: exists, when: [zz]}\n",
                "names no rule",
            ),
            (
                "rules:\n  - {id: a, phase: head, targets: [ua], operator: {regex: '('}}\n",
                "regex",
            ),
            (
                "rules:\n  - {id: a, phase: head, targets: [ua], operator: exists, action: header}\n",
                "without `header`",
            ),
            (
                "rules:\n  - {id: a, phase: upload, targets: [upload.head], operator: {magic_is: [doc]}}\n",
                "unknown file type",
            ),
            (
                "rules:\n  - {id: a, phase: connection, operator: exists}\n",
                "connection rule",
            ),
            (
                "rules:\n  - {id: a, phase: head, targets: [ua], operator: exists, refs: {cwe: [CWE89]}}\n",
                "rule a: refs.cwe: \"CWE89\" is not CWE-<number>",
            ),
            (
                "rules:\n  - {id: a, phase: head, targets: [ua], operator: exists, refs: {crs: [9421]}}\n",
                "rule a: refs.crs: 9421",
            ),
            (
                "rules:\n  - {id: a, phase: head, targets: [ua], operator: exists, refs: {urls: ['ftp://x']}}\n",
                "rule a: refs.urls",
            ),
        ];
        for (yaml, expected) in bad {
            let Err(error) = compile(&sourced(yaml), Mode::Block, &[]) else {
                panic!("{yaml} compiled");
            };
            let error = format!("{error:#}");
            assert!(error.contains(expected), "{yaml}: {error}");
        }
        let implicit = compile(
            &sourced("rules:\n  - {id: a, phase: connection, operator: {country_in: [kp]}}\n"),
            Mode::Block,
            &[],
        )
        .unwrap();
        assert_eq!(implicit.plans[0].target, Target::Country);
        assert!(matches!(&implicit.rules[0].matcher, Matcher::CountryIn(codes) if codes == &[*b"KP"]));
    }

    #[test]
    fn a_detector_is_gated_by_its_prefilter_as_a_regex_is() {
        let yaml = "rules:\n  - {id: a, phase: head, targets: [args], transform: [lowercase], operator: detect_sqli, prefilter: [\"'\", UNION]}\n  - {id: b, phase: head, targets: [args], operator: detect_xss}\n";
        let compiled = compile(&sourced(yaml), Mode::Block, &[]);
        if !cfg!(feature = "libinjection") {
            assert!(compiled.is_err(), "without libinjection a detector does not load");
            return;
        }
        let compiled = compiled.unwrap();
        assert!(matches!(compiled.rules[0].matcher, Matcher::DetectSqli));
        let args = compiled
            .plans
            .iter()
            .find(|p| p.phase == Phase::Head && p.target == Target::Args)
            .unwrap();
        let ac = args.automaton.as_ref().unwrap();
        assert_eq!(
            ac.patterns_len(),
            2,
            "the prefilter's literals, lowercased with the chain"
        );
        assert_eq!(args.chains[0].per_value, Vec::<u32>::new(), "gated: no per-value test");
        assert_eq!(args.chains[1].per_value, [1], "no prefilter: tested on every value");
    }

    #[cfg(not(feature = "libinjection"))]
    #[test]
    fn a_detector_does_not_load_without_libinjection() {
        for operator in ["detect_sqli", "detect_xss"] {
            let yaml = format!("rules:\n  - {{id: a, phase: head, targets: [args], operator: {operator}}}\n");
            let Err(error) = compile(&sourced(&yaml), Mode::Block, &[]) else {
                panic!("{operator} compiled");
            };
            let error = format!("{error:#}");
            assert!(
                error.contains(&format!(
                    "rule a: {operator}: this webfast was built without libinjection (cargo feature libinjection)"
                )),
                "{error}"
            );
        }
        // The built-in sets load, without their rules on the detectors.
        let config = super::super::config::RulesConfig::default();
        let (rules, _) = super::super::config::compose(&config, Path::new(".")).unwrap();
        assert!(!rules.iter().any(|r| r.rule.operator.is_libinjection()));
        assert!(rules.iter().any(|r| r.rule.id == "wf-942-100"));
        compile(&rules, Mode::Block, &[]).unwrap();
    }

    #[test]
    fn exclusions_are_attached_to_the_rules_they_name() {
        let rules = sourced(
            r#"
rules:
  - {id: wf-941-100, set: xss, phase: head, targets: [args], operator: {contains_any: ['<script']}}
  - {id: wf-942-100, set: sqli, phase: head, targets: [args], operator: {contains_any: ['union select']}}
  - {id: site-1, phase: head, targets: [args], operator: {contains_any: ['x']}}
"#,
        );
        let exclusions: Vec<ExclusionConfig> = webfast_core::yaml::from_str(
            r#"
- paths: ['/admin/editor/*']
  rules: [wf-941-*]
- paths: ['/api/search']
  targets: [args.q]
- hosts: ['legacy.example.com']
  sets: [sqli]
- paths: ['/off/*']
"#,
        )
        .unwrap();
        let compiled = compile(&rules, Mode::LogOnly, &exclusions).unwrap();
        assert_eq!(compiled.rules[0].excluded_by, [0, 3]);
        assert_eq!(compiled.rules[1].excluded_by, [2, 3]);
        assert_eq!(compiled.rules[2].excluded_by, [3]);
        assert_eq!(compiled.rules[2].set, "site");
        assert_eq!(compiled.rules[2].mode, Mode::LogOnly);
        assert!(compiled.exclusions[0].applies("any.host", "/admin/editor/x"));
        assert!(!compiled.exclusions[0].applies("any.host", "/admin/other"));
        assert!(compiled.exclusions[2].applies("LEGACY.example.com", "/"));
        assert!(!compiled.exclusions[2].applies("www.example.com", "/"));
    }

    #[test]
    fn magic_types_by_their_first_bytes() {
        assert!(Magic::Png.detect(b"\x89PNG\r\n\x1a\n...."));
        assert!(!Magic::Png.detect(b"<?php echo 1;"));
        assert!(Magic::Php.detect(b"GIF89a<?php system($_GET['c']); ?>"));
        assert!(Magic::Script.detect(b"#!/bin/sh\n"));
        assert!(Magic::Svg.detect(b"  <?xml version='1.0'?><svg xmlns=...>"));
        assert!(Magic::Webp.detect(b"RIFF\x00\x00\x00\x00WEBPVP8 "));
        assert_eq!(Magic::of_content_type("image/PNG; charset=x"), Some(Magic::Png));
        assert_eq!(Magic::of_content_type("text/plain"), None);
    }
}
