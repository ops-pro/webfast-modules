//! Rule engines from other crates (docs/ngfw.md "Rule engines"): a ruleset with semantics of its
//! own — the OWASP CRS in SecLang (the webfast-ngfw-crs crate) — run beside the built-in engine
//! over the same parsed request, its hits counted in the same evaluation: one decision, one log
//! line, one ban list, one challenge, go-ftw's markers for all.
//!
//! A crate registers its `Factory` once per process (`register`; webfast's src/compose.rs does it
//! for the engines it is built with). A registered engine is on: the file's `engines.<name>` is its
//! configuration (none: its defaults), `engines.<name>: false` turns it off. While one is on,
//! `rules.builtin` left out means the sets the engines name (`Factory::builtin_sets`), not all of
//! them: the CRS numbers its rules as the built-in sets do.

use super::engine::{Evaluation, Input};
use super::rule::{Phase, Severity};
use super::source::HitSource;
use anyhow::Result;
use std::any::Any;
use std::path::Path;
use std::sync::{Arc, Mutex};

/// What an engine is made from.
pub trait Factory: Send + Sync {
    /// The name in the file (`engines.<name>`) and in the log (each hit's `set` starts with it).
    fn name(&self) -> &'static str;
    /// The built-in sets left on while this engine is (`rules.builtin` not given).
    fn builtin_sets(&self) -> &'static [&'static str];
    /// The engine from its configuration (`Value::Null` when the file has none), its files
    /// relative to `base`.
    fn load(&self, config: &serde_json::Value, base: &Path) -> Result<Box<dyn Engine>>;
}

/// A loaded engine, shared by every request until a reload.
pub trait Engine: Send + Sync {
    /// Lines for `webfast validate` and the start (what was loaded).
    fn summary(&self) -> Vec<String>;
    /// Whether it has rules for `phase` (`Head`: the request's head; `Body`: its body, run with
    /// `input.body` `None` when there is none to read).
    fn runs_in(&self, phase: Phase) -> bool;
    /// Its rules of `phase` over `input`; what matched goes to `found`. `state` is the request's,
    /// kept from phase to phase (`None` at the first).
    fn run(&self, phase: Phase, input: &Input<'_>, state: &mut EngineState, found: &mut Found<'_>);
}

/// An engine's state of one request (its variables, the rules it removed for the request).
pub type EngineState = Option<Box<dyn Any + Send>>;

/// A rule of an engine, as the log writes it.
#[derive(Debug, Clone)]
pub struct EngineRule {
    /// `942100`.
    pub id: String,
    /// The number go-ftw looks for (`ruleId`).
    pub number: Option<u32>,
    /// `crs-942`: the engine's name and the rule's file.
    pub set: String,
    pub severity: Severity,
    pub tags: Vec<String>,
    pub msg: String,
}

/// What a hit of an engine does to the request.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Verdict {
    /// Its score is added (the anomaly scoring of the CRS).
    Score,
    /// Refused whatever the score (`deny`).
    Block,
    /// Written with the others, no score.
    Log,
    /// Nothing more is checked (`allow`).
    Pass,
}

/// One rule of an engine that matched.
pub struct EngineHit<'a> {
    pub rule: &'a Arc<EngineRule>,
    /// What it matched in: `ARGS:q`, `REQUEST_HEADERS:user-agent` (SecLang's names: the log
    /// classes the matched text by it, src/source.rs).
    pub target: &'a str,
    /// The variables the other links of a chain matched in (`data` may carry their values): the
    /// log hides `data` as the most hidden of them and `target`.
    pub chain: &'a [String],
    /// What matched.
    pub matched: &'a str,
    /// The rule's own words on the match (the CRS's `logdata`), if any.
    pub data: Option<&'a str>,
    /// Counted under the file's `mode`.
    pub score: u32,
    pub verdict: Verdict,
}

/// Where an engine puts its hits: the request's evaluation.
pub struct Found<'a> {
    pub(crate) evaluation: &'a mut Evaluation,
    pub(crate) log_matched: usize,
    /// The request: what a source is worked out from (its URI, its `Referer`).
    pub(crate) parts: &'a http::request::Parts,
    /// The file's `mode`: how a hit counts.
    pub(crate) mode: super::rule::Mode,
}

impl Found<'_> {
    /// One rule matched: written with the request, counted under the file's `mode`. The matched
    /// text and the data are cut to `log.matched` (none with 0), and shown as their sources let
    /// them (src/source.rs).
    pub fn hit(&mut self, hit: EngineHit<'_>) {
        let matched = super::engine::cut(hit.matched, self.log_matched).to_string();
        let data = match hit.data {
            Some(d) if self.log_matched > 0 && !d.is_empty() => {
                Some(super::engine::cut(d, self.log_matched).to_string())
            }
            _ => None,
        };
        let policy = webfast_core::privacy::policy();
        let source = HitSource::of_seclang(hit.target, self.parts, &policy);
        let data_source = hit.chain.iter().fold(source.clone(), |most, variable| {
            most.most_hidden(HitSource::of_seclang(variable, self.parts, &policy), &policy)
        });
        self.evaluation.engine_hit(
            Arc::clone(hit.rule),
            hit.target,
            matched,
            data,
            (source, data_source),
            hit.score,
            hit.verdict,
            self.mode,
        );
    }

    /// Whether the request is decided (a `Block` or `Pass`): nothing more need run.
    pub fn stopped(&self) -> bool {
        self.evaluation.is_stopped()
    }
}

static REGISTERED: Mutex<Vec<&'static dyn Factory>> = Mutex::new(Vec::new());

/// Registers an engine for every file loaded from now on; a second registration of a name is
/// ignored.
pub fn register(factory: &'static dyn Factory) {
    let mut registered = REGISTERED.lock().unwrap_or_else(|e| e.into_inner());
    if !registered.iter().any(|f| f.name() == factory.name()) {
        registered.push(factory);
    }
}

/// The engines registered, in the order they were.
pub(crate) fn registered() -> Vec<&'static dyn Factory> {
    REGISTERED.lock().unwrap_or_else(|e| e.into_inner()).clone()
}

/// An engine of the file; its place in the list is the place of its state in the evaluation.
pub(crate) struct Loaded {
    pub name: &'static str,
    pub engine: Box<dyn Engine>,
}

/// The engines on for a file: every registered one but those set to `false`; a name not
/// registered is an error, but with `false` (turned off where it is not built either: a file for
/// builds with and without it).
pub(crate) fn load(
    configs: &std::collections::BTreeMap<String, serde_json::Value>,
    base: &Path,
) -> Result<Vec<Loaded>> {
    let registered = registered();
    for (name, config) in configs {
        if !registered.iter().any(|f| f.name() == name) && *config != serde_json::Value::Bool(false) {
            let known: Vec<_> = registered.iter().map(|f| f.name()).collect();
            anyhow::bail!(
                "engines.{name}: no such rule engine in this webfast (built with: {})",
                if known.is_empty() {
                    "none".to_string()
                } else {
                    known.join(", ")
                }
            );
        }
    }
    let mut loaded = Vec::new();
    for factory in registered {
        let config = configs.get(factory.name()).cloned().unwrap_or(serde_json::Value::Null);
        if config == serde_json::Value::Bool(false) {
            continue;
        }
        let config = if config == serde_json::Value::Bool(true) {
            serde_json::Value::Null
        } else {
            config
        };
        let engine = factory
            .load(&config, base)
            .map_err(|e| e.context(format!("engines.{}", factory.name())))?;
        loaded.push(Loaded {
            name: factory.name(),
            engine,
        });
    }
    Ok(loaded)
}

/// The built-in sets the engines on leave on (`rules.builtin` not given); `None`: no engine is on.
pub(crate) fn builtin_sets(
    configs: &std::collections::BTreeMap<String, serde_json::Value>,
) -> Option<Vec<&'static str>> {
    let on: Vec<_> = registered()
        .into_iter()
        .filter(|f| configs.get(f.name()) != Some(&serde_json::Value::Bool(false)))
        .collect();
    if on.is_empty() {
        return None;
    }
    let mut sets: Vec<&'static str> = Vec::new();
    for factory in on {
        for set in factory.builtin_sets() {
            if !sets.contains(set) {
                sets.push(set);
            }
        }
    }
    Some(sets)
}

/// Runs `engine` alone over a request's phases, in order, as the filter would after its own rules
/// (an engine's tests, tools): the evaluation its hits made, counted under `mode`.
pub fn evaluate(engine: &dyn Engine, phases: &[(Phase, &Input<'_>)], mode: super::rule::Mode) -> Evaluation {
    let mut evaluation = Evaluation::new();
    let mut state: EngineState = None;
    for (phase, input) in phases {
        if evaluation.is_stopped() {
            break;
        }
        evaluation.phase = *phase;
        let mut found = Found {
            evaluation: &mut evaluation,
            log_matched: 200,
            parts: input.parts,
            mode,
        };
        engine.run(*phase, input, &mut state, &mut found);
    }
    evaluation
}
