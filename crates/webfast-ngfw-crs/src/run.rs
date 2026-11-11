//! The rules run over one request (a transaction, `Tx`): each phase's rules in order, a rule
//! matching when every link of its chain does — a link when its operator holds for one of its
//! variables' values, after its transformations (any of them with `multiMatch`). A link that
//! matches sets `MATCHED_VAR(S)` and its captures (`TX.0`–`TX.9`), then runs its `setvar` and `ctl`
//! actions at once, so the next link sees them; the rule's `skipAfter` jumps past its marker.
//!
//! What a rule adds to the CRS's inbound anomaly score at the blocking paranoia level
//! (`tx.inbound_anomaly_score_pl1`… up to `tx.blocking_paranoia_level`) is its hit's score in the
//! filter's evaluation: the filter's threshold decides, not the CRS's blocking rules (949), which
//! are not loaded. A rule above the blocking level (detection only) is written with no score.
//!
//! What a request's values cost is paid once per value and chain of transformations: the value
//! transformed, then one pass of the chain's automaton over it for the literals of the regexes run
//! after that chain (`Program::chains`), kept for the request (`Tx::transformed`). A regex whose
//! literals the value has none of does not run; most do not.

use super::program::{Collection, Ctl, Disruptive, Item, Link, Program, Rule, SetOp, Var, in_ranges};
use super::request::{Pair, Request};
use rustc_hash::FxHashMap;
use std::borrow::Cow;
use std::cell::RefCell;
use webfast_ngfw::plugin::{EngineHit, Found, Verdict};

/// Rule ids, as `first-last` ranges.
type Ranges = Vec<(u32, u32)>;

/// One request's state, kept from phase 1 to phase 2.
pub struct Tx {
    pub req: Request,
    /// `TX`, keys in lower case.
    pub vars: FxHashMap<String, Vec<u8>>,
    /// `MATCHED_VARS`: the last link's matches (the last is `MATCHED_VAR`).
    matched: Vec<Pair>,
    removed_ids: Ranges,
    removed_tags: Vec<String>,
    removed_targets_by_id: Vec<(Ranges, Vec<Var>)>,
    removed_targets_by_tag: Vec<(String, Vec<Var>)>,
    pub processor: Option<String>,
    pub force_body: bool,
    off: bool,
    detection_only: bool,
    unique_id: Vec<u8>,
    pub body_read: bool,
    /// The request's values transformed, by (the value's address and length, the chain): a
    /// value of the request is not freed nor changed while the transaction lives (`Value::stable`).
    cache: RefCell<FxHashMap<(usize, usize, u32), Transformed>>,
    /// Per chain and collection, the candidates of all the collection's values, for the phase
    /// running (the body's values come with phase 2).
    unions: RefCell<FxHashMap<(u32, Collection), u128>>,
}

/// A value after a chain of transformations, and which regexes run after the chain may match it.
struct Transformed {
    /// `None`: the value as it was.
    bytes: Option<Vec<u8>>,
    /// By the chain's candidate slot.
    candidates: u128,
}

impl Tx {
    pub fn new(req: Request, vars: FxHashMap<String, Vec<u8>>, processor: Option<String>, unique_id: u64) -> Tx {
        Tx {
            req,
            vars,
            matched: Vec::new(),
            removed_ids: Vec::new(),
            removed_tags: Vec::new(),
            removed_targets_by_id: Vec::new(),
            removed_targets_by_tag: Vec::new(),
            processor,
            force_body: false,
            off: false,
            detection_only: false,
            unique_id: format!("{unique_id:016x}").into_bytes(),
            body_read: false,
            cache: RefCell::new(FxHashMap::default()),
            unions: RefCell::new(FxHashMap::default()),
        }
    }

    /// Whether some value of the link's variables' collections has the literals of its regex
    /// (a `whole` link's: every variable one of the request's).
    fn any_candidate(&self, program: &Program, link: &Link, slot: u32) -> bool {
        let mut union = 0u128;
        for var in link.vars.iter().filter(|v| !v.exclude) {
            let key = (link.chain, var.collection);
            let known = self.unions.borrow().get(&key).copied();
            let bits = match known {
                Some(bits) => bits,
                None => {
                    let mut bits = 0u128;
                    each(self, var.collection, &mut |_, _, bytes| {
                        bits |= self.transformed(program, link.chain, &bytes, |t| t.candidates);
                    });
                    self.unions.borrow_mut().insert(key, bits);
                    bits
                }
            };
            union |= bits;
            if union & (1 << slot) != 0 {
                return true;
            }
        }
        false
    }

    /// `value` (one of the request's, `Value::stable`) through `chain`, with its candidates:
    /// worked out at its first use in the request; `f` reads it.
    fn transformed<R>(&self, program: &Program, chain: u32, value: &[u8], f: impl FnOnce(&Transformed) -> R) -> R {
        let key = (value.as_ptr() as usize, value.len(), chain);
        if let Some(done) = self.cache.borrow().get(&key) {
            return f(done);
        }
        let c = &program.chains[chain as usize];
        let mut current: Option<Vec<u8>> = None;
        for t in &c.transforms {
            let input = current.as_deref().unwrap_or(value);
            if t.changes(input) {
                current = Some(t.apply(input));
            }
        }
        let bytes = current.filter(|b| b != value);
        let text = bytes.as_deref().unwrap_or(value);
        let mut candidates = 0u128;
        if let Some(automaton) = &c.automaton {
            for m in automaton.find_overlapping_iter(text) {
                candidates |= 1 << c.slots[m.pattern().as_usize()];
            }
        }
        let done = Transformed { bytes, candidates };
        let r = f(&done);
        self.cache.borrow_mut().insert(key, done);
        r
    }

    fn removed(&self, rule: &Rule) -> bool {
        in_ranges(&self.removed_ids, rule.id)
            || rule
                .tags
                .iter()
                .any(|t| self.removed_tags.iter().any(|r| r.eq_ignore_ascii_case(t)))
    }

    /// The inbound anomaly score at the blocking paranoia level.
    fn score(&self) -> i64 {
        const LEVELS: [&str; 4] = [
            "inbound_anomaly_score_pl1",
            "inbound_anomaly_score_pl2",
            "inbound_anomaly_score_pl3",
            "inbound_anomaly_score_pl4",
        ];
        let level = self
            .vars
            .get("blocking_paranoia_level")
            .map_or(1, |v| atoi(v))
            .clamp(1, 4) as usize;
        LEVELS[..level]
            .iter()
            .map(|key| self.vars.get(*key).map_or(0, |v| atoi(v)))
            .sum()
    }
}

/// One value of a variable.
struct Value<'a> {
    collection: Collection,
    key: Cow<'a, str>,
    keyed: bool,
    bytes: Cow<'a, [u8]>,
}

impl Value<'_> {
    /// One of the request's own values, borrowed: neither freed nor changed while the transaction
    /// lives, so its address keys the cache (`TX`, the matched variables, the body processor and
    /// the values made on the fly change or go).
    fn stable(&self) -> bool {
        matches!(self.bytes, Cow::Borrowed(_))
            && !matches!(
                self.collection,
                Collection::Tx
                    | Collection::MatchedVar
                    | Collection::MatchedVarName
                    | Collection::MatchedVars
                    | Collection::MatchedVarsNames
                    | Collection::ReqbodyProcessor
            )
    }
}

impl Value<'_> {
    fn name(&self) -> String {
        if self.keyed {
            format!("{}:{}", self.collection.name(), self.key)
        } else {
            self.collection.name().to_string()
        }
    }
}

/// A link's match, owned: the name, the value as the operator saw it, the captures.
struct Match {
    name: String,
    value: Vec<u8>,
    captures: Vec<Vec<u8>>,
}

fn atoi(text: &[u8]) -> i64 {
    let text = text.trim_ascii();
    let (negative, digits) = match text.first() {
        Some(b'-') => (true, &text[1..]),
        Some(b'+') => (false, &text[1..]),
        _ => (false, text),
    };
    let n = digits
        .iter()
        .take_while(|b| b.is_ascii_digit())
        .fold(0i64, |a, &b| a.saturating_mul(10).saturating_add((b - b'0') as i64));
    if negative { -n } else { n }
}

/// Calls `f` with each value of `collection` (its key, whether it has one, the value).
fn each<'a>(tx: &'a Tx, collection: Collection, f: &mut dyn FnMut(Cow<'a, str>, bool, Cow<'a, [u8]>)) {
    let r = &tx.req;
    let pairs = |list: &'a [Pair], f: &mut dyn FnMut(Cow<'a, str>, bool, Cow<'a, [u8]>)| {
        for p in list {
            f(Cow::Borrowed(p.name.as_str()), true, Cow::Borrowed(p.value.as_slice()));
        }
    };
    let names = |list: &'a [Pair], f: &mut dyn FnMut(Cow<'a, str>, bool, Cow<'a, [u8]>)| {
        for p in list {
            f(Cow::Borrowed(p.name.as_str()), true, Cow::Borrowed(p.name.as_bytes()));
        }
    };
    let one = |bytes: &'a [u8], f: &mut dyn FnMut(Cow<'a, str>, bool, Cow<'a, [u8]>)| {
        f(Cow::Borrowed(""), false, Cow::Borrowed(bytes));
    };
    let owned = |bytes: Vec<u8>, f: &mut dyn FnMut(Cow<'a, str>, bool, Cow<'a, [u8]>)| {
        f(Cow::Borrowed(""), false, Cow::Owned(bytes));
    };
    match collection {
        Collection::Args => {
            pairs(&r.args_get, f);
            pairs(&r.args_post, f);
        }
        Collection::ArgsNames => {
            names(&r.args_get, f);
            names(&r.args_post, f);
        }
        Collection::ArgsGet => pairs(&r.args_get, f),
        Collection::ArgsGetNames => names(&r.args_get, f),
        Collection::ArgsPost => pairs(&r.args_post, f),
        Collection::ArgsPostNames => names(&r.args_post, f),
        Collection::ArgsCombinedSize => {
            let size: usize = r
                .args_get
                .iter()
                .chain(&r.args_post)
                .map(|p| p.name.len() + p.value.len())
                .sum();
            owned(size.to_string().into_bytes(), f);
        }
        Collection::RequestHeaders => pairs(&r.headers, f),
        Collection::RequestHeadersNames => names(&r.headers, f),
        Collection::RequestCookies => pairs(&r.cookies, f),
        Collection::RequestCookiesNames => names(&r.cookies, f),
        Collection::RequestFilename => one(&r.filename, f),
        Collection::RequestBasename => one(&r.basename, f),
        Collection::RequestUri => one(&r.uri, f),
        Collection::RequestUriRaw => one(&r.uri_raw, f),
        Collection::RequestLine => one(&r.line, f),
        Collection::RequestMethod => one(&r.method, f),
        Collection::RequestProtocol => one(&r.protocol, f),
        Collection::QueryString => one(&r.query, f),
        Collection::RequestBody => {
            if let Some(body) = &r.body {
                one(body, f);
            }
        }
        Collection::RequestBodyLength => owned(r.body_length.to_string().into_bytes(), f),
        Collection::Files => pairs(&r.files, f),
        Collection::FilesNames => names(&r.files, f),
        Collection::FilesSizes => pairs(&r.files_sizes, f),
        Collection::FilesCombinedSize => {
            let size: i64 = r.files_sizes.iter().map(|p| atoi(&p.value)).sum();
            owned(size.to_string().into_bytes(), f);
        }
        Collection::MultipartPartHeaders => pairs(&r.multipart_headers, f),
        Collection::ReqbodyProcessor => {
            if let Some(p) = &tx.processor {
                one(p.as_bytes(), f);
            }
        }
        Collection::ReqbodyError => one(if r.body_error { b"1" } else { b"0" }, f),
        Collection::RemoteAddr => one(&r.remote_addr, f),
        Collection::ServerName => one(&r.server_name, f),
        Collection::UniqueId => one(&tx.unique_id, f),
        Collection::Tx => {
            for (k, v) in &tx.vars {
                f(Cow::Borrowed(k.as_str()), true, Cow::Borrowed(v.as_slice()));
            }
        }
        Collection::MatchedVar => {
            if let Some(m) = tx.matched.last() {
                one(&m.value, f);
            }
        }
        Collection::MatchedVarName => {
            if let Some(m) = tx.matched.last() {
                one(m.name.as_bytes(), f);
            }
        }
        Collection::MatchedVars => {
            for m in &tx.matched {
                f(Cow::Borrowed(m.name.as_str()), true, Cow::Borrowed(m.value.as_slice()));
            }
        }
        Collection::MatchedVarsNames => {
            for m in &tx.matched {
                f(Cow::Borrowed(m.name.as_str()), true, Cow::Borrowed(m.name.as_bytes()));
            }
        }
        Collection::Xml => {
            if let Some(text) = &r.xml_text {
                f(Cow::Borrowed("/*"), true, Cow::Borrowed(text.as_slice()));
            }
            for a in &r.xml_attrs {
                f(Cow::Borrowed("//@*"), true, Cow::Borrowed(a.as_slice()));
            }
        }
        Collection::Empty => {}
    }
}

/// A link's values: its variables less its exclusions and the request's (`ctl`), counts for `&`.
fn values<'a>(tx: &'a Tx, rule: &Rule, link: &Link, first: bool) -> Vec<Value<'a>> {
    let mut exclusions: Vec<&Var> = Vec::new();
    if link.vars.iter().any(|v| v.exclude) {
        exclusions.extend(link.vars.iter().filter(|v| v.exclude));
    }
    if first && !(tx.removed_targets_by_id.is_empty() && tx.removed_targets_by_tag.is_empty()) {
        for (ids, vars) in &tx.removed_targets_by_id {
            if in_ranges(ids, rule.id) {
                exclusions.extend(vars);
            }
        }
        for (tag, vars) in &tx.removed_targets_by_tag {
            if rule.tags.iter().any(|t| t.eq_ignore_ascii_case(tag)) {
                exclusions.extend(vars);
            }
        }
    }
    let excluded = |collection: Collection, key: &str| {
        !exclusions.is_empty()
            && exclusions
                .iter()
                .any(|e| e.collection == collection && e.selector.as_ref().is_none_or(|s| s.matches(key)))
    };
    let mut out = Vec::new();
    for var in link.vars.iter().filter(|v| !v.exclude) {
        // `TX:name`: one lookup, not a walk of every variable (TX's keys are lower case, and so
        // is the selector).
        if var.collection == Collection::Tx
            && let Some(super::program::Select::Key(k)) = &var.selector
        {
            let found = tx.vars.get_key_value(k.as_str());
            if var.count {
                out.push(Value {
                    collection: var.collection,
                    key: Cow::Borrowed(""),
                    keyed: false,
                    bytes: Cow::Borrowed(if found.is_some() { b"1" } else { b"0" }),
                });
            } else if let Some((key, value)) = found
                && !excluded(var.collection, key)
            {
                out.push(Value {
                    collection: var.collection,
                    key: Cow::Borrowed(key.as_str()),
                    keyed: true,
                    bytes: Cow::Borrowed(value.as_slice()),
                });
            }
            continue;
        }
        if var.count {
            let mut n = 0usize;
            each(tx, var.collection, &mut |key, _, _| {
                if var.selector.as_ref().is_none_or(|s| s.matches(&key)) {
                    n += 1;
                }
            });
            out.push(Value {
                collection: var.collection,
                key: Cow::Borrowed(""),
                keyed: false,
                bytes: Cow::Owned(n.to_string().into_bytes()),
            });
            continue;
        }
        each(tx, var.collection, &mut |key, keyed, bytes| {
            if var.selector.as_ref().is_some_and(|s| !s.matches(&key)) {
                return;
            }
            if keyed && excluded(var.collection, &key) || !keyed && excluded(var.collection, "") {
                return;
            }
            out.push(Value {
                collection: var.collection,
                key,
                keyed,
                bytes,
            });
        });
    }
    out
}

/// A macro's variable: `TX`, `MATCHED_VAR(_NAME)`, or the first value of another variable.
fn resolve(tx: &Tx, collection: &str, key: Option<&str>) -> Option<Vec<u8>> {
    match (collection, key) {
        ("TX", Some(k)) => tx.vars.get(k).cloned(),
        ("MATCHED_VAR", None) => tx.matched.last().map(|m| m.value.clone()),
        ("MATCHED_VAR_NAME", None) => tx.matched.last().map(|m| m.name.clone().into_bytes()),
        _ => {
            let c = Collection::parse(collection).ok()?;
            let mut found = None;
            each(tx, c, &mut |k, _, v| {
                if found.is_none() && key.is_none_or(|key| k.eq_ignore_ascii_case(key)) {
                    found = Some(v.into_owned());
                }
            });
            found
        }
    }
}

/// Whether the link matches; its matches when it does.
fn eval_link(program: &Program, tx: &Tx, rule: &Rule, link: &Link, first: bool) -> Option<Vec<Match>> {
    let values = values(tx, rule, link, first);
    if values.is_empty() {
        return None;
    }
    let arg: Cow<[u8]> = match &link.op.fixed_arg {
        Some(text) => Cow::Borrowed(text.as_slice()),
        None => Cow::Owned(link.op.arg.expand(&mut |c, k| resolve(tx, c, k))),
    };
    let mut matches = Vec::new();
    let mut found = super::ops::Matched::default();
    for v in &values {
        let chain = &program.chains[link.chain as usize];
        if !link.multi_match && chain.transforms.is_empty() && chain.automaton.is_none() {
            // Nothing to transform nor to look up: the value as it is.
            if link.op.test(&v.bytes, &arg, link.capture, &mut found) != link.op.negated {
                matches.push(Match {
                    name: v.name(),
                    value: v.bytes.to_vec(),
                    captures: std::mem::take(&mut found.captures),
                });
            }
            continue;
        }
        if !link.multi_match && v.stable() {
            // Transformed once per request; a regex none of whose literals it has, not run.
            let hit = tx.transformed(program, link.chain, &v.bytes, |done| {
                if link.prefilter.is_some_and(|slot| done.candidates & (1 << slot) == 0) {
                    return None;
                }
                let text = done.bytes.as_deref().unwrap_or(&v.bytes);
                (link.op.test(text, &arg, link.capture, &mut found) != link.op.negated).then(|| text.to_vec())
            });
            if let Some(value) = hit {
                matches.push(Match {
                    name: v.name(),
                    value,
                    captures: std::mem::take(&mut found.captures),
                });
            }
            continue;
        }
        let mut current: Cow<[u8]> = Cow::Borrowed(v.bytes.as_ref());
        let tested = |text: &[u8], found: &mut super::ops::Matched| {
            link.op.test(text, &arg, link.capture, found) != link.op.negated
        };
        let mut hit: Option<Vec<u8>> = None;
        if link.multi_match && tested(&current, &mut found) {
            hit = Some(current.to_vec());
        }
        if hit.is_none() {
            for t in &link.transforms {
                let next = t.apply(&current);
                let changed = next != *current;
                current = Cow::Owned(next);
                if link.multi_match && changed && tested(&current, &mut found) {
                    hit = Some(current.to_vec());
                    break;
                }
            }
        }
        if hit.is_none() && !link.multi_match && tested(&current, &mut found) {
            hit = Some(current.to_vec());
        }
        if let Some(value) = hit {
            matches.push(Match {
                name: v.name(),
                value,
                captures: std::mem::take(&mut found.captures),
            });
        }
    }
    (!matches.is_empty()).then_some(matches)
}

/// A link matched: for each value that matched, in order, as ModSecurity runs a rule's
/// non-disruptive actions per match — `MATCHED_VAR` that value (`MATCHED_VARS` the matches so far),
/// its captures (`capture`), then the link's `setvar`s; then its `ctl`s, once.
fn apply(tx: &mut Tx, link: &Link, matches: &[Match]) {
    tx.matched.clear();
    for m in matches {
        tx.matched.push(Pair {
            name: m.name.clone(),
            value: m.value.clone(),
        });
        if link.capture && !m.captures.is_empty() {
            for i in 0..10 {
                tx.vars.remove(&i.to_string());
            }
            for (i, c) in m.captures.iter().enumerate().take(10) {
                tx.vars.insert(i.to_string(), c.clone());
            }
        }
        setvars(tx, link);
    }
    for ctl in &link.ctls {
        match ctl {
            Ctl::RemoveById(ranges) => tx.removed_ids.extend(ranges),
            Ctl::RemoveByTag(tag) => tx.removed_tags.push(tag.clone()),
            Ctl::RemoveTargetById(ids, vars) => tx.removed_targets_by_id.push((ids.clone(), vars.clone())),
            Ctl::RemoveTargetByTag(tag, vars) => tx.removed_targets_by_tag.push((tag.clone(), vars.clone())),
            Ctl::BodyProcessor(p) => tx.processor = Some(p.clone()),
            Ctl::ForceBodyVariable => tx.force_body = true,
            Ctl::EngineOff => tx.off = true,
            Ctl::EngineDetectionOnly => tx.detection_only = true,
            Ctl::Ignored => {}
        }
    }
}

/// A link's `setvar`s, macros expanded against the transaction as it is.
fn setvars(tx: &mut Tx, link: &Link) {
    for set in &link.setvars {
        let key: Cow<str> = match &set.fixed_key {
            Some(k) => Cow::Borrowed(k.as_str()),
            None => {
                Cow::Owned(String::from_utf8_lossy(&set.key.expand(&mut |c, k| resolve(tx, c, k))).to_ascii_lowercase())
            }
        };
        if key.is_empty() {
            continue;
        }
        match &set.op {
            SetOp::Delete => {
                tx.vars.remove(key.as_ref());
            }
            SetOp::Set(m) => {
                let v = match &set.fixed_value {
                    Some(v) => v.clone(),
                    None => m.expand(&mut |c, k| resolve(tx, c, k)),
                };
                match tx.vars.get_mut(key.as_ref()) {
                    Some(old) => *old = v,
                    None => {
                        tx.vars.insert(key.into_owned(), v);
                    }
                }
            }
            SetOp::Add(m) | SetOp::Sub(m) => {
                // `+%{tx.critical_anomaly_score}`: the number read where it is, not copied.
                let n = match (&set.fixed_value, m.single()) {
                    (Some(v), _) => atoi(v),
                    (None, Some(("TX", Some(k)))) => tx.vars.get(k).map_or(0, |v| atoi(v)),
                    _ => atoi(&m.expand(&mut |c, k| resolve(tx, c, k))),
                };
                let n = if matches!(set.op, SetOp::Add(_)) { n } else { -n };
                match tx.vars.get_mut(key.as_ref()) {
                    Some(old) => {
                        let new = atoi(old) + n;
                        old.clear();
                        let _ = std::io::Write::write_fmt(old, format_args!("{new}"));
                    }
                    None => {
                        tx.vars.insert(key.into_owned(), n.to_string().into_bytes());
                    }
                }
            }
        }
    }
}

/// The rules of `phase` (0: the head, 1: the body) over the transaction; hits go to `found`.
pub fn run(program: &Program, phase: usize, tx: &mut Tx, found: &mut Found<'_>) {
    // The candidates of phase 1 do not know the body's values.
    tx.unions.borrow_mut().clear();
    let items = &program.phases[phase];
    let jumps = &program.jumps[phase];
    let mut i = 0;
    while i < items.len() {
        if tx.off || found.stopped() {
            return;
        }
        let Item::Rule(r) = &items[i] else {
            i += 1;
            continue;
        };
        let rule = &program.rules[*r];
        if tx.removed(rule) {
            i += 1;
            continue;
        }
        // The score is looked at only around a rule that may change it.
        let scores = rule.links.iter().any(|l| !l.setvars.is_empty());
        let before = if scores { tx.score() } else { 0 };
        let mut first: Option<(String, Vec<u8>)> = None;
        let mut matched = true;
        for (k, link) in rule.links.iter().enumerate() {
            // A regex none of whose literals any of the values it reads has: no match, the values
            // not gathered.
            if link.whole
                && let Some(slot) = link.prefilter
                && !tx.any_candidate(program, link, slot)
            {
                matched = false;
                break;
            }
            match eval_link(program, tx, rule, link, k == 0) {
                Some(matches) => {
                    if k == 0 {
                        let m = &matches[0];
                        let shown = if link.capture && !m.captures.is_empty() {
                            m.captures[0].clone()
                        } else {
                            m.value.clone()
                        };
                        first = Some((m.name.clone(), shown));
                    }
                    apply(tx, link, &matches);
                }
                None => {
                    matched = false;
                    break;
                }
            }
        }
        if !matched {
            i += 1;
            continue;
        }
        let score = if scores { (tx.score() - before).max(0) as u32 } else { 0 };
        let verdict = match rule.disruptive {
            Disruptive::Deny => Some(Verdict::Block),
            Disruptive::Allow => Some(Verdict::Pass),
            Disruptive::Pass if score > 0 => Some(Verdict::Score),
            Disruptive::Pass if rule.log && !rule.msg.pieces.is_empty() => Some(Verdict::Log),
            Disruptive::Pass => None,
        };
        if let Some(verdict) = verdict {
            let (verdict, score) = if tx.detection_only {
                (Verdict::Log, 0)
            } else {
                (verdict, score)
            };
            let (target, value) = first.unwrap_or_default();
            let param = target
                .strip_prefix("ARGS:")
                .or_else(|| target.strip_prefix("ARGS_GET:"))
                .or_else(|| target.strip_prefix("ARGS_POST:"));
            // `logdata` as ModSecurity expands it, at the chain's end.
            let data = (!rule.logdata.pieces.is_empty())
                .then(|| String::from_utf8_lossy(&rule.logdata.expand(&mut |c, k| resolve(tx, c, k))).into_owned());
            found.hit(EngineHit {
                rule: &rule.info,
                target: &target,
                param,
                matched: &String::from_utf8_lossy(&value),
                data: data.as_deref(),
                score,
                verdict,
            });
        }
        i = jumps.get(i).copied().flatten().unwrap_or(i + 1);
    }
}
