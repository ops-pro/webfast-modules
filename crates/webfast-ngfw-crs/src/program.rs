//! The rules compiled from the directives: each rule with its chain of links (variables,
//! transformations, operator, the actions run when the link matches), its metadata for the log,
//! and where its `skipAfter` lands; the rules of phases 1 and 2 in file order with the markers.
//! Directives that change rules already read (`SecRuleUpdateTargetById`, `SecRuleRemoveById`, …)
//! are applied as they come; the engine's own configuration (`SecRuleEngine`, the audit log, the
//! body limits) is webfast's to set, so those directives are read and left without effect.

use super::macros::Macro;
use super::ops::Operator;
use super::seclang::{self, Directive, Selector, Variable};
use super::transform::Transform;
use anyhow::{Context, Result, anyhow, bail};
use regex::bytes::Regex;
use std::sync::Arc;
use webfast_ngfw::plugin::EngineRule;
use webfast_ngfw::rule::Severity;

/// The phases run (`phase:1` the head, `phase:2` the body); later phases are the response's.
pub const PHASES: usize = 2;

/// A variable of a link with its selector compiled.
#[derive(Debug, Clone)]
pub struct Var {
    pub collection: Collection,
    pub selector: Option<Select>,
    pub count: bool,
    pub exclude: bool,
}

#[derive(Debug, Clone)]
pub enum Select {
    Key(String),
    Regex(Regex),
}

impl Select {
    pub fn matches(&self, key: &str) -> bool {
        match self {
            Select::Key(k) => k.eq_ignore_ascii_case(key),
            Select::Regex(re) => re.is_match(key.as_bytes()),
        }
    }
}

/// The collections and single variables known (request.rs gives their values).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Collection {
    Args,
    ArgsNames,
    ArgsGet,
    ArgsGetNames,
    ArgsPost,
    ArgsPostNames,
    ArgsCombinedSize,
    RequestHeaders,
    RequestHeadersNames,
    RequestCookies,
    RequestCookiesNames,
    RequestFilename,
    RequestBasename,
    RequestUri,
    RequestUriRaw,
    RequestLine,
    RequestMethod,
    RequestProtocol,
    QueryString,
    RequestBody,
    RequestBodyLength,
    Files,
    FilesNames,
    FilesSizes,
    FilesCombinedSize,
    MultipartPartHeaders,
    ReqbodyProcessor,
    ReqbodyError,
    RemoteAddr,
    ServerName,
    UniqueId,
    Tx,
    MatchedVar,
    MatchedVarName,
    MatchedVars,
    MatchedVarsNames,
    /// `XML:/*` (the document's text) and `XML://@*` (its attributes' values); other XPaths have
    /// no values.
    Xml,
    /// Kept empty: XML bodies are not parsed, the response is not in these phases, and there are no
    /// persistent collections.
    Empty,
}

impl Collection {
    pub fn parse(name: &str) -> Result<Collection> {
        Ok(match name {
            "ARGS" => Collection::Args,
            "ARGS_NAMES" => Collection::ArgsNames,
            "ARGS_GET" => Collection::ArgsGet,
            "ARGS_GET_NAMES" => Collection::ArgsGetNames,
            "ARGS_POST" => Collection::ArgsPost,
            "ARGS_POST_NAMES" => Collection::ArgsPostNames,
            "ARGS_COMBINED_SIZE" => Collection::ArgsCombinedSize,
            "REQUEST_HEADERS" => Collection::RequestHeaders,
            "REQUEST_HEADERS_NAMES" => Collection::RequestHeadersNames,
            "REQUEST_COOKIES" => Collection::RequestCookies,
            "REQUEST_COOKIES_NAMES" => Collection::RequestCookiesNames,
            "REQUEST_FILENAME" => Collection::RequestFilename,
            "REQUEST_BASENAME" => Collection::RequestBasename,
            "REQUEST_URI" => Collection::RequestUri,
            "REQUEST_URI_RAW" => Collection::RequestUriRaw,
            "REQUEST_LINE" => Collection::RequestLine,
            "REQUEST_METHOD" => Collection::RequestMethod,
            "REQUEST_PROTOCOL" => Collection::RequestProtocol,
            "QUERY_STRING" => Collection::QueryString,
            "REQUEST_BODY" => Collection::RequestBody,
            "REQUEST_BODY_LENGTH" => Collection::RequestBodyLength,
            "FILES" => Collection::Files,
            "FILES_NAMES" => Collection::FilesNames,
            "FILES_SIZES" => Collection::FilesSizes,
            "FILES_COMBINED_SIZE" => Collection::FilesCombinedSize,
            "MULTIPART_PART_HEADERS" => Collection::MultipartPartHeaders,
            "REQBODY_PROCESSOR" => Collection::ReqbodyProcessor,
            "REQBODY_ERROR" => Collection::ReqbodyError,
            "REMOTE_ADDR" => Collection::RemoteAddr,
            "SERVER_NAME" => Collection::ServerName,
            "UNIQUE_ID" => Collection::UniqueId,
            "TX" => Collection::Tx,
            "MATCHED_VAR" => Collection::MatchedVar,
            "MATCHED_VAR_NAME" => Collection::MatchedVarName,
            "MATCHED_VARS" => Collection::MatchedVars,
            "MATCHED_VARS_NAMES" => Collection::MatchedVarsNames,
            "XML" => Collection::Xml,
            "RESPONSE_BODY"
            | "RESPONSE_HEADERS"
            | "RESPONSE_HEADERS_NAMES"
            | "RESPONSE_STATUS"
            | "RESPONSE_PROTOCOL"
            | "RESPONSE_CONTENT_TYPE"
            | "RESPONSE_CONTENT_LENGTH"
            | "ENV"
            | "GEO"
            | "IP"
            | "GLOBAL"
            | "SESSION"
            | "USER"
            | "RESOURCE"
            | "MULTIPART_STRICT_ERROR"
            | "MULTIPART_UNMATCHED_BOUNDARY"
            | "REQBODY_ERROR_MSG"
            | "INBOUND_DATA_ERROR"
            | "OUTBOUND_DATA_ERROR"
            | "WEBSERVER_ERROR_LOG" => Collection::Empty,
            other => bail!("variable {other}: not known here"),
        })
    }

    /// Whether its values are the request's own, borrowed and kept as they are while the
    /// transaction lives (not `TX`, the matched variables, the body processor, nor values made on
    /// the fly as the sizes and counts).
    pub fn stable(self) -> bool {
        !matches!(
            self,
            Collection::Tx
                | Collection::MatchedVar
                | Collection::MatchedVarName
                | Collection::MatchedVars
                | Collection::MatchedVarsNames
                | Collection::ReqbodyProcessor
                | Collection::ArgsCombinedSize
                | Collection::RequestBodyLength
                | Collection::FilesCombinedSize
                | Collection::UniqueId
        )
    }

    /// The name before `:` in `MATCHED_VAR_NAME`.
    pub fn name(self) -> &'static str {
        match self {
            Collection::Args => "ARGS",
            Collection::ArgsNames => "ARGS_NAMES",
            Collection::ArgsGet => "ARGS_GET",
            Collection::ArgsGetNames => "ARGS_GET_NAMES",
            Collection::ArgsPost => "ARGS_POST",
            Collection::ArgsPostNames => "ARGS_POST_NAMES",
            Collection::ArgsCombinedSize => "ARGS_COMBINED_SIZE",
            Collection::RequestHeaders => "REQUEST_HEADERS",
            Collection::RequestHeadersNames => "REQUEST_HEADERS_NAMES",
            Collection::RequestCookies => "REQUEST_COOKIES",
            Collection::RequestCookiesNames => "REQUEST_COOKIES_NAMES",
            Collection::RequestFilename => "REQUEST_FILENAME",
            Collection::RequestBasename => "REQUEST_BASENAME",
            Collection::RequestUri => "REQUEST_URI",
            Collection::RequestUriRaw => "REQUEST_URI_RAW",
            Collection::RequestLine => "REQUEST_LINE",
            Collection::RequestMethod => "REQUEST_METHOD",
            Collection::RequestProtocol => "REQUEST_PROTOCOL",
            Collection::QueryString => "QUERY_STRING",
            Collection::RequestBody => "REQUEST_BODY",
            Collection::RequestBodyLength => "REQUEST_BODY_LENGTH",
            Collection::Files => "FILES",
            Collection::FilesNames => "FILES_NAMES",
            Collection::FilesSizes => "FILES_SIZES",
            Collection::FilesCombinedSize => "FILES_COMBINED_SIZE",
            Collection::MultipartPartHeaders => "MULTIPART_PART_HEADERS",
            Collection::ReqbodyProcessor => "REQBODY_PROCESSOR",
            Collection::ReqbodyError => "REQBODY_ERROR",
            Collection::RemoteAddr => "REMOTE_ADDR",
            Collection::ServerName => "SERVER_NAME",
            Collection::UniqueId => "UNIQUE_ID",
            Collection::Tx => "TX",
            Collection::MatchedVar => "MATCHED_VAR",
            Collection::MatchedVarName => "MATCHED_VAR_NAME",
            Collection::MatchedVars => "MATCHED_VARS",
            Collection::MatchedVarsNames => "MATCHED_VARS_NAMES",
            Collection::Xml => "XML",
            Collection::Empty => "",
        }
    }
}

/// `setvar`: `tx.name=value`, `=+n`, `=-n`, or `!tx.name`.
#[derive(Debug, Clone)]
pub struct SetVar {
    pub key: Macro,
    pub op: SetOp,
    /// The key when it has no macro (lower case), made once.
    pub fixed_key: Option<String>,
    /// The value (or the number added) when it has no macro, made once.
    pub fixed_value: Option<Vec<u8>>,
}

#[derive(Debug, Clone)]
pub enum SetOp {
    Set(Macro),
    Add(Macro),
    Sub(Macro),
    Delete,
}

/// `ctl:` for the rest of the request.
#[derive(Debug, Clone)]
pub enum Ctl {
    RemoveById(Vec<(u32, u32)>),
    RemoveByTag(String),
    RemoveTargetById(Vec<(u32, u32)>, Vec<Var>),
    RemoveTargetByTag(String, Vec<Var>),
    BodyProcessor(String),
    ForceBodyVariable,
    EngineOff,
    /// `DetectionOnly`: what is found is written, nothing is refused.
    EngineDetectionOnly,
    /// The audit log and the like: webfast's to configure.
    Ignored,
}

/// What a rule does when it matches.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Disruptive {
    /// `pass`, and `block` in the CRS's anomaly scoring (`SecDefaultAction … pass`).
    Pass,
    /// `deny`, `drop`, `redirect`: refused.
    Deny,
    /// `allow`: nothing more checked.
    Allow,
}

/// One rule of a chain.
#[derive(Debug, Clone)]
pub struct Link {
    pub vars: Vec<Var>,
    pub op: Arc<Operator>,
    pub transforms: Vec<Transform>,
    pub multi_match: bool,
    pub capture: bool,
    pub setvars: Vec<SetVar>,
    pub ctls: Vec<Ctl>,
    /// Its transformations' place in `Program::chains` (`build_prefilters`).
    pub chain: u32,
    /// Its slot in a value's candidates for its chain (0 to 127): set when the value has one of
    /// its regex's literals; none, the regex runs on every value.
    pub prefilter: Option<u32>,
    /// With a prefilter, every variable one of the request's own (`Collection::stable`): the
    /// link fails at once when no value of its chain's collections has its literals.
    pub whole: bool,
}

/// One list of transformations the links use, with the automaton of the literals of the regexes
/// run after it: one pass over a transformed value says which of them may match.
#[derive(Debug, Clone, Default)]
pub struct Chain {
    pub transforms: Vec<Transform>,
    pub automaton: Option<aho_corasick::AhoCorasick>,
    /// The candidate slot of each of the automaton's patterns.
    pub slots: Vec<u32>,
}

/// Candidate slots per chain: one `u128` per value.
pub const SLOTS: u32 = 128;

impl std::fmt::Debug for Operator {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "@{:?}", self.kind)
    }
}

#[derive(Debug, Clone)]
pub struct Rule {
    pub id: u32,
    pub phase: usize,
    pub links: Vec<Link>,
    pub disruptive: Disruptive,
    /// `log` (the default) and not `nolog`.
    pub log: bool,
    pub tags: Vec<String>,
    pub msg: Macro,
    pub logdata: Macro,
    pub skip_after: Option<String>,
    pub skip: usize,
    pub info: Arc<EngineRule>,
}

/// A rule or a marker, in a phase's order.
#[derive(Debug, Clone)]
pub enum Item {
    Rule(usize),
    Marker(String),
}

/// The compiled rules.
#[derive(Debug, Default)]
pub struct Program {
    pub rules: Vec<Rule>,
    /// Per phase: its rules and every marker, in file order.
    pub phases: [Vec<Item>; PHASES],
    /// Per phase, per item: where a matching rule's `skipAfter` or `skip` goes on.
    pub jumps: [Vec<Option<usize>>; PHASES],
    /// Directives read without effect, by name.
    pub ignored: Vec<String>,
    /// Rules of the response phases left out.
    pub later: usize,
    /// The links' lists of transformations, each once (`build_prefilters`).
    pub chains: Vec<Chain>,
}

/// What reads the CRS's data files (`@pmFromFile`).
pub type Data<'a> = &'a dyn Fn(&str) -> Result<String>;

/// The defaults of a rule: `SecDefaultAction`'s, per phase (only its transformations matter here;
/// its disruptive action is the CRS's `pass`).
#[derive(Default, Clone)]
struct Defaults {
    transforms: [Vec<Transform>; PHASES],
}

impl Program {
    /// Adds a file's directives; `set`: the log's set for its rules (`crs-942`).
    pub fn add(&mut self, text: &str, file: &str, set: &str, data: Data<'_>) -> Result<()> {
        let directives = seclang::directives(text, file)?;
        let mut defaults = Defaults::default();
        let mut i = 0;
        while i < directives.len() {
            let d = &directives[i];
            let used = self
                .directive(&directives[i..], &mut defaults, set, data)
                .with_context(|| d.at.clone())?;
            i += used;
        }
        Ok(())
    }

    /// One directive (a rule with its chain: as many as it takes); how many were read.
    fn directive(&mut self, ds: &[Directive], defaults: &mut Defaults, set: &str, data: Data<'_>) -> Result<usize> {
        let d = &ds[0];
        match d.name.as_str() {
            "SecRule" | "SecAction" => {
                let mut links = Vec::new();
                let mut first_actions = Vec::new();
                let mut used = 0;
                loop {
                    let Some(d) = ds.get(used) else {
                        bail!("a chain ends without its next rule");
                    };
                    if used > 0 && d.name != "SecRule" {
                        bail!("a chained rule is followed by {}, not SecRule", d.name);
                    }
                    let (vars, op, actions) = match d.name.as_str() {
                        "SecRule" => {
                            if d.args.len() < 2 {
                                bail!("SecRule needs variables and an operator");
                            }
                            (
                                seclang::variables(&d.args[0])?,
                                seclang::operator(&d.args[1]),
                                seclang::actions(d.args.get(2).map_or("", |s| s.as_str()))?,
                            )
                        }
                        _ => (
                            Vec::new(),
                            seclang::operator("@unconditionalMatch"),
                            seclang::actions(d.args.first().map_or("", |s| s.as_str()))?,
                        ),
                    };
                    used += 1;
                    let chained = actions.iter().any(|a| a.name == "chain");
                    let op = Arc::new(Operator::new(&op.name, &op.arg, op.negated, data)?);
                    let vars = if d.name == "SecAction" {
                        // Matches once: one value of its own.
                        vec![Var {
                            collection: Collection::UniqueId,
                            selector: None,
                            count: false,
                            exclude: false,
                        }]
                    } else {
                        compile_vars(&vars)?
                    };
                    let phase = if links.is_empty() {
                        phase_of(&actions)?.or(Some(1))
                    } else {
                        None
                    };
                    let default_t = phase
                        .filter(|p| *p < PHASES)
                        .map(|p| defaults.transforms[p].clone())
                        .unwrap_or_default();
                    links.push(link(
                        vars,
                        op,
                        &actions,
                        if links.is_empty() { default_t } else { Vec::new() },
                    )?);
                    if first_actions.is_empty() {
                        first_actions = actions;
                    }
                    if !chained {
                        break;
                    }
                }
                self.rule(links, &first_actions, set)?;
                Ok(used)
            }
            "SecMarker" => {
                let name = d.args.first().ok_or_else(|| anyhow!("SecMarker without a name"))?;
                for phase in &mut self.phases {
                    phase.push(Item::Marker(name.clone()));
                }
                Ok(1)
            }
            "SecDefaultAction" => {
                let actions = seclang::actions(d.args.first().map_or("", |s| s.as_str()))?;
                if let Some(p) = phase_of(&actions)?
                    && p < PHASES
                {
                    defaults.transforms[p] = transforms(&actions)?;
                }
                Ok(1)
            }
            "SecRuleRemoveById" => {
                let ranges = d.args.iter().map(|a| ranges(a)).collect::<Result<Vec<_>>>()?.concat();
                self.remove(|r| in_ranges(&ranges, r.id));
                Ok(1)
            }
            "SecRuleRemoveByTag" => {
                let re = super::ops::regex(d.args.first().map_or("", |s| s.as_str()), true)?;
                self.remove(|r| r.tags.iter().any(|t| re.is_match(t.as_bytes())));
                Ok(1)
            }
            "SecRuleRemoveByMsg" => {
                let re = super::ops::regex(d.args.first().map_or("", |s| s.as_str()), true)?;
                self.remove(|r| r.msg.fixed().is_some_and(|m| re.is_match(m.as_bytes())));
                Ok(1)
            }
            "SecRuleUpdateTargetById" | "SecRuleUpdateTargetByTag" => {
                let (Some(which), Some(targets)) = (d.args.first(), d.args.get(1)) else {
                    bail!("{} needs a rule and the variables", d.name);
                };
                let vars = compile_vars(&seclang::variables(targets)?)?;
                let by_id = d.name == "SecRuleUpdateTargetById";
                let ids = if by_id { ranges(which)? } else { Vec::new() };
                let tag = if by_id {
                    None
                } else {
                    Some(super::ops::regex(which, true)?)
                };
                let mut found = false;
                for rule in &mut self.rules {
                    let hit = match &tag {
                        None => in_ranges(&ids, rule.id),
                        Some(re) => rule.tags.iter().any(|t| re.is_match(t.as_bytes())),
                    };
                    if hit {
                        found = true;
                        rule.links[0].vars.extend(vars.iter().cloned());
                    }
                }
                if !found && by_id {
                    bail!("{} {which}: no such rule", d.name);
                }
                Ok(1)
            }
            "SecRuleUpdateActionById" => {
                let (Some(which), Some(text)) = (d.args.first(), d.args.get(1)) else {
                    bail!("SecRuleUpdateActionById needs a rule and the actions");
                };
                let id: u32 = which.parse().context("a rule id")?;
                let actions = seclang::actions(text)?;
                let rule = self
                    .rules
                    .iter_mut()
                    .find(|r| r.id == id)
                    .ok_or_else(|| anyhow!("SecRuleUpdateActionById {id}: no such rule"))?;
                update_actions(rule, &actions)?;
                Ok(1)
            }
            "SecComponentSignature"
            | "SecRuleEngine"
            | "SecRequestBodyAccess"
            | "SecResponseBodyAccess"
            | "SecRequestBodyLimit"
            | "SecRequestBodyNoFilesLimit"
            | "SecRequestBodyLimitAction"
            | "SecRequestBodyJsonDepthLimit"
            | "SecArgumentsLimit"
            | "SecPcreMatchLimit"
            | "SecPcreMatchLimitRecursion"
            | "SecResponseBodyMimeType"
            | "SecResponseBodyLimit"
            | "SecResponseBodyLimitAction"
            | "SecTmpDir"
            | "SecDataDir"
            | "SecAuditEngine"
            | "SecAuditLog"
            | "SecAuditLogParts"
            | "SecAuditLogType"
            | "SecAuditLogRelevantStatus"
            | "SecAuditLogStorageDir"
            | "SecArgumentSeparator"
            | "SecCookieFormat"
            | "SecUnicodeMapFile"
            | "SecStatusEngine"
            | "SecCollectionTimeout"
            | "SecDebugLog"
            | "SecDebugLogLevel"
            | "SecUploadDir"
            | "SecUploadKeepFiles"
            | "SecTmpSaveUploadedFiles"
            | "SecAuditLogFormat"
            | "SecAuditLogFileMode"
            | "SecAuditLogDirMode" => {
                if d.name != "SecComponentSignature" && !self.ignored.contains(&d.name) {
                    self.ignored.push(d.name.clone());
                }
                Ok(1)
            }
            other => bail!("directive {other}: not supported"),
        }
    }

    fn rule(&mut self, links: Vec<Link>, actions: &[seclang::Action], set: &str) -> Result<()> {
        let mut id = None;
        let mut phase = 2;
        let mut disruptive = Disruptive::Pass;
        let mut log = true;
        let mut tags = Vec::new();
        let mut msg = Macro::default();
        let mut logdata = Macro::default();
        let mut skip_after = None;
        let mut skip = 0;
        let mut severity = None;
        for a in actions {
            let value = a.value.as_deref().unwrap_or("");
            match a.name.as_str() {
                "id" => id = Some(value.trim().parse::<u32>().with_context(|| format!("id:{value}"))?),
                "phase" => phase = phase_number(value)?,
                "msg" => msg = Macro::parse(value)?,
                "logdata" => logdata = Macro::parse(value)?,
                "tag" => tags.push(value.to_string()),
                "severity" => severity = Some(severity_of(value)?),
                "deny" | "drop" | "redirect" => disruptive = Disruptive::Deny,
                "allow" => disruptive = Disruptive::Allow,
                "pass" | "block" => {}
                "nolog" => log = false,
                "log" => log = true,
                "skipafter" => skip_after = Some(value.to_string()),
                "skip" => skip = value.trim().parse::<usize>().context("skip:N")?,
                _ => {}
            }
        }
        let id = id.ok_or_else(|| anyhow!("a rule without an id"))?;
        if self.rules.iter().any(|r| r.id == id) {
            bail!("rule {id} is defined twice");
        }
        let severity = severity.unwrap_or(Severity::Notice);
        let info = Arc::new(EngineRule {
            id: id.to_string(),
            number: Some(id),
            set: set.to_string(),
            severity,
            tags: tags.clone(),
            msg: msg
                .fixed()
                .unwrap_or_else(|| String::from_utf8_lossy(&msg.expand(&mut |_, _| None)).into_owned()),
        });
        if phase > PHASES {
            self.later += 1;
            return Ok(());
        }
        let index = self.rules.len();
        self.rules.push(Rule {
            id,
            phase: phase - 1,
            links,
            disruptive,
            log,
            tags,
            msg,
            logdata,
            skip_after,
            skip,
            info,
        });
        self.phases[phase - 1].push(Item::Rule(index));
        Ok(())
    }

    fn remove(&mut self, which: impl Fn(&Rule) -> bool) {
        let gone: Vec<usize> = self
            .rules
            .iter()
            .enumerate()
            .filter(|(_, r)| which(r))
            .map(|(i, _)| i)
            .collect();
        for phase in &mut self.phases {
            phase.retain(|item| !matches!(item, Item::Rule(i) if gone.contains(i)));
        }
    }

    /// Where each rule's `skipAfter` (after its marker; the phase's end when there is none) or
    /// `skip` (that many rules on) goes, once every file is in.
    pub fn link_jumps(&mut self) {
        for p in 0..PHASES {
            let items = &self.phases[p];
            let mut jumps = vec![None; items.len()];
            for (i, item) in items.iter().enumerate() {
                let Item::Rule(r) = item else { continue };
                let rule = &self.rules[*r];
                if let Some(marker) = &rule.skip_after {
                    let to = items[i + 1..]
                        .iter()
                        .position(|it| matches!(it, Item::Marker(m) if m == marker))
                        .map_or(items.len(), |k| i + 1 + k + 1);
                    jumps[i] = Some(to);
                } else if rule.skip > 0 {
                    let mut left = rule.skip;
                    let mut to = items.len();
                    for (k, it) in items.iter().enumerate().skip(i + 1) {
                        if matches!(it, Item::Rule(_)) {
                            if left == 0 {
                                to = k;
                                break;
                            }
                            left -= 1;
                        }
                    }
                    jumps[i] = Some(if left == 0 { to } else { items.len() });
                }
            }
            self.jumps[p] = jumps;
        }
    }

    /// Each link's chain of transformations, and for each regex with literals a candidate slot in
    /// its chain's automaton (a negated or `multiMatch` one has none: it runs on every value; nor
    /// has one past the chain's `SLOTS`).
    pub fn build_prefilters(&mut self) -> Result<()> {
        let mut chains: Vec<Chain> = Vec::new();
        let mut patterns: Vec<Vec<(Vec<u8>, u32)>> = Vec::new();
        let mut used: Vec<u32> = Vec::new();
        for rule in &mut self.rules {
            for link in &mut rule.links {
                let chain = match chains.iter().position(|c| c.transforms == link.transforms) {
                    Some(i) => i,
                    None => {
                        chains.push(Chain {
                            transforms: link.transforms.clone(),
                            ..Chain::default()
                        });
                        patterns.push(Vec::new());
                        used.push(0);
                        chains.len() - 1
                    }
                };
                link.chain = chain as u32;
                if link.op.kind == super::ops::Kind::Rx
                    && !link.op.negated
                    && !link.multi_match
                    && used[chain] < SLOTS
                    && let Some(literals) = &link.op.literals
                {
                    let slot = used[chain];
                    used[chain] += 1;
                    link.prefilter = Some(slot);
                    patterns[chain].extend(literals.iter().map(|l| (l.clone(), slot)));
                    link.whole = link
                        .vars
                        .iter()
                        .all(|v| v.exclude || (!v.count && v.collection.stable()));
                }
            }
        }
        for (chain, list) in chains.iter_mut().zip(patterns) {
            if list.is_empty() {
                continue;
            }
            let automaton = aho_corasick::AhoCorasickBuilder::new()
                .ascii_case_insensitive(true)
                .kind(Some(aho_corasick::AhoCorasickKind::DFA))
                .build(list.iter().map(|(l, _)| l))
                .context("the prefilter's automaton")?;
            chain.automaton = Some(automaton);
            chain.slots = list.into_iter().map(|(_, s)| s).collect();
        }
        self.chains = chains;
        Ok(())
    }

    /// The rules in the phases (removed ones not counted).
    pub fn count(&self) -> usize {
        self.phases
            .iter()
            .map(|p| p.iter().filter(|i| matches!(i, Item::Rule(_))).count())
            .sum()
    }
}

fn phase_number(value: &str) -> Result<usize> {
    Ok(match value.trim().to_ascii_lowercase().as_str() {
        "1" | "request_headers" => 1,
        "2" | "request" | "request_body" => 2,
        "3" | "response_headers" => 3,
        "4" | "response" | "response_body" => 4,
        "5" | "logging" => 5,
        other => bail!("phase:{other}"),
    })
}

/// The 0-based phase of an action list, when it names one.
fn phase_of(actions: &[seclang::Action]) -> Result<Option<usize>> {
    for a in actions {
        if a.name == "phase" {
            return Ok(Some(phase_number(a.value.as_deref().unwrap_or(""))? - 1));
        }
    }
    Ok(None)
}

fn severity_of(value: &str) -> Result<Severity> {
    Ok(match value.trim().to_ascii_uppercase().as_str() {
        "EMERGENCY" | "ALERT" | "CRITICAL" | "0" | "1" | "2" => Severity::Critical,
        "ERROR" | "3" => Severity::High,
        "WARNING" | "4" => Severity::Medium,
        "NOTICE" | "5" => Severity::Low,
        "INFO" | "DEBUG" | "6" | "7" => Severity::Notice,
        other => bail!("severity:{other}"),
    })
}

fn transforms(actions: &[seclang::Action]) -> Result<Vec<Transform>> {
    let mut out = Vec::new();
    for a in actions {
        if a.name == "t" {
            match Transform::parse(a.value.as_deref().unwrap_or(""))? {
                Some(t) => out.push(t),
                None => out.clear(),
            }
        }
    }
    Ok(out)
}

/// A link from its variables, operator and actions (`default_t`: `SecDefaultAction`'s
/// transformations, for a chain's first rule).
fn link(vars: Vec<Var>, op: Arc<Operator>, actions: &[seclang::Action], default_t: Vec<Transform>) -> Result<Link> {
    let mut transforms = default_t;
    let mut multi_match = false;
    let mut capture = false;
    let mut setvars = Vec::new();
    let mut ctls = Vec::new();
    for a in actions {
        let value = a.value.as_deref().unwrap_or("");
        match a.name.as_str() {
            "t" => match Transform::parse(value)? {
                Some(t) => transforms.push(t),
                None => transforms.clear(),
            },
            "multimatch" => multi_match = true,
            "capture" => capture = true,
            "setvar" => setvars.push(setvar(value)?),
            "ctl" => ctls.push(ctl(value)?),
            "id"
            | "phase"
            | "msg"
            | "logdata"
            | "tag"
            | "severity"
            | "ver"
            | "rev"
            | "maturity"
            | "accuracy"
            | "chain"
            | "deny"
            | "drop"
            | "redirect"
            | "allow"
            | "pass"
            | "block"
            | "nolog"
            | "log"
            | "auditlog"
            | "noauditlog"
            | "skipafter"
            | "skip"
            | "status"
            | "expirevar"
            | "initcol"
            | "setenv"
            | "setuid"
            | "setsid"
            | "sanitisearg"
            | "sanitisematched"
            | "sanitisematchedbytes"
            | "sanitiserequestheader"
            | "sanitiseresponseheader"
            | "append"
            | "prepend"
            | "exec"
            | "deprecatevar"
            | "xmlns"
            | "proxy"
            | "pause" => {}
            other => bail!("action {other}: not supported"),
        }
    }
    Ok(Link {
        vars,
        op,
        transforms,
        multi_match,
        capture,
        setvars,
        ctls,
        chain: 0,
        prefilter: None,
        whole: false,
    })
}

fn update_actions(rule: &mut Rule, actions: &[seclang::Action]) -> Result<()> {
    let mut tags_cleared = false;
    for a in actions {
        let value = a.value.as_deref().unwrap_or("");
        match a.name.as_str() {
            "msg" => rule.msg = Macro::parse(value)?,
            "logdata" => rule.logdata = Macro::parse(value)?,
            "tag" => {
                if !tags_cleared {
                    rule.tags.clear();
                    tags_cleared = true;
                }
                rule.tags.push(value.to_string());
            }
            "deny" | "drop" | "redirect" => rule.disruptive = Disruptive::Deny,
            "allow" => rule.disruptive = Disruptive::Allow,
            "pass" | "block" => rule.disruptive = Disruptive::Pass,
            "nolog" => rule.log = false,
            "log" => rule.log = true,
            "t" => match Transform::parse(value)? {
                Some(t) => rule.links[0].transforms.push(t),
                None => rule.links[0].transforms.clear(),
            },
            "setvar" => {
                let set = setvar(value)?;
                if let Some(last) = rule.links.last_mut() {
                    last.setvars.push(set);
                }
            }
            "severity" | "ver" | "rev" | "maturity" | "accuracy" | "status" | "auditlog" | "noauditlog" => {}
            other => bail!("SecRuleUpdateActionById: action {other} is not supported"),
        }
    }
    let mut info = (*rule.info).clone();
    info.tags = rule.tags.clone();
    info.msg = rule.msg.fixed().unwrap_or_default();
    rule.info = Arc::new(info);
    Ok(())
}

pub fn compile_vars(vars: &[Variable]) -> Result<Vec<Var>> {
    vars.iter()
        .map(|v| {
            let collection = Collection::parse(&v.collection)?;
            Ok(Var {
                collection,
                selector: match &v.selector {
                    None => None,
                    Some(Selector::Key(k)) if collection == Collection::Tx => Some(Select::Key(k.to_ascii_lowercase())),
                    Some(Selector::Key(k)) => Some(Select::Key(k.clone())),
                    Some(Selector::Regex(re)) => Some(Select::Regex(super::ops::regex(re, true)?)),
                },
                count: v.count,
                exclude: v.exclude,
            })
        })
        .collect()
}

fn setvar(text: &str) -> Result<SetVar> {
    let text = text.trim();
    let (delete, text) = match text.strip_prefix('!') {
        Some(rest) => (true, rest),
        None => (false, text),
    };
    let (name, value) = match text.split_once('=') {
        Some((n, v)) => (n, Some(v)),
        None => (text, None),
    };
    let Some((collection, key)) = name.split_once('.') else {
        bail!("setvar:{text}: no collection");
    };
    if !collection.eq_ignore_ascii_case("tx") {
        // ip., session. and the like: no persistent collections here.
        return Ok(SetVar {
            key: Macro::default(),
            op: SetOp::Delete,
            fixed_key: Some(String::new()),
            fixed_value: None,
        });
    }
    let key = Macro::parse(&key.to_ascii_lowercase())?;
    let op = match (delete, value) {
        (true, _) => SetOp::Delete,
        (false, None) => SetOp::Set(Macro::parse("1")?),
        (false, Some(v)) => {
            if let Some(n) = v.strip_prefix('+') {
                SetOp::Add(Macro::parse(n)?)
            } else if let Some(n) = v.strip_prefix('-') {
                SetOp::Sub(Macro::parse(n)?)
            } else {
                SetOp::Set(Macro::parse(v)?)
            }
        }
    };
    let fixed_key = key.fixed().map(|k| k.to_ascii_lowercase());
    let fixed_value = match &op {
        SetOp::Set(m) | SetOp::Add(m) | SetOp::Sub(m) => m.fixed().map(String::into_bytes),
        SetOp::Delete => None,
    };
    Ok(SetVar {
        key,
        op,
        fixed_key,
        fixed_value,
    })
}

/// `920100` or `920100-920199`.
pub fn ranges(text: &str) -> Result<Vec<(u32, u32)>> {
    text.split([',', ' '])
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .map(|part| match part.split_once('-') {
            Some((a, b)) => Ok((a.trim().parse()?, b.trim().parse()?)),
            None => {
                let v: u32 = part.parse().with_context(|| format!("rule id {part:?}"))?;
                Ok((v, v))
            }
        })
        .collect()
}

pub fn in_ranges(ranges: &[(u32, u32)], id: u32) -> bool {
    ranges.iter().any(|&(a, b)| (a..=b).contains(&id))
}

fn ctl(text: &str) -> Result<Ctl> {
    let (name, value) = text.split_once('=').unwrap_or((text, ""));
    let value = value.trim();
    Ok(match name.trim().to_ascii_lowercase().as_str() {
        "ruleremovebyid" => Ctl::RemoveById(ranges(value)?),
        "ruleremovebytag" => Ctl::RemoveByTag(value.to_string()),
        "ruleremovetargetbyid" | "ruleremovetargetbytag" => {
            let (which, vars) = value
                .split_once(';')
                .ok_or_else(|| anyhow!("ctl:{name}={value}: rule;variable"))?;
            let vars: Vec<Var> = compile_vars(&seclang::variables(vars)?)?
                .into_iter()
                .map(|mut v| {
                    v.exclude = true;
                    v
                })
                .collect();
            if name.eq_ignore_ascii_case("ruleRemoveTargetById") {
                Ctl::RemoveTargetById(ranges(which)?, vars)
            } else {
                Ctl::RemoveTargetByTag(which.to_string(), vars)
            }
        }
        "requestbodyprocessor" => Ctl::BodyProcessor(value.to_ascii_uppercase()),
        "forcerequestbodyvariable" => {
            if value.eq_ignore_ascii_case("on") {
                Ctl::ForceBodyVariable
            } else {
                Ctl::Ignored
            }
        }
        "ruleengine" => match value.to_ascii_lowercase().as_str() {
            "off" => Ctl::EngineOff,
            "detectiononly" => Ctl::EngineDetectionOnly,
            _ => Ctl::Ignored,
        },
        "auditengine" | "auditlogparts" | "requestbodyaccess" | "requestbodylimit" | "responsebodyaccess"
        | "responsebodylimit" | "debugloglevel" | "hashengine" | "hashenforcement" | "parsexmlintoargs" => Ctl::Ignored,
        other => bail!("ctl:{other}: not supported"),
    })
}
