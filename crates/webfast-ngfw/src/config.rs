//! The module's YAML file (docs/ngfw.md "Configuration"): its types with serde, the `duration`
//! and `size` readers every part shares, and the composition of the rule list — the built-in
//! sets, the included files in order (a rule with an earlier rule's id replaces it in place),
//! then `override`, then `disable` — with a summary (`Loaded`) for `webfast validate`.

use super::ban::BanConfig;
use super::geo::GeoConfig;
use super::iplist::IpConfig;
use super::rule::{
    Action, Confidence, IdPattern, Mode, Operator, Phase, Refs, Rule, RulesFile, Severity, Target, Transform,
};
use anyhow::{Context, Result, anyhow, bail};
use serde::Deserialize;
use std::collections::BTreeMap;
use std::path::{Path, PathBuf};
use std::time::Duration;

#[derive(Deserialize, Debug)]
#[serde(deny_unknown_fields)]
pub struct FileConfig {
    #[serde(default)]
    pub mode: Mode,
    pub log: Option<LogConfig>,
    #[serde(default = "five")]
    pub threshold: u32,
    #[serde(default)]
    pub response: ResponseConfig,
    #[serde(default)]
    pub rules: RulesConfig,
    #[serde(default)]
    pub body: BodyConfig,
    pub geo: Option<GeoConfig>,
    #[serde(default)]
    pub access: AccessConfig,
    #[serde(rename = "match")]
    pub matcher: Option<MatchConfig>,
    /// The rule engines' configurations (src/plugin.rs), by name; `false` turns one off.
    #[serde(default)]
    pub engines: BTreeMap<String, serde_json::Value>,
}

fn five() -> u32 {
    5
}

#[derive(Deserialize, Debug, Clone)]
#[serde(deny_unknown_fields)]
pub struct LogConfig {
    /// `stdout`, `stderr`, `discard`, or a file relative to this file.
    pub output: String,
    /// Bytes of the matched text written per hit; 0: none.
    #[serde(default = "two_hundred")]
    pub matched: usize,
    /// Also write requests let through with hits: scored under the threshold, or hits that only
    /// log (`action: log`, an engine's detection-only rules).
    #[serde(default)]
    pub passed: bool,
    /// For a test deployment: a request with this header (go-ftw's `X-CRS-Test`) also writes its
    /// value as a marker line; it is checked as any other. Off by default.
    #[serde(default)]
    pub test_marker: Option<String>,
}

fn two_hundred() -> usize {
    200
}

#[derive(Deserialize, Debug, Clone)]
#[serde(deny_unknown_fields)]
pub struct ResponseConfig {
    /// 403 | 404 | 444 (444: the connection is closed after it).
    #[serde(default = "forbidden")]
    pub status: u16,
    /// What a response the `response` phase refuses is replaced by.
    #[serde(default = "server_error")]
    pub leak_status: u16,
    /// A 200 goes out at once and its body is scanned as it streams, cut on a leak (`true`, the
    /// default); `false`: held until `body.max_inspect` bytes are in, and replaced on a leak, as a
    /// 5xx always is.
    #[serde(default = "yes")]
    pub stream: bool,
    /// The browser challenge's level where one is asked (`action: challenge`, `mode: challenge`,
    /// `access.*.challenge`, `ban.then: challenge`): `cookie | js | pow | captcha` (default `js`).
    pub challenge: Option<String>,
    /// `level captcha`: the provider and its keys.
    pub captcha: Option<CaptchaConfig>,
    /// How long a passed client is not asked again (default `7d`).
    pub challenge_valid: Option<String>,
    /// `ip | none`: whether the cookie is bound to the client's /24 or /48 (default `ip`).
    pub challenge_bind: Option<String>,
}

impl ResponseConfig {
    /// Whether any key of the challenge is set (the challenge module must then be built).
    pub fn asks_challenge(&self) -> bool {
        self.challenge.is_some()
            || self.captcha.is_some()
            || self.challenge_valid.is_some()
            || self.challenge_bind.is_some()
    }
}

/// `response.captcha`: the CAPTCHA provider the challenge at level `captcha` uses.
#[derive(Deserialize, Debug, Clone)]
#[serde(deny_unknown_fields)]
pub struct CaptchaConfig {
    /// `turnstile | hcaptcha | recaptcha`.
    pub provider: String,
    pub site_key: String,
    /// The secret, or `env:NAME` for the environment variable that holds it.
    pub secret: String,
}

impl CaptchaConfig {
    /// The secret: the literal, or the environment variable `env:NAME` names.
    pub fn secret(&self) -> Result<String> {
        match self.secret.strip_prefix("env:") {
            Some(name) => std::env::var(name)
                .map_err(|_| anyhow!("response.captcha.secret: {name} is not set in the environment")),
            None => Ok(self.secret.clone()),
        }
    }
}

impl Default for ResponseConfig {
    fn default() -> Self {
        ResponseConfig {
            status: forbidden(),
            leak_status: server_error(),
            stream: true,
            challenge: None,
            captcha: None,
            challenge_valid: None,
            challenge_bind: None,
        }
    }
}

/// `Ok` when the browser challenge is built in; the error that names `what` otherwise, as the
/// Caddyfile reports a directive of a feature left out.
pub fn needs_challenge(what: &str) -> Result<()> {
    if cfg!(feature = "challenge") {
        Ok(())
    } else {
        bail!("{what}: this webfast was built without the challenge module (cargo feature challenge)")
    }
}

/// `Ok` when libinjection's detectors are built in (`detect_sqli`, `detect_xss`); the error that
/// names `what` otherwise.
pub fn needs_libinjection(what: &str) -> Result<()> {
    if cfg!(feature = "libinjection") {
        Ok(())
    } else {
        bail!("{what}: this webfast was built without libinjection (cargo feature libinjection)")
    }
}

fn forbidden() -> u16 {
    403
}

fn server_error() -> u16 {
    500
}

fn yes() -> bool {
    true
}

#[derive(Deserialize, Debug, Default)]
#[serde(deny_unknown_fields)]
pub struct RulesConfig {
    /// Not given: all the sets, or with a rule engine on (src/plugin.rs) the sets it names.
    #[serde(default)]
    pub builtin: Option<Builtin>,
    /// The site's own files, relative to this file, applied in order.
    #[serde(default)]
    pub include: Vec<String>,
    /// Ids, or masks with a trailing `*`.
    #[serde(default)]
    pub disable: Vec<String>,
    /// Tags: every rule with one of them is disabled (after `disable`), as `disable_tags:
    /// [wordpress]` turns off the probes of a WordPress site.
    #[serde(default)]
    pub disable_tags: Vec<String>,
    /// Fields of a rule changed in place (any but `id`); a mask as the key changes every rule it
    /// matches (so a whole set goes `log_only`).
    #[serde(default, rename = "override")]
    pub overrides: BTreeMap<String, Override>,
    #[serde(default)]
    pub exclusions: Vec<ExclusionConfig>,
}

/// `all`, `none`, or a list of set names.
#[derive(Deserialize, Debug, Clone, PartialEq, Eq)]
#[serde(untagged)]
pub enum Builtin {
    Word(BuiltinWord),
    Sets(Vec<String>),
}

#[derive(Deserialize, Debug, Clone, Copy, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum BuiltinWord {
    All,
    None,
}

impl Default for Builtin {
    fn default() -> Self {
        Builtin::Word(BuiltinWord::All)
    }
}

impl Builtin {
    /// The sets to load, in the built-in order.
    pub fn sets(&self) -> Result<Vec<&'static str>> {
        match self {
            Builtin::Word(BuiltinWord::All) => Ok(super::rules::SETS.iter().map(|(name, _)| *name).collect()),
            Builtin::Word(BuiltinWord::None) => Ok(Vec::new()),
            Builtin::Sets(names) => {
                for name in names {
                    if super::rules::set(name).is_none() {
                        bail!(
                            "rules.builtin: no built-in set {name:?}; the sets are {}",
                            super::rules::SETS
                                .iter()
                                .map(|(n, _)| *n)
                                .collect::<Vec<_>>()
                                .join(", ")
                        );
                    }
                }
                Ok(super::rules::SETS
                    .iter()
                    .map(|(name, _)| *name)
                    .filter(|name| names.iter().any(|n| n == name))
                    .collect())
            }
        }
    }
}

/// Fields of a rule changed in place.
#[derive(Deserialize, Debug, Clone, Default)]
#[serde(deny_unknown_fields)]
pub struct Override {
    pub set: Option<String>,
    pub phase: Option<Phase>,
    pub msg: Option<String>,
    pub severity: Option<Severity>,
    pub score: Option<u32>,
    pub targets: Option<Vec<Target>>,
    pub transform: Option<Vec<Transform>>,
    pub operator: Option<Operator>,
    pub prefilter: Option<Vec<String>>,
    pub action: Option<Action>,
    pub header: Option<BTreeMap<String, String>>,
    pub when: Option<Vec<String>>,
    pub unless: Option<Vec<String>>,
    pub mode: Option<Mode>,
    pub tags: Option<Vec<String>>,
    pub confidence: Option<Confidence>,
    pub refs: Option<Refs>,
    pub doc: Option<String>,
}

impl Override {
    fn apply(&self, rule: &mut Rule) {
        let o = self.clone();
        if let Some(v) = o.set {
            rule.set = Some(v);
        }
        if let Some(v) = o.phase {
            rule.phase = v;
        }
        if let Some(v) = o.msg {
            rule.msg = Some(v);
        }
        if let Some(v) = o.severity {
            rule.severity = v;
        }
        if let Some(v) = o.score {
            rule.score = Some(v);
        }
        if let Some(v) = o.targets {
            rule.targets = v;
        }
        if let Some(v) = o.transform {
            rule.transform = v;
        }
        if let Some(v) = o.operator {
            rule.operator = v;
        }
        if let Some(v) = o.prefilter {
            rule.prefilter = v;
        }
        if let Some(v) = o.action {
            rule.action = v;
        }
        if let Some(v) = o.header {
            rule.header = v;
        }
        if let Some(v) = o.when {
            rule.when = v;
        }
        if let Some(v) = o.unless {
            rule.unless = v;
        }
        if let Some(v) = o.mode {
            rule.mode = Some(v);
        }
        if let Some(v) = o.tags {
            rule.tags = v;
        }
        if let Some(v) = o.confidence {
            rule.confidence = Some(v);
        }
        if let Some(v) = o.refs {
            rule.refs = v;
        }
        if let Some(v) = o.doc {
            rule.doc = Some(v);
        }
    }
}

/// Where rules do not apply: on these hosts and paths, these rules, sets or targets (none of the
/// three: nothing runs there).
#[derive(Deserialize, Debug, Clone, Default)]
#[serde(deny_unknown_fields)]
pub struct ExclusionConfig {
    #[serde(default)]
    pub hosts: Vec<String>,
    #[serde(default)]
    pub paths: Vec<String>,
    #[serde(default)]
    pub rules: Vec<String>,
    #[serde(default)]
    pub sets: Vec<String>,
    #[serde(default)]
    pub targets: Vec<Target>,
}

#[derive(Deserialize, Debug, Clone)]
#[serde(deny_unknown_fields)]
pub struct BodyConfig {
    #[serde(default = "sixty_four_kib")]
    pub max_inspect: String,
    #[serde(default = "body_types")]
    pub types: Vec<String>,
    #[serde(default = "twenty")]
    pub json_max_depth: usize,
    #[serde(default = "sixty_four")]
    pub multipart_max_parts: usize,
    #[serde(default = "four_kib")]
    pub upload_head: String,
}

impl Default for BodyConfig {
    fn default() -> Self {
        BodyConfig {
            max_inspect: sixty_four_kib(),
            types: body_types(),
            json_max_depth: twenty(),
            multipart_max_parts: sixty_four(),
            upload_head: four_kib(),
        }
    }
}

fn sixty_four_kib() -> String {
    "64KiB".to_string()
}

fn four_kib() -> String {
    "4KiB".to_string()
}

fn twenty() -> usize {
    20
}

fn sixty_four() -> usize {
    64
}

fn body_types() -> Vec<String> {
    [
        "application/x-www-form-urlencoded",
        "application/json",
        "multipart/form-data",
        "text/xml",
        "application/xml",
    ]
    .iter()
    .map(|s| s.to_string())
    .collect()
}

#[derive(Deserialize, Debug, Clone, Default)]
#[serde(deny_unknown_fields)]
pub struct AccessConfig {
    pub countries: Option<CountriesConfig>,
    pub asn: Option<AsnConfig>,
    #[serde(default)]
    pub ip: IpConfig,
    #[serde(default)]
    pub ban: BanConfig,
}

#[derive(Deserialize, Debug, Clone, Default)]
#[serde(deny_unknown_fields)]
pub struct CountriesConfig {
    #[serde(default)]
    pub allow: Vec<String>,
    #[serde(default)]
    pub deny: Vec<String>,
    /// Asked the browser challenge, not refused (a country in `deny` too is refused).
    #[serde(default)]
    pub challenge: Vec<String>,
    #[serde(default)]
    pub except_paths: Vec<String>,
}

#[derive(Deserialize, Debug, Clone, Default)]
#[serde(deny_unknown_fields)]
pub struct AsnConfig {
    #[serde(default)]
    pub allow: Vec<String>,
    #[serde(default)]
    pub deny: Vec<String>,
    /// Asked the browser challenge, not refused.
    #[serde(default)]
    pub challenge: Vec<String>,
}

#[derive(Deserialize, Debug, Clone, Default)]
#[serde(deny_unknown_fields)]
pub struct MatchConfig {
    #[serde(default)]
    pub hosts: Vec<String>,
    #[serde(default)]
    pub except_paths: Vec<String>,
}

/// `10m`, `1h`, `24h`, `30s`, `2d`, `1h30m`; a bare number is seconds.
pub fn duration(text: &str) -> Result<Duration> {
    let text = text.trim();
    if text.is_empty() {
        bail!("an empty duration");
    }
    let mut total = Duration::ZERO;
    let mut rest = text;
    while !rest.is_empty() {
        let digits = rest.len() - rest.trim_start_matches(|c: char| c.is_ascii_digit()).len();
        if digits == 0 {
            bail!("invalid duration {text:?} (e.g. 30s, 10m, 1h, 2d)");
        }
        let number: u64 = rest[..digits]
            .parse()
            .map_err(|_| anyhow!("invalid duration {text:?}"))?;
        rest = &rest[digits..];
        let unit = rest.len() - rest.trim_start_matches(|c: char| c.is_ascii_alphabetic()).len();
        let seconds = match &rest[..unit] {
            "" | "s" => 1,
            "m" => 60,
            "h" => 3600,
            "d" => 86_400,
            other => bail!("invalid duration {text:?}: unit {other:?} (s, m, h, d)"),
        };
        rest = &rest[unit..];
        total += Duration::from_secs(
            number
                .checked_mul(seconds)
                .ok_or_else(|| anyhow!("duration {text:?} is too long"))?,
        );
    }
    Ok(total)
}

/// `64KiB`, `4KiB`, `1MiB`, `512B`, a bare number of bytes (`KB`, `MB`, `K`, `M` too).
pub fn size(text: &str) -> Result<usize> {
    let text = text.trim();
    let split = text.find(|c: char| !c.is_ascii_digit()).unwrap_or(text.len());
    let (number, unit) = text.split_at(split);
    let number: usize = number
        .parse()
        .map_err(|_| anyhow!("invalid size {text:?} (e.g. 64KiB, 1MiB, 512B)"))?;
    let factor = match unit.trim().to_ascii_lowercase().as_str() {
        "" | "b" => 1,
        "k" | "kb" | "kib" => 1 << 10,
        "m" | "mb" | "mib" => 1 << 20,
        "g" | "gb" | "gib" => 1 << 30,
        _ => bail!("invalid size {text:?}: unit {unit:?} (B, KiB, MiB)"),
    };
    number
        .checked_mul(factor)
        .ok_or_else(|| anyhow!("size {text:?} is too large"))
}

/// What composing the rules found, for `validate` and the startup line.
#[derive(Debug, Default)]
pub struct Loaded {
    /// Rules per set, in the order the sets came.
    pub counts: Vec<(String, usize)>,
    /// Built-in or earlier rules replaced by an included file.
    pub replaced: Vec<String>,
    pub overridden: Vec<String>,
    pub disabled: Vec<String>,
    pub warnings: Vec<String>,
}

impl Loaded {
    pub fn total(&self) -> usize {
        self.counts.iter().map(|(_, n)| n).sum()
    }
}

/// A rule with where it came from (for `in_set` files relative to it).
#[derive(Debug, Clone)]
pub struct Sourced {
    pub rule: Rule,
    pub base: PathBuf,
}

fn parse_rules(text: &str, what: &str) -> Result<Vec<Rule>> {
    let file: RulesFile = webfast_core::yaml::from_str(text).with_context(|| format!("rules {what}"))?;
    Ok(file.rules)
}

fn valid_id(id: &str) -> bool {
    !id.is_empty()
        && id
            .bytes()
            .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-')
}

/// The rule list composed (docs/ngfw.md "Composition"); `base`: the configuration file's
/// directory, where `include` files are.
///
/// `engine_sets`: the sets the rule engines on leave on, for a `rules.builtin` not given.
pub fn compose(
    config: &RulesConfig,
    base: &Path,
    engine_sets: Option<Vec<&'static str>>,
) -> Result<(Vec<Sourced>, Loaded)> {
    let mut loaded = Loaded::default();
    let mut rules: Vec<Sourced> = Vec::new();
    // The built-in rules on libinjection's detectors: left out at the end when it is not built.
    let mut detecting: Vec<String> = Vec::new();
    let sets = match (&config.builtin, engine_sets) {
        (Some(builtin), _) => builtin.sets()?,
        (None, Some(sets)) => sets,
        (None, None) => Builtin::default().sets()?,
    };
    for name in sets {
        let text = super::rules::set(name).expect("a listed set");
        for mut rule in parse_rules(text, &format!("built-in set {name}"))? {
            rule.set.get_or_insert_with(|| name.to_string());
            if rules.iter().any(|r| r.rule.id == rule.id) {
                bail!("built-in set {name}: rule {} is defined twice", rule.id);
            }
            if rule.operator.is_libinjection() {
                detecting.push(rule.id.clone());
            }
            rules.push(Sourced {
                rule,
                base: base.to_path_buf(),
            });
        }
    }
    for include in &config.include {
        let path = base.join(include);
        let text = std::fs::read_to_string(&path).with_context(|| format!("reading {}", path.display()))?;
        let file_base = path.parent().unwrap_or(Path::new(".")).to_path_buf();
        for mut rule in parse_rules(&text, &path.display().to_string())? {
            if !valid_id(&rule.id) {
                bail!("{}: rule id {:?}: [a-z0-9-]+", path.display(), rule.id);
            }
            match rules.iter().position(|r| r.rule.id == rule.id) {
                // Replaced in place; without a `set` of its own it stays in the replaced rule's.
                Some(index) => {
                    if rule.set.is_none() {
                        rule.set = rules[index].rule.set.clone();
                    }
                    loaded.replaced.push(rule.id.clone());
                    rules[index] = Sourced {
                        rule,
                        base: file_base.clone(),
                    };
                }
                None => {
                    rule.set.get_or_insert_with(|| "site".to_string());
                    rules.push(Sourced {
                        rule,
                        base: file_base.clone(),
                    });
                }
            }
        }
    }
    for (key, change) in &config.overrides {
        let pattern = IdPattern::new(key);
        let mut hit = false;
        for sourced in rules.iter_mut().filter(|r| pattern.matches(&r.rule.id)) {
            change.apply(&mut sourced.rule);
            loaded.overridden.push(sourced.rule.id.clone());
            hit = true;
        }
        if !hit {
            bail!("rules.override: no rule {key:?}");
        }
    }
    for key in &config.disable {
        let pattern = IdPattern::new(key);
        let before = rules.len();
        rules.retain(|r| {
            let gone = pattern.matches(&r.rule.id);
            if gone {
                loaded.disabled.push(r.rule.id.clone());
            }
            !gone
        });
        if rules.len() == before {
            if pattern.is_mask() {
                loaded.warnings.push(format!("rules.disable: {key} matches no rule"));
            } else {
                bail!("rules.disable: no rule {key:?}");
            }
        }
    }
    // A tag that names no rule left is a warning, as a mask that matches nothing: the sets'
    // tags change with the binary.
    for tag in &config.disable_tags {
        if !rules.iter().any(|r| r.rule.tags.contains(tag)) {
            loaded
                .warnings
                .push(format!("rules.disable_tags: {tag} matches no rule"));
        }
    }
    if !config.disable_tags.is_empty() {
        rules.retain(|r| {
            let gone = r.rule.tags.iter().any(|t| config.disable_tags.contains(t));
            if gone {
                loaded.disabled.push(r.rule.id.clone());
            }
            !gone
        });
    }
    // Without libinjection its built-in rules are left out, after `override` and `disable` (which
    // may name them whatever the build); a site's own rule on a detector does not load (compile.rs).
    if !cfg!(feature = "libinjection") {
        rules.retain(|r| {
            !(r.rule.operator.is_libinjection()
                && detecting.contains(&r.rule.id)
                && !loaded.replaced.contains(&r.rule.id))
        });
    }
    for sourced in &rules {
        let rule = &sourced.rule;
        let set = rule.set.clone().unwrap_or_default();
        match loaded.counts.iter_mut().find(|(name, _)| *name == set) {
            Some((_, n)) => *n += 1,
            None => loaded.counts.push((set, 1)),
        }
        if matches!(rule.operator, Operator::Regex(_)) && rule.prefilter.is_empty() {
            loaded.warnings.push(format!(
                "rule {}: a regex without a prefilter runs on every request",
                rule.id
            ));
        }
        if rule.operator.is_libinjection() && rule.prefilter.is_empty() {
            loaded.warnings.push(format!(
                "rule {}: a libinjection detector without a prefilter runs on every value",
                rule.id
            ));
        }
    }
    if rules.iter().any(|r| r.rule.set.as_deref() == Some("scanners")) {
        loaded.warnings.push(
            "the scanners set refuses requests to /wp-login.php, /xmlrpc.php, /phpmyadmin and the like: turn its \
             path rules off (rules.disable: [wf-913-2*]) for a site that serves them"
                .to_string(),
        );
    }
    Ok((rules, loaded))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn durations_and_sizes() {
        assert_eq!(duration("10m").unwrap(), Duration::from_secs(600));
        assert_eq!(duration("1h").unwrap(), Duration::from_secs(3600));
        assert_eq!(duration("2d").unwrap(), Duration::from_secs(172_800));
        assert_eq!(duration("30s").unwrap(), Duration::from_secs(30));
        assert_eq!(duration("1h30m").unwrap(), Duration::from_secs(5400));
        assert_eq!(duration("45").unwrap(), Duration::from_secs(45));
        for bad in ["", "x", "10x", "m", "-1s"] {
            assert!(duration(bad).is_err(), "{bad:?}");
        }
        assert_eq!(size("64KiB").unwrap(), 65_536);
        assert_eq!(size("4KiB").unwrap(), 4096);
        assert_eq!(size("1MiB").unwrap(), 1 << 20);
        assert_eq!(size("512B").unwrap(), 512);
        assert_eq!(size("100").unwrap(), 100);
        assert!(size("1x").is_err());
        assert!(size("").is_err());
    }

    #[test]
    fn the_challenge_keys_read_and_need_the_module() {
        let config: FileConfig = webfast_core::yaml::from_str(
            "mode: challenge\nresponse:\n  challenge: pow\n  challenge_valid: 1d\n  challenge_bind: none\n  captcha: {provider: turnstile, site_key: k, secret: 'env:WEBFAST_NGFW_TEST_SECRET'}\naccess:\n  countries: {challenge: [CN]}\n  asn: {challenge: [AS1]}\n  ban: {then: challenge}\n",
        )
        .unwrap();
        assert_eq!(config.mode, Mode::Challenge);
        assert_eq!(config.response.challenge.as_deref(), Some("pow"));
        assert!(config.response.asks_challenge());
        assert!(!ResponseConfig::default().asks_challenge());
        let captcha = config.response.captcha.as_ref().unwrap();
        assert!(captcha.secret().is_err(), "the variable is not set");
        // SAFETY: the tests of this module do not read the environment concurrently with this.
        unsafe { std::env::set_var("WEBFAST_NGFW_TEST_SECRET", "s3") };
        assert_eq!(captcha.secret().unwrap(), "s3");
        assert_eq!(
            CaptchaConfig {
                provider: "turnstile".into(),
                site_key: "k".into(),
                secret: "literal".into(),
            }
            .secret()
            .unwrap(),
            "literal"
        );
        assert_eq!(config.access.countries.unwrap().challenge, ["CN"]);
        assert_eq!(config.access.asn.unwrap().challenge, ["AS1"]);
        assert_eq!(config.access.ban.then, super::super::ban::Then::Challenge);
        let rules: RulesFile = webfast_core::yaml::from_str(
            "rules:\n  - {id: a, phase: head, targets: [ua], operator: exists, action: challenge, mode: challenge}\n",
        )
        .unwrap();
        assert_eq!(rules.rules[0].action, Action::Challenge);
        assert_eq!(rules.rules[0].mode, Some(Mode::Challenge));
        assert_eq!(needs_challenge("x").is_ok(), cfg!(feature = "challenge"));
        if let Err(e) = needs_challenge("rule a: action challenge") {
            assert!(e.to_string().contains("built without the challenge module"), "{e}");
        }
    }

    #[test]
    fn the_file_reads_with_defaults_and_refuses_unknown_keys() {
        let config: FileConfig = webfast_core::yaml::from_str("threshold: 7\n").unwrap();
        assert_eq!(config.threshold, 7);
        assert_eq!(config.response.status, 403);
        assert_eq!(config.body.json_max_depth, 20);
        assert_eq!(config.rules.builtin, None);
        let config: FileConfig = webfast_core::yaml::from_str("").unwrap();
        assert_eq!(config.threshold, 5);
        assert!(webfast_core::yaml::from_str::<FileConfig>("thresold: 5\n").is_err());
        let config: FileConfig = webfast_core::yaml::from_str(
            "rules:\n  builtin: [sqli, xss]\n  override:\n    wf-942-100: {score: 2, mode: log_only}\n",
        )
        .unwrap();
        assert_eq!(
            config.rules.builtin.as_ref().unwrap().sets().unwrap(),
            vec!["sqli", "xss"]
        );
        assert_eq!(config.rules.overrides["wf-942-100"].score, Some(2));
        let config: FileConfig = webfast_core::yaml::from_str("rules:\n  builtin: none\n").unwrap();
        assert!(config.rules.builtin.as_ref().unwrap().sets().unwrap().is_empty());
        let config: FileConfig = webfast_core::yaml::from_str("rules:\n  builtin: [bogus]\n").unwrap();
        assert!(config.rules.builtin.as_ref().unwrap().sets().is_err());
    }

    fn site_file(dir: &Path, name: &str, text: &str) {
        std::fs::write(dir.join(name), text).unwrap();
    }

    #[test]
    fn composition_replaces_overrides_and_disables() {
        let dir = tempfile::tempdir().unwrap();
        // A first file stands in for the built-in sets (whose rules change with the binary).
        site_file(
            dir.path(),
            "base.yaml",
            r#"
rules:
  - id: wf-913-100
    set: scanners
    phase: head
    targets: [ua]
    operator: { contains_any: ['nikto'] }
  - id: wf-913-200
    set: scanners
    phase: head
    targets: [path]
    operator: { contains_any: ['/.env'] }
  - id: wf-942-100
    set: sqli
    phase: head
    targets: [args]
    operator: { contains_any: ['union select'] }
  - id: wf-942-130
    set: sqli
    phase: body
    targets: [args]
    operator: { contains_any: ['union select'] }
"#,
        );
        site_file(
            dir.path(),
            "site.yaml",
            r#"
rules:
  - id: wf-942-100
    phase: head
    targets: [args]
    operator: { contains_any: ['replaced'] }
  - id: my-rule
    phase: head
    targets: [ua]
    operator: { regex: 'x+' }
"#,
        );
        let config: RulesConfig = webfast_core::yaml::from_str(
            r#"
builtin: none
include: [base.yaml, site.yaml]
disable: [wf-913-1*, wf-942-130]
override:
  my-rule: { score: 1 }
  wf-913-*: { mode: log_only }
"#,
        )
        .unwrap();
        let (rules, loaded) = compose(&config, dir.path(), None).unwrap();
        let ids: Vec<&str> = rules.iter().map(|r| r.rule.id.as_str()).collect();
        // The replaced rule keeps its place; disabled ones are gone; the new site rule is last.
        assert_eq!(ids, ["wf-913-200", "wf-942-100", "my-rule"]);
        let replaced = &rules[1].rule;
        assert_eq!(
            replaced.set.as_deref(),
            Some("sqli"),
            "a replacement stays in the replaced rule's set"
        );
        assert_eq!(replaced.operator, Operator::ContainsAny(vec!["replaced".into()]));
        assert_eq!(rules[2].rule.set.as_deref(), Some("site"));
        assert_eq!(rules[2].rule.score, Some(1));
        assert_eq!(rules[0].rule.mode, Some(Mode::LogOnly), "a mask override");
        assert_eq!(loaded.replaced, ["wf-942-100"]);
        assert_eq!(loaded.disabled, ["wf-913-100", "wf-942-130"]);
        assert!(loaded.overridden.contains(&"my-rule".to_string()));
        assert!(loaded.overridden.contains(&"wf-913-200".to_string()));
        assert_eq!(
            loaded.counts,
            [
                ("scanners".to_string(), 1),
                ("sqli".to_string(), 1),
                ("site".to_string(), 1)
            ]
        );
        assert!(
            loaded
                .warnings
                .iter()
                .any(|w| w.contains("my-rule") && w.contains("prefilter"))
        );
        assert!(loaded.warnings.iter().any(|w| w.contains("scanners")));

        let config: RulesConfig =
            webfast_core::yaml::from_str("builtin: none\noverride: {nothing: {score: 1}}\n").unwrap();
        assert!(compose(&config, dir.path(), None).is_err(), "an override of no rule");
        let config: RulesConfig = webfast_core::yaml::from_str("builtin: none\ndisable: [nothing]\n").unwrap();
        assert!(compose(&config, dir.path(), None).is_err(), "a disable of no rule");
        let config: RulesConfig = webfast_core::yaml::from_str("builtin: none\ndisable: [nothing-*]\n").unwrap();
        let (rules, loaded) = compose(&config, dir.path(), None).unwrap();
        assert!(rules.is_empty());
        assert_eq!(loaded.warnings.len(), 1, "a mask that matches nothing is a warning");
    }

    #[test]
    fn disable_tags_takes_off_every_rule_with_a_tag() {
        let config: RulesConfig = webfast_core::yaml::from_str(
            "builtin: [scanners, cve]\ndisable: [wf-913-100]\ndisable_tags: [wordpress, spring, no-such-tag]\n",
        )
        .unwrap();
        let (rules, loaded) = compose(&config, Path::new("."), None).unwrap();
        let ids: Vec<&str> = rules.iter().map(|r| r.rule.id.as_str()).collect();
        assert!(!ids.contains(&"wf-913-200"), "the WordPress probe is off");
        assert!(ids.contains(&"wf-913-210"), "the rest of the set stays");
        assert!(
            !ids.iter()
                .any(|id| *id == "wf-cve-2022-22965" || *id == "wf-cve-2022-22963")
        );
        assert!(ids.contains(&"wf-cve-2021-41773"));
        // Listed with `disable`'s ids, in the order they went.
        assert_eq!(
            loaded.disabled,
            ["wf-913-100", "wf-913-200", "wf-cve-2022-22963", "wf-cve-2022-22965"]
        );
        assert!(
            loaded
                .warnings
                .iter()
                .any(|w| w == "rules.disable_tags: no-such-tag matches no rule"),
            "{:?}",
            loaded.warnings
        );
        assert!(!loaded.warnings.iter().any(|w| w.contains("wordpress")));
    }

    #[test]
    fn an_override_changes_the_metadata_too() {
        let config: RulesConfig = webfast_core::yaml::from_str(
            "builtin: [sqli]\noverride:\n  wf-942-100: {confidence: low, refs: {cwe: [CWE-20]}, doc: changed}\n",
        )
        .unwrap();
        let (rules, _) = compose(&config, Path::new("."), None).unwrap();
        let rule = &rules.iter().find(|r| r.rule.id == "wf-942-100").unwrap().rule;
        assert_eq!(rule.confidence, Some(Confidence::Low));
        assert_eq!(rule.refs.cwe, ["CWE-20"]);
        assert_eq!(rule.doc.as_deref(), Some("changed"));
    }

    #[test]
    fn every_builtin_set_parses_with_unique_ids() {
        let (rules, loaded) = compose(&RulesConfig::default(), Path::new("."), None).unwrap();
        assert_eq!(loaded.total(), rules.len());
        assert_eq!(loaded.counts.len(), super::super::rules::SETS.len());
        for rule in &rules {
            assert!(rule.rule.id.starts_with("wf-"), "{}", rule.rule.id);
        }
        // libinjection's two, with prefilters (no warning), when it is built.
        let detecting: Vec<&str> = rules
            .iter()
            .filter(|r| r.rule.operator.is_libinjection())
            .map(|r| r.rule.id.as_str())
            .collect();
        if cfg!(feature = "libinjection") {
            assert_eq!(detecting, ["wf-942-170", "wf-941-150"]);
        } else {
            assert!(detecting.is_empty());
        }
        assert!(!loaded.warnings.iter().any(|w| w.contains("libinjection")));
        // `disable` and `override` name them whatever the build.
        let config: RulesConfig = webfast_core::yaml::from_str(
            "builtin: [sqli, xss]\ndisable: [wf-941-150]\noverride: {wf-942-170: {score: 4}}\n",
        )
        .unwrap();
        let (rules, _) = compose(&config, Path::new("."), None).unwrap();
        assert!(!rules.iter().any(|r| r.rule.id == "wf-941-150"));
        assert_eq!(
            rules.iter().any(|r| r.rule.id == "wf-942-170"),
            cfg!(feature = "libinjection")
        );
    }
}
