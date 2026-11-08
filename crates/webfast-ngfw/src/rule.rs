//! A rule as the YAML gives it (docs/ngfw.md "The rule format"): its phase, targets,
//! transformations, the one operator, the action, and the enums each of those is drawn from.
//! What a rule becomes once compiled is in compile.rs.

use serde::Deserialize;
use std::collections::BTreeMap;
use std::fmt;

#[derive(Deserialize, Debug, Clone)]
#[serde(deny_unknown_fields)]
pub struct Rule {
    pub id: String,
    /// The set it belongs to; a site's rule without one is in `site`.
    pub set: Option<String>,
    pub phase: Phase,
    /// Defaults to the id.
    pub msg: Option<String>,
    #[serde(default)]
    pub severity: Severity,
    /// Explicit; else the severity's.
    pub score: Option<u32>,
    #[serde(default)]
    pub targets: Vec<Target>,
    #[serde(default)]
    pub transform: Vec<Transform>,
    pub operator: Operator,
    /// Literals one of which must occur before a `regex` runs.
    #[serde(default)]
    pub prefilter: Vec<String>,
    #[serde(default)]
    pub action: Action,
    /// With `action: header`: added to the request going on.
    #[serde(default)]
    pub header: BTreeMap<String, String>,
    /// Runs only if these rules matched earlier in this request.
    #[serde(default)]
    pub when: Vec<String>,
    /// Does not run if one of these matched.
    #[serde(default)]
    pub unless: Vec<String>,
    pub mode: Option<Mode>,
    #[serde(default)]
    pub tags: Vec<String>,
    /// How rare false positives are (`high`, `medium`, `low`); a rule without one is `medium`.
    /// Written in the log; no other effect yet.
    pub confidence: Option<Confidence>,
    /// CWE, CAPEC, CRS, CVE ids and advisory URLs (checked at load, `Refs::check`).
    #[serde(default)]
    pub refs: Refs,
    /// What the rule catches, why its score, where false positives come from, how to exclude
    /// it: for docs/ngfw-rules.md, not used by the server.
    pub doc: Option<String>,
}

/// A rules file: its description (`doc`, for docs/ngfw-rules.md), `rules:` and its list.
#[derive(Deserialize, Debug, Default)]
#[serde(deny_unknown_fields)]
pub struct RulesFile {
    pub doc: Option<String>,
    #[serde(default)]
    pub rules: Vec<Rule>,
}

#[derive(Deserialize, Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord, Default)]
#[serde(rename_all = "snake_case")]
pub enum Phase {
    #[default]
    Connection,
    Head,
    Body,
    Upload,
    Response,
}

impl Phase {
    pub const ALL: [Phase; 5] = [
        Phase::Connection,
        Phase::Head,
        Phase::Body,
        Phase::Upload,
        Phase::Response,
    ];

    pub fn index(self) -> usize {
        match self {
            Phase::Connection => 0,
            Phase::Head => 1,
            Phase::Body => 2,
            Phase::Upload => 3,
            Phase::Response => 4,
        }
    }

    pub fn name(self) -> &'static str {
        match self {
            Phase::Connection => "connection",
            Phase::Head => "head",
            Phase::Body => "body",
            Phase::Upload => "upload",
            Phase::Response => "response",
        }
    }
}

#[derive(Deserialize, Debug, Clone, Copy, PartialEq, Eq, Default)]
#[serde(rename_all = "snake_case")]
pub enum Severity {
    Critical,
    High,
    #[default]
    Medium,
    Low,
    Notice,
}

impl Severity {
    /// The default score of the severity.
    pub fn score(self) -> u32 {
        match self {
            Severity::Critical => 5,
            Severity::High => 4,
            Severity::Medium => 3,
            Severity::Low => 2,
            Severity::Notice => 1,
        }
    }

    pub fn name(self) -> &'static str {
        match self {
            Severity::Critical => "critical",
            Severity::High => "high",
            Severity::Medium => "medium",
            Severity::Low => "low",
            Severity::Notice => "notice",
        }
    }
}

/// How rare a rule's false positives are: the axis next to `severity` (what a hit means).
#[derive(Deserialize, Debug, Clone, Copy, PartialEq, Eq, Default)]
#[serde(rename_all = "snake_case")]
pub enum Confidence {
    /// An honest client practically never sends what the rule matches.
    High,
    #[default]
    Medium,
    /// A signal to add up with others rather than a verdict.
    Low,
}

impl Confidence {
    pub fn name(self) -> &'static str {
        match self {
            Confidence::High => "high",
            Confidence::Medium => "medium",
            Confidence::Low => "low",
        }
    }
}

/// What a rule refers to: weaknesses (CWE), attack patterns (CAPEC), the OWASP Core Rule Set's
/// rules it corresponds to (CRS ids, numbers), vulnerabilities (CVE), advisories (URLs).
#[derive(Deserialize, Debug, Clone, Default, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct Refs {
    #[serde(default)]
    pub cwe: Vec<String>,
    #[serde(default)]
    pub capec: Vec<String>,
    #[serde(default)]
    pub crs: Vec<u32>,
    #[serde(default)]
    pub cve: Vec<String>,
    #[serde(default)]
    pub urls: Vec<String>,
}

impl Refs {
    pub fn is_empty(&self) -> bool {
        self.cwe.is_empty()
            && self.capec.is_empty()
            && self.crs.is_empty()
            && self.cve.is_empty()
            && self.urls.is_empty()
    }

    /// Each value in its form: `CWE-<n>`, `CAPEC-<n>`, `CVE-<year>-<n of 4 digits or more>`, a
    /// CRS id of six digits, an `https://` URL. The error names the field (`refs.cwe: ...`).
    pub fn check(&self) -> Result<(), String> {
        fn digits(text: &str, min: usize, max: usize) -> bool {
            (min..=max).contains(&text.len()) && text.bytes().all(|b| b.is_ascii_digit())
        }
        for cwe in &self.cwe {
            if !cwe.strip_prefix("CWE-").is_some_and(|n| digits(n, 1, 6)) {
                return Err(format!("refs.cwe: {cwe:?} is not CWE-<number>"));
            }
        }
        for capec in &self.capec {
            if !capec.strip_prefix("CAPEC-").is_some_and(|n| digits(n, 1, 6)) {
                return Err(format!("refs.capec: {capec:?} is not CAPEC-<number>"));
            }
        }
        for crs in &self.crs {
            if !(100_000..=999_999).contains(crs) {
                return Err(format!("refs.crs: {crs} is not a CRS rule id (six digits)"));
            }
        }
        for cve in &self.cve {
            let valid = cve
                .strip_prefix("CVE-")
                .and_then(|rest| rest.split_once('-'))
                .is_some_and(|(year, number)| digits(year, 4, 4) && digits(number, 4, 12));
            if !valid {
                return Err(format!("refs.cve: {cve:?} is not CVE-<year>-<number>"));
            }
        }
        for url in &self.urls {
            let valid =
                url.strip_prefix("https://").is_some_and(|rest| !rest.is_empty()) && !url.contains(char::is_whitespace);
            if !valid {
                return Err(format!("refs.urls: {url:?} is not an https:// URL"));
            }
        }
        Ok(())
    }
}

#[derive(Deserialize, Debug, Clone, Copy, PartialEq, Eq, Default)]
#[serde(rename_all = "snake_case")]
pub enum Action {
    #[default]
    Score,
    Block,
    Log,
    Ban,
    Pass,
    Header,
    /// Refuses with the browser challenge (docs/challenge.md) unless the client passed it; needs
    /// the `challenge` feature.
    Challenge,
}

impl Action {
    pub fn name(self) -> &'static str {
        match self {
            Action::Score => "score",
            Action::Block => "block",
            Action::Log => "log",
            Action::Ban => "ban",
            Action::Pass => "pass",
            Action::Header => "header",
            Action::Challenge => "challenge",
        }
    }
}

#[derive(Deserialize, Debug, Clone, Copy, PartialEq, Eq, Default)]
#[serde(rename_all = "snake_case")]
pub enum Mode {
    #[default]
    Block,
    LogOnly,
    /// Every refusal by rule is the browser challenge instead (docs/challenge.md); needs the
    /// `challenge` feature.
    Challenge,
}

impl Mode {
    pub fn name(self) -> &'static str {
        match self {
            Mode::Block => "block",
            Mode::LogOnly => "log_only",
            Mode::Challenge => "challenge",
        }
    }
}

#[derive(Deserialize, Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[serde(rename_all = "snake_case")]
pub enum Transform {
    UrlDecode,
    HtmlDecode,
    Lowercase,
    NormalizePath,
    RemoveNulls,
    CompressWhitespace,
    RemoveComments,
    Base64Decode,
    JsDecode,
    CmdLine,
    Utf8ToUnicode,
}

impl Transform {
    pub fn name(self) -> &'static str {
        match self {
            Transform::UrlDecode => "url_decode",
            Transform::HtmlDecode => "html_decode",
            Transform::Lowercase => "lowercase",
            Transform::NormalizePath => "normalize_path",
            Transform::RemoveNulls => "remove_nulls",
            Transform::CompressWhitespace => "compress_whitespace",
            Transform::RemoveComments => "remove_comments",
            Transform::Base64Decode => "base64_decode",
            Transform::JsDecode => "js_decode",
            Transform::CmdLine => "cmd_line",
            Transform::Utf8ToUnicode => "utf8_to_unicode",
        }
    }
}

/// What a rule looks at (docs/ngfw.md "Targets"), parsed from its text.
#[derive(Deserialize, Debug, Clone, PartialEq, Eq, Hash)]
#[serde(try_from = "String")]
pub enum Target {
    Method,
    Version,
    Path,
    PathRaw,
    Query,
    Args,
    ArgsNames,
    Arg(String),
    ArgsCount,
    Headers,
    HeadersNames,
    Header(String),
    Cookies,
    CookiesNames,
    Cookie(String),
    Ua,
    Host,
    ClientIp,
    Country,
    Asn,
    Body,
    BodyJson,
    BodyJsonPointer(String),
    UploadFilename,
    UploadExt,
    UploadType,
    UploadHead,
    UploadCount,
    TlsSni,
    ResponseStatus,
    ResponseHeader(String),
    ResponseBody,
    /// `1` when a `url_decode` of this request needed a second pass.
    AnomalyDoubleEncoding,
    /// `1` when the JSON body is deeper than `json_max_depth`.
    AnomalyJsonDepth,
    /// `1` with two Content-Length fields, or Content-Length with Transfer-Encoding.
    AnomalyDuplicateContentLength,
    /// `1` for an HTTP/1.0 request without a Host.
    AnomalyHttp10WithoutHost,
    /// `1` for a POST, PUT or PATCH with a body and no Content-Type.
    AnomalyPostWithoutContentType,
    /// `1` when the body is declared JSON and its bytes are not JSON.
    AnomalyBodyTypeMismatch,
}

impl TryFrom<String> for Target {
    type Error = String;

    fn try_from(text: String) -> Result<Target, String> {
        text.parse()
    }
}

impl std::str::FromStr for Target {
    type Err = String;

    fn from_str(text: &str) -> Result<Target, String> {
        Ok(match text {
            "method" => Target::Method,
            "version" => Target::Version,
            "path" => Target::Path,
            "path_raw" => Target::PathRaw,
            "query" => Target::Query,
            "args" => Target::Args,
            "args_names" => Target::ArgsNames,
            "args_count" => Target::ArgsCount,
            "headers" => Target::Headers,
            "headers_names" => Target::HeadersNames,
            "cookies" => Target::Cookies,
            "cookies_names" => Target::CookiesNames,
            "ua" => Target::Ua,
            "host" => Target::Host,
            "client_ip" => Target::ClientIp,
            "country" => Target::Country,
            "asn" => Target::Asn,
            "body" => Target::Body,
            "body.json" => Target::BodyJson,
            "upload.filename" => Target::UploadFilename,
            "upload.ext" => Target::UploadExt,
            "upload.type" => Target::UploadType,
            "upload.head" => Target::UploadHead,
            "upload.count" => Target::UploadCount,
            "tls.sni" => Target::TlsSni,
            "response.status" => Target::ResponseStatus,
            "response.body" => Target::ResponseBody,
            "anomaly.double_encoding" => Target::AnomalyDoubleEncoding,
            "anomaly.json_depth" => Target::AnomalyJsonDepth,
            "anomaly.duplicate_content_length" => Target::AnomalyDuplicateContentLength,
            "anomaly.http10_without_host" => Target::AnomalyHttp10WithoutHost,
            "anomaly.post_without_content_type" => Target::AnomalyPostWithoutContentType,
            "anomaly.body_type_mismatch" => Target::AnomalyBodyTypeMismatch,
            _ => {
                let named = |prefix: &str| text.strip_prefix(prefix).filter(|n| !n.is_empty());
                if let Some(name) = named("args.") {
                    Target::Arg(name.to_string())
                } else if let Some(name) = named("headers.") {
                    Target::Header(name.to_ascii_lowercase())
                } else if let Some(name) = named("cookies.") {
                    Target::Cookie(name.to_string())
                } else if let Some(pointer) = text.strip_prefix("body.json").filter(|p| p.starts_with('/')) {
                    Target::BodyJsonPointer(pointer.to_string())
                } else if let Some(name) = named("response.headers.") {
                    Target::ResponseHeader(name.to_ascii_lowercase())
                } else {
                    return Err(format!("unknown target {text:?}"));
                }
            }
        })
    }
}

impl fmt::Display for Target {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Target::Method => f.write_str("method"),
            Target::Version => f.write_str("version"),
            Target::Path => f.write_str("path"),
            Target::PathRaw => f.write_str("path_raw"),
            Target::Query => f.write_str("query"),
            Target::Args => f.write_str("args"),
            Target::ArgsNames => f.write_str("args_names"),
            Target::Arg(name) => write!(f, "args.{name}"),
            Target::ArgsCount => f.write_str("args_count"),
            Target::Headers => f.write_str("headers"),
            Target::HeadersNames => f.write_str("headers_names"),
            Target::Header(name) => write!(f, "headers.{name}"),
            Target::Cookies => f.write_str("cookies"),
            Target::CookiesNames => f.write_str("cookies_names"),
            Target::Cookie(name) => write!(f, "cookies.{name}"),
            Target::Ua => f.write_str("ua"),
            Target::Host => f.write_str("host"),
            Target::ClientIp => f.write_str("client_ip"),
            Target::Country => f.write_str("country"),
            Target::Asn => f.write_str("asn"),
            Target::Body => f.write_str("body"),
            Target::BodyJson => f.write_str("body.json"),
            Target::BodyJsonPointer(pointer) => write!(f, "body.json{pointer}"),
            Target::UploadFilename => f.write_str("upload.filename"),
            Target::UploadExt => f.write_str("upload.ext"),
            Target::UploadType => f.write_str("upload.type"),
            Target::UploadHead => f.write_str("upload.head"),
            Target::UploadCount => f.write_str("upload.count"),
            Target::TlsSni => f.write_str("tls.sni"),
            Target::ResponseStatus => f.write_str("response.status"),
            Target::ResponseHeader(name) => write!(f, "response.headers.{name}"),
            Target::ResponseBody => f.write_str("response.body"),
            Target::AnomalyDoubleEncoding => f.write_str("anomaly.double_encoding"),
            Target::AnomalyJsonDepth => f.write_str("anomaly.json_depth"),
            Target::AnomalyDuplicateContentLength => f.write_str("anomaly.duplicate_content_length"),
            Target::AnomalyHttp10WithoutHost => f.write_str("anomaly.http10_without_host"),
            Target::AnomalyPostWithoutContentType => f.write_str("anomaly.post_without_content_type"),
            Target::AnomalyBodyTypeMismatch => f.write_str("anomaly.body_type_mismatch"),
        }
    }
}

impl Target {
    /// The phases a rule on the target may be in. A `head` rule on a body target runs in the body
    /// phase (`body_phase_too`), so a rule on `[args, cookies, body]` is written once.
    pub fn phases(&self) -> &'static [Phase] {
        use Phase::*;
        match self {
            Target::ClientIp | Target::Country | Target::Asn | Target::TlsSni => &[Connection, Head, Body, Upload],
            Target::Body
            | Target::BodyJson
            | Target::BodyJsonPointer(_)
            | Target::AnomalyJsonDepth
            | Target::AnomalyBodyTypeMismatch => &[Head, Body],
            Target::UploadFilename
            | Target::UploadExt
            | Target::UploadType
            | Target::UploadHead
            | Target::UploadCount => &[Upload],
            Target::ResponseStatus | Target::ResponseHeader(_) | Target::ResponseBody => &[Response],
            _ => &[Head, Body, Upload],
        }
    }

    /// A target whose values come (or come too) from the body: a `head` rule on it runs again in
    /// the body phase when a body is inspected.
    pub fn body_phase_too(&self) -> bool {
        matches!(
            self,
            Target::Args
                | Target::ArgsNames
                | Target::Arg(_)
                | Target::ArgsCount
                | Target::Body
                | Target::BodyJson
                | Target::BodyJsonPointer(_)
                | Target::AnomalyJsonDepth
                | Target::AnomalyBodyTypeMismatch
        )
    }

    /// A target with no value before a body is inspected.
    pub fn body_only(&self) -> bool {
        matches!(
            self,
            Target::Body
                | Target::BodyJson
                | Target::BodyJsonPointer(_)
                | Target::AnomalyJsonDepth
                | Target::AnomalyBodyTypeMismatch
        )
    }

    /// A target that is a number (for `gt`).
    pub fn is_numeric(&self) -> bool {
        matches!(
            self,
            Target::ArgsCount | Target::UploadCount | Target::ResponseStatus | Target::Asn
        )
    }
}

/// The one test of a rule (docs/ngfw.md "Operators").
#[derive(Deserialize, Debug, Clone, PartialEq)]
#[serde(rename_all = "snake_case")]
pub enum Operator {
    ContainsAny(Vec<String>),
    EqualsAny(Vec<String>),
    StartsWithAny(Vec<String>),
    EndsWithAny(Vec<String>),
    Regex(String),
    LengthGt(usize),
    CountGt(usize),
    Gt(i64),
    /// A file of one literal per line, relative to the rules file.
    InSet(String),
    IpIn(Vec<String>),
    CountryIn(Vec<String>),
    #[serde(deserialize_with = "asn_list")]
    AsnIn(Vec<u32>),
    MagicNot(Vec<String>),
    MagicIs(Vec<String>),
    NotValidUtf8,
    NotValidJson,
    Exists,
    Missing,
    /// libinjection's SQL injection detector on each value (src/detect.rs); needs the
    /// `libinjection` feature.
    DetectSqli,
    /// libinjection's XSS detector on each value; needs the `libinjection` feature.
    DetectXss,
}

impl Operator {
    /// One of libinjection's detectors.
    pub fn is_libinjection(&self) -> bool {
        matches!(self, Operator::DetectSqli | Operator::DetectXss)
    }
}

/// `[12345, AS6789]`: numbers, or `AS` and a number.
fn asn_list<'de, D: serde::Deserializer<'de>>(deserializer: D) -> Result<Vec<u32>, D::Error> {
    #[derive(Deserialize)]
    #[serde(untagged)]
    enum Item {
        Number(u32),
        Text(String),
    }
    let items: Vec<Item> = Vec::deserialize(deserializer)?;
    items
        .into_iter()
        .map(|item| match item {
            Item::Number(n) => Ok(n),
            Item::Text(text) => parse_asn(&text).map_err(serde::de::Error::custom),
        })
        .collect()
}

/// `AS12345` or `12345`.
pub fn parse_asn(text: &str) -> Result<u32, String> {
    let digits = text.trim();
    let digits = digits
        .strip_prefix("AS")
        .or_else(|| digits.strip_prefix("as"))
        .unwrap_or(digits);
    digits.parse().map_err(|_| format!("not an AS number: {text:?}"))
}

/// A rule id, or a mask with a trailing `*` (`wf-921-*`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum IdPattern {
    Exact(String),
    Prefix(String),
}

impl IdPattern {
    pub fn new(text: &str) -> IdPattern {
        match text.strip_suffix('*') {
            Some(prefix) => IdPattern::Prefix(prefix.to_string()),
            None => IdPattern::Exact(text.to_string()),
        }
    }

    pub fn matches(&self, id: &str) -> bool {
        match self {
            IdPattern::Exact(exact) => exact == id,
            IdPattern::Prefix(prefix) => id.starts_with(prefix),
        }
    }

    pub fn is_mask(&self) -> bool {
        matches!(self, IdPattern::Prefix(_))
    }
}

impl fmt::Display for IdPattern {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            IdPattern::Exact(id) => f.write_str(id),
            IdPattern::Prefix(prefix) => write!(f, "{prefix}*"),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn targets_parse_from_their_text_and_print_back() {
        for text in [
            "method",
            "path",
            "args",
            "args.q",
            "headers.referer",
            "cookies.session",
            "body.json",
            "body.json/user/name",
            "upload.ext",
            "response.headers.server",
            "anomaly.double_encoding",
        ] {
            let target: Target = text.parse().unwrap();
            assert_eq!(target.to_string(), text);
        }
        assert_eq!(
            "headers.Referer".parse::<Target>().unwrap(),
            Target::Header("referer".into())
        );
        assert!("bogus".parse::<Target>().is_err());
        assert!("args.".parse::<Target>().is_err());
        assert!("body.jsonx".parse::<Target>().is_err());
    }

    #[test]
    fn a_rule_reads_with_every_kind_of_operator() {
        let text = r#"
rules:
  - id: a
    phase: head
    targets: [args, headers.referer]
    transform: [url_decode, lowercase]
    operator: { contains_any: ['php://'] }
  - id: b
    phase: head
    targets: [ua]
    operator: exists
    action: header
    header: { X-Threat: ua }
  - id: c
    phase: connection
    operator: { asn_in: [AS12345, 6789] }
    severity: critical
  - id: d
    phase: head
    targets: [args_count]
    operator: { gt: 128 }
    prefilter: [x]
"#;
        let file: RulesFile = webfast_core::yaml::from_str(text).unwrap();
        assert_eq!(file.rules.len(), 4);
        assert_eq!(file.rules[0].operator, Operator::ContainsAny(vec!["php://".into()]));
        assert_eq!(file.rules[1].operator, Operator::Exists);
        assert_eq!(file.rules[1].action, Action::Header);
        assert_eq!(file.rules[2].operator, Operator::AsnIn(vec![12345, 6789]));
        assert_eq!(file.rules[2].severity.score(), 5);
        assert_eq!(file.rules[3].operator, Operator::Gt(128));
        assert!(
            webfast_core::yaml::from_str::<RulesFile>(
                "rules:\n  - id: x\n    phase: head\n    operator: exists\n    bogus: 1\n"
            )
            .is_err()
        );
    }

    #[test]
    fn metadata_reads_and_its_references_are_checked() {
        let text = r#"
doc: |
  The set.
rules:
  - id: a
    phase: head
    targets: [args]
    operator: { contains_any: [x] }
    confidence: high
    refs: { cwe: [CWE-89], capec: [CAPEC-66], crs: [942100], cve: [CVE-2021-44228], urls: ['https://example.com/a'] }
    doc: |
      What it catches.
  - id: b
    phase: head
    targets: [args]
    operator: { contains_any: [y] }
"#;
        let file: RulesFile = webfast_core::yaml::from_str(text).unwrap();
        assert_eq!(file.doc.as_deref(), Some("The set.\n"));
        let (a, b) = (&file.rules[0], &file.rules[1]);
        assert_eq!(a.confidence, Some(Confidence::High));
        assert_eq!(a.refs.crs, [942100]);
        assert_eq!(a.refs.cve, ["CVE-2021-44228"]);
        assert_eq!(a.doc.as_deref(), Some("What it catches.\n"));
        assert!(a.refs.check().is_ok());
        assert_eq!(b.confidence, None);
        assert_eq!(
            b.confidence.unwrap_or_default(),
            Confidence::Medium,
            "medium by default"
        );
        assert!(b.refs.is_empty() && b.refs.check().is_ok() && b.doc.is_none());
        for (refs, field) in [
            (
                Refs {
                    cwe: vec!["CWE89".into()],
                    ..Refs::default()
                },
                "refs.cwe",
            ),
            (
                Refs {
                    cwe: vec!["cwe-89".into()],
                    ..Refs::default()
                },
                "refs.cwe",
            ),
            (
                Refs {
                    capec: vec!["CAPEC-".into()],
                    ..Refs::default()
                },
                "refs.capec",
            ),
            (
                Refs {
                    crs: vec![94210],
                    ..Refs::default()
                },
                "refs.crs",
            ),
            (
                Refs {
                    cve: vec!["CVE-21-44228".into()],
                    ..Refs::default()
                },
                "refs.cve",
            ),
            (
                Refs {
                    cve: vec!["CVE-2021-442".into()],
                    ..Refs::default()
                },
                "refs.cve",
            ),
            (
                Refs {
                    urls: vec!["http://example.com".into()],
                    ..Refs::default()
                },
                "refs.urls",
            ),
        ] {
            let error = refs.check().unwrap_err();
            assert!(error.starts_with(field), "{error}");
        }
        assert!(
            webfast_core::yaml::from_str::<RulesFile>(
                "rules:\n  - {id: x, phase: head, targets: [ua], operator: exists, refs: {cwes: [CWE-1]}}\n"
            )
            .is_err(),
            "an unknown key under refs"
        );
        assert!(
            webfast_core::yaml::from_str::<RulesFile>(
                "rules:\n  - {id: x, phase: head, targets: [ua], operator: exists, confidence: certain}\n"
            )
            .is_err()
        );
    }

    #[test]
    fn id_patterns() {
        assert!(IdPattern::new("wf-921-*").matches("wf-921-100"));
        assert!(!IdPattern::new("wf-921-*").matches("wf-920-100"));
        assert!(IdPattern::new("wf-921-100").matches("wf-921-100"));
        assert!(!IdPattern::new("wf-921-100").matches("wf-921-1000"));
        assert_eq!(IdPattern::new("wf-9*").to_string(), "wf-9*");
        assert_eq!(parse_asn("AS12"), Ok(12));
        assert!(parse_asn("ASx").is_err());
    }
}
