//! A rule as the YAML gives it (docs/ngfw.md "The rule format"): its phase, targets,
//! transformations, the one operator, the action, and the enums each of those is drawn from.
//! What a rule becomes once compiled is in compile.rs.

use serde::Deserialize;
use std::collections::BTreeMap;
use std::fmt;

#[cfg_attr(test, derive(schemars::JsonSchema))]
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
    /// Requests the rule must match (`hit`) and must not match (`pass`): its tests, run in
    /// process and, written as go-ftw files, against a binary; not used by the server.
    #[serde(default)]
    pub examples: Examples,
}

/// A rule's examples: what it must match and what it must let be.
#[cfg_attr(test, derive(schemars::JsonSchema))]
#[derive(Deserialize, Debug, Clone, Default, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct Examples {
    /// Each one makes the rule match.
    #[serde(default)]
    pub hit: Vec<Example>,
    /// None makes the rule match: the near misses, the honest look-alikes.
    #[serde(default)]
    pub pass: Vec<Example>,
}

impl Examples {
    pub fn is_empty(&self) -> bool {
        self.hit.is_empty() && self.pass.is_empty()
    }
}

/// One example: a value, put where the rule looks (each of its targets that has a place in a
/// request: a query parameter, a cookie, a header, the path, a form or JSON body), or a request
/// written out whole, for what a value alone does not say (a path, a method, a missing header, a
/// response from the backend).
#[cfg_attr(test, derive(schemars::JsonSchema))]
#[derive(Deserialize, Debug, Clone, PartialEq)]
#[serde(untagged)]
pub enum Example {
    Value(String),
    Request(ExampleRequest),
}

/// A request written out: sent as it is, the `host` added when it has none (no User-Agent nor
/// Accept are added: an example of a rule on their absence needs them absent).
#[cfg_attr(test, derive(schemars::JsonSchema))]
#[derive(Deserialize, Debug, Clone, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct ExampleRequest {
    #[serde(default = "Example::get")]
    pub method: String,
    /// The request target as sent: percent-encoded where it has to be.
    #[serde(default = "Example::root")]
    pub uri: String,
    /// Names as given, lowercase by convention.
    #[serde(default)]
    pub headers: BTreeMap<String, String>,
    pub body: Option<String>,
    /// What the backend answers, for a rule of the `response` phase: sent to the backend's
    /// `/reflect` (albedo's), which answers with it.
    pub response: Option<ExampleResponse>,
    /// The request's bytes, sent as they are on a connection of their own (`\r\n` line ends
    /// written out), for what the fields above cannot say: another HTTP version, no Host, a
    /// header twice, a byte the HTTP parser may refuse. With it, none of the fields above. An
    /// HTTP/1.1 one ends its head with `Connection: close`, so the server closes after answering.
    pub raw: Option<String>,
    /// The status the server must answer: for a request refused before the filter sees it (the
    /// HTTP parser's 400), with the example in `pass`.
    pub status: Option<u16>,
}

/// A backend's answer for a `response` example.
#[cfg_attr(test, derive(schemars::JsonSchema))]
#[derive(Deserialize, Debug, Clone, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct ExampleResponse {
    #[serde(default = "Example::ok")]
    pub status: u16,
    #[serde(default)]
    pub headers: BTreeMap<String, String>,
    #[serde(default)]
    pub body: String,
}

impl Example {
    fn get() -> String {
        "GET".to_string()
    }
    fn root() -> String {
        "/".to_string()
    }
    fn ok() -> u16 {
        200
    }
}

/// A rules file: its description (`doc`, for docs/ngfw-rules.md), `rules:` and its list.
#[cfg_attr(test, derive(schemars::JsonSchema))]
#[derive(Deserialize, Debug, Default)]
#[serde(deny_unknown_fields)]
pub struct RulesFile {
    pub doc: Option<String>,
    #[serde(default)]
    pub rules: Vec<Rule>,
}

#[cfg_attr(test, derive(schemars::JsonSchema))]
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

#[cfg_attr(test, derive(schemars::JsonSchema))]
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
#[cfg_attr(test, derive(schemars::JsonSchema))]
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
#[cfg_attr(test, derive(schemars::JsonSchema))]
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

#[cfg_attr(test, derive(schemars::JsonSchema))]
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

#[cfg_attr(test, derive(schemars::JsonSchema))]
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

#[cfg_attr(test, derive(schemars::JsonSchema))]
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

    /// A target that is a number (for `gt`, `ge`, `lt`, `le`, `eq`, `ne`).
    pub fn is_numeric(&self) -> bool {
        matches!(
            self,
            Target::ArgsCount | Target::UploadCount | Target::ResponseStatus | Target::Asn
        )
    }
}

/// The one test of a rule (docs/ngfw.md "Operators").
#[cfg_attr(test, derive(schemars::JsonSchema))]
#[derive(Deserialize, Debug, Clone, PartialEq)]
#[serde(rename_all = "snake_case")]
pub enum Operator {
    ContainsAny(Vec<String>),
    EqualsAny(Vec<String>),
    StartsWithAny(Vec<String>),
    EndsWithAny(Vec<String>),
    Regex(String),
    /// The length in bytes of each value against a number.
    LengthGt(usize),
    LengthGe(usize),
    LengthLt(usize),
    LengthLe(usize),
    LengthEq(usize),
    LengthNe(usize),
    /// The number of the target's values against a number.
    CountGt(usize),
    CountGe(usize),
    CountLt(usize),
    CountLe(usize),
    CountEq(usize),
    CountNe(usize),
    /// A numeric target (`Target::is_numeric`) against a number.
    Gt(i64),
    Ge(i64),
    Lt(i64),
    Le(i64),
    Eq(i64),
    Ne(i64),
    /// A file of one literal per line, relative to the rules file.
    InSet(String),
    IpIn(Vec<String>),
    CountryIn(Vec<String>),
    #[serde(deserialize_with = "asn_list")]
    #[cfg_attr(test, schemars(with = "Vec<schema::Asn>"))]
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

    /// A comparison of a number with the operator's: what is compared, how, and the number.
    pub fn comparison(&self) -> Option<(Measure, Cmp, i64)> {
        use {Cmp::*, Measure::*};
        let n = |v: &usize| i64::try_from(*v).unwrap_or(i64::MAX);
        Some(match self {
            Operator::LengthGt(v) => (Length, Gt, n(v)),
            Operator::LengthGe(v) => (Length, Ge, n(v)),
            Operator::LengthLt(v) => (Length, Lt, n(v)),
            Operator::LengthLe(v) => (Length, Le, n(v)),
            Operator::LengthEq(v) => (Length, Eq, n(v)),
            Operator::LengthNe(v) => (Length, Ne, n(v)),
            Operator::CountGt(v) => (Count, Gt, n(v)),
            Operator::CountGe(v) => (Count, Ge, n(v)),
            Operator::CountLt(v) => (Count, Lt, n(v)),
            Operator::CountLe(v) => (Count, Le, n(v)),
            Operator::CountEq(v) => (Count, Eq, n(v)),
            Operator::CountNe(v) => (Count, Ne, n(v)),
            Operator::Gt(v) => (Number, Gt, *v),
            Operator::Ge(v) => (Number, Ge, *v),
            Operator::Lt(v) => (Number, Lt, *v),
            Operator::Le(v) => (Number, Le, *v),
            Operator::Eq(v) => (Number, Eq, *v),
            Operator::Ne(v) => (Number, Ne, *v),
            _ => return None,
        })
    }
}

/// What a comparison operator compares: each value's length (`length_*`), the number of the
/// target's values (`count_*`), or a numeric target's number (`gt` and the others).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Measure {
    Length,
    Count,
    Number,
}

impl Measure {
    /// The operator's name before the comparison: `length_`, `count_`, or none.
    pub fn prefix(self) -> &'static str {
        match self {
            Measure::Length => "length_",
            Measure::Count => "count_",
            Measure::Number => "",
        }
    }
}

/// A comparison, the measured number on the left: `gt` holds for 5 against 3.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Cmp {
    Gt,
    Ge,
    Lt,
    Le,
    Eq,
    Ne,
}

impl Cmp {
    pub fn holds(self, measured: i64, against: i64) -> bool {
        match self {
            Cmp::Gt => measured > against,
            Cmp::Ge => measured >= against,
            Cmp::Lt => measured < against,
            Cmp::Le => measured <= against,
            Cmp::Eq => measured == against,
            Cmp::Ne => measured != against,
        }
    }

    pub fn name(self) -> &'static str {
        match self {
            Cmp::Gt => "gt",
            Cmp::Ge => "ge",
            Cmp::Lt => "lt",
            Cmp::Le => "le",
            Cmp::Eq => "eq",
            Cmp::Ne => "ne",
        }
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

/// The number a rule id stands for, made from the id and stored nowhere: what test tools that
/// know rules by number (go-ftw's `rule_id` and `expect_ids`) and the log's `ruleId` use. Fixed by
/// the id alone, so a test that names it stays right:
/// - `wf-942-190` → 942190 (the six digits, as CRS numbers its rules);
/// - `wf-cve-2022-22965` → 20220022965 (the year, then the CVE's number in seven digits);
///   `wf-cve-…-b` to `-j`, a second to tenth rule for one CVE, adds 1 to 9 hundred billion.
///
/// Any other id (a site's own rules may be named freely) has none.
pub fn number_of(id: &str) -> Option<u64> {
    let digits = |s: &str, n: usize| s.len() == n && s.bytes().all(|b| b.is_ascii_digit());
    let rest = id.strip_prefix("wf-")?;
    if let Some(cve) = rest.strip_prefix("cve-") {
        let mut parts = cve.split('-');
        let (year, number, suffix) = (parts.next()?, parts.next()?, parts.next());
        if parts.next().is_some()
            || !digits(year, 4)
            || !(4..=7).contains(&number.len())
            || !digits(number, number.len())
        {
            return None;
        }
        let extra = match suffix {
            None => 0,
            Some(s) if s.len() == 1 && (b'b'..=b'j').contains(&s.as_bytes()[0]) => u64::from(s.as_bytes()[0] - b'a'),
            Some(_) => return None,
        };
        let (year, number): (u64, u64) = (year.parse().ok()?, number.parse().ok()?);
        return Some(extra * 100_000_000_000 + year * 10_000_000 + number);
    }
    let (section, rule) = rest.split_once('-')?;
    (digits(section, 3) && digits(rule, 3)).then(|| format!("{section}{rule}").parse().ok())?
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

/// The JSON Schema of a rules file (docs/ngfw-rules.schema.json), made in the tests from the
/// types serde reads: what serde's derive cannot say (a target's text, an ASN as a number or
/// `AS…`) is written here.
#[cfg(test)]
pub(crate) mod schema {
    use super::{RulesFile, Target};
    use schemars::{JsonSchema, Schema, SchemaGenerator, json_schema};
    use std::borrow::Cow;

    /// The targets of a fixed name; the named ones are `args.<name>`, `headers.<name>`,
    /// `cookies.<name>`, `response.headers.<name>` and `body.json/<pointer>`.
    pub const FIXED_TARGETS: &[&str] = &[
        "method",
        "version",
        "path",
        "path_raw",
        "query",
        "args",
        "args_names",
        "args_count",
        "headers",
        "headers_names",
        "cookies",
        "cookies_names",
        "ua",
        "host",
        "client_ip",
        "country",
        "asn",
        "body",
        "body.json",
        "upload.filename",
        "upload.ext",
        "upload.type",
        "upload.head",
        "upload.count",
        "tls.sni",
        "response.status",
        "response.body",
        "anomaly.double_encoding",
        "anomaly.json_depth",
        "anomaly.duplicate_content_length",
        "anomaly.http10_without_host",
        "anomaly.post_without_content_type",
        "anomaly.body_type_mismatch",
    ];

    impl JsonSchema for Target {
        fn schema_name() -> Cow<'static, str> {
            "Target".into()
        }

        fn json_schema(_: &mut SchemaGenerator) -> Schema {
            json_schema!({
                "description": "What the rule looks at (docs/ngfw.md \"Targets\"): a fixed name, or a named parameter, header, cookie, response header, or a JSON pointer into the body.",
                "anyOf": [
                    { "enum": FIXED_TARGETS },
                    { "type": "string", "pattern": "^(args|headers|cookies|response\\.headers)\\..+$" },
                    { "type": "string", "pattern": "^body\\.json/.*$" }
                ]
            })
        }
    }

    /// An ASN of `asn_in`: a number, or `AS` and a number.
    pub struct Asn;

    impl JsonSchema for Asn {
        fn schema_name() -> Cow<'static, str> {
            "Asn".into()
        }

        fn json_schema(_: &mut SchemaGenerator) -> Schema {
            json_schema!({
                "description": "An autonomous system: its number, or `AS` and its number.",
                "anyOf": [
                    { "type": "integer", "minimum": 0, "maximum": 4294967295u32 },
                    { "type": "string", "pattern": "^AS[0-9]+$" }
                ]
            })
        }
    }

    /// The schema as the file holds it: pretty JSON and a newline.
    pub fn text() -> String {
        let mut schema = schemars::schema_for!(RulesFile);
        schema.insert(
            "$id".to_string(),
            "https://github.com/ops-pro/webfast-modules/blob/main/docs/ngfw-rules.schema.json".into(),
        );
        schema.insert("title".to_string(), "webfast-ngfw rules file".into());
        let mut text = serde_json::to_string_pretty(&schema).unwrap();
        text.push('\n');
        text
    }

    #[test]
    fn every_fixed_target_parses_and_prints_its_name() {
        for name in FIXED_TARGETS {
            let target: Target = name.parse().unwrap_or_else(|e| panic!("{name}: {e}"));
            assert_eq!(target.to_string(), *name);
        }
    }

    #[test]
    fn the_rules_schema_is_current() {
        let text = text();
        let path = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../../docs/ngfw-rules.schema.json");
        if std::env::var_os("UPDATE_RULES_DOC").is_some() {
            std::fs::write(&path, &text).unwrap();
            return;
        }
        let current = std::fs::read_to_string(&path).unwrap_or_default().replace("\r\n", "\n");
        assert!(
            current == text,
            "docs/ngfw-rules.schema.json is out of date: run `UPDATE_RULES_DOC=1 cargo test -p webfast-ngfw`"
        );
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_rule_id_stands_for_its_number() {
        assert_eq!(number_of("wf-942-190"), Some(942_190));
        assert_eq!(number_of("wf-913-100"), Some(913_100));
        assert_eq!(number_of("wf-cve-2022-22965"), Some(20_220_022_965));
        assert_eq!(number_of("wf-cve-2014-6271"), Some(20_140_006_271));
        assert_eq!(number_of("wf-cve-2024-1234567"), Some(20_241_234_567));
        assert_eq!(number_of("wf-cve-2021-41773-b"), Some(120_210_041_773));
        for none in [
            "site-rule",
            "wf-94-190",
            "wf-942-1900",
            "wf-cve-22-1",
            "wf-cve-2022-123",
            "wf-cve-2022-1-a",
            "wf-cve-2022-1234-k",
            "xx-942-190",
        ] {
            assert_eq!(number_of(none), None, "{none}");
        }
    }

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
