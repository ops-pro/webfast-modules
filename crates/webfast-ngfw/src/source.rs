//! Where a hit's matched text came from (webfast's docs/logging.md, "Sources"): what the log's
//! policy raises its class by, so that a rule matching in `Authorization`, a cookie, a token's
//! query parameter or a password field writes its rule and target but not the value.
//!
//! A source named by the request (a parameter, a header, a cookie, a body field) is kept with its
//! name and classed when the line is made, under the policy in place then. A composite one — the
//! query string, the path, a `Referer`, a JSON body read whole — is classed when the hit is found,
//! while the text it was found in is at hand: the most hidden of the parts the match touches.

use super::rule::Target;
use std::ops::Range;
use webfast_core::privacy::{Class, Policy, Source};

/// Where a hit's matched text came from.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum HitSource {
    /// A query or form parameter, by its name as sent.
    Arg(String),
    /// A request header, by its name.
    Header(String),
    /// A cookie: always a secret.
    Cookie(String),
    /// A field of a body (a JSON pointer, a SecLang name such as `json.user.password`).
    Body(String),
    /// The names of a collection: a name is not its value.
    Names,
    /// A count of a collection's values.
    Count,
    /// A response header, by its name.
    ResponseHeader(String),
    /// The response's body.
    ResponseBody,
    /// About the person (the User-Agent, the client's address, its TLS fingerprint).
    Personal,
    /// What the request carried, nothing in it hidden by name (the method, a path, a query whose
    /// parameters the match did not touch a secret of).
    Payload,
    /// Several values in one that cannot be taken apart (a raw body, every header at once), or a
    /// composite one whose match touched a secret: hidden whole.
    Opaque,
}

impl HitSource {
    /// As the policy takes it: a parameter named as a body's secret field (`password`) is one,
    /// and never hashed.
    pub fn source<'a>(&'a self, policy: &Policy) -> Source<'a> {
        match self {
            HitSource::Arg(name) if policy.secret_field(name) => Source::Body(name),
            HitSource::Arg(name) => Source::Query(name),
            HitSource::Header(name) if name.eq_ignore_ascii_case("user-agent") => Source::Personal,
            HitSource::Header(name) => Source::Header(name),
            HitSource::Cookie(name) => Source::Cookie(name),
            HitSource::Body(name) => Source::Body(name),
            HitSource::Names => Source::Names,
            HitSource::Count => Source::Count,
            HitSource::ResponseHeader(name) => Source::ResponseHeader(name),
            HitSource::ResponseBody => Source::ResponseBody,
            HitSource::Personal => Source::Personal,
            HitSource::Payload => Source::Derived,
            HitSource::Opaque => Source::Opaque,
        }
    }

    /// The class of a payload from here.
    pub fn class(&self, policy: &Policy) -> Class {
        policy.class_of(Class::Payload, self.source(policy))
    }

    /// The more hidden of the two (a chain's free text may carry the value of any of its links).
    pub fn most_hidden(self, other: HitSource, policy: &Policy) -> HitSource {
        if rank(other.class(policy)) > rank(self.class(policy)) {
            other
        } else {
            self
        }
    }

    /// The source of a composite value whose class was worked out over its parts.
    fn of_class(class: Class) -> HitSource {
        match class {
            Class::Secret => HitSource::Opaque,
            Class::Personal => HitSource::Personal,
            Class::Payload | Class::Public => HitSource::Payload,
        }
    }

    /// A built-in rule's hit on `target` (the value's `name` in a collection), found at `range`
    /// of `text`.
    pub fn of_target(
        target: &Target,
        name: Option<&str>,
        text: &str,
        range: Range<usize>,
        parts: &http::request::Parts,
        json: Option<&serde_json::Value>,
    ) -> HitSource {
        let policy = || webfast_core::privacy::policy();
        match (target, name) {
            (Target::Arg(name), _) => HitSource::Arg(name.clone()),
            (Target::Args, Some(name)) => HitSource::Arg(name.to_string()),
            (Target::Header(name), _) => header(name, parts, &policy()),
            (Target::Headers, Some(name)) => header(name, parts, &policy()),
            (Target::Cookie(name), _) => HitSource::Cookie(name.clone()),
            (Target::Cookies, Some(name)) => HitSource::Cookie(name.to_string()),
            (Target::BodyJsonPointer(pointer), _) => HitSource::Body(pointer.clone()),
            // A string of the JSON body, its key not told: a secret if the body has a field the
            // policy holds secret anywhere.
            (Target::BodyJson, _) => match json {
                Some(json) if json_has_secret(json, &policy()) => HitSource::Opaque,
                Some(_) => HitSource::Payload,
                None => HitSource::Opaque,
            },
            (Target::Query, _) => HitSource::of_class(policy().query_class(text, range)),
            (Target::Path | Target::PathRaw, _) => HitSource::of_class(policy().path_class(text, range)),
            (Target::ArgsNames | Target::HeadersNames | Target::CookiesNames, _) => HitSource::Names,
            (Target::ArgsCount | Target::UploadCount, _) => HitSource::Count,
            (Target::Ua | Target::ClientIp | Target::TlsJa4, _) => HitSource::Personal,
            (Target::ResponseHeader(name), _) => HitSource::ResponseHeader(name.clone()),
            (Target::ResponseBody, _) => HitSource::ResponseBody,
            (Target::Args | Target::Headers | Target::Cookies | Target::Body, _) => HitSource::Opaque,
            _ => HitSource::Payload,
        }
    }

    /// A rule engine's hit (src/plugin.rs) on a SecLang variable: `ARGS:q`,
    /// `REQUEST_HEADERS:authorization`, `REQUEST_URI`.
    pub fn of_seclang(variable: &str, parts: &http::request::Parts, policy: &Policy) -> HitSource {
        let (collection, key) = match variable.split_once(':') {
            Some((collection, key)) => (collection, Some(key)),
            None => (variable, None),
        };
        match (collection, key) {
            ("ARGS" | "ARGS_GET" | "ARGS_POST", Some(name)) => HitSource::Arg(name.to_string()),
            ("REQUEST_HEADERS", Some(name)) => header(name, parts, policy),
            ("REQUEST_COOKIES", Some(name)) => HitSource::Cookie(name.to_string()),
            ("RESPONSE_HEADERS", Some(name)) => HitSource::ResponseHeader(name.to_ascii_lowercase()),
            ("RESPONSE_BODY", _) => HitSource::ResponseBody,
            (
                "ARGS_NAMES"
                | "ARGS_GET_NAMES"
                | "ARGS_POST_NAMES"
                | "REQUEST_HEADERS_NAMES"
                | "REQUEST_COOKIES_NAMES"
                | "FILES_NAMES"
                | "RESPONSE_HEADERS_NAMES",
                _,
            ) => HitSource::Names,
            // The URI and the parts of it: classed whole, as the request has it (a value matched
            // there may be a capture, not where it was).
            (
                "REQUEST_URI" | "REQUEST_URI_RAW" | "REQUEST_LINE" | "QUERY_STRING" | "REQUEST_FILENAME"
                | "REQUEST_BASENAME" | "PATH_INFO",
                _,
            ) => HitSource::of_class(policy.uri_class(parts.uri.path_and_query().map_or("/", |pq| pq.as_str()), 0..0)),
            ("REMOTE_ADDR" | "REMOTE_HOST", _) => HitSource::Personal,
            (
                "REQUEST_METHOD"
                | "REQUEST_PROTOCOL"
                | "SERVER_NAME"
                | "SERVER_PORT"
                | "REQUEST_BODY_LENGTH"
                | "ARGS_COMBINED_SIZE"
                | "FILES"
                | "FILES_SIZES"
                | "FILES_COMBINED_SIZE"
                | "REQBODY_PROCESSOR"
                | "REQBODY_ERROR"
                | "UNIQUE_ID"
                | "TX"
                | "MATCHED_VAR"
                | "MATCHED_VAR_NAME"
                | "MATCHED_VARS"
                | "MATCHED_VARS_NAMES",
                _,
            ) => HitSource::Payload,
            // The body whole, every header or cookie at once, a part's headers, XML, and what is
            // not known here.
            _ => HitSource::Opaque,
        }
    }
}

/// A header's source: one whose value is a URI (`Referer`) is classed by its query's parameters.
fn header(name: &str, parts: &http::request::Parts, policy: &Policy) -> HitSource {
    if name.eq_ignore_ascii_case("referer")
        && let Some(value) = parts.headers.get(http::header::REFERER)
        && policy.uri_class(&String::from_utf8_lossy(value.as_bytes()), 0..0) == Class::Secret
    {
        return HitSource::Opaque;
    }
    HitSource::Header(name.to_ascii_lowercase())
}

/// Whether a JSON value has a field, at any depth, whose name the policy holds secret.
fn json_has_secret(value: &serde_json::Value, policy: &Policy) -> bool {
    match value {
        serde_json::Value::Object(map) => map
            .iter()
            .any(|(key, value)| policy.secret_field(key) || json_has_secret(value, policy)),
        serde_json::Value::Array(items) => items.iter().any(|v| json_has_secret(v, policy)),
        _ => false,
    }
}

fn rank(class: Class) -> u8 {
    match class {
        Class::Public => 0,
        Class::Payload => 1,
        Class::Personal => 2,
        Class::Secret => 3,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn parts(uri: &str, referer: Option<&str>) -> http::request::Parts {
        let mut builder = http::Request::get(uri);
        if let Some(referer) = referer {
            builder = builder.header("referer", referer);
        }
        builder.body(()).unwrap().into_parts().0
    }

    #[test]
    fn a_source_is_classed_by_its_name_and_its_parts() {
        let policy = Policy::default();
        let p = parts("/a?q=1", None);
        let class = |s: HitSource| s.class(&policy);
        assert_eq!(class(HitSource::Arg("q".into())), Class::Payload);
        assert_eq!(class(HitSource::Arg("password".into())), Class::Secret);
        assert_eq!(class(HitSource::Header("authorization".into())), Class::Secret);
        assert_eq!(class(HitSource::Header("user-agent".into())), Class::Personal);
        assert_eq!(class(HitSource::Cookie("theme".into())), Class::Secret);
        assert_eq!(class(HitSource::Names), Class::Payload);
        assert_eq!(class(HitSource::Opaque), Class::Secret);
        // SecLang's names.
        let of = |v: &str| HitSource::of_seclang(v, &p, &policy);
        assert_eq!(of("ARGS:q"), HitSource::Arg("q".into()));
        assert_eq!(
            of("REQUEST_HEADERS:Authorization"),
            HitSource::Header("authorization".into())
        );
        assert_eq!(of("ARGS_NAMES:password"), HitSource::Names);
        assert_eq!(of("REQUEST_BODY"), HitSource::Opaque);
        assert_eq!(of("REQUEST_HEADERS"), HitSource::Opaque);
        assert_eq!(of("REQUEST_URI"), HitSource::Payload);
        assert_eq!(of("REQUEST_METHOD"), HitSource::Payload);
        // A query that carries a secret: its URI is hidden whole for an engine's hit.
        let p = parts("/a?q=1&password=x", Some("https://example.com/r?password=y"));
        assert_eq!(HitSource::of_seclang("REQUEST_URI", &p, &policy), HitSource::Opaque);
        assert_eq!(
            HitSource::of_seclang("REQUEST_HEADERS:referer", &p, &policy),
            HitSource::Opaque
        );
        // A built-in rule's on the query string: what the match touches.
        let q = "q=union+select&password=hunter2";
        let built = |range: Range<usize>| HitSource::of_target(&Target::Query, None, q, range, &p, None);
        assert_eq!(built(2..14), HitSource::Payload);
        assert_eq!(built(24..31), HitSource::Opaque);
        assert_eq!(built(0..0), HitSource::Opaque, "the whole");
        let json: serde_json::Value = serde_json::json!({"user": {"name": "a", "password": "b"}});
        assert_eq!(
            HitSource::of_target(&Target::BodyJson, None, "a", 0..1, &p, Some(&json)),
            HitSource::Opaque
        );
        let json: serde_json::Value = serde_json::json!({"q": "a"});
        assert_eq!(
            HitSource::of_target(&Target::BodyJson, None, "a", 0..1, &p, Some(&json)),
            HitSource::Payload
        );
    }
}
