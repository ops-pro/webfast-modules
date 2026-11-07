//! The challenge page: the built-in one (assets/challenge.html, `include_str!`, one file for every
//! level) and a site's own, split once at their placeholders and rendered per request into a
//! string of the final size. The built-in script's SHA-256 is computed at first use from the bytes
//! as they are served, for the `Content-Security-Policy` that lets it, and nothing else, run; a
//! site's own page gets the header only when the built-in script is its only one.

use super::token::encode_standard;
use aws_lc_rs::digest::{SHA256, digest};
use std::sync::LazyLock;

/// The built-in page.
const BUILTIN: &str = include_str!("../assets/challenge.html");
/// The built-in page's script placeholder in a site's own page.
const SCRIPT_PLACEHOLDER: &str = "{challenge.script}";

/// A page split at its placeholders.
#[derive(Debug)]
pub struct Page {
    segments: Vec<Segment>,
    /// The built-in script is the page's only one: the CSP hash covers it.
    hashed_script_only: bool,
}

#[derive(Debug)]
enum Segment {
    Text(Box<str>),
    Nonce,
    Level,
    Difficulty,
    Title,
    Host,
    RequestId,
    SiteKey,
    Provider,
    Script,
}

/// What a page is filled with.
pub struct Values<'a> {
    pub nonce: &'a str,
    pub level: &'a str,
    pub difficulty: u8,
    pub title: &'a str,
    pub host: &'a str,
    pub request_id: &'a str,
    pub site_key: &'a str,
    pub provider: &'a str,
}

static BUILTIN_PAGE: LazyLock<Page> = LazyLock::new(|| Page::parse(BUILTIN));

/// The built-in script, as served, between its tags.
static SCRIPT: LazyLock<&'static str> = LazyLock::new(|| {
    let start = BUILTIN.find("<script>").map(|at| at + "<script>".len()).unwrap_or(0);
    let end = BUILTIN[start..]
        .find("</script>")
        .map_or(BUILTIN.len(), |at| start + at);
    &BUILTIN[start..end]
});

/// `sha256-…` of the built-in script, for `script-src`.
static SCRIPT_HASH: LazyLock<String> = LazyLock::new(|| {
    format!(
        "sha256-{}",
        encode_standard(digest(&SHA256, SCRIPT.as_bytes()).as_ref())
    )
});

/// The built-in page.
pub fn builtin() -> &'static Page {
    &BUILTIN_PAGE
}

/// The built-in script's text (what `{challenge.script}` stands for).
pub fn script() -> &'static str {
    &SCRIPT
}

/// The built-in script's CSP source: `'sha256-…'`.
pub fn script_hash() -> &'static str {
    &SCRIPT_HASH
}

impl Page {
    /// A site's own page, read now.
    pub fn from_file(path: &std::path::Path) -> std::io::Result<Page> {
        Ok(Page::parse(&std::fs::read_to_string(path)?))
    }

    /// `text` split at its `{challenge.*}` placeholders; unknown ones stay as they are.
    pub fn parse(text: &str) -> Page {
        let mut segments = Vec::new();
        let mut rest = text;
        while let Some(at) = rest.find("{challenge.") {
            let Some(len) = rest[at..].find('}') else {
                break;
            };
            let name = &rest[at + "{challenge.".len()..at + len];
            let segment = match name {
                "nonce" => Segment::Nonce,
                "level" => Segment::Level,
                "difficulty" => Segment::Difficulty,
                "title" => Segment::Title,
                "host" => Segment::Host,
                "request_id" => Segment::RequestId,
                "site_key" => Segment::SiteKey,
                "provider" => Segment::Provider,
                "script" => Segment::Script,
                _ => {
                    push_text(&mut segments, &rest[..at + len + 1]);
                    rest = &rest[at + len + 1..];
                    continue;
                }
            };
            push_text(&mut segments, &rest[..at]);
            segments.push(segment);
            rest = &rest[at + len + 1..];
        }
        push_text(&mut segments, rest);
        let scripts = text.matches("<script").count();
        let hashed_script_only = if std::ptr::eq(text, BUILTIN) || text == BUILTIN {
            scripts == 1
        } else {
            scripts == 1 && text.contains(&format!("<script>{SCRIPT_PLACEHOLDER}</script>"))
        };
        Page {
            segments,
            hashed_script_only,
        }
    }

    /// Whether the response may carry the CSP that allows the built-in script alone.
    pub fn hashed_script_only(&self) -> bool {
        self.hashed_script_only
    }

    /// The page with `values` in place (HTML-escaped, the script as it is).
    pub fn render(&self, values: &Values<'_>) -> String {
        let fixed: usize = self
            .segments
            .iter()
            .map(|s| match s {
                Segment::Text(t) => t.len(),
                Segment::Script => script().len(),
                _ => 64,
            })
            .sum();
        let mut out = String::with_capacity(fixed + values.title.len() + values.host.len());
        for segment in &self.segments {
            match segment {
                Segment::Text(text) => out.push_str(text),
                Segment::Nonce => escape_into(values.nonce, &mut out),
                Segment::Level => escape_into(values.level, &mut out),
                Segment::Difficulty => out.push_str(&values.difficulty.to_string()),
                Segment::Title => escape_into(values.title, &mut out),
                Segment::Host => escape_into(values.host, &mut out),
                Segment::RequestId => escape_into(values.request_id, &mut out),
                Segment::SiteKey => escape_into(values.site_key, &mut out),
                Segment::Provider => escape_into(values.provider, &mut out),
                Segment::Script => out.push_str(script()),
            }
        }
        out
    }
}

fn push_text(segments: &mut Vec<Segment>, text: &str) {
    if text.is_empty() {
        return;
    }
    if let Some(Segment::Text(last)) = segments.last_mut() {
        let mut joined = String::with_capacity(last.len() + text.len());
        joined.push_str(last);
        joined.push_str(text);
        *last = joined.into_boxed_str();
        return;
    }
    segments.push(Segment::Text(Box::from(text)));
}

/// `text` with `& < > " '` escaped, for an attribute value or text.
pub fn escape_into(text: &str, out: &mut String) {
    for c in text.chars() {
        match c {
            '&' => out.push_str("&amp;"),
            '<' => out.push_str("&lt;"),
            '>' => out.push_str("&gt;"),
            '"' => out.push_str("&quot;"),
            '\'' => out.push_str("&#39;"),
            other => out.push(other),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn values<'a>() -> Values<'a> {
        Values {
            nonce: "AQAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
            level: "pow",
            difficulty: 18,
            title: "Just a moment...",
            host: "shop.example.com",
            request_id: "0123456789ab",
            site_key: "",
            provider: "",
        }
    }

    #[test]
    fn every_placeholder_is_filled_and_the_page_stays_small() {
        let page = builtin().render(&values());
        assert!(!page.contains("{challenge."), "a placeholder left: {page}");
        assert!(page.contains(r#"data-nonce="AQAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA""#));
        assert!(page.contains(r#"data-level="pow""#));
        assert!(page.contains(r#"data-difficulty="18""#));
        assert!(page.contains("<h1>shop.example.com</h1>"));
        assert!(page.contains("<h2>Just a moment...</h2>"));
        assert!(page.contains("<title>Just a moment...</title>"));
        assert!(page.contains("Request 0123456789ab"));
        assert!(page.contains("<noscript>"));
        assert!(page.contains("webfast"));
        assert!(page.len() < 6 * 1024, "{} bytes", page.len());
        assert!(builtin().hashed_script_only());
        // No brand, no company: the providers' script URLs are the one vendor reference, in the script.
        let without_script = page.replace(script(), "");
        for word in ["Cloudflare", "Google", "hCaptcha", "Turnstile", "reCAPTCHA"] {
            assert!(!without_script.contains(word), "{word} named on the page");
        }
    }

    #[test]
    fn the_csp_hash_is_of_the_script_as_served() {
        let page = builtin().render(&values());
        let start = page.find("<script>").unwrap() + "<script>".len();
        let end = page[start..].find("</script>").unwrap() + start;
        assert_eq!(&page[start..end], script(), "the script is served verbatim");
        let expected = format!(
            "sha256-{}",
            encode_standard(digest(&SHA256, &page.as_bytes()[start..end]).as_ref())
        );
        assert_eq!(script_hash(), expected);
        assert!(script().contains("/.well-known/c-wf"));
        assert!(!script().contains("</script"), "the script must not end itself");
    }

    #[test]
    fn a_site_page_takes_the_placeholders_and_is_hashed_only_with_the_built_in_script() {
        let own = Page::parse(
            "<html><body data-nonce=\"{challenge.nonce}\" data-level=\"{challenge.level}\">{challenge.host} \
             {challenge.title} {challenge.difficulty} {challenge.request_id} {challenge.site_key} \
             {challenge.provider} {challenge.unknown} <script>{challenge.script}</script></body></html>",
        );
        let text = own.render(&Values {
            host: "a<b",
            title: "x\"y",
            ..values()
        });
        assert!(text.contains("a&lt;b x&quot;y 18 0123456789ab"));
        assert!(text.contains("{challenge.unknown}"), "unknown placeholders stay");
        assert!(text.contains(&format!("<script>{}</script>", script())));
        assert!(own.hashed_script_only());
        let scripted = Page::parse("<script>alert(1)</script><script>{challenge.script}</script>");
        assert!(!scripted.hashed_script_only(), "a script of its own: no CSP");
        let without = Page::parse("<p>{challenge.nonce}</p>");
        assert!(!without.hashed_script_only());
        assert!(!own.render(&values()).contains("{challenge.script}"));
    }
}
