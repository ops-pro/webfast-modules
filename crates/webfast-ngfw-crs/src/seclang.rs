//! SecLang, the language of ModSecurity's rules, as the CRS writes it: the text split into
//! directives (comments dropped, `\` at a line's end joining it to the next), each directive's
//! arguments (bare words, or double-quoted with `\"` for a quote), and the three parts of a rule —
//! its variables (`ARGS|!ARGS:foo|&TX:x|XML:/*`), its operator (`!@rx …`, a bare text being a
//! regex) and its actions (`id:1,phase:2,t:none,msg:'…'`).

use anyhow::{Result, anyhow, bail};

/// One directive and where it is.
#[derive(Debug, Clone)]
pub struct Directive {
    pub name: String,
    pub args: Vec<String>,
    /// `file:line` of its first line.
    pub at: String,
}

/// The directives of a file's text.
pub fn directives(text: &str, file: &str) -> Result<Vec<Directive>> {
    let mut out = Vec::new();
    let mut lines = text.lines().enumerate().peekable();
    while let Some((n, line)) = lines.next() {
        let trimmed = line.trim_start();
        if trimmed.is_empty() || trimmed.starts_with('#') {
            continue;
        }
        // A line ending in a backslash goes on in the next: the backslash and the line break go.
        let mut joined = String::new();
        let mut current = line.trim_end_matches(['\r']).to_string();
        loop {
            if let Some(stripped) = current.strip_suffix('\\') {
                joined.push_str(stripped);
                match lines.next() {
                    Some((_, next)) => current = next.trim_end_matches(['\r']).to_string(),
                    None => break,
                }
            } else {
                joined.push_str(&current);
                break;
            }
        }
        let at = format!("{file}:{}", n + 1);
        let words = split_args(&joined).map_err(|e| anyhow!("{at}: {e}"))?;
        let mut words = words.into_iter();
        let Some(name) = words.next() else { continue };
        out.push(Directive {
            name,
            args: words.collect(),
            at,
        });
    }
    Ok(out)
}

/// A directive's line into words: bare ones end at whitespace; a double-quoted one keeps
/// everything to its closing quote, with `\"` for a quote (other backslashes stay as they are).
fn split_args(line: &str) -> Result<Vec<String>> {
    let mut words = Vec::new();
    let mut chars = line.chars().peekable();
    loop {
        while chars.peek().is_some_and(|c| c.is_whitespace()) {
            chars.next();
        }
        let Some(&first) = chars.peek() else { break };
        let mut word = String::new();
        if first == '"' {
            chars.next();
            let mut closed = false;
            while let Some(c) = chars.next() {
                match c {
                    '\\' if chars.peek() == Some(&'"') => {
                        word.push('"');
                        chars.next();
                    }
                    '"' => {
                        closed = true;
                        break;
                    }
                    c => word.push(c),
                }
            }
            if !closed {
                bail!("a quoted argument is not closed");
            }
        } else {
            while let Some(&c) = chars.peek() {
                if c.is_whitespace() {
                    break;
                }
                word.push(c);
                chars.next();
            }
        }
        words.push(word);
    }
    Ok(words)
}

/// One variable of a rule: `[!&]NAME[:selector]`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Variable {
    /// Upper case: `ARGS`, `REQUEST_HEADERS`.
    pub collection: String,
    pub selector: Option<Selector>,
    /// `&`: the number of values, not the values.
    pub count: bool,
    /// `!`: left out of the rule's other variables.
    pub exclude: bool,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Selector {
    /// A key, compared ignoring case.
    Key(String),
    /// `/regex/`: the keys it matches (ignoring case).
    Regex(String),
}

/// `ARGS|!ARGS:foo|&TX:x|REQUEST_COOKIES:/^_ga/` into its variables.
pub fn variables(text: &str) -> Result<Vec<Variable>> {
    let mut out = Vec::new();
    let mut chars = text.chars().peekable();
    while chars.peek().is_some() {
        let mut exclude = false;
        let mut count = false;
        loop {
            match chars.peek() {
                Some('!') => exclude = true,
                Some('&') => count = true,
                _ => break,
            }
            chars.next();
        }
        let mut collection = String::new();
        while let Some(&c) = chars.peek() {
            if c == ':' || c == '|' {
                break;
            }
            collection.push(c);
            chars.next();
        }
        let collection = collection.trim().to_ascii_uppercase();
        if collection.is_empty() {
            bail!("an empty variable in {text:?}");
        }
        let mut selector = None;
        if chars.peek() == Some(&':') {
            chars.next();
            match chars.peek() {
                // An XPath (`XML:/*`, `XML://@*`): to the next `|`, as it is.
                _ if collection == "XML" => {
                    let mut key = String::new();
                    while let Some(&c) = chars.peek() {
                        if c == '|' {
                            break;
                        }
                        key.push(c);
                        chars.next();
                    }
                    selector = Some(Selector::Key(key));
                }
                Some('/') => {
                    chars.next();
                    let mut re = String::new();
                    let mut closed = false;
                    while let Some(c) = chars.next() {
                        match c {
                            '\\' => {
                                re.push('\\');
                                if let Some(n) = chars.next() {
                                    re.push(n);
                                }
                            }
                            '/' => {
                                closed = true;
                                break;
                            }
                            c => re.push(c),
                        }
                    }
                    if !closed {
                        bail!("a /regex/ selector is not closed in {text:?}");
                    }
                    selector = Some(Selector::Regex(re));
                }
                Some('\'') => {
                    chars.next();
                    let mut key = String::new();
                    for c in chars.by_ref() {
                        if c == '\'' {
                            break;
                        }
                        key.push(c);
                    }
                    selector = Some(Selector::Key(key));
                }
                _ => {
                    let mut key = String::new();
                    while let Some(&c) = chars.peek() {
                        if c == '|' {
                            break;
                        }
                        key.push(c);
                        chars.next();
                    }
                    selector = Some(Selector::Key(key.trim().to_string()));
                }
            }
        }
        out.push(Variable {
            collection,
            selector,
            count,
            exclude,
        });
        if chars.peek() == Some(&'|') {
            chars.next();
        }
    }
    Ok(out)
}

/// A rule's operator: `!@name argument`; a text without `@` is `@rx` of it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OperatorText {
    pub name: String,
    pub arg: String,
    pub negated: bool,
}

pub fn operator(text: &str) -> OperatorText {
    let mut rest = text;
    let negated = rest.starts_with('!');
    if negated {
        rest = &rest[1..];
    }
    match rest.strip_prefix('@') {
        Some(op) => {
            let (name, arg) = match op.find(char::is_whitespace) {
                Some(i) => (&op[..i], op[i..].trim_start()),
                None => (op, ""),
            };
            OperatorText {
                name: name.to_string(),
                arg: arg.to_string(),
                negated,
            }
        }
        None => OperatorText {
            name: "rx".to_string(),
            arg: rest.to_string(),
            negated,
        },
    }
}

/// One action: `name` or `name:value` (a single-quoted value unquoted, `\'` a quote).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Action {
    pub name: String,
    pub value: Option<String>,
}

/// `id:1,phase:2,msg:'a, b',t:none` into its actions.
pub fn actions(text: &str) -> Result<Vec<Action>> {
    let mut out = Vec::new();
    let mut chars = text.chars().peekable();
    loop {
        while chars.peek().is_some_and(|c| c.is_whitespace() || *c == ',') {
            chars.next();
        }
        if chars.peek().is_none() {
            break;
        }
        let mut name = String::new();
        while let Some(&c) = chars.peek() {
            if c == ':' || c == ',' {
                break;
            }
            name.push(c);
            chars.next();
        }
        let name = name.trim().to_string();
        let mut value = None;
        if chars.peek() == Some(&':') {
            chars.next();
            while chars.peek().is_some_and(|c| *c == ' ') {
                chars.next();
            }
            let mut v = String::new();
            if chars.peek() == Some(&'\'') {
                chars.next();
                let mut closed = false;
                while let Some(c) = chars.next() {
                    match c {
                        '\\' if chars.peek() == Some(&'\'') => {
                            v.push('\'');
                            chars.next();
                        }
                        '\'' => {
                            closed = true;
                            break;
                        }
                        c => v.push(c),
                    }
                }
                if !closed {
                    bail!("action {name}: a quoted value is not closed");
                }
            } else {
                while let Some(&c) = chars.peek() {
                    if c == ',' {
                        break;
                    }
                    v.push(c);
                    chars.next();
                }
                v = v.trim_end().to_string();
            }
            value = Some(v);
        }
        if name.is_empty() {
            bail!("an action without a name in {text:?}");
        }
        out.push(Action {
            name: name.to_ascii_lowercase(),
            value,
        });
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn directives_join_lines_and_unquote() {
        let text = "# a comment\nSecRule ARGS \"@rx a\\\"b\" \\\n    \"id:1,\\\n    phase:2\"\n\nSecMarker END\n";
        let d = directives(text, "f.conf").unwrap();
        assert_eq!(d.len(), 2);
        assert_eq!(d[0].name, "SecRule");
        assert_eq!(d[0].args, vec!["ARGS", "@rx a\"b", "id:1,    phase:2"]);
        assert_eq!(d[0].at, "f.conf:2");
        assert_eq!(d[1].args, vec!["END"]);
    }

    #[test]
    fn variables_with_selectors() {
        let v = variables("REQUEST_COOKIES|!REQUEST_COOKIES:/__utm/|&TX:x|ARGS:'a b'|XML:/*|XML://@*").unwrap();
        assert_eq!(v.len(), 6);
        assert_eq!(v[1].selector, Some(Selector::Regex("__utm".into())));
        assert!(v[1].exclude);
        assert!(v[2].count);
        assert_eq!(v[2].selector, Some(Selector::Key("x".into())));
        assert_eq!(v[3].selector, Some(Selector::Key("a b".into())));
        assert_eq!(v[4].selector, Some(Selector::Key("/*".into())));
        assert_eq!(v[5].selector, Some(Selector::Key("//@*".into())));
        let v = variables("TX:/^922100_charset_/").unwrap();
        assert_eq!(v[0].selector, Some(Selector::Regex("^922100_charset_".into())));
    }

    #[test]
    fn operators_and_actions() {
        assert_eq!(
            operator("!@within %{tx.allowed_methods}"),
            OperatorText {
                name: "within".into(),
                arg: "%{tx.allowed_methods}".into(),
                negated: true
            }
        );
        assert_eq!(operator("^a$").name, "rx");
        assert_eq!(operator("@detectSQLi").arg, "");
        let a = actions("id:942100,phase:2,t:none,msg:'a, \\'b\\'',setvar:'tx.x=+%{tx.y}',chain").unwrap();
        assert_eq!(a.len(), 6);
        assert_eq!(a[3].value.as_deref(), Some("a, 'b'"));
        assert_eq!(a[4].value.as_deref(), Some("tx.x=+%{tx.y}"));
        assert_eq!(a[5].value, None);
    }
}
