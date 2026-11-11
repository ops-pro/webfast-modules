//! Macros: `%{tx.critical_anomaly_score}`, `%{MATCHED_VAR}`, `%{request_headers.host}` in an
//! action's value or an operator's argument, expanded per request.

use anyhow::{Result, bail};

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Piece {
    Text(Vec<u8>),
    /// A collection (upper case) and the key after its first dot (lower case), if any.
    Var(String, Option<String>),
}

/// What gives a macro's variable its value: the collection (upper case) and the key (lower case).
pub type Resolve<'a> = dyn FnMut(&str, Option<&str>) -> Option<Vec<u8>> + 'a;

#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct Macro {
    pub pieces: Vec<Piece>,
}

impl Macro {
    pub fn parse(text: &str) -> Result<Macro> {
        let mut pieces = Vec::new();
        let mut rest = text;
        while let Some(start) = rest.find("%{") {
            if start > 0 {
                pieces.push(Piece::Text(rest.as_bytes()[..start].to_vec()));
            }
            let after = &rest[start + 2..];
            let Some(end) = after.find('}') else {
                bail!("an unclosed macro in {text:?}");
            };
            let name = &after[..end];
            let (collection, key) = match name.split_once('.') {
                Some((c, k)) => (c, Some(k.to_ascii_lowercase())),
                None => (name, None),
            };
            pieces.push(Piece::Var(collection.trim().to_ascii_uppercase(), key));
            rest = &after[end + 1..];
        }
        if !rest.is_empty() {
            pieces.push(Piece::Text(rest.as_bytes().to_vec()));
        }
        Ok(Macro { pieces })
    }

    /// Whether it has a variable.
    pub fn is_dynamic(&self) -> bool {
        self.pieces.iter().any(|p| matches!(p, Piece::Var(..)))
    }

    /// The text of a macro without variables.
    pub fn fixed(&self) -> Option<String> {
        if self.is_dynamic() {
            return None;
        }
        let mut out = Vec::new();
        for p in &self.pieces {
            if let Piece::Text(t) = p {
                out.extend_from_slice(t);
            }
        }
        Some(String::from_utf8_lossy(&out).into_owned())
    }

    /// Expanded: each variable by `resolve` (nothing where it has no value).
    pub fn expand(&self, resolve: &mut Resolve<'_>) -> Vec<u8> {
        let mut out = Vec::new();
        for p in &self.pieces {
            match p {
                Piece::Text(t) => out.extend_from_slice(t),
                Piece::Var(c, k) => {
                    if let Some(v) = resolve(c, k.as_deref()) {
                        out.extend_from_slice(&v);
                    }
                }
            }
        }
        out
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_and_expand() {
        let m = Macro::parse("a %{tx.X_y} b %{MATCHED_VAR}").unwrap();
        assert_eq!(
            m.pieces,
            vec![
                Piece::Text(b"a ".to_vec()),
                Piece::Var("TX".into(), Some("x_y".into())),
                Piece::Text(b" b ".to_vec()),
                Piece::Var("MATCHED_VAR".into(), None),
            ]
        );
        let out = m.expand(&mut |c, k| Some(format!("{c}/{}", k.unwrap_or("-")).into_bytes()));
        assert_eq!(out, b"a TX/x_y b MATCHED_VAR/-");
        assert_eq!(Macro::parse("plain").unwrap().fixed().as_deref(), Some("plain"));
        assert!(Macro::parse("%{x").is_err());
    }
}
