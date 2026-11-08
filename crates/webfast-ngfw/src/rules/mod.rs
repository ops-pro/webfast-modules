//! The built-in rule sets, one YAML file each, compiled into the binary; `BUILTIN_VERSION` is
//! written in every log line so a line says which rules it came from. Each file's `doc` and each
//! rule's `doc`, `confidence` and `refs` make docs/ngfw-rules.md (reference.rs, a test).

/// The date of the built-in sets.
pub const BUILTIN_VERSION: &str = "2026-11-08";

/// The sets in the order they are composed, with their text.
pub const SETS: &[(&str, &str)] = &[
    ("protocol", include_str!("protocol.yaml")),
    ("scanners", include_str!("scanners.yaml")),
    ("traversal", include_str!("traversal.yaml")),
    ("rfi", include_str!("rfi.yaml")),
    ("cmdi", include_str!("cmdi.yaml")),
    ("php", include_str!("php.yaml")),
    ("sqli", include_str!("sqli.yaml")),
    ("xss", include_str!("xss.yaml")),
    ("template", include_str!("template.yaml")),
    ("upload", include_str!("upload.yaml")),
    ("leakage", include_str!("leakage.yaml")),
    ("cve", include_str!("cve.yaml")),
];

/// The text of a built-in set.
pub fn set(name: &str) -> Option<&'static str> {
    SETS.iter().find(|(n, _)| *n == name).map(|(_, text)| *text)
}

#[cfg(all(test, feature = "libinjection"))]
mod reference;

#[cfg(test)]
mod tests {
    use super::super::rule::RulesFile;
    use super::SETS;

    /// Built-in rules for which no CWE fits: none now (a protocol or size rule takes CWE-20,
    /// CWE-400 or a narrower one). A rule added here says why.
    const WITHOUT_CWE: &[(&str, &str)] = &[];

    #[test]
    fn every_built_in_rule_has_a_doc_a_confidence_and_a_cwe() {
        let mut ids = Vec::new();
        for (name, text) in SETS {
            let file: RulesFile = webfast_core::yaml::from_str(text).unwrap();
            assert!(
                file.doc.as_deref().is_some_and(|d| d.trim().len() > 40),
                "set {name}: no doc"
            );
            for rule in &file.rules {
                let id = &rule.id;
                assert!(rule.doc.as_deref().is_some_and(|d| d.trim().len() > 40), "{id}: no doc");
                assert!(rule.confidence.is_some(), "{id}: no confidence");
                assert!(
                    !rule.refs.cwe.is_empty() || WITHOUT_CWE.iter().any(|(w, _)| w == id),
                    "{id}: no refs.cwe"
                );
                rule.refs.check().unwrap_or_else(|e| panic!("{id}: {e}"));
                assert!(rule.msg.is_some(), "{id}: no msg");
                assert!(rule.tags.iter().any(|t| t.starts_with("OWASP_")), "{id}: no OWASP tag");
                ids.push(id.clone());
            }
            if *name == "cve" {
                for rule in &file.rules {
                    let id = &rule.id;
                    let cve = id.strip_prefix("wf-").unwrap().to_uppercase();
                    let cve = cve.strip_suffix("-B").unwrap_or(&cve);
                    assert!(
                        rule.refs.cve.iter().any(|c| c == cve),
                        "{id}: refs.cve does not name {cve}"
                    );
                    assert!(!rule.refs.urls.is_empty(), "{id}: no refs.urls");
                    assert!(
                        rule.tags.contains(&"cve".to_string()) && rule.tags.len() >= 3,
                        "{id}: tags"
                    );
                }
            }
        }
        let mut sorted = ids.clone();
        sorted.sort();
        sorted.dedup();
        assert_eq!(sorted.len(), ids.len(), "an id twice");
    }
}
