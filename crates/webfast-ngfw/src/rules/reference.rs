//! docs/ngfw-rules.md, the reference of the built-in rules, made from the sets' YAML as they are
//! compiled into the crate (`SETS`, composed as `builtin: all`): a table per set, a section per
//! rule, indexes by CVE and CWE. Not built into the server: the test `the_rules_reference_is_current`
//! compares the file with what this gives, and writes it with `UPDATE_RULES_DOC=1`.

use super::super::config::{RulesConfig, compose};
use super::super::rule::{Operator, Rule, RulesFile};
use std::collections::BTreeMap;
use std::fmt::Write as _;
use std::path::Path;

/// The command that writes the file again.
pub(crate) const REGENERATE: &str = "UPDATE_RULES_DOC=1 cargo test -p webfast-ngfw the_rules_reference_is_current";

/// The names of the weaknesses the built-in rules name, for the index.
const CWE_NAMES: &[(u32, &str)] = &[
    (15, "External Control of System or Configuration Setting"),
    (20, "Improper Input Validation"),
    (22, "Path Traversal"),
    (77, "Command Injection"),
    (78, "OS Command Injection"),
    (79, "Cross-site Scripting"),
    (89, "SQL Injection"),
    (94, "Code Injection"),
    (95, "Eval Injection"),
    (98, "PHP Remote File Inclusion"),
    (158, "Improper Neutralization of Null Byte"),
    (174, "Double Decoding of the Same Data"),
    (176, "Improper Handling of Unicode Encoding"),
    (200, "Exposure of Sensitive Information"),
    (209, "Error Message Containing Sensitive Information"),
    (285, "Improper Authorization"),
    (287, "Improper Authentication"),
    (306, "Missing Authentication for Critical Function"),
    (307, "Improper Restriction of Excessive Authentication Attempts"),
    (400, "Uncontrolled Resource Consumption"),
    (434, "Unrestricted Upload of File with Dangerous Type"),
    (444, "HTTP Request Smuggling"),
    (502, "Deserialization of Untrusted Data"),
    (527, "Exposure of Version-Control Repository"),
    (530, "Exposure of Backup File"),
    (538, "Sensitive Information in an Externally-Accessible File"),
    (548, "Exposure of Information Through Directory Listing"),
    (650, "Trusting HTTP Permission Methods on the Server Side"),
    (674, "Uncontrolled Recursion"),
    (770, "Allocation of Resources Without Limits or Throttling"),
    (917, "Expression Language Injection"),
    (918, "Server-Side Request Forgery"),
    (1336, "Template Injection"),
];

/// The number after the prefix (`CWE-89` → 89).
fn number(text: &str) -> u64 {
    text.rsplit('-').next().and_then(|n| n.parse().ok()).unwrap_or(0)
}

fn cwe_link(cwe: &str) -> String {
    format!("[{cwe}](https://cwe.mitre.org/data/definitions/{}.html)", number(cwe))
}

fn capec_link(capec: &str) -> String {
    format!(
        "[{capec}](https://capec.mitre.org/data/definitions/{}.html)",
        number(capec)
    )
}

fn cve_link(cve: &str) -> String {
    format!("[{cve}](https://nvd.nist.gov/vuln/detail/{cve})")
}

/// A literal as inline code: control bytes as `\xNN`, a backtick inside the code span's own
/// delimiters.
fn code(text: &str) -> String {
    let mut shown = String::new();
    for c in text.chars() {
        if (c as u32) < 0x20 || c == '\x7f' {
            let _ = write!(shown, "\\x{:02x}", c as u32);
        } else {
            shown.push(c);
        }
    }
    if shown.contains('`') {
        format!("`` {shown} ``")
    } else {
        format!("`{shown}`")
    }
}

fn codes<T: AsRef<str>>(items: &[T]) -> String {
    items.iter().map(|i| code(i.as_ref())).collect::<Vec<_>>().join(", ")
}

/// A table cell: `|` escaped, one line.
fn cell(text: &str) -> String {
    text.replace('|', "\\|").replace('\n', " ")
}

/// The operator in a line, or a line and an indented code block for a regex.
fn operator(rule: &Rule) -> String {
    match &rule.operator {
        Operator::ContainsAny(l) => format!("`contains_any`: {}", codes(l)),
        Operator::EqualsAny(l) => format!("`equals_any`: {}", codes(l)),
        Operator::StartsWithAny(l) => format!("`starts_with_any`: {}", codes(l)),
        Operator::EndsWithAny(l) => format!("`ends_with_any`: {}", codes(l)),
        Operator::Regex(pattern) => format!("`regex`:\n\n  ```text\n  {pattern}\n  ```\n"),
        Operator::LengthGt(n) => format!("`length_gt: {n}`"),
        Operator::CountGt(n) => format!("`count_gt: {n}`"),
        Operator::Gt(n) => format!("`gt: {n}`"),
        Operator::InSet(file) => format!("`in_set`: {}", code(file)),
        Operator::IpIn(l) => format!("`ip_in`: {}", codes(l)),
        Operator::CountryIn(l) => format!("`country_in`: {}", codes(l)),
        Operator::AsnIn(l) => format!(
            "`asn_in`: {}",
            l.iter().map(|n| format!("`AS{n}`")).collect::<Vec<_>>().join(", ")
        ),
        Operator::MagicNot(l) => format!("`magic_not`: {}", codes(l)),
        Operator::MagicIs(l) => format!("`magic_is`: {}", codes(l)),
        Operator::NotValidUtf8 => "`not_valid_utf8`".to_string(),
        Operator::NotValidJson => "`not_valid_json`".to_string(),
        Operator::Exists => "`exists`".to_string(),
        Operator::Missing => "`missing`".to_string(),
        Operator::DetectSqli => "`detect_sqli` (libinjection's SQL injection detector)".to_string(),
        Operator::DetectXss => "`detect_xss` (libinjection's XSS detector)".to_string(),
    }
}

fn score(rule: &Rule) -> u32 {
    rule.score.unwrap_or_else(|| rule.severity.score())
}

/// The text of docs/ngfw-rules.md.
pub(crate) fn reference() -> String {
    let (composed, _) = compose(&RulesConfig::default(), Path::new(".")).expect("the built-in sets load");
    let sets: Vec<(&str, String)> = super::SETS
        .iter()
        .map(|(name, text)| {
            let file: RulesFile = webfast_core::yaml::from_str(text).expect("a built-in set parses");
            (*name, file.doc.unwrap_or_default())
        })
        .collect();
    let in_set = |set: &str| -> Vec<&Rule> {
        composed
            .iter()
            .map(|s| &s.rule)
            .filter(|r| r.set.as_deref() == Some(set))
            .collect()
    };
    let mut out = String::new();
    out.push_str("# NGFW: the built-in rules\n\n");
    out.push_str("<!-- Generated from crates/webfast-ngfw/src/rules/*.yaml: do not edit by hand. -->\n\n");
    let _ = write!(
        out,
        "This file is generated from the built-in sets (`crates/webfast-ngfw/src/rules/*.yaml`, as they are \
         compiled into the crate) by the test `the_rules_reference_is_current`, which fails when the file is \
         out of date. After a change to a set, write it again:\n\n```sh\n{REGENERATE}\n```\n\n"
    );
    let _ = write!(
        out,
        "The rule format, the targets, transformations and operators, the composition of the sets with a \
         site's own rules and the exclusions are in [ngfw.md](ngfw.md). Built-in version `{}`: {} rules in {} \
         sets, as `builtin: all` loads them with the `libinjection` feature (without it, wf-942-170 and \
         wf-941-150 are left out).\n\n",
        super::BUILTIN_VERSION,
        composed.len(),
        sets.len()
    );
    out.push_str(
        "**Severity** is what a hit means, and gives the default score (critical 5, high 4, medium 3, low 2, \
         notice 1; a request is refused at `threshold`, 5 by default). **Confidence** is how rare false \
         positives are: `high`, an honest client practically never sends what the rule matches; `medium`, \
         some sites' ordinary traffic does (the rule's notes say which, and how to exclude it); `low`, the \
         rule is a signal to add up with others rather than a verdict.\n\n",
    );
    out.push_str("## Contents\n\n");
    for (name, _) in &sets {
        let _ = writeln!(out, "- [Set `{name}`](#set-{name}): {} rules", in_set(name).len());
    }
    out.push_str("- [Index by CVE](#index-by-cve)\n- [Index by CWE](#index-by-cwe)\n\n");

    for (name, doc) in &sets {
        let rules = in_set(name);
        let _ = write!(out, "## Set `{name}`\n\n{}\n\n", doc.trim());
        out.push_str("| Rule | Phase | Severity / score | Confidence | Action | Message |\n");
        out.push_str("| --- | --- | --- | --- | --- | --- |\n");
        for rule in &rules {
            let _ = writeln!(
                out,
                "| [{id}](#{id}) | {} | {} / {} | {} | {} | {} |",
                rule.phase.name(),
                rule.severity.name(),
                score(rule),
                rule.confidence.map_or("—", |c| c.name()),
                rule.action.name(),
                cell(rule.msg.as_deref().unwrap_or(&rule.id)),
                id = rule.id,
            );
        }
        out.push('\n');
        for rule in &rules {
            section(&mut out, rule);
        }
    }

    let mut by_cve: BTreeMap<(u64, u64, String), Vec<&str>> = BTreeMap::new();
    let mut by_cwe: BTreeMap<u64, (String, Vec<&str>)> = BTreeMap::new();
    for rule in composed.iter().map(|s| &s.rule) {
        for cve in &rule.refs.cve {
            let mut parts = cve.split('-').skip(1).map(|p| p.parse::<u64>().unwrap_or(0));
            let key = (parts.next().unwrap_or(0), parts.next().unwrap_or(0), cve.clone());
            by_cve.entry(key).or_default().push(&rule.id);
        }
        for cwe in &rule.refs.cwe {
            by_cwe
                .entry(number(cwe))
                .or_insert_with(|| (cwe.clone(), Vec::new()))
                .1
                .push(&rule.id);
        }
    }
    out.push_str("## Index by CVE\n\n| CVE | Rules |\n| --- | --- |\n");
    for ((_, _, cve), ids) in &by_cve {
        let _ = writeln!(out, "| {} | {} |", cve_link(cve), links(ids));
    }
    out.push_str("\n## Index by CWE\n\n| CWE | Weakness | Rules |\n| --- | --- | --- |\n");
    for (n, (cwe, ids)) in &by_cwe {
        let name = CWE_NAMES
            .iter()
            .find(|(k, _)| u64::from(*k) == *n)
            .map_or("", |(_, name)| name);
        let _ = writeln!(out, "| {} | {name} | {} |", cwe_link(cwe), links(ids));
    }
    out
}

fn links(ids: &[&str]) -> String {
    ids.iter()
        .map(|id| format!("[{id}](#{id})"))
        .collect::<Vec<_>>()
        .join(", ")
}

/// One rule's section.
fn section(out: &mut String, rule: &Rule) {
    let _ = write!(out, "### {}\n\n", rule.id);
    let _ = write!(out, "**{}**\n\n", rule.msg.as_deref().unwrap_or(&rule.id));
    let _ = writeln!(
        out,
        "- Set `{}`, phase `{}`",
        rule.set.as_deref().unwrap_or("site"),
        rule.phase.name()
    );
    if let Some(number) = crate::rule::number_of(&rule.id) {
        let _ = writeln!(
            out,
            "- Number `{number}` (the log's `ruleId`, go-ftw's `rule_id` and `expect_ids`)"
        );
    }
    let targets: Vec<String> = rule.targets.iter().map(ToString::to_string).collect();
    if !targets.is_empty() {
        let _ = writeln!(out, "- Targets: {}", codes(&targets));
    }
    let transforms: Vec<&str> = rule.transform.iter().map(|t| t.name()).collect();
    let _ = writeln!(
        out,
        "- Transformations: {}",
        if transforms.is_empty() {
            "none".to_string()
        } else {
            codes(&transforms)
        }
    );
    let _ = writeln!(out, "- Operator: {}", operator(rule).trim_end());
    if !rule.prefilter.is_empty() {
        let _ = writeln!(out, "- Prefilter: {}", codes(&rule.prefilter));
    }
    let mut decision = format!(
        "- Severity `{}`, score {}, confidence `{}`, action `{}`",
        rule.severity.name(),
        score(rule),
        rule.confidence.map_or("medium", |c| c.name()),
        rule.action.name()
    );
    if let Some(mode) = rule.mode {
        let _ = write!(decision, ", mode `{}`", mode.name());
    }
    let _ = writeln!(out, "{decision}");
    if !rule.header.is_empty() {
        let headers: Vec<String> = rule.header.iter().map(|(k, v)| format!("{k}: {v}")).collect();
        let _ = writeln!(out, "- Header: {}", codes(&headers));
    }
    if !rule.when.is_empty() {
        let _ = writeln!(
            out,
            "- When: {}",
            links(&rule.when.iter().map(String::as_str).collect::<Vec<_>>())
        );
    }
    if !rule.unless.is_empty() {
        let _ = writeln!(
            out,
            "- Unless: {}",
            links(&rule.unless.iter().map(String::as_str).collect::<Vec<_>>())
        );
    }
    if !rule.tags.is_empty() {
        let _ = writeln!(out, "- Tags: {}", codes(&rule.tags));
    }
    let refs = &rule.refs;
    let mut shown: Vec<String> = Vec::new();
    shown.extend(refs.cve.iter().map(|c| cve_link(c)));
    shown.extend(refs.cwe.iter().map(|c| cwe_link(c)));
    shown.extend(refs.capec.iter().map(|c| capec_link(c)));
    shown.extend(refs.crs.iter().map(|n| format!("CRS {n}")));
    shown.extend(refs.urls.iter().map(|u| format!("<{u}>")));
    if !shown.is_empty() {
        let _ = writeln!(out, "- References: {}", shown.join(", "));
    }
    out.push('\n');
    if let Some(doc) = &rule.doc {
        let _ = write!(out, "{}\n\n", doc.trim());
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_rules_reference_is_current() {
        let text = reference();
        let path = Path::new(env!("CARGO_MANIFEST_DIR")).join("../../docs/ngfw-rules.md");
        if std::env::var_os("UPDATE_RULES_DOC").is_some() {
            std::fs::write(&path, &text).unwrap();
            return;
        }
        let current = std::fs::read_to_string(&path).unwrap_or_default().replace("\r\n", "\n");
        assert!(current == text, "docs/ngfw-rules.md is out of date: run `{REGENERATE}`");
    }

    #[test]
    fn the_reference_renders_literals_and_links() {
        assert_eq!(code("a"), "`a`");
        assert_eq!(code("`"), "`` ` ``");
        assert_eq!(code("\x00\x7f"), "`\\x00\\x7f`");
        assert_eq!(cell("a|b"), "a\\|b");
        assert_eq!(
            cwe_link("CWE-89"),
            "[CWE-89](https://cwe.mitre.org/data/definitions/89.html)"
        );
        assert_eq!(
            capec_link("CAPEC-66"),
            "[CAPEC-66](https://capec.mitre.org/data/definitions/66.html)"
        );
        assert_eq!(
            cve_link("CVE-2021-44228"),
            "[CVE-2021-44228](https://nvd.nist.gov/vuln/detail/CVE-2021-44228)"
        );
    }
}
