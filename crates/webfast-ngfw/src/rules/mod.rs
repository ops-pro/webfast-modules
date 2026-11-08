//! The built-in rule sets, one YAML file each, compiled into the binary; `BUILTIN_VERSION` is
//! written in every log line so a line says which rules it came from.

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
];

/// The text of a built-in set.
pub fn set(name: &str) -> Option<&'static str> {
    SETS.iter().find(|(n, _)| *n == name).map(|(_, text)| *text)
}
