//! The bundled CRS (crs/rules, OWASP CRS v4.30.0): the request rules in the order ModSecurity
//! loads them (by name), and the data files their `@pmFromFile` read. The test
//! `bundled_files_are_listed` checks both lists against the directory.

pub const RULES: &[(&str, &str)] = &[
    (
        "REQUEST-901-INITIALIZATION.conf",
        include_str!("../crs/rules/REQUEST-901-INITIALIZATION.conf"),
    ),
    (
        "REQUEST-905-COMMON-EXCEPTIONS.conf",
        include_str!("../crs/rules/REQUEST-905-COMMON-EXCEPTIONS.conf"),
    ),
    (
        "REQUEST-911-METHOD-ENFORCEMENT.conf",
        include_str!("../crs/rules/REQUEST-911-METHOD-ENFORCEMENT.conf"),
    ),
    (
        "REQUEST-913-SCANNER-DETECTION.conf",
        include_str!("../crs/rules/REQUEST-913-SCANNER-DETECTION.conf"),
    ),
    (
        "REQUEST-920-PROTOCOL-ENFORCEMENT.conf",
        include_str!("../crs/rules/REQUEST-920-PROTOCOL-ENFORCEMENT.conf"),
    ),
    (
        "REQUEST-921-PROTOCOL-ATTACK.conf",
        include_str!("../crs/rules/REQUEST-921-PROTOCOL-ATTACK.conf"),
    ),
    (
        "REQUEST-922-MULTIPART-ATTACK.conf",
        include_str!("../crs/rules/REQUEST-922-MULTIPART-ATTACK.conf"),
    ),
    (
        "REQUEST-930-APPLICATION-ATTACK-LFI.conf",
        include_str!("../crs/rules/REQUEST-930-APPLICATION-ATTACK-LFI.conf"),
    ),
    (
        "REQUEST-931-APPLICATION-ATTACK-RFI.conf",
        include_str!("../crs/rules/REQUEST-931-APPLICATION-ATTACK-RFI.conf"),
    ),
    (
        "REQUEST-932-APPLICATION-ATTACK-RCE.conf",
        include_str!("../crs/rules/REQUEST-932-APPLICATION-ATTACK-RCE.conf"),
    ),
    (
        "REQUEST-933-APPLICATION-ATTACK-PHP.conf",
        include_str!("../crs/rules/REQUEST-933-APPLICATION-ATTACK-PHP.conf"),
    ),
    (
        "REQUEST-934-APPLICATION-ATTACK-GENERIC.conf",
        include_str!("../crs/rules/REQUEST-934-APPLICATION-ATTACK-GENERIC.conf"),
    ),
    (
        "REQUEST-941-APPLICATION-ATTACK-XSS.conf",
        include_str!("../crs/rules/REQUEST-941-APPLICATION-ATTACK-XSS.conf"),
    ),
    (
        "REQUEST-942-APPLICATION-ATTACK-SQLI.conf",
        include_str!("../crs/rules/REQUEST-942-APPLICATION-ATTACK-SQLI.conf"),
    ),
    (
        "REQUEST-943-APPLICATION-ATTACK-SESSION-FIXATION.conf",
        include_str!("../crs/rules/REQUEST-943-APPLICATION-ATTACK-SESSION-FIXATION.conf"),
    ),
    (
        "REQUEST-944-APPLICATION-ATTACK-JAVA.conf",
        include_str!("../crs/rules/REQUEST-944-APPLICATION-ATTACK-JAVA.conf"),
    ),
    (
        "REQUEST-999-COMMON-EXCEPTIONS-AFTER.conf",
        include_str!("../crs/rules/REQUEST-999-COMMON-EXCEPTIONS-AFTER.conf"),
    ),
];

pub const DATA: &[(&str, &str)] = &[
    (
        "ai-critical-artifacts.data",
        include_str!("../crs/rules/ai-critical-artifacts.data"),
    ),
    ("java-classes.data", include_str!("../crs/rules/java-classes.data")),
    ("lfi-os-files.data", include_str!("../crs/rules/lfi-os-files.data")),
    (
        "php-function-names-933150.data",
        include_str!("../crs/rules/php-function-names-933150.data"),
    ),
    ("php-variables.data", include_str!("../crs/rules/php-variables.data")),
    (
        "restricted-files.data",
        include_str!("../crs/rules/restricted-files.data"),
    ),
    (
        "scanners-user-agents.data",
        include_str!("../crs/rules/scanners-user-agents.data"),
    ),
    ("ssrf-no-scheme.data", include_str!("../crs/rules/ssrf-no-scheme.data")),
    ("ssrf.data", include_str!("../crs/rules/ssrf.data")),
    ("unix-shell.data", include_str!("../crs/rules/unix-shell.data")),
    (
        "windows-powershell-commands.data",
        include_str!("../crs/rules/windows-powershell-commands.data"),
    ),
];
