# Changelog

## Unreleased

- The filter's rule tests as go-ftw YAML (`crates/webfast-ngfw/tests/ftw/`), generated from the
  Rust tests by `scripts/ftw-convert.py`: each `cve` rule's request and its neighbours, and the
  SQL injection, XSS and benign values of the detectors' corpus, each in a query (a space as
  `%20` and as `+`) and in a cookie. `--check` fails when the files differ from what the sources
  give. The neighbours and the benign values, about no one rule, have the `rule_id`s 999001 and
  999002 (section 999 has no rules): go-ftw takes 0 for a missing one.
- `scripts/ftw-run.sh` and CI's `ftw` job: the go-ftw tests against webfast's binary built with
  the checkout's modules (`ci/ftw/compose.yaml`, go-ftw 2.6.2 and albedo 0.3.0 pinned), a pass
  with every built-in set (three tests that wf-913-220 answers first are ignored, each with its
  reason) and a pass with the cve set alone.
- The filter's comparison operators: besides `gt`, `ge`, `lt`, `le`, `eq` and `ne` on a numeric
  target; `count_ge` … `count_ne` besides `count_gt` (the number of the target's values) and
  `length_ge` … `length_ne` besides `length_gt` (each value's length). One matcher compares for
  all of them; the rules that use `gt`, `count_gt` and `length_gt` are unchanged.

## 0.1.1 — 2026-11-08

The filter's second release: a fix for requests with a parameter or a cookie without `=`, which
made the head phase panic; libinjection's SQL injection and XSS detectors as operators and two
built-in rules on them, and rules for what they let through; a `cve` set; every rule's severity,
confidence, tags, CWE and CVE references and description, in the log and in a generated reference;
a number for each rule and test markers in the log, for go-ftw; a query's `+` read as a space; the response phase streaming a 200 instead of holding it; the staged
checks of webfast-core handing the head's state to the body by value; and fewer allocations on the
body path. The webfast binary takes the detectors only when its `ngfw` feature names
`webfast-ngfw/libinjection` (it pulls the crate without its default features).

- **Fixed: a query parameter or a cookie without `=` panicked the head phase.** `?debug`,
  `?a&b`, `Cookie: flag`: the empty value of such a pair was the literal `""`, not a slice of the
  request's text, and the range kept for it was the distance between two unrelated addresses. A
  debug build panicked on the subtraction, a release build on the slice (`start byte index … is
  out of bounds`), so with the filter on such a request lost its connection (0.1.0, and webfast
  0.1.3's binary). The empty value is now the slice at the pair's end. Tests: the pairs' ranges
  in debug and release, and `?debug` with `Cookie: flag` answered 200 through the server.
- **Every rule describes itself** (docs/ngfw.md "The rule format"): `confidence` (`high`,
  `medium`, `low`: how rare its false positives are, next to `severity`'s impact), `refs` (`cwe`,
  `capec`, `crs`, `cve`, `urls`, each checked at load: a malformed one does not load) and `doc`;
  a rules file has a `doc` of its own (the built-in sets' header comments became it). Every
  built-in rule has a `doc`, a `confidence` and a CWE, a CAPEC where one fits and its CRS v4 rule
  where one was checked against the CRS files (a test holds them to it). Each hit in the log now
  names the rule's `severity`, `tags`, `confidence` and `refs`, written without an allocation.
- **docs/ngfw-rules.md, the rules' reference, generated** from the rule files: per set its
  description and a table, per rule its phase, targets, chain, operator, prefilter, score,
  confidence, tags, links to CWE, CAPEC and NVD, and its `doc`; an index by CVE and by CWE. The
  test `the_rules_reference_is_current` fails when the files and the reference differ;
  `UPDATE_RULES_DOC=1` writes it again.
- **`rules.disable_tags`**: every rule with one of the tags is left out (`disable_tags:
  [wordpress]`), after `disable`; a tag no rule has is a warning.
- **A number for each rule, and go-ftw's markers** (docs/ngfw.md "The log"): a built-in rule's
  hit names its number as `ruleId`, made from the id and stored nowhere (`wf-942-190` is 942190,
  `wf-cve-2022-22965` is 20220022965; two rules for one number do not load), as go-ftw, the OWASP
  CRS test runner, reads rules by number from a JSON log line; the reference lists each rule's.
  `log.test_marker: X-CRS-Test` (off by default) writes a request's value of the header as a
  marker line, which go-ftw sends before and after each test; the marked request is checked as
  any other (a probe with the header is refused as without it, a test).
- **The `cve` set**: 21 rules, `wf-cve-<year>-<number>`, each blocking the narrow request
  signature of a known, exploited vulnerability of a web product — Shellshock, Apache Struts 2,
  PHPUnit eval-stdin, Drupalgeddon2, FortiOS, ThinkPHP, Citrix ADC, F5 BIG-IP TMUI and iControl
  REST, Exchange ProxyShell and ProxyNotShell, Apache HTTP Server 2.4.49 and 2.4.50, Spring
  Cloud Function, Spring4Shell, Confluence, Text4Shell, Ivanti Connect Secure, PAN-OS
  GlobalProtect, PHP-CGI, GeoServer, Next.js middleware — with the CVE, CWE and advisory in
  `refs` and the product in `tags` (`disable_tags: [f5]` for a site that is one). Tested on the
  marker of each exploit's request and on an ordinary request to the same product.
- **Rules for what libinjection lets through**: wf-942-180 (`procedure analyse(`, a stacked
  `; shutdown`), wf-942-190 (a quote closed by a comment at the end of a value: `admin' #`),
  wf-942-200 (a numeric tautology as the whole value: `1 or true`, `-1 or 2>1`), wf-941-160 (a
  tag split by another: `<scr<script>ipt>`), wf-941-170 (a script scheme broken up by control
  characters or spaces). wf-942-110 (`select … from`) now wants a column list between the two,
  so "please select one option from the list" is not a hit. The sets together refuse every one
  of the 115 payloads of the evaluation set as a query value (with `%20` and with `+`) and as a
  cookie, and hit none of its 104 benign values with any rule (a test). 98 built-in rules, 72
  before: a clean GET's connection and head phases take 3.69 µs where they took 3.36 (in
  process, release, one core, alternated with the previous commit) and still allocate nothing
  (tests/cost.rs counts).
- **libinjection's detectors: the operators `detect_sqli` and `detect_xss`** (docs/ngfw.md
  "Operators"; the cargo feature `libinjection`, on by default: the `barbacane-libinjection`
  crate `=0.1.3`, pure Rust, BSD-3-Clause). They run on each value after the rule's
  transformations, gated by the rule's `prefilter` as a regex is, once per (rule, text); a SQLi
  hit's `matched` starts with libinjection's fingerprint (`[s&sos] 1' or '1'='1`). Two built-in
  rules, critical (one hit refuses): **wf-942-170** on args, cookies, their names and JSON
  strings, gated by quotes, `=`, `(`, `;`, comments, `||`, `@@`, `union`, `select`; **wf-941-150**
  on those and the User-Agent and Referer, gated by `<`, script schemes, `expression(` and event
  handler names. On the crate's evaluation set they catch 60 of 65 SQL injections (61 ungated)
  and 48 of 50 XSS payloads (48 ungated), with no false positive on 98 benign values (one
  ungated), the SQLi gate opening on 46 of them and the XSS gate on 7. A clean request does not
  reach them: a clean GET still allocates 6 times and costs the same; a 1 KiB form and a 4 KiB
  upload allocate as before (37, 43). A query value with an apostrophe (`O'Brien`) is looked at
  by the SQLi detector: about 3 µs and 15 allocations more. Without the feature a rule on a
  detector does not load and the two built-in rules are left out. `BUILTIN_VERSION` 2026-11-08.
- **A query's `+` is a space** (docs/ngfw.md "Targets"): `args` and `args_names` read a query
  string as a form body is read, so a form sent by GET (`q=1+union+select`) is seen with its
  spaces by every rule; `%2B` is still a `+`. Before, `url_decode` left the `+`, and the sets'
  literals (`union select`) and libinjection missed such a value: the detectors caught 41 of 65
  and 12 of 50 written so, now 60 and 47, as with `%20`. The query is copied once per request,
  into the thread's buffer, only when it has a `+`; the `query` target stays as sent.
- **The response phase streams a 200 and holds only a 5xx** (docs/ngfw.md "Response phase"). A
  covered 200 goes out at once: its status and header rules run before any byte (a hit replaces
  the response by `leak_status`, as before), then each body frame is scanned as it passes — the
  automaton over the frame and over a window across each frame boundary (the longest literal
  less one, 512 bytes where a body rule is a regex), so a leak split between frames is found —
  until `body.max_inspect` bytes were. At a hit the frame that has it is not forwarded: the body
  ends with an error, HTTP/1.1 closes the connection, HTTP/2 resets the stream, HTTP/3 stops it,
  and the event is written as `leak` ("response cut"); `log_only` writes it and lets the body
  through. A 5xx is held up to `max_inspect` and replaced through `handle_errors` as before.
  `response.stream: false` holds and replaces a 200 too. The holding of an 8 KiB 200 is gone
  (in process on one core, the filter on less off, the best of three runs: a 1 KiB form POST to a
  proxied 8 KiB page 39.7 µs before and 37.0 µs after, a 4 KiB upload 32.9 µs and 27.9 µs);
  nothing is allocated per frame.
- **Built on webfast-core's staged checks by value** (webfast's CHANGELOG): the filter's
  `Check::Pending` is what its head found (the state, the evaluation so far, the body's kind),
  handed to the body phase in `Head::Body` instead of through the request's extensions (an `Arc`
  and a mutex, a map entry); the challenge's endpoint hands on `()`. `Check::body` and
  `Inspect::inspect` are `async fn`s, boxed once by the core for the whole set.
- Fewer allocations on the body path: the Content-Type's media type compared without a
  lowercased copy (four strings per proxied POST), the body prefix of one frame held without a
  queue, a form's names decoded straight into the pairs' buffer, a multipart body's delimiter
  made once and its parameter names compared without a lowercased copy. A 1 KiB form POST through
  the filter to a proxied 8 KiB page: 37 allocations (49 before), a 4 KiB multipart upload 43 (58).

## 0.1.0 — 2026-11-07

The first release: two modules of webfast as crates on the module API of `webfast-core`
(webfast 0.1.3, docs/modules.md there), compiled into the webfast binary through its
composition. They were written in the webfast repository and never released there.

- **`webfast-ngfw`, the NGFW request filter** (docs/ngfw.md), on when `WEB_NGFW_CONFIG` names
  its YAML file. Rules with anomaly scoring over the request's head, its body (forms, JSON,
  multipart uploads: names, declared types and the first bytes of each file) and proxied
  responses. Eleven built-in sets of seventy rules, numbered after the Core Rule Set sections:
  protocol anomalies, scanners and probes, path traversal, remote inclusion, command, PHP, SQL,
  template and script injection, file uploads (executable names, server configuration files,
  PHP tags or a shebang in an image, a declared type its bytes are not), and error messages
  leaking in proxied responses, replaced by `response.leak_status` through the site's
  `handle_errors`. A site's own files extend, replace, override or disable the rules;
  `log_only` or `challenge` for the module, a set or a rule; exclusions by path, host, set,
  rule or target. Access by the client's address (lists, files, feeds fetched on a schedule),
  country and ASN (MaxMind DB files), honeypot paths, and a ban list for repeat offenders
  (`then: challenge` marks instead of banning). One JSON line per event in its own log; a
  reload reads the file again and keeps the old rules when the new do not load.
- The filter's engine: one plan per (phase, target) with one Aho-Corasick automaton over every
  transformation chain's literals; values no chain changes are gathered and searched in one
  pass; the query and the cookies are parsed once per request, a form into one string with
  ranges, a multipart body by a parser of its own; a regex runs only after its literal, once per
  (rule, text). Measured in process on one core, release profile: a clean GET costs 2–3 µs over
  the server's ~12 µs and allocates nothing; a 1 KiB form some 12 µs and a 4 KiB upload some
  5 µs on the request side; a scanner or a probe is refused for 1.5–2 µs. The response phase
  holds a covered proxied response until `body.max_inspect` bytes of it are in (5–10 µs on an
  8 KiB page); `disable: [wf-950-*]` turns it off.
- **`webfast-challenge`, the browser challenge** (docs/challenge.md): a client proves it is a
  browser before a site answers — by accepting a cookie (a redirect), by running a script, by a
  proof-of-work (SHA-256 with `difficulty` leading zero bits, in a Web Worker) or by a CAPTCHA
  (Turnstile, hCaptcha, reCAPTCHA, verified with the provider). Asked by the `challenge`
  directive, for every request a site or a `handle` matches or only once a client is over a rate
  (`defer`: navigations counted, not assets), with `except` matchers; or by the request filter.
  The built-in page is under 6 KiB, without a brand, with a dark mode and a strict CSP; a site
  may give its own `page` with placeholders. The answer endpoint `POST /.well-known/c-wf` is
  served on every site.
- The challenge's cookie `__wf_c` is signed (keyed blake3, a key per day derived from the TLS
  ticket seed, so replicas given one seed accept each other's cookies) and bound to the client's
  /24 or /48 and its User-Agent; the server keeps no state per client. A cookie that verified is
  remembered in a bounded table (`WEB_CHALLENGE_PASSED`, a million by default): afterwards it is
  one lookup, ~160 ns; a verification ~350 ns. A request that carries a good cookie costs no
  more than one without the directive.
- maxminddb 0.27 (RUSTSEC advisory on 0.26's `Reader::open_mmap`, which the filter does not
  call; the lookup API changed with it).
- The repository: CI on `main` and `dev-ci` (formatting, clippy on the workspace and on each
  crate without its defaults, the tests on x86-64 and arm64 and on the minimum Rust, 1.89,
  cargo-deny); a tag `vX.Y.Z` makes a GitHub release with the version's section of this file.
