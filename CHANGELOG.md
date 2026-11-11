# Changelog

## Unreleased

The request filter's lines under webfast's log policy (webfast's docs/logging.md, step 3): a
credential a rule matched in is no longer written.

Worth knowing when upgrading:

- Needs a webfast with the log policy (its `log_policy`, 0.1.7).
- A hit's `matched` (and an engine's `data`) is `REDACTED` where it came from a secret: a token's
  query parameter, `Authorization` or another secret header, a cookie, a password field, a query
  string, `Referer` or JSON body that carries one, a raw body. Before, only the JWT check's
  parameters were hidden. Rules, targets and the decision are as they were.
- `request.id` in every line, the access log's id for the same request.
- `log.privacy` (`{ personal: hash, payload: drop, secret: hash }`) over the global policy;
  `log.matched: 0` drops `matched` and `data` rather than writing them empty.
- For code that uses the crate: `Ngfw::hide_params` and `engine::Input::hidden` are gone (the
  policy holds the JWT's parameters); `engine::Hit` has `source` and `data_source`
  (`source::HitSource`); a rule engine's `plugin::EngineHit` has `chain` (the variables its
  chain matched in) in place of `param`.

### Changes

- `log.rs`: the lines as events of declared kinds (`EventKind`, fields with their classes),
  through `EventLog::event_with`; the test marker's line too.
- `source.rs`: a hit's source from its target (built-in rules) or SecLang variable (an engine's),
  a composite one classed where the match is found.
- The response phase's line has the request's id.
- tests/privacy.rs: requests with a token, `Authorization`, a cookie, a `Referer`, a form's and a
  JSON body's password, each matched by a rule; none is in a line.

## 0.1.3 — 2026-11-11

The OWASP Core Rule Set v4 inside the request filter: a new crate, `webfast-ngfw-crs`, reads the
CRS as it is released, in SecLang, and runs it with an interpreter of its own, plugged into the
filter as a rule engine — one decision against the filter's threshold, one log line, one ban list
and one challenge with the built-in rules. The CRS's own regression tests pass against it (5080
of 5231; the rest are of rules not loaded or of what httpd does before ModSecurity, each listed
with its reason). How it differs from ModSecurity, Coraza and CrowdSec, what is not loaded and
why the response rules are not there yet: [docs/ngfw-crs.md](docs/ngfw-crs.md#compared-with-modsecurity-coraza-and-crowdsec).

Worth knowing when upgrading from 0.1.2:

- Nothing changes in a webfast built without the engine (webfast's feature `ngfw-crs`, not a
  default): `rules.builtin` left out is still every built-in set.
- In a webfast built with it, the CRS is on in every filter file: `rules.builtin` left out means
  `cve` alone (the CRS numbers its rules as the built-in sets do), and so the `leakage` set is
  off and no response is looked at unless the file names it (`rules.builtin: [cve, leakage]`).
  `engines: { crs: false }` gives the filter as before.
- A new key, `engines` (an engine's configuration by name; `false` turns one off, also one this
  webfast was not built with); another name is an error.
- While an engine has rules for the body, a body of a type `body.types` does not list, or of
  none, is read for it as text (up to `body.max_inspect`), as ModSecurity reads every body.
- `log.passed` writes every request let through with hits, those that only log included (they
  were written only when something scored).
- For code that uses the crate: `engine::Hit` has the fields `engine`, `score` and `data`;
  `config::compose` takes the engines' sets; `config::RulesConfig::builtin` is an `Option`.

### Changes

- **`webfast-ngfw-crs`**: CRS 4.30.0 pinned and bundled (its request rules, 901 to 944 and 999,
  and the data files they read; Apache-2.0), byte for byte the release's. A SecLang reader and
  compiler (directives, variables with keys, regexes, counts and exclusions, operators, actions,
  chains, markers and `skipAfter`, `SecRuleRemove*`, `SecRuleUpdateTarget*`,
  `SecRuleUpdateActionById`), ModSecurity's variables of a request (arguments decoded, the
  URLENCODED, JSON, MULTIPART and XML body processors, files and part headers), the
  transformations on bytes (`%uXXXX` folded by a best-fit table), the operators (`@rx` on bytes,
  `@pm`/`@pmFromFile` as one automaton, the comparisons, `@within`, `@validate*`, `@ipMatch`,
  libinjection's `@detectSQLi` and `@detectXSS`), and the interpreter (`setvar` and captures per
  matched value, `ctl`, `MATCHED_VAR(S)`, the anomaly score at the blocking paranoia level as each
  hit's score). Configured in the filter's file, `engines.crs`: `paranoia`, `detection_paranoia`,
  `tx` (crs-setup's variables), `before` and `after` (the site's SecLang exclusions), `remove`.
  Each hit in the log with the CRS rule's id as `ruleId`, its set (`crs-942`), `msg`, the target
  and the expanded `logdata`.
- **What it costs**: on one core, a browser's GET some 200 µs at paranoia 1 and 350 µs at 4, a
  form POST 260 µs and 470 µs — a request's values worked once per chain of transformations, and
  each chain's regexes behind one automaton of their prefix literals.
- **The rule engine API** of the filter (`src/plugin.rs`): `Factory`, `Engine`, `Found`,
  `EngineHit`, `register()`; engines run in the `head` and `body` phases after the built-in rules;
  `plugin::evaluate()` runs one alone, for its tests.
- **go-ftw**: a third pass, `crs` (`scripts/ftw-run.sh`, `ci/ftw/ngfw-crs.yaml` and
  `ftw-crs.yaml`): the CRS release's regression tests, fetched by tag with the checksum checked,
  against a webfast built with the engine. CI runs it once webfast's `dev-ci` has the feature; the
  `all` and `cve` passes turn the CRS off. In process, `crs_regression` runs the same tests in
  `cargo test` (ignored; `CRS_TESTS` names them).
- docs/ngfw-crs.md (what runs, the configuration, the SecLang supported, the comparison with
  ModSecurity, Coraza and CrowdSec, how close it is, what it costs, updating the CRS); docs/ngfw.md
  (rule engines, `engines`, `rules.builtin`'s default); the README's crates as a table.

## 0.1.2 — 2026-11-09

The filter takes up the client's TLS fingerprint (JA4) and flags a browser's User-Agent over a
handshake no browser makes; a rule's tests live in the rule, with a JSON Schema for the rules
files and go-ftw tests written from both; comparison operators beside `gt`; a corpus of known
evasions; fewer per-request copies in the head check.

Worth knowing when upgrading from 0.1.1:

- The crates need webfast-core with `ConnInfo::ja4` (webfast's `dev-ci` from 9253abe, webfast
  0.1.5): a `ConnInfo` made by hand needs `ja4: None`.
- A new built-in rule, wf-920-600 (`log_only`): a log line for each request whose User-Agent
  claims a current browser over a TLS handshake none makes. It refuses nothing until a site arms
  it (`override: {wf-920-600: {mode: challenge}}`); `disable: [wf-920-600]` silences it.
- Log lines carry `request.ja4` when the connection has a fingerprint.
- Rules files may have `examples` (the format is otherwise unchanged); docs/ngfw-rules.schema.json
  describes the format for editors and tools.

### Changes

- **A rule's tests are in the rule**: `examples`, with `hit` (requests it must match) and `pass`
  (requests it must not), each a value put in the rule's targets (a query parameter both ways, a
  cookie, a header, the path, a form or JSON body) or a request written out (`method`, `uri`,
  `headers`, `body`, and `response` for what the backend answers), or a request's raw bytes
  (`raw`, go-ftw's `encoded_request`), with the `status` expected if it matters. The raw examples
  showed that over HTTP/1.1 wf-920-120 never sees its byte (the server's parser answers 400
  first) and wf-920-170 never sees a doubled framing (the parser settles it before the filter);
  wf-920-110 matches an HTTP/1.0 request without Host. The `cve` set's rules carry the
  cases of the Rust test they replace. `docs/ngfw-rules.md` lists them with each rule; a site's
  own rules may have them too. A test lists the built-in rules still without a `hit` example.
- **The rules files' JSON Schema**, `docs/ngfw-rules.schema.json`, made from the types the server
  reads them with (a test keeps it current, `UPDATE_RULES_DOC=1` writes it with the reference):
  every field, target, transformation and operator with what it means; the built-in files name it
  for the YAML language server.
- **The go-ftw tests** (`crates/webfast-ngfw/tests/ftw/`) are written from the rules' `examples`
  (`rules/<set>/<number>.yaml`, `expect_ids` / `no_expect_ids` with the rule's number) and from the
  corpus, now plain lists in `tests/corpus/*.txt` (one value per line, SecLists' format; sqli, xss,
  bypass and benign, each in a query both ways and in a cookie, 403 or 200; `rule_id`s 999002 to
  999005). `src/ftw.rs` writes them (`UPDATE_FTW_TESTS=1`) and a test fails when they are out of
  date; `scripts/ftw-convert.py` is gone. `tests/ftw.rs` runs them in process in `cargo test`, two
  passes as in CI, with a backend that answers `/reflect` as albedo does.
- `scripts/ftw-run.sh` and CI's `ftw` job: the go-ftw tests against webfast's binary built with
  the checkout's modules (`ci/ftw/compose.yaml`, go-ftw 2.6.2 and albedo 0.3.0 pinned), a pass
  with every built-in set (one test that wf-913-220 answers first is ignored, with its reason) and
  a pass with the cve set alone.
- The filter's comparison operators: besides `gt`, `ge`, `lt`, `le`, `eq` and `ne` on a numeric
  target; `count_ge` … `count_ne` besides `count_gt` (the number of the target's values) and
  `length_ge` … `length_ne` besides `length_gt` (each value's length). One matcher compares for
  all of them; the rules that use `gt`, `count_gt` and `length_gt` are unchanged.
- A `BYPASS` corpus beside SQLI and XSS: 61 known WAF evasions (comments and encodings inside
  keywords, spaces swapped or left out, entities and escapes, tags and attributes closed or split)
  that the built-in sets must keep refusing, in the Rust test and as go-ftw's `corpus/bypass.yaml`.
  A regression set: it holds what the sets catch.
- docs/ngfw.md: the feeds' example is Spamhaus DROP and blocklist.de, with how a feed is fetched,
  parsed and kept; EDROP is merged into DROP, and a list with the bogons in it (FireHOL level 1
  has the loopback and the private ranges) denies a health check and internal clients.
- The filter's head check: the query parameters the JWT check hides from the logs are a slice
  made once and shared with each request (they were copied per request, a string each, on a site
  with JWT `from_params`); the ban list is looked up once for the ban and the challenge mark.
- The browser challenge: a `js` or `cookie` answer that is not 64 characters is refused before the
  nonce's hash is computed.
- **The client's TLS fingerprint in the filter** (webfast-core's `ConnInfo::ja4`): the target
  `tls.ja4` (no value without a fingerprint), `request.ja4` in the log lines, and
  `anomaly.tls_ua_mismatch` with the rule wf-920-600: a User-Agent of a current Chrome, Edge,
  Firefox or Safari over a handshake none of them makes (not TLS 1.3, no SNI for a host that is a
  name, ALPN without `h2` first), with no list of fingerprints to keep current; a bot's, an old
  browser's or no User-Agent claims nothing. The rule is `log_only` until a site arms it
  (`override: {wf-920-600: {mode: challenge}}`: a TLS-inspecting proxy in front of a real browser is
  the honest mismatch, and passes the challenge). Examples may give the connection a `ja4`; they
  run through the engine, not go-ftw. Needs webfast-core with `ConnInfo::ja4`.

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
