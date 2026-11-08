# Changelog

## Unreleased

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
