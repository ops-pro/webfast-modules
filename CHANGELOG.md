# Changelog

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
