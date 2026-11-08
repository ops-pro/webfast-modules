# NGFW: the request filter

An optional module of webfast (the `webfast-ngfw` crate, [`crates/webfast-ngfw/src`](../crates/webfast-ngfw/src), the webfast binary's cargo feature `ngfw`, in its default build) that
refuses, marks or logs requests by rules: protocol anomalies, scanners, injection, path traversal,
PHP and upload attacks, data leaking in responses; and by where they come from: country, ASN,
address lists, a dynamic ban list. It is used only when `WEB_NGFW_CONFIG` names its file; without
the file nothing of it is on the request path, without the feature nothing of it is built.

It is a filter for the mass of noise and the known techniques, cheap enough for every request of a
loaded server (a clean GET costs two to three microseconds), with a small set of rules that comes
built in and is replaced, extended or overridden by the site's own. It is not a replacement for
the OWASP Core Rule Set under Coraza or ModSecurity, which trades two orders of magnitude of CPU
for coverage of obfuscated, targeted attacks.

This document is the specification the module is built to: the configuration, the rule format,
the built-in sets, the hook points, the module layout and the interfaces between its parts.

## How it takes part

The crate is a module in the sense of webfast's
[docs/modules.md](https://github.com/ops-pro/webfast/blob/main/docs/modules.md), written against
`webfast_core`'s public API alone. What it provides, and what the webfast binary's `compose.rs`
takes of it:

- `webfast_ngfw::MODULE`, the `Module` the binary registers: its environment (`WEB_NGFW_CONFIG`),
  its file loaded into `config.modules` as an `Ngfw` (`Module::load`), its lines for `webfast
  validate`, its background worker (`Module::start`), its reload.
- `Ngfw`, a request check (`module::Check`): the binary's composition puts
  `config.modules.get::<Ngfw>()` — `Option<Arc<Ngfw>>`, `None` when no file was named — in its
  slot among the checks, after the browser challenge's answer endpoint and before the core's JWT
  and API firewall checks. It sees the head and, when it must, the body; it refuses with a
  response that goes through the site's `handle_errors` routes (`ErrorPage`), or lets the request
  on, perhaps with headers added.
- `response::NgfwResponses`, an inspector of proxied responses (`module::Inspect`), for the
  `response` phase: it looks at a proxied response's status, headers and the start of its body,
  and may replace the response before the core's cache sees it or the client gets it (see
  "Response phase").
- Its events go to an event log of its own (`log.output`), through the core's
  `webfast_core::eventlog`, as the JWT and API firewall events do.
- Its background work (feeds, file and database reloads, the ban list's sweep) runs on a
  `background::Worker` thread of its own, nothing on the request threads.

The file is read at startup and by `webfast validate`; a reload (SIGHUP) reads it again and keeps
the old rules when the new file does not load, saying why in the log. Address lists and the
geo databases are read again when their files change (checked every `reload`).

## Configuration: `WEB_NGFW_CONFIG`

```yaml
mode: block                       # block | log_only | challenge: the default for every rule and set
log:
  output: /var/log/web/ngfw.log   # stdout | stderr | discard | a file, relative to this file
  matched: 200                    # bytes of the matched text written per hit; 0: none
  passed: false                   # also write requests that scored but stayed under the threshold
threshold: 5                      # the sum of scores from which a request is refused
response:
  status: 403                     # 403 | 404 | 444 (444: the connection is closed, nothing sent)
  leak_status: 500                # what a response the `response` phase refuses is replaced by
  stream: true                    # a 200 goes out at once, scanned as it streams and cut on a leak;
                                  # false: held until max_inspect and replaced, as a 5xx always is
  challenge: js                   # the browser challenge's level where one is asked: cookie | js | pow | captcha
  challenge_valid: 7d             # how long a passed client is not asked again
  challenge_bind: ip              # ip | none: the cookie bound to the client's /24 or /48
  captcha:                        # level captcha: the provider and its keys
    provider: turnstile           # turnstile | hcaptcha | recaptcha
    site_key: 0x4AAAAAAA...
    secret: env:TURNSTILE_SECRET  # the secret, or `env:NAME` for the variable that holds it

rules:
  builtin: all                    # all | none | [protocol, scanners, traversal, rfi, cmdi, php, sqli, xss, template, upload, leakage, cve]
  include: [rules/site.yaml]      # the site's own files, relative to this file, applied in order
  disable: [wf-942-130, wf-921-*] # ids, or masks with a trailing `*`
  disable_tags: [wordpress]       # every rule with one of these tags (a site that is not WordPress)
  override:                       # fields of a rule changed in place (any field but `id`)
    wf-913-100: { score: 2 }
    wf-920-300: { mode: log_only }
    wf-933-110: { action: block }
  exclusions:                     # where rules do not apply
    - paths: ['/admin/editor/*']  # path patterns, as the Caddyfile's `path` matcher
      rules: [wf-941-*]           # these rules (ids or masks) do not run here
    - paths: ['/api/search']
      targets: [args.q]           # this target is not looked at here, by any rule
    - hosts: ['legacy.example.com']
      sets: [php]                 # a whole set does not run here

body:
  max_inspect: 64KiB              # of the body is read for the `body` and `upload` phases
  types: [application/x-www-form-urlencoded, application/json, multipart/form-data, text/xml, application/xml]
  json_max_depth: 20              # deeper JSON is an anomaly (wf-920-520), not parsed further
  multipart_max_parts: 64
  upload_head: 4KiB               # of each uploaded file is looked at

geo:
  country_db: GeoLite2-Country.mmdb   # MaxMind GeoLite2 or DB-IP Lite (mmdb), relative to this file
  asn_db: GeoLite2-ASN.mmdb           # optional
  reload: 24h                         # files and databases are checked for a change this often
  header: X-Client-Country            # set on the request going on: the ISO code, or `--`

access:                           # decided first, on the client's address alone
  countries:
    deny: [KP]                    # or allow: [...], one of the two
    challenge: [CN, RU]           # asked the browser challenge, not refused (deny wins over challenge)
    except_paths: ['/.well-known/*', '/health']
  asn:
    deny: [AS12345]
    challenge: [AS64496]          # asked, not refused
  ip:
    allow: [10.0.0.0/8, 203.0.113.7]   # passes everything below, and the rules
    deny: [198.51.100.0/24]
    deny_files: [blocklist.txt]        # one address or CIDR per line, `#` and `;` comments
    feeds:
      - url: https://www.spamhaus.org/drop/drop.txt
        every: 12h
  ban:
    on_blocks: 10                 # this many refusals within `window`: banned
    window: 10m
    for: 1h
    then: ban                     # ban | challenge: what reaching on_blocks does (honeypots always ban)
    honeypots: ['/wp-login.php', '/.git/*', '/phpmyadmin/*']   # one request: banned

match:                            # where the module runs at all; none: everywhere
  hosts: ['*.example.com']
  except_paths: ['/internal/*']
```

Every key is optional but `threshold`, which defaults to 5, and `rules.builtin`, which defaults to
`all`. Sizes take `KiB`/`MiB`/`B`; durations `s`, `m`, `h`, `d`. Unknown keys are errors (serde
`deny_unknown_fields`).

**The browser challenge** (docs/challenge.md; this crate's cargo feature `challenge`, on by default: the `webfast-challenge` crate). Anything that asks for it
— `mode: challenge`, a rule's `action: challenge` or `mode: challenge`, `access.countries.challenge`,
`access.asn.challenge`, `access.ban.then: challenge`, any `response.challenge*` key — is a
configuration error in a webfast built without the module (`… this webfast was built without the
challenge module (cargo feature challenge)`), as a Caddyfile directive of a feature left out is.
`response.challenge`, `challenge_valid`, `challenge_bind` and `captcha` make the one `Asking` every
challenge of the module is asked with, at load; their defaults are the directive's (`js`, `7d`, `ip`).
`captcha.secret` is a literal or `env:NAME` (the module's file reads the environment nowhere else).
A client that passed (a good cookie of the level or above) is not asked: the
hit is written as `challenge_passed` and the request goes on through the rules left, so a passed
client is still refused by what refuses everyone.

**libinjection** (this crate's cargo feature `libinjection`, on by default: the
[`barbacane-libinjection`](https://crates.io/crates/barbacane-libinjection) crate, `=0.1.3`,
BSD-3-Clause, a pure Rust port of libinjection without `unsafe`, tested against the C library on
some 163,000 inputs). It brings the operators `detect_sqli` and `detect_xss` and the two built-in
rules on them, wf-942-170 and wf-941-150. A rule of the site's that uses either operator is a
configuration error in a webfast built without it (`… this webfast was built without libinjection
(cargo feature libinjection)`); the two built-in rules are left out of their sets then (after
`override` and `disable`, which may name them whatever the build), so the sets load. The webfast
binary pulls this crate with `default-features = false` and names `challenge` alone: libinjection
is in its build only when its `ngfw` feature also names `webfast-ngfw/libinjection`.

**Composition.** The rule list is built in this order: the built-in sets named by `builtin`; the
files of `include`, in order; then `override`, then `disable`, then `disable_tags` (a rule with
any of the tags is left out; a tag no rule has is a warning). A rule in an included file with the
`id` of an earlier rule **replaces** it, keeping its position; so one built-in rule is patched
without touching its set, and `builtin: none` with `include` gives a site its own rules only.
`validate` prints the resulting count per set and every replaced, overridden and disabled id.

**Where it runs.** `match` and the `exclusions` use the Caddyfile's matcher semantics:
`host_matches` for hosts, `path_matches` for paths (decoded, cleaned, case-insensitive). `access`
is not subject to `exclusions` but to `countries.except_paths` and `match`.

## Phases and order

Each phase can end the request. Later phases see what earlier ones added to the request (the
country header, say).

| Phase        | Looks at                                                              | Runs for                                  |
| ------------ | --------------------------------------------------------------------- | ----------------------------------------- |
| `connection` | the client address: `access.ip`, the ban list, `access.countries`, `access.asn` | every request                   |
| `head`       | method, version, path, query, headers, cookies, User-Agent, host      | every request                             |
| `body`       | the body up to `max_inspect`, parsed by type: form, JSON, XML as text | a body of a listed type                   |
| `upload`     | each part of a multipart body with a `filename`                       | multipart bodies                          |
| `response`   | a proxied response: status, headers, the body's start (a 200 as it streams) | proxied responses, rules in the set |

Decision per request: `access.ip.allow` lets the request through everything; a ban, `deny`, a
denied country or ASN, a honeypot refuses at once; a `ban.then: challenge` mark, a country or ASN
in a `challenge` list asks the browser challenge (in that order: ban, ip deny, country deny, asn
deny, honeypot, the challenge lists, then the rules); then the rules of each phase add their
scores, and a rule with `action: block` refuses at once. At the end of the `head` and
`body`/`upload` phases, a sum of scores at or over `threshold` refuses (so a body is read only when
the head did not already decide). In `log_only` (globally, for a set, or for a rule) a refusal is
written down and the request goes on as it came. In `challenge` mode (globally, for a set, or for a
rule) a refusal by rule is the browser challenge instead: a `block` action, or a sum over the
threshold made of challenge-mode scores alone (a block-mode rule's score in the sum keeps the
refusal a refusal); `ban` actions still ban. A challenge is not counted for `on_blocks`.

**Refusal.** `response.status` with an empty body and `ErrorPage`, so a site's `handle_errors`
can render it; `444` closes the connection (the response gets the `Close` marker the server
already has for refused heads). A refusal is counted for the ban list (`on_blocks`). The access
log line is the ordinary one for the status. A challenge is answered with the module's page (503)
or redirect (302) as it is, without `ErrorPage`: the server sends a check's refusal through
`handle_errors` only when it carries that marker (the core's src/server.rs `Refusal`), and the challenge page
is the answer.

## The rule format

Rules are YAML, a list under `rules:` in each file (the built-in sets are files of the same
format in `crates/webfast-ngfw/src/rules/`, compiled into the crate with `include_str!`).

```yaml
doc: |                            # the file's (a set's) description, for the reference
  PHP code and its wrappers in what a client sends.
rules:
  - id: wf-933-120
    set: php                      # the set it belongs to (exclusions by set, counts)
    phase: head                   # connection | head | body | upload | response
    msg: "PHP stream wrapper in a parameter"
    severity: critical            # critical 5, high 4, medium 3, low 2, notice 1: the default score
    confidence: high              # high | medium (default) | low: how rare its false positives are
    score: 5                      # explicit; 0 with `action: log` for a rule that only writes
    targets: [args, args_names, cookies, headers.referer, path]
    transform: [url_decode, lowercase, remove_nulls, compress_whitespace]
    operator: { contains_any: ['php://', 'phar://', 'data:', 'expect://', 'zip://', 'glob://'] }
    action: score                 # score (default) | block | log | ban | pass | header | challenge
    header: { X-Threat: php }     # with `action: header`: added to the request going on
    when: [wf-920-440]            # runs only if these rules matched earlier in this request
    unless: [wf-920-100]          # does not run if one of these matched
    mode: block                   # block | log_only | challenge, this rule's own
    tags: [OWASP_A03, injection, php]
    refs:                         # references, checked at load
      cwe: [CWE-98]               # CWE-<n>
      capec: [CAPEC-193]          # CAPEC-<n>
      crs: [933110]               # the OWASP CRS v4 rule it corresponds to (six digits)
      cve: []                     # CVE-<year>-<n>, for a rule against one vulnerability
      urls: []                    # https:// only
    doc: |                        # what it catches, why its score, its false positives, how to exclude it
      A PHP stream wrapper (`php://`, `phar://` …) in a value: …
```

Required: `id` (`wf-` + three digits + `-` + three digits for the built-in ones, `wf-cve-` + the
CVE's year and number for the `cve` set; a site's own may be any `[a-z0-9-]+`), `phase`,
`targets` (not for `connection`), `operator`. `msg` defaults to the id, `severity` to `medium`,
`confidence` to `medium`, `set` to `site` for a site's rules. A malformed reference (`CWE-x`, a
CRS id of five digits, an `http://` URL) does not load, naming the rule and the field.
`severity`, `confidence`, `tags` and `refs` are written with each hit in the log; `doc` and the
file's `doc` are for the reference (below) and for whoever reads the file, not for the server.

### Targets

| Target              | What it is                                                                          |
| ------------------- | ----------------------------------------------------------------------------------- |
| `method`            | the method's text                                                                   |
| `version`           | `1.0`, `1.1`, `2`, `3`                                                              |
| `path`              | the decoded, cleaned path (what `path` matchers see)                                |
| `path_raw`          | the path as sent, before any decoding                                               |
| `query`             | the query string as sent                                                            |
| `args`              | every parameter value of the query and, in the `body` phase, of a form body; a query's `+` is read as a space (form encoding, as a form body's), `%2B` stays a `+` |
| `args_names`        | every parameter name (a query's `+` a space, as for `args`)                         |
| `args.<name>`       | the values of one parameter                                                         |
| `args_count`        | the number of parameters (as text, for `gt`)                                        |
| `headers`           | every header value (the request's)                                                  |
| `headers_names`     | every header name                                                                   |
| `headers.<name>`    | the values of one header                                                            |
| `cookies`           | every cookie value; `cookies_names`, `cookies.<name>` as for args                   |
| `ua`                | User-Agent                                                                          |
| `host`              | the Host, port stripped, lowercased                                                 |
| `client_ip`         | the client's address (text; the `ip_in` operator takes it as an address)            |
| `country`, `asn`    | from the geo databases; `--` / `0` when unknown or no database                      |
| `body`              | the inspected body as text                                                          |
| `body.json.<ptr>`   | a JSON pointer into a JSON body (`/user/name`); `body.json` every string value        |
| `upload.filename`   | each part's file name; `upload.ext` its extension(s): every suffix after a dot, so `a.php.jpg` gives `php.jpg`, `jpg` and `php` |
| `upload.type`       | the part's declared Content-Type                                                    |
| `upload.head`       | the first `upload_head` bytes of the file                                           |
| `upload.count`      | the number of file parts                                                            |
| `tls.sni`           | the connection's SNI, `-` without TLS                                               |
| `response.status`   | (response phase) the status                                                         |
| `response.headers.<name>` | a response header                                                             |
| `response.body`     | the first `max_inspect` bytes of the response body                                  |

A target that is absent (no such header) matches nothing. Several targets: the rule matches when
any does; a rule scores once per request however many targets match (the first match is logged).

### Transformations

Applied in the order written, to a copy of the target in a thread-local buffer:
`url_decode` (percent-escapes; a second pass is applied when the result still has escapes, and
that fact is the target `anomaly.double_encoding` for wf-920-xxx), `html_decode` (named and
numeric entities), `lowercase`, `normalize_path` (`.` and `..` segments, repeated slashes,
backslashes to slashes), `remove_nulls`, `compress_whitespace`, `remove_comments` (`/* */`, `--`,
`#` to the line's end), `base64_decode` (only when the text is valid base64 of 8 bytes or more),
`js_decode` (`\xNN`, `\uNNNN`), `cmd_line` (removes quotes, backslashes, `^` and spaces around
`,` `;` `|` `&`, as the CRS `cmdLine` transformation), `utf8_to_unicode`.

### Operators

Exactly one per rule:

- `contains_any: [literals]` — any of the strings occurs. The literals of every rule on a target
  class go into one Aho-Corasick automaton for that class, so a clean request costs one pass.
- `equals_any`, `starts_with_any`, `ends_with_any: [literals]`.
- `regex: pattern` — the `regex` crate's syntax, compiled once; `prefilter: [literals]` on the
  rule gates it: the regex runs only when a literal occurs (strongly recommended; `validate`
  warns about a regex without one).
- `length_gt: n`, `count_gt: n` (number of values of the target), `gt: n` for numeric targets
  (`args_count`, `upload.count`, `response.status`).
- `in_set: file` — a file of one literal per line, relative to the rules file (a word list).
- `ip_in: [cidrs]`, `country_in: [codes]`, `asn_in: [numbers]`.
- `magic_not: [types]` — (upload) the declared type is one of these and the file's first bytes are
  not that type's signature; `magic_is: [types]` — the bytes are one of these whatever is
  declared. Types known: `png jpeg gif webp pdf zip gzip bmp ico svg php script` (`php`: `<?php` or
  `<?=` anywhere in the head; `script`: `#!` at the start).
- `not_valid_utf8`, `not_valid_json` (body phase).
- `exists` — the target has a value (a header is present); `missing` — it has none.
- `detect_sqli`, `detect_xss` — libinjection's SQL injection and XSS detectors on each value, after
  the rule's transformations (the `libinjection` feature). They are gated as a regex is: with
  `prefilter: [literals]` a detector runs only on a value one of them occurs in, once per (rule,
  text); without one, on every value (`validate` warns). A hit's `matched` is the value; for
  `detect_sqli` libinjection's fingerprint comes first, in brackets (`[s&sos] 1' or '1'='1`), all
  of it cut to `log.matched`. A call costs about 1 µs on a short value and 7 to 36 µs on a
  kilobyte (SQLi; XSS 0.1 to 0.4 µs short, 7 to 20 µs a kilobyte), so the prefilter is what keeps
  a clean request cheap.

### Actions

- `score` (default): adds `score` to the request's sum; the sum decides at the phase's end.
- `block`: refuses at once (through `mode`).
- `log`: writes the hit, adds nothing.
- `ban`: refuses and puts the client in the ban list for `access.ban.for`.
- `pass`: ends the checks for this request (an allow rule: e.g. a monitoring UA on `/health`).
- `header`: adds `header` to the request going on and adds the score; a site can let the
  application decide. The headers of every `header` action are removed from every request first,
  so a client cannot set them (as the JWT claim headers are).
- `challenge`: like `block`, but the refusal is the browser challenge at `response.challenge`'s
  level (docs/challenge.md), written as `challenge`; a client that passed it counts as `log`
  (written as `challenge_passed`) and the request goes on. In `log_only` it is a `log_only` line.
  Needs the `challenge` feature.

## Built-in sets

Numbered by the CRS sections they correspond to, so the numbers are familiar; the rules are this
module's own, few (tens, not hundreds) and cheap. Each set is a file `crates/webfast-ngfw/src/rules/<set>.yaml`.
Every rule has `msg`, `severity`, `confidence`, `tags` with the OWASP category, `refs` with its
CWE (and CAPEC, and the CRS rule where one was checked against CRS v4) and a `doc`; a test holds
every built-in rule to it. Every rule, its targets, chain, operator, score and description, is
in **[docs/ngfw-rules.md](ngfw-rules.md)**, generated from these files, with an index by CVE and
by CWE. The test `the_rules_reference_is_current` fails when the files and the reference differ;
`UPDATE_RULES_DOC=1 cargo test -p webfast-ngfw the_rules_reference_is_current` writes it again.

- **protocol (920)** — method not in `[GET, HEAD, POST, PUT, PATCH, DELETE, OPTIONS]` (medium);
  HTTP/1.0 without Host; a control or non-UTF-8 byte in the path or a header; `%00`; double
  encoding; `..` left after normalization; path over 2048, query over 8192, a cookie over 8192, a
  header over 8192 bytes, more than 128 parameters, more than 64 cookies; two Content-Length or
  Content-Length with Transfer-Encoding (wf-920-170, critical); a `Content-Type` that does not
  match the body's first bytes (JSON declared, not JSON); POST without Content-Type; no User-Agent
  (notice); no Accept (notice); a Range with more than 16 parts; JSON deeper than
  `json_max_depth`.
- **scanners (913)** — User-Agents of scanners: `sqlmap nikto nuclei masscan zgrab nmap dirbuster
  gobuster wpscan acunetix nessus openvas burp havij arachni w3af whatweb` (critical, `block`);
  probing paths: `/.env /.git/ /.svn/ /.hg/ /.DS_Store /wp-login.php /wp-admin/ /xmlrpc.php
  /phpmyadmin /pma/ /adminer /actuator/ /server-status /.aws/ /config.json /.htpasswd /.vscode/
  /vendor/phpunit /cgi-bin/ /boaform/ /HNAP1`, backups in the root (`*.bak *.sql *.zip *.tar.gz
  *.old *.orig *.swp` at depth 1) — critical, `block`; `validate` says this set should be turned off
  for sites that are what it probes for (a WordPress site turns `wf-913-2*` off).
- **traversal (930)** — `../` and `..\` and their encodings after `url_decode normalize_path`;
  `/etc/passwd /etc/shadow /proc/self /windows/win.ini c:\windows boot.ini` in args and path;
  `php://filter` and `.../` sequences.
- **rfi (931)** — `http://` `https://` `ftp://` in a parameter whose name suggests a target
  (`url uri src dest redirect next path file page include template callback`), with a host that
  is an address, `localhost`, `169.254.169.254`, `metadata.google.internal`, `[::1]`, a decimal
  or octal address; `file://`, `gopher://`, `dict://`.
- **cmdi (932)** — shell metacharacter followed by a command name: `; | & $( \` ` with `cat ls id
  whoami uname wget curl nc bash sh python perl php chmod rm sleep ping` (after `cmd_line`);
  `/bin/sh /bin/bash cmd.exe powershell`; `%0a` followed by a command.
- **php (933)** — wrappers `php:// phar:// expect:// zip:// glob:// data:`; `<?php` `<?=` in a
  parameter; `eval( system( passthru( shell_exec( exec( popen( proc_open( assert( preg_replace(`
  with `/e`, `create_function( include( require( file_get_contents( file_put_contents( unserialize(`
  as function calls; `allow_url_include auto_prepend_file auto_append_file disable_functions
  open_basedir` as names; serialized objects `O:\d+:"` and `a:\d+:{` in args/cookies/body;
  `.php` followed by a path separator in the path (`/a.php/b`, path info abuse).
- **sqli (942)** — `union select`, `union all select`, `select <columns> from` (a column list:
  names, `*`, calls, aliases, so prose with words between the two does not match), `insert into`, `drop
  table`, `' or '`, `" or "`, `or 1=1`, `and 1=1`, `sleep(`, `benchmark(`, `pg_sleep(`,
  `waitfor delay`, `information_schema`, `load_file(`, `into outfile`, `xp_cmdshell`,
  `/*!`, `--` with a quote before it, `;--`, `@@version`, `char(`, `concat(` with a quote, `0x` +
  hex of 8 digits with a quote; stacked `; drop|delete|update|insert`. Values and cookies, after
  `url_decode lowercase remove_comments compress_whitespace`. And **wf-942-170** (critical, so
  one hit refuses), libinjection's detector after CRS 942100, with the `libinjection` feature: on
  `args args_names cookies cookies_names body.json`, after `url_decode remove_nulls lowercase
  compress_whitespace` (CRS: `utf8toUnicode urlDecodeUni removeNulls`; the chain is wf-942-140's,
  so a value goes through no chain more; comments are kept, libinjection reads them), gated by
  `' " ` = ( ; -- /* || @@ union select`. Not on the User-Agent or the Referer, as CRS has it: a
  browser's User-Agent has `(` and `;`, and the detector would run on every request. And three
  rules for what libinjection lets through (critical): **wf-942-180** `procedure analyse(` and a
  stacked `; shutdown` that ends the statement; **wf-942-190** a quote closed by a comment at the
  end of a value (`admin' #`, `admin'--`, `admin'/*`); **wf-942-200** a numeric tautology as the
  whole value (`1 or true`, `-1 or 2>1`, `1 and 1=1`, `0 or not 0`), anchored at both ends.
- **xss (941)** — `<script`, `</script`, `javascript:`, `vbscript:`, `data:text/html`, `on` +
  event name + `=` (`onload= onerror= onmouseover= onfocus= onclick=` …), `<svg`, `<iframe`,
  `<object`, `<embed`, `<img src=x onerror`, `document.cookie`, `document.location`,
  `window.location`, `eval(`, `alert(`, `String.fromCharCode`, `expression(`, `<meta
  http-equiv`, after `url_decode html_decode js_decode lowercase compress_whitespace`. And
  **wf-941-150** (critical), libinjection's detector after CRS 941100: on the same targets and
  `ua`, `headers.referer`, after the set's chain (CRS: `utf8toUnicode urlDecodeUni
  htmlEntityDecode jsDecode cssDecode removeNulls`; ngfw has no `css_decode`), gated by `<`,
  `javascript: vbscript: data: expression(` and the event handler names of wf-941-120 (and
  `onstart`). A quote alone does not open the gate: an attribute broken out of needs one of these
  to run script. And for what libinjection lets through: **wf-941-160** a tag split by another
  (`<scr<script>ipt>`), **wf-941-170** a script scheme broken up by control characters or spaces
  (`jav&#x09;ascript:`, `j a v a s c r i p t :`), on a chain that keeps the whitespace.

  **What the gates trade**, measured on the crate's evaluation set (src/detect/corpus.rs: 65 SQL
  injections, 50 XSS payloads, 104 benign values; the test `gates_by_measurement` prints it):
  wf-942-170 catches 60 of the 65 (libinjection alone, ungated, 61: the gate loses `-1 or 2>1`,
  which has no quote, `=` or parenthesis), with no false positive (ungated one: `1 < 2 and 3 >
  2`), and opens on 49 of the 104 benign values (names with apostrophes, `=` and parentheses in
  text) instead of all of them; a gate of keywords as well (` or `, ` and `) catches no more and
  opens on most prose. wf-941-150 catches 48 of the 50, as ungated, with no false positive, and
  opens on 8 of the 104. libinjection itself misses `1 or true`, `1 procedure analyse()`, `admin'
  #` and `'; shutdown--`, and `<scr<script>ipt>` and a tab entity inside `javascript:`: the rules
  above take them. **The sets together** refuse every one of the 115 payloads as a query value
  (spaces as `%20` and as `+`, an HTML form's GET: `args` above) and as a cookie, and hit none of
  the 104 benign values with any rule (the test `the_whole_filter_refuses_the_corpus_and_hits_no_benign_value`,
  with a browser's User-Agent and Accept).
- **template (944)** — `{{`, `}}`, `${`, `#{`, `<%`, `%>` with a call inside (`(`), `__class__
  __globals__ __import__ __subclasses__ mro( lipsum cycler joiner`, `T(java.lang`, `freemarker`,
  `#set(`, `${jndi:` (critical, `block`).
- **upload (960)** — on each file part: an extension in `php php3 php4 php5 php7 php8 phtml pht
  phar phps inc htaccess htpasswd ini cgi pl py sh bash jsp jspx asp aspx ashx asmx cer soap exe
  dll bat cmd com scr vbs js hta` anywhere in the name (double extensions: `shot.php.jpg`,
  `a.php;.jpg`, `a.php%00.jpg`, `a.pHp`) — critical, `block`; a name with `/`, `\`, `..`, a
  null, a control character, or over 255 bytes; `.htaccess .user.ini web.config php.ini` as the
  name; the part's type `application/x-php application/x-httpd-php text/x-php
  application/x-sh`; `magic_not: [png, jpeg, gif, webp, pdf]` (declared an image or PDF, the bytes
  say otherwise); `magic_is: [php, script]` in a file declared as an image or document (a
  polyglot); more than `multipart_max_parts` parts. A site that takes only images writes its own
  `upload.ext` rule with `action: block` on everything not in its list.
- **leakage (950, response phase)** — in the first bytes of a 200 or 5xx response:
  `Warning: ... on line`, `Fatal error:`, `Parse error:`, `Stack trace:`, `Uncaught Exception`,
  `at java.`, `Traceback (most recent call last)`, `ORA-\d{5}`, `SQLSTATE[`, `You have an error in
  your SQL syntax`, `Microsoft OLE DB`, `ODBC Driver`, `<title>Index of /`, `Directory listing
  for`; `X-Powered-By` is not a leak (sites set it on purpose), but `wf-950-900` (`log`) notes
  `Server: Apache/2.4.x` with a full version. A match in a 5xx (or in a 200's headers, or in a 200
  with `response.stream: false`) replaces the response by `leak_status` through `handle_errors`,
  body dropped; a match in a streamed 200's body cuts the response before the frame that has it
  (see "Response phase"). Either is written to the log as `leak` with the matched text.
- **cve** — known, exploited vulnerabilities of web products, each by the narrow signature of its
  exploit request (a path, a header, a parameter name), not by a technique; one rule per CVE,
  named after it (`wf-cve-2022-22965`), critical, `block`, confidence high, with the CVE, CWE and
  advisory in `refs` and the product in `tags`: Shellshock (CVE-2014-6271), Apache Struts 2
  (2017-5638), PHPUnit eval-stdin (2017-9841), Drupalgeddon2 (2018-7600), FortiOS fgt_lang
  (2018-13379), ThinkPHP (2018-20062), Citrix ADC (2019-19781), F5 BIG-IP TMUI (2020-5902) and
  iControl REST (2022-1388), Exchange ProxyShell and ProxyNotShell (2021-34473, 2022-41040),
  Apache HTTP Server 2.4.49 and 2.4.50 (2021-41773, 2021-42013), Spring Cloud Function
  (2022-22963), Spring4Shell (2022-22965), Confluence (2022-26134), Text4Shell (2022-42889),
  Ivanti Connect Secure (2023-46805, 2024-21887), PAN-OS GlobalProtect (2024-3400), PHP-CGI
  (2024-4577), GeoServer (2024-36401), Next.js middleware (2025-29927). Log4Shell (2021-44228)
  is in `template`. A site that is one of these products and reaches its own administration
  through webfast (F5's `/mgmt/tm/util/bash` is an administrators' endpoint) turns the product
  off by its tag: `disable_tags: [f5]`.

Each rule has a stable id; a site that needs a rule the sets do not have writes it in its own
file; a rule that a new vulnerability calls for is added to the set that fits and reaches sites
with the binary. `BUILTIN_VERSION` (a date, in `crates/webfast-ngfw/src/rules/mod.rs`) is written in every log
line.

## The log

One JSON line per event through the core's `webfast_core::eventlog`, extended with the module's fields:

```json
{"level":"info","ts":1760788800.123,"logger":"ngfw","msg":"request refused","builtin":"2026-11-08",
 "request":{"client_ip":"203.0.113.7","country":"NL","asn":1136,"method":"POST","host":"www.example.com",
            "uri":"/upload","user_agent":"Mozilla/5.0 …"},
 "decision":"block","status":403,"score":9,"threshold":5,"phase":"upload",
 "hits":[{"id":"wf-960-110","set":"upload","score":5,"severity":"critical","confidence":"high",
          "tags":["OWASP_A04","upload","webshell"],
          "refs":{"cwe":["CWE-434"],"capec":["CAPEC-650"],"crs":[933110]},
          "target":"upload.ext","matched":"php"},
         {"id":"wf-960-140","set":"upload","score":4,"severity":"high","confidence":"medium",
          "tags":["OWASP_A04","upload","webshell","polyglot"],
          "refs":{"cwe":["CWE-434"],"capec":["CAPEC-650"]},
          "target":"upload.head","matched":"<?php"}]}
```

Each hit names the rule's `severity`, `tags`, and its `confidence` and `refs` (only the lists
that are not empty) when it has them, so a SIEM selects by CWE, CVE or OWASP category without a
table of rule ids.

## Performance

- Compilation at load: for each phase and target class, one `aho_corasick::AhoCorasick` of every
  `contains_any` literal (and every `prefilter`) of the rules on that class, built with
  `MatchKind::LeftmostFirst` and ASCII case-insensitivity where the rule lowercases, mapping each
  pattern back to its rules; regexes compiled once; sets of literals (`equals_any`,
  `starts_with_any`, `ends_with_any`) as hash sets or sorted arrays.
- A request: the query and the cookies are parsed once per request into thread-local buffers;
  for each (phase, target) one plan holds every rule's transformation chain and one automaton
  over every chain's literals. A value no chain would change (classified by its byte classes)
  is appended to one text and the automaton runs once over all of them; a value some chain
  changes goes through each chain once, the distinct results searched. Only the rules whose
  literal was found are checked further (regex, `when`/`unless`, exclusions), once per (rule,
  text). Measured by the bench, release, one core: a clean GET costs 2–3 µs over the server's
  ~12 µs, with no allocation; a 1 KiB form 12 µs and a 4 KiB multipart upload 5 µs on the
  request side (the form's pairs are its `args`, the upload's parts its `upload.*`; neither is a
  `body` text).
- The body is read only up to `max_inspect` and only for the listed types; the bytes read go on
  to the handler as a `Body::full` followed by the rest of the stream, so nothing is read twice.
  Multipart is parsed from the inspected prefix in one pass of the module's own (a truncated last
  part is fine: only names, types and heads are looked at).
- The response phase does not hold a covered 200 (text, JSON or XHTML): its head goes out at
  once and its frames as they come, each scanned in passing (the automaton over the frame and
  over a window across each frame boundary; nothing allocated per frame). A 5xx, and a 200 with
  `response.stream: false`, is held until `max_inspect` bytes of its body have arrived before the
  first byte goes to the client (5–10 µs of waiting and a copy for an 8 KiB page, plus the scan).
  Measured in process on one core (the bench's POSTs to a proxied 8 KiB page, the filter on less
  off, best of three): streaming took 2.7 µs off a 1 KiB form and 5.0 µs off a 4 KiB upload. A
  site that wants neither disables the set (`disable: [wf-950-*]`) or lowers `body.max_inspect`.
- Geo lookups: `maxminddb` over a memory-mapped or read file, ~100 ns, two per request when both
  databases are configured.
- Address lists: two prefix tries (v4, v6) under `ArcSwap`, replaced whole on reload.
- The ban list: 64 shards of `Mutex<FxHashMap<IpAddr, Entry>>`, padded; `banned` is one lock on
  one shard; the sweep runs on the worker.
- Nothing is allocated on the request path for a clean request but the body prefix when a body is
  inspected.
- libinjection's detectors run only on what their rules' prefilters let through, and their
  chains are the sets' own (wf-942-140's, wf-941-100's), so a value goes through no chain more.
  Measured by the bench (release, one core, the filter on less off, the best of three; the
  server's own allocations are the 6 of a GET): a clean GET, a 1 KiB form POST and a 4 KiB upload
  allocate as without the rules (6, 37, 43) and cost the same within the bench's noise. A GET
  with `q=O%27Brien+family` reaches the SQLi detector: 21 allocations (6 without the rule) and
  about 3 µs more. The detector allocates as it reads: barbacane-libinjection 0.1.3 upper-cases
  each word into a new `String` to look it up among the keywords, and formats a `String` for each
  pair of words it tries to fold and for the fingerprint's lookup.
- The `cve` set and the rules for libinjection's gaps (98 built-in rules, 72 before) add targets
  a clean GET has (every header for Shellshock and Text4Shell, the raw path, the parameter
  names): the connection and head phases of a clean GET under `builtin: all`, timed in process
  in release on one core (tests/cost.rs, the best of five, five rounds alternating with the
  previous commit), take 3.69 µs where they took 3.36, and still allocate nothing (the same test
  counts the allocations).

## Module layout and interfaces

```
crates/webfast-ngfw/src/
  lib.rs        MODULE (what the binary's composition registers), Ngfw (the loaded module: config, compiled rules, geo, lists, bans, log), load(),
                the Module and Check impls, counts() for validate, start() for the worker
  config.rs     the YAML types (serde), sizes and durations, composition of the rule list
  rule.rs       Rule, Target, Transform, Operator, Action as parsed and as compiled
  compile.rs    the per-phase/per-target automata, regex sets, index from pattern to rules
  detect.rs     libinjection's detectors (the `libinjection` feature) for `detect_sqli` and `detect_xss`;
                detect/corpus.rs, the evaluation set of the detectors and their gates (tests)
  engine.rs     a request's evaluation: targets decoded into buffers, the phases, the decision
  body.rs       reading the body prefix, form/JSON parsing, handing the body on
  response.rs   the response phase: the inspect step, leak rules, the replacement response
  geo.rs        Geo: country and ASN from mmdb files, reloaded on change
  iplist.rs     IpSet (prefix tries), IpLists (allow/deny/files/feeds under ArcSwap)
  ban.rs        Bans: counts per address in a window, bans for a duration, sweep
  multipart.rs  the parts of a multipart prefix: name, filename, type, head bytes
  log.rs        the event lines (through webfast_core::eventlog)
  rules/        the built-in sets, one YAML each, plus mod.rs with BUILTIN_VERSION and include_str!
```

The interfaces between the parts, fixed here so they can be written apart:

```rust
// geo.rs
#[derive(serde::Deserialize, Debug, Clone, Default)]
#[serde(deny_unknown_fields)]
pub struct GeoConfig { pub country_db: Option<String>, pub asn_db: Option<String>,
                       #[serde(default = "day")] pub reload: String, pub header: Option<String> }
pub struct Geo { /* ArcSwap<Databases>, paths, mtimes */ }
impl Geo {
    pub fn open(config: &GeoConfig, base: &Path) -> anyhow::Result<Geo>;
    pub fn country(&self, ip: IpAddr) -> Option<[u8; 2]>;      // upper-case ISO 3166-1 alpha-2
    pub fn asn(&self, ip: IpAddr) -> Option<u32>;
    pub fn reload_if_changed(&self) -> anyhow::Result<bool>;   // by the files' mtime
    pub fn has_country(&self) -> bool; pub fn has_asn(&self) -> bool;
}

// iplist.rs
pub struct IpSet { /* v4 and v6 prefix tries */ }
impl IpSet {
    pub fn new() -> IpSet; pub fn insert(&mut self, net: ipnet::IpNet); pub fn contains(&self, ip: IpAddr) -> bool;
    pub fn len(&self) -> usize; pub fn is_empty(&self) -> bool;
    /// One address or CIDR per line; `#` and `;` start a comment; blank lines skipped.
    pub fn parse(text: &str) -> anyhow::Result<IpSet>;
}
#[derive(serde::Deserialize, Debug, Clone, Default)]
#[serde(deny_unknown_fields)]
pub struct IpConfig { #[serde(default)] pub allow: Vec<String>, #[serde(default)] pub deny: Vec<String>,
                      #[serde(default)] pub deny_files: Vec<String>, #[serde(default)] pub feeds: Vec<FeedConfig> }
#[derive(serde::Deserialize, Debug, Clone)]
#[serde(deny_unknown_fields)]
pub struct FeedConfig { pub url: String, #[serde(default = "twelve_hours")] pub every: String }
pub struct IpLists { /* allow: IpSet, deny: ArcSwap<IpSet> (static + files + feeds), file mtimes, feed state */ }
impl IpLists {
    pub fn new(config: &IpConfig, base: &Path) -> anyhow::Result<IpLists>;   // reads the files once
    pub fn allowed(&self, ip: IpAddr) -> bool;
    pub fn denied(&self, ip: IpAddr) -> bool;
    pub fn refresh_files(&self) -> anyhow::Result<bool>;                      // by mtime
    /// Fetches the feeds that are due (webfast_core::fetch); how many changed.
    pub async fn fetch_feeds(&self, client: &crate::fetch::Client) -> anyhow::Result<usize>;
    pub fn counts(&self) -> (usize, usize);                                    // allow, deny entries
}

// ban.rs
#[derive(serde::Deserialize, Debug, Clone, Default)]
#[serde(deny_unknown_fields)]
pub struct BanConfig { #[serde(default)] pub on_blocks: u32, #[serde(default = "ten_minutes")] pub window: String,
                       #[serde(default = "one_hour")] pub r#for: String, #[serde(default)] pub honeypots: Vec<String>,
                       #[serde(default)] pub then: Then }
pub enum Then { Ban, Challenge }     // `then`: what reaching `on_blocks` does
pub struct Bans { /* 64 padded shards; window, duration, then */ }
impl Bans {
    pub fn new(config: &BanConfig) -> anyhow::Result<Bans>;
    pub fn banned(&self, ip: IpAddr, now: Instant) -> bool;       // false for an address marked for the challenge
    pub fn challenged(&self, ip: IpAddr, now: Instant) -> bool;   // marked by `then: challenge`, for `for`
    /// A refusal happened: counted in the window; `Some(then)` when the count reached `on_blocks`
    /// and the address is now banned or marked for the challenge.
    pub fn refused(&self, ip: IpAddr, now: Instant) -> Option<Then>;
    pub fn ban(&self, ip: IpAddr, now: Instant);                  // a ban whatever `then` says
    pub fn sweep(&self, now: Instant);           // drops expired entries
    pub fn len(&self) -> usize;
}

// multipart.rs
pub struct Part { pub name: String, pub filename: Option<String>, pub content_type: Option<String>,
                  pub head: bytes::Bytes, pub size: usize, pub complete: bool }
/// The boundary of a `multipart/form-data` Content-Type.
pub fn boundary(content_type: &http::HeaderValue) -> Option<String>;
/// The parts of `prefix` (the inspected start of a body, perhaps cut mid-part), at most
/// `max_parts`, each with its first `head` bytes.
pub async fn parts(boundary: &str, prefix: bytes::Bytes, max_parts: usize, head: usize) -> anyhow::Result<Vec<Part>>;
```

Durations in the configs are strings (`10m`, `1h`, `24h`, `30s`, `2d`) parsed by one function in
`config.rs` (`pub fn duration(text: &str) -> anyhow::Result<Duration>`); sizes (`64KiB`, `4KiB`,
`1MiB`, `512B`, a bare number of bytes) by `pub fn size(text: &str) -> anyhow::Result<usize>`.

### Response phase

`NgfwResponses` implements the core's `module::Inspect` (`covers` is a plain call on the response's
status and headers; `inspect` runs only for a response it covers, in the one future the core boxes
for the set's inspectors):

```rust
/// The response as the upstream gave it: may read the start of the body (giving back a body
/// that yields the same bytes), wrap the body, or replace the response.
fn inspect<'a>(&'a self, ctx: &'a mut Ctx, parts: &'a mut http::response::Parts, body: Body)
    -> impl Future<Output = Result<Body, Response<Body>>> + Send + 'a;
```

The core calls the composed inspectors in order before the proxy cache keeps the response;
`Err(response)` is sent in the response's place (marked `ErrorPage`, so `handle_errors` applies).
It is zero-sized and finds the loaded module among the composed checks by its type
(`ctx.hook::<Ngfw>()`). It looks at a response whose status and Content-Type the leakage rules
cover (200 or 5xx; `text/*`, `application/json`, `application/xhtml+xml`); responses that no rule
covers (an image, a 304) are not read. Of the body, at most `body.max_inspect` bytes are scanned.

- **5xx** (and a 200 with `response.stream: false`): held. The body is read up to `max_inspect`
  bytes, the `response` rules run over the status, the headers and that text, and the response
  goes on as the same frames followed by the rest — or, on a hit, is replaced by `leak_status`
  through the site's `handle_errors` (its headers dropped too). Error pages are short, and are
  where leaks are.
- **200** (`response.stream: true`, the default): streamed. The status and header rules run first,
  before any byte goes out; a hit there replaces the whole response as above. The body is then
  wrapped in a scanning body: every data frame is scanned as it passes, until `max_inspect` bytes
  were, and frames after that pass untouched.
  - The `response.body` rules' automaton runs over the frame, and over a window across the
    boundary before it: the last `carry` bytes of the body before the boundary and as many of the
    frame after it. `carry` is the longest `response.body` literal less one, and 512 bytes
    (`WINDOW`) when a body rule is a regex or another per-value test (the built-in wf-950-110 and
    -140 are), at most 1024. So a literal cut between frames is found, and a regex whose
    prefilter literal was found is tested on the whole frame and on up to 512 bytes either side
    of each boundary: a match of up to 512 bytes is found however the frames are cut (`^` and `$`
    then mean the edges of that window). The window lives in a buffer inline in the scanning
    body; nothing is allocated per frame (a frame that is not UTF-8 is made text in one string
    reused for the response).
  - On a hit (`block`, `ban`, `challenge`) the frame that has it is not forwarded: the body ends
    with an error and the server gives up on the response — HTTP/1.1 closes the connection (a
    head and frames not yet flushed are not sent either), HTTP/2 resets the stream (`RST_STREAM`
    `INTERNAL_ERROR`; the connection's other streams go on), HTTP/3 stops the stream
    (`H3_REQUEST_CANCELLED`) — so the client never has a whole response, and the proxy cache does
    not keep it. The event is written as `leak` ("response cut", `status` the response's own),
    with the matched text and the header rules' hits.
  - `log_only` (the module's, the set's or the rule's mode) writes the hits once, when the scan
    ends, and never cuts.

## Tests

- Unit tests in each file: parsing and composition (replace, override, disable, masks),
  transformations, every operator (the detectors: a hit, a miss, a value the prefilter keeps out
  never reaching libinjection, and without the feature a load error; the built-in wf-942-170 and
  wf-941-150 over the evaluation set, no hit on its benign values), the automaton mapping
  patterns back to rules, the decision with thresholds and modes, exclusions by path/host/target/set/rule, `when`/`unless`, prefix
  tries with v4 and v6 and lists with comments, bans counting within the window and expiring,
  multipart parts from a cut prefix, geo with a small mmdb made in the test (the `maxminddb`
  crate's test data, or a writer-made file), the response inspection chaining the body. The
  metadata: malformed `refs` refused, `disable_tags`, every built-in rule with a `doc`, a
  `confidence` and a CWE (a `cve` rule also with its CVE, a URL and its product's tag), and the
  reference in step with the files. The sets together over the evaluation set: every payload
  refused as a query value (`%20` and `+`) and as a cookie, no benign value hit by any rule. Each
  `cve` rule takes the marker of its exploit's request and lets an ordinary request to the same
  product through. A query parameter and a cookie without `=` (`?debug`, `Cookie: flag`).
- `tests/cost.rs`: a counting allocator holds a clean GET's connection and head phases under
  `builtin: all` to no allocation; an ignored test prints their time.
- `tests/ngfw.rs`: a server booted by the core's test harness (`webfast_core::harness`) with a
  composition of this crate (and the challenge, when built) and the module's instance put on the
  parsed configuration as `Module::load` would, requests that are refused (scanner UA, `/.env`, `union select` in a query, a `.php.jpg`
  upload, a denied country through a test database), let through (a clean page, an allowed
  address with a banned UA), `log_only` writing the line and letting through, `action: header`,
  the ban after `on_blocks`, a honeypot path, a leaking upstream 5xx replaced by 500 with
  `handle_errors`, a streamed 200 cut at a leak in its first frame and at one split across two
  frames (the client has no whole response, the log has `leak`), a clean 200 passed frame for
  frame, a leak after `max_inspect` let through, `response.stream: false` replacing a 200,
  `log_only` passing it whole, a header rule replacing a 200 before any byte, and a site's own
  rule replacing a built-in one. With libinjection built: a quoted SQL injection in a query and an
  XSS in a form body that the other rules score under the threshold refused, a name with an
  apostrophe let through. A query parameter and a cookie without `=` let through, and a hit's
  log line with its severity, tags and CWE. With the challenge built: a rule
  with `action: challenge` answers the page (503, a nonce, not the error page) and, with the cookie
  earned at `POST /.well-known/c-wf`, lets the request through with the hit written as
  `challenge_passed`; `mode: challenge` turns the built-in blocks into the page; `ban.then:
  challenge` answers the page, not 403, after `on_blocks` refusals.
- webfast's bench adds a site with the module on, default sets, for a clean GET
  and a clean POST: the cost over the same site without the module.

## Not in this version

Shared ban lists between replicas (each process keeps its own); a `webfast ngfw report` over the
log; TLS fingerprints (`tls.ja4`) as a target; rate limiting as a rule action (use `rate_limit`).
