# NGFW: the built-in rules

<!-- Generated from crates/webfast-ngfw/src/rules/*.yaml: do not edit by hand. -->

This file is generated from the built-in sets (`crates/webfast-ngfw/src/rules/*.yaml`, as they are compiled into the crate) by the test `the_rules_reference_is_current`, which fails when the file is out of date. After a change to a set, write it again:

```sh
UPDATE_RULES_DOC=1 cargo test -p webfast-ngfw the_rules_reference_is_current
```

The rule format, the targets, transformations and operators, the composition of the sets with a site's own rules and the exclusions are in [ngfw.md](ngfw.md). Built-in version `2026-11-08`: 98 rules in 12 sets, as `builtin: all` loads them with the `libinjection` feature (without it, wf-942-170 and wf-941-150 are left out).

**Severity** is what a hit means, and gives the default score (critical 5, high 4, medium 3, low 2, notice 1; a request is refused at `threshold`, 5 by default). **Confidence** is how rare false positives are: `high`, an honest client practically never sends what the rule matches; `medium`, some sites' ordinary traffic does (the rule's notes say which, and how to exclude it); `low`, the rule is a signal to add up with others rather than a verdict.

## Contents

- [Set `protocol`](#set-protocol): 20 rules
- [Set `scanners`](#set-scanners): 5 rules
- [Set `traversal`](#set-traversal): 3 rules
- [Set `rfi`](#set-rfi): 2 rules
- [Set `cmdi`](#set-cmdi): 3 rules
- [Set `php`](#set-php): 7 rules
- [Set `sqli`](#set-sqli): 11 rules
- [Set `xss`](#set-xss): 8 rules
- [Set `template`](#set-template): 3 rules
- [Set `upload`](#set-upload): 8 rules
- [Set `leakage`](#set-leakage): 7 rules
- [Set `cve`](#set-cve): 21 rules
- [Index by CVE](#index-by-cve)
- [Index by CWE](#index-by-cwe)

## Set `protocol`

Set `protocol` (wf-920-*): protocol anomalies. Methods outside the usual seven, HTTP/1.0
without Host, control and non-UTF-8 bytes, nulls, double encoding, `..` that survives
normalization, oversized paths, queries, cookies and headers, too many parameters or cookies,
conflicting framing headers, a declared body type the bytes contradict, a POST without a
Content-Type, missing User-Agent and Accept, a Range with too many parts, JSON nested too deep.
OWASP: A05 Security Misconfiguration (requests no honest client sends). The `anomaly.*`
targets are facts the parser records while reading the request (docs/ngfw.md, Targets).

| Rule | Phase | Severity / score | Confidence | Action | Message |
| --- | --- | --- | --- | --- | --- |
| [wf-920-100](#wf-920-100) | head | medium / 3 | medium | score | Method not in GET, HEAD, POST, PUT, PATCH, DELETE, OPTIONS |
| [wf-920-110](#wf-920-110) | head | medium / 3 | medium | score | HTTP/1.0 request without a Host header |
| [wf-920-120](#wf-920-120) | head | high / 4 | high | score | Control character in the path or a header |
| [wf-920-130](#wf-920-130) | head | medium / 3 | medium | score | Byte sequence that is not UTF-8 in the path or a header |
| [wf-920-140](#wf-920-140) | head | high / 4 | high | score | Null byte (%00) in the path or query |
| [wf-920-150](#wf-920-150) | head | medium / 3 | medium | score | Double URL encoding |
| [wf-920-160](#wf-920-160) | head | medium / 3 | medium | score | Path with `..` left after normalization |
| [wf-920-170](#wf-920-170) | head | critical / 5 | high | block | Two Content-Length headers, or Content-Length with Transfer-Encoding |
| [wf-920-180](#wf-920-180) | head | medium / 3 | medium | score | Path over 2048 bytes |
| [wf-920-190](#wf-920-190) | head | medium / 3 | medium | score | Query string over 8192 bytes |
| [wf-920-200](#wf-920-200) | head | medium / 3 | medium | score | Cookie value over 8192 bytes |
| [wf-920-210](#wf-920-210) | head | medium / 3 | medium | score | Header value over 8192 bytes |
| [wf-920-220](#wf-920-220) | head | medium / 3 | medium | score | More than 128 parameters |
| [wf-920-230](#wf-920-230) | head | medium / 3 | medium | score | More than 64 cookies |
| [wf-920-300](#wf-920-300) | head | notice / 1 | low | score | No User-Agent header |
| [wf-920-310](#wf-920-310) | head | notice / 1 | low | score | No Accept header |
| [wf-920-400](#wf-920-400) | body | medium / 3 | high | score | Body does not match its declared Content-Type (JSON declared, not JSON) |
| [wf-920-410](#wf-920-410) | head | medium / 3 | medium | score | POST without a Content-Type |
| [wf-920-440](#wf-920-440) | head | medium / 3 | high | score | Range header with more than 16 parts |
| [wf-920-520](#wf-920-520) | body | medium / 3 | medium | score | JSON body nested deeper than json_max_depth |

### wf-920-100

**Method not in GET, HEAD, POST, PUT, PATCH, DELETE, OPTIONS**

- Set `protocol`, phase `head`
- Number `920100` (the log's `ruleId`, go-ftw's `rule_id` and `expect_ids`)
- Targets: `method`
- Transformations: none
- Operator: `regex`:

  ```text
  ^(?:[^GHPDO]|G(?:[^E]|$)|GE(?:[^T]|$)|GET.|H(?:[^E]|$)|HE(?:[^A]|$)|HEA(?:[^D]|$)|HEAD.|P(?:[^OUA]|$)|PO(?:[^S]|$)|POS(?:[^T]|$)|POST.|PU(?:[^T]|$)|PUT.|PA(?:[^T]|$)|PAT(?:[^C]|$)|PATC(?:[^H]|$)|PATCH.|D(?:[^E]|$)|DE(?:[^L]|$)|DEL(?:[^E]|$)|DELE(?:[^T]|$)|DELET(?:[^E]|$)|DELETE.|O(?:[^P]|$)|OP(?:[^T]|$)|OPT(?:[^I]|$)|OPTI(?:[^O]|$)|OPTIO(?:[^N]|$)|OPTION(?:[^S]|$)|OPTIONS.)
  ```
- Severity `medium`, score 3, confidence `medium`, action `score`
- Tags: `OWASP_A05`, `protocol`, `method`
- References: [CWE-650](https://cwe.mitre.org/data/definitions/650.html), [CAPEC-274](https://capec.mitre.org/data/definitions/274.html), CRS 911100

A method other than the seven a web application uses: TRACE, CONNECT, PROPFIND, a made-up
verb, a lowercase `get`. Scanners send them to find a handler that treats an unknown verb
as GET and skips its checks (verb tampering). WebDAV (PROPFIND, MKCOL, LOCK) and CalDAV
clients send others honestly: a site that serves them excludes the rule on their paths
(`exclusions: [{paths: ['/dav/*'], rules: [wf-920-100]}]`). Medium, so it refuses only with
another hit.

### wf-920-110

**HTTP/1.0 request without a Host header**

- Set `protocol`, phase `head`
- Number `920110` (the log's `ruleId`, go-ftw's `rule_id` and `expect_ids`)
- Targets: `anomaly.http10_without_host`
- Transformations: none
- Operator: `exists`
- Severity `medium`, score 3, confidence `medium`, action `score`
- Tags: `OWASP_A05`, `protocol`, `host`
- References: [CWE-20](https://cwe.mitre.org/data/definitions/20.html), CRS 920280

An HTTP/1.0 request without Host: what simple scanners and scripts send, and what reaches
the default site of a server by its address. Browsers have sent Host since the nineties.
Old monitoring probes and load balancer health checks may still send bare HTTP/1.0; such a
probe is better given its own path and excluded there (or `disable: [wf-920-110]`).

### wf-920-120

**Control character in the path or a header**

- Set `protocol`, phase `head`
- Number `920120` (the log's `ruleId`, go-ftw's `rule_id` and `expect_ids`)
- Targets: `path_raw`, `headers`
- Transformations: none
- Operator: `contains_any`: `\x00`, `\x01`, `\x02`, `\x03`, `\x04`, `\x05`, `\x06`, `\x07`, `\x08`, `\x0b`, `\x0c`, `\x0e`, `\x0f`, `\x10`, `\x11`, `\x12`, `\x13`, `\x14`, `\x15`, `\x16`, `\x17`, `\x18`, `\x19`, `\x1a`, `\x1b`, `\x1c`, `\x1d`, `\x1e`, `\x1f`, `\x7f`
- Severity `high`, score 4, confidence `high`, action `score`
- Tags: `OWASP_A05`, `protocol`, `encoding`
- References: [CWE-20](https://cwe.mitre.org/data/definitions/20.html), CRS 920270, CRS 920271

A raw control byte (other than tab, line feed and carriage return) in the path as sent or
in a header value. No browser or HTTP library puts one there; they are used to confuse
parsers, logs and terminals. The HTTP parser refuses most of them already; the rule catches
what gets through. False positives are practically unknown.

### wf-920-130

**Byte sequence that is not UTF-8 in the path or a header**

- Set `protocol`, phase `head`
- Number `920130` (the log's `ruleId`, go-ftw's `rule_id` and `expect_ids`)
- Targets: `path_raw`, `headers`
- Transformations: `url_decode`
- Operator: `not_valid_utf8`
- Severity `medium`, score 3, confidence `medium`, action `score`
- Tags: `OWASP_A05`, `protocol`, `encoding`
- References: [CWE-176](https://cwe.mitre.org/data/definitions/176.html), [CAPEC-71](https://capec.mitre.org/data/definitions/71.html), CRS 920250

The path or a header, percent-decoded, is not valid UTF-8: overlong encodings (`%c0%af` for
`/`) and stray bytes are how filters that compare text are slipped past. Legacy clients
that send Latin-1 in a path (`%E9` for é) or in a header (some old download managers) are
the false positives; a site that has them lowers the score or excludes the path.

### wf-920-140

**Null byte (%00) in the path or query**

- Set `protocol`, phase `head`
- Number `920140` (the log's `ruleId`, go-ftw's `rule_id` and `expect_ids`)
- Targets: `path_raw`, `query`
- Transformations: none
- Operator: `contains_any`: `%00`
- Severity `high`, score 4, confidence `high`, action `score`
- Tags: `OWASP_A05`, `protocol`, `encoding`
- References: [CWE-158](https://cwe.mitre.org/data/definitions/158.html), [CAPEC-52](https://capec.mitre.org/data/definitions/52.html), CRS 920270

An encoded null in the path or the query: the classic cut of a file name (`../../etc/passwd%00.jpg`)
in code that hands strings to C. No form or link produces it. An API that takes binary
data in the query (rare, and better in a body) would need the rule excluded on its path.

### wf-920-150

**Double URL encoding**

- Set `protocol`, phase `head`
- Number `920150` (the log's `ruleId`, go-ftw's `rule_id` and `expect_ids`)
- Targets: `anomaly.double_encoding`
- Transformations: none
- Operator: `exists`
- Severity `medium`, score 3, confidence `medium`, action `score`
- Tags: `OWASP_A05`, `protocol`, `encoding`
- References: [CWE-174](https://cwe.mitre.org/data/definitions/174.html), [CAPEC-120](https://capec.mitre.org/data/definitions/120.html), CRS 920230

A `url_decode` of a value left percent-escapes that needed a second pass (`%252e`): a
payload encoded twice to pass a filter that decodes once and reach an application that
decodes again. Some applications put an encoded URL in a parameter of another (a
`redirect=` with its own query), which is honest double encoding; those parameters are
excluded by target (`exclusions: [{paths: [...], targets: [args.redirect]}]`).

### wf-920-160

**Path with `..` left after normalization**

- Set `protocol`, phase `head`
- Number `920160` (the log's `ruleId`, go-ftw's `rule_id` and `expect_ids`)
- Targets: `path_raw`
- Transformations: `url_decode`, `normalize_path`, `remove_nulls`, `lowercase`
- Operator: `contains_any`: `..`
- Severity `medium`, score 3, confidence `medium`, action `score`
- Tags: `OWASP_A05`, `protocol`, `path`
- References: [CWE-22](https://cwe.mitre.org/data/definitions/22.html), [CAPEC-126](https://capec.mitre.org/data/definitions/126.html)

Two dots left in the path after `.` and `..` segments are resolved: `..` above the root,
`...`, or dots inside a segment (`/a..b`). Traversal attempts leave these; so do file names
with two dots in a row (`/files/report..pdf`, `/v1..2/`), the false positives, which a site
with such names excludes on their paths.

### wf-920-170

**Two Content-Length headers, or Content-Length with Transfer-Encoding**

- Set `protocol`, phase `head`
- Number `920170` (the log's `ruleId`, go-ftw's `rule_id` and `expect_ids`)
- Targets: `anomaly.duplicate_content_length`
- Transformations: none
- Operator: `exists`
- Severity `critical`, score 5, confidence `high`, action `block`
- Tags: `OWASP_A05`, `protocol`, `smuggling`
- References: [CWE-444](https://cwe.mitre.org/data/definitions/444.html), [CAPEC-33](https://capec.mitre.org/data/definitions/33.html), CRS 920181

Conflicting framing: two Content-Length fields, or Content-Length with Transfer-Encoding.
This is how a request is smuggled past a proxy that reads one framing to a backend that
reads the other, so the rule blocks at once. RFC 9112 tells a server to treat it as an
error; no correct client sends it.

### wf-920-180

**Path over 2048 bytes**

- Set `protocol`, phase `head`
- Number `920180` (the log's `ruleId`, go-ftw's `rule_id` and `expect_ids`)
- Targets: `path_raw`
- Transformations: none
- Operator: `length_gt: 2048`
- Severity `medium`, score 3, confidence `medium`, action `score`
- Tags: `OWASP_A05`, `protocol`, `size`
- References: [CWE-400](https://cwe.mitre.org/data/definitions/400.html)

A path longer than 2048 bytes: overflow probes, fuzzers and payloads packed into the path.
Applications that put long state in the path (some single-page routers, signed asset URLs)
can pass it; they raise the limit with an override of their own (`override: {wf-920-180:
{operator: {length_gt: 8192}}}`) or exclude their paths.

### wf-920-190

**Query string over 8192 bytes**

- Set `protocol`, phase `head`
- Number `920190` (the log's `ruleId`, go-ftw's `rule_id` and `expect_ids`)
- Targets: `query`
- Transformations: none
- Operator: `length_gt: 8192`
- Severity `medium`, score 3, confidence `medium`, action `score`
- Tags: `OWASP_A05`, `protocol`, `size`
- References: [CWE-400](https://cwe.mitre.org/data/definitions/400.html)

A query longer than 8 KiB: payload stuffing, hash-collision and parser exhaustion attempts.
A large GET form or a search with a long filter state may reach it; such data belongs in a
POST body, and a site that cannot move it raises the limit by `override`.

### wf-920-200

**Cookie value over 8192 bytes**

- Set `protocol`, phase `head`
- Number `920200` (the log's `ruleId`, go-ftw's `rule_id` and `expect_ids`)
- Targets: `cookies`
- Transformations: none
- Operator: `length_gt: 8192`
- Severity `medium`, score 3, confidence `medium`, action `score`
- Tags: `OWASP_A05`, `protocol`, `size`
- References: [CWE-400](https://cwe.mitre.org/data/definitions/400.html)

One cookie value over 8 KiB, beyond what browsers keep for a cookie (4 KiB): written by a
client, not by a site. Large session cookies of some frameworks chunk themselves under the
limit; one that does not is excluded by its name (`targets: [cookies.<name>]`).

### wf-920-210

**Header value over 8192 bytes**

- Set `protocol`, phase `head`
- Number `920210` (the log's `ruleId`, go-ftw's `rule_id` and `expect_ids`)
- Targets: `headers`
- Transformations: none
- Operator: `length_gt: 8192`
- Severity `medium`, score 3, confidence `medium`, action `score`
- Tags: `OWASP_A05`, `protocol`, `size`
- References: [CWE-400](https://cwe.mitre.org/data/definitions/400.html)

A header value over 8 KiB: overflow probes and payloads carried in headers. The usual false
positive is a large bearer token or a Cookie header of many cookies on a busy domain; the
header is excluded by target (`targets: [headers.authorization]`) where that is the case.

### wf-920-220

**More than 128 parameters**

- Set `protocol`, phase `head`
- Number `920220` (the log's `ruleId`, go-ftw's `rule_id` and `expect_ids`)
- Targets: `args_count`
- Transformations: none
- Operator: `gt: 128`
- Severity `medium`, score 3, confidence `medium`, action `score`
- Tags: `OWASP_A05`, `protocol`, `size`
- References: [CWE-770](https://cwe.mitre.org/data/definitions/770.html), CRS 920380

More than 128 parameters in the query and form together: hash-flooding and parameter
pollution. Large admin forms (permission matrices, bulk edits) can have more; their paths
are excluded, or the limit raised by `override`.

### wf-920-230

**More than 64 cookies**

- Set `protocol`, phase `head`
- Number `920230` (the log's `ruleId`, go-ftw's `rule_id` and `expect_ids`)
- Targets: `cookies`
- Transformations: none
- Operator: `count_gt: 64`
- Severity `medium`, score 3, confidence `medium`, action `score`
- Tags: `OWASP_A05`, `protocol`, `size`
- References: [CWE-770](https://cwe.mitre.org/data/definitions/770.html)

More than 64 cookies in one request. A domain with many analytics and advertising scripts
can accumulate that many, which is the false positive; otherwise it is cookie stuffing
against parsers. Raise the count by `override` on such a site.

### wf-920-300

**No User-Agent header**

- Set `protocol`, phase `head`
- Number `920300` (the log's `ruleId`, go-ftw's `rule_id` and `expect_ids`)
- Targets: `ua`
- Transformations: none
- Operator: `missing`
- Severity `notice`, score 1, confidence `low`, action `score`
- Tags: `OWASP_A05`, `protocol`, `headers`
- References: [CWE-20](https://cwe.mitre.org/data/definitions/20.html), CRS 920320

No User-Agent at all. Every browser sends one; many scripts and some API clients do not.
A notice, scored 1: it only adds to other hits. An API served to clients that omit it
excludes the rule on its paths.

### wf-920-310

**No Accept header**

- Set `protocol`, phase `head`
- Number `920310` (the log's `ruleId`, go-ftw's `rule_id` and `expect_ids`)
- Targets: `headers.accept`
- Transformations: none
- Operator: `missing`
- Severity `notice`, score 1, confidence `low`, action `score`
- Tags: `OWASP_A05`, `protocol`, `headers`
- References: [CWE-20](https://cwe.mitre.org/data/definitions/20.html), CRS 920300

No Accept header. Browsers always send one; scanners and simple scripts often do not, and
neither do some API and feed clients. A notice that only adds to other hits.

### wf-920-400

**Body does not match its declared Content-Type (JSON declared, not JSON)**

- Set `protocol`, phase `body`
- Number `920400` (the log's `ruleId`, go-ftw's `rule_id` and `expect_ids`)
- Targets: `anomaly.body_type_mismatch`
- Transformations: none
- Operator: `exists`
- Severity `medium`, score 3, confidence `high`, action `score`
- Tags: `OWASP_A05`, `protocol`, `body`
- References: [CWE-20](https://cwe.mitre.org/data/definitions/20.html)

A body declared `application/json` that does not parse as JSON. A JSON client produces
JSON; a body that is something else is sent to make the filter skip parsing while the
application reads it another way. A body cut at `max_inspect` is not counted as invalid.

### wf-920-410

**POST without a Content-Type**

- Set `protocol`, phase `head`
- Number `920410` (the log's `ruleId`, go-ftw's `rule_id` and `expect_ids`)
- Targets: `anomaly.post_without_content_type`
- Transformations: none
- Operator: `exists`
- Severity `medium`, score 3, confidence `medium`, action `score`
- Tags: `OWASP_A05`, `protocol`, `body`
- References: [CWE-20](https://cwe.mitre.org/data/definitions/20.html), CRS 920340

A POST, PUT or PATCH with a body and no Content-Type: the body cannot be parsed for the
rules, which is why it is sent so. Some hand-written webhook senders and IoT clients omit
it; their endpoint is excluded by path.

### wf-920-440

**Range header with more than 16 parts**

- Set `protocol`, phase `head`
- Number `920440` (the log's `ruleId`, go-ftw's `rule_id` and `expect_ids`)
- Targets: `headers.range`
- Transformations: `compress_whitespace`
- Operator: `regex`:

  ```text
  (?:,[^,]*){16}
  ```
- Prefilter: `,`
- Severity `medium`, score 3, confidence `high`, action `score`
- Tags: `OWASP_A05`, `protocol`, `range`
- References: [CWE-400](https://cwe.mitre.org/data/definitions/400.html), CRS 920200

A Range header with more than 16 ranges: the "Apache Killer" style of exhausting a server
with overlapping ranges (CVE-2011-3192). Video players and PDF readers ask for one or a few
ranges. False positives are practically unknown.

### wf-920-520

**JSON body nested deeper than json_max_depth**

- Set `protocol`, phase `body`
- Number `920520` (the log's `ruleId`, go-ftw's `rule_id` and `expect_ids`)
- Targets: `anomaly.json_depth`
- Transformations: none
- Operator: `exists`
- Severity `medium`, score 3, confidence `medium`, action `score`
- Tags: `OWASP_A05`, `protocol`, `body`
- References: [CWE-674](https://cwe.mitre.org/data/definitions/674.html)

A JSON body nested deeper than `body.json_max_depth` (20 by default): stack exhaustion of
recursive parsers. Deep documents are rare in forms and APIs; an API that takes them (a
tree editor, GeoJSON) raises `json_max_depth`.

## Set `scanners`

Set `scanners` (wf-913-*): the tools and the probes. User-Agents of vulnerability scanners and
brute-forcers, the paths they try everywhere (dot-files, version control, WordPress, admin
tools, framework endpoints), backups left in the site root. Every rule blocks at once: nothing
of this comes from a browser or an honest client.
OWASP: A05 Security Misconfiguration (what the probes look for). A site that is what a rule
probes for turns it off: a WordPress site disables wf-913-200 (`disable: [wf-913-200]`, or
`disable_tags: [wordpress]`), a site with a real /actuator/ excludes wf-913-220 on that path
(docs/configuration.md).

| Rule | Phase | Severity / score | Confidence | Action | Message |
| --- | --- | --- | --- | --- | --- |
| [wf-913-100](#wf-913-100) | head | critical / 5 | high | block | User-Agent of a vulnerability scanner |
| [wf-913-200](#wf-913-200) | head | critical / 5 | high | block | WordPress probe on a site that is not WordPress |
| [wf-913-210](#wf-913-210) | head | critical / 5 | high | block | Probe for a dot-file: environment, version control, editor and cloud settings |
| [wf-913-220](#wf-913-220) | head | critical / 5 | medium | block | Probe for an admin tool, a framework endpoint or a router interface |
| [wf-913-230](#wf-913-230) | head | critical / 5 | high | block | Backup, dump or configuration file asked for in the site root |

### wf-913-100

**User-Agent of a vulnerability scanner**

- Set `scanners`, phase `head`
- Number `913100` (the log's `ruleId`, go-ftw's `rule_id` and `expect_ids`)
- Targets: `ua`
- Transformations: `lowercase`
- Operator: `contains_any`: `sqlmap`, `nikto`, `nuclei`, `masscan`, `zgrab`, `nmap`, `dirbuster`, `gobuster`, `wpscan`, `acunetix`, `nessus`, `openvas`, `burp`, `havij`, `arachni`, `w3af`, `whatweb`
- Severity `critical`, score 5, confidence `high`, action `block`
- Tags: `OWASP_A05`, `scanner`, `user-agent`
- References: [CWE-200](https://cwe.mitre.org/data/definitions/200.html), [CAPEC-541](https://capec.mitre.org/data/definitions/541.html), CRS 913100

A User-Agent that names a vulnerability scanner or brute-forcer: sqlmap, Nikto, Nuclei,
Nmap's scripts, WPScan and the rest of the list. Blocks at once. A site that has itself
scanned on purpose (a penetration test, an uptime service built on one of these tools)
allows the scanner's address (`access.ip.allow`) rather than turning the rule off; a
User-Agent that merely contains a listed word by accident (`burp` in a product name) is
the rare false positive.

### wf-913-200

**WordPress probe on a site that is not WordPress**

- Set `scanners`, phase `head`
- Number `913200` (the log's `ruleId`, go-ftw's `rule_id` and `expect_ids`)
- Targets: `path`
- Transformations: `lowercase`
- Operator: `contains_any`: `/wp-login.php`, `/wp-admin/`, `/xmlrpc.php`
- Severity `critical`, score 5, confidence `high`, action `block`
- Tags: `OWASP_A05`, `scanner`, `probe`, `wordpress`
- References: [CWE-307](https://cwe.mitre.org/data/definitions/307.html), [CWE-200](https://cwe.mitre.org/data/definitions/200.html)

The WordPress login, admin and XML-RPC paths, which bots try on every site for password
guessing and plugin exploits. Blocks at once. On a WordPress site these are the site's own
pages: it turns the rule off (`disable: [wf-913-200]` or `disable_tags: [wordpress]`) and
keeps the others of the set.

### wf-913-210

**Probe for a dot-file: environment, version control, editor and cloud settings**

- Set `scanners`, phase `head`
- Number `913210` (the log's `ruleId`, go-ftw's `rule_id` and `expect_ids`)
- Targets: `path`
- Transformations: `lowercase`
- Operator: `contains_any`: `/.env`, `/.git/`, `/.svn/`, `/.hg/`, `/.ds_store`, `/.aws/`, `/.htpasswd`, `/.vscode/`
- Severity `critical`, score 5, confidence `high`, action `block`
- Tags: `OWASP_A05`, `scanner`, `probe`, `dotfile`
- References: [CWE-538](https://cwe.mitre.org/data/definitions/538.html), [CWE-527](https://cwe.mitre.org/data/definitions/527.html), CRS 930130

A request for `.env`, a version control directory, an editor's settings, AWS credentials or
`.htpasswd`, anywhere in the path: the files that hold secrets when a deployment publishes
its working tree. Blocks at once, whether the file exists or not. `/.well-known/` is not
matched. A path that only starts like one of these (`/.envoy/`, `/.environment.html`) is the
rare false positive; exclude the rule on it.

### wf-913-220

**Probe for an admin tool, a framework endpoint or a router interface**

- Set `scanners`, phase `head`
- Number `913220` (the log's `ruleId`, go-ftw's `rule_id` and `expect_ids`)
- Targets: `path`
- Transformations: `lowercase`
- Operator: `contains_any`: `/phpmyadmin`, `/pma/`, `/adminer`, `/actuator/`, `/server-status`, `/vendor/phpunit`, `/cgi-bin/`, `/boaform/`, `/hnap1`
- Severity `critical`, score 5, confidence `medium`, action `block`
- Tags: `OWASP_A05`, `scanner`, `probe`, `admin`
- References: [CWE-200](https://cwe.mitre.org/data/definitions/200.html)

phpMyAdmin, Adminer, Spring Boot's actuator, Apache's server-status, PHPUnit in a vendor
directory, CGI scripts, and the router interfaces bots exploit (`/boaform/`, `/HNAP1`).
Blocks at once. Medium confidence: a site that really serves one of these (a CGI
application, an actuator behind the proxy) excludes the rule on that path
(`exclusions: [{paths: ['/actuator/*'], rules: [wf-913-220]}]`).

### wf-913-230

**Backup, dump or configuration file asked for in the site root**

- Set `scanners`, phase `head`
- Number `913230` (the log's `ruleId`, go-ftw's `rule_id` and `expect_ids`)
- Targets: `path`
- Transformations: `lowercase`
- Operator: `regex`:

  ```text
  ^/(?:[^/]+\.(?:bak|sql|zip|tar\.gz|old|orig|swp)|config\.json)$
  ```
- Prefilter: `.bak`, `.sql`, `.zip`, `.tar.gz`, `.old`, `.orig`, `.swp`, `/config.json`
- Severity `critical`, score 5, confidence `high`, action `block`
- Tags: `OWASP_A05`, `scanner`, `probe`, `backup`
- References: [CWE-530](https://cwe.mitre.org/data/definitions/530.html), CRS 920440

A backup, dump or archive in the root (`/backup.zip`, `/db.sql`, `/index.php.bak`,
`/site.tar.gz`) or `/config.json`: scanners guess these names to download a site's source
or database. Only at depth one, so `/downloads/app.zip` is not matched. A site that offers
a download in its root (`/release.zip`) moves it or excludes that path.

## Set `traversal`

Set `traversal` (wf-930-*): path traversal and local file inclusion. `../` and `..\` in any
encoding, the files every traversal payload reaches for (/etc/passwd, win.ini, boot.ini),
`php://filter` and the `.../` sequence.
OWASP: A01 Broken Access Control.

| Rule | Phase | Severity / score | Confidence | Action | Message |
| --- | --- | --- | --- | --- | --- |
| [wf-930-100](#wf-930-100) | head | high / 4 | medium | score | Directory traversal sequence (../ or ..\) in the path, query or a cookie |
| [wf-930-110](#wf-930-110) | head | critical / 5 | high | score | Operating system file in a parameter or the path |
| [wf-930-120](#wf-930-120) | head | high / 4 | high | score | php://filter wrapper or .../ sequence |

### wf-930-100

**Directory traversal sequence (../ or ..\) in the path, query or a cookie**

- Set `traversal`, phase `head`
- Number `930100` (the log's `ruleId`, go-ftw's `rule_id` and `expect_ids`)
- Targets: `path_raw`, `query`, `args`, `cookies`
- Transformations: `url_decode`, `remove_nulls`, `lowercase`, `compress_whitespace`
- Operator: `contains_any`: `../`, `..\`, `/..`, `..;/`
- Severity `high`, score 4, confidence `medium`, action `score`
- Tags: `OWASP_A01`, `traversal`, `lfi`
- References: [CWE-22](https://cwe.mitre.org/data/definitions/22.html), [CAPEC-126](https://capec.mitre.org/data/definitions/126.html), CRS 930100, CRS 930110

`../`, `..\`, `/..` or Tomcat's `..;/`, after percent-decoding, in the path, the query, a
parameter or a cookie: climbing out of a directory to read or include another file. High,
not critical, since relative paths are honest in some parameters (a `path=../shared` of a
file manager, a relative `return=` link); such a parameter is excluded by target
(`targets: [args.path]` on its path).

### wf-930-110

**Operating system file in a parameter or the path**

- Set `traversal`, phase `head`
- Number `930110` (the log's `ruleId`, go-ftw's `rule_id` and `expect_ids`)
- Targets: `args`, `path`, `cookies`
- Transformations: `url_decode`, `normalize_path`, `remove_nulls`, `lowercase`
- Operator: `contains_any`: `/etc/passwd`, `/etc/shadow`, `/proc/self`, `/windows/win.ini`, `c:/windows`, `c:\windows`, `boot.ini`
- Severity `critical`, score 5, confidence `high`, action `score`
- Tags: `OWASP_A01`, `traversal`, `lfi`
- References: [CWE-22](https://cwe.mitre.org/data/definitions/22.html), [CAPEC-126](https://capec.mitre.org/data/definitions/126.html), CRS 930120

The files a traversal or inclusion payload reads to prove it worked: `/etc/passwd`,
`/etc/shadow`, `/proc/self/...`, `win.ini`, `boot.ini`, the Windows directory. Critical:
one hit refuses. A documentation or support site whose texts name these files (a Linux
tutorial's search box) is the false positive; it excludes the rule on the parameter that
takes such text.

### wf-930-120

**php://filter wrapper or .../ sequence**

- Set `traversal`, phase `head`
- Number `930120` (the log's `ruleId`, go-ftw's `rule_id` and `expect_ids`)
- Targets: `args`, `path_raw`, `cookies`
- Transformations: `url_decode`, `remove_nulls`, `lowercase`, `compress_whitespace`
- Operator: `contains_any`: `php://filter`, `.../`
- Severity `high`, score 4, confidence `high`, action `score`
- Tags: `OWASP_A01`, `traversal`, `lfi`, `php`
- References: [CWE-22](https://cwe.mitre.org/data/definitions/22.html), [CWE-98](https://cwe.mitre.org/data/definitions/98.html), [CAPEC-126](https://capec.mitre.org/data/definitions/126.html)

`php://filter`, which reads a PHP source through an inclusion (`php://filter/convert.base64-encode/resource=index.php`),
and `.../`, the sequence that becomes `../` after a filter strips `../` once. Neither
appears in honest values.

## Set `rfi`

Set `rfi` (wf-931-*): remote file inclusion and server-side request forgery. A URL in a
parameter whose name says it is a target (url, src, redirect, file, ...) pointing at an
address, localhost, the cloud metadata services or a numeric address; the file, gopher and dict
schemes anywhere.
OWASP: A10 Server-Side Request Forgery (and A03 Injection for the include wrappers).

| Rule | Phase | Severity / score | Confidence | Action | Message |
| --- | --- | --- | --- | --- | --- |
| [wf-931-100](#wf-931-100) | head | critical / 5 | medium | score | URL to an address, localhost or a metadata service in a target parameter |
| [wf-931-110](#wf-931-110) | head | critical / 5 | high | score | file://, gopher:// or dict:// scheme in a parameter |

### wf-931-100

**URL to an address, localhost or a metadata service in a target parameter**

- Set `rfi`, phase `head`
- Number `931100` (the log's `ruleId`, go-ftw's `rule_id` and `expect_ids`)
- Targets: `args.url`, `args.uri`, `args.src`, `args.dest`, `args.redirect`, `args.next`, `args.path`, `args.file`, `args.page`, `args.include`, `args.template`, `args.callback`
- Transformations: `url_decode`, `remove_nulls`, `lowercase`, `compress_whitespace`
- Operator: `regex`:

  ```text
  (?:https?|ftp)://(?:[^/@]*@)?(?:\d{1,4}\.\d{1,4}\.\d{1,4}\.\d{1,4}|0x[0-9a-f]{1,8}|\d{8,10}|0\d{3,11}|localhost|169\.254\.169\.254|metadata\.google\.internal|\[::1\]|\[::ffff:[0-9a-f.:]+\])(?::\d+)?(?:[/?#]|$)
  ```
- Prefilter: `://`
- Severity `critical`, score 5, confidence `medium`, action `score`
- Tags: `OWASP_A10`, `rfi`, `ssrf`
- References: [CWE-918](https://cwe.mitre.org/data/definitions/918.html), [CWE-98](https://cwe.mitre.org/data/definitions/98.html), [CAPEC-664](https://capec.mitre.org/data/definitions/664.html), CRS 931100

A URL whose host is an IP address (in any of the notations that hide one), `localhost`, the
IPv6 loopback or a cloud metadata host, in a parameter named like a fetch or include target
(`url`, `src`, `redirect`, `file`, `callback`, ...): the shape of server-side request
forgery and remote inclusion. Medium confidence: a development setup, or an application
that lets users link to a device on their network, sends such URLs honestly; it excludes
the parameter on its path.

### wf-931-110

**file://, gopher:// or dict:// scheme in a parameter**

- Set `rfi`, phase `head`
- Number `931110` (the log's `ruleId`, go-ftw's `rule_id` and `expect_ids`)
- Targets: `args`, `cookies`, `path_raw`
- Transformations: `url_decode`, `remove_nulls`, `lowercase`, `compress_whitespace`
- Operator: `contains_any`: `file://`, `gopher://`, `dict://`
- Severity `critical`, score 5, confidence `high`, action `score`
- Tags: `OWASP_A10`, `rfi`, `ssrf`
- References: [CWE-918](https://cwe.mitre.org/data/definitions/918.html), [CAPEC-664](https://capec.mitre.org/data/definitions/664.html)

The `file://`, `gopher://` and `dict://` schemes, which turn a URL fetch into a file read or
a raw TCP request to an internal service (gopher to Redis or SMTP). No web form value
needs them. A help desk that takes pasted `file://` links from users is the false positive.

## Set `cmdi`

Set `cmdi` (wf-932-*): operating system command injection. A shell metacharacter followed by a
command name, the shells and interpreters by path, a newline followed by a command.
OWASP: A03 Injection.

| Rule | Phase | Severity / score | Confidence | Action | Message |
| --- | --- | --- | --- | --- | --- |
| [wf-932-100](#wf-932-100) | head | critical / 5 | medium | score | Shell metacharacter followed by a command name |
| [wf-932-110](#wf-932-110) | head | critical / 5 | medium | score | Shell or interpreter named by path |
| [wf-932-120](#wf-932-120) | head | high / 4 | medium | score | Newline (%0a) followed by a command name |

### wf-932-100

**Shell metacharacter followed by a command name**

- Set `cmdi`, phase `head`
- Number `932100` (the log's `ruleId`, go-ftw's `rule_id` and `expect_ids`)
- Targets: `args`, `cookies`, `body`
- Transformations: `url_decode`, `remove_nulls`, `lowercase`, `cmd_line`
- Operator: `regex`:

  ```text
  (?:[;|&`]|\$\()\s*(?:cat|ls|id|whoami|uname|wget|curl|nc|bash|sh|python[0-9.]*|perl|php[0-9.]*|chmod|rm|sleep|ping)(?:[^a-z0-9_-]|$)
  ```
- Prefilter: `;`, `|`, `&`, `` ` ``, `$(`
- Severity `critical`, score 5, confidence `medium`, action `score`
- Tags: `OWASP_A03`, `injection`, `cmdi`
- References: [CWE-78](https://cwe.mitre.org/data/definitions/78.html), [CAPEC-88](https://capec.mitre.org/data/definitions/88.html), CRS 932230, CRS 932235

`;`, `|`, `&`, a backtick or `$(` followed by one of the commands an injection runs first
(`id`, `whoami`, `cat`, `wget`, `curl`, `sleep`, a shell or interpreter), after `cmd_line`
removes the quotes and carets that split them. Medium confidence: prose can have it
("salt & pepper; cat food", "R&D | ls"), as can a field of shell snippets on a developer
site; those parameters are excluded by target.

### wf-932-110

**Shell or interpreter named by path**

- Set `cmdi`, phase `head`
- Number `932110` (the log's `ruleId`, go-ftw's `rule_id` and `expect_ids`)
- Targets: `args`, `cookies`, `path_raw`, `body`
- Transformations: `url_decode`, `remove_nulls`, `lowercase`, `cmd_line`
- Operator: `contains_any`: `/bin/sh`, `/bin/bash`, `cmd.exe`, `powershell`
- Severity `critical`, score 5, confidence `medium`, action `score`
- Tags: `OWASP_A03`, `injection`, `cmdi`
- References: [CWE-78](https://cwe.mitre.org/data/definitions/78.html), [CAPEC-88](https://capec.mitre.org/data/definitions/88.html), CRS 932160

`/bin/sh`, `/bin/bash`, `cmd.exe` or `powershell` anywhere in a value, the path or the body:
what a reverse shell or a command injection names to run its payload. A site about
programming or system administration (a search for "powershell script") hits it honestly;
it excludes the rule on its search and content parameters.

### wf-932-120

**Newline (%0a) followed by a command name**

- Set `cmdi`, phase `head`
- Number `932120` (the log's `ruleId`, go-ftw's `rule_id` and `expect_ids`)
- Targets: `args`, `query`, `path_raw`, `cookies`
- Transformations: `url_decode`, `remove_nulls`, `lowercase`
- Operator: `regex`:

  ```text
  \n\s*(?:cat|ls|id|whoami|uname|wget|curl|nc|bash|sh|python[0-9.]*|perl|php[0-9.]*|chmod|rm|sleep|ping)(?:[^a-z0-9_-]|$)
  ```
- Prefilter: `\x0a`
- Severity `high`, score 4, confidence `medium`, action `score`
- Tags: `OWASP_A03`, `injection`, `cmdi`
- References: [CWE-78](https://cwe.mitre.org/data/definitions/78.html), [CAPEC-88](https://capec.mitre.org/data/definitions/88.html)

A newline followed by a command name: the newline ends the command a value was put into, and
the next line runs. A multi-line text field whose line starts with one of the words
("ping me tomorrow", "cat photos") matches; such a field (a comment, a message) is excluded
by target if the site sees it.

## Set `php`

Set `php` (wf-933-*): PHP injection. Stream wrappers, PHP open tags in a parameter, the
dangerous functions called, the ini directives attackers set, serialized objects, and `.php`
followed by path info.
OWASP: A03 Injection. A site that is not PHP keeps the set: the payloads say what the client is.

| Rule | Phase | Severity / score | Confidence | Action | Message |
| --- | --- | --- | --- | --- | --- |
| [wf-933-100](#wf-933-100) | head | critical / 5 | high | score | PHP open tag in a parameter |
| [wf-933-110](#wf-933-110) | head | critical / 5 | medium | score | PHP function that runs code, commands or files, called in a parameter |
| [wf-933-115](#wf-933-115) | head | critical / 5 | high | score | preg_replace with the /e modifier |
| [wf-933-120](#wf-933-120) | head | critical / 5 | medium | score | PHP stream wrapper in a parameter |
| [wf-933-130](#wf-933-130) | head | medium / 3 | medium | score | PHP ini directive name in a parameter |
| [wf-933-140](#wf-933-140) | head | high / 4 | medium | score | Serialized PHP object or array in a parameter |
| [wf-933-150](#wf-933-150) | head | medium / 3 | medium | score | .php followed by path info (/a.php/b) |

### wf-933-100

**PHP open tag in a parameter**

- Set `php`, phase `head`
- Number `933100` (the log's `ruleId`, go-ftw's `rule_id` and `expect_ids`)
- Targets: `args`, `cookies`, `body`
- Transformations: `url_decode`, `remove_nulls`, `lowercase`, `compress_whitespace`
- Operator: `contains_any`: `<?php`, `<?=`
- Severity `critical`, score 5, confidence `high`, action `score`
- Tags: `OWASP_A03`, `injection`, `php`
- References: [CWE-94](https://cwe.mitre.org/data/definitions/94.html), [CAPEC-242](https://capec.mitre.org/data/definitions/242.html), CRS 933100

`<?php` or `<?=` in a parameter, a cookie or the body: code sent to be written into a file
that is later included, or evaluated. A code-sharing or support site where users paste PHP
hits it honestly; it excludes the rule on the paste field. An XML declaration (`<?xml`)
does not match.

### wf-933-110

**PHP function that runs code, commands or files, called in a parameter**

- Set `php`, phase `head`
- Number `933110` (the log's `ruleId`, go-ftw's `rule_id` and `expect_ids`)
- Targets: `args`, `cookies`, `body`
- Transformations: `url_decode`, `remove_nulls`, `lowercase`, `compress_whitespace`
- Operator: `contains_any`: `eval(`, `system(`, `passthru(`, `shell_exec(`, `exec(`, `popen(`, `proc_open(`, `assert(`, `create_function(`, `include(`, `require(`, `file_get_contents(`, `file_put_contents(`, `unserialize(`
- Severity `critical`, score 5, confidence `medium`, action `score`
- Tags: `OWASP_A03`, `injection`, `php`
- References: [CWE-94](https://cwe.mitre.org/data/definitions/94.html), [CAPEC-242](https://capec.mitre.org/data/definitions/242.html), CRS 933160

A call of a PHP function that runs code or commands or reads and writes files
(`system(`, `eval(`, `shell_exec(`, `file_put_contents(`, ...): the payload of a code
injection or a web shell's command. The words with a parenthesis are rare in prose, but
`include(` and `require(` turn up in code questions and JavaScript snippets; a developer
forum excludes its text fields.

### wf-933-115

**preg_replace with the /e modifier**

- Set `php`, phase `head`
- Number `933115` (the log's `ruleId`, go-ftw's `rule_id` and `expect_ids`)
- Targets: `args`, `cookies`, `body`
- Transformations: `url_decode`, `remove_nulls`, `lowercase`, `compress_whitespace`
- Operator: `regex`:

  ```text
  preg_replace\s*\(.{0,200}?/[a-z]*e[a-z]*['"]
  ```
- Prefilter: `preg_replace`
- Severity `critical`, score 5, confidence `high`, action `score`
- Tags: `OWASP_A03`, `injection`, `php`
- References: [CWE-95](https://cwe.mitre.org/data/definitions/95.html), [CAPEC-242](https://capec.mitre.org/data/definitions/242.html)

`preg_replace(` with a pattern whose modifiers include `e`, which old PHP versions evaluated
as code. Sent by exploit kits against legacy applications. Only a code paste on a
developer site matches honestly.

### wf-933-120

**PHP stream wrapper in a parameter**

- Set `php`, phase `head`
- Number `933120` (the log's `ruleId`, go-ftw's `rule_id` and `expect_ids`)
- Targets: `args`, `args_names`, `cookies`, `headers.referer`, `path`
- Transformations: `url_decode`, `remove_nulls`, `lowercase`, `compress_whitespace`
- Operator: `contains_any`: `php://`, `phar://`, `data:`, `expect://`, `zip://`, `glob://`
- Severity `critical`, score 5, confidence `medium`, action `score`
- Tags: `OWASP_A03`, `injection`, `php`
- References: [CWE-98](https://cwe.mitre.org/data/definitions/98.html), [CAPEC-193](https://capec.mitre.org/data/definitions/193.html), CRS 933200, CRS 933140

A PHP stream wrapper (`php://input`, `phar://`, `expect://`, `zip://`, `glob://`) or a
`data:` URI in a parameter, its name, a cookie, the Referer or the path: how a file
inclusion reads the request body, unpacks an archive or runs a command. Medium confidence
because of `data:`: a form that takes an image as a data URL (an avatar cropper, a canvas
export) sends `data:image/png;base64,...` honestly, and is excluded by target.

### wf-933-130

**PHP ini directive name in a parameter**

- Set `php`, phase `head`
- Number `933130` (the log's `ruleId`, go-ftw's `rule_id` and `expect_ids`)
- Targets: `args`, `args_names`, `cookies`, `body`
- Transformations: `url_decode`, `remove_nulls`, `lowercase`, `compress_whitespace`
- Operator: `contains_any`: `allow_url_include`, `auto_prepend_file`, `auto_append_file`, `disable_functions`, `open_basedir`
- Severity `medium`, score 3, confidence `medium`, action `score`
- Tags: `OWASP_A03`, `injection`, `php`
- References: [CWE-15](https://cwe.mitre.org/data/definitions/15.html), CRS 933120

The ini directives an attacker sets to turn an inclusion or a CGI argument injection into
code execution (`allow_url_include`, `auto_prepend_file`, ...). Medium, so it needs another
hit: the names also appear in honest PHP hosting control panels and documentation
searches.

### wf-933-140

**Serialized PHP object or array in a parameter**

- Set `php`, phase `head`
- Number `933140` (the log's `ruleId`, go-ftw's `rule_id` and `expect_ids`)
- Targets: `args`, `cookies`, `body`
- Transformations: `url_decode`, `remove_nulls`, `lowercase`, `compress_whitespace`
- Operator: `regex`:

  ```text
  (?:^|[^a-z0-9_])[oa]:\d+:["{]
  ```
- Prefilter: `:"`, `:{`
- Severity `high`, score 4, confidence `medium`, action `score`
- Tags: `OWASP_A03`, `injection`, `php`, `deserialization`
- References: [CWE-502](https://cwe.mitre.org/data/definitions/502.html), [CAPEC-586](https://capec.mitre.org/data/definitions/586.html), CRS 933170

A PHP serialized object (`O:8:"stdClass"`) or array (`a:2:{`) in a value: the input of an
`unserialize()` that builds attacker-chosen objects (a POP chain). Some PHP applications
keep serialized arrays in their own cookies or hidden fields, which is the false positive;
those are excluded by target (`targets: [cookies.<name>]`).

### wf-933-150

**.php followed by path info (/a.php/b)**

- Set `php`, phase `head`
- Number `933150` (the log's `ruleId`, go-ftw's `rule_id` and `expect_ids`)
- Targets: `path`
- Transformations: `lowercase`
- Operator: `regex`:

  ```text
  \.ph(?:p[0-9]?|tml|ar)/
  ```
- Prefilter: `.php`
- Severity `medium`, score 3, confidence `medium`, action `score`
- Tags: `OWASP_A03`, `injection`, `php`, `pathinfo`
- References: [CWE-20](https://cwe.mitre.org/data/definitions/20.html)

A `.php` (or `.phtml`, `.phar`) segment followed by more path: path info, which reaches a
script past a rule that looks at the path's end (`/admin.php/style.css` served by
`admin.php`). Front controllers with path info (`/index.php/blog/post`) are common in PHP
frameworks; such a site disables the rule (`disable: [wf-933-150]`).

## Set `sqli`

Set `sqli` (wf-942-*): SQL injection. Statements and keywords no form value needs, the
time-based and file functions, tautologies, comment and quote tricks, stacked statements,
MySQL's `procedure analyse` and `shutdown`, a quote closed by a comment at the end of a value,
a numeric tautology as a whole value. On parameter values and cookies, after `url_decode
remove_nulls lowercase remove_comments compress_whitespace` (wf-942-140 and wf-942-190 keep the
comments to see them); wf-942-170 is libinjection's detector on what its prefilter lets
through (the `libinjection` feature; left out without it).
OWASP: A03 Injection.

| Rule | Phase | Severity / score | Confidence | Action | Message |
| --- | --- | --- | --- | --- | --- |
| [wf-942-100](#wf-942-100) | head | critical / 5 | high | score | SQL statement in a parameter (union select, insert into, drop table, into outfile) |
| [wf-942-110](#wf-942-110) | head | high / 4 | medium | score | select ... from in a parameter |
| [wf-942-120](#wf-942-120) | head | critical / 5 | high | score | SQL function for timing, files or the system (sleep, benchmark, load_file, xp_cmdshell) |
| [wf-942-130](#wf-942-130) | head | high / 4 | medium | score | SQL tautology (' or ', or 1=1, and 1=1) |
| [wf-942-140](#wf-942-140) | head | high / 4 | medium | score | SQL comment after a quote or a semicolon, or a MySQL version comment (/*!) |
| [wf-942-150](#wf-942-150) | head | medium / 3 | medium | score | char() or concat() with a quote, or a hex literal with a quote |
| [wf-942-160](#wf-942-160) | head | high / 4 | medium | score | Stacked SQL statement (; drop, ; delete, ; update, ; insert) |
| [wf-942-170](#wf-942-170) | head | critical / 5 | high | score | SQL injection (libinjection) |
| [wf-942-180](#wf-942-180) | head | critical / 5 | high | score | SQL procedure analyse or a stacked shutdown |
| [wf-942-190](#wf-942-190) | head | critical / 5 | high | score | Quote closed by a SQL comment at the end of a value (admin' #, admin'/*) |
| [wf-942-200](#wf-942-200) | head | critical / 5 | high | score | Numeric SQL tautology as the whole value (1 or true, -1 or 2>1, 1 and 1=1) |

### wf-942-100

**SQL statement in a parameter (union select, insert into, drop table, into outfile)**

- Set `sqli`, phase `head`
- Number `942100` (the log's `ruleId`, go-ftw's `rule_id` and `expect_ids`)
- Targets: `args`, `cookies`, `body`
- Transformations: `url_decode`, `remove_nulls`, `lowercase`, `remove_comments`, `compress_whitespace`
- Operator: `contains_any`: `union select`, `union all select`, `insert into`, `drop table`, `into outfile`
- Severity `critical`, score 5, confidence `high`, action `score`
- Tags: `OWASP_A03`, `injection`, `sqli`
- References: [CWE-89](https://cwe.mitre.org/data/definitions/89.html), [CAPEC-66](https://capec.mitre.org/data/definitions/66.html)

`union select`, `union all select`, `insert into`, `drop table` or `into outfile`, after
comments are removed and whitespace compressed (so `UNION/**/SELECT` is seen): the core of
a data-extracting or destructive injection. Critical: one hit refuses. A database course,
a SQL tutorial's search box or a query builder that sends SQL in parameters hits it
honestly, and excludes the rule on those parameters.

### wf-942-110

**select ... from in a parameter**

- Set `sqli`, phase `head`
- Number `942110` (the log's `ruleId`, go-ftw's `rule_id` and `expect_ids`)
- Targets: `args`, `cookies`, `body`
- Transformations: `url_decode`, `remove_nulls`, `lowercase`, `remove_comments`, `compress_whitespace`
- Operator: `regex`:

  ```text
  (?:^|[^a-z0-9_])select (?:(?:distinct|all|top \d+) )?(?:\*|[a-z0-9_.@`"'$]+(?:\([^()]*\))?(?: as [a-z0-9_]+)?)(?: ?, ?(?:\*|[a-z0-9_.@`"'$]+(?:\([^()]*\))?(?: as [a-z0-9_]+)?))* from(?:[^a-z0-9_]|$)
  ```
- Prefilter: `select `
- Severity `high`, score 4, confidence `medium`, action `score`
- Tags: `OWASP_A03`, `injection`, `sqli`
- References: [CWE-89](https://cwe.mitre.org/data/definitions/89.html), [CAPEC-66](https://capec.mitre.org/data/definitions/66.html)

`select`, a column list and `from`: a subquery or a second statement. The list is what
SQL has there — `*`, names, numbers, quoted names, calls such as `version()`, `as` aliases,
separated by commas — so prose with words between the two ("please select one option from
the list") does not match, while "select a from" still does. High, not critical: a one-word
list is still English ("select one from the list"), so it refuses only with another hit,
such as a quote trick.

### wf-942-120

**SQL function for timing, files or the system (sleep, benchmark, load_file, xp_cmdshell)**

- Set `sqli`, phase `head`
- Number `942120` (the log's `ruleId`, go-ftw's `rule_id` and `expect_ids`)
- Targets: `args`, `cookies`, `body`
- Transformations: `url_decode`, `remove_nulls`, `lowercase`, `remove_comments`, `compress_whitespace`
- Operator: `contains_any`: `sleep(`, `benchmark(`, `pg_sleep(`, `waitfor delay`, `information_schema`, `load_file(`, `xp_cmdshell`, `@@version`
- Severity `critical`, score 5, confidence `high`, action `score`
- Tags: `OWASP_A03`, `injection`, `sqli`
- References: [CWE-89](https://cwe.mitre.org/data/definitions/89.html), [CAPEC-66](https://capec.mitre.org/data/definitions/66.html), CRS 942160, CRS 942280

The functions of blind and out-of-band injection: `sleep(`, `benchmark(`, `pg_sleep(`,
`waitfor delay`, and the system catalog, file and command functions (`information_schema`,
`load_file(`, `xp_cmdshell`, `@@version`). None of them is in an honest form value but on
a site about databases.

### wf-942-130

**SQL tautology (' or ', or 1=1, and 1=1)**

- Set `sqli`, phase `head`
- Number `942130` (the log's `ruleId`, go-ftw's `rule_id` and `expect_ids`)
- Targets: `args`, `cookies`, `body`
- Transformations: `url_decode`, `remove_nulls`, `lowercase`, `remove_comments`, `compress_whitespace`
- Operator: `contains_any`: `' or '`, `" or "`, `or 1=1`, `and 1=1`, `' or 1`, `" or 1`
- Severity `high`, score 4, confidence `medium`, action `score`
- Tags: `OWASP_A03`, `injection`, `sqli`
- References: [CWE-89](https://cwe.mitre.org/data/definitions/89.html), [CAPEC-66](https://capec.mitre.org/data/definitions/66.html), CRS 942130

A quote closed and an `or` opened (`' or '`, `" or 1`), or `or 1=1` / `and 1=1`: the
authentication bypass and the boolean probe. High: quoted alternatives in prose ("'tea' or
'coffee'") match too, so it needs a second hit, which a real injection brings.

### wf-942-140

**SQL comment after a quote or a semicolon, or a MySQL version comment (/*!)**

- Set `sqli`, phase `head`
- Number `942140` (the log's `ruleId`, go-ftw's `rule_id` and `expect_ids`)
- Targets: `args`, `cookies`, `body`
- Transformations: `url_decode`, `remove_nulls`, `lowercase`, `compress_whitespace`
- Operator: `contains_any`: `'--`, `"--`, `' --`, `" --`, `;--`, `; --`, `/*!`
- Severity `high`, score 4, confidence `medium`, action `score`
- Tags: `OWASP_A03`, `injection`, `sqli`
- References: [CWE-89](https://cwe.mitre.org/data/definitions/89.html), [CAPEC-66](https://capec.mitre.org/data/definitions/66.html), CRS 942440

A quote or a semicolon followed by `--`, which cuts off the rest of the query (`admin'--`),
or MySQL's version comment `/*!`, which hides keywords from filters. Prose with a dash
after a quote ("he said 'no' -- then left") matches, hence high: it refuses with another
hit.

### wf-942-150

**char() or concat() with a quote, or a hex literal with a quote**

- Set `sqli`, phase `head`
- Number `942150` (the log's `ruleId`, go-ftw's `rule_id` and `expect_ids`)
- Targets: `args`, `cookies`, `body`
- Transformations: `url_decode`, `remove_nulls`, `lowercase`, `remove_comments`, `compress_whitespace`
- Operator: `regex`:

  ```text
  (?:['"].{0,40}?(?:^|[^a-z0-9_])(?:char|concat)\(|(?:^|[^a-z0-9_])(?:char|concat)\(.{0,40}?['"]|['"].{0,20}?0x[0-9a-f]{8}|0x[0-9a-f]{8}.{0,20}?['"])
  ```
- Prefilter: `char(`, `concat(`, `0x`
- Severity `medium`, score 3, confidence `medium`, action `score`
- Tags: `OWASP_A03`, `injection`, `sqli`
- References: [CWE-89](https://cwe.mitre.org/data/definitions/89.html), [CAPEC-66](https://capec.mitre.org/data/definitions/66.html)

`char(` or `concat(` near a quote, or a hex literal of eight digits or more near a quote:
how an injection builds strings without writing them, past a filter of keywords. Medium:
code snippets and spreadsheet formulas have it, so it only adds to other hits.

### wf-942-160

**Stacked SQL statement (; drop, ; delete, ; update, ; insert)**

- Set `sqli`, phase `head`
- Number `942160` (the log's `ruleId`, go-ftw's `rule_id` and `expect_ids`)
- Targets: `args`, `cookies`, `body`
- Transformations: `url_decode`, `remove_nulls`, `lowercase`, `remove_comments`, `compress_whitespace`
- Operator: `regex`:

  ```text
  ;\s*(?:drop|delete|update|insert)(?:[^a-z0-9_]|$)
  ```
- Prefilter: `;`
- Severity `high`, score 4, confidence `medium`, action `score`
- Tags: `OWASP_A03`, `injection`, `sqli`
- References: [CWE-89](https://cwe.mitre.org/data/definitions/89.html), [CAPEC-66](https://capec.mitre.org/data/definitions/66.html)

A semicolon followed by `drop`, `delete`, `update` or `insert`: a second statement stacked
after the one the value was put into. Prose with a semicolon before one of the words
("saved; update tomorrow") matches, hence high.

### wf-942-170

**SQL injection (libinjection)**

- Set `sqli`, phase `head`
- Number `942170` (the log's `ruleId`, go-ftw's `rule_id` and `expect_ids`)
- Targets: `args`, `args_names`, `cookies`, `cookies_names`, `body.json`
- Transformations: `url_decode`, `remove_nulls`, `lowercase`, `compress_whitespace`
- Operator: `detect_sqli` (libinjection's SQL injection detector)
- Prefilter: `'`, `"`, `` ` ``, `=`, `(`, `;`, `--`, `/*`, `||`, `@@`, `union`, `select`
- Severity `critical`, score 5, confidence `high`, action `score`
- Tags: `OWASP_A03`, `injection`, `sqli`, `libinjection`
- References: [CWE-89](https://cwe.mitre.org/data/definitions/89.html), [CAPEC-66](https://capec.mitre.org/data/definitions/66.html), CRS 942100

libinjection's SQL injection detector, which tokenizes a value as SQL in each quoting
context and compares the token sequence with its list of injection fingerprints; the hit's
`matched` starts with the fingerprint. It runs only on a value with one of the prefilter's
literals, so most values never reach it. Measured on the crate's evaluation set it has no
false positive among names with apostrophes, prose with keywords, URLs and JSON; a value it
misjudges is excluded by target, or the rule's score lowered by `override`.

### wf-942-180

**SQL procedure analyse or a stacked shutdown**

- Set `sqli`, phase `head`
- Number `942180` (the log's `ruleId`, go-ftw's `rule_id` and `expect_ids`)
- Targets: `args`, `cookies`, `body`
- Transformations: `url_decode`, `remove_nulls`, `lowercase`, `remove_comments`, `compress_whitespace`
- Operator: `regex`:

  ```text
  procedure analyse\s*\(|;\s*shutdown\s*(?:with\s+nowait\s*)?(?:;|--|#|/\*|$)
  ```
- Prefilter: `procedure analyse`, `shutdown`
- Severity `critical`, score 5, confidence `high`, action `score`
- Tags: `OWASP_A03`, `injection`, `sqli`
- References: [CWE-89](https://cwe.mitre.org/data/definitions/89.html), [CAPEC-66](https://capec.mitre.org/data/definitions/66.html), CRS 942280

MySQL's `procedure analyse(`, appended to a query to read its columns' types, and
`shutdown` stacked after a semicolon and ending the statement (`'; shutdown--`), which stops
a SQL Server. The call needs its parenthesis and the shutdown its end (`;`, a comment or the
end of the value), so prose ("the procedure analyses", "power failure; shutdown at 5") does
not match.

### wf-942-190

**Quote closed by a SQL comment at the end of a value (admin' #, admin'/*)**

- Set `sqli`, phase `head`
- Number `942190` (the log's `ruleId`, go-ftw's `rule_id` and `expect_ids`)
- Targets: `args`, `cookies`, `body`
- Transformations: `url_decode`, `remove_nulls`, `lowercase`, `compress_whitespace`
- Operator: `regex`:

  ```text
  ['"] ?(?:#|--|/\*)[\s-]*$
  ```
- Prefilter: `'#`, `' #`, `'--`, `' --`, `'/*`, `' /*`, `"#`, `" #`, `"--`, `" --`, `"/*`, `" /*`
- Severity `critical`, score 5, confidence `high`, action `score`
- Tags: `OWASP_A03`, `injection`, `sqli`
- References: [CWE-89](https://cwe.mitre.org/data/definitions/89.html), [CAPEC-66](https://capec.mitre.org/data/definitions/66.html), CRS 942440

A quote followed by a comment (`#`, `--`, `/*`) and nothing more: the login bypass
`admin' #` / `admin'--` / `admin'/*`, which closes the string and drops the password check.
Anchored at the end of the value, so `it's #1` and `O'Brien -- CEO` do not match. A value
that really ends in a quote and a dash or hash ("say 'hi' --") is the rare false positive.

### wf-942-200

**Numeric SQL tautology as the whole value (1 or true, -1 or 2>1, 1 and 1=1)**

- Set `sqli`, phase `head`
- Number `942200` (the log's `ruleId`, go-ftw's `rule_id` and `expect_ids`)
- Targets: `args`, `cookies`, `body`
- Transformations: `url_decode`, `remove_nulls`, `lowercase`, `remove_comments`, `compress_whitespace`
- Operator: `regex`:

  ```text
  ^\s*-?\d+(?:\s+(?:or|and|xor)\s+|\s*(?:\|\||&&)\s*)(?:not\s+-?\d+|true|-?\d+\s*(?:=|<=>|<>|!=|<=|>=|<|>)\s*-?\d+)\s*$
  ```
- Prefilter: ` or `, ` and `, ` xor `, `||`, `&&`
- Severity `critical`, score 5, confidence `high`, action `score`
- Tags: `OWASP_A03`, `injection`, `sqli`
- References: [CWE-89](https://cwe.mitre.org/data/definitions/89.html), [CAPEC-66](https://capec.mitre.org/data/definitions/66.html)

A whole value that is a number, `or`, `and` or `xor`, and something always true or a
comparison of numbers (`1 or true`, `-1 or 2>1`, `1 and 1=1`, `0 or not 0`): the probe of
a numeric parameter (`?id=1 or true`) that has no quote for other rules to see. Anchored at
both ends of the value, so "1 or 2 items" and "1 < 2 and 3 > 2" do not match; a numeric
field that takes a comparison as text ("2 or 3>1") would be the false positive.

## Set `xss`

Set `xss` (wf-941-*): cross-site scripting. Script and embedding tags, script schemes, event
handler attributes, the DOM and functions a payload reaches for, a tag split by another
(`<scr<script>ipt>`), a script scheme broken up by control characters or spaces. On parameter
values, cookies and the body, after `url_decode html_decode js_decode remove_nulls lowercase
compress_whitespace` (wf-941-170 keeps the whitespace to see it); wf-941-150 is libinjection's
detector, also on the User-Agent and the Referer (the `libinjection` feature; left out without
it).
OWASP: A03 Injection.

| Rule | Phase | Severity / score | Confidence | Action | Message |
| --- | --- | --- | --- | --- | --- |
| [wf-941-100](#wf-941-100) | head | critical / 5 | high | score | HTML tag that runs or embeds script (script, svg, iframe, object, embed, meta http-equiv) |
| [wf-941-110](#wf-941-110) | head | critical / 5 | high | score | Script scheme (javascript:, vbscript:, data:text/html) |
| [wf-941-120](#wf-941-120) | head | high / 4 | medium | score | Event handler attribute (onload=, onerror=, onmouseover=, ...) |
| [wf-941-130](#wf-941-130) | head | high / 4 | medium | score | Script payload reaching for the document, the location or an encoder |
| [wf-941-140](#wf-941-140) | head | medium / 3 | low | score | eval( or alert( in a parameter |
| [wf-941-150](#wf-941-150) | head | critical / 5 | high | score | XSS (libinjection) |
| [wf-941-160](#wf-941-160) | head | high / 4 | medium | score | HTML tag split by another tag (<scr<script>ipt>) |
| [wf-941-170](#wf-941-170) | head | critical / 5 | high | score | Script scheme broken up by control characters or spaces (jav&#x09;ascript:) |

### wf-941-100

**HTML tag that runs or embeds script (script, svg, iframe, object, embed, meta http-equiv)**

- Set `xss`, phase `head`
- Number `941100` (the log's `ruleId`, go-ftw's `rule_id` and `expect_ids`)
- Targets: `args`, `cookies`, `body`
- Transformations: `url_decode`, `html_decode`, `js_decode`, `remove_nulls`, `lowercase`, `compress_whitespace`
- Operator: `contains_any`: `<script`, `</script`, `<svg`, `<iframe`, `<object`, `<embed`, `<meta http-equiv`, `<img src=x onerror`
- Severity `critical`, score 5, confidence `high`, action `score`
- Tags: `OWASP_A03`, `injection`, `xss`
- References: [CWE-79](https://cwe.mitre.org/data/definitions/79.html), [CAPEC-63](https://capec.mitre.org/data/definitions/63.html), CRS 941110, CRS 941160

A `<script`, `<svg`, `<iframe`, `<object`, `<embed` or `<meta http-equiv` tag, after
percent, HTML-entity and JavaScript escapes are decoded: markup that runs script or loads a
document. A rich-text editor that posts HTML with embedded media (an `<iframe>` of a video,
an inline `<svg>`) is the false positive; its field is excluded by target, and the HTML
sanitized by the application.

### wf-941-110

**Script scheme (javascript:, vbscript:, data:text/html)**

- Set `xss`, phase `head`
- Number `941110` (the log's `ruleId`, go-ftw's `rule_id` and `expect_ids`)
- Targets: `args`, `cookies`, `body`
- Transformations: `url_decode`, `html_decode`, `js_decode`, `remove_nulls`, `lowercase`, `compress_whitespace`
- Operator: `contains_any`: `javascript:`, `vbscript:`, `data:text/html`
- Severity `critical`, score 5, confidence `high`, action `score`
- Tags: `OWASP_A03`, `injection`, `xss`
- References: [CWE-79](https://cwe.mitre.org/data/definitions/79.html), [CAPEC-63](https://capec.mitre.org/data/definitions/63.html), CRS 941170

`javascript:`, `vbscript:` or `data:text/html`: a URL that runs script where a link or a
redirect target is expected. "JavaScript: the good parts" in a search box is the false
positive (the colon right after the word), rare enough to exclude by target where it
happens.

### wf-941-120

**Event handler attribute (onload=, onerror=, onmouseover=, ...)**

- Set `xss`, phase `head`
- Number `941120` (the log's `ruleId`, go-ftw's `rule_id` and `expect_ids`)
- Targets: `args`, `cookies`, `body`
- Transformations: `url_decode`, `html_decode`, `js_decode`, `remove_nulls`, `lowercase`, `compress_whitespace`
- Operator: `regex`:

  ```text
  (?:^|[^a-z0-9_])on(?:load|error|mouseover|mouseout|mouseenter|mouseleave|mousedown|mouseup|focus|blur|click|dblclick|keydown|keyup|keypress|submit|change|input|animationstart|animationend|transitionend|toggle|pointerover|pointerenter|pointerdown|wheel|scroll|resize|pageshow|beforeunload|unload|abort|readystatechange|message|hashchange|play|pause|ended|begin|drag|drop|cut|copy|paste|select|contextmenu|auxclick|loadstart)\s*=
  ```
- Prefilter: `onload`, `onerror`, `onmouseover`, `onmouseout`, `onmouseenter`, `onmouseleave`, `onmousedown`, `onmouseup`, `onfocus`, `onblur`, `onclick`, `ondblclick`, `onkeydown`, `onkeyup`, `onkeypress`, `onsubmit`, `onchange`, `oninput`, `onanimationstart`, `onanimationend`, `ontransitionend`, `ontoggle`, `onpointerover`, `onpointerenter`, `onpointerdown`, `onwheel`, `onscroll`, `onresize`, `onpageshow`, `onbeforeunload`, `onunload`, `onabort`, `onreadystatechange`, `onmessage`, `onhashchange`, `onplay`, `onpause`, `onended`, `onbegin`, `ondrag`, `ondrop`, `oncut`, `oncopy`, `onpaste`, `onselect`, `oncontextmenu`, `onauxclick`, `onloadstart`
- Severity `high`, score 4, confidence `medium`, action `score`
- Tags: `OWASP_A03`, `injection`, `xss`
- References: [CWE-79](https://cwe.mitre.org/data/definitions/79.html), [CAPEC-63](https://capec.mitre.org/data/definitions/63.html), CRS 941120

An event handler attribute (`onerror=`, `onload=`, `onfocus=`, ... about fifty names)
as a word followed by `=`: script run from an attribute, the vector when `<script` is
filtered. High, so it refuses with a second hit; a value of code or a query language
(`onclick = handler` in a developer forum) is the false positive.

### wf-941-130

**Script payload reaching for the document, the location or an encoder**

- Set `xss`, phase `head`
- Number `941130` (the log's `ruleId`, go-ftw's `rule_id` and `expect_ids`)
- Targets: `args`, `cookies`, `body`
- Transformations: `url_decode`, `html_decode`, `js_decode`, `remove_nulls`, `lowercase`, `compress_whitespace`
- Operator: `contains_any`: `document.cookie`, `document.location`, `window.location`, `string.fromcharcode`, `expression(`
- Severity `high`, score 4, confidence `medium`, action `score`
- Tags: `OWASP_A03`, `injection`, `xss`
- References: [CWE-79](https://cwe.mitre.org/data/definitions/79.html), [CAPEC-63](https://capec.mitre.org/data/definitions/63.html), CRS 941180

What a script payload does once it runs: `document.cookie` to steal a session,
`document.location` / `window.location` to send it away, `String.fromCharCode` to build a
string past a filter, CSS `expression(`. Developer content mentions them; high, so a hit
alone does not refuse.

### wf-941-140

**eval( or alert( in a parameter**

- Set `xss`, phase `head`
- Number `941140` (the log's `ruleId`, go-ftw's `rule_id` and `expect_ids`)
- Targets: `args`, `cookies`, `body`
- Transformations: `url_decode`, `html_decode`, `js_decode`, `remove_nulls`, `lowercase`, `compress_whitespace`
- Operator: `contains_any`: `eval(`, `alert(`
- Severity `medium`, score 3, confidence `low`, action `score`
- Tags: `OWASP_A03`, `injection`, `xss`
- References: [CWE-79](https://cwe.mitre.org/data/definitions/79.html), [CAPEC-63](https://capec.mitre.org/data/definitions/63.html), CRS 941390

`eval(` or `alert(`: the call every proof-of-concept payload makes. Low confidence (code
in a text field has it), and medium severity: it only adds to the other rules' hits.

### wf-941-150

**XSS (libinjection)**

- Set `xss`, phase `head`
- Number `941150` (the log's `ruleId`, go-ftw's `rule_id` and `expect_ids`)
- Targets: `args`, `args_names`, `cookies`, `cookies_names`, `body.json`, `ua`, `headers.referer`
- Transformations: `url_decode`, `html_decode`, `js_decode`, `remove_nulls`, `lowercase`, `compress_whitespace`
- Operator: `detect_xss` (libinjection's XSS detector)
- Prefilter: `<`, `javascript:`, `vbscript:`, `data:`, `expression(`, `onload`, `onerror`, `onmouseover`, `onmouseout`, `onmouseenter`, `onmouseleave`, `onmousedown`, `onmouseup`, `onfocus`, `onblur`, `onclick`, `ondblclick`, `onkeydown`, `onkeyup`, `onkeypress`, `onsubmit`, `onchange`, `oninput`, `onanimationstart`, `onanimationend`, `ontransitionend`, `ontoggle`, `onpointerover`, `onpointerenter`, `onpointerdown`, `onwheel`, `onscroll`, `onresize`, `onpageshow`, `onbeforeunload`, `onunload`, `onabort`, `onreadystatechange`, `onmessage`, `onhashchange`, `onplay`, `onpause`, `onended`, `onbegin`, `ondrag`, `ondrop`, `oncut`, `oncopy`, `onpaste`, `onselect`, `oncontextmenu`, `onauxclick`, `onloadstart`, `onstart`
- Severity `critical`, score 5, confidence `high`, action `score`
- Tags: `OWASP_A03`, `injection`, `xss`, `libinjection`
- References: [CWE-79](https://cwe.mitre.org/data/definitions/79.html), [CAPEC-63](https://capec.mitre.org/data/definitions/63.html), CRS 941100

libinjection's XSS detector, which parses a value as HTML in each context it could land in
(text, attribute, quoted attribute) and reports a tag, attribute or URL that runs script.
It runs on what the prefilter lets through: a `<`, a script scheme, `expression(` or an
event handler's name. Harmless markup (`<b>`, `<p>`, `<br>`) and `<3` are not reported; a
rich-text field is excluded by target as for wf-941-100.

### wf-941-160

**HTML tag split by another tag (<scr<script>ipt>)**

- Set `xss`, phase `head`
- Number `941160` (the log's `ruleId`, go-ftw's `rule_id` and `expect_ids`)
- Targets: `args`, `cookies`, `body`
- Transformations: `url_decode`, `html_decode`, `js_decode`, `remove_nulls`, `lowercase`, `compress_whitespace`
- Operator: `regex`:

  ```text
  <[a-z]{0,12}<[a-z]{1,12}[\s/>]
  ```
- Prefilter: `<`
- Severity `high`, score 4, confidence `medium`, action `score`
- Tags: `OWASP_A03`, `injection`, `xss`
- References: [CWE-79](https://cwe.mitre.org/data/definitions/79.html), [CAPEC-63](https://capec.mitre.org/data/definitions/63.html)

A tag opened inside the name of another (`<scr<script>ipt>`, `<<script>`): when a filter
removes the inner `<script>` once, the outer one is left whole. `a < b`, `<3` and `x<<y`
do not match (letters must follow the second `<` and end at a space, `/` or `>`); code
with nested generics (`List<Map<String>>`) does, and is the false positive on a developer
site, which excludes its code fields by target.

### wf-941-170

**Script scheme broken up by control characters or spaces (jav&#x09;ascript:)**

- Set `xss`, phase `head`
- Number `941170` (the log's `ruleId`, go-ftw's `rule_id` and `expect_ids`)
- Targets: `args`, `cookies`, `body`
- Transformations: `url_decode`, `html_decode`, `js_decode`, `remove_nulls`, `lowercase`
- Operator: `regex`:

  ```text
  j[\x01-\x1f]*a[\x01-\x1f]*v[\x01-\x1f]*a[\x01-\x1f]*s[\x01-\x1f]*c[\x01-\x1f]*r[\x01-\x1f]*i[\x01-\x1f]*p[\x01-\x1f]*t[\x01-\x1f]*:|j\s+a\s+v\s+a\s+s\s+c\s+r\s+i\s+p\s+t\s*:|v[\x01-\x1f]*b[\x01-\x1f]*s[\x01-\x1f]*c[\x01-\x1f]*r[\x01-\x1f]*i[\x01-\x1f]*p[\x01-\x1f]*t[\x01-\x1f]*:
  ```
- Prefilter: `:`
- Severity `critical`, score 5, confidence `high`, action `score`
- Tags: `OWASP_A03`, `injection`, `xss`
- References: [CWE-79](https://cwe.mitre.org/data/definitions/79.html), [CAPEC-63](https://capec.mitre.org/data/definitions/63.html), CRS 941210

`javascript:` or `vbscript:` with tabs, newlines or other control characters between the
letters (`java&#x09;script:`, `jav%0aascript:`), which browsers drop inside a URL, or with a
space between every letter: the scheme a filter looking for `javascript:` misses. "java
script course" and "JavaScript basics: part 1" do not match (no colon after the word, or
not every letter apart).

## Set `template`

Set `template` (wf-944-*): server-side template injection and expression language injection.
Template delimiters with a call inside, the Python and Java names a payload climbs through,
Velocity and FreeMarker, and `${jndi:` (Log4Shell), which blocks at once wherever it appears.
OWASP: A03 Injection.

| Rule | Phase | Severity / score | Confidence | Action | Message |
| --- | --- | --- | --- | --- | --- |
| [wf-944-100](#wf-944-100) | head | high / 4 | medium | score | Template expression with a call inside ({{ ( }}, ${ ( }, #{ ( }, <% ( %>) |
| [wf-944-110](#wf-944-110) | head | critical / 5 | high | score | Template engine internals (__class__, __globals__, mro(), lipsum, T(java.lang, freemarker, #set() |
| [wf-944-120](#wf-944-120) | head | critical / 5 | high | block | JNDI lookup (${jndi:) in a parameter, header or the path |

### wf-944-100

**Template expression with a call inside ({{ ( }}, ${ ( }, #{ ( }, <% ( %>)**

- Set `template`, phase `head`
- Number `944100` (the log's `ruleId`, go-ftw's `rule_id` and `expect_ids`)
- Targets: `args`, `cookies`, `body`
- Transformations: `url_decode`, `remove_nulls`, `lowercase`, `compress_whitespace`
- Operator: `regex`:

  ```text
  (?:\{\{|\$\{|#\{|<%)[^}%]{0,200}?\(
  ```
- Prefilter: `{{`, `${`, `#{`, `<%`
- Severity `high`, score 4, confidence `medium`, action `score`
- Tags: `OWASP_A03`, `injection`, `ssti`
- References: [CWE-1336](https://cwe.mitre.org/data/definitions/1336.html), [CWE-917](https://cwe.mitre.org/data/definitions/917.html), [CAPEC-242](https://capec.mitre.org/data/definitions/242.html)

A template or expression delimiter (`{{`, `${`, `#{`, `<%`) with a call inside before it
closes: `{{config.items()}}`, `${7*7}` turned into `${T(java.lang.Runtime)...}`, `#{...}`
in JSF and Spring. High: a CMS or a mail template editor that posts templates with
function calls is the false positive, and excludes its template fields by target.

### wf-944-110

**Template engine internals (__class__, __globals__, mro(), lipsum, T(java.lang, freemarker, #set()**

- Set `template`, phase `head`
- Number `944110` (the log's `ruleId`, go-ftw's `rule_id` and `expect_ids`)
- Targets: `args`, `cookies`, `body`
- Transformations: `url_decode`, `remove_nulls`, `lowercase`, `compress_whitespace`
- Operator: `contains_any`: `__class__`, `__globals__`, `__import__`, `__subclasses__`, `mro(`, `lipsum.`, `cycler.`, `joiner.`, `t(java.lang`, `freemarker`, `#set(`
- Severity `critical`, score 5, confidence `high`, action `score`
- Tags: `OWASP_A03`, `injection`, `ssti`
- References: [CWE-1336](https://cwe.mitre.org/data/definitions/1336.html), [CAPEC-242](https://capec.mitre.org/data/definitions/242.html)

The names a template injection climbs through to reach code: Python's `__class__`,
`__globals__`, `__subclasses__`, `mro()`, Jinja's `lipsum`, `cycler` and `joiner` globals,
Spring EL's `T(java.lang...)`, FreeMarker, Velocity's `#set(`. Critical: one hit refuses.
Python and Java developer content names them; such a site excludes its code fields.

### wf-944-120

**JNDI lookup (${jndi:) in a parameter, header or the path**

- Set `template`, phase `head`
- Number `944120` (the log's `ruleId`, go-ftw's `rule_id` and `expect_ids`)
- Targets: `args`, `cookies`, `headers`, `path_raw`, `body`
- Transformations: `url_decode`, `remove_nulls`, `lowercase`, `compress_whitespace`
- Operator: `contains_any`: `${jndi:`
- Severity `critical`, score 5, confidence `high`, action `block`
- Tags: `OWASP_A03`, `injection`, `jndi`, `log4shell`
- References: [CVE-2021-44228](https://nvd.nist.gov/vuln/detail/CVE-2021-44228), [CWE-917](https://cwe.mitre.org/data/definitions/917.html), [CWE-502](https://cwe.mitre.org/data/definitions/502.html), [CAPEC-242](https://capec.mitre.org/data/definitions/242.html), CRS 944150, <https://logging.apache.org/log4j/2.x/security.html>

Log4Shell (CVE-2021-44228): `${jndi:` in any parameter, header, cookie, the path or the
body, the lookup that makes Log4j 2 before 2.15 load and run a class from an LDAP or RMI
server when it logs the text. Blocks at once wherever it appears, since anything a request
carries may be logged by a backend. Obfuscations that build `jndi` from nested lookups
(`${${lower:j}ndi:`) are not matched by this literal.

## Set `upload`

Set `upload` (wf-960-*): file uploads (the `upload` phase, each multipart part with a
filename). Executable extensions anywhere in the name (double extensions too), names that
traverse or carry control characters, server configuration files, declared script types, a
declared image or PDF whose bytes are something else, a script or PHP tag at the start of a
file, too many parts.
OWASP: A04 Insecure Design (unrestricted file upload). A site that takes only images writes
its own `upload.ext` rule with `action: block` on everything not in its list
(docs/configuration.md, Request filter).

| Rule | Phase | Severity / score | Confidence | Action | Message |
| --- | --- | --- | --- | --- | --- |
| [wf-960-100](#wf-960-100) | upload | high / 4 | high | score | Upload file name with a path separator, .., a null or a control character |
| [wf-960-105](#wf-960-105) | upload | medium / 3 | medium | score | Upload file name over 255 bytes |
| [wf-960-110](#wf-960-110) | upload | critical / 5 | high | block | Executable extension in an uploaded file's name |
| [wf-960-120](#wf-960-120) | upload | critical / 5 | high | block | Server configuration file uploaded (.htaccess, .user.ini, web.config, php.ini) |
| [wf-960-130](#wf-960-130) | upload | critical / 5 | high | score | Uploaded part declared as a PHP or shell script |
| [wf-960-140](#wf-960-140) | upload | high / 4 | medium | score | Uploaded file starts with a PHP tag or a shebang (a polyglot when declared an image or document) |
| [wf-960-150](#wf-960-150) | upload | high / 4 | medium | score | Uploaded file declared an image or PDF whose bytes are not one |
| [wf-960-160](#wf-960-160) | upload | medium / 3 | medium | score | More than 64 file parts in a multipart body |

### wf-960-100

**Upload file name with a path separator, .., a null or a control character**

- Set `upload`, phase `upload`
- Number `960100` (the log's `ruleId`, go-ftw's `rule_id` and `expect_ids`)
- Targets: `upload.filename`
- Transformations: `url_decode`
- Operator: `contains_any`: `/`, `\`, `..`, `\x00`, `\x01`, `\x02`, `\x03`, `\x04`, `\x05`, `\x06`, `\x07`, `\x08`, `\x09`, `\x0a`, `\x0b`, `\x0c`, `\x0d`, `\x0e`, `\x0f`, `\x10`, `\x11`, `\x12`, `\x13`, `\x14`, `\x15`, `\x16`, `\x17`, `\x18`, `\x19`, `\x1a`, `\x1b`, `\x1c`, `\x1d`, `\x1e`, `\x1f`, `\x7f`
- Severity `high`, score 4, confidence `high`, action `score`
- Tags: `OWASP_A04`, `upload`, `traversal`
- References: [CWE-22](https://cwe.mitre.org/data/definitions/22.html), [CAPEC-126](https://capec.mitre.org/data/definitions/126.html)

A file name with `/`, `\`, `..`, a null or a control character: a name meant to be written
outside the upload directory or to cut the extension a check reads. Browsers send the base
name alone. An old Internet Explorer sent the full Windows path (`C:\Users\...`), the
historical false positive.

### wf-960-105

**Upload file name over 255 bytes**

- Set `upload`, phase `upload`
- Number `960105` (the log's `ruleId`, go-ftw's `rule_id` and `expect_ids`)
- Targets: `upload.filename`
- Transformations: none
- Operator: `length_gt: 255`
- Severity `medium`, score 3, confidence `medium`, action `score`
- Tags: `OWASP_A04`, `upload`, `size`
- References: [CWE-20](https://cwe.mitre.org/data/definitions/20.html)

A file name longer than 255 bytes, more than most file systems store: truncation tricks
(a long name cut back to `.php`) and parser stress. Medium; a genuinely long name (a
document title in a non-Latin script, three bytes a character) adds only this.

### wf-960-110

**Executable extension in an uploaded file's name**

- Set `upload`, phase `upload`
- Number `960110` (the log's `ruleId`, go-ftw's `rule_id` and `expect_ids`)
- Targets: `upload.ext`
- Transformations: `url_decode`, `remove_nulls`, `lowercase`
- Operator: `regex`:

  ```text
  ^(?:php[3-8]?|phtml|pht|phar|phps|inc|htaccess|htpasswd|ini|cgi|pl|py|sh|bash|jsp|jspx|asp|aspx|ashx|asmx|cer|soap|exe|dll|bat|cmd|com|scr|vbs|js|hta)(?:[^a-z0-9]|$)
  ```
- Prefilter: `php`, `phtml`, `pht`, `phar`, `phps`, `inc`, `htaccess`, `htpasswd`, `ini`, `cgi`, `pl`, `py`, `sh`, `bash`, `jsp`, `jspx`, `asp`, `aspx`, `ashx`, `asmx`, `cer`, `soap`, `exe`, `dll`, `bat`, `cmd`, `com`, `scr`, `vbs`, `js`, `hta`
- Severity `critical`, score 5, confidence `high`, action `block`
- Tags: `OWASP_A04`, `upload`, `webshell`
- References: [CWE-434](https://cwe.mitre.org/data/definitions/434.html), [CAPEC-650](https://capec.mitre.org/data/definitions/650.html), CRS 933110

An extension a server runs or a client executes (PHP in all its spellings, CGI, Perl,
Python, shell, JSP, ASP.NET, Windows executables and scripts, `.htaccess`, `.ini`, `.js`)
anywhere among the name's suffixes, so `shot.php.jpg`, `a.php;.jpg`, `a.php%00.jpg` and
`a.pHp` count. Blocks at once. A site that accepts code or executables on purpose (a
software repository, a CI artifact upload) excludes the rule on that endpoint.

### wf-960-120

**Server configuration file uploaded (.htaccess, .user.ini, web.config, php.ini)**

- Set `upload`, phase `upload`
- Number `960120` (the log's `ruleId`, go-ftw's `rule_id` and `expect_ids`)
- Targets: `upload.filename`
- Transformations: `url_decode`, `remove_nulls`, `lowercase`
- Operator: `equals_any`: `.htaccess`, `.user.ini`, `web.config`, `php.ini`
- Severity `critical`, score 5, confidence `high`, action `block`
- Tags: `OWASP_A04`, `upload`, `configuration`
- References: [CWE-434](https://cwe.mitre.org/data/definitions/434.html), [CAPEC-650](https://capec.mitre.org/data/definitions/650.html), CRS 932180

A file named `.htaccess`, `.user.ini`, `web.config` or `php.ini`: dropped in an upload
directory, it makes the server run the next upload as code. Blocks at once; no ordinary
upload has these names.

### wf-960-130

**Uploaded part declared as a PHP or shell script**

- Set `upload`, phase `upload`
- Number `960130` (the log's `ruleId`, go-ftw's `rule_id` and `expect_ids`)
- Targets: `upload.type`
- Transformations: `lowercase`, `compress_whitespace`
- Operator: `contains_any`: `application/x-php`, `application/x-httpd-php`, `text/x-php`, `application/x-sh`
- Severity `critical`, score 5, confidence `high`, action `score`
- Tags: `OWASP_A04`, `upload`, `webshell`
- References: [CWE-434](https://cwe.mitre.org/data/definitions/434.html), [CAPEC-650](https://capec.mitre.org/data/definitions/650.html)

A file part whose declared Content-Type is PHP or a shell script. A browser takes the type
from the file's extension, so this is a script upload by name too, or a tool that says
what it sends. A code-hosting upload is the exception, excluded by path.

### wf-960-140

**Uploaded file starts with a PHP tag or a shebang (a polyglot when declared an image or document)**

- Set `upload`, phase `upload`
- Number `960140` (the log's `ruleId`, go-ftw's `rule_id` and `expect_ids`)
- Targets: `upload.head`
- Transformations: none
- Operator: `magic_is`: `php`, `script`
- Severity `high`, score 4, confidence `medium`, action `score`
- Tags: `OWASP_A04`, `upload`, `webshell`, `polyglot`
- References: [CWE-434](https://cwe.mitre.org/data/definitions/434.html), [CAPEC-650](https://capec.mitre.org/data/definitions/650.html)

The file's first bytes (`upload_head`) have a PHP tag anywhere, or start with `#!`: a web
shell, often behind an image header (`GIF89a<?php ...`). High: a text or code upload that
legitimately contains `<?php` or a shell script adds this alone, and wf-960-150 brings the
second hit when the file pretends to be an image.

### wf-960-150

**Uploaded file declared an image or PDF whose bytes are not one**

- Set `upload`, phase `upload`
- Number `960150` (the log's `ruleId`, go-ftw's `rule_id` and `expect_ids`)
- Targets: `upload.head`
- Transformations: none
- Operator: `magic_not`: `png`, `jpeg`, `gif`, `webp`, `pdf`
- Severity `high`, score 4, confidence `medium`, action `score`
- Tags: `OWASP_A04`, `upload`, `mismatch`
- References: [CWE-434](https://cwe.mitre.org/data/definitions/434.html), [CAPEC-650](https://capec.mitre.org/data/definitions/650.html)

A part declared `image/png`, `image/jpeg`, `image/gif`, `image/webp` or `application/pdf`
whose bytes do not start with that format's signature: a script dressed as an image.
Browsers declare the type by extension, so a mislabelled file (a WebP saved as `.jpg`)
matches too; high, so it refuses only with another hit.

### wf-960-160

**More than 64 file parts in a multipart body**

- Set `upload`, phase `upload`
- Number `960160` (the log's `ruleId`, go-ftw's `rule_id` and `expect_ids`)
- Targets: `upload.count`
- Transformations: none
- Operator: `gt: 64`
- Severity `medium`, score 3, confidence `medium`, action `score`
- Tags: `OWASP_A04`, `upload`, `size`
- References: [CWE-770](https://cwe.mitre.org/data/definitions/770.html)

More than 64 files in one request: parser and disk exhaustion. A bulk photo upload can
have more; its endpoint raises `body.multipart_max_parts` and the count by `override`.

## Set `leakage`

Set `leakage` (wf-950-*, the `response` phase): what an upstream should not tell the client.
In the first bytes of a 200 or 5xx response: PHP errors and stack traces, Java and Python
tracebacks, database error messages, directory listings. A match replaces the response by
`response.leak_status` through the site's `handle_errors`. The Server header with a full version
is noted (`log`), not refused; X-Powered-By is not a leak (sites set it on purpose).
OWASP: A05 Security Misconfiguration (verbose errors). The literals are case-sensitive: these
messages are written by the runtimes, not by people.

| Rule | Phase | Severity / score | Confidence | Action | Message |
| --- | --- | --- | --- | --- | --- |
| [wf-950-100](#wf-950-100) | response | critical / 5 | medium | block | PHP error or exception text in the response |
| [wf-950-110](#wf-950-110) | response | high / 4 | medium | block | PHP warning with the file and line in the response |
| [wf-950-120](#wf-950-120) | response | high / 4 | medium | block | Java or Python stack trace in the response |
| [wf-950-130](#wf-950-130) | response | critical / 5 | medium | block | Database error message in the response |
| [wf-950-140](#wf-950-140) | response | critical / 5 | medium | block | Oracle error code (ORA-nnnnn) in the response |
| [wf-950-150](#wf-950-150) | response | high / 4 | high | block | Directory listing in the response |
| [wf-950-900](#wf-950-900) | response | notice / 0 | high | log | Server header with a full version |

### wf-950-100

**PHP error or exception text in the response**

- Set `leakage`, phase `response`
- Number `950100` (the log's `ruleId`, go-ftw's `rule_id` and `expect_ids`)
- Targets: `response.body`
- Transformations: none
- Operator: `contains_any`: `Fatal error:`, `Parse error:`, `Stack trace:`, `Uncaught Exception`, `Uncaught Error`
- Severity `critical`, score 5, confidence `medium`, action `block`
- Tags: `OWASP_A05`, `leakage`, `php`
- References: [CWE-209](https://cwe.mitre.org/data/definitions/209.html), [CAPEC-54](https://capec.mitre.org/data/definitions/54.html), CRS 953100

A PHP fatal or parse error, an uncaught exception or a stack trace in the response body: it
shows file paths, code and sometimes arguments, and tells an attacker which input broke
what. The response is replaced. Medium confidence: a page that writes these words as
content (a blog post about PHP errors, a log viewer) is replaced too, and is excluded by
path.

### wf-950-110

**PHP warning with the file and line in the response**

- Set `leakage`, phase `response`
- Number `950110` (the log's `ruleId`, go-ftw's `rule_id` and `expect_ids`)
- Targets: `response.body`
- Transformations: none
- Operator: `regex`:

  ```text
  Warning:.{1,300}? on line \d+
  ```
- Prefilter: `Warning:`
- Severity `high`, score 4, confidence `medium`, action `block`
- Tags: `OWASP_A05`, `leakage`, `php`
- References: [CWE-209](https://cwe.mitre.org/data/definitions/209.html), [CAPEC-54](https://capec.mitre.org/data/definitions/54.html), CRS 953100

A PHP warning with its file and line (`Warning: ... in /var/www/x.php on line 12`), the
sign of `display_errors` left on. The response is replaced. Documentation pages that quote
such warnings are the false positive.

### wf-950-120

**Java or Python stack trace in the response**

- Set `leakage`, phase `response`
- Number `950120` (the log's `ruleId`, go-ftw's `rule_id` and `expect_ids`)
- Targets: `response.body`
- Transformations: none
- Operator: `contains_any`: `at java.`, `Traceback (most recent call last)`
- Severity `high`, score 4, confidence `medium`, action `block`
- Tags: `OWASP_A05`, `leakage`, `trace`
- References: [CWE-209](https://cwe.mitre.org/data/definitions/209.html), [CAPEC-54](https://capec.mitre.org/data/definitions/54.html), CRS 952110

A Java stack frame (`at java.`) or a Python traceback in the response: a debug error page
in production, with the code's structure and libraries. The response is replaced. A
developer blog or an issue tracker that shows traces is excluded by path.

### wf-950-130

**Database error message in the response**

- Set `leakage`, phase `response`
- Number `950130` (the log's `ruleId`, go-ftw's `rule_id` and `expect_ids`)
- Targets: `response.body`
- Transformations: none
- Operator: `contains_any`: `SQLSTATE[`, `You have an error in your SQL syntax`, `Microsoft OLE DB`, `ODBC Driver`
- Severity `critical`, score 5, confidence `medium`, action `block`
- Tags: `OWASP_A05`, `leakage`, `sql`
- References: [CWE-209](https://cwe.mitre.org/data/definitions/209.html), [CAPEC-54](https://capec.mitre.org/data/definitions/54.html)

A database driver's error text (`SQLSTATE[`, MySQL's syntax error, OLE DB, ODBC) in the
response: the feedback error-based SQL injection reads. Replacing the response takes that
feedback away. Pages about databases that quote these errors are the false positive.

### wf-950-140

**Oracle error code (ORA-nnnnn) in the response**

- Set `leakage`, phase `response`
- Number `950140` (the log's `ruleId`, go-ftw's `rule_id` and `expect_ids`)
- Targets: `response.body`
- Transformations: none
- Operator: `regex`:

  ```text
  ORA-\d{5}
  ```
- Prefilter: `ORA-`
- Severity `critical`, score 5, confidence `medium`, action `block`
- Tags: `OWASP_A05`, `leakage`, `sql`
- References: [CWE-209](https://cwe.mitre.org/data/definitions/209.html), [CAPEC-54](https://capec.mitre.org/data/definitions/54.html), CRS 951120

An Oracle error code (`ORA-01756`) in the response, the Oracle counterpart of wf-950-130.
The pattern is specific; an unrelated `ORA-` followed by five digits (a product code) is
the rare false positive.

### wf-950-150

**Directory listing in the response**

- Set `leakage`, phase `response`
- Number `950150` (the log's `ruleId`, go-ftw's `rule_id` and `expect_ids`)
- Targets: `response.body`
- Transformations: none
- Operator: `contains_any`: `<title>Index of /`, `Directory listing for`
- Severity `high`, score 4, confidence `high`, action `block`
- Tags: `OWASP_A05`, `leakage`, `listing`
- References: [CWE-548](https://cwe.mitre.org/data/definitions/548.html), [CAPEC-127](https://capec.mitre.org/data/definitions/127.html), CRS 950130

An automatic directory listing (Apache's and nginx's `Index of /`, Python's `Directory
listing for`): files the site did not mean to link become browsable. The response is
replaced. A site that lists a download directory on purpose excludes the rule on that
path.

### wf-950-900

**Server header with a full version**

- Set `leakage`, phase `response`
- Number `950900` (the log's `ruleId`, go-ftw's `rule_id` and `expect_ids`)
- Targets: `response.headers.server`
- Transformations: none
- Operator: `regex`:

  ```text
  ^(?:Apache|nginx|Microsoft-IIS|lighttpd|LiteSpeed|Jetty|Apache-Coyote|openresty|gunicorn|uvicorn|Werkzeug|Kestrel)/\d+\.\d+
  ```
- Prefilter: `/`
- Severity `notice`, score 0, confidence `high`, action `log`
- Tags: `OWASP_A05`, `leakage`, `server`
- References: [CWE-200](https://cwe.mitre.org/data/definitions/200.html)

An upstream's Server header with a version (`Apache/2.4.41`), which tells a scanner which
vulnerabilities to try. Written to the log only (`action: log`, score 0): the fix is in
the upstream's configuration, and the line says which upstream to fix.

## Set `cve`

Set `cve` (wf-cve-*): known, exploited vulnerabilities of web products, each by the narrow
signature of its exploit request (a path, a header, a parameter name or value) rather than by
the technique the other sets look for. One rule per CVE, named after it (`wf-cve-2022-22965`; a
second rule for the same CVE gets `-b`), with the advisory, the CWE and the product in its
tags (`cve`, and `spring`, `apache`, `f5`, ...: `disable_tags` turns a product's rules off).
Every rule blocks at once: the signatures are what the public exploits send, not what a
product's own clients do. Log4Shell (CVE-2021-44228) is in the `template` set (wf-944-120).
OWASP: A06 Vulnerable and Outdated Components.

| Rule | Phase | Severity / score | Confidence | Action | Message |
| --- | --- | --- | --- | --- | --- |
| [wf-cve-2014-6271](#wf-cve-2014-6271) | head | critical / 5 | high | block | Shellshock: a bash function definition at the start of a header or parameter (CVE-2014-6271) |
| [wf-cve-2017-5638](#wf-cve-2017-5638) | head | critical / 5 | high | block | Apache Struts 2 OGNL in the Content-Type (CVE-2017-5638) |
| [wf-cve-2017-9841](#wf-cve-2017-9841) | head | critical / 5 | high | block | PHPUnit eval-stdin.php reached over HTTP (CVE-2017-9841) |
| [wf-cve-2018-7600](#wf-cve-2018-7600) | head | critical / 5 | high | block | Drupalgeddon2: a render array property as a parameter name (CVE-2018-7600) |
| [wf-cve-2018-13379](#wf-cve-2018-13379) | head | critical / 5 | high | block | Fortinet FortiOS SSL VPN path traversal in fgt_lang (CVE-2018-13379) |
| [wf-cve-2018-20062](#wf-cve-2018-20062) | head | critical / 5 | high | block | ThinkPHP invokefunction through the router (CVE-2018-20062) |
| [wf-cve-2019-19781](#wf-cve-2019-19781) | head | critical / 5 | high | block | Citrix ADC / Gateway path traversal to /vpns/ (CVE-2019-19781) |
| [wf-cve-2020-5902](#wf-cve-2020-5902) | head | critical / 5 | high | block | F5 BIG-IP TMUI path traversal (..;/ after /tmui/) (CVE-2020-5902) |
| [wf-cve-2021-34473](#wf-cve-2021-34473) | head | critical / 5 | high | block | Microsoft Exchange ProxyShell / ProxyNotShell autodiscover SSRF (CVE-2021-34473, CVE-2022-41040) |
| [wf-cve-2021-41773](#wf-cve-2021-41773) | head | critical / 5 | high | block | Apache HTTP Server 2.4.49 path traversal with an encoded dot (CVE-2021-41773) |
| [wf-cve-2021-42013](#wf-cve-2021-42013) | head | critical / 5 | high | block | Apache HTTP Server 2.4.50 path traversal with a double-encoded dot (CVE-2021-42013) |
| [wf-cve-2022-1388](#wf-cve-2022-1388) | head | critical / 5 | high | block | F5 BIG-IP iControl REST command endpoint (/mgmt/tm/util/bash) (CVE-2022-1388) |
| [wf-cve-2022-22963](#wf-cve-2022-22963) | head | critical / 5 | high | block | Spring Cloud Function routing expression header (CVE-2022-22963) |
| [wf-cve-2022-22965](#wf-cve-2022-22965) | head | critical / 5 | high | block | Spring4Shell: class.module.classLoader in a parameter name (CVE-2022-22965) |
| [wf-cve-2022-26134](#wf-cve-2022-26134) | head | critical / 5 | high | block | Atlassian Confluence OGNL injection in the path (CVE-2022-26134) |
| [wf-cve-2022-42889](#wf-cve-2022-42889) | head | critical / 5 | high | block | Text4Shell: Apache Commons Text script, dns or url lookup (CVE-2022-42889) |
| [wf-cve-2023-46805](#wf-cve-2023-46805) | head | critical / 5 | high | block | Ivanti Connect Secure authentication bypass through /api/v1/totp/user-backup-code/../ (CVE-2023-46805, CVE-2024-21887) |
| [wf-cve-2024-3400](#wf-cve-2024-3400) | head | critical / 5 | high | block | PAN-OS GlobalProtect SESSID cookie with a traversal or a command (CVE-2024-3400) |
| [wf-cve-2024-4577](#wf-cve-2024-4577) | head | critical / 5 | high | block | PHP-CGI argument injection through the query (CVE-2024-4577, CVE-2012-1823) |
| [wf-cve-2024-36401](#wf-cve-2024-36401) | head | critical / 5 | high | block | GeoServer property name evaluated as code (exec(java.lang.Runtime) (CVE-2024-36401) |
| [wf-cve-2025-29927](#wf-cve-2025-29927) | head | critical / 5 | high | block | Next.js middleware bypass: x-middleware-subrequest from a client (CVE-2025-29927) |

### wf-cve-2014-6271

**Shellshock: a bash function definition at the start of a header or parameter (CVE-2014-6271)**

- Set `cve`, phase `head`
- Number `20140006271` (the log's `ruleId`, go-ftw's `rule_id` and `expect_ids`)
- Targets: `headers`, `args`
- Transformations: `url_decode`
- Operator: `regex`:

  ```text
  ^\s*\(\s*\)\s*\{
  ```
- Prefilter: `()`, `( )`
- Severity `critical`, score 5, confidence `high`, action `block`
- Tags: `OWASP_A06`, `cve`, `bash`
- References: [CVE-2014-6271](https://nvd.nist.gov/vuln/detail/CVE-2014-6271), [CWE-78](https://cwe.mitre.org/data/definitions/78.html), [CAPEC-88](https://capec.mitre.org/data/definitions/88.html), CRS 932170, CRS 932171, <https://nvd.nist.gov/vuln/detail/CVE-2014-6271>

Shellshock: bash before 4.3 patch 25 runs what follows a function definition in an
environment variable, and CGI passes every header (and the query) to the script as one.
The exploit puts `() { :; }; command` at the start of the User-Agent, the Referer or a
cookie. The rule matches a header or parameter value that starts with `() {`. No browser or
form sends that; the risk of a false positive is negligible.

### wf-cve-2017-5638

**Apache Struts 2 OGNL in the Content-Type (CVE-2017-5638)**

- Set `cve`, phase `head`
- Number `20170005638` (the log's `ruleId`, go-ftw's `rule_id` and `expect_ids`)
- Targets: `headers.content-type`
- Transformations: none
- Operator: `contains_any`: `%{`, `${`
- Severity `critical`, score 5, confidence `high`, action `block`
- Tags: `OWASP_A06`, `cve`, `struts`
- References: [CVE-2017-5638](https://nvd.nist.gov/vuln/detail/CVE-2017-5638), [CWE-20](https://cwe.mitre.org/data/definitions/20.html), [CWE-917](https://cwe.mitre.org/data/definitions/917.html), [CAPEC-242](https://capec.mitre.org/data/definitions/242.html), <https://cwiki.apache.org/confluence/display/WW/S2-045>

Apache Struts 2 (2.3.5 to 2.3.31, 2.5 to 2.5.10), the Jakarta multipart parser: an invalid
Content-Type is put into an error message that is evaluated as OGNL, so
`Content-Type: %{(#_='multipart/form-data')...}` runs commands (the Equifax breach). The
rule matches `%{` or `${` in the Content-Type, which no media type has.

### wf-cve-2017-9841

**PHPUnit eval-stdin.php reached over HTTP (CVE-2017-9841)**

- Set `cve`, phase `head`
- Number `20170009841` (the log's `ruleId`, go-ftw's `rule_id` and `expect_ids`)
- Targets: `path`
- Transformations: `lowercase`
- Operator: `contains_any`: `/util/php/eval-stdin.php`
- Severity `critical`, score 5, confidence `high`, action `block`
- Tags: `OWASP_A06`, `cve`, `phpunit`
- References: [CVE-2017-9841](https://nvd.nist.gov/vuln/detail/CVE-2017-9841), [CWE-94](https://cwe.mitre.org/data/definitions/94.html), [CAPEC-242](https://capec.mitre.org/data/definitions/242.html), <https://nvd.nist.gov/vuln/detail/CVE-2017-9841>

PHPUnit before 4.8.28 and 5.6.3 ships `src/Util/PHP/eval-stdin.php`, which evaluates the
request body as PHP; a `vendor/` directory published with the site makes it a web shell,
and bots POST `<?php ...` to `/vendor/phpunit/phpunit/src/Util/PHP/eval-stdin.php` and its
variants under other directories. The rule matches the script's path wherever it is (the
scanners set's wf-913-220 covers `/vendor/phpunit` only). No site serves this file on
purpose.

### wf-cve-2018-7600

**Drupalgeddon2: a render array property as a parameter name (CVE-2018-7600)**

- Set `cve`, phase `head`
- Number `20180007600` (the log's `ruleId`, go-ftw's `rule_id` and `expect_ids`)
- Targets: `args_names`
- Transformations: `url_decode`, `lowercase`
- Operator: `contains_any`: `#post_render`, `#pre_render`, `#lazy_builder`, `#access_callback`, `#markup`
- Severity `critical`, score 5, confidence `high`, action `block`
- Tags: `OWASP_A06`, `cve`, `drupal`
- References: [CVE-2018-7600](https://nvd.nist.gov/vuln/detail/CVE-2018-7600), [CWE-20](https://cwe.mitre.org/data/definitions/20.html), [CWE-94](https://cwe.mitre.org/data/definitions/94.html), [CAPEC-242](https://capec.mitre.org/data/definitions/242.html), <https://www.drupal.org/sa-core-2018-002>

Drupal 7 before 7.58 and 8 before 8.5.1 merge request parameters into render arrays, whose
keys starting with `#` are callbacks: `mail[#post_render][]=exec&mail[#markup]=id` on the
registration form runs a command. The rule matches a parameter name, in the query or a
form, with `#post_render`, `#pre_render`, `#lazy_builder`, `#access_callback` or `#markup`.
Browsers never send `#` in a form field's name (Drupal's own forms do not either).

### wf-cve-2018-13379

**Fortinet FortiOS SSL VPN path traversal in fgt_lang (CVE-2018-13379)**

- Set `cve`, phase `head`
- Number `20180013379` (the log's `ruleId`, go-ftw's `rule_id` and `expect_ids`)
- Targets: `args.lang`
- Transformations: `url_decode`, `lowercase`
- Operator: `contains_any`: `/dev/cmdb/`, `sslvpn_websession`
- Severity `critical`, score 5, confidence `high`, action `block`
- Tags: `OWASP_A06`, `cve`, `fortios`
- References: [CVE-2018-13379](https://nvd.nist.gov/vuln/detail/CVE-2018-13379), [CWE-22](https://cwe.mitre.org/data/definitions/22.html), [CAPEC-126](https://capec.mitre.org/data/definitions/126.html), <https://www.fortiguard.com/psirt/FG-IR-18-384>

FortiOS SSL VPN 5.4 to 6.0.4: `/remote/fgt_lang?lang=/../../../..//////////dev/cmdb/sslvpn_websession`
reads the file of active sessions, with user names and passwords in clear. The rule
matches the `lang` parameter naming the configuration database (`/dev/cmdb/`) or the
session file. A language code never looks like this; the traversal itself is also scored
by the traversal set.

### wf-cve-2018-20062

**ThinkPHP invokefunction through the router (CVE-2018-20062)**

- Set `cve`, phase `head`
- Number `20180020062` (the log's `ruleId`, go-ftw's `rule_id` and `expect_ids`)
- Targets: `args`, `path_raw`
- Transformations: `url_decode`, `lowercase`
- Operator: `regex`:

  ```text
  think\\(?:app|container)/invokefunction
  ```
- Prefilter: `invokefunction`
- Severity `critical`, score 5, confidence `high`, action `block`
- Tags: `OWASP_A06`, `cve`, `thinkphp`
- References: [CVE-2018-20062](https://nvd.nist.gov/vuln/detail/CVE-2018-20062), [CWE-94](https://cwe.mitre.org/data/definitions/94.html), [CAPEC-242](https://capec.mitre.org/data/definitions/242.html), <https://nvd.nist.gov/vuln/detail/CVE-2018-20062>

ThinkPHP 5.0 before 5.0.23 and 5.1 before 5.1.31 (and applications built on them, such as
NoneCMS) route `s=/index/\think\app/invokefunction&function=call_user_func_array&vars[0]=system&vars[1][]=id`
to any public method of any class, which runs a command. The rule matches
`think\app/invokefunction` or `think\container/invokefunction` in a parameter or the path,
a controller path no honest link has.

### wf-cve-2019-19781

**Citrix ADC / Gateway path traversal to /vpns/ (CVE-2019-19781)**

- Set `cve`, phase `head`
- Number `20190019781` (the log's `ruleId`, go-ftw's `rule_id` and `expect_ids`)
- Targets: `path_raw`
- Transformations: `url_decode`, `lowercase`
- Operator: `contains_any`: `../vpns/`, `..\vpns/`
- Severity `critical`, score 5, confidence `high`, action `block`
- Tags: `OWASP_A06`, `cve`, `citrix`
- References: [CVE-2019-19781](https://nvd.nist.gov/vuln/detail/CVE-2019-19781), [CWE-22](https://cwe.mitre.org/data/definitions/22.html), [CAPEC-126](https://capec.mitre.org/data/definitions/126.html), <https://support.citrix.com/article/CTX267027>

Citrix ADC and Gateway (NetScaler) before the January 2020 fixes: `POST /vpn/../vpns/portal/scripts/newbm.pl`
reaches a Perl script without authentication, and with an `NSC_USER` header of `../` writes
a template that runs commands when it is fetched. The rule matches `../vpns/` in the path
as sent, after percent-decoding; a client normalizes `..` before sending, so only a crafted
request has it.

### wf-cve-2020-5902

**F5 BIG-IP TMUI path traversal (..;/ after /tmui/) (CVE-2020-5902)**

- Set `cve`, phase `head`
- Number `20200005902` (the log's `ruleId`, go-ftw's `rule_id` and `expect_ids`)
- Targets: `path_raw`
- Transformations: `url_decode`, `lowercase`
- Operator: `regex`:

  ```text
  /tmui/[^?]*\.\.;
  ```
- Prefilter: `..;`
- Severity `critical`, score 5, confidence `high`, action `block`
- Tags: `OWASP_A06`, `cve`, `f5`
- References: [CVE-2020-5902](https://nvd.nist.gov/vuln/detail/CVE-2020-5902), [CWE-22](https://cwe.mitre.org/data/definitions/22.html), [CAPEC-126](https://capec.mitre.org/data/definitions/126.html), <https://my.f5.com/manage/s/article/K52145254>

F5 BIG-IP's Traffic Management User Interface (11.6 to 15.1.0): Tomcat reads `..;/` as
`../`, so `/tmui/login.jsp/..;/tmui/locallb/workspace/fileRead.jsp?fileName=/etc/passwd`
reaches pages behind the login and runs commands. The rule matches `..;` after `/tmui/` in
the path. The traversal set's wf-930-100 also scores `..;/` anywhere.

### wf-cve-2021-34473

**Microsoft Exchange ProxyShell / ProxyNotShell autodiscover SSRF (CVE-2021-34473, CVE-2022-41040)**

- Set `cve`, phase `head`
- Number `20210034473` (the log's `ruleId`, go-ftw's `rule_id` and `expect_ids`)
- Targets: `args`
- Transformations: `url_decode`, `lowercase`
- Operator: `contains_any`: `autodiscover.json?@`
- Severity `critical`, score 5, confidence `high`, action `block`
- Tags: `OWASP_A06`, `cve`, `exchange`
- References: [CVE-2021-34473](https://nvd.nist.gov/vuln/detail/CVE-2021-34473), [CVE-2022-41040](https://nvd.nist.gov/vuln/detail/CVE-2022-41040), [CWE-918](https://cwe.mitre.org/data/definitions/918.html), [CAPEC-664](https://capec.mitre.org/data/definitions/664.html), <https://msrc.microsoft.com/update-guide/vulnerability/CVE-2021-34473>, <https://msrc.microsoft.com/update-guide/vulnerability/CVE-2022-41040>

Microsoft Exchange Server: the autodiscover endpoint takes an `Email` parameter of
`autodiscover/autodiscover.json?@x.com` as a path to proxy to, so
`/autodiscover/autodiscover.json?@x.com/mapi/nspi/?&Email=autodiscover/autodiscover.json%3f@x.com`
reaches the backend as SYSTEM (ProxyShell, chained to remote code execution;
ProxyNotShell, 2022, the same request with `PowerShell` as the protocol). The rule matches
`autodiscover.json?@` in a parameter value, after decoding: no mail client sends it.

### wf-cve-2021-41773

**Apache HTTP Server 2.4.49 path traversal with an encoded dot (CVE-2021-41773)**

- Set `cve`, phase `head`
- Number `20210041773` (the log's `ruleId`, go-ftw's `rule_id` and `expect_ids`)
- Targets: `path_raw`
- Transformations: `lowercase`
- Operator: `contains_any`: `/.%2e/`, `/%2e./`, `/%2e%2e/`
- Severity `critical`, score 5, confidence `high`, action `block`
- Tags: `OWASP_A06`, `cve`, `apache`
- References: [CVE-2021-41773](https://nvd.nist.gov/vuln/detail/CVE-2021-41773), [CWE-22](https://cwe.mitre.org/data/definitions/22.html), [CAPEC-126](https://capec.mitre.org/data/definitions/126.html), CRS 930100, <https://httpd.apache.org/security/vulnerabilities_24.html>

Apache HTTP Server 2.4.49 normalized the path before decoding it, so a dot segment with an
encoded dot (`/.%2e/`) passed: `/cgi-bin/.%2e/.%2e/.%2e/bin/sh` runs a shell with CGI on,
`/icons/.%2e/%2e%2e/%2e%2e/etc/passwd` reads files. The rule matches a segment of two dots
of which at least one is `%2e`, in the path as sent. Clients do not percent-encode a dot,
an unreserved character; the false-positive risk is negligible.

### wf-cve-2021-42013

**Apache HTTP Server 2.4.50 path traversal with a double-encoded dot (CVE-2021-42013)**

- Set `cve`, phase `head`
- Number `20210042013` (the log's `ruleId`, go-ftw's `rule_id` and `expect_ids`)
- Targets: `path_raw`
- Transformations: `lowercase`
- Operator: `contains_any`: `%%32%65`, `%%32e`, `%2%65`
- Severity `critical`, score 5, confidence `high`, action `block`
- Tags: `OWASP_A06`, `cve`, `apache`
- References: [CVE-2021-42013](https://nvd.nist.gov/vuln/detail/CVE-2021-42013), [CWE-22](https://cwe.mitre.org/data/definitions/22.html), [CAPEC-126](https://capec.mitre.org/data/definitions/126.html), <https://httpd.apache.org/security/vulnerabilities_24.html>

Apache HTTP Server 2.4.50's fix of CVE-2021-41773 decoded once more and was bypassed by
encoding the escape itself: `%%32%65` (and `%%32e`, `%2%65`) becomes `%2e`, then `.`, as in
`/cgi-bin/.%%32%65/.%%32%65/bin/sh`. The rule matches those sequences in the path as sent,
which are not even valid percent-encoding: no client produces them.

### wf-cve-2022-1388

**F5 BIG-IP iControl REST command endpoint (/mgmt/tm/util/bash) (CVE-2022-1388)**

- Set `cve`, phase `head`
- Number `20220001388` (the log's `ruleId`, go-ftw's `rule_id` and `expect_ids`)
- Targets: `path`
- Transformations: `lowercase`
- Operator: `contains_any`: `/mgmt/tm/util/bash`
- Severity `critical`, score 5, confidence `high`, action `block`
- Tags: `OWASP_A06`, `cve`, `f5`
- References: [CVE-2022-1388](https://nvd.nist.gov/vuln/detail/CVE-2022-1388), [CVE-2021-22986](https://nvd.nist.gov/vuln/detail/CVE-2021-22986), [CWE-306](https://cwe.mitre.org/data/definitions/306.html), <https://my.f5.com/manage/s/article/K23605346>

F5 BIG-IP iControl REST: a request with `Connection: X-F5-Auth-Token` and an empty token
passes authentication (CVE-2022-1388; CVE-2021-22986 before it was another bypass) and
`POST /mgmt/tm/util/bash` with `{"command":"run","utilCmdArgs":"-c id"}` runs a command
as root. The rule matches the command endpoint's path, which is the target of both
exploits. The management interface should never be behind a public site; one that does
proxy it for its administrators excludes the rule on `/mgmt/*`.

### wf-cve-2022-22963

**Spring Cloud Function routing expression header (CVE-2022-22963)**

- Set `cve`, phase `head`
- Number `20220022963` (the log's `ruleId`, go-ftw's `rule_id` and `expect_ids`)
- Targets: `headers.spring.cloud.function.routing-expression`
- Transformations: none
- Operator: `exists`
- Severity `critical`, score 5, confidence `high`, action `block`
- Tags: `OWASP_A06`, `cve`, `spring`
- References: [CVE-2022-22963](https://nvd.nist.gov/vuln/detail/CVE-2022-22963), [CWE-917](https://cwe.mitre.org/data/definitions/917.html), [CAPEC-242](https://capec.mitre.org/data/definitions/242.html), <https://spring.io/security/cve-2022-22963>

Spring Cloud Function 3.1.6, 3.2.2 and older evaluate the
`spring.cloud.function.routing-expression` header as SpEL, so
`T(java.lang.Runtime).getRuntime().exec("id")` in it runs a command on a POST to
`/functionRouter`. The rule matches the header's presence: routing by a client-sent
expression is what the fix took away, and a client of an application that still relies on
it is excluded by path.

### wf-cve-2022-22965

**Spring4Shell: class.module.classLoader in a parameter name (CVE-2022-22965)**

- Set `cve`, phase `head`
- Number `20220022965` (the log's `ruleId`, go-ftw's `rule_id` and `expect_ids`)
- Targets: `args_names`
- Transformations: `url_decode`, `lowercase`
- Operator: `contains_any`: `class.module.classloader`
- Severity `critical`, score 5, confidence `high`, action `block`
- Tags: `OWASP_A06`, `cve`, `spring`
- References: [CVE-2022-22965](https://nvd.nist.gov/vuln/detail/CVE-2022-22965), [CWE-94](https://cwe.mitre.org/data/definitions/94.html), [CAPEC-242](https://capec.mitre.org/data/definitions/242.html), CRS 944260, <https://spring.io/security/cve-2022-22965>

Spring Framework 5.3.0 to 5.3.17 and 5.2.0 to 5.2.19 on JDK 9+: data binding follows
`class.module.classLoader...` from a parameter name to Tomcat's access log valve, and the
exploit rewrites it to write a JSP web shell
(`class.module.classLoader.resources.context.parent.pipeline.first.pattern=...`). The rule
matches a parameter name, in the query or a form, with `class.module.classLoader`; no form
field is named so.

### wf-cve-2022-26134

**Atlassian Confluence OGNL injection in the path (CVE-2022-26134)**

- Set `cve`, phase `head`
- Number `20220026134` (the log's `ruleId`, go-ftw's `rule_id` and `expect_ids`)
- Targets: `path_raw`
- Transformations: `url_decode`, `lowercase`
- Operator: `regex`:

  ```text
  \$\{[^}]{0,500}?[(@#]
  ```
- Prefilter: `${`
- Severity `critical`, score 5, confidence `high`, action `block`
- Tags: `OWASP_A06`, `cve`, `confluence`
- References: [CVE-2022-26134](https://nvd.nist.gov/vuln/detail/CVE-2022-26134), [CWE-917](https://cwe.mitre.org/data/definitions/917.html), [CAPEC-242](https://capec.mitre.org/data/definitions/242.html), <https://nvd.nist.gov/vuln/detail/CVE-2022-26134>

Atlassian Confluence Server and Data Center before 7.4.17, 7.13.7, 7.14.3, 7.15.2, 7.16.4,
7.17.4 and 7.18.1 evaluate the namespace of a request path as OGNL without
authentication: `/${(#a=@java.lang.Runtime@getRuntime().exec("id"))}/`, percent-encoded,
runs a command. The rule matches `${` followed by `(`, `@` or `#` in the decoded path.
A front end that requests an unfilled template literally (`/user/${id}`) has no `(`, `@` or
`#` there and is not matched.

### wf-cve-2022-42889

**Text4Shell: Apache Commons Text script, dns or url lookup (CVE-2022-42889)**

- Set `cve`, phase `head`
- Number `20220042889` (the log's `ruleId`, go-ftw's `rule_id` and `expect_ids`)
- Targets: `args`, `cookies`, `headers`, `body`
- Transformations: `url_decode`, `remove_nulls`, `lowercase`, `compress_whitespace`
- Operator: `contains_any`: `${script:`, `${dns:`, `${url:`
- Severity `critical`, score 5, confidence `high`, action `block`
- Tags: `OWASP_A06`, `cve`, `commons-text`
- References: [CVE-2022-42889](https://nvd.nist.gov/vuln/detail/CVE-2022-42889), [CWE-94](https://cwe.mitre.org/data/definitions/94.html), [CAPEC-242](https://capec.mitre.org/data/definitions/242.html), <https://nvd.nist.gov/vuln/detail/CVE-2022-42889>

Apache Commons Text 1.5 to 1.9 interpolate `${prefix:...}` in strings passed to
`StringSubstitutor`, and the `script` lookup runs JavaScript
(`${script:javascript:java.lang.Runtime.getRuntime().exec('id')}`), `dns` and `url` reach
out. The rule matches the three lookups in a parameter, a cookie, a header or the body.
Template syntax of this form is not in honest values.

### wf-cve-2023-46805

**Ivanti Connect Secure authentication bypass through /api/v1/totp/user-backup-code/../ (CVE-2023-46805, CVE-2024-21887)**

- Set `cve`, phase `head`
- Number `20230046805` (the log's `ruleId`, go-ftw's `rule_id` and `expect_ids`)
- Targets: `path_raw`
- Transformations: `url_decode`, `lowercase`
- Operator: `contains_any`: `/api/v1/totp/user-backup-code/..`
- Severity `critical`, score 5, confidence `high`, action `block`
- Tags: `OWASP_A06`, `cve`, `ivanti`
- References: [CVE-2023-46805](https://nvd.nist.gov/vuln/detail/CVE-2023-46805), [CVE-2024-21887](https://nvd.nist.gov/vuln/detail/CVE-2024-21887), [CWE-287](https://cwe.mitre.org/data/definitions/287.html), [CWE-77](https://cwe.mitre.org/data/definitions/77.html), [CAPEC-126](https://capec.mitre.org/data/definitions/126.html), <https://nvd.nist.gov/vuln/detail/CVE-2023-46805>, <https://nvd.nist.gov/vuln/detail/CVE-2024-21887>

Ivanti Connect Secure and Policy Secure 9.x and 22.x: the unauthenticated
`/api/v1/totp/user-backup-code/` prefix followed by `../` reaches the authenticated REST
API (CVE-2023-46805), where `/api/v1/license/keys-status/;command` injects a command
(CVE-2024-21887); the two were chained in mass exploitation in 2024. The rule matches the
traversal out of the backup-code prefix in the path as sent.

### wf-cve-2024-3400

**PAN-OS GlobalProtect SESSID cookie with a traversal or a command (CVE-2024-3400)**

- Set `cve`, phase `head`
- Number `20240003400` (the log's `ruleId`, go-ftw's `rule_id` and `expect_ids`)
- Targets: `cookies.SESSID`
- Transformations: `url_decode`, `lowercase`
- Operator: `contains_any`: `../`, `..\`, `` ` ``, `$(`, `${ifs}`
- Severity `critical`, score 5, confidence `high`, action `block`
- Tags: `OWASP_A06`, `cve`, `panos`
- References: [CVE-2024-3400](https://nvd.nist.gov/vuln/detail/CVE-2024-3400), [CWE-77](https://cwe.mitre.org/data/definitions/77.html), [CWE-22](https://cwe.mitre.org/data/definitions/22.html), [CAPEC-88](https://capec.mitre.org/data/definitions/88.html), <https://security.paloaltonetworks.com/CVE-2024-3400>

Palo Alto Networks PAN-OS 10.2, 11.0 and 11.1 with GlobalProtect: the `SESSID` cookie is
used as a file name, so a `SESSID` of `/../../../opt/panlogs/tmp/device_telemetry/minute/`
and a name with a command in backticks creates a file whose name the telemetry job runs.
The rule matches `../`, a backtick, `$(` or `${IFS}` in a cookie named `SESSID`; a session
id is hex or base64.

### wf-cve-2024-4577

**PHP-CGI argument injection through the query (CVE-2024-4577, CVE-2012-1823)**

- Set `cve`, phase `head`
- Number `20240004577` (the log's `ruleId`, go-ftw's `rule_id` and `expect_ids`)
- Targets: `query`
- Transformations: `lowercase`
- Operator: `regex`:

  ```text
  (?:^|\+|%20)(?:%ad|-)d(?:\+|%20)+(?:allow_url_include|auto_prepend_file|auto_append_file|safe_mode|open_basedir|disable_functions|cgi\.force_redirect|register_argc_argv)
  ```
- Prefilter: `allow_url_include`, `auto_prepend_file`, `auto_append_file`, `safe_mode`, `open_basedir`, `disable_functions`, `cgi.force_redirect`, `register_argc_argv`
- Severity `critical`, score 5, confidence `high`, action `block`
- Tags: `OWASP_A06`, `cve`, `php`
- References: [CVE-2024-4577](https://nvd.nist.gov/vuln/detail/CVE-2024-4577), [CVE-2012-1823](https://nvd.nist.gov/vuln/detail/CVE-2012-1823), [CWE-78](https://cwe.mitre.org/data/definitions/78.html), [CAPEC-88](https://capec.mitre.org/data/definitions/88.html), <https://nvd.nist.gov/vuln/detail/CVE-2024-4577>

PHP in CGI mode takes a query without `=` as command-line arguments (CVE-2012-1823); on
Windows with some code pages a soft hyphen (`%AD`) is read as `-`, past the fix
(CVE-2024-4577, PHP before 8.1.29, 8.2.20, 8.3.8). `?%ADd+allow_url_include%3d1+%ADd+auto_prepend_file%3dphp://input`
then runs the body as PHP. The rule matches `-d` or `%ADd` followed by one of the ini
directives these exploits set, in the query as sent.

### wf-cve-2024-36401

**GeoServer property name evaluated as code (exec(java.lang.Runtime) (CVE-2024-36401)**

- Set `cve`, phase `head`
- Number `20240036401` (the log's `ruleId`, go-ftw's `rule_id` and `expect_ids`)
- Targets: `args`, `body`
- Transformations: `url_decode`, `lowercase`, `compress_whitespace`
- Operator: `contains_any`: `exec(java.lang.runtime`
- Severity `critical`, score 5, confidence `high`, action `block`
- Tags: `OWASP_A06`, `cve`, `geoserver`
- References: [CVE-2024-36401](https://nvd.nist.gov/vuln/detail/CVE-2024-36401), [CWE-95](https://cwe.mitre.org/data/definitions/95.html), [CAPEC-242](https://capec.mitre.org/data/definitions/242.html), <https://nvd.nist.gov/vuln/detail/CVE-2024-36401>

GeoServer before 2.23.6, 2.24.4 and 2.25.2 evaluates the property names of OGC requests
(WFS `valueReference`, `propertyName`) as XPath through commons-jxpath, which calls Java:
`valueReference=exec(java.lang.Runtime.getRuntime(),'id')` runs a command, in a GET's
query or a POSTed XML request. The rule matches `exec(java.lang.Runtime` in a parameter or
the body; a feature property is never called so.

### wf-cve-2025-29927

**Next.js middleware bypass: x-middleware-subrequest from a client (CVE-2025-29927)**

- Set `cve`, phase `head`
- Number `20250029927` (the log's `ruleId`, go-ftw's `rule_id` and `expect_ids`)
- Targets: `headers.x-middleware-subrequest`
- Transformations: none
- Operator: `exists`
- Severity `critical`, score 5, confidence `high`, action `block`
- Tags: `OWASP_A06`, `cve`, `nextjs`
- References: [CVE-2025-29927](https://nvd.nist.gov/vuln/detail/CVE-2025-29927), [CWE-285](https://cwe.mitre.org/data/definitions/285.html), <https://nvd.nist.gov/vuln/detail/CVE-2025-29927>

Next.js before 12.3.5, 13.5.9, 14.2.25 and 15.2.3 skips its middleware, where many sites
check authentication, for a request with the internal `x-middleware-subrequest` header
(`x-middleware-subrequest: middleware:middleware:middleware:middleware:middleware`). The
rule matches the header's presence: Next.js sets it on its own internal requests, never a
browser, and those do not pass through the proxy in front.

## Index by CVE

| CVE | Rules |
| --- | --- |
| [CVE-2012-1823](https://nvd.nist.gov/vuln/detail/CVE-2012-1823) | [wf-cve-2024-4577](#wf-cve-2024-4577) |
| [CVE-2014-6271](https://nvd.nist.gov/vuln/detail/CVE-2014-6271) | [wf-cve-2014-6271](#wf-cve-2014-6271) |
| [CVE-2017-5638](https://nvd.nist.gov/vuln/detail/CVE-2017-5638) | [wf-cve-2017-5638](#wf-cve-2017-5638) |
| [CVE-2017-9841](https://nvd.nist.gov/vuln/detail/CVE-2017-9841) | [wf-cve-2017-9841](#wf-cve-2017-9841) |
| [CVE-2018-7600](https://nvd.nist.gov/vuln/detail/CVE-2018-7600) | [wf-cve-2018-7600](#wf-cve-2018-7600) |
| [CVE-2018-13379](https://nvd.nist.gov/vuln/detail/CVE-2018-13379) | [wf-cve-2018-13379](#wf-cve-2018-13379) |
| [CVE-2018-20062](https://nvd.nist.gov/vuln/detail/CVE-2018-20062) | [wf-cve-2018-20062](#wf-cve-2018-20062) |
| [CVE-2019-19781](https://nvd.nist.gov/vuln/detail/CVE-2019-19781) | [wf-cve-2019-19781](#wf-cve-2019-19781) |
| [CVE-2020-5902](https://nvd.nist.gov/vuln/detail/CVE-2020-5902) | [wf-cve-2020-5902](#wf-cve-2020-5902) |
| [CVE-2021-22986](https://nvd.nist.gov/vuln/detail/CVE-2021-22986) | [wf-cve-2022-1388](#wf-cve-2022-1388) |
| [CVE-2021-34473](https://nvd.nist.gov/vuln/detail/CVE-2021-34473) | [wf-cve-2021-34473](#wf-cve-2021-34473) |
| [CVE-2021-41773](https://nvd.nist.gov/vuln/detail/CVE-2021-41773) | [wf-cve-2021-41773](#wf-cve-2021-41773) |
| [CVE-2021-42013](https://nvd.nist.gov/vuln/detail/CVE-2021-42013) | [wf-cve-2021-42013](#wf-cve-2021-42013) |
| [CVE-2021-44228](https://nvd.nist.gov/vuln/detail/CVE-2021-44228) | [wf-944-120](#wf-944-120) |
| [CVE-2022-1388](https://nvd.nist.gov/vuln/detail/CVE-2022-1388) | [wf-cve-2022-1388](#wf-cve-2022-1388) |
| [CVE-2022-22963](https://nvd.nist.gov/vuln/detail/CVE-2022-22963) | [wf-cve-2022-22963](#wf-cve-2022-22963) |
| [CVE-2022-22965](https://nvd.nist.gov/vuln/detail/CVE-2022-22965) | [wf-cve-2022-22965](#wf-cve-2022-22965) |
| [CVE-2022-26134](https://nvd.nist.gov/vuln/detail/CVE-2022-26134) | [wf-cve-2022-26134](#wf-cve-2022-26134) |
| [CVE-2022-41040](https://nvd.nist.gov/vuln/detail/CVE-2022-41040) | [wf-cve-2021-34473](#wf-cve-2021-34473) |
| [CVE-2022-42889](https://nvd.nist.gov/vuln/detail/CVE-2022-42889) | [wf-cve-2022-42889](#wf-cve-2022-42889) |
| [CVE-2023-46805](https://nvd.nist.gov/vuln/detail/CVE-2023-46805) | [wf-cve-2023-46805](#wf-cve-2023-46805) |
| [CVE-2024-3400](https://nvd.nist.gov/vuln/detail/CVE-2024-3400) | [wf-cve-2024-3400](#wf-cve-2024-3400) |
| [CVE-2024-4577](https://nvd.nist.gov/vuln/detail/CVE-2024-4577) | [wf-cve-2024-4577](#wf-cve-2024-4577) |
| [CVE-2024-21887](https://nvd.nist.gov/vuln/detail/CVE-2024-21887) | [wf-cve-2023-46805](#wf-cve-2023-46805) |
| [CVE-2024-36401](https://nvd.nist.gov/vuln/detail/CVE-2024-36401) | [wf-cve-2024-36401](#wf-cve-2024-36401) |
| [CVE-2025-29927](https://nvd.nist.gov/vuln/detail/CVE-2025-29927) | [wf-cve-2025-29927](#wf-cve-2025-29927) |

## Index by CWE

| CWE | Weakness | Rules |
| --- | --- | --- |
| [CWE-15](https://cwe.mitre.org/data/definitions/15.html) | External Control of System or Configuration Setting | [wf-933-130](#wf-933-130) |
| [CWE-20](https://cwe.mitre.org/data/definitions/20.html) | Improper Input Validation | [wf-920-110](#wf-920-110), [wf-920-120](#wf-920-120), [wf-920-300](#wf-920-300), [wf-920-310](#wf-920-310), [wf-920-400](#wf-920-400), [wf-920-410](#wf-920-410), [wf-933-150](#wf-933-150), [wf-960-105](#wf-960-105), [wf-cve-2017-5638](#wf-cve-2017-5638), [wf-cve-2018-7600](#wf-cve-2018-7600) |
| [CWE-22](https://cwe.mitre.org/data/definitions/22.html) | Path Traversal | [wf-920-160](#wf-920-160), [wf-930-100](#wf-930-100), [wf-930-110](#wf-930-110), [wf-930-120](#wf-930-120), [wf-960-100](#wf-960-100), [wf-cve-2018-13379](#wf-cve-2018-13379), [wf-cve-2019-19781](#wf-cve-2019-19781), [wf-cve-2020-5902](#wf-cve-2020-5902), [wf-cve-2021-41773](#wf-cve-2021-41773), [wf-cve-2021-42013](#wf-cve-2021-42013), [wf-cve-2024-3400](#wf-cve-2024-3400) |
| [CWE-77](https://cwe.mitre.org/data/definitions/77.html) | Command Injection | [wf-cve-2023-46805](#wf-cve-2023-46805), [wf-cve-2024-3400](#wf-cve-2024-3400) |
| [CWE-78](https://cwe.mitre.org/data/definitions/78.html) | OS Command Injection | [wf-932-100](#wf-932-100), [wf-932-110](#wf-932-110), [wf-932-120](#wf-932-120), [wf-cve-2014-6271](#wf-cve-2014-6271), [wf-cve-2024-4577](#wf-cve-2024-4577) |
| [CWE-79](https://cwe.mitre.org/data/definitions/79.html) | Cross-site Scripting | [wf-941-100](#wf-941-100), [wf-941-110](#wf-941-110), [wf-941-120](#wf-941-120), [wf-941-130](#wf-941-130), [wf-941-140](#wf-941-140), [wf-941-150](#wf-941-150), [wf-941-160](#wf-941-160), [wf-941-170](#wf-941-170) |
| [CWE-89](https://cwe.mitre.org/data/definitions/89.html) | SQL Injection | [wf-942-100](#wf-942-100), [wf-942-110](#wf-942-110), [wf-942-120](#wf-942-120), [wf-942-130](#wf-942-130), [wf-942-140](#wf-942-140), [wf-942-150](#wf-942-150), [wf-942-160](#wf-942-160), [wf-942-170](#wf-942-170), [wf-942-180](#wf-942-180), [wf-942-190](#wf-942-190), [wf-942-200](#wf-942-200) |
| [CWE-94](https://cwe.mitre.org/data/definitions/94.html) | Code Injection | [wf-933-100](#wf-933-100), [wf-933-110](#wf-933-110), [wf-cve-2017-9841](#wf-cve-2017-9841), [wf-cve-2018-7600](#wf-cve-2018-7600), [wf-cve-2018-20062](#wf-cve-2018-20062), [wf-cve-2022-22965](#wf-cve-2022-22965), [wf-cve-2022-42889](#wf-cve-2022-42889) |
| [CWE-95](https://cwe.mitre.org/data/definitions/95.html) | Eval Injection | [wf-933-115](#wf-933-115), [wf-cve-2024-36401](#wf-cve-2024-36401) |
| [CWE-98](https://cwe.mitre.org/data/definitions/98.html) | PHP Remote File Inclusion | [wf-930-120](#wf-930-120), [wf-931-100](#wf-931-100), [wf-933-120](#wf-933-120) |
| [CWE-158](https://cwe.mitre.org/data/definitions/158.html) | Improper Neutralization of Null Byte | [wf-920-140](#wf-920-140) |
| [CWE-174](https://cwe.mitre.org/data/definitions/174.html) | Double Decoding of the Same Data | [wf-920-150](#wf-920-150) |
| [CWE-176](https://cwe.mitre.org/data/definitions/176.html) | Improper Handling of Unicode Encoding | [wf-920-130](#wf-920-130) |
| [CWE-200](https://cwe.mitre.org/data/definitions/200.html) | Exposure of Sensitive Information | [wf-913-100](#wf-913-100), [wf-913-200](#wf-913-200), [wf-913-220](#wf-913-220), [wf-950-900](#wf-950-900) |
| [CWE-209](https://cwe.mitre.org/data/definitions/209.html) | Error Message Containing Sensitive Information | [wf-950-100](#wf-950-100), [wf-950-110](#wf-950-110), [wf-950-120](#wf-950-120), [wf-950-130](#wf-950-130), [wf-950-140](#wf-950-140) |
| [CWE-285](https://cwe.mitre.org/data/definitions/285.html) | Improper Authorization | [wf-cve-2025-29927](#wf-cve-2025-29927) |
| [CWE-287](https://cwe.mitre.org/data/definitions/287.html) | Improper Authentication | [wf-cve-2023-46805](#wf-cve-2023-46805) |
| [CWE-306](https://cwe.mitre.org/data/definitions/306.html) | Missing Authentication for Critical Function | [wf-cve-2022-1388](#wf-cve-2022-1388) |
| [CWE-307](https://cwe.mitre.org/data/definitions/307.html) | Improper Restriction of Excessive Authentication Attempts | [wf-913-200](#wf-913-200) |
| [CWE-400](https://cwe.mitre.org/data/definitions/400.html) | Uncontrolled Resource Consumption | [wf-920-180](#wf-920-180), [wf-920-190](#wf-920-190), [wf-920-200](#wf-920-200), [wf-920-210](#wf-920-210), [wf-920-440](#wf-920-440) |
| [CWE-434](https://cwe.mitre.org/data/definitions/434.html) | Unrestricted Upload of File with Dangerous Type | [wf-960-110](#wf-960-110), [wf-960-120](#wf-960-120), [wf-960-130](#wf-960-130), [wf-960-140](#wf-960-140), [wf-960-150](#wf-960-150) |
| [CWE-444](https://cwe.mitre.org/data/definitions/444.html) | HTTP Request Smuggling | [wf-920-170](#wf-920-170) |
| [CWE-502](https://cwe.mitre.org/data/definitions/502.html) | Deserialization of Untrusted Data | [wf-933-140](#wf-933-140), [wf-944-120](#wf-944-120) |
| [CWE-527](https://cwe.mitre.org/data/definitions/527.html) | Exposure of Version-Control Repository | [wf-913-210](#wf-913-210) |
| [CWE-530](https://cwe.mitre.org/data/definitions/530.html) | Exposure of Backup File | [wf-913-230](#wf-913-230) |
| [CWE-538](https://cwe.mitre.org/data/definitions/538.html) | Sensitive Information in an Externally-Accessible File | [wf-913-210](#wf-913-210) |
| [CWE-548](https://cwe.mitre.org/data/definitions/548.html) | Exposure of Information Through Directory Listing | [wf-950-150](#wf-950-150) |
| [CWE-650](https://cwe.mitre.org/data/definitions/650.html) | Trusting HTTP Permission Methods on the Server Side | [wf-920-100](#wf-920-100) |
| [CWE-674](https://cwe.mitre.org/data/definitions/674.html) | Uncontrolled Recursion | [wf-920-520](#wf-920-520) |
| [CWE-770](https://cwe.mitre.org/data/definitions/770.html) | Allocation of Resources Without Limits or Throttling | [wf-920-220](#wf-920-220), [wf-920-230](#wf-920-230), [wf-960-160](#wf-960-160) |
| [CWE-917](https://cwe.mitre.org/data/definitions/917.html) | Expression Language Injection | [wf-944-100](#wf-944-100), [wf-944-120](#wf-944-120), [wf-cve-2017-5638](#wf-cve-2017-5638), [wf-cve-2022-22963](#wf-cve-2022-22963), [wf-cve-2022-26134](#wf-cve-2022-26134) |
| [CWE-918](https://cwe.mitre.org/data/definitions/918.html) | Server-Side Request Forgery | [wf-931-100](#wf-931-100), [wf-931-110](#wf-931-110), [wf-cve-2021-34473](#wf-cve-2021-34473) |
| [CWE-1336](https://cwe.mitre.org/data/definitions/1336.html) | Template Injection | [wf-944-100](#wf-944-100), [wf-944-110](#wf-944-110) |
