# The OWASP CRS in the request filter

`webfast-ngfw-crs` runs the [OWASP Core Rule Set](https://coreruleset.org/) v4 inside webfast's
request filter (docs/ngfw.md): the CRS's rules in SecLang, as the CRS releases them, read at
load and run by an interpreter of this crate, plugged into the filter as a rule engine
(webfast-ngfw's src/plugin.rs). There is no ModSecurity or Coraza underneath: the SecLang the
CRS uses — its directives, variables, operators, transformations and actions — is implemented
here, and the CRS's own regression tests (go-ftw) are the measure of how close it is.

The webfast binary has it with its cargo feature `ngfw-crs` (not a default): built so, the filter
runs the CRS whenever its file is loaded (`WEB_NGFW_CONFIG`), unless the file says
`engines: { crs: false }`.

## What runs

- **The CRS bundled**, a pinned release (crs/rules, now 4.30.0, Apache-2.0, crs/LICENSE): its
  request rules, `REQUEST-901` to `REQUEST-944` and `REQUEST-999`, and the data files they read.
  The blocking evaluation (`REQUEST-949`) is not loaded: the filter decides. The response rules
  (`RESPONSE-95x`, phases 3 and 4) are not loaded in this version.
- **Phase 1** runs in the filter's `head` phase, **phase 2** in its `body` phase — on a request
  without a body (or one whose type `body.types` does not list) at the end of the head, with no
  body, as ModSecurity runs phase 2 with an empty one.
- **The decision is the filter's.** What a rule adds to the CRS's inbound anomaly score at the
  blocking paranoia level (`tx.inbound_anomaly_score_pl1` up to the level) is its hit's score:
  the CRS's critical is 5, error 4, warning 3, notice 2, against the filter's `threshold` (5, as
  the CRS's `inbound_anomaly_score_threshold`), under the file's `mode` (`block`, `log_only`,
  `challenge`). A rule with `deny` refuses at once; `allow` lets the request through the rest. A
  rule above the blocking level (with `detection_paranoia` higher) is written with no score.
- **The built-in sets** of the filter are off while the CRS is on, but `cve`: the CRS numbers its
  rules as they do (942100 is the CRS's and wf-942-100's `ruleId`). `rules.builtin` given is as
  written: both may run, a hit of each written with its own id.
- **The log** is the filter's line: each CRS hit with `id` and `ruleId` the CRS rule's number,
  `set` `crs-942` (its file), its `severity`, `tags` and `msg`, the variable it matched in
  (`ARGS:q`, `REQUEST_HEADERS:user-agent`) as `target`, and what matched (the capture, or the
  value after the rule's transformations) cut to `log.matched`.

## Configuration

```yaml
engines:
  crs:
    paranoia: 1               # the blocking paranoia level, 1 to 4
    detection_paranoia: 2     # rules up to this level are written, not scored (default: paranoia)
    tx:                       # the CRS's variables, as crs-setup.conf sets them
      allowed_methods: GET HEAD POST OPTIONS
      max_num_args: 255
      arg_length: 400
    before: [crs/before.conf] # the site's SecLang, read before the CRS (exclusions by `ctl`)
    after: [crs/after.conf]   # read after it (SecRuleRemoveById, SecRuleUpdateTargetById)
    remove: [920350, '942100-942199']   # rules removed, by id or range
```

Every key is optional; `engines: { crs: {} }` and no `engines` at all are the same. `tx` sets any
of the CRS's own variables (`crs-setup.conf.example` lists them; the CRS's initialization rules
give the rest their defaults); `crs_setup_version`, `blocking_paranoia_level` and
`detection_paranoia_level` are the engine's to set. The files of `before` and `after` are
relative to the filter's file, as are data files their rules name that are not the CRS's.

**Exclusions** are written as for ModSecurity, in the site's own SecLang: a rule in `before` with
`ctl:ruleRemoveById`, `ctl:ruleRemoveTargetById` or `ctl:ruleRemoveByTag` for the request it
matches (the CRS's `REQUEST-900-EXCLUSION-RULES-BEFORE-CRS`); `SecRuleRemoveById`,
`SecRuleRemoveByTag`, `SecRuleUpdateTargetById` and `SecRuleUpdateTargetByTag` in `after` (its
`RESPONSE-999-EXCLUSION-RULES-AFTER-CRS`). The filter's own `rules.disable`, `override` and
`exclusions` are its built-in rules', not the CRS's.

## The SecLang supported

What the CRS uses, and the rest of the request phases' common language:

- **Directives**: `SecRule`, `SecAction`, `SecMarker`, `SecDefaultAction` (its transformations),
  `SecRuleRemoveById`, `SecRuleRemoveByTag`, `SecRuleRemoveByMsg`, `SecRuleUpdateTargetById`,
  `SecRuleUpdateTargetByTag`, `SecRuleUpdateActionById`. The engine's configuration
  (`SecRuleEngine`, `SecRequestBodyAccess`, the limits, the audit log) is webfast's: those are read
  and left without effect, and `validate` lists them. Any other directive is an error.
- **Variables**: `ARGS`, `ARGS_NAMES`, `ARGS_GET(_NAMES)`, `ARGS_POST(_NAMES)`,
  `ARGS_COMBINED_SIZE`, `REQUEST_HEADERS(_NAMES)`, `REQUEST_COOKIES(_NAMES)`, `REQUEST_FILENAME`,
  `REQUEST_BASENAME`, `REQUEST_URI`, `REQUEST_URI_RAW`, `REQUEST_LINE`, `REQUEST_METHOD`,
  `REQUEST_PROTOCOL`, `QUERY_STRING`, `REQUEST_BODY`, `REQUEST_BODY_LENGTH`, `FILES`,
  `FILES_NAMES`, `FILES_SIZES`, `FILES_COMBINED_SIZE`, `MULTIPART_PART_HEADERS`,
  `REQBODY_PROCESSOR`, `REQBODY_ERROR`, `REMOTE_ADDR`, `SERVER_NAME`, `UNIQUE_ID`, `TX`,
  `MATCHED_VAR(S)`, `MATCHED_VAR(S)_NAME(S)`; with a key (`ARGS:q`, case ignored), a
  `/regex/`, a count (`&`) or an exclusion (`!`). `XML`, the response's variables and the
  persistent collections (`IP`, `SESSION`, …) are known and empty.
- **Body processors**: `URLENCODED` and `MULTIPART` by Content-Type, `JSON` for
  `application/json` (as ModSecurity's recommended configuration does) and by
  `ctl:requestBodyProcessor`, its leaves as `json.a.b` arguments (an array's items by the array's name, `json.list`); `XML` bodies are
  `REQUEST_BODY` only.
- **Operators**: `@rx`, `@pm`, `@pmFromFile`, `@streq`, `@contains`, `@containsWord`,
  `@beginsWith`, `@endsWith`, `@within`, `@strmatch`, `@eq`, `@ge`, `@gt`, `@le`, `@lt`,
  `@validateByteRange`, `@validateUrlEncoding`, `@validateUtf8Encoding`, `@ipMatch`,
  `@ipMatchFromFile`, `@detectSQLi`, `@detectXSS` (libinjection), `@unconditionalMatch`,
  `@noMatch`; negated with `!`, macros in the arguments of the comparisons.
- **Transformations**: those of ModSecurity's reference that work on a value — `lowercase`,
  `urlDecode(Uni)`, `htmlEntityDecode`, `jsDecode`, `cssDecode`, `utf8toUnicode`,
  `removeNulls`, `replaceNulls`, `removeWhitespace`, `compressWhitespace`, `replaceComments`,
  `removeComments(Char)`, `cmdLine`, `normalizePath(Win)`, `escapeSeqDecode`, `length`,
  `base64Decode(Ext)`, `base64Encode`, `hexDecode`, `hexEncode`, `sha1`, `md5`, `trim(Left|Right)`.
- **Actions**: `id`, `phase`, `chain`, `t`, `multiMatch`, `capture`, `setvar` (on `TX`), `ctl`
  (`ruleRemoveById`, `ruleRemoveByTag`, `ruleRemoveTargetById`, `ruleRemoveTargetByTag`,
  `requestBodyProcessor`, `forceRequestBodyVariable`, `ruleEngine`), `skipAfter`, `skip`,
  `block`, `pass`, `deny`, `drop`, `allow`, `msg`, `tag`, `severity`, `log`, `nolog`; the audit
  log's and the persistent collections' actions are read and left without effect.

**How a rule runs**, as ModSecurity's: the values of its variables, each through its
transformations (and, with `multiMatch`, the operator after each one), until the operator holds
for one. A chain's link that matches sets `MATCHED_VAR(S)` and its captures (`TX.0`–`TX.9`) and
runs its `setvar` and `ctl` at once, so the next link sees them. The rule's `skipAfter` goes on
after its marker.

**Regexes** are the regex crate's, on bytes, without Unicode where the pattern allows it (as
ModSecurity's PCRE reads bytes): every `@rx` of the CRS 4 compiles so, as the CRS writes its
regexes for RE2 and Hyperscan too. A site's regex with a backreference or a lookaround does not
load.

## Compared with ModSecurity, Coraza and CrowdSec

**The rules are the same.** The bundled files are the release's, byte for byte (crs/rules
against the release's rules/); ModSecurity and Coraza load the same files, and CrowdSec's AppSec
runs the CRS (its `crowdsecurity/crs` collection, at a version of its own) through an embedded
Coraza. Rule ids, messages, severities and scores are the CRS's.

**What is not loaded:**

- `REQUEST-949` and `RESPONSE-959`, the blocking evaluation: the filter's `threshold` decides (5 by
  default, as the CRS's `inbound_anomaly_score_threshold`).
- The response rules, `RESPONSE-950` to `956`, and the correlation, `RESPONSE-980` (see below).
- `crs-setup.conf` and the `*.example` exclusion files: `engines.crs.tx`, `before` and `after`
  take their place, and the CRS's initialization (901) gives the defaults.

**What behaves otherwise, the rules being the same:**

- The interpreter is this crate's, not ModSecurity's or Coraza's; the CRS's regression tests are
  what show it reads the rules as they do ("How close it is").
- The decision is taken at the end of the head and at the end of the body, where the CRS decides
  at the end of phase 2 by default: the CRS's `early_blocking`. A head over the threshold is
  refused before its body is read.
- webfast's HTTP/1 parser refuses a raw `<`, `>`, `"`, `[` or `]` in the request target (400)
  before any check, where httpd lets it through to ModSecurity.
- Regexes are the regex crate's, not PCRE: the CRS's compile (it writes them for RE2 too), a
  site's with a backreference or a lookaround does not.
- XML bodies are read for their text and their attributes' values (`XML:/*`, `XML://@*`), with no
  other XPath.
- There are no persistent collections (`IP`, `SESSION`, …); the CRS 4's request rules do not need
  them.
- The log is the filter's JSON line, header names in lower case, not ModSecurity's
  `[id "…"] [msg "…"]` text.
- CrowdSec runs the CRS beside virtual patches of its own; the filter's `cve` set is that here,
  on beside the CRS.

**The response rules and the correlation**, and why they are not here yet:

- *Correlation (`RESPONSE-980`)* is of no use here: in the CRS 4 it is phase 5 rules that write a
  summary of the inbound and outbound scores and the rules that hit, refusing nothing. The
  filter's line has the scores, the threshold and every hit already.
- *Leaks (`RESPONSE-950` to `954`)*: SQL, Java, PHP and IIS error text, directory listings, in a
  response. Nearly what the filter's built-in `leakage` set does, which does more: it reads a
  response as it streams and cuts it at a leak, and replaces a 5xx before the cache keeps it.
- *Web shells (`RESPONSE-955`)* is the one of them a site would miss: it knows a known web shell's
  page in a response — a sign the server is compromised, not of an attempt. `RESPONSE-956` (Ruby
  errors) is narrow.
- What they would cost: some hundred regexes over the start of each proxied response's body (64
  KiB), where many ModSecurity and Coraza deployments turn the response analysis off
  (`tx.crs_skip_response_analysis`) for the CPU and for pages that show error text as content
  (documentation, forums, issue trackers). And the CRS reads a response whole, where the filter's
  response phase streams: they would run on a held response, or on windows of it and miss matches
  across a window's edge.
- So they would be an option, off by default, the web shells first.

**Responses with the CRS on, as things are:** `rules.builtin` left out means `cve` alone, so the
`leakage` set is off too and no response is looked at. A site that wants leaks found names both,
`rules.builtin: [cve, leakage]`: the leakage rules' numbers are the CRS's response rules', which
are not loaded, so nothing collides.

## How close it is

**The CRS's own regression tests** (go-ftw, the release's tests/regression/tests: 5231 tests),
run blackbox against a webfast built with the engine at the tests' settings (paranoia 4, the
CRS's test image's limits; scripts/ftw-run.sh's `crs` pass, ci/ftw/ngfw-crs.yaml):

- **5080 pass**: every test of the request rules but those below.
- 111 are not run: the tests of the rules not loaded (the blocking evaluation, 949, and the
  response phases', 95x, 959, 980) and one go-ftw cannot send (a raw CR/LF in a header).
- 40 are listed in ci/ftw/ftw-crs.yaml's `ignore`, each with its reason; none is the engine's: 26
  send a raw `<`, `>`, `"`, `[` or `]` in the request target, which webfast's HTTP/1 parser
  refuses (400) before any check, where Apache httpd, the tests' reference, lets it through to
  ModSecurity; 9 expect httpd's own answer to a request line or a header (its 400s, its joining of
  two `Content-Type` headers, its dropping of `Content-Length` beside `Transfer-Encoding`); 5 look
  for ModSecurity's log line as text (`[id "922130"] [msg …]`) or a header name as sent, where the
  filter writes JSON with header names in lower case — their rules match.

The same tests run in process (`crs_regression` in src/regression.rs, for work on the engine) pass
5021 of the 5024 they can build (the `http` crate refuses the request targets the parser does);
the three left are httpd's answers above.

**What it costs**, on one core of the machine this was written on (`cost` in src/tests.rs):
the CRS's two request phases over a browser's GET, some 200 µs at paranoia 1 and 350 µs at
paranoia 4; over a small form POST, 260 µs and 470 µs. Every rule still runs in its order, as
ModSecurity's, but a request's values are worked once per chain of transformations: transformed
(a transformation that would give the value back as it is, not run), then one pass of the chain's
automaton over the literals every match of each of its regexes starts with (regex-syntax's prefix
literals). A regex none of whose literals any value it reads has fails at once, its values not
gathered; one that may match runs on the values that have them. `TX` is a hash map read by key,
and the anomaly score is looked at only around a rule that sets variables. That is the order of
ModSecurity's and Coraza's own, and still two orders over the built-in sets' (a few µs): the CRS
has some 250 rules to run at paranoia 1, 430 at 4, the most of them comparisons of its own
variables.

## Updating the CRS

The release is pinned in the crate (crs/, `CRS_VERSION` in src/lib.rs) and changed in a commit of
its own: the new release's request rules and data files in crs/rules, the version, and the
checksum of its tarball in scripts/ftw-run.sh. The crate's tests load the bundled CRS whole (a
directive, variable, operator or action it does not know fails them); the `crs` pass of the go-ftw
run (scripts/ftw-run.sh, ci/ftw) runs the release's own regression tests against a webfast built
with the engine.
