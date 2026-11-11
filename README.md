# webfast-modules

[![CI](https://github.com/ops-pro/webfast-modules/actions/workflows/ci.yml/badge.svg)](https://github.com/ops-pro/webfast-modules/actions/workflows/ci.yml)

The optional modules of [webfast](https://github.com/ops-pro/webfast), each a crate on the module
API of `webfast-core`
([docs/modules.md](https://github.com/ops-pro/webfast/blob/main/docs/modules.md)): a `Module` the
webfast binary registers, the Caddyfile directives it adds, its request checks and inspectors of
proxied responses, its state loaded from its own files. The crates reach the core through
`webfast_core::` paths alone and the core names neither; they are compiled into the webfast binary
through its composition (`crates/webfast/src/compose.rs` there), where the order of the hooks is
fixed at compile time.

```
crates/webfast-ngfw         the NGFW request filter     webfast_ngfw::MODULE, Ngfw, response::NgfwResponses
crates/webfast-ngfw-crs     the OWASP CRS in the filter webfast_ngfw_crs::ENGINE (a rule engine of the filter)
crates/webfast-challenge    the browser challenge       webfast_challenge::MODULE, ChallengeEndpoint, Asking, Level
docs/ngfw.md, docs/ngfw-crs.md, docs/challenge.md
```

## The request filter: `webfast-ngfw`

Requests refused, marked or logged by rules and by where they come from, on when `WEB_NGFW_CONFIG`
names its YAML file. Twelve built-in sets of some hundred rules, numbered after the Core Rule Set
sections: protocol anomalies, scanners and probes, path traversal, remote inclusion, command, PHP,
SQL, template and script injection, file uploads, and error messages leaking in proxied responses
(replaced by a 500 through `handle_errors` before the proxy cache keeps them); and `cve`, known
exploited vulnerabilities of web products (Spring4Shell, Confluence, Struts 2, Citrix, F5,
Fortinet, Ivanti, PAN-OS, Next.js and others) by the signature of their exploit requests. Every
rule has its severity, confidence, tags, CWE and CVE references and a description, written with
each hit in the log; all of them are in [docs/ngfw-rules.md](docs/ngfw-rules.md), generated from
the rule files (a test keeps the two in step). Access by the
client's address (lists, files, feeds fetched on a schedule), country and ASN (MaxMind DB files),
honeypot paths, and a ban list for repeat offenders. A site's own file extends, replaces, overrides
or disables rules, by id, mask or tag; `log_only` or `challenge` for the module, a set or a rule. The head decides
synchronously and a clean request allocates nothing; the body is read only when its type is listed
and there are rules for it. One JSON line per event in its own log; a reload (SIGHUP) reads the file
again and keeps the old rules when the new do not load.

```yaml
# WEB_NGFW_CONFIG=/etc/webfast/ngfw.yaml
mode: block                        # block | log_only | challenge
threshold: 5
log: { output: /var/log/web/ngfw.log }
response: { status: 403, challenge: js }
rules:
  builtin: all
  include: [rules/site.yaml]
  disable: [wf-942-130]
access:
  ip: { allow: [10.0.0.0/8], feeds: [{ url: https://example.net/bad-ips.txt, every: 12h }] }
  countries: { deny: [KP], challenge: [CN, RU] }
  ban: { on_blocks: 5, window: 10m, for: 1h }
```

Its `challenge` feature (on by default) brings the browser challenge as an answer: `action:
challenge`, `mode: challenge`, `access.*.challenge`, `access.ban.then: challenge`. Without it a file
that asks for one does not load. Its `libinjection` feature (on by default) brings libinjection's
SQL injection and XSS detectors (the `barbacane-libinjection` crate, pure Rust, BSD-3-Clause) as
the operators `detect_sqli` and `detect_xss`, and two built-in rules on them (wf-942-170,
wf-941-150), run only on values their prefilter lets through; without it a file whose rule uses
them does not load and the two built-in rules that use them are left out. [docs/ngfw.md](docs/ngfw.md).

## The OWASP CRS in the filter: `webfast-ngfw-crs`

The [OWASP Core Rule Set](https://coreruleset.org/) v4 as it is released, in SecLang, run inside
the request filter: the crate reads the CRS's directives, variables, operators, transformations
and actions and interprets them itself (no ModSecurity or Coraza), as a rule engine of the filter
(`webfast_ngfw::plugin`), so its hits are the filter's — one decision against the filter's
threshold, one log line with each CRS rule's id, one ban list, one challenge. The CRS is bundled
(a pinned release, its request rules, phases 1 and 2); the paranoia level, the CRS's own variables
and the site's SecLang exclusions are set in the filter's file (`engines.crs`). While it is on, the
built-in sets are off but `cve`. webfast has it with its cargo feature `ngfw-crs`.
[docs/ngfw-crs.md](docs/ngfw-crs.md).

```yaml
engines:
  crs: { paranoia: 2, after: [crs/exclusions.conf] }
```

## The browser challenge: `webfast-challenge`

A client proves it is a browser before a site answers it — by accepting a cookie, by running a
small script, by a proof-of-work, or by a CAPTCHA (Turnstile, hCaptcha, reCAPTCHA) — and carries a
signed cookie that spares it the question until it expires. Who asks is the `challenge` directive
of a site, for every request it matches or only once a client is over a rate (`defer`), or the
request filter. The server keeps no state per client: the cookie is checked by its signature, with
the keys derived from the TLS ticket seed (`WEB_TLS_TICKET_SEED`), so every replica given the seed
accepts the others' cookies; a cookie that verified is remembered in a bounded table
(`WEB_CHALLENGE_PASSED`), so afterwards it is one hash lookup. The answer endpoint
`POST /.well-known/c-wf` is served on every site; the page is the answer (503 with the nonce), not
an error page.

```caddyfile
example.com {
	challenge {
		level pow                # cookie | js | pow | captcha
		valid 7d
		defer {                  # ask only a client over this rate
			events 100
			window 10m
		}
		except {
			path /api/*
		}
	}
	reverse_proxy app:8787
}
```

[docs/challenge.md](docs/challenge.md).

## Building and testing

```sh
cargo test --workspace                                   # unit tests and the end-to-end tests of the crates
cargo clippy --workspace --all-targets -- -D warnings
cargo clippy -p webfast-ngfw --all-targets --no-default-features -- -D warnings   # the filter without the challenge and libinjection
scripts/check.sh                                         # the CI checks, in Docker
UPDATE_FTW_TESTS=1 cargo test -p webfast-ngfw --lib ftw  # write tests/ftw/ from the rules' examples and tests/corpus/
UPDATE_RULES_DOC=1 cargo test -p webfast-ngfw --lib      # write docs/ngfw-rules.md and its JSON Schema
WEBFAST_BIN=… scripts/ftw-run.sh                         # go-ftw against a webfast binary, in Docker
```

A rule's tests are in the rule: its `examples`, requests it must match (`hit`) and must not
(`pass`), next to its operator in `crates/webfast-ngfw/src/rules/*.yaml`. The value lists of the
corpus are `crates/webfast-ngfw/tests/corpus/*.txt`, one value per line (SecLists' format). From
these two the go-ftw files of `crates/webfast-ngfw/tests/ftw/` are written (a test fails when they
are out of date), and `tests/ftw.rs` runs them in process, both passes, in `cargo test`. The rules
files' JSON Schema is [docs/ngfw-rules.schema.json](docs/ngfw-rules.schema.json).

`scripts/ftw-run.sh` runs the same go-ftw files blackbox,
with `ci/ftw/compose.yaml` (go-ftw, albedo as the backend, the images pinned): once with every
built-in set, as the filter ships, and once with the cve set alone. The binary is webfast's,
built with this checkout's modules (the script's header has the command; CI's `ftw` job builds
it from webfast's `dev-ci`). Its `crs` pass runs the CRS release's own regression tests against
a binary built with the `ngfw-crs` feature.

The end-to-end tests boot a server from a Caddyfile text with the core's test harness
(`webfast_core::harness`, the core's cargo feature `test-harness`) and a composition of the crate
under test, and speak HTTP/1.1 to it.

`webfast-core` is a git dependency on the webfast repository (its `dev-ci` branch; `Cargo.lock`
pins the commit). For work on both at once, copy `.cargo/config.toml.example` to
`.cargo/config.toml` (ignored by git): its `[patch]` takes the core from a webfast checkout next
to this one (`../webfast/crates/webfast-core`); the lock written with the patch in place has no
source for the core, so run `cargo update -p webfast-core` without it before committing the lock.

## How the webfast binary includes them

webfast's binary crate (`crates/webfast`) depends on these crates by git and names them in its
features: `ngfw` and `challenge`, both in its default set. Its `compose.rs` registers the modules
and writes the order of their hooks as a type:

```rust
pub type Checks = (ChallengeEndpoint, (Option<Arc<Ngfw>>, ()));   // the challenge's endpoint, then the filter
pub type Inspectors = (NgfwResponses, ());                          // the filter's response phase

pub static MODULES: &[&dyn Module] = &[&webfast_challenge::MODULE, &webfast_ngfw::MODULE];

fn hooks(config: &Config) -> (Checks, Inspectors) {
    ((ChallengeEndpoint, (config.modules.get::<Ngfw>(), ())), (NgfwResponses, ()))
}
```

A feature that is off puts `()` in the slot and a `module::Unbuilt` in the list, so a variable of a
module that is not built stops the start instead of being ignored. Nothing here is a binary: the
binary with the modules is webfast's release.

## Branches and releases

`main` is what is released; `dev-ci` is where development happens. CI (formatting, clippy with and
without the default features, the tests on x86-64 and arm64, the minimum Rust, cargo-deny) runs on
both and on pull requests. A release is a tag `vX.Y.Z` on `main`, as webfast's: the checks run
again and a GitHub release is created with the version's section of [CHANGELOG.md](CHANGELOG.md)
as its notes. No binaries are published here; webfast's release pins the tag of this repository its
binary was built with.

## License

MIT or Apache-2.0, at your option ([LICENSE-MIT](LICENSE-MIT), [LICENSE-APACHE](LICENSE-APACHE)).
