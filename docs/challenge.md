# The browser challenge

The `webfast-challenge` crate ([`crates/webfast-challenge/src`](../crates/webfast-challenge/src); the webfast binary's cargo feature `challenge`, in its default build) asks a client to prove it is a
browser before a site answers it: by accepting a cookie, by running a small script, by a
proof-of-work, or by a CAPTCHA of an outside provider. A client that passed carries a signed cookie
and is not asked again until it expires. The server keeps no state per client: the cookie is
verified by its signature, and the key comes from the same seed the TLS tickets use, so every
replica given the seed accepts the others' cookies.

Three things ask for a challenge:

- the `challenge` directive of a site, for every request it matches — at once, or only once a client
  has made more requests than a threshold allows (`defer`);
- the request filter (docs/ngfw.md): a rule with `action: challenge`, a set or the module in
  `mode: challenge`, `access.countries.challenge`, and `access.ban.then: challenge`;
- nothing else: the module has no opinion of its own.

What asks decides the *level*; the module serves the page, checks the answer, makes and verifies the
cookie. A request that passed is an ordinary request: the filter's rules still run on it.

## The directive

```caddyfile
example.com {
    challenge                        # every request, level js
    reverse_proxy 127.0.0.1:9000
}

shop.example.com {
    challenge {
        level pow                    # cookie | js | pow | captcha      (default js)
        difficulty 18                # pow: leading zero bits of the hash (default 18, 12..=28)
        valid 7d                     # how long a passed client is not asked again (default 7d)
        bind ip                      # ip | none: the cookie is bound to the client's /24 or /48 (default ip)
        defer {                      # ask only a client over this rate
            events 100               # requests ...
            window 10m               # ... in this window (GCRA, as rate_limit)
            key {client_ip}          # default; any placeholder
            count pages              # pages | all: only navigations (default pages)
        }
        except {                     # never asked; a matcher block, as `rate_limit`'s `match`
            path /api/* /.well-known/*
        }
        captcha turnstile {          # level captcha: the provider and its keys
            site_key 0x4AAAAAAA...
            secret {env.TURNSTILE_SECRET}
        }
        page /srv/challenge.html     # a page of the site's own (default: the built-in one)
        title "Just a moment..."     # the built-in page's heading (default this)
    }
    reverse_proxy 127.0.0.1:9000
}
```

It is a directive like `rate_limit`: in the site, or in `route`/`handle` with a matcher, so a part
of a site can be behind it. It runs where it stands in the chain, before the handlers that answer.
`except` and the directive's own matcher are the same thing from two sides: a request `except`
matches is passed on without a look.

`count pages` counts a request when it is a navigation: method GET or HEAD, `Accept` lists
`text/html`, `Sec-Fetch-Mode` is absent or `navigate`, and the path does not end in one of the
static extensions (`css js mjs map png jpg jpeg gif webp avif svg ico woff woff2 ttf json xml txt
webmanifest`). Images, scripts, XHR and API calls do not count: a page with sixty assets is one page.
`count all` counts everything.

A request `defer` counts is let through until its key is over the rate; from then on, and until the
key is rested again, the client is asked. The counter is one GCRA cell per key (16 bytes), in 64
shards under their own locks, swept like `rate_limit`'s; with `defer` the directive never prevents
a ready answer (the core's `webfast_core::memo`): the count is a side effect, like a zone's.

Without `defer`, every matching request without a valid cookie gets the challenge. `respond` and the
other ready answers behind the directive stay ready (the cookie is checked before them), but while
answers are prepared (the core's `memo::Preparing`) the directive marks a request it would look at
`Unkept`, so no ready answer stands where the challenge decides: always without `defer`; with
`defer` only for a request `count` could take, so assets stay ready and pages are counted live. A
`defer`'s counters have the identity `file:line|events|window|key|count` (so a reload keeps them
while those stay), and what they asked is summarized every 60 s.

## Levels

| level     | what the client must do                                                               | who passes                        |
|-----------|---------------------------------------------------------------------------------------|-----------------------------------|
| `cookie`  | follow a redirect that set the cookie                                                | anything that keeps cookies       |
| `js`      | run a script that computes the answer to a nonce and reloads with the cookie set     | anything that runs JavaScript     |
| `pow`     | the same, with a hash search of `difficulty` leading zero bits (Web Worker)          | a browser spending 0.1–2 seconds  |
| `captcha` | solve the provider's widget; the server verifies the response with the provider      | a person, mostly                  |

**cookie.** The answer is a `302` to the request's own URL with `Set-Cookie` and `Cache-Control:
no-store`; a redirect loop is not possible because the second request carries the cookie. Only for
GET and HEAD: a POST or other method without the cookie gets the `js` page instead (a body cannot be
replayed through a redirect), which is also why `cookie` is the level for sites whose clients may
not run scripts, not for forms.

**js.** The page is answered with status `503`, `Retry-After: 5`, `Cache-Control: no-store`, and
`Content-Security-Policy: default-src 'none'; script-src 'sha256-<built-in script>'; style-src
'unsafe-inline'; img-src data:; connect-src 'self'; worker-src blob:`; no external resource is
loaded. Its script reads `nonce` and the level from `data-` attributes, computes `answer =
hex(sha256(nonce))` — a synchronous SHA-256 in the script itself: `crypto.subtle` is unavailable on
plain-HTTP origins and asynchronous per hash — and posts `POST /.well-known/c-wf` with `nonce`,
`answer` and the original URL as a form; the server verifies, answers `204` with `Set-Cookie`, and
the script reloads the page. The `POST` endpoint is served by the module for every site (see "From
the request filter"), so a site needs no route for it; it answers `400` to a wrong answer and `403`
to a stale nonce, and a request to it that is not a `POST` passes through to the routes. A client
that cannot post is shown the `<noscript>` text.

**pow.** The script searches `counter` such that `sha256(nonce || ":" || counter)` has `difficulty`
leading zero bits, in a Web Worker, with a progress bar; the server checks one hash. `difficulty` 18
is 2^18 hashes: about 0.3 s on a laptop, 1–2 s on a phone. The server never searches.

**captcha.** The page loads the provider's widget script (the CSP adds the provider's origins to
`script-src`, `connect-src` and `frame-src`: Turnstile `challenges.cloudflare.com`; hCaptcha
`js.hcaptcha.com *.hcaptcha.com`; reCAPTCHA `www.google.com www.gstatic.com www.recaptcha.net`),
and the widget's token is posted as `answer`; the server verifies it with the provider's
`siteverify` endpoint (an outbound HTTPS POST through the core's `webfast_core::fetch`, 5 s timeout), then sets the
cookie. Providers: `turnstile` (Cloudflare; `https://challenges.cloudflare.com/turnstile/v0/siteverify`),
`hcaptcha` (`https://api.hcaptcha.com/siteverify`), `recaptcha` (v2, `https://www.google.com/recaptcha/api/siteverify`).
The secret may come from `{env.NAME}`. The provider is told the client's IP (`remoteip`) and
nothing else. When the provider cannot be reached the endpoint answers a bare `503` (no page: the
script shows its text and the client may try again).

## The nonce and the cookie

Both are signed with a key of the period: `HKDF-SHA256(seed, "webfast challenge", period)`, the
period being the day number (`unix_time / 86400`) — the same derivation as the core's src/tickets.rs, from the
same seed (`WEB_TLS_TICKET_SEED` / `_FILE`); without a seed the process draws one at start, as the
tickets do. The key of a period is derived when first needed (~44 µs, once per period) and kept in
a small table, so any period's key is at hand: a cookie or nonce is good while its expiry is in the
future and no more than 400 days ahead, whatever period it was made in, and a cluster given one
seed shares cookies and nonces.

**Nonce** (in the page, 60 s): `base64url( version:u8 | expiry:u32 | level:u8 | difficulty:u8 |
provider:u8 | flags:u8 | valid_secs:u32 | random:u64 | tag:16 )` — 37 raw bytes, 50 characters;
`tag = blake3::keyed_hash(key(period of expiry), the bytes before it || client prefix)[..16]`. The
nonce carries everything the answer endpoint needs (the level, the difficulty, the CAPTCHA provider's
index, the binding and `valid` of the cookie to make), so one endpoint serves every site's and the
filter's challenges from the nonce alone. Stateless: a nonce is not remembered, so one could be
answered twice within its 60 s — which gives two cookies to one client, nothing more.

**Cookie** `__wf_c` (`Max-Age=valid; Path=/; HttpOnly; SameSite=Lax`, `Secure` on TLS):
`base64url( version:u8 | expiry:u32 | level:u8 | flags:u8 | tag:16 )` — 23 raw bytes, 31
characters; `flags` holds the binding; `tag = blake3::keyed_hash(key(period of expiry), version |
expiry | level | flags | client prefix | ua_hash)[..16]`. `client prefix` is the client's address at
`/24` (IPv4) or `/48` (IPv6) with `bind ip`, nothing with `bind none`; `ua_hash` is
`blake3(User-Agent)[..8]` — a cookie is not good from another address block or another browser. A
cookie with a level below the one asked (a `cookie`-level cookie where `pow` is asked) is not good:
the level is in the signed bytes.

**Verification** is one base64 decode and one keyed blake3 over a few dozen bytes: ~350 ns — and
it is done once per cookie and client, not per request. A cookie that verified goes into the table
of passed cookies: 64 shards of `FxHashMap<[u8; 37], ()>` keyed by the cookie's 23 decoded bytes,
the client prefix (3 or 6 bytes, as the cookie's `bind` says) and `fxhash(User-Agent)` (8 bytes),
compared whole on a hit — so a hit still honours the binding to the address block and the browser.
A lookup is a hash of the key and one compare, ~160 ns in a release build, and no signature is
computed again for a cookie a connection already brought from that client. A cookie not in the
table is verified and, good, inserted; a bad one is not remembered (the table holds nothing an
attacker chose). The table is bounded (`WEB_CHALLENGE_PASSED`, default 1,000,000 cookies; full, a
new cookie is verified every time and not inserted) and swept of expired entries on the module's
sweep (every 60 s). The expiry and the level are in the key, so a hit answers "good until when, at
what level" without anything else stored.

## The page

`assets/challenge.html` (`include_str!`), one file for every level: a centered card on a plain
background, the host as heading, `title` under it ("Just a moment..." by default), a spinner, one
line of explanation per level ("Verifying your browser", "This takes a few seconds", "Please
complete the check below"), a progress bar for `pow`, the provider's widget for `captcha`, a
`<noscript>` paragraph, and a footer with the request's id (a short random, also sent as
`X-Request-Id` on the page response; for the site's log) and the server's name. No logo, no brand,
no reference to any company; the look is the plain centered-card interstitial browsers' users know.
Dark mode by `prefers-color-scheme`. The whole page is under 6 KiB, served from memory.

A site's own `page` is a file read at start (reloaded with the configuration) with the placeholders
`{challenge.nonce}`, `{challenge.level}`, `{challenge.difficulty}`, `{challenge.title}`,
`{challenge.host}`, `{challenge.request_id}`, `{challenge.site_key}`, `{challenge.provider}` and
`{challenge.script}` — the last is the built-in script, which the page must include for
`js`/`pow`/`captcha` to work. The CSP hash covers the built-in script only; a page with scripts of
its own gets no CSP header.

## From the request filter

The filter (docs/ngfw.md) gets:

- `action: challenge` on a rule: like `block`, but the refusal is the challenge at
  `response.challenge` level (default `js`), and the hit is logged as `challenge`. A client that
  carries a good cookie of that level or above is not challenged by
  rules: the rule then counts as `log`, written as `challenge_passed`, and the request goes on
  through the rules left. (The cookie was earned; the rule's score still goes to the log.)
- `mode: challenge` on the module, a set or a rule: every `block` becomes `challenge`, and so does a
  sum over the threshold made of challenge-mode scores alone (a block-mode rule in the sum keeps it
  a block); `ban` stays `ban`. In the `response` phase a leak is replaced as in `block`: a response
  cannot be challenged.
- `access.countries.challenge: [CN, RU]` and `access.asn.challenge: [...]`: these are asked, not
  refused; `deny` stays what it is, and an address in both is denied. The order before the rules:
  ban, ip deny, country deny, asn deny, honeypot, then the challenge lists.
- `access.ban.then: challenge`: on reaching `on_blocks` the address is not banned but marked for the
  challenge for `for`: the ban list keeps the address with the mark, `banned()` stays false for it,
  and every request of it is asked unless it passed. Honeypots and `action: ban` ban whatever `then`
  says, and a ban in force is not softened to a mark. A challenge asked is not a refusal for
  `on_blocks`.
- `response: { challenge: js, challenge_valid: 7d, challenge_bind: ip, captcha: { provider:
  turnstile, site_key: …, secret: … } }` builds the one `Asking` at load; `captcha.secret` is a
  literal or `env:NAME`. Any of these in a webfast built without the module is a configuration
  error that says so.

The filter reaches the module through `challenge::instance()` (one static instance per process:
its state is nothing but the key schedule, the built-in page, the tables of passed cookies and
tokens, and the counters) and answers with `instance().ask(conn, parts, client_ip, &asking)`, which
gives the page or the redirect as a `Response` with `ErrorPage` **not** set (the challenge page is
the answer; the server sends a check's refusal through `handle_errors` only when it carries
`ErrorPage`, the core's src/server.rs `Refusal`). `instance().passed(conn, parts, client_ip, level)` says
whether the request carries a good cookie of that level or above. `Asking` holds what a challenge is asked with — `level`, `difficulty`, `valid`,
`bind`, `title`, the `captcha` provider, the `page` — with a `Default` of the directive's defaults;
the filter builds one from `response.challenge` (and `response.captcha` for the provider's keys).
`defer` counters belong to each directive.

The answer endpoint `POST /.well-known/c-wf` is served for every site by a request check of the
module (`ChallengeEndpoint`, a `module::Check`; the webfast binary's composition puts it first
among the modules' checks, before the request filter), so it works for the filter's challenges on
sites without the directive. A nonce carries the index of the
CAPTCHA provider that will verify its answer; providers are registered in a process-wide list at
configuration time (deduplicated by provider, site key and secret, so a reload keeps the indices).

## Operations

- `webfast validate` prints each site's `challenge` with its level and `defer`.
- Log: the module writes nothing per request. The site's access log shows the challenge page as a
  `503` (or the `302`) with the `X-Request-Id`; `webfast` counts challenges asked, passed and failed
  per level, summarized in the server log every 60 s like the zones.
- Reload: the directive's `defer` counters outlive a reload when the site, path and limits stay
  (the zone identity is `host|matcher|events|window`), as `rate_limit`'s do.
- Clients behind one NAT share a `/24`: `bind ip` means a cookie stolen on the same network works
  there; `bind none` means it works anywhere. Neither is a session: the cookie says "a browser was
  here", not who.
- `cookie` level is the one for feeds, old clients, `curl` users who accept cookies — it stops
  nothing that tries. `pow` and `captcha` cost the client; `js` is the default because it stops the
  bulk (scripts and scanners) at no cost to people.

## Module layout

```
crates/webfast-challenge/src/
  lib.rs        MODULE (what the binary's composition registers), Challenge (the static instance),
                Level, Asking, ask(), passed(), ChallengeEndpoint (the POST answer endpoint)
  token.rs      the key schedule (periods from the seed), the nonce and the cookie: make, check
  pow.rs        the proof-of-work check (one SHA-256, leading zero bits)
  page.rs       the built-in page and a site's own: rendering with the placeholders, the CSP hash
  captcha.rs    the providers: their verify URL, the form, the answer's parsing
  defer.rs      the deferred threshold: GCRA cells per key (the shape of the core's rate_limit
                shards)
  directive.rs  the Caddyfile directive: its parser (a module::Directive, Order::Before("rate_limit")),
                ChallengeDirective (a module::RouteHandler), run()
assets/challenge.html   the built-in page (include_str!)
tests/challenge.rs      the end-to-end tests on webfast_core::harness
```

The directive's route is a `Handler::Extension(Arc<ChallengeDirective>)` (a `module::RouteHandler`),
run in the chain where it stands like `rate_limit`: `None` → the chain goes on; `Some(response)` →
the answer (the page or the redirect). The crate is a module in the sense of webfast's
[docs/modules.md](https://github.com/ops-pro/webfast/blob/main/docs/modules.md): the webfast
binary's `compose.rs` registers `webfast_challenge::MODULE` (the directive, `WEB_CHALLENGE_PASSED`,
the seed) and puts `ChallengeEndpoint` first among the composed request checks.

The public pieces the filter and the binary use:

```rust
pub static MODULE: ChallengeModule;   // impl Module: the directive, configure_from_env, seed, validate
pub fn instance() -> &'static Challenge;
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum Level { Cookie, Js, Pow, Captcha }
pub enum Bind { Ip, None }
pub struct Asking { pub level: Level, pub difficulty: u8, pub valid: Duration, pub bind: Bind,
                    pub title: Arc<str>, pub captcha: Option<Arc<Captcha>>, pub page: Option<Arc<Page>> }
impl Default for Asking { /* js, 18, 7d, Ip, "Just a moment...", None, None */ }
impl Challenge {
    pub fn passed(&self, conn: &ConnInfo, parts: &http::request::Parts, ip: IpAddr, level: Level) -> bool;
    pub fn ask(&self, conn: &ConnInfo, parts: &http::request::Parts, ip: IpAddr, asking: &Asking) -> Response<Body>;
}
pub struct ChallengeEndpoint;   // impl module::Check: the POST answer endpoint
pub struct Captcha { pub provider: Provider, pub site_key: String, secret: String }
impl Captcha { pub fn register(self) -> Arc<Captcha>; }  // the process-wide list, deduplicated
```

## Tests

- token.rs: a cookie is good until its expiry, not after; not from another /24 with `bind ip`,
  good with `bind none`; not with another User-Agent; a lower level is not good for a higher ask; a
  changed byte fails; the nonce expires at 60 s.
- pow.rs: an answer with the bits is accepted, one bit short is not; difficulty bounds.
- defer.rs: the 101st page in the window is asked, the 100th is not; assets are not counted; the key
  rests.
- page.rs: every placeholder filled, the CSP hash matches the script, size under 6 KiB.
- directive.rs: parsing of every option and the errors (level unknown, difficulty out of range,
  captcha without keys).
- tests/challenge.rs (a server): no cookie → 503 page with nonce; the js answer → 204 + cookie →
  200; cookie level → 302 then 200; `except` path passes; `defer` lets 100 through and asks the
  101st; a wrong answer → 400; stale nonce → 403. The filter's `action: challenge` → page, and with a
  cookie → passes with the hit logged as `challenge_passed` (tests/ngfw.rs).
