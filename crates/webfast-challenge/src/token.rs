//! The key schedule, the nonce and the cookie: made and checked here, remembered nowhere.
//!
//! One key per day, `HKDF-SHA256(seed, "webfast challenge", period)` with the period the day
//! number (`unix_time / 86400`), from the same seed as the TLS tickets (webfast_core::tickets): every
//! replica given the seed derives the same keys, so a cookie set by one is good at the others, and
//! a restart loses nothing. Nonce and cookie carry their expiry and are tagged under the key of
//! the expiry's period (`blake3::keyed_hash`, 16 bytes kept); checking one is a base64url decode
//! into a stack array, one keyed hash over a few dozen bytes and a constant-time compare. The keys
//! of the periods in use are kept in a small table swapped whole (arc-swap: a load is a pointer
//! read), so HKDF runs once per period, not per request.
//!
//! Both are bound to the client: the nonce and the cookie to the address block (`/24`, `/48`) with
//! `bind ip`, the cookie also to `blake3(User-Agent)[..8]`. A cookie says "a browser passed from
//! this block with this User-Agent, at this level": its level is in the signed bytes, so a cookie
//! earned at a lower level is not good where a higher one is asked.

use super::{Bind, Level};
use arc_swap::ArcSwap;
use aws_lc_rs::hkdf::{HKDF_SHA256, Prk, Salt};
use std::net::IpAddr;
use std::sync::Arc;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

/// How long a nonce answers.
pub const NONCE_TTL: Duration = Duration::from_secs(60);
/// The cookie's name.
pub const COOKIE_NAME: &str = "__wf_c";
/// A day: how long a key makes nonces and cookies.
const PERIOD_SECS: u64 = 86_400;
/// No cookie or nonce is good for longer than this (a sanity bound on the expiry carried).
const MAX_AHEAD: u64 = 400 * PERIOD_SECS;
const VERSION: u8 = 1;
const TAG: usize = 16;
/// Nonce: version, expiry, level, difficulty, provider, flags, valid (seconds), random, tag.
const NONCE_RAW: usize = 1 + 4 + 1 + 1 + 1 + 1 + 4 + 8 + TAG;
/// The nonce as base64url (no padding).
pub const NONCE_LEN: usize = (NONCE_RAW * 4).div_ceil(3);
/// Cookie: version, expiry, level, flags, tag.
pub const COOKIE_RAW: usize = 1 + 4 + 1 + 1 + TAG;
/// The cookie value as base64url (no padding).
pub const COOKIE_LEN: usize = (COOKIE_RAW * 4).div_ceil(3);
/// Keys cached, by period: the days a `valid` of a week spans, and some.
const CACHED: usize = 16;
const EMPTY: u64 = u64::MAX;
const FLAG_BIND_IP: u8 = 1;

/// Seconds since the epoch.
pub fn now_secs() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}

/// The keys of a seed.
pub struct Keys {
    seed: Prk,
    cache: ArcSwap<Table>,
}

/// Period → key, indexed by `period % CACHED`.
#[derive(Clone)]
struct Table {
    periods: [u64; CACHED],
    keys: [[u8; 32]; CACHED],
}

impl std::fmt::Debug for Keys {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("Keys")
    }
}

/// What a nonce carries: what was asked, and how the cookie it earns is to be made.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct NonceData {
    pub expiry: u32,
    pub level: Level,
    pub difficulty: u8,
    /// The CAPTCHA provider that verifies the answer (captcha.rs); 0: none.
    pub provider: u8,
    pub bind: Bind,
    /// How long the cookie is good, in seconds.
    pub valid: u32,
}

/// What a cookie carries.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CookieData {
    pub expiry: u32,
    pub level: Level,
    pub bind: Bind,
}

impl Keys {
    /// The keys of `seed` (any length; the tickets ask for 32 bytes at least, and the same seed
    /// comes here).
    pub fn new(seed: &[u8]) -> Keys {
        Keys {
            seed: Salt::new(HKDF_SHA256, b"webfast challenge").extract(seed),
            cache: ArcSwap::from_pointee(Table {
                periods: [EMPTY; CACHED],
                keys: [[0; 32]; CACHED],
            }),
        }
    }

    /// Keys of a seed drawn now: the process's own, as the tickets' are without a seed.
    pub fn random() -> Keys {
        let mut seed = [0u8; 32];
        if aws_lc_rs::rand::fill(&mut seed).is_err() {
            // The system's random source failed (it does not, short of a broken system): the
            // clock's nanoseconds hashed, rather than a seed of zeros.
            let now = SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap_or_default()
                .as_nanos();
            seed = *blake3::hash(&now.to_le_bytes()).as_bytes();
        }
        Keys::new(&seed)
    }

    /// The key of `period`, derived once and kept.
    fn key(&self, period: u64) -> [u8; 32] {
        let slot = (period % CACHED as u64) as usize;
        let table = self.cache.load();
        if table.periods[slot] == period {
            return table.keys[slot];
        }
        let mut key = [0u8; 32];
        let info: [&[u8]; 2] = [b"period", &period.to_be_bytes()];
        if let Ok(okm) = self.seed.expand(&info, HKDF_SHA256) {
            // HKDF_SHA256 as the key type fills exactly 32 bytes.
            let _ = okm.fill(&mut key);
        }
        let mut next = Table::clone(&table);
        next.periods[slot] = period;
        next.keys[slot] = key;
        self.cache.store(Arc::new(next));
        key
    }

    /// A nonce for `ip`, as the page carries it (ASCII).
    pub fn make_nonce(&self, data: &NonceData, ip: IpAddr) -> [u8; NONCE_LEN] {
        let mut raw = [0u8; NONCE_RAW + 6];
        raw[0] = VERSION;
        raw[1..5].copy_from_slice(&data.expiry.to_be_bytes());
        raw[5] = data.level as u8;
        raw[6] = data.difficulty;
        raw[7] = data.provider;
        raw[8] = flags(data.bind);
        raw[9..13].copy_from_slice(&data.valid.to_be_bytes());
        let mut random = [0u8; 8];
        if aws_lc_rs::rand::fill(&mut random).is_err() {
            random = now_nanos_bytes();
        }
        raw[13..21].copy_from_slice(&random);
        let signed = NONCE_RAW - TAG;
        let bound = signed + prefix_into(ip, data.bind, &mut raw[signed..]);
        let tag = blake3::keyed_hash(&self.key(period_of(data.expiry)), &raw[..bound]);
        raw[signed..NONCE_RAW].copy_from_slice(&tag.as_bytes()[..TAG]);
        let mut out = [0u8; NONCE_LEN];
        encode(&raw[..NONCE_RAW], &mut out);
        out
    }

    /// The nonce's data when it is good: made by us for `ip`'s block, not expired at `now`.
    pub fn check_nonce(&self, text: &[u8], ip: IpAddr, now: u64) -> Option<NonceData> {
        let mut raw = [0u8; NONCE_RAW + 6];
        if text.len() != NONCE_LEN || decode(text, &mut raw[..NONCE_RAW])? != NONCE_RAW || raw[0] != VERSION {
            return None;
        }
        let expiry = u32::from_be_bytes(raw[1..5].try_into().ok()?);
        if !alive(expiry, now) {
            return None;
        }
        let level = Level::from_u8(raw[5])?;
        let bind = bind_of(raw[8]);
        let signed = NONCE_RAW - TAG;
        let mut tag = [0u8; TAG];
        tag.copy_from_slice(&raw[signed..NONCE_RAW]);
        let bound = signed + prefix_into(ip, bind, &mut raw[signed..]);
        let expected = blake3::keyed_hash(&self.key(period_of(expiry)), &raw[..bound]);
        if !same(&tag, &expected.as_bytes()[..TAG]) {
            return None;
        }
        Some(NonceData {
            expiry,
            level,
            difficulty: raw[6],
            provider: raw[7],
            bind,
            valid: u32::from_be_bytes(raw[9..13].try_into().ok()?),
        })
    }

    /// The cookie value for `ip` with `ua` (the User-Agent's bytes), as `Set-Cookie` carries it.
    pub fn make_cookie(&self, data: &CookieData, ip: IpAddr, ua: &[u8]) -> [u8; COOKIE_LEN] {
        let mut raw = [0u8; COOKIE_RAW + 6 + 8];
        raw[0] = VERSION;
        raw[1..5].copy_from_slice(&data.expiry.to_be_bytes());
        raw[5] = data.level as u8;
        raw[6] = flags(data.bind);
        let signed = COOKIE_RAW - TAG;
        let bound = cookie_binding(&mut raw, signed, ip, data.bind, ua);
        let tag = blake3::keyed_hash(&self.key(period_of(data.expiry)), &raw[..bound]);
        raw[signed..COOKIE_RAW].copy_from_slice(&tag.as_bytes()[..TAG]);
        let mut out = [0u8; COOKIE_LEN];
        encode(&raw[..COOKIE_RAW], &mut out);
        out
    }

    /// The cookie's data when it is good for `ip` with `ua` at `now`.
    pub fn check_cookie(&self, text: &[u8], ip: IpAddr, ua: &[u8], now: u64) -> Option<CookieData> {
        let mut raw = [0u8; COOKIE_RAW + 6 + 8];
        if text.len() != COOKIE_LEN || decode(text, &mut raw[..COOKIE_RAW])? != COOKIE_RAW || raw[0] != VERSION {
            return None;
        }
        let expiry = u32::from_be_bytes(raw[1..5].try_into().ok()?);
        if !alive(expiry, now) {
            return None;
        }
        let level = Level::from_u8(raw[5])?;
        let bind = bind_of(raw[6]);
        let signed = COOKIE_RAW - TAG;
        let mut tag = [0u8; TAG];
        tag.copy_from_slice(&raw[signed..COOKIE_RAW]);
        let bound = cookie_binding(&mut raw, signed, ip, bind, ua);
        let expected = blake3::keyed_hash(&self.key(period_of(expiry)), &raw[..bound]);
        if !same(&tag, &expected.as_bytes()[..TAG]) {
            return None;
        }
        Some(CookieData { expiry, level, bind })
    }
}

/// The cookie's decoded bytes into `raw` (`COOKIE_RAW` long) when `text` has the shape of a cookie
/// of ours, with its level; the signature is not checked here (the table of passed cookies looks
/// the bytes up first, lib.rs).
pub(super) fn decode_cookie_head(text: &[u8], raw: &mut [u8]) -> Option<Level> {
    if text.len() != COOKIE_LEN || decode(text, raw)? != COOKIE_RAW || raw[0] != VERSION {
        return None;
    }
    Level::from_u8(raw[5])
}

/// What a decoded cookie says it is bound to.
pub(super) fn bind_of_cookie(raw: &[u8]) -> Bind {
    bind_of(raw[6])
}

/// The client prefix and the User-Agent's hash after the cookie's head, at `signed`; where they end.
fn cookie_binding(raw: &mut [u8], signed: usize, ip: IpAddr, bind: Bind, ua: &[u8]) -> usize {
    let mut at = signed + prefix_into(ip, bind, &mut raw[signed..]);
    raw[at..at + 8].copy_from_slice(&blake3::hash(ua).as_bytes()[..8]);
    at += 8;
    at
}

/// Not expired, and not absurdly far ahead (a tag is checked after this, so this only bounds
/// what a cookie may claim).
fn alive(expiry: u32, now: u64) -> bool {
    let expiry = u64::from(expiry);
    expiry > now && expiry - now <= MAX_AHEAD
}

fn period_of(expiry: u32) -> u64 {
    u64::from(expiry) / PERIOD_SECS
}

fn flags(bind: Bind) -> u8 {
    match bind {
        Bind::Ip => FLAG_BIND_IP,
        Bind::None => 0,
    }
}

fn bind_of(flags: u8) -> Bind {
    if flags & FLAG_BIND_IP != 0 {
        Bind::Ip
    } else {
        Bind::None
    }
}

/// The client's block into `out`: the first 3 bytes of an IPv4 address (`/24`), the first 6 of an
/// IPv6 one (`/48`); nothing with `bind none`. How many bytes.
pub(super) fn prefix_into(ip: IpAddr, bind: Bind, out: &mut [u8]) -> usize {
    if bind == Bind::None {
        return 0;
    }
    match ip.to_canonical() {
        IpAddr::V4(v4) => {
            out[..3].copy_from_slice(&v4.octets()[..3]);
            3
        }
        IpAddr::V6(v6) => {
            out[..6].copy_from_slice(&v6.octets()[..6]);
            6
        }
    }
}

/// Constant-time equality of two tags.
fn same(a: &[u8], b: &[u8]) -> bool {
    aws_lc_rs::constant_time::verify_slices_are_equal(a, b).is_ok()
}

fn now_nanos_bytes() -> [u8; 8] {
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_nanos() as u64;
    nanos.to_le_bytes()
}

const URL_ALPHABET: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";
const STD_ALPHABET: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

/// base64url without padding of `input` into `out` (sized `(len * 4).div_ceil(3)`).
pub fn encode(input: &[u8], out: &mut [u8]) {
    encode_with(URL_ALPHABET, input, out);
}

/// Standard base64 with padding, as a `Content-Security-Policy` hash wants it.
pub fn encode_standard(input: &[u8]) -> String {
    let mut out = vec![0u8; (input.len() * 4).div_ceil(3)];
    encode_with(STD_ALPHABET, input, &mut out);
    while !out.len().is_multiple_of(4) {
        out.push(b'=');
    }
    String::from_utf8(out).unwrap_or_default()
}

fn encode_with(alphabet: &[u8; 64], input: &[u8], out: &mut [u8]) {
    let mut o = 0;
    for chunk in input.chunks(3) {
        let n = chunk.len();
        let bits = (u32::from(chunk[0]) << 16)
            | (u32::from(*chunk.get(1).unwrap_or(&0)) << 8)
            | u32::from(*chunk.get(2).unwrap_or(&0));
        let symbols = [
            alphabet[(bits >> 18) as usize & 63],
            alphabet[(bits >> 12) as usize & 63],
            alphabet[(bits >> 6) as usize & 63],
            alphabet[bits as usize & 63],
        ];
        let take = n + 1;
        if o + take > out.len() {
            return;
        }
        out[o..o + take].copy_from_slice(&symbols[..take]);
        o += take;
    }
}

/// base64url without padding, into `out`; how many bytes, `None` on a character outside the
/// alphabet or more bytes than `out` holds.
pub fn decode(input: &[u8], out: &mut [u8]) -> Option<usize> {
    let value = |c: u8| -> Option<u32> {
        Some(match c {
            b'A'..=b'Z' => u32::from(c - b'A'),
            b'a'..=b'z' => u32::from(c - b'a') + 26,
            b'0'..=b'9' => u32::from(c - b'0') + 52,
            b'-' => 62,
            b'_' => 63,
            _ => return None,
        })
    };
    let mut o = 0;
    for chunk in input.chunks(4) {
        if chunk.len() == 1 {
            return None;
        }
        let mut bits = 0u32;
        for (i, &c) in chunk.iter().enumerate() {
            bits |= value(c)? << (18 - 6 * i);
        }
        let bytes = [(bits >> 16) as u8, (bits >> 8) as u8, bits as u8];
        let take = chunk.len() - 1;
        if o + take > out.len() {
            return None;
        }
        out[o..o + take].copy_from_slice(&bytes[..take]);
        o += take;
    }
    Some(o)
}

#[cfg(test)]
mod tests {
    use super::*;

    const SEED: &[u8] = b"0123456789abcdef0123456789abcdef";
    const NOW: u64 = 1_800_000_000;

    fn ip(text: &str) -> IpAddr {
        text.parse().unwrap()
    }

    fn cookie(keys: &Keys, level: Level, bind: Bind, valid: u64) -> CookieData {
        let _ = keys;
        CookieData {
            expiry: (NOW + valid) as u32,
            level,
            bind,
        }
    }

    #[test]
    fn base64url_round_trips_and_refuses_what_is_not_it() {
        for len in 0..40usize {
            let input: Vec<u8> = (0..len as u8).map(|i| i.wrapping_mul(37).wrapping_add(11)).collect();
            let mut text = vec![0u8; (len * 4).div_ceil(3)];
            encode(&input, &mut text);
            assert!(
                text.iter()
                    .all(|c| c.is_ascii_alphanumeric() || *c == b'-' || *c == b'_')
            );
            let mut back = vec![0u8; len];
            assert_eq!(decode(&text, &mut back), Some(len));
            assert_eq!(back, input);
        }
        let mut out = [0u8; 8];
        assert_eq!(decode(b"AB+D", &mut out), None, "the standard alphabet is not ours");
        assert_eq!(decode(b"A", &mut out), None, "a lone symbol is no byte");
        assert_eq!(decode(b"AAAAAAAAAAAAAAAA", &mut out), None, "more than the buffer");
        assert_eq!(encode_standard(b"hello"), "aGVsbG8=");
        assert_eq!(encode_standard(&[0xfb, 0xff]), "+/8=");
    }

    #[test]
    fn a_cookie_is_good_until_it_expires_for_its_block_and_browser() {
        let keys = Keys::new(SEED);
        let replica = Keys::new(SEED);
        let other = Keys::new(b"another seed of thirty-two bytes!");
        let ua = b"Mozilla/5.0 (test)";
        let week = 7 * PERIOD_SECS;
        let data = cookie(&keys, Level::Js, Bind::Ip, week);
        let value = keys.make_cookie(&data, ip("203.0.113.7"), ua);
        assert_eq!(value.len(), COOKIE_LEN);
        assert_eq!(keys.check_cookie(&value, ip("203.0.113.7"), ua, NOW), Some(data));
        assert_eq!(
            replica.check_cookie(&value, ip("203.0.113.7"), ua, NOW),
            Some(data),
            "a replica with the seed"
        );
        assert_eq!(
            keys.check_cookie(&value, ip("203.0.113.200"), ua, NOW + PERIOD_SECS + 61),
            Some(data),
            "the next day, from another address of the /24"
        );
        assert_eq!(
            keys.check_cookie(&value, ip("203.0.113.7"), ua, NOW + week - 1),
            Some(data),
            "just before it expires"
        );
        assert_eq!(
            keys.check_cookie(&value, ip("203.0.113.7"), ua, NOW + week),
            None,
            "expired"
        );
        assert_eq!(
            keys.check_cookie(&value, ip("203.0.114.7"), ua, NOW),
            None,
            "another /24"
        );
        assert_eq!(
            keys.check_cookie(&value, ip("203.0.113.7"), b"curl/8", NOW),
            None,
            "another browser"
        );
        assert_eq!(
            other.check_cookie(&value, ip("203.0.113.7"), ua, NOW),
            None,
            "another seed"
        );
        for at in [0, 3, 7, 12, COOKIE_LEN - 1] {
            let mut bad = value;
            bad[at] = if bad[at] == b'A' { b'B' } else { b'A' };
            assert_eq!(keys.check_cookie(&bad, ip("203.0.113.7"), ua, NOW), None, "symbol {at}");
        }
        assert_eq!(
            keys.check_cookie(&value[..COOKIE_LEN - 1], ip("203.0.113.7"), ua, NOW),
            None
        );
        assert_eq!(keys.check_cookie(b"", ip("203.0.113.7"), ua, NOW), None);

        // IPv6: the /48.
        let value = keys.make_cookie(&data, ip("2001:db8:1:2::1"), ua);
        assert!(keys.check_cookie(&value, ip("2001:db8:1:ffff::9"), ua, NOW).is_some());
        assert!(keys.check_cookie(&value, ip("2001:db8:2::1"), ua, NOW).is_none());

        // `bind none`: good anywhere, still the browser's.
        let free = cookie(&keys, Level::Js, Bind::None, week);
        let value = keys.make_cookie(&free, ip("203.0.113.7"), ua);
        assert_eq!(keys.check_cookie(&value, ip("198.51.100.1"), ua, NOW), Some(free));
        assert_eq!(keys.check_cookie(&value, ip("198.51.100.1"), b"other", NOW), None);
    }

    #[test]
    fn the_level_is_signed_and_ordered() {
        let keys = Keys::new(SEED);
        let ua = b"ua";
        let low = keys.make_cookie(&cookie(&keys, Level::Cookie, Bind::Ip, 3600), ip("10.0.0.1"), ua);
        let got = keys.check_cookie(&low, ip("10.0.0.1"), ua, NOW).unwrap();
        assert!(
            got.level < Level::Pow,
            "a cookie-level cookie is not good for a pow ask"
        );
        assert!(got.level >= Level::Cookie);
        // Flipping the level byte is caught by the tag.
        let mut raw = [0u8; COOKIE_RAW];
        decode(&low, &mut raw).unwrap();
        raw[5] = Level::Captcha as u8;
        let mut forged = [0u8; COOKIE_LEN];
        encode(&raw, &mut forged);
        assert_eq!(keys.check_cookie(&forged, ip("10.0.0.1"), ua, NOW), None);
    }

    #[test]
    fn a_nonce_answers_for_a_minute_from_its_block() {
        let keys = Keys::new(SEED);
        let data = NonceData {
            expiry: (NOW + NONCE_TTL.as_secs()) as u32,
            level: Level::Pow,
            difficulty: 18,
            provider: 2,
            bind: Bind::Ip,
            valid: 604_800,
        };
        let nonce = keys.make_nonce(&data, ip("203.0.113.7"));
        assert_eq!(nonce.len(), NONCE_LEN);
        assert_eq!(keys.check_nonce(&nonce, ip("203.0.113.9"), NOW), Some(data));
        assert_eq!(keys.check_nonce(&nonce, ip("203.0.113.9"), NOW + 59), Some(data));
        assert_eq!(keys.check_nonce(&nonce, ip("203.0.113.9"), NOW + 60), None, "stale");
        assert_eq!(keys.check_nonce(&nonce, ip("198.51.100.1"), NOW), None, "another block");
        assert_ne!(
            keys.make_nonce(&data, ip("203.0.113.7")),
            nonce,
            "every nonce has its random"
        );
        let mut bad = nonce;
        bad[20] ^= 1;
        assert_eq!(keys.check_nonce(&bad, ip("203.0.113.7"), NOW), None);
        let free = NonceData {
            bind: Bind::None,
            ..data
        };
        let nonce = keys.make_nonce(&free, ip("203.0.113.7"));
        assert_eq!(keys.check_nonce(&nonce, ip("198.51.100.1"), NOW), Some(free));
    }

    #[test]
    fn the_keys_of_a_period_are_derived_once() {
        let keys = Keys::new(SEED);
        let a = keys.key(20_000);
        let b = keys.key(20_000);
        let c = keys.key(20_001);
        assert_eq!(a, b);
        assert_ne!(a, c);
        assert_eq!(Keys::new(SEED).key(20_000), a);
        // Many periods: the table wraps, the keys stay right.
        for period in 0..100u64 {
            assert_eq!(keys.key(period), Keys::new(SEED).key(period));
        }
        assert_eq!(keys.key(20_000), a);
    }
}
