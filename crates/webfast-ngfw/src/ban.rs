//! The ban list (`access.ban`, docs/ngfw.md): refusals counted per client address in a window, and
//! an address banned for a duration once it has `on_blocks` of them, or at once by a honeypot path
//! or a rule with `action: ban`. With `then: challenge`, reaching `on_blocks` marks the address for
//! the browser challenge instead (docs/challenge.md): `banned` stays false for it, `challenged`
//! says so, and the mark lasts `for`; honeypots and `action: ban` ban whatever `then` says.
//!
//! The window is fixed: it opens with an address's first refusal and the count starts again at the
//! first refusal after it has closed. A sliding window would need every refusal's time per address;
//! this needs one `Instant` and a count, and bans at most one window later than a sliding one would.
//!
//! The addresses are in 64 shards, each a `Mutex<FxHashMap>` padded to its own cache lines, so the
//! request threads lock one shard for one address (`banned` is one lock and one lookup). The sweep,
//! on the module's worker, drops the entries whose ban and window are both over. Each process keeps
//! its own list.

use rustc_hash::FxHashMap;
use std::hash::BuildHasher;
use std::net::IpAddr;
use std::sync::{Mutex, PoisonError};
use std::time::{Duration, Instant};

const SHARDS: usize = 64;

/// `access.ban` of the configuration.
#[derive(serde::Deserialize, Debug, Clone, Default)]
#[serde(deny_unknown_fields)]
pub struct BanConfig {
    /// This many refusals within `window`: banned. 0: refusals never ban by count.
    #[serde(default)]
    pub on_blocks: u32,
    #[serde(default = "ten_minutes")]
    pub window: String,
    #[serde(default = "one_hour")]
    pub r#for: String,
    /// Paths (patterns, as the Caddyfile's `path` matcher) that ban on one request; matched by the
    /// engine, not here.
    #[serde(default)]
    pub honeypots: Vec<String>,
    /// What reaching `on_blocks` does: `ban`, or `challenge` (the address is asked the browser
    /// challenge for `for` instead; docs/challenge.md). Honeypots and `action: ban` always ban.
    #[serde(default)]
    pub then: Then,
}

/// `access.ban.then`.
#[derive(serde::Deserialize, Debug, Clone, Copy, PartialEq, Eq, Default)]
#[serde(rename_all = "snake_case")]
pub enum Then {
    #[default]
    Ban,
    Challenge,
}

fn ten_minutes() -> String {
    "10m".to_string()
}

fn one_hour() -> String {
    "1h".to_string()
}

/// `10m`, `1h`, `2d`, `30s`: a count with a unit. The configuration's parser (`config.rs`) is the
/// one the module uses; this one reads the two fields here so the list stands on its own.
fn duration(text: &str) -> anyhow::Result<Duration> {
    let text = text.trim();
    let split = text.find(|c: char| !c.is_ascii_digit()).unwrap_or(text.len());
    let (number, unit) = text.split_at(split);
    let number: u64 = number
        .parse()
        .map_err(|_| anyhow::anyhow!("{text:?}: a duration is a number with a unit (s, m, h, d)"))?;
    let seconds = match unit.trim() {
        "s" => number,
        "m" => number.saturating_mul(60),
        "h" => number.saturating_mul(3600),
        "d" => number.saturating_mul(86_400),
        _ => anyhow::bail!("{text:?}: a duration is a number with a unit (s, m, h, d)"),
    };
    Ok(Duration::from_secs(seconds))
}

/// One address: its refusals in the open window, and its ban or challenge mark.
struct Entry {
    /// Refusals since `window_start`.
    count: u32,
    /// `until` is a challenge mark (`then: challenge`), not a ban.
    challenged: bool,
    window_start: Instant,
    /// Banned, or challenged, until then.
    until: Option<Instant>,
}

impl Entry {
    fn fresh(now: Instant) -> Entry {
        Entry {
            count: 0,
            challenged: false,
            window_start: now,
            until: None,
        }
    }

    fn marked(&self, now: Instant) -> bool {
        self.until.is_some_and(|until| until > now)
    }
}

/// A shard on cache lines of its own: the lock of one is not bounced by the next.
#[repr(align(128))]
struct Shard(Mutex<FxHashMap<IpAddr, Entry>>);

/// The ban list.
pub struct Bans {
    shards: Box<[Shard]>,
    /// Which shard an address is in: hashed with a key of the process's own, so a client cannot
    /// choose its shard.
    hasher: std::hash::RandomState,
    on_blocks: u32,
    window: Duration,
    duration: Duration,
    then: Then,
}

impl Bans {
    pub fn new(config: &BanConfig) -> anyhow::Result<Bans> {
        // `BanConfig::default()` has empty strings where the file would have the serde defaults.
        let or = |text: &str, default: fn() -> String| {
            if text.trim().is_empty() {
                default()
            } else {
                text.to_string()
            }
        };
        let window =
            duration(&or(&config.window, ten_minutes)).map_err(|e| anyhow::anyhow!("access.ban.window: {e}"))?;
        let duration = duration(&or(&config.r#for, one_hour)).map_err(|e| anyhow::anyhow!("access.ban.for: {e}"))?;
        if duration.is_zero() {
            anyhow::bail!("access.ban.for: a ban lasts some time");
        }
        Ok(Bans {
            shards: (0..SHARDS).map(|_| Shard(Mutex::new(FxHashMap::default()))).collect(),
            hasher: std::hash::RandomState::new(),
            on_blocks: config.on_blocks,
            window: window.max(Duration::from_secs(1)),
            duration,
            then: config.then,
        })
    }

    fn shard(&self, ip: IpAddr) -> std::sync::MutexGuard<'_, FxHashMap<IpAddr, Entry>> {
        let index = (self.hasher.hash_one(ip) as usize) % SHARDS;
        self.shards[index].0.lock().unwrap_or_else(PoisonError::into_inner)
    }

    /// What `ip` is marked with at `now`: banned (`Then::Ban`), marked for the browser challenge
    /// (`Then::Challenge`, `then: challenge` reached), or nothing; one lock, one lookup.
    pub fn mark(&self, ip: IpAddr, now: Instant) -> Option<Then> {
        let shard = self.shard(ip);
        let entry = shard.get(&ip).filter(|entry| entry.marked(now))?;
        Some(if entry.challenged { Then::Challenge } else { Then::Ban })
    }

    /// Whether `ip` is banned at `now`. An address marked for the challenge is not banned.
    pub fn banned(&self, ip: IpAddr, now: Instant) -> bool {
        self.mark(ip, now) == Some(Then::Ban)
    }

    /// Whether `ip` is marked for the browser challenge at `now`.
    pub fn challenged(&self, ip: IpAddr, now: Instant) -> bool {
        self.mark(ip, now) == Some(Then::Challenge)
    }

    /// A refusal happened: counted in the window; `Some(then)` when the count reached `on_blocks`
    /// and the address is now banned, or marked for the challenge, for `for` from `now`. With
    /// `on_blocks` 0 nothing is counted.
    pub fn refused(&self, ip: IpAddr, now: Instant) -> Option<Then> {
        if self.on_blocks == 0 {
            return None;
        }
        let mut shard = self.shard(ip);
        let entry = shard.entry(ip).or_insert_with(|| Entry::fresh(now));
        if now.saturating_duration_since(entry.window_start) >= self.window {
            entry.count = 0;
            entry.window_start = now;
        }
        entry.count += 1;
        if entry.count >= self.on_blocks {
            entry.count = 0;
            // A ban already in force is not softened to a challenge mark.
            if !(entry.marked(now) && !entry.challenged) {
                entry.challenged = self.then == Then::Challenge;
            }
            entry.until = Some(now + self.duration);
            return Some(self.then);
        }
        None
    }

    /// Bans `ip` for `for`, from `now` (a honeypot, a rule with `action: ban`), whatever `then`.
    pub fn ban(&self, ip: IpAddr, now: Instant) {
        let mut shard = self.shard(ip);
        let entry = shard.entry(ip).or_insert_with(|| Entry::fresh(now));
        entry.count = 0;
        entry.challenged = false;
        entry.until = Some(now + self.duration);
    }

    /// Drops the entries whose ban or mark is over and whose window has closed.
    pub fn sweep(&self, now: Instant) {
        for shard in &self.shards {
            let mut shard = shard.0.lock().unwrap_or_else(PoisonError::into_inner);
            shard.retain(|_, entry| {
                let counting = entry.count > 0 && now.saturating_duration_since(entry.window_start) < self.window;
                entry.marked(now) || counting
            });
        }
    }

    /// Addresses in the list: banned, or with refusals counted in an open window (until swept).
    pub fn len(&self) -> usize {
        self.shards
            .iter()
            .map(|shard| shard.0.lock().unwrap_or_else(PoisonError::into_inner).len())
            .sum()
    }

    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    /// Addresses banned at `now`.
    pub fn banned_len(&self, now: Instant) -> usize {
        self.shards
            .iter()
            .map(|shard| {
                shard
                    .0
                    .lock()
                    .unwrap_or_else(PoisonError::into_inner)
                    .values()
                    .filter(|entry| !entry.challenged && entry.marked(now))
                    .count()
            })
            .sum()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn bans(on_blocks: u32, window: &str, r#for: &str) -> Bans {
        Bans::new(&BanConfig {
            on_blocks,
            window: window.to_string(),
            r#for: r#for.to_string(),
            honeypots: Vec::new(),
            then: Then::Ban,
        })
        .unwrap()
    }

    fn ip(text: &str) -> IpAddr {
        text.parse().unwrap()
    }

    #[test]
    fn refusals_in_the_window_ban_and_the_ban_expires() {
        let bans = bans(3, "10m", "1h");
        let now = Instant::now();
        let client = ip("203.0.113.7");
        assert!(bans.refused(client, now).is_none());
        assert!(bans.refused(client, now + Duration::from_secs(60)).is_none());
        assert!(!bans.banned(client, now + Duration::from_secs(61)));
        assert_eq!(
            bans.refused(client, now + Duration::from_secs(120)),
            Some(Then::Ban),
            "the third refusal bans"
        );
        assert!(bans.banned(client, now + Duration::from_secs(121)));
        assert!(bans.banned(client, now + Duration::from_secs(120 + 3599)));
        assert!(
            !bans.banned(client, now + Duration::from_secs(120 + 3600)),
            "the ban is over"
        );
        assert!(
            !bans.banned(ip("203.0.113.8"), now + Duration::from_secs(121)),
            "another address"
        );
        assert_eq!(bans.len(), 1);
    }

    #[test]
    fn the_window_is_fixed_from_the_first_refusal() {
        let bans = bans(3, "10m", "1h");
        let now = Instant::now();
        let client = ip("2001:db8::1");
        assert!(bans.refused(client, now).is_none());
        assert!(bans.refused(client, now + Duration::from_secs(300)).is_none());
        // The window closed: the count starts again.
        assert!(bans.refused(client, now + Duration::from_secs(600)).is_none());
        assert!(bans.refused(client, now + Duration::from_secs(601)).is_none());
        assert_eq!(bans.refused(client, now + Duration::from_secs(602)), Some(Then::Ban));
    }

    #[test]
    fn a_direct_ban_and_the_sweep() {
        let bans = bans(0, "10m", "30m");
        let now = Instant::now();
        let a = ip("198.51.100.1");
        let b = ip("198.51.100.2");
        assert!(bans.refused(a, now).is_none(), "on_blocks 0: refusals never ban");
        assert_eq!(bans.len(), 0, "and are not counted");
        bans.ban(a, now);
        bans.ban(b, now + Duration::from_secs(60));
        assert!(bans.banned(a, now + Duration::from_secs(1)));
        assert_eq!(bans.banned_len(now + Duration::from_secs(61)), 2);
        bans.sweep(now + Duration::from_secs(30 * 60 + 1));
        assert_eq!(bans.len(), 1, "a's ban is over, b's not");
        assert!(bans.banned(b, now + Duration::from_secs(30 * 60 + 1)));
        bans.sweep(now + Duration::from_secs(31 * 60 + 1));
        assert!(bans.is_empty());
    }

    #[test]
    fn the_sweep_keeps_an_open_window() {
        let bans = bans(5, "10m", "1h");
        let now = Instant::now();
        let client = ip("203.0.113.9");
        bans.refused(client, now);
        bans.sweep(now + Duration::from_secs(60));
        assert_eq!(bans.len(), 1, "still counting");
        bans.sweep(now + Duration::from_secs(600));
        assert_eq!(bans.len(), 0, "the window closed");
    }

    #[test]
    fn then_challenge_marks_instead_of_banning_and_a_direct_ban_still_bans() {
        let bans = Bans::new(&BanConfig {
            on_blocks: 2,
            window: "10m".to_string(),
            r#for: "1h".to_string(),
            honeypots: Vec::new(),
            then: Then::Challenge,
        })
        .unwrap();
        let now = Instant::now();
        let client = ip("203.0.113.7");
        assert!(bans.refused(client, now).is_none());
        assert_eq!(
            bans.refused(client, now + Duration::from_secs(1)),
            Some(Then::Challenge)
        );
        let later = now + Duration::from_secs(2);
        assert!(!bans.banned(client, later), "marked, not banned");
        assert!(bans.challenged(client, later));
        assert_eq!(bans.banned_len(later), 0);
        assert!(
            !bans.challenged(client, now + Duration::from_secs(3601)),
            "the mark is over"
        );
        bans.sweep(now + Duration::from_secs(3601));
        assert!(bans.is_empty());
        // A honeypot or `action: ban` bans whatever `then` says, and a ban is not softened.
        bans.ban(client, later);
        assert!(bans.banned(client, later + Duration::from_secs(1)));
        assert!(!bans.challenged(client, later + Duration::from_secs(1)));
        bans.refused(client, later + Duration::from_secs(2));
        assert_eq!(
            bans.refused(client, later + Duration::from_secs(3)),
            Some(Then::Challenge)
        );
        assert!(bans.banned(client, later + Duration::from_secs(4)), "still a ban");
        let config: BanConfig = webfast_core::yaml::from_str("on_blocks: 3\nthen: challenge\n").unwrap();
        assert_eq!(config.then, Then::Challenge);
        assert_eq!(BanConfig::default().then, Then::Ban);
        assert!(webfast_core::yaml::from_str::<BanConfig>("then: ask\n").is_err());
    }

    #[test]
    fn configuration() {
        assert!(Bans::new(&BanConfig::default()).is_ok(), "the defaults: 10m, 1h");
        assert_eq!(duration("10m").unwrap(), Duration::from_secs(600));
        assert_eq!(duration("2d").unwrap(), Duration::from_secs(172_800));
        assert_eq!(duration(" 30s ").unwrap(), Duration::from_secs(30));
        assert!(duration("10").is_err(), "a unit is required");
        assert!(duration("10x").is_err());
        assert!(duration("m").is_err());
        let error = bans_error("1h", "0s");
        assert!(error.contains("access.ban.for"), "{error}");
        let error = bans_error("soon", "1h");
        assert!(error.contains("access.ban.window"), "{error}");
        let config: BanConfig =
            webfast_core::yaml::from_str("on_blocks: 10\nwindow: 10m\nfor: 1h\nhoneypots: ['/wp-login.php']\n")
                .unwrap();
        assert_eq!(config.on_blocks, 10);
        assert_eq!(config.r#for, "1h");
        assert_eq!(config.honeypots, ["/wp-login.php"]);
        assert!(
            webfast_core::yaml::from_str::<BanConfig>("blocks: 10\n").is_err(),
            "an unknown key"
        );
    }

    fn bans_error(window: &str, r#for: &str) -> String {
        Bans::new(&BanConfig {
            on_blocks: 1,
            window: window.to_string(),
            r#for: r#for.to_string(),
            honeypots: Vec::new(),
            then: Then::Ban,
        })
        .err()
        .unwrap()
        .to_string()
    }
}
