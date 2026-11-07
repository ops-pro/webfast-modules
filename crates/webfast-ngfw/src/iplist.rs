//! Address lists (`access.ip`, docs/ngfw.md): an `IpSet` of prefixes, and the `IpLists` of a
//! configuration: the static allow and deny lists, the deny files read again when they change, and
//! the feeds fetched every so often, all the denies in one set replaced whole under an `ArcSwap`.
//!
//! An `IpSet` is two binary tries (32 levels for IPv4, 128 for IPv6) in flat arrays: a lookup walks
//! one node per bit until a prefix ends (a hit) or a branch is missing (a miss), so an address that
//! is in no list — nearly every request — stops after about log2(entries) bits, some 16 dependent
//! loads from a few hundred KiB that stay in cache: tens of nanoseconds, nothing allocated.

use anyhow::Context;
use arc_swap::ArcSwap;
use bytes::Bytes;
use http::{HeaderMap, HeaderValue, Uri};
use ipnet::IpNet;
use std::net::IpAddr;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex, PoisonError};
use std::time::{Duration, Instant, SystemTime};

/// No child.
const NONE: u32 = u32::MAX;

/// A node of a trie: the children for a 0 and a 1 bit, and whether a prefix ends here.
#[derive(Clone, Copy)]
struct Node {
    child: [u32; 2],
    terminal: bool,
}

const EMPTY: Node = Node {
    child: [NONE, NONE],
    terminal: false,
};

/// A binary trie over the first `bits` bits of an address, the root at index 0.
struct Trie {
    nodes: Vec<Node>,
}

impl Trie {
    fn new() -> Trie {
        Trie { nodes: vec![EMPTY] }
    }

    /// Marks the prefix of `prefix_len` bits of `bits` (the address as an integer, the first bit
    /// highest); `true` when it was not there yet.
    fn insert(&mut self, bits: u128, width: u32, prefix_len: u8) -> bool {
        let mut node = 0usize;
        for i in 0..u32::from(prefix_len).min(width) {
            let bit = ((bits >> (width - 1 - i)) & 1) as usize;
            let next = self.nodes[node].child[bit];
            node = if next == NONE {
                let index = u32::try_from(self.nodes.len()).expect("a trie of fewer than 4G nodes");
                self.nodes.push(EMPTY);
                self.nodes[node].child[bit] = index;
                index as usize
            } else {
                next as usize
            };
        }
        !std::mem::replace(&mut self.nodes[node].terminal, true)
    }

    #[inline]
    fn contains(&self, bits: u128, width: u32) -> bool {
        let nodes = &self.nodes[..];
        let mut node = 0usize;
        for i in 0..width {
            let current = &nodes[node];
            if current.terminal {
                return true;
            }
            let bit = ((bits >> (width - 1 - i)) & 1) as usize;
            let next = current.child[bit];
            if next == NONE {
                return false;
            }
            node = next as usize;
        }
        nodes[node].terminal
    }
}

/// A set of networks, asked whether an address is in one of them.
pub struct IpSet {
    v4: Trie,
    v6: Trie,
    len: usize,
}

impl Default for IpSet {
    fn default() -> Self {
        IpSet::new()
    }
}

impl IpSet {
    pub fn new() -> IpSet {
        IpSet {
            v4: Trie::new(),
            v6: Trie::new(),
            len: 0,
        }
    }

    pub fn insert(&mut self, net: IpNet) {
        let new = match net {
            IpNet::V4(net) => self.v4.insert(u128::from(u32::from(net.addr())), 32, net.prefix_len()),
            IpNet::V6(net) => self.v6.insert(u128::from(net.addr()), 128, net.prefix_len()),
        };
        if new {
            self.len += 1;
        }
    }

    /// Whether `ip` is in one of the networks. An IPv4-mapped IPv6 address is its IPv4 address.
    #[inline]
    pub fn contains(&self, ip: IpAddr) -> bool {
        match ip.to_canonical() {
            IpAddr::V4(v4) => self.v4.contains(u128::from(u32::from(v4)), 32),
            IpAddr::V6(v6) => self.v6.contains(u128::from(v6), 128),
        }
    }

    /// Distinct networks inserted.
    pub fn len(&self) -> usize {
        self.len
    }

    pub fn is_empty(&self) -> bool {
        self.len == 0
    }

    /// One address or CIDR per line; `#` and `;` start a comment; blank lines skipped.
    pub fn parse(text: &str) -> anyhow::Result<IpSet> {
        let mut set = IpSet::new();
        for net in parse_entries(text)? {
            set.insert(net);
        }
        Ok(set)
    }
}

/// The networks of a list, in order; a bad line is an error naming its number.
fn parse_entries(text: &str) -> anyhow::Result<Vec<IpNet>> {
    let mut nets = Vec::new();
    for (index, line) in text.lines().enumerate() {
        let line = match line.find(['#', ';']) {
            Some(at) => &line[..at],
            None => line,
        };
        let entry = line.trim();
        if entry.is_empty() {
            continue;
        }
        let net = parse_net(entry).with_context(|| format!("line {}", index + 1))?;
        nets.push(net);
    }
    Ok(nets)
}

/// `203.0.113.0/24`, `203.0.113.7`, `2001:db8::/32`.
pub(crate) fn parse_net(text: &str) -> anyhow::Result<IpNet> {
    if let Ok(net) = text.parse::<IpNet>() {
        return Ok(net);
    }
    match text.parse::<IpAddr>() {
        Ok(ip) => Ok(IpNet::from(ip)),
        Err(_) => anyhow::bail!("{text:?} is not an address or a CIDR"),
    }
}

/// `access.ip` of the configuration.
#[derive(serde::Deserialize, Debug, Clone, Default)]
#[serde(deny_unknown_fields)]
pub struct IpConfig {
    #[serde(default)]
    pub allow: Vec<String>,
    #[serde(default)]
    pub deny: Vec<String>,
    /// Files of one address or CIDR per line, relative to the configuration file.
    #[serde(default)]
    pub deny_files: Vec<String>,
    #[serde(default)]
    pub feeds: Vec<FeedConfig>,
}

/// A list fetched over HTTP(S), in the files' format.
#[derive(serde::Deserialize, Debug, Clone)]
#[serde(deny_unknown_fields)]
pub struct FeedConfig {
    pub url: String,
    #[serde(default = "twelve_hours")]
    pub every: String,
}

fn twelve_hours() -> String {
    "12h".to_string()
}

/// `12h`, `30m`, `1d`: a count with a unit. The configuration's parser (`config.rs`) is the one
/// the module uses; this one reads `every` so the lists stand on their own.
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

/// At most this much of a feed is read.
const FEED_LIMIT: usize = 16 << 20;
const FEED_TIMEOUT: Duration = Duration::from_secs(30);

/// A deny file as last read.
struct DenyFile {
    path: PathBuf,
    mtime: Option<SystemTime>,
    nets: Vec<IpNet>,
}

/// A feed as last fetched: its entries and the validators to ask for a change only.
struct Feed {
    url: Uri,
    every: Duration,
    /// When it was last fetched, or tried.
    fetched: Option<Instant>,
    etag: Option<HeaderValue>,
    last_modified: Option<HeaderValue>,
    nets: Vec<IpNet>,
}

/// The lists of a configuration.
pub struct IpLists {
    allow: IpSet,
    /// `deny` and the files and feeds in one set, replaced whole when any changes.
    deny: ArcSwap<IpSet>,
    static_deny: Vec<IpNet>,
    files: Mutex<Vec<DenyFile>>,
    feeds: Mutex<Vec<Feed>>,
}

impl IpLists {
    /// Reads the files once; the feeds are empty until `fetch_feeds`.
    pub fn new(config: &IpConfig, base: &Path) -> anyhow::Result<IpLists> {
        let mut allow = IpSet::new();
        for entry in &config.allow {
            allow.insert(parse_net(entry).context("access.ip.allow")?);
        }
        let mut static_deny = Vec::with_capacity(config.deny.len());
        for entry in &config.deny {
            static_deny.push(parse_net(entry).context("access.ip.deny")?);
        }
        let mut files = Vec::with_capacity(config.deny_files.len());
        for name in &config.deny_files {
            let path = base.join(name);
            let (mtime, nets) = read_list(&path)?;
            files.push(DenyFile { path, mtime, nets });
        }
        let mut feeds = Vec::with_capacity(config.feeds.len());
        for feed in &config.feeds {
            let url: Uri = feed
                .url
                .parse()
                .with_context(|| format!("access.ip.feeds: {:?} is not a URL", feed.url))?;
            if url.scheme().is_none() || url.host().is_none() {
                anyhow::bail!("access.ip.feeds: {:?} is not an http(s) URL", feed.url);
            }
            let every = duration(&feed.every).with_context(|| format!("access.ip.feeds {}: every", feed.url))?;
            feeds.push(Feed {
                url,
                every: every.max(Duration::from_secs(60)),
                fetched: None,
                etag: None,
                last_modified: None,
                nets: Vec::new(),
            });
        }
        let lists = IpLists {
            allow,
            deny: ArcSwap::from_pointee(IpSet::new()),
            static_deny,
            files: Mutex::new(files),
            feeds: Mutex::new(feeds),
        };
        lists.rebuild();
        Ok(lists)
    }

    /// Whether `ip` is on the allow list (and passes everything else).
    #[inline]
    pub fn allowed(&self, ip: IpAddr) -> bool {
        self.allow.contains(ip)
    }

    /// Whether `ip` is on the deny list, a deny file or a feed.
    #[inline]
    pub fn denied(&self, ip: IpAddr) -> bool {
        self.deny.load().contains(ip)
    }

    /// Reads again the files whose mtime changed; `true` when the deny set was replaced. A file
    /// that cannot be read or parsed keeps its last entries; the others are still applied, and the
    /// first such error is returned.
    pub fn refresh_files(&self) -> anyhow::Result<bool> {
        let mut changed = false;
        let mut failed = None;
        {
            let mut files = self.files.lock().unwrap_or_else(PoisonError::into_inner);
            for file in files.iter_mut() {
                let mtime = match std::fs::metadata(&file.path).and_then(|m| m.modified()) {
                    Ok(mtime) => Some(mtime),
                    Err(e) => {
                        failed.get_or_insert_with(|| anyhow::anyhow!("{}: {e}", file.path.display()));
                        continue;
                    }
                };
                if mtime == file.mtime {
                    continue;
                }
                match read_list(&file.path) {
                    Ok((mtime, nets)) => {
                        file.mtime = mtime;
                        file.nets = nets;
                        changed = true;
                    }
                    Err(e) => {
                        failed.get_or_insert(e);
                    }
                }
            }
        }
        if changed {
            self.rebuild();
        }
        match failed {
            Some(error) => Err(error),
            None => Ok(changed),
        }
    }

    /// Fetches the feeds that are due (webfast_core::fetch); how many changed. A feed is asked for a
    /// change only (`If-None-Match`, `If-Modified-Since`) once it has been fetched; one that fails
    /// keeps its last entries and is tried again after its `every`. The feeds that fetched are
    /// applied; the first failure is returned.
    pub async fn fetch_feeds(&self, client: &webfast_core::fetch::Client) -> anyhow::Result<usize> {
        let now = Instant::now();
        let due: Vec<(usize, Uri, HeaderMap)> = {
            let feeds = self.feeds.lock().unwrap_or_else(PoisonError::into_inner);
            feeds
                .iter()
                .enumerate()
                .filter(|(_, feed)| {
                    feed.fetched
                        .is_none_or(|at| now.saturating_duration_since(at) >= feed.every)
                })
                .map(|(index, feed)| {
                    let mut headers = HeaderMap::new();
                    if let Some(etag) = &feed.etag {
                        headers.insert(http::header::IF_NONE_MATCH, etag.clone());
                    }
                    if let Some(date) = &feed.last_modified {
                        headers.insert(http::header::IF_MODIFIED_SINCE, date.clone());
                    }
                    (index, feed.url.clone(), headers)
                })
                .collect()
        };
        let mut changed = 0;
        let mut failed = None;
        for (index, url, headers) in due {
            let result = fetch_list(client, &url, &headers).await;
            let mut feeds = self.feeds.lock().unwrap_or_else(PoisonError::into_inner);
            let Some(feed) = feeds.get_mut(index) else { continue };
            feed.fetched = Some(Instant::now());
            match result {
                Ok(None) => {}
                Ok(Some((nets, etag, last_modified))) => {
                    feed.nets = nets;
                    feed.etag = etag;
                    feed.last_modified = last_modified;
                    changed += 1;
                }
                Err(e) => {
                    failed.get_or_insert(e);
                }
            }
        }
        if changed > 0 {
            self.rebuild();
        }
        match failed {
            Some(error) => Err(error),
            None => Ok(changed),
        }
    }

    /// Entries on the allow list and in the deny set.
    pub fn counts(&self) -> (usize, usize) {
        (self.allow.len(), self.deny.load().len())
    }

    /// The deny set from the static list, the files and the feeds, put in place of the old one.
    fn rebuild(&self) {
        let mut set = IpSet::new();
        for net in &self.static_deny {
            set.insert(*net);
        }
        for file in self.files.lock().unwrap_or_else(PoisonError::into_inner).iter() {
            for net in &file.nets {
                set.insert(*net);
            }
        }
        for feed in self.feeds.lock().unwrap_or_else(PoisonError::into_inner).iter() {
            for net in &feed.nets {
                set.insert(*net);
            }
        }
        self.deny.store(Arc::new(set));
    }
}

/// A deny file: its mtime and its entries.
fn read_list(path: &Path) -> anyhow::Result<(Option<SystemTime>, Vec<IpNet>)> {
    let text = std::fs::read_to_string(path).with_context(|| path.display().to_string())?;
    let mtime = std::fs::metadata(path).and_then(|m| m.modified()).ok();
    let nets = parse_entries(&text).with_context(|| path.display().to_string())?;
    Ok((mtime, nets))
}

/// One fetch of a feed: `None` when it has not changed (304), else its entries and validators.
async fn fetch_list(
    client: &webfast_core::fetch::Client,
    url: &Uri,
    headers: &HeaderMap,
) -> anyhow::Result<Option<(Vec<IpNet>, Option<HeaderValue>, Option<HeaderValue>)>> {
    let fetched = webfast_core::fetch::get(client, url, headers, FEED_LIMIT, FEED_TIMEOUT).await?;
    if fetched.status == http::StatusCode::NOT_MODIFIED && !headers.is_empty() {
        return Ok(None);
    }
    if !fetched.status.is_success() {
        anyhow::bail!("GET {url}: {}", fetched.status);
    }
    let nets = parse_feed(&fetched.body).with_context(|| format!("GET {url}"))?;
    let etag = fetched.headers.get(http::header::ETAG).cloned();
    let last_modified = fetched.headers.get(http::header::LAST_MODIFIED).cloned();
    Ok(Some((nets, etag, last_modified)))
}

fn parse_feed(body: &Bytes) -> anyhow::Result<Vec<IpNet>> {
    let text = std::str::from_utf8(body).context("the list is not UTF-8")?;
    parse_entries(text)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ip(text: &str) -> IpAddr {
        text.parse().unwrap()
    }

    fn set(entries: &[&str]) -> IpSet {
        let mut set = IpSet::new();
        for entry in entries {
            set.insert(parse_net(entry).unwrap());
        }
        set
    }

    #[test]
    fn v4_prefixes_and_edges() {
        let set = set(&["203.0.113.0/24", "198.51.100.7", "10.0.0.0/8", "0.0.0.0/1"]);
        assert_eq!(set.len(), 4);
        assert!(set.contains(ip("203.0.113.0")));
        assert!(set.contains(ip("203.0.113.255")));
        assert!(!set.contains(ip("203.0.114.0")));
        assert!(!set.contains(ip("203.0.112.255")));
        assert!(set.contains(ip("198.51.100.7")));
        assert!(!set.contains(ip("198.51.100.6")));
        assert!(!set.contains(ip("198.51.100.8")));
        assert!(set.contains(ip("10.255.255.255")));
        assert!(
            set.contains(ip("127.255.255.255")),
            "0.0.0.0/1 takes everything under 128"
        );
        assert!(!set.contains(ip("128.0.0.0")));
        assert!(
            set.contains(ip("::ffff:203.0.113.9")),
            "an IPv4-mapped address is its IPv4 one"
        );
        assert!(!set.contains(ip("2001:db8::1")), "the v6 trie is empty");
        assert!(!set.contains(ip("::")));
    }

    #[test]
    fn v6_prefixes_and_edges() {
        let set = set(&["2001:db8::/32", "2001:db8:1::/48", "::1", "fe80::/10"]);
        assert_eq!(set.len(), 4);
        assert!(set.contains(ip("2001:db8::")));
        assert!(set.contains(ip("2001:db8:ffff:ffff:ffff:ffff:ffff:ffff")));
        assert!(!set.contains(ip("2001:db9::")));
        assert!(!set.contains(ip("2001:db7:ffff::")));
        assert!(set.contains(ip("2001:db8:1::1")), "the /48 inside the /32");
        assert!(set.contains(ip("::1")));
        assert!(!set.contains(ip("::2")));
        assert!(set.contains(ip("febf:ffff::1")));
        assert!(!set.contains(ip("fec0::1")));
        assert!(!set.contains(ip("203.0.113.1")), "the v4 trie is empty");
    }

    #[test]
    fn overlapping_prefixes_and_the_whole_space() {
        let mut set = set(&["10.1.0.0/16", "10.0.0.0/8", "10.1.2.0/24", "10.1.0.0/16"]);
        assert_eq!(set.len(), 3, "a repeated network counts once");
        assert!(set.contains(ip("10.1.2.3")));
        assert!(set.contains(ip("10.9.9.9")));
        assert!(!set.contains(ip("9.255.255.255")));
        set.insert("0.0.0.0/0".parse().unwrap());
        assert!(set.contains(ip("9.255.255.255")), "/0 takes everything");
        assert!(set.contains(ip("255.255.255.255")));
        assert!(!set.contains(ip("::1")), "but only of IPv4");
        set.insert("::/0".parse().unwrap());
        assert!(set.contains(ip("::1")));
        assert!(IpSet::new().is_empty());
        assert!(!IpSet::new().contains(ip("0.0.0.0")));
        assert!(!IpSet::new().contains(ip("::")));
    }

    #[test]
    fn a_host_bits_network_is_its_prefix() {
        let set = set(&["203.0.113.77/24"]);
        assert!(set.contains(ip("203.0.113.1")));
        assert!(!set.contains(ip("203.0.112.77")));
    }

    #[test]
    fn lists_are_parsed_with_comments_and_crlf() {
        let text =
            "# the deny list\r\n203.0.113.0/24 ; SBL1\r\n\r\n  198.51.100.7  \r\n2001:db8::/32 # docs\n;a whole line\n";
        let set = IpSet::parse(text).unwrap();
        assert_eq!(set.len(), 3);
        assert!(set.contains(ip("203.0.113.9")));
        assert!(set.contains(ip("198.51.100.7")));
        assert!(set.contains(ip("2001:db8::9")));
        assert!(IpSet::parse("").unwrap().is_empty());
        let error = IpSet::parse("10.0.0.0/8\nnot-an-address\n").err().unwrap().to_string();
        assert!(error.contains("line 2"), "{error:?}");
        let error = format!("{:#}", IpSet::parse("10.0.0.0/8\n10.0.0.0/33\n").err().unwrap());
        assert!(error.contains("line 2") && error.contains("10.0.0.0/33"), "{error:?}");
    }

    #[test]
    fn lists_from_a_configuration_and_a_file_refreshed_by_mtime() {
        let dir = tempfile::tempdir().unwrap();
        let file = dir.path().join("blocklist.txt");
        std::fs::write(&file, "198.51.100.0/24\n").unwrap();
        let config = IpConfig {
            allow: vec!["10.0.0.0/8".into(), "203.0.113.7".into()],
            deny: vec!["192.0.2.0/24".into()],
            deny_files: vec!["blocklist.txt".into()],
            feeds: vec![FeedConfig {
                url: "https://example.com/drop.txt".into(),
                every: "12h".into(),
            }],
        };
        let lists = IpLists::new(&config, dir.path()).unwrap();
        assert!(lists.allowed(ip("10.1.2.3")) && lists.allowed(ip("203.0.113.7")));
        assert!(!lists.allowed(ip("203.0.113.8")));
        assert!(lists.denied(ip("192.0.2.1")), "the static list");
        assert!(lists.denied(ip("198.51.100.1")), "the file");
        assert!(!lists.denied(ip("198.51.101.1")));
        assert_eq!(lists.counts(), (2, 2));

        assert!(!lists.refresh_files().unwrap(), "nothing changed");
        std::fs::write(&file, "198.51.100.0/24\n2001:db8::/32\n").unwrap();
        let later = SystemTime::now() + Duration::from_secs(5);
        std::fs::File::options()
            .write(true)
            .open(&file)
            .unwrap()
            .set_modified(later)
            .unwrap();
        assert!(lists.refresh_files().unwrap(), "the file changed");
        assert!(lists.denied(ip("2001:db8::1")));
        assert_eq!(lists.counts(), (2, 3));

        // A file that no longer parses: the last entries stay, the error names it.
        std::fs::write(&file, "bad line\n").unwrap();
        std::fs::File::options()
            .write(true)
            .open(&file)
            .unwrap()
            .set_modified(later + Duration::from_secs(5))
            .unwrap();
        let error = format!("{:#}", lists.refresh_files().unwrap_err());
        assert!(error.contains("blocklist.txt") && error.contains("line 1"), "{error:?}");
        assert!(lists.denied(ip("2001:db8::1")));
    }

    #[test]
    fn a_missing_file_or_a_bad_entry_is_an_error_at_start() {
        let dir = tempfile::tempdir().unwrap();
        let config = IpConfig {
            deny_files: vec!["missing.txt".into()],
            ..IpConfig::default()
        };
        let error = format!("{:#}", IpLists::new(&config, dir.path()).err().unwrap());
        assert!(error.contains("missing.txt"), "{error:?}");
        let config = IpConfig {
            allow: vec!["10.0.0.0/8".into(), "lan".into()],
            ..IpConfig::default()
        };
        let error = format!("{:#}", IpLists::new(&config, dir.path()).err().unwrap());
        assert!(error.contains("access.ip.allow") && error.contains("lan"), "{error:?}");
        let config = IpConfig {
            feeds: vec![FeedConfig {
                url: "drop.txt".into(),
                every: "12h".into(),
            }],
            ..IpConfig::default()
        };
        assert!(IpLists::new(&config, dir.path()).is_err(), "a relative URL");
        let config = IpConfig {
            feeds: vec![FeedConfig {
                url: "https://example.com/drop.txt".into(),
                every: "often".into(),
            }],
            ..IpConfig::default()
        };
        assert!(IpLists::new(&config, dir.path()).is_err(), "a bad duration");
    }

    #[test]
    fn configuration_is_read() {
        let config: IpConfig = webfast_core::yaml::from_str(
            "allow: [10.0.0.0/8]\ndeny_files: [blocklist.txt]\nfeeds:\n  - url: https://example.com/drop.txt\n    every: 6h\n  - url: https://example.com/edrop.txt\n",
        )
        .unwrap();
        assert_eq!(config.allow, ["10.0.0.0/8"]);
        assert!(config.deny.is_empty());
        assert_eq!(config.feeds.len(), 2);
        assert_eq!(config.feeds[0].every, "6h");
        assert_eq!(config.feeds[1].every, "12h", "the default");
        assert!(
            webfast_core::yaml::from_str::<IpConfig>("block: [10.0.0.0/8]\n").is_err(),
            "an unknown key"
        );
        assert!(
            webfast_core::yaml::from_str::<IpConfig>("feeds: [{every: 1h}]\n").is_err(),
            "a feed needs its URL"
        );
    }

    #[test]
    fn a_large_set_is_fast_enough() {
        // Tens of thousands of /24s: a miss walks some 16 levels, a hit 24.
        let mut set = IpSet::new();
        for i in 0..50_000u32 {
            let addr = std::net::Ipv4Addr::from(0x0100_0000 + ((i * 7919) % 0x00fe_ffff) * 256);
            set.insert(IpNet::V4(ipnet::Ipv4Net::new(addr, 24).unwrap()));
        }
        assert!(set.len() > 40_000);
        let hit = ip("1.0.0.1");
        assert!(set.contains(hit));
        let miss = ip("203.0.113.9");
        let started = Instant::now();
        let mut found = 0u32;
        for i in 0..1_000_000u32 {
            found += u32::from(set.contains(if i % 2 == 0 { hit } else { miss }));
        }
        let per_lookup = started.elapsed() / 1_000_000;
        assert_eq!(found, 500_000);
        // Generous: debug builds are many times slower than release; this guards against a
        // regression to something that allocates or walks the whole set.
        assert!(per_lookup < Duration::from_micros(5), "{per_lookup:?} per lookup");
    }
}
