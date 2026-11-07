//! Country and ASN of a client address (`geo`, docs/ngfw.md) from MaxMind DB files: GeoLite2 or
//! DB-IP Lite, Country and ASN. The files are read whole into memory and kept under an `ArcSwap`;
//! `reload_if_changed` reads them again when their mtime changed and puts the new readers in place
//! of the old (a failing file keeps the old). A lookup decodes the record borrowed from the file's
//! bytes (`&str` fields), so nothing is allocated for it: about a hundred nanoseconds.

use anyhow::Context;
use arc_swap::ArcSwap;
use maxminddb::Reader;
use std::net::IpAddr;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex, PoisonError};
use std::time::SystemTime;

/// `geo` of the configuration.
#[derive(serde::Deserialize, Debug, Clone, Default)]
#[serde(deny_unknown_fields)]
pub struct GeoConfig {
    /// A Country database (mmdb), relative to the configuration file.
    pub country_db: Option<String>,
    /// An ASN database (mmdb), relative to the configuration file.
    pub asn_db: Option<String>,
    /// How often the files are checked for a change (and the address lists' files).
    #[serde(default = "day")]
    pub reload: String,
    /// A header set on the request going on with the country's code, or `--`.
    pub header: Option<String>,
}

fn day() -> String {
    "24h".to_string()
}

/// The open readers; in `Arc`s so that a reload of one file keeps the other's reader as it is.
#[derive(Default)]
struct Databases {
    country: Option<Arc<Reader<Vec<u8>>>>,
    asn: Option<Arc<Reader<Vec<u8>>>>,
}

/// A database file as last read.
struct File {
    path: PathBuf,
    mtime: Option<SystemTime>,
}

/// The geo databases of a configuration.
pub struct Geo {
    databases: ArcSwap<Databases>,
    country: Option<Mutex<File>>,
    asn: Option<Mutex<File>>,
}

/// The record of a Country database, as much of it as is looked at. `registered_country` stands
/// in when `country` is missing (an address whose location is unknown but whose registrant is not).
#[derive(serde::Deserialize)]
struct CountryRecord<'a> {
    #[serde(borrow)]
    country: Option<Named<'a>>,
    #[serde(borrow)]
    registered_country: Option<Named<'a>>,
}

#[derive(serde::Deserialize)]
struct Named<'a> {
    iso_code: Option<&'a str>,
}

/// The record of an ASN database, as much of it as is looked at.
#[derive(serde::Deserialize)]
struct AsnRecord {
    autonomous_system_number: Option<u32>,
}

impl Geo {
    /// Opens the files named, relative to `base`. Without any, every lookup is `None`.
    pub fn open(config: &GeoConfig, base: &Path) -> anyhow::Result<Geo> {
        let file = |name: &Option<String>| name.as_ref().map(|name| base.join(name));
        let country = file(&config.country_db);
        let asn = file(&config.asn_db);
        let mut databases = Databases::default();
        let mut mtimes = (None, None);
        if let Some(path) = &country {
            let (reader, mtime) = read(path).context("geo.country_db")?;
            databases.country = Some(reader);
            mtimes.0 = mtime;
        }
        if let Some(path) = &asn {
            let (reader, mtime) = read(path).context("geo.asn_db")?;
            databases.asn = Some(reader);
            mtimes.1 = mtime;
        }
        Ok(Geo {
            databases: ArcSwap::from_pointee(databases),
            country: country.map(|path| Mutex::new(File { path, mtime: mtimes.0 })),
            asn: asn.map(|path| Mutex::new(File { path, mtime: mtimes.1 })),
        })
    }

    /// The upper-case ISO 3166-1 alpha-2 code of the country `ip` is in (GeoLite2: `country`, or
    /// `registered_country`); `None` without a database or for an address it does not have.
    pub fn country(&self, ip: IpAddr) -> Option<[u8; 2]> {
        let databases = self.databases.load();
        let reader = databases.country.as_ref()?;
        let record: CountryRecord = reader.lookup(ip.to_canonical()).ok()?.decode().ok().flatten()?;
        let code = record
            .country
            .and_then(|c| c.iso_code)
            .or_else(|| record.registered_country.and_then(|c| c.iso_code))?;
        let code = code.as_bytes();
        if code.len() != 2 || !code.iter().all(u8::is_ascii_alphabetic) {
            return None;
        }
        Some([code[0].to_ascii_uppercase(), code[1].to_ascii_uppercase()])
    }

    /// The autonomous system `ip` is announced from; `None` without a database or for an address
    /// it does not have.
    pub fn asn(&self, ip: IpAddr) -> Option<u32> {
        let databases = self.databases.load();
        let reader = databases.asn.as_ref()?;
        let record: AsnRecord = reader.lookup(ip.to_canonical()).ok()?.decode().ok().flatten()?;
        record.autonomous_system_number
    }

    /// Reads again the files whose mtime changed and puts the new readers in place; `true` when
    /// one was replaced. A file that does not read keeps its old reader, and its error is returned
    /// after the other has been replaced.
    pub fn reload_if_changed(&self) -> anyhow::Result<bool> {
        let mut country = None;
        let mut asn = None;
        let mut failed = None;
        let files = [
            (&self.country, &mut country, "geo.country_db"),
            (&self.asn, &mut asn, "geo.asn_db"),
        ];
        for (file, slot, what) in files {
            let Some(file) = file else { continue };
            let mut file = file.lock().unwrap_or_else(PoisonError::into_inner);
            match std::fs::metadata(&file.path).and_then(|m| m.modified()) {
                Ok(mtime) if Some(mtime) == file.mtime => {}
                Ok(_) => match read(&file.path) {
                    Ok((reader, mtime)) => {
                        file.mtime = mtime;
                        *slot = Some(reader);
                    }
                    Err(e) => {
                        failed.get_or_insert(e.context(what));
                    }
                },
                Err(e) => {
                    failed.get_or_insert(anyhow::anyhow!("{}: {e}", file.path.display()).context(what));
                }
            }
        }
        let changed = country.is_some() || asn.is_some();
        if changed {
            // The reader not replaced is the current one, shared.
            self.databases.rcu(|current| Databases {
                country: country.clone().or_else(|| current.country.clone()),
                asn: asn.clone().or_else(|| current.asn.clone()),
            });
        }
        match failed {
            Some(error) => Err(error),
            None => Ok(changed),
        }
    }

    pub fn has_country(&self) -> bool {
        self.country.is_some()
    }

    pub fn has_asn(&self) -> bool {
        self.asn.is_some()
    }
}

/// A database file as opened: its reader and its mtime.
type Opened = (Arc<Reader<Vec<u8>>>, Option<SystemTime>);

/// A database file: its reader and its mtime.
fn read(path: &Path) -> anyhow::Result<Opened> {
    let reader = Reader::open_readfile(path).with_context(|| path.display().to_string())?;
    let mtime = std::fs::metadata(path).and_then(|m| m.modified()).ok();
    Ok((Arc::new(reader), mtime))
}

#[cfg(test)]
mod tests {
    //! The databases are made here: the crate ships no test data and no writer. The format
    //! (maxmind.github.io/MaxMind-DB): a binary search tree of `node_count` nodes, two records of
    //! `record_size` bits each (a node number, `node_count` for no data, or a data offset plus
    //! `node_count` + 16), 16 zero bytes, the data section, the metadata marker and the metadata map.

    use super::*;
    use std::time::Duration;

    /// A record of a search tree node.
    #[derive(Clone, Copy)]
    enum Record {
        Empty,
        Node(usize),
        Data(usize),
    }

    /// The data section: values encoded as the format has them (control byte: type in the top
    /// three bits, size in the low five; extended types in a second byte).
    #[derive(Default)]
    struct Data(Vec<u8>);

    impl Data {
        /// Sizes under 29 are in the control byte; up to 284 in one more byte, less 29.
        fn control(&mut self, kind: u8, size: usize) {
            assert!(size < 285);
            let (in_control, extra) = if size < 29 {
                (size as u8, None)
            } else {
                (29, Some((size - 29) as u8))
            };
            if kind < 8 {
                self.0.push((kind << 5) | in_control);
            } else {
                self.0.push(in_control);
                self.0.push(kind - 7);
            }
            self.0.extend(extra);
        }

        fn string(&mut self, text: &str) {
            self.control(2, text.len());
            self.0.extend_from_slice(text.as_bytes());
        }

        fn u16(&mut self, n: u16) {
            self.control(5, 2);
            self.0.extend_from_slice(&n.to_be_bytes());
        }

        fn u32(&mut self, n: u32) {
            self.control(6, 4);
            self.0.extend_from_slice(&n.to_be_bytes());
        }

        fn u64(&mut self, n: u64) {
            self.control(9, 8);
            self.0.extend_from_slice(&n.to_be_bytes());
        }

        fn map(&mut self, entries: usize) {
            self.control(7, entries);
        }

        fn array(&mut self, entries: usize) {
            self.control(11, entries);
        }

        /// A country record: `country.iso_code` (or none) and `registered_country.iso_code`.
        fn country(&mut self, country: Option<&str>, registered: &str) -> usize {
            let at = self.0.len();
            self.map(1 + usize::from(country.is_some()));
            if let Some(code) = country {
                self.string("country");
                self.map(2);
                self.string("geoname_id");
                self.u32(2750405);
                self.string("iso_code");
                self.string(code);
            }
            self.string("registered_country");
            self.map(1);
            self.string("iso_code");
            self.string(registered);
            at
        }

        fn asn(&mut self, number: u32, organization: &str) -> usize {
            let at = self.0.len();
            self.map(2);
            self.string("autonomous_system_number");
            self.u32(number);
            self.string("autonomous_system_organization");
            self.string(organization);
            at
        }
    }

    /// An IPv6 search tree (IPv4 under ::/96, as GeoLite2 has it) over 24-bit records.
    struct Tree {
        nodes: Vec<[Record; 2]>,
    }

    impl Tree {
        fn new() -> Tree {
            Tree {
                nodes: vec![[Record::Empty, Record::Empty]],
            }
        }

        fn insert(&mut self, net: &str, data: usize) {
            let net: ipnet::IpNet = net.parse().unwrap();
            let (bits, prefix_len) = match net {
                ipnet::IpNet::V4(net) => (u128::from(u32::from(net.addr())), 96 + usize::from(net.prefix_len())),
                ipnet::IpNet::V6(net) => (u128::from(net.addr()), usize::from(net.prefix_len())),
            };
            let mut node = 0;
            for depth in 0..prefix_len {
                let bit = ((bits >> (127 - depth)) & 1) as usize;
                if depth + 1 == prefix_len {
                    self.nodes[node][bit] = Record::Data(data);
                    return;
                }
                node = match self.nodes[node][bit] {
                    Record::Node(next) => next,
                    _ => {
                        self.nodes.push([Record::Empty, Record::Empty]);
                        let next = self.nodes.len() - 1;
                        self.nodes[node][bit] = Record::Node(next);
                        next
                    }
                };
            }
        }

        fn file(&self, data: &Data, database_type: &str) -> Vec<u8> {
            let node_count = self.nodes.len();
            let mut file = Vec::new();
            for node in &self.nodes {
                for record in node {
                    let value = match *record {
                        Record::Empty => node_count,
                        Record::Node(n) => n,
                        Record::Data(offset) => offset + node_count + 16,
                    };
                    file.extend_from_slice(&value.to_be_bytes()[5..8]);
                }
            }
            file.extend_from_slice(&[0; 16]);
            file.extend_from_slice(&data.0);
            file.extend_from_slice(b"\xab\xcd\xefMaxMind.com");
            let mut metadata = Data::default();
            metadata.map(9);
            metadata.string("node_count");
            metadata.u32(node_count as u32);
            metadata.string("record_size");
            metadata.u16(24);
            metadata.string("ip_version");
            metadata.u16(6);
            metadata.string("database_type");
            metadata.string(database_type);
            metadata.string("languages");
            metadata.array(1);
            metadata.string("en");
            metadata.string("binary_format_major_version");
            metadata.u16(2);
            metadata.string("binary_format_minor_version");
            metadata.u16(0);
            metadata.string("build_epoch");
            metadata.u64(1_760_788_800);
            metadata.string("description");
            metadata.map(1);
            metadata.string("en");
            metadata.string("a test database");
            file.extend_from_slice(&metadata.0);
            file
        }
    }

    fn country_db(entries: &[(&str, Option<&str>, &str)]) -> Vec<u8> {
        let mut data = Data::default();
        let mut tree = Tree::new();
        for (net, country, registered) in entries {
            let at = data.country(*country, registered);
            tree.insert(net, at);
        }
        tree.file(&data, "GeoLite2-Country")
    }

    fn asn_db(entries: &[(&str, u32, &str)]) -> Vec<u8> {
        let mut data = Data::default();
        let mut tree = Tree::new();
        for (net, number, organization) in entries {
            let at = data.asn(*number, organization);
            tree.insert(net, at);
        }
        tree.file(&data, "GeoLite2-ASN")
    }

    fn ip(text: &str) -> IpAddr {
        text.parse().unwrap()
    }

    fn touch(path: &Path, later_by: Duration) {
        std::fs::File::options()
            .write(true)
            .open(path)
            .unwrap()
            .set_modified(SystemTime::now() + later_by)
            .unwrap();
    }

    #[test]
    fn countries_and_asns_are_looked_up() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(
            dir.path().join("country.mmdb"),
            country_db(&[
                ("203.0.113.0/24", Some("NL"), "NL"),
                ("198.51.100.0/24", None, "de"),
                ("2001:db8::/32", Some("KP"), "KP"),
            ]),
        )
        .unwrap();
        std::fs::write(
            dir.path().join("asn.mmdb"),
            asn_db(&[
                ("203.0.113.0/24", 1136, "KPN B.V."),
                ("2001:db8::/32", 64512, "Example"),
            ]),
        )
        .unwrap();
        let config = GeoConfig {
            country_db: Some("country.mmdb".into()),
            asn_db: Some("asn.mmdb".into()),
            ..GeoConfig::default()
        };
        let geo = Geo::open(&config, dir.path()).unwrap();
        assert!(geo.has_country() && geo.has_asn());
        assert_eq!(geo.country(ip("203.0.113.7")), Some(*b"NL"));
        assert_eq!(geo.country(ip("203.0.113.255")), Some(*b"NL"));
        assert_eq!(
            geo.country(ip("198.51.100.1")),
            Some(*b"DE"),
            "registered_country, upper-cased"
        );
        assert_eq!(geo.country(ip("2001:db8:1::1")), Some(*b"KP"));
        assert_eq!(
            geo.country(ip("::ffff:203.0.113.7")),
            Some(*b"NL"),
            "an IPv4-mapped address"
        );
        assert_eq!(geo.country(ip("10.0.0.1")), None, "not in the database");
        assert_eq!(geo.country(ip("2001:db9::1")), None);
        assert_eq!(geo.asn(ip("203.0.113.7")), Some(1136));
        assert_eq!(geo.asn(ip("2001:db8::1")), Some(64512));
        assert_eq!(geo.asn(ip("198.51.100.1")), None);
        assert!(!geo.reload_if_changed().unwrap(), "nothing changed");
    }

    #[test]
    fn without_databases() {
        let dir = tempfile::tempdir().unwrap();
        let geo = Geo::open(&GeoConfig::default(), dir.path()).unwrap();
        assert!(!geo.has_country() && !geo.has_asn());
        assert_eq!(geo.country(ip("203.0.113.7")), None);
        assert_eq!(geo.asn(ip("203.0.113.7")), None);
        assert!(!geo.reload_if_changed().unwrap());
    }

    #[test]
    fn a_missing_or_broken_file_is_an_error() {
        let dir = tempfile::tempdir().unwrap();
        let config = GeoConfig {
            country_db: Some("missing.mmdb".into()),
            ..GeoConfig::default()
        };
        let error = format!("{:#}", Geo::open(&config, dir.path()).err().unwrap());
        assert!(
            error.contains("geo.country_db") && error.contains("missing.mmdb"),
            "{error}"
        );
        std::fs::write(dir.path().join("broken.mmdb"), b"not a database").unwrap();
        let config = GeoConfig {
            asn_db: Some("broken.mmdb".into()),
            ..GeoConfig::default()
        };
        let error = format!("{:#}", Geo::open(&config, dir.path()).err().unwrap());
        assert!(error.contains("geo.asn_db"), "{error}");
    }

    #[test]
    fn files_are_reloaded_when_their_mtime_changes() {
        let dir = tempfile::tempdir().unwrap();
        let country = dir.path().join("country.mmdb");
        let asn = dir.path().join("asn.mmdb");
        std::fs::write(&country, country_db(&[("203.0.113.0/24", Some("NL"), "NL")])).unwrap();
        std::fs::write(&asn, asn_db(&[("203.0.113.0/24", 1136, "KPN")])).unwrap();
        let config = GeoConfig {
            country_db: Some("country.mmdb".into()),
            asn_db: Some("asn.mmdb".into()),
            ..GeoConfig::default()
        };
        let geo = Geo::open(&config, dir.path()).unwrap();
        assert_eq!(geo.country(ip("203.0.113.7")), Some(*b"NL"));

        // The country file changes: read again; the ASN reader stays.
        std::fs::write(&country, country_db(&[("203.0.113.0/24", Some("BE"), "BE")])).unwrap();
        touch(&country, Duration::from_secs(5));
        assert!(geo.reload_if_changed().unwrap());
        assert_eq!(geo.country(ip("203.0.113.7")), Some(*b"BE"));
        assert_eq!(geo.asn(ip("203.0.113.7")), Some(1136));
        assert!(!geo.reload_if_changed().unwrap());

        // A broken file: the error names it, the old reader stays, and the other file's change
        // is still taken.
        std::fs::write(&country, b"half-written").unwrap();
        touch(&country, Duration::from_secs(10));
        std::fs::write(&asn, asn_db(&[("203.0.113.0/24", 64512, "Example")])).unwrap();
        touch(&asn, Duration::from_secs(10));
        let error = format!("{:#}", geo.reload_if_changed().unwrap_err());
        assert!(error.contains("geo.country_db"), "{error}");
        assert_eq!(geo.country(ip("203.0.113.7")), Some(*b"BE"));
        assert_eq!(geo.asn(ip("203.0.113.7")), Some(64512));

        // Fixed: read again (its mtime differs from the one last read).
        std::fs::write(&country, country_db(&[("203.0.113.0/24", Some("NL"), "NL")])).unwrap();
        touch(&country, Duration::from_secs(15));
        assert!(geo.reload_if_changed().unwrap());
        assert_eq!(geo.country(ip("203.0.113.7")), Some(*b"NL"));
    }

    #[test]
    fn configuration_is_read() {
        let config: GeoConfig =
            webfast_core::yaml::from_str("country_db: GeoLite2-Country.mmdb\nheader: X-Client-Country\n").unwrap();
        assert_eq!(config.country_db.as_deref(), Some("GeoLite2-Country.mmdb"));
        assert_eq!(config.asn_db, None);
        assert_eq!(config.reload, "24h", "the default");
        assert_eq!(config.header.as_deref(), Some("X-Client-Country"));
        assert!(
            webfast_core::yaml::from_str::<GeoConfig>("city_db: x.mmdb\n").is_err(),
            "an unknown key"
        );
    }
}
