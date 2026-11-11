//! The OWASP Core Rule Set for webfast's request filter (the `webfast-ngfw-crs` crate; the webfast
//! binary's cargo feature `ngfw-crs`; docs/ngfw-crs.md): the CRS v4 rules in SecLang, parsed at
//! load and run by an interpreter of their own, plugged into webfast-ngfw as a rule engine
//! (`webfast_ngfw::plugin`). Its hits are the filter's: one evaluation, one decision against the
//! filter's `threshold`, one log line (each hit with the CRS rule's id as `ruleId`, as go-ftw reads
//! it), one ban list, one challenge.
//!
//! The CRS is bundled (crs/rules, a pinned release, its request rules: phases 1 and 2); the
//! blocking evaluation (949) is the filter's, and the response rules are not loaded. The file's
//! `engines.crs` sets the paranoia level, the CRS's own variables (`crs-setup.conf`'s), the site's
//! SecLang files read before the CRS (exclusions by `ctl`) and after it (`SecRuleRemoveById`,
//! `SecRuleUpdateTargetById`), and rules removed by id.
//!
//! The pieces: seclang.rs reads the text, program.rs compiles the directives, request.rs gives
//! ModSecurity's variables of a request, transform.rs and ops.rs the transformations and the
//! operators, run.rs the interpreter.

mod bestfit;
mod bundled;
mod macros;
mod ops;
pub mod program;
mod request;
mod run;
mod seclang;
mod transform;

use anyhow::{Context, Result, bail};
use serde::Deserialize;
use std::collections::BTreeMap;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
use webfast_ngfw::engine::Input;
use webfast_ngfw::plugin::{Engine, EngineState, Factory, Found};
use webfast_ngfw::rule::Phase;

/// The CRS release bundled.
pub const CRS_VERSION: &str = "4.30.0";

/// `tx.crs_setup_version` for it (the CRS refuses every request without one).
const SETUP_VERSION: &str = "430";

/// The engine as webfast's composition registers it (`webfast_ngfw::plugin::register`).
pub struct Crs;

/// The one to register.
pub static ENGINE: Crs = Crs;

/// `engines.crs` in the filter's file.
#[derive(Deserialize, Debug, Default)]
#[serde(deny_unknown_fields)]
struct Config {
    /// The blocking paranoia level, 1 to 4 (default 1).
    #[serde(default)]
    paranoia: Option<u8>,
    /// The detection paranoia level, at least the blocking one (default: the same): the rules
    /// above the blocking level are written, not scored.
    #[serde(default)]
    detection_paranoia: Option<u8>,
    /// The CRS's own variables (`crs-setup.conf`'s `tx.*`): `allowed_methods`, `max_num_args`, …
    #[serde(default)]
    tx: BTreeMap<String, serde_json::Value>,
    /// SecLang files read before the CRS, relative to the filter's file (exclusions by `ctl`).
    #[serde(default)]
    before: Vec<String>,
    /// SecLang files read after it (`SecRuleRemoveById`, `SecRuleUpdateTargetById`).
    #[serde(default)]
    after: Vec<String>,
    /// Rules removed: ids or `first-last` ranges.
    #[serde(default)]
    remove: Vec<serde_json::Value>,
}

/// The CRS as loaded.
pub struct CrsEngine {
    program: program::Program,
    /// `TX` at a request's start: the setup's variables.
    setup: rustc_hash::FxHashMap<String, Vec<u8>>,
    paranoia: u8,
    detection: u8,
    /// Files of the site read, for the summary.
    site_files: usize,
}

static REQUESTS: AtomicU64 = AtomicU64::new(1);

impl Factory for Crs {
    fn name(&self) -> &'static str {
        "crs"
    }

    fn builtin_sets(&self) -> &'static [&'static str] {
        // The CRS numbers its rules as the built-in sets do; `cve`'s numbers are their own.
        &["cve"]
    }

    fn load(&self, config: &serde_json::Value, base: &Path) -> Result<Box<dyn Engine>> {
        let config: Config = if config.is_null() {
            Config::default()
        } else {
            serde_json::from_value(config.clone()).context("its configuration")?
        };
        Ok(Box::new(CrsEngine::new(&config, base)?))
    }
}

/// A data file by name: the bundled one, else one next to the filter's file.
fn data(base: &Path, name: &str) -> Result<String> {
    if let Some((_, text)) = bundled::DATA.iter().find(|(n, _)| *n == name) {
        return Ok(text.to_string());
    }
    let path = base.join(name);
    std::fs::read_to_string(&path).with_context(|| format!("reading {}", path.display()))
}

/// The log's set for a CRS file: `crs-942` for `REQUEST-942-….conf`.
fn set_of(file: &str) -> String {
    let number = file.split('-').nth(1).unwrap_or("");
    if number.len() == 3 && number.bytes().all(|b| b.is_ascii_digit()) {
        format!("crs-{number}")
    } else {
        "crs".to_string()
    }
}

impl CrsEngine {
    fn new(config: &Config, base: &Path) -> Result<CrsEngine> {
        let paranoia = config.paranoia.unwrap_or(1);
        if !(1..=4).contains(&paranoia) {
            bail!("paranoia: 1 to 4, not {paranoia}");
        }
        let detection = config.detection_paranoia.unwrap_or(paranoia);
        if !(paranoia..=4).contains(&detection) {
            bail!("detection_paranoia: from paranoia ({paranoia}) to 4, not {detection}");
        }
        let mut setup = rustc_hash::FxHashMap::default();
        setup.insert("crs_setup_version".to_string(), SETUP_VERSION.as_bytes().to_vec());
        setup.insert("blocking_paranoia_level".to_string(), paranoia.to_string().into_bytes());
        setup.insert(
            "detection_paranoia_level".to_string(),
            detection.to_string().into_bytes(),
        );
        for (key, value) in &config.tx {
            let text = match value {
                serde_json::Value::String(s) => s.clone(),
                serde_json::Value::Number(n) => n.to_string(),
                serde_json::Value::Bool(b) => (*b as u8).to_string(),
                other => bail!("tx.{key}: a string or a number, not {other}"),
            };
            let key = key.trim().to_ascii_lowercase();
            let key = key.strip_prefix("tx.").unwrap_or(&key).to_string();
            if matches!(
                key.as_str(),
                "crs_setup_version" | "blocking_paranoia_level" | "detection_paranoia_level"
            ) {
                bail!("tx.{key}: set by the engine (paranoia, detection_paranoia)");
            }
            setup.insert(key, text.into_bytes());
        }
        let mut program = program::Program::default();
        let read_data = |name: &str| data(base, name);
        let mut site_files = 0;
        let site = |program: &mut program::Program, files: &[String]| -> Result<usize> {
            for file in files {
                let path: PathBuf = base.join(file);
                let text = std::fs::read_to_string(&path).with_context(|| format!("reading {}", path.display()))?;
                let dir = path.parent().unwrap_or(base).to_path_buf();
                program.add(&text, &path.display().to_string(), "crs-site", &|name| data(&dir, name))?;
            }
            Ok(files.len())
        };
        site_files += site(&mut program, &config.before)?;
        for (name, text) in bundled::RULES {
            program.add(text, name, &set_of(name), &read_data)?;
        }
        site_files += site(&mut program, &config.after)?;
        if !config.remove.is_empty() {
            let mut text = String::from("SecRuleRemoveById");
            for item in &config.remove {
                match item {
                    serde_json::Value::Number(n) => text.push_str(&format!(" {n}")),
                    serde_json::Value::String(s) => {
                        program::ranges(s).with_context(|| format!("remove: {s:?}"))?;
                        text.push_str(&format!(" {s}"));
                    }
                    other => bail!("remove: an id or a range, not {other}"),
                }
            }
            program.add(&text, "remove", "crs", &read_data)?;
        }
        program.link_jumps();
        program.build_prefilters()?;
        Ok(CrsEngine {
            program,
            setup,
            paranoia,
            detection,
            site_files,
        })
    }
}

impl Engine for CrsEngine {
    fn summary(&self) -> Vec<String> {
        let mut lines = vec![format!(
            "OWASP CRS {CRS_VERSION}, {} rule(s) of phases 1 and 2, paranoia {}{}{}",
            self.program.count(),
            self.paranoia,
            if self.detection > self.paranoia {
                format!(" (detection {})", self.detection)
            } else {
                String::new()
            },
            if self.site_files > 0 {
                format!(", {} site file(s)", self.site_files)
            } else {
                String::new()
            },
        )];
        if !self.program.ignored.is_empty() {
            lines.push(format!(
                "read without effect (webfast's to configure): {}",
                self.program.ignored.join(", ")
            ));
        }
        lines
    }

    fn runs_in(&self, phase: Phase) -> bool {
        matches!(phase, Phase::Head | Phase::Body)
    }

    fn run(&self, phase: Phase, input: &Input<'_>, state: &mut EngineState, found: &mut Found<'_>) {
        let index = match phase {
            Phase::Head => 0,
            Phase::Body => 1,
            _ => return,
        };
        let state = state.get_or_insert_with(|| {
            let req = request::Request::head(input.parts, input.client_ip);
            let processor = input
                .parts
                .headers
                .get(http::header::CONTENT_TYPE)
                .and_then(|v| request::processor_of(v.as_bytes()))
                .map(str::to_string);
            Box::new(run::Tx::new(
                req,
                self.setup.clone(),
                processor,
                REQUESTS.fetch_add(1, Ordering::Relaxed),
            ))
        });
        let Some(tx) = state.downcast_mut::<run::Tx>() else {
            return;
        };
        if index == 1 && !tx.body_read {
            tx.body_read = true;
            if let Some(body) = input.body {
                let content_type = input
                    .parts
                    .headers
                    .get(http::header::CONTENT_TYPE)
                    .map_or(&b""[..], |v| v.as_bytes());
                let processor = tx.processor.clone();
                let force = tx.force_body;
                tx.req.body(&body.bytes, processor.as_deref(), content_type, 64, force);
            }
        }
        run::run(&self.program, index, tx, found);
    }
}

#[cfg(test)]
mod regression;
#[cfg(test)]
mod tests;
