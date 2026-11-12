// SPDX-License-Identifier: LicenseRef-Reticulum
//! The configuration file (TOML).

use std::path::{Path, PathBuf};
use std::time::Duration;

use serde::Deserialize;

/// The whole file, as written.
#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Config {
    /// The user's Reticulum identity (a 64-byte private key file).
    pub identity: PathBuf,
    /// Where the bouncer keeps its message store, ratchets, Reticulum
    /// config (when it writes one) and status file.
    pub state_dir: PathBuf,
    /// The name announced with the user's LXMF address.
    #[serde(default)]
    pub display_name: Option<String>,
    /// `error`, `warn`, `info`, `debug` or `trace`, or a full tracing filter.
    #[serde(default = "default_log_level")]
    pub log_level: String,
    #[serde(default)]
    pub reticulum: ReticulumSection,
    #[serde(default)]
    pub announce: AnnounceSection,
    #[serde(default)]
    pub store: StoreSection,
    #[serde(default)]
    pub node: NodeSection,
    #[serde(default)]
    pub upstream: UpstreamSection,
    /// Identities the user had before, whose messages the bouncer also
    /// takes and hands to the apps (`[[old_identity]]`).
    #[serde(default)]
    pub old_identity: Vec<OldIdentitySection>,
}

/// An identity the user had before (people may still write to its
/// address).
#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct OldIdentitySection {
    /// Its private key file.
    pub identity: PathBuf,
    /// Ratchet files of apps that announced its address (see
    /// `[upstream] extra_ratchets`).
    #[serde(default)]
    pub extra_ratchets: Vec<PathBuf>,
}

/// How to reach Reticulum. Exactly one of `shared_instance`, `tcp` or
/// `config_dir`.
#[derive(Debug, Clone, Default, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ReticulumSection {
    /// Attach to the local shared instance (an `rnsd` on this host).
    #[serde(default)]
    pub shared_instance: bool,
    /// The shared instance's name (`instance_name` in its config).
    #[serde(default)]
    pub instance_name: Option<String>,
    /// A `TCPServerInterface` to connect to, as `host:port`.
    #[serde(default)]
    pub tcp: Option<String>,
    /// A complete Reticulum config directory, used as it is.
    #[serde(default)]
    pub config_dir: Option<PathBuf>,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AnnounceSection {
    /// Minutes between announces of the LXMF address (and the node).
    #[serde(default = "default_announce_minutes")]
    pub interval_minutes: u64,
}

impl Default for AnnounceSection {
    fn default() -> Self {
        Self {
            interval_minutes: default_announce_minutes(),
        }
    }
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct StoreSection {
    /// Most megabytes of messages kept; the oldest go first past it.
    #[serde(default = "default_max_size_mb")]
    pub max_size_mb: u64,
    /// Days a message is kept for clients to fetch.
    #[serde(default = "default_expiry_days")]
    pub expiry_days: u64,
}

impl Default for StoreSection {
    fn default() -> Self {
        Self {
            max_size_mb: default_max_size_mb(),
            expiry_days: default_expiry_days(),
        }
    }
}

#[derive(Debug, Clone, Default, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct NodeSection {
    /// The node's own identity file (created if missing). It cannot be the
    /// user's identity: every LXMF client registers `lxmf.propagation` for
    /// its own identity, so it would never find a path to the node.
    #[serde(default)]
    pub identity: Option<PathBuf>,
    /// The name the propagation node announces.
    #[serde(default)]
    pub name: Option<String>,
    /// Identity hashes (32 hex characters) allowed to sync besides the
    /// user's own.
    #[serde(default)]
    pub allowed_identities: Vec<String>,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct UpstreamSection {
    /// A propagation node (its `lxmf.propagation` hash) to fetch the user's
    /// messages from.
    #[serde(default)]
    pub node: Option<String>,
    /// Minutes between fetches.
    #[serde(default = "default_upstream_minutes")]
    pub interval_minutes: u64,
    /// Ratchet files of clients that announced this identity before the
    /// bouncer did, so messages encrypted to their ratchets can still be
    /// read (Python LXMF's `<storage>/lxmf/ratchets/<address>.ratchets`).
    #[serde(default)]
    pub extra_ratchets: Vec<PathBuf>,
}

impl Default for UpstreamSection {
    fn default() -> Self {
        Self {
            node: None,
            interval_minutes: default_upstream_minutes(),
            extra_ratchets: Vec::new(),
        }
    }
}

fn default_log_level() -> String {
    "info".into()
}
fn default_announce_minutes() -> u64 {
    30
}
fn default_max_size_mb() -> u64 {
    500
}
fn default_expiry_days() -> u64 {
    30
}
fn default_upstream_minutes() -> u64 {
    15
}

/// How the bouncer reaches Reticulum, checked.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RnsAccess {
    Shared { instance_name: String },
    Tcp { host: String, port: u16 },
    ConfigDir(PathBuf),
}

/// The configuration, checked and with paths resolved.
#[derive(Debug, Clone)]
pub struct Settings {
    pub identity: PathBuf,
    pub state_dir: PathBuf,
    pub display_name: Option<String>,
    pub log_level: String,
    pub rns: RnsAccess,
    pub announce_interval: Duration,
    pub max_store_bytes: usize,
    pub expiry: Duration,
    pub node_identity: PathBuf,
    pub node_name: Option<String>,
    pub allowed_identities: Vec<[u8; 16]>,
    pub upstream: Option<[u8; 16]>,
    pub upstream_interval: Duration,
    pub extra_ratchets: Vec<PathBuf>,
    /// Old identities: key file and extra ratchet files.
    pub old_identities: Vec<(PathBuf, Vec<PathBuf>)>,
}

/// Parse a 16-byte hash written as 32 hex characters (`<` `>` and `:`
/// tolerated, as Reticulum tools print them).
pub fn parse_hash(text: &str) -> Option<[u8; 16]> {
    let clean: String = text.chars().filter(|c| !matches!(c, '<' | '>' | ':' | ' ')).collect();
    hex::decode(clean).ok()?.try_into().ok()
}

/// `~/` at the start of a path is the home directory.
fn expand(path: &Path) -> PathBuf {
    match path.strip_prefix("~") {
        Ok(rest) => std::env::var_os("HOME")
            .map(PathBuf::from)
            .unwrap_or_default()
            .join(rest),
        Err(_) => path.to_path_buf(),
    }
}

impl Config {
    pub fn parse(text: &str) -> Result<Self, String> {
        toml::from_str(text).map_err(|e| e.to_string())
    }

    pub fn load(path: &Path) -> Result<Self, String> {
        let text = std::fs::read_to_string(path).map_err(|e| format!("{}: {e}", path.display()))?;
        Self::parse(&text).map_err(|e| format!("{}: {e}", path.display()))
    }

    /// Check it, resolving paths relative to the directory the file is in.
    pub fn settings(&self, base: &Path) -> Result<Settings, String> {
        let resolve = |path: &Path| {
            let path = expand(path);
            if path.is_absolute() { path } else { base.join(path) }
        };
        let r = &self.reticulum;
        let chosen = [r.shared_instance, r.tcp.is_some(), r.config_dir.is_some()]
            .iter()
            .filter(|c| **c)
            .count();
        if chosen != 1 {
            return Err(
                "[reticulum]: set exactly one of shared_instance = true, tcp = \"host:port\" or config_dir".into(),
            );
        }
        if r.instance_name.is_some() && !r.shared_instance {
            return Err("[reticulum]: instance_name only applies with shared_instance = true".into());
        }
        let rns = if r.shared_instance {
            let name = r.instance_name.clone().unwrap_or_else(|| "default".into());
            if name.is_empty() || !name.bytes().all(|b| b.is_ascii_alphanumeric() || b"-_.".contains(&b)) {
                return Err(format!(
                    "[reticulum]: instance_name {name:?} is not a valid instance name"
                ));
            }
            RnsAccess::Shared { instance_name: name }
        } else if let Some(tcp) = &r.tcp {
            let (host, port) = tcp
                .rsplit_once(':')
                .ok_or_else(|| format!("[reticulum]: tcp = {tcp:?} is not host:port"))?;
            let port = port
                .parse::<u16>()
                .ok()
                .filter(|p| *p > 0)
                .ok_or_else(|| format!("[reticulum]: bad port in {tcp:?}"))?;
            let host = host.trim_start_matches('[').trim_end_matches(']');
            if host.is_empty() || host.contains(['\n', '\r', '[', ']']) {
                return Err(format!("[reticulum]: bad host in {tcp:?}"));
            }
            RnsAccess::Tcp {
                host: host.to_string(),
                port,
            }
        } else {
            RnsAccess::ConfigDir(resolve(r.config_dir.as_deref().unwrap_or(Path::new(""))))
        };
        if self.announce.interval_minutes == 0 {
            return Err("[announce]: interval_minutes must be at least 1".into());
        }
        if self.store.expiry_days == 0 {
            return Err("[store]: expiry_days must be at least 1".into());
        }
        if self.store.max_size_mb == 0 {
            return Err("[store]: max_size_mb must be at least 1".into());
        }
        let allowed_identities = self
            .node
            .allowed_identities
            .iter()
            .map(|h| parse_hash(h).ok_or_else(|| format!("[node]: allowed_identities: {h:?} is not 32 hex characters")))
            .collect::<Result<Vec<_>, _>>()?;
        let upstream = match &self.upstream.node {
            None => None,
            Some(h) if h.trim().is_empty() => None,
            Some(h) => Some(parse_hash(h).ok_or_else(|| format!("[upstream]: node {h:?} is not 32 hex characters"))?),
        };
        if self.upstream.interval_minutes == 0 {
            return Err("[upstream]: interval_minutes must be at least 1".into());
        }
        Ok(Settings {
            identity: resolve(&self.identity),
            state_dir: resolve(&self.state_dir),
            display_name: self.display_name.clone().filter(|n| !n.trim().is_empty()),
            log_level: self.log_level.clone(),
            rns,
            announce_interval: Duration::from_secs(self.announce.interval_minutes * 60),
            max_store_bytes: usize::try_from(self.store.max_size_mb.saturating_mul(1_000_000)).unwrap_or(usize::MAX),
            expiry: Duration::from_secs(self.store.expiry_days.saturating_mul(86_400)),
            node_identity: match &self.node.identity {
                Some(path) => resolve(path),
                None => resolve(&self.state_dir).join("node_identity"),
            },
            node_name: self.node.name.clone().filter(|n| !n.trim().is_empty()),
            allowed_identities,
            upstream,
            upstream_interval: Duration::from_secs(self.upstream.interval_minutes * 60),
            extra_ratchets: self.upstream.extra_ratchets.iter().map(|p| resolve(p)).collect(),
            old_identities: self
                .old_identity
                .iter()
                .map(|o| {
                    (
                        resolve(&o.identity),
                        o.extra_ratchets.iter().map(|p| resolve(p)).collect(),
                    )
                })
                .collect(),
        })
    }
}

impl Settings {
    /// Load and check the file at `path`.
    pub fn load(path: &Path) -> Result<Self, String> {
        let base = path.parent().map(Path::to_path_buf).unwrap_or_default();
        let base = if base.as_os_str().is_empty() {
            PathBuf::from(".")
        } else {
            base
        };
        Config::load(path)?.settings(&base)
    }

    pub fn store_dir(&self) -> PathBuf {
        self.state_dir.join("messagestore")
    }
    pub fn outbox_dir(&self) -> PathBuf {
        self.state_dir.join("outbox")
    }
    pub fn ratchet_dir(&self) -> PathBuf {
        self.state_dir.join("ratchets")
    }
    pub fn ledger_path(&self) -> PathBuf {
        self.state_dir.join("ledger.json")
    }
    pub fn status_path(&self) -> PathBuf {
        self.state_dir.join("status.json")
    }
    /// The Reticulum config directory: the configured one, or one the
    /// bouncer writes under its state directory.
    pub fn rns_config_dir(&self) -> PathBuf {
        match &self.rns {
            RnsAccess::ConfigDir(dir) => dir.clone(),
            _ => self.state_dir.join("reticulum"),
        }
    }

    /// The Reticulum config the bouncer writes for itself (`None` when a
    /// config directory of the user's is used).
    pub fn generated_rns_config(&self) -> Option<String> {
        match &self.rns {
            RnsAccess::ConfigDir(_) => None,
            RnsAccess::Shared { instance_name } => Some(format!(
                "# Written by lxmf-bouncer on each start; edit its own config instead.\n\
                 [reticulum]\n  enable_transport = No\n  share_instance = Yes\n  instance_name = {instance_name}\n  panic_on_interface_error = No\n\n\
                 [logging]\n  loglevel = 2\n\n[interfaces]\n"
            )),
            RnsAccess::Tcp { host, port } => Some(format!(
                "# Written by lxmf-bouncer on each start; edit its own config instead.\n\
                 [reticulum]\n  enable_transport = No\n  share_instance = No\n  instance_name = lxmf-bouncer\n  panic_on_interface_error = No\n\n\
                 [logging]\n  loglevel = 2\n\n[interfaces]\n  [[lxmf-bouncer uplink]]\n    type = TCPClientInterface\n    enabled = Yes\n    target_host = {host}\n    target_port = {port}\n"
            )),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const MINIMAL: &str = "identity = \"id\"\nstate_dir = \"/var/lib/b\"\n[reticulum]\ntcp = \"127.0.0.1:4242\"\n";

    #[test]
    fn minimal_config_gets_defaults() {
        let s = Config::parse(MINIMAL).unwrap().settings(Path::new("/etc/b")).unwrap();
        assert_eq!(s.identity, PathBuf::from("/etc/b/id"));
        assert_eq!(s.state_dir, PathBuf::from("/var/lib/b"));
        assert_eq!(
            s.rns,
            RnsAccess::Tcp {
                host: "127.0.0.1".into(),
                port: 4242
            }
        );
        assert_eq!(s.announce_interval, Duration::from_secs(1800));
        assert_eq!(s.expiry, Duration::from_secs(30 * 86_400));
        assert_eq!(s.max_store_bytes, 500_000_000);
        assert_eq!(s.node_identity, PathBuf::from("/var/lib/b/node_identity"));
        assert!(s.upstream.is_none());
        let generated = s.generated_rns_config().unwrap();
        assert!(generated.contains("share_instance = No"));
        assert!(generated.contains("target_port = 4242"));
    }

    #[test]
    fn exactly_one_way_to_reticulum() {
        let none = "identity = \"id\"\nstate_dir = \"s\"\n";
        assert!(Config::parse(none).unwrap().settings(Path::new("/")).is_err());
        let two = "identity = \"id\"\nstate_dir = \"s\"\n[reticulum]\nshared_instance = true\ntcp = \"a:1\"\n";
        assert!(Config::parse(two).unwrap().settings(Path::new("/")).is_err());
        let shared = "identity = \"id\"\nstate_dir = \"s\"\n[reticulum]\nshared_instance = true\n";
        let s = Config::parse(shared).unwrap().settings(Path::new("/")).unwrap();
        assert_eq!(
            s.rns,
            RnsAccess::Shared {
                instance_name: "default".into()
            }
        );
        assert!(s.generated_rns_config().unwrap().contains("share_instance = Yes"));
    }

    #[test]
    fn hashes_and_typos_are_checked() {
        let bad_hash = format!("{MINIMAL}[upstream]\nnode = \"abc\"\n");
        assert!(Config::parse(&bad_hash).unwrap().settings(Path::new("/")).is_err());
        let good = format!(
            "{MINIMAL}[upstream]\nnode = \"<a67a6768c612e972746eaaeb6ee242e1>\"\n[node]\nallowed_identities = [\"00112233445566778899aabbccddeeff\"]\n"
        );
        let s = Config::parse(&good).unwrap().settings(Path::new("/")).unwrap();
        assert_eq!(s.upstream.unwrap()[0], 0xa6);
        assert_eq!(s.allowed_identities.len(), 1);
        let typo = format!("{MINIMAL}[store]\nexpiry = 3\n");
        assert!(Config::parse(&typo).is_err());
    }
}
