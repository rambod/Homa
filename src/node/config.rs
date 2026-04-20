//! Node runtime configuration loading and validation.

use std::fs;
use std::net::SocketAddr;
use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};
use thiserror::Error;

use crate::crypto::address::Network;
use crate::crypto::keys::SECRET_KEY_LENGTH;

const DEFAULT_SEED_DOMAIN: &str = "seed1.homanetwork.io";
const MAX_POW_BITS: u16 = 256;
const DEFAULT_SLOT_DURATION_MS: u64 = 1_000;
const DEFAULT_MAX_BLOCK_TRANSACTIONS: usize = 1_024;
const DEFAULT_MEMPOOL_CHECKPOINT_INTERVAL_MS: u64 = 10_000;
const DEFAULT_INDEX_MAX_RETAINED_BLOCKS: usize = 100_000;
const DEFAULT_RPC_LISTEN_ADDR: &str = "127.0.0.1:8545";
const DEFAULT_RPC_MAX_BODY_BYTES: usize = 256 * 1024;
const DEFAULT_RPC_RATE_LIMIT_PER_SEC: u32 = 100;
const DEFAULT_WS_MAX_SUBSCRIPTIONS_PER_CONN: usize = 32;

/// Typed network selector for node configuration files.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(rename_all = "lowercase")]
pub enum NodeConfigNetwork {
    /// Main production network.
    Mainnet,
    /// Public testing network.
    #[default]
    Testnet,
    /// Local development network.
    Devnet,
}

impl NodeConfigNetwork {
    /// Converts to the runtime network domain.
    #[must_use]
    pub const fn into_network(self) -> Network {
        match self {
            Self::Mainnet => Network::Mainnet,
            Self::Testnet => Network::Testnet,
            Self::Devnet => Network::Devnet,
        }
    }
}

/// Runtime configuration used by the node daemon CLI.
#[allow(clippy::struct_excessive_bools)]
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct NodeRuntimeConfig {
    /// Network domain for signatures and addresses.
    pub network: NodeConfigNetwork,
    /// DNS seed domain for bootstrap peer discovery.
    pub seed_domain: String,
    /// Fallback bootstrap entries (`IP`, `IP:PORT`, or full multiaddr).
    pub fallback_bootstrap: Vec<String>,
    /// Whether the daemon opens listen sockets.
    pub listen: bool,
    /// Whether the daemon resolves and dials bootstrap peers.
    pub bootstrap: bool,
    /// Whether bootstrap failures are fatal.
    pub strict_bootstrap: bool,
    /// Mempool minimum accepted transaction `PoW` bits.
    pub min_pow_bits: u16,
    /// Runtime event-loop poll interval in milliseconds.
    pub event_loop_tick_ms: u64,
    /// Consensus slot duration in milliseconds used for proposer scheduling.
    pub slot_duration_ms: u64,
    /// Maximum transactions selected when producing one local block.
    pub max_block_transactions: usize,
    /// Maximum pending decoded block queue size.
    pub max_pending_blocks: usize,
    /// Interval for periodic mempool checkpoint flushes in milliseconds.
    pub mempool_checkpoint_interval_ms: u64,
    /// Maximum retained finalized blocks in persistent query indexes.
    pub index_max_retained_blocks: usize,
    /// JSON-RPC + WebSocket listen address (`IP:PORT`).
    pub rpc_listen_addr: String,
    /// Maximum accepted JSON-RPC request body size (bytes).
    pub rpc_max_body_bytes: usize,
    /// Per-IP request-rate budget (requests/second).
    pub rpc_rate_limit_per_sec: u32,
    /// Maximum WebSocket subscriptions allowed per connection.
    pub ws_max_subscriptions_per_conn: usize,
    /// Enables fail-closed startup recovery coherence checks.
    pub strict_recovery: bool,
    /// Forces index rebuild from retained finalized events during startup.
    pub repair_index: bool,
    /// Skips mempool checkpoint ingestion during startup.
    pub ignore_mempool_checkpoint: bool,
    /// Optional bounded run-step count for smoke testing.
    pub max_steps: Option<usize>,
    /// Optional persistence directory used for graceful shutdown checkpointing.
    pub state_directory: Option<PathBuf>,
    /// Optional local block producer secret key (`hex`-encoded 32-byte Ed25519 secret key).
    pub producer_secret_key_hex: Option<String>,
}

impl Default for NodeRuntimeConfig {
    fn default() -> Self {
        Self {
            network: NodeConfigNetwork::default(),
            seed_domain: DEFAULT_SEED_DOMAIN.to_owned(),
            fallback_bootstrap: Vec::new(),
            listen: true,
            bootstrap: true,
            strict_bootstrap: false,
            min_pow_bits: 10,
            event_loop_tick_ms: 250,
            slot_duration_ms: DEFAULT_SLOT_DURATION_MS,
            max_block_transactions: DEFAULT_MAX_BLOCK_TRANSACTIONS,
            max_pending_blocks: 512,
            mempool_checkpoint_interval_ms: DEFAULT_MEMPOOL_CHECKPOINT_INTERVAL_MS,
            index_max_retained_blocks: DEFAULT_INDEX_MAX_RETAINED_BLOCKS,
            rpc_listen_addr: DEFAULT_RPC_LISTEN_ADDR.to_owned(),
            rpc_max_body_bytes: DEFAULT_RPC_MAX_BODY_BYTES,
            rpc_rate_limit_per_sec: DEFAULT_RPC_RATE_LIMIT_PER_SEC,
            ws_max_subscriptions_per_conn: DEFAULT_WS_MAX_SUBSCRIPTIONS_PER_CONN,
            strict_recovery: true,
            repair_index: false,
            ignore_mempool_checkpoint: false,
            max_steps: None,
            state_directory: None,
            producer_secret_key_hex: None,
        }
    }
}

/// CLI-time overrides that can modify loaded file configuration.
#[allow(clippy::struct_excessive_bools)]
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct NodeRuntimeOverrides {
    /// Optional network override.
    pub network: Option<NodeConfigNetwork>,
    /// Optional seed domain override.
    pub seed_domain: Option<String>,
    /// Optional fallback bootstrap replacement set.
    pub fallback_bootstrap: Option<Vec<String>>,
    /// Disable listen sockets.
    pub no_listen: bool,
    /// Disable bootstrap dialing.
    pub no_bootstrap: bool,
    /// Make bootstrap failures fatal.
    pub strict_bootstrap: bool,
    /// Optional minimum `PoW` bits override.
    pub min_pow_bits: Option<u16>,
    /// Optional event loop tick override.
    pub event_loop_tick_ms: Option<u64>,
    /// Optional slot duration override.
    pub slot_duration_ms: Option<u64>,
    /// Optional per-block transaction cap override.
    pub max_block_transactions: Option<usize>,
    /// Optional max pending block queue override.
    pub max_pending_blocks: Option<usize>,
    /// Optional mempool checkpoint interval override.
    pub mempool_checkpoint_interval_ms: Option<u64>,
    /// Optional finalized-index retention override.
    pub index_max_retained_blocks: Option<usize>,
    /// Optional RPC listen address override.
    pub rpc_listen_addr: Option<String>,
    /// Optional RPC max request-body bytes override.
    pub rpc_max_body_bytes: Option<usize>,
    /// Optional RPC requests/second rate-limit override.
    pub rpc_rate_limit_per_sec: Option<u32>,
    /// Optional WebSocket max-subscriptions-per-connection override.
    pub ws_max_subscriptions_per_conn: Option<usize>,
    /// Optional strict recovery toggle override.
    pub strict_recovery: Option<bool>,
    /// Optional index rebuild toggle override.
    pub repair_index: Option<bool>,
    /// Optional mempool-checkpoint recovery toggle override.
    pub ignore_mempool_checkpoint: Option<bool>,
    /// Optional bounded step count override.
    pub max_steps: Option<usize>,
    /// Optional persistence directory override.
    pub state_directory: Option<PathBuf>,
    /// Optional local producer secret key override.
    pub producer_secret_key_hex: Option<String>,
}

impl NodeRuntimeConfig {
    /// Loads one runtime configuration from `TOML` file.
    pub fn load_from_file(path: &Path) -> Result<Self, NodeConfigError> {
        let raw = fs::read_to_string(path).map_err(|source| NodeConfigError::ReadConfig {
            path: path.to_string_lossy().into_owned(),
            source,
        })?;
        toml::from_str(&raw).map_err(|source| NodeConfigError::ParseConfig {
            path: path.to_string_lossy().into_owned(),
            source,
        })
    }

    /// Applies CLI overrides to this runtime configuration.
    pub fn apply_overrides(&mut self, overrides: &NodeRuntimeOverrides) {
        if let Some(network) = overrides.network {
            self.network = network;
        }
        if let Some(seed_domain) = &overrides.seed_domain {
            self.seed_domain.clone_from(seed_domain);
        }
        if let Some(fallback_bootstrap) = &overrides.fallback_bootstrap {
            self.fallback_bootstrap.clone_from(fallback_bootstrap);
        }
        if overrides.no_listen {
            self.listen = false;
        }
        if overrides.no_bootstrap {
            self.bootstrap = false;
        }
        if overrides.strict_bootstrap {
            self.strict_bootstrap = true;
        }
        if let Some(min_pow_bits) = overrides.min_pow_bits {
            self.min_pow_bits = min_pow_bits;
        }
        if let Some(event_loop_tick_ms) = overrides.event_loop_tick_ms {
            self.event_loop_tick_ms = event_loop_tick_ms;
        }
        if let Some(slot_duration_ms) = overrides.slot_duration_ms {
            self.slot_duration_ms = slot_duration_ms;
        }
        if let Some(max_block_transactions) = overrides.max_block_transactions {
            self.max_block_transactions = max_block_transactions;
        }
        if let Some(max_pending_blocks) = overrides.max_pending_blocks {
            self.max_pending_blocks = max_pending_blocks;
        }
        if let Some(mempool_checkpoint_interval_ms) = overrides.mempool_checkpoint_interval_ms {
            self.mempool_checkpoint_interval_ms = mempool_checkpoint_interval_ms;
        }
        if let Some(index_max_retained_blocks) = overrides.index_max_retained_blocks {
            self.index_max_retained_blocks = index_max_retained_blocks;
        }
        if let Some(rpc_listen_addr) = &overrides.rpc_listen_addr {
            self.rpc_listen_addr.clone_from(rpc_listen_addr);
        }
        if let Some(rpc_max_body_bytes) = overrides.rpc_max_body_bytes {
            self.rpc_max_body_bytes = rpc_max_body_bytes;
        }
        if let Some(rpc_rate_limit_per_sec) = overrides.rpc_rate_limit_per_sec {
            self.rpc_rate_limit_per_sec = rpc_rate_limit_per_sec;
        }
        if let Some(ws_max_subscriptions_per_conn) = overrides.ws_max_subscriptions_per_conn {
            self.ws_max_subscriptions_per_conn = ws_max_subscriptions_per_conn;
        }
        if let Some(strict_recovery) = overrides.strict_recovery {
            self.strict_recovery = strict_recovery;
        }
        if let Some(repair_index) = overrides.repair_index {
            self.repair_index = repair_index;
        }
        if let Some(ignore_mempool_checkpoint) = overrides.ignore_mempool_checkpoint {
            self.ignore_mempool_checkpoint = ignore_mempool_checkpoint;
        }
        if let Some(max_steps) = overrides.max_steps {
            self.max_steps = Some(max_steps);
        }
        if let Some(state_directory) = &overrides.state_directory {
            self.state_directory = Some(state_directory.clone());
        }
        if let Some(producer_secret_key_hex) = &overrides.producer_secret_key_hex {
            self.producer_secret_key_hex = Some(producer_secret_key_hex.clone());
        }
    }

    /// Returns the configured runtime network.
    #[must_use]
    pub const fn network(&self) -> Network {
        self.network.into_network()
    }

    /// Validates startup-critical node runtime configuration.
    pub fn validate(&self) -> Result<(), NodeConfigError> {
        if self.event_loop_tick_ms == 0 {
            return Err(NodeConfigError::InvalidEventLoopTickMs {
                event_loop_tick_ms: self.event_loop_tick_ms,
            });
        }
        if self.slot_duration_ms == 0 {
            return Err(NodeConfigError::InvalidSlotDurationMs {
                slot_duration_ms: self.slot_duration_ms,
            });
        }
        if self.max_block_transactions == 0 {
            return Err(NodeConfigError::InvalidMaxBlockTransactions {
                max_block_transactions: self.max_block_transactions,
            });
        }
        if self.max_pending_blocks == 0 {
            return Err(NodeConfigError::InvalidPendingBlockLimit {
                max_pending_blocks: self.max_pending_blocks,
            });
        }
        if self.mempool_checkpoint_interval_ms == 0 {
            return Err(NodeConfigError::InvalidMempoolCheckpointIntervalMs {
                mempool_checkpoint_interval_ms: self.mempool_checkpoint_interval_ms,
            });
        }
        if self.index_max_retained_blocks == 0 {
            return Err(NodeConfigError::InvalidIndexMaxRetainedBlocks {
                index_max_retained_blocks: self.index_max_retained_blocks,
            });
        }
        if self.rpc_max_body_bytes == 0 {
            return Err(NodeConfigError::InvalidRpcMaxBodyBytes {
                rpc_max_body_bytes: self.rpc_max_body_bytes,
            });
        }
        if self.rpc_rate_limit_per_sec == 0 {
            return Err(NodeConfigError::InvalidRpcRateLimitPerSec {
                rpc_rate_limit_per_sec: self.rpc_rate_limit_per_sec,
            });
        }
        if self.ws_max_subscriptions_per_conn == 0 {
            return Err(NodeConfigError::InvalidWsMaxSubscriptionsPerConnection {
                ws_max_subscriptions_per_conn: self.ws_max_subscriptions_per_conn,
            });
        }
        if self.rpc_listen_addr.parse::<SocketAddr>().is_err() {
            return Err(NodeConfigError::InvalidRpcListenAddr {
                rpc_listen_addr: self.rpc_listen_addr.clone(),
            });
        }
        if self.min_pow_bits > MAX_POW_BITS {
            return Err(NodeConfigError::InvalidMinPowBits {
                min_pow_bits: self.min_pow_bits,
                max_pow_bits: MAX_POW_BITS,
            });
        }
        let _ = self.producer_secret_key_bytes()?;
        if self.bootstrap
            && self.seed_domain.trim().is_empty()
            && self.fallback_bootstrap.is_empty()
        {
            return Err(NodeConfigError::BootstrapAddressSourceMissing);
        }
        if let Some(directory) = &self.state_directory {
            let rendered = directory.to_string_lossy();
            if rendered.trim().is_empty() {
                return Err(NodeConfigError::EmptyStateDirectory);
            }
        }
        Ok(())
    }

    /// Decodes optional producer secret key from hex into fixed 32-byte key material.
    pub fn producer_secret_key_bytes(
        &self,
    ) -> Result<Option<[u8; SECRET_KEY_LENGTH]>, NodeConfigError> {
        let Some(encoded) = self.producer_secret_key_hex.as_deref() else {
            return Ok(None);
        };
        let sanitized = encoded.trim();
        if sanitized.is_empty() {
            return Err(NodeConfigError::InvalidProducerSecretKeyHex {
                reason: "secret key cannot be empty".to_owned(),
            });
        }
        let decoded =
            hex::decode(sanitized).map_err(|_| NodeConfigError::InvalidProducerSecretKeyHex {
                reason: "secret key must be valid hex".to_owned(),
            })?;
        if decoded.len() != SECRET_KEY_LENGTH {
            return Err(NodeConfigError::InvalidProducerSecretKeyLength {
                expected: SECRET_KEY_LENGTH,
                actual: decoded.len(),
            });
        }
        let mut key = [0_u8; SECRET_KEY_LENGTH];
        key.copy_from_slice(&decoded);
        Ok(Some(key))
    }
}

/// Errors raised by node runtime configuration loading and validation.
#[derive(Debug, Error)]
pub enum NodeConfigError {
    /// Reading a `TOML` config file failed.
    #[error("failed to read node config file: {path}")]
    ReadConfig {
        /// File path.
        path: String,
        /// Underlying I/O error.
        source: std::io::Error,
    },
    /// Parsing a `TOML` config file failed.
    #[error("failed to parse node config file: {path}")]
    ParseConfig {
        /// File path.
        path: String,
        /// Underlying parse error.
        source: toml::de::Error,
    },
    /// Poll interval must be non-zero.
    #[error("invalid node config: event_loop_tick_ms must be > 0")]
    InvalidEventLoopTickMs {
        /// Configured value.
        event_loop_tick_ms: u64,
    },
    /// Slot duration must be non-zero.
    #[error("invalid node config: slot_duration_ms must be > 0")]
    InvalidSlotDurationMs {
        /// Configured value.
        slot_duration_ms: u64,
    },
    /// Maximum transactions per produced block must be non-zero.
    #[error("invalid node config: max_block_transactions must be > 0")]
    InvalidMaxBlockTransactions {
        /// Configured value.
        max_block_transactions: usize,
    },
    /// Pending block queue must be non-zero.
    #[error("invalid node config: max_pending_blocks must be > 0")]
    InvalidPendingBlockLimit {
        /// Configured value.
        max_pending_blocks: usize,
    },
    /// Mempool checkpoint interval must be non-zero.
    #[error("invalid node config: mempool_checkpoint_interval_ms must be > 0")]
    InvalidMempoolCheckpointIntervalMs {
        /// Configured value.
        mempool_checkpoint_interval_ms: u64,
    },
    /// Finalized-index retention bound must be non-zero.
    #[error("invalid node config: index_max_retained_blocks must be > 0")]
    InvalidIndexMaxRetainedBlocks {
        /// Configured value.
        index_max_retained_blocks: usize,
    },
    /// RPC listen address is not a valid `IP:PORT` socket address.
    #[error("invalid node config: rpc_listen_addr must be a valid socket address")]
    InvalidRpcListenAddr {
        /// Configured value.
        rpc_listen_addr: String,
    },
    /// RPC max request body size must be non-zero.
    #[error("invalid node config: rpc_max_body_bytes must be > 0")]
    InvalidRpcMaxBodyBytes {
        /// Configured value.
        rpc_max_body_bytes: usize,
    },
    /// RPC rate-limit budget must be non-zero.
    #[error("invalid node config: rpc_rate_limit_per_sec must be > 0")]
    InvalidRpcRateLimitPerSec {
        /// Configured value.
        rpc_rate_limit_per_sec: u32,
    },
    /// WS max subscriptions per connection must be non-zero.
    #[error("invalid node config: ws_max_subscriptions_per_conn must be > 0")]
    InvalidWsMaxSubscriptionsPerConnection {
        /// Configured value.
        ws_max_subscriptions_per_conn: usize,
    },
    /// Minimum `PoW` bits must fit algorithm bounds.
    #[error(
        "invalid node config: min_pow_bits={min_pow_bits} exceeds supported maximum {max_pow_bits}"
    )]
    InvalidMinPowBits {
        /// Configured value.
        min_pow_bits: u16,
        /// Maximum supported value.
        max_pow_bits: u16,
    },
    /// Bootstrap requires either DNS seed domain or fallback list.
    #[error(
        "invalid node config: bootstrap enabled but no seed_domain or fallback_bootstrap entries configured"
    )]
    BootstrapAddressSourceMissing,
    /// Persisted state directory path is empty/whitespace.
    #[error("invalid node config: state_directory cannot be empty")]
    EmptyStateDirectory,
    /// Producer secret key hex string is malformed.
    #[error("invalid node config: producer_secret_key_hex is malformed ({reason})")]
    InvalidProducerSecretKeyHex {
        /// Human-readable parse failure reason.
        reason: String,
    },
    /// Producer secret key must be exactly 32 bytes.
    #[error(
        "invalid node config: producer_secret_key_hex decoded length must be {expected} bytes (got {actual})"
    )]
    InvalidProducerSecretKeyLength {
        /// Expected Ed25519 secret-key length.
        expected: usize,
        /// Actual decoded byte-length.
        actual: usize,
    },
}

#[cfg(test)]
mod tests {
    use super::{NodeConfigError, NodeRuntimeConfig, NodeRuntimeOverrides};
    use crate::crypto::keys::SECRET_KEY_LENGTH;
    use std::fs;

    fn temp_config_path(name: &str) -> std::path::PathBuf {
        let mut path = std::env::temp_dir();
        let unique = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map_or(0_u128, |duration| duration.as_nanos());
        path.push(format!(
            "homa-node-config-{name}-{}-{unique}.toml",
            std::process::id()
        ));
        path
    }

    #[test]
    fn loads_config_from_toml_and_validates() {
        let path = temp_config_path("load-validate");
        let raw = r#"
network = "devnet"
seed_domain = "seed.devnet.homa"
fallback_bootstrap = ["127.0.0.1:7000"]
listen = true
bootstrap = true
strict_bootstrap = false
min_pow_bits = 12
event_loop_tick_ms = 300
slot_duration_ms = 1000
max_block_transactions = 512
max_pending_blocks = 1024
mempool_checkpoint_interval_ms = 2000
index_max_retained_blocks = 4096
rpc_listen_addr = "127.0.0.1:9555"
rpc_max_body_bytes = 131072
rpc_rate_limit_per_sec = 250
ws_max_subscriptions_per_conn = 64
strict_recovery = false
repair_index = true
ignore_mempool_checkpoint = true
max_steps = 5
state_directory = "state/devnet"
"#;

        let write_result = fs::write(&path, raw);
        assert!(write_result.is_ok(), "test config should be writable");

        let loaded = NodeRuntimeConfig::load_from_file(&path);
        assert!(loaded.is_ok(), "config should parse");
        let loaded = loaded.unwrap_or_else(|_| unreachable!());
        assert!(
            loaded.validate().is_ok(),
            "loaded config should pass validation"
        );
        assert_eq!(loaded.seed_domain, "seed.devnet.homa");
        assert_eq!(loaded.slot_duration_ms, 1000);
        assert_eq!(loaded.max_block_transactions, 512);
        assert_eq!(loaded.mempool_checkpoint_interval_ms, 2000);
        assert_eq!(loaded.index_max_retained_blocks, 4096);
        assert_eq!(loaded.rpc_listen_addr, "127.0.0.1:9555");
        assert_eq!(loaded.rpc_max_body_bytes, 131_072);
        assert_eq!(loaded.rpc_rate_limit_per_sec, 250);
        assert_eq!(loaded.ws_max_subscriptions_per_conn, 64);
        assert!(!loaded.strict_recovery);
        assert!(loaded.repair_index);
        assert!(loaded.ignore_mempool_checkpoint);
        assert_eq!(loaded.max_steps, Some(5));

        let cleanup = fs::remove_file(path);
        assert!(cleanup.is_ok(), "test config file should clean up");
    }

    #[test]
    fn rejects_missing_bootstrap_sources_when_enabled() {
        let config = NodeRuntimeConfig {
            bootstrap: true,
            seed_domain: "  ".to_owned(),
            fallback_bootstrap: Vec::new(),
            ..NodeRuntimeConfig::default()
        };
        let validation = config.validate();
        assert!(
            matches!(
                validation,
                Err(NodeConfigError::BootstrapAddressSourceMissing)
            ),
            "bootstrap-enabled config must provide DNS seed or fallback peers"
        );
    }

    #[test]
    fn rejects_zero_mempool_checkpoint_interval() {
        let config = NodeRuntimeConfig {
            mempool_checkpoint_interval_ms: 0,
            ..NodeRuntimeConfig::default()
        };
        let validation = config.validate();
        assert!(
            matches!(
                validation,
                Err(NodeConfigError::InvalidMempoolCheckpointIntervalMs {
                    mempool_checkpoint_interval_ms: 0
                })
            ),
            "zero mempool checkpoint interval must be rejected"
        );
    }

    #[test]
    fn rejects_zero_index_retention_bound() {
        let config = NodeRuntimeConfig {
            index_max_retained_blocks: 0,
            ..NodeRuntimeConfig::default()
        };
        let validation = config.validate();
        assert!(
            matches!(
                validation,
                Err(NodeConfigError::InvalidIndexMaxRetainedBlocks {
                    index_max_retained_blocks: 0
                })
            ),
            "zero finalized-index retention bound must be rejected"
        );
    }

    #[test]
    fn overrides_apply_as_expected() {
        let mut config = NodeRuntimeConfig::default();
        let overrides = NodeRuntimeOverrides {
            no_listen: true,
            no_bootstrap: true,
            strict_bootstrap: true,
            event_loop_tick_ms: Some(999),
            slot_duration_ms: Some(777),
            max_block_transactions: Some(33),
            max_pending_blocks: Some(12),
            mempool_checkpoint_interval_ms: Some(3_333),
            index_max_retained_blocks: Some(55),
            rpc_listen_addr: Some("127.0.0.1:9777".to_owned()),
            rpc_max_body_bytes: Some(65_536),
            rpc_rate_limit_per_sec: Some(42),
            ws_max_subscriptions_per_conn: Some(7),
            strict_recovery: Some(false),
            repair_index: Some(true),
            ignore_mempool_checkpoint: Some(true),
            max_steps: Some(2),
            ..NodeRuntimeOverrides::default()
        };

        config.apply_overrides(&overrides);

        assert!(!config.listen, "listen should be disabled by override");
        assert!(
            !config.bootstrap,
            "bootstrap should be disabled by override"
        );
        assert!(
            config.strict_bootstrap,
            "strict bootstrap should be enabled by override"
        );
        assert_eq!(config.event_loop_tick_ms, 999);
        assert_eq!(config.slot_duration_ms, 777);
        assert_eq!(config.max_block_transactions, 33);
        assert_eq!(config.max_pending_blocks, 12);
        assert_eq!(config.mempool_checkpoint_interval_ms, 3_333);
        assert_eq!(config.index_max_retained_blocks, 55);
        assert_eq!(config.rpc_listen_addr, "127.0.0.1:9777");
        assert_eq!(config.rpc_max_body_bytes, 65_536);
        assert_eq!(config.rpc_rate_limit_per_sec, 42);
        assert_eq!(config.ws_max_subscriptions_per_conn, 7);
        assert!(!config.strict_recovery);
        assert!(config.repair_index);
        assert!(config.ignore_mempool_checkpoint);
        assert_eq!(config.max_steps, Some(2));
    }

    #[test]
    fn rejects_invalid_producer_secret_key_hex() {
        let config = NodeRuntimeConfig {
            producer_secret_key_hex: Some("zzzz".to_owned()),
            ..NodeRuntimeConfig::default()
        };
        let validation = config.validate();
        assert!(
            matches!(
                validation,
                Err(NodeConfigError::InvalidProducerSecretKeyHex { reason: _ })
            ),
            "malformed producer hex should be rejected"
        );
    }

    #[test]
    fn decodes_valid_producer_secret_key_hex() {
        let config = NodeRuntimeConfig {
            producer_secret_key_hex: Some(
                "0101010101010101010101010101010101010101010101010101010101010101".to_owned(),
            ),
            ..NodeRuntimeConfig::default()
        };
        let decoded = config.producer_secret_key_bytes();
        assert!(decoded.is_ok(), "valid producer secret key should decode");
        assert_eq!(
            decoded.unwrap_or(None).unwrap_or([0_u8; SECRET_KEY_LENGTH]),
            [1_u8; SECRET_KEY_LENGTH]
        );
    }
}
