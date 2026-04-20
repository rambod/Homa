//! Durable mempool checkpoint persistence/recovery backed by `redb`.

use std::fs::{self, File};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};

use redb::{Database, ReadableTable, TableDefinition};
use thiserror::Error;

use crate::core::mempool::{Mempool, MempoolCheckpointEntry};
use crate::crypto::address::Network;

/// Canonical mempool checkpoint database filename.
pub const MEMPOOL_CHECKPOINT_FILE_NAME: &str = "mempool.checkpoint.redb";
const MEMPOOL_SCHEMA_VERSION: u64 = 1;
const MEMPOOL_MAX_ENTRY_BYTES: usize = 64 * 1024;
const META_KEY_SCHEMA_VERSION: &str = "schema_version";
const META_KEY_NETWORK: &str = "network";
const TEMP_FILE_NAME_FALLBACK: &str = "mempool.checkpoint";
static TEMP_FILE_COUNTER: AtomicU64 = AtomicU64::new(0);

const META_TABLE: TableDefinition<'static, &str, u64> = TableDefinition::new("mempool_meta");
const ENTRY_TABLE: TableDefinition<'static, u64, &[u8]> = TableDefinition::new("mempool_entries");

/// Disk paths used for mempool checkpoint persistence/recovery.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MempoolCheckpointPaths {
    /// Storage root directory.
    pub directory: PathBuf,
    /// Canonical checkpoint database file.
    pub checkpoint_path: PathBuf,
}

impl MempoolCheckpointPaths {
    /// Creates checkpoint paths rooted at `directory`.
    #[must_use]
    pub fn new(directory: PathBuf) -> Self {
        Self {
            checkpoint_path: directory.join(MEMPOOL_CHECKPOINT_FILE_NAME),
            directory,
        }
    }
}

/// Report produced after successful mempool checkpoint persistence.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct MempoolCheckpointPersistReport {
    /// Number of checkpoint entries written.
    pub entries_persisted: usize,
    /// Number of encoded entry bytes written.
    pub bytes_written: usize,
}

/// Typed errors emitted by mempool checkpoint persistence/recovery.
#[derive(Debug, Error)]
pub enum MempoolCheckpointError {
    /// Checkpoint directory creation failed.
    #[error("failed to create mempool checkpoint directory: {path}")]
    CreateCheckpointDirectory {
        /// Directory path.
        path: String,
        /// Underlying I/O error.
        source: std::io::Error,
    },
    /// Generic `redb` operation failure.
    #[error("mempool checkpoint redb operation failed ({operation}) at {path}: {reason}")]
    Redb {
        /// Operation label.
        operation: &'static str,
        /// Database path.
        path: String,
        /// Rendered `redb` error.
        reason: String,
    },
    /// Checkpoint entry serialization failed.
    #[error("mempool checkpoint entry serialization failed")]
    EntrySerialization,
    /// Checkpoint entry deserialization failed.
    #[error("mempool checkpoint entry deserialization failed")]
    EntryDeserialization,
    /// Persisted checkpoint metadata is missing.
    #[error("mempool checkpoint metadata is missing key: {key}")]
    MissingMetadata {
        /// Missing metadata key.
        key: &'static str,
    },
    /// Persisted schema version does not match runtime expectation.
    #[error("mempool checkpoint schema version mismatch: expected={expected}, observed={observed}")]
    SchemaVersionMismatch {
        /// Expected schema version.
        expected: u64,
        /// Observed schema version.
        observed: u64,
    },
    /// Persisted checkpoint network does not match expected runtime network.
    #[error("mempool checkpoint network mismatch: expected={expected}, observed={observed}")]
    NetworkMismatch {
        /// Expected network domain byte.
        expected: u8,
        /// Observed network domain byte.
        observed: u8,
    },
    /// Persisted entry index sequence is non-canonical/corrupted.
    #[error("mempool checkpoint entry index mismatch: expected={expected}, observed={observed}")]
    EntryIndexMismatch {
        /// Expected contiguous index.
        expected: u64,
        /// Observed index from `redb`.
        observed: u64,
    },
    /// Atomic checkpoint rename failed.
    #[error("failed to atomically rename mempool checkpoint: {from} -> {to}")]
    RenameCheckpoint {
        /// Temporary source path.
        from: String,
        /// Final destination path.
        to: String,
        /// Underlying I/O error.
        source: std::io::Error,
    },
    /// Parent-directory fsync failed.
    #[error("failed to fsync mempool checkpoint directory: {path}")]
    SyncCheckpointDirectory {
        /// Directory path.
        path: String,
        /// Underlying I/O error.
        source: std::io::Error,
    },
}

/// Persists current mempool entries as a durable checkpoint.
pub fn persist_mempool_checkpoint(
    mempool: &Mempool,
    paths: &MempoolCheckpointPaths,
) -> Result<MempoolCheckpointPersistReport, MempoolCheckpointError> {
    persist_mempool_checkpoint_entries(
        &mempool.checkpoint_entries(),
        mempool.config().network,
        paths,
    )
}

/// Persists explicit checkpoint entries as a durable checkpoint.
pub fn persist_mempool_checkpoint_entries(
    entries: &[MempoolCheckpointEntry],
    network: Network,
    paths: &MempoolCheckpointPaths,
) -> Result<MempoolCheckpointPersistReport, MempoolCheckpointError> {
    fs::create_dir_all(&paths.directory).map_err(|source| {
        MempoolCheckpointError::CreateCheckpointDirectory {
            path: display_path(&paths.directory),
            source,
        }
    })?;

    let temporary_path = temp_path_for(&paths.checkpoint_path);
    let persisted = persist_to_redb_path(entries, network, &temporary_path)?;
    fs::rename(&temporary_path, &paths.checkpoint_path).map_err(|source| {
        MempoolCheckpointError::RenameCheckpoint {
            from: display_path(&temporary_path),
            to: display_path(&paths.checkpoint_path),
            source,
        }
    })?;
    sync_directory(&paths.directory)?;
    Ok(persisted)
}

/// Recovers mempool checkpoint entries when one persisted file exists.
pub fn recover_mempool_checkpoint(
    paths: &MempoolCheckpointPaths,
    expected_network: Network,
) -> Result<Option<Vec<MempoolCheckpointEntry>>, MempoolCheckpointError> {
    if !paths.checkpoint_path.exists() {
        return Ok(None);
    }
    let entries = recover_from_redb_path(&paths.checkpoint_path, expected_network)?;
    Ok(Some(entries))
}

fn persist_to_redb_path(
    entries: &[MempoolCheckpointEntry],
    network: Network,
    checkpoint_path: &Path,
) -> Result<MempoolCheckpointPersistReport, MempoolCheckpointError> {
    if checkpoint_path.exists() {
        let _ = fs::remove_file(checkpoint_path);
    }

    let database = Database::create(checkpoint_path)
        .map_err(|source| redb_error("create", checkpoint_path, &source))?;
    let write_txn = database
        .begin_write()
        .map_err(|source| redb_error("begin_write", checkpoint_path, &source))?;
    let mut bytes_written = 0_usize;
    {
        let mut metadata = write_txn
            .open_table(META_TABLE)
            .map_err(|source| redb_error("open_meta_table", checkpoint_path, &source))?;
        metadata
            .insert(META_KEY_SCHEMA_VERSION, MEMPOOL_SCHEMA_VERSION)
            .map_err(|source| redb_error("insert_schema_version", checkpoint_path, &source))?;
        metadata
            .insert(META_KEY_NETWORK, u64::from(network.as_byte()))
            .map_err(|source| redb_error("insert_network", checkpoint_path, &source))?;

        let mut checkpoint_entries = write_txn
            .open_table(ENTRY_TABLE)
            .map_err(|source| redb_error("open_entry_table", checkpoint_path, &source))?;
        for (index, entry) in entries.iter().enumerate() {
            let encoded = bincode::serde::encode_to_vec(
                entry,
                bincode::config::standard()
                    .with_fixed_int_encoding()
                    .with_little_endian(),
            )
            .map_err(|_| MempoolCheckpointError::EntrySerialization)?;
            checkpoint_entries
                .insert(u64::try_from(index).unwrap_or(u64::MAX), encoded.as_slice())
                .map_err(|source| redb_error("insert_entry", checkpoint_path, &source))?;
            bytes_written = bytes_written.saturating_add(encoded.len());
        }
    }
    write_txn
        .commit()
        .map_err(|source| redb_error("commit", checkpoint_path, &source))?;
    Ok(MempoolCheckpointPersistReport {
        entries_persisted: entries.len(),
        bytes_written,
    })
}

fn recover_from_redb_path(
    checkpoint_path: &Path,
    expected_network: Network,
) -> Result<Vec<MempoolCheckpointEntry>, MempoolCheckpointError> {
    let database = Database::open(checkpoint_path)
        .map_err(|source| redb_error("open", checkpoint_path, &source))?;
    let read_txn = database
        .begin_read()
        .map_err(|source| redb_error("begin_read", checkpoint_path, &source))?;
    let metadata = read_txn
        .open_table(META_TABLE)
        .map_err(|source| redb_error("open_meta_table", checkpoint_path, &source))?;
    let schema_version = metadata
        .get(META_KEY_SCHEMA_VERSION)
        .map_err(|source| redb_error("read_schema_version", checkpoint_path, &source))?
        .ok_or(MempoolCheckpointError::MissingMetadata {
            key: META_KEY_SCHEMA_VERSION,
        })?
        .value();
    if schema_version != MEMPOOL_SCHEMA_VERSION {
        return Err(MempoolCheckpointError::SchemaVersionMismatch {
            expected: MEMPOOL_SCHEMA_VERSION,
            observed: schema_version,
        });
    }

    let persisted_network = metadata
        .get(META_KEY_NETWORK)
        .map_err(|source| redb_error("read_network", checkpoint_path, &source))?
        .ok_or(MempoolCheckpointError::MissingMetadata {
            key: META_KEY_NETWORK,
        })?
        .value();
    if persisted_network != u64::from(expected_network.as_byte()) {
        return Err(MempoolCheckpointError::NetworkMismatch {
            expected: expected_network.as_byte(),
            observed: u8::try_from(persisted_network).unwrap_or(u8::MAX),
        });
    }

    let checkpoint_entries = read_txn
        .open_table(ENTRY_TABLE)
        .map_err(|source| redb_error("open_entry_table", checkpoint_path, &source))?;
    let mut expected_index = 0_u64;
    let mut recovered = Vec::new();
    for row in checkpoint_entries
        .iter()
        .map_err(|source| redb_error("iter_entries", checkpoint_path, &source))?
    {
        let (index, encoded) =
            row.map_err(|source| redb_error("read_entry_row", checkpoint_path, &source))?;
        if index.value() != expected_index {
            return Err(MempoolCheckpointError::EntryIndexMismatch {
                expected: expected_index,
                observed: index.value(),
            });
        }
        let (entry, _) = bincode::serde::decode_from_slice(
            encoded.value(),
            bincode::config::standard()
                .with_fixed_int_encoding()
                .with_little_endian()
                .with_limit::<MEMPOOL_MAX_ENTRY_BYTES>(),
        )
        .map_err(|_| MempoolCheckpointError::EntryDeserialization)?;
        recovered.push(entry);
        expected_index = expected_index.saturating_add(1);
    }
    Ok(recovered)
}

fn redb_error(
    operation: &'static str,
    path: &Path,
    source: &impl ToString,
) -> MempoolCheckpointError {
    MempoolCheckpointError::Redb {
        operation,
        path: display_path(path),
        reason: source.to_string(),
    }
}

#[cfg(unix)]
fn sync_directory(directory: &Path) -> Result<(), MempoolCheckpointError> {
    let handle = File::open(directory).map_err(|source| {
        MempoolCheckpointError::SyncCheckpointDirectory {
            path: display_path(directory),
            source,
        }
    })?;
    handle
        .sync_all()
        .map_err(|source| MempoolCheckpointError::SyncCheckpointDirectory {
            path: display_path(directory),
            source,
        })
}

#[cfg(not(unix))]
fn sync_directory(_directory: &Path) -> Result<(), MempoolCheckpointError> {
    Ok(())
}

fn temp_path_for(path: &Path) -> PathBuf {
    let file_stem = path
        .file_name()
        .and_then(|value| value.to_str())
        .unwrap_or(TEMP_FILE_NAME_FALLBACK);
    let unique_suffix = TEMP_FILE_COUNTER.fetch_add(1, Ordering::Relaxed);
    path.with_file_name(format!(
        "{file_stem}.tmp.{}.{}",
        std::process::id(),
        unique_suffix
    ))
}

fn display_path(path: &Path) -> String {
    path.to_string_lossy().into_owned()
}

#[cfg(test)]
mod tests {
    use std::path::{Path, PathBuf};

    use super::{
        MEMPOOL_CHECKPOINT_FILE_NAME, MempoolCheckpointError, MempoolCheckpointPaths,
        persist_mempool_checkpoint, recover_mempool_checkpoint,
    };
    use crate::consensus::pow::mine_pow_nonce;
    use crate::core::mempool::{Mempool, MempoolConfig};
    use crate::core::transaction::Transaction;
    use crate::crypto::address::{Network, derive_address};
    use crate::crypto::keys::Keypair;

    struct TestDirectory {
        path: PathBuf,
    }

    impl TestDirectory {
        fn new(prefix: &str) -> Self {
            let unique = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map_or(0_u128, |value| value.as_nanos());
            let path =
                std::env::temp_dir().join(format!("{prefix}-{}-{unique}", std::process::id()));
            let created = std::fs::create_dir_all(&path);
            assert!(created.is_ok(), "test directory should be created");
            Self { path }
        }

        fn path(&self) -> &Path {
            &self.path
        }
    }

    impl Drop for TestDirectory {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.path);
        }
    }

    fn signed_transaction(network: Network, nonce: u64) -> Transaction {
        let sender_keypair = Keypair::generate();
        let receiver_keypair = Keypair::generate();
        let sender_address = derive_address(&sender_keypair.public_key_bytes(), network);
        assert!(sender_address.is_ok(), "sender address should derive");
        let receiver_address = derive_address(&receiver_keypair.public_key_bytes(), network);
        assert!(receiver_address.is_ok(), "receiver address should derive");

        let unsigned = Transaction::new_unsigned(
            sender_address.unwrap_or_else(|_| unreachable!()),
            receiver_address.unwrap_or_else(|_| unreachable!()),
            10,
            1,
            nonce,
            0,
        )
        .with_sender_public_key(sender_keypair.public_key_bytes());
        let solved = mine_pow_nonce(&unsigned, 8, 0, 900_000);
        assert!(solved.is_ok(), "pow solving should succeed");
        let mut mined = unsigned;
        mined.pow_nonce = solved.unwrap_or_else(|_| unreachable!()).nonce;
        let signing_bytes = mined.signing_bytes_for_network(network);
        assert!(signing_bytes.is_ok(), "signing bytes should build");
        mined.with_signature(sender_keypair.sign(&signing_bytes.unwrap_or_else(|_| unreachable!())))
    }

    #[test]
    fn persist_and_recover_roundtrip() {
        let network = Network::Testnet;
        let mut mempool = Mempool::new(MempoolConfig::new(16, 0, network));
        let inserted = mempool.insert(signed_transaction(network, 1));
        assert!(inserted.is_ok(), "transaction should enter mempool");
        let directory = TestDirectory::new("homa-mempool-checkpoint");
        let paths = MempoolCheckpointPaths::new(directory.path().to_path_buf());

        let persisted = persist_mempool_checkpoint(&mempool, &paths);
        assert!(persisted.is_ok(), "checkpoint persistence should succeed");
        let persisted = persisted.unwrap_or_else(|_| unreachable!());
        assert_eq!(persisted.entries_persisted, 1);
        assert!(persisted.bytes_written > 0);
        assert!(
            directory.path().join(MEMPOOL_CHECKPOINT_FILE_NAME).exists(),
            "checkpoint database should be written"
        );

        let recovered = recover_mempool_checkpoint(&paths, network);
        assert!(recovered.is_ok(), "checkpoint recovery should succeed");
        let recovered = recovered.unwrap_or_else(|_| unreachable!());
        assert!(recovered.is_some(), "checkpoint should be discovered");
        assert_eq!(
            recovered.unwrap_or_else(|| unreachable!()).len(),
            1,
            "one checkpoint transaction should roundtrip"
        );
    }

    #[test]
    fn recover_returns_none_for_missing_checkpoint() {
        let directory = TestDirectory::new("homa-mempool-checkpoint-missing");
        let paths = MempoolCheckpointPaths::new(directory.path().to_path_buf());

        let recovered = recover_mempool_checkpoint(&paths, Network::Devnet);
        assert!(
            matches!(recovered, Ok(None)),
            "missing mempool checkpoint should recover as None"
        );
    }

    #[test]
    fn recover_rejects_network_mismatch() {
        let mut mempool = Mempool::new(MempoolConfig::new(16, 0, Network::Testnet));
        let inserted = mempool.insert(signed_transaction(Network::Testnet, 1));
        assert!(inserted.is_ok(), "transaction should enter mempool");
        let directory = TestDirectory::new("homa-mempool-checkpoint-network-mismatch");
        let paths = MempoolCheckpointPaths::new(directory.path().to_path_buf());
        let persisted = persist_mempool_checkpoint(&mempool, &paths);
        assert!(persisted.is_ok(), "checkpoint persistence should succeed");

        let recovered = recover_mempool_checkpoint(&paths, Network::Mainnet);
        assert!(
            matches!(
                recovered,
                Err(MempoolCheckpointError::NetworkMismatch {
                    expected: _,
                    observed: _
                })
            ),
            "network mismatch should fail closed on recovery"
        );
    }
}
