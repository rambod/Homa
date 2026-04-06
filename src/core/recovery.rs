//! Crash-safe state persistence and recovery using a write-ahead snapshot log.

use std::fs::{self, File, OpenOptions};
use std::io::Write;
use std::path::{Path, PathBuf};

use thiserror::Error;

use crate::core::block::StateRoot;
use crate::core::state::{ChainState, StateError};
use crate::core::sync::{StateSnapshot, SyncError, build_state_snapshot};
use crate::crypto::address::Network;

/// Canonical persisted state snapshot filename.
pub const SNAPSHOT_FILE_NAME: &str = "chain_state.snapshot";
/// Write-ahead log filename used to guarantee recoverability across crashes.
pub const WAL_FILE_NAME: &str = "chain_state.wal";

/// Disk paths used by state commit and recovery routines.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RecoveryPaths {
    /// Storage root directory.
    pub directory: PathBuf,
    /// Canonical state snapshot file.
    pub snapshot_path: PathBuf,
    /// Write-ahead snapshot file.
    pub wal_path: PathBuf,
}

impl RecoveryPaths {
    /// Creates recovery paths rooted at `directory`.
    #[must_use]
    pub fn new(directory: PathBuf) -> Self {
        Self {
            snapshot_path: directory.join(SNAPSHOT_FILE_NAME),
            wal_path: directory.join(WAL_FILE_NAME),
            directory,
        }
    }
}

/// Commit report for an atomic snapshot persistence operation.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CommitReport {
    /// Height associated with the committed state snapshot.
    pub block_height: u64,
    /// State root of the committed snapshot.
    pub state_root: StateRoot,
    /// Number of encoded bytes persisted.
    pub bytes_written: usize,
}

/// Indicates which on-disk source was used during recovery.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RecoverySource {
    /// Recovered directly from canonical snapshot.
    Snapshot,
    /// Recovered from WAL and then promoted to canonical snapshot.
    WalPromoted,
}

/// Result of a successful crash-recovery load.
#[derive(Debug, Clone)]
pub struct RecoveredState {
    /// Restored chain state.
    pub state: ChainState,
    /// Source used for restore.
    pub source: RecoverySource,
    /// Height encoded in restored snapshot.
    pub block_height: u64,
    /// State root encoded in restored snapshot.
    pub state_root: StateRoot,
}

/// Errors produced by atomic state commit and recovery.
#[derive(Debug, Error)]
pub enum RecoveryError {
    /// No persisted state material exists.
    #[error("no persisted chain state found")]
    NoPersistedState,
    /// Directory creation failed.
    #[error("failed to create state directory: {path}")]
    CreateDirectory {
        /// Directory path.
        path: String,
    },
    /// File open failed.
    #[error("failed to open file: {path}")]
    OpenFile {
        /// File path.
        path: String,
    },
    /// File write failed.
    #[error("failed to write file: {path}")]
    WriteFile {
        /// File path.
        path: String,
    },
    /// File sync failed.
    #[error("failed to fsync file: {path}")]
    SyncFile {
        /// File path.
        path: String,
    },
    /// File rename failed.
    #[error("failed to atomically rename file: {from} -> {to}")]
    RenameFile {
        /// Temporary source file.
        from: String,
        /// Final destination file.
        to: String,
    },
    /// File read failed.
    #[error("failed to read file: {path}")]
    ReadFile {
        /// File path.
        path: String,
    },
    /// Snapshot encode failed.
    #[error("state snapshot encoding failed")]
    SnapshotEncode {
        /// Underlying snapshot encode error.
        source: SyncError,
    },
    /// Snapshot decode failed.
    #[error("state snapshot decoding failed: {path}")]
    SnapshotDecode {
        /// File path.
        path: String,
        /// Underlying snapshot decode error.
        source: SyncError,
    },
    /// Snapshot import into chain state failed.
    #[error("state snapshot import failed")]
    SnapshotImport {
        /// Underlying chain-state import error.
        source: StateError,
    },
    /// Snapshot-declared state root does not match computed root after import.
    #[error("snapshot integrity mismatch")]
    SnapshotIntegrityMismatch {
        /// Root encoded in snapshot metadata.
        expected: StateRoot,
        /// Root computed from restored account set.
        actual: StateRoot,
    },
}

/// Persists state using WAL-first atomic commit:
/// 1) write WAL snapshot
/// 2) write canonical snapshot
/// 3) remove WAL
pub fn commit_state_snapshot_atomic(
    state: &ChainState,
    block_height: u64,
    paths: &RecoveryPaths,
) -> Result<CommitReport, RecoveryError> {
    let snapshot = build_state_snapshot(state, block_height);
    let encoded = snapshot
        .encode()
        .map_err(|source| RecoveryError::SnapshotEncode { source })?;

    write_atomic_file(&paths.wal_path, &encoded)?;
    write_atomic_file(&paths.snapshot_path, &encoded)?;
    remove_file_if_exists(&paths.wal_path)?;

    Ok(CommitReport {
        block_height,
        state_root: snapshot.state_root,
        bytes_written: encoded.len(),
    })
}

/// Restores chain state from persisted snapshot files and reconciles WAL state.
///
/// Recovery behavior:
/// - If only snapshot exists, load snapshot.
/// - If only WAL exists, load WAL, promote it to snapshot, and clear WAL.
/// - If both exist, choose higher height (WAL wins ties), then clean stale file.
pub fn recover_chain_state(
    network: Network,
    paths: &RecoveryPaths,
) -> Result<RecoveredState, RecoveryError> {
    let snapshot = read_snapshot_if_exists(&paths.snapshot_path)?;
    let wal = read_snapshot_if_exists(&paths.wal_path)?;

    let (selected_snapshot, source, stale_wal) = match (snapshot, wal) {
        (None, None) => return Err(RecoveryError::NoPersistedState),
        (Some(snapshot), None) => (snapshot, RecoverySource::Snapshot, false),
        (None, Some(wal)) => (wal, RecoverySource::WalPromoted, false),
        (Some(snapshot), Some(wal)) => {
            if wal.block_height >= snapshot.block_height {
                (wal, RecoverySource::WalPromoted, false)
            } else {
                (snapshot, RecoverySource::Snapshot, true)
            }
        }
    };

    let restored_state = state_from_snapshot(network, &selected_snapshot)?;

    match source {
        RecoverySource::Snapshot => {
            if stale_wal {
                remove_file_if_exists(&paths.wal_path)?;
            }
        }
        RecoverySource::WalPromoted => {
            let encoded = selected_snapshot
                .encode()
                .map_err(|source| RecoveryError::SnapshotEncode { source })?;
            write_atomic_file(&paths.snapshot_path, &encoded)?;
            remove_file_if_exists(&paths.wal_path)?;
        }
    }

    Ok(RecoveredState {
        state: restored_state,
        source,
        block_height: selected_snapshot.block_height,
        state_root: selected_snapshot.state_root,
    })
}

fn state_from_snapshot(
    network: Network,
    snapshot: &StateSnapshot,
) -> Result<ChainState, RecoveryError> {
    let mut state = ChainState::new(network);
    let entries = snapshot
        .accounts
        .iter()
        .map(|entry| (entry.address.clone(), entry.state))
        .collect();

    state
        .load_snapshot(entries)
        .map_err(|source| RecoveryError::SnapshotImport { source })?;

    let computed_root = state.state_root();
    if computed_root != snapshot.state_root {
        return Err(RecoveryError::SnapshotIntegrityMismatch {
            expected: snapshot.state_root,
            actual: computed_root,
        });
    }

    Ok(state)
}

fn read_snapshot_if_exists(path: &Path) -> Result<Option<StateSnapshot>, RecoveryError> {
    if !path.exists() {
        return Ok(None);
    }

    let bytes = fs::read(path).map_err(|_| RecoveryError::ReadFile {
        path: display_path(path),
    })?;

    let snapshot =
        StateSnapshot::decode(&bytes).map_err(|source| RecoveryError::SnapshotDecode {
            path: display_path(path),
            source,
        })?;

    Ok(Some(snapshot))
}

fn write_atomic_file(path: &Path, bytes: &[u8]) -> Result<(), RecoveryError> {
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent).map_err(|_| RecoveryError::CreateDirectory {
            path: display_path(parent),
        })?;
    }

    let temporary_path = temp_path_for(path);
    let mut file = open_file_for_write(&temporary_path)?;
    file.write_all(bytes)
        .map_err(|_| RecoveryError::WriteFile {
            path: display_path(&temporary_path),
        })?;
    file.sync_all().map_err(|_| RecoveryError::SyncFile {
        path: display_path(&temporary_path),
    })?;

    fs::rename(&temporary_path, path).map_err(|_| RecoveryError::RenameFile {
        from: display_path(&temporary_path),
        to: display_path(path),
    })?;

    if let Some(parent) = path.parent() {
        sync_directory(parent)?;
    }

    Ok(())
}

fn open_file_for_write(path: &Path) -> Result<File, RecoveryError> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;

        let mut options = OpenOptions::new();
        options.create(true).truncate(true).write(true).mode(0o600);
        options.open(path).map_err(|_| RecoveryError::OpenFile {
            path: display_path(path),
        })
    }

    #[cfg(not(unix))]
    {
        OpenOptions::new()
            .create(true)
            .truncate(true)
            .write(true)
            .open(path)
            .map_err(|_| RecoveryError::OpenFile {
                path: display_path(path),
            })
    }
}

#[cfg(unix)]
fn sync_directory(directory: &Path) -> Result<(), RecoveryError> {
    let dir = File::open(directory).map_err(|_| RecoveryError::OpenFile {
        path: display_path(directory),
    })?;
    dir.sync_all().map_err(|_| RecoveryError::SyncFile {
        path: display_path(directory),
    })
}

#[cfg(not(unix))]
fn sync_directory(_directory: &Path) -> Result<(), RecoveryError> {
    Ok(())
}

fn remove_file_if_exists(path: &Path) -> Result<(), RecoveryError> {
    match fs::remove_file(path) {
        Ok(()) => Ok(()),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(_) => Err(RecoveryError::WriteFile {
            path: display_path(path),
        }),
    }
}

fn temp_path_for(path: &Path) -> PathBuf {
    let file_name = path
        .file_name()
        .and_then(|name| name.to_str())
        .unwrap_or("state");
    path.with_file_name(format!("{file_name}.tmp.{}", std::process::id()))
}

fn display_path(path: &Path) -> String {
    path.to_string_lossy().into_owned()
}

#[cfg(test)]
mod tests {
    use std::path::{Path, PathBuf};
    use std::time::{SystemTime, UNIX_EPOCH};

    use super::{
        RecoveryError, RecoveryPaths, RecoverySource, commit_state_snapshot_atomic,
        recover_chain_state, write_atomic_file,
    };
    use crate::core::state::{AccountState, ChainState};
    use crate::core::sync::build_state_snapshot;
    use crate::crypto::address::{Network, derive_address};
    use crate::crypto::keys::Keypair;

    struct TestDirectory {
        path: PathBuf,
    }

    impl TestDirectory {
        fn new() -> Self {
            let now_nanos = SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .map_or(0_u128, |duration| duration.as_nanos());
            let path = std::env::temp_dir().join(format!(
                "homa-recovery-test-{}-{now_nanos}",
                std::process::id()
            ));
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

    fn address(network: Network, seed: u8) -> String {
        let keypair = Keypair::from_secret_key(&[seed; 32]);
        assert!(keypair.is_ok(), "seeded keypair should be valid");
        let keypair = keypair.unwrap_or_else(|_| unreachable!());
        let derived = derive_address(&keypair.public_key_bytes(), network);
        assert!(derived.is_ok(), "address derivation should succeed");
        derived.unwrap_or_else(|_| unreachable!())
    }

    fn seeded_state(network: Network) -> (ChainState, String, String) {
        let sender = address(network, 7);
        let receiver = address(network, 8);

        let mut state = ChainState::new(network);
        let initialized =
            state.initialize_genesis(vec![(sender.clone(), 1_000), (receiver.clone(), 0)]);
        assert!(initialized.is_ok(), "genesis initialization should succeed");
        (state, sender, receiver)
    }

    #[test]
    fn commit_and_recover_from_snapshot() {
        let network = Network::Testnet;
        let test_directory = TestDirectory::new();
        let paths = RecoveryPaths::new(test_directory.path().to_path_buf());
        let (state, _, _) = seeded_state(network);

        let committed = commit_state_snapshot_atomic(&state, 4, &paths);
        assert!(committed.is_ok(), "state commit should succeed");

        let recovered = recover_chain_state(network, &paths);
        assert!(recovered.is_ok(), "state recovery should succeed");
        let recovered = recovered.unwrap_or_else(|_| unreachable!());

        assert_eq!(recovered.source, RecoverySource::Snapshot);
        assert_eq!(recovered.block_height, 4);
        assert_eq!(recovered.state_root, state.state_root());
        assert_eq!(recovered.state.state_root(), state.state_root());
        assert!(
            !paths.wal_path.exists(),
            "wal should be removed after successful commit"
        );
    }

    #[test]
    fn recovers_from_wal_when_snapshot_missing() {
        let network = Network::Devnet;
        let test_directory = TestDirectory::new();
        let paths = RecoveryPaths::new(test_directory.path().to_path_buf());
        let (state, _, _) = seeded_state(network);

        let snapshot = build_state_snapshot(&state, 10);
        let encoded = snapshot.encode();
        assert!(encoded.is_ok(), "snapshot encoding should succeed");
        let wal_written =
            write_atomic_file(&paths.wal_path, &encoded.unwrap_or_else(|_| unreachable!()));
        assert!(wal_written.is_ok(), "wal write should succeed");

        let recovered = recover_chain_state(network, &paths);
        assert!(recovered.is_ok(), "wal-based recovery should succeed");
        let recovered = recovered.unwrap_or_else(|_| unreachable!());
        assert_eq!(recovered.source, RecoverySource::WalPromoted);
        assert_eq!(recovered.block_height, 10);
        assert!(paths.snapshot_path.exists(), "wal should be promoted");
        assert!(
            !paths.wal_path.exists(),
            "wal should be cleared after promotion"
        );
    }

    #[test]
    fn prefers_newer_wal_over_snapshot() {
        let network = Network::Testnet;
        let test_directory = TestDirectory::new();
        let paths = RecoveryPaths::new(test_directory.path().to_path_buf());
        let (state, sender, receiver) = seeded_state(network);

        let snapshot_v1 = build_state_snapshot(&state, 1);
        let encoded_v1 = snapshot_v1.encode();
        assert!(encoded_v1.is_ok(), "snapshot v1 should encode");
        assert!(
            write_atomic_file(
                &paths.snapshot_path,
                &encoded_v1.unwrap_or_else(|_| unreachable!()),
            )
            .is_ok()
        );

        let mut state_v2 = state;
        let loaded = state_v2.load_snapshot(vec![
            (
                sender,
                AccountState {
                    balance: 900,
                    nonce: 1,
                },
            ),
            (
                receiver,
                AccountState {
                    balance: 100,
                    nonce: 0,
                },
            ),
        ]);
        assert!(loaded.is_ok(), "second snapshot state should load");

        let snapshot_v2 = build_state_snapshot(&state_v2, 2);
        let encoded_v2 = snapshot_v2.encode();
        assert!(encoded_v2.is_ok(), "snapshot v2 should encode");
        assert!(
            write_atomic_file(
                &paths.wal_path,
                &encoded_v2.unwrap_or_else(|_| unreachable!()),
            )
            .is_ok()
        );

        let recovered = recover_chain_state(network, &paths);
        assert!(recovered.is_ok(), "recovery should succeed");
        let recovered = recovered.unwrap_or_else(|_| unreachable!());
        assert_eq!(recovered.source, RecoverySource::WalPromoted);
        assert_eq!(recovered.block_height, 2);
        assert_eq!(recovered.state_root, state_v2.state_root());
        assert!(
            !paths.wal_path.exists(),
            "wal should be cleared after newer promotion"
        );
    }

    #[test]
    fn removes_stale_wal_when_snapshot_is_newer() {
        let network = Network::Mainnet;
        let test_directory = TestDirectory::new();
        let paths = RecoveryPaths::new(test_directory.path().to_path_buf());
        let (state, _, _) = seeded_state(network);

        let snapshot_v2 = build_state_snapshot(&state, 2);
        let encoded_v2 = snapshot_v2.encode();
        assert!(encoded_v2.is_ok(), "snapshot should encode");
        assert!(
            write_atomic_file(
                &paths.snapshot_path,
                &encoded_v2.unwrap_or_else(|_| unreachable!()),
            )
            .is_ok()
        );

        let snapshot_v1 = build_state_snapshot(&state, 1);
        let encoded_v1 = snapshot_v1.encode();
        assert!(encoded_v1.is_ok(), "snapshot should encode");
        assert!(
            write_atomic_file(
                &paths.wal_path,
                &encoded_v1.unwrap_or_else(|_| unreachable!()),
            )
            .is_ok()
        );

        let recovered = recover_chain_state(network, &paths);
        assert!(recovered.is_ok(), "recovery should succeed");
        let recovered = recovered.unwrap_or_else(|_| unreachable!());
        assert_eq!(recovered.source, RecoverySource::Snapshot);
        assert_eq!(recovered.block_height, 2);
        assert!(
            !paths.wal_path.exists(),
            "stale wal should be removed during recovery"
        );
    }

    #[test]
    fn rejects_tampered_snapshot_integrity() {
        let network = Network::Devnet;
        let test_directory = TestDirectory::new();
        let paths = RecoveryPaths::new(test_directory.path().to_path_buf());
        let (state, _, _) = seeded_state(network);

        let mut snapshot = build_state_snapshot(&state, 5);
        snapshot.state_root[0] ^= 0x01;
        let encoded = snapshot.encode();
        assert!(encoded.is_ok(), "snapshot should encode");
        assert!(
            write_atomic_file(
                &paths.snapshot_path,
                &encoded.unwrap_or_else(|_| unreachable!())
            )
            .is_ok()
        );

        let recovered = recover_chain_state(network, &paths);
        assert!(
            matches!(
                recovered,
                Err(RecoveryError::SnapshotIntegrityMismatch {
                    expected: _,
                    actual: _
                })
            ),
            "recovery must reject root-mismatched snapshots"
        );
    }

    #[test]
    fn reports_no_persisted_state() {
        let network = Network::Testnet;
        let test_directory = TestDirectory::new();
        let paths = RecoveryPaths::new(test_directory.path().to_path_buf());

        let recovered = recover_chain_state(network, &paths);
        assert!(
            matches!(recovered, Err(RecoveryError::NoPersistedState)),
            "empty storage should return no-state error"
        );
    }
}
