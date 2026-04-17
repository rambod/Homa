//! Snapshot sync request scheduling and chunk-serving controls.

use std::collections::{BTreeMap, BTreeSet, HashMap, VecDeque};
use std::fs::{self, File, OpenOptions};
use std::io::Write;
use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};
use thiserror::Error;

use crate::core::sync::{
    CheckpointVerificationPolicy, SnapshotCheckpoint, SnapshotChunk, StateSnapshot, SyncError,
    verify_snapshot_checkpoint,
};
use crate::crypto::address::Network;
use crate::network::p2p::{SnapshotChunkRequest, SnapshotChunkResponse};

/// Upper bound for pending in-flight chunk requests.
pub const DEFAULT_MAX_IN_FLIGHT_REQUESTS: usize = 128;
/// Default timeout before one in-flight request is retried.
pub const DEFAULT_REQUEST_TIMEOUT_MS: u64 = 3_000;
/// Default retry budget per request after the initial send.
pub const DEFAULT_MAX_RETRIES: u8 = 3;
/// Default per-peer chunk request budget in one rolling window.
pub const DEFAULT_PER_PEER_QUOTA: usize = 64;
/// Default rolling window for per-peer serve quotas.
pub const DEFAULT_PER_PEER_QUOTA_WINDOW_MS: u64 = 1_000;
/// Default max in-flight chunks tracked per session.
pub const DEFAULT_MAX_IN_FLIGHT_PER_SESSION: usize = 16;
/// Default max in-flight chunks tracked across all sessions for one peer.
pub const DEFAULT_MAX_IN_FLIGHT_PER_PEER: usize = 64;
/// Default base backoff after one packet-loss event.
pub const DEFAULT_BASE_RETRY_BACKOFF_MS: u64 = 100;
/// Default upper bound for exponential retry backoff.
pub const DEFAULT_MAX_RETRY_BACKOFF_MS: u64 = 5_000;
/// Canonical persisted sync-session checkpoint filename.
pub const SYNC_SESSION_CHECKPOINT_FILE_NAME: &str = "sync_session.checkpoint";

/// Outbound chunk request scheduling policy.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct RequestSchedulerPolicy {
    /// Timeout for one in-flight request before retry.
    pub request_timeout_ms: u64,
    /// Retry budget after the initial send.
    pub max_retries: u8,
    /// Maximum number of simultaneously tracked in-flight requests.
    pub max_in_flight: usize,
}

impl RequestSchedulerPolicy {
    /// Strict default policy for high-latency public networks.
    #[must_use]
    pub const fn strict_default() -> Self {
        Self {
            request_timeout_ms: DEFAULT_REQUEST_TIMEOUT_MS,
            max_retries: DEFAULT_MAX_RETRIES,
            max_in_flight: DEFAULT_MAX_IN_FLIGHT_REQUESTS,
        }
    }
}

impl Default for RequestSchedulerPolicy {
    fn default() -> Self {
        Self::strict_default()
    }
}

/// Per-peer serving budget policy.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ChunkServePolicy {
    /// Max requests admitted from one peer in the rolling window.
    pub per_peer_quota: usize,
    /// Rolling window length for request accounting.
    pub quota_window_ms: u64,
}

impl ChunkServePolicy {
    /// Strict default serve policy for anti-amplification protection.
    #[must_use]
    pub const fn strict_default() -> Self {
        Self {
            per_peer_quota: DEFAULT_PER_PEER_QUOTA,
            quota_window_ms: DEFAULT_PER_PEER_QUOTA_WINDOW_MS,
        }
    }
}

impl Default for ChunkServePolicy {
    fn default() -> Self {
        Self::strict_default()
    }
}

/// Per-peer/per-session in-flight window and retry-backoff policy.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct ChunkSessionPolicy {
    /// Maximum in-flight chunk indexes per session.
    pub max_in_flight_per_session: usize,
    /// Maximum in-flight chunk indexes aggregated per peer across sessions.
    pub max_in_flight_per_peer: usize,
    /// Base retry backoff after one consecutive loss.
    pub base_retry_backoff_ms: u64,
    /// Hard upper bound for retry backoff.
    pub max_retry_backoff_ms: u64,
}

impl ChunkSessionPolicy {
    /// Strict default policy for adversarial links.
    #[must_use]
    pub const fn strict_default() -> Self {
        Self {
            max_in_flight_per_session: DEFAULT_MAX_IN_FLIGHT_PER_SESSION,
            max_in_flight_per_peer: DEFAULT_MAX_IN_FLIGHT_PER_PEER,
            base_retry_backoff_ms: DEFAULT_BASE_RETRY_BACKOFF_MS,
            max_retry_backoff_ms: DEFAULT_MAX_RETRY_BACKOFF_MS,
        }
    }
}

impl Default for ChunkSessionPolicy {
    fn default() -> Self {
        Self::strict_default()
    }
}

/// Outcome when trying to schedule one chunk request in a session window.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SessionSchedule {
    /// Chunk is admitted into in-flight set and can be sent now.
    Scheduled,
    /// Chunk is currently in cooldown; caller should retry at `retry_at_ms`.
    Deferred {
        /// Earliest retry timestamp.
        retry_at_ms: u64,
    },
}

/// Checkpoint policy stored in owned form for long-lived handshake config.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OwnedCheckpointPolicy {
    /// Network domain expected for checkpoint signatures.
    pub network: Network,
    /// Minimum number of trusted signatures required.
    pub min_signatures: usize,
    /// Trusted validator addresses accepted for checkpoint signatures.
    pub trusted_validators: Vec<String>,
}

impl OwnedCheckpointPolicy {
    #[must_use]
    fn as_borrowed(&self) -> CheckpointVerificationPolicy<'_> {
        CheckpointVerificationPolicy {
            network: self.network,
            min_signatures: self.min_signatures,
            trusted_validators: &self.trusted_validators,
        }
    }
}

/// Handshake mode deciding whether checkpoint metadata is mandatory.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SyncHandshakeMode {
    /// Accept snapshot metadata without validator checkpoint requirement.
    Permissive,
    /// Require and verify validator checkpoint before chunk stream acceptance.
    RequireCheckpoint {
        /// Trusted checkpoint verification policy.
        checkpoint_policy: OwnedCheckpointPolicy,
    },
}

/// Peer-advertised snapshot metadata for sync handshake.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SnapshotHandshakeAdvertisement {
    /// Snapshot block height being advertised.
    pub block_height: u64,
    /// Snapshot state root being advertised.
    pub state_root: [u8; 32],
    /// Hash of full serialized snapshot payload.
    pub snapshot_hash: [u8; 32],
    /// Optional validator-signed checkpoint.
    pub checkpoint: Option<SnapshotCheckpoint>,
}

/// Disk locations for persisted sync-session checkpoint state.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SyncSessionCheckpointPaths {
    /// Storage root directory.
    pub directory: PathBuf,
    /// Canonical sync-session checkpoint file.
    pub checkpoint_path: PathBuf,
}

impl SyncSessionCheckpointPaths {
    /// Creates persisted-path mapping rooted at `directory`.
    #[must_use]
    pub fn new(directory: PathBuf) -> Self {
        Self {
            checkpoint_path: directory.join(SYNC_SESSION_CHECKPOINT_FILE_NAME),
            directory,
        }
    }
}

/// One persisted in-flight request entry.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PendingRequestCheckpoint {
    /// Peer id currently responsible for this request.
    pub peer_id: String,
    /// Request payload.
    pub request: SnapshotChunkRequest,
    /// Current attempt number.
    pub attempt: u8,
    /// Retry deadline timestamp.
    pub deadline_ms: u64,
}

/// Persisted scheduler state.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ChunkRequestSchedulerCheckpoint {
    /// Scheduler policy.
    pub policy: RequestSchedulerPolicy,
    /// In-flight request map keyed by request id.
    pub in_flight: Vec<(u64, PendingRequestCheckpoint)>,
}

/// One persisted retry/backoff entry for a chunk index.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ChunkRetryCheckpoint {
    /// Chunk index.
    pub chunk_index: u32,
    /// Consecutive loss count.
    pub consecutive_losses: u8,
    /// Earliest retry timestamp.
    pub retry_at_ms: u64,
}

/// One persisted session window state.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SessionCheckpoint {
    /// Peer id.
    pub peer_id: String,
    /// Session id.
    pub session_id: u64,
    /// In-flight chunk indices.
    pub in_flight_chunks: Vec<u32>,
    /// Retry checkpoints keyed by chunk index.
    pub retry_state: Vec<ChunkRetryCheckpoint>,
}

/// Persisted session manager state.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ChunkSessionManagerCheckpoint {
    /// Session policy.
    pub policy: ChunkSessionPolicy,
    /// Peer-level in-flight counters.
    pub peer_in_flight: Vec<(String, usize)>,
    /// Session window entries.
    pub sessions: Vec<SessionCheckpoint>,
}

/// Combined persisted sync-session checkpoint payload.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SyncSessionCheckpoint {
    /// Outbound request scheduler state.
    pub scheduler: ChunkRequestSchedulerCheckpoint,
    /// Session window state.
    pub session_manager: ChunkSessionManagerCheckpoint,
}

impl SyncSessionCheckpoint {
    /// Encodes checkpoint as compact deterministic bytes.
    pub fn encode(&self) -> Result<Vec<u8>, SyncEngineError> {
        bincode::serde::encode_to_vec(
            self,
            bincode::config::standard()
                .with_fixed_int_encoding()
                .with_little_endian(),
        )
        .map_err(|_| SyncEngineError::CheckpointSerialization)
    }

    /// Decodes checkpoint from compact deterministic bytes.
    pub fn decode(bytes: &[u8]) -> Result<Self, SyncEngineError> {
        bincode::serde::decode_from_slice(
            bytes,
            bincode::config::standard()
                .with_fixed_int_encoding()
                .with_little_endian(),
        )
        .map(|(checkpoint, _)| checkpoint)
        .map_err(|_| SyncEngineError::CheckpointDeserialization)
    }

    /// Captures scheduler + session manager runtime state into one checkpoint.
    #[must_use]
    pub fn from_runtime(
        scheduler: &ChunkRequestScheduler,
        session_manager: &ChunkSessionManager,
    ) -> Self {
        Self {
            scheduler: scheduler.checkpoint(),
            session_manager: session_manager.checkpoint(),
        }
    }

    /// Restores runtime scheduler + session manager from one checkpoint payload.
    pub fn into_runtime(
        self,
    ) -> Result<(ChunkRequestScheduler, ChunkSessionManager), SyncEngineError> {
        let scheduler = ChunkRequestScheduler::from_checkpoint(self.scheduler)?;
        let session_manager = ChunkSessionManager::from_checkpoint(self.session_manager)?;
        Ok((scheduler, session_manager))
    }
}

/// One request that should be (re)dispatched to a peer.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RetryDispatch {
    /// Target peer id.
    pub peer_id: String,
    /// Request payload.
    pub request: SnapshotChunkRequest,
    /// Attempt counter (1 = initial send, 2+ = retries).
    pub attempt: u8,
}

/// One request that exhausted retry budget without response.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ExhaustedRequest {
    /// Target peer id.
    pub peer_id: String,
    /// Final request payload.
    pub request: SnapshotChunkRequest,
    /// Attempts consumed before exhaustion.
    pub attempts: u8,
}

/// Aggregated timeout poll result.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct RetryPollOutcome {
    /// Requests that should be sent again.
    pub retries: Vec<RetryDispatch>,
    /// Requests that were dropped after retry budget exhaustion.
    pub exhausted: Vec<ExhaustedRequest>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct PendingRequest {
    peer_id: String,
    request: SnapshotChunkRequest,
    attempt: u8,
    deadline_ms: u64,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct ChunkRetryState {
    consecutive_losses: u8,
    retry_at_ms: u64,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct SessionState {
    in_flight_chunks: BTreeSet<u32>,
    retry_state: BTreeMap<u32, ChunkRetryState>,
}

type SessionKey = (String, u64);
type SessionMap = HashMap<SessionKey, SessionState>;
type PeerInFlightMap = HashMap<String, usize>;

/// Typed sync-engine failures for scheduler and serve controls.
#[derive(Debug, Clone, PartialEq, Eq, Error)]
pub enum SyncEngineError {
    /// Scheduler policy thresholds must be non-zero.
    #[error(
        "invalid scheduler policy: request_timeout_ms={request_timeout_ms}, max_in_flight={max_in_flight}"
    )]
    InvalidSchedulerPolicy {
        /// Configured timeout.
        request_timeout_ms: u64,
        /// Configured in-flight limit.
        max_in_flight: usize,
    },
    /// Serve policy thresholds must be non-zero.
    #[error(
        "invalid chunk serve policy: per_peer_quota={per_peer_quota}, quota_window_ms={quota_window_ms}"
    )]
    InvalidServePolicy {
        /// Configured per-peer quota.
        per_peer_quota: usize,
        /// Configured window length.
        quota_window_ms: u64,
    },
    /// Scheduler already tracks the request id.
    #[error("duplicate in-flight request id: {request_id}")]
    DuplicateRequestId {
        /// Colliding request id.
        request_id: u64,
    },
    /// Scheduler cannot exceed configured in-flight limit.
    #[error("in-flight request limit exceeded: limit={limit}")]
    InFlightLimitExceeded {
        /// Maximum allowed in-flight requests.
        limit: usize,
    },
    /// Response/acknowledgement referenced unknown request id.
    #[error("unknown in-flight request id: {request_id}")]
    UnknownRequestId {
        /// Missing request id.
        request_id: u64,
    },
    /// Peer exceeded rolling serve quota.
    #[error(
        "peer chunk request quota exceeded: peer={peer_id}, quota={quota}, window_ms={window_ms}"
    )]
    PeerQuotaExceeded {
        /// Offending peer id.
        peer_id: String,
        /// Quota threshold.
        quota: usize,
        /// Window length.
        window_ms: u64,
    },
    /// Session policy thresholds must be non-zero and internally coherent.
    #[error(
        "invalid chunk session policy: per_session={max_in_flight_per_session}, per_peer={max_in_flight_per_peer}, base_backoff_ms={base_retry_backoff_ms}, max_backoff_ms={max_retry_backoff_ms}"
    )]
    InvalidSessionPolicy {
        /// Session in-flight cap.
        max_in_flight_per_session: usize,
        /// Peer in-flight cap.
        max_in_flight_per_peer: usize,
        /// Base retry backoff.
        base_retry_backoff_ms: u64,
        /// Max retry backoff.
        max_retry_backoff_ms: u64,
    },
    /// One session exceeded its in-flight chunk window.
    #[error(
        "session in-flight chunk limit exceeded: peer={peer_id}, session_id={session_id}, limit={limit}"
    )]
    SessionInFlightLimitExceeded {
        /// Peer id.
        peer_id: String,
        /// Session id.
        session_id: u64,
        /// Configured limit.
        limit: usize,
    },
    /// One peer exceeded aggregate in-flight chunks across sessions.
    #[error("peer in-flight chunk limit exceeded: peer={peer_id}, limit={limit}")]
    PeerInFlightLimitExceeded {
        /// Peer id.
        peer_id: String,
        /// Configured limit.
        limit: usize,
    },
    /// Duplicate chunk scheduling attempt in same session.
    #[error(
        "duplicate in-flight chunk in session: peer={peer_id}, session_id={session_id}, chunk_index={chunk_index}"
    )]
    DuplicateChunkInFlight {
        /// Peer id.
        peer_id: String,
        /// Session id.
        session_id: u64,
        /// Chunk index.
        chunk_index: u32,
    },
    /// Chunk completion/loss reported for chunk not in in-flight window.
    #[error(
        "unknown in-flight chunk in session: peer={peer_id}, session_id={session_id}, chunk_index={chunk_index}"
    )]
    UnknownInFlightChunk {
        /// Peer id.
        peer_id: String,
        /// Session id.
        session_id: u64,
        /// Chunk index.
        chunk_index: u32,
    },
    /// Snapshot metadata advertised in handshake has mismatched height.
    #[error("snapshot handshake height mismatch: expected {expected}, advertised {advertised}")]
    HandshakeHeightMismatch {
        /// Expected snapshot height.
        expected: u64,
        /// Advertised snapshot height.
        advertised: u64,
    },
    /// Snapshot metadata advertised in handshake has mismatched state root.
    #[error("snapshot handshake state-root mismatch")]
    HandshakeStateRootMismatch {
        /// Expected snapshot state root.
        expected: [u8; 32],
        /// Advertised snapshot state root.
        advertised: [u8; 32],
    },
    /// Snapshot metadata advertised in handshake has mismatched payload hash.
    #[error("snapshot handshake payload-hash mismatch")]
    HandshakeSnapshotHashMismatch {
        /// Expected snapshot payload hash.
        expected: [u8; 32],
        /// Advertised snapshot payload hash.
        advertised: [u8; 32],
    },
    /// Strict handshake mode requires a checkpoint advertisement.
    #[error("missing required checkpoint in strict sync handshake")]
    MissingRequiredCheckpoint,
    /// Snapshot encoding failed while computing handshake payload hash.
    #[error("snapshot handshake encoding failed")]
    SnapshotEncoding {
        /// Underlying sync encoding error.
        source: SyncError,
    },
    /// Advertised checkpoint failed cryptographic verification policy.
    #[error("snapshot handshake checkpoint verification failed")]
    CheckpointVerification {
        /// Underlying checkpoint verification error.
        source: SyncError,
    },
    /// Chunk vector length cannot be represented as `u32`.
    #[error("chunk set too large: {count}")]
    ChunkSetTooLarge {
        /// Actual chunk count.
        count: usize,
    },
    /// Requested chunk index is outside available chunk set.
    #[error("requested chunk index out of range: index={index}, total={total}")]
    ChunkIndexOutOfRange {
        /// Requested chunk index.
        index: u32,
        /// Available chunk count.
        total: u32,
    },
    /// Chunk metadata mismatch between request and served chunk.
    #[error("chunk request/response metadata mismatch for field {field}")]
    ChunkMetadataMismatch {
        /// Field name that mismatched.
        field: &'static str,
    },
    /// Checkpoint serialization failed.
    #[error("sync-session checkpoint serialization failed")]
    CheckpointSerialization,
    /// Checkpoint deserialization failed.
    #[error("sync-session checkpoint deserialization failed")]
    CheckpointDeserialization,
    /// Persisted checkpoint file path could not be created.
    #[error("failed to create sync checkpoint directory: {path}")]
    CreateCheckpointDirectory {
        /// Directory path.
        path: String,
    },
    /// Persisted checkpoint file could not be opened.
    #[error("failed to open sync checkpoint file: {path}")]
    OpenCheckpointFile {
        /// File path.
        path: String,
    },
    /// Persisted checkpoint file write failed.
    #[error("failed to write sync checkpoint file: {path}")]
    WriteCheckpointFile {
        /// File path.
        path: String,
    },
    /// Persisted checkpoint file sync failed.
    #[error("failed to fsync sync checkpoint file: {path}")]
    SyncCheckpointFile {
        /// File path.
        path: String,
    },
    /// Persisted checkpoint rename failed.
    #[error("failed to atomically rename sync checkpoint file: {from} -> {to}")]
    RenameCheckpointFile {
        /// Temporary source file.
        from: String,
        /// Final destination file.
        to: String,
    },
    /// Persisted checkpoint file read failed.
    #[error("failed to read sync checkpoint file: {path}")]
    ReadCheckpointFile {
        /// File path.
        path: String,
    },
    /// Persisted request checkpoint stored mismatched request-id fields.
    #[error(
        "persisted request-id mismatch: map_key={request_id}, payload_request_id={payload_request_id}"
    )]
    PersistedRequestIdMismatch {
        /// Request-id map key.
        request_id: u64,
        /// Request id carried inside payload.
        payload_request_id: u64,
    },
    /// Persisted request checkpoint stored an invalid zero attempt.
    #[error("persisted request checkpoint has invalid zero attempt: request_id={request_id}")]
    PersistedRequestAttemptZero {
        /// Offending request id.
        request_id: u64,
    },
    /// Persisted retry checkpoint stored an invalid zero loss count.
    #[error(
        "persisted retry checkpoint has invalid zero loss count: peer={peer_id}, session_id={session_id}, chunk_index={chunk_index}"
    )]
    PersistedRetryLossCountZero {
        /// Peer id.
        peer_id: String,
        /// Session id.
        session_id: u64,
        /// Chunk index.
        chunk_index: u32,
    },
    /// Persisted checkpoint contained duplicate peer counter entries.
    #[error("persisted peer in-flight counter duplicate entry: peer={peer_id}")]
    PersistedDuplicatePeerCounter {
        /// Peer id.
        peer_id: String,
    },
    /// Persisted checkpoint contained duplicate session entries.
    #[error(
        "persisted session checkpoint duplicate entry: peer={peer_id}, session_id={session_id}"
    )]
    PersistedDuplicateSessionEntry {
        /// Peer id.
        peer_id: String,
        /// Session id.
        session_id: u64,
    },
    /// Persisted checkpoint contained duplicate in-flight chunk entry.
    #[error(
        "persisted in-flight chunk duplicate entry: peer={peer_id}, session_id={session_id}, chunk_index={chunk_index}"
    )]
    PersistedDuplicateInFlightChunk {
        /// Peer id.
        peer_id: String,
        /// Session id.
        session_id: u64,
        /// Chunk index.
        chunk_index: u32,
    },
    /// Persisted checkpoint contained duplicate retry state entry.
    #[error(
        "persisted retry-state duplicate entry: peer={peer_id}, session_id={session_id}, chunk_index={chunk_index}"
    )]
    PersistedDuplicateRetryState {
        /// Peer id.
        peer_id: String,
        /// Session id.
        session_id: u64,
        /// Chunk index.
        chunk_index: u32,
    },
    /// Persisted checkpoint placed one chunk in both in-flight and retry state.
    #[error(
        "persisted session chunk appears in both in-flight and retry state: peer={peer_id}, session_id={session_id}, chunk_index={chunk_index}"
    )]
    PersistedChunkStateConflict {
        /// Peer id.
        peer_id: String,
        /// Session id.
        session_id: u64,
        /// Chunk index.
        chunk_index: u32,
    },
    /// Persisted peer in-flight counters do not match reconstructed session state.
    #[error(
        "persisted peer in-flight mismatch: peer={peer_id}, expected={expected}, actual={actual}"
    )]
    PersistedPeerInFlightMismatch {
        /// Peer id.
        peer_id: String,
        /// Expected count from reconstructed sessions.
        expected: usize,
        /// Actual count declared in persisted peer map.
        actual: usize,
    },
}

const fn validate_scheduler_policy(policy: RequestSchedulerPolicy) -> Result<(), SyncEngineError> {
    if policy.request_timeout_ms == 0 || policy.max_in_flight == 0 {
        return Err(SyncEngineError::InvalidSchedulerPolicy {
            request_timeout_ms: policy.request_timeout_ms,
            max_in_flight: policy.max_in_flight,
        });
    }
    Ok(())
}

const fn validate_serve_policy(policy: ChunkServePolicy) -> Result<(), SyncEngineError> {
    if policy.per_peer_quota == 0 || policy.quota_window_ms == 0 {
        return Err(SyncEngineError::InvalidServePolicy {
            per_peer_quota: policy.per_peer_quota,
            quota_window_ms: policy.quota_window_ms,
        });
    }
    Ok(())
}

const fn validate_session_policy(policy: ChunkSessionPolicy) -> Result<(), SyncEngineError> {
    if policy.max_in_flight_per_session == 0
        || policy.max_in_flight_per_peer == 0
        || policy.base_retry_backoff_ms == 0
        || policy.max_retry_backoff_ms == 0
        || policy.max_in_flight_per_session > policy.max_in_flight_per_peer
        || policy.base_retry_backoff_ms > policy.max_retry_backoff_ms
    {
        return Err(SyncEngineError::InvalidSessionPolicy {
            max_in_flight_per_session: policy.max_in_flight_per_session,
            max_in_flight_per_peer: policy.max_in_flight_per_peer,
            base_retry_backoff_ms: policy.base_retry_backoff_ms,
            max_retry_backoff_ms: policy.max_retry_backoff_ms,
        });
    }
    Ok(())
}

fn display_path(path: &Path) -> String {
    path.to_string_lossy().into_owned()
}

fn temp_path_for(path: &Path) -> PathBuf {
    let file_name = path
        .file_name()
        .and_then(|name| name.to_str())
        .unwrap_or("sync_session");
    path.with_file_name(format!("{file_name}.tmp.{}", std::process::id()))
}

fn open_file_for_write(path: &Path) -> Result<File, SyncEngineError> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;

        let mut options = OpenOptions::new();
        options.create(true).truncate(true).write(true).mode(0o600);
        options
            .open(path)
            .map_err(|_| SyncEngineError::OpenCheckpointFile {
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
            .map_err(|_| SyncEngineError::OpenCheckpointFile {
                path: display_path(path),
            })
    }
}

#[cfg(unix)]
fn sync_directory(directory: &Path) -> Result<(), SyncEngineError> {
    let directory_handle =
        File::open(directory).map_err(|_| SyncEngineError::OpenCheckpointFile {
            path: display_path(directory),
        })?;
    directory_handle
        .sync_all()
        .map_err(|_| SyncEngineError::SyncCheckpointFile {
            path: display_path(directory),
        })
}

#[cfg(not(unix))]
fn sync_directory(_directory: &Path) -> Result<(), SyncEngineError> {
    Ok(())
}

fn write_checkpoint_atomic(path: &Path, bytes: &[u8]) -> Result<(), SyncEngineError> {
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent).map_err(|_| SyncEngineError::CreateCheckpointDirectory {
            path: display_path(parent),
        })?;
    }

    let temporary_path = temp_path_for(path);
    let mut file = open_file_for_write(&temporary_path)?;
    file.write_all(bytes)
        .map_err(|_| SyncEngineError::WriteCheckpointFile {
            path: display_path(&temporary_path),
        })?;
    file.sync_all()
        .map_err(|_| SyncEngineError::SyncCheckpointFile {
            path: display_path(&temporary_path),
        })?;

    fs::rename(&temporary_path, path).map_err(|_| SyncEngineError::RenameCheckpointFile {
        from: display_path(&temporary_path),
        to: display_path(path),
    })?;

    if let Some(parent) = path.parent() {
        sync_directory(parent)?;
    }
    Ok(())
}

/// Persists one sync-session checkpoint payload using atomic replace semantics.
pub fn persist_sync_session_checkpoint(
    checkpoint: &SyncSessionCheckpoint,
    paths: &SyncSessionCheckpointPaths,
) -> Result<usize, SyncEngineError> {
    let encoded = checkpoint.encode()?;
    write_checkpoint_atomic(&paths.checkpoint_path, &encoded)?;
    Ok(encoded.len())
}

/// Persists runtime scheduler/session state into one sync-session checkpoint file.
pub fn persist_sync_runtime_checkpoint(
    scheduler: &ChunkRequestScheduler,
    session_manager: &ChunkSessionManager,
    paths: &SyncSessionCheckpointPaths,
) -> Result<usize, SyncEngineError> {
    let checkpoint = SyncSessionCheckpoint::from_runtime(scheduler, session_manager);
    persist_sync_session_checkpoint(&checkpoint, paths)
}

/// Recovers one sync-session checkpoint from disk when present.
pub fn recover_sync_session_checkpoint(
    paths: &SyncSessionCheckpointPaths,
) -> Result<Option<SyncSessionCheckpoint>, SyncEngineError> {
    let bytes = match fs::read(&paths.checkpoint_path) {
        Ok(bytes) => bytes,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(_) => {
            return Err(SyncEngineError::ReadCheckpointFile {
                path: display_path(&paths.checkpoint_path),
            });
        }
    };
    let checkpoint = SyncSessionCheckpoint::decode(&bytes)?;
    Ok(Some(checkpoint))
}

/// Recovers runtime scheduler/session state from a persisted sync-session checkpoint.
pub fn recover_sync_runtime_checkpoint(
    paths: &SyncSessionCheckpointPaths,
) -> Result<Option<(ChunkRequestScheduler, ChunkSessionManager)>, SyncEngineError> {
    let Some(checkpoint) = recover_sync_session_checkpoint(paths)? else {
        return Ok(None);
    };
    let runtime = checkpoint.into_runtime()?;
    Ok(Some(runtime))
}

fn snapshot_payload_hash(snapshot: &StateSnapshot) -> Result<[u8; 32], SyncEngineError> {
    let encoded = snapshot
        .encode()
        .map_err(|source| SyncEngineError::SnapshotEncoding { source })?;
    Ok(*blake3::hash(&encoded).as_bytes())
}

/// Validates peer-advertised sync handshake metadata before chunk stream acceptance.
pub fn validate_snapshot_handshake(
    snapshot: &StateSnapshot,
    advertisement: &SnapshotHandshakeAdvertisement,
    mode: &SyncHandshakeMode,
) -> Result<(), SyncEngineError> {
    if advertisement.block_height != snapshot.block_height {
        return Err(SyncEngineError::HandshakeHeightMismatch {
            expected: snapshot.block_height,
            advertised: advertisement.block_height,
        });
    }
    if advertisement.state_root != snapshot.state_root {
        return Err(SyncEngineError::HandshakeStateRootMismatch {
            expected: snapshot.state_root,
            advertised: advertisement.state_root,
        });
    }

    let expected_hash = snapshot_payload_hash(snapshot)?;
    if advertisement.snapshot_hash != expected_hash {
        return Err(SyncEngineError::HandshakeSnapshotHashMismatch {
            expected: expected_hash,
            advertised: advertisement.snapshot_hash,
        });
    }

    if let SyncHandshakeMode::RequireCheckpoint { checkpoint_policy } = mode {
        let checkpoint = advertisement
            .checkpoint
            .as_ref()
            .ok_or(SyncEngineError::MissingRequiredCheckpoint)?;
        verify_snapshot_checkpoint(snapshot, checkpoint, checkpoint_policy.as_borrowed())
            .map_err(|source| SyncEngineError::CheckpointVerification { source })?;
    }

    Ok(())
}

/// Tracks in-flight chunk requests with retry timeout/retry budgets.
#[derive(Debug, Clone)]
pub struct ChunkRequestScheduler {
    policy: RequestSchedulerPolicy,
    in_flight: BTreeMap<u64, PendingRequest>,
}

impl ChunkRequestScheduler {
    /// Creates a request scheduler from explicit policy.
    pub fn new(policy: RequestSchedulerPolicy) -> Result<Self, SyncEngineError> {
        validate_scheduler_policy(policy)?;
        Ok(Self {
            policy,
            in_flight: BTreeMap::new(),
        })
    }

    /// Schedules one outbound request and starts timeout tracking.
    pub fn schedule(
        &mut self,
        peer_id: String,
        request: SnapshotChunkRequest,
        now_ms: u64,
    ) -> Result<(), SyncEngineError> {
        if self.in_flight.contains_key(&request.request_id) {
            return Err(SyncEngineError::DuplicateRequestId {
                request_id: request.request_id,
            });
        }
        if self.in_flight.len() >= self.policy.max_in_flight {
            return Err(SyncEngineError::InFlightLimitExceeded {
                limit: self.policy.max_in_flight,
            });
        }

        self.in_flight.insert(
            request.request_id,
            PendingRequest {
                peer_id,
                request,
                attempt: 1,
                deadline_ms: now_ms.saturating_add(self.policy.request_timeout_ms),
            },
        );
        Ok(())
    }

    /// Acknowledges a completed request and removes it from in-flight set.
    pub fn acknowledge(&mut self, request_id: u64) -> Result<(), SyncEngineError> {
        if self.in_flight.remove(&request_id).is_none() {
            return Err(SyncEngineError::UnknownRequestId { request_id });
        }
        Ok(())
    }

    /// Returns in-flight request context without mutating scheduler state.
    pub fn in_flight_request_context(
        &self,
        request_id: u64,
    ) -> Result<PendingRequestCheckpoint, SyncEngineError> {
        let Some(pending) = self.in_flight.get(&request_id) else {
            return Err(SyncEngineError::UnknownRequestId { request_id });
        };
        Ok(PendingRequestCheckpoint {
            peer_id: pending.peer_id.clone(),
            request: pending.request,
            attempt: pending.attempt,
            deadline_ms: pending.deadline_ms,
        })
    }

    /// Polls timeout state and returns retry/exhausted actions.
    pub fn poll_timeouts(&mut self, now_ms: u64) -> RetryPollOutcome {
        let timed_out = self
            .in_flight
            .iter()
            .filter_map(|(request_id, pending)| {
                if now_ms >= pending.deadline_ms {
                    return Some(*request_id);
                }
                None
            })
            .collect::<Vec<_>>();

        let mut outcome = RetryPollOutcome::default();
        for request_id in timed_out {
            let Some(pending) = self.in_flight.get_mut(&request_id) else {
                continue;
            };
            if pending.attempt <= self.policy.max_retries {
                pending.attempt = pending.attempt.saturating_add(1);
                pending.deadline_ms = now_ms.saturating_add(self.policy.request_timeout_ms);
                outcome.retries.push(RetryDispatch {
                    peer_id: pending.peer_id.clone(),
                    request: pending.request,
                    attempt: pending.attempt,
                });
                continue;
            }

            if let Some(expired) = self.in_flight.remove(&request_id) {
                outcome.exhausted.push(ExhaustedRequest {
                    peer_id: expired.peer_id,
                    request: expired.request,
                    attempts: expired.attempt,
                });
            }
        }
        outcome
    }

    /// Returns number of currently tracked in-flight requests.
    #[must_use]
    pub fn in_flight_count(&self) -> usize {
        self.in_flight.len()
    }

    /// Drops all in-flight requests during process restart recovery.
    ///
    /// The request-session map lives in the runtime coordinator (not in this scheduler),
    /// so recovered in-flight requests cannot be safely replayed after restart.
    pub fn abandon_in_flight_for_restart(&mut self) -> usize {
        let dropped = self.in_flight.len();
        self.in_flight.clear();
        dropped
    }

    /// Returns scheduler policy.
    #[must_use]
    pub const fn policy(&self) -> RequestSchedulerPolicy {
        self.policy
    }

    /// Exports current scheduler state into a persistable checkpoint payload.
    #[must_use]
    pub fn checkpoint(&self) -> ChunkRequestSchedulerCheckpoint {
        let in_flight = self
            .in_flight
            .iter()
            .map(|(request_id, pending)| {
                (
                    *request_id,
                    PendingRequestCheckpoint {
                        peer_id: pending.peer_id.clone(),
                        request: pending.request,
                        attempt: pending.attempt,
                        deadline_ms: pending.deadline_ms,
                    },
                )
            })
            .collect();

        ChunkRequestSchedulerCheckpoint {
            policy: self.policy,
            in_flight,
        }
    }

    /// Restores scheduler state from persisted checkpoint bytes.
    pub fn from_checkpoint(
        checkpoint: ChunkRequestSchedulerCheckpoint,
    ) -> Result<Self, SyncEngineError> {
        validate_scheduler_policy(checkpoint.policy)?;
        if checkpoint.in_flight.len() > checkpoint.policy.max_in_flight {
            return Err(SyncEngineError::InFlightLimitExceeded {
                limit: checkpoint.policy.max_in_flight,
            });
        }

        let mut in_flight = BTreeMap::new();
        for (request_id, pending) in checkpoint.in_flight {
            if pending.request.request_id != request_id {
                return Err(SyncEngineError::PersistedRequestIdMismatch {
                    request_id,
                    payload_request_id: pending.request.request_id,
                });
            }
            if pending.attempt == 0 {
                return Err(SyncEngineError::PersistedRequestAttemptZero { request_id });
            }
            if in_flight.contains_key(&request_id) {
                return Err(SyncEngineError::DuplicateRequestId { request_id });
            }
            in_flight.insert(
                request_id,
                PendingRequest {
                    peer_id: pending.peer_id,
                    request: pending.request,
                    attempt: pending.attempt,
                    deadline_ms: pending.deadline_ms,
                },
            );
        }

        Ok(Self {
            policy: checkpoint.policy,
            in_flight,
        })
    }
}

/// Tracks per-peer serve quotas for anti-amplification controls.
#[derive(Debug, Clone)]
pub struct ChunkServeLimiter {
    policy: ChunkServePolicy,
    peer_windows: HashMap<String, VecDeque<u64>>,
}

impl ChunkServeLimiter {
    /// Creates a serve limiter from explicit policy.
    pub fn new(policy: ChunkServePolicy) -> Result<Self, SyncEngineError> {
        validate_serve_policy(policy)?;
        Ok(Self {
            policy,
            peer_windows: HashMap::new(),
        })
    }

    /// Admits or rejects one request from `peer_id` at `now_ms`.
    pub fn admit(&mut self, peer_id: &str, now_ms: u64) -> Result<(), SyncEngineError> {
        self.admit_with_quota(peer_id, now_ms, self.policy.per_peer_quota)
    }

    /// Admits one request using an explicit dynamic quota override.
    pub fn admit_with_quota(
        &mut self,
        peer_id: &str,
        now_ms: u64,
        quota: usize,
    ) -> Result<(), SyncEngineError> {
        let cutoff = now_ms.saturating_sub(self.policy.quota_window_ms);
        let window = self.peer_windows.entry(peer_id.to_owned()).or_default();
        while let Some(oldest) = window.front().copied() {
            if oldest >= cutoff {
                break;
            }
            let _ = window.pop_front();
        }
        if window.len() >= quota {
            return Err(SyncEngineError::PeerQuotaExceeded {
                peer_id: peer_id.to_owned(),
                quota,
                window_ms: self.policy.quota_window_ms,
            });
        }
        window.push_back(now_ms);
        Ok(())
    }
}

/// Tracks per-peer/per-session chunk windows and deterministic retry backoff.
#[derive(Debug, Clone)]
pub struct ChunkSessionManager {
    policy: ChunkSessionPolicy,
    peer_in_flight: PeerInFlightMap,
    sessions: SessionMap,
}

impl ChunkSessionManager {
    /// Creates a session manager with strict window/backoff constraints.
    pub fn new(policy: ChunkSessionPolicy) -> Result<Self, SyncEngineError> {
        validate_session_policy(policy)?;
        Ok(Self {
            policy,
            peer_in_flight: HashMap::new(),
            sessions: HashMap::new(),
        })
    }

    /// Tries to schedule `chunk_index` for one `(peer_id, session_id)` stream.
    pub fn try_schedule_chunk(
        &mut self,
        peer_id: &str,
        session_id: u64,
        chunk_index: u32,
        now_ms: u64,
    ) -> Result<SessionSchedule, SyncEngineError> {
        let peer_key = peer_id.to_owned();
        let session_key = (peer_key.clone(), session_id);
        let peer_in_flight = self.peer_in_flight.entry(peer_key.clone()).or_insert(0);
        if *peer_in_flight >= self.policy.max_in_flight_per_peer {
            return Err(SyncEngineError::PeerInFlightLimitExceeded {
                peer_id: peer_key,
                limit: self.policy.max_in_flight_per_peer,
            });
        }

        let session = self
            .sessions
            .entry(session_key)
            .or_insert_with(|| SessionState {
                in_flight_chunks: BTreeSet::new(),
                retry_state: BTreeMap::new(),
            });
        if session.in_flight_chunks.contains(&chunk_index) {
            return Err(SyncEngineError::DuplicateChunkInFlight {
                peer_id: peer_id.to_owned(),
                session_id,
                chunk_index,
            });
        }
        if session.in_flight_chunks.len() >= self.policy.max_in_flight_per_session {
            return Err(SyncEngineError::SessionInFlightLimitExceeded {
                peer_id: peer_id.to_owned(),
                session_id,
                limit: self.policy.max_in_flight_per_session,
            });
        }

        if let Some(retry_state) = session.retry_state.get(&chunk_index)
            && now_ms < retry_state.retry_at_ms
        {
            return Ok(SessionSchedule::Deferred {
                retry_at_ms: retry_state.retry_at_ms,
            });
        }

        let inserted = session.in_flight_chunks.insert(chunk_index);
        if inserted {
            *peer_in_flight = peer_in_flight.saturating_add(1);
        }
        Ok(SessionSchedule::Scheduled)
    }

    /// Marks chunk delivery success, removes it from in-flight, and clears loss history.
    pub fn acknowledge_chunk(
        &mut self,
        peer_id: &str,
        session_id: u64,
        chunk_index: u32,
    ) -> Result<(), SyncEngineError> {
        let session_key = (peer_id.to_owned(), session_id);
        let Some(session) = self.sessions.get_mut(&session_key) else {
            return Err(SyncEngineError::UnknownInFlightChunk {
                peer_id: peer_id.to_owned(),
                session_id,
                chunk_index,
            });
        };
        if !session.in_flight_chunks.remove(&chunk_index) {
            return Err(SyncEngineError::UnknownInFlightChunk {
                peer_id: peer_id.to_owned(),
                session_id,
                chunk_index,
            });
        }
        session.retry_state.remove(&chunk_index);
        if let Some(in_flight) = self.peer_in_flight.get_mut(peer_id) {
            *in_flight = in_flight.saturating_sub(1);
        }
        Ok(())
    }

    /// Marks packet loss for one in-flight chunk and computes deterministic retry timestamp.
    pub fn report_loss(
        &mut self,
        peer_id: &str,
        session_id: u64,
        chunk_index: u32,
        now_ms: u64,
    ) -> Result<u64, SyncEngineError> {
        let session_key = (peer_id.to_owned(), session_id);
        let Some(session) = self.sessions.get_mut(&session_key) else {
            return Err(SyncEngineError::UnknownInFlightChunk {
                peer_id: peer_id.to_owned(),
                session_id,
                chunk_index,
            });
        };
        if !session.in_flight_chunks.remove(&chunk_index) {
            return Err(SyncEngineError::UnknownInFlightChunk {
                peer_id: peer_id.to_owned(),
                session_id,
                chunk_index,
            });
        }
        if let Some(in_flight) = self.peer_in_flight.get_mut(peer_id) {
            *in_flight = in_flight.saturating_sub(1);
        }

        let retry_state = session
            .retry_state
            .entry(chunk_index)
            .or_insert(ChunkRetryState {
                consecutive_losses: 0,
                retry_at_ms: now_ms,
            });
        retry_state.consecutive_losses = retry_state.consecutive_losses.saturating_add(1);
        let shift = u32::from(retry_state.consecutive_losses.saturating_sub(1)).min(20);
        let multiplier = 1_u64 << shift;
        let backoff = self
            .policy
            .base_retry_backoff_ms
            .saturating_mul(multiplier)
            .min(self.policy.max_retry_backoff_ms);
        retry_state.retry_at_ms = now_ms.saturating_add(backoff);
        Ok(retry_state.retry_at_ms)
    }

    /// Returns current in-flight chunk count for one peer across sessions.
    #[must_use]
    pub fn peer_in_flight_count(&self, peer_id: &str) -> usize {
        self.peer_in_flight.get(peer_id).copied().unwrap_or(0)
    }

    /// Returns total in-flight chunk count across all peers/sessions.
    #[must_use]
    pub fn total_in_flight_count(&self) -> usize {
        self.peer_in_flight.values().copied().sum()
    }

    /// Drops all in-flight session-chunk state during process restart recovery.
    ///
    /// This preserves historical retry/backoff entries while clearing transport state that
    /// depends on volatile request-session bindings.
    pub fn abandon_in_flight_for_restart(&mut self) -> usize {
        let mut dropped = 0_usize;
        for state in self.sessions.values_mut() {
            dropped = dropped.saturating_add(state.in_flight_chunks.len());
            state.in_flight_chunks.clear();
        }
        self.peer_in_flight.clear();
        self.sessions
            .retain(|_, state| !state.in_flight_chunks.is_empty() || !state.retry_state.is_empty());
        dropped
    }

    /// Returns session policy.
    #[must_use]
    pub const fn policy(&self) -> ChunkSessionPolicy {
        self.policy
    }

    /// Exports current session manager state into a persistable checkpoint payload.
    #[must_use]
    pub fn checkpoint(&self) -> ChunkSessionManagerCheckpoint {
        let mut peer_in_flight = self
            .peer_in_flight
            .iter()
            .map(|(peer_id, count)| (peer_id.clone(), *count))
            .collect::<Vec<_>>();
        peer_in_flight.sort_by(|left, right| left.0.cmp(&right.0));

        let mut sessions = self
            .sessions
            .iter()
            .map(|((peer_id, session_id), state)| SessionCheckpoint {
                peer_id: peer_id.clone(),
                session_id: *session_id,
                in_flight_chunks: state.in_flight_chunks.iter().copied().collect(),
                retry_state: state
                    .retry_state
                    .iter()
                    .map(|(chunk_index, retry)| ChunkRetryCheckpoint {
                        chunk_index: *chunk_index,
                        consecutive_losses: retry.consecutive_losses,
                        retry_at_ms: retry.retry_at_ms,
                    })
                    .collect(),
            })
            .collect::<Vec<_>>();
        sessions.sort_by(|left, right| {
            left.peer_id
                .cmp(&right.peer_id)
                .then(left.session_id.cmp(&right.session_id))
        });

        ChunkSessionManagerCheckpoint {
            policy: self.policy,
            peer_in_flight,
            sessions,
        }
    }

    /// Restores session manager state from one persisted checkpoint payload.
    pub fn from_checkpoint(
        checkpoint: ChunkSessionManagerCheckpoint,
    ) -> Result<Self, SyncEngineError> {
        validate_session_policy(checkpoint.policy)?;
        let persisted_peer_in_flight = parse_persisted_peer_counters(checkpoint.peer_in_flight)?;
        let (sessions, computed_peer_in_flight) =
            parse_persisted_sessions(checkpoint.sessions, checkpoint.policy)?;
        validate_persisted_peer_counters(&persisted_peer_in_flight, &computed_peer_in_flight)?;

        Ok(Self {
            policy: checkpoint.policy,
            peer_in_flight: persisted_peer_in_flight,
            sessions,
        })
    }
}

fn parse_persisted_peer_counters(
    peer_counters: Vec<(String, usize)>,
) -> Result<PeerInFlightMap, SyncEngineError> {
    let mut persisted_peer_in_flight = HashMap::new();
    for (peer_id, count) in peer_counters {
        if persisted_peer_in_flight.contains_key(&peer_id) {
            return Err(SyncEngineError::PersistedDuplicatePeerCounter { peer_id });
        }
        persisted_peer_in_flight.insert(peer_id, count);
    }
    Ok(persisted_peer_in_flight)
}

fn parse_persisted_sessions(
    persisted_sessions: Vec<SessionCheckpoint>,
    policy: ChunkSessionPolicy,
) -> Result<(SessionMap, PeerInFlightMap), SyncEngineError> {
    let mut sessions = HashMap::new();
    let mut computed_peer_in_flight = HashMap::new();

    for persisted_session in persisted_sessions {
        let session_key = (
            persisted_session.peer_id.clone(),
            persisted_session.session_id,
        );
        if sessions.contains_key(&session_key) {
            return Err(SyncEngineError::PersistedDuplicateSessionEntry {
                peer_id: persisted_session.peer_id,
                session_id: persisted_session.session_id,
            });
        }

        let mut in_flight_chunks = BTreeSet::new();
        for &chunk_index in &persisted_session.in_flight_chunks {
            if in_flight_chunks.contains(&chunk_index) {
                return Err(SyncEngineError::PersistedDuplicateInFlightChunk {
                    peer_id: persisted_session.peer_id.clone(),
                    session_id: persisted_session.session_id,
                    chunk_index,
                });
            }
            in_flight_chunks.insert(chunk_index);
        }
        if in_flight_chunks.len() > policy.max_in_flight_per_session {
            return Err(SyncEngineError::SessionInFlightLimitExceeded {
                peer_id: persisted_session.peer_id,
                session_id: persisted_session.session_id,
                limit: policy.max_in_flight_per_session,
            });
        }

        let retry_state = parse_persisted_retry_state(&persisted_session, &in_flight_chunks)?;

        let peer_total = computed_peer_in_flight
            .entry(persisted_session.peer_id.clone())
            .or_insert(0_usize);
        *peer_total = peer_total.saturating_add(in_flight_chunks.len());
        if *peer_total > policy.max_in_flight_per_peer {
            return Err(SyncEngineError::PeerInFlightLimitExceeded {
                peer_id: persisted_session.peer_id,
                limit: policy.max_in_flight_per_peer,
            });
        }

        sessions.insert(
            session_key,
            SessionState {
                in_flight_chunks,
                retry_state,
            },
        );
    }

    Ok((sessions, computed_peer_in_flight))
}

fn parse_persisted_retry_state(
    session: &SessionCheckpoint,
    in_flight_chunks: &BTreeSet<u32>,
) -> Result<BTreeMap<u32, ChunkRetryState>, SyncEngineError> {
    let mut retry_state = BTreeMap::new();
    for retry_entry in &session.retry_state {
        if retry_state.contains_key(&retry_entry.chunk_index) {
            return Err(SyncEngineError::PersistedDuplicateRetryState {
                peer_id: session.peer_id.clone(),
                session_id: session.session_id,
                chunk_index: retry_entry.chunk_index,
            });
        }
        if retry_entry.consecutive_losses == 0 {
            return Err(SyncEngineError::PersistedRetryLossCountZero {
                peer_id: session.peer_id.clone(),
                session_id: session.session_id,
                chunk_index: retry_entry.chunk_index,
            });
        }
        if in_flight_chunks.contains(&retry_entry.chunk_index) {
            return Err(SyncEngineError::PersistedChunkStateConflict {
                peer_id: session.peer_id.clone(),
                session_id: session.session_id,
                chunk_index: retry_entry.chunk_index,
            });
        }
        retry_state.insert(
            retry_entry.chunk_index,
            ChunkRetryState {
                consecutive_losses: retry_entry.consecutive_losses,
                retry_at_ms: retry_entry.retry_at_ms,
            },
        );
    }
    Ok(retry_state)
}

fn validate_persisted_peer_counters(
    persisted_peer_in_flight: &PeerInFlightMap,
    computed_peer_in_flight: &PeerInFlightMap,
) -> Result<(), SyncEngineError> {
    for (peer_id, expected) in computed_peer_in_flight {
        let actual = persisted_peer_in_flight.get(peer_id).copied().unwrap_or(0);
        if actual != *expected {
            return Err(SyncEngineError::PersistedPeerInFlightMismatch {
                peer_id: peer_id.clone(),
                expected: *expected,
                actual,
            });
        }
    }
    for (peer_id, actual) in persisted_peer_in_flight {
        let expected = computed_peer_in_flight.get(peer_id).copied().unwrap_or(0);
        if *actual != expected {
            return Err(SyncEngineError::PersistedPeerInFlightMismatch {
                peer_id: peer_id.clone(),
                expected,
                actual: *actual,
            });
        }
    }
    Ok(())
}

/// Validates and serves one chunk request under per-peer quota controls.
pub fn serve_chunk_request(
    limiter: &mut ChunkServeLimiter,
    peer_id: &str,
    now_ms: u64,
    request: SnapshotChunkRequest,
    chunks: &[SnapshotChunk],
) -> Result<SnapshotChunkResponse, SyncEngineError> {
    limiter.admit(peer_id, now_ms)?;

    let total = u32::try_from(chunks.len()).map_err(|_| SyncEngineError::ChunkSetTooLarge {
        count: chunks.len(),
    })?;
    let chunk = chunks
        .get(usize::try_from(request.chunk_index).unwrap_or(usize::MAX))
        .ok_or(SyncEngineError::ChunkIndexOutOfRange {
            index: request.chunk_index,
            total,
        })?;

    if request.total_chunks != chunk.total_chunks {
        return Err(SyncEngineError::ChunkMetadataMismatch {
            field: "total_chunks",
        });
    }
    if request.block_height != chunk.block_height {
        return Err(SyncEngineError::ChunkMetadataMismatch {
            field: "block_height",
        });
    }
    if request.state_root != chunk.state_root {
        return Err(SyncEngineError::ChunkMetadataMismatch {
            field: "state_root",
        });
    }
    if request.snapshot_hash != chunk.snapshot_hash {
        return Err(SyncEngineError::ChunkMetadataMismatch {
            field: "snapshot_hash",
        });
    }
    if request.chunk_index != chunk.chunk_index {
        return Err(SyncEngineError::ChunkMetadataMismatch {
            field: "chunk_index",
        });
    }
    if request.total_chunks != total {
        return Err(SyncEngineError::ChunkMetadataMismatch {
            field: "chunk_set_total",
        });
    }

    Ok(SnapshotChunkResponse {
        request_id: request.request_id,
        chunk: chunk.clone(),
    })
}

#[cfg(test)]
mod tests {
    use std::path::{Path, PathBuf};
    use std::sync::atomic::{AtomicU64, Ordering};
    use std::time::{SystemTime, UNIX_EPOCH};

    use super::{
        ChunkRequestScheduler, ChunkServeLimiter, ChunkServePolicy, ChunkSessionManager,
        ChunkSessionPolicy, OwnedCheckpointPolicy, RequestSchedulerPolicy, SessionSchedule,
        SnapshotHandshakeAdvertisement, SyncEngineError, SyncHandshakeMode, SyncSessionCheckpoint,
        SyncSessionCheckpointPaths, persist_sync_runtime_checkpoint,
        recover_sync_runtime_checkpoint, recover_sync_session_checkpoint, serve_chunk_request,
        validate_snapshot_handshake,
    };
    use crate::core::state::AccountState;
    use crate::core::sync::{
        SnapshotAccount, SnapshotCheckpoint, StateSnapshot, sign_snapshot_checkpoint,
        split_snapshot_into_chunks,
    };
    use crate::crypto::address::{Network, derive_address};
    use crate::crypto::keys::Keypair;
    use crate::network::p2p::SnapshotChunkRequest;

    static TEST_DIRECTORY_COUNTER: AtomicU64 = AtomicU64::new(0);

    struct TestDirectory {
        path: PathBuf,
    }

    impl TestDirectory {
        fn new() -> Self {
            let now_nanos = SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .map(|value| value.as_nanos())
                .unwrap_or(0);
            let unique_id = TEST_DIRECTORY_COUNTER.fetch_add(1, Ordering::Relaxed);
            let path = std::env::temp_dir().join(format!(
                "homa-sync-session-test-{}-{now_nanos}-{unique_id}",
                std::process::id(),
            ));
            let created = std::fs::create_dir_all(&path);
            assert!(created.is_ok(), "temp directory creation should succeed");
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

    fn sample_snapshot() -> StateSnapshot {
        StateSnapshot {
            block_height: 10,
            state_root: [1_u8; 32],
            accounts: vec![
                SnapshotAccount {
                    address: "HMA_SYNC_SVC_A".to_owned(),
                    state: AccountState {
                        balance: 100,
                        nonce: 1,
                    },
                },
                SnapshotAccount {
                    address: "HMA_SYNC_SVC_B".to_owned(),
                    state: AccountState {
                        balance: 200,
                        nonce: 0,
                    },
                },
            ],
        }
    }

    fn sample_chunks() -> Vec<crate::core::sync::SnapshotChunk> {
        let snapshot = sample_snapshot();
        let chunks = split_snapshot_into_chunks(&snapshot, 24);
        assert!(chunks.is_ok(), "snapshot chunk split should succeed");
        chunks.unwrap_or_else(|_| unreachable!())
    }

    #[test]
    fn scheduler_retries_and_exhausts_after_budget() {
        let scheduler = ChunkRequestScheduler::new(RequestSchedulerPolicy {
            request_timeout_ms: 100,
            max_retries: 1,
            max_in_flight: 8,
        });
        assert!(scheduler.is_ok(), "scheduler should initialize");
        let mut scheduler = scheduler.unwrap_or_else(|_| unreachable!());
        let chunks = sample_chunks();
        let first = &chunks[0];
        let request = SnapshotChunkRequest {
            request_id: 1,
            block_height: first.block_height,
            state_root: first.state_root,
            snapshot_hash: first.snapshot_hash,
            chunk_index: first.chunk_index,
            total_chunks: first.total_chunks,
        };

        assert!(
            scheduler
                .schedule("peer-a".to_owned(), request, 1_000)
                .is_ok(),
            "initial schedule should succeed"
        );
        assert_eq!(scheduler.in_flight_count(), 1);

        let first_timeout = scheduler.poll_timeouts(1_100);
        assert_eq!(first_timeout.retries.len(), 1);
        assert_eq!(first_timeout.exhausted.len(), 0);
        assert_eq!(first_timeout.retries[0].attempt, 2);

        let second_timeout = scheduler.poll_timeouts(1_200);
        assert_eq!(second_timeout.retries.len(), 0);
        assert_eq!(second_timeout.exhausted.len(), 1);
        assert_eq!(second_timeout.exhausted[0].attempts, 2);
        assert_eq!(scheduler.in_flight_count(), 0);
    }

    #[test]
    fn scheduler_enforces_in_flight_limit_and_acknowledgement() {
        let scheduler = ChunkRequestScheduler::new(RequestSchedulerPolicy {
            request_timeout_ms: 100,
            max_retries: 2,
            max_in_flight: 1,
        });
        assert!(scheduler.is_ok(), "scheduler should initialize");
        let mut scheduler = scheduler.unwrap_or_else(|_| unreachable!());
        let chunks = sample_chunks();
        let chunk = &chunks[0];
        let request_one = SnapshotChunkRequest {
            request_id: 7,
            block_height: chunk.block_height,
            state_root: chunk.state_root,
            snapshot_hash: chunk.snapshot_hash,
            chunk_index: chunk.chunk_index,
            total_chunks: chunk.total_chunks,
        };
        let request_two = SnapshotChunkRequest {
            request_id: 8,
            ..request_one
        };

        assert!(
            scheduler
                .schedule("peer-a".to_owned(), request_one, 1_000)
                .is_ok()
        );
        let denied = scheduler.schedule("peer-b".to_owned(), request_two, 1_000);
        assert!(
            matches!(
                denied,
                Err(SyncEngineError::InFlightLimitExceeded { limit: 1 })
            ),
            "scheduler should reject beyond configured in-flight cap"
        );

        assert!(scheduler.acknowledge(7).is_ok());
        assert!(
            scheduler
                .schedule("peer-b".to_owned(), request_two, 1_001)
                .is_ok()
        );
    }

    #[test]
    fn scheduler_abandon_in_flight_for_restart_clears_requests() {
        let scheduler = ChunkRequestScheduler::new(RequestSchedulerPolicy {
            request_timeout_ms: 100,
            max_retries: 1,
            max_in_flight: 4,
        });
        assert!(scheduler.is_ok(), "scheduler should initialize");
        let mut scheduler = scheduler.unwrap_or_else(|_| unreachable!());
        let chunks = sample_chunks();
        let request = SnapshotChunkRequest {
            request_id: 99,
            block_height: chunks[0].block_height,
            state_root: chunks[0].state_root,
            snapshot_hash: chunks[0].snapshot_hash,
            chunk_index: chunks[0].chunk_index,
            total_chunks: chunks[0].total_chunks,
        };
        assert!(
            scheduler
                .schedule("peer-restart".to_owned(), request, 1_000)
                .is_ok(),
            "scheduler should accept in-flight request before restart sanitization"
        );
        assert_eq!(scheduler.in_flight_count(), 1);

        let dropped = scheduler.abandon_in_flight_for_restart();
        assert_eq!(
            dropped, 1,
            "exactly one in-flight request should be dropped"
        );
        assert_eq!(
            scheduler.in_flight_count(),
            0,
            "scheduler should be empty after restart sanitization"
        );
    }

    #[test]
    fn serve_limiter_blocks_peer_burst_and_allows_after_window() {
        let limiter = ChunkServeLimiter::new(ChunkServePolicy {
            per_peer_quota: 2,
            quota_window_ms: 50,
        });
        assert!(limiter.is_ok(), "serve limiter should initialize");
        let mut limiter = limiter.unwrap_or_else(|_| unreachable!());

        assert!(limiter.admit("peer-1", 10).is_ok());
        assert!(limiter.admit("peer-1", 20).is_ok());
        let denied = limiter.admit("peer-1", 40);
        assert!(
            matches!(
                denied,
                Err(SyncEngineError::PeerQuotaExceeded {
                    peer_id: _,
                    quota: 2,
                    window_ms: 50
                })
            ),
            "peer burst should be rate-limited"
        );

        assert!(
            limiter.admit("peer-1", 80).is_ok(),
            "quota should recover after rolling window elapses"
        );
    }

    #[test]
    fn handshake_permissive_accepts_matching_metadata_without_checkpoint() {
        let snapshot = sample_snapshot();
        let payload_hash = super::snapshot_payload_hash(&snapshot);
        assert!(payload_hash.is_ok(), "snapshot hash should compute");
        let advertisement = SnapshotHandshakeAdvertisement {
            block_height: snapshot.block_height,
            state_root: snapshot.state_root,
            snapshot_hash: payload_hash.unwrap_or_else(|_| unreachable!()),
            checkpoint: None,
        };

        let validated =
            validate_snapshot_handshake(&snapshot, &advertisement, &SyncHandshakeMode::Permissive);
        assert!(
            validated.is_ok(),
            "permissive mode should accept matching metadata without checkpoint"
        );
    }

    #[test]
    fn handshake_strict_rejects_missing_checkpoint() {
        let snapshot = sample_snapshot();
        let payload_hash = super::snapshot_payload_hash(&snapshot);
        assert!(payload_hash.is_ok(), "snapshot hash should compute");
        let advertisement = SnapshotHandshakeAdvertisement {
            block_height: snapshot.block_height,
            state_root: snapshot.state_root,
            snapshot_hash: payload_hash.unwrap_or_else(|_| unreachable!()),
            checkpoint: None,
        };
        let mode = SyncHandshakeMode::RequireCheckpoint {
            checkpoint_policy: OwnedCheckpointPolicy {
                network: Network::Testnet,
                min_signatures: 1,
                trusted_validators: vec!["placeholder".to_owned()],
            },
        };

        let validated = validate_snapshot_handshake(&snapshot, &advertisement, &mode);
        assert!(
            matches!(validated, Err(SyncEngineError::MissingRequiredCheckpoint)),
            "strict mode must reject handshake without checkpoint"
        );
    }

    #[test]
    fn handshake_strict_accepts_valid_checkpoint() {
        let snapshot = sample_snapshot();
        let payload_hash = super::snapshot_payload_hash(&snapshot);
        assert!(payload_hash.is_ok(), "snapshot hash should compute");

        let keypair = Keypair::generate();
        let validator_address = derive_address(&keypair.public_key_bytes(), Network::Testnet);
        assert!(
            validator_address.is_ok(),
            "validator address derivation should succeed"
        );
        let validator_address = validator_address.unwrap_or_else(|_| unreachable!());

        let signature = sign_snapshot_checkpoint(
            &snapshot,
            Network::Testnet,
            validator_address.clone(),
            &keypair,
        );
        assert!(signature.is_ok(), "checkpoint signing should succeed");
        let mut checkpoint = SnapshotCheckpoint::new(&snapshot, Network::Testnet);
        checkpoint
            .signatures
            .push(signature.unwrap_or_else(|_| unreachable!()));

        let advertisement = SnapshotHandshakeAdvertisement {
            block_height: snapshot.block_height,
            state_root: snapshot.state_root,
            snapshot_hash: payload_hash.unwrap_or_else(|_| unreachable!()),
            checkpoint: Some(checkpoint),
        };
        let mode = SyncHandshakeMode::RequireCheckpoint {
            checkpoint_policy: OwnedCheckpointPolicy {
                network: Network::Testnet,
                min_signatures: 1,
                trusted_validators: vec![validator_address],
            },
        };

        let validated = validate_snapshot_handshake(&snapshot, &advertisement, &mode);
        assert!(
            validated.is_ok(),
            "strict mode should accept valid trusted checkpoint"
        );
    }

    #[test]
    fn handshake_strict_rejects_tampered_checkpoint() {
        let snapshot = sample_snapshot();
        let payload_hash = super::snapshot_payload_hash(&snapshot);
        assert!(payload_hash.is_ok(), "snapshot hash should compute");

        let keypair = Keypair::generate();
        let validator_address = derive_address(&keypair.public_key_bytes(), Network::Testnet);
        assert!(
            validator_address.is_ok(),
            "validator address derivation should succeed"
        );
        let validator_address = validator_address.unwrap_or_else(|_| unreachable!());

        let signature = sign_snapshot_checkpoint(
            &snapshot,
            Network::Testnet,
            validator_address.clone(),
            &keypair,
        );
        assert!(signature.is_ok(), "checkpoint signing should succeed");
        let mut signature = signature.unwrap_or_else(|_| unreachable!());
        if let Some(first_byte) = signature.signature.first_mut() {
            *first_byte ^= 0x55;
        }

        let mut checkpoint = SnapshotCheckpoint::new(&snapshot, Network::Testnet);
        checkpoint.signatures.push(signature);
        let advertisement = SnapshotHandshakeAdvertisement {
            block_height: snapshot.block_height,
            state_root: snapshot.state_root,
            snapshot_hash: payload_hash.unwrap_or_else(|_| unreachable!()),
            checkpoint: Some(checkpoint),
        };
        let mode = SyncHandshakeMode::RequireCheckpoint {
            checkpoint_policy: OwnedCheckpointPolicy {
                network: Network::Testnet,
                min_signatures: 1,
                trusted_validators: vec![validator_address],
            },
        };

        let validated = validate_snapshot_handshake(&snapshot, &advertisement, &mode);
        assert!(
            matches!(
                validated,
                Err(SyncEngineError::CheckpointVerification { source: _ })
            ),
            "tampered checkpoint signature must fail strict handshake verification"
        );
    }

    #[test]
    fn session_manager_enforces_duplicate_and_window_limits() {
        let manager = ChunkSessionManager::new(ChunkSessionPolicy {
            max_in_flight_per_session: 1,
            max_in_flight_per_peer: 2,
            base_retry_backoff_ms: 100,
            max_retry_backoff_ms: 1_000,
        });
        assert!(manager.is_ok(), "session manager should initialize");
        let mut manager = manager.unwrap_or_else(|_| unreachable!());

        assert!(matches!(
            manager.try_schedule_chunk("peer-1", 10, 0, 1_000),
            Ok(SessionSchedule::Scheduled)
        ));
        let duplicate = manager.try_schedule_chunk("peer-1", 10, 0, 1_000);
        assert!(
            matches!(
                duplicate,
                Err(SyncEngineError::DuplicateChunkInFlight {
                    peer_id: _,
                    session_id: 10,
                    chunk_index: 0
                })
            ),
            "duplicate chunk in same session should be rejected"
        );

        let session_limited = manager.try_schedule_chunk("peer-1", 10, 1, 1_000);
        assert!(
            matches!(
                session_limited,
                Err(SyncEngineError::SessionInFlightLimitExceeded {
                    peer_id: _,
                    session_id: 10,
                    limit: 1
                })
            ),
            "session should enforce configured in-flight window"
        );

        assert!(matches!(
            manager.try_schedule_chunk("peer-1", 11, 0, 1_000),
            Ok(SessionSchedule::Scheduled)
        ));
        let peer_limited = manager.try_schedule_chunk("peer-1", 12, 0, 1_000);
        assert!(
            matches!(
                peer_limited,
                Err(SyncEngineError::PeerInFlightLimitExceeded {
                    peer_id: _,
                    limit: 2
                })
            ),
            "peer should enforce aggregated in-flight cap across sessions"
        );
    }

    #[test]
    fn session_manager_applies_deterministic_backoff_and_resets_on_ack() {
        let manager = ChunkSessionManager::new(ChunkSessionPolicy {
            max_in_flight_per_session: 2,
            max_in_flight_per_peer: 4,
            base_retry_backoff_ms: 100,
            max_retry_backoff_ms: 250,
        });
        assert!(manager.is_ok(), "session manager should initialize");
        let mut manager = manager.unwrap_or_else(|_| unreachable!());

        assert!(matches!(
            manager.try_schedule_chunk("peer-b", 7, 3, 1_000),
            Ok(SessionSchedule::Scheduled)
        ));
        let retry_after_one = manager.report_loss("peer-b", 7, 3, 1_000);
        assert!(retry_after_one.is_ok(), "first loss should produce backoff");
        assert_eq!(retry_after_one.unwrap_or_else(|_| unreachable!()), 1_100);
        assert_eq!(manager.peer_in_flight_count("peer-b"), 0);

        let deferred = manager.try_schedule_chunk("peer-b", 7, 3, 1_050);
        assert!(
            matches!(
                deferred,
                Ok(SessionSchedule::Deferred { retry_at_ms: 1_100 })
            ),
            "request should be deferred until retry timestamp"
        );
        assert!(matches!(
            manager.try_schedule_chunk("peer-b", 7, 3, 1_100),
            Ok(SessionSchedule::Scheduled)
        ));

        let retry_after_two = manager.report_loss("peer-b", 7, 3, 1_100);
        assert!(retry_after_two.is_ok(), "second loss should double backoff");
        assert_eq!(retry_after_two.unwrap_or_else(|_| unreachable!()), 1_300);
        assert!(matches!(
            manager.try_schedule_chunk("peer-b", 7, 3, 1_200),
            Ok(SessionSchedule::Deferred { retry_at_ms: 1_300 })
        ));

        assert!(matches!(
            manager.try_schedule_chunk("peer-b", 7, 3, 1_300),
            Ok(SessionSchedule::Scheduled)
        ));
        assert!(manager.acknowledge_chunk("peer-b", 7, 3).is_ok());
        assert!(matches!(
            manager.try_schedule_chunk("peer-b", 7, 3, 1_301),
            Ok(SessionSchedule::Scheduled)
        ));
        let retry_after_reset = manager.report_loss("peer-b", 7, 3, 1_301);
        assert!(
            retry_after_reset.is_ok(),
            "acknowledgement should reset loss streak for next backoff cycle"
        );
        assert_eq!(retry_after_reset.unwrap_or_else(|_| unreachable!()), 1_401);
    }

    #[test]
    fn session_manager_abandon_in_flight_for_restart_clears_transport_counters() {
        let manager = ChunkSessionManager::new(ChunkSessionPolicy {
            max_in_flight_per_session: 2,
            max_in_flight_per_peer: 4,
            base_retry_backoff_ms: 100,
            max_retry_backoff_ms: 400,
        });
        assert!(manager.is_ok(), "session manager should initialize");
        let mut manager = manager.unwrap_or_else(|_| unreachable!());

        assert!(matches!(
            manager.try_schedule_chunk("peer-r", 55, 0, 1_000),
            Ok(SessionSchedule::Scheduled)
        ));
        assert_eq!(manager.peer_in_flight_count("peer-r"), 1);
        assert_eq!(manager.total_in_flight_count(), 1);

        let dropped = manager.abandon_in_flight_for_restart();
        assert_eq!(dropped, 1, "one in-flight chunk should be dropped");
        assert_eq!(
            manager.peer_in_flight_count("peer-r"),
            0,
            "peer in-flight counter should reset after sanitization"
        );
        assert_eq!(
            manager.total_in_flight_count(),
            0,
            "aggregate in-flight counter should reset after sanitization"
        );
    }

    #[test]
    fn serve_chunk_request_validates_request_and_returns_chunk() {
        let chunks = sample_chunks();
        let requested = &chunks[0];
        let request = SnapshotChunkRequest {
            request_id: 19,
            block_height: requested.block_height,
            state_root: requested.state_root,
            snapshot_hash: requested.snapshot_hash,
            chunk_index: requested.chunk_index,
            total_chunks: requested.total_chunks,
        };

        let limiter = ChunkServeLimiter::new(ChunkServePolicy::default());
        assert!(limiter.is_ok());
        let mut limiter = limiter.unwrap_or_else(|_| unreachable!());
        let served = serve_chunk_request(&mut limiter, "peer-ok", 1_000, request, &chunks);
        assert!(served.is_ok(), "valid request should return a chunk");
        let served = served.unwrap_or_else(|_| unreachable!());
        assert_eq!(served.request_id, 19);
        assert_eq!(served.chunk, *requested);
    }

    #[test]
    fn serve_chunk_request_rejects_mismatched_metadata() {
        let chunks = sample_chunks();
        let requested = &chunks[0];
        let request = SnapshotChunkRequest {
            request_id: 21,
            block_height: requested.block_height.saturating_add(1),
            state_root: requested.state_root,
            snapshot_hash: requested.snapshot_hash,
            chunk_index: requested.chunk_index,
            total_chunks: requested.total_chunks,
        };

        let limiter = ChunkServeLimiter::new(ChunkServePolicy::default());
        assert!(limiter.is_ok());
        let mut limiter = limiter.unwrap_or_else(|_| unreachable!());
        let served = serve_chunk_request(&mut limiter, "peer-bad", 1_000, request, &chunks);
        assert!(
            matches!(
                served,
                Err(SyncEngineError::ChunkMetadataMismatch {
                    field: "block_height"
                })
            ),
            "serve path must reject metadata-mismatched requests"
        );
    }

    #[test]
    fn sync_runtime_checkpoint_persist_and_recover_roundtrip() {
        let chunks = sample_chunks();
        let request = SnapshotChunkRequest {
            request_id: 777,
            block_height: chunks[0].block_height,
            state_root: chunks[0].state_root,
            snapshot_hash: chunks[0].snapshot_hash,
            chunk_index: chunks[0].chunk_index,
            total_chunks: chunks[0].total_chunks,
        };

        let scheduler = ChunkRequestScheduler::new(RequestSchedulerPolicy {
            request_timeout_ms: 500,
            max_retries: 4,
            max_in_flight: 8,
        });
        assert!(scheduler.is_ok(), "scheduler should initialize");
        let mut scheduler = scheduler.unwrap_or_else(|_| unreachable!());
        assert!(
            scheduler
                .schedule("peer-a".to_owned(), request, 1_000)
                .is_ok(),
            "request should schedule before persistence"
        );

        let manager = ChunkSessionManager::new(ChunkSessionPolicy {
            max_in_flight_per_session: 4,
            max_in_flight_per_peer: 8,
            base_retry_backoff_ms: 100,
            max_retry_backoff_ms: 1_000,
        });
        assert!(manager.is_ok(), "session manager should initialize");
        let mut manager = manager.unwrap_or_else(|_| unreachable!());
        assert!(matches!(
            manager.try_schedule_chunk("peer-a", 10, 1, 2_000),
            Ok(SessionSchedule::Scheduled)
        ));
        let retry = manager.report_loss("peer-a", 10, 1, 2_000);
        assert!(retry.is_ok(), "loss should record retry cursor");
        assert!(matches!(
            manager.try_schedule_chunk("peer-a", 10, 2, 2_050),
            Ok(SessionSchedule::Scheduled)
        ));

        let expected = SyncSessionCheckpoint::from_runtime(&scheduler, &manager);

        let directory = TestDirectory::new();
        let paths = SyncSessionCheckpointPaths::new(directory.path().to_path_buf());
        let persisted = persist_sync_runtime_checkpoint(&scheduler, &manager, &paths);
        assert!(persisted.is_ok(), "checkpoint persistence should succeed");
        assert!(
            persisted.unwrap_or(0) > 0,
            "checkpoint persistence should write bytes"
        );

        let recovered = recover_sync_runtime_checkpoint(&paths);
        assert!(recovered.is_ok(), "checkpoint recovery should succeed");
        let recovered = recovered.unwrap_or_else(|_| unreachable!());
        assert!(recovered.is_some(), "checkpoint file should be discovered");
        let (recovered_scheduler, recovered_manager) = recovered.unwrap_or_else(|| unreachable!());
        let recovered_checkpoint =
            SyncSessionCheckpoint::from_runtime(&recovered_scheduler, &recovered_manager);
        assert_eq!(
            recovered_checkpoint, expected,
            "recovered runtime should match persisted checkpoint payload"
        );
    }

    #[test]
    fn sync_checkpoint_recover_returns_none_when_file_is_missing() {
        let directory = TestDirectory::new();
        let paths = SyncSessionCheckpointPaths::new(directory.path().to_path_buf());

        let recovered_payload = recover_sync_session_checkpoint(&paths);
        assert!(
            matches!(recovered_payload, Ok(None)),
            "missing checkpoint file should recover as None"
        );

        let recovered_runtime = recover_sync_runtime_checkpoint(&paths);
        assert!(
            matches!(recovered_runtime, Ok(None)),
            "missing checkpoint runtime should recover as None"
        );
    }

    #[test]
    fn sync_checkpoint_rejects_malformed_payload_bytes() {
        let directory = TestDirectory::new();
        let paths = SyncSessionCheckpointPaths::new(directory.path().to_path_buf());
        let written = std::fs::write(&paths.checkpoint_path, [1_u8, 2_u8, 3_u8, 4_u8]);
        assert!(written.is_ok(), "test setup should write malformed bytes");

        let recovered = recover_sync_session_checkpoint(&paths);
        assert!(
            matches!(recovered, Err(SyncEngineError::CheckpointDeserialization)),
            "malformed checkpoint payload should produce typed decode error"
        );
    }

    #[test]
    fn sync_checkpoint_rejects_mismatched_peer_in_flight_counters() {
        let manager = ChunkSessionManager::new(ChunkSessionPolicy {
            max_in_flight_per_session: 2,
            max_in_flight_per_peer: 4,
            base_retry_backoff_ms: 50,
            max_retry_backoff_ms: 500,
        });
        assert!(manager.is_ok(), "session manager should initialize");
        let mut manager = manager.unwrap_or_else(|_| unreachable!());
        assert!(matches!(
            manager.try_schedule_chunk("peer-z", 99, 0, 1_000),
            Ok(SessionSchedule::Scheduled)
        ));

        let scheduler = ChunkRequestScheduler::new(RequestSchedulerPolicy::default());
        assert!(scheduler.is_ok(), "scheduler should initialize");
        let scheduler = scheduler.unwrap_or_else(|_| unreachable!());

        let mut checkpoint = SyncSessionCheckpoint::from_runtime(&scheduler, &manager);
        checkpoint.session_manager.peer_in_flight = vec![("peer-z".to_owned(), 9)];

        let restored = checkpoint.into_runtime();
        assert!(
            matches!(
                restored,
                Err(SyncEngineError::PersistedPeerInFlightMismatch {
                    peer_id: _,
                    expected: 1,
                    actual: 9
                })
            ),
            "tampered peer counters must be rejected during runtime restore"
        );
    }

    #[test]
    fn sync_checkpoint_rejects_mismatched_scheduler_request_ids() {
        let chunks = sample_chunks();
        let request = SnapshotChunkRequest {
            request_id: 41,
            block_height: chunks[0].block_height,
            state_root: chunks[0].state_root,
            snapshot_hash: chunks[0].snapshot_hash,
            chunk_index: chunks[0].chunk_index,
            total_chunks: chunks[0].total_chunks,
        };

        let scheduler = ChunkRequestScheduler::new(RequestSchedulerPolicy::default());
        assert!(scheduler.is_ok(), "scheduler should initialize");
        let mut scheduler = scheduler.unwrap_or_else(|_| unreachable!());
        assert!(
            scheduler
                .schedule("peer-y".to_owned(), request, 100)
                .is_ok(),
            "scheduler should accept request"
        );

        let manager = ChunkSessionManager::new(ChunkSessionPolicy::default());
        assert!(manager.is_ok(), "session manager should initialize");
        let manager = manager.unwrap_or_else(|_| unreachable!());

        let mut checkpoint = SyncSessionCheckpoint::from_runtime(&scheduler, &manager);
        assert!(
            !checkpoint.scheduler.in_flight.is_empty(),
            "scheduler checkpoint should carry one request"
        );
        checkpoint.scheduler.in_flight[0].0 = 42;

        let restored = checkpoint.into_runtime();
        assert!(
            matches!(
                restored,
                Err(SyncEngineError::PersistedRequestIdMismatch {
                    request_id: 42,
                    payload_request_id: 41
                })
            ),
            "tampered request-id key must be rejected during restore"
        );
    }
}
