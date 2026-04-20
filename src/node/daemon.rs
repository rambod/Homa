//! Node daemon skeleton and runtime event-loop wiring.

use std::collections::{BTreeMap, VecDeque};
use std::fs;
use std::path::Path;
use std::str::FromStr;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use futures::StreamExt;
use libp2p::Multiaddr;
use libp2p::gossipsub::Event as GossipsubEvent;
use libp2p::swarm::{Swarm, SwarmEvent};
use thiserror::Error;

use crate::consensus::leader::{LeaderElectionError, elect_leader, record_slot_observation};
use crate::consensus::stake::{StakeError, StakeLedger};
use crate::core::block::{Block, BlockError};
use crate::core::genesis::{
    GENESIS_TIMESTAMP_UNIX_MS, GenesisError, default_genesis_allocations, forge_genesis,
};
use crate::core::indexer::{
    FinalizedIndexer, FinalizedIndexerConfig, FinalizedIndexerDiagnostics, FinalizedIndexerError,
    FinalizedIndexerPaths, IndexedAddressTimelineRecord, IndexedBlockRecord,
    IndexedTransactionRecord,
};
use crate::core::mempool::{Mempool, MempoolConfig, MempoolError, TransactionId, transaction_id};
use crate::core::mempool_checkpoint::{
    MempoolCheckpointError, MempoolCheckpointPaths, persist_mempool_checkpoint,
    recover_mempool_checkpoint,
};
use crate::core::recovery::{
    RecoveryError, RecoveryPaths, commit_state_snapshot_atomic, recover_chain_state,
};
use crate::core::state::ChainState;
use crate::core::state::StateError;
use crate::core::sync::{SnapshotAdmissionPolicy, SnapshotImportMode};
use crate::core::transaction::Transaction;
use crate::crypto::address::{AddressError, Network, derive_address};
use crate::crypto::keys::{CryptoError, Keypair, SECRET_KEY_LENGTH};
use crate::network::checkpoint_rotation::{
    CheckpointRotationPolicy, RotationIngestOutcome, TrustedCheckpointSet,
};
use crate::network::p2p::{
    DEFAULT_BOOTSTRAP_QUIC_PORT, DEFAULT_BOOTSTRAP_TCP_PORT, HomaBehaviour, HomaBehaviourEvent,
    NetworkError, P2PConfig, add_kademlia_address, blocks_topic, bootstrap_dht, build_swarm,
    resolve_bootstrap_addresses,
};
use crate::network::reputation::{AdaptivePenaltyPolicy, ReputationEvent, ReputationPolicy};
use crate::network::runtime_loop::{
    InboundGossipAction, RuntimeLoopError,
    handle_inbound_gossip_message_with_feedback_and_sync_runtime,
};
use crate::network::runtime_policy::{RuntimePolicyError, SyncRuntimePolicyController};
use crate::network::sync_engine::{ChunkServePolicy, ChunkSessionPolicy, RequestSchedulerPolicy};
use crate::network::sync_engine::{
    SyncEngineError, SyncSessionCheckpointPaths, persist_sync_runtime_checkpoint,
    recover_sync_runtime_checkpoint,
};
use crate::network::sync_runtime::{
    SnapshotImportFailurePolicy, SyncRuntimeCoordinator, SyncRuntimeError,
};
use crate::observability::{GossipOperation, Observability};

/// Default in-memory queue bound for decoded pending block payloads.
pub const DEFAULT_MAX_PENDING_BLOCKS: usize = 512;
/// Default runtime event-loop poll interval.
pub const DEFAULT_EVENT_LOOP_TICK_MS: u64 = 250;
/// Default consensus slot duration for proposer scheduling.
pub const DEFAULT_SLOT_DURATION_MS: u64 = 1_000;
/// Default transaction cap for one locally produced block.
pub const DEFAULT_MAX_BLOCK_TRANSACTIONS: usize = 1_024;
/// Default periodic mempool checkpoint interval in milliseconds.
pub const DEFAULT_MEMPOOL_CHECKPOINT_INTERVAL_MS: u64 = 10_000;
/// Default finalized index retention bound (in finalized blocks).
pub const DEFAULT_INDEX_MAX_RETAINED_BLOCKS: usize = 100_000;
/// Scale used to normalize large genesis balances into practical leader-election weights.
const NORMALIZED_GENESIS_STAKE_SCALE: u64 = 10_000;
/// Maximum publish attempts for one locally produced block.
const BLOCK_PUBLISH_MAX_ATTEMPTS: usize = 3;
/// Canonical persisted finalized-block checkpoint filename.
pub const FINALIZED_BLOCK_CHECKPOINT_FILE_NAME: &str = "finalized_block.checkpoint";
/// Maximum allowed inbound block future skew measured in slot intervals.
const MAX_INBOUND_BLOCK_FUTURE_SLOTS: u64 = 2;
/// Maximum accepted inbound block historical skew behind finalized tip.
const MAX_INBOUND_BLOCK_PAST_SLOTS: u64 = 128;
/// Bounded tracked slot-commitments used to detect same-slot equivocation attempts.
const MAX_TRACKED_INBOUND_SLOT_COMMITMENTS: usize = 8_192;

/// Node daemon runtime configuration.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct NodeDaemonConfig {
    /// Network domain for address and signature validation.
    pub network: Network,
    /// Mempool admission and backpressure policy.
    pub mempool_config: MempoolConfig,
    /// Outbound sync request scheduling policy.
    pub request_policy: RequestSchedulerPolicy,
    /// Per-peer/per-session sync window policy.
    pub session_policy: ChunkSessionPolicy,
    /// Inbound sync-request serving quota policy.
    pub serve_policy: ChunkServePolicy,
    /// Peer reputation scoring policy.
    pub reputation_policy: ReputationPolicy,
    /// Adaptive dial/serve penalty policy.
    pub adaptive_penalty_policy: AdaptivePenaltyPolicy,
    /// Trusted-checkpoint rotation policy.
    pub checkpoint_rotation_policy: CheckpointRotationPolicy,
    /// Snapshot chunk assembly and import admission policy.
    pub snapshot_admission_policy: SnapshotAdmissionPolicy,
    /// Maximum accepted chunk payload bytes for runtime assembly.
    pub snapshot_chunk_bytes: usize,
    /// Snapshot import failure/quarantine policy.
    pub snapshot_import_failure_policy: SnapshotImportFailurePolicy,
    /// Bounded in-memory observability event capacity.
    pub observability_event_capacity: usize,
    /// Runtime event-loop tick interval in milliseconds.
    pub event_loop_tick_ms: u64,
    /// Consensus slot duration used for deterministic leader scheduling.
    pub slot_duration_ms: u64,
    /// Maximum transactions selected for one locally produced block.
    pub max_block_transactions: usize,
    /// Maximum decoded pending blocks retained in-memory.
    pub max_pending_blocks: usize,
    /// Interval for periodic mempool checkpoint flushes when persistence is enabled.
    pub mempool_checkpoint_interval_ms: u64,
    /// Maximum retained finalized blocks in durable index segments.
    pub index_max_retained_blocks: usize,
    /// Enables fail-closed startup coherence checks.
    pub strict_recovery: bool,
    /// Forces deterministic finalized-index rebuild from retained events on startup.
    pub repair_index: bool,
    /// Skips mempool checkpoint ingestion during startup recovery.
    pub ignore_mempool_checkpoint: bool,
    /// Optional local producer secret key for block production.
    pub producer_secret_key: Option<[u8; SECRET_KEY_LENGTH]>,
}

impl NodeDaemonConfig {
    /// Returns strict defaults bound to one network domain.
    #[must_use]
    pub fn for_network(network: Network) -> Self {
        Self {
            network,
            mempool_config: MempoolConfig {
                network,
                ..MempoolConfig::default()
            },
            ..Self::default()
        }
    }
}

impl Default for NodeDaemonConfig {
    fn default() -> Self {
        let network = Network::Mainnet;
        Self {
            network,
            mempool_config: MempoolConfig {
                network,
                ..MempoolConfig::default()
            },
            request_policy: RequestSchedulerPolicy::default(),
            session_policy: ChunkSessionPolicy::default(),
            serve_policy: ChunkServePolicy::default(),
            reputation_policy: ReputationPolicy::default(),
            adaptive_penalty_policy: AdaptivePenaltyPolicy::default(),
            checkpoint_rotation_policy: CheckpointRotationPolicy::default(),
            snapshot_admission_policy: SnapshotAdmissionPolicy::default(),
            snapshot_chunk_bytes: crate::core::sync::DEFAULT_SNAPSHOT_CHUNK_BYTES,
            snapshot_import_failure_policy: SnapshotImportFailurePolicy::default(),
            observability_event_capacity: crate::observability::DEFAULT_EVENT_CAPACITY,
            event_loop_tick_ms: DEFAULT_EVENT_LOOP_TICK_MS,
            slot_duration_ms: DEFAULT_SLOT_DURATION_MS,
            max_block_transactions: DEFAULT_MAX_BLOCK_TRANSACTIONS,
            max_pending_blocks: DEFAULT_MAX_PENDING_BLOCKS,
            mempool_checkpoint_interval_ms: DEFAULT_MEMPOOL_CHECKPOINT_INTERVAL_MS,
            index_max_retained_blocks: DEFAULT_INDEX_MAX_RETAINED_BLOCKS,
            strict_recovery: true,
            repair_index: false,
            ignore_mempool_checkpoint: false,
            producer_secret_key: None,
        }
    }
}

/// Explicit node daemon lifecycle phases.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NodeLifecycleState {
    /// Startup bootstrap and recovery checks.
    Bootstrapping,
    /// Snapshot import / catch-up in progress.
    Syncing,
    /// Ready for steady-state intake + block processing.
    Ready,
    /// Intake stopped while draining/persisting runtime state.
    Draining,
    /// Fully stopped; swarm detached.
    Stopped,
}

/// One handled inbound gossip outcome at daemon boundary.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum NodeInboundOutcome {
    /// Transaction passed runtime decode/policy gates and was admitted to mempool.
    TransactionAccepted {
        /// Deterministic transaction identifier.
        tx_id: TransactionId,
    },
    /// Block payload was decoded/validated and queued for downstream consensus processing.
    BlockQueued {
        /// Block height from decoded payload.
        height: u64,
    },
    /// Sync chunk request was accepted by runtime policy.
    SyncChunkRequestAccepted {
        /// Request id.
        request_id: u64,
    },
    /// Sync chunk response was accepted by runtime sync coordinator.
    SyncChunkResponseAccepted {
        /// Response request id.
        request_id: u64,
    },
    /// Checkpoint trust-rotation update ingest outcome.
    CheckpointRotationIngested {
        /// Rotation ingest result.
        outcome: RotationIngestOutcome,
    },
}

/// Aggregated daemon runtime counters.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct NodeRuntimeStats {
    /// Number of inbound gossip messages processed.
    pub inbound_messages_total: u64,
    /// Number of transactions admitted to mempool.
    pub tx_admitted_total: u64,
    /// Number of transactions rejected at mempool boundary.
    pub tx_rejected_total: u64,
    /// Number of decoded blocks queued for downstream processing.
    pub blocks_queued_total: u64,
    /// Number of pending blocks finalized into chain state.
    pub blocks_finalized_total: u64,
    /// Number of pending blocks rejected during finalization checks.
    pub block_rejected_total: u64,
    /// Number of inbound blocks rejected by consensus admission gates.
    pub inbound_block_consensus_rejected_total: u64,
    /// Number of inbound duplicate blocks ignored after slot-commitment match.
    pub inbound_block_duplicate_total: u64,
    /// Number of blocks successfully produced by local validator.
    pub blocks_produced_total: u64,
    /// Number of produced block publish failures.
    pub block_publish_failure_total: u64,
    /// Number of pending-block queue evictions due to capacity bound.
    pub pending_block_evictions_total: u64,
    /// Number of accepted sync chunk requests.
    pub sync_requests_total: u64,
    /// Number of accepted sync chunk responses.
    pub sync_responses_total: u64,
    /// Number of checkpoint-rotation updates ingested.
    pub checkpoint_rotations_total: u64,
    /// Number of successful snapshot imports.
    pub snapshot_imported_total: u64,
    /// Number of quarantined snapshot imports.
    pub snapshot_quarantined_total: u64,
    /// Number of maintenance ticks that saw blocked import outcome.
    pub snapshot_import_blocked_total: u64,
}

/// One maintenance-tick summary.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NodeMaintenanceReport {
    /// Number of timeout-retry entries observed this tick.
    pub retried_requests: usize,
    /// Number of timeout-exhausted entries observed this tick.
    pub exhausted_requests: usize,
    /// Number of pending blocks finalized this tick.
    pub finalized_blocks: usize,
    /// Number of pending blocks rejected this tick.
    pub rejected_blocks: usize,
    /// Number of locally produced blocks this tick.
    pub produced_blocks: usize,
    /// Number of snapshots imported this tick.
    pub imported_snapshots: usize,
    /// Number of snapshots quarantined this tick.
    pub quarantined_snapshots: usize,
    /// Optional blocking import error that stopped batch progression.
    pub blocked_import: Option<SyncRuntimeError>,
}

/// Bounded event-loop execution summary.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct NodeEventLoopReport {
    /// Number of swarm events consumed.
    pub processed_swarm_events: usize,
    /// Number of gossip-message swarm events mapped to inbound handling.
    pub processed_gossip_messages: usize,
    /// Number of maintenance ticks executed due to poll timeout.
    pub maintenance_ticks: usize,
    /// Number of pending blocks finalized during maintenance ticks.
    pub finalized_blocks: usize,
    /// Number of pending blocks rejected during maintenance ticks.
    pub rejected_blocks: usize,
    /// Number of locally produced blocks during maintenance ticks.
    pub produced_blocks: usize,
    /// Number of imported snapshots observed across ticks.
    pub imported_snapshots: usize,
    /// Number of quarantined snapshots observed across ticks.
    pub quarantined_snapshots: usize,
    /// Number of maintenance ticks that had blocked imports.
    pub blocked_import_events: usize,
}

/// Graceful-shutdown persistence report.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct NodePersistenceReport {
    /// Finalized block height used for snapshot persistence.
    pub state_height: u64,
    /// Number of encoded snapshot bytes written.
    pub state_snapshot_bytes: usize,
    /// Number of encoded sync checkpoint bytes written.
    pub sync_checkpoint_bytes: usize,
    /// Number of encoded finalized-block checkpoint bytes written.
    pub finalized_block_checkpoint_bytes: usize,
    /// Number of mempool checkpoint entries persisted.
    pub mempool_checkpoint_entries: usize,
    /// Number of encoded mempool checkpoint bytes written.
    pub mempool_checkpoint_bytes: usize,
    /// Number of retained finalized index blocks after flush.
    pub index_retained_blocks: usize,
    /// Next finalized index event sequence.
    pub index_next_event_sequence: u64,
}

/// Startup recovery report emitted after daemon initialization from persisted state.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct NodeRecoveryReport {
    /// Number of mempool checkpoint entries successfully recovered into mempool.
    pub mempool_recovered: usize,
    /// Number of recovered mempool entries dropped as invalid/stale.
    pub mempool_dropped_invalid: usize,
    /// Number of recovered mempool entries dropped due to duplicate/conflict conditions.
    pub mempool_dropped_conflict: usize,
    /// Whether startup rebuilt finalized indexes from retained finalized events.
    pub index_rebuild_performed: bool,
    /// Number of finalized events replayed into indexes during startup rebuild.
    pub index_events_replayed: usize,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
struct NodePendingBlockProcessingReport {
    finalized_blocks: usize,
    rejected_blocks: usize,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
struct NodeBlockProductionReport {
    produced_blocks: usize,
}

#[derive(Debug, Clone, PartialEq, Eq, Error)]
pub enum InboundBlockAdmissionError {
    #[error("inbound block proposer proof validation failed: {source}")]
    ProposerProof { source: BlockError },
    #[error("inbound block leader election failed: {source}")]
    LeaderElection { source: LeaderElectionError },
    #[error(
        "inbound block height is stale: block_height={block_height}, finalized_height={finalized_height}"
    )]
    StaleHeight {
        block_height: u64,
        finalized_height: u64,
    },
    #[error("inbound block finalized parent hash computation failed: {source}")]
    FinalizedBlockHash { source: BlockError },
    #[error(
        "inbound block parent mismatch at finalized boundary for height {block_height}: expected_parent={expected_parent_hash:?}, observed_parent={observed_parent_hash:?}"
    )]
    ParentMismatch {
        block_height: u64,
        expected_parent_hash: [u8; 32],
        observed_parent_hash: [u8; 32],
    },
    #[error(
        "inbound block timestamp is too far in the future: block={block_timestamp_unix_ms}, now={now_unix_ms}, max_allowed={max_allowed_unix_ms}"
    )]
    FutureTimestamp {
        block_timestamp_unix_ms: u64,
        now_unix_ms: u64,
        max_allowed_unix_ms: u64,
    },
    #[error(
        "inbound block timestamp is stale: block={block_timestamp_unix_ms}, min_allowed={min_allowed_unix_ms}"
    )]
    StaleTimestamp {
        block_timestamp_unix_ms: u64,
        min_allowed_unix_ms: u64,
    },
    #[error(
        "inbound block timestamp regressed below finalized tip: finalized={finalized_timestamp_unix_ms}, block={block_timestamp_unix_ms}"
    )]
    TimestampRegression {
        finalized_timestamp_unix_ms: u64,
        block_timestamp_unix_ms: u64,
    },
    #[error(
        "inbound block proposer does not match elected leader for slot {slot}: expected={expected_leader}, observed={observed_proposer}"
    )]
    UnexpectedProposer {
        slot: u64,
        expected_leader: String,
        observed_proposer: String,
    },
    #[error("inbound block hash computation failed: {source}")]
    BlockHash { source: BlockError },
    #[error(
        "inbound block equivocation detected for slot {slot}: existing={existing_block_hash:?}, observed={observed_block_hash:?}"
    )]
    Equivocation {
        slot: u64,
        existing_block_hash: [u8; 32],
        observed_block_hash: [u8; 32],
    },
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum InboundBlockQueueAction {
    Queue,
    Duplicate,
}

impl NodeEventLoopReport {
    pub(crate) const fn absorb(&mut self, other: Self) {
        self.processed_swarm_events = self
            .processed_swarm_events
            .saturating_add(other.processed_swarm_events);
        self.processed_gossip_messages = self
            .processed_gossip_messages
            .saturating_add(other.processed_gossip_messages);
        self.maintenance_ticks = self
            .maintenance_ticks
            .saturating_add(other.maintenance_ticks);
        self.finalized_blocks = self.finalized_blocks.saturating_add(other.finalized_blocks);
        self.rejected_blocks = self.rejected_blocks.saturating_add(other.rejected_blocks);
        self.produced_blocks = self.produced_blocks.saturating_add(other.produced_blocks);
        self.imported_snapshots = self
            .imported_snapshots
            .saturating_add(other.imported_snapshots);
        self.quarantined_snapshots = self
            .quarantined_snapshots
            .saturating_add(other.quarantined_snapshots);
        self.blocked_import_events = self
            .blocked_import_events
            .saturating_add(other.blocked_import_events);
    }
}

/// Node daemon construction and runtime execution failures.
#[derive(Debug, Error)]
pub enum NodeDaemonError {
    /// Genesis bootstrap failed.
    #[error("node daemon genesis bootstrap failed: {source}")]
    Genesis {
        /// Underlying genesis error.
        source: GenesisError,
    },
    /// Stake-ledger bootstrap failed.
    #[error("node daemon stake-ledger bootstrap failed: {source}")]
    Stake {
        /// Underlying stake error.
        source: StakeError,
    },
    /// Leader election failed for one scheduling slot.
    #[error("node daemon leader election failed: {source}")]
    LeaderElection {
        /// Underlying election error.
        source: LeaderElectionError,
    },
    /// Local producer secret key could not initialize.
    #[error("node daemon local producer key initialization failed: {source}")]
    ProducerKey {
        /// Underlying key initialization error.
        source: CryptoError,
    },
    /// Local producer address derivation failed.
    #[error("node daemon local producer address derivation failed: {source}")]
    ProducerAddress {
        /// Underlying address derivation error.
        source: AddressError,
    },
    /// Configured producer is not present in active stake set.
    #[error("node daemon local producer is not staked: {address}")]
    ProducerNotStaked {
        /// Derived producer address.
        address: String,
    },
    /// Config network mismatches state network.
    #[error(
        "node daemon network mismatch: config={config_network}, state={state_network}, mempool={mempool_network}"
    )]
    NetworkMismatch {
        /// Network from daemon config.
        config_network: u8,
        /// Network from chain state.
        state_network: u8,
        /// Network from mempool config.
        mempool_network: u8,
    },
    /// Finalized block root does not match initial chain state root.
    #[error("finalized block/state root mismatch during daemon initialization")]
    FinalizedStateRootMismatch,
    /// Runtime policy controller construction failed.
    #[error("node daemon runtime policy initialization failed: {source}")]
    RuntimePolicy {
        /// Underlying runtime policy error.
        source: RuntimePolicyError,
    },
    /// Sync runtime coordinator construction failed.
    #[error("node daemon sync runtime initialization failed: {source}")]
    SyncRuntimeConfig {
        /// Underlying sync runtime error.
        source: SyncRuntimeError,
    },
    /// Inbound runtime-loop handling failed.
    #[error("node daemon inbound runtime-loop handling failed: {source}")]
    RuntimeLoop {
        /// Underlying runtime-loop error.
        source: RuntimeLoopError,
    },
    /// Mempool admission failed for one decoded inbound transaction.
    #[error("node daemon mempool admission failed: {source}")]
    MempoolAdmission {
        /// Underlying mempool error.
        source: MempoolError,
    },
    /// Inbound block payload decode/validation failed.
    #[error("node daemon inbound block payload failed decode/validation: {source}")]
    BlockDecode {
        /// Underlying block error.
        source: BlockError,
    },
    /// Inbound block failed consensus-admission hardening checks.
    #[error("node daemon inbound block rejected by consensus admission: {source}")]
    BlockAdmission {
        /// Underlying consensus-admission rejection.
        source: InboundBlockAdmissionError,
    },
    /// Block failed proposer proof validation at finalization boundary.
    #[error("node daemon block proposer proof validation failed: {source}")]
    BlockConsensus {
        /// Underlying block validation error.
        source: BlockError,
    },
    /// Produced block construction failed.
    #[error("node daemon block production failed: {source}")]
    BlockBuild {
        /// Underlying block-construction error.
        source: BlockError,
    },
    /// Produced block state transition failed.
    #[error("node daemon produced block state transition failed: {source}")]
    BlockStateTransition {
        /// Underlying state-transition error.
        source: StateError,
    },
    /// Hashing current finalized block failed during pending-block processing.
    #[error("node daemon finalized block hash computation failed: {source}")]
    FinalizedBlockHash {
        /// Underlying block hash error.
        source: BlockError,
    },
    /// Sync runtime maintenance operation failed.
    #[error("node daemon sync runtime maintenance failed: {source}")]
    SyncRuntime {
        /// Underlying sync runtime error.
        source: SyncRuntimeError,
    },
    /// P2P wiring operation failed.
    #[error("node daemon p2p operation failed: {source}")]
    Network {
        /// Underlying network error.
        source: NetworkError,
    },
    /// State snapshot persistence failed.
    #[error("node daemon state persistence failed: {source}")]
    Recovery {
        /// Underlying state recovery/persistence error.
        source: RecoveryError,
    },
    /// Sync-session checkpoint persistence failed.
    #[error("node daemon sync checkpoint persistence failed: {source}")]
    SyncCheckpoint {
        /// Underlying sync-engine checkpoint error.
        source: SyncEngineError,
    },
    /// Durable mempool checkpoint persistence/recovery failed.
    #[error("node daemon mempool checkpoint persistence/recovery failed: {source}")]
    MempoolCheckpoint {
        /// Underlying mempool checkpoint error.
        source: MempoolCheckpointError,
    },
    /// Durable finalized index persistence/recovery failed.
    #[error("node daemon finalized index operation failed: {source}")]
    Indexer {
        /// Underlying indexer error.
        source: FinalizedIndexerError,
    },
    /// Finalized-block checkpoint encoding failed.
    #[error("node daemon finalized-block checkpoint encoding failed: {source}")]
    FinalizedBlockCheckpointEncode {
        /// Underlying block codec error.
        source: BlockError,
    },
    /// Finalized-block checkpoint write failed.
    #[error("node daemon finalized-block checkpoint write failed: {path}")]
    FinalizedBlockCheckpointWrite {
        /// Checkpoint file path.
        path: String,
        /// Underlying I/O error.
        source: std::io::Error,
    },
    /// Finalized-block checkpoint read failed.
    #[error("node daemon finalized-block checkpoint read failed: {path}")]
    FinalizedBlockCheckpointRead {
        /// Checkpoint file path.
        path: String,
        /// Underlying I/O error.
        source: std::io::Error,
    },
    /// Finalized-block checkpoint is missing.
    #[error("node daemon finalized-block checkpoint is missing: {path}")]
    MissingFinalizedBlockCheckpoint {
        /// Checkpoint file path.
        path: String,
    },
    /// Finalized-block checkpoint decode failed.
    #[error("node daemon finalized-block checkpoint decode failed: {source}")]
    FinalizedBlockCheckpointDecode {
        /// Underlying block decode error.
        source: BlockError,
    },
    /// Recovered state snapshot metadata mismatches recovered finalized-block checkpoint.
    #[error(
        "node daemon recovered state/finalized checkpoint mismatch: recovered_height={recovered_height}, finalized_height={finalized_height}, recovered_state_root={recovered_state_root:?}, finalized_state_root={finalized_state_root:?}"
    )]
    RecoveredFinalizedMismatch {
        /// Height recovered from state snapshot.
        recovered_height: u64,
        /// Height encoded in finalized-block checkpoint.
        finalized_height: u64,
        /// State root recovered from state snapshot.
        recovered_state_root: [u8; 32],
        /// State root encoded in finalized-block checkpoint.
        finalized_state_root: [u8; 32],
    },
    /// Recovered sync checkpoint scheduler policy mismatches daemon config policy.
    #[error(
        "node daemon recovered sync scheduler policy mismatch: expected={expected:?}, recovered={recovered:?}"
    )]
    RecoveredSyncSchedulerPolicyMismatch {
        /// Scheduler policy from daemon config.
        expected: RequestSchedulerPolicy,
        /// Scheduler policy from recovered sync checkpoint.
        recovered: RequestSchedulerPolicy,
    },
    /// Recovered sync checkpoint session policy mismatches daemon config policy.
    #[error(
        "node daemon recovered sync session policy mismatch: expected={expected:?}, recovered={recovered:?}"
    )]
    RecoveredSyncSessionPolicyMismatch {
        /// Session policy from daemon config.
        expected: ChunkSessionPolicy,
        /// Session policy from recovered sync checkpoint.
        recovered: ChunkSessionPolicy,
    },
    /// Swarm-backed event loop was requested without attached swarm.
    #[error("node daemon has no attached swarm")]
    MissingSwarm,
    /// Attached swarm stream closed unexpectedly.
    #[error("node daemon swarm stream closed")]
    SwarmClosed,
    /// Inbound intake attempted while daemon is draining/stopped.
    #[error("node daemon intake is unavailable in lifecycle state: {state:?}")]
    IntakeStopped {
        /// Current lifecycle state.
        state: NodeLifecycleState,
    },
    /// Startup mempool/state coherence mismatch detected.
    #[error(
        "node daemon startup mempool/state coherence mismatch: invalid_entries={invalid_entries}"
    )]
    StartupMempoolStateMismatch {
        /// Number of recovered mempool entries incompatible with recovered chain state.
        invalid_entries: usize,
    },
    /// Startup finalized-index coherence mismatch detected.
    #[error(
        "node daemon startup finalized-index coherence mismatch at height {finalized_height}: indexed_hash={indexed_hash:?}, finalized_hash={finalized_hash:?}"
    )]
    StartupIndexMismatch {
        /// Finalized tip height checked for coherence.
        finalized_height: u64,
        /// Indexed hash observed at finalized height.
        indexed_hash: Option<[u8; 32]>,
        /// Finalized block hash from recovered chain head.
        finalized_hash: [u8; 32],
    },
}

#[derive(Debug)]
struct LocalBlockProducer {
    address: String,
    keypair: Keypair,
    last_observed_slot: Option<u64>,
}

/// Long-running daemon skeleton that wires runtime policy + sync + mempool handling.
pub struct NodeDaemon {
    config: NodeDaemonConfig,
    stake_ledger: StakeLedger,
    local_block_producer: Option<LocalBlockProducer>,
    controller: SyncRuntimePolicyController,
    sync_runtime: SyncRuntimeCoordinator,
    chain_state: ChainState,
    finalized_block: Block,
    mempool: Mempool,
    pending_blocks: VecDeque<Block>,
    inbound_slot_commitments: BTreeMap<u64, [u8; 32]>,
    inbound_slot_commitment_order: VecDeque<u64>,
    observability: Observability,
    stats: NodeRuntimeStats,
    lifecycle_state: NodeLifecycleState,
    recovery_report: NodeRecoveryReport,
    persistence_directory: Option<std::path::PathBuf>,
    indexer: Option<FinalizedIndexer>,
    last_mempool_checkpoint_unix_ms: Option<u64>,
    swarm: Option<Swarm<HomaBehaviour>>,
}

impl std::fmt::Debug for NodeDaemon {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("NodeDaemon")
            .field("config", &self.config)
            .field("stake_ledger", &self.stake_ledger)
            .field(
                "local_block_producer",
                &self
                    .local_block_producer
                    .as_ref()
                    .map(|producer| &producer.address),
            )
            .field("controller", &self.controller)
            .field("sync_runtime", &self.sync_runtime)
            .field("chain_state", &self.chain_state)
            .field("finalized_block", &self.finalized_block)
            .field("mempool", &self.mempool)
            .field("pending_blocks", &self.pending_blocks)
            .field(
                "inbound_slot_commitments",
                &self.inbound_slot_commitments.len(),
            )
            .field("observability", &self.observability)
            .field("stats", &self.stats)
            .field("lifecycle_state", &self.lifecycle_state)
            .field("recovery_report", &self.recovery_report)
            .field("persistence_directory", &self.persistence_directory)
            .field("indexer_attached", &self.indexer.is_some())
            .field("swarm_attached", &self.swarm.is_some())
            .finish_non_exhaustive()
    }
}

impl NodeDaemon {
    /// Creates a daemon from deterministic genesis state and trusted-set bootstrap.
    pub fn from_genesis(network: Network) -> Result<Self, NodeDaemonError> {
        Self::from_genesis_with_config(NodeDaemonConfig::for_network(network))
    }

    /// Creates a daemon from deterministic genesis state using explicit config.
    pub fn from_genesis_with_config(config: NodeDaemonConfig) -> Result<Self, NodeDaemonError> {
        let network = config.network;
        let trusted_set = trusted_checkpoint_set_from_genesis(network)?;
        let stake_ledger = stake_ledger_from_genesis(network)?;
        let (genesis_block, chain_state) =
            forge_genesis(network).map_err(|source| NodeDaemonError::Genesis { source })?;
        let mut daemon = Self::new(
            config,
            genesis_block,
            chain_state,
            trusted_set,
            stake_ledger,
        )?;
        daemon.lifecycle_state = NodeLifecycleState::Bootstrapping;
        daemon.validate_startup_coherence()?;
        daemon.update_runtime_lifecycle_state();
        Ok(daemon)
    }

    /// Creates a daemon from persisted state when available, otherwise bootstraps from genesis.
    pub fn from_persisted_or_genesis(
        config: NodeDaemonConfig,
        directory: &Path,
    ) -> Result<Self, NodeDaemonError> {
        match Self::from_persisted(config, directory) {
            Ok(daemon) => Ok(daemon),
            Err(NodeDaemonError::Recovery {
                source: RecoveryError::NoPersistedState,
            }) => {
                let mut daemon = Self::from_genesis_with_config(config)?;
                daemon.configure_persistence_directory(directory.to_path_buf())?;
                Ok(daemon)
            }
            Err(source) => Err(source),
        }
    }

    /// Creates a daemon from persisted chain-state and finalized-block checkpoints.
    pub fn from_persisted(
        config: NodeDaemonConfig,
        directory: &Path,
    ) -> Result<Self, NodeDaemonError> {
        let recovery_paths = RecoveryPaths::new(directory.to_path_buf());
        let recovered = recover_chain_state(config.network, &recovery_paths)
            .map_err(|source| NodeDaemonError::Recovery { source })?;
        let finalized_block = recover_finalized_block_checkpoint(directory)?;
        if finalized_block.header.height != recovered.block_height
            || finalized_block.header.state_root != recovered.state_root
        {
            return Err(NodeDaemonError::RecoveredFinalizedMismatch {
                recovered_height: recovered.block_height,
                finalized_height: finalized_block.header.height,
                recovered_state_root: recovered.state_root,
                finalized_state_root: finalized_block.header.state_root,
            });
        }

        let trusted_set = trusted_checkpoint_set_from_genesis(config.network)?;
        let stake_ledger = stake_ledger_from_genesis(config.network)?;
        let mut daemon = Self::new(
            config,
            finalized_block,
            recovered.state,
            trusted_set,
            stake_ledger,
        )?;
        daemon.lifecycle_state = NodeLifecycleState::Bootstrapping;
        if let Some(sync_runtime) = recover_sync_runtime_for_daemon(&config, directory)? {
            daemon.sync_runtime = sync_runtime;
        }
        if !config.ignore_mempool_checkpoint {
            daemon.recovery_report =
                recover_mempool_for_daemon(config.network, &mut daemon.mempool, directory)?;
        }
        daemon.configure_persistence_directory(directory.to_path_buf())?;
        Ok(daemon)
    }

    /// Creates a daemon from explicit runtime config and initialized state.
    pub fn new(
        config: NodeDaemonConfig,
        finalized_block: Block,
        chain_state: ChainState,
        trusted_checkpoint_set: TrustedCheckpointSet,
        stake_ledger: StakeLedger,
    ) -> Result<Self, NodeDaemonError> {
        let config_network = config.network.as_byte();
        let state_network = chain_state.network().as_byte();
        let mempool_network = config.mempool_config.network.as_byte();
        if state_network != config_network || mempool_network != config_network {
            return Err(NodeDaemonError::NetworkMismatch {
                config_network,
                state_network,
                mempool_network,
            });
        }
        if finalized_block.header.state_root != chain_state.state_root() {
            return Err(NodeDaemonError::FinalizedStateRootMismatch);
        }

        let controller = SyncRuntimePolicyController::new(
            config.network,
            config.serve_policy,
            config.reputation_policy,
            config.adaptive_penalty_policy,
            config.checkpoint_rotation_policy,
            finalized_block.header.height,
            trusted_checkpoint_set,
        )
        .map_err(|source| NodeDaemonError::RuntimePolicy { source })?;
        let sync_runtime = SyncRuntimeCoordinator::with_assembly_and_import_policy(
            config.request_policy,
            config.session_policy,
            config.snapshot_chunk_bytes,
            config.snapshot_admission_policy,
            config.snapshot_import_failure_policy,
        )
        .map_err(|source| NodeDaemonError::SyncRuntimeConfig { source })?;
        let mempool = Mempool::new(config.mempool_config);
        let observability = Observability::new(config.observability_event_capacity);
        let local_block_producer = local_block_producer_from_config(&config, &stake_ledger)?;

        Ok(Self {
            config,
            stake_ledger,
            local_block_producer,
            controller,
            sync_runtime,
            chain_state,
            finalized_block,
            mempool,
            pending_blocks: VecDeque::new(),
            inbound_slot_commitments: BTreeMap::new(),
            inbound_slot_commitment_order: VecDeque::new(),
            observability,
            stats: NodeRuntimeStats::default(),
            lifecycle_state: NodeLifecycleState::Ready,
            recovery_report: NodeRecoveryReport::default(),
            persistence_directory: None,
            indexer: None,
            last_mempool_checkpoint_unix_ms: None,
            swarm: None,
        })
    }

    /// Attaches an externally built swarm for event-loop execution.
    pub fn attach_swarm(&mut self, swarm: Swarm<HomaBehaviour>) {
        self.swarm = Some(swarm);
    }

    /// Builds and attaches a new swarm from `p2p` config.
    pub fn build_and_attach_swarm(&mut self, p2p_config: P2PConfig) -> Result<(), NodeDaemonError> {
        let swarm =
            build_swarm(p2p_config).map_err(|source| NodeDaemonError::Network { source })?;
        self.attach_swarm(swarm);
        Ok(())
    }

    /// Opens default TCP+QUIC listen sockets on the attached swarm.
    pub fn listen_on_default_addresses(&mut self) -> Result<(), NodeDaemonError> {
        let tcp =
            Multiaddr::from_str("/ip4/0.0.0.0/tcp/0").map_err(|_| NodeDaemonError::Network {
                source: NetworkError::ListenAddress,
            })?;
        let quic = Multiaddr::from_str("/ip4/0.0.0.0/udp/0/quic-v1").map_err(|_| {
            NodeDaemonError::Network {
                source: NetworkError::ListenAddress,
            }
        })?;

        let swarm = self.swarm_mut()?;
        swarm.listen_on(tcp).map_err(|_| NodeDaemonError::Network {
            source: NetworkError::ListenAddress,
        })?;
        swarm
            .listen_on(quic)
            .map_err(|_| NodeDaemonError::Network {
                source: NetworkError::ListenAddress,
            })?;
        Ok(())
    }

    /// Resolves and dials bootstrap peers on the attached swarm.
    pub async fn bootstrap_from_seed(
        &mut self,
        seed_domain: &str,
        fallback_tokens: &[&str],
    ) -> Result<usize, NodeDaemonError> {
        let addresses = resolve_bootstrap_addresses(
            seed_domain,
            fallback_tokens,
            DEFAULT_BOOTSTRAP_TCP_PORT,
            DEFAULT_BOOTSTRAP_QUIC_PORT,
        )
        .await
        .map_err(|source| NodeDaemonError::Network { source })?;

        let swarm = self.swarm_mut()?;
        let mut dial_attempts = 0_usize;
        let mut has_kademlia_seed = false;
        for address in addresses {
            dial_attempts = dial_attempts.saturating_add(1);
            if add_kademlia_address(swarm, address.clone()).is_ok() {
                has_kademlia_seed = true;
            }
            if swarm.dial(address.clone()).is_err() {
                return Err(NodeDaemonError::Network {
                    source: NetworkError::DialAddress(address.to_string()),
                });
            }
        }
        if has_kademlia_seed {
            let _ = bootstrap_dht(swarm);
        }
        Ok(dial_attempts)
    }

    /// Handles one inbound gossip tuple through runtime policy + sync + state gates.
    #[allow(clippy::too_many_lines)]
    pub fn handle_inbound_gossip_message(
        &mut self,
        topic: &str,
        payload: &[u8],
        peer_id: &str,
        now_ms: u64,
    ) -> Result<NodeInboundOutcome, NodeDaemonError> {
        if !matches!(
            self.lifecycle_state,
            NodeLifecycleState::Ready | NodeLifecycleState::Syncing
        ) {
            return Err(NodeDaemonError::IntakeStopped {
                state: self.lifecycle_state,
            });
        }
        let action = handle_inbound_gossip_message_with_feedback_and_sync_runtime(
            &mut self.controller,
            &mut self.sync_runtime,
            topic,
            payload,
            peer_id,
            now_ms,
        )
        .map_err(|source| NodeDaemonError::RuntimeLoop { source })?;

        self.stats.inbound_messages_total = self.stats.inbound_messages_total.saturating_add(1);

        match action {
            InboundGossipAction::Transaction(transaction) => {
                let admitted = self.mempool.insert_from_peer(transaction, peer_id, now_ms);
                let tx_id = admitted.map_err(|source| {
                    self.stats.tx_rejected_total = self.stats.tx_rejected_total.saturating_add(1);
                    self.controller.record_peer_event(
                        peer_id,
                        ReputationEvent::ProtocolViolation,
                        now_ms,
                    );
                    NodeDaemonError::MempoolAdmission { source }
                })?;
                self.stats.tx_admitted_total = self.stats.tx_admitted_total.saturating_add(1);
                self.controller
                    .record_peer_event(peer_id, ReputationEvent::HelpfulRelay, now_ms);
                Ok(NodeInboundOutcome::TransactionAccepted { tx_id })
            }
            InboundGossipAction::BlockPayload(block_payload) => {
                let block = Block::decode(&block_payload).map_err(|source| {
                    self.controller.record_peer_event(
                        peer_id,
                        ReputationEvent::ProtocolViolation,
                        now_ms,
                    );
                    NodeDaemonError::BlockDecode { source }
                })?;
                block.validate_basic().map_err(|source| {
                    self.controller.record_peer_event(
                        peer_id,
                        ReputationEvent::ProtocolViolation,
                        now_ms,
                    );
                    NodeDaemonError::BlockDecode { source }
                })?;
                let queue_action =
                    self.admit_inbound_block_consensus(&block, now_ms)
                        .map_err(|source| {
                            self.stats.inbound_block_consensus_rejected_total = self
                                .stats
                                .inbound_block_consensus_rejected_total
                                .saturating_add(1);
                            self.controller.record_peer_event(
                                peer_id,
                                ReputationEvent::ProtocolViolation,
                                now_ms,
                            );
                            NodeDaemonError::BlockAdmission { source }
                        })?;
                let height = block.header.height;
                if queue_action == InboundBlockQueueAction::Queue {
                    self.enqueue_pending_block(block);
                    self.stats.blocks_queued_total =
                        self.stats.blocks_queued_total.saturating_add(1);
                    self.controller.record_peer_event(
                        peer_id,
                        ReputationEvent::HelpfulRelay,
                        now_ms,
                    );
                } else {
                    self.stats.inbound_block_duplicate_total =
                        self.stats.inbound_block_duplicate_total.saturating_add(1);
                }
                Ok(NodeInboundOutcome::BlockQueued { height })
            }
            InboundGossipAction::SyncChunkRequest(request) => {
                self.stats.sync_requests_total = self.stats.sync_requests_total.saturating_add(1);
                Ok(NodeInboundOutcome::SyncChunkRequestAccepted {
                    request_id: request.request_id,
                })
            }
            InboundGossipAction::SyncChunkResponse(response) => {
                self.stats.sync_responses_total = self.stats.sync_responses_total.saturating_add(1);
                self.controller.record_peer_event(
                    peer_id,
                    ReputationEvent::SuccessfulResponse,
                    now_ms,
                );
                Ok(NodeInboundOutcome::SyncChunkResponseAccepted {
                    request_id: response.request_id,
                })
            }
            InboundGossipAction::CheckpointRotation { outcome } => {
                self.stats.checkpoint_rotations_total =
                    self.stats.checkpoint_rotations_total.saturating_add(1);
                Ok(NodeInboundOutcome::CheckpointRotationIngested { outcome })
            }
        }
    }

    /// Runs one maintenance tick: timeout feedback, reputation updates, and snapshot import batch.
    pub fn run_maintenance_tick(
        &mut self,
        now_ms: u64,
    ) -> Result<NodeMaintenanceReport, NodeDaemonError> {
        self.update_runtime_lifecycle_state();
        let timeout_feedback = self
            .sync_runtime
            .poll_timeout_feedback(now_ms)
            .map_err(|source| NodeDaemonError::SyncRuntime { source })?;
        for retry in &timeout_feedback.retries {
            self.controller
                .record_peer_event(&retry.peer_id, ReputationEvent::Timeout, now_ms);
        }
        for exhausted in &timeout_feedback.exhausted {
            self.controller
                .record_peer_event(&exhausted.peer_id, ReputationEvent::Timeout, now_ms);
        }

        let block_processing = self.process_pending_blocks(self.config.max_pending_blocks)?;
        let production = self.maybe_produce_local_block(now_ms)?;
        self.maybe_persist_mempool_checkpoint(now_ms)?;

        let import_mode = SnapshotImportMode::SteadyState {
            local_finalized_height: self.finalized_block.header.height,
        };
        let batch = self.sync_runtime.import_completed_snapshot_batch(
            &mut self.chain_state,
            &self.finalized_block,
            import_mode,
            Some(&self.observability),
        );

        self.stats.snapshot_imported_total = self
            .stats
            .snapshot_imported_total
            .saturating_add(u64::try_from(batch.imported.len()).unwrap_or(u64::MAX));
        self.stats.snapshot_quarantined_total = self
            .stats
            .snapshot_quarantined_total
            .saturating_add(u64::try_from(batch.quarantined.len()).unwrap_or(u64::MAX));
        if batch.blocked.is_some() {
            self.stats.snapshot_import_blocked_total =
                self.stats.snapshot_import_blocked_total.saturating_add(1);
        }
        let finalized_blocks = block_processing
            .finalized_blocks
            .saturating_add(production.produced_blocks);
        self.update_runtime_lifecycle_state();

        Ok(NodeMaintenanceReport {
            retried_requests: timeout_feedback.retries.len(),
            exhausted_requests: timeout_feedback.exhausted.len(),
            finalized_blocks,
            rejected_blocks: block_processing.rejected_blocks,
            produced_blocks: production.produced_blocks,
            imported_snapshots: batch.imported.len(),
            quarantined_snapshots: batch.quarantined.len(),
            blocked_import: batch.blocked,
        })
    }

    /// Runs one maintenance tick using the current wall-clock timestamp.
    pub fn run_maintenance_tick_now(&mut self) -> Result<NodeMaintenanceReport, NodeDaemonError> {
        self.run_maintenance_tick(now_unix_ms())
    }

    fn maybe_produce_local_block(
        &mut self,
        now_ms: u64,
    ) -> Result<NodeBlockProductionReport, NodeDaemonError> {
        let Some(local_producer) = self.local_block_producer.as_mut() else {
            return Ok(NodeBlockProductionReport::default());
        };

        let slot = slot_from_timestamp(now_ms, self.config.slot_duration_ms);
        if local_producer.last_observed_slot == Some(slot) {
            return Ok(NodeBlockProductionReport::default());
        }
        local_producer.last_observed_slot = Some(slot);
        let producer_address = local_producer.address.clone();

        let selection = elect_leader(&self.stake_ledger, slot)
            .map_err(|source| NodeDaemonError::LeaderElection { source })?;
        if selection.leader != producer_address {
            return Ok(NodeBlockProductionReport::default());
        }

        let Ok(candidate_block) = self.build_local_block_candidate(&producer_address, now_ms)
        else {
            let _ = record_slot_observation(&self.observability, slot, &producer_address, None);
            return Ok(NodeBlockProductionReport::default());
        };

        let Ok(signing_bytes) = candidate_block.header_signing_bytes() else {
            let _ = record_slot_observation(&self.observability, slot, &producer_address, None);
            return Ok(NodeBlockProductionReport::default());
        };

        let (signature, public_key) = self
            .local_block_producer
            .as_ref()
            .map(|producer| {
                (
                    producer.keypair.sign(&signing_bytes),
                    producer.keypair.public_key_bytes(),
                )
            })
            .ok_or_else(|| NodeDaemonError::ProducerNotStaked {
                address: producer_address.clone(),
            })?;
        let produced_block = candidate_block.with_proposer_proof(signature, public_key);
        if self.apply_finalized_block(produced_block.clone()).is_err() {
            let _ = record_slot_observation(&self.observability, slot, &producer_address, None);
            self.stats.block_rejected_total = self.stats.block_rejected_total.saturating_add(1);
            return Ok(NodeBlockProductionReport::default());
        }

        self.stats.blocks_produced_total = self.stats.blocks_produced_total.saturating_add(1);
        let encoded = produced_block
            .encode()
            .map_err(|source| NodeDaemonError::BlockBuild { source })?;
        let _ = self.publish_produced_block_best_effort(&encoded);

        Ok(NodeBlockProductionReport { produced_blocks: 1 })
    }

    fn build_local_block_candidate(
        &self,
        producer: &str,
        now_ms: u64,
    ) -> Result<Block, NodeDaemonError> {
        let next_height = self.finalized_block.header.height.saturating_add(1);
        let previous_block_hash = self
            .finalized_block
            .hash()
            .map_err(|source| NodeDaemonError::BlockBuild { source })?;
        let selected_transactions =
            self.select_production_transactions(producer, next_height, now_ms)?;

        let mut projected_state = self.chain_state.clone();
        if !selected_transactions.is_empty() {
            let provisional_header = crate::core::block::BlockHeader::new(
                next_height,
                previous_block_hash,
                projected_state.state_root(),
                now_ms,
                producer.to_owned(),
            );
            let provisional_block =
                Block::new_unsigned(provisional_header, selected_transactions.clone())
                    .map_err(|source| NodeDaemonError::BlockBuild { source })?;
            projected_state
                .apply_block(&provisional_block)
                .map_err(|source| NodeDaemonError::BlockStateTransition { source })?;
        }

        let header = crate::core::block::BlockHeader::new(
            next_height,
            previous_block_hash,
            projected_state.state_root(),
            now_ms,
            producer.to_owned(),
        );
        Block::new_unsigned(header, selected_transactions)
            .map_err(|source| NodeDaemonError::BlockBuild { source })
    }

    fn select_production_transactions(
        &self,
        proposer: &str,
        block_height: u64,
        timestamp_unix_ms: u64,
    ) -> Result<Vec<Transaction>, NodeDaemonError> {
        let candidates = self
            .mempool
            .prioritized_transactions(self.config.max_block_transactions);
        let mut projected_state = self.chain_state.clone();
        let mut selected = Vec::new();

        for (_, transaction) in candidates {
            let provisional_header = crate::core::block::BlockHeader::new(
                block_height,
                [0_u8; crate::core::block::HASH_LENGTH],
                projected_state.state_root(),
                timestamp_unix_ms,
                proposer.to_owned(),
            );
            let provisional_block =
                Block::new_unsigned(provisional_header, vec![transaction.clone()])
                    .map_err(|source| NodeDaemonError::BlockBuild { source })?;
            if projected_state.apply_block(&provisional_block).is_ok() {
                selected.push(transaction);
            }
        }

        Ok(selected)
    }

    fn admit_inbound_block_consensus(
        &mut self,
        block: &Block,
        now_ms: u64,
    ) -> Result<InboundBlockQueueAction, InboundBlockAdmissionError> {
        block
            .validate_proposer_proof_for_network(self.config.network)
            .map_err(|source| InboundBlockAdmissionError::ProposerProof { source })?;
        self.validate_inbound_block_height(block)?;

        let slot =
            slot_from_timestamp(block.header.timestamp_unix_ms, self.config.slot_duration_ms);
        self.validate_inbound_block_timestamp(block, now_ms)?;

        let leader_selection = elect_leader(&self.stake_ledger, slot)
            .map_err(|source| InboundBlockAdmissionError::LeaderElection { source })?;
        if leader_selection.leader != block.header.proposer {
            let _ = record_slot_observation(
                &self.observability,
                slot,
                &leader_selection.leader,
                Some(&block.header.proposer),
            );
            return Err(InboundBlockAdmissionError::UnexpectedProposer {
                slot,
                expected_leader: leader_selection.leader,
                observed_proposer: block.header.proposer.clone(),
            });
        }

        let block_hash = block
            .hash()
            .map_err(|source| InboundBlockAdmissionError::BlockHash { source })?;
        self.register_inbound_slot_commitment(slot, block_hash)
    }

    fn validate_inbound_block_height(
        &self,
        block: &Block,
    ) -> Result<(), InboundBlockAdmissionError> {
        let finalized_height = self.finalized_block.header.height;
        if block.header.height <= finalized_height {
            return Err(InboundBlockAdmissionError::StaleHeight {
                block_height: block.header.height,
                finalized_height,
            });
        }

        if block.header.height == finalized_height.saturating_add(1) {
            let expected_parent_hash = self
                .finalized_block
                .hash()
                .map_err(|source| InboundBlockAdmissionError::FinalizedBlockHash { source })?;
            if block.header.previous_block_hash != expected_parent_hash {
                return Err(InboundBlockAdmissionError::ParentMismatch {
                    block_height: block.header.height,
                    expected_parent_hash,
                    observed_parent_hash: block.header.previous_block_hash,
                });
            }
        }

        Ok(())
    }

    const fn validate_inbound_block_timestamp(
        &self,
        block: &Block,
        now_ms: u64,
    ) -> Result<(), InboundBlockAdmissionError> {
        let max_future = now_ms.saturating_add(
            self.config
                .slot_duration_ms
                .saturating_mul(MAX_INBOUND_BLOCK_FUTURE_SLOTS),
        );
        if block.header.timestamp_unix_ms > max_future {
            return Err(InboundBlockAdmissionError::FutureTimestamp {
                block_timestamp_unix_ms: block.header.timestamp_unix_ms,
                now_unix_ms: now_ms,
                max_allowed_unix_ms: max_future,
            });
        }

        let min_timestamp = self
            .finalized_block
            .header
            .timestamp_unix_ms
            .saturating_sub(
                self.config
                    .slot_duration_ms
                    .saturating_mul(MAX_INBOUND_BLOCK_PAST_SLOTS),
            );
        if block.header.timestamp_unix_ms < min_timestamp {
            return Err(InboundBlockAdmissionError::StaleTimestamp {
                block_timestamp_unix_ms: block.header.timestamp_unix_ms,
                min_allowed_unix_ms: min_timestamp,
            });
        }

        if block.header.height > self.finalized_block.header.height
            && block.header.timestamp_unix_ms < self.finalized_block.header.timestamp_unix_ms
        {
            return Err(InboundBlockAdmissionError::TimestampRegression {
                finalized_timestamp_unix_ms: self.finalized_block.header.timestamp_unix_ms,
                block_timestamp_unix_ms: block.header.timestamp_unix_ms,
            });
        }

        Ok(())
    }

    fn register_inbound_slot_commitment(
        &mut self,
        slot: u64,
        block_hash: [u8; 32],
    ) -> Result<InboundBlockQueueAction, InboundBlockAdmissionError> {
        if let Some(existing_hash) = self.inbound_slot_commitments.get(&slot).copied() {
            if existing_hash == block_hash {
                return Ok(InboundBlockQueueAction::Duplicate);
            }
            return Err(InboundBlockAdmissionError::Equivocation {
                slot,
                existing_block_hash: existing_hash,
                observed_block_hash: block_hash,
            });
        }

        self.inbound_slot_commitments.insert(slot, block_hash);
        self.inbound_slot_commitment_order.push_back(slot);
        while self.inbound_slot_commitment_order.len() > MAX_TRACKED_INBOUND_SLOT_COMMITMENTS {
            let Some(evicted_slot) = self.inbound_slot_commitment_order.pop_front() else {
                break;
            };
            let _ = self.inbound_slot_commitments.remove(&evicted_slot);
        }
        Ok(InboundBlockQueueAction::Queue)
    }

    fn apply_finalized_block(&mut self, block: Block) -> Result<(), NodeDaemonError> {
        block
            .validate_proposer_proof_for_network(self.config.network)
            .map_err(|source| NodeDaemonError::BlockConsensus { source })?;

        let mut next_state = self.chain_state.clone();
        next_state
            .apply_block(&block)
            .map_err(|source| NodeDaemonError::BlockStateTransition { source })?;
        if next_state.state_root() != block.header.state_root {
            return Err(NodeDaemonError::FinalizedStateRootMismatch);
        }

        if let Some(indexer) = self.indexer.as_ref() {
            let _ = indexer
                .append_finalized_block(&block, now_unix_ms())
                .map_err(|source| NodeDaemonError::Indexer { source })?;
        }

        self.remove_included_transactions_from_mempool(&block);
        self.chain_state = next_state;
        self.finalized_block = block;
        self.stats.blocks_finalized_total = self.stats.blocks_finalized_total.saturating_add(1);
        Ok(())
    }

    fn publish_produced_block_best_effort(&mut self, payload: &[u8]) -> bool {
        let Some(swarm) = self.swarm.as_mut() else {
            return false;
        };
        let topic = blocks_topic();
        for _ in 0..BLOCK_PUBLISH_MAX_ATTEMPTS {
            match swarm
                .behaviour_mut()
                .gossipsub
                .publish(topic.clone(), payload.to_owned())
            {
                Ok(_) => return true,
                Err(libp2p::gossipsub::PublishError::NoPeersSubscribedToTopic) => {}
                Err(source) => {
                    self.stats.block_publish_failure_total =
                        self.stats.block_publish_failure_total.saturating_add(1);
                    self.observability.record_gossip_failure(
                        crate::network::p2p::BLOCKS_TOPIC,
                        GossipOperation::Publish,
                        None,
                        &source.to_string(),
                    );
                    return false;
                }
            }
        }

        self.stats.block_publish_failure_total =
            self.stats.block_publish_failure_total.saturating_add(1);
        self.observability.record_gossip_failure(
            crate::network::p2p::BLOCKS_TOPIC,
            GossipOperation::Publish,
            None,
            "no peers subscribed to block topic",
        );
        false
    }

    /// Handles one raw swarm event and routes gossipsub messages through daemon inbound handling.
    pub fn handle_swarm_event(
        &mut self,
        event: SwarmEvent<HomaBehaviourEvent>,
        now_ms: u64,
    ) -> Result<Option<NodeInboundOutcome>, NodeDaemonError> {
        match event {
            SwarmEvent::Behaviour(HomaBehaviourEvent::Gossipsub(GossipsubEvent::Message {
                propagation_source,
                message,
                ..
            })) => {
                let peer_id = propagation_source.to_string();
                let topic = message.topic.to_string();
                let outcome =
                    self.handle_inbound_gossip_message(&topic, &message.data, &peer_id, now_ms)?;
                Ok(Some(outcome))
            }
            _ => Ok(None),
        }
    }

    /// Runs a bounded swarm-backed event loop for `steps` iterations.
    pub async fn run_event_loop_steps(
        &mut self,
        steps: usize,
    ) -> Result<NodeEventLoopReport, NodeDaemonError> {
        if self.lifecycle_state == NodeLifecycleState::Stopped {
            return Err(NodeDaemonError::IntakeStopped {
                state: self.lifecycle_state,
            });
        }
        self.update_runtime_lifecycle_state();
        let mut report = NodeEventLoopReport::default();
        for _ in 0..steps {
            let poll_interval = Duration::from_millis(self.config.event_loop_tick_ms);
            let event = {
                let swarm = self.swarm_mut()?;
                tokio::time::timeout(poll_interval, swarm.next()).await
            };

            match event {
                Ok(Some(event)) => {
                    report.processed_swarm_events = report.processed_swarm_events.saturating_add(1);
                    if self.handle_swarm_event(event, now_unix_ms())?.is_some() {
                        report.processed_gossip_messages =
                            report.processed_gossip_messages.saturating_add(1);
                    }
                }
                Ok(None) => return Err(NodeDaemonError::SwarmClosed),
                Err(_) => {
                    let maintenance = self.run_maintenance_tick_now()?;
                    report.maintenance_ticks = report.maintenance_ticks.saturating_add(1);
                    report.finalized_blocks = report
                        .finalized_blocks
                        .saturating_add(maintenance.finalized_blocks);
                    report.rejected_blocks = report
                        .rejected_blocks
                        .saturating_add(maintenance.rejected_blocks);
                    report.produced_blocks = report
                        .produced_blocks
                        .saturating_add(maintenance.produced_blocks);
                    report.imported_snapshots = report
                        .imported_snapshots
                        .saturating_add(maintenance.imported_snapshots);
                    report.quarantined_snapshots = report
                        .quarantined_snapshots
                        .saturating_add(maintenance.quarantined_snapshots);
                    if maintenance.blocked_import.is_some() {
                        report.blocked_import_events =
                            report.blocked_import_events.saturating_add(1);
                    }
                }
            }
        }
        Ok(report)
    }

    /// Runs the swarm-backed daemon loop until receiving `Ctrl+C`.
    pub async fn run_until_ctrl_c(&mut self) -> Result<NodeEventLoopReport, NodeDaemonError> {
        let mut shutdown = std::pin::pin!(tokio::signal::ctrl_c());
        let mut report = NodeEventLoopReport::default();

        loop {
            tokio::select! {
                _ = &mut shutdown => break,
                step = self.run_event_loop_steps(1) => {
                    report.absorb(step?);
                }
            }
        }

        Ok(report)
    }

    /// Replaces finalized-block metadata used by snapshot import checks.
    pub fn set_finalized_block(&mut self, finalized_block: Block) {
        self.finalized_block = finalized_block;
    }

    /// Returns immutable daemon runtime stats.
    #[must_use]
    pub const fn stats(&self) -> NodeRuntimeStats {
        self.stats
    }

    /// Returns current daemon lifecycle state.
    #[must_use]
    pub const fn lifecycle_state(&self) -> NodeLifecycleState {
        self.lifecycle_state
    }

    /// Returns immutable chain state reference.
    #[must_use]
    pub const fn chain_state(&self) -> &ChainState {
        &self.chain_state
    }

    /// Returns configured network domain.
    #[must_use]
    pub const fn network(&self) -> Network {
        self.config.network
    }

    /// Returns immutable finalized block metadata.
    #[must_use]
    pub const fn finalized_block(&self) -> &Block {
        &self.finalized_block
    }

    /// Returns immutable observability collector reference.
    #[must_use]
    pub const fn observability(&self) -> &Observability {
        &self.observability
    }

    /// Returns startup recovery report for persisted mempool checkpoint ingestion.
    #[must_use]
    pub const fn recovery_report(&self) -> NodeRecoveryReport {
        self.recovery_report
    }

    /// Configures persistence directory used by periodic mempool checkpoint ticks.
    pub fn configure_persistence_directory(
        &mut self,
        directory: std::path::PathBuf,
    ) -> Result<(), NodeDaemonError> {
        self.indexer = None;
        self.attach_indexer(&directory)?;
        self.persistence_directory = Some(directory);
        self.last_mempool_checkpoint_unix_ms = None;
        self.validate_startup_coherence()?;
        self.update_runtime_lifecycle_state();
        Ok(())
    }

    /// Returns pending mempool transaction count.
    #[must_use]
    pub fn mempool_len(&self) -> usize {
        self.mempool.len()
    }

    /// Returns pending decoded block queue length.
    #[must_use]
    pub fn pending_block_count(&self) -> usize {
        self.pending_blocks.len()
    }

    /// Returns completed snapshot queue length waiting for import.
    #[must_use]
    pub fn completed_snapshot_count(&self) -> usize {
        self.sync_runtime.completed_snapshot_count()
    }

    /// Returns indexed finalized block record by height, when persistence/indexing is enabled.
    pub fn indexed_block_by_height(
        &self,
        height: u64,
    ) -> Result<Option<IndexedBlockRecord>, NodeDaemonError> {
        let Some(indexer) = self.indexer.as_ref() else {
            return Ok(None);
        };
        indexer
            .get_block_by_height(height)
            .map_err(|source| NodeDaemonError::Indexer { source })
    }

    /// Returns indexed finalized block record by hash, when persistence/indexing is enabled.
    pub fn indexed_block_by_hash(
        &self,
        block_hash: &[u8; 32],
    ) -> Result<Option<IndexedBlockRecord>, NodeDaemonError> {
        let Some(indexer) = self.indexer.as_ref() else {
            return Ok(None);
        };
        indexer
            .get_block_by_hash(block_hash)
            .map_err(|source| NodeDaemonError::Indexer { source })
    }

    /// Returns indexed transaction record by hash, when persistence/indexing is enabled.
    pub fn indexed_transaction_by_hash(
        &self,
        tx_hash: &[u8; 32],
    ) -> Result<Option<IndexedTransactionRecord>, NodeDaemonError> {
        let Some(indexer) = self.indexer.as_ref() else {
            return Ok(None);
        };
        indexer
            .get_transaction_by_hash(tx_hash)
            .map_err(|source| NodeDaemonError::Indexer { source })
    }

    /// Returns indexed transaction record by `(sender, nonce)`, when enabled.
    pub fn indexed_transaction_by_sender_nonce(
        &self,
        sender: &str,
        nonce: u64,
    ) -> Result<Option<IndexedTransactionRecord>, NodeDaemonError> {
        let Some(indexer) = self.indexer.as_ref() else {
            return Ok(None);
        };
        indexer
            .get_transaction_by_sender_nonce(sender, nonce)
            .map_err(|source| NodeDaemonError::Indexer { source })
    }

    /// Returns indexed address timeline records, latest-first, when enabled.
    pub fn indexed_address_timeline(
        &self,
        address: &str,
        limit: usize,
    ) -> Result<Vec<IndexedAddressTimelineRecord>, NodeDaemonError> {
        let Some(indexer) = self.indexer.as_ref() else {
            return Ok(Vec::new());
        };
        indexer
            .get_address_timeline(address, limit)
            .map_err(|source| NodeDaemonError::Indexer { source })
    }

    /// Returns finalized block payload by hash when known.
    pub fn block_by_hash(&self, block_hash: &[u8; 32]) -> Result<Option<Block>, NodeDaemonError> {
        let finalized_hash = self
            .finalized_block
            .hash()
            .map_err(|source| NodeDaemonError::FinalizedBlockHash { source })?;
        if &finalized_hash == block_hash {
            return Ok(Some(self.finalized_block.clone()));
        }
        let indexed = self.indexed_block_by_hash(block_hash)?;
        Ok(indexed.map(|record| record.block))
    }

    /// Returns current account `(balance, nonce)` snapshot for one address.
    #[must_use]
    pub fn account_balance_and_nonce(&self, address: &str) -> (u64, u64) {
        let account = self.chain_state.account(address).unwrap_or_default();
        (account.balance, account.nonce)
    }

    /// Returns one mempool transaction by deterministic hash when present.
    #[must_use]
    pub fn mempool_transaction_by_id(&self, tx_id: &TransactionId) -> Option<Transaction> {
        self.mempool.get(tx_id).cloned()
    }

    /// Returns currently connected peer ids.
    #[must_use]
    pub fn connected_peer_ids(&self) -> Vec<String> {
        let Some(swarm) = self.swarm.as_ref() else {
            return Vec::new();
        };
        swarm
            .connected_peers()
            .map(std::string::ToString::to_string)
            .collect()
    }

    /// Persists chain state, sync-session, finalized-block, and mempool checkpoints on shutdown.
    pub fn persist_runtime_state(
        &self,
        directory: &Path,
    ) -> Result<NodePersistenceReport, NodeDaemonError> {
        let recovery_paths = RecoveryPaths::new(directory.to_path_buf());
        let state_commit = commit_state_snapshot_atomic(
            &self.chain_state,
            self.finalized_block.header.height,
            &recovery_paths,
        )
        .map_err(|source| NodeDaemonError::Recovery { source })?;

        let sync_paths = SyncSessionCheckpointPaths::new(directory.to_path_buf());
        let sync_checkpoint_bytes = persist_sync_runtime_checkpoint(
            self.sync_runtime.request_scheduler(),
            self.sync_runtime.session_manager(),
            &sync_paths,
        )
        .map_err(|source| NodeDaemonError::SyncCheckpoint { source })?;
        let finalized_block_checkpoint_bytes =
            persist_finalized_block_checkpoint(&self.finalized_block, directory)?;
        let mempool_paths = MempoolCheckpointPaths::new(directory.to_path_buf());
        let mempool_checkpoint = persist_mempool_checkpoint(&self.mempool, &mempool_paths)
            .map_err(|source| NodeDaemonError::MempoolCheckpoint { source })?;
        let index_diagnostics = if let Some(indexer) = self.indexer.as_ref() {
            indexer
                .diagnostics()
                .map_err(|source| NodeDaemonError::Indexer { source })?
        } else {
            FinalizedIndexerDiagnostics {
                first_retained_sequence: 0,
                next_event_sequence: 0,
                retained_blocks: 0,
            }
        };

        Ok(NodePersistenceReport {
            state_height: state_commit.block_height,
            state_snapshot_bytes: state_commit.bytes_written,
            sync_checkpoint_bytes,
            finalized_block_checkpoint_bytes,
            mempool_checkpoint_entries: mempool_checkpoint.entries_persisted,
            mempool_checkpoint_bytes: mempool_checkpoint.bytes_written,
            index_retained_blocks: index_diagnostics.retained_blocks,
            index_next_event_sequence: index_diagnostics.next_event_sequence,
        })
    }

    /// Transitions daemon into draining shutdown, flushes persistence, and detaches swarm.
    pub fn drain_and_stop(&mut self) -> Result<Option<NodePersistenceReport>, NodeDaemonError> {
        if self.lifecycle_state == NodeLifecycleState::Stopped {
            return Ok(None);
        }

        self.lifecycle_state = NodeLifecycleState::Draining;
        let persistence_report = self
            .persistence_directory
            .as_deref()
            .map(|directory| self.persist_runtime_state(directory))
            .transpose()?;
        self.indexer = None;
        self.swarm = None;
        self.lifecycle_state = NodeLifecycleState::Stopped;
        Ok(persistence_report)
    }

    /// Returns current peer reputation score.
    #[must_use]
    pub fn peer_score(&self, peer_id: &str, now_ms: u64) -> i32 {
        self.controller.peer_score(peer_id, now_ms)
    }

    /// Returns whether a peer is currently banned.
    #[must_use]
    pub fn is_peer_banned(&self, peer_id: &str, now_ms: u64) -> bool {
        self.controller.is_peer_banned(peer_id, now_ms)
    }

    /// Returns mutable access to sync runtime coordinator for external scheduling orchestration.
    pub const fn sync_runtime_mut(&mut self) -> &mut SyncRuntimeCoordinator {
        &mut self.sync_runtime
    }

    /// Pops oldest queued decoded block for downstream consensus execution.
    pub fn pop_pending_block(&mut self) -> Option<Block> {
        self.pending_blocks.pop_front()
    }

    fn process_pending_blocks(
        &mut self,
        max_blocks: usize,
    ) -> Result<NodePendingBlockProcessingReport, NodeDaemonError> {
        let mut report = NodePendingBlockProcessingReport::default();
        let mut finalized_attempts = 0_usize;
        let max_iterations = max_blocks.max(1);

        while finalized_attempts < max_iterations {
            let expected_height = self.finalized_block.header.height.saturating_add(1);

            let stale_rejections = self
                .drop_pending_blocks_by_predicate(|block| block.header.height < expected_height);
            report.rejected_blocks = report.rejected_blocks.saturating_add(stale_rejections);
            if stale_rejections > 0 {
                continue;
            }

            let finalized_hash = self
                .finalized_block
                .hash()
                .map_err(|source| NodeDaemonError::FinalizedBlockHash { source })?;

            if let Some(index) = self.pending_blocks.iter().position(|block| {
                block.header.height == expected_height
                    && block.header.previous_block_hash == finalized_hash
            }) {
                let Some(candidate) = self.pending_blocks.remove(index) else {
                    break;
                };
                finalized_attempts = finalized_attempts.saturating_add(1);
                if self.try_finalize_pending_block(candidate) {
                    report.finalized_blocks = report.finalized_blocks.saturating_add(1);
                } else {
                    report.rejected_blocks = report.rejected_blocks.saturating_add(1);
                }
                continue;
            }

            let parent_mismatch_rejections = self.drop_pending_blocks_by_predicate(|block| {
                block.header.height == expected_height
                    && block.header.previous_block_hash != finalized_hash
            });
            report.rejected_blocks = report
                .rejected_blocks
                .saturating_add(parent_mismatch_rejections);
            if parent_mismatch_rejections > 0 {
                continue;
            }

            break;
        }

        Ok(report)
    }

    fn try_finalize_pending_block(&mut self, block: Block) -> bool {
        if self.apply_finalized_block(block).is_err() {
            self.stats.block_rejected_total = self.stats.block_rejected_total.saturating_add(1);
            return false;
        }
        true
    }

    fn remove_included_transactions_from_mempool(&mut self, block: &Block) {
        for transaction in &block.transactions {
            if let Ok(tx_id) = transaction_id(transaction) {
                let _ = self.mempool.remove(&tx_id);
            }
        }
    }

    fn drop_pending_blocks_by_predicate<F>(&mut self, mut predicate: F) -> usize
    where
        F: FnMut(&Block) -> bool,
    {
        let mut dropped = 0_usize;
        let mut index = 0_usize;
        while index < self.pending_blocks.len() {
            let should_drop = self.pending_blocks.get(index).is_some_and(&mut predicate);
            if should_drop {
                let _ = self.pending_blocks.remove(index);
                dropped = dropped.saturating_add(1);
                self.stats.block_rejected_total = self.stats.block_rejected_total.saturating_add(1);
            } else {
                index = index.saturating_add(1);
            }
        }
        dropped
    }

    fn enqueue_pending_block(&mut self, block: Block) {
        if self.pending_blocks.len() >= self.config.max_pending_blocks {
            let _ = self.pending_blocks.pop_front();
            self.stats.pending_block_evictions_total =
                self.stats.pending_block_evictions_total.saturating_add(1);
        }
        self.pending_blocks.push_back(block);
    }

    fn attach_indexer(&mut self, directory: &Path) -> Result<(), NodeDaemonError> {
        let paths = FinalizedIndexerPaths::new(directory.to_path_buf());
        let (indexer, open_report) = FinalizedIndexer::open(
            &paths,
            self.config.network,
            FinalizedIndexerConfig {
                max_retained_blocks: self.config.index_max_retained_blocks,
            },
        )
        .map_err(|source| NodeDaemonError::Indexer { source })?;
        let mut rebuild_performed = open_report.rebuild_performed;
        let mut events_replayed = open_report.events_replayed;
        if self.config.repair_index {
            let repaired = indexer
                .rebuild_indexes()
                .map_err(|source| NodeDaemonError::Indexer { source })?;
            rebuild_performed = true;
            events_replayed = events_replayed.saturating_add(repaired.events_replayed);
        }
        let _ = indexer
            .ensure_finalized_block_indexed(&self.finalized_block, now_unix_ms())
            .map_err(|source| NodeDaemonError::Indexer { source })?;

        self.recovery_report.index_rebuild_performed = rebuild_performed;
        self.recovery_report.index_events_replayed = events_replayed;
        self.indexer = Some(indexer);
        Ok(())
    }

    fn update_runtime_lifecycle_state(&mut self) {
        if matches!(
            self.lifecycle_state,
            NodeLifecycleState::Draining | NodeLifecycleState::Stopped
        ) {
            return;
        }
        self.lifecycle_state = if self.sync_runtime.completed_snapshot_count() > 0 {
            NodeLifecycleState::Syncing
        } else {
            NodeLifecycleState::Ready
        };
    }

    fn validate_startup_coherence(&mut self) -> Result<(), NodeDaemonError> {
        let scheduler_policy = self.sync_runtime.request_scheduler().policy();
        let session_policy = self.sync_runtime.session_manager().policy();
        if scheduler_policy != self.config.request_policy
            || session_policy != self.config.session_policy
        {
            if self.config.strict_recovery {
                if scheduler_policy != self.config.request_policy {
                    return Err(NodeDaemonError::RecoveredSyncSchedulerPolicyMismatch {
                        expected: self.config.request_policy,
                        recovered: scheduler_policy,
                    });
                }
                return Err(NodeDaemonError::RecoveredSyncSessionPolicyMismatch {
                    expected: self.config.session_policy,
                    recovered: session_policy,
                });
            }

            self.sync_runtime = SyncRuntimeCoordinator::with_assembly_and_import_policy(
                self.config.request_policy,
                self.config.session_policy,
                self.config.snapshot_chunk_bytes,
                self.config.snapshot_admission_policy,
                self.config.snapshot_import_failure_policy,
            )
            .map_err(|source| NodeDaemonError::SyncRuntimeConfig { source })?;
        }

        let mut incoherent_entries = 0_usize;
        let candidates = self.mempool.prioritized_transactions(self.mempool.len());
        let mut invalid_ids = Vec::new();
        for (tx_id, transaction) in candidates {
            if !transaction_is_coherent_with_chain_state(&self.chain_state, &transaction) {
                incoherent_entries = incoherent_entries.saturating_add(1);
                invalid_ids.push(tx_id);
            }
        }
        if incoherent_entries > 0 {
            if self.config.strict_recovery {
                return Err(NodeDaemonError::StartupMempoolStateMismatch {
                    invalid_entries: incoherent_entries,
                });
            }
            for tx_id in invalid_ids {
                let _ = self.mempool.remove(&tx_id);
            }
        }

        if let Some(indexer) = self.indexer.as_ref() {
            let finalized_hash = self
                .finalized_block
                .hash()
                .map_err(|source| NodeDaemonError::FinalizedBlockHash { source })?;
            let indexed = indexer
                .get_block_by_height(self.finalized_block.header.height)
                .map_err(|source| NodeDaemonError::Indexer { source })?;
            let indexed_hash = indexed.as_ref().map(|record| record.block_hash);
            if indexed_hash != Some(finalized_hash) {
                if self.config.strict_recovery {
                    return Err(NodeDaemonError::StartupIndexMismatch {
                        finalized_height: self.finalized_block.header.height,
                        indexed_hash,
                        finalized_hash,
                    });
                }
                let _ = indexer
                    .ensure_finalized_block_indexed(&self.finalized_block, now_unix_ms())
                    .map_err(|source| NodeDaemonError::Indexer { source })?;
            }
        }

        Ok(())
    }

    fn maybe_persist_mempool_checkpoint(&mut self, now_ms: u64) -> Result<(), NodeDaemonError> {
        let Some(directory) = self.persistence_directory.as_deref() else {
            return Ok(());
        };

        let should_persist =
            self.last_mempool_checkpoint_unix_ms
                .is_none_or(|last_checkpoint_ms| {
                    now_ms.saturating_sub(last_checkpoint_ms)
                        >= self.config.mempool_checkpoint_interval_ms
                });
        if !should_persist {
            return Ok(());
        }

        let paths = MempoolCheckpointPaths::new(directory.to_path_buf());
        let _ = persist_mempool_checkpoint(&self.mempool, &paths)
            .map_err(|source| NodeDaemonError::MempoolCheckpoint { source })?;
        self.last_mempool_checkpoint_unix_ms = Some(now_ms);
        Ok(())
    }

    fn swarm_mut(&mut self) -> Result<&mut Swarm<HomaBehaviour>, NodeDaemonError> {
        self.swarm.as_mut().ok_or(NodeDaemonError::MissingSwarm)
    }
}

fn transaction_is_coherent_with_chain_state(state: &ChainState, transaction: &Transaction) -> bool {
    let Ok(required) = transaction.debited_total() else {
        return false;
    };
    let sender_state = state.account(&transaction.sender).unwrap_or_default();
    if transaction.nonce <= sender_state.nonce {
        return false;
    }
    sender_state.balance >= required
}

fn local_block_producer_from_config(
    config: &NodeDaemonConfig,
    stake_ledger: &StakeLedger,
) -> Result<Option<LocalBlockProducer>, NodeDaemonError> {
    let Some(secret_key) = config.producer_secret_key else {
        return Ok(None);
    };
    let keypair = Keypair::from_secret_key(&secret_key)
        .map_err(|source| NodeDaemonError::ProducerKey { source })?;
    let address = derive_address(&keypair.public_key_bytes(), config.network)
        .map_err(|source| NodeDaemonError::ProducerAddress { source })?;
    if stake_ledger.stake_of(&address) == 0 {
        return Err(NodeDaemonError::ProducerNotStaked { address });
    }

    Ok(Some(LocalBlockProducer {
        address,
        keypair,
        last_observed_slot: None,
    }))
}

fn normalized_stake_weight(allocation: u64, total_allocation: u64) -> u64 {
    if total_allocation == 0 {
        return 1;
    }
    let scaled = (u128::from(allocation) * u128::from(NORMALIZED_GENESIS_STAKE_SCALE))
        / u128::from(total_allocation);
    let scaled_u64 = u64::try_from(scaled).unwrap_or(1);
    scaled_u64.max(1)
}

fn slot_from_timestamp(now_ms: u64, slot_duration_ms: u64) -> u64 {
    let elapsed = now_ms.saturating_sub(GENESIS_TIMESTAMP_UNIX_MS);
    elapsed / slot_duration_ms.max(1)
}

/// Builds initial trusted-checkpoint set from deterministic genesis validator addresses.
pub fn trusted_checkpoint_set_from_genesis(
    network: Network,
) -> Result<TrustedCheckpointSet, NodeDaemonError> {
    let allocations = default_genesis_allocations(network)
        .map_err(|source| NodeDaemonError::Genesis { source })?;
    let mut validators = allocations
        .into_iter()
        .map(|(address, _)| address)
        .collect::<Vec<_>>();
    validators.sort();
    let min_signatures = validators.len().saturating_div(2).saturating_add(1);

    Ok(TrustedCheckpointSet {
        network: network.as_byte(),
        epoch: 1,
        min_signatures,
        validators,
    })
}

/// Builds initial stake ledger from deterministic genesis validator allocations.
pub fn stake_ledger_from_genesis(network: Network) -> Result<StakeLedger, NodeDaemonError> {
    let allocations = default_genesis_allocations(network)
        .map_err(|source| NodeDaemonError::Genesis { source })?;
    let total_allocation = allocations.iter().map(|(_, amount)| *amount).sum::<u64>();
    let mut ledger = StakeLedger::new(network);
    for (address, allocation) in allocations {
        let weight = normalized_stake_weight(allocation, total_allocation);
        ledger
            .add_stake(address, weight)
            .map_err(|source| NodeDaemonError::Stake { source })?;
    }
    Ok(ledger)
}

fn now_unix_ms() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |duration| {
            u64::try_from(duration.as_millis()).unwrap_or(u64::MAX)
        })
}

fn finalized_block_checkpoint_path(directory: &Path) -> std::path::PathBuf {
    directory.join(FINALIZED_BLOCK_CHECKPOINT_FILE_NAME)
}

fn persist_finalized_block_checkpoint(
    finalized_block: &Block,
    directory: &Path,
) -> Result<usize, NodeDaemonError> {
    let encoded = finalized_block
        .encode()
        .map_err(|source| NodeDaemonError::FinalizedBlockCheckpointEncode { source })?;
    let checkpoint_path = finalized_block_checkpoint_path(directory);
    let path_display = checkpoint_path.to_string_lossy().into_owned();
    if let Some(parent) = checkpoint_path.parent() {
        fs::create_dir_all(parent).map_err(|source| {
            NodeDaemonError::FinalizedBlockCheckpointWrite {
                path: path_display.clone(),
                source,
            }
        })?;
    }

    let unique_suffix = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0_u128, |duration| duration.as_nanos());
    let temporary_path = checkpoint_path.with_extension(format!(
        "checkpoint.tmp.{}.{unique_suffix}",
        std::process::id()
    ));
    let temporary_display = temporary_path.to_string_lossy().into_owned();
    fs::write(&temporary_path, &encoded).map_err(|source| {
        NodeDaemonError::FinalizedBlockCheckpointWrite {
            path: temporary_display.clone(),
            source,
        }
    })?;
    fs::rename(&temporary_path, &checkpoint_path).map_err(|source| {
        NodeDaemonError::FinalizedBlockCheckpointWrite {
            path: path_display,
            source,
        }
    })?;
    Ok(encoded.len())
}

fn recover_finalized_block_checkpoint(directory: &Path) -> Result<Block, NodeDaemonError> {
    let checkpoint_path = finalized_block_checkpoint_path(directory);
    let path_display = checkpoint_path.to_string_lossy().into_owned();
    let bytes = match fs::read(&checkpoint_path) {
        Ok(bytes) => bytes,
        Err(source) if source.kind() == std::io::ErrorKind::NotFound => {
            return Err(NodeDaemonError::MissingFinalizedBlockCheckpoint { path: path_display });
        }
        Err(source) => {
            return Err(NodeDaemonError::FinalizedBlockCheckpointRead {
                path: path_display,
                source,
            });
        }
    };

    Block::decode(&bytes)
        .map_err(|source| NodeDaemonError::FinalizedBlockCheckpointDecode { source })
}

fn recover_sync_runtime_for_daemon(
    config: &NodeDaemonConfig,
    directory: &Path,
) -> Result<Option<SyncRuntimeCoordinator>, NodeDaemonError> {
    let paths = SyncSessionCheckpointPaths::new(directory.to_path_buf());
    let recovered = recover_sync_runtime_checkpoint(&paths)
        .map_err(|source| NodeDaemonError::SyncCheckpoint { source })?;
    let Some((mut scheduler, mut session_manager)) = recovered else {
        return Ok(None);
    };

    if scheduler.policy() != config.request_policy {
        if config.strict_recovery {
            return Err(NodeDaemonError::RecoveredSyncSchedulerPolicyMismatch {
                expected: config.request_policy,
                recovered: scheduler.policy(),
            });
        }
        return Ok(None);
    }
    if session_manager.policy() != config.session_policy {
        if config.strict_recovery {
            return Err(NodeDaemonError::RecoveredSyncSessionPolicyMismatch {
                expected: config.session_policy,
                recovered: session_manager.policy(),
            });
        }
        return Ok(None);
    }

    let _ = scheduler.abandon_in_flight_for_restart();
    let _ = session_manager.abandon_in_flight_for_restart();

    let sync_runtime = SyncRuntimeCoordinator::with_recovered_transport_state(
        scheduler,
        session_manager,
        config.snapshot_chunk_bytes,
        config.snapshot_admission_policy,
        config.snapshot_import_failure_policy,
    )
    .map_err(|source| NodeDaemonError::SyncRuntimeConfig { source })?;

    Ok(Some(sync_runtime))
}

fn recover_mempool_for_daemon(
    network: Network,
    mempool: &mut Mempool,
    directory: &Path,
) -> Result<NodeRecoveryReport, NodeDaemonError> {
    let paths = MempoolCheckpointPaths::new(directory.to_path_buf());
    let recovered = recover_mempool_checkpoint(&paths, network)
        .map_err(|source| NodeDaemonError::MempoolCheckpoint { source })?;
    let Some(entries) = recovered else {
        return Ok(NodeRecoveryReport::default());
    };

    let now_ms = now_unix_ms();
    let mut report = NodeRecoveryReport::default();
    for entry in entries {
        match mempool.insert_recovered_checkpoint_entry(entry, now_ms) {
            Ok(_) => {
                report.mempool_recovered = report.mempool_recovered.saturating_add(1);
            }
            Err(error) if is_mempool_recovery_conflict(&error) => {
                report.mempool_dropped_conflict = report.mempool_dropped_conflict.saturating_add(1);
            }
            Err(_) => {
                report.mempool_dropped_invalid = report.mempool_dropped_invalid.saturating_add(1);
            }
        }
    }
    Ok(report)
}

const fn is_mempool_recovery_conflict(error: &MempoolError) -> bool {
    matches!(
        error,
        MempoolError::DuplicateSenderNonce {
            sender: _,
            nonce: _
        } | MempoolError::DuplicateTransaction
    )
}

#[cfg(test)]
mod tests {
    use super::{
        DEFAULT_SLOT_DURATION_MS, FINALIZED_BLOCK_CHECKPOINT_FILE_NAME, InboundBlockAdmissionError,
        NodeDaemon, NodeDaemonConfig, NodeDaemonError, NodeInboundOutcome, NodeLifecycleState,
        stake_ledger_from_genesis, trusted_checkpoint_set_from_genesis,
    };
    use crate::consensus::leader::elect_leader;
    use crate::core::block::{Block, BlockHeader};
    use crate::core::genesis::{
        GENESIS_TIMESTAMP_UNIX_MS, default_genesis_allocations, forge_genesis,
    };
    use crate::core::indexer::FINALIZED_INDEX_FILE_NAME;
    use crate::core::mempool::MempoolCheckpointEntry;
    use crate::core::mempool::MempoolConfig;
    use crate::core::mempool_checkpoint::{
        MEMPOOL_CHECKPOINT_FILE_NAME, MempoolCheckpointPaths, persist_mempool_checkpoint_entries,
    };
    use crate::core::recovery::SNAPSHOT_FILE_NAME;
    use crate::core::sync::{build_state_snapshot, split_snapshot_into_chunks};
    use crate::core::transaction::Transaction;
    use crate::crypto::address::{Network, derive_address};
    use crate::crypto::keys::Keypair;
    use crate::network::p2p::{
        BLOCKS_TOPIC, MAX_BLOCK_GOSSIP_BYTES, NetworkError, SYNC_CHUNKS_TOPIC,
        SnapshotChunkRequest, SnapshotChunkResponse, TRANSACTIONS_TOPIC,
        encode_snapshot_chunk_response,
    };
    use crate::network::runtime_loop::RuntimeLoopError;
    use crate::network::sync_engine::{RequestSchedulerPolicy, SYNC_SESSION_CHECKPOINT_FILE_NAME};
    use std::fs;
    use std::path::PathBuf;

    fn daemon_with_low_pow(network: Network) -> NodeDaemon {
        let mut config = NodeDaemonConfig::for_network(network);
        config.mempool_config = MempoolConfig::new(10_000, 0, network);
        config.max_pending_blocks = 16;

        let trusted = trusted_checkpoint_set_from_genesis(network);
        assert!(trusted.is_ok(), "trusted-set bootstrap should succeed");
        let trusted = trusted.unwrap_or_else(|_| unreachable!());
        let stake_ledger = stake_ledger_from_genesis(network);
        assert!(
            stake_ledger.is_ok(),
            "stake ledger bootstrap should succeed"
        );
        let stake_ledger = stake_ledger.unwrap_or_else(|_| unreachable!());
        let forged = forge_genesis(network);
        assert!(forged.is_ok(), "genesis forge should succeed");
        let (genesis_block, chain_state) = forged.unwrap_or_else(|_| unreachable!());

        let daemon = NodeDaemon::new(config, genesis_block, chain_state, trusted, stake_ledger);
        assert!(daemon.is_ok(), "daemon should initialize");
        daemon.unwrap_or_else(|_| unreachable!())
    }

    fn daemon_with_local_producer(network: Network) -> NodeDaemon {
        let mut config = NodeDaemonConfig::for_network(network);
        config.mempool_config = MempoolConfig::new(10_000, 0, network);
        config.max_pending_blocks = 16;
        config.slot_duration_ms = DEFAULT_SLOT_DURATION_MS;
        config.producer_secret_key = Some([1_u8; 32]);
        config.max_block_transactions = 64;

        let trusted = trusted_checkpoint_set_from_genesis(network);
        assert!(trusted.is_ok(), "trusted-set bootstrap should succeed");
        let trusted = trusted.unwrap_or_else(|_| unreachable!());
        let stake_ledger = stake_ledger_from_genesis(network);
        assert!(
            stake_ledger.is_ok(),
            "stake ledger bootstrap should succeed"
        );
        let stake_ledger = stake_ledger.unwrap_or_else(|_| unreachable!());
        let forged = forge_genesis(network);
        assert!(forged.is_ok(), "genesis forge should succeed");
        let (genesis_block, chain_state) = forged.unwrap_or_else(|_| unreachable!());

        let daemon = NodeDaemon::new(config, genesis_block, chain_state, trusted, stake_ledger);
        assert!(daemon.is_ok(), "daemon should initialize");
        daemon.unwrap_or_else(|_| unreachable!())
    }

    fn test_directory(prefix: &str) -> PathBuf {
        let mut directory = std::env::temp_dir();
        let unique = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map_or(0_u128, |duration| duration.as_nanos());
        directory.push(format!("{prefix}-{}-{unique}", std::process::id()));
        let _ = fs::remove_dir_all(&directory);
        directory
    }

    fn producer_address(network: Network) -> String {
        let keypair = Keypair::from_secret_key(&[1_u8; 32]);
        assert!(keypair.is_ok(), "producer key should parse");
        let keypair = keypair.unwrap_or_else(|_| unreachable!());
        let address = derive_address(&keypair.public_key_bytes(), network);
        assert!(address.is_ok(), "producer address should derive");
        address.unwrap_or_else(|_| unreachable!())
    }

    fn slot_for_leader(network: Network, leader: &str, start_slot: u64) -> u64 {
        let ledger = stake_ledger_from_genesis(network);
        assert!(ledger.is_ok(), "stake ledger should build");
        let ledger = ledger.unwrap_or_else(|_| unreachable!());

        for slot in start_slot..start_slot.saturating_add(50_000) {
            let selected = elect_leader(&ledger, slot);
            assert!(selected.is_ok(), "leader election should succeed");
            if selected.unwrap_or_else(|_| unreachable!()).leader == leader {
                return slot;
            }
        }

        unreachable!("leader slot should be found within bounded search window");
    }

    fn leader_for_slot(network: Network, slot: u64) -> String {
        let ledger = stake_ledger_from_genesis(network);
        assert!(ledger.is_ok(), "stake ledger should build");
        let ledger = ledger.unwrap_or_else(|_| unreachable!());
        let selected = elect_leader(&ledger, slot);
        assert!(selected.is_ok(), "leader election should succeed");
        selected.unwrap_or_else(|_| unreachable!()).leader
    }

    fn validator_keypair_for_address(network: Network, validator_address: &str) -> Keypair {
        for seed in [1_u8, 2_u8, 3_u8] {
            let keypair = Keypair::from_secret_key(&[seed; 32]);
            assert!(keypair.is_ok(), "seeded validator key should parse");
            let keypair = keypair.unwrap_or_else(|_| unreachable!());
            let derived = derive_address(&keypair.public_key_bytes(), network);
            assert!(derived.is_ok(), "validator address should derive");
            if derived.unwrap_or_else(|_| unreachable!()) == validator_address {
                return keypair;
            }
        }
        unreachable!("validator address should map to deterministic genesis keypair");
    }

    fn sign_block_for_proposer(network: Network, block: Block) -> Block {
        let keypair = validator_keypair_for_address(network, &block.header.proposer);
        let signing_bytes = block.header_signing_bytes();
        assert!(signing_bytes.is_ok(), "block signing bytes should build");
        block.with_proposer_proof(
            keypair.sign(&signing_bytes.unwrap_or_else(|_| unreachable!())),
            keypair.public_key_bytes(),
        )
    }

    fn timestamp_for_slot(slot: u64, slot_duration_ms: u64) -> u64 {
        GENESIS_TIMESTAMP_UNIX_MS
            .saturating_add(slot.saturating_mul(slot_duration_ms))
            .saturating_add(1)
    }

    fn signed_transaction(network: Network) -> Transaction {
        let sender_keypair = Keypair::generate();
        let receiver_keypair = Keypair::generate();
        let sender_address = derive_address(&sender_keypair.public_key_bytes(), network);
        assert!(sender_address.is_ok(), "sender address should derive");
        let receiver_address = derive_address(&receiver_keypair.public_key_bytes(), network);
        assert!(receiver_address.is_ok(), "receiver address should derive");

        let unsigned = Transaction::new_unsigned(
            sender_address.unwrap_or_else(|_| unreachable!()),
            receiver_address.unwrap_or_else(|_| unreachable!()),
            11,
            1,
            1,
            0,
        )
        .with_sender_public_key(sender_keypair.public_key_bytes());
        let signing_bytes = unsigned.signing_bytes_for_network(network);
        assert!(
            signing_bytes.is_ok(),
            "network-bound signing bytes should build"
        );
        unsigned
            .with_signature(sender_keypair.sign(&signing_bytes.unwrap_or_else(|_| unreachable!())))
    }

    fn genesis_sender(network: Network) -> (Keypair, String) {
        let sender_secret = [1_u8; 32];
        let sender_keypair = Keypair::from_secret_key(&sender_secret);
        assert!(sender_keypair.is_ok(), "genesis sender key should parse");
        let sender_keypair = sender_keypair.unwrap_or_else(|_| unreachable!());
        let sender_address = derive_address(&sender_keypair.public_key_bytes(), network);
        assert!(
            sender_address.is_ok(),
            "genesis sender address should derive"
        );
        (
            sender_keypair,
            sender_address.unwrap_or_else(|_| unreachable!()),
        )
    }

    fn signed_transaction_from_genesis_sender(
        network: Network,
        nonce: u64,
        amount: u64,
        fee: u64,
    ) -> Transaction {
        let (sender_keypair, sender_address) = genesis_sender(network);
        let receiver_keypair = Keypair::generate();
        let receiver_address = derive_address(&receiver_keypair.public_key_bytes(), network);
        assert!(receiver_address.is_ok(), "receiver address should derive");
        let receiver_address = receiver_address.unwrap_or_else(|_| unreachable!());

        let unsigned =
            Transaction::new_unsigned(sender_address, receiver_address, amount, fee, nonce, 0)
                .with_sender_public_key(sender_keypair.public_key_bytes());
        let signing_bytes = unsigned.signing_bytes_for_network(network);
        assert!(signing_bytes.is_ok(), "signing bytes should build");

        unsigned
            .with_signature(sender_keypair.sign(&signing_bytes.unwrap_or_else(|_| unreachable!())))
    }

    fn invalid_checkpoint_transaction(network: Network) -> Transaction {
        let (sender_keypair, sender_address) = genesis_sender(network);
        let receiver_keypair = Keypair::generate();
        let receiver_address = derive_address(&receiver_keypair.public_key_bytes(), network);
        assert!(receiver_address.is_ok(), "receiver address should derive");
        Transaction::new_unsigned(
            sender_address,
            receiver_address.unwrap_or_else(|_| unreachable!()),
            0,
            1,
            99,
            0,
        )
        .with_sender_public_key(sender_keypair.public_key_bytes())
    }

    fn empty_child_block(
        network: Network,
        parent: &Block,
        state_root: [u8; 32],
        timestamp_unix_ms: u64,
        proposer: String,
    ) -> Block {
        let parent_hash = parent.hash();
        assert!(parent_hash.is_ok(), "parent hash should compute");
        let header = BlockHeader::new(
            parent.header.height.saturating_add(1),
            parent_hash.unwrap_or_else(|_| unreachable!()),
            state_root,
            timestamp_unix_ms,
            proposer,
        );
        let block = Block::new_unsigned(header, Vec::new());
        assert!(block.is_ok(), "empty child block should build");
        sign_block_for_proposer(network, block.unwrap_or_else(|_| unreachable!()))
    }

    #[test]
    fn from_genesis_bootstraps_daemon_state() {
        let daemon = NodeDaemon::from_genesis(Network::Testnet);
        assert!(daemon.is_ok(), "daemon should bootstrap from genesis");
        let daemon = daemon.unwrap_or_else(|_| unreachable!());
        assert_eq!(daemon.finalized_block().header.height, 0);
        assert_eq!(daemon.mempool_len(), 0);
        assert_eq!(daemon.pending_block_count(), 0);
    }

    #[test]
    fn inbound_transaction_is_admitted_to_mempool() {
        let network = Network::Testnet;
        let mut daemon = daemon_with_low_pow(network);
        let transaction = signed_transaction(network);
        let encoded = transaction.encode();
        assert!(encoded.is_ok(), "transaction should encode");

        let outcome = daemon.handle_inbound_gossip_message(
            TRANSACTIONS_TOPIC,
            &encoded.unwrap_or_else(|_| unreachable!()),
            "peer-tx",
            10_000,
        );
        assert!(
            outcome.is_ok(),
            "transaction should pass daemon inbound path"
        );
        assert!(matches!(
            outcome.unwrap_or_else(|_| unreachable!()),
            NodeInboundOutcome::TransactionAccepted { .. }
        ));
        assert_eq!(daemon.mempool_len(), 1);
        assert_eq!(daemon.stats().tx_admitted_total, 1);
        assert_eq!(daemon.stats().tx_rejected_total, 0);
    }

    #[test]
    fn malformed_transaction_payload_is_rejected_and_penalized() {
        let network = Network::Testnet;
        let mut daemon = daemon_with_low_pow(network);
        let handled = daemon.handle_inbound_gossip_message(
            TRANSACTIONS_TOPIC,
            b"\xFF\x00\xAA",
            "peer-mal",
            20_000,
        );
        assert!(
            matches!(
                handled,
                Err(NodeDaemonError::RuntimeLoop {
                    source: RuntimeLoopError::Network { source: _ }
                })
            ),
            "malformed payload should fail at runtime-loop network decode boundary"
        );
        assert_eq!(
            daemon.peer_score("peer-mal", 20_001),
            -30,
            "malformed inbound payload must apply deterministic malformed-payload penalty"
        );
    }

    #[test]
    fn unknown_topic_is_rejected_and_penalized() {
        let network = Network::Testnet;
        let mut daemon = daemon_with_low_pow(network);
        let handled =
            daemon.handle_inbound_gossip_message("unknown-topic", b"abc", "peer-unknown", 21_000);
        assert!(
            matches!(
                handled,
                Err(NodeDaemonError::RuntimeLoop {
                    source: RuntimeLoopError::UnknownTopic { topic }
                }) if topic == "unknown-topic"
            ),
            "unknown inbound topic should fail with typed runtime-loop error"
        );
        assert_eq!(
            daemon.peer_score("peer-unknown", 21_001),
            -50,
            "unknown topic should map to protocol-violation penalty"
        );
    }

    #[test]
    fn oversized_block_payload_is_rejected_and_penalized() {
        let network = Network::Testnet;
        let mut daemon = daemon_with_low_pow(network);
        let payload = vec![0_u8; MAX_BLOCK_GOSSIP_BYTES + 1];
        let handled =
            daemon.handle_inbound_gossip_message(BLOCKS_TOPIC, &payload, "peer-block", 22_000);
        assert!(
            matches!(
                handled,
                Err(NodeDaemonError::RuntimeLoop {
                    source: RuntimeLoopError::Network {
                        source: NetworkError::BlockPayloadTooLarge {
                            actual: _,
                            max: MAX_BLOCK_GOSSIP_BYTES
                        }
                    }
                })
            ),
            "oversized block payload should fail before decode/queue"
        );
        assert_eq!(
            daemon.peer_score("peer-block", 22_001),
            -30,
            "oversized inbound payload should apply malformed-payload penalty"
        );
    }

    #[test]
    fn inbound_block_rejects_unexpected_slot_proposer_and_penalizes_peer() {
        let network = Network::Testnet;
        let mut daemon = daemon_with_low_pow(network);
        let slot = 0_u64;
        let timestamp_unix_ms = timestamp_for_slot(slot, DEFAULT_SLOT_DURATION_MS);
        let expected_leader = leader_for_slot(network, slot);
        let allocations = default_genesis_allocations(network);
        assert!(allocations.is_ok(), "genesis allocations should build");
        let unexpected_proposer = allocations
            .unwrap_or_else(|_| unreachable!())
            .into_iter()
            .map(|(address, _)| address)
            .find(|address| address != &expected_leader)
            .unwrap_or_else(|| unreachable!());

        let block = empty_child_block(
            network,
            daemon.finalized_block(),
            daemon.chain_state().state_root(),
            timestamp_unix_ms,
            unexpected_proposer,
        );
        let payload = block.encode();
        assert!(payload.is_ok(), "block should encode");
        let handled = daemon.handle_inbound_gossip_message(
            BLOCKS_TOPIC,
            &payload.unwrap_or_else(|_| unreachable!()),
            "peer-wrong-proposer",
            timestamp_unix_ms,
        );
        assert!(
            matches!(
                handled,
                Err(NodeDaemonError::BlockAdmission {
                    source: InboundBlockAdmissionError::UnexpectedProposer { slot: 0, .. }
                })
            ),
            "unexpected proposer must be rejected at inbound admission boundary"
        );
        assert_eq!(daemon.pending_block_count(), 0);
        assert_eq!(daemon.stats().inbound_block_consensus_rejected_total, 1);
        assert_eq!(
            daemon.peer_score("peer-wrong-proposer", timestamp_unix_ms + 1),
            -50
        );
    }

    #[test]
    fn inbound_block_rejects_excessive_future_timestamp() {
        let network = Network::Testnet;
        let mut daemon = daemon_with_low_pow(network);
        let slot = 10_u64;
        let block_timestamp = timestamp_for_slot(slot, DEFAULT_SLOT_DURATION_MS);
        let proposer = leader_for_slot(network, slot);
        let block = empty_child_block(
            network,
            daemon.finalized_block(),
            daemon.chain_state().state_root(),
            block_timestamp,
            proposer,
        );
        let payload = block.encode();
        assert!(payload.is_ok(), "block should encode");

        let now_ms = GENESIS_TIMESTAMP_UNIX_MS.saturating_add(1);
        let handled = daemon.handle_inbound_gossip_message(
            BLOCKS_TOPIC,
            &payload.unwrap_or_else(|_| unreachable!()),
            "peer-future-block",
            now_ms,
        );
        assert!(
            matches!(
                handled,
                Err(NodeDaemonError::BlockAdmission {
                    source: InboundBlockAdmissionError::FutureTimestamp { .. }
                })
            ),
            "far-future block timestamps must be rejected"
        );
        assert_eq!(daemon.pending_block_count(), 0);
        assert_eq!(daemon.stats().inbound_block_consensus_rejected_total, 1);
        assert_eq!(daemon.peer_score("peer-future-block", now_ms + 1), -50);
    }

    #[test]
    fn inbound_block_rejects_stale_height_replay_and_penalizes_peer() {
        let network = Network::Testnet;
        let mut daemon = daemon_with_low_pow(network);
        let slot = 0_u64;
        let timestamp_unix_ms = timestamp_for_slot(slot, DEFAULT_SLOT_DURATION_MS);
        let proposer = leader_for_slot(network, slot);
        let block = empty_child_block(
            network,
            daemon.finalized_block(),
            daemon.chain_state().state_root(),
            timestamp_unix_ms,
            proposer,
        );
        let payload = block.encode();
        assert!(payload.is_ok(), "block should encode");
        let payload = payload.unwrap_or_else(|_| unreachable!());
        let queued = daemon.handle_inbound_gossip_message(
            BLOCKS_TOPIC,
            &payload,
            "peer-first",
            timestamp_unix_ms,
        );
        assert!(queued.is_ok(), "first block should queue");

        let finalized = daemon.run_maintenance_tick(timestamp_unix_ms.saturating_add(100));
        assert!(
            finalized.is_ok(),
            "maintenance should finalize queued block"
        );
        assert_eq!(daemon.finalized_block().header.height, 1);

        let replay = daemon.handle_inbound_gossip_message(
            BLOCKS_TOPIC,
            &payload,
            "peer-replay",
            timestamp_unix_ms.saturating_add(200),
        );
        assert!(
            matches!(
                replay,
                Err(NodeDaemonError::BlockAdmission {
                    source: InboundBlockAdmissionError::StaleHeight {
                        block_height: 1,
                        finalized_height: 1
                    }
                })
            ),
            "already finalized block replay must be rejected at inbound admission"
        );
        assert_eq!(daemon.pending_block_count(), 0);
        assert_eq!(daemon.stats().inbound_block_consensus_rejected_total, 1);
        assert_eq!(
            daemon.peer_score("peer-replay", timestamp_unix_ms.saturating_add(201)),
            -50
        );
    }

    #[test]
    fn inbound_block_rejects_parent_mismatch_at_finalized_boundary() {
        let network = Network::Testnet;
        let mut daemon = daemon_with_low_pow(network);
        let slot = 0_u64;
        let timestamp_unix_ms = timestamp_for_slot(slot, DEFAULT_SLOT_DURATION_MS);
        let proposer = leader_for_slot(network, slot);
        let mut block = empty_child_block(
            network,
            daemon.finalized_block(),
            daemon.chain_state().state_root(),
            timestamp_unix_ms,
            proposer,
        );
        block.header.previous_block_hash = [9_u8; 32];
        let block = sign_block_for_proposer(network, block);
        let payload = block.encode();
        assert!(payload.is_ok(), "block should encode");

        let handled = daemon.handle_inbound_gossip_message(
            BLOCKS_TOPIC,
            &payload.unwrap_or_else(|_| unreachable!()),
            "peer-parent-mismatch",
            timestamp_unix_ms,
        );
        assert!(
            matches!(
                handled,
                Err(NodeDaemonError::BlockAdmission {
                    source: InboundBlockAdmissionError::ParentMismatch {
                        block_height: 1,
                        expected_parent_hash: _,
                        observed_parent_hash
                    }
                }) if observed_parent_hash == [9_u8; 32]
            ),
            "next-height block with wrong parent must be rejected before queueing"
        );
        assert_eq!(daemon.pending_block_count(), 0);
        assert_eq!(daemon.stats().inbound_block_consensus_rejected_total, 1);
        assert_eq!(
            daemon.peer_score("peer-parent-mismatch", timestamp_unix_ms.saturating_add(1)),
            -50
        );
    }

    #[test]
    fn inbound_block_equivocation_same_slot_is_rejected() {
        let network = Network::Testnet;
        let mut daemon = daemon_with_low_pow(network);
        let slot = 0_u64;
        let proposer = leader_for_slot(network, slot);
        let timestamp_one = timestamp_for_slot(slot, DEFAULT_SLOT_DURATION_MS);
        let timestamp_two = timestamp_one.saturating_add(2);
        let first_block = empty_child_block(
            network,
            daemon.finalized_block(),
            daemon.chain_state().state_root(),
            timestamp_one,
            proposer.clone(),
        );
        let second_block = empty_child_block(
            network,
            daemon.finalized_block(),
            daemon.chain_state().state_root(),
            timestamp_two,
            proposer,
        );
        let first_payload = first_block.encode();
        let second_payload = second_block.encode();
        assert!(first_payload.is_ok(), "first block should encode");
        assert!(second_payload.is_ok(), "second block should encode");

        let first = daemon.handle_inbound_gossip_message(
            BLOCKS_TOPIC,
            &first_payload.unwrap_or_else(|_| unreachable!()),
            "peer-first",
            timestamp_one,
        );
        assert!(first.is_ok(), "first block should be accepted");
        assert_eq!(daemon.pending_block_count(), 1);

        let second = daemon.handle_inbound_gossip_message(
            BLOCKS_TOPIC,
            &second_payload.unwrap_or_else(|_| unreachable!()),
            "peer-equiv",
            timestamp_two,
        );
        assert!(
            matches!(
                second,
                Err(NodeDaemonError::BlockAdmission {
                    source: InboundBlockAdmissionError::Equivocation { slot: 0, .. }
                })
            ),
            "conflicting second block in same slot must be rejected as equivocation"
        );
        assert_eq!(daemon.pending_block_count(), 1);
        assert_eq!(daemon.stats().blocks_queued_total, 1);
        assert_eq!(daemon.stats().inbound_block_consensus_rejected_total, 1);
        assert_eq!(daemon.peer_score("peer-equiv", timestamp_two + 1), -50);
    }

    #[test]
    fn inbound_duplicate_block_is_ignored_without_queue_growth() {
        let network = Network::Testnet;
        let mut daemon = daemon_with_low_pow(network);
        let slot = 0_u64;
        let timestamp_unix_ms = timestamp_for_slot(slot, DEFAULT_SLOT_DURATION_MS);
        let proposer = leader_for_slot(network, slot);
        let block = empty_child_block(
            network,
            daemon.finalized_block(),
            daemon.chain_state().state_root(),
            timestamp_unix_ms,
            proposer,
        );
        let payload = block.encode();
        assert!(payload.is_ok(), "block should encode");
        let payload = payload.unwrap_or_else(|_| unreachable!());

        let first = daemon.handle_inbound_gossip_message(
            BLOCKS_TOPIC,
            &payload,
            "peer-dup-first",
            timestamp_unix_ms,
        );
        assert!(first.is_ok(), "first block should queue");
        assert_eq!(daemon.pending_block_count(), 1);

        let second = daemon.handle_inbound_gossip_message(
            BLOCKS_TOPIC,
            &payload,
            "peer-dup-second",
            timestamp_unix_ms.saturating_add(1),
        );
        assert!(
            second.is_ok(),
            "duplicate payload should be ignored, not rejected"
        );
        assert_eq!(daemon.pending_block_count(), 1);
        assert_eq!(daemon.stats().blocks_queued_total, 1);
        assert_eq!(daemon.stats().inbound_block_duplicate_total, 1);
        assert_eq!(
            daemon.peer_score("peer-dup-second", timestamp_unix_ms + 2),
            0
        );
    }

    #[test]
    fn maintenance_tick_finalizes_valid_pending_block() {
        let network = Network::Testnet;
        let mut daemon = daemon_with_low_pow(network);
        let slot = 0_u64;
        let timestamp_unix_ms = timestamp_for_slot(slot, DEFAULT_SLOT_DURATION_MS);
        let proposer = leader_for_slot(network, slot);

        let block = empty_child_block(
            network,
            daemon.finalized_block(),
            daemon.chain_state().state_root(),
            timestamp_unix_ms,
            proposer,
        );
        let payload = block.encode();
        assert!(payload.is_ok(), "block should encode");
        let handled = daemon.handle_inbound_gossip_message(
            BLOCKS_TOPIC,
            &payload.unwrap_or_else(|_| unreachable!()),
            "peer-block-good",
            timestamp_unix_ms,
        );
        assert!(
            matches!(handled, Ok(NodeInboundOutcome::BlockQueued { height: 1 })),
            "valid block payload should queue"
        );

        let report = daemon.run_maintenance_tick(timestamp_unix_ms.saturating_add(100));
        assert!(report.is_ok(), "maintenance should run");
        let report = report.unwrap_or_else(|_| unreachable!());
        assert_eq!(report.finalized_blocks, 1);
        assert_eq!(report.rejected_blocks, 0);
        assert_eq!(daemon.finalized_block().header.height, 1);
        assert_eq!(daemon.pending_block_count(), 0);
        assert_eq!(daemon.stats().blocks_finalized_total, 1);
        assert_eq!(daemon.stats().block_rejected_total, 0);
    }

    #[test]
    fn maintenance_tick_rejects_block_with_state_root_mismatch() {
        let network = Network::Testnet;
        let mut daemon = daemon_with_low_pow(network);
        let slot = 0_u64;
        let timestamp_unix_ms = timestamp_for_slot(slot, DEFAULT_SLOT_DURATION_MS);
        let proposer = leader_for_slot(network, slot);

        let mut invalid_block = empty_child_block(
            network,
            daemon.finalized_block(),
            daemon.chain_state().state_root(),
            timestamp_unix_ms,
            proposer,
        );
        invalid_block.header.state_root = [7_u8; 32];
        let invalid_block = sign_block_for_proposer(network, invalid_block);
        let payload = invalid_block.encode();
        assert!(payload.is_ok(), "invalid block payload should encode");

        let queued = daemon.handle_inbound_gossip_message(
            BLOCKS_TOPIC,
            &payload.unwrap_or_else(|_| unreachable!()),
            "peer-block-bad-root",
            timestamp_unix_ms,
        );
        assert!(queued.is_ok(), "invalid-root block should still queue");

        let report = daemon.run_maintenance_tick(timestamp_unix_ms.saturating_add(100));
        assert!(report.is_ok(), "maintenance should run");
        let report = report.unwrap_or_else(|_| unreachable!());
        assert_eq!(report.finalized_blocks, 0);
        assert_eq!(report.rejected_blocks, 1);
        assert_eq!(daemon.finalized_block().header.height, 0);
        assert_eq!(daemon.pending_block_count(), 0);
        assert_eq!(daemon.stats().blocks_finalized_total, 0);
        assert_eq!(daemon.stats().block_rejected_total, 1);
    }

    #[test]
    fn maintenance_tick_keeps_future_block_until_parent_arrives() {
        let network = Network::Testnet;
        let mut daemon = daemon_with_low_pow(network);
        let slot_one = 0_u64;
        let slot_two = 1_u64;
        let timestamp_one = timestamp_for_slot(slot_one, DEFAULT_SLOT_DURATION_MS);
        let timestamp_two = timestamp_for_slot(slot_two, DEFAULT_SLOT_DURATION_MS);
        let proposer_one = leader_for_slot(network, slot_one);
        let proposer_two = leader_for_slot(network, slot_two);
        let block_one = empty_child_block(
            network,
            daemon.finalized_block(),
            daemon.chain_state().state_root(),
            timestamp_one,
            proposer_one,
        );
        let block_two = empty_child_block(
            network,
            &block_one,
            daemon.chain_state().state_root(),
            timestamp_two,
            proposer_two,
        );

        let block_two_payload = block_two.encode();
        assert!(block_two_payload.is_ok(), "block two should encode");
        let queued_block_two = daemon.handle_inbound_gossip_message(
            BLOCKS_TOPIC,
            &block_two_payload.unwrap_or_else(|_| unreachable!()),
            "peer-future",
            timestamp_two,
        );
        assert!(queued_block_two.is_ok(), "future block should queue");

        let first_report = daemon.run_maintenance_tick(timestamp_two.saturating_add(100));
        assert!(first_report.is_ok(), "maintenance should run");
        let first_report = first_report.unwrap_or_else(|_| unreachable!());
        assert_eq!(first_report.finalized_blocks, 0);
        assert_eq!(first_report.rejected_blocks, 0);
        assert_eq!(daemon.pending_block_count(), 1);
        assert_eq!(daemon.finalized_block().header.height, 0);

        let block_one_payload = block_one.encode();
        assert!(block_one_payload.is_ok(), "block one should encode");
        let queued_block_one = daemon.handle_inbound_gossip_message(
            BLOCKS_TOPIC,
            &block_one_payload.unwrap_or_else(|_| unreachable!()),
            "peer-parent",
            timestamp_two.saturating_add(200),
        );
        assert!(queued_block_one.is_ok(), "parent block should queue");

        let second_report = daemon.run_maintenance_tick(timestamp_two.saturating_add(300));
        assert!(second_report.is_ok(), "maintenance should run");
        let second_report = second_report.unwrap_or_else(|_| unreachable!());
        assert_eq!(second_report.finalized_blocks, 2);
        assert_eq!(second_report.rejected_blocks, 0);
        assert_eq!(daemon.finalized_block().header.height, 2);
        assert_eq!(daemon.pending_block_count(), 0);
        assert_eq!(daemon.stats().blocks_finalized_total, 2);
    }

    #[test]
    fn finalizing_block_evicts_included_transactions_from_mempool() {
        let network = Network::Testnet;
        let mut daemon = daemon_with_low_pow(network);
        let slot = 0_u64;
        let timestamp_unix_ms = timestamp_for_slot(slot, DEFAULT_SLOT_DURATION_MS);
        let proposer = leader_for_slot(network, slot);

        let transaction = signed_transaction_from_genesis_sender(network, 1, 100, 2);
        let tx_payload = transaction.encode();
        assert!(tx_payload.is_ok(), "transaction should encode");
        let tx_admission = daemon.handle_inbound_gossip_message(
            TRANSACTIONS_TOPIC,
            &tx_payload.unwrap_or_else(|_| unreachable!()),
            "peer-tx-evict",
            27_000,
        );
        assert!(tx_admission.is_ok(), "transaction should be admitted");
        assert_eq!(daemon.mempool_len(), 1);

        let header = BlockHeader::new(
            1,
            daemon
                .finalized_block()
                .hash()
                .unwrap_or_else(|_| unreachable!()),
            [0_u8; 32],
            timestamp_unix_ms,
            proposer,
        );
        let block = Block::new_unsigned(header, vec![transaction]);
        assert!(block.is_ok(), "block should build");
        let mut block = block.unwrap_or_else(|_| unreachable!());
        let mut post_state = daemon.chain_state().clone();
        let applied = post_state.apply_block(&block);
        assert!(applied.is_ok(), "block transition should apply");
        block.header.state_root = post_state.state_root();
        let block = sign_block_for_proposer(network, block);

        let block_payload = block.encode();
        assert!(block_payload.is_ok(), "block should encode");
        let block_queued = daemon.handle_inbound_gossip_message(
            BLOCKS_TOPIC,
            &block_payload.unwrap_or_else(|_| unreachable!()),
            "peer-block-evict",
            timestamp_unix_ms,
        );
        assert!(block_queued.is_ok(), "block should queue");

        let report = daemon.run_maintenance_tick(timestamp_unix_ms.saturating_add(100));
        assert!(report.is_ok(), "maintenance should run");
        let report = report.unwrap_or_else(|_| unreachable!());
        assert_eq!(report.finalized_blocks, 1);
        assert_eq!(daemon.mempool_len(), 0);
        assert_eq!(daemon.finalized_block().header.height, 1);
    }

    #[test]
    fn maintenance_tick_produces_local_block_when_node_is_slot_leader() {
        let network = Network::Testnet;
        let mut daemon = daemon_with_local_producer(network);
        let address = producer_address(network);
        let slot = slot_for_leader(network, &address, 0);
        let now_ms = timestamp_for_slot(slot, DEFAULT_SLOT_DURATION_MS);

        let report = daemon.run_maintenance_tick(now_ms);
        assert!(report.is_ok(), "maintenance tick should run");
        let report = report.unwrap_or_else(|_| unreachable!());
        assert_eq!(report.produced_blocks, 1);
        assert_eq!(report.finalized_blocks, 1);
        assert_eq!(daemon.finalized_block().header.height, 1);
        assert_eq!(daemon.finalized_block().proposer_signature.len(), 64);
        assert_eq!(daemon.finalized_block().proposer_public_key.len(), 32);
        assert_eq!(daemon.stats().blocks_produced_total, 1);
    }

    #[test]
    fn maintenance_tick_skips_duplicate_production_for_same_slot() {
        let network = Network::Testnet;
        let mut daemon = daemon_with_local_producer(network);
        let address = producer_address(network);
        let slot = slot_for_leader(network, &address, 0);
        let now_ms = timestamp_for_slot(slot, DEFAULT_SLOT_DURATION_MS);

        let first = daemon.run_maintenance_tick(now_ms);
        assert!(first.is_ok(), "first tick should run");
        let first = first.unwrap_or_else(|_| unreachable!());
        assert_eq!(first.produced_blocks, 1);

        let second = daemon.run_maintenance_tick(now_ms);
        assert!(second.is_ok(), "second tick should run");
        let second = second.unwrap_or_else(|_| unreachable!());
        assert_eq!(
            second.produced_blocks, 0,
            "same slot should not produce more than one block"
        );
        assert_eq!(daemon.finalized_block().header.height, 1);
        assert_eq!(daemon.stats().blocks_produced_total, 1);
    }

    #[test]
    fn local_production_consumes_mempool_transactions() {
        let network = Network::Testnet;
        let mut daemon = daemon_with_local_producer(network);
        let transaction = signed_transaction_from_genesis_sender(network, 1, 50, 1);
        let encoded = transaction.encode();
        assert!(encoded.is_ok(), "transaction should encode");
        let admitted = daemon.handle_inbound_gossip_message(
            TRANSACTIONS_TOPIC,
            &encoded.unwrap_or_else(|_| unreachable!()),
            "peer-produce",
            28_000,
        );
        assert!(admitted.is_ok(), "transaction should be admitted");
        assert_eq!(daemon.mempool_len(), 1);

        let address = producer_address(network);
        let slot = slot_for_leader(network, &address, 0);
        let now_ms = timestamp_for_slot(slot, DEFAULT_SLOT_DURATION_MS);
        let report = daemon.run_maintenance_tick(now_ms);
        assert!(report.is_ok(), "maintenance should run");
        let report = report.unwrap_or_else(|_| unreachable!());
        assert_eq!(report.produced_blocks, 1);
        assert_eq!(daemon.mempool_len(), 0);
        assert_eq!(daemon.finalized_block().header.height, 1);
    }

    #[test]
    fn maintenance_tick_imports_completed_snapshot_and_updates_observability() {
        let network = Network::Testnet;
        let mut daemon = daemon_with_low_pow(network);

        let snapshot =
            build_state_snapshot(daemon.chain_state(), daemon.finalized_block().header.height);
        let chunks = split_snapshot_into_chunks(&snapshot, 32);
        assert!(chunks.is_ok(), "snapshot should split into chunks");
        let chunks = chunks.unwrap_or_else(|_| unreachable!());

        for (index, chunk) in chunks.iter().enumerate() {
            let request = SnapshotChunkRequest {
                request_id: u64::try_from(index).unwrap_or(u64::MAX) + 1_000,
                block_height: chunk.block_height,
                state_root: chunk.state_root,
                snapshot_hash: chunk.snapshot_hash,
                chunk_index: chunk.chunk_index,
                total_chunks: chunk.total_chunks,
            };
            let scheduled = daemon.sync_runtime_mut().schedule_outbound_request(
                "peer-sync",
                7,
                request,
                15_000,
            );
            assert!(scheduled.is_ok(), "outbound request should schedule");

            let encoded = encode_snapshot_chunk_response(SnapshotChunkResponse {
                request_id: request.request_id,
                chunk: chunk.clone(),
            });
            assert!(encoded.is_ok(), "chunk response should encode");
            let handled = daemon.handle_inbound_gossip_message(
                SYNC_CHUNKS_TOPIC,
                &encoded.unwrap_or_else(|_| unreachable!()),
                "peer-sync",
                15_010 + u64::try_from(index).unwrap_or(u64::MAX),
            );
            assert!(
                matches!(
                    handled,
                    Ok(NodeInboundOutcome::SyncChunkResponseAccepted { .. })
                ),
                "sync response should pass inbound runtime path"
            );
        }

        assert_eq!(daemon.completed_snapshot_count(), 1);
        let report = daemon.run_maintenance_tick(16_000);
        assert!(report.is_ok(), "maintenance tick should run");
        let report = report.unwrap_or_else(|_| unreachable!());

        assert_eq!(report.finalized_blocks, 0);
        assert_eq!(report.rejected_blocks, 0);
        assert_eq!(report.produced_blocks, 0);
        assert_eq!(report.imported_snapshots, 1);
        assert_eq!(report.quarantined_snapshots, 0);
        assert!(report.blocked_import.is_none());
        assert_eq!(daemon.completed_snapshot_count(), 0);
        assert_eq!(daemon.observability().snapshot_import_success_total(), 1);
    }

    #[tokio::test(flavor = "current_thread")]
    async fn event_loop_requires_attached_swarm() {
        let mut daemon = daemon_with_low_pow(Network::Testnet);
        let result = daemon.run_event_loop_steps(1).await;
        assert!(
            matches!(result, Err(NodeDaemonError::MissingSwarm)),
            "event loop should reject execution without attached swarm"
        );
    }

    #[test]
    fn persist_runtime_state_flushes_state_sync_and_mempool_checkpoints() {
        let daemon = daemon_with_low_pow(Network::Testnet);
        let directory = test_directory("homa-daemon-persist");

        let persisted = daemon.persist_runtime_state(&directory);
        assert!(
            persisted.is_ok(),
            "runtime state persistence should succeed"
        );
        let persisted = persisted.unwrap_or_else(|_| unreachable!());
        assert!(
            persisted.state_snapshot_bytes > 0,
            "state snapshot persistence should report encoded bytes"
        );
        assert!(
            persisted.sync_checkpoint_bytes > 0,
            "sync checkpoint persistence should report encoded bytes"
        );
        assert!(
            persisted.finalized_block_checkpoint_bytes > 0,
            "finalized-block checkpoint persistence should report encoded bytes"
        );
        assert_eq!(
            persisted.mempool_checkpoint_entries, 0,
            "empty mempool should persist with zero checkpoint entries"
        );

        let snapshot_path = directory.join(SNAPSHOT_FILE_NAME);
        let sync_path = directory.join(SYNC_SESSION_CHECKPOINT_FILE_NAME);
        let finalized_path = directory.join(FINALIZED_BLOCK_CHECKPOINT_FILE_NAME);
        let mempool_path = directory.join(MEMPOOL_CHECKPOINT_FILE_NAME);
        assert!(
            snapshot_path.exists(),
            "state snapshot file should be written"
        );
        assert!(sync_path.exists(), "sync checkpoint file should be written");
        assert!(
            finalized_path.exists(),
            "finalized-block checkpoint file should be written"
        );
        assert!(
            mempool_path.exists(),
            "mempool checkpoint file should be written"
        );

        let cleanup = fs::remove_dir_all(&directory);
        assert!(
            cleanup.is_ok(),
            "test persistence directory should clean up"
        );
    }

    #[test]
    fn maintenance_tick_indexes_finalized_transactions_when_persistence_is_configured() {
        let network = Network::Testnet;
        let mut daemon = daemon_with_local_producer(network);
        let directory = test_directory("homa-daemon-indexer");
        let configured = daemon.configure_persistence_directory(directory.clone());
        assert!(configured.is_ok(), "persistence directory should configure");

        let transaction = signed_transaction_from_genesis_sender(network, 1, 100, 2);
        let tx_hash = crate::core::mempool::transaction_id(&transaction);
        assert!(tx_hash.is_ok(), "transaction id should compute");
        let tx_hash = tx_hash.unwrap_or_else(|_| unreachable!());
        let encoded = transaction.encode();
        assert!(encoded.is_ok(), "transaction should encode");
        let admitted = daemon.handle_inbound_gossip_message(
            TRANSACTIONS_TOPIC,
            &encoded.unwrap_or_else(|_| unreachable!()),
            "peer-indexed",
            50_000,
        );
        assert!(admitted.is_ok(), "transaction should admit");

        let local_producer = producer_address(network);
        let slot = slot_for_leader(network, &local_producer, 0);
        let now_ms = timestamp_for_slot(slot, DEFAULT_SLOT_DURATION_MS);
        let maintenance = daemon.run_maintenance_tick(now_ms);
        assert!(maintenance.is_ok(), "maintenance tick should succeed");
        let maintenance = maintenance.unwrap_or_else(|_| unreachable!());
        assert_eq!(maintenance.finalized_blocks, 1);

        let indexed_block = daemon.indexed_block_by_height(1);
        assert!(indexed_block.is_ok(), "indexed block lookup should succeed");
        let indexed_block = indexed_block.unwrap_or_else(|_| unreachable!());
        assert!(indexed_block.is_some(), "finalized block should be indexed");
        assert_eq!(
            indexed_block.unwrap_or_else(|| unreachable!()).height,
            1,
            "height-one block should be indexed"
        );

        let indexed_tx = daemon.indexed_transaction_by_hash(&tx_hash);
        assert!(indexed_tx.is_ok(), "indexed tx lookup should succeed");
        let indexed_tx = indexed_tx.unwrap_or_else(|_| unreachable!());
        assert!(
            indexed_tx.is_some(),
            "finalized transaction should be indexed"
        );
        let indexed_tx = indexed_tx.unwrap_or_else(|| unreachable!());
        assert_eq!(indexed_tx.nonce, 1);
        assert_eq!(indexed_tx.fee, 2);

        let by_sender_nonce = daemon.indexed_transaction_by_sender_nonce(&transaction.sender, 1);
        assert!(
            by_sender_nonce.is_ok(),
            "sender+nonce lookup should succeed"
        );
        let by_sender_nonce = by_sender_nonce.unwrap_or_else(|_| unreachable!());
        assert!(
            by_sender_nonce.is_some(),
            "sender+nonce index should map to finalized tx"
        );

        let sender_timeline = daemon.indexed_address_timeline(&transaction.sender, 16);
        assert!(sender_timeline.is_ok(), "sender timeline should query");
        assert!(
            !sender_timeline
                .unwrap_or_else(|_| unreachable!())
                .is_empty(),
            "sender timeline should include finalized tx"
        );

        let index_path = directory.join(FINALIZED_INDEX_FILE_NAME);
        assert!(
            index_path.exists(),
            "finalized index file should be written"
        );

        let cleanup = fs::remove_dir_all(&directory);
        assert!(cleanup.is_ok(), "test directory should clean up");
    }

    #[test]
    fn from_persisted_or_genesis_restores_finalized_state_after_restart() {
        let network = Network::Testnet;
        let mut daemon = daemon_with_low_pow(network);
        let slot = 0_u64;
        let timestamp_unix_ms = timestamp_for_slot(slot, DEFAULT_SLOT_DURATION_MS);
        let proposer = leader_for_slot(network, slot);
        let block = empty_child_block(
            network,
            daemon.finalized_block(),
            daemon.chain_state().state_root(),
            timestamp_unix_ms,
            proposer,
        );
        let payload = block.encode();
        assert!(payload.is_ok(), "block should encode");
        let queued = daemon.handle_inbound_gossip_message(
            BLOCKS_TOPIC,
            &payload.unwrap_or_else(|_| unreachable!()),
            "peer-restart",
            timestamp_unix_ms,
        );
        assert!(
            matches!(queued, Ok(NodeInboundOutcome::BlockQueued { height: 1 })),
            "inbound block should queue before restart persistence"
        );
        let finalized = daemon.run_maintenance_tick(timestamp_unix_ms.saturating_add(100));
        assert!(
            finalized.is_ok(),
            "maintenance should finalize queued block"
        );
        assert_eq!(daemon.finalized_block().header.height, 1);

        let expected_hash = daemon.finalized_block().hash();
        assert!(expected_hash.is_ok(), "finalized block hash should compute");
        let expected_hash = expected_hash.unwrap_or_else(|_| unreachable!());
        let expected_height = daemon.finalized_block().header.height;
        let expected_state_root = daemon.chain_state().state_root();
        let directory = test_directory("homa-daemon-restart");
        let persisted = daemon.persist_runtime_state(&directory);
        assert!(persisted.is_ok(), "persist should succeed");

        let mut config = NodeDaemonConfig::for_network(network);
        config.mempool_config = MempoolConfig::new(10_000, 0, network);
        config.max_pending_blocks = 16;
        let recovered = NodeDaemon::from_persisted_or_genesis(config, &directory);
        assert!(
            recovered.is_ok(),
            "daemon should recover from persisted state"
        );
        let recovered = recovered.unwrap_or_else(|_| unreachable!());
        assert_eq!(recovered.finalized_block().header.height, expected_height);
        assert_eq!(recovered.chain_state().state_root(), expected_state_root);
        let recovered_hash = recovered.finalized_block().hash();
        assert!(
            recovered_hash.is_ok(),
            "recovered finalized block hash should compute"
        );
        assert_eq!(
            recovered_hash.unwrap_or_else(|_| unreachable!()),
            expected_hash
        );

        let cleanup = fs::remove_dir_all(&directory);
        assert!(
            cleanup.is_ok(),
            "test persistence directory should clean up"
        );
    }

    #[test]
    fn from_persisted_or_genesis_recovers_mempool_checkpoint_entries() {
        let network = Network::Testnet;
        let mut daemon = daemon_with_low_pow(network);
        let transaction = signed_transaction_from_genesis_sender(network, 1, 10, 1);
        let encoded = transaction.encode();
        assert!(encoded.is_ok(), "transaction should encode");
        let admitted = daemon.handle_inbound_gossip_message(
            TRANSACTIONS_TOPIC,
            &encoded.unwrap_or_else(|_| unreachable!()),
            "peer-recovery",
            25_000,
        );
        assert!(admitted.is_ok(), "transaction should be admitted");
        assert_eq!(daemon.mempool_len(), 1);

        let directory = test_directory("homa-daemon-mempool-recover");
        let persisted = daemon.persist_runtime_state(&directory);
        assert!(persisted.is_ok(), "persist should succeed");

        let mut config = NodeDaemonConfig::for_network(network);
        config.mempool_config = MempoolConfig::new(10_000, 0, network);
        config.max_pending_blocks = 16;
        let recovered = NodeDaemon::from_persisted_or_genesis(config, &directory);
        assert!(recovered.is_ok(), "recovery should succeed");
        let recovered = recovered.unwrap_or_else(|_| unreachable!());
        assert_eq!(recovered.mempool_len(), 1, "mempool entry should recover");
        let recovery_report = recovered.recovery_report();
        assert_eq!(recovery_report.mempool_recovered, 1);
        assert_eq!(recovery_report.mempool_dropped_invalid, 0);
        assert_eq!(recovery_report.mempool_dropped_conflict, 0);

        let cleanup = fs::remove_dir_all(&directory);
        assert!(cleanup.is_ok(), "test directory should clean up");
    }

    #[test]
    fn from_persisted_or_genesis_tracks_invalid_and_conflicting_mempool_recovery_drops() {
        let network = Network::Testnet;
        let daemon = daemon_with_low_pow(network);
        let directory = test_directory("homa-daemon-mempool-drop-accounting");
        let persisted = daemon.persist_runtime_state(&directory);
        assert!(persisted.is_ok(), "persist should succeed");
        let now_ms = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map_or(0_u64, |duration| {
                u64::try_from(duration.as_millis()).unwrap_or(u64::MAX)
            });

        let checkpoint_entries = vec![
            MempoolCheckpointEntry {
                transaction: signed_transaction_from_genesis_sender(network, 1, 10, 1),
                observed_at_unix_ms: now_ms,
            },
            MempoolCheckpointEntry {
                transaction: signed_transaction_from_genesis_sender(network, 1, 11, 1),
                observed_at_unix_ms: now_ms.saturating_add(1),
            },
            MempoolCheckpointEntry {
                transaction: invalid_checkpoint_transaction(network),
                observed_at_unix_ms: now_ms.saturating_add(2),
            },
        ];
        let mempool_paths = MempoolCheckpointPaths::new(directory.clone());
        let checkpoint_persisted =
            persist_mempool_checkpoint_entries(&checkpoint_entries, network, &mempool_paths);
        assert!(
            checkpoint_persisted.is_ok(),
            "explicit mempool checkpoint should persist"
        );

        let mut config = NodeDaemonConfig::for_network(network);
        config.mempool_config = MempoolConfig::new(10_000, 0, network);
        config.max_pending_blocks = 16;
        let recovered = NodeDaemon::from_persisted_or_genesis(config, &directory);
        assert!(recovered.is_ok(), "recovery should succeed");
        let recovered = recovered.unwrap_or_else(|_| unreachable!());
        assert_eq!(
            recovered.mempool_len(),
            1,
            "only one valid, non-conflicting checkpoint tx should recover"
        );
        let recovery_report = recovered.recovery_report();
        assert_eq!(recovery_report.mempool_recovered, 1);
        assert_eq!(recovery_report.mempool_dropped_conflict, 1);
        assert_eq!(recovery_report.mempool_dropped_invalid, 1);

        let cleanup = fs::remove_dir_all(&directory);
        assert!(cleanup.is_ok(), "test directory should clean up");
    }

    #[test]
    fn maintenance_tick_persists_mempool_checkpoint_when_directory_is_configured() {
        let network = Network::Testnet;
        let mut daemon = daemon_with_low_pow(network);
        daemon.config.mempool_checkpoint_interval_ms = 1;
        let directory = test_directory("homa-daemon-periodic-mempool-checkpoint");
        let configured = daemon.configure_persistence_directory(directory.clone());
        assert!(configured.is_ok(), "persistence directory should configure");
        let transaction = signed_transaction_from_genesis_sender(network, 1, 10, 1);
        let encoded = transaction.encode();
        assert!(encoded.is_ok(), "transaction should encode");
        let admitted = daemon.handle_inbound_gossip_message(
            TRANSACTIONS_TOPIC,
            &encoded.unwrap_or_else(|_| unreachable!()),
            "peer-periodic",
            40_000,
        );
        assert!(admitted.is_ok(), "transaction should be admitted");

        let maintenance = daemon.run_maintenance_tick(40_001);
        assert!(maintenance.is_ok(), "maintenance tick should succeed");
        assert!(
            directory.join(MEMPOOL_CHECKPOINT_FILE_NAME).exists(),
            "maintenance tick should write periodic mempool checkpoint"
        );

        let cleanup = fs::remove_dir_all(&directory);
        assert!(cleanup.is_ok(), "test directory should clean up");
    }

    #[test]
    fn from_persisted_or_genesis_bootstraps_genesis_when_state_absent() {
        let network = Network::Testnet;
        let directory = test_directory("homa-daemon-empty");
        let mut config = NodeDaemonConfig::for_network(network);
        config.mempool_config = MempoolConfig::new(10_000, 0, network);
        config.max_pending_blocks = 16;

        let daemon = NodeDaemon::from_persisted_or_genesis(config, &directory);
        assert!(
            daemon.is_ok(),
            "daemon should fall back to genesis when no persisted state exists"
        );
        let daemon = daemon.unwrap_or_else(|_| unreachable!());
        assert_eq!(daemon.finalized_block().header.height, 0);
        assert_eq!(daemon.pending_block_count(), 0);

        let _ = fs::remove_dir_all(&directory);
    }

    #[test]
    fn from_persisted_or_genesis_rejects_missing_finalized_block_checkpoint() {
        let network = Network::Testnet;
        let daemon = daemon_with_low_pow(network);
        let directory = test_directory("homa-daemon-missing-finalized");
        let persisted = daemon.persist_runtime_state(&directory);
        assert!(persisted.is_ok(), "persist should succeed");

        let remove = fs::remove_file(directory.join(FINALIZED_BLOCK_CHECKPOINT_FILE_NAME));
        assert!(
            remove.is_ok(),
            "finalized-block checkpoint should be removable for corruption test"
        );

        let mut config = NodeDaemonConfig::for_network(network);
        config.mempool_config = MempoolConfig::new(10_000, 0, network);
        config.max_pending_blocks = 16;
        let restored = NodeDaemon::from_persisted_or_genesis(config, &directory);
        assert!(
            matches!(
                restored,
                Err(NodeDaemonError::MissingFinalizedBlockCheckpoint { path: _ })
            ),
            "daemon startup must reject persisted state missing finalized-block checkpoint"
        );

        let cleanup = fs::remove_dir_all(&directory);
        assert!(
            cleanup.is_ok(),
            "test persistence directory should clean up"
        );
    }

    #[test]
    fn from_persisted_or_genesis_sanitizes_in_flight_sync_checkpoint_state() {
        let network = Network::Testnet;
        let mut daemon = daemon_with_low_pow(network);
        let scheduled = daemon.sync_runtime_mut().schedule_outbound_request(
            "peer-sync",
            7,
            SnapshotChunkRequest {
                request_id: 42,
                block_height: 1,
                state_root: [3_u8; 32],
                snapshot_hash: [4_u8; 32],
                chunk_index: 0,
                total_chunks: 1,
            },
            9_000,
        );
        assert!(scheduled.is_ok(), "sync request should schedule");
        let directory = test_directory("homa-daemon-sync-in-flight");
        let persisted = daemon.persist_runtime_state(&directory);
        assert!(persisted.is_ok(), "persist should succeed");

        let mut config = NodeDaemonConfig::for_network(network);
        config.mempool_config = MempoolConfig::new(10_000, 0, network);
        config.max_pending_blocks = 16;
        let restored = NodeDaemon::from_persisted_or_genesis(config, &directory);
        assert!(
            restored.is_ok(),
            "startup recovery should sanitize stranded in-flight sync transport state"
        );
        let mut restored = restored.unwrap_or_else(|_| unreachable!());
        assert_eq!(
            restored.sync_runtime_mut().in_flight_request_count(),
            0,
            "recovered scheduler must not retain in-flight request transport state"
        );
        assert_eq!(
            restored
                .sync_runtime_mut()
                .peer_in_flight_count("peer-sync"),
            0,
            "recovered session manager must not retain in-flight peer chunk state"
        );
        let rescheduled = restored.sync_runtime_mut().schedule_outbound_request(
            "peer-sync",
            7,
            SnapshotChunkRequest {
                request_id: 77,
                block_height: 1,
                state_root: [3_u8; 32],
                snapshot_hash: [4_u8; 32],
                chunk_index: 0,
                total_chunks: 1,
            },
            9_500,
        );
        assert!(
            rescheduled.is_ok(),
            "sync scheduling should remain operational after restart sanitization"
        );

        let cleanup = fs::remove_dir_all(&directory);
        assert!(
            cleanup.is_ok(),
            "test persistence directory should clean up"
        );
    }

    #[test]
    fn from_genesis_with_config_transitions_to_ready_lifecycle() {
        let mut config = NodeDaemonConfig::for_network(Network::Testnet);
        config.mempool_config = MempoolConfig::new(10_000, 0, Network::Testnet);
        config.max_pending_blocks = 16;
        let daemon = NodeDaemon::from_genesis_with_config(config);
        assert!(daemon.is_ok(), "daemon should initialize from genesis");
        let daemon = daemon.unwrap_or_else(|_| unreachable!());
        assert_eq!(
            daemon.lifecycle_state(),
            NodeLifecycleState::Ready,
            "genesis startup should settle to ready lifecycle state"
        );
    }

    #[test]
    fn strict_recovery_rejects_sync_policy_mismatch_on_startup() {
        let network = Network::Testnet;
        let daemon = daemon_with_low_pow(network);
        let directory = test_directory("homa-daemon-strict-sync-mismatch");
        let persisted = daemon.persist_runtime_state(&directory);
        assert!(persisted.is_ok(), "persist should succeed");

        let mut config = NodeDaemonConfig::for_network(network);
        config.mempool_config = MempoolConfig::new(10_000, 0, network);
        config.max_pending_blocks = 16;
        config.request_policy = RequestSchedulerPolicy {
            max_retries: config.request_policy.max_retries.saturating_add(1),
            ..config.request_policy
        };
        config.strict_recovery = true;

        let restored = NodeDaemon::from_persisted_or_genesis(config, &directory);
        assert!(
            matches!(
                restored,
                Err(NodeDaemonError::RecoveredSyncSchedulerPolicyMismatch {
                    expected: _,
                    recovered: _
                })
            ),
            "strict recovery should fail closed when recovered sync scheduler policy mismatches startup config"
        );

        let cleanup = fs::remove_dir_all(&directory);
        assert!(cleanup.is_ok(), "test directory should clean up");
    }

    #[test]
    fn non_strict_recovery_replaces_mismatched_sync_policy() {
        let network = Network::Testnet;
        let daemon = daemon_with_low_pow(network);
        let directory = test_directory("homa-daemon-relaxed-sync-mismatch");
        let persisted = daemon.persist_runtime_state(&directory);
        assert!(persisted.is_ok(), "persist should succeed");

        let mut config = NodeDaemonConfig::for_network(network);
        config.mempool_config = MempoolConfig::new(10_000, 0, network);
        config.max_pending_blocks = 16;
        config.request_policy = RequestSchedulerPolicy {
            max_retries: config.request_policy.max_retries.saturating_add(1),
            ..config.request_policy
        };
        config.strict_recovery = false;

        let restored = NodeDaemon::from_persisted_or_genesis(config, &directory);
        assert!(
            restored.is_ok(),
            "non-strict recovery should replace mismatched sync policy and continue startup: {restored:?}"
        );
        let mut restored = restored.unwrap_or_else(|_| unreachable!());
        assert_eq!(
            restored.sync_runtime_mut().request_scheduler().policy(),
            config.request_policy,
            "recovered runtime should adopt configured scheduler policy in non-strict mode"
        );
        assert_eq!(
            restored.lifecycle_state(),
            NodeLifecycleState::Ready,
            "daemon should still transition to ready in non-strict mode"
        );

        let cleanup = fs::remove_dir_all(&directory);
        assert!(cleanup.is_ok(), "test directory should clean up");
    }

    #[test]
    fn ignore_mempool_checkpoint_skips_recovery_entries() {
        let network = Network::Testnet;
        let mut daemon = daemon_with_low_pow(network);
        let transaction = signed_transaction_from_genesis_sender(network, 1, 10, 1);
        let encoded = transaction.encode();
        assert!(encoded.is_ok(), "transaction should encode");
        let admitted = daemon.handle_inbound_gossip_message(
            TRANSACTIONS_TOPIC,
            &encoded.unwrap_or_else(|_| unreachable!()),
            "peer-ignore-mempool",
            60_000,
        );
        assert!(admitted.is_ok(), "transaction should be admitted");
        assert_eq!(daemon.mempool_len(), 1);

        let directory = test_directory("homa-daemon-ignore-mempool");
        let persisted = daemon.persist_runtime_state(&directory);
        assert!(persisted.is_ok(), "persist should succeed");

        let mut config = NodeDaemonConfig::for_network(network);
        config.mempool_config = MempoolConfig::new(10_000, 0, network);
        config.max_pending_blocks = 16;
        config.ignore_mempool_checkpoint = true;

        let restored = NodeDaemon::from_persisted_or_genesis(config, &directory);
        assert!(
            restored.is_ok(),
            "recovery should succeed when mempool checkpoint ingestion is disabled"
        );
        let restored = restored.unwrap_or_else(|_| unreachable!());
        assert_eq!(
            restored.mempool_len(),
            0,
            "mempool checkpoint entries should be ignored on startup"
        );
        assert_eq!(
            restored.recovery_report().mempool_recovered,
            0,
            "mempool recovery counter should stay zero when ingestion is disabled"
        );

        let cleanup = fs::remove_dir_all(&directory);
        assert!(cleanup.is_ok(), "test directory should clean up");
    }

    #[test]
    fn repair_index_mode_marks_rebuild_in_recovery_report() {
        let network = Network::Testnet;
        let mut daemon = daemon_with_local_producer(network);
        let directory = test_directory("homa-daemon-repair-index");
        let configured = daemon.configure_persistence_directory(directory.clone());
        assert!(configured.is_ok(), "persistence directory should configure");
        let persisted = daemon.persist_runtime_state(&directory);
        assert!(persisted.is_ok(), "persist should succeed");
        let drained = daemon.drain_and_stop();
        assert!(
            drained.is_ok(),
            "initial daemon should close index db handle before restart simulation"
        );

        let mut config = NodeDaemonConfig::for_network(network);
        config.mempool_config = MempoolConfig::new(10_000, 0, network);
        config.max_pending_blocks = 16;
        config.repair_index = true;

        let restored = NodeDaemon::from_persisted_or_genesis(config, &directory);
        assert!(
            restored.is_ok(),
            "recovery should succeed with explicit repair-index mode: {restored:?}"
        );
        let restored = restored.unwrap_or_else(|_| unreachable!());
        let recovery = restored.recovery_report();
        assert!(
            recovery.index_rebuild_performed,
            "repair-index mode should report rebuild as performed"
        );

        let cleanup = fs::remove_dir_all(&directory);
        assert!(cleanup.is_ok(), "test directory should clean up");
    }

    #[test]
    fn drain_and_stop_transitions_lifecycle_and_blocks_new_intake() {
        let network = Network::Testnet;
        let mut daemon = daemon_with_low_pow(network);
        let directory = test_directory("homa-daemon-drain-stop");
        let configured = daemon.configure_persistence_directory(directory.clone());
        assert!(configured.is_ok(), "persistence directory should configure");

        let drained = daemon.drain_and_stop();
        assert!(drained.is_ok(), "drain and stop should succeed");
        let drained = drained.unwrap_or_else(|_| unreachable!());
        assert!(
            drained.is_some(),
            "drain should emit persistence report when persistence is configured"
        );
        assert_eq!(
            daemon.lifecycle_state(),
            NodeLifecycleState::Stopped,
            "drain should transition daemon to stopped lifecycle state"
        );

        let rejected = daemon.handle_inbound_gossip_message(
            TRANSACTIONS_TOPIC,
            &[0_u8; 1],
            "peer-after-stop",
            70_000,
        );
        assert!(
            matches!(
                rejected,
                Err(NodeDaemonError::IntakeStopped {
                    state: NodeLifecycleState::Stopped
                })
            ),
            "inbound intake must reject messages after stop transition"
        );

        let second = daemon.drain_and_stop();
        assert!(second.is_ok(), "second drain call should be harmless");
        assert!(
            second.unwrap_or_else(|_| unreachable!()).is_none(),
            "second drain call should not persist again when already stopped"
        );

        let cleanup = fs::remove_dir_all(&directory);
        assert!(cleanup.is_ok(), "test directory should clean up");
    }
}
