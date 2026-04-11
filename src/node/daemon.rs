//! Node daemon skeleton and runtime event-loop wiring.

use std::collections::VecDeque;
use std::str::FromStr;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use futures::StreamExt;
use libp2p::Multiaddr;
use libp2p::gossipsub::Event as GossipsubEvent;
use libp2p::swarm::{Swarm, SwarmEvent};
use thiserror::Error;

use crate::core::block::{Block, BlockError};
use crate::core::genesis::{GenesisError, default_genesis_allocations, forge_genesis};
use crate::core::mempool::{Mempool, MempoolConfig, MempoolError, TransactionId};
use crate::core::state::ChainState;
use crate::core::sync::{SnapshotAdmissionPolicy, SnapshotImportMode};
use crate::crypto::address::Network;
use crate::network::checkpoint_rotation::{
    CheckpointRotationPolicy, RotationIngestOutcome, TrustedCheckpointSet,
};
use crate::network::p2p::{
    DEFAULT_BOOTSTRAP_QUIC_PORT, DEFAULT_BOOTSTRAP_TCP_PORT, HomaBehaviour, HomaBehaviourEvent,
    NetworkError, P2PConfig, add_kademlia_address, bootstrap_dht, build_swarm,
    resolve_bootstrap_addresses,
};
use crate::network::reputation::{AdaptivePenaltyPolicy, ReputationEvent, ReputationPolicy};
use crate::network::runtime_loop::{
    InboundGossipAction, RuntimeLoopError,
    handle_inbound_gossip_message_with_feedback_and_sync_runtime,
};
use crate::network::runtime_policy::{RuntimePolicyError, SyncRuntimePolicyController};
use crate::network::sync_engine::{ChunkServePolicy, ChunkSessionPolicy, RequestSchedulerPolicy};
use crate::network::sync_runtime::{
    SnapshotImportFailurePolicy, SyncRuntimeCoordinator, SyncRuntimeError,
};
use crate::observability::Observability;

/// Default in-memory queue bound for decoded pending block payloads.
pub const DEFAULT_MAX_PENDING_BLOCKS: usize = 512;
/// Default runtime event-loop poll interval.
pub const DEFAULT_EVENT_LOOP_TICK_MS: u64 = 250;

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
    /// Maximum decoded pending blocks retained in-memory.
    pub max_pending_blocks: usize,
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
            max_pending_blocks: DEFAULT_MAX_PENDING_BLOCKS,
        }
    }
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
    /// Number of imported snapshots observed across ticks.
    pub imported_snapshots: usize,
    /// Number of quarantined snapshots observed across ticks.
    pub quarantined_snapshots: usize,
    /// Number of maintenance ticks that had blocked imports.
    pub blocked_import_events: usize,
}

impl NodeEventLoopReport {
    const fn absorb(&mut self, other: Self) {
        self.processed_swarm_events = self
            .processed_swarm_events
            .saturating_add(other.processed_swarm_events);
        self.processed_gossip_messages = self
            .processed_gossip_messages
            .saturating_add(other.processed_gossip_messages);
        self.maintenance_ticks = self
            .maintenance_ticks
            .saturating_add(other.maintenance_ticks);
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
    /// Swarm-backed event loop was requested without attached swarm.
    #[error("node daemon has no attached swarm")]
    MissingSwarm,
    /// Attached swarm stream closed unexpectedly.
    #[error("node daemon swarm stream closed")]
    SwarmClosed,
}

/// Long-running daemon skeleton that wires runtime policy + sync + mempool handling.
pub struct NodeDaemon {
    config: NodeDaemonConfig,
    controller: SyncRuntimePolicyController,
    sync_runtime: SyncRuntimeCoordinator,
    chain_state: ChainState,
    finalized_block: Block,
    mempool: Mempool,
    pending_blocks: VecDeque<Block>,
    observability: Observability,
    stats: NodeRuntimeStats,
    swarm: Option<Swarm<HomaBehaviour>>,
}

impl std::fmt::Debug for NodeDaemon {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("NodeDaemon")
            .field("config", &self.config)
            .field("controller", &self.controller)
            .field("sync_runtime", &self.sync_runtime)
            .field("chain_state", &self.chain_state)
            .field("finalized_block", &self.finalized_block)
            .field("mempool", &self.mempool)
            .field("pending_blocks", &self.pending_blocks)
            .field("observability", &self.observability)
            .field("stats", &self.stats)
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
        let (genesis_block, chain_state) =
            forge_genesis(network).map_err(|source| NodeDaemonError::Genesis { source })?;
        Self::new(config, genesis_block, chain_state, trusted_set)
    }

    /// Creates a daemon from explicit runtime config and initialized state.
    pub fn new(
        config: NodeDaemonConfig,
        finalized_block: Block,
        chain_state: ChainState,
        trusted_checkpoint_set: TrustedCheckpointSet,
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

        Ok(Self {
            config,
            controller,
            sync_runtime,
            chain_state,
            finalized_block,
            mempool,
            pending_blocks: VecDeque::new(),
            observability,
            stats: NodeRuntimeStats::default(),
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
    pub fn handle_inbound_gossip_message(
        &mut self,
        topic: &str,
        payload: &[u8],
        peer_id: &str,
        now_ms: u64,
    ) -> Result<NodeInboundOutcome, NodeDaemonError> {
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
                let height = block.header.height;
                self.enqueue_pending_block(block);
                self.stats.blocks_queued_total = self.stats.blocks_queued_total.saturating_add(1);
                self.controller
                    .record_peer_event(peer_id, ReputationEvent::HelpfulRelay, now_ms);
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

        Ok(NodeMaintenanceReport {
            retried_requests: timeout_feedback.retries.len(),
            exhausted_requests: timeout_feedback.exhausted.len(),
            imported_snapshots: batch.imported.len(),
            quarantined_snapshots: batch.quarantined.len(),
            blocked_import: batch.blocked,
        })
    }

    /// Runs one maintenance tick using the current wall-clock timestamp.
    pub fn run_maintenance_tick_now(&mut self) -> Result<NodeMaintenanceReport, NodeDaemonError> {
        self.run_maintenance_tick(now_unix_ms())
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

    /// Returns immutable chain state reference.
    #[must_use]
    pub const fn chain_state(&self) -> &ChainState {
        &self.chain_state
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

    fn enqueue_pending_block(&mut self, block: Block) {
        if self.pending_blocks.len() >= self.config.max_pending_blocks {
            let _ = self.pending_blocks.pop_front();
            self.stats.pending_block_evictions_total =
                self.stats.pending_block_evictions_total.saturating_add(1);
        }
        self.pending_blocks.push_back(block);
    }

    fn swarm_mut(&mut self) -> Result<&mut Swarm<HomaBehaviour>, NodeDaemonError> {
        self.swarm.as_mut().ok_or(NodeDaemonError::MissingSwarm)
    }
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

fn now_unix_ms() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |duration| {
            u64::try_from(duration.as_millis()).unwrap_or(u64::MAX)
        })
}

#[cfg(test)]
mod tests {
    use super::{
        NodeDaemon, NodeDaemonConfig, NodeDaemonError, NodeInboundOutcome,
        trusted_checkpoint_set_from_genesis,
    };
    use crate::core::genesis::forge_genesis;
    use crate::core::mempool::MempoolConfig;
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

    fn daemon_with_low_pow(network: Network) -> NodeDaemon {
        let mut config = NodeDaemonConfig::for_network(network);
        config.mempool_config = MempoolConfig::new(10_000, 0, network);
        config.max_pending_blocks = 16;

        let trusted = trusted_checkpoint_set_from_genesis(network);
        assert!(trusted.is_ok(), "trusted-set bootstrap should succeed");
        let trusted = trusted.unwrap_or_else(|_| unreachable!());
        let forged = forge_genesis(network);
        assert!(forged.is_ok(), "genesis forge should succeed");
        let (genesis_block, chain_state) = forged.unwrap_or_else(|_| unreachable!());

        let daemon = NodeDaemon::new(config, genesis_block, chain_state, trusted);
        assert!(daemon.is_ok(), "daemon should initialize");
        daemon.unwrap_or_else(|_| unreachable!())
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
}
