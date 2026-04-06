//! Runtime coordinator for outbound snapshot sync retries, inbound chunk responses, and snapshot assembly.

use std::collections::{HashMap, VecDeque};

use thiserror::Error;

use crate::core::block::Block;
use crate::core::state::ChainState;
use crate::core::sync::{
    CheckpointVerificationPolicy, DEFAULT_SNAPSHOT_CHUNK_BYTES, SnapshotAdmissionPolicy,
    SnapshotCheckpoint, SnapshotChunkAssembler, SnapshotImportMode, StateSnapshot, SyncError,
    import_verified_snapshot_with_checkpoint_and_policy, import_verified_snapshot_with_policy,
};
use crate::network::p2p::{SnapshotChunkRequest, SnapshotChunkResponse};
use crate::network::sync_engine::{
    ChunkRequestScheduler, ChunkSessionManager, ChunkSessionPolicy, RequestSchedulerPolicy,
    SessionSchedule, SyncEngineError,
};
use crate::observability::Observability;

/// Outcome of scheduling one outbound snapshot chunk request.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum OutboundRequestScheduleOutcome {
    /// Request is admitted and ready to dispatch now.
    Scheduled {
        /// Request id.
        request_id: u64,
    },
    /// Request is deferred due to session backoff.
    Deferred {
        /// Request id.
        request_id: u64,
        /// Earliest retry timestamp.
        retry_at_ms: u64,
    },
}

/// Outcome of trying to activate one already-tracked retry dispatch.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RetryDispatchActivation {
    /// Retry dispatch is admitted and can be sent now.
    Ready {
        /// Target peer id.
        peer_id: String,
        /// Session id.
        session_id: u64,
        /// Request payload to send.
        request: SnapshotChunkRequest,
        /// Attempt number currently tracked by the scheduler.
        attempt: u8,
    },
    /// Retry dispatch is still in cooldown.
    Deferred {
        /// Earliest retry timestamp.
        retry_at_ms: u64,
    },
}

/// Accepted inbound chunk response with resolved session context.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AcceptedInboundChunkResponse {
    /// Session id associated with request tracking.
    pub session_id: u64,
    /// Decoded inbound response payload.
    pub response: SnapshotChunkResponse,
    /// Snapshot assembly progress after ingesting this response chunk.
    pub assembly: AssemblyIngestOutcome,
}

/// One timeout-driven retry entry with session backoff decision.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TimeoutRetryFeedback {
    /// Request id.
    pub request_id: u64,
    /// Target peer id.
    pub peer_id: String,
    /// Session id.
    pub session_id: u64,
    /// Attempt number after timeout processing.
    pub attempt: u8,
    /// Earliest allowed retry dispatch timestamp.
    pub retry_at_ms: u64,
}

/// One timeout-driven exhausted entry after retry budget depletion.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TimeoutExhaustedFeedback {
    /// Request id.
    pub request_id: u64,
    /// Target peer id.
    pub peer_id: String,
    /// Session id.
    pub session_id: u64,
    /// Attempts consumed before exhaustion.
    pub attempts: u8,
    /// Earliest timestamp at which this chunk may be rescheduled again.
    pub retry_at_ms: u64,
}

/// Aggregated timeout processing result.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct SyncRuntimeTimeoutFeedback {
    /// Retry entries still tracked by scheduler.
    pub retries: Vec<TimeoutRetryFeedback>,
    /// Exhausted entries removed from scheduler tracking.
    pub exhausted: Vec<TimeoutExhaustedFeedback>,
}

/// Stable key identifying one snapshot chunk stream.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct SnapshotStreamKey {
    /// Snapshot block height.
    pub block_height: u64,
    /// Snapshot state root.
    pub state_root: [u8; 32],
    /// Snapshot payload hash.
    pub snapshot_hash: [u8; 32],
    /// Total chunks expected for this stream.
    pub total_chunks: u32,
}

/// Assembly progress outcome for one accepted inbound chunk response.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AssemblyIngestOutcome {
    /// Stream is still incomplete after ingest.
    InProgress {
        /// Snapshot stream key.
        stream: SnapshotStreamKey,
        /// Missing chunk indices after ingest.
        missing_chunks: Vec<u32>,
    },
    /// Stream completed and snapshot was finalized.
    Complete {
        /// Snapshot stream key.
        stream: SnapshotStreamKey,
    },
}

/// One snapshot finalized from completed chunk stream assembly.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CompletedSnapshot {
    /// Snapshot stream key.
    pub stream: SnapshotStreamKey,
    /// Finalized decoded snapshot payload.
    pub snapshot: StateSnapshot,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct CompletedSnapshotQueueEntry {
    completed: CompletedSnapshot,
    failed_import_attempts: u32,
}

impl CompletedSnapshotQueueEntry {
    const fn new(completed: CompletedSnapshot) -> Self {
        Self {
            completed,
            failed_import_attempts: 0,
        }
    }
}

/// Policy controlling when repeatedly failing completed snapshots are quarantined.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SnapshotImportFailurePolicy {
    /// Maximum consecutive failed import attempts before quarantine.
    pub max_consecutive_failures: u32,
}

impl SnapshotImportFailurePolicy {
    /// Recommended default failure policy for long-running runtime loops.
    #[must_use]
    pub const fn strict_default() -> Self {
        Self {
            max_consecutive_failures: 3,
        }
    }
}

impl Default for SnapshotImportFailurePolicy {
    fn default() -> Self {
        Self::strict_default()
    }
}

/// One completed snapshot quarantined after repeated failed imports.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct QuarantinedSnapshot {
    /// Snapshot stream key.
    pub stream: SnapshotStreamKey,
    /// Finalized decoded snapshot payload.
    pub snapshot: StateSnapshot,
    /// Count of consecutive failed import attempts before quarantine.
    pub failed_import_attempts: u32,
    /// Last typed import failure that triggered quarantine.
    pub last_error: SyncError,
}

/// Outcome for one completed snapshot successfully imported into chain state.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ImportedSnapshot {
    /// Snapshot stream key that was imported.
    pub stream: SnapshotStreamKey,
    /// Imported snapshot block height.
    pub block_height: u64,
    /// Imported snapshot state root.
    pub state_root: [u8; 32],
}

/// Batch import processing outcome for queued completed snapshots.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct SnapshotImportBatchOutcome {
    /// Successfully imported snapshots in processing order.
    pub imported: Vec<ImportedSnapshot>,
    /// Snapshots quarantined during this batch due to repeated import failures.
    pub quarantined: Vec<QuarantinedSnapshot>,
    /// First blocking error that prevented further progress this batch.
    pub blocked: Option<SyncRuntimeError>,
}

/// Runtime orchestration errors for sync request/response coordination.
#[derive(Debug, Clone, PartialEq, Eq, Error)]
pub enum SyncRuntimeError {
    /// Assembly policy fields are invalid.
    #[error(
        "invalid sync assembly policy: max_chunk_bytes={max_chunk_bytes}, max_snapshot_bytes={max_snapshot_bytes}, max_accounts={max_accounts}"
    )]
    InvalidAssemblyPolicy {
        /// Maximum per-chunk payload bytes.
        max_chunk_bytes: usize,
        /// Maximum snapshot payload bytes.
        max_snapshot_bytes: usize,
        /// Maximum snapshot account count.
        max_accounts: usize,
    },
    /// Import failure policy fields are invalid.
    #[error(
        "invalid snapshot import failure policy: max_consecutive_failures={max_consecutive_failures}"
    )]
    InvalidImportFailurePolicy {
        /// Maximum consecutive failures before quarantine.
        max_consecutive_failures: u32,
    },
    /// Sync-engine component returned a typed failure.
    #[error("sync engine failure")]
    SyncEngine {
        /// Underlying sync-engine error.
        source: SyncEngineError,
    },
    /// Request id is already tracked in runtime request-session map.
    #[error("sync runtime request id already tracked: {request_id}")]
    RequestAlreadyTracked {
        /// Duplicate request id.
        request_id: u64,
    },
    /// Runtime request-session map has no session for one tracked request id.
    #[error("sync runtime missing tracked session for request id: {request_id}")]
    MissingTrackedSession {
        /// Missing request id.
        request_id: u64,
    },
    /// Runtime assembly state unexpectedly missing for one response stream.
    #[error("sync runtime missing assembly state for snapshot stream at height {block_height}")]
    MissingAssemblyState {
        /// Snapshot stream block height.
        block_height: u64,
    },
    /// Inbound chunk response came from unexpected peer.
    #[error(
        "sync chunk response peer mismatch for request {request_id}: expected {expected_peer_id}, got {actual_peer_id}"
    )]
    ResponsePeerMismatch {
        /// Request id.
        request_id: u64,
        /// Expected peer id.
        expected_peer_id: String,
        /// Actual peer id.
        actual_peer_id: String,
    },
    /// Inbound chunk response metadata mismatched its tracked request.
    #[error("sync chunk response metadata mismatch for request {request_id} on field {field}")]
    ResponseMetadataMismatch {
        /// Request id.
        request_id: u64,
        /// Metadata field that mismatched.
        field: &'static str,
    },
    /// Session rollback failed after scheduler rejection.
    #[error("sync runtime failed to rollback session state after scheduler rejection")]
    SessionRollback {
        /// Underlying rollback error.
        source: SyncEngineError,
    },
    /// Snapshot chunk assembly or finalization failed.
    #[error("snapshot assembly failure")]
    SnapshotAssembly {
        /// Underlying snapshot sync error.
        source: SyncError,
    },
    /// Snapshot import verification or state-load operation failed.
    #[error(
        "snapshot import failure at height {block_height} (state_root={state_root:?}, failure_count={failure_count})"
    )]
    SnapshotImport {
        /// Snapshot height that failed import.
        block_height: u64,
        /// Snapshot state root that failed import.
        state_root: [u8; 32],
        /// Consecutive failed attempt count for this queued snapshot.
        failure_count: u32,
        /// Underlying snapshot import error.
        source: SyncError,
    },
    /// Snapshot import exceeded failure budget and was quarantined.
    #[error(
        "snapshot import quarantined at height {block_height} (state_root={state_root:?}) after {failure_count} consecutive failures"
    )]
    SnapshotImportQuarantined {
        /// Snapshot height that was quarantined.
        block_height: u64,
        /// Snapshot state root that was quarantined.
        state_root: [u8; 32],
        /// Failure count observed before quarantine.
        failure_count: u32,
        /// Underlying typed import error that triggered quarantine.
        source: SyncError,
    },
}

/// Runtime coordinator composing request scheduler + session windows for sync traffic.
#[derive(Debug, Clone)]
pub struct SyncRuntimeCoordinator {
    scheduler: ChunkRequestScheduler,
    session_manager: ChunkSessionManager,
    request_sessions: HashMap<u64, u64>,
    max_chunk_bytes: usize,
    admission_policy: SnapshotAdmissionPolicy,
    import_failure_policy: SnapshotImportFailurePolicy,
    assemblers: HashMap<SnapshotStreamKey, SnapshotChunkAssembler>,
    completed_snapshots: VecDeque<CompletedSnapshotQueueEntry>,
    quarantined_snapshots: VecDeque<QuarantinedSnapshot>,
}

impl SyncRuntimeCoordinator {
    /// Builds a runtime coordinator from explicit scheduler/session policies.
    pub fn new(
        request_policy: RequestSchedulerPolicy,
        session_policy: ChunkSessionPolicy,
    ) -> Result<Self, SyncRuntimeError> {
        Self::with_assembly_policy(
            request_policy,
            session_policy,
            DEFAULT_SNAPSHOT_CHUNK_BYTES,
            SnapshotAdmissionPolicy::default(),
        )
    }

    /// Builds a runtime coordinator with explicit snapshot assembly policy.
    pub fn with_assembly_policy(
        request_policy: RequestSchedulerPolicy,
        session_policy: ChunkSessionPolicy,
        max_chunk_bytes: usize,
        admission_policy: SnapshotAdmissionPolicy,
    ) -> Result<Self, SyncRuntimeError> {
        Self::with_assembly_and_import_policy(
            request_policy,
            session_policy,
            max_chunk_bytes,
            admission_policy,
            SnapshotImportFailurePolicy::default(),
        )
    }

    /// Builds a runtime coordinator with explicit assembly and import failure policies.
    pub fn with_assembly_and_import_policy(
        request_policy: RequestSchedulerPolicy,
        session_policy: ChunkSessionPolicy,
        max_chunk_bytes: usize,
        admission_policy: SnapshotAdmissionPolicy,
        import_failure_policy: SnapshotImportFailurePolicy,
    ) -> Result<Self, SyncRuntimeError> {
        validate_assembly_policy(max_chunk_bytes, admission_policy)?;
        validate_import_failure_policy(import_failure_policy)?;
        let scheduler = ChunkRequestScheduler::new(request_policy)
            .map_err(|source| SyncRuntimeError::SyncEngine { source })?;
        let session_manager = ChunkSessionManager::new(session_policy)
            .map_err(|source| SyncRuntimeError::SyncEngine { source })?;
        Ok(Self {
            scheduler,
            session_manager,
            request_sessions: HashMap::new(),
            max_chunk_bytes,
            admission_policy,
            import_failure_policy,
            assemblers: HashMap::new(),
            completed_snapshots: VecDeque::new(),
            quarantined_snapshots: VecDeque::new(),
        })
    }

    /// Schedules one outbound chunk request under session backoff + in-flight limits.
    pub fn schedule_outbound_request(
        &mut self,
        peer_id: &str,
        session_id: u64,
        request: SnapshotChunkRequest,
        now_ms: u64,
    ) -> Result<OutboundRequestScheduleOutcome, SyncRuntimeError> {
        if self.request_sessions.contains_key(&request.request_id) {
            return Err(SyncRuntimeError::RequestAlreadyTracked {
                request_id: request.request_id,
            });
        }

        match self
            .session_manager
            .try_schedule_chunk(peer_id, session_id, request.chunk_index, now_ms)
            .map_err(|source| SyncRuntimeError::SyncEngine { source })?
        {
            SessionSchedule::Deferred { retry_at_ms } => {
                return Ok(OutboundRequestScheduleOutcome::Deferred {
                    request_id: request.request_id,
                    retry_at_ms,
                });
            }
            SessionSchedule::Scheduled => {}
        }

        if let Err(source) = self.scheduler.schedule(peer_id.to_owned(), request, now_ms) {
            self.session_manager
                .acknowledge_chunk(peer_id, session_id, request.chunk_index)
                .map_err(|source| SyncRuntimeError::SessionRollback { source })?;
            return Err(SyncRuntimeError::SyncEngine { source });
        }

        if self
            .request_sessions
            .insert(request.request_id, session_id)
            .is_some()
        {
            let _ = self.scheduler.acknowledge(request.request_id);
            let _ =
                self.session_manager
                    .acknowledge_chunk(peer_id, session_id, request.chunk_index);
            return Err(SyncRuntimeError::RequestAlreadyTracked {
                request_id: request.request_id,
            });
        }

        Ok(OutboundRequestScheduleOutcome::Scheduled {
            request_id: request.request_id,
        })
    }

    /// Activates one timeout-retry dispatch when session backoff allows it.
    pub fn activate_retry_dispatch(
        &mut self,
        request_id: u64,
        now_ms: u64,
    ) -> Result<RetryDispatchActivation, SyncRuntimeError> {
        let context = self
            .scheduler
            .in_flight_request_context(request_id)
            .map_err(|source| SyncRuntimeError::SyncEngine { source })?;
        let session_id = self
            .request_sessions
            .get(&request_id)
            .copied()
            .ok_or(SyncRuntimeError::MissingTrackedSession { request_id })?;

        match self
            .session_manager
            .try_schedule_chunk(
                &context.peer_id,
                session_id,
                context.request.chunk_index,
                now_ms,
            )
            .map_err(|source| SyncRuntimeError::SyncEngine { source })?
        {
            SessionSchedule::Scheduled => Ok(RetryDispatchActivation::Ready {
                peer_id: context.peer_id,
                session_id,
                request: context.request,
                attempt: context.attempt,
            }),
            SessionSchedule::Deferred { retry_at_ms } => {
                Ok(RetryDispatchActivation::Deferred { retry_at_ms })
            }
        }
    }

    /// Processes one decoded inbound chunk response and wires ack feedback to runtime state.
    pub fn handle_inbound_chunk_response(
        &mut self,
        peer_id: &str,
        response: SnapshotChunkResponse,
    ) -> Result<AcceptedInboundChunkResponse, SyncRuntimeError> {
        let request_id = response.request_id;
        let context = self
            .scheduler
            .in_flight_request_context(request_id)
            .map_err(|source| SyncRuntimeError::SyncEngine { source })?;
        let session_id = self
            .request_sessions
            .get(&request_id)
            .copied()
            .ok_or(SyncRuntimeError::MissingTrackedSession { request_id })?;

        if context.peer_id != peer_id {
            return Err(SyncRuntimeError::ResponsePeerMismatch {
                request_id,
                expected_peer_id: context.peer_id,
                actual_peer_id: peer_id.to_owned(),
            });
        }

        if let Some(field) = response_metadata_mismatch_field(context.request, &response) {
            return Err(SyncRuntimeError::ResponseMetadataMismatch { request_id, field });
        }

        let assembly = self.ingest_response_chunk(&response)?;

        self.scheduler
            .acknowledge(request_id)
            .map_err(|source| SyncRuntimeError::SyncEngine { source })?;
        self.session_manager
            .acknowledge_chunk(peer_id, session_id, response.chunk.chunk_index)
            .map_err(|source| SyncRuntimeError::SyncEngine { source })?;
        let _ = self.request_sessions.remove(&request_id);

        Ok(AcceptedInboundChunkResponse {
            session_id,
            response,
            assembly,
        })
    }

    /// Polls timeout state and applies deterministic loss feedback to session windows.
    pub fn poll_timeout_feedback(
        &mut self,
        now_ms: u64,
    ) -> Result<SyncRuntimeTimeoutFeedback, SyncRuntimeError> {
        let timeout_outcome = self.scheduler.poll_timeouts(now_ms);
        let mut feedback = SyncRuntimeTimeoutFeedback::default();

        for retry in timeout_outcome.retries {
            let request_id = retry.request.request_id;
            let session_id = self
                .request_sessions
                .get(&request_id)
                .copied()
                .ok_or(SyncRuntimeError::MissingTrackedSession { request_id })?;
            let retry_at_ms = self
                .session_manager
                .report_loss(
                    &retry.peer_id,
                    session_id,
                    retry.request.chunk_index,
                    now_ms,
                )
                .map_err(|source| SyncRuntimeError::SyncEngine { source })?;
            feedback.retries.push(TimeoutRetryFeedback {
                request_id,
                peer_id: retry.peer_id,
                session_id,
                attempt: retry.attempt,
                retry_at_ms,
            });
        }

        for exhausted in timeout_outcome.exhausted {
            let request_id = exhausted.request.request_id;
            let session_id = self
                .request_sessions
                .remove(&request_id)
                .ok_or(SyncRuntimeError::MissingTrackedSession { request_id })?;
            let retry_at_ms = self
                .session_manager
                .report_loss(
                    &exhausted.peer_id,
                    session_id,
                    exhausted.request.chunk_index,
                    now_ms,
                )
                .map_err(|source| SyncRuntimeError::SyncEngine { source })?;
            feedback.exhausted.push(TimeoutExhaustedFeedback {
                request_id,
                peer_id: exhausted.peer_id,
                session_id,
                attempts: exhausted.attempts,
                retry_at_ms,
            });
        }

        Ok(feedback)
    }

    /// Returns number of in-flight requests tracked by scheduler.
    #[must_use]
    pub fn in_flight_request_count(&self) -> usize {
        self.scheduler.in_flight_count()
    }

    /// Returns number of runtime tracked request -> session bindings.
    #[must_use]
    pub fn tracked_request_count(&self) -> usize {
        self.request_sessions.len()
    }

    /// Returns per-peer in-flight chunk count from session manager.
    #[must_use]
    pub fn peer_in_flight_count(&self, peer_id: &str) -> usize {
        self.session_manager.peer_in_flight_count(peer_id)
    }

    /// Returns number of active snapshot stream assemblers.
    #[must_use]
    pub fn active_assembly_stream_count(&self) -> usize {
        self.assemblers.len()
    }

    /// Returns number of completed snapshots waiting to be consumed.
    #[must_use]
    pub fn completed_snapshot_count(&self) -> usize {
        self.completed_snapshots.len()
    }

    /// Returns number of quarantined completed snapshots retained for inspection.
    #[must_use]
    pub fn quarantined_snapshot_count(&self) -> usize {
        self.quarantined_snapshots.len()
    }

    /// Drains and returns all completed snapshots assembled so far.
    pub fn drain_completed_snapshots(&mut self) -> Vec<CompletedSnapshot> {
        self.completed_snapshots
            .drain(..)
            .map(|entry| entry.completed)
            .collect()
    }

    /// Drains and returns all quarantined snapshots.
    pub fn drain_quarantined_snapshots(&mut self) -> Vec<QuarantinedSnapshot> {
        self.quarantined_snapshots.drain(..).collect()
    }

    /// Imports the next completed snapshot without checkpoint verification.
    ///
    /// Returns `Ok(None)` when no completed snapshot is queued.
    pub fn import_next_completed_snapshot(
        &mut self,
        state: &mut ChainState,
        finalized_block: &Block,
        import_mode: SnapshotImportMode,
    ) -> Result<Option<ImportedSnapshot>, SyncRuntimeError> {
        self.import_next_completed_snapshot_inner(state, finalized_block, None, None, import_mode)
    }

    /// Imports the next completed snapshot using checkpoint verification policy.
    ///
    /// Returns `Ok(None)` when no completed snapshot is queued.
    pub fn import_next_completed_snapshot_with_checkpoint(
        &mut self,
        state: &mut ChainState,
        finalized_block: &Block,
        checkpoint: &SnapshotCheckpoint,
        checkpoint_policy: CheckpointVerificationPolicy<'_>,
        import_mode: SnapshotImportMode,
    ) -> Result<Option<ImportedSnapshot>, SyncRuntimeError> {
        self.import_next_completed_snapshot_inner(
            state,
            finalized_block,
            Some(checkpoint),
            Some(checkpoint_policy),
            import_mode,
        )
    }

    /// Imports queued completed snapshots until queue drains or a non-quarantine failure blocks progress.
    pub fn import_completed_snapshot_batch(
        &mut self,
        state: &mut ChainState,
        finalized_block: &Block,
        import_mode: SnapshotImportMode,
        observability: Option<&Observability>,
    ) -> SnapshotImportBatchOutcome {
        self.import_completed_snapshot_batch_inner(
            state,
            finalized_block,
            None,
            None,
            import_mode,
            observability,
        )
    }

    /// Imports queued completed snapshots with checkpoint verification until queue drains or one failure blocks progress.
    pub fn import_completed_snapshot_batch_with_checkpoint(
        &mut self,
        state: &mut ChainState,
        finalized_block: &Block,
        checkpoint: &SnapshotCheckpoint,
        checkpoint_policy: CheckpointVerificationPolicy<'_>,
        import_mode: SnapshotImportMode,
        observability: Option<&Observability>,
    ) -> SnapshotImportBatchOutcome {
        self.import_completed_snapshot_batch_inner(
            state,
            finalized_block,
            Some(checkpoint),
            Some(checkpoint_policy),
            import_mode,
            observability,
        )
    }

    fn ingest_response_chunk(
        &mut self,
        response: &SnapshotChunkResponse,
    ) -> Result<AssemblyIngestOutcome, SyncRuntimeError> {
        let stream = stream_key_from_response(response);
        if !self.assemblers.contains_key(&stream) {
            let assembler = SnapshotChunkAssembler::new(self.max_chunk_bytes)
                .map_err(|source| SyncRuntimeError::SnapshotAssembly { source })?;
            let _ = self.assemblers.insert(stream, assembler);
        }

        let is_complete = {
            let assembler =
                self.assemblers
                    .get_mut(&stream)
                    .ok_or(SyncRuntimeError::MissingAssemblyState {
                        block_height: stream.block_height,
                    })?;
            assembler
                .ingest_chunk(response.chunk.clone())
                .map_err(|source| SyncRuntimeError::SnapshotAssembly { source })?;
            assembler.is_complete()
        };
        if !is_complete {
            let assembler =
                self.assemblers
                    .get(&stream)
                    .ok_or(SyncRuntimeError::MissingAssemblyState {
                        block_height: stream.block_height,
                    })?;
            return Ok(AssemblyIngestOutcome::InProgress {
                stream,
                missing_chunks: assembler.missing_chunk_indices(),
            });
        }

        let assembler =
            self.assemblers
                .remove(&stream)
                .ok_or(SyncRuntimeError::MissingAssemblyState {
                    block_height: stream.block_height,
                })?;
        let snapshot = assembler
            .finalize(self.admission_policy)
            .map_err(|source| SyncRuntimeError::SnapshotAssembly { source })?;
        self.completed_snapshots
            .push_back(CompletedSnapshotQueueEntry::new(CompletedSnapshot {
                stream,
                snapshot,
            }));

        Ok(AssemblyIngestOutcome::Complete { stream })
    }

    fn import_next_completed_snapshot_inner(
        &mut self,
        state: &mut ChainState,
        finalized_block: &Block,
        checkpoint: Option<&SnapshotCheckpoint>,
        checkpoint_policy: Option<CheckpointVerificationPolicy<'_>>,
        import_mode: SnapshotImportMode,
    ) -> Result<Option<ImportedSnapshot>, SyncRuntimeError> {
        let Some(completed) = self.completed_snapshots.front() else {
            return Ok(None);
        };
        let completed = completed.completed.clone();

        let import_result = match (checkpoint, checkpoint_policy) {
            (None, None) => import_verified_snapshot_with_policy(
                state,
                &completed.snapshot,
                finalized_block,
                self.admission_policy,
                import_mode,
            ),
            (Some(checkpoint), Some(checkpoint_policy)) => {
                import_verified_snapshot_with_checkpoint_and_policy(
                    state,
                    &completed.snapshot,
                    finalized_block,
                    checkpoint,
                    checkpoint_policy,
                    self.admission_policy,
                    import_mode,
                )
            }
            _ => unreachable!("checkpoint and checkpoint_policy must be provided together"),
        };

        if let Err(source) = import_result {
            let Some(front) = self.completed_snapshots.front_mut() else {
                return Ok(None);
            };
            front.failed_import_attempts = front.failed_import_attempts.saturating_add(1);
            let failure_count = front.failed_import_attempts;
            let block_height = completed.snapshot.block_height;
            let state_root = completed.snapshot.state_root;
            if failure_count >= self.import_failure_policy.max_consecutive_failures {
                let quarantined =
                    self.completed_snapshots
                        .pop_front()
                        .map(|entry| QuarantinedSnapshot {
                            stream: entry.completed.stream,
                            snapshot: entry.completed.snapshot,
                            failed_import_attempts: failure_count,
                            last_error: source.clone(),
                        });
                if let Some(quarantined) = quarantined {
                    self.quarantined_snapshots.push_back(quarantined);
                    return Err(SyncRuntimeError::SnapshotImportQuarantined {
                        block_height,
                        state_root,
                        failure_count,
                        source,
                    });
                }
            }
            return Err(SyncRuntimeError::SnapshotImport {
                block_height,
                state_root,
                failure_count,
                source,
            });
        }

        let imported = ImportedSnapshot {
            stream: completed.stream,
            block_height: completed.snapshot.block_height,
            state_root: completed.snapshot.state_root,
        };
        let _ = self.completed_snapshots.pop_front();
        Ok(Some(imported))
    }

    fn import_completed_snapshot_batch_inner(
        &mut self,
        state: &mut ChainState,
        finalized_block: &Block,
        checkpoint: Option<&SnapshotCheckpoint>,
        checkpoint_policy: Option<CheckpointVerificationPolicy<'_>>,
        import_mode: SnapshotImportMode,
        observability: Option<&Observability>,
    ) -> SnapshotImportBatchOutcome {
        let mut outcome = SnapshotImportBatchOutcome::default();
        loop {
            let result = self.import_next_completed_snapshot_inner(
                state,
                finalized_block,
                checkpoint,
                checkpoint_policy,
                import_mode,
            );
            record_snapshot_import_observability(observability, &result);

            match result {
                Ok(Some(imported)) => outcome.imported.push(imported),
                Ok(None) => break,
                Err(SyncRuntimeError::SnapshotImportQuarantined {
                    block_height: _,
                    state_root: _,
                    failure_count: _,
                    source: _,
                }) => {
                    if let Some(quarantined) = self.quarantined_snapshots.back() {
                        outcome.quarantined.push(quarantined.clone());
                    }
                }
                Err(error) => {
                    outcome.blocked = Some(error);
                    break;
                }
            }
        }
        outcome
    }
}

fn record_snapshot_import_observability(
    observability: Option<&Observability>,
    result: &Result<Option<ImportedSnapshot>, SyncRuntimeError>,
) {
    let Some(observability) = observability else {
        return;
    };
    match result {
        Ok(Some(imported)) => {
            observability
                .record_snapshot_import_success(imported.block_height, imported.state_root);
        }
        Err(SyncRuntimeError::SnapshotImport {
            block_height,
            state_root,
            failure_count,
            source,
        }) => {
            observability.record_snapshot_import_failure(
                *block_height,
                *state_root,
                *failure_count,
                &source.to_string(),
            );
        }
        Err(SyncRuntimeError::SnapshotImportQuarantined {
            block_height,
            state_root,
            failure_count,
            source,
        }) => {
            observability.record_snapshot_quarantine(
                *block_height,
                *state_root,
                *failure_count,
                &source.to_string(),
            );
        }
        Ok(None) | Err(_) => {}
    }
}

fn response_metadata_mismatch_field(
    request: SnapshotChunkRequest,
    response: &SnapshotChunkResponse,
) -> Option<&'static str> {
    if response.request_id != request.request_id {
        return Some("request_id");
    }
    if response.chunk.block_height != request.block_height {
        return Some("block_height");
    }
    if response.chunk.state_root != request.state_root {
        return Some("state_root");
    }
    if response.chunk.snapshot_hash != request.snapshot_hash {
        return Some("snapshot_hash");
    }
    if response.chunk.chunk_index != request.chunk_index {
        return Some("chunk_index");
    }
    if response.chunk.total_chunks != request.total_chunks {
        return Some("total_chunks");
    }
    None
}

const fn validate_assembly_policy(
    max_chunk_bytes: usize,
    admission_policy: SnapshotAdmissionPolicy,
) -> Result<(), SyncRuntimeError> {
    if max_chunk_bytes == 0
        || admission_policy.max_snapshot_bytes == 0
        || admission_policy.max_accounts == 0
    {
        return Err(SyncRuntimeError::InvalidAssemblyPolicy {
            max_chunk_bytes,
            max_snapshot_bytes: admission_policy.max_snapshot_bytes,
            max_accounts: admission_policy.max_accounts,
        });
    }
    Ok(())
}

const fn validate_import_failure_policy(
    import_failure_policy: SnapshotImportFailurePolicy,
) -> Result<(), SyncRuntimeError> {
    if import_failure_policy.max_consecutive_failures == 0 {
        return Err(SyncRuntimeError::InvalidImportFailurePolicy {
            max_consecutive_failures: import_failure_policy.max_consecutive_failures,
        });
    }
    Ok(())
}

const fn stream_key_from_response(response: &SnapshotChunkResponse) -> SnapshotStreamKey {
    SnapshotStreamKey {
        block_height: response.chunk.block_height,
        state_root: response.chunk.state_root,
        snapshot_hash: response.chunk.snapshot_hash,
        total_chunks: response.chunk.total_chunks,
    }
}

#[cfg(test)]
mod tests {
    use super::{
        AssemblyIngestOutcome, OutboundRequestScheduleOutcome, RetryDispatchActivation,
        SnapshotImportFailurePolicy, SyncRuntimeCoordinator, SyncRuntimeError,
    };
    use crate::core::block::{Block, BlockHeader, HASH_LENGTH};
    use crate::core::state::AccountState;
    use crate::core::state::ChainState;
    use crate::core::sync::{
        CheckpointVerificationPolicy, SnapshotAccount, SnapshotAdmissionPolicy, SnapshotCheckpoint,
        SnapshotImportMode, StateSnapshot, SyncError, build_state_snapshot,
        sign_snapshot_checkpoint, split_snapshot_into_chunks,
    };
    use crate::crypto::address::{Network, derive_address};
    use crate::crypto::keys::Keypair;
    use crate::network::p2p::{SnapshotChunkRequest, SnapshotChunkResponse};
    use crate::network::sync_engine::{ChunkSessionPolicy, RequestSchedulerPolicy};
    use crate::observability::{Observability, ObservabilityEventKind, SnapshotImportOutcome};

    fn sample_chunk() -> crate::core::sync::SnapshotChunk {
        let snapshot = StateSnapshot {
            block_height: 88,
            state_root: [4_u8; 32],
            accounts: vec![
                SnapshotAccount {
                    address: "HMA_RUNTIME_SYNC_A".to_owned(),
                    state: AccountState {
                        balance: 10,
                        nonce: 0,
                    },
                },
                SnapshotAccount {
                    address: "HMA_RUNTIME_SYNC_B".to_owned(),
                    state: AccountState {
                        balance: 20,
                        nonce: 1,
                    },
                },
            ],
        };
        let chunks = split_snapshot_into_chunks(&snapshot, 24);
        assert!(chunks.is_ok(), "snapshot chunk split should succeed");
        let mut chunks = chunks.unwrap_or_else(|_| unreachable!());
        assert!(!chunks.is_empty(), "chunk split should not be empty");
        chunks.remove(0)
    }

    fn sample_request_and_response(
        request_id: u64,
    ) -> (SnapshotChunkRequest, SnapshotChunkResponse) {
        let chunk = sample_chunk();
        let request = SnapshotChunkRequest {
            request_id,
            block_height: chunk.block_height,
            state_root: chunk.state_root,
            snapshot_hash: chunk.snapshot_hash,
            chunk_index: chunk.chunk_index,
            total_chunks: chunk.total_chunks,
        };
        let response = SnapshotChunkResponse { request_id, chunk };
        (request, response)
    }

    fn coordinator(max_retries: u8) -> SyncRuntimeCoordinator {
        let runtime = SyncRuntimeCoordinator::new(
            RequestSchedulerPolicy {
                request_timeout_ms: 100,
                max_retries,
                max_in_flight: 8,
            },
            ChunkSessionPolicy {
                max_in_flight_per_session: 4,
                max_in_flight_per_peer: 8,
                base_retry_backoff_ms: 100,
                max_retry_backoff_ms: 1_000,
            },
        );
        assert!(runtime.is_ok(), "runtime coordinator should initialize");
        runtime.unwrap_or_else(|_| unreachable!())
    }

    fn assembly_snapshot() -> StateSnapshot {
        StateSnapshot {
            block_height: 120,
            state_root: [8_u8; 32],
            accounts: vec![
                SnapshotAccount {
                    address: "HMA_ASSEMBLY_A".to_owned(),
                    state: AccountState {
                        balance: 10,
                        nonce: 0,
                    },
                },
                SnapshotAccount {
                    address: "HMA_ASSEMBLY_B".to_owned(),
                    state: AccountState {
                        balance: 20,
                        nonce: 1,
                    },
                },
                SnapshotAccount {
                    address: "HMA_ASSEMBLY_C".to_owned(),
                    state: AccountState {
                        balance: 30,
                        nonce: 2,
                    },
                },
                SnapshotAccount {
                    address: "HMA_ASSEMBLY_D".to_owned(),
                    state: AccountState {
                        balance: 40,
                        nonce: 3,
                    },
                },
            ],
        }
    }

    fn valid_address(network: Network) -> String {
        let keypair = Keypair::generate();
        let address = derive_address(&keypair.public_key_bytes(), network);
        assert!(address.is_ok(), "address derivation should succeed");
        address.unwrap_or_else(|_| unreachable!())
    }

    fn finalized_block_for_snapshot(snapshot: &StateSnapshot, proposer: String) -> Block {
        let header = BlockHeader::new(
            snapshot.block_height,
            [0_u8; HASH_LENGTH],
            snapshot.state_root,
            1_800_000_000,
            proposer,
        );
        let block = Block::new_unsigned(header, Vec::new());
        assert!(
            block.is_ok(),
            "finalized block fixture should be constructible"
        );
        block.unwrap_or_else(|_| unreachable!())
    }

    fn runtime_with_large_assembly() -> SyncRuntimeCoordinator {
        let runtime = SyncRuntimeCoordinator::with_assembly_policy(
            RequestSchedulerPolicy {
                request_timeout_ms: 100,
                max_retries: 1,
                max_in_flight: 64,
            },
            ChunkSessionPolicy {
                max_in_flight_per_session: 64,
                max_in_flight_per_peer: 128,
                base_retry_backoff_ms: 100,
                max_retry_backoff_ms: 1_000,
            },
            32,
            SnapshotAdmissionPolicy::default(),
        );
        assert!(
            runtime.is_ok(),
            "runtime with explicit assembly policy should initialize"
        );
        runtime.unwrap_or_else(|_| unreachable!())
    }

    fn runtime_with_import_failure_policy(
        import_failure_policy: SnapshotImportFailurePolicy,
    ) -> SyncRuntimeCoordinator {
        let runtime = SyncRuntimeCoordinator::with_assembly_and_import_policy(
            RequestSchedulerPolicy {
                request_timeout_ms: 100,
                max_retries: 1,
                max_in_flight: 64,
            },
            ChunkSessionPolicy {
                max_in_flight_per_session: 64,
                max_in_flight_per_peer: 128,
                base_retry_backoff_ms: 100,
                max_retry_backoff_ms: 1_000,
            },
            32,
            SnapshotAdmissionPolicy::default(),
            import_failure_policy,
        );
        assert!(
            runtime.is_ok(),
            "runtime with explicit import failure policy should initialize"
        );
        runtime.unwrap_or_else(|_| unreachable!())
    }

    fn runtime_with_completed_snapshot(snapshot: &StateSnapshot) -> SyncRuntimeCoordinator {
        let chunks = split_snapshot_into_chunks(snapshot, 32);
        assert!(chunks.is_ok(), "snapshot should split into chunks");
        let chunks = chunks.unwrap_or_else(|_| unreachable!());
        assert!(
            chunks.len() > 1,
            "snapshot fixture should produce multiple chunks for assembly path"
        );

        let mut runtime = runtime_with_large_assembly();
        let requests = chunks
            .iter()
            .enumerate()
            .map(|(index, chunk)| SnapshotChunkRequest {
                request_id: u64::try_from(index).unwrap_or(u64::MAX) + 1_000,
                block_height: chunk.block_height,
                state_root: chunk.state_root,
                snapshot_hash: chunk.snapshot_hash,
                chunk_index: chunk.chunk_index,
                total_chunks: chunk.total_chunks,
            })
            .collect::<Vec<_>>();
        let responses = requests
            .iter()
            .zip(chunks.iter())
            .map(|(request, chunk)| SnapshotChunkResponse {
                request_id: request.request_id,
                chunk: chunk.clone(),
            })
            .collect::<Vec<_>>();

        for request in &requests {
            let scheduled = runtime.schedule_outbound_request("peer-asm", 21, *request, 9_000);
            assert!(scheduled.is_ok(), "all requests should schedule");
        }
        for response in responses.into_iter().rev() {
            let accepted = runtime.handle_inbound_chunk_response("peer-asm", response);
            assert!(accepted.is_ok(), "chunk response should be accepted");
        }

        assert_eq!(
            runtime.completed_snapshot_count(),
            1,
            "runtime fixture should queue one completed snapshot"
        );
        runtime
    }

    #[test]
    fn inbound_chunk_response_acknowledges_scheduler_and_session_state() {
        let mut runtime = coordinator(1);
        let (request, response) = sample_request_and_response(11);

        let scheduled = runtime.schedule_outbound_request("peer-a", 7, request, 1_000);
        assert!(
            matches!(
                scheduled,
                Ok(OutboundRequestScheduleOutcome::Scheduled { request_id: 11 })
            ),
            "initial request should schedule successfully"
        );
        assert_eq!(runtime.in_flight_request_count(), 1);
        assert_eq!(runtime.tracked_request_count(), 1);
        assert_eq!(runtime.peer_in_flight_count("peer-a"), 1);

        let accepted = runtime.handle_inbound_chunk_response("peer-a", response.clone());
        assert!(accepted.is_ok(), "inbound response should be accepted");
        assert_eq!(
            accepted.unwrap_or_else(|_| unreachable!()).response,
            response,
            "accepted response should match inbound payload"
        );
        assert_eq!(runtime.in_flight_request_count(), 0);
        assert_eq!(runtime.tracked_request_count(), 0);
        assert_eq!(runtime.peer_in_flight_count("peer-a"), 0);
    }

    #[test]
    fn inbound_response_from_unexpected_peer_is_rejected_without_ack() {
        let mut runtime = coordinator(1);
        let (request, response) = sample_request_and_response(22);

        let scheduled = runtime.schedule_outbound_request("peer-a", 9, request, 2_000);
        assert!(scheduled.is_ok(), "initial request should schedule");

        let rejected = runtime.handle_inbound_chunk_response("peer-b", response);
        assert!(
            matches!(
                rejected,
                Err(SyncRuntimeError::ResponsePeerMismatch {
                    request_id: 22,
                    expected_peer_id: _,
                    actual_peer_id: _
                })
            ),
            "wrong peer response should be rejected before ack state changes"
        );
        assert_eq!(runtime.in_flight_request_count(), 1);
        assert_eq!(runtime.tracked_request_count(), 1);
        assert_eq!(runtime.peer_in_flight_count("peer-a"), 1);
    }

    #[test]
    fn timeout_retry_feedback_enforces_backoff_before_retry_activation() {
        let mut runtime = coordinator(1);
        let (request, response) = sample_request_and_response(33);

        let scheduled = runtime.schedule_outbound_request("peer-r", 4, request, 3_000);
        assert!(scheduled.is_ok(), "initial request should schedule");

        let feedback = runtime.poll_timeout_feedback(3_100);
        assert!(feedback.is_ok(), "timeout feedback should process");
        let feedback = feedback.unwrap_or_else(|_| unreachable!());
        assert_eq!(feedback.retries.len(), 1);
        assert_eq!(feedback.exhausted.len(), 0);
        assert_eq!(feedback.retries[0].attempt, 2);
        assert_eq!(feedback.retries[0].retry_at_ms, 3_200);

        let early_activation = runtime.activate_retry_dispatch(33, 3_150);
        assert!(
            matches!(
                early_activation,
                Ok(RetryDispatchActivation::Deferred { retry_at_ms: 3_200 })
            ),
            "retry activation should defer until deterministic backoff expires"
        );

        let ready_activation = runtime.activate_retry_dispatch(33, 3_200);
        assert!(
            matches!(
                ready_activation,
                Ok(RetryDispatchActivation::Ready { attempt: 2, .. })
            ),
            "retry activation should become ready once backoff has elapsed"
        );

        let accepted = runtime.handle_inbound_chunk_response("peer-r", response);
        assert!(accepted.is_ok(), "retry response should be accepted");
        assert_eq!(runtime.in_flight_request_count(), 0);
        assert_eq!(runtime.tracked_request_count(), 0);
    }

    #[test]
    fn exhausted_timeout_untracks_request_and_applies_reschedule_backoff() {
        let mut runtime = coordinator(0);
        let (request, _response) = sample_request_and_response(44);

        let scheduled = runtime.schedule_outbound_request("peer-x", 6, request, 4_000);
        assert!(scheduled.is_ok(), "initial request should schedule");

        let feedback = runtime.poll_timeout_feedback(4_100);
        assert!(feedback.is_ok(), "timeout feedback should process");
        let feedback = feedback.unwrap_or_else(|_| unreachable!());
        assert_eq!(feedback.retries.len(), 0);
        assert_eq!(feedback.exhausted.len(), 1);
        assert_eq!(feedback.exhausted[0].attempts, 1);
        assert_eq!(feedback.exhausted[0].retry_at_ms, 4_200);
        assert_eq!(runtime.in_flight_request_count(), 0);
        assert_eq!(runtime.tracked_request_count(), 0);

        let deferred_reschedule = runtime.schedule_outbound_request("peer-x", 6, request, 4_150);
        assert!(
            matches!(
                deferred_reschedule,
                Ok(OutboundRequestScheduleOutcome::Deferred {
                    request_id: 44,
                    retry_at_ms: 4_200
                })
            ),
            "exhausted request should still respect session backoff before reschedule"
        );

        let scheduled_again = runtime.schedule_outbound_request("peer-x", 6, request, 4_200);
        assert!(
            matches!(
                scheduled_again,
                Ok(OutboundRequestScheduleOutcome::Scheduled { request_id: 44 })
            ),
            "request should be schedulable once backoff expires"
        );
    }

    #[test]
    fn assembled_stream_emits_completed_snapshot_on_last_chunk() {
        let snapshot = assembly_snapshot();
        let chunks = split_snapshot_into_chunks(&snapshot, 32);
        assert!(chunks.is_ok(), "snapshot should split into chunks");
        let chunks = chunks.unwrap_or_else(|_| unreachable!());
        assert!(
            chunks.len() > 1,
            "assembly snapshot fixture should produce multiple chunks"
        );

        let runtime = SyncRuntimeCoordinator::with_assembly_policy(
            RequestSchedulerPolicy {
                request_timeout_ms: 100,
                max_retries: 1,
                max_in_flight: 64,
            },
            ChunkSessionPolicy {
                max_in_flight_per_session: 64,
                max_in_flight_per_peer: 128,
                base_retry_backoff_ms: 100,
                max_retry_backoff_ms: 1_000,
            },
            32,
            SnapshotAdmissionPolicy::default(),
        );
        assert!(
            runtime.is_ok(),
            "runtime with explicit assembly policy should initialize"
        );
        let mut runtime = runtime.unwrap_or_else(|_| unreachable!());

        let requests = chunks
            .iter()
            .enumerate()
            .map(|(index, chunk)| SnapshotChunkRequest {
                request_id: u64::try_from(index).unwrap_or(u64::MAX) + 1_000,
                block_height: chunk.block_height,
                state_root: chunk.state_root,
                snapshot_hash: chunk.snapshot_hash,
                chunk_index: chunk.chunk_index,
                total_chunks: chunk.total_chunks,
            })
            .collect::<Vec<_>>();
        let responses = requests
            .iter()
            .zip(chunks.iter())
            .map(|(request, chunk)| SnapshotChunkResponse {
                request_id: request.request_id,
                chunk: chunk.clone(),
            })
            .collect::<Vec<_>>();

        for request in &requests {
            let scheduled = runtime.schedule_outbound_request("peer-asm", 21, *request, 9_000);
            assert!(scheduled.is_ok(), "all requests should schedule");
        }

        for response in responses.into_iter().rev() {
            let accepted = runtime.handle_inbound_chunk_response("peer-asm", response);
            assert!(accepted.is_ok(), "chunk response should be accepted");
            let accepted = accepted.unwrap_or_else(|_| unreachable!());
            assert!(
                matches!(
                    accepted.assembly,
                    AssemblyIngestOutcome::InProgress { .. }
                        | AssemblyIngestOutcome::Complete { .. }
                ),
                "assembly outcome should be emitted for each accepted response"
            );
        }

        assert_eq!(runtime.in_flight_request_count(), 0);
        assert_eq!(runtime.tracked_request_count(), 0);
        assert_eq!(
            runtime.completed_snapshot_count(),
            1,
            "final chunk should complete exactly one assembled snapshot"
        );
        assert_eq!(
            runtime.active_assembly_stream_count(),
            0,
            "completed stream should be removed from active assembler map"
        );

        let completed = runtime.drain_completed_snapshots();
        assert_eq!(completed.len(), 1);
        assert_eq!(completed[0].snapshot, snapshot);
        assert_eq!(runtime.completed_snapshot_count(), 0);
    }

    #[test]
    fn tampered_chunk_response_is_rejected_without_ack() {
        let mut runtime = coordinator(1);
        let (request, response) = sample_request_and_response(77);

        let scheduled = runtime.schedule_outbound_request("peer-tmp", 8, request, 13_000);
        assert!(
            scheduled.is_ok(),
            "request should schedule before tampered response"
        );

        let mut tampered = response;
        if let Some(first) = tampered.chunk.payload_hash.first_mut() {
            *first ^= 0x01;
        }

        let handled = runtime.handle_inbound_chunk_response("peer-tmp", tampered);
        assert!(
            matches!(
                handled,
                Err(SyncRuntimeError::SnapshotAssembly {
                    source: SyncError::SnapshotChunkHashMismatch { index: _ }
                })
            ),
            "tampered chunk payload hash should fail assembly validation"
        );
        assert_eq!(
            runtime.in_flight_request_count(),
            1,
            "invalid chunk should not ack scheduler request state"
        );
        assert_eq!(
            runtime.tracked_request_count(),
            1,
            "invalid chunk should keep request-session tracking for retries"
        );
        assert_eq!(
            runtime.peer_in_flight_count("peer-tmp"),
            1,
            "invalid chunk should keep session in-flight state for timeout/loss feedback"
        );
    }

    #[test]
    fn import_next_completed_snapshot_applies_state_with_bootstrap_mode() {
        let network = Network::Testnet;
        let mut source_state = ChainState::new(network);
        let initialized = source_state.initialize_genesis(vec![
            (valid_address(network), 700),
            (valid_address(network), 900),
        ]);
        assert!(
            initialized.is_ok(),
            "source state genesis fixture should initialize"
        );
        let snapshot = build_state_snapshot(&source_state, 33);
        let mut runtime = runtime_with_completed_snapshot(&snapshot);
        let finalized_block = finalized_block_for_snapshot(&snapshot, valid_address(network));

        let mut target_state = ChainState::new(network);
        let imported = runtime.import_next_completed_snapshot(
            &mut target_state,
            &finalized_block,
            SnapshotImportMode::BootstrapRecovery,
        );
        assert!(
            imported.is_ok(),
            "completed snapshot should import successfully"
        );
        assert!(
            imported.unwrap_or_else(|_| unreachable!()).is_some(),
            "import should consume one queued completed snapshot"
        );
        assert_eq!(
            target_state.account_entries(),
            source_state.account_entries(),
            "imported state must match assembled snapshot payload"
        );
        assert_eq!(
            runtime.completed_snapshot_count(),
            0,
            "successful import should pop completed snapshot queue"
        );
    }

    #[test]
    fn steady_state_rollback_rejection_keeps_completed_snapshot_queued() {
        let network = Network::Testnet;
        let mut source_state = ChainState::new(network);
        let initialized = source_state.initialize_genesis(vec![(valid_address(network), 1_500)]);
        assert!(initialized.is_ok(), "source fixture should initialize");
        let snapshot = build_state_snapshot(&source_state, 40);
        let mut runtime = runtime_with_completed_snapshot(&snapshot);
        let finalized_block = finalized_block_for_snapshot(&snapshot, valid_address(network));

        let mut target_state = ChainState::new(network);
        let imported = runtime.import_next_completed_snapshot(
            &mut target_state,
            &finalized_block,
            SnapshotImportMode::SteadyState {
                local_finalized_height: 41,
            },
        );
        assert!(
            matches!(
                imported,
                Err(SyncRuntimeError::SnapshotImport {
                    block_height: 40,
                    state_root: _,
                    failure_count: 1,
                    source: SyncError::SnapshotRollbackRejected {
                        local_finalized_height: 41,
                        snapshot_height: 40
                    }
                })
            ),
            "steady-state rollback protection should reject older completed snapshot"
        );
        assert_eq!(
            runtime.completed_snapshot_count(),
            1,
            "failed import should keep completed snapshot queued for explicit operator handling"
        );
    }

    #[test]
    fn repeated_failed_imports_are_quarantined_and_removed_from_completed_queue() {
        let network = Network::Testnet;
        let mut source_state = ChainState::new(network);
        let initialized = source_state.initialize_genesis(vec![(valid_address(network), 1_500)]);
        assert!(initialized.is_ok(), "source fixture should initialize");
        let snapshot = build_state_snapshot(&source_state, 40);
        let mut runtime = runtime_with_import_failure_policy(SnapshotImportFailurePolicy {
            max_consecutive_failures: 2,
        });
        let mut seeded_runtime = runtime_with_completed_snapshot(&snapshot);
        runtime
            .completed_snapshots
            .append(&mut seeded_runtime.completed_snapshots);
        let finalized_block = finalized_block_for_snapshot(&snapshot, valid_address(network));

        let mut target_state = ChainState::new(network);
        let first_attempt = runtime.import_next_completed_snapshot(
            &mut target_state,
            &finalized_block,
            SnapshotImportMode::SteadyState {
                local_finalized_height: 41,
            },
        );
        assert!(
            matches!(
                first_attempt,
                Err(SyncRuntimeError::SnapshotImport {
                    block_height: 40,
                    state_root: _,
                    failure_count: 1,
                    source: SyncError::SnapshotRollbackRejected { .. }
                })
            ),
            "first failed import should remain on completed queue"
        );
        assert_eq!(runtime.completed_snapshot_count(), 1);
        assert_eq!(runtime.quarantined_snapshot_count(), 0);

        let second_attempt = runtime.import_next_completed_snapshot(
            &mut target_state,
            &finalized_block,
            SnapshotImportMode::SteadyState {
                local_finalized_height: 41,
            },
        );
        assert!(
            matches!(
                second_attempt,
                Err(SyncRuntimeError::SnapshotImportQuarantined {
                    block_height: 40,
                    state_root: _,
                    failure_count: 2,
                    source: SyncError::SnapshotRollbackRejected {
                        local_finalized_height: 41,
                        snapshot_height: 40
                    }
                })
            ),
            "second consecutive failure should quarantine and remove the bad queue head"
        );
        assert_eq!(runtime.completed_snapshot_count(), 0);
        assert_eq!(runtime.quarantined_snapshot_count(), 1);

        let quarantined = runtime.drain_quarantined_snapshots();
        assert_eq!(quarantined.len(), 1);
        assert_eq!(quarantined[0].snapshot.block_height, 40);
        assert_eq!(quarantined[0].failed_import_attempts, 2);
        assert!(
            matches!(
                quarantined[0].last_error,
                SyncError::SnapshotRollbackRejected {
                    local_finalized_height: 41,
                    snapshot_height: 40
                }
            ),
            "quarantine record should preserve last typed import error"
        );
    }

    #[test]
    fn quarantining_bad_queue_head_unblocks_next_completed_snapshot_import() {
        let network = Network::Testnet;

        let mut old_state = ChainState::new(network);
        let old_initialized = old_state.initialize_genesis(vec![(valid_address(network), 150)]);
        assert!(
            old_initialized.is_ok(),
            "old snapshot fixture should initialize"
        );
        let old_snapshot = build_state_snapshot(&old_state, 40);

        let mut next_state = ChainState::new(network);
        let next_initialized = next_state.initialize_genesis(vec![(valid_address(network), 250)]);
        assert!(
            next_initialized.is_ok(),
            "next snapshot fixture should initialize"
        );
        let next_snapshot = build_state_snapshot(&next_state, 60);

        let mut runtime = runtime_with_import_failure_policy(SnapshotImportFailurePolicy {
            max_consecutive_failures: 1,
        });
        let mut old_runtime = runtime_with_completed_snapshot(&old_snapshot);
        let mut next_runtime = runtime_with_completed_snapshot(&next_snapshot);
        runtime
            .completed_snapshots
            .append(&mut old_runtime.completed_snapshots);
        runtime
            .completed_snapshots
            .append(&mut next_runtime.completed_snapshots);
        assert_eq!(
            runtime.completed_snapshot_count(),
            2,
            "fixture should queue bad head + valid follower snapshots"
        );

        let old_finalized = finalized_block_for_snapshot(&old_snapshot, valid_address(network));
        let mut target_state = ChainState::new(network);
        let first_attempt = runtime.import_next_completed_snapshot(
            &mut target_state,
            &old_finalized,
            SnapshotImportMode::SteadyState {
                local_finalized_height: 41,
            },
        );
        assert!(
            matches!(
                first_attempt,
                Err(SyncRuntimeError::SnapshotImportQuarantined {
                    block_height: 40,
                    state_root: _,
                    failure_count: 1,
                    source: SyncError::SnapshotRollbackRejected { .. }
                })
            ),
            "bad queue head should quarantine immediately under one-failure policy"
        );
        assert_eq!(
            runtime.completed_snapshot_count(),
            1,
            "quarantining should expose next queued completed snapshot"
        );

        let next_finalized = finalized_block_for_snapshot(&next_snapshot, valid_address(network));
        let second_attempt = runtime.import_next_completed_snapshot(
            &mut target_state,
            &next_finalized,
            SnapshotImportMode::BootstrapRecovery,
        );
        assert!(
            matches!(second_attempt, Ok(Some(_))),
            "next queued snapshot should import after bad head quarantine"
        );
        assert_eq!(
            target_state.account_entries(),
            next_state.account_entries(),
            "imported state should match second queued snapshot payload"
        );
        assert_eq!(runtime.completed_snapshot_count(), 0);
        assert_eq!(runtime.quarantined_snapshot_count(), 1);
    }

    #[test]
    fn import_batch_continues_after_quarantine_and_records_observability() {
        let network = Network::Testnet;

        let mut old_state = ChainState::new(network);
        let old_initialized = old_state.initialize_genesis(vec![(valid_address(network), 150)]);
        assert!(
            old_initialized.is_ok(),
            "old snapshot fixture should initialize"
        );
        let old_snapshot = build_state_snapshot(&old_state, 60);

        let mut next_state = ChainState::new(network);
        let next_initialized = next_state.initialize_genesis(vec![(valid_address(network), 250)]);
        assert!(
            next_initialized.is_ok(),
            "next snapshot fixture should initialize"
        );
        let next_snapshot = build_state_snapshot(&next_state, 60);

        let mut runtime = runtime_with_import_failure_policy(SnapshotImportFailurePolicy {
            max_consecutive_failures: 1,
        });
        let mut old_runtime = runtime_with_completed_snapshot(&old_snapshot);
        let mut next_runtime = runtime_with_completed_snapshot(&next_snapshot);
        runtime
            .completed_snapshots
            .append(&mut old_runtime.completed_snapshots);
        runtime
            .completed_snapshots
            .append(&mut next_runtime.completed_snapshots);

        let observability = Observability::new(8);
        let finalized_block = finalized_block_for_snapshot(&next_snapshot, valid_address(network));
        let mut target_state = ChainState::new(network);
        let outcome = runtime.import_completed_snapshot_batch(
            &mut target_state,
            &finalized_block,
            SnapshotImportMode::BootstrapRecovery,
            Some(&observability),
        );

        assert!(
            outcome.blocked.is_none(),
            "batch import should continue after quarantine and not remain blocked"
        );
        assert_eq!(outcome.quarantined.len(), 1);
        assert_eq!(outcome.quarantined[0].snapshot.block_height, 60);
        assert_eq!(outcome.imported.len(), 1);
        assert_eq!(outcome.imported[0].block_height, 60);
        assert_eq!(runtime.completed_snapshot_count(), 0);
        assert_eq!(runtime.quarantined_snapshot_count(), 1);
        assert_eq!(
            target_state.account_entries(),
            next_state.account_entries(),
            "batch import should advance to follower snapshot after quarantine"
        );

        assert_eq!(observability.snapshot_import_success_total(), 1);
        assert_eq!(observability.snapshot_import_failure_total(), 0);
        assert_eq!(observability.snapshot_quarantine_total(), 1);
        let snapshot = observability.snapshot();
        assert_eq!(snapshot.recent_events.len(), 2);
        assert!(matches!(
            snapshot.recent_events[0].kind,
            ObservabilityEventKind::SnapshotImport {
                outcome: SnapshotImportOutcome::Quarantined,
                ..
            }
        ));
        assert!(matches!(
            snapshot.recent_events[1].kind,
            ObservabilityEventKind::SnapshotImport {
                outcome: SnapshotImportOutcome::Success,
                ..
            }
        ));
    }

    #[test]
    fn import_batch_stops_on_retryable_failure_and_records_observability() {
        let network = Network::Testnet;
        let mut bad_state = ChainState::new(network);
        let bad_initialized = bad_state.initialize_genesis(vec![(valid_address(network), 1_500)]);
        assert!(
            bad_initialized.is_ok(),
            "bad snapshot fixture should initialize"
        );
        let bad_snapshot = build_state_snapshot(&bad_state, 40);

        let mut finalized_state = ChainState::new(network);
        let finalized_initialized =
            finalized_state.initialize_genesis(vec![(valid_address(network), 2_500)]);
        assert!(
            finalized_initialized.is_ok(),
            "finalized block fixture should initialize"
        );
        let finalized_snapshot = build_state_snapshot(&finalized_state, 40);

        let mut runtime = runtime_with_import_failure_policy(SnapshotImportFailurePolicy {
            max_consecutive_failures: 2,
        });
        let mut seeded_runtime = runtime_with_completed_snapshot(&bad_snapshot);
        runtime
            .completed_snapshots
            .append(&mut seeded_runtime.completed_snapshots);

        let observability = Observability::new(8);
        let finalized_block =
            finalized_block_for_snapshot(&finalized_snapshot, valid_address(network));
        let mut target_state = ChainState::new(network);
        let outcome = runtime.import_completed_snapshot_batch(
            &mut target_state,
            &finalized_block,
            SnapshotImportMode::BootstrapRecovery,
            Some(&observability),
        );

        assert_eq!(outcome.imported.len(), 0);
        assert_eq!(outcome.quarantined.len(), 0);
        assert!(
            matches!(
                outcome.blocked,
                Some(SyncRuntimeError::SnapshotImport {
                    block_height: 40,
                    state_root: _,
                    failure_count: 1,
                    source: SyncError::StateRootMismatch { .. }
                })
            ),
            "batch import should stop at first retryable queue-head failure"
        );
        assert_eq!(runtime.completed_snapshot_count(), 1);
        assert_eq!(runtime.quarantined_snapshot_count(), 0);

        assert_eq!(observability.snapshot_import_success_total(), 0);
        assert_eq!(observability.snapshot_import_failure_total(), 1);
        assert_eq!(observability.snapshot_quarantine_total(), 0);
        let snapshot = observability.snapshot();
        assert_eq!(snapshot.recent_events.len(), 1);
        assert!(matches!(
            snapshot.recent_events[0].kind,
            ObservabilityEventKind::SnapshotImport {
                outcome: SnapshotImportOutcome::Failed,
                failure_count: 1,
                ..
            }
        ));
    }

    #[test]
    fn checkpoint_verified_import_succeeds_and_drains_queue() {
        let network = Network::Testnet;
        let mut source_state = ChainState::new(network);
        let initialized = source_state.initialize_genesis(vec![
            (valid_address(network), 500),
            (valid_address(network), 250),
        ]);
        assert!(initialized.is_ok(), "source fixture should initialize");
        let snapshot = build_state_snapshot(&source_state, 51);
        let mut runtime = runtime_with_completed_snapshot(&snapshot);
        let finalized_block = finalized_block_for_snapshot(&snapshot, valid_address(network));

        let validator_key = Keypair::generate();
        let validator_address = derive_address(&validator_key.public_key_bytes(), network);
        assert!(
            validator_address.is_ok(),
            "validator address derivation should succeed"
        );
        let validator_address = validator_address.unwrap_or_else(|_| unreachable!());

        let signature = sign_snapshot_checkpoint(
            &snapshot,
            network,
            validator_address.clone(),
            &validator_key,
        );
        assert!(signature.is_ok(), "checkpoint signing should succeed");
        let mut checkpoint = SnapshotCheckpoint::new(&snapshot, network);
        checkpoint
            .signatures
            .push(signature.unwrap_or_else(|_| unreachable!()));

        let trusted_validators = vec![validator_address];
        let mut target_state = ChainState::new(network);
        let imported = runtime.import_next_completed_snapshot_with_checkpoint(
            &mut target_state,
            &finalized_block,
            &checkpoint,
            CheckpointVerificationPolicy {
                network,
                min_signatures: 1,
                trusted_validators: &trusted_validators,
            },
            SnapshotImportMode::BootstrapRecovery,
        );
        assert!(
            matches!(imported, Ok(Some(_))),
            "checkpoint-verified import should succeed"
        );
        assert_eq!(
            target_state.account_entries(),
            source_state.account_entries(),
            "checkpoint-verified import should load snapshot entries"
        );
        assert_eq!(
            runtime.completed_snapshot_count(),
            0,
            "checkpoint import should drain one completed snapshot"
        );
    }

    #[test]
    fn import_returns_none_when_no_completed_snapshot_is_queued() {
        let network = Network::Testnet;
        let mut runtime = runtime_with_large_assembly();
        let snapshot = assembly_snapshot();
        let finalized_block = finalized_block_for_snapshot(&snapshot, valid_address(network));
        let mut target_state = ChainState::new(network);

        let imported = runtime.import_next_completed_snapshot(
            &mut target_state,
            &finalized_block,
            SnapshotImportMode::BootstrapRecovery,
        );
        assert!(
            matches!(imported, Ok(None)),
            "empty completion queue should return None without side effects"
        );
    }

    #[test]
    fn rejects_invalid_assembly_policy_configuration() {
        let runtime = SyncRuntimeCoordinator::with_assembly_policy(
            RequestSchedulerPolicy::default(),
            ChunkSessionPolicy::default(),
            0,
            SnapshotAdmissionPolicy::default(),
        );
        assert!(
            matches!(
                runtime,
                Err(SyncRuntimeError::InvalidAssemblyPolicy {
                    max_chunk_bytes: 0,
                    max_snapshot_bytes: _,
                    max_accounts: _
                })
            ),
            "runtime should reject zero chunk-byte assembly policy"
        );
    }

    #[test]
    fn rejects_invalid_import_failure_policy_configuration() {
        let runtime = SyncRuntimeCoordinator::with_assembly_and_import_policy(
            RequestSchedulerPolicy::default(),
            ChunkSessionPolicy::default(),
            32,
            SnapshotAdmissionPolicy::default(),
            SnapshotImportFailurePolicy {
                max_consecutive_failures: 0,
            },
        );
        assert!(
            matches!(
                runtime,
                Err(SyncRuntimeError::InvalidImportFailurePolicy {
                    max_consecutive_failures: 0
                })
            ),
            "runtime should reject zero max-consecutive import failure policy"
        );
    }
}
