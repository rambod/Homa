//! Structured observability metrics and events.

use std::collections::VecDeque;
use std::sync::Mutex;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{SystemTime, UNIX_EPOCH};

use serde::{Deserialize, Serialize};

/// Default bounded in-memory event history capacity.
pub const DEFAULT_EVENT_CAPACITY: usize = 1_024;

/// Thread-safe metrics and event collector for node runtime observability.
#[derive(Debug)]
pub struct Observability {
    slot_miss_total: AtomicU64,
    gossip_failure_total: AtomicU64,
    sync_lag_blocks: AtomicU64,
    snapshot_import_success_total: AtomicU64,
    snapshot_import_failure_total: AtomicU64,
    snapshot_quarantine_total: AtomicU64,
    event_capacity: usize,
    recent_events: Mutex<VecDeque<ObservabilityEvent>>,
}

impl Default for Observability {
    fn default() -> Self {
        Self::new(DEFAULT_EVENT_CAPACITY)
    }
}

/// Snapshot view of metrics plus bounded event history.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ObservabilitySnapshot {
    /// Total number of consensus slot misses observed.
    pub slot_miss_total: u64,
    /// Total number of gossip propagation failures observed.
    pub gossip_failure_total: u64,
    /// Current sync lag gauge in blocks.
    pub sync_lag_blocks: u64,
    /// Total number of successful snapshot imports.
    pub snapshot_import_success_total: u64,
    /// Total number of failed snapshot import attempts.
    pub snapshot_import_failure_total: u64,
    /// Total number of snapshot quarantine actions.
    pub snapshot_quarantine_total: u64,
    /// Most recent structured events.
    pub recent_events: Vec<ObservabilityEvent>,
}

/// One structured observability event.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ObservabilityEvent {
    /// Event emission timestamp in unix milliseconds.
    pub timestamp_unix_ms: u64,
    /// Typed event payload.
    pub kind: ObservabilityEventKind,
}

/// Typed event payload variants.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum ObservabilityEventKind {
    /// Consensus expected leader did not produce (or wrong proposer produced).
    ConsensusSlotMiss {
        /// Slot index.
        slot: u64,
        /// Expected leader address.
        expected_leader: String,
        /// Optional observed proposer address.
        observed_proposer: Option<String>,
        /// Miss classification.
        reason: SlotMissReason,
    },
    /// Gossip dial/publish/bootstrap propagation failure.
    GossipFailure {
        /// Affected gossip topic.
        topic: String,
        /// Operation phase that failed.
        operation: GossipOperation,
        /// Optional peer id involved in failure.
        peer_id: Option<String>,
        /// Error context.
        error: String,
    },
    /// Sync lag gauge update.
    SyncLag {
        /// Local node height.
        local_height: u64,
        /// Finalized/target network height.
        finalized_height: u64,
        /// Derived lag in blocks.
        lag_blocks: u64,
    },
    /// Snapshot import attempt outcome.
    SnapshotImport {
        /// Snapshot block height being imported.
        block_height: u64,
        /// Snapshot state root being imported.
        state_root: [u8; 32],
        /// Import outcome class.
        outcome: SnapshotImportOutcome,
        /// Consecutive failure attempts for this queue-head snapshot.
        failure_count: u32,
        /// Optional typed error context.
        error: Option<String>,
    },
}

/// Slot-miss reason classes.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SlotMissReason {
    /// Expected leader produced no block for the slot.
    LeaderDidNotProduce,
    /// A block arrived but from an unexpected proposer.
    UnexpectedProposer,
    /// Slot missed due to network propagation delay.
    NetworkDelay,
}

/// Gossip operation phases that can fail.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum GossipOperation {
    /// Seed/bootstrap discovery failure.
    Bootstrap,
    /// Dialing one or more peers failed.
    Dial,
    /// Publishing a gossip payload failed.
    Publish,
}

/// Snapshot import outcome classes.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SnapshotImportOutcome {
    /// Snapshot import succeeded and was applied to state.
    Success,
    /// Snapshot import failed but remains queued for retry.
    Failed,
    /// Snapshot import failed and was quarantined.
    Quarantined,
}

impl Observability {
    /// Creates a new collector with bounded event history.
    #[must_use]
    pub fn new(event_capacity: usize) -> Self {
        let bounded_capacity = event_capacity.max(1);
        Self {
            slot_miss_total: AtomicU64::new(0),
            gossip_failure_total: AtomicU64::new(0),
            sync_lag_blocks: AtomicU64::new(0),
            snapshot_import_success_total: AtomicU64::new(0),
            snapshot_import_failure_total: AtomicU64::new(0),
            snapshot_quarantine_total: AtomicU64::new(0),
            event_capacity: bounded_capacity,
            recent_events: Mutex::new(VecDeque::with_capacity(bounded_capacity)),
        }
    }

    /// Records one consensus slot miss.
    pub fn record_slot_miss(
        &self,
        slot: u64,
        expected_leader: &str,
        observed_proposer: Option<&str>,
        reason: SlotMissReason,
    ) {
        self.slot_miss_total.fetch_add(1, Ordering::Relaxed);
        self.push_event(ObservabilityEventKind::ConsensusSlotMiss {
            slot,
            expected_leader: expected_leader.to_owned(),
            observed_proposer: observed_proposer.map(str::to_owned),
            reason,
        });
    }

    /// Records one gossip propagation failure.
    pub fn record_gossip_failure(
        &self,
        topic: &str,
        operation: GossipOperation,
        peer_id: Option<&str>,
        error: &str,
    ) {
        self.gossip_failure_total.fetch_add(1, Ordering::Relaxed);
        self.push_event(ObservabilityEventKind::GossipFailure {
            topic: topic.to_owned(),
            operation,
            peer_id: peer_id.map(str::to_owned),
            error: error.to_owned(),
        });
    }

    /// Updates sync lag gauge and emits a structured sync-lag event.
    pub fn record_sync_lag(&self, local_height: u64, finalized_height: u64) {
        let lag_blocks = finalized_height.saturating_sub(local_height);
        self.sync_lag_blocks.store(lag_blocks, Ordering::Relaxed);
        self.push_event(ObservabilityEventKind::SyncLag {
            local_height,
            finalized_height,
            lag_blocks,
        });
    }

    /// Records one successful snapshot import application.
    pub fn record_snapshot_import_success(&self, block_height: u64, state_root: [u8; 32]) {
        self.snapshot_import_success_total
            .fetch_add(1, Ordering::Relaxed);
        self.push_event(ObservabilityEventKind::SnapshotImport {
            block_height,
            state_root,
            outcome: SnapshotImportOutcome::Success,
            failure_count: 0,
            error: None,
        });
    }

    /// Records one failed snapshot import attempt that remains queued.
    pub fn record_snapshot_import_failure(
        &self,
        block_height: u64,
        state_root: [u8; 32],
        failure_count: u32,
        error: &str,
    ) {
        self.snapshot_import_failure_total
            .fetch_add(1, Ordering::Relaxed);
        self.push_event(ObservabilityEventKind::SnapshotImport {
            block_height,
            state_root,
            outcome: SnapshotImportOutcome::Failed,
            failure_count,
            error: Some(error.to_owned()),
        });
    }

    /// Records one snapshot quarantine action after repeated import failures.
    pub fn record_snapshot_quarantine(
        &self,
        block_height: u64,
        state_root: [u8; 32],
        failure_count: u32,
        error: &str,
    ) {
        self.snapshot_quarantine_total
            .fetch_add(1, Ordering::Relaxed);
        self.push_event(ObservabilityEventKind::SnapshotImport {
            block_height,
            state_root,
            outcome: SnapshotImportOutcome::Quarantined,
            failure_count,
            error: Some(error.to_owned()),
        });
    }

    /// Returns total slot misses.
    #[must_use]
    pub fn slot_miss_total(&self) -> u64 {
        self.slot_miss_total.load(Ordering::Relaxed)
    }

    /// Returns total gossip failures.
    #[must_use]
    pub fn gossip_failure_total(&self) -> u64 {
        self.gossip_failure_total.load(Ordering::Relaxed)
    }

    /// Returns current sync-lag gauge.
    #[must_use]
    pub fn sync_lag_blocks(&self) -> u64 {
        self.sync_lag_blocks.load(Ordering::Relaxed)
    }

    /// Returns total successful snapshot imports.
    #[must_use]
    pub fn snapshot_import_success_total(&self) -> u64 {
        self.snapshot_import_success_total.load(Ordering::Relaxed)
    }

    /// Returns total failed snapshot import attempts.
    #[must_use]
    pub fn snapshot_import_failure_total(&self) -> u64 {
        self.snapshot_import_failure_total.load(Ordering::Relaxed)
    }

    /// Returns total snapshot quarantines.
    #[must_use]
    pub fn snapshot_quarantine_total(&self) -> u64 {
        self.snapshot_quarantine_total.load(Ordering::Relaxed)
    }

    /// Returns an immutable snapshot of metrics and bounded recent events.
    #[must_use]
    pub fn snapshot(&self) -> ObservabilitySnapshot {
        let recent_events = self.recent_events.lock().map_or_else(
            |_| Vec::new(),
            |guard| guard.iter().cloned().collect::<Vec<_>>(),
        );

        ObservabilitySnapshot {
            slot_miss_total: self.slot_miss_total(),
            gossip_failure_total: self.gossip_failure_total(),
            sync_lag_blocks: self.sync_lag_blocks(),
            snapshot_import_success_total: self.snapshot_import_success_total(),
            snapshot_import_failure_total: self.snapshot_import_failure_total(),
            snapshot_quarantine_total: self.snapshot_quarantine_total(),
            recent_events,
        }
    }

    fn push_event(&self, kind: ObservabilityEventKind) {
        if let Ok(mut guard) = self.recent_events.lock() {
            guard.push_back(ObservabilityEvent {
                timestamp_unix_ms: now_unix_ms(),
                kind,
            });
            while guard.len() > self.event_capacity {
                let _ = guard.pop_front();
            }
        }
    }
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
        GossipOperation, Observability, ObservabilityEventKind, SlotMissReason,
        SnapshotImportOutcome,
    };

    #[test]
    fn records_slot_miss_metrics_and_event() {
        let observability = Observability::new(8);
        observability.record_slot_miss(
            42,
            "HMA_EXPECTED",
            Some("HMA_OTHER"),
            SlotMissReason::UnexpectedProposer,
        );

        assert_eq!(observability.slot_miss_total(), 1);
        let snapshot = observability.snapshot();
        assert_eq!(snapshot.recent_events.len(), 1);
        assert!(matches!(
            snapshot.recent_events[0].kind,
            ObservabilityEventKind::ConsensusSlotMiss {
                slot: 42,
                reason: SlotMissReason::UnexpectedProposer,
                ..
            }
        ));
    }

    #[test]
    fn records_gossip_failure_metrics_and_event() {
        let observability = Observability::new(8);
        observability.record_gossip_failure(
            "transactions",
            GossipOperation::Publish,
            Some("peer-a"),
            "timeout",
        );

        assert_eq!(observability.gossip_failure_total(), 1);
        let snapshot = observability.snapshot();
        assert_eq!(snapshot.recent_events.len(), 1);
        assert!(matches!(
            snapshot.recent_events[0].kind,
            ObservabilityEventKind::GossipFailure {
                operation: GossipOperation::Publish,
                ..
            }
        ));
    }

    #[test]
    fn updates_sync_lag_gauge_and_event() {
        let observability = Observability::new(8);
        observability.record_sync_lag(90, 100);
        assert_eq!(observability.sync_lag_blocks(), 10);

        let snapshot = observability.snapshot();
        assert!(matches!(
            snapshot.recent_events[0].kind,
            ObservabilityEventKind::SyncLag { lag_blocks: 10, .. }
        ));
    }

    #[test]
    fn event_history_is_bounded() {
        let observability = Observability::new(2);
        observability.record_sync_lag(1, 1);
        observability.record_sync_lag(1, 2);
        observability.record_sync_lag(1, 3);

        let snapshot = observability.snapshot();
        assert_eq!(snapshot.recent_events.len(), 2);
        assert!(matches!(
            snapshot.recent_events[0].kind,
            ObservabilityEventKind::SyncLag { lag_blocks: 1, .. }
        ));
        assert!(matches!(
            snapshot.recent_events[1].kind,
            ObservabilityEventKind::SyncLag { lag_blocks: 2, .. }
        ));
    }

    #[test]
    fn records_snapshot_import_lifecycle_metrics_and_events() {
        let observability = Observability::new(8);
        let root = [9_u8; 32];

        observability.record_snapshot_import_success(44, root);
        observability.record_snapshot_import_failure(44, root, 1, "rollback rejected");
        observability.record_snapshot_quarantine(44, root, 3, "rollback rejected");

        assert_eq!(observability.snapshot_import_success_total(), 1);
        assert_eq!(observability.snapshot_import_failure_total(), 1);
        assert_eq!(observability.snapshot_quarantine_total(), 1);

        let snapshot = observability.snapshot();
        assert_eq!(snapshot.snapshot_import_success_total, 1);
        assert_eq!(snapshot.snapshot_import_failure_total, 1);
        assert_eq!(snapshot.snapshot_quarantine_total, 1);
        assert_eq!(snapshot.recent_events.len(), 3);
        assert!(matches!(
            snapshot.recent_events[0].kind,
            ObservabilityEventKind::SnapshotImport {
                outcome: SnapshotImportOutcome::Success,
                failure_count: 0,
                ..
            }
        ));
        assert!(matches!(
            snapshot.recent_events[1].kind,
            ObservabilityEventKind::SnapshotImport {
                outcome: SnapshotImportOutcome::Failed,
                failure_count: 1,
                ..
            }
        ));
        assert!(matches!(
            snapshot.recent_events[2].kind,
            ObservabilityEventKind::SnapshotImport {
                outcome: SnapshotImportOutcome::Quarantined,
                failure_count: 3,
                ..
            }
        ));
    }
}
