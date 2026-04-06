//! Runtime policy controller wiring reputation, sync serving, and checkpoint trust rotation.

use thiserror::Error;

use crate::core::sync::StateSnapshot;
use crate::crypto::address::Network;
use crate::network::checkpoint_rotation::{
    CheckpointRotationError, CheckpointRotationManager, CheckpointRotationPolicy,
    CheckpointSetRotationUpdate, RotationActivationOutcome, RotationIngestOutcome,
    TrustedCheckpointSet,
};
use crate::network::reputation::{
    AdaptivePenaltyManager, AdaptivePenaltyPolicy, ReputationError, ReputationEvent,
    ReputationPolicy,
};
use crate::network::sync_engine::{
    ChunkServeLimiter, ChunkServePolicy, SnapshotHandshakeAdvertisement, SyncEngineError,
    SyncHandshakeMode, validate_snapshot_handshake,
};

/// Typed runtime-policy failures surfaced while combining sync and reputation controls.
#[derive(Debug, Error)]
pub enum RuntimePolicyError {
    /// Reputation policy or enforcement failed.
    #[error("reputation policy failure")]
    Reputation {
        /// Underlying reputation error.
        source: ReputationError,
    },
    /// Sync-engine quota or handshake validation failed.
    #[error("sync runtime policy failure")]
    SyncEngine {
        /// Underlying sync-engine error.
        source: SyncEngineError,
    },
    /// Checkpoint rotation validation or activation failed.
    #[error("checkpoint trust rotation failure")]
    CheckpointRotation {
        /// Underlying rotation error.
        source: CheckpointRotationError,
    },
    /// Peer is currently banned from serve-side sync handling.
    #[error("peer {peer_id} is temporarily banned from sync serving")]
    ServeDeniedBanned {
        /// Offending peer id.
        peer_id: String,
    },
}

/// Runtime controller that combines reputation penalties with sync and trust policy.
#[derive(Debug, Clone)]
pub struct SyncRuntimePolicyController {
    base_serve_policy: ChunkServePolicy,
    serve_limiter: ChunkServeLimiter,
    penalties: AdaptivePenaltyManager,
    checkpoint_rotation: CheckpointRotationManager,
}

impl SyncRuntimePolicyController {
    /// Creates a runtime policy controller from explicit component policies.
    pub fn new(
        network: Network,
        serve_policy: ChunkServePolicy,
        reputation_policy: ReputationPolicy,
        adaptive_penalty_policy: AdaptivePenaltyPolicy,
        checkpoint_rotation_policy: CheckpointRotationPolicy,
        finalized_height: u64,
        active_trusted_set: TrustedCheckpointSet,
    ) -> Result<Self, RuntimePolicyError> {
        let serve_limiter = ChunkServeLimiter::new(serve_policy)
            .map_err(|source| RuntimePolicyError::SyncEngine { source })?;
        let penalties = AdaptivePenaltyManager::new(reputation_policy, adaptive_penalty_policy)
            .map_err(|source| RuntimePolicyError::Reputation { source })?;
        let checkpoint_rotation = CheckpointRotationManager::new(
            network,
            checkpoint_rotation_policy,
            finalized_height,
            active_trusted_set,
        )
        .map_err(|source| RuntimePolicyError::CheckpointRotation { source })?;

        Ok(Self {
            base_serve_policy: serve_policy,
            serve_limiter,
            penalties,
            checkpoint_rotation,
        })
    }

    /// Records one peer reputation event.
    pub fn record_peer_event(&mut self, peer_id: &str, event: ReputationEvent, now_ms: u64) {
        self.penalties.record_event(peer_id, event, now_ms);
    }

    /// Returns current peer reputation score at `now_ms`.
    #[must_use]
    pub fn peer_score(&self, peer_id: &str, now_ms: u64) -> i32 {
        self.penalties.score(peer_id, now_ms)
    }

    /// Returns whether one peer is currently banned at `now_ms`.
    #[must_use]
    pub fn is_peer_banned(&self, peer_id: &str, now_ms: u64) -> bool {
        self.penalties.is_banned(peer_id, now_ms)
    }

    /// Enforces dial policy for one peer at `now_ms`.
    pub fn enforce_dial_allowed(
        &self,
        peer_id: &str,
        now_ms: u64,
    ) -> Result<(), RuntimePolicyError> {
        self.penalties
            .enforce_dial_allowed(peer_id, now_ms)
            .map_err(|source| RuntimePolicyError::Reputation { source })
    }

    /// Returns effective dynamic per-peer sync serve quota at `now_ms`.
    #[must_use]
    pub fn effective_serve_quota(&self, peer_id: &str, now_ms: u64) -> usize {
        self.penalties
            .effective_serve_quota(peer_id, self.base_serve_policy.per_peer_quota, now_ms)
    }

    /// Admits or rejects one sync serve request from `peer_id` at `now_ms`.
    pub fn admit_chunk_request(
        &mut self,
        peer_id: &str,
        now_ms: u64,
    ) -> Result<(), RuntimePolicyError> {
        if self.penalties.is_banned(peer_id, now_ms) {
            return Err(RuntimePolicyError::ServeDeniedBanned {
                peer_id: peer_id.to_owned(),
            });
        }

        let quota = self.effective_serve_quota(peer_id, now_ms);
        self.serve_limiter
            .admit_with_quota(peer_id, now_ms, quota)
            .map_err(|source| RuntimePolicyError::SyncEngine { source })
    }

    /// Returns strict handshake mode using the currently active trusted checkpoint set.
    #[must_use]
    pub fn sync_handshake_mode(&self) -> SyncHandshakeMode {
        SyncHandshakeMode::RequireCheckpoint {
            checkpoint_policy: self.checkpoint_rotation.active_checkpoint_policy(),
        }
    }

    /// Validates one snapshot handshake under the active trust set.
    pub fn validate_handshake(
        &self,
        snapshot: &StateSnapshot,
        advertisement: &SnapshotHandshakeAdvertisement,
    ) -> Result<(), RuntimePolicyError> {
        let mode = self.sync_handshake_mode();
        validate_snapshot_handshake(snapshot, advertisement, &mode)
            .map_err(|source| RuntimePolicyError::SyncEngine { source })
    }

    /// Ingests one signed checkpoint-trust rotation update.
    pub fn ingest_checkpoint_rotation_update(
        &mut self,
        update: CheckpointSetRotationUpdate,
    ) -> Result<RotationIngestOutcome, RuntimePolicyError> {
        self.checkpoint_rotation
            .ingest_update(update)
            .map_err(|source| RuntimePolicyError::CheckpointRotation { source })
    }

    /// Advances finalized height and activates staged trust-rotation updates when eligible.
    pub fn advance_finalized_height(
        &mut self,
        new_finalized_height: u64,
    ) -> Result<RotationActivationOutcome, RuntimePolicyError> {
        self.checkpoint_rotation
            .advance_finalized_height(new_finalized_height)
            .map_err(|source| RuntimePolicyError::CheckpointRotation { source })
    }

    /// Returns active trusted checkpoint epoch.
    #[must_use]
    pub const fn active_trusted_epoch(&self) -> u64 {
        self.checkpoint_rotation.active_set().epoch
    }
}

#[cfg(test)]
mod tests {
    use super::{RuntimePolicyError, SyncRuntimePolicyController};
    use crate::core::state::AccountState;
    use crate::core::sync::{
        SnapshotAccount, SnapshotCheckpoint, StateSnapshot, sign_snapshot_checkpoint,
    };
    use crate::crypto::address::{Network, derive_address};
    use crate::crypto::keys::Keypair;
    use crate::network::checkpoint_rotation::{
        CheckpointRotationPolicy, CheckpointSetRotationUpdate, RotationActivationOutcome,
        RotationIngestOutcome, TrustedCheckpointSet, sign_checkpoint_set_rotation,
    };
    use crate::network::reputation::{AdaptivePenaltyPolicy, ReputationEvent, ReputationPolicy};
    use crate::network::sync_engine::{
        ChunkServePolicy, SnapshotHandshakeAdvertisement, SyncEngineError,
    };

    fn validator(network: Network) -> (Keypair, String) {
        let keypair = Keypair::generate();
        let address = derive_address(&keypair.public_key_bytes(), network);
        assert!(
            address.is_ok(),
            "validator address derivation should succeed"
        );
        (keypair, address.unwrap_or_else(|_| unreachable!()))
    }

    fn trusted_set(
        network: Network,
        epoch: u64,
        min_signatures: usize,
        mut validators: Vec<String>,
    ) -> TrustedCheckpointSet {
        validators.sort();
        TrustedCheckpointSet {
            network: network.as_byte(),
            epoch,
            min_signatures,
            validators,
        }
    }

    fn sample_snapshot() -> StateSnapshot {
        StateSnapshot {
            block_height: 33,
            state_root: [7_u8; 32],
            accounts: vec![
                SnapshotAccount {
                    address: "HMA_RUNTIME_POLICY_A".to_owned(),
                    state: AccountState {
                        balance: 500,
                        nonce: 2,
                    },
                },
                SnapshotAccount {
                    address: "HMA_RUNTIME_POLICY_B".to_owned(),
                    state: AccountState {
                        balance: 800,
                        nonce: 1,
                    },
                },
            ],
        }
    }

    fn snapshot_hash(snapshot: &StateSnapshot) -> [u8; 32] {
        let encoded = snapshot.encode();
        assert!(encoded.is_ok(), "snapshot encoding should succeed");
        *blake3::hash(&encoded.unwrap_or_else(|_| unreachable!())).as_bytes()
    }

    fn signed_advertisement(
        snapshot: &StateSnapshot,
        network: Network,
        signer_address: String,
        signer_keypair: &Keypair,
    ) -> SnapshotHandshakeAdvertisement {
        let signature = sign_snapshot_checkpoint(snapshot, network, signer_address, signer_keypair);
        assert!(signature.is_ok(), "checkpoint signing should succeed");

        let mut checkpoint = SnapshotCheckpoint::new(snapshot, network);
        checkpoint
            .signatures
            .push(signature.unwrap_or_else(|_| unreachable!()));

        SnapshotHandshakeAdvertisement {
            block_height: snapshot.block_height,
            state_root: snapshot.state_root,
            snapshot_hash: snapshot_hash(snapshot),
            checkpoint: Some(checkpoint),
        }
    }

    #[test]
    fn reputation_penalties_throttle_sync_serve_quota() {
        let network = Network::Testnet;
        let (_active_key, active_address) = validator(network);

        let controller = SyncRuntimePolicyController::new(
            network,
            ChunkServePolicy {
                per_peer_quota: 4,
                quota_window_ms: 1_000,
            },
            ReputationPolicy::default(),
            AdaptivePenaltyPolicy::default(),
            CheckpointRotationPolicy::default(),
            10,
            trusted_set(network, 1, 1, vec![active_address]),
        );
        assert!(controller.is_ok(), "runtime controller should initialize");
        let mut controller = controller.unwrap_or_else(|_| unreachable!());

        controller.record_peer_event("peer-a", ReputationEvent::MalformedPayload, 1_000);

        assert!(controller.admit_chunk_request("peer-a", 1_010).is_ok());
        assert!(controller.admit_chunk_request("peer-a", 1_020).is_ok());
        assert!(controller.admit_chunk_request("peer-a", 1_030).is_ok());

        let denied = controller.admit_chunk_request("peer-a", 1_040);
        assert!(
            matches!(
                denied,
                Err(RuntimePolicyError::SyncEngine {
                    source: SyncEngineError::PeerQuotaExceeded {
                        peer_id: _,
                        quota: 3,
                        window_ms: 1_000,
                    }
                })
            ),
            "low-score peer should be throttled to scaled quota"
        );
    }

    #[test]
    fn banned_peer_is_denied_sync_serving() {
        let network = Network::Testnet;
        let (_active_key, active_address) = validator(network);

        let controller = SyncRuntimePolicyController::new(
            network,
            ChunkServePolicy::default(),
            ReputationPolicy::default(),
            AdaptivePenaltyPolicy::default(),
            CheckpointRotationPolicy::default(),
            10,
            trusted_set(network, 1, 1, vec![active_address]),
        );
        assert!(controller.is_ok(), "runtime controller should initialize");
        let mut controller = controller.unwrap_or_else(|_| unreachable!());

        controller.record_peer_event("peer-b", ReputationEvent::ProtocolViolation, 2_000);
        controller.record_peer_event("peer-b", ReputationEvent::ProtocolViolation, 2_010);

        let denied = controller.admit_chunk_request("peer-b", 2_020);
        assert!(
            matches!(
                denied,
                Err(RuntimePolicyError::ServeDeniedBanned { peer_id }) if peer_id == "peer-b"
            ),
            "banned peer should be denied before serve quota checks"
        );
    }

    #[test]
    fn handshake_trust_policy_switches_after_rotation_activation() {
        let network = Network::Testnet;
        let (active_key, active_address) = validator(network);
        let (next_key, next_address) = validator(network);

        let controller = SyncRuntimePolicyController::new(
            network,
            ChunkServePolicy::default(),
            ReputationPolicy::default(),
            AdaptivePenaltyPolicy::default(),
            CheckpointRotationPolicy {
                min_activation_delay_blocks: 3,
                max_validators: 16,
            },
            100,
            trusted_set(network, 1, 1, vec![active_address.clone()]),
        );
        assert!(controller.is_ok(), "runtime controller should initialize");
        let mut controller = controller.unwrap_or_else(|_| unreachable!());

        let next_set = trusted_set(network, 2, 1, vec![next_address.clone()]);
        let rotation_signature =
            sign_checkpoint_set_rotation(&next_set, 103, network, active_address, &active_key);
        assert!(
            rotation_signature.is_ok(),
            "rotation signature should succeed"
        );

        let ingest = controller.ingest_checkpoint_rotation_update(CheckpointSetRotationUpdate {
            next_set,
            activation_height: 103,
            signatures: vec![rotation_signature.unwrap_or_else(|_| unreachable!())],
        });
        assert!(
            matches!(ingest, Ok(RotationIngestOutcome::Accepted)),
            "rotation update should stage successfully"
        );

        let snapshot = sample_snapshot();
        let advertisement = signed_advertisement(&snapshot, network, next_address, &next_key);

        let before_activation = controller.validate_handshake(&snapshot, &advertisement);
        assert!(
            matches!(
                before_activation,
                Err(RuntimePolicyError::SyncEngine {
                    source: SyncEngineError::CheckpointVerification { source: _ },
                })
            ),
            "before activation, next-epoch signer should remain untrusted"
        );

        let activated = controller.advance_finalized_height(103);
        assert!(
            matches!(
                activated,
                Ok(RotationActivationOutcome::Activated {
                    previous_epoch: 1,
                    new_epoch: 2,
                    activation_height: 103
                })
            ),
            "rotation should activate once finalized height reaches threshold"
        );
        assert_eq!(controller.active_trusted_epoch(), 2);

        let after_activation = controller.validate_handshake(&snapshot, &advertisement);
        assert!(
            after_activation.is_ok(),
            "after activation, rotated trusted set should validate handshake"
        );
    }

    #[test]
    fn controller_surfaces_dial_cooldown_from_reputation() {
        let network = Network::Testnet;
        let (_active_key, active_address) = validator(network);

        let controller = SyncRuntimePolicyController::new(
            network,
            ChunkServePolicy::default(),
            ReputationPolicy::default(),
            AdaptivePenaltyPolicy::default(),
            CheckpointRotationPolicy::default(),
            10,
            trusted_set(network, 1, 1, vec![active_address]),
        );
        assert!(controller.is_ok(), "runtime controller should initialize");
        let mut controller = controller.unwrap_or_else(|_| unreachable!());

        controller.record_peer_event("peer-c", ReputationEvent::MalformedPayload, 3_000);
        let dial = controller.enforce_dial_allowed("peer-c", 3_001);
        assert!(
            matches!(dial, Err(RuntimePolicyError::Reputation { source: _ })),
            "controller should surface reputation dial cooldown policy"
        );
    }
}
