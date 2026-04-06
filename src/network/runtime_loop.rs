//! Inbound network message runtime handling with policy enforcement.

use thiserror::Error;

use crate::core::transaction::Transaction;
use crate::network::checkpoint_rotation::{
    CheckpointRotationError, CheckpointSetRotationUpdate, RotationIngestOutcome,
};
use crate::network::p2p::{
    BLOCKS_TOPIC, CHECKPOINT_ROTATIONS_TOPIC, NetworkError, SYNC_CHUNKS_TOPIC, SYNC_REQUESTS_TOPIC,
    SnapshotChunkRequest, SnapshotChunkResponse, TRANSACTIONS_TOPIC, decode_snapshot_chunk_request,
    decode_snapshot_chunk_response, decode_transaction_gossip_payload,
    validate_block_gossip_payload_bounds,
};
use crate::network::reputation::ReputationEvent;
use crate::network::runtime_policy::{RuntimePolicyError, SyncRuntimePolicyController};
use crate::network::sync_engine::SyncEngineError;
use crate::network::sync_runtime::{SyncRuntimeCoordinator, SyncRuntimeError};

/// Runtime handling outcome for one inbound gossip message.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum InboundGossipAction {
    /// Decoded transaction payload.
    Transaction(Transaction),
    /// Raw block payload to be validated by block pipeline.
    BlockPayload(Vec<u8>),
    /// Decoded snapshot chunk request accepted by runtime policy gates.
    SyncChunkRequest(SnapshotChunkRequest),
    /// Decoded snapshot chunk response.
    SyncChunkResponse(SnapshotChunkResponse),
    /// Checkpoint trust-set rotation update outcome.
    CheckpointRotation {
        /// Rotation ingest decision.
        outcome: RotationIngestOutcome,
    },
}

/// Runtime message-handling failures for inbound gossip payloads.
#[derive(Debug, Error)]
pub enum RuntimeLoopError {
    /// Network payload decode failure.
    #[error("network payload handling failed")]
    Network {
        /// Underlying network decode error.
        source: NetworkError,
    },
    /// Runtime policy gate failure.
    #[error("runtime policy rejected inbound message")]
    RuntimePolicy {
        /// Underlying runtime policy error.
        source: RuntimePolicyError,
    },
    /// Checkpoint rotation payload decode failure.
    #[error("checkpoint rotation payload decode failed")]
    CheckpointRotationDecode {
        /// Underlying checkpoint-rotation decode error.
        source: CheckpointRotationError,
    },
    /// Sync runtime coordinator rejected inbound sync chunk response.
    #[error("sync runtime handling failed")]
    SyncRuntime {
        /// Underlying sync-runtime error.
        source: SyncRuntimeError,
    },
    /// Topic is not recognized by the runtime handler.
    #[error("unknown inbound gossip topic: {topic}")]
    UnknownTopic {
        /// Topic string.
        topic: String,
    },
}

/// Handles one inbound gossip message with runtime policy enforcement.
pub fn handle_inbound_gossip_message(
    controller: &mut SyncRuntimePolicyController,
    topic: &str,
    payload: &[u8],
    peer_id: &str,
    now_ms: u64,
) -> Result<InboundGossipAction, RuntimeLoopError> {
    match topic {
        TRANSACTIONS_TOPIC => {
            let transaction = decode_transaction_gossip_payload(payload)
                .map_err(|source| RuntimeLoopError::Network { source })?;
            Ok(InboundGossipAction::Transaction(transaction))
        }
        BLOCKS_TOPIC => {
            validate_block_gossip_payload_bounds(payload)
                .map_err(|source| RuntimeLoopError::Network { source })?;
            Ok(InboundGossipAction::BlockPayload(payload.to_vec()))
        }
        SYNC_REQUESTS_TOPIC => handle_sync_request_topic(controller, payload, peer_id, now_ms),
        SYNC_CHUNKS_TOPIC => {
            let response = decode_snapshot_chunk_response(payload)
                .map_err(|source| RuntimeLoopError::Network { source })?;
            Ok(InboundGossipAction::SyncChunkResponse(response))
        }
        CHECKPOINT_ROTATIONS_TOPIC => handle_checkpoint_rotation_topic(controller, payload),
        _ => Err(RuntimeLoopError::UnknownTopic {
            topic: topic.to_owned(),
        }),
    }
}

/// Handles one inbound gossip message and records reputation penalties for abusive traffic.
pub fn handle_inbound_gossip_message_with_feedback(
    controller: &mut SyncRuntimePolicyController,
    topic: &str,
    payload: &[u8],
    peer_id: &str,
    now_ms: u64,
) -> Result<InboundGossipAction, RuntimeLoopError> {
    let outcome = handle_inbound_gossip_message(controller, topic, payload, peer_id, now_ms);
    if let Err(error) = &outcome
        && let Some(event) = classify_reputation_event(error)
    {
        controller.record_peer_event(peer_id, event, now_ms);
    }
    outcome
}

/// Handles one inbound gossip message with feedback and sync-runtime response wiring.
pub fn handle_inbound_gossip_message_with_feedback_and_sync_runtime(
    controller: &mut SyncRuntimePolicyController,
    sync_runtime: &mut SyncRuntimeCoordinator,
    topic: &str,
    payload: &[u8],
    peer_id: &str,
    now_ms: u64,
) -> Result<InboundGossipAction, RuntimeLoopError> {
    let action =
        handle_inbound_gossip_message_with_feedback(controller, topic, payload, peer_id, now_ms)?;
    match action {
        InboundGossipAction::SyncChunkResponse(response) => {
            if let Err(source) =
                sync_runtime.handle_inbound_chunk_response(peer_id, response.clone())
            {
                controller.record_peer_event(peer_id, ReputationEvent::ProtocolViolation, now_ms);
                return Err(RuntimeLoopError::SyncRuntime { source });
            }
            Ok(InboundGossipAction::SyncChunkResponse(response))
        }
        _ => Ok(action),
    }
}

const fn classify_reputation_event(error: &RuntimeLoopError) -> Option<ReputationEvent> {
    match error {
        RuntimeLoopError::Network { .. } | RuntimeLoopError::CheckpointRotationDecode { .. } => {
            Some(ReputationEvent::MalformedPayload)
        }
        RuntimeLoopError::SyncRuntime { .. } | RuntimeLoopError::UnknownTopic { .. } => {
            Some(ReputationEvent::ProtocolViolation)
        }
        RuntimeLoopError::RuntimePolicy { source } => match source {
            RuntimePolicyError::SyncEngine {
                source: SyncEngineError::PeerQuotaExceeded { .. },
            }
            | RuntimePolicyError::CheckpointRotation { .. } => {
                Some(ReputationEvent::ProtocolViolation)
            }
            RuntimePolicyError::Reputation { .. }
            | RuntimePolicyError::ServeDeniedBanned { .. }
            | RuntimePolicyError::SyncEngine { .. } => None,
        },
    }
}

fn handle_sync_request_topic(
    controller: &mut SyncRuntimePolicyController,
    payload: &[u8],
    peer_id: &str,
    now_ms: u64,
) -> Result<InboundGossipAction, RuntimeLoopError> {
    controller
        .admit_chunk_request(peer_id, now_ms)
        .map_err(|source| RuntimeLoopError::RuntimePolicy { source })?;
    let request = decode_snapshot_chunk_request(payload)
        .map_err(|source| RuntimeLoopError::Network { source })?;
    Ok(InboundGossipAction::SyncChunkRequest(request))
}

fn handle_checkpoint_rotation_topic(
    controller: &mut SyncRuntimePolicyController,
    payload: &[u8],
) -> Result<InboundGossipAction, RuntimeLoopError> {
    let update = CheckpointSetRotationUpdate::decode(payload)
        .map_err(|source| RuntimeLoopError::CheckpointRotationDecode { source })?;
    let outcome = controller
        .ingest_checkpoint_rotation_update(update)
        .map_err(|source| RuntimeLoopError::RuntimePolicy { source })?;
    Ok(InboundGossipAction::CheckpointRotation { outcome })
}

#[cfg(test)]
mod tests {
    use super::{
        InboundGossipAction, RuntimeLoopError, handle_inbound_gossip_message,
        handle_inbound_gossip_message_with_feedback,
        handle_inbound_gossip_message_with_feedback_and_sync_runtime,
    };
    use crate::core::state::AccountState;
    use crate::core::sync::{SnapshotAccount, StateSnapshot, split_snapshot_into_chunks};
    use crate::core::transaction::Transaction;
    use crate::crypto::address::{Network, derive_address};
    use crate::crypto::keys::Keypair;
    use crate::network::checkpoint_rotation::{
        CheckpointRotationPolicy, CheckpointSetRotationUpdate, RotationIngestOutcome,
        TrustedCheckpointSet, sign_checkpoint_set_rotation,
    };
    use crate::network::p2p::{
        BLOCKS_TOPIC, CHECKPOINT_ROTATIONS_TOPIC, MAX_BLOCK_GOSSIP_BYTES, NetworkError,
        SYNC_CHUNKS_TOPIC, SYNC_REQUESTS_TOPIC, TRANSACTIONS_TOPIC, encode_snapshot_chunk_request,
        encode_snapshot_chunk_response,
    };
    use crate::network::reputation::{AdaptivePenaltyPolicy, ReputationEvent, ReputationPolicy};
    use crate::network::runtime_policy::{RuntimePolicyError, SyncRuntimePolicyController};
    use crate::network::sync_engine::{
        ChunkServePolicy, ChunkSessionPolicy, RequestSchedulerPolicy,
    };
    use crate::network::sync_runtime::{SyncRuntimeCoordinator, SyncRuntimeError};

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

    fn controller_with_quota(per_peer_quota: usize) -> SyncRuntimePolicyController {
        let network = Network::Testnet;
        let (_key, address) = validator(network);
        let controller = SyncRuntimePolicyController::new(
            network,
            ChunkServePolicy {
                per_peer_quota,
                quota_window_ms: 1_000,
            },
            ReputationPolicy::default(),
            AdaptivePenaltyPolicy::default(),
            CheckpointRotationPolicy::default(),
            100,
            trusted_set(network, 1, 1, vec![address]),
        );
        assert!(controller.is_ok(), "controller should initialize");
        controller.unwrap_or_else(|_| unreachable!())
    }

    fn sample_encoded_request(request_id: u64) -> Vec<u8> {
        let payload = encode_snapshot_chunk_request(crate::network::p2p::SnapshotChunkRequest {
            request_id,
            block_height: 10,
            state_root: [1_u8; 32],
            snapshot_hash: [2_u8; 32],
            chunk_index: 0,
            total_chunks: 1,
        });
        assert!(payload.is_ok(), "request encoding should succeed");
        payload.unwrap_or_else(|_| unreachable!())
    }

    fn sample_sync_runtime() -> SyncRuntimeCoordinator {
        let runtime = SyncRuntimeCoordinator::new(
            RequestSchedulerPolicy {
                request_timeout_ms: 100,
                max_retries: 1,
                max_in_flight: 8,
            },
            ChunkSessionPolicy {
                max_in_flight_per_session: 4,
                max_in_flight_per_peer: 8,
                base_retry_backoff_ms: 100,
                max_retry_backoff_ms: 1_000,
            },
        );
        assert!(runtime.is_ok(), "sync runtime should initialize");
        runtime.unwrap_or_else(|_| unreachable!())
    }

    fn sample_sync_response_payload(
        request_id: u64,
    ) -> (Vec<u8>, crate::network::p2p::SnapshotChunkRequest) {
        let snapshot = StateSnapshot {
            block_height: 10,
            state_root: [1_u8; 32],
            accounts: vec![
                SnapshotAccount {
                    address: "HMA_RUNTIME_LOOP_SYNC_A".to_owned(),
                    state: AccountState {
                        balance: 11,
                        nonce: 0,
                    },
                },
                SnapshotAccount {
                    address: "HMA_RUNTIME_LOOP_SYNC_B".to_owned(),
                    state: AccountState {
                        balance: 22,
                        nonce: 1,
                    },
                },
            ],
        };
        let chunks = split_snapshot_into_chunks(&snapshot, 24);
        assert!(chunks.is_ok(), "snapshot chunk split should succeed");
        let mut chunks = chunks.unwrap_or_else(|_| unreachable!());
        assert!(
            !chunks.is_empty(),
            "chunk split should return at least one chunk"
        );
        let chunk = chunks.remove(0);

        let request = crate::network::p2p::SnapshotChunkRequest {
            request_id,
            block_height: chunk.block_height,
            state_root: chunk.state_root,
            snapshot_hash: chunk.snapshot_hash,
            chunk_index: chunk.chunk_index,
            total_chunks: chunk.total_chunks,
        };
        let encoded = encode_snapshot_chunk_response(crate::network::p2p::SnapshotChunkResponse {
            request_id,
            chunk,
        });
        assert!(encoded.is_ok(), "chunk response encoding should succeed");
        (encoded.unwrap_or_else(|_| unreachable!()), request)
    }

    fn sample_sync_stream_payloads(
        request_id_base: u64,
    ) -> Vec<(Vec<u8>, crate::network::p2p::SnapshotChunkRequest)> {
        let snapshot = StateSnapshot {
            block_height: 21,
            state_root: [9_u8; 32],
            accounts: vec![
                SnapshotAccount {
                    address: "HMA_RUNTIME_LOOP_STREAM_A".to_owned(),
                    state: AccountState {
                        balance: 10,
                        nonce: 0,
                    },
                },
                SnapshotAccount {
                    address: "HMA_RUNTIME_LOOP_STREAM_B".to_owned(),
                    state: AccountState {
                        balance: 20,
                        nonce: 1,
                    },
                },
                SnapshotAccount {
                    address: "HMA_RUNTIME_LOOP_STREAM_C".to_owned(),
                    state: AccountState {
                        balance: 30,
                        nonce: 2,
                    },
                },
                SnapshotAccount {
                    address: "HMA_RUNTIME_LOOP_STREAM_D".to_owned(),
                    state: AccountState {
                        balance: 40,
                        nonce: 3,
                    },
                },
            ],
        };
        let chunks = split_snapshot_into_chunks(&snapshot, 32);
        assert!(chunks.is_ok(), "snapshot chunk split should succeed");
        let chunks = chunks.unwrap_or_else(|_| unreachable!());
        assert!(
            chunks.len() > 1,
            "fixture should produce multi-chunk stream"
        );

        chunks
            .into_iter()
            .enumerate()
            .map(|(index, chunk)| {
                let request_id = request_id_base + u64::try_from(index).unwrap_or(u64::MAX);
                let request = crate::network::p2p::SnapshotChunkRequest {
                    request_id,
                    block_height: chunk.block_height,
                    state_root: chunk.state_root,
                    snapshot_hash: chunk.snapshot_hash,
                    chunk_index: chunk.chunk_index,
                    total_chunks: chunk.total_chunks,
                };
                let encoded =
                    encode_snapshot_chunk_response(crate::network::p2p::SnapshotChunkResponse {
                        request_id,
                        chunk,
                    });
                assert!(encoded.is_ok(), "chunk response encoding should succeed");
                (encoded.unwrap_or_else(|_| unreachable!()), request)
            })
            .collect()
    }

    #[test]
    fn handles_transaction_topic_with_decode() {
        let mut controller = controller_with_quota(4);
        let transaction = Transaction::new_unsigned(
            "HMA_LOOP_TX_SENDER".to_owned(),
            "HMA_LOOP_TX_RECEIVER".to_owned(),
            5,
            1,
            7,
            0,
        );
        let payload = transaction.encode();
        assert!(payload.is_ok(), "transaction encoding should succeed");

        let handled = handle_inbound_gossip_message(
            &mut controller,
            TRANSACTIONS_TOPIC,
            &payload.unwrap_or_else(|_| unreachable!()),
            "peer-x",
            1_000,
        );
        assert!(handled.is_ok(), "transaction payload should be handled");
        assert_eq!(
            handled.unwrap_or_else(|_| unreachable!()),
            InboundGossipAction::Transaction(transaction)
        );
    }

    #[test]
    fn handles_block_topic_as_raw_payload() {
        let mut controller = controller_with_quota(4);
        let payload = vec![9_u8, 8_u8, 7_u8];
        let handled =
            handle_inbound_gossip_message(&mut controller, BLOCKS_TOPIC, &payload, "peer-y", 5_000);
        assert!(
            handled.is_ok(),
            "block payload should be accepted as raw bytes"
        );
        assert_eq!(
            handled.unwrap_or_else(|_| unreachable!()),
            InboundGossipAction::BlockPayload(payload)
        );
    }

    #[test]
    fn block_topic_rejects_oversized_payload() {
        let mut controller = controller_with_quota(4);
        let payload = vec![0_u8; MAX_BLOCK_GOSSIP_BYTES + 1];
        let handled =
            handle_inbound_gossip_message(&mut controller, BLOCKS_TOPIC, &payload, "peer-y", 5_000);
        assert!(
            matches!(
                handled,
                Err(RuntimeLoopError::Network {
                    source: NetworkError::BlockPayloadTooLarge {
                        actual: _,
                        max: MAX_BLOCK_GOSSIP_BYTES
                    }
                })
            ),
            "oversized block gossip payload must be rejected at runtime boundary"
        );
    }

    #[test]
    fn sync_request_topic_applies_runtime_quota_penalties() {
        let mut controller = controller_with_quota(4);
        controller.record_peer_event("peer-a", ReputationEvent::MalformedPayload, 1_000);

        for request_id in [1_u64, 2_u64, 3_u64] {
            let payload = sample_encoded_request(request_id);
            let handled = handle_inbound_gossip_message(
                &mut controller,
                SYNC_REQUESTS_TOPIC,
                &payload,
                "peer-a",
                1_010 + request_id,
            );
            assert!(
                handled.is_ok(),
                "throttled quota should still admit first three requests"
            );
        }

        let denied = handle_inbound_gossip_message(
            &mut controller,
            SYNC_REQUESTS_TOPIC,
            &sample_encoded_request(4),
            "peer-a",
            1_020,
        );
        assert!(
            matches!(
                denied,
                Err(RuntimeLoopError::RuntimePolicy {
                    source: RuntimePolicyError::SyncEngine { source: _ }
                })
            ),
            "fourth request should be denied under scaled quota"
        );
    }

    #[test]
    fn sync_request_topic_denies_banned_peer() {
        let mut controller = controller_with_quota(8);
        controller.record_peer_event("peer-b", ReputationEvent::ProtocolViolation, 2_000);
        controller.record_peer_event("peer-b", ReputationEvent::ProtocolViolation, 2_001);

        let denied = handle_inbound_gossip_message(
            &mut controller,
            SYNC_REQUESTS_TOPIC,
            &sample_encoded_request(11),
            "peer-b",
            2_010,
        );
        assert!(
            matches!(
                denied,
                Err(RuntimeLoopError::RuntimePolicy {
                    source: RuntimePolicyError::ServeDeniedBanned { peer_id }
                }) if peer_id == "peer-b"
            ),
            "banned peer should be denied before sync request decode"
        );
    }

    #[test]
    fn checkpoint_rotation_topic_ingests_signed_update() {
        let network = Network::Testnet;
        let (active_key, active_address) = validator(network);
        let (_new_key, new_address) = validator(network);
        let controller = SyncRuntimePolicyController::new(
            network,
            ChunkServePolicy {
                per_peer_quota: 4,
                quota_window_ms: 1_000,
            },
            ReputationPolicy::default(),
            AdaptivePenaltyPolicy::default(),
            CheckpointRotationPolicy::default(),
            100,
            trusted_set(network, 1, 1, vec![active_address.clone()]),
        );
        assert!(controller.is_ok(), "controller should initialize");
        let mut controller = controller.unwrap_or_else(|_| unreachable!());

        let next_set = trusted_set(network, 2, 1, vec![new_address]);
        let signature =
            sign_checkpoint_set_rotation(&next_set, 116, network, active_address, &active_key);
        assert!(signature.is_ok(), "rotation signature should succeed");

        let update = CheckpointSetRotationUpdate {
            next_set,
            activation_height: 116,
            signatures: vec![signature.unwrap_or_else(|_| unreachable!())],
        };
        let encoded = update.encode();
        assert!(encoded.is_ok(), "rotation update encoding should succeed");

        let handled = handle_inbound_gossip_message(
            &mut controller,
            CHECKPOINT_ROTATIONS_TOPIC,
            &encoded.unwrap_or_else(|_| unreachable!()),
            "peer-rot",
            9_000,
        );
        assert!(handled.is_ok(), "rotation update should be ingested");
        assert_eq!(
            handled.unwrap_or_else(|_| unreachable!()),
            InboundGossipAction::CheckpointRotation {
                outcome: RotationIngestOutcome::Accepted
            }
        );
    }

    #[test]
    fn rejects_unknown_topic() {
        let mut controller = controller_with_quota(4);
        let handled =
            handle_inbound_gossip_message(&mut controller, "unknown", b"abc", "peer-z", 7_000);
        assert!(
            matches!(
                handled,
                Err(RuntimeLoopError::UnknownTopic { topic }) if topic == "unknown"
            ),
            "unknown topic should return typed runtime-loop error"
        );
    }

    #[test]
    fn feedback_loop_penalizes_malformed_transaction_payload() {
        let mut controller = controller_with_quota(4);
        let handled = handle_inbound_gossip_message_with_feedback(
            &mut controller,
            TRANSACTIONS_TOPIC,
            b"\xFF\xAA\x00",
            "peer-mal",
            10_000,
        );
        assert!(
            matches!(handled, Err(RuntimeLoopError::Network { source: _ })),
            "malformed transaction payload should return network decode error"
        );
        assert_eq!(
            controller.peer_score("peer-mal", 10_001),
            -30,
            "one malformed payload should apply deterministic malformed-payload penalty"
        );
    }

    #[test]
    fn feedback_loop_penalizes_unknown_topic_as_protocol_violation() {
        let mut controller = controller_with_quota(4);
        let handled = handle_inbound_gossip_message_with_feedback(
            &mut controller,
            "unknown",
            b"abc",
            "peer-unknown",
            11_000,
        );
        assert!(
            matches!(handled, Err(RuntimeLoopError::UnknownTopic { topic }) if topic == "unknown"),
            "unknown topic should be rejected"
        );
        assert_eq!(
            controller.peer_score("peer-unknown", 11_001),
            -50,
            "unknown topic must map to protocol-violation penalty"
        );
    }

    #[test]
    fn feedback_loop_does_not_double_penalize_banned_sync_request() {
        let mut controller = controller_with_quota(8);
        controller.record_peer_event("peer-ban", ReputationEvent::ProtocolViolation, 12_000);
        controller.record_peer_event("peer-ban", ReputationEvent::ProtocolViolation, 12_010);
        assert!(
            controller.is_peer_banned("peer-ban", 12_020),
            "peer should be banned after repeated protocol violations"
        );
        let score_before = controller.peer_score("peer-ban", 12_020);

        let handled = handle_inbound_gossip_message_with_feedback(
            &mut controller,
            SYNC_REQUESTS_TOPIC,
            &sample_encoded_request(40),
            "peer-ban",
            12_020,
        );
        assert!(
            matches!(
                handled,
                Err(RuntimeLoopError::RuntimePolicy {
                    source: RuntimePolicyError::ServeDeniedBanned { peer_id }
                }) if peer_id == "peer-ban"
            ),
            "banned peer should still be denied for sync requests"
        );
        assert_eq!(
            controller.peer_score("peer-ban", 12_021),
            score_before,
            "banned request denial should not apply additional penalty"
        );
    }

    #[test]
    fn sync_chunk_topic_wires_into_runtime_ack_path() {
        let mut controller = controller_with_quota(4);
        let mut sync_runtime = sample_sync_runtime();
        let (payload, request) = sample_sync_response_payload(55);

        let scheduled = sync_runtime.schedule_outbound_request("peer-sync", 3, request, 20_000);
        assert!(
            scheduled.is_ok(),
            "outbound request should be tracked before response arrives"
        );
        assert_eq!(sync_runtime.in_flight_request_count(), 1);
        assert_eq!(sync_runtime.tracked_request_count(), 1);

        let handled = handle_inbound_gossip_message_with_feedback_and_sync_runtime(
            &mut controller,
            &mut sync_runtime,
            SYNC_CHUNKS_TOPIC,
            &payload,
            "peer-sync",
            20_010,
        );
        assert!(
            handled.is_ok(),
            "inbound sync response should be accepted and acked"
        );
        assert!(
            matches!(handled, Ok(InboundGossipAction::SyncChunkResponse(_))),
            "runtime-loop action should preserve decoded response"
        );
        assert_eq!(
            sync_runtime.in_flight_request_count(),
            0,
            "runtime ack should clear scheduler in-flight tracking"
        );
        assert_eq!(
            sync_runtime.tracked_request_count(),
            0,
            "runtime ack should clear request->session binding"
        );
    }

    #[test]
    fn sync_chunk_from_wrong_peer_is_rejected_and_penalized() {
        let mut controller = controller_with_quota(4);
        let mut sync_runtime = sample_sync_runtime();
        let (payload, request) = sample_sync_response_payload(56);

        let scheduled = sync_runtime.schedule_outbound_request("peer-good", 4, request, 21_000);
        assert!(scheduled.is_ok(), "outbound request should be tracked");

        let handled = handle_inbound_gossip_message_with_feedback_and_sync_runtime(
            &mut controller,
            &mut sync_runtime,
            SYNC_CHUNKS_TOPIC,
            &payload,
            "peer-bad",
            21_010,
        );
        assert!(
            matches!(
                handled,
                Err(RuntimeLoopError::SyncRuntime {
                    source: SyncRuntimeError::ResponsePeerMismatch {
                        request_id: 56,
                        expected_peer_id: _,
                        actual_peer_id: _
                    }
                })
            ),
            "unexpected sync response peer should be rejected by runtime coordinator"
        );
        assert_eq!(
            controller.peer_score("peer-bad", 21_011),
            -50,
            "sync runtime rejection should apply protocol-violation penalty"
        );
        assert_eq!(
            sync_runtime.in_flight_request_count(),
            1,
            "rejected response must not ack tracked in-flight request"
        );
    }

    #[test]
    fn sync_chunk_runtime_path_completes_snapshot_assembly_queue() {
        let mut controller = controller_with_quota(16);
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
            crate::core::sync::SnapshotAdmissionPolicy::default(),
        );
        assert!(
            runtime.is_ok(),
            "sync runtime for full stream assembly should initialize"
        );
        let mut sync_runtime = runtime.unwrap_or_else(|_| unreachable!());
        let stream = sample_sync_stream_payloads(10_000);

        for (_payload, request) in &stream {
            let scheduled =
                sync_runtime.schedule_outbound_request("peer-stream", 12, *request, 30_000);
            assert!(scheduled.is_ok(), "all stream requests should schedule");
        }

        for (payload, _request) in stream.into_iter().rev() {
            let handled = handle_inbound_gossip_message_with_feedback_and_sync_runtime(
                &mut controller,
                &mut sync_runtime,
                SYNC_CHUNKS_TOPIC,
                &payload,
                "peer-stream",
                30_100,
            );
            assert!(
                matches!(handled, Ok(InboundGossipAction::SyncChunkResponse(_))),
                "runtime loop should decode + wire sync responses"
            );
        }

        assert_eq!(
            sync_runtime.completed_snapshot_count(),
            1,
            "full stream should finalize exactly one snapshot"
        );
        let completed = sync_runtime.drain_completed_snapshots();
        assert_eq!(completed.len(), 1);
        assert_eq!(
            sync_runtime.completed_snapshot_count(),
            0,
            "completed snapshot queue should drain cleanly"
        );
    }
}
