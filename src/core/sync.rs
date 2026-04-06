//! Fast-sync snapshot export/import and verification.

use std::collections::BTreeSet;

use serde::{Deserialize, Serialize};
use thiserror::Error;

use crate::core::block::{Block, HASH_LENGTH};
use crate::core::state::{AccountState, ChainState, StateError};
use crate::crypto::address::{AddressError, Network, validate_address_for_network};
use crate::crypto::keys::{
    CryptoError, Keypair, PUBLIC_KEY_LENGTH, SIGNATURE_LENGTH, verify_signature,
};
use crate::observability::Observability;

/// 32-byte state commitment hash.
pub type StateRoot = [u8; HASH_LENGTH];
/// Explicit domain separator for snapshot checkpoint signatures.
pub const SNAPSHOT_CHECKPOINT_DOMAIN_SEPARATOR: [u8; 21] = *b"HOMA_SNAPSHOT_CKPT_V1";
/// Explicit domain separator for snapshot chunk payload integrity.
pub const SNAPSHOT_CHUNK_DOMAIN_SEPARATOR: [u8; 22] = *b"HOMA_SNAPSHOT_CHUNK_V1";
/// Default chunk payload size for snapshot streaming.
pub const DEFAULT_SNAPSHOT_CHUNK_BYTES: usize = 64 * 1024;

/// One account entry inside a fast-sync snapshot.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SnapshotAccount {
    /// Account address.
    pub address: String,
    /// Account balance + nonce state.
    pub state: AccountState,
}

/// Serializable state snapshot used for fast sync.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct StateSnapshot {
    /// Height of the finalized block this snapshot corresponds to.
    pub block_height: u64,
    /// Deterministic state root over all snapshot accounts.
    pub state_root: StateRoot,
    /// Full account set in deterministic address order.
    pub accounts: Vec<SnapshotAccount>,
}

/// One streamed snapshot chunk for resumable fast-sync transfer.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SnapshotChunk {
    /// Snapshot height this chunk belongs to.
    pub block_height: u64,
    /// Snapshot state root this chunk belongs to.
    pub state_root: StateRoot,
    /// Hash of the full serialized snapshot payload.
    pub snapshot_hash: StateRoot,
    /// Zero-based chunk index.
    pub chunk_index: u32,
    /// Total chunk count for this snapshot payload.
    pub total_chunks: u32,
    /// Chunk payload bytes.
    #[serde(with = "serde_bytes")]
    pub payload: Vec<u8>,
    /// Domain-separated chunk integrity hash.
    pub payload_hash: StateRoot,
}

/// Incremental assembler for resumable out-of-order snapshot chunk streams.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SnapshotChunkAssembler {
    max_chunk_bytes: usize,
    expected_block_height: Option<u64>,
    expected_state_root: Option<StateRoot>,
    expected_snapshot_hash: Option<StateRoot>,
    expected_total_chunks: Option<u32>,
    chunks: Vec<Option<Vec<u8>>>,
}

/// One validator signature included in a snapshot checkpoint.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SnapshotCheckpointSignature {
    /// Validator address that signed this checkpoint.
    pub validator_address: String,
    /// Validator Ed25519 public key.
    #[serde(with = "serde_bytes")]
    pub validator_public_key: Vec<u8>,
    /// Signature over canonical checkpoint signing bytes.
    #[serde(with = "serde_bytes")]
    pub signature: Vec<u8>,
}

/// Validator-signed checkpoint over a specific snapshot root and height.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SnapshotCheckpoint {
    /// Network byte for signature-domain separation.
    pub network: u8,
    /// Snapshot block height being attested.
    pub block_height: u64,
    /// Snapshot state root being attested.
    pub state_root: StateRoot,
    /// Validator signatures over checkpoint payload.
    pub signatures: Vec<SnapshotCheckpointSignature>,
}

/// Verification policy for optional snapshot checkpoints.
#[derive(Debug, Clone, Copy)]
pub struct CheckpointVerificationPolicy<'a> {
    /// Network domain expected by snapshot/checkpoint signers.
    pub network: Network,
    /// Minimum number of distinct trusted validator signatures required.
    pub min_signatures: usize,
    /// Trusted validator addresses accepted for checkpoint signatures.
    pub trusted_validators: &'a [String],
}

/// Default upper bound for accepted snapshot payload bytes.
pub const DEFAULT_MAX_SNAPSHOT_BYTES: usize = 64 * 1024 * 1024;
/// Default upper bound for accepted snapshot account entries.
pub const DEFAULT_MAX_SNAPSHOT_ACCOUNTS: usize = 1_000_000;

/// Admission guardrails for fast-sync snapshot payloads.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SnapshotAdmissionPolicy {
    /// Maximum serialized snapshot size accepted from peers.
    pub max_snapshot_bytes: usize,
    /// Maximum number of account entries accepted from peers.
    pub max_accounts: usize,
}

impl SnapshotAdmissionPolicy {
    /// Recommended default guardrails for public-network sync.
    #[must_use]
    pub const fn strict_default() -> Self {
        Self {
            max_snapshot_bytes: DEFAULT_MAX_SNAPSHOT_BYTES,
            max_accounts: DEFAULT_MAX_SNAPSHOT_ACCOUNTS,
        }
    }
}

impl Default for SnapshotAdmissionPolicy {
    fn default() -> Self {
        Self::strict_default()
    }
}

/// Import-mode context for rollback-safe fast-sync.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SnapshotImportMode {
    /// Node is bootstrapping or recovering from disk; older snapshots are allowed.
    BootstrapRecovery,
    /// Node already tracks finalized chain progress and must not roll back behind it.
    SteadyState {
        /// Lowest finalized height the node already trusts locally.
        local_finalized_height: u64,
    },
}

/// Fast-sync validation and import errors.
#[derive(Debug, Clone, PartialEq, Eq, Error)]
pub enum SyncError {
    /// Snapshot is empty.
    #[error("snapshot contains no accounts")]
    EmptySnapshot,
    /// Snapshot account list is not in strict deterministic address order.
    #[error("snapshot account ordering is not canonical: previous={previous}, current={current}")]
    SnapshotAccountOrderInvalid {
        /// Previous address encountered.
        previous: String,
        /// Current address encountered.
        current: String,
    },
    /// Snapshot payload does not hash to the declared state root.
    #[error("snapshot payload root mismatch")]
    SnapshotPayloadRootMismatch {
        /// Declared root in the snapshot payload.
        declared: StateRoot,
        /// Root computed from snapshot account entries.
        computed: StateRoot,
    },
    /// Snapshot admission policy cannot enforce zero thresholds.
    #[error(
        "invalid snapshot admission policy: max_snapshot_bytes={max_snapshot_bytes}, max_accounts={max_accounts}"
    )]
    InvalidSnapshotAdmissionPolicy {
        /// Configured maximum snapshot bytes.
        max_snapshot_bytes: usize,
        /// Configured maximum account entries.
        max_accounts: usize,
    },
    /// Snapshot payload exceeds configured serialized-byte budget.
    #[error("snapshot payload exceeds byte budget: limit={limit}, actual={actual}")]
    SnapshotByteLimitExceeded {
        /// Maximum permitted snapshot bytes.
        limit: usize,
        /// Actual serialized byte length.
        actual: usize,
    },
    /// Snapshot payload exceeds configured account-count budget.
    #[error("snapshot payload exceeds account budget: limit={limit}, actual={actual}")]
    SnapshotAccountLimitExceeded {
        /// Maximum permitted account entries.
        limit: usize,
        /// Actual account entry count.
        actual: usize,
    },
    /// Snapshot would roll local node back behind already-trusted finalized height.
    #[error(
        "snapshot rollback rejected: local_finalized_height={local_finalized_height}, snapshot_height={snapshot_height}"
    )]
    SnapshotRollbackRejected {
        /// Finalized height already trusted by the local node.
        local_finalized_height: u64,
        /// Height carried by incoming snapshot.
        snapshot_height: u64,
    },
    /// Snapshot chunk size must be non-zero.
    #[error("invalid snapshot chunk size: {chunk_size}")]
    InvalidSnapshotChunkSize {
        /// Configured chunk byte size.
        chunk_size: usize,
    },
    /// Snapshot payload fanout exceeds supported chunk index space.
    #[error("snapshot chunk count overflow: {count}")]
    SnapshotChunkCountOverflow {
        /// Computed chunk count.
        count: usize,
    },
    /// Chunk index is outside advertised chunk range.
    #[error("snapshot chunk index out of range: index={index}, total={total}")]
    SnapshotChunkIndexOutOfRange {
        /// Provided chunk index.
        index: u32,
        /// Advertised total chunk count.
        total: u32,
    },
    /// Chunk payload exceeds local per-chunk byte budget.
    #[error("snapshot chunk payload exceeds limit: index={index}, limit={limit}, actual={actual}")]
    SnapshotChunkPayloadTooLarge {
        /// Chunk index.
        index: u32,
        /// Maximum allowed chunk payload bytes.
        limit: usize,
        /// Actual payload bytes.
        actual: usize,
    },
    /// Chunk integrity hash does not match payload + metadata.
    #[error("snapshot chunk hash mismatch at index {index}")]
    SnapshotChunkHashMismatch {
        /// Chunk index.
        index: u32,
    },
    /// Chunks from different snapshot streams were mixed together.
    #[error("snapshot chunk stream metadata mismatch on field {field}")]
    SnapshotChunkStreamInconsistent {
        /// Metadata field that mismatched.
        field: &'static str,
    },
    /// Duplicate chunk index arrived with conflicting payload.
    #[error("snapshot chunk duplicate conflict at index {index}")]
    SnapshotChunkDuplicateConflict {
        /// Chunk index.
        index: u32,
    },
    /// Attempted finalize before receiving enough chunks.
    #[error("snapshot chunk stream is incomplete: missing {missing:?}")]
    SnapshotChunksIncomplete {
        /// Missing chunk indices.
        missing: Vec<u32>,
    },
    /// Attempted finalize before any valid chunk established stream metadata.
    #[error("snapshot chunk stream is uninitialized")]
    SnapshotChunkStreamUninitialized,
    /// Reassembled payload hash mismatches expected stream hash.
    #[error("snapshot reassembly hash mismatch")]
    SnapshotChunkReassemblyHashMismatch {
        /// Expected full snapshot hash.
        expected: StateRoot,
        /// Actual hash from reassembled bytes.
        actual: StateRoot,
    },
    /// Snapshot block height does not match finalized block height.
    #[error("snapshot height mismatch: expected {expected}, got {actual}")]
    HeightMismatch {
        /// Height from finalized block.
        expected: u64,
        /// Height from snapshot.
        actual: u64,
    },
    /// Snapshot state root does not match finalized block header state root.
    #[error("snapshot state root mismatch")]
    StateRootMismatch {
        /// Expected root from finalized block header.
        expected: StateRoot,
        /// Actual root from snapshot.
        actual: StateRoot,
    },
    /// Snapshot checkpoint has unsupported network byte.
    #[error("snapshot checkpoint network mismatch: expected {expected}, got {actual}")]
    CheckpointNetworkMismatch {
        /// Expected network byte.
        expected: u8,
        /// Actual checkpoint network byte.
        actual: u8,
    },
    /// Snapshot and checkpoint heights differ.
    #[error("snapshot checkpoint height mismatch: expected {expected}, got {actual}")]
    CheckpointHeightMismatch {
        /// Expected height from snapshot.
        expected: u64,
        /// Actual height from checkpoint.
        actual: u64,
    },
    /// Snapshot and checkpoint roots differ.
    #[error("snapshot checkpoint state root mismatch")]
    CheckpointStateRootMismatch {
        /// Expected root from snapshot.
        expected: StateRoot,
        /// Actual root from checkpoint.
        actual: StateRoot,
    },
    /// Checkpoint threshold is invalid for trusted validator set size.
    #[error("invalid checkpoint threshold: required {required}, trusted {trusted}")]
    InvalidCheckpointThreshold {
        /// Required minimum signature count.
        required: usize,
        /// Count of trusted validators in policy.
        trusted: usize,
    },
    /// Checkpoint contains no signatures.
    #[error("snapshot checkpoint contains no signatures")]
    EmptyCheckpointSignatures,
    /// Same validator appears multiple times in checkpoint signatures.
    #[error("duplicate checkpoint validator signature: {validator}")]
    DuplicateCheckpointValidator {
        /// Duplicated validator address.
        validator: String,
    },
    /// Signature was produced by a validator outside trusted set.
    #[error("untrusted checkpoint validator signature: {validator}")]
    UntrustedCheckpointValidator {
        /// Untrusted validator address.
        validator: String,
    },
    /// Checkpoint validator address failed parsing/network checks.
    #[error("invalid checkpoint validator address")]
    InvalidCheckpointValidatorAddress {
        /// Inner address parsing error.
        source: AddressError,
    },
    /// Checkpoint validator public key has invalid length.
    #[error("invalid checkpoint validator public key length: expected {expected}, got {actual}")]
    InvalidCheckpointValidatorPublicKeyLength {
        /// Expected key length.
        expected: usize,
        /// Actual key length.
        actual: usize,
    },
    /// Checkpoint signature has invalid length.
    #[error("invalid checkpoint signature length: expected {expected}, got {actual}")]
    InvalidCheckpointSignatureLength {
        /// Expected signature length.
        expected: usize,
        /// Actual signature length.
        actual: usize,
    },
    /// Validator public key does not correspond to validator address.
    #[error("checkpoint validator key/address mismatch: {validator}")]
    CheckpointValidatorKeyMismatch {
        /// Validator address.
        validator: String,
    },
    /// Validator signature verification failed.
    #[error("checkpoint signature verification failed for validator {validator}")]
    CheckpointSignatureVerification {
        /// Validator address.
        validator: String,
        /// Underlying verification error.
        source: CryptoError,
    },
    /// Checkpoint does not meet required signature threshold.
    #[error("insufficient checkpoint signatures: required {required}, actual {actual}")]
    InsufficientCheckpointSignatures {
        /// Required signature count.
        required: usize,
        /// Distinct valid signatures observed.
        actual: usize,
    },
    /// Snapshot serialization failed.
    #[error("snapshot serialization failed")]
    Serialization,
    /// Snapshot deserialization failed.
    #[error("snapshot deserialization failed")]
    Deserialization,
    /// Chain state import failed.
    #[error("state import failed")]
    StateImport {
        /// Underlying state error.
        source: StateError,
    },
}

impl StateSnapshot {
    /// Serializes snapshot payload to compact binary bytes.
    pub fn encode(&self) -> Result<Vec<u8>, SyncError> {
        bincode::serde::encode_to_vec(
            self,
            bincode::config::standard()
                .with_fixed_int_encoding()
                .with_little_endian(),
        )
        .map_err(|_| SyncError::Serialization)
    }

    /// Decodes a snapshot from binary bytes.
    pub fn decode(bytes: &[u8]) -> Result<Self, SyncError> {
        bincode::serde::decode_from_slice(
            bytes,
            bincode::config::standard()
                .with_fixed_int_encoding()
                .with_little_endian(),
        )
        .map(|(snapshot, _)| snapshot)
        .map_err(|_| SyncError::Deserialization)
    }

    /// Decodes a snapshot using byte/account admission guardrails.
    pub fn decode_with_policy(
        bytes: &[u8],
        policy: SnapshotAdmissionPolicy,
    ) -> Result<Self, SyncError> {
        validate_snapshot_admission_policy(policy)?;
        if bytes.len() > policy.max_snapshot_bytes {
            return Err(SyncError::SnapshotByteLimitExceeded {
                limit: policy.max_snapshot_bytes,
                actual: bytes.len(),
            });
        }

        let snapshot = Self::decode(bytes)?;
        validate_snapshot_admission(&snapshot, policy)?;
        Ok(snapshot)
    }
}

impl SnapshotCheckpoint {
    /// Builds an empty checkpoint bound to one snapshot and network domain.
    #[must_use]
    pub const fn new(snapshot: &StateSnapshot, network: Network) -> Self {
        Self {
            network: network.as_byte(),
            block_height: snapshot.block_height,
            state_root: snapshot.state_root,
            signatures: Vec::new(),
        }
    }

    /// Serializes checkpoint payload to compact binary bytes.
    pub fn encode(&self) -> Result<Vec<u8>, SyncError> {
        bincode::serde::encode_to_vec(
            self,
            bincode::config::standard()
                .with_fixed_int_encoding()
                .with_little_endian(),
        )
        .map_err(|_| SyncError::Serialization)
    }

    /// Decodes checkpoint payload from binary bytes.
    pub fn decode(bytes: &[u8]) -> Result<Self, SyncError> {
        bincode::serde::decode_from_slice(
            bytes,
            bincode::config::standard()
                .with_fixed_int_encoding()
                .with_little_endian(),
        )
        .map(|(checkpoint, _)| checkpoint)
        .map_err(|_| SyncError::Deserialization)
    }

    fn signing_bytes(&self) -> Result<Vec<u8>, SyncError> {
        checkpoint_signing_bytes(self.network, self.block_height, self.state_root)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
struct SnapshotCheckpointSigningEnvelope {
    domain_separator: [u8; 21],
    network: u8,
    block_height: u64,
    state_root: StateRoot,
}

fn checkpoint_signing_bytes(
    network: u8,
    block_height: u64,
    state_root: StateRoot,
) -> Result<Vec<u8>, SyncError> {
    let envelope = SnapshotCheckpointSigningEnvelope {
        domain_separator: SNAPSHOT_CHECKPOINT_DOMAIN_SEPARATOR,
        network,
        block_height,
        state_root,
    };
    bincode::serde::encode_to_vec(
        envelope,
        bincode::config::standard()
            .with_fixed_int_encoding()
            .with_little_endian(),
    )
    .map_err(|_| SyncError::Serialization)
}

fn snapshot_chunk_payload_hash(
    block_height: u64,
    state_root: StateRoot,
    snapshot_hash: StateRoot,
    chunk_index: u32,
    total_chunks: u32,
    payload: &[u8],
) -> StateRoot {
    let mut hasher = blake3::Hasher::new();
    hasher.update(&SNAPSHOT_CHUNK_DOMAIN_SEPARATOR);
    hasher.update(&block_height.to_le_bytes());
    hasher.update(&state_root);
    hasher.update(&snapshot_hash);
    hasher.update(&chunk_index.to_le_bytes());
    hasher.update(&total_chunks.to_le_bytes());
    hasher.update(&(payload.len() as u64).to_le_bytes());
    hasher.update(payload);
    *hasher.finalize().as_bytes()
}

/// Splits one encoded snapshot payload into deterministic hashed chunks.
pub fn split_snapshot_into_chunks(
    snapshot: &StateSnapshot,
    chunk_size: usize,
) -> Result<Vec<SnapshotChunk>, SyncError> {
    if chunk_size == 0 {
        return Err(SyncError::InvalidSnapshotChunkSize { chunk_size });
    }

    let encoded = snapshot.encode()?;
    let total_chunks = encoded.len().div_ceil(chunk_size);
    let total_chunks_u32 =
        u32::try_from(total_chunks).map_err(|_| SyncError::SnapshotChunkCountOverflow {
            count: total_chunks,
        })?;
    let snapshot_hash = *blake3::hash(&encoded).as_bytes();
    let mut chunks = Vec::with_capacity(total_chunks);

    for (chunk_index, payload) in encoded.chunks(chunk_size).enumerate() {
        let chunk_index_u32 =
            u32::try_from(chunk_index).map_err(|_| SyncError::SnapshotChunkCountOverflow {
                count: total_chunks,
            })?;
        chunks.push(SnapshotChunk {
            block_height: snapshot.block_height,
            state_root: snapshot.state_root,
            snapshot_hash,
            chunk_index: chunk_index_u32,
            total_chunks: total_chunks_u32,
            payload: payload.to_vec(),
            payload_hash: snapshot_chunk_payload_hash(
                snapshot.block_height,
                snapshot.state_root,
                snapshot_hash,
                chunk_index_u32,
                total_chunks_u32,
                payload,
            ),
        });
    }

    Ok(chunks)
}

fn validate_snapshot_chunk(chunk: &SnapshotChunk, max_chunk_bytes: usize) -> Result<(), SyncError> {
    if max_chunk_bytes == 0 {
        return Err(SyncError::InvalidSnapshotChunkSize {
            chunk_size: max_chunk_bytes,
        });
    }
    if chunk.total_chunks == 0 || chunk.chunk_index >= chunk.total_chunks {
        return Err(SyncError::SnapshotChunkIndexOutOfRange {
            index: chunk.chunk_index,
            total: chunk.total_chunks,
        });
    }
    if chunk.payload.len() > max_chunk_bytes {
        return Err(SyncError::SnapshotChunkPayloadTooLarge {
            index: chunk.chunk_index,
            limit: max_chunk_bytes,
            actual: chunk.payload.len(),
        });
    }

    let expected_hash = snapshot_chunk_payload_hash(
        chunk.block_height,
        chunk.state_root,
        chunk.snapshot_hash,
        chunk.chunk_index,
        chunk.total_chunks,
        &chunk.payload,
    );
    if expected_hash != chunk.payload_hash {
        return Err(SyncError::SnapshotChunkHashMismatch {
            index: chunk.chunk_index,
        });
    }
    Ok(())
}

impl SnapshotChunkAssembler {
    /// Creates a chunk assembler with a per-chunk payload budget.
    pub const fn new(max_chunk_bytes: usize) -> Result<Self, SyncError> {
        if max_chunk_bytes == 0 {
            return Err(SyncError::InvalidSnapshotChunkSize {
                chunk_size: max_chunk_bytes,
            });
        }
        Ok(Self {
            max_chunk_bytes,
            expected_block_height: None,
            expected_state_root: None,
            expected_snapshot_hash: None,
            expected_total_chunks: None,
            chunks: Vec::new(),
        })
    }

    /// Ingests one chunk; supports out-of-order and idempotent retry delivery.
    pub fn ingest_chunk(&mut self, chunk: SnapshotChunk) -> Result<(), SyncError> {
        validate_snapshot_chunk(&chunk, self.max_chunk_bytes)?;

        match self.expected_block_height {
            None => {
                self.expected_block_height = Some(chunk.block_height);
                self.expected_state_root = Some(chunk.state_root);
                self.expected_snapshot_hash = Some(chunk.snapshot_hash);
                self.expected_total_chunks = Some(chunk.total_chunks);
                let total = usize::try_from(chunk.total_chunks)
                    .map_err(|_| SyncError::SnapshotChunkCountOverflow { count: usize::MAX })?;
                self.chunks = vec![None; total];
            }
            Some(expected_block_height) => {
                if chunk.block_height != expected_block_height {
                    return Err(SyncError::SnapshotChunkStreamInconsistent {
                        field: "block_height",
                    });
                }
                if Some(chunk.state_root) != self.expected_state_root {
                    return Err(SyncError::SnapshotChunkStreamInconsistent {
                        field: "state_root",
                    });
                }
                if Some(chunk.snapshot_hash) != self.expected_snapshot_hash {
                    return Err(SyncError::SnapshotChunkStreamInconsistent {
                        field: "snapshot_hash",
                    });
                }
                if Some(chunk.total_chunks) != self.expected_total_chunks {
                    return Err(SyncError::SnapshotChunkStreamInconsistent {
                        field: "total_chunks",
                    });
                }
            }
        }

        let chunk_index = usize::try_from(chunk.chunk_index).map_err(|_| {
            SyncError::SnapshotChunkIndexOutOfRange {
                index: chunk.chunk_index,
                total: chunk.total_chunks,
            }
        })?;
        let slot = self.chunks.get_mut(chunk_index).ok_or_else(|| {
            SyncError::SnapshotChunkIndexOutOfRange {
                index: chunk.chunk_index,
                total: self.expected_total_chunks.unwrap_or(chunk.total_chunks),
            }
        })?;
        match slot {
            None => {
                *slot = Some(chunk.payload);
                Ok(())
            }
            Some(existing_payload) => {
                if *existing_payload == chunk.payload {
                    return Ok(());
                }
                Err(SyncError::SnapshotChunkDuplicateConflict {
                    index: chunk.chunk_index,
                })
            }
        }
    }

    /// Returns missing chunk indices for resume/retry requests.
    #[must_use]
    pub fn missing_chunk_indices(&self) -> Vec<u32> {
        self.chunks
            .iter()
            .enumerate()
            .filter_map(|(index, chunk)| {
                if chunk.is_none() {
                    return u32::try_from(index).ok();
                }
                None
            })
            .collect()
    }

    /// Returns `true` when all chunks for the stream are present.
    #[must_use]
    pub fn is_complete(&self) -> bool {
        !self.chunks.is_empty() && self.chunks.iter().all(Option::is_some)
    }

    /// Reassembles and decodes snapshot payload once all chunks have arrived.
    pub fn finalize(
        self,
        admission_policy: SnapshotAdmissionPolicy,
    ) -> Result<StateSnapshot, SyncError> {
        let expected_block_height = self
            .expected_block_height
            .ok_or(SyncError::SnapshotChunkStreamUninitialized)?;
        let expected_state_root = self
            .expected_state_root
            .ok_or(SyncError::SnapshotChunkStreamUninitialized)?;
        let expected_snapshot_hash = self
            .expected_snapshot_hash
            .ok_or(SyncError::SnapshotChunkStreamUninitialized)?;

        let missing = self.missing_chunk_indices();
        if !missing.is_empty() {
            return Err(SyncError::SnapshotChunksIncomplete { missing });
        }

        let mut encoded = Vec::new();
        for (index, payload) in self.chunks.into_iter().enumerate() {
            let Some(payload) = payload else {
                let missing_index = u32::try_from(index).unwrap_or(u32::MAX);
                return Err(SyncError::SnapshotChunksIncomplete {
                    missing: vec![missing_index],
                });
            };
            encoded.extend_from_slice(&payload);
        }

        let actual_hash = *blake3::hash(&encoded).as_bytes();
        if actual_hash != expected_snapshot_hash {
            return Err(SyncError::SnapshotChunkReassemblyHashMismatch {
                expected: expected_snapshot_hash,
                actual: actual_hash,
            });
        }

        let snapshot = StateSnapshot::decode_with_policy(&encoded, admission_policy)?;
        if snapshot.block_height != expected_block_height {
            return Err(SyncError::SnapshotChunkStreamInconsistent {
                field: "block_height",
            });
        }
        if snapshot.state_root != expected_state_root {
            return Err(SyncError::SnapshotChunkStreamInconsistent {
                field: "state_root",
            });
        }

        Ok(snapshot)
    }
}

/// Builds a deterministic snapshot from local state.
#[must_use]
pub fn build_state_snapshot(state: &ChainState, block_height: u64) -> StateSnapshot {
    let accounts = state
        .account_entries()
        .into_iter()
        .map(|(address, account_state)| SnapshotAccount {
            address,
            state: account_state,
        })
        .collect();

    StateSnapshot {
        block_height,
        state_root: state.state_root(),
        accounts,
    }
}

const fn validate_snapshot_admission_policy(
    policy: SnapshotAdmissionPolicy,
) -> Result<(), SyncError> {
    if policy.max_snapshot_bytes == 0 || policy.max_accounts == 0 {
        return Err(SyncError::InvalidSnapshotAdmissionPolicy {
            max_snapshot_bytes: policy.max_snapshot_bytes,
            max_accounts: policy.max_accounts,
        });
    }
    Ok(())
}

fn validate_snapshot_admission(
    snapshot: &StateSnapshot,
    policy: SnapshotAdmissionPolicy,
) -> Result<(), SyncError> {
    validate_snapshot_admission_policy(policy)?;

    let account_count = snapshot.accounts.len();
    if account_count > policy.max_accounts {
        return Err(SyncError::SnapshotAccountLimitExceeded {
            limit: policy.max_accounts,
            actual: account_count,
        });
    }

    let encoded_size = snapshot.encode()?.len();
    if encoded_size > policy.max_snapshot_bytes {
        return Err(SyncError::SnapshotByteLimitExceeded {
            limit: policy.max_snapshot_bytes,
            actual: encoded_size,
        });
    }

    Ok(())
}

const fn validate_snapshot_import_mode(
    snapshot_height: u64,
    import_mode: SnapshotImportMode,
) -> Result<(), SyncError> {
    match import_mode {
        SnapshotImportMode::BootstrapRecovery => Ok(()),
        SnapshotImportMode::SteadyState {
            local_finalized_height,
        } => {
            if snapshot_height < local_finalized_height {
                return Err(SyncError::SnapshotRollbackRejected {
                    local_finalized_height,
                    snapshot_height,
                });
            }
            Ok(())
        }
    }
}

fn compute_snapshot_state_root(snapshot: &StateSnapshot) -> Result<StateRoot, SyncError> {
    let mut previous_address: Option<&str> = None;
    let mut hasher = blake3::Hasher::new();
    hasher.update(&(snapshot.accounts.len() as u64).to_le_bytes());

    for account in &snapshot.accounts {
        if let Some(previous) = previous_address
            && account.address.as_str() <= previous
        {
            return Err(SyncError::SnapshotAccountOrderInvalid {
                previous: previous.to_owned(),
                current: account.address.clone(),
            });
        }

        hasher.update(&(account.address.len() as u64).to_le_bytes());
        hasher.update(account.address.as_bytes());
        hasher.update(&account.state.balance.to_le_bytes());
        hasher.update(&account.state.nonce.to_le_bytes());
        previous_address = Some(account.address.as_str());
    }

    Ok(*hasher.finalize().as_bytes())
}

/// Creates one validator signature over a snapshot checkpoint payload.
pub fn sign_snapshot_checkpoint(
    snapshot: &StateSnapshot,
    network: Network,
    validator_address: String,
    validator_keypair: &Keypair,
) -> Result<SnapshotCheckpointSignature, SyncError> {
    let parsed_validator = validate_address_for_network(&validator_address, network)
        .map_err(|source| SyncError::InvalidCheckpointValidatorAddress { source })?;

    let validator_public_key = validator_keypair.public_key_bytes();
    let validator_key_hash = blake3::hash(&validator_public_key);
    if validator_key_hash.as_bytes() != &parsed_validator.key_hash {
        return Err(SyncError::CheckpointValidatorKeyMismatch {
            validator: validator_address,
        });
    }

    let signing_bytes = checkpoint_signing_bytes(
        network.as_byte(),
        snapshot.block_height,
        snapshot.state_root,
    )?;
    let signature = validator_keypair.sign(&signing_bytes);

    Ok(SnapshotCheckpointSignature {
        validator_address,
        validator_public_key: validator_public_key.to_vec(),
        signature: signature.to_vec(),
    })
}

/// Verifies snapshot root and height against a finalized block header.
pub fn verify_snapshot_against_block(
    snapshot: &StateSnapshot,
    finalized_block: &Block,
) -> Result<(), SyncError> {
    if snapshot.accounts.is_empty() {
        return Err(SyncError::EmptySnapshot);
    }

    let computed_root = compute_snapshot_state_root(snapshot)?;
    if computed_root != snapshot.state_root {
        return Err(SyncError::SnapshotPayloadRootMismatch {
            declared: snapshot.state_root,
            computed: computed_root,
        });
    }

    if snapshot.block_height != finalized_block.header.height {
        return Err(SyncError::HeightMismatch {
            expected: finalized_block.header.height,
            actual: snapshot.block_height,
        });
    }

    if snapshot.state_root != finalized_block.header.state_root {
        return Err(SyncError::StateRootMismatch {
            expected: finalized_block.header.state_root,
            actual: snapshot.state_root,
        });
    }

    Ok(())
}

/// Verifies validator-signed snapshot checkpoint against snapshot payload and policy.
pub fn verify_snapshot_checkpoint(
    snapshot: &StateSnapshot,
    checkpoint: &SnapshotCheckpoint,
    policy: CheckpointVerificationPolicy<'_>,
) -> Result<(), SyncError> {
    let trusted_count = policy.trusted_validators.len();
    if policy.min_signatures == 0 || policy.min_signatures > trusted_count {
        return Err(SyncError::InvalidCheckpointThreshold {
            required: policy.min_signatures,
            trusted: trusted_count,
        });
    }

    let expected_network = policy.network.as_byte();
    if checkpoint.network != expected_network {
        return Err(SyncError::CheckpointNetworkMismatch {
            expected: expected_network,
            actual: checkpoint.network,
        });
    }
    if checkpoint.block_height != snapshot.block_height {
        return Err(SyncError::CheckpointHeightMismatch {
            expected: snapshot.block_height,
            actual: checkpoint.block_height,
        });
    }
    if checkpoint.state_root != snapshot.state_root {
        return Err(SyncError::CheckpointStateRootMismatch {
            expected: snapshot.state_root,
            actual: checkpoint.state_root,
        });
    }
    if checkpoint.signatures.is_empty() {
        return Err(SyncError::EmptyCheckpointSignatures);
    }

    let signing_bytes = checkpoint.signing_bytes()?;
    let trusted = policy
        .trusted_validators
        .iter()
        .cloned()
        .collect::<BTreeSet<_>>();
    let mut seen_validators = BTreeSet::<String>::new();

    for signature_entry in &checkpoint.signatures {
        if !seen_validators.insert(signature_entry.validator_address.clone()) {
            return Err(SyncError::DuplicateCheckpointValidator {
                validator: signature_entry.validator_address.clone(),
            });
        }
        if !trusted.contains(&signature_entry.validator_address) {
            return Err(SyncError::UntrustedCheckpointValidator {
                validator: signature_entry.validator_address.clone(),
            });
        }

        let parsed =
            validate_address_for_network(&signature_entry.validator_address, policy.network)
                .map_err(|source| SyncError::InvalidCheckpointValidatorAddress { source })?;

        if signature_entry.validator_public_key.len() != PUBLIC_KEY_LENGTH {
            return Err(SyncError::InvalidCheckpointValidatorPublicKeyLength {
                expected: PUBLIC_KEY_LENGTH,
                actual: signature_entry.validator_public_key.len(),
            });
        }
        if signature_entry.signature.len() != SIGNATURE_LENGTH {
            return Err(SyncError::InvalidCheckpointSignatureLength {
                expected: SIGNATURE_LENGTH,
                actual: signature_entry.signature.len(),
            });
        }

        let key_hash = blake3::hash(&signature_entry.validator_public_key);
        if key_hash.as_bytes() != &parsed.key_hash {
            return Err(SyncError::CheckpointValidatorKeyMismatch {
                validator: signature_entry.validator_address.clone(),
            });
        }

        verify_signature(
            &signature_entry.validator_public_key,
            &signing_bytes,
            &signature_entry.signature,
        )
        .map_err(|source| SyncError::CheckpointSignatureVerification {
            validator: signature_entry.validator_address.clone(),
            source,
        })?;
    }

    let actual = seen_validators.len();
    if actual < policy.min_signatures {
        return Err(SyncError::InsufficientCheckpointSignatures {
            required: policy.min_signatures,
            actual,
        });
    }

    Ok(())
}

fn snapshot_entries(snapshot: &StateSnapshot) -> Vec<(String, AccountState)> {
    snapshot
        .accounts
        .iter()
        .map(|entry| (entry.address.clone(), entry.state))
        .collect()
}

/// Imports a snapshot only after cryptographic verification against a finalized block.
pub fn import_verified_snapshot(
    state: &mut ChainState,
    snapshot: &StateSnapshot,
    finalized_block: &Block,
    import_mode: SnapshotImportMode,
) -> Result<(), SyncError> {
    import_verified_snapshot_with_policy(
        state,
        snapshot,
        finalized_block,
        SnapshotAdmissionPolicy::default(),
        import_mode,
    )
}

/// Imports a snapshot using explicit snapshot admission guardrails.
pub fn import_verified_snapshot_with_policy(
    state: &mut ChainState,
    snapshot: &StateSnapshot,
    finalized_block: &Block,
    admission_policy: SnapshotAdmissionPolicy,
    import_mode: SnapshotImportMode,
) -> Result<(), SyncError> {
    validate_snapshot_admission(snapshot, admission_policy)?;
    validate_snapshot_import_mode(snapshot.block_height, import_mode)?;
    verify_snapshot_against_block(snapshot, finalized_block)?;

    state
        .load_snapshot(snapshot_entries(snapshot))
        .map_err(|source| SyncError::StateImport { source })
}

/// Imports a snapshot after finalized-block checks and optional validator checkpoint verification.
pub fn import_verified_snapshot_with_checkpoint(
    state: &mut ChainState,
    snapshot: &StateSnapshot,
    finalized_block: &Block,
    checkpoint: &SnapshotCheckpoint,
    policy: CheckpointVerificationPolicy<'_>,
    import_mode: SnapshotImportMode,
) -> Result<(), SyncError> {
    import_verified_snapshot_with_checkpoint_and_policy(
        state,
        snapshot,
        finalized_block,
        checkpoint,
        policy,
        SnapshotAdmissionPolicy::default(),
        import_mode,
    )
}

/// Imports a checkpointed snapshot with explicit checkpoint + admission policies.
pub fn import_verified_snapshot_with_checkpoint_and_policy(
    state: &mut ChainState,
    snapshot: &StateSnapshot,
    finalized_block: &Block,
    checkpoint: &SnapshotCheckpoint,
    checkpoint_policy: CheckpointVerificationPolicy<'_>,
    admission_policy: SnapshotAdmissionPolicy,
    import_mode: SnapshotImportMode,
) -> Result<(), SyncError> {
    validate_snapshot_admission(snapshot, admission_policy)?;
    validate_snapshot_import_mode(snapshot.block_height, import_mode)?;
    verify_snapshot_against_block(snapshot, finalized_block)?;
    verify_snapshot_checkpoint(snapshot, checkpoint, checkpoint_policy)?;

    state
        .load_snapshot(snapshot_entries(snapshot))
        .map_err(|source| SyncError::StateImport { source })
}

/// Computes sync lag in blocks (`finalized_height - local_height`, saturating at zero).
#[must_use]
pub const fn compute_sync_lag(local_height: u64, finalized_height: u64) -> u64 {
    finalized_height.saturating_sub(local_height)
}

/// Records sync lag as a structured observability metric/event update.
pub fn record_sync_lag(
    observability: &Observability,
    local_height: u64,
    finalized_height: u64,
) -> u64 {
    observability.record_sync_lag(local_height, finalized_height);
    compute_sync_lag(local_height, finalized_height)
}

#[cfg(test)]
mod tests {
    use super::{
        CheckpointVerificationPolicy, SnapshotAdmissionPolicy, SnapshotCheckpoint,
        SnapshotChunkAssembler, SnapshotImportMode, SyncError, build_state_snapshot,
        compute_sync_lag, import_verified_snapshot, import_verified_snapshot_with_checkpoint,
        import_verified_snapshot_with_policy, record_sync_lag, sign_snapshot_checkpoint,
        split_snapshot_into_chunks, verify_snapshot_against_block, verify_snapshot_checkpoint,
    };
    use crate::core::block::{Block, BlockHeader, HASH_LENGTH};
    use crate::core::state::ChainState;
    use crate::crypto::address::{Network, derive_address};
    use crate::crypto::keys::Keypair;
    use crate::observability::Observability;

    fn address(network: Network) -> String {
        let keypair = Keypair::generate();
        let address = derive_address(&keypair.public_key_bytes(), network);
        assert!(address.is_ok(), "address derivation should succeed");
        address.unwrap_or_else(|_| unreachable!())
    }

    fn validator(network: Network) -> (Keypair, String) {
        let keypair = Keypair::generate();
        let address = derive_address(&keypair.public_key_bytes(), network);
        assert!(
            address.is_ok(),
            "validator address derivation should succeed"
        );
        (keypair, address.unwrap_or_else(|_| unreachable!()))
    }

    fn finalized_block(height: u64, proposer: String, state_root: [u8; HASH_LENGTH]) -> Block {
        let header = BlockHeader::new(
            height,
            [0_u8; HASH_LENGTH],
            state_root,
            1_717_171_999,
            proposer,
        );
        let block = Block::new_unsigned(header, Vec::new());
        assert!(block.is_ok(), "block construction should succeed");
        block.unwrap_or_else(|_| unreachable!())
    }

    #[test]
    fn snapshot_roundtrip_and_verification() {
        let network = Network::Testnet;
        let proposer = address(network);
        let sender = address(network);
        let receiver = address(network);

        let mut state = ChainState::new(network);
        assert!(
            state
                .initialize_genesis(vec![(sender, 700), (receiver, 100)])
                .is_ok()
        );

        let snapshot = build_state_snapshot(&state, 99);
        let encoded = snapshot.encode();
        assert!(encoded.is_ok(), "snapshot should serialize");
        let decoded =
            crate::core::sync::StateSnapshot::decode(&encoded.unwrap_or_else(|_| unreachable!()));
        assert!(decoded.is_ok(), "snapshot should deserialize");

        let decoded = decoded.unwrap_or_else(|_| unreachable!());
        let block = finalized_block(99, proposer, decoded.state_root);
        let verified = verify_snapshot_against_block(&decoded, &block);
        assert!(
            verified.is_ok(),
            "snapshot should match finalized block root"
        );
    }

    #[test]
    fn rejects_snapshot_payload_root_mismatch() {
        let network = Network::Testnet;
        let proposer = address(network);
        let sender = address(network);
        let receiver = address(network);

        let mut state = ChainState::new(network);
        assert!(
            state
                .initialize_genesis(vec![(sender, 700), (receiver, 100)])
                .is_ok()
        );

        let snapshot = build_state_snapshot(&state, 101);
        let block = finalized_block(101, proposer, snapshot.state_root);
        let mut tampered = snapshot;
        tampered.accounts[0].state.balance = tampered.accounts[0].state.balance.saturating_add(1);

        let verified = verify_snapshot_against_block(&tampered, &block);
        assert!(
            matches!(
                verified,
                Err(SyncError::SnapshotPayloadRootMismatch {
                    declared: _,
                    computed: _
                })
            ),
            "snapshot payload changes must be rejected when declared state root is stale"
        );
    }

    #[test]
    fn rejects_snapshot_with_non_canonical_account_order() {
        let network = Network::Devnet;
        let proposer = address(network);
        let account_a = address(network);
        let account_b = address(network);

        let mut state = ChainState::new(network);
        assert!(
            state
                .initialize_genesis(vec![(account_a, 700), (account_b, 100)])
                .is_ok()
        );

        let snapshot = build_state_snapshot(&state, 33);
        let block = finalized_block(33, proposer, snapshot.state_root);
        let mut reordered = snapshot;
        reordered.accounts.swap(0, 1);

        let verified = verify_snapshot_against_block(&reordered, &block);
        assert!(
            matches!(
                verified,
                Err(SyncError::SnapshotAccountOrderInvalid {
                    previous: _,
                    current: _
                })
            ),
            "snapshot account ordering must remain canonical to keep one deterministic root"
        );
    }

    #[test]
    fn rejects_mismatched_state_root() {
        let network = Network::Testnet;
        let proposer = address(network);
        let sender = address(network);

        let mut state = ChainState::new(network);
        assert!(state.initialize_genesis(vec![(sender, 42)]).is_ok());

        let snapshot = build_state_snapshot(&state, 7);
        let block = finalized_block(7, proposer, [9_u8; HASH_LENGTH]);

        let verified = verify_snapshot_against_block(&snapshot, &block);
        assert!(
            matches!(
                verified,
                Err(SyncError::StateRootMismatch {
                    expected: _,
                    actual: _
                })
            ),
            "state root mismatch should reject snapshot"
        );
    }

    #[test]
    fn imports_verified_snapshot_into_fresh_state() {
        let network = Network::Devnet;
        let proposer = address(network);
        let a = address(network);
        let b = address(network);

        let mut source_state = ChainState::new(network);
        assert!(
            source_state
                .initialize_genesis(vec![(a.clone(), 500), (b.clone(), 250)])
                .is_ok()
        );

        let snapshot = build_state_snapshot(&source_state, 5);
        let block = finalized_block(5, proposer, snapshot.state_root);

        let mut target_state = ChainState::new(network);
        let imported = import_verified_snapshot(
            &mut target_state,
            &snapshot,
            &block,
            SnapshotImportMode::BootstrapRecovery,
        );
        assert!(imported.is_ok(), "verified snapshot should import");

        assert_eq!(target_state.total_issued(), source_state.total_issued());
        assert_eq!(target_state.state_root(), source_state.state_root());
        assert_eq!(target_state.account(&a), source_state.account(&a));
        assert_eq!(target_state.account(&b), source_state.account(&b));
    }

    #[test]
    fn decode_with_policy_rejects_oversized_payload() {
        let bytes = vec![7_u8; 256];
        let decoded = crate::core::sync::StateSnapshot::decode_with_policy(
            &bytes,
            SnapshotAdmissionPolicy {
                max_snapshot_bytes: 64,
                max_accounts: 16,
            },
        );
        assert!(
            matches!(
                decoded,
                Err(SyncError::SnapshotByteLimitExceeded {
                    limit: 64,
                    actual: 256
                })
            ),
            "oversized payload should be rejected before deserialization"
        );
    }

    #[test]
    fn rejects_snapshot_when_account_limit_is_exceeded() {
        let network = Network::Devnet;
        let proposer = address(network);
        let a = address(network);
        let b = address(network);

        let mut source_state = ChainState::new(network);
        assert!(
            source_state
                .initialize_genesis(vec![(a, 500), (b, 250)])
                .is_ok()
        );

        let snapshot = build_state_snapshot(&source_state, 5);
        let block = finalized_block(5, proposer, snapshot.state_root);
        let mut target_state = ChainState::new(network);
        let imported = import_verified_snapshot_with_policy(
            &mut target_state,
            &snapshot,
            &block,
            SnapshotAdmissionPolicy {
                max_snapshot_bytes: 4 * 1024,
                max_accounts: 1,
            },
            SnapshotImportMode::BootstrapRecovery,
        );
        assert!(
            matches!(
                imported,
                Err(SyncError::SnapshotAccountLimitExceeded {
                    limit: 1,
                    actual: 2
                })
            ),
            "snapshot should be rejected when account-count budget is exceeded"
        );
    }

    #[test]
    fn rejects_snapshot_when_admission_policy_is_invalid() {
        let network = Network::Testnet;
        let proposer = address(network);
        let account = address(network);

        let mut source_state = ChainState::new(network);
        assert!(
            source_state
                .initialize_genesis(vec![(account, 500)])
                .is_ok()
        );

        let snapshot = build_state_snapshot(&source_state, 9);
        let block = finalized_block(9, proposer, snapshot.state_root);
        let mut target_state = ChainState::new(network);
        let imported = import_verified_snapshot_with_policy(
            &mut target_state,
            &snapshot,
            &block,
            SnapshotAdmissionPolicy {
                max_snapshot_bytes: 0,
                max_accounts: 1,
            },
            SnapshotImportMode::BootstrapRecovery,
        );
        assert!(
            matches!(
                imported,
                Err(SyncError::InvalidSnapshotAdmissionPolicy {
                    max_snapshot_bytes: 0,
                    max_accounts: 1
                })
            ),
            "zero-valued policy thresholds must be rejected"
        );
    }

    #[test]
    fn rejects_rollback_snapshot_in_steady_state_mode() {
        let network = Network::Testnet;
        let proposer = address(network);
        let account = address(network);

        let mut source_state = ChainState::new(network);
        assert!(
            source_state
                .initialize_genesis(vec![(account, 500)])
                .is_ok()
        );

        let snapshot = build_state_snapshot(&source_state, 9);
        let block = finalized_block(9, proposer, snapshot.state_root);
        let mut target_state = ChainState::new(network);
        let imported = import_verified_snapshot(
            &mut target_state,
            &snapshot,
            &block,
            SnapshotImportMode::SteadyState {
                local_finalized_height: 10,
            },
        );
        assert!(
            matches!(
                imported,
                Err(SyncError::SnapshotRollbackRejected {
                    local_finalized_height: 10,
                    snapshot_height: 9
                })
            ),
            "steady-state nodes must reject snapshots older than local finalized height"
        );
    }

    #[test]
    fn bootstrap_mode_allows_importing_older_snapshot() {
        let network = Network::Devnet;
        let proposer = address(network);
        let account = address(network);

        let mut source_state = ChainState::new(network);
        assert!(
            source_state
                .initialize_genesis(vec![(account.clone(), 777)])
                .is_ok()
        );

        let snapshot = build_state_snapshot(&source_state, 3);
        let block = finalized_block(3, proposer, snapshot.state_root);
        let mut target_state = ChainState::new(network);
        let imported = import_verified_snapshot(
            &mut target_state,
            &snapshot,
            &block,
            SnapshotImportMode::BootstrapRecovery,
        );
        assert!(
            imported.is_ok(),
            "bootstrap/recovery mode should permit importing older snapshots"
        );
        assert_eq!(
            target_state.account(&account),
            source_state.account(&account)
        );
    }

    #[test]
    fn snapshot_chunks_support_out_of_order_resume_and_reassembly() {
        let network = Network::Testnet;
        let a = address(network);
        let b = address(network);
        let c = address(network);

        let mut state = ChainState::new(network);
        assert!(
            state
                .initialize_genesis(vec![(a, 900), (b, 400), (c, 100)])
                .is_ok()
        );
        let snapshot = build_state_snapshot(&state, 44);

        let chunks = split_snapshot_into_chunks(&snapshot, 32);
        assert!(chunks.is_ok(), "snapshot chunk split should succeed");
        let chunks = chunks.unwrap_or_else(|_| unreachable!());
        assert!(
            chunks.len() > 1,
            "small chunk size should produce multiple chunks for resume simulation"
        );

        let mut first_wave = Vec::new();
        let mut second_wave = Vec::new();
        for (index, chunk) in chunks.into_iter().enumerate() {
            if index % 2 == 0 {
                first_wave.push(chunk);
            } else {
                second_wave.push(chunk);
            }
        }

        let assembler = SnapshotChunkAssembler::new(32);
        assert!(assembler.is_ok(), "assembler should initialize");
        let mut assembler = assembler.unwrap_or_else(|_| unreachable!());
        for chunk in first_wave {
            assert!(
                assembler.ingest_chunk(chunk).is_ok(),
                "first wave chunk should ingest"
            );
        }

        assert!(
            !assembler.is_complete(),
            "assembler should report incomplete state after partial delivery"
        );
        assert!(
            !assembler.missing_chunk_indices().is_empty(),
            "missing chunk set should expose resume targets"
        );

        for chunk in second_wave.into_iter().rev() {
            assert!(
                assembler.ingest_chunk(chunk).is_ok(),
                "out-of-order retry chunk should ingest"
            );
        }
        assert!(assembler.is_complete(), "all chunks should be present");

        let rebuilt = assembler.finalize(SnapshotAdmissionPolicy::default());
        assert!(
            rebuilt.is_ok(),
            "complete chunk stream should reassemble into one snapshot"
        );
        assert_eq!(
            rebuilt.unwrap_or_else(|_| unreachable!()),
            snapshot,
            "chunk reassembly must preserve exact snapshot payload"
        );
    }

    #[test]
    fn snapshot_chunks_reject_tampered_payload() {
        let network = Network::Devnet;
        let account = address(network);
        let mut state = ChainState::new(network);
        assert!(state.initialize_genesis(vec![(account, 1_000)]).is_ok());
        let snapshot = build_state_snapshot(&state, 5);

        let chunks = split_snapshot_into_chunks(&snapshot, 24);
        assert!(chunks.is_ok(), "chunk split should succeed");
        let mut chunks = chunks.unwrap_or_else(|_| unreachable!());
        let mut tampered = chunks.remove(0);
        assert!(
            !tampered.payload.is_empty(),
            "test chunk payload must be non-empty"
        );
        if let Some(first_byte) = tampered.payload.first_mut() {
            *first_byte ^= 0xAA;
        }

        let assembler = SnapshotChunkAssembler::new(24);
        assert!(assembler.is_ok());
        let mut assembler = assembler.unwrap_or_else(|_| unreachable!());
        let ingested = assembler.ingest_chunk(tampered);
        assert!(
            matches!(
                ingested,
                Err(SyncError::SnapshotChunkHashMismatch { index: 0 })
            ),
            "tampered chunk bytes must fail per-chunk integrity hash validation"
        );
    }

    #[test]
    fn snapshot_chunks_reject_mixed_stream_metadata() {
        let network = Network::Mainnet;
        let account_a = address(network);
        let account_b = address(network);
        let mut state = ChainState::new(network);
        assert!(
            state
                .initialize_genesis(vec![(account_a.clone(), 100), (account_b.clone(), 200)])
                .is_ok()
        );

        let snapshot_one = build_state_snapshot(&state, 7);
        let mut changed = state.clone();
        assert!(
            changed
                .initialize_genesis(vec![(account_a, 300), (account_b, 0)])
                .is_ok()
        );
        let snapshot_two = build_state_snapshot(&changed, 8);

        let chunks_one = split_snapshot_into_chunks(&snapshot_one, 64);
        let chunks_two = split_snapshot_into_chunks(&snapshot_two, 64);
        assert!(chunks_one.is_ok());
        assert!(chunks_two.is_ok());
        let mut chunks_one = chunks_one.unwrap_or_else(|_| unreachable!());
        let mut chunks_two = chunks_two.unwrap_or_else(|_| unreachable!());
        let first_chunk = chunks_one.remove(0);
        let second_chunk = chunks_two.remove(0);

        let assembler = SnapshotChunkAssembler::new(64);
        assert!(assembler.is_ok());
        let mut assembler = assembler.unwrap_or_else(|_| unreachable!());
        assert!(assembler.ingest_chunk(first_chunk).is_ok());

        let mixed = assembler.ingest_chunk(second_chunk);
        assert!(
            matches!(
                mixed,
                Err(SyncError::SnapshotChunkStreamInconsistent {
                    field: "block_height"
                })
            ),
            "chunks from different snapshot streams must not be mixed"
        );
    }

    #[test]
    fn snapshot_chunk_finalize_reports_missing_indices() {
        let network = Network::Devnet;
        let account = address(network);
        let mut state = ChainState::new(network);
        assert!(state.initialize_genesis(vec![(account, 77)]).is_ok());
        let snapshot = build_state_snapshot(&state, 2);

        let chunks = split_snapshot_into_chunks(&snapshot, 16);
        assert!(chunks.is_ok());
        let mut chunks = chunks.unwrap_or_else(|_| unreachable!());
        let first = chunks.remove(0);

        let assembler = SnapshotChunkAssembler::new(16);
        assert!(assembler.is_ok());
        let mut assembler = assembler.unwrap_or_else(|_| unreachable!());
        assert!(assembler.ingest_chunk(first).is_ok());
        let finalized = assembler.finalize(SnapshotAdmissionPolicy::default());
        assert!(
            matches!(
                finalized,
                Err(SyncError::SnapshotChunksIncomplete { missing: _ })
            ),
            "finalize should report missing chunks until stream is complete"
        );
    }

    #[test]
    fn checkpoint_roundtrip_serialization() {
        let network = Network::Testnet;
        let sender = address(network);
        let mut state = ChainState::new(network);
        assert!(state.initialize_genesis(vec![(sender, 42)]).is_ok());

        let snapshot = build_state_snapshot(&state, 12);
        let checkpoint = SnapshotCheckpoint::new(&snapshot, network);
        let encoded = checkpoint.encode();
        assert!(encoded.is_ok(), "checkpoint should serialize");

        let decoded = SnapshotCheckpoint::decode(&encoded.unwrap_or_else(|_| unreachable!()));
        assert!(decoded.is_ok(), "checkpoint should deserialize");
        assert_eq!(
            decoded.unwrap_or_else(|_| unreachable!()),
            checkpoint,
            "checkpoint binary encoding should roundtrip"
        );
    }

    #[test]
    fn imports_verified_snapshot_with_validator_checkpoint() {
        let network = Network::Testnet;
        let proposer = address(network);
        let account_a = address(network);
        let account_b = address(network);

        let mut source_state = ChainState::new(network);
        assert!(
            source_state
                .initialize_genesis(vec![(account_a.clone(), 800), (account_b.clone(), 200)])
                .is_ok()
        );
        let snapshot = build_state_snapshot(&source_state, 15);
        let finalized = finalized_block(15, proposer, snapshot.state_root);

        let (signer_key_one, signer_address_one) = validator(network);
        let (signer_key_two, signer_address_two) = validator(network);

        let signature_a =
            sign_snapshot_checkpoint(&snapshot, network, signer_address_one, &signer_key_one);
        let signature_b =
            sign_snapshot_checkpoint(&snapshot, network, signer_address_two, &signer_key_two);
        assert!(signature_a.is_ok(), "validator A should sign checkpoint");
        assert!(signature_b.is_ok(), "validator B should sign checkpoint");
        let signature_a = signature_a.unwrap_or_else(|_| unreachable!());
        let signature_b = signature_b.unwrap_or_else(|_| unreachable!());
        let trusted = vec![
            signature_a.validator_address.clone(),
            signature_b.validator_address.clone(),
        ];

        let mut checkpoint = SnapshotCheckpoint::new(&snapshot, network);
        checkpoint.signatures.push(signature_a);
        checkpoint.signatures.push(signature_b);

        let mut target_state = ChainState::new(network);
        let imported = import_verified_snapshot_with_checkpoint(
            &mut target_state,
            &snapshot,
            &finalized,
            &checkpoint,
            CheckpointVerificationPolicy {
                network,
                min_signatures: 2,
                trusted_validators: &trusted,
            },
            SnapshotImportMode::BootstrapRecovery,
        );
        assert!(
            imported.is_ok(),
            "verified snapshot + checkpoint should import into fresh state"
        );
        assert_eq!(target_state.state_root(), source_state.state_root());
        assert_eq!(
            target_state.account(&account_a),
            source_state.account(&account_a)
        );
        assert_eq!(
            target_state.account(&account_b),
            source_state.account(&account_b)
        );
    }

    #[test]
    fn rejects_checkpoint_with_untrusted_validator_signature() {
        let network = Network::Devnet;
        let sender = address(network);
        let proposer = address(network);
        let mut state = ChainState::new(network);
        assert!(state.initialize_genesis(vec![(sender, 999)]).is_ok());

        let snapshot = build_state_snapshot(&state, 21);
        let finalized = finalized_block(21, proposer, snapshot.state_root);

        let (trusted_key, trusted_address) = validator(network);
        let (untrusted_key, untrusted_address) = validator(network);
        let trusted = vec![trusted_address.clone()];

        let trusted_signature =
            sign_snapshot_checkpoint(&snapshot, network, trusted_address, &trusted_key);
        let untrusted_signature =
            sign_snapshot_checkpoint(&snapshot, network, untrusted_address, &untrusted_key);
        assert!(trusted_signature.is_ok());
        assert!(untrusted_signature.is_ok());

        let mut checkpoint = SnapshotCheckpoint::new(&snapshot, network);
        checkpoint
            .signatures
            .push(trusted_signature.unwrap_or_else(|_| unreachable!()));
        checkpoint
            .signatures
            .push(untrusted_signature.unwrap_or_else(|_| unreachable!()));

        let verified = verify_snapshot_checkpoint(
            &snapshot,
            &checkpoint,
            CheckpointVerificationPolicy {
                network,
                min_signatures: 1,
                trusted_validators: &trusted,
            },
        );
        assert!(
            matches!(
                verified,
                Err(SyncError::UntrustedCheckpointValidator { validator: _ })
            ),
            "signatures from validators outside trusted set must be rejected"
        );

        let mut target = ChainState::new(network);
        let imported = import_verified_snapshot_with_checkpoint(
            &mut target,
            &snapshot,
            &finalized,
            &checkpoint,
            CheckpointVerificationPolicy {
                network,
                min_signatures: 1,
                trusted_validators: &trusted,
            },
            SnapshotImportMode::BootstrapRecovery,
        );
        assert!(
            matches!(
                imported,
                Err(SyncError::UntrustedCheckpointValidator { validator: _ })
            ),
            "checkpoint verification failure must block snapshot import"
        );
    }

    #[test]
    fn rejects_checkpoint_with_insufficient_signatures() {
        let network = Network::Mainnet;
        let sender = address(network);
        let proposer = address(network);
        let mut state = ChainState::new(network);
        assert!(state.initialize_genesis(vec![(sender, 77)]).is_ok());

        let snapshot = build_state_snapshot(&state, 3);
        let _finalized = finalized_block(3, proposer, snapshot.state_root);

        let (validator_a_key, validator_a) = validator(network);
        let (_, validator_b) = validator(network);
        let trusted = vec![validator_a.clone(), validator_b];

        let signature = sign_snapshot_checkpoint(&snapshot, network, validator_a, &validator_a_key);
        assert!(signature.is_ok());

        let mut checkpoint = SnapshotCheckpoint::new(&snapshot, network);
        checkpoint
            .signatures
            .push(signature.unwrap_or_else(|_| unreachable!()));

        let verified = verify_snapshot_checkpoint(
            &snapshot,
            &checkpoint,
            CheckpointVerificationPolicy {
                network,
                min_signatures: 2,
                trusted_validators: &trusted,
            },
        );
        assert!(
            matches!(
                verified,
                Err(SyncError::InsufficientCheckpointSignatures {
                    required: 2,
                    actual: 1
                })
            ),
            "checkpoint should enforce minimum unique trusted signatures"
        );
    }

    #[test]
    fn rejects_checkpoint_with_tampered_signature() {
        let network = Network::Testnet;
        let sender = address(network);
        let mut state = ChainState::new(network);
        assert!(state.initialize_genesis(vec![(sender, 500)]).is_ok());
        let snapshot = build_state_snapshot(&state, 8);

        let (validator_key, validator_address) = validator(network);
        let trusted = vec![validator_address.clone()];
        let signature_entry =
            sign_snapshot_checkpoint(&snapshot, network, validator_address, &validator_key);
        assert!(signature_entry.is_ok(), "validator should sign checkpoint");
        let mut signature_entry = signature_entry.unwrap_or_else(|_| unreachable!());
        signature_entry.signature[0] ^= 0x01;

        let mut checkpoint = SnapshotCheckpoint::new(&snapshot, network);
        checkpoint.signatures.push(signature_entry);

        let verified = verify_snapshot_checkpoint(
            &snapshot,
            &checkpoint,
            CheckpointVerificationPolicy {
                network,
                min_signatures: 1,
                trusted_validators: &trusted,
            },
        );
        assert!(
            matches!(
                verified,
                Err(SyncError::CheckpointSignatureVerification {
                    validator: _,
                    source: _
                })
            ),
            "tampered checkpoint signatures must fail verification"
        );
    }

    #[test]
    fn rejects_checkpoint_network_mismatch() {
        let network = Network::Testnet;
        let sender = address(network);
        let mut state = ChainState::new(network);
        assert!(state.initialize_genesis(vec![(sender, 120)]).is_ok());
        let snapshot = build_state_snapshot(&state, 5);

        let mut checkpoint = SnapshotCheckpoint::new(&snapshot, Network::Mainnet);
        let (validator_key, validator_address) = validator(network);
        let trusted = vec![validator_address.clone()];
        let signature_entry = sign_snapshot_checkpoint(
            &snapshot,
            Network::Mainnet,
            validator_address,
            &validator_key,
        );
        assert!(
            signature_entry.is_err(),
            "cross-network validator signing must fail"
        );
        checkpoint.signatures.clear();

        let verified = verify_snapshot_checkpoint(
            &snapshot,
            &checkpoint,
            CheckpointVerificationPolicy {
                network,
                min_signatures: 1,
                trusted_validators: &trusted,
            },
        );
        assert!(
            matches!(
                verified,
                Err(SyncError::CheckpointNetworkMismatch {
                    expected: _,
                    actual: _
                })
            ),
            "checkpoint network byte must match verification policy"
        );
    }

    #[test]
    fn reports_sync_lag_to_observability() {
        let observability = Observability::new(8);
        let lag = record_sync_lag(&observability, 88, 100);
        assert_eq!(lag, 12);
        assert_eq!(compute_sync_lag(120, 100), 0);
        assert_eq!(observability.sync_lag_blocks(), 12);
    }
}
