//! Block data structures.

use serde::{Deserialize, Serialize};
use thiserror::Error;

use crate::core::transaction::{Transaction, TransactionError};
use crate::crypto::keys::SIGNATURE_LENGTH;

/// Hash length used by BLAKE3 in bytes.
pub const HASH_LENGTH: usize = 32;
/// Current block-header version.
pub const BLOCK_VERSION: u16 = 1;
/// Upper bound for encoded block bytes accepted during decode.
pub const MAX_BLOCK_BYTES: usize = 4 * 1024 * 1024;

/// Fixed-size 32-byte block hash.
pub type BlockHash = [u8; HASH_LENGTH];
/// Fixed-size 32-byte state root commitment.
pub type StateRoot = [u8; HASH_LENGTH];
/// Fixed-size 32-byte transactions root commitment.
pub type TransactionsRoot = [u8; HASH_LENGTH];

/// Minimal block header for Phase 1.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct BlockHeader {
    /// Protocol version of this block.
    pub version: u16,
    /// Monotonic block height.
    pub height: u64,
    /// Previous block hash (`[0; 32]` for genesis).
    pub previous_block_hash: BlockHash,
    /// State commitment after applying this block.
    pub state_root: StateRoot,
    /// Transaction set commitment.
    pub transactions_root: TransactionsRoot,
    /// Millisecond unix timestamp.
    pub timestamp_unix_ms: u64,
    /// Validator address allowed to propose this block.
    pub proposer: String,
}

/// Full block payload.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Block {
    /// Block header fields.
    pub header: BlockHeader,
    /// Ordered transactions included by proposer.
    pub transactions: Vec<Transaction>,
    /// Proposer signature over canonical header bytes.
    #[serde(with = "serde_bytes")]
    pub proposer_signature: Vec<u8>,
}

/// Block validation and codec errors.
#[derive(Debug, Clone, PartialEq, Eq, Error)]
pub enum BlockError {
    /// Proposer address is empty.
    #[error("block proposer address is empty")]
    EmptyProposer,
    /// Header version is unsupported.
    #[error("invalid block version: expected {expected}, got {actual}")]
    InvalidVersion { expected: u16, actual: u16 },
    /// Proposer signature size is not 64 bytes.
    #[error("invalid proposer signature length: expected {expected}, got {actual}")]
    InvalidSignatureLength { expected: usize, actual: usize },
    /// Header transaction root does not match block transactions.
    #[error("transactions root mismatch")]
    TransactionsRootMismatch,
    /// Included transaction failed basic validation.
    #[error("invalid transaction at index {index}")]
    InvalidTransaction {
        /// Transaction position in block ordering.
        index: usize,
        /// Underlying transaction validation error.
        source: TransactionError,
    },
    /// Block serialization failed.
    #[error("block serialization failed")]
    Serialization,
    /// Block deserialization failed.
    #[error("block deserialization failed")]
    Deserialization,
}

impl BlockHeader {
    /// Constructs a new unsigned header shell.
    #[must_use]
    pub const fn new(
        height: u64,
        previous_block_hash: BlockHash,
        state_root: StateRoot,
        timestamp_unix_ms: u64,
        proposer: String,
    ) -> Self {
        Self {
            version: BLOCK_VERSION,
            height,
            previous_block_hash,
            state_root,
            transactions_root: [0_u8; HASH_LENGTH],
            timestamp_unix_ms,
            proposer,
        }
    }
}

impl Block {
    /// Constructs an unsigned block and populates the `transactions_root`.
    pub fn new_unsigned(
        mut header: BlockHeader,
        transactions: Vec<Transaction>,
    ) -> Result<Self, BlockError> {
        header.transactions_root = compute_transactions_root(&transactions)?;
        Ok(Self {
            header,
            transactions,
            proposer_signature: Vec::new(),
        })
    }

    /// Assigns a 64-byte Ed25519 signature over `header_signing_bytes`.
    #[must_use]
    pub fn with_proposer_signature(mut self, signature: [u8; SIGNATURE_LENGTH]) -> Self {
        self.proposer_signature = signature.to_vec();
        self
    }

    /// Encodes canonical header bytes used for proposer signatures and block hash.
    pub fn header_signing_bytes(&self) -> Result<Vec<u8>, BlockError> {
        bincode::serde::encode_to_vec(
            &self.header,
            bincode::config::standard()
                .with_fixed_int_encoding()
                .with_little_endian(),
        )
        .map_err(|_| BlockError::Serialization)
    }

    /// Computes the block hash as `blake3(header_signing_bytes)`.
    pub fn hash(&self) -> Result<BlockHash, BlockError> {
        let bytes = self.header_signing_bytes()?;
        Ok(*blake3::hash(&bytes).as_bytes())
    }

    /// Encodes this block for network propagation/storage.
    pub fn encode(&self) -> Result<Vec<u8>, BlockError> {
        bincode::serde::encode_to_vec(
            self,
            bincode::config::standard()
                .with_fixed_int_encoding()
                .with_little_endian(),
        )
        .map_err(|_| BlockError::Serialization)
    }

    /// Decodes a block from network bytes.
    pub fn decode(bytes: &[u8]) -> Result<Self, BlockError> {
        bincode::serde::decode_from_slice(
            bytes,
            bincode::config::standard()
                .with_fixed_int_encoding()
                .with_little_endian()
                .with_limit::<MAX_BLOCK_BYTES>(),
        )
        .map(|(block, _)| block)
        .map_err(|_| BlockError::Deserialization)
    }

    /// Validates stateless block constraints and all included transaction payloads.
    pub fn validate_basic(&self) -> Result<(), BlockError> {
        if self.header.proposer.is_empty() {
            return Err(BlockError::EmptyProposer);
        }
        if self.header.version != BLOCK_VERSION {
            return Err(BlockError::InvalidVersion {
                expected: BLOCK_VERSION,
                actual: self.header.version,
            });
        }
        if !self.proposer_signature.is_empty() && self.proposer_signature.len() != SIGNATURE_LENGTH
        {
            return Err(BlockError::InvalidSignatureLength {
                expected: SIGNATURE_LENGTH,
                actual: self.proposer_signature.len(),
            });
        }

        let expected_transactions_root = compute_transactions_root(&self.transactions)?;
        if self.header.transactions_root != expected_transactions_root {
            return Err(BlockError::TransactionsRootMismatch);
        }

        self.transactions
            .iter()
            .enumerate()
            .try_for_each(|(index, transaction)| {
                transaction
                    .validate_basic()
                    .map_err(|source| BlockError::InvalidTransaction { index, source })
            })?;

        Ok(())
    }
}

fn compute_transactions_root(transactions: &[Transaction]) -> Result<TransactionsRoot, BlockError> {
    let mut hasher = blake3::Hasher::new();
    hasher.update(&(transactions.len() as u64).to_le_bytes());
    for transaction in transactions {
        let encoded = transaction
            .encode()
            .map_err(|_| BlockError::Serialization)?;
        hasher.update(&(encoded.len() as u64).to_le_bytes());
        hasher.update(&encoded);
    }
    Ok(*hasher.finalize().as_bytes())
}

#[cfg(test)]
mod tests {
    use super::{BLOCK_VERSION, Block, BlockError, BlockHeader, HASH_LENGTH};
    use crate::core::transaction::Transaction;

    fn sample_transactions() -> Vec<Transaction> {
        vec![
            Transaction::new_unsigned("HMA_A".to_owned(), "HMA_B".to_owned(), 10, 1, 1, 44),
            Transaction::new_unsigned("HMA_C".to_owned(), "HMA_D".to_owned(), 20, 1, 2, 77),
        ]
    }

    fn sample_header() -> BlockHeader {
        BlockHeader::new(
            42,
            [9_u8; HASH_LENGTH],
            [7_u8; HASH_LENGTH],
            1_717_171_717_u64,
            "HMA_VALIDATOR".to_owned(),
        )
    }

    #[test]
    fn new_block_populates_transactions_root() {
        let block_result = Block::new_unsigned(sample_header(), sample_transactions());
        assert!(block_result.is_ok(), "block construction should succeed");
        let block = block_result.unwrap_or_else(|_| unreachable!());

        assert_ne!(
            block.header.transactions_root, [0_u8; HASH_LENGTH],
            "transaction root should be populated by constructor"
        );
        assert!(
            block.validate_basic().is_ok(),
            "freshly built block should pass basic validation"
        );
    }

    #[test]
    fn block_hash_is_deterministic() {
        let first_result = Block::new_unsigned(sample_header(), sample_transactions());
        let second_result = Block::new_unsigned(sample_header(), sample_transactions());
        assert!(first_result.is_ok(), "first block should build");
        assert!(second_result.is_ok(), "second block should build");
        let first = first_result.unwrap_or_else(|_| unreachable!());
        let second = second_result.unwrap_or_else(|_| unreachable!());

        let first_hash = first.hash();
        let second_hash = second.hash();
        assert!(first_hash.is_ok(), "first hash should compute");
        assert!(second_hash.is_ok(), "second hash should compute");
        assert_eq!(
            first_hash.unwrap_or_else(|_| unreachable!()),
            second_hash.unwrap_or_else(|_| unreachable!()),
            "same header payload should yield the same hash"
        );
    }

    #[test]
    fn rejects_tampered_transactions_root() {
        let block_result = Block::new_unsigned(sample_header(), sample_transactions());
        assert!(block_result.is_ok(), "block construction should succeed");
        let mut block = block_result.unwrap_or_else(|_| unreachable!());
        block.header.transactions_root[0] ^= 0x01;

        assert!(
            matches!(
                block.validate_basic(),
                Err(BlockError::TransactionsRootMismatch)
            ),
            "tampered transaction root must be rejected"
        );
    }

    #[test]
    fn rejects_invalid_signature_length() {
        let block_result = Block::new_unsigned(sample_header(), sample_transactions());
        assert!(block_result.is_ok(), "block construction should succeed");
        let mut block = block_result.unwrap_or_else(|_| unreachable!());
        block.proposer_signature = vec![1_u8; 63];

        assert!(
            matches!(
                block.validate_basic(),
                Err(BlockError::InvalidSignatureLength {
                    expected: 64,
                    actual: 63
                })
            ),
            "signature must be exactly 64 bytes when present"
        );
    }

    #[test]
    fn rejects_invalid_header_version() {
        let mut header = sample_header();
        header.version = BLOCK_VERSION + 1;
        let block_result = Block::new_unsigned(header, sample_transactions());
        assert!(block_result.is_ok(), "block construction should succeed");
        let block = block_result.unwrap_or_else(|_| unreachable!());

        assert!(
            matches!(
                block.validate_basic(),
                Err(BlockError::InvalidVersion {
                    expected: BLOCK_VERSION,
                    actual: _
                })
            ),
            "unknown header versions must be rejected"
        );
    }

    #[test]
    fn full_block_encoding_roundtrip() {
        let block_result = Block::new_unsigned(sample_header(), sample_transactions());
        assert!(block_result.is_ok(), "block construction should succeed");
        let block = block_result.unwrap_or_else(|_| unreachable!());
        let encoded = block.encode();
        assert!(encoded.is_ok(), "block encoding should succeed");
        let decoded = Block::decode(&encoded.unwrap_or_else(|_| unreachable!()));
        assert!(decoded.is_ok(), "block decoding should succeed");
        assert_eq!(
            block,
            decoded.unwrap_or_else(|_| unreachable!()),
            "block should roundtrip through binary codec"
        );
    }

    #[test]
    fn decode_rejects_malicious_length_prefix_payload() {
        let payload = [
            34, 17, 0, 0, 0, 0, 0, 0, 0, 34, 34, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
            0, 0, 0, 0, 0, 0, 0, 0, 255, 255, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
            0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 255, 255, 0,
            0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
            0, 0, 0, 0, 76, 76, 76, 16,
        ];
        let decoded = Block::decode(&payload);
        assert!(
            matches!(decoded, Err(BlockError::Deserialization)),
            "malicious payload should fail decode without oversized allocation"
        );
    }
}
