//! Client-side proof-of-work (`PoW`) puzzle and verification.

use thiserror::Error;

use crate::core::transaction::{Transaction, TransactionError};

/// BLAKE3 digest size in bits.
pub const POW_HASH_BITS: u16 = 256;

/// Successful `PoW` search result.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PowSolution {
    /// Nonce that satisfied the target difficulty.
    pub nonce: u64,
    /// Final hash computed for `nonce`.
    pub hash: [u8; 32],
    /// Number of leading zero bits in `hash`.
    pub leading_zero_bits: u16,
    /// Number of attempted nonce values.
    pub attempts: u64,
}

/// Errors emitted by `PoW` mining and verification.
#[derive(Debug, Clone, PartialEq, Eq, Error)]
pub enum PowError {
    /// Difficulty is outside the supported 0..=256 bit range.
    #[error("invalid PoW difficulty bits: expected 0..={max}, got {actual}")]
    InvalidDifficulty {
        /// Highest accepted difficulty value.
        max: u16,
        /// Provided difficulty value.
        actual: u16,
    },
    /// Transaction canonical byte serialization failed.
    #[error("failed to build PoW preimage from transaction")]
    TransactionEncoding,
    /// Nonce search exhausted the configured range.
    #[error("no PoW solution found in nonce range")]
    NonceExhausted,
}

/// Mines a transaction `pow_nonce` in the inclusive range [`start_nonce`, `end_nonce`].
///
/// The puzzle target is: `blake3(transaction_signing_bytes)`, where
/// `transaction_signing_bytes` includes the candidate `pow_nonce` and excludes signatures.
pub fn mine_pow_nonce(
    transaction: &Transaction,
    difficulty_bits: u16,
    start_nonce: u64,
    end_nonce: u64,
) -> Result<PowSolution, PowError> {
    validate_difficulty(difficulty_bits)?;

    let mut candidate = transaction.clone();
    let mut attempts = 0_u64;

    for nonce in start_nonce..=end_nonce {
        candidate.pow_nonce = nonce;
        let hash = transaction_pow_hash(&candidate)?;
        let zero_bits = leading_zero_bits(&hash);
        attempts = attempts.saturating_add(1);

        if zero_bits >= difficulty_bits {
            return Ok(PowSolution {
                nonce,
                hash,
                leading_zero_bits: zero_bits,
                attempts,
            });
        }
    }

    Err(PowError::NonceExhausted)
}

/// Verifies whether a transaction satisfies the supplied `PoW` difficulty.
pub fn verify_pow(transaction: &Transaction, difficulty_bits: u16) -> Result<bool, PowError> {
    validate_difficulty(difficulty_bits)?;
    let hash = transaction_pow_hash(transaction)?;
    Ok(leading_zero_bits(&hash) >= difficulty_bits)
}

/// Computes the canonical hash used for `PoW` checks.
pub fn transaction_pow_hash(transaction: &Transaction) -> Result<[u8; 32], PowError> {
    let preimage = transaction
        .signing_bytes()
        .map_err(|_: TransactionError| PowError::TransactionEncoding)?;
    Ok(*blake3::hash(&preimage).as_bytes())
}

/// Counts leading zero bits in a 32-byte hash.
#[must_use]
pub fn leading_zero_bits(hash: &[u8; 32]) -> u16 {
    let mut count = 0_u16;
    for byte in hash {
        if *byte == 0 {
            count += 8;
            continue;
        }
        let mut bits = *byte;
        let mut local_count = 0_u16;
        while (bits & 0b1000_0000) == 0 {
            local_count += 1;
            bits <<= 1;
        }
        count += local_count;
        return count;
    }
    count
}

const fn validate_difficulty(difficulty_bits: u16) -> Result<(), PowError> {
    if difficulty_bits > POW_HASH_BITS {
        return Err(PowError::InvalidDifficulty {
            max: POW_HASH_BITS,
            actual: difficulty_bits,
        });
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::{
        POW_HASH_BITS, PowError, leading_zero_bits, mine_pow_nonce, transaction_pow_hash,
        verify_pow,
    };
    use crate::core::transaction::Transaction;
    use crate::crypto::address::{Network, derive_address};
    use crate::crypto::keys::Keypair;

    fn sample_transaction() -> Transaction {
        let sender_keypair = Keypair::generate();
        let receiver_keypair = Keypair::generate();
        let sender_address_result =
            derive_address(&sender_keypair.public_key_bytes(), Network::Testnet);
        let receiver_address_result =
            derive_address(&receiver_keypair.public_key_bytes(), Network::Testnet);
        assert!(
            sender_address_result.is_ok(),
            "sender address derivation should succeed"
        );
        assert!(
            receiver_address_result.is_ok(),
            "receiver address derivation should succeed"
        );

        Transaction::new_unsigned(
            sender_address_result.unwrap_or_else(|_| unreachable!()),
            receiver_address_result.unwrap_or_else(|_| unreachable!()),
            100,
            1,
            1,
            0,
        )
        .with_sender_public_key(sender_keypair.public_key_bytes())
    }

    #[test]
    fn mines_and_verifies_valid_pow_nonce() {
        let transaction = sample_transaction();
        let solution = mine_pow_nonce(&transaction, 12, 0, 5_000_000);
        assert!(
            solution.is_ok(),
            "should find a valid nonce for low difficulty in bounded range"
        );
        let solution = solution.unwrap_or_else(|_| unreachable!());

        let mut mined = transaction;
        mined.pow_nonce = solution.nonce;

        let verify_result = verify_pow(&mined, 12);
        assert!(verify_result.is_ok(), "verification should run");
        assert!(
            verify_result.unwrap_or(false),
            "mined nonce must satisfy target difficulty"
        );
    }

    #[test]
    fn rejects_invalid_difficulty() {
        let transaction = sample_transaction();
        let mined = mine_pow_nonce(&transaction, POW_HASH_BITS + 1, 0, 10);
        assert!(
            matches!(
                mined,
                Err(PowError::InvalidDifficulty {
                    max: POW_HASH_BITS,
                    actual: _
                })
            ),
            "difficulty above 256 bits must be rejected"
        );
    }

    #[test]
    fn verification_rejects_tampered_nonce() {
        let transaction = sample_transaction();
        let solution = mine_pow_nonce(&transaction, 10, 0, 5_000_000);
        assert!(solution.is_ok(), "nonce mining should succeed");
        let solution = solution.unwrap_or_else(|_| unreachable!());

        let mut mined = transaction;
        mined.pow_nonce = solution.nonce;

        let mut tampered = mined.clone();
        tampered.pow_nonce = tampered.pow_nonce.saturating_add(1);

        let verify_original = verify_pow(&mined, 10);
        let verify_tampered = verify_pow(&tampered, 10);
        assert!(verify_original.is_ok(), "verification should run");
        assert!(verify_tampered.is_ok(), "verification should run");
        assert!(
            verify_original.unwrap_or(false),
            "original mined nonce should pass verification"
        );
        assert!(
            !verify_tampered.unwrap_or(true),
            "tampered nonce should fail verification"
        );
    }

    #[test]
    fn nonce_exhaustion_is_reported() {
        let transaction = sample_transaction();
        let result = mine_pow_nonce(&transaction, 64, 0, 32);
        assert!(
            matches!(result, Err(PowError::NonceExhausted)),
            "small search window should fail for high difficulty"
        );
    }

    #[test]
    fn leading_zero_count_matches_known_values() {
        let all_zero = [0_u8; 32];
        assert_eq!(leading_zero_bits(&all_zero), 256);

        let mut four_zero_bits = [0_u8; 32];
        four_zero_bits[0] = 0b0000_1111;
        assert_eq!(leading_zero_bits(&four_zero_bits), 4);

        let mut nine_zero_bits = [0_u8; 32];
        nine_zero_bits[0] = 0;
        nine_zero_bits[1] = 0b0111_1111;
        assert_eq!(leading_zero_bits(&nine_zero_bits), 9);
    }

    #[test]
    fn pow_hash_changes_when_nonce_changes() {
        let mut tx_a = sample_transaction();
        tx_a.pow_nonce = 1;
        let mut tx_b = sample_transaction();
        tx_b.pow_nonce = 2;

        let hash_a = transaction_pow_hash(&tx_a);
        let hash_b = transaction_pow_hash(&tx_b);
        assert!(hash_a.is_ok(), "hashing should succeed");
        assert!(hash_b.is_ok(), "hashing should succeed");
        assert_ne!(
            hash_a.unwrap_or_else(|_| unreachable!()),
            hash_b.unwrap_or_else(|_| unreachable!()),
            "different nonces should produce different PoW hash values"
        );
    }
}
