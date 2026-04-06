//! Transaction data structures.

use serde::{Deserialize, Serialize};
use thiserror::Error;

use crate::crypto::address::{AddressError, Network, parse_address, validate_address_for_network};
use crate::crypto::keys::{CryptoError, PUBLIC_KEY_LENGTH, SIGNATURE_LENGTH, verify_signature};

/// Monetary amount in micro-homas.
pub type Amount = u64;
/// Monotonic account nonce used for replay protection.
pub type AccountNonce = u64;
/// Client-side `PoW` nonce included in transaction payload.
pub type PowNonce = u64;
/// Upper bound for encoded transaction payloads accepted from untrusted input.
pub const MAX_TRANSACTION_BYTES: usize = 16 * 1024;
/// Explicit signature-domain separator for transaction signing payloads.
pub const TRANSACTION_SIGNATURE_DOMAIN_SEPARATOR: [u8; 14] = *b"HOMA_TX_SIG_V1";

/// Transfer transaction for Homa's account-based ledger.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Transaction {
    /// Sender account address (`HMA...`).
    pub sender: String,
    /// Receiver account address (`HMA...`).
    pub receiver: String,
    /// Amount to transfer in micro-homas.
    pub amount: Amount,
    /// Transaction fee in micro-homas.
    pub fee: Amount,
    /// Sender-side transaction counter.
    pub nonce: AccountNonce,
    /// Client-side `PoW` solution nonce.
    pub pow_nonce: PowNonce,
    /// Sender Ed25519 public key used for address-authority proof.
    #[serde(with = "serde_bytes")]
    pub sender_public_key: Vec<u8>,
    /// Ed25519 signature over canonical signing bytes.
    #[serde(with = "serde_bytes")]
    pub signature: Vec<u8>,
}

/// Borrowed transaction view decoded directly from a network byte slice.
///
/// This representation enables zero-copy parsing in hot networking paths where
/// callers may inspect payload fields before deciding whether to materialize an
/// owned [`Transaction`].
#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize)]
pub struct BorrowedTransaction<'a> {
    /// Sender account address (`HMA...`).
    #[serde(borrow)]
    pub sender: &'a str,
    /// Receiver account address (`HMA...`).
    #[serde(borrow)]
    pub receiver: &'a str,
    /// Amount to transfer in micro-homas.
    pub amount: Amount,
    /// Transaction fee in micro-homas.
    pub fee: Amount,
    /// Sender-side transaction counter.
    pub nonce: AccountNonce,
    /// Client-side `PoW` solution nonce.
    pub pow_nonce: PowNonce,
    /// Sender Ed25519 public key used for address-authority proof.
    #[serde(borrow, with = "serde_bytes")]
    pub sender_public_key: &'a [u8],
    /// Ed25519 signature over canonical signing bytes.
    #[serde(borrow, with = "serde_bytes")]
    pub signature: &'a [u8],
}

impl BorrowedTransaction<'_> {
    /// Materializes an owned transaction copy from a borrowed view.
    #[must_use]
    pub fn into_owned(self) -> Transaction {
        Transaction {
            sender: self.sender.to_owned(),
            receiver: self.receiver.to_owned(),
            amount: self.amount,
            fee: self.fee,
            nonce: self.nonce,
            pow_nonce: self.pow_nonce,
            sender_public_key: self.sender_public_key.to_vec(),
            signature: self.signature.to_vec(),
        }
    }
}

/// Canonical pre-signing payload (excludes signature field).
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
struct TransactionSigningPayload<'a> {
    sender: &'a str,
    receiver: &'a str,
    amount: Amount,
    fee: Amount,
    nonce: AccountNonce,
    pow_nonce: PowNonce,
    #[serde(with = "serde_bytes")]
    sender_public_key: &'a [u8],
}

/// Canonical signing envelope that binds signatures to one chain domain.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
struct TransactionSigningEnvelope<'a> {
    domain_separator: [u8; 14],
    network: u8,
    payload: TransactionSigningPayload<'a>,
}

/// Errors emitted by transaction validation and binary codec routines.
#[derive(Debug, Clone, PartialEq, Eq, Error)]
pub enum TransactionError {
    /// Sender address is empty.
    #[error("sender address is empty")]
    EmptySender,
    /// Receiver address is empty.
    #[error("receiver address is empty")]
    EmptyReceiver,
    /// Sender and receiver must differ.
    #[error("sender and receiver must differ")]
    SameSenderReceiver,
    /// Zero-value transfer is rejected.
    #[error("transaction amount must be greater than zero")]
    ZeroAmount,
    /// Signature size is not 64 bytes.
    #[error("invalid signature length: expected {expected}, got {actual}")]
    InvalidSignatureLength { expected: usize, actual: usize },
    /// Sender public key is missing.
    #[error("sender public key is missing")]
    MissingSenderPublicKey,
    /// Sender public key size is not 32 bytes.
    #[error("invalid sender public key length: expected {expected}, got {actual}")]
    InvalidSenderPublicKeyLength { expected: usize, actual: usize },
    /// Signature is required for sender-authority validation.
    #[error("transaction signature is missing")]
    MissingSignature,
    /// Sender public key does not match sender address hash.
    #[error("sender authority mismatch: public key does not match sender address")]
    SenderAuthorityMismatch,
    /// Signature verification failed for sender authority proof.
    #[error("signature verification failed for sender authority proof")]
    SignatureVerification {
        /// Inner signature verification error.
        source: CryptoError,
    },
    /// `amount + fee` overflowed.
    #[error("amount + fee overflowed")]
    AmountOverflow,
    /// Sender address failed parsing/network checks.
    #[error("invalid sender address")]
    InvalidSenderAddress {
        /// Inner address parsing error.
        source: AddressError,
    },
    /// Receiver address failed parsing/network checks.
    #[error("invalid receiver address")]
    InvalidReceiverAddress {
        /// Inner address parsing error.
        source: AddressError,
    },
    /// Sender and receiver are not from the same network domain.
    #[error("transaction network domain mismatch: sender={sender}, receiver={receiver}")]
    NetworkDomainMismatch {
        /// Sender network.
        sender: Network,
        /// Receiver network.
        receiver: Network,
    },
    /// Transaction serialization failed.
    #[error("transaction serialization failed")]
    Serialization,
    /// Transaction deserialization failed.
    #[error("transaction deserialization failed")]
    Deserialization,
}

impl Transaction {
    /// Creates an unsigned transaction payload.
    #[must_use]
    pub const fn new_unsigned(
        sender: String,
        receiver: String,
        amount: Amount,
        fee: Amount,
        nonce: AccountNonce,
        pow_nonce: PowNonce,
    ) -> Self {
        Self {
            sender,
            receiver,
            amount,
            fee,
            nonce,
            pow_nonce,
            sender_public_key: Vec::new(),
            signature: Vec::new(),
        }
    }

    /// Assigns the sender public key used for authority binding.
    #[must_use]
    pub fn with_sender_public_key(mut self, sender_public_key: [u8; PUBLIC_KEY_LENGTH]) -> Self {
        self.sender_public_key = sender_public_key.to_vec();
        self
    }

    /// Assigns a 64-byte Ed25519 signature to this transaction.
    #[must_use]
    pub fn with_signature(mut self, signature: [u8; SIGNATURE_LENGTH]) -> Self {
        self.signature = signature.to_vec();
        self
    }

    /// Returns canonical signing bytes domain-separated by sender/receiver network.
    pub fn signing_bytes(&self) -> Result<Vec<u8>, TransactionError> {
        let sender_network = parse_address(&self.sender)
            .map_err(|source| TransactionError::InvalidSenderAddress { source })?
            .network;
        let receiver_network = parse_address(&self.receiver)
            .map_err(|source| TransactionError::InvalidReceiverAddress { source })?
            .network;
        if sender_network != receiver_network {
            return Err(TransactionError::NetworkDomainMismatch {
                sender: sender_network,
                receiver: receiver_network,
            });
        }
        self.signing_bytes_for_network(sender_network)
    }

    /// Returns canonical signing bytes explicitly bound to one expected network.
    pub fn signing_bytes_for_network(&self, network: Network) -> Result<Vec<u8>, TransactionError> {
        validate_address_for_network(&self.sender, network)
            .map_err(|source| TransactionError::InvalidSenderAddress { source })?;
        validate_address_for_network(&self.receiver, network)
            .map_err(|source| TransactionError::InvalidReceiverAddress { source })?;

        let payload = TransactionSigningPayload {
            sender: &self.sender,
            receiver: &self.receiver,
            amount: self.amount,
            fee: self.fee,
            nonce: self.nonce,
            pow_nonce: self.pow_nonce,
            sender_public_key: self.sender_public_key.as_slice(),
        };
        let envelope = TransactionSigningEnvelope {
            domain_separator: TRANSACTION_SIGNATURE_DOMAIN_SEPARATOR,
            network: network.as_byte(),
            payload,
        };

        bincode::serde::encode_to_vec(
            &envelope,
            bincode::config::standard()
                .with_fixed_int_encoding()
                .with_little_endian(),
        )
        .map_err(|_| TransactionError::Serialization)
    }

    /// Encodes the full signed transaction for network propagation/storage.
    pub fn encode(&self) -> Result<Vec<u8>, TransactionError> {
        bincode::serde::encode_to_vec(
            self,
            bincode::config::standard()
                .with_fixed_int_encoding()
                .with_little_endian(),
        )
        .map_err(|_| TransactionError::Serialization)
    }

    /// Decodes a full transaction from network bytes.
    pub fn decode(bytes: &[u8]) -> Result<Self, TransactionError> {
        bincode::serde::decode_from_slice(
            bytes,
            bincode::config::standard()
                .with_fixed_int_encoding()
                .with_little_endian()
                .with_limit::<MAX_TRANSACTION_BYTES>(),
        )
        .map(|(transaction, _)| transaction)
        .map_err(|_| TransactionError::Deserialization)
    }

    /// Decodes a borrowed transaction view from network bytes without copying
    /// string/byte fields.
    pub fn decode_borrowed(bytes: &[u8]) -> Result<BorrowedTransaction<'_>, TransactionError> {
        bincode::serde::borrow_decode_from_slice(
            bytes,
            bincode::config::standard()
                .with_fixed_int_encoding()
                .with_little_endian()
                .with_limit::<MAX_TRANSACTION_BYTES>(),
        )
        .map(|(transaction, _)| transaction)
        .map_err(|_| TransactionError::Deserialization)
    }

    /// Computes sender debited value (`amount + fee`), with overflow checks.
    pub fn debited_total(&self) -> Result<Amount, TransactionError> {
        self.amount
            .checked_add(self.fee)
            .ok_or(TransactionError::AmountOverflow)
    }

    /// Performs stateless validity checks before mempool admission.
    pub fn validate_basic(&self) -> Result<(), TransactionError> {
        if self.sender.is_empty() {
            return Err(TransactionError::EmptySender);
        }
        if self.receiver.is_empty() {
            return Err(TransactionError::EmptyReceiver);
        }
        if self.sender == self.receiver {
            return Err(TransactionError::SameSenderReceiver);
        }
        if self.amount == 0 {
            return Err(TransactionError::ZeroAmount);
        }
        if !self.sender_public_key.is_empty() && self.sender_public_key.len() != PUBLIC_KEY_LENGTH {
            return Err(TransactionError::InvalidSenderPublicKeyLength {
                expected: PUBLIC_KEY_LENGTH,
                actual: self.sender_public_key.len(),
            });
        }
        if !self.signature.is_empty() && self.signature.len() != SIGNATURE_LENGTH {
            return Err(TransactionError::InvalidSignatureLength {
                expected: SIGNATURE_LENGTH,
                actual: self.signature.len(),
            });
        }
        self.debited_total()?;
        Ok(())
    }

    /// Validates sender ownership proof against expected network domain.
    pub fn validate_sender_authority_for_network(
        &self,
        network: Network,
    ) -> Result<(), TransactionError> {
        let parsed_sender = validate_address_for_network(&self.sender, network)
            .map_err(|source| TransactionError::InvalidSenderAddress { source })?;
        validate_address_for_network(&self.receiver, network)
            .map_err(|source| TransactionError::InvalidReceiverAddress { source })?;

        if self.sender_public_key.is_empty() {
            return Err(TransactionError::MissingSenderPublicKey);
        }
        if self.sender_public_key.len() != PUBLIC_KEY_LENGTH {
            return Err(TransactionError::InvalidSenderPublicKeyLength {
                expected: PUBLIC_KEY_LENGTH,
                actual: self.sender_public_key.len(),
            });
        }
        if self.signature.is_empty() {
            return Err(TransactionError::MissingSignature);
        }
        if self.signature.len() != SIGNATURE_LENGTH {
            return Err(TransactionError::InvalidSignatureLength {
                expected: SIGNATURE_LENGTH,
                actual: self.signature.len(),
            });
        }

        let sender_key_hash = blake3::hash(&self.sender_public_key);
        if sender_key_hash.as_bytes() != &parsed_sender.key_hash {
            return Err(TransactionError::SenderAuthorityMismatch);
        }

        let signing_bytes = self.signing_bytes_for_network(network)?;
        verify_signature(&self.sender_public_key, &signing_bytes, &self.signature)
            .map_err(|source| TransactionError::SignatureVerification { source })
    }
}

#[cfg(test)]
mod tests {
    use super::{Amount, Transaction, TransactionError};
    use crate::crypto::address::{Network, derive_address};
    use crate::crypto::keys::{Keypair, verify_signature};

    fn address_from_seed(network: Network, seed: u8) -> String {
        let keypair_result = Keypair::from_secret_key(&[seed; 32]);
        assert!(keypair_result.is_ok(), "seeded keypair should be valid");
        let keypair = keypair_result.unwrap_or_else(|_| unreachable!());
        let derived = derive_address(&keypair.public_key_bytes(), network);
        assert!(derived.is_ok(), "address derivation should succeed");
        derived.unwrap_or_else(|_| unreachable!())
    }

    fn sample_unsigned() -> Transaction {
        Transaction::new_unsigned(
            address_from_seed(Network::Testnet, 21),
            address_from_seed(Network::Testnet, 22),
            25_u64,
            1_u64,
            9_u64,
            991_u64,
        )
    }

    fn signed_authorized_transaction(
        network: Network,
        sender_seed: u8,
        receiver_seed: u8,
        nonce: u64,
        fee: u64,
    ) -> Transaction {
        let sender_keypair_result = Keypair::from_secret_key(&[sender_seed; 32]);
        assert!(
            sender_keypair_result.is_ok(),
            "seeded sender keypair should be valid"
        );
        let sender_keypair = sender_keypair_result.unwrap_or_else(|_| unreachable!());
        let sender_address_result = derive_address(&sender_keypair.public_key_bytes(), network);
        assert!(
            sender_address_result.is_ok(),
            "sender address derivation should succeed"
        );
        let receiver_address = address_from_seed(network, receiver_seed);

        let unsigned = Transaction::new_unsigned(
            sender_address_result.unwrap_or_else(|_| unreachable!()),
            receiver_address,
            100,
            fee,
            nonce,
            0,
        )
        .with_sender_public_key(sender_keypair.public_key_bytes());
        let signing_bytes = unsigned.signing_bytes_for_network(network);
        assert!(
            signing_bytes.is_ok(),
            "signed authority transaction payload should encode"
        );
        unsigned
            .with_signature(sender_keypair.sign(&signing_bytes.unwrap_or_else(|_| unreachable!())))
    }

    #[test]
    fn signing_bytes_exclude_signature_field() {
        let mut transaction = sample_unsigned();
        let before = transaction.signing_bytes();
        assert!(
            before.is_ok(),
            "unsigned transaction signing bytes should encode"
        );
        let before_bytes = before.unwrap_or_else(|_| unreachable!());

        transaction.signature = vec![7_u8; 64];
        let after = transaction.signing_bytes();
        assert!(
            after.is_ok(),
            "signed transaction signing bytes should encode"
        );
        let after_bytes = after.unwrap_or_else(|_| unreachable!());

        assert_eq!(
            before_bytes, after_bytes,
            "signature must not influence pre-signing bytes"
        );
    }

    #[test]
    fn validates_signature_over_signing_bytes() {
        let keypair_result = Keypair::from_secret_key(&[31; 32]);
        assert!(keypair_result.is_ok(), "seeded keypair should be valid");
        let keypair = keypair_result.unwrap_or_else(|_| unreachable!());
        let sender_address_result = derive_address(&keypair.public_key_bytes(), Network::Testnet);
        assert!(
            sender_address_result.is_ok(),
            "address derivation should succeed"
        );

        let transaction = Transaction::new_unsigned(
            sender_address_result.unwrap_or_else(|_| unreachable!()),
            address_from_seed(Network::Testnet, 32),
            1_000_u64,
            10_u64,
            3_u64,
            55_u64,
        )
        .with_sender_public_key(keypair.public_key_bytes());

        let payload_result = transaction.signing_bytes();
        assert!(payload_result.is_ok(), "signing bytes should encode");
        let payload = payload_result.unwrap_or_else(|_| unreachable!());
        let signature = keypair.sign(&payload);
        let signed = transaction.with_signature(signature);

        let verify_result =
            verify_signature(&keypair.public_key_bytes(), &payload, &signed.signature);
        assert!(
            verify_result.is_ok(),
            "transaction signing payload must verify with sender key"
        );
    }

    #[test]
    fn signing_bytes_for_network_rejects_mismatch() {
        let transaction = sample_unsigned();
        let payload = transaction.signing_bytes_for_network(Network::Mainnet);
        assert!(
            matches!(
                payload,
                Err(TransactionError::InvalidSenderAddress { source: _ })
            ),
            "explicit network signing must reject cross-network transactions"
        );
    }

    #[test]
    fn signing_bytes_differ_across_network_domains() {
        let sender_keypair_result = Keypair::from_secret_key(&[41; 32]);
        let receiver_keypair_result = Keypair::from_secret_key(&[42; 32]);
        assert!(sender_keypair_result.is_ok());
        assert!(receiver_keypair_result.is_ok());
        let sender_keypair = sender_keypair_result.unwrap_or_else(|_| unreachable!());
        let receiver_keypair = receiver_keypair_result.unwrap_or_else(|_| unreachable!());

        let sender_main_result =
            derive_address(&sender_keypair.public_key_bytes(), Network::Mainnet);
        let sender_test_result =
            derive_address(&sender_keypair.public_key_bytes(), Network::Testnet);
        let receiver_main_result =
            derive_address(&receiver_keypair.public_key_bytes(), Network::Mainnet);
        let receiver_test_result =
            derive_address(&receiver_keypair.public_key_bytes(), Network::Testnet);
        assert!(sender_main_result.is_ok());
        assert!(sender_test_result.is_ok());
        assert!(receiver_main_result.is_ok());
        assert!(receiver_test_result.is_ok());

        let tx_main = Transaction::new_unsigned(
            sender_main_result.unwrap_or_else(|_| unreachable!()),
            receiver_main_result.unwrap_or_else(|_| unreachable!()),
            5,
            1,
            1,
            1,
        )
        .with_sender_public_key(sender_keypair.public_key_bytes());
        let tx_test = Transaction::new_unsigned(
            sender_test_result.unwrap_or_else(|_| unreachable!()),
            receiver_test_result.unwrap_or_else(|_| unreachable!()),
            5,
            1,
            1,
            1,
        )
        .with_sender_public_key(sender_keypair.public_key_bytes());

        let main_bytes = tx_main.signing_bytes();
        let test_bytes = tx_test.signing_bytes();
        assert!(main_bytes.is_ok(), "mainnet signing bytes should encode");
        assert!(test_bytes.is_ok(), "testnet signing bytes should encode");
        assert_ne!(
            main_bytes.unwrap_or_else(|_| unreachable!()),
            test_bytes.unwrap_or_else(|_| unreachable!()),
            "network domain separation must alter signing payload bytes"
        );
    }

    #[test]
    fn signatures_do_not_replay_across_network_domains() {
        let sender_keypair_result = Keypair::from_secret_key(&[51; 32]);
        let receiver_keypair_result = Keypair::from_secret_key(&[52; 32]);
        assert!(sender_keypair_result.is_ok());
        assert!(receiver_keypair_result.is_ok());
        let sender_keypair = sender_keypair_result.unwrap_or_else(|_| unreachable!());
        let receiver_keypair = receiver_keypair_result.unwrap_or_else(|_| unreachable!());

        let sender_main_result =
            derive_address(&sender_keypair.public_key_bytes(), Network::Mainnet);
        let sender_test_result =
            derive_address(&sender_keypair.public_key_bytes(), Network::Testnet);
        let receiver_main_result =
            derive_address(&receiver_keypair.public_key_bytes(), Network::Mainnet);
        let receiver_test_result =
            derive_address(&receiver_keypair.public_key_bytes(), Network::Testnet);
        assert!(sender_main_result.is_ok());
        assert!(sender_test_result.is_ok());
        assert!(receiver_main_result.is_ok());
        assert!(receiver_test_result.is_ok());

        let tx_main = Transaction::new_unsigned(
            sender_main_result.unwrap_or_else(|_| unreachable!()),
            receiver_main_result.unwrap_or_else(|_| unreachable!()),
            9,
            2,
            7,
            3,
        )
        .with_sender_public_key(sender_keypair.public_key_bytes());
        let tx_test = Transaction::new_unsigned(
            sender_test_result.unwrap_or_else(|_| unreachable!()),
            receiver_test_result.unwrap_or_else(|_| unreachable!()),
            9,
            2,
            7,
            3,
        )
        .with_sender_public_key(sender_keypair.public_key_bytes());

        let main_bytes_result = tx_main.signing_bytes();
        let test_bytes_result = tx_test.signing_bytes();
        assert!(main_bytes_result.is_ok());
        assert!(test_bytes_result.is_ok());
        let main_bytes = main_bytes_result.unwrap_or_else(|_| unreachable!());
        let test_bytes = test_bytes_result.unwrap_or_else(|_| unreachable!());

        let signature = sender_keypair.sign(&main_bytes);
        let valid_on_main =
            verify_signature(&sender_keypair.public_key_bytes(), &main_bytes, &signature);
        let replay_on_test =
            verify_signature(&sender_keypair.public_key_bytes(), &test_bytes, &signature);

        assert!(
            valid_on_main.is_ok(),
            "signature must verify on original network-domain bytes"
        );
        assert!(
            replay_on_test.is_err(),
            "same signature must fail on different network-domain bytes"
        );
    }

    #[test]
    fn roundtrip_full_transaction_encoding() {
        let keypair = Keypair::generate();
        let transaction = sample_unsigned().with_sender_public_key(keypair.public_key_bytes());
        let signing_bytes = transaction.signing_bytes();
        assert!(signing_bytes.is_ok(), "signing bytes should encode");
        let signature = keypair.sign(&signing_bytes.unwrap_or_else(|_| unreachable!()));
        let signed = transaction.with_signature(signature);

        let encoded = signed.encode();
        assert!(encoded.is_ok(), "transaction encoding should succeed");
        let decoded = Transaction::decode(&encoded.unwrap_or_else(|_| unreachable!()));
        assert!(decoded.is_ok(), "transaction decoding should succeed");
        assert_eq!(
            signed,
            decoded.unwrap_or_else(|_| unreachable!()),
            "encoded transaction should roundtrip byte-for-byte semantically"
        );
    }

    #[test]
    fn borrowed_decode_roundtrip_matches_owned_transaction() {
        let transaction = signed_authorized_transaction(Network::Testnet, 111, 112, 3, 5);
        let encoded = transaction.encode();
        assert!(encoded.is_ok(), "transaction encoding should succeed");
        let encoded = encoded.unwrap_or_else(|_| unreachable!());

        let borrowed = Transaction::decode_borrowed(&encoded);
        assert!(
            borrowed.is_ok(),
            "borrowed decode should succeed for valid payload"
        );
        let borrowed = borrowed.unwrap_or_else(|_| unreachable!());
        let materialized = borrowed.into_owned();

        assert_eq!(
            materialized, transaction,
            "borrowed decode must preserve full transaction payload when materialized"
        );
    }

    #[test]
    fn rejects_invalid_signature_length() {
        let mut transaction = sample_unsigned();
        transaction.signature = vec![1_u8; 63];
        let result = transaction.validate_basic();
        assert!(
            matches!(
                result,
                Err(TransactionError::InvalidSignatureLength {
                    expected: 64,
                    actual: 63
                })
            ),
            "signature length must be exactly 64 bytes when present"
        );
    }

    #[test]
    fn rejects_invalid_sender_public_key_length() {
        let mut transaction = sample_unsigned();
        transaction.sender_public_key = vec![3_u8; 31];
        let result = transaction.validate_basic();
        assert!(
            matches!(
                result,
                Err(TransactionError::InvalidSenderPublicKeyLength {
                    expected: 32,
                    actual: 31
                })
            ),
            "sender public key length must be exactly 32 bytes when present"
        );
    }

    #[test]
    fn sender_authority_validation_accepts_valid_signature() {
        let transaction = signed_authorized_transaction(Network::Testnet, 71, 72, 1, 2);
        let result = transaction.validate_sender_authority_for_network(Network::Testnet);
        assert!(
            result.is_ok(),
            "sender authority should validate for matching key/address/signature"
        );
    }

    #[test]
    fn sender_authority_validation_requires_sender_public_key() {
        let keypair_result = Keypair::from_secret_key(&[81; 32]);
        assert!(keypair_result.is_ok());
        let keypair = keypair_result.unwrap_or_else(|_| unreachable!());
        let sender_address_result = derive_address(&keypair.public_key_bytes(), Network::Testnet);
        assert!(sender_address_result.is_ok());
        let receiver_address = address_from_seed(Network::Testnet, 82);

        let unsigned = Transaction::new_unsigned(
            sender_address_result.unwrap_or_else(|_| unreachable!()),
            receiver_address,
            1,
            1,
            1,
            0,
        );
        let payload = unsigned.signing_bytes_for_network(Network::Testnet);
        assert!(payload.is_ok());
        let signed =
            unsigned.with_signature(keypair.sign(&payload.unwrap_or_else(|_| unreachable!())));

        let result = signed.validate_sender_authority_for_network(Network::Testnet);
        assert!(
            matches!(result, Err(TransactionError::MissingSenderPublicKey)),
            "sender authority validation requires embedded sender public key"
        );
    }

    #[test]
    fn sender_authority_validation_rejects_address_mismatch() {
        let mut transaction = signed_authorized_transaction(Network::Testnet, 91, 92, 1, 2);
        let attacker_keypair = Keypair::from_secret_key(&[93; 32]);
        assert!(attacker_keypair.is_ok(), "attacker keypair should be valid");
        transaction.sender_public_key = attacker_keypair
            .unwrap_or_else(|_| unreachable!())
            .public_key_bytes()
            .to_vec();

        let result = transaction.validate_sender_authority_for_network(Network::Testnet);
        assert!(
            matches!(result, Err(TransactionError::SenderAuthorityMismatch)),
            "sender public key must hash to sender address payload"
        );
    }

    #[test]
    fn sender_authority_validation_rejects_signature_tampering() {
        let mut transaction = signed_authorized_transaction(Network::Testnet, 101, 102, 1, 2);
        transaction.signature[0] ^= 0x01;

        let result = transaction.validate_sender_authority_for_network(Network::Testnet);
        assert!(
            matches!(
                result,
                Err(TransactionError::SignatureVerification { source: _ })
            ),
            "tampered signature must fail sender authority validation"
        );
    }

    #[test]
    fn rejects_zero_amount() {
        let transaction = Transaction::new_unsigned("A".to_owned(), "B".to_owned(), 0, 1, 1, 9);
        let result = transaction.validate_basic();
        assert!(
            matches!(result, Err(TransactionError::ZeroAmount)),
            "zero amount transactions should be rejected"
        );
    }

    #[test]
    fn rejects_sender_receiver_equality() {
        let transaction = Transaction::new_unsigned(
            "HMA_SAME".to_owned(),
            "HMA_SAME".to_owned(),
            1_u64,
            1_u64,
            1_u64,
            1_u64,
        );
        let result = transaction.validate_basic();
        assert!(
            matches!(result, Err(TransactionError::SameSenderReceiver)),
            "self-transfers should be rejected at this validation layer"
        );
    }

    #[test]
    fn detects_amount_overflow() {
        let transaction = Transaction::new_unsigned(
            "HMA_SENDER".to_owned(),
            "HMA_RECEIVER".to_owned(),
            Amount::MAX,
            1_u64,
            0_u64,
            0_u64,
        );
        let result = transaction.debited_total();
        assert!(
            matches!(result, Err(TransactionError::AmountOverflow)),
            "overflow in amount + fee must be rejected"
        );
    }

    #[test]
    fn decode_rejects_malicious_length_prefix_payload() {
        let malformed = [0xFF_u8; 32];
        let decoded = Transaction::decode(&malformed);
        assert!(
            matches!(decoded, Err(TransactionError::Deserialization)),
            "malformed untrusted bytes should return a typed deserialization error"
        );
    }
}
