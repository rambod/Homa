//! Mempool data structures and transaction ingestion rules.

use std::collections::{BTreeMap, BTreeSet};
use std::time::{SystemTime, UNIX_EPOCH};

use serde::{Deserialize, Serialize};
use thiserror::Error;

use crate::consensus::pow::{PowError, leading_zero_bits, transaction_pow_hash};
use crate::core::transaction::{Transaction, TransactionError};
use crate::crypto::address::{AddressError, Network, validate_address_for_network};

/// 32-byte transaction identifier.
pub type TransactionId = [u8; 32];

/// Runtime configuration for mempool admission policy.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct MempoolConfig {
    /// Maximum pending transactions retained in memory.
    pub max_transactions: usize,
    /// Minimum `PoW` difficulty required for tx admission.
    pub min_pow_difficulty_bits: u16,
    /// Expected address network of sender/receiver fields.
    pub network: Network,
    /// Optional per-sender admission window policy.
    pub sender_rate_limit: Option<RateLimitPolicy>,
    /// Optional per-peer admission window policy.
    pub peer_rate_limit: Option<RateLimitPolicy>,
    /// Soft-limit threshold where low-priority transactions are backpressured.
    pub backpressure_soft_limit: usize,
    /// Optional transaction retention `TTL` in milliseconds.
    ///
    /// Expired transactions are lazily pruned on admission or explicit maintenance calls.
    pub transaction_ttl_ms: Option<u64>,
}

impl MempoolConfig {
    /// Constructs a policy config.
    #[must_use]
    pub const fn new(
        max_transactions: usize,
        min_pow_difficulty_bits: u16,
        network: Network,
    ) -> Self {
        Self {
            max_transactions,
            min_pow_difficulty_bits,
            network,
            sender_rate_limit: None,
            peer_rate_limit: None,
            backpressure_soft_limit: max_transactions,
            transaction_ttl_ms: Some(600_000),
        }
    }

    /// Enables per-sender admission throttling.
    #[must_use]
    pub const fn with_sender_rate_limit(mut self, policy: RateLimitPolicy) -> Self {
        self.sender_rate_limit = Some(policy);
        self
    }

    /// Enables per-peer admission throttling.
    #[must_use]
    pub const fn with_peer_rate_limit(mut self, policy: RateLimitPolicy) -> Self {
        self.peer_rate_limit = Some(policy);
        self
    }

    /// Sets mempool backpressure soft-limit.
    ///
    /// Values above `max_transactions` are clamped to `max_transactions`.
    #[must_use]
    pub fn with_backpressure_soft_limit(mut self, soft_limit: usize) -> Self {
        self.backpressure_soft_limit = soft_limit.min(self.max_transactions);
        self
    }

    /// Sets transaction retention `TTL` in milliseconds.
    #[must_use]
    pub const fn with_transaction_ttl_ms(mut self, ttl_ms: u64) -> Self {
        self.transaction_ttl_ms = Some(ttl_ms);
        self
    }

    /// Disables transaction `TTL` pruning.
    #[must_use]
    pub const fn without_transaction_ttl(mut self) -> Self {
        self.transaction_ttl_ms = None;
        self
    }
}

impl Default for MempoolConfig {
    fn default() -> Self {
        Self {
            max_transactions: 100_000,
            min_pow_difficulty_bits: 10,
            network: Network::Mainnet,
            sender_rate_limit: None,
            peer_rate_limit: None,
            backpressure_soft_limit: 90_000,
            transaction_ttl_ms: Some(600_000),
        }
    }
}

/// Sliding-window admission throttling policy.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RateLimitPolicy {
    /// Window duration in milliseconds.
    pub window_ms: u64,
    /// Maximum admissions allowed in one window.
    pub max_admissions: u32,
}

impl RateLimitPolicy {
    /// Constructs a rate-limit policy.
    #[must_use]
    pub const fn new(window_ms: u64, max_admissions: u32) -> Self {
        Self {
            window_ms,
            max_admissions,
        }
    }
}

/// In-memory pending transaction set.
#[derive(Debug, Default)]
pub struct Mempool {
    config: MempoolConfig,
    transactions: BTreeMap<TransactionId, MempoolEntry>,
    priority_index: BTreeSet<PriorityKey>,
    sender_nonce_index: BTreeSet<(String, u64)>,
    sender_rate_windows: BTreeMap<String, RateWindow>,
    peer_rate_windows: BTreeMap<String, RateWindow>,
}

/// Persisted mempool entry used for durable checkpointing/recovery.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct MempoolCheckpointEntry {
    /// Full transaction payload.
    pub transaction: Transaction,
    /// Observation timestamp used for TTL enforcement during restart recovery.
    pub observed_at_unix_ms: u64,
}

#[derive(Debug, Clone)]
struct MempoolEntry {
    transaction: Transaction,
    pow_difficulty_bits: u16,
    observed_at_unix_ms: u64,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
struct PriorityKey {
    fee: u64,
    pow_difficulty_bits: u16,
    transaction_id: TransactionId,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct RateWindow {
    window_start_ms: u64,
    admissions: u32,
}

/// Errors emitted during mempool admission and maintenance.
#[derive(Debug, Clone, PartialEq, Eq, Error)]
pub enum MempoolError {
    /// Mempool reached configured capacity.
    #[error("mempool is full: capacity={capacity}")]
    Full {
        /// Configured max size.
        capacity: usize,
    },
    /// Transaction byte encoding failed.
    #[error("transaction encoding failed")]
    TransactionEncoding,
    /// Stateless transaction validation failed.
    #[error("transaction validation failed")]
    TransactionValidation {
        /// Inner validation error.
        source: TransactionError,
    },
    /// Sender authority proof (public-key binding/signature) failed.
    #[error("transaction sender authority validation failed")]
    TransactionAuthority {
        /// Inner authority-validation error.
        source: TransactionError,
    },
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
    /// `PoW` verification failed because difficulty target was not met.
    #[error("transaction PoW does not satisfy required difficulty")]
    InvalidPow,
    /// `PoW` subsystem returned an internal/parameterization error.
    #[error("PoW verification engine failed")]
    PowEngine {
        /// Inner `PoW` error.
        source: PowError,
    },
    /// Transaction with same hash already exists in mempool.
    #[error("duplicate transaction")]
    DuplicateTransaction,
    /// Sender nonce collision detected.
    #[error("duplicate sender nonce: sender={sender}, nonce={nonce}")]
    DuplicateSenderNonce {
        /// Sender address.
        sender: String,
        /// Duplicate account nonce.
        nonce: u64,
    },
    /// Sender exceeded configured admission rate.
    #[error("sender rate limit exceeded: sender={sender}, window_ms={window_ms}, max={max}")]
    SenderRateLimited {
        /// Sender address.
        sender: String,
        /// Applied window duration.
        window_ms: u64,
        /// Max admissions allowed in the window.
        max: u32,
    },
    /// Peer exceeded configured admission rate.
    #[error("peer rate limit exceeded: peer={peer}, window_ms={window_ms}, max={max}")]
    PeerRateLimited {
        /// Peer identifier string.
        peer: String,
        /// Applied window duration.
        window_ms: u64,
        /// Max admissions allowed in the window.
        max: u32,
    },
    /// Transaction was rejected by mempool backpressure rules.
    #[error("backpressure rejected low-priority transaction")]
    BackpressureRejected {
        /// Current mempool length.
        current_len: usize,
        /// Soft-limit threshold.
        soft_limit: usize,
        /// Candidate fee.
        incoming_fee: u64,
        /// Candidate `PoW` bits.
        incoming_pow_difficulty_bits: u16,
        /// Lowest fee currently in mempool.
        lowest_fee: u64,
        /// Lowest `PoW` bits currently in mempool.
        lowest_pow_difficulty_bits: u16,
    },
}

impl Mempool {
    /// Creates an empty mempool with explicit config.
    #[must_use]
    pub const fn new(config: MempoolConfig) -> Self {
        Self {
            config,
            transactions: BTreeMap::new(),
            priority_index: BTreeSet::new(),
            sender_nonce_index: BTreeSet::new(),
            sender_rate_windows: BTreeMap::new(),
            peer_rate_windows: BTreeMap::new(),
        }
    }

    /// Returns transaction count.
    #[must_use]
    pub fn len(&self) -> usize {
        self.transactions.len()
    }

    /// Returns mempool admission policy configuration.
    #[must_use]
    pub const fn config(&self) -> MempoolConfig {
        self.config
    }

    /// Returns true when no transactions are queued.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.transactions.is_empty()
    }

    /// Inserts a new transaction after all admission checks pass.
    pub fn insert(&mut self, transaction: Transaction) -> Result<TransactionId, MempoolError> {
        self.insert_with_context(transaction, None, now_unix_ms())
    }

    /// Inserts a transaction attributed to a network peer at a specific observation timestamp.
    pub fn insert_from_peer(
        &mut self,
        transaction: Transaction,
        peer_id: &str,
        observed_at_unix_ms: u64,
    ) -> Result<TransactionId, MempoolError> {
        self.insert_with_context(transaction, Some(peer_id), observed_at_unix_ms)
    }

    /// Inserts one checkpoint-recovered transaction with full admission revalidation.
    ///
    /// Recovery inserts intentionally bypass sender/peer rate limiting because those windows
    /// represent transient online traffic, not persisted safety constraints.
    pub fn insert_recovered_checkpoint_entry(
        &mut self,
        entry: MempoolCheckpointEntry,
        now_unix_ms: u64,
    ) -> Result<TransactionId, MempoolError> {
        self.insert_with_context_with_options(
            entry.transaction,
            None,
            now_unix_ms,
            entry.observed_at_unix_ms,
            false,
        )
    }

    /// Exports deterministic checkpoint entries for all queued transactions.
    #[must_use]
    pub fn checkpoint_entries(&self) -> Vec<MempoolCheckpointEntry> {
        self.transactions
            .values()
            .map(|entry| MempoolCheckpointEntry {
                transaction: entry.transaction.clone(),
                observed_at_unix_ms: entry.observed_at_unix_ms,
            })
            .collect()
    }

    fn insert_with_context(
        &mut self,
        transaction: Transaction,
        peer_id: Option<&str>,
        observed_at_unix_ms: u64,
    ) -> Result<TransactionId, MempoolError> {
        self.insert_with_context_with_options(
            transaction,
            peer_id,
            observed_at_unix_ms,
            observed_at_unix_ms,
            true,
        )
    }

    fn insert_with_context_with_options(
        &mut self,
        transaction: Transaction,
        peer_id: Option<&str>,
        now_unix_ms: u64,
        observed_at_unix_ms: u64,
        enforce_rate_limits: bool,
    ) -> Result<TransactionId, MempoolError> {
        let observed_at_unix_ms = observed_at_unix_ms.min(now_unix_ms);
        let _ = self.prune_expired_at(now_unix_ms);

        if self.transactions.len() >= self.config.max_transactions {
            return Err(MempoolError::Full {
                capacity: self.config.max_transactions,
            });
        }

        transaction
            .validate_basic()
            .map_err(|source| MempoolError::TransactionValidation { source })?;

        validate_address_for_network(&transaction.sender, self.config.network)
            .map_err(|source| MempoolError::InvalidSenderAddress { source })?;
        validate_address_for_network(&transaction.receiver, self.config.network)
            .map_err(|source| MempoolError::InvalidReceiverAddress { source })?;

        if enforce_rate_limits {
            self.enforce_sender_rate_limit(&transaction.sender, now_unix_ms)?;
            if let Some(peer) = peer_id {
                self.enforce_peer_rate_limit(peer, now_unix_ms)?;
            }
        }

        let pow_hash = transaction_pow_hash(&transaction)
            .map_err(|source| MempoolError::PowEngine { source })?;
        let pow_difficulty_bits = leading_zero_bits(&pow_hash);
        if pow_difficulty_bits < self.config.min_pow_difficulty_bits {
            return Err(MempoolError::InvalidPow);
        }
        transaction
            .validate_sender_authority_for_network(self.config.network)
            .map_err(|source| MempoolError::TransactionAuthority { source })?;

        let sender_nonce_key = (transaction.sender.clone(), transaction.nonce);
        if self.sender_nonce_index.contains(&sender_nonce_key) {
            return Err(MempoolError::DuplicateSenderNonce {
                sender: transaction.sender,
                nonce: transaction.nonce,
            });
        }

        let transaction_id = transaction_id(&transaction)?;
        if self.transactions.contains_key(&transaction_id) {
            return Err(MempoolError::DuplicateTransaction);
        }

        let priority_key = PriorityKey {
            fee: transaction.fee,
            pow_difficulty_bits,
            transaction_id,
        };

        if self.transactions.len() >= self.config.backpressure_soft_limit {
            if let Some(lowest_priority) = self.priority_index.first() {
                if priority_key <= *lowest_priority {
                    return Err(MempoolError::BackpressureRejected {
                        current_len: self.transactions.len(),
                        soft_limit: self.config.backpressure_soft_limit,
                        incoming_fee: priority_key.fee,
                        incoming_pow_difficulty_bits: priority_key.pow_difficulty_bits,
                        lowest_fee: lowest_priority.fee,
                        lowest_pow_difficulty_bits: lowest_priority.pow_difficulty_bits,
                    });
                }
            }
        }

        self.sender_nonce_index.insert(sender_nonce_key);
        self.priority_index.insert(priority_key);
        self.transactions.insert(
            transaction_id,
            MempoolEntry {
                transaction,
                pow_difficulty_bits,
                observed_at_unix_ms,
            },
        );
        Ok(transaction_id)
    }

    /// Prunes expired transactions using current wall-clock time.
    pub fn prune_expired(&mut self) -> usize {
        self.prune_expired_at(now_unix_ms())
    }

    /// Returns a transaction by id.
    #[must_use]
    pub fn get(&self, transaction_id: &TransactionId) -> Option<&Transaction> {
        self.transactions
            .get(transaction_id)
            .map(|entry| &entry.transaction)
    }

    /// Returns the highest-priority transaction currently in the queue.
    ///
    /// Priority order is: higher fee first, then higher `PoW` difficulty.
    #[must_use]
    pub fn peek_highest_priority(&self) -> Option<&Transaction> {
        let highest = self.priority_index.last()?;
        self.get(&highest.transaction_id)
    }

    /// Returns cloned transactions ordered by current priority (highest first).
    #[must_use]
    pub fn prioritized_transactions(&self, limit: usize) -> Vec<(TransactionId, Transaction)> {
        self.priority_index
            .iter()
            .rev()
            .take(limit)
            .filter_map(|key| {
                self.transactions
                    .get(&key.transaction_id)
                    .map(|entry| (key.transaction_id, entry.transaction.clone()))
            })
            .collect()
    }

    /// Removes and returns the highest-priority transaction.
    pub fn pop_highest_priority(&mut self) -> Option<(TransactionId, Transaction)> {
        let highest = *self.priority_index.last()?;
        let removed = self.remove(&highest.transaction_id)?;
        Some((highest.transaction_id, removed))
    }

    /// Removes a transaction and updates sender/nonce index.
    pub fn remove(&mut self, transaction_id: &TransactionId) -> Option<Transaction> {
        let removed = self.transactions.remove(transaction_id)?;
        let removed_key = (
            removed.transaction.sender.clone(),
            removed.transaction.nonce,
        );
        let priority_key = PriorityKey {
            fee: removed.transaction.fee,
            pow_difficulty_bits: removed.pow_difficulty_bits,
            transaction_id: *transaction_id,
        };
        self.sender_nonce_index.remove(&removed_key);
        self.priority_index.remove(&priority_key);
        Some(removed.transaction)
    }

    fn enforce_sender_rate_limit(
        &mut self,
        sender: &str,
        observed_at_unix_ms: u64,
    ) -> Result<(), MempoolError> {
        if let Some(policy) = self.config.sender_rate_limit {
            enforce_window_limit(
                &mut self.sender_rate_windows,
                sender,
                observed_at_unix_ms,
                policy,
                |window_ms, max| MempoolError::SenderRateLimited {
                    sender: sender.to_owned(),
                    window_ms,
                    max,
                },
            )?;
        }
        Ok(())
    }

    fn enforce_peer_rate_limit(
        &mut self,
        peer_id: &str,
        observed_at_unix_ms: u64,
    ) -> Result<(), MempoolError> {
        if let Some(policy) = self.config.peer_rate_limit {
            enforce_window_limit(
                &mut self.peer_rate_windows,
                peer_id,
                observed_at_unix_ms,
                policy,
                |window_ms, max| MempoolError::PeerRateLimited {
                    peer: peer_id.to_owned(),
                    window_ms,
                    max,
                },
            )?;
        }
        Ok(())
    }

    fn prune_expired_at(&mut self, now_unix_ms: u64) -> usize {
        let Some(ttl_ms) = self.config.transaction_ttl_ms else {
            return 0;
        };

        let expired_ids: Vec<TransactionId> = self
            .transactions
            .iter()
            .filter_map(|(transaction_id, entry)| {
                if now_unix_ms.saturating_sub(entry.observed_at_unix_ms) >= ttl_ms {
                    Some(*transaction_id)
                } else {
                    None
                }
            })
            .collect();

        for transaction_id in &expired_ids {
            let _ = self.remove(transaction_id);
        }
        expired_ids.len()
    }
}

fn enforce_window_limit<E>(
    windows: &mut BTreeMap<String, RateWindow>,
    key: &str,
    now_ms: u64,
    policy: RateLimitPolicy,
    error_builder: impl FnOnce(u64, u32) -> E,
) -> Result<(), E> {
    let window = windows.entry(key.to_owned()).or_insert(RateWindow {
        window_start_ms: now_ms,
        admissions: 0,
    });

    if now_ms.saturating_sub(window.window_start_ms) >= policy.window_ms {
        window.window_start_ms = now_ms;
        window.admissions = 0;
    }

    if window.admissions >= policy.max_admissions {
        return Err(error_builder(policy.window_ms, policy.max_admissions));
    }

    window.admissions = window.admissions.saturating_add(1);
    Ok(())
}

fn now_unix_ms() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |duration| {
            u64::try_from(duration.as_millis()).unwrap_or(u64::MAX)
        })
}

/// Computes a stable transaction id from encoded tx bytes.
pub fn transaction_id(transaction: &Transaction) -> Result<TransactionId, MempoolError> {
    let bytes = transaction
        .encode()
        .map_err(|_| MempoolError::TransactionEncoding)?;
    Ok(*blake3::hash(&bytes).as_bytes())
}

#[cfg(test)]
mod tests {
    use super::{Mempool, MempoolConfig, MempoolError, RateLimitPolicy, transaction_id};
    use crate::consensus::pow::{leading_zero_bits, mine_pow_nonce, transaction_pow_hash};
    use crate::core::transaction::{Transaction, TransactionError};
    use crate::crypto::address::{Network, derive_address};
    use crate::crypto::keys::Keypair;

    fn build_valid_transaction_with(nonce: u64, fee: u64, pow_target: u16) -> Transaction {
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

        let sender_address = sender_address_result.unwrap_or_else(|_| unreachable!());
        let receiver_address = receiver_address_result.unwrap_or_else(|_| unreachable!());

        let tx = Transaction::new_unsigned(sender_address, receiver_address, 50, fee, nonce, 0)
            .with_sender_public_key(sender_keypair.public_key_bytes());
        let solution_result = mine_pow_nonce(&tx, pow_target, 0, 800_000);
        assert!(
            solution_result.is_ok(),
            "PoW mining should find a solution quickly"
        );
        let solution = solution_result.unwrap_or_else(|_| unreachable!());

        let mut mined = tx;
        mined.pow_nonce = solution.nonce;

        let signing_bytes_result = mined.signing_bytes();
        assert!(
            signing_bytes_result.is_ok(),
            "transaction signing bytes should encode"
        );
        let signing_bytes = signing_bytes_result.unwrap_or_else(|_| unreachable!());
        let signature = sender_keypair.sign(&signing_bytes);
        mined.with_signature(signature)
    }

    fn build_valid_transaction(nonce: u64) -> Transaction {
        build_valid_transaction_with(nonce, 1, 8)
    }

    fn build_valid_transaction_for_sender(
        sender_keypair: &Keypair,
        receiver_address: &str,
        nonce: u64,
        fee: u64,
        pow_target: u16,
    ) -> Transaction {
        let sender_address_result =
            derive_address(&sender_keypair.public_key_bytes(), Network::Testnet);
        assert!(
            sender_address_result.is_ok(),
            "sender address derivation should succeed"
        );
        let sender_address = sender_address_result.unwrap_or_else(|_| unreachable!());

        let tx = Transaction::new_unsigned(
            sender_address,
            receiver_address.to_owned(),
            50,
            fee,
            nonce,
            0,
        )
        .with_sender_public_key(sender_keypair.public_key_bytes());
        let solution_result = mine_pow_nonce(&tx, pow_target, 0, 800_000);
        assert!(solution_result.is_ok(), "PoW mining should succeed");
        let solution = solution_result.unwrap_or_else(|_| unreachable!());

        let mut mined = tx;
        mined.pow_nonce = solution.nonce;

        let signing_bytes_result = mined.signing_bytes();
        assert!(
            signing_bytes_result.is_ok(),
            "transaction signing bytes should encode"
        );
        let signature =
            sender_keypair.sign(&signing_bytes_result.unwrap_or_else(|_| unreachable!()));
        mined.with_signature(signature)
    }

    #[test]
    fn accepts_valid_pow_transaction() {
        let mut mempool = Mempool::new(MempoolConfig::new(8, 8, Network::Testnet));
        let tx = build_valid_transaction(1);

        let inserted = mempool.insert(tx);
        assert!(inserted.is_ok(), "valid transaction should enter mempool");
        assert_eq!(mempool.len(), 1);
    }

    #[test]
    fn rejects_invalid_pow() {
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

        let tx = Transaction::new_unsigned(
            sender_address_result.unwrap_or_else(|_| unreachable!()),
            receiver_address_result.unwrap_or_else(|_| unreachable!()),
            50,
            1,
            1,
            0,
        );

        let mut mempool = Mempool::new(MempoolConfig::new(8, 14, Network::Testnet));
        let inserted = mempool.insert(tx);
        assert!(
            matches!(inserted, Err(MempoolError::InvalidPow)),
            "transactions without enough PoW should be rejected"
        );
    }

    #[test]
    fn rejects_duplicate_sender_nonce() {
        let sender_key = Keypair::generate();
        let receiver_key = Keypair::generate();
        let receiver_address_result =
            derive_address(&receiver_key.public_key_bytes(), Network::Testnet);
        assert!(
            receiver_address_result.is_ok(),
            "receiver address derivation should succeed"
        );
        let receiver_address = receiver_address_result.unwrap_or_else(|_| unreachable!());

        let tx1 = build_valid_transaction_for_sender(&sender_key, &receiver_address, 8, 1, 8);
        let tx2 = build_valid_transaction_for_sender(&sender_key, &receiver_address, 8, 2, 8);

        let mut mempool = Mempool::new(MempoolConfig::new(8, 0, Network::Testnet));
        let first_insert = mempool.insert(tx1);
        assert!(first_insert.is_ok(), "first insert should succeed");

        let second_insert = mempool.insert(tx2);
        assert!(
            matches!(
                second_insert,
                Err(MempoolError::DuplicateSenderNonce {
                    sender: _,
                    nonce: _
                })
            ),
            "same sender+nonce should be rejected"
        );
    }

    #[test]
    fn rejects_cross_network_addresses() {
        let sender_keypair = Keypair::generate();
        let receiver_keypair = Keypair::generate();

        let sender_address_result =
            derive_address(&sender_keypair.public_key_bytes(), Network::Mainnet);
        let receiver_address_result =
            derive_address(&receiver_keypair.public_key_bytes(), Network::Mainnet);
        assert!(
            sender_address_result.is_ok(),
            "sender address derivation should succeed"
        );
        assert!(
            receiver_address_result.is_ok(),
            "receiver address derivation should succeed"
        );

        let tx = Transaction::new_unsigned(
            sender_address_result.unwrap_or_else(|_| unreachable!()),
            receiver_address_result.unwrap_or_else(|_| unreachable!()),
            5,
            1,
            2,
            0,
        );

        let mut mempool = Mempool::new(MempoolConfig::new(8, 0, Network::Testnet));
        let inserted = mempool.insert(tx);
        assert!(
            matches!(
                inserted,
                Err(MempoolError::InvalidSenderAddress { source: _ })
            ),
            "mempool network check should reject addresses from other networks"
        );
    }

    #[test]
    fn rejects_sender_authority_when_public_key_does_not_match_sender_address() {
        let sender_keypair = Keypair::generate();
        let receiver_keypair = Keypair::generate();
        let attacker_keypair = Keypair::generate();

        let sender_address_result =
            derive_address(&sender_keypair.public_key_bytes(), Network::Testnet);
        let receiver_address_result =
            derive_address(&receiver_keypair.public_key_bytes(), Network::Testnet);
        assert!(sender_address_result.is_ok());
        assert!(receiver_address_result.is_ok());
        let sender_address = sender_address_result.unwrap_or_else(|_| unreachable!());
        let receiver_address = receiver_address_result.unwrap_or_else(|_| unreachable!());

        let unsigned = Transaction::new_unsigned(sender_address, receiver_address, 5, 1, 1, 0)
            .with_sender_public_key(attacker_keypair.public_key_bytes());
        let solution = mine_pow_nonce(&unsigned, 8, 0, 800_000);
        assert!(solution.is_ok(), "PoW mining should succeed");
        let mut mined = unsigned;
        mined.pow_nonce = solution.unwrap_or_else(|_| unreachable!()).nonce;

        let signing_bytes = mined.signing_bytes();
        assert!(signing_bytes.is_ok());
        let signed = mined.with_signature(
            attacker_keypair.sign(&signing_bytes.unwrap_or_else(|_| unreachable!())),
        );

        let mut mempool = Mempool::new(MempoolConfig::new(8, 8, Network::Testnet));
        let inserted = mempool.insert(signed);
        assert!(
            matches!(
                inserted,
                Err(MempoolError::TransactionAuthority {
                    source: TransactionError::SenderAuthorityMismatch
                })
            ),
            "sender address hash must match embedded sender public key"
        );
    }

    #[test]
    fn rejects_sender_authority_when_sender_public_key_is_missing() {
        let sender_keypair = Keypair::generate();
        let receiver_keypair = Keypair::generate();

        let sender_address_result =
            derive_address(&sender_keypair.public_key_bytes(), Network::Testnet);
        let receiver_address_result =
            derive_address(&receiver_keypair.public_key_bytes(), Network::Testnet);
        assert!(sender_address_result.is_ok());
        assert!(receiver_address_result.is_ok());
        let sender_address = sender_address_result.unwrap_or_else(|_| unreachable!());
        let receiver_address = receiver_address_result.unwrap_or_else(|_| unreachable!());

        let unsigned = Transaction::new_unsigned(sender_address, receiver_address, 5, 1, 1, 0);
        let solution = mine_pow_nonce(&unsigned, 8, 0, 800_000);
        assert!(solution.is_ok(), "PoW mining should succeed");
        let mut mined = unsigned;
        mined.pow_nonce = solution.unwrap_or_else(|_| unreachable!()).nonce;

        let signing_bytes = mined.signing_bytes();
        assert!(signing_bytes.is_ok());
        let signed = mined
            .with_signature(sender_keypair.sign(&signing_bytes.unwrap_or_else(|_| unreachable!())));

        let mut mempool = Mempool::new(MempoolConfig::new(8, 8, Network::Testnet));
        let inserted = mempool.insert(signed);
        assert!(
            matches!(
                inserted,
                Err(MempoolError::TransactionAuthority {
                    source: TransactionError::MissingSenderPublicKey
                })
            ),
            "sender public key must be present for authority validation"
        );
    }

    #[test]
    fn rejects_when_full() {
        let mut mempool = Mempool::new(MempoolConfig::new(1, 8, Network::Testnet));
        let tx1 = build_valid_transaction(1);
        let tx2 = build_valid_transaction(2);

        assert!(mempool.insert(tx1).is_ok(), "first transaction should fit");
        let second = mempool.insert(tx2);
        assert!(
            matches!(second, Err(MempoolError::Full { capacity: 1 })),
            "second transaction must fail when capacity reached"
        );
    }

    #[test]
    fn ttl_pruning_reclaims_capacity_before_full_check() {
        let mut mempool =
            Mempool::new(MempoolConfig::new(1, 8, Network::Testnet).with_transaction_ttl_ms(100));
        let tx1 = build_valid_transaction(1);
        let tx2 = build_valid_transaction(2);

        let first_id = mempool.insert_with_context(tx1, None, 1_000);
        assert!(first_id.is_ok(), "first transaction should be admitted");
        let first_id = first_id.unwrap_or_else(|_| unreachable!());

        let second_id = mempool.insert_with_context(tx2, None, 1_101);
        assert!(
            second_id.is_ok(),
            "second transaction should fit after first expires"
        );
        assert_eq!(
            mempool.len(),
            1,
            "only non-expired transaction should remain"
        );
        assert!(
            mempool.get(&first_id).is_none(),
            "expired transaction must be removed from tx index"
        );
    }

    #[test]
    fn explicit_prune_removes_only_expired_transactions() {
        let mut mempool =
            Mempool::new(MempoolConfig::new(8, 8, Network::Testnet).with_transaction_ttl_ms(100));
        let tx1 = build_valid_transaction(1);
        let tx2 = build_valid_transaction(2);
        let tx3 = build_valid_transaction(3);

        let id1 = mempool.insert_with_context(tx1, None, 1_000);
        let id2 = mempool.insert_with_context(tx2, None, 1_050);
        let id3 = mempool.insert_with_context(tx3, None, 1_080);
        assert!(id1.is_ok() && id2.is_ok() && id3.is_ok());
        let id1 = id1.unwrap_or_else(|_| unreachable!());
        let id2 = id2.unwrap_or_else(|_| unreachable!());
        let id3 = id3.unwrap_or_else(|_| unreachable!());

        let pruned = mempool.prune_expired_at(1_151);
        assert_eq!(pruned, 2, "two expired entries should be evicted");
        assert_eq!(mempool.len(), 1, "only freshest transaction should remain");
        assert!(mempool.get(&id1).is_none());
        assert!(mempool.get(&id2).is_none());
        assert!(mempool.get(&id3).is_some());
    }

    #[test]
    fn ttl_can_be_disabled() {
        let mut mempool =
            Mempool::new(MempoolConfig::new(8, 8, Network::Testnet).without_transaction_ttl());
        let tx = build_valid_transaction(1);

        let inserted = mempool.insert_with_context(tx, None, 1_000);
        assert!(inserted.is_ok());
        let pruned = mempool.prune_expired_at(50_000);
        assert_eq!(pruned, 0, "disabled ttl should not prune any transaction");
        assert_eq!(mempool.len(), 1);
    }

    #[test]
    fn prioritizes_higher_fee_before_harder_pow() {
        let mut mempool = Mempool::new(MempoolConfig::new(8, 8, Network::Testnet));
        let high_fee = build_valid_transaction_with(1, 7, 8);
        let low_fee_higher_pow = build_valid_transaction_with(2, 1, 12);

        let high_fee_id = mempool.insert(high_fee);
        let low_fee_id = mempool.insert(low_fee_higher_pow);
        assert!(high_fee_id.is_ok());
        assert!(low_fee_id.is_ok());

        let top = mempool.peek_highest_priority();
        assert!(top.is_some(), "mempool should have top entry");
        let top = top.unwrap_or_else(|| unreachable!());
        assert_eq!(top.fee, 7, "higher fee must be selected first");
    }

    #[test]
    fn prioritizes_harder_pow_when_fees_are_equal() {
        let mut mempool = Mempool::new(MempoolConfig::new(8, 8, Network::Testnet));
        let tx_a = build_valid_transaction_with(1, 5, 8);
        let tx_b = build_valid_transaction_with(2, 5, 11);

        let id_a = mempool.insert(tx_a.clone());
        let id_b = mempool.insert(tx_b.clone());
        assert!(id_a.is_ok());
        assert!(id_b.is_ok());
        let id_a = id_a.unwrap_or_else(|_| unreachable!());
        let id_b = id_b.unwrap_or_else(|_| unreachable!());

        let hash_a = transaction_pow_hash(&tx_a);
        let hash_b = transaction_pow_hash(&tx_b);
        assert!(hash_a.is_ok());
        assert!(hash_b.is_ok());
        let bits_a = leading_zero_bits(&hash_a.unwrap_or_else(|_| unreachable!()));
        let bits_b = leading_zero_bits(&hash_b.unwrap_or_else(|_| unreachable!()));

        let top = mempool.peek_highest_priority();
        assert!(top.is_some());
        let top = top.unwrap_or_else(|| unreachable!());
        let top_id = transaction_id(top);
        assert!(top_id.is_ok(), "transaction id derivation should succeed");
        let top_id = top_id.unwrap_or_else(|_| unreachable!());

        let expected_top_id = if bits_a > bits_b {
            id_a
        } else if bits_b > bits_a {
            id_b
        } else if id_a > id_b {
            id_a
        } else {
            id_b
        };
        assert_eq!(top_id, expected_top_id);
    }

    #[test]
    fn pop_highest_priority_removes_entry() {
        let mut mempool = Mempool::new(MempoolConfig::new(8, 8, Network::Testnet));
        let tx1 = build_valid_transaction_with(1, 2, 8);
        let tx2 = build_valid_transaction_with(2, 9, 8);

        assert!(mempool.insert(tx1).is_ok());
        assert!(mempool.insert(tx2).is_ok());
        assert_eq!(mempool.len(), 2);

        let popped = mempool.pop_highest_priority();
        assert!(popped.is_some(), "one entry should be popped");
        let popped = popped.unwrap_or_else(|| unreachable!());
        assert_eq!(popped.1.fee, 9, "highest fee entry should be popped");
        assert_eq!(mempool.len(), 1, "mempool length should decrease");
    }

    #[test]
    fn prioritized_transactions_returns_highest_first_with_limit() {
        let mut mempool = Mempool::new(MempoolConfig::new(16, 8, Network::Testnet));
        let tx_low = build_valid_transaction_with(1, 1, 8);
        let tx_high = build_valid_transaction_with(2, 7, 8);
        let tx_mid = build_valid_transaction_with(3, 5, 8);

        assert!(mempool.insert(tx_low).is_ok());
        assert!(mempool.insert(tx_high).is_ok());
        assert!(mempool.insert(tx_mid).is_ok());

        let prioritized = mempool.prioritized_transactions(2);
        assert_eq!(prioritized.len(), 2, "limit should cap returned entries");
        assert!(
            prioritized[0].1.fee >= prioritized[1].1.fee,
            "results must be sorted by descending priority"
        );
        assert_eq!(prioritized[0].1.fee, 7);
        assert_eq!(prioritized[1].1.fee, 5);
    }

    #[test]
    fn sender_rate_limit_rejects_burst_within_window() {
        let mut mempool = Mempool::new(
            MempoolConfig::new(16, 8, Network::Testnet)
                .with_sender_rate_limit(RateLimitPolicy::new(1_000, 2)),
        );

        let sender_key = Keypair::generate();
        let receiver_key = Keypair::generate();
        let receiver_address_result =
            derive_address(&receiver_key.public_key_bytes(), Network::Testnet);
        assert!(receiver_address_result.is_ok());
        let receiver_address = receiver_address_result.unwrap_or_else(|_| unreachable!());

        let tx1 = build_valid_transaction_for_sender(&sender_key, &receiver_address, 1, 1, 8);
        let tx2 = build_valid_transaction_for_sender(&sender_key, &receiver_address, 2, 1, 8);
        let tx3 = build_valid_transaction_for_sender(&sender_key, &receiver_address, 3, 1, 8);

        assert!(mempool.insert_with_context(tx1, None, 10_000).is_ok());
        assert!(mempool.insert_with_context(tx2, None, 10_100).is_ok());
        let third = mempool.insert_with_context(tx3, None, 10_200);
        assert!(
            matches!(
                third,
                Err(MempoolError::SenderRateLimited {
                    sender: _,
                    window_ms: 1_000,
                    max: 2
                })
            ),
            "third sender admission in same window should be throttled"
        );
    }

    #[test]
    fn peer_rate_limit_rejects_single_peer_spam() {
        let mut mempool = Mempool::new(
            MempoolConfig::new(16, 8, Network::Testnet)
                .with_peer_rate_limit(RateLimitPolicy::new(2_000, 2)),
        );

        let tx1 = build_valid_transaction(1);
        let tx2 = build_valid_transaction(2);
        let tx3 = build_valid_transaction(3);

        assert!(mempool.insert_from_peer(tx1, "peer-a", 20_000).is_ok());
        assert!(mempool.insert_from_peer(tx2, "peer-a", 20_010).is_ok());
        let third = mempool.insert_from_peer(tx3, "peer-a", 20_050);
        assert!(
            matches!(
                third,
                Err(MempoolError::PeerRateLimited {
                    peer,
                    window_ms: 2_000,
                    max: 2
                }) if peer == "peer-a"
            ),
            "single peer should be throttled after rate cap"
        );
    }

    #[test]
    fn sender_rate_limit_window_resets() {
        let mut mempool = Mempool::new(
            MempoolConfig::new(16, 8, Network::Testnet)
                .with_sender_rate_limit(RateLimitPolicy::new(1_000, 1)),
        );

        let sender_key = Keypair::generate();
        let receiver_key = Keypair::generate();
        let receiver_address_result =
            derive_address(&receiver_key.public_key_bytes(), Network::Testnet);
        assert!(receiver_address_result.is_ok());
        let receiver_address = receiver_address_result.unwrap_or_else(|_| unreachable!());

        let tx1 = build_valid_transaction_for_sender(&sender_key, &receiver_address, 1, 1, 8);
        let tx2 = build_valid_transaction_for_sender(&sender_key, &receiver_address, 2, 1, 8);
        let tx3 = build_valid_transaction_for_sender(&sender_key, &receiver_address, 3, 1, 8);

        assert!(mempool.insert_with_context(tx1, None, 30_000).is_ok());
        let second_same_window = mempool.insert_with_context(tx2, None, 30_500);
        assert!(matches!(
            second_same_window,
            Err(MempoolError::SenderRateLimited { .. })
        ));
        assert!(
            mempool.insert_with_context(tx3, None, 31_001).is_ok(),
            "new window should allow next sender admission"
        );
    }

    #[test]
    fn backpressure_rejects_low_priority_when_soft_limit_reached() {
        let mut mempool = Mempool::new(
            MempoolConfig::new(4, 8, Network::Testnet).with_backpressure_soft_limit(2),
        );

        let high_a = build_valid_transaction_with(1, 8, 8);
        let high_b = build_valid_transaction_with(2, 7, 8);
        let low = build_valid_transaction_with(3, 1, 8);

        assert!(mempool.insert(high_a).is_ok());
        assert!(mempool.insert(high_b).is_ok());
        let rejected = mempool.insert(low);
        assert!(
            matches!(
                rejected,
                Err(MempoolError::BackpressureRejected {
                    current_len: 2,
                    soft_limit: 2,
                    incoming_fee: 1,
                    incoming_pow_difficulty_bits: _,
                    lowest_fee: _,
                    lowest_pow_difficulty_bits: _
                })
            ),
            "low-priority tx should be dropped under backpressure"
        );
    }

    #[test]
    fn backpressure_allows_higher_priority_when_soft_limit_reached() {
        let mut mempool = Mempool::new(
            MempoolConfig::new(4, 8, Network::Testnet).with_backpressure_soft_limit(2),
        );

        let low_a = build_valid_transaction_with(1, 2, 8);
        let low_b = build_valid_transaction_with(2, 3, 8);
        let high = build_valid_transaction_with(3, 9, 8);

        assert!(mempool.insert(low_a).is_ok());
        assert!(mempool.insert(low_b).is_ok());
        let accepted = mempool.insert(high);
        assert!(
            accepted.is_ok(),
            "higher-priority tx should pass backpressure"
        );
        assert_eq!(mempool.len(), 3);
    }
}
