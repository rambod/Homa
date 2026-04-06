//! Account-state storage and block finalization logic.

use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};
use thiserror::Error;

use crate::core::block::{Block, BlockError};
use crate::core::transaction::{Amount, TransactionError};
use crate::crypto::address::{AddressError, Network, validate_address_for_network};

/// Base-unit conversion constant.
pub const MICRO_HOMA_PER_HMA: u64 = 100_000_000;
/// Hard-capped maximum supply in `HMA`.
pub const MAX_SUPPLY_HMA: u64 = 36_000_000;
/// Hard-capped maximum supply in micro-homas.
pub const MAX_SUPPLY_MICRO_HOMA: u64 = MAX_SUPPLY_HMA * MICRO_HOMA_PER_HMA;

/// Runtime account record.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
pub struct AccountState {
    /// Spendable balance in micro-homas.
    pub balance: Amount,
    /// Last accepted transaction nonce.
    pub nonce: u64,
}

/// Result summary of successful block application.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct BlockApplyOutcome {
    /// Number of applied transactions.
    pub applied_transactions: usize,
    /// Total fees paid by transactions in this block.
    pub collected_fees: Amount,
    /// Fee reward credited to block proposer.
    pub proposer_reward: Amount,
}

/// State transition and ledger errors.
#[derive(Debug, Clone, PartialEq, Eq, Error)]
pub enum StateError {
    /// Genesis allocation contains duplicate account entries.
    #[error("duplicate genesis allocation for address: {address}")]
    DuplicateGenesisAddress {
        /// Duplicated address.
        address: String,
    },
    /// Snapshot contains duplicate account entries.
    #[error("duplicate snapshot account for address: {address}")]
    DuplicateSnapshotAddress {
        /// Duplicated address.
        address: String,
    },
    /// Address failed format/network checks.
    #[error("invalid address")]
    InvalidAddress {
        /// Address parsing error.
        source: AddressError,
    },
    /// Aggregate supply overflowed arithmetic bounds.
    #[error("supply overflow")]
    SupplyOverflow,
    /// Genesis supply exceeds hard-cap.
    #[error("maximum supply exceeded: cap={cap}, attempted={attempted}")]
    SupplyCapExceeded {
        /// Maximum allowed supply.
        cap: Amount,
        /// Attempted supply value.
        attempted: Amount,
    },
    /// Block failed structural validation.
    #[error("block validation failed")]
    BlockValidation {
        /// Inner block error.
        source: BlockError,
    },
    /// Transaction contains invalid arithmetic fields.
    #[error("transaction at index {index} failed validation")]
    TransactionValidation {
        /// Transaction index.
        index: usize,
        /// Inner transaction error.
        source: TransactionError,
    },
    /// Sender nonce did not strictly increment.
    #[error("nonce mismatch for sender {sender}: expected {expected}, got {actual}")]
    NonceMismatch {
        /// Sender address.
        sender: String,
        /// Required nonce value.
        expected: u64,
        /// Observed nonce value.
        actual: u64,
    },
    /// Sender does not hold enough funds.
    #[error("insufficient balance for sender {sender}: available {available}, required {required}")]
    InsufficientBalance {
        /// Sender address.
        sender: String,
        /// Available balance.
        available: Amount,
        /// Required debited amount.
        required: Amount,
    },
    /// Receiver/proposer credit overflowed.
    #[error("balance overflow")]
    BalanceOverflow,
    /// Sum of fees overflowed.
    #[error("fee overflow")]
    FeeOverflow,
}

/// Account-based state store used by block finalization.
#[derive(Debug, Clone)]
pub struct ChainState {
    network: Network,
    accounts: BTreeMap<String, AccountState>,
    total_issued: Amount,
}

impl ChainState {
    /// Creates an empty chain state for a given network.
    #[must_use]
    pub const fn new(network: Network) -> Self {
        Self {
            network,
            accounts: BTreeMap::new(),
            total_issued: 0,
        }
    }

    /// Returns the configured network namespace.
    #[must_use]
    pub const fn network(&self) -> Network {
        self.network
    }

    /// Returns currently issued supply.
    #[must_use]
    pub const fn total_issued(&self) -> Amount {
        self.total_issued
    }

    /// Returns a read-only account state snapshot.
    #[must_use]
    pub fn account(&self, address: &str) -> Option<AccountState> {
        self.accounts.get(address).copied()
    }

    /// Returns all accounts in deterministic address order.
    #[must_use]
    pub fn account_entries(&self) -> Vec<(String, AccountState)> {
        self.accounts
            .iter()
            .map(|(address, state)| (address.clone(), *state))
            .collect()
    }

    /// Returns deterministic state root for the current account map.
    #[must_use]
    pub fn state_root(&self) -> [u8; 32] {
        compute_state_root(&self.accounts)
    }

    /// Initializes genesis balances and enforces max-supply cap.
    pub fn initialize_genesis(
        &mut self,
        allocations: Vec<(String, Amount)>,
    ) -> Result<(), StateError> {
        self.accounts.clear();
        self.total_issued = 0;

        for (address, balance) in allocations {
            validate_address_for_network(&address, self.network)
                .map_err(|source| StateError::InvalidAddress { source })?;
            if self.accounts.contains_key(&address) {
                return Err(StateError::DuplicateGenesisAddress { address });
            }

            let new_total = self
                .total_issued
                .checked_add(balance)
                .ok_or(StateError::SupplyOverflow)?;
            if new_total > MAX_SUPPLY_MICRO_HOMA {
                return Err(StateError::SupplyCapExceeded {
                    cap: MAX_SUPPLY_MICRO_HOMA,
                    attempted: new_total,
                });
            }

            self.accounts
                .insert(address, AccountState { balance, nonce: 0 });
            self.total_issued = new_total;
        }

        Ok(())
    }

    /// Loads full account snapshot entries and enforces max-supply cap.
    pub fn load_snapshot(
        &mut self,
        entries: Vec<(String, AccountState)>,
    ) -> Result<(), StateError> {
        self.accounts.clear();
        self.total_issued = 0;

        for (address, state) in entries {
            validate_address_for_network(&address, self.network)
                .map_err(|source| StateError::InvalidAddress { source })?;
            if self.accounts.contains_key(&address) {
                return Err(StateError::DuplicateSnapshotAddress { address });
            }

            let new_total = self
                .total_issued
                .checked_add(state.balance)
                .ok_or(StateError::SupplyOverflow)?;
            if new_total > MAX_SUPPLY_MICRO_HOMA {
                return Err(StateError::SupplyCapExceeded {
                    cap: MAX_SUPPLY_MICRO_HOMA,
                    attempted: new_total,
                });
            }

            self.accounts.insert(address, state);
            self.total_issued = new_total;
        }

        Ok(())
    }

    /// Applies a block and credits all collected fees to the proposer.
    pub fn apply_block(&mut self, block: &Block) -> Result<BlockApplyOutcome, StateError> {
        block
            .validate_basic()
            .map_err(|source| StateError::BlockValidation { source })?;

        validate_address_for_network(&block.header.proposer, self.network)
            .map_err(|source| StateError::InvalidAddress { source })?;

        let mut collected_fees = 0_u64;

        for (index, transaction) in block.transactions.iter().enumerate() {
            transaction
                .validate_sender_authority_for_network(self.network)
                .map_err(|source| StateError::TransactionValidation { index, source })?;

            let required = transaction
                .debited_total()
                .map_err(|source| StateError::TransactionValidation { index, source })?;

            let sender_state = self.accounts.entry(transaction.sender.clone()).or_default();

            let expected_nonce = sender_state.nonce.saturating_add(1);
            if transaction.nonce != expected_nonce {
                return Err(StateError::NonceMismatch {
                    sender: transaction.sender.clone(),
                    expected: expected_nonce,
                    actual: transaction.nonce,
                });
            }
            if sender_state.balance < required {
                return Err(StateError::InsufficientBalance {
                    sender: transaction.sender.clone(),
                    available: sender_state.balance,
                    required,
                });
            }

            sender_state.balance -= required;
            sender_state.nonce = transaction.nonce;

            let receiver_state = self
                .accounts
                .entry(transaction.receiver.clone())
                .or_default();
            receiver_state.balance = receiver_state
                .balance
                .checked_add(transaction.amount)
                .ok_or(StateError::BalanceOverflow)?;

            collected_fees = collected_fees
                .checked_add(transaction.fee)
                .ok_or(StateError::FeeOverflow)?;
        }

        let proposer_state = self
            .accounts
            .entry(block.header.proposer.clone())
            .or_default();
        proposer_state.balance = proposer_state
            .balance
            .checked_add(collected_fees)
            .ok_or(StateError::BalanceOverflow)?;

        Ok(BlockApplyOutcome {
            applied_transactions: block.transactions.len(),
            collected_fees,
            proposer_reward: collected_fees,
        })
    }
}

fn compute_state_root(accounts: &BTreeMap<String, AccountState>) -> [u8; 32] {
    let mut hasher = blake3::Hasher::new();
    hasher.update(&(accounts.len() as u64).to_le_bytes());

    for (address, state) in accounts {
        hasher.update(&(address.len() as u64).to_le_bytes());
        hasher.update(address.as_bytes());
        hasher.update(&state.balance.to_le_bytes());
        hasher.update(&state.nonce.to_le_bytes());
    }

    *hasher.finalize().as_bytes()
}

#[cfg(test)]
mod tests {
    use super::{ChainState, MAX_SUPPLY_MICRO_HOMA, MICRO_HOMA_PER_HMA, StateError};
    use crate::core::block::{Block, BlockHeader, HASH_LENGTH};
    use crate::core::transaction::Transaction;
    use crate::crypto::address::{Network, derive_address};
    use crate::crypto::keys::Keypair;

    fn address(network: Network) -> String {
        let keypair = Keypair::generate();
        let result = derive_address(&keypair.public_key_bytes(), network);
        assert!(result.is_ok(), "address derivation should succeed");
        result.unwrap_or_else(|_| unreachable!())
    }

    fn address_with_keypair(network: Network) -> (Keypair, String) {
        let keypair = Keypair::generate();
        let address_result = derive_address(&keypair.public_key_bytes(), network);
        assert!(address_result.is_ok(), "address derivation should succeed");
        (keypair, address_result.unwrap_or_else(|_| unreachable!()))
    }

    fn signed_transfer(
        network: Network,
        sender_keypair: &Keypair,
        sender_address: &str,
        receiver_address: &str,
        amount: u64,
        fee: u64,
        nonce: u64,
    ) -> Transaction {
        let unsigned = Transaction::new_unsigned(
            sender_address.to_owned(),
            receiver_address.to_owned(),
            amount,
            fee,
            nonce,
            0,
        )
        .with_sender_public_key(sender_keypair.public_key_bytes());
        let signing_bytes = unsigned.signing_bytes_for_network(network);
        assert!(
            signing_bytes.is_ok(),
            "transaction signing bytes should encode"
        );
        unsigned
            .with_signature(sender_keypair.sign(&signing_bytes.unwrap_or_else(|_| unreachable!())))
    }

    fn sample_block(proposer: String, txs: Vec<Transaction>) -> Block {
        let header = BlockHeader::new(
            1,
            [0_u8; HASH_LENGTH],
            [9_u8; HASH_LENGTH],
            1_717_171_800,
            proposer,
        );
        let block = Block::new_unsigned(header, txs);
        assert!(block.is_ok(), "block construction should succeed");
        block.unwrap_or_else(|_| unreachable!())
    }

    #[test]
    fn genesis_enforces_supply_cap() {
        let mut state = ChainState::new(Network::Testnet);
        let addr = address(Network::Testnet);
        let result = state.initialize_genesis(vec![(addr, MAX_SUPPLY_MICRO_HOMA + 1)]);

        assert!(
            matches!(
                result,
                Err(StateError::SupplyCapExceeded {
                    cap: MAX_SUPPLY_MICRO_HOMA,
                    attempted: _
                })
            ),
            "genesis should reject allocations above max supply"
        );
    }

    #[test]
    fn applies_block_and_distributes_fees_to_proposer() {
        let proposer = address(Network::Testnet);
        let (sender_keypair, sender) = address_with_keypair(Network::Testnet);
        let receiver = address(Network::Testnet);

        let mut state = ChainState::new(Network::Testnet);
        assert!(
            state
                .initialize_genesis(vec![(sender.clone(), 1_000), (receiver.clone(), 0)])
                .is_ok()
        );

        let tx = signed_transfer(
            Network::Testnet,
            &sender_keypair,
            &sender,
            &receiver,
            100,
            3,
            1,
        );
        let block = sample_block(proposer.clone(), vec![tx]);
        let apply_result = state.apply_block(&block);
        assert!(apply_result.is_ok(), "block should apply successfully");
        let outcome = apply_result.unwrap_or_else(|_| unreachable!());

        assert_eq!(outcome.applied_transactions, 1);
        assert_eq!(outcome.collected_fees, 3);
        assert_eq!(outcome.proposer_reward, 3);

        let sender_state = state.account(&sender).unwrap_or_default();
        let receiver_state = state.account(&receiver).unwrap_or_default();
        let proposer_state = state.account(&proposer).unwrap_or_default();

        assert_eq!(sender_state.balance, 897);
        assert_eq!(sender_state.nonce, 1);
        assert_eq!(receiver_state.balance, 100);
        assert_eq!(proposer_state.balance, 3);
    }

    #[test]
    fn rejects_nonce_gap() {
        let proposer = address(Network::Testnet);
        let (sender_keypair, sender) = address_with_keypair(Network::Testnet);
        let receiver = address(Network::Testnet);

        let mut state = ChainState::new(Network::Testnet);
        assert!(
            state
                .initialize_genesis(vec![(sender.clone(), 1000)])
                .is_ok()
        );

        let tx = signed_transfer(
            Network::Testnet,
            &sender_keypair,
            &sender,
            &receiver,
            10,
            1,
            2,
        );
        let block = sample_block(proposer, vec![tx]);
        let apply_result = state.apply_block(&block);

        assert!(
            matches!(
                apply_result,
                Err(StateError::NonceMismatch {
                    sender: _,
                    expected: 1,
                    actual: 2
                })
            ),
            "sender nonce must increment by exactly one"
        );
    }

    #[test]
    fn rejects_insufficient_balance() {
        let proposer = address(Network::Testnet);
        let (sender_keypair, sender) = address_with_keypair(Network::Testnet);
        let receiver = address(Network::Testnet);

        let mut state = ChainState::new(Network::Testnet);
        assert!(state.initialize_genesis(vec![(sender.clone(), 50)]).is_ok());

        let tx = signed_transfer(
            Network::Testnet,
            &sender_keypair,
            &sender,
            &receiver,
            60,
            1,
            1,
        );
        let block = sample_block(proposer, vec![tx]);
        let apply_result = state.apply_block(&block);

        assert!(
            matches!(
                apply_result,
                Err(StateError::InsufficientBalance {
                    sender: _,
                    available: 50,
                    required: 61
                })
            ),
            "sender must hold enough balance for amount + fee"
        );
    }

    #[test]
    fn block_finalization_preserves_total_issued_supply() {
        let proposer = address(Network::Testnet);
        let (sender_keypair, sender) = address_with_keypair(Network::Testnet);
        let receiver = address(Network::Testnet);

        let mut state = ChainState::new(Network::Testnet);
        let genesis_total = 500 * MICRO_HOMA_PER_HMA;
        assert!(
            state
                .initialize_genesis(vec![(sender.clone(), genesis_total), (receiver.clone(), 0)])
                .is_ok()
        );

        let before = state.total_issued();
        let tx = signed_transfer(
            Network::Testnet,
            &sender_keypair,
            &sender,
            &receiver,
            100,
            2,
            1,
        );
        let block = sample_block(proposer, vec![tx]);
        assert!(state.apply_block(&block).is_ok());
        let after = state.total_issued();

        assert_eq!(before, after, "fee redistribution must not mint new supply");
    }

    #[test]
    fn rejects_sender_authority_mismatch() {
        let proposer = address(Network::Testnet);
        let (sender_keypair, sender) = address_with_keypair(Network::Testnet);
        let receiver = address(Network::Testnet);
        let attacker_keypair = Keypair::generate();

        let mut state = ChainState::new(Network::Testnet);
        assert!(
            state
                .initialize_genesis(vec![(sender.clone(), 500)])
                .is_ok()
        );

        let mut tx = signed_transfer(
            Network::Testnet,
            &sender_keypair,
            &sender,
            &receiver,
            10,
            1,
            1,
        );
        tx.sender_public_key = attacker_keypair.public_key_bytes().to_vec();

        let block = sample_block(proposer, vec![tx]);
        let apply_result = state.apply_block(&block);
        assert!(
            matches!(
                apply_result,
                Err(StateError::TransactionValidation {
                    index: 0,
                    source: crate::core::transaction::TransactionError::SenderAuthorityMismatch
                })
            ),
            "block finalization must reject transactions whose sender key does not match sender address"
        );
    }
}
