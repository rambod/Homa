//! In-memory validator stake tracking.

use std::collections::BTreeMap;

use thiserror::Error;

use crate::crypto::address::{AddressError, Network, validate_address_for_network};

/// Stake amount in micro-homas.
pub type StakeAmount = u64;

/// Validator stake table with cached total staked amount.
#[derive(Debug, Clone)]
pub struct StakeLedger {
    network: Network,
    stakes: BTreeMap<String, StakeAmount>,
    total_staked: StakeAmount,
}

/// Stake accounting and validation errors.
#[derive(Debug, Clone, PartialEq, Eq, Error)]
pub enum StakeError {
    /// Stake target address is malformed or from another network.
    #[error("invalid validator address")]
    InvalidValidatorAddress {
        /// Inner address parsing error.
        source: AddressError,
    },
    /// Stake delta must be non-zero.
    #[error("stake amount must be greater than zero")]
    ZeroAmount,
    /// Stake addition overflowed the `u64` domain.
    #[error("stake amount overflow")]
    StakeOverflow,
    /// Global total staked amount overflowed.
    #[error("total staked overflow")]
    TotalOverflow,
    /// Validator does not exist in ledger.
    #[error("unknown validator")]
    UnknownValidator,
    /// Unstake request exceeds current balance.
    #[error("insufficient stake: available {available}, requested {requested}")]
    InsufficientStake {
        /// Current validator stake.
        available: StakeAmount,
        /// Requested unstake amount.
        requested: StakeAmount,
    },
}

impl StakeLedger {
    /// Creates an empty ledger bound to one network namespace.
    #[must_use]
    pub const fn new(network: Network) -> Self {
        Self {
            network,
            stakes: BTreeMap::new(),
            total_staked: 0,
        }
    }

    /// Returns the configured network for validator addresses.
    #[must_use]
    pub const fn network(&self) -> Network {
        self.network
    }

    /// Returns staked amount for a validator, or 0 if not present.
    #[must_use]
    pub fn stake_of(&self, validator: &str) -> StakeAmount {
        self.stakes.get(validator).copied().unwrap_or(0)
    }

    /// Returns total staked amount across all validators.
    #[must_use]
    pub const fn total_staked(&self) -> StakeAmount {
        self.total_staked
    }

    /// Returns number of validators with non-zero stake.
    #[must_use]
    pub fn validator_count(&self) -> usize {
        self.stakes.len()
    }

    /// Adds stake to a validator entry, creating it if needed.
    pub fn add_stake(
        &mut self,
        validator: String,
        amount: StakeAmount,
    ) -> Result<StakeAmount, StakeError> {
        self.validate_validator_address(&validator)?;
        if amount == 0 {
            return Err(StakeError::ZeroAmount);
        }

        let current = self.stakes.get(&validator).copied().unwrap_or(0);
        let updated = current
            .checked_add(amount)
            .ok_or(StakeError::StakeOverflow)?;
        let updated_total = self
            .total_staked
            .checked_add(amount)
            .ok_or(StakeError::TotalOverflow)?;

        self.stakes.insert(validator, updated);
        self.total_staked = updated_total;
        Ok(updated)
    }

    /// Removes stake from a validator entry.
    ///
    /// The validator is removed from the map when resulting stake reaches zero.
    pub fn remove_stake(
        &mut self,
        validator: &str,
        amount: StakeAmount,
    ) -> Result<StakeAmount, StakeError> {
        self.validate_validator_address(validator)?;
        if amount == 0 {
            return Err(StakeError::ZeroAmount);
        }

        let current = self
            .stakes
            .get(validator)
            .copied()
            .ok_or(StakeError::UnknownValidator)?;
        if amount > current {
            return Err(StakeError::InsufficientStake {
                available: current,
                requested: amount,
            });
        }

        let remaining = current - amount;
        self.total_staked = self
            .total_staked
            .checked_sub(amount)
            .ok_or(StakeError::TotalOverflow)?;

        if remaining == 0 {
            self.stakes.remove(validator);
        } else {
            self.stakes.insert(validator.to_owned(), remaining);
        }

        Ok(remaining)
    }

    /// Returns validators sorted by descending stake, then lexicographically by address.
    #[must_use]
    pub fn top_validators(&self, limit: usize) -> Vec<(String, StakeAmount)> {
        let mut entries = self
            .stakes
            .iter()
            .map(|(validator, amount)| (validator.clone(), *amount))
            .collect::<Vec<_>>();

        entries.sort_unstable_by(|left, right| {
            right.1.cmp(&left.1).then_with(|| left.0.cmp(&right.0))
        });

        entries.truncate(limit);
        entries
    }

    /// Returns a deterministic snapshot ordered lexicographically by validator address.
    #[must_use]
    pub fn snapshot(&self) -> Vec<(String, StakeAmount)> {
        self.stakes
            .iter()
            .map(|(validator, amount)| (validator.clone(), *amount))
            .collect()
    }

    fn validate_validator_address(&self, validator: &str) -> Result<(), StakeError> {
        validate_address_for_network(validator, self.network)
            .map(|_| ())
            .map_err(|source| StakeError::InvalidValidatorAddress { source })
    }
}

#[cfg(test)]
mod tests {
    use super::{StakeError, StakeLedger};
    use crate::crypto::address::{Network, derive_address};
    use crate::crypto::keys::Keypair;

    fn validator_address(network: Network) -> String {
        let keypair = Keypair::generate();
        let address = derive_address(&keypair.public_key_bytes(), network);
        assert!(address.is_ok(), "address derivation should succeed");
        address.unwrap_or_else(|_| unreachable!())
    }

    #[test]
    fn add_stake_updates_ledger_and_total() {
        let mut ledger = StakeLedger::new(Network::Testnet);
        let validator = validator_address(Network::Testnet);

        let first = ledger.add_stake(validator.clone(), 10);
        assert!(first.is_ok(), "first stake should succeed");
        assert_eq!(first.unwrap_or_default(), 10);

        let second = ledger.add_stake(validator.clone(), 5);
        assert!(second.is_ok(), "second stake should succeed");
        assert_eq!(second.unwrap_or_default(), 15);
        assert_eq!(ledger.stake_of(&validator), 15);
        assert_eq!(ledger.total_staked(), 15);
        assert_eq!(ledger.validator_count(), 1);
    }

    #[test]
    fn remove_stake_reduces_and_prunes_zero_entries() {
        let mut ledger = StakeLedger::new(Network::Testnet);
        let validator = validator_address(Network::Testnet);

        assert!(ledger.add_stake(validator.clone(), 25).is_ok());
        let remaining = ledger.remove_stake(&validator, 5);
        assert!(remaining.is_ok(), "unstake should succeed");
        assert_eq!(remaining.unwrap_or_default(), 20);
        assert_eq!(ledger.stake_of(&validator), 20);
        assert_eq!(ledger.total_staked(), 20);

        let final_remaining = ledger.remove_stake(&validator, 20);
        assert!(final_remaining.is_ok(), "full unstake should succeed");
        assert_eq!(final_remaining.unwrap_or_default(), 0);
        assert_eq!(ledger.stake_of(&validator), 0);
        assert_eq!(ledger.total_staked(), 0);
        assert_eq!(ledger.validator_count(), 0);
    }

    #[test]
    fn rejects_cross_network_validator_address() {
        let mut ledger = StakeLedger::new(Network::Testnet);
        let mainnet_validator = validator_address(Network::Mainnet);

        let result = ledger.add_stake(mainnet_validator, 1);
        assert!(
            matches!(
                result,
                Err(StakeError::InvalidValidatorAddress { source: _ })
            ),
            "cross-network validator addresses must be rejected"
        );
    }

    #[test]
    fn rejects_insufficient_unstake_amount() {
        let mut ledger = StakeLedger::new(Network::Testnet);
        let validator = validator_address(Network::Testnet);

        assert!(ledger.add_stake(validator.clone(), 3).is_ok());
        let result = ledger.remove_stake(&validator, 5);
        assert!(
            matches!(
                result,
                Err(StakeError::InsufficientStake {
                    available: 3,
                    requested: 5
                })
            ),
            "cannot unstake beyond available amount"
        );
    }

    #[test]
    fn top_validators_are_sorted_by_stake_then_address() {
        let mut ledger = StakeLedger::new(Network::Devnet);

        let validator_a = validator_address(Network::Devnet);
        let validator_b = validator_address(Network::Devnet);
        let validator_c = validator_address(Network::Devnet);

        assert!(ledger.add_stake(validator_a, 10).is_ok());
        assert!(ledger.add_stake(validator_b, 30).is_ok());
        assert!(ledger.add_stake(validator_c, 20).is_ok());

        let top_two = ledger.top_validators(2);
        assert_eq!(top_two.len(), 2);
        assert!(top_two[0].1 >= top_two[1].1);
        assert_eq!(top_two[0].1, 30);
        assert_eq!(top_two[1].1, 20);
    }
}
