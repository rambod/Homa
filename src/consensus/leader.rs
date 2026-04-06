//! Stake-weighted leader election.

use thiserror::Error;

use crate::consensus::stake::{StakeAmount, StakeLedger};
use crate::observability::{Observability, SlotMissReason};

/// Output of one leader election decision.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LeaderSelection {
    /// Slot index used for deterministic selection.
    pub slot: u64,
    /// Selected validator address.
    pub leader: String,
    /// Total active stake considered for this election.
    pub total_stake: StakeAmount,
    /// Slot modulo `total_stake` that mapped to the leader bucket.
    pub bucket_index: StakeAmount,
}

/// Leader election errors.
#[derive(Debug, Clone, PartialEq, Eq, Error)]
pub enum LeaderElectionError {
    /// No validators exist in the stake table.
    #[error("cannot elect leader from an empty stake set")]
    EmptyStakeSet,
    /// Aggregate stake overflowed while computing totals.
    #[error("stake total overflowed")]
    StakeTotalOverflow,
    /// Stake entry with zero amount was observed.
    #[error("zero stake validator encountered: {validator}")]
    ZeroStakeValidator {
        /// Validator address with zero stake.
        validator: String,
    },
    /// Internal inconsistency while mapping bucket index to a validator.
    #[error("failed to map slot bucket to validator")]
    MappingFailure,
}

/// Deterministic stake-weighted round-robin election.
///
/// Validators are traversed in lexicographic address order. Each validator owns a
/// contiguous bucket range proportional to stake amount. Slot-to-leader mapping uses:
///
/// `bucket_index = slot % total_stake`
#[allow(clippy::missing_panics_doc)]
pub fn elect_leader(
    ledger: &StakeLedger,
    slot: u64,
) -> Result<LeaderSelection, LeaderElectionError> {
    let snapshot = ledger.snapshot();
    if snapshot.is_empty() {
        return Err(LeaderElectionError::EmptyStakeSet);
    }

    let total_stake = snapshot.iter().try_fold(0_u64, |accumulator, (_, stake)| {
        if *stake == 0 {
            return Err(LeaderElectionError::ZeroStakeValidator {
                validator: String::new(),
            });
        }
        accumulator
            .checked_add(*stake)
            .ok_or(LeaderElectionError::StakeTotalOverflow)
    })?;

    if total_stake == 0 {
        return Err(LeaderElectionError::EmptyStakeSet);
    }

    let bucket_index = slot % total_stake;
    let mut cumulative = 0_u64;

    for (validator, stake) in snapshot {
        if stake == 0 {
            return Err(LeaderElectionError::ZeroStakeValidator { validator });
        }
        cumulative = cumulative
            .checked_add(stake)
            .ok_or(LeaderElectionError::StakeTotalOverflow)?;
        if bucket_index < cumulative {
            return Ok(LeaderSelection {
                slot,
                leader: validator,
                total_stake,
                bucket_index,
            });
        }
    }

    Err(LeaderElectionError::MappingFailure)
}

/// Builds a contiguous leader schedule for `[start_slot, start_slot + slots)`.
pub fn build_schedule(
    ledger: &StakeLedger,
    start_slot: u64,
    slots: u64,
) -> Result<Vec<LeaderSelection>, LeaderElectionError> {
    (0..slots)
        .map(|offset| {
            let slot = start_slot
                .checked_add(offset)
                .ok_or(LeaderElectionError::StakeTotalOverflow)?;
            elect_leader(ledger, slot)
        })
        .collect()
}

/// Records a consensus slot miss when observed proposer diverges from expected leader.
///
/// Returns `true` if a miss was recorded and `false` when slot execution matched expectation.
pub fn record_slot_observation(
    observability: &Observability,
    slot: u64,
    expected_leader: &str,
    observed_proposer: Option<&str>,
) -> bool {
    if observed_proposer == Some(expected_leader) {
        return false;
    }

    let reason = if observed_proposer.is_some() {
        SlotMissReason::UnexpectedProposer
    } else {
        SlotMissReason::LeaderDidNotProduce
    };
    observability.record_slot_miss(slot, expected_leader, observed_proposer, reason);
    true
}

#[cfg(test)]
mod tests {
    use std::collections::{BTreeMap, BTreeSet};

    use super::{LeaderElectionError, build_schedule, elect_leader, record_slot_observation};
    use crate::consensus::stake::{StakeError, StakeLedger};
    use crate::crypto::address::{Network, derive_address};
    use crate::crypto::keys::Keypair;
    use crate::observability::Observability;

    fn validator(network: Network) -> String {
        let keypair = Keypair::generate();
        let derived = derive_address(&keypair.public_key_bytes(), network);
        assert!(derived.is_ok(), "address derivation should succeed");
        derived.unwrap_or_else(|_| unreachable!())
    }

    fn deterministic_validator(network: Network, seed: u64) -> String {
        let mut material = [0_u8; 8];
        material.copy_from_slice(&seed.to_le_bytes());
        let secret = *blake3::hash(&material).as_bytes();
        let keypair = Keypair::from_secret_key(&secret);
        assert!(keypair.is_ok(), "seeded keypair should be constructible");
        let keypair = keypair.unwrap_or_else(|_| unreachable!());
        let derived = derive_address(&keypair.public_key_bytes(), network);
        assert!(derived.is_ok(), "address derivation should succeed");
        derived.unwrap_or_else(|_| unreachable!())
    }

    #[test]
    fn rejects_empty_stake_set() {
        let ledger = StakeLedger::new(Network::Testnet);
        let selected = elect_leader(&ledger, 0);
        assert!(
            matches!(selected, Err(LeaderElectionError::EmptyStakeSet)),
            "leader election requires at least one validator"
        );
    }

    #[test]
    fn election_is_deterministic_for_same_slot() {
        let mut ledger = StakeLedger::new(Network::Testnet);
        let validator_a = validator(Network::Testnet);
        let validator_b = validator(Network::Testnet);
        assert!(ledger.add_stake(validator_a, 5).is_ok());
        assert!(ledger.add_stake(validator_b, 2).is_ok());

        let first = elect_leader(&ledger, 123);
        let second = elect_leader(&ledger, 123);
        assert!(first.is_ok(), "first election should succeed");
        assert!(second.is_ok(), "second election should succeed");
        assert_eq!(
            first.unwrap_or_else(|_| unreachable!()),
            second.unwrap_or_else(|_| unreachable!()),
            "same slot and stake table must yield same leader"
        );
    }

    #[test]
    fn weighted_round_robin_matches_stake_proportions_per_cycle() {
        let mut ledger = StakeLedger::new(Network::Devnet);
        let validator_a = validator(Network::Devnet);
        let validator_b = validator(Network::Devnet);
        assert!(ledger.add_stake(validator_a.clone(), 3).is_ok());
        assert!(ledger.add_stake(validator_b.clone(), 1).is_ok());

        let schedule = build_schedule(&ledger, 0, 4);
        assert!(schedule.is_ok(), "schedule should build");
        let schedule = schedule.unwrap_or_else(|_| unreachable!());

        let mut counts = BTreeMap::new();
        for selection in schedule {
            *counts.entry(selection.leader).or_insert(0_u64) += 1;
        }

        assert_eq!(counts.get(&validator_a).copied().unwrap_or(0), 3);
        assert_eq!(counts.get(&validator_b).copied().unwrap_or(0), 1);
    }

    #[test]
    fn bucket_index_is_bounded_by_total_stake() {
        let mut ledger = StakeLedger::new(Network::Mainnet);
        let validator_a = validator(Network::Mainnet);
        assert!(ledger.add_stake(validator_a, 10).is_ok());

        let selected = elect_leader(&ledger, 999_999);
        assert!(selected.is_ok(), "election should succeed");
        let selected = selected.unwrap_or_else(|_| unreachable!());

        assert!(selected.bucket_index < selected.total_stake);
    }

    #[test]
    fn zero_stake_sybil_nodes_cannot_influence_leader_schedule() {
        let mut ledger = StakeLedger::new(Network::Testnet);

        let validator_a = deterministic_validator(Network::Testnet, 1);
        let validator_b = deterministic_validator(Network::Testnet, 2);
        assert!(ledger.add_stake(validator_a.clone(), 70).is_ok());
        assert!(ledger.add_stake(validator_b.clone(), 30).is_ok());

        let mut sybil_addresses = BTreeSet::new();
        for index in 0_u64..1_000_u64 {
            let sybil = deterministic_validator(Network::Testnet, 10_000 + index);
            let inserted = sybil_addresses.insert(sybil.clone());
            assert!(inserted, "deterministic seed should produce unique sybil");

            let add_result = ledger.add_stake(sybil, 0);
            assert!(
                matches!(add_result, Err(StakeError::ZeroAmount)),
                "zero-stake nodes must be rejected from validator stake set"
            );
        }

        assert_eq!(
            ledger.validator_count(),
            2,
            "only staked validators should remain eligible"
        );
        assert_eq!(ledger.total_staked(), 100);

        let schedule = build_schedule(&ledger, 0, 2_000);
        assert!(
            schedule.is_ok(),
            "leader schedule should build with honest validators"
        );

        for selection in schedule.unwrap_or_else(|_| unreachable!()) {
            assert!(
                !sybil_addresses.contains(&selection.leader),
                "zero-stake sybil nodes must never appear as block leaders"
            );
            assert!(
                selection.leader == validator_a || selection.leader == validator_b,
                "only honest staked validators may produce blocks"
            );
        }
    }

    #[test]
    fn records_slot_miss_when_no_block_produced() {
        let observability = Observability::new(8);
        let recorded = record_slot_observation(&observability, 55, "HMA_EXPECTED", None);
        assert!(recorded, "missing block should be counted as slot miss");
        assert_eq!(observability.slot_miss_total(), 1);
    }

    #[test]
    fn does_not_record_slot_miss_for_expected_proposer() {
        let observability = Observability::new(8);
        let recorded =
            record_slot_observation(&observability, 56, "HMA_EXPECTED", Some("HMA_EXPECTED"));
        assert!(!recorded, "matching proposer should not be a slot miss");
        assert_eq!(observability.slot_miss_total(), 0);
    }
}
