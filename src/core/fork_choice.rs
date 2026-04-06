//! Deterministic fork-choice and partition rejoin reconciliation.

use thiserror::Error;

use crate::core::block::{Block, BlockError, BlockHash, StateRoot};
use crate::core::state::{ChainState, StateError};

/// Summary metadata for one candidate branch tip.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct BranchMeta {
    /// Tip height of the candidate branch.
    pub tip_height: u64,
    /// Hash of the tip block.
    pub tip_hash: BlockHash,
    /// Cumulative transaction fees across branch blocks.
    pub cumulative_fees: u128,
    /// Number of blocks in the branch segment.
    pub block_count: usize,
}

/// Deterministic fork preference when comparing local vs remote branches.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ForkPreference {
    /// Keep the currently local branch.
    KeepLocal,
    /// Switch to the remote branch.
    SwitchToRemote,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum BranchRole {
    Local,
    Remote,
}

/// Errors produced by fork-choice validation and partition reconciliation.
#[derive(Debug, Clone, PartialEq, Eq, Error)]
pub enum ForkChoiceError {
    /// Branch has no blocks.
    #[error("{branch:?} branch is empty")]
    EmptyBranch {
        /// Which branch failed validation.
        branch: ForkBranch,
    },
    /// Height continuity check failed for adjacent blocks.
    #[error(
        "{branch:?} branch height mismatch at block index {index}: expected {expected}, got {actual}"
    )]
    HeightMismatch {
        /// Which branch failed validation.
        branch: ForkBranch,
        /// Index of the block that failed the check.
        index: usize,
        /// Expected block height (`previous + 1`).
        expected: u64,
        /// Observed block height.
        actual: u64,
    },
    /// Height arithmetic overflowed while validating continuity.
    #[error("{branch:?} branch height overflow while validating block index {index}")]
    HeightOverflow {
        /// Which branch failed validation.
        branch: ForkBranch,
        /// Index of predecessor block that overflowed on `+1`.
        index: usize,
    },
    /// `previous_block_hash` does not match predecessor hash.
    #[error("{branch:?} branch previous hash mismatch at block index {index}")]
    PreviousHashMismatch {
        /// Which branch failed validation.
        branch: ForkBranch,
        /// Index of the block that failed the check.
        index: usize,
        /// Expected parent hash.
        expected: BlockHash,
        /// Observed parent hash.
        actual: BlockHash,
    },
    /// Failed to compute block hash while validating branch links.
    #[error("{branch:?} branch block hash computation failed at block index {index}")]
    BlockHashComputation {
        /// Which branch failed validation.
        branch: ForkBranch,
        /// Block index that failed hashing.
        index: usize,
        /// Underlying block error.
        source: BlockError,
    },
    /// Fee accumulation overflowed while summarizing branch weight.
    #[error("{branch:?} branch cumulative fee overflow")]
    FeeOverflow {
        /// Which branch overflowed.
        branch: ForkBranch,
    },
    /// Branches do not descend from the same known ancestor tip.
    #[error("local and remote branches do not share a common ancestor hash")]
    NoCommonAncestor {
        /// First local block parent hash.
        local_parent: BlockHash,
        /// First remote block parent hash.
        remote_parent: BlockHash,
    },
    /// Applying selected branch failed state-transition checks.
    #[error("{branch:?} branch state transition failed at block index {index}")]
    StateTransition {
        /// Which branch failed reconciliation application.
        branch: ForkBranch,
        /// Block index that failed state application.
        index: usize,
        /// Underlying state transition error.
        source: StateError,
    },
    /// Header state root did not match computed post-state root.
    #[error("{branch:?} branch state root mismatch at block index {index}")]
    StateRootMismatch {
        /// Which branch failed reconciliation application.
        branch: ForkBranch,
        /// Block index that failed state-root verification.
        index: usize,
        /// Header-declared state root.
        expected: StateRoot,
        /// Computed state root after applying block.
        actual: StateRoot,
    },
}

/// Public branch label used in typed fork-choice errors.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ForkBranch {
    /// Local branch.
    Local,
    /// Remote branch.
    Remote,
}

impl From<BranchRole> for ForkBranch {
    fn from(value: BranchRole) -> Self {
        match value {
            BranchRole::Local => Self::Local,
            BranchRole::Remote => Self::Remote,
        }
    }
}

/// Result of partition reconciliation against local and remote candidate branches.
#[derive(Debug, Clone)]
pub struct ReconciliationOutcome {
    /// Deterministic branch preference decision.
    pub preference: ForkPreference,
    /// Metadata of local branch candidate.
    pub local_meta: BranchMeta,
    /// Metadata of remote branch candidate.
    pub remote_meta: BranchMeta,
    /// Reconciled resulting chain state after applying the winning branch.
    pub resulting_state: ChainState,
}

/// Summarizes one branch and validates internal block-link continuity.
pub fn branch_meta(
    branch: &[Block],
    branch_label: ForkBranch,
) -> Result<BranchMeta, ForkChoiceError> {
    let role = match branch_label {
        ForkBranch::Local => BranchRole::Local,
        ForkBranch::Remote => BranchRole::Remote,
    };
    branch_meta_for_role(branch, role)
}

/// Deterministic fork-choice rule:
/// 1) higher tip height wins
/// 2) if equal, higher cumulative fees win
/// 3) if equal, lexicographically smaller tip hash wins
#[must_use]
pub fn choose_fork(local: &BranchMeta, remote: &BranchMeta) -> ForkPreference {
    if remote.tip_height > local.tip_height {
        return ForkPreference::SwitchToRemote;
    }
    if remote.tip_height < local.tip_height {
        return ForkPreference::KeepLocal;
    }

    if remote.cumulative_fees > local.cumulative_fees {
        return ForkPreference::SwitchToRemote;
    }
    if remote.cumulative_fees < local.cumulative_fees {
        return ForkPreference::KeepLocal;
    }

    if remote.tip_hash < local.tip_hash {
        ForkPreference::SwitchToRemote
    } else {
        ForkPreference::KeepLocal
    }
}

/// Reconciles a partition by selecting one branch with deterministic fork-choice
/// and re-applying it from a shared pre-fork state snapshot.
pub fn reconcile_partition(
    pre_fork_state: &ChainState,
    local_branch: &[Block],
    remote_branch: &[Block],
) -> Result<ReconciliationOutcome, ForkChoiceError> {
    let local_meta = branch_meta_for_role(local_branch, BranchRole::Local)?;
    let remote_meta = branch_meta_for_role(remote_branch, BranchRole::Remote)?;

    let local_parent = local_branch
        .first()
        .map(|block| block.header.previous_block_hash)
        .ok_or(ForkChoiceError::EmptyBranch {
            branch: ForkBranch::Local,
        })?;
    let remote_parent = remote_branch
        .first()
        .map(|block| block.header.previous_block_hash)
        .ok_or(ForkChoiceError::EmptyBranch {
            branch: ForkBranch::Remote,
        })?;
    if local_parent != remote_parent {
        return Err(ForkChoiceError::NoCommonAncestor {
            local_parent,
            remote_parent,
        });
    }

    let preference = choose_fork(&local_meta, &remote_meta);
    let (selected_role, selected_branch) = match preference {
        ForkPreference::KeepLocal => (BranchRole::Local, local_branch),
        ForkPreference::SwitchToRemote => (BranchRole::Remote, remote_branch),
    };

    let mut resulting_state = pre_fork_state.clone();
    for (index, block) in selected_branch.iter().enumerate() {
        resulting_state
            .apply_block(block)
            .map_err(|source| ForkChoiceError::StateTransition {
                branch: selected_role.into(),
                index,
                source,
            })?;

        let computed_root = resulting_state.state_root();
        if computed_root != block.header.state_root {
            return Err(ForkChoiceError::StateRootMismatch {
                branch: selected_role.into(),
                index,
                expected: block.header.state_root,
                actual: computed_root,
            });
        }
    }

    Ok(ReconciliationOutcome {
        preference,
        local_meta,
        remote_meta,
        resulting_state,
    })
}

fn branch_meta_for_role(branch: &[Block], role: BranchRole) -> Result<BranchMeta, ForkChoiceError> {
    if branch.is_empty() {
        return Err(ForkChoiceError::EmptyBranch {
            branch: role.into(),
        });
    }

    let mut cumulative_fees = 0_u128;

    for (index, block) in branch.iter().enumerate() {
        if index > 0 {
            let previous = &branch[index - 1];
            let expected_height = previous.header.height.checked_add(1).ok_or_else(|| {
                ForkChoiceError::HeightOverflow {
                    branch: role.into(),
                    index: index - 1,
                }
            })?;
            if block.header.height != expected_height {
                return Err(ForkChoiceError::HeightMismatch {
                    branch: role.into(),
                    index,
                    expected: expected_height,
                    actual: block.header.height,
                });
            }

            let expected_parent =
                previous
                    .hash()
                    .map_err(|source| ForkChoiceError::BlockHashComputation {
                        branch: role.into(),
                        index: index - 1,
                        source,
                    })?;
            if block.header.previous_block_hash != expected_parent {
                return Err(ForkChoiceError::PreviousHashMismatch {
                    branch: role.into(),
                    index,
                    expected: expected_parent,
                    actual: block.header.previous_block_hash,
                });
            }
        }

        let block_fees =
            block
                .transactions
                .iter()
                .try_fold(0_u128, |accumulator, transaction| {
                    accumulator
                        .checked_add(u128::from(transaction.fee))
                        .ok_or_else(|| ForkChoiceError::FeeOverflow {
                            branch: role.into(),
                        })
                })?;
        cumulative_fees = cumulative_fees.checked_add(block_fees).ok_or_else(|| {
            ForkChoiceError::FeeOverflow {
                branch: role.into(),
            }
        })?;
    }

    let tip_index = branch.len() - 1;
    let tip = &branch[tip_index];
    let tip_hash = tip
        .hash()
        .map_err(|source| ForkChoiceError::BlockHashComputation {
            branch: role.into(),
            index: tip_index,
            source,
        })?;

    Ok(BranchMeta {
        tip_height: tip.header.height,
        tip_hash,
        cumulative_fees,
        block_count: branch.len(),
    })
}

#[cfg(test)]
mod tests {
    use super::{
        BranchMeta, ForkBranch, ForkChoiceError, ForkPreference, branch_meta, choose_fork,
        reconcile_partition,
    };
    use crate::core::block::{Block, BlockHash, BlockHeader, HASH_LENGTH};
    use crate::core::state::ChainState;
    use crate::core::transaction::Transaction;
    use crate::crypto::address::{Network, derive_address};
    use crate::crypto::keys::Keypair;

    const TEST_SENDER_SEED: u64 = 13;

    fn deterministic_address(network: Network, seed: u64) -> String {
        let material = blake3::hash(&seed.to_le_bytes());
        let keypair = Keypair::from_secret_key(material.as_bytes());
        assert!(keypair.is_ok(), "seeded keypair should be valid");
        let keypair = keypair.unwrap_or_else(|_| unreachable!());
        let derived = derive_address(&keypair.public_key_bytes(), network);
        assert!(derived.is_ok(), "address derivation should succeed");
        derived.unwrap_or_else(|_| unreachable!())
    }

    fn build_state(network: Network) -> (ChainState, String, String, String, String) {
        let proposer_local = deterministic_address(network, 11);
        let proposer_remote = deterministic_address(network, 12);
        let sender = deterministic_address(network, TEST_SENDER_SEED);
        let receiver = deterministic_address(network, 14);

        let mut state = ChainState::new(network);
        let initialized =
            state.initialize_genesis(vec![(sender.clone(), 1_000_000), (receiver.clone(), 0)]);
        assert!(initialized.is_ok(), "genesis should initialize");
        (state, proposer_local, proposer_remote, sender, receiver)
    }

    fn transaction(
        network: Network,
        sender_seed: u64,
        sender: &str,
        receiver: &str,
        nonce: u64,
        fee: u64,
    ) -> Transaction {
        let material = blake3::hash(&sender_seed.to_le_bytes());
        let sender_keypair = Keypair::from_secret_key(material.as_bytes());
        assert!(
            sender_keypair.is_ok(),
            "seeded sender keypair should be valid"
        );
        let sender_keypair = sender_keypair.unwrap_or_else(|_| unreachable!());

        let unsigned =
            Transaction::new_unsigned(sender.to_owned(), receiver.to_owned(), 10, fee, nonce, 0)
                .with_sender_public_key(sender_keypair.public_key_bytes());
        let signing_bytes = unsigned.signing_bytes_for_network(network);
        assert!(
            signing_bytes.is_ok(),
            "branch transaction signing bytes should encode"
        );
        unsigned
            .with_signature(sender_keypair.sign(&signing_bytes.unwrap_or_else(|_| unreachable!())))
    }

    fn build_block_with_state_root(
        state_before: &ChainState,
        previous_hash: BlockHash,
        height: u64,
        proposer: &str,
        txs: Vec<Transaction>,
        timestamp_unix_ms: u64,
    ) -> Block {
        let provisional_header = BlockHeader::new(
            height,
            previous_hash,
            [0_u8; HASH_LENGTH],
            timestamp_unix_ms,
            proposer.to_owned(),
        );
        let provisional = Block::new_unsigned(provisional_header, txs.clone());
        assert!(provisional.is_ok(), "provisional block should build");
        let provisional = provisional.unwrap_or_else(|_| unreachable!());

        let mut projected_state = state_before.clone();
        let projected = projected_state.apply_block(&provisional);
        assert!(
            projected.is_ok(),
            "projected block application should succeed"
        );
        let projected_root = projected_state.state_root();

        let final_header = BlockHeader::new(
            height,
            previous_hash,
            projected_root,
            timestamp_unix_ms,
            proposer.to_owned(),
        );
        let final_block = Block::new_unsigned(final_header, txs);
        assert!(final_block.is_ok(), "final block should build");
        final_block.unwrap_or_else(|_| unreachable!())
    }

    fn build_branch(
        pre_fork_state: &ChainState,
        ancestor_hash: BlockHash,
        proposer: &str,
        sender: &str,
        receiver: &str,
        fees: &[u64],
    ) -> Vec<Block> {
        let mut branch = Vec::new();
        let mut state = pre_fork_state.clone();
        let mut previous_hash = ancestor_hash;

        for (index, fee) in fees.iter().enumerate() {
            let block = build_block_with_state_root(
                &state,
                previous_hash,
                (index as u64) + 1,
                proposer,
                vec![transaction(
                    state.network(),
                    TEST_SENDER_SEED,
                    sender,
                    receiver,
                    (index as u64) + 1,
                    *fee,
                )],
                1_800_000_000_000 + (index as u64),
            );
            let applied = state.apply_block(&block);
            assert!(applied.is_ok(), "branch block should apply");
            let hashed = block.hash();
            assert!(hashed.is_ok(), "block hash should compute");
            previous_hash = hashed.unwrap_or_else(|_| unreachable!());
            branch.push(block);
        }

        branch
    }

    #[test]
    fn fork_choice_prefers_higher_height() {
        let network = Network::Testnet;
        let (pre_state, proposer_local, proposer_remote, sender, receiver) = build_state(network);
        let ancestor_hash = [7_u8; HASH_LENGTH];

        let local_branch = build_branch(
            &pre_state,
            ancestor_hash,
            &proposer_local,
            &sender,
            &receiver,
            &[1],
        );
        let remote_branch = build_branch(
            &pre_state,
            ancestor_hash,
            &proposer_remote,
            &sender,
            &receiver,
            &[1, 1],
        );

        let local_meta = branch_meta(&local_branch, ForkBranch::Local);
        let remote_meta = branch_meta(&remote_branch, ForkBranch::Remote);
        assert!(local_meta.is_ok(), "local metadata should build");
        assert!(remote_meta.is_ok(), "remote metadata should build");
        let preference = choose_fork(
            &local_meta.unwrap_or_else(|_| unreachable!()),
            &remote_meta.unwrap_or_else(|_| unreachable!()),
        );
        assert_eq!(preference, ForkPreference::SwitchToRemote);
    }

    #[test]
    fn fork_choice_prefers_higher_fees_when_height_ties() {
        let network = Network::Testnet;
        let (pre_state, proposer_local, proposer_remote, sender, receiver) = build_state(network);
        let ancestor_hash = [8_u8; HASH_LENGTH];

        let local_branch = build_branch(
            &pre_state,
            ancestor_hash,
            &proposer_local,
            &sender,
            &receiver,
            &[1, 1],
        );
        let remote_branch = build_branch(
            &pre_state,
            ancestor_hash,
            &proposer_remote,
            &sender,
            &receiver,
            &[3, 3],
        );

        let local_meta = branch_meta(&local_branch, ForkBranch::Local);
        let remote_meta = branch_meta(&remote_branch, ForkBranch::Remote);
        assert!(local_meta.is_ok(), "local metadata should build");
        assert!(remote_meta.is_ok(), "remote metadata should build");
        let preference = choose_fork(
            &local_meta.unwrap_or_else(|_| unreachable!()),
            &remote_meta.unwrap_or_else(|_| unreachable!()),
        );
        assert_eq!(preference, ForkPreference::SwitchToRemote);
    }

    #[test]
    fn fork_choice_uses_tip_hash_tiebreaker() {
        let local = BranchMeta {
            tip_height: 9,
            tip_hash: [2_u8; HASH_LENGTH],
            cumulative_fees: 100,
            block_count: 9,
        };
        let remote_lower_hash = BranchMeta {
            tip_height: 9,
            tip_hash: [1_u8; HASH_LENGTH],
            cumulative_fees: 100,
            block_count: 9,
        };
        let remote_higher_hash = BranchMeta {
            tip_height: 9,
            tip_hash: [3_u8; HASH_LENGTH],
            cumulative_fees: 100,
            block_count: 9,
        };

        assert_eq!(
            choose_fork(&local, &remote_lower_hash),
            ForkPreference::SwitchToRemote
        );
        assert_eq!(
            choose_fork(&local, &remote_higher_hash),
            ForkPreference::KeepLocal
        );
    }

    #[test]
    fn reconcile_partition_switches_to_remote_and_converges_state() {
        let network = Network::Testnet;
        let (pre_state, proposer_local, proposer_remote, sender, receiver) = build_state(network);
        let ancestor_hash = [9_u8; HASH_LENGTH];

        let local_branch = build_branch(
            &pre_state,
            ancestor_hash,
            &proposer_local,
            &sender,
            &receiver,
            &[1, 1],
        );
        let remote_branch = build_branch(
            &pre_state,
            ancestor_hash,
            &proposer_remote,
            &sender,
            &receiver,
            &[2, 2],
        );

        let reconciled = reconcile_partition(&pre_state, &local_branch, &remote_branch);
        assert!(
            reconciled.is_ok(),
            "partition reconciliation should succeed"
        );
        let reconciled = reconciled.unwrap_or_else(|_| unreachable!());
        assert_eq!(reconciled.preference, ForkPreference::SwitchToRemote);
        assert!(reconciled.remote_meta.cumulative_fees > reconciled.local_meta.cumulative_fees);

        let remote_tip = remote_branch.last();
        assert!(remote_tip.is_some(), "remote branch must have a tip");
        let remote_tip = remote_tip.unwrap_or_else(|| unreachable!());
        assert_eq!(
            reconciled.resulting_state.state_root(),
            remote_tip.header.state_root,
            "all nodes should converge to selected branch tip state root"
        );
    }

    #[test]
    fn reconcile_partition_rejects_missing_common_ancestor() {
        let network = Network::Testnet;
        let (pre_state, proposer_local, proposer_remote, sender, receiver) = build_state(network);

        let local_branch = build_branch(
            &pre_state,
            [1_u8; HASH_LENGTH],
            &proposer_local,
            &sender,
            &receiver,
            &[1],
        );
        let remote_branch = build_branch(
            &pre_state,
            [2_u8; HASH_LENGTH],
            &proposer_remote,
            &sender,
            &receiver,
            &[2],
        );

        let reconciled = reconcile_partition(&pre_state, &local_branch, &remote_branch);
        assert!(
            matches!(
                reconciled,
                Err(ForkChoiceError::NoCommonAncestor {
                    local_parent: _,
                    remote_parent: _
                })
            ),
            "branches from different ancestors cannot be reconciled directly"
        );
    }

    #[test]
    fn reconcile_partition_detects_tampered_state_root() {
        let network = Network::Testnet;
        let (pre_state, proposer_local, proposer_remote, sender, receiver) = build_state(network);
        let ancestor_hash = [6_u8; HASH_LENGTH];

        let local_branch = build_branch(
            &pre_state,
            ancestor_hash,
            &proposer_local,
            &sender,
            &receiver,
            &[1, 1],
        );
        let mut remote_branch = build_branch(
            &pre_state,
            ancestor_hash,
            &proposer_remote,
            &sender,
            &receiver,
            &[4, 4],
        );
        remote_branch[1].header.state_root[0] ^= 0x01;

        let reconciled = reconcile_partition(&pre_state, &local_branch, &remote_branch);
        assert!(
            matches!(
                reconciled,
                Err(ForkChoiceError::StateRootMismatch {
                    branch: ForkBranch::Remote,
                    index: 1,
                    expected: _,
                    actual: _
                })
            ),
            "tampered state roots must be detected during branch replay"
        );
    }
}
