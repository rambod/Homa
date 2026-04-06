//! Genesis block forging and initial validator allocations.

use thiserror::Error;

use crate::core::block::{Block, BlockHeader, HASH_LENGTH};
use crate::core::state::{ChainState, MAX_SUPPLY_MICRO_HOMA, StateError};
use crate::core::transaction::Amount;
use crate::crypto::address::{AddressError, Network, derive_address};
use crate::crypto::keys::{CryptoError, Keypair};

/// Immutable genesis timestamp (`2026-01-01T00:00:00Z`).
pub const GENESIS_TIMESTAMP_UNIX_MS: u64 = 1_767_225_600_000;

const VALIDATOR_SECRET_KEYS: [[u8; 32]; 3] = [[1_u8; 32], [2_u8; 32], [3_u8; 32]];

/// Amount assigned to validator 1.
pub const GENESIS_ALLOCATION_VALIDATOR_1: Amount = 1_440_000_000_000_000;
/// Amount assigned to validator 2.
pub const GENESIS_ALLOCATION_VALIDATOR_2: Amount = 1_260_000_000_000_000;
/// Amount assigned to validator 3.
pub const GENESIS_ALLOCATION_VALIDATOR_3: Amount = 900_000_000_000_000;

/// Errors emitted while generating genesis allocations/state.
#[derive(Debug, Error)]
pub enum GenesisError {
    /// Embedded key material was invalid.
    #[error("invalid genesis key material")]
    KeyMaterial {
        /// Inner crypto error.
        source: CryptoError,
    },
    /// Address derivation failed.
    #[error("genesis address derivation failed")]
    AddressDerivation {
        /// Inner address error.
        source: AddressError,
    },
    /// Initial state initialization failed.
    #[error("genesis state initialization failed")]
    State {
        /// Inner state error.
        source: StateError,
    },
    /// Allocation sum does not match hard-capped supply.
    #[error("genesis allocations do not sum to max supply")]
    InvalidSupply,
    /// Internal block construction failed unexpectedly.
    #[error("genesis block construction failed")]
    Block,
}

/// Builds deterministic validator allocations for the selected network.
pub fn default_genesis_allocations(
    network: Network,
) -> Result<Vec<(String, Amount)>, GenesisError> {
    let amounts = [
        GENESIS_ALLOCATION_VALIDATOR_1,
        GENESIS_ALLOCATION_VALIDATOR_2,
        GENESIS_ALLOCATION_VALIDATOR_3,
    ];

    let total = amounts.iter().copied().sum::<Amount>();
    if total != MAX_SUPPLY_MICRO_HOMA {
        return Err(GenesisError::InvalidSupply);
    }

    VALIDATOR_SECRET_KEYS
        .iter()
        .zip(amounts)
        .map(|(secret_key, amount)| {
            let keypair = Keypair::from_secret_key(secret_key)
                .map_err(|source| GenesisError::KeyMaterial { source })?;
            let address = derive_address(&keypair.public_key_bytes(), network)
                .map_err(|source| GenesisError::AddressDerivation { source })?;
            Ok((address, amount))
        })
        .collect()
}

/// Builds the genesis block together with initialized chain state.
///
/// The returned state is already initialized with the full max-supply allocation.
pub fn forge_genesis(network: Network) -> Result<(Block, ChainState), GenesisError> {
    let allocations = default_genesis_allocations(network)?;
    let proposer = allocations
        .first()
        .map(|(address, _)| address.clone())
        .ok_or(GenesisError::InvalidSupply)?;

    let mut state = ChainState::new(network);
    state
        .initialize_genesis(allocations)
        .map_err(|source| GenesisError::State { source })?;

    let state_root = state.state_root();
    let header = BlockHeader::new(
        0,
        [0_u8; HASH_LENGTH],
        state_root,
        GENESIS_TIMESTAMP_UNIX_MS,
        proposer,
    );

    let block = Block::new_unsigned(header, Vec::new()).map_err(|_| GenesisError::Block)?;
    Ok((block, state))
}

#[cfg(test)]
mod tests {
    use super::{
        GENESIS_ALLOCATION_VALIDATOR_1, GENESIS_ALLOCATION_VALIDATOR_2,
        GENESIS_ALLOCATION_VALIDATOR_3, GENESIS_TIMESTAMP_UNIX_MS, default_genesis_allocations,
        forge_genesis,
    };
    use crate::core::state::MAX_SUPPLY_MICRO_HOMA;
    use crate::crypto::address::Network;

    #[test]
    fn allocations_sum_to_max_supply() {
        let allocations_result = default_genesis_allocations(Network::Mainnet);
        assert!(allocations_result.is_ok(), "allocations should build");
        let allocations = allocations_result.unwrap_or_else(|_| unreachable!());

        assert_eq!(allocations.len(), 3);
        let total = allocations.iter().map(|(_, amount)| *amount).sum::<u64>();
        assert_eq!(total, MAX_SUPPLY_MICRO_HOMA);
        assert_eq!(
            GENESIS_ALLOCATION_VALIDATOR_1
                + GENESIS_ALLOCATION_VALIDATOR_2
                + GENESIS_ALLOCATION_VALIDATOR_3,
            MAX_SUPPLY_MICRO_HOMA
        );
    }

    #[test]
    fn forge_genesis_builds_height_zero_block_with_state_root() {
        let forged = forge_genesis(Network::Testnet);
        assert!(forged.is_ok(), "genesis should forge");
        let (block, state) = forged.unwrap_or_else(|_| unreachable!());

        assert_eq!(block.header.height, 0);
        assert_eq!(block.header.timestamp_unix_ms, GENESIS_TIMESTAMP_UNIX_MS);
        assert_eq!(block.header.state_root, state.state_root());
        assert_eq!(state.total_issued(), MAX_SUPPLY_MICRO_HOMA);
    }
}
