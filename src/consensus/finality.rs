//! Validator finality votes and quorum certificates.

use std::collections::BTreeSet;

use serde::{Deserialize, Serialize};
use thiserror::Error;

use crate::consensus::stake::StakeLedger;
use crate::core::block::BlockHash;
use crate::crypto::address::{AddressError, Network, derive_address, validate_address_for_network};
use crate::crypto::keys::{CryptoError, Keypair, verify_signature};

const FINALITY_VOTE_DOMAIN: &[u8] = b"HOMA_FINALITY_VOTE_V1";

/// Finalization mode selected by node configuration.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(rename_all = "snake_case")]
pub enum FinalityMode {
    /// Development mode: valid blocks can self-finalize locally.
    #[default]
    DevSelf,
    /// Network mode: blocks require a stake-weighted validator quorum certificate.
    Quorum,
}

/// One validator vote attesting finality for a block hash at a height/round.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct FinalityVote {
    /// Network byte for signature-domain separation.
    pub network: u8,
    /// Finalized block height being voted on.
    pub height: u64,
    /// Finality round. The current protocol uses round 0.
    pub round: u64,
    /// Block hash being finalized.
    pub block_hash: BlockHash,
    /// Validator address signing the vote.
    pub validator_address: String,
    /// Validator Ed25519 public key.
    #[serde(with = "serde_bytes")]
    pub validator_public_key: Vec<u8>,
    /// Signature over canonical finality vote bytes.
    #[serde(with = "serde_bytes")]
    pub signature: Vec<u8>,
}

/// One validator signature entry included in a finality certificate.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct FinalityCertificateSignature {
    /// Validator address that signed the vote.
    pub validator_address: String,
    /// Validator Ed25519 public key.
    #[serde(with = "serde_bytes")]
    pub validator_public_key: Vec<u8>,
    /// Signature over canonical finality vote bytes.
    #[serde(with = "serde_bytes")]
    pub signature: Vec<u8>,
}

/// Compact quorum proof for one finalized block.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct FinalityCertificate {
    /// Network byte for signature-domain separation.
    pub network: u8,
    /// Finalized block height.
    pub height: u64,
    /// Finality round.
    pub round: u64,
    /// Finalized block hash.
    pub block_hash: BlockHash,
    /// Validator-set epoch. Static-genesis testnet uses epoch 0.
    pub validator_set_epoch: u64,
    /// Distinct validator signatures meeting quorum.
    pub signatures: Vec<FinalityCertificateSignature>,
}

/// Finality vote/certificate validation errors.
#[derive(Debug, Clone, PartialEq, Eq, Error)]
pub enum FinalityError {
    /// Network byte does not match the active node network.
    #[error("finality network mismatch: expected {expected}, got {actual}")]
    NetworkMismatch {
        /// Expected network byte.
        expected: u8,
        /// Actual network byte.
        actual: u8,
    },
    /// Finality quorum threshold must be 1..=100.
    #[error("invalid finality quorum threshold percent: {threshold_percent}")]
    InvalidThreshold {
        /// Configured threshold.
        threshold_percent: u8,
    },
    /// Validator address is malformed or from the wrong network.
    #[error("invalid finality validator address")]
    InvalidValidatorAddress {
        /// Underlying address error.
        source: AddressError,
    },
    /// Validator public key does not derive to the claimed address.
    #[error("finality validator address does not match public key")]
    ValidatorAddressMismatch {
        /// Expected address derived from public key.
        expected: String,
        /// Claimed validator address.
        actual: String,
    },
    /// Validator is not in the active stake ledger.
    #[error("finality vote from unstaked validator: {validator_address}")]
    UnstakedValidator {
        /// Claimed validator address.
        validator_address: String,
    },
    /// Vote signature verification failed.
    #[error("finality vote signature verification failed")]
    Signature {
        /// Underlying crypto error.
        source: CryptoError,
    },
    /// Certificate contains no signatures.
    #[error("finality certificate contains no signatures")]
    EmptyCertificate,
    /// Certificate contains duplicate validator signatures.
    #[error("finality certificate contains duplicate validator: {validator_address}")]
    DuplicateValidator {
        /// Duplicate validator address.
        validator_address: String,
    },
    /// Vote fields do not match certificate metadata.
    #[error("finality certificate signature metadata mismatch on field {field}")]
    CertificateSignatureMismatch {
        /// Mismatched field.
        field: &'static str,
    },
    /// Distinct signed stake is below quorum threshold.
    #[error(
        "finality quorum not reached: signed_stake={signed_stake}, total_stake={total_stake}, threshold_percent={threshold_percent}"
    )]
    QuorumNotReached {
        /// Signed stake weight.
        signed_stake: u64,
        /// Total stake weight.
        total_stake: u64,
        /// Required threshold.
        threshold_percent: u8,
    },
}

/// Creates and signs one finality vote.
#[must_use]
pub fn sign_finality_vote(
    network: Network,
    height: u64,
    round: u64,
    block_hash: BlockHash,
    validator_address: String,
    keypair: &Keypair,
) -> FinalityVote {
    let public_key = keypair.public_key_bytes();
    let signing_bytes = finality_vote_signing_bytes(network.as_byte(), height, round, block_hash);
    let signature = keypair.sign(&signing_bytes);
    FinalityVote {
        network: network.as_byte(),
        height,
        round,
        block_hash,
        validator_address,
        validator_public_key: public_key.to_vec(),
        signature: signature.to_vec(),
    }
}

/// Verifies one finality vote against the active network and stake ledger.
pub fn verify_finality_vote(
    vote: &FinalityVote,
    network: Network,
    stake_ledger: &StakeLedger,
) -> Result<u64, FinalityError> {
    if vote.network != network.as_byte() {
        return Err(FinalityError::NetworkMismatch {
            expected: network.as_byte(),
            actual: vote.network,
        });
    }
    validate_address_for_network(&vote.validator_address, network)
        .map_err(|source| FinalityError::InvalidValidatorAddress { source })?;
    let derived = derive_address(&vote.validator_public_key, network)
        .map_err(|source| FinalityError::InvalidValidatorAddress { source })?;
    if derived != vote.validator_address {
        return Err(FinalityError::ValidatorAddressMismatch {
            expected: derived,
            actual: vote.validator_address.clone(),
        });
    }
    let stake = stake_ledger.stake_of(&vote.validator_address);
    if stake == 0 {
        return Err(FinalityError::UnstakedValidator {
            validator_address: vote.validator_address.clone(),
        });
    }
    let signing_bytes =
        finality_vote_signing_bytes(vote.network, vote.height, vote.round, vote.block_hash);
    verify_signature(&vote.validator_public_key, &signing_bytes, &vote.signature)
        .map_err(|source| FinalityError::Signature { source })?;
    Ok(stake)
}

/// Builds a finality certificate from verified votes when stake quorum is reached.
pub fn certificate_from_votes<'a, I>(
    votes: I,
    network: Network,
    stake_ledger: &StakeLedger,
    threshold_percent: u8,
    validator_set_epoch: u64,
) -> Result<FinalityCertificate, FinalityError>
where
    I: IntoIterator<Item = &'a FinalityVote>,
{
    validate_threshold(threshold_percent)?;
    let mut iterator = votes.into_iter();
    let Some(first) = iterator.next() else {
        return Err(FinalityError::EmptyCertificate);
    };
    let mut certificate = FinalityCertificate {
        network: first.network,
        height: first.height,
        round: first.round,
        block_hash: first.block_hash,
        validator_set_epoch,
        signatures: Vec::new(),
    };
    let mut seen = BTreeSet::new();
    let mut signed_stake =
        push_certificate_vote(&mut certificate, first, network, stake_ledger, &mut seen)?;
    for vote in iterator {
        signed_stake = signed_stake.saturating_add(push_certificate_vote(
            &mut certificate,
            vote,
            network,
            stake_ledger,
            &mut seen,
        )?);
    }
    ensure_quorum(signed_stake, stake_ledger.total_staked(), threshold_percent)?;
    Ok(certificate)
}

/// Verifies a finality certificate against the active stake ledger.
pub fn verify_finality_certificate(
    certificate: &FinalityCertificate,
    network: Network,
    stake_ledger: &StakeLedger,
    threshold_percent: u8,
) -> Result<u64, FinalityError> {
    validate_threshold(threshold_percent)?;
    if certificate.signatures.is_empty() {
        return Err(FinalityError::EmptyCertificate);
    }
    if certificate.network != network.as_byte() {
        return Err(FinalityError::NetworkMismatch {
            expected: network.as_byte(),
            actual: certificate.network,
        });
    }
    let mut seen = BTreeSet::new();
    let mut signed_stake = 0_u64;
    for signature in &certificate.signatures {
        if !seen.insert(signature.validator_address.clone()) {
            return Err(FinalityError::DuplicateValidator {
                validator_address: signature.validator_address.clone(),
            });
        }
        let vote = FinalityVote {
            network: certificate.network,
            height: certificate.height,
            round: certificate.round,
            block_hash: certificate.block_hash,
            validator_address: signature.validator_address.clone(),
            validator_public_key: signature.validator_public_key.clone(),
            signature: signature.signature.clone(),
        };
        signed_stake =
            signed_stake.saturating_add(verify_finality_vote(&vote, network, stake_ledger)?);
    }
    ensure_quorum(signed_stake, stake_ledger.total_staked(), threshold_percent)?;
    Ok(signed_stake)
}

fn push_certificate_vote(
    certificate: &mut FinalityCertificate,
    vote: &FinalityVote,
    network: Network,
    stake_ledger: &StakeLedger,
    seen: &mut BTreeSet<String>,
) -> Result<u64, FinalityError> {
    if vote.network != certificate.network {
        return Err(FinalityError::CertificateSignatureMismatch { field: "network" });
    }
    if vote.height != certificate.height {
        return Err(FinalityError::CertificateSignatureMismatch { field: "height" });
    }
    if vote.round != certificate.round {
        return Err(FinalityError::CertificateSignatureMismatch { field: "round" });
    }
    if vote.block_hash != certificate.block_hash {
        return Err(FinalityError::CertificateSignatureMismatch {
            field: "block_hash",
        });
    }
    if !seen.insert(vote.validator_address.clone()) {
        return Err(FinalityError::DuplicateValidator {
            validator_address: vote.validator_address.clone(),
        });
    }
    let stake = verify_finality_vote(vote, network, stake_ledger)?;
    certificate.signatures.push(FinalityCertificateSignature {
        validator_address: vote.validator_address.clone(),
        validator_public_key: vote.validator_public_key.clone(),
        signature: vote.signature.clone(),
    });
    Ok(stake)
}

fn ensure_quorum(
    signed_stake: u64,
    total_stake: u64,
    threshold_percent: u8,
) -> Result<(), FinalityError> {
    let required = u128::from(total_stake).saturating_mul(u128::from(threshold_percent));
    let actual = u128::from(signed_stake).saturating_mul(100);
    if total_stake == 0 || actual < required {
        return Err(FinalityError::QuorumNotReached {
            signed_stake,
            total_stake,
            threshold_percent,
        });
    }
    Ok(())
}

const fn validate_threshold(threshold_percent: u8) -> Result<(), FinalityError> {
    if threshold_percent == 0 || threshold_percent > 100 {
        return Err(FinalityError::InvalidThreshold { threshold_percent });
    }
    Ok(())
}

fn finality_vote_signing_bytes(
    network: u8,
    height: u64,
    round: u64,
    block_hash: BlockHash,
) -> Vec<u8> {
    let mut bytes = Vec::with_capacity(
        FINALITY_VOTE_DOMAIN.len()
            + 1
            + core::mem::size_of::<u64>()
            + core::mem::size_of::<u64>()
            + block_hash.len(),
    );
    bytes.extend_from_slice(FINALITY_VOTE_DOMAIN);
    bytes.push(network);
    bytes.extend_from_slice(&height.to_le_bytes());
    bytes.extend_from_slice(&round.to_le_bytes());
    bytes.extend_from_slice(&block_hash);
    bytes
}

#[cfg(test)]
mod tests {
    use super::{
        FinalityError, certificate_from_votes, sign_finality_vote, verify_finality_certificate,
        verify_finality_vote,
    };
    use crate::consensus::stake::StakeLedger;
    use crate::crypto::address::{Network, derive_address};
    use crate::crypto::keys::Keypair;

    fn validator(network: Network) -> (Keypair, String) {
        let keypair = Keypair::generate();
        let address = derive_address(&keypair.public_key_bytes(), network);
        assert!(address.is_ok(), "address derivation should succeed");
        (keypair, address.unwrap_or_else(|_| unreachable!()))
    }

    #[test]
    fn vote_signing_and_verification_roundtrip() {
        let network = Network::Testnet;
        let (keypair, address) = validator(network);
        let mut ledger = StakeLedger::new(network);
        assert!(ledger.add_stake(address.clone(), 10).is_ok());
        let vote = sign_finality_vote(network, 7, 0, [5_u8; 32], address, &keypair);
        let verified = verify_finality_vote(&vote, network, &ledger);
        assert_eq!(verified, Ok(10));
    }

    #[test]
    fn vote_rejects_wrong_network() {
        let (keypair, address) = validator(Network::Testnet);
        let ledger = StakeLedger::new(Network::Devnet);
        let vote = sign_finality_vote(Network::Testnet, 7, 0, [5_u8; 32], address, &keypair);
        let verified = verify_finality_vote(&vote, Network::Devnet, &ledger);
        assert!(
            matches!(
                verified,
                Err(FinalityError::NetworkMismatch {
                    expected: 3,
                    actual: 2
                })
            ),
            "network mismatch should reject vote"
        );
    }

    #[test]
    fn certificate_requires_quorum() {
        let network = Network::Devnet;
        let (key_a, address_a) = validator(network);
        let (key_b, address_b) = validator(network);
        let (key_c, address_c) = validator(network);
        let mut ledger = StakeLedger::new(network);
        assert!(ledger.add_stake(address_a.clone(), 34).is_ok());
        assert!(ledger.add_stake(address_b.clone(), 33).is_ok());
        assert!(ledger.add_stake(address_c.clone(), 33).is_ok());
        let hash = [9_u8; 32];
        let vote_a = sign_finality_vote(network, 11, 0, hash, address_a, &key_a);
        let vote_b = sign_finality_vote(network, 11, 0, hash, address_b, &key_b);
        let vote_c = sign_finality_vote(network, 11, 0, hash, address_c, &key_c);

        let not_enough = certificate_from_votes([&vote_a, &vote_b], network, &ledger, 68, 0);
        assert!(
            matches!(not_enough, Err(FinalityError::QuorumNotReached { .. })),
            "67 signed stake should not satisfy 68 percent"
        );
        let certificate =
            certificate_from_votes([&vote_a, &vote_b, &vote_c], network, &ledger, 67, 0);
        assert!(
            certificate.is_ok(),
            "100 signed stake should satisfy quorum"
        );
        let certificate = certificate.unwrap_or_else(|_| unreachable!());
        assert_eq!(
            verify_finality_certificate(&certificate, network, &ledger, 67),
            Ok(100)
        );
    }

    #[test]
    fn certificate_rejects_duplicate_validator() {
        let network = Network::Devnet;
        let (keypair, address) = validator(network);
        let mut ledger = StakeLedger::new(network);
        assert!(ledger.add_stake(address.clone(), 100).is_ok());
        let vote = sign_finality_vote(network, 11, 0, [9_u8; 32], address, &keypair);
        let certificate = certificate_from_votes([&vote, &vote], network, &ledger, 67, 0);
        assert!(
            matches!(certificate, Err(FinalityError::DuplicateValidator { .. })),
            "duplicate validators must not count twice"
        );
    }
}
