//! Trusted checkpoint validator-set rotation with deterministic activation.

use std::collections::BTreeSet;

use serde::{Deserialize, Serialize};
use thiserror::Error;

use crate::crypto::address::{AddressError, Network, derive_address, validate_address_for_network};
use crate::crypto::keys::{CryptoError, Keypair, verify_signature};
use crate::network::sync_engine::OwnedCheckpointPolicy;

/// Explicit domain separator for checkpoint trusted-set rotation signatures.
pub const CHECKPOINT_ROTATION_DOMAIN_SEPARATOR: &[u8] = b"HOMA_CHECKPOINT_ROTATION_V1";
/// Maximum accepted bytes for one encoded checkpoint-rotation gossip payload.
pub const MAX_CHECKPOINT_ROTATION_MESSAGE_BYTES: usize = 128 * 1024;
/// Default finalized-height delay before one accepted rotation can activate.
pub const DEFAULT_MIN_ROTATION_ACTIVATION_DELAY_BLOCKS: u64 = 16;
/// Default upper bound for validator count in one trusted checkpoint set.
pub const DEFAULT_MAX_ROTATION_VALIDATORS: usize = 4_096;

/// One trusted validator-set definition used for checkpoint verification.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TrustedCheckpointSet {
    /// Network byte that this set is valid for.
    pub network: u8,
    /// Monotonic epoch identifier.
    pub epoch: u64,
    /// Minimum number of signatures required from this trusted set.
    pub min_signatures: usize,
    /// Canonically sorted validator addresses trusted for checkpoint signatures.
    pub validators: Vec<String>,
}

/// One validator signature that authorizes a trusted checkpoint-set rotation.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CheckpointSetRotationSignature {
    /// Validator address that signed the rotation payload.
    pub validator_address: String,
    /// Raw Ed25519 validator public key bytes.
    #[serde(with = "serde_bytes")]
    pub validator_public_key: Vec<u8>,
    /// Raw Ed25519 signature over deterministic rotation bytes.
    #[serde(with = "serde_bytes")]
    pub signature: Vec<u8>,
}

/// Gossip payload that proposes the next trusted checkpoint set.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CheckpointSetRotationUpdate {
    /// Candidate trusted checkpoint set for the next epoch.
    pub next_set: TrustedCheckpointSet,
    /// Finalized block height at or after which this set can activate.
    pub activation_height: u64,
    /// Signatures from validators in the currently active trusted set.
    pub signatures: Vec<CheckpointSetRotationSignature>,
}

impl CheckpointSetRotationUpdate {
    /// Encodes one rotation update into deterministic bounded wire bytes.
    pub fn encode(&self) -> Result<Vec<u8>, CheckpointRotationError> {
        let encoded = bincode::serde::encode_to_vec(
            self,
            bincode::config::standard()
                .with_fixed_int_encoding()
                .with_little_endian(),
        )
        .map_err(|_| CheckpointRotationError::RotationSerialization)?;
        if encoded.len() > MAX_CHECKPOINT_ROTATION_MESSAGE_BYTES {
            return Err(CheckpointRotationError::RotationPayloadTooLarge {
                actual: encoded.len(),
                max: MAX_CHECKPOINT_ROTATION_MESSAGE_BYTES,
            });
        }
        Ok(encoded)
    }

    /// Decodes one rotation update from deterministic bounded wire bytes.
    pub fn decode(bytes: &[u8]) -> Result<Self, CheckpointRotationError> {
        if bytes.len() > MAX_CHECKPOINT_ROTATION_MESSAGE_BYTES {
            return Err(CheckpointRotationError::RotationPayloadTooLarge {
                actual: bytes.len(),
                max: MAX_CHECKPOINT_ROTATION_MESSAGE_BYTES,
            });
        }
        bincode::serde::decode_from_slice(
            bytes,
            bincode::config::standard()
                .with_fixed_int_encoding()
                .with_little_endian(),
        )
        .map(|(update, _)| update)
        .map_err(|_| CheckpointRotationError::RotationDeserialization)
    }
}

/// Policy knobs for rotation-acceptance safety limits.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CheckpointRotationPolicy {
    /// Minimum finalized-height delay required before activation.
    pub min_activation_delay_blocks: u64,
    /// Maximum allowed validator entries in one trusted set.
    pub max_validators: usize,
}

impl CheckpointRotationPolicy {
    /// Strict default policy for public-network operation.
    #[must_use]
    pub const fn strict_default() -> Self {
        Self {
            min_activation_delay_blocks: DEFAULT_MIN_ROTATION_ACTIVATION_DELAY_BLOCKS,
            max_validators: DEFAULT_MAX_ROTATION_VALIDATORS,
        }
    }
}

impl Default for CheckpointRotationPolicy {
    fn default() -> Self {
        Self::strict_default()
    }
}

/// One currently staged, not-yet-activated trusted checkpoint-set rotation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PendingCheckpointRotation {
    /// Candidate trusted checkpoint set.
    pub next_set: TrustedCheckpointSet,
    /// Finalized height at or above which this candidate can activate.
    pub activation_height: u64,
    /// Deterministic content hash used for tie-break selection.
    pub payload_hash: [u8; 32],
}

/// Ingest outcome for one rotation update.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RotationIngestOutcome {
    /// Candidate was accepted and staged.
    Accepted,
    /// Candidate replaced a previously staged one by deterministic tie-break.
    Replaced,
    /// Candidate duplicated the currently staged content.
    IgnoredDuplicate,
    /// Candidate lost deterministic tie-break against staged content.
    IgnoredByTieBreak,
}

/// Activation outcome after finalized-height progression.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RotationActivationOutcome {
    /// No activation happened at the provided finalized height.
    NoActivation,
    /// One staged candidate activated and became the active trusted set.
    Activated {
        /// Previous active epoch.
        previous_epoch: u64,
        /// Newly activated epoch.
        new_epoch: u64,
        /// Activation finalized height.
        activation_height: u64,
    },
}

/// Typed errors for checkpoint trusted-set rotation validation and activation.
#[derive(Debug, Clone, PartialEq, Eq, Error)]
pub enum CheckpointRotationError {
    /// Rotation policy fields are invalid.
    #[error(
        "invalid checkpoint rotation policy: min_activation_delay_blocks={min_activation_delay_blocks}, max_validators={max_validators}"
    )]
    InvalidRotationPolicy {
        /// Configured delay.
        min_activation_delay_blocks: u64,
        /// Configured validator cap.
        max_validators: usize,
    },
    /// Trusted checkpoint set fields are invalid.
    #[error(
        "invalid trusted checkpoint set: validator_count={validator_count}, min_signatures={min_signatures}, max_validators={max_validators}"
    )]
    InvalidTrustedSet {
        /// Number of validator entries.
        validator_count: usize,
        /// Required threshold.
        min_signatures: usize,
        /// Configured maximum validator entries.
        max_validators: usize,
    },
    /// Trusted validator address list is not canonical strict ascending order.
    #[error(
        "trusted validator set ordering is not canonical: previous={previous}, current={current}"
    )]
    ValidatorSetNotCanonical {
        /// Previous validator address.
        previous: String,
        /// Current validator address.
        current: String,
    },
    /// Trusted validator address is malformed or mismatched network.
    #[error("invalid trusted validator address: {validator}")]
    InvalidTrustedValidatorAddress {
        /// Validator address.
        validator: String,
        /// Underlying parse/network error.
        source: AddressError,
    },
    /// Trusted-set network byte mismatches manager network.
    #[error("checkpoint rotation network mismatch: expected {expected}, got {actual}")]
    NetworkMismatch {
        /// Expected network byte.
        expected: u8,
        /// Actual network byte.
        actual: u8,
    },
    /// Proposed epoch is stale or regressive.
    #[error(
        "checkpoint rotation epoch regression: active={active_epoch}, proposed={proposed_epoch}"
    )]
    EpochRegression {
        /// Current active epoch.
        active_epoch: u64,
        /// Proposed next epoch.
        proposed_epoch: u64,
    },
    /// Proposed epoch skips required next epoch.
    #[error("checkpoint rotation epoch skip: expected {expected_epoch}, proposed {proposed_epoch}")]
    EpochSkip {
        /// Required next epoch.
        expected_epoch: u64,
        /// Proposed epoch.
        proposed_epoch: u64,
    },
    /// Proposed activation height is too early.
    #[error(
        "checkpoint rotation activation too early: finalized_height={finalized_height}, minimum_allowed={minimum_allowed}, proposed={proposed}"
    )]
    ActivationTooEarly {
        /// Current finalized height.
        finalized_height: u64,
        /// Minimum accepted activation height.
        minimum_allowed: u64,
        /// Proposed activation height.
        proposed: u64,
    },
    /// Finalized height progression attempted to go backward.
    #[error(
        "finalized height regression: current={current_finalized_height}, proposed={proposed_finalized_height}"
    )]
    FinalizedHeightRegression {
        /// Current finalized height.
        current_finalized_height: u64,
        /// Proposed finalized height.
        proposed_finalized_height: u64,
    },
    /// Rotation update carried no signatures.
    #[error("checkpoint rotation update contains no signatures")]
    EmptyRotationSignatures,
    /// Rotation update carries duplicate signature from same validator.
    #[error("duplicate checkpoint rotation signer: {validator}")]
    DuplicateRotationSigner {
        /// Duplicate validator address.
        validator: String,
    },
    /// Rotation update signature signer is not trusted in current active set.
    #[error("untrusted checkpoint rotation signer: {validator}")]
    UntrustedRotationSigner {
        /// Untrusted validator address.
        validator: String,
    },
    /// Signer public key bytes did not derive to claimed validator address.
    #[error("checkpoint rotation signer key/address mismatch: {validator}")]
    RotationSignerKeyMismatch {
        /// Signer validator address.
        validator: String,
    },
    /// Signer key bytes could not be parsed/validated as a network address.
    #[error("invalid checkpoint rotation signer address material: {validator}")]
    InvalidRotationSignerAddress {
        /// Signer validator address.
        validator: String,
        /// Underlying parse/network error.
        source: AddressError,
    },
    /// Signature verification failed for one signer.
    #[error("checkpoint rotation signature verification failed for validator {validator}")]
    RotationSignatureVerification {
        /// Signer validator address.
        validator: String,
        /// Underlying crypto error.
        source: CryptoError,
    },
    /// Distinct valid signatures did not meet required threshold.
    #[error("insufficient checkpoint rotation signatures: required {required}, actual {actual}")]
    InsufficientRotationSignatures {
        /// Required threshold.
        required: usize,
        /// Distinct valid signatures observed.
        actual: usize,
    },
    /// Rotation update encoding failed.
    #[error("checkpoint rotation serialization failed")]
    RotationSerialization,
    /// Rotation update decoding failed.
    #[error("checkpoint rotation deserialization failed")]
    RotationDeserialization,
    /// Encoded rotation update exceeds bounded payload size.
    #[error("checkpoint rotation payload exceeds max size: {actual} > {max}")]
    RotationPayloadTooLarge {
        /// Actual payload size.
        actual: usize,
        /// Maximum accepted payload size.
        max: usize,
    },
}

const fn validate_rotation_policy(
    policy: CheckpointRotationPolicy,
) -> Result<(), CheckpointRotationError> {
    if policy.min_activation_delay_blocks == 0 || policy.max_validators == 0 {
        return Err(CheckpointRotationError::InvalidRotationPolicy {
            min_activation_delay_blocks: policy.min_activation_delay_blocks,
            max_validators: policy.max_validators,
        });
    }
    Ok(())
}

fn validate_trusted_set(
    set: &TrustedCheckpointSet,
    expected_network: Network,
    max_validators: usize,
) -> Result<(), CheckpointRotationError> {
    if set.network != expected_network.as_byte() {
        return Err(CheckpointRotationError::NetworkMismatch {
            expected: expected_network.as_byte(),
            actual: set.network,
        });
    }

    let validator_count = set.validators.len();
    if validator_count == 0
        || validator_count > max_validators
        || set.min_signatures == 0
        || set.min_signatures > validator_count
    {
        return Err(CheckpointRotationError::InvalidTrustedSet {
            validator_count,
            min_signatures: set.min_signatures,
            max_validators,
        });
    }

    for window in set.validators.windows(2) {
        if window[0] >= window[1] {
            return Err(CheckpointRotationError::ValidatorSetNotCanonical {
                previous: window[0].clone(),
                current: window[1].clone(),
            });
        }
    }

    for validator in &set.validators {
        validate_address_for_network(validator, expected_network).map_err(|source| {
            CheckpointRotationError::InvalidTrustedValidatorAddress {
                validator: validator.clone(),
                source,
            }
        })?;
    }

    Ok(())
}

#[derive(Debug, Serialize)]
struct RotationSigningEnvelope<'a> {
    #[serde(with = "serde_bytes")]
    domain: &'a [u8],
    next_set: &'a TrustedCheckpointSet,
    activation_height: u64,
}

fn rotation_signing_bytes(
    next_set: &TrustedCheckpointSet,
    activation_height: u64,
) -> Result<Vec<u8>, CheckpointRotationError> {
    let envelope = RotationSigningEnvelope {
        domain: CHECKPOINT_ROTATION_DOMAIN_SEPARATOR,
        next_set,
        activation_height,
    };

    bincode::serde::encode_to_vec(
        envelope,
        bincode::config::standard()
            .with_fixed_int_encoding()
            .with_little_endian(),
    )
    .map_err(|_| CheckpointRotationError::RotationSerialization)
}

fn rotation_payload_hash(
    next_set: &TrustedCheckpointSet,
    activation_height: u64,
) -> Result<[u8; 32], CheckpointRotationError> {
    let bytes = rotation_signing_bytes(next_set, activation_height)?;
    Ok(*blake3::hash(&bytes).as_bytes())
}

/// Creates one validator signature over a deterministic checkpoint-set rotation payload.
pub fn sign_checkpoint_set_rotation(
    next_set: &TrustedCheckpointSet,
    activation_height: u64,
    network: Network,
    validator_address: String,
    signer: &Keypair,
) -> Result<CheckpointSetRotationSignature, CheckpointRotationError> {
    if next_set.network != network.as_byte() {
        return Err(CheckpointRotationError::NetworkMismatch {
            expected: network.as_byte(),
            actual: next_set.network,
        });
    }

    let derived = derive_address(&signer.public_key_bytes(), network).map_err(|source| {
        CheckpointRotationError::InvalidRotationSignerAddress {
            validator: validator_address.clone(),
            source,
        }
    })?;
    if derived != validator_address {
        return Err(CheckpointRotationError::RotationSignerKeyMismatch {
            validator: validator_address,
        });
    }

    let signing_bytes = rotation_signing_bytes(next_set, activation_height)?;
    let signature = signer.sign(&signing_bytes);

    Ok(CheckpointSetRotationSignature {
        validator_address,
        validator_public_key: signer.public_key_bytes().to_vec(),
        signature: signature.to_vec(),
    })
}

/// Runtime manager that stages and activates trusted checkpoint-set rotations.
#[derive(Debug, Clone)]
pub struct CheckpointRotationManager {
    network: Network,
    policy: CheckpointRotationPolicy,
    finalized_height: u64,
    active_set: TrustedCheckpointSet,
    pending: Option<PendingCheckpointRotation>,
}

impl CheckpointRotationManager {
    /// Creates one manager from active set, policy, and current finalized height.
    pub fn new(
        network: Network,
        policy: CheckpointRotationPolicy,
        finalized_height: u64,
        active_set: TrustedCheckpointSet,
    ) -> Result<Self, CheckpointRotationError> {
        validate_rotation_policy(policy)?;
        validate_trusted_set(&active_set, network, policy.max_validators)?;

        Ok(Self {
            network,
            policy,
            finalized_height,
            active_set,
            pending: None,
        })
    }

    /// Returns currently active trusted checkpoint set.
    #[must_use]
    pub const fn active_set(&self) -> &TrustedCheckpointSet {
        &self.active_set
    }

    /// Returns currently staged pending rotation candidate.
    #[must_use]
    pub const fn pending_rotation(&self) -> Option<&PendingCheckpointRotation> {
        self.pending.as_ref()
    }

    /// Returns latest finalized height tracked by this manager.
    #[must_use]
    pub const fn finalized_height(&self) -> u64 {
        self.finalized_height
    }

    /// Returns active set in the handshake-owned checkpoint policy representation.
    #[must_use]
    pub fn active_checkpoint_policy(&self) -> OwnedCheckpointPolicy {
        OwnedCheckpointPolicy {
            network: self.network,
            min_signatures: self.active_set.min_signatures,
            trusted_validators: self.active_set.validators.clone(),
        }
    }

    /// Ingests one rotation update and applies deterministic tie-breaks for competing candidates.
    pub fn ingest_update(
        &mut self,
        update: CheckpointSetRotationUpdate,
    ) -> Result<RotationIngestOutcome, CheckpointRotationError> {
        validate_trusted_set(&update.next_set, self.network, self.policy.max_validators)?;

        let proposed_epoch = update.next_set.epoch;
        if proposed_epoch <= self.active_set.epoch {
            return Err(CheckpointRotationError::EpochRegression {
                active_epoch: self.active_set.epoch,
                proposed_epoch,
            });
        }
        let expected_epoch = self.active_set.epoch.saturating_add(1);
        if proposed_epoch != expected_epoch {
            return Err(CheckpointRotationError::EpochSkip {
                expected_epoch,
                proposed_epoch,
            });
        }

        let minimum_allowed = self
            .finalized_height
            .saturating_add(self.policy.min_activation_delay_blocks);
        if update.activation_height < minimum_allowed {
            return Err(CheckpointRotationError::ActivationTooEarly {
                finalized_height: self.finalized_height,
                minimum_allowed,
                proposed: update.activation_height,
            });
        }

        self.verify_rotation_signatures(&update)?;

        let payload_hash = rotation_payload_hash(&update.next_set, update.activation_height)?;
        let candidate = PendingCheckpointRotation {
            next_set: update.next_set,
            activation_height: update.activation_height,
            payload_hash,
        };

        let Some(pending) = self.pending.as_ref() else {
            self.pending = Some(candidate);
            return Ok(RotationIngestOutcome::Accepted);
        };

        if pending == &candidate {
            return Ok(RotationIngestOutcome::IgnoredDuplicate);
        }

        if candidate.payload_hash < pending.payload_hash {
            self.pending = Some(candidate);
            return Ok(RotationIngestOutcome::Replaced);
        }

        Ok(RotationIngestOutcome::IgnoredByTieBreak)
    }

    /// Advances finalized height and activates pending candidate when threshold is reached.
    pub fn advance_finalized_height(
        &mut self,
        new_finalized_height: u64,
    ) -> Result<RotationActivationOutcome, CheckpointRotationError> {
        if new_finalized_height < self.finalized_height {
            return Err(CheckpointRotationError::FinalizedHeightRegression {
                current_finalized_height: self.finalized_height,
                proposed_finalized_height: new_finalized_height,
            });
        }
        self.finalized_height = new_finalized_height;

        let Some(pending) = self.pending.as_ref() else {
            return Ok(RotationActivationOutcome::NoActivation);
        };
        if new_finalized_height < pending.activation_height {
            return Ok(RotationActivationOutcome::NoActivation);
        }

        let previous_epoch = self.active_set.epoch;
        let pending = self.pending.take().unwrap_or_else(|| unreachable!());
        self.active_set = pending.next_set;

        Ok(RotationActivationOutcome::Activated {
            previous_epoch,
            new_epoch: self.active_set.epoch,
            activation_height: self.finalized_height,
        })
    }

    fn verify_rotation_signatures(
        &self,
        update: &CheckpointSetRotationUpdate,
    ) -> Result<(), CheckpointRotationError> {
        if update.signatures.is_empty() {
            return Err(CheckpointRotationError::EmptyRotationSignatures);
        }

        let signing_bytes = rotation_signing_bytes(&update.next_set, update.activation_height)?;
        let trusted = self.active_set.validators.iter().collect::<BTreeSet<_>>();
        let mut seen = BTreeSet::new();
        let mut valid = 0_usize;

        for signature in &update.signatures {
            if !seen.insert(signature.validator_address.clone()) {
                return Err(CheckpointRotationError::DuplicateRotationSigner {
                    validator: signature.validator_address.clone(),
                });
            }
            if !trusted.contains(&signature.validator_address) {
                return Err(CheckpointRotationError::UntrustedRotationSigner {
                    validator: signature.validator_address.clone(),
                });
            }

            let derived = derive_address(&signature.validator_public_key, self.network).map_err(
                |source| CheckpointRotationError::InvalidRotationSignerAddress {
                    validator: signature.validator_address.clone(),
                    source,
                },
            )?;
            if derived != signature.validator_address {
                return Err(CheckpointRotationError::RotationSignerKeyMismatch {
                    validator: signature.validator_address.clone(),
                });
            }

            verify_signature(
                &signature.validator_public_key,
                &signing_bytes,
                &signature.signature,
            )
            .map_err(|source| {
                CheckpointRotationError::RotationSignatureVerification {
                    validator: signature.validator_address.clone(),
                    source,
                }
            })?;
            valid = valid.saturating_add(1);
        }

        if valid < self.active_set.min_signatures {
            return Err(CheckpointRotationError::InsufficientRotationSignatures {
                required: self.active_set.min_signatures,
                actual: valid,
            });
        }

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::{
        CheckpointRotationError, CheckpointRotationManager, CheckpointRotationPolicy,
        CheckpointSetRotationUpdate, RotationActivationOutcome, RotationIngestOutcome,
        TrustedCheckpointSet, rotation_payload_hash, sign_checkpoint_set_rotation,
    };
    use crate::crypto::address::{Network, derive_address};
    use crate::crypto::keys::Keypair;

    fn validator(network: Network) -> (Keypair, String) {
        let keypair = Keypair::generate();
        let address = derive_address(&keypair.public_key_bytes(), network);
        assert!(
            address.is_ok(),
            "validator address derivation should succeed"
        );
        (keypair, address.unwrap_or_else(|_| unreachable!()))
    }

    fn trusted_set(
        network: Network,
        epoch: u64,
        min_signatures: usize,
        mut validators: Vec<String>,
    ) -> TrustedCheckpointSet {
        validators.sort();
        TrustedCheckpointSet {
            network: network.as_byte(),
            epoch,
            min_signatures,
            validators,
        }
    }

    #[test]
    fn rotation_update_codec_roundtrip() {
        let network = Network::Testnet;
        let (_k0, a0) = validator(network);
        let (_k1, a1) = validator(network);
        let set = trusted_set(network, 9, 1, vec![a0, a1]);
        let update = CheckpointSetRotationUpdate {
            next_set: set,
            activation_height: 120,
            signatures: vec![],
        };

        let encoded = update.encode();
        assert!(encoded.is_ok(), "rotation update should encode");
        let decoded =
            CheckpointSetRotationUpdate::decode(&encoded.unwrap_or_else(|_| unreachable!()));
        assert!(decoded.is_ok(), "rotation update should decode");
        assert_eq!(decoded.unwrap_or_else(|_| unreachable!()), update);
    }

    #[test]
    fn rotation_manager_accepts_valid_update_and_activates_after_delay() {
        let network = Network::Testnet;
        let (k0, a0) = validator(network);
        let (k1, a1) = validator(network);
        let (_k2, a2) = validator(network);
        let (_k3, a3) = validator(network);

        let active = trusted_set(network, 3, 2, vec![a0.clone(), a1.clone(), a2]);
        let policy = CheckpointRotationPolicy {
            min_activation_delay_blocks: 5,
            max_validators: 64,
        };
        let manager = CheckpointRotationManager::new(network, policy, 100, active);
        assert!(manager.is_ok(), "rotation manager should initialize");
        let mut manager = manager.unwrap_or_else(|_| unreachable!());

        let next_set = trusted_set(network, 4, 2, vec![a0.clone(), a1.clone(), a3]);
        let sig0 = sign_checkpoint_set_rotation(&next_set, 110, network, a0, &k0);
        let sig1 = sign_checkpoint_set_rotation(&next_set, 110, network, a1, &k1);
        assert!(
            sig0.is_ok() && sig1.is_ok(),
            "rotation signatures should succeed"
        );

        let outcome = manager.ingest_update(CheckpointSetRotationUpdate {
            next_set,
            activation_height: 110,
            signatures: vec![
                sig0.unwrap_or_else(|_| unreachable!()),
                sig1.unwrap_or_else(|_| unreachable!()),
            ],
        });
        assert!(
            matches!(outcome, Ok(RotationIngestOutcome::Accepted)),
            "valid update should be accepted"
        );

        let before = manager.advance_finalized_height(109);
        assert!(
            matches!(before, Ok(RotationActivationOutcome::NoActivation)),
            "activation must wait until threshold finalized height"
        );

        let activated = manager.advance_finalized_height(110);
        assert!(
            matches!(
                activated,
                Ok(RotationActivationOutcome::Activated {
                    previous_epoch: 3,
                    new_epoch: 4,
                    activation_height: 110
                })
            ),
            "pending rotation should activate at threshold"
        );
    }

    #[test]
    fn rotation_manager_rejects_early_activation_height() {
        let network = Network::Testnet;
        let (k0, a0) = validator(network);
        let (_k1, a1) = validator(network);

        let active = trusted_set(network, 1, 1, vec![a0.clone()]);
        let policy = CheckpointRotationPolicy {
            min_activation_delay_blocks: 10,
            max_validators: 32,
        };
        let manager = CheckpointRotationManager::new(network, policy, 50, active);
        assert!(manager.is_ok(), "rotation manager should initialize");
        let mut manager = manager.unwrap_or_else(|_| unreachable!());

        let next_set = trusted_set(network, 2, 1, vec![a0.clone(), a1]);
        let sig0 = sign_checkpoint_set_rotation(&next_set, 55, network, a0, &k0);
        assert!(sig0.is_ok(), "rotation signature should succeed");

        let outcome = manager.ingest_update(CheckpointSetRotationUpdate {
            next_set,
            activation_height: 55,
            signatures: vec![sig0.unwrap_or_else(|_| unreachable!())],
        });
        assert!(
            matches!(
                outcome,
                Err(CheckpointRotationError::ActivationTooEarly {
                    finalized_height: 50,
                    minimum_allowed: 60,
                    proposed: 55
                })
            ),
            "too-early activation height must be rejected"
        );
    }

    #[test]
    fn rotation_manager_rejects_untrusted_signer() {
        let network = Network::Testnet;
        let (_k0, a0) = validator(network);
        let (k1, a1) = validator(network);

        let active = trusted_set(network, 7, 1, vec![a0.clone()]);
        let manager = CheckpointRotationManager::new(
            network,
            CheckpointRotationPolicy::default(),
            200,
            active,
        );
        assert!(manager.is_ok(), "rotation manager should initialize");
        let mut manager = manager.unwrap_or_else(|_| unreachable!());

        let next_set = trusted_set(network, 8, 1, vec![a0, a1.clone()]);
        let untrusted_sig = sign_checkpoint_set_rotation(&next_set, 220, network, a1, &k1);
        assert!(
            untrusted_sig.is_ok(),
            "test setup signature should still be cryptographically valid"
        );

        let outcome = manager.ingest_update(CheckpointSetRotationUpdate {
            next_set,
            activation_height: 220,
            signatures: vec![untrusted_sig.unwrap_or_else(|_| unreachable!())],
        });
        assert!(
            matches!(
                outcome,
                Err(CheckpointRotationError::UntrustedRotationSigner { validator: _ })
            ),
            "signatures from non-active validators must be rejected"
        );
    }

    #[test]
    fn rotation_manager_uses_deterministic_payload_hash_tie_break() {
        let network = Network::Testnet;
        let (k0, a0) = validator(network);
        let (_k1, a1) = validator(network);
        let (_k2, a2) = validator(network);

        let active = trusted_set(network, 10, 1, vec![a0.clone()]);
        let manager = CheckpointRotationManager::new(
            network,
            CheckpointRotationPolicy {
                min_activation_delay_blocks: 2,
                max_validators: 16,
            },
            500,
            active,
        );
        assert!(manager.is_ok(), "rotation manager should initialize");
        let mut manager = manager.unwrap_or_else(|_| unreachable!());

        let candidate_a = trusted_set(network, 11, 1, vec![a0.clone(), a1]);
        let candidate_b = trusted_set(network, 11, 1, vec![a0.clone(), a2]);

        let sig_a = sign_checkpoint_set_rotation(&candidate_a, 503, network, a0.clone(), &k0);
        let sig_b = sign_checkpoint_set_rotation(&candidate_b, 503, network, a0, &k0);
        assert!(sig_a.is_ok() && sig_b.is_ok(), "signatures should succeed");

        let first = manager.ingest_update(CheckpointSetRotationUpdate {
            next_set: candidate_a.clone(),
            activation_height: 503,
            signatures: vec![sig_a.unwrap_or_else(|_| unreachable!())],
        });
        assert!(matches!(first, Ok(RotationIngestOutcome::Accepted)));

        let second = manager.ingest_update(CheckpointSetRotationUpdate {
            next_set: candidate_b.clone(),
            activation_height: 503,
            signatures: vec![sig_b.unwrap_or_else(|_| unreachable!())],
        });

        let hash_a = rotation_payload_hash(&candidate_a, 503);
        let hash_b = rotation_payload_hash(&candidate_b, 503);
        assert!(hash_a.is_ok() && hash_b.is_ok(), "hashing should succeed");
        let hash_a = hash_a.unwrap_or_else(|_| unreachable!());
        let hash_b = hash_b.unwrap_or_else(|_| unreachable!());

        if hash_b < hash_a {
            assert!(
                matches!(second, Ok(RotationIngestOutcome::Replaced)),
                "lower hash candidate should replace staged candidate"
            );
            let pending = manager.pending_rotation();
            assert!(pending.is_some());
            assert_eq!(
                pending.unwrap_or_else(|| unreachable!()).next_set,
                candidate_b,
                "lower hash candidate must remain staged"
            );
        } else {
            assert!(
                matches!(second, Ok(RotationIngestOutcome::IgnoredByTieBreak)),
                "higher hash candidate should be ignored"
            );
            let pending = manager.pending_rotation();
            assert!(pending.is_some());
            assert_eq!(
                pending.unwrap_or_else(|| unreachable!()).next_set,
                candidate_a,
                "existing lower hash candidate must remain staged"
            );
        }
    }

    #[test]
    fn rotation_manager_rejects_finalized_height_regression() {
        let network = Network::Testnet;
        let (_k0, a0) = validator(network);
        let active = trusted_set(network, 2, 1, vec![a0]);

        let manager = CheckpointRotationManager::new(
            network,
            CheckpointRotationPolicy::default(),
            900,
            active,
        );
        assert!(manager.is_ok(), "rotation manager should initialize");
        let mut manager = manager.unwrap_or_else(|_| unreachable!());

        let regressed = manager.advance_finalized_height(899);
        assert!(
            matches!(
                regressed,
                Err(CheckpointRotationError::FinalizedHeightRegression {
                    current_finalized_height: 900,
                    proposed_finalized_height: 899
                })
            ),
            "finalized height regression must be rejected"
        );
    }
}
