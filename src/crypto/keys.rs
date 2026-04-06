//! Key generation and signing primitives.

use core::fmt;

use ed25519_dalek::{Signature, Signer, SigningKey, VerifyingKey};
use rand_core::OsRng;
use thiserror::Error;
use zeroize::Zeroize;

/// Ed25519 secret key size in bytes.
pub const SECRET_KEY_LENGTH: usize = 32;
/// Ed25519 public key size in bytes.
pub const PUBLIC_KEY_LENGTH: usize = 32;
/// Ed25519 signature size in bytes.
pub const SIGNATURE_LENGTH: usize = 64;

/// Cryptographic errors surfaced by key management and signature verification.
#[derive(Debug, Clone, PartialEq, Eq, Error)]
pub enum CryptoError {
    /// Input secret key byte-length does not match Ed25519 requirements.
    #[error("invalid secret key length: expected {expected}, got {actual}")]
    InvalidSecretKeyLength { expected: usize, actual: usize },
    /// Input public key byte-length does not match Ed25519 requirements.
    #[error("invalid public key length: expected {expected}, got {actual}")]
    InvalidPublicKeyLength { expected: usize, actual: usize },
    /// Input signature byte-length does not match Ed25519 requirements.
    #[error("invalid signature length: expected {expected}, got {actual}")]
    InvalidSignatureLength { expected: usize, actual: usize },
    /// Public key bytes are malformed.
    #[error("public key decoding failed")]
    PublicKeyDecoding,
    /// Signature bytes are malformed.
    #[error("signature decoding failed")]
    SignatureDecoding,
    /// Signature verification failed.
    #[error("signature verification failed")]
    SignatureVerification,
}

/// In-memory Ed25519 keypair wrapper used by Homa wallet and node flows.
pub struct Keypair {
    signing_key: SigningKey,
}

impl fmt::Debug for Keypair {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("Keypair")
            .field("public_key", &self.public_key_bytes())
            .finish_non_exhaustive()
    }
}

impl Keypair {
    /// Generates a fresh keypair using the OS cryptographic RNG.
    #[must_use]
    pub fn generate() -> Self {
        let signing_key = SigningKey::generate(&mut OsRng);
        Self { signing_key }
    }

    /// Creates a keypair from raw 32-byte secret key material.
    ///
    /// The input bytes are copied and zeroized after initialization.
    pub fn from_secret_key(secret_key: &[u8]) -> Result<Self, CryptoError> {
        let mut secret_bytes = to_array::<SECRET_KEY_LENGTH>(
            secret_key,
            CryptoError::InvalidSecretKeyLength {
                expected: SECRET_KEY_LENGTH,
                actual: secret_key.len(),
            },
        )?;

        let signing_key = SigningKey::from_bytes(&secret_bytes);
        secret_bytes.zeroize();
        Ok(Self { signing_key })
    }

    /// Returns the secret key bytes.
    #[must_use]
    pub fn secret_key_bytes(&self) -> [u8; SECRET_KEY_LENGTH] {
        self.signing_key.to_bytes()
    }

    /// Returns the public key bytes.
    #[must_use]
    pub fn public_key_bytes(&self) -> [u8; PUBLIC_KEY_LENGTH] {
        self.signing_key.verifying_key().to_bytes()
    }

    /// Signs arbitrary message bytes.
    #[must_use]
    pub fn sign(&self, message: &[u8]) -> [u8; SIGNATURE_LENGTH] {
        self.signing_key.sign(message).to_bytes()
    }
}

/// Verifies a message signature against a raw Ed25519 public key.
pub fn verify_signature(
    public_key: &[u8],
    message: &[u8],
    signature: &[u8],
) -> Result<(), CryptoError> {
    let public_key_bytes = to_array::<PUBLIC_KEY_LENGTH>(
        public_key,
        CryptoError::InvalidPublicKeyLength {
            expected: PUBLIC_KEY_LENGTH,
            actual: public_key.len(),
        },
    )?;
    let signature_bytes = to_array::<SIGNATURE_LENGTH>(
        signature,
        CryptoError::InvalidSignatureLength {
            expected: SIGNATURE_LENGTH,
            actual: signature.len(),
        },
    )?;

    let verifying_key =
        VerifyingKey::from_bytes(&public_key_bytes).map_err(|_| CryptoError::PublicKeyDecoding)?;
    let parsed_signature =
        Signature::from_slice(&signature_bytes).map_err(|_| CryptoError::SignatureDecoding)?;

    verifying_key
        .verify_strict(message, &parsed_signature)
        .map_err(|_| CryptoError::SignatureVerification)
}

fn to_array<const LENGTH: usize>(
    bytes: &[u8],
    invalid_length_error: CryptoError,
) -> Result<[u8; LENGTH], CryptoError> {
    let mut out = [0_u8; LENGTH];
    if bytes.len() != LENGTH {
        return Err(invalid_length_error);
    }
    out.copy_from_slice(bytes);
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::{CryptoError, Keypair, SIGNATURE_LENGTH, verify_signature};

    #[test]
    fn generates_valid_keypair_and_signs() {
        let keypair = Keypair::generate();
        let message = b"homa-phase-1";
        let signature = keypair.sign(message);

        assert_eq!(signature.len(), SIGNATURE_LENGTH);
        assert!(
            verify_signature(&keypair.public_key_bytes(), message, &signature).is_ok(),
            "freshly signed message should verify"
        );
    }

    #[test]
    fn rejects_tampered_message() {
        let keypair = Keypair::generate();
        let message = b"original-payload";
        let tampered_message = b"original-payload-tampered";
        let signature = keypair.sign(message);

        assert!(
            matches!(
                verify_signature(&keypair.public_key_bytes(), tampered_message, &signature),
                Err(CryptoError::SignatureVerification)
            ),
            "signature must fail when payload bytes change"
        );
    }

    #[test]
    fn imports_keypair_from_secret_key_bytes() {
        let original = Keypair::generate();
        let imported = Keypair::from_secret_key(&original.secret_key_bytes());

        assert!(
            imported.is_ok(),
            "importing generated key material should work"
        );
        let imported_keypair = imported.unwrap_or_else(|_| unreachable!());
        assert_eq!(
            imported_keypair.public_key_bytes(),
            original.public_key_bytes(),
            "public key derived from imported secret key must match"
        );
    }

    #[test]
    fn rejects_invalid_secret_key_length() {
        let invalid_secret_key = [0_u8; 31];
        let imported = Keypair::from_secret_key(&invalid_secret_key);

        assert!(
            matches!(
                imported,
                Err(CryptoError::InvalidSecretKeyLength {
                    expected: 32,
                    actual: 31
                })
            ),
            "invalid key lengths must return a typed error"
        );
    }
}
