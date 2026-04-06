//! Address derivation and validation logic.

use core::fmt;

use thiserror::Error;

use crate::crypto::keys::PUBLIC_KEY_LENGTH;

/// Human-readable address prefix.
pub const ADDRESS_PREFIX: &str = "HMA";
const ADDRESS_VERSION: u8 = 1;
const CHECKSUM_LENGTH: usize = 4;
const HASH_LENGTH: usize = 32;
const PAYLOAD_LENGTH: usize = 2 + HASH_LENGTH;
const ENCODED_ADDRESS_LENGTH: usize = PAYLOAD_LENGTH + CHECKSUM_LENGTH;

/// Supported Homa network IDs.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[repr(u8)]
pub enum Network {
    /// Homa mainnet.
    Mainnet = 0x01,
    /// Homa public testnet.
    Testnet = 0x02,
    /// Local development network.
    Devnet = 0x03,
}

impl Network {
    /// Returns the wire-format byte representation.
    #[must_use]
    pub const fn as_byte(self) -> u8 {
        self as u8
    }

    const fn from_byte(value: u8) -> Result<Self, AddressError> {
        match value {
            0x01 => Ok(Self::Mainnet),
            0x02 => Ok(Self::Testnet),
            0x03 => Ok(Self::Devnet),
            _ => Err(AddressError::InvalidNetworkByte(value)),
        }
    }
}

impl fmt::Display for Network {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        let label = match self {
            Self::Mainnet => "mainnet",
            Self::Testnet => "testnet",
            Self::Devnet => "devnet",
        };
        formatter.write_str(label)
    }
}

/// Decoded address data after successful structural verification.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ParsedAddress {
    /// Encoded target network.
    pub network: Network,
    /// Blake3 hash digest of the source public key.
    pub key_hash: [u8; HASH_LENGTH],
}

/// Typed address-encoding and parsing errors.
#[derive(Debug, Clone, PartialEq, Eq, Error)]
pub enum AddressError {
    /// Input public key byte-length does not match Ed25519 requirements.
    #[error("invalid public key length: expected {expected}, got {actual}")]
    InvalidPublicKeyLength { expected: usize, actual: usize },
    /// Address does not start with the expected `HMA` prefix.
    #[error("invalid address prefix")]
    InvalidPrefix,
    /// Address body cannot be decoded from base58.
    #[error("base58 decoding failed")]
    Base58Decoding,
    /// Address byte-length is not the expected payload + checksum size.
    #[error("invalid address length: expected {expected}, got {actual}")]
    InvalidLength { expected: usize, actual: usize },
    /// Address version byte is unsupported.
    #[error("invalid address version: expected {expected}, got {actual}")]
    InvalidVersion { expected: u8, actual: u8 },
    /// Address network byte is unknown.
    #[error("invalid network byte: {0}")]
    InvalidNetworkByte(u8),
    /// Address checksum mismatch.
    #[error("address checksum mismatch")]
    InvalidChecksum,
    /// Address encodes a different network than required by the caller.
    #[error("address network mismatch: expected {expected}, got {actual}")]
    NetworkMismatch { expected: Network, actual: Network },
}

/// Derives an address string from a raw Ed25519 public key.
///
/// Format:
/// `HMA` + base58(version || network || `blake3(public_key)` || checksum4).
pub fn derive_address(public_key: &[u8], network: Network) -> Result<String, AddressError> {
    if public_key.len() != PUBLIC_KEY_LENGTH {
        return Err(AddressError::InvalidPublicKeyLength {
            expected: PUBLIC_KEY_LENGTH,
            actual: public_key.len(),
        });
    }

    let key_hash = blake3::hash(public_key);
    let mut payload = [0_u8; PAYLOAD_LENGTH];
    payload[0] = ADDRESS_VERSION;
    payload[1] = network.as_byte();
    payload[2..].copy_from_slice(key_hash.as_bytes());

    let checksum = checksum(&payload);
    let mut buffer = [0_u8; ENCODED_ADDRESS_LENGTH];
    buffer[..PAYLOAD_LENGTH].copy_from_slice(&payload);
    buffer[PAYLOAD_LENGTH..].copy_from_slice(&checksum);

    let encoded = bs58::encode(buffer).into_string();
    Ok(format!("{ADDRESS_PREFIX}{encoded}"))
}

/// Parses an address and verifies prefix, checksum, and version fields.
pub fn parse_address(address: &str) -> Result<ParsedAddress, AddressError> {
    let Some(base58_body) = address.strip_prefix(ADDRESS_PREFIX) else {
        return Err(AddressError::InvalidPrefix);
    };

    let decoded = bs58::decode(base58_body)
        .into_vec()
        .map_err(|_| AddressError::Base58Decoding)?;
    if decoded.len() != ENCODED_ADDRESS_LENGTH {
        return Err(AddressError::InvalidLength {
            expected: ENCODED_ADDRESS_LENGTH,
            actual: decoded.len(),
        });
    }

    let (payload, checksum_bytes) = decoded.split_at(PAYLOAD_LENGTH);
    let expected_checksum = checksum(payload);
    if checksum_bytes != expected_checksum.as_slice() {
        return Err(AddressError::InvalidChecksum);
    }

    if payload[0] != ADDRESS_VERSION {
        return Err(AddressError::InvalidVersion {
            expected: ADDRESS_VERSION,
            actual: payload[0],
        });
    }

    let network = Network::from_byte(payload[1])?;
    let mut key_hash = [0_u8; HASH_LENGTH];
    key_hash.copy_from_slice(&payload[2..]);

    Ok(ParsedAddress { network, key_hash })
}

/// Parses an address and enforces that it matches an expected network.
pub fn validate_address_for_network(
    address: &str,
    expected_network: Network,
) -> Result<ParsedAddress, AddressError> {
    let parsed = parse_address(address)?;
    if parsed.network != expected_network {
        return Err(AddressError::NetworkMismatch {
            expected: expected_network,
            actual: parsed.network,
        });
    }
    Ok(parsed)
}

fn checksum(payload: &[u8]) -> [u8; CHECKSUM_LENGTH] {
    let first = blake3::hash(payload);
    let second = blake3::hash(first.as_bytes());
    let mut out = [0_u8; CHECKSUM_LENGTH];
    out.copy_from_slice(&second.as_bytes()[..CHECKSUM_LENGTH]);
    out
}

#[cfg(test)]
mod tests {
    use super::{
        ADDRESS_PREFIX, AddressError, Network, derive_address, parse_address,
        validate_address_for_network,
    };
    use crate::crypto::keys::Keypair;

    #[test]
    fn derives_and_parses_mainnet_address() {
        let keypair = Keypair::generate();
        let address_result = derive_address(&keypair.public_key_bytes(), Network::Mainnet);
        assert!(address_result.is_ok(), "address derivation should succeed");
        let address = address_result.unwrap_or_else(|_| unreachable!());

        assert!(
            address.starts_with(ADDRESS_PREFIX),
            "address must use HMA prefix"
        );

        let parsed_result = parse_address(&address);
        assert!(parsed_result.is_ok(), "derived address should parse");
        let parsed = parsed_result.unwrap_or_else(|_| unreachable!());
        assert_eq!(parsed.network, Network::Mainnet);
    }

    #[test]
    fn derivation_is_deterministic_for_same_public_key() {
        let keypair = Keypair::generate();
        let first = derive_address(&keypair.public_key_bytes(), Network::Testnet);
        let second = derive_address(&keypair.public_key_bytes(), Network::Testnet);

        assert!(first.is_ok(), "first derivation should succeed");
        assert!(second.is_ok(), "second derivation should succeed");
        assert_eq!(
            first.unwrap_or_else(|_| unreachable!()),
            second.unwrap_or_else(|_| unreachable!()),
            "address derivation must be deterministic"
        );
    }

    #[test]
    fn rejects_invalid_prefix() {
        let keypair = Keypair::generate();
        let address_result = derive_address(&keypair.public_key_bytes(), Network::Mainnet);
        assert!(address_result.is_ok(), "address derivation should succeed");
        let address = address_result.unwrap_or_else(|_| unreachable!());
        let without_prefix = &address[ADDRESS_PREFIX.len()..];
        let invalid_prefix_address = format!("XYZ{without_prefix}");

        assert!(
            matches!(
                parse_address(&invalid_prefix_address),
                Err(AddressError::InvalidPrefix)
            ),
            "prefix validation should fail for non-HMA addresses"
        );
    }

    #[test]
    fn rejects_tampered_checksum() {
        let keypair = Keypair::generate();
        let address_result = derive_address(&keypair.public_key_bytes(), Network::Devnet);
        assert!(address_result.is_ok(), "address derivation should succeed");
        let address = address_result.unwrap_or_else(|_| unreachable!());
        let encoded = &address[ADDRESS_PREFIX.len()..];

        let decoded_result = bs58::decode(encoded).into_vec();
        assert!(decoded_result.is_ok(), "derived address must be decodable");
        let mut decoded = decoded_result.unwrap_or_else(|_| unreachable!());
        let last_index = decoded.len() - 1;
        decoded[last_index] ^= 0x01;

        let tampered_address = format!("{ADDRESS_PREFIX}{}", bs58::encode(decoded).into_string());
        assert!(
            matches!(
                parse_address(&tampered_address),
                Err(AddressError::InvalidChecksum)
            ),
            "checksum mismatch should be rejected"
        );
    }

    #[test]
    fn rejects_invalid_public_key_length() {
        let short_public_key = [7_u8; 31];
        let derived = derive_address(&short_public_key, Network::Mainnet);

        assert!(
            matches!(
                derived,
                Err(AddressError::InvalidPublicKeyLength {
                    expected: 32,
                    actual: 31
                })
            ),
            "invalid public key lengths must return a typed error"
        );
    }

    #[test]
    fn validates_expected_network() {
        let keypair = Keypair::generate();
        let address_result = derive_address(&keypair.public_key_bytes(), Network::Mainnet);
        assert!(address_result.is_ok(), "address derivation should succeed");
        let address = address_result.unwrap_or_else(|_| unreachable!());

        let mismatched = validate_address_for_network(&address, Network::Testnet);
        assert!(
            matches!(
                mismatched,
                Err(AddressError::NetworkMismatch {
                    expected: Network::Testnet,
                    actual: Network::Mainnet
                })
            ),
            "network-enforced validation must reject cross-network addresses"
        );
    }
}
