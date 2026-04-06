//! Homa core library.

/// Consensus and validator primitives.
pub mod consensus;
/// Core chain data structures.
pub mod core;
/// Cryptographic primitives and key/address handling.
pub mod crypto;
/// Networking and peer-discovery primitives.
pub mod network;
/// Structured metrics and event instrumentation primitives.
pub mod observability;
/// Wallet and CLI entrypoints.
pub mod wallet;
