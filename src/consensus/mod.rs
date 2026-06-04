//! Consensus primitives.

/// Stake-weighted finality votes and quorum certificates.
pub mod finality;
/// Deterministic stake-weighted leader election.
pub mod leader;
/// Client-side proof-of-work puzzle and verification.
pub mod pow;
/// In-memory validator stake accounting.
pub mod stake;
