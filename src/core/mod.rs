//! Core blockchain data types.

/// Block and block-header primitives.
pub mod block;
/// Deterministic fork-choice and partition reconciliation.
pub mod fork_choice;
/// Genesis block and initial allocations.
pub mod genesis;
/// Mempool data structures and ingestion checks.
pub mod mempool;
/// Crash-safe state commit and recovery primitives.
pub mod recovery;
/// Account state storage and block application.
pub mod state;
/// Fast-sync snapshot and state-root verification primitives.
pub mod sync;
/// Transaction primitives.
pub mod transaction;
