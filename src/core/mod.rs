//! Core blockchain data types.

/// Block and block-header primitives.
pub mod block;
/// Deterministic fork-choice and partition reconciliation.
pub mod fork_choice;
/// Genesis block and initial allocations.
pub mod genesis;
/// Durable finalized-block event indexer and replayable query indexes.
pub mod indexer;
/// Mempool data structures and ingestion checks.
pub mod mempool;
/// Durable mempool checkpoint persistence/recovery primitives.
pub mod mempool_checkpoint;
/// Crash-safe state commit and recovery primitives.
pub mod recovery;
/// Account state storage and block application.
pub mod state;
/// Fast-sync snapshot and state-root verification primitives.
pub mod sync;
/// Transaction primitives.
pub mod transaction;
