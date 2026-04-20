//! Durable finalized-block indexer backed by `redb`.

use std::fs;
use std::path::{Path, PathBuf};

use redb::{Database, ReadableTable, TableDefinition};
use serde::{Deserialize, Serialize};
use thiserror::Error;

use crate::core::block::{Block, BlockError};
use crate::core::mempool::{MempoolError, transaction_id};
use crate::core::transaction::Amount;
use crate::crypto::address::Network;

/// Canonical finalized-index database filename.
pub const FINALIZED_INDEX_FILE_NAME: &str = "finalized_index.redb";
const FINALIZED_INDEX_SCHEMA_VERSION: u64 = 1;

const META_KEY_SCHEMA_VERSION: &str = "schema_version";
const META_KEY_NETWORK: &str = "network";
const META_KEY_FIRST_RETAINED_SEQUENCE: &str = "first_retained_sequence";
const META_KEY_NEXT_EVENT_SEQUENCE: &str = "next_event_sequence";
const META_KEY_INDEXED_THROUGH_SEQUENCE: &str = "indexed_through_sequence";

const META_TABLE: TableDefinition<'static, &str, u64> =
    TableDefinition::new("finalized_index_meta");
const FINALIZED_EVENT_TABLE: TableDefinition<'static, u64, &[u8]> =
    TableDefinition::new("finalized_block_events");
const BLOCK_BY_HEIGHT_TABLE: TableDefinition<'static, u64, &[u8]> =
    TableDefinition::new("block_by_height");
const TX_BY_HASH_TABLE: TableDefinition<'static, &str, &[u8]> = TableDefinition::new("tx_by_hash");
const TX_BY_SENDER_NONCE_TABLE: TableDefinition<'static, &str, &[u8]> =
    TableDefinition::new("tx_by_sender_nonce");
const TX_BY_ADDRESS_TIMELINE_TABLE: TableDefinition<'static, &str, &[u8]> =
    TableDefinition::new("tx_by_address_timeline");

/// Runtime path configuration used by the finalized indexer.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FinalizedIndexerPaths {
    /// Storage root directory.
    pub directory: PathBuf,
    /// Canonical redb file path.
    pub index_path: PathBuf,
}

impl FinalizedIndexerPaths {
    /// Creates finalized indexer paths rooted at `directory`.
    #[must_use]
    pub fn new(directory: PathBuf) -> Self {
        Self {
            index_path: directory.join(FINALIZED_INDEX_FILE_NAME),
            directory,
        }
    }
}

/// Retention + compaction policy for finalized index segments.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct FinalizedIndexerConfig {
    /// Maximum finalized blocks retained across event/index tables.
    pub max_retained_blocks: usize,
}

impl Default for FinalizedIndexerConfig {
    fn default() -> Self {
        Self {
            max_retained_blocks: 100_000,
        }
    }
}

/// Open/recovery report for finalized indexer startup.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct FinalizedIndexerOpenReport {
    /// Whether startup triggered deterministic event replay rebuild.
    pub rebuild_performed: bool,
    /// Number of finalized events replayed into secondary indexes.
    pub events_replayed: usize,
    /// Number of event rows removed during retention compaction.
    pub compacted_events: usize,
    /// Number of finalized blocks retained after startup validation.
    pub retained_blocks: usize,
}

/// Append report for one finalized block indexing operation.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct FinalizedIndexerAppendReport {
    /// Number of indexed transactions in the appended finalized block.
    pub indexed_transactions: usize,
    /// Number of event rows removed by retention compaction.
    pub compacted_events: usize,
    /// Number of finalized blocks retained after append/compaction.
    pub retained_blocks: usize,
}

/// Lightweight diagnostics for lifecycle integrity checks.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct FinalizedIndexerDiagnostics {
    /// Earliest retained finalized-event sequence.
    pub first_retained_sequence: u64,
    /// Next append sequence for finalized-event log.
    pub next_event_sequence: u64,
    /// Number of retained finalized blocks.
    pub retained_blocks: usize,
}

/// One indexed finalized block record.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct IndexedBlockRecord {
    /// Finalized block height.
    pub height: u64,
    /// Finalized block hash.
    pub block_hash: [u8; 32],
    /// Wall-clock timestamp when block crossed finalization boundary.
    pub finalized_at_unix_ms: u64,
    /// Full finalized block payload.
    pub block: Block,
}

/// One indexed transaction reference.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct IndexedTransactionRecord {
    /// Transaction hash.
    pub tx_hash: [u8; 32],
    /// Sender address.
    pub sender: String,
    /// Receiver address.
    pub receiver: String,
    /// Transaction nonce.
    pub nonce: u64,
    /// Transaction amount.
    pub amount: Amount,
    /// Transaction fee.
    pub fee: Amount,
    /// Finalized block height.
    pub block_height: u64,
    /// Finalized block hash.
    pub block_hash: [u8; 32],
    /// Position inside finalized block transaction list.
    pub tx_index: u32,
    /// Wall-clock timestamp when block crossed finalization boundary.
    pub finalized_at_unix_ms: u64,
}

/// Timeline direction relative to queried address.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum AddressTimelineDirection {
    /// Address appears as transaction sender.
    Outgoing,
    /// Address appears as transaction receiver.
    Incoming,
}

/// One indexed address timeline entry.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct IndexedAddressTimelineRecord {
    /// Address timeline owner.
    pub address: String,
    /// Direction relative to address.
    pub direction: AddressTimelineDirection,
    /// Transaction hash.
    pub tx_hash: [u8; 32],
    /// Finalized block height.
    pub block_height: u64,
    /// Position inside finalized block transaction list.
    pub tx_index: u32,
    /// Transaction sender.
    pub sender: String,
    /// Transaction receiver.
    pub receiver: String,
    /// Transaction amount.
    pub amount: Amount,
    /// Transaction fee.
    pub fee: Amount,
    /// Wall-clock timestamp when block crossed finalization boundary.
    pub finalized_at_unix_ms: u64,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
struct FinalizedBlockEvent {
    finalized_at_unix_ms: u64,
    block: Block,
}

/// Typed finalized-index persistence/query errors.
#[derive(Debug, Error)]
pub enum FinalizedIndexerError {
    /// Retention policy was invalid.
    #[error("finalized indexer retention policy is invalid: max_retained_blocks must be > 0")]
    InvalidRetentionLimit,
    /// Failed to create finalized-index directory.
    #[error("failed to create finalized index directory: {path}")]
    CreateIndexDirectory {
        /// Directory path.
        path: String,
        /// Underlying I/O error.
        source: std::io::Error,
    },
    /// Generic `redb` operation failure.
    #[error("finalized index redb operation failed ({operation}) at {path}: {reason}")]
    Redb {
        /// Operation label.
        operation: &'static str,
        /// Database path.
        path: String,
        /// Rendered error reason.
        reason: String,
    },
    /// Persisted metadata is missing.
    #[error("finalized index metadata is missing key: {key}")]
    MissingMetadata {
        /// Missing metadata key.
        key: &'static str,
    },
    /// Persisted schema version mismatches runtime schema.
    #[error("finalized index schema version mismatch: expected={expected}, observed={observed}")]
    SchemaVersionMismatch {
        /// Expected schema version.
        expected: u64,
        /// Observed schema version.
        observed: u64,
    },
    /// Persisted network mismatches runtime network.
    #[error("finalized index network mismatch: expected={expected}, observed={observed}")]
    NetworkMismatch {
        /// Expected network domain byte.
        expected: u8,
        /// Observed network domain byte.
        observed: u8,
    },
    /// Finalized block hash computation failed.
    #[error("finalized index block hash computation failed: {source}")]
    BlockHash {
        /// Underlying block hash error.
        source: BlockError,
    },
    /// Transaction identifier computation failed.
    #[error("finalized index transaction identifier computation failed: {source}")]
    TransactionId {
        /// Underlying transaction-id error.
        source: MempoolError,
    },
    /// Record serialization failed.
    #[error("finalized index record serialization failed")]
    Serialization,
    /// Record deserialization failed.
    #[error("finalized index record deserialization failed")]
    Deserialization,
    /// Indexed block height exists with different hash.
    #[error(
        "finalized index block height conflict: height={height}, existing_hash={existing_hash}, incoming_hash={incoming_hash}"
    )]
    BlockHeightConflict {
        /// Conflicting block height.
        height: u64,
        /// Existing hash in index.
        existing_hash: String,
        /// Incoming hash.
        incoming_hash: String,
    },
}

/// Durable finalized block indexer with deterministic replay/rebuild support.
#[derive(Debug)]
pub struct FinalizedIndexer {
    database: Database,
    path: PathBuf,
    network: Network,
    config: FinalizedIndexerConfig,
}

impl FinalizedIndexer {
    /// Opens or creates one finalized index database and validates/rebuilds indexes.
    pub fn open(
        paths: &FinalizedIndexerPaths,
        network: Network,
        config: FinalizedIndexerConfig,
    ) -> Result<(Self, FinalizedIndexerOpenReport), FinalizedIndexerError> {
        if config.max_retained_blocks == 0 {
            return Err(FinalizedIndexerError::InvalidRetentionLimit);
        }

        fs::create_dir_all(&paths.directory).map_err(|source| {
            FinalizedIndexerError::CreateIndexDirectory {
                path: display_path(&paths.directory),
                source,
            }
        })?;

        let database = Database::create(&paths.index_path)
            .map_err(|source| redb_error("create", &paths.index_path, &source))?;
        let mut report = FinalizedIndexerOpenReport::default();

        let write_txn = database
            .begin_write()
            .map_err(|source| redb_error("begin_write", &paths.index_path, &source))?;
        initialize_or_validate_metadata(&write_txn, network, &paths.index_path)?;

        let next_event_sequence =
            read_meta_u64(&write_txn, META_KEY_NEXT_EVENT_SEQUENCE, &paths.index_path)?;
        let indexed_through_sequence = read_meta_u64(
            &write_txn,
            META_KEY_INDEXED_THROUGH_SEQUENCE,
            &paths.index_path,
        )?;

        let mut rebuild_required = indexed_through_sequence != next_event_sequence;
        if !rebuild_required {
            rebuild_required = secondary_indexes_corrupted(&write_txn, &paths.index_path)?;
        }
        if rebuild_required {
            clear_secondary_indexes(&write_txn, &paths.index_path)?;
            report.events_replayed = replay_events_into_indexes(&write_txn, &paths.index_path)?;
            write_meta_u64(
                &write_txn,
                META_KEY_INDEXED_THROUGH_SEQUENCE,
                next_event_sequence,
                &paths.index_path,
            )?;
            report.rebuild_performed = true;
        }

        let compacted =
            compact_retention(&write_txn, config.max_retained_blocks, &paths.index_path)?;
        report.compacted_events = compacted.compacted_events;
        report.retained_blocks = compacted.retained_blocks;

        write_txn
            .commit()
            .map_err(|source| redb_error("commit", &paths.index_path, &source))?;

        Ok((
            Self {
                database,
                path: paths.index_path.clone(),
                network,
                config,
            },
            report,
        ))
    }

    /// Appends one finalized block event and updates all query indexes atomically.
    pub fn append_finalized_block(
        &self,
        block: &Block,
        finalized_at_unix_ms: u64,
    ) -> Result<FinalizedIndexerAppendReport, FinalizedIndexerError> {
        let write_txn = self
            .database
            .begin_write()
            .map_err(|source| redb_error("begin_write", &self.path, &source))?;
        initialize_or_validate_metadata(&write_txn, self.network, &self.path)?;

        let block_hash = block
            .hash()
            .map_err(|source| FinalizedIndexerError::BlockHash { source })?;

        if let Some(existing) =
            self.get_block_by_height_from_txn(&write_txn, block.header.height)?
        {
            if existing.block_hash != block_hash {
                return Err(FinalizedIndexerError::BlockHeightConflict {
                    height: block.header.height,
                    existing_hash: hex::encode(existing.block_hash),
                    incoming_hash: hex::encode(block_hash),
                });
            }
            return Ok(FinalizedIndexerAppendReport {
                indexed_transactions: 0,
                compacted_events: 0,
                retained_blocks: self.diagnostics()?.retained_blocks,
            });
        }

        let next_event_sequence =
            read_meta_u64(&write_txn, META_KEY_NEXT_EVENT_SEQUENCE, &self.path)?;
        let event = FinalizedBlockEvent {
            finalized_at_unix_ms,
            block: block.clone(),
        };
        let event_bytes = encode_record(&event)?;
        {
            let mut events = write_txn
                .open_table(FINALIZED_EVENT_TABLE)
                .map_err(|source| redb_error("open_event_table", &self.path, &source))?;
            events
                .insert(next_event_sequence, event_bytes.as_slice())
                .map_err(|source| redb_error("insert_event", &self.path, &source))?;
        }

        let indexed_transactions =
            index_block_into_secondary_tables(&write_txn, block, finalized_at_unix_ms, &self.path)?;
        write_meta_u64(
            &write_txn,
            META_KEY_NEXT_EVENT_SEQUENCE,
            next_event_sequence.saturating_add(1),
            &self.path,
        )?;
        write_meta_u64(
            &write_txn,
            META_KEY_INDEXED_THROUGH_SEQUENCE,
            next_event_sequence.saturating_add(1),
            &self.path,
        )?;

        let compacted = compact_retention(&write_txn, self.config.max_retained_blocks, &self.path)?;
        write_txn
            .commit()
            .map_err(|source| redb_error("commit", &self.path, &source))?;

        Ok(FinalizedIndexerAppendReport {
            indexed_transactions,
            compacted_events: compacted.compacted_events,
            retained_blocks: compacted.retained_blocks,
        })
    }

    /// Ensures one finalized block is indexed (idempotent by height/hash).
    pub fn ensure_finalized_block_indexed(
        &self,
        block: &Block,
        finalized_at_unix_ms: u64,
    ) -> Result<bool, FinalizedIndexerError> {
        let maybe_existing = self.get_block_by_height(block.header.height)?;
        if let Some(existing) = maybe_existing {
            let incoming_hash = block
                .hash()
                .map_err(|source| FinalizedIndexerError::BlockHash { source })?;
            if existing.block_hash == incoming_hash {
                return Ok(false);
            }
            return Err(FinalizedIndexerError::BlockHeightConflict {
                height: block.header.height,
                existing_hash: hex::encode(existing.block_hash),
                incoming_hash: hex::encode(incoming_hash),
            });
        }
        let _ = self.append_finalized_block(block, finalized_at_unix_ms)?;
        Ok(true)
    }

    /// Rebuilds all secondary indexes deterministically from retained finalized events.
    pub fn rebuild_indexes(&self) -> Result<FinalizedIndexerOpenReport, FinalizedIndexerError> {
        let write_txn = self
            .database
            .begin_write()
            .map_err(|source| redb_error("begin_write", &self.path, &source))?;
        initialize_or_validate_metadata(&write_txn, self.network, &self.path)?;
        clear_secondary_indexes(&write_txn, &self.path)?;
        let events_replayed = replay_events_into_indexes(&write_txn, &self.path)?;
        let next_event_sequence =
            read_meta_u64(&write_txn, META_KEY_NEXT_EVENT_SEQUENCE, &self.path)?;
        write_meta_u64(
            &write_txn,
            META_KEY_INDEXED_THROUGH_SEQUENCE,
            next_event_sequence,
            &self.path,
        )?;
        let compacted = compact_retention(&write_txn, self.config.max_retained_blocks, &self.path)?;
        write_txn
            .commit()
            .map_err(|source| redb_error("commit", &self.path, &source))?;
        Ok(FinalizedIndexerOpenReport {
            rebuild_performed: true,
            events_replayed,
            compacted_events: compacted.compacted_events,
            retained_blocks: compacted.retained_blocks,
        })
    }

    /// Returns indexed block metadata by finalized height.
    pub fn get_block_by_height(
        &self,
        height: u64,
    ) -> Result<Option<IndexedBlockRecord>, FinalizedIndexerError> {
        let read_txn = self
            .database
            .begin_read()
            .map_err(|source| redb_error("begin_read", &self.path, &source))?;
        let table = read_txn
            .open_table(BLOCK_BY_HEIGHT_TABLE)
            .map_err(|source| redb_error("open_block_by_height_table", &self.path, &source))?;
        let maybe = table
            .get(height)
            .map_err(|source| redb_error("get_block_by_height", &self.path, &source))?;
        maybe.map(|value| decode_record(value.value())).transpose()
    }

    /// Returns indexed block metadata by block hash.
    pub fn get_block_by_hash(
        &self,
        block_hash: &[u8; 32],
    ) -> Result<Option<IndexedBlockRecord>, FinalizedIndexerError> {
        let read_txn = self
            .database
            .begin_read()
            .map_err(|source| redb_error("begin_read", &self.path, &source))?;
        let table = read_txn
            .open_table(FINALIZED_EVENT_TABLE)
            .map_err(|source| redb_error("open_event_table", &self.path, &source))?;
        for row in table
            .iter()
            .map_err(|source| redb_error("iter_event_table", &self.path, &source))?
        {
            let (_, value) =
                row.map_err(|source| redb_error("read_event_row", &self.path, &source))?;
            let event: FinalizedBlockEvent = decode_record(value.value())?;
            let event_hash = event
                .block
                .hash()
                .map_err(|source| FinalizedIndexerError::BlockHash { source })?;
            if &event_hash == block_hash {
                return Ok(Some(IndexedBlockRecord {
                    height: event.block.header.height,
                    block_hash: event_hash,
                    finalized_at_unix_ms: event.finalized_at_unix_ms,
                    block: event.block,
                }));
            }
        }
        Ok(None)
    }

    /// Returns indexed transaction metadata by transaction hash.
    pub fn get_transaction_by_hash(
        &self,
        tx_hash: &[u8; 32],
    ) -> Result<Option<IndexedTransactionRecord>, FinalizedIndexerError> {
        let read_txn = self
            .database
            .begin_read()
            .map_err(|source| redb_error("begin_read", &self.path, &source))?;
        let table = read_txn
            .open_table(TX_BY_HASH_TABLE)
            .map_err(|source| redb_error("open_tx_by_hash_table", &self.path, &source))?;
        let key = hex::encode(tx_hash);
        let maybe = table
            .get(key.as_str())
            .map_err(|source| redb_error("get_tx_by_hash", &self.path, &source))?;
        maybe.map(|value| decode_record(value.value())).transpose()
    }

    /// Returns indexed transaction metadata by `(sender, nonce)` uniqueness key.
    pub fn get_transaction_by_sender_nonce(
        &self,
        sender: &str,
        nonce: u64,
    ) -> Result<Option<IndexedTransactionRecord>, FinalizedIndexerError> {
        let read_txn = self
            .database
            .begin_read()
            .map_err(|source| redb_error("begin_read", &self.path, &source))?;
        let table = read_txn
            .open_table(TX_BY_SENDER_NONCE_TABLE)
            .map_err(|source| redb_error("open_tx_by_sender_nonce_table", &self.path, &source))?;
        let key = sender_nonce_key(sender, nonce);
        let maybe = table
            .get(key.as_str())
            .map_err(|source| redb_error("get_tx_by_sender_nonce", &self.path, &source))?;
        maybe.map(|value| decode_record(value.value())).transpose()
    }

    /// Returns address timeline entries ordered by latest `(height, tx_index)` first.
    pub fn get_address_timeline(
        &self,
        address: &str,
        limit: usize,
    ) -> Result<Vec<IndexedAddressTimelineRecord>, FinalizedIndexerError> {
        if limit == 0 {
            return Ok(Vec::new());
        }
        let read_txn = self
            .database
            .begin_read()
            .map_err(|source| redb_error("begin_read", &self.path, &source))?;
        let table = read_txn
            .open_table(TX_BY_ADDRESS_TIMELINE_TABLE)
            .map_err(|source| {
                redb_error("open_tx_by_address_timeline_table", &self.path, &source)
            })?;
        let prefix = format!("{address}:");
        let mut results: Vec<IndexedAddressTimelineRecord> = Vec::new();
        for row in table
            .iter()
            .map_err(|source| redb_error("iter_tx_by_address_timeline", &self.path, &source))?
        {
            let (key, value) = row.map_err(|source| {
                redb_error("read_tx_by_address_timeline_row", &self.path, &source)
            })?;
            if !key.value().starts_with(&prefix) {
                continue;
            }
            results.push(decode_record(value.value())?);
        }

        results.sort_by(|left, right| {
            right
                .block_height
                .cmp(&left.block_height)
                .then(right.tx_index.cmp(&left.tx_index))
        });
        if results.len() > limit {
            results.truncate(limit);
        }
        Ok(results)
    }

    /// Returns finalized-index diagnostics used by daemon integrity checks.
    pub fn diagnostics(&self) -> Result<FinalizedIndexerDiagnostics, FinalizedIndexerError> {
        let read_txn = self
            .database
            .begin_read()
            .map_err(|source| redb_error("begin_read", &self.path, &source))?;
        let metadata = read_txn
            .open_table(META_TABLE)
            .map_err(|source| redb_error("open_meta_table", &self.path, &source))?;
        let first_retained_sequence = metadata
            .get(META_KEY_FIRST_RETAINED_SEQUENCE)
            .map_err(|source| redb_error("read_first_retained_sequence", &self.path, &source))?
            .ok_or(FinalizedIndexerError::MissingMetadata {
                key: META_KEY_FIRST_RETAINED_SEQUENCE,
            })?
            .value();
        let next_event_sequence = metadata
            .get(META_KEY_NEXT_EVENT_SEQUENCE)
            .map_err(|source| redb_error("read_next_event_sequence", &self.path, &source))?
            .ok_or(FinalizedIndexerError::MissingMetadata {
                key: META_KEY_NEXT_EVENT_SEQUENCE,
            })?
            .value();
        let retained_blocks_u64 = next_event_sequence.saturating_sub(first_retained_sequence);
        let retained_blocks = usize::try_from(retained_blocks_u64).unwrap_or(usize::MAX);
        Ok(FinalizedIndexerDiagnostics {
            first_retained_sequence,
            next_event_sequence,
            retained_blocks,
        })
    }

    fn get_block_by_height_from_txn(
        &self,
        write_txn: &redb::WriteTransaction,
        height: u64,
    ) -> Result<Option<IndexedBlockRecord>, FinalizedIndexerError> {
        let table = write_txn
            .open_table(BLOCK_BY_HEIGHT_TABLE)
            .map_err(|source| redb_error("open_block_by_height_table", &self.path, &source))?;
        let maybe = table
            .get(height)
            .map_err(|source| redb_error("get_block_by_height", &self.path, &source))?;
        maybe.map(|value| decode_record(value.value())).transpose()
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
struct CompactionReport {
    compacted_events: usize,
    retained_blocks: usize,
}

fn initialize_or_validate_metadata(
    write_txn: &redb::WriteTransaction,
    network: Network,
    path: &Path,
) -> Result<(), FinalizedIndexerError> {
    let mut metadata = write_txn
        .open_table(META_TABLE)
        .map_err(|source| redb_error("open_meta_table", path, &source))?;
    let schema_version = metadata
        .get(META_KEY_SCHEMA_VERSION)
        .map_err(|source| redb_error("read_schema_version", path, &source))?
        .map(|value| value.value());
    match schema_version {
        Some(value) if value != FINALIZED_INDEX_SCHEMA_VERSION => {
            return Err(FinalizedIndexerError::SchemaVersionMismatch {
                expected: FINALIZED_INDEX_SCHEMA_VERSION,
                observed: value,
            });
        }
        None => {
            metadata
                .insert(META_KEY_SCHEMA_VERSION, FINALIZED_INDEX_SCHEMA_VERSION)
                .map_err(|source| redb_error("insert_schema_version", path, &source))?;
        }
        Some(_) => {}
    }

    let observed_network = metadata
        .get(META_KEY_NETWORK)
        .map_err(|source| redb_error("read_network", path, &source))?
        .map(|value| value.value());
    match observed_network {
        Some(value) if value != u64::from(network.as_byte()) => {
            return Err(FinalizedIndexerError::NetworkMismatch {
                expected: network.as_byte(),
                observed: u8::try_from(value).unwrap_or(u8::MAX),
            });
        }
        None => {
            metadata
                .insert(META_KEY_NETWORK, u64::from(network.as_byte()))
                .map_err(|source| redb_error("insert_network", path, &source))?;
        }
        Some(_) => {}
    }

    for key in [
        META_KEY_FIRST_RETAINED_SEQUENCE,
        META_KEY_NEXT_EVENT_SEQUENCE,
        META_KEY_INDEXED_THROUGH_SEQUENCE,
    ] {
        if metadata
            .get(key)
            .map_err(|source| redb_error("read_meta_key", path, &source))?
            .is_none()
        {
            metadata
                .insert(key, 0)
                .map_err(|source| redb_error("insert_meta_key", path, &source))?;
        }
    }
    Ok(())
}

fn read_meta_u64(
    write_txn: &redb::WriteTransaction,
    key: &'static str,
    path: &Path,
) -> Result<u64, FinalizedIndexerError> {
    let metadata = write_txn
        .open_table(META_TABLE)
        .map_err(|source| redb_error("open_meta_table", path, &source))?;
    metadata
        .get(key)
        .map_err(|source| redb_error("read_meta_u64", path, &source))?
        .map(|value| value.value())
        .ok_or(FinalizedIndexerError::MissingMetadata { key })
}

fn write_meta_u64(
    write_txn: &redb::WriteTransaction,
    key: &'static str,
    value: u64,
    path: &Path,
) -> Result<(), FinalizedIndexerError> {
    let mut metadata = write_txn
        .open_table(META_TABLE)
        .map_err(|source| redb_error("open_meta_table", path, &source))?;
    metadata
        .insert(key, value)
        .map_err(|source| redb_error("insert_meta_u64", path, &source))?;
    Ok(())
}

fn secondary_indexes_corrupted(
    write_txn: &redb::WriteTransaction,
    path: &Path,
) -> Result<bool, FinalizedIndexerError> {
    {
        let block_index = write_txn
            .open_table(BLOCK_BY_HEIGHT_TABLE)
            .map_err(|source| redb_error("open_block_by_height_table", path, &source))?;
        for row in block_index
            .iter()
            .map_err(|source| redb_error("iter_block_by_height", path, &source))?
        {
            let (height, bytes) =
                row.map_err(|source| redb_error("read_block_by_height_row", path, &source))?;
            let Ok(record) = decode_record::<IndexedBlockRecord>(bytes.value()) else {
                return Ok(true);
            };
            if record.height != height.value() {
                return Ok(true);
            }
        }
    }

    {
        let tx_by_hash = write_txn
            .open_table(TX_BY_HASH_TABLE)
            .map_err(|source| redb_error("open_tx_by_hash_table", path, &source))?;
        for row in tx_by_hash
            .iter()
            .map_err(|source| redb_error("iter_tx_by_hash", path, &source))?
        {
            let (key, value) =
                row.map_err(|source| redb_error("read_tx_by_hash_row", path, &source))?;
            let Ok(record) = decode_record::<IndexedTransactionRecord>(value.value()) else {
                return Ok(true);
            };
            if key.value() != hex::encode(record.tx_hash) {
                return Ok(true);
            }
        }
    }

    {
        let tx_by_sender_nonce = write_txn
            .open_table(TX_BY_SENDER_NONCE_TABLE)
            .map_err(|source| redb_error("open_tx_by_sender_nonce_table", path, &source))?;
        for row in tx_by_sender_nonce
            .iter()
            .map_err(|source| redb_error("iter_tx_by_sender_nonce", path, &source))?
        {
            let (key, value) =
                row.map_err(|source| redb_error("read_tx_by_sender_nonce_row", path, &source))?;
            let Ok(record) = decode_record::<IndexedTransactionRecord>(value.value()) else {
                return Ok(true);
            };
            if key.value() != sender_nonce_key(&record.sender, record.nonce) {
                return Ok(true);
            }
        }
    }

    {
        let tx_by_timeline = write_txn
            .open_table(TX_BY_ADDRESS_TIMELINE_TABLE)
            .map_err(|source| redb_error("open_tx_by_address_timeline_table", path, &source))?;
        for row in tx_by_timeline
            .iter()
            .map_err(|source| redb_error("iter_tx_by_address_timeline", path, &source))?
        {
            let (key, value) =
                row.map_err(|source| redb_error("read_tx_by_address_timeline_row", path, &source))?;
            let Ok(record) = decode_record::<IndexedAddressTimelineRecord>(value.value()) else {
                return Ok(true);
            };
            if key.value()
                != timeline_key(
                    &record.address,
                    record.block_height,
                    record.tx_index,
                    record.direction,
                    &record.tx_hash,
                )
            {
                return Ok(true);
            }
        }
    }

    Ok(false)
}

fn clear_secondary_indexes(
    write_txn: &redb::WriteTransaction,
    path: &Path,
) -> Result<(), FinalizedIndexerError> {
    clear_block_by_height_index(write_txn, path)?;
    clear_tx_by_hash_index(write_txn, path)?;
    clear_tx_by_sender_nonce_index(write_txn, path)?;
    clear_address_timeline_index(write_txn, path)?;
    Ok(())
}

fn clear_block_by_height_index(
    write_txn: &redb::WriteTransaction,
    path: &Path,
) -> Result<(), FinalizedIndexerError> {
    let keys = {
        let table = write_txn
            .open_table(BLOCK_BY_HEIGHT_TABLE)
            .map_err(|source| redb_error("open_block_by_height_table", path, &source))?;
        let mut keys = Vec::new();
        for row in table
            .iter()
            .map_err(|source| redb_error("iter_block_by_height", path, &source))?
        {
            let (key, _) =
                row.map_err(|source| redb_error("read_block_by_height_row", path, &source))?;
            keys.push(key.value());
        }
        keys
    };
    let mut table = write_txn
        .open_table(BLOCK_BY_HEIGHT_TABLE)
        .map_err(|source| redb_error("open_block_by_height_table", path, &source))?;
    for key in keys {
        let _ = table
            .remove(key)
            .map_err(|source| redb_error("remove_block_by_height", path, &source))?;
    }
    Ok(())
}

fn clear_tx_by_hash_index(
    write_txn: &redb::WriteTransaction,
    path: &Path,
) -> Result<(), FinalizedIndexerError> {
    let keys = {
        let table = write_txn
            .open_table(TX_BY_HASH_TABLE)
            .map_err(|source| redb_error("open_tx_by_hash_table", path, &source))?;
        let mut keys = Vec::new();
        for row in table
            .iter()
            .map_err(|source| redb_error("iter_tx_by_hash", path, &source))?
        {
            let (key, _) =
                row.map_err(|source| redb_error("read_tx_by_hash_row", path, &source))?;
            keys.push(key.value().to_owned());
        }
        keys
    };
    let mut table = write_txn
        .open_table(TX_BY_HASH_TABLE)
        .map_err(|source| redb_error("open_tx_by_hash_table", path, &source))?;
    for key in keys {
        let _ = table
            .remove(key.as_str())
            .map_err(|source| redb_error("remove_tx_by_hash", path, &source))?;
    }
    Ok(())
}

fn clear_tx_by_sender_nonce_index(
    write_txn: &redb::WriteTransaction,
    path: &Path,
) -> Result<(), FinalizedIndexerError> {
    let keys = {
        let table = write_txn
            .open_table(TX_BY_SENDER_NONCE_TABLE)
            .map_err(|source| redb_error("open_tx_by_sender_nonce_table", path, &source))?;
        let mut keys = Vec::new();
        for row in table
            .iter()
            .map_err(|source| redb_error("iter_tx_by_sender_nonce", path, &source))?
        {
            let (key, _) =
                row.map_err(|source| redb_error("read_tx_by_sender_nonce_row", path, &source))?;
            keys.push(key.value().to_owned());
        }
        keys
    };
    let mut table = write_txn
        .open_table(TX_BY_SENDER_NONCE_TABLE)
        .map_err(|source| redb_error("open_tx_by_sender_nonce_table", path, &source))?;
    for key in keys {
        let _ = table
            .remove(key.as_str())
            .map_err(|source| redb_error("remove_tx_by_sender_nonce", path, &source))?;
    }
    Ok(())
}

fn clear_address_timeline_index(
    write_txn: &redb::WriteTransaction,
    path: &Path,
) -> Result<(), FinalizedIndexerError> {
    let keys = {
        let table = write_txn
            .open_table(TX_BY_ADDRESS_TIMELINE_TABLE)
            .map_err(|source| redb_error("open_tx_by_address_timeline_table", path, &source))?;
        let mut keys = Vec::new();
        for row in table
            .iter()
            .map_err(|source| redb_error("iter_tx_by_address_timeline", path, &source))?
        {
            let (key, _) =
                row.map_err(|source| redb_error("read_tx_by_address_timeline_row", path, &source))?;
            keys.push(key.value().to_owned());
        }
        keys
    };
    let mut table = write_txn
        .open_table(TX_BY_ADDRESS_TIMELINE_TABLE)
        .map_err(|source| redb_error("open_tx_by_address_timeline_table", path, &source))?;
    for key in keys {
        let _ = table
            .remove(key.as_str())
            .map_err(|source| redb_error("remove_tx_by_address_timeline", path, &source))?;
    }
    Ok(())
}

fn replay_events_into_indexes(
    write_txn: &redb::WriteTransaction,
    path: &Path,
) -> Result<usize, FinalizedIndexerError> {
    let first_retained = read_meta_u64(write_txn, META_KEY_FIRST_RETAINED_SEQUENCE, path)?;
    let next_event = read_meta_u64(write_txn, META_KEY_NEXT_EVENT_SEQUENCE, path)?;

    let events = {
        let event_table = write_txn
            .open_table(FINALIZED_EVENT_TABLE)
            .map_err(|source| redb_error("open_event_table", path, &source))?;
        let mut events = Vec::new();
        for row in event_table
            .range(first_retained..next_event)
            .map_err(|source| redb_error("range_events", path, &source))?
        {
            let (_, value) = row.map_err(|source| redb_error("read_event_row", path, &source))?;
            let event: FinalizedBlockEvent = decode_record(value.value())?;
            events.push(event);
        }
        events
    };

    for event in &events {
        let _ = index_block_into_secondary_tables(
            write_txn,
            &event.block,
            event.finalized_at_unix_ms,
            path,
        )?;
    }
    Ok(events.len())
}

fn compact_retention(
    write_txn: &redb::WriteTransaction,
    max_retained_blocks: usize,
    path: &Path,
) -> Result<CompactionReport, FinalizedIndexerError> {
    if max_retained_blocks == 0 {
        return Err(FinalizedIndexerError::InvalidRetentionLimit);
    }

    let first_retained = read_meta_u64(write_txn, META_KEY_FIRST_RETAINED_SEQUENCE, path)?;
    let next_event = read_meta_u64(write_txn, META_KEY_NEXT_EVENT_SEQUENCE, path)?;
    let retained_u64 = next_event.saturating_sub(first_retained);
    let retained_usize = usize::try_from(retained_u64).unwrap_or(usize::MAX);
    if retained_usize <= max_retained_blocks {
        return Ok(CompactionReport {
            compacted_events: 0,
            retained_blocks: retained_usize,
        });
    }

    let prune_count = retained_usize.saturating_sub(max_retained_blocks);
    let prune_until = first_retained.saturating_add(u64::try_from(prune_count).unwrap_or(u64::MAX));
    let old_events = collect_compacted_events(write_txn, first_retained, prune_until, path)?;
    remove_compacted_index_rows(write_txn, &old_events, path)?;
    remove_compacted_event_rows(write_txn, &old_events, path)?;

    write_meta_u64(
        write_txn,
        META_KEY_FIRST_RETAINED_SEQUENCE,
        prune_until,
        path,
    )?;
    let retained_after = next_event.saturating_sub(prune_until);
    Ok(CompactionReport {
        compacted_events: old_events.len(),
        retained_blocks: usize::try_from(retained_after).unwrap_or(usize::MAX),
    })
}

fn collect_compacted_events(
    write_txn: &redb::WriteTransaction,
    first_retained: u64,
    prune_until: u64,
    path: &Path,
) -> Result<Vec<(u64, FinalizedBlockEvent)>, FinalizedIndexerError> {
    let event_table = write_txn
        .open_table(FINALIZED_EVENT_TABLE)
        .map_err(|source| redb_error("open_event_table", path, &source))?;
    let mut events = Vec::new();
    for row in event_table
        .range(first_retained..prune_until)
        .map_err(|source| redb_error("range_events", path, &source))?
    {
        let (sequence, value) =
            row.map_err(|source| redb_error("read_event_row", path, &source))?;
        let event: FinalizedBlockEvent = decode_record(value.value())?;
        events.push((sequence.value(), event));
    }
    Ok(events)
}

fn remove_compacted_index_rows(
    write_txn: &redb::WriteTransaction,
    old_events: &[(u64, FinalizedBlockEvent)],
    path: &Path,
) -> Result<(), FinalizedIndexerError> {
    let mut block_by_height = write_txn
        .open_table(BLOCK_BY_HEIGHT_TABLE)
        .map_err(|source| redb_error("open_block_by_height_table", path, &source))?;
    let mut tx_by_hash = write_txn
        .open_table(TX_BY_HASH_TABLE)
        .map_err(|source| redb_error("open_tx_by_hash_table", path, &source))?;
    let mut tx_by_sender_nonce = write_txn
        .open_table(TX_BY_SENDER_NONCE_TABLE)
        .map_err(|source| redb_error("open_tx_by_sender_nonce_table", path, &source))?;
    let mut tx_by_timeline = write_txn
        .open_table(TX_BY_ADDRESS_TIMELINE_TABLE)
        .map_err(|source| redb_error("open_tx_by_address_timeline_table", path, &source))?;

    for (_, event) in old_events {
        let _ = block_by_height
            .remove(event.block.header.height)
            .map_err(|source| redb_error("remove_block_by_height", path, &source))?;
        for (tx_index, transaction) in event.block.transactions.iter().enumerate() {
            let tx_hash = transaction_id(transaction)
                .map_err(|source| FinalizedIndexerError::TransactionId { source })?;
            let tx_hash_hex = hex::encode(tx_hash);
            let sender_nonce_key = sender_nonce_key(&transaction.sender, transaction.nonce);
            let outgoing_key = timeline_key(
                &transaction.sender,
                event.block.header.height,
                u32::try_from(tx_index).unwrap_or(u32::MAX),
                AddressTimelineDirection::Outgoing,
                &tx_hash,
            );
            let incoming_key = timeline_key(
                &transaction.receiver,
                event.block.header.height,
                u32::try_from(tx_index).unwrap_or(u32::MAX),
                AddressTimelineDirection::Incoming,
                &tx_hash,
            );
            let _ = tx_by_hash
                .remove(tx_hash_hex.as_str())
                .map_err(|source| redb_error("remove_tx_by_hash", path, &source))?;
            let _ = tx_by_sender_nonce
                .remove(sender_nonce_key.as_str())
                .map_err(|source| redb_error("remove_tx_by_sender_nonce", path, &source))?;
            let _ = tx_by_timeline
                .remove(outgoing_key.as_str())
                .map_err(|source| redb_error("remove_tx_by_address_timeline", path, &source))?;
            let _ = tx_by_timeline
                .remove(incoming_key.as_str())
                .map_err(|source| redb_error("remove_tx_by_address_timeline", path, &source))?;
        }
    }
    Ok(())
}

fn remove_compacted_event_rows(
    write_txn: &redb::WriteTransaction,
    old_events: &[(u64, FinalizedBlockEvent)],
    path: &Path,
) -> Result<(), FinalizedIndexerError> {
    let mut event_table = write_txn
        .open_table(FINALIZED_EVENT_TABLE)
        .map_err(|source| redb_error("open_event_table", path, &source))?;
    for (sequence, _) in old_events {
        let _ = event_table
            .remove(*sequence)
            .map_err(|source| redb_error("remove_event", path, &source))?;
    }
    Ok(())
}

fn index_block_into_secondary_tables(
    write_txn: &redb::WriteTransaction,
    block: &Block,
    finalized_at_unix_ms: u64,
    path: &Path,
) -> Result<usize, FinalizedIndexerError> {
    let block_hash = block
        .hash()
        .map_err(|source| FinalizedIndexerError::BlockHash { source })?;
    let block_record = IndexedBlockRecord {
        height: block.header.height,
        block_hash,
        finalized_at_unix_ms,
        block: block.clone(),
    };
    let block_record_bytes = encode_record(&block_record)?;
    {
        let mut block_by_height = write_txn
            .open_table(BLOCK_BY_HEIGHT_TABLE)
            .map_err(|source| redb_error("open_block_by_height_table", path, &source))?;
        block_by_height
            .insert(block.header.height, block_record_bytes.as_slice())
            .map_err(|source| redb_error("insert_block_by_height", path, &source))?;
    }

    let mut tx_by_hash = write_txn
        .open_table(TX_BY_HASH_TABLE)
        .map_err(|source| redb_error("open_tx_by_hash_table", path, &source))?;
    let mut tx_by_sender_nonce = write_txn
        .open_table(TX_BY_SENDER_NONCE_TABLE)
        .map_err(|source| redb_error("open_tx_by_sender_nonce_table", path, &source))?;
    let mut tx_by_address_timeline = write_txn
        .open_table(TX_BY_ADDRESS_TIMELINE_TABLE)
        .map_err(|source| redb_error("open_tx_by_address_timeline_table", path, &source))?;

    for (tx_index, transaction) in block.transactions.iter().enumerate() {
        let tx_index_u32 = u32::try_from(tx_index).unwrap_or(u32::MAX);
        let tx_hash = transaction_id(transaction)
            .map_err(|source| FinalizedIndexerError::TransactionId { source })?;
        let tx_hash_hex = hex::encode(tx_hash);
        let tx_record = IndexedTransactionRecord {
            tx_hash,
            sender: transaction.sender.clone(),
            receiver: transaction.receiver.clone(),
            nonce: transaction.nonce,
            amount: transaction.amount,
            fee: transaction.fee,
            block_height: block.header.height,
            block_hash,
            tx_index: tx_index_u32,
            finalized_at_unix_ms,
        };
        let tx_record_bytes = encode_record(&tx_record)?;
        tx_by_hash
            .insert(tx_hash_hex.as_str(), tx_record_bytes.as_slice())
            .map_err(|source| redb_error("insert_tx_by_hash", path, &source))?;

        let sender_nonce_key = sender_nonce_key(&transaction.sender, transaction.nonce);
        tx_by_sender_nonce
            .insert(sender_nonce_key.as_str(), tx_record_bytes.as_slice())
            .map_err(|source| redb_error("insert_tx_by_sender_nonce", path, &source))?;

        let outgoing_record = IndexedAddressTimelineRecord {
            address: transaction.sender.clone(),
            direction: AddressTimelineDirection::Outgoing,
            tx_hash,
            block_height: block.header.height,
            tx_index: tx_index_u32,
            sender: transaction.sender.clone(),
            receiver: transaction.receiver.clone(),
            amount: transaction.amount,
            fee: transaction.fee,
            finalized_at_unix_ms,
        };
        let outgoing_key = timeline_key(
            &outgoing_record.address,
            outgoing_record.block_height,
            outgoing_record.tx_index,
            outgoing_record.direction,
            &tx_hash,
        );
        let outgoing_bytes = encode_record(&outgoing_record)?;
        tx_by_address_timeline
            .insert(outgoing_key.as_str(), outgoing_bytes.as_slice())
            .map_err(|source| redb_error("insert_tx_by_address_timeline", path, &source))?;

        let incoming_record = IndexedAddressTimelineRecord {
            address: transaction.receiver.clone(),
            direction: AddressTimelineDirection::Incoming,
            tx_hash,
            block_height: block.header.height,
            tx_index: tx_index_u32,
            sender: transaction.sender.clone(),
            receiver: transaction.receiver.clone(),
            amount: transaction.amount,
            fee: transaction.fee,
            finalized_at_unix_ms,
        };
        let incoming_key = timeline_key(
            &incoming_record.address,
            incoming_record.block_height,
            incoming_record.tx_index,
            incoming_record.direction,
            &tx_hash,
        );
        let incoming_bytes = encode_record(&incoming_record)?;
        tx_by_address_timeline
            .insert(incoming_key.as_str(), incoming_bytes.as_slice())
            .map_err(|source| redb_error("insert_tx_by_address_timeline", path, &source))?;
    }

    Ok(block.transactions.len())
}

fn sender_nonce_key(sender: &str, nonce: u64) -> String {
    format!("{sender}:{nonce:020}")
}

fn timeline_key(
    address: &str,
    block_height: u64,
    tx_index: u32,
    direction: AddressTimelineDirection,
    tx_hash: &[u8; 32],
) -> String {
    let direction_byte = match direction {
        AddressTimelineDirection::Outgoing => 0_u8,
        AddressTimelineDirection::Incoming => 1_u8,
    };
    format!(
        "{address}:{block_height:020}:{tx_index:010}:{direction_byte}:{}",
        hex::encode(tx_hash)
    )
}

fn encode_record<T: Serialize>(record: &T) -> Result<Vec<u8>, FinalizedIndexerError> {
    bincode::serde::encode_to_vec(
        record,
        bincode::config::standard()
            .with_fixed_int_encoding()
            .with_little_endian(),
    )
    .map_err(|_| FinalizedIndexerError::Serialization)
}

fn decode_record<T: for<'de> Deserialize<'de>>(bytes: &[u8]) -> Result<T, FinalizedIndexerError> {
    bincode::serde::decode_from_slice(
        bytes,
        bincode::config::standard()
            .with_fixed_int_encoding()
            .with_little_endian(),
    )
    .map(|(record, _)| record)
    .map_err(|_| FinalizedIndexerError::Deserialization)
}

fn redb_error(
    operation: &'static str,
    path: &Path,
    source: &impl ToString,
) -> FinalizedIndexerError {
    FinalizedIndexerError::Redb {
        operation,
        path: display_path(path),
        reason: source.to_string(),
    }
}

fn display_path(path: &Path) -> String {
    path.to_string_lossy().into_owned()
}

#[cfg(test)]
mod tests {
    use std::path::{Path, PathBuf};

    use redb::Database;

    use super::{
        FINALIZED_INDEX_FILE_NAME, FinalizedIndexer, FinalizedIndexerConfig, FinalizedIndexerPaths,
        META_KEY_INDEXED_THROUGH_SEQUENCE, META_TABLE,
    };
    use crate::core::block::{Block, BlockHeader, HASH_LENGTH};
    use crate::core::mempool::transaction_id;
    use crate::core::transaction::Transaction;
    use crate::crypto::address::Network;

    struct TestDirectory {
        path: PathBuf,
    }

    impl TestDirectory {
        fn new(prefix: &str) -> Self {
            let unique = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map_or(0_u128, |value| value.as_nanos());
            let path =
                std::env::temp_dir().join(format!("{prefix}-{}-{unique}", std::process::id()));
            let created = std::fs::create_dir_all(&path);
            assert!(created.is_ok(), "test directory should be created");
            Self { path }
        }

        fn path(&self) -> &Path {
            &self.path
        }
    }

    impl Drop for TestDirectory {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.path);
        }
    }

    fn sample_transaction(sender: &str, receiver: &str, nonce: u64, fee: u64) -> Transaction {
        Transaction::new_unsigned(sender.to_owned(), receiver.to_owned(), 10, fee, nonce, 0)
    }

    fn sample_block(height: u64, previous_hash: [u8; 32], transactions: Vec<Transaction>) -> Block {
        let state_byte = u8::try_from(height).unwrap_or(u8::MAX);
        let header = BlockHeader::new(
            height,
            previous_hash,
            [state_byte; HASH_LENGTH],
            1_700_000_000_u64.saturating_add(height),
            "HMA_VALIDATOR".to_owned(),
        );
        let block = Block::new_unsigned(header, transactions);
        assert!(block.is_ok(), "sample block should construct");
        block.unwrap_or_else(|_| unreachable!())
    }

    #[test]
    fn append_and_query_indexes_roundtrip() {
        let directory = TestDirectory::new("homa-finalized-index-roundtrip");
        let paths = FinalizedIndexerPaths::new(directory.path().to_path_buf());
        let opened = FinalizedIndexer::open(
            &paths,
            Network::Testnet,
            FinalizedIndexerConfig {
                max_retained_blocks: 8,
            },
        );
        assert!(opened.is_ok(), "indexer should open");
        let (indexer, report) = opened.unwrap_or_else(|_| unreachable!());
        assert!(!report.rebuild_performed);

        let transaction = sample_transaction("HMA_A", "HMA_B", 7, 3);
        let tx_hash = transaction_id(&transaction);
        assert!(tx_hash.is_ok(), "tx hash should compute");
        let tx_hash = tx_hash.unwrap_or_else(|_| unreachable!());

        let block = sample_block(1, [0_u8; 32], vec![transaction.clone()]);
        let appended = indexer.append_finalized_block(&block, 42_000);
        assert!(appended.is_ok(), "append should succeed");
        let appended = appended.unwrap_or_else(|_| unreachable!());
        assert_eq!(appended.indexed_transactions, 1);
        assert_eq!(appended.compacted_events, 0);

        let by_height = indexer.get_block_by_height(1);
        assert!(by_height.is_ok(), "block query should succeed");
        let by_height = by_height.unwrap_or_else(|_| unreachable!());
        assert!(by_height.is_some(), "indexed block should exist");
        let by_height = by_height.unwrap_or_else(|| unreachable!());
        assert_eq!(by_height.height, 1);
        assert_eq!(by_height.block.transactions.len(), 1);
        let block_hash = block.hash();
        assert!(block_hash.is_ok(), "block hash should compute");
        let by_block_hash =
            indexer.get_block_by_hash(&block_hash.unwrap_or_else(|_| unreachable!()));
        assert!(by_block_hash.is_ok(), "block hash query should succeed");
        assert!(
            by_block_hash.unwrap_or_else(|_| unreachable!()).is_some(),
            "indexed block should be queryable by hash"
        );

        let by_hash = indexer.get_transaction_by_hash(&tx_hash);
        assert!(by_hash.is_ok(), "tx hash query should succeed");
        let by_hash = by_hash.unwrap_or_else(|_| unreachable!());
        assert!(by_hash.is_some(), "indexed tx hash should exist");
        assert_eq!(
            by_hash.unwrap_or_else(|| unreachable!()).nonce,
            transaction.nonce
        );

        let by_sender_nonce =
            indexer.get_transaction_by_sender_nonce(&transaction.sender, transaction.nonce);
        assert!(by_sender_nonce.is_ok(), "sender+nonce query should succeed");
        let by_sender_nonce = by_sender_nonce.unwrap_or_else(|_| unreachable!());
        assert!(by_sender_nonce.is_some(), "sender+nonce index should exist");
        assert_eq!(
            by_sender_nonce.unwrap_or_else(|| unreachable!()).tx_hash,
            tx_hash
        );

        let sender_timeline = indexer.get_address_timeline(&transaction.sender, 8);
        assert!(sender_timeline.is_ok(), "sender timeline should query");
        let sender_timeline = sender_timeline.unwrap_or_else(|_| unreachable!());
        assert_eq!(sender_timeline.len(), 1);
        assert_eq!(
            sender_timeline[0].direction,
            super::AddressTimelineDirection::Outgoing
        );

        let receiver_timeline = indexer.get_address_timeline(&transaction.receiver, 8);
        assert!(receiver_timeline.is_ok(), "receiver timeline should query");
        let receiver_timeline = receiver_timeline.unwrap_or_else(|_| unreachable!());
        assert_eq!(receiver_timeline.len(), 1);
        assert_eq!(
            receiver_timeline[0].direction,
            super::AddressTimelineDirection::Incoming
        );
    }

    #[test]
    fn open_rebuilds_indexes_when_marked_out_of_sync() {
        let directory = TestDirectory::new("homa-finalized-index-rebuild");
        let paths = FinalizedIndexerPaths::new(directory.path().to_path_buf());
        let opened =
            FinalizedIndexer::open(&paths, Network::Devnet, FinalizedIndexerConfig::default());
        assert!(opened.is_ok(), "indexer should open");
        let (indexer, _) = opened.unwrap_or_else(|_| unreachable!());

        let block = sample_block(
            1,
            [0_u8; 32],
            vec![sample_transaction("HMA_S", "HMA_R", 1, 1)],
        );
        let appended = indexer.append_finalized_block(&block, 1_000);
        assert!(appended.is_ok(), "append should succeed");
        drop(indexer);

        let db = Database::open(directory.path().join(FINALIZED_INDEX_FILE_NAME));
        assert!(db.is_ok(), "db should open");
        let db = db.unwrap_or_else(|_| unreachable!());
        let write_txn = db.begin_write();
        assert!(write_txn.is_ok(), "write txn should open");
        let write_txn = write_txn.unwrap_or_else(|_| unreachable!());
        {
            let metadata = write_txn.open_table(META_TABLE);
            assert!(metadata.is_ok(), "meta table should open");
            let mut metadata = metadata.unwrap_or_else(|_| unreachable!());
            assert!(
                metadata
                    .insert(META_KEY_INDEXED_THROUGH_SEQUENCE, 0)
                    .is_ok(),
                "metadata should update"
            );
        }
        let committed = write_txn.commit();
        assert!(committed.is_ok(), "metadata tamper should commit");
        drop(db);

        let reopened =
            FinalizedIndexer::open(&paths, Network::Devnet, FinalizedIndexerConfig::default());
        assert!(reopened.is_ok(), "reopen should succeed: {reopened:?}");
        let (reopened, report) = reopened.unwrap_or_else(|_| unreachable!());
        assert!(report.rebuild_performed, "startup should rebuild indexes");
        assert_eq!(report.events_replayed, 1);
        let indexed_block = reopened.get_block_by_height(1);
        assert!(indexed_block.is_ok(), "rebuilt block index should query");
        assert!(indexed_block.unwrap_or_else(|_| unreachable!()).is_some());
    }

    #[test]
    fn retention_compaction_drops_old_segments() {
        let directory = TestDirectory::new("homa-finalized-index-retention");
        let paths = FinalizedIndexerPaths::new(directory.path().to_path_buf());
        let opened = FinalizedIndexer::open(
            &paths,
            Network::Testnet,
            FinalizedIndexerConfig {
                max_retained_blocks: 2,
            },
        );
        assert!(opened.is_ok(), "indexer should open");
        let (indexer, _) = opened.unwrap_or_else(|_| unreachable!());

        let tx1 = sample_transaction("HMA_A", "HMA_B", 1, 1);
        let tx1_hash = transaction_id(&tx1);
        assert!(tx1_hash.is_ok(), "tx hash should compute");
        let tx1_hash = tx1_hash.unwrap_or_else(|_| unreachable!());
        let block1 = sample_block(1, [0_u8; 32], vec![tx1]);
        let hash1 = block1.hash();
        assert!(hash1.is_ok(), "block hash should compute");
        let hash1 = hash1.unwrap_or_else(|_| unreachable!());

        let tx2 = sample_transaction("HMA_C", "HMA_D", 2, 1);
        let block2 = sample_block(2, hash1, vec![tx2]);
        let hash2 = block2.hash();
        assert!(hash2.is_ok(), "block hash should compute");
        let hash2 = hash2.unwrap_or_else(|_| unreachable!());

        let tx3 = sample_transaction("HMA_E", "HMA_F", 3, 1);
        let block3 = sample_block(3, hash2, vec![tx3]);

        assert!(
            indexer.append_finalized_block(&block1, 11).is_ok(),
            "append block1 should succeed"
        );
        assert!(
            indexer.append_finalized_block(&block2, 22).is_ok(),
            "append block2 should succeed"
        );
        let third = indexer.append_finalized_block(&block3, 33);
        assert!(third.is_ok(), "append block3 should succeed");
        let third = third.unwrap_or_else(|_| unreachable!());
        assert_eq!(third.compacted_events, 1);
        assert_eq!(third.retained_blocks, 2);

        let block1_query = indexer.get_block_by_height(1);
        assert!(block1_query.is_ok(), "query should succeed");
        assert!(
            block1_query.unwrap_or_else(|_| unreachable!()).is_none(),
            "old block should be compacted"
        );
        let block2_query = indexer.get_block_by_height(2);
        assert!(block2_query.is_ok(), "query should succeed");
        assert!(
            block2_query.unwrap_or_else(|_| unreachable!()).is_some(),
            "retained block should remain"
        );
        let tx1_query = indexer.get_transaction_by_hash(&tx1_hash);
        assert!(tx1_query.is_ok(), "tx query should succeed");
        assert!(
            tx1_query.unwrap_or_else(|_| unreachable!()).is_none(),
            "old tx index should be compacted with block segment"
        );
    }

    #[test]
    fn ensure_finalized_block_indexed_is_idempotent() {
        let directory = TestDirectory::new("homa-finalized-index-idempotent");
        let paths = FinalizedIndexerPaths::new(directory.path().to_path_buf());
        let opened =
            FinalizedIndexer::open(&paths, Network::Devnet, FinalizedIndexerConfig::default());
        assert!(opened.is_ok(), "indexer should open");
        let (indexer, _) = opened.unwrap_or_else(|_| unreachable!());

        let block = sample_block(
            1,
            [0_u8; 32],
            vec![sample_transaction("HMA_X", "HMA_Y", 1, 2)],
        );
        let first = indexer.ensure_finalized_block_indexed(&block, 123);
        assert!(first.is_ok(), "first ensure should succeed");
        assert!(first.unwrap_or_else(|_| unreachable!()));
        let second = indexer.ensure_finalized_block_indexed(&block, 456);
        assert!(second.is_ok(), "second ensure should succeed");
        assert!(!second.unwrap_or_else(|_| unreachable!()));

        let diagnostics = indexer.diagnostics();
        assert!(diagnostics.is_ok(), "diagnostics should query");
        let diagnostics = diagnostics.unwrap_or_else(|_| unreachable!());
        assert_eq!(diagnostics.next_event_sequence, 1);
        assert_eq!(diagnostics.retained_blocks, 1);

        let block_query = indexer.get_block_by_height(1);
        assert!(block_query.is_ok(), "query should succeed");
        let block_query = block_query.unwrap_or_else(|_| unreachable!());
        assert!(block_query.is_some(), "indexed block should exist");
        assert_eq!(
            block_query.unwrap_or_else(|| unreachable!()).height,
            1,
            "indexed record height should remain stable"
        );
    }
}
