//! Node daemon command-line interface.

use std::net::SocketAddr;
use std::path::Path;
use std::path::PathBuf;
use std::sync::Arc;
use std::{fs, io::Write};

use clap::{Args, Parser, Subcommand, ValueEnum};
use serde_json::json;
use thiserror::Error;
use tokio::sync::{Mutex, watch};

use crate::core::indexer::FINALIZED_INDEX_FILE_NAME;
use crate::core::mempool::MempoolConfig;
use crate::core::mempool_checkpoint::MEMPOOL_CHECKPOINT_FILE_NAME;
use crate::core::recovery::SNAPSHOT_FILE_NAME;
use crate::crypto::address::derive_address;
use crate::crypto::keys::{Keypair, SECRET_KEY_LENGTH};
use crate::network::p2p::P2PConfig;
use crate::network::sync_engine::SYNC_SESSION_CHECKPOINT_FILE_NAME;
use crate::node::config::{
    NodeConfigError, NodeConfigNetwork, NodeRuntimeConfig, NodeRuntimeOverrides,
};
use crate::node::daemon::{
    FINALIZED_BLOCK_CHECKPOINT_FILE_NAME, NodeDaemon, NodeDaemonConfig, NodeDaemonError,
    NodeEventLoopReport,
};
use crate::node::rpc::{RpcServerConfig, RpcServerError, run_rpc_server};

/// Executes node CLI parsing and dispatch.
pub fn run() -> Result<(), NodeCliError> {
    let cli = Cli::parse();
    let runtime = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
        .map_err(|_| NodeCliError::Runtime)?;

    runtime.block_on(async move {
        match cli.command {
            TopLevelCommand::Run(args) => Box::pin(run_node(args)).await,
            TopLevelCommand::Validator(args) => run_validator(args),
        }
    })
}

#[derive(Debug, Parser)]
#[command(name = "homa-node", version, about = "Homa node daemon CLI")]
struct Cli {
    #[command(subcommand)]
    command: TopLevelCommand,
}

#[derive(Debug, Subcommand)]
#[allow(clippy::large_enum_variant)]
enum TopLevelCommand {
    /// Runs a long-lived node daemon event loop.
    Run(NodeRunArgs),
    /// Runs validator/operator lifecycle commands.
    Validator(ValidatorArgs),
}

#[derive(Debug, Args)]
struct NodeRunArgs {
    /// Optional path to `node.toml` runtime config.
    #[arg(long)]
    config: Option<PathBuf>,
    /// Target network domain for addresses/signatures.
    #[arg(long, value_enum)]
    network: Option<CliNetwork>,
    /// DNS seed domain for bootstrap peer discovery.
    #[arg(long)]
    seed_domain: Option<String>,
    /// Fallback bootstrap entries (`IP`, `IP:PORT`, or full multiaddr).
    #[arg(long = "fallback-bootstrap")]
    fallback_bootstrap: Vec<String>,
    /// Do not open listen sockets.
    #[arg(long, default_value_t = false)]
    no_listen: bool,
    /// Do not resolve/dial bootstrap peers.
    #[arg(long, default_value_t = false)]
    no_bootstrap: bool,
    /// Treat bootstrap failure as fatal instead of warning-only.
    #[arg(long, default_value_t = false)]
    strict_bootstrap: bool,
    /// Mempool minimum required transaction `PoW` bits.
    #[arg(long)]
    min_pow_bits: Option<u16>,
    /// Runtime event loop tick interval in milliseconds.
    #[arg(long)]
    event_loop_tick_ms: Option<u64>,
    /// Consensus slot duration in milliseconds for leader scheduling.
    #[arg(long)]
    slot_duration_ms: Option<u64>,
    /// Maximum transactions selected while producing one local block.
    #[arg(long)]
    max_block_transactions: Option<usize>,
    /// Maximum inbound pending block queue length.
    #[arg(long)]
    max_pending_blocks: Option<usize>,
    /// Periodic mempool checkpoint flush interval in milliseconds.
    #[arg(long)]
    mempool_checkpoint_interval_ms: Option<u64>,
    /// Maximum retained finalized blocks in persistent query indexes.
    #[arg(long)]
    index_max_retained_blocks: Option<usize>,
    /// RPC listen socket (`IP:PORT`) for JSON-RPC + WS endpoints.
    #[arg(long)]
    rpc_listen_addr: Option<String>,
    /// Maximum accepted JSON-RPC request body bytes.
    #[arg(long)]
    rpc_max_body_bytes: Option<usize>,
    /// Per-IP RPC request budget per second.
    #[arg(long)]
    rpc_rate_limit_per_sec: Option<u32>,
    /// Maximum WS subscriptions allowed per connection.
    #[arg(long)]
    ws_max_subscriptions_per_conn: Option<usize>,
    /// Enable/disable strict startup coherence checks (fail closed when true).
    #[arg(long)]
    strict_recovery: Option<bool>,
    /// Force finalized-index rebuild from retained finalized events on startup.
    #[arg(long)]
    repair_index: Option<bool>,
    /// Skip mempool checkpoint ingestion during startup recovery.
    #[arg(long)]
    ignore_mempool_checkpoint: Option<bool>,
    /// Run only a bounded number of event-loop iterations then exit.
    #[arg(long)]
    max_steps: Option<usize>,
    /// Optional persistence directory flushed during graceful shutdown.
    #[arg(long)]
    state_directory: Option<PathBuf>,
    /// Optional hex-encoded 32-byte local producer secret key.
    #[arg(long)]
    producer_secret_key_hex: Option<String>,
}

#[derive(Debug, Args)]
struct ValidatorArgs {
    #[command(subcommand)]
    command: ValidatorCommand,
}

#[derive(Debug, Subcommand)]
enum ValidatorCommand {
    /// Prints validator/runtime status and persisted checkpoint inventory.
    Status(ValidatorStatusArgs),
    /// Validator key-management commands.
    Key(ValidatorKeyArgs),
    /// Snapshot export/import commands.
    Snapshot(ValidatorSnapshotArgs),
    /// Checkpoint-rotation submission/inspection commands.
    Checkpoint(ValidatorCheckpointArgs),
}

#[derive(Debug, Args)]
struct ValidatorStatusArgs {
    /// Optional path to `node.toml` runtime config.
    #[arg(long)]
    config: Option<PathBuf>,
}

#[derive(Debug, Args)]
struct ValidatorKeyArgs {
    #[command(subcommand)]
    command: ValidatorKeyCommand,
}

#[derive(Debug, Subcommand)]
enum ValidatorKeyCommand {
    /// Validates one secret key and prints derived validator address.
    Load(ValidatorKeyLoadArgs),
    /// Rotates local validator key material file under state directory.
    Rotate(ValidatorKeyRotateArgs),
}

#[derive(Debug, Args)]
struct ValidatorKeyLoadArgs {
    /// Hex-encoded 32-byte Ed25519 secret key.
    #[arg(long)]
    secret_key_hex: String,
    /// Network for address derivation.
    #[arg(long, value_enum, default_value_t = CliNetwork::Testnet)]
    network: CliNetwork,
}

#[derive(Debug, Args)]
struct ValidatorKeyRotateArgs {
    /// Node state directory where local key material file is stored.
    #[arg(long)]
    state_directory: PathBuf,
    /// New hex-encoded 32-byte Ed25519 secret key.
    #[arg(long)]
    new_secret_key_hex: String,
    /// Network for derived address reporting.
    #[arg(long, value_enum, default_value_t = CliNetwork::Testnet)]
    network: CliNetwork,
}

#[derive(Debug, Args)]
struct ValidatorSnapshotArgs {
    #[command(subcommand)]
    command: ValidatorSnapshotCommand,
}

#[derive(Debug, Subcommand)]
enum ValidatorSnapshotCommand {
    /// Exports current state snapshot file from state directory.
    Export(ValidatorSnapshotExportArgs),
    /// Imports a snapshot file into state directory.
    Import(ValidatorSnapshotImportArgs),
}

#[derive(Debug, Args)]
struct ValidatorSnapshotExportArgs {
    /// Node state directory containing snapshot files.
    #[arg(long)]
    state_directory: PathBuf,
    /// Output file path for exported snapshot bytes.
    #[arg(long)]
    output: PathBuf,
}

#[derive(Debug, Args)]
struct ValidatorSnapshotImportArgs {
    /// Node state directory destination.
    #[arg(long)]
    state_directory: PathBuf,
    /// Input snapshot file path.
    #[arg(long)]
    input: PathBuf,
}

#[derive(Debug, Args)]
struct ValidatorCheckpointArgs {
    #[command(subcommand)]
    command: ValidatorCheckpointCommand,
}

#[derive(Debug, Subcommand)]
enum ValidatorCheckpointCommand {
    /// Writes one checkpoint-rotation submission payload template.
    Submit(ValidatorCheckpointSubmitArgs),
    /// Prints stored checkpoint-rotation submission payload.
    Inspect(ValidatorCheckpointInspectArgs),
}

#[derive(Debug, Args)]
struct ValidatorCheckpointSubmitArgs {
    /// Node state directory used for operational artifacts.
    #[arg(long)]
    state_directory: PathBuf,
    /// Finalized height where new trusted set becomes active.
    #[arg(long)]
    effective_height: u64,
    /// Current finalized height used for anti-regression guard.
    #[arg(long)]
    target_height: u64,
    /// Comma-separated validator addresses included in next trusted set.
    #[arg(long, value_delimiter = ',')]
    validators: Vec<String>,
}

#[derive(Debug, Args)]
struct ValidatorCheckpointInspectArgs {
    /// Node state directory used for operational artifacts.
    #[arg(long)]
    state_directory: PathBuf,
}

#[derive(Debug, Clone, Copy, Default, ValueEnum)]
enum CliNetwork {
    /// Main production network.
    Mainnet,
    /// Public testing network.
    #[default]
    Testnet,
    /// Local developer network.
    Devnet,
}

impl CliNetwork {
    #[must_use]
    const fn into_config_network(self) -> NodeConfigNetwork {
        match self {
            Self::Mainnet => NodeConfigNetwork::Mainnet,
            Self::Testnet => NodeConfigNetwork::Testnet,
            Self::Devnet => NodeConfigNetwork::Devnet,
        }
    }
}

/// Errors returned by node CLI commands.
#[derive(Debug, Error)]
pub enum NodeCliError {
    /// Tokio runtime initialization failed.
    #[error("runtime initialization failed")]
    Runtime,
    /// Runtime config load or validation failed.
    #[error("node runtime config failed: {source}")]
    Config {
        /// Underlying config error.
        source: Box<NodeConfigError>,
    },
    /// Daemon construction or runtime operation failed.
    #[error("node daemon operation failed: {source}")]
    Daemon {
        /// Underlying daemon error.
        source: Box<NodeDaemonError>,
    },
    /// RPC server operation failed.
    #[error("node rpc operation failed: {source}")]
    Rpc {
        /// Underlying RPC server error.
        source: Box<RpcServerError>,
    },
    /// RPC task join failed.
    #[error("node rpc task join failed: {source}")]
    RpcTaskJoin {
        /// Underlying task-join error.
        source: Box<tokio::task::JoinError>,
    },
    /// Validator key material was malformed.
    #[error("validator key material failed: {reason}")]
    InvalidKeyMaterial {
        /// Human-readable key parse/validation reason.
        reason: String,
    },
    /// Local filesystem operation failed.
    #[error("filesystem operation failed ({operation}) at {path}: {source}")]
    Filesystem {
        /// Operation label.
        operation: &'static str,
        /// File path.
        path: String,
        /// Underlying I/O error.
        source: std::io::Error,
    },
}

async fn run_node(args: NodeRunArgs) -> Result<(), NodeCliError> {
    let mut runtime_config = load_runtime_config(&args)?;
    let overrides = runtime_overrides_from_args(args);
    runtime_config.apply_overrides(&overrides);
    runtime_config
        .validate()
        .map_err(|source| NodeCliError::Config {
            source: Box::new(source),
        })?;

    let mut daemon = initialize_daemon(&runtime_config)?;
    bootstrap_daemon_if_enabled(&mut daemon, &runtime_config).await?;
    run_daemon(daemon, &runtime_config).await
}

fn run_validator(args: ValidatorArgs) -> Result<(), NodeCliError> {
    match args.command {
        ValidatorCommand::Status(args) => run_validator_status(&args),
        ValidatorCommand::Key(args) => run_validator_key(&args),
        ValidatorCommand::Snapshot(args) => run_validator_snapshot(&args),
        ValidatorCommand::Checkpoint(args) => run_validator_checkpoint(&args),
    }
}

fn run_validator_status(args: &ValidatorStatusArgs) -> Result<(), NodeCliError> {
    let runtime_config = if let Some(path) = args.config.as_deref() {
        NodeRuntimeConfig::load_from_file(path).map_err(|source| NodeCliError::Config {
            source: Box::new(source),
        })?
    } else {
        NodeRuntimeConfig::default()
    };
    runtime_config
        .validate()
        .map_err(|source| NodeCliError::Config {
            source: Box::new(source),
        })?;

    println!("validator status");
    println!("  network: {}", runtime_config.network());
    println!("  rpc_listen_addr: {}", runtime_config.rpc_listen_addr);
    println!("  strict_recovery: {}", runtime_config.strict_recovery);
    println!("  repair_index: {}", runtime_config.repair_index);
    println!(
        "  ignore_mempool_checkpoint: {}",
        runtime_config.ignore_mempool_checkpoint
    );

    if let Some(directory) = runtime_config.state_directory.as_deref() {
        println!("  state_directory: {}", directory.to_string_lossy());
        let snapshot = directory.join(SNAPSHOT_FILE_NAME);
        let sync = directory.join(SYNC_SESSION_CHECKPOINT_FILE_NAME);
        let finalized = directory.join(FINALIZED_BLOCK_CHECKPOINT_FILE_NAME);
        let mempool = directory.join(MEMPOOL_CHECKPOINT_FILE_NAME);
        let index = directory.join(FINALIZED_INDEX_FILE_NAME);
        let key = directory.join(VALIDATOR_KEY_FILE_NAME);
        let checkpoint_rotation = directory.join(CHECKPOINT_ROTATION_SUBMISSION_FILE_NAME);
        print_file_presence("state_snapshot", &snapshot);
        print_file_presence("sync_checkpoint", &sync);
        print_file_presence("finalized_block_checkpoint", &finalized);
        print_file_presence("mempool_checkpoint", &mempool);
        print_file_presence("finalized_index", &index);
        print_file_presence("validator_key", &key);
        print_file_presence("checkpoint_rotation_submission", &checkpoint_rotation);
    } else {
        println!("  state_directory: <not configured>");
    }

    Ok(())
}

fn run_validator_key(args: &ValidatorKeyArgs) -> Result<(), NodeCliError> {
    match &args.command {
        ValidatorKeyCommand::Load(args) => run_validator_key_load(args),
        ValidatorKeyCommand::Rotate(args) => run_validator_key_rotate(args),
    }
}

fn run_validator_key_load(args: &ValidatorKeyLoadArgs) -> Result<(), NodeCliError> {
    let key = decode_secret_key_hex(&args.secret_key_hex)?;
    let address =
        derive_validator_address(&key, args.network.into_config_network().into_network())?;
    println!("validator key loaded");
    println!(
        "  network: {}",
        args.network.into_config_network().into_network()
    );
    println!("  validator_address: {address}");
    Ok(())
}

fn run_validator_key_rotate(args: &ValidatorKeyRotateArgs) -> Result<(), NodeCliError> {
    let key = decode_secret_key_hex(&args.new_secret_key_hex)?;
    create_directory_if_missing(&args.state_directory)?;
    let key_path = args.state_directory.join(VALIDATOR_KEY_FILE_NAME);
    write_text_file(&key_path, &args.new_secret_key_hex)?;

    let address =
        derive_validator_address(&key, args.network.into_config_network().into_network())?;
    println!("validator key rotated");
    println!("  key_path: {}", key_path.to_string_lossy());
    println!("  validator_address: {address}");
    Ok(())
}

fn run_validator_snapshot(args: &ValidatorSnapshotArgs) -> Result<(), NodeCliError> {
    match &args.command {
        ValidatorSnapshotCommand::Export(args) => run_validator_snapshot_export(args),
        ValidatorSnapshotCommand::Import(args) => run_validator_snapshot_import(args),
    }
}

fn run_validator_snapshot_export(args: &ValidatorSnapshotExportArgs) -> Result<(), NodeCliError> {
    let source = args.state_directory.join(SNAPSHOT_FILE_NAME);
    copy_file(&source, &args.output, "snapshot_export")?;
    println!("snapshot exported");
    println!("  source: {}", source.to_string_lossy());
    println!("  output: {}", args.output.to_string_lossy());
    Ok(())
}

fn run_validator_snapshot_import(args: &ValidatorSnapshotImportArgs) -> Result<(), NodeCliError> {
    create_directory_if_missing(&args.state_directory)?;
    let destination = args.state_directory.join(SNAPSHOT_FILE_NAME);
    copy_file(&args.input, &destination, "snapshot_import")?;
    println!("snapshot imported");
    println!("  input: {}", args.input.to_string_lossy());
    println!("  destination: {}", destination.to_string_lossy());
    Ok(())
}

fn run_validator_checkpoint(args: &ValidatorCheckpointArgs) -> Result<(), NodeCliError> {
    match &args.command {
        ValidatorCheckpointCommand::Submit(args) => run_validator_checkpoint_submit(args),
        ValidatorCheckpointCommand::Inspect(args) => run_validator_checkpoint_inspect(args),
    }
}

fn run_validator_checkpoint_submit(
    args: &ValidatorCheckpointSubmitArgs,
) -> Result<(), NodeCliError> {
    create_directory_if_missing(&args.state_directory)?;
    let submission_path = args
        .state_directory
        .join(CHECKPOINT_ROTATION_SUBMISSION_FILE_NAME);
    let payload = json!({
        "target_height": args.target_height,
        "effective_height": args.effective_height,
        "validators": args.validators,
        "created_at_unix_ms": now_unix_ms(),
    });
    write_text_file(&submission_path, &payload.to_string())?;
    println!("checkpoint rotation submission written");
    println!("  path: {}", submission_path.to_string_lossy());
    Ok(())
}

fn run_validator_checkpoint_inspect(
    args: &ValidatorCheckpointInspectArgs,
) -> Result<(), NodeCliError> {
    let submission_path = args
        .state_directory
        .join(CHECKPOINT_ROTATION_SUBMISSION_FILE_NAME);
    let content =
        fs::read_to_string(&submission_path).map_err(|source| NodeCliError::Filesystem {
            operation: "read",
            path: submission_path.to_string_lossy().into_owned(),
            source,
        })?;
    println!("checkpoint rotation submission");
    println!("{content}");
    Ok(())
}

const VALIDATOR_KEY_FILE_NAME: &str = "validator.key.hex";
const CHECKPOINT_ROTATION_SUBMISSION_FILE_NAME: &str = "checkpoint_rotation.submit.json";

fn print_file_presence(label: &str, path: &Path) {
    println!(
        "  {label}: {} ({})",
        path.to_string_lossy(),
        if path.exists() { "present" } else { "missing" }
    );
}

fn create_directory_if_missing(path: &Path) -> Result<(), NodeCliError> {
    fs::create_dir_all(path).map_err(|source| NodeCliError::Filesystem {
        operation: "create_dir_all",
        path: path.to_string_lossy().into_owned(),
        source,
    })
}

fn copy_file(
    source: &Path,
    destination: &Path,
    operation: &'static str,
) -> Result<(), NodeCliError> {
    let parent = destination.parent();
    if let Some(parent) = parent {
        create_directory_if_missing(parent)?;
    }
    let _ = fs::copy(source, destination).map_err(|source_error| NodeCliError::Filesystem {
        operation,
        path: format!(
            "{} -> {}",
            source.to_string_lossy(),
            destination.to_string_lossy()
        ),
        source: source_error,
    })?;
    Ok(())
}

fn write_text_file(path: &Path, content: &str) -> Result<(), NodeCliError> {
    if let Some(parent) = path.parent() {
        create_directory_if_missing(parent)?;
    }
    let mut file = fs::File::create(path).map_err(|source| NodeCliError::Filesystem {
        operation: "create",
        path: path.to_string_lossy().into_owned(),
        source,
    })?;
    file.write_all(content.as_bytes())
        .map_err(|source| NodeCliError::Filesystem {
            operation: "write_all",
            path: path.to_string_lossy().into_owned(),
            source,
        })
}

fn decode_secret_key_hex(encoded: &str) -> Result<[u8; SECRET_KEY_LENGTH], NodeCliError> {
    let decoded = hex::decode(encoded.trim()).map_err(|_| NodeCliError::InvalidKeyMaterial {
        reason: "secret key must be valid hex".to_owned(),
    })?;
    if decoded.len() != SECRET_KEY_LENGTH {
        return Err(NodeCliError::InvalidKeyMaterial {
            reason: format!(
                "secret key must decode to exactly {SECRET_KEY_LENGTH} bytes (got {})",
                decoded.len()
            ),
        });
    }
    let mut key = [0_u8; SECRET_KEY_LENGTH];
    key.copy_from_slice(&decoded);
    Ok(key)
}

fn derive_validator_address(
    key: &[u8; SECRET_KEY_LENGTH],
    network: crate::crypto::address::Network,
) -> Result<String, NodeCliError> {
    let keypair =
        Keypair::from_secret_key(key).map_err(|source| NodeCliError::InvalidKeyMaterial {
            reason: source.to_string(),
        })?;
    derive_address(&keypair.public_key_bytes(), network).map_err(|source| {
        NodeCliError::InvalidKeyMaterial {
            reason: source.to_string(),
        }
    })
}

fn now_unix_ms() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0_u64, |duration| {
            u64::try_from(duration.as_millis()).unwrap_or(u64::MAX)
        })
}

fn daemon_config_from_runtime(
    runtime_config: &NodeRuntimeConfig,
) -> Result<NodeDaemonConfig, NodeCliError> {
    let network = runtime_config.network();
    let mut config = NodeDaemonConfig::for_network(network);
    config.event_loop_tick_ms = runtime_config.event_loop_tick_ms;
    config.slot_duration_ms = runtime_config.slot_duration_ms;
    config.max_block_transactions = runtime_config.max_block_transactions;
    config.max_pending_blocks = runtime_config.max_pending_blocks;
    config.mempool_checkpoint_interval_ms = runtime_config.mempool_checkpoint_interval_ms;
    config.index_max_retained_blocks = runtime_config.index_max_retained_blocks;
    config.strict_recovery = runtime_config.strict_recovery;
    config.repair_index = runtime_config.repair_index;
    config.ignore_mempool_checkpoint = runtime_config.ignore_mempool_checkpoint;
    config.producer_secret_key = runtime_config
        .producer_secret_key_bytes()
        .map_err(|source| NodeCliError::Config {
            source: Box::new(source),
        })?;
    config.mempool_config = MempoolConfig {
        min_pow_difficulty_bits: runtime_config.min_pow_bits,
        network,
        ..config.mempool_config
    };
    Ok(config)
}

fn initialize_daemon(runtime_config: &NodeRuntimeConfig) -> Result<NodeDaemon, NodeCliError> {
    let daemon_config = daemon_config_from_runtime(runtime_config)?;
    let mut daemon = if let Some(directory) = runtime_config.state_directory.as_deref() {
        NodeDaemon::from_persisted_or_genesis(daemon_config, directory).map_err(|source| {
            NodeCliError::Daemon {
                source: Box::new(source),
            }
        })?
    } else {
        NodeDaemon::from_genesis_with_config(daemon_config).map_err(|source| {
            NodeCliError::Daemon {
                source: Box::new(source),
            }
        })?
    };
    if runtime_config.state_directory.is_some() {
        let recovery = daemon.recovery_report();
        println!(
            "node recovery: mempool_recovered={} mempool_dropped_invalid={} mempool_dropped_conflict={} index_rebuild_performed={} index_events_replayed={}",
            recovery.mempool_recovered,
            recovery.mempool_dropped_invalid,
            recovery.mempool_dropped_conflict,
            recovery.index_rebuild_performed,
            recovery.index_events_replayed,
        );
    }
    daemon
        .build_and_attach_swarm(P2PConfig::default())
        .map_err(|source| NodeCliError::Daemon {
            source: Box::new(source),
        })?;
    if runtime_config.listen {
        daemon
            .listen_on_default_addresses()
            .map_err(|source| NodeCliError::Daemon {
                source: Box::new(source),
            })?;
    }
    Ok(daemon)
}

async fn bootstrap_daemon_if_enabled(
    daemon: &mut NodeDaemon,
    runtime_config: &NodeRuntimeConfig,
) -> Result<(), NodeCliError> {
    if !runtime_config.bootstrap {
        return Ok(());
    }
    let fallback = runtime_config
        .fallback_bootstrap
        .iter()
        .map(String::as_str)
        .collect::<Vec<_>>();
    if let Err(source) = daemon
        .bootstrap_from_seed(&runtime_config.seed_domain, &fallback)
        .await
    {
        if runtime_config.strict_bootstrap {
            return Err(NodeCliError::Daemon {
                source: Box::new(source),
            });
        }
        eprintln!("warning: bootstrap failed (continuing): {source}");
    }
    Ok(())
}

async fn run_daemon(
    mut daemon: NodeDaemon,
    runtime_config: &NodeRuntimeConfig,
) -> Result<(), NodeCliError> {
    if let Some(max_steps) = runtime_config.max_steps {
        return run_daemon_bounded(&mut daemon, runtime_config, max_steps).await;
    }
    run_daemon_until_signal(daemon, runtime_config).await
}

async fn run_daemon_bounded(
    daemon: &mut NodeDaemon,
    _runtime_config: &NodeRuntimeConfig,
    max_steps: usize,
) -> Result<(), NodeCliError> {
    let report = daemon
        .run_event_loop_steps(max_steps)
        .await
        .map_err(|source| NodeCliError::Daemon {
            source: Box::new(source),
        })?;
    drain_daemon_and_report_persistence(daemon)?;
    print_daemon_report("node run complete", daemon, report, Some(max_steps));
    Ok(())
}

async fn run_daemon_until_signal(
    daemon: NodeDaemon,
    runtime_config: &NodeRuntimeConfig,
) -> Result<(), NodeCliError> {
    let rpc_config = rpc_server_config_from_runtime(runtime_config)?;
    println!(
        "node daemon started: network={} tick_ms={} slot_ms={} rpc_addr={} (press Ctrl+C to stop)",
        runtime_config.network(),
        runtime_config.event_loop_tick_ms,
        runtime_config.slot_duration_ms,
        rpc_config.listen_addr,
    );
    let shared_daemon = Arc::new(Mutex::new(daemon));
    let (shutdown_tx, shutdown_rx) = watch::channel(false);
    let rpc_state = Arc::clone(&shared_daemon);
    let mut rpc_task =
        tokio::spawn(async move { run_rpc_server(rpc_state, rpc_config, shutdown_rx).await });

    let mut report = NodeEventLoopReport::default();
    let mut ctrl_c = std::pin::pin!(tokio::signal::ctrl_c());
    loop {
        tokio::select! {
            _ = &mut ctrl_c => {
                break;
            }
            step = run_daemon_shared_step(Arc::clone(&shared_daemon)) => {
                report.absorb(step?);
            }
            rpc = &mut rpc_task => {
                return match rpc {
                    Ok(Ok(())) => Err(NodeCliError::Rpc {
                        source: Box::new(RpcServerError::Serve {
                            source: std::io::Error::other("rpc server exited unexpectedly"),
                        }),
                    }),
                    Ok(Err(source)) => Err(NodeCliError::Rpc {
                        source: Box::new(source),
                    }),
                    Err(source) => Err(NodeCliError::RpcTaskJoin {
                        source: Box::new(source),
                    }),
                };
            }
        }
    }

    let _ = shutdown_tx.send(true);
    match rpc_task.await {
        Ok(Ok(())) => {}
        Ok(Err(source)) => {
            return Err(NodeCliError::Rpc {
                source: Box::new(source),
            });
        }
        Err(source) => {
            return Err(NodeCliError::RpcTaskJoin {
                source: Box::new(source),
            });
        }
    }

    let mut daemon = shared_daemon.lock().await;
    drain_daemon_and_report_persistence(&mut daemon)?;
    print_daemon_report("node daemon stopped", &daemon, report, None);
    Ok(())
}

async fn run_daemon_shared_step(
    shared_daemon: Arc<Mutex<NodeDaemon>>,
) -> Result<NodeEventLoopReport, NodeCliError> {
    let mut daemon = shared_daemon.lock().await;
    daemon
        .run_event_loop_steps(1)
        .await
        .map_err(|source| NodeCliError::Daemon {
            source: Box::new(source),
        })
}

fn print_daemon_report(
    prefix: &str,
    daemon: &NodeDaemon,
    report: crate::node::daemon::NodeEventLoopReport,
    max_steps: Option<usize>,
) {
    let stats = daemon.stats();
    if let Some(max_steps) = max_steps {
        println!(
            "{prefix}: steps={max_steps} swarm_events={} gossip_messages={} maintenance_ticks={} finalized_blocks={} rejected_blocks={} produced_blocks={} imported_snapshots={} quarantined_snapshots={} blocked_import_events={} tx_admitted={} tx_rejected={} blocks_finalized_total={} blocks_rejected_total={} inbound_block_consensus_rejected_total={} inbound_block_duplicate_total={} blocks_produced_total={} block_publish_failure_total={} mempool_len={} pending_blocks={}",
            report.processed_swarm_events,
            report.processed_gossip_messages,
            report.maintenance_ticks,
            report.finalized_blocks,
            report.rejected_blocks,
            report.produced_blocks,
            report.imported_snapshots,
            report.quarantined_snapshots,
            report.blocked_import_events,
            stats.tx_admitted_total,
            stats.tx_rejected_total,
            stats.blocks_finalized_total,
            stats.block_rejected_total,
            stats.inbound_block_consensus_rejected_total,
            stats.inbound_block_duplicate_total,
            stats.blocks_produced_total,
            stats.block_publish_failure_total,
            daemon.mempool_len(),
            daemon.pending_block_count(),
        );
        return;
    }

    println!(
        "{prefix}: swarm_events={} gossip_messages={} maintenance_ticks={} finalized_blocks={} rejected_blocks={} produced_blocks={} imported_snapshots={} quarantined_snapshots={} blocked_import_events={} tx_admitted={} tx_rejected={} blocks_finalized_total={} blocks_rejected_total={} inbound_block_consensus_rejected_total={} inbound_block_duplicate_total={} blocks_produced_total={} block_publish_failure_total={} mempool_len={} pending_blocks={}",
        report.processed_swarm_events,
        report.processed_gossip_messages,
        report.maintenance_ticks,
        report.finalized_blocks,
        report.rejected_blocks,
        report.produced_blocks,
        report.imported_snapshots,
        report.quarantined_snapshots,
        report.blocked_import_events,
        stats.tx_admitted_total,
        stats.tx_rejected_total,
        stats.blocks_finalized_total,
        stats.block_rejected_total,
        stats.inbound_block_consensus_rejected_total,
        stats.inbound_block_duplicate_total,
        stats.blocks_produced_total,
        stats.block_publish_failure_total,
        daemon.mempool_len(),
        daemon.pending_block_count(),
    );
}

fn load_runtime_config(args: &NodeRunArgs) -> Result<NodeRuntimeConfig, NodeCliError> {
    if let Some(path) = args.config.as_deref() {
        return NodeRuntimeConfig::load_from_file(path).map_err(|source| NodeCliError::Config {
            source: Box::new(source),
        });
    }
    Ok(NodeRuntimeConfig::default())
}

fn runtime_overrides_from_args(args: NodeRunArgs) -> NodeRuntimeOverrides {
    NodeRuntimeOverrides {
        network: args.network.map(CliNetwork::into_config_network),
        seed_domain: args.seed_domain,
        fallback_bootstrap: (!args.fallback_bootstrap.is_empty())
            .then_some(args.fallback_bootstrap),
        no_listen: args.no_listen,
        no_bootstrap: args.no_bootstrap,
        strict_bootstrap: args.strict_bootstrap,
        min_pow_bits: args.min_pow_bits,
        event_loop_tick_ms: args.event_loop_tick_ms,
        slot_duration_ms: args.slot_duration_ms,
        max_block_transactions: args.max_block_transactions,
        max_pending_blocks: args.max_pending_blocks,
        mempool_checkpoint_interval_ms: args.mempool_checkpoint_interval_ms,
        index_max_retained_blocks: args.index_max_retained_blocks,
        rpc_listen_addr: args.rpc_listen_addr,
        rpc_max_body_bytes: args.rpc_max_body_bytes,
        rpc_rate_limit_per_sec: args.rpc_rate_limit_per_sec,
        ws_max_subscriptions_per_conn: args.ws_max_subscriptions_per_conn,
        strict_recovery: args.strict_recovery,
        repair_index: args.repair_index,
        ignore_mempool_checkpoint: args.ignore_mempool_checkpoint,
        max_steps: args.max_steps,
        state_directory: args.state_directory,
        producer_secret_key_hex: args.producer_secret_key_hex,
    }
}

fn drain_daemon_and_report_persistence(daemon: &mut NodeDaemon) -> Result<(), NodeCliError> {
    let persistence = daemon
        .drain_and_stop()
        .map_err(|source| NodeCliError::Daemon {
            source: Box::new(source),
        })?;
    if let Some(report) = persistence {
        println!(
            "node persistence flush: state_height={} state_bytes={} sync_checkpoint_bytes={} finalized_block_checkpoint_bytes={} mempool_checkpoint_entries={} mempool_checkpoint_bytes={} index_retained_blocks={} index_next_event_sequence={}",
            report.state_height,
            report.state_snapshot_bytes,
            report.sync_checkpoint_bytes,
            report.finalized_block_checkpoint_bytes,
            report.mempool_checkpoint_entries,
            report.mempool_checkpoint_bytes,
            report.index_retained_blocks,
            report.index_next_event_sequence,
        );
    }
    Ok(())
}

fn rpc_server_config_from_runtime(
    runtime_config: &NodeRuntimeConfig,
) -> Result<RpcServerConfig, NodeCliError> {
    let listen_addr = runtime_config
        .rpc_listen_addr
        .parse::<SocketAddr>()
        .map_err(|_| NodeCliError::Config {
            source: Box::new(NodeConfigError::InvalidRpcListenAddr {
                rpc_listen_addr: runtime_config.rpc_listen_addr.clone(),
            }),
        })?;
    Ok(RpcServerConfig {
        listen_addr,
        max_body_bytes: runtime_config.rpc_max_body_bytes,
        rate_limit_per_sec: runtime_config.rpc_rate_limit_per_sec,
        ws_max_subscriptions_per_conn: runtime_config.ws_max_subscriptions_per_conn,
    })
}

#[cfg(test)]
mod tests {
    use super::{Cli, NodeCliError, TopLevelCommand};
    use crate::node::daemon::NodeDaemonError;
    use clap::Parser;

    #[test]
    fn parses_run_command_with_step_bound() {
        let parsed = Cli::try_parse_from([
            "homa-node",
            "run",
            "--network",
            "devnet",
            "--no-bootstrap",
            "--max-steps",
            "2",
        ]);
        assert!(parsed.is_ok(), "node run args should parse");
        let parsed = parsed.unwrap_or_else(|_| unreachable!());
        assert!(
            matches!(parsed.command, TopLevelCommand::Run(_)),
            "top-level command should decode as run"
        );
    }

    #[test]
    fn parses_config_path_override() {
        let parsed = Cli::try_parse_from([
            "homa-node",
            "run",
            "--config",
            "node.toml",
            "--max-steps",
            "1",
        ]);
        assert!(parsed.is_ok(), "config flag should parse");
    }

    #[test]
    fn parses_recovery_mode_overrides() {
        let parsed = Cli::try_parse_from([
            "homa-node",
            "run",
            "--strict-recovery",
            "false",
            "--repair-index",
            "true",
            "--ignore-mempool-checkpoint",
            "true",
            "--max-steps",
            "1",
        ]);
        assert!(parsed.is_ok(), "recovery mode flags should parse");
    }

    #[test]
    fn parses_rpc_overrides() {
        let parsed = Cli::try_parse_from([
            "homa-node",
            "run",
            "--rpc-listen-addr",
            "127.0.0.1:9550",
            "--rpc-max-body-bytes",
            "65536",
            "--rpc-rate-limit-per-sec",
            "50",
            "--ws-max-subscriptions-per-conn",
            "9",
            "--max-steps",
            "1",
        ]);
        assert!(parsed.is_ok(), "rpc override flags should parse");
    }

    #[test]
    fn parses_validator_key_load_command() {
        let parsed = Cli::try_parse_from([
            "homa-node",
            "validator",
            "key",
            "load",
            "--secret-key-hex",
            "0101010101010101010101010101010101010101010101010101010101010101",
            "--network",
            "testnet",
        ]);
        assert!(parsed.is_ok(), "validator key load args should parse");
    }

    #[test]
    fn daemon_error_display_includes_source_details() {
        let error = NodeCliError::Daemon {
            source: Box::new(NodeDaemonError::MissingSwarm),
        };
        let rendered = error.to_string();
        assert!(
            rendered.contains("no attached swarm"),
            "display output should include daemon source details"
        );
    }
}
