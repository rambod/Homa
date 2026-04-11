//! Node daemon command-line interface.

use std::path::PathBuf;

use clap::{Args, Parser, Subcommand, ValueEnum};
use thiserror::Error;

use crate::core::mempool::MempoolConfig;
use crate::network::p2p::P2PConfig;
use crate::node::config::{
    NodeConfigError, NodeConfigNetwork, NodeRuntimeConfig, NodeRuntimeOverrides,
};
use crate::node::daemon::{NodeDaemon, NodeDaemonConfig, NodeDaemonError};

/// Executes node CLI parsing and dispatch.
pub fn run() -> Result<(), NodeCliError> {
    let cli = Cli::parse();
    let runtime = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
        .map_err(|_| NodeCliError::Runtime)?;

    runtime.block_on(async move {
        match cli.command {
            TopLevelCommand::Run(args) => run_node(args).await,
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
enum TopLevelCommand {
    /// Runs a long-lived node daemon event loop.
    Run(NodeRunArgs),
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
    /// Maximum inbound pending block queue length.
    #[arg(long)]
    max_pending_blocks: Option<usize>,
    /// Run only a bounded number of event-loop iterations then exit.
    #[arg(long)]
    max_steps: Option<usize>,
    /// Optional persistence directory flushed during graceful shutdown.
    #[arg(long)]
    state_directory: Option<PathBuf>,
}

#[derive(Debug, Clone, Copy, ValueEnum)]
enum CliNetwork {
    /// Main production network.
    Mainnet,
    /// Public testing network.
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
    run_daemon(&mut daemon, &runtime_config).await
}

fn daemon_config_from_runtime(runtime_config: &NodeRuntimeConfig) -> NodeDaemonConfig {
    let network = runtime_config.network();
    let mut config = NodeDaemonConfig::for_network(network);
    config.event_loop_tick_ms = runtime_config.event_loop_tick_ms;
    config.max_pending_blocks = runtime_config.max_pending_blocks;
    config.mempool_config = MempoolConfig {
        min_pow_difficulty_bits: runtime_config.min_pow_bits,
        network,
        ..config.mempool_config
    };
    config
}

fn initialize_daemon(runtime_config: &NodeRuntimeConfig) -> Result<NodeDaemon, NodeCliError> {
    let mut daemon = NodeDaemon::from_genesis_with_config(daemon_config_from_runtime(
        runtime_config,
    ))
    .map_err(|source| NodeCliError::Daemon {
        source: Box::new(source),
    })?;
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
    daemon: &mut NodeDaemon,
    runtime_config: &NodeRuntimeConfig,
) -> Result<(), NodeCliError> {
    if let Some(max_steps) = runtime_config.max_steps {
        return run_daemon_bounded(daemon, runtime_config, max_steps).await;
    }
    run_daemon_until_signal(daemon, runtime_config).await
}

async fn run_daemon_bounded(
    daemon: &mut NodeDaemon,
    runtime_config: &NodeRuntimeConfig,
    max_steps: usize,
) -> Result<(), NodeCliError> {
    let report = daemon
        .run_event_loop_steps(max_steps)
        .await
        .map_err(|source| NodeCliError::Daemon {
            source: Box::new(source),
        })?;
    flush_runtime_state_if_configured(runtime_config, daemon)?;
    print_daemon_report("node run complete", daemon, report, Some(max_steps));
    Ok(())
}

async fn run_daemon_until_signal(
    daemon: &mut NodeDaemon,
    runtime_config: &NodeRuntimeConfig,
) -> Result<(), NodeCliError> {
    println!(
        "node daemon started: network={} tick_ms={} (press Ctrl+C to stop)",
        runtime_config.network(),
        runtime_config.event_loop_tick_ms
    );
    let report = daemon
        .run_until_ctrl_c()
        .await
        .map_err(|source| NodeCliError::Daemon {
            source: Box::new(source),
        })?;
    flush_runtime_state_if_configured(runtime_config, daemon)?;
    print_daemon_report("node daemon stopped", daemon, report, None);
    Ok(())
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
            "{prefix}: steps={max_steps} swarm_events={} gossip_messages={} maintenance_ticks={} finalized_blocks={} rejected_blocks={} imported_snapshots={} quarantined_snapshots={} blocked_import_events={} tx_admitted={} tx_rejected={} blocks_finalized_total={} blocks_rejected_total={} mempool_len={} pending_blocks={}",
            report.processed_swarm_events,
            report.processed_gossip_messages,
            report.maintenance_ticks,
            report.finalized_blocks,
            report.rejected_blocks,
            report.imported_snapshots,
            report.quarantined_snapshots,
            report.blocked_import_events,
            stats.tx_admitted_total,
            stats.tx_rejected_total,
            stats.blocks_finalized_total,
            stats.block_rejected_total,
            daemon.mempool_len(),
            daemon.pending_block_count(),
        );
        return;
    }

    println!(
        "{prefix}: swarm_events={} gossip_messages={} maintenance_ticks={} finalized_blocks={} rejected_blocks={} imported_snapshots={} quarantined_snapshots={} blocked_import_events={} tx_admitted={} tx_rejected={} blocks_finalized_total={} blocks_rejected_total={} mempool_len={} pending_blocks={}",
        report.processed_swarm_events,
        report.processed_gossip_messages,
        report.maintenance_ticks,
        report.finalized_blocks,
        report.rejected_blocks,
        report.imported_snapshots,
        report.quarantined_snapshots,
        report.blocked_import_events,
        stats.tx_admitted_total,
        stats.tx_rejected_total,
        stats.blocks_finalized_total,
        stats.block_rejected_total,
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
        max_pending_blocks: args.max_pending_blocks,
        max_steps: args.max_steps,
        state_directory: args.state_directory,
    }
}

fn flush_runtime_state_if_configured(
    runtime_config: &NodeRuntimeConfig,
    daemon: &NodeDaemon,
) -> Result<(), NodeCliError> {
    if let Some(directory) = runtime_config.state_directory.as_deref() {
        let report =
            daemon
                .persist_runtime_state(directory)
                .map_err(|source| NodeCliError::Daemon {
                    source: Box::new(source),
                })?;
        println!(
            "node persistence flush: state_height={} state_bytes={} sync_checkpoint_bytes={}",
            report.state_height, report.state_snapshot_bytes, report.sync_checkpoint_bytes
        );
    }
    Ok(())
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
