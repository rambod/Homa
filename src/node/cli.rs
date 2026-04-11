//! Node daemon command-line interface.

use clap::{Args, Parser, Subcommand, ValueEnum};
use thiserror::Error;

use crate::core::mempool::MempoolConfig;
use crate::crypto::address::Network;
use crate::network::p2p::P2PConfig;
use crate::node::daemon::{NodeDaemon, NodeDaemonConfig, NodeDaemonError};

const DEFAULT_SEED_DOMAIN: &str = "seed1.homanetwork.io";

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
    /// Target network domain for addresses/signatures.
    #[arg(long, value_enum, default_value_t = CliNetwork::Testnet)]
    network: CliNetwork,
    /// DNS seed domain for bootstrap peer discovery.
    #[arg(long, default_value = DEFAULT_SEED_DOMAIN)]
    seed_domain: String,
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
    #[arg(long, default_value_t = 10)]
    min_pow_bits: u16,
    /// Runtime event loop tick interval in milliseconds.
    #[arg(long, default_value_t = 250)]
    event_loop_tick_ms: u64,
    /// Maximum inbound pending block queue length.
    #[arg(long, default_value_t = 512)]
    max_pending_blocks: usize,
    /// Run only a bounded number of event-loop iterations then exit.
    #[arg(long)]
    max_steps: Option<usize>,
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
    const fn into_network(self) -> Network {
        match self {
            Self::Mainnet => Network::Mainnet,
            Self::Testnet => Network::Testnet,
            Self::Devnet => Network::Devnet,
        }
    }
}

/// Errors returned by node CLI commands.
#[derive(Debug, Error)]
pub enum NodeCliError {
    /// Tokio runtime initialization failed.
    #[error("runtime initialization failed")]
    Runtime,
    /// Daemon construction or runtime operation failed.
    #[error("node daemon operation failed: {source}")]
    Daemon {
        /// Underlying daemon error.
        source: Box<NodeDaemonError>,
    },
}

async fn run_node(args: NodeRunArgs) -> Result<(), NodeCliError> {
    let network = args.network.into_network();
    let mut config = NodeDaemonConfig::for_network(network);
    config.event_loop_tick_ms = args.event_loop_tick_ms;
    config.max_pending_blocks = args.max_pending_blocks;
    config.mempool_config = MempoolConfig {
        min_pow_difficulty_bits: args.min_pow_bits,
        network,
        ..config.mempool_config
    };

    let mut daemon =
        NodeDaemon::from_genesis_with_config(config).map_err(|source| NodeCliError::Daemon {
            source: Box::new(source),
        })?;
    daemon
        .build_and_attach_swarm(P2PConfig::default())
        .map_err(|source| NodeCliError::Daemon {
            source: Box::new(source),
        })?;

    if !args.no_listen {
        daemon
            .listen_on_default_addresses()
            .map_err(|source| NodeCliError::Daemon {
                source: Box::new(source),
            })?;
    }

    if !args.no_bootstrap {
        let fallback = args
            .fallback_bootstrap
            .iter()
            .map(String::as_str)
            .collect::<Vec<_>>();
        if let Err(source) = daemon
            .bootstrap_from_seed(&args.seed_domain, &fallback)
            .await
        {
            if args.strict_bootstrap {
                return Err(NodeCliError::Daemon {
                    source: Box::new(source),
                });
            }
            eprintln!("warning: bootstrap failed (continuing): {source}");
        }
    }

    if let Some(max_steps) = args.max_steps {
        let report = daemon
            .run_event_loop_steps(max_steps)
            .await
            .map_err(|source| NodeCliError::Daemon {
                source: Box::new(source),
            })?;
        let stats = daemon.stats();
        println!(
            "node run complete: steps={max_steps} swarm_events={} gossip_messages={} maintenance_ticks={} imported_snapshots={} quarantined_snapshots={} blocked_import_events={} tx_admitted={} tx_rejected={} mempool_len={} pending_blocks={}",
            report.processed_swarm_events,
            report.processed_gossip_messages,
            report.maintenance_ticks,
            report.imported_snapshots,
            report.quarantined_snapshots,
            report.blocked_import_events,
            stats.tx_admitted_total,
            stats.tx_rejected_total,
            daemon.mempool_len(),
            daemon.pending_block_count(),
        );
        return Ok(());
    }

    println!(
        "node daemon started: network={} tick_ms={} (press Ctrl+C to stop)",
        network, args.event_loop_tick_ms
    );
    let report = daemon
        .run_until_ctrl_c()
        .await
        .map_err(|source| NodeCliError::Daemon {
            source: Box::new(source),
        })?;
    let stats = daemon.stats();
    println!(
        "node daemon stopped: swarm_events={} gossip_messages={} maintenance_ticks={} imported_snapshots={} quarantined_snapshots={} blocked_import_events={} tx_admitted={} tx_rejected={} mempool_len={} pending_blocks={}",
        report.processed_swarm_events,
        report.processed_gossip_messages,
        report.maintenance_ticks,
        report.imported_snapshots,
        report.quarantined_snapshots,
        report.blocked_import_events,
        stats.tx_admitted_total,
        stats.tx_rejected_total,
        daemon.mempool_len(),
        daemon.pending_block_count(),
    );

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
