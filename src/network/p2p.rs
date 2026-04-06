//! Libp2p swarm setup, pub/sub wiring, and seed peer resolution.

use core::fmt;
use std::net::{IpAddr, SocketAddr};
use std::str::FromStr;
use std::time::{Duration, Instant};

use futures::StreamExt;
use hickory_resolver::TokioResolver;
use libp2p::gossipsub::{
    self, ConfigBuilder as GossipsubConfigBuilder, Event as GossipsubEvent, IdentTopic,
    MessageAuthenticity, ValidationMode,
};
use libp2p::identity;
use libp2p::kad::{
    self, Behaviour as KademliaBehaviour, Event as KademliaEvent, QueryId, store::MemoryStore,
};
use libp2p::multiaddr::Protocol;
use libp2p::swarm::{NetworkBehaviour, Swarm};
use libp2p::{Multiaddr, PeerId, StreamProtocol, SwarmBuilder, noise, tcp, yamux};
use serde::{Deserialize, Serialize};
use thiserror::Error;

use crate::core::sync::SnapshotChunk;
use crate::core::transaction::{
    BorrowedTransaction, MAX_TRANSACTION_BYTES, Transaction, TransactionError,
};
use crate::observability::{GossipOperation, Observability};

/// Gossipsub topic for transaction propagation.
pub const TRANSACTIONS_TOPIC: &str = "transactions";
/// Gossipsub topic for block propagation.
pub const BLOCKS_TOPIC: &str = "blocks";
/// Gossipsub topic for snapshot chunk requests.
pub const SYNC_REQUESTS_TOPIC: &str = "sync-requests";
/// Gossipsub topic for snapshot chunk responses.
pub const SYNC_CHUNKS_TOPIC: &str = "sync-chunks";
/// Gossipsub topic for checkpoint trust-set rotation updates.
pub const CHECKPOINT_ROTATIONS_TOPIC: &str = "checkpoint-rotations";
/// Upper bound for inbound block gossip payload size in bytes.
pub const MAX_BLOCK_GOSSIP_BYTES: usize = 4 * 1024 * 1024;
/// Default TCP port used for bootstrapping when DNS only returns plain IP addresses.
pub const DEFAULT_BOOTSTRAP_TCP_PORT: u16 = 7000;
/// Default QUIC port used for bootstrapping when DNS only returns plain IP addresses.
pub const DEFAULT_BOOTSTRAP_QUIC_PORT: u16 = 7001;
/// Upper bound for sync wire message payload size.
pub const MAX_SYNC_WIRE_MESSAGE_BYTES: usize = 256 * 1024;

/// Runtime configuration for P2P stack construction.
pub struct P2PConfig {
    /// Node identity keypair.
    pub local_key: identity::Keypair,
    /// Gossipsub heartbeat interval.
    pub gossipsub_heartbeat: Duration,
    /// Upper bound for gossip message payload size.
    pub max_gossip_message_size: usize,
    /// Kademlia protocol identifier.
    pub kad_protocol_name: &'static str,
}

impl fmt::Debug for P2PConfig {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("P2PConfig")
            .field("peer_id", &PeerId::from(self.local_key.public()))
            .field("gossipsub_heartbeat", &self.gossipsub_heartbeat)
            .field("max_gossip_message_size", &self.max_gossip_message_size)
            .field("kad_protocol_name", &self.kad_protocol_name)
            .finish()
    }
}

impl Default for P2PConfig {
    fn default() -> Self {
        Self {
            local_key: identity::Keypair::generate_ed25519(),
            gossipsub_heartbeat: Duration::from_secs(1),
            max_gossip_message_size: 1_048_576,
            kad_protocol_name: "/homa/kad/1.0.0",
        }
    }
}

/// Combined libp2p behaviour for Homa nodes.
#[derive(NetworkBehaviour)]
#[behaviour(to_swarm = "HomaBehaviourEvent")]
pub struct HomaBehaviour {
    /// Pub/sub plane for transactions and blocks.
    pub gossipsub: gossipsub::Behaviour,
    /// Kademlia DHT for peer discovery.
    pub kademlia: KademliaBehaviour<MemoryStore>,
}

impl fmt::Debug for HomaBehaviour {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("HomaBehaviour")
            .finish_non_exhaustive()
    }
}

/// Unified event type emitted by [`HomaBehaviour`].
#[derive(Debug)]
pub enum HomaBehaviourEvent {
    /// Gossipsub event stream.
    Gossipsub(GossipsubEvent),
    /// Kademlia event stream.
    Kademlia(KademliaEvent),
}

impl From<GossipsubEvent> for HomaBehaviourEvent {
    fn from(value: GossipsubEvent) -> Self {
        Self::Gossipsub(value)
    }
}

impl From<KademliaEvent> for HomaBehaviourEvent {
    fn from(value: KademliaEvent) -> Self {
        Self::Kademlia(value)
    }
}

/// Network and seed-resolution errors.
#[derive(Debug, Error)]
pub enum NetworkError {
    /// Gossipsub config construction failed.
    #[error("gossipsub config initialization failed")]
    GossipsubConfig,
    /// Gossipsub behaviour initialization failed.
    #[error("gossipsub initialization failed")]
    GossipsubInit,
    /// Topic subscription failed.
    #[error("gossipsub topic subscription failed")]
    TopicSubscription,
    /// Building swarm transport/behaviour failed.
    #[error("swarm build failed")]
    SwarmBuild,
    /// DNS TXT lookup failed.
    #[error("seed DNS TXT lookup failed")]
    SeedLookup,
    /// DNS record contained no usable addresses and no fallback succeeded.
    #[error("no bootstrap addresses resolved")]
    EmptyBootstrapSet,
    /// Provided address token could not be parsed.
    #[error("invalid bootstrap address token: {0}")]
    InvalidBootstrapToken(String),
    /// Could not extract peer id from bootstrap multiaddr.
    #[error("bootstrap multiaddr missing /p2p/<peer-id>: {0}")]
    MissingPeerId(String),
    /// Kademlia bootstrap failed because the routing table has no known peers.
    #[error("kademlia bootstrap requires at least one known peer")]
    NoKnownPeers,
    /// Node failed to open local listen address.
    #[error("failed to open local listen address")]
    ListenAddress,
    /// Dialing a bootstrap address failed.
    #[error("failed to dial bootstrap address: {0}")]
    DialAddress(String),
    /// Gossipsub publish failed.
    #[error("gossipsub publish failed")]
    Publish,
    /// Broadcast timed out before successful publish.
    #[error("transaction broadcast timed out")]
    BroadcastTimeout,
    /// Payload is larger than accepted transaction gossip frame size.
    #[error("transaction gossip payload exceeds max size: {actual} > {max}")]
    TransactionPayloadTooLarge {
        /// Received payload byte length.
        actual: usize,
        /// Maximum accepted payload length.
        max: usize,
    },
    /// Block payload is larger than accepted gossip frame size.
    #[error("block gossip payload exceeds max size: {actual} > {max}")]
    BlockPayloadTooLarge {
        /// Received payload byte length.
        actual: usize,
        /// Maximum accepted payload length.
        max: usize,
    },
    /// Transaction payload from gossip could not be decoded.
    #[error("malformed transaction gossip payload")]
    MalformedTransactionPayload {
        /// Inner transaction decoding error.
        source: TransactionError,
    },
    /// Sync payload is larger than accepted wire frame size.
    #[error("sync payload exceeds max size: {actual} > {max}")]
    SyncPayloadTooLarge {
        /// Received payload byte length.
        actual: usize,
        /// Maximum accepted payload length.
        max: usize,
    },
    /// Sync payload from gossip could not be decoded.
    #[error("malformed sync wire payload")]
    MalformedSyncPayload,
    /// Decoded sync message variant does not match expected type.
    #[error("unexpected sync message kind: expected {expected}, got {actual}")]
    UnexpectedSyncMessageKind {
        /// Expected variant name.
        expected: &'static str,
        /// Actual variant name.
        actual: &'static str,
    },
}

/// Summary of a best-effort broadcast attempt.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct BroadcastReport {
    /// Number of dial attempts performed.
    pub dial_attempts: usize,
    /// Number of publish attempts performed.
    pub publish_attempts: usize,
}

/// Request envelope for one snapshot chunk.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct SnapshotChunkRequest {
    /// Caller-provided request correlation id.
    pub request_id: u64,
    /// Snapshot block height being requested.
    pub block_height: u64,
    /// Snapshot state root being requested.
    pub state_root: [u8; 32],
    /// Hash of full snapshot payload.
    pub snapshot_hash: [u8; 32],
    /// Zero-based chunk index requested.
    pub chunk_index: u32,
    /// Total chunk count expected for this snapshot.
    pub total_chunks: u32,
}

/// Response envelope carrying one requested snapshot chunk.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SnapshotChunkResponse {
    /// Request correlation id copied from [`SnapshotChunkRequest`].
    pub request_id: u64,
    /// Returned chunk payload.
    pub chunk: SnapshotChunk,
}

/// Typed sync wire message used over request/chunk sync topics.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum SyncWireMessage {
    /// Request one chunk for a known snapshot root.
    SnapshotChunkRequest(SnapshotChunkRequest),
    /// Response with one snapshot chunk payload.
    SnapshotChunkResponse(SnapshotChunkResponse),
}

impl SyncWireMessage {
    const fn kind_name(&self) -> &'static str {
        match self {
            Self::SnapshotChunkRequest(_) => "snapshot_chunk_request",
            Self::SnapshotChunkResponse(_) => "snapshot_chunk_response",
        }
    }
}

/// Builds a production transport stack with TCP+QUIC and wires gossipsub+kademlia.
pub fn build_swarm(config: P2PConfig) -> Result<Swarm<HomaBehaviour>, NetworkError> {
    let swarm = SwarmBuilder::with_existing_identity(config.local_key)
        .with_tokio()
        .with_tcp(
            tcp::Config::default().nodelay(true),
            noise::Config::new,
            yamux::Config::default,
        )
        .map_err(|_| NetworkError::SwarmBuild)?
        .with_quic()
        .with_behaviour(|local_key| {
            let gossip_config = GossipsubConfigBuilder::default()
                .heartbeat_interval(config.gossipsub_heartbeat)
                .validation_mode(ValidationMode::Strict)
                .max_transmit_size(config.max_gossip_message_size)
                .build()
                .map_err(|_| NetworkError::GossipsubConfig)?;

            let mut gossipsub = gossipsub::Behaviour::new(
                MessageAuthenticity::Signed(local_key.clone()),
                gossip_config,
            )
            .map_err(|_| NetworkError::GossipsubInit)?;

            gossipsub
                .subscribe(&IdentTopic::new(TRANSACTIONS_TOPIC))
                .map_err(|_| NetworkError::TopicSubscription)?;
            gossipsub
                .subscribe(&IdentTopic::new(BLOCKS_TOPIC))
                .map_err(|_| NetworkError::TopicSubscription)?;
            gossipsub
                .subscribe(&IdentTopic::new(SYNC_REQUESTS_TOPIC))
                .map_err(|_| NetworkError::TopicSubscription)?;
            gossipsub
                .subscribe(&IdentTopic::new(SYNC_CHUNKS_TOPIC))
                .map_err(|_| NetworkError::TopicSubscription)?;
            gossipsub
                .subscribe(&IdentTopic::new(CHECKPOINT_ROTATIONS_TOPIC))
                .map_err(|_| NetworkError::TopicSubscription)?;

            let local_peer_id = PeerId::from(local_key.public());
            let kademlia_config = kad::Config::new(StreamProtocol::new(config.kad_protocol_name));
            let kademlia = KademliaBehaviour::with_config(
                local_peer_id,
                MemoryStore::new(local_peer_id),
                kademlia_config,
            );

            Ok(HomaBehaviour {
                gossipsub,
                kademlia,
            })
        })
        .map_err(|_| NetworkError::SwarmBuild)?
        .build();

    Ok(swarm)
}

/// Returns canonical topic descriptor for transaction gossip.
#[must_use]
pub fn transactions_topic() -> IdentTopic {
    IdentTopic::new(TRANSACTIONS_TOPIC)
}

/// Returns canonical topic descriptor for block gossip.
#[must_use]
pub fn blocks_topic() -> IdentTopic {
    IdentTopic::new(BLOCKS_TOPIC)
}

/// Returns canonical topic descriptor for snapshot chunk requests.
#[must_use]
pub fn sync_requests_topic() -> IdentTopic {
    IdentTopic::new(SYNC_REQUESTS_TOPIC)
}

/// Returns canonical topic descriptor for snapshot chunk responses.
#[must_use]
pub fn sync_chunks_topic() -> IdentTopic {
    IdentTopic::new(SYNC_CHUNKS_TOPIC)
}

/// Returns canonical topic descriptor for checkpoint trust-set rotations.
#[must_use]
pub fn checkpoint_rotations_topic() -> IdentTopic {
    IdentTopic::new(CHECKPOINT_ROTATIONS_TOPIC)
}

/// Decodes a transaction payload received from gossipsub.
///
/// This function acts as a hardened boundary between untrusted network bytes and
/// in-process transaction handling code.
pub fn decode_transaction_gossip_payload(payload: &[u8]) -> Result<Transaction, NetworkError> {
    decode_transaction_gossip_payload_zero_copy(payload).map(BorrowedTransaction::into_owned)
}

/// Decodes a transaction payload received from gossipsub into a borrowed
/// zero-copy view.
///
/// Callers can inspect fields directly from the original payload buffer and
/// materialize an owned [`Transaction`] only when needed.
pub fn decode_transaction_gossip_payload_zero_copy(
    payload: &[u8],
) -> Result<BorrowedTransaction<'_>, NetworkError> {
    if payload.len() > MAX_TRANSACTION_BYTES {
        return Err(NetworkError::TransactionPayloadTooLarge {
            actual: payload.len(),
            max: MAX_TRANSACTION_BYTES,
        });
    }

    Transaction::decode_borrowed(payload)
        .map_err(|source| NetworkError::MalformedTransactionPayload { source })
}

/// Validates bounded size for inbound block gossip payload bytes.
pub const fn validate_block_gossip_payload_bounds(payload: &[u8]) -> Result<(), NetworkError> {
    if payload.len() > MAX_BLOCK_GOSSIP_BYTES {
        return Err(NetworkError::BlockPayloadTooLarge {
            actual: payload.len(),
            max: MAX_BLOCK_GOSSIP_BYTES,
        });
    }
    Ok(())
}

/// Encodes a typed sync wire message into compact binary payload bytes.
pub fn encode_sync_wire_message(message: &SyncWireMessage) -> Result<Vec<u8>, NetworkError> {
    let bytes = bincode::serde::encode_to_vec(
        message,
        bincode::config::standard()
            .with_fixed_int_encoding()
            .with_little_endian(),
    )
    .map_err(|_| NetworkError::MalformedSyncPayload)?;
    if bytes.len() > MAX_SYNC_WIRE_MESSAGE_BYTES {
        return Err(NetworkError::SyncPayloadTooLarge {
            actual: bytes.len(),
            max: MAX_SYNC_WIRE_MESSAGE_BYTES,
        });
    }
    Ok(bytes)
}

/// Decodes a typed sync wire message from compact binary payload bytes.
pub fn decode_sync_wire_message(payload: &[u8]) -> Result<SyncWireMessage, NetworkError> {
    if payload.len() > MAX_SYNC_WIRE_MESSAGE_BYTES {
        return Err(NetworkError::SyncPayloadTooLarge {
            actual: payload.len(),
            max: MAX_SYNC_WIRE_MESSAGE_BYTES,
        });
    }

    bincode::serde::decode_from_slice(
        payload,
        bincode::config::standard()
            .with_fixed_int_encoding()
            .with_little_endian(),
    )
    .map(|(message, _)| message)
    .map_err(|_| NetworkError::MalformedSyncPayload)
}

/// Encodes a chunk request into sync wire bytes.
pub fn encode_snapshot_chunk_request(
    request: SnapshotChunkRequest,
) -> Result<Vec<u8>, NetworkError> {
    encode_sync_wire_message(&SyncWireMessage::SnapshotChunkRequest(request))
}

/// Decodes and extracts a chunk request from sync wire bytes.
pub fn decode_snapshot_chunk_request(payload: &[u8]) -> Result<SnapshotChunkRequest, NetworkError> {
    let message = decode_sync_wire_message(payload)?;
    let actual = message.kind_name();
    match message {
        SyncWireMessage::SnapshotChunkRequest(request) => Ok(request),
        SyncWireMessage::SnapshotChunkResponse(_) => Err(NetworkError::UnexpectedSyncMessageKind {
            expected: "snapshot_chunk_request",
            actual,
        }),
    }
}

/// Encodes a chunk response into sync wire bytes.
pub fn encode_snapshot_chunk_response(
    response: SnapshotChunkResponse,
) -> Result<Vec<u8>, NetworkError> {
    encode_sync_wire_message(&SyncWireMessage::SnapshotChunkResponse(response))
}

/// Decodes and extracts a chunk response from sync wire bytes.
pub fn decode_snapshot_chunk_response(
    payload: &[u8],
) -> Result<SnapshotChunkResponse, NetworkError> {
    let message = decode_sync_wire_message(payload)?;
    let actual = message.kind_name();
    match message {
        SyncWireMessage::SnapshotChunkResponse(response) => Ok(response),
        SyncWireMessage::SnapshotChunkRequest(_) => Err(NetworkError::UnexpectedSyncMessageKind {
            expected: "snapshot_chunk_response",
            actual,
        }),
    }
}

/// Adds a known bootstrap peer to Kademlia and returns its peer id.
pub fn add_kademlia_address(
    swarm: &mut Swarm<HomaBehaviour>,
    address_with_peer: Multiaddr,
) -> Result<PeerId, NetworkError> {
    let (peer_id, base_address) = split_peer_id(address_with_peer)?;
    swarm
        .behaviour_mut()
        .kademlia
        .add_address(&peer_id, base_address);
    Ok(peer_id)
}

/// Starts DHT bootstrap after at least one known peer was added.
pub fn bootstrap_dht(swarm: &mut Swarm<HomaBehaviour>) -> Result<QueryId, NetworkError> {
    swarm
        .behaviour_mut()
        .kademlia
        .bootstrap()
        .map_err(|_| NetworkError::NoKnownPeers)
}

/// Broadcasts encoded transaction bytes over gossipsub with best-effort dialing.
pub async fn broadcast_transaction_bytes(
    payload: Vec<u8>,
    seed_domain: &str,
    fallback_tokens: &[&str],
    timeout: Duration,
) -> Result<BroadcastReport, NetworkError> {
    broadcast_transaction_bytes_with_observability(
        payload,
        seed_domain,
        fallback_tokens,
        timeout,
        None,
    )
    .await
}

fn record_gossip_failure(
    observability: Option<&Observability>,
    operation: GossipOperation,
    error: &str,
) {
    if let Some(metrics) = observability {
        metrics.record_gossip_failure(TRANSACTIONS_TOPIC, operation, None, error);
    }
}

async fn resolve_bootstrap_addresses_with_observability(
    seed_domain: &str,
    fallback_tokens: &[&str],
    observability: Option<&Observability>,
) -> Result<Vec<Multiaddr>, NetworkError> {
    match resolve_bootstrap_addresses(
        seed_domain,
        fallback_tokens,
        DEFAULT_BOOTSTRAP_TCP_PORT,
        DEFAULT_BOOTSTRAP_QUIC_PORT,
    )
    .await
    {
        Ok(addresses) => Ok(addresses),
        Err(error) => {
            record_gossip_failure(
                observability,
                GossipOperation::Bootstrap,
                &error.to_string(),
            );
            Err(error)
        }
    }
}

fn dial_bootstrap_addresses_with_observability(
    swarm: &mut Swarm<HomaBehaviour>,
    bootstrap_addresses: Vec<Multiaddr>,
    observability: Option<&Observability>,
) -> Result<(usize, bool), NetworkError> {
    let mut dial_attempts = 0_usize;
    let mut has_kademlia_seed = false;

    for address in bootstrap_addresses {
        dial_attempts = dial_attempts.saturating_add(1);
        if add_kademlia_address(swarm, address.clone()).is_ok() {
            has_kademlia_seed = true;
        }
        if swarm.dial(address.clone()).is_err() {
            let rendered = address.to_string();
            record_gossip_failure(observability, GossipOperation::Dial, &rendered);
            return Err(NetworkError::DialAddress(rendered));
        }
    }

    Ok((dial_attempts, has_kademlia_seed))
}

/// Broadcasts encoded transaction bytes over gossipsub and records structured failures.
pub async fn broadcast_transaction_bytes_with_observability(
    payload: Vec<u8>,
    seed_domain: &str,
    fallback_tokens: &[&str],
    timeout: Duration,
    observability: Option<&Observability>,
) -> Result<BroadcastReport, NetworkError> {
    let mut swarm = build_swarm(P2PConfig::default())?;

    let tcp_listen_address =
        Multiaddr::from_str("/ip4/0.0.0.0/tcp/0").map_err(|_| NetworkError::ListenAddress)?;
    let quic_listen_address = Multiaddr::from_str("/ip4/0.0.0.0/udp/0/quic-v1")
        .map_err(|_| NetworkError::ListenAddress)?;
    swarm
        .listen_on(tcp_listen_address)
        .map_err(|_| NetworkError::ListenAddress)?;
    swarm
        .listen_on(quic_listen_address)
        .map_err(|_| NetworkError::ListenAddress)?;

    let bootstrap_addresses =
        resolve_bootstrap_addresses_with_observability(seed_domain, fallback_tokens, observability)
            .await?;

    let (dial_attempts, has_kademlia_seed) = dial_bootstrap_addresses_with_observability(
        &mut swarm,
        bootstrap_addresses,
        observability,
    )?;

    if has_kademlia_seed {
        let _ = bootstrap_dht(&mut swarm);
    }

    let topic = transactions_topic();
    let start = Instant::now();
    let mut publish_attempts = 0_usize;

    loop {
        publish_attempts = publish_attempts.saturating_add(1);
        match swarm
            .behaviour_mut()
            .gossipsub
            .publish(topic.clone(), payload.clone())
        {
            Ok(_) => {
                return Ok(BroadcastReport {
                    dial_attempts,
                    publish_attempts,
                });
            }
            Err(gossipsub::PublishError::NoPeersSubscribedToTopic) => {}
            Err(error) => {
                record_gossip_failure(observability, GossipOperation::Publish, &error.to_string());
                return Err(NetworkError::Publish);
            }
        }

        if start.elapsed() >= timeout {
            record_gossip_failure(observability, GossipOperation::Publish, "broadcast timeout");
            return Err(NetworkError::BroadcastTimeout);
        }

        let remaining = timeout.saturating_sub(start.elapsed());
        let step = remaining.min(Duration::from_millis(200));
        let _ = tokio::time::timeout(step, swarm.next()).await;
    }
}

/// Resolves bootstrap seed peers via DNS TXT records.
///
/// If DNS lookup yields no usable addresses, falls back to the provided `fallback_tokens`.
pub async fn resolve_bootstrap_addresses(
    seed_domain: &str,
    fallback_tokens: &[&str],
    tcp_port: u16,
    quic_port: u16,
) -> Result<Vec<Multiaddr>, NetworkError> {
    let resolved_from_dns = resolve_dns_txt_tokens(seed_domain)
        .await
        .unwrap_or_default();
    let mut addresses = tokens_to_multiaddrs(&resolved_from_dns, tcp_port, quic_port)?;

    if addresses.is_empty() {
        addresses = tokens_to_multiaddrs(fallback_tokens, tcp_port, quic_port)?;
    }

    if addresses.is_empty() {
        return Err(NetworkError::EmptyBootstrapSet);
    }

    dedupe_multiaddrs(addresses)
}

async fn resolve_dns_txt_tokens(seed_domain: &str) -> Result<Vec<String>, NetworkError> {
    let resolver = TokioResolver::builder_tokio()
        .map_err(|_| NetworkError::SeedLookup)?
        .build();

    let response = resolver
        .txt_lookup(seed_domain)
        .await
        .map_err(|_| NetworkError::SeedLookup)?;

    let tokens = response
        .iter()
        .flat_map(|txt| txt.txt_data().iter())
        .filter_map(|bytes| std::str::from_utf8(bytes).ok())
        .flat_map(split_txt_payload)
        .collect::<Vec<_>>();

    Ok(tokens)
}

fn split_txt_payload(payload: &str) -> Vec<String> {
    payload
        .split([' ', ',', ';', '\n', '\t'])
        .filter(|entry| !entry.trim().is_empty())
        .map(str::trim)
        .map(str::to_owned)
        .collect()
}

fn tokens_to_multiaddrs(
    tokens: &[impl AsRef<str>],
    tcp_port: u16,
    quic_port: u16,
) -> Result<Vec<Multiaddr>, NetworkError> {
    let mut output = Vec::new();

    for token in tokens {
        let normalized = token.as_ref().trim();
        if normalized.is_empty() {
            continue;
        }

        if normalized.starts_with('/') {
            let multiaddr = Multiaddr::from_str(normalized)
                .map_err(|_| NetworkError::InvalidBootstrapToken(normalized.to_owned()))?;
            output.push(multiaddr);
            continue;
        }

        if let Ok(socket_addr) = SocketAddr::from_str(normalized) {
            output.push(socket_to_tcp_multiaddr(socket_addr));
            continue;
        }

        if let Ok(ip_address) = IpAddr::from_str(normalized) {
            output.extend(ip_to_default_multiaddrs(ip_address, tcp_port, quic_port));
            continue;
        }

        return Err(NetworkError::InvalidBootstrapToken(normalized.to_owned()));
    }

    Ok(output)
}

fn socket_to_tcp_multiaddr(address: SocketAddr) -> Multiaddr {
    match address.ip() {
        IpAddr::V4(ipv4) => Multiaddr::empty()
            .with(Protocol::Ip4(ipv4))
            .with(Protocol::Tcp(address.port())),
        IpAddr::V6(ipv6) => Multiaddr::empty()
            .with(Protocol::Ip6(ipv6))
            .with(Protocol::Tcp(address.port())),
    }
}

fn ip_to_default_multiaddrs(ip_address: IpAddr, tcp_port: u16, quic_port: u16) -> [Multiaddr; 2] {
    match ip_address {
        IpAddr::V4(ipv4) => [
            Multiaddr::empty()
                .with(Protocol::Ip4(ipv4))
                .with(Protocol::Tcp(tcp_port)),
            Multiaddr::empty()
                .with(Protocol::Ip4(ipv4))
                .with(Protocol::Udp(quic_port))
                .with(Protocol::QuicV1),
        ],
        IpAddr::V6(ipv6) => [
            Multiaddr::empty()
                .with(Protocol::Ip6(ipv6))
                .with(Protocol::Tcp(tcp_port)),
            Multiaddr::empty()
                .with(Protocol::Ip6(ipv6))
                .with(Protocol::Udp(quic_port))
                .with(Protocol::QuicV1),
        ],
    }
}

fn dedupe_multiaddrs(addresses: Vec<Multiaddr>) -> Result<Vec<Multiaddr>, NetworkError> {
    let mut deduped = Vec::new();
    let mut seen = std::collections::BTreeSet::new();

    for address in addresses {
        let encoded = address.to_string();
        if seen.insert(encoded) {
            deduped.push(address);
        }
    }

    if deduped.is_empty() {
        return Err(NetworkError::EmptyBootstrapSet);
    }

    Ok(deduped)
}

fn split_peer_id(mut address: Multiaddr) -> Result<(PeerId, Multiaddr), NetworkError> {
    let last = address
        .pop()
        .ok_or_else(|| NetworkError::MissingPeerId(address.to_string()))?;

    match last {
        Protocol::P2p(peer_id) => Ok((peer_id, address)),
        _ => Err(NetworkError::MissingPeerId(address.to_string())),
    }
}

#[cfg(test)]
mod tests {
    use super::{
        DEFAULT_BOOTSTRAP_QUIC_PORT, DEFAULT_BOOTSTRAP_TCP_PORT, MAX_BLOCK_GOSSIP_BYTES,
        MAX_SYNC_WIRE_MESSAGE_BYTES, NetworkError, P2PConfig, SnapshotChunkRequest,
        SnapshotChunkResponse, add_kademlia_address, blocks_topic,
        broadcast_transaction_bytes_with_observability, build_swarm, checkpoint_rotations_topic,
        decode_snapshot_chunk_request, decode_snapshot_chunk_response, decode_sync_wire_message,
        decode_transaction_gossip_payload, decode_transaction_gossip_payload_zero_copy,
        dedupe_multiaddrs, encode_snapshot_chunk_request, encode_snapshot_chunk_response,
        ip_to_default_multiaddrs, resolve_bootstrap_addresses, split_txt_payload,
        sync_chunks_topic, sync_requests_topic, tokens_to_multiaddrs, transactions_topic,
        validate_block_gossip_payload_bounds,
    };
    use crate::core::state::AccountState;
    use crate::core::sync::{SnapshotAccount, StateSnapshot, split_snapshot_into_chunks};
    use crate::core::transaction::Transaction;
    use crate::observability::Observability;
    use libp2p::Multiaddr;
    use std::str::FromStr;
    use std::time::Duration;

    fn sample_sync_chunk() -> crate::core::sync::SnapshotChunk {
        let snapshot = StateSnapshot {
            block_height: 44,
            state_root: [7_u8; 32],
            accounts: vec![
                SnapshotAccount {
                    address: "HMA_SYNC_A".to_owned(),
                    state: AccountState {
                        balance: 11,
                        nonce: 1,
                    },
                },
                SnapshotAccount {
                    address: "HMA_SYNC_B".to_owned(),
                    state: AccountState {
                        balance: 99,
                        nonce: 0,
                    },
                },
            ],
        };
        let chunks = split_snapshot_into_chunks(&snapshot, 24);
        assert!(chunks.is_ok(), "snapshot chunk split should succeed");
        let mut chunks = chunks.unwrap_or_else(|_| unreachable!());
        assert!(
            !chunks.is_empty(),
            "chunk split should yield at least one chunk"
        );
        chunks.remove(0)
    }

    #[test]
    fn parses_txt_payload_tokens() {
        let parsed = split_txt_payload("1.1.1.1, 2.2.2.2; /ip4/3.3.3.3/tcp/7000");
        assert_eq!(parsed.len(), 3);
        assert_eq!(parsed[0], "1.1.1.1");
        assert_eq!(parsed[1], "2.2.2.2");
        assert_eq!(parsed[2], "/ip4/3.3.3.3/tcp/7000");
    }

    #[test]
    fn converts_ip_token_to_tcp_and_quic_multiaddrs() {
        let converted = tokens_to_multiaddrs(&["127.0.0.1"], 7000, 7001);
        assert!(converted.is_ok(), "conversion should succeed");
        let converted = converted.unwrap_or_else(|_| unreachable!());

        assert_eq!(converted.len(), 2);
        assert!(
            converted
                .iter()
                .any(|entry| entry.to_string() == "/ip4/127.0.0.1/tcp/7000")
        );
        assert!(
            converted
                .iter()
                .any(|entry| entry.to_string() == "/ip4/127.0.0.1/udp/7001/quic-v1")
        );
    }

    #[test]
    fn dedupes_multiaddrs_stably() {
        let a = Multiaddr::from_str("/ip4/127.0.0.1/tcp/7000");
        let b = Multiaddr::from_str("/ip4/127.0.0.1/tcp/7000");
        assert!(a.is_ok(), "a should parse");
        assert!(b.is_ok(), "b should parse");
        let deduped = dedupe_multiaddrs(vec![
            a.unwrap_or_else(|_| unreachable!()),
            b.unwrap_or_else(|_| unreachable!()),
        ]);
        assert!(deduped.is_ok(), "dedupe should succeed");
        assert_eq!(deduped.unwrap_or_else(|_| unreachable!()).len(), 1);
    }

    #[test]
    fn topic_helpers_match_expected_names() {
        assert_eq!(transactions_topic().to_string(), "transactions");
        assert_eq!(blocks_topic().to_string(), "blocks");
        assert_eq!(sync_requests_topic().to_string(), "sync-requests");
        assert_eq!(sync_chunks_topic().to_string(), "sync-chunks");
        assert_eq!(
            checkpoint_rotations_topic().to_string(),
            "checkpoint-rotations"
        );
    }

    #[test]
    fn snapshot_chunk_request_roundtrip_over_sync_wire() {
        let request = SnapshotChunkRequest {
            request_id: 7,
            block_height: 44,
            state_root: [3_u8; 32],
            snapshot_hash: [9_u8; 32],
            chunk_index: 1,
            total_chunks: 5,
        };
        let encoded = encode_snapshot_chunk_request(request);
        assert!(encoded.is_ok(), "sync request encode should succeed");

        let decoded = decode_snapshot_chunk_request(&encoded.unwrap_or_else(|_| unreachable!()));
        assert!(decoded.is_ok(), "sync request decode should succeed");
        assert_eq!(
            decoded.unwrap_or_else(|_| unreachable!()),
            request,
            "decoded request should match encoded request payload"
        );
    }

    #[test]
    fn snapshot_chunk_response_roundtrip_over_sync_wire() {
        let response = SnapshotChunkResponse {
            request_id: 22,
            chunk: sample_sync_chunk(),
        };
        let encoded = encode_snapshot_chunk_response(response.clone());
        assert!(encoded.is_ok(), "sync response encode should succeed");

        let decoded = decode_snapshot_chunk_response(&encoded.unwrap_or_else(|_| unreachable!()));
        assert!(decoded.is_ok(), "sync response decode should succeed");
        assert_eq!(
            decoded.unwrap_or_else(|_| unreachable!()),
            response,
            "decoded response should match encoded response payload"
        );
    }

    #[test]
    fn snapshot_chunk_decode_rejects_wrong_sync_variant() {
        let request = SnapshotChunkRequest {
            request_id: 99,
            block_height: 50,
            state_root: [4_u8; 32],
            snapshot_hash: [6_u8; 32],
            chunk_index: 0,
            total_chunks: 1,
        };
        let encoded = encode_snapshot_chunk_request(request);
        assert!(encoded.is_ok(), "sync request encode should succeed");

        let decoded = decode_snapshot_chunk_response(&encoded.unwrap_or_else(|_| unreachable!()));
        assert!(
            matches!(
                decoded,
                Err(NetworkError::UnexpectedSyncMessageKind {
                    expected: "snapshot_chunk_response",
                    actual: "snapshot_chunk_request"
                })
            ),
            "typed sync decoder should reject payloads from wrong variant"
        );
    }

    #[test]
    fn oversized_sync_payload_is_rejected_before_decode() {
        let payload = vec![0_u8; MAX_SYNC_WIRE_MESSAGE_BYTES + 1];
        let decoded = decode_sync_wire_message(&payload);
        assert!(
            matches!(
                decoded,
                Err(NetworkError::SyncPayloadTooLarge {
                    actual: _,
                    max: MAX_SYNC_WIRE_MESSAGE_BYTES
                })
            ),
            "oversized sync payload must be rejected before decode"
        );
    }

    #[test]
    fn malformed_sync_payload_is_rejected_without_panic() {
        let payload = [0xAB_u8; 17];
        let decoded = decode_sync_wire_message(&payload);
        assert!(
            matches!(decoded, Err(NetworkError::MalformedSyncPayload)),
            "malformed sync payload should return typed decode error"
        );
    }

    #[test]
    fn ip_to_default_multiaddrs_uses_configured_ports() {
        let ip = "10.0.0.8".parse();
        assert!(ip.is_ok(), "ip should parse");
        let addrs = ip_to_default_multiaddrs(
            ip.unwrap_or_else(|_| unreachable!()),
            DEFAULT_BOOTSTRAP_TCP_PORT,
            DEFAULT_BOOTSTRAP_QUIC_PORT,
        );

        let rendered = addrs.iter().map(ToString::to_string).collect::<Vec<_>>();
        assert!(rendered.contains(&"/ip4/10.0.0.8/tcp/7000".to_owned()));
        assert!(rendered.contains(&"/ip4/10.0.0.8/udp/7001/quic-v1".to_owned()));
    }

    #[tokio::test(flavor = "current_thread")]
    async fn fallback_bootstrap_is_used_when_dns_fails() {
        let resolved = resolve_bootstrap_addresses(
            "invalid.seed.homa.local",
            &["127.0.0.1", "/ip4/127.0.0.1/tcp/8999"],
            7000,
            7001,
        )
        .await;
        assert!(resolved.is_ok(), "fallback should produce usable addresses");
        let resolved = resolved.unwrap_or_else(|_| unreachable!());
        assert!(
            resolved
                .iter()
                .any(|entry| entry.to_string() == "/ip4/127.0.0.1/tcp/8999")
        );
    }

    #[test]
    fn can_add_kademlia_bootstrap_address() {
        let built = build_swarm(P2PConfig::default());
        assert!(built.is_ok(), "swarm should build");
        let mut swarm = built.unwrap_or_else(|_| unreachable!());
        let peer_id = swarm.local_peer_id().to_base58();
        let address = format!("/ip4/127.0.0.1/tcp/7000/p2p/{peer_id}");
        let multiaddr = Multiaddr::from_str(&address);
        assert!(multiaddr.is_ok(), "bootstrap address should parse");

        let added = add_kademlia_address(&mut swarm, multiaddr.unwrap_or_else(|_| unreachable!()));
        assert!(added.is_ok(), "kademlia address should be added");
    }

    #[test]
    fn malformed_transaction_payload_is_rejected_without_panic() {
        let payload = [0xFF_u8; 32];
        let decoded = decode_transaction_gossip_payload(&payload);
        assert!(
            decoded.is_err(),
            "malformed gossip payload should return a typed decode error"
        );
    }

    #[test]
    fn block_payload_bounds_accepts_reasonable_size() {
        let payload = vec![0_u8; 1024];
        let validated = validate_block_gossip_payload_bounds(&payload);
        assert!(validated.is_ok(), "small block payload should be accepted");
    }

    #[test]
    fn block_payload_bounds_rejects_oversized_payload() {
        let payload = vec![0_u8; MAX_BLOCK_GOSSIP_BYTES + 1];
        let validated = validate_block_gossip_payload_bounds(&payload);
        assert!(
            matches!(
                validated,
                Err(NetworkError::BlockPayloadTooLarge {
                    actual: _,
                    max: MAX_BLOCK_GOSSIP_BYTES
                })
            ),
            "oversized block payload must be rejected before downstream validation"
        );
    }

    #[test]
    fn valid_transaction_payload_decodes_from_gossip() {
        let transaction = Transaction::new_unsigned(
            "HMA_TEST_SENDER".to_owned(),
            "HMA_TEST_RECEIVER".to_owned(),
            1,
            0,
            7,
            3,
        );
        let encoded = transaction.encode();
        assert!(encoded.is_ok(), "transaction encoding should succeed");

        let decoded =
            decode_transaction_gossip_payload(&encoded.unwrap_or_else(|_| unreachable!()));
        assert!(decoded.is_ok(), "encoded payload should decode");
        assert_eq!(
            decoded.unwrap_or_else(|_| unreachable!()),
            transaction,
            "decoded transaction must match original payload"
        );
    }

    #[test]
    fn zero_copy_decode_borrows_from_payload_buffer() {
        let transaction = Transaction::new_unsigned(
            "HMA_BORROWED_SENDER".to_owned(),
            "HMA_BORROWED_RECEIVER".to_owned(),
            9,
            2,
            4,
            8,
        )
        .with_sender_public_key([9_u8; 32])
        .with_signature([7_u8; 64]);
        let encoded = transaction.encode();
        assert!(encoded.is_ok(), "transaction encoding should succeed");
        let encoded = encoded.unwrap_or_else(|_| unreachable!());

        let borrowed = decode_transaction_gossip_payload_zero_copy(&encoded);
        assert!(borrowed.is_ok(), "zero-copy decode should succeed");
        let borrowed = borrowed.unwrap_or_else(|_| unreachable!());

        let start = encoded.as_ptr() as usize;
        let end = start + encoded.len();
        let sender_ptr = borrowed.sender.as_ptr() as usize;
        let receiver_ptr = borrowed.receiver.as_ptr() as usize;
        let key_ptr = borrowed.sender_public_key.as_ptr() as usize;
        let sig_ptr = borrowed.signature.as_ptr() as usize;

        assert!((start..end).contains(&sender_ptr));
        assert!((start..end).contains(&receiver_ptr));
        assert!((start..end).contains(&key_ptr));
        assert!((start..end).contains(&sig_ptr));
    }

    #[test]
    fn zero_copy_decode_materializes_to_owned_transaction() {
        let transaction = Transaction::new_unsigned(
            "HMA_ZERO_COPY_SRC".to_owned(),
            "HMA_ZERO_COPY_DST".to_owned(),
            5,
            1,
            3,
            6,
        )
        .with_sender_public_key([4_u8; 32])
        .with_signature([6_u8; 64]);
        let encoded = transaction.encode();
        assert!(encoded.is_ok(), "transaction encoding should succeed");
        let encoded = encoded.unwrap_or_else(|_| unreachable!());

        let borrowed = decode_transaction_gossip_payload_zero_copy(&encoded);
        assert!(borrowed.is_ok(), "zero-copy decode should succeed");
        let materialized = borrowed.unwrap_or_else(|_| unreachable!()).into_owned();

        assert_eq!(materialized, transaction);
    }

    #[test]
    fn oversized_payload_is_rejected_before_decode() {
        let payload = vec![0_u8; crate::core::transaction::MAX_TRANSACTION_BYTES + 1];
        let decoded = decode_transaction_gossip_payload(&payload);
        assert!(
            matches!(
                decoded,
                Err(NetworkError::TransactionPayloadTooLarge { .. })
            ),
            "oversized payload must be rejected before decoding"
        );
    }

    #[tokio::test(flavor = "current_thread")]
    async fn broadcast_failures_are_recorded_in_observability() {
        let observability = Observability::new(8);
        let result = broadcast_transaction_bytes_with_observability(
            vec![1_u8, 2_u8, 3_u8],
            "invalid.seed.homa.local",
            &[],
            Duration::from_millis(20),
            Some(&observability),
        )
        .await;
        assert!(
            result.is_err(),
            "broadcast should fail without bootstrap peers"
        );
        assert!(
            observability.gossip_failure_total() >= 1,
            "observability should record bootstrap/dial/publish failures"
        );
    }
}
