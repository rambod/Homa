//! JSON-RPC + WebSocket API surface for node daemon operations.

use std::collections::HashMap;
use std::net::{IpAddr, SocketAddr};
use std::sync::Arc;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use axum::extract::connect_info::ConnectInfo;
use axum::extract::ws::{Message, WebSocket, WebSocketUpgrade};
use axum::extract::{DefaultBodyLimit, State};
use axum::http::StatusCode;
use axum::response::IntoResponse;
use axum::routing::{get, post};
use axum::{Json, Router};
use futures::{StreamExt, future::pending};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use thiserror::Error;
use tokio::sync::{Mutex, broadcast, watch};

use crate::core::mempool::TransactionId;
use crate::crypto::address::Network;
use crate::network::p2p::TRANSACTIONS_TOPIC;
use crate::node::daemon::{NodeDaemon, NodeDaemonError, NodeLifecycleState, NodeRuntimeStats};

const RPC_JSON_VERSION: &str = "2.0";

/// Runtime settings for RPC/WS server startup.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RpcServerConfig {
    /// Socket address used for HTTP JSON-RPC and WS endpoints.
    pub listen_addr: SocketAddr,
    /// Maximum accepted request payload size in bytes.
    pub max_body_bytes: usize,
    /// Fixed-window per-IP request budget (requests per second).
    pub rate_limit_per_sec: u32,
    /// Max active WS subscriptions per connection.
    pub ws_max_subscriptions_per_conn: usize,
}

/// Top-level RPC server failures.
#[derive(Debug, Error)]
pub enum RpcServerError {
    /// Failed to bind TCP listener.
    #[error("rpc server bind failed at {listen_addr}: {source}")]
    Bind {
        /// Listen address.
        listen_addr: SocketAddr,
        /// Underlying I/O error.
        source: std::io::Error,
    },
    /// Axum server terminated with an I/O error.
    #[error("rpc server runtime failed: {source}")]
    Serve {
        /// Underlying I/O error.
        source: std::io::Error,
    },
}

/// Starts RPC/WS server and runs until shutdown signal is received.
pub async fn run_rpc_server(
    daemon: Arc<Mutex<NodeDaemon>>,
    config: RpcServerConfig,
    shutdown: watch::Receiver<bool>,
) -> Result<(), RpcServerError> {
    let events = RpcEventBus::new(256);
    let state = RpcAppState {
        daemon,
        limiter: Arc::new(Mutex::new(IpRateLimiter::default())),
        events: events.clone(),
        rate_limit_per_sec: config.rate_limit_per_sec,
        max_body_bytes: config.max_body_bytes,
        max_subscriptions_per_conn: config.ws_max_subscriptions_per_conn,
    };

    let event_shutdown = shutdown.clone();
    let event_state = state.clone();
    let _event_task = tokio::spawn(async move {
        publish_runtime_events(event_state, event_shutdown).await;
    });

    let app = Router::new()
        .route("/", post(handle_json_rpc))
        .route("/ws", get(handle_ws))
        .layer(DefaultBodyLimit::max(config.max_body_bytes))
        .with_state(state);

    let listener = tokio::net::TcpListener::bind(config.listen_addr)
        .await
        .map_err(|source| RpcServerError::Bind {
            listen_addr: config.listen_addr,
            source,
        })?;

    axum::serve(
        listener,
        app.into_make_service_with_connect_info::<SocketAddr>(),
    )
    .with_graceful_shutdown(wait_for_shutdown(shutdown))
    .await
    .map_err(|source| RpcServerError::Serve { source })
}

#[derive(Debug, Clone)]
struct RpcAppState {
    daemon: Arc<Mutex<NodeDaemon>>,
    limiter: Arc<Mutex<IpRateLimiter>>,
    events: RpcEventBus,
    rate_limit_per_sec: u32,
    max_body_bytes: usize,
    max_subscriptions_per_conn: usize,
}

#[derive(Debug, Clone)]
struct RpcEventBus {
    new_heads: broadcast::Sender<Value>,
    tx_accepted: broadcast::Sender<Value>,
    sync_status: broadcast::Sender<Value>,
    peer_reputation_events: broadcast::Sender<Value>,
}

impl RpcEventBus {
    fn new(capacity: usize) -> Self {
        let (new_heads, _) = broadcast::channel(capacity);
        let (tx_accepted, _) = broadcast::channel(capacity);
        let (sync_status, _) = broadcast::channel(capacity);
        let (peer_reputation_events, _) = broadcast::channel(capacity);
        Self {
            new_heads,
            tx_accepted,
            sync_status,
            peer_reputation_events,
        }
    }

    fn publish_new_head(&self, payload: Value) {
        let _ = self.new_heads.send(payload);
    }

    fn publish_tx_accepted(&self, payload: Value) {
        let _ = self.tx_accepted.send(payload);
    }

    fn publish_sync_status(&self, payload: Value) {
        let _ = self.sync_status.send(payload);
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
struct IpWindow {
    second: u64,
    count: u32,
}

#[derive(Debug, Default)]
struct IpRateLimiter {
    windows: HashMap<IpAddr, IpWindow>,
}

impl IpRateLimiter {
    fn allow(&mut self, ip: IpAddr, now_sec: u64, limit_per_sec: u32) -> bool {
        if self.windows.len() > 16_384 {
            self.windows
                .retain(|_, window| now_sec.saturating_sub(window.second) <= 60);
        }

        let entry = self.windows.entry(ip).or_insert(IpWindow {
            second: now_sec,
            count: 0,
        });
        if entry.second != now_sec {
            entry.second = now_sec;
            entry.count = 0;
        }
        if entry.count >= limit_per_sec {
            return false;
        }
        entry.count = entry.count.saturating_add(1);
        true
    }
}

#[derive(Debug, Clone, Deserialize)]
struct RpcRequest {
    jsonrpc: Option<String>,
    id: Option<Value>,
    method: String,
    params: Option<Value>,
}

#[derive(Debug, Clone, Serialize)]
struct RpcResponse {
    jsonrpc: &'static str,
    id: Value,
    #[serde(skip_serializing_if = "Option::is_none")]
    result: Option<Value>,
    #[serde(skip_serializing_if = "Option::is_none")]
    error: Option<RpcErrorObject>,
}

#[derive(Debug, Clone, Serialize)]
struct RpcErrorObject {
    code: i64,
    message: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    data: Option<Value>,
}

impl RpcErrorObject {
    fn invalid_request(reason: &str) -> Self {
        Self {
            code: -32_600,
            message: "Invalid Request".to_owned(),
            data: Some(json!({ "reason": reason })),
        }
    }

    fn method_not_found(method: &str) -> Self {
        Self {
            code: -32_601,
            message: "Method not found".to_owned(),
            data: Some(json!({ "method": method })),
        }
    }

    fn invalid_params(reason: &str) -> Self {
        Self {
            code: -32_602,
            message: "Invalid params".to_owned(),
            data: Some(json!({ "reason": reason })),
        }
    }

    fn rate_limited() -> Self {
        Self {
            code: -32_970,
            message: "Rate limit exceeded".to_owned(),
            data: None,
        }
    }

    fn internal(reason: &str) -> Self {
        Self {
            code: -32_603,
            message: "Internal error".to_owned(),
            data: Some(json!({ "reason": reason })),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum WsChannel {
    NewHeads,
    TxAccepted,
    SyncStatus,
    PeerReputationEvents,
}

impl WsChannel {
    const fn as_str(self) -> &'static str {
        match self {
            Self::NewHeads => "newHeads",
            Self::TxAccepted => "txAccepted",
            Self::SyncStatus => "syncStatus",
            Self::PeerReputationEvents => "peerReputationEvents",
        }
    }

    fn parse(value: &str) -> Option<Self> {
        match value {
            "newHeads" => Some(Self::NewHeads),
            "txAccepted" => Some(Self::TxAccepted),
            "syncStatus" => Some(Self::SyncStatus),
            "peerReputationEvents" => Some(Self::PeerReputationEvents),
            _ => None,
        }
    }
}

#[allow(clippy::too_many_lines)]
async fn handle_json_rpc(
    State(state): State<RpcAppState>,
    ConnectInfo(peer): ConnectInfo<SocketAddr>,
    Json(request): Json<RpcRequest>,
) -> impl IntoResponse {
    let id = request.id.clone().unwrap_or(Value::Null);
    if !rate_limit_allow(&state, peer.ip()).await {
        return Json(RpcResponse {
            jsonrpc: RPC_JSON_VERSION,
            id,
            result: None,
            error: Some(RpcErrorObject::rate_limited()),
        });
    }
    if request.jsonrpc.as_deref() != Some(RPC_JSON_VERSION) {
        return Json(RpcResponse {
            jsonrpc: RPC_JSON_VERSION,
            id,
            result: None,
            error: Some(RpcErrorObject::invalid_request(
                "jsonrpc must equal \"2.0\"",
            )),
        });
    }

    match dispatch_json_rpc(&state, &request.method, request.params).await {
        Ok(result) => Json(RpcResponse {
            jsonrpc: RPC_JSON_VERSION,
            id,
            result: Some(result),
            error: None,
        }),
        Err(error) => Json(RpcResponse {
            jsonrpc: RPC_JSON_VERSION,
            id,
            result: None,
            error: Some(error),
        }),
    }
}

async fn handle_ws(
    ws: WebSocketUpgrade,
    State(state): State<RpcAppState>,
    ConnectInfo(peer): ConnectInfo<SocketAddr>,
) -> impl IntoResponse {
    if !rate_limit_allow(&state, peer.ip()).await {
        return (StatusCode::TOO_MANY_REQUESTS, "rate limit exceeded").into_response();
    }
    ws.max_message_size(state.max_body_bytes)
        .on_upgrade(move |socket| ws_session(socket, state))
}

async fn wait_for_shutdown(mut shutdown: watch::Receiver<bool>) {
    if *shutdown.borrow() {
        return;
    }
    while shutdown.changed().await.is_ok() {
        if *shutdown.borrow() {
            return;
        }
    }
}

async fn rate_limit_allow(state: &RpcAppState, ip: IpAddr) -> bool {
    let mut limiter = state.limiter.lock().await;
    limiter.allow(ip, now_unix_sec(), state.rate_limit_per_sec)
}

#[allow(clippy::too_many_lines)]
async fn dispatch_json_rpc(
    state: &RpcAppState,
    method: &str,
    params: Option<Value>,
) -> Result<Value, RpcErrorObject> {
    match method {
        "homa_getStatus" => rpc_get_status(state).await,
        "homa_getBlockByHeight" => {
            let height = parse_u64_param(params, "height", 0)?;
            rpc_get_block_by_height(state, height).await
        }
        "homa_getBlockByHash" => {
            let hash = parse_hash_param(params, "hash", 0)?;
            rpc_get_block_by_hash(state, hash).await
        }
        "homa_getBalance" => {
            let address = parse_string_param(params, "address", 0)?;
            rpc_get_balance(state, &address).await
        }
        "homa_getTransaction" => {
            let hash = parse_hash_param(params, "hash", 0)?;
            rpc_get_transaction(state, hash).await
        }
        "homa_sendRawTransaction" => {
            let encoded = parse_string_param(params, "raw_tx", 0)?;
            rpc_send_raw_transaction(state, &encoded).await
        }
        "homa_getMempoolStats" => rpc_get_mempool_stats(state).await,
        "homa_getPeers" => rpc_get_peers(state).await,
        _ => Err(RpcErrorObject::method_not_found(method)),
    }
}

async fn rpc_get_status(app_state: &RpcAppState) -> Result<Value, RpcErrorObject> {
    let (
        network,
        lifecycle_state,
        finalized_height,
        finalized_hash_hex,
        mempool_size,
        pending_blocks,
        runtime_stats,
    ) = {
        let daemon = app_state.daemon.lock().await;
        let finalized_hash = daemon
            .finalized_block()
            .hash()
            .map_err(|source| RpcErrorObject::internal(&source.to_string()))?;
        (
            daemon.network(),
            daemon.lifecycle_state(),
            daemon.finalized_block().header.height,
            hex::encode(finalized_hash),
            daemon.mempool_len(),
            daemon.pending_block_count(),
            daemon.stats(),
        )
    };
    Ok(json!({
        "network": network_label(network),
        "lifecycle_state": lifecycle_label(lifecycle_state),
        "finalized_height": finalized_height,
        "finalized_hash": finalized_hash_hex,
        "mempool_size": mempool_size,
        "pending_blocks": pending_blocks,
        "stats": stats_json(runtime_stats),
    }))
}

async fn rpc_get_block_by_height(
    state: &RpcAppState,
    height: u64,
) -> Result<Value, RpcErrorObject> {
    let daemon = state.daemon.lock().await;
    let block = if daemon.finalized_block().header.height == height {
        Some(daemon.finalized_block().clone())
    } else {
        daemon
            .indexed_block_by_height(height)
            .map_err(|source| map_daemon_error(&source))?
            .map(|record| record.block)
    };
    Ok(serde_json::to_value(block).unwrap_or(Value::Null))
}

async fn rpc_get_block_by_hash(
    state: &RpcAppState,
    block_hash: [u8; 32],
) -> Result<Value, RpcErrorObject> {
    let block = {
        let daemon = state.daemon.lock().await;
        daemon
            .block_by_hash(&block_hash)
            .map_err(|source| map_daemon_error(&source))?
    };
    Ok(serde_json::to_value(block).unwrap_or(Value::Null))
}

async fn rpc_get_balance(state: &RpcAppState, address: &str) -> Result<Value, RpcErrorObject> {
    let (balance, nonce) = {
        let daemon = state.daemon.lock().await;
        daemon.account_balance_and_nonce(address)
    };
    Ok(json!({
        "address": address,
        "balance": balance,
        "nonce": nonce,
    }))
}

async fn rpc_get_transaction(
    state: &RpcAppState,
    tx_hash: TransactionId,
) -> Result<Value, RpcErrorObject> {
    let resolved = {
        let daemon = state.daemon.lock().await;
        if let Some(indexed) = daemon
            .indexed_transaction_by_hash(&tx_hash)
            .map_err(|source| map_daemon_error(&source))?
        {
            json!({
                "status": "finalized",
                "tx_hash": hex::encode(indexed.tx_hash),
                "sender": indexed.sender,
                "receiver": indexed.receiver,
                "nonce": indexed.nonce,
                "amount": indexed.amount,
                "fee": indexed.fee,
                "block_height": indexed.block_height,
                "block_hash": hex::encode(indexed.block_hash),
                "tx_index": indexed.tx_index,
                "finalized_at_unix_ms": indexed.finalized_at_unix_ms,
            })
        } else if let Some(pending) = daemon.mempool_transaction_by_id(&tx_hash) {
            json!({
                "status": "pending",
                "tx_hash": hex::encode(tx_hash),
                "transaction": pending,
            })
        } else {
            Value::Null
        }
    };

    Ok(resolved)
}

async fn rpc_send_raw_transaction(
    state: &RpcAppState,
    raw_tx_hex: &str,
) -> Result<Value, RpcErrorObject> {
    let payload = hex::decode(raw_tx_hex)
        .map_err(|_| RpcErrorObject::invalid_params("raw_tx must be valid hex bytes"))?;
    let outcome = {
        let mut daemon = state.daemon.lock().await;
        daemon
            .handle_inbound_gossip_message(TRANSACTIONS_TOPIC, &payload, "rpc-local", now_unix_ms())
            .map_err(|source| map_daemon_error(&source))?
    };

    if let crate::node::daemon::NodeInboundOutcome::TransactionAccepted { tx_id } = outcome {
        state.events.publish_tx_accepted(json!({
            "tx_hash": hex::encode(tx_id),
            "source": "rpc",
            "observed_at_unix_ms": now_unix_ms(),
        }));
        return Ok(json!({ "tx_hash": hex::encode(tx_id) }));
    }

    Err(RpcErrorObject::internal(
        "unexpected inbound outcome for transaction payload",
    ))
}

async fn rpc_get_mempool_stats(app_state: &RpcAppState) -> Result<Value, RpcErrorObject> {
    let (mempool_size, admitted, rejected) = {
        let daemon = app_state.daemon.lock().await;
        let runtime_stats = daemon.stats();
        (
            daemon.mempool_len(),
            runtime_stats.tx_admitted_total,
            runtime_stats.tx_rejected_total,
        )
    };
    Ok(json!({
        "mempool_size": mempool_size,
        "tx_admitted_total": admitted,
        "tx_rejected_total": rejected,
    }))
}

async fn rpc_get_peers(state: &RpcAppState) -> Result<Value, RpcErrorObject> {
    let peers = {
        let daemon = state.daemon.lock().await;
        let now_ms = now_unix_ms();
        daemon
            .connected_peer_ids()
            .into_iter()
            .map(|peer_id| {
                json!({
                    "peer_id": peer_id,
                    "score": daemon.peer_score(&peer_id, now_ms),
                    "banned": daemon.is_peer_banned(&peer_id, now_ms),
                })
            })
            .collect::<Vec<_>>()
    };
    Ok(json!(peers))
}

#[allow(clippy::too_many_lines)]
async fn ws_session(mut socket: WebSocket, state: RpcAppState) {
    let mut subscriptions = WsSubscriptions::default();
    loop {
        tokio::select! {
            incoming = socket.next() => {
                let Some(Ok(message)) = incoming else {
                    return;
                };
                if !handle_ws_client_message(&state, &mut socket, &mut subscriptions, message).await {
                    return;
                }
            }
            payload = recv_or_pending(subscriptions.new_heads.as_mut()) => {
                if let Some(payload) = payload {
                    if send_ws_notification(&mut socket, WsChannel::NewHeads, payload).await.is_err() {
                        return;
                    }
                }
            }
            payload = recv_or_pending(subscriptions.tx_accepted.as_mut()) => {
                if let Some(payload) = payload {
                    if send_ws_notification(&mut socket, WsChannel::TxAccepted, payload).await.is_err() {
                        return;
                    }
                }
            }
            payload = recv_or_pending(subscriptions.sync_status.as_mut()) => {
                if let Some(payload) = payload {
                    if send_ws_notification(&mut socket, WsChannel::SyncStatus, payload).await.is_err() {
                        return;
                    }
                }
            }
            payload = recv_or_pending(subscriptions.peer_reputation_events.as_mut()) => {
                if let Some(payload) = payload {
                    if send_ws_notification(&mut socket, WsChannel::PeerReputationEvents, payload).await.is_err() {
                        return;
                    }
                }
            }
        }
    }
}

async fn recv_or_pending(receiver: Option<&mut broadcast::Receiver<Value>>) -> Option<Value> {
    match receiver {
        Some(receiver) => receiver.recv().await.ok(),
        None => pending::<Option<Value>>().await,
    }
}

async fn handle_ws_client_message(
    state: &RpcAppState,
    socket: &mut WebSocket,
    subscriptions: &mut WsSubscriptions,
    message: Message,
) -> bool {
    let Message::Text(raw) = message else {
        return !matches!(message, Message::Close(_));
    };
    let parsed: Value = if let Ok(parsed) = serde_json::from_str(&raw) {
        parsed
    } else {
        let _ = send_ws_error(
            socket,
            Value::Null,
            RpcErrorObject::invalid_request("invalid JSON payload"),
        )
        .await;
        return true;
    };
    let id = parsed.get("id").cloned().unwrap_or(Value::Null);
    let method = parsed
        .get("method")
        .and_then(Value::as_str)
        .unwrap_or_default();
    let channel_name = parsed
        .get("params")
        .and_then(Value::as_object)
        .and_then(|params| params.get("channel"))
        .and_then(Value::as_str)
        .unwrap_or_default();
    let Some(channel) = WsChannel::parse(channel_name) else {
        let _ = send_ws_error(
            socket,
            id,
            RpcErrorObject::invalid_params("unsupported or missing channel"),
        )
        .await;
        return true;
    };

    match method {
        "subscribe" => {
            if subscriptions.is_subscribed(channel) {
                let _ = send_ws_result(
                    socket,
                    id,
                    json!({"subscribed": channel.as_str(), "already_subscribed": true}),
                )
                .await;
                return true;
            }
            if subscriptions.count() >= state.max_subscriptions_per_conn {
                let _ = send_ws_error(
                    socket,
                    id,
                    RpcErrorObject {
                        code: -32_971,
                        message: "WS subscription limit exceeded".to_owned(),
                        data: Some(json!({
                            "max_subscriptions_per_connection": state.max_subscriptions_per_conn
                        })),
                    },
                )
                .await;
                return true;
            }
            subscriptions.subscribe(channel, state);
            let _ = send_ws_result(socket, id, json!({"subscribed": channel.as_str()})).await;
            if channel == WsChannel::SyncStatus {
                let payload = current_sync_status_json(&state.daemon).await;
                let _ = send_ws_notification(socket, WsChannel::SyncStatus, payload).await;
            }
            true
        }
        "unsubscribe" => {
            let removed = subscriptions.unsubscribe(channel);
            let _ = send_ws_result(
                socket,
                id,
                json!({"unsubscribed": channel.as_str(), "removed": removed}),
            )
            .await;
            true
        }
        _ => {
            let _ = send_ws_error(socket, id, RpcErrorObject::method_not_found(method)).await;
            true
        }
    }
}

async fn send_ws_result(
    socket: &mut WebSocket,
    id: Value,
    result: Value,
) -> Result<(), axum::Error> {
    send_ws_json(
        socket,
        json!({
            "jsonrpc": RPC_JSON_VERSION,
            "id": id,
            "result": result,
        }),
    )
    .await
}

async fn send_ws_error(
    socket: &mut WebSocket,
    id: Value,
    error: RpcErrorObject,
) -> Result<(), axum::Error> {
    send_ws_json(
        socket,
        json!({
            "jsonrpc": RPC_JSON_VERSION,
            "id": id,
            "error": error,
        }),
    )
    .await
}

async fn send_ws_notification(
    socket: &mut WebSocket,
    channel: WsChannel,
    payload: Value,
) -> Result<(), axum::Error> {
    send_ws_json(
        socket,
        json!({
            "jsonrpc": RPC_JSON_VERSION,
            "method": "homa_subscription",
            "params": {
                "channel": channel.as_str(),
                "data": payload,
            },
        }),
    )
    .await
}

async fn send_ws_json(socket: &mut WebSocket, payload: Value) -> Result<(), axum::Error> {
    socket.send(Message::Text(payload.to_string().into())).await
}

async fn publish_runtime_events(state: RpcAppState, mut shutdown: watch::Receiver<bool>) {
    let mut interval = tokio::time::interval(Duration::from_millis(500));
    let mut last_height = None;
    let mut last_sync = None;
    loop {
        tokio::select! {
            _ = interval.tick() => {
                let snapshot = {
                    let daemon = state.daemon.lock().await;
                    (
                        daemon.lifecycle_state(),
                        daemon.finalized_block().header.height,
                        daemon.finalized_block().hash().ok(),
                        daemon.completed_snapshot_count(),
                        daemon.pending_block_count(),
                        daemon.mempool_len(),
                    )
                };
                if last_height != Some(snapshot.1) {
                    state.events.publish_new_head(json!({
                        "height": snapshot.1,
                        "hash": snapshot.2.map(hex::encode),
                        "observed_at_unix_ms": now_unix_ms(),
                    }));
                    last_height = Some(snapshot.1);
                }
                let sync_payload = json!({
                    "lifecycle_state": lifecycle_label(snapshot.0),
                    "completed_snapshots": snapshot.3,
                    "pending_blocks": snapshot.4,
                    "mempool_size": snapshot.5,
                    "observed_at_unix_ms": now_unix_ms(),
                });
                if last_sync.as_ref() != Some(&sync_payload) {
                    state.events.publish_sync_status(sync_payload.clone());
                    last_sync = Some(sync_payload);
                }
            }
            _ = shutdown.changed() => {
                if *shutdown.borrow() {
                    return;
                }
            }
        }
    }
}

async fn current_sync_status_json(daemon: &Arc<Mutex<NodeDaemon>>) -> Value {
    let (lifecycle_state, completed_snapshots, pending_blocks, mempool_size) = {
        let daemon = daemon.lock().await;
        (
            daemon.lifecycle_state(),
            daemon.completed_snapshot_count(),
            daemon.pending_block_count(),
            daemon.mempool_len(),
        )
    };
    json!({
        "lifecycle_state": lifecycle_label(lifecycle_state),
        "completed_snapshots": completed_snapshots,
        "pending_blocks": pending_blocks,
        "mempool_size": mempool_size,
        "observed_at_unix_ms": now_unix_ms(),
    })
}

fn parse_u64_param(params: Option<Value>, key: &str, index: usize) -> Result<u64, RpcErrorObject> {
    let value = parse_param_value(params, key, index)?;
    if let Some(value) = value.as_u64() {
        return Ok(value);
    }
    if let Some(value) = value.as_str() {
        return value
            .parse::<u64>()
            .map_err(|_| RpcErrorObject::invalid_params("parameter must be u64"));
    }
    Err(RpcErrorObject::invalid_params("parameter must be u64"))
}

fn parse_string_param(
    params: Option<Value>,
    key: &str,
    index: usize,
) -> Result<String, RpcErrorObject> {
    let value = parse_param_value(params, key, index)?;
    value
        .as_str()
        .map(ToOwned::to_owned)
        .ok_or_else(|| RpcErrorObject::invalid_params("parameter must be string"))
}

fn parse_hash_param(
    params: Option<Value>,
    key: &str,
    index: usize,
) -> Result<[u8; 32], RpcErrorObject> {
    let encoded = parse_string_param(params, key, index)?;
    decode_hash_hex(&encoded)
}

fn parse_param_value(
    params: Option<Value>,
    key: &str,
    index: usize,
) -> Result<Value, RpcErrorObject> {
    let Some(params) = params else {
        return Err(RpcErrorObject::invalid_params("missing method params"));
    };
    if let Some(array) = params.as_array() {
        return array
            .get(index)
            .cloned()
            .ok_or_else(|| RpcErrorObject::invalid_params("missing positional parameter"));
    }
    if let Some(object) = params.as_object() {
        return object
            .get(key)
            .cloned()
            .ok_or_else(|| RpcErrorObject::invalid_params("missing named parameter"));
    }
    Err(RpcErrorObject::invalid_params(
        "params must be array or object",
    ))
}

fn decode_hash_hex(encoded: &str) -> Result<[u8; 32], RpcErrorObject> {
    let bytes =
        hex::decode(encoded).map_err(|_| RpcErrorObject::invalid_params("hash must be hex"))?;
    let Ok(hash) = <[u8; 32]>::try_from(bytes.as_slice()) else {
        return Err(RpcErrorObject::invalid_params(
            "hash must decode to exactly 32 bytes",
        ));
    };
    Ok(hash)
}

fn map_daemon_error(error: &NodeDaemonError) -> RpcErrorObject {
    let (code, message) = match error {
        NodeDaemonError::MempoolAdmission { source: _ } => (-32_110, "Transaction rejected"),
        NodeDaemonError::IntakeStopped { state: _ } => (-32_120, "Node intake is stopped"),
        NodeDaemonError::RuntimeLoop { source: _ } => (-32_121, "Inbound runtime-loop rejected"),
        NodeDaemonError::BlockDecode { source: _ } => (-32_122, "Block payload decode failed"),
        NodeDaemonError::Indexer { source: _ } => (-32_130, "Indexer operation failed"),
        NodeDaemonError::Network { source: _ } => (-32_140, "Network operation failed"),
        _ => (-32_603, "Internal daemon error"),
    };
    RpcErrorObject {
        code,
        message: message.to_owned(),
        data: Some(json!({ "source": error.to_string() })),
    }
}

fn stats_json(stats: NodeRuntimeStats) -> Value {
    json!({
        "inbound_messages_total": stats.inbound_messages_total,
        "tx_admitted_total": stats.tx_admitted_total,
        "tx_rejected_total": stats.tx_rejected_total,
        "blocks_queued_total": stats.blocks_queued_total,
        "blocks_finalized_total": stats.blocks_finalized_total,
        "block_rejected_total": stats.block_rejected_total,
        "inbound_block_consensus_rejected_total": stats.inbound_block_consensus_rejected_total,
        "inbound_block_duplicate_total": stats.inbound_block_duplicate_total,
        "blocks_produced_total": stats.blocks_produced_total,
        "block_publish_failure_total": stats.block_publish_failure_total,
    })
}

const fn lifecycle_label(state: NodeLifecycleState) -> &'static str {
    match state {
        NodeLifecycleState::Bootstrapping => "bootstrapping",
        NodeLifecycleState::Syncing => "syncing",
        NodeLifecycleState::Ready => "ready",
        NodeLifecycleState::Draining => "draining",
        NodeLifecycleState::Stopped => "stopped",
    }
}

const fn network_label(network: Network) -> &'static str {
    match network {
        Network::Mainnet => "mainnet",
        Network::Testnet => "testnet",
        Network::Devnet => "devnet",
    }
}

fn now_unix_ms() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0_u64, |duration| {
            u64::try_from(duration.as_millis()).unwrap_or(u64::MAX)
        })
}

fn now_unix_sec() -> u64 {
    now_unix_ms() / 1_000
}

#[derive(Default)]
struct WsSubscriptions {
    new_heads: Option<broadcast::Receiver<Value>>,
    tx_accepted: Option<broadcast::Receiver<Value>>,
    sync_status: Option<broadcast::Receiver<Value>>,
    peer_reputation_events: Option<broadcast::Receiver<Value>>,
}

impl WsSubscriptions {
    fn count(&self) -> usize {
        [
            self.new_heads.is_some(),
            self.tx_accepted.is_some(),
            self.sync_status.is_some(),
            self.peer_reputation_events.is_some(),
        ]
        .into_iter()
        .filter(|active| *active)
        .count()
    }

    const fn is_subscribed(&self, channel: WsChannel) -> bool {
        match channel {
            WsChannel::NewHeads => self.new_heads.is_some(),
            WsChannel::TxAccepted => self.tx_accepted.is_some(),
            WsChannel::SyncStatus => self.sync_status.is_some(),
            WsChannel::PeerReputationEvents => self.peer_reputation_events.is_some(),
        }
    }

    fn subscribe(&mut self, channel: WsChannel, state: &RpcAppState) {
        match channel {
            WsChannel::NewHeads => self.new_heads = Some(state.events.new_heads.subscribe()),
            WsChannel::TxAccepted => {
                self.tx_accepted = Some(state.events.tx_accepted.subscribe());
            }
            WsChannel::SyncStatus => {
                self.sync_status = Some(state.events.sync_status.subscribe());
            }
            WsChannel::PeerReputationEvents => {
                self.peer_reputation_events = Some(state.events.peer_reputation_events.subscribe());
            }
        }
    }

    fn unsubscribe(&mut self, channel: WsChannel) -> bool {
        match channel {
            WsChannel::NewHeads => self.new_heads.take().is_some(),
            WsChannel::TxAccepted => self.tx_accepted.take().is_some(),
            WsChannel::SyncStatus => self.sync_status.take().is_some(),
            WsChannel::PeerReputationEvents => self.peer_reputation_events.take().is_some(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::{IpRateLimiter, RpcAppState, RpcEventBus, dispatch_json_rpc};
    use crate::core::mempool::MempoolConfig;
    use crate::core::transaction::Transaction;
    use crate::crypto::address::{Network, derive_address};
    use crate::crypto::keys::Keypair;
    use crate::node::daemon::{NodeDaemon, NodeDaemonConfig};
    use serde_json::json;
    use std::sync::Arc;
    use tokio::sync::Mutex;

    fn rpc_state_with_genesis_daemon() -> RpcAppState {
        let network = Network::Testnet;
        let mut config = NodeDaemonConfig::for_network(network);
        config.mempool_config = MempoolConfig::new(10_000, 0, network);
        config.max_pending_blocks = 16;
        let daemon = NodeDaemon::from_genesis_with_config(config);
        assert!(daemon.is_ok(), "daemon should initialize for rpc tests");
        let daemon = daemon.unwrap_or_else(|_| unreachable!());
        RpcAppState {
            daemon: Arc::new(Mutex::new(daemon)),
            limiter: Arc::new(Mutex::new(IpRateLimiter::default())),
            events: RpcEventBus::new(64),
            rate_limit_per_sec: 64,
            max_body_bytes: 65_536,
            max_subscriptions_per_conn: 8,
        }
    }

    fn signed_transaction_from_genesis_sender() -> Transaction {
        let network = Network::Testnet;
        let sender_keypair = Keypair::from_secret_key(&[1_u8; 32]);
        assert!(sender_keypair.is_ok(), "sender key should parse");
        let sender_keypair = sender_keypair.unwrap_or_else(|_| unreachable!());
        let sender_address = derive_address(&sender_keypair.public_key_bytes(), network);
        assert!(sender_address.is_ok(), "sender address should derive");
        let receiver_keypair = Keypair::generate();
        let receiver_address = derive_address(&receiver_keypair.public_key_bytes(), network);
        assert!(receiver_address.is_ok(), "receiver address should derive");
        let unsigned = Transaction::new_unsigned(
            sender_address.unwrap_or_else(|_| unreachable!()),
            receiver_address.unwrap_or_else(|_| unreachable!()),
            10,
            1,
            1,
            0,
        )
        .with_sender_public_key(sender_keypair.public_key_bytes());
        let signing_bytes = unsigned.signing_bytes_for_network(network);
        assert!(signing_bytes.is_ok(), "signing bytes should build");
        unsigned
            .with_signature(sender_keypair.sign(&signing_bytes.unwrap_or_else(|_| unreachable!())))
    }

    #[tokio::test(flavor = "current_thread")]
    async fn get_status_returns_genesis_height() {
        let state = rpc_state_with_genesis_daemon();
        let response = dispatch_json_rpc(&state, "homa_getStatus", None).await;
        assert!(response.is_ok(), "status rpc should succeed");
        let response = response.unwrap_or_else(|_| unreachable!());
        assert_eq!(
            response
                .get("finalized_height")
                .and_then(serde_json::Value::as_u64),
            Some(0),
            "new daemon should report genesis finalized height"
        );
    }

    #[tokio::test(flavor = "current_thread")]
    async fn send_raw_transaction_roundtrip_exposes_pending_lookup() {
        let state = rpc_state_with_genesis_daemon();
        let transaction = signed_transaction_from_genesis_sender();
        let encoded = transaction.encode();
        assert!(encoded.is_ok(), "transaction should encode");
        let encoded = encoded.unwrap_or_else(|_| unreachable!());
        let send = dispatch_json_rpc(
            &state,
            "homa_sendRawTransaction",
            Some(json!({ "raw_tx": hex::encode(encoded) })),
        )
        .await;
        assert!(send.is_ok(), "raw transaction submission should succeed");
        let send = send.unwrap_or_else(|_| unreachable!());
        let tx_hash = send
            .get("tx_hash")
            .and_then(serde_json::Value::as_str)
            .map(ToOwned::to_owned);
        assert!(tx_hash.is_some(), "send result should include tx hash");

        let lookup = dispatch_json_rpc(
            &state,
            "homa_getTransaction",
            Some(json!({ "hash": tx_hash.unwrap_or_else(|| unreachable!()) })),
        )
        .await;
        assert!(lookup.is_ok(), "transaction lookup should succeed");
        let lookup = lookup.unwrap_or_else(|_| unreachable!());
        assert_eq!(
            lookup.get("status").and_then(serde_json::Value::as_str),
            Some("pending"),
            "freshly submitted transaction should be discoverable as pending"
        );
    }

    #[test]
    fn per_ip_rate_limiter_enforces_fixed_window_budget() {
        let mut limiter = IpRateLimiter::default();
        let ip = "127.0.0.1".parse();
        assert!(ip.is_ok(), "loopback ip should parse");
        let ip = ip.unwrap_or_else(|_| unreachable!());
        assert!(limiter.allow(ip, 42, 2));
        assert!(limiter.allow(ip, 42, 2));
        assert!(
            !limiter.allow(ip, 42, 2),
            "third request in same second should be rejected"
        );
        assert!(
            limiter.allow(ip, 43, 2),
            "budget should reset in a new second window"
        );
    }
}
