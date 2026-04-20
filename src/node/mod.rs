//! Node daemon runtime orchestration.

/// Node daemon command-line interface.
pub mod cli;
/// Node runtime config loading + validation.
pub mod config;
/// Long-running node daemon skeleton and runtime event loop wiring.
pub mod daemon;
/// JSON-RPC + WebSocket node API surface.
pub mod rpc;
