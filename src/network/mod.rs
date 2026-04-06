//! Networking and peer-discovery primitives.

/// Trusted checkpoint validator-set rotation and activation controls.
pub mod checkpoint_rotation;
/// Libp2p swarm setup and DNS seed resolution.
pub mod p2p;
/// Peer reputation scoring and ban-threshold controls.
pub mod reputation;
/// Inbound gossip runtime handler wiring topics to policy-enforced actions.
pub mod runtime_loop;
/// Runtime policy controller combining reputation, sync serving, and trust rotation.
pub mod runtime_policy;
/// Snapshot sync request scheduling and serve-side quota controls.
pub mod sync_engine;
/// Runtime coordinator for outbound sync retries and inbound chunk-response feedback.
pub mod sync_runtime;
