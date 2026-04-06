//! Peer reputation scoring and ban-threshold controls.

use std::collections::HashMap;

use thiserror::Error;

/// Default score floor.
pub const DEFAULT_MIN_SCORE: i32 = -200;
/// Default score ceiling.
pub const DEFAULT_MAX_SCORE: i32 = 200;
/// Default ban threshold.
pub const DEFAULT_BAN_THRESHOLD: i32 = -100;
/// Default temporary ban duration.
pub const DEFAULT_BAN_DURATION_MS: u64 = 60_000;
/// Default score decay interval.
pub const DEFAULT_DECAY_INTERVAL_MS: u64 = 1_000;
/// Default magnitude decayed toward zero each interval.
pub const DEFAULT_DECAY_STEP: i32 = 2;
/// Default low-penalty threshold.
pub const DEFAULT_LOW_PENALTY_SCORE_THRESHOLD: i32 = -20;
/// Default medium-penalty threshold.
pub const DEFAULT_MEDIUM_PENALTY_SCORE_THRESHOLD: i32 = -60;
/// Default severe-penalty threshold.
pub const DEFAULT_SEVERE_PENALTY_SCORE_THRESHOLD: i32 = -90;
/// Default dial cooldown for low-penalty peers.
pub const DEFAULT_LOW_DIAL_COOLDOWN_MS: u64 = 1_000;
/// Default dial cooldown for medium-penalty peers.
pub const DEFAULT_MEDIUM_DIAL_COOLDOWN_MS: u64 = 5_000;
/// Default dial cooldown for severe-penalty peers.
pub const DEFAULT_SEVERE_DIAL_COOLDOWN_MS: u64 = 15_000;
/// Default serve-quota scale for low-penalty peers (per-mille).
pub const DEFAULT_LOW_SERVE_SCALE_PER_MILLE: u16 = 750;
/// Default serve-quota scale for medium-penalty peers (per-mille).
pub const DEFAULT_MEDIUM_SERVE_SCALE_PER_MILLE: u16 = 500;
/// Default serve-quota scale for severe-penalty peers (per-mille).
pub const DEFAULT_SEVERE_SERVE_SCALE_PER_MILLE: u16 = 250;

/// Configurable policy for peer reputation scoring.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ReputationPolicy {
    /// Minimum allowed score.
    pub min_score: i32,
    /// Maximum allowed score.
    pub max_score: i32,
    /// Score at or below this value triggers a temporary ban.
    pub ban_threshold: i32,
    /// Ban duration applied once threshold is crossed.
    pub ban_duration_ms: u64,
    /// Score-decay interval duration.
    pub decay_interval_ms: u64,
    /// Magnitude decayed toward zero on each interval.
    pub decay_step: i32,
}

impl ReputationPolicy {
    /// Strict default policy for public network operation.
    #[must_use]
    pub const fn strict_default() -> Self {
        Self {
            min_score: DEFAULT_MIN_SCORE,
            max_score: DEFAULT_MAX_SCORE,
            ban_threshold: DEFAULT_BAN_THRESHOLD,
            ban_duration_ms: DEFAULT_BAN_DURATION_MS,
            decay_interval_ms: DEFAULT_DECAY_INTERVAL_MS,
            decay_step: DEFAULT_DECAY_STEP,
        }
    }
}

impl Default for ReputationPolicy {
    fn default() -> Self {
        Self::strict_default()
    }
}

/// Adaptive dial/serve penalties keyed by reputation score bands.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct AdaptivePenaltyPolicy {
    /// Score threshold that enters low-penalty band.
    pub low_score_threshold: i32,
    /// Score threshold that enters medium-penalty band.
    pub medium_score_threshold: i32,
    /// Score threshold that enters severe-penalty band.
    pub severe_score_threshold: i32,
    /// Dial cooldown duration for low-penalty peers.
    pub low_dial_cooldown_ms: u64,
    /// Dial cooldown duration for medium-penalty peers.
    pub medium_dial_cooldown_ms: u64,
    /// Dial cooldown duration for severe-penalty peers.
    pub severe_dial_cooldown_ms: u64,
    /// Serve quota scaling factor for low-penalty peers in per-mille.
    pub low_serve_scale_per_mille: u16,
    /// Serve quota scaling factor for medium-penalty peers in per-mille.
    pub medium_serve_scale_per_mille: u16,
    /// Serve quota scaling factor for severe-penalty peers in per-mille.
    pub severe_serve_scale_per_mille: u16,
}

impl AdaptivePenaltyPolicy {
    /// Strict default penalties for public network operation.
    #[must_use]
    pub const fn strict_default() -> Self {
        Self {
            low_score_threshold: DEFAULT_LOW_PENALTY_SCORE_THRESHOLD,
            medium_score_threshold: DEFAULT_MEDIUM_PENALTY_SCORE_THRESHOLD,
            severe_score_threshold: DEFAULT_SEVERE_PENALTY_SCORE_THRESHOLD,
            low_dial_cooldown_ms: DEFAULT_LOW_DIAL_COOLDOWN_MS,
            medium_dial_cooldown_ms: DEFAULT_MEDIUM_DIAL_COOLDOWN_MS,
            severe_dial_cooldown_ms: DEFAULT_SEVERE_DIAL_COOLDOWN_MS,
            low_serve_scale_per_mille: DEFAULT_LOW_SERVE_SCALE_PER_MILLE,
            medium_serve_scale_per_mille: DEFAULT_MEDIUM_SERVE_SCALE_PER_MILLE,
            severe_serve_scale_per_mille: DEFAULT_SEVERE_SERVE_SCALE_PER_MILLE,
        }
    }
}

impl Default for AdaptivePenaltyPolicy {
    fn default() -> Self {
        Self::strict_default()
    }
}

/// Weighted event classes that influence reputation score.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ReputationEvent {
    /// Peer produced malformed payload that failed decode.
    MalformedPayload,
    /// Peer violated protocol-level rules (invalid checkpoint/chunk metadata).
    ProtocolViolation,
    /// Peer frequently timed out or failed to answer requests.
    Timeout,
    /// Peer responded correctly to one request.
    SuccessfulResponse,
    /// Peer contributed expected traffic (useful gossip/chunk relay).
    HelpfulRelay,
}

impl ReputationEvent {
    const fn score_delta(self) -> i32 {
        match self {
            Self::MalformedPayload => -30,
            Self::ProtocolViolation => -50,
            Self::Timeout => -12,
            Self::SuccessfulResponse => 6,
            Self::HelpfulRelay => 3,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum PenaltyBand {
    None,
    Low,
    Medium,
    Severe,
}

const fn penalty_band(score: i32, policy: AdaptivePenaltyPolicy) -> PenaltyBand {
    if score <= policy.severe_score_threshold {
        return PenaltyBand::Severe;
    }
    if score <= policy.medium_score_threshold {
        return PenaltyBand::Medium;
    }
    if score <= policy.low_score_threshold {
        return PenaltyBand::Low;
    }
    PenaltyBand::None
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct PeerRecord {
    score: i32,
    last_updated_ms: u64,
    banned_until_ms: u64,
}

/// Reputation policy and state validation failures.
#[derive(Debug, Clone, PartialEq, Eq, Error)]
pub enum ReputationError {
    /// Policy fields are inconsistent.
    #[error(
        "invalid reputation policy: min_score={min_score}, max_score={max_score}, ban_threshold={ban_threshold}, ban_duration_ms={ban_duration_ms}, decay_interval_ms={decay_interval_ms}, decay_step={decay_step}"
    )]
    InvalidPolicy {
        /// Configured score floor.
        min_score: i32,
        /// Configured score ceiling.
        max_score: i32,
        /// Configured ban threshold.
        ban_threshold: i32,
        /// Configured ban duration.
        ban_duration_ms: u64,
        /// Configured decay interval.
        decay_interval_ms: u64,
        /// Configured decay step.
        decay_step: i32,
    },
    /// Adaptive policy fields are inconsistent.
    #[error(
        "invalid adaptive penalty policy: low_threshold={low_score_threshold}, medium_threshold={medium_score_threshold}, severe_threshold={severe_score_threshold}, low_cooldown_ms={low_dial_cooldown_ms}, medium_cooldown_ms={medium_dial_cooldown_ms}, severe_cooldown_ms={severe_dial_cooldown_ms}, low_scale={low_serve_scale_per_mille}, medium_scale={medium_serve_scale_per_mille}, severe_scale={severe_serve_scale_per_mille}"
    )]
    InvalidAdaptivePolicy {
        /// Low score threshold.
        low_score_threshold: i32,
        /// Medium score threshold.
        medium_score_threshold: i32,
        /// Severe score threshold.
        severe_score_threshold: i32,
        /// Low-band dial cooldown.
        low_dial_cooldown_ms: u64,
        /// Medium-band dial cooldown.
        medium_dial_cooldown_ms: u64,
        /// Severe-band dial cooldown.
        severe_dial_cooldown_ms: u64,
        /// Low-band serve scale.
        low_serve_scale_per_mille: u16,
        /// Medium-band serve scale.
        medium_serve_scale_per_mille: u16,
        /// Severe-band serve scale.
        severe_serve_scale_per_mille: u16,
    },
    /// Dial operation should be delayed until this timestamp.
    #[error("dial cooldown active for peer {peer_id} until {retry_at_ms}")]
    DialCooldownActive {
        /// Target peer id.
        peer_id: String,
        /// Earliest allowed retry timestamp.
        retry_at_ms: u64,
    },
    /// Peer is currently banned by reputation thresholding.
    #[error("peer {peer_id} is banned until {banned_until_ms}")]
    PeerBanned {
        /// Target peer id.
        peer_id: String,
        /// Ban expiration timestamp.
        banned_until_ms: u64,
    },
}

const fn validate_policy(policy: ReputationPolicy) -> Result<(), ReputationError> {
    if policy.min_score >= policy.max_score
        || policy.ban_threshold < policy.min_score
        || policy.ban_threshold > policy.max_score
        || policy.ban_duration_ms == 0
        || policy.decay_interval_ms == 0
        || policy.decay_step == 0
    {
        return Err(ReputationError::InvalidPolicy {
            min_score: policy.min_score,
            max_score: policy.max_score,
            ban_threshold: policy.ban_threshold,
            ban_duration_ms: policy.ban_duration_ms,
            decay_interval_ms: policy.decay_interval_ms,
            decay_step: policy.decay_step,
        });
    }
    Ok(())
}

const fn validate_adaptive_policy(policy: AdaptivePenaltyPolicy) -> Result<(), ReputationError> {
    if policy.low_score_threshold <= policy.medium_score_threshold
        || policy.medium_score_threshold <= policy.severe_score_threshold
        || policy.low_dial_cooldown_ms == 0
        || policy.medium_dial_cooldown_ms == 0
        || policy.severe_dial_cooldown_ms == 0
        || policy.low_serve_scale_per_mille == 0
        || policy.medium_serve_scale_per_mille == 0
        || policy.severe_serve_scale_per_mille == 0
        || policy.low_serve_scale_per_mille > 1_000
        || policy.medium_serve_scale_per_mille > 1_000
        || policy.severe_serve_scale_per_mille > 1_000
    {
        return Err(ReputationError::InvalidAdaptivePolicy {
            low_score_threshold: policy.low_score_threshold,
            medium_score_threshold: policy.medium_score_threshold,
            severe_score_threshold: policy.severe_score_threshold,
            low_dial_cooldown_ms: policy.low_dial_cooldown_ms,
            medium_dial_cooldown_ms: policy.medium_dial_cooldown_ms,
            severe_dial_cooldown_ms: policy.severe_dial_cooldown_ms,
            low_serve_scale_per_mille: policy.low_serve_scale_per_mille,
            medium_serve_scale_per_mille: policy.medium_serve_scale_per_mille,
            severe_serve_scale_per_mille: policy.severe_serve_scale_per_mille,
        });
    }
    Ok(())
}

fn decay_toward_zero(mut score: i32, policy: ReputationPolicy, elapsed_ms: u64) -> i32 {
    let intervals = elapsed_ms / policy.decay_interval_ms;
    if intervals == 0 {
        return score;
    }
    let decay_total = policy
        .decay_step
        .saturating_mul(i32::try_from(intervals).unwrap_or(i32::MAX));
    if score > 0 {
        score = score.saturating_sub(decay_total);
        return score.max(0);
    }
    if score < 0 {
        score = score.saturating_add(decay_total);
        return score.min(0);
    }
    0
}

/// In-memory peer reputation ledger with weighted events and decay.
#[derive(Debug, Clone)]
pub struct PeerReputationLedger {
    policy: ReputationPolicy,
    peers: HashMap<String, PeerRecord>,
}

impl PeerReputationLedger {
    /// Creates an empty ledger under one policy.
    pub fn new(policy: ReputationPolicy) -> Result<Self, ReputationError> {
        validate_policy(policy)?;
        Ok(Self {
            policy,
            peers: HashMap::new(),
        })
    }

    /// Records one event for `peer_id` at `now_ms`.
    pub fn record_event(&mut self, peer_id: &str, event: ReputationEvent, now_ms: u64) {
        let entry = self.peers.entry(peer_id.to_owned()).or_insert(PeerRecord {
            score: 0,
            last_updated_ms: now_ms,
            banned_until_ms: 0,
        });

        let elapsed = now_ms.saturating_sub(entry.last_updated_ms);
        entry.score = decay_toward_zero(entry.score, self.policy, elapsed);
        entry.last_updated_ms = now_ms;
        entry.score = entry
            .score
            .saturating_add(event.score_delta())
            .clamp(self.policy.min_score, self.policy.max_score);
        if entry.score <= self.policy.ban_threshold {
            entry.banned_until_ms = now_ms.saturating_add(self.policy.ban_duration_ms);
        }
    }

    /// Returns current score for one peer with decay applied to `now_ms`.
    #[must_use]
    pub fn score(&self, peer_id: &str, now_ms: u64) -> i32 {
        let Some(record) = self.peers.get(peer_id) else {
            return 0;
        };
        let elapsed = now_ms.saturating_sub(record.last_updated_ms);
        decay_toward_zero(record.score, self.policy, elapsed)
    }

    /// Returns `true` if peer remains under active ban.
    #[must_use]
    pub fn is_banned(&self, peer_id: &str, now_ms: u64) -> bool {
        let Some(record) = self.peers.get(peer_id) else {
            return false;
        };
        now_ms < record.banned_until_ms
    }

    /// Returns active ban-until timestamp when present.
    #[must_use]
    pub fn banned_until_ms(&self, peer_id: &str, now_ms: u64) -> Option<u64> {
        let record = self.peers.get(peer_id)?;
        if now_ms < record.banned_until_ms {
            return Some(record.banned_until_ms);
        }
        None
    }
}

/// Reputation-driven adaptive dial/serve penalty controller.
#[derive(Debug, Clone)]
pub struct AdaptivePenaltyManager {
    ledger: PeerReputationLedger,
    penalty_policy: AdaptivePenaltyPolicy,
    dial_cooldown_until: HashMap<String, u64>,
}

impl AdaptivePenaltyManager {
    /// Creates one adaptive penalty manager from reputation + penalty policies.
    pub fn new(
        reputation_policy: ReputationPolicy,
        penalty_policy: AdaptivePenaltyPolicy,
    ) -> Result<Self, ReputationError> {
        validate_adaptive_policy(penalty_policy)?;
        Ok(Self {
            ledger: PeerReputationLedger::new(reputation_policy)?,
            penalty_policy,
            dial_cooldown_until: HashMap::new(),
        })
    }

    const fn dial_cooldown_for_band(&self, band: PenaltyBand) -> u64 {
        match band {
            PenaltyBand::None => 0,
            PenaltyBand::Low => self.penalty_policy.low_dial_cooldown_ms,
            PenaltyBand::Medium => self.penalty_policy.medium_dial_cooldown_ms,
            PenaltyBand::Severe => self.penalty_policy.severe_dial_cooldown_ms,
        }
    }

    const fn serve_scale_for_band(&self, band: PenaltyBand) -> u16 {
        match band {
            PenaltyBand::None => 1_000,
            PenaltyBand::Low => self.penalty_policy.low_serve_scale_per_mille,
            PenaltyBand::Medium => self.penalty_policy.medium_serve_scale_per_mille,
            PenaltyBand::Severe => self.penalty_policy.severe_serve_scale_per_mille,
        }
    }

    /// Records one peer event and refreshes adaptive penalties.
    pub fn record_event(&mut self, peer_id: &str, event: ReputationEvent, now_ms: u64) {
        self.ledger.record_event(peer_id, event, now_ms);
        let score = self.ledger.score(peer_id, now_ms);
        let band = penalty_band(score, self.penalty_policy);
        let cooldown = self.dial_cooldown_for_band(band);
        if cooldown == 0 {
            return;
        }
        let until = now_ms.saturating_add(cooldown);
        let entry = self
            .dial_cooldown_until
            .entry(peer_id.to_owned())
            .or_insert(0);
        *entry = (*entry).max(until);
    }

    /// Returns current peer score.
    #[must_use]
    pub fn score(&self, peer_id: &str, now_ms: u64) -> i32 {
        self.ledger.score(peer_id, now_ms)
    }

    /// Returns whether peer is currently banned.
    #[must_use]
    pub fn is_banned(&self, peer_id: &str, now_ms: u64) -> bool {
        self.ledger.is_banned(peer_id, now_ms)
    }

    /// Returns active dial cooldown timestamp if present.
    #[must_use]
    pub fn dial_cooldown_until_ms(&self, peer_id: &str, now_ms: u64) -> Option<u64> {
        let until = self.dial_cooldown_until.get(peer_id).copied()?;
        if now_ms < until {
            return Some(until);
        }
        None
    }

    /// Enforces dial penalties by returning a typed error while blocked.
    pub fn enforce_dial_allowed(&self, peer_id: &str, now_ms: u64) -> Result<(), ReputationError> {
        if let Some(banned_until_ms) = self.ledger.banned_until_ms(peer_id, now_ms) {
            return Err(ReputationError::PeerBanned {
                peer_id: peer_id.to_owned(),
                banned_until_ms,
            });
        }
        if let Some(retry_at_ms) = self.dial_cooldown_until_ms(peer_id, now_ms) {
            return Err(ReputationError::DialCooldownActive {
                peer_id: peer_id.to_owned(),
                retry_at_ms,
            });
        }
        Ok(())
    }

    /// Returns effective serve quota after adaptive score-based throttling.
    #[must_use]
    pub fn effective_serve_quota(&self, peer_id: &str, base_quota: usize, now_ms: u64) -> usize {
        if base_quota == 0 {
            return 0;
        }
        if self.is_banned(peer_id, now_ms) {
            return 0;
        }
        let score = self.score(peer_id, now_ms);
        let band = penalty_band(score, self.penalty_policy);
        let scaled = base_quota
            .saturating_mul(usize::from(self.serve_scale_for_band(band)))
            .saturating_div(1_000);
        if scaled == 0 { 1 } else { scaled }
    }
}

#[cfg(test)]
mod tests {
    use super::{
        AdaptivePenaltyManager, AdaptivePenaltyPolicy, DEFAULT_BAN_DURATION_MS,
        DEFAULT_BAN_THRESHOLD, DEFAULT_MAX_SCORE, DEFAULT_MIN_SCORE, PeerReputationLedger,
        ReputationError, ReputationEvent, ReputationPolicy,
    };

    #[test]
    fn protocol_violations_trigger_temporary_ban() {
        let ledger = PeerReputationLedger::new(ReputationPolicy::default());
        assert!(ledger.is_ok(), "ledger should initialize");
        let mut ledger = ledger.unwrap_or_else(|_| unreachable!());

        ledger.record_event("peer-a", ReputationEvent::ProtocolViolation, 1_000);
        ledger.record_event("peer-a", ReputationEvent::ProtocolViolation, 1_010);
        assert!(
            ledger.score("peer-a", 1_010) <= DEFAULT_BAN_THRESHOLD,
            "score should drop below ban threshold after repeated severe violations"
        );
        assert!(
            ledger.is_banned("peer-a", 1_011),
            "peer should be temporarily banned after threshold breach"
        );
    }

    #[test]
    fn ban_expires_after_configured_duration() {
        let ledger = PeerReputationLedger::new(ReputationPolicy::default());
        assert!(ledger.is_ok(), "ledger should initialize");
        let mut ledger = ledger.unwrap_or_else(|_| unreachable!());

        ledger.record_event("peer-b", ReputationEvent::ProtocolViolation, 5_000);
        ledger.record_event("peer-b", ReputationEvent::ProtocolViolation, 5_010);
        let banned_until = ledger.banned_until_ms("peer-b", 5_020);
        assert!(banned_until.is_some(), "ban timestamp should be recorded");
        let banned_until = banned_until.unwrap_or_else(|| unreachable!());
        assert_eq!(banned_until, 5_010 + DEFAULT_BAN_DURATION_MS);
        assert!(ledger.is_banned("peer-b", 5_020));
        assert!(
            !ledger.is_banned("peer-b", banned_until),
            "ban should expire at configured cutoff"
        );
    }

    #[test]
    fn score_decays_toward_zero_between_events() {
        let ledger = PeerReputationLedger::new(ReputationPolicy::default());
        assert!(ledger.is_ok(), "ledger should initialize");
        let mut ledger = ledger.unwrap_or_else(|_| unreachable!());

        ledger.record_event("peer-c", ReputationEvent::MalformedPayload, 1_000);
        let immediate = ledger.score("peer-c", 1_000);
        let decayed = ledger.score("peer-c", 20_000);
        assert!(immediate < 0, "negative event should reduce score");
        assert!(
            decayed > immediate,
            "score should decay toward zero over long quiet periods"
        );
        assert!(
            decayed <= 0,
            "decayed score should not cross zero without positive events"
        );
    }

    #[test]
    fn score_is_clamped_within_policy_bounds() {
        let policy = ReputationPolicy::default();
        let ledger = PeerReputationLedger::new(policy);
        assert!(ledger.is_ok(), "ledger should initialize");
        let mut ledger = ledger.unwrap_or_else(|_| unreachable!());

        for i in 0_u64..200 {
            ledger.record_event("peer-d", ReputationEvent::HelpfulRelay, i);
        }
        assert_eq!(
            ledger.score("peer-d", 1_000),
            DEFAULT_MAX_SCORE,
            "positive burst should clamp at configured max score"
        );

        for i in 0_u64..200 {
            ledger.record_event("peer-d", ReputationEvent::ProtocolViolation, 2_000 + i);
        }
        assert_eq!(
            ledger.score("peer-d", 3_000),
            DEFAULT_MIN_SCORE,
            "negative burst should clamp at configured min score"
        );
    }

    #[test]
    fn adaptive_dial_penalty_blocks_and_recovers_after_cooldown() {
        let manager = AdaptivePenaltyManager::new(
            ReputationPolicy::default(),
            AdaptivePenaltyPolicy::default(),
        );
        assert!(
            manager.is_ok(),
            "adaptive penalty manager should initialize"
        );
        let mut manager = manager.unwrap_or_else(|_| unreachable!());

        manager.record_event("peer-e", ReputationEvent::MalformedPayload, 10_000);
        let blocked = manager.enforce_dial_allowed("peer-e", 10_001);
        assert!(
            matches!(
                blocked,
                Err(ReputationError::DialCooldownActive {
                    peer_id: _,
                    retry_at_ms: _
                })
            ),
            "low-score peers should hit temporary dial cooldown"
        );
        assert!(
            manager.enforce_dial_allowed("peer-e", 11_100).is_ok(),
            "peer should be dial-eligible again after cooldown expiry"
        );
    }

    #[test]
    fn adaptive_dial_penalty_escalates_for_worse_score_bands() {
        let manager = AdaptivePenaltyManager::new(
            ReputationPolicy::default(),
            AdaptivePenaltyPolicy::default(),
        );
        assert!(
            manager.is_ok(),
            "adaptive penalty manager should initialize"
        );
        let mut manager = manager.unwrap_or_else(|_| unreachable!());

        manager.record_event("peer-f", ReputationEvent::MalformedPayload, 1_000);
        let first_until = manager.dial_cooldown_until_ms("peer-f", 1_000);
        assert!(first_until.is_some(), "first cooldown should be set");
        let first_until = first_until.unwrap_or_else(|| unreachable!());

        manager.record_event("peer-f", ReputationEvent::ProtocolViolation, 1_100);
        let second_until = manager.dial_cooldown_until_ms("peer-f", 1_100);
        assert!(second_until.is_some(), "second cooldown should be set");
        let second_until = second_until.unwrap_or_else(|| unreachable!());
        assert!(
            second_until > first_until,
            "worse score band should extend dial cooldown horizon"
        );
    }

    #[test]
    fn adaptive_serve_penalty_scales_quota_and_denies_banned_peers() {
        let manager = AdaptivePenaltyManager::new(
            ReputationPolicy::default(),
            AdaptivePenaltyPolicy::default(),
        );
        assert!(
            manager.is_ok(),
            "adaptive penalty manager should initialize"
        );
        let mut manager = manager.unwrap_or_else(|_| unreachable!());

        let baseline = manager.effective_serve_quota("peer-g", 100, 1_000);
        assert_eq!(
            baseline, 100,
            "neutral peers should retain full serve quota"
        );

        manager.record_event("peer-g", ReputationEvent::MalformedPayload, 1_000);
        let throttled = manager.effective_serve_quota("peer-g", 100, 1_001);
        assert!(
            throttled < baseline,
            "penalized peer should receive throttled serve quota"
        );

        manager.record_event("peer-g", ReputationEvent::ProtocolViolation, 1_010);
        manager.record_event("peer-g", ReputationEvent::ProtocolViolation, 1_020);
        assert!(
            manager.is_banned("peer-g", 1_021),
            "repeated severe violations should transition peer to banned state"
        );
        assert_eq!(
            manager.effective_serve_quota("peer-g", 100, 1_021),
            0,
            "banned peers should receive zero serve quota"
        );
    }
}
