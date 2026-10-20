mod cost_explore;
/// `pool_advanced` 默认值的**单一事实来源** ✓（网关与前端都对着它，别再各写一份 ✗）。
pub mod pool_advanced_defaults;
mod scheduler;
mod scoring;

pub use cost_explore::{
    pool_cost_explore_promote_index, pool_member_cost_tier, POOL_COST_TIER_FREE_OBSERVED,
    POOL_COST_TIER_PAID_OBSERVED, POOL_COST_TIER_UNOBSERVED,
};
pub use scheduler::{
    normalize_enabled_pool_presets, run_pool_scheduler, PoolCandidateFacts, PoolCandidateInput,
    PoolCandidateOrchestration, PoolMemberSignals, PoolRuntimeState, PoolScheduledCandidate,
    PoolSchedulerOutcome, PoolSchedulingConfig, PoolSchedulingPreset, PoolSkippedCandidate,
    POOL_ACCOUNT_BLOCKED_SKIP_REASON, POOL_ACCOUNT_EXHAUSTED_SKIP_REASON,
    POOL_COOLDOWN_SKIP_REASON, POOL_COST_LIMIT_REACHED_SKIP_REASON,
};
pub use scoring::{
    probe_freshness_score, probe_freshness_score_with_ttl, score_pool_member,
    score_pool_member_with_rules, PoolMemberScoreInput, PoolMemberScoreOutput,
    PoolMemberScoreRules, PoolMemberScoreWeights, POOL_SCORE_VERSION,
    PROBE_FAILURE_COOLDOWN_THRESHOLD, PROBE_FAILURE_PENALTY, PROBE_FRESHNESS_TTL_SECONDS,
    REQUEST_FAILURE_PENALTY, UNSCHEDULABLE_SCORE_CAP,
};
