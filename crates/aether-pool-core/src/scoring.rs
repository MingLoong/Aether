use aether_data_contracts::repository::pool_scores::{
    PoolMemberHardState, PoolMemberIdentity, PoolMemberProbeStatus, PoolScoreScope,
};
use serde_json::{json, Value};

pub const POOL_SCORE_VERSION: u64 = 1;
pub const PROBE_FRESHNESS_TTL_SECONDS: u64 = 30 * 60;
pub const UNSCHEDULABLE_SCORE_CAP: f64 = 0.05;
pub const PROBE_FAILURE_PENALTY: f64 = 0.05;
pub const REQUEST_FAILURE_PENALTY: f64 = 0.005;
pub const PROBE_FAILURE_COOLDOWN_THRESHOLD: u64 = 3;
/// 快过期积分路由窗口默认 7 天（对齐面板 `pool.expiring_soon` 默认 `"168h"`）。
pub const EXPIRING_SOON_SECONDS: u64 = 7 * 24 * 60 * 60;
/// 快过期加分默认值：在 0..1 的分值域里表达**温和偏好**（面板用 `expiringVirtualSlots = 3`
/// 的虚拟实例权重表达同一意图——「尽早把要过期的积分用掉」，但不是硬优先）。
pub const EXPIRING_CREDIT_BONUS: f64 = 0.10;
/// 闲置补偿：每小时未用 +0.5 权重（面板 `pool.idle_weight_per_hour` 默认 `0.5`）。
pub const IDLE_WEIGHT_PER_HOUR: f64 = 0.5;
/// 闲置补偿封顶（面板 `pool.idle_weight_max` 默认 `5.0`；`0` = 关闭闲置补偿）。
pub const IDLE_WEIGHT_MAX: f64 = 5.0;

#[derive(Debug, Clone, Copy, PartialEq)]
pub struct PoolMemberScoreWeights {
    pub manual_priority: f64,
    pub health: f64,
    pub probe_freshness: f64,
    pub quota_remaining: f64,
    pub latency: f64,
    pub cost_lru: f64,
}

impl Default for PoolMemberScoreWeights {
    fn default() -> Self {
        Self {
            manual_priority: 0.30,
            health: 0.20,
            probe_freshness: 0.15,
            quota_remaining: 0.15,
            latency: 0.10,
            cost_lru: 0.10,
        }
    }
}

impl PoolMemberScoreWeights {
    pub fn normalized(self) -> Self {
        let sanitized = Self {
            manual_priority: finite_non_negative(self.manual_priority),
            health: finite_non_negative(self.health),
            probe_freshness: finite_non_negative(self.probe_freshness),
            quota_remaining: finite_non_negative(self.quota_remaining),
            latency: finite_non_negative(self.latency),
            cost_lru: finite_non_negative(self.cost_lru),
        };
        let total = sanitized.manual_priority
            + sanitized.health
            + sanitized.probe_freshness
            + sanitized.quota_remaining
            + sanitized.latency
            + sanitized.cost_lru;
        if total <= f64::EPSILON {
            return sanitized;
        }
        Self {
            manual_priority: sanitized.manual_priority / total,
            health: sanitized.health / total,
            probe_freshness: sanitized.probe_freshness / total,
            quota_remaining: sanitized.quota_remaining / total,
            latency: sanitized.latency / total,
            cost_lru: sanitized.cost_lru / total,
        }
    }

    fn as_reason_json(self) -> Value {
        json!({
            "manual_priority": self.manual_priority,
            "health": self.health,
            "probe_freshness": self.probe_freshness,
            "quota_remaining": self.quota_remaining,
            "latency": self.latency,
            "cost_lru": self.cost_lru
        })
    }
}

#[derive(Debug, Clone, Copy, PartialEq)]
pub struct PoolMemberScoreRules {
    pub weights: PoolMemberScoreWeights,
    pub probe_freshness_ttl_seconds: u64,
    pub unschedulable_score_cap: f64,
    pub probe_failure_penalty: f64,
    pub request_failure_penalty: f64,
    pub probe_failure_cooldown_threshold: u64,
    /// 快过期积分窗口（秒）。**0 = 关闭分桶**（等价面板 `expiring_soon` 填空/`"0"`）。
    pub expiring_soon_seconds: u64,
    /// 快过期加分。**0 = 关闭优先**（等价面板 `prefer_expiring=false`）。
    pub expiring_credit_bonus: f64,
    /// 闲置补偿：每小时未用增加的权重（面板 `idle_weight_per_hour`，默认 **0.5**）。
    pub idle_weight_per_hour: f64,
    /// 闲置补偿封顶（面板 `idle_weight_max`，默认 **5.0**）。**0 = 关闭闲置补偿**。
    pub idle_weight_max: f64,
}

impl Default for PoolMemberScoreRules {
    fn default() -> Self {
        Self {
            weights: PoolMemberScoreWeights::default(),
            probe_freshness_ttl_seconds: PROBE_FRESHNESS_TTL_SECONDS,
            unschedulable_score_cap: UNSCHEDULABLE_SCORE_CAP,
            probe_failure_penalty: PROBE_FAILURE_PENALTY,
            request_failure_penalty: REQUEST_FAILURE_PENALTY,
            probe_failure_cooldown_threshold: PROBE_FAILURE_COOLDOWN_THRESHOLD,
            expiring_soon_seconds: EXPIRING_SOON_SECONDS,
            expiring_credit_bonus: EXPIRING_CREDIT_BONUS,
            idle_weight_per_hour: IDLE_WEIGHT_PER_HOUR,
            idle_weight_max: IDLE_WEIGHT_MAX,
        }
    }
}

impl PoolMemberScoreRules {
    pub fn effective(self) -> Self {
        let defaults = Self::default();
        Self {
            weights: self.weights.normalized(),
            probe_freshness_ttl_seconds: if self.probe_freshness_ttl_seconds == 0 {
                defaults.probe_freshness_ttl_seconds
            } else {
                self.probe_freshness_ttl_seconds
            },
            unschedulable_score_cap: if self.unschedulable_score_cap.is_finite() {
                self.unschedulable_score_cap.clamp(0.0, 1.0)
            } else {
                defaults.unschedulable_score_cap
            },
            probe_failure_penalty: if self.probe_failure_penalty.is_finite() {
                self.probe_failure_penalty.clamp(0.0, 1.0)
            } else {
                defaults.probe_failure_penalty
            },
            request_failure_penalty: if self.request_failure_penalty.is_finite() {
                self.request_failure_penalty.clamp(0.0, 1.0)
            } else {
                defaults.request_failure_penalty
            },
            probe_failure_cooldown_threshold: self.probe_failure_cooldown_threshold,
            // 窗口**不做**默认替换：0 是「关闭分桶」的显式语义（面板同款）。
            expiring_soon_seconds: self.expiring_soon_seconds,
            expiring_credit_bonus: if self.expiring_credit_bonus.is_finite() {
                self.expiring_credit_bonus.clamp(0.0, 1.0)
            } else {
                defaults.expiring_credit_bonus
            },
            idle_weight_per_hour: if self.idle_weight_per_hour.is_finite() {
                self.idle_weight_per_hour.max(0.0)
            } else {
                defaults.idle_weight_per_hour
            },
            // 0 是「关闭闲置补偿」的显式语义（面板同款，不做默认替换）。
            idle_weight_max: if self.idle_weight_max.is_finite() {
                self.idle_weight_max.max(0.0)
            } else {
                defaults.idle_weight_max
            },
        }
    }
}

#[derive(Debug, Clone)]
pub struct PoolMemberScoreInput {
    pub identity: PoolMemberIdentity,
    pub scope: PoolScoreScope,
    pub internal_priority: i32,
    pub is_active: bool,
    pub health_score: Option<f64>,
    pub quota_usage_ratio: Option<f64>,
    pub quota_exhausted: bool,
    /// 配置窗口内即将过期的可用积分（`credits` 的子集）。**0 = 无快过期批次**。
    ///
    /// 面板等价物：`entry.creditsExpiring`——余额刷新时按套餐真实 `CycleEndTime`
    /// （Aether 侧为 `packages[].expires_at`）分桶；且要求到期时刻**仍在未来**
    /// （面板 `expiringNow`）。调用方负责算好这个数，打分器只做「有则加分」。
    pub expiring_credits: i64,
    pub account_blocked: bool,
    pub oauth_invalid_reason: Option<String>,
    pub success_count: u64,
    pub error_count: u64,
    pub total_response_time_ms: u64,
    pub total_tokens: u64,
    pub total_cost_usd: f64,
    pub last_used_at: Option<u64>,
    pub last_probe_success_at: Option<u64>,
    pub probe_failure_count: u64,
    pub probe_status: PoolMemberProbeStatus,
    pub now_unix_secs: u64,
}

#[derive(Debug, Clone, PartialEq)]
pub struct PoolMemberScoreOutput {
    pub score: f64,
    pub hard_state: PoolMemberHardState,
    pub score_reason: Value,
}

pub fn score_pool_member(input: &PoolMemberScoreInput) -> PoolMemberScoreOutput {
    score_pool_member_with_rules(input, PoolMemberScoreRules::default())
}

pub fn score_pool_member_with_rules(
    input: &PoolMemberScoreInput,
    rules: PoolMemberScoreRules,
) -> PoolMemberScoreOutput {
    let rules = rules.effective();
    let weights = rules.weights;
    let hard_state = derive_hard_state(input, &rules);
    let manual_priority = manual_priority_score(input.internal_priority);
    let health = input.health_score.unwrap_or(0.5).clamp(0.0, 1.0);
    let probe_freshness = probe_freshness_score_with_ttl(
        input.last_probe_success_at,
        input.probe_status,
        input.now_unix_secs,
        rules.probe_freshness_ttl_seconds,
    );
    let quota_remaining = input
        .quota_usage_ratio
        .map(|ratio| 1.0 - ratio.clamp(0.0, 1.0))
        .unwrap_or(0.5);
    let latency = latency_score(input.success_count, input.total_response_time_ms);
    let cost_lru = cost_lru_score(input.total_cost_usd, input.total_tokens, input.last_used_at);

    let weighted_score = manual_priority * weights.manual_priority
        + health * weights.health
        + probe_freshness * weights.probe_freshness
        + quota_remaining * weights.quota_remaining
        + latency * weights.latency
        + cost_lru * weights.cost_lru;
    let probe_failure_penalty =
        (input.probe_failure_count.min(10) as f64 * rules.probe_failure_penalty).min(0.5);
    let request_failure_penalty =
        (input.error_count.min(20) as f64 * rules.request_failure_penalty).min(0.5);
    let total_penalty = (probe_failure_penalty + request_failure_penalty).min(1.0);
    // 快过期加分：温和偏好，不是硬优先（面板 `prefer_expiring` 的等价物）。
    // 放在惩罚之后、不可调度上限之前——所以它**不会**把不可调度的账号抬起来。
    let expiring_bonus = if input.expiring_credits > 0 {
        rules.expiring_credit_bonus
    } else {
        0.0
    };
    // 闲置补偿（面板 `idle_weight_per_hour` / `idle_weight_max`）：每小时未用 +0.5、封顶 5.0。
    //
    // **与面板的一处有意差异** ✗：从未使用过的账号面板按「满额闲置」计（全新号天然占优 ✓），
    // 这里按 **0** 计 —— 因为 Aether 的 `last_used_at` 缺失既可能是「全新号」也可能是
    // 「数据未回填」，满额补偿会让一批无历史数据的账号被突然抬高，风险大于收益。
    // 影响面很小：池内老账号都有 `last_used_at`，补偿照常生效。
    let idle_seconds = input
        .last_used_at
        .map(|last_used_at| input.now_unix_secs.saturating_sub(last_used_at))
        .unwrap_or(0);
    let idle_bonus = if rules.idle_weight_max <= 0.0 || input.last_used_at.is_none() {
        0.0
    } else {
        (idle_seconds as f64 / 3600.0 * rules.idle_weight_per_hour).min(rules.idle_weight_max)
    };
    let mut score = weighted_score - total_penalty + expiring_bonus + idle_bonus;
    if !hard_state.schedulable() {
        score = score.min(rules.unschedulable_score_cap);
    }
    score = score.clamp(0.0, 1.0);

    PoolMemberScoreOutput {
        score,
        hard_state,
        score_reason: json!({
            "weights": weights.as_reason_json(),
            "factors": {
                "manual_priority": manual_priority,
                "health": health,
                "probe_freshness": probe_freshness,
                "quota_remaining": quota_remaining,
                "latency": latency,
                "cost_lru": cost_lru,
                "expiring_credits": input.expiring_credits,
                "expiring_bonus": expiring_bonus,
                "idle_seconds": idle_seconds,
                "idle_bonus": idle_bonus
            },
            "rules": {
                "probe_freshness_ttl_seconds": rules.probe_freshness_ttl_seconds,
                "unschedulable_score_cap": rules.unschedulable_score_cap,
                "probe_failure_penalty": rules.probe_failure_penalty,
                "request_failure_penalty": rules.request_failure_penalty,
                "probe_failure_cooldown_threshold": rules.probe_failure_cooldown_threshold,
                "expiring_soon_seconds": rules.expiring_soon_seconds,
                "expiring_credit_bonus": rules.expiring_credit_bonus,
                "idle_weight_per_hour": rules.idle_weight_per_hour,
                "idle_weight_max": rules.idle_weight_max
            },
            "penalties": {
                "probe_failure": probe_failure_penalty,
                "request_failure": request_failure_penalty,
                "total": total_penalty
            },
            "hard_state": hard_state.as_database(),
            "score_version": POOL_SCORE_VERSION
        }),
    }
}

fn finite_non_negative(value: f64) -> f64 {
    if value.is_finite() {
        value.max(0.0)
    } else {
        0.0
    }
}

fn derive_hard_state(
    input: &PoolMemberScoreInput,
    rules: &PoolMemberScoreRules,
) -> PoolMemberHardState {
    if !input.is_active {
        return PoolMemberHardState::Inactive;
    }
    if let Some(reason) = input.oauth_invalid_reason.as_deref() {
        let reason = reason.to_ascii_lowercase();
        if reason.contains("ban") || reason.contains("blocked") || reason.contains("suspended") {
            return PoolMemberHardState::Banned;
        }
        return PoolMemberHardState::AuthInvalid;
    }
    if input.account_blocked {
        return PoolMemberHardState::Banned;
    }
    if input.quota_exhausted {
        return PoolMemberHardState::QuotaExhausted;
    }
    if input.probe_status == PoolMemberProbeStatus::Failed
        && rules.probe_failure_cooldown_threshold > 0
        && input.probe_failure_count >= rules.probe_failure_cooldown_threshold
    {
        return PoolMemberHardState::Cooldown;
    }
    if input.health_score.is_some() || input.probe_status == PoolMemberProbeStatus::Ok {
        PoolMemberHardState::Available
    } else {
        PoolMemberHardState::Unknown
    }
}

fn manual_priority_score(internal_priority: i32) -> f64 {
    (1.0 - (f64::from(internal_priority).clamp(0.0, 100.0) / 100.0)).clamp(0.0, 1.0)
}

pub fn probe_freshness_score(
    last_probe_success_at: Option<u64>,
    probe_status: PoolMemberProbeStatus,
    now_unix_secs: u64,
) -> f64 {
    probe_freshness_score_with_ttl(
        last_probe_success_at,
        probe_status,
        now_unix_secs,
        PROBE_FRESHNESS_TTL_SECONDS,
    )
}

pub fn probe_freshness_score_with_ttl(
    last_probe_success_at: Option<u64>,
    probe_status: PoolMemberProbeStatus,
    now_unix_secs: u64,
    ttl_seconds: u64,
) -> f64 {
    if probe_status != PoolMemberProbeStatus::Ok {
        return 0.0;
    }
    let Some(success_at) = last_probe_success_at else {
        return 0.0;
    };
    let ttl_seconds = ttl_seconds.max(1);
    let age = now_unix_secs.saturating_sub(success_at);
    if age >= ttl_seconds {
        0.0
    } else {
        1.0 - (age as f64 / ttl_seconds as f64)
    }
}

fn latency_score(success_count: u64, total_response_time_ms: u64) -> f64 {
    if success_count == 0 || total_response_time_ms == 0 {
        return 0.5;
    }
    let avg = total_response_time_ms as f64 / success_count as f64;
    if avg <= 500.0 {
        1.0
    } else if avg >= 60_000.0 {
        0.0
    } else {
        1.0 - ((avg - 500.0) / 59_500.0)
    }
}

fn cost_lru_score(total_cost_usd: f64, total_tokens: u64, last_used_at: Option<u64>) -> f64 {
    let cost_penalty = if total_cost_usd.is_finite() {
        (total_cost_usd.max(0.0) / 100.0).min(0.5)
    } else {
        0.0
    };
    let token_penalty = (total_tokens as f64 / 10_000_000.0).min(0.25);
    let lru_bonus = if last_used_at.unwrap_or(0) == 0 {
        0.25
    } else {
        0.0
    };
    (0.75 - cost_penalty - token_penalty + lru_bonus).clamp(0.0, 1.0)
}

#[cfg(test)]
mod tests {
    use super::*;
    use aether_data_contracts::repository::pool_scores::{
        POOL_KIND_PROVIDER_KEY_POOL, POOL_MEMBER_KIND_PROVIDER_API_KEY, POOL_SCORE_SCOPE_KIND_MODEL,
    };

    fn input() -> PoolMemberScoreInput {
        PoolMemberScoreInput {
            expiring_credits: 0,
            identity: PoolMemberIdentity {
                pool_kind: POOL_KIND_PROVIDER_KEY_POOL.to_string(),
                pool_id: "provider-1".to_string(),
                member_kind: POOL_MEMBER_KIND_PROVIDER_API_KEY.to_string(),
                member_id: "key-1".to_string(),
            },
            scope: PoolScoreScope {
                capability: "openai:responses".to_string(),
                scope_kind: POOL_SCORE_SCOPE_KIND_MODEL.to_string(),
                scope_id: Some("model-1".to_string()),
            },
            internal_priority: 10,
            is_active: true,
            health_score: Some(1.0),
            quota_usage_ratio: Some(0.1),
            quota_exhausted: false,
            account_blocked: false,
            oauth_invalid_reason: None,
            success_count: 10,
            error_count: 0,
            total_response_time_ms: 2_000,
            total_tokens: 10,
            total_cost_usd: 0.01,
            last_used_at: None,
            last_probe_success_at: Some(1_000),
            probe_failure_count: 0,
            probe_status: PoolMemberProbeStatus::Ok,
            now_unix_secs: 1_000,
        }
    }

    #[test]
    fn hard_state_caps_unavailable_member_score() {
        let mut input = input();
        input.oauth_invalid_reason = Some("token invalid".to_string());

        let output = score_pool_member(&input);

        assert_eq!(output.hard_state, PoolMemberHardState::AuthInvalid);
        assert!(output.score <= 0.05);
    }

    #[test]
    fn probe_freshness_has_ttl() {
        assert_eq!(
            probe_freshness_score(Some(1_000), PoolMemberProbeStatus::Ok, 1_000),
            1.0
        );
        assert_eq!(
            probe_freshness_score(
                Some(1_000),
                PoolMemberProbeStatus::Ok,
                1_000 + PROBE_FRESHNESS_TTL_SECONDS
            ),
            0.0
        );
    }

    #[test]
    fn custom_rules_change_weights_and_probe_ttl() {
        let mut input = input();
        input.last_probe_success_at = Some(1_000);
        input.now_unix_secs = 1_900;
        let rules = PoolMemberScoreRules {
            idle_weight_per_hour: 0.0,
            idle_weight_max: 0.0,
            expiring_soon_seconds: 0,
            expiring_credit_bonus: 0.0,
            weights: PoolMemberScoreWeights {
                manual_priority: 0.0,
                health: 0.0,
                probe_freshness: 1.0,
                quota_remaining: 0.0,
                latency: 0.0,
                cost_lru: 0.0,
            },
            probe_freshness_ttl_seconds: 1_000,
            unschedulable_score_cap: 0.05,
            probe_failure_penalty: 0.0,
            request_failure_penalty: 0.0,
            probe_failure_cooldown_threshold: PROBE_FAILURE_COOLDOWN_THRESHOLD,
        };

        let output = score_pool_member_with_rules(&input, rules);

        assert!((output.score - 0.1).abs() < 0.000_001);
        assert_eq!(
            output.score_reason["rules"]["probe_freshness_ttl_seconds"],
            1_000
        );
        assert_eq!(output.score_reason["weights"]["probe_freshness"], 1.0);
    }

    #[test]
    fn custom_rules_normalize_weights() {
        let rules = PoolMemberScoreRules {
            idle_weight_per_hour: 0.0,
            idle_weight_max: 0.0,
            expiring_soon_seconds: 0,
            expiring_credit_bonus: 0.0,
            weights: PoolMemberScoreWeights {
                manual_priority: 2.0,
                health: 2.0,
                probe_freshness: 0.0,
                quota_remaining: 0.0,
                latency: -1.0,
                cost_lru: f64::NAN,
            },
            probe_freshness_ttl_seconds: 0,
            unschedulable_score_cap: f64::INFINITY,
            probe_failure_penalty: f64::NAN,
            request_failure_penalty: f64::INFINITY,
            probe_failure_cooldown_threshold: 2,
        }
        .effective();

        assert_eq!(rules.weights.manual_priority, 0.5);
        assert_eq!(rules.weights.health, 0.5);
        assert_eq!(
            rules.probe_freshness_ttl_seconds,
            PROBE_FRESHNESS_TTL_SECONDS
        );
        assert_eq!(rules.unschedulable_score_cap, UNSCHEDULABLE_SCORE_CAP);
        assert_eq!(rules.probe_failure_penalty, PROBE_FAILURE_PENALTY);
        assert_eq!(rules.request_failure_penalty, REQUEST_FAILURE_PENALTY);
        assert_eq!(rules.probe_failure_cooldown_threshold, 2);
    }

    #[test]
    fn custom_rules_preserve_zero_weight_total() {
        let rules = PoolMemberScoreRules {
            idle_weight_per_hour: 0.0,
            idle_weight_max: 0.0,
            weights: PoolMemberScoreWeights {
                manual_priority: 0.0,
                health: 0.0,
                probe_freshness: 0.0,
                quota_remaining: 0.0,
                latency: 0.0,
                cost_lru: 0.0,
            },
            ..PoolMemberScoreRules::default()
        }
        .effective();

        assert_eq!(
            rules.weights,
            PoolMemberScoreWeights {
                manual_priority: 0.0,
                health: 0.0,
                probe_freshness: 0.0,
                quota_remaining: 0.0,
                latency: 0.0,
                cost_lru: 0.0,
            }
        );
    }

    #[test]
    fn repeated_probe_failures_move_member_to_cooldown() {
        let mut input = input();
        input.probe_status = PoolMemberProbeStatus::Failed;
        input.probe_failure_count = 3;

        let output = score_pool_member(&input);

        assert_eq!(output.hard_state, PoolMemberHardState::Cooldown);
        assert!(output.score <= UNSCHEDULABLE_SCORE_CAP);
        assert_eq!(
            output.score_reason["rules"]["probe_failure_cooldown_threshold"],
            PROBE_FAILURE_COOLDOWN_THRESHOLD
        );
    }

    #[test]
    fn probe_and_request_failures_penalize_schedulable_score() {
        let mut input = input();
        input.last_probe_success_at = None;
        input.probe_status = PoolMemberProbeStatus::Never;
        input.probe_failure_count = 1;
        input.error_count = 2;
        let rules = PoolMemberScoreRules {
            idle_weight_per_hour: 0.0,
            idle_weight_max: 0.0,
            probe_failure_penalty: 0.1,
            request_failure_penalty: 0.01,
            probe_failure_cooldown_threshold: 3,
            ..PoolMemberScoreRules::default()
        };

        let output = score_pool_member_with_rules(&input, rules);

        assert_eq!(output.hard_state, PoolMemberHardState::Available);
        assert_eq!(output.score_reason["penalties"]["probe_failure"], 0.1);
        assert_eq!(output.score_reason["penalties"]["request_failure"], 0.02);
    }

    #[test]
    fn expiring_credit_bonus_is_gentle_and_capped_by_unschedulable_cap() {
        let mut input = input();
        let rules = PoolMemberScoreRules::default();
        let baseline = score_pool_member_with_rules(&input, rules).score;
        assert_eq!(input.expiring_credits, 0);

        // 有快过期积分 → 加分（0..1 域内封顶）
        input.expiring_credits = 500;
        let boosted = score_pool_member_with_rules(&input, rules).score;
        assert!((boosted - (baseline + EXPIRING_CREDIT_BONUS).min(1.0)).abs() < 1e-9);

        // 关闭加分（= 面板 prefer_expiring=false）→ 与基线逐字节一致
        let mut off = rules;
        off.expiring_credit_bonus = 0.0;
        assert!((score_pool_member_with_rules(&input, off).score - baseline).abs() < 1e-9);

        // 窗口 0 只是「不算分桶」，不影响打分器：分桶由调用方给出
        let mut no_window = rules;
        no_window.expiring_soon_seconds = 0;
        assert!((score_pool_member_with_rules(&input, no_window).score - boosted).abs() < 1e-9);

        // 不可调度账号**不会**被加分抬起来
        input.is_active = false;
        assert!(score_pool_member_with_rules(&input, rules).score <= UNSCHEDULABLE_SCORE_CAP);
    }

    #[test]
    fn expiring_bucket_flags_appear_in_score_reason() {
        let mut input = input();
        input.expiring_credits = 42;
        let reason =
            score_pool_member_with_rules(&input, PoolMemberScoreRules::default()).score_reason;
        assert_eq!(reason["factors"]["expiring_credits"], 42);
        assert_eq!(reason["factors"]["expiring_bonus"], EXPIRING_CREDIT_BONUS);
        assert_eq!(
            reason["rules"]["expiring_soon_seconds"],
            EXPIRING_SOON_SECONDS
        );
        assert_eq!(
            reason["rules"]["expiring_credit_bonus"],
            EXPIRING_CREDIT_BONUS
        );
    }

    /// 闲置补偿（面板 `idle_weight_per_hour` 0.5 / `idle_weight_max` 5.0）：
    /// 按小时线性增长、封顶；从未使用过按 0 计（与面板的有意差异，见实现处注释）。
    #[test]
    fn idle_bonus_grows_hourly_and_caps() {
        let mut input = input();
        let rules = PoolMemberScoreRules::default();
        assert_eq!(rules.idle_weight_per_hour, IDLE_WEIGHT_PER_HOUR);
        assert_eq!(rules.idle_weight_max, IDLE_WEIGHT_MAX);

        // 从未使用 → 不补偿（与面板不同，取保守口径）
        input.last_used_at = None;
        let no_history = score_pool_member_with_rules(&input, rules).score_reason;
        assert_eq!(no_history["factors"]["idle_seconds"], 0);
        assert_eq!(no_history["factors"]["idle_bonus"], 0.0);

        // 刚用过 → 0；用满 2 小时 → 1.0；用满 10 小时 → 封顶 5.0
        input.now_unix_secs = 1_000_000;
        let now = input.now_unix_secs;
        for (idle_hours, expected) in [
            (0u64, 0.0f64),
            (2, 1.0),
            (10, IDLE_WEIGHT_MAX),
            (100, IDLE_WEIGHT_MAX),
        ] {
            input.last_used_at = Some(now - idle_hours * 3600);
            let reason = score_pool_member_with_rules(&input, rules).score_reason;
            assert_eq!(reason["factors"]["idle_seconds"], idle_hours * 3600);
            let bonus = reason["factors"]["idle_bonus"].as_f64().expect("bonus");
            assert!(
                (bonus - expected.min(IDLE_WEIGHT_MAX)).abs() < 1e-9,
                "idle_hours={idle_hours} bonus={bonus} expected={expected}"
            );
        }

        // 关闭闲置补偿（idle_weight_max = 0）→ 与关闭前同分
        let mut off = rules;
        off.idle_weight_max = 0.0;
        input.last_used_at = Some(now - 10 * 3600);
        let off_reason = score_pool_member_with_rules(&input, off).score_reason;
        assert_eq!(off_reason["factors"]["idle_bonus"], 0.0);

        // 规则回显，便于真机核对
        let reason = score_pool_member_with_rules(&input, rules).score_reason;
        assert_eq!(
            reason["rules"]["idle_weight_per_hour"],
            IDLE_WEIGHT_PER_HOUR
        );
        assert_eq!(reason["rules"]["idle_weight_max"], IDLE_WEIGHT_MAX);
    }
}
