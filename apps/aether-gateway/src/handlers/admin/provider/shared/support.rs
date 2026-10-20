use crate::handlers::admin::request::AdminAppState;
use crate::LocalProviderDeleteTaskState;
use aether_pool_core::PoolMemberScoreRules;
use serde_json::json;
use std::collections::{BTreeMap, BTreeSet};

pub(crate) const ADMIN_PROVIDER_MAPPING_PREVIEW_MAX_KEYS: usize = 200;
pub(crate) const ADMIN_PROVIDER_MAPPING_PREVIEW_MAX_MODELS: usize = 500;
pub(crate) const ADMIN_PROVIDER_MAPPING_PREVIEW_FETCH_LIMIT: usize = 10_000;
pub(crate) const ADMIN_PROVIDER_POOL_SCAN_BATCH: u64 = 200;
pub(crate) const ADMIN_PROVIDER_POOL_QUOTA_PROBE_ACTIVE_SET_PREFIX: &str =
    "ap:quota_probe:active_members";
pub(crate) const ADMIN_PROVIDER_OAUTH_DATA_UNAVAILABLE_DETAIL: &str =
    "Admin provider OAuth data unavailable";
pub(crate) const PROVIDER_MAX_TRANSFER_COUNT_CONFIG_KEY: &str = "max_transfer_count";
pub(crate) const PROVIDER_MAX_TRANSFER_TIMEOUT_SECONDS_CONFIG_KEY: &str =
    "max_transfer_timeout_seconds";

pub(crate) fn normalize_provider_transfer_limit(
    value: i64,
    field_name: &str,
) -> Result<u64, String> {
    u64::try_from(value).map_err(|_| format!("{field_name} 必须是非负整数"))
}

pub(crate) fn normalize_provider_transfer_limit_json(
    value: &serde_json::Value,
    field_name: &str,
) -> Result<u64, String> {
    value
        .as_u64()
        .ok_or_else(|| format!("{field_name} 必须是非负整数"))
}

pub(crate) fn provider_transfer_limit_from_config(
    config: Option<&serde_json::Map<String, serde_json::Value>>,
    field_name: &str,
) -> u64 {
    config
        .and_then(|config| config.get(field_name))
        .and_then(serde_json::Value::as_u64)
        .unwrap_or(0)
}

pub(crate) fn admin_provider_pool_quota_probe_active_members_key(provider_id: &str) -> String {
    format!("{ADMIN_PROVIDER_POOL_QUOTA_PROBE_ACTIVE_SET_PREFIX}:{provider_id}")
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct AdminProviderPoolSchedulingPreset {
    pub(crate) preset: String,
    pub(crate) enabled: bool,
    pub(crate) mode: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct AdminProviderPoolUnschedulableRule {
    pub(crate) keyword: String,
    pub(crate) duration_minutes: u64,
}

#[derive(Debug, Clone)]
pub(crate) struct AdminProviderPoolConfig {
    pub(crate) scheduling_presets: Vec<AdminProviderPoolSchedulingPreset>,
    pub(crate) unschedulable_rules: Vec<AdminProviderPoolUnschedulableRule>,
    pub(crate) lru_enabled: bool,
    pub(crate) skip_exhausted_accounts: bool,
    pub(crate) reserve_minimum_quota: bool,
    /// 积分保底（面板 `pool.credit_floor`）：余额**严格低于**该值的账号不接收费模型；
    /// `0` = 关闭。落在池内**硬排除**上（`quota_hard_blocked`）。
    pub(crate) credit_floor: i64,
    /// 池内账号是否**也计入** key 级熔断（面板的口径：池就是全量账号，熔断对所有账号生效）。
    ///
    /// **默认 `true` = 面板口径** ✓（用户 2026-10-16 确认「面板默认即默认」）；设 `false` 回到
    /// Aether 旧行为（池内只降健康分）。
    pub(crate) pool_counts_toward_circuit_breaker: bool,
    /// 连续失败多少次触发 key 级熔断（面板 `breaker_threshold`）。
    ///
    /// **默认 `3` = 面板口径** ✓；显式 `0` 才回到 Aether 历史值 8（见 `orchestration/health.rs`）。
    pub(crate) breaker_threshold: u64,
    /// **单账号最大在途**（并发，面板 `max_in_flight`，面板默认 **3**）—— 所有域的兜底档
    /// （global 档优先 ✓）；`0` = 不分档（回落账号自身上限）。
    pub(crate) max_in_flight: usize,
    /// 熔断**基础**探测间隔（分钟，面板 `breaker_cooldown`，面板默认 30m）。
    ///
    /// `0` = 用 Aether 历史默认 **1 分钟**（不静默改变既有部署行为）。
    pub(crate) breaker_cooldown_minutes: u64,
    /// 熔断指数退避**上限**（分钟，面板 `breaker_cooldown_max`，面板默认 6h）。
    ///
    /// `0` = 用 Aether 历史默认 **32 分钟**（key 字段仍可通过 `max_probe_interval_minutes` 压低）；
    /// 显式配置时受 24h 安全天花板夹住，防误配成「永不重试」。
    pub(crate) breaker_cooldown_max_minutes: u64,
    /// costTier 条件探索窗口（秒）：面板 `cost_explore_interval`，面板默认 **1800（30m）**。
    ///
    /// `0`（或缺省）= **关停**。含义：当**当前最优是「已观测免费」档**、且池中存在
    /// **「无观测」档**账号、且该账号距上次探索已超过本窗口时，改选未被观测的账号去探路。
    pub(crate) cost_explore_interval_seconds: u64,
    /// WAF **出口 IP 级**拦截窗口（秒，面板 `internal/server/wafip.go`：滑动窗与激活时长同值 ✓）。
    ///
    /// 窗口内 ≥2 个**不同账号**命中 WAF 403 → 判定 IP 级拦截，激活期内选号层**快速失败**
    /// （不再换号打同一个被拦的出口 IP ✓）。**默认 60**（面板同值 ✓）；`0` = 关停。
    pub(crate) waf_ip_cooldown_seconds: u64,
    /// WAF 出口 IP 拦截期是否**连新请求一起挡**（默认 `true` = 现状 ✓）。
    ///
    /// 面板只停「本次请求内的轮转」✓；Aether 默认更严一档：激活期内**任何新请求**都在选号层
    /// 快速失败（不再去打那个已被拦的出口 IP ✓）。想完全对齐面板 → 置 `false` ✓
    /// （账号级软冷却仍在，所以同一账号也不会被反复重试 ✓）。
    pub(crate) waf_ip_block_new_requests: bool,
    pub(crate) sticky_session_ttl_seconds: u64,
    pub(crate) latency_window_seconds: u64,
    pub(crate) latency_sample_limit: u64,
    pub(crate) cost_window_seconds: u64,
    pub(crate) cost_limit_per_key_tokens: Option<u64>,
    pub(crate) rate_limit_cooldown_seconds: u64,
    pub(crate) overload_cooldown_seconds: u64,
    pub(crate) probing_enabled: bool,
    pub(crate) probing_target_percent: Option<f64>,
    pub(crate) probing_target_count: Option<u64>,
    pub(crate) probe_concurrency: u64,
    pub(crate) account_self_check_enabled: bool,
    pub(crate) account_self_check_interval_minutes: u64,
    pub(crate) account_self_check_concurrency: u64,
    pub(crate) score_top_n: u64,
    pub(crate) score_fallback_scan_limit: u64,
    pub(crate) score_rules: PoolMemberScoreRules,
    pub(crate) stream_timeout_threshold: u64,
    pub(crate) stream_timeout_window_seconds: u64,
    pub(crate) stream_timeout_cooldown_seconds: u64,
    /// 连败降权阈值：**未分类错误**连败 N 次后临时出池（0 = 关闭）。
    /// 只作用于此前完全空转的「未分类错误」分支，已分类路径（401/402/403/400/429/529/5xx…）行为不变。
    pub(crate) request_demote_threshold: u64,
    /// 连败降权基础出池时长（秒）。
    pub(crate) request_demote_seconds: u64,
    /// 连败降权退避上限（秒）：重复连败按 2 的幂放大到此上限为止。
    pub(crate) request_demote_max_seconds: u64,
    /// 429 软限流退避上限（秒，面板 `softRateMax`）：连续 429 且**上游未给 Retry-After** 时，
    /// 把基础冷却按 2 的幂放大到此上限；`<= rate_limit_cooldown_seconds` = 未开启退避（旧行为）。
    pub(crate) rate_limit_cooldown_max_seconds: u64,
}

#[derive(Debug, Default)]
pub(crate) struct AdminProviderPoolRuntimeState {
    pub(crate) total_sticky_sessions: usize,
    pub(crate) sticky_sessions_by_key: BTreeMap<String, usize>,
    pub(crate) sticky_bound_key_id: Option<String>,
    pub(crate) active_probe_member_ids: BTreeSet<String>,
    pub(crate) provider_in_flight: usize,
    pub(crate) provider_ema_in_flight: f64,
    pub(crate) provider_desired_hot: usize,
    pub(crate) provider_burst_pending: bool,
    pub(crate) cooldown_reason_by_key: BTreeMap<String, String>,
    pub(crate) cooldown_ttl_by_key: BTreeMap<String, u64>,
    pub(crate) cost_window_usage_by_key: BTreeMap<String, u64>,
    pub(crate) latency_avg_ms_by_key: BTreeMap<String, f64>,
    pub(crate) lru_score_by_key: BTreeMap<String, f64>,
}

pub(crate) fn build_admin_provider_delete_task_payload(
    task: &LocalProviderDeleteTaskState,
) -> serde_json::Value {
    json!({
        "task_id": task.task_id,
        "provider_id": task.provider_id,
        "status": task.status,
        "stage": task.stage,
        "total_keys": task.total_keys,
        "deleted_keys": task.deleted_keys,
        "total_endpoints": task.total_endpoints,
        "deleted_endpoints": task.deleted_endpoints,
        "message": task.message,
    })
}

pub(crate) fn put_admin_provider_delete_task(
    state: &AdminAppState<'_>,
    task: &LocalProviderDeleteTaskState,
) {
    state.as_ref().put_provider_delete_task(task.clone());
}

pub(crate) fn normalize_provider_billing_type(value: &str) -> Result<String, String> {
    let normalized = value.trim().to_ascii_lowercase();
    match normalized.as_str() {
        "monthly_quota" | "pay_as_you_go" | "free_tier" => Ok(normalized),
        _ => Err("billing_type 仅支持 monthly_quota / pay_as_you_go / free_tier".to_string()),
    }
}

pub(crate) fn parse_optional_rfc3339_unix_secs(
    value: &str,
    field_name: &str,
) -> Result<u64, String> {
    let trimmed = value.trim();
    if trimmed.is_empty() {
        return Err(format!("{field_name} 不能为空"));
    }
    let parsed = chrono::DateTime::parse_from_rfc3339(trimmed)
        .map_err(|_| format!("{field_name} 必须是合法的 RFC3339 时间"))?;
    u64::try_from(parsed.timestamp()).map_err(|_| format!("{field_name} 超出有效时间范围"))
}
