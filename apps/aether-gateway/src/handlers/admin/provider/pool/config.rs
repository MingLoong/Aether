use crate::handlers::admin::provider::shared::support::{
    AdminProviderPoolConfig, AdminProviderPoolSchedulingPreset, AdminProviderPoolUnschedulableRule,
};
use aether_pool_core::{PoolMemberScoreRules, PoolMemberScoreWeights};
use serde_json::{Map, Value};

const POOL_ALLOWED_SCHEDULING_PRESETS: &[&str] = &[
    "lru",
    "cache_affinity",
    "load_balance",
    "single_account",
    "priority_first",
    "free_team_first",
    "free_first",
    "team_first",
    "plus_first",
    "pro_first",
    "health_first",
    "latency_first",
    "cost_first",
    "quota_balanced",
    "recent_refresh",
    "expiry_first",
];

fn json_u64(value: &Value) -> Option<u64> {
    value
        .as_u64()
        .or_else(|| value.as_i64().and_then(|raw| u64::try_from(raw).ok()))
}

fn json_f64(value: &Value) -> Option<f64> {
    value.as_f64().or_else(|| {
        value
            .as_str()
            .map(str::trim)
            .filter(|value| !value.is_empty())
            .and_then(|value| value.parse::<f64>().ok())
    })
}

fn parse_pool_probe_target_percent(pool_advanced: &Map<String, Value>) -> Option<f64> {
    pool_advanced
        .get("probing_target_percent")
        .or_else(|| pool_advanced.get("probing_active_target_percent"))
        .or_else(|| pool_advanced.get("active_probe_target_percent"))
        .and_then(json_f64)
        .filter(|value| value.is_finite() && *value > 0.0)
        .map(|value| value.clamp(0.0, 100.0))
}

fn parse_pool_probe_target_count(pool_advanced: &Map<String, Value>) -> Option<u64> {
    pool_advanced
        .get("probing_target_count")
        .or_else(|| pool_advanced.get("probing_active_target_count"))
        .or_else(|| pool_advanced.get("active_probe_target_count"))
        .and_then(json_u64)
        .filter(|value| *value > 0)
        .map(|value| value.min(100_000))
}

fn pool_score_weight(object: &Map<String, Value>, names: &[&str], current: f64) -> f64 {
    names
        .iter()
        .find_map(|name| {
            object
                .get(*name)
                .and_then(json_f64)
                .filter(|value| value.is_finite() && *value >= 0.0)
        })
        .unwrap_or(current)
}

fn parse_pool_score_weights(
    raw_weights: Option<&Map<String, Value>>,
    current: PoolMemberScoreWeights,
) -> PoolMemberScoreWeights {
    let Some(raw_weights) = raw_weights else {
        return current;
    };
    PoolMemberScoreWeights {
        manual_priority: pool_score_weight(
            raw_weights,
            &["manual_priority", "priority", "internal_priority"],
            current.manual_priority,
        ),
        health: pool_score_weight(raw_weights, &["health"], current.health),
        probe_freshness: pool_score_weight(
            raw_weights,
            &["probe_freshness", "freshness", "probe"],
            current.probe_freshness,
        ),
        quota_remaining: pool_score_weight(
            raw_weights,
            &["quota_remaining", "quota", "quota_available"],
            current.quota_remaining,
        ),
        latency: pool_score_weight(raw_weights, &["latency"], current.latency),
        cost_lru: pool_score_weight(
            raw_weights,
            &["cost_lru", "cost_remaining", "cost", "lru"],
            current.cost_lru,
        ),
    }
}

fn parse_pool_score_rules(pool_advanced: &Map<String, Value>) -> PoolMemberScoreRules {
    let mut rules = PoolMemberScoreRules::default();

    for key in ["score_weights", "pool_score_weights", "scoring_weights"] {
        rules.weights = parse_pool_score_weights(
            pool_advanced.get(key).and_then(Value::as_object),
            rules.weights,
        );
    }

    if let Some(score_rules) = pool_advanced
        .get("score_rules")
        .or_else(|| pool_advanced.get("pool_score_rules"))
        .and_then(Value::as_object)
    {
        rules.weights = parse_pool_score_weights(
            score_rules.get("weights").and_then(Value::as_object),
            rules.weights,
        );
        if let Some(ttl_seconds) = score_rules
            .get("probe_freshness_ttl_seconds")
            .or_else(|| score_rules.get("score_probe_freshness_ttl_seconds"))
            .and_then(json_u64)
            .filter(|value| *value > 0)
        {
            rules.probe_freshness_ttl_seconds = ttl_seconds.min(7 * 24 * 3600);
        }
        if let Some(cap) = score_rules
            .get("unschedulable_score_cap")
            .or_else(|| score_rules.get("hard_state_score_cap"))
            .and_then(json_f64)
            .filter(|value| value.is_finite())
        {
            rules.unschedulable_score_cap = cap.clamp(0.0, 1.0);
        }
        if let Some(penalty) = score_rules
            .get("probe_failure_penalty")
            .and_then(json_f64)
            .filter(|value| value.is_finite())
        {
            rules.probe_failure_penalty = penalty.clamp(0.0, 1.0);
        }
        if let Some(penalty) = score_rules
            .get("request_failure_penalty")
            .or_else(|| score_rules.get("runtime_failure_penalty"))
            .and_then(json_f64)
            .filter(|value| value.is_finite())
        {
            rules.request_failure_penalty = penalty.clamp(0.0, 1.0);
        }
        if let Some(threshold) = score_rules
            .get("probe_failure_cooldown_threshold")
            .or_else(|| score_rules.get("probe_failure_hard_state_threshold"))
            .and_then(json_u64)
        {
            rules.probe_failure_cooldown_threshold = threshold.min(100);
        }
    }

    // 快过期积分优先路由（面板 `pool.prefer_expiring` / `pool.expiring_soon`）：
    // 顶层键优先（面板名），其次 `score_rules.*`。
    let nested = pool_advanced
        .get("score_rules")
        .or_else(|| pool_advanced.get("pool_score_rules"))
        .and_then(Value::as_object);
    let pick = |name: &str| {
        pool_advanced
            .get(name)
            .or_else(|| nested.and_then(|rules| rules.get(name)))
    };
    if let Some(window_seconds) = pick("expiring_soon_seconds").and_then(json_u64) {
        // **0 是显式语义**：关闭分桶（等价面板 `expiring_soon` 填空 / `"0"`）。
        rules.expiring_soon_seconds = window_seconds.min(30 * 24 * 3600);
    }
    if let Some(bonus) = pick("expiring_credit_bonus")
        .and_then(json_f64)
        .filter(|value| value.is_finite())
    {
        rules.expiring_credit_bonus = bonus.clamp(0.0, 1.0);
    }
    // 面板 `prefer_expiring = false`：窗口照算（前端照展示），但**不加分**。
    if pick("prefer_expiring").and_then(Value::as_bool) == Some(false) {
        rules.expiring_credit_bonus = 0.0;
    }
    // 闲置补偿（面板 `pool.idle_weight_per_hour` 默认 0.5 / `pool.idle_weight_max` 默认 5.0）：
    // 顶层键优先，其次 `score_rules.*`；`idle_weight_max = 0` = 关闭闲置补偿（显式语义）。
    if let Some(per_hour) = pick("idle_weight_per_hour")
        .and_then(json_f64)
        .filter(|value| value.is_finite())
    {
        rules.idle_weight_per_hour = per_hour.clamp(0.0, 100.0);
    }
    if let Some(max) = pick("idle_weight_max")
        .and_then(json_f64)
        .filter(|value| value.is_finite())
    {
        rules.idle_weight_max = max.clamp(0.0, 100.0);
    }

    rules.effective()
}

fn normalize_pool_preset_mode(preset: &str, raw_mode: Option<&Value>) -> Option<String> {
    match preset {
        "cache_affinity" => Some(
            raw_mode
                .and_then(Value::as_str)
                .map(str::trim)
                .filter(|value| matches!(*value, "single_account" | "lru"))
                .unwrap_or("single_account")
                .to_string(),
        ),
        "free_team_first" | "free_first" | "team_first" | "plus_first" | "pro_first" => {
            let default_mode = match preset {
                "free_team_first" => "both",
                "free_first" => "free_only",
                "team_first" => "team_only",
                "plus_first" => "plus_only",
                "pro_first" => "pro_only",
                _ => unreachable!("preset covered by outer match"),
            };
            let normalized = raw_mode
                .and_then(Value::as_str)
                .map(str::trim)
                .filter(|value| !value.is_empty())
                .map(|value| value.to_ascii_lowercase())
                .filter(|value| match preset {
                    "free_team_first" => {
                        matches!(value.as_str(), "free_only" | "team_only" | "both")
                    }
                    "free_first" => value == "free_only",
                    "team_first" => value == "team_only",
                    "plus_first" => value == "plus_only",
                    "pro_first" => value == "pro_only",
                    _ => false,
                })
                .unwrap_or_else(|| default_mode.to_string());
            Some(normalized)
        }
        _ => None,
    }
}

fn parse_object_style_pool_scheduling_presets(
    presets: &[Value],
) -> Vec<AdminProviderPoolSchedulingPreset> {
    let mut normalized = Vec::new();
    let mut seen = std::collections::BTreeSet::new();

    for item in presets {
        let Some(object) = item.as_object() else {
            continue;
        };
        let Some(preset) = object
            .get("preset")
            .and_then(Value::as_str)
            .map(str::trim)
            .filter(|value| !value.is_empty())
            .map(|value| value.to_ascii_lowercase())
        else {
            continue;
        };
        if !POOL_ALLOWED_SCHEDULING_PRESETS.contains(&preset.as_str())
            || !seen.insert(preset.clone())
        {
            continue;
        }
        normalized.push(AdminProviderPoolSchedulingPreset {
            mode: normalize_pool_preset_mode(&preset, object.get("mode")),
            preset,
            enabled: object
                .get("enabled")
                .and_then(Value::as_bool)
                .unwrap_or(true),
        });
    }

    if normalized.is_empty() {
        vec![AdminProviderPoolSchedulingPreset {
            preset: "lru".to_string(),
            enabled: true,
            mode: None,
        }]
    } else {
        normalized
    }
}

fn parse_legacy_string_style_pool_scheduling_presets(
    raw_pool_advanced: &Map<String, Value>,
    presets: &[Value],
) -> Vec<AdminProviderPoolSchedulingPreset> {
    let lru_enabled = raw_pool_advanced
        .get("lru_enabled")
        .and_then(Value::as_bool)
        .unwrap_or(true);
    let mut normalized = vec![AdminProviderPoolSchedulingPreset {
        preset: "lru".to_string(),
        enabled: lru_enabled,
        mode: None,
    }];
    let mut seen = std::collections::BTreeSet::from(["lru".to_string()]);

    for item in presets {
        let Some(preset) = item
            .as_str()
            .map(str::trim)
            .filter(|value| !value.is_empty())
            .map(|value| value.to_ascii_lowercase())
        else {
            continue;
        };
        if preset == "lru"
            || !POOL_ALLOWED_SCHEDULING_PRESETS.contains(&preset.as_str())
            || !seen.insert(preset.clone())
        {
            continue;
        }
        normalized.push(AdminProviderPoolSchedulingPreset {
            preset,
            enabled: true,
            mode: None,
        });
    }

    normalized
}

fn parse_pool_scheduling_presets_from_legacy_fields(
    raw_pool_advanced: &Map<String, Value>,
) -> Vec<AdminProviderPoolSchedulingPreset> {
    if raw_pool_advanced
        .get("lru_enabled")
        .and_then(Value::as_bool)
        .unwrap_or(false)
    {
        vec![AdminProviderPoolSchedulingPreset {
            preset: "lru".to_string(),
            enabled: true,
            mode: None,
        }]
    } else {
        vec![AdminProviderPoolSchedulingPreset {
            preset: "cache_affinity".to_string(),
            enabled: true,
            mode: None,
        }]
    }
}

fn parse_pool_scheduling_presets(
    raw_pool_advanced: &Map<String, Value>,
) -> Vec<AdminProviderPoolSchedulingPreset> {
    match raw_pool_advanced
        .get("scheduling_presets")
        .and_then(Value::as_array)
    {
        Some(presets) if !presets.is_empty() => match presets.first() {
            Some(Value::Object(_)) => parse_object_style_pool_scheduling_presets(presets),
            Some(Value::String(_)) => {
                parse_legacy_string_style_pool_scheduling_presets(raw_pool_advanced, presets)
            }
            _ => parse_pool_scheduling_presets_from_legacy_fields(raw_pool_advanced),
        },
        _ => parse_pool_scheduling_presets_from_legacy_fields(raw_pool_advanced),
    }
}

fn parse_pool_unschedulable_rules(
    raw_pool_advanced: &Map<String, Value>,
) -> Vec<AdminProviderPoolUnschedulableRule> {
    raw_pool_advanced
        .get("unschedulable_rules")
        .and_then(Value::as_array)
        .into_iter()
        .flatten()
        .filter_map(|item| {
            let object = item.as_object()?;
            let keyword = object
                .get("keyword")
                .and_then(Value::as_str)
                .map(str::trim)
                .filter(|value| !value.is_empty())?;
            Some(AdminProviderPoolUnschedulableRule {
                keyword: keyword.to_string(),
                duration_minutes: object
                    .get("duration_minutes")
                    .and_then(json_u64)
                    .filter(|value| *value > 0)
                    .unwrap_or(5),
            })
        })
        .collect()
}

fn admin_provider_pool_lru_enabled(
    scheduling_presets: &[AdminProviderPoolSchedulingPreset],
) -> bool {
    scheduling_presets
        .iter()
        .any(|item| item.enabled && item.preset.eq_ignore_ascii_case("lru"))
}

pub(crate) fn admin_provider_pool_cache_affinity_enabled(
    pool_config: &AdminProviderPoolConfig,
) -> bool {
    let mut seen = std::collections::BTreeSet::new();
    for item in &pool_config.scheduling_presets {
        let preset = item.preset.trim().to_ascii_lowercase();
        if preset.is_empty() || !seen.insert(preset.clone()) {
            continue;
        }
        if !item.enabled {
            continue;
        }
        if matches!(
            preset.as_str(),
            "lru" | "cache_affinity" | "load_balance" | "single_account"
        ) {
            return preset == "cache_affinity";
        }
    }
    false
}

pub(crate) fn admin_provider_pool_config(
    provider: &aether_data_contracts::repository::provider_catalog::StoredProviderCatalogProvider,
) -> Option<AdminProviderPoolConfig> {
    admin_provider_pool_config_for_provider(&provider.provider_type, provider.config.as_ref())
}

/// 带 `provider_type` 的入口：**AMD 供应商永不接入号池**。
///
/// 号池接入的判据是 config 里有没有 `pool_advanced`，但 AMD 与 Cline 都不接号池：
/// AMD 走纯游标轮转（`crate::amd_rotation`），一旦被池接手，key 顺序会被池调度器改写，
/// 故障处理也从「失败就换下一把」变成池冷却。所以在**读取侧强制不认**——写入侧另有剥离
/// （create/update），存量的 `pool_advanced` 脏数据因此也自愈。
pub(crate) fn admin_provider_pool_config_for_provider(
    provider_type: &str,
    config: Option<&serde_json::Value>,
) -> Option<AdminProviderPoolConfig> {
    if crate::amd_rotation::provider_type_exempt_from_generic_pool(provider_type) {
        return None;
    }
    let mut pool_config = admin_provider_pool_config_from_config_value(config)?;
    // cline：独立调度。通用池的空配置默认 `cache_affinity`（粘性、钉死一把），cline 要的是
    // 轮询/分摊，所以按 `cline_strategy` 覆盖调度预设，关掉 cache_affinity 的粘性绑定。
    if provider_type
        .trim()
        .eq_ignore_ascii_case(aether_provider_transport::cline::PROVIDER_TYPE)
    {
        let raw_pool_advanced = config.and_then(|value| value.get("pool_advanced"));
        let strategy = crate::cline_pool::ClinePoolStrategy::from_config(raw_pool_advanced);
        let (preset, lru_enabled) = match strategy {
            crate::cline_pool::ClinePoolStrategy::Fill => ("single_account", false),
            crate::cline_pool::ClinePoolStrategy::LeastUsed => ("lru", true),
            crate::cline_pool::ClinePoolStrategy::Random
            | crate::cline_pool::ClinePoolStrategy::RoundRobin => ("load_balance", false),
        };
        pool_config.scheduling_presets = vec![AdminProviderPoolSchedulingPreset {
            preset: preset.to_string(),
            enabled: true,
            mode: None,
        }];
        pool_config.lru_enabled = lru_enabled;
    }
    Some(pool_config)
}

pub(crate) fn admin_provider_pool_config_from_config_value(
    config: Option<&serde_json::Value>,
) -> Option<AdminProviderPoolConfig> {
    let raw_pool_advanced = config
        .and_then(Value::as_object)
        .and_then(|config| config.get("pool_advanced"))?;

    let Some(pool_advanced) = raw_pool_advanced.as_object() else {
        return Some(AdminProviderPoolConfig {
            scheduling_presets: vec![AdminProviderPoolSchedulingPreset {
                preset: "cache_affinity".to_string(),
                enabled: true,
                mode: None,
            }],
            unschedulable_rules: Vec::new(),
            lru_enabled: false,
            skip_exhausted_accounts: true,
            reserve_minimum_quota: false,
            credit_floor: 0,
            pool_counts_toward_circuit_breaker:
                aether_pool_core::pool_advanced_defaults::POOL_COUNTS_TOWARD_CIRCUIT_BREAKER,
            breaker_threshold: aether_pool_core::pool_advanced_defaults::BREAKER_THRESHOLD,
            max_in_flight: aether_pool_core::pool_advanced_defaults::MAX_IN_FLIGHT,
            // 与下面解析路径**同一口径** ✓（面板默认）—— 曾经这里是 0/0/0 ✗，
            // 同一个函数两条路径给出不同默认值（维护性审计 H2 ✗）。
            breaker_cooldown_minutes:
                aether_pool_core::pool_advanced_defaults::BREAKER_COOLDOWN_MINUTES,
            breaker_cooldown_max_minutes:
                aether_pool_core::pool_advanced_defaults::BREAKER_COOLDOWN_MAX_MINUTES,
            cost_explore_interval_seconds:
                aether_pool_core::pool_advanced_defaults::COST_EXPLORE_INTERVAL_SECONDS,
            waf_ip_cooldown_seconds:
                aether_pool_core::pool_advanced_defaults::WAF_IP_COOLDOWN_SECONDS,
            waf_ip_block_new_requests:
                aether_pool_core::pool_advanced_defaults::WAF_IP_BLOCK_NEW_REQUESTS,
            sticky_session_ttl_seconds: 3600,
            latency_window_seconds: 3600,
            latency_sample_limit: 50,
            cost_window_seconds: 18_000,
            cost_limit_per_key_tokens: None,
            rate_limit_cooldown_seconds: 300,
            overload_cooldown_seconds: 30,
            probing_enabled: false,
            probing_target_percent: None,
            probing_target_count: None,
            probe_concurrency: 4,
            account_self_check_enabled: false,
            account_self_check_interval_minutes: 60,
            account_self_check_concurrency: 4,
            score_top_n: 128,
            score_fallback_scan_limit: 4096,
            score_rules: PoolMemberScoreRules::default(),
            stream_timeout_threshold: 3,
            stream_timeout_window_seconds: 1800,
            stream_timeout_cooldown_seconds: 300,
            request_demote_threshold: 5,
            request_demote_seconds: 600,
            request_demote_max_seconds: 7200,
            rate_limit_cooldown_max_seconds: 7200,
        });
    };

    let scheduling_presets = parse_pool_scheduling_presets(pool_advanced);
    let unschedulable_rules = parse_pool_unschedulable_rules(pool_advanced);
    let score_rules = parse_pool_score_rules(pool_advanced);

    Some(AdminProviderPoolConfig {
        lru_enabled: admin_provider_pool_lru_enabled(&scheduling_presets),
        scheduling_presets,
        unschedulable_rules,
        skip_exhausted_accounts: pool_advanced
            .get("ignore_exhausted_accounts")
            .and_then(Value::as_bool)
            .map(|ignore| !ignore)
            .unwrap_or(true),
        reserve_minimum_quota: pool_advanced
            .get("reserve_minimum_quota")
            .and_then(Value::as_bool)
            .unwrap_or(false),
        // 积分保底：0/缺失 = 关闭；负值钳到 0（面板同款）。
        credit_floor: pool_advanced
            .get("credit_floor")
            .and_then(|value| {
                value
                    .as_i64()
                    .or_else(|| value.as_str().and_then(|text| text.trim().parse().ok()))
            })
            .unwrap_or(0)
            .max(0),
        // 池内账号是否计入 key 级熔断（面板口径 **true** ✓，用户确认「面板默认即默认」；
        // 显式 false = 只降健康分）。
        pool_counts_toward_circuit_breaker: pool_advanced
            .get("pool_counts_toward_circuit_breaker")
            .and_then(Value::as_bool)
            .unwrap_or(
                aether_pool_core::pool_advanced_defaults::POOL_COUNTS_TOWARD_CIRCUIT_BREAKER,
            ),
        // 熔断阈值（面板 `breaker_threshold` **默认 3** ✓）：显式 0/负值 = 沿用历史 8。
        breaker_threshold: pool_advanced
            .get("breaker_threshold")
            .and_then(json_u64)
            .filter(|value| *value > 0)
            .unwrap_or(aether_pool_core::pool_advanced_defaults::BREAKER_THRESHOLD),
        // 单账号最大在途（面板 `max_in_flight` **默认 3**，所有域兜底）：
        // **缺失 = 3**（面板 `config.go:276` 就是默认值 ✓）；**显式 0** = 不分档（回落账号自身上限 ✓）。
        // 钳到 1 万（审计 P1-2：荒谬的大数会在 i32 转换时失败 → 上限静默变无限 ✗）。
        max_in_flight: pool_advanced
            .get("max_in_flight")
            .and_then(json_u64)
            .and_then(|value| usize::try_from(value).ok())
            .map(|value| value.min(aether_pool_core::pool_advanced_defaults::MAX_IN_FLIGHT_CAP))
            .unwrap_or(aether_pool_core::pool_advanced_defaults::MAX_IN_FLIGHT),
        // 熔断基础时长 / 退避上限（面板 `breaker_cooldown` **默认 30m** / `breaker_cooldown_max` **6h** ✓，
        // 用户确认「面板默认即默认」✓）：显式 0 = 沿用 Aether 历史（1 分钟 / 32 分钟）。
        breaker_cooldown_minutes: pool_advanced
            .get("breaker_cooldown_minutes")
            .and_then(json_u64)
            .unwrap_or(aether_pool_core::pool_advanced_defaults::BREAKER_COOLDOWN_MINUTES),
        breaker_cooldown_max_minutes: pool_advanced
            .get("breaker_cooldown_max_minutes")
            .and_then(json_u64)
            .unwrap_or(aether_pool_core::pool_advanced_defaults::BREAKER_COOLDOWN_MAX_MINUTES),
        // costTier 条件探索窗口（面板 `cost_explore_interval` **默认 30m** ✓，用户确认「面板默认即默认」）：
        // 显式 0 = 关停。面板对负值也是归 0，`json_u64` 天然忽略负值 ✓。
        cost_explore_interval_seconds: pool_advanced
            .get("cost_explore_interval_seconds")
            .or_else(|| pool_advanced.get("cost_explore_interval"))
            .and_then(json_u64)
            .unwrap_or(aether_pool_core::pool_advanced_defaults::COST_EXPLORE_INTERVAL_SECONDS),
        // WAF 出口 IP 级拦截窗口（面板固定 60s ✓）：默认 60（面板同款行为）；显式 0 = 关停。
        waf_ip_cooldown_seconds: pool_advanced
            .get("waf_ip_cooldown_seconds")
            .and_then(json_u64)
            .unwrap_or(aether_pool_core::pool_advanced_defaults::WAF_IP_COOLDOWN_SECONDS),
        // 拦截期是否连新请求一起挡：默认 true（Aether 现状，更严一档 ✓）；false = 面板口径
        // （只停本次请求的轮转 ✓）。
        waf_ip_block_new_requests: pool_advanced
            .get("waf_ip_block_new_requests")
            .and_then(|value| value.as_bool())
            .unwrap_or(aether_pool_core::pool_advanced_defaults::WAF_IP_BLOCK_NEW_REQUESTS),
        sticky_session_ttl_seconds: pool_advanced
            .get("sticky_session_ttl_seconds")
            .and_then(json_u64)
            .unwrap_or(3600),
        latency_window_seconds: pool_advanced
            .get("latency_window_seconds")
            .and_then(json_u64)
            .filter(|value| *value > 0)
            .unwrap_or(3600),
        latency_sample_limit: pool_advanced
            .get("latency_sample_limit")
            .and_then(json_u64)
            .filter(|value| *value > 0)
            .unwrap_or(50),
        cost_window_seconds: pool_advanced
            .get("cost_window_seconds")
            .and_then(json_u64)
            .filter(|value| *value > 0)
            .unwrap_or(18_000),
        cost_limit_per_key_tokens: pool_advanced
            .get("cost_limit_per_key_tokens")
            .and_then(json_u64),
        rate_limit_cooldown_seconds: pool_advanced
            .get("rate_limit_cooldown_seconds")
            .and_then(json_u64)
            .unwrap_or(300),
        // 429 软限流退避上限（面板 softRateMax）：0 也可显式填写 = 关闭退避（<= 基础冷却）。
        rate_limit_cooldown_max_seconds: pool_advanced
            .get("rate_limit_cooldown_max_seconds")
            .and_then(json_u64)
            .map(|value| value.min(86_400))
            .unwrap_or(7200),
        overload_cooldown_seconds: pool_advanced
            .get("overload_cooldown_seconds")
            .and_then(json_u64)
            .unwrap_or(30),
        probing_enabled: pool_advanced
            .get("probing_enabled")
            .and_then(Value::as_bool)
            .unwrap_or(false),
        probing_target_percent: parse_pool_probe_target_percent(pool_advanced),
        probing_target_count: parse_pool_probe_target_count(pool_advanced),
        probe_concurrency: pool_advanced
            .get("probe_concurrency")
            .and_then(json_u64)
            .filter(|value| *value > 0)
            .map(|value| value.min(64))
            .unwrap_or(4),
        account_self_check_enabled: pool_advanced
            .get("account_self_check_enabled")
            .or_else(|| pool_advanced.get("self_check_enabled"))
            .and_then(Value::as_bool)
            .unwrap_or(false),
        account_self_check_interval_minutes: pool_advanced
            .get("account_self_check_interval_minutes")
            .or_else(|| pool_advanced.get("self_check_interval_minutes"))
            .and_then(json_u64)
            .filter(|value| *value > 0)
            .map(|value| value.min(1440))
            .unwrap_or(60),
        account_self_check_concurrency: pool_advanced
            .get("account_self_check_concurrency")
            .or_else(|| pool_advanced.get("self_check_concurrency"))
            .and_then(json_u64)
            .filter(|value| *value > 0)
            .map(|value| value.min(64))
            .unwrap_or(4),
        score_top_n: pool_advanced
            .get("score_top_n")
            .and_then(json_u64)
            .filter(|value| *value > 0)
            .map(|value| value.min(4096))
            .unwrap_or(128),
        score_fallback_scan_limit: pool_advanced
            .get("score_fallback_scan_limit")
            .and_then(json_u64)
            .filter(|value| *value > 0)
            .map(|value| value.min(50_000))
            .unwrap_or(4096),
        score_rules,
        stream_timeout_threshold: pool_advanced
            .get("stream_timeout_threshold")
            .and_then(json_u64)
            .filter(|value| *value > 0)
            .unwrap_or(3),
        stream_timeout_window_seconds: pool_advanced
            .get("stream_timeout_window_seconds")
            .and_then(json_u64)
            .filter(|value| *value > 0)
            .unwrap_or(1800),
        stream_timeout_cooldown_seconds: pool_advanced
            .get("stream_timeout_cooldown_seconds")
            .and_then(json_u64)
            .filter(|value| *value > 0)
            .unwrap_or(300),
        // 连败降权三件套（面板 `pool_advanced`）：阈值 0 = 关闭；时长/上限钳到 24h 内。
        request_demote_threshold: pool_advanced
            .get("request_demote_threshold")
            .and_then(json_u64)
            .map(|value| value.min(1000))
            .unwrap_or(5),
        request_demote_seconds: pool_advanced
            .get("request_demote_seconds")
            .and_then(json_u64)
            .filter(|value| *value > 0)
            .map(|value| value.min(86_400))
            .unwrap_or(600),
        request_demote_max_seconds: pool_advanced
            .get("request_demote_max_seconds")
            .and_then(json_u64)
            .filter(|value| *value > 0)
            .map(|value| value.min(86_400))
            .unwrap_or(7200),
    })
}

#[cfg(test)]
mod tests {
    use super::{
        admin_provider_pool_cache_affinity_enabled, admin_provider_pool_config,
        admin_provider_pool_config_for_provider, admin_provider_pool_config_from_config_value,
    };
    use aether_data_contracts::repository::provider_catalog::StoredProviderCatalogProvider;
    use serde_json::json;

    fn sample_provider(config: serde_json::Value) -> StoredProviderCatalogProvider {
        sample_provider_with_type("codex", config)
    }

    fn sample_provider_with_type(
        provider_type: &str,
        config: serde_json::Value,
    ) -> StoredProviderCatalogProvider {
        StoredProviderCatalogProvider::new(
            "provider-1".to_string(),
            "provider-1".to_string(),
            Some("https://example.com".to_string()),
            provider_type.to_string(),
        )
        .expect("provider should build")
        .with_transport_fields(
            true,
            false,
            false,
            None,
            None,
            None,
            None,
            None,
            Some(config),
        )
    }

    #[test]
    /// 熔断相关旋钮：**默认 = 面板口径**（用户 2026-10-16 确认「面板默认即默认」✓）；
    /// 显式 0/历史值仍可通过配置回到旧行为（不删能力 ✓）。
    fn parses_breaker_knobs() {
        let defaults =
            admin_provider_pool_config_from_config_value(Some(&json!({ "pool_advanced": {} })))
                .expect("pool config");
        assert_eq!(defaults.breaker_threshold, 3, "默认 = 面板口径 ✓");
        assert!(
            defaults.pool_counts_toward_circuit_breaker,
            "默认 = 面板口径（池即全量账号）✓"
        );

        // 显式历史值仍可回到旧行为（能力不删 ✓，只是不再是默认 ✓）。
        let legacy = admin_provider_pool_config_from_config_value(Some(&json!({
            "pool_advanced": {
                "breaker_threshold": 8,
                "pool_counts_toward_circuit_breaker": false
            }
        })))
        .expect("pool config");
        assert_eq!(legacy.breaker_threshold, 8);
        assert!(!legacy.pool_counts_toward_circuit_breaker);

        // 0/负值 → 钳回面板默认 3（避免误配成“永不熔断”）。
        let zero = admin_provider_pool_config_from_config_value(Some(&json!({
            "pool_advanced": { "breaker_threshold": 0 }
        })))
        .expect("pool config");
        assert_eq!(zero.breaker_threshold, 3);

        // WAF 出口 IP 拦截：默认 60s 且**连新请求一起挡**（更严一档 ✓）；
        // `waf_ip_block_new_requests = false` = 对齐面板（只停本次请求的轮转 ✓），
        // `waf_ip_cooldown_seconds = 0` 则整项关停 ✓。
        assert_eq!(defaults.waf_ip_cooldown_seconds, 60);
        assert!(defaults.waf_ip_block_new_requests, "默认更严一档");
        let panel_waf = admin_provider_pool_config_from_config_value(Some(&json!({
            "pool_advanced": {
                "waf_ip_cooldown_seconds": 0,
                "waf_ip_block_new_requests": false
            }
        })))
        .expect("pool config");
        assert_eq!(panel_waf.waf_ip_cooldown_seconds, 0);
        assert!(!panel_waf.waf_ip_block_new_requests);

        // 单账号最大在途（面板 `max_in_flight` 默认 3，**所有域**兜底 ✓）：显式 0 = 不分档。
        assert_eq!(defaults.max_in_flight, 3);
        let max_in_flight_off = admin_provider_pool_config_from_config_value(Some(&json!({
            "pool_advanced": { "max_in_flight": 0 }
        })))
        .expect("pool config");
        assert_eq!(max_in_flight_off.max_in_flight, 0);

        // 熔断基础时长 / 退避上限：**默认 = 面板口径（30m / 6h）✓**；显式 0 = 沿用历史（1 分钟 / 32 分钟）。
        assert_eq!(defaults.breaker_cooldown_minutes, 30);
        assert_eq!(defaults.breaker_cooldown_max_minutes, 360);
        let legacy_durations = admin_provider_pool_config_from_config_value(Some(&json!({
            "pool_advanced": {
                "breaker_cooldown_minutes": 0,
                "breaker_cooldown_max_minutes": 0
            }
        })))
        .expect("pool config");
        assert_eq!(legacy_durations.breaker_cooldown_minutes, 0);
        assert_eq!(legacy_durations.breaker_cooldown_max_minutes, 0);

        // costTier 条件探索窗口：**默认 = 面板口径 30m（1800s）✓**；显式 0 = 关停。
        assert_eq!(defaults.cost_explore_interval_seconds, 1800);
        let off = admin_provider_pool_config_from_config_value(Some(&json!({
            "pool_advanced": { "cost_explore_interval_seconds": 0 }
        })))
        .expect("pool config");
        assert_eq!(off.cost_explore_interval_seconds, 0);
        // 面板别名 `cost_explore_interval` 也认；负值/非法 → 默认 1800
        let alias = admin_provider_pool_config_from_config_value(Some(&json!({
            "pool_advanced": { "cost_explore_interval": 900 }
        })))
        .expect("pool config");
        assert_eq!(alias.cost_explore_interval_seconds, 900);
        let negative = admin_provider_pool_config_from_config_value(Some(&json!({
            "pool_advanced": { "cost_explore_interval_seconds": -5 }
        })))
        .expect("pool config");
        assert_eq!(negative.cost_explore_interval_seconds, 1800);
    }

    /// 维护性审计 ④：**非对象** `pool_advanced` 的兜底分支必须与解析路径**同口径** ✓。
    ///
    /// 审计 H2 就是在这一对路径上抓到真实漂移 ✗：当时兜底分支给 `cooldown 0/0`、
    /// `cost_explore 0`，而解析路径给 `30/360/1800` —— 同一个函数两个答案 ✗，
    /// 且当时**没有任何测试**走过非对象分支 ✗（所有用例都传 `{}` ✓）。
    #[test]
    fn non_object_pool_advanced_falls_back_to_the_same_defaults_as_the_parsed_path() {
        let object =
            admin_provider_pool_config_from_config_value(Some(&json!({ "pool_advanced": {} })))
                .expect("对象形态应解析成功");
        for weird in [
            json!({ "pool_advanced": true }),
            json!({ "pool_advanced": 1 }),
            json!({ "pool_advanced": "x" }),
            json!({ "pool_advanced": [] }),
            json!({ "pool_advanced": null }),
        ] {
            let fallback = admin_provider_pool_config_from_config_value(Some(&weird))
                .unwrap_or_else(|| panic!("{weird} 应返回兜底配置，而不是 None"));
            assert_eq!(
                fallback.breaker_threshold, object.breaker_threshold,
                "{weird}"
            );
            assert_eq!(
                fallback.breaker_cooldown_minutes, object.breaker_cooldown_minutes,
                "{weird}"
            );
            assert_eq!(
                fallback.breaker_cooldown_max_minutes, object.breaker_cooldown_max_minutes,
                "{weird}"
            );
            assert_eq!(
                fallback.cost_explore_interval_seconds, object.cost_explore_interval_seconds,
                "{weird}"
            );
            assert_eq!(fallback.max_in_flight, object.max_in_flight, "{weird}");
            assert_eq!(
                fallback.waf_ip_cooldown_seconds, object.waf_ip_cooldown_seconds,
                "{weird}"
            );
            assert_eq!(
                fallback.waf_ip_block_new_requests, object.waf_ip_block_new_requests,
                "{weird}"
            );
            assert_eq!(
                fallback.pool_counts_toward_circuit_breaker,
                object.pool_counts_toward_circuit_breaker,
                "{weird}"
            );
            assert_eq!(fallback.credit_floor, object.credit_floor, "{weird}");
        }
    }

    /// 积分保底配置解析（面板 `pool.credit_floor`）：默认 0 = 关闭，负值钳 0。
    #[test]
    fn parses_credit_floor_config() {
        // 默认关闭
        let defaults =
            admin_provider_pool_config_from_config_value(Some(&json!({ "pool_advanced": {} })))
                .expect("pool config");
        assert_eq!(defaults.credit_floor, 0);

        // 显式值
        let configured = admin_provider_pool_config_from_config_value(Some(&json!({
            "pool_advanced": { "credit_floor": 100 }
        })))
        .expect("pool config");
        assert_eq!(configured.credit_floor, 100);

        // 负值钳到 0（面板同款），字符串数字也认
        let negative = admin_provider_pool_config_from_config_value(Some(&json!({
            "pool_advanced": { "credit_floor": -7 }
        })))
        .expect("pool config");
        assert_eq!(negative.credit_floor, 0);
        let as_string = admin_provider_pool_config_from_config_value(Some(&json!({
            "pool_advanced": { "credit_floor": "2048" }
        })))
        .expect("pool config");
        assert_eq!(as_string.credit_floor, 2048);
    }

    #[test]
    fn parses_expiring_credit_routing_config() {
        // 默认：7 天窗口 + 0.10 加分（面板 `prefer_expiring` 默认 true、`expiring_soon` 默认 168h）
        let defaults =
            admin_provider_pool_config_from_config_value(Some(&json!({ "pool_advanced": {} })))
                .expect("pool config");
        assert_eq!(defaults.score_rules.expiring_soon_seconds, 604_800);
        assert!((defaults.score_rules.expiring_credit_bonus - 0.10).abs() < 1e-9);

        // 顶层键（面板命名）
        let configured = admin_provider_pool_config_from_config_value(Some(&json!({
            "pool_advanced": {
                "expiring_soon_seconds": 3600,
                "expiring_credit_bonus": 0.25
            }
        })))
        .expect("pool config");
        assert_eq!(configured.score_rules.expiring_soon_seconds, 3600);
        assert!((configured.score_rules.expiring_credit_bonus - 0.25).abs() < 1e-9);

        // 嵌套 `score_rules.*` 也认
        let nested = admin_provider_pool_config_from_config_value(Some(&json!({
            "pool_advanced": { "score_rules": { "expiring_soon_seconds": 7200 } }
        })))
        .expect("pool config");
        assert_eq!(nested.score_rules.expiring_soon_seconds, 7200);

        // 关闭开关 → 加分为 0（窗口保留，前端照展示）
        let disabled = admin_provider_pool_config_from_config_value(Some(&json!({
            "pool_advanced": { "prefer_expiring": false }
        })))
        .expect("pool config");
        assert_eq!(disabled.score_rules.expiring_credit_bonus, 0.0);
        assert_eq!(disabled.score_rules.expiring_soon_seconds, 604_800);

        // 窗口 0 = 关闭分桶
        let no_window = admin_provider_pool_config_from_config_value(Some(&json!({
            "pool_advanced": { "expiring_soon_seconds": 0 }
        })))
        .expect("pool config");
        assert_eq!(no_window.score_rules.expiring_soon_seconds, 0);
    }

    #[test]
    fn parses_ignore_exhausted_accounts_with_default_off() {
        for ignore in [false, true] {
            let provider = sample_provider(json!({
                "pool_advanced": {
                    "ignore_exhausted_accounts": ignore,
                    "skip_exhausted_accounts": true
                }
            }));
            let config = admin_provider_pool_config(&provider).expect("pool config should exist");
            assert_eq!(config.skip_exhausted_accounts, !ignore);
        }
    }

    /// AMD 永不接入号池：config 里即使带着 `pool_advanced`，读取侧也必须返回 None。
    ///
    /// 这条判据同时兜住三种脏数据来源：历史遗留、直接调 API 写入、
    /// 以及把别的 provider_type 改成 amd 时跟着留下的旧配置。
    #[test]
    fn amd_provider_never_joins_the_pool() {
        let config = json!({ "pool_advanced": {} });

        let amd_provider = sample_provider_with_type("amd", config.clone());
        assert!(admin_provider_pool_config(&amd_provider).is_none());

        // serving 路径用的带类型入口（拿得到 transport 的 provider_type）。
        assert!(admin_provider_pool_config_for_provider("amd", Some(&config)).is_none());
        assert!(admin_provider_pool_config_for_provider(" AMD ", Some(&config)).is_none());

        // 其它类型一字不改：池仍然是它们的能力。
        assert!(admin_provider_pool_config_for_provider("custom", Some(&config)).is_some());
        assert!(admin_provider_pool_config_for_provider("opencode", Some(&config)).is_some());

        // 没有 pool_advanced 的 AMD 供应商同样返回 None（本来就是非池）。
        assert!(admin_provider_pool_config_for_provider("amd", None).is_none());
    }

    #[test]
    fn defaults_skip_exhausted_accounts_to_true() {
        let provider = sample_provider(json!({ "pool_advanced": {} }));
        let config = admin_provider_pool_config(&provider).expect("pool config should exist");

        assert!(config.skip_exhausted_accounts);
        assert!(!config.reserve_minimum_quota);
    }

    #[test]
    fn parses_reserve_minimum_quota_independently_of_skip_exhausted_accounts() {
        for enabled in [false, true] {
            let provider = sample_provider(json!({
                "pool_advanced": {
                    "reserve_minimum_quota": enabled,
                    "skip_exhausted_accounts": false
                }
            }));
            let config = admin_provider_pool_config(&provider).expect("pool config should exist");
            assert_eq!(config.reserve_minimum_quota, enabled);
            assert!(config.skip_exhausted_accounts);
        }
    }

    #[test]
    fn parses_skip_exhausted_accounts_from_pool_advanced() {
        let provider = sample_provider(json!({
            "pool_advanced": {
                "skip_exhausted_accounts": true,
                "lru_enabled": true,
                "sticky_session_ttl_seconds": 600,
                "latency_window_seconds": 900,
                "latency_sample_limit": 75,
                "cost_window_seconds": 7200,
                "cost_limit_per_key_tokens": 12000,
                "rate_limit_cooldown_seconds": 420,
                "overload_cooldown_seconds": 45,
                "probing_enabled": true,
                "probing_target_percent": 25,
                "probing_target_count": 3,
                "probe_concurrency": 6,
                "account_self_check_enabled": true,
                "account_self_check_interval_minutes": 90,
                "account_self_check_concurrency": 5,
                "score_top_n": 256,
                "score_fallback_scan_limit": 2048,
                "score_rules": {
                    "weights": {
                        "manual_priority": 0.4,
                        "health": 0.2,
                        "probe_freshness": 0.2,
                        "quota_remaining": 0.1,
                        "latency": 0.05,
                        "cost_lru": 0.05
                    },
                    "probe_freshness_ttl_seconds": 1200,
                    "unschedulable_score_cap": 0.03,
                    "probe_failure_penalty": 0.08,
                    "request_failure_penalty": 0.01,
                    "probe_failure_cooldown_threshold": 2
                },
                "stream_timeout_threshold": 4,
                "stream_timeout_window_seconds": 900,
                "stream_timeout_cooldown_seconds": 180
            }
        }));
        let config = admin_provider_pool_config(&provider).expect("pool config should exist");

        assert!(config.skip_exhausted_accounts);
        assert!(config.lru_enabled);
        assert_eq!(config.sticky_session_ttl_seconds, 600);
        assert_eq!(config.latency_window_seconds, 900);
        assert_eq!(config.latency_sample_limit, 75);
        assert_eq!(config.cost_window_seconds, 7200);
        assert_eq!(config.cost_limit_per_key_tokens, Some(12_000));
        assert_eq!(config.rate_limit_cooldown_seconds, 420);
        assert_eq!(config.overload_cooldown_seconds, 45);
        assert!(config.probing_enabled);
        assert_eq!(config.probing_target_percent, Some(25.0));
        assert_eq!(config.probing_target_count, Some(3));
        assert_eq!(config.probe_concurrency, 6);
        assert!(config.account_self_check_enabled);
        assert_eq!(config.account_self_check_interval_minutes, 90);
        assert_eq!(config.account_self_check_concurrency, 5);
        assert_eq!(config.score_top_n, 256);
        assert_eq!(config.score_fallback_scan_limit, 2048);
        assert_eq!(config.score_rules.weights.manual_priority, 0.4);
        assert_eq!(config.score_rules.weights.health, 0.2);
        assert_eq!(config.score_rules.probe_freshness_ttl_seconds, 1200);
        assert_eq!(config.score_rules.unschedulable_score_cap, 0.03);
        assert_eq!(config.score_rules.probe_failure_penalty, 0.08);
        assert_eq!(config.score_rules.request_failure_penalty, 0.01);
        assert_eq!(config.score_rules.probe_failure_cooldown_threshold, 2);
        assert_eq!(config.stream_timeout_threshold, 4);
        assert_eq!(config.stream_timeout_window_seconds, 900);
        assert_eq!(config.stream_timeout_cooldown_seconds, 180);
    }

    #[test]
    fn ignores_legacy_pool_quota_probe_interval() {
        let provider = sample_provider(json!({
            "pool_advanced": {
                "probing_enabled": true,
                "probing_interval_minutes": 2000,
            }
        }));
        let config = admin_provider_pool_config(&provider).expect("pool config should exist");
        assert!(config.probing_enabled);

        let provider = sample_provider(json!({
            "pool_advanced": {
                "probing_enabled": true,
                "probing_interval_minutes": 0,
            }
        }));
        let config = admin_provider_pool_config(&provider).expect("pool config should exist");
        assert!(config.probing_enabled);
    }

    #[test]
    fn parses_zero_sticky_session_ttl_to_disable_sticky_sessions() {
        let config = admin_provider_pool_config_from_config_value(Some(&json!({
            "pool_advanced": {
                "sticky_session_ttl_seconds": 0
            }
        })))
        .expect("pool config should parse");

        assert_eq!(config.sticky_session_ttl_seconds, 0);
    }

    #[test]
    fn parses_zero_cooldown_seconds_to_disable_error_cooldowns() {
        let config = admin_provider_pool_config_from_config_value(Some(&json!({
            "pool_advanced": {
                "rate_limit_cooldown_seconds": 0,
                "overload_cooldown_seconds": 0
            }
        })))
        .expect("pool config should parse");

        assert_eq!(config.rate_limit_cooldown_seconds, 0);
        assert_eq!(config.overload_cooldown_seconds, 0);
    }

    #[test]
    fn parses_legacy_pool_score_weights_from_pool_advanced() {
        let config = admin_provider_pool_config_from_config_value(Some(&json!({
            "pool_advanced": {
                "scoring_weights": {
                    "manual_priority": 0,
                    "health": 2,
                    "probe": 1,
                    "quota_remaining": 0,
                    "latency": 0,
                    "cost_remaining": 1
                }
            }
        })))
        .expect("pool config should parse");

        assert_eq!(config.score_rules.weights.health, 0.5);
        assert_eq!(config.score_rules.weights.probe_freshness, 0.25);
        assert_eq!(config.score_rules.weights.cost_lru, 0.25);
    }

    #[test]
    fn parses_pool_config_from_generic_config_value() {
        let config = admin_provider_pool_config_from_config_value(Some(&json!({
            "pool_advanced": {
                "scheduling_presets": [{"preset": "lru", "enabled": true}],
                "cost_limit_per_key_tokens": 4096
            }
        })))
        .expect("pool config should parse");

        assert!(config.lru_enabled);
        assert_eq!(config.scheduling_presets.len(), 1);
        assert_eq!(config.scheduling_presets[0].preset, "lru");
        assert_eq!(config.cost_limit_per_key_tokens, Some(4096));
    }

    #[test]
    fn defaults_empty_pool_advanced_to_cache_affinity_preset() {
        let config = admin_provider_pool_config_from_config_value(Some(&json!({
            "pool_advanced": {}
        })))
        .expect("pool config should parse");

        assert!(!config.lru_enabled);
        assert_eq!(config.scheduling_presets.len(), 1);
        assert_eq!(config.scheduling_presets[0].preset, "cache_affinity");
        assert!(config.scheduling_presets[0].enabled);
    }

    #[test]
    fn parses_object_style_scheduling_presets_with_modes() {
        let config = admin_provider_pool_config_from_config_value(Some(&json!({
            "pool_advanced": {
                "scheduling_presets": [
                    {"preset": "cache_affinity", "enabled": false},
                    {"preset": "plus_first", "enabled": true, "mode": "plus_only"},
                    {"preset": "pro_first", "enabled": true, "mode": "pro_only"}
                ]
            }
        })))
        .expect("pool config should parse");

        assert!(!config.lru_enabled);
        assert_eq!(config.scheduling_presets.len(), 3);
        assert_eq!(config.scheduling_presets[0].preset, "cache_affinity");
        assert!(!config.scheduling_presets[0].enabled);
        assert_eq!(config.scheduling_presets[1].preset, "plus_first");
        assert_eq!(
            config.scheduling_presets[1].mode.as_deref(),
            Some("plus_only")
        );
        assert_eq!(config.scheduling_presets[2].preset, "pro_first");
        assert_eq!(
            config.scheduling_presets[2].mode.as_deref(),
            Some("pro_only")
        );
    }

    #[test]
    fn parses_legacy_string_style_scheduling_presets() {
        let config = admin_provider_pool_config_from_config_value(Some(&json!({
            "pool_advanced": {
                "lru_enabled": false,
                "scheduling_presets": [
                    "free_first",
                    "recent_refresh",
                    "free_first"
                ]
            }
        })))
        .expect("pool config should parse");

        assert!(!config.lru_enabled);
        assert_eq!(config.scheduling_presets.len(), 3);
        assert_eq!(config.scheduling_presets[0].preset, "lru");
        assert!(!config.scheduling_presets[0].enabled);
        assert_eq!(config.scheduling_presets[1].preset, "free_first");
        assert_eq!(config.scheduling_presets[2].preset, "recent_refresh");
    }

    #[test]
    fn legacy_free_team_first_preset_is_preserved() {
        let config = admin_provider_pool_config_from_config_value(Some(&json!({
            "pool_advanced": {
                "scheduling_presets": [
                    {"preset": "free_team_first", "enabled": true, "mode": "team_only"}
                ]
            }
        })))
        .expect("pool config should parse");

        assert_eq!(config.scheduling_presets.len(), 1);
        assert_eq!(config.scheduling_presets[0].preset, "free_team_first");
        assert_eq!(
            config.scheduling_presets[0].mode.as_deref(),
            Some("team_only")
        );
    }

    #[test]
    fn parses_unschedulable_rules_from_pool_advanced() {
        let config = admin_provider_pool_config_from_config_value(Some(&json!({
            "pool_advanced": {
                "unschedulable_rules": [
                    {"keyword": "suspended", "duration_minutes": 15},
                    {"keyword": "review_required"}
                ]
            }
        })))
        .expect("pool config should parse");

        assert_eq!(config.unschedulable_rules.len(), 2);
        assert_eq!(config.unschedulable_rules[0].keyword, "suspended");
        assert_eq!(config.unschedulable_rules[0].duration_minutes, 15);
        assert_eq!(config.unschedulable_rules[1].keyword, "review_required");
        assert_eq!(config.unschedulable_rules[1].duration_minutes, 5);
    }

    #[test]
    fn cache_affinity_enabled_only_when_it_is_distribution_mode() {
        let cache_affinity = admin_provider_pool_config_from_config_value(Some(&json!({
            "pool_advanced": {
                "scheduling_presets": [
                    {"preset": "cache_affinity", "enabled": true},
                    {"preset": "priority_first", "enabled": true}
                ]
            }
        })))
        .expect("pool config should parse");
        assert!(admin_provider_pool_cache_affinity_enabled(&cache_affinity));

        let load_balance = admin_provider_pool_config_from_config_value(Some(&json!({
            "pool_advanced": {
                "scheduling_presets": [
                    {"preset": "load_balance", "enabled": true},
                    {"preset": "cache_affinity", "enabled": true}
                ]
            }
        })))
        .expect("pool config should parse");
        assert!(!admin_provider_pool_cache_affinity_enabled(&load_balance));
    }
}
