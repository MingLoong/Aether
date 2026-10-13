//! cline 独立的号池调度逻辑。
//!
//! 不复用通用号池的评分 / LRU / 探测那一套：cline 的账号是订阅/额度级的，借鉴
//! cline2api 的多账号轮换，用「反应式冷却 + 选号策略」这条更简单的路径。
//!
//! - **选号策略**：`round_robin` / `fill` / `random` / `least_used`（对应 cline2api 的
//!   round_robin / fill / random，least_used 是其回退链上的「选历史用量最少」）。
//! - **两级冷却**：账号级（402 额度不足 / 429 限流）与模型级（403 `ENTITLEMENT_ERROR`，
//!   即 free 账号打 cline-pass 档位模型——只该冷却「该账号对该模型」，不整账号拉黑）。
//! - **冷却状态**：`runtime_kv` + TTL（与 `amd_rotation` 的轮转游标同款），进程内可观察、
//!   跨请求持久，进程重启后靠下次请求重新记录，不追求强一致。
//!
//! 402/429 的账号级冷却**复用通用号池已记录的 `PoolMemberHardState`**（见
//! `orchestration/effects.rs`），这里补通用号池不处理的 403 entitlement 模型级冷却，
//! 以及 `ClinePoolStrategy`（round_robin/fill/random/least_used 的枚举与配置解析）。
//! 选号的实际映射在 `dispatch/pool_scheduler.rs` 与 `handlers/admin/provider/pool/config.rs`
//! （round_robin/random → load_balance，fill → single_account，least_used → lru）。

use std::time::{SystemTime, UNIX_EPOCH};

use serde_json::Value;

use crate::AppState;

/// cline 号池的选号策略。
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub(crate) enum ClinePoolStrategy {
    #[default]
    RoundRobin,
    Fill,
    Random,
    LeastUsed,
}

impl ClinePoolStrategy {
    /// 从 `pool_advanced` 读 `cline_strategy`。缺省 / 非法一律回退 `round_robin`。
    pub(crate) fn from_config(pool_advanced: Option<&Value>) -> Self {
        let Some(raw) = pool_advanced.and_then(Value::as_object) else {
            return Self::default();
        };
        match raw
            .get("cline_strategy")
            .and_then(Value::as_str)
            .map(str::trim)
            .unwrap_or("round_robin")
        {
            "fill" => Self::Fill,
            "random" => Self::Random,
            "least_used" => Self::LeastUsed,
            _ => Self::RoundRobin,
        }
    }
}

/// 402 / 429 / 403 命中后的默认冷却时长（30 分钟，与 cline2api 一致）。
pub(crate) const CLINE_DEFAULT_COOLDOWN_SECS: u64 = 30 * 60;

fn now_unix_secs() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}

fn account_cooldown_key(provider_id: &str, key_id: &str) -> String {
    format!("cline_pool:acct_cool:{provider_id}:{key_id}")
}

fn model_cooldown_key(provider_id: &str, key_id: &str, model: &str) -> String {
    format!("cline_pool:model_cool:{provider_id}:{key_id}:{model}")
}

/// 记录一次冷却。
///
/// `account_level = true` 表示账号级（402/429），`false` 表示模型级（403 entitlement，
/// 需要 `model`）。冷却值写 `until` 时间戳（秒），TTL 同步到期。
pub(crate) async fn record_cline_cooldown(
    state: &AppState,
    provider_id: &str,
    key_id: &str,
    model: Option<&str>,
    account_level: bool,
    cooldown_secs: Option<u64>,
) {
    let secs = cooldown_secs.unwrap_or(CLINE_DEFAULT_COOLDOWN_SECS);
    let until = now_unix_secs().saturating_add(secs).to_string();
    let key = match (account_level, model) {
        (false, Some(model)) => model_cooldown_key(provider_id, key_id, model),
        _ => account_cooldown_key(provider_id, key_id),
    };
    let _ = state.runtime_kv_setex(&key, &until, secs).await;
}

/// 判断某把 key（对某模型）是否处于冷却，返回剩余冷却秒数（0 = 未冷却）。
///
/// 账号级与模型级取更久的那一个。
pub(crate) async fn cline_cooldown_remaining(
    state: &AppState,
    provider_id: &str,
    key_id: &str,
    model: Option<&str>,
) -> u64 {
    let now = now_unix_secs();
    let mut remaining = 0u64;
    if let Ok(Some(raw)) = state
        .runtime_kv_get(&account_cooldown_key(provider_id, key_id))
        .await
    {
        if let Ok(until) = raw.trim().parse::<u64>() {
            remaining = remaining.max(until.saturating_sub(now));
        }
    }
    if let Some(model) = model {
        if let Ok(Some(raw)) = state
            .runtime_kv_get(&model_cooldown_key(provider_id, key_id, model))
            .await
        {
            if let Ok(until) = raw.trim().parse::<u64>() {
                remaining = remaining.max(until.saturating_sub(now));
            }
        }
    }
    remaining
}

#[cfg(test)]
mod tests {
    use super::ClinePoolStrategy;
    use serde_json::json;

    #[test]
    fn strategy_defaults_to_round_robin() {
        assert_eq!(
            ClinePoolStrategy::from_config(None),
            ClinePoolStrategy::RoundRobin
        );
        assert_eq!(
            ClinePoolStrategy::from_config(Some(&json!({}))),
            ClinePoolStrategy::RoundRobin
        );
        assert_eq!(
            ClinePoolStrategy::from_config(Some(&json!({"cline_strategy": "bogus"}))),
            ClinePoolStrategy::RoundRobin
        );
    }

    #[test]
    fn strategy_parses_all_variants() {
        for (raw, expected) in [
            ("round_robin", ClinePoolStrategy::RoundRobin),
            ("fill", ClinePoolStrategy::Fill),
            ("random", ClinePoolStrategy::Random),
            ("least_used", ClinePoolStrategy::LeastUsed),
        ] {
            assert_eq!(
                ClinePoolStrategy::from_config(Some(&json!({"cline_strategy": raw}))),
                expected
            );
        }
    }
}
