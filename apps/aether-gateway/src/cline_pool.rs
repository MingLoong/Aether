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
//! `orchestration/effects.rs`），这里只补通用号池不处理的 403 entitlement 模型级冷却，
//! 以及 cline 自己的选号策略。

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

fn round_robin_cursor_key(provider_id: &str) -> String {
    format!("cline_pool:rr_cursor:{provider_id}")
}

const ROUND_ROBIN_CURSOR_TTL_SECS: u64 = 24 * 60 * 60;

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

/// 推进 round_robin 游标，返回**本次**的序号（首次 0，之后 1、2、…）。
///
/// 与 `amd_rotation::next_amd_key_cursor` 同款实现（`GETDEL` + `SETEX`），非严格原子，
/// 并发下可能跳号或重复，但不会卡死——顺序是近似的。
pub(crate) async fn next_cline_round_robin_cursor(state: &AppState, provider_id: &str) -> u64 {
    let key = round_robin_cursor_key(provider_id);
    let taken = state.runtime_kv_getdel(&key).await.ok().flatten();
    let next = match taken
        .as_deref()
        .map(str::trim)
        .and_then(|raw| raw.parse::<u64>().ok())
    {
        Some(previous) => previous.wrapping_add(1),
        None => 0,
    };
    let _ = state
        .runtime_kv_setex(&key, &next.to_string(), ROUND_ROBIN_CURSOR_TTL_SECS)
        .await;
    next
}

/// 纯选号：在 `eligible_len` 个候选里挑一个下标。
///
/// - `RoundRobin`：`cursor % eligible_len`；
/// - `Fill`：恒 0（一直用第一个可用）；
/// - `Random`：`random_seed % eligible_len`（seed 由调用方给，测试可确定）；
/// - `LeastUsed`：`usage_counts` 里最小的那个下标（等量取靠前的）。
///
/// 调用方保证 `eligible_len > 0` 且 `usage_counts.len() >= eligible_len`。
pub(crate) fn cline_pick_index(
    strategy: ClinePoolStrategy,
    eligible_len: usize,
    cursor: u64,
    random_seed: u64,
    usage_counts: &[u64],
) -> usize {
    if eligible_len == 0 {
        return 0;
    }
    let len = eligible_len as u64;
    match strategy {
        ClinePoolStrategy::RoundRobin => (cursor % len) as usize,
        ClinePoolStrategy::Fill => 0,
        ClinePoolStrategy::Random => (random_seed % len) as usize,
        ClinePoolStrategy::LeastUsed => usage_counts
            .iter()
            .take(eligible_len)
            .enumerate()
            .min_by_key(|(_, count)| **count)
            .map(|(index, _)| index)
            .unwrap_or(0),
    }
}

#[cfg(test)]
mod tests {
    use super::{cline_pick_index, ClinePoolStrategy};
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

    #[test]
    fn round_robin_wraps_and_advances() {
        assert_eq!(
            cline_pick_index(ClinePoolStrategy::RoundRobin, 3, 0, 0, &[]),
            0
        );
        assert_eq!(
            cline_pick_index(ClinePoolStrategy::RoundRobin, 3, 1, 0, &[]),
            1
        );
        assert_eq!(
            cline_pick_index(ClinePoolStrategy::RoundRobin, 3, 2, 0, &[]),
            2
        );
        assert_eq!(
            cline_pick_index(ClinePoolStrategy::RoundRobin, 3, 3, 0, &[]),
            0
        );
    }

    #[test]
    fn fill_always_picks_first() {
        assert_eq!(cline_pick_index(ClinePoolStrategy::Fill, 4, 9, 0, &[]), 0);
    }

    #[test]
    fn random_uses_seed_modulo() {
        assert_eq!(cline_pick_index(ClinePoolStrategy::Random, 4, 0, 5, &[]), 1);
        assert_eq!(cline_pick_index(ClinePoolStrategy::Random, 4, 0, 8, &[]), 0);
    }

    #[test]
    fn least_used_picks_minimum_usage() {
        assert_eq!(
            cline_pick_index(ClinePoolStrategy::LeastUsed, 4, 0, 0, &[10, 3, 7, 3]),
            1
        );
    }
}
