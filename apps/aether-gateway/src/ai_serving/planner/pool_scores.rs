use aether_data_contracts::repository::pool_scores::{
    PoolMemberIdentity, PoolMemberProbeStatus, PoolScoreScope, UpsertPoolMemberScore,
    POOL_SCORE_CAPABILITY_ACCOUNT, POOL_SCORE_SCOPE_KIND_ACCOUNT,
};
use aether_data_contracts::repository::provider_catalog::StoredProviderCatalogKey;
use aether_pool_core::{
    score_pool_member_with_rules, PoolMemberScoreInput, PoolMemberScoreRules, POOL_SCORE_VERSION,
};
use serde_json::Value;

use crate::handlers::shared::{provider_key_health_summary, provider_key_status_snapshot_payload};

pub(crate) fn build_provider_key_pool_score_upsert(
    key: &StoredProviderCatalogKey,
    provider_type: &str,
    existing: Option<&aether_data_contracts::repository::pool_scores::StoredPoolMemberScore>,
    now_unix_secs: u64,
    score_rules: PoolMemberScoreRules,
) -> UpsertPoolMemberScore {
    let identity = PoolMemberIdentity::provider_api_key(key.provider_id.clone(), key.id.clone());
    let scope = provider_key_pool_score_scope();
    let input = provider_key_score_input(
        key,
        provider_type,
        identity.clone(),
        scope.clone(),
        existing,
        now_unix_secs,
        score_rules.expiring_soon_seconds,
    );
    let output = score_pool_member_with_rules(&input, score_rules);
    UpsertPoolMemberScore {
        id: provider_key_pool_score_id(&identity, &scope),
        identity,
        scope,
        score: output.score,
        hard_state: output.hard_state,
        score_version: POOL_SCORE_VERSION,
        score_reason: output.score_reason,
        last_ranked_at: Some(now_unix_secs),
        last_scheduled_at: existing.and_then(|score| score.last_scheduled_at),
        last_success_at: existing.and_then(|score| score.last_success_at),
        last_failure_at: existing.and_then(|score| score.last_failure_at),
        failure_count: existing.map(|score| score.failure_count).unwrap_or(0),
        last_probe_attempt_at: existing.and_then(|score| score.last_probe_attempt_at),
        last_probe_success_at: existing.and_then(|score| score.last_probe_success_at),
        last_probe_failure_at: existing.and_then(|score| score.last_probe_failure_at),
        probe_failure_count: existing.map(|score| score.probe_failure_count).unwrap_or(0),
        probe_status: existing
            .map(|score| score.probe_status)
            .unwrap_or(PoolMemberProbeStatus::Never),
        updated_at: now_unix_secs,
    }
}

pub(crate) fn provider_key_pool_score_scope() -> PoolScoreScope {
    PoolScoreScope {
        capability: POOL_SCORE_CAPABILITY_ACCOUNT.to_string(),
        scope_kind: POOL_SCORE_SCOPE_KIND_ACCOUNT.to_string(),
        scope_id: None,
    }
}

pub(crate) fn provider_key_pool_score_id(
    identity: &PoolMemberIdentity,
    scope: &PoolScoreScope,
) -> String {
    let raw = format!(
        "{}:{}:{}:{}:{}:{}:{}",
        identity.pool_kind,
        identity.pool_id,
        identity.member_kind,
        identity.member_id,
        scope.capability,
        scope.scope_kind,
        scope.scope_id.as_deref().unwrap_or("*")
    );
    format!(
        "pms-{:016x}-{:016x}",
        stable_hash(raw.as_bytes()),
        stable_hash(identity.member_id.as_bytes())
    )
}

fn provider_key_score_input(
    key: &StoredProviderCatalogKey,
    provider_type: &str,
    identity: PoolMemberIdentity,
    scope: PoolScoreScope,
    existing: Option<&aether_data_contracts::repository::pool_scores::StoredPoolMemberScore>,
    now_unix_secs: u64,
    expiring_soon_seconds: u64,
) -> PoolMemberScoreInput {
    let status_snapshot = provider_key_status_snapshot_payload(key, provider_type);
    let quota_snapshot = status_snapshot
        .as_object()
        .and_then(|snapshot| snapshot.get("quota"))
        .and_then(Value::as_object);
    let account_snapshot = status_snapshot
        .as_object()
        .and_then(|snapshot| snapshot.get("account"))
        .and_then(Value::as_object);
    let (health_score, _, _, _, _) = provider_key_health_summary(key);
    let health_score = key
        .health_by_format
        .as_ref()
        .and_then(Value::as_object)
        .filter(|payload| !payload.is_empty())
        .map(|_| health_score);

    PoolMemberScoreInput {
        identity,
        scope: scope.clone(),
        internal_priority: key.internal_priority,
        is_active: key.is_active,
        health_score,
        quota_usage_ratio: quota_snapshot
            .and_then(|quota| quota.get("usage_ratio"))
            .and_then(json_f64)
            .map(|value| value.clamp(0.0, 1.0)),
        quota_exhausted: quota_snapshot
            .and_then(|quota| quota.get("exhausted"))
            .and_then(Value::as_bool)
            .unwrap_or(false),
        expiring_credits: expiring_credits_from_upstream_metadata(
            key,
            now_unix_secs,
            expiring_soon_seconds,
        ),
        account_blocked: account_snapshot
            .and_then(|account| account.get("blocked"))
            .and_then(Value::as_bool)
            .unwrap_or(false),
        oauth_invalid_reason: key.oauth_invalid_reason.clone(),
        success_count: key.success_count.unwrap_or(0).into(),
        error_count: key.error_count.unwrap_or(0).into(),
        total_response_time_ms: key.total_response_time_ms.unwrap_or(0),
        total_tokens: key.total_tokens,
        total_cost_usd: key.total_cost_usd,
        last_used_at: key.last_used_at_unix_secs,
        last_probe_success_at: existing.and_then(|score| score.last_probe_success_at),
        probe_failure_count: existing.map(|score| score.probe_failure_count).unwrap_or(0),
        probe_status: existing
            .map(|score| score.probe_status)
            .unwrap_or(PoolMemberProbeStatus::Never),
        now_unix_secs,
    }
}

/// workbuddy 桶里「窗口内即将过期的可用积分」（面板 `entry.creditsExpiring` 的等价物）。
///
/// 判据与面板一致（`UserResourceDetailedWithExpiry` + `expiringNow`）：
/// 套餐到期时刻 `packages[].expires_at` **仍在未来**、且 ≤ `now + 窗口` → 该份 `remaining` 计入。
/// `窗口 == 0` 时直接返回 0（**关闭分桶**，与引入前逐字节一致）。
///
/// 注意：这里读的是**上游元数据桶里的明细**（快照会按白名单丢掉 `packages`，
/// 见 `build_workbuddy_quota_status_snapshot` 的注释），所以走 `upstream_metadata` 而不是快照。
fn expiring_credits_from_upstream_metadata(
    key: &StoredProviderCatalogKey,
    now_unix_secs: u64,
    expiring_soon_seconds: u64,
) -> i64 {
    if expiring_soon_seconds == 0 {
        return 0;
    }
    let Some(bucket) = key
        .upstream_metadata
        .as_ref()
        .and_then(|metadata| metadata.get("workbuddy"))
    else {
        return 0;
    };
    let Some(packages) = bucket
        .get("packages")
        .or_else(|| {
            bucket
                .get("balance")
                .and_then(|balance| balance.get("packages"))
        })
        .and_then(Value::as_array)
    else {
        return 0;
    };
    let horizon = now_unix_secs.saturating_add(expiring_soon_seconds);
    packages
        .iter()
        .filter_map(|package| {
            let expires_at = package.get("expires_at").and_then(json_u64)?;
            // 已过期的不算；窗口外的不算（面板同款：只有「快过期」才插队）。
            if expires_at <= now_unix_secs || expires_at > horizon {
                return None;
            }
            let remaining = package.get("remaining").and_then(json_f64).unwrap_or(0.0);
            Some(remaining.max(0.0) as i64)
        })
        .sum()
}

fn json_u64(value: &Value) -> Option<u64> {
    value.as_u64().or_else(|| {
        value
            .as_str()
            .map(str::trim)
            .filter(|value| !value.is_empty())
            .and_then(|value| value.parse::<u64>().ok())
    })
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

fn stable_hash(bytes: &[u8]) -> u64 {
    let mut hash = 0xcbf29ce484222325u64;
    for byte in bytes {
        hash ^= u64::from(*byte);
        hash = hash.wrapping_mul(0x100000001b3);
    }
    hash
}

#[cfg(test)]
mod tests {
    use super::*;
    use aether_data_contracts::repository::pool_scores::PoolMemberHardState;
    use serde_json::json;

    fn sample_key_with_circuit_next_probe(
        next_probe_at_unix_secs: u64,
    ) -> StoredProviderCatalogKey {
        let mut key = StoredProviderCatalogKey::new(
            "key-gemini-5".to_string(),
            "provider-google-api".to_string(),
            "5".to_string(),
            "api_key".to_string(),
            None,
            true,
        )
        .expect("sample key should be valid");
        key.health_by_format = Some(json!({
            "gemini:generate_content": {
                "health_score": 0.2,
                "consecutive_failures": 8
            }
        }));
        key.circuit_breaker_by_format = Some(json!({
            "gemini:generate_content": {
                "open": true,
                "reason": "consecutive_failures_8",
                "next_probe_at_unix_secs": next_probe_at_unix_secs
            }
        }));
        key
    }

    #[test]
    fn expired_circuit_probe_deadline_does_not_leave_pool_score_in_cooldown() {
        let now_unix_secs = 1_000;
        let key = sample_key_with_circuit_next_probe(900);

        let score = build_provider_key_pool_score_upsert(
            &key,
            "custom",
            None,
            now_unix_secs,
            PoolMemberScoreRules::default(),
        );

        assert_eq!(score.hard_state, PoolMemberHardState::Available);
    }

    #[test]
    fn future_key_circuit_probe_deadline_does_not_drive_pool_score_cooldown() {
        let now_unix_secs = 1_000;
        let key = sample_key_with_circuit_next_probe(1_100);

        let score = build_provider_key_pool_score_upsert(
            &key,
            "custom",
            None,
            now_unix_secs,
            PoolMemberScoreRules::default(),
        );

        assert_eq!(score.hard_state, PoolMemberHardState::Available);
    }
}
