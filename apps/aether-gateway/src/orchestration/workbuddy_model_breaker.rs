//! WorkBuddy（腾讯 CodeBuddy）「账号×模型」不可用负缓存（`11102`）的**写入侧**。
//!
//! **为什么按 (账号, 模型) 而不是按账号**：上游 `11102`（该后端无此模型 / `service info
//! not found`）是**确定性**答复——同一个 (账号, 模型) 再试结果不变，但账号对别的模型完全
//! 正常。把账号标成坏号会误杀健康账号，把整个模型全局避让又会牵连其它账号；只有
//! (账号, 模型) 这一格是准的。
//!
//! **读取侧不在这里**：`WorkbuddyProviderPoolAdapter::quota_hard_blocked` 会读这段元数据，
//! 而调度器评估候选时本来就会问它（`read_key_account_quota_exhaustion_map` →
//! `admin_pool_key_model_quota_hard_blocked`）——所以本模块只负责写，**不需要改调度器**。
//!
//! 退避照面板 `pool.BlockModelBackoff`：6h 起、每再失败一次翻倍、封顶 24h；到点自动失效，
//! 下次允许再试（半开探测）。

use aether_contracts::ExecutionPlan;
use serde_json::{json, Map, Value};
use tracing::info;

use crate::AppState;
use aether_provider_transport::workbuddy::failure::{
    classify_workbuddy_failure, workbuddy_body_is_model_rate_limit,
    workbuddy_parse_rate_reset_unix_secs, WorkbuddyFailureKind,
};

/// 负缓存起始时长（面板 `modelBlockBaseTTL`）。
const WORKBUDDY_MODEL_BLOCK_BASE_TTL_SECONDS: u64 = 6 * 60 * 60;
/// 负缓存上限（面板 `modelBlockMaxTTL`）。
const WORKBUDDY_MODEL_BLOCK_MAX_TTL_SECONDS: u64 = 24 * 60 * 60;
/// 退避最多左移几位（面板 `modelBlockShift`）。
const WORKBUDDY_MODEL_BLOCK_MAX_SHIFT: u32 = 4;

/// 模型级限流（`6004`，带上游重置墙钟）的冷却上限。
///
/// 面板 `cappedSoftUntilLocked`：`until = min(resetAt, now + softRateMax)`，而
/// `softRateMaxOr()` 未注册时**默认 2h**——上游偶尔会给出很远的重置时间，不截顶就是变相永久锁。
const WORKBUDDY_MODEL_RATE_LIMIT_CAP_SECONDS: u64 = 2 * 60 * 60;

/// 模型级限流（`6004`）的冷却截止时刻（纯函数，便于测试）。
///
/// - 解析出上游重置墙钟 → `min(重置时刻, now + 2h)`（面板截顶口径）；
/// - 解析不出来 → `None`，表示**只能记一条 AuditOnly 展示项**：面板此时不按模型锁路由
///   （账号仍按原有有界退避冷却），我方对应的做法是**不写 `until_unix_secs`**，
///   这样读侧 `workbuddy_model_blocked_at` 读不到 until 就天然不拦截。
pub(crate) fn workbuddy_model_rate_limit_until(
    reset_unix_secs: Option<u64>,
    now_unix_secs: u64,
) -> Option<u64> {
    let reset = reset_unix_secs?;
    let cap = now_unix_secs.saturating_add(WORKBUDDY_MODEL_RATE_LIMIT_CAP_SECONDS);
    Some(reset.min(cap))
}

/// 从计划里取**provider 侧模型名**（调度器读的是 `selected_provider_model_name`）。
///
/// 最权威的来源是**出站 body 里的 `model`**（正是上游看到的模型名）；取不到再退回
/// `plan.model_name`。两条写入路径（`11102` / `6004`）必须用同一套解析，否则缓存读不到。
fn workbuddy_plan_provider_model(plan: &ExecutionPlan) -> Option<&str> {
    let body_model = plan
        .body
        .json_body
        .as_ref()
        .and_then(|body| body.get("model"))
        .and_then(Value::as_str)
        .map(str::trim)
        .filter(|value| !value.is_empty());
    body_model.or_else(|| {
        plan.model_name
            .as_deref()
            .map(str::trim)
            .filter(|value| !value.is_empty())
    })
}

/// 读出现有的 `model_blocked` 条目表（保留其它模型的记录）。
fn workbuddy_model_blocked_entries(existing_metadata: Option<&Value>) -> Map<String, Value> {
    existing_metadata
        .and_then(Value::as_object)
        .and_then(|metadata| metadata.get("workbuddy"))
        .and_then(Value::as_object)
        .and_then(|bucket| bucket.get("model_blocked"))
        .and_then(Value::as_object)
        .cloned()
        .unwrap_or_default()
}

/// 第 `hits` 次失败对应的负缓存时长（纯函数，便于测试）。
///
/// 面板口径：`base * 2^min(hits-1, shift)`，超过上限就取上限。所以
/// hits=1 → 6h、2 → 12h、3 → 24h、≥3 → 24h（6h×8=48h 已被上限截断）。
pub(crate) fn workbuddy_model_block_ttl_seconds(hits: u64) -> u64 {
    let hits = hits.max(1);
    let shift = hits
        .saturating_sub(1)
        .min(u64::from(WORKBUDDY_MODEL_BLOCK_MAX_SHIFT));
    let scaled = WORKBUDDY_MODEL_BLOCK_BASE_TTL_SECONDS.saturating_mul(1u64 << shift);
    scaled.min(WORKBUDDY_MODEL_BLOCK_MAX_TTL_SECONDS)
}

/// 记录一次 `11102`：给 (key, model) 写/续一段负缓存。
///
/// 只在**同时满足**下列条件时动手，否则什么都不做（返回 `false`）：
/// 1. 计划带 workbuddy 内部标记头（别的 provider 一律不碰）；
/// 2. 失败分类是 `model_blocked`（`11102` / `service info not found`）；
/// 3. 计划里有**provider 侧**模型名（`mapped_model`，回退 `model_name`）。
pub(crate) async fn note_workbuddy_model_blocked(
    state: &AppState,
    plan: &ExecutionPlan,
    status_code: u16,
    error_body: Option<&str>,
) -> bool {
    if !aether_provider_transport::workbuddy::has_workbuddy_internal_header_map(&plan.headers) {
        return false;
    }
    let failure_kind = classify_workbuddy_failure(status_code, error_body);
    if !matches!(
        failure_kind,
        WorkbuddyFailureKind::ModelBlocked | WorkbuddyFailureKind::PlanBlocked
    ) {
        return false;
    }
    let plan_blocked = failure_kind == WorkbuddyFailureKind::PlanBlocked;
    // **必须用 provider 侧模型名**，而 `plan.model_name` 是**客户端请求的**模型
    // （`build_ai_execution_plan_from_decision` 从 decision 的 `model_name` 取，chat 路径
    // 填的是 `input.requested_model`，可能带 `-high` 之类的指令后缀）。调度器读的却是
    // `candidate.selected_provider_model_name`——用错就永远命不中缓存。
    let Some(model_name) = workbuddy_plan_provider_model(plan) else {
        return false;
    };

    let existing_metadata = state
        .read_provider_catalog_keys_by_ids(std::slice::from_ref(&plan.key_id))
        .await
        .ok()
        .and_then(|keys| keys.into_iter().next())
        .and_then(|key| key.upstream_metadata);

    let now_unix_secs = crate::clock::current_unix_secs();
    let hits = workbuddy_model_blocked_hits(existing_metadata.as_ref(), model_name) + 1;
    let ttl_seconds = workbuddy_model_block_ttl_seconds(hits);
    let until_unix_secs = now_unix_secs.saturating_add(ttl_seconds);

    let mut entries = workbuddy_model_blocked_entries(existing_metadata.as_ref());
    entries.insert(
        model_name.to_string(),
        json!({
            "until_unix_secs": until_unix_secs,
            "observed_at_unix_secs": now_unix_secs,
            "hits": hits,
            "kind": if plan_blocked { "plan_blocked" } else { "model_unavailable" },
            "reason": if plan_blocked { "11158 model is not allowed for this user type" } else { "11102 model not available" },
        }),
    );

    let update = json!({
        "workbuddy": {
            "model_blocked": Value::Object(entries),
            "updated_at": now_unix_secs,
        }
    });
    let merged = merge_workbuddy_metadata(existing_metadata.as_ref(), &update);

    match state
        .update_provider_catalog_key_upstream_metadata(
            &plan.key_id,
            Some(&merged),
            Some(now_unix_secs),
        )
        .await
    {
        Ok(true) => {
            info!(
                event_name = "workbuddy_model_blocked_recorded",
                log_type = "event",
                provider_id = %plan.provider_id,
                endpoint_id = %plan.endpoint_id,
                key_id = %plan.key_id,
                model_name,
                hits,
                ttl_seconds,
                until_unix_secs,
                status_code,
                "gateway recorded a WorkBuddy (account, model) negative cache entry"
            );
            true
        }
        Ok(false) => false,
        Err(error) => {
            // 写不进去不影响本次请求（下次 11102 会再试），只记日志。
            tracing::warn!(
                event_name = "workbuddy_model_blocked_persist_failed",
                log_type = "ops",
                key_id = %plan.key_id,
                model_name,
                error = ?error,
                "gateway could not persist WorkBuddy model negative cache"
            );
            false
        }
    }
}

/// 记录一次 **`6004` 模型级限流**：只锁 `(账号, 模型)` 这一格，**不锁账号**。
///
/// 与 `11102` 的区别（面板 `applyErrorPolicy` 的 `ErrSoftRate` 分支）：
/// - `11102` 是**确定性**答复 → 指数退避（6h 起、封顶 24h）；
/// - `6004` 是**限流**，上游通常给出**权威重置墙钟** → `until = min(重置时刻, now+2h)`；
///   给不出重置时间时**只记 AuditOnly 展示项**（不写 `until_unix_secs`，路由不拦），
///   账号级退避由通用软限流机制照旧处理。
///
/// 只在**同时满足**下列条件时动手（否则 `false`，什么都不做）：
/// 1. 计划带 workbuddy 内部标记头；
/// 2. 响应体里确实有业务码 `6004`（面板 `IsModelRateLimit`）——账号级 429 不在此列；
/// 3. 计划里能取到 provider 侧模型名。
pub(crate) async fn note_workbuddy_model_rate_limited(
    state: &AppState,
    plan: &ExecutionPlan,
    status_code: u16,
    error_body: Option<&str>,
) -> bool {
    if !aether_provider_transport::workbuddy::has_workbuddy_internal_header_map(&plan.headers) {
        return false;
    }
    let body = error_body.unwrap_or_default();
    if !workbuddy_body_is_model_rate_limit(body) {
        return false;
    }
    let Some(model_name) = workbuddy_plan_provider_model(plan) else {
        return false;
    };

    let existing_metadata = state
        .read_provider_catalog_keys_by_ids(std::slice::from_ref(&plan.key_id))
        .await
        .ok()
        .and_then(|keys| keys.into_iter().next())
        .and_then(|key| key.upstream_metadata);

    let now_unix_secs = crate::clock::current_unix_secs();
    let reset_unix_secs = workbuddy_parse_rate_reset_unix_secs(body);
    let until_unix_secs = workbuddy_model_rate_limit_until(reset_unix_secs, now_unix_secs);

    let mut entries = workbuddy_model_blocked_entries(existing_metadata.as_ref());
    // `hits` 恒 0：6004 没有「连续次数驱动退避」的语义（面板注释原话）。
    let entry = match until_unix_secs {
        Some(until) => json!({
            "until_unix_secs": until,
            "reset_at_unix_secs": reset_unix_secs,
            "observed_at_unix_secs": now_unix_secs,
            "hits": 0,
            "kind": "rate_limit",
            "reason": "6004 model rate limit",
        }),
        None => json!({
            // 注意：**故意不写 `until_unix_secs`** —— 读侧读不到就不拦路由，
            // 与面板「AuditOnly 只展示」的语义一致。
            "audit_only": true,
            "observed_at_unix_secs": now_unix_secs,
            "hits": 0,
            "kind": "rate_limit",
            "reason": "6004 model rate limit (reset unknown)",
        }),
    };
    entries.insert(model_name.to_string(), entry);

    let update = json!({
        "workbuddy": {
            "model_blocked": Value::Object(entries),
            "updated_at": now_unix_secs,
        }
    });
    let merged = merge_workbuddy_metadata(existing_metadata.as_ref(), &update);

    match state
        .update_provider_catalog_key_upstream_metadata(
            &plan.key_id,
            Some(&merged),
            Some(now_unix_secs),
        )
        .await
    {
        Ok(true) => {
            info!(
                event_name = "workbuddy_model_rate_limit_recorded",
                log_type = "event",
                provider_id = %plan.provider_id,
                endpoint_id = %plan.endpoint_id,
                key_id = %plan.key_id,
                model_name,
                status_code,
                reset_unix_secs,
                until_unix_secs,
                audit_only = until_unix_secs.is_none(),
                "gateway recorded a WorkBuddy (account, model) rate-limit entry"
            );
            true
        }
        Ok(false) => false,
        Err(error) => {
            tracing::warn!(
                event_name = "workbuddy_model_rate_limit_persist_failed",
                log_type = "ops",
                key_id = %plan.key_id,
                model_name,
                error = ?error,
                "gateway could not persist WorkBuddy model rate-limit entry"
            );
            false
        }
    }
}

/// 该模型已有的连续失败次数（用于退避）。
fn workbuddy_model_blocked_hits(metadata: Option<&Value>, model_name: &str) -> u64 {
    let normalized = model_name.trim().to_ascii_lowercase();
    metadata
        .and_then(Value::as_object)
        .and_then(|metadata| metadata.get("workbuddy"))
        .and_then(Value::as_object)
        .and_then(|bucket| bucket.get("model_blocked"))
        .and_then(Value::as_object)
        .and_then(|entries| {
            entries.iter().find_map(|(model, entry)| {
                (model.trim().to_ascii_lowercase() == normalized)
                    .then(|| entry.get("hits").and_then(Value::as_u64).unwrap_or(0))
            })
        })
        .unwrap_or(0)
}

/// 把更新合并进现有元数据：`workbuddy` 桶内**逐字段**合并（新值胜出），
/// 其它 provider 的桶原样保留。
fn merge_workbuddy_metadata(existing: Option<&Value>, update: &Value) -> Value {
    let mut merged = existing
        .and_then(Value::as_object)
        .cloned()
        .unwrap_or_default();
    let Some(update_object) = update.as_object() else {
        return Value::Object(merged);
    };
    for (provider_type, value) in update_object {
        let mut next = value.clone();
        if let (Some(current), Some(next_object)) = (
            merged.get(provider_type).and_then(Value::as_object),
            next.as_object_mut(),
        ) {
            let mut combined = current.clone();
            combined.extend(next_object.clone());
            next = Value::Object(combined);
        }
        merged.insert(provider_type.clone(), next);
    }
    Value::Object(merged)
}

#[cfg(test)]
mod tests {
    use super::{
        merge_workbuddy_metadata, workbuddy_model_block_ttl_seconds,
        workbuddy_model_rate_limit_until, WORKBUDDY_MODEL_RATE_LIMIT_CAP_SECONDS,
    };
    use serde_json::json;

    /// `6004` 冷却截止：**对齐上游重置墙钟但截顶 2h**；解析不出重置时间就**不锁路由**。
    ///
    /// 这测试钉住的是「模型级限流只锁模型、且不会变成变相永久锁」这两条语义。
    #[test]
    fn model_rate_limit_until_aligns_to_reset_and_caps_at_two_hours() {
        let now = 1_000_000u64;
        let cap = now + WORKBUDDY_MODEL_RATE_LIMIT_CAP_SECONDS;
        assert_eq!(WORKBUDDY_MODEL_RATE_LIMIT_CAP_SECONDS, 2 * 60 * 60);

        // 上游给的重置时间在 2h 内 → 就用它（对齐权威墙钟）。
        assert_eq!(
            workbuddy_model_rate_limit_until(Some(now + 600), now),
            Some(now + 600)
        );
        // 恰好等于上限 → 取上限本身。
        assert_eq!(workbuddy_model_rate_limit_until(Some(cap), now), Some(cap));
        // 上游给了很远的重置时间（甚至几年后）→ 截顶到 2h，绝不永久锁。
        assert_eq!(
            workbuddy_model_rate_limit_until(Some(now + 365 * 24 * 3600), now),
            Some(cap)
        );
        // 上游给的重置时间已经过去（时钟偏差）→ 仍然截顶（返回过去时刻 → 立即失效）。
        assert_eq!(
            workbuddy_model_rate_limit_until(Some(now - 10), now),
            Some(now - 10)
        );
        // **解析不出来 → None**：面板此时只记 AuditOnly 展示项，不按模型锁路由。
        assert_eq!(workbuddy_model_rate_limit_until(None, now), None);
    }

    /// 退避：6h 起、翻倍、封顶 24h（面板 `BlockModelBackoff` 同口径）。
    #[test]
    fn ttl_backs_off_exponentially_and_caps_at_one_day() {
        assert_eq!(workbuddy_model_block_ttl_seconds(0), 6 * 3600);
        assert_eq!(workbuddy_model_block_ttl_seconds(1), 6 * 3600);
        assert_eq!(workbuddy_model_block_ttl_seconds(2), 12 * 3600);
        assert_eq!(workbuddy_model_block_ttl_seconds(3), 24 * 3600);
        // 再往上都被上限截断，不会无限增长。
        for hits in [4u64, 5, 16, 1_000] {
            assert_eq!(workbuddy_model_block_ttl_seconds(hits), 24 * 3600);
        }
    }

    /// 合并：workbuddy 桶内逐字段合并、别的 provider 原样保留。
    #[test]
    fn metadata_merge_keeps_other_providers_and_bucket_fields() {
        let existing = json!({
            "codex": {"primary_used_percent": 10.0},
            "workbuddy": {"updated_at": 1, "credits_used": 5.0}
        });
        let update = json!({
            "workbuddy": {"model_blocked": {"glm-5.2": {"until_unix_secs": 99}}, "updated_at": 2}
        });
        let merged = merge_workbuddy_metadata(Some(&existing), &update);
        assert_eq!(merged["codex"]["primary_used_percent"], json!(10.0));
        assert_eq!(merged["workbuddy"]["updated_at"], json!(2));
        // 桶内原有字段不被抹掉（余额刷新写的字段还在）。
        assert_eq!(merged["workbuddy"]["credits_used"], json!(5.0));
        assert_eq!(
            merged["workbuddy"]["model_blocked"]["glm-5.2"]["until_unix_secs"],
            json!(99)
        );

        // 没有既有元数据时也能建出来。
        let merged = merge_workbuddy_metadata(None, &update);
        assert_eq!(merged["workbuddy"]["updated_at"], json!(2));
    }
}
