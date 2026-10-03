//! AMD 模型负载感知的管理接口。
//!
//! - `GET  /api/admin/amd-load/providers/{id}`            快照 + 生效配置 + 判定结果
//! - `PUT  /api/admin/amd-load/providers/{id}/config`     保存阈值与轮询配置
//! - `POST /api/admin/amd-load/providers/{id}/refresh`    立刻拉一次负载快照
//!
//! 领域逻辑在 `crate::amd_load`（快照、判定、轮询），这里只做 HTTP 与配置读写。

use std::collections::HashMap;

use axum::{
    body::{Body, Bytes},
    http,
    response::{IntoResponse, Response},
    Json,
};
use serde_json::{json, Value};

use crate::amd_load::{config::AmdLoadConfig, now_unix_secs, poller, AMD_LOAD_CONFIG_KEY};
use crate::handlers::admin::request::{AdminAppState, AdminRequestContext};
use crate::opencode_pool::pool::write_provider_config_section_with;
use crate::GatewayError;

const AMD_LOAD_PATH_PREFIX: &str = "/api/admin/amd-load/providers/";
/// CAS 重试次数，与出口池那边一致。
const CONFIG_WRITE_RETRIES: usize = 8;

pub(crate) async fn maybe_build_local_admin_amd_load_response(
    state: &AdminAppState<'_>,
    request_context: &AdminRequestContext<'_>,
    request_body: Option<&Bytes>,
) -> Result<Option<Response<Body>>, GatewayError> {
    let path = request_context.path();
    if !path.starts_with(AMD_LOAD_PATH_PREFIX) {
        return Ok(None);
    }
    let Some(provider_id) = amd_load_provider_id(path) else {
        return Ok(Some(bad_request("provider id 缺失")));
    };
    let app = state.as_ref();

    if path.ends_with("/config") {
        return save_config(app, &provider_id, request_body).await.map(Some);
    }
    if path.ends_with("/refresh") {
        return refresh_snapshot(app, &provider_id).await.map(Some);
    }
    status(app, &provider_id).await.map(Some)
}

/// 读 provider 的 config 段。
///
/// `None` = 供应商不存在；`Some(None)` = 供应商存在但 config 尚未写入过。这两种
/// 情况要分开：前者是 404 语义的错误，后者只是「还没配置过」，应当按默认配置处理。
async fn read_provider_config(
    app: &crate::AppState,
    provider_id: &str,
) -> Result<Option<Option<Value>>, GatewayError> {
    Ok(app
        .read_provider_catalog_providers_by_ids(std::slice::from_ref(&provider_id.to_string()))
        .await?
        .into_iter()
        .next()
        .map(|provider| provider.config))
}

async fn save_config(
    app: &crate::AppState,
    provider_id: &str,
    request_body: Option<&Bytes>,
) -> Result<Response<Body>, GatewayError> {
    let payload: Value = match request_body {
        Some(body) => match serde_json::from_slice::<Value>(body) {
            Ok(value) => value,
            Err(err) => return Ok(bad_request(format!("请求体不是合法 JSON：{err}"))),
        },
        None => json!({}),
    };
    // 请求体可以带 `amd_load` 外层段，也可以直接就是段本身。
    let section = payload
        .get(AMD_LOAD_CONFIG_KEY)
        .cloned()
        .unwrap_or_else(|| payload.clone());

    // 校验必须在**合并之前**做：合并后已被默认值兜底改过，报错会指不到用户真正
    // 写错的那个字段（他会看到「5，怎么不对」，而他写的是 -1）。
    let probe = AmdLoadConfig::default().merged_with_payload(Some(&section));
    if let Err(detail) = probe.validate() {
        return Ok(bad_request(format!("AMD 负载配置无效：{detail}")));
    }

    let mut conflict = true;
    let mut saved_section = section.clone();
    for _ in 0..CONFIG_WRITE_RETRIES {
        let Some(current) = read_provider_config(app, provider_id).await? else {
            return Ok(bad_request(format!("供应商不存在：{provider_id}")));
        };
        // 每轮都重读并按最新值合并：后台轮询可能刚写入过，别人的修改要保住。
        let next = AmdLoadConfig::from_provider_config(current.as_ref())
            .merged_with_payload(Some(&saved_section));
        if let Err(detail) = next.validate() {
            return Ok(bad_request(format!("AMD 负载配置无效：{detail}")));
        }
        let to_write = config_to_value(&next);
        // CAS 写入这个原语内部自带重试；这里那层循环是为了把「重读 + 合并」放到
        // 每次重试里，否则第一次 CAS 失败后重试的仍是旧合并结果。
        let outcome =
            write_provider_config_section_with(app, provider_id, "AMD 负载配置", |config_map| {
                config_map.insert(AMD_LOAD_CONFIG_KEY.to_string(), to_write.clone());
            })
            .await;
        match outcome {
            Ok(()) => {
                conflict = false;
                break;
            }
            Err(GatewayError::Internal(detail)) if detail.contains("撞上并发修改") => {
                continue
            }
            Err(err) => return Err(err),
        }
    }
    if conflict {
        // 这是「有人正在改，请重试」，不是保存失败。回 500 会让用户以为没存上，
        // 然后反复点、反复撞上、反复失败。
        return Ok(conflict_response());
    }

    // 回显生效值而不是刚提交的原始值：合并后可能被默认值兜底改过（比如用户没填
    // recovery_threshold，实际生效的是禁用阈值），界面上显示的必须是真正在判定用的数。
    let applied = AmdLoadConfig::from_provider_config(
        read_provider_config(app, provider_id)
            .await?
            .as_ref()
            .and_then(|config| config.as_ref()),
    );
    Ok(Json(json!({
        "saved": true,
        "config": config_to_value(&applied),
        "warnings": applied.warnings(),
    }))
    .into_response())
}

async fn refresh_snapshot(
    app: &crate::AppState,
    provider_id: &str,
) -> Result<Response<Body>, GatewayError> {
    let Some(config) = read_provider_config(app, provider_id).await? else {
        return Ok(bad_request(format!("供应商不存在：{provider_id}")));
    };
    let base_url = app
        .list_provider_catalog_endpoints_by_provider_ids(std::slice::from_ref(
            &provider_id.to_string(),
        ))
        .await?
        .into_iter()
        .next()
        .map(|endpoint| endpoint.base_url)
        .unwrap_or_default();
    if !poller::is_amd_upstream(&base_url) {
        return Ok(bad_request(
            "该供应商的端点不是 AMD 上游：负载接口只对 /radeon/api/v1 形式的 base_url 有效",
        ));
    }
    if !AmdLoadConfig::from_provider_config(config.as_ref()).enabled {
        return Ok(bad_request("AMD 负载感知未启用，请先启用后再刷新"));
    }

    // 轮询本身是**全体 AMD 供应商**跑的，不是按 provider 的：它内部按 provider_id
    // 记上次尝试时间来限速，传一个空的 map 意味着这一轮对所有到点的供应商各拉一次。
    // 所以这里的 summary 是聚合值，不能当成「只有这个 provider 被刷了」。
    let mut last_attempt: HashMap<String, u64> = HashMap::new();
    let summary = poller::run_amd_load_poll_once(app, &mut last_attempt, now_unix_secs()).await?;
    let config = AmdLoadConfig::from_provider_config(
        read_provider_config(app, provider_id)
            .await?
            .as_ref()
            .and_then(|config| config.as_ref()),
    );
    let snapshot = poller::read_snapshot(app, provider_id).await;
    Ok(Json(json!({
        "summary": summary,
        "snapshot_expired": snapshot
            .as_ref()
            .map(|snapshot| snapshot.is_expired(&config, now_unix_secs()))
            .unwrap_or(true),
        "blocked_models": snapshot
            .as_ref()
            .map(|snapshot| snapshot.blocked_models(&config))
            .unwrap_or_default(),
    }))
    .into_response())
}

async fn status(app: &crate::AppState, provider_id: &str) -> Result<Response<Body>, GatewayError> {
    let Some(raw_config) = read_provider_config(app, provider_id).await? else {
        return Ok(bad_request(format!("供应商不存在：{provider_id}")));
    };
    let config = AmdLoadConfig::from_provider_config(raw_config.as_ref());
    let base_url = app
        .list_provider_catalog_endpoints_by_provider_ids(std::slice::from_ref(
            &provider_id.to_string(),
        ))
        .await?
        .into_iter()
        .next()
        .map(|endpoint| endpoint.base_url)
        .unwrap_or_default();
    let snapshot = poller::read_snapshot(app, provider_id).await;
    let now = now_unix_secs();
    Ok(Json(json!({
        "config": config_to_value(&config),
        "warnings": config.warnings(),
        "is_amd_upstream": poller::is_amd_upstream(&base_url),
        "load_endpoint": poller::load_endpoint_url(&base_url),
        "usage_endpoint": poller::usage_endpoint_url(&base_url),
        "usage": usage_to_value(poller::read_usage_snapshot(app, provider_id).await.as_ref()),
        "snapshot_present": snapshot.is_some(),
        "snapshot_expired": snapshot
            .as_ref()
            .map(|snapshot| snapshot.is_expired(&config, now))
            .unwrap_or(true),
        "snapshot_fetched_at": snapshot.as_ref().map(|snapshot| snapshot.fetched_at),
        "scope": snapshot.as_ref().map(|snapshot| snapshot.scope.clone()),
        "blocked_models": snapshot
            .as_ref()
            .map(|snapshot| snapshot.blocked_models(&config))
            .unwrap_or_default(),
        "models": snapshot
            .as_ref()
            .map(|snapshot| snapshot.describe(&config))
            .unwrap_or_default(),
    }))
    .into_response())
}

/// `AmdLoadConfig` 只有读取与合并，没有序列化。响应里要回显**生效值**（已套默认值），
/// 而不是用户提交的原始值——界面上显示的必须是真正在判定用的那个数。
fn config_to_value(config: &AmdLoadConfig) -> Value {
    json!({
        "enabled": config.enabled,
        // 漏掉这一项会让接口读不回自己刚写的字段：保存 block_models 后响应里没有
        // 它，界面只能靠猜「到底存没存上」。
        "block_models": config.block_models,
        "poll_sec": config.poll_sec,
        "disable_threshold": config.disable_threshold,
        "recovery_threshold": config.recovery_threshold,
        "disable_streak": config.disable_streak,
        "snapshot_ttl_sec": config.snapshot_ttl_sec,
        "timeout_sec": config.timeout_sec,
        "has_hysteresis": config.has_hysteresis(),
        "effective_recovery": config.effective_recovery(),
    })
}

/// 从 `/api/admin/amd-load/providers/{id}[/action]` 解析 Provider ID。
///
/// 刻意**不**校验 id 长度。opencode 那边同名函数强制 `len() == 36`，而整条处理链
/// 取不到路由时只返回一个 501，症状看起来像「接口没实现」，真因却是 id 不合长度。
/// 同目录其他路径解析器都没有这个限制，这里也不要有。
fn amd_load_provider_id(path: &str) -> Option<String> {
    let rest = path.strip_prefix(AMD_LOAD_PATH_PREFIX)?;
    let segments: Vec<&str> = rest.split('/').filter(|s| !s.is_empty()).collect();
    let id = segments.first()?.to_string();
    if id.is_empty() {
        return None;
    }
    Some(id)
}

fn bad_request(detail: impl Into<String>) -> Response<Body> {
    (
        http::StatusCode::BAD_REQUEST,
        Json(json!({ "detail": detail.into() })),
    )
        .into_response()
}

/// 配额快照的响应形状。
///
/// **回传那两个死字段**（`daily_cost_used_usd` / `daily_cost_remaining_usd`），并附上
/// `untrustworthy_fields` 说明——刻意不隐藏它们：接口里真实存在的东西悄悄消失，
/// 会让人以为是我们读错了。标清楚「上游未实现，请勿当作余额」比藏起来好。
///
/// `usage_ratio` 是我们自己用 `today.cost / daily_cost_limit_usd` 算的，不来自上游。
fn usage_to_value(snapshot: Option<&crate::amd_load::AmdUsageSnapshot>) -> Value {
    let Some(snapshot) = snapshot else {
        return Value::Null;
    };
    json!({
        "fetched_at": snapshot.fetched_at,
        "daily_cost_limit_usd": snapshot.daily_cost_limit_usd,
        "rpm_limit": snapshot.rpm_limit,
        "usage_ratio": snapshot.usage_ratio(),
        "today": window_to_value(&snapshot.today),
        "last_24_hours": window_to_value(&snapshot.last_24_hours),
        "all_time": window_to_value(&snapshot.all_time),
        "by_model": snapshot
            .models_by_error_rate()
            .iter()
            .map(|entry| json!({
                "model": entry.model,
                "requests": entry.requests,
                "errors": entry.errors,
                "cost": entry.cost,
                "error_rate": if entry.requests == 0 {
                    0.0
                } else {
                    entry.errors as f64 / entry.requests as f64 * 100.0
                },
            }))
            .collect::<Vec<_>>(),
        "untrustworthy_fields": snapshot.untrustworthy_fields(),
        // 照实回传，但上面已标注不可信。前端不显示这两个。
        "daily_cost_used_usd": snapshot.daily_cost_used_usd,
        "daily_cost_remaining_usd": snapshot.daily_cost_remaining_usd,
    })
}

fn window_to_value(window: &crate::amd_load::AmdUsageWindow) -> Value {
    json!({
        "requests": window.requests,
        "errors": window.errors,
        "error_rate": window.error_rate(),
        "total_tokens": window.total_tokens,
        "cost": window.cost,
        "kv_cache_hit_rate": window.kv_cache_hit_rate,
        "last_request_at": window.last_request_at,
    })
}

fn conflict_response() -> Response<Body> {
    (
        http::StatusCode::CONFLICT,
        Json(json!({ "detail": "配置正在被后台负载轮询更新，请稍后重试" })),
    )
        .into_response()
}

#[cfg(test)]
mod tests {
    use super::*;

    /// 响应里必须带齐结构体的每一个可配置字段。
    ///
    /// `block_models` 曾经漏在这里：保存接口返回 200、字段确实写进了库，但响应里
    /// 没有它——接口读不回自己刚写的值，只能靠猜。`AmdLoadConfig` 以后再加字段，
    /// 这个测试会先红。
    ///
    /// 不用字段名清单做断言，而是逐个比对结构体与 JSON 的键集合：新增字段忘了加进
    /// `config_to_value` 时，键数量对不上，测试立刻失败，不会被漏掉。
    #[test]
    fn config_response_covers_every_configurable_field() {
        let value = config_to_value(&AmdLoadConfig::default());
        let object = value.as_object().expect("config 响应应为对象");

        let mut from_config: Vec<&str> = vec![
            "enabled",
            "block_models",
            "poll_sec",
            "disable_threshold",
            "recovery_threshold",
            "disable_streak",
            "snapshot_ttl_sec",
            "timeout_sec",
        ];
        from_config.sort_unstable();
        from_config.dedup();

        let mut in_response: Vec<&str> = object.keys().map(String::as_str).collect();
        in_response.sort_unstable();

        let missing: Vec<&&str> = from_config
            .iter()
            .filter(|key| !object.contains_key(**key))
            .collect();
        assert!(missing.is_empty(), "config 响应缺少字段: {missing:?}");

        // 多出来的键也要解释——那是计算派生值（has_hysteresis / effective_recovery），
        // 属于有意为之，但不该有别的意外字段混进来。
        let derived = ["has_hysteresis", "effective_recovery"];
        let unexpected: Vec<&&str> = in_response
            .iter()
            .filter(|key| !from_config.contains(key) && !derived.contains(*key))
            .collect();
        assert!(
            unexpected.is_empty(),
            "config 响应出现未预期字段: {unexpected:?}"
        );
    }

    /// 默认不屏蔽任何模型，且响应里明确回这个值。
    ///
    /// 只靠默认 false 的话，界面上分不清「关闭」与「接口没返回这个字段」。
    #[test]
    fn default_response_reports_block_models_false() {
        let value = config_to_value(&AmdLoadConfig::default());
        assert_eq!(
            value.get("block_models").and_then(Value::as_bool),
            Some(false)
        );
    }
}
