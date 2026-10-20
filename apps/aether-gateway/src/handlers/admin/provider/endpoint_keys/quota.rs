use crate::handlers::admin::provider::shared::paths::admin_provider_id_for_refresh_quota;
use crate::handlers::admin::provider::shared::payloads::{
    AdminProviderKeyUpdatePatch, AdminProviderQuotaRefreshRequest, OAUTH_ACCOUNT_BLOCK_PREFIX,
};
use crate::handlers::admin::provider::write::keys::build_provider_catalog_key_admin_cas_update;
use crate::handlers::admin::request::{AdminAppState, AdminRequestContext};
use crate::GatewayError;
use aether_data_contracts::repository::provider_catalog::{
    StoredProviderCatalogKey, StoredProviderCatalogProvider,
};
use axum::{
    body::{Body, Bytes},
    http,
    response::{IntoResponse, Response},
    Json,
};
use serde_json::json;
use std::collections::{BTreeMap, BTreeSet};
use tracing::info;

use super::super::oauth::quota::dispatch::refresh_provider_pool_quota_locally;
use super::super::oauth::quota::shared::normalize_string_id_list;
use super::super::oauth::quota::shared::persist_provider_quota_refresh_state;
use super::super::oauth::quota::shared::{
    provider_quota_refresh_endpoint_for_provider, provider_quota_refresh_missing_endpoint_message,
    provider_type_supports_quota_refresh, unsupported_provider_quota_refresh_message,
};
use super::super::oauth::quota::workbuddy::fetch_workbuddy_account_nickname;
use super::super::write::provider::reconcile_admin_fixed_provider_template_endpoints;

fn unsupported_provider_quota_refresh_response(provider_type: &str) -> Response<Body> {
    let message = unsupported_provider_quota_refresh_message(provider_type);
    Json(json!({
        "success": 0,
        "failed": 0,
        "total": 0,
        "results": [],
        "message": message,
        "auto_removed": 0,
    }))
    .into_response()
}

pub(super) async fn maybe_handle(
    state: &AdminAppState<'_>,
    request_context: &AdminRequestContext<'_>,
    request_body: Option<&Bytes>,
) -> Result<Option<Response<Body>>, GatewayError> {
    let Some(decision) = request_context.decision() else {
        return Ok(None);
    };

    if decision.route_family.as_deref() != Some("endpoints_manage")
        || decision.route_kind.as_deref() != Some("refresh_quota")
        || request_context.method() != http::Method::POST
        || !request_context
            .path()
            .starts_with("/api/admin/endpoints/providers/")
        || !request_context.path().ends_with("/refresh-quota")
    {
        return Ok(None);
    }

    let Some(provider_id) = admin_provider_id_for_refresh_quota(request_context.path()) else {
        return Ok(Some(
            (
                http::StatusCode::NOT_FOUND,
                Json(json!({ "detail": "Provider 不存在" })),
            )
                .into_response(),
        ));
    };
    let Some(provider) = state
        .read_provider_catalog_providers_by_ids(std::slice::from_ref(&provider_id))
        .await?
        .into_iter()
        .next()
    else {
        return Ok(Some(
            (
                http::StatusCode::NOT_FOUND,
                Json(json!({ "detail": format!("Provider {provider_id} 不存在") })),
            )
                .into_response(),
        ));
    };

    let normalized_provider_type = provider.provider_type.trim().to_ascii_lowercase();

    let payload = if let Some(request_body) = request_body.filter(|body| !body.is_empty()) {
        match serde_json::from_slice::<AdminProviderQuotaRefreshRequest>(request_body) {
            Ok(payload) => payload,
            Err(_) => {
                return Ok(Some(
                    (
                        http::StatusCode::BAD_REQUEST,
                        Json(json!({ "detail": "请求体必须是合法的 JSON 对象" })),
                    )
                        .into_response(),
                ));
            }
        }
    } else {
        AdminProviderQuotaRefreshRequest { key_ids: None }
    };

    let raw_key_ids = payload.key_ids;
    let selected_key_ids = normalize_string_id_list(raw_key_ids.clone());
    let explicit_key_ids_requested = raw_key_ids.is_some();

    let is_fixed_provider = state
        .fixed_provider_template(&provider.provider_type)
        .is_some();
    if !is_fixed_provider && !provider_type_supports_quota_refresh(&normalized_provider_type) {
        return Ok(None);
    }

    let mut endpoints = state
        .list_provider_catalog_endpoints_by_provider_ids(std::slice::from_ref(&provider_id))
        .await?;
    let mut endpoint =
        provider_quota_refresh_endpoint_for_provider(&normalized_provider_type, &endpoints, true);

    if endpoint.is_none() && is_fixed_provider {
        if !state.has_provider_catalog_data_writer() {
            if !provider_type_supports_quota_refresh(&normalized_provider_type) {
                return Ok(Some(unsupported_provider_quota_refresh_response(
                    &normalized_provider_type,
                )));
            }
            return Ok(Some(
                (
                    http::StatusCode::BAD_REQUEST,
                    Json(json!({ "detail": "固定 Provider 端点缺失，且 provider catalog writer 不可用，无法自动补全端点" })),
                )
                    .into_response(),
            ));
        }
        reconcile_admin_fixed_provider_template_endpoints(state, &provider).await?;
        endpoints = state
            .list_provider_catalog_endpoints_by_provider_ids(std::slice::from_ref(&provider_id))
            .await?;
        endpoint = provider_quota_refresh_endpoint_for_provider(
            &normalized_provider_type,
            &endpoints,
            true,
        );
    }

    if !provider_type_supports_quota_refresh(&normalized_provider_type) {
        return Ok(Some(unsupported_provider_quota_refresh_response(
            &normalized_provider_type,
        )));
    }

    let Some(endpoint) = endpoint else {
        let detail = provider_quota_refresh_missing_endpoint_message(&normalized_provider_type);
        return Ok(Some(
            (
                http::StatusCode::BAD_REQUEST,
                Json(json!({ "detail": detail })),
            )
                .into_response(),
        ));
    };

    let keys = if let Some(selected_key_ids) = selected_key_ids.as_ref() {
        if selected_key_ids.is_empty() {
            Vec::new()
        } else {
            let selected = selected_key_ids.iter().cloned().collect::<BTreeSet<_>>();
            let mut by_id = state
                .read_provider_catalog_keys_by_ids(selected_key_ids)
                .await?
                .into_iter()
                .filter(|key| key.provider_id == provider_id && selected.contains(&key.id))
                .map(|key| (key.id.clone(), key))
                .collect::<BTreeMap<_, _>>();
            selected_key_ids
                .iter()
                .filter_map(|key_id| by_id.remove(key_id))
                .collect()
        }
    } else {
        state
            .list_provider_catalog_keys_by_provider_ids(std::slice::from_ref(&provider_id))
            .await?
            .into_iter()
            .filter(|key| {
                key.is_active
                    || key
                        .oauth_invalid_reason
                        .as_deref()
                        .map(str::trim)
                        .is_some_and(|value| value.starts_with(OAUTH_ACCOUNT_BLOCK_PREFIX))
            })
            .collect()
    };

    if explicit_key_ids_requested && selected_key_ids.is_none() {
        return Ok(Some(
            Json(json!({
                "success": 0,
                "failed": 0,
                "total": 0,
                "results": [],
                "message": "未提供可刷新的 Key",
                "auto_removed": 0,
            }))
            .into_response(),
        ));
    }

    if keys.is_empty() {
        let message = if explicit_key_ids_requested {
            "未提供可刷新的 Key"
        } else {
            "没有可刷新的 Key"
        };
        return Ok(Some(
            Json(json!({
                "success": 0,
                "failed": 0,
                "total": 0,
                "results": [],
                "message": message,
                "auto_removed": 0,
            }))
            .into_response(),
        ));
    }

    let nickname_keys = keys.clone();
    let Some(payload) = refresh_provider_pool_quota_locally(
        state,
        &provider,
        &endpoint,
        &normalized_provider_type,
        keys,
        None,
    )
    .await?
    else {
        return Ok(None);
    };

    // 账号昵称刷新（面板 issue #94：改名后免重登同步昵称）——**只有手动刷新走这里**，
    // 后台余额轮询不碰该接口（面板同款约束）。失败不影响额度刷新结果，但**原因会落库** ✓
    // （`account.nickname_error`）—— 此前国际号因为「宁缺勿错」的守卫永远没有昵称 ✗
    // 且看不出为什么 ✗（静默跳过）。
    // 只把结果写进 `workbuddy.account.*`（继承 account 原有字段，避免浅合并冲掉）。
    if normalized_provider_type == "workbuddy" {
        for key in nickname_keys {
            let Some(transport) = state
                .read_provider_transport_snapshot(&provider.id, &endpoint.id, &key.id)
                .await?
            else {
                continue;
            };
            let Some(authorization) = state.resolve_local_oauth_header_auth(&transport).await?
            else {
                continue;
            };
            let mut account = key
                .upstream_metadata
                .as_ref()
                .and_then(|metadata| metadata.get("workbuddy"))
                .and_then(|workbuddy| workbuddy.get("account"))
                .and_then(serde_json::Value::as_object)
                .cloned()
                .unwrap_or_default();
            let attempted_at = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map(|elapsed| elapsed.as_secs())
                .unwrap_or(0);
            match fetch_workbuddy_account_nickname(state, &transport, authorization, None).await {
                Ok(nickname) => {
                    account.insert("nickname".to_string(), json!(nickname));
                    account.insert("nickname_refreshed_at".to_string(), json!(attempted_at));
                    // 上一次的失败原因已经过期，清掉避免误导。
                    account.remove("nickname_error");
                    // key 名还是系统生成的（`账号_<ts>`）= 用户没手动命名过 →
                    // 换成上游账号名 ✓（用户改过名的 key 一律不动 ✓）。
                    rename_system_generated_workbuddy_key_if_needed(
                        state, &provider, &key, &nickname,
                    )
                    .await;
                }
                Err(reason) => {
                    // 截断后再落库（避免把上游整段文本塞进 metadata）。
                    account.insert(
                        "nickname_error".to_string(),
                        json!(reason.chars().take(200).collect::<String>()),
                    );
                    account.insert("nickname_attempted_at".to_string(), json!(attempted_at));
                }
            }
            let update = json!({ "workbuddy": { "account": serde_json::Value::Object(account) } });
            let _ = persist_provider_quota_refresh_state(
                state,
                key.id.as_str(),
                Some(&update),
                None,
                None,
                None,
            )
            .await;
        }
    }

    Ok(Some(Json(payload).into_response()))
}

/// 把「系统自动生成的」WorkBuddy key 名换成上游账号名（**best-effort** ✓）。
///
/// 只在名字仍未被用户改过时才动手 ✓（判据是纯函数 `workbuddy_system_generated_key_name` ✓），
/// 走与后台「重命名 key」**同一条**管理端 CAS 通道 ✓，改完刷新缓存 ✓。
/// 任何一步失败都**静默跳过** ✓ —— 改名只是展示优化，绝不能让额度刷新失败 ✗。
async fn rename_system_generated_workbuddy_key_if_needed(
    state: &AdminAppState<'_>,
    provider: &StoredProviderCatalogProvider,
    key: &StoredProviderCatalogKey,
    nickname: &str,
) {
    // 决策收在 pool crate 的纯函数里 ✓（维护性审计 ④：整条决策原先零测试 ✗）；
    // 这里只管「强读最新版本 → 再判一次 → 发 CAS」这段需要 state 的动作 ✓。
    if aether_provider_pool::providers::workbuddy::workbuddy_key_rename_target(&key.name, nickname)
        .is_none()
    {
        return;
    }
    // 强读拿最新版本：额度刷新全程在改同一行，用旧快照发 CAS 必然冲突 ✓。
    let Some(latest) = state
        .app()
        .list_provider_catalog_keys_by_ids_strong(std::slice::from_ref(&key.id))
        .await
        .ok()
        .and_then(|keys| keys.into_iter().next())
    else {
        return;
    };
    // 再判一次（强读回来的名字可能刚被别的请求改过 ✓）；判据与上面**同一个**纯函数 ✓。
    let Some(new_name) = aether_provider_pool::providers::workbuddy::workbuddy_key_rename_target(
        &latest.name,
        nickname,
    ) else {
        return;
    };
    let patch_object = serde_json::Map::from_iter([("name".to_string(), json!(new_name.clone()))]);
    let Ok(patch) = AdminProviderKeyUpdatePatch::from_object(patch_object) else {
        return;
    };
    let Ok(record) = state
        .build_admin_update_provider_key_record(provider, &latest, patch)
        .await
    else {
        return;
    };
    let admin_update =
        build_provider_catalog_key_admin_cas_update(&latest, record, &provider.provider_type);
    match state
        .compare_and_update_provider_catalog_key_admin_state(&admin_update)
        .await
    {
        Ok(true) => info!(
            event_name = "workbuddy_key_renamed_to_account_name",
            provider_id = %provider.id,
            key_id = %key.id,
            new_name = %new_name,
            "gateway workbuddy quota refresh renamed an auto-named key to the upstream account name"
        ),
        Ok(false) => tracing::debug!(
            provider_id = %provider.id,
            key_id = %key.id,
            "gateway workbuddy key rename skipped: concurrent update won the CAS"
        ),
        Err(err) => tracing::debug!(
            provider_id = %provider.id,
            key_id = %key.id,
            error = ?err,
            "gateway workbuddy key rename failed"
        ),
    }
}
