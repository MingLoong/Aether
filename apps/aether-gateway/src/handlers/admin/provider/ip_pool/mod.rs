//! OpenCode 前置代理 IP 池管理接口。
//!
//! - `GET  /api/admin/opencode-ip-pool/providers/{id}`             状态 + 配置 + 池 IP
//! - `PUT  /api/admin/opencode-ip-pool/providers/{id}/config`      保存扫描配置 / 改写前置域名
//! - `POST /api/admin/opencode-ip-pool/providers/{id}/scan`        扫描网段并建池 key
//! - `POST /api/admin/opencode-ip-pool/providers/{id}/clean`       探测并清理失效池 key
//! - `POST /api/admin/opencode-ip-pool/providers/{id}/restore-original` 还原官方域名
//!
//! 扫描/清理的运行时逻辑在 `pool.rs`，只依赖 AppState 的 Provider Catalog 访问，
//! 因此管理接口与未来的定时 worker 可以共用同一套实现。

mod pool;

use axum::{
    body::{Body, Bytes},
    http,
    response::{IntoResponse, Response},
    Json,
};
use serde_json::{json, Value};
use url::Url;

use crate::handlers::admin::request::{AdminAppState, AdminRequestContext};
use crate::GatewayError;

pub(crate) use pool::{
    list_opencode_pool_ips, opencode_ip_pool_status_for, opencode_pool_key_ip, parse_cidr,
    run_open_code_pool_clean, run_open_code_pool_scan, OpenCodeScanConfig,
    OPENCODE_SCAN_DEFAULT_CONCURRENCY,
};

/// 官方直连域名（用于「还原原始链接」）。
const OPENCODE_ORIGINAL_DOMAIN: &str = "opencode.ai";

/// 本组接口的 route_family。
pub(crate) const OPENCODE_IP_POOL_ROUTE_FAMILY: &str = "opencode_ip_pool_manage";

pub(crate) async fn maybe_build_local_admin_opencode_ip_pool_response(
    state: &AdminAppState<'_>,
    request_context: &AdminRequestContext<'_>,
    request_body: Option<&Bytes>,
) -> Result<Option<Response<Body>>, GatewayError> {
    let Some(decision) = request_context.decision() else {
        return Ok(None);
    };
    if decision.route_family.as_deref() != Some(OPENCODE_IP_POOL_ROUTE_FAMILY) {
        return Ok(None);
    }
    if !state.has_provider_catalog_data_reader() {
        return Ok(None);
    }

    let route_kind = decision.route_kind.as_deref().unwrap_or_default();
    let Some(provider_id) = opencode_ip_pool_provider_id(request_context.path()) else {
        return Ok(None);
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
    if !provider
        .provider_type
        .trim()
        .eq_ignore_ascii_case("opencode")
    {
        return Ok(Some(
            (
                http::StatusCode::BAD_REQUEST,
                Json(json!({ "detail": "仅 OpenCode 类型供应商支持前置代理 IP 池" })),
            )
                .into_response(),
        ));
    }

    let response = match route_kind {
        "get_opencode_ip_pool_status" => build_status_response(state, &provider).await?,
        "save_opencode_ip_pool_config" => save_config(state, &provider, request_body).await?,
        "run_opencode_ip_pool_scan" => run_scan(state, &provider).await?,
        "run_opencode_ip_pool_clean" => run_clean(state, &provider).await?,
        "restore_opencode_original_base_url" => restore_original_base_url(state, &provider).await?,
        "add_opencode_exit_ip" => add_exit_ip(state, &provider, request_body).await?,
        "remove_opencode_exit_ip" => remove_exit_ip(state, &provider, request_body).await?,
        "update_opencode_exit_ip" => update_exit_ip(state, &provider, request_body).await?,
        "toggle_opencode_exit_ip" => toggle_exit_ip(state, &provider, request_body).await?,
        _ => return Ok(None),
    };
    Ok(Some(response))
}

fn read_json_body(request_body: Option<&Bytes>) -> Result<Value, Response<Body>> {
    let Some(raw) = request_body else {
        return Err(bad_request("请求体不能为空"));
    };
    serde_json::from_slice::<Value>(raw)
        .map_err(|_| bad_request("请求体必须是合法的 JSON 对象"))
}

fn normalize_exit_ip(raw: &str) -> Option<String> {
    let value = raw.trim();
    if value.is_empty() || value.parse::<std::net::IpAddr>().is_err() {
        return None;
    }
    Some(value.to_string())
}

/// 手动往 provider 级 IP 池里加一个地址（**不会**创建密钥）。
async fn add_exit_ip(
    state: &AdminAppState<'_>,
    provider: &aether_data_contracts::repository::provider_catalog::StoredProviderCatalogProvider,
    request_body: Option<&Bytes>,
) -> Result<Response<Body>, GatewayError> {
    let payload = match read_json_body(request_body) {
        Ok(value) => value,
        Err(response) => return Ok(response),
    };
    let Some(ip) = payload.get("ip").and_then(Value::as_str).and_then(normalize_exit_ip) else {
        return Ok(bad_request("缺少或无效的 ip"));
    };
    let mut config = OpenCodeScanConfig::from_provider_config(&provider.config);
    if config.exit_pool.iter().any(|item| item == &ip) {
        return Ok(Json(json!({ "saved": true, "duplicate": true })).into_response());
    }
    config.exit_pool.push(ip.clone());
    crate::handlers::admin::provider::ip_pool::pool::write_scan_config(state, provider, &config).await?;
    Ok(Json(json!({ "saved": true, "ip": ip })).into_response())
}

/// 从 provider 级 IP 池里移除一个地址（**不会**删除密钥）。
async fn remove_exit_ip(
    state: &AdminAppState<'_>,
    provider: &aether_data_contracts::repository::provider_catalog::StoredProviderCatalogProvider,
    request_body: Option<&Bytes>,
) -> Result<Response<Body>, GatewayError> {
    let payload = match read_json_body(request_body) {
        Ok(value) => value,
        Err(response) => return Ok(response),
    };
    let Some(ip) = payload.get("ip").and_then(Value::as_str).and_then(normalize_exit_ip) else {
        return Ok(bad_request("缺少或无效的 ip"));
    };
    let mut config = OpenCodeScanConfig::from_provider_config(&provider.config);
    let before = config.exit_pool.len();
    config.exit_pool.retain(|item| item != &ip);
    config.exit_pool_disabled.retain(|item| item != &ip);
    if config.exit_pool.len() == before {
        return Ok(Json(json!({ "removed": false })).into_response());
    }
    crate::handlers::admin::provider::ip_pool::pool::write_scan_config(state, provider, &config).await?;
    Ok(Json(json!({ "removed": true, "ip": ip })).into_response())
}

/// 修改池中某个 IP。
async fn update_exit_ip(
    state: &AdminAppState<'_>,
    provider: &aether_data_contracts::repository::provider_catalog::StoredProviderCatalogProvider,
    request_body: Option<&Bytes>,
) -> Result<Response<Body>, GatewayError> {
    let payload = match read_json_body(request_body) {
        Ok(value) => value,
        Err(response) => return Ok(response),
    };
    let Some(old_ip) = payload
        .get("old_ip")
        .and_then(Value::as_str)
        .and_then(normalize_exit_ip)
    else {
        return Ok(bad_request("缺少或无效的 old_ip"));
    };
    let Some(new_ip) = payload
        .get("new_ip")
        .and_then(Value::as_str)
        .and_then(normalize_exit_ip)
    else {
        return Ok(bad_request("缺少或无效的 new_ip"));
    };
    let mut config = OpenCodeScanConfig::from_provider_config(&provider.config);
    if !config.exit_pool.iter().any(|item| item == &old_ip) {
        return Ok(Json(json!({ "updated": false })).into_response());
    }
    for item in config.exit_pool.iter_mut() {
        if item == &old_ip {
            *item = new_ip.clone();
        }
    }
    for item in config.exit_pool_disabled.iter_mut() {
        if item == &old_ip {
            *item = new_ip.clone();
        }
    }
    crate::handlers::admin::provider::ip_pool::pool::write_scan_config(state, provider, &config).await?;
    Ok(Json(json!({ "updated": true, "old_ip": old_ip, "new_ip": new_ip })).into_response())
}

/// 启用 / 停用池中某个 IP（停用只是不参与轮转，条目仍保留）。
async fn toggle_exit_ip(
    state: &AdminAppState<'_>,
    provider: &aether_data_contracts::repository::provider_catalog::StoredProviderCatalogProvider,
    request_body: Option<&Bytes>,
) -> Result<Response<Body>, GatewayError> {
    let payload = match read_json_body(request_body) {
        Ok(value) => value,
        Err(response) => return Ok(response),
    };
    let Some(ip) = payload.get("ip").and_then(Value::as_str).and_then(normalize_exit_ip) else {
        return Ok(bad_request("缺少或无效的 ip"));
    };
    let is_active = payload
        .get("is_active")
        .and_then(Value::as_bool)
        .unwrap_or(true);
    let mut config = OpenCodeScanConfig::from_provider_config(&provider.config);
    if !config.exit_pool.iter().any(|item| item == &ip) {
        return Ok(bad_request("该 IP 不在池中"));
    }
    config.exit_pool_disabled.retain(|item| item != &ip);
    if !is_active && !config.exit_pool_disabled.contains(&ip) {
        config.exit_pool_disabled.push(ip.clone());
    }
    crate::handlers::admin::provider::ip_pool::pool::write_scan_config(state, provider, &config).await?;
    Ok(Json(json!({ "saved": true, "ip": ip, "is_active": is_active })).into_response())
}

/// 从 `/api/admin/opencode-ip-pool/providers/{id}[/action]` 解析 Provider ID。
fn opencode_ip_pool_provider_id(path: &str) -> Option<String> {
    let rest = path.strip_prefix("/api/admin/opencode-ip-pool/providers/")?;
    let segments: Vec<&str> = rest.split('/').filter(|s| !s.is_empty()).collect();
    if segments.is_empty() || segments[0].len() != 36 {
        return None;
    }
    Some(segments[0].to_string())
}

fn bad_request(detail: impl Into<String>) -> Response<Body> {
    (
        http::StatusCode::BAD_REQUEST,
        Json(json!({ "detail": detail.into() })),
    )
        .into_response()
}

fn internal_error(detail: impl Into<String>) -> Response<Body> {
    (
        http::StatusCode::INTERNAL_SERVER_ERROR,
        Json(json!({ "detail": detail.into() })),
    )
        .into_response()
}

/// 读取端点当前使用的 host（前置代理域名）。
async fn endpoint_host(
    state: &AdminAppState<'_>,
    provider_id: &str,
) -> Result<Option<String>, GatewayError> {
    let endpoints = state
        .list_provider_catalog_endpoints_by_provider_ids(&[provider_id.to_string()])
        .await?;
    for endpoint in endpoints {
        if let Ok(url) = Url::parse(endpoint.base_url.trim()) {
            if let Some(host) = url.host_str() {
                return Ok(Some(host.to_string()));
            }
        }
    }
    Ok(None)
}

async fn build_status_response(
    state: &AdminAppState<'_>,
    provider: &aether_data_contracts::repository::provider_catalog::StoredProviderCatalogProvider,
) -> Result<Response<Body>, GatewayError> {
    let config = OpenCodeScanConfig::from_provider_config(&provider.config);
    let status = opencode_ip_pool_status_for(&provider.id);
    let pool_ips = list_opencode_pool_ips(state.as_ref(), &provider.id, &config).await?;
    Ok(Json(json!({
        "provider_id": provider.id,
        "scanning": status.scanning,
        "cleaning": status.cleaning,
        "last_scan_at": status.last_scan_at,
        "last_scan_targets": status.last_scan_targets,
        "last_scan_found": status.last_scan_found,
        "last_scan_added": status.last_scan_added,
        "last_clean_at": status.last_clean_at,
        "last_clean_checked": status.last_clean_checked,
        "last_clean_removed": status.last_clean_removed,
        "auto_enabled": config.auto_enabled,
        "autoscan_effective": config.autoscan_effective(),
        "rotation_enabled": config.rotation_enabled,
        "rotation_effective": config.rotation_effective(),
        "cooldown_minutes": config.effective_cooldown_minutes(),
        "rotation_cursor": crate::opencode_rotation::peek_rotation_cursor(state.as_ref(), &provider.id)
            .await,
        "interval_hours": config.interval_hours.unwrap_or(0),
        "concurrency": config.concurrency.unwrap_or(OPENCODE_SCAN_DEFAULT_CONCURRENCY),
        "cidrs": config.cidrs,
        "proxy_domain": config
            .effective_proxy_domain()
            .unwrap_or_else(|| OPENCODE_ORIGINAL_DOMAIN.to_string()),
        "proxy_enabled": config.proxy_enabled,
        "saved_proxy_domain": config.proxy_domain.clone(),
        "exit_pool": config.exit_pool.clone(),
        "exit_pool_disabled": config.exit_pool_disabled.clone(),
        "pool_source": if config.exit_pool.is_empty() { "key" } else { "provider" },
        "original_domain": OPENCODE_ORIGINAL_DOMAIN,
        "pool_ips": pool_ips,
    }))
    .into_response())
}

async fn save_config(
    state: &AdminAppState<'_>,
    provider: &aether_data_contracts::repository::provider_catalog::StoredProviderCatalogProvider,
    request_body: Option<&Bytes>,
) -> Result<Response<Body>, GatewayError> {
    let Some(request_body) = request_body else {
        return Ok(bad_request("请求体不能为空"));
    };
    let Ok(Value::Object(payload)) = serde_json::from_slice::<Value>(request_body) else {
        return Ok(bad_request("请求体必须是合法的 JSON 对象"));
    };
    // 部分更新：请求体里没出现的字段保持原值，避免「只改域名」把 CIDR、
    // 自动扫描、轮转开关、冷却时长一并打回默认值。
    let mut config = OpenCodeScanConfig::merged_with_payload(&provider.config, &payload);
    for cidr in &config.cidrs {
        if parse_cidr(cidr).is_none() {
            return Ok(bad_request(format!("无效的 CIDR: {cidr}")));
        }
    }

    // 前置代理域名只做**记住**，不再改写 endpoint.base_url。
    // 端点 base_url 是真实上游，属于配置事实；是否走前置代理由 proxy_enabled 开关
    // 在请求路径上决定（见 planner 的 host 注入）。这样输入框里的域名永远只归用户
    // 所有，开关不会把端点或输入框改来改去。
    let mut changed_domains = 0u64;
    if let Some(Value::String(domain)) = payload.get("proxy_domain") {
        let domain = domain.trim();
        if domain.is_empty() {
            return Ok(bad_request("前置代理域名不能为空"));
        }
        if domain.contains('/') || domain.contains(' ') {
            return Ok(bad_request("前置代理域名格式无效"));
        }
        let endpoints = state
            .list_provider_catalog_endpoints_by_provider_ids(&[provider.id.clone()])
            .await?;
        changed_domains = endpoints
            .iter()
            .filter(|endpoint| {
                Url::parse(endpoint.base_url.trim())
                    .ok()
                    .and_then(|url| url.host_str().map(str::to_string))
                    .is_some_and(|host| host.eq_ignore_ascii_case(domain))
            })
            .count() as u64;
    }

    let mut config_map = provider
        .config
        .as_ref()
        .and_then(Value::as_object)
        .cloned()
        .unwrap_or_default();
    config_map.insert(
        "opencode_scan".to_string(),
        config.to_provider_config_value(),
    );
    let mut updated_provider = provider.clone();
    updated_provider.config = Some(Value::Object(config_map));
    if state
        .update_provider_catalog_provider(&updated_provider)
        .await?
        .is_none()
    {
        return Ok(internal_error("保存扫描配置失败"));
    }
    Ok(Json(json!({
        "provider_id": provider.id,
        "saved": true,
        "proxy_domain_changed": changed_domains,
    }))
    .into_response())
}

async fn run_scan(
    state: &AdminAppState<'_>,
    provider: &aether_data_contracts::repository::provider_catalog::StoredProviderCatalogProvider,
) -> Result<Response<Body>, GatewayError> {
    match run_open_code_pool_scan(state.as_ref(), provider).await {
        Ok(summary) => Ok(Json(json!({
            "provider_id": provider.id,
            "scanning": false,
            "targets": summary.targets,
            "found": summary.found,
            "added": summary.added,
        }))
        .into_response()),
        Err(error) => Ok(internal_error(error.into_message())),
    }
}

async fn run_clean(
    state: &AdminAppState<'_>,
    provider: &aether_data_contracts::repository::provider_catalog::StoredProviderCatalogProvider,
) -> Result<Response<Body>, GatewayError> {
    match run_open_code_pool_clean(state.as_ref(), provider).await {
        Ok(summary) => Ok(Json(json!({
            "provider_id": provider.id,
            "cleaning": false,
            "checked": summary.checked,
            "removed": summary.removed,
        }))
        .into_response()),
        Err(error) => Ok(internal_error(error.into_message())),
    }
}

async fn restore_original_base_url(
    state: &AdminAppState<'_>,
    provider: &aether_data_contracts::repository::provider_catalog::StoredProviderCatalogProvider,
) -> Result<Response<Body>, GatewayError> {
    let endpoints = state
        .list_provider_catalog_endpoints_by_provider_ids(&[provider.id.clone()])
        .await?;
    let mut changed = 0u64;
    let mut errors: Vec<String> = Vec::new();
    for endpoint in endpoints {
        let Ok(mut url) = Url::parse(endpoint.base_url.trim()) else {
            continue;
        };
        if url
            .host_str()
            .is_some_and(|host| host.eq_ignore_ascii_case(OPENCODE_ORIGINAL_DOMAIN))
        {
            continue;
        }
        if url.set_host(Some(OPENCODE_ORIGINAL_DOMAIN)).is_err() {
            errors.push(endpoint.id.clone());
            continue;
        }
        let mut updated = endpoint.clone();
        updated.base_url = url.to_string();
        match state.update_provider_catalog_endpoint(&updated).await {
            Ok(Some(_)) => changed += 1,
            _ => errors.push(endpoint.id.clone()),
        }
    }
    Ok(Json(json!({
        "provider_id": provider.id,
        "changed": changed,
        "errors": errors,
    }))
    .into_response())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn provider_id_parsing_accepts_action_suffix() {
        let id = "8fa10a07-1d41-4f9e-ab32-68c9760caedd";
        assert_eq!(
            opencode_ip_pool_provider_id(&format!(
                "/api/admin/opencode-ip-pool/providers/{id}/scan"
            )),
            Some(id.to_string())
        );
        assert_eq!(
            opencode_ip_pool_provider_id(&format!("/api/admin/opencode-ip-pool/providers/{id}")),
            Some(id.to_string())
        );
        assert_eq!(opencode_ip_pool_provider_id("/api/admin/providers"), None);
        assert_eq!(
            opencode_ip_pool_provider_id("/api/admin/opencode-ip-pool/providers/short"),
            None
        );
    }
}
