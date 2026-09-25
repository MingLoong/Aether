//! OpenCode front-proxy IP pool management.
//!
//! Exposes
//! `GET  /api/admin/opencode-ip-pool/providers/{id}`        (status + config)
//! `PUT  /api/admin/opencode-ip-pool/providers/{id}/config` (config)
//! `POST /api/admin/opencode-ip-pool/providers/{id}/scan`   (run scan)
//! `POST /api/admin/opencode-ip-pool/providers/{id}/clean`  (run clean)
//!
//! A scan probes the configured CIDRs for healthy front-proxy exit IPs (raw
//! TLS to `ip:443`, SNI = upstream domain, `GET /zen/v1/models` 2xx/3xx) and
//! turns healthy addresses into pool keys where `api_key` = the IP literal.
//! A clean probes existing keys and deletes unhealthy ones.  Automatic scan
//! scheduling is driven by the maintenance worker in
//! `maintenance/runtime/opencode_ip_pool.rs`.

use crate::handlers::admin::request::{AdminAppState, AdminRequestContext};
use crate::maintenance::opencode_ip_pool::{
    list_opencode_pool_ips, opencode_ip_pool_status_for, parse_cidr, run_open_code_pool_clean,
    run_open_code_pool_scan, CleanSummary, OpenCodeScanConfig, ScanSummary,
    OPENCODE_SCAN_DEFAULT_CONCURRENCY,
};
use crate::GatewayError;
use axum::{
    body::{Body, Bytes},
    http,
    response::{IntoResponse, Response},
    Json,
};
use serde_json::{json, Value};
use url::Url;

pub(crate) use crate::maintenance::opencode_ip_pool::{
    CleanSummary as PoolCleanSummary, ScanSummary as PoolScanSummary,
};

pub(crate) async fn maybe_build_local_admin_provider_opencode_ip_pool_response(
    state: &AdminAppState<'_>,
    request_context: &AdminRequestContext<'_>,
    request_body: Option<&Bytes>,
) -> Result<Option<Response<Body>>, GatewayError> {
    let Some(decision) = request_context.decision() else {
        return Ok(None);
    };
    if decision.route_family.as_deref() != Some("opencode_ip_pool_manage") {
        return Ok(None);
    }
    let route_kind = decision.route_kind.as_deref().unwrap_or_default();
    let path = request_context.path();
    let Some(provider_id) = opencode_ip_pool_provider_id(path, route_kind) else {
        return Ok(None);
    };
    if !state.has_provider_catalog_data_reader() {
        return Ok(None);
    }

    let provider = match state
        .read_provider_catalog_providers_by_ids(&[provider_id.to_string()])
        .await?
        .into_iter()
        .next()
    {
        Some(provider) => provider,
        None => return Ok(Some(not_found_response("Provider 不存在"))),
    };
    if !opencode_provider_type(&provider.provider_type) {
        return Ok(Some(bad_request_response("仅支持 opencode 供应商")));
    }

    let response = match route_kind {
        "get_opencode_ip_pool_status" => build_ip_pool_status_response(state, &provider).await?,
        "restore_opencode_original_base_url" => {
            restore_opencode_original_base_url(state, &provider).await?
        }
        "save_opencode_ip_pool_config" => {
            let Some(body) = request_body else {
                return Ok(Some(bad_request_response("请求体不能为空")));
            };
            save_ip_pool_config(state, &provider, body).await?
        }
        "run_opencode_ip_pool_scan" => {
            let summary = run_open_code_pool_scan(state.as_ref(), &provider).await?;
            let status = opencode_ip_pool_status_for(&provider.id);
            Some(
                Json(json!({
                    "provider_id": provider.id,
                    "scanning": status.scanning,
                    "targets": summary.targets,
                    "found": summary.found,
                    "added": summary.added,
                }))
                .into_response(),
            )
        }
        "run_opencode_ip_pool_clean" => {
            let summary = run_open_code_pool_clean(state.as_ref(), &provider).await?;
            let status = opencode_ip_pool_status_for(&provider.id);
            Some(
                Json(json!({
                    "provider_id": provider.id,
                    "cleaning": status.cleaning,
                    "checked": summary.checked,
                    "removed": summary.removed,
                }))
                .into_response(),
            )
        }
        _ => return Ok(None),
    };

    if let Some(response) = response {
        return Ok(Some(response));
    }
    Ok(None)
}

fn opencode_provider_type(provider_type: &str) -> bool {
    provider_type.trim().eq_ignore_ascii_case("opencode")
}

/// path: `/api/admin/opencode-ip-pool/providers/{id}[/action]`
fn opencode_ip_pool_provider_id(path: &str, route_kind: &str) -> Option<String> {
    if !path.starts_with("/api/admin/opencode-ip-pool/providers/") {
        return None;
    }
    let Some(rest) = path.strip_prefix("/api/admin/opencode-ip-pool/providers/") else {
        return None;
    };
    let segments = rest
        .split('/')
        .filter(|s| !s.is_empty())
        .collect::<Vec<_>>();
    if segments.is_empty() || segments[0].len() != 36 {
        return None;
    }
    Some(segments[0].to_string())
}

/// 原始无 CDN 的直接上游域名（opencode2api 的 `upstreamDomain`）。
const OPENCODE_ORIGINAL_DOMAIN: &str = "opencode.ai";

async fn opencode_endpoint_domains(
    state: &AdminAppState<'_>,
    provider_id: &str,
) -> Result<(Option<String>, Option<String>), GatewayError> {
    let endpoints = state
        .list_provider_catalog_endpoints_by_provider_ids(&[provider_id.to_string()])
        .await?;
    let mut proxy_domain: Option<String> = None;
    for endpoint in endpoints {
        if let Ok(url) = Url::parse(endpoint.base_url.trim()) {
            if let Some(host) = url.host_str() {
                proxy_domain = Some(host.to_string());
                break;
            }
        }
    }
    Ok((proxy_domain, Some(OPENCODE_ORIGINAL_DOMAIN.to_string())))
}

pub(crate) async fn build_ip_pool_status_response(
    state: &AdminAppState<'_>,
    provider: &aether_data_contracts::repository::provider_catalog::StoredProviderCatalogProvider,
) -> Result<Option<Response<Body>>, GatewayError> {
    let config = OpenCodeScanConfig::from_provider_config(&provider.config);
    let status = opencode_ip_pool_status_for(&provider.id);
    let (proxy_domain, original_domain) = opencode_endpoint_domains(state, &provider.id).await?;
    let pool_ips = list_opencode_pool_ips(state.as_ref(), &provider.id).await?;
    let data = json!({
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
        "interval_hours": config.interval_hours.unwrap_or(0),
        "concurrency": config.concurrency.unwrap_or(OPENCODE_SCAN_DEFAULT_CONCURRENCY),
        "cidrs": config.cidrs,
        "proxy_domain": proxy_domain,
        "original_domain": original_domain,
        "pool_ips": pool_ips,
    });
    Ok(Some(Json(data).into_response()))
}

pub(crate) async fn save_ip_pool_config(
    state: &AdminAppState<'_>,
    provider: &aether_data_contracts::repository::provider_catalog::StoredProviderCatalogProvider,
    request_body: &Bytes,
) -> Result<Option<Response<Body>>, GatewayError> {
    let payload = match serde_json::from_slice::<Value>(request_body) {
        Ok(Value::Object(payload)) => payload,
        Ok(_) => return Ok(Some(bad_request_response("请求体必须是 JSON 对象"))),
        Err(_) => return Ok(Some(bad_request_response("请求体必须是合法的 JSON 对象"))),
    };
    let config = OpenCodeScanConfig::from_provider_config_object(&payload);
    for cidr in &config.cidrs {
        if parse_cidr(cidr).is_none() {
            return Ok(Some(bad_request_response(format!("无效的 CIDR: {cidr}"))));
        }
    }

    let mut config_map = provider
        .config
        .as_ref()
        .and_then(|value| value.as_object().cloned())
        .unwrap_or_default();
    config_map.insert(
        "opencode_scan".to_string(),
        config.to_provider_config_value(),
    );
    let mut updated_provider = provider.clone();
    updated_provider.config = Some(serde_json::Value::Object(config_map));
    let _ = state
        .update_provider_catalog_provider(&updated_provider)
        .await?;
    Ok(Some(
        Json(json!({ "provider_id": provider.id, "saved": true })).into_response(),
    ))
}

/// 将供应商全部端点的 base_url 从 CDN 前置代理域名还原为原始无 CDN 链接
/// （保留原有协议/端口/路径，仅替换 host）。
pub(crate) async fn restore_opencode_original_base_url(
    state: &AdminAppState<'_>,
    provider: &aether_data_contracts::repository::provider_catalog::StoredProviderCatalogProvider,
) -> Result<Option<Response<Body>>, GatewayError> {
    let endpoints = state
        .list_provider_catalog_endpoints_by_provider_ids(std::slice::from_ref(&provider.id))
        .await?;
    let mut changed = 0u64;
    let mut errors = Vec::new();
    for endpoint in endpoints {
        let Ok(mut url) = Url::parse(endpoint.base_url.trim()) else {
            continue;
        };
        let Some(host) = url.host_str().map(str::to_string) else {
            continue;
        };
        if host.eq_ignore_ascii_case(OPENCODE_ORIGINAL_DOMAIN) {
            continue;
        }
        let _ = url.set_host(Some(OPENCODE_ORIGINAL_DOMAIN));
        let mut updated = endpoint.clone();
        updated.base_url = url.to_string();
        match state.update_provider_catalog_endpoint(&updated).await {
            Ok(Some(_)) => changed += 1,
            Ok(None) => errors.push(format!("端点不存在: {}", endpoint.id)),
            Err(err) => errors.push(format!("端点 {} 更新失败: {err:?}", endpoint.id)),
        }
    }
    Ok(Some(
        Json(json!({
            "provider_id": provider.id,
            "changed": changed,
            "errors": errors,
        }))
        .into_response(),
    ))
}

fn not_found_response(detail: impl Into<String>) -> Response<Body> {
    (
        http::StatusCode::NOT_FOUND,
        Json(json!({ "detail": detail.into() })),
    )
        .into_response()
}

fn bad_request_response(detail: impl Into<String>) -> Response<Body> {
    (
        http::StatusCode::BAD_REQUEST,
        Json(json!({ "detail": detail.into() })),
    )
        .into_response()
}
