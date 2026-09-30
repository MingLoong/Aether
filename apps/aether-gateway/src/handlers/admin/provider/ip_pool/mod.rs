//! OpenCode 前置代理 IP 池管理接口。
//!
//! - `GET  /api/admin/opencode-ip-pool/providers/{id}`             状态 + 配置 + 池 IP
//! - `PUT  /api/admin/opencode-ip-pool/providers/{id}/config`      保存扫描配置 / 改写前置域名
//! - `POST /api/admin/opencode-ip-pool/providers/{id}/scan`        扫描网段，产出候选
//! - `POST /api/admin/opencode-ip-pool/providers/{id}/verify`      复验健康，产出生产池
//! - `POST /api/admin/opencode-ip-pool/providers/{id}/clean`       探测并清理失效池 key
//! - `POST /api/admin/opencode-ip-pool/providers/{id}/restore-original` 还原官方域名
//!
//! 扫描/清理的运行时逻辑在 `crate::opencode_pool`（领域层），只依赖 AppState 的
//! Provider Catalog 访问，因此管理接口与定时 worker 可以共用同一套实现。
//! 领域层住在自己模块下而不是本目录，是为了让轮转与 worker 不必从管理台内部取配置
//! 类型——上游的架构守卫禁止 `apps/aether-gateway/src` 下非管理台文件出现
//! `crate::handlers::admin::` 字面量。

use axum::{
    body::{Body, Bytes},
    http,
    response::{IntoResponse, Response},
    Json,
};
use serde_json::{json, Value};
use url::Url;

use std::collections::BTreeSet;

use crate::handlers::admin::request::{AdminAppState, AdminRequestContext};
// 领域层在 crate::opencode_pool 下；这里按模块引一次，函数体里的 `pool::xxx`
// 就还能照旧写，不必把每一处都展开成完整路径。
use crate::opencode_pool::pool;
use crate::GatewayError;

pub(crate) use crate::opencode_pool::{
    claim_verify_slot, list_opencode_pool_ips, opencode_ip_pool_status_for, opencode_pool_key_ip,
    parse_cidr, run_claimed_open_code_pool_verify, run_open_code_pool_clean,
    run_open_code_pool_scan, OpenCodeHealthConfig, OpenCodeScanConfig,
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
        "run_opencode_ip_pool_verify" => run_verify(state, &provider).await?,
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
    serde_json::from_slice::<Value>(raw).map_err(|_| bad_request("请求体必须是合法的 JSON 对象"))
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
    let Some(ip) = payload
        .get("ip")
        .and_then(Value::as_str)
        .and_then(normalize_exit_ip)
    else {
        return Ok(bad_request("缺少或无效的 ip"));
    };
    let mut config = OpenCodeScanConfig::from_provider_config(&provider.config);
    if config.exit_pool.iter().any(|item| item == &ip) {
        return Ok(Json(json!({ "saved": true, "duplicate": true })).into_response());
    }
    config.exit_pool.push(ip.clone());
    crate::opencode_pool::pool::write_scan_config(state.as_ref(), provider, &config).await?;
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
    let Some(ip) = payload
        .get("ip")
        .and_then(Value::as_str)
        .and_then(normalize_exit_ip)
    else {
        return Ok(bad_request("缺少或无效的 ip"));
    };
    let mut config = OpenCodeScanConfig::from_provider_config(&provider.config);
    let before = config.exit_pool.len();
    config.exit_pool.retain(|item| item != &ip);
    config.exit_pool_disabled.retain(|item| item != &ip);
    if config.exit_pool.len() == before {
        return Ok(Json(json!({ "removed": false })).into_response());
    }
    crate::opencode_pool::pool::write_scan_config(state.as_ref(), provider, &config).await?;
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
    // 改名目标不能已经在池里：否则会产生重复条目，而 remove 会把同名条目一并清掉，
    // 结果是误删两个 IP。
    if new_ip != old_ip && config.exit_pool.iter().any(|item| item == &new_ip) {
        return Ok(bad_request(format!("IP {new_ip} 已在池中")));
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
    crate::opencode_pool::pool::write_scan_config(state.as_ref(), provider, &config).await?;
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
    let Some(ip) = payload
        .get("ip")
        .and_then(Value::as_str)
        .and_then(normalize_exit_ip)
    else {
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
    crate::opencode_pool::pool::write_scan_config(state.as_ref(), provider, &config).await?;
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
    let health = OpenCodeHealthConfig::from_provider_config(&provider.config);
    let status = opencode_ip_pool_status_for(&provider.id);
    let pool_ips = list_opencode_pool_ips(state.as_ref(), &provider.id, &config).await?;
    // 迁移期间 healthy 可能还没播种，状态里的数字必须按实际生效的那份算，
    // 否则面板会显示「健康 0」而线上明明在用 65 个。
    let effective_pool = config.effective_pool(&health);
    let disabled: BTreeSet<&str> = config
        .exit_pool_disabled
        .iter()
        .map(|ip| ip.trim())
        .filter(|ip| !ip.is_empty())
        .collect();
    let in_use = effective_pool
        .iter()
        .filter(|ip| !disabled.contains(ip.trim()))
        .count();
    // 生效状态与停用原因必须同源实时计算。之前一个取实时值、一个取复验
    // 任务写入的状态，于是会出现「active=false 但 reason=null」——
    // 使用者既看不出功能关了，也看不出为什么关。
    let sticky_active = health.session_sticky_active(in_use);
    let sticky_reason = if sticky_active {
        None
    } else if !health.session_sticky_enabled {
        Some("disabled_by_operator".to_string())
    } else {
        Some(format!(
            "pool_below_min({in_use}<{})",
            health.session_sticky_min_pool()
        ))
    };
    let degrade_active = health.passive_degrade_active(in_use);
    let degrade_reason = if degrade_active {
        None
    } else if !health.passive_degrade_enabled {
        Some("disabled_by_operator".to_string())
    } else {
        Some(format!(
            "pool_below_min({in_use}<{})",
            health.passive_degrade_min_pool()
        ))
    };
    Ok(Json(json!({
        "provider_id": provider.id,
        "scanning": status.scanning,
        "cleaning": status.cleaning,
        "verifying": status.verifying,
        "last_scan_at": status.last_scan_at,
        "last_scan_targets": status.last_scan_targets,
        "last_scan_found": status.last_scan_found,
        "last_scan_added": status.last_scan_added,
        "last_clean_at": status.last_clean_at,
        "last_clean_checked": status.last_clean_checked,
        "last_clean_removed": status.last_clean_removed,
        // 复验摘要以落盘值为准，内存状态只在本次进程内更新过它。
        // 进程重启后内存态清空，而 `latencies` 仍然留着——两者取不同的
        // 来源会让界面显示「上次复验：无」却列着一整屏节点延迟。
        "last_verify_at": health
            .last_verify_at
            .clone()
            .or_else(|| status.last_verify_at.clone()),
        "last_verify_checked": if health.last_verify_at.is_some() {
            health.last_verify_checked
        } else {
            status.last_verify_checked
        },
        "last_verify_kept": if health.last_verify_at.is_some() {
            health.last_verify_kept
        } else {
            status.last_verify_kept
        },
        "last_verify_dropped": if health.last_verify_at.is_some() {
            health.last_verify_dropped
        } else {
            status.last_verify_dropped
        },
        "auto_enabled": config.auto_enabled,
        "autoscan_effective": config.autoscan_effective(),
        "rotation_enabled": config.rotation_enabled,
        "rotation_effective": config.rotation_effective(),
        "cooldown_minutes": config.effective_cooldown_minutes(),
        "rotation_cursor": crate::opencode_rotation::peek_rotation_cursor(state.as_ref(), &provider.id)
            .await,
        // 池大小单独给一份，前端要显示「第 N / M 个」而不是单调递增的原始计数。
        "rotation_pool_size": effective_pool.len(),
        // 上次真正选中的出口 IP：取模基数是「可用」池（剔除停用+冷却），
        // 只拿 exit_pool 长度去除会偏，所以精确值由请求路径记在这里。
        "rotation_last_ip": crate::opencode_rotation::peek_last_exit_ip(state.as_ref(), &provider.id)
            .await,
        "interval_hours": config.interval_hours.unwrap_or(0),
        "concurrency": config.concurrency.unwrap_or(OPENCODE_SCAN_DEFAULT_CONCURRENCY),
        "cidrs": config.cidrs,
        "proxy_domain": config
            .effective_proxy_domain()
            .unwrap_or_else(|| OPENCODE_ORIGINAL_DOMAIN.to_string()),
        "proxy_enabled": config.proxy_enabled,
        "saved_proxy_domain": config.proxy_domain.clone(),
        "exit_pool": effective_pool.clone(),
        "exit_pool_disabled": config.exit_pool_disabled.clone(),
        "pool_source": if effective_pool.is_empty() { "key" } else { "provider" },
        "original_domain": OPENCODE_ORIGINAL_DOMAIN,
        "pool_ips": pool_ips,
        // 长任务进度：大批量扫描要跑几十分钟，没有这两个数面板上只会像卡死
        "progress_done": status.progress_done,
        "progress_total": status.progress_total,
        "progress_kind": status.progress_kind,
        // 复验的进度独立于扫描：两个任务共用一组数字会互相覆盖
        "verify_progress_done": status.verify_progress_done,
        "verify_progress_total": status.verify_progress_total,
        "verify_targets": status.verify_targets,
        // 分层计数：候选 / 健康 / 在用，放一起才看得出扫描筛掉了什么
        "candidate_count": config.candidates.len() as u64,
        "healthy_count": effective_pool.len() as u64,
        "in_use_count": in_use as u64,
        "degraded_count": health.degraded.len() as u64,
        "healthy": effective_pool.clone(),
        "candidates": config.candidates.clone(),
        "pinned": config.pinned.clone(),
        "degraded": health.degraded.clone(),
        "healthy_prev_count": health.healthy_prev.len() as u64,
        // 逐节点延迟与淘汰原因。面板的「在用 / 候选 / 已淘汰」三张表
        // 都靠它们渲染——没有延迟就看不出池里混进了慢节点。
        "latencies": health.latencies.clone(),
        "rejections": health.rejections.clone(),
        // 自动停用的原因。不回报原因，使用者无法判断粘性失效是保护
        // 机制起作用还是出了故障。
        "session_sticky_active": sticky_active,
        "session_sticky_enabled": health.session_sticky_enabled,
        "session_sticky_disabled_reason": sticky_reason,
        "passive_degrade_active": degrade_active,
        "passive_degrade_enabled": health.passive_degrade_enabled,
        "passive_degrade_disabled_reason": degrade_reason,
        // 给的是**生效值**而不是原始配置：界面上显示的阈值必须是真正在判定
        // 用的那个，否则用户照着一个没在生效的数字做判断。
        "passive_degrade_first_byte_ms": health.passive_degrade_first_byte_ms(),
        "passive_degrade_cooldown_minutes": health.passive_degrade_cooldown_minutes(),
        "auto_verify_enabled": health.auto_verify_enabled,
        "autoverify_effective": health.autoverify_effective(),
        "verify_interval_hours": health.verify_interval_hours.unwrap_or(0),
        "verify_samples": health.verify_samples(),
        "verify_max_median_ms": health.verify_max_median_ms(),
        "min_pool_size": health.min_pool_size(),
        "pool_below_floor": in_use < health.min_pool_size(),
        "pool_empty": in_use == 0,
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
    //
    // 校验必须在合并之前：合并后的值已经被默认值兜底改过，越界信息丢失，
    // 报错就指不到真正写错的那个字段。段的位置与 `merged_with_payload`
    // 保持一致：没有 `opencode_scan` 段时，请求体本身就是扫描段。
    let scan_section = payload
        .get("opencode_scan")
        .and_then(Value::as_object)
        .unwrap_or(&payload);
    if let Err(detail) = OpenCodeScanConfig::validate_section(scan_section) {
        return Ok(bad_request(format!("扫描配置无效：{detail}")));
    }
    if let Some(health_section) = payload.get("opencode_health").and_then(Value::as_object) {
        if let Err(detail) = OpenCodeHealthConfig::validate_section(health_section) {
            return Ok(bad_request(format!("健康维护配置无效：{detail}")));
        }
    }

    // 前置代理域名只做**记住**，不再改写 endpoint.base_url。
    // 端点 base_url 是真实上游，属于配置事实；是否走前置代理由 proxy_enabled 开关
    // 在请求路径上决定（见 planner 的 host 注入）。这样输入框里的域名永远只归用户
    // 所有，开关不会把端点或输入框改来改去。
    //
    // 端点计数与配置写入无关，且不会因为重试而变化，所以留在重试循环外。
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
            .list_provider_catalog_endpoints_by_provider_ids(std::slice::from_ref(&provider.id))
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

    // 合并、CIDR 复查、两段 CAS 一起放进重试循环：每轮都重读最新配置再合并，
    // 于是后台扫描/复验刚写入的 healthy、candidates 不会被这次保存按旧值盖回去。
    //
    // 之前这里是「请求开始时读一次 → 合并 → 整行写回」，没有 CAS。方向和任务侧
    // 正好相反：任务撞上保存会 CAS 失败重试（安全），保存撞上任务则静默覆盖
    // （不安全）。窗口只有几十毫秒，但它命中的症状和之前那次线上事故一模一样：
    // 摘要写着 kept=337，池子却还是 65 个。
    let outcome = pool::write_pool_config_pair(state.as_ref(), &provider.id, |latest| {
        let config = OpenCodeScanConfig::merged_with_payload(latest, &payload);
        for cidr in &config.cidrs {
            if parse_cidr(cidr).is_none() {
                return Err(format!("无效的 CIDR: {cidr}"));
            }
        }
        // 验健康域是独立的一段，和扫描段在同一次提交里落盘，两者不能互相覆盖。
        let health = OpenCodeHealthConfig::merged_with_payload(latest, &payload);
        Ok((
            config.to_provider_config_value(),
            health.to_provider_config_value(),
        ))
    })
    .await?;

    match outcome {
        pool::PoolConfigWriteOutcome::Saved => {}
        pool::PoolConfigWriteOutcome::Invalid(detail) => {
            return Ok(bad_request(detail));
        }
        pool::PoolConfigWriteOutcome::Conflict => {
            // 连续 8 次都撞上并发修改。这是「有人正在改，请重试」，不是保存失败——
            // 回 500 会让用户以为没存上，然后反复点，反复撞上，反复失败。
            return Ok((
                http::StatusCode::CONFLICT,
                Json(json!({
                    "detail": "配置正在被后台扫描或复验更新，请稍后重试"
                })),
            )
                .into_response());
        }
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
    // 扫描可能跑几十分钟，同步等待会让前端 HTTP 超时、用户看到「扫描失败」，
    // 但后端其实还在跑。这里改成：同步占位 → 后台执行 → 立刻 202，
    // 前端改为轮询状态。同步占位是为了消除 scanning=false 的空窗期。
    let config = OpenCodeScanConfig::from_provider_config(&provider.config);
    if config.cidrs.is_empty() {
        return Ok(bad_request("未配置扫描网段，请先在扫描配置中添加 CIDR"));
    }
    if !pool::claim_scan_slot(&provider.id) {
        return Ok(bad_request("扫描正在进行中"));
    }
    let app = state.as_ref().clone();
    let owned = provider.clone();
    tokio::spawn(async move {
        if let Err(error) = pool::run_claimed_open_code_pool_scan(&app, &owned).await {
            tracing::warn!(
                event_name = "opencode_ip_pool_scan_failed",
                log_type = "ops",
                provider_id = owned.id.as_str(),
                error = error.into_message(),
                "opencode ip pool scan failed"
            );
        }
    });
    Ok((
        http::StatusCode::ACCEPTED,
        Json(json!({
            "provider_id": provider.id,
            "started": true,
            "scanning": true,
        })),
    )
        .into_response())
}

/// 复验健康：把候选（以及现有健康池）重新按真实负载测一遍，
/// 产出生产使用的 `healthy` 集合。与扫描同样异步 + 202 + 轮询。
async fn run_verify(
    state: &AdminAppState<'_>,
    provider: &aether_data_contracts::repository::provider_catalog::StoredProviderCatalogProvider,
) -> Result<Response<Body>, GatewayError> {
    if !pool::claim_verify_slot(&provider.id) {
        return Ok(bad_request(
            "扫描、复验或清理正在进行中，请等待当前任务结束",
        ));
    }
    let app = state.as_ref().clone();
    let owned = provider.clone();
    tokio::spawn(async move {
        if let Err(error) = pool::run_claimed_open_code_pool_verify(&app, &owned).await {
            tracing::warn!(
                event_name = "opencode_ip_pool_verify_failed",
                log_type = "ops",
                provider_id = owned.id.as_str(),
                error = error.into_message(),
                "opencode ip pool verify failed"
            );
        }
    });
    Ok((
        http::StatusCode::ACCEPTED,
        Json(json!({
            "provider_id": provider.id,
            "started": true,
            "verifying": true,
        })),
    )
        .into_response())
}

async fn run_clean(
    state: &AdminAppState<'_>,
    provider: &aether_data_contracts::repository::provider_catalog::StoredProviderCatalogProvider,
) -> Result<Response<Body>, GatewayError> {
    if !pool::claim_clean_slot(&provider.id) {
        return Ok(bad_request("清理正在进行中"));
    }
    let app = state.as_ref().clone();
    let owned = provider.clone();
    tokio::spawn(async move {
        if let Err(error) = pool::run_claimed_open_code_pool_clean(&app, &owned).await {
            tracing::warn!(
                event_name = "opencode_ip_pool_clean_failed",
                log_type = "ops",
                provider_id = owned.id.as_str(),
                error = error.into_message(),
                "opencode ip pool clean failed"
            );
        }
    });
    Ok((
        http::StatusCode::ACCEPTED,
        Json(json!({
            "provider_id": provider.id,
            "started": true,
            "cleaning": true,
        })),
    )
        .into_response())
}

async fn restore_original_base_url(
    state: &AdminAppState<'_>,
    provider: &aether_data_contracts::repository::provider_catalog::StoredProviderCatalogProvider,
) -> Result<Response<Body>, GatewayError> {
    let endpoints = state
        .list_provider_catalog_endpoints_by_provider_ids(std::slice::from_ref(&provider.id))
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
