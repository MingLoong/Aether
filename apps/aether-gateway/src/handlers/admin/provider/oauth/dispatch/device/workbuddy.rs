//! WorkBuddy（腾讯 CodeBuddy）设备授权：发起 + 轮询。
//!
//! 与 xai 的分工完全一致：`aether-oauth` 的适配器只关心协议，
//! 网关这一层负责「建会话 → 落库 → 轮询 → 建 key → 触发账号状态刷新」。
//!
//! 与标准设备码流程的差异：
//! - 没有 `device_code` / `user_code`：上游签发的是 `state`，轮询时把 `state`
//!   拼进 query，所以 `state` 存在会话的 `device_code` 字段里；
//! - 「未完成」用**业务 code ≠ 0** 表达（HTTP 200），适配器映射成 `Pending`；
//! - 域（cn / global）决定 base_url、Origin/Referer 与 UA 平台段，
//!   存在会话的 `region` 字段里，轮询时据此重建适配器。

use super::session::attach_admin_provider_oauth_device_poll_terminal_response;
use crate::control::GatewayAdminPrincipalContext;
use crate::handlers::admin::provider::oauth::dispatch::helpers::admin_provider_oauth_key_name_from_auth_config;
use crate::handlers::admin::provider::oauth::errors::build_internal_control_error_response;
use crate::handlers::admin::provider::oauth::provisioning::{
    provider_oauth_active_api_formats, provider_oauth_key_proxy_value,
};
use crate::handlers::admin::provider::oauth::runtime::spawn_provider_oauth_account_state_refresh_after_update;
use crate::handlers::admin::provider::oauth::state::{
    current_unix_secs, generate_provider_oauth_nonce,
};
use crate::handlers::admin::request::AdminAppState;
use crate::GatewayError;
use aether_contracts::ProxySnapshot;
use aether_data::repository::provider_oauth::{
    StoredAdminProviderOAuthDeviceSession, KIRO_DEVICE_AUTH_SESSION_TTL_BUFFER_SECS,
};
use aether_data_contracts::repository::provider_catalog::{
    StoredProviderCatalogEndpoint, StoredProviderCatalogProvider,
};
use aether_oauth::core::OAuthError;
use aether_oauth::provider::providers::{
    WorkbuddyDevicePollOutcome, WorkbuddyOAuthRealm, WorkbuddyProviderOAuthAdapter,
    WORKBUDDY_CHAT_BASE_CN, WORKBUDDY_CHAT_BASE_GLOBAL,
};
use aether_oauth::provider::ProviderOAuthTransportContext;
use axum::{
    body::Body,
    http,
    response::{IntoResponse, Response},
    Json,
};
use serde_json::{json, Value};
use std::time::Duration;

/// 上游设备授权端点的路径尾巴（用于从注入后的 URL 反推 base）。
const AUTH_STATE_SUFFIX: &str = "/v2/plugin/auth/state?platform=CLI";
const AUTH_TOKEN_SUFFIX: &str = "token?state=";
const LOGIN_ACCOUNT_SUFFIX: &str = "login/account?state=";

/// 单次轮询上游的等待预算。
///
/// **必须明显小于前门的等待上限**。2026-10-24 真机事故形状（154 生产，25 分钟）：
/// 网关这一层单次上游调用用的上限是 `OAuthTimeouts::DIRECT_DEFAULT`
/// （`total_ms = 30s`），而浏览器侧在那段时间里一律 ~30s 就换来 504 / 499 ——
/// 两者同一量级，于是上游一卡住，浏览器**先**死掉，本轮真实结果（pending / token）
/// 全部丢弃；前端把 5xx 当网络抖动继续静默重试，界面永远停在「等待授权」
/// （现象就是「浏览器里登录完了却没回调」）。
/// 取 20s：给前门留余量，同时远高于实测一次正常轮询的 0.3–0.5s。
fn workbuddy_device_poll_budget() -> Duration {
    Duration::from_secs(20)
}

/// 由 realm 推导默认 base，再按状态里的注入值统一改写四个端点。
///
/// 搜索顺序与 xai 一致：`state.provider_oauth_token_url` 允许测试注入一个
/// 假域名；一旦注入，token / account / refresh 三个端点都从同一个 base 派生，
/// 避免出现「state 打到 mock、轮询打回线上」的半截注入。
fn workbuddy_endpoints(
    state: &AdminAppState<'_>,
    realm: WorkbuddyOAuthRealm,
) -> WorkbuddyEndpoints {
    let base = if realm.is_global() {
        WORKBUDDY_CHAT_BASE_GLOBAL
    } else {
        WORKBUDDY_CHAT_BASE_CN
    };
    let default_state_url = format!("{base}{AUTH_STATE_SUFFIX}");
    let state_url = state.provider_oauth_token_url("workbuddy_device", &default_state_url);
    let resolved_base = state_url
        .strip_suffix(AUTH_STATE_SUFFIX)
        .map(str::to_string)
        .unwrap_or_else(|| base.to_string());
    WorkbuddyEndpoints {
        state_url,
        token_url_prefix: format!("{resolved_base}/v2/plugin/auth/{AUTH_TOKEN_SUFFIX}"),
        account_url_prefix: format!("{resolved_base}/v2/plugin/{LOGIN_ACCOUNT_SUFFIX}"),
        refresh_url: format!("{resolved_base}/v2/plugin/auth/token/refresh"),
    }
}

struct WorkbuddyEndpoints {
    state_url: String,
    token_url_prefix: String,
    account_url_prefix: String,
    refresh_url: String,
}

impl WorkbuddyEndpoints {
    fn adapter(&self, realm: WorkbuddyOAuthRealm) -> WorkbuddyProviderOAuthAdapter {
        let adapter = if realm.is_global() {
            WorkbuddyProviderOAuthAdapter::default().with_global_realm()
        } else {
            WorkbuddyProviderOAuthAdapter::default()
        };
        adapter.with_endpoint_overrides(
            self.state_url.clone(),
            self.token_url_prefix.clone(),
            self.account_url_prefix.clone(),
            self.refresh_url.clone(),
        )
    }
}

/// 轮询时按会话记录的 token 前缀反推其它端点（会话里只存一个前缀）。
fn endpoints_from_token_prefix(token_url_prefix: &str) -> WorkbuddyEndpoints {
    let resolved_base = token_url_prefix
        .strip_suffix(&format!("/v2/plugin/auth/{AUTH_TOKEN_SUFFIX}"))
        .unwrap_or(token_url_prefix.trim_end_matches('/'));
    WorkbuddyEndpoints {
        state_url: format!("{resolved_base}{AUTH_STATE_SUFFIX}"),
        token_url_prefix: token_url_prefix.to_string(),
        account_url_prefix: format!("{resolved_base}/v2/plugin/{LOGIN_ACCOUNT_SUFFIX}"),
        refresh_url: format!("{resolved_base}/v2/plugin/auth/token/refresh"),
    }
}

/// 发起设备授权：POST `/v2/plugin/auth/state?platform=CLI` → `{state, authUrl}`。
#[allow(clippy::too_many_arguments)]
pub(super) async fn handle_admin_provider_oauth_workbuddy_device_authorize(
    state: &AdminAppState<'_>,
    provider_id: &str,
    provider: &StoredProviderCatalogProvider,
    principal: &GatewayAdminPrincipalContext,
    runtime_endpoint: Option<&StoredProviderCatalogEndpoint>,
    request_proxy: Option<ProxySnapshot>,
    proxy_node_id: Option<&str>,
    realm: WorkbuddyOAuthRealm,
) -> Result<Response<Body>, GatewayError> {
    // 号池声明的区域优先于请求参数。UI 已经按号池把区域锁死，但这里是 HTTP 入口，
    // 直接调 API 仍能传 `login_option=global`——那样会拿国际域的 state 去换 CN 的账号，
    // 要等到落号时被 `ensure_workbuddy_credential_matches_provider_realm` 拦下才发现，
    // 用户看到的是「登录完了号进不来」。所以在会话建立前就拒掉。
    if let Some(instance) = workbuddy_instance_realm_from_provider(provider) {
        if instance != realm.as_str() {
            return Ok(build_internal_control_error_response(
                http::StatusCode::BAD_REQUEST,
                format!(
                    "该号池固定为{}，不能发起{}的设备授权：请到对应区域的号池里添加",
                    workbuddy_realm_label(&instance),
                    workbuddy_realm_label(realm.as_str()),
                ),
            ));
        }
    }

    let endpoints = workbuddy_endpoints(state, realm);
    let adapter = endpoints.adapter(realm);
    let ctx = ProviderOAuthTransportContext {
        provider_id: provider_id.to_string(),
        provider_type: provider.provider_type.clone(),
        endpoint_id: runtime_endpoint.map(|endpoint| endpoint.id.clone()),
        key_id: None,
        auth_type: Some("oauth".to_string()),
        decrypted_api_key: None,
        decrypted_auth_config: None,
        provider_config: provider.config.clone(),
        endpoint_config: runtime_endpoint.and_then(|endpoint| endpoint.config.clone()),
        key_config: None,
        network: aether_oauth::network::OAuthNetworkContext::provider_operation(
            request_proxy.clone(),
        ),
    };
    let executor = crate::oauth::GatewayOAuthHttpExecutor::new(*state);
    let authorization = match adapter.start_device_flow(&executor, &ctx).await {
        Ok(authorization) => authorization,
        Err(error) => {
            return Ok(build_internal_control_error_response(
                http::StatusCode::BAD_REQUEST,
                sanitize_workbuddy_oauth_error(&error),
            ));
        }
    };

    let now_unix_secs = current_unix_secs();
    let session_id = generate_provider_oauth_nonce();
    let session = StoredAdminProviderOAuthDeviceSession {
        session_id: session_id.clone(),
        provider_id: provider_id.to_string(),
        initiated_by_user_id: principal.user_id.clone(),
        initiated_by_session_id: principal.session_id.clone(),
        initiated_by_management_token_id: principal.management_token_id.clone(),
        // region 承载 realm（cn / global）：轮询时据此重建 base 与出站头。
        region: realm.as_str().to_string(),
        client_id: String::new(),
        client_secret: String::new(),
        // 上游没有 device_code：把服务端签发的 state 存进这个字段。
        device_code: authorization.device_code.clone(),
        auth_type: Some("device".to_string()),
        social_provider: None,
        code_verifier: None,
        // redirect_uri 承载 token 前缀（与 xai 存 token url 同一手法）。
        redirect_uri: Some(endpoints.token_url_prefix.clone()),
        machine_id: None,
        interval: authorization.interval,
        expires_at_unix_secs: now_unix_secs.saturating_add(authorization.expires_in),
        status: "pending".to_string(),
        proxy_node_id: proxy_node_id
            .map(str::trim)
            .filter(|value| !value.is_empty())
            .map(ToOwned::to_owned),
        created_at_unix_ms: now_unix_secs,
        key_id: None,
        email: None,
        replaced: false,
        error_msg: None,
    };
    if let Err(response) = state
        .save_provider_oauth_device_session(
            &session_id,
            &session,
            authorization
                .expires_in
                .saturating_add(KIRO_DEVICE_AUTH_SESSION_TTL_BUFFER_SECS),
        )
        .await
    {
        return Ok(response);
    }

    Ok(Json(json!({
        "session_id": session_id,
        "user_code": authorization.user_code,
        "verification_uri": authorization.verification_uri,
        "verification_uri_complete": authorization.verification_uri_complete,
        "expires_in": authorization.expires_in,
        "interval": authorization.interval,
        "auth_type": "device",
        "realm": realm.as_str(),
    }))
    .into_response())
}

/// 轮询：拿到凭证就落库成 key；用户还没登录完就继续 pending。
pub(super) async fn handle_admin_provider_oauth_workbuddy_device_poll(
    state: &AdminAppState<'_>,
    provider: &StoredProviderCatalogProvider,
    endpoints: &[StoredProviderCatalogEndpoint],
    request_proxy: Option<ProxySnapshot>,
    session_id: &str,
    mut session: StoredAdminProviderOAuthDeviceSession,
) -> Result<Response<Body>, GatewayError> {
    let realm = workbuddy_realm_from_stored(&session.region);
    let token_url_prefix = session
        .redirect_uri
        .as_deref()
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .map(ToOwned::to_owned)
        .unwrap_or_else(|| workbuddy_endpoints(state, realm).token_url_prefix);
    let urls = endpoints_from_token_prefix(&token_url_prefix);
    let adapter = urls.adapter(realm);
    let ctx = ProviderOAuthTransportContext {
        provider_id: provider.id.clone(),
        provider_type: provider.provider_type.clone(),
        endpoint_id: None,
        key_id: None,
        auth_type: Some("oauth".to_string()),
        decrypted_api_key: None,
        decrypted_auth_config: None,
        provider_config: provider.config.clone(),
        endpoint_config: None,
        key_config: None,
        network: aether_oauth::network::OAuthNetworkContext::provider_operation(
            request_proxy.clone(),
        ),
    };
    let executor = crate::oauth::GatewayOAuthHttpExecutor::new(*state);
    let polled = tokio::time::timeout(
        workbuddy_device_poll_budget(),
        adapter.poll_device_token(&executor, &ctx, &session.device_code),
    )
    .await;
    let outcome = match polled {
        Ok(Ok(outcome)) => outcome,
        Ok(Err(error)) => {
            return Ok(workbuddy_device_poll_terminal_from_error(
                state,
                session_id,
                &mut session,
                &error,
            )
            .await);
        }
        Err(_elapsed) => {
            // 上游这一轮没在预算内应答 —— **不能**判死会话（用户可能正在浏览器里输验证码），
            // 也不能让反代先超时：按 pending 回报，前端按 interval 继续轮询。
            tracing::warn!(
                provider_id = %provider.id,
                session_id = %session_id,
                budget_ms = workbuddy_device_poll_budget().as_millis() as u64,
                "workbuddy device poll did not answer within budget; reporting pending"
            );
            return Ok(Json(json!({"status": "pending", "replaced": false})).into_response());
        }
    };

    match outcome {
        WorkbuddyDevicePollOutcome::Pending => {
            Ok(Json(json!({"status": "pending", "replaced": false})).into_response())
        }
        WorkbuddyDevicePollOutcome::Authorized(result) => {
            persist_workbuddy_device_authorization(
                state,
                provider,
                endpoints,
                request_proxy,
                session_id,
                session,
                *result,
            )
            .await
        }
    }
}

/// 实例级域：`providers.config.workbuddy.realm`（`cn` / `global`）；未声明 → `None`。
///
/// 未声明 = 拆双实例之前建的老实例，保持原行为（不拦任何号）；新建实例由
/// `ProviderFormDialog` 的两个预设写入 realm，从此只会收本域的号。
pub(crate) fn workbuddy_instance_realm_from_provider(
    provider: &StoredProviderCatalogProvider,
) -> Option<String> {
    workbuddy_instance_realm_from_config(provider.config.as_ref())
}

/// 区域的中文标签，只用于把「预期 / 实际」写进报错文案。
fn workbuddy_realm_label(realm: &str) -> &'static str {
    if realm == "global" {
        "WorkBuddy 国际版 (Global)"
    } else {
        "CodeBuddy 国内版 (CN)"
    }
}

/// 纯函数版本（便于测试）：只认 `cn` / `global`，其它值一律当「未声明」。
pub(crate) fn workbuddy_instance_realm_from_config(config: Option<&Value>) -> Option<String> {
    let realm = config
        .and_then(|config| config.get("workbuddy"))
        .and_then(|bucket| bucket.get("realm"))
        .and_then(Value::as_str)
        .map(|realm| realm.trim().to_ascii_lowercase())?;
    matches!(realm.as_str(), "cn" | "global").then_some(realm)
}

async fn persist_workbuddy_device_authorization(
    state: &AdminAppState<'_>,
    provider: &StoredProviderCatalogProvider,
    endpoints: &[StoredProviderCatalogEndpoint],
    request_proxy: Option<ProxySnapshot>,
    session_id: &str,
    mut session: StoredAdminProviderOAuthDeviceSession,
    result: aether_oauth::provider::ProviderOAuthTokenSet,
) -> Result<Response<Body>, GatewayError> {
    let access_token = result.token_set.access_token.trim().to_string();
    if access_token.is_empty() {
        return Ok(Json(json!({
            "status": "error",
            "error": "WorkBuddy token 响应缺少 accessToken",
            "replaced": false,
        }))
        .into_response());
    }
    let mut auth_config = result.auth_config.as_object().cloned().unwrap_or_default();
    auth_config.insert("provider_type".to_string(), json!("workbuddy"));
    auth_config.insert("auth_method".to_string(), json!("oauth"));

    // 「国内 / 国际」双实例：实例固定哪一域就只能落哪一域的号。
    //
    // 这条不是体验优化，是硬约束 ✗：对话域跟着**端点**走（token 刷新域只看账号 realm），
    // 把国际号存进 CN 实例，之后每一次对话都会打到 `copilot.tencent.com` 拿 401
    // （真机 2026-10-17 复现）。入口直接拒掉，比让运营事后翻日志便宜得多。
    if let Some(instance_realm) = workbuddy_instance_realm_from_provider(provider) {
        let credential_realm = auth_config
            .get("realm")
            .and_then(Value::as_str)
            .map(|realm| realm.trim().to_ascii_lowercase())
            .unwrap_or_else(|| "cn".to_string());
        if credential_realm != instance_realm {
            return Ok(Json(json!({
                "status": "error",
                "error": format!(
                    "该供应商固定为{instance_realm}版，不能添加{credential_realm}账号：请到对应区域的供应商实例里添加",
                ),
                "replaced": false,
            }))
            .into_response());
        }
    }
    auth_config.insert("using_api".to_string(), json!(false));

    let duplicate = match state
        .find_duplicate_provider_oauth_key(&provider.id, &auth_config, None)
        .await
    {
        Ok(duplicate) => duplicate,
        Err(detail) => {
            return Ok(Json(json!({
                "status": "error",
                "error": detail,
                "replaced": false,
            }))
            .into_response());
        }
    };

    let api_formats = provider_oauth_active_api_formats(endpoints);
    let key_proxy = provider_oauth_key_proxy_value(session.proxy_node_id.as_deref());
    let expires_at = result.token_set.expires_at_unix_secs;
    // WorkBuddy 没有邮箱：展示名用 nickname，缺省由 key 名兜底。
    let email = auth_config
        .get("nickname")
        .and_then(Value::as_str)
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .map(ToOwned::to_owned);
    let mut replaced = false;
    let persisted_key = if let Some(existing_key) = duplicate {
        replaced = true;
        match state
            .update_existing_provider_oauth_catalog_key(
                &existing_key,
                &provider.provider_type,
                &access_token,
                &auth_config,
                &api_formats,
                key_proxy.clone(),
                expires_at,
            )
            .await?
        {
            Some(key) => key,
            None => {
                return Ok(build_internal_control_error_response(
                    http::StatusCode::SERVICE_UNAVAILABLE,
                    "provider oauth write unavailable",
                ));
            }
        }
    } else {
        let key_name = admin_provider_oauth_key_name_from_auth_config(
            &provider.provider_type,
            &auth_config,
            None,
        );
        match state
            .create_provider_oauth_catalog_key(
                &provider.id,
                &provider.provider_type,
                &key_name,
                &access_token,
                &auth_config,
                &api_formats,
                key_proxy,
                expires_at,
            )
            .await?
        {
            Some(key) => key,
            None => {
                return Ok(build_internal_control_error_response(
                    http::StatusCode::SERVICE_UNAVAILABLE,
                    "provider oauth write unavailable",
                ));
            }
        }
    };

    spawn_provider_oauth_account_state_refresh_after_update(
        state.cloned_app(),
        provider.clone(),
        persisted_key.id.clone(),
        request_proxy.clone(),
    );

    session.status = "authorized".to_string();
    session.key_id = Some(persisted_key.id.clone());
    session.email = email.clone();
    session.replaced = replaced;
    session.error_msg = None;
    let _ = state
        .save_provider_oauth_device_session(session_id, &session, 60)
        .await;

    Ok(attach_admin_provider_oauth_device_poll_terminal_response(
        session_id,
        "authorized",
        Json(json!({
            "status": "authorized",
            "key_id": persisted_key.id,
            "email": email,
            "replaced": replaced,
        }))
        .into_response(),
    ))
}

async fn workbuddy_device_poll_terminal_from_error(
    state: &AdminAppState<'_>,
    session_id: &str,
    session: &mut StoredAdminProviderOAuthDeviceSession,
    error: &OAuthError,
) -> Response<Body> {
    let (status, message) = match error {
        OAuthError::InvalidRequest(detail) if detail.to_ascii_lowercase().contains("expired") => {
            ("expired", "设备授权已过期".to_string())
        }
        _ => ("error", sanitize_workbuddy_oauth_error(error)),
    };
    session.status = status.to_string();
    session.error_msg = Some(message.clone());
    let _ = state
        .save_provider_oauth_device_session(session_id, session, 30)
        .await;
    attach_admin_provider_oauth_device_poll_terminal_response(
        session_id,
        status,
        Json(json!({
            "status": status,
            "error": message,
            "replaced": false,
        }))
        .into_response(),
    )
}

fn sanitize_workbuddy_oauth_error(error: &OAuthError) -> String {
    match error {
        OAuthError::InvalidRequest(_) => "WorkBuddy 设备授权失败: 请求参数无效".to_string(),
        OAuthError::HttpStatus { status_code, .. } => {
            format!("WorkBuddy 设备授权失败: HTTP {status_code}")
        }
        _ => "WorkBuddy 设备授权失败".to_string(),
    }
}

/// 会话里记录的 realm 字符串 → 枚举（未知值按 CN 处理，与上游零回归口径一致）。
pub(super) fn workbuddy_realm_from_stored(value: &str) -> WorkbuddyOAuthRealm {
    if value.trim().eq_ignore_ascii_case("global") {
        WorkbuddyOAuthRealm::Global
    } else {
        WorkbuddyOAuthRealm::Cn
    }
}

#[cfg(test)]
mod workbuddy_realm_tests {
    use super::workbuddy_instance_realm_from_config;
    use serde_json::json;

    /// 实例级 realm：只认精确的 cn / global（trim + 大小写归一）；脏值一律当「未声明」——
    /// 未声明 = 拆双实例之前建的老实例，保持原行为（不拦任何号），避免把老数据锁死。
    #[test]
    fn instance_realm_recognises_only_cn_and_global() {
        assert_eq!(
            workbuddy_instance_realm_from_config(Some(&json!({"workbuddy": {"realm": "cn"}}))),
            Some("cn".to_string())
        );
        assert_eq!(
            workbuddy_instance_realm_from_config(Some(
                &json!({"workbuddy": {"realm": " Global "}})
            )),
            Some("global".to_string())
        );
        assert_eq!(workbuddy_instance_realm_from_config(None), None);
        assert_eq!(workbuddy_instance_realm_from_config(Some(&json!({}))), None);
        assert_eq!(
            workbuddy_instance_realm_from_config(Some(&json!({"workbuddy": {"realm": "intl"}}))),
            None
        );
        assert_eq!(
            workbuddy_instance_realm_from_config(Some(&json!({"codex": {"realm": "global"}}))),
            None
        );
    }

    /// 轮询预算必须**严格小于**前门/出站两道 30s 上限（实测浏览器 ~30s 即 504/499，
    /// `OAuthTimeouts::DIRECT_DEFAULT.total_ms = 30000`）：
    /// 一旦两者相等或更大，上游卡住时浏览器先死，本轮结果被丢弃，
    /// 前端进入静默重试的死循环（真机 2026-10-24 事故）。
    #[test]
    fn device_poll_budget_stays_under_the_frontdoor_wait_ceiling() {
        let budget = super::workbuddy_device_poll_budget();
        assert!(
            budget < std::time::Duration::from_secs(30),
            "轮询预算 {budget:?} 必须小于前门 30s 量级的等待上限"
        );
        assert!(
            budget >= std::time::Duration::from_secs(10),
            "轮询预算 {budget:?} 太小，慢网络下的正常轮询会被误判成 pending"
        );
    }
}
