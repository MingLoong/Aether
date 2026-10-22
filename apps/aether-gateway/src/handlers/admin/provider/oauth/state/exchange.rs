use super::super::errors::{
    build_internal_control_error_response, normalize_provider_oauth_refresh_error_message,
};
use crate::handlers::admin::request::{AdminAppState, AdminProviderOAuthTemplate};
use aether_contracts::ProxySnapshot;
use aether_oauth::provider::providers::{
    AntigravityProviderOAuthAdapter, ClaudeCodeProviderOAuthAdapter, ClineProviderOAuthAdapter,
    GenericProviderOAuthAdapter, WorkbuddyProviderOAuthAdapter, ANTIGRAVITY_USER_INFO_URL,
    CLAUDE_CODE_PROVIDER_TYPE, CLAUDE_CODE_TOKEN_URL, CLAUDE_CODE_WEB_BASE_URL, CLINE_API_BASE_URL,
};
use aether_oauth::provider::{
    ProviderOAuthCookieAuthorizationInput, ProviderOAuthService, ProviderOAuthTransportContext,
};
use axum::{body::Body, http, response::Response};
use std::sync::Arc;

fn provider_oauth_transport_error_detail(prefix: &str, _error: &str) -> String {
    prefix.to_string()
}

fn provider_oauth_exchange_context(
    provider_type: &str,
    proxy: Option<ProxySnapshot>,
) -> ProviderOAuthTransportContext {
    ProviderOAuthTransportContext {
        provider_id: String::new(),
        provider_type: provider_type.to_string(),
        endpoint_id: None,
        key_id: None,
        auth_type: Some("oauth".to_string()),
        decrypted_api_key: None,
        decrypted_auth_config: None,
        provider_config: None,
        endpoint_config: None,
        key_config: None,
        network: aether_oauth::network::OAuthNetworkContext::provider_operation(proxy),
    }
}

/// 按模板挑适配器。失败只可能是「这个 provider 没有 OAuth 适配器」，因此回一个
/// `'static` 文案，让每个调用方自己拼响应（刷新链路要把文案塞进结构化失败信息）。
fn provider_oauth_service_for_template(
    template: AdminProviderOAuthTemplate,
    token_url: String,
    antigravity_user_info_url: String,
) -> Result<ProviderOAuthService, &'static str> {
    if template.provider_type.eq_ignore_ascii_case("antigravity") {
        let adapter = AntigravityProviderOAuthAdapter::default()
            .with_token_url_override(token_url)
            .with_user_info_url_override(antigravity_user_info_url);
        #[cfg(test)]
        let adapter = adapter.with_oauth_credentials_for_tests(
            "gateway-test-antigravity-client-id",
            "gateway-test-antigravity-client-secret",
        );
        return Ok(ProviderOAuthService::new().with_adapter(Arc::new(adapter)));
    }
    if template.provider_type.eq_ignore_ascii_case("cline") {
        // Cline 账号模式不是标准 OAuth：refreshToken 必须先经 `/auth/register` 换成 Cline token，
        // 聊天时再用 `Bearer workos:<token>`（前缀在适配器里贴好）。走 generic 会只拿到
        // WorkOS 的裸 token，那些 token 发给 `api.cline.bot` 一定 401。
        let adapter = ClineProviderOAuthAdapter::default().with_endpoint_overrides(
            template.authorize_url,
            token_url,
            CLINE_API_BASE_URL,
        );
        return Ok(ProviderOAuthService::new().with_adapter(Arc::new(adapter)));
    }
    if template
        .provider_type
        .eq_ignore_ascii_case(aether_oauth::provider::providers::WORKBUDDY_PROVIDER_TYPE)
    {
        // WorkBuddy 的刷新不是 OAuth 标准授权：`POST /v2/plugin/auth/token/refresh`、无 body、
        // 凭证放 `X-Refresh-Token`，还要求官方客户端指纹头。generic 适配器里根本没有它，
        // 于是「用 refreshToken 换 token」会在这里直接失败，跟上游一句话都没说上。
        let adapter = WorkbuddyProviderOAuthAdapter::default();
        // 域决定 Origin/Referer 与 UA 平台段：解析后的端点落在国际站就按国际域发。
        let adapter = if token_url.to_ascii_lowercase().contains("workbuddy.ai") {
            adapter.with_global_realm()
        } else {
            adapter
        };
        // refresh 用解析后的 URL（测试注入 / 私有部署改域名都从这里进来）。
        let adapter = adapter.with_refresh_url_override(token_url);
        return Ok(ProviderOAuthService::new().with_adapter(Arc::new(adapter)));
    }
    GenericProviderOAuthAdapter::for_provider_type(template.provider_type)
        .map(|adapter| adapter.with_token_url_override(token_url))
        .map(|adapter| ProviderOAuthService::new().with_adapter(Arc::new(adapter)))
        .ok_or("该 Provider 不支持 OAuth 授权")
}

fn token_payload_from_provider_oauth_result(
    result: aether_oauth::provider::ProviderOAuthTokenSet,
) -> Result<serde_json::Value, Response<Body>> {
    result.token_set.raw_payload.ok_or_else(|| {
        build_internal_control_error_response(
            http::StatusCode::BAD_REQUEST,
            "token exchange 返回缺少 access_token",
        )
    })
}

pub(crate) async fn exchange_admin_provider_oauth_code(
    state: &AdminAppState<'_>,
    template: AdminProviderOAuthTemplate,
    code: &str,
    state_nonce: &str,
    pkce_verifier: Option<&str>,
    proxy: Option<ProxySnapshot>,
) -> Result<serde_json::Value, Response<Body>> {
    let token_url = state.provider_oauth_token_url(template.provider_type, template.token_url);
    let antigravity_user_info_url =
        state.provider_oauth_token_url("antigravity_user_info", ANTIGRAVITY_USER_INFO_URL);
    let service =
        provider_oauth_service_for_template(template, token_url, antigravity_user_info_url)
            .map_err(|detail| {
                build_internal_control_error_response(http::StatusCode::BAD_REQUEST, detail)
            })?;
    let ctx = provider_oauth_exchange_context(template.provider_type, proxy);
    let executor = crate::oauth::GatewayOAuthHttpExecutor::new(*state);
    let result = service
        .exchange_code(&executor, &ctx, code, state_nonce, pkce_verifier)
        .await
        .map_err(|error| match error {
            aether_oauth::core::OAuthError::HttpStatus { .. } => {
                build_internal_control_error_response(
                    http::StatusCode::BAD_REQUEST,
                    "token exchange 失败",
                )
            }
            error => build_internal_control_error_response(
                http::StatusCode::BAD_REQUEST,
                provider_oauth_transport_error_detail("token exchange 失败", &error.to_string()),
            ),
        })?;
    token_payload_from_provider_oauth_result(result)
}

/// 刷新令牌失败的**结构化**原因。
///
/// 为什么需要它：旧的 `Response<Body>` 通道只能带一句内部文案——
/// `provider_oauth_transport_error_detail` 刻意不回显上游细节（见文件末尾的脱敏测试），
/// 于是批量导入永远只看到「Token 验证失败」。WorkBuddy 尤其吃亏：它的失败是
/// HTTP 200 + `{code,msg}` 信封，落到 `InvalidResponse` 后原文直接被吞。
///
/// 这条额外通道只给批量导入用：`message` 与拆分前的行为**逐字一致**（其它调用方不受影响），
/// `detail` 是上游原文摘要，调用方还会再脱敏 + 限长后才写日志 / 给面板。
pub(crate) struct AdminProviderOAuthRefreshFailure {
    /// 内部响应文案（与拆分前一致）。
    pub message: String,
    /// 上游 / 传输层给出的原始原因（可能为空）。
    pub detail: String,
    /// 上游 HTTP 状态码：只有 `HttpStatus` 分支拿得到。业务码失败（HTTP 200 + code != 0）
    /// 没有状态码，这里是 `None`——不要拿内部响应的 400 冒充上游状态。
    pub upstream_status_code: Option<u16>,
}

impl AdminProviderOAuthRefreshFailure {
    fn from_oauth_error(error: aether_oauth::core::OAuthError) -> Self {
        match error {
            aether_oauth::core::OAuthError::HttpStatus {
                status_code,
                body_excerpt,
            } => {
                let reason = normalize_provider_oauth_refresh_error_message(
                    Some(status_code),
                    Some(&body_excerpt),
                );
                Self {
                    message: format!("Refresh Token 验证失败: {reason}"),
                    detail: reason,
                    upstream_status_code: Some(status_code),
                }
            }
            error => Self {
                message: provider_oauth_transport_error_detail(
                    "Refresh Token 验证失败: token exchange 失败",
                    &error.to_string(),
                ),
                // `OAuthError::Display` 已按 aether-oauth 口径脱敏（URL 与 secret 形状的值都
                // 打码过），这里保留原文摘要，交给批量导入侧再限长。
                detail: error.to_string(),
                upstream_status_code: None,
            },
        }
    }

    fn missing_access_token() -> Self {
        Self {
            message: "token refresh 返回缺少 access_token".to_string(),
            detail: String::new(),
            upstream_status_code: None,
        }
    }
}

pub(crate) async fn exchange_admin_provider_oauth_refresh_token(
    state: &AdminAppState<'_>,
    template: AdminProviderOAuthTemplate,
    refresh_token: &str,
    proxy: Option<ProxySnapshot>,
) -> Result<serde_json::Value, Response<Body>> {
    exchange_admin_provider_oauth_refresh_token_failure(state, template, refresh_token, proxy, None)
        .await
        .map_err(|failure| {
            build_internal_control_error_response(http::StatusCode::BAD_REQUEST, failure.message)
        })
}

/// 与 [`exchange_admin_provider_oauth_refresh_token`] 同一条链路，但失败时把**上游原文与
/// 状态码**一并交回调用方（批量导入用它写结构化日志 + 把原因拼进面板文案）。
///
/// `refresh_identity` 是身份提示（目前只有 WorkBuddy 用得上：刷新要 `X-Machine-ID` /
/// `X-Enterprise-ID` 这类官方客户端头，而它们只能由 `uid` / `enterpriseId` 派生）。
/// **只放身份字段，绝不能带 accessToken**——带了适配器就会跳过刷新。
pub(crate) async fn exchange_admin_provider_oauth_refresh_token_failure(
    state: &AdminAppState<'_>,
    template: AdminProviderOAuthTemplate,
    refresh_token: &str,
    proxy: Option<ProxySnapshot>,
    refresh_identity: Option<&serde_json::Value>,
) -> Result<serde_json::Value, AdminProviderOAuthRefreshFailure> {
    let token_url = state.provider_oauth_token_url(template.provider_type, template.token_url);
    let antigravity_user_info_url =
        state.provider_oauth_token_url("antigravity_user_info", ANTIGRAVITY_USER_INFO_URL);
    let service =
        provider_oauth_service_for_template(template, token_url, antigravity_user_info_url)
            .map_err(|detail| AdminProviderOAuthRefreshFailure {
                message: detail.to_string(),
                detail: detail.to_string(),
                upstream_status_code: None,
            })?;
    let ctx = provider_oauth_exchange_context(template.provider_type, proxy);
    let executor = crate::oauth::GatewayOAuthHttpExecutor::new(*state);
    let input = aether_oauth::provider::ProviderOAuthImportInput {
        provider_type: template.provider_type.to_string(),
        name: None,
        refresh_token: Some(refresh_token.to_string()),
        raw_credentials: refresh_identity.cloned(),
        network: ctx.network.clone(),
    };
    let result = service
        .import_credentials(&executor, &ctx, input)
        .await
        .map_err(AdminProviderOAuthRefreshFailure::from_oauth_error)?;
    token_payload_from_provider_oauth_result(result)
        .map_err(|_| AdminProviderOAuthRefreshFailure::missing_access_token())
}

pub(crate) async fn authorize_admin_provider_oauth_with_cookie(
    state: &AdminAppState<'_>,
    session_key: String,
    proxy: Option<ProxySnapshot>,
) -> Result<serde_json::Value, Response<Body>> {
    let web_base_url =
        state.provider_oauth_token_url("claude_code_cookie_base_url", CLAUDE_CODE_WEB_BASE_URL);
    let token_url =
        state.provider_oauth_token_url(CLAUDE_CODE_PROVIDER_TYPE, CLAUDE_CODE_TOKEN_URL);
    let service = ProviderOAuthService::new().with_adapter(Arc::new(
        ClaudeCodeProviderOAuthAdapter::default().with_endpoint_overrides(web_base_url, token_url),
    ));
    let ctx = provider_oauth_exchange_context(CLAUDE_CODE_PROVIDER_TYPE, proxy);
    let executor = crate::oauth::GatewayOAuthHttpExecutor::new(*state);
    let result = service
        .authorize_with_cookie(
            &executor,
            &ctx,
            ProviderOAuthCookieAuthorizationInput { session_key },
        )
        .await
        .map_err(|error| {
            let detail = if matches!(error, aether_oauth::core::OAuthError::InvalidRequest(_)) {
                "Claude Cookie 格式无效"
            } else {
                "Claude Cookie 授权失败"
            };
            build_internal_control_error_response(http::StatusCode::BAD_REQUEST, detail)
        })?;
    token_payload_from_provider_oauth_result(result).map_err(|_| {
        build_internal_control_error_response(
            http::StatusCode::BAD_REQUEST,
            "Claude Cookie 授权返回缺少 access_token",
        )
    })
}

#[cfg(test)]
mod tests {
    use super::provider_oauth_transport_error_detail;

    #[test]
    fn provider_oauth_transport_error_does_not_reflect_network_details() {
        let detail = provider_oauth_transport_error_detail(
            "token exchange 失败",
            "request failed for https://user:pass@example.test/token?secret=value authorization=Bearer upstream-secret",
        );

        assert_eq!(detail, "token exchange 失败");
        assert!(!detail.contains("upstream-secret"));
        assert!(!detail.contains("user:pass"));
    }
}
