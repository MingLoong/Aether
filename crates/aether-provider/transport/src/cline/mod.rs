//! Cline 官方上游（`api.cline.bot`）的一等接入。
//!
//! 与其它 fixed provider 的差别，全部来自对上游的实测（2026-10-12，见
//! `handoff/docs/PLAN-cline-provider-type.md` §7.5）：
//!
//! 1. **鉴权只有 Bearer**：凭据是 Cline 侧签发的 `sk_…`（67 字符）或 OAuth
//!    账号换来的 token，无第三种形状。故策略取 `OAuthOrConfiguredBearer`：
//!    同一种供应商既能放"贴一把 key"，也能放"OAuth 登录"。
//! 2. **有一个"产品面"闸门头**：不带 `x-client-type` 会被上游 403
//!    （*only available via Cline product surfaces*）；带上即 200。
//!    因此指纹头不能由运营者手配，必须由本模块固定下发。
//! 3. **`max_tokens` 有隐式下限**：给得过小（实测 16）时上游返回 500
//!    `{"error":"empty response content"}` —— 推理把预算吃光、正文为空。
//!    故请求体必须做下限兜底，不能纯透传。
//!
//! 上游本身是 OpenAI 兼容的 `/chat/completions`，所以走「本地 OpenAI 直通」，
//! 不需要像 kiro 那样自带 envelope 与格式转换器。

mod headers;
mod refresh;
mod request;
mod url;

use std::collections::BTreeMap;

use crate::provider_types::{
    ProviderApiFormatInheritance, ProviderLocalEmbeddingSupport, ProviderRuntimePolicy,
};
use crate::snapshot::GatewayProviderTransportSnapshot;

pub const PROVIDER_TYPE: &str = "cline";

/// Cline 的运行策略。
///
/// - `fixed_provider: true`：上游地址锁死（模板给端点，前端隐藏手填表单）。
/// - `api_format_inheritance: OAuthOrConfiguredBearer`：两种凭据形状共用一种类型
///   （与 `kiro` 同款）。
/// - 两个 local transport 都开：上游说 OpenAI，Aether 自己就能把 claude / gemini
///   客户端转过来，无需 provider 专属转换器。
pub const RUNTIME_POLICY: ProviderRuntimePolicy = ProviderRuntimePolicy {
    fixed_provider: true,
    api_format_inheritance: ProviderApiFormatInheritance::OAuthOrConfiguredBearer,
    enable_format_conversion_by_default: true,
    allow_auth_channel_mismatch_by_default: true,
    oauth_is_bearer_like: true,
    supports_model_fetch: true,
    supports_local_openai_chat_transport: true,
    supports_local_same_format_transport: true,
    local_embedding_support: ProviderLocalEmbeddingSupport::None,
    force_no_retry: false,
    stop_failover_on_error: false,
    ignore_key_health_exclusion: false,
    skip_active_probe: false,
};

pub use headers::{
    apply_cline_identity_headers, build_cline_identity_headers, CLINE_CLIENT_TYPE,
    CLINE_CLIENT_TYPE_HEADER, CLINE_CLIENT_VERSION, CLINE_CORE_VERSION, CLINE_IDENTITY_HEADERS,
    CLINE_PLATFORM, CLINE_PLATFORM_VERSION, CLINE_TASK_ID_HEADER, CLINE_USER_AGENT,
};
pub use refresh::ClineOAuthRefreshAdapter;
pub use request::{
    cline_openai_chat_body_rules, CLINE_DEFAULT_MAX_TOKENS, CLINE_MIN_UPSTREAM_MAX_TOKENS,
};
pub use url::{
    CLINE_API_BASE_URL, CLINE_BASE_URL, CLINE_CHAT_CUSTOM_PATH, CLINE_RECOMMENDED_MODELS_URL,
};

pub fn is_cline_provider_transport(transport: &GatewayProviderTransportSnapshot) -> bool {
    transport
        .provider
        .provider_type
        .trim()
        .eq_ignore_ascii_case(PROVIDER_TYPE)
}

/// 账号模式（OAuth）密钥的本地鉴权解析是否可行。
///
/// Cline 的两种凭据形状最终都是「把 key 行里存的值原样作为 Bearer 下发」：
/// - Key 模式（sk_…）走普通 api_key 路径，不经过这里；
/// - 账号模式落库的 `access_token` 本来就是**可直接下发**的 `workos:<cline token>`
///   （前缀在适配器里已贴好，见 aether-oauth 的 cline 适配器），
///   所以这里跟 windsurf 一样：值非空非占位即可。
pub fn supports_local_cline_request_auth_resolution(
    transport: &GatewayProviderTransportSnapshot,
) -> bool {
    resolve_local_cline_request_auth(transport).is_some()
}

/// 解析 cline 密钥的请求鉴权头：`("authorization", "Bearer <存的值>")`。
pub fn resolve_local_cline_request_auth(
    transport: &GatewayProviderTransportSnapshot,
) -> Option<(String, String)> {
    if !is_cline_provider_transport(transport) {
        return None;
    }
    let auth_type = transport.key.auth_type.trim().to_ascii_lowercase();
    if !matches!(auth_type.as_str(), "oauth" | "api_key" | "bearer") {
        return None;
    }
    let secret = transport.key.decrypted_api_key.trim();
    if secret.is_empty() || secret == "__placeholder__" {
        return None;
    }
    Some(("authorization".to_string(), format!("Bearer {secret}")))
}

/// 上游头构建的统一钩子（与 `xai` / `opencode` 同名同形状）。
///
/// 在**所有** provider 共用的头构建函数里被调用，因此新增 cline 不需要在网关的
/// 每个 planner 分支里插桩 —— 指纹头是 transport 层的协议事实，不是 planner 的策略。
pub fn insert_cline_request_headers_if_needed(
    transport: &GatewayProviderTransportSnapshot,
    headers: &mut BTreeMap<String, String>,
) {
    if !is_cline_provider_transport(transport) {
        return;
    }
    apply_cline_identity_headers(headers);
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn runtime_policy_matches_the_dual_credential_design() {
        // 先绑到局部变量再断言：直接断言 `RUNTIME_POLICY.<field>`（常量字段）会被 clippy 的
        // `assertions_on_constants` 拦下，而 CI 是 `-D warnings`。
        let policy = RUNTIME_POLICY;
        assert_eq!(
            policy.api_format_inheritance,
            ProviderApiFormatInheritance::OAuthOrConfiguredBearer
        );
        let shape = (
            policy.fixed_provider,
            policy.supports_local_openai_chat_transport,
            policy.supports_local_same_format_transport,
            policy.supports_model_fetch,
            policy.enable_format_conversion_by_default,
        );
        assert_eq!(shape, (true, true, true, true, true));
    }

    #[test]
    fn identity_headers_carry_the_product_surface_gate() {
        let headers = build_cline_identity_headers();
        assert_eq!(
            headers.get(CLINE_CLIENT_TYPE_HEADER).map(String::as_str),
            Some(CLINE_CLIENT_TYPE)
        );
        assert_eq!(
            headers.get("user-agent").map(String::as_str),
            Some(CLINE_USER_AGENT)
        );
        assert_eq!(
            headers.get("http-referer").map(String::as_str),
            Some("https://cline.bot")
        );
    }

    #[test]
    fn base_url_keeps_the_upstream_api_prefix_in_the_custom_path() {
        assert!(CLINE_BASE_URL.ends_with('/'));
        assert!(CLINE_CHAT_CUSTOM_PATH.starts_with('/'));
        assert_eq!(
            format!(
                "{}{}",
                CLINE_BASE_URL.trim_end_matches('/'),
                CLINE_CHAT_CUSTOM_PATH
            ),
            "https://api.cline.bot/api/v1/chat/completions"
        );
        assert_eq!(
            format!("{}/chat/completions", CLINE_API_BASE_URL),
            "https://api.cline.bot/api/v1/chat/completions"
        );
    }
}
