//! WorkBuddy（腾讯 CodeBuddy）账号 OAuth 适配器。
//!
//! 上游不是标准 OAuth2：**没有 client_id / PKCE / 回调**，而是服务端签发
//! `state` 的私有设备授权流程：
//!
//! 1. `POST /v2/plugin/auth/state?platform=CLI`（body `{}`）→ `data.{state, authUrl}`；
//! 2. 用户在浏览器打开 `authUrl` 完成登录；
//! 3. `GET /v2/plugin/auth/token?state=<state>` → 未完成时**业务 code ≠ 0**
//!    （HTTP 200），完成时 `data.{accessToken, refreshToken, expiresIn, domain}`；
//! 4. `GET /v2/plugin/login/account?state=<state>`（带 Bearer）→
//!    `data.{uid, enterpriseId, nickname}`。
//!
//! 刷新是独立端点：`POST /v2/plugin/auth/token/refresh`，**无 body**，
//! 凭证走 `X-Refresh-Token` 头（聊天请求里绝不允许出现该头）。
//!
//! 事实来源：开源面板 `linguo2625469/workbuddy2api-panel`
//! （`internal/panel/login.go`、`internal/upstream/client.go`、`headers.go`）。

use crate::core::{
    current_unix_secs, redacted_oauth_error_body_excerpt, OAuthDeviceAuthorization, OAuthError,
    OAuthTokenSet,
};
use crate::network::{OAuthHttpExecutor, OAuthHttpRequest, OAuthHttpResponse};
use crate::provider::{
    ProviderOAuthAccount, ProviderOAuthAdapter, ProviderOAuthCapabilities,
    ProviderOAuthImportInput, ProviderOAuthRequestAuth, ProviderOAuthTokenSet,
    ProviderOAuthTransportContext,
};
use async_trait::async_trait;
use serde_json::{json, Map, Value};
use sha2::{Digest, Sha256};
use std::collections::BTreeMap;

pub const WORKBUDDY_PROVIDER_TYPE: &str = "workbuddy";

/// CN 对话域（同时是设备授权与刷新的宿主域）。
pub const WORKBUDDY_CHAT_BASE_CN: &str = "https://copilot.tencent.com";
/// 国际对话域。
pub const WORKBUDDY_CHAT_BASE_GLOBAL: &str = "https://www.workbuddy.ai";

/// 设备授权第一步**路径**（与下面的完整 URL 同源 ✓）。
///
/// 维护性审计 ⑤（2026-10-17 ✗）：这批端点此前在 oauth 与
/// `aether-provider-transport` **各写一份字面量** ✗（transport 的注释自己都写着
/// 「改上游路径时两处都要改」✗）。现在**本 crate 是唯一来源** ✓：
/// transport 直接重导出这些常量 ✓，下面那条单测把「完整 URL == base + 路径」
/// 钉死 ✓，任何一边改了都会红 ✓。
pub const WORKBUDDY_AUTH_STATE_PATH: &str = "/v2/plugin/auth/state?platform=CLI";
/// 设备授权轮询路径（后面直接拼 `state`）。
pub const WORKBUDDY_AUTH_TOKEN_PATH: &str = "/v2/plugin/auth/token?state=";
/// 账号信息路径（需要 `Authorization: Bearer <accessToken>`）。
pub const WORKBUDDY_LOGIN_ACCOUNT_PATH: &str = "/v2/plugin/login/account?state=";
/// 刷新路径（POST，无 body，凭证在 `X-Refresh-Token`）。
pub const WORKBUDDY_REFRESH_PATH: &str = "/v2/plugin/auth/token/refresh";

/// 设备授权第一步端点（= 上面的 `WORKBUDDY_AUTH_STATE_PATH` 挂在 CN 域上 ✓）。
pub const WORKBUDDY_AUTHORIZE_STATE_URL: &str =
    "https://copilot.tencent.com/v2/plugin/auth/state?platform=CLI";
/// 设备授权轮询前缀（后面直接拼 `state`）。
pub const WORKBUDDY_TOKEN_URL_PREFIX: &str =
    "https://copilot.tencent.com/v2/plugin/auth/token?state=";
/// 账号信息前缀（需要 `Authorization: Bearer <accessToken>`）。
pub const WORKBUDDY_ACCOUNT_URL_PREFIX: &str =
    "https://copilot.tencent.com/v2/plugin/login/account?state=";
/// 刷新端点（POST，无 body，凭证在 `X-Refresh-Token`）。
pub const WORKBUDDY_REFRESH_URL: &str = "https://copilot.tencent.com/v2/plugin/auth/token/refresh";

/// CN 账号的 `Origin` / `Referer` 基础域。
pub const WORKBUDDY_ORIGIN_CN: &str = "https://www.codebuddy.cn";
/// 国际账号的 `Origin` / `Referer` 基础域。
pub const WORKBUDDY_ORIGIN_GLOBAL: &str = "https://www.workbuddy.ai";

/// 设备授权流程使用的 UA（官方 CLI 形态）。
pub const WORKBUDDY_LOGIN_USER_AGENT: &str = "CLI/2.63.2 CodeBuddy/2.63.2";
/// 聊天/刷新出站 UA 的 `WorkBuddy/<ver>` 段。
pub const WORKBUDDY_CLIENT_VERSION: &str = "5.5.4";
/// 聊天/刷新出站 UA 的 `CLI/<ver>` 段。
pub const WORKBUDDY_CLI_VERSION: &str = "2.137.1";

/// 设备授权默认有效期（上游未回 `expiresIn` 时的兜底）。
const DEFAULT_DEVICE_EXPIRES_IN_SECS: u64 = 600;
/// 面板前端 3 秒一次轮询，与之一致。
const DEFAULT_DEVICE_POLL_INTERVAL_SECS: u64 = 3;

/// 域：决定 base_url、Origin/Referer、UA 平台段与 Accept-Language。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum WorkbuddyOAuthRealm {
    Cn,
    Global,
}

impl WorkbuddyOAuthRealm {
    pub fn is_global(self) -> bool {
        matches!(self, Self::Global)
    }

    /// 落库用的小写标识（会话 `region` 字段）。
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Cn => "cn",
            Self::Global => "global",
        }
    }

    fn chat_base(self) -> &'static str {
        match self {
            Self::Cn => WORKBUDDY_CHAT_BASE_CN,
            Self::Global => WORKBUDDY_CHAT_BASE_GLOBAL,
        }
    }

    fn origin(self) -> &'static str {
        match self {
            Self::Cn => WORKBUDDY_ORIGIN_CN,
            Self::Global => WORKBUDDY_ORIGIN_GLOBAL,
        }
    }

    fn accept_language(self) -> &'static str {
        match self {
            Self::Cn => "zh-CN",
            Self::Global => "en-US",
        }
    }

    /// 三段式 UA：CN 平台段 `WorkBuddy`，国际 `WorkBuddy AI`。
    ///
    /// 国际账号送错平台段会触发上游 403 code 11140 风控。
    fn refresh_user_agent(self) -> String {
        let platform = match self {
            Self::Cn => "WorkBuddy",
            Self::Global => "WorkBuddy AI",
        };
        format!(
            "WorkBuddy/{client} {platform}/{client} CLI/{cli}",
            client = WORKBUDDY_CLIENT_VERSION,
            cli = WORKBUDDY_CLI_VERSION,
        )
    }
}

/// 设备授权轮询结果。
#[derive(Debug, Clone, PartialEq)]
pub enum WorkbuddyDevicePollOutcome {
    /// 用户还没在浏览器里完成登录（上游 `code != 0`）。
    Pending,
    /// 拿到凭证（并已补齐 uid 等身份字段）。
    Authorized(Box<ProviderOAuthTokenSet>),
}

/// 一次性解析出的信封：`{code,msg,data}`。
#[derive(Debug, Clone, PartialEq)]
struct WorkbuddyEnvelope {
    status_code: u16,
    code: i64,
    msg: String,
    data: Value,
}

impl WorkbuddyEnvelope {
    fn is_ok(&self) -> bool {
        (200..300).contains(&self.status_code) && self.code == 0
    }

    /// 是否属于「登录尚未完成」：上游用业务 code 表达 pending。
    fn is_pending_login(&self) -> bool {
        !self.is_ok() && self.status_code < 500
    }
}

#[derive(Clone)]
pub struct WorkbuddyProviderOAuthAdapter {
    realm: WorkbuddyOAuthRealm,
    /// 端点覆写：默认按 realm 推导，测试与私有部署可整体替换。
    state_url_override: Option<String>,
    token_url_prefix_override: Option<String>,
    account_url_prefix_override: Option<String>,
    refresh_url_override: Option<String>,
}

impl std::fmt::Debug for WorkbuddyProviderOAuthAdapter {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("WorkbuddyProviderOAuthAdapter")
            .field("realm", &self.realm)
            .finish()
    }
}

impl Default for WorkbuddyProviderOAuthAdapter {
    fn default() -> Self {
        Self {
            realm: WorkbuddyOAuthRealm::Cn,
            state_url_override: None,
            token_url_prefix_override: None,
            account_url_prefix_override: None,
            refresh_url_override: None,
        }
    }
}

impl WorkbuddyProviderOAuthAdapter {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn with_global_realm(mut self) -> Self {
        self.realm = WorkbuddyOAuthRealm::Global;
        self
    }

    pub fn realm(&self) -> WorkbuddyOAuthRealm {
        self.realm
    }

    /// 覆写四个端点（state / token 前缀 / account 前缀 / refresh）。
    ///
    /// 网关用它把「设备授权端点的测试注入」与「私有部署改域名」都收敛到一处；
    /// 生产路径不需要调用。
    pub fn with_endpoint_overrides(
        mut self,
        state_url: impl Into<String>,
        token_url_prefix: impl Into<String>,
        account_url_prefix: impl Into<String>,
        refresh_url: impl Into<String>,
    ) -> Self {
        self.state_url_override = Some(state_url.into());
        self.token_url_prefix_override = Some(token_url_prefix.into());
        self.account_url_prefix_override = Some(account_url_prefix.into());
        self.refresh_url_override = Some(refresh_url.into());
        self
    }

    /// 只覆写刷新端点：管理端「用 refreshToken 换 token」只走刷新，其余端点继续按 realm 推导
    /// （测试注入与私有部署改域名用这个，不必连带改写设备授权端点）。
    pub fn with_refresh_url_override(mut self, refresh_url: impl Into<String>) -> Self {
        self.refresh_url_override = Some(refresh_url.into());
        self
    }

    fn authorize_state_url(&self) -> String {
        self.state_url_override.clone().unwrap_or_else(|| {
            format!(
                "{}/v2/plugin/auth/state?platform=CLI",
                self.realm.chat_base()
            )
        })
    }

    fn token_url_prefix(&self) -> String {
        self.token_url_prefix_override
            .clone()
            .unwrap_or_else(|| format!("{}/v2/plugin/auth/token?state=", self.realm.chat_base()))
    }

    fn account_url_prefix(&self) -> String {
        self.account_url_prefix_override
            .clone()
            .unwrap_or_else(|| format!("{}/v2/plugin/login/account?state=", self.realm.chat_base()))
    }

    fn refresh_url(&self) -> String {
        self.refresh_url_override
            .clone()
            .unwrap_or_else(|| format!("{}/v2/plugin/auth/token/refresh", self.realm.chat_base()))
    }

    /// 设备授权专用头：浏览器指纹 + JSON 协商（面板 `commonHeaders`）。
    fn login_headers(&self) -> BTreeMap<String, String> {
        let origin = self.realm.origin();
        BTreeMap::from([
            ("content-type".to_string(), "application/json".to_string()),
            (
                "accept".to_string(),
                "application/json, text/plain, */*".to_string(),
            ),
            ("x-requested-with".to_string(), "XMLHttpRequest".to_string()),
            ("origin".to_string(), origin.to_string()),
            ("referer".to_string(), format!("{origin}/")),
            (
                "user-agent".to_string(),
                WORKBUDDY_LOGIN_USER_AGENT.to_string(),
            ),
        ])
    }

    /// 第一步：申请授权 URL。返回 `device_code = state`（Aether 的设备会话
    /// 用它轮询），`verification_uri` 即让用户在浏览器打开的 `authUrl`。
    pub async fn start_device_flow(
        &self,
        executor: &dyn OAuthHttpExecutor,
        ctx: &ProviderOAuthTransportContext,
    ) -> Result<OAuthDeviceAuthorization, OAuthError> {
        let response = executor
            .execute(OAuthHttpRequest {
                request_id: "provider-oauth:workbuddy-auth-state".to_string(),
                method: reqwest::Method::POST,
                url: self.authorize_state_url(),
                headers: self.login_headers(),
                content_type: Some("application/json".to_string()),
                json_body: Some(json!({})),
                body_bytes: None,
                network: ctx.network.clone(),
                transport_profile: None,
            })
            .await?;
        let envelope = parse_envelope(&response);
        if !envelope.is_ok() {
            return Err(envelope_error("workbuddy auth state", &envelope, &response));
        }
        let state = non_empty_string_field(&envelope.data, &["state"])
            .ok_or_else(|| OAuthError::invalid_response("workbuddy auth state missing state"))?;
        let auth_url = non_empty_string_field(&envelope.data, &["authUrl", "auth_url"])
            .ok_or_else(|| OAuthError::invalid_response("workbuddy auth state missing authUrl"))?;
        Ok(OAuthDeviceAuthorization {
            device_code: state,
            // 上游没有 user_code：用户看到并打开的就是完整授权链接。
            user_code: String::new(),
            verification_uri: auth_url.clone(),
            verification_uri_complete: auth_url,
            expires_in: DEFAULT_DEVICE_EXPIRES_IN_SECS,
            interval: DEFAULT_DEVICE_POLL_INTERVAL_SECS,
        })
    }

    /// 第二步：轮询 token。`Pending` 表示用户还没登录完（上游业务 code ≠ 0）。
    pub async fn poll_device_token(
        &self,
        executor: &dyn OAuthHttpExecutor,
        ctx: &ProviderOAuthTransportContext,
        state: &str,
    ) -> Result<WorkbuddyDevicePollOutcome, OAuthError> {
        let state = state.trim();
        if state.is_empty() {
            return Err(OAuthError::invalid_request("workbuddy state is required"));
        }
        let response = executor
            .execute(OAuthHttpRequest {
                request_id: "provider-oauth:workbuddy-auth-token".to_string(),
                method: reqwest::Method::GET,
                url: format!("{}{state}", self.token_url_prefix()),
                headers: self.login_headers(),
                content_type: None,
                json_body: None,
                body_bytes: None,
                network: ctx.network.clone(),
                transport_profile: None,
            })
            .await?;
        let envelope = parse_envelope(&response);
        if !envelope.is_ok() {
            if envelope.is_pending_login() {
                return Ok(WorkbuddyDevicePollOutcome::Pending);
            }
            return Err(envelope_error("workbuddy auth token", &envelope, &response));
        }
        let mut token_set = OAuthTokenSet::from_token_payload(envelope.data.clone())
            .ok_or_else(|| OAuthError::invalid_response("workbuddy token missing accessToken"))?;
        if token_set.access_token.trim().is_empty() {
            return Err(OAuthError::invalid_response(
                "workbuddy token missing accessToken",
            ));
        }
        let account = self
            .fetch_account_identity(executor, ctx, state, &token_set.access_token)
            .await?;
        let auth_config = build_auth_config(self.realm, &token_set, &account);
        // 凭证里带上账号域（上游 X-Domain 用），没有则保持空。
        token_set.raw_payload = Some(envelope.data);
        Ok(WorkbuddyDevicePollOutcome::Authorized(Box::new(
            ProviderOAuthTokenSet {
                token_set,
                auth_config,
            },
        )))
    }

    /// 第三步：取 uid / enterpriseId / nickname。
    ///
    /// uid 是后续所有请求头（`X-User-Id` / `X-Machine-ID`）的来源，缺了它
    /// 账号就只能匿名发请求，所以这里把「有 token 但拿不到 uid」当成失败。
    async fn fetch_account_identity(
        &self,
        executor: &dyn OAuthHttpExecutor,
        ctx: &ProviderOAuthTransportContext,
        state: &str,
        access_token: &str,
    ) -> Result<WorkbuddyAccount, OAuthError> {
        let mut headers = self.login_headers();
        headers.insert(
            "authorization".to_string(),
            format!("Bearer {}", access_token.trim()),
        );
        let response = executor
            .execute(OAuthHttpRequest {
                request_id: "provider-oauth:workbuddy-login-account".to_string(),
                method: reqwest::Method::GET,
                url: format!("{}{state}", self.account_url_prefix()),
                headers,
                content_type: None,
                json_body: None,
                body_bytes: None,
                network: ctx.network.clone(),
                transport_profile: None,
            })
            .await?;
        let envelope = parse_envelope(&response);
        if !envelope.is_ok() {
            return Err(envelope_error(
                "workbuddy login account",
                &envelope,
                &response,
            ));
        }
        let uid = non_empty_string_field(&envelope.data, &["uid"])
            .ok_or_else(|| OAuthError::invalid_response("workbuddy login account missing uid"))?;
        // uid 会拼进 key 名/文件名，只放行 [A-Za-z0-9_-]（面板同规则）。
        if !is_valid_workbuddy_uid(&uid) {
            return Err(OAuthError::invalid_response(
                "workbuddy uid contains illegal characters",
            ));
        }
        Ok(WorkbuddyAccount {
            uid,
            enterprise_id: non_empty_string_field(
                &envelope.data,
                &["enterpriseId", "enterprise_id"],
            ),
            nickname: non_empty_string_field(&envelope.data, &["nickname"]),
        })
    }

    /// 刷新：`POST /v2/plugin/auth/token/refresh`，无 body，凭证在
    /// `X-Refresh-Token`（与聊天请求严格分离）。
    ///
    /// 参数看着多，但每一项都是上游要的独立字段（刷新令牌 + 既有 auth_config 里的身份三元组），
    /// 打包成结构体只会在唯一调用点来回拆包，故保留平铺并 allow（与 planner 里几处同款处理）。
    #[allow(clippy::too_many_arguments)]
    async fn refresh_with_token(
        &self,
        executor: &dyn OAuthHttpExecutor,
        ctx: &ProviderOAuthTransportContext,
        refresh_token: &str,
        existing_auth_config: Option<&Value>,
        uid: Option<&str>,
        enterprise_id: Option<&str>,
        domain: Option<&str>,
    ) -> Result<ProviderOAuthTokenSet, OAuthError> {
        let refresh_token = refresh_token.trim();
        if refresh_token.is_empty() {
            return Err(OAuthError::invalid_request(
                "workbuddy refresh_token is required",
            ));
        }
        let origin = self.realm.origin();
        let mut headers = BTreeMap::from([
            ("content-type".to_string(), "application/json".to_string()),
            ("accept".to_string(), "application/json".to_string()),
            ("x-requested-with".to_string(), "XMLHttpRequest".to_string()),
            ("origin".to_string(), origin.to_string()),
            ("referer".to_string(), format!("{origin}/")),
            ("user-agent".to_string(), self.realm.refresh_user_agent()),
            // 官方客户端风控闸门头：所有 API 请求必带。
            ("x-codebuddy-request".to_string(), "1".to_string()),
            (
                "accept-language".to_string(),
                self.realm.accept_language().to_string(),
            ),
            ("x-refresh-token".to_string(), refresh_token.to_string()),
            ("x-auth-refresh-source".to_string(), "plugin".to_string()),
        ]);
        if let Some(uid) = uid.map(str::trim).filter(|value| !value.is_empty()) {
            if let Some(machine_id) = derive_account_stable_id(uid, "machine") {
                headers.insert("x-machine-id".to_string(), machine_id);
            }
            if let Some(session_id) = derive_account_stable_id(uid, "session") {
                headers.insert("x-session-id".to_string(), session_id);
            }
        }
        if let Some(enterprise_id) = enterprise_id
            .map(str::trim)
            .filter(|value| !value.is_empty())
        {
            headers.insert("x-enterprise-id".to_string(), enterprise_id.to_string());
        }

        let response = executor
            .execute(OAuthHttpRequest {
                request_id: "provider-oauth:workbuddy-refresh".to_string(),
                method: reqwest::Method::POST,
                url: self.refresh_url(),
                headers,
                content_type: Some("application/json".to_string()),
                json_body: None,
                body_bytes: None,
                network: ctx.network.clone(),
                transport_profile: None,
            })
            .await?;
        let envelope = parse_envelope(&response);
        if !envelope.is_ok() {
            return Err(envelope_error("workbuddy refresh", &envelope, &response));
        }
        let mut token_set = OAuthTokenSet::from_token_payload(envelope.data.clone())
            .ok_or_else(|| OAuthError::invalid_response("workbuddy refresh missing accessToken"))?;
        // 上游可能不回新的 refresh_token / domain：保留旧值，避免把账号写坏。
        if token_set.refresh_token.is_none() {
            token_set.refresh_token = Some(refresh_token.to_string());
        }
        let account = WorkbuddyAccount {
            uid: uid.unwrap_or_default().trim().to_string(),
            enterprise_id: enterprise_id.map(|value| value.trim().to_string()),
            nickname: existing_auth_config
                .and_then(|config| non_empty_string_field(config, &["nickname"])),
        };
        let mut auth_config = build_auth_config(self.realm, &token_set, &account);
        if let Some(domain) = domain.map(str::trim).filter(|value| !value.is_empty()) {
            if let Some(object) = auth_config.as_object_mut() {
                object.insert("domain".to_string(), json!(domain));
            }
        }
        token_set.raw_payload = Some(envelope.data);
        Ok(ProviderOAuthTokenSet {
            token_set,
            auth_config,
        })
    }

    /// 从 `auth_config` 取 refresh_token（两种命名都认）。
    fn refresh_token_from_auth_config(auth_config: &Value) -> Option<String> {
        non_empty_string_field(auth_config, &["refresh_token", "refreshToken"])
    }

    fn uid_from_auth_config(auth_config: &Value) -> Option<String> {
        non_empty_string_field(auth_config, &["uid"])
    }

    fn enterprise_id_from_auth_config(auth_config: &Value) -> Option<String> {
        non_empty_string_field(auth_config, &["enterprise_id", "enterpriseId"])
    }

    fn domain_from_auth_config(auth_config: &Value) -> Option<String> {
        non_empty_string_field(auth_config, &["domain"])
    }
}

/// 账号身份三元组。
#[derive(Debug, Clone, PartialEq, Eq)]
struct WorkbuddyAccount {
    uid: String,
    enterprise_id: Option<String>,
    nickname: Option<String>,
}

#[async_trait]
impl ProviderOAuthAdapter for WorkbuddyProviderOAuthAdapter {
    fn provider_type(&self) -> &'static str {
        WORKBUDDY_PROVIDER_TYPE
    }

    fn capabilities(&self) -> ProviderOAuthCapabilities {
        ProviderOAuthCapabilities {
            supports_authorization_code: false,
            supports_cookie_authorization: false,
            supports_refresh_token_import: true,
            supports_batch_import: true,
            supports_device_flow: true,
            supports_account_probe: false,
            // 上游刷新会轮换 refreshToken。
            rotates_refresh_token: true,
        }
    }

    /// 导入凭证：支持面板账号文件的两种形态（嵌套 / 扁平）、
    /// 直接粘贴 `accessToken`，以及只给 `refresh_token` 时走一次刷新。
    async fn import_credentials(
        &self,
        executor: &dyn OAuthHttpExecutor,
        ctx: &ProviderOAuthTransportContext,
        input: ProviderOAuthImportInput,
    ) -> Result<ProviderOAuthTokenSet, OAuthError> {
        let raw = input.raw_credentials.clone();
        let nested = raw
            .as_ref()
            .and_then(|value| value.get("auth"))
            .filter(|value| value.is_object());
        let account_object = raw
            .as_ref()
            .and_then(|value| value.get("account"))
            .filter(|value| value.is_object());

        let credential_source = nested.or(raw.as_ref());
        let access_token = credential_source
            .and_then(|value| non_empty_string_field(value, &["accessToken", "access_token"]));
        let refresh_token = credential_source
            .and_then(|value| non_empty_string_field(value, &["refreshToken", "refresh_token"]))
            .or_else(|| {
                input
                    .refresh_token
                    .as_deref()
                    .map(str::trim)
                    .filter(|value| !value.is_empty())
                    .map(ToOwned::to_owned)
            });
        let uid = account_object
            .and_then(|value| non_empty_string_field(value, &["uid"]))
            .or_else(|| {
                credential_source.and_then(|value| non_empty_string_field(value, &["uid"]))
            });
        let enterprise_id = account_object
            .and_then(|value| non_empty_string_field(value, &["enterpriseId", "enterprise_id"]))
            .or_else(|| {
                credential_source.and_then(|value| {
                    non_empty_string_field(value, &["enterpriseId", "enterprise_id"])
                })
            });
        let nickname = account_object
            .and_then(|value| non_empty_string_field(value, &["nickname"]))
            .or_else(|| {
                credential_source.and_then(|value| non_empty_string_field(value, &["nickname"]))
            });
        let domain = credential_source
            .and_then(|value| non_empty_string_field(value, &["domain"]))
            .or_else(|| {
                raw.as_ref()
                    .and_then(|value| non_empty_string_field(value, &["domain"]))
            });

        if access_token.is_none() {
            if let Some(refresh_token) = refresh_token {
                return self
                    .refresh_with_token(
                        executor,
                        ctx,
                        &refresh_token,
                        raw.as_ref(),
                        uid.as_deref(),
                        enterprise_id.as_deref(),
                        domain.as_deref(),
                    )
                    .await;
            }
            return Err(OAuthError::invalid_request(
                "workbuddy credentials require accessToken or refreshToken",
            ));
        }
        let mut payload = Map::new();
        payload.insert("accessToken".to_string(), json!(access_token));
        if let Some(refresh_token) = refresh_token {
            payload.insert("refreshToken".to_string(), json!(refresh_token));
        }
        if let Some(expires_at) =
            credential_source.and_then(|value| json_u64(value, &["expiresAt", "expires_at"]))
        {
            // 面板导入工具给的是**毫秒**，10 位以上按毫秒归一成秒。
            let expires_at = if expires_at > 100_000_000_000 {
                expires_at / 1000
            } else {
                expires_at
            };
            payload.insert("expiresAt".to_string(), json!(expires_at));
        }
        if let Some(domain) = domain {
            payload.insert("domain".to_string(), json!(domain));
        }
        let token_set = OAuthTokenSet::from_token_payload(Value::Object(payload))
            .ok_or_else(|| OAuthError::invalid_response("workbuddy accessToken is required"))?;
        let account = WorkbuddyAccount {
            uid: uid.unwrap_or_default(),
            enterprise_id,
            nickname,
        };
        let auth_config = build_auth_config(self.realm, &token_set, &account);
        Ok(ProviderOAuthTokenSet {
            token_set,
            auth_config,
        })
    }

    async fn refresh(
        &self,
        executor: &dyn OAuthHttpExecutor,
        ctx: &ProviderOAuthTransportContext,
        account: &ProviderOAuthAccount,
    ) -> Result<ProviderOAuthTokenSet, OAuthError> {
        let auth_config = &account.auth_config;
        let refresh_token = Self::refresh_token_from_auth_config(auth_config).ok_or_else(|| {
            OAuthError::invalid_request("workbuddy refresh_token is required; re-login required")
        })?;
        let uid = Self::uid_from_auth_config(auth_config);
        let enterprise_id = Self::enterprise_id_from_auth_config(auth_config);
        let domain = Self::domain_from_auth_config(auth_config);
        self.refresh_with_token(
            executor,
            ctx,
            &refresh_token,
            Some(auth_config),
            uid.as_deref(),
            enterprise_id.as_deref(),
            domain.as_deref(),
        )
        .await
    }

    fn resolve_request_auth(
        &self,
        account: &ProviderOAuthAccount,
    ) -> Result<ProviderOAuthRequestAuth, OAuthError> {
        // 上游就是 `Authorization: Bearer <accessToken>`。
        Ok(account.request_bearer_auth())
    }

    fn account_fingerprint(&self, account: &ProviderOAuthAccount) -> Option<String> {
        Self::uid_from_auth_config(&account.auth_config)
            .or_else(|| non_empty_string_field(&account.auth_config, &["sub"]))
    }
}

/// 组 auth_config：provider-oauth 写入 key 的元数据。
fn build_auth_config(
    realm: WorkbuddyOAuthRealm,
    token_set: &OAuthTokenSet,
    account: &WorkbuddyAccount,
) -> Value {
    let mut config = Map::new();
    config.insert("provider_type".to_string(), json!(WORKBUDDY_PROVIDER_TYPE));
    config.insert("auth_method".to_string(), json!("oauth"));
    config.insert("using_api".to_string(), json!(false));
    config.insert(
        "realm".to_string(),
        json!(if realm.is_global() { "global" } else { "cn" }),
    );
    config.insert("updated_at".to_string(), json!(current_unix_secs()));
    let uid = account.uid.trim();
    if !uid.is_empty() {
        config.insert("uid".to_string(), json!(uid));
    }
    if let Some(enterprise_id) = account
        .enterprise_id
        .as_deref()
        .map(str::trim)
        .filter(|value| !value.is_empty())
    {
        config.insert("enterprise_id".to_string(), json!(enterprise_id));
    }
    if let Some(nickname) = account
        .nickname
        .as_deref()
        .map(str::trim)
        .filter(|value| !value.is_empty())
    {
        config.insert("nickname".to_string(), json!(nickname));
    }
    if let Some(domain) = token_set
        .raw_payload
        .as_ref()
        .and_then(|payload| non_empty_string_field(payload, &["domain"]))
    {
        config.insert("domain".to_string(), json!(domain));
    }
    if let Some(refresh_token) = token_set.refresh_token.as_deref() {
        config.insert("refresh_token".to_string(), json!(refresh_token));
    }
    Value::Object(config)
}

/// 解析 `{code,msg,data}` 信封。
///
/// 非 JSON / 非法 JSON 一律降级成 `code = -1`（不当成成功），
/// 避免把 HTML 错误页误判成凭证。
fn parse_envelope(response: &OAuthHttpResponse) -> WorkbuddyEnvelope {
    let payload = response
        .json_body
        .clone()
        .or_else(|| serde_json::from_str::<Value>(&response.body_text).ok());
    let Some(payload) = payload.filter(Value::is_object) else {
        return WorkbuddyEnvelope {
            status_code: response.status_code,
            code: -1,
            msg: String::new(),
            data: Value::Null,
        };
    };
    WorkbuddyEnvelope {
        status_code: response.status_code,
        code: payload.get("code").and_then(Value::as_i64).unwrap_or(0),
        msg: non_empty_string_field(&payload, &["msg", "message"]).unwrap_or_default(),
        data: payload.get("data").cloned().unwrap_or(Value::Null),
    }
}

/// 把失败信封转成 `OAuthError`：HTTP 层给状态码，业务层给 code/msg。
fn envelope_error(
    operation: &str,
    envelope: &WorkbuddyEnvelope,
    response: &OAuthHttpResponse,
) -> OAuthError {
    if !(200..300).contains(&envelope.status_code) {
        return OAuthError::HttpStatus {
            status_code: envelope.status_code,
            body_excerpt: redacted_oauth_error_body_excerpt(&response.body_text),
        };
    }
    OAuthError::invalid_response(format!(
        "{operation} failed: code={} msg={}",
        envelope.code,
        envelope.msg.trim()
    ))
}

fn non_empty_string_field(payload: &Value, keys: &[&str]) -> Option<String> {
    let object = payload.as_object()?;
    keys.iter().find_map(|key| {
        object
            .get(*key)
            .and_then(Value::as_str)
            .map(str::trim)
            .filter(|value| !value.is_empty())
            .map(ToOwned::to_owned)
    })
}

fn json_u64(payload: &Value, keys: &[&str]) -> Option<u64> {
    keys.iter().find_map(|key| match payload.get(*key)? {
        Value::Number(number) => number.as_u64(),
        Value::String(string) => string.trim().parse::<u64>().ok(),
        _ => None,
    })
}

/// uid 会进入 key 名与日志，只放行 `[A-Za-z0-9_-]` 且长度 ≤ 64。
fn is_valid_workbuddy_uid(uid: &str) -> bool {
    let uid = uid.trim();
    !uid.is_empty()
        && uid.len() <= 64
        && uid
            .chars()
            .all(|ch| ch.is_ascii_alphanumeric() || ch == '-' || ch == '_')
}

/// `sha256("wb2a:" + purpose + ":" + uid)` 前 18 字节的 hex。
///
/// 与供应商传输层 `derive_workbuddy_account_stable_id` 同一算法（那边用于
/// 聊天出站头，这边用于刷新出站头），两处必须一致。
fn derive_account_stable_id(uid: &str, purpose: &str) -> Option<String> {
    let uid = uid.trim();
    if uid.is_empty() {
        return None;
    }
    let mut hasher = Sha256::new();
    hasher.update(b"wb2a:");
    hasher.update(purpose.as_bytes());
    hasher.update(b":");
    hasher.update(uid.as_bytes());
    let digest = hasher.finalize();
    let mut out = String::with_capacity(36);
    for byte in digest.iter().take(18) {
        out.push_str(&format!("{byte:02x}"));
    }
    Some(out)
}

#[cfg(test)]
mod protocol_constants_tests {
    use super::{
        WORKBUDDY_ACCOUNT_URL_PREFIX, WORKBUDDY_AUTHORIZE_STATE_URL, WORKBUDDY_AUTH_STATE_PATH,
        WORKBUDDY_AUTH_TOKEN_PATH, WORKBUDDY_CHAT_BASE_CN, WORKBUDDY_LOGIN_ACCOUNT_PATH,
        WORKBUDDY_REFRESH_PATH, WORKBUDDY_REFRESH_URL, WORKBUDDY_TOKEN_URL_PREFIX,
    };

    /// 维护性审计 ⑤（2026-10-17）漂移钉子 ✓：这批端点此前在 **oauth 与
    /// `aether-provider-transport` 各写一份字面量** ✗（transport 的旧注释写着
    /// 「改上游路径时两处都要改」✗）。现在路径是唯一来源 ✓，完整 URL 必须
    /// **恰好等于 base + 路径** ✓ —— 谁改了其中一半，这条测试立刻红 ✓。
    #[test]
    fn composed_endpoint_urls_match_their_base_plus_path() {
        assert_eq!(
            WORKBUDDY_AUTHORIZE_STATE_URL.to_string(),
            format!("{WORKBUDDY_CHAT_BASE_CN}{WORKBUDDY_AUTH_STATE_PATH}")
        );
        assert_eq!(
            WORKBUDDY_TOKEN_URL_PREFIX.to_string(),
            format!("{WORKBUDDY_CHAT_BASE_CN}{WORKBUDDY_AUTH_TOKEN_PATH}")
        );
        assert_eq!(
            WORKBUDDY_ACCOUNT_URL_PREFIX.to_string(),
            format!("{WORKBUDDY_CHAT_BASE_CN}{WORKBUDDY_LOGIN_ACCOUNT_PATH}")
        );
        assert_eq!(
            WORKBUDDY_REFRESH_URL.to_string(),
            format!("{WORKBUDDY_CHAT_BASE_CN}{WORKBUDDY_REFRESH_PATH}")
        );
    }
}

#[cfg(test)]
mod tests {
    use super::{
        derive_account_stable_id, is_valid_workbuddy_uid, WorkbuddyDevicePollOutcome,
        WorkbuddyProviderOAuthAdapter, WORKBUDDY_PROVIDER_TYPE,
    };
    use crate::network::{OAuthHttpExecutor, OAuthHttpRequest, OAuthHttpResponse};
    use crate::provider::{
        ProviderOAuthAccount, ProviderOAuthAdapter, ProviderOAuthImportInput,
        ProviderOAuthTransportContext,
    };
    use async_trait::async_trait;
    use serde_json::{json, Value};
    use std::collections::BTreeMap;
    use std::sync::{Arc, Mutex};

    /// 依次返回脚本化响应，并记录每一次请求。
    #[derive(Clone)]
    struct ScriptedExecutor {
        seen: Arc<Mutex<Vec<OAuthHttpRequest>>>,
        responses: Arc<Mutex<Vec<OAuthHttpResponse>>>,
    }

    impl ScriptedExecutor {
        fn new(responses: Vec<OAuthHttpResponse>) -> Self {
            Self {
                seen: Arc::new(Mutex::new(Vec::new())),
                responses: Arc::new(Mutex::new(responses)),
            }
        }

        fn seen(&self) -> Vec<OAuthHttpRequest> {
            self.seen.lock().expect("lock").clone()
        }
    }

    #[async_trait]
    impl OAuthHttpExecutor for ScriptedExecutor {
        async fn execute(
            &self,
            request: OAuthHttpRequest,
        ) -> Result<OAuthHttpResponse, crate::core::OAuthError> {
            self.seen.lock().expect("lock").push(request);
            let mut responses = self.responses.lock().expect("lock");
            if responses.is_empty() {
                return Err(crate::core::OAuthError::transport("no scripted response"));
            }
            Ok(responses.remove(0))
        }
    }

    fn json_response(status_code: u16, payload: Value) -> OAuthHttpResponse {
        OAuthHttpResponse {
            status_code,
            body_text: payload.to_string(),
            json_body: Some(payload),
        }
    }

    fn transport_context() -> ProviderOAuthTransportContext {
        ProviderOAuthTransportContext {
            provider_id: "provider-workbuddy".to_string(),
            provider_type: WORKBUDDY_PROVIDER_TYPE.to_string(),
            endpoint_id: None,
            key_id: None,
            auth_type: Some("oauth".to_string()),
            decrypted_api_key: None,
            decrypted_auth_config: None,
            provider_config: None,
            endpoint_config: None,
            key_config: None,
            network: crate::network::OAuthNetworkContext::provider_operation(None),
        }
    }

    #[tokio::test]
    async fn device_flow_returns_the_authorization_url_and_polls_pending() {
        let adapter = WorkbuddyProviderOAuthAdapter::default();
        let executor = ScriptedExecutor::new(vec![
            json_response(
                200,
                json!({"code": 0, "msg": "ok", "data": {"state": "state-1", "authUrl": "https://www.codebuddy.cn/login?x=1"}}),
            ),
            json_response(200, json!({"code": 10001, "msg": "login ing"})),
        ]);

        let authorization = adapter
            .start_device_flow(&executor, &transport_context())
            .await
            .expect("device flow should start");
        assert_eq!(authorization.device_code, "state-1");
        assert_eq!(
            authorization.verification_uri,
            "https://www.codebuddy.cn/login?x=1"
        );
        assert_eq!(authorization.interval, 3);

        let outcome = adapter
            .poll_device_token(&executor, &transport_context(), "state-1")
            .await
            .expect("poll should succeed");
        assert_eq!(outcome, WorkbuddyDevicePollOutcome::Pending);

        let seen = executor.seen();
        assert_eq!(seen[0].method, reqwest::Method::POST);
        assert_eq!(
            seen[0].headers.get("x-requested-with").map(String::as_str),
            Some("XMLHttpRequest")
        );
        assert_eq!(
            seen[0].headers.get("origin").map(String::as_str),
            Some("https://www.codebuddy.cn")
        );
        assert_eq!(
            seen[1].url,
            "https://copilot.tencent.com/v2/plugin/auth/token?state=state-1"
        );
    }

    #[tokio::test]
    async fn device_poll_authorizes_and_enriches_identity() {
        let adapter = WorkbuddyProviderOAuthAdapter::default();
        let executor = ScriptedExecutor::new(vec![
            json_response(
                200,
                json!({"code": 0, "data": {
                    "accessToken": "access-1",
                    "refreshToken": "refresh-1",
                    "expiresIn": 5184000,
                    "domain": "www.codebuddy.cn"
                }}),
            ),
            json_response(
                200,
                json!({"code": 0, "data": {"uid": "uid-1", "enterpriseId": "ent-1", "nickname": "Buddy"}}),
            ),
        ]);

        let outcome = adapter
            .poll_device_token(&executor, &transport_context(), "state-1")
            .await
            .expect("poll should succeed");
        let WorkbuddyDevicePollOutcome::Authorized(result) = outcome else {
            panic!("expected authorized outcome");
        };
        assert_eq!(result.token_set.access_token, "access-1");
        assert_eq!(result.token_set.refresh_token.as_deref(), Some("refresh-1"));
        assert!(result.token_set.expires_at_unix_secs.is_some());
        assert_eq!(result.auth_config["uid"], json!("uid-1"));
        assert_eq!(result.auth_config["enterprise_id"], json!("ent-1"));
        assert_eq!(result.auth_config["nickname"], json!("Buddy"));
        assert_eq!(result.auth_config["domain"], json!("www.codebuddy.cn"));
        assert_eq!(result.auth_config["realm"], json!("cn"));
        assert_eq!(result.auth_config["auth_method"], json!("oauth"));
        assert_eq!(result.auth_config["using_api"], json!(false));

        let seen = executor.seen();
        assert_eq!(
            seen[1].headers.get("authorization").map(String::as_str),
            Some("Bearer access-1")
        );
    }

    #[tokio::test]
    async fn device_poll_requires_uid_after_token_issue() {
        let adapter = WorkbuddyProviderOAuthAdapter::default();
        let executor = ScriptedExecutor::new(vec![
            json_response(
                200,
                json!({"code": 0, "data": {"accessToken": "access-1", "refreshToken": "refresh-1"}}),
            ),
            json_response(200, json!({"code": 0, "data": {"nickname": "no-uid"}})),
        ]);
        let error = adapter
            .poll_device_token(&executor, &transport_context(), "state-1")
            .await
            .expect_err("missing uid must fail");
        assert!(format!("{error:?}").contains("uid") || format!("{error}").contains("uid"));
    }

    #[tokio::test]
    async fn refresh_sends_the_refresh_token_header_and_keeps_old_refresh_token() {
        let adapter = WorkbuddyProviderOAuthAdapter::default();
        let executor = ScriptedExecutor::new(vec![json_response(
            200,
            json!({"code": 0, "data": {"accessToken": "access-2", "expiresIn": 3600}}),
        )]);
        let account = ProviderOAuthAccount {
            provider_type: WORKBUDDY_PROVIDER_TYPE.to_string(),
            access_token: "access-1".to_string(),
            auth_config: json!({
                "uid": "uid-1",
                "enterprise_id": "ent-1",
                "domain": "www.codebuddy.cn",
                "refresh_token": "refresh-1"
            }),
            expires_at_unix_secs: None,
            identity: BTreeMap::new(),
        };

        let refreshed = adapter
            .refresh(&executor, &transport_context(), &account)
            .await
            .expect("refresh should succeed");
        assert_eq!(refreshed.token_set.access_token, "access-2");
        // 上游没回新 refreshToken，必须保留旧值。
        assert_eq!(
            refreshed.token_set.refresh_token.as_deref(),
            Some("refresh-1")
        );
        assert_eq!(refreshed.auth_config["uid"], json!("uid-1"));
        assert_eq!(refreshed.auth_config["domain"], json!("www.codebuddy.cn"));

        let seen = executor.seen();
        assert_eq!(seen[0].method, reqwest::Method::POST);
        assert_eq!(
            seen[0].url,
            "https://copilot.tencent.com/v2/plugin/auth/token/refresh"
        );
        assert_eq!(
            seen[0].headers.get("x-refresh-token").map(String::as_str),
            Some("refresh-1")
        );
        assert_eq!(
            seen[0]
                .headers
                .get("x-auth-refresh-source")
                .map(String::as_str),
            Some("plugin")
        );
        assert_eq!(
            seen[0].headers.get("x-enterprise-id").map(String::as_str),
            Some("ent-1")
        );
        assert_eq!(
            seen[0]
                .headers
                .get("x-codebuddy-request")
                .map(String::as_str),
            Some("1")
        );
        assert_eq!(
            seen[0].headers.get("user-agent").map(String::as_str),
            Some("WorkBuddy/5.5.4 WorkBuddy/5.5.4 CLI/2.137.1")
        );
        assert!(seen[0].json_body.is_none(), "refresh 必须无 body");
        assert!(seen[0].body_bytes.is_none());
    }

    #[tokio::test]
    async fn refresh_without_refresh_token_is_rejected() {
        let adapter = WorkbuddyProviderOAuthAdapter::default();
        let executor = ScriptedExecutor::new(vec![]);
        let account = ProviderOAuthAccount {
            provider_type: WORKBUDDY_PROVIDER_TYPE.to_string(),
            access_token: "access-1".to_string(),
            auth_config: json!({"uid": "uid-1"}),
            expires_at_unix_secs: None,
            identity: BTreeMap::new(),
        };
        assert!(adapter
            .refresh(&executor, &transport_context(), &account)
            .await
            .is_err());
        assert!(executor.seen().is_empty(), "不应发出请求");
    }

    #[tokio::test]
    async fn imports_flat_and_nested_panel_credential_files() {
        let adapter = WorkbuddyProviderOAuthAdapter::default();
        let executor = ScriptedExecutor::new(vec![]);

        let flat = adapter
            .import_credentials(
                &executor,
                &transport_context(),
                ProviderOAuthImportInput {
                    provider_type: WORKBUDDY_PROVIDER_TYPE.to_string(),
                    name: None,
                    refresh_token: None,
                    raw_credentials: Some(json!({
                        "accessToken": "access-flat",
                        "refreshToken": "refresh-flat",
                        "expiresAt": 1_800_000_000_000u64,
                        "domain": "www.codebuddy.cn",
                        "uid": "uid-flat"
                    })),
                    network: crate::network::OAuthNetworkContext::provider_operation(None),
                },
            )
            .await
            .expect("flat import should succeed");
        assert_eq!(flat.token_set.access_token, "access-flat");
        assert_eq!(flat.auth_config["uid"], json!("uid-flat"));
        // 毫秒时间戳必须归一成秒，否则会被当成 5 万年后的过期时间。
        assert_eq!(flat.token_set.expires_at_unix_secs, Some(1_800_000_000u64));

        let nested = adapter
            .import_credentials(
                &executor,
                &transport_context(),
                ProviderOAuthImportInput {
                    provider_type: WORKBUDDY_PROVIDER_TYPE.to_string(),
                    name: None,
                    refresh_token: None,
                    raw_credentials: Some(json!({
                        "auth": {
                            "accessToken": "access-nested",
                            "refreshToken": "refresh-nested",
                            "domain": "www.codebuddy.cn",
                            "realm": "cn"
                        },
                        "account": {
                            "uid": "uid-nested",
                            "enterpriseId": "ent-nested",
                            "nickname": "Nested"
                        }
                    })),
                    network: crate::network::OAuthNetworkContext::provider_operation(None),
                },
            )
            .await
            .expect("nested import should succeed");
        assert_eq!(nested.token_set.access_token, "access-nested");
        assert_eq!(nested.auth_config["uid"], json!("uid-nested"));
        assert_eq!(nested.auth_config["enterprise_id"], json!("ent-nested"));
        assert_eq!(nested.auth_config["nickname"], json!("Nested"));
        assert!(executor.seen().is_empty(), "纯导入不应发请求");
    }

    #[tokio::test]
    async fn import_with_only_refresh_token_triggers_a_refresh() {
        let adapter = WorkbuddyProviderOAuthAdapter::default();
        let executor = ScriptedExecutor::new(vec![json_response(
            200,
            json!({"code": 0, "data": {"accessToken": "access-3", "refreshToken": "refresh-3"}}),
        )]);
        let imported = adapter
            .import_credentials(
                &executor,
                &transport_context(),
                ProviderOAuthImportInput {
                    provider_type: WORKBUDDY_PROVIDER_TYPE.to_string(),
                    name: None,
                    refresh_token: Some("refresh-1".to_string()),
                    raw_credentials: Some(json!({"uid": "uid-1"})),
                    network: crate::network::OAuthNetworkContext::provider_operation(None),
                },
            )
            .await
            .expect("refresh import should succeed");
        assert_eq!(imported.token_set.access_token, "access-3");
        assert_eq!(imported.auth_config["uid"], json!("uid-1"));
        assert_eq!(executor.seen().len(), 1);
    }

    #[tokio::test]
    async fn resolve_request_auth_is_bearer() {
        let adapter = WorkbuddyProviderOAuthAdapter::default();
        let account = ProviderOAuthAccount {
            provider_type: WORKBUDDY_PROVIDER_TYPE.to_string(),
            access_token: "access-1".to_string(),
            auth_config: json!({"uid": "uid-1"}),
            expires_at_unix_secs: None,
            identity: BTreeMap::new(),
        };
        let auth = adapter
            .resolve_request_auth(&account)
            .expect("bearer auth should resolve");
        assert!(!format!("{auth:?}").contains("access-1"), "不应泄漏 token");
        assert_eq!(
            adapter.account_fingerprint(&account).as_deref(),
            Some("uid-1")
        );
    }

    #[test]
    fn stable_id_and_uid_validation_match_the_panel_rules() {
        let machine = derive_account_stable_id("uid-1", "machine").expect("machine id");
        assert_eq!(machine.len(), 36);
        assert_eq!(
            machine,
            derive_account_stable_id("uid-1", "machine").expect("stable")
        );
        assert_ne!(
            machine,
            derive_account_stable_id("uid-1", "session").expect("session differs")
        );
        assert!(derive_account_stable_id(" ", "machine").is_none());

        assert!(is_valid_workbuddy_uid("2f2a-91_b"));
        assert!(!is_valid_workbuddy_uid("../evil"));
        assert!(!is_valid_workbuddy_uid(""));
        assert!(!is_valid_workbuddy_uid(&"x".repeat(65)));
    }

    #[tokio::test]
    async fn global_realm_switches_base_url_origin_and_user_agent() {
        let adapter = WorkbuddyProviderOAuthAdapter::default().with_global_realm();
        let executor = ScriptedExecutor::new(vec![json_response(
            200,
            json!({"code": 0, "data": {"state": "state-g", "authUrl": "https://www.workbuddy.ai/login"}}),
        )]);
        adapter
            .start_device_flow(&executor, &transport_context())
            .await
            .expect("global device flow should start");
        let seen = executor.seen();
        assert_eq!(
            seen[0].url,
            "https://www.workbuddy.ai/v2/plugin/auth/state?platform=CLI"
        );
        assert_eq!(
            seen[0].headers.get("origin").map(String::as_str),
            Some("https://www.workbuddy.ai")
        );
    }
}
