//! Cline 账号模式：WorkOS 设备码登录 → Cline token 对（`/auth/register`），
//! 之后用 Cline 的 `/auth/refresh` 续期，被拒时走 WorkOS `authenticate` 自愈。
//!
//! 契约来源：`luawei1/cline2api` v1.6.5 的实测实现（快照在 `handoff/cline2api-recon/auth.go`）。
//! 有三条语义是「照抄，别顺手优化掉」的：
//!
//! 1. **只有 400/401/403 才算被拒**。5xx、超时、DNS 失败都是暂时的；把它们当成失效，
//!    一次网络抖动就会把整个账号池标成 expired（参考实现专门为这事写了 `refreshRejectedError`）。
//! 2. **Cline 的 refreshToken 就是 WorkOS 的 refreshToken**（`/auth/register` 只是换皮），
//!    所以"自愈"不需要用户重新授权：拿同一把 token 走 WorkOS `authenticate` 换新的一对，
//!    再 `register` 一次即可。
//! 3. **聊天请求的鉴权头是 `Authorization: Bearer workos:<clineAccessToken>`**，
//!    `workos:` 是字面量前缀，不是 scheme 参数。
//!
//! 设备码与 `/auth/register`、`/auth/refresh` 三个调用都**不带** IDE 指纹头（参考实现如此，
//! 实测可用）；指纹头只加在聊天请求上，那是传输层的事。

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
use url::form_urlencoded;

pub const CLINE_PROVIDER_TYPE: &str = "cline";
/// WorkOS 的公开 client id（参考实现硬编码的同一个值，不是账号专属机密）。
pub const CLINE_WORKOS_CLIENT_ID: &str = "client_01K3A541FN8TA3EPPHTD2325AR";
pub const CLINE_WORKOS_DEVICE_URL: &str = "https://api.workos.com/user_management/authorize/device";
pub const CLINE_WORKOS_AUTHENTICATE_URL: &str =
    "https://api.workos.com/user_management/authenticate";
pub const CLINE_API_BASE_URL: &str = "https://api.cline.bot/api/v1";
pub const CLINE_REGISTER_PATH: &str = "/auth/register";
pub const CLINE_REFRESH_PATH: &str = "/auth/refresh";
pub const CLINE_DEVICE_CODE_GRANT_TYPE: &str = "urn:ietf:params:oauth:grant-type:device_code";
/// 聊天请求鉴权头的前缀：`Bearer workos:<accessToken>`。
pub const CLINE_AUTH_SCHEME_PREFIX: &str = "workos:";
/// WorkOS refresh_token grant（自愈路径用）。
pub const CLINE_REFRESH_TOKEN_GRANT_TYPE: &str = "refresh_token";

const DEFAULT_DEVICE_EXPIRES_IN_SECS: u64 = 600;
const DEFAULT_DEVICE_POLL_INTERVAL_SECS: u64 = 5;
/// 参考实现把 `expiresAt` 当毫秒时间戳用；大于这个量级的数值按毫秒换算。
const EPOCH_MILLIS_THRESHOLD: f64 = 100_000_000_000.0;

#[derive(Debug, Clone, PartialEq)]
pub enum ClineDevicePollOutcome {
    Pending,
    SlowDown,
    Authorized(Box<ProviderOAuthTokenSet>),
}

/// `/auth/refresh` 的三种结局。分开是因为"被拒"和"暂时失败"的处理完全不同：
/// 前者要自愈（或让账号走重新授权），后者只能等下一次。
#[derive(Debug)]
enum ClineRefreshOutcome {
    Refreshed(Box<ProviderOAuthTokenSet>),
    Rejected {
        status_code: u16,
        body_excerpt: String,
    },
    Transient(OAuthError),
}

#[derive(Clone, Default)]
pub struct ClineProviderOAuthAdapter {
    device_url_override: Option<String>,
    authenticate_url_override: Option<String>,
    api_base_url_override: Option<String>,
}

impl std::fmt::Debug for ClineProviderOAuthAdapter {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("ClineProviderOAuthAdapter")
            .field(
                "has_device_url_override",
                &self.device_url_override.is_some(),
            )
            .field(
                "has_authenticate_url_override",
                &self.authenticate_url_override.is_some(),
            )
            .field(
                "has_api_base_url_override",
                &self.api_base_url_override.is_some(),
            )
            .finish_non_exhaustive()
    }
}

impl ClineProviderOAuthAdapter {
    /// 测试用：把三个上游入口都指到本地桩。
    pub fn with_endpoint_overrides(
        mut self,
        device_url: impl Into<String>,
        authenticate_url: impl Into<String>,
        api_base_url: impl Into<String>,
    ) -> Self {
        self.device_url_override = Some(device_url.into());
        self.authenticate_url_override = Some(authenticate_url.into());
        self.api_base_url_override = Some(api_base_url.into());
        self
    }

    fn device_url(&self) -> String {
        self.device_url_override
            .clone()
            .unwrap_or_else(|| CLINE_WORKOS_DEVICE_URL.to_string())
    }

    fn authenticate_url(&self) -> String {
        self.authenticate_url_override
            .clone()
            .unwrap_or_else(|| CLINE_WORKOS_AUTHENTICATE_URL.to_string())
    }

    fn api_url(&self, path: &str) -> String {
        let base = self
            .api_base_url_override
            .clone()
            .unwrap_or_else(|| CLINE_API_BASE_URL.to_string());
        format!("{}{}", base.trim_end_matches('/'), path)
    }

    pub async fn start_device_flow(
        &self,
        executor: &dyn OAuthHttpExecutor,
        ctx: &ProviderOAuthTransportContext,
    ) -> Result<OAuthDeviceAuthorization, OAuthError> {
        // 参考实现只传 client_id（没有 scope 参数），照抄。
        let form = form_urlencoded::Serializer::new(String::new())
            .append_pair("client_id", CLINE_WORKOS_CLIENT_ID)
            .finish()
            .into_bytes();
        let response = executor
            .execute(OAuthHttpRequest {
                request_id: "provider-oauth:cline-device-code".to_string(),
                method: reqwest::Method::POST,
                url: self.device_url(),
                headers: form_headers(),
                content_type: Some("application/x-www-form-urlencoded".to_string()),
                json_body: None,
                body_bytes: Some(form),
                network: ctx.network.clone(),
                transport_profile: None,
            })
            .await?;
        if !(200..300).contains(&response.status_code) {
            return Err(OAuthError::HttpStatus {
                status_code: response.status_code,
                body_excerpt: redacted_oauth_error_body_excerpt(&response.body_text),
            });
        }
        let payload = response_json(&response).ok_or_else(|| {
            OAuthError::invalid_response("Cline device code response is not json")
        })?;
        parse_device_authorization(&payload)
    }

    pub async fn poll_device_token(
        &self,
        executor: &dyn OAuthHttpExecutor,
        ctx: &ProviderOAuthTransportContext,
        device_code: &str,
    ) -> Result<ClineDevicePollOutcome, OAuthError> {
        let device_code = device_code.trim();
        if device_code.is_empty() {
            return Err(OAuthError::invalid_request("Cline device_code is required"));
        }
        let form = form_urlencoded::Serializer::new(String::new())
            .append_pair("grant_type", CLINE_DEVICE_CODE_GRANT_TYPE)
            .append_pair("device_code", device_code)
            .append_pair("client_id", CLINE_WORKOS_CLIENT_ID)
            .finish()
            .into_bytes();
        let response = executor
            .execute(OAuthHttpRequest {
                request_id: "provider-oauth:cline-device-token".to_string(),
                method: reqwest::Method::POST,
                url: self.authenticate_url(),
                headers: form_headers(),
                content_type: Some("application/x-www-form-urlencoded".to_string()),
                json_body: None,
                body_bytes: Some(form),
                network: ctx.network.clone(),
                transport_profile: None,
            })
            .await?;
        let payload = response_json(&response);
        if let Some(error_code) = payload.as_ref().and_then(oauth_error_code) {
            return match error_code.as_str() {
                "authorization_pending" => Ok(ClineDevicePollOutcome::Pending),
                "slow_down" => Ok(ClineDevicePollOutcome::SlowDown),
                "expired_token" => Err(OAuthError::invalid_request("Cline device code expired")),
                "access_denied" => Err(OAuthError::invalid_request(
                    "Cline device authorization denied",
                )),
                other => Err(OAuthError::invalid_response(format!(
                    "Cline device token error: {other}"
                ))),
            };
        }
        if !(200..300).contains(&response.status_code) {
            return Err(OAuthError::HttpStatus {
                status_code: response.status_code,
                body_excerpt: redacted_oauth_error_body_excerpt(&response.body_text),
            });
        }
        let payload = payload.ok_or_else(|| {
            OAuthError::invalid_response("Cline device token response is not json")
        })?;
        let workos_access = json_non_empty_string(&payload, &["access_token", "accessToken"])
            .ok_or_else(|| {
                OAuthError::invalid_response("Cline device token response missing access_token")
            })?;
        let workos_refresh = json_non_empty_string(&payload, &["refresh_token", "refreshToken"])
            .ok_or_else(|| {
                OAuthError::invalid_response("Cline device token response missing refresh_token")
            })?;
        let token_set = self
            .register_cline_tokens(executor, ctx, &workos_access, &workos_refresh)
            .await?;
        Ok(ClineDevicePollOutcome::Authorized(Box::new(token_set)))
    }

    /// `POST /auth/register`：拿 WorkOS 的一对 token 换 Cline 的一对 token。
    async fn register_cline_tokens(
        &self,
        executor: &dyn OAuthHttpExecutor,
        ctx: &ProviderOAuthTransportContext,
        workos_access_token: &str,
        workos_refresh_token: &str,
    ) -> Result<ProviderOAuthTokenSet, OAuthError> {
        let body = json!({
            "accessToken": workos_access_token,
            "refreshToken": workos_refresh_token,
        });
        let response = executor
            .execute(OAuthHttpRequest {
                request_id: "provider-oauth:cline-register".to_string(),
                method: reqwest::Method::POST,
                url: self.api_url(CLINE_REGISTER_PATH),
                headers: json_headers(),
                content_type: Some("application/json".to_string()),
                json_body: Some(body),
                body_bytes: None,
                network: ctx.network.clone(),
                transport_profile: None,
            })
            .await?;
        if !(200..300).contains(&response.status_code) {
            return Err(OAuthError::HttpStatus {
                status_code: response.status_code,
                body_excerpt: redacted_oauth_error_body_excerpt(&response.body_text),
            });
        }
        let payload = response_json(&response)
            .ok_or_else(|| OAuthError::invalid_response("Cline register response is not json"))?;
        let data = payload.get("data").unwrap_or(&payload);
        let access_token = json_non_empty_string(data, &["accessToken", "access_token"])
            .ok_or_else(|| {
                OAuthError::invalid_response("Cline register response missing accessToken")
            })?;
        // 刷新响应可能不带新 refresh token（不轮换），此时沿用 WorkOS 那把。
        let refresh_token = json_non_empty_string(data, &["refreshToken", "refresh_token"])
            .unwrap_or_else(|| workos_refresh_token.to_string());
        let expires_at =
            parse_cline_expires_at(data.get("expiresAt").or_else(|| data.get("expires_at")));
        let email = data
            .get("userInfo")
            .and_then(|value| value.get("email"))
            .and_then(Value::as_str)
            .map(str::trim)
            .filter(|value| !value.is_empty())
            .map(ToOwned::to_owned);
        Ok(cline_token_set(
            access_token,
            refresh_token,
            expires_at,
            email,
            Some(payload),
        ))
    }

    /// `POST /auth/refresh`，并把"被拒"与"暂时失败"分开。
    async fn refresh_via_cline(
        &self,
        executor: &dyn OAuthHttpExecutor,
        ctx: &ProviderOAuthTransportContext,
        refresh_token: &str,
    ) -> ClineRefreshOutcome {
        let body = json!({
            "refreshToken": refresh_token,
            "grantType": CLINE_REFRESH_TOKEN_GRANT_TYPE,
        });
        let response = match executor
            .execute(OAuthHttpRequest {
                request_id: "provider-oauth:cline-refresh".to_string(),
                method: reqwest::Method::POST,
                url: self.api_url(CLINE_REFRESH_PATH),
                headers: json_headers(),
                content_type: Some("application/json".to_string()),
                json_body: Some(body),
                body_bytes: None,
                network: ctx.network.clone(),
                transport_profile: None,
            })
            .await
        {
            Ok(response) => response,
            Err(error) => return ClineRefreshOutcome::Transient(error),
        };
        if !(200..300).contains(&response.status_code) {
            let status_code = response.status_code;
            let body_excerpt = redacted_oauth_error_body_excerpt(&response.body_text);
            // 只有这三个码代表 Cline 真的拒绝了这把 refresh token。
            if is_refresh_rejection_status(status_code) {
                return ClineRefreshOutcome::Rejected {
                    status_code,
                    body_excerpt,
                };
            }
            return ClineRefreshOutcome::Transient(OAuthError::HttpStatus {
                status_code,
                body_excerpt,
            });
        }
        let Some(payload) = response_json(&response) else {
            return ClineRefreshOutcome::Transient(OAuthError::invalid_response(
                "Cline refresh response is not json",
            ));
        };
        let data = payload.get("data").unwrap_or(&payload);
        let Some(access_token) = json_non_empty_string(data, &["accessToken", "access_token"])
        else {
            return ClineRefreshOutcome::Transient(OAuthError::invalid_response(
                "Cline refresh response missing accessToken",
            ));
        };
        let rotated = json_non_empty_string(data, &["refreshToken", "refresh_token"])
            .unwrap_or_else(|| refresh_token.to_string());
        let expires_at =
            parse_cline_expires_at(data.get("expiresAt").or_else(|| data.get("expires_at")));
        ClineRefreshOutcome::Refreshed(Box::new(cline_token_set(
            access_token,
            rotated,
            expires_at,
            None,
            None,
        )))
    }

    /// 自愈：用同一把 refresh token 走 WorkOS `authenticate`，再 `register` 一次。
    /// 失败返回 None（调用方保留原始"被拒"错误）。
    async fn refresh_via_workos(
        &self,
        executor: &dyn OAuthHttpExecutor,
        ctx: &ProviderOAuthTransportContext,
        refresh_token: &str,
    ) -> Option<ProviderOAuthTokenSet> {
        let body = json!({
            "grant_type": CLINE_REFRESH_TOKEN_GRANT_TYPE,
            "client_id": CLINE_WORKOS_CLIENT_ID,
            "refresh_token": refresh_token,
        });
        let response = executor
            .execute(OAuthHttpRequest {
                request_id: "provider-oauth:cline-workos-refresh".to_string(),
                method: reqwest::Method::POST,
                url: self.authenticate_url(),
                headers: json_headers(),
                content_type: Some("application/json".to_string()),
                json_body: Some(body),
                body_bytes: None,
                network: ctx.network.clone(),
                transport_profile: None,
            })
            .await
            .ok()?;
        if !(200..300).contains(&response.status_code) {
            return None;
        }
        let payload = response_json(&response)?;
        let access_token = json_non_empty_string(&payload, &["access_token", "accessToken"])?;
        let refresh_token = json_non_empty_string(&payload, &["refresh_token", "refreshToken"])
            .unwrap_or_else(|| refresh_token.to_string());
        self.register_cline_tokens(executor, ctx, &access_token, &refresh_token)
            .await
            .ok()
    }
}

#[async_trait]
impl ProviderOAuthAdapter for ClineProviderOAuthAdapter {
    fn provider_type(&self) -> &'static str {
        CLINE_PROVIDER_TYPE
    }

    fn capabilities(&self) -> ProviderOAuthCapabilities {
        ProviderOAuthCapabilities {
            supports_authorization_code: false,
            supports_cookie_authorization: false,
            supports_refresh_token_import: true,
            supports_batch_import: true,
            supports_device_flow: true,
            supports_account_probe: false,
            rotates_refresh_token: true,
        }
    }

    async fn import_credentials(
        &self,
        executor: &dyn OAuthHttpExecutor,
        ctx: &ProviderOAuthTransportContext,
        input: ProviderOAuthImportInput,
    ) -> Result<ProviderOAuthTokenSet, OAuthError> {
        let refresh_token = input
            .refresh_token
            .as_deref()
            .map(str::trim)
            .filter(|value| !value.is_empty())
            .map(ToOwned::to_owned)
            .or_else(|| {
                raw_credential_string(
                    input.raw_credentials.as_ref(),
                    &["refreshToken", "refresh_token"],
                )
            })
            .ok_or_else(|| OAuthError::invalid_request("Cline credentials require refreshToken"))?;

        // 参考实现的凭据文件里通常还带着上一次的 accessToken：有就先直接 register
        //（等价于"用现成的 WorkOS 会话换 Cline token"，少一次刷新）。
        if let Some(workos_access) = raw_credential_string(
            input.raw_credentials.as_ref(),
            &["accessToken", "access_token"],
        ) {
            // register 被拒（或暂时失败）都退回下面的刷新路径，那里会给出更准确的错误。
            if let Ok(token_set) = self
                .register_cline_tokens(executor, ctx, &workos_access, &refresh_token)
                .await
            {
                return Ok(token_set);
            }
        }

        match self.refresh_via_cline(executor, ctx, &refresh_token).await {
            ClineRefreshOutcome::Refreshed(token_set) => Ok(*token_set),
            ClineRefreshOutcome::Rejected { .. } => self
                .refresh_via_workos(executor, ctx, &refresh_token)
                .await
                .ok_or_else(|| OAuthError::HttpStatus {
                    status_code: 401,
                    body_excerpt:
                        "Cline rejected the refresh token and the WorkOS self-heal failed"
                            .to_string(),
                }),
            ClineRefreshOutcome::Transient(error) => Err(error),
        }
    }

    async fn refresh(
        &self,
        executor: &dyn OAuthHttpExecutor,
        ctx: &ProviderOAuthTransportContext,
        account: &ProviderOAuthAccount,
    ) -> Result<ProviderOAuthTokenSet, OAuthError> {
        let refresh_token = ["refresh_token", "refreshToken"]
            .iter()
            .find_map(|field| account.auth_config.get(*field).and_then(Value::as_str))
            .map(str::trim)
            .filter(|value| !value.is_empty())
            .ok_or_else(|| {
                OAuthError::invalid_request("Cline auth_config missing refresh_token")
            })?;
        // 刷新响应常常不带账号信息，用存量配置打底，让新 token 覆盖同名键。
        let existing_email = account
            .auth_config
            .get("email")
            .and_then(Value::as_str)
            .map(str::trim)
            .filter(|value| !value.is_empty())
            .map(ToOwned::to_owned);
        match self.refresh_via_cline(executor, ctx, refresh_token).await {
            ClineRefreshOutcome::Refreshed(mut token_set) => {
                if let Some(email) = existing_email {
                    attach_auth_config_email(&mut token_set.auth_config, &email);
                }
                Ok(*token_set)
            }
            ClineRefreshOutcome::Rejected {
                status_code,
                body_excerpt,
            } => {
                if let Some(mut token_set) =
                    self.refresh_via_workos(executor, ctx, refresh_token).await
                {
                    if let Some(email) = existing_email {
                        attach_auth_config_email(&mut token_set.auth_config, &email);
                    }
                    return Ok(token_set);
                }
                Err(OAuthError::HttpStatus {
                    status_code,
                    body_excerpt,
                })
            }
            ClineRefreshOutcome::Transient(error) => Err(error),
        }
    }

    fn resolve_request_auth(
        &self,
        account: &ProviderOAuthAccount,
    ) -> Result<ProviderOAuthRequestAuth, OAuthError> {
        let access_token = account.access_token.trim();
        if access_token.is_empty() {
            return Err(OAuthError::invalid_request("Cline access_token is empty"));
        }
        Ok(ProviderOAuthRequestAuth::Header {
            name: "authorization".to_string(),
            value: format!("Bearer {}", cline_bearer_value(access_token)),
        })
    }

    fn account_fingerprint(&self, account: &ProviderOAuthAccount) -> Option<String> {
        let refresh_token = ["refresh_token", "refreshToken"]
            .iter()
            .find_map(|field| account.auth_config.get(*field).and_then(Value::as_str))
            .map(str::trim)
            .filter(|value| !value.is_empty())
            .unwrap_or_else(|| account.access_token.trim());
        (!refresh_token.is_empty()).then(|| secret_fingerprint(refresh_token))
    }
}

/// 落库的 `access_token` 就是**可直接下发**的值。
///
/// 网关运行时只认 key 行里的 `access_token` 拼 `Bearer <access_token>`，不会调用
/// `resolve_request_auth`（全仓 `apps/aether-gateway` 里搜不到这个调用）。所以账号模式
/// 必须在这里就把 `workos:` 前缀贴好：裸 Cline token 发出去只会 401。
/// 原始 token 另存 `auth_config.cline_access_token`，便于排查与将来的账号探测。
fn cline_token_set(
    access_token: String,
    refresh_token: String,
    expires_at_unix_secs: Option<u64>,
    email: Option<String>,
    raw_payload: Option<Value>,
) -> ProviderOAuthTokenSet {
    let mut auth_config = Map::new();
    auth_config.insert("provider_type".to_string(), json!(CLINE_PROVIDER_TYPE));
    auth_config.insert("auth_method".to_string(), json!("oauth"));
    auth_config.insert("using_api".to_string(), json!(false));
    auth_config.insert("refresh_token".to_string(), json!(refresh_token));
    auth_config.insert("updated_at".to_string(), json!(current_unix_secs()));
    auth_config.insert(
        "cline_access_token".to_string(),
        json!(access_token.as_str()),
    );
    auth_config.insert(
        "workos_client_id".to_string(),
        json!(CLINE_WORKOS_CLIENT_ID),
    );
    if let Some(email) = email.as_deref() {
        auth_config.insert("email".to_string(), json!(email));
    }
    ProviderOAuthTokenSet {
        token_set: OAuthTokenSet {
            access_token: cline_bearer_value(&access_token),
            refresh_token: Some(refresh_token),
            token_type: Some("Bearer".to_string()),
            scope: None,
            expires_at_unix_secs,
            raw_payload,
        },
        auth_config: Value::Object(auth_config),
    }
}

/// 幂等地贴上 `workos:` 前缀（已经是带前缀的形状就原样返回）。
fn cline_bearer_value(access_token: &str) -> String {
    if access_token.starts_with(CLINE_AUTH_SCHEME_PREFIX) {
        access_token.to_string()
    } else {
        format!("{CLINE_AUTH_SCHEME_PREFIX}{access_token}")
    }
}

fn attach_auth_config_email(auth_config: &mut Value, email: &str) {
    let Some(object) = auth_config.as_object_mut() else {
        return;
    };
    object.insert("email".to_string(), json!(email));
}

fn is_refresh_rejection_status(status_code: u16) -> bool {
    matches!(status_code, 400 | 401 | 403)
}

fn parse_device_authorization(payload: &Value) -> Result<OAuthDeviceAuthorization, OAuthError> {
    let device_code = json_non_empty_string(payload, &["device_code", "deviceCode"])
        .ok_or_else(|| OAuthError::invalid_response("Cline device response missing device_code"))?;
    let user_code = json_non_empty_string(payload, &["user_code", "userCode"])
        .ok_or_else(|| OAuthError::invalid_response("Cline device response missing user_code"))?;
    let verification_uri = json_non_empty_string(
        payload,
        &["verification_uri", "verificationUri", "verification_url"],
    )
    .unwrap_or_default();
    let verification_uri_complete = json_non_empty_string(
        payload,
        &[
            "verification_uri_complete",
            "verificationUriComplete",
            "verification_url_complete",
        ],
    )
    .unwrap_or_else(|| verification_uri.clone());
    if verification_uri.is_empty() && verification_uri_complete.is_empty() {
        return Err(OAuthError::invalid_response(
            "Cline device response missing verification URI",
        ));
    }
    Ok(OAuthDeviceAuthorization {
        device_code,
        user_code,
        verification_uri: if verification_uri.is_empty() {
            verification_uri_complete.clone()
        } else {
            verification_uri
        },
        verification_uri_complete,
        expires_in: json_u64(payload, &["expires_in", "expiresIn"])
            .unwrap_or(DEFAULT_DEVICE_EXPIRES_IN_SECS),
        interval: json_u64(payload, &["interval"]).unwrap_or(DEFAULT_DEVICE_POLL_INTERVAL_SECS),
    })
}

/// `expiresAt` 在参考实现里是 `any`：既见过毫秒数，也可能给 ISO-8601 字符串。
/// 解析不出来就返回 None（不编造过期时间），运行时 401 那条路仍会触发刷新。
fn parse_cline_expires_at(value: Option<&Value>) -> Option<u64> {
    match value? {
        Value::Number(number) => number.as_f64().and_then(normalize_epoch_number),
        Value::String(text) => {
            let text = text.trim();
            if text.is_empty() {
                return None;
            }
            if let Ok(number) = text.parse::<f64>() {
                return normalize_epoch_number(number);
            }
            parse_rfc3339_utc_secs(text)
        }
        _ => None,
    }
}

fn normalize_epoch_number(value: f64) -> Option<u64> {
    if !value.is_finite() || value <= 0.0 {
        return None;
    }
    if value > EPOCH_MILLIS_THRESHOLD {
        Some((value / 1000.0) as u64)
    } else {
        Some(value as u64)
    }
}

/// 只认 `YYYY-MM-DDTHH:MM:SS[.fff][Z|±hh:mm]` 这一族；解析不了返回 None。
fn parse_rfc3339_utc_secs(text: &str) -> Option<u64> {
    let bytes = text.as_bytes();
    if bytes.len() < 19 {
        return None;
    }
    let year = text.get(0..4)?.parse::<i64>().ok()?;
    if bytes[4] != b'-' || bytes[7] != b'-' {
        return None;
    }
    let month = text.get(5..7)?.parse::<u32>().ok()?;
    let day = text.get(8..10)?.parse::<u32>().ok()?;
    let separator = bytes[10];
    if separator != b'T' && separator != b't' && separator != b' ' {
        return None;
    }
    if bytes[13] != b':' || bytes[16] != b':' {
        return None;
    }
    let hour = text.get(11..13)?.parse::<i64>().ok()?;
    let minute = text.get(14..16)?.parse::<i64>().ok()?;
    let second = text.get(17..19)?.parse::<i64>().ok()?;
    if !(1..=12).contains(&month) || !(1..=31).contains(&day) || hour > 23 || minute > 59 {
        return None;
    }
    if second > 60 {
        return None;
    }
    let days = days_from_civil(year, month, day);
    let secs = days * 86_400 + hour * 3_600 + minute * 60 + second;
    u64::try_from(secs).ok()
}

/// Howard Hinnant 的 days_from_civil：把公历日期换成 1970-01-01 起的天数。
fn days_from_civil(year: i64, month: u32, day: u32) -> i64 {
    let year = if month <= 2 { year - 1 } else { year };
    let era = if year >= 0 { year } else { year - 399 } / 400;
    let year_of_era = year - era * 400;
    let month_prime = (i64::from(month) + 9) % 12;
    let day_of_year = (153 * month_prime + 2) / 5 + i64::from(day) - 1;
    let day_of_era = year_of_era * 365 + year_of_era / 4 - year_of_era / 100 + day_of_year;
    era * 146_097 + day_of_era - 719_468
}

fn secret_fingerprint(value: &str) -> String {
    let digest = Sha256::digest(value.as_bytes());
    digest
        .iter()
        .take(16)
        .map(|byte| format!("{byte:02x}"))
        .collect()
}

fn raw_credential_string(raw: Option<&Value>, keys: &[&str]) -> Option<String> {
    let object = raw?.as_object()?;
    keys.iter().find_map(|key| {
        object
            .get(*key)
            .and_then(Value::as_str)
            .map(str::trim)
            .filter(|value| !value.is_empty())
            .map(ToOwned::to_owned)
    })
}

fn response_json(response: &OAuthHttpResponse) -> Option<Value> {
    response
        .json_body
        .clone()
        .or_else(|| serde_json::from_str::<Value>(&response.body_text).ok())
}

fn oauth_error_code(payload: &Value) -> Option<String> {
    payload
        .get("error")
        .and_then(Value::as_str)
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .map(ToOwned::to_owned)
}

fn json_non_empty_string(payload: &Value, keys: &[&str]) -> Option<String> {
    keys.iter().find_map(|key| {
        payload
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

fn form_headers() -> BTreeMap<String, String> {
    BTreeMap::from([
        (
            "content-type".to_string(),
            "application/x-www-form-urlencoded".to_string(),
        ),
        ("accept".to_string(), "application/json".to_string()),
    ])
}

fn json_headers() -> BTreeMap<String, String> {
    BTreeMap::from([
        ("content-type".to_string(), "application/json".to_string()),
        ("accept".to_string(), "application/json".to_string()),
    ])
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::network::{OAuthHttpExecutor, OAuthHttpRequest, OAuthHttpResponse};
    use crate::provider::{
        ProviderOAuthAccount, ProviderOAuthAdapter, ProviderOAuthImportInput,
        ProviderOAuthTransportContext,
    };
    use async_trait::async_trait;
    use std::collections::VecDeque;
    use std::sync::{Arc, Mutex};

    /// 按脚本依次回放响应，并把收到的请求原样记下来（顺序即断言依据）。
    #[derive(Clone, Default)]
    struct ScriptedExecutor {
        responses: Arc<Mutex<VecDeque<(u16, Value)>>>,
        seen: Arc<Mutex<Vec<OAuthHttpRequest>>>,
    }

    impl ScriptedExecutor {
        fn new(responses: Vec<(u16, Value)>) -> Self {
            Self {
                responses: Arc::new(Mutex::new(responses.into())),
                seen: Arc::new(Mutex::new(Vec::new())),
            }
        }

        fn requests(&self) -> Vec<OAuthHttpRequest> {
            self.seen.lock().expect("mutex should lock").clone()
        }
    }

    #[async_trait]
    impl OAuthHttpExecutor for ScriptedExecutor {
        async fn execute(
            &self,
            request: OAuthHttpRequest,
        ) -> Result<OAuthHttpResponse, OAuthError> {
            self.seen.lock().expect("mutex should lock").push(request);
            let (status_code, payload) = self
                .responses
                .lock()
                .expect("mutex should lock")
                .pop_front()
                .expect("scripted response should exist");
            Ok(OAuthHttpResponse {
                status_code,
                body_text: payload.to_string(),
                json_body: Some(payload),
            })
        }
    }

    fn transport_context() -> ProviderOAuthTransportContext {
        ProviderOAuthTransportContext {
            provider_id: "provider-cline".to_string(),
            provider_type: CLINE_PROVIDER_TYPE.to_string(),
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

    fn adapter() -> ClineProviderOAuthAdapter {
        ClineProviderOAuthAdapter::default().with_endpoint_overrides(
            "https://workos.test/authorize/device",
            "https://workos.test/authenticate",
            "https://cline.test/api/v1",
        )
    }

    fn workos_pair_payload() -> Value {
        json!({"access_token": "workos-access", "refresh_token": "workos-refresh"})
    }

    fn cline_register_payload() -> Value {
        json!({"data": {
            "accessToken": "cline-access-1",
            "refreshToken": "cline-refresh-1",
            "expiresAt": 1_800_000_000_000_i64,
            "userInfo": {"email": "alice@example.com"}
        }})
    }

    fn account_with(refresh_token: &str) -> ProviderOAuthAccount {
        ProviderOAuthAccount {
            provider_type: CLINE_PROVIDER_TYPE.to_string(),
            access_token: "workos:cline-access-1".to_string(),
            auth_config: json!({
                "provider_type": CLINE_PROVIDER_TYPE,
                "auth_method": "oauth",
                "refresh_token": refresh_token,
                "email": "alice@example.com",
            }),
            expires_at_unix_secs: Some(1),
            identity: BTreeMap::new(),
        }
    }

    #[test]
    fn capabilities_advertise_device_flow_and_refresh_rotation() {
        let adapter = adapter();
        let capabilities = adapter.capabilities();
        assert_eq!(adapter.provider_type(), "cline");
        assert!(capabilities.supports_device_flow);
        assert!(capabilities.supports_refresh_token_import);
        assert!(capabilities.supports_batch_import);
        assert!(capabilities.rotates_refresh_token);
        assert!(!capabilities.supports_authorization_code);
    }

    #[tokio::test]
    async fn device_start_sends_client_id_and_parses_authorization() {
        let executor = ScriptedExecutor::new(vec![(
            200,
            json!({
                "device_code": "dc-1",
                "user_code": "ABCD-EFGH",
                "verification_uri": "https://cline.bot/device",
                "verification_uri_complete": "https://cline.bot/device?user_code=ABCD-EFGH",
                "interval": 5,
                "expires_in": 600
            }),
        )]);
        let authorization = adapter()
            .start_device_flow(&executor, &transport_context())
            .await
            .expect("device start should succeed");

        let requests = executor.requests();
        assert_eq!(requests.len(), 1);
        assert_eq!(requests[0].url, "https://workos.test/authorize/device");
        let body = String::from_utf8(requests[0].body_bytes.clone().expect("form body"))
            .expect("utf8 body");
        assert_eq!(body, format!("client_id={CLINE_WORKOS_CLIENT_ID}"));
        assert_eq!(authorization.device_code, "dc-1");
        assert_eq!(authorization.user_code, "ABCD-EFGH");
        assert_eq!(authorization.interval, 5);
        assert_eq!(authorization.expires_in, 600);
    }

    #[tokio::test]
    async fn device_poll_maps_pending_and_slow_down() {
        let executor = ScriptedExecutor::new(vec![
            (400, json!({"error": "authorization_pending"})),
            (400, json!({"error": "slow_down"})),
        ]);
        let adapter = adapter();
        let ctx = transport_context();
        assert_eq!(
            adapter
                .poll_device_token(&executor, &ctx, "dc-1")
                .await
                .expect("pending should not error"),
            ClineDevicePollOutcome::Pending
        );
        assert_eq!(
            adapter
                .poll_device_token(&executor, &ctx, "dc-1")
                .await
                .expect("slow down should not error"),
            ClineDevicePollOutcome::SlowDown
        );
        // 轮询体里必须带 device_code + client_id（RFC 8628 的 device_code grant）。
        let body = String::from_utf8(executor.requests()[0].body_bytes.clone().unwrap()).unwrap();
        assert!(body.contains("grant_type=urn%3Aietf%3Aparams%3Aoauth%3Agrant-type%3Adevice_code"));
        assert!(body.contains("device_code=dc-1"));
    }

    #[tokio::test]
    async fn device_poll_swaps_workos_pair_for_cline_tokens() {
        let executor = ScriptedExecutor::new(vec![
            (200, workos_pair_payload()),
            (200, cline_register_payload()),
        ]);
        let outcome = adapter()
            .poll_device_token(&executor, &transport_context(), "dc-1")
            .await
            .expect("poll should succeed");
        let ClineDevicePollOutcome::Authorized(token_set) = outcome else {
            panic!("expected an authorized outcome");
        };

        let requests = executor.requests();
        assert_eq!(requests.len(), 2, "设备码授权后必须再换一次 Cline token");
        assert_eq!(requests[1].url, "https://cline.test/api/v1/auth/register");
        let register_body = requests[1].json_body.clone().expect("json body");
        assert_eq!(register_body["accessToken"], json!("workos-access"));
        assert_eq!(register_body["refreshToken"], json!("workos-refresh"));

        assert_eq!(token_set.token_set.access_token, "workos:cline-access-1");
        // 原始 token 另存一份，落库的值才是可直接下发的那个。
        assert_eq!(
            token_set.auth_config["cline_access_token"],
            json!("cline-access-1")
        );
        assert_eq!(
            token_set.token_set.refresh_token.as_deref(),
            Some("cline-refresh-1")
        );
        // expiresAt 是毫秒时间戳 → 落库要换成秒。
        assert_eq!(
            token_set.token_set.expires_at_unix_secs,
            Some(1_800_000_000)
        );
        assert_eq!(token_set.auth_config["auth_method"], json!("oauth"));
        assert_eq!(token_set.auth_config["email"], json!("alice@example.com"));
        assert_eq!(token_set.auth_config["using_api"], json!(false));
    }

    #[tokio::test]
    async fn refresh_uses_cline_endpoint_only_when_it_succeeds() {
        let executor = ScriptedExecutor::new(vec![(
            200,
            json!({"data": {"accessToken": "cline-access-2", "refreshToken": "cline-refresh-2"}}),
        )]);
        let refreshed = adapter()
            .refresh(
                &executor,
                &transport_context(),
                &account_with("cline-refresh-1"),
            )
            .await
            .expect("refresh should succeed");

        assert_eq!(executor.requests().len(), 1, "成功时不该碰 WorkOS");
        assert_eq!(
            executor.requests()[0].url,
            "https://cline.test/api/v1/auth/refresh"
        );
        assert_eq!(
            executor.requests()[0].json_body.as_ref().unwrap()["grantType"],
            json!("refresh_token")
        );
        assert_eq!(refreshed.token_set.access_token, "workos:cline-access-2");
        assert_eq!(
            refreshed.token_set.refresh_token.as_deref(),
            Some("cline-refresh-2")
        );
        // 刷新响应不带账号信息，存量的 email 必须保留。
        assert_eq!(refreshed.auth_config["email"], json!("alice@example.com"));
    }

    #[tokio::test]
    async fn refresh_self_heals_through_workos_when_cline_rejects() {
        let executor = ScriptedExecutor::new(vec![
            (401, json!({"error": "invalid_grant"})),
            (200, workos_pair_payload()),
            (200, cline_register_payload()),
        ]);
        let refreshed = adapter()
            .refresh(
                &executor,
                &transport_context(),
                &account_with("cline-refresh-1"),
            )
            .await
            .expect("self-heal should recover the account");

        let requests = executor.requests();
        assert_eq!(requests.len(), 3);
        assert_eq!(requests[1].url, "https://workos.test/authenticate");
        assert_eq!(
            requests[1].json_body.as_ref().unwrap()["grant_type"],
            json!("refresh_token")
        );
        assert_eq!(
            requests[1].json_body.as_ref().unwrap()["refresh_token"],
            json!("cline-refresh-1")
        );
        assert_eq!(requests[2].url, "https://cline.test/api/v1/auth/register");
        assert_eq!(refreshed.token_set.access_token, "workos:cline-access-1");
    }

    #[tokio::test]
    async fn refresh_treats_5xx_as_transient_and_does_not_self_heal() {
        let executor = ScriptedExecutor::new(vec![(503, json!({"error": "upstream busy"}))]);
        let error = adapter()
            .refresh(
                &executor,
                &transport_context(),
                &account_with("cline-refresh-1"),
            )
            .await
            .expect_err("5xx must surface as a transient error");

        // 关键语义：5xx 只意味着"这次没成功"，绝不能顺手把账号当成失效去自愈。
        assert!(
            matches!(
                error,
                OAuthError::HttpStatus {
                    status_code: 503,
                    ..
                }
            ),
            "unexpected error: {error}"
        );
        assert_eq!(executor.requests().len(), 1, "暂时失败不该触发 WorkOS 自愈");
    }

    #[tokio::test]
    async fn import_accepts_the_reference_credentials_shape() {
        let executor = ScriptedExecutor::new(vec![(
            200,
            json!({"data": {"accessToken": "cline-access-9", "refreshToken": "cline-refresh-9"}}),
        )]);
        let imported = adapter()
            .import_credentials(
                &executor,
                &transport_context(),
                ProviderOAuthImportInput {
                    provider_type: CLINE_PROVIDER_TYPE.to_string(),
                    name: Some("alice@example.com".to_string()),
                    refresh_token: None,
                    raw_credentials: Some(json!({"refreshToken": "cline-refresh-1"})),
                    network: crate::network::OAuthNetworkContext::provider_operation(None),
                },
            )
            .await
            .expect("import should succeed");

        assert_eq!(executor.requests().len(), 1);
        assert_eq!(imported.token_set.access_token, "workos:cline-access-9");
        assert_eq!(
            imported.auth_config["refresh_token"],
            json!("cline-refresh-9")
        );
    }

    #[tokio::test]
    async fn import_uses_a_present_access_token_to_register_directly() {
        let executor = ScriptedExecutor::new(vec![(200, cline_register_payload())]);
        let imported = adapter()
            .import_credentials(
                &executor,
                &transport_context(),
                ProviderOAuthImportInput {
                    provider_type: CLINE_PROVIDER_TYPE.to_string(),
                    name: None,
                    refresh_token: None,
                    raw_credentials: Some(json!({
                        "accessToken": "workos-access",
                        "refreshToken": "workos-refresh"
                    })),
                    network: crate::network::OAuthNetworkContext::provider_operation(None),
                },
            )
            .await
            .expect("import should succeed");

        assert_eq!(
            executor.requests()[0].url,
            "https://cline.test/api/v1/auth/register"
        );
        assert_eq!(imported.token_set.access_token, "workos:cline-access-1");
    }

    #[test]
    fn resolve_request_auth_prefixes_the_workos_scheme() {
        let adapter = adapter();
        // 落库值已带前缀（正常路径）与只带裸 token（手工导入/历史数据）都要得到同一个头。
        for stored in ["workos:cline-access-1", "cline-access-1"] {
            let mut account = account_with("cline-refresh-1");
            account.access_token = stored.to_string();
            match adapter
                .resolve_request_auth(&account)
                .expect("auth should resolve")
            {
                ProviderOAuthRequestAuth::Header { name, value } => {
                    assert_eq!(name, "authorization");
                    assert_eq!(value, "Bearer workos:cline-access-1");
                }
                other => panic!("unexpected auth shape: {other:?}"),
            }
        }
    }

    #[test]
    fn bearer_value_is_prefixed_exactly_once() {
        assert_eq!(
            cline_bearer_value("cline-access-1"),
            "workos:cline-access-1"
        );
        assert_eq!(
            cline_bearer_value("workos:cline-access-1"),
            "workos:cline-access-1"
        );
    }

    #[test]
    fn account_fingerprint_is_stable_and_hides_the_token() {
        let adapter = adapter();
        let first = adapter
            .account_fingerprint(&account_with("cline-refresh-1"))
            .expect("fingerprint");
        let second = adapter
            .account_fingerprint(&account_with("cline-refresh-1"))
            .expect("fingerprint");
        let other = adapter
            .account_fingerprint(&account_with("cline-refresh-2"))
            .expect("fingerprint");
        assert_eq!(first, second);
        assert_ne!(first, other);
        assert!(!first.contains("cline-refresh"));
        assert_eq!(first.len(), 32);
    }

    #[test]
    fn expires_at_accepts_epoch_numbers_and_iso_strings() {
        assert_eq!(
            parse_cline_expires_at(Some(&json!(1_800_000_000_000_i64))),
            Some(1_800_000_000)
        );
        assert_eq!(
            parse_cline_expires_at(Some(&json!(1_800_000_000_u64))),
            Some(1_800_000_000)
        );
        assert_eq!(
            parse_cline_expires_at(Some(&json!("1800000000"))),
            Some(1_800_000_000)
        );
        // 2027-01-15T08:00:00Z
        assert_eq!(
            parse_cline_expires_at(Some(&json!("2027-01-15T08:00:00Z"))),
            Some(1_800_000_000)
        );
        assert_eq!(
            parse_cline_expires_at(Some(&json!("2027-01-15T08:00:00.000Z"))),
            Some(1_800_000_000)
        );
        assert_eq!(parse_cline_expires_at(Some(&json!("not-a-time"))), None);
        assert_eq!(parse_cline_expires_at(None), None);
    }
}
