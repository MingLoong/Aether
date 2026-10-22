use super::super::token_import::{
    flatten_claude_code_credentials_payload, import_tokens_from_raw_token,
    normalize_provider_import_tokens, normalize_provider_oauth_import_headers_from_object,
    provider_oauth_import_authorization_bearer_token,
};
use crate::handlers::admin::provider::oauth::errors::build_internal_control_error_response;
use crate::handlers::admin::provider::oauth::state::{current_unix_secs, json_u64_value};
use axum::{
    body::{to_bytes, Body, Bytes},
    http,
    response::{IntoResponse, Response},
    Json,
};
use serde::Deserialize;
use serde_json::json;
use std::collections::BTreeMap;
use std::time::{SystemTime, UNIX_EPOCH};

#[derive(Clone, Deserialize)]
pub(super) struct AdminProviderOAuthBatchImportRequest {
    pub credentials: String,
    pub proxy_node_id: Option<String>,
}

#[derive(Clone)]
pub(super) struct AdminProviderOAuthBatchImportEntry {
    pub parse_error: Option<String>,
    pub refresh_token: Option<String>,
    pub access_token: Option<String>,
    pub export_access_token: Option<String>,
    pub raw_credentials: Option<serde_json::Value>,
    pub expires_at: Option<u64>,
    pub account_id: Option<String>,
    pub account_user_id: Option<String>,
    pub plan_type: Option<String>,
    pub pool_tier: Option<String>,
    pub user_id: Option<String>,
    pub email: Option<String>,
    pub account_name: Option<String>,
    pub project_id: Option<String>,
    pub client_version: Option<String>,
    pub session_id: Option<String>,
    pub sso_rw_token: Option<String>,
    pub cf_cookies: Option<String>,
    pub cf_clearance: Option<String>,
    pub request_headers: Option<BTreeMap<String, String>>,
    pub user_agent: Option<String>,
    pub browser_profile: Option<String>,
    pub organization_uuid: Option<String>,
    pub scopes: Option<serde_json::Value>,
    pub subscription_type: Option<String>,
    pub rate_limit_tier: Option<String>,
}

#[derive(Clone)]
pub(super) struct AdminProviderOAuthBatchImportOutcome {
    pub total: usize,
    pub success: usize,
    pub failed: usize,
    pub results: Vec<serde_json::Value>,
}

pub(super) fn parse_admin_provider_oauth_batch_import_request(
    request_body: Option<&Bytes>,
) -> Result<AdminProviderOAuthBatchImportRequest, Response<Body>> {
    let Some(request_body) = request_body else {
        return Err(
            crate::handlers::admin::provider::oauth::errors::build_internal_control_error_response(
                http::StatusCode::BAD_REQUEST,
                "请求体必须是合法的 JSON 对象",
            ),
        );
    };
    match serde_json::from_slice::<AdminProviderOAuthBatchImportRequest>(request_body) {
        Ok(payload) if !payload.credentials.trim().is_empty() => Ok(payload),
        _ => Err(
            crate::handlers::admin::provider::oauth::errors::build_internal_control_error_response(
                http::StatusCode::BAD_REQUEST,
                "请求体必须是合法的 JSON 对象",
            ),
        ),
    }
}

fn json_value_contains_agent_identity(value: &serde_json::Value) -> bool {
    if value.as_object().is_some_and(|_| {
        aether_provider_transport::is_codex_agent_identity_auth_config_value(value)
    }) {
        return true;
    }
    match value {
        serde_json::Value::Array(items) => items.iter().any(json_value_contains_agent_identity),
        serde_json::Value::Object(object) => {
            object.values().any(json_value_contains_agent_identity)
        }
        _ => false,
    }
}

pub(super) fn admin_provider_oauth_batch_contains_agent_identity(raw_credentials: &str) -> bool {
    let raw = raw_credentials.trim();
    if raw.is_empty() {
        return false;
    }
    if let Ok(value) = serde_json::from_str::<serde_json::Value>(raw) {
        return json_value_contains_agent_identity(&value);
    }
    raw.lines()
        .map(str::trim)
        .filter(|line| !line.is_empty() && !line.starts_with('#'))
        .filter_map(|line| serde_json::from_str::<serde_json::Value>(line).ok())
        .any(|value| json_value_contains_agent_identity(&value))
}

fn coerce_admin_provider_oauth_import_str(value: Option<&serde_json::Value>) -> Option<String> {
    value
        .and_then(serde_json::Value::as_str)
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .map(ToOwned::to_owned)
}

fn coerce_admin_provider_oauth_import_project_id(
    value: Option<&serde_json::Value>,
) -> Option<String> {
    match value {
        Some(serde_json::Value::Object(object)) => coerce_admin_provider_oauth_import_str(
            object
                .get("id")
                .or_else(|| object.get("project_id"))
                .or_else(|| object.get("projectId")),
        ),
        other => coerce_admin_provider_oauth_import_str(other),
    }
}

fn json_import_expiry_value(value: Option<&serde_json::Value>) -> Option<u64> {
    let value = value?;
    json_u64_value(Some(value)).or_else(|| {
        value
            .as_str()
            .map(str::trim)
            .filter(|value| !value.is_empty())
            .and_then(|value| chrono::DateTime::parse_from_rfc3339(value).ok())
            .and_then(|value| u64::try_from(value.timestamp()).ok())
    })
}

fn json_import_expiry_from_keys(
    object: &serde_json::Map<String, serde_json::Value>,
    keys: &[&str],
) -> Option<u64> {
    keys.iter()
        .find_map(|key| json_import_expiry_value(object.get(*key)))
}

fn grok_cookie_value(raw: &str, name: &str) -> Option<String> {
    raw.trim()
        .strip_prefix("Cookie:")
        .unwrap_or_else(|| raw.trim())
        .split(';')
        .filter_map(|segment| segment.trim().split_once('='))
        .find_map(|(cookie_name, cookie_value)| {
            cookie_name
                .trim()
                .eq_ignore_ascii_case(name)
                .then(|| cookie_value.trim())
                .filter(|value| !value.is_empty())
                .map(ToOwned::to_owned)
        })
}

fn grok_cookie_profile(raw: &str) -> Option<String> {
    let raw = raw
        .trim()
        .strip_prefix("Cookie:")
        .unwrap_or_else(|| raw.trim());
    let parts = raw
        .split(';')
        .filter_map(|segment| {
            let (cookie_name, cookie_value) = segment.trim().split_once('=')?;
            let cookie_name = cookie_name.trim();
            let cookie_value = cookie_value.trim();
            if cookie_name.is_empty()
                || cookie_value.is_empty()
                || cookie_name.eq_ignore_ascii_case("sso")
                || cookie_name.eq_ignore_ascii_case("sso-rw")
            {
                return None;
            }
            Some(format!("{cookie_name}={cookie_value}"))
        })
        .collect::<Vec<_>>();
    (!parts.is_empty()).then(|| parts.join("; "))
}

fn grok_cookie_session_token(provider_type: &str, raw: &str) -> Option<String> {
    provider_type
        .trim()
        .eq_ignore_ascii_case("grok")
        .then(|| grok_cookie_value(raw, "sso"))
        .flatten()
}

fn extract_admin_provider_oauth_batch_import_entry(
    provider_type: &str,
    item: &serde_json::Value,
) -> Option<AdminProviderOAuthBatchImportEntry> {
    match item {
        serde_json::Value::String(value) => {
            let raw_token = value.trim();
            if raw_token.is_empty() {
                None
            } else {
                let sso_from_cookie = grok_cookie_session_token(provider_type, raw_token);
                let token_input = sso_from_cookie.as_deref().unwrap_or(raw_token);
                let (refresh_token, access_token) =
                    if provider_type.trim().eq_ignore_ascii_case("xai") {
                        (None, Some(token_input.to_string()))
                    } else {
                        import_tokens_from_raw_token(token_input)
                    };
                let (refresh_token, access_token) = normalize_provider_import_tokens(
                    provider_type,
                    refresh_token.as_deref(),
                    access_token.as_deref(),
                );
                Some(AdminProviderOAuthBatchImportEntry {
                    parse_error: None,
                    refresh_token,
                    access_token,
                    export_access_token: None,
                    raw_credentials: None,
                    expires_at: None,
                    account_id: None,
                    account_user_id: None,
                    plan_type: None,
                    pool_tier: None,
                    user_id: grok_cookie_value(raw_token, "x-userid"),
                    email: None,
                    account_name: None,
                    project_id: None,
                    client_version: None,
                    session_id: None,
                    sso_rw_token: grok_cookie_value(raw_token, "sso-rw"),
                    cf_cookies: grok_cookie_profile(raw_token),
                    cf_clearance: grok_cookie_value(raw_token, "cf_clearance"),
                    request_headers: None,
                    user_agent: None,
                    browser_profile: None,
                    organization_uuid: None,
                    scopes: None,
                    subscription_type: None,
                    rate_limit_tier: None,
                })
            }
        }
        serde_json::Value::Object(object) => {
            let is_claude = provider_type.trim().eq_ignore_ascii_case("claude_code");
            let normalized_claude_object = if is_claude {
                let mut normalized = object.clone();
                flatten_claude_code_credentials_payload(&mut normalized);
                Some(normalized)
            } else {
                None
            };
            let object = normalized_claude_object.as_ref().unwrap_or(object);
            let is_grok = provider_type.trim().eq_ignore_ascii_case("grok");
            let is_windsurf = provider_type.trim().eq_ignore_ascii_case("windsurf");
            let is_xai = provider_type.trim().eq_ignore_ascii_case("xai");
            let is_workbuddy = provider_type.trim().eq_ignore_ascii_case("workbuddy");
            let is_codex_agent_identity = provider_type.trim().eq_ignore_ascii_case("codex")
                && aether_provider_transport::is_codex_agent_identity_auth_config_value(item);
            if is_codex_agent_identity {
                return Some(AdminProviderOAuthBatchImportEntry {
                    parse_error: None,
                    refresh_token: None,
                    access_token: None,
                    export_access_token: None,
                    raw_credentials: Some(item.clone()),
                    expires_at: None,
                    account_id: None,
                    account_user_id: None,
                    plan_type: None,
                    pool_tier: None,
                    user_id: None,
                    email: None,
                    account_name: None,
                    project_id: None,
                    client_version: None,
                    session_id: None,
                    sso_rw_token: None,
                    cf_cookies: None,
                    cf_clearance: None,
                    request_headers: None,
                    user_agent: None,
                    browser_profile: None,
                    organization_uuid: None,
                    scopes: None,
                    subscription_type: None,
                    rate_limit_tier: None,
                });
            }
            let refresh_token = coerce_admin_provider_oauth_import_str(
                object
                    .get("refresh_token")
                    .or_else(|| object.get("refreshToken")),
            );
            let access_token = coerce_admin_provider_oauth_import_str(
                object
                    .get("access_token")
                    .or_else(|| object.get("accessToken")),
            );
            let grok_token_alias = if is_grok { object.get("token") } else { None };
            let grok_cookie = if is_grok {
                coerce_admin_provider_oauth_import_str(
                    object.get("cookie").or_else(|| object.get("cookieHeader")),
                )
            } else {
                None
            };
            let session_token = coerce_admin_provider_oauth_import_str(
                object
                    .get("sso_token")
                    .or_else(|| object.get("ssoToken"))
                    .or_else(|| object.get("session_token"))
                    .or_else(|| object.get("sessionToken"))
                    .or(grok_token_alias),
            )
            .or_else(|| {
                grok_cookie
                    .as_deref()
                    .and_then(|cookie| grok_cookie_value(cookie, "sso"))
            });
            let request_headers = normalize_provider_oauth_import_headers_from_object(object);
            let header_bearer_token =
                provider_oauth_import_authorization_bearer_token(request_headers.as_ref());
            let export_access_token = if refresh_token.is_none() {
                access_token
                    .as_ref()
                    .filter(|value| header_bearer_token.as_deref() != Some(value.as_str()))
                    .cloned()
            } else {
                None
            };
            let windsurf_api_key = is_windsurf
                .then(|| {
                    coerce_admin_provider_oauth_import_str(
                        object.get("api_key").or_else(|| object.get("apiKey")),
                    )
                })
                .flatten();
            let xai_api_key = is_xai
                .then(|| {
                    coerce_admin_provider_oauth_import_str(
                        object.get("api_key").or_else(|| object.get("apiKey")),
                    )
                })
                .flatten();
            let (refresh_token, access_token) = normalize_provider_import_tokens(
                provider_type,
                refresh_token.as_deref(),
                access_token
                    .as_deref()
                    .or(session_token.as_deref())
                    .or(header_bearer_token.as_deref())
                    .or(xai_api_key.as_deref()),
            );
            let windsurf_token = is_windsurf
                .then(|| {
                    coerce_admin_provider_oauth_import_str(
                        object
                            .get("token")
                            .or_else(|| object.get("auth_token"))
                            .or_else(|| object.get("authToken")),
                    )
                })
                .flatten();
            let windsurf_password = is_windsurf
                .then(|| coerce_admin_provider_oauth_import_str(object.get("password")))
                .flatten();
            let raw_credentials = if is_windsurf
                && (windsurf_api_key.is_some()
                    || windsurf_token.is_some()
                    || windsurf_password.is_some())
            {
                Some(item.clone())
            } else if is_workbuddy && (refresh_token.is_some() || access_token.is_some()) {
                // WorkBuddy 的身份（`uid` / `domain` / `realm` / `nickname`）只在原始条目里：
                // 刷新响应与 token 响应都不回传。留着原始对象，域预检
                // （`workbuddy_batch_entry_realm`）和身份落盘（`apply_..._hints`）才有东西可读。
                // 只在真的带凭据时保留，避免「空条目」从「静默丢弃」变成「报错」。
                Some(item.clone())
            } else {
                None
            };
            if refresh_token.is_none() && access_token.is_none() && raw_credentials.is_none() {
                return None;
            }
            let refresh_token = if is_windsurf {
                refresh_token.or(windsurf_api_key).or(windsurf_token)
            } else {
                refresh_token
            };
            let expires_at =
                json_import_expiry_from_keys(object, &["expires_at", "expiresAt", "expired"]);
            let account_id = coerce_admin_provider_oauth_import_str(
                object
                    .get("account_id")
                    .or_else(|| object.get("accountId"))
                    .or_else(|| object.get("chatgpt_account_id"))
                    .or_else(|| object.get("chatgptAccountId")),
            );
            let account_user_id = coerce_admin_provider_oauth_import_str(
                object
                    .get("account_user_id")
                    .or_else(|| object.get("accountUserId"))
                    .or_else(|| object.get("chatgpt_account_user_id"))
                    .or_else(|| object.get("chatgptAccountUserId")),
            );
            let plan_type = coerce_admin_provider_oauth_import_str(
                object
                    .get("plan_type")
                    .or_else(|| object.get("planType"))
                    .or_else(|| object.get("chatgpt_plan_type"))
                    .or_else(|| object.get("chatgptPlanType")),
            )
            .map(|value| value.to_ascii_lowercase());
            let pool_tier = coerce_admin_provider_oauth_import_str(
                object
                    .get("pool_tier")
                    .or_else(|| object.get("poolTier"))
                    .or_else(|| object.get("tier")),
            )
            .map(|value| value.to_ascii_lowercase());
            let user_id = coerce_admin_provider_oauth_import_str(
                object
                    .get("user_id")
                    .or_else(|| object.get("userId"))
                    .or_else(|| object.get("chatgpt_user_id"))
                    .or_else(|| object.get("chatgptUserId")),
            )
            .or_else(|| {
                grok_cookie
                    .as_deref()
                    .and_then(|cookie| grok_cookie_value(cookie, "x-userid"))
            });
            let email = coerce_admin_provider_oauth_import_str(object.get("email"));
            let account_name = coerce_admin_provider_oauth_import_str(
                object
                    .get("account_name")
                    .or_else(|| object.get("accountName")),
            );
            let project_id = coerce_admin_provider_oauth_import_project_id(
                object
                    .get("project_id")
                    .or_else(|| object.get("projectId"))
                    .or_else(|| object.get("cloudaicompanionProject"))
                    .or_else(|| object.get("cloudAiCompanionProject")),
            );
            let client_version = coerce_admin_provider_oauth_import_str(
                object
                    .get("client_version")
                    .or_else(|| object.get("clientVersion"))
                    .or_else(|| object.get("antigravityClientVersion")),
            );
            let session_id = coerce_admin_provider_oauth_import_str(
                object
                    .get("session_id")
                    .or_else(|| object.get("sessionId"))
                    .or_else(|| object.get("vscode_session_id"))
                    .or_else(|| object.get("vscodeSessionId")),
            );
            let sso_rw_token = coerce_admin_provider_oauth_import_str(
                object
                    .get("sso_rw_token")
                    .or_else(|| object.get("ssoRwToken")),
            )
            .or_else(|| {
                grok_cookie
                    .as_deref()
                    .and_then(|cookie| grok_cookie_value(cookie, "sso-rw"))
            });
            let cf_clearance = coerce_admin_provider_oauth_import_str(
                object
                    .get("cf_clearance")
                    .or_else(|| object.get("cfClearance")),
            )
            .or_else(|| {
                grok_cookie
                    .as_deref()
                    .and_then(|cookie| grok_cookie_value(cookie, "cf_clearance"))
            });
            let cf_cookies = coerce_admin_provider_oauth_import_str(
                object.get("cf_cookies").or_else(|| object.get("cfCookies")),
            )
            .or_else(|| grok_cookie.as_deref().and_then(grok_cookie_profile));
            let user_agent = coerce_admin_provider_oauth_import_str(
                object.get("user_agent").or_else(|| object.get("userAgent")),
            );
            let browser_profile = coerce_admin_provider_oauth_import_str(
                object
                    .get("browser_profile")
                    .or_else(|| object.get("browserProfile"))
                    .or_else(|| object.get("browser"))
                    .or_else(|| object.get("impersonate")),
            );
            let organization_uuid = is_claude
                .then(|| {
                    coerce_admin_provider_oauth_import_str(
                        object
                            .get("organization_uuid")
                            .or_else(|| object.get("organizationUuid"))
                            .or_else(|| object.get("org_uuid")),
                    )
                })
                .flatten();
            let scopes = is_claude
                .then(|| object.get("scopes"))
                .flatten()
                .filter(|value| value.is_array() || value.is_string())
                .cloned();
            let subscription_type = is_claude
                .then(|| {
                    coerce_admin_provider_oauth_import_str(
                        object
                            .get("subscription_type")
                            .or_else(|| object.get("subscriptionType")),
                    )
                })
                .flatten();
            let rate_limit_tier = is_claude
                .then(|| {
                    coerce_admin_provider_oauth_import_str(
                        object
                            .get("rate_limit_tier")
                            .or_else(|| object.get("rateLimitTier")),
                    )
                })
                .flatten();
            Some(AdminProviderOAuthBatchImportEntry {
                parse_error: None,
                refresh_token,
                access_token,
                export_access_token,
                raw_credentials,
                expires_at,
                account_id,
                account_user_id,
                plan_type,
                pool_tier,
                user_id,
                email,
                account_name,
                project_id,
                client_version,
                session_id,
                sso_rw_token,
                cf_cookies,
                cf_clearance,
                request_headers,
                user_agent,
                browser_profile,
                organization_uuid,
                scopes,
                subscription_type,
                rate_limit_tier,
            })
        }
        _ => None,
    }
}

fn parse_sub2api_export_accounts(
    provider_type: &str,
    object: &serde_json::Map<String, serde_json::Value>,
) -> Option<Vec<AdminProviderOAuthBatchImportEntry>> {
    if !provider_type.trim().eq_ignore_ascii_case("codex") {
        return None;
    }
    let is_sub2api_export = object
        .get("type")
        .and_then(serde_json::Value::as_str)
        .is_some_and(|value| value.trim().eq_ignore_ascii_case("sub2api-data"));
    if !is_sub2api_export {
        return None;
    }

    let Some(accounts) = object.get("accounts").and_then(serde_json::Value::as_array) else {
        return Some(vec![parse_error_entry(
            "sub2api 导出缺少 accounts 数组".to_string(),
        )]);
    };

    let mut entries = Vec::new();
    for (index, account) in accounts.iter().enumerate() {
        let Some(account) = account.as_object() else {
            entries.push(parse_error_entry(format!(
                "sub2api 第 {} 个账号必须是 JSON 对象",
                index + 1
            )));
            continue;
        };
        if account
            .get("platform")
            .and_then(serde_json::Value::as_str)
            .is_some_and(|platform| !platform.trim().eq_ignore_ascii_case("openai"))
        {
            continue;
        }

        let Some(mut credentials) = account
            .get("credentials")
            .and_then(serde_json::Value::as_object)
            .cloned()
        else {
            entries.push(parse_error_entry(format!(
                "sub2api 第 {} 个账号缺少 credentials 对象",
                index + 1
            )));
            continue;
        };
        if let Some(name) = account
            .get("name")
            .and_then(serde_json::Value::as_str)
            .map(str::trim)
            .filter(|value| !value.is_empty())
        {
            credentials
                .entry("account_name".to_string())
                .or_insert_with(|| json!(name));
        }
        if let Some(extra) = account.get("extra").and_then(serde_json::Value::as_object) {
            for key in [
                "account_id",
                "chatgpt_account_id",
                "chatgpt_user_id",
                "chatgpt_account_is_fedramp",
                "email",
                "plan_type",
                "workspace_id",
            ] {
                if let Some(value) = extra.get(key).cloned() {
                    credentials.entry(key.to_string()).or_insert(value);
                }
            }
        }

        let credentials = serde_json::Value::Object(credentials);
        match extract_admin_provider_oauth_batch_import_entry(provider_type, &credentials) {
            Some(entry) => entries.push(entry),
            None => entries.push(parse_error_entry(format!(
                "sub2api 第 {} 个账号没有可导入的凭据",
                index + 1
            ))),
        }
    }

    if entries.is_empty() {
        entries.push(parse_error_entry(
            "sub2api 导出中没有可导入的 OpenAI 账号".to_string(),
        ));
    }
    Some(entries)
}

pub(super) fn parse_admin_provider_oauth_batch_import_entries(
    provider_type: &str,
    raw_credentials: &str,
) -> Vec<AdminProviderOAuthBatchImportEntry> {
    let raw = raw_credentials.trim();
    if raw.is_empty() {
        return Vec::new();
    }

    if raw.starts_with('[') {
        match serde_json::from_str::<serde_json::Value>(raw) {
            Ok(serde_json::Value::Array(items)) => {
                return items
                    .iter()
                    .filter_map(|item| {
                        extract_admin_provider_oauth_batch_import_entry(provider_type, item)
                    })
                    .collect();
            }
            Ok(_) => {}
            Err(_) => return vec![parse_error_entry("JSON 数组解析失败".to_string())],
        }
    }

    if raw.starts_with('{') {
        if let Ok(value) = serde_json::from_str::<serde_json::Value>(raw) {
            if let Some(object) = value.as_object() {
                if let Some(entries) = parse_sub2api_export_accounts(provider_type, object) {
                    return entries;
                }
                return extract_admin_provider_oauth_batch_import_entry(provider_type, &value)
                    .into_iter()
                    .collect();
            }
        }
    }

    raw.lines()
        .map(str::trim)
        .filter(|line| !line.is_empty() && !line.starts_with('#'))
        .filter_map(|token| {
            if is_json_like_batch_line(token) {
                match serde_json::from_str::<serde_json::Value>(token) {
                    Ok(value @ serde_json::Value::Object(_)) => {
                        return extract_admin_provider_oauth_batch_import_entry(
                            provider_type,
                            &value,
                        );
                    }
                    Ok(_) => {
                        return Some(parse_error_entry(
                            "JSON 行必须是账号对象，不能作为 raw token 导入".to_string(),
                        ));
                    }
                    Err(_) => {
                        return Some(parse_error_entry("JSON 行解析失败".to_string()));
                    }
                }
            }

            extract_admin_provider_oauth_batch_import_entry(
                provider_type,
                &serde_json::Value::String(token.to_string()),
            )
        })
        .collect()
}

pub(super) fn parse_admin_provider_oauth_agent_identity_import_entries(
    raw_credentials: &str,
) -> Result<Vec<AdminProviderOAuthBatchImportEntry>, String> {
    let raw = raw_credentials.trim();
    if raw.is_empty() {
        return Err("Agent Identity 凭据不能为空".to_string());
    }
    let value = serde_json::from_str::<serde_json::Value>(raw)
        .map_err(|_| "Agent Identity JSON 解析失败".to_string())?;
    let entries = match &value {
        serde_json::Value::Array(items) => items
            .iter()
            .enumerate()
            .map(|(index, item)| {
                extract_admin_provider_oauth_batch_import_entry("codex", item).unwrap_or_else(
                    || {
                        parse_error_entry(format!(
                            "第 {} 个条目没有可导入的 Agent Identity 凭据",
                            index + 1
                        ))
                    },
                )
            })
            .collect(),
        serde_json::Value::Object(object) => parse_sub2api_export_accounts("codex", object)
            .unwrap_or_else(|| {
                vec![
                    extract_admin_provider_oauth_batch_import_entry("codex", &value)
                        .unwrap_or_else(|| {
                            parse_error_entry("没有可导入的 Agent Identity 凭据".to_string())
                        }),
                ]
            }),
        _ => return Err("Agent Identity 凭据必须是 JSON 对象、数组或 sub2api 导出".to_string()),
    };
    if entries.is_empty() {
        return Err("Agent Identity 凭据不能为空".to_string());
    }
    Ok(entries)
}

fn parse_error_entry(error: String) -> AdminProviderOAuthBatchImportEntry {
    AdminProviderOAuthBatchImportEntry {
        parse_error: Some(error),
        refresh_token: None,
        access_token: None,
        export_access_token: None,
        raw_credentials: None,
        expires_at: None,
        account_id: None,
        account_user_id: None,
        plan_type: None,
        pool_tier: None,
        user_id: None,
        email: None,
        account_name: None,
        project_id: None,
        client_version: None,
        session_id: None,
        sso_rw_token: None,
        cf_cookies: None,
        cf_clearance: None,
        request_headers: None,
        user_agent: None,
        browser_profile: None,
        organization_uuid: None,
        scopes: None,
        subscription_type: None,
        rate_limit_tier: None,
    }
}

fn is_json_like_batch_line(line: &str) -> bool {
    let line = line.trim_start();
    line.starts_with('{') || line.starts_with('[')
}

/// 批量导入条目属于哪个域（WorkBuddy 双实例用）。
///
/// 判定顺序：显式 `realm` → `domain`/`base_url` 是否指向 `workbuddy.ai` → 都没有按 CN
/// （上游缺省口径，与面板一致）。
///
/// 这里读的是 `entry.raw_credentials`，所以 workbuddy 条目必须在解析阶段把原始对象留下来
/// （见 `extract_admin_provider_oauth_batch_import_entry`）——否则一律被判成 CN，
/// 国际实例导入国际账号会被预检整批拦掉。
pub(super) fn workbuddy_batch_entry_realm(entry: &AdminProviderOAuthBatchImportEntry) -> String {
    let raw = entry.raw_credentials.as_ref();
    if let Some(realm) = raw
        .and_then(|raw| raw.get("realm"))
        .and_then(serde_json::Value::as_str)
        .map(|realm| realm.trim().to_ascii_lowercase())
        .filter(|realm| realm == "cn" || realm == "global")
    {
        return realm;
    }
    let domain = raw
        .and_then(|raw| raw.get("domain").or_else(|| raw.get("base_url")))
        .and_then(serde_json::Value::as_str)
        .unwrap_or_default()
        .to_ascii_lowercase();
    if domain.contains("workbuddy.ai") {
        "global".to_string()
    } else {
        "cn".to_string()
    }
}

/// 从批量导入条目的原始对象里取一个字符串字段（同时认 snake_case 与 camelCase）。
fn workbuddy_batch_entry_string(
    entry: &AdminProviderOAuthBatchImportEntry,
    keys: &[&str],
) -> Option<String> {
    let raw = entry.raw_credentials.as_ref()?;
    keys.iter()
        .find_map(|key| raw.get(*key))
        .and_then(serde_json::Value::as_str)
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .map(ToOwned::to_owned)
}

/// 交给「用 refreshToken 换 token」的身份提示：只放 WorkBuddy 刷新要用的身份字段，
/// **一个 token 都不带**。
///
/// 为什么不能整条原样传：`WorkbuddyProviderOAuthAdapter::import_credentials` 一旦在
/// `raw_credentials` 里看到 `accessToken` 就直接跳过刷新——那就等于放弃上游校验，
/// 而这里的语义是「先刷新，失败才回退」。
pub(super) fn workbuddy_batch_refresh_identity(
    entry: &AdminProviderOAuthBatchImportEntry,
) -> Option<serde_json::Value> {
    let mut identity = serde_json::Map::new();
    for (target, keys) in [
        ("uid", &["uid", "user_id", "userId"][..]),
        ("enterpriseId", &["enterprise_id", "enterpriseId"][..]),
        ("domain", &["domain", "base_url", "baseUrl"][..]),
        ("nickname", &["nickname", "name", "account_name"][..]),
    ] {
        let Some(value) = workbuddy_batch_entry_string(entry, keys) else {
            continue;
        };
        identity.insert(target.to_string(), json!(value));
    }
    (!identity.is_empty()).then(|| serde_json::Value::Object(identity))
}

pub(super) fn apply_admin_provider_oauth_batch_import_hints(
    provider_type: &str,
    entry: &AdminProviderOAuthBatchImportEntry,
    auth_config: &mut serde_json::Map<String, serde_json::Value>,
) {
    let provider_type = provider_type.trim().to_ascii_lowercase();
    if provider_type == "workbuddy" {
        // WorkBuddy 的运行时身份（`aether_provider_transport::workbuddy::workbuddy_identity`）
        // 只认 auth_config 里的这几样：`realm` / `domain` / `uid`（外加 `enterprise_id`、
        // `nickname`）。刷新接口与 token 响应都不回身份，导出文件却带齐了——不照抄进去，
        // 导进来的凭据就会按「CN + 空 uid」出站：`X-Machine-ID` / `X-Session-ID` 直接没有，
        // 上游一律按非官方客户端拒掉。
        for (target, keys) in [
            ("uid", &["uid", "user_id", "userId"][..]),
            ("domain", &["domain", "base_url", "baseUrl"][..]),
            ("enterprise_id", &["enterprise_id", "enterpriseId"][..]),
            ("nickname", &["nickname", "name", "account_name"][..]),
        ] {
            let Some(value) = workbuddy_batch_entry_string(entry, keys) else {
                continue;
            };
            auth_config
                .entry(target.to_string())
                .or_insert_with(|| json!(value));
        }
        // realm 与批量预检同口径（显式 realm → domain 后缀 → CN）：写进凭据的域必须就是
        // 预检用来放行的域，否则「校验通过但运行时打错域」。
        auth_config
            .entry("realm".to_string())
            .or_insert_with(|| json!(workbuddy_batch_entry_realm(entry)));
        auth_config
            .entry("auth_method".to_string())
            .or_insert_with(|| json!("oauth"));
        auth_config
            .entry("using_api".to_string())
            .or_insert_with(|| json!(false));
        return;
    }
    if provider_type == "gemini_cli" {
        if let Some(project_id) = entry.project_id.as_ref() {
            auth_config
                .entry("project_id".to_string())
                .or_insert_with(|| json!(project_id));
        }
        if let Some(plan_type) = entry.plan_type.as_ref() {
            auth_config
                .entry("plan_type".to_string())
                .or_insert_with(|| json!(plan_type));
        }
        return;
    }
    if provider_type == "antigravity" {
        // The Google refresh-token response does not include the account email.
        // Preserve the identity supplied by the imported Antigravity credentials so
        // account naming and duplicate detection can use it after token exchange.
        if let Some(email) = entry.email.as_ref() {
            auth_config
                .entry("email".to_string())
                .or_insert_with(|| json!(email));
        }
        if let Some(project_id) = entry.project_id.as_ref() {
            auth_config
                .entry("project_id".to_string())
                .or_insert_with(|| json!(project_id));
        }
        if let Some(client_version) = entry.client_version.as_ref() {
            auth_config
                .entry("client_version".to_string())
                .or_insert_with(|| json!(client_version));
        }
        if let Some(session_id) = entry.session_id.as_ref() {
            auth_config
                .entry("session_id".to_string())
                .or_insert_with(|| json!(session_id));
        }
        if let Some(user_agent) = entry.user_agent.as_ref() {
            auth_config
                .entry("user_agent".to_string())
                .or_insert_with(|| json!(user_agent));
        }
        return;
    }
    if provider_type == "claude_code" {
        if let Some(organization_uuid) = entry.organization_uuid.as_ref() {
            auth_config
                .entry("org_uuid".to_string())
                .or_insert_with(|| json!(organization_uuid));
        }
        if let Some(scopes) = entry.scopes.as_ref() {
            auth_config
                .entry("scopes".to_string())
                .or_insert_with(|| scopes.clone());
        }
        if let Some(subscription_type) = entry.subscription_type.as_ref() {
            auth_config
                .entry("subscription_type".to_string())
                .or_insert_with(|| json!(subscription_type));
        }
        if let Some(rate_limit_tier) = entry.rate_limit_tier.as_ref() {
            auth_config
                .entry("rate_limit_tier".to_string())
                .or_insert_with(|| json!(rate_limit_tier));
        }
        return;
    }
    if !matches!(provider_type.as_str(), "codex" | "chatgpt_web" | "grok") {
        return;
    }
    if let Some(account_id) = entry.account_id.as_ref() {
        auth_config
            .entry("account_id".to_string())
            .or_insert_with(|| json!(account_id));
    }
    if let Some(account_user_id) = entry.account_user_id.as_ref() {
        auth_config
            .entry("account_user_id".to_string())
            .or_insert_with(|| json!(account_user_id));
    }
    if let Some(plan_type) = entry.plan_type.as_ref() {
        auth_config
            .entry("plan_type".to_string())
            .or_insert_with(|| json!(plan_type));
    }
    if let Some(pool_tier) = entry.pool_tier.as_ref() {
        auth_config
            .entry("pool_tier".to_string())
            .or_insert_with(|| json!(pool_tier));
    }
    if let Some(access_token) = entry.export_access_token.as_ref() {
        auth_config
            .entry("access_token".to_string())
            .or_insert_with(|| json!(access_token));
    }
    if let Some(user_id) = entry.user_id.as_ref() {
        auth_config
            .entry("user_id".to_string())
            .or_insert_with(|| json!(user_id));
    }
    if let Some(email) = entry.email.as_ref() {
        auth_config
            .entry("email".to_string())
            .or_insert_with(|| json!(email));
    }
    if let Some(account_name) = entry.account_name.as_ref() {
        auth_config
            .entry("account_name".to_string())
            .or_insert_with(|| json!(account_name));
    }
    if let Some(sso_rw_token) = entry.sso_rw_token.as_ref() {
        auth_config
            .entry("sso_rw_token".to_string())
            .or_insert_with(|| json!(sso_rw_token));
    }
    if let Some(cf_cookies) = entry.cf_cookies.as_ref() {
        auth_config
            .entry("cf_cookies".to_string())
            .or_insert_with(|| json!(cf_cookies));
    }
    if let Some(cf_clearance) = entry.cf_clearance.as_ref() {
        auth_config
            .entry("cf_clearance".to_string())
            .or_insert_with(|| json!(cf_clearance));
    }
    if let Some(request_headers) = entry.request_headers.as_ref() {
        auth_config
            .entry("headers".to_string())
            .or_insert_with(|| json!(request_headers));
    }
    if let Some(user_agent) = entry.user_agent.as_ref() {
        auth_config
            .entry("user_agent".to_string())
            .or_insert_with(|| json!(user_agent));
    }
    if let Some(browser_profile) = entry.browser_profile.as_ref() {
        auth_config
            .entry("browser_profile".to_string())
            .or_insert_with(|| json!(browser_profile));
    }
}

/// 面板 / 日志里能放的错误摘要长度上限。
pub(super) const ADMIN_PROVIDER_OAUTH_BATCH_ERROR_DETAIL_MAX_CHARS: usize = 200;

/// 超过这个长度的字母数字串一律当凭据打码（token / 签名 / 密文都远长于此）。
const BATCH_ERROR_DETAIL_LONG_RUN_CHARS: usize = 24;

/// 把上游原文压成「一行、能直接展示」的错误摘要。
///
/// 三层处理，缺一不可：
/// 1. `aether-oauth` 的脱敏口径（敏感键、secret 形状的值、URL 全部打码）；
/// 2. 收掉换行 / 连续空白（多行 JSON 会撑爆面板），并把超长的无分隔串当凭据打码；
/// 3. 截断到 200 字符。
pub(super) fn sanitize_admin_provider_oauth_batch_error_detail(raw: &str) -> String {
    let excerpt = aether_oauth::redacted_oauth_error_body_excerpt(raw);
    let collapsed = excerpt.split_whitespace().collect::<Vec<_>>().join(" ");
    let collapsed = redact_long_batch_error_runs(&collapsed);
    let trimmed = collapsed.trim();
    // `redacted_oauth_error_body_excerpt` 对空输入返回 "-"。
    if trimmed.is_empty() || trimmed == "-" {
        return "上游未返回可读原因".to_string();
    }
    trimmed
        .chars()
        .take(ADMIN_PROVIDER_OAUTH_BATCH_ERROR_DETAIL_MAX_CHARS)
        .collect()
}

fn redact_long_batch_error_runs(text: &str) -> String {
    let mut output = String::with_capacity(text.len());
    let mut run = String::new();
    for ch in text.chars() {
        if ch.is_ascii_alphanumeric() || matches!(ch, '-' | '_' | '+' | '/' | '=' | '~') {
            run.push(ch);
        } else {
            flush_batch_error_run(&mut run, &mut output);
            output.push(ch);
        }
    }
    flush_batch_error_run(&mut run, &mut output);
    output
}

fn flush_batch_error_run(run: &mut String, output: &mut String) {
    if run.chars().count() >= BATCH_ERROR_DETAIL_LONG_RUN_CHARS {
        output.push_str("[redacted]");
    } else {
        output.push_str(run);
    }
    run.clear();
}

pub(super) async fn extract_admin_provider_oauth_batch_error_detail(
    response: Response<Body>,
) -> String {
    let status = response.status();
    let body = to_bytes(response.into_body(), crate::MAX_ERROR_BODY_BYTES)
        .await
        .ok();
    // 内部错误响应体固定是 `{"detail": "..."}`；读不到就只报状态码。
    let raw = body
        .and_then(|bytes| serde_json::from_slice::<serde_json::Value>(&bytes).ok())
        .and_then(|value| {
            value
                .get("detail")
                .and_then(serde_json::Value::as_str)
                .map(str::to_string)
        })
        .unwrap_or_default();
    format!(
        "HTTP {} · {}",
        status.as_u16(),
        sanitize_admin_provider_oauth_batch_error_detail(&raw)
    )
}

pub(super) fn build_admin_provider_oauth_batch_import_response(
    outcome: &AdminProviderOAuthBatchImportOutcome,
) -> Json<serde_json::Value> {
    Json(json!({
        "total": outcome.total,
        "success": outcome.success,
        "failed": outcome.failed,
        "results": outcome.results,
    }))
}

pub(in super::super) fn build_admin_provider_oauth_batch_task_state(
    task_id: &str,
    provider_id: &str,
    provider_type: &str,
    import_kind: &str,
    status: &str,
    total: usize,
    processed: usize,
    success: usize,
    failed: usize,
    created_count: usize,
    replaced_count: usize,
    message: Option<&str>,
    error: Option<&str>,
    error_samples: Vec<serde_json::Value>,
    created_at: u64,
    started_at: Option<u64>,
    finished_at: Option<u64>,
) -> serde_json::Value {
    let updated_at = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .ok()
        .map(|duration| duration.as_secs())
        .unwrap_or(created_at);
    let progress_percent = processed
        .saturating_mul(100)
        .checked_div(total)
        .unwrap_or(0)
        .min(100) as u64;
    json!({
        "task_id": task_id,
        "provider_id": provider_id,
        "provider_type": provider_type,
        "import_kind": import_kind,
        "status": status,
        "total": total,
        "processed": processed,
        "success": success,
        "failed": failed,
        "created_count": created_count,
        "replaced_count": replaced_count,
        "progress_percent": progress_percent,
        "message": message,
        "error": error,
        "error_samples": error_samples,
        "created_at": created_at,
        "started_at": started_at,
        "finished_at": finished_at,
        "updated_at": updated_at,
    })
}

#[cfg(test)]
mod tests {
    use super::{
        admin_provider_oauth_batch_contains_agent_identity,
        apply_admin_provider_oauth_batch_import_hints,
        parse_admin_provider_oauth_batch_import_entries,
        sanitize_admin_provider_oauth_batch_error_detail, workbuddy_batch_entry_realm,
        AdminProviderOAuthBatchImportEntry, ADMIN_PROVIDER_OAUTH_BATCH_ERROR_DETAIL_MAX_CHARS,
    };
    use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine as _};
    use serde_json::json;

    fn unsigned_jwt(payload: serde_json::Value) -> String {
        let header = json!({"alg": "none", "typ": "JWT"});
        let encode = |value: serde_json::Value| {
            URL_SAFE_NO_PAD.encode(serde_json::to_vec(&value).expect("jwt json should serialize"))
        };
        format!("{}.{}.signature", encode(header), encode(payload))
    }

    #[test]
    fn ordinary_batch_guard_detects_agent_identity_in_all_json_shapes() {
        let single = json!({
            "auth_mode": "agentIdentity",
            "agent_runtime_id": "runtime-1",
            "agent_private_key": "private-key"
        });
        assert!(admin_provider_oauth_batch_contains_agent_identity(
            &single.to_string()
        ));
        assert!(admin_provider_oauth_batch_contains_agent_identity(
            &json!([{"refresh_token":"ordinary"}, single.clone()]).to_string()
        ));
        assert!(admin_provider_oauth_batch_contains_agent_identity(
            &format!("ordinary-token\n{}", single)
        ));
        assert!(admin_provider_oauth_batch_contains_agent_identity(
            &json!({
                "type": "sub2api-data",
                "accounts": [{"credentials": single.clone()}]
            })
            .to_string()
        ));
        assert!(!admin_provider_oauth_batch_contains_agent_identity(
            &json!([{"refresh_token":"ordinary"}]).to_string()
        ));
        assert!(!admin_provider_oauth_batch_contains_agent_identity(
            "ordinary-token"
        ));
    }

    #[test]
    fn parses_access_token_only_entry() {
        let entries = parse_admin_provider_oauth_batch_import_entries(
            "codex",
            r#"[{"accessToken":"at_1","expiresAt":2100000000,"accountId":"acc-1","email":"u@example.com"}]"#,
        );

        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0].refresh_token, None);
        assert_eq!(entries[0].access_token.as_deref(), Some("at_1"));
        assert_eq!(entries[0].export_access_token.as_deref(), Some("at_1"));
        assert_eq!(entries[0].expires_at, Some(2_100_000_000));
        assert_eq!(entries[0].account_id.as_deref(), Some("acc-1"));
        assert_eq!(entries[0].email.as_deref(), Some("u@example.com"));
    }

    #[test]
    fn parses_claude_credentials_json_and_ignores_mcp_oauth() {
        let entries = parse_admin_provider_oauth_batch_import_entries(
            "claude_code",
            r#"{
                "claudeAiOauth": {
                    "accessToken": "sk-ant-oat01-access",
                    "refreshToken": "sk-ant-ort01-refresh",
                    "expiresAt": 2100000000123,
                    "scopes": ["user:profile"],
                    "subscriptionType": "pro",
                    "rateLimitTier": "tier_1",
                    "organizationUuid": "org-123"
                },
                "mcpOAuth": {"accessToken": "must-not-be-imported"}
            }"#,
        );

        assert_eq!(entries.len(), 1);
        assert_eq!(
            entries[0].access_token.as_deref(),
            Some("sk-ant-oat01-access")
        );
        assert_eq!(
            entries[0].refresh_token.as_deref(),
            Some("sk-ant-ort01-refresh")
        );
        assert_eq!(entries[0].expires_at, Some(2_100_000_000));
        assert_eq!(entries[0].organization_uuid.as_deref(), Some("org-123"));
        assert_eq!(entries[0].scopes, Some(json!(["user:profile"])));
        assert_eq!(entries[0].subscription_type.as_deref(), Some("pro"));
        assert_eq!(entries[0].rate_limit_tier.as_deref(), Some("tier_1"));

        let ignored = parse_admin_provider_oauth_batch_import_entries(
            "claude_code",
            r#"{"mcpOAuth":{"accessToken":"must-not-be-imported"}}"#,
        );
        assert!(ignored.is_empty());
    }

    #[test]
    fn preserves_codex_agent_identity_entry_without_access_token() {
        let entries = parse_admin_provider_oauth_batch_import_entries(
            "codex",
            r#"{"auth_mode":"agentIdentity","agent_identity":{"agent_runtime_id":"runtime-1","agent_private_key":"not-validated-until-import"}}"#,
        );

        assert_eq!(entries.len(), 1);
        assert!(entries[0].refresh_token.is_none());
        assert!(entries[0].access_token.is_none());
        assert_eq!(
            entries[0]
                .raw_credentials
                .as_ref()
                .and_then(|value| value.get("auth_mode")),
            Some(&json!("agentIdentity"))
        );
    }

    #[test]
    fn unwraps_sub2api_agent_identity_export_accounts() {
        let entries = parse_admin_provider_oauth_batch_import_entries(
            "codex",
            r#"{
                "type":"sub2api-data",
                "version":1,
                "accounts":[
                    {
                        "name":"agent@example.com",
                        "platform":"openai",
                        "type":"oauth",
                        "credentials":{
                            "auth_mode":"agentIdentity",
                            "agent_runtime_id":"runtime-1",
                            "agent_private_key":"test-key",
                            "task_id":"task-1",
                            "chatgpt_account_id":"account-1"
                        },
                        "extra":{
                            "email":"agent@example.com",
                            "chatgpt_user_id":"user-1"
                        }
                    },
                    {
                        "name":"unrelated@example.com",
                        "platform":"anthropic",
                        "credentials":{"access_token":"ignored-token"}
                    }
                ]
            }"#,
        );

        assert_eq!(entries.len(), 1);
        assert!(entries[0].parse_error.is_none());
        assert!(entries[0].refresh_token.is_none());
        assert!(entries[0].access_token.is_none());
        let credentials = entries[0]
            .raw_credentials
            .as_ref()
            .and_then(serde_json::Value::as_object)
            .expect("Agent Identity credentials should be preserved");
        assert_eq!(credentials.get("auth_mode"), Some(&json!("agentIdentity")));
        assert_eq!(
            credentials.get("account_name"),
            Some(&json!("agent@example.com"))
        );
        assert_eq!(credentials.get("email"), Some(&json!("agent@example.com")));
        assert_eq!(credentials.get("chatgpt_user_id"), Some(&json!("user-1")));
    }

    #[test]
    fn parses_codex_import_header_overrides() {
        let entries = parse_admin_provider_oauth_batch_import_entries(
            "codex",
            r#"[{"access_token":"jwt_access","headers":{"authorization":"Bearer session-1","chatgpt-account-id":"acc-1","host":"blocked.example"}}]"#,
        );

        assert_eq!(entries.len(), 1);
        let headers = entries[0]
            .request_headers
            .as_ref()
            .expect("headers should parse");
        assert_eq!(
            headers.get("authorization"),
            Some(&"Bearer session-1".to_string())
        );
        assert_eq!(
            headers.get("chatgpt-account-id"),
            Some(&"acc-1".to_string())
        );
        assert!(!headers.contains_key("host"));
    }

    #[test]
    fn treats_import_authorization_header_as_session_access_token() {
        let entries = parse_admin_provider_oauth_batch_import_entries(
            "codex",
            r#"[{"access_token":"jwt_access","headers":{"authorization":"Bearer session-1"}}]"#,
        );

        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0].access_token.as_deref(), Some("jwt_access"));
        assert_eq!(
            entries[0].export_access_token.as_deref(),
            Some("jwt_access")
        );

        let entries = parse_admin_provider_oauth_batch_import_entries(
            "codex",
            r#"[{"headers":{"authorization":"Bearer session-1"}}]"#,
        );

        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0].access_token.as_deref(), Some("session-1"));
        assert!(entries[0].export_access_token.is_none());
    }

    #[test]
    fn applies_codex_import_header_overrides_to_auth_config() {
        let entries = parse_admin_provider_oauth_batch_import_entries(
            "codex",
            r#"{"accessToken":"at_1","headers":{"Authorization":"Bearer session-1"}}"#,
        );
        let mut auth_config = serde_json::Map::new();

        apply_admin_provider_oauth_batch_import_hints("codex", &entries[0], &mut auth_config);

        assert_eq!(
            auth_config.get("headers"),
            Some(&json!({"authorization":"Bearer session-1"}))
        );
        assert_eq!(auth_config.get("access_token"), Some(&json!("at_1")));
    }

    #[test]
    fn does_not_export_access_token_when_it_is_the_header_bearer() {
        let entries = parse_admin_provider_oauth_batch_import_entries(
            "codex",
            r#"{"accessToken":"session-1","headers":{"Authorization":"Bearer session-1"}}"#,
        );
        let mut auth_config = serde_json::Map::new();

        apply_admin_provider_oauth_batch_import_hints("codex", &entries[0], &mut auth_config);

        assert!(entries[0].export_access_token.is_none());
        assert!(auth_config.get("access_token").is_none());
        assert_eq!(
            auth_config.get("headers"),
            Some(&json!({"authorization":"Bearer session-1"}))
        );
    }

    #[test]
    fn does_not_export_access_token_from_refresh_token_payload() {
        let entries = parse_admin_provider_oauth_batch_import_entries(
            "codex",
            r#"{"refreshToken":"refresh-1","accessToken":"refreshed-access"}"#,
        );
        let mut auth_config = serde_json::Map::new();

        apply_admin_provider_oauth_batch_import_hints("codex", &entries[0], &mut auth_config);

        assert_eq!(entries[0].refresh_token.as_deref(), Some("refresh-1"));
        assert_eq!(entries[0].access_token.as_deref(), Some("refreshed-access"));
        assert!(entries[0].export_access_token.is_none());
        assert!(auth_config.get("access_token").is_none());
    }

    #[test]
    fn parses_common_chatgpt_web_json_aliases() {
        let entries = parse_admin_provider_oauth_batch_import_entries(
            "chatgpt_web",
            r#"[{"session_token":"session-1","expired":"2030-01-01T00:00:00Z","chatgpt_account_id":"acc-1","chatgpt_plan_type":"plus"}]"#,
        );

        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0].refresh_token, None);
        assert_eq!(entries[0].access_token.as_deref(), Some("session-1"));
        assert_eq!(entries[0].expires_at, Some(1_893_456_000));
        assert_eq!(entries[0].account_id.as_deref(), Some("acc-1"));
        assert_eq!(entries[0].plan_type.as_deref(), Some("plus"));
    }

    #[test]
    fn parses_plain_jwt_line_as_access_token() {
        let token = unsigned_jwt(json!({
            "iss": "https://auth.openai.com",
            "aud": ["https://api.openai.com/v1"],
            "exp": 2_000_000_000u64,
        }));

        let entries = parse_admin_provider_oauth_batch_import_entries("codex", &token);

        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0].refresh_token, None);
        assert_eq!(entries[0].access_token.as_deref(), Some(token.as_str()));
    }

    #[test]
    fn parses_grok_jsonl_session_entries() {
        let entries = parse_admin_provider_oauth_batch_import_entries(
            "grok",
            r#"{"sso_token":"sso-1","cf_clearance":"cf-1","pool_tier":"heavy","email":"grok@example.com","browser_profile":"chrome136"}"#,
        );

        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0].refresh_token, None);
        assert_eq!(entries[0].access_token.as_deref(), Some("sso-1"));
        assert_eq!(entries[0].cf_clearance.as_deref(), Some("cf-1"));
        assert_eq!(entries[0].pool_tier.as_deref(), Some("heavy"));
        assert_eq!(entries[0].email.as_deref(), Some("grok@example.com"));
        assert_eq!(entries[0].browser_profile.as_deref(), Some("chrome136"));
    }

    #[test]
    fn parses_grok_token_alias_with_account_traits() {
        let entries = parse_admin_provider_oauth_batch_import_entries(
            "grok",
            r#"[{"token":"sso-1","planType":"super","tier":"heavy","accountName":"Grok Heavy"}]"#,
        );

        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0].refresh_token, None);
        assert_eq!(entries[0].access_token.as_deref(), Some("sso-1"));
        assert_eq!(entries[0].plan_type.as_deref(), Some("super"));
        assert_eq!(entries[0].pool_tier.as_deref(), Some("heavy"));
        assert_eq!(entries[0].account_name.as_deref(), Some("Grok Heavy"));
    }

    #[test]
    fn parses_grok_plain_line_as_session_token() {
        let entries = parse_admin_provider_oauth_batch_import_entries("grok", "opaque-sso-token");

        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0].refresh_token, None);
        assert_eq!(entries[0].access_token.as_deref(), Some("opaque-sso-token"));
    }

    #[test]
    fn parses_grok_cookie_line_as_session_metadata() {
        let entries = parse_admin_provider_oauth_batch_import_entries(
            "grok",
            "i18nextLng=zh; cf_clearance=cf-1; sso-rw=rw-1; sso=sso-1; x-userid=user-1",
        );

        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0].refresh_token, None);
        assert_eq!(entries[0].access_token.as_deref(), Some("sso-1"));
        assert_eq!(entries[0].sso_rw_token.as_deref(), Some("rw-1"));
        assert_eq!(
            entries[0].cf_cookies.as_deref(),
            Some("i18nextLng=zh; cf_clearance=cf-1; x-userid=user-1")
        );
        assert_eq!(entries[0].cf_clearance.as_deref(), Some("cf-1"));
        assert_eq!(entries[0].user_id.as_deref(), Some("user-1"));
    }

    #[test]
    fn parses_grok_cookie_object_as_session_metadata() {
        let entries = parse_admin_provider_oauth_batch_import_entries(
            "grok",
            r#"[{"cookie":"cf_clearance=cf-1; sso-rw=rw-1; sso=sso-1; x-userid=user-1","tier":"heavy"}]"#,
        );

        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0].refresh_token, None);
        assert_eq!(entries[0].access_token.as_deref(), Some("sso-1"));
        assert_eq!(entries[0].sso_rw_token.as_deref(), Some("rw-1"));
        assert_eq!(
            entries[0].cf_cookies.as_deref(),
            Some("cf_clearance=cf-1; x-userid=user-1")
        );
        assert_eq!(entries[0].cf_clearance.as_deref(), Some("cf-1"));
        assert_eq!(entries[0].user_id.as_deref(), Some("user-1"));
        assert_eq!(entries[0].pool_tier.as_deref(), Some("heavy"));
    }

    #[test]
    fn parses_gemini_cli_project_id_hint() {
        let entries = parse_admin_provider_oauth_batch_import_entries(
            "gemini_cli",
            r#"[{"refresh_token":"rt-1","projectId":"project-gemini-cli-1","planType":"free"}]"#,
        );

        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0].refresh_token.as_deref(), Some("rt-1"));
        assert_eq!(
            entries[0].project_id.as_deref(),
            Some("project-gemini-cli-1")
        );
        assert_eq!(entries[0].plan_type.as_deref(), Some("free"));
    }

    #[test]
    fn applies_gemini_cli_project_id_hint_to_auth_config() {
        let entries = parse_admin_provider_oauth_batch_import_entries(
            "gemini_cli",
            r#"{"refreshToken":"rt-1","cloudaicompanionProject":{"id":"project-gemini-cli-2"}}"#,
        );
        let mut auth_config = serde_json::Map::new();

        apply_admin_provider_oauth_batch_import_hints("gemini_cli", &entries[0], &mut auth_config);

        assert_eq!(
            auth_config.get("project_id"),
            Some(&json!("project-gemini-cli-2"))
        );
    }

    #[test]
    fn applies_antigravity_project_and_user_agent_hints_to_auth_config() {
        let entries = parse_admin_provider_oauth_batch_import_entries(
            "antigravity",
            r#"{"refreshToken":"rt-1","email":"anti@example.com","cloudaicompanionProject":{"id":"project-antigravity-2"},"userAgent":"antigravity"}"#,
        );
        let mut auth_config = serde_json::Map::new();

        apply_admin_provider_oauth_batch_import_hints("antigravity", &entries[0], &mut auth_config);

        assert_eq!(
            auth_config.get("project_id"),
            Some(&json!("project-antigravity-2"))
        );
        assert_eq!(auth_config.get("user_agent"), Some(&json!("antigravity")));
        assert_eq!(auth_config.get("email"), Some(&json!("anti@example.com")));
    }

    #[test]
    fn antigravity_batch_import_keeps_json_email_for_key_naming() {
        let entries = parse_admin_provider_oauth_batch_import_entries(
            "antigravity",
            r#"{"access_token":"at-1","refresh_token":"rt-1","email":"anti@example.com","project_id":"project-antigravity-3","type":"antigravity"}"#,
        );
        // Simulate Google's refresh-token response, which carries no email.
        let mut auth_config = json!({
            "provider_type": "antigravity",
            "refresh_token": "rt-1",
        })
        .as_object()
        .cloned()
        .expect("auth config should be an object");

        apply_admin_provider_oauth_batch_import_hints("antigravity", &entries[0], &mut auth_config);

        assert_eq!(auth_config.get("email"), Some(&json!("anti@example.com")));
        assert_eq!(
            super::super::super::helpers::admin_provider_oauth_key_name_from_auth_config(
                "antigravity",
                &auth_config,
                Some(0),
            ),
            "anti@example.com"
        );
    }

    #[test]
    fn parses_windsurf_json_credentials_for_native_import() {
        let entries = parse_admin_provider_oauth_batch_import_entries(
            "windsurf",
            r#"[
                {"api_key":"devin-session-token$abc","email":"a@example.com"},
                {"token":"firebase-id-token","name":"Browser Login"},
                {"email":"b@example.com","password":"secret"},
                {"access_token":"devin-session-token$alias","email":"c@example.com"}
            ]"#,
        );

        assert_eq!(entries.len(), 4);
        assert_eq!(
            entries[0].refresh_token.as_deref(),
            Some("devin-session-token$abc")
        );
        assert_eq!(entries[0].email.as_deref(), Some("a@example.com"));
        assert_eq!(
            entries[0]
                .raw_credentials
                .as_ref()
                .and_then(|value| value.get("api_key")),
            Some(&json!("devin-session-token$abc"))
        );
        assert_eq!(
            entries[1]
                .raw_credentials
                .as_ref()
                .and_then(|value| value.get("token")),
            Some(&json!("firebase-id-token"))
        );
        assert_eq!(
            entries[2]
                .raw_credentials
                .as_ref()
                .and_then(|value| value.get("password")),
            Some(&json!("secret"))
        );
        assert_eq!(
            entries[3].access_token.as_deref(),
            Some("devin-session-token$alias")
        );
    }

    #[test]
    fn parses_windsurf_json_lines_credentials_for_native_import() {
        let entries = parse_admin_provider_oauth_batch_import_entries(
            "windsurf",
            r#"{"api_key":"devin-session-token$abc","email":"a@example.com"}
{"token":"firebase-id-token","name":"Browser Login"}
{"email":"b@example.com","password":"secret"}"#,
        );

        assert_eq!(entries.len(), 3);
        assert_eq!(
            entries[0]
                .raw_credentials
                .as_ref()
                .and_then(|value| value.get("api_key")),
            Some(&json!("devin-session-token$abc"))
        );
        assert_eq!(
            entries[1]
                .raw_credentials
                .as_ref()
                .and_then(|value| value.get("token")),
            Some(&json!("firebase-id-token"))
        );
        assert_eq!(
            entries[2]
                .raw_credentials
                .as_ref()
                .and_then(|value| value.get("password")),
            Some(&json!("secret"))
        );
    }

    #[test]
    fn invalid_json_line_is_parse_error_not_token() {
        let entries = parse_admin_provider_oauth_batch_import_entries(
            "windsurf",
            r#"{"email":"b@example.com","password":"secret""#,
        );

        assert_eq!(entries.len(), 1);
        assert!(entries[0].parse_error.is_some());
        assert!(entries[0].refresh_token.is_none());
        assert!(entries[0].access_token.is_none());
        assert!(entries[0].raw_credentials.is_none());
    }

    #[test]
    fn json_like_line_after_token_is_parse_error_not_token() {
        let entries = parse_admin_provider_oauth_batch_import_entries(
            "windsurf",
            "devin-session-token$abc\n[not-json",
        );

        assert_eq!(entries.len(), 2);
        assert!(entries[0].parse_error.is_none());
        assert_eq!(
            entries[0].refresh_token.as_deref(),
            Some("devin-session-token$abc")
        );
        assert!(entries[1].parse_error.is_some());
        assert!(entries[1].refresh_token.is_none());
        assert!(entries[1].access_token.is_none());
        assert!(entries[1].raw_credentials.is_none());
    }

    #[test]
    fn parses_xai_api_key_json_and_raw_lines_as_access_token() {
        let entries = parse_admin_provider_oauth_batch_import_entries(
            "xai",
            r#"{"api_key":"xai-api-key","email":"a@x.ai"}
{"refresh_token":"xai-refresh"}
xai-raw-api-key"#,
        );

        assert_eq!(entries.len(), 3);
        assert!(entries[0].refresh_token.is_none());
        assert_eq!(entries[0].access_token.as_deref(), Some("xai-api-key"));
        assert_eq!(entries[0].email.as_deref(), Some("a@x.ai"));
        assert_eq!(entries[1].refresh_token.as_deref(), Some("xai-refresh"));
        assert!(entries[1].access_token.is_none());
        assert!(entries[2].refresh_token.is_none());
        assert_eq!(entries[2].access_token.as_deref(), Some("xai-raw-api-key"));
    }

    // ---- WorkBuddy 批量导入：域预检 + 身份落盘 -------------------------------------

    fn parse_workbuddy_export(credentials: &str) -> Vec<AdminProviderOAuthBatchImportEntry> {
        parse_admin_provider_oauth_batch_import_entries("workbuddy", credentials)
    }

    #[test]
    fn workbuddy_batch_entry_keeps_raw_credentials_so_realm_can_be_resolved() {
        // 导出文件就是「一条账号一个对象」，域只在对象里（realm / domain），
        // 解析阶段必须原样留下，否则一律被判成 CN。
        let entries = parse_workbuddy_export(
            r#"[
                {"realm":"cn","domain":"www.codebuddy.cn","uid":"uid-cn-1","refresh_token":"rt-cn","access_token":"at-cn","nickname":"CN Buddy"},
                {"realm":"global","domain":"www.workbuddy.ai","uid":"uid-global-1","refresh_token":"rt-global"}
            ]"#,
        );

        assert_eq!(entries.len(), 2);
        assert_eq!(workbuddy_batch_entry_realm(&entries[0]), "cn");
        assert_eq!(workbuddy_batch_entry_realm(&entries[1]), "global");
    }

    #[test]
    fn workbuddy_batch_entry_realm_falls_back_to_domain_suffix_then_cn() {
        let entries = parse_workbuddy_export(
            r#"[
                {"domain":"www.workbuddy.ai","refresh_token":"rt-1"},
                {"domain":"www.codebuddy.cn","refresh_token":"rt-2"},
                {"refresh_token":"rt-3"}
            ]"#,
        );

        assert_eq!(workbuddy_batch_entry_realm(&entries[0]), "global");
        assert_eq!(workbuddy_batch_entry_realm(&entries[1]), "cn");
        assert_eq!(workbuddy_batch_entry_realm(&entries[2]), "cn");
    }

    #[test]
    fn workbuddy_batch_import_hints_write_identity_into_auth_config() {
        let entries = parse_workbuddy_export(
            r#"[{"realm":"cn","domain":"www.codebuddy.cn","uid":"uid-cn-1","enterprise_id":"ent-1","nickname":"CN Buddy","refresh_token":"rt-cn","access_token":"at-cn"}]"#,
        );
        let mut auth_config = serde_json::Map::new();

        apply_admin_provider_oauth_batch_import_hints("workbuddy", &entries[0], &mut auth_config);

        // 运行时身份三元组（workbuddy_identity 只认这几样）。
        assert_eq!(auth_config.get("uid"), Some(&json!("uid-cn-1")));
        assert_eq!(auth_config.get("domain"), Some(&json!("www.codebuddy.cn")));
        assert_eq!(auth_config.get("realm"), Some(&json!("cn")));
        assert_eq!(auth_config.get("enterprise_id"), Some(&json!("ent-1")));
        // key 名要用昵称（WorkBuddy 没有邮箱）。
        assert_eq!(auth_config.get("nickname"), Some(&json!("CN Buddy")));
        assert_eq!(auth_config.get("auth_method"), Some(&json!("oauth")));
        assert_eq!(auth_config.get("using_api"), Some(&json!(false)));
    }

    #[test]
    fn workbuddy_batch_import_hints_do_not_override_refreshed_values() {
        let entries = parse_workbuddy_export(
            r#"[{"realm":"cn","domain":"www.codebuddy.cn","uid":"uid-cn-1","nickname":"CN Buddy","refresh_token":"rt-cn"}]"#,
        );
        let mut auth_config = serde_json::Map::new();
        auth_config.insert("domain".to_string(), json!("www.workbuddy.ai"));
        auth_config.insert("realm".to_string(), json!("global"));

        apply_admin_provider_oauth_batch_import_hints("workbuddy", &entries[0], &mut auth_config);

        assert_eq!(auth_config.get("domain"), Some(&json!("www.workbuddy.ai")));
        assert_eq!(auth_config.get("realm"), Some(&json!("global")));
        assert_eq!(auth_config.get("uid"), Some(&json!("uid-cn-1")));
    }

    // ---- 错误摘要脱敏 / 限长 ---------------------------------------------------

    #[test]
    fn batch_error_detail_redacts_secrets_but_keeps_provider_message() {
        let raw = json!({
            "code": 10002,
            "msg": "refresh token revoked",
            "refresh_token": "refresh-canary",
            "url": "https://user:pass@refresh.example.test/token?access_token=access-canary",
        })
        .to_string();

        let detail = sanitize_admin_provider_oauth_batch_error_detail(&raw);

        assert!(detail.contains("refresh token revoked"), "detail={detail}");
        for secret in [
            "refresh-canary",
            "access-canary",
            "user:pass",
            "refresh.example.test",
        ] {
            assert!(!detail.contains(secret), "secret leaked: {detail}");
        }
    }

    #[test]
    fn batch_error_detail_redacts_long_runs_and_caps_length() {
        let raw = format!(
            "workbuddy refresh failed: code=10002 msg=refresh token revoked {}",
            "A".repeat(400)
        );

        let detail = sanitize_admin_provider_oauth_batch_error_detail(&raw);

        assert!(
            detail.contains("workbuddy refresh failed"),
            "detail={detail}"
        );
        assert!(detail.contains("code=10002"), "detail={detail}");
        assert!(
            !detail.contains(&"A".repeat(24)),
            "long run leaked: {detail}"
        );
        assert!(detail.chars().count() <= ADMIN_PROVIDER_OAUTH_BATCH_ERROR_DETAIL_MAX_CHARS);
        assert!(!detail.contains('\n'));
    }

    #[test]
    fn batch_error_detail_redacts_whole_unstructured_body_with_token_markers() {
        // 无结构但带凭据标记的正文无法逐段定位，整段换掉是 aether-oauth 的既定口径。
        let detail = sanitize_admin_provider_oauth_batch_error_detail(
            "refresh failed x-refresh-token=eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxIn0.c2lnbmF0dXJl",
        );

        assert!(!detail.contains("eyJhbGciOiJIUzI1NiJ9"), "detail={detail}");
    }

    #[test]
    fn batch_error_detail_collapses_multiline_json_and_keeps_provider_message() {
        let detail = sanitize_admin_provider_oauth_batch_error_detail(
            "{\n  \"code\": 10002,\n  \"msg\": \"refresh token has been revoked\"\n}",
        );

        assert_eq!(
            detail,
            "{\"code\":10002,\"msg\":\"refresh token has been revoked\"}"
        );
    }

    #[test]
    fn batch_error_detail_marks_missing_upstream_reason() {
        assert_eq!(
            sanitize_admin_provider_oauth_batch_error_detail(""),
            "上游未返回可读原因"
        );
        assert_eq!(
            sanitize_admin_provider_oauth_batch_error_detail("   "),
            "上游未返回可读原因"
        );
    }
}
