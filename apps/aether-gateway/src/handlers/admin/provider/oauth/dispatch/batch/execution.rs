use super::super::helpers::admin_provider_oauth_key_name_from_auth_config;
use super::super::token_import::{
    build_provider_access_token_import_auth_config, decode_access_token_expires_at,
    is_claude_session_key, provider_oauth_import_authorization_bearer_token,
    provider_type_supports_access_token_import, validate_claude_access_token_import,
};
use super::kiro_import::execute_admin_provider_oauth_kiro_batch_import;
use super::parse::{
    apply_admin_provider_oauth_batch_import_hints, parse_admin_provider_oauth_batch_import_entries,
    sanitize_admin_provider_oauth_batch_error_detail, workbuddy_batch_entry_realm,
    workbuddy_batch_refresh_identity, AdminProviderOAuthBatchImportEntry,
    AdminProviderOAuthBatchImportOutcome,
};
use super::progress::{
    maybe_report_admin_provider_oauth_batch_import_progress,
    AdminProviderOAuthBatchProgressReporter,
};
use crate::handlers::admin::provider::oauth::duplicates::{
    acquire_codex_oauth_account_locks, find_duplicate_provider_oauth_key,
    release_codex_oauth_account_locks,
};
use crate::handlers::admin::provider::oauth::provisioning::build_provider_oauth_auth_config_from_token_payload;
use crate::handlers::admin::provider::oauth::provisioning::{
    create_provider_oauth_catalog_key, provider_oauth_active_api_formats,
    provider_oauth_key_proxy_value, update_existing_provider_oauth_catalog_key,
};
use crate::handlers::admin::provider::oauth::runtime::{
    resolve_provider_oauth_runtime_endpoints,
    spawn_provider_oauth_account_state_refresh_after_update,
};
use crate::handlers::admin::provider::oauth::state::{
    admin_provider_oauth_template, exchange_admin_provider_oauth_refresh_token_failure,
    AdminProviderOAuthRefreshFailure,
};
use crate::handlers::admin::provider::shared::support::ADMIN_PROVIDER_OAUTH_DATA_UNAVAILABLE_DETAIL;
use crate::handlers::admin::request::{AdminAppState, AdminProviderOAuthTemplate};
use crate::GatewayError;
use aether_admin::provider::oauth::parse_admin_provider_oauth_kiro_batch_import_entries;
use aether_contracts::ProxySnapshot;
use aether_oauth::core::OAuthError;
use aether_oauth::provider::{
    ProviderOAuthImportInput, ProviderOAuthService, ProviderOAuthTransportContext,
};
use serde_json::{json, Map, Value};

struct AdminProviderOAuthResolvedBatchImport {
    access_token: String,
    auth_config: Map<String, Value>,
    expires_at: Option<u64>,
}

fn sanitize_windsurf_batch_import_error(error: &OAuthError) -> String {
    match error {
        OAuthError::InvalidRequest(_) => "Windsurf 凭据验证失败: 请求参数无效".to_string(),
        OAuthError::HttpStatus { status_code, .. } => {
            format!("Windsurf 凭据验证失败: HTTP {status_code}")
        }
        _ => "Windsurf 凭据验证失败".to_string(),
    }
}

fn can_fallback_batch_refresh_to_access_token(
    provider_type: &str,
    access_token: Option<&str>,
) -> bool {
    !provider_type.eq_ignore_ascii_case("claude_code")
        && access_token.is_some()
        && provider_type_supports_access_token_import(provider_type)
}

/// 「refresh 失败且不能兜底」这条路径的唯一收尾点：先把**上游真实原因**写进结构化日志，
/// 再把同一份摘要拼进给面板的文案。
///
/// 为什么必须有：以前这里只有一句 `return Err("Token 验证失败")`——detail 算了又丢，
/// 日志里一行线索都没有（154 上 WorkBuddy 4/4 全失败那次只能靠猜）。WorkBuddy 的失败
/// 尤其隐蔽：上游是 HTTP 200 + `{code,msg}` 信封，没有状态码、没有 4xx，只能靠 `msg`。
fn log_admin_provider_oauth_batch_refresh_failure(
    provider_type: &str,
    entry: &AdminProviderOAuthBatchImportEntry,
    failure: &AdminProviderOAuthRefreshFailure,
    detail: &str,
) {
    let is_workbuddy = provider_type.trim().eq_ignore_ascii_case("workbuddy");
    let event_name = if is_workbuddy {
        "workbuddy_batch_import_refresh_failed"
    } else {
        "provider_batch_import_refresh_failed"
    };
    // WorkBuddy 有 CN / 国际双实例，凭据落在哪个域是排查的第一信息；其它 provider 没有这个概念。
    let credential_realm = is_workbuddy.then(|| workbuddy_batch_entry_realm(entry));
    tracing::warn!(
        event_name = event_name,
        provider_type = %provider_type,
        realm = credential_realm.as_deref().unwrap_or("unknown"),
        status_code = ?failure.upstream_status_code,
        error_message = %failure.message,
        upstream_detail = %detail,
        "gateway provider batch import refresh failed and no access token was available to fall back to"
    );
}

/// 批量导入条目属于哪个域（WorkBuddy 双实例用）——实现放在 `parse` 里，与解析阶段保留原始
/// 条目同处一地（域预检与身份落盘必须读同一份数据）。
fn validate_batch_access_token_import(
    provider_type: &str,
    access_token: &str,
    imported_expires_at: Option<u64>,
    now_unix_secs: u64,
) -> Result<(), String> {
    if !provider_type_supports_access_token_import(provider_type) {
        return Err(
            "Access Token 导入仅支持 Claude Code / Codex / ChatGPT Web / Grok / xAI / WorkBuddy Provider"
                .to_string(),
        );
    }
    if provider_type.eq_ignore_ascii_case("claude_code") {
        validate_claude_access_token_import(access_token, imported_expires_at, now_unix_secs)
            .map_err(str::to_string)?;
    }
    Ok(())
}

const CODEX_AGENT_IDENTITY_SAFE_FIELDS: &[(&str, &[&str])] = &[
    ("agent_runtime_id", &["agent_runtime_id", "agentRuntimeId"]),
    (
        "agent_private_key",
        &["agent_private_key", "agentPrivateKey"],
    ),
    ("task_id", &["task_id", "taskId"]),
    (
        "account_id",
        &[
            "account_id",
            "accountId",
            "chatgpt_account_id",
            "chatgptAccountId",
        ],
    ),
    (
        "account_user_id",
        &[
            "account_user_id",
            "accountUserId",
            "chatgpt_account_user_id",
            "chatgptAccountUserId",
        ],
    ),
    (
        "user_id",
        &["user_id", "userId", "chatgpt_user_id", "chatgptUserId"],
    ),
    ("email", &["email"]),
    (
        "plan_type",
        &[
            "plan_type",
            "planType",
            "chatgpt_plan_type",
            "chatgptPlanType",
        ],
    ),
    ("account_name", &["account_name", "accountName"]),
    (
        "is_fedramp",
        &[
            "is_fedramp",
            "chatgpt_account_is_fedramp",
            "chatgptAccountIsFedramp",
        ],
    ),
    ("workspace_id", &["workspace_id", "workspaceId"]),
];

fn copy_codex_agent_identity_safe_fields(
    auth_config: &mut Map<String, Value>,
    preferred: Option<&Map<String, Value>>,
    fallback: &Map<String, Value>,
) {
    for (canonical_key, aliases) in CODEX_AGENT_IDENTITY_SAFE_FIELDS {
        if auth_config.contains_key(*canonical_key) {
            continue;
        }
        let value = preferred
            .and_then(|map| aliases.iter().find_map(|key| map.get(*key)))
            .or_else(|| aliases.iter().find_map(|key| fallback.get(*key)))
            .cloned();
        let Some(value) = value else {
            continue;
        };
        let type_is_allowed = if *canonical_key == "is_fedramp" {
            value.is_boolean()
        } else {
            value.as_str().is_some_and(|text| !text.trim().is_empty())
        };
        if !type_is_allowed {
            continue;
        }
        auth_config.insert((*canonical_key).to_string(), value);
    }
}

fn sanitize_codex_agent_identity_nested_fields(nested: &Map<String, Value>) -> Map<String, Value> {
    let mut sanitized = Map::new();
    copy_codex_agent_identity_safe_fields(&mut sanitized, None, nested);
    sanitized
}

pub(super) fn codex_agent_identity_auth_config_from_import(
    entry: &AdminProviderOAuthBatchImportEntry,
) -> Result<Option<Map<String, Value>>, String> {
    let Some(raw_credentials) = entry.raw_credentials.as_ref() else {
        return Ok(None);
    };
    if !aether_provider_transport::is_codex_agent_identity_auth_config_value(raw_credentials) {
        return Ok(None);
    }
    let root = raw_credentials
        .as_object()
        .ok_or_else(|| "Agent Identity 凭据必须是 JSON 对象".to_string())?;
    let nested = root
        .get("agent_identity")
        .or_else(|| root.get("agentIdentity"))
        .and_then(Value::as_object)
        .cloned();
    let mut auth_config = Map::new();
    copy_codex_agent_identity_safe_fields(&mut auth_config, nested.as_ref(), root);
    if let Some(nested) = nested.as_ref() {
        let sanitized_nested = sanitize_codex_agent_identity_nested_fields(nested);
        if !sanitized_nested.is_empty() {
            auth_config.insert(
                "agent_identity".to_string(),
                Value::Object(sanitized_nested),
            );
        }
    }
    auth_config.insert("provider_type".to_string(), json!("codex"));
    auth_config.insert("auth_mode".to_string(), json!("agentIdentity"));
    aether_provider_transport::validate_codex_agent_identity_auth_config(&Value::Object(
        auth_config.clone(),
    ))?;
    Ok(Some(auth_config))
}

pub(super) fn estimate_admin_provider_oauth_batch_import_total(
    provider_type: &str,
    raw_credentials: &str,
) -> usize {
    if provider_type.eq_ignore_ascii_case("kiro") {
        parse_admin_provider_oauth_kiro_batch_import_entries(raw_credentials).len()
    } else {
        parse_admin_provider_oauth_batch_import_entries(provider_type, raw_credentials).len()
    }
}

pub(super) async fn execute_admin_provider_oauth_batch_import_for_provider_type(
    state: &AdminAppState<'_>,
    provider_id: &str,
    provider_type: &str,
    raw_credentials: &str,
    proxy_node_id: Option<&str>,
    progress: Option<&mut dyn AdminProviderOAuthBatchProgressReporter>,
) -> Result<AdminProviderOAuthBatchImportOutcome, GatewayError> {
    if provider_type.eq_ignore_ascii_case("kiro") {
        execute_admin_provider_oauth_kiro_batch_import(
            state,
            provider_id,
            raw_credentials,
            proxy_node_id,
            progress,
        )
        .await
    } else {
        let entries =
            parse_admin_provider_oauth_batch_import_entries(provider_type, raw_credentials);
        execute_admin_provider_oauth_batch_import(
            state,
            provider_id,
            provider_type,
            &entries,
            proxy_node_id,
            progress,
        )
        .await
    }
}

async fn resolve_admin_provider_oauth_batch_import_tokens(
    state: &AdminAppState<'_>,
    template: Option<AdminProviderOAuthTemplate>,
    provider_type: &str,
    entry: &AdminProviderOAuthBatchImportEntry,
    request_proxy: Option<ProxySnapshot>,
) -> Result<AdminProviderOAuthResolvedBatchImport, String> {
    if provider_type.eq_ignore_ascii_case("codex") {
        if let Some(auth_config) = codex_agent_identity_auth_config_from_import(entry)? {
            return Ok(AdminProviderOAuthResolvedBatchImport {
                // Agent Identity signs an assertion for every request. The existing OAuth
                // record keeps a placeholder in its encrypted token column only.
                access_token: "__placeholder__".to_string(),
                auth_config,
                expires_at: None,
            });
        }
    }

    let refresh_token = entry
        .refresh_token
        .as_deref()
        .map(str::trim)
        .filter(|value| !value.is_empty());
    let access_token = entry
        .access_token
        .as_deref()
        .map(str::trim)
        .filter(|value| !value.is_empty());
    let is_claude = provider_type.eq_ignore_ascii_case("claude_code");
    if is_claude
        && refresh_token
            .into_iter()
            .chain(access_token)
            .any(is_claude_session_key)
    {
        return Err("Claude sessionKey 请使用 Cookie 授权，不能作为导入凭据".to_string());
    }

    if provider_type.eq_ignore_ascii_case("windsurf") {
        let token_for_import = refresh_token.or(access_token);
        let ctx = ProviderOAuthTransportContext {
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
            network: aether_oauth::network::OAuthNetworkContext::provider_operation(
                request_proxy.clone(),
            ),
        };
        let executor = crate::oauth::GatewayOAuthHttpExecutor::new(*state);
        let result = ProviderOAuthService::with_builtin_adapters()
            .import_credentials(
                &executor,
                &ctx,
                ProviderOAuthImportInput {
                    provider_type: provider_type.to_string(),
                    name: entry
                        .raw_credentials
                        .as_ref()
                        .and_then(|raw| raw.get("name"))
                        .and_then(Value::as_str)
                        .map(str::trim)
                        .filter(|value| !value.is_empty())
                        .map(ToOwned::to_owned),
                    refresh_token: token_for_import.map(ToOwned::to_owned),
                    raw_credentials: entry.raw_credentials.clone(),
                    network: ctx.network.clone(),
                },
            )
            .await
            .map_err(|error| sanitize_windsurf_batch_import_error(&error))?;
        let access_token = result.token_set.access_token.trim().to_string();
        if access_token.is_empty() {
            return Err("Windsurf 凭据验证返回缺少 apiKey/sessionToken".to_string());
        }
        let auth_config = result
            .auth_config
            .as_object()
            .cloned()
            .ok_or_else(|| "Windsurf 凭据验证返回缺少 auth_config".to_string())?;
        return Ok(AdminProviderOAuthResolvedBatchImport {
            access_token,
            auth_config,
            expires_at: result.token_set.expires_at_unix_secs,
        });
    }

    if let Some(refresh_token) = refresh_token {
        let Some(template) = template else {
            if can_fallback_batch_refresh_to_access_token(provider_type, access_token) {
                if let Some(access_token) = access_token {
                    let (auth_config, expires_at) = build_provider_access_token_import_auth_config(
                        provider_type,
                        access_token,
                        Some(refresh_token),
                        entry.expires_at,
                        Some("Provider 不支持 Refresh Token 交换，已回退为 Session Token 导入"),
                    );
                    return Ok(AdminProviderOAuthResolvedBatchImport {
                        access_token: access_token.to_string(),
                        auth_config,
                        expires_at,
                    });
                }
            }
            return Err(
                "该 Provider 不支持 Refresh Token 导入，请提供 sso_token 或 access_token"
                    .to_string(),
            );
        };

        // WorkBuddy 刷新要官方客户端头（X-Machine-ID / X-Enterprise-ID），只能由身份派生；
        // 其它 provider 不需要，传 None 保持原样。
        let refresh_identity = provider_type
            .trim()
            .eq_ignore_ascii_case("workbuddy")
            .then(|| workbuddy_batch_refresh_identity(entry))
            .flatten();
        let token_payload = match exchange_admin_provider_oauth_refresh_token_failure(
            state,
            template,
            refresh_token,
            request_proxy.clone(),
            refresh_identity.as_ref(),
        )
        .await
        {
            Ok(payload) => payload,
            Err(failure) => {
                let detail = sanitize_admin_provider_oauth_batch_error_detail(&failure.detail);
                if can_fallback_batch_refresh_to_access_token(provider_type, access_token) {
                    if let Some(access_token) = access_token {
                        let (auth_config, expires_at) =
                            build_provider_access_token_import_auth_config(
                                provider_type,
                                access_token,
                                Some(refresh_token),
                                entry.expires_at,
                                Some(detail.as_str()),
                            );
                        return Ok(AdminProviderOAuthResolvedBatchImport {
                            access_token: access_token.to_string(),
                            auth_config,
                            expires_at,
                        });
                    }
                }
                log_admin_provider_oauth_batch_refresh_failure(
                    provider_type,
                    entry,
                    &failure,
                    &detail,
                );
                return Err(format!("Token 验证失败: {detail}"));
            }
        };

        let (mut auth_config, access_token, returned_refresh_token, expires_at) =
            build_provider_oauth_auth_config_from_token_payload(provider_type, &token_payload);
        let Some(access_token) = access_token else {
            return Err("Token 刷新返回缺少 access_token".to_string());
        };

        let refresh_token = returned_refresh_token
            .or_else(|| Some(refresh_token.to_string()))
            .filter(|value| !value.trim().is_empty());
        if let Some(refresh_token) = refresh_token.as_ref() {
            auth_config.insert("refresh_token".to_string(), json!(refresh_token));
        }
        return Ok(AdminProviderOAuthResolvedBatchImport {
            access_token,
            auth_config,
            expires_at,
        });
    }

    if let Some(access_token) = access_token {
        let now_unix_secs = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .ok()
            .map(|duration| duration.as_secs())
            .unwrap_or(0);
        validate_batch_access_token_import(
            provider_type,
            access_token,
            entry.expires_at,
            now_unix_secs,
        )?;
        let (auth_config, expires_at) = build_provider_access_token_import_auth_config(
            provider_type,
            access_token,
            None,
            entry.expires_at,
            None,
        );
        return Ok(AdminProviderOAuthResolvedBatchImport {
            access_token: access_token.to_string(),
            auth_config,
            expires_at,
        });
    }

    Err("Refresh Token 或 Access Token 不能为空".to_string())
}

pub(super) async fn execute_admin_provider_oauth_batch_import(
    state: &AdminAppState<'_>,
    provider_id: &str,
    provider_type: &str,
    entries: &[AdminProviderOAuthBatchImportEntry],
    proxy_node_id: Option<&str>,
    mut progress: Option<&mut dyn AdminProviderOAuthBatchProgressReporter>,
) -> Result<AdminProviderOAuthBatchImportOutcome, GatewayError> {
    let Some(provider) = state
        .read_provider_catalog_providers_by_ids(&[provider_id.to_string()])
        .await?
        .into_iter()
        .next()
    else {
        return Ok(AdminProviderOAuthBatchImportOutcome {
            total: entries.len(),
            success: 0,
            failed: entries.len(),
            results: entries
                .iter()
                .enumerate()
                .map(|(index, _)| {
                    json!({
                        "index": index,
                        "status": "error",
                        "error": "Provider 不存在",
                        "replaced": false,
                    })
                })
                .collect(),
        });
    };

    // WorkBuddy「国内 / 国际」双实例：**先按域筛，再校验 Token**。
    //
    // 顺序很关键：Token 校验要打上游，跨域凭据在那里只会得到一句「Token 验证失败」
    // （真机实测），运营完全看不出是「加错实例了」。所以这里先读实例 realm，把跨域条目
    // 直接在结果里标清楚，一条上游请求都不用发。
    let workbuddy_instance_realm = if provider_type.eq_ignore_ascii_case("workbuddy") {
        provider
            .config
            .as_ref()
            .and_then(|config| config.get("workbuddy"))
            .and_then(|bucket| bucket.get("realm"))
            .and_then(Value::as_str)
            .map(|realm| realm.trim().to_ascii_lowercase())
            .filter(|realm| realm == "cn" || realm == "global")
    } else {
        None
    };
    if let Some(instance_realm) = workbuddy_instance_realm.as_deref() {
        let mut rejected: Vec<serde_json::Value> = Vec::new();
        for (index, entry) in entries.iter().enumerate() {
            let credential_realm = workbuddy_batch_entry_realm(entry);
            if credential_realm != instance_realm {
                rejected.push(json!({
                    "index": index,
                    "status": "error",
                    "error": format!(
                        "该供应商固定为{instance_realm}版，不能添加{credential_realm}账号：请到对应区域的供应商实例里添加",
                    ),
                    "replaced": false,
                }));
            }
        }
        if !rejected.is_empty() {
            let mut results: Vec<serde_json::Value> = rejected;
            for index in 0..entries.len() {
                if !results
                    .iter()
                    .any(|item| item.get("index").and_then(Value::as_u64) == Some(index as u64))
                {
                    results.push(json!({
                        "index": index,
                        "status": "error",
                        "error": "未执行：同一批次里存在跨域凭据，已整批拦下",
                        "replaced": false,
                    }));
                }
            }
            results.sort_by_key(|item| item.get("index").and_then(Value::as_u64).unwrap_or(0));
            return Ok(AdminProviderOAuthBatchImportOutcome {
                total: entries.len(),
                success: 0,
                failed: entries.len(),
                results,
            });
        }
    }

    let template = admin_provider_oauth_template(provider_type);
    if template.is_none()
        && !provider_type.eq_ignore_ascii_case("windsurf")
        && !provider_type_supports_access_token_import(provider_type)
    {
        return Ok(AdminProviderOAuthBatchImportOutcome {
            total: entries.len(),
            success: 0,
            failed: entries.len(),
            results: entries
                .iter()
                .enumerate()
                .map(|(index, _)| {
                    json!({
                        "index": index,
                        "status": "error",
                        "error": ADMIN_PROVIDER_OAUTH_DATA_UNAVAILABLE_DETAIL,
                        "replaced": false,
                    })
                })
                .collect(),
        });
    }

    let endpoint_resolution =
        resolve_provider_oauth_runtime_endpoints(state, &provider, provider_type).await?;
    let endpoints = endpoint_resolution.endpoints;
    let api_formats = provider_oauth_active_api_formats(&endpoints);
    let runtime_endpoint = endpoint_resolution.runtime_endpoint;
    let request_proxy = state
        .resolve_admin_provider_oauth_operation_proxy_snapshot(
            proxy_node_id,
            &[
                runtime_endpoint
                    .as_ref()
                    .and_then(|endpoint| endpoint.proxy.as_ref()),
                provider.proxy.as_ref(),
            ],
        )
        .await;
    let key_proxy = provider_oauth_key_proxy_value(proxy_node_id);
    let mut results = Vec::with_capacity(entries.len());
    let mut success = 0usize;
    let mut failed = 0usize;

    for (index, entry) in entries.iter().enumerate() {
        if let Some(error) = entry.parse_error.as_ref() {
            failed += 1;
            results.push(json!({
                "index": index,
                "status": "error",
                "error": error,
                "replaced": false,
            }));
            maybe_report_admin_provider_oauth_batch_import_progress(
                &mut progress,
                entries.len(),
                success,
                failed,
                &results,
            )
            .await;
            continue;
        }

        let resolved_import = match resolve_admin_provider_oauth_batch_import_tokens(
            state,
            template,
            provider_type,
            entry,
            request_proxy.clone(),
        )
        .await
        {
            Ok(value) => value,
            Err(error) => {
                failed += 1;
                results.push(json!({
                    "index": index,
                    "status": "error",
                    "error": error,
                    "replaced": false,
                }));
                maybe_report_admin_provider_oauth_batch_import_progress(
                    &mut progress,
                    entries.len(),
                    success,
                    failed,
                    &results,
                )
                .await;
                continue;
            }
        };
        let AdminProviderOAuthResolvedBatchImport {
            access_token,
            mut auth_config,
            mut expires_at,
        } = resolved_import;
        apply_admin_provider_oauth_batch_import_hints(provider_type, entry, &mut auth_config);
        if let Some(header_access_token) =
            provider_oauth_import_authorization_bearer_token(entry.request_headers.as_ref())
        {
            if let Some(header_expires_at) =
                decode_access_token_expires_at(&header_access_token).or(entry.expires_at)
            {
                auth_config.insert("expires_at".to_string(), json!(header_expires_at));
                expires_at = Some(header_expires_at);
            } else {
                auth_config.remove("expires_at");
                expires_at = None;
            }
        }

        let is_agent_identity = provider_type.eq_ignore_ascii_case("codex")
            && aether_provider_transport::is_codex_agent_identity_auth_config_value(
                &Value::Object(auth_config.clone()),
            );
        let codex_oauth_account_leases =
            if provider_type.eq_ignore_ascii_case("codex") && !is_agent_identity {
                match acquire_codex_oauth_account_locks(
                    state,
                    provider_id,
                    &auth_config,
                    "batch-import",
                )
                .await
                {
                    Ok(leases) => leases,
                    Err(error) => {
                        failed += 1;
                        results.push(json!({
                            "index": index,
                            "status": "error",
                            "error": error.detail(),
                            "replaced": false,
                        }));
                        maybe_report_admin_provider_oauth_batch_import_progress(
                            &mut progress,
                            entries.len(),
                            success,
                            failed,
                            &results,
                        )
                        .await;
                        continue;
                    }
                }
            } else {
                Vec::new()
            };

        let duplicate =
            match find_duplicate_provider_oauth_key(state, provider_id, &auth_config, None).await {
                Ok(value) => value,
                Err(detail) => {
                    release_codex_oauth_account_locks(state, codex_oauth_account_leases).await;
                    failed += 1;
                    results.push(json!({
                        "index": index,
                        "status": "error",
                        "error": detail,
                        "replaced": false,
                    }));
                    maybe_report_admin_provider_oauth_batch_import_progress(
                        &mut progress,
                        entries.len(),
                        success,
                        failed,
                        &results,
                    )
                    .await;
                    continue;
                }
            };

        let replaced = duplicate.is_some();
        let (persisted_key, key_name) = if let Some(existing_key) = duplicate {
            let update_result = update_existing_provider_oauth_catalog_key(
                state,
                &existing_key,
                provider_type,
                &access_token,
                &auth_config,
                &api_formats,
                key_proxy.clone(),
                expires_at,
            )
            .await;
            match update_result {
                Err(error) => {
                    release_codex_oauth_account_locks(state, codex_oauth_account_leases).await;
                    return Err(error);
                }
                Ok(Some(key)) => (key, existing_key.name.clone()),
                Ok(None) => {
                    release_codex_oauth_account_locks(state, codex_oauth_account_leases).await;
                    failed += 1;
                    results.push(json!({
                        "index": index,
                        "status": "error",
                        "error": "provider oauth write unavailable",
                        "replaced": true,
                    }));
                    maybe_report_admin_provider_oauth_batch_import_progress(
                        &mut progress,
                        entries.len(),
                        success,
                        failed,
                        &results,
                    )
                    .await;
                    continue;
                }
            }
        } else {
            let key_name = admin_provider_oauth_key_name_from_auth_config(
                provider_type,
                &auth_config,
                Some(index),
            );
            let create_result = create_provider_oauth_catalog_key(
                state,
                provider_id,
                provider_type,
                key_name.as_str(),
                &access_token,
                &auth_config,
                &api_formats,
                key_proxy.clone(),
                expires_at,
            )
            .await;
            match create_result {
                Err(error) => {
                    release_codex_oauth_account_locks(state, codex_oauth_account_leases).await;
                    return Err(error);
                }
                Ok(Some(key)) => (key, key_name),
                Ok(None) => {
                    release_codex_oauth_account_locks(state, codex_oauth_account_leases).await;
                    failed += 1;
                    results.push(json!({
                        "index": index,
                        "status": "error",
                        "error": "provider oauth write unavailable",
                        "replaced": false,
                    }));
                    maybe_report_admin_provider_oauth_batch_import_progress(
                        &mut progress,
                        entries.len(),
                        success,
                        failed,
                        &results,
                    )
                    .await;
                    continue;
                }
            }
        };
        release_codex_oauth_account_locks(state, codex_oauth_account_leases).await;

        spawn_provider_oauth_account_state_refresh_after_update(
            state.cloned_app(),
            provider.clone(),
            persisted_key.id.clone(),
            request_proxy.clone(),
        );

        success += 1;
        results.push(json!({
            "index": index,
            "status": "success",
            "key_id": persisted_key.id,
            "key_name": key_name,
            "error": serde_json::Value::Null,
            "replaced": replaced,
        }));
        maybe_report_admin_provider_oauth_batch_import_progress(
            &mut progress,
            entries.len(),
            success,
            failed,
            &results,
        )
        .await;
    }

    Ok(AdminProviderOAuthBatchImportOutcome {
        total: entries.len(),
        success,
        failed,
        results,
    })
}

#[cfg(test)]
mod tests {
    use super::super::parse::parse_admin_provider_oauth_batch_import_entries;
    use super::{
        can_fallback_batch_refresh_to_access_token, codex_agent_identity_auth_config_from_import,
        sanitize_windsurf_batch_import_error, validate_batch_access_token_import,
    };
    use aether_oauth::core::OAuthError;
    use serde_json::json;

    #[test]
    fn windsurf_batch_import_error_redacts_http_body() {
        let error = OAuthError::HttpStatus {
            status_code: 401,
            body_excerpt: "sessionToken=devin-session-token$secret".to_string(),
        };

        let detail = sanitize_windsurf_batch_import_error(&error);

        assert_eq!(detail, "Windsurf 凭据验证失败: HTTP 401");
        assert!(!detail.contains("devin-session-token$secret"));
    }

    #[test]
    fn windsurf_batch_import_error_redacts_provider_detail() {
        let error = OAuthError::invalid_response("apiKey=sk-secret token=secret-token");

        let detail = sanitize_windsurf_batch_import_error(&error);

        assert_eq!(detail, "Windsurf 凭据验证失败");
        assert!(!detail.contains("sk-secret"));
        assert!(!detail.contains("secret-token"));
    }

    #[test]
    fn claude_batch_refresh_failure_never_falls_back_to_imported_access_token() {
        assert!(!can_fallback_batch_refresh_to_access_token(
            "claude_code",
            Some("sk-ant-oat01-stale")
        ));
        assert!(can_fallback_batch_refresh_to_access_token(
            "codex",
            Some("fallback-access-token")
        ));
    }

    #[test]
    fn workbuddy_batch_refresh_failure_falls_back_to_imported_access_token() {
        assert!(can_fallback_batch_refresh_to_access_token(
            "workbuddy",
            Some("workbuddy-access-token")
        ));
        assert!(can_fallback_batch_refresh_to_access_token(
            " WorkBuddy ",
            Some("workbuddy-access-token")
        ));
        // 没有 accessToken 就没有兜底可选，只能报错。
        assert!(!can_fallback_batch_refresh_to_access_token(
            "workbuddy",
            None
        ));
        // 不支持 accessToken 导入的类型（windsurf）也不兜底。
        assert!(!can_fallback_batch_refresh_to_access_token(
            "windsurf",
            Some("devin-session-token")
        ));
    }

    #[test]
    fn claude_batch_access_only_requires_oat_prefix_and_future_expiry() {
        let now = 2_000_000_000;
        assert!(validate_batch_access_token_import(
            "claude_code",
            "sk-ant-oat01-valid",
            Some(now + 3600),
            now,
        )
        .is_ok());
        assert!(validate_batch_access_token_import(
            "claude_code",
            "not-an-oat",
            Some(now + 3600),
            now,
        )
        .is_err());
        assert!(validate_batch_access_token_import(
            "claude_code",
            "sk-ant-oat01-missing-expiry",
            None,
            now,
        )
        .is_err());
        assert!(validate_batch_access_token_import(
            "claude_code",
            "sk-ant-oat01-expired",
            Some(now),
            now,
        )
        .is_err());
    }

    #[test]
    fn normalizes_codex_agent_identity_import_without_access_token() {
        let entries = parse_admin_provider_oauth_batch_import_entries(
            "codex",
            r#"{
                "type":"sub2api-data",
                "version":1,
                "accounts":[{
                    "name":"agent@example.com",
                    "platform":"openai",
                    "credentials":{
                        "auth_mode":"agentIdentity",
                        "id_token":"stale-id-token",
                        "sessionToken":"stale-session-token",
                        "apiKey":"stale-api-key",
                        "cookie":"stale-cookie",
                        "headers":{
                            "authorization":"Bearer stale-bearer-token",
                            "cookie":"stale-header-cookie",
                            "x-api-key":"stale-header-api-key"
                        },
                        "profile":{"token":"stale-deep-token"},
                        "agent_identity":{
                            "agent_runtime_id":"runtime-1",
                            "agent_private_key":"MC4CAQAwBQYDK2VwBCIEIAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
                            "accountId":"account-1",
                            "chatgptUserId":"user-1",
                            "chatgptAccountIsFedramp":true,
                            "access_token":"stale-access-token",
                            "refreshToken":"stale-refresh-token",
                            "headers":{"authorization":"Bearer stale-nested-bearer"}
                        }
                    }
                }]
            }"#,
        );

        let auth_config = codex_agent_identity_auth_config_from_import(&entries[0])
            .expect("Agent Identity import should validate")
            .expect("Agent Identity config should be recognized");

        assert_eq!(auth_config.get("provider_type"), Some(&json!("codex")));
        assert_eq!(auth_config.get("auth_mode"), Some(&json!("agentIdentity")));
        assert_eq!(
            auth_config.get("agent_runtime_id"),
            Some(&json!("runtime-1"))
        );
        assert_eq!(auth_config.get("account_id"), Some(&json!("account-1")));
        assert_eq!(auth_config.get("user_id"), Some(&json!("user-1")));
        assert_eq!(auth_config.get("is_fedramp"), Some(&json!(true)));
        assert_eq!(
            auth_config.get("account_name"),
            Some(&json!("agent@example.com"))
        );
        assert!(!auth_config.contains_key("id_token"));
        assert!(auth_config
            .get("agent_identity")
            .and_then(serde_json::Value::as_object)
            .is_some_and(|nested| !nested.contains_key("access_token")));
        let serialized = serde_json::to_string(&auth_config).expect("auth config should serialize");
        for secret in [
            "stale-id-token",
            "stale-session-token",
            "stale-api-key",
            "stale-cookie",
            "stale-bearer-token",
            "stale-header-cookie",
            "stale-header-api-key",
            "stale-deep-token",
            "stale-access-token",
            "stale-refresh-token",
            "stale-nested-bearer",
        ] {
            assert!(!serialized.contains(secret), "secret leaked: {secret}");
        }
        for forbidden_key in [
            "access_token",
            "refreshToken",
            "sessionToken",
            "apiKey",
            "cookie",
            "headers",
            "profile",
        ] {
            assert!(
                !serialized.contains(forbidden_key),
                "forbidden key persisted: {forbidden_key}"
            );
        }
    }
}
