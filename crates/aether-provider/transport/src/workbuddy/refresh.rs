//! WorkBuddy（腾讯 CodeBuddy）本地 OAuth 刷新适配器。
//!
//! 为什么不能用 `GenericOAuthRefreshAdapter`：那条路走的是标准 `grant_type=
//! refresh_token` 表单/JSON 授权，而 WorkBuddy 的刷新是
//! **`POST /v2/plugin/auth/token/refresh`、无 body、凭证放 `X-Refresh-Token` 头**，
//! 还要求官方桌面端指纹头族。所以这里像 kiro 一样自带一个本地适配器，
//! 把刷新协议委托给 `aether-oauth` 的 `WorkbuddyProviderOAuthAdapter`。
//!
//! 没有这个适配器会发生什么（两者都是静默的）：
//! 1. `policy.rs` 对「有 auth_config 但没有本地 OAuth 解析」的密钥返回
//!    `transport_oauth_resolution_unsupported`，本地 `openai:chat` 计划直接被否；
//! 2. `maintenance/runtime/oauth_token_refresh.rs` 的候选过滤走到 `Ok(None)`，
//!    token 过期后没人续，请求全部 401。

use std::collections::BTreeMap;

use aether_oauth::provider::providers::WorkbuddyProviderOAuthAdapter;
use aether_oauth::provider::{ProviderOAuthAccount, ProviderOAuthAdapter, ProviderOAuthTokenSet};
use async_trait::async_trait;
use serde_json::Value;
use sha2::{Digest, Sha256};

use super::{is_workbuddy_provider_transport, workbuddy_identity};
use crate::oauth_refresh::{
    oauth_error_to_local_refresh_error, provider_oauth_transport_context_from_snapshot,
    CachedOAuthEntry, LocalOAuthHttpExecutor, LocalOAuthRefreshAdapter, LocalOAuthRefreshError,
    LocalResolvedOAuthRequestAuth, ProviderOAuthLocalHttpExecutor,
};
use crate::snapshot::GatewayProviderTransportSnapshot;

const AUTH_HEADER_NAME: &str = "authorization";
/// 到期前多久开始续（与 generic 适配器同口径）。
const OAUTH_REFRESH_SKEW_SECS: u64 = 120;
/// 刷新请求的展示名（同 provider_type，便于日志与 `refresh_fingerprint` 对齐）。
const PROVIDER_TYPE: &str = super::WORKBUDDY_PROVIDER_TYPE;

/// 本 provider 是否支持**本地** OAuth 解析（gateway 内直接解出 Authorization）。
pub fn supports_local_workbuddy_request_auth_resolution(
    transport: &GatewayProviderTransportSnapshot,
) -> bool {
    is_workbuddy_provider_transport(transport)
        && transport.key.auth_type.trim().eq_ignore_ascii_case("oauth")
}

#[derive(Debug, Clone, Default)]
pub struct WorkbuddyOAuthRefreshAdapter;

impl WorkbuddyOAuthRefreshAdapter {
    pub fn new() -> Self {
        Self
    }

    fn auth_config_from_transport(transport: &GatewayProviderTransportSnapshot) -> Option<Value> {
        transport
            .key
            .decrypted_auth_config
            .as_deref()
            .map(str::trim)
            .filter(|value| !value.is_empty())
            .and_then(|value| serde_json::from_str::<Value>(value).ok())
            .filter(Value::is_object)
    }

    fn auth_config_from_entry(
        transport: &GatewayProviderTransportSnapshot,
        entry: &CachedOAuthEntry,
    ) -> Option<Value> {
        entry
            .metadata
            .as_ref()
            .filter(|_| {
                entry
                    .provider_type
                    .eq_ignore_ascii_case(transport.provider.provider_type.as_str())
                    && workbuddy_cached_entry_matches_transport(transport, entry)
            })
            .cloned()
    }

    fn auth_config_updated_at(auth_config: &Value) -> Option<u64> {
        auth_config
            .as_object()
            .and_then(|object| object.get("updated_at"))
            .and_then(parse_u64_value)
    }

    /// 缓存条目与快照里谁新用谁：请求线程可能刚刷新过，缓存可能落后。
    fn base_auth_config(
        &self,
        transport: &GatewayProviderTransportSnapshot,
        entry: Option<&CachedOAuthEntry>,
    ) -> Option<Value> {
        let cached = entry.and_then(|cached| Self::auth_config_from_entry(transport, cached));
        let transport_auth = Self::auth_config_from_transport(transport);
        match (cached, transport_auth) {
            (Some(cached), Some(transport_auth)) => {
                if Self::auth_config_updated_at(&transport_auth)
                    > Self::auth_config_updated_at(&cached)
                {
                    Some(transport_auth)
                } else {
                    Some(cached)
                }
            }
            (Some(cached), None) => Some(cached),
            (None, Some(transport_auth)) => Some(transport_auth),
            (None, None) => None,
        }
    }

    /// 刷新用的适配器：realm 决定 base_url、Origin/Referer 与 UA 平台段。
    fn adapter_for_transport(
        transport: &GatewayProviderTransportSnapshot,
    ) -> WorkbuddyProviderOAuthAdapter {
        if workbuddy_identity(transport).realm.is_global() {
            WorkbuddyProviderOAuthAdapter::default().with_global_realm()
        } else {
            WorkbuddyProviderOAuthAdapter::default()
        }
    }

    fn resolve_direct_header(
        &self,
        transport: &GatewayProviderTransportSnapshot,
    ) -> Option<LocalResolvedOAuthRequestAuth> {
        if !supports_local_workbuddy_request_auth_resolution(transport) {
            return None;
        }
        let auth_config = Self::auth_config_from_transport(transport);
        let refreshable = auth_config
            .as_ref()
            .and_then(refresh_token_from_auth_config)
            .is_some();
        // 有 refresh_token 且已临近过期：交回刷新，不要拿旧 token 去撞 401。
        if refreshable && expires_at_requires_refresh(transport.key.expires_at_unix_secs) {
            return None;
        }
        let token = current_access_token(transport)
            .or_else(|| auth_config.as_ref().and_then(access_token_from_auth_config))?;
        Some(LocalResolvedOAuthRequestAuth::Header {
            name: AUTH_HEADER_NAME.to_string(),
            value: format!("Bearer {token}"),
        })
    }

    fn build_cached_entry(
        transport: &GatewayProviderTransportSnapshot,
        refreshed: ProviderOAuthTokenSet,
    ) -> CachedOAuthEntry {
        CachedOAuthEntry {
            provider_type: PROVIDER_TYPE.to_string(),
            auth_header_name: AUTH_HEADER_NAME.to_string(),
            auth_header_value: refreshed.token_set.bearer_header_value(),
            expires_at_unix_secs: refreshed.token_set.expires_at_unix_secs,
            metadata: Some(refreshed.auth_config),
            source_fingerprint: Some(workbuddy_transport_source_fingerprint(transport)),
        }
    }
}

#[async_trait]
impl LocalOAuthRefreshAdapter for WorkbuddyOAuthRefreshAdapter {
    fn provider_type(&self) -> &'static str {
        PROVIDER_TYPE
    }

    fn supports(&self, transport: &GatewayProviderTransportSnapshot) -> bool {
        supports_local_workbuddy_request_auth_resolution(transport)
    }

    fn resolve_cached(
        &self,
        transport: &GatewayProviderTransportSnapshot,
        entry: &CachedOAuthEntry,
    ) -> Option<LocalResolvedOAuthRequestAuth> {
        if !entry
            .provider_type
            .eq_ignore_ascii_case(transport.provider.provider_type.as_str())
        {
            return None;
        }
        // 直读能出结果（且没过期）时优先直读：本 provider 的 token 就在 key 上。
        if let Some(direct) = self.resolve_direct_header(transport) {
            return Some(direct);
        }
        if !workbuddy_cached_entry_matches_transport(transport, entry) {
            return None;
        }
        if expires_at_requires_refresh(entry.expires_at_unix_secs) {
            return None;
        }
        resolved_entry_header(entry)
    }

    fn resolve_without_refresh(
        &self,
        transport: &GatewayProviderTransportSnapshot,
    ) -> Option<LocalResolvedOAuthRequestAuth> {
        self.resolve_direct_header(transport)
    }

    fn should_refresh(
        &self,
        transport: &GatewayProviderTransportSnapshot,
        entry: Option<&CachedOAuthEntry>,
    ) -> bool {
        if !supports_local_workbuddy_request_auth_resolution(transport) {
            return false;
        }
        if entry
            .and_then(|cached| self.resolve_cached(transport, cached))
            .is_some()
            || self.resolve_direct_header(transport).is_some()
        {
            return false;
        }
        self.base_auth_config(transport, entry)
            .as_ref()
            .and_then(refresh_token_from_auth_config)
            .is_some()
    }

    fn refresh_fingerprint(
        &self,
        transport: &GatewayProviderTransportSnapshot,
        entry: Option<&CachedOAuthEntry>,
    ) -> Option<String> {
        workbuddy_refresh_fingerprint(transport, entry)
    }

    fn cached_entry_from_transport(
        &self,
        transport: &GatewayProviderTransportSnapshot,
    ) -> Option<CachedOAuthEntry> {
        let Some(LocalResolvedOAuthRequestAuth::Header { name, value }) =
            self.resolve_direct_header(transport)
        else {
            return None;
        };
        let metadata = Self::auth_config_from_transport(transport);
        let expires_at_unix_secs = transport.key.expires_at_unix_secs.or_else(|| {
            metadata
                .as_ref()
                .and_then(auth_config_expires_at)
                .or_else(|| {
                    metadata
                        .as_ref()
                        .and_then(|config| parse_u64_value_field(config, "expires_at"))
                })
        });
        Some(CachedOAuthEntry {
            provider_type: PROVIDER_TYPE.to_string(),
            auth_header_name: name,
            auth_header_value: value,
            expires_at_unix_secs,
            metadata,
            source_fingerprint: Some(workbuddy_transport_source_fingerprint(transport)),
        })
    }

    async fn refresh(
        &self,
        executor: &dyn LocalOAuthHttpExecutor,
        transport: &GatewayProviderTransportSnapshot,
        entry: Option<&CachedOAuthEntry>,
    ) -> Result<Option<CachedOAuthEntry>, LocalOAuthRefreshError> {
        if !supports_local_workbuddy_request_auth_resolution(transport) {
            return Ok(None);
        }
        let Some(auth_config) = self.base_auth_config(transport, entry) else {
            return Ok(None);
        };
        let Some(refresh_token) = refresh_token_from_auth_config(&auth_config) else {
            tracing::warn!(
                key_id = %transport.key.id,
                provider_id = %transport.provider.id,
                provider_type = PROVIDER_TYPE,
                "gateway workbuddy refresh skipped because auth_config has no refresh_token"
            );
            return Ok(None);
        };
        let realm = workbuddy_identity(transport).realm;
        tracing::info!(
            key_id = %transport.key.id,
            provider_id = %transport.provider.id,
            endpoint_id = %transport.endpoint.id,
            provider_type = PROVIDER_TYPE,
            realm = realm.as_str(),
            request_refresh_token_len = refresh_token.len(),
            "gateway workbuddy refresh delegated to provider oauth adapter"
        );

        let adapter = Self::adapter_for_transport(transport);
        let oauth_executor =
            ProviderOAuthLocalHttpExecutor::new(PROVIDER_TYPE, transport, executor);
        let ctx = provider_oauth_transport_context_from_snapshot(transport);
        let account = ProviderOAuthAccount {
            provider_type: PROVIDER_TYPE.to_string(),
            access_token: current_access_token(transport).unwrap_or_default(),
            expires_at_unix_secs: transport.key.expires_at_unix_secs,
            auth_config,
            identity: BTreeMap::new(),
        };
        let refreshed = adapter
            .refresh(&oauth_executor, &ctx, &account)
            .await
            .map_err(|error| oauth_error_to_local_refresh_error(PROVIDER_TYPE, error))?;

        tracing::info!(
            key_id = %transport.key.id,
            provider_id = %transport.provider.id,
            provider_type = PROVIDER_TYPE,
            expires_at_unix_secs = ?refreshed.token_set.expires_at_unix_secs,
            response_has_refresh_token = refreshed.token_set.refresh_token.is_some(),
            "gateway workbuddy refresh succeeded"
        );

        Ok(Some(Self::build_cached_entry(transport, refreshed)))
    }
}

fn workbuddy_transport_source_fingerprint(transport: &GatewayProviderTransportSnapshot) -> String {
    workbuddy_credential_fingerprint(
        transport.provider.provider_type.as_str(),
        transport.key.auth_type.as_str(),
        transport
            .key
            .decrypted_auth_config
            .as_deref()
            .unwrap_or_default(),
        transport.key.decrypted_api_key.as_str(),
    )
}

fn workbuddy_credential_fingerprint(
    provider_type: &str,
    auth_type: &str,
    auth_config: &str,
    access_token: &str,
) -> String {
    let provider_type = provider_type.trim().to_ascii_lowercase();
    let auth_type = auth_type.trim().to_ascii_lowercase();
    let mut digest = Sha256::new();
    for field in [
        provider_type.as_bytes(),
        auth_type.as_bytes(),
        auth_config.as_bytes(),
        access_token.as_bytes(),
    ] {
        digest.update((field.len() as u64).to_be_bytes());
        digest.update(field);
    }
    format!("{:x}", digest.finalize())
}

fn workbuddy_cached_entry_matches_transport(
    transport: &GatewayProviderTransportSnapshot,
    entry: &CachedOAuthEntry,
) -> bool {
    entry.source_fingerprint.as_deref()
        == Some(workbuddy_transport_source_fingerprint(transport).as_str())
}

fn workbuddy_refresh_fingerprint(
    transport: &GatewayProviderTransportSnapshot,
    entry: Option<&CachedOAuthEntry>,
) -> Option<String> {
    if !supports_local_workbuddy_request_auth_resolution(transport) {
        return None;
    }
    entry
        .filter(|entry| {
            entry
                .provider_type
                .eq_ignore_ascii_case(transport.provider.provider_type.as_str())
                && workbuddy_cached_entry_matches_transport(transport, entry)
                && !expires_at_requires_refresh(entry.expires_at_unix_secs)
        })
        .and_then(|entry| {
            let metadata = serde_json::to_string(entry.metadata.as_ref()?).ok()?;
            let access_token = bearer_access_token(entry.auth_header_value.as_str())?;
            Some(workbuddy_credential_fingerprint(
                transport.provider.provider_type.as_str(),
                transport.key.auth_type.as_str(),
                metadata.as_str(),
                access_token,
            ))
        })
        .or_else(|| Some(workbuddy_transport_source_fingerprint(transport)))
}

fn resolved_entry_header(entry: &CachedOAuthEntry) -> Option<LocalResolvedOAuthRequestAuth> {
    let name = entry.auth_header_name.trim();
    let value = entry.auth_header_value.trim();
    if name.is_empty() || value.is_empty() {
        return None;
    }
    Some(LocalResolvedOAuthRequestAuth::Header {
        name: name.to_ascii_lowercase(),
        value: value.to_string(),
    })
}

fn bearer_access_token(authorization: &str) -> Option<&str> {
    let mut parts = authorization.split_ascii_whitespace();
    let scheme = parts.next()?;
    let token = parts.next()?;
    (scheme.eq_ignore_ascii_case("bearer") && parts.next().is_none()).then_some(token)
}

fn current_access_token(transport: &GatewayProviderTransportSnapshot) -> Option<String> {
    let token = transport.key.decrypted_api_key.trim();
    (!token.is_empty()).then(|| token.to_string())
}

fn refresh_token_from_auth_config(auth_config: &Value) -> Option<String> {
    let object = auth_config.as_object()?;
    ["refresh_token", "refreshToken"]
        .iter()
        .find_map(|field| object.get(*field).and_then(non_empty_string))
}

fn access_token_from_auth_config(auth_config: &Value) -> Option<String> {
    let object = auth_config.as_object()?;
    ["access_token", "accessToken"]
        .iter()
        .find_map(|field| object.get(*field).and_then(non_empty_string))
}

fn auth_config_expires_at(auth_config: &Value) -> Option<u64> {
    parse_u64_value_field(auth_config, "expires_at")
}

fn parse_u64_value_field(value: &Value, field: &str) -> Option<u64> {
    value.as_object()?.get(field).and_then(parse_u64_value)
}

fn parse_u64_value(value: &Value) -> Option<u64> {
    match value {
        Value::Number(number) => number.as_u64(),
        Value::String(string) => string.trim().parse::<u64>().ok(),
        _ => None,
    }
}

fn non_empty_string(value: &Value) -> Option<String> {
    value
        .as_str()
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .map(ToOwned::to_owned)
}

fn expires_at_requires_refresh(expires_at_unix_secs: Option<u64>) -> bool {
    let Some(expires_at_unix_secs) = expires_at_unix_secs else {
        return false;
    };
    let Some(now) = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .ok()
        .map(|value| value.as_secs())
    else {
        return false;
    };
    now.saturating_add(OAUTH_REFRESH_SKEW_SECS) >= expires_at_unix_secs
}

#[cfg(test)]
mod tests {
    use serde_json::json;

    use super::{
        expires_at_requires_refresh, refresh_token_from_auth_config,
        supports_local_workbuddy_request_auth_resolution, workbuddy_credential_fingerprint,
        WorkbuddyOAuthRefreshAdapter,
    };
    use crate::oauth_refresh::{
        CachedOAuthEntry, LocalOAuthRefreshAdapter, LocalResolvedOAuthRequestAuth,
    };
    use crate::snapshot::{
        GatewayProviderTransportEndpoint, GatewayProviderTransportKey,
        GatewayProviderTransportProvider, GatewayProviderTransportSnapshot,
    };

    fn sample_transport(
        provider_type: &str,
        auth_type: &str,
        api_key: &str,
        auth_config: Option<serde_json::Value>,
    ) -> GatewayProviderTransportSnapshot {
        GatewayProviderTransportSnapshot {
            provider: GatewayProviderTransportProvider {
                id: "provider-1".to_string(),
                name: "WorkBuddy".to_string(),
                provider_type: provider_type.to_string(),
                website: None,
                is_active: true,
                keep_priority_on_conversion: false,
                enable_format_conversion: true,
                concurrent_limit: None,
                max_retries: None,
                proxy: None,
                request_timeout_secs: None,
                stream_first_byte_timeout_secs: None,
                config: None,
            },
            endpoint: GatewayProviderTransportEndpoint {
                id: "endpoint-1".to_string(),
                provider_id: "provider-1".to_string(),
                api_format: "openai:chat".to_string(),
                api_family: Some("openai".to_string()),
                endpoint_kind: Some("chat".to_string()),
                is_active: true,
                base_url: "https://copilot.tencent.com/".to_string(),
                header_rules: None,
                body_rules: None,
                max_retries: None,
                custom_path: Some("/v2/chat/completions".to_string()),
                config: None,
                format_acceptance_config: None,
                proxy: None,
            },
            key: GatewayProviderTransportKey {
                id: "key-1".to_string(),
                provider_id: "provider-1".to_string(),
                name: "Key".to_string(),
                auth_type: auth_type.to_string(),
                is_active: true,
                api_formats: Some(vec!["openai:chat".to_string()]),
                auth_type_by_format: None,
                allow_auth_channel_mismatch_formats: None,
                allowed_models: None,
                capabilities: None,
                rate_multipliers: None,
                global_priority_by_format: None,
                expires_at_unix_secs: None,
                proxy: None,
                fingerprint: None,
                upstream_metadata: None,
                decrypted_api_key: api_key.to_string(),
                decrypted_auth_config: auth_config.map(|value| value.to_string()),
            },
        }
    }

    #[test]
    fn local_resolution_requires_workbuddy_oauth_keys() {
        let adapter = WorkbuddyOAuthRefreshAdapter::new();
        let oauth = sample_transport(
            "workbuddy",
            "oauth",
            "access-1",
            Some(json!({"uid": "uid-1"})),
        );
        assert!(supports_local_workbuddy_request_auth_resolution(&oauth));
        assert!(adapter.supports(&oauth));

        let bearer = sample_transport("workbuddy", "bearer", "access-1", None);
        assert!(!supports_local_workbuddy_request_auth_resolution(&bearer));

        let other = sample_transport("opencode", "oauth", "access-1", None);
        assert!(!supports_local_workbuddy_request_auth_resolution(&other));
    }

    #[test]
    fn direct_resolution_reads_the_key_access_token() {
        let adapter = WorkbuddyOAuthRefreshAdapter::new();
        let transport = sample_transport(
            "workbuddy",
            "oauth",
            "access-1",
            Some(json!({"uid": "uid-1"})),
        );
        match adapter
            .resolve_without_refresh(&transport)
            .expect("direct header should resolve")
        {
            LocalResolvedOAuthRequestAuth::Header { name, value } => {
                assert_eq!(name, "authorization");
                assert_eq!(value, "Bearer access-1");
            }
            other => panic!("unexpected auth variant: {other:?}"),
        }
    }

    /// token 快过期时不再直读，好让协调器去刷新——否则会拿旧 token 撞 401。
    #[test]
    fn expiring_token_forces_refresh_instead_of_direct_read() {
        let adapter = WorkbuddyOAuthRefreshAdapter::new();
        let mut transport = sample_transport(
            "workbuddy",
            "oauth",
            "access-1",
            Some(json!({"uid": "uid-1", "refresh_token": "refresh-1"})),
        );
        transport.key.expires_at_unix_secs = Some(1);
        assert!(adapter.resolve_without_refresh(&transport).is_none());
        assert!(adapter.should_refresh(&transport, None));

        // 没有 refresh_token 时只能直读（刷也刷不了），不能把自己饿死。
        transport.key.decrypted_auth_config = Some(json!({"uid": "uid-1"}).to_string());
        assert!(adapter.resolve_without_refresh(&transport).is_some());
        assert!(!adapter.should_refresh(&transport, None));
    }

    #[test]
    fn cached_entry_round_trips_and_respects_fingerprint() {
        let adapter = WorkbuddyOAuthRefreshAdapter::new();
        let transport = sample_transport(
            "workbuddy",
            "oauth",
            "access-1",
            Some(json!({"uid": "uid-1"})),
        );
        let entry = adapter
            .cached_entry_from_transport(&transport)
            .expect("cached entry should build");
        assert_eq!(entry.provider_type, "workbuddy");
        assert_eq!(entry.auth_header_value, "Bearer access-1");
        assert!(entry.source_fingerprint.is_some());

        // 直读优先：缓存条目本身也能解出同一个头。
        assert!(adapter.resolve_cached(&transport, &entry).is_some());

        // 指纹不匹配（换了密钥）时必须拒绝**缓存条目里的**凭据：另一把 key
        // 自己没有可直读的 token 时，绝不能把上一个账号的 token 发出去。
        let other = sample_transport(
            "workbuddy",
            "oauth",
            "",
            Some(json!({"uid": "uid-2", "refresh_token": "refresh-2"})),
        );
        assert!(adapter.resolve_cached(&other, &entry).is_none());
        assert!(adapter.refresh_fingerprint(&other, Some(&entry)).is_some());
    }

    #[test]
    fn cached_entry_requires_a_usable_header() {
        let adapter = WorkbuddyOAuthRefreshAdapter::new();
        let transport = sample_transport(
            "workbuddy",
            "oauth",
            "",
            Some(json!({"uid": "uid-1", "refresh_token": "refresh-1"})),
        );
        assert!(adapter.cached_entry_from_transport(&transport).is_none());
        assert!(adapter.should_refresh(&transport, None));
    }

    #[test]
    fn helpers_match_the_core_adapter_conventions() {
        assert!(refresh_token_from_auth_config(&json!({"refreshToken": "r"})).is_some());
        assert!(refresh_token_from_auth_config(&json!({"uid": "u"})).is_none());
        assert!(!expires_at_requires_refresh(None));
        assert!(expires_at_requires_refresh(Some(1)));

        let fingerprint_a = workbuddy_credential_fingerprint("workbuddy", "oauth", "{}", "a");
        let fingerprint_b = workbuddy_credential_fingerprint("workbuddy", "oauth", "{}", "b");
        assert_eq!(fingerprint_a.len(), 64);
        assert_ne!(fingerprint_a, fingerprint_b);
    }

    #[test]
    fn refresh_reports_none_without_a_refresh_token() {
        let adapter = WorkbuddyOAuthRefreshAdapter::new();
        let transport = sample_transport(
            "workbuddy",
            "oauth",
            "access-1",
            Some(json!({"uid": "uid-1"})),
        );
        assert!(!adapter.should_refresh(&transport, None));
        let cached = CachedOAuthEntry {
            provider_type: "workbuddy".to_string(),
            auth_header_name: "authorization".to_string(),
            auth_header_value: "Bearer access-1".to_string(),
            expires_at_unix_secs: None,
            metadata: transport
                .key
                .decrypted_auth_config
                .as_deref()
                .and_then(|value| serde_json::from_str(value).ok()),
            source_fingerprint: Some(super::workbuddy_transport_source_fingerprint(&transport)),
        };
        assert!(adapter.resolve_cached(&transport, &cached).is_some());
    }
}
