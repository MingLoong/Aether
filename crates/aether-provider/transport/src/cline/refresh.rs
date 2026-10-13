//! Cline 账号模式（OAuth）的本地刷新适配器。
//!
//! 桥接到 aether-oauth 的 `ClineProviderOAuthAdapter`（WorkOS 设备码 → `/auth/register` →
//! `/auth/refresh` → 自愈）。落库的 access_token 已是可直接下发的 `workos:<token>`，
//! 所以「解析请求鉴权」跟 windsurf 一样就是 `Bearer <存的值>`；「刷新」走 Cline 专属协议。

use std::collections::BTreeMap;

use aether_oauth::provider::providers::ClineProviderOAuthAdapter;
use aether_oauth::provider::{ProviderOAuthAccount, ProviderOAuthAdapter, ProviderOAuthTokenSet};
use async_trait::async_trait;
use serde_json::Value;
use sha2::{Digest, Sha256};

use crate::oauth_refresh::{
    oauth_error_to_local_refresh_error, provider_oauth_transport_context_from_snapshot,
    CachedOAuthEntry, LocalOAuthHttpExecutor, LocalOAuthRefreshAdapter, LocalOAuthRefreshError,
    LocalResolvedOAuthRequestAuth, ProviderOAuthLocalHttpExecutor,
};
use crate::snapshot::GatewayProviderTransportSnapshot;

use super::resolve_local_cline_request_auth;

const AUTH_HEADER_NAME: &str = "authorization";
const OAUTH_REFRESH_SKEW_SECS: u64 = 120;
const PROVIDER_TYPE: &str = "cline";

/// Cline 账号模式的密钥：`auth_type = oauth`。sk_ 密钥走普通 api_key 路径，不经过这里。
fn is_cline_oauth_account_transport(transport: &GatewayProviderTransportSnapshot) -> bool {
    transport
        .provider
        .provider_type
        .trim()
        .eq_ignore_ascii_case(PROVIDER_TYPE)
        && transport.key.auth_type.trim().eq_ignore_ascii_case("oauth")
}

fn auth_config_from_transport(transport: &GatewayProviderTransportSnapshot) -> Option<Value> {
    transport
        .key
        .decrypted_auth_config
        .as_deref()
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .and_then(|value| serde_json::from_str::<Value>(value).ok())
}

fn refresh_token_from_auth_config(auth_config: &Value) -> Option<String> {
    let object = auth_config.as_object()?;
    ["refresh_token", "refreshToken"]
        .iter()
        .find_map(|field| object.get(*field).and_then(Value::as_str))
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .map(str::to_string)
}

fn auth_config_expires_at(auth_config: &Value) -> Option<u64> {
    auth_config
        .as_object()
        .and_then(|object| object.get("expires_at"))
        .and_then(|value| match value {
            Value::Number(number) => number.as_u64(),
            Value::String(string) => string.trim().parse::<u64>().ok(),
            _ => None,
        })
}

fn transport_expires_at(transport: &GatewayProviderTransportSnapshot) -> Option<u64> {
    transport.key.expires_at_unix_secs.or_else(|| {
        auth_config_from_transport(transport).and_then(|config| auth_config_expires_at(&config))
    })
}

fn expires_at_requires_refresh(expires_at_unix_secs: Option<u64>) -> bool {
    expires_at_unix_secs
        .map(|expires_at| {
            aether_oauth::core::current_unix_secs()
                >= expires_at.saturating_sub(OAUTH_REFRESH_SKEW_SECS)
        })
        .unwrap_or(false)
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

fn cline_credential_fingerprint(transport: &GatewayProviderTransportSnapshot) -> String {
    let auth_config = transport
        .key
        .decrypted_auth_config
        .as_deref()
        .unwrap_or_default();
    let mut digest = Sha256::new();
    for field in [
        b"cline".as_slice(),
        transport.key.auth_type.as_bytes(),
        auth_config.as_bytes(),
        transport.key.decrypted_api_key.as_bytes(),
    ] {
        digest.update((field.len() as u64).to_be_bytes());
        digest.update(field);
    }
    format!("{:x}", digest.finalize())
}

#[derive(Clone, Default)]
pub struct ClineOAuthRefreshAdapter;

impl ClineOAuthRefreshAdapter {
    fn resolve_direct_header(
        &self,
        transport: &GatewayProviderTransportSnapshot,
    ) -> Option<LocalResolvedOAuthRequestAuth> {
        let (name, value) = resolve_local_cline_request_auth(transport)?;
        let refreshable = auth_config_from_transport(transport)
            .as_ref()
            .and_then(refresh_token_from_auth_config)
            .is_some();
        // 到期且可刷新时返回 None，让 coordinator 走刷新而不是把过期 token 发出去。
        if refreshable && expires_at_requires_refresh(transport_expires_at(transport)) {
            return None;
        }
        Some(LocalResolvedOAuthRequestAuth::Header { name, value })
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
            source_fingerprint: Some(cline_credential_fingerprint(transport)),
        }
    }
}

#[async_trait]
impl LocalOAuthRefreshAdapter for ClineOAuthRefreshAdapter {
    fn provider_type(&self) -> &'static str {
        PROVIDER_TYPE
    }

    fn supports(&self, transport: &GatewayProviderTransportSnapshot) -> bool {
        is_cline_oauth_account_transport(transport)
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
        if !self.supports(transport) {
            return false;
        }
        if entry
            .and_then(|cached| self.resolve_cached(transport, cached))
            .is_some()
            || self.resolve_direct_header(transport).is_some()
        {
            return false;
        }
        auth_config_from_transport(transport)
            .as_ref()
            .and_then(refresh_token_from_auth_config)
            .is_some()
    }

    fn refresh_fingerprint(
        &self,
        transport: &GatewayProviderTransportSnapshot,
        _entry: Option<&CachedOAuthEntry>,
    ) -> Option<String> {
        self.supports(transport)
            .then(|| cline_credential_fingerprint(transport))
    }

    async fn refresh(
        &self,
        executor: &dyn LocalOAuthHttpExecutor,
        transport: &GatewayProviderTransportSnapshot,
        _entry: Option<&CachedOAuthEntry>,
    ) -> Result<Option<CachedOAuthEntry>, LocalOAuthRefreshError> {
        let Some(auth_config) = auth_config_from_transport(transport) else {
            return Ok(None);
        };
        if refresh_token_from_auth_config(&auth_config).is_none() {
            tracing::warn!(
                key_id = %transport.key.id,
                provider_id = %transport.provider.id,
                provider_type = PROVIDER_TYPE,
                "gateway cline oauth refresh skipped because auth_config has no refresh_token"
            );
            return Ok(None);
        }

        let oauth_executor =
            ProviderOAuthLocalHttpExecutor::new(PROVIDER_TYPE, transport, executor);
        let ctx = provider_oauth_transport_context_from_snapshot(transport);
        let account = ProviderOAuthAccount {
            provider_type: PROVIDER_TYPE.to_string(),
            access_token: transport.key.decrypted_api_key.clone(),
            expires_at_unix_secs: transport_expires_at(transport),
            auth_config,
            identity: BTreeMap::new(),
        };
        let adapter = ClineProviderOAuthAdapter::default();
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
            "gateway cline oauth refresh succeeded"
        );

        Ok(Some(Self::build_cached_entry(transport, refreshed)))
    }
}
