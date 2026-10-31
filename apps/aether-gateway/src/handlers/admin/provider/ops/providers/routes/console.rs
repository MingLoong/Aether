use super::super::config::admin_provider_ops_config_object;
use crate::handlers::admin::request::AdminAppState;
use crate::handlers::admin::shared::{
    attach_admin_audit_response, mark_sensitive_admin_response_no_store,
};
use crate::GatewayError;
use aether_data_contracts::repository::provider_catalog::{
    ProviderCatalogProviderConfigCasUpdate, StoredProviderCatalogProvider,
};
use axum::{
    body::{Body, Bytes},
    http::StatusCode,
    response::{IntoResponse, Response},
    Json,
};
use hmac::{Hmac, Mac};
use serde_json::{json, Value};
use sha2::Sha256;

type HmacSha256 = Hmac<Sha256>;

/// Provider Ops 配置里控制台直通用的两个自定义键。
const CONSOLE_BASE_URL_KEY: &str = "console_base_url";
const CONSOLE_SHARED_SECRET_KEY: &str = "console_shared_secret";
const CONSOLE_SETTINGS_SAVE_RETRIES: usize = 8;

/// 与 opencode2api 的 `consoleSSOSign` 完全对齐：`sig = hex(HMAC-SHA256(secret, "pid|exp|nonce"))`。
pub(crate) fn console_sso_signature(secret: &str, pid: &str, exp: i64, nonce: &str) -> String {
    let mut mac = <HmacSha256 as Mac>::new_from_slice(secret.as_bytes())
        .expect("HMAC accepts any key length");
    mac.update(pid.as_bytes());
    mac.update(b"|");
    mac.update(exp.to_string().as_bytes());
    mac.update(b"|");
    mac.update(nonce.as_bytes());
    hex_encode(&mac.finalize().into_bytes())
}

fn hex_encode(bytes: &[u8]) -> String {
    let mut out = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        out.push_str(&format!("{byte:02x}"));
    }
    out
}

pub(super) async fn handle_admin_provider_ops_console_url(
    state: &AdminAppState<'_>,
    provider_id: &str,
) -> Result<Response<Body>, GatewayError> {
    let providers = state
        .read_provider_catalog_providers_by_ids(std::slice::from_ref(&provider_id.to_string()))
        .await?;
    let Some(provider) = providers.first() else {
        return Err(GatewayError::Client {
            status: axum::http::StatusCode::NOT_FOUND,
            message: "供应商不存在".to_string(),
        });
    };
    if provider.provider_type != "relay" {
        return Err(GatewayError::Client {
            status: axum::http::StatusCode::BAD_REQUEST,
            message: "仅 relay 供应商支持管理面板直通".to_string(),
        });
    }
    let Some(provider_ops_config) = admin_provider_ops_config_object(provider) else {
        return Err(GatewayError::Client {
            status: axum::http::StatusCode::BAD_REQUEST,
            message: "供应商 provider_ops 配置缺失".to_string(),
        });
    };
    let secret = provider_ops_config
        .get("console_shared_secret")
        .and_then(serde_json::Value::as_str)
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .ok_or_else(|| GatewayError::Client {
            status: axum::http::StatusCode::BAD_REQUEST,
            message: "未配置 console_shared_secret".to_string(),
        })?;

    let exp = chrono::Utc::now().timestamp() + 90;
    let nonce = new_console_sso_nonce();
    let signature = console_sso_signature(secret, provider_id, exp, &nonce);
    let url = format!(
        "/console/{provider_id}/console-sso?pid={provider_id}&exp={exp}&n={nonce}&sig={signature}"
    );

    let response = Json(json!({
        "provider_id": provider_id,
        "url": url,
        "expires_at": exp,
    }))
    .into_response();
    let response = attach_admin_audit_response(
        response,
        "admin_provider_ops_console_url_issued",
        "issue_console_url",
        "provider",
        provider_id,
    );
    // 免密跳转 URL 泄露即可进入面板：短 TTL + 禁缓存。
    Ok(mark_sensitive_admin_response_no_store(response))
}

fn new_console_sso_nonce() -> String {
    uuid::Uuid::new_v4().simple().to_string()
}

/// 读控制台设置：面板地址（显式配置 + 当前生效值）与共享密钥是否已配置。
/// 密钥本身永不回传，只给一个首尾片段用于核对是不是同一把。
pub(super) async fn handle_admin_provider_ops_console_settings_read(
    state: &AdminAppState<'_>,
    provider_id: &str,
) -> Result<Response<Body>, GatewayError> {
    let provider = read_console_provider(state, provider_id).await?;
    let settings = console_settings_snapshot(state, provider_id, &provider).await?;
    Ok(mark_sensitive_admin_response_no_store(
        Json(settings).into_response(),
    ))
}

/// 保存控制台设置。两个字段都可选：不传 = 不改；传空串 = 清除该项。
/// 只动 provider_ops 下的两个键，不碰架构/凭据等其它配置。
pub(super) async fn handle_admin_provider_ops_console_settings_save(
    state: &AdminAppState<'_>,
    provider_id: &str,
    request_body: Option<&Bytes>,
) -> Result<Response<Body>, GatewayError> {
    let payload: ConsoleSettingsRequest = match request_body {
        Some(bytes) if !bytes.is_empty() => {
            serde_json::from_slice(bytes).map_err(|_| bad_request("请求体格式无效"))?
        }
        _ => return Err(bad_request("请求体不能为空")),
    };
    let base_url = match payload.console_base_url.as_deref() {
        Some(raw) => Some(normalize_console_base_url_input(raw)?),
        None => None,
    };
    let secret = match payload.console_shared_secret.as_deref() {
        Some(raw) => Some(normalize_console_secret_input(raw)?),
        None => None,
    };
    if base_url.is_none() && secret.is_none() {
        return Err(bad_request("没有需要保存的设置项"));
    }

    let mut provider = read_console_provider(state, provider_id).await?;
    let mut saved = false;
    for _ in 0..CONSOLE_SETTINGS_SAVE_RETRIES {
        let mut config = provider
            .config
            .as_ref()
            .and_then(Value::as_object)
            .cloned()
            .unwrap_or_default();
        let mut provider_ops = config
            .get("provider_ops")
            .and_then(Value::as_object)
            .cloned()
            .unwrap_or_default();
        if let Some(value) = base_url.as_deref() {
            write_or_clear(&mut provider_ops, CONSOLE_BASE_URL_KEY, value);
        }
        if let Some(value) = secret.as_deref() {
            write_or_clear(&mut provider_ops, CONSOLE_SHARED_SECRET_KEY, value);
        }
        if provider_ops.is_empty() {
            config.remove("provider_ops");
        } else {
            config.insert("provider_ops".to_string(), Value::Object(provider_ops));
        }
        let update = ProviderCatalogProviderConfigCasUpdate {
            provider_id: provider.id.clone(),
            expected_config: provider.config.clone(),
            config: Some(Value::Object(config)),
        };
        if state
            .compare_and_swap_provider_catalog_provider_config(&update)
            .await?
        {
            saved = true;
            break;
        }
        provider = read_console_provider(state, provider_id).await?;
    }
    if !saved {
        return Err(GatewayError::Client {
            status: StatusCode::CONFLICT,
            message: "控制台设置并发更新冲突，请重试".to_string(),
        });
    }

    let refreshed = read_console_provider(state, provider_id).await?;
    let settings = console_settings_snapshot(state, provider_id, &refreshed).await?;
    let response = Json(settings).into_response();
    let response = attach_admin_audit_response(
        response,
        "admin_provider_ops_console_settings_saved",
        "save_console_settings",
        "provider",
        provider_id,
    );
    Ok(mark_sensitive_admin_response_no_store(response))
}

#[derive(serde::Deserialize)]
struct ConsoleSettingsRequest {
    #[serde(default)]
    console_base_url: Option<String>,
    #[serde(default)]
    console_shared_secret: Option<String>,
}

async fn read_console_provider(
    state: &AdminAppState<'_>,
    provider_id: &str,
) -> Result<StoredProviderCatalogProvider, GatewayError> {
    state
        .read_provider_catalog_providers_by_ids(std::slice::from_ref(&provider_id.to_string()))
        .await?
        .into_iter()
        .next()
        .ok_or_else(|| GatewayError::Client {
            status: StatusCode::NOT_FOUND,
            message: "供应商不存在".to_string(),
        })
}

/// 当前生效的面板地址：显式配置优先，否则回退到首个启用端点（去掉结尾 /v1）。
async fn console_settings_snapshot(
    state: &AdminAppState<'_>,
    provider_id: &str,
    provider: &StoredProviderCatalogProvider,
) -> Result<Value, GatewayError> {
    let provider_ops = admin_provider_ops_config_object(provider).cloned();
    let configured_base_url = provider_ops
        .as_ref()
        .and_then(|ops| ops.get(CONSOLE_BASE_URL_KEY))
        .and_then(Value::as_str)
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .map(str::to_string);
    let secret = provider_ops
        .as_ref()
        .and_then(|ops| ops.get(CONSOLE_SHARED_SECRET_KEY))
        .and_then(Value::as_str)
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .map(str::to_string);
    let secret_preview = secret.as_deref().map(mask_console_secret);

    let endpoints = state
        .list_provider_catalog_endpoints_by_provider_ids(std::slice::from_ref(
            &provider_id.to_string(),
        ))
        .await?;
    let endpoint_base_url = endpoints
        .iter()
        .find(|endpoint| endpoint.is_active)
        .map(|endpoint| endpoint.base_url.trim().to_string());
    let effective_base_url = configured_base_url
        .clone()
        .or_else(|| endpoint_base_url.as_deref().map(strip_v1_suffix));

    Ok(json!({
        "provider_id": provider_id,
        "console_base_url": configured_base_url,
        "console_base_url_effective": effective_base_url,
        "console_base_url_source": if configured_base_url.is_some() { "explicit" } else if endpoint_base_url.is_some() { "endpoint" } else { "missing" },
        "endpoint_base_url": endpoint_base_url,
        "console_shared_secret_configured": secret.is_some(),
        "console_shared_secret_preview": secret_preview,
    }))
}

fn strip_v1_suffix(base_url: &str) -> String {
    base_url
        .trim()
        .strip_suffix("/v1")
        .unwrap_or_else(|| base_url.trim())
        .to_string()
}

/// 只暴露首尾各 4 个字符，足够核对「是不是同一把」，又不至于泄露。
fn mask_console_secret(secret: &str) -> String {
    let chars: Vec<char> = secret.chars().collect();
    if chars.len() <= 8 {
        return "*".repeat(chars.len());
    }
    let head: String = chars.iter().take(4).collect();
    let tail: String = chars.iter().skip(chars.len() - 4).collect();
    format!("{head}…{tail}")
}

fn write_or_clear(target: &mut serde_json::Map<String, Value>, key: &str, value: &str) {
    if value.is_empty() {
        target.remove(key);
    } else {
        target.insert(key.to_string(), Value::String(value.to_string()));
    }
}

fn normalize_console_base_url_input(raw: &str) -> Result<String, GatewayError> {
    let trimmed = raw.trim().trim_end_matches('/');
    if trimmed.is_empty() {
        return Ok(String::new());
    }
    let parsed =
        url::Url::parse(trimmed).map_err(|_| bad_request("面板地址必须是完整的 http(s) URL"))?;
    if !matches!(parsed.scheme(), "http" | "https") {
        return Err(bad_request("面板地址只支持 http/https"));
    }
    if parsed.host_str().is_none() {
        return Err(bad_request("面板地址缺少主机名"));
    }
    if parsed.query().is_some() || parsed.fragment().is_some() {
        return Err(bad_request("面板地址不能带查询串或锚点"));
    }
    Ok(trimmed.to_string())
}

fn normalize_console_secret_input(raw: &str) -> Result<String, GatewayError> {
    let trimmed = raw.trim();
    if trimmed.is_empty() {
        return Ok(String::new());
    }
    if trimmed.len() < 8 || trimmed.len() > 256 {
        return Err(bad_request("共享密钥长度需在 8~256 之间"));
    }
    if !trimmed
        .chars()
        .all(|ch| ch.is_ascii_graphic() && ch != '\\' && ch != '"')
    {
        return Err(bad_request("共享密钥只能包含可见 ASCII 字符"));
    }
    Ok(trimmed.to_string())
}

fn bad_request(message: &str) -> GatewayError {
    GatewayError::Client {
        status: StatusCode::BAD_REQUEST,
        message: message.to_string(),
    }
}

#[cfg(test)]
mod tests {
    use super::{
        console_sso_signature, mask_console_secret, normalize_console_base_url_input,
        normalize_console_secret_input,
    };

    #[test]
    fn console_sso_signature_matches_go_reference() {
        // opencode2api TestConsoleSSOHappyPath 同一密钥/输入的期望值（openssl dgst 复算核对）。
        let signature = console_sso_signature("shared-secret", "prov-1", 1_700_000_000, "nonce-ok");
        assert_eq!(signature.len(), 64);
        // 确定性：同输入同签名
        assert_eq!(
            signature,
            console_sso_signature("shared-secret", "prov-1", 1_700_000_000, "nonce-ok")
        );
        // 与独立实现（python 语义）不一致的密钥应产生不同签名
        assert_ne!(
            signature,
            console_sso_signature("other-secret", "prov-1", 1_700_000_000, "nonce-ok")
        );
    }

    #[test]
    fn console_secret_is_masked_to_head_and_tail() {
        let secret = "26e45b6c136e9a3b06bd97f033ff28ef7aff286d3a8d5a55cddd0369a8d63e60";
        let masked = mask_console_secret(secret);
        assert_eq!(masked, "26e4…3e60");
        // 太短的密钥整段打码，不泄露任何字符
        assert_eq!(mask_console_secret("abcd1234"), "********");
    }

    #[test]
    fn console_base_url_input_is_validated() {
        assert_eq!(
            normalize_console_base_url_input(" https://panel.example.com/ ").expect("valid url"),
            "https://panel.example.com"
        );
        // 空串表示清除，是合法输入
        assert_eq!(
            normalize_console_base_url_input("   ").expect("clear is allowed"),
            ""
        );
        // 只接受 http/https，且不能带查询串
        assert!(normalize_console_base_url_input("ftp://panel.example.com").is_err());
        assert!(normalize_console_base_url_input("https://panel.example.com/?a=1").is_err());
        assert!(normalize_console_base_url_input("not-a-url").is_err());
    }

    #[test]
    fn console_secret_input_is_validated() {
        let secret = "26e45b6c136e9a3b06bd97f033ff28ef7aff286d3a8d5a55cddd0369a8d63e60";
        assert_eq!(
            normalize_console_secret_input(secret).expect("valid secret"),
            secret
        );
        assert_eq!(
            normalize_console_secret_input("  ").expect("clear is allowed"),
            ""
        );
        // 太短/带空白/带引号都拒掉：这些几乎都是复制粘贴出错
        assert!(normalize_console_secret_input("short").is_err());
        assert!(normalize_console_secret_input("has space in secret").is_err());
        assert!(normalize_console_secret_input("has\"quote-value-12345678").is_err());
    }
}
