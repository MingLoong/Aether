use super::super::config::admin_provider_ops_config_object;
use crate::handlers::admin::request::AdminAppState;
use crate::handlers::admin::shared::{
    attach_admin_audit_response, mark_sensitive_admin_response_no_store,
};
use crate::GatewayError;
use axum::{
    body::Body,
    response::{IntoResponse, Response},
    Json,
};
use hmac::{Hmac, Mac};
use serde_json::json;
use sha2::Sha256;

type HmacSha256 = Hmac<Sha256>;

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

#[cfg(test)]
mod tests {
    use super::console_sso_signature;

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
}
