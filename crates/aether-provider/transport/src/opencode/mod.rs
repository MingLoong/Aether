//! OpenCode free-tier upstream transport support.
//!
//! The OpenCode upstream (`/zen/v1/*`, self-hosted gateway deployments) applies
//! fingerprint checks to free-tier models.  Observed requirements (port from
//! the opencode2api project, 2026-09-18):
//!
//! 1. Every request must carry a per-request `x-session-id` header in the
//!    official client shape: `ses_` + 12 lowercase hex digits + 14
//!    `[A-Za-z0-9]` digits.  The session does not need to be registered
//!    server-side; the upstream only checks the shape.
//! 2. The request body must include the four built-in tools
//!    `bash` / `glob` / `grep` / `read`; missing any of them returns
//!    403 `FreeTierError`.  Extra tools are fine.
//! 3. The request body must set `stream: true`; `stream: false` returns
//!    403 `FreeTierError`.  Sync clients are served by the gateway forcing the
//!    upstream stream and aggregating the SSE stream back locally.
//! 4. `User-Agent` must parse as `opencode/<version>` with
//!    `version >= 1.17.0`; older versions return `426 Upgrade Required`.
//! 5. `Authorization: Bearer public` is fixed; the provider API key is not
//!    forwarded upstream for this provider.

mod session;

use std::collections::BTreeMap;

use crate::provider_types::{
    ProviderApiFormatInheritance, ProviderLocalEmbeddingSupport, ProviderRuntimePolicy,
};
use crate::snapshot::GatewayProviderTransportSnapshot;

pub const PROVIDER_TYPE: &str = "opencode";

/// Default client version embedded in the upstream `User-Agent`.  Matches the
/// official OpenCode client used by the opencode2api project.
pub const DEFAULT_OPENCODE_UA_VERSION: &str = "1.18.31";

/// Minimum upstream-accepted OpenCode client version.
pub const MIN_OPENCODE_UA_VERSION: &str = "1.17.0";

/// Upstream chat completions path relative to the configured provider base
/// URL.  Aether's standard `openai:chat` URL builder appends
/// `/chat/completions` to the endpoint base URL, so operators should configure
/// the provider endpoint base URL as `https://<upstream-domain>/zen/v1`.
pub const OPENCODE_CHAT_COMPLETIONS_PATH: &str = "/zen/v1/chat/completions";

/// Upstream model list path relative to the configured provider base URL.
pub const OPENCODE_MODELS_PATH: &str = "/zen/v1/models";

/// Authorization value the upstream expects for free-tier access.
pub const OPENCODE_UPSTREAM_AUTH_VALUE: &str = "Bearer public";

/// Suffix appended to the OpenCode `User-Agent`.  Not strictly required by the
/// upstream but kept close to the official client shape.
pub const OPENCODE_UA_SUFFIX: &str = " ai-sdk/provider-utils/4.0.23 runtime/bun/1.3.14";

/// Runtime policy for the `opencode` provider type.
///
/// OpenCode is an OpenAI-compatible upstream (standard family, local
/// `openai:chat` transport), conversion enabled by default so Claude-style
/// clients can also reach it, model fetching supported.
pub const RUNTIME_POLICY: ProviderRuntimePolicy = ProviderRuntimePolicy {
    fixed_provider: false,
    api_format_inheritance: ProviderApiFormatInheritance::None,
    enable_format_conversion_by_default: true,
    allow_auth_channel_mismatch_by_default: true,
    oauth_is_bearer_like: true,
    supports_model_fetch: true,
    supports_local_openai_chat_transport: true,
    supports_local_same_format_transport: true,
    local_embedding_support: ProviderLocalEmbeddingSupport::None,
};

/// Returns true when the transport belongs to the `opencode` provider type.
pub fn is_opencode_provider_transport(transport: &GatewayProviderTransportSnapshot) -> bool {
    transport
        .provider
        .provider_type
        .trim()
        .eq_ignore_ascii_case(PROVIDER_TYPE)
}

/// Resolves the front-proxy exit IP configured on an OpenCode pool key.
///
/// OpenCode upstreams share a fixed `Bearer public` credential; each pool key
/// represents one front-proxy exit IP that carries a fixed daily quota, so
/// the key's API key field stores the IP literal instead of a secret.
///
/// Returns `None` when the key value is empty or not a valid IP address.
pub fn opencode_key_upstream_ip(
    transport: &GatewayProviderTransportSnapshot,
) -> Option<std::net::IpAddr> {
    if !is_opencode_provider_transport(transport) {
        return None;
    }
    transport
        .key
        .decrypted_api_key
        .trim()
        .parse::<std::net::IpAddr>()
        .ok()
}

/// Builds the DNS pin for an OpenCode transport: the endpoint host (TLS
/// subject / HTTP Host) together with the key's exit IP and the endpoint
/// port.  Connection targets resolve to the pinned IP while TLS/SNI and the
/// HTTP Host header keep the original CDN domain, mirroring the
/// `dialUpstream` behaviour of the opencode2api project.
pub fn opencode_dns_pin(
    transport: &GatewayProviderTransportSnapshot,
) -> Option<(String, std::net::IpAddr, u16)> {
    let ip = opencode_key_upstream_ip(transport)?;
    let base_url = url::Url::parse(transport.endpoint.base_url.trim()).ok()?;
    let host = base_url.host_str()?.to_string();
    let port = base_url.port_or_known_default()?;
    Some((host, ip, port))
}

/// Bakes the OpenCode DNS pin into a `ResolvedTransportProfile` so the
/// execution layer can pin the CDN domain to the key's exit IP.  Returns
/// `None` for non-OpenCode transports or when no usable IP is configured.
pub fn opencode_resolved_transport_profile(
    transport: &GatewayProviderTransportSnapshot,
) -> Option<aether_contracts::ResolvedTransportProfile> {
    let (host, ip, port) = opencode_dns_pin(transport)?;
    Some(aether_contracts::ResolvedTransportProfile {
        profile_id: format!("opencode:{}", host),
        backend: aether_contracts::TRANSPORT_BACKEND_REQWEST_RUSTLS.to_string(),
        http_mode: aether_contracts::TRANSPORT_HTTP_MODE_AUTO.to_string(),
        pool_scope: aether_contracts::TRANSPORT_POOL_SCOPE_KEY.to_string(),
        header_fingerprint: None,
        extra: Some(serde_json::json!({
            "opencode_dns_pin": {
                "host": host,
                "ip": ip.to_string(),
                "port": port,
            },
        })),
    })
}

/// Parses an OpenCode DNS pin from a resolved transport profile extra.
pub fn opencode_dns_pin_from_profile(
    profile: &aether_contracts::ResolvedTransportProfile,
) -> Option<(String, std::net::IpAddr, u16)> {
    let extra = profile.extra.as_ref()?;
    opencode_dns_pin_from_json_value(Some(extra))
}

/// Parses an OpenCode DNS pin from a serialized transport-profile extra
/// (a JSON string as stored in the gateway's direct-reqwest client cache
/// key).  This lets the execution layer recover the pin at client-build
/// time without the full `ResolvedTransportProfile`.
pub fn opencode_dns_pin_from_extra(extra: Option<&str>) -> Option<(String, std::net::IpAddr, u16)> {
    let value = extra?.parse::<serde_json::Value>().ok()?;
    let pin = value.get("opencode_dns_pin")?;
    let host = pin.get("host")?.as_str()?.to_string();
    let ip = pin.get("ip")?.as_str()?.parse::<std::net::IpAddr>().ok()?;
    let port = pin.get("port")?.as_u64()? as u16;
    Some((host, ip, port))
}

fn opencode_dns_pin_from_json_value(
    extra: Option<&serde_json::Value>,
) -> Option<(String, std::net::IpAddr, u16)> {
    let pin = extra?.get("opencode_dns_pin")?;
    let host = pin.get("host")?.as_str()?.to_string();
    let ip = pin.get("ip")?.as_str()?.parse::<std::net::IpAddr>().ok()?;
    let port = pin.get("port")?.as_u64()? as u16;
    Some((host, ip, port))
}

/// Generates an official-shape OpenCode session id.
///
/// Shape: `ses_` + 12 lowercase hex digits + 14 `[A-Za-z0-9]` digits.
/// The session id is generated per request and never registered server-side.
pub fn new_opencode_session_id() -> String {
    session::new_session_id()
}

/// Normalizes an OpenCode client version to the minimum upstream-accepted
/// version when the configured value is too old or unparsable.
pub fn normalize_opencode_client_version(version: &str) -> String {
    if session::compare_client_version(version, MIN_OPENCODE_UA_VERSION) >= 0 {
        version.trim().to_string()
    } else {
        DEFAULT_OPENCODE_UA_VERSION.to_string()
    }
}

/// Builds the extra upstream headers required by the OpenCode free-tier
/// fingerprint check.
///
/// `client_version` should come from `normalize_opencode_client_version`.
/// A fresh `x-session-id` is generated for every call.
pub fn build_opencode_upstream_headers(client_version: &str) -> BTreeMap<String, String> {
    let mut headers = BTreeMap::new();
    headers.insert(
        "authorization".to_string(),
        OPENCODE_UPSTREAM_AUTH_VALUE.to_string(),
    );
    headers.insert(
        "user-agent".to_string(),
        format!(
            "opencode/{}{}",
            normalize_opencode_client_version(client_version),
            OPENCODE_UA_SUFFIX
        ),
    );
    headers.insert("x-session-id".to_string(), new_opencode_session_id());
    headers
}

/// Ensures the outbound OpenAI chat body satisfies OpenCode free-tier
/// fingerprint requirements:
///
/// - `stream` is forced to `true` (the gateway aggregates the upstream SSE
///   stream back for sync clients).
/// - `tools` contains the four required built-in tools
///   `bash` / `glob` / `grep` / `read` (missing tools are appended).
///
/// Returns `false` when the body is not a JSON object.
pub fn ensure_opencode_chat_request_body(body: &mut serde_json::Value) -> bool {
    let Some(object) = body.as_object_mut() else {
        return false;
    };
    object.insert("stream".to_string(), serde_json::Value::Bool(true));
    ensure_opencode_builtin_tools(object);
    true
}

fn ensure_opencode_builtin_tools(object: &mut serde_json::Map<String, serde_json::Value>) {
    const REQUIRED_TOOLS: &[&str] = &["bash", "glob", "grep", "read"];
    let mut present = std::collections::BTreeSet::new();
    if let Some(serde_json::Value::Array(tools)) = object.get("tools") {
        for tool in tools {
            if let Some(name) = tool.get("type").and_then(serde_json::Value::as_str) {
                present.insert(name.to_string());
            } else if let Some(function) = tool.get("function") {
                if let Some(name) = function.get("name").and_then(serde_json::Value::as_str) {
                    present.insert(name.to_string());
                }
            }
        }
    }
    for required in REQUIRED_TOOLS {
        if !present.contains(*required) {
            object
                .entry("tools")
                .or_insert_with(|| serde_json::Value::Array(Vec::new()));
            if let Some(serde_json::Value::Array(tools)) = object.get_mut("tools") {
                tools.push(serde_json::json!({
                    "type": "function",
                    "function": {
                        "name": required,
                        "description": format!("OpenCode built-in tool '{required}'"),
                        "parameters": {
                            "type": "object",
                            "properties": {},
                        },
                    },
                }));
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn session_id_matches_official_shape() {
        let id = new_opencode_session_id();
        assert!(id.starts_with("ses_"));
        assert_eq!(id.len(), "ses_".len() + 12 + 14);
        let hex_part = &id["ses_".len().."ses_".len() + 12];
        assert!(hex_part.chars().all(|c| c.is_ascii_hexdigit()));
        let alnum_part = &id[id.len() - 14..];
        assert!(alnum_part.chars().all(|c| c.is_ascii_alphanumeric()));
        // Consecutive ids should differ.
        assert_ne!(id, new_opencode_session_id());
    }

    #[test]
    fn version_normalization_keeps_supported_versions() {
        assert_eq!(normalize_opencode_client_version("1.18.31"), "1.18.31");
        assert_eq!(normalize_opencode_client_version("2.0.0"), "2.0.0");
        assert_eq!(normalize_opencode_client_version("1.16.0"), "1.18.31");
        assert_eq!(normalize_opencode_client_version(""), "1.18.31");
    }

    #[test]
    fn upstream_headers_include_fingerprint_requirements() {
        let headers = build_opencode_upstream_headers("1.18.31");
        assert_eq!(
            headers.get("authorization").map(String::as_str),
            Some("Bearer public")
        );
        let ua = headers.get("user-agent").expect("ua should exist");
        assert!(ua.starts_with("opencode/1.18.31"));
        let sid = headers
            .get("x-session-id")
            .expect("session id should exist");
        assert!(sid.starts_with("ses_"));
    }

    #[test]
    fn body_gets_stream_and_missing_tools() {
        let mut body = json!({
            "model": "big-pickle",
            "messages": [{"role": "user", "content": "hi"}],
            "tools": [{"type": "function", "function": {"name": "bash", "parameters": {}}}],
            "stream": false,
        });
        assert!(ensure_opencode_chat_request_body(&mut body));
        assert_eq!(body["stream"], json!(true));
        let names: Vec<&str> = body["tools"]
            .as_array()
            .unwrap()
            .iter()
            .map(|t| t["function"]["name"].as_str().unwrap())
            .collect();
        for required in ["bash", "glob", "grep", "read"] {
            assert!(names.contains(&required), "missing {required}: {names:?}");
        }
    }

    #[test]
    fn body_with_no_tools_gets_all_builtin_tools() {
        let mut body = json!({
            "model": "m",
            "messages": [{"role": "user", "content": "hi"}],
        });
        assert!(ensure_opencode_chat_request_body(&mut body));
        assert_eq!(body["tools"].as_array().unwrap().len(), 4);
    }
}
