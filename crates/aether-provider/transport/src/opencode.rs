//! OpenCode cloud provider (`/zen` endpoints, with optional front-proxy routing).
//!
//! The upstream free tier fingerprint-checks every `/zen/v1/chat/completions`
//! request (verified 2026-09-18 against the opencode2api reference proxy):
//!
//!   1. Requests must carry a fresh `x-session-id` header shaped like
//!      `ses_` + 12 lowercase hex chars + 14 `[A-Za-z0-9]` chars. The legacy
//!      `x-opencode-session` / `x-opencode-client` / `x-opencode-project`
//!      headers are ignored by the upstream and are not emitted here. The
//!      current OpenCode transport does not send `x-session-affinity`.
//!   2. The `User-Agent` must parse to `opencode/<version>` with a version at
//!      or above the upstream minimum.
//!   3. Chat requests must use `Authorization: Bearer public`; forwarding the
//!      configured pool key as the bearer token returns HTTP 401.
//!   4. The request `tools` array must contain the `bash` / `glob` / `grep` /
//!      `read` tools (order, descriptions and extra tools are irrelevant;
//!      missing any one of them returns 403 FreeTierError).
//!   5. The body must be `stream: true`.
//!
//! Only the first four are provider-code concerns here; the forced streaming
//! is expressed through the fixed-provider endpoint config default
//! `upstream_stream_policy: "force_stream"`.

use std::collections::{BTreeMap, BTreeSet};

use serde_json::{json, Value};
use uuid::Uuid;

use crate::snapshot::GatewayProviderTransportSnapshot;

pub const OPENCODE_PROVIDER_TYPE: &str = "opencode";

/// Base URL for the OpenCode official cloud service.
pub const OPENCODE_BASE_URL: &str = "https://opencode.ai";
/// 官方直连域名。前置代理开关关闭时端点会被改写到这个域名，此时出口 IP 必须失效。
pub const OPENCODE_ORIGINAL_DOMAIN: &str = "opencode.ai";
/// Custom path for the OpenAI-compatible chat endpoint.
pub const OPENCODE_CHAT_PATH: &str = "/zen/v1/chat/completions";

/// Lowest client version the upstream accepts (below this it returns 426).
pub const OPENCODE_MIN_CLIENT_VERSION: &str = "1.17.0";
/// Fallback client version, mirroring the reference proxy's npm default.
pub const OPENCODE_DEFAULT_CLIENT_VERSION: &str = "1.18.31";

/// Constant `opencode/<version>` suffix kept close to the real client UA.
const OPENCODE_USER_AGENT_SUFFIX: &str = "ai-sdk/provider-utils/4.0.23 runtime/bun/1.3.14";
/// OpenCode's public free tier authenticates with this fixed bearer token.
const OPENCODE_CHAT_AUTHORIZATION: &str = "Bearer public";

/// The four tools the upstream free tier requires on every chat request.
const OPENCODE_FREE_TIER_TOOL_NAMES: [&str; 4] = ["bash", "glob", "grep", "read"];

const OPENCODE_SESSION_HEX_ALPHABET: &[u8] = b"0123456789abcdef";
const OPENCODE_SESSION_ALNUM_ALPHABET: &[u8] =
    b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789";

pub fn is_opencode_provider_transport(transport: &GatewayProviderTransportSnapshot) -> bool {
    transport
        .provider
        .provider_type
        .trim()
        .eq_ignore_ascii_case(OPENCODE_PROVIDER_TYPE)
}

/// 解析 key 级配置的出口 IP（CDN 前置代理 pin）。
///
/// 从 `key.upstream_metadata` JSON 对象的 `"opencode_exit_ip"` 字段读取并
/// `parse::<IpAddr>()`。缺失 / 非法 / 非 opencode provider 一律返回 `None`，
/// 此时行为与未配置出口 IP 完全一致（零破坏）。
pub fn opencode_key_exit_ip(
    transport: &GatewayProviderTransportSnapshot,
) -> Option<std::net::IpAddr> {
    if !is_opencode_provider_transport(transport) {
        return None;
    }
    let metadata = transport.key.upstream_metadata.as_ref()?;
    let value = metadata.get("opencode_exit_ip")?.as_str()?;
    parse_opencode_exit_ip(value)
}

/// Parse and validate a public OpenCode front-proxy exit IP.
///
/// The DNS pin is intentionally limited to public addresses: allowing a
/// metadata value such as loopback or a private network address would bypass
/// the normal provider DNS policy and turn the key metadata field into an
/// SSRF primitive.
pub fn parse_opencode_exit_ip(value: &str) -> Option<std::net::IpAddr> {
    let ip = value.trim().parse::<std::net::IpAddr>().ok()?;
    (!aether_http::is_private_or_reserved_ip(ip)).then_some(ip)
}

/// 构造 OpenCode 前置代理 DNS pin：`(host, ip, port)`。
///
/// `host` 取 `endpoint.base_url` 的域名（TLS/SNI 与 HTTP Host 保持该域名），
/// `ip` 取 key 配置的出口 IP，`port` 取 base_url 的默认端口。
pub fn opencode_dns_pin(
    transport: &GatewayProviderTransportSnapshot,
) -> Option<(String, std::net::IpAddr, u16)> {
    let ip = opencode_key_exit_ip(transport)?;
    let base_url = url::Url::parse(transport.endpoint.base_url.trim()).ok()?;
    if base_url.scheme() != "https"
        || !base_url.username().is_empty()
        || base_url.password().is_some()
        || base_url.query().is_some()
        || base_url.fragment().is_some()
    {
        return None;
    }
    let host = base_url.host_str()?.trim();
    if host.is_empty() || host.parse::<std::net::IpAddr>().is_ok() {
        return None;
    }
    // 直连官方域名时**不应用出口 IP**：池里的 IP 是前置代理/CDN 节点，
    // 用官方域名的 SNI 去连它们会导致 TLS 握手失败，进而整个池不可用。
    if host.eq_ignore_ascii_case(OPENCODE_ORIGINAL_DOMAIN) {
        return None;
    }
    let port = base_url.port_or_known_default().filter(|port| *port != 0)?;
    Some((host.to_string(), ip, port))
}

/// 生成携带 `opencode_dns_pin` 的 `ResolvedTransportProfile`。
///
/// 执行层据此把 CDN 域名解析到 key 的出口 IP（连接目标 = 出口 IP，
/// TLS/SNI 与 Host 保持域名）。`pool_scope = key` 保证不同 key 的连接池隔离。
pub fn opencode_resolved_transport_profile(
    transport: &GatewayProviderTransportSnapshot,
) -> Option<aether_contracts::ResolvedTransportProfile> {
    let (host, ip, port) = opencode_dns_pin(transport)?;
    Some(aether_contracts::ResolvedTransportProfile {
        profile_id: format!("opencode:{host}"),
        backend: aether_contracts::TRANSPORT_BACKEND_REQWEST_RUSTLS.to_string(),
        http_mode: aether_contracts::TRANSPORT_HTTP_MODE_AUTO.to_string(),
        pool_scope: aether_contracts::TRANSPORT_POOL_SCOPE_KEY.to_string(),
        header_fingerprint: None,
        extra: Some(json!({
            "opencode_dns_pin": {
                "host": host,
                "ip": ip.to_string(),
                "port": port,
            },
        })),
    })
}

/// 从 `ResolvedTransportProfile.extra`（JSON 字符串）解析 pin，消费侧防御式解析。
pub fn opencode_dns_pin_from_extra(extra: Option<&str>) -> Option<(String, std::net::IpAddr, u16)> {
    let extra = extra?;
    let value: Value = serde_json::from_str(extra).ok()?;
    let pin = value.get("opencode_dns_pin")?.as_object()?;
    let host = pin.get("host")?.as_str()?.trim();
    if host.is_empty()
        || host.parse::<std::net::IpAddr>().is_ok()
        || host.chars().any(|character| {
            character.is_whitespace() || matches!(character, '/' | '\\' | '?' | '#' | '@')
        })
    {
        return None;
    }
    let ip = parse_opencode_exit_ip(pin.get("ip")?.as_str()?)?;
    let port = pin.get("port")?.as_u64()?.try_into().ok()?;
    (port != 0).then_some((host.to_string(), ip, port))
}

pub fn opencode_user_agent() -> String {
    format!("opencode/{OPENCODE_DEFAULT_CLIENT_VERSION} {OPENCODE_USER_AGENT_SUFFIX}")
}

/// Generates an official-form session id: `ses_` + 12 lowercase hex chars +
/// 14 `[A-Za-z0-9]` chars, mirroring the reference `newOCSessionID` which
/// derives all 26 characters from random bytes.
pub fn new_opencode_session_id() -> String {
    let mut bytes = [0u8; 26];
    let first = Uuid::new_v4();
    let second = Uuid::new_v4();
    bytes[..16].copy_from_slice(first.as_bytes());
    bytes[16..].copy_from_slice(&second.as_bytes()[..10]);

    let mut id = String::with_capacity(4 + 26);
    id.push_str("ses_");
    for &byte in &bytes[..12] {
        id.push(OPENCODE_SESSION_HEX_ALPHABET[(byte as usize) % 16] as char);
    }
    for &byte in &bytes[12..] {
        id.push(
            OPENCODE_SESSION_ALNUM_ALPHABET[(byte as usize) % OPENCODE_SESSION_ALNUM_ALPHABET.len()]
                as char,
        );
    }
    id
}

/// Injects the OpenCode fingerprint headers on the standard OpenAI chat path.
///
/// `x-session-id` is refreshed per request; the `user-agent` is
/// unconditionally replaced with the OpenCode client UA because the upstream
/// fingerprint requires it (a passthrough/client UA yields 403 FreeTierError).
pub fn insert_opencode_request_headers_if_needed(
    transport: &GatewayProviderTransportSnapshot,
    provider_api_format: &str,
    headers: &mut BTreeMap<String, String>,
) {
    if !is_opencode_provider_transport(transport) {
        return;
    }
    if !aether_ai_formats::api_format_alias_matches(provider_api_format, "openai:chat") {
        return;
    }

    // The OpenCode upstream fingerprint REQUIRES a User-Agent that parses to
    // `opencode/<version>`; passthrough/client UAs (e.g. curl/8.x) are rejected
    // with 403 FreeTierError. Unconditionally replace any incoming UA on the
    // OpenCode chat path instead of only filling it when missing.
    headers.insert("user-agent".to_string(), opencode_user_agent());
    headers.insert("accept".to_string(), "application/json".to_string());
    // The upstream free tier rejects the configured pool key as a bearer token
    // with HTTP 401. The reference client always sends the fixed public token.
    headers.insert(
        "authorization".to_string(),
        OPENCODE_CHAT_AUTHORIZATION.to_string(),
    );
    let session_id = new_opencode_session_id();
    headers.insert("x-session-id".to_string(), session_id);
}

/// Applies the OpenCode body fingerprint on the OpenAI chat path, gated on the
/// provider type and api format. Used by both the generic transport body
/// semantics pass and the standard OpenAI chat decision body finalizer.
pub fn apply_opencode_request_body_semantics(
    transport: &GatewayProviderTransportSnapshot,
    provider_api_format: &str,
    body: &mut Value,
) {
    if !is_opencode_provider_transport(transport)
        || !aether_ai_formats::api_format_alias_matches(provider_api_format, "openai:chat")
    {
        return;
    }
    if let Some(object) = body.as_object_mut() {
        // The free tier rejects non-streaming chat requests. OpenCode is a
        // free-form provider, so enforce this in the body rather than relying
        // on a fixed-provider endpoint default.
        object.insert("stream".to_string(), Value::Bool(true));
    }
    ensure_opencode_free_tier_tools(body);
}

/// Ensures the request body carries the four upstream free-tier tools.
///
/// Existing client tools are left untouched; only the missing names are
/// appended. A body without a `tools` array gets the full minimal set, which
/// the upstream free tier requires (otherwise 403 FreeTierError).
pub fn ensure_opencode_free_tier_tools(body: &mut Value) {
    let Some(object) = body.as_object_mut() else {
        return;
    };

    let tools_entry = object
        .entry("tools")
        .or_insert_with(|| Value::Array(Vec::new()));
    let Some(tools) = tools_entry.as_array_mut() else {
        return;
    };

    let mut existing = BTreeSet::new();
    for tool in tools.iter() {
        if let Some(name) = tool
            .get("function")
            .and_then(|function| function.get("name"))
            .and_then(Value::as_str)
        {
            existing.insert(name.to_string());
        }
    }

    for name in OPENCODE_FREE_TIER_TOOL_NAMES {
        if existing.contains(name) {
            continue;
        }
        tools.push(json!({
            "type": "function",
            "function": opencode_free_tier_tool(name),
        }));
    }
}

fn opencode_free_tier_tool(name: &str) -> Value {
    match name {
        "bash" => json!({
            "name": "bash",
            "description": "Run a shell command and return its output",
            "parameters": {
                "type": "object",
                "properties": {"command": {"type": "string"}},
                "required": ["command"]
            }
        }),
        "glob" => json!({
            "name": "glob",
            "description": "Find files matching a glob pattern",
            "parameters": {
                "type": "object",
                "properties": {"pattern": {"type": "string"}},
                "required": ["pattern"]
            }
        }),
        "grep" => json!({
            "name": "grep",
            "description": "Search file contents with a regular expression",
            "parameters": {
                "type": "object",
                "properties": {"pattern": {"type": "string"}},
                "required": ["pattern"]
            }
        }),
        "read" => json!({
            "name": "read",
            "description": "Read the contents of a file",
            "parameters": {
                "type": "object",
                "properties": {"file_path": {"type": "string"}},
                "required": ["file_path"]
            }
        }),
        _ => json!({
            "name": name,
            "parameters": {"type": "object"}
        }),
    }
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeMap;

    use serde_json::json;

    use super::{
        apply_opencode_request_body_semantics, ensure_opencode_free_tier_tools,
        insert_opencode_request_headers_if_needed, is_opencode_provider_transport,
        new_opencode_session_id, opencode_dns_pin, opencode_dns_pin_from_extra,
        opencode_key_exit_ip, opencode_resolved_transport_profile, opencode_user_agent,
    };
    use crate::snapshot::{
        GatewayProviderTransportEndpoint, GatewayProviderTransportKey,
        GatewayProviderTransportProvider, GatewayProviderTransportSnapshot,
    };

    #[test]
    fn exit_ip_parses_from_upstream_metadata() {
        let mut transport = sample_transport("opencode");
        transport.key.upstream_metadata = Some(json!({"opencode_exit_ip": "93.184.216.34"}));
        assert_eq!(
            opencode_key_exit_ip(&transport).map(|ip| ip.to_string()),
            Some("93.184.216.34".to_string())
        );
        let (host, ip, port) = opencode_dns_pin(&transport).expect("pin");
        assert_eq!(host, "opencode.ai");
        assert_eq!(ip.to_string(), "93.184.216.34");
        assert_eq!(port, 443);
    }

    #[test]
    fn exit_ip_rejects_reserved_addresses() {
        let mut transport = sample_transport("opencode");
        transport.key.upstream_metadata = Some(json!({"opencode_exit_ip": "10.0.0.1"}));
        assert!(opencode_key_exit_ip(&transport).is_none());
        assert!(opencode_dns_pin(&transport).is_none());
    }

    #[test]
    fn dns_pin_requires_https_hostname_and_nonzero_port() {
        let mut transport = sample_transport("opencode");
        transport.key.upstream_metadata = Some(json!({"opencode_exit_ip": "93.184.216.34"}));

        transport.endpoint.base_url = "http://opencode.example".to_string();
        assert!(opencode_dns_pin(&transport).is_none());

        transport.endpoint.base_url = "https://opencode.example:8443/zen/v1".to_string();
        let (host, _, port) = opencode_dns_pin(&transport).expect("custom TLS endpoint pin");
        assert_eq!(host, "opencode.example");
        assert_eq!(port, 8443);
    }

    #[test]
    fn exit_ip_missing_or_invalid_returns_none() {
        let transport = sample_transport("opencode");
        assert!(opencode_key_exit_ip(&transport).is_none());

        let mut transport = sample_transport("opencode");
        transport.key.upstream_metadata = Some(json!({"opencode_exit_ip": "not-an-ip"}));
        assert!(opencode_key_exit_ip(&transport).is_none());

        // 非 opencode provider 即使配了 exit_ip 也不启用
        let mut other = sample_transport("openai");
        other.key.upstream_metadata = Some(json!({"opencode_exit_ip": "1.2.3.4"}));
        assert!(opencode_key_exit_ip(&other).is_none());
        assert!(opencode_resolved_transport_profile(&other).is_none());
    }

    #[test]
    fn resolved_profile_carries_pin_and_from_extra_roundtrips() {
        let mut transport = sample_transport("opencode");
        transport.key.upstream_metadata = Some(json!({"opencode_exit_ip": "93.184.216.36"}));
        let profile = opencode_resolved_transport_profile(&transport).expect("profile");
        assert_eq!(
            profile.pool_scope,
            aether_contracts::TRANSPORT_POOL_SCOPE_KEY
        );
        let extra = profile.extra.expect("extra");
        let (host, ip, port) =
            opencode_dns_pin_from_extra(Some(extra.to_string().as_str())).expect("pin");
        assert_eq!(host, "opencode.ai");
        assert_eq!(ip.to_string(), "93.184.216.36");
        assert_eq!(port, 443);
    }

    #[test]
    fn pin_from_extra_rejects_malformed_input() {
        assert!(opencode_dns_pin_from_extra(None).is_none());
        assert!(opencode_dns_pin_from_extra(Some("not-json")).is_none());
        assert!(opencode_dns_pin_from_extra(Some(
            r#"{"opencode_dns_pin":{"host":"x","ip":"bad","port":443}}"#
        ))
        .is_none());
        assert!(opencode_dns_pin_from_extra(Some(
            r#"{"opencode_dns_pin":{"host":"","ip":"93.184.216.34","port":443}}"#
        ))
        .is_none());
        assert!(opencode_dns_pin_from_extra(Some(
            r#"{"opencode_dns_pin":{"host":"x","ip":"93.184.216.34","port":0}}"#
        ))
        .is_none());
        assert!(opencode_dns_pin_from_extra(Some(
            r#"{"opencode_dns_pin":{"host":"x","ip":"127.0.0.1","port":443}}"#
        ))
        .is_none());
        assert!(opencode_dns_pin_from_extra(Some(r#"{"other":1}"#)).is_none());
    }

    fn sample_transport(provider_type: &str) -> GatewayProviderTransportSnapshot {
        GatewayProviderTransportSnapshot {
            provider: GatewayProviderTransportProvider {
                id: "provider-1".to_string(),
                name: "Provider".to_string(),
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
                base_url: "https://opencode.ai".to_string(),
                header_rules: None,
                body_rules: None,
                max_retries: None,
                custom_path: Some("/zen/v1/chat/completions".to_string()),
                config: None,
                format_acceptance_config: None,
                proxy: None,
            },
            key: GatewayProviderTransportKey {
                id: "key-1".to_string(),
                provider_id: "provider-1".to_string(),
                name: "Key".to_string(),
                auth_type: "bearer".to_string(),
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
                decrypted_api_key: "public".to_string(),
                decrypted_auth_config: None,
            },
        }
    }

    #[test]
    fn session_id_has_official_shape() {
        let id = new_opencode_session_id();
        assert!(id.starts_with("ses_"));
        assert_eq!(id.len(), 4 + 12 + 14);
        let body = &id[4..];
        assert!(body[..12]
            .chars()
            .all(|c| c.is_ascii_hexdigit() && !c.is_ascii_uppercase()));
        assert!(body[12..].chars().all(|c| c.is_ascii_alphanumeric()));
    }

    #[test]
    fn session_id_is_unique_per_request() {
        let a = new_opencode_session_id();
        let b = new_opencode_session_id();
        assert_ne!(a, b);
    }

    #[test]
    fn user_agent_parses_to_opencode_version() {
        let ua = opencode_user_agent();
        assert!(ua.starts_with("opencode/1."));
        assert!(ua.contains("ai-sdk/provider-utils/4.0.23"));
    }

    #[test]
    fn header_injection_targets_opencode_chat_only() {
        let transport = sample_transport("opencode");
        let mut headers = BTreeMap::new();
        insert_opencode_request_headers_if_needed(&transport, "openai:chat", &mut headers);
        assert!(headers.contains_key("x-session-id"));
        assert!(!headers.contains_key("x-session-affinity"));
        assert_eq!(
            headers.get("accept").map(String::as_str),
            Some("application/json")
        );
        assert_eq!(
            headers.get("user-agent").map(String::as_str),
            Some(opencode_user_agent().as_str())
        );
        assert_eq!(
            headers.get("authorization").map(String::as_str),
            Some("Bearer public")
        );

        let mut unchanged = BTreeMap::new();
        insert_opencode_request_headers_if_needed(&transport, "openai:image", &mut unchanged);
        assert!(unchanged.is_empty());

        let other = sample_transport("openai");
        let mut untouched = BTreeMap::new();
        insert_opencode_request_headers_if_needed(&other, "openai:chat", &mut untouched);
        assert!(untouched.is_empty());
    }

    #[test]
    fn header_injection_replaces_existing_user_agent_with_opencode_ua() {
        let transport = sample_transport("opencode");
        let mut headers = BTreeMap::from([
            ("user-agent".to_string(), "custom/1".to_string()),
            ("authorization".to_string(), "Bearer pool-key".to_string()),
        ]);
        insert_opencode_request_headers_if_needed(&transport, "openai:chat", &mut headers);
        // Upstream fingerprint requires opencode/<version>; a passthrough UA must be replaced.
        let ua = headers
            .get("user-agent")
            .map(String::as_str)
            .unwrap_or_default();
        assert!(
            ua.starts_with("opencode/"),
            "UA should be forced to opencode, got {ua}"
        );
        assert_eq!(
            headers.get("authorization").map(String::as_str),
            Some("Bearer public")
        );
        assert!(headers.contains_key("x-session-id"));
        assert!(!headers.contains_key("x-session-affinity"));
    }

    #[test]
    fn is_opencode_provider_transport_matches_case_insensitively() {
        assert!(is_opencode_provider_transport(&sample_transport(
            "opencode"
        )));
        assert!(!is_opencode_provider_transport(&sample_transport("openai")));
    }

    #[test]
    fn free_tier_tools_are_added_when_missing() {
        let mut body = json!({"model": "jev-1.13-free", "messages": []});
        ensure_opencode_free_tier_tools(&mut body);
        let tools = body["tools"].as_array().expect("tools array");
        let names: Vec<&str> = tools
            .iter()
            .map(|tool| tool["function"]["name"].as_str().unwrap())
            .collect();
        assert_eq!(names, vec!["bash", "glob", "grep", "read"]);
    }

    #[test]
    fn free_tier_tools_preserve_existing_tools() {
        let mut body = json!({
            "model": "jev-1.13-free",
            "tools": [{"type": "function", "function": {"name": "bash", "parameters": {}}}]
        });
        ensure_opencode_free_tier_tools(&mut body);
        let tools = body["tools"].as_array().expect("tools array");
        let names: Vec<&str> = tools
            .iter()
            .map(|tool| tool["function"]["name"].as_str().unwrap())
            .collect();
        assert_eq!(names, vec!["bash", "glob", "grep", "read"]);
    }

    #[test]
    fn chat_body_semantics_force_streaming_and_tools() {
        let transport = sample_transport("opencode");
        let mut body = json!({"model": "big-pickle", "stream": false, "messages": []});
        apply_opencode_request_body_semantics(&transport, "openai:chat", &mut body);
        assert_eq!(body["stream"], json!(true));
        assert!(body["tools"]
            .as_array()
            .is_some_and(|tools| tools.len() == 4));

        let mut untouched = json!({"model": "big-pickle", "stream": false});
        apply_opencode_request_body_semantics(
            &sample_transport("openai"),
            "openai:chat",
            &mut untouched,
        );
        assert_eq!(untouched["stream"], json!(false));
        assert!(untouched.get("tools").is_none());
    }
}
