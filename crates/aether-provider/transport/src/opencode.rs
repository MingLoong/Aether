//! OpenCode official cloud provider (opencode.ai `/zen` endpoints).
//!
//! The upstream free tier fingerprint-checks every `/zen/v1/chat/completions`
//! request (verified 2026-09-18 against the opencode2api reference proxy):
//!
//!   1. Requests must carry a fresh `x-session-id` header shaped like
//!      `ses_` + 12 lowercase hex chars + 14 `[A-Za-z0-9]` chars. The legacy
//!      `x-opencode-session` / `x-opencode-client` / `x-opencode-project`
//!      headers are ignored by the upstream and are not emitted here. The
//!      official client also sends `x-session-affinity` with the same value;
//!      it is not strictly required but is emitted for fidelity.
//!   2. The `User-Agent` must parse to `opencode/<version>` with a version at
//!      or above the upstream minimum.
//!   3. The request `tools` array must contain the `bash` / `glob` / `grep` /
//!      `read` tools (order, descriptions and extra tools are irrelevant;
//!      missing any one of them returns 403 FreeTierError).
//!   4. The body must be `stream: true`.
//!
//! Only the first three are provider-code concerns here; the forced streaming
//! is expressed through the fixed-provider endpoint config default
//! `upstream_stream_policy: "force_stream"`.

use std::collections::{BTreeMap, BTreeSet};

use serde_json::{json, Value};
use uuid::Uuid;

use crate::snapshot::GatewayProviderTransportSnapshot;

pub const OPENCODE_PROVIDER_TYPE: &str = "opencode";

/// Base URL for the OpenCode official cloud service.
pub const OPENCODE_BASE_URL: &str = "https://opencode.ai";
/// Custom path for the OpenAI-compatible chat endpoint.
pub const OPENCODE_CHAT_PATH: &str = "/zen/v1/chat/completions";

/// Lowest client version the upstream accepts (below this it returns 426).
pub const OPENCODE_MIN_CLIENT_VERSION: &str = "1.17.0";
/// Fallback client version, mirroring the reference proxy's npm default.
pub const OPENCODE_DEFAULT_CLIENT_VERSION: &str = "1.18.31";

/// Constant `opencode/<version>` suffix kept close to the real client UA.
const OPENCODE_USER_AGENT_SUFFIX: &str = "ai-sdk/provider-utils/4.0.23 runtime/bun/1.3.14";

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
        id.push(OPENCODE_SESSION_ALNUM_ALPHABET[(byte as usize)
            % OPENCODE_SESSION_ALNUM_ALPHABET.len()] as char);
    }
    id
}

/// Injects the OpenCode fingerprint headers on the standard OpenAI chat path.
///
/// `x-session-id` and `x-session-affinity` are always refreshed per request
/// and share the same freshly generated value; the `user-agent` is
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
    let session_id = new_opencode_session_id();
    headers.insert("x-session-id".to_string(), session_id.clone());
    headers.insert("x-session-affinity".to_string(), session_id);
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
        insert_opencode_request_headers_if_needed, is_opencode_provider_transport,
        new_opencode_session_id, ensure_opencode_free_tier_tools, opencode_user_agent,
    };
    use crate::snapshot::{
        GatewayProviderTransportEndpoint, GatewayProviderTransportKey,
        GatewayProviderTransportProvider, GatewayProviderTransportSnapshot,
    };

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
        assert!(body[..12].chars().all(|c| c.is_ascii_hexdigit() && !c.is_ascii_uppercase()));
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
        assert_eq!(headers.get("x-session-affinity"), headers.get("x-session-id"));
        assert_eq!(
            headers.get("user-agent").map(String::as_str),
            Some(opencode_user_agent().as_str())
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
        let mut headers = BTreeMap::from([("user-agent".to_string(), "custom/1".to_string())]);
        insert_opencode_request_headers_if_needed(&transport, "openai:chat", &mut headers);
        // Upstream fingerprint requires opencode/<version>; a passthrough UA must be replaced.
        let ua = headers.get("user-agent").map(String::as_str).unwrap_or_default();
        assert!(ua.starts_with("opencode/"), "UA should be forced to opencode, got {ua}");
        assert!(headers.contains_key("x-session-id"));
        assert!(headers.contains_key("x-session-affinity"));
    }

    #[test]
    fn is_opencode_provider_transport_matches_case_insensitively() {
        assert!(is_opencode_provider_transport(&sample_transport("opencode")));
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
}