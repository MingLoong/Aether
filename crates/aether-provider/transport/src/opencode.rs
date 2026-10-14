//! OpenCode cloud provider (`/zen` endpoints, with optional front-proxy routing).
//!
//! The upstream free tier fingerprint-checks every `/zen/v1/chat/completions`
//! request (verified 2026-09-18 against the opencode2api reference proxy):
//!
//!   1. Requests must carry a fresh `x-session-id` header shaped like
//!      `ses_` + 12 lowercase hex chars + 14 `[A-Za-z0-9]` chars. The
//!      `x-opencode-session` / `x-opencode-session-id` / `x-session-affinity`
//!      headers repeat that same value, while `x-opencode-client` and
//!      `x-opencode-project` carry the real client's fixed identifiers
//!      (`cli` / `global`) and `x-opencode-request` carries a fresh
//!      `msg_` + 26 `[A-Za-z0-9]` id.
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
//!
//! The `typesafe:systemone` decision endpoint (`/zen/v1/systemone`) shares this
//! same header set (measured 2026-10-14: HTTP 200 with the full chat headers,
//! with a `curl` UA, and with no session headers at all — identical `usage` in
//! all three cases). It deliberately does **not** share the body semantics:
//! that endpoint rejects any field outside its four-key whitelist with 400.

use std::collections::{BTreeMap, BTreeSet};

use crate::snapshot::GatewayProviderTransportSnapshot;
use serde_json::{json, Value};

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

/// Fixed `x-opencode-project` value sent by the real opencode 1.19.0 client
/// (and by the opencode2api-lite reference). See P2-7 in the module docs.
const OPENCODE_PROJECT_ID: &str = "global";

/// The four tools the upstream free tier requires on every chat request.
const OPENCODE_FREE_TIER_TOOL_NAMES: [&str; 4] = ["bash", "glob", "grep", "read"];

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

/// Generates an official-form session id matching the upstream free-tier
/// descending-time algorithm: `ses_` + 12 lowercase hex chars (descending
/// time field, `~(ts_ms * 0x1000) & 0xFFFFFFFFFFFF` rendered as 6 big-endian
/// bytes) + 14 `[A-Za-z0-9]` chars (counter-mixed random tail).
///
/// The upstream `Identifier.create(true)` (or its equivalent in the opencode
/// 1.19.x client) emits descending time fields; ascending timestamp variants
/// are rejected with 403 FreeTierError (measured against
/// `https://opencode.ai/zen/v1/chat/completions` on 2026-10-13). The
/// reference `newOCSessionID` (opencode2api-lite) keeps the same shape; we
/// mirror it so the gateway bypasses the free-tier fingerprint.
pub fn new_opencode_session_id() -> String {
    use std::sync::atomic::{AtomicU64, Ordering};
    use std::time::{SystemTime, UNIX_EPOCH};

    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|duration| duration.as_millis())
        .unwrap_or(0);
    // value = ~(ts_ms * 0x1000) & 0x0000_FFFF_FFFF_FFFF
    let time_value = (now << 12) as u64;
    let descending = (!time_value) & 0x0000_FFFF_FFFF_FFFF;

    let mut id = String::with_capacity(4 + 12 + 14);
    id.push_str("ses_");
    // 12 hex chars: the descending time field, rendered as 6 big-endian bytes
    // (i.e. 12 hex characters).
    id.push_str(&format!("{descending:012x}"));
    // 14 alphanumeric chars. A process-wide counter is mixed in so two calls
    // in the same millisecond still get distinct ids (the upstream rejects
    // any id with a non-descending time field but does not dedupe per-time).
    static COUNTER: AtomicU64 = AtomicU64::new(0);
    let counter = COUNTER.fetch_add(1, Ordering::Relaxed);
    let alphabet_len = OPENCODE_SESSION_ALNUM_ALPHABET.len();
    let mut rng_state: u64 = (now as u64).wrapping_mul(6_364_136_223_846_793_005)
        ^ counter.wrapping_mul(0x9E37_79B9_7F4A_7C15);
    for _ in 0..14 {
        // splitmix64
        rng_state = rng_state.wrapping_add(0x9E37_79B9_7F4A_7C15);
        let mut z = rng_state;
        z = (z ^ (z >> 30)).wrapping_mul(0xBF58_476D_1CE4_E5B9);
        z = (z ^ (z >> 27)).wrapping_mul(0x94D0_49BB_1331_11EB);
        z = z ^ (z >> 31);
        let pick = (z as usize) % alphabet_len;
        id.push(OPENCODE_SESSION_ALNUM_ALPHABET[pick] as char);
    }
    id
}

/// Derives a session id for the chat path.
///
/// Historically this keyed off `x-client-device-id` so one conversation kept
/// one id and the upstream saw the same conversation across turns (latency /
/// jitter win). The 2026-10-13 free-tier fingerprint upgrade rejects any
/// session id whose time field is **not** descending, so the deterministic
/// device-derived id is no longer free-tier valid. We therefore ignore the
/// device id and mint a fresh descending id per call — every turn the
/// upstream sees a "new conversation" but each turn is itself valid.
///
/// `client_device_id` is kept in the signature to avoid churn at the call
/// site; it is intentionally unused.
pub fn derive_opencode_session_id(client_device_id: Option<&str>) -> String {
    let _ = client_device_id;
    new_opencode_session_id()
}

/// Injects the OpenCode client fingerprint headers.
///
/// Applied to **both** OpenCode API formats:
///
/// * `openai:chat` (`/zen/v1/chat/completions`) — the upstream free tier
///   rejects a request that is missing any of these with `403 FreeTierError`.
/// * `typesafe:systemone` (`/zen/v1/systemone`) — the decision endpoint does
///   not *require* the fingerprint (measured 2026-10-14: HTTP 200 with a
///   `curl/8.5.0` User-Agent and no session headers, byte-identical `usage`),
///   but it accepts the full set unchanged. Sharing one builder keeps the two
///   paths from drifting if the upstream ever extends the check.
///
/// Only the HEADERS are shared. The body semantics are deliberately not: the
/// chat path forces `stream: true` and injects the four free-tier tools, while
/// System One rejects every field outside its four-key whitelist
/// (`model` / `state` / `questions` / `instructions`) with HTTP 400.
pub fn insert_opencode_request_headers_if_needed(
    transport: &GatewayProviderTransportSnapshot,
    provider_api_format: &str,
    headers: &mut BTreeMap<String, String>,
) {
    if !is_opencode_provider_transport(transport) {
        return;
    }
    let is_systemone =
        aether_ai_formats::api_format_alias_matches(provider_api_format, "typesafe:systemone");
    let is_chat = aether_ai_formats::api_format_alias_matches(provider_api_format, "openai:chat");
    if !is_systemone && !is_chat {
        return;
    }
    insert_opencode_fingerprint_headers(headers);
}

/// The shared OpenCode client header set. See
/// [`insert_opencode_request_headers_if_needed`] for which formats use it.
fn insert_opencode_fingerprint_headers(headers: &mut BTreeMap<String, String>) {
    // The OpenCode upstream fingerprint REQUIRES a User-Agent that parses to
    // `opencode/<version>`; passthrough/client UAs (e.g. curl/8.x) are rejected
    // with 403 FreeTierError on the chat path. Unconditionally replace any
    // incoming UA instead of only filling it when missing.
    headers.insert("user-agent".to_string(), opencode_user_agent());
    // P2-8: the reference client (opencode2api-lite `buildOCRequest`) sends
    // `Accept: */*`. The upstream accepts either, but we mirror the reference
    // exactly so the fingerprint cannot drift on a future edge change.
    headers.insert("accept".to_string(), "*/*".to_string());
    // The upstream free tier rejects the configured pool key as a bearer token
    // with HTTP 401. The reference client always sends the fixed public token.
    headers.insert(
        "authorization".to_string(),
        OPENCODE_CHAT_AUTHORIZATION.to_string(),
    );
    // Every call mints a fresh descending session id. The 2026-10-13
    // fingerprint rejects a session whose time field is not descending, so the
    // old device-derived (repeatable) id is no longer free-tier valid.
    let session_id = new_opencode_session_id();
    headers.insert("x-session-id".to_string(), session_id.clone());
    // 2026-10-13 free-tier fingerprint upgrade (measured against
    // https://opencode.ai/zen/v1/chat/completions): the upstream now
    // requires four additional `x-opencode-*` headers alongside the legacy
    // `x-session-id` / `user-agent` / `accept` / `authorization` quartet.
    // Without any one of them the upstream returns 403 FreeTierError.
    headers.insert("x-opencode-session".to_string(), session_id.clone());
    headers.insert("x-opencode-session-id".to_string(), session_id.clone());
    // Legacy `x-session-affinity` header (opencode 1.18.x) — also sent by
    // the opencode2api-lite reference client. Costless defensive parity
    // with the upstream free-tier fingerprint.
    headers.insert("x-session-affinity".to_string(), session_id.clone());
    headers.insert("x-opencode-request".to_string(), new_opencode_request_id());
    headers.insert("x-opencode-client".to_string(), "cli".to_string());
    // P2-7: the real 1.19.0 client and the opencode2api-lite reference both
    // send the literal project key `global`. P1 used a per-provider 40-hex
    // splitmix64 hash, which the upstream happened to accept, but a literal
    // cannot be mistaken for a different project cohort by the edge.
    headers.insert(
        "x-opencode-project".to_string(),
        OPENCODE_PROJECT_ID.to_string(),
    );
}

/// Generates an `x-opencode-request` id: `msg_` + 26 `[A-Za-z0-9]` chars,
/// matching the opencode 1.19.x client request id shape.
///
/// P2-9: draws the 26 characters from real CSPRNG bytes (`Uuid::new_v4`
/// reads the OS entropy source) instead of a millisecond-seeded
/// deterministic mix. The old scheme produced an identical id for two
/// requests that landed in the same millisecond, and the id leaked the
/// request timestamp through its digits. This mirrors the reference
/// client's `"msg_" + randAlnum(26)` over `crypto/rand`.
pub fn new_opencode_request_id() -> String {
    let mut random = [0u8; 32];
    random[..16].copy_from_slice(uuid::Uuid::new_v4().as_bytes());
    random[16..].copy_from_slice(uuid::Uuid::new_v4().as_bytes());

    let mut id = String::with_capacity(4 + 26);
    id.push_str("msg_");
    for byte in &random[..26] {
        let pick = (*byte as usize) % OPENCODE_SESSION_ALNUM_ALPHABET.len();
        id.push(OPENCODE_SESSION_ALNUM_ALPHABET[pick] as char);
    }
    id
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
    // P2-5: a client may send `tools: null` (or any non-array). Treat that
    // exactly like a missing `tools` field instead of returning early: the
    // upstream free tier rejects a request that carries no tools with
    // 403 FreeTierError / 500, so silently leaving it untouched would turn a
    // harmless client quirk into a hard upstream failure.
    if !tools_entry.is_array() {
        *tools_entry = Value::Array(Vec::new());
    }
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
        new_opencode_request_id, new_opencode_session_id, opencode_dns_pin,
        opencode_dns_pin_from_extra, opencode_key_exit_ip, opencode_resolved_transport_profile,
        opencode_user_agent, OPENCODE_ORIGINAL_DOMAIN, OPENCODE_PROJECT_ID,
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
        transport.endpoint.base_url = "https://opencode-proxy.example.com/zen/v1".to_string();
        let (host, ip, port) = opencode_dns_pin(&transport).expect("pin");
        assert_eq!(host, "opencode-proxy.example.com");
        assert_eq!(ip.to_string(), "93.184.216.34");
        assert_eq!(port, 443);
    }

    /// 直连官方域名时**不能**套出口 IP：池里的 IP 是前置代理/CDN 节点，
    /// 用官方域名的 SNI 去连它们会 TLS 握手失败，导致整池不可用。
    #[test]
    fn dns_pin_is_disabled_for_the_official_domain() {
        let mut transport = sample_transport("opencode");
        transport.key.upstream_metadata = Some(json!({"opencode_exit_ip": "93.184.216.34"}));
        transport.endpoint.base_url = format!("https://{OPENCODE_ORIGINAL_DOMAIN}/zen/v1");
        assert!(
            opencode_dns_pin(&transport).is_none(),
            "直连官方域名时不应套用出口 IP"
        );
        assert!(
            opencode_resolved_transport_profile(&transport).is_none(),
            "直连官方域名时不应生成带 pin 的传输画像"
        );
        // 大小写不敏感也要判定为官方域名
        transport.endpoint.base_url =
            format!("https://{}/zen/v1", OPENCODE_ORIGINAL_DOMAIN.to_uppercase());
        assert!(opencode_dns_pin(&transport).is_none());
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
        // pin 只在前置代理域名前面生效，测试要用代理域名而不是官方域名。
        transport.endpoint.base_url = "https://opencode-proxy.example.com/zen/v1".to_string();
        let profile = opencode_resolved_transport_profile(&transport).expect("profile");
        assert_eq!(
            profile.pool_scope,
            aether_contracts::TRANSPORT_POOL_SCOPE_KEY
        );
        let extra = profile.extra.expect("extra");
        let (host, ip, port) =
            opencode_dns_pin_from_extra(Some(extra.to_string().as_str())).expect("pin");
        assert_eq!(host, "opencode-proxy.example.com");
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
        assert!(headers.contains_key("x-session-affinity"));
        assert_eq!(
            headers.get("x-session-affinity").map(String::as_str),
            headers.get("x-session-id").map(String::as_str)
        );
        assert_eq!(headers.get("accept").map(String::as_str), Some("*/*"));
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
        assert!(headers.contains_key("x-session-affinity"));
        assert_eq!(
            headers.get("x-session-affinity").map(String::as_str),
            headers.get("x-session-id").map(String::as_str)
        );
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
    fn systemone_reuses_the_chat_fingerprint_headers() {
        let transport = sample_transport("opencode");
        let mut headers = BTreeMap::from([
            ("user-agent".to_string(), "curl/8.5.0".to_string()),
            ("authorization".to_string(), "Bearer pool-key".to_string()),
            ("x-client-device-id".to_string(), "device-1".to_string()),
        ]);
        insert_opencode_request_headers_if_needed(&transport, "typesafe:systemone", &mut headers);

        // Upstream accepts the fixed public token only; the pool key yields 401 AuthError.
        assert_eq!(
            headers.get("authorization").map(String::as_str),
            Some("Bearer public")
        );
        // System One does not *require* the fingerprint, but it accepts the full
        // chat header set unchanged (measured 2026-10-14: HTTP 200, identical
        // usage), so both formats share one builder.
        assert_eq!(
            headers.get("user-agent").map(String::as_str),
            Some(opencode_user_agent().as_str())
        );
        assert_eq!(headers.get("accept").map(String::as_str), Some("*/*"));
        assert_eq!(
            headers.get("x-opencode-client").map(String::as_str),
            Some("cli")
        );
        assert_eq!(
            headers.get("x-opencode-project").map(String::as_str),
            Some(OPENCODE_PROJECT_ID)
        );
        let session = headers
            .get("x-session-id")
            .map(String::as_str)
            .unwrap_or_default();
        assert!(session.starts_with("ses_"), "session id shape");
        for key in [
            "x-opencode-session",
            "x-opencode-session-id",
            "x-session-affinity",
        ] {
            assert_eq!(
                headers.get(key).map(String::as_str),
                Some(session),
                "{key} must share the canonical session id"
            );
        }
        let req = headers
            .get("x-opencode-request")
            .map(String::as_str)
            .unwrap_or_default();
        assert!(req.starts_with("msg_"));
        assert_eq!(req.len(), 4 + 26);
    }

    #[test]
    fn non_opencode_formats_still_get_no_fingerprint_headers() {
        // The shared builder must not leak onto formats the OpenCode transport
        // does not own.
        let transport = sample_transport("opencode");
        for format in ["openai:image", "openai:embedding", "openai:rerank"] {
            let mut headers = BTreeMap::new();
            insert_opencode_request_headers_if_needed(&transport, format, &mut headers);
            assert!(headers.is_empty(), "{format} must stay untouched");
        }
    }

    #[test]
    fn systemone_body_semantics_leave_body_untouched() {
        let transport = sample_transport("opencode");
        let original = json!({
            "model": "jev-1.13-free",
            "state": "hello",
            "questions": {"is_urgent": {"type": "noul"}}
        });
        let mut body = original.clone();
        apply_opencode_request_body_semantics(&transport, "typesafe:systemone", &mut body);
        assert_eq!(body, original);
        assert!(body.get("stream").is_none());
        assert!(body.get("tools").is_none());
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

    #[test]
    fn chat_headers_emit_all_four_x_opencode_session_headers() {
        let transport = sample_transport("opencode");
        let mut headers = BTreeMap::new();
        insert_opencode_request_headers_if_needed(&transport, "openai:chat", &mut headers);

        for required in [
            "x-opencode-session",
            "x-opencode-session-id",
            "x-opencode-request",
            "x-opencode-client",
            "x-opencode-project",
            "x-session-affinity",
        ] {
            assert!(
                headers.contains_key(required),
                "missing required header {required}"
            );
        }
        // x-session-affinity shares the canonical id with the new
        // x-opencode-session[-id] triple and the legacy x-session-id
        // (opencode2api-lite parity; costless defensive layer).
        let sid = headers.get("x-session-id").map(String::as_str);
        assert_eq!(headers.get("x-session-affinity").map(String::as_str), sid);
        assert_eq!(headers.get("x-opencode-session").map(String::as_str), sid);
        assert_eq!(
            headers.get("x-opencode-session-id").map(String::as_str),
            sid
        );
        assert_eq!(
            headers.get("x-opencode-client").map(String::as_str),
            Some("cli")
        );
        assert_eq!(
            headers.get("x-opencode-session").map(String::as_str),
            headers.get("x-opencode-session-id").map(String::as_str)
        );
        assert_eq!(
            headers.get("x-opencode-session").map(String::as_str),
            headers.get("x-session-id").map(String::as_str)
        );
        let req = headers
            .get("x-opencode-request")
            .map(String::as_str)
            .unwrap_or_default();
        assert!(req.starts_with("msg_"));
        assert_eq!(req.len(), 4 + 26);
        assert!(req[4..].chars().all(|c| c.is_ascii_alphanumeric()));
        assert_eq!(
            headers.get("x-opencode-project").map(String::as_str),
            Some(OPENCODE_PROJECT_ID),
            "P2-7: x-opencode-project must be the literal the real client sends"
        );
    }

    #[test]
    fn x_opencode_session_id_uses_descending_time_field() {
        let a = new_opencode_session_id();
        std::thread::sleep(std::time::Duration::from_millis(2));
        let b = new_opencode_session_id();
        let time_a = u64::from_str_radix(&a[4..16], 16).expect("a time hex");
        let time_b = u64::from_str_radix(&b[4..16], 16).expect("b time hex");
        assert!(
            time_a > time_b,
            "descending time field: a={:x} should be > b={:x}",
            time_a,
            time_b
        );
    }

    #[test]
    fn x_opencode_request_id_has_msg_prefix_and_26_alnum() {
        let id = new_opencode_request_id();
        assert!(id.starts_with("msg_"));
        assert_eq!(id.len(), 4 + 26);
        assert!(id[4..].chars().all(|c| c.is_ascii_alphanumeric()));
    }

    #[test]
    fn x_opencode_request_id_is_unique_across_same_millisecond_calls() {
        // P2-9: the previous millisecond-seeded scheme produced identical ids
        // for two calls in the same millisecond. The id must now be drawn from
        // real entropy so concurrent requests never collide.
        let ids: std::collections::BTreeSet<String> =
            (0..64).map(|_| new_opencode_request_id()).collect();
        assert_eq!(ids.len(), 64, "request ids must be unique");
        for id in &ids {
            assert!(id.starts_with("msg_"));
            assert_eq!(id.len(), 4 + 26);
            assert!(id[4..].chars().all(|c| c.is_ascii_alphanumeric()));
        }
    }

    #[test]
    fn free_tier_tools_are_restored_when_tools_is_not_an_array() {
        // P2-5: `tools: null` (or any non-array) previously returned early and
        // left the request with no tools, which the upstream rejects with
        // 403 FreeTierError / 500. It must now behave like a missing field.
        for bad in [json!(null), json!({}), json!("bash")] {
            let mut body = json!({"model": "big-pickle", "tools": bad});
            ensure_opencode_free_tier_tools(&mut body);
            let tools = body["tools"]
                .as_array()
                .expect("tools must become an array");
            let names: Vec<&str> = tools
                .iter()
                .filter_map(|tool| tool["function"]["name"].as_str())
                .collect();
            assert_eq!(
                names,
                vec!["bash", "glob", "grep", "read"],
                "non-array tools must be replaced by the full free-tier set"
            );
        }
    }
}
