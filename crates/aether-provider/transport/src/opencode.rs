//! OpenCode cloud provider (`/inference` endpoints, with optional front-proxy routing).
//!
//! ## 2026-10-15：真正生效的门禁（已实测，推翻了此前"TLS 指纹"的判断）
//!
//! 上游把可用路由迁到了 `/inference/` 命名空间。**旧的 `/zen/v1/chat/completions`
//! 现在无条件返回 `403 FreeTierError`**——换请求头、换请求体、换 UA、换 TLS
//! 指纹（连 BoringSSL 结构级一致的 ClientHello）都无效。官方 1.19.0 客户端打的是
//! `POST /inference/v1/chat/completions`。
//!
//! 在**正确路径**上，实测放行条件只有两条：
//!
//!   1. 请求必须带会话头：`x-opencode-request`（`msg_` + **12 位小写 hex 正序
//!      时间字段** + 14 位 `[A-Za-z0-9]`；纯随机 26 字符会被判 403——2026-10-15
//!      A/B 实测的网关 403 唯一根因；2026-10-17 按官方二进制纠正为**正序**）、
//!      `x-opencode-session` 与 `x-opencode-session-id`（同一 `ses_` 值，12 hex
//!      **降序**时间字段 + 14 alnum）。缺任一个或 `msg_` 缺时间字段 → 403。
//!   2. 请求体 `tools` 必须包含 `bash` / `glob` / `grep` / `read`，且**每个工具
//!      的 JSON schema 要完整**（带 `properties`）。只给 `{"type":"object"}`
//!      这种裸 schema → 403。
//!
//! 另外 `Authorization: Bearer public` 与 `stream: true` 仍照旧必需。
//!
//! ## 2026-10-17：官方身份 + 直连/前置两条链路的实测结论
//!
//! 对官方 CLI **1.19.3**（npm `opencode-ai`，bun 编译的单文件二进制）做全量字符串
//! 扫描，确认身份字段集中在 [`opencode_identity`]，包括 UA 模板
//! `opencode/<ver> ai-sdk/provider-utils/<ver> runtime/<runtime>`、11 个
//! `x-opencode-*` 头（含 `x-opencode-request`）、`x-opencode-project: global`。
//! 上游换版时只改那个常量块。
//!
//! 同一时刻（154 同机、同客户端、同请求体）对照：
//!
//!   | 上游 | 结果 |
//!   |---|---|
//!   | 直连 `https://opencode.ai` | **403 FreeTierError**（rustls 与 uTLS 复刻都是 403） |
//!   | 走前置域名（CDN） | **200** |
//!
//! 所以「客户端 TLS 指纹」不是判据，**出口链路**才是：直连时机房 IP 被判成非
//! OpenCode 环境，经 CDN 前置出网才放行。此前"普通 Go `crypto/tls` 直连即可 200"
//! 的结论在 2026-10-17 已不成立。
//!
//! 历史（2026-09-18 的判断，部分已被推翻，保留作为排查记录）：上游曾对
//! `/zen/v1/chat/completions` 做"指纹校验"，当时的结论是会话头 + UA 版本 +
//! `Bearer public` + 四个 tools + `stream: true`。
//!
//! 只有会话头与 tools 属于 provider-code 关注点；强制流式由固定供应商端点的
//! 默认配置 `upstream_stream_policy: "force_stream"` 表达。
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
///
/// Upstream moved the live free-tier chat route to the `/inference/` namespace;
/// the legacy `/zen/v1/chat/completions` route is now hard-rejected with
/// `403 FreeTierError` regardless of headers, body or TLS fingerprint
/// (measured 2026-10-15). The official 1.19.0 client posts to
/// `/inference/v1/chat/completions`.
pub const OPENCODE_CHAT_PATH: &str = "/inference/v1/chat/completions";

/// Lowest client version the upstream accepts (below this it returns 426).
pub const OPENCODE_MIN_CLIENT_VERSION: &str = "1.17.0";
/// OpenCode 官方客户端身份常量块。
///
/// 上游免费层按「请求像不像官方客户端」判定准入，所以这些值必须与官方一致。
/// **取值来源**：2026-10-17 对官方 CLI **1.19.3**（npm 包 `opencode-ai`，bun 编译的
/// 单文件二进制）做全量字符串扫描核对：
///
/// * UA 模板 `opencode/${ver} ai-sdk/provider-utils/${ver} runtime/${runtime}/${runtime_ver}`
///   （二进制内含 `bun/1.3.14`、`runtime/node.js/${process.version}`）；
/// * 头族 11 个 `x-opencode-*`，其中 **`x-opencode-request` 存在**；
/// * `x-opencode-project` 固定为字面量 `global`。
///
/// 上游一旦换版，**只改这一块**：不要再像 #93/#94 那样分散在多个函数里各改一半。
pub mod opencode_identity {
    /// 官方 CLI 版本（npm `opencode-ai` 的 latest）。
    pub const CLIENT_VERSION: &str = "1.19.3";
    /// 官方 UA 里的 AI SDK provider-utils 版本。
    pub const PROVIDER_UTILS_VERSION: &str = "4.0.23";
    /// 官方 UA 里的运行时标识（官方是 bun 编译产物）。
    pub const RUNTIME: &str = "bun";
    /// 官方 UA 里的运行时版本。官方 1.19.3 二进制内含字面量 `bun/1.3.14` /
    /// `Bun v1.3.14`，且模板为 `runtime/<name>/<version>`（同文件里还有
    /// `runtime/node.js/${process.version}` 佐证）。
    pub const RUNTIME_VERSION: &str = "1.3.14";
    /// `x-opencode-client` 的取值。
    pub const CLIENT_KIND: &str = "cli";
    /// `x-opencode-project` 的取值（官方固定 `global`，不是 40 位 hex 项目 id）。
    pub const PROJECT: &str = "global";
    /// session id 前缀。
    pub const SESSION_ID_PREFIX: &str = "ses_";
    /// request id 前缀。
    pub const REQUEST_ID_PREFIX: &str = "msg_";
}

/// 客户端版本（UA 用）。必须 `>= OPENCODE_MIN_CLIENT_VERSION`，否则上游回 426。
pub const OPENCODE_DEFAULT_CLIENT_VERSION: &str = opencode_identity::CLIENT_VERSION;

/// 是否下发 `x-opencode-request`。
///
/// 默认**下发**：官方 1.19.3 二进制里存在这个头（11 个 `x-opencode-*` 之一），
/// 2026-10-15 的 A/B 也证明过"缺了它 → 403"。保留一键关闭
/// （`AETHER_OPENCODE_DISABLE_REQUEST_HEADER=1`）用于上游再次变脸时快速回退。
fn opencode_send_request_header_enabled() -> bool {
    !matches!(
        std::env::var("AETHER_OPENCODE_DISABLE_REQUEST_HEADER")
            .unwrap_or_default()
            .trim()
            .to_ascii_lowercase()
            .as_str(),
        "1" | "true" | "yes" | "on"
    )
}
/// OpenCode's public free tier authenticates with this fixed bearer token.
const OPENCODE_CHAT_AUTHORIZATION: &str = "Bearer public";

/// `x-opencode-project` 的取值，保留旧常量名以便调用方与测试无需改动。
const OPENCODE_PROJECT_ID: &str = opencode_identity::PROJECT;

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
    let mut extra = serde_json::Map::new();
    extra.insert(
        "opencode_dns_pin".to_string(),
        json!({
            "host": host,
            "ip": ip.to_string(),
            "port": port,
        }),
    );
    // 会话锚点键随 pin 一起进 profile：执行期（首字节成功）要拿它把「这个会话现在
    // 用的是哪个节点」写回绑定表。规划期没开粘性时不写这个字段，执行期行为不变。
    if let Some(session_key) = opencode_session_anchor_key(transport) {
        extra.insert(
            OPENCODE_SESSION_ANCHOR_METADATA_KEY.to_string(),
            json!(session_key),
        );
    }
    Some(aether_contracts::ResolvedTransportProfile {
        profile_id: format!("opencode:{host}"),
        backend: aether_contracts::TRANSPORT_BACKEND_REQWEST_RUSTLS.to_string(),
        http_mode: aether_contracts::TRANSPORT_HTTP_MODE_AUTO.to_string(),
        pool_scope: aether_contracts::TRANSPORT_POOL_SCOPE_KEY.to_string(),
        header_fingerprint: None,
        extra: Some(serde_json::Value::Object(extra)),
    })
}

/// 规划期写进 key metadata 的会话锚点键（会话粘性开启时才有）。
pub const OPENCODE_SESSION_ANCHOR_METADATA_KEY: &str = "opencode_session_anchor";

/// 读 key metadata 里的会话锚点键。
pub fn opencode_session_anchor_key(transport: &GatewayProviderTransportSnapshot) -> Option<String> {
    transport
        .key
        .upstream_metadata
        .as_ref()?
        .get(OPENCODE_SESSION_ANCHOR_METADATA_KEY)?
        .as_str()
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .map(str::to_string)
}

/// 从 `ResolvedTransportProfile.extra` 读回会话锚点键。
pub fn opencode_session_anchor_from_extra(extra: Option<&serde_json::Value>) -> Option<String> {
    extra
        .and_then(|value| value.get(OPENCODE_SESSION_ANCHOR_METADATA_KEY))
        .and_then(serde_json::Value::as_str)
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .map(str::to_string)
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

/// 官方客户端的 User-Agent。
///
/// 模板取自官方 CLI 1.19.3 二进制（`opencode/${ver} ai-sdk/provider-utils/${ver}
/// runtime/${runtime}`，其中 runtime 由运行时探测填 `bun` / `node.js` / `browser`）。
/// 2026-10-17 之前这里用的 `opencode/latest/<ver>/cli` 是**自造格式**：官方二进制里
/// 不存在该形态，属于早前在「自定义 provider」上下文抓包得出的偏差结论。
pub fn opencode_user_agent() -> String {
    format!(
        "opencode/{} ai-sdk/provider-utils/{} runtime/{}/{}",
        opencode_identity::CLIENT_VERSION,
        opencode_identity::PROVIDER_UTILS_VERSION,
        opencode_identity::RUNTIME,
        opencode_identity::RUNTIME_VERSION
    )
}

/// Generates an official-form session id matching the upstream free-tier
/// descending-time algorithm: `ses_` + 12 lowercase hex chars (descending
/// time field, `~(ts_ms * 0x1000) & 0xFFFFFFFFFFFF` rendered as 6 big-endian
/// bytes) + 14 `[A-Za-z0-9]` chars (counter-mixed random tail).
///
/// 2026-10-15 更正：会话 id 的**时间字段方向本身不是门禁**——同一套请求把
/// 时间戳从"未来 +10s"到"1 天前"全试一遍，返回的都是同一个 403；真正拦住
/// 我们的是**路径**（`/zen/v1` 已废，须用 `/inference/v1`）。这里保留官方形状
/// 只是"发得像官方客户端"，不再声称它负责绕过指纹校验。
/// The upstream `Identifier.create(true)` emits descending time fields.
/// The reference `newOCSessionID` (opencode2api-lite) keeps the same shape; we
/// mirror it for wire-compatibility.
/// Session-id time field step: the client's `Identifier.create` multiplies the
/// millisecond timestamp by `0x1000` (a 12-bit counter slot) before taking the
/// complement.
const OPENCODE_SESSION_TIME_MULTIPLIER: u64 = 0x1000;
/// 48-bit mask for the descending time field (`ses_` + 12 lowercase hex).
const OPENCODE_SESSION_TIME_MASK: u64 = 0x0000_FFFF_FFFF_FFFF;

/// 生成下降时间字段（12 位小写 hex）：`!(ts_ms * 0x1000) & 0xFFFF_FFFF_FFFF`。
///
/// session id（`ses_`）与 request id（`msg_`）共用——上游的 `Identifier.create`
/// 对两类 id 用的是同一个生成器，只是前缀不同。
fn opencode_descending_time_field_hex() -> String {
    use std::time::{SystemTime, UNIX_EPOCH};

    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|duration| duration.as_millis())
        .unwrap_or(0);
    // value = ~(ts_ms * 0x1000) & 0x0000_FFFF_FFFF_FFFF
    let time_value = (now as u64).wrapping_mul(OPENCODE_SESSION_TIME_MULTIPLIER);
    format!("{:012x}", (!time_value) & OPENCODE_SESSION_TIME_MASK)
}

/// 生成**正序**时间字段（12 位小写 hex）：`(ts_ms * 0x1000) & 0xFFFF_FFFF_FFFF`。
///
/// request id（`msg_`）用它，session id（`ses_`）用降序版本——这是官方 CLI 两个
/// 生成器的差别：`Identifier.create()` 对 session 取反、对 message 取正。
/// 2026-10-17 之前两者共用降序版本，是 #93/#94 遗留的偏差。
fn opencode_ascending_time_field_hex() -> String {
    use std::time::{SystemTime, UNIX_EPOCH};

    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|duration| duration.as_millis())
        .unwrap_or(0);
    let time_value = (now as u64).wrapping_mul(OPENCODE_SESSION_TIME_MULTIPLIER);
    format!("{:012x}", time_value & OPENCODE_SESSION_TIME_MASK)
}

pub fn new_opencode_session_id() -> String {
    let mut id = String::with_capacity(4 + 12 + 14);
    id.push_str(opencode_identity::SESSION_ID_PREFIX);
    // 12 hex chars: the descending time field, rendered as 6 big-endian bytes
    // (i.e. 12 hex characters).
    id.push_str(&opencode_descending_time_field_hex());
    // 14 alphanumeric chars from real entropy (Uuid::new_v4), mirroring the
    // reference client's crypto/rand tail. The upstream only validates the
    // time-field direction, not the tail randomness, but real entropy avoids a
    // deterministic, restart-repeatable tail (the old splitmix64 scheme).
    push_alnum_from_entropy(&mut id, 14);
    id
}

/// Appends `count` `[A-Za-z0-9]` chars drawn from `Uuid::new_v4` bytes.
///
/// Shared by the session-id tail and the request id so both use the same
/// entropy source instead of mixing `Uuid` with a hand-rolled splitmix64.
/// `count` must not exceed 32 (two UUIDs worth of bytes).
fn push_alnum_from_entropy(out: &mut String, count: usize) {
    debug_assert!(count <= 32);
    let mut bytes = [0u8; 32];
    bytes[..16].copy_from_slice(uuid::Uuid::new_v4().as_bytes());
    bytes[16..].copy_from_slice(uuid::Uuid::new_v4().as_bytes());
    for byte in bytes.iter().take(count) {
        let pick = (*byte as usize) % OPENCODE_SESSION_ALNUM_ALPHABET.len();
        out.push(OPENCODE_SESSION_ALNUM_ALPHABET[pick] as char);
    }
}

/// Injects the OpenCode client fingerprint headers.
///
/// Applied to **both** OpenCode API formats:
///
/// * `openai:chat` (`/inference/v1/chat/completions`) — the upstream free tier
///   rejects a request that is missing any of these with `403 FreeTierError`
///   (verified 2026-10-15; the legacy `/zen/v1` path returns 403 unconditionally).
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
    insert_opencode_fingerprint_headers(transport, headers);
}

/// 免费层**占位凭据**：`public`。
///
/// 它不是一个真账号——上游按「免费层」策略放行，额度与限流都不落在它身上，所以
/// 健康度、熔断、熔断探测都不该记在它头上（2026-10-15 现场：它曾累积 645 次连续
/// 失败并打开熔断，全是假信号）。真 key（`oc_sk_…`）走完整机制。
pub const OPENCODE_FREE_TIER_PLACEHOLDER_KEY: &str = "public";

/// 凭据本身是不是「免费层占位」（`public`，或没填凭据）。
///
/// 拆出纯字符串版本：调度/健康度路径有时只拿得到凭据，拿不到完整 transport。
pub fn opencode_key_is_free_tier_placeholder(credential: &str) -> bool {
    let credential = credential.trim();
    credential.is_empty() || credential.eq_ignore_ascii_case(OPENCODE_FREE_TIER_PLACEHOLDER_KEY)
}

/// 这个 transport 的 key 是不是免费层占位（仅对 opencode 供应商有意义）。
pub fn is_opencode_free_tier_placeholder_key(transport: &GatewayProviderTransportSnapshot) -> bool {
    is_opencode_provider_transport(transport)
        && opencode_key_is_free_tier_placeholder(&transport.key.decrypted_api_key)
}

/// 官方客户端那套头——**只有这些**允许发往 opencode 上游。
///
/// 依据 2026-10-16 现场抓包（真实 opencode CLI 经边缘到达上游的头集合）与
/// `chat_headers_emit_the_official_x_opencode_set_only` 里记的官方 1.19.0 集合。
const OPENCODE_UPSTREAM_HEADER_ALLOWLIST: &[&str] = &[
    "accept",
    "accept-encoding",
    "accept-language",
    "authorization",
    "content-type",
    "user-agent",
    "x-opencode-client",
    "x-opencode-project",
    // 官方 1.19.3 二进制里有这个头（11 个 `x-opencode-*` 之一）。
    "x-opencode-request",
    "x-opencode-session",
    "x-opencode-session-id",
    // 2026-10-17 MITM 实测（官方 CLI 1.19.3 打 opencode.ai 的明文请求）：
    // 官方 **不发** `x-session-id`，也**不发** `x-session-affinity`；
    // 会话标识只有 `x-opencode-session` / `x-opencode-session-id`（同值）。
    // 参照实现（opencode2api-lite 第 2223 行）会发 `x-session-id`，实测无害，
    // 但既然要跟抓包对齐，就一并去掉——白名单不放行即等于不发。
];

/// 允许的前缀：SDK 遥测。
///
/// **真实 opencode CLI 自己也发**（同一份抓包里有 `x-stainless-arch/lang/os/
/// package-version/retry-count/runtime/runtime-version`），所以留着它比删掉更接近
/// 原生客户端；删掉反而制造一个"与真实客户端不一致"的偏差。
const OPENCODE_UPSTREAM_HEADER_ALLOWED_PREFIXES: &[&str] = &["x-stainless-"];

fn opencode_upstream_header_is_allowed(normalized_name: &str) -> bool {
    OPENCODE_UPSTREAM_HEADER_ALLOWLIST.contains(&normalized_name)
        || OPENCODE_UPSTREAM_HEADER_ALLOWED_PREFIXES
            .iter()
            .any(|prefix| normalized_name.starts_with(prefix))
}

/// 白名单收口：只留官方客户端那套，并把头名规范成小写。
///
/// **为什么是白名单而不是黑名单**：上游按客户端指纹判定——实测多带一个 1.18.x 遗留头
/// 就直接 403 FreeTierError，所以"像不像原生客户端"是功能问题。黑名单永远在追客户端
/// （以及中间层）塞进来的新头：`eo-*` 边缘头、`sec-fetch-*`、`x-deepseek-harness-*`、
/// 我们自己的 `x-trace-id`、别家产品的 `x-client-type`/`x-platform*`……白名单一次收口，
/// 之后无论谁来什么都不会漏出去。
///
/// **顺带保证"同名头只出现一次"**：`Accept` 与 `accept` 会归一成同一个键（BTreeMap 后写
/// 覆盖先写），所以出站 map 里不可能出现同名不同大小写的两条。
fn retain_official_upstream_headers(headers: &mut BTreeMap<String, String>) {
    let canonical = std::mem::take(headers)
        .into_iter()
        .map(|(name, value)| (name.trim().to_ascii_lowercase(), value))
        .filter(|(name, _)| opencode_upstream_header_is_allowed(name))
        .collect::<BTreeMap<String, String>>();
    *headers = canonical;
}

/// 官方客户端（bun fetch）出站时的 `accept`。
///
/// 上游免费层按「像不像官方客户端」判定，`accept` 是其中一条：官方是 `*/*`，
/// **不是** `text/event-stream`（实测见 [`restore_official_opencode_wire_headers`]）。
pub const OPENCODE_OFFICIAL_ACCEPT: &str = "*/*";

/// 官方客户端出站时的 `accept-encoding`（四段，bun fetch 的固定形态）。
///
/// 上游同样按这个值判指纹：`identity` 会被判成非官方客户端。
pub const OPENCODE_OFFICIAL_ACCEPT_ENCODING: &str = "gzip, deflate, br, zstd";

/// 把「官方 opencode 客户端的线上握手头」重新落一遍（`accept` / `accept-encoding`）。
///
/// ## 为什么需要单独一个函数
///
/// 网关的通用流式策略（`standard::build_standard_plan_fallback_headers`）会在
/// opencode 指纹头**之后**执行，把 `accept` 改写成 `text/event-stream`
/// （`TextEventStreamIfStreamingOrWildcard` 把 `*/*` 当作"没设"），并把
/// `accept-encoding` 强制成 `identity`（好让网关自己解 SSE 时不必处理压缩）。
/// 这两条对别的上游是对的，对 opencode 恰好是**反**的。
///
/// ## 实测证据（2026-10-17，154 同一台机、同一 provider / key / TLS / 目标域名）
///
/// 从 `usage_http_audits.provider_request_headers` 取两条真实出站请求逐头对比，
/// 只有这两处不同：
///
///   | 路径 | accept | accept-encoding | 结果 |
///   |---|---|---|---|
///   | admin `test-model` | `*/*` | `gzip, deflate, br, zstd` | **200** |
///   | 客户端 `/v1/chat/completions` | `text/event-stream` | `identity` | **403 FreeTierError** |
///
/// 其余 9 个头（user-agent / x-opencode-client / -project / -session /
/// -session-id / x-session-id / x-session-affinity / content-type / authorization）
/// **逐字节一致**，说明此前怀疑的 UA、project、TLS 指纹都不是这次的拦点。
///
/// ## 为什么用「有没有 `x-opencode-client`」当标记
///
/// 只有 [`insert_opencode_fingerprint_headers`] 会写这个头，所以它等价于
/// "这份头已经过 opencode 指纹处理"。这样调用方不需要再拿 transport 快照
/// （通用流式策略那层拿不到 transport），也不会误改别的上游的头。
pub fn restore_official_opencode_wire_headers(headers: &mut BTreeMap<String, String>) {
    let fingerprint_applied = headers
        .keys()
        .any(|name| name.eq_ignore_ascii_case("x-opencode-client"));
    if !fingerprint_applied {
        return;
    }
    set_header_ci(headers, "accept", OPENCODE_OFFICIAL_ACCEPT);
    set_header_ci(
        headers,
        "accept-encoding",
        OPENCODE_OFFICIAL_ACCEPT_ENCODING,
    );
}

/// 大小写不敏感地覆盖一个头：先删掉同名不同大小写的键，再写入规范小写键。
///
/// 上游只看头名（不区分大小写），但出站 map 里同时存在 `Accept` 与 `accept`
/// 会变成两条重复头，反而更像机器拼出来的请求。
fn set_header_ci(headers: &mut BTreeMap<String, String>, name: &str, value: &str) {
    let stale: Vec<String> = headers
        .keys()
        .filter(|existing| existing.eq_ignore_ascii_case(name))
        .cloned()
        .collect();
    for key in stale {
        headers.remove(&key);
    }
    headers.insert(name.to_string(), value.to_string());
}

/// The shared OpenCode client header set. See
/// [`insert_opencode_request_headers_if_needed`] for which formats use it.
fn insert_opencode_fingerprint_headers(
    transport: &GatewayProviderTransportSnapshot,
    headers: &mut BTreeMap<String, String>,
) {
    // The OpenCode upstream fingerprint REQUIRES a User-Agent that parses to
    // `opencode/<version>`; passthrough/client UAs (e.g. curl/8.x) are rejected
    // with 403 FreeTierError on the chat path. Unconditionally replace any
    // incoming UA instead of only filling it when missing.
    headers.insert("user-agent".to_string(), opencode_user_agent());
    // P2-8: the reference client (opencode2api-lite `buildOCRequest`) sends
    // `Accept: */*`. The upstream accepts either, but we mirror the reference
    // exactly so the fingerprint cannot drift on a future edge change.
    set_header_ci(headers, "accept", OPENCODE_OFFICIAL_ACCEPT);
    // 凭据：真 key（`oc_sk_…`）用它自己，占位/空凭据才回落到免费层的固定 `public`。
    // 2026-10-15 实测（同一台机、同一请求）：
    //   真 key + big-pickle + 指纹            → 200
    //   真 key + big-pickle + **不带**指纹    → 403 FreeTierError（指纹门禁对所有 key 生效）
    //   真 key + deepseek-v4.1-flash（付费名）→ 402 Insufficient account funds（真账号，没余额）
    //   真 key + deepseek-v4.1-flash-free     → 200
    // 所以硬写 `Bearer public` 会把真 key 变成摆设；同时免费层仍然只认字面量 public。
    let credential = transport.key.decrypted_api_key.trim();
    let authorization = if opencode_key_is_free_tier_placeholder(credential) {
        OPENCODE_CHAT_AUTHORIZATION.to_string()
    } else {
        format!("Bearer {credential}")
    };
    headers.insert("authorization".to_string(), authorization);
    // Every call mints a fresh session id in the official `ses_` shape. The
    // time-field direction is NOT itself the gate (see
    // `new_opencode_session_id`), but matching the official shape costs nothing.
    let session_id = new_opencode_session_id();
    // 2026-10-15 (verified): on the live `/inference/v1/chat/completions` route
    // the upstream requires the `x-opencode-*` session headers. Dropping any of
    // `x-opencode-session` / `x-opencode-session-id` / `x-opencode-request`
    // returns 403 FreeTierError even with the correct path, body and tools.
    headers.insert("x-opencode-session".to_string(), session_id.clone());
    headers.insert("x-opencode-session-id".to_string(), session_id.clone());
    // 2026-10-17 MITM 实测（官方 CLI 1.19.3 → opencode.ai 的明文请求）：
    //   x-opencode-session / x-opencode-session-id  = 同一个 ses_ 值
    //   x-opencode-request / x-opencode-project / x-opencode-client 均有
    //   **没有** x-session-id、**没有** x-session-affinity
    // 所以这两个遗留头一律不发（白名单里也不放行）。
    // 说明：参照实现会发 `x-session-id`（它自己注明"实测无害"），但抓包口径是官方不发。
    // 官方客户端的 Accept-Encoding 是四段（含 br/zstd）。
    set_header_ci(
        headers,
        "accept-encoding",
        OPENCODE_OFFICIAL_ACCEPT_ENCODING,
    );
    if opencode_send_request_header_enabled() {
        headers.insert("x-opencode-request".to_string(), new_opencode_request_id());
    }
    headers.insert(
        "x-opencode-client".to_string(),
        opencode_identity::CLIENT_KIND.to_string(),
    );
    // P2-7: the real 1.19.0 client and the opencode2api-lite reference both
    // send the literal project key `global`. P1 used a per-provider 40-hex
    // splitmix64 hash, which the upstream happened to accept, but a literal
    // cannot be mistaken for a different project cohort by the edge.
    headers.insert(
        "x-opencode-project".to_string(),
        OPENCODE_PROJECT_ID.to_string(),
    );
    // 收口：官方那套之外的，一个都不发（含 eo-*/sec-fetch-*/x-deepseek-harness-*/
    // x-trace-id/别家产品的 x-client-type 等）。见 `retain_official_upstream_headers`。
    retain_official_upstream_headers(headers);
}

/// Generates an `x-opencode-request` id: `msg_` + 12 位小写 hex **正序**时间字段
/// + 14 `[A-Za-z0-9]` chars。
///
/// 时间字段必须是**正序**（`ts_ms * 0x1000`），与 session id 的降序相反——两者在官方
/// 客户端里由不同生成器产出。纯随机 26 字符会被判 `403 FreeTierError`（2026-10-15
/// 实测）；而方向搞反同样不对，2026-10-17 按官方二进制纠正。
pub fn new_opencode_request_id() -> String {
    let mut id = String::with_capacity(4 + 12 + 14);
    id.push_str(opencode_identity::REQUEST_ID_PREFIX);
    id.push_str(&opencode_ascending_time_field_hex());
    push_alnum_from_entropy(&mut id, 14);
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
        // 官方 CLI 的 chat body 带 `stream_options.include_usage`（2026-10-17 静态核对
        // 官方 1.19.3，与 admin `test-model` 实测 body 一致）。补齐后 body 形状与官方
        // 一致，同时让流式请求也能带回 usage。客户端已显式给值时保持不动。
        let entry = object
            .entry("stream_options".to_string())
            .or_insert_with(|| json!({}));
        if !entry.is_object() {
            *entry = json!({});
        }
        if let Some(options) = entry.as_object_mut() {
            options
                .entry("include_usage".to_string())
                .or_insert(Value::Bool(true));
        }
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

/// `(name, description, required parameter)` for the four free-tier tools.
const OPENCODE_FREE_TIER_TOOL_SPECS: [(&str, &str, &str); 4] = [
    (
        "bash",
        "Run a shell command and return its output",
        "command",
    ),
    ("glob", "Find files matching a glob pattern", "pattern"),
    (
        "grep",
        "Search file contents with a regular expression",
        "pattern",
    ),
    ("read", "Read the contents of a file", "file_path"),
];

fn opencode_free_tier_tool(name: &str) -> Value {
    for (tool_name, description, param) in OPENCODE_FREE_TIER_TOOL_SPECS {
        if tool_name == name {
            let mut properties = serde_json::Map::new();
            properties.insert(param.to_string(), json!({"type": "string"}));
            return json!({
                "name": tool_name,
                "description": description,
                "parameters": {
                    "type": "object",
                    "properties": Value::Object(properties),
                    "required": [param]
                }
            });
        }
    }
    json!({"name": name, "parameters": {"type": "object"}})
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeMap;

    use serde_json::json;

    use super::{
        apply_opencode_request_body_semantics, ensure_opencode_free_tier_tools,
        insert_opencode_request_headers_if_needed, is_opencode_free_tier_placeholder_key,
        is_opencode_provider_transport, new_opencode_request_id, new_opencode_session_id,
        opencode_dns_pin, opencode_dns_pin_from_extra, opencode_key_exit_ip,
        opencode_key_is_free_tier_placeholder, opencode_resolved_transport_profile,
        opencode_session_anchor_from_extra, opencode_user_agent,
        restore_official_opencode_wire_headers, OPENCODE_OFFICIAL_ACCEPT,
        OPENCODE_OFFICIAL_ACCEPT_ENCODING, OPENCODE_ORIGINAL_DOMAIN, OPENCODE_PROJECT_ID,
        OPENCODE_SESSION_ANCHOR_METADATA_KEY,
    };
    use crate::snapshot::{
        GatewayProviderTransportEndpoint, GatewayProviderTransportKey,
        GatewayProviderTransportProvider, GatewayProviderTransportSnapshot,
    };

    /// 官方 wire 头：`accept` / `accept-encoding` 必须与官方客户端一致。
    ///
    /// 上游免费层按客户端指纹放行，这两个值在网关的通用流式策略下会被改成
    /// `text/event-stream` + `identity`，实测直接 403（见函数文档）。
    #[test]
    fn restore_official_wire_headers_overrides_generic_stream_values() {
        let mut headers = BTreeMap::new();
        headers.insert("x-opencode-client".to_string(), "cli".to_string());
        headers.insert("accept".to_string(), "text/event-stream".to_string());
        headers.insert("accept-encoding".to_string(), "identity".to_string());

        restore_official_opencode_wire_headers(&mut headers);

        assert_eq!(
            headers.get("accept").map(String::as_str),
            Some(OPENCODE_OFFICIAL_ACCEPT)
        );
        assert_eq!(
            headers.get("accept-encoding").map(String::as_str),
            Some(OPENCODE_OFFICIAL_ACCEPT_ENCODING)
        );
    }

    /// 头名大小写不同时不能留下重复头（否则出站 map 里 `Accept` 与 `accept` 并存）。
    #[test]
    fn restore_official_wire_headers_dedupes_case_variants() {
        let mut headers = BTreeMap::new();
        headers.insert("x-opencode-client".to_string(), "cli".to_string());
        headers.insert("Accept".to_string(), "text/event-stream".to_string());
        headers.insert("Accept-Encoding".to_string(), "identity".to_string());

        restore_official_opencode_wire_headers(&mut headers);

        assert!(!headers.keys().any(|name| name == "Accept"));
        assert!(!headers.keys().any(|name| name == "Accept-Encoding"));
        assert_eq!(
            headers.get("accept").map(String::as_str),
            Some(OPENCODE_OFFICIAL_ACCEPT)
        );
    }

    /// 没有 opencode 指纹标记时必须是空操作：绝不能把别的上游的 accept 一起改了。
    #[test]
    fn restore_official_wire_headers_is_noop_without_fingerprint() {
        let mut headers = BTreeMap::new();
        headers.insert("accept".to_string(), "text/event-stream".to_string());
        headers.insert("accept-encoding".to_string(), "identity".to_string());

        restore_official_opencode_wire_headers(&mut headers);

        assert_eq!(
            headers.get("accept").map(String::as_str),
            Some("text/event-stream")
        );
        assert_eq!(
            headers.get("accept-encoding").map(String::as_str),
            Some("identity")
        );
    }

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
    fn resolved_profile_carries_the_session_anchor_key_only_when_present() {
        // 会话粘性开启时，规划期会把会话键写进 key metadata；它必须随 pin 一起进
        // profile，执行期首字节成功后才能把「本会话 → 这个节点」写回绑定表。
        let mut transport = sample_transport("opencode");
        transport.key.upstream_metadata = Some(json!({
            "opencode_exit_ip": "93.184.216.37",
            "opencode_session_anchor": "device-a",
        }));
        transport.endpoint.base_url = "https://opencode-proxy.example.com/zen/v1".to_string();
        let profile = opencode_resolved_transport_profile(&transport).expect("profile");
        let extra = profile.extra.expect("extra");
        assert_eq!(
            opencode_session_anchor_from_extra(Some(&extra)).as_deref(),
            Some("device-a")
        );
        assert_eq!(extra["opencode_dns_pin"]["ip"], "93.184.216.37");

        // 没开会话粘性（或键为空）：不写这个字段，执行期读不到 → 一行都不做。
        let mut plain = sample_transport("opencode");
        plain.key.upstream_metadata = Some(json!({
            "opencode_exit_ip": "93.184.216.37",
            "opencode_session_anchor": "   ",
        }));
        plain.endpoint.base_url = "https://opencode-proxy.example.com/zen/v1".to_string();
        let profile = opencode_resolved_transport_profile(&plain).expect("profile");
        let extra = profile.extra.expect("extra");
        assert!(opencode_session_anchor_from_extra(Some(&extra)).is_none());
        assert!(extra.get(OPENCODE_SESSION_ANCHOR_METADATA_KEY).is_none());
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
    fn user_agent_matches_official_cli_template() {
        let ua = opencode_user_agent();
        // 官方 1.19.3：`opencode/<ver> ai-sdk/provider-utils/<ver> runtime/bun`
        assert_eq!(
            ua,
            format!(
                "opencode/{} ai-sdk/provider-utils/{} runtime/{}/{}",
                super::opencode_identity::CLIENT_VERSION,
                super::opencode_identity::PROVIDER_UTILS_VERSION,
                super::opencode_identity::RUNTIME,
                super::opencode_identity::RUNTIME_VERSION
            )
        );
        assert!(ua.starts_with("opencode/1.19.3 "), "got {ua}");
        assert!(ua.contains("ai-sdk/provider-utils/"), "got {ua}");
        assert!(
            ua.ends_with("runtime/bun/1.3.14"),
            "runtime 段必须带版本号（官方二进制内含 bun/1.3.14），got {ua}"
        );
        assert!(
            !ua.contains("/latest/") && !ua.ends_with("/cli"),
            "自造格式 `opencode/latest/<ver>/cli` 必须消失，got {ua}"
        );
    }

    #[test]
    fn header_injection_targets_opencode_chat_only() {
        let transport = sample_transport("opencode");
        let mut headers = BTreeMap::new();
        insert_opencode_request_headers_if_needed(&transport, "openai:chat", &mut headers);
        // 2026-10-15：两个 1.18.x 遗留头**必须不发**——`x-session-affinity`
        // 会让上游在 `/inference/v1/chat/completions` 上回 403 FreeTierError。
        // 2026-10-17 MITM 抓包：官方两个遗留头都不发。
        assert!(
            !headers.contains_key("x-session-id"),
            "抓包口径：x-session-id 不发"
        );
        assert!(
            !headers.contains_key("x-session-affinity"),
            "抓包口径：x-session-affinity 不发"
        );
        let sid = headers.get("x-opencode-session-id").map(String::as_str);
        assert!(sid.is_some());
        assert_eq!(headers.get("x-opencode-session").map(String::as_str), sid);
        // 2026-10-17 更正：官方 1.19.3 发 x-opencode-request（默认开启）
        let request_id = headers
            .get("x-opencode-request")
            .map(String::as_str)
            .expect("默认必须下发 x-opencode-request");
        assert!(request_id.starts_with("msg_"), "got {request_id}");
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
    fn real_opencode_key_is_forwarded_as_its_own_bearer_token() {
        // 2026-10-15：真 key（`oc_sk_…`）必须用它自己。此前传输层无条件硬写
        // `Bearer public`，真 key 等于摆设（实测真 key 打上游免费模型 200、
        // 付费模型 402「余额不足」，都是真账号行为）。
        let mut transport = sample_transport("opencode");
        transport.key.decrypted_api_key = "oc_sk_testonly".to_string();
        let mut headers = BTreeMap::new();
        insert_opencode_request_headers_if_needed(&transport, "openai:chat", &mut headers);
        assert_eq!(
            headers.get("authorization").map(String::as_str),
            Some("Bearer oc_sk_testonly")
        );
    }

    #[test]
    fn free_tier_placeholder_credential_is_classified_case_insensitively() {
        for placeholder in ["public", "PUBLIC", "  Public  ", ""] {
            assert!(
                opencode_key_is_free_tier_placeholder(placeholder),
                "{placeholder:?} 应判为免费层占位"
            );
        }
        for real in ["oc_sk_1dbb0f975140_xxxx", "sk-abc123"] {
            assert!(
                !opencode_key_is_free_tier_placeholder(real),
                "{real:?} 是真 key，不该被判成占位"
            );
        }
    }

    #[test]
    fn free_tier_placeholder_transport_is_recognized() {
        assert!(is_opencode_free_tier_placeholder_key(&sample_transport(
            "opencode"
        )));
        let mut real = sample_transport("opencode");
        real.key.decrypted_api_key = "oc_sk_real".to_string();
        assert!(!is_opencode_free_tier_placeholder_key(&real));
        // 其它供应商的同名凭据不受影响。
        let other = sample_transport("openai");
        assert!(!is_opencode_free_tier_placeholder_key(&other));
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
        // 2026-10-17 MITM 抓包：官方两个遗留头都不发。
        assert!(
            !headers.contains_key("x-session-id"),
            "抓包口径：x-session-id 不发"
        );
        assert!(
            !headers.contains_key("x-session-affinity"),
            "抓包口径：x-session-affinity 不发"
        );
        assert!(headers.contains_key("x-opencode-session-id"));
        assert!(headers.contains_key("x-opencode-session"));
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
        // 2026-10-15：1.18.x 遗留头不得出现——`x-session-affinity` 会触发 403。
        // 2026-10-17 MITM 抓包：官方两个遗留头都不发。
        assert!(
            !headers.contains_key("x-session-id"),
            "抓包口径：x-session-id 不发"
        );
        assert!(
            !headers.contains_key("x-session-affinity"),
            "抓包口径：x-session-affinity 不发"
        );
        let session = headers
            .get("x-opencode-session-id")
            .map(String::as_str)
            .unwrap_or_default();
        assert!(session.starts_with("ses_"), "session id shape");
        for key in ["x-opencode-session", "x-opencode-session-id"] {
            assert_eq!(
                headers.get(key).map(String::as_str),
                Some(session),
                "{key} must share the canonical session id"
            );
        }
        // 2026-10-17 更正：`x-opencode-request` 默认下发（官方 1.19.3 有该头）。
        let req = headers
            .get("x-opencode-request")
            .map(String::as_str)
            .expect("默认必须下发 x-opencode-request");
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
        assert_eq!(body["stream_options"]["include_usage"], json!(true));
        assert!(body["tools"]
            .as_array()
            .is_some_and(|tools| tools.len() == 4));

        // 客户端已显式给 include_usage 时保持不动。
        let mut explicit = json!({
            "model": "big-pickle",
            "messages": [],
            "stream_options": {"include_usage": false}
        });
        apply_opencode_request_body_semantics(&transport, "openai:chat", &mut explicit);
        assert_eq!(explicit["stream_options"]["include_usage"], json!(false));

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
    fn chat_headers_emit_the_official_x_opencode_set_only() {
        let transport = sample_transport("opencode");
        let mut headers = BTreeMap::new();
        insert_opencode_request_headers_if_needed(&transport, "openai:chat", &mut headers);

        for required in [
            "x-opencode-session",
            "x-opencode-session-id",
            "x-opencode-client",
            "x-opencode-project",
        ] {
            assert!(
                headers.contains_key(required),
                "missing required header {required}"
            );
        }
        // 2026-10-15：1.18.x 遗留头一律不发。实测矩阵（其余条件完全相同）：
        //   x-opencode-* 单独 → 200；+ x-session-id → 200；+ x-session-affinity → 403。
        // 2026-10-17 MITM 抓包：官方两个遗留头都不发。
        assert!(
            !headers.contains_key("x-session-id"),
            "抓包口径：x-session-id 不发"
        );
        assert!(
            !headers.contains_key("x-session-affinity"),
            "抓包口径：x-session-affinity 不发"
        );
        let sid = headers.get("x-opencode-session-id").map(String::as_str);
        assert_eq!(headers.get("x-opencode-session").map(String::as_str), sid);
        assert_eq!(
            headers.get("x-opencode-client").map(String::as_str),
            Some("cli")
        );
        // 2026-10-17 更正：官方 1.19.3 发 x-opencode-request，默认下发并校验格式。
        let req = headers
            .get("x-opencode-request")
            .map(String::as_str)
            .expect("默认必须下发 x-opencode-request");
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
    fn whitelist_keeps_only_the_official_client_header_set() {
        let transport = sample_transport("opencode");
        let mut headers = BTreeMap::new();
        // 现场出现过的"不该发出去"的头（边缘注入 / 网关侧客户端 / 我们自己的追踪 id）。
        for (name, value) in [
            ("eo-connecting-ip", "203.0.113.250"),
            ("eo-log-uuid", "16201963437506502153"),
            ("EO-Connecting-IP", "203.0.113.250"),
            ("sec-fetch-mode", "cors"),
            ("x-deepseek-harness-session-id", "session-1"),
            ("x-trace-id", "c9f90960-be3d-4778-8706-b4a371c9a05b"),
            ("http-referer", "https://cline.bot"),
            ("x-client-type", "cline-sdk"),
            ("x-platform", "terminal"),
            ("x-title", "Cline"),
            ("content-length", "8642"),
            ("cookie", "session=client"),
            ("host", "ai.mr-fan.top"),
        ] {
            headers.insert(name.to_string(), value.to_string());
        }
        // 该留的：官方集合 + 真客户端也发的 SDK 遥测 + 协商类头。
        headers.insert("accept-language".to_string(), "zh-CN".to_string());
        headers.insert("accept-encoding".to_string(), "gzip, deflate".to_string());
        headers.insert("content-type".to_string(), "application/json".to_string());
        headers.insert("x-stainless-lang".to_string(), "python".to_string());
        // 大写变体：用来验证"同名头只出现一次"（归一后只应剩一条）。
        headers.insert("Accept".to_string(), "application/json".to_string());

        insert_opencode_request_headers_if_needed(&transport, "openai:chat", &mut headers);

        for kept in [
            "accept",
            "accept-encoding",
            "accept-language",
            "authorization",
            "content-type",
            "user-agent",
            "x-opencode-client",
            "x-opencode-project",
            "x-opencode-session",
            "x-opencode-session-id",
            "x-stainless-lang",
        ] {
            assert!(headers.contains_key(kept), "should keep {kept}");
        }
        for dropped in [
            "eo-connecting-ip",
            "EO-Connecting-IP",
            "eo-log-uuid",
            "sec-fetch-mode",
            "x-deepseek-harness-session-id",
            "x-trace-id",
            "http-referer",
            "x-client-type",
            "x-platform",
            "x-title",
            "content-length",
            "cookie",
            "host",
            "Accept",
        ] {
            assert!(!headers.contains_key(dropped), "should drop {dropped}");
        }

        // 「同名头只出现一次」：accept 只有一条（`Accept` 与 `accept` 已归一）。
        assert_eq!(
            headers
                .keys()
                .filter(|name| name.eq_ignore_ascii_case("accept"))
                .count(),
            1
        );
        // 所有键都是小写，且不存在同名不同大小写的第二条。
        let mut lowered: Vec<String> = headers.keys().map(|k| k.to_ascii_lowercase()).collect();
        assert!(
            headers.keys().all(|k| *k == k.to_ascii_lowercase()),
            "header names must be lowercase: {:?}",
            headers.keys().collect::<Vec<_>>()
        );
        lowered.sort();
        let before = lowered.len();
        lowered.dedup();
        assert_eq!(before, lowered.len(), "duplicate spellings must collapse");
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
    fn x_opencode_request_id_has_msg_prefix_time_field_and_26_chars() {
        // 2026-10-15：`/inference` 路径上游会校验 msg id 的 12 位小写 hex 下降
        // 时间字段；缺了（纯随机 26 字符）直接 403 FreeTierError。
        let id = new_opencode_request_id();
        assert!(id.starts_with("msg_"));
        assert_eq!(id.len(), 4 + 26);
        assert!(
            id[4..16]
                .chars()
                .all(|c| c.is_ascii_digit() || ('a'..='f').contains(&c)),
            "前 12 位必须是小写 hex 时间字段，got {}",
            &id[4..16]
        );
        assert!(id[16..].chars().all(|c| c.is_ascii_alphanumeric()));
        // 时间字段必须≈当前时间的下降值（按同一公式重算，5 秒容差）。
        let field = u64::from_str_radix(&id[4..16], 16).expect("hex time field");
        let now_ms = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .expect("clock")
            .as_millis() as u64;
        let expected = now_ms.wrapping_mul(0x1000) & 0x0000_FFFF_FFFF_FFFF;
        assert!(
            expected.abs_diff(field) <= 5_000 * 0x1000,
            "msg 时间字段应≈当前时间的正序值：field={field:012x} expected={expected:012x}"
        );
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
