//! Relay echo request controls.
//!
//! Relay gateways (workbuddy2api / zcode2api) can return the exact header set
//! they sent to their real provider. Asking for it is a relay-only protocol
//! detail, so the plan builders in this module own the injection and the
//! execution runtime only parses the reply.

use std::collections::BTreeMap;

pub(crate) const ECHO_REQUEST_HEADER: &str = "x-aether-echo";
pub(crate) const ECHO_TRACE_HEADER: &str = "x-aether-trace-id";
/// 请求 relay 回传真正发往上游的请求体（v2）。
pub(crate) const ECHO_BODY_REQUEST_HEADER: &str = "x-aether-echo-body";

/// Injects the echo control headers for `relay` provider types only.
///
/// First-party providers never understand this header, so it is skipped for
/// them and they keep the previous behaviour.
pub(crate) fn inject_echo_request_headers(
    headers: &mut BTreeMap<String, String>,
    provider_type: Option<&str>,
    trace_id: &str,
) -> bool {
    let is_relay = provider_type
        .map(|value| value.trim().eq_ignore_ascii_case("relay"))
        .unwrap_or(false);
    if !is_relay || trace_id.trim().is_empty() {
        return false;
    }
    headers.insert(ECHO_REQUEST_HEADER.to_string(), "1".to_string());
    headers.insert(ECHO_TRACE_HEADER.to_string(), trace_id.to_string());
    // 与请求头同一条回执通道：要求 relay 把最终上游 body 一并回传。
    // 未开启 body 采集时 AE 侧不会落库（request_record_level 决定）。
    headers.insert(ECHO_BODY_REQUEST_HEADER.to_string(), "1".to_string());
    true
}
