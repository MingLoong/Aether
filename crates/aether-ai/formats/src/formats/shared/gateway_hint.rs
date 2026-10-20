//! `error.gateway_hint`：与 `error.message` **并列**的网关视角补充说明
//! （面板 `internal/upstream/hint.go` 的等价物，任务书 gateway-hint）。
//!
//! 纪律（逐条对齐面板）：
//! - `error.message` 永远是**上游原文/既有文案** ✓；`gateway_hint` 只做**并列**补充 ✓，
//!   **绝不替换、不包装** message ✓；
//! - 文案集中在本文件（一张 kind 表 + 上游业务码形态判定 ✓），不散落到各 handler 的 if-else ✓；
//! - **未覆盖形态返回 `None`** → 响应里**不带**该字段（不编造）✓；
//! - 措辞一律**英文** ✓（错误响应面向客户端工具链，英文是通用口径 ✓）。

use super::error_body::LocalCoreSyncErrorKind;

/// 上游业务码 11133（`model_param_invalid`）家族：参数被模型供应商拒绝。
pub const HINT_MODEL_PARAM_INVALID: &str =
    "request parameters were rejected by the model provider; \
check message format and model capabilities";
/// 上游业务码 11135（`invalid_image_data`）家族：图片数据无效。
pub const HINT_INVALID_IMAGE_DATA: &str = "image data rejected by upstream; \
use a real/valid image, may need a new conversation";
/// 上下文超限（上游 `prompt is too long` 家族 / 网关侧上下文判定）。
pub const HINT_CONTEXT_TOO_LONG: &str =
    "request context exceeds the model's limit; reduce history/message size";
/// 请求体过大（网关侧限制；面板无对应形态，措辞按本仓语义）。
pub const HINT_REQUEST_TOO_LARGE: &str =
    "request body exceeds the gateway's size limit; reduce the payload size";
/// 上游限流（模型级 6004 / 账号级 soft rate 同口径）。
pub const HINT_RATE_LIMITED: &str = "rate limited by upstream; retry after reset";
/// 网关过载 / 池内无可用账号。
///
/// ⚠️ 刻意**中性化**（与面板 `no_healthy_account` 的池视角措辞不同）：本仓的 `Overloaded`
/// 既可能是真上游过载、也可能是网关本地并发闸门 → 说成「upstream」会误导客户端 ✓。
pub const HINT_OVERLOADED: &str =
    "the gateway is overloaded or has no healthy account; retry after a short backoff";

/// 上游业务码 11133 家族判定（`code` 字段 / `model_param_invalid` / 文案家族）。
///
/// 子串口径**宁宽勿漏** ✓：hint 是补充说明而非权威分类 ✓，误判代价只是多一条中性补充说明 ✓。
fn is_model_param_invalid(lower: &str) -> bool {
    code_marker(lower, "11133")
        || lower.contains("model_param_invalid")
        || lower.contains("invalid request parameters")
        || lower.contains("request parameters do not meet the current model requirements")
}

/// 上游业务码 11135 家族判定（`code` 字段 / `invalid_image_data` / `replace the image`）。
fn is_invalid_image_data(lower: &str) -> bool {
    code_marker(lower, "11135")
        || lower.contains("invalid_image_data")
        || lower.contains("replace the image")
}

/// JSON `code` 字段命中（`"code":N` / `"code": N` / `"code":"N"` 等形态）。
/// `lower` 必须已是小写。
fn code_marker(lower: &str, code: &str) -> bool {
    [
        format!("\"code\":{code}"),
        format!("\"code\": {code}"),
        format!("\"code\":\"{code}\""),
        format!("\"code\": \"{code}\""),
    ]
    .iter()
    .any(|marker| lower.contains(marker.as_str()))
}

/// 由错误分类 + 上游文案（或 SSE error 帧 payload）给出 `error.gateway_hint`。
///
/// 返回 `None` = 未覆盖形态 → 调用方**不带该字段**。
///
/// 判定次序与面板一致：上游业务码（11133/11135）与「prompt is too long」**先于** kind 表
/// （这三族可能被归到 `InvalidRequest`/`Authentication` 等不同 kind 上 ✓，
/// hint 层自带判定更稳 ✓）；其余走 kind 一对一映射 ✓。
pub fn gateway_hint(kind: LocalCoreSyncErrorKind, message: &str) -> Option<&'static str> {
    let lower = message.to_ascii_lowercase();
    if is_model_param_invalid(&lower) {
        return Some(HINT_MODEL_PARAM_INVALID);
    }
    if is_invalid_image_data(&lower) {
        return Some(HINT_INVALID_IMAGE_DATA);
    }
    if lower.contains("prompt is too long") || lower.contains("context length exceeded") {
        return Some(HINT_CONTEXT_TOO_LONG);
    }
    match kind {
        LocalCoreSyncErrorKind::ContextLengthExceeded => Some(HINT_CONTEXT_TOO_LONG),
        LocalCoreSyncErrorKind::RequestTooLarge => Some(HINT_REQUEST_TOO_LARGE),
        LocalCoreSyncErrorKind::RateLimit => Some(HINT_RATE_LIMITED),
        LocalCoreSyncErrorKind::Overloaded => Some(HINT_OVERLOADED),
        // InvalidRequest / Authentication / PermissionDenied / NotFound / ServerError：
        // 语义过于宽泛（可能是客户端自己的错），**不编造** hint。
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn upstream_business_codes_win_over_kind() {
        // 11133 家族（参数被供应商拒绝）：即使 kind 是 InvalidRequest 也给参数 hint
        assert_eq!(
            gateway_hint(
                LocalCoreSyncErrorKind::InvalidRequest,
                r#"{"code":11133,"msg":"model_param_invalid"}"#
            ),
            Some(HINT_MODEL_PARAM_INVALID)
        );
        // 容差形态：带空格 / 字符串 code / 纯文案
        assert_eq!(
            gateway_hint(LocalCoreSyncErrorKind::InvalidRequest, r#"{"code": 11133}"#),
            Some(HINT_MODEL_PARAM_INVALID)
        );
        assert_eq!(
            gateway_hint(
                LocalCoreSyncErrorKind::ServerError,
                r#"{"extError":{"code":"11133"}}"#
            ),
            Some(HINT_MODEL_PARAM_INVALID)
        );
        assert_eq!(
            gateway_hint(
                LocalCoreSyncErrorKind::InvalidRequest,
                "Invalid request parameters, please check"
            ),
            Some(HINT_MODEL_PARAM_INVALID)
        );

        // 11135 家族（图片数据无效）
        assert_eq!(
            gateway_hint(
                LocalCoreSyncErrorKind::InvalidRequest,
                r#"{"code":11135,"msg":"invalid_image_data"}"#
            ),
            Some(HINT_INVALID_IMAGE_DATA)
        );
        assert_eq!(
            gateway_hint(
                LocalCoreSyncErrorKind::InvalidRequest,
                "please replace the image and retry"
            ),
            Some(HINT_INVALID_IMAGE_DATA)
        );

        // 「prompt is too long」先于 kind 表：即使被归成 ServerError 也给上下文 hint
        assert_eq!(
            gateway_hint(LocalCoreSyncErrorKind::ServerError, "prompt is too long"),
            Some(HINT_CONTEXT_TOO_LONG)
        );
    }

    #[test]
    fn kind_table_covers_only_unambiguous_kinds() {
        assert_eq!(
            gateway_hint(
                LocalCoreSyncErrorKind::ContextLengthExceeded,
                "too many tokens"
            ),
            Some(HINT_CONTEXT_TOO_LONG)
        );
        assert_eq!(
            gateway_hint(LocalCoreSyncErrorKind::RequestTooLarge, "body too big"),
            Some(HINT_REQUEST_TOO_LARGE)
        );
        assert_eq!(
            gateway_hint(LocalCoreSyncErrorKind::RateLimit, "rate limit"),
            Some(HINT_RATE_LIMITED)
        );
        assert_eq!(
            gateway_hint(LocalCoreSyncErrorKind::Overloaded, "服务繁忙，请稍后重试"),
            Some(HINT_OVERLOADED)
        );

        // 未覆盖形态：**必须**是 None（响应不带字段，不编造）
        for kind in [
            LocalCoreSyncErrorKind::InvalidRequest,
            LocalCoreSyncErrorKind::Authentication,
            LocalCoreSyncErrorKind::PermissionDenied,
            LocalCoreSyncErrorKind::NotFound,
            LocalCoreSyncErrorKind::ServerError,
        ] {
            assert_eq!(
                gateway_hint(kind, "some upstream message"),
                None,
                "{kind:?}"
            );
            assert_eq!(gateway_hint(kind, ""), None, "{kind:?} 空文案");
        }
    }
}
