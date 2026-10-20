use serde_json::{Map, Value};

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum LocalCoreSyncErrorKind {
    InvalidRequest,
    Authentication,
    PermissionDenied,
    NotFound,
    RateLimit,
    ContextLengthExceeded,
    RequestTooLarge,
    Overloaded,
    ServerError,
}

pub fn is_core_error_finalize_kind(report_kind: &str) -> bool {
    core_error_default_client_api_format(report_kind).is_some()
}

pub fn core_error_default_client_api_format(report_kind: &str) -> Option<&'static str> {
    crate::contracts::core_error_default_client_api_format(report_kind)
}

pub fn core_error_background_report_kind(report_kind: &str) -> Option<&'static str> {
    crate::contracts::core_error_background_report_kind(report_kind)
}

pub fn core_success_background_report_kind(report_kind: &str) -> Option<&'static str> {
    crate::contracts::core_success_background_report_kind(report_kind)
}

pub fn build_core_error_body_for_client_format(
    client_api_format: &str,
    message: &str,
    code: Option<&str>,
    kind: LocalCoreSyncErrorKind,
) -> Option<Value> {
    let mut error_object = Map::new();
    error_object.insert("message".to_string(), Value::String(message.to_string()));
    // `error.gateway_hint`（面板 `hint.go`）：与 message **并列**的网关视角补充说明 ✓，
    // **绝不替换/包装** message ✓；未覆盖形态**不带**该字段（不编造 ✓）。
    if let Some(hint) = super::gateway_hint::gateway_hint(kind, message) {
        error_object.insert("gateway_hint".to_string(), Value::String(hint.to_string()));
    }

    match aether_ai_formats::normalize_api_format_alias(client_api_format).as_str() {
        "openai:chat"
        | "openai:responses"
        | "openai:responses:compact"
        | "openai:search"
        | "openai:embedding" => {
            error_object.insert(
                "type".to_string(),
                Value::String(map_local_sync_error_kind_to_openai_type(kind).to_string()),
            );
            if let Some(code) = code.filter(|value| !value.is_empty()) {
                error_object.insert("code".to_string(), Value::String(code.to_string()));
            }
            Some(Value::Object(Map::from_iter([(
                "error".to_string(),
                Value::Object(error_object),
            )])))
        }
        "claude:messages" => {
            error_object.insert(
                "type".to_string(),
                Value::String(map_local_sync_error_kind_to_claude_type(kind).to_string()),
            );
            if let Some(code) = code.filter(|value| !value.is_empty()) {
                error_object.insert("code".to_string(), Value::String(code.to_string()));
            }
            Some(Value::Object(Map::from_iter([
                ("type".to_string(), Value::String("error".to_string())),
                ("error".to_string(), Value::Object(error_object)),
            ])))
        }
        "gemini:generate_content" => Some(Value::Object(Map::from_iter([(
            "error".to_string(),
            Value::Object({
                let mut gemini_error = Map::from_iter([
                    (
                        "code".to_string(),
                        Value::from(map_local_sync_error_kind_to_gemini_code(kind)),
                    ),
                    ("message".to_string(), Value::String(message.to_string())),
                    (
                        "status".to_string(),
                        Value::String(map_local_sync_error_kind_to_gemini_status(kind).to_string()),
                    ),
                ]);
                // gemini 的错误对象是另建的，hint 也要一并带上（同一事实来源）。
                if let Some(hint) = super::gateway_hint::gateway_hint(kind, message) {
                    gemini_error
                        .insert("gateway_hint".to_string(), Value::String(hint.to_string()));
                }
                gemini_error
            }),
        )]))),
        _ => None,
    }
}

fn map_local_sync_error_kind_to_openai_type(kind: LocalCoreSyncErrorKind) -> &'static str {
    match kind {
        LocalCoreSyncErrorKind::InvalidRequest => "invalid_request_error",
        LocalCoreSyncErrorKind::Authentication => "authentication_error",
        LocalCoreSyncErrorKind::PermissionDenied => "permission_error",
        LocalCoreSyncErrorKind::NotFound => "not_found_error",
        LocalCoreSyncErrorKind::RateLimit => "rate_limit_error",
        LocalCoreSyncErrorKind::ContextLengthExceeded | LocalCoreSyncErrorKind::RequestTooLarge => {
            "context_length_exceeded"
        }
        LocalCoreSyncErrorKind::Overloaded | LocalCoreSyncErrorKind::ServerError => "server_error",
    }
}

fn map_local_sync_error_kind_to_claude_type(kind: LocalCoreSyncErrorKind) -> &'static str {
    match kind {
        LocalCoreSyncErrorKind::InvalidRequest | LocalCoreSyncErrorKind::ContextLengthExceeded => {
            "invalid_request_error"
        }
        LocalCoreSyncErrorKind::RequestTooLarge => "request_too_large",
        LocalCoreSyncErrorKind::Authentication => "authentication_error",
        LocalCoreSyncErrorKind::PermissionDenied => "permission_error",
        LocalCoreSyncErrorKind::NotFound => "not_found_error",
        LocalCoreSyncErrorKind::RateLimit => "rate_limit_error",
        LocalCoreSyncErrorKind::Overloaded => "overloaded_error",
        LocalCoreSyncErrorKind::ServerError => "api_error",
    }
}

fn map_local_sync_error_kind_to_gemini_code(kind: LocalCoreSyncErrorKind) -> u16 {
    match kind {
        LocalCoreSyncErrorKind::InvalidRequest
        | LocalCoreSyncErrorKind::ContextLengthExceeded
        | LocalCoreSyncErrorKind::RequestTooLarge => 400,
        LocalCoreSyncErrorKind::Authentication => 401,
        LocalCoreSyncErrorKind::PermissionDenied => 403,
        LocalCoreSyncErrorKind::NotFound => 404,
        LocalCoreSyncErrorKind::RateLimit => 429,
        LocalCoreSyncErrorKind::Overloaded => 503,
        LocalCoreSyncErrorKind::ServerError => 500,
    }
}

fn map_local_sync_error_kind_to_gemini_status(kind: LocalCoreSyncErrorKind) -> &'static str {
    match kind {
        LocalCoreSyncErrorKind::InvalidRequest
        | LocalCoreSyncErrorKind::ContextLengthExceeded
        | LocalCoreSyncErrorKind::RequestTooLarge => "INVALID_ARGUMENT",
        LocalCoreSyncErrorKind::Authentication => "UNAUTHENTICATED",
        LocalCoreSyncErrorKind::PermissionDenied => "PERMISSION_DENIED",
        LocalCoreSyncErrorKind::NotFound => "NOT_FOUND",
        LocalCoreSyncErrorKind::RateLimit => "RESOURCE_EXHAUSTED",
        LocalCoreSyncErrorKind::Overloaded => "UNAVAILABLE",
        LocalCoreSyncErrorKind::ServerError => "INTERNAL",
    }
}

#[cfg(test)]
mod tests {
    use super::{
        build_core_error_body_for_client_format, core_success_background_report_kind,
        is_core_error_finalize_kind, LocalCoreSyncErrorKind,
    };

    #[test]
    fn builds_openai_core_error_body() {
        let body = build_core_error_body_for_client_format(
            "openai:chat",
            "bad request",
            Some("invalid_request"),
            LocalCoreSyncErrorKind::InvalidRequest,
        )
        .expect("body should build");

        assert_eq!(body["error"]["message"], "bad request");
        assert_eq!(body["error"]["type"], "invalid_request_error");
        assert_eq!(body["error"]["code"], "invalid_request");
    }

    #[test]
    fn builds_openai_search_core_error_body() {
        let body = build_core_error_body_for_client_format(
            "openai:search",
            "search unavailable",
            Some("upstream_unavailable"),
            LocalCoreSyncErrorKind::ServerError,
        )
        .expect("body should build");

        assert_eq!(body["error"]["message"], "search unavailable");
        assert_eq!(body["error"]["type"], "server_error");
        assert_eq!(body["error"]["code"], "upstream_unavailable");
    }

    #[test]
    fn builds_claude_overloaded_error_body() {
        let body = build_core_error_body_for_client_format(
            "claude:messages",
            "busy",
            None,
            LocalCoreSyncErrorKind::Overloaded,
        )
        .expect("body should build");

        assert_eq!(body["type"], "error");
        assert_eq!(body["error"]["type"], "overloaded_error");
    }

    #[test]
    fn maps_request_too_large_for_each_client_format() {
        let claude = build_core_error_body_for_client_format(
            "claude:messages",
            "too large",
            None,
            LocalCoreSyncErrorKind::RequestTooLarge,
        )
        .expect("Claude body should build");
        assert_eq!(claude["error"]["type"], "request_too_large");

        let openai = build_core_error_body_for_client_format(
            "openai:chat",
            "too large",
            None,
            LocalCoreSyncErrorKind::RequestTooLarge,
        )
        .expect("OpenAI body should build");
        assert_eq!(openai["error"]["type"], "context_length_exceeded");

        let gemini = build_core_error_body_for_client_format(
            "gemini:generate_content",
            "too large",
            None,
            LocalCoreSyncErrorKind::RequestTooLarge,
        )
        .expect("Gemini body should build");
        assert_eq!(gemini["error"]["code"], 400);
        assert_eq!(gemini["error"]["status"], "INVALID_ARGUMENT");
    }

    #[test]
    fn recognizes_finalize_kind_and_success_mapping() {
        assert!(is_core_error_finalize_kind("openai_chat_sync_finalize"));
        assert_eq!(
            core_success_background_report_kind("openai_chat_sync_finalize"),
            Some("openai_chat_sync_success")
        );
    }

    /// `error.gateway_hint`：三种格式都带；**未覆盖形态不带**；message 永远原样不动。
    #[test]
    fn core_error_body_carries_gateway_hint_only_when_covered() {
        use serde_json::json;

        let hint = super::super::gateway_hint::HINT_CONTEXT_TOO_LONG;
        for client_format in ["openai:chat", "claude:messages", "gemini:generate_content"] {
            let body = build_core_error_body_for_client_format(
                client_format,
                "prompt is too long",
                None,
                LocalCoreSyncErrorKind::ContextLengthExceeded,
            )
            .unwrap_or_else(|| panic!("{client_format} body"));
            // message 仍是上游原文（hint 绝不替换/包装它）
            assert_eq!(
                body["error"]["message"],
                json!("prompt is too long"),
                "{client_format}"
            );
            assert_eq!(
                body["error"]["gateway_hint"],
                json!(hint),
                "{client_format}"
            );
        }

        // 上游业务码形态优先于 kind（11133 → 参数 hint）
        let param = build_core_error_body_for_client_format(
            "openai:chat",
            r#"{"code":11133,"msg":"model_param_invalid"}"#,
            None,
            LocalCoreSyncErrorKind::InvalidRequest,
        )
        .expect("openai body");
        assert_eq!(
            param["error"]["gateway_hint"],
            json!(super::super::gateway_hint::HINT_MODEL_PARAM_INVALID)
        );
        assert_eq!(
            param["error"]["message"],
            json!(r#"{"code":11133,"msg":"model_param_invalid"}"#)
        );

        // 未覆盖形态：**不带**该字段（不编造），message 依旧原样
        let uncovered = build_core_error_body_for_client_format(
            "openai:chat",
            "upstream exploded",
            None,
            LocalCoreSyncErrorKind::ServerError,
        )
        .expect("openai body");
        assert!(uncovered["error"].get("gateway_hint").is_none());
        assert_eq!(uncovered["error"]["message"], json!("upstream exploded"));
    }
}
