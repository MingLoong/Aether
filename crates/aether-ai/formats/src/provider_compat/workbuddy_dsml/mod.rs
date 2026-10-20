//! WorkBuddy（腾讯 CodeBuddy）响应侧兼容：内联 DSML 工具调用标记的还原。
//!
//! 放在 `provider_compat` 而不是 gateway：**流改写矩阵归格式 crate 所有**
//! （见 `apps/aether-gateway/tests/architecture/ai_serving.rs` 的
//! `ai_serving_finalize_stream_rewrite_matrix_is_owned_by_format_crate`），
//! kiro 的流式状态机（`kiro_stream.rs`）就是先例。gateway 只负责把
//! `report_context` 递进来、把改写结果转发出去。
//!
//! 事实来源：开源面板 `linguo2625469/workbuddy2api-panel` 的 `dsml.go`。

mod dsml;
mod dsml_stream;
mod usage;

pub use dsml::{
    declared_workbuddy_tool_names, drop_truncated_workbuddy_tool_calls, repair_workbuddy_dsml_text,
    repair_workbuddy_openai_chat_sync_response, tool_name_is_acceptable, WorkbuddyDsmlRepair,
    WorkbuddyRepairedToolCall, WORKBUDDY_DSML_MAX_BLOCK_BYTES,
};
pub use dsml_stream::{
    has_workbuddy_internal_marker, maybe_build_workbuddy_dsml_stream_repair_for_parts,
    workbuddy_dsml_open_marker, WorkbuddyDsmlStreamRepair,
};
pub use usage::{
    ensure_workbuddy_usage_total, normalize_workbuddy_response_usage,
    normalize_workbuddy_usage_cache_aliases, workbuddy_usage_cache_hit_tokens,
};

use serde_json::Value;

/// Aether 内部标记头：让**响应侧**（finalize / 执行运行时）认出「这是 workbuddy 的
/// 计划」，而不必在 gateway 里内联 provider_type 判断（架构守卫禁止那种写法）。
///
/// 与 grok 的 `x-aether-grok-runtime` 同一手法：随出站头发给上游，上游忽略未知头。
/// 出站注入在 `aether-provider-transport` 的 `insert_workbuddy_request_headers`。
pub const WORKBUDDY_INTERNAL_HEADER: &str = "x-aether-workbuddy-runtime";

/// 流式侧入口：gateway 直接把 `report_context` 递进来，判定与状态机都在本模块。
///
/// 返回 `None` 表示这条流不该被接管（调用方原样透传）：没有内部标记头、或客户端与
/// 上游格式不同（跨格式由格式层的转换器负责，两边同时改会互相踩）。
pub fn maybe_build_workbuddy_dsml_stream_repair(
    report_context: Option<&Value>,
) -> Option<WorkbuddyDsmlStreamRepair> {
    let report_context = report_context?;
    maybe_build_workbuddy_dsml_stream_repair_for_parts(
        report_context.get("provider_request_headers"),
        report_context
            .get("client_api_format")
            .and_then(Value::as_str),
        report_context
            .get("provider_api_format")
            .and_then(Value::as_str),
        report_context.get("original_request_body"),
    )
}
