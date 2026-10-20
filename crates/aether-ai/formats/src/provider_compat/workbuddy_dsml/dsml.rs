//! WorkBuddy（腾讯 CodeBuddy）原生工具调用（DSML 标记）还原。
//!
//! **为什么需要它**：上游模型的工具调用不是结构化字段，而是一段内联标记文本；
//! 只有当请求声明了 `tools` 时，上游才会把它转换成 `tool_calls`。一旦某一跳丢了
//! `tools`（协议转换、一次性探测、复核回合），标记就会原样落进 assistant 正文，
//! 执行工具的客户端（Codex 一类只认结构化 `function_call`）把它当散文记进历史，
//! **回合直接结束、工具一次都没跑**——失败是静默的。
//!
//! 标记形状（`‖` 是两个 U+FF5C 全角竖线）：
//!
//! ```text
//! <‖‖DSML‖‖ calls>
//! <‖‖DSML‖‖ invoke name="exec_command">
//! <‖‖DSML‖‖ parameter name="cmd" string="true">ls -la<‖‖DSML‖‖ parameter>
//! </‖‖DSML‖‖ invoke>
//! </‖‖DSML‖‖ calls>
//! ```
//!
//! 接受条件（照面板 `internal/upstream/dsml.go` 的口径）：
//! 整块闭合；invoke / parameter 之间有且只有空白；至少一个 invoke；
//! 工具名校验在**声明清单非空时严格**（必须在清单里）、清单为空时宽松
//! （只要求形状合法）；超过 256 KiB 仍未闭合的块直接放弃。
//!
//! **绝不吞字节**：任何一条不满足就返回 `None`，调用方保持原文（含开标签）不动。
//!
//! 事实来源：开源面板 `linguo2625469/workbuddy2api-panel` 的 `dsml.go`。

use std::sync::LazyLock;

use regex::Regex;
use serde_json::{json, Map, Value};

use super::dsml_stream::has_workbuddy_internal_marker;

/// 分隔符：两个 U+FF5C 全角竖线。
const MARKUP_PIPE: &str = "\u{FF5C}\u{FF5C}";
/// 未闭合块的字节上限：超过就放弃（面板 `markupMaxBlockBytes`）。
pub const WORKBUDDY_DSML_MAX_BLOCK_BYTES: usize = 256 * 1024;

/// 宽松模式下的工具名形状（面板 `markupToolNameRe`）。
static WEAK_TOOL_NAME_RE: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"^[A-Za-z0-9_][A-Za-z0-9_.:-]{0,63}$").expect("regex"));

static INVOKE_RE: LazyLock<Regex> = LazyLock::new(|| {
    // 与面板逐字一致：标记前缀与 `invoke`、`invoke` 与 `name=` 之间都允许**任意空白**
    // （`\s+`，含换行/制表/多空格）。早期版本这里写成字面单空格，上游只要多一个空格
    // 或换成换行就认不出块 → DSML 原文透传给客户端、工具调用直接失效。
    Regex::new(&format!(
        r#"{}\s+invoke\s+name="([^"]*)"\s*>"#,
        regex::escape(&format!("<{MARKUP_PIPE}DSML{MARKUP_PIPE}"))
    ))
    .expect("regex")
});

static PARAMETER_RE: LazyLock<Regex> = LazyLock::new(|| {
    // 同样对齐面板：`\s+parameter\s+name=` + 可选 `string` 属性 + 任意空白 + `>`。
    Regex::new(&format!(
        r#"{}\s+parameter\s+name="([^"]*)"(?:\s+string="(true|false)")?\s*>"#,
        regex::escape(&format!("<{MARKUP_PIPE}DSML{MARKUP_PIPE}"))
    ))
    .expect("regex")
});

fn open_marker() -> String {
    format!("<{MARKUP_PIPE}DSML{MARKUP_PIPE} calls>")
}

fn close_marker() -> String {
    format!("</{MARKUP_PIPE}DSML{MARKUP_PIPE} calls>")
}

fn invoke_close_marker() -> String {
    format!("</{MARKUP_PIPE}DSML{MARKUP_PIPE} invoke>")
}

fn parameter_close_marker() -> String {
    format!("</{MARKUP_PIPE}DSML{MARKUP_PIPE} parameter>")
}

/// 还原出的一次工具调用。
#[derive(Debug, Clone, PartialEq)]
pub struct WorkbuddyRepairedToolCall {
    pub name: String,
    pub arguments: Value,
}

/// 还原结果：去掉标记后的正文 + 结构化调用。
#[derive(Debug, Clone, PartialEq)]
pub struct WorkbuddyDsmlRepair {
    pub text: String,
    pub calls: Vec<WorkbuddyRepairedToolCall>,
}

/// 从文本里还原 DSML 工具调用。
///
/// 返回 `None` 表示「没有可接受的完整块」——调用方必须原样保留文本。
/// 只处理**第一块**完整标记：一块都还原不了时不做部分猜测。
pub fn repair_workbuddy_dsml_text(
    text: &str,
    declared_tools: &[String],
) -> Option<WorkbuddyDsmlRepair> {
    let open = open_marker();
    let open_at = text.find(&open)?;
    let body_start = open_at + open.len();
    let close = close_marker();
    let close_offset = text[body_start..].find(&close)?;
    let block = &text[body_start..body_start + close_offset];
    if block.len() > WORKBUDDY_DSML_MAX_BLOCK_BYTES {
        return None;
    }
    let calls = parse_workbuddy_dsml_block(block, declared_tools)?;
    if calls.is_empty() {
        return None;
    }
    let mut repaired = String::with_capacity(text.len());
    repaired.push_str(&text[..open_at]);
    repaired.push_str(&text[body_start + close_offset + close.len()..]);
    Some(WorkbuddyDsmlRepair {
        text: repaired.trim().to_string(),
        calls,
    })
}

/// 解析**块内部**（开标记与闭标记之间）的 invoke/parameter 序列。
///
/// 流式还原器（`dsml_stream.rs`）复用同一份解析逻辑：两边对「什么算合法块」的
/// 判断必须完全一致，否则会出现「整段能还原、流式还原不了」的不一致。
pub(crate) fn parse_workbuddy_dsml_block(
    block: &str,
    declared_tools: &[String],
) -> Option<Vec<WorkbuddyRepairedToolCall>> {
    let invoke_close = invoke_close_marker();
    let parameter_close = parameter_close_marker();
    let mut rest = block;
    let mut calls = Vec::new();

    loop {
        let trimmed = rest.trim_start();
        if trimmed.is_empty() {
            break;
        }
        rest = trimmed;
        if rest.starts_with(&invoke_close) {
            // 多余的 invoke 闭合标签：块结构非法。
            return None;
        }
        let captures = INVOKE_RE.captures(rest)?;
        let whole = captures.get(0)?;
        if whole.start() != 0 {
            // invoke 之前夹了非空白内容。
            return None;
        }
        let name = captures.get(1)?.as_str().trim().to_string();
        rest = &rest[whole.end()..];

        let mut arguments = Map::new();
        loop {
            let trimmed = rest.trim_start();
            if trimmed.starts_with(&invoke_close) {
                rest = &trimmed[invoke_close.len()..];
                break;
            }
            let captures = PARAMETER_RE.captures(trimmed)?;
            let whole = captures.get(0)?;
            if whole.start() != 0 {
                return None;
            }
            let parameter_name = captures.get(1)?.as_str().trim().to_string();
            let raw_string = captures
                .get(2)
                .map(|value| value.as_str().eq_ignore_ascii_case("true"))
                .unwrap_or(false);
            let after_open = &trimmed[whole.end()..];
            let close_at = after_open.find(&parameter_close)?;
            let raw_value = &after_open[..close_at];
            rest = &after_open[close_at + parameter_close.len()..];
            arguments.insert(parameter_name, parameter_value(raw_value, raw_string));
        }

        if !tool_name_is_acceptable(&name, declared_tools) {
            return None;
        }
        calls.push(WorkbuddyRepairedToolCall {
            name,
            arguments: Value::Object(arguments),
        });
    }

    Some(calls)
}

/// `string="true"` → 原样字符串；否则先试 JSON，失败退化成字符串（面板同口径）。
fn parameter_value(raw: &str, raw_string: bool) -> Value {
    if raw_string {
        return Value::String(raw.to_string());
    }
    match serde_json::from_str::<Value>(raw) {
        Ok(value) => value,
        Err(_) => Value::String(raw.to_string()),
    }
}

/// 工具名验收：声明清单非空 → 必须命中；清单为空 → 只校验形状。
pub fn tool_name_is_acceptable(name: &str, declared_tools: &[String]) -> bool {
    let name = name.trim();
    if name.is_empty() {
        return false;
    }
    if declared_tools.is_empty() {
        return WEAK_TOOL_NAME_RE.is_match(name);
    }
    declared_tools
        .iter()
        .any(|declared| declared.trim() == name)
}

/// 从 openai:chat 请求体里收集「本次声明过的工具名」。
///
/// 两个来源都要看，因为任一都可能缺失：请求声明（`tools[].function.name` /
/// `tools[].name` / 遗留 `functions[].name`）与历史消息里已出现过的调用名。
pub fn declared_workbuddy_tool_names(body: &Value) -> Vec<String> {
    let mut names: Vec<String> = Vec::new();
    let mut push = |value: Option<&str>| {
        let Some(value) = value.map(str::trim).filter(|value| !value.is_empty()) else {
            return;
        };
        if !names.iter().any(|existing| existing == value) {
            names.push(value.to_string());
        }
    };

    if let Some(tools) = body.get("tools").and_then(Value::as_array) {
        for tool in tools {
            push(
                tool.get("function")
                    .and_then(|function| function.get("name"))
                    .and_then(Value::as_str),
            );
            push(tool.get("name").and_then(Value::as_str));
        }
    }
    if let Some(functions) = body.get("functions").and_then(Value::as_array) {
        for function in functions {
            push(function.get("name").and_then(Value::as_str));
        }
    }
    if let Some(messages) = body.get("messages").and_then(Value::as_array) {
        for message in messages {
            if let Some(tool_calls) = message.get("tool_calls").and_then(Value::as_array) {
                for call in tool_calls {
                    push(
                        call.get("function")
                            .and_then(|function| function.get("name"))
                            .and_then(Value::as_str),
                    );
                }
            }
            push(
                message
                    .get("function_call")
                    .and_then(|call| call.get("name"))
                    .and_then(Value::as_str),
            );
        }
    }
    names
}

/// 同步（非流式）openai:chat 响应的 DSML 还原入口。
///
/// 供 gateway 的 finalize 层调用：判定全部留在本 crate，调用方只传原始数据，
/// 不在 gateway 里内联 provider_type 判断（架构守卫的要求）。
///
/// 只在**同时满足**下列条件时动手，否则原样返回 `false`：
/// 1. `provider_request_headers` 里带内部标记头 `x-aether-workbuddy-runtime: 1`
///    （由出站头注入，见 `insert_workbuddy_request_headers`）；
/// 2. 客户端与上游同为 `openai:chat`（跨格式转换后的响应形态由格式层负责）；
/// 3. `choices[0].message` 有字符串 `content`、**没有**结构化 `tool_calls`；
/// 4. `finish_reason == "stop"`（`length` 截断的正文里不可能有完整块）。
///
/// 还原成功时把正文替换为去掉标记的文本（为空则删除该字段）、写入
/// `message.tool_calls`、并把 `finish_reason` 改成 `tool_calls`。
/// 生成工具调用 id：`call_<纳秒时间戳>_<序号>`（面板 `markupCallID` 逐字口径）。
///
/// 为什么必须带时间戳：客户端按 id 把 `role: tool` 结果配回调用。早期实现是
/// `call_wb2a_<序号>`——**每次响应都从 0 开始**，同一会话多轮之间 id 会重复，
/// 客户端可能把结果配到上一轮的调用上。面板用纳秒时间戳保证跨响应唯一。
pub(crate) fn workbuddy_dsml_call_id(index: usize) -> String {
    let nanos = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|duration| duration.as_nanos())
        .unwrap_or_default();
    format!("call_{nanos}_{index}")
}

/// 丢弃参数残缺的工具调用（面板 `truncation.go::dropTruncatedToolCalls`）。
///
/// 为什么必须有：流被截断时（`finish_reason == "length"`，模型撞 `max_tokens` 提前中止）
/// 工具调用的 `arguments` 会只剩半截 JSON；原样交给客户端会让它解析非法 JSON **卡死会话**。
/// 面板的处置是**丢弃**这些调用（而不是补成 `{}` 伪造合法外观）。
///
/// 判定只看 `arguments` 本身：
/// - 空串 / 纯空白 → **保留**（无参工具合法）；
/// - 非空且 JSON 解析失败 → **丢弃**（截断）；
/// - 能解析（含 `null`/标量/数组等任何合法 JSON）→ 保留。
///
/// 只在 `finish_reason == "length"` 时动手。面板另有「流没收 `[DONE]`」的触发条件，那需要
/// **聚合整条流**才有的信息；Aether 流式路径逐帧透传、无法收回已发出的 delta，差异见
/// `docs/operations/workbuddy-provider.md`。返回是否发生了丢弃。
pub fn drop_truncated_workbuddy_tool_calls(response_body: &mut Value) -> bool {
    let Some(choices) = response_body
        .get_mut("choices")
        .and_then(Value::as_array_mut)
    else {
        return false;
    };
    let mut dropped = false;
    for choice in choices.iter_mut() {
        let Some(choice) = choice.as_object_mut() else {
            continue;
        };
        let finish_reason = choice
            .get("finish_reason")
            .and_then(Value::as_str)
            .unwrap_or_default()
            .trim();
        if !finish_reason.eq_ignore_ascii_case("length") {
            continue;
        }
        let Some(message) = choice.get_mut("message").and_then(Value::as_object_mut) else {
            continue;
        };
        let Some(calls) = message.get_mut("tool_calls").and_then(Value::as_array_mut) else {
            continue;
        };
        let before = calls.len();
        calls.retain(|call| !workbuddy_tool_call_arguments_truncated(call));
        if calls.len() != before {
            dropped = true;
        }
        if calls.is_empty() {
            message.remove("tool_calls");
        }
    }
    dropped
}

/// 该工具调用的 `arguments` 是否「非空但无法解析」（面板 `isTruncatedArguments`）。
fn workbuddy_tool_call_arguments_truncated(call: &Value) -> bool {
    let Some(arguments) = call
        .get("function")
        .and_then(|function| function.get("arguments"))
        .and_then(Value::as_str)
    else {
        return false;
    };
    let trimmed = arguments.trim();
    if trimmed.is_empty() {
        return false;
    }
    serde_json::from_str::<Value>(trimmed).is_err()
}

pub fn repair_workbuddy_openai_chat_sync_response(
    provider_request_headers: Option<&Value>,
    client_api_format: Option<&str>,
    original_request_body: Option<&Value>,
    response_body: &mut Value,
) -> bool {
    if !has_workbuddy_internal_marker(provider_request_headers) {
        return false;
    }
    let client_api_format = client_api_format.unwrap_or_default().trim();
    if !client_api_format.eq_ignore_ascii_case("openai:chat") {
        return false;
    }
    // 截断清理先做：`finish_reason == "length"` 时丢弃参数残缺的调用（与下面的 DSML
    // 还原互不影响——还原要求 `finish_reason == "stop"`）。
    let dropped_truncated = drop_truncated_workbuddy_tool_calls(response_body);
    // usage 规范化（缓存命中别名对齐 + total_tokens 补齐）与 DSML 无关，凡本 provider 的
    // 响应都做一次。
    super::usage::normalize_workbuddy_response_usage(response_body);
    let Some(choices) = response_body
        .get_mut("choices")
        .and_then(Value::as_array_mut)
    else {
        return false;
    };
    let Some(choice) = choices.first_mut().and_then(Value::as_object_mut) else {
        return false;
    };
    let finish_reason = choice
        .get("finish_reason")
        .and_then(Value::as_str)
        .unwrap_or_default()
        .trim()
        .to_ascii_lowercase();
    if finish_reason != "stop" {
        // `length` 截断走的就是这条：截断清理可能已经改过 body，如实上报。
        return dropped_truncated;
    }
    let Some(message) = choice.get_mut("message").and_then(Value::as_object_mut) else {
        return false;
    };
    if message
        .get("tool_calls")
        .and_then(Value::as_array)
        .is_some_and(|calls| !calls.is_empty())
    {
        // 已有结构化调用（可能是截断清理后剩下的）：不再做 DSML 还原，但要如实上报变更。
        return dropped_truncated;
    }
    let Some(content) = message
        .get("content")
        .and_then(Value::as_str)
        .map(str::to_string)
    else {
        return false;
    };
    if !content.contains(&open_marker()) {
        return false;
    }

    let declared_tools = original_request_body
        .map(declared_workbuddy_tool_names)
        .unwrap_or_default();
    let Some(repaired) = repair_workbuddy_dsml_text(&content, &declared_tools) else {
        return false;
    };

    if repaired.text.is_empty() {
        message.remove("content");
    } else {
        message.insert("content".to_string(), Value::String(repaired.text));
    }
    message.insert(
        "tool_calls".to_string(),
        Value::Array(
            repaired
                .calls
                .into_iter()
                .enumerate()
                .map(|(index, call)| {
                    json!({
                        "id": workbuddy_dsml_call_id(index),
                        "type": "function",
                        "function": {
                            "name": call.name,
                            // 上游与 OpenAI 一致：arguments 是 JSON 字符串。
                            "arguments": serde_json::to_string(&call.arguments)
                                .unwrap_or_else(|_| "{}".to_string()),
                        }
                    })
                })
                .collect(),
        ),
    );
    choice.insert(
        "finish_reason".to_string(),
        Value::String("tool_calls".to_string()),
    );
    true
}

// 内部标记头的判定与流式模块共用一份实现（`dsml_stream::has_workbuddy_internal_marker`），
// 避免出现「同步认得出、流式认不出」的偏差。

#[cfg(test)]
mod tests {
    use serde_json::{json, Value};

    use super::{
        declared_workbuddy_tool_names, repair_workbuddy_dsml_text,
        repair_workbuddy_openai_chat_sync_response, tool_name_is_acceptable,
        WORKBUDDY_DSML_MAX_BLOCK_BYTES,
    };
    use crate::provider_compat::workbuddy_dsml::WORKBUDDY_INTERNAL_HEADER;

    fn marker_headers() -> Value {
        json!({ WORKBUDDY_INTERNAL_HEADER: "1" })
    }

    fn sync_response(content: &str) -> Value {
        json!({
            "id": "chatcmpl-1",
            "object": "chat.completion",
            "choices": [{
                "index": 0,
                "message": {"role": "assistant", "content": content},
                "finish_reason": "stop"
            }]
        })
    }

    /// 标记内的**任意空白**都要容忍（面板正则是 `\s+`，不是字面空格）：
    /// 上游只要多一个空格或换行，早期实现就认不出块 → DSML 原文透传、工具调用失效。
    #[test]
    fn marker_whitespace_variations_are_tolerated() {
        use super::{open_marker, repair_workbuddy_dsml_text};

        let pipe = "\u{FF5C}\u{FF5C}";
        // 开/闭标记本身是**固定串**（面板同样是常量），只有 invoke/parameter **头内部**
        // 允许任意空白——这正是面板 `\s+` 覆盖的范围。
        let open = format!("<{pipe}DSML{pipe} calls>");
        let close = format!("</{pipe}DSML{pipe} calls>");
        for (invoke, parameter) in [
            (
                format!("<{pipe}DSML{pipe} invoke"),
                format!("<{pipe}DSML{pipe} parameter"),
            ),
            (
                format!("<{pipe}DSML{pipe}  invoke"),
                format!("<{pipe}DSML{pipe}  parameter"),
            ),
            (
                format!("<{pipe}DSML{pipe}\tinvoke"),
                format!("<{pipe}DSML{pipe}\nparameter"),
            ),
        ] {
            let text = format!(
                "{open}\n{invoke} name=\"exec_command\">\n{parameter} name=\"cmd\" string=\"true\">ls -la</{pipe}DSML{pipe} parameter>\n</{pipe}DSML{pipe} invoke>\n{close}"
            );
            let repaired = repair_workbuddy_dsml_text(&text, &["exec_command".to_string()])
                .unwrap_or_else(|| panic!("空白形态应被识别：{text:?}"));
            assert_eq!(repaired.calls.len(), 1, "{text:?}");
            assert_eq!(repaired.calls[0].name, "exec_command");
        }

        // 开标记本身（无额外空白）仍然正常。
        assert!(repair_workbuddy_dsml_text(&open_marker(), &[]).is_none());
    }

    /// 工具调用 id 必须**跨响应唯一**（带纳秒时间戳），否则客户端会把多轮的结果配错。
    #[test]
    fn dsml_call_ids_are_unique_across_responses() {
        use super::workbuddy_dsml_call_id;

        let first = workbuddy_dsml_call_id(0);
        assert!(first.starts_with("call_"), "{first}");
        assert!(first.ends_with("_0"), "{first}");
        // 序号相同、时间不同 → 两次调用不应相等（纳秒级时间戳保证）。
        let mut ids = std::collections::BTreeSet::new();
        for index in 0..8 {
            ids.insert(workbuddy_dsml_call_id(index));
            std::thread::sleep(std::time::Duration::from_millis(1));
        }
        assert_eq!(ids.len(), 8, "同一批内 id 必须互不相同");
    }

    /// 截断清理（面板 `dropTruncatedToolCalls`）：只在 `finish_reason == "length"` 时丢弃
    /// 参数残缺的调用；空参数（无参工具）与可解析参数一律保留。
    #[test]
    fn truncated_tool_calls_are_dropped_only_when_the_stream_was_cut() {
        use super::drop_truncated_workbuddy_tool_calls;

        let call = |id: &str, arguments: &str| {
            json!({
                "id": id,
                "type": "function",
                "function": {"name": "f", "arguments": arguments}
            })
        };

        // length 截断：残缺参数被丢、完整/空/可解析标量保留。
        let mut body = json!({
            "choices": [{
                "finish_reason": "length",
                "message": {
                    "role": "assistant",
                    "content": "",
                    "tool_calls": [
                        call("c1", "{\"a\": 1}"),
                        call("c2", "{\"a\": "),
                        call("c3", ""),
                        call("c4", "null")
                    ]
                }
            }]
        });
        assert!(drop_truncated_workbuddy_tool_calls(&mut body));
        let calls = body["choices"][0]["message"]["tool_calls"]
            .as_array()
            .expect("array");
        let ids: Vec<&str> = calls
            .iter()
            .map(|call| call["id"].as_str().unwrap_or(""))
            .collect();
        assert_eq!(ids, vec!["c1", "c3", "c4"], "只丢残缺参数那条：{calls:?}");

        // finish_reason == stop：一字不动（没被截断；脏参数属于模型输出问题，交客户端校验）。
        let mut body = json!({
            "choices": [{
                "finish_reason": "stop",
                "message": {"tool_calls": [call("c2", "{\"a\": ")]}
            }]
        });
        assert!(!drop_truncated_workbuddy_tool_calls(&mut body));
        assert_eq!(
            body["choices"][0]["message"]["tool_calls"][0]["id"],
            json!("c2")
        );

        // 全被丢光 → 删掉 tool_calls 键（不留空数组）。
        let mut body = json!({
            "choices": [{
                "finish_reason": "length",
                "message": {"tool_calls": [call("c2", "{\"a\": ")]}
            }]
        });
        assert!(drop_truncated_workbuddy_tool_calls(&mut body));
        assert!(body["choices"][0]["message"].get("tool_calls").is_none());

        // 没有 tool_calls / 没有 choices：不 panic、返回 false。
        let mut body = json!({"choices": [{"finish_reason": "length", "message": {}}]});
        assert!(!drop_truncated_workbuddy_tool_calls(&mut body));
        let mut body = json!({});
        assert!(!drop_truncated_workbuddy_tool_calls(&mut body));
    }

    /// 入口函数端到端：length 截断的响应走完后，残缺调用已被丢掉；非 workbuddy 不碰。
    #[test]
    fn sync_repair_entry_drops_truncated_calls() {
        use super::repair_workbuddy_openai_chat_sync_response;

        let headers = marker_headers();
        let mut body = json!({
            "choices": [{
                "finish_reason": "length",
                "message": {
                    "role": "assistant",
                    "content": "被截断的正文",
                    "tool_calls": [{
                        "id": "c1",
                        "type": "function",
                        "function": {"name": "f", "arguments": "{\"a\": "}
                    }]
                }
            }]
        });
        let changed = repair_workbuddy_openai_chat_sync_response(
            Some(&headers),
            Some("openai:chat"),
            None,
            &mut body,
        );
        assert!(changed, "丢弃发生时应上报变更");
        assert!(
            body["choices"][0]["message"].get("tool_calls").is_none(),
            "残缺调用应被丢弃：{}",
            body["choices"][0]["message"]
        );

        // 非 workbuddy（没有内部标记头）→ 不碰。
        let mut body = json!({
            "choices": [{
                "finish_reason": "length",
                "message": {"tool_calls": [{"id": "c1", "function": {"arguments": "{"}}]}
            }]
        });
        assert!(!repair_workbuddy_openai_chat_sync_response(
            None,
            Some("openai:chat"),
            None,
            &mut body
        ));
        assert!(body["choices"][0]["message"].get("tool_calls").is_some());
    }

    #[test]
    fn sync_repair_rewrites_content_into_tool_calls() {
        let content = format!(
            "我来执行\n{}",
            block(&invoke("exec_command", &parameter("cmd", true, "ls -la")))
        );
        let mut response = sync_response(&content);
        let request_body =
            json!({"tools": [{"type": "function", "function": {"name": "exec_command"}}]});

        let changed = repair_workbuddy_openai_chat_sync_response(
            Some(&marker_headers()),
            Some("openai:chat"),
            Some(&request_body),
            &mut response,
        );
        assert!(changed);

        let choice = &response["choices"][0];
        assert_eq!(choice["finish_reason"], "tool_calls");
        assert_eq!(choice["message"]["content"], "我来执行");
        let calls = choice["message"]["tool_calls"]
            .as_array()
            .expect("tool_calls");
        assert_eq!(calls.len(), 1);
        assert_eq!(calls[0]["type"], "function");
        assert_eq!(calls[0]["function"]["name"], "exec_command");
        // arguments 必须是 JSON 字符串（OpenAI 形态）。
        let arguments: Value =
            serde_json::from_str(calls[0]["function"]["arguments"].as_str().expect("string"))
                .expect("arguments should be json");
        assert_eq!(arguments["cmd"], json!("ls -la"));
    }

    /// 没有内部标记 / 不是同格式 / 已有结构化调用 / 非 stop —— 四种情况都必须零改动。
    #[test]
    fn sync_repair_is_scoped_and_never_overwrites_structured_calls() {
        let content = block(&invoke("exec_command", &parameter("cmd", true, "ls")));

        let mut response = sync_response(&content);
        assert!(!repair_workbuddy_openai_chat_sync_response(
            None,
            Some("openai:chat"),
            None,
            &mut response
        ));
        assert_eq!(response["choices"][0]["finish_reason"], "stop");

        let mut response = sync_response(&content);
        assert!(!repair_workbuddy_openai_chat_sync_response(
            Some(&marker_headers()),
            Some("claude:messages"),
            None,
            &mut response
        ));

        let mut response = sync_response(&content);
        response["choices"][0]["message"]["tool_calls"] = json!([{"id": "call_1", "type": "function", "function": {"name": "real", "arguments": "{}"}}]);
        assert!(!repair_workbuddy_openai_chat_sync_response(
            Some(&marker_headers()),
            Some("openai:chat"),
            None,
            &mut response
        ));
        assert_eq!(
            response["choices"][0]["message"]["tool_calls"][0]["function"]["name"],
            "real"
        );

        let mut response = sync_response(&content);
        response["choices"][0]["finish_reason"] = json!("length");
        assert!(!repair_workbuddy_openai_chat_sync_response(
            Some(&marker_headers()),
            Some("openai:chat"),
            None,
            &mut response
        ));

        let mut response = sync_response("普通回答");
        assert!(!repair_workbuddy_openai_chat_sync_response(
            Some(&marker_headers()),
            Some("openai:chat"),
            None,
            &mut response
        ));
    }

    /// 还原后正文为空时删除 content 字段（不留空串）。
    #[test]
    fn sync_repair_drops_empty_content() {
        let content = block(&invoke("exec_command", &parameter("cmd", true, "ls")));
        let mut response = sync_response(&content);
        assert!(repair_workbuddy_openai_chat_sync_response(
            Some(&marker_headers()),
            Some("openai:chat"),
            None,
            &mut response
        ));
        assert!(response["choices"][0]["message"].get("content").is_none());
    }

    /// 拼一个合法标记块（`‖` 用两个 U+FF5C）。
    fn block(invokes: &str) -> String {
        let pipe = "\u{FF5C}\u{FF5C}";
        format!("<{pipe}DSML{pipe} calls>{invokes}</{pipe}DSML{pipe} calls>")
    }

    fn invoke(name: &str, params: &str) -> String {
        let pipe = "\u{FF5C}\u{FF5C}";
        format!("<{pipe}DSML{pipe} invoke name=\"{name}\">{params}</{pipe}DSML{pipe} invoke>")
    }

    fn parameter(name: &str, string_flag: bool, value: &str) -> String {
        let pipe = "\u{FF5C}\u{FF5C}";
        let flag = if string_flag { " string=\"true\"" } else { "" };
        format!(
            "<{pipe}DSML{pipe} parameter name=\"{name}\"{flag}>{value}</{pipe}DSML{pipe} parameter>"
        )
    }

    #[test]
    fn repairs_a_canonical_block_into_tool_calls() {
        let text = format!(
            "先看一下目录\n{}",
            block(&invoke("exec_command", &parameter("cmd", true, "ls -la")))
        );
        let repaired = repair_workbuddy_dsml_text(&text, &["exec_command".to_string()])
            .expect("canonical block should repair");

        // 标记整体（含开闭标签）从正文里消失，前后正文保留。
        assert!(!repaired.text.contains("DSML"));
        assert_eq!(repaired.text, "先看一下目录");
        assert_eq!(repaired.calls.len(), 1);
        assert_eq!(repaired.calls[0].name, "exec_command");
        assert_eq!(repaired.calls[0].arguments["cmd"], json!("ls -la"));
    }

    #[test]
    fn reparses_json_parameters_when_string_flag_is_absent() {
        let text = block(&invoke(
            "exec_command",
            &format!(
                "{}{}",
                parameter("timeout", false, "30"),
                parameter("env", false, "{\"A\":\"1\"}")
            ),
        ));
        let repaired =
            repair_workbuddy_dsml_text(&text, &["exec_command".to_string()]).expect("repair");
        // 非 string 参数先试 JSON：数字与对象都要还原成结构，而不是字符串。
        assert_eq!(repaired.calls[0].arguments["timeout"], json!(30));
        assert_eq!(repaired.calls[0].arguments["env"], json!({"A": "1"}));
    }

    /// 未闭合的块必须**原样保留**（含开标签），一个字节都不能吞。
    #[test]
    fn unclosed_block_is_left_verbatim() {
        let text = format!(
            "<{pipe}DSML{pipe} calls><{pipe}DSML{pipe} invoke name=\"exec_command\">",
            pipe = "\u{FF5C}\u{FF5C}"
        );
        assert!(repair_workbuddy_dsml_text(&text, &[]).is_none());
    }

    #[test]
    fn stray_non_whitespace_between_invokes_is_rejected() {
        let text = block(&format!(
            "{}{}",
            invoke("exec_command", &parameter("cmd", true, "ls")),
            "夹了正文"
        ));
        assert!(repair_workbuddy_dsml_text(&text, &[]).is_none());
    }

    #[test]
    fn unknown_tool_name_is_strict_when_a_list_is_declared_and_weak_when_empty() {
        let text = block(&invoke("rm_rf", &parameter("cmd", true, "x")));
        // 声明清单非空 → 严格：不在清单里就整体放弃。
        assert!(repair_workbuddy_dsml_text(&text, &["exec_command".to_string()]).is_none());
        // 清单为空 → 宽松：形状合法即可（这正是「tools 丢在路上」的常见形态）。
        let repaired = repair_workbuddy_dsml_text(&text, &[]).expect("weak mode should repair");
        assert_eq!(repaired.calls[0].name, "rm_rf");

        // 宽松模式仍要挡掉形状非法的名字（含空格、首字符非法、超长）。
        assert!(!tool_name_is_acceptable("has space", &[]));
        assert!(!tool_name_is_acceptable("-leading", &[]));
        assert!(!tool_name_is_acceptable(&"x".repeat(65), &[]));
        assert!(tool_name_is_acceptable("exec_command", &[]));
        assert!(tool_name_is_acceptable("mcp.tool:sub", &[]));
    }

    #[test]
    fn oversized_unclosed_block_is_abandoned() {
        let pipe = "\u{FF5C}\u{FF5C}";
        let mut text = format!("<{pipe}DSML{pipe} calls>");
        text.push_str(&"a".repeat(WORKBUDDY_DSML_MAX_BLOCK_BYTES + 1));
        assert!(repair_workbuddy_dsml_text(&text, &[]).is_none());
    }

    #[test]
    fn plain_text_is_untouched_and_needs_no_repair() {
        assert!(repair_workbuddy_dsml_text("普通回答，没有任何标记", &[]).is_none());
    }

    #[test]
    fn multiple_invokes_in_one_block_are_all_repaired() {
        let text = block(&format!(
            "{}{}",
            invoke("exec_command", &parameter("cmd", true, "ls")),
            invoke("read_file", &parameter("path", true, "/tmp/a"))
        ));
        let repaired = repair_workbuddy_dsml_text(
            &text,
            &["exec_command".to_string(), "read_file".to_string()],
        )
        .expect("repair");
        assert_eq!(repaired.calls.len(), 2);
        assert_eq!(repaired.calls[0].name, "exec_command");
        assert_eq!(repaired.calls[1].name, "read_file");
        assert_eq!(repaired.calls[1].arguments["path"], json!("/tmp/a"));
        assert!(repaired.text.is_empty());
    }

    #[test]
    fn declared_tool_names_collect_from_every_source() {
        let body = json!({
            "tools": [
                {"type": "function", "function": {"name": "exec_command"}},
                {"type": "function", "name": "bare_form"}
            ],
            "functions": [{"name": "legacy_form"}],
            "messages": [
                {"role": "assistant", "tool_calls": [{"function": {"name": "from_history"}}]},
                {"role": "assistant", "function_call": {"name": "legacy_history"}},
                {"role": "user", "content": "hi"}
            ]
        });
        let names = declared_workbuddy_tool_names(&body);
        for expected in [
            "exec_command",
            "bare_form",
            "legacy_form",
            "from_history",
            "legacy_history",
        ] {
            assert!(names.contains(&expected.to_string()), "missing {expected}");
        }
        assert_eq!(names.len(), 5, "不能重复收集：{names:?}");
    }
}
