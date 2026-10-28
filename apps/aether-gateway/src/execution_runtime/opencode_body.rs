//! 把发往 opencode 的请求体改写成「官方 CLI 的形状」。
//!
//! 背景见 `docs/opencode-tls13-egress.md` §8：实测结论是 ——
//! TLS 指纹、9 个请求头、官方系统提示词、11 个官方工具，**四者缺一不可**；
//! 而用户消息、多轮历史、追加的 system 消息、追加的自定义工具都可以叠加进去。
//!
//! 所以这里只做「补底座 + 保留用户内容」：
//! * 官方系统提示词放在最前面；客户端的 system 消息合并成一条紧随其后；
//! * 官方 11 个工具在前，客户端自带的工具按名字去重后追加；
//! * `stream` / `stream_options` 强制成官方取值（`max_tokens` 保持客户端原值）；
//! * 客户端**没带任何工具**时补 `tool_choice: "none"`（2026-10-29）：注入的工具只是
//!   过门禁用的，调用方没有执行能力时不该让模型去调它们；
//! * 其余字段（`model`、`temperature`、`max_tokens`、`tool_choice`）原样保留。

use std::collections::HashSet;

use serde_json::{json, Map, Value};

/// 官方 1.19.x 系统提示词模板。
///
/// 上游按真实取值校验：`{{MODEL}}` 必须是本次请求的模型 id（出现两处：模型名与
/// `opencode/<id>`），`{{DATE}}` 必须是当天日期（`Mon Jan 02 2006` 形态）。
/// 写死任何一个都会被上游判成「不像官方客户端」而回 429，所以这里保留占位符，
/// 每次请求渲染。
const OFFICIAL_SYSTEM_PROMPT_TEMPLATE: &str =
    include_str!("../../assets/opencode/system_prompt.txt");

/// 客户端自带的官方提示词标记：命中就不重复注入。
const OFFICIAL_SYSTEM_PROMPT_MARKER: &str = "You are opencode, an interactive CLI tool";

/// 渲染官方系统提示词：填模型 id 与当天日期。
fn render_official_system_prompt(model: &str) -> String {
    OFFICIAL_SYSTEM_PROMPT_TEMPLATE
        .replace("{{MODEL}}", model)
        .replace("{{DATE}}", &current_date_label())
}

/// 当天日期，格式与官方客户端一致（`Tue Oct 27 2026`，UTC）。
fn current_date_label() -> String {
    const WEEKDAYS: [&str; 7] = ["Thu", "Fri", "Sat", "Sun", "Mon", "Tue", "Wed"];
    const MONTHS: [&str; 12] = [
        "Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec",
    ];
    let secs = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|elapsed| elapsed.as_secs())
        .unwrap_or(0);
    let days = (secs / 86_400) as i64;
    // 1970-01-01 是周四，与 WEEKDAYS 的起点对应。
    let weekday = WEEKDAYS[(days.rem_euclid(7)) as usize];
    let (year, month, day) = civil_from_days(days);
    format!("{weekday} {} {day:02} {year}", MONTHS[(month - 1) as usize])
}

/// 由「1970-01-01 起的天数」换算公历年月日（Howard Hinnant 的算法）。
fn civil_from_days(days: i64) -> (i64, u32, u32) {
    let z = days + 719_468;
    let era = if z >= 0 { z } else { z - 146_096 } / 146_097;
    let doe = z - era * 146_097;
    let yoe = (doe - doe / 1_460 + doe / 36_524 - doe / 146_096) / 365;
    let y = yoe + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = doy - (153 * mp + 2) / 5 + 1;
    let m = if mp < 10 { mp + 3 } else { mp - 9 };
    (if m <= 2 { y + 1 } else { y }, m as u32, d as u32)
}
/// 官方 11 个工具定义。
const OFFICIAL_TOOLS_JSON: &str = include_str!("../../assets/opencode/tools.json");

fn official_tools() -> Result<Vec<Value>, String> {
    let parsed: Value = serde_json::from_str(OFFICIAL_TOOLS_JSON)
        .map_err(|error| format!("内置 opencode 工具表解析失败: {error}"))?;
    match parsed {
        Value::Array(tools) => Ok(tools),
        _ => Err("内置 opencode 工具表不是数组".to_string()),
    }
}

fn tool_name(tool: &Value) -> Option<String> {
    tool.get("function")
        .and_then(|function| function.get("name"))
        .or_else(|| tool.get("name"))
        .and_then(|name| name.as_str())
        .map(str::to_string)
}

/// 该模型是否接受 `response_format`。
///
/// 目前只有免费档的 `big-pickle` 实测拒绝（400
/// `Structured response_format is not enabled for model 'big-pickle'`）。
/// 其余模型原样透传，避免误伤真正支持结构化输出的模型。
fn opencode_model_supports_response_format(model: &str) -> bool {
    !model.trim().eq_ignore_ascii_case("big-pickle")
}

/// 把客户端请求体改写成官方形状。非 JSON 对象、或没有 `messages` 时返回原样。
pub(crate) fn shape_request_body(raw: &[u8]) -> Result<Vec<u8>, String> {
    let parsed: Value = serde_json::from_slice(raw)
        .map_err(|error| format!("opencode 请求体不是合法 JSON，未改写: {error}"))?;
    let Value::Object(mut object) = parsed else {
        return Err("opencode 请求体顶层不是对象，未改写".to_string());
    };

    let model_id = object
        .get("model")
        .and_then(Value::as_str)
        .unwrap_or_default()
        .to_string();
    // 有些模型不接受结构化输出，上游对带 `response_format` 的请求直接回
    // 400 `Structured response_format is not enabled for model '<id>'`。
    // 保留字段会让「生成会话标题」这类请求每次白跑 3 个候选再 503
    // （2026-10-28 实测：同一个请求 opencode2api 200、我们 400），所以在
    // 改写阶段按模型剔掉——客户端最多退化成自己解析纯文本。
    if !opencode_model_supports_response_format(model_id.as_str())
        && object.remove("response_format").is_some()
    {
        tracing::info!(
            event_name = "opencode_response_format_dropped",
            model = %model_id,
            "upstream 该模型不支持结构化输出，已剔除 response_format"
        );
    }
    let client_messages = match object.remove("messages") {
        Some(Value::Array(messages)) => messages,
        Some(_) => return Err("opencode 请求体的 messages 不是数组，未改写".to_string()),
        None => Vec::new(),
    };

    let mut messages = Vec::with_capacity(client_messages.len() + 1);
    let official_prompt = render_official_system_prompt(model_id.as_str());

    // 客户端的 system 消息合并成一条追加在官方提示词之后；其余消息原样保留。
    let mut client_system = Vec::new();
    let mut conversation = Vec::new();
    for message in client_messages {
        let role = message
            .get("role")
            .and_then(|role| role.as_str())
            .unwrap_or_default();
        if role.eq_ignore_ascii_case("system") {
            if let Some(text) = message.get("content").and_then(|content| content.as_str()) {
                let text = text.trim();
                if !text.is_empty() {
                    client_system.push(text.to_string());
                }
            }
            continue;
        }
        conversation.push(message);
    }
    // 官方客户端只有一条 system 消息：官方提示词在前，客户端的 system 内容用空行
    // 拼在后面。拆成两条会被上游判成非官方形状。
    let prompt = if client_system.is_empty() {
        official_prompt
    } else {
        format!("{official_prompt}\n\n{}", client_system.join("\n\n"))
    };
    messages.push(json!({ "role": "system", "content": prompt }));
    messages.extend(align_tool_messages(conversation));

    // 官方工具在前；客户端自带的按名字去重后追加，重名一律用官方版本。
    let mut tools = official_tools()?;
    let mut names: HashSet<String> = tools.iter().filter_map(tool_name).collect();
    let mut client_tool_count = 0usize;
    match object.remove("tools") {
        Some(Value::Array(client_tools)) => {
            client_tool_count = client_tools.len();
            for tool in client_tools {
                if let Some(name) = tool_name(&tool) {
                    if names.insert(name) {
                        tools.push(tool);
                    }
                }
            }
        }
        Some(_) => {}
        None => {}
    }

    // 2026-10-29：客户端**一个工具都没带**时，补 `tool_choice: "none"`。
    //
    // 注入的 11 个官方工具是为了过上游门禁（缺 bash/glob/grep/read 直接 403），
    // 不是给调用方用的。调用方没声明工具，说明它没有执行能力：模型真去调
    // `read` / `glob` 只会落空，客户端那侧表现为「一直在读、一直没结果」。
    // 把 `tool_choice` 钉成 none，模型只能正常作答。
    //
    // 客户端自己带了工具（opencode CLI、DSH 这类真跑 agent 的）时**绝不干预**；
    // 客户端显式传了 `tool_choice` 也尊重它。
    //
    // 回退开关：`AETHER_OPENCODE_TOOL_CHOICE_NONE_WITHOUT_CLIENT_TOOLS=0`
    // （写进 /etc/aether/aether-gateway.env 后重启即生效，不需要换二进制）。
    let mut injected_tool_choice_none = false;
    if client_tool_count == 0
        && tool_choice_none_without_client_tools_enabled()
        && !object.contains_key("tool_choice")
    {
        object.insert("tool_choice".to_string(), json!("none"));
        injected_tool_choice_none = true;
    }

    object.insert("messages".to_string(), Value::Array(messages));
    object.insert("tools".to_string(), Value::Array(tools));
    // 与官方客户端（以及 opencode2api）一致：只强制流式，不改客户端的
    // `max_tokens` / `tool_choice`。免费额度按 token 计，凭空把 `max_tokens`
    // 抬到 32000 会让一次请求直接吃掉整天额度，上游立刻回 429。
    object.insert("stream".to_string(), json!(true));
    object.insert(
        "stream_options".to_string(),
        json!({ "include_usage": true }),
    );

    if injected_tool_choice_none {
        tracing::info!(
            event_name = "opencode_tool_choice_none_injected",
            model = %model_id,
            "客户端未声明工具，已固定 tool_choice=none 以阻止幽灵工具调用"
        );
    }

    serde_json::to_vec(&Value::Object(object))
        .map_err(|error| format!("opencode 请求体序列化失败: {error}"))
}

/// 客户端没有声明工具时，是否把 `tool_choice` 固定为 `none`。
///
/// 判定逻辑只有一份，放在 transport crate 里（planner 层的
/// `apply_opencode_request_body_semantics` 用的是同一个开关），这里直接复用，
/// 避免两处行为不一致。
fn tool_choice_none_without_client_tools_enabled() -> bool {
    aether_provider_transport::opencode_tool_choice_none_without_client_tools_enabled()
}

/// 对齐官方客户端对 `tool_calls` / `tool` 消息的硬性要求。
///
/// 上游对这两类消息的配对极其敏感，缺一条就整轮失败：
/// * `assistant.tool_calls[*].function.arguments` 必须是「JSON 对象字符串」，
///   空串、`null`、数组或非法 JSON 都会被拒；
/// * 每个 `assistant.tool_calls[*].id` 后面必须有一条 `role = "tool"` 且
///   `tool_call_id` 相同的消息。客户端中途取消或历史被裁剪时常会丢，官方客户端
///   会补一条占位结果；
/// * 同一条 `tool_call_id` 只能有一条 `tool` 消息，重复的会被上游判为非法。
fn align_tool_messages(conversation: Vec<Value>) -> Vec<Value> {
    let mut conversation = conversation;

    for message in conversation.iter_mut() {
        let Some(calls) = message.get_mut("tool_calls").and_then(Value::as_array_mut) else {
            continue;
        };
        for call in calls.iter_mut() {
            let Some(function) = call.get_mut("function").and_then(Value::as_object_mut) else {
                continue;
            };
            let normalized = match function.get("arguments") {
                Some(Value::String(raw)) => serde_json::from_str::<Value>(raw)
                    .ok()
                    .filter(Value::is_object)
                    .map(|value| value.to_string()),
                Some(value @ Value::Object(_)) => Some(value.to_string()),
                _ => None,
            };
            function.insert(
                "arguments".to_string(),
                Value::String(normalized.unwrap_or_else(|| "{}".to_string())),
            );
        }
    }

    // 第一遍：记下已有的 tool 响应 id（重复的直接丢掉，只留第一条）。
    let mut answered: HashSet<String> = HashSet::new();
    for message in conversation.iter() {
        if message.get("role").and_then(Value::as_str) != Some("tool") {
            continue;
        }
        if let Some(id) = message.get("tool_call_id").and_then(Value::as_str) {
            answered.insert(id.to_string());
        }
    }

    let mut rebuilt: Vec<Value> = Vec::with_capacity(conversation.len());
    let mut seen_responses: HashSet<String> = HashSet::new();
    for message in conversation.into_iter() {
        if message.get("role").and_then(Value::as_str) == Some("tool") {
            let duplicate = message
                .get("tool_call_id")
                .and_then(Value::as_str)
                .map(|id| !seen_responses.insert(id.to_string()))
                .unwrap_or(false);
            if duplicate {
                continue;
            }
        }
        let pending: Vec<String> = message
            .get("tool_calls")
            .and_then(Value::as_array)
            .map(|calls| {
                calls
                    .iter()
                    .filter_map(|call| call.get("id").and_then(Value::as_str))
                    .filter(|id| !answered.contains(*id))
                    .map(str::to_string)
                    .collect()
            })
            .unwrap_or_default();
        rebuilt.push(message);
        for id in pending {
            seen_responses.insert(id.clone());
            rebuilt.push(json!({
                "role": "tool",
                "tool_call_id": id,
                "content": "Tool call result not available",
            }));
        }
    }
    rebuilt
}

/// 请求体是否值得改写：空体（如 GET /models）直接跳过。
pub(crate) fn should_shape(body: &[u8]) -> bool {
    !body.is_empty()
}

/// 便于诊断/测试：改写后的系统提示词长度。
pub(crate) fn official_system_prompt_len() -> usize {
    OFFICIAL_SYSTEM_PROMPT_TEMPLATE.chars().count()
}

/// 便于诊断/测试：官方工具名列表。
pub(crate) fn official_tool_names() -> Vec<String> {
    official_tools()
        .unwrap_or_default()
        .iter()
        .filter_map(tool_name)
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn client_body() -> Vec<u8> {
        serde_json::to_vec(&json!({
            "model": "big-pickle",
            "temperature": 0.3,
            "messages": [
                { "role": "system", "content": "你是中文助手。" },
                { "role": "user", "content": "你好" },
                { "role": "assistant", "content": "你好，请问需要什么？" },
                { "role": "user", "content": "讲个笑话" }
            ],
            "tools": [
                { "type": "function", "function": { "name": "my_tool", "description": "自定义", "parameters": { "type": "object", "properties": {} } } },
                { "type": "function", "function": { "name": "bash", "description": "被官方版本取代", "parameters": { "type": "object", "properties": {} } } }
            ]
        }))
        .unwrap()
    }

    #[test]
    fn official_assets_are_complete() {
        // 模板化后比写死版短：model 与 date 换成了占位符。
        assert_eq!(official_system_prompt_len(), 9530);
        assert_eq!(
            official_tool_names(),
            vec![
                "bash",
                "edit",
                "glob",
                "grep",
                "read",
                "skill",
                "task",
                "todowrite",
                "webfetch",
                "websearch",
                "write"
            ]
        );
    }

    #[test]
    fn shaping_prepends_official_prompt_and_keeps_conversation() {
        let shaped = shape_request_body(&client_body()).unwrap();
        let value: Value = serde_json::from_slice(&shaped).unwrap();
        let messages = value["messages"].as_array().unwrap();

        // 官方提示词在最前，客户端的 system 用空行拼在同一条消息里，然后才是对话。
        assert_eq!(messages[0]["role"], "system");
        let prompt = messages[0]["content"].as_str().unwrap();
        assert!(prompt.starts_with(OFFICIAL_SYSTEM_PROMPT_MARKER));
        assert!(prompt.ends_with("你是中文助手。"));
        // 占位符已按本次请求的 model 与当天日期渲染。
        assert!(!prompt.contains("{{MODEL}}") && !prompt.contains("{{DATE}}"));
        assert!(prompt.contains("The exact model ID is opencode/big-pickle"));
        assert!(prompt.contains("Today's date: "));
        assert_eq!(messages.len(), 4);
        assert_eq!(messages[1]["content"], "你好");
        assert_eq!(messages[3]["content"], "讲个笑话");

        // 官方工具全在，自定义工具被追加，同名工具用官方版本。
        let names: Vec<&str> = value["tools"]
            .as_array()
            .unwrap()
            .iter()
            .map(|tool| tool["function"]["name"].as_str().unwrap())
            .collect();
        assert_eq!(names.len(), 12);
        assert_eq!(names[0], "bash");
        assert_eq!(names[11], "my_tool");
        let bash = &value["tools"][0]["function"]["description"];
        assert_ne!(bash, "被官方版本取代");

        // 强制字段与保留字段。
        assert_eq!(value["stream"], true);
        assert_eq!(value["stream_options"]["include_usage"], true);
        // 客户端没给 tool_choice / max_tokens，就保持没有：不替客户端凭空放大额度占用。
        assert!(value.get("tool_choice").is_none());
        assert_eq!(value["model"], "big-pickle");
        assert_eq!(value["temperature"], 0.3);
        assert!(value.get("max_tokens").is_none());
    }

    #[test]
    fn shaping_rejects_non_object_body() {
        assert!(shape_request_body(b"[]").is_err());
        assert!(shape_request_body(b"not json").is_err());
    }

    #[test]
    fn shaping_without_messages_still_emits_official_base() {
        let shaped = shape_request_body(br#"{"model":"big-pickle"}"#).unwrap();
        let value: Value = serde_json::from_slice(&shaped).unwrap();
        assert_eq!(value["messages"].as_array().unwrap().len(), 1);
        assert_eq!(value["tools"].as_array().unwrap().len(), 11);
    }

    /// 客户端没带工具 → 补 `tool_choice: "none"`，挡住幽灵工具调用。
    #[test]
    fn shaping_pins_tool_choice_none_when_client_sends_no_tools() {
        let shaped = shape_request_body(
            br#"{"model":"big-pickle","messages":[{"role":"user","content":"hi"}]}"#,
        )
        .unwrap();
        let value: Value = serde_json::from_slice(&shaped).unwrap();
        assert_eq!(value["tool_choice"], "none");
        // 门禁需要的官方工具仍然全在，只是不允许模型去调。
        assert_eq!(value["tools"].as_array().unwrap().len(), 11);
    }

    /// 客户端带了工具（真 agent 客户端）→ 一律不干预 `tool_choice`。
    #[test]
    fn shaping_leaves_tool_choice_alone_when_client_sends_tools() {
        let shaped = shape_request_body(
            br#"{"model":"big-pickle","messages":[{"role":"user","content":"hi"}],
                 "tools":[{"type":"function","function":{"name":"read",
                   "parameters":{"type":"object","properties":{"file_path":{"type":"string"}}}}}]}"#,
        )
        .unwrap();
        let value: Value = serde_json::from_slice(&shaped).unwrap();
        assert!(value.get("tool_choice").is_none());
    }

    /// 客户端显式给了 `tool_choice` → 尊重客户端，不覆盖。
    #[test]
    fn shaping_respects_explicit_client_tool_choice() {
        let shaped = shape_request_body(
            br#"{"model":"big-pickle","tool_choice":"required",
                 "messages":[{"role":"user","content":"hi"}]}"#,
        )
        .unwrap();
        let value: Value = serde_json::from_slice(&shaped).unwrap();
        assert_eq!(value["tool_choice"], "required");
    }
}
