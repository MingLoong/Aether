//! 把发往 opencode 的请求体改写成「官方 CLI 的形状」。
//!
//! 背景见 `docs/opencode-tls13-egress.md` §8：实测结论是 ——
//! TLS 指纹、9 个请求头、官方系统提示词、11 个官方工具，**四者缺一不可**；
//! 而用户消息、多轮历史、追加的 system 消息、追加的自定义工具都可以叠加进去。
//!
//! 所以这里只做「补底座 + 保留用户内容」：
//! * 官方系统提示词放在最前面；客户端的 system 消息合并成一条紧随其后；
//! * 官方 11 个工具在前，客户端自带的工具按名字去重后追加；
//! * `tool_choice` / `stream` / `stream_options` 强制成官方取值；
//! * 其余字段（`model`、`temperature` 等）原样保留，`max_tokens` 缺省补官方值。

use std::collections::HashSet;

use serde_json::{json, Map, Value};

/// 官方 1.19.x 系统提示词（9539 字）。
const OFFICIAL_SYSTEM_PROMPT: &str = include_str!("../../assets/opencode/system_prompt.txt");
/// 官方 11 个工具定义。
const OFFICIAL_TOOLS_JSON: &str = include_str!("../../assets/opencode/tools.json");

/// 官方默认输出上限。
const OFFICIAL_MAX_TOKENS: u32 = 32000;

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

/// 把客户端请求体改写成官方形状。非 JSON 对象、或没有 `messages` 时返回原样。
pub(crate) fn shape_request_body(raw: &[u8]) -> Result<Vec<u8>, String> {
    let parsed: Value = serde_json::from_slice(raw)
        .map_err(|error| format!("opencode 请求体不是合法 JSON，未改写: {error}"))?;
    let Value::Object(mut object) = parsed else {
        return Err("opencode 请求体顶层不是对象，未改写".to_string());
    };

    let client_messages = match object.remove("messages") {
        Some(Value::Array(messages)) => messages,
        Some(_) => return Err("opencode 请求体的 messages 不是数组，未改写".to_string()),
        None => Vec::new(),
    };

    let mut messages = Vec::with_capacity(client_messages.len() + 2);
    messages.push(json!({ "role": "system", "content": OFFICIAL_SYSTEM_PROMPT }));

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
    if !client_system.is_empty() {
        messages.push(json!({ "role": "system", "content": client_system.join("\n\n") }));
    }
    messages.extend(conversation);

    // 官方工具在前；客户端自带的按名字去重后追加，重名一律用官方版本。
    let mut tools = official_tools()?;
    let mut names: HashSet<String> = tools.iter().filter_map(tool_name).collect();
    match object.remove("tools") {
        Some(Value::Array(client_tools)) => {
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

    object.insert("messages".to_string(), Value::Array(messages));
    object.insert("tools".to_string(), Value::Array(tools));
    object.insert("tool_choice".to_string(), json!("auto"));
    object.insert("stream".to_string(), json!(true));
    object.insert(
        "stream_options".to_string(),
        json!({ "include_usage": true }),
    );
    if let Some(max_tokens) = object.get("max_tokens") {
        if !max_tokens.is_number() {
            object.insert("max_tokens".to_string(), json!(OFFICIAL_MAX_TOKENS));
        }
    } else {
        object.insert("max_tokens".to_string(), json!(OFFICIAL_MAX_TOKENS));
    }

    serde_json::to_vec(&Value::Object(object))
        .map_err(|error| format!("opencode 请求体序列化失败: {error}"))
}

/// 请求体是否值得改写：空体（如 GET /models）直接跳过。
pub(crate) fn should_shape(body: &[u8]) -> bool {
    !body.is_empty()
}

/// 便于诊断/测试：改写后的系统提示词长度。
pub(crate) fn official_system_prompt_len() -> usize {
    OFFICIAL_SYSTEM_PROMPT.chars().count()
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
        assert_eq!(official_system_prompt_len(), 9539);
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

        // 官方提示词在最前，随后是合并后的客户端 system，再是对话本身。
        assert_eq!(messages[0]["role"], "system");
        assert_eq!(
            messages[0]["content"].as_str().unwrap(),
            OFFICIAL_SYSTEM_PROMPT
        );
        assert_eq!(messages[1]["content"], "你是中文助手。");
        assert_eq!(messages.len(), 5);
        assert_eq!(messages[2]["content"], "你好");
        assert_eq!(messages[4]["content"], "讲个笑话");

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
        assert_eq!(value["tool_choice"], "auto");
        assert_eq!(value["model"], "big-pickle");
        assert_eq!(value["temperature"], 0.3);
        assert_eq!(value["max_tokens"], OFFICIAL_MAX_TOKENS);
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
}
