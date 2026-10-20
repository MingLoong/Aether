//! WorkBuddy（腾讯 CodeBuddy）**流式** DSML 工具调用还原。
//!
//! 非流式那一套见 `dsml.rs`：那里整段正文一次到手，可以一次性判断。流式不同——
//! 标记会被切在任意字节位置（SSE 分片边界、正文 delta 边界都可能落在标记中间），
//! 所以这里是一个**带回退缓冲的状态机**：
//!
//! - 只在「可能是标记开头」时才把正文扣住（回退缓冲），普通文本即时放行，
//!   不牺牲首字节延迟；
//! - 完整块一闭合就解析成 `tool_calls` 并记忆，等上游的 `finish_reason: "stop"`
//!   帧到达时把调用挂上去、并把 `finish_reason` 改成 `tool_calls`；上游没给收尾帧
//!   时由 `finish()` 自己补一帧；
//! - **绝不吞字节**：未闭合的块、超过上限的块、结尾残留的半截标记，都会在
//!   `finish()` 里原样补发。
//!
//! 事实来源：开源面板 `linguo2625469/workbuddy2api-panel` 的 `dsml.go` +
//! `sse.go`（它同样把修复后的调用以**额外的 delta 帧**发出，并把 `finish_reason`
//! 从 `stop` 挪到 `tool_calls` 之后）。

use serde_json::{json, Map, Value};

use super::dsml::{
    declared_workbuddy_tool_names, parse_workbuddy_dsml_block, WorkbuddyRepairedToolCall,
    WORKBUDDY_DSML_MAX_BLOCK_BYTES,
};

/// 判定「这条流要不要走 DSML 还原」，并建好状态机（显式参数版）。
///
/// 条件（全部满足才返回 `Some`，否则返回 `None` 让流原样透传）：
/// 1. 出站头里带内部标记 `x-aether-workbuddy-runtime: 1`；
/// 2. 客户端与上游同为 `openai:chat`——**跨格式时返回 `None`**，那种情况由格式层的
///    流式转换器负责，两边同时改写会互相踩；
/// 3. 声明清单从 `original_request_body` 里取。
///
/// gateway 通常用 `maybe_build_workbuddy_dsml_stream_repair(report_context)`（见本模块
/// `mod.rs`），这个显式版本供单测与其它调用方直接用。
pub fn maybe_build_workbuddy_dsml_stream_repair_for_parts(
    provider_request_headers: Option<&Value>,
    client_api_format: Option<&str>,
    provider_api_format: Option<&str>,
    original_request_body: Option<&Value>,
) -> Option<WorkbuddyDsmlStreamRepair> {
    if !has_workbuddy_internal_marker(provider_request_headers) {
        return None;
    }
    let same_format = |value: Option<&str>| {
        value
            .unwrap_or_default()
            .trim()
            .eq_ignore_ascii_case("openai:chat")
    };
    if !same_format(client_api_format) || !same_format(provider_api_format) {
        return None;
    }
    Some(WorkbuddyDsmlStreamRepair::new(
        original_request_body
            .map(declared_workbuddy_tool_names)
            .unwrap_or_default(),
    ))
}

/// 出站头里是否带 workbuddy 内部标记（大小写不敏感，值必须是 "1"）。
pub fn has_workbuddy_internal_marker(headers: Option<&Value>) -> bool {
    headers.and_then(Value::as_object).is_some_and(|headers| {
        headers.iter().any(|(name, value)| {
            name.eq_ignore_ascii_case(super::WORKBUDDY_INTERNAL_HEADER)
                && value.as_str().map(str::trim) == Some("1")
        })
    })
}

/// 开标记（`‖` 是两个 U+FF5C 全角竖线）。
pub fn workbuddy_dsml_open_marker() -> String {
    format!("<{}DSML{} calls>", "\u{FF5C}\u{FF5C}", "\u{FF5C}\u{FF5C}")
}

fn close_marker() -> String {
    format!("</{}DSML{} calls>", "\u{FF5C}\u{FF5C}", "\u{FF5C}\u{FF5C}")
}

/// 流式还原状态机。
#[derive(Debug, Clone, Default)]
pub struct WorkbuddyDsmlStreamRepair {
    declared_tools: Vec<String>,
    /// 未处理的字节尾巴（可能是半个 SSE 行 / 帧）。
    pending_bytes: String,
    /// 正文回退缓冲：可能是标记前缀，或一个尚未闭合的块。
    holdback: String,
    /// 已还原但还没发出去的调用。
    repaired_calls: Vec<WorkbuddyRepairedToolCall>,
    /// 最近一帧的骨架（合成帧要用 id / model / created）。
    frame_skeleton: Option<Value>,
    /// 是否已经发出过带 `finish_reason` 的收尾帧。
    finish_emitted: bool,
    /// 是否见过上游的 `[DONE]`（没见过就在 `finish()` 里补一个，面板 `Stream` 同款保证）。
    saw_done: bool,
    /// 已经发过首片的 tool_call index（面板 `stripToolCallNames` 的 `seen`）。
    seen_tool_call_indexes: std::collections::BTreeSet<i64>,
}

impl WorkbuddyDsmlStreamRepair {
    pub fn new(declared_tools: Vec<String>) -> Self {
        Self {
            declared_tools,
            ..Self::default()
        }
    }

    /// 喂一段上游字节，返回**应当转发给客户端**的字节。
    pub fn push_bytes(&mut self, chunk: &[u8]) -> Vec<u8> {
        if chunk.is_empty() {
            return Vec::new();
        }
        self.pending_bytes.push_str(&String::from_utf8_lossy(chunk));
        let mut output = String::new();
        // SSE 以空行分隔事件；逐行处理，最后一行若没有换行则留在 pending 里等下一片。
        while let Some(newline_at) = self.pending_bytes.find('\n') {
            let line: String = self.pending_bytes.drain(..=newline_at).collect();
            output.push_str(&self.process_line(&line));
        }
        output.into_bytes()
    }

    /// 流结束：补发残留正文与（若上游没给收尾帧）补一帧带 `tool_calls` 的收尾。
    pub fn finish(&mut self) -> Vec<u8> {
        let mut output = String::new();

        // 1. 残留字节（上游最后一行没有换行）先原样放出去。
        if !self.pending_bytes.is_empty() {
            let pending = std::mem::take(&mut self.pending_bytes);
            output.push_str(&pending);
        }

        // 2. 回退缓冲里的正文原样补发（绝不吞字节）。
        let held = std::mem::take(&mut self.holdback);
        if !held.is_empty() {
            output.push_str(&self.build_content_frame(&held));
        }

        // 3. 上游没给收尾帧时，自己补一帧把调用和 finish_reason 发出。
        if !self.repaired_calls.is_empty() && !self.finish_emitted {
            output.push_str(&self.build_tool_calls_frame(None));
            self.finish_emitted = true;
        }

        // 4. **保证至少一个 `[DONE]`**（面板 `Stream` 同款）：上游被截断/没发收尾时，
        //    等 `[DONE]` 的客户端会一直挂住。这里没见过就补一个。
        if !self.saw_done {
            output.push_str("data: [DONE]\n\n");
            self.saw_done = true;
        }

        output.into_bytes()
    }

    /// 处理一行（含结尾换行；SSE 行）。
    fn process_line(&mut self, line: &str) -> String {
        let trimmed = line.trim_end_matches(['\r', '\n']);
        let Some(payload) = trimmed.strip_prefix("data:") else {
            // 注释、`event:`、空行等一律原样转发。
            return line.to_string();
        };
        let payload = payload.trim();
        if payload.is_empty() {
            return line.to_string();
        }
        if payload == "[DONE]" {
            self.saw_done = true;
            return line.to_string();
        }
        let Ok(mut frame) = serde_json::from_str::<Value>(payload) else {
            return line.to_string();
        };
        if !frame.is_object() {
            return line.to_string();
        }
        self.frame_skeleton = Some(skeleton_of(&frame));

        // 原生 tool_calls 分片：收敛 name 语义为「每个 index 只出现一次」
        // （面板 `stripToolCallNames`：首片保留 `function.name`，后续分片删掉该键）。
        // 这是 OpenAI 官方流的真实形态，也是**累加型**（`name += … || ""`，重复会拼成
        // `BashBash`）与**覆盖型**（`name ?? state.name`，空串会清空）客户端的共同祖先行为。
        let names_stripped =
            strip_repeated_tool_call_names(&mut frame, &mut self.seen_tool_call_indexes);

        // usage 规范化（缓存命中别名对齐 + `total_tokens` 补齐）：末帧/用量帧都可能有，
        // 命中就在本帧生效（面板 `usage.go` 与 `sse.go::ensureUsageTotal` 同口径）。
        let usage_changed = match frame.get_mut("usage") {
            Some(usage) => {
                let aliases = super::usage::normalize_workbuddy_usage_cache_aliases(usage);
                let total = super::usage::ensure_workbuddy_usage_total(usage);
                aliases || total
            }
            None => false,
        };

        let finish_reason = first_choice_finish_reason(&frame);
        let delta_content = first_delta_content(&frame);

        // 正文增量：过一遍回退缓冲，只有内容真被改动时才重建帧。
        if let Some(content) = delta_content {
            let forwarded = self.feed_content(&content);
            if forwarded != content {
                set_first_delta_content(&mut frame, &forwarded);
                if finish_reason.as_deref() == Some("stop") && !self.repaired_calls.is_empty() {
                    // 同一帧既收尾又完成还原：直接挂上调用（省一帧）。
                    attach_tool_calls(&mut frame, &self.repaired_calls);
                    self.repaired_calls.clear();
                    self.finish_emitted = true;
                }
                return format!("data: {frame}\n");
            }
        }

        // 收尾帧：把已还原的调用挂上去，并把 finish_reason 改成 tool_calls。
        if finish_reason.as_deref() == Some("stop") && !self.repaired_calls.is_empty() {
            attach_tool_calls(&mut frame, &self.repaired_calls);
            self.repaired_calls.clear();
            self.finish_emitted = true;
            return format!("data: {frame}\n");
        }
        if finish_reason.is_some() {
            self.finish_emitted = true;
        }
        if usage_changed || names_stripped {
            // usage 被规范化 / tool_call 的重复 name 被收敛 → 重建这一帧
            // （其余帧保持上游字节形态，不做无谓重建）。
            return format!("data: {frame}\n");
        }
        // 其余帧原样转发（保持上游的字节形态，不做无谓重建）。
        line.to_string()
    }

    /// 正文回退缓冲：返回**当前可以安全转发**的文本。
    ///
    /// 规则：
    /// - 没有开标记、且结尾不可能是开标记的前缀 → 全部放行；
    /// - 结尾是开标记的前缀 → 扣住那段前缀等下一片（避免把标记拆散后漏判）；
    /// - 出现开标记但块未闭合 → 从开标记起全部扣住；
    /// - 块闭合 → 解析成调用，继续扫描后面的内容；
    /// - 扣住的量超过上限 → 原样放行（放弃这一块，绝不吞字节）。
    fn feed_content(&mut self, content: &str) -> String {
        if content.is_empty() {
            return String::new();
        }
        self.holdback.push_str(content);
        let open = workbuddy_dsml_open_marker();
        let close = close_marker();
        let mut output = String::new();

        loop {
            let Some(open_at) = self.holdback.find(&open) else {
                // 没有完整开标记：只扣住「可能是开标记前缀」的尾巴。
                let tail = partial_marker_suffix(&self.holdback, &open);
                let safe_len = self.holdback.len() - tail;
                output.push_str(&self.holdback[..safe_len]);
                self.holdback.drain(..safe_len);
                break;
            };
            output.push_str(&self.holdback[..open_at]);
            let after_open = open_at + open.len();
            let Some(close_offset) = self.holdback[after_open..].find(&close) else {
                // 块还没闭合：扣住（含开标记）。超限则放弃并原样放行。
                if self.holdback.len() - open_at > WORKBUDDY_DSML_MAX_BLOCK_BYTES {
                    let rest: String = self.holdback.drain(open_at..).collect();
                    output.push_str(&rest);
                } else {
                    self.holdback.drain(..open_at);
                }
                break;
            };
            let block_end = after_open + close_offset + close.len();
            let block: String = self.holdback[open_at..block_end].to_string();
            let inner = &block[open.len()..block.len() - close.len()];
            match parse_workbuddy_dsml_block(inner, &self.declared_tools) {
                Some(calls) if !calls.is_empty() => {
                    self.repaired_calls.extend(calls);
                    // 整块消费掉，继续看后面还有没有内容。
                    self.holdback.drain(..block_end);
                }
                _ => {
                    // 块本身不合法：原样放行（含开闭标记），不做部分猜测。
                    output.push_str(&block);
                    self.holdback.drain(..block_end);
                }
            }
        }
        output
    }

    /// 用最近一帧的骨架合成一个只带正文增量的帧。
    fn build_content_frame(&self, content: &str) -> String {
        let mut frame = self
            .frame_skeleton
            .clone()
            .unwrap_or_else(|| json!({"object": "chat.completion.chunk"}));
        frame["choices"] = json!([{
            "index": 0,
            "delta": {"content": content},
            "finish_reason": Value::Null,
        }]);
        format!("data: {frame}\n\n")
    }

    /// 合成收尾帧：delta 带 tool_calls，`finish_reason = "tool_calls"`。
    fn build_tool_calls_frame(&self, finish_reason: Option<&str>) -> String {
        let mut frame = self
            .frame_skeleton
            .clone()
            .unwrap_or_else(|| json!({"object": "chat.completion.chunk"}));
        let mut delta = Map::new();
        delta.insert(
            "tool_calls".to_string(),
            tool_calls_delta(&self.repaired_calls),
        );
        frame["choices"] = json!([{
            "index": 0,
            "delta": Value::Object(delta),
            "finish_reason": finish_reason.unwrap_or("tool_calls"),
        }]);
        format!("data: {frame}\n\n")
    }
}

fn skeleton_of(frame: &Value) -> Value {
    let mut skeleton = Map::new();
    for key in ["id", "object", "created", "model"] {
        if let Some(value) = frame.get(key) {
            skeleton.insert(key.to_string(), value.clone());
        }
    }
    Value::Object(skeleton)
}

fn first_choice_mut(frame: &mut Value) -> Option<&mut Map<String, Value>> {
    frame
        .get_mut("choices")?
        .as_array_mut()?
        .first_mut()?
        .as_object_mut()
}

fn first_choice_finish_reason(frame: &Value) -> Option<String> {
    frame
        .get("choices")?
        .as_array()?
        .first()?
        .get("finish_reason")?
        .as_str()
        .map(|value| value.trim().to_ascii_lowercase())
}

fn first_delta_content(frame: &Value) -> Option<String> {
    frame
        .get("choices")?
        .as_array()?
        .first()?
        .get("delta")?
        .get("content")?
        .as_str()
        .map(ToOwned::to_owned)
}

fn set_first_delta_content(frame: &mut Value, content: &str) {
    if let Some(choice) = first_choice_mut(frame) {
        if let Some(delta) = choice.get_mut("delta").and_then(Value::as_object_mut) {
            delta.insert("content".to_string(), Value::String(content.to_string()));
        }
    }
}

/// 把调用按 OpenAI 流式形态挂到 `choices[0].delta.tool_calls`，
/// 并把 `finish_reason` 改成 `tool_calls`。
fn attach_tool_calls(frame: &mut Value, calls: &[WorkbuddyRepairedToolCall]) {
    if let Some(choice) = first_choice_mut(frame) {
        if let Some(delta) = choice.get_mut("delta").and_then(Value::as_object_mut) {
            delta.insert("tool_calls".to_string(), tool_calls_delta(calls));
        }
        choice.insert(
            "finish_reason".to_string(),
            Value::String("tool_calls".to_string()),
        );
    }
}

/// 收敛流式 `tool_calls` 的 `name` 语义：**每个 index 只出现一次**（面板 `stripToolCallNames`）。
///
/// 首片保留 `function.name`，同一 index 的后续分片一律**删掉该键**（无论上游给的是空串还是
/// 重复非空串）。为什么必须做：OpenAI 官方流的真实形态就是「首帧带 name、后续只带
/// arguments 片段」，而两类消费模型只有在键**缺失**时才同时正确——
/// - 累加型（`name += tc.function?.name || ""`）：缺失 → 追加空串，名字不会被拼成
///   `BashBash…`（面板 issue #82）；
/// - 覆盖型（`name ?? state.name` / `if (name) state.name = name`）：缺失 → 保留首帧名字；
///   若发空串，`??` 会误判成重设并把工具名清空。
///
/// `seen` 记录每个 index 是否已发过首片（**与 name 是否非空无关**，面板逐字口径）；
/// 删除是幂等的。只动 `function.name`，`id` / `type` / `arguments` 原样透传。
///
/// > 真机记录（2026-10-15）：CodeBuddy 的 `deepseek-v4-flash` 在**原生** tool_calls 场景下
/// > 首片就带 `function.name: ""`（空串），最终客户端拿到的 name 也是空——**这不是本函数的
/// > 问题**（上游就没给名字；面板同样如此）。真机那次没有出现「名字在后续分片才到」的形态，
/// > 所以这里**保持与面板逐字一致**，不为未证实的场景引入分叉。若将来真的观测到名字晚到，
/// > 应作为**独立议题**（可考虑「请求里只有一个 tool 时用它的名字兜底」）而不是改这里。
fn strip_repeated_tool_call_names(
    frame: &mut Value,
    seen: &mut std::collections::BTreeSet<i64>,
) -> bool {
    let Some(choices) = frame.get_mut("choices").and_then(Value::as_array_mut) else {
        return false;
    };
    let mut changed = false;
    for choice in choices.iter_mut() {
        let Some(tool_calls) = choice
            .get_mut("delta")
            .and_then(|delta| delta.get_mut("tool_calls"))
            .and_then(Value::as_array_mut)
        else {
            continue;
        };
        for tool_call in tool_calls.iter_mut() {
            let Some(tool_call) = tool_call.as_object_mut() else {
                continue;
            };
            let index = tool_call.get("index").and_then(Value::as_i64).unwrap_or(0);
            if seen.contains(&index) {
                // 已发过首片：删掉本分片的 name 键（存在即删，幂等）。
                if let Some(function) = tool_call.get_mut("function").and_then(Value::as_object_mut)
                {
                    if function.remove("name").is_some() {
                        changed = true;
                    }
                }
                continue;
            }
            // 首现：保留 name 键原样（空 name 也照发，与 OpenAI 对首帧无 name 的容忍一致）。
            seen.insert(index);
        }
    }
    changed
}

fn tool_calls_delta(calls: &[WorkbuddyRepairedToolCall]) -> Value {
    Value::Array(
        calls
            .iter()
            .enumerate()
            .map(|(index, call)| {
                json!({
                    "index": index,
                    "id": super::dsml::workbuddy_dsml_call_id(index),
                    "type": "function",
                    "function": {
                        "name": call.name,
                        "arguments": serde_json::to_string(&call.arguments)
                            .unwrap_or_else(|_| "{}".to_string()),
                    }
                })
            })
            .collect(),
    )
}

/// 返回 `text` 结尾那段「可能是 `marker` 前缀」的长度（不超过 marker 长度）。
fn partial_marker_suffix(text: &str, marker: &str) -> usize {
    let max = text.len().min(marker.len().saturating_sub(1));
    for len in (1..=max).rev() {
        let start = text.len() - len;
        if text.is_char_boundary(start) && marker.starts_with(&text[start..]) {
            return len;
        }
    }
    0
}

#[cfg(test)]
mod tests {
    use serde_json::json;

    use super::{workbuddy_dsml_open_marker, WorkbuddyDsmlStreamRepair};

    fn pipe() -> &'static str {
        "\u{FF5C}\u{FF5C}"
    }

    fn delta_frame(content: &str) -> String {
        format!(
            "data: {}\n\n",
            json!({
                "id": "chatcmpl-wb-stream",
                "object": "chat.completion.chunk",
                "created": 1,
                "model": "deepseek-v4-flash",
                "choices": [{"index": 0, "delta": {"content": content}, "finish_reason": null}]
            })
        )
    }

    fn finish_frame() -> String {
        format!(
            "data: {}\n\n",
            json!({
                "id": "chatcmpl-wb-stream",
                "object": "chat.completion.chunk",
                "created": 1,
                "model": "deepseek-v4-flash",
                "choices": [{"index": 0, "delta": {}, "finish_reason": "stop"}]
            })
        )
    }

    fn dsml_block(invoke_name: &str) -> String {
        let pipe = pipe();
        format!(
            "<{pipe}DSML{pipe} calls><{pipe}DSML{pipe} invoke name=\"{invoke_name}\">\
<{pipe}DSML{pipe} parameter name=\"cmd\" string=\"true\">ls -la</{pipe}DSML{pipe} parameter>\
</{pipe}DSML{pipe} invoke></{pipe}DSML{pipe} calls>"
        )
    }

    /// 把一段字节按给定大小切碎喂进去，返回全部输出与 finish 输出。
    fn feed_in_chunks(repair: &mut WorkbuddyDsmlStreamRepair, bytes: &str, size: usize) -> String {
        let mut output = String::new();
        let mut offset = 0;
        while offset < bytes.len() {
            let end = (offset + size).min(bytes.len());
            // 切点必须落在 char 边界上。
            let mut end = end;
            while end < bytes.len() && !bytes.is_char_boundary(end) {
                end += 1;
            }
            output.push_str(&String::from_utf8_lossy(
                &repair.push_bytes(&bytes.as_bytes()[offset..end]),
            ));
            offset = end;
        }
        output
    }

    #[test]
    fn repairs_a_block_split_across_many_chunks() {
        let mut events = delta_frame("我先看目录");
        events.push_str(&delta_frame(&dsml_block("exec_command")));
        events.push_str(&finish_frame());

        // 每个字节都可能被切在标记中间，逐个粒度都要能还原。
        for size in [1usize, 3, 7, 64, 4096] {
            let mut repair = WorkbuddyDsmlStreamRepair::new(vec!["exec_command".to_string()]);
            let mut output = feed_in_chunks(&mut repair, &events, size);
            output.push_str(&String::from_utf8_lossy(&repair.finish()));

            assert!(!output.contains("DSML"), "size={size} 时标记泄漏：{output}");
            assert!(output.contains("我先看目录"), "size={size} 丢了正文");
            assert!(
                output.contains("\"tool_calls\""),
                "size={size} 没有合成 tool_calls：{output}"
            );
            assert!(
                output.contains("tool_calls"),
                "size={size} finish_reason 未改写"
            );
            assert!(output.contains("exec_command"));
            // 收尾帧的 finish_reason 必须是 tool_calls，不能留 stop。
            assert!(!output.contains("\"finish_reason\":\"stop\""), "{output}");
        }
    }

    /// 上游没给收尾帧：`finish()` 必须自己补一帧，否则客户端拿不到 finish_reason。
    #[test]
    fn synthesizes_a_finish_frame_when_upstream_omits_it() {
        let mut events = delta_frame(&dsml_block("exec_command"));
        let mut repair = WorkbuddyDsmlStreamRepair::new(vec!["exec_command".to_string()]);
        let mut output = feed_in_chunks(&mut repair, &events, 5);
        output.push_str(&String::from_utf8_lossy(&repair.finish()));

        assert!(output.contains("\"tool_calls\""));
        assert!(
            output.contains("\"finish_reason\":\"tool_calls\""),
            "{output}"
        );

        events.clear();
        let _ = events;
    }

    /// 未闭合的块在流结束时必须**原样补发**（含开标签），绝不吞字节。
    #[test]
    fn unclosed_block_is_flushed_verbatim_on_finish() {
        let open_only = format!(
            "<{}DSML{} calls><{}DSML{} invoke name=\"exec_command\">",
            pipe(),
            pipe(),
            pipe(),
            pipe()
        );
        let mut repair = WorkbuddyDsmlStreamRepair::new(vec!["exec_command".to_string()]);
        let mut output = feed_in_chunks(&mut repair, &delta_frame(&open_only), 4);
        output.push_str(&String::from_utf8_lossy(&repair.finish()));

        let marker = workbuddy_dsml_open_marker();
        assert!(output.contains(&marker), "开标签被吞了：{output}");
        assert!(output.contains("exec_command"));
    }

    /// 用量帧也要被规范化：缓存命中别名回写 + `total_tokens` 补齐（面板 `usage.go`）。
    #[test]
    fn usage_frames_are_normalized_in_the_stream() {
        let mut repair = WorkbuddyDsmlStreamRepair::new(Vec::new());
        let frame = concat!(
            "data: {\"id\":\"chatcmpl-1\",\"object\":\"chat.completion.chunk\",",
            "\"choices\":[],\"usage\":{\"prompt_tokens\":10,\"completion_tokens\":4,",
            "\"cached_tokens\":0,\"prompt_tokens_details\":{\"cached_tokens\":6}}}\n"
        );
        let output = repair.push_bytes(frame.as_bytes());
        let output = String::from_utf8_lossy(&output).to_string();
        assert!(output.contains("\"total_tokens\":14"), "{output}");
        assert!(output.contains("\"prompt_cache_hit_tokens\":6"), "{output}");
        assert!(output.contains("\"cached_tokens\":6"), "{output}");
        // 上游没给 `[DONE]` → finish 只补这一个终止符（见 `finish_guarantees_a_done_terminator`）。
        let tail = String::from_utf8_lossy(&repair.finish()).to_string();
        assert_eq!(tail.trim(), "data: [DONE]");
    }

    /// **面板口径**：`seen` 与 name 是否非空无关——首片（哪怕只有 id/type）就占位，
    /// 后续分片的 name 一律删掉。
    ///
    /// 真机记录（2026-10-15）：CodeBuddy 的 `deepseek-v4-flash` 原生 tool_calls **首片就带
    /// `function.name: ""`**，客户端最终拿到的 name 是空——那是**上游没给名字**（面板同样如此），
    /// 与本函数无关。这里刻意**不做**「名字晚到就保留」的加固：真机没有观测到该形态，
    /// 与参考实现保持一致更重要（见函数上的说明）。
    #[test]
    fn tool_call_name_is_stripped_after_the_first_fragment_even_when_empty() {
        let mut repair = WorkbuddyDsmlStreamRepair::new(Vec::new());
        // 首片：只有 id/type（面板口径下这也算「首片」，会占位）。
        let first = concat!(
            "data: {\"choices\":[{\"index\":0,\"delta\":{\"tool_calls\":[",
            "{\"index\":0,\"id\":\"call_00_x\",\"type\":\"function\",\"function\":{\"arguments\":\"\"}}]},\"finish_reason\":null}]}\n"
        );
        let out = String::from_utf8_lossy(&repair.push_bytes(first.as_bytes())).to_string();
        assert!(!out.contains("\"name\""), "首片本来就没有 name：{out}");

        // 第二片带 name → 面板口径下会被删掉（index 已占位）。
        let second = concat!(
            "data: {\"choices\":[{\"index\":0,\"delta\":{\"tool_calls\":[",
            "{\"index\":0,\"function\":{\"name\":\"get_weather\",\"arguments\":\"{}\"}}]},\"finish_reason\":null}]}\n"
        );
        let out = String::from_utf8_lossy(&repair.push_bytes(second.as_bytes())).to_string();
        assert!(
            !out.contains("\"name\""),
            "面板口径：首片已占位，后续 name 一律删：{out}"
        );
    }

    /// 上游截断/没发 `[DONE]` 时，`finish()` 必须补一个（否则等 `[DONE]` 的客户端挂住）。
    #[test]
    fn finish_guarantees_a_done_terminator() {
        // 上游只给了正文帧就断了 → finish 补 [DONE]。
        let mut repair = WorkbuddyDsmlStreamRepair::new(Vec::new());
        let _ = repair.push_bytes(delta_frame("你好").as_bytes());
        let output = String::from_utf8_lossy(&repair.finish()).to_string();
        assert!(output.contains("data: [DONE]"), "{output}");

        // 上游正常给了 [DONE] → 不重复补（finish 只输出残留，不含第二个 [DONE]）。
        let mut repair = WorkbuddyDsmlStreamRepair::new(Vec::new());
        let mut input = delta_frame("你好");
        input.push_str("data: [DONE]\n\n");
        let streamed = String::from_utf8_lossy(&repair.push_bytes(input.as_bytes())).to_string();
        assert_eq!(streamed.matches("[DONE]").count(), 1, "{streamed}");
        let tail = String::from_utf8_lossy(&repair.finish()).to_string();
        assert!(!tail.contains("[DONE]"), "不该重复补：{tail}");
    }

    /// 原生 tool_calls 分片：同一 index 的后续分片必须**去掉重复的 `name`**
    /// （面板 `stripToolCallNames`；累加型会拼成 `BashBash`、覆盖型会被空串清空）。
    #[test]
    fn repeated_tool_call_names_are_stripped_after_the_first_fragment() {
        let mut repair = WorkbuddyDsmlStreamRepair::new(Vec::new());
        // 首片：带 id/name。
        let first = concat!(
            "data: {\"choices\":[{\"index\":0,\"delta\":{\"tool_calls\":[",
            "{\"index\":0,\"id\":\"call_1\",\"type\":\"function\",",
            "\"function\":{\"name\":\"Bash\",\"arguments\":\"\"}}]},\"finish_reason\":null}]}\n"
        );
        let out = String::from_utf8_lossy(&repair.push_bytes(first.as_bytes())).to_string();
        assert!(out.contains("\"name\":\"Bash\""), "首片保留 name：{out}");

        // 第二片：重复 name（面板实测上游会给重复非空串）+ arguments 片段 → name 键被删。
        let second = concat!(
            "data: {\"choices\":[{\"index\":0,\"delta\":{\"tool_calls\":[",
            "{\"index\":0,\"function\":{\"name\":\"Bash\",\"arguments\":\"{\\\"a\\\":\"}}]},\"finish_reason\":null}]}\n"
        );
        let out = String::from_utf8_lossy(&repair.push_bytes(second.as_bytes())).to_string();
        assert!(
            !out.contains("\"name\""),
            "后续分片的 name 键必须删掉：{out}"
        );
        assert!(out.contains("\\\"a\\\":"), "arguments 原样透传：{out}");

        // 第三片：空 name 同样删除（幂等）。
        let third = concat!(
            "data: {\"choices\":[{\"index\":0,\"delta\":{\"tool_calls\":[",
            "{\"index\":0,\"function\":{\"name\":\"\",\"arguments\":\"1}\"}}]},\"finish_reason\":null}]}\n"
        );
        let out = String::from_utf8_lossy(&repair.push_bytes(third.as_bytes())).to_string();
        assert!(!out.contains("\"name\""), "{out}");
    }

    /// 普通流（没有标记）必须零延迟透传：正文不因为「可能在标记里」而被扣住。
    #[test]
    fn plain_text_streams_through_without_buffering() {
        let mut repair = WorkbuddyDsmlStreamRepair::new(Vec::new());
        let framed = delta_frame("你好，这里是普通回答。");
        let output = feed_in_chunks(&mut repair, &framed, 3);
        assert!(output.contains("你好，这里是普通回答。"), "{output}");
        // 不该额外合成任何帧。
        assert!(!output.contains("tool_calls"));
        // 普通流结束时只剩补的 `[DONE]` 终止符（上游没给就补，面板同款保证）。
        let tail = String::from_utf8_lossy(&repair.finish()).to_string();
        assert_eq!(
            tail.trim(),
            "data: [DONE]",
            "普通流结束时不该有其它残留输出"
        );
    }

    /// 结尾是一个「像标记开头」的半截前缀：必须扣住，并在 finish 时补发。
    #[test]
    fn partial_marker_prefix_at_end_is_held_then_flushed() {
        let marker_head = &workbuddy_dsml_open_marker()[..4];
        let mut repair = WorkbuddyDsmlStreamRepair::new(Vec::new());
        let framed = delta_frame(&format!("正文{marker_head}"));
        let mut output = feed_in_chunks(&mut repair, &framed, 2);
        let held_only = !output.contains(marker_head);
        output.push_str(&String::from_utf8_lossy(&repair.finish()));
        assert!(held_only, "半截前缀应当先被扣住：{output}");
        assert!(
            output.contains(marker_head),
            "finish 必须补发半截前缀：{output}"
        );
        assert!(output.contains("正文"));
    }

    /// 块合法但工具名不在声明清单里：按整段还原的口径拒绝，标记原样留在流里。
    #[test]
    fn name_outside_declared_list_is_not_repaired() {
        let mut events = delta_frame(&dsml_block("rm_rf"));
        events.push_str(&finish_frame());
        let mut repair = WorkbuddyDsmlStreamRepair::new(vec!["exec_command".to_string()]);
        let mut output = feed_in_chunks(&mut repair, &events, 8);
        output.push_str(&String::from_utf8_lossy(&repair.finish()));

        assert!(output.contains("DSML"), "不合法的块应原样透出：{output}");
        assert!(!output.contains("\"tool_calls\""));
    }
}
