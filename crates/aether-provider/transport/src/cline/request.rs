//! Cline 上游的请求体默认规则（声明式）。
//!
//! 为什么不能纯透传（实测 2026-10-12）：`max_tokens: 16` 时上游回
//! **500 `{"error":"empty response content"}`** —— Cline 免费档多为推理模型，
//! 预算被思考吃光后正文为空，上游把这当成错误。同一请求给 512 即 200。
//!
//! 这里刻意**不写请求时改写的 Rust 代码**，而是产出端点级 `body_rules`：
//!
//! - 规则存进端点，运营者在面板上看得见、调得动；
//! - 规则由规则引擎在**两条链路**（跨格式的标准链路、同格式直通链路）都会应用，
//!   不需要在每个 planner 里插钩子；
//! - 语义上这是"上游协议的默认值"，不是"运行时补丁"。
//!
//! 策略：
//!
//! 1. `max_completion_tokens` → `max_tokens`（上游只认后者）；
//! 2. `max_tokens` 缺失 / null / 字符串 / 小于 [`CLINE_MIN_UPSTREAM_MAX_TOKENS`]
//!    → 一律兜到 [`CLINE_DEFAULT_MAX_TOKENS`]；
//! 3. 给了足够大的值 → 原样尊重（每个模型的硬上限由上游裁决，Aether 不猜）。
//!
//! 规则的**顺序有意义**：归一化必须排在兜底之前，否则被换算过来的值不会经过下限检查。

use serde_json::{json, Value};

/// 低于这个预算一律视为"没给"：上游对过小预算直接报错，而不是截断。
pub const CLINE_MIN_UPSTREAM_MAX_TOKENS: u64 = 64;

/// 兜底预算：远大于推理开销，又不容易撞上多数模型的硬上限。
pub const CLINE_DEFAULT_MAX_TOKENS: u64 = 32_000;

/// `openai:chat` 端点的默认 `body_rules`。
pub fn cline_openai_chat_body_rules() -> Vec<Value> {
    let default_max_tokens = Value::from(CLINE_DEFAULT_MAX_TOKENS);
    vec![
        json!({
            "action": "rename",
            "from": "max_completion_tokens",
            "to": "max_tokens"
        }),
        json!({
            "action": "set",
            "path": "max_tokens",
            "value": default_max_tokens,
            "condition": { "path": "max_tokens", "op": "not_exists" }
        }),
        json!({
            "action": "set",
            "path": "max_tokens",
            "value": default_max_tokens,
            "condition": { "path": "max_tokens", "op": "type_is", "value": "null" }
        }),
        json!({
            "action": "set",
            "path": "max_tokens",
            "value": default_max_tokens,
            "condition": { "path": "max_tokens", "op": "type_is", "value": "string" }
        }),
        json!({
            "action": "set",
            "path": "max_tokens",
            "value": default_max_tokens,
            "condition": {
                "path": "max_tokens",
                "op": "lt",
                "value": CLINE_MIN_UPSTREAM_MAX_TOKENS
            }
        }),
    ]
}

#[cfg(test)]
mod tests {
    use serde_json::json;

    use crate::apply_local_body_rules_with_request_headers;

    use super::*;

    fn apply_rules(body: &mut Value) {
        let rules = Value::Array(cline_openai_chat_body_rules());
        assert!(
            apply_local_body_rules_with_request_headers(body, Some(&rules), None, None),
            "规则必须被本地规则引擎接受"
        );
    }

    fn max_tokens_of(body: &Value) -> Option<u64> {
        body.get("max_tokens").and_then(Value::as_u64)
    }

    #[test]
    fn rules_are_locally_supported() {
        let rules = Value::Array(cline_openai_chat_body_rules());
        assert!(crate::body_rules_are_locally_supported(Some(&rules)));
    }

    #[test]
    fn tiny_budget_is_raised_to_the_default() {
        // 实测：max_tokens=16 → 上游 500 empty response content
        let mut body = json!({"model": "cline-free/step-5-preview", "max_tokens": 16});
        apply_rules(&mut body);
        assert_eq!(max_tokens_of(&body), Some(CLINE_DEFAULT_MAX_TOKENS));
    }

    #[test]
    fn missing_zero_null_and_string_budgets_fall_back_to_the_default() {
        for mut body in [
            json!({"model": "m"}),
            json!({"model": "m", "max_tokens": 0}),
            json!({"model": "m", "max_tokens": null}),
            json!({"model": "m", "max_tokens": "512"}),
        ] {
            apply_rules(&mut body);
            assert_eq!(
                max_tokens_of(&body),
                Some(CLINE_DEFAULT_MAX_TOKENS),
                "unexpected budget for {body}"
            );
        }
    }

    #[test]
    fn usable_budget_is_respected() {
        for budget in [CLINE_MIN_UPSTREAM_MAX_TOKENS, 512, 128_000] {
            let mut body = json!({"model": "m", "max_tokens": budget});
            apply_rules(&mut body);
            assert_eq!(max_tokens_of(&body), Some(budget));
        }
    }

    #[test]
    fn max_completion_tokens_is_normalized_into_max_tokens() {
        let mut body = json!({"model": "m", "max_completion_tokens": 4096});
        apply_rules(&mut body);
        assert_eq!(max_tokens_of(&body), Some(4096));
        assert!(body.get("max_completion_tokens").is_none());
    }

    #[test]
    fn normalized_budget_still_passes_through_the_floor() {
        let mut body = json!({"model": "m", "max_completion_tokens": 8});
        apply_rules(&mut body);
        assert_eq!(
            max_tokens_of(&body),
            Some(CLINE_DEFAULT_MAX_TOKENS),
            "换算过来的过小预算也必须被兜底"
        );
        assert!(body.get("max_completion_tokens").is_none());
    }

    #[test]
    fn other_fields_are_left_untouched() {
        let mut body = json!({
            "model": "cline-free/mimo-v2.6-flash",
            "messages": [{"role": "user", "content": "hi"}],
            "stream": true,
            "temperature": 0.7,
            "max_tokens": 1024
        });
        let before = body.clone();
        apply_rules(&mut body);
        assert_eq!(body, before);
    }
}
