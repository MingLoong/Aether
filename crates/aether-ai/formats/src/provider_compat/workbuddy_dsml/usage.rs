//! 响应侧 usage 规范化（面板 `usage.go` + `sse.go::ensureUsageTotal`）。
//!
//! 两件事，都是「让严格的下游解析器读到正确数字」：
//!
//! 1. **缓存命中别名对齐**（`normalizeUsageCacheAliases`）：WorkBuddy 有些响应把真实命中
//!    写在 `prompt_tokens_details.cached_tokens`，同时又发 `cache_read_input_tokens: 0` /
//!    `cached_tokens: 0` 这类**兼容别名**。严格的客户端可能优先读那些 0 别名，
//!    于是**命中被丢掉**。这里把最可信的命中值回写到所有别名。
//! 2. **`total_tokens` 补齐**（`ensureUsageTotal`）：严格按 schema 校验的客户端要求
//!    usage 必含 `total_tokens`；上游偶尔只发 prompt/completion。两者都在时才补和，
//!    单边有值**不臆造**。

use serde_json::{json, Value};

/// 缓存命中 token 数的候选来源，**按可信度排序**（面板 `bestUsageCacheHitTokens` 同序）。
const CACHE_HIT_PATHS: &[(&str, &str)] = &[
    ("prompt_tokens_details", "cached_tokens"),
    ("", "prompt_cache_hit_tokens"),
    ("", "cache_read_input_tokens"),
    ("", "cached_tokens"),
    ("input_tokens_details", "cached_tokens"),
];

/// 取 usage 里最可信的缓存命中数：第一个**正数**候选胜出；全无则 `None`。
pub fn workbuddy_usage_cache_hit_tokens(usage: &Value) -> Option<i64> {
    let object = usage.as_object()?;
    for (section, key) in CACHE_HIT_PATHS {
        let value = if section.is_empty() {
            object.get(*key)
        } else {
            object
                .get(*section)
                .and_then(Value::as_object)
                .and_then(|details| details.get(*key))
        };
        if let Some(tokens) = value.and_then(positive_usage_integer) {
            return Some(tokens);
        }
    }
    None
}

/// 把最可信的缓存命中值回写到全部别名（面板 `normalizeUsageCacheAliases`）。
///
/// 命中值非正 / usage 非对象 → 一字不动。`input_tokens_details` 只在**上游已经给了**时
/// 才回写（不给 Chat-only 客户端凭空造 Responses API 的嵌套字段）。返回是否改动。
pub fn normalize_workbuddy_usage_cache_aliases(usage: &mut Value) -> bool {
    let Some(best) = workbuddy_usage_cache_hit_tokens(usage) else {
        return false;
    };
    let Some(object) = usage.as_object_mut() else {
        return false;
    };
    object.insert("cache_read_input_tokens".to_string(), json!(best));
    object.insert("cached_tokens".to_string(), json!(best));
    object.insert("prompt_cache_hit_tokens".to_string(), json!(best));
    let mut details = object
        .get("prompt_tokens_details")
        .and_then(Value::as_object)
        .cloned()
        .unwrap_or_default();
    details.insert("cached_tokens".to_string(), json!(best));
    object.insert("prompt_tokens_details".to_string(), Value::Object(details));
    if object.contains_key("input_tokens_details") {
        let mut input_details = object
            .get("input_tokens_details")
            .and_then(Value::as_object)
            .cloned()
            .unwrap_or_default();
        input_details.insert("cached_tokens".to_string(), json!(best));
        object.insert(
            "input_tokens_details".to_string(),
            Value::Object(input_details),
        );
    }
    true
}

/// usage 缺 `total_tokens` 时用 prompt + completion 补齐（面板 `ensureUsageTotal`）。
///
/// 已有 total、或 prompt/completion 缺一 → 一字不动（单边有值无法合成可信的 total）。
pub fn ensure_workbuddy_usage_total(usage: &mut Value) -> bool {
    let Some(object) = usage.as_object_mut() else {
        return false;
    };
    if object.contains_key("total_tokens") {
        return false;
    }
    let (Some(prompt), Some(completion)) = (
        object.get("prompt_tokens").and_then(usage_integer),
        object.get("completion_tokens").and_then(usage_integer),
    ) else {
        return false;
    };
    object.insert("total_tokens".to_string(), json!(prompt + completion));
    true
}

/// 一次性做完两件规范化（顺序无关，各自幂等）。
pub fn normalize_workbuddy_response_usage(response_body: &mut Value) -> bool {
    let Some(usage) = response_body.get_mut("usage") else {
        return false;
    };
    let aliases = normalize_workbuddy_usage_cache_aliases(usage);
    let total = ensure_workbuddy_usage_total(usage);
    aliases || total
}

fn positive_usage_integer(value: &Value) -> Option<i64> {
    usage_integer(value).filter(|tokens| *tokens > 0)
}

fn usage_integer(value: &Value) -> Option<i64> {
    if let Some(number) = value.as_i64() {
        return Some(number);
    }
    value.as_f64().map(|number| number as i64)
}

/// 便于测试的构造入口：把 map 包成 `Value`。
#[cfg(test)]
fn usage_map(entries: &[(&str, Value)]) -> Value {
    let mut map = serde_json::Map::new();
    for (key, value) in entries {
        map.insert((*key).to_string(), value.clone());
    }
    Value::Object(map)
}

#[cfg(test)]
mod tests {
    use super::{
        ensure_workbuddy_usage_total, normalize_workbuddy_response_usage,
        normalize_workbuddy_usage_cache_aliases, usage_map, workbuddy_usage_cache_hit_tokens,
    };
    use serde_json::json;

    /// 缓存命中别名：取最可信的正数并回写到全部别名；全零/缺失则不动。
    #[test]
    fn cache_hit_aliases_are_normalized_to_the_best_positive_value() {
        // 真实命中在 prompt_tokens_details，顶层别名是 0 → 回写。
        let mut usage = json!({
            "prompt_tokens": 100,
            "prompt_tokens_details": {"cached_tokens": 64},
            "cache_read_input_tokens": 0,
            "cached_tokens": 0
        });
        assert_eq!(workbuddy_usage_cache_hit_tokens(&usage), Some(64));
        assert!(normalize_workbuddy_usage_cache_aliases(&mut usage));
        assert_eq!(usage["cache_read_input_tokens"], json!(64));
        assert_eq!(usage["cached_tokens"], json!(64));
        assert_eq!(usage["prompt_cache_hit_tokens"], json!(64));
        assert_eq!(usage["prompt_tokens_details"]["cached_tokens"], json!(64));
        // 上游没给 Responses 形态 → 不凭空造。
        assert!(usage.get("input_tokens_details").is_none());

        // 上游给了 input_tokens_details → 一并回写。
        let mut usage = json!({
            "prompt_cache_hit_tokens": 7,
            "input_tokens_details": {"cached_tokens": 0}
        });
        assert!(normalize_workbuddy_usage_cache_aliases(&mut usage));
        assert_eq!(usage["input_tokens_details"]["cached_tokens"], json!(7));

        // 全零 / 全缺 → 不动。
        let mut usage = json!({"prompt_tokens": 5, "cached_tokens": 0});
        assert!(!normalize_workbuddy_usage_cache_aliases(&mut usage));
        assert_eq!(usage, json!({"prompt_tokens": 5, "cached_tokens": 0}));

        // 命中数取「第一个正数」：details 优先于顶层别名。
        let usage = usage_map(&[
            ("cached_tokens", json!(3)),
            ("prompt_cache_hit_tokens", json!(9)),
        ]);
        assert_eq!(workbuddy_usage_cache_hit_tokens(&usage), Some(9));
    }

    /// `total_tokens` 补齐：两边都在才补；已有 total / 缺一边都不动。
    #[test]
    fn total_tokens_is_synthesized_only_when_both_parts_exist() {
        let mut usage = json!({"prompt_tokens": 10, "completion_tokens": 4});
        assert!(ensure_workbuddy_usage_total(&mut usage));
        assert_eq!(usage["total_tokens"], json!(14));

        let mut usage = json!({"prompt_tokens": 10, "completion_tokens": 4, "total_tokens": 99});
        assert!(!ensure_workbuddy_usage_total(&mut usage));
        assert_eq!(usage["total_tokens"], json!(99));

        let mut usage = json!({"prompt_tokens": 10});
        assert!(!ensure_workbuddy_usage_total(&mut usage));
        assert!(usage.get("total_tokens").is_none());

        // 非对象 usage 不 panic。
        let mut usage = json!("oops");
        assert!(!ensure_workbuddy_usage_total(&mut usage));
    }

    /// 组合入口：只动 `usage` 字段，别的字段不碰；没有 usage 则不动。
    #[test]
    fn response_usage_normalization_touches_only_usage() {
        let mut body = json!({
            "id": "x",
            "usage": {"prompt_tokens": 10, "completion_tokens": 4, "cached_tokens": 2}
        });
        assert!(normalize_workbuddy_response_usage(&mut body));
        assert_eq!(body["usage"]["total_tokens"], json!(14));
        assert_eq!(body["usage"]["prompt_cache_hit_tokens"], json!(2));
        assert_eq!(body["id"], json!("x"));

        let mut body = json!({"id": "x"});
        assert!(!normalize_workbuddy_response_usage(&mut body));
    }
}
