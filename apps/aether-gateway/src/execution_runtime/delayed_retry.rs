//! opencode 的「延迟重试」（delayed retry）：等一会儿再试，而不是立刻换供应商/换 IP。
//!
//! 它同时服务两类**值得等一等**的上游拒绝，所以名字取机制本身（延迟重试），而不是
//! 其中一类触发原因：
//!
//! 1. **上下文超长**（400）：opencode 的免费层模型（`big-pickle` 等）是**自动路由**的，
//!    同一条请求每次可能落到上下文窗口不同的后端，所以「输入超出模型上下文」这个 4xx
//!    不是确定性的请求错误 —— 延迟之后重试，有可能被路由到窗口更大的后端而成功
//!    （2026-10-19 实测：`input token count (276047) exceeds the model's maximum
//!    context length of (262139)`）。其它供应商的窗口是固定的，重试多少次都超限，
//!    延迟只会让客户端白等。
//! 2. **配额 / 限流**（429、带额度文案的 403）：等待档位同样来自这套阶梯，但换点规则
//!    与次数上限由供应商侧的配额重试策略负责（见
//!    `crate::opencode_rotation::OpenCodeQuotaRetryPolicy`：默认 10s → 20s → 40s、
//!    最多 3 次含第一次、换点只从**未冷却**的 IP 里随机挑）。
//!
//! 间隔来自路由策略里的 `opencode_delayed_retry`（界面「延迟重试」，默认 10s/×2/封顶 80s）。
//! **这里不限制次数**：上下文超长沿用路由策略的 `sticky_key_attempts`（界面「错误重试
//! 次数」），配额型失败由 `quota_retry_max_attempts` 兜底。

use std::collections::HashMap;
use std::sync::{Mutex, OnceLock};

use aether_contracts::ExecutionPlan;
use aether_routing_core::OpenCodeDelayedRetryPolicy;
use serde_json::Value;
use tracing::warn;

use crate::AppState;

/// 日志事件 `opencode_delayed_retry` 的 `reason` 取值之一：上游「上下文超长」。
///
/// 配额型的两个取值（`quota_429` / `quota_403`）由 `opencode_rotation` 记在同一个
/// 事件名下——一个事件名 + 一个 `reason` 字段，比三套事件名更容易统计。
pub(crate) const OPENCODE_DELAYED_RETRY_REASON_CONTEXT_LENGTH: &str = "context_length";

/// 只有 opencode 才做「延迟重试」。
pub(crate) fn provider_type_supports_delayed_retry(provider_type: &str) -> bool {
    provider_type.trim().eq_ignore_ascii_case("opencode")
}

/// 上游错误体是否表示「输入超出模型上下文」。
///
/// 三种写法都见过：OpenAI 兼容的 `maximum context length`、动辄出现在 SSE 里的
/// `context_length_exceeded` 代码、以及 opencode 免费层实际回的
/// `exceeds the model's maximum context length`。
///
/// `error.code` / `error.type` 也要看：上游有时只把语义放在代码里，`message` 只写
/// 一句 "too long"，只读 message 会漏判。
pub(crate) fn context_length_exceeded_in_body(body: Option<&Value>) -> bool {
    let Some(body) = body else { return false };
    let field = |pointer: &str| {
        body.pointer(pointer)
            .and_then(Value::as_str)
            .unwrap_or_default()
            .to_ascii_lowercase()
    };
    let message = {
        let nested = field("/error/message");
        if nested.is_empty() {
            field("/message")
        } else {
            nested
        }
    };
    let code = {
        let nested = field("/error/code");
        if nested.is_empty() {
            field("/error/type")
        } else {
            nested
        }
    };
    let matches = |text: &str| {
        text.contains("maximum context length")
            || text.contains("context_length_exceeded")
            || text.contains("exceeds the model's maximum context")
    };
    matches(&message) || matches(&code)
}

/// 每个请求的「延迟重试」计数（按 trace_id），只决定**阶梯档位**。
///
/// 只决定间隔，**不限制次数**：次数沿用路由策略里的 `sticky_key_attempts`
/// （界面「错误重试次数」：2 → 同 key 重试 1 次，3 → 2 次）。重试预算用完后候选循环
/// 自然停止，这个计数也就不会再被读到。配额型失败另有 `quota_retry_max_attempts`
/// 那条硬上限（在 `opencode_rotation` 里判定）。
fn next_delayed_retry_index(trace_id: &str) -> u32 {
    static COUNTS: OnceLock<Mutex<HashMap<String, u32>>> = OnceLock::new();
    let counts = COUNTS.get_or_init(|| Mutex::new(HashMap::new()));
    let mut guard = match counts.lock() {
        Ok(guard) => guard,
        // 锁中毒时退化成第一档，功能不因此失效。
        Err(_) => return 0,
    };
    // 防泄漏：异常退出可能留下条目，超过阈值直接清空（只是节流计数，丢了也无害）。
    if guard.len() > 512 {
        guard.clear();
    }
    let used = guard.entry(trace_id.to_string()).or_insert(0);
    let index = *used;
    *used = used.saturating_add(1);
    index
}

/// 从请求的路由策略快照里读阶梯。
///
/// 快照缺字段（老请求、老配置）时回落到 `OpenCodeDelayedRetryPolicy::default()`，
/// 也就是「开启 + 10s/×2/封顶 80s」。
pub(crate) fn delayed_retry_policy_from_report_context(
    report_context: Option<&Value>,
) -> OpenCodeDelayedRetryPolicy {
    crate::orchestration::routing_execution_policy_from_report_context(report_context)
        .map(|policy| policy.opencode_delayed_retry)
        .unwrap_or_default()
}

/// 命中 opencode「上下文超长」时，按配置睡一会儿再让调用方重试。
///
/// 返回 `true` 表示这次真的延迟过（日志里会出现 `opencode_delayed_retry`，
/// `reason = "context_length"`）。流式与非流式路径共用这个入口，避免两条路径行为不一致。
#[allow(clippy::too_many_arguments)]
pub(crate) async fn delay_opencode_retry_if_needed(
    state: &AppState,
    plan: &ExecutionPlan,
    trace_id: &str,
    request_id_for_log: &str,
    status_code: u16,
    model_name: &str,
    provider_body_json: Option<&Value>,
    report_context: Option<&Value>,
) -> bool {
    if !context_length_exceeded_in_body(provider_body_json) {
        return false;
    }
    let provider_type = state
        .read_provider_transport_snapshot(&plan.provider_id, &plan.endpoint_id, &plan.key_id)
        .await
        .ok()
        .flatten()
        .map(|transport| transport.provider.provider_type.clone())
        .unwrap_or_default();
    if !provider_type_supports_delayed_retry(&provider_type) {
        return false;
    }
    let retry_policy = delayed_retry_policy_from_report_context(report_context);
    if !retry_policy.enabled {
        return false;
    }
    let retry_index = next_delayed_retry_index(trace_id);
    let Some(delay) = retry_policy.delay_for_attempt(retry_index) else {
        return false;
    };
    warn!(
        event_name = "opencode_delayed_retry",
        log_type = "event",
        trace_id = %trace_id,
        request_id = %request_id_for_log,
        status_code,
        model_name,
        provider_type = provider_type.as_str(),
        reason = OPENCODE_DELAYED_RETRY_REASON_CONTEXT_LENGTH,
        retry_index,
        delay_ms = delay.as_millis() as u64,
        "gateway delaying before retrying an upstream context-length rejection"
    );
    tokio::time::sleep(delay).await;
    true
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn only_opencode_gets_the_delayed_retry() {
        assert!(provider_type_supports_delayed_retry("opencode"));
        assert!(provider_type_supports_delayed_retry(" OpenCode "));
        assert!(!provider_type_supports_delayed_retry("openai"));
        assert!(!provider_type_supports_delayed_retry(""));
    }

    #[test]
    fn detects_context_length_rejections_in_every_observed_wording() {
        assert!(context_length_exceeded_in_body(Some(&json!({
            "error": { "message": "input token count (276047) exceeds the model's maximum context length of (262139)" }
        }))));
        // 语义只在 code 里，message 是没信息量的 "too long"。
        assert!(context_length_exceeded_in_body(Some(&json!({
            "error": { "code": "context_length_exceeded", "message": "too long" }
        }))));
        // 顶层 message，没有 error 包装。
        assert!(context_length_exceeded_in_body(Some(&json!({
            "message": "This model's maximum context length is 8192 tokens"
        }))));
        assert!(!context_length_exceeded_in_body(Some(&json!({
            "error": { "message": "rate limit exceeded" }
        }))));
        assert!(!context_length_exceeded_in_body(Some(&json!({
            "error": { "code": "invalid_request_error", "message": "bad param" }
        }))));
        assert!(!context_length_exceeded_in_body(None));
    }

    #[test]
    fn retry_index_grows_per_trace_id_and_is_independent_between_requests() {
        let first = next_delayed_retry_index("trace-unit-test-a");
        let second = next_delayed_retry_index("trace-unit-test-a");
        let other = next_delayed_retry_index("trace-unit-test-b");
        assert_eq!(second, first + 1);
        assert_eq!(other, 0);
    }

    #[test]
    fn missing_report_context_falls_back_to_the_documented_default() {
        let policy = delayed_retry_policy_from_report_context(None);
        assert_eq!(policy, OpenCodeDelayedRetryPolicy::default());
        assert_eq!(
            policy.delay_for_attempt(0),
            Some(std::time::Duration::from_secs(10))
        );
        assert_eq!(
            policy.delay_for_attempt(1),
            Some(std::time::Duration::from_secs(20))
        );
        assert_eq!(
            policy.delay_for_attempt(2),
            Some(std::time::Duration::from_secs(40))
        );
        assert_eq!(
            policy.delay_for_attempt(3),
            Some(std::time::Duration::from_secs(80))
        );
        assert_eq!(
            policy.delay_for_attempt(9),
            Some(std::time::Duration::from_secs(80))
        );
    }

    /// 路由策略快照里的新键能被读回来（不是只认 default）。
    #[test]
    fn delayed_retry_policy_is_read_from_the_report_context_snapshot() {
        let snapshot = json!({
            "routing_execution_policy": {
                "opencode_delayed_retry": {
                    "enabled": true,
                    "base_ms": 7000,
                    "multiplier": 2,
                    "max_ms": 80000
                }
            }
        });
        let policy = delayed_retry_policy_from_report_context(Some(&snapshot));
        assert_eq!(policy.base_ms, 7000);
        assert_eq!(
            policy.delay_for_attempt(0),
            Some(std::time::Duration::from_millis(7000))
        );
    }
}
