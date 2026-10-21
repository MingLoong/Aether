//! 号池 `cache_affinity`（会话粘性）用的会话 token 的**请求级作用域**。
//!
//! 粘性 token 原先只从请求体里取（[`aether_ai_serving::extract_ai_pool_sticky_session_token`]），
//! 而普通 OpenAI 兼容客户端一个字段都不带（`prompt_cache_key` / `conversation_id` /
//! `session_id` …），于是 token 恒为 `None`，粘性逻辑在入口就短路了 —— 线上实测
//! 567 次请求、Redis 里 0 个 sticky 键。
//!
//! 这里把**请求头**派生出来的会话标识挂到 tokio task-local 上：
//!
//! * 请求入口（前端门 handler）用 [`scope_pool_sticky_session_token`] 把派生结果包住整个
//!   请求 future；
//! * 叶子函数（planner / 效果回写）照旧只吃 `&serde_json::Value`，通过
//!   [`extract_pool_sticky_session_token`] 安全读取 task-local；
//! * **body 优先**：body 里有会话字段就完全按旧行为走，header 只是 body 缺失时的兜底。
//!
//! 跨 `tokio::spawn` 边界时必须先 [`current_pool_sticky_session_token`] 捕获、再在子任务里
//! 用 [`scope_pool_sticky_session_token`] 重新包一层（与
//! [`crate::request_diagnostics`] 的 `scope_request_diagnostics_with` 同一套写法）；
//! 拿不到就退化成旧行为（返回 `None`），不会引入新的副作用。

use std::future::Future;

use serde_json::Value;

tokio::task_local! {
    static POOL_STICKY_SESSION_TOKEN: String;
}

/// 请求入口调用：从**原始请求头**派生会话 token。
///
/// 复用 [`crate::client_session_affinity`] 里那套按客户端家族（codex / claude_code /
/// opencode / qwen / roo / kilo / cherry / openui / openai-js / openai-python /
/// anthropic-js / anthropic-python / generic）分别识别 header 的解析器，只取 header
/// 这一路（`body_json = None`），body 一路仍由 [`extract_pool_sticky_session_token`] 负责。
pub(crate) fn pool_sticky_session_token_from_headers(headers: &http::HeaderMap) -> Option<String> {
    crate::client_session_affinity::client_session_token_from_headers(headers)
}

/// 把会话 token 注入 `future` 的 task-local 作用域。
///
/// `None` 时原样执行 `future` —— 没有会话信息的请求行为与旧版完全一致。
pub(crate) async fn scope_pool_sticky_session_token<F>(
    token: Option<String>,
    future: F,
) -> F::Output
where
    F: Future,
{
    match token {
        Some(token) => POOL_STICKY_SESSION_TOKEN.scope(token, future).await,
        None => future.await,
    }
}

/// `tokio::spawn` + [`scope_pool_sticky_session_token`]。
///
/// 用于「先在请求任务里捕获 token、再在 spawn 出去的任务里继续跑业务」的跨 task 边界
/// （流式响应的终端回写、sync 心跳响应等）：写在一行里可以让子任务代码保持原有缩进，
/// 不必为多一层 `scope(...)` 重新缩进上千行。
///
/// `token` 为 `None` 时等价于原来的 `tokio::spawn(future)` —— **不多套任何一帧**
/// （这些调用点的 future 极深，debug 构建下测试线程栈本来就紧）。
pub(crate) fn spawn_scoped<F>(
    token: Option<String>,
    future: F,
) -> tokio::task::JoinHandle<F::Output>
where
    F: Future + Send + 'static,
    F::Output: Send + 'static,
{
    match token {
        Some(token) => tokio::spawn(POOL_STICKY_SESSION_TOKEN.scope(token, future)),
        None => tokio::spawn(future),
    }
}

/// 当前请求（task）已派生出的会话 token。
///
/// 跨 `tokio::spawn` 边界会读到 `None`（task-local 不随任务传播），需要显式捕获后重新
/// [`scope_pool_sticky_session_token`]。
pub(crate) fn current_pool_sticky_session_token() -> Option<String> {
    POOL_STICKY_SESSION_TOKEN
        .try_with(|token| token.clone())
        .ok()
        .filter(|token| !token.trim().is_empty())
}

/// 粘性 token 解析：**body 优先**，body 里没有任何会话字段时才退回请求入口从 header
/// 派生的值。两者都没有 → `None`（粘性照旧短路）。
pub(crate) fn extract_pool_sticky_session_token(body_json: &Value) -> Option<String> {
    aether_ai_serving::extract_ai_pool_sticky_session_token(body_json)
        .or_else(current_pool_sticky_session_token)
}

#[cfg(test)]
mod tests {
    use http::{HeaderMap, HeaderName, HeaderValue};
    use serde_json::json;

    use super::{
        extract_pool_sticky_session_token, pool_sticky_session_token_from_headers,
        scope_pool_sticky_session_token,
    };

    fn headers(pairs: &[(&str, &str)]) -> HeaderMap {
        let mut headers = HeaderMap::new();
        for (name, value) in pairs {
            headers.insert(
                HeaderName::from_bytes(name.as_bytes()).expect("valid header name"),
                HeaderValue::from_str(value).expect("valid header value"),
            );
        }
        headers
    }

    async fn token_for(headers: &HeaderMap, body: &serde_json::Value) -> Option<String> {
        let header_token = pool_sticky_session_token_from_headers(headers);
        scope_pool_sticky_session_token(header_token, async {
            extract_pool_sticky_session_token(body)
        })
        .await
    }

    #[tokio::test]
    async fn body_prompt_cache_key_wins_over_header_session_token() {
        let headers = headers(&[("session_id", "header-session")]);
        let body = json!({ "prompt_cache_key": "body-session" });
        assert_eq!(
            token_for(&headers, &body).await.as_deref(),
            Some("body-session")
        );
    }

    #[tokio::test]
    async fn generic_session_headers_supply_the_token_when_body_has_none() {
        for (name, value) in [
            ("session_id", "header-session"),
            ("session-id", "header-session"),
            ("conversation_id", "header-session"),
        ] {
            let headers = headers(&[(name, value)]);
            let body = json!({ "model": "gpt-5", "messages": [] });
            assert_eq!(
                token_for(&headers, &body).await.as_deref(),
                Some("session=header-session"),
                "header {name} should yield a sticky session token"
            );
        }
    }

    #[tokio::test]
    async fn client_family_specific_headers_supply_the_token() {
        // opencode：`x-opencode-session-id` 自己就能让 family 自适应。
        let opencode = headers(&[("x-opencode-session-id", "opencode-session")]);
        assert_eq!(
            token_for(&opencode, &json!({ "model": "gpt-5" }))
                .await
                .as_deref(),
            Some("session=opencode-session")
        );

        // claude code：`x-claude-code-session-id` 同理。
        let claude_code = headers(&[("x-claude-code-session-id", "claude-session")]);
        assert_eq!(
            token_for(&claude_code, &json!({ "model": "claude-sonnet-4-5" }))
                .await
                .as_deref(),
            Some("session=claude-session")
        );

        // codex：`session-id` 需要 codex 指纹（UA / originator / chatgpt-account-id）才认。
        let codex = headers(&[
            ("user-agent", "codex_cli_rs/0.52.0"),
            ("session-id", "codex-session"),
        ]);
        assert_eq!(
            token_for(&codex, &json!({ "model": "gpt-5-codex" }))
                .await
                .as_deref(),
            Some("session=codex-session")
        );
    }

    #[tokio::test]
    async fn no_session_signal_anywhere_returns_none() {
        let headers = headers(&[("user-agent", "OpenAI/Python 1.0.0")]);
        let body = json!({ "model": "gpt-5", "messages": [] });
        assert_eq!(token_for(&headers, &body).await, None);
        assert_eq!(token_for(&HeaderMap::new(), &json!({})).await, None);
    }

    #[tokio::test]
    async fn body_token_is_used_without_any_scope() {
        // 没有 task-local（例如后台任务/单测）时，body 一路必须照旧可用。
        assert_eq!(
            extract_pool_sticky_session_token(&json!({ "conversation_id": "conv-1" })).as_deref(),
            Some("conv-1")
        );
        assert_eq!(extract_pool_sticky_session_token(&json!({})), None);
    }
}
