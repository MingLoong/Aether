//! Experimental Codex Frameless Bidi V3 (`/v1/live`) bridge.
//!
//! The public OpenAI Realtime and Responses WebSocket protocols are related
//! transport families, but this Codex protocol has a distinct event grammar.
//! Keeping it in an independent module prevents a `session.update` frame from
//! ever entering the Responses `response.create` state machine.

mod audit;
mod http;
mod planner;
mod protocol;
mod registry;
mod session;

use std::net::SocketAddr;

use axum::body::Body;
use axum::extract::ws::WebSocketUpgrade;
use axum::extract::{ConnectInfo, State};
use axum::http::{HeaderMap, Response, Uri};

use crate::control::GatewayControlDecision;
use crate::handlers::proxy::websocket::ingress::{
    prepare_authenticated_ai_websocket, AuthenticatedAiWebSocketUpgradePreparation,
    WebSocketIngressSpec,
};
use crate::handlers::proxy::websocket::session::LIVE_WEBSOCKET_SESSION_LIMITS;
use crate::{AppState, GatewayError};

pub(crate) use http::maybe_handle_live_http;

/// Frameless Bidi currently exposes no stable token/cost usage object that can
/// be fed into Aether's settlement pipeline. Fail closed for finite-balance
/// principals instead of silently serving unmetered traffic. Standalone or
/// shared keys backed by an unlimited/no-wallet policy resolve without a
/// finite `balance_remaining` and remain eligible.
fn live_usage_accounting_is_safe(decision: &GatewayControlDecision) -> bool {
    decision
        .auth_context
        .as_ref()
        .is_some_and(|auth| auth.balance_remaining.is_none())
}

pub(crate) async fn live_websocket(
    State(state): State<AppState>,
    ConnectInfo(remote_addr): ConnectInfo<SocketAddr>,
    ws: WebSocketUpgrade,
    headers: HeaderMap,
    uri: Uri,
) -> Result<Response<Body>, GatewayError> {
    match prepare_authenticated_ai_websocket(
        state,
        remote_addr,
        headers,
        uri,
        LIVE_WEBSOCKET_INGRESS_SPEC,
    )
    .await?
    {
        AuthenticatedAiWebSocketUpgradePreparation::Rejected(response) => Ok(response),
        AuthenticatedAiWebSocketUpgradePreparation::Ready(prepared) => {
            // 号池 `cache_affinity`（会话粘性）：Codex Live 的 provider / 号池选路发生在
            // 101 之前的预检里（还在 HTTP 请求任务中），所以握手头派生出的会话 token
            // 必须在这里就注入 task-local，否则 planner 读不到。
            // token 为 `None` 时直接 await 原 future —— 不套任何帧。
            // `Some` 时用非 async 的 `scope_token`，只多一个 `TaskLocalFuture` 薄包装，
            // 不引入 async 栈帧（这条路径的 future 极深）。
            let preflight = session::prepare_live_websocket(prepared.state(), prepared.context());
            let live = match prepared.pool_sticky_session_token() {
                Some(token) => crate::pool_sticky_session::scope_token(token, preflight).await,
                None => preflight.await,
            };
            let live = match live {
                Ok(live) => live,
                Err(rejection) => {
                    if !rejection.audit_persisted() {
                        audit::record_live_websocket_preflight_failure(
                            prepared.state(),
                            &prepared.context().decision,
                            prepared.context().trace_id.as_str(),
                            prepared.context().uri.path(),
                            prepared.context().uri.query(),
                            rejection.status(),
                            rejection.termination(),
                        );
                    }
                    return prepared.rejection_response(rejection.status(), rejection.message());
                }
            };
            Ok(prepared.into_response_with(
                ws,
                LIVE_WEBSOCKET_SESSION_LIMITS,
                live,
                session::run_live_websocket,
            ))
        }
    }
}

const LIVE_WEBSOCKET_INGRESS_SPEC: WebSocketIngressSpec = WebSocketIngressSpec {
    route_unavailable_message: "Codex Live WebSocket route is unavailable",
};
