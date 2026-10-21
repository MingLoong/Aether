//! Public OpenAI Realtime (`/v1/realtime`) WebSocket bridge.
//!
//! This is intentionally separate from Responses WebSocket mode and Codex
//! Frameless `/v1/live`: all three use WebSocket transport but have different
//! event grammars and lifecycle semantics.

mod audit;
mod planner;
mod protocol;
mod session;

use std::net::SocketAddr;

use axum::body::Body;
use axum::extract::ws::WebSocketUpgrade;
use axum::extract::{ConnectInfo, State};
use axum::http::{HeaderMap, Response, Uri};

use crate::handlers::proxy::websocket::ingress::{
    prepare_authenticated_ai_websocket, AuthenticatedAiWebSocketUpgradePreparation,
    WebSocketIngressSpec,
};
use crate::handlers::proxy::websocket::session::REALTIME_WEBSOCKET_SESSION_LIMITS;
use crate::{AppState, GatewayError};

pub(crate) async fn realtime_websocket(
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
        REALTIME_WEBSOCKET_INGRESS_SPEC,
    )
    .await?
    {
        AuthenticatedAiWebSocketUpgradePreparation::Rejected(response) => Ok(response),
        AuthenticatedAiWebSocketUpgradePreparation::Ready(prepared) => {
            // 号池 `cache_affinity`（会话粘性）：OpenAI Realtime 的 provider / 号池选路
            // 发生在 101 之前的预检里（还在 HTTP 请求任务中），所以握手头派生出的会话
            // token 必须在这里就注入 task-local，否则 planner 读不到。
            // token 为 `None` 时直接 await 原 future —— 不套任何帧；`Some` 时用非
            // async 的 `scope_token`，只多一个 `TaskLocalFuture` 薄包装，不加 async 帧。
            let preflight =
                session::prepare_realtime_websocket(prepared.state(), prepared.context());
            let realtime = match prepared.pool_sticky_session_token() {
                Some(token) => crate::pool_sticky_session::scope_token(token, preflight).await,
                None => preflight.await,
            };
            let realtime = match realtime {
                Ok(realtime) => realtime,
                Err(rejection) => {
                    return prepared.rejection_response(rejection.status(), rejection.message())
                }
            };
            Ok(prepared.into_response_with(
                ws,
                REALTIME_WEBSOCKET_SESSION_LIMITS,
                realtime,
                session::run_realtime_websocket,
            ))
        }
    }
}

const REALTIME_WEBSOCKET_INGRESS_SPEC: WebSocketIngressSpec = WebSocketIngressSpec {
    route_unavailable_message: "OpenAI Realtime WebSocket route is unavailable",
};
