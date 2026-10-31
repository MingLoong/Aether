use crate::{AppState, GatewayError};
use axum::body::{Body, Bytes};
use axum::http::{self, HeaderMap, HeaderValue, Response};
use axum::response::IntoResponse;
use serde_json::json;
use tracing::warn;

/// 面板前缀在 AE 侧的形态：/console/{provider_id}（不带尾斜杠）。
pub(crate) fn console_base_for_provider(provider_id: &str) -> String {
    format!("/console/{provider_id}")
}

/// 从 /console/{id}/... 请求路径里取 provider_id 段；返回 (provider_id, 剥前缀后的子路径)。
/// 剥前缀规则与 opencode2api 的 wrappedMux 对齐：
///   /console/{id}      → "/"
///   /console/{id}/     → "/"
///   /console/{id}/x/y  → "/x/y"
pub(crate) fn split_console_proxy_path(path: &str) -> Option<(String, String)> {
    let rest = path.strip_prefix("/console")?;
    let rest = rest.strip_prefix('/')?;
    let (provider_id, sub) = match rest.split_once('/') {
        Some((id, sub)) => (id, sub),
        None => (rest, ""),
    };
    if provider_id.is_empty() {
        return None;
    }
    let sub = if sub.is_empty() {
        "/".to_string()
    } else {
        format!("/{sub}")
    };
    Some((provider_id.to_string(), sub))
}

/// relay 端点 base_url 面板源站：opencode2api 的面板与 /v1 API 同端口，
/// base_url 形如 http://host:port/v1 —— 面板源站就是去掉 /v1 后缀。
fn console_origin_of(base_url: &str) -> String {
    base_url
        .trim()
        .strip_suffix("/v1")
        .unwrap_or_else(|| base_url.trim())
        .to_string()
}

/// AE 面板反代：把 /console/{id}/* 原样转发到 relay 供应商 base_url 源站。
/// 鉴权由 Go 面板自身的 session/SSO 负责，AE 只做路径还原 + X-Console-Base 注入。
pub(crate) async fn maybe_build_console_proxy_response(
    state: &AppState,
    request_path: &str,
    request_query: Option<&str>,
    method: &http::Method,
    request_headers: &HeaderMap,
    request_body: Option<&Bytes>,
) -> Result<Option<Response<Body>>, GatewayError> {
    let Some((provider_id, sub_path)) = split_console_proxy_path(request_path) else {
        return Ok(None);
    };
    let provider_ids = [provider_id.clone()];
    let providers = state.read_provider_catalog_providers_by_ids(&provider_ids).await?;
    let Some(provider) = providers.first() else {
        return Ok(Some(
            (
                http::StatusCode::NOT_FOUND,
                axum::Json(json!({"detail": "console provider not found"})),
            )
                .into_response(),
        ));
    };
    if provider.provider_type != "relay" {
        return Ok(Some(
            (
                http::StatusCode::BAD_REQUEST,
                axum::Json(json!({"detail": "console proxy only supports relay providers"})),
            )
                .into_response(),
        ));
    }
    let endpoints = state
        .list_provider_catalog_endpoints_by_provider_ids(&provider_ids)
        .await?;
    let Some(enabled_base_url) = endpoints
        .iter()
        .find(|endpoint| endpoint.is_active)
        .map(|endpoint| endpoint.base_url.clone())
    else {
        return Ok(Some(
            (
                http::StatusCode::BAD_GATEWAY,
                axum::Json(json!({"detail": "relay provider has no enabled endpoint base_url"})),
            )
                .into_response(),
        ));
    };

    let mut upstream_url = format!("{}{sub_path}", console_origin_of(&enabled_base_url));
    if let Some(query) = request_query.filter(|query| !query.is_empty()) {
        upstream_url.push('?');
        upstream_url.push_str(query);
    }

    let reqwest_method =
        reqwest::Method::from_bytes(method.as_str().as_bytes()).unwrap_or(reqwest::Method::GET);
    let mut builder = state
        .client
        .request(reqwest_method, &upstream_url)
        .header("X-Console-Base", console_base_for_provider(&provider_id))
        // 面板 API 不走 AE 的上游 key 鉴权；也不把客户端的 Authorization 带给面板源站。
        .headers(filtered_forward_headers(request_headers));
    match request_body {
        Some(body) if !body.is_empty() => builder = builder.body(body.clone()),
        _ => {}
    }

    let response = match builder.send().await {
        Ok(response) => response,
        Err(error) => {
            warn!(
                provider_id = %provider_id,
                upstream_url = %upstream_url,
                error = %error,
                "console proxy upstream request failed"
            );
            return Ok(Some(
                (
                    http::StatusCode::BAD_GATEWAY,
                    axum::Json(json!({"detail": "console upstream unavailable"})),
                )
                    .into_response(),
            ));
        }
    };

    Ok(Some(convert_upstream_response(response).await))
}

/// 只转发安全头；逐跳头/鉴权头/长度类头由 reqwest 重算。
fn filtered_forward_headers(request_headers: &HeaderMap) -> HeaderMap {
    let mut headers = HeaderMap::new();
    for (name, value) in request_headers {
        let lower = name.as_str().to_ascii_lowercase();
        let skip = matches!(
            lower.as_str(),
            "authorization"
                | "host"
                | "content-length"
                | "transfer-encoding"
                | "connection"
                | "keep-alive"
                | "proxy-authorization"
                | "proxy-connection"
                | "te"
                | "trailer"
                | "upgrade"
                | "x-console-base"
                | "cookie"
        );
        if skip {
            continue;
        }
        if let Ok(value) = HeaderValue::from_bytes(value.as_bytes()) {
            headers.append(name.clone(), value);
        }
    }
    headers
}

async fn convert_upstream_response(response: reqwest::Response) -> Response<Body> {
    let mut builder = Response::builder().status(response.status());
    for (name, value) in response.headers() {
        let lower = name.as_str().to_ascii_lowercase();
        // 逐跳头不能透传；Set-Cookie 单独 append 保多值。
        if matches!(
            lower.as_str(),
            "content-length" | "transfer-encoding" | "connection" | "keep-alive"
        ) {
            continue;
        }
        builder = if lower == "set-cookie" {
            builder.headers_mut().expect("valid builder").append(
                http::header::SET_COOKIE,
                HeaderValue::from_bytes(value.as_bytes()).unwrap_or_else(|_| {
                    HeaderValue::from_static("")
                }),
            );
            builder
        } else if let Ok(value) = HeaderValue::from_bytes(value.as_bytes()) {
            builder.header(name.clone(), value)
        } else {
            builder
        };
    }
    let body = match response.bytes().await {
        Ok(bytes) => Body::from(bytes),
        Err(error) => {
            warn!(error = %error, "console proxy upstream body read failed");
            Body::empty()
        }
    };
    builder.body(body).unwrap_or_else(|_| Body::empty().into_response())
}

#[cfg(test)]
mod tests {
    use super::{console_base_for_provider, console_origin_of, split_console_proxy_path};

    #[test]
    fn splits_console_proxy_paths_like_go_wrapped_mux() {
        assert_eq!(
            split_console_proxy_path("/console/abc-123/api/stats"),
            Some(("abc-123".to_string(), "/api/stats".to_string()))
        );
        assert_eq!(
            split_console_proxy_path("/console/abc-123"),
            Some(("abc-123".to_string(), "/".to_string()))
        );
        assert_eq!(
            split_console_proxy_path("/console/abc-123/"),
            Some(("abc-123".to_string(), "/".to_string()))
        );
        assert_eq!(
            split_console_proxy_path("/console/abc-123/console-sso"),
            Some(("abc-123".to_string(), "/console-sso".to_string()))
        );
        assert_eq!(split_console_proxy_path("/console"), None);
        assert_eq!(split_console_proxy_path("/console/"), None);
        assert_eq!(split_console_proxy_path("/console//"), None);
    }

    #[test]
    fn console_origin_strips_v1_suffix() {
        assert_eq!(
            console_origin_of("http://127.0.0.1:8000/v1"),
            "http://127.0.0.1:8000"
        );
        assert_eq!(
            console_origin_of("http://127.0.0.1:8000"),
            "http://127.0.0.1:8000"
        );
    }

    #[test]
    fn console_base_shape() {
        assert_eq!(
            console_base_for_provider("abc-123"),
            "/console/abc-123"
        );
    }
}
