use super::{classified, ClassifiedRoute};

/// `/console/{provider_id}` 前缀下的一切请求都反代到该 relay 供应商的
/// 管理面板（Go 侧自持 session，AE 不做 admin 会话校验，只做路径还原）。
pub(super) fn classify_console_proxy_route(
    _method: &http::Method,
    normalized_path: &str,
) -> Option<ClassifiedRoute> {
    let rest = normalized_path.strip_prefix("/console")?;
    let rest = rest.strip_prefix('/')?;
    let provider_id = rest.split('/').next()?;
    if provider_id.is_empty() {
        return None;
    }
    Some(classified(
        "console_proxy",
        "console_proxy",
        "proxy",
        "",
        false,
    ))
}

#[cfg(test)]
mod tests {
    use super::classify_console_proxy_route;
    use axum::http::Method;

    #[test]
    fn classifies_console_proxy_paths() {
        for path in [
            "/console/410847c2-3398-4978-9ae9-a121b09009d8",
            "/console/410847c2-3398-4978-9ae9-a121b09009d8/",
            "/console/p1/api/stats",
            "/console/p1/console-sso?ignored=query",
        ] {
            let route = classify_console_proxy_route(&Method::GET, path)
                .unwrap_or_else(|| panic!("should classify {path}"));
            assert_eq!(route.route_class, "console_proxy");
            assert_eq!(route.route_family, "console_proxy");
            assert_eq!(route.route_kind, "proxy");
            assert_eq!(route.auth_endpoint_signature, "");
        }
    }

    #[test]
    fn rejects_non_console_paths() {
        for path in ["/console", "/console/", "/consolex/p1", "/api/console/p1"] {
            assert!(
                classify_console_proxy_route(&Method::GET, path).is_none(),
                "should not classify {path}"
            );
        }
        // 空段（/console//）不通过
        assert!(classify_console_proxy_route(&Method::GET, "/console//").is_none());
    }
}
