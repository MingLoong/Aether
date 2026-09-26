use axum::http;

use super::{classified, ClassifiedRoute};

const OPENCODE_IP_POOL_PATH_PREFIX: &str = "/api/admin/opencode-ip-pool/providers/";

/// Classifies the OpenCode front-proxy IP pool admin routes:
/// `GET  /api/admin/opencode-ip-pool/providers/{id}`
/// `PUT  /api/admin/opencode-ip-pool/providers/{id}/config`
/// `POST /api/admin/opencode-ip-pool/providers/{id}/scan`
/// `POST /api/admin/opencode-ip-pool/providers/{id}/clean`
/// `POST /api/admin/opencode-ip-pool/providers/{id}/restore-original`
pub(super) fn classify_admin_opencode_ip_pool_routes(
    method: &http::Method,
    normalized_path: &str,
) -> Option<ClassifiedRoute> {
    if !normalized_path.starts_with(OPENCODE_IP_POOL_PATH_PREFIX) {
        return None;
    }
    let route_kind = if method == http::Method::GET {
        "get_opencode_ip_pool_status"
    } else if method == http::Method::PUT && normalized_path.ends_with("/config") {
        "save_opencode_ip_pool_config"
    } else if method == http::Method::POST && normalized_path.ends_with("/scan") {
        "run_opencode_ip_pool_scan"
    } else if method == http::Method::POST && normalized_path.ends_with("/clean") {
        "run_opencode_ip_pool_clean"
    } else if method == http::Method::POST && normalized_path.ends_with("/restore-original") {
        "restore_opencode_original_base_url"
    } else {
        return None;
    };
    Some(classified(
        "admin_proxy",
        "opencode_ip_pool_manage",
        route_kind,
        "admin:opencode_ip_pool",
        false,
    ))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn route_kind_of(method: &http::Method, path: &str) -> Option<String> {
        classify_admin_opencode_ip_pool_routes(method, path)
            .map(|route| route.route_kind.to_string())
    }

    #[test]
    fn classifies_all_opencode_ip_pool_routes() {
        let id = "8fa10a07-1d41-4f9e-ab32-68c9760caedd";
        let base = format!("/api/admin/opencode-ip-pool/providers/{id}");
        assert_eq!(
            route_kind_of(&http::Method::GET, &base).as_deref(),
            Some("get_opencode_ip_pool_status")
        );
        assert_eq!(
            route_kind_of(&http::Method::PUT, &format!("{base}/config")).as_deref(),
            Some("save_opencode_ip_pool_config")
        );
        assert_eq!(
            route_kind_of(&http::Method::POST, &format!("{base}/scan")).as_deref(),
            Some("run_opencode_ip_pool_scan")
        );
        assert_eq!(
            route_kind_of(&http::Method::POST, &format!("{base}/clean")).as_deref(),
            Some("run_opencode_ip_pool_clean")
        );
        assert_eq!(
            route_kind_of(&http::Method::POST, &format!("{base}/restore-original")).as_deref(),
            Some("restore_opencode_original_base_url")
        );
    }

    #[test]
    fn ignores_other_admin_paths_and_methods() {
        assert!(route_kind_of(&http::Method::GET, "/api/admin/providers").is_none());
        assert!(route_kind_of(
            &http::Method::DELETE,
            "/api/admin/opencode-ip-pool/providers/8fa10a07-1d41-4f9e-ab32-68c9760caedd"
        )
        .is_none());
    }
}
