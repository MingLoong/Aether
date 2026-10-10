use axum::http;

use super::{classified, ClassifiedRoute};

const OPENCODE_IP_POOL_PATH_PREFIX: &str = "/api/admin/opencode-ip-pool/providers/";

/// Classifies the OpenCode front-proxy IP pool admin routes:
/// `GET  /api/admin/opencode-ip-pool/providers/{id}`
/// `PUT  /api/admin/opencode-ip-pool/providers/{id}/config`
/// `POST /api/admin/opencode-ip-pool/providers/{id}/scan`
/// `POST /api/admin/opencode-ip-pool/providers/{id}/verify`
/// `POST /api/admin/opencode-ip-pool/providers/{id}/clean`
/// `POST /api/admin/opencode-ip-pool/providers/{id}/restore-original`
/// `POST /api/admin/opencode-ip-pool/providers/{id}/pool/ips/block`
/// `POST /api/admin/opencode-ip-pool/providers/{id}/pool/ips/unblock`
/// `POST /api/admin/opencode-ip-pool/providers/{id}/abnormal/reset`
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
    } else if method == http::Method::POST && normalized_path.ends_with("/verify") {
        "run_opencode_ip_pool_verify"
    } else if method == http::Method::POST && normalized_path.ends_with("/clean") {
        "run_opencode_ip_pool_clean"
    } else if method == http::Method::POST && normalized_path.ends_with("/restore-original") {
        "restore_opencode_original_base_url"
    } else if method == http::Method::POST && normalized_path.ends_with("/pool/ips/add") {
        "add_opencode_exit_ip"
    } else if method == http::Method::POST && normalized_path.ends_with("/pool/ips/remove") {
        "remove_opencode_exit_ip"
    } else if method == http::Method::POST && normalized_path.ends_with("/pool/ips/update") {
        "update_opencode_exit_ip"
    } else if method == http::Method::POST && normalized_path.ends_with("/pool/ips/toggle") {
        "toggle_opencode_exit_ip"
    } else if method == http::Method::POST && normalized_path.ends_with("/pool/ips/block") {
        "block_opencode_exit_ip"
    } else if method == http::Method::POST && normalized_path.ends_with("/pool/ips/unblock") {
        "unblock_opencode_exit_ip"
    } else if method == http::Method::POST && normalized_path.ends_with("/abnormal/reset") {
        "reset_opencode_abnormal_ips"
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
            route_kind_of(&http::Method::POST, &format!("{base}/verify")).as_deref(),
            Some("run_opencode_ip_pool_verify")
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
    fn classifies_provider_level_exit_ip_routes() {
        let id = "8fa10a07-1d41-4f9e-ab32-68c9760caedd";
        let base = format!("/api/admin/opencode-ip-pool/providers/{id}");
        assert_eq!(
            route_kind_of(&http::Method::POST, &format!("{base}/pool/ips/add")).as_deref(),
            Some("add_opencode_exit_ip")
        );
        assert_eq!(
            route_kind_of(&http::Method::POST, &format!("{base}/pool/ips/remove")).as_deref(),
            Some("remove_opencode_exit_ip")
        );
        assert_eq!(
            route_kind_of(&http::Method::POST, &format!("{base}/pool/ips/update")).as_deref(),
            Some("update_opencode_exit_ip")
        );
        assert_eq!(
            route_kind_of(&http::Method::POST, &format!("{base}/pool/ips/toggle")).as_deref(),
            Some("toggle_opencode_exit_ip")
        );
    }

    #[test]
    fn classifies_abnormal_pool_routes() {
        let id = "8fa10a07-1d41-4f9e-ab32-68c9760caedd";
        let base = format!("/api/admin/opencode-ip-pool/providers/{id}");
        assert_eq!(
            route_kind_of(&http::Method::POST, &format!("{base}/pool/ips/block")).as_deref(),
            Some("block_opencode_exit_ip")
        );
        assert_eq!(
            route_kind_of(&http::Method::POST, &format!("{base}/pool/ips/unblock")).as_deref(),
            Some("unblock_opencode_exit_ip")
        );
        assert_eq!(
            route_kind_of(&http::Method::POST, &format!("{base}/abnormal/reset")).as_deref(),
            Some("reset_opencode_abnormal_ips")
        );
        // 别把整体的 /verify 抢走：新路径都不以它结尾。
        assert_eq!(
            route_kind_of(&http::Method::POST, &format!("{base}/verify")).as_deref(),
            Some("run_opencode_ip_pool_verify")
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
