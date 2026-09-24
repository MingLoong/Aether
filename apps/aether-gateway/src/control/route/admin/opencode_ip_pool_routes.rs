use axum::http;

use super::{classified, ClassifiedRoute};

/// Classifies OpenCode IP-pool management routes.
///
/// `GET  /api/admin/opencode-ip-pool/providers/{id}`        → status + config
/// `PUT  /api/admin/opencode-ip-pool/providers/{id}/config` → save config
/// `POST /api/admin/opencode-ip-pool/providers/{id}/scan`   → run scan
/// `POST /api/admin/opencode-ip-pool/providers/{id}/clean`  → run clean
pub(super) fn classify_admin_opencode_ip_pool_routes(
    method: &http::Method,
    normalized_path: &str,
) -> Option<ClassifiedRoute> {
    if method == http::Method::GET
        && normalized_path.starts_with("/api/admin/opencode-ip-pool/providers/")
        && normalized_path.matches('/').count() == 5
    {
        Some(classified(
            "admin_proxy",
            "opencode_ip_pool_manage",
            "get_opencode_ip_pool_status",
            "admin:providers",
            false,
        ))
    } else if method == http::Method::PUT
        && normalized_path.starts_with("/api/admin/opencode-ip-pool/providers/")
        && normalized_path.ends_with("/config")
        && normalized_path.matches('/').count() == 6
    {
        Some(classified(
            "admin_proxy",
            "opencode_ip_pool_manage",
            "save_opencode_ip_pool_config",
            "admin:providers",
            false,
        ))
    } else if method == http::Method::POST
        && normalized_path.starts_with("/api/admin/opencode-ip-pool/providers/")
        && normalized_path.ends_with("/scan")
        && normalized_path.matches('/').count() == 6
    {
        Some(classified(
            "admin_proxy",
            "opencode_ip_pool_manage",
            "run_opencode_ip_pool_scan",
            "admin:providers",
            false,
        ))
    } else if method == http::Method::POST
        && normalized_path.starts_with("/api/admin/opencode-ip-pool/providers/")
        && normalized_path.ends_with("/restore-original")
        && normalized_path.matches('/').count() == 6
    {
        Some(classified(
            "admin_proxy",
            "opencode_ip_pool_manage",
            "restore_opencode_original_base_url",
            "admin:providers",
            false,
        ))
    } else if method == http::Method::POST
        && normalized_path.starts_with("/api/admin/opencode-ip-pool/providers/")
        && normalized_path.ends_with("/clean")
        && normalized_path.matches('/').count() == 6
    {
        Some(classified(
            "admin_proxy",
            "opencode_ip_pool_manage",
            "run_opencode_ip_pool_clean",
            "admin:providers",
            false,
        ))
    } else {
        None
    }
}
