use axum::http;

use super::{classified, ClassifiedRoute};

const AMD_LOAD_PATH_PREFIX: &str = "/api/admin/amd-load/providers/";

/// Classifies the AMD model-load admin routes:
/// `GET  /api/admin/amd-load/providers/{id}`           快照 + 生效配置 + 判定结果
/// `PUT  /api/admin/amd-load/providers/{id}/config`    保存阈值与轮询配置
/// `POST /api/admin/amd-load/providers/{id}/refresh`   立刻拉一次负载快照
///
/// 刻意不解析 `{id}`，也不校验它的长度。opencode 那个分类器下游的
/// `opencode_ip_pool_provider_id` 强制 id 长度必须等于 36，而整条处理链取不到路由
/// 时只会返回一个 501——症状看起来像「接口没实现」，真因却是 id 不合长度。同目录的
/// 其他路径解析器都没有这个限制，这里也不要有：id 的形状该由取 provider 的那层负责，
/// 分类器只做前缀与后缀匹配。
pub(super) fn classify_admin_amd_load_routes(
    method: &http::Method,
    normalized_path: &str,
) -> Option<ClassifiedRoute> {
    if !normalized_path.starts_with(AMD_LOAD_PATH_PREFIX) {
        return None;
    }
    let route_kind = if method == http::Method::GET {
        "get_amd_load_status"
    } else if method == http::Method::PUT && normalized_path.ends_with("/config") {
        "save_amd_load_config"
    } else if method == http::Method::POST && normalized_path.ends_with("/refresh") {
        "refresh_amd_load_snapshot"
    } else {
        return None;
    };
    Some(classified(
        "admin_proxy",
        "amd_load_manage",
        route_kind,
        "admin:amd_load",
        false,
    ))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn route_kind_of(method: &http::Method, path: &str) -> Option<String> {
        classify_admin_amd_load_routes(method, path).map(|route| route.route_kind.to_string())
    }

    #[test]
    fn classifies_all_amd_load_routes() {
        let id = "8fa10a07-1d41-4f9e-ab32-68c9760caedd";
        let base = format!("/api/admin/amd-load/providers/{id}");
        assert_eq!(
            route_kind_of(&http::Method::GET, &base).as_deref(),
            Some("get_amd_load_status")
        );
        assert_eq!(
            route_kind_of(&http::Method::PUT, &format!("{base}/config")).as_deref(),
            Some("save_amd_load_config")
        );
        assert_eq!(
            route_kind_of(&http::Method::POST, &format!("{base}/refresh")).as_deref(),
            Some("refresh_amd_load_snapshot")
        );
    }

    /// 分类器不校验 id 形状：任何非空 id 都应命中。
    ///
    /// 这一条是刻意写的回归。opencode 那边因为 id 长度必须等于 36，导致同一条路径在
    /// 别的 id 形态下整条链返回 501，看起来像「没实现」。这里锁死「不解析 id」。
    #[test]
    fn classifies_regardless_of_provider_id_shape() {
        for id in ["short-id", "not-a-uuid-at-all-but-still-fine", "x"] {
            let base = format!("/api/admin/amd-load/providers/{id}");
            assert_eq!(
                route_kind_of(&http::Method::GET, &base).as_deref(),
                Some("get_amd_load_status"),
                "id={id} 应被接受"
            );
        }
    }

    #[test]
    fn ignores_other_paths_and_methods() {
        assert!(route_kind_of(&http::Method::GET, "/api/admin/providers").is_none());
        assert!(route_kind_of(
            &http::Method::DELETE,
            "/api/admin/amd-load/providers/8fa10a07-1d41-4f9e-ab32-68c9760caedd"
        )
        .is_none());
        // 前缀相同但后缀不认识
        assert!(route_kind_of(
            &http::Method::POST,
            "/api/admin/amd-load/providers/8fa10a07-1d41-4f9e-ab32-68c9760caedd/unknown"
        )
        .is_none());
        // opencode 的路径不能被本分类器抢走
        assert!(route_kind_of(
            &http::Method::GET,
            "/api/admin/opencode-ip-pool/providers/8fa10a07-1d41-4f9e-ab32-68c9760caedd"
        )
        .is_none());
    }
}
