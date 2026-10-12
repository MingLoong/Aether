//! Cline 上游地址常量。
//!
//! 两套写法都要留着，别合并：
//!
//! - [`CLINE_BASE_URL`] + [`CLINE_CHAT_CUSTOM_PATH`] 是**固定供应商模板**的写法：
//!   模板的 `base_url` 必须是完整 URL（裸域名过不了 `normalize_admin_base_url`，
//!   opencode 第一版就踩过这个坑），路径另放 `custom_path`。
//! - [`CLINE_API_BASE_URL`] 是**给非端点场景**（如模型清单）拼 URL 用的。

/// 固定模板的 `base_url`（必须以 `/` 结尾，与 `opencode` 模板一致）。
pub const CLINE_BASE_URL: &str = "https://api.cline.bot/";

/// 对话端点路径（拼在 `base_url` 之后）。
pub const CLINE_CHAT_CUSTOM_PATH: &str = "/api/v1/chat/completions";

/// 上游 API 根（不带尾斜杠），供模型清单等场景拼接。
pub const CLINE_API_BASE_URL: &str = "https://api.cline.bot/api/v1";

/// Cline 官方推荐模型清单，**无需鉴权**（实测 200）。
///
/// 返回 `{recommended, free, clinePass}` 三个数组，且清单每日可变 ——
/// 因此模型同步必须是实时拉取，不能硬编码。
pub const CLINE_RECOMMENDED_MODELS_URL: &str =
    "https://api.cline.bot/api/v1/ai/cline/recommended-models";

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn chat_url_is_absolute_and_matches_the_measured_endpoint() {
        let url = format!(
            "{}{}",
            CLINE_BASE_URL.trim_end_matches('/'),
            CLINE_CHAT_CUSTOM_PATH
        );
        assert_eq!(url, "https://api.cline.bot/api/v1/chat/completions");
        assert_eq!(
            url,
            format!("{CLINE_API_BASE_URL}/chat/completions"),
            "两种写法必须指向同一地址"
        );
    }

    #[test]
    fn recommended_models_url_is_under_the_api_base() {
        assert!(CLINE_RECOMMENDED_MODELS_URL.starts_with(CLINE_API_BASE_URL));
        assert_eq!(
            CLINE_RECOMMENDED_MODELS_URL,
            "https://api.cline.bot/api/v1/ai/cline/recommended-models"
        );
    }
}
