//! Cline 客户端的指纹头。
//!
//! 上游按这些头判断"请求来自 Cline 产品面"。实测（2026-10-12）：
//!
//! | 下发的头 | 结果 |
//! |---|---|
//! | 只带 `User-Agent: Cline/3.0.47` | **403** `only available via Cline product surfaces` |
//! | 只带 `x-client-type: cline-cli` | **200** |
//! | 全套指纹 | **200** |
//!
//! 结论：闸门是 `x-client-type`，但这里仍按**全套**下发 —— 与真实 Cline IDE
//! 一致，最不容易被上游后续收紧打中；代价只是几个常量。
//!
//! 版本号会随 Cline 发版变化，故意集中在本文件，便于一处更新（同
//! `kiro/headers.rs` 里 `AWS_SDK_JS_MAIN_VERSION` 的做法）。

use std::collections::BTreeMap;

pub const CLINE_CLIENT_TYPE_HEADER: &str = "x-client-type";
pub const CLINE_TASK_ID_HEADER: &str = "x-task-id";

/// `x-client-type` 的取值。实测 `cline-cli` 与 `cline-sdk` 都能过闸门；
/// 取 `cline-sdk` 与 `luawei1/cline2api` 的真实客户端一致。
pub const CLINE_CLIENT_TYPE: &str = "cline-sdk";
pub const CLINE_USER_AGENT: &str = "Cline/3.0.47";
pub const CLINE_CLIENT_VERSION: &str = "3.0.47";
pub const CLINE_PLATFORM: &str = "terminal";
pub const CLINE_PLATFORM_VERSION: &str = "3.0.47";
pub const CLINE_CORE_VERSION: &str = "0.0.66";
pub const CLINE_REFERER: &str = "https://cline.bot";
pub const CLINE_TITLE: &str = "Cline";
pub const CLINE_IS_MULTIROOT: &str = "false";

/// 除 `x-task-id` 外的固定指纹头（键全部小写，与上游头的比较语义一致）。
pub const CLINE_IDENTITY_HEADERS: &[(&str, &str)] = &[
    (CLINE_CLIENT_TYPE_HEADER, CLINE_CLIENT_TYPE),
    ("user-agent", CLINE_USER_AGENT),
    ("http-referer", CLINE_REFERER),
    ("x-title", CLINE_TITLE),
    ("x-is-multiroot", CLINE_IS_MULTIROOT),
    ("x-client-version", CLINE_CLIENT_VERSION),
    ("x-platform", CLINE_PLATFORM),
    ("x-platform-version", CLINE_PLATFORM_VERSION),
    ("x-core-version", CLINE_CORE_VERSION),
];

fn current_unix_millis() -> u128 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|duration| duration.as_millis())
        .unwrap_or(0)
}

/// 每次请求一条 `sess_<毫秒>`，与真实 Cline 客户端一致（`X-Task-ID`）。
pub fn build_cline_task_id() -> String {
    format!("sess_{}", current_unix_millis())
}

pub fn build_cline_identity_headers() -> BTreeMap<String, String> {
    let mut headers: BTreeMap<String, String> = CLINE_IDENTITY_HEADERS
        .iter()
        .map(|(name, value)| ((*name).to_string(), (*value).to_string()))
        .collect();
    headers.insert(CLINE_TASK_ID_HEADER.to_string(), build_cline_task_id());
    headers
}

/// 把指纹头写进已构建的上游头表。
///
/// 语义是**覆盖**：客户端自带的 `user-agent`、运营者手配的同名头都不该
/// 顶掉产品面标识，否则请求会被上游 403。
pub fn apply_cline_identity_headers(headers: &mut BTreeMap<String, String>) {
    for (name, value) in build_cline_identity_headers() {
        headers.insert(name, value);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn identity_headers_are_lowercase_and_complete() {
        let headers = build_cline_identity_headers();
        for (name, _) in CLINE_IDENTITY_HEADERS {
            assert_eq!(name, &name.to_ascii_lowercase());
            assert!(headers.contains_key(*name), "missing {name}");
        }
        assert_eq!(headers.len(), CLINE_IDENTITY_HEADERS.len() + 1);
    }

    #[test]
    fn task_id_uses_the_session_prefix() {
        let task_id = build_cline_task_id();
        assert!(
            task_id.starts_with("sess_"),
            "unexpected task id: {task_id}"
        );
        assert!(task_id["sess_".len()..].chars().all(|c| c.is_ascii_digit()));
    }

    #[test]
    fn apply_overrides_client_supplied_identity_headers() {
        let mut headers = BTreeMap::from([
            ("user-agent".to_string(), "curl/8.0".to_string()),
            (
                CLINE_CLIENT_TYPE_HEADER.to_string(),
                "some-other-client".to_string(),
            ),
            ("authorization".to_string(), "Bearer sk_test".to_string()),
        ]);
        apply_cline_identity_headers(&mut headers);
        assert_eq!(
            headers.get("user-agent").map(String::as_str),
            Some(CLINE_USER_AGENT)
        );
        assert_eq!(
            headers.get(CLINE_CLIENT_TYPE_HEADER).map(String::as_str),
            Some(CLINE_CLIENT_TYPE)
        );
        assert_eq!(
            headers.get("authorization").map(String::as_str),
            Some("Bearer sk_test")
        );
    }
}
