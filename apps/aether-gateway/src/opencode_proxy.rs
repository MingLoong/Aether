//! OpenCode 前置代理的**请求路径**目标改写。
//!
//! 设计约束（来自产品需求，改动时勿破坏）：
//! - 端点 `base_url` **永远**是真实上游，任何开关都不许回写端点。
//! - 「启用前置代理」只决定**这一次请求**用哪个 host：
//!   开启且填了域名 → 用该域名；否则 → 用默认官方域名。
//! - 官方域名（`opencode.ai`）绝不能套 CDN IP 锚点，见
//!   `aether_provider_transport::opencode::opencode_dns_pin`。
//!
//! 规划器（真实请求）、模型列表拉取、模型测试都必须走这里，
//! 否则管理端会绕过代理直连官方，看起来就像「开关没生效」。

use serde_json::Value;

/// 从 `provider.config.opencode_scan` 读出「本次请求该用的 host」。
///
/// 返回 `None` 表示按端点里配置的上游走（不改写）。
pub(crate) fn front_proxy_domain(provider_config: Option<&Value>) -> Option<String> {
    let section = provider_config?.get("opencode_scan")?;
    if !section
        .get("proxy_enabled")
        .and_then(Value::as_bool)
        .unwrap_or(false)
    {
        return None;
    }
    let domain = section
        .get("proxy_domain")
        .and_then(Value::as_str)
        .map(str::trim)
        .filter(|value| !value.is_empty())?;
    // 填了官方域名等于没开代理，不改写。
    if domain.eq_ignore_ascii_case(aether_provider_transport::opencode::OPENCODE_ORIGINAL_DOMAIN) {
        return None;
    }
    Some(domain.to_string())
}

/// 把 transport 的目标 host 换成前置代理域名。
///
/// 解析失败或换 host 失败时**保持原样**，绝不能把请求打到一个非法地址上。
pub(crate) fn apply_front_proxy_domain(
    transport: &mut aether_provider_transport::GatewayProviderTransportSnapshot,
    provider_config: Option<&Value>,
) -> bool {
    let Some(domain) = front_proxy_domain(provider_config) else {
        return false;
    };
    let Ok(mut url) = url::Url::parse(transport.endpoint.base_url.trim()) else {
        return false;
    };
    if url.set_host(Some(domain.as_str())).is_err() {
        return false;
    }
    transport.endpoint.base_url = url.to_string();
    true
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn cfg(enabled: bool, domain: &str) -> Value {
        json!({ "opencode_scan": { "proxy_enabled": enabled, "proxy_domain": domain } })
    }

    #[test]
    fn disabled_switch_yields_no_domain() {
        assert_eq!(
            front_proxy_domain(Some(&cfg(false, "cdn.example.com"))),
            None
        );
    }

    #[test]
    fn enabled_with_domain_yields_that_domain() {
        assert_eq!(
            front_proxy_domain(Some(&cfg(true, " cdn.example.com "))).as_deref(),
            Some("cdn.example.com")
        );
    }

    #[test]
    fn enabled_without_domain_yields_none() {
        assert_eq!(front_proxy_domain(Some(&cfg(true, "   "))), None);
    }

    #[test]
    fn official_domain_is_treated_as_disabled() {
        assert_eq!(front_proxy_domain(Some(&cfg(true, "opencode.ai"))), None);
        assert_eq!(front_proxy_domain(Some(&cfg(true, "OpenCode.AI"))), None);
    }

    #[test]
    fn missing_section_yields_none() {
        assert_eq!(front_proxy_domain(Some(&json!({}))), None);
        assert_eq!(front_proxy_domain(None), None);
    }
}
