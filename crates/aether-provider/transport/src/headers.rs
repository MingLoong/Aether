use std::collections::{BTreeMap, BTreeSet};

use aether_contracts::USAGE_SERVER_NOW_UNIX_MS_HEADER;

/// Return the case-insensitive field names nominated by all `Connection`
/// header values in a request.  Those fields are hop-by-hop even when their
/// names are application-defined and therefore must not cross to a provider.
pub(crate) fn declared_connection_header_names(
    headers: &http::HeaderMap,
    extra_headers: &BTreeMap<String, String>,
) -> BTreeSet<String> {
    let mut values = headers
        .get_all(http::header::CONNECTION)
        .iter()
        .filter_map(|value| value.to_str().ok())
        .collect::<Vec<_>>();
    values.extend(
        extra_headers
            .iter()
            .filter(|(name, _)| name.eq_ignore_ascii_case(http::header::CONNECTION.as_str()))
            .map(|(_, value)| value.as_str()),
    );
    aether_http::connection_declared_header_names(values)
}

pub(crate) fn is_declared_connection_header(
    name: &str,
    declared_connection_headers: &BTreeSet<String>,
) -> bool {
    declared_connection_headers.contains(&name.trim().to_ascii_lowercase())
}

const UPSTREAM_CREDENTIAL_HEADER_NAMES: &[&str] = &[
    "authorization",
    "proxy-authorization",
    "api-key",
    "x-api-key",
    "x-goog-api-key",
    "cookie",
    "cookie2",
    "set-cookie",
];

pub(crate) fn upstream_credential_header_names() -> &'static [&'static str] {
    UPSTREAM_CREDENTIAL_HEADER_NAMES
}

pub(crate) fn is_upstream_credential_header(name: &str) -> bool {
    let name = name.trim();
    UPSTREAM_CREDENTIAL_HEADER_NAMES
        .iter()
        .any(|candidate| name.eq_ignore_ascii_case(candidate))
}

pub(crate) fn is_aether_internal_header(name: &str) -> bool {
    name.trim().to_ascii_lowercase().starts_with("x-aether-")
}

pub fn should_skip_request_header(name: &str) -> bool {
    let normalized = name.to_ascii_lowercase();
    if is_aether_internal_header(&normalized)
        || is_untrusted_forwarding_metadata_header(&normalized)
        || is_untrusted_routing_override_header(&normalized)
    {
        return true;
    }
    matches!(
        normalized.as_str(),
        "connection"
            | "keep-alive"
            | "proxy-authenticate"
            | "proxy-authorization"
            | "proxy-connection"
            | "te"
            | "trailer"
            | "transfer-encoding"
            | "upgrade"
            | "set-cookie"
            | USAGE_SERVER_NOW_UNIX_MS_HEADER
    )
}

fn is_untrusted_forwarding_metadata_header(normalized_name: &str) -> bool {
    matches!(normalized_name, "forwarded" | "via" | "x-envoy-internal")
        || normalized_name.starts_with("x-forwarded-")
        || normalized_name.starts_with("x_forwarded_")
        || normalized_name.starts_with("x-real-")
        || normalized_name.starts_with("x_real_")
        || is_edge_or_client_ip_metadata_header(normalized_name)
        || is_middleware_client_fingerprint_header(normalized_name)
}

/// 边缘/CDN 注入的元数据，以及「把客户端真实 IP 告诉后端」的那类头。
///
/// 直连上游的真实客户端**不会带**这些：要么是 CDN/反代在边缘加上的（腾讯 EdgeOne
/// `eo-*`、Cloudflare `cf-*`、AWS `x-amzn-*` / `x-amz-cf-*`、Vercel / Akamai /
/// Fastly / Azure 各家前缀），要么是显式转发客户端地址的头。
///
/// 带上去等于一次交出三样东西：① 我们这一跳的存在（代理指纹）② 客户端真实 IP
/// ③ CDN 的日志关联 id。现场样本（2026-10-16 抓包）里就带着
/// `eo-connecting-ip: 223.104.88.13` 与 `eo-log-uuid` —— 那是 EdgeOne 在边缘
/// 注入的，客户端自己都不知道有这两个头。
///
/// opencode 这类对客户端指纹敏感的上游更会因此改变判定：实测多带一个客户端遗留头
/// 就返回 403 FreeTierError，所以「像不像原生客户端」在这里是功能问题，不只是隐私问题。
fn is_edge_or_client_ip_metadata_header(normalized_name: &str) -> bool {
    const CLIENT_IP_HEADER_NAMES: &[&str] = &[
        "true-client-ip",
        "x-client-ip",
        "x-cluster-client-ip",
        "proxy-client-ip",
        "wl-proxy-client-ip",
        "fastly-client-ip",
        "x-originating-ip",
        "x-remote-ip",
        "x-remote-addr",
        "x-proxyuser-ip",
        "incap-client-ip",
    ];
    const EDGE_METADATA_PREFIXES: &[&str] = &[
        // 腾讯 EdgeOne：eo-connecting-ip / eo-log-uuid / ...
        "eo-",
        // Cloudflare：cf-connecting-ip / cf-ray / cf-ipcountry / ...
        "cf-",
        "x-amz-cf-",
        "x-amzn-",
        // 其它常见边缘与 CDN
        "x-vercel-",
        "akamai-",
        "x-akamai-",
        "x-fastly-",
        "x-azure-",
        "x-cdn-",
        "x-edge-",
        "x-served-by",
        "x-cache",
    ];
    CLIENT_IP_HEADER_NAMES.contains(&normalized_name)
        || EDGE_METADATA_PREFIXES
            .iter()
            .any(|prefix| normalized_name.starts_with(prefix))
}

/// 只有「网关/中间层客户端」才会带、而上游协议完全不需要的头。
///
/// - `x-deepseek-harness-*`：本机客户端（DSH）的会话与用户标识，属于我们自己的链路信息；
/// - `sec-fetch-*`：浏览器安全上下文元数据，命令行客户端根本不会发。
///
/// 直连上游的原生客户端不会有它们，留着只会让上游看到「这不是原生客户端」——
/// 生产实测（2026-10-16，`usage_http_audits`）：这两类头此前被原样转发给了上游
/// （`sec-fetch-mode` 6849 条、`x-deepseek-harness-session-id` 6501 条），
/// 而同一批请求里的 `x-forwarded-*` / `x-real-ip` 是 0 条 —— 说明既有名单生效，
/// 只是这两类不在名单里。
///
/// 注意：`x-stainless-*` / `anthropic-*` **刻意不在这里**。它们由
/// [`should_skip_upstream_passthrough_header`] 按路径决定（complete passthrough 上
/// `anthropic-beta` / `x-stainless-runtime-version` 是既有契约要保留的"业务头"，
/// 见 `auth.rs` 的 `complete_passthrough_headers_preserve_business_headers`）。
/// 是否要让 opencode 也去掉 `x-stainless-*`，属于单独的决策，不在本次改动里。
fn is_middleware_client_fingerprint_header(normalized_name: &str) -> bool {
    normalized_name.starts_with("x-deepseek-harness-")
        || normalized_name.starts_with("x-harness-")
        || normalized_name.starts_with("sec-fetch-")
}

fn is_untrusted_routing_override_header(normalized_name: &str) -> bool {
    matches!(
        normalized_name,
        "x-http-method"
            | "x-http-method-override"
            | "x-method-override"
            | "x-override-url"
            | "x-rewrite-url"
    ) || normalized_name.starts_with("x-original-")
        || normalized_name.starts_with("x_original_")
        || normalized_name.starts_with("x-envoy-original-")
}

pub fn should_skip_upstream_passthrough_header(name: &str) -> bool {
    let lower = name.to_ascii_lowercase();
    // Anthropic SDK (stainless) client metadata and Anthropic-specific headers
    // (anthropic-version / anthropic-beta / anthropic-dangerous-direct-browser-access / ...).
    // These are only meaningful when the upstream is Anthropic. The Claude Code
    // adapter re-reads what it needs directly from the original HeaderMap and
    // injects its own values *after* this filter runs, so stripping both prefixes
    // here prevents leakage to any other upstream (OpenAI/Gemini/Codex/...).
    if lower.starts_with("x-stainless-") || lower.starts_with("anthropic-") {
        return true;
    }
    is_upstream_credential_header(&lower)
        || matches!(
            lower.as_str(),
            "host"
            | "content-length"
            | "transfer-encoding"
            | "connection"
            | "content-encoding"
            | "x-real-ip"
            | "x-real-proto"
            | "x-forwarded-for"
            | "x-forwarded-proto"
            | "x-forwarded-scheme"
            | "x-forwarded-host"
            | "x-forwarded-port"
            // Claude CLI client identifier; re-injected by the Claude Code adapter
            // when the upstream is Anthropic, filtered for everybody else.
            | "x-app"
        )
        || should_skip_request_header(name)
}

pub(crate) fn should_skip_upstream_passthrough_header_with_connection(
    name: &str,
    declared_connection_headers: &BTreeSet<String>,
) -> bool {
    should_skip_upstream_passthrough_header(name)
        || is_declared_connection_header(name, declared_connection_headers)
}

pub(crate) fn should_skip_upstream_complete_passthrough_header(name: &str) -> bool {
    let lower = name.to_ascii_lowercase();
    is_upstream_credential_header(&lower)
        || matches!(
            lower.as_str(),
            "host"
                | "content-length"
                | "transfer-encoding"
                | "connection"
                | "content-encoding"
                | "x-real-ip"
                | "x-real-proto"
                | "x-forwarded-for"
                | "x-forwarded-proto"
                | "x-forwarded-scheme"
                | "x-forwarded-host"
                | "x-forwarded-port"
        )
        || should_skip_request_header(name)
}

pub(crate) fn should_skip_upstream_complete_passthrough_header_with_connection(
    name: &str,
    declared_connection_headers: &BTreeSet<String>,
) -> bool {
    should_skip_upstream_complete_passthrough_header(name)
        || is_declared_connection_header(name, declared_connection_headers)
}

pub(crate) fn remove_declared_connection_headers(
    headers: &mut BTreeMap<String, String>,
    declared_connection_headers: &BTreeSet<String>,
) {
    let mut all_declared = declared_connection_headers.clone();
    let connection_values = headers
        .iter()
        .filter(|(name, _)| name.eq_ignore_ascii_case("connection"))
        .map(|(_, value)| value.as_str())
        .collect::<Vec<_>>();
    all_declared.extend(aether_http::connection_declared_header_names(
        connection_values,
    ));
    headers.retain(|name, _| {
        !name.eq_ignore_ascii_case("connection")
            && !name.eq_ignore_ascii_case("x-envoy-internal")
            && !is_declared_connection_header(name, &all_declared)
    });
}

pub fn normalize_upstream_accept_encoding(value: &str) -> Option<String> {
    let mut accepted = Vec::new();
    let mut wildcard_allowed = false;
    let mut gzip_disabled = false;
    let mut deflate_disabled = false;
    let mut identity_disabled = false;

    for item in value.split(',') {
        let Some((token, normalized_item, enabled)) = parse_accept_encoding_item(item) else {
            continue;
        };
        match token.as_str() {
            "gzip" if enabled => accepted.push(normalized_item),
            "gzip" => gzip_disabled = true,
            "deflate" if enabled => accepted.push(normalized_item),
            "deflate" => deflate_disabled = true,
            "identity" if enabled => accepted.push(normalized_item),
            "identity" => identity_disabled = true,
            "*" if enabled => wildcard_allowed = true,
            _ => {}
        }
    }

    if !accepted.is_empty() {
        return Some(accepted.join(", "));
    }

    if wildcard_allowed && !gzip_disabled {
        Some("gzip".to_string())
    } else if wildcard_allowed && !deflate_disabled {
        Some("deflate".to_string())
    } else if wildcard_allowed && !identity_disabled {
        Some("identity".to_string())
    } else {
        None
    }
}

fn parse_accept_encoding_item(raw_item: &str) -> Option<(String, String, bool)> {
    let mut parts = raw_item.trim().split(';');
    let token = parts.next()?.trim().to_ascii_lowercase();
    if token.is_empty() {
        return None;
    }

    let mut enabled = true;
    let mut normalized = token.clone();
    for raw_param in parts {
        let param = raw_param.trim();
        if param.is_empty() {
            continue;
        }
        let Some((name, value)) = param.split_once('=') else {
            continue;
        };
        if name.trim().eq_ignore_ascii_case("q") {
            let value = value.trim();
            if q_value_is_zero(value) {
                enabled = false;
                continue;
            }
            normalized.push_str(";q=");
            normalized.push_str(value);
        }
    }

    Some((token, normalized, enabled))
}

fn q_value_is_zero(value: &str) -> bool {
    value
        .trim_matches('"')
        .parse::<f32>()
        .is_ok_and(|q| q <= 0.0)
}

pub fn force_identity_accept_encoding(headers: &mut BTreeMap<String, String>) {
    if let Some(existing_key) = headers
        .keys()
        .find(|key| key.eq_ignore_ascii_case("accept-encoding"))
        .cloned()
    {
        headers.remove(&existing_key);
    }
    headers.insert("accept-encoding".to_string(), "identity".to_string());
}

#[cfg(test)]
mod tests {
    use super::{
        force_identity_accept_encoding, is_upstream_credential_header,
        normalize_upstream_accept_encoding, should_skip_request_header,
        should_skip_upstream_complete_passthrough_header, should_skip_upstream_passthrough_header,
    };
    use aether_contracts::USAGE_SERVER_NOW_UNIX_MS_HEADER;
    use std::collections::BTreeMap;

    #[test]
    fn strips_all_stainless_headers() {
        let stainless = [
            "x-stainless-arch",
            "x-stainless-lang",
            "x-stainless-os",
            "x-stainless-package-version",
            "x-stainless-retry-count",
            "x-stainless-runtime",
            "x-stainless-runtime-version",
            "x-stainless-timeout",
            "x-stainless-helper-method",
            "X-Stainless-Arch",
            "X-STAINLESS-FUTURE-HEADER",
        ];
        for h in stainless {
            assert!(
                should_skip_upstream_passthrough_header(h),
                "should skip {h}"
            );
        }
    }

    #[test]
    fn accept_encoding_is_not_classified_as_hop_by_hop_passthrough_skip() {
        assert!(!should_skip_upstream_passthrough_header("accept-encoding"));
        assert!(!should_skip_upstream_complete_passthrough_header(
            "accept-encoding"
        ));
    }

    #[test]
    fn normalizes_accept_encoding_to_supported_upstream_codecs() {
        assert_eq!(
            normalize_upstream_accept_encoding("gzip, br").as_deref(),
            Some("gzip")
        );
        assert_eq!(
            normalize_upstream_accept_encoding("br, deflate").as_deref(),
            Some("deflate")
        );
        assert_eq!(
            normalize_upstream_accept_encoding("identity").as_deref(),
            Some("identity")
        );
        assert_eq!(
            normalize_upstream_accept_encoding("gzip;q=0.5, br").as_deref(),
            Some("gzip;q=0.5")
        );
        assert_eq!(
            normalize_upstream_accept_encoding("gzip;q=0, br, deflate").as_deref(),
            Some("deflate")
        );
        assert_eq!(
            normalize_upstream_accept_encoding("gzip;q=0, br").as_deref(),
            None
        );
        assert_eq!(
            normalize_upstream_accept_encoding("*").as_deref(),
            Some("gzip")
        );
        assert_eq!(normalize_upstream_accept_encoding("br"), None);
    }

    #[test]
    fn force_identity_accept_encoding_replaces_existing_casing() {
        let mut headers = BTreeMap::from([("Accept-Encoding".to_string(), "gzip".to_string())]);

        force_identity_accept_encoding(&mut headers);

        assert_eq!(
            headers.get("accept-encoding").map(String::as_str),
            Some("identity")
        );
        assert!(!headers.contains_key("Accept-Encoding"));
    }

    #[test]
    fn strips_anthropic_and_claude_cli_identity_headers() {
        let anthropic = [
            "anthropic-version",
            "anthropic-beta",
            "anthropic-dangerous-direct-browser-access",
            "Anthropic-Version",
            "ANTHROPIC-FUTURE-HEADER",
            "x-app",
            "X-App",
        ];
        for h in anthropic {
            assert!(
                should_skip_upstream_passthrough_header(h),
                "should skip {h}"
            );
        }
    }

    #[test]
    fn strips_all_client_credential_carriers_from_passthrough() {
        for header in [
            "authorization",
            "proxy-authorization",
            "api-key",
            "x-api-key",
            "x-goog-api-key",
            "cookie",
            "cookie2",
            "set-cookie",
            "Authorization",
            "COOKIE",
        ] {
            assert!(is_upstream_credential_header(header), "credential {header}");
            assert!(
                should_skip_upstream_passthrough_header(header),
                "normal passthrough should strip {header}"
            );
            assert!(
                should_skip_upstream_complete_passthrough_header(header),
                "complete passthrough should strip {header}"
            );
        }
    }

    #[test]
    fn strips_all_aether_owned_headers_from_provider_requests() {
        for header in [
            "x-aether-gateway",
            "x-aether-auth-user-id",
            "x-aether-auth-api-key-id",
            "x-aether-auth-balance-remaining",
            "X-Aether-Tunnel-Forwarded-By",
        ] {
            assert!(should_skip_request_header(header));
            assert!(should_skip_upstream_passthrough_header(header));
            assert!(should_skip_upstream_complete_passthrough_header(header));
        }
    }

    #[test]
    fn strips_all_client_supplied_forwarding_metadata() {
        for header in [
            "Forwarded",
            "Via",
            "X-Forwarded-For",
            "X-Forwarded-Host",
            "X-Forwarded-Prefix",
            "X-Forwarded-Server",
            "x_forwarded_for",
            "X-Real-IP",
            "X-Real-Host",
            "x_real_ip",
        ] {
            assert!(should_skip_request_header(header));
            assert!(should_skip_upstream_passthrough_header(header));
            assert!(should_skip_upstream_complete_passthrough_header(header));
        }
    }

    #[test]
    fn strips_client_supplied_upstream_routing_overrides() {
        for header in [
            "X-HTTP-Method-Override",
            "X-Method-Override",
            "X-Original-URL",
            "X-Original-URI",
            "x_original_url",
            "X-Rewrite-URL",
            "X-Override-URL",
            "X-Envoy-Original-Path",
            "X-Envoy-Internal",
        ] {
            assert!(should_skip_request_header(header));
            assert!(should_skip_upstream_passthrough_header(header));
            assert!(should_skip_upstream_complete_passthrough_header(header));
        }
    }

    #[test]
    fn strips_edge_and_client_ip_metadata() {
        // 2026-10-16 现场抓包：EdgeOne 在边缘注入了 eo-connecting-ip / eo-log-uuid。
        // 它们不是客户端发的，也不该出现在我们发往上游的请求里。
        for header in [
            "eo-connecting-ip",
            "eo-log-uuid",
            "EO-Connecting-IP",
            "cf-connecting-ip",
            "cf-ray",
            "cf-ipcountry",
            "x-amz-cf-id",
            "x-amzn-trace-id",
            "x-vercel-id",
            "akamai-grn",
            "x-akamai-config-log-detail",
            "x-fastly-request-id",
            "x-azure-ref",
            "true-client-ip",
            "x-client-ip",
            "x-cluster-client-ip",
            "proxy-client-ip",
            "wl-proxy-client-ip",
            "fastly-client-ip",
            "x-originating-ip",
            "x-remote-ip",
            "x-remote-addr",
            "x-proxyuser-ip",
            "incap-client-ip",
        ] {
            assert!(should_skip_request_header(header), "should skip {header}");
            assert!(
                should_skip_upstream_passthrough_header(header),
                "should skip passthrough {header}"
            );
            assert!(
                should_skip_upstream_complete_passthrough_header(header),
                "should skip complete passthrough {header}"
            );
        }
    }

    #[test]
    fn strips_middleware_only_client_fingerprints() {
        for header in [
            "x-deepseek-harness-session-id",
            "x-deepseek-harness-user-id",
            "x-harness-session-id",
            "sec-fetch-mode",
            "sec-fetch-site",
            "sec-fetch-dest",
        ] {
            assert!(should_skip_request_header(header), "should skip {header}");
            assert!(
                should_skip_upstream_passthrough_header(header),
                "should skip passthrough {header}"
            );
            assert!(
                should_skip_upstream_complete_passthrough_header(header),
                "should skip complete passthrough {header}"
            );
        }
    }

    #[test]
    fn keeps_the_native_opencode_client_header_set() {
        // 反面守卫：opencode 的原生客户端头必须原样通过，不能被上面的规则误伤，
        // 否则会把指纹打坏（上游对这套头是硬要求）。
        for header in [
            "user-agent",
            "accept",
            "accept-encoding",
            "accept-language",
            "content-type",
            "authorization",
            "x-opencode-client",
            "x-opencode-project",
            "x-opencode-request",
            "x-opencode-session",
            "x-opencode-session-id",
        ] {
            assert!(!should_skip_request_header(header), "must keep {header}");
        }
    }

    #[test]
    fn strips_usage_server_time_header_from_provider_requests() {
        for h in [
            USAGE_SERVER_NOW_UNIX_MS_HEADER,
            "X-Aether-Server-Now-Unix-Ms",
        ] {
            assert!(should_skip_request_header(h), "should skip {h}");
            assert!(
                should_skip_upstream_passthrough_header(h),
                "should skip passthrough {h}"
            );
            assert!(
                should_skip_upstream_complete_passthrough_header(h),
                "should skip complete passthrough {h}"
            );
        }
    }

    #[test]
    fn allows_normal_headers_through() {
        let allowed = ["user-agent", "accept", "content-type", "x-custom-header"];
        for h in allowed {
            assert!(
                !should_skip_upstream_passthrough_header(h),
                "should allow {h}"
            );
        }
    }

    #[test]
    fn declared_connection_names_are_case_insensitive_and_multi_line() {
        let mut headers = http::HeaderMap::new();
        headers.append(
            http::header::CONNECTION,
            http::HeaderValue::from_static("X-Hop, keep-alive"),
        );
        headers.append(
            http::header::CONNECTION,
            http::HeaderValue::from_static("x-other-hop"),
        );

        let names = super::declared_connection_header_names(&headers, &BTreeMap::new());
        assert!(names.contains("x-hop"));
        assert!(names.contains("keep-alive"));
        assert!(names.contains("x-other-hop"));
        assert!(super::is_declared_connection_header("X-HOP", &names));
    }
}
