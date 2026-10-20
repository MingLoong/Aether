use crate::handlers::admin::provider::shared::payloads::AdminProviderCreateRequest;
use crate::handlers::admin::provider::shared::support::{
    normalize_provider_billing_type, normalize_provider_transfer_limit,
    normalize_provider_transfer_limit_json, parse_optional_rfc3339_unix_secs,
    PROVIDER_MAX_TRANSFER_COUNT_CONFIG_KEY, PROVIDER_MAX_TRANSFER_TIMEOUT_SECONDS_CONFIG_KEY,
};
use crate::handlers::admin::provider::write::normalize::normalize_chat_pii_redaction_config;
use crate::handlers::admin::provider::write::normalize::normalize_pool_advanced_config;
use crate::handlers::admin::provider::write::normalize::normalize_provider_type_input;
use crate::handlers::admin::provider::write::normalize::set_responses_websocket_enabled;
use crate::handlers::admin::provider::write::normalize::validate_responses_websocket_config;
use crate::handlers::admin::request::AdminAppState;
use crate::handlers::admin::shared::normalize_json_object;
use aether_data_contracts::repository::provider_catalog::StoredProviderCatalogProvider;
use serde_json::json;
use std::time::{SystemTime, UNIX_EPOCH};
use uuid::Uuid;

pub(crate) async fn build_admin_create_provider_record(
    state: &AdminAppState<'_>,
    payload: AdminProviderCreateRequest,
) -> Result<(StoredProviderCatalogProvider, Option<i32>), String> {
    let name = payload.name.trim();
    if name.is_empty() {
        return Err("name 为必填字段".to_string());
    }

    let existing_providers = state
        .list_provider_catalog_providers(false)
        .await
        .map_err(|err| format!("{err:?}"))?;
    if existing_providers
        .iter()
        .any(|provider| provider.name == name)
    {
        return Err(format!("提供商名称 '{name}' 已存在"));
    }

    let provider_type =
        normalize_provider_type_input(payload.provider_type.as_deref().unwrap_or("custom"))?;
    let billing_type = normalize_provider_billing_type(
        payload.billing_type.as_deref().unwrap_or("pay_as_you_go"),
    )?;

    let website = payload.website.and_then(|value| {
        let trimmed = value.trim().to_string();
        (!trimmed.is_empty()).then_some(trimmed)
    });
    let website = website.map(|value| {
        if value.starts_with("http://") || value.starts_with("https://") {
            value
        } else {
            format!("https://{value}")
        }
    });

    let monthly_quota_usd = match payload.monthly_quota_usd {
        Some(value) if value.is_finite() && value >= 0.0 => Some(value),
        Some(_) => return Err("monthly_quota_usd 必须是非负数".to_string()),
        None => None,
    };
    let quota_reset_day = match payload.quota_reset_day {
        Some(value) if (1..=365).contains(&value) => Some(value),
        Some(_) => return Err("quota_reset_day 必须是 1 到 365 之间的整数".to_string()),
        None => Some(30),
    };
    let quota_last_reset_at_unix_secs = payload
        .quota_last_reset_at
        .as_deref()
        .map(|value| parse_optional_rfc3339_unix_secs(value, "quota_last_reset_at"))
        .transpose()?;
    let quota_expires_at_unix_secs = payload
        .quota_expires_at
        .as_deref()
        .map(|value| parse_optional_rfc3339_unix_secs(value, "quota_expires_at"))
        .transpose()?;
    let provider_priority = match payload.provider_priority {
        Some(value) if (0..=10_000).contains(&value) => value,
        Some(_) => return Err("provider_priority 必须在 0 到 10000 之间".to_string()),
        None => {
            let current_min_priority = existing_providers
                .iter()
                .map(|provider| provider.provider_priority)
                .min();
            match current_min_priority {
                Some(value) if value <= 0 => 0,
                Some(value) => value - 1,
                None => 100,
            }
        }
    };
    let shift_existing_priorities_from = match payload.provider_priority {
        Some(_) => Some(provider_priority),
        None => existing_providers
            .iter()
            .map(|provider| provider.provider_priority)
            .min()
            .filter(|value| *value <= 0)
            .map(|_| 0),
    };

    let is_active = payload.is_active.unwrap_or(true);
    let concurrent_limit = match payload.concurrent_limit {
        Some(value) if value >= 0 => Some(value),
        Some(_) => return Err("concurrent_limit 必须是非负整数".to_string()),
        None => None,
    };
    let max_retries = match payload.max_retries {
        Some(value) if (0..=999).contains(&value) => Some(value),
        Some(_) => return Err("max_retries 必须是 0 到 999 之间的整数".to_string()),
        None => Some(2),
    };
    let proxy = normalize_json_object(payload.proxy, "proxy")?;
    let stream_first_byte_timeout_secs =
        super::normalize_provider_stream_first_byte_timeout(payload.stream_first_byte_timeout)?;
    let request_timeout_secs = super::normalize_provider_request_timeout(payload.request_timeout)?;

    let mut config_map = normalize_json_object(payload.config, "config")?
        .and_then(|value| value.as_object().cloned())
        .unwrap_or_default();
    for (field_name, payload_value) in [
        (
            PROVIDER_MAX_TRANSFER_COUNT_CONFIG_KEY,
            payload.max_transfer_count,
        ),
        (
            PROVIDER_MAX_TRANSFER_TIMEOUT_SECONDS_CONFIG_KEY,
            payload.max_transfer_timeout_seconds,
        ),
    ] {
        let value = match payload_value {
            Some(value) => Some(normalize_provider_transfer_limit(value, field_name)?),
            None => config_map
                .get(field_name)
                .map(|value| normalize_provider_transfer_limit_json(value, field_name))
                .transpose()?,
        };
        if let Some(value) = value {
            config_map.insert(field_name.to_string(), json!(value));
        }
    }
    // WorkBuddy「国内 / 国际」双实例：`config.workbuddy.realm` 是**实例级唯一真相** ——
    // 前端据此锁死加账号的「版本」，后端写侧据此拒绝跨域凭据，账号元数据里的 realm 也与它
    // 一致。所以这里只接受 `cn` / `global` 两个值，写成别的直接拒绝（否则三处各理解一个域）。
    if provider_type == "workbuddy" {
        if let Some(bucket) = config_map.get_mut("workbuddy") {
            let Some(object) = bucket.as_object_mut() else {
                return Err("config.workbuddy 必须是 JSON 对象".to_string());
            };
            if let Some(value) = object.get("realm") {
                let raw = value
                    .as_str()
                    .unwrap_or_default()
                    .trim()
                    .to_ascii_lowercase();
                if raw != "cn" && raw != "global" {
                    return Err("config.workbuddy.realm 只能是 cn 或 global".to_string());
                }
                object.insert("realm".to_string(), json!(raw));
            }
        }
    }
    // 不接号池的类型（AMD、Cline）一律剥离：写入侧直接剥离（读取侧另有一道强制不认，
    // 见 `admin_provider_pool_config_for_provider`）。
    if !crate::amd_rotation::provider_type_exempt_from_generic_pool(provider_type.as_str()) {
        if let Some(value) = normalize_pool_advanced_config(payload.pool_advanced)? {
            config_map.insert("pool_advanced".to_string(), value);
        }
    }
    if let Some(enabled) = payload.codex_fingerprint_convergence_enabled {
        if provider_type != "codex" && enabled {
            return Err(
                "codex_fingerprint_convergence_enabled 仅适用于 provider_type=codex".to_string(),
            );
        }
        if provider_type == "codex" {
            let codex_config = config_map
                .entry(crate::provider_transport::CODEX_FINGERPRINT_CONFIG_NAMESPACE.to_string())
                .or_insert_with(|| json!({}));
            let Some(codex_config) = codex_config.as_object_mut() else {
                return Err("config.codex 必须是 JSON 对象".to_string());
            };
            codex_config.insert(
                crate::provider_transport::CODEX_FINGERPRINT_ENABLED_CONFIG_KEY.to_string(),
                json!(enabled),
            );
        }
    }
    if provider_type != "codex" {
        remove_codex_fingerprint_config(&mut config_map);
    }
    if let Some(value) = normalize_json_object(payload.failover_rules, "failover_rules")? {
        config_map.insert("failover_rules".to_string(), value);
    }
    if let Some(value) =
        normalize_json_object(payload.claude_code_advanced, "claude_code_advanced")?
    {
        if provider_type != "claude_code" {
            return Err("claude_code_advanced 仅适用于 provider_type=claude_code".to_string());
        }
        config_map.insert("claude_code_advanced".to_string(), value);
    }
    if config_map.contains_key("chat_pii_redaction") {
        let value = normalize_chat_pii_redaction_config(config_map.remove("chat_pii_redaction"))?;
        if let Some(value) = value {
            config_map.insert("chat_pii_redaction".to_string(), value);
        }
    }
    if let Some(enabled) = payload.responses_websocket_enabled {
        set_responses_websocket_enabled(&mut config_map, enabled)?;
    }
    validate_responses_websocket_config(&config_map)?;
    apply_fixed_provider_default_config(&mut config_map, &provider_type);
    let config = (!config_map.is_empty()).then_some(serde_json::Value::Object(config_map));
    crate::provider_transport::validate_anthropic_compatibility_profile_config(config.as_ref())
        .map_err(|_| "无效的 Anthropic compatibility profile".to_string())?;

    let now_unix_secs = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .ok()
        .map(|duration| duration.as_secs())
        .unwrap_or(0);

    let record = StoredProviderCatalogProvider::new(
        Uuid::new_v4().to_string(),
        name.to_string(),
        website,
        provider_type.clone(),
    )
    .map_err(|err| err.to_string())?
    .with_description(
        payload
            .description
            .map(|value| value.trim().to_string())
            .filter(|value| !value.is_empty()),
    )
    .with_billing_fields(
        Some(billing_type),
        monthly_quota_usd,
        None,
        quota_reset_day,
        quota_last_reset_at_unix_secs,
        quota_expires_at_unix_secs,
    )
    .with_routing_fields(provider_priority)
    .with_transport_fields(
        is_active,
        payload.keep_priority_on_conversion.unwrap_or(false),
        state.provider_type_enables_format_conversion_by_default(&provider_type),
        concurrent_limit,
        max_retries,
        proxy,
        request_timeout_secs,
        stream_first_byte_timeout_secs,
        config,
    )
    .with_timestamps(Some(now_unix_secs), Some(now_unix_secs));

    Ok((record, shift_existing_priorities_from))
}

/// 把固定模板的 **provider 级默认值**补进 config：只补「操作者没显式给」的键——
/// 显式配置永远优先（默认值不能覆盖人的意图）。
fn apply_fixed_provider_default_config(
    config_map: &mut serde_json::Map<String, serde_json::Value>,
    provider_type: &str,
) {
    let Some(defaults) =
        crate::provider_transport::provider_types::fixed_provider_default_provider_config(
            provider_type,
        )
    else {
        return;
    };
    let Some(defaults) = defaults.as_object() else {
        return;
    };
    for (key, value) in defaults {
        config_map
            .entry(key.clone())
            .or_insert_with(|| value.clone());
    }
}

fn remove_codex_fingerprint_config(config_map: &mut serde_json::Map<String, serde_json::Value>) {
    let namespace = crate::provider_transport::CODEX_FINGERPRINT_CONFIG_NAMESPACE;
    let key = crate::provider_transport::CODEX_FINGERPRINT_ENABLED_CONFIG_KEY;
    let mut remove_namespace = false;
    if let Some(codex_config) = config_map
        .get_mut(namespace)
        .and_then(|value| value.as_object_mut())
    {
        codex_config.remove(key);
        remove_namespace = codex_config.is_empty();
    }
    if remove_namespace {
        config_map.remove(namespace);
    }
}

#[cfg(test)]
mod tests {
    use serde_json::json;

    /// 固定模板的 provider 级默认值：补默认、**显式配置优先**、别的类型不受影响。
    #[test]
    fn fixed_provider_defaults_fill_missing_keys_without_overriding_explicit_config() {
        // workbuddy + 空 config → 补上 failover_rules（请求级错误不换号）。
        let mut config = serde_json::Map::new();
        super::apply_fixed_provider_default_config(&mut config, "workbuddy");
        assert_eq!(
            config["failover_rules"]["error_stop_patterns"][0]["status_codes"],
            json!([400])
        );

        // workbuddy + 显式给了 failover_rules → 一个字都不改（人的意图优先）。
        let explicit = json!({"failover_rules": {"strategy": "ordered"}});
        let mut config = explicit.as_object().expect("object").clone();
        super::apply_fixed_provider_default_config(&mut config, "workbuddy");
        assert_eq!(config["failover_rules"], json!({"strategy": "ordered"}));

        // 别的类型完全没有默认值。
        let mut config = serde_json::Map::new();
        super::apply_fixed_provider_default_config(&mut config, "codex");
        assert!(config.is_empty());
    }

    #[test]
    fn removing_fingerprint_setting_preserves_other_codex_config() {
        let mut config = json!({
            "codex": {
                "fingerprint_convergence_enabled": true,
                "pass_through_cyber_flag_interrupt": true
            },
            "other": {"kept": true}
        })
        .as_object()
        .expect("config object")
        .clone();

        super::remove_codex_fingerprint_config(&mut config);

        assert_eq!(
            config["codex"],
            json!({"pass_through_cyber_flag_interrupt": true})
        );
        assert_eq!(config["other"], json!({"kept": true}));
    }
}
