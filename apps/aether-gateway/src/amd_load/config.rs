//! AMD 模型负载感知 —— 配置解析、校验与环境变量兜底。
//!
//! 设计依据见 `docs/operations/model-load-control-plan.md` 第 6 节。
//!
//! 数据源是 AMD 专有的 `GET /radeon/api/tokenfactory/load`（fleet 级容量占用），
//! 本模块不做任何供应商抽象：只服务 `provider_type: custom` 且上游为
//! `https://.../radeon/api/v1` 的供应商。

use serde_json::Value;

// ---------------------------------------------------------------------------
// 默认值与硬边界
// ---------------------------------------------------------------------------

/// 总开关默认关闭：装好 key 之前不应有任何行为。
pub(crate) const AMD_LOAD_DEFAULT_ENABLED: bool = false;
/// 轮询间隔默认 60s。
///
/// 下限 30s 是硬约束：实测该接口单次耗时 20.5s–23.3s（p50=22.3s），
/// 间隔低于 30s 会让请求堆叠。
pub(crate) const AMD_LOAD_DEFAULT_POLL_SEC: u64 = 60;
pub(crate) const AMD_LOAD_MIN_POLL_SEC: u64 = 30;
pub(crate) const AMD_LOAD_MAX_POLL_SEC: u64 = 3600;

/// 禁用阈值默认 85%。
///
/// 取值依据（15 次采样，约 5.5 分钟窗口）：主力文本模型
/// `DeepSeek-V4-Flash` 的 p50=78.6、stdev=6.1。阈值 80 正好切在分布中部，
/// 会导致 27% 的轮询被禁用；85 降到 7%，而每轮可用模型数反而略升
/// （80→均值 3.9，85→均值 4.1）。
pub(crate) const AMD_LOAD_DEFAULT_DISABLE_THRESHOLD: f64 = 85.0;

/// 低于此阈值时保存配置会告警：按实测分布，几乎所有模型都会被禁用。
pub(crate) const AMD_LOAD_UNSAFE_LOW_THRESHOLD: f64 = 50.0;

/// 连续几次越线才禁用，默认 2。
pub(crate) const AMD_LOAD_DEFAULT_DISABLE_STREAK: u32 = 2;
pub(crate) const AMD_LOAD_MAX_DISABLE_STREAK: u32 = 10;

/// 快照有效期默认 180s，必须 >= poll_sec * 2。
pub(crate) const AMD_LOAD_DEFAULT_SNAPSHOT_TTL_SEC: u64 = 180;

/// 单次请求超时默认 40s。实测接口耗时 20.5s–23.3s，40s 留约 1.7 倍余量。
pub(crate) const AMD_LOAD_DEFAULT_TIMEOUT_SEC: u64 = 40;
pub(crate) const AMD_LOAD_MIN_TIMEOUT_SEC: u64 = 10;
pub(crate) const AMD_LOAD_MAX_TIMEOUT_SEC: u64 = 120;

// ---------------------------------------------------------------------------
// 环境变量兜底
// ---------------------------------------------------------------------------

const AMD_LOAD_ENV_ENABLED: &str = "AMD_LOAD_ENABLED";
const AMD_LOAD_ENV_POLL_SEC: &str = "AMD_LOAD_POLL_SEC";
const AMD_LOAD_ENV_DISABLE_THRESHOLD: &str = "AMD_LOAD_DISABLE_THRESHOLD";
const AMD_LOAD_ENV_RECOVERY_THRESHOLD: &str = "AMD_LOAD_RECOVERY_THRESHOLD";
const AMD_LOAD_ENV_DISABLE_STREAK: &str = "AMD_LOAD_DISABLE_STREAK";
const AMD_LOAD_ENV_SNAPSHOT_TTL_SEC: &str = "AMD_LOAD_SNAPSHOT_TTL_SEC";
const AMD_LOAD_ENV_TIMEOUT_SEC: &str = "AMD_LOAD_TIMEOUT_SEC";

fn env_string(name: &str) -> Option<String> {
    std::env::var(name).ok().and_then(|raw| {
        let trimmed = raw.trim();
        (!trimmed.is_empty()).then(|| trimmed.to_string())
    })
}

fn env_bool(name: &str) -> Option<bool> {
    match env_string(name)?.to_ascii_lowercase().as_str() {
        "1" | "true" | "yes" | "on" => Some(true),
        "0" | "false" | "no" | "off" => Some(false),
        _ => None,
    }
}

fn env_u64(name: &str) -> Option<u64> {
    env_string(name).and_then(|raw| raw.parse::<u64>().ok())
}

fn env_f64(name: &str) -> Option<f64> {
    env_string(name).and_then(|raw| raw.parse::<f64>().ok())
}

// ---------------------------------------------------------------------------
// 配置结构
// ---------------------------------------------------------------------------

/// 一个供应商的 AMD 负载感知配置。
#[derive(Debug, Clone, PartialEq)]
pub(crate) struct AmdLoadConfig {
    pub enabled: bool,
    pub poll_sec: u64,
    pub disable_threshold: f64,
    /// 留空表示单阈值模式：`< disable_threshold` 即放行，不设滞回。
    pub recovery_threshold: Option<f64>,
    pub disable_streak: u32,
    pub snapshot_ttl_sec: u64,
    pub timeout_sec: u64,
}

impl Default for AmdLoadConfig {
    fn default() -> Self {
        Self {
            enabled: AMD_LOAD_DEFAULT_ENABLED,
            poll_sec: AMD_LOAD_DEFAULT_POLL_SEC,
            disable_threshold: AMD_LOAD_DEFAULT_DISABLE_THRESHOLD,
            recovery_threshold: None,
            disable_streak: AMD_LOAD_DEFAULT_DISABLE_STREAK,
            snapshot_ttl_sec: AMD_LOAD_DEFAULT_SNAPSHOT_TTL_SEC,
            timeout_sec: AMD_LOAD_DEFAULT_TIMEOUT_SEC,
        }
    }
}

impl AmdLoadConfig {
    /// 有效恢复阈值：未配置时等于禁用阈值，即单阈值模式。
    pub(crate) fn effective_recovery(&self) -> f64 {
        self.recovery_threshold.unwrap_or(self.disable_threshold)
    }

    /// 是否配置了滞回带（恢复阈值低于禁用阈值）。
    pub(crate) fn has_hysteresis(&self) -> bool {
        self.recovery_threshold
            .is_some_and(|r| r < self.disable_threshold)
    }

    /// 快照有效期是否已过期。
    pub(crate) fn snapshot_expired(&self, now_unix_secs: u64, fetched_at_unix_secs: u64) -> bool {
        now_unix_secs.saturating_sub(fetched_at_unix_secs) > self.snapshot_ttl_sec
    }

    /// 从环境变量构造默认值。`provider.config.amd_load` 缺省时使用。
    pub(crate) fn from_env() -> Self {
        let defaults = Self::default();
        let poll_sec = env_u64(AMD_LOAD_ENV_POLL_SEC)
            .map(|v| v.clamp(AMD_LOAD_MIN_POLL_SEC, AMD_LOAD_MAX_POLL_SEC))
            .unwrap_or(defaults.poll_sec);
        let disable_threshold = env_f64(AMD_LOAD_ENV_DISABLE_THRESHOLD)
            .filter(|v| *v > 0.0 && *v <= 100.0)
            .unwrap_or(defaults.disable_threshold);
        Self {
            enabled: env_bool(AMD_LOAD_ENV_ENABLED).unwrap_or(defaults.enabled),
            poll_sec,
            disable_threshold,
            recovery_threshold: env_f64(AMD_LOAD_ENV_RECOVERY_THRESHOLD)
                .filter(|v| *v > 0.0 && *v <= 100.0),
            disable_streak: env_u64(AMD_LOAD_ENV_DISABLE_STREAK)
                .map(|v| v.clamp(1, AMD_LOAD_MAX_DISABLE_STREAK as u64) as u32)
                .unwrap_or(defaults.disable_streak),
            snapshot_ttl_sec: env_u64(AMD_LOAD_ENV_SNAPSHOT_TTL_SEC)
                .unwrap_or(defaults.snapshot_ttl_sec.max(poll_sec * 2)),
            timeout_sec: env_u64(AMD_LOAD_ENV_TIMEOUT_SEC)
                .map(|v| v.clamp(AMD_LOAD_MIN_TIMEOUT_SEC, AMD_LOAD_MAX_TIMEOUT_SEC))
                .unwrap_or(defaults.timeout_sec),
        }
    }

    /// 从 `providers.config` 读出本供应商配置；节点缺失时走 env。
    pub(crate) fn from_provider_config(provider_config: Option<&Value>) -> Self {
        let base = Self::from_env();
        let Some(section) = provider_config
            .and_then(|config| config.get(AMD_LOAD_CONFIG_KEY))
            .filter(|value| value.is_object())
        else {
            return base;
        };
        base.merged_with_payload(Some(section))
    }

    /// 合并一个 `amd_load` JSON 片段。片段里出现的字段覆盖当前值。
    pub(crate) fn merged_with_payload(&self, payload: Option<&Value>) -> Self {
        let mut merged = self.clone();
        let Some(payload) = payload.and_then(|value| value.as_object()) else {
            return merged;
        };
        if let Some(value) = payload_bool(payload, "enabled") {
            merged.enabled = value;
        }
        if let Some(value) = payload_u64(payload, "poll_sec") {
            merged.poll_sec = value.clamp(AMD_LOAD_MIN_POLL_SEC, AMD_LOAD_MAX_POLL_SEC);
        }
        if let Some(value) = payload_f64(payload, "disable_threshold") {
            merged.disable_threshold = value;
        }
        // 显式 null 表示「回到单阈值模式」，与「未提供该字段」不同。
        if let Some(raw) = payload.get("recovery_threshold") {
            merged.recovery_threshold = match raw {
                Value::Null => None,
                other => json_f64(other),
            };
        }
        if let Some(value) = payload_u64(payload, "disable_streak") {
            merged.disable_streak = value.clamp(1, AMD_LOAD_MAX_DISABLE_STREAK as u64) as u32;
        }
        if let Some(value) = payload_u64(payload, "snapshot_ttl_sec") {
            merged.snapshot_ttl_sec = value;
        }
        if let Some(value) = payload_u64(payload, "timeout_sec") {
            merged.timeout_sec = value.clamp(AMD_LOAD_MIN_TIMEOUT_SEC, AMD_LOAD_MAX_TIMEOUT_SEC);
        }
        // 快照有效期不得短于两倍轮询间隔，否则会出现「下一轮还没回来、
        // 上一份快照先过期」的窗口，判定直接失效。
        if merged.snapshot_ttl_sec < merged.poll_sec * 2 {
            merged.snapshot_ttl_sec = merged.poll_sec * 2;
        }
        merged
    }

    /// 保存校验：返回 `Err` 表示拒绝写入。
    pub(crate) fn validate(&self) -> Result<(), String> {
        if !(self.disable_threshold > 0.0 && self.disable_threshold <= 100.0) {
            return Err(format!(
                "AMD_LOAD_DISABLE_THRESHOLD 必须在 (0, 100] 之间，当前为 {}",
                self.disable_threshold
            ));
        }
        if let Some(recovery) = self.recovery_threshold {
            if !(recovery > 0.0 && recovery <= 100.0) {
                return Err(format!(
                    "AMD_LOAD_RECOVERY_THRESHOLD 必须在 (0, 100] 之间，当前为 {recovery}"
                ));
            }
        }
        if self.poll_sec < AMD_LOAD_MIN_POLL_SEC {
            return Err(format!(
                "AMD_LOAD_POLL_SEC 不能小于 {AMD_LOAD_MIN_POLL_SEC}，当前为 {}（该接口单次耗时约 22 秒）",
                self.poll_sec
            ));
        }
        if self.disable_streak < 1 {
            return Err("AMD_LOAD_DISABLE_STREAK 必须大于等于 1".to_string());
        }
        if self.snapshot_ttl_sec < self.poll_sec * 2 {
            return Err(format!(
                "AMD_LOAD_SNAPSHOT_TTL_SEC 必须大于等于轮询间隔的两倍（{}）",
                self.poll_sec * 2
            ));
        }
        if self.timeout_sec < AMD_LOAD_MIN_TIMEOUT_SEC {
            return Err(format!(
                "AMD_LOAD_TIMEOUT_SEC 不能小于 {AMD_LOAD_MIN_TIMEOUT_SEC}"
            ));
        }
        Ok(())
    }

    /// 不阻断保存、但值得提示的配置问题。
    pub(crate) fn warnings(&self) -> Vec<String> {
        let mut out = Vec::new();
        if self
            .recovery_threshold
            .is_some_and(|recovery| recovery >= self.disable_threshold)
        {
            out.push(
                "恢复阈值不低于禁用阈值，会造成反复启停；建议设成更小的值以形成滞回带".to_string(),
            );
        }
        if self.disable_threshold < AMD_LOAD_UNSAFE_LOW_THRESHOLD {
            out.push(format!(
                "禁用阈值低于 {AMD_LOAD_UNSAFE_LOW_THRESHOLD}，按实测负载分布几乎所有模型都会被禁用"
            ));
        }
        out
    }
}

// ---------------------------------------------------------------------------
// 字段解析辅助
// ---------------------------------------------------------------------------

/// `providers.config` 中的节点名。
pub(crate) const AMD_LOAD_CONFIG_KEY: &str = "amd_load";

fn json_f64(value: &Value) -> Option<f64> {
    match value {
        Value::Number(number) => number.as_f64(),
        // 宽松接受字符串：管理端表单回传可能是 "85"。
        Value::String(raw) => raw.trim().parse::<f64>().ok(),
        _ => None,
    }
}

fn json_u64(value: &Value) -> Option<u64> {
    match value {
        Value::Number(number) => number.as_u64().or_else(|| {
            let as_f64 = number.as_f64()?;
            (as_f64 >= 0.0 && as_f64.fract() == 0.0).then_some(as_f64 as u64)
        }),
        Value::String(raw) => raw.trim().parse::<u64>().ok(),
        _ => None,
    }
}

fn json_bool(value: &Value) -> Option<bool> {
    match value {
        Value::Bool(flag) => Some(*flag),
        Value::String(raw) => match raw.trim().to_ascii_lowercase().as_str() {
            "1" | "true" | "yes" | "on" => Some(true),
            "0" | "false" | "no" | "off" => Some(false),
            _ => None,
        },
        _ => None,
    }
}

fn payload_bool(payload: &serde_json::Map<String, Value>, key: &str) -> Option<bool> {
    payload.get(key).and_then(json_bool)
}

fn payload_u64(payload: &serde_json::Map<String, Value>, key: &str) -> Option<u64> {
    payload.get(key).and_then(json_u64)
}

fn payload_f64(payload: &serde_json::Map<String, Value>, key: &str) -> Option<f64> {
    payload.get(key).and_then(json_f64)
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn cfg() -> AmdLoadConfig {
        AmdLoadConfig::default()
    }

    #[test]
    fn defaults_match_the_design_doc() {
        let config = cfg();
        assert!(!config.enabled);
        assert_eq!(config.poll_sec, 60);
        assert_eq!(config.disable_threshold, 85.0);
        assert_eq!(config.recovery_threshold, None);
        assert_eq!(config.disable_streak, 2);
        assert_eq!(config.snapshot_ttl_sec, 180);
        assert_eq!(config.timeout_sec, 40);
        assert!(config.validate().is_ok());
    }

    #[test]
    fn empty_recovery_falls_back_to_single_threshold_mode() {
        let config = cfg();
        assert_eq!(config.effective_recovery(), 85.0);
        assert!(!config.has_hysteresis());
    }

    #[test]
    fn explicit_null_recovery_returns_to_single_threshold_mode() {
        let merged = cfg().merged_with_payload(Some(&json!({
            "recovery_threshold": null,
            "disable_threshold": 90.0
        })));
        assert_eq!(merged.recovery_threshold, None);
        assert_eq!(merged.disable_threshold, 90.0);
        assert_eq!(merged.effective_recovery(), 90.0);
    }

    #[test]
    fn missing_payload_keeps_current_values() {
        let merged = cfg().merged_with_payload(None);
        assert_eq!(merged, cfg());
        let merged = cfg().merged_with_payload(Some(&json!({})));
        assert_eq!(merged, cfg());
    }

    /// 前端 `Input` 组件回传字符串，`.number` 不生效，这里必须能吃下字符串。
    #[test]
    fn accepts_string_and_number_payloads() {
        let merged = cfg().merged_with_payload(Some(&json!({
            "enabled": "true",
            "poll_sec": "120",
            "disable_threshold": "77.5",
            "disable_streak": "3",
            "timeout_sec": "50"
        })));
        assert!(merged.enabled);
        assert_eq!(merged.poll_sec, 120);
        assert_eq!(merged.disable_threshold, 77.5);
        assert_eq!(merged.disable_streak, 3);
        assert_eq!(merged.timeout_sec, 50);
    }

    #[test]
    fn poll_sec_below_floor_is_clamped_when_merging() {
        let merged = cfg().merged_with_payload(Some(&json!({ "poll_sec": 5 })));
        assert_eq!(merged.poll_sec, AMD_LOAD_MIN_POLL_SEC);
    }

    #[test]
    fn snapshot_ttl_is_raised_to_twice_poll_sec() {
        let merged = cfg().merged_with_payload(Some(&json!({
            "poll_sec": 120,
            "snapshot_ttl_sec": 130
        })));
        assert_eq!(merged.snapshot_ttl_sec, 240);
    }

    #[test]
    fn validate_rejects_out_of_range_values() {
        let mut bad = cfg();
        bad.disable_threshold = 0.0;
        assert!(bad.validate().is_err());

        let mut bad = cfg();
        bad.disable_threshold = 101.0;
        assert!(bad.validate().is_err());

        let mut bad = cfg();
        bad.recovery_threshold = Some(0.0);
        assert!(bad.validate().is_err());

        let mut bad = cfg();
        bad.poll_sec = 10;
        assert!(bad.validate().is_err());

        let mut bad = cfg();
        bad.disable_streak = 0;
        assert!(bad.validate().is_err());

        let mut bad = cfg();
        bad.snapshot_ttl_sec = 60;
        assert!(bad.validate().is_err());
    }

    #[test]
    fn warns_on_reversed_hysteresis_and_low_threshold() {
        let reversed = AmdLoadConfig {
            recovery_threshold: Some(90.0),
            ..cfg()
        };
        assert!(reversed.warnings().iter().any(|w| w.contains("滞回")));

        let low = AmdLoadConfig {
            disable_threshold: 30.0,
            ..cfg()
        };
        assert_eq!(low.warnings().len(), 1);
        // 告警不阻断保存
        assert!(low.validate().is_ok());
    }

    #[test]
    fn snapshot_expiry_uses_ttl() {
        let config = cfg();
        assert!(!config.snapshot_expired(1000, 1000));
        assert!(!config.snapshot_expired(1180, 1000));
        assert!(config.snapshot_expired(1181, 1000));
    }

    #[test]
    fn provider_config_without_section_falls_back_to_env() {
        let config = AmdLoadConfig::from_provider_config(None);
        assert_eq!(config, AmdLoadConfig::from_env());

        let provider_config = json!({ "other_node": { "enabled": true } });
        let config = AmdLoadConfig::from_provider_config(Some(&provider_config));
        assert_eq!(config, AmdLoadConfig::from_env());
    }

    #[test]
    fn provider_config_section_is_merged() {
        let provider_config = json!({
            "amd_load": { "enabled": true, "disable_threshold": 70 }
        });
        let config = AmdLoadConfig::from_provider_config(Some(&provider_config));
        assert!(config.enabled);
        assert_eq!(config.disable_threshold, 70.0);
        // 未提供的字段保持默认
        assert_eq!(config.poll_sec, 60);
    }
}
