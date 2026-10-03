//! AMD 模型负载感知 —— 负载快照与判定。
//!
//! 数据源是 AMD 专有的 `GET /radeon/api/tokenfactory/load`，fleet 级容量占用。
//! 详见 `docs/operations/model-load-control-plan.md`。
//!
//! 本模块不做供应商抽象。判定粒度是**供应商 × 模型**：负载高的模型在这家供应商上
//! 被临时停用，同一个模型若还有别家供应商在供，那家不受影响。

pub(crate) mod config;
pub(crate) mod poller;
pub(crate) mod usage;

use std::collections::{BTreeMap, BTreeSet};

use serde::{Deserialize, Serialize};

pub(crate) use config::{AmdLoadConfig, AMD_LOAD_CONFIG_KEY};
pub(crate) use usage::{AmdUsageSnapshot, AmdUsageWindow};

/// 单个模型的负载条目。
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub(crate) struct AmdLoadModelEntry {
    /// `idle` / `busy` / `full`。`full` 比百分比更严格，判定时优先。
    #[serde(default)]
    pub state: String,
    /// 容量占用百分比 0-100。
    #[serde(default)]
    pub utilization: f64,
    /// 连续越线次数，轮询侧累计。
    #[serde(default)]
    pub streak: u32,
    /// 上一轮的禁用结论。仅在滞回带内被读到。
    #[serde(default)]
    pub blocked_prev: bool,
}

impl AmdLoadModelEntry {
    fn from_upstream(state: Option<&str>, utilization: Option<f64>) -> Self {
        Self {
            state: state.unwrap_or_default().trim().to_ascii_lowercase(),
            utilization: utilization.unwrap_or(0.0).clamp(0.0, 100.0),
            streak: 0,
            blocked_prev: false,
        }
    }
}

/// 一次成功拉取得到的完整负载快照。
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
pub(crate) struct AmdLoadSnapshot {
    /// 上次成功拉取的 unix 秒。用于 TTL 判定。
    #[serde(default)]
    pub fetched_at: u64,
    /// 上游返回的 scope，实测恒为 `fleet`（平台级，与具体 key 无关）。
    #[serde(default)]
    pub scope: String,
    pub models: BTreeMap<String, AmdLoadModelEntry>,
}

impl AmdLoadSnapshot {
    /// 解析上游响应。结构不符时返回 `Err`，调用方保留旧快照。
    ///
    /// 容忍的偏差：`models` 为空对象视为异常（`minerU2.5-Pro` 曾在 12 次采样中
    /// 从响应里消失又出现，单个模型缺失不算异常，整个对象缺失才算）。
    pub(crate) fn parse_upstream(body: &str, fetched_at: u64) -> Result<Self, String> {
        let raw: serde_json::Value =
            serde_json::from_str(body).map_err(|err| format!("响应不是合法 JSON: {err}"))?;
        let models = raw
            .get("models")
            .and_then(serde_json::Value::as_object)
            .ok_or_else(|| "响应缺少 models 对象".to_string())?;
        if models.is_empty() {
            return Err("响应 models 为空".to_string());
        }
        let parsed = models
            .iter()
            .filter_map(|(name, value)| {
                let state = value.get("state").and_then(serde_json::Value::as_str);
                let utilization = value.get("utilization").and_then(serde_json::Value::as_f64);
                // 原来写成 state.or(utilization.map(|_| ()))，两个分支类型不同
                // （Option<&str> 对 Option<()>），编译不过。它想表达的是
                // 「两个字段任一存在就保留这条」——不能只看 state：判定要同时用
                // state 和 utilization，只带其中一个的条目也要留下来由判定层决定。
                (state.is_some() || utilization.is_some()).then(|| {
                    (
                        name.clone(),
                        AmdLoadModelEntry::from_upstream(state, utilization),
                    )
                })
            })
            .collect::<BTreeMap<_, _>>();
        if parsed.is_empty() {
            return Err("响应 models 中没有可解析的条目".to_string());
        }
        Ok(Self {
            fetched_at,
            scope: raw
                .get("scope")
                .and_then(serde_json::Value::as_str)
                .unwrap_or_default()
                .to_string(),
            models: parsed,
        })
    }

    /// 快照是否已过期。过期后**不参与判定**（失败开放）。
    pub(crate) fn is_expired(&self, config: &AmdLoadConfig, now_unix_secs: u64) -> bool {
        if self.fetched_at == 0 {
            return true;
        }
        config.snapshot_expired(now_unix_secs, self.fetched_at)
    }

    /// 按当前配置算出应禁用的模型集合。
    ///
    /// 判定顺序（见规划书第 7 节）：
    /// 1. `state == "full"` → 禁用（比百分比更严格）
    /// 2. `utilization >= disable_threshold` 且 `streak >= disable_streak` → 禁用
    /// 3. `utilization <= recovery_threshold` → 放行
    /// 4. 滞回带内 → 沿用上一轮结论
    ///
    /// **阈值在此处、读取时判定**，改配置立即生效，不必等下一轮轮询。
    pub(crate) fn blocked_models(&self, config: &AmdLoadConfig) -> BTreeSet<String> {
        let recovery = config.effective_recovery();
        self.models
            .iter()
            .filter(|(_, entry)| Self::is_blocked(entry, config, recovery))
            .map(|(name, _)| name.clone())
            .collect()
    }

    fn is_blocked(entry: &AmdLoadModelEntry, config: &AmdLoadConfig, recovery: f64) -> bool {
        // 只展示模式下不屏蔽任何模型。快照与 streak 照常计算，面板照常显示占用。
        if !config.block_models {
            return false;
        }
        if entry.state == "full" {
            return true;
        }
        if entry.utilization >= config.disable_threshold {
            return entry.streak >= config.disable_streak;
        }
        if entry.utilization <= recovery {
            return false;
        }
        // 滞回带内：没有新证据，沿用上一轮。
        entry.blocked_prev
    }

    /// 应用全禁保护：该供应商全部模型都被禁时，保留利用率最低的一个。
    ///
    /// 保护只解除「因负载而禁用」，不解除 `state == "full"` 的判定之外的东西——
    /// 若唯一未解除的也是 `full`，则保持全部禁用，交由既有的「无可用候选」路径处理。
    pub(crate) fn apply_all_blocked_guard(&mut self) -> Option<String> {
        if self.models.is_empty() {
            return None;
        }
        let blocked = self
            .models
            .iter()
            .filter(|(_, entry)| entry.blocked_prev)
            .count();
        if blocked < self.models.len() || blocked == 0 {
            return None;
        }
        let lowest = self
            .models
            .iter()
            .min_by(|(_, a), (_, b)| {
                a.utilization
                    .partial_cmp(&b.utilization)
                    .unwrap_or(std::cmp::Ordering::Equal)
            })
            .map(|(name, _)| name.clone())?;
        if let Some(entry) = self.models.get_mut(&lowest) {
            entry.blocked_prev = false;
        }
        Some(lowest)
    }

    /// 面板展示用：当前负载与生效阈值的对照。
    pub(crate) fn describe(&self, config: &AmdLoadConfig) -> Vec<AmdLoadModelStatus> {
        let recovery = config.effective_recovery();
        self.models
            .iter()
            .map(|(name, entry)| {
                let blocked = Self::is_blocked(entry, config, recovery);
                let hysteresis = !config.has_hysteresis()
                    && entry.utilization < config.disable_threshold
                    && entry.utilization > recovery;
                AmdLoadModelStatus {
                    model: name.clone(),
                    state: entry.state.clone(),
                    utilization: entry.utilization,
                    streak: entry.streak,
                    blocked,
                    in_hysteresis_band: hysteresis,
                }
            })
            .collect()
    }
}

/// 面板 / 遥测用的单模型状态。
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub(crate) struct AmdLoadModelStatus {
    pub model: String,
    pub state: String,
    pub utilization: f64,
    pub streak: u32,
    pub blocked: bool,
    /// 单阈值模式下正常不会出现；双阈值下表示落在滞回带里、沿用上轮结论。
    pub in_hysteresis_band: bool,
}

// ---------------------------------------------------------------------------
// Redis 键
// ---------------------------------------------------------------------------

/// 负载快照键。内容是 JSON 字符串——引擎的 Redis 层没有 hash 原语。
pub(crate) fn snapshot_key(provider_id: &str) -> String {
    format!("amd_load:{provider_id}")
}

/// 连续越线计数键。与快照分开存，便于快照过期后计数仍在。
pub(crate) fn streak_key(provider_id: &str) -> String {
    format!("amd_load_streak:{provider_id}")
}

/// 当前 unix 秒。
pub(crate) fn now_unix_secs() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or_default()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn body(models: &str) -> String {
        format!(r#"{{"models":{{{models}}},"scope":"fleet"}}"#)
    }

    fn snapshot(models: &str) -> AmdLoadSnapshot {
        AmdLoadSnapshot::parse_upstream(&body(models), 1_000).expect("parse")
    }

    fn entry(state: &str, utilization: f64) -> AmdLoadModelEntry {
        AmdLoadModelEntry {
            state: state.to_string(),
            utilization,
            streak: 0,
            blocked_prev: false,
        }
    }

    // --- 解析 ---

    #[test]
    fn parses_the_real_upstream_shape() {
        let snap = snapshot(
            r#""DeepSeek-V4-Flash":{"state":"busy","label":"Busy","utilization":77.4},
               "GLM-5.3-Flash":{"state":"full","label":"At capacity","utilization":100.0}"#,
        );
        assert_eq!(snap.scope, "fleet");
        assert_eq!(snap.fetched_at, 1_000);
        assert_eq!(snap.models.len(), 2);
        let flash = &snap.models["DeepSeek-V4-Flash"];
        assert_eq!(flash.state, "busy");
        assert!((flash.utilization - 77.4).abs() < 1e-9);
    }

    /// 实测：模型会在数小时内上下架，某个模型缺失不是异常。
    #[test]
    fn tolerates_a_single_model_being_absent() {
        let snap = snapshot(r#""MiniCPM5-2B":{"state":"idle","utilization":3.1}"#);
        assert_eq!(snap.models.len(), 1);
    }

    #[test]
    fn rejects_structurally_broken_payloads() {
        assert!(AmdLoadSnapshot::parse_upstream("not json", 1).is_err());
        assert!(AmdLoadSnapshot::parse_upstream(r#"{"scope":"fleet"}"#, 1).is_err());
        assert!(AmdLoadSnapshot::parse_upstream(r#"{"models":{}}"#, 1).is_err());
    }

    // --- 判定 ---

    /// 守护判定逻辑本身时用：显式打开禁用开关。
    ///
    /// 这些测试断言的是「打开禁用后阈值/streak/state 各自怎么判」，与默认关闭无关。
    /// 默认关闭的行为由 `default_config_does_not_block_any_model` 单独锁住。
    #[cfg(test)]
    fn blocking_config() -> AmdLoadConfig {
        AmdLoadConfig {
            block_models: true,
            ..AmdLoadConfig::default()
        }
    }

    /// 默认只展示不禁用：满载、越阈、滞回带一律放行。
    ///
    /// 实测（2026-10-02）不支持「按负载禁用能改善首字节」这个前提，所以默认必须
    /// 是不屏蔽。这个测试是那道闸——有人想改回默认开启时，它会先红。
    #[test]
    fn default_config_does_not_block_any_model() {
        let config = AmdLoadConfig::default();
        assert!(!config.block_models);
        // 满载且 100%：老逻辑一定会禁。
        assert!(!AmdLoadSnapshot::is_blocked(
            &entry("full", 100.0),
            &config,
            85.0
        ));
        // 越阈且 streak 已满：老逻辑也一定会禁。
        let mut hot = entry("busy", 99.0);
        hot.streak = 99;
        assert!(!AmdLoadSnapshot::is_blocked(&hot, &config, 85.0));
        // 滞回带内沿用上一轮结论：上一轮禁了也不该再禁。
        let mut carried = entry("busy", 70.0);
        carried.blocked_prev = true;
        assert!(!AmdLoadSnapshot::is_blocked(&carried, &config, 85.0));
        // 面板展示仍然要标出「已禁用」，否则管理员看不到上游给出的 full 状态。
        let mut snap = snapshot(r#""GLM-5.3-Flash":{"state":"full","utilization":100.0}"#);
        snap.models.get_mut("GLM-5.3-Flash").unwrap().blocked_prev = true;
        assert!(snap.blocked_models(&config).is_empty());
    }

    #[test]
    fn state_full_blocks_regardless_of_percentage() {
        // 实测 DeepSeek-V4-Flash-Vision-Exp 曾出现 state=full 但 utilization=80。
        let config = blocking_config();
        let entry = entry("full", 80.0);
        assert!(AmdLoadSnapshot::is_blocked(&entry, &config, 85.0));
    }

    #[test]
    fn below_threshold_passes_in_single_threshold_mode() {
        let config = AmdLoadConfig::default();
        assert!(!AmdLoadSnapshot::is_blocked(
            &entry("busy", 78.6),
            &config,
            85.0
        ));
    }

    #[test]
    fn above_threshold_needs_the_streak() {
        let config = blocking_config(); // disable_streak = 2
        let mut hot = entry("busy", 88.0);
        assert!(!AmdLoadSnapshot::is_blocked(&hot, &config, 85.0));
        hot.streak = 1;
        assert!(!AmdLoadSnapshot::is_blocked(&hot, &config, 85.0));
        hot.streak = 2;
        assert!(AmdLoadSnapshot::is_blocked(&hot, &config, 85.0));
    }

    /// 滞回带内沿用上一轮结论，且改阈值立即生效（不必等下一轮）。
    #[test]
    fn hysteresis_band_keeps_previous_decision() {
        let config = AmdLoadConfig {
            block_models: true,
            disable_threshold: 85.0,
            recovery_threshold: Some(60.0),
            disable_streak: 1,
            ..AmdLoadConfig::default()
        };
        let mut mid = entry("busy", 70.0);
        // 原来写成 !config.has_hysteresis() == false，那恒等于 has_hysteresis()，
        // 绕了一圈却和断言文字表达的是同一件事。
        assert!(config.has_hysteresis(), "应处于滞回模式");

        // 带内、无历史 → 放行
        assert!(!AmdLoadSnapshot::is_blocked(&mid, &config, 60.0));
        // 带内、上轮已禁 → 继续禁
        mid.blocked_prev = true;
        assert!(AmdLoadSnapshot::is_blocked(&mid, &config, 60.0));
        // 掉到恢复线以下 → 立刻放行
        mid.utilization = 55.0;
        assert!(!AmdLoadSnapshot::is_blocked(&mid, &config, 60.0));
    }

    #[test]
    fn expired_snapshot_blocks_nothing() {
        let config = AmdLoadConfig::default(); // ttl 180
        let mut snap = snapshot(r#""GLM-5.3-Flash":{"state":"full","utilization":100.0}"#);
        snap.models.get_mut("GLM-5.3-Flash").unwrap().blocked_prev = true;

        assert!(!snap.is_expired(&config, 1_000));
        assert!(!snap.is_expired(&config, 1_180));
        assert!(snap.is_expired(&config, 1_181));
    }

    #[test]
    fn zero_fetched_at_is_treated_as_expired() {
        let config = AmdLoadConfig::default();
        let mut snap = snapshot(r#""MiniCPM5-2B":{"state":"idle","utilization":1.0}"#);
        snap.fetched_at = 0;
        assert!(snap.is_expired(&config, 1_000));
    }

    // --- 全禁保护 ---

    #[test]
    fn all_blocked_guard_releases_the_least_loaded_model() {
        let mut snap = snapshot(
            r#""A":{"state":"full","utilization":100.0},
               "B":{"state":"full","utilization":100.0}"#,
        );
        for entry in snap.models.values_mut() {
            entry.blocked_prev = true;
        }
        let released = snap.apply_all_blocked_guard();
        assert_eq!(released.as_deref(), Some("A"));
        assert!(!snap.models["A"].blocked_prev);
        assert!(snap.models["B"].blocked_prev);
    }

    #[test]
    fn all_blocked_guard_is_a_no_op_when_something_is_healthy() {
        let mut snap = snapshot(
            r#""A":{"state":"full","utilization":100.0},
               "B":{"state":"idle","utilization":3.1}"#,
        );
        snap.models.get_mut("A").unwrap().blocked_prev = true;
        assert_eq!(snap.apply_all_blocked_guard(), None);
        assert!(snap.models["A"].blocked_prev);
    }

    // --- 描述 ---

    #[test]
    fn describe_reports_blocked_state_for_the_panel() {
        let mut snap = snapshot(
            r#""GLM-5.3-Flash":{"state":"full","utilization":100.0},
               "MiniCPM5-2B":{"state":"idle","utilization":3.1}"#,
        );
        snap.models.get_mut("GLM-5.3-Flash").unwrap().blocked_prev = true;
        let described = snap.describe(&blocking_config());
        let by_model = described
            .iter()
            .map(|status| (status.model.as_str(), status.blocked))
            .collect::<std::collections::BTreeMap<_, _>>();
        assert!(by_model["GLM-5.3-Flash"]);
        assert!(!by_model["MiniCPM5-2B"]);
    }

    #[test]
    fn keys_are_provider_scoped() {
        assert_eq!(snapshot_key("abc"), "amd_load:abc");
        assert_eq!(streak_key("abc"), "amd_load_streak:abc");
        assert_ne!(snapshot_key("a"), snapshot_key("b"));
    }
}
