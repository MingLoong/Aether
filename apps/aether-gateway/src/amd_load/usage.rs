//! AMD 账号配额快照。
//!
//! 数据源：`GET {origin}/v1/usage`（同一个 Bearer key）。
//!
//! ## 接口里哪些字段能用，哪些不能
//!
//! 实测（2026-10-02，10 个账号逐个查过）：
//!
//! ```text
//! daily_cost_limit_usd      1     ← 真实，恒为 1
//! daily_cost_used_usd       0     ← 死字段：65 分钟、69 次请求之后仍是 0
//! daily_cost_remaining_usd  1     ← 死字段：恒等于限额，不是真实余额
//! daily_reset_timezone      null  ← 未实现
//! daily_reset_epoch         null  ← 未实现
//! period_started_at         null  ← 未实现
//! today.cost                0.0029 ← 真实
//! rpm_limit                 20    ← 真实
//! ```
//!
//! 所以**余额不能展示，也不能用来自动停用**——那会在真正撞满时撒谎（`remaining` 仍
//! 显示满额）。能算的是**用量比例**：`today.cost / daily_cost_limit_usd`。分子分母都
//! 是真值，比 `daily_cost_remaining_usd` 可靠。
//!
//! ## 最有价值的是 by_model.errors
//!
//! 那不是推断出来的「模型满了」，而是 AMD 自己记的失败数。按错误率排序就能知道哪
//! 个模型真的在挂，比 `utilization` 直接得多。

use serde::{Deserialize, Serialize};

/// 一段窗口内的用量统计（`today` / `last_24_hours` / `all_time` 是同一个形状）。
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
pub(crate) struct AmdUsageWindow {
    #[serde(default)]
    pub requests: u64,
    #[serde(default)]
    pub errors: u64,
    #[serde(default)]
    pub total_tokens: u64,
    #[serde(default)]
    pub cost: f64,
    /// KV 命中率，0~1。只有 `all_time` 稳定有值。
    #[serde(default)]
    pub kv_cache_hit_rate: Option<f64>,
    #[serde(default)]
    pub last_request_at: Option<String>,
}

impl AmdUsageWindow {
    /// 错误率。分母为 0 时返回 0——没有请求就没有错误，不该显示成「100% 错误」。
    pub(crate) fn error_rate(&self) -> f64 {
        if self.requests == 0 {
            return 0.0;
        }
        self.errors as f64 / self.requests as f64 * 100.0
    }
}

/// 单个模型的用量。字段名与上游一致。
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
pub(crate) struct AmdUsageByModel {
    pub model: String,
    #[serde(default)]
    pub requests: u64,
    #[serde(default)]
    pub errors: u64,
    #[serde(default)]
    pub cost: f64,
}

/// 配额快照。
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
pub(crate) struct AmdUsageSnapshot {
    /// 采集时刻（unix 秒）。
    ///
    /// **这是我们自己加的字段，上游响应里没有。** 必须 `default`，否则整个响应会直接
    /// 反序列化失败——本文件的测试最初就抓到这个问题。
    #[serde(default)]
    pub fetched_at: u64,

    // —— 以下为可信字段 ——
    /// 日限额（美元）。上游恒为 1，但要真值才能算比例。
    pub daily_cost_limit_usd: Option<f64>,
    pub rpm_limit: Option<u64>,
    /// 上游可能省略任一窗口，`default` 兜住而不是让整个解析失败。
    #[serde(default)]
    pub today: AmdUsageWindow,
    #[serde(default)]
    pub last_24_hours: AmdUsageWindow,
    #[serde(default)]
    pub all_time: AmdUsageWindow,
    /// 上游是数组；缺失时给空 vec。
    #[serde(default)]
    pub by_model: Vec<AmdUsageByModel>,

    // —— 以下为上游未实现的字段，留着是为了在面板上显式说明「别指望它们」——
    /// 恒为 0。见文件头说明。
    pub daily_cost_used_usd: Option<f64>,
    /// 恒等于限额，不是真实余额。见文件头说明。
    pub daily_cost_remaining_usd: Option<f64>,
}

impl AmdUsageSnapshot {
    /// **用量比例 0~1**：`today.cost / daily_cost_limit_usd`。
    ///
    /// 分母缺失时返回 `None` 而不是 0——「限额未知」和「没用过」必须能区分，混成 0
    /// 会让界面显示「用了 0%」，看起来一切正常。
    pub(crate) fn usage_ratio(&self) -> Option<f64> {
        let limit = self.daily_cost_limit_usd?;
        if limit <= 0.0 {
            return None;
        }
        Some(self.today.cost / limit)
    }

    /// 按错误率排序的模型，越高越前。只列出有过请求的。
    ///
    /// 这是整份快照里最该看的一栏：它是 AMD 自己记的失败，不是我们从 `utilization`
    /// 推断出来的。实测里唯一出错的模型错误率就是 20%，其余全是 0%。
    pub(crate) fn models_by_error_rate(&self) -> Vec<&AmdUsageByModel> {
        let mut models: Vec<&AmdUsageByModel> = self
            .by_model
            .iter()
            .filter(|entry| entry.requests > 0)
            .collect();
        // 先按错误率降序，再按请求数降序：同样 0% 错误时请求多的排前面，符合直觉。
        models.sort_by(|a, b| {
            let ra = if a.requests == 0 {
                0.0
            } else {
                a.errors as f64 / a.requests as f64
            };
            let rb = if b.requests == 0 {
                0.0
            } else {
                b.errors as f64 / b.requests as f64
            };
            rb.partial_cmp(&ra)
                .unwrap_or(std::cmp::Ordering::Equal)
                .then(b.requests.cmp(&a.requests))
        });
        models
    }

    /// 解析上游响应。
    ///
    /// `by_model` 是数组而非对象，直接 `serde(default)` 兜住缺失，避免上游改结构时整个
    /// 轮询崩掉。
    pub(crate) fn parse_upstream(body: &str, fetched_at: u64) -> Result<Self, String> {
        serde_json::from_str::<Self>(body)
            .map(|mut snapshot| {
                snapshot.fetched_at = fetched_at;
                snapshot
            })
            .map_err(|err| format!("解析 /v1/usage 失败：{err}"))
    }

    /// 面板展示用：把死字段的问题直接写成文字，而不是让用户自己去发现数字不对。
    pub(crate) fn untrustworthy_fields(&self) -> Vec<String> {
        let mut notes = Vec::new();
        if self.daily_cost_used_usd == Some(0.0) {
            notes.push("daily_cost_used_usd 恒为 0（上游未实现），不能当作已用额度".to_string());
        }
        if let (Some(limit), Some(remaining)) =
            (self.daily_cost_limit_usd, self.daily_cost_remaining_usd)
        {
            if (limit - remaining).abs() < f64::EPSILON {
                notes.push(
                    "daily_cost_remaining_usd 恒等于限额（上游未实现），不能当作真实余额"
                        .to_string(),
                );
            }
        }
        notes
    }
}

/// Redis 键。
pub(crate) fn usage_key(provider_id: &str) -> String {
    format!("amd_usage:{provider_id}")
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample() -> &'static str {
        r#"{
          "daily_cost_limit_usd": 1,
          "daily_cost_used_usd": 0,
          "daily_cost_remaining_usd": 1,
          "rpm_limit": 20,
          "today": {"requests": 69, "errors": 1, "cost": 0.0028865330386906862, "total_tokens": 100},
          "last_24_hours": {"requests": 33, "errors": 3, "cost": 0.00084},
          "all_time": {"requests": 365, "errors": 36, "cost": 0.7266, "kv_cache_hit_rate": 0.7417},
          "by_model": [
            {"model": "DeepSeek-V4.1-Flash", "requests": 20, "errors": 4, "cost": 0.00001},
            {"model": "MiniCPM5-2B", "requests": 21, "errors": 0, "cost": 0.00024},
            {"model": "DeepSeek-V4-Flash", "requests": 19, "errors": 0, "cost": 0.00003}
          ]
        }"#
    }

    #[test]
    fn parses_real_response_shape() {
        let snapshot = AmdUsageSnapshot::parse_upstream(sample(), 1_700_000_000).unwrap();
        assert_eq!(snapshot.daily_cost_limit_usd, Some(1.0));
        assert_eq!(snapshot.rpm_limit, Some(20));
        assert_eq!(snapshot.today.requests, 69);
        assert_eq!(snapshot.all_time.errors, 36);
        assert_eq!(snapshot.by_model.len(), 3);
        assert_eq!(snapshot.fetched_at, 1_700_000_000);
    }

    /// 用量比例是真值算出来的，不依赖那两个死字段。
    #[test]
    fn usage_ratio_uses_today_cost_over_limit() {
        let snapshot = AmdUsageSnapshot::parse_upstream(sample(), 0).unwrap();
        let ratio = snapshot.usage_ratio().unwrap();
        assert!((ratio - 0.0028865330386906862).abs() < 1e-12);
    }

    /// 限额缺失时必须返回 None，不能返回 0——「不知道」和「没用过」要能区分。
    #[test]
    fn usage_ratio_is_none_when_limit_unknown() {
        let mut snapshot = AmdUsageSnapshot::parse_upstream(sample(), 0).unwrap();
        snapshot.daily_cost_limit_usd = None;
        assert_eq!(snapshot.usage_ratio(), None);

        snapshot.daily_cost_limit_usd = Some(0.0);
        assert_eq!(snapshot.usage_ratio(), None);
    }

    /// 错误率排序是这栏的核心：唯一出错的模型必须排第一。
    #[test]
    fn models_sorted_by_error_rate_desc() {
        let snapshot = AmdUsageSnapshot::parse_upstream(sample(), 0).unwrap();
        let ordered: Vec<&str> = snapshot
            .models_by_error_rate()
            .iter()
            .map(|entry| entry.model.as_str())
            .collect();
        assert_eq!(ordered[0], "DeepSeek-V4.1-Flash");
        // 剩下两个都是 0% 错误，按请求数降序：21 > 19
        assert_eq!(ordered[1], "MiniCPM5-2B");
        assert_eq!(ordered[2], "DeepSeek-V4-Flash");
    }

    /// 死字段必须在快照里显式标注，否则面板上那两个数字会误导人。
    #[test]
    fn flags_upstream_unimplemented_fields() {
        let snapshot = AmdUsageSnapshot::parse_upstream(sample(), 0).unwrap();
        let notes = snapshot.untrustworthy_fields();
        assert_eq!(notes.len(), 2, "应同时标注 used 与 remaining：{notes:?}");
        assert!(notes.iter().any(|n| n.contains("daily_cost_used_usd")));
        assert!(notes.iter().any(|n| n.contains("daily_cost_remaining_usd")));
    }

    /// 上游改了结构时不能崩——整个轮询会因为一个字段缺失而挂掉。
    #[test]
    fn tolerates_missing_optional_fields() {
        let snapshot = AmdUsageSnapshot::parse_upstream(r#"{"today":{"requests":3}}"#, 0).unwrap();
        assert_eq!(snapshot.today.requests, 3);
        assert_eq!(snapshot.by_model.len(), 0);
        assert_eq!(snapshot.usage_ratio(), None);
        // 没有 dead 字段可标注，不应凭空造一条。
        assert!(snapshot.untrustworthy_fields().is_empty());
    }

    #[test]
    fn error_rate_is_zero_when_no_requests() {
        let window = AmdUsageWindow::default();
        assert_eq!(window.error_rate(), 0.0, "没有请求不等于 100% 错误");
    }

    #[test]
    fn usage_key_is_provider_scoped() {
        assert_ne!(usage_key("a"), usage_key("b"));
        assert!(usage_key("a").contains("a"));
    }
}
