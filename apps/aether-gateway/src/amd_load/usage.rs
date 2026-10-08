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

/// 单个账号的窗口集合。每个 key 一份。
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
pub(crate) struct AmdUsageWindowSet {
    /// 采集时刻。**这是我们自己加的字段，上游响应里没有**，必须 `default`。
    ///
    /// 这个坑踩过一次：从旧的单账号结构搬过来时漏标，导致每个账号的 `/v1/usage` 响应
    /// 都反序列化失败，10 个账号的用量一个都拿不到。下面的
    /// `tolerates_missing_optional_fields` 就是为它留的。
    #[serde(default)]
    pub fetched_at: u64,
    pub daily_cost_limit_usd: Option<f64>,
    pub rpm_limit: Option<u64>,
    #[serde(default)]
    pub today: AmdUsageWindow,
    #[serde(default)]
    pub last_24_hours: AmdUsageWindow,
    #[serde(default)]
    pub all_time: AmdUsageWindow,
    #[serde(default)]
    pub by_model: Vec<AmdUsageByModel>,
    #[serde(default)]
    pub daily_cost_used_usd: Option<f64>,
    #[serde(default)]
    pub daily_cost_remaining_usd: Option<f64>,
}

impl AmdUsageWindowSet {
    pub(crate) fn usage_ratio(&self) -> Option<f64> {
        let limit = self.daily_cost_limit_usd?;
        if limit <= 0.0 {
            return None;
        }
        Some(self.today.cost / limit)
    }

    pub(crate) fn models_by_error_rate(&self) -> Vec<&AmdUsageByModel> {
        let mut models: Vec<&AmdUsageByModel> =
            self.by_model.iter().filter(|e| e.requests > 0).collect();
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
}

/// 单个账号（key）的采集结果。
///
/// **必须逐 key 采集**：10 个 key 就是 10 个独立 AMD 账号（实测 10 个互不相同的
/// `organization_id`，各 85~440 次累计请求不等），各有独立的日限额。只抓第一把会漏掉
/// 其余 9 个——而额度管理的全部意义就是「别让某个账号撞满」。
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
pub(crate) struct AmdUsageAccount {
    /// 面板显示名（key 的 name，如「账号1」）。
    pub key_name: String,
    pub key_id: String,
    /// 上游 organization_id，账号的真实标识。用于判断两把 key 是不是同一个账号——
    /// 同账号多 key 时只拉一次，避免重复计入 RPM。
    pub organization_id: Option<String>,
    /// 该账号的用量。**拉取失败时为 None**，界面显示「拉取失败」而不是显示 0——
    /// 0 和「没查到」是两件事，混淆会让额度面板在最需要它的时候撒谎。
    pub usage: Option<AmdUsageWindowSet>,
    /// 该 key 是否因为 organization_id 与前面某把重复而未发起请求。
    #[serde(default)]
    pub deduped: bool,
    /// 失败原因（可含上游状态码），成功时为空。
    #[serde(default)]
    pub error: Option<String>,
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

    /// **逐账号采集结果。** 10 个 key 就有 10 条。
    #[serde(default)]
    pub accounts: Vec<AmdUsageAccount>,
    /// 本轮实际发起的 HTTP 请求数（去重后）。
    #[serde(default)]
    pub fetched_requests: u32,
    /// 本轮失败的账号数。
    #[serde(default)]
    pub failed_accounts: u32,
    /// 因 organization_id 重复而跳过请求的 key 数。
    #[serde(default)]
    pub deduped_keys: u32,
}

impl AmdUsageSnapshot {
    /// 各账号，按 key 的配置顺序返回。
    ///
    /// **刻意不按用量排序。** 用量每天都在变，按它排会让 10 行在每次刷新时跳来跳去——
    /// 第 3 行这次是「账号3」、下次变成「账号7」，没人能记住哪个位置对应哪个账号。
    /// key 顺序稳定，管理员扫一眼就能定位到自己关心的那个。
    ///
    pub(crate) fn accounts_in_key_order(&self) -> Vec<&AmdUsageAccount> {
        self.accounts.iter().collect()
    }

    /// 今日消费合计。只统计拉到数据的账号——失败的不按 0 算，否则会把「没查到」误
    /// 当成「没花钱」，那正是额度面板最不能犯的错。
    pub(crate) fn total_today_cost(&self) -> f64 {
        self.accounts
            .iter()
            .filter_map(|a| a.usage.as_ref().map(|u| u.today.cost))
            .sum()
    }

    pub(crate) fn total_today_requests(&self) -> u64 {
        self.accounts
            .iter()
            .filter_map(|a| a.usage.as_ref().map(|u| u.today.requests))
            .sum()
    }

    pub(crate) fn total_today_errors(&self) -> u64 {
        self.accounts
            .iter()
            .filter_map(|a| a.usage.as_ref().map(|u| u.today.errors))
            .sum()
    }

    /// 从单个 key 的 `/v1/usage` 响应构造窗口集合。
    pub(crate) fn parse_account_usage(
        body: &str,
        fetched_at: u64,
    ) -> Result<AmdUsageWindowSet, String> {
        serde_json::from_str(body)
            .map(|mut set: AmdUsageWindowSet| {
                set.fetched_at = fetched_at;
                set
            })
            .map_err(|err| format!("解析 /v1/usage 失败：{err}"))
    }

    /// 从响应里取 organization_id，用于同账号去重。解析失败返回 None（不去重）。
    pub(crate) fn extract_organization_id(body: &str) -> Option<String> {
        serde_json::from_str::<serde_json::Value>(body)
            .ok()?
            .get("organization_id")?
            .as_str()
            .map(str::to_string)
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

    /// 用真实响应形状解析（实测自 oneclick-org-20485）。
    #[test]
    fn parses_real_response_shape() {
        let set = AmdUsageSnapshot::parse_account_usage(sample(), 1_700_000_000).unwrap();
        assert_eq!(set.daily_cost_limit_usd, Some(1.0));
        assert_eq!(set.rpm_limit, Some(20));
        assert_eq!(set.today.requests, 69);
        assert_eq!(set.all_time.errors, 36);
        assert_eq!(set.by_model.len(), 3);
        assert_eq!(set.fetched_at, 1_700_000_000);
    }

    /// 用量比例是真值算出来的，不依赖那两个死字段。
    #[test]
    fn usage_ratio_uses_today_cost_over_limit() {
        let set = AmdUsageSnapshot::parse_account_usage(sample(), 0).unwrap();
        let ratio = set.usage_ratio().unwrap();
        assert!((ratio - 0.0028865330386906862).abs() < 1e-12);
    }

    /// 限额缺失时必须返回 None，不能返回 0——「不知道」和「没用过」要能区分。
    #[test]
    fn usage_ratio_is_none_when_limit_unknown() {
        let mut set = AmdUsageSnapshot::parse_account_usage(sample(), 0).unwrap();
        set.daily_cost_limit_usd = None;
        assert_eq!(set.usage_ratio(), None);

        set.daily_cost_limit_usd = Some(0.0);
        assert_eq!(set.usage_ratio(), None);
    }

    /// 错误率排序是这栏的核心：唯一出错的模型必须排第一。
    #[test]
    fn models_sorted_by_error_rate_desc() {
        let set = AmdUsageSnapshot::parse_account_usage(sample(), 0).unwrap();
        let ordered: Vec<&str> = set
            .models_by_error_rate()
            .iter()
            .map(|entry| entry.model.as_str())
            .collect();
        assert_eq!(ordered[0], "DeepSeek-V4.1-Flash");
        // 剩下两个都是 0% 错误，按请求数降序：21 > 19
        assert_eq!(ordered[1], "MiniCPM5-2B");
        assert_eq!(ordered[2], "DeepSeek-V4-Flash");
    }

    /// 死字段照实回传：上游确实有这两个字段，藏起来会让人以为是我们读错了。
    #[test]
    fn keeps_unimplemented_fields_as_returned() {
        let set = AmdUsageSnapshot::parse_account_usage(sample(), 0).unwrap();
        assert_eq!(
            set.daily_cost_used_usd,
            Some(0.0),
            "上游确实返回了这个死字段"
        );
        assert_eq!(
            set.daily_cost_remaining_usd,
            Some(1.0),
            "恒等于限额，不是真实余额"
        );
    }

    /// 上游改了结构时不能崩——整个轮询会因为一个字段缺失而挂掉。
    ///
    /// `fetched_at` 是我们自己加的、上游没有的字段。它曾经漏标 `default`，结果**每个账号
    /// 的用量都拉不到**，而症状只是「列表空着」——很难一眼看出是序列化问题。所以这里
    /// 显式断言：响应里没有该字段时必须照样解析成功。
    #[test]
    fn tolerates_missing_optional_fields() {
        // 刻意不含 fetched_at：这是上游本来就没有的字段
        let set =
            AmdUsageSnapshot::parse_account_usage(r#"{"today":{"requests":3},"by_model":[]}"#, 42)
                .expect("上游没有 fetched_at 也必须解析成功");
        assert_eq!(set.today.requests, 3);
        assert!(set.by_model.is_empty());
        assert_eq!(set.fetched_at, 42, "采集时刻由我们自己填，不来自上游");
        assert_eq!(set.usage_ratio(), None);

        // 只剩一个空对象时也不能崩
        let empty = AmdUsageSnapshot::parse_account_usage("{}", 1).unwrap();
        assert_eq!(empty.today.requests, 0);
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

    /// organization_id 是同账号去重的依据，必须真的能从响应里取出来。
    ///
    /// 取不到就退化成 10 次重复请求，白白消耗 rpm_limit（20/分钟）。
    #[test]
    fn extracts_organization_id_from_real_response() {
        let body = r#"{"organization_id":"oneclick-org-20485","rpm_limit":20}"#;
        assert_eq!(
            AmdUsageSnapshot::extract_organization_id(body).as_deref(),
            Some("oneclick-org-20485")
        );
        // 没有该字段时返回 None（不去重，而不是误判成同账号）
        assert_eq!(
            AmdUsageSnapshot::extract_organization_id(r#"{"rpm_limit":20}"#),
            None
        );
        // 坏 JSON 也不能 panic
        assert_eq!(AmdUsageSnapshot::extract_organization_id("not json"), None);
    }

    /// 展示顺序必须是 key 的配置顺序，不能按用量排。
    ///
    /// 用量每天都在变，按它排会让 10 行在每次刷新时跳来跳去——第 3 行这次是「账号3」、
    /// 下次变成「账号7」，没人能记住哪个位置对应哪个账号。
    #[test]
    fn accounts_keep_key_order_not_usage_order() {
        let account = |name: &str, cost: f64| AmdUsageAccount {
            key_name: name.to_string(),
            key_id: format!("k-{name}"),
            organization_id: None,
            usage: Some(AmdUsageWindowSet {
                today: AmdUsageWindow {
                    requests: 1,
                    cost,
                    ..Default::default()
                },
                daily_cost_limit_usd: Some(1.0),
                ..Default::default()
            }),
            deduped: false,
            error: None,
        };
        let snapshot = AmdUsageSnapshot {
            fetched_at: 0,
            accounts: vec![
                account("账号1", 0.001),
                // 故意让后一个账号用量更高：排序若按用量就会把它换到前面。
                account("账号2", 0.9),
            ],
            fetched_requests: 2,
            failed_accounts: 0,
            deduped_keys: 0,
        };

        let names: Vec<&str> = snapshot
            .accounts_in_key_order()
            .iter()
            .map(|a| a.key_name.as_str())
            .collect();
        assert_eq!(names, vec!["账号1", "账号2"], "必须保持 key 配置顺序");
    }

    /// 拉取失败的账号必须留在自己的位置上，不能被挪到前面或末尾。
    #[test]
    fn failed_account_keeps_its_position_in_key_order() {
        let ok = |name: &str, cost: f64| AmdUsageAccount {
            key_name: name.to_string(),
            key_id: format!("k-{name}"),
            organization_id: None,
            usage: Some(AmdUsageWindowSet {
                today: AmdUsageWindow {
                    cost,
                    ..Default::default()
                },
                daily_cost_limit_usd: Some(1.0),
                ..Default::default()
            }),
            deduped: false,
            error: None,
        };
        let snapshot = AmdUsageSnapshot {
            fetched_at: 0,
            accounts: vec![
                ok("正常的", 0.5),
                AmdUsageAccount {
                    key_name: "失败的".to_string(),
                    key_id: "k-fail".to_string(),
                    organization_id: None,
                    usage: None,
                    deduped: false,
                    error: Some("HTTP 500".to_string()),
                },
            ],
            fetched_requests: 2,
            failed_accounts: 1,
            deduped_keys: 0,
        };
        // 顺序仍按配置，失败账号不被顶到前面或推到最后
        let names: Vec<&str> = snapshot
            .accounts_in_key_order()
            .iter()
            .map(|a| a.key_name.as_str())
            .collect();
        assert_eq!(names, vec!["正常的", "失败的"]);
    }

    /// 10 个 key = 10 个独立账号，这是本轮改动的前提。若将来上游改成同账号共享，去重逻辑
    /// 才生效；这里锁定「逐账号独立采集」这个行为。
    #[test]
    fn accounts_are_collected_independently() {
        let body = r#"{
          "organization_id": "oneclick-org-20485",
          "daily_cost_limit_usd": 1,
          "rpm_limit": 20,
          "today": {"requests": 5, "errors": 0, "cost": 0.0001},
          "all_time": {"requests": 440, "errors": 37, "cost": 0.7296}
        }"#;
        let set = AmdUsageSnapshot::parse_account_usage(body, 1_700_000_000).unwrap();
        let snapshot = AmdUsageSnapshot {
            fetched_at: 1_700_000_000,
            accounts: vec![
                AmdUsageAccount {
                    key_name: "账号1".to_string(),
                    key_id: "k1".to_string(),
                    organization_id: Some("oneclick-org-20485".to_string()),
                    usage: Some(set.clone()),
                    deduped: false,
                    error: None,
                },
                AmdUsageAccount {
                    key_name: "账号2".to_string(),
                    key_id: "k2".to_string(),
                    organization_id: Some("oneclick-org-20491".to_string()),
                    usage: Some(AmdUsageWindowSet {
                        today: AmdUsageWindow {
                            requests: 9,
                            cost: 0.004,
                            ..Default::default()
                        },
                        daily_cost_limit_usd: Some(1.0),
                        ..Default::default()
                    }),
                    deduped: false,
                    error: None,
                },
            ],
            fetched_requests: 2,
            failed_accounts: 0,
            deduped_keys: 0,
        };

        // 两个账号都要在，不能只剩第一把
        assert_eq!(snapshot.accounts.len(), 2);
        // 展示顺序保持 key 配置顺序
        let ordered: Vec<&str> = snapshot
            .accounts_in_key_order()
            .iter()
            .map(|a| a.key_name.as_str())
            .collect();
        assert_eq!(ordered, vec!["账号1", "账号2"]);

        // 合计只算拉到数据的账号
        assert!((snapshot.total_today_cost() - 0.0041).abs() < 1e-9);
        assert_eq!(snapshot.total_today_requests(), 14);
    }

    /// 拉取失败的账号不计入合计，且不被当成「最危险」。
    ///
    /// 把失败当 0 会让「今天花了 0.01 美元」显示成实际值，可一旦那个账号其实花了很多，
    /// 面板就会给出危险的错误结论——额度面板最不能犯的错。
    #[test]
    fn failed_accounts_keep_position_and_are_excluded_from_totals() {
        let ok = AmdUsageWindowSet {
            today: AmdUsageWindow {
                requests: 3,
                cost: 0.01,
                ..Default::default()
            },
            daily_cost_limit_usd: Some(1.0),
            ..Default::default()
        };
        let snapshot = AmdUsageSnapshot {
            fetched_at: 0,
            accounts: vec![
                AmdUsageAccount {
                    key_name: "失败的".to_string(),
                    key_id: "k1".to_string(),
                    organization_id: None,
                    usage: None,
                    deduped: false,
                    error: Some("HTTP 500".to_string()),
                },
                AmdUsageAccount {
                    key_name: "正常的".to_string(),
                    key_id: "k2".to_string(),
                    organization_id: Some("org-2".to_string()),
                    usage: Some(ok),
                    deduped: false,
                    error: None,
                },
            ],
            fetched_requests: 2,
            failed_accounts: 1,
            deduped_keys: 0,
        };

        let ordered: Vec<&str> = snapshot
            .accounts_in_key_order()
            .iter()
            .map(|a| a.key_name.as_str())
            .collect();
        assert_eq!(
            ordered,
            vec!["失败的", "正常的"],
            "保持配置顺序，不因失败而重排"
        );
        // 失败的账号不按 0 计入合计
        assert!((snapshot.total_today_cost() - 0.01).abs() < 1e-9);
        assert_eq!(snapshot.total_today_requests(), 3);
        assert_eq!(snapshot.failed_accounts, 1);
    }

    /// 去重标记要能让界面区分「独立账号」与「同账号的第二把 key」。
    #[test]
    fn deduped_key_carries_copied_usage() {
        let set = AmdUsageWindowSet {
            today: AmdUsageWindow {
                requests: 7,
                ..Default::default()
            },
            daily_cost_limit_usd: Some(1.0),
            ..Default::default()
        };
        let snapshot = AmdUsageSnapshot {
            fetched_at: 0,
            accounts: vec![AmdUsageAccount {
                key_name: "账号1-副本".to_string(),
                key_id: "k2".to_string(),
                organization_id: Some("org-1".to_string()),
                usage: Some(set),
                deduped: true,
                error: None,
            }],
            fetched_requests: 0,
            failed_accounts: 0,
            deduped_keys: 1,
        };
        assert!(snapshot.accounts[0].deduped);
        assert_eq!(snapshot.deduped_keys, 1);
        assert_eq!(snapshot.fetched_requests, 0, "去重后不应计入实际请求数");
    }
}
