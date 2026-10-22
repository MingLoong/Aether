//! OpenCode 前置代理出口 IP 池扫描运行时。
//!
//! 与 MingLoong/Aether 参考实现的关键差异：**出口 IP 的唯一来源是 key 的
//! `upstream_metadata.opencode_exit_ip`**，而不是把 IP 明文塞进 `api_key`。
//! 池 key 的 `api_key` 只是一个唯一占位值（`public-<ip>`），因为 OpenCode 免费层
//! 认证固定为 `Bearer public`，由传输层强制注入。
//!
//! 扫描器从显式 CIDR 列表枚举候选 IP，对 `ip:port` 做裸 TLS 握手（SNI = 上游域名），
//! 再发一条带 OpenCode 指纹的 `GET /inference/v1/models`，2xx/3xx 视为健康；健康的新 IP
//! 会被物化成池 key，清理轮次会删除探测失败的陈旧 key。

use std::collections::{BTreeMap, BTreeSet};
use std::io::{Read, Write};
use std::net::IpAddr;
use std::sync::{Arc, Mutex, OnceLock};

use aether_data_contracts::repository::provider_catalog::{
    ProviderCatalogProviderConfigCasUpdate, StoredProviderCatalogKey, StoredProviderCatalogProvider,
};
use serde_json::{json, Value};

use crate::{AppState, GatewayError};

/// 单次探测（TCP + TLS + 首字节）的超时秒数。
pub(crate) const OPENCODE_PROBE_TIMEOUT_SECS: u64 = 4;

/// 验健康采样时的单次超时。给得比粗筛宽，因为这里要测的正是
/// 「这个节点到底能忍多久」——把它和粗筛用同一个超时，等于在
/// 还没量出真实耗时前就先把慢节点当成失败。
const VERIFY_PROBE_TIMEOUT_SECS: u64 = 15;

/// A node that answers the round trip this quickly is fast enough to keep.
///
/// The probe only measures "can we connect, complete a handshake and get a
/// response" — every reachable node passes that, including nodes that then take
/// 100–200s to answer a real request. Measured on this deployment: the pool
/// held nodes spanning 8s to 201s for a 150K-token request, and every one of
/// them passed the scan. Thresholding the probe keeps the obvious laggards out.
///
/// **This applies to scanning only.** Verification measures the same round trip
/// but judges it against its own budget; pre-filtering here would discard nodes
/// before their latency is ever recorded.
const OPENCODE_PROBE_MAX_HANDSHAKE_MS: u128 = 800;
const OPENCODE_PROBE_MAX_HANDSHAKE_ENV: &str = "OPENCODE_PROBE_MAX_HANDSHAKE_MS";
/// Provider 级阈值配置的合法区间（毫秒）。
///
/// 下限挡住「填 0/个位数把整池判空」，上限 60s 与单次探测超时
/// （[`OPENCODE_PROBE_TIMEOUT_SECS`] = 4s）刻意留出量级差——阈值一旦超过探测超时，
/// 这个快筛就不再筛任何东西，等于「只要连得上就算通过」。
pub(crate) const OPENCODE_PROBE_MIN_HANDSHAKE_MS: u64 = 100;
pub(crate) const OPENCODE_PROBE_MAX_HANDSHAKE_MS_LIMIT: u64 = 60_000;
/// 单次域名解析的超时（秒）。
///
/// `tokio::net::lookup_host` 自身没有超时：解析器卡住时这个 await 永不返回，扫描会
/// 永远停在“候选来源”这一步，`scanning` 标志随之永久为 true，之后所有扫描/复验都被
/// 守卫挡成 400（2026-10-18 实测踩到一次）。这里给每次解析兜一个上限。
const DNS_LOOKUP_TIMEOUT_SECS: u64 = 5;
/// 扫描游标存活时长的下限：即使没配自动间隔（只手动扫），也要够跨天补扫。
pub(crate) const OPENCODE_SCAN_CURSOR_MIN_TTL_SECONDS: u64 = 7 * 24 * 60 * 60;
/// 单轮扫描候选上限可配置后的硬上限（安全阀，防止一次切片把内存和进度计数打爆）。
pub(crate) const OPENCODE_SCAN_MAX_CANDIDATES_LIMIT: usize = 65_536;

fn probe_max_round_trip_ms() -> u128 {
    std::env::var(OPENCODE_PROBE_MAX_HANDSHAKE_ENV)
        .ok()
        .and_then(|raw| raw.trim().parse::<u128>().ok())
        .filter(|value| *value > 0)
        .unwrap_or(OPENCODE_PROBE_MAX_HANDSHAKE_MS)
}
/// 未配置时每轮扫描的默认并发。
pub(crate) const OPENCODE_SCAN_DEFAULT_CONCURRENCY: usize = 32;
/// 并发硬上限（安全阀）。
pub(crate) const OPENCODE_SCAN_MAX_CONCURRENCY: usize = 128;
/// 单轮扫描的候选 IP 上限。
pub(crate) const OPENCODE_SCAN_MAX_CANDIDATES: usize = 4096;
/// 池 key 上记录出口 IP 的 metadata 字段名。
///
/// 仍然需要：线上已有一批「一 IP 一 key」的历史密钥，靠这个字段识别它们的出口 IP
/// （`opencode_pool_key_ip`）。新扫描**不再**创建这类密钥。
const OPENCODE_EXIT_IP_METADATA_KEY: &str = "opencode_exit_ip";

/// 默认保底池大小：低于这个数量，任何机制都不允许把池子变小。
///
/// 会话粘性和被动降权的收益随池增大而升高，风险却随池减小而放大：
/// 三个节点的池子里冷却掉一个就只剩两个，一个设备锁死一个节点就没有
/// 分散可言。所以保底是硬约束，不提供关闭开关。
pub(crate) use crate::opencode_rotation::OPENCODE_DEFAULT_MIN_POOL_SIZE;
/// 会话粘性的最小可用池：低于此数量自动退回游标轮转。
pub(crate) use crate::opencode_rotation::OPENCODE_DEFAULT_STICKY_MIN_POOL;
/// 验健康的默认采样次数。
pub(crate) const OPENCODE_DEFAULT_VERIFY_SAMPLES: usize = 3;
/// 验健康的默认首字节中位数上限（毫秒）。
///
/// 对照实测：CloudFront 节点 6~9.5 秒，钉错的国内节点 92~201 秒。
/// 10 秒能把后者全挡掉，同时给前者留出余量。
pub(crate) const OPENCODE_DEFAULT_VERIFY_MAX_MEDIAN_MS: u64 = 10_000;

/// 各可写数值的合法区间。越界一律拒绝，不静默改写。
///
/// 之前没有上界，`min_pool_size: 999999999` 能原样落库且返回
/// `saved: true`。它的后果不是「阈值很严」而是**淘汰机制彻底失效**：
/// `kept.len() < min_pool_size` 恒成立，保底逻辑会把每个待淘汰节点都捞回来，
/// 于是复验再也不会剔除任何节点，而界面上看不出任何异常。
pub(crate) const OPENCODE_MAX_MIN_POOL_SIZE: usize = 512;
/// 采样次数上限。3 次已能压住抖动，再高只是把一轮复验的探测量线性放大。
pub(crate) const OPENCODE_MAX_VERIFY_SAMPLES: usize = 10;
/// 中位数阈值的上限：10 分钟。再大就失去了「慢节点」的意义。
pub(crate) const OPENCODE_MAX_VERIFY_MAX_MEDIAN_MS: u64 = 600_000;
/// 复验间隔上限（小时）：一年。`0` 是合法值，表示不自动执行。
pub(crate) const OPENCODE_MAX_VERIFY_INTERVAL_HOURS: u32 = 8_760;

/// 异常池上限（条）。超出后从最旧的开始丢——异常池只表达「暂时不用」，
/// 不需要无限历史。
pub(crate) const OPENCODE_ABNORMAL_MAX_ENTRIES: usize = 500;
/// 复验连续未通过多少次就丢弃。
///
/// 计数每个复验轮最多加一，所以「≥2」天然等价于「跨轮」——单轮内的抖动
/// 不可能把它推到门槛。实测并发会把 p50 放大 3.9 倍，一次复验失败说明不了
/// 什么，连续两轮才值得丢。
pub(crate) const OPENCODE_ABNORMAL_DISCARD_FAILS: u32 = 2;
/// 异常池条目过期天数（默认 7 天；`0` = 永不过期）。
///
/// 为什么需要过期：`providers.config` 是整行 jsonb，**每次健康更新都整段重写**，
/// 异常池里每条记录（实测 ≈146 bytes）都会跟着一起搬。复验只增不减地往里塞，
/// config 就从 22.8KB 涨到 30KB，其中大半是「七天前失败过一次、之后既没被复验
/// 碰到也没被丢弃」的僵尸条目。
///
/// 只清 `fails` **未达出池阈值**的条目：已达阈值的条目本该被丢弃，若它还在，
/// 说明当时池子低于保护线不允许丢，那种条目必须继续拦住这个 IP。
pub(crate) const OPENCODE_DEFAULT_ABNORMAL_MAX_AGE_DAYS: u32 = 7;
/// 过期天数的校验上限（一年）。再长就等于「永不过期」。
pub(crate) const OPENCODE_MAX_ABNORMAL_MAX_AGE_DAYS: u32 = 365;
/// 同一出口 IP **连续**失败多少次后从轮转池里摘掉（默认 3）。
///
/// 与 [`OPENCODE_ABNORMAL_DISCARD_FAILS`] 的区别是判据来源：那个计数来自**复验**
/// （每个复验轮最多 +1，代价是每 IP 一次真实 chat），这个计数来自**真实流量**
/// （流式/同步两条路径的失败钩子），所以它能在「加进来不验证就参与轮转」的
/// 前提下把坏 IP 筛出去——失败 IP 留在 `exit_pool` 里会永久抬高每轮复验的成本。
///
/// 计数由 `opencode_pool:fail:{provider}:{ip}` 承载（窗口内累计），成功一次即清零，
/// 因此「连续」= 窗口内没有成功过。`0` 表示关闭自动出池。
pub(crate) const OPENCODE_DEFAULT_EVICT_FAILS: u32 = 3;
/// 池小保护下限：可用池小于它时，异常池与人工拉黑**照记但不生效**。
///
/// 三五个节点的池子里，任何「立刻不用」都会把流量压到一两个节点上，
/// 而「压到一两个节点」比「用到一个慢节点」更难察觉，也更难恢复。
pub(crate) const OPENCODE_PROTECT_POOL_FLOOR: usize = 5;

// 被动降权的首字节阈值与冷却时长，常量统一放在 opencode_rotation：那里才是
// 真正用它们做判定的地方，放在这里曾经留下一对从未被引用的同名常量。

/// 验健康配置，存放在 provider `config.opencode_health`。
///
/// 与扫描配置分开，是因为两者的成本与周期差一个数量级：扫描一轮
/// 37,888 次探测约 50 分钟，产出是新候选；验健康一轮 195 次探测约
/// 3 分钟，产出是当前可信集。驱动它们的是质量漂移的速度——小时级，
/// 而不是 AWS 扩容新网段的月级。
/// 异常池条目：**权威**的「这个 IP 有问题」记录，由复验维护。
///
/// 取代了旧的 `rejections`：那个字段只写不读、没有任何消费者，面板上除了
/// 一列原因之外什么也做不了。这里的条目既解释「为什么不用它」，也驱动
/// 「还要不要再给它机会」。
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub(crate) struct OpenCodeAbnormalIp {
    pub(crate) ip: String,
    /// 首次进入异常池的时间（RFC3339）。
    pub(crate) since: String,
    /// 复验未通过的累计次数；每个复验轮最多加一，因此 ≥2 等价于「跨轮」。
    pub(crate) fails: u32,
    /// 最近一次判定原因：`unreachable` / `partial_timeout` / `too_slow`。
    pub(crate) reason: String,
    /// 最近一次实测中位延迟（毫秒）；一次都没测出来时为 `None`。
    pub(crate) median_ms: Option<u64>,
}

#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub(crate) struct OpenCodeHealthConfig {
    /// 当前可信的节点集合。轮转只从这里选，空则不锚定（走域名 DNS）。
    pub(crate) healthy: Vec<String>,
    /// pinned 但本轮未达标，保留在池中但标记出来。
    pub(crate) degraded: Vec<String>,
    /// 上一版 healthy，供 UI 一键回滚。
    pub(crate) healthy_prev: Vec<String>,
    /// 逐节点的首字节中位数（毫秒），键是 IP。
    ///
    /// 存下来是因为「哪些节点快、哪些慢」是这次事故里最缺的信息：
    /// 原来界面只有一个 IP 列表，池里塞满要 100~200 秒的节点时，
    /// 看上去和健康节点没有任何区别。
    pub(crate) latencies: std::collections::BTreeMap<String, u64>,
    /// 异常池：有嫌疑、**立刻不再使用**但仍在跟踪的节点。
    ///
    /// 存在 config 里而不是 Redis 里是有意的：Redis 清空最多让坏节点被用一会儿，
    /// 下一轮复验就会纠正；反过来把权威状态放 Redis，一次 flush 就等于
    /// 「所有坏节点集体复活」。
    pub(crate) abnormal: Vec<OpenCodeAbnormalIp>,
    /// 人工拉黑：请求路径永远跳过，复验也不放回（可解禁）。
    pub(crate) blocked: Vec<String>,
    /// 上一次复验的摘要（RFC3339）。
    ///
    /// 持久化而不是只留在内存状态里：进程重启会清空
    /// `OPENCODE_IP_POOL_STATUSES`，重启后界面上的「上次复验」会变成空，
    /// 让人以为从没验过——而 `latencies` 因为存在这里所以还在，
    /// 两者的存活期不一致只会让人更困惑。
    pub(crate) last_verify_at: Option<String>,
    /// 上一次复验检查的节点数。
    pub(crate) last_verify_checked: u64,
    /// 上一次复验保留的节点数。
    pub(crate) last_verify_kept: u64,
    /// 上一次复验淘汰的节点数。
    pub(crate) last_verify_dropped: u64,
    /// 是否允许自动验健康。
    pub(crate) auto_verify_enabled: bool,
    /// 自动验健康间隔（小时）；`0` 表示即使开启也不自动执行。
    pub(crate) verify_interval_hours: Option<u32>,
    /// 每 IP 采样次数，取中位数判定。
    pub(crate) verify_samples: Option<usize>,
    /// 首字节中位数上限（毫秒）。
    pub(crate) verify_max_median_ms: Option<u64>,
    /// 保底池大小：低于此值不做任何淘汰。
    pub(crate) min_pool_size: Option<usize>,
    /// 是否启用会话级粘性锚点。
    pub(crate) session_sticky_enabled: bool,
    /// 池小于此值时自动停用会话粘性。
    pub(crate) session_sticky_min_pool: Option<usize>,
    /// 异常池条目的过期天数；`None` 用 [`OPENCODE_DEFAULT_ABNORMAL_MAX_AGE_DAYS`]，
    /// `Some(0)` 表示永不过期。
    ///
    /// 放在健康段而不是扫描段：异常池本身就是健康段的一部分，清理它的阈值跟着
    /// 它自己走，改一处就够了。
    pub(crate) abnormal_max_age_days: Option<u32>,
}

impl OpenCodeHealthConfig {
    pub(crate) fn min_pool_size(&self) -> usize {
        self.min_pool_size
            .filter(|value| *value > 0)
            .unwrap_or(OPENCODE_DEFAULT_MIN_POOL_SIZE)
    }

    pub(crate) fn verify_samples(&self) -> usize {
        self.verify_samples
            .filter(|value| *value > 0)
            .unwrap_or(OPENCODE_DEFAULT_VERIFY_SAMPLES)
    }

    pub(crate) fn verify_max_median_ms(&self) -> u64 {
        self.verify_max_median_ms
            .filter(|value| *value > 0)
            .unwrap_or(OPENCODE_DEFAULT_VERIFY_MAX_MEDIAN_MS)
    }

    pub(crate) fn session_sticky_min_pool(&self) -> usize {
        self.session_sticky_min_pool
            .filter(|value| *value > 0)
            .unwrap_or(OPENCODE_DEFAULT_STICKY_MIN_POOL)
    }

    /// 会话粘性是否实际生效。池太小时自动停用——一个设备锁死唯一的
    /// 节点等于没有分散。
    pub(crate) fn session_sticky_active(&self, pool_size: usize) -> bool {
        self.session_sticky_enabled && pool_size >= self.session_sticky_min_pool()
    }

    /// 池小保护下限：可用池小于它时，异常池与人工拉黑**照记但不生效**。
    pub(crate) fn protect_pool_floor(&self) -> usize {
        self.min_pool_size().max(OPENCODE_PROTECT_POOL_FLOOR)
    }

    /// 异常池条目的过期天数（`0` = 永不过期）。
    pub(crate) fn abnormal_max_age_days(&self) -> u32 {
        self.abnormal_max_age_days
            .unwrap_or(OPENCODE_DEFAULT_ABNORMAL_MAX_AGE_DAYS)
    }

    /// 清掉过期且**未达出池阈值**的异常池条目，返回被清掉的 IP。
    ///
    /// 触发时机是**健康更新**（复验、一键复验、拉黑等每一次 `opencode_health` 的
    /// 写入），见 [`write_health_config`]：那些位置本来就整段重写 config，
    /// 顺手删几条比再起一个后台任务更省事，也不会与写入路径抢同一段配置。
    ///
    /// 幂等：同一份配置连续调用两次，第二次一定返回空（条目已经不在了）。
    /// 纯函数（`now` 由调用方给），所以能被单测直接钉住——这条规则决定「一个失败过的
    /// IP 多久之后会重新回到轮转里」，改错了不会编译失败。
    ///
    /// `since` 解析不了时**保留**条目：宁可留一条僵尸记录，也不要把一条我们读不懂的
    /// 记录当成过期清掉——清理的代价是「这个 IP 重新参与轮转」，猜错方向更贵。
    pub(crate) fn prune_expired_abnormal_at(
        &mut self,
        now: chrono::DateTime<chrono::Utc>,
    ) -> Vec<String> {
        let max_age_days = self.abnormal_max_age_days();
        if max_age_days == 0 {
            return Vec::new();
        }
        let max_age = chrono::Duration::days(i64::from(max_age_days));
        let mut expired: Vec<String> = Vec::new();
        self.abnormal.retain(|entry| {
            if entry.fails >= OPENCODE_ABNORMAL_DISCARD_FAILS {
                // 已达出池阈值的条目本该被丢弃，还在就说明当时池子低于保护线
                // 不允许丢：这种条目必须继续拦住这个 IP，不受过期影响。
                return true;
            }
            let Ok(since) = chrono::DateTime::parse_from_rfc3339(entry.since.trim()) else {
                return true;
            };
            if now.signed_duration_since(since.with_timezone(&chrono::Utc)) >= max_age {
                expired.push(entry.ip.clone());
                return false;
            }
            true
        });
        expired
    }

    /// 用当前时间清理过期异常池条目（见 [`Self::prune_expired_abnormal_at`]）。
    pub(crate) fn prune_expired_abnormal(&mut self) -> Vec<String> {
        self.prune_expired_abnormal_at(chrono::Utc::now())
    }

    /// 异常池里的 IP 集合（已 trim、去重）。
    pub(crate) fn abnormal_ips(&self) -> BTreeSet<String> {
        self.abnormal
            .iter()
            .map(|entry| entry.ip.trim().to_string())
            .filter(|ip| !ip.is_empty())
            .collect()
    }

    /// 人工拉黑集合（已 trim、去重）。
    pub(crate) fn blocked_ips(&self) -> BTreeSet<String> {
        self.blocked
            .iter()
            .map(|ip| ip.trim().to_string())
            .filter(|ip| !ip.is_empty())
            .collect()
    }

    /// 该 IP 是否被人工拉黑。
    pub(crate) fn is_blocked(&self, ip: &str) -> bool {
        self.blocked.iter().any(|item| item.trim() == ip.trim())
    }

    /// 记一次复验未通过，返回累计次数。
    ///
    /// `since` 只在首次进入时写入：界面上「加入时间」要表达的是「它什么时候
    /// 开始有问题」，每轮复验都刷新的话这个信息就没了。
    pub(crate) fn record_abnormal(
        &mut self,
        ip: &str,
        reason: &str,
        median_ms: Option<u64>,
        now: &str,
    ) -> u32 {
        let position = self.abnormal.iter().position(|entry| entry.ip == ip);
        let fails = match position {
            Some(index) => {
                let entry = &mut self.abnormal[index];
                entry.fails = entry.fails.saturating_add(1);
                entry.reason = reason.to_string();
                entry.median_ms = median_ms;
                entry.fails
            }
            None => {
                self.abnormal.push(OpenCodeAbnormalIp {
                    ip: ip.to_string(),
                    since: now.to_string(),
                    fails: 1,
                    reason: reason.to_string(),
                    median_ms,
                });
                1
            }
        };
        truncate_abnormal(&mut self.abnormal);
        fails
    }

    /// 复验通过：从异常池移除（失败计数随之清零）。返回是否真的移除过。
    pub(crate) fn clear_abnormal(&mut self, ip: &str) -> bool {
        let before = self.abnormal.len();
        self.abnormal.retain(|entry| entry.ip != ip);
        self.abnormal.len() != before
    }

    /// 一键重置异常池（返回移除的条数）。丢弃本身不再留任何配置态，只写事件日志。
    pub(crate) fn reset_abnormal(&mut self) -> usize {
        let removed = self.abnormal.len();
        self.abnormal.clear();
        removed
    }

    /// 校验 `opencode_health` 段的取值。
    ///
    /// 放在合并之前校验，是为了让报错指向**请求里真正写错的那个字段**。
    /// 合并之后再校验就只能看到最终值——而最终值已经被默认值兜底改过了，
    /// 写错的人看到的会是「5，怎么不对」，而他写的是 -1。
    pub(crate) fn validate_section(section: &serde_json::Map<String, Value>) -> Result<(), String> {
        for field in ["min_pool_size", "session_sticky_min_pool"] {
            validate_bounded_uint(section, field, 1, OPENCODE_MAX_MIN_POOL_SIZE as u64)?;
        }
        validate_bounded_uint(
            section,
            "verify_samples",
            1,
            OPENCODE_MAX_VERIFY_SAMPLES as u64,
        )?;
        validate_bounded_uint(
            section,
            "verify_max_median_ms",
            1,
            OPENCODE_MAX_VERIFY_MAX_MEDIAN_MS,
        )?;
        // 间隔允许 0：那表示「开关开着但永不自动执行」，是有意义的取值。
        validate_bounded_uint(
            section,
            "verify_interval_hours",
            0,
            OPENCODE_MAX_VERIFY_INTERVAL_HOURS as u64,
        )?;
        // 异常池过期天数：允许 0（永不过期），其余按天计。
        validate_bounded_uint(
            section,
            "abnormal_max_age_days",
            0,
            OPENCODE_MAX_ABNORMAL_MAX_AGE_DAYS as u64,
        )?;
        for field in ["auto_verify_enabled", "session_sticky_enabled"] {
            validate_bool(section, field)?;
        }
        Ok(())
    }
}

/// 扫描配置，存放在 provider `config.opencode_scan`。
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub(crate) struct OpenCodeScanConfig {
    /// 显式 CIDR 列表；为空表示未配置扫描网段。
    pub(crate) cidrs: Vec<String>,
    /// 上一轮扫描**完成**的落盘时间（RFC3339）。
    ///
    /// `autoscan` 必须按这个判断间隔，不能用进程内存里的时间：内存时间在每次重启后
    /// 清零，于是"重启即该扫"——2026-10-18 实测踩到过，重启后立刻起了一轮扫描，
    /// 卡在无超时的 DNS 解析上，`scanning` 永久 true，把复验全堵成 400。
    pub(crate) last_scan_at: Option<String>,
    /// 扫描广撒网的产物：粗筛通过的候选，**不是**生产列表。
    /// 验健康任务从这里产出 `OpenCodeHealthConfig::healthy`。
    pub(crate) candidates: Vec<String>,
    /// 手工保护名单：只影响「是否被自动淘汰」，不影响是否使用。
    /// 保留它而不是设一个独立的手工池，是因为任何绕过定期复验的集合
    /// 都会随时间腐烂，而腐烂本身没有任何信号能暴露出来。
    pub(crate) pinned: Vec<String>,
    /// 是否允许维护 worker 自动扫描。
    pub(crate) auto_enabled: bool,
    /// 自动扫描间隔（小时）；`0` 表示即使开启也不自动执行。
    pub(crate) interval_hours: Option<u32>,
    /// 单轮扫描最大并发探测数。
    ///
    /// 与 [`Self::probe_max_handshake_ms`] 强耦合：并发越高，探测实测耗时越长
    /// （争用是自己造的），阈值不变时通过率会随并发升高而下降。两个要一起调。
    pub(crate) concurrency: Option<usize>,
    /// 单轮扫描的候选上限（分片大小）。候选总数超过它时按 Redis 游标分多轮。
    ///
    /// **注意**：只有完整走完一轮（`next_cursor == 0`）才会按「本轮未见即淘汰」
    /// 重建 `candidates`，而一轮真实扫描要跨 `ceil(总数/上限)` 个 interval，
    /// 游标存活时长由 [`Self::scan_cursor_ttl_seconds`] 保证。未配置时用
    /// [`OPENCODE_SCAN_MAX_CANDIDATES`]。
    pub(crate) max_candidates_per_round: Option<usize>,
    /// 扫描快筛阈值（毫秒）：连接 + TLS + 读到响应首行超过它判死。
    ///
    /// 未配置时回退全局环境变量 [`OPENCODE_PROBE_MAX_HANDSHAKE_ENV`]（默认
    /// [`OPENCODE_PROBE_MAX_HANDSHAKE_MS`]）。做成 provider 级配置，是因为实测
    /// 最优值与这台机器到 CDN 的基线延迟有关，全局一个值没法同时适配。
    pub(crate) probe_max_handshake_ms: Option<u64>,
    /// 是否启用「最少在途 + 游标轮转」选 key。
    pub(crate) rotation_enabled: bool,
    /// 额度耗尽后的冷却时长（分钟）。
    pub(crate) cooldown_minutes: Option<u32>,
    /// 配额类失败（`403 FreeTierError` / `429`）要把出口 IP 打成 suspect 需要几次。
    /// 默认 1：这类失败是「换个出口就好」的强信号。
    pub(crate) quota_fail_threshold: Option<u32>,
    /// 只有最近这么多分钟内**有过成功**，才把配额类失败归到出口 IP 头上。
    /// 默认 10：防「我们自己的身份/body 坏了导致全 403」时把池子掏空。
    pub(crate) quota_attribution_window_minutes: Option<u32>,
    /// 其它运行时失败（传输错误 / 网关超时 / 首字节慢）的阈值。默认 3。
    pub(crate) runtime_fail_threshold: Option<u32>,
    /// 其它运行时失败计数的窗口（分钟）。默认 60。
    pub(crate) runtime_fail_window_minutes: Option<u32>,
    /// 出口 IP 被打成 suspect 后的冷却时长（分钟）。默认 20。
    pub(crate) suspect_ttl_minutes: Option<u32>,
    /// 同一出口 IP **连续**失败多少次后从轮转池里摘掉（默认 3；`0` = 不自动出池）。
    ///
    /// 判定用真实流量的失败计数（与 suspect 同一个键，成功一次即清零），不是复验。
    /// 这是「加进来不验证也能扩池」的另一半：进池不花探测成本，出池由真实流量决定。
    pub(crate) evict_fail_threshold: Option<u32>,
    /// 复验用的真实 chat 探测模型。默认 `big-pickle`。
    pub(crate) probe_model: Option<String>,
    /// 相邻两次 chat 探测之间的最小间隔（毫秒），防被上游封。默认 2500。
    pub(crate) probe_interval_ms: Option<u64>,
    /// 用户填写过的前置代理域名。持久化后即使开关关闭也保留，
    /// 输入框内容永远由用户决定，不会被开关联动改写。
    pub(crate) proxy_domain: Option<String>,
    /// 前置代理开关。开启时本次请求用 `proxy_domain` 作为 host，
    /// 关闭时用默认的官方域名。**不写回 endpoint.base_url**。
    pub(crate) proxy_enabled: bool,
    /// provider 级出口 IP 池：每次请求从这里挑一个 IP 作为 DNS 锚点。
    /// 与「一个 IP 一个 key」的旧模型不同，这里池子挂在 provider 上，
    /// 密钥管理只需 1 个 key。
    /// **已废弃**——生产列表改由 `opencode_health.healthy` 承担，
    /// 此字段仅在迁移时作为数据来源读取一次。
    pub(crate) exit_pool: Vec<String>,
    /// provider 级池里被手动停用的 IP（不参与轮转，但仍保留在池中）。
    pub(crate) exit_pool_disabled: Vec<String>,
}

// 出口 IP 池只有**一个**模型：provider 级四态池（候选 → 可用 → 异常 → 丢弃）。
//
// 历史上还有一套「一 key 一 IP」的 `pool_mode` 开关，已删除。原因与迁移依据：
// - key 只承担**凭据**，出口 IP 一律由 provider 级池决定（`candidates` / `healthy`）；
// - 那个开关同时是自举死锁的来源（空池 ⇒ 推断成 key 模式 ⇒ 扫描把 IP 写成 key 元数据
//   ⇒ 池还是空）；而它的扫描分支会为每个探通的 IP **创建启用的生产密钥**，
//   等于「扫描即上线」；
// - 删除时实测：全库非空 `exit_pool` 的供应商为 0，且扫描产物密钥已清理完毕，
//   没有任何配置依赖该模式，迁移成本为零。
// - 仍保留的手工能力：`upstream_metadata.opencode_exit_ip` 字段在写入校验里仍被接受，
//   但面板不再暴露它，且 provider 级池非空时每请求锚点会覆盖它。

/// 扫描器运行期状态（进程内、按 Provider 维度）。
#[derive(Clone, Debug, Default)]
pub(crate) struct OpenCodeIpPoolStatus {
    pub(crate) scanning: bool,
    pub(crate) cleaning: bool,
    pub(crate) last_scan_at: Option<String>,
    pub(crate) last_scan_at_unix_secs: Option<u64>,
    pub(crate) last_scan_targets: u64,
    pub(crate) last_scan_found: u64,
    pub(crate) last_scan_added: u64,
    pub(crate) last_clean_at: Option<String>,
    pub(crate) last_clean_checked: u64,
    pub(crate) last_clean_removed: u64,
    /// 本轮长任务进度：已探 / 总数。大批量扫描要跑几十分钟，
    /// 没有这两个数面板上只会像卡死。
    pub(crate) progress_done: u64,
    pub(crate) progress_total: u64,
    pub(crate) progress_kind: Option<String>,
    /// 验健康任务独立于扫描：两者进度不能共用一个字段，否则同时运行时
    /// 面板上的数字会互相覆盖。
    pub(crate) verifying: bool,
    pub(crate) verify_progress_done: u64,
    pub(crate) verify_progress_total: u64,
    /// 本轮待验的 IP 数。进度分母 verify_progress_total 是「IP 数 × 每 IP 采样
    /// 次数」，直接把它摆到界面上会被读成「有一千多个 IP」——实际 IP 只有几百个
    /// （337 × 3 = 1011）。单独给出 IP 数，界面才能同时说清有多少个 IP、采了
    /// 多少次样。采样次数本身状态接口已按配置给出（verify_samples），不重复。
    pub(crate) verify_targets: u64,
    /// 一键复验（池内 IP 批量）独立的一套状态。
    ///
    /// 与整轮复验**语义不同**（只验 `exit_pool`、永不丢弃），共用 `verify_*` 字段会让
    /// 两个入口的进度互相覆盖；而且它以前是同步执行的，21 个 IP 最坏要 10 分钟，
    /// HTTP 请求会先超时。现在改成后台任务 + 这套独立进度字段。
    pub(crate) reverify_running: bool,
    pub(crate) reverify_progress_done: u64,
    pub(crate) reverify_progress_total: u64,
    /// 可用节点是否已跌破保底线（`healthy ≤ min_pool_size`）。
    ///
    /// 只用于**状态翻转时告警一次**：每个维护 tick 都打日志会刷屏，而跌破保底线
    /// 意味着池子已经很少、随时可能开始失败，必须有一条明确的告警。
    pub(crate) pool_low_alarm: bool,
    pub(crate) last_verify_at: Option<String>,
    pub(crate) last_verify_checked: u64,
    pub(crate) last_verify_kept: u64,
    pub(crate) last_verify_dropped: u64,
    /// 分层计数。候选 / 健康 / 实际在用，三个数放在一起才看得出
    /// 扫描到底筛掉了什么。
    pub(crate) candidate_count: u64,
    pub(crate) healthy_count: u64,
    pub(crate) in_use_count: u64,
    pub(crate) degraded_count: u64,
    /// 可用池骤缩告警（一轮复验砍掉一半以上）。
    ///
    /// 只报警不回滚：自动回滚会把真实的集体劣化一起盖掉，而「探针坏了」与
    /// 「节点集体变差」在数据上长得一模一样。人看到告警可以点「重置全部异常」。
    pub(crate) pool_shrink_alarm: Option<String>,
    /// 自动停用的原因。这些不是诊断便利——不回报原因，用户就无法判断
    /// 是不是该干预，自动降级会变成无从查证的玄学。
    pub(crate) session_sticky_active: bool,
    pub(crate) session_sticky_disabled_reason: Option<String>,
    pub(crate) pool_below_floor: bool,
    pub(crate) pool_empty: bool,
}

/// 一轮扫描的结果摘要。
#[derive(Debug, Default, Clone)]
pub(crate) struct ScanSummary {
    pub(crate) targets: u64,
    pub(crate) found: u64,
    pub(crate) added: u64,
}

/// 一轮清理的结果摘要。
#[derive(Debug, Default, Clone)]
pub(crate) struct CleanSummary {
    pub(crate) checked: u64,
    pub(crate) removed: u64,
}

static OPENCODE_IP_POOL_STATUSES: OnceLock<Arc<Mutex<BTreeMap<String, OpenCodeIpPoolStatus>>>> =
    OnceLock::new();

fn opencode_ip_pool_status_map_locked(
) -> std::sync::MutexGuard<'static, BTreeMap<String, OpenCodeIpPoolStatus>> {
    OPENCODE_IP_POOL_STATUSES
        .get_or_init(|| Arc::new(Mutex::new(BTreeMap::new())))
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner())
}

/// 读取某 Provider 的扫描器状态（缺省返回全零状态）。
pub(crate) fn opencode_ip_pool_status_for(provider_id: &str) -> OpenCodeIpPoolStatus {
    opencode_ip_pool_status_map_locked()
        .get(provider_id)
        .cloned()
        .unwrap_or_default()
}

pub(crate) fn update_opencode_ip_pool_status(
    provider_id: &str,
    patch: impl FnOnce(&mut OpenCodeIpPoolStatus),
) {
    let mut map = opencode_ip_pool_status_map_locked();
    let mut status = map.get(provider_id).cloned().unwrap_or_default();
    patch(&mut status);
    map.insert(provider_id.to_string(), status);
}

/// 清掉可用池骤缩告警。
///
/// 由「重置全部异常」调用：那一步本来就是人确认过「这是误报」的表达，
/// 告警留着只会让人以为重置没生效。
pub(crate) fn clear_opencode_ip_pool_shrink_alarm(provider_id: &str) {
    update_opencode_ip_pool_status(provider_id, |status| {
        status.pool_shrink_alarm = None;
    });
}

/// 从 JSON 数组里收集非空字符串（trim 后）。
fn string_list(value: Option<&Value>) -> Vec<String> {
    value
        .and_then(Value::as_array)
        .map(|items| {
            items
                .iter()
                .filter_map(Value::as_str)
                .map(str::trim)
                .filter(|item| !item.is_empty())
                .map(str::to_string)
                .collect()
        })
        .unwrap_or_default()
}

/// 取一个可选字符串字段（trim 后为空视为缺失，返回空串）。
fn optional_string(value: Option<&Value>) -> String {
    value
        .and_then(Value::as_str)
        .unwrap_or_default()
        .trim()
        .to_string()
}

/// 取一个可选的无符号整数字段并截断到 `u32`。
fn optional_u32(value: Option<&Value>) -> Option<u32> {
    value
        .and_then(Value::as_u64)
        .map(|number| number.min(u32::MAX as u64) as u32)
}

/// 解析 `opencode_health.abnormal` 数组。
fn parse_abnormal_entries(value: Option<&Value>) -> Vec<OpenCodeAbnormalIp> {
    let Some(items) = value.and_then(Value::as_array) else {
        return Vec::new();
    };
    let mut entries: Vec<OpenCodeAbnormalIp> = Vec::with_capacity(items.len());
    for item in items {
        let Some(object) = item.as_object() else {
            continue;
        };
        let ip = optional_string(object.get("ip"));
        if ip.is_empty() {
            continue;
        }
        entries.push(OpenCodeAbnormalIp {
            ip,
            since: optional_string(object.get("since")),
            fails: optional_u32(object.get("fails")).unwrap_or(1).max(1),
            reason: optional_string(object.get("reason")),
            median_ms: object.get("median_ms").and_then(Value::as_u64),
        });
    }
    truncate_abnormal(&mut entries);
    entries
}

/// 输出 `opencode_health.abnormal` 数组。
fn abnormal_entries_json(entries: &[OpenCodeAbnormalIp]) -> Value {
    let mut items: Vec<Value> = Vec::with_capacity(entries.len());
    for entry in entries {
        items.push(json!({
            "ip": entry.ip.clone(),
            "since": entry.since.clone(),
            "fails": entry.fails,
            "reason": entry.reason.clone(),
            "median_ms": entry.median_ms,
        }));
    }
    Value::Array(items)
}

/// 异常池超上限时丢最旧的几条。
fn truncate_abnormal(entries: &mut Vec<OpenCodeAbnormalIp>) {
    if entries.len() > OPENCODE_ABNORMAL_MAX_ENTRIES {
        let excess = entries.len() - OPENCODE_ABNORMAL_MAX_ENTRIES;
        entries.drain(0..excess);
    }
}

/// 复验失败次数是否已达丢弃门槛。
///
/// 纯函数是为了能被单测直接钉住：这条门槛决定「一个节点还能在池里待多久」，
/// 改错了不会编译失败，只会让坏节点活很久、或者好节点被丢得太快。
pub(crate) fn abnormal_reached_discard_threshold(fails: u32) -> bool {
    fails >= OPENCODE_ABNORMAL_DISCARD_FAILS
}

/// 异常池与人工拉黑是否**实际生效**（池小保护）。
///
/// 池子小于保护下限时，异常池与拉黑只记录、不参与选择——三五个节点的池子里
/// 「立刻不用」会把流量压到一两个节点上，那比用一个慢节点更难察觉。
pub(crate) fn soft_marks_active(pool_size: usize, protect_floor: usize) -> bool {
    pool_size >= protect_floor.max(1)
}

/// 校验请求体里的整数字段是否落在 `[min, max]`。
///
/// 越界返回 `Err` 而不是就地修正。原来的做法是「读不出来就沿用旧值、
/// 读得出来就直接存」，于是负数被静默丢弃、`0` 被静默换成默认值、
/// 巨大值原样落库，而响应永远是 `saved: true`——保存成功这句话本身就是
/// 假的：使用者以为自己设了 1000ms 阈值，实际生效的是 10000ms，界面上
/// 没有任何提示。
fn validate_bounded_uint(
    section: &serde_json::Map<String, Value>,
    field: &str,
    min: u64,
    max: u64,
) -> Result<(), String> {
    let Some(value) = section.get(field) else {
        return Ok(());
    };
    // 负数、字符串、浮点数都走不到 `as_u64`，一并按类型错误拒绝。
    let Some(number) = value.as_u64() else {
        return Err(format!("{field} 必须是 {min}~{max} 之间的整数"));
    };
    if number < min || number > max {
        return Err(format!("{field} 必须在 {min}~{max} 之间，当前是 {number}"));
    }
    Ok(())
}

/// 校验请求体里的布尔字段。类型不对直接拒绝，避免开关被静默忽略后
/// 使用者以为「已经关掉了」。
fn validate_bool(section: &serde_json::Map<String, Value>, field: &str) -> Result<(), String> {
    match section.get(field) {
        None | Some(Value::Bool(_)) => Ok(()),
        Some(_) => Err(format!("{field} 必须是 true 或 false")),
    }
}

impl OpenCodeScanConfig {
    /// 从 provider 的 `config` 读取扫描配置。
    pub(crate) fn from_provider_config(config: &Option<Value>) -> Self {
        match config.as_ref().and_then(Value::as_object) {
            Some(object) => Self::from_provider_config_object(object),
            None => Self::default(),
        }
    }

    /// 把请求体里**出现的**字段合并到已有配置上。
    ///
    /// PUT config 是部分更新：只改域名不应该把 CIDR、自动扫描、轮转开关、冷却时长
    /// 全部打回默认值。做法是从已存配置出发，逐个检查请求体里有没有对应键。
    pub(crate) fn merged_with_payload(
        existing: &Option<Value>,
        payload: &serde_json::Map<String, Value>,
    ) -> Self {
        let section = payload
            .get("opencode_scan")
            .and_then(Value::as_object)
            .unwrap_or(payload);
        let mut result = Self::from_provider_config(existing);
        if section.contains_key("cidrs") {
            result.cidrs = string_list(section.get("cidrs"));
        }
        if let Some(Value::String(value)) = section.get("last_scan_at") {
            result.last_scan_at = Some(value.clone());
        }
        if let Some(Value::Bool(enabled)) = section.get("auto_enabled") {
            result.auto_enabled = *enabled;
        }
        if section.contains_key("interval_hours") {
            result.interval_hours = section
                .get("interval_hours")
                .and_then(Value::as_u64)
                .map(|v| v as u32);
        }
        if section.contains_key("concurrency") {
            result.concurrency = section
                .get("concurrency")
                .and_then(Value::as_u64)
                .map(|value| value as usize);
        }
        if section.contains_key("max_candidates_per_round") {
            result.max_candidates_per_round = section
                .get("max_candidates_per_round")
                .and_then(Value::as_u64)
                .map(|value| value as usize);
        }
        if section.contains_key("probe_max_handshake_ms") {
            result.probe_max_handshake_ms = section
                .get("probe_max_handshake_ms")
                .and_then(Value::as_u64);
        }
        if let Some(Value::Bool(enabled)) = section.get("rotation_enabled") {
            result.rotation_enabled = *enabled;
        }
        if section.contains_key("cooldown_minutes") {
            result.cooldown_minutes = section
                .get("cooldown_minutes")
                .and_then(Value::as_u64)
                .map(|value| value as u32);
        }
        for (key, slot) in [
            ("quota_fail_threshold", &mut result.quota_fail_threshold),
            (
                "quota_attribution_window_minutes",
                &mut result.quota_attribution_window_minutes,
            ),
            ("runtime_fail_threshold", &mut result.runtime_fail_threshold),
            (
                "runtime_fail_window_minutes",
                &mut result.runtime_fail_window_minutes,
            ),
            ("suspect_ttl_minutes", &mut result.suspect_ttl_minutes),
            ("evict_fail_threshold", &mut result.evict_fail_threshold),
        ] {
            if section.contains_key(key) {
                *slot = section.get(key).and_then(Value::as_u64).map(|v| v as u32);
            }
        }
        if section.contains_key("exit_pool") {
            result.exit_pool = string_list(section.get("exit_pool"));
        }
        if section.contains_key("exit_pool_disabled") {
            result.exit_pool_disabled = string_list(section.get("exit_pool_disabled"));
        }
        if section.contains_key("candidates") {
            result.candidates = string_list(section.get("candidates"));
        }
        if section.contains_key("pinned") {
            result.pinned = string_list(section.get("pinned"));
        }
        if let Some(Value::Bool(enabled)) = section.get("proxy_enabled") {
            result.proxy_enabled = *enabled;
        }
        if let Some(Value::String(domain)) = section.get("proxy_domain") {
            let trimmed = domain.trim();
            if !trimmed.is_empty() {
                result.proxy_domain = Some(trimmed.to_string());
            }
        }
        if let Some(Value::String(model)) = section.get("probe_model") {
            let trimmed = model.trim();
            if !trimmed.is_empty() {
                result.probe_model = Some(trimmed.to_string());
            }
        }
        if section.contains_key("probe_interval_ms") {
            result.probe_interval_ms = section.get("probe_interval_ms").and_then(Value::as_u64);
        }
        result
    }

    /// 校验 `opencode_scan` 段的取值。
    ///
    /// `interval_hours` / `cooldown_minutes` 存的是 `u32`，读取时用
    /// `as u32` 强转。超过 `u32::MAX` 的值会被静默截断成一个看似合理的
    /// 数字（例如 5_000_000_000 → 1_416_151_040），所以必须在这里挡住。
    pub(crate) fn validate_section(section: &serde_json::Map<String, Value>) -> Result<(), String> {
        validate_bounded_uint(
            section,
            "concurrency",
            1,
            OPENCODE_SCAN_MAX_CONCURRENCY as u64,
        )?;
        validate_bounded_uint(
            section,
            "interval_hours",
            0,
            OPENCODE_MAX_VERIFY_INTERVAL_HOURS as u64,
        )?;
        validate_bounded_uint(section, "cooldown_minutes", 1, 10_080)?;
        validate_bounded_uint(section, "quota_fail_threshold", 1, 100)?;
        validate_bounded_uint(section, "quota_attribution_window_minutes", 1, 1_440)?;
        validate_bounded_uint(section, "runtime_fail_threshold", 1, 100)?;
        validate_bounded_uint(section, "runtime_fail_window_minutes", 1, 1_440)?;
        validate_bounded_uint(section, "suspect_ttl_minutes", 1, 1_440)?;
        // 出池阈值允许 0（关闭自动出池）；上限与其它失败阈值同口径。
        validate_bounded_uint(section, "evict_fail_threshold", 0, 100)?;
        validate_bounded_uint(section, "probe_interval_ms", 0, 60_000)?;
        validate_bounded_uint(
            section,
            "max_candidates_per_round",
            1,
            OPENCODE_SCAN_MAX_CANDIDATES_LIMIT as u64,
        )?;
        validate_bounded_uint(
            section,
            "probe_max_handshake_ms",
            OPENCODE_PROBE_MIN_HANDSHAKE_MS,
            OPENCODE_PROBE_MAX_HANDSHAKE_MS_LIMIT,
        )?;
        // 429 换点的段预算（默认关闭，显式打开时才生效）：0 段 / 0 毫秒会让
        // 「优先换段」失去意义（不是保护），所以下限是 1；上限与 opencode_rotation
        // 里的常量保持同一口径。
        validate_bounded_uint(
            section,
            crate::opencode_rotation::OPENCODE_SEGMENT_BUDGET_SEGMENTS_FIELD,
            1,
            crate::opencode_rotation::MAX_OPENCODE_SEGMENT_BUDGET,
        )?;
        validate_bounded_uint(
            section,
            crate::opencode_rotation::OPENCODE_SEGMENT_BUDGET_MS_FIELD,
            1,
            crate::opencode_rotation::MAX_OPENCODE_SEGMENT_BUDGET_MS,
        )?;
        // 429 / 配额型 403 的延迟重试（`quota_retry_*`）：这是配额型失败的主开关，
        // 挡掉 0 值——0 毫秒等于「不等就重试」，0 次等于「首试就放弃」，都是配置错误
        // 而不是保护。上限与 opencode_rotation 里的常量同口径。
        validate_bounded_uint(
            section,
            crate::opencode_rotation::OPENCODE_QUOTA_RETRY_BASE_MS_FIELD,
            1,
            crate::opencode_rotation::MAX_OPENCODE_QUOTA_RETRY_DELAY_MS,
        )?;
        validate_bounded_uint(
            section,
            crate::opencode_rotation::OPENCODE_QUOTA_RETRY_MAX_MS_FIELD,
            1,
            crate::opencode_rotation::MAX_OPENCODE_QUOTA_RETRY_DELAY_MS,
        )?;
        validate_bounded_uint(
            section,
            crate::opencode_rotation::OPENCODE_QUOTA_RETRY_MULTIPLIER_FIELD,
            1,
            crate::opencode_rotation::MAX_OPENCODE_QUOTA_RETRY_MULTIPLIER,
        )?;
        validate_bounded_uint(
            section,
            crate::opencode_rotation::OPENCODE_QUOTA_RETRY_MAX_ATTEMPTS_FIELD,
            1,
            u64::from(crate::opencode_rotation::MAX_OPENCODE_QUOTA_RETRY_ATTEMPTS),
        )?;
        for field in [
            "auto_enabled",
            "rotation_enabled",
            "proxy_enabled",
            crate::opencode_rotation::OPENCODE_SEGMENT_BUDGET_ENABLED_FIELD,
            crate::opencode_rotation::OPENCODE_QUOTA_RETRY_ENABLED_FIELD,
        ] {
            validate_bool(section, field)?;
        }
        Ok(())
    }

    /// 从 JSON 对象读取扫描配置。存在 `opencode_scan` 段时用该段，
    /// 否则把对象本身当作配置段（PUT config 的请求体走这条路径）。
    pub(crate) fn from_provider_config_object(object: &serde_json::Map<String, Value>) -> Self {
        let mut result = Self::default();
        let section = object
            .get("opencode_scan")
            .and_then(Value::as_object)
            .unwrap_or(object);
        result.cidrs = string_list(section.get("cidrs"));
        if let Some(Value::String(value)) = section.get("last_scan_at") {
            result.last_scan_at = Some(value.clone());
        }
        result.candidates = string_list(section.get("candidates"));
        result.pinned = string_list(section.get("pinned"));
        if let Some(Value::Bool(enabled)) = section.get("auto_enabled") {
            result.auto_enabled = *enabled;
        }
        if let Some(value) = section.get("interval_hours").and_then(Value::as_u64) {
            result.interval_hours = Some(value as u32);
        }
        if let Some(value) = section.get("concurrency").and_then(Value::as_u64) {
            result.concurrency = Some(value as usize);
        }
        if let Some(value) = section
            .get("max_candidates_per_round")
            .and_then(Value::as_u64)
        {
            result.max_candidates_per_round = Some(value as usize);
        }
        if let Some(value) = section
            .get("probe_max_handshake_ms")
            .and_then(Value::as_u64)
        {
            result.probe_max_handshake_ms = Some(value);
        }
        if let Some(Value::Bool(enabled)) = section.get("rotation_enabled") {
            result.rotation_enabled = *enabled;
        }
        if let Some(value) = section.get("cooldown_minutes").and_then(Value::as_u64) {
            result.cooldown_minutes = Some(value as u32);
        }
        // 这一条必须在这里解析（不能只写在 `merged_with_payload` 里）：
        // 保存路径写进去的值，请求路径要靠 `from_provider_config` 读回来，
        // 少一处就等于「面板上设了、实际永远用默认值」。
        if let Some(value) = section.get("evict_fail_threshold").and_then(Value::as_u64) {
            result.evict_fail_threshold = Some(value as u32);
        }
        if let Some(value) = section.get("proxy_domain").and_then(Value::as_str) {
            let trimmed = value.trim();
            if !trimmed.is_empty() {
                result.proxy_domain = Some(trimmed.to_string());
            }
        }
        if let Some(Value::Array(items)) = section.get("exit_pool") {
            result.exit_pool = items
                .iter()
                .filter_map(Value::as_str)
                .map(str::trim)
                .filter(|value| !value.is_empty())
                .map(str::to_string)
                .collect();
        }
        // `exit_pool_disabled` 也要在这里读。它以前只被 `merged_with_payload` 写、
        // 没人读回来，于是「人工停用某个 IP」在请求路径上根本不存在（`in_use` 计数
        // 与选点的硬跳过都读不到它）。轮转池现在按它扣减，少了这一步等于开关失效。
        if let Some(Value::Array(items)) = section.get("exit_pool_disabled") {
            result.exit_pool_disabled = items
                .iter()
                .filter_map(Value::as_str)
                .map(str::trim)
                .filter(|value| !value.is_empty())
                .map(str::to_string)
                .collect();
        }
        if let Some(Value::Bool(enabled)) = section.get("proxy_enabled") {
            result.proxy_enabled = *enabled;
        }
        result
    }

    /// 输出裸配置对象（不含 `opencode_scan` 外层键），由调用方决定存放位置。
    pub(crate) fn to_provider_config_value(&self) -> Value {
        json!({
            "cidrs": self.cidrs,
            "last_scan_at": self.last_scan_at,
            "candidates": self.candidates.clone(),
            "pinned": self.pinned.clone(),
            "auto_enabled": self.auto_enabled,
            "interval_hours": self.interval_hours.unwrap_or(0),
            "concurrency": self.effective_concurrency(),
            "max_candidates_per_round": self.effective_max_candidates_per_round(),
            "probe_max_handshake_ms": self.effective_probe_max_handshake_ms(),
            "rotation_enabled": self.rotation_enabled,
            "cooldown_minutes": self.effective_cooldown_minutes(),
            "quota_fail_threshold": self.quota_fail_threshold(),
            "quota_attribution_window_minutes": self.quota_attribution_window_minutes(),
            "runtime_fail_threshold": self.runtime_fail_threshold(),
            "runtime_fail_window_minutes": self.runtime_fail_window_minutes(),
            "suspect_ttl_minutes": self.suspect_ttl_minutes(),
            "evict_fail_threshold": self.evict_fail_threshold(),
            "probe_model": self.probe_model(),
            "probe_interval_ms": self.probe_interval_ms(),
            "proxy_domain": self.proxy_domain.clone().unwrap_or_default(),
            "proxy_enabled": self.proxy_enabled,
            "exit_pool": self.exit_pool.clone(),
            "exit_pool_disabled": self.exit_pool_disabled.clone(),
        })
    }

    pub(crate) fn effective_concurrency(&self) -> usize {
        self.concurrency
            .unwrap_or(OPENCODE_SCAN_DEFAULT_CONCURRENCY)
            .clamp(1, OPENCODE_SCAN_MAX_CONCURRENCY)
    }

    /// 生效的单轮候选上限：配置优先，未配置用 [`OPENCODE_SCAN_MAX_CANDIDATES`]。
    pub(crate) fn effective_max_candidates_per_round(&self) -> usize {
        self.max_candidates_per_round
            .unwrap_or(OPENCODE_SCAN_MAX_CANDIDATES)
            .clamp(1, OPENCODE_SCAN_MAX_CANDIDATES_LIMIT)
    }

    /// 生效的扫描快筛阈值：**配置 > 环境变量 > 代码默认 600ms**。
    pub(crate) fn effective_probe_max_handshake_ms(&self) -> u64 {
        self.probe_max_handshake_ms
            .unwrap_or_else(|| probe_max_round_trip_ms() as u64)
            .clamp(
                OPENCODE_PROBE_MIN_HANDSHAKE_MS,
                OPENCODE_PROBE_MAX_HANDSHAKE_MS_LIMIT,
            )
    }

    /// 阈值来源：`config` = 面板配置的，`env` = 环境变量兜底，`default` = 代码默认。
    ///
    /// 面板要能说明"这个数字是配的还是兜底的"——否则用户改了环境变量却看见
    /// 一个配置值，会以为改动没生效。
    pub(crate) fn probe_max_handshake_source(&self) -> &'static str {
        if self.probe_max_handshake_ms.is_some() {
            "config"
        } else if std::env::var(OPENCODE_PROBE_MAX_HANDSHAKE_ENV).is_ok() {
            "env"
        } else {
            "default"
        }
    }

    /// 扫描游标需要的存活时长。
    ///
    /// 一轮真实扫描要跨 `ceil(候选总数 / 单轮上限)` 个 interval；游标一旦过期就从
    /// 第 0 个重来，超出单轮上限的网段会被**静默饿死**（见 [`Self::scan_slice`] 的注释）。
    /// 所以 TTL 要覆盖"一整轮扫描"而不是"一个 interval"，再留 2 倍余量。
    pub(crate) fn scan_cursor_ttl_seconds(&self, total_candidates: usize) -> u64 {
        let rounds = total_candidates
            .div_ceil(self.effective_max_candidates_per_round().max(1))
            .max(1) as u64;
        let interval_secs = self.interval_hours.unwrap_or(0) as u64 * 3600;
        interval_secs
            .saturating_mul(rounds)
            .saturating_mul(2)
            .max(OPENCODE_SCAN_CURSOR_MIN_TTL_SECONDS)
    }

    /// 自动扫描是否真正生效：开关打开且间隔大于 0。
    pub(crate) fn autoscan_effective(&self) -> bool {
        self.auto_enabled && self.interval_hours.unwrap_or(0) > 0
    }

    /// 冷却时长（分钟），带默认值与下限保护。
    /// 配额类失败把出口 IP 打成 suspect 的阈值（默认 1 次）。
    pub(crate) fn quota_fail_threshold(&self) -> u32 {
        self.quota_fail_threshold
            .filter(|value| *value > 0)
            .unwrap_or(1)
    }

    /// 配额类失败归因窗口（分钟，默认 10）：窗口内有成功才归因到出口 IP。
    pub(crate) fn quota_attribution_window_minutes(&self) -> u32 {
        self.quota_attribution_window_minutes
            .filter(|value| *value > 0)
            .unwrap_or(10)
    }

    /// 其它运行时失败的阈值（默认 3 次）。
    pub(crate) fn runtime_fail_threshold(&self) -> u32 {
        self.runtime_fail_threshold
            .filter(|value| *value > 0)
            .unwrap_or(3)
    }

    /// 其它运行时失败的计数窗口（分钟，默认 60）。
    pub(crate) fn runtime_fail_window_minutes(&self) -> u32 {
        self.runtime_fail_window_minutes
            .filter(|value| *value > 0)
            .unwrap_or(60)
    }

    /// suspect 冷却时长（分钟，默认 20）。
    pub(crate) fn suspect_ttl_minutes(&self) -> u32 {
        self.suspect_ttl_minutes
            .filter(|value| *value > 0)
            .unwrap_or(20)
    }

    /// 连续失败多少次后自动出池（默认 3；`0` = 关闭，返回 0 表示不判）。
    ///
    /// `None` 与 `Some(0)` 的语义必须分开：`None` 是「没配过」→ 用默认 3，
    /// `Some(0)` 是「明确关掉」。旧代码里 `.filter(|value| *value > 0)` 的写法会把
    /// 两者混成一个，那样就没有办法关掉自动出池——而配额枯竭的日子里，
    /// 「IP 一被 429 就从池里消失」正是必须能关掉的那个行为。
    pub(crate) fn evict_fail_threshold(&self) -> u32 {
        match self.evict_fail_threshold {
            None => OPENCODE_DEFAULT_EVICT_FAILS,
            Some(value) => value,
        }
    }

    /// 复验用的真实 chat 探测模型（默认 `big-pickle`）。
    pub(crate) fn probe_model(&self) -> String {
        self.probe_model
            .as_deref()
            .map(str::trim)
            .filter(|value| !value.is_empty())
            .unwrap_or("big-pickle")
            .to_string()
    }

    /// 相邻两次 chat 探测的最小间隔（毫秒，默认 2500；0 = 不限速）。
    pub(crate) fn probe_interval_ms(&self) -> u64 {
        self.probe_interval_ms.unwrap_or(2_500)
    }

    /// 额度耗尽后的冷却时长（分钟）。
    pub(crate) fn effective_cooldown_minutes(&self) -> u32 {
        self.cooldown_minutes
            .unwrap_or(crate::opencode_rotation::DEFAULT_COOLDOWN_MINUTES)
            .max(1)
    }

    /// 轮转是否可用：开关打开且池内确实有配置了出口 IP 的 key。
    pub(crate) fn rotation_effective(&self) -> bool {
        self.rotation_enabled
    }

    /// 生产轮转实际使用的集合（**trust-on-add**）。
    ///
    /// 组成（精确、有序）：
    ///
    /// ```text
    /// effective_pool = [ healthy 里去掉 abnormal/blocked 的成员 ]   // 已复验转正，顺序不变
    ///               ++ [ exit_pool 里既不在 healthy、也不在 abnormal/blocked 的成员 ]
    /// ```
    ///
    /// 也就是说 **`exit_pool` 里「已加入但从未验证」的 IP 直接参与轮转**，由真实
    /// 流量的成败来筛选它们（失败累计到 `evict_fail_threshold` 就从池里摘掉，
    /// 见 [`evict_opencode_exit_ip`]）。这是刻意的：探测一次就是对该 IP 发一次真实
    /// chat，会消耗它本就很少的免费额度；2000 个 IP 全验要 15 小时，还会把老 IP
    /// 踢出 healthy。加进来不验证，才可能从 194 扩到 2000+。
    ///
    /// 两条硬约束：
    /// - `abnormal` / `blocked` 的成员**不参与**（前者是复验判过的问题 IP，后者是
    ///   人工否决）；`exit_pool_disabled` 不在这里剔除——`in_use` 计数与选点自己会
    ///   扣掉它，这与改动前 `healthy` 里被停用的 IP 的处理完全一致。
    /// - `candidates` **绝不**进这个集合：候选只是「探通了」的粗筛产物，扫描即上线
    ///   正是线上 503 的根源（见 `run_open_code_pool_scan_inner`）。
    ///
    /// `healthy` 为空时旧行为是退回整个 `exit_pool`；新组成天然包含这种情况
    /// （`healthy` 为空 ⇒ 只剩 `exit_pool` 里未异常/未拉黑的成员），语义不变。
    pub(crate) fn effective_pool(&self, health: &OpenCodeHealthConfig) -> Vec<String> {
        let (verified, trusted) = self.rotation_pool_parts(health);
        let mut pool = Vec::with_capacity(verified.len() + trusted.len());
        pool.extend(verified);
        pool.extend(trusted);
        pool
    }

    /// 轮转池里「已复验转正」与「trust-on-add（未验证）」两段，顺序与
    /// [`Self::effective_pool`] 一致。
    ///
    /// 两段分开返回是为了对外计数：`rotation_pool_size` 说的是「轮转池有多大」，
    /// 而「其中多少真的被验证过」是另一个问题。把它们混成一个数，面板上就没法
    /// 区分「194 个验过的」和「194 个验过的 + 1806 个没验过的」。
    pub(crate) fn rotation_pool_parts(
        &self,
        health: &OpenCodeHealthConfig,
    ) -> (Vec<String>, Vec<String>) {
        let abnormal = health.abnormal_ips();
        let blocked = health.blocked_ips();
        let mut seen: BTreeSet<String> = BTreeSet::new();
        let mut verified: Vec<String> = Vec::with_capacity(health.healthy.len());
        for ip in &health.healthy {
            let trimmed = ip.trim();
            if trimmed.is_empty() {
                continue;
            }
            // 同一个 IP 既在 healthy 又在 abnormal 是配置被并发写坏时的中间态；
            // 此时按「先别用」处理（异常池是更保守的那一方）。
            if abnormal.contains(trimmed) || blocked.contains(trimmed) {
                continue;
            }
            if seen.insert(trimmed.to_string()) {
                verified.push(trimmed.to_string());
            }
        }
        let mut trusted: Vec<String> = Vec::new();
        for ip in &self.exit_pool {
            let trimmed = ip.trim();
            if trimmed.is_empty() {
                continue;
            }
            if abnormal.contains(trimmed) || blocked.contains(trimmed) {
                continue;
            }
            if seen.insert(trimmed.to_string()) {
                trusted.push(trimmed.to_string());
            }
        }
        (verified, trusted)
    }

    /// 轮转池里「已加入但未验证」的数量（对外计数用）。
    pub(crate) fn trusted_on_add_count(&self, health: &OpenCodeHealthConfig) -> usize {
        self.rotation_pool_parts(health).1.len()
    }

    /// 本次请求应该使用的前置代理 host。
    ///
    /// 开关关闭、或没填域名时返回 `None`——此时应当直连默认官方域名。
    /// 这个值只在请求路径上生效，绝不写回 `endpoint.base_url`。
    pub(crate) fn effective_proxy_domain(&self) -> Option<String> {
        if !self.proxy_enabled {
            return None;
        }
        self.proxy_domain
            .as_deref()
            .map(str::trim)
            .filter(|domain| !domain.is_empty())
            .map(str::to_string)
    }

    /// 从 CIDR 枚举候选 IP，排除池中已有 IP 与网络/广播地址。
    ///
    /// 结果按字典序稳定排列，交给 [`Self::scan_slice`] 按游标切片。
    pub(crate) fn candidate_ips(&self, known_ips: &BTreeSet<String>) -> Vec<String> {
        let mut candidates = BTreeSet::new();
        for cidr in &self.cidrs {
            let Some((prefix, bits)) = parse_cidr(cidr) else {
                continue;
            };
            let host_bits = (32 - bits).max(1);
            let host_count = (1u32 << host_bits.min(30)) as u64;
            let base = prefix as u64;
            for offset in 1..host_count.saturating_sub(1) {
                let value = base + offset;
                let octets = [
                    (value >> 24) as u8,
                    (value >> 16) as u8,
                    (value >> 8) as u8,
                    value as u8,
                ];
                let ip = format!("{}.{}.{}.{}", octets[0], octets[1], octets[2], octets[3]);
                if !known_ips.contains(&ip) {
                    candidates.insert(ip);
                }
            }
        }
        candidates.into_iter().collect()
    }

    /// 按游标切出本轮要探的一段，并算出下一轮的游标。
    ///
    /// 没有游标时，候选超过 [`OPENCODE_SCAN_MAX_CANDIDATES`] 会让每轮只探字典序
    /// 最靠前的同一批（探不通的 IP 永远排在前面），后面的网段被静默饿死。
    pub(crate) fn scan_slice(&self, candidates: &[String], cursor: u64) -> (Vec<String>, u64) {
        let total = candidates.len();
        if total == 0 {
            return (Vec::new(), 0);
        }
        let start = if (cursor as usize) < total {
            cursor as usize
        } else {
            0
        };
        let end = start
            .saturating_add(self.effective_max_candidates_per_round())
            .min(total);
        let selected = candidates[start..end].to_vec();
        // 本轮探完整段则回到开头，否则接着往后走。
        let next_cursor = if end >= total { 0 } else { end as u64 };
        (selected, next_cursor)
    }
}

/// 解析 IPv4 CIDR（`a.b.c.d/len`），返回 (网络地址, 前缀长度)。
pub(crate) fn parse_cidr(cidr: &str) -> Option<(u32, u32)> {
    let (addr_part, len_part) = cidr.split_once('/')?;
    let bits = len_part.trim().parse::<u32>().ok()?;
    if bits == 0 || bits > 32 {
        return None;
    }
    let IpAddr::V4(ipv4) = addr_part.trim().parse::<IpAddr>().ok()? else {
        return None;
    };
    let value = u32::from(ipv4);
    let mask = u32::MAX << (32 - bits);
    Some((value & mask, bits))
}

/// 读取池 key 上配置的出口 IP。
///
/// 唯一来源是 `upstream_metadata.opencode_exit_ip`（本仓库既有约定）。
pub(crate) fn opencode_pool_key_ip(key: &StoredProviderCatalogKey) -> Option<String> {
    let raw = key
        .upstream_metadata
        .as_ref()
        .and_then(|metadata| metadata.get(OPENCODE_EXIT_IP_METADATA_KEY))
        .and_then(Value::as_str)?
        .trim()
        .to_string();
    if raw.is_empty() || raw.parse::<IpAddr>().is_err() {
        return None;
    }
    Some(raw)
}

/// 列出 Provider 的池 IP，供状态接口渲染，不暴露任何凭据。
pub(crate) async fn list_opencode_pool_ips(
    app: &AppState,
    provider_id: &str,
    config: &OpenCodeScanConfig,
) -> Result<Vec<Value>, GatewayError> {
    // provider 级 IP 池是权威来源：IP 属于「池」，不属于「密钥」。
    // 密钥只负责鉴权，凭据数量和 IP 数量本来就不该相等。
    if !config.exit_pool.is_empty() {
        let keys = app
            .list_provider_catalog_keys_by_provider_ids(&[provider_id.to_string()])
            .await?;
        let disabled: BTreeSet<String> = config
            .exit_pool_disabled
            .iter()
            .map(|ip| ip.trim().to_string())
            .filter(|ip| !ip.is_empty())
            .collect();
        return Ok(config
            .exit_pool
            .iter()
            .map(|ip| ip.trim())
            .filter(|ip| !ip.is_empty())
            .map(|ip| {
                // key_id 仅用于兼容旧前端：只有当某个 key 仍带着这个 IP 的元数据时才回填
                let key_id = keys
                    .iter()
                    .find(|key| opencode_pool_key_ip(key).as_deref() == Some(ip))
                    .map(|key| Value::String(key.id.clone()))
                    .unwrap_or(Value::String(String::new()));
                json!({
                    "key_id": key_id,
                    "ip": ip,
                    "is_active": !disabled.contains(ip),
                    "source": "provider",
                })
            })
            .collect());
    }

    // 兼容旧数据：IP 存在 key 元数据里。
    let keys = app
        .list_provider_catalog_keys_by_provider_ids(&[provider_id.to_string()])
        .await?;
    Ok(keys
        .iter()
        .filter_map(|key| {
            let ip = opencode_pool_key_ip(key)?;
            Some(json!({
                "key_id": key.id,
                "ip": ip,
                "is_active": key.is_active,
                "source": "key",
            }))
        })
        .collect())
}

/// 从 Provider 的 Endpoint 解析上游域名与端口。
pub(crate) async fn opencode_upstream_target(
    app: &AppState,
    provider_id: &str,
    config: &OpenCodeScanConfig,
) -> Result<(String, u16), GatewayError> {
    // 探测目标必须是**前置代理域名**。池里的 IP 都是该域名背后的 CDN 节点，
    // 如果拿当前端点主机去探：开关关闭时端点是官方域名，用官方域名的 SNI 连这些
    // 节点必然 TLS 失败，于是「清理」会把整个池误判为失效并全部删除。
    // 因此优先使用配置里记住的代理域名，端点主机只作为没有配置时的兜底。
    if let Some(domain) = config
        .proxy_domain
        .as_deref()
        .map(str::trim)
        .filter(|domain| !domain.is_empty())
    {
        let port = config
            .proxy_domain
            .as_deref()
            .and_then(|domain| url::Url::parse(&format!("https://{domain}")).ok())
            .and_then(|url| url.port_or_known_default())
            .unwrap_or(443);
        return Ok((domain.to_string(), port));
    }
    let endpoints = app
        .list_provider_catalog_endpoints_by_provider_ids(&[provider_id.to_string()])
        .await?;
    for endpoint in endpoints {
        if let Ok(url) = url::Url::parse(endpoint.base_url.trim()) {
            if let Some(host) = url.host_str() {
                if let Some(port) = url.port_or_known_default() {
                    return Ok((host.to_string(), port));
                }
            }
        }
    }
    Err(GatewayError::Internal(
        "无法从供应商端点解析上游域名/端口，请先配置端点".to_string(),
    ))
}

/// 探测目标是否就是官方直连域名。这种情况下探测结果不可信，禁止执行清理。
pub(crate) fn probe_target_is_official(domain: &str) -> bool {
    domain
        .trim()
        .eq_ignore_ascii_case(aether_provider_transport::opencode::OPENCODE_ORIGINAL_DOMAIN)
}

/// 扫描一轮：探测配置的网段，为每个健康新 IP 建一个池 key。
pub(crate) async fn run_open_code_pool_scan(
    app: &AppState,
    provider: &StoredProviderCatalogProvider,
) -> Result<ScanSummary, GatewayError> {
    let provider_id = provider.id.clone();
    let config = OpenCodeScanConfig::from_provider_config(&provider.config);
    // 候选有两个来源：用户填的 CIDR，以及**前置代理域名的 DNS**。后者才是跟得上
    // CDN 换段的那个——换 CDN 只改域名，扫描自动跟随；旧网段 `108.138.0.0/24`
    // 就是因为没人改 CIDR，整段失效后还在被反复扫描（2026-10-17 实测 254 个全废）。
    if config.cidrs.is_empty() && config.effective_proxy_domain().is_none() {
        return Err(GatewayError::Internal(
            "未配置扫描网段、也没有前置代理域名：请至少填其中一个（推荐直接填域名）".to_string(),
        ));
    }
    if opencode_ip_pool_status_for(&provider_id).scanning {
        return Err(GatewayError::Internal("扫描正在进行中".to_string()));
    }
    update_opencode_ip_pool_status(&provider_id, |status| status.scanning = true);
    // 兜底闸：任务被取消（tokio abort）或 unwind panic 时，正常的收尾代码不会执行，
    // `scanning` 就会永远卡在 true —— 表现为「每次进供应商都显示扫描中」，
    // 而且再也点不动扫描。靠 Drop 保证任何退出路径都会复位。
    let _guard = ScanFlagGuard {
        provider_id: provider_id.clone(),
    };

    let outcome = run_open_code_pool_scan_inner(app, provider, &config).await;

    update_opencode_ip_pool_status(&provider_id, |status| {
        status.scanning = false;
        if let Ok(summary) = &outcome {
            status.last_scan_targets = summary.targets;
            status.last_scan_found = summary.found;
            status.last_scan_added = summary.added;
            status.last_scan_at = Some(now_string());
            status.last_scan_at_unix_secs = Some(now_unix_secs());
        }
    });
    outcome
}

/// 扫描结束时（正常/取消/panic）都复位 `scanning` 标志。
struct ScanFlagGuard {
    provider_id: String,
}

impl Drop for ScanFlagGuard {
    fn drop(&mut self) {
        update_opencode_ip_pool_status(&self.provider_id, |status| {
            if status.scanning {
                tracing::warn!(
                    event_name = "opencode_ip_pool_scan_abandoned",
                    log_type = "ops",
                    provider_id = self.provider_id.as_str(),
                    "opencode ip pool scan exited without clearing its flag; reset"
                );
            }
            status.scanning = false;
        });
    }
}

/// 标记扫描已开始，返回 false 表示已有扫描在跑。
///
/// 供「异步触发」入口使用：先同步占位再返回 202，避免客户端轮询到
/// `scanning=false` 的空窗期。真正的清理由 `ScanFlagGuard` 负责。
/// 任一池任务（扫描 / 清理 / 整轮复验 / 一键复验）在跑时为 true。
///
/// 四个入口都会写 `provider.config`，同时跑就是互相覆盖，所以互斥必须**对称**：
/// 每个 claim 都要检查另外三个。2026-10-18 实测踩过一次——只在新入口里检查对方，
/// 老入口不知道新任务的存在，于是「一键复验」和「整轮复验」同时跑、互相覆盖 healthy。
fn any_pool_task_running(provider_id: &str) -> bool {
    let status = opencode_ip_pool_status_for(provider_id);
    status.scanning || status.cleaning || status.verifying || status.reverify_running
}

pub(crate) fn claim_scan_slot(provider_id: &str) -> bool {
    if any_pool_task_running(provider_id) {
        return false;
    }
    update_opencode_ip_pool_status(provider_id, |status| {
        status.scanning = true;
        status.progress_done = 0;
        status.progress_total = 0;
        status.progress_kind = Some("scan".to_string());
    });
    true
}

/// 标记清理已开始，返回 false 表示已有清理在跑。
pub(crate) fn claim_clean_slot(provider_id: &str) -> bool {
    if any_pool_task_running(provider_id) {
        return false;
    }
    update_opencode_ip_pool_status(provider_id, |status| {
        status.cleaning = true;
        status.progress_done = 0;
        status.progress_total = 0;
        status.progress_kind = Some("clean".to_string());
    });
    true
}

/// 扫描主体。调用方必须已用 [`claim_scan_slot`] 占位（同步或异步触发都算）。
pub(crate) async fn run_claimed_open_code_pool_scan(
    app: &AppState,
    provider: &StoredProviderCatalogProvider,
) -> Result<ScanSummary, GatewayError> {
    let provider_id = provider.id.clone();
    let config = OpenCodeScanConfig::from_provider_config(&provider.config);
    let _guard = ScanFlagGuard {
        provider_id: provider_id.clone(),
    };
    let outcome = run_open_code_pool_scan_inner(app, provider, &config).await;
    update_opencode_ip_pool_status(&provider_id, |status| {
        if let Ok(summary) = &outcome {
            status.last_scan_targets = summary.targets;
            status.last_scan_found = summary.found;
            status.last_scan_added = summary.added;
            status.last_scan_at = Some(now_string());
            status.last_scan_at_unix_secs = Some(now_unix_secs());
        }
    });
    outcome
}

/// 清理主体。调用方必须已用 [`claim_clean_slot`] 占位。
pub(crate) async fn run_claimed_open_code_pool_clean(
    app: &AppState,
    provider: &StoredProviderCatalogProvider,
) -> Result<CleanSummary, GatewayError> {
    let provider_id = provider.id.clone();
    let _guard = CleanFlagGuard {
        provider_id: provider_id.clone(),
    };
    let outcome = run_open_code_pool_clean_inner(app, provider).await;
    update_opencode_ip_pool_status(&provider_id, |status| {
        if let Ok(summary) = &outcome {
            status.last_clean_checked = summary.checked;
            status.last_clean_removed = summary.removed;
            status.last_clean_at = Some(now_string());
        }
    });
    outcome
}

/// 一轮验健康的结果摘要。
#[derive(Debug, Default, Clone)]
pub(crate) struct VerifySummary {
    pub(crate) checked: u64,
    pub(crate) kept: u64,
    pub(crate) dropped: u64,
    /// 因为低于保底池大小而放弃淘汰的数量。
    pub(crate) spared_by_floor: u64,
    /// 本轮达到丢弃门槛、被删记录的节点数。
    pub(crate) discarded: u64,
    /// 本轮结束后异常池的条目数。
    pub(crate) abnormal: u64,
}

/// 标记验健康已开始，返回 false 表示已有扫描或验健康在跑。
///
/// 两者互斥：并发探测同一批节点既没有意义，也会让进度数字互相覆盖。
pub(crate) fn claim_verify_slot(provider_id: &str) -> bool {
    if any_pool_task_running(provider_id) {
        return false;
    }
    update_opencode_ip_pool_status(provider_id, |status| {
        status.verifying = true;
        status.verify_progress_done = 0;
        status.verify_progress_total = 0;
        status.verify_targets = 0;
    });
    true
}

/// 验健康结束时复位 `verifying`。
struct VerifyFlagGuard {
    provider_id: String,
}

impl Drop for VerifyFlagGuard {
    fn drop(&mut self) {
        update_opencode_ip_pool_status(&self.provider_id, |status| {
            status.verifying = false;
        });
    }
}

fn verify_progress_callback(provider_id: &str) -> Arc<dyn Fn(u64) + Send + Sync> {
    let provider_id = provider_id.to_string();
    Arc::new(move |done| {
        update_opencode_ip_pool_status(&provider_id, |status| {
            status.verify_progress_done = done;
        });
    })
}

/// 标记「一键复验（池内 IP）」已开始；返回 false 表示已有扫描/复验/清理在跑。
///
/// 与整轮复验共用同一把互斥：两个入口都会写 `opencode_health`，同时跑就是互相覆盖。
pub(crate) fn claim_reverify_slot(provider_id: &str) -> bool {
    if any_pool_task_running(provider_id) {
        return false;
    }
    update_opencode_ip_pool_status(provider_id, |status| {
        status.reverify_running = true;
        status.reverify_progress_done = 0;
        status.reverify_progress_total = 0;
    });
    true
}

/// 一键复验结束时复位 `reverify_running`（任务被 abort / panic 也会走到）。
struct ReverifyFlagGuard {
    provider_id: String,
}

impl Drop for ReverifyFlagGuard {
    fn drop(&mut self) {
        update_opencode_ip_pool_status(&self.provider_id, |status| {
            status.reverify_running = false;
        });
    }
}

fn reverify_progress_callback(provider_id: &str) -> Arc<dyn Fn(u64) + Send + Sync> {
    let provider_id = provider_id.to_string();
    Arc::new(move |done| {
        update_opencode_ip_pool_status(&provider_id, |status| {
            status.reverify_progress_done = done;
        });
    })
}

/// 验健康任务主体。调用方必须已用 [`claim_verify_slot`] 占位。
pub(crate) async fn run_claimed_open_code_pool_verify(
    app: &AppState,
    provider: &StoredProviderCatalogProvider,
) -> Result<VerifySummary, GatewayError> {
    let provider_id = provider.id.clone();
    let _guard = VerifyFlagGuard {
        provider_id: provider_id.clone(),
    };
    let outcome = run_open_code_pool_verify_inner(app, provider).await;
    if let Ok(summary) = &outcome {
        // 摘要的落盘已经并入复验主体的那一次写入（见 run_open_code_pool_verify_inner
        // 里的说明）：曾经这里额外再写一次，而那次写用的是任务开始时的陈旧快照，
        // 等于把复验刚算出来的结果整段覆盖回去。这里只更新进程内的展示状态。
        let finished_at = now_string();
        update_opencode_ip_pool_status(&provider_id, |status| {
            status.last_verify_checked = summary.checked;
            status.last_verify_kept = summary.kept;
            status.last_verify_dropped = summary.dropped;
            status.last_verify_at = Some(finished_at);
        });
    }
    outcome
}

/// 单点复验的结果。响应体由调用方拼（这里不引入 serde 派生，保持字段即语义）。
#[derive(Debug, Clone)]
pub struct OpenCodeSingleVerifyOutcome {
    pub ip: String,
    /// 是否通过：全部采样成功，且首字节中位数在阈值内。
    pub healthy: bool,
    /// 未通过时的原因（`unreachable` / `partial_timeout` / `too_slow`）；通过时为 `None`。
    pub reason: Option<String>,
    /// 本轮采样的首字节中位数（毫秒）。
    pub median_ms: Option<u64>,
    /// 异常池里累计的失败轮数（通过后清零）。
    pub fails: u32,
}

/// 一键复验**全部手动池内 IP**（`scan.exit_pool`）：批量版单点复验。
///
/// 语义与 [`run_open_code_pool_verify_single`] 完全一致——通过即转正进 healthy
/// （参与轮转）、不过则记入异常池跟踪，**永不丢弃**、不动候选池、池内 IP 列表
/// 本身也不动（彻底不通的由 clean 任务剔除）。只有整轮复验有权按跨轮证据丢弃。
///
/// 与整轮复验的分工：整轮要重扫候选 ∪ 在用 ∪ 异常（默认 12 小时、约 3 分钟），
/// 这个入口只探测手动加的那几个 IP，秒级返回，供「池内 IP」区域的复验按钮使用。
/// 池内 IP 为空时直接返回空结果（不探测、不写配置）。
/// 一键复验（池内 IP）的后台任务主体。调用方必须已用 [`claim_reverify_slot`] 占位。
///
/// 之所以要这个包装：Drop guard 必须覆盖整个任务（包括 panic / abort），否则
/// `reverify_running` 会永久为 true，把后续所有扫描/复验挡成 400。
pub(crate) async fn run_claimed_exit_ips_batch_verify(
    app: &AppState,
    provider: &StoredProviderCatalogProvider,
) -> Result<Vec<OpenCodeSingleVerifyOutcome>, GatewayError> {
    let _guard = ReverifyFlagGuard {
        provider_id: provider.id.clone(),
    };
    run_open_code_pool_verify_pool_ips(app, provider).await
}

pub async fn run_open_code_pool_verify_pool_ips(
    app: &AppState,
    provider: &StoredProviderCatalogProvider,
) -> Result<Vec<OpenCodeSingleVerifyOutcome>, GatewayError> {
    let provider_id = provider.id.clone();
    let scan = OpenCodeScanConfig::from_provider_config(&provider.config);
    let mut targets: Vec<String> = Vec::new();
    for ip in scan.exit_pool.iter().map(|ip| ip.trim()) {
        if !ip.is_empty() && !targets.iter().any(|existing| existing == ip) {
            targets.push(ip.to_string());
        }
    }
    if targets.is_empty() {
        return Ok(Vec::new());
    }

    let mut health = OpenCodeHealthConfig::from_provider_config(&provider.config);
    let (domain, port) = opencode_upstream_target(app, &provider_id, &scan).await?;
    if probe_target_is_official(&domain) {
        return Err(GatewayError::Internal(
            "未配置前置代理域名，无法判断节点是否健康；请先在前置代理池里填写并保存 CDN 域名，再执行复验"
                .to_string(),
        ));
    }

    let max_median_ms = health.verify_max_median_ms();
    let samples = health.verify_samples();
    let concurrency = scan.effective_concurrency();
    // 进度分母与整轮复验同口径：IP 数 × 每 IP 采样次数。
    let total_jobs = targets.len() as u64 * samples as u64;
    update_opencode_ip_pool_status(&provider_id, |status| {
        status.reverify_progress_done = 0;
        status.reverify_progress_total = total_jobs;
    });
    let verdicts = verify_ips(
        &targets,
        &domain,
        port,
        samples,
        concurrency,
        &scan.probe_model(),
        scan.probe_interval_ms(),
        Some(reverify_progress_callback(&provider_id)),
    )
    .await;

    let mut outcomes = Vec::with_capacity(targets.len());
    for target in targets {
        let verdict = verdicts.get(&target);
        let healthy = verdict.is_some_and(|item| item.is_healthy(max_median_ms));
        let median_ms = verdict.and_then(|item| item.median_ms);
        if healthy {
            health.clear_abnormal(&target);
            if !health.healthy.iter().any(|existing| existing == &target) {
                health.healthy.push(target.clone());
            }
        } else {
            // 与整轮复验（`run_open_code_pool_verify_inner`）保持一致：不通过的 IP
            // 必须同时从生产集合里移除。否则同一个 IP 会同时出现在 `healthy` 和
            // `abnormal` 里——选点虽然会按 abnormal 跳过（行为安全），但面板的
            // `healthy` 计数会虚高，看起来"还有 19 个可用"实际只有 13 个。
            health.healthy.retain(|existing| existing != &target);
            health.record_abnormal(
                &target,
                verdict_rejection_reason(verdict),
                median_ms,
                &now_string(),
            );
        }
        let fails = health
            .abnormal
            .iter()
            .find(|entry| entry.ip == target)
            .map(|entry| entry.fails)
            .unwrap_or_default();
        outcomes.push(OpenCodeSingleVerifyOutcome {
            ip: target,
            healthy,
            reason: (!healthy).then(|| verdict_rejection_reason(verdict).to_string()),
            median_ms,
            fails,
        });
    }
    // 延迟列以前只由整轮复验刷新，一键复验完全不更新它——面板上的「延迟」会一直停在
    // 上一次整轮复验的值。这里把本次测到的中位数合并进去（只覆盖被测到的 IP）。
    for (ip, verdict) in &verdicts {
        if let Some(ms) = verdict.median_ms {
            health.latencies.insert(ip.clone(), ms);
        }
    }
    write_health_config(app, provider, &health).await?;

    let checked = outcomes.len();
    let passed = outcomes.iter().filter(|item| item.healthy).count();
    tracing::info!(
        event_name = "opencode_ip_pool_exit_ips_batch_verify",
        provider_id,
        checked,
        passed,
        failed = checked - passed,
        "opencode pool ips batch verify finished"
    );
    Ok(outcomes)
}

async fn run_open_code_pool_verify_inner(
    app: &AppState,
    provider: &StoredProviderCatalogProvider,
) -> Result<VerifySummary, GatewayError> {
    let provider_id = provider.id.clone();
    let scan = OpenCodeScanConfig::from_provider_config(&provider.config);
    let mut health = OpenCodeHealthConfig::from_provider_config(&provider.config);
    health.migrated_from(&scan);

    let (domain, port) = opencode_upstream_target(app, &provider_id, &scan).await?;
    if probe_target_is_official(&domain) {
        return Err(GatewayError::Internal(
            "未配置前置代理域名，无法判断节点是否健康；请先在前置代理池里填写并保存 CDN 域名，再执行复验"
                .to_string(),
        ));
    }

    // 待验集合 = 候选 ∪ 现有健康 ∪ 保护名单。
    // 现有健康必须重验：它现在是生产集合，退化的节点要靠这一步掉出去。
    let mut targets: Vec<String> = Vec::new();
    for ip in scan
        .candidates
        .iter()
        .chain(health.healthy.iter())
        .chain(health.abnormal.iter().map(|entry| &entry.ip))
        .chain(scan.pinned.iter())
    {
        if !targets.iter().any(|existing| existing == ip) {
            targets.push(ip.clone());
        }
    }
    let max_median_ms = health.verify_max_median_ms();
    let samples = health.verify_samples();
    let total_jobs = targets.len() as u64 * samples as u64;
    // 进度**必须**在这里连分子一起归零：`verify_progress_done` 是常驻字段，上一轮跑完
    // 会停在它的终值（例如 717）。只改分母不改分子的话，新一轮刚开始就显示
    // 717/717 = 100%，看起来像「几秒钟就复验完了」，而实际上一次探测都还没做。
    update_opencode_ip_pool_status(&provider_id, |status| {
        status.verify_progress_done = 0;
        status.verify_progress_total = total_jobs;
        status.verify_targets = targets.len() as u64;
    });
    let started_at = std::time::Instant::now();
    tracing::info!(
        event_name = "opencode_ip_pool_verify_started",
        log_type = "ops",
        provider_id,
        targets = targets.len() as u64,
        samples,
        total_jobs,
        concurrency = scan.effective_concurrency(),
        max_median_ms,
        "opencode ip pool verify started"
    );

    let verdicts = verify_ips(
        &targets,
        &domain,
        port,
        samples,
        scan.effective_concurrency(),
        &scan.probe_model(),
        scan.probe_interval_ms(),
        Some(verify_progress_callback(&provider_id)),
    )
    .await;

    let mut kept: Vec<String> = Vec::new();
    let mut degraded: Vec<String> = Vec::new();
    let mut dropped = 0u64;
    for ip in &targets {
        let pinned = scan.pinned.iter().any(|item| item == ip);
        let verdict = verdicts.get(ip);
        let healthy = verdict.is_some_and(|item| item.is_healthy(max_median_ms));
        if health.is_blocked(ip) {
            // 人工拉黑：不进可用池，也不算「异常」——它不是探测出来的问题，
            // 把它记进异常池会让「异常」同时表示两件不同的事。
            dropped += 1;
            continue;
        }
        if healthy {
            kept.push(ip.clone());
        } else if pinned {
            // 保护名单豁免淘汰：保的东西状态可见即可，不该被静默删掉。
            kept.push(ip.clone());
            degraded.push(ip.clone());
        } else {
            dropped += 1;
        }
    }

    // 保底：池子已经比保底线还小时不再淘汰。
    // 淘汰到空不会报错，只会静默把流量压到一个节点上——那比慢更难察觉。
    let mut spared = 0u64;
    if kept.len() < health.min_pool_size() && dropped > 0 {
        let deficit = health.min_pool_size() - kept.len();
        let shortfall = deficit.min(dropped as usize);
        spared = shortfall as u64;
        for ip in &targets {
            if spared == 0 {
                break;
            }
            if kept.iter().any(|item| item == ip) {
                continue;
            }
            let was_healthy = verdicts
                .get(ip)
                .is_some_and(|item| item.is_healthy(max_median_ms));
            if was_healthy {
                continue;
            }
            if health.is_blocked(ip) {
                // 保底也不能把人工拉黑的节点捞回来：那等于用一次「池子太小」
                // 掩盖掉用户明确表达的意图，而且从池子列表上看完全正常。
                continue;
            }
            kept.push(ip.clone());
        }
        // 保护名单与保底保留下来的，仍然要标出降级
        for ip in &kept {
            if !degraded.iter().any(|item| item == ip)
                && !verdicts
                    .get(ip)
                    .is_some_and(|item| item.is_healthy(max_median_ms))
            {
                degraded.push(ip.clone());
            }
        }
        kept.sort();
        kept.dedup();
        dropped = dropped.saturating_sub(spared);
    }

    // 幂等的关键：先备份，再覆盖。任务中途失败时上一次的好结果还在。
    let finished_at = now_string();
    let mut next = health.clone();
    next.healthy_prev = if next.healthy.is_empty() {
        health.healthy.clone()
    } else {
        next.healthy.clone()
    };
    next.healthy = kept.clone();
    next.degraded = degraded;
    // 逐节点延迟：这是界面上「哪些快、哪些慢」的唯一数据来源。之前只有计数，
    // 池里混进 100~200 秒的节点时完全看不出来——那正是这次事故的直接原因。
    next.latencies = verdicts
        .iter()
        .filter_map(|(ip, verdict)| verdict.median_ms.map(|ms| (ip.clone(), ms)))
        .collect();

    // ── 异常池 ────────────────────────────────────────────────────────────
    //
    // 与可用池严格分开：异常池表达「有嫌疑、先别用它」，它不改变本轮的可用池
    // ——把不健康节点留在 healthy 里是复验的失败，不是异常池的失败。
    //
    // 计数每个复验轮最多加一，因此 `fails >= 2` 天然等价于「跨轮失败」：单轮内
    // 的抖动不可能把它推到门槛（实测并发会把 p50 放大 3.9 倍，一次失败说明不了
    // 什么）。池子小到保护线以下时不丢弃——那时丢弃等于把一个可能还用得上的
    // 节点彻底忘掉。
    let discard_allowed = kept.len() >= health.protect_pool_floor();
    let mut discarded: Vec<String> = Vec::new();
    for ip in &targets {
        let pinned = scan.pinned.iter().any(|item| item == ip);
        let verdict = verdicts.get(ip);
        let healthy = verdict.is_some_and(|item| item.is_healthy(max_median_ms));
        if pinned || healthy {
            // 通过、或被人工保护：失败计数清零。保护名单的节点即使不健康也不记
            // 异常——它的语义是「我知道它慢，但我要留着」。
            next.clear_abnormal(ip);
            continue;
        }
        let reason = verdict_rejection_reason(verdict);
        let median_ms = verdict.and_then(|item| item.median_ms);
        let fails = next.record_abnormal(ip, reason, median_ms, &finished_at);
        if abnormal_reached_discard_threshold(fails) && discard_allowed {
            // 丢弃 = 删记录、不再跟踪。它只能因为下一次扫描重新发现而回来，
            // 没有「到期自动回归」这回事。
            //
            // 丢弃是**事件**，不是状态：原因、失败轮数、耗时只写进这条日志，配置里
            // 不留任何痕。留痕曾经存在，问题是它记的是历史——节点可能下一轮扫描就
            // 回到候选，于是同一个 IP 同时出现在「候选」和「已丢弃」，读起来自相矛盾；
            // 而它不参与任何判定（只有面板在读）。要查丢弃史就查日志。
            tracing::info!(
                event_name = "opencode_ip_pool_ip_discarded",
                log_type = "ops",
                provider_id,
                ip = ip.as_str(),
                reason,
                fails,
                median_ms,
                "opencode ip pool discarded an abnormal ip"
            );
            next.clear_abnormal(ip);
            discarded.push(ip.clone());
        }
    }
    for ip in &discarded {
        // 计数保留：它回答「这台机器第几次被丢」（30 天窗口），是唯一能看出惯犯的信号。
        // 原因已经在上面那条丢弃事件里，这里不再重复打一遍。
        crate::opencode_rotation::bump_opencode_ip_discard_count(app, &provider_id, ip).await;
    }

    let summary = VerifySummary {
        checked: targets.len() as u64,
        kept: kept.len() as u64,
        dropped,
        spared_by_floor: spared,
        discarded: discarded.len() as u64,
        abnormal: next.abnormal.len() as u64,
    };

    // 摘要和结果必须**一次**写回。曾经这里是先写 next，之后调用方又调
    // persist_verify_summary 从任务开始时的陈旧快照重建整段再写一次，于是刚写
    // 好的 healthy 被覆盖回旧值：线上实测复验 kept=337、dropped=0，而生产池
    // 仍是 65 个节点，latencies / degraded 一起回滚——健康门槛等于没生效，
    // 界面上的延迟列也一直显示上一轮的数据。摘要搭同一次写入，顺带保证
    // 「kept=N」和「池里 N 个」永远不会再对不上。
    next.last_verify_checked = summary.checked;
    next.last_verify_kept = summary.kept;
    next.last_verify_dropped = summary.dropped;
    next.last_verify_at = Some(finished_at);

    // 丢弃必须**同时**从 `exit_pool` 里摘掉。只清异常池是不够的：轮转池的组成是
    // `healthy ∪ (exit_pool − abnormal − blocked)`（见 `effective_pool`），所以
    // 「清掉异常记录但留在 exit_pool」等于把刚判死的 IP 立刻放回生产——这曾经是
    // 完美自洽的（轮转只看 healthy），加了 trust-on-add 之后就成了复活开关。
    write_pool_state_pair(app, &provider_id, &next, &discarded).await?;

    // 全局熔断告警：一轮复验把可用池砍掉一半以上，第一嫌疑是「我们自己的探针
    // 坏了」。不自动回滚——自动回滚会把真实的集体劣化一起盖掉——只报警，
    // 由人决定要不要「重置全部异常」。
    let before = health.healthy.len();
    let after = kept.len();
    let pool_shrink_alarm = if before >= 2 && after * 2 < before {
        Some(format!(
            "pool_shrunk_by_verify(before={before},after={after})"
        ))
    } else {
        None
    };
    update_opencode_ip_pool_status(&provider_id, |status| {
        status.pool_shrink_alarm = pool_shrink_alarm.clone();
    });

    tracing::info!(
        event_name = "opencode_ip_pool_verify_completed",
        log_type = "ops",
        provider_id,
        checked = summary.checked,
        kept = summary.kept,
        dropped = summary.dropped,
        discarded = summary.discarded,
        abnormal = summary.abnormal,
        discard_allowed,
        spared_by_floor = summary.spared_by_floor,
        max_median_ms,
        samples,
        // 有了它，「这次复验到底跑了多久」不用再靠人工对齐时间戳去猜
        duration_ms = started_at.elapsed().as_millis() as u64,
        "opencode ip pool verify completed"
    );

    update_pool_status_counts(&provider_id, &scan, &next, scan.exit_pool_disabled.len());
    Ok(summary)
}

/// 复验未通过的原因，用于异常池与丢弃留痕。
///
/// 三分法对应三种真实故障：完全连不上、连上了但部分采样超时、每次都答但太慢。
/// 界面上必须能区分，否则「它为什么不健康」永远只有一个答案。
fn verdict_rejection_reason(verdict: Option<&NodeVerdict>) -> &'static str {
    let Some(verdict) = verdict else {
        return "unreachable";
    };
    if verdict.samples_ok == 0 {
        "unreachable"
    } else if verdict.samples_ok < verdict.samples_total {
        "partial_timeout"
    } else {
        "too_slow"
    }
}

/// 把分层计数与「功能是否真的生效」写回状态。
///
/// 自动降级的原因必须回传：不回报原因，使用者就无法判断粘性失效
/// 是保护机制起作用还是出了故障。
fn update_pool_status_counts(
    provider_id: &str,
    scan: &OpenCodeScanConfig,
    health: &OpenCodeHealthConfig,
    disabled_count: usize,
) {
    let pool = scan.effective_pool(health);
    let disabled: BTreeSet<&str> = scan
        .exit_pool_disabled
        .iter()
        .map(|ip| ip.trim())
        .filter(|ip| !ip.is_empty())
        .collect();
    let in_use = pool
        .iter()
        .filter(|ip| !disabled.contains(ip.trim()))
        .count();
    let pool_size = in_use;
    let sticky_active = health.session_sticky_active(pool_size);
    let min_pool = health.min_pool_size();
    update_opencode_ip_pool_status(provider_id, |status| {
        status.candidate_count = scan.candidates.len() as u64;
        status.healthy_count = health.healthy.len() as u64;
        status.in_use_count = in_use as u64;
        status.degraded_count = health.degraded.len() as u64;
        status.session_sticky_active = sticky_active;
        status.session_sticky_disabled_reason = if sticky_active {
            None
        } else if !health.session_sticky_enabled {
            Some("disabled_by_operator".to_string())
        } else {
            Some(format!(
                "pool_below_min({pool_size}<{})",
                health.session_sticky_min_pool()
            ))
        };
        status.pool_below_floor = pool_size < min_pool;
        status.pool_empty = pool_size == 0;
    });
}

/// 轮末重建候选列表（「本轮未见即淘汰」）。
///
/// 返回 `None` 表示**放弃这次重建**：只有在能确认「本轮已见集合是完整的」时才允许
/// 整表替换。`round_started_in_this_call` 为真说明整轮都在这次调用里跑完（含单切片
/// 轮），累积集合天然完整；`accumulator_present` 为真说明前面切片确实落过累积集合。
/// 两者都假（例如 Redis 里的集合过期或被清）时，整表替换只会把前面切片探到的节点
/// 一起抹掉——宁可保留旧候选，也不清错。
///
/// `all_candidates_empty`：网段被清空时这一轮没有任何地址可探，结论是确定的
/// （候选清到只剩保护名单），不依赖累积集合。
fn rebuild_candidates_on_round_completion(
    accumulator_present: bool,
    merged_seen: &BTreeSet<String>,
    pinned: &[String],
    round_started_in_this_call: bool,
    all_candidates_empty: bool,
) -> Option<Vec<String>> {
    if !(accumulator_present || round_started_in_this_call || all_candidates_empty) {
        return None;
    }
    let mut kept: BTreeSet<String> = merged_seen.clone();
    kept.extend(pinned.iter().cloned());
    Some(kept.into_iter().collect())
}

async fn run_open_code_pool_scan_inner(
    app: &AppState,
    provider: &StoredProviderCatalogProvider,
    config: &OpenCodeScanConfig,
) -> Result<ScanSummary, GatewayError> {
    let provider_id = provider.id.clone();
    let (domain, port) = opencode_upstream_target(app, &provider_id, config).await?;
    if probe_target_is_official(&domain) {
        return Err(GatewayError::Internal(
            "未配置前置代理域名，无法判断出口 IP 是否可用；请先在前置代理池里填写并保存 CDN 域名，再执行扫描"
                .to_string(),
        ));
    }
    let concurrency = config.effective_concurrency();
    let max_handshake_ms = config.effective_probe_max_handshake_ms();
    let keys = app
        .list_provider_catalog_keys_by_provider_ids(std::slice::from_ref(&provider_id))
        .await?;
    // 已知 IP = 现有生产池 + 旧模型里仍带元数据的 key。
    //
    // **候选池不在其中**：候选必须是可重复探测的，否则「本轮未见即淘汰」
    // 会把从没被探到过的候选全部清掉。added 的判定另外拿旧候选做差集。
    let known_ips: BTreeSet<String> = keys
        .iter()
        .filter_map(opencode_pool_key_ip)
        .chain(config.exit_pool.iter().cloned())
        .collect();
    let existing_candidates: BTreeSet<String> = config.candidates.iter().cloned().collect();
    let health = OpenCodeHealthConfig::from_provider_config(&provider.config);
    // 已在跟踪中的节点不再进候选：异常池的节点由复验负责到底（转正或丢弃），
    // 人工拉黑的是明确意图。**丢弃的不在此列**——丢弃的定义就是「靠下一次扫描回来」。
    let mut skip_ips: BTreeSet<String> = health.blocked_ips();
    skip_ips.extend(health.abnormal_ips());
    let mut all_candidates = config.candidate_ips(&known_ips);
    // 候选来源之二：前置代理域名的 DNS 解析结果（多采样取并集）。
    // 这是**供应商无关**的来源——换 CloudFront / Cloudflare / EdgeOne / 自建 nginx
    // 都只改域名，扫描自动跟随；CIDR 只是可选补充。
    if let Some(domain) = config.effective_proxy_domain() {
        let resolved = resolve_domain_candidates(&domain, 6).await;
        tracing::info!(
            event_name = "opencode_scan_domain_candidates",
            log_type = "ops",
            provider_id,
            domain = domain.as_str(),
            resolved = resolved.len(),
            "opencode scan resolved candidates from the front proxy domain"
        );
        for ip in resolved {
            if !known_ips.contains(&ip) {
                all_candidates.push(ip);
            }
        }
        all_candidates.sort();
        all_candidates.dedup();
    }
    all_candidates.retain(|ip| !skip_ips.contains(ip));
    // 按 Redis 游标切片：候选总数超过单轮上限时，下一轮从这一轮结束处继续，
    // 避免「字典序靠前的死 IP 永远霸占名额、后面的网段饿死」。
    let cursor = crate::opencode_rotation::read_scan_cursor(app, &provider_id).await;
    let (candidates, next_cursor) = config.scan_slice(&all_candidates, cursor);
    // 游标归零意味着这一轮从网段开头开始——也就是刚好完整走完全部地址。
    // 只有这种时候才能按「本轮未见即淘汰」清理候选：分片轮里没被探到的地址
    // 只是还没轮到，删掉就等于把后面的网段清空。
    let round_completed = next_cursor == 0;
    // 扫描只做「发现」，与池模式**无关**：两种模式都只写候选。
    //
    // key 模式此前会在这里为每个探通的 IP 造一个 key（`create_ip_pool_key`）：一个发现
    // 动作顺手创建生产密钥，而密钥自带钉死的 IP、`is_active=true`，等于「扫描即上线」；
    // 下面那段注释（粗筛只看得见连得通、扫描即上线正是线上 503 的根源）讲的正是这件事，
    // 却只改了 provider 分支。自动扫描（间隔 48h）同样会造，且没有任何数量上限。
    // 「本轮已见」累积集合的 TTL 与游标同源：两者必须同生共死——游标还在而集合先
    // 过期，轮末重建就会拿到不完整的输入。
    let cursor_ttl = config.scan_cursor_ttl_seconds(all_candidates.len());
    // 游标为 0 = 这一轮从网段开头开始：先清掉上一轮的累积，否则陈旧集合会被当成
    // 「本轮已见」（表现为候选永远清不掉）。
    if cursor == 0 {
        crate::opencode_rotation::clear_scan_seen(app, &provider_id).await;
    }
    // 必须在 clear 之后读：`None` 是「累积不可信 → 禁止破坏性重建」的依据。
    let prior_seen = crate::opencode_rotation::read_scan_seen(app, &provider_id).await;
    let target_count = candidates.len() as u64;
    update_opencode_ip_pool_status(&provider_id, |status| status.progress_total = target_count);
    tracing::info!(
        event_name = "opencode_ip_pool_scan_slice",
        log_type = "ops",
        provider_id,
        total_candidates = all_candidates.len(),
        from = cursor,
        probing = target_count,
        next_cursor,
        max_candidates_per_round = config.effective_max_candidates_per_round(),
        max_handshake_ms,
        "opencode ip pool scan slice"
    );

    let healthy = probe_ips(
        &candidates,
        &domain,
        port,
        concurrency,
        max_handshake_ms,
        Some(scan_progress(&provider_id)),
    )
    .await;
    // found = 本轮探通的总数（含已在池中的）；added = 真正新加入的。
    // 两者分开报，否则「网段里可达 IP 都已入库」会被误读成扫描失败。
    let found_count = healthy.len() as u64;
    let mut added = 0u64;
    let mut next_config = config.clone();
    // 扫描只写候选，不碰生产列表。生产信任哪些节点由验健康任务决定——
    // 扫描即上线正是这次线上 503 的根源：粗筛只看得见「连得通」，
    // 而连得通的节点里绝大多数扛不住大请求。
    let mut seen: BTreeSet<String> = BTreeSet::new();
    for ip in healthy {
        // 刚连着失败的节点：扫描探通它并不能推翻「它有问题」——粗筛只看得见
        // 连得通。让它把冷静期过完再说，否则异常池会候选→异常地来回跳。
        let suspect =
            crate::opencode_rotation::opencode_ip_suspect_reason(app, &provider_id, &ip).await;
        if suspect.is_some() {
            continue;
        }
        let is_new = !existing_candidates.contains(&ip) && !known_ips.contains(&ip);
        seen.insert(ip.clone());
        if !is_new {
            continue;
        }
        next_config.candidates.push(ip);
        added += 1;
    }
    // 把**本片**探通的并入「本轮已见」累积集合（Redis，TTL 与游标同源）。
    // 轮末重建必须用整轮的累积：`seen` 只是本片的，拿它整表覆盖会把前面所有
    // 切片探到的节点一起抹掉。
    let mut merged_seen: BTreeSet<String> = prior_seen.clone().unwrap_or_default();
    merged_seen.extend(seen.iter().cloned());
    let seen_persisted =
        crate::opencode_rotation::write_scan_seen(app, &provider_id, &merged_seen, cursor_ttl)
            .await;
    if !seen_persisted {
        tracing::warn!(
            event_name = "opencode_ip_pool_scan_seen_write_failed",
            log_type = "ops",
            provider_id,
            "opencode ip pool failed to persist the round seen set"
        );
    }
    if round_completed {
        match rebuild_candidates_on_round_completion(
            prior_seen.is_some(),
            &merged_seen,
            &config.pinned,
            cursor == 0,
            all_candidates.is_empty(),
        ) {
            Some(kept) => {
                next_config.candidates = kept;
                // 一轮走完，累积集合同步清账：下一轮从空开始。
                crate::opencode_rotation::clear_scan_seen(app, &provider_id).await;
            }
            None => {
                // 累积集合丢了（过期/被清）：这时重建只会把前面切片探到的节点一起
                // 抹掉，宁可保留旧候选，也不清错。
                tracing::warn!(
                    event_name = "opencode_ip_pool_scan_rebuild_skipped",
                    log_type = "ops",
                    provider_id,
                    total_candidates = all_candidates.len(),
                    "opencode ip pool skipped candidate rebuild because the round seen set was lost"
                );
            }
        }
    }
    // 落盘扫描完成时间：`autoscan` 必须按**落盘**时间判断间隔。用进程内存时间的话，
    // 每次重启都会立刻判定"该扫了"——2026-10-18 实测：重启后马上起了一轮扫描，
    // 卡在无超时的 DNS 解析上，`scanning` 永久 true，把复验全堵成 400。
    next_config.last_scan_at = Some(now_string());
    write_scan_config(app, provider, &next_config).await?;
    // 无论本轮有没有新增，都要把游标推进，否则会一直重复探同一片。
    // TTL 按「一整轮扫描」给（可能跨多个 interval）：游标过期会让超出单轮上限的
    // 网段永远轮不到，而 `round_completed` 也永远不为真，candidates 永不重建。
    crate::opencode_rotation::write_scan_cursor(app, &provider_id, next_cursor, cursor_ttl).await;

    tracing::info!(
        event_name = "opencode_ip_pool_scan_completed",
        log_type = "ops",
        provider_id,
        targets = target_count,
        found = found_count,
        added,
        "opencode ip pool scan completed"
    );
    Ok(ScanSummary {
        targets: target_count,
        found: found_count,
        added,
    })
}

/// 清理一轮：探测已有池 key 的 IP，删除不健康的。
pub(crate) async fn run_open_code_pool_clean(
    app: &AppState,
    provider: &StoredProviderCatalogProvider,
) -> Result<CleanSummary, GatewayError> {
    let provider_id = provider.id.clone();
    if opencode_ip_pool_status_for(&provider_id).cleaning {
        return Err(GatewayError::Internal("清理正在进行中".to_string()));
    }
    update_opencode_ip_pool_status(&provider_id, |status| status.cleaning = true);
    // 与扫描同理：取消/panic 也要复位，否则「清理」按钮会永久显示进行中。
    let _guard = CleanFlagGuard {
        provider_id: provider_id.clone(),
    };

    let outcome = run_open_code_pool_clean_inner(app, provider).await;

    update_opencode_ip_pool_status(&provider_id, |status| {
        status.cleaning = false;
        if let Ok(summary) = &outcome {
            status.last_clean_checked = summary.checked;
            status.last_clean_removed = summary.removed;
            status.last_clean_at = Some(now_string());
        }
    });
    outcome
}

/// 清理结束时（正常/取消/panic）都复位 `cleaning` 标志。
struct CleanFlagGuard {
    provider_id: String,
}

impl Drop for CleanFlagGuard {
    fn drop(&mut self) {
        update_opencode_ip_pool_status(&self.provider_id, |status| {
            status.cleaning = false;
        });
    }
}

async fn run_open_code_pool_clean_inner(
    app: &AppState,
    provider: &StoredProviderCatalogProvider,
) -> Result<CleanSummary, GatewayError> {
    let provider_id = provider.id.clone();
    let config = OpenCodeScanConfig::from_provider_config(&provider.config);
    let (domain, port) = opencode_upstream_target(app, &provider_id, &config).await?;
    // 安全闸：探测目标是官方直连域名时结果不可信，此时执行清理会把整个池删光。
    if probe_target_is_official(&domain) {
        return Err(GatewayError::Internal(
            "未配置前置代理域名，无法判断出口 IP 是否可用；请先在前置代理池里填写并保存 CDN 域名，再执行清理"
                .to_string(),
        ));
    }
    let concurrency = config.effective_concurrency().min(32);
    let max_handshake_ms = config.effective_probe_max_handshake_ms();

    // provider 级池：IP 存在配置里，剔除的是「池里的 IP」，不涉及删除密钥。
    if !config.exit_pool.is_empty() {
        let ips = config.exit_pool.clone();
        let checked = ips.len() as u64;
        update_opencode_ip_pool_status(&provider_id, |status| status.progress_total = checked);
        let healthy: BTreeSet<String> = BTreeSet::from_iter(
            probe_ips(
                &ips,
                &domain,
                port,
                concurrency,
                max_handshake_ms,
                Some(clean_progress(&provider_id)),
            )
            .await,
        );
        let kept: Vec<String> = ips
            .iter()
            .filter(|ip| healthy.contains(*ip))
            .cloned()
            .collect();
        let removed = (ips.len() - kept.len()) as u64;
        if removed > 0 {
            let mut next = config.clone();
            next.exit_pool = kept;
            write_scan_config(app, provider, &next).await?;
        }
        tracing::info!(
            event_name = "opencode_ip_pool_clean_completed",
            log_type = "ops",
            provider_id,
            checked,
            removed,
            source = "provider",
            "opencode ip pool clean completed"
        );
        return Ok(CleanSummary { checked, removed });
    }

    // 兼容旧数据：IP 在 key 元数据里，剔除时删除对应 key。
    let keys = app
        .list_provider_catalog_keys_by_provider_ids(std::slice::from_ref(&provider_id))
        .await?;
    let entries: Vec<(String, String)> = keys
        .iter()
        .filter_map(|key| opencode_pool_key_ip(key).map(|ip| (key.id.clone(), ip)))
        .collect();
    let checked = entries.len() as u64;
    let ips: Vec<String> = entries.iter().map(|(_, ip)| ip.clone()).collect();
    let healthy: BTreeSet<String> = BTreeSet::from_iter(
        probe_ips(&ips, &domain, port, concurrency, max_handshake_ms, None).await,
    );

    let mut removed = 0u64;
    for (key_id, ip) in entries {
        if !healthy.contains(&ip) && app.delete_provider_catalog_key(&key_id).await.is_ok() {
            removed += 1;
        }
    }

    tracing::info!(
        event_name = "opencode_ip_pool_clean_completed",
        log_type = "ops",
        provider_id,
        checked,
        removed,
        source = "key",
        "opencode ip pool clean completed"
    );
    Ok(CleanSummary { checked, removed })
}

/// CAS 重试次数：写回时若发现别人刚改过配置，就重读后重试。
///
/// 取 8 而不是 2：扫描每一片都会写一次，界面上每存一次配置都会让下一次写
/// 失败一次，两者交替时需要足够轮次才能收敛；真收敛不了会显式报错，
/// 不会静默丢数据。
const POOL_CONFIG_WRITE_RETRIES: usize = 8;

/// 只改 `config` 里的某一段，且用 CAS 保证不覆盖别人的并发修改。
///
/// 为什么不能直接拿传入的 provider 快照重建整个 config 写回：扫描最长 50 分钟、
/// 复验约 3 分钟，这期间快照就过时了。整行写回会让**后写的那一趟任务把先写
/// 好的段覆盖回旧值**——实测就是这样：复验先把 337 个通过体检的节点写进
/// `opencode_health`，紧接着写 `opencode_scan` 时又用任务开始时的快照把
/// `opencode_health` 覆盖回 65，于是「复验 kept=337」而生产池仍是 65 个，
/// 延迟数据、降级名单、淘汰原因一起回滚，健康门槛等于没生效；同一机制还会
/// 吞掉任务运行期间用户在界面上改的任何配置。
///
/// 这里的做法是：每次写都重读当前配置，只替换自己那一段，再用
/// compare-and-swap 提交。CAS 失败说明期间有人改过，就带上新值重试，
/// 于是各段互不覆盖，别人的修改也保得住。
///
/// 没有 provider 写库时（只读部署）保持旧行为：静默不写。旧实现走
/// update_provider_catalog_provider，它在无 writer 时返回 Ok(None) 被忽略；
/// 换成 CAS 后无 writer 会一律返回 false，若照直重试就会把一个静默 no-op
/// 变成硬失败，让复验整趟报错——那是行为倒退，不是修复。
/// provider 配置的 CAS 分段写入。**通用原语，不只服务 opencode 池。**
///
/// 现在 `amd_load` 的配置保存也走这里。两处各写一份 CAS 是「保存覆盖了复验结果」
/// 那个 bug 的成因，所以宁可共用一份也不要复制。
pub(crate) async fn write_provider_config_section_with(
    app: &AppState,
    provider_id: &str,
    section_label: &str,
    mutate: impl Fn(&mut serde_json::Map<String, Value>),
) -> Result<(), GatewayError> {
    if !app.has_provider_catalog_data_writer() {
        return Ok(());
    }
    for _ in 0..POOL_CONFIG_WRITE_RETRIES {
        let Some(current) = app
            .read_provider_catalog_providers_by_ids(std::slice::from_ref(&provider_id.to_string()))
            .await?
            .into_iter()
            .next()
        else {
            return Err(GatewayError::Internal(format!(
                "{section_label} 写回失败：provider {provider_id} 不存在"
            )));
        };
        let mut config_map = current
            .config
            .as_ref()
            .and_then(Value::as_object)
            .cloned()
            .unwrap_or_default();
        mutate(&mut config_map);
        let update = ProviderCatalogProviderConfigCasUpdate {
            provider_id: provider_id.to_string(),
            expected_config: current.config.clone(),
            config: Some(Value::Object(config_map)),
        };
        if app
            .compare_and_swap_provider_catalog_provider_config(&update)
            .await?
        {
            return Ok(());
        }
    }

    Err(GatewayError::Internal(format!(
        "{section_label} 写回失败：连续 {POOL_CONFIG_WRITE_RETRIES} 次撞上并发修改，已放弃以免覆盖别人的配置"
    )))
}

/// 扫描/复验任务只拥有 `opencode_scan` 里的**池内容**字段。
///
/// 其余字段（网段、间隔、并发、轮询开关、冷却、前置代理域名与开关、保护名单、
/// 手工停用）都是用户在界面上改的设置，整段替换会把任务运行期间的修改覆盖掉：
/// 扫描最长 50 分钟，这段时间并不短。所以这里只把任务真正产出的两个字段
/// 写进当前段，其余原样保留用户最新的值。
///
/// 段本身不存在时（还没保存过配置）退回整段写入：此时没有"用户的值"要保留。
fn merge_scan_section_into(
    config_map: &mut serde_json::Map<String, Value>,
    produced: &OpenCodeScanConfig,
) {
    let Some(section) = config_map
        .get("opencode_scan")
        .and_then(Value::as_object)
        .cloned()
    else {
        config_map.insert(
            "opencode_scan".to_string(),
            produced.to_provider_config_value(),
        );
        return;
    };
    let mut merged = section;
    merged.insert("candidates".to_string(), json!(produced.candidates.clone()));
    // exit_pool 只在迁移期被任务写入（生产列表已改由 opencode_health.healthy 承担），
    // 仍然属于任务产出，不能被用户在界面上没有对应输入框的旧值覆盖回去。
    merged.insert("exit_pool".to_string(), json!(produced.exit_pool.clone()));
    // 扫描完成时间也是任务产出：`autoscan` 靠它判断间隔，必须落盘。
    // （第一版漏了这里——`to_provider_config_value` 里加了字段，但这条写入路径
    // 走的是本函数按 key 合并，于是字段被静默丢弃，实测扫描后 last_scan_at 仍为空。）
    if let Some(stamp) = produced.last_scan_at.clone() {
        merged.insert("last_scan_at".to_string(), json!(stamp));
    }
    config_map.insert("opencode_scan".to_string(), Value::Object(merged));
}

/// 把扫描任务的产出写回 provider。只动 `opencode_scan` 段里的池内容字段。
pub(crate) async fn write_scan_config(
    app: &AppState,
    provider: &StoredProviderCatalogProvider,
    config: &OpenCodeScanConfig,
) -> Result<(), GatewayError> {
    write_provider_config_section_with(app, &provider.id, "opencode 出口 IP 池", |config_map| {
        merge_scan_section_into(config_map, config)
    })
    .await
}

/// 手工维护池成员（加 / 删 / 改名 / 停用）后写回 `opencode_scan` 的两个列表。
///
/// 为什么不复用 [`write_scan_config`]：那条路径是给**扫描任务**用的，而任务的快照
/// 可能是 50 分钟前的；把用户的手工改动交给它写，等于让任务收尾时把用户的调整
/// 覆盖回去。这里只写 `exit_pool` 与 `exit_pool_disabled` 两个数组，其余字段
/// （网段、间隔、并发、开关…）一个字节都不碰。
///
/// 单独一个入口还修掉了一个静默失效：`exit_pool_disabled` 以前既没有被
/// [`OpenCodeScanConfig::from_provider_config_object`] 读回、也没有被
/// [`merge_scan_section_into`] 写入，于是「停用某个 IP」的接口返回 `saved: true`
/// 而配置里什么都没变。
pub(crate) async fn write_scan_pool_lists(
    app: &AppState,
    provider: &StoredProviderCatalogProvider,
    exit_pool: &[String],
    exit_pool_disabled: &[String],
) -> Result<(), GatewayError> {
    write_provider_config_section_with(app, &provider.id, "opencode 出口 IP 池", |config_map| {
        let section = config_map
            .entry("opencode_scan".to_string())
            .or_insert_with(|| Value::Object(serde_json::Map::new()));
        let Some(section) = section.as_object_mut() else {
            return;
        };
        section.insert("exit_pool".to_string(), json!(exit_pool.to_vec()));
        section.insert(
            "exit_pool_disabled".to_string(),
            json!(exit_pool_disabled.to_vec()),
        );
    })
    .await
}

/// 写回 `opencode_health` 段。只改这一段，`opencode_scan` 不动。
///
/// 旧注释说这里「与扫描配置互不覆盖」，那是错的：旧实现两个函数都拿传入的
/// provider 快照重建整个 config 再整行写回，谁后写谁赢，被覆盖的永远是先写的
/// 那一段。改成按段 CAS 写入后这句话才成立。
///
/// 每次写都顺手清一次**过期异常池条目**（[`OpenCodeHealthConfig::prune_expired_abnormal`]）：
/// 健康更新是异常池唯一的写入方，把清理挂在这里就不需要额外的定时任务；
/// 它是纯内存操作（不读库、不发网络请求），因此不会让主流程多等一秒。
pub(crate) async fn write_health_config(
    app: &AppState,
    provider: &StoredProviderCatalogProvider,
    health: &OpenCodeHealthConfig,
) -> Result<(), GatewayError> {
    let mut pruned = health.clone();
    prune_abnormal_before_write(&mut pruned, provider.id.as_str());
    write_provider_config_section_with(app, &provider.id, "opencode 出口 IP 池", |config_map| {
        config_map.insert(
            "opencode_health".to_string(),
            pruned.to_provider_config_value(),
        );
    })
    .await
}

/// 健康段写入前的统一清理（目前只有异常池过期）。
///
/// 抽成函数只为让「写入前一定清过一次」这件事只有一处实现——`write_health_config`
/// 与 [`write_pool_state_pair`] 两条写路径都必须走它，漏一处就会出现
/// 「健康更新会清、出池那一笔不清」的半吊子行为。
fn prune_abnormal_before_write(health: &mut OpenCodeHealthConfig, provider_id: &str) {
    let expired = health.prune_expired_abnormal();
    if expired.is_empty() {
        return;
    }
    // 只记前 10 个 IP：异常池上限 500 条，一次性清空时把 500 个 IP 塞进一条
    // 日志会把真正要看的其它事件挤掉，条数才是这里的主信息。
    let sample: Vec<&str> = expired.iter().take(10).map(String::as_str).collect();
    tracing::info!(
        event_name = "opencode_pool_abnormal_pruned",
        log_type = "ops",
        provider_id,
        removed = expired.len(),
        remaining = health.abnormal.len(),
        max_age_days = health.abnormal_max_age_days(),
        sample = ?sample,
        "opencode ip pool pruned expired abnormal entries before writing the health section"
    );
}

/// 把「健康段的新内容」与「要从 `exit_pool` 摘掉的 IP」**一次**写回（同一个 CAS）。
///
/// 为什么必须一次写：调用方（复验丢弃、连续失败出池）在 `health` 里已经把那些 IP
/// 从异常池清掉了，而它们这时还在 `exit_pool` 里。分两次写会留下「异常记录已删、
/// 池子还没删」的中间态，而轮转池 = healthy ∪ (exit_pool − abnormal − blocked)，
/// 在那个窗口里这些 IP 会**重新参与轮转**——刚判定为坏的点被放回生产。
///
/// 只动自己拥有的字段：`exit_pool` / `exit_pool_disabled` 里删条目是原地删，
/// 扫描段其它字段（网段、间隔、并发、开关…）一个字节都不碰，与
/// [`merge_scan_section_into`] 的克制口径一致。
pub(crate) async fn write_pool_state_pair(
    app: &AppState,
    provider_id: &str,
    health: &OpenCodeHealthConfig,
    evict_ips: &[String],
) -> Result<(), GatewayError> {
    let mut pruned = health.clone();
    prune_abnormal_before_write(&mut pruned, provider_id);
    write_provider_config_section_with(app, provider_id, "opencode 出口 IP 池", |config_map| {
        if !evict_ips.is_empty() {
            remove_ips_from_scan_section(config_map, evict_ips);
        }
        config_map.insert(
            "opencode_health".to_string(),
            pruned.to_provider_config_value(),
        );
    })
    .await
}

/// 从 `opencode_scan` 段的 `exit_pool` / `exit_pool_disabled` 里原地删掉这些 IP。
///
/// 原地删而不是整段重写：`to_provider_config_value` 会把「生效值」写回配置
/// （并发、快筛阈值、各种阈值的默认值都会被固化成具体数字），而这里只是要删两条
/// 数组成员，没有理由顺手改写用户的设置。
fn remove_ips_from_scan_section(config_map: &mut serde_json::Map<String, Value>, ips: &[String]) {
    let wanted: BTreeSet<&str> = ips
        .iter()
        .map(|ip| ip.trim())
        .filter(|ip| !ip.is_empty())
        .collect();
    if wanted.is_empty() {
        return;
    }
    let Some(section) = config_map
        .get_mut("opencode_scan")
        .and_then(Value::as_object_mut)
    else {
        return;
    };
    for key in ["exit_pool", "exit_pool_disabled"] {
        let Some(Value::Array(items)) = section.get_mut(key) else {
            continue;
        };
        items.retain(|item| match item.as_str() {
            Some(raw) => !wanted.contains(raw.trim()),
            // 非字符串项不归我们判，原样留着。
            None => true,
        });
    }
}

/// 一次出池的结果。写日志与单测都要看它——「为什么这个 IP 没被摘掉」必须能回答，
/// 否则出池会变成猜谜。
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum OpenCodeEvictOutcome {
    /// 已从 `exit_pool` 与 `healthy` 里摘掉（含异常池条目与延迟记录）。
    Removed,
    /// 它本来就不在任何轮转集合里（已被摘过 / 从未进池）。
    NotInPool,
    /// 在手工保护名单 `pinned` 里：人工声明要留着，不动。
    ProtectedPinned,
    /// 被人工停用（`exit_pool_disabled`）：尊重人工开关，不动。
    ProtectedDisabled,
    /// 摘掉之后池子会低于保护线：不动。宁可留一个坏 IP，也不要让池子塌到个位数。
    ProtectedPoolFloor,
    /// 只读部署（没有写库）：静默跳过。
    SkippedReadOnly,
}

impl OpenCodeEvictOutcome {
    pub(crate) fn label(self) -> &'static str {
        match self {
            Self::Removed => "removed",
            Self::NotInPool => "not_in_pool",
            Self::ProtectedPinned => "protected_pinned",
            Self::ProtectedDisabled => "protected_disabled",
            Self::ProtectedPoolFloor => "protected_pool_floor",
            Self::SkippedReadOnly => "skipped_read_only",
        }
    }
}

/// 把一个**连续失败达阈值**的出口 IP 从轮转池里摘掉（trust-on-add 的出口）。
///
/// 语义是「不再参与任何轮转」：从 `exit_pool` 与 `healthy` 两处一起删，顺带清掉它的
/// 异常池条目、`degraded` 记录与延迟记录——只删其中一处的后果是「健康节点照样被
/// 抽中」，或者「延迟表继续膨胀」。不删 `candidates`：候选是扫描的原始产物，
/// 让它有机会被下一次复验重新验证是合理的（复验转正才是回到轮转的正路）。
///
/// 幂等：已经不在池里的 IP 返回 [`OpenCodeEvictOutcome::NotInPool`]，什么都不写。
pub(crate) async fn evict_opencode_exit_ip(
    app: &AppState,
    provider_id: &str,
    ip: &str,
) -> Result<OpenCodeEvictOutcome, GatewayError> {
    let ip = ip.trim().to_string();
    if ip.is_empty() {
        return Ok(OpenCodeEvictOutcome::NotInPool);
    }
    if !app.has_provider_catalog_data_writer() {
        return Ok(OpenCodeEvictOutcome::SkippedReadOnly);
    }
    // `Mutex` 而不是 `Cell`：这个函数会在 `tokio::spawn` 的后台任务里跑，Future 必须
    // `Send`，而 `Cell` 不是 `Sync`。锁只在同步的 CAS 回调里取，跨不过 await。
    let outcome = std::sync::Mutex::new(OpenCodeEvictOutcome::NotInPool);
    let record = |value: OpenCodeEvictOutcome| {
        if let Ok(mut slot) = outcome.lock() {
            *slot = value;
        }
    };
    write_provider_config_section_with(app, provider_id, "opencode 出口 IP 池", |config_map| {
        let scan = OpenCodeScanConfig::from_provider_config_object(config_map);
        let health = OpenCodeHealthConfig::from_config_object(config_map);
        let same = |item: &String| item.trim() == ip;
        let in_exit_pool = scan.exit_pool.iter().any(same);
        let in_healthy = health.healthy.iter().any(same) || health.degraded.iter().any(same);
        if !in_exit_pool && !in_healthy {
            record(OpenCodeEvictOutcome::NotInPool);
            return;
        }
        if scan.pinned.iter().any(same) {
            record(OpenCodeEvictOutcome::ProtectedPinned);
            return;
        }
        if scan.exit_pool_disabled.iter().any(same) {
            record(OpenCodeEvictOutcome::ProtectedDisabled);
            return;
        }
        // 保护线：摘掉之后可用池会低于保底值时不动。这条与复验的
        // `discard_allowed` 同一个口径——池子塌到个位数比留一个坏节点更难恢复。
        let floor = health.protect_pool_floor();
        if scan.effective_pool(&health).len() <= floor {
            record(OpenCodeEvictOutcome::ProtectedPoolFloor);
            return;
        }
        remove_ips_from_scan_section(config_map, std::slice::from_ref(&ip));
        let mut next = health.clone();
        next.healthy.retain(|item| !same(item));
        next.degraded.retain(|item| !same(item));
        next.abnormal.retain(|entry| entry.ip.trim() != ip);
        next.latencies.remove(ip.as_str());
        config_map.insert(
            "opencode_health".to_string(),
            next.to_provider_config_value(),
        );
        record(OpenCodeEvictOutcome::Removed);
    })
    .await?;
    Ok(outcome
        .lock()
        .map(|slot| *slot)
        .unwrap_or(OpenCodeEvictOutcome::NotInPool))
}

/// 保存接口的结果。响应构造留给调用方：那里才有 bad_request / 409 这些辅助函数，
/// 也不必依赖 GatewayError 在这条路由族里怎么渲染。
#[derive(Debug)]
pub(crate) enum PoolConfigWriteOutcome {
    Saved,
    /// 字段越界等输入问题，`detail` 面向用户。
    Invalid(String),
    /// 连续重试都撞上并发修改。
    Conflict,
}

/// 保存接口用：把 `opencode_scan` 和 `opencode_health` 两段**一起**做 CAS 写入。
///
/// 为什么不能拆成两次 write_* 调用：拆开之后两段之间若失败，会留下"新的一段 +
/// 旧的一段"，而这两段在请求体里是同一次提交的内容，用户看到的保存结果会自相
/// 矛盾。合并成一次 CAS 才能保证要么都生效、要么都不生效。
///
/// `build` 每轮都会被重新调用，拿到的是**当轮重读到的最新配置**：请求体里的
/// 字段按最新值合并，于是后台任务刚写入的 healthy / candidates 不会被这次保存
/// 按旧值盖回去。CAS 失败说明期间又有人改了，带新值再试。
pub(crate) async fn write_pool_config_pair(
    app: &AppState,
    provider_id: &str,
    build: impl Fn(&Option<Value>) -> Result<(Value, Value), String>,
) -> Result<PoolConfigWriteOutcome, GatewayError> {
    if !app.has_provider_catalog_data_writer() {
        return Ok(PoolConfigWriteOutcome::Saved);
    }
    for _ in 0..POOL_CONFIG_WRITE_RETRIES {
        let Some(current) = app
            .read_provider_catalog_providers_by_ids(std::slice::from_ref(&provider_id.to_string()))
            .await?
            .into_iter()
            .next()
        else {
            return Err(GatewayError::Internal(format!(
                "opencode 出口 IP 池保存失败：provider {provider_id} 不存在"
            )));
        };
        let (scan_value, health_value) = match build(&current.config) {
            Ok(pair) => pair,
            // 校验要指回真正写错的那个字段，所以把 detail 原样带回调用方，
            // 由它转成 400，而不是在这里变成 500。
            Err(detail) => return Ok(PoolConfigWriteOutcome::Invalid(detail)),
        };
        let mut config_map = current
            .config
            .as_ref()
            .and_then(Value::as_object)
            .cloned()
            .unwrap_or_default();
        config_map.insert("opencode_scan".to_string(), scan_value);
        config_map.insert("opencode_health".to_string(), health_value);
        let update = ProviderCatalogProviderConfigCasUpdate {
            provider_id: provider_id.to_string(),
            expected_config: current.config.clone(),
            config: Some(Value::Object(config_map)),
        };
        if app
            .compare_and_swap_provider_catalog_provider_config(&update)
            .await?
        {
            return Ok(PoolConfigWriteOutcome::Saved);
        }
    }
    Ok(PoolConfigWriteOutcome::Conflict)
}

/// 为一个健康 IP 创建池 key。
///
/// 出口 IP 写在 `upstream_metadata.opencode_exit_ip`；`api_key` 只是逐 IP 唯一的
/// 占位值（`public-<ip>`），上游认证由传输层强制为 `Bearer public`。
/// 并发探测一批 IP，返回健康列表。
/// 生成一个把进度写进池状态的回调（扫描用）。
fn scan_progress(provider_id: &str) -> Arc<dyn Fn(u64) + Send + Sync> {
    let provider_id = provider_id.to_string();
    Arc::new(move |done| {
        update_opencode_ip_pool_status(&provider_id, |status| {
            status.progress_done = done;
            status.progress_kind = Some("scan".to_string());
        });
    })
}

/// 生成一个把进度写进池状态的回调（清理用）。
fn clean_progress(provider_id: &str) -> Arc<dyn Fn(u64) + Send + Sync> {
    let provider_id = provider_id.to_string();
    Arc::new(move |done| {
        update_opencode_ip_pool_status(&provider_id, |status| {
            status.progress_done = done;
            status.progress_kind = Some("clean".to_string());
        });
    })
}

/// 一个候选节点的验健康结果。
#[derive(Clone, Debug, Default)]
pub(crate) struct NodeVerdict {
    /// 采样成功次数。
    pub(crate) samples_ok: usize,
    /// 采样总次数。
    pub(crate) samples_total: usize,
    /// 首字节耗时中位数（毫秒）；`None` 表示一次都没成功。
    pub(crate) median_ms: Option<u64>,
}

impl NodeVerdict {
    /// 判定是否值得进入生产池。
    ///
    /// 要求**每一次**采样都成功，而不只是中位数达标：单次成功掩盖不了
    /// 「三次里两次超时」的节点，而那种节点正是会在生产上拖死用户的。
    pub(crate) fn is_healthy(&self, max_median_ms: u64) -> bool {
        self.samples_total > 0
            && self.samples_ok == self.samples_total
            && self.median_ms.is_some_and(|ms| ms <= max_median_ms)
    }
}

fn median_u64(values: &mut [u64]) -> Option<u64> {
    if values.is_empty() {
        return None;
    }
    values.sort_unstable();
    let mid = values.len() / 2;
    Some(if values.len().is_multiple_of(2) {
        // 偶数个取中间两个的平均，避免边界上把一次 9.9s 的抖动算成达标
        (values[mid - 1] + values[mid]) / 2
    } else {
        values[mid]
    })
}

/// 探测一批 IP，每个采样 `samples` 次，取首字节耗时的中位数。
///
/// 多次采样不是保守，是必需：实测同一个节点三次能差 3 倍
/// （8.9s / 23.4s / 8.8s），单次判定必然误判。
async fn verify_ips(
    ips: &[String],
    domain: &str,
    port: u16,
    samples: usize,
    concurrency: usize,
    model: &str,
    interval_ms: u64,
    on_progress: Option<Arc<dyn Fn(u64) + Send + Sync>>,
) -> BTreeMap<String, NodeVerdict> {
    let samples = samples.max(1);
    let semaphore = Arc::new(tokio::sync::Semaphore::new(concurrency.max(1)));
    // 限速闸门：相邻两次 chat 探测之间至少间隔 interval_ms，防止把上游打爆被封。
    let pace_gate = Arc::new(tokio::sync::Mutex::new(None::<std::time::Instant>));
    let model = model.to_string();
    // 每个 IP 收集全部成功样本的耗时，最后统一求中位数。
    let timings = Arc::new(Mutex::new(BTreeMap::<String, Vec<u64>>::new()));
    let attempted = Arc::new(Mutex::new(BTreeMap::<String, usize>::new()));
    let done = Arc::new(std::sync::atomic::AtomicU64::new(0));
    let mut tasks = Vec::new();
    for ip in ips {
        for _ in 0..samples {
            let semaphore = Arc::clone(&semaphore);
            let pace_gate = Arc::clone(&pace_gate);
            let model = model.clone();
            let timings = Arc::clone(&timings);
            let attempted = Arc::clone(&attempted);
            let done = Arc::clone(&done);
            let on_progress = on_progress.clone();
            let domain = domain.to_string();
            let ip = ip.clone();
            tasks.push(tokio::spawn(async move {
                let Ok(_permit) = semaphore.acquire().await else {
                    return;
                };
                if interval_ms > 0 {
                    let mut gate = pace_gate.lock().await;
                    if let Some(previous) = *gate {
                        let target = std::time::Duration::from_millis(interval_ms);
                        let elapsed = previous.elapsed();
                        if elapsed < target {
                            tokio::time::sleep(target - elapsed).await;
                        }
                    }
                    *gate = Some(std::time::Instant::now());
                }
                let elapsed = probe_upstream_ip_chat_timed(
                    &ip,
                    &domain,
                    port,
                    VERIFY_PROBE_TIMEOUT_SECS,
                    &model,
                )
                .await
                .unwrap_or(None);
                {
                    let mut counter = attempted.lock().unwrap_or_else(|e| e.into_inner());
                    *counter.entry(ip.clone()).or_insert(0) += 1;
                }
                if let Some(ms) = elapsed {
                    let mut guard = timings.lock().unwrap_or_else(|e| e.into_inner());
                    guard.entry(ip).or_default().push(ms);
                }
                let finished = done.fetch_add(1, std::sync::atomic::Ordering::Relaxed) + 1;
                if let Some(callback) = on_progress.as_ref() {
                    callback(finished);
                }
            }));
        }
    }
    for task in tasks {
        let _ = task.await;
    }
    let totals = attempted.lock().unwrap_or_else(|e| e.into_inner()).clone();
    let collected = timings.lock().unwrap_or_else(|e| e.into_inner()).clone();
    drop(timings);

    let mut verdicts = BTreeMap::new();
    for (ip, total) in totals {
        let mut values = collected.get(&ip).cloned().unwrap_or_default();
        let median_ms = median_u64(&mut values);
        verdicts.insert(
            ip,
            NodeVerdict {
                samples_ok: values.len(),
                samples_total: total,
                median_ms,
            },
        );
    }
    verdicts
}

/// 探测一批 IP，返回可达的那些。
/// `on_progress` 每完成一个探测就回调一次（已探数量），用来给面板显示进度——
/// 大批量扫描要跑几十分钟，没有进度用户只会以为卡死。
async fn probe_ips(
    ips: &[String],
    domain: &str,
    port: u16,
    concurrency: usize,
    max_handshake_ms: u64,
    on_progress: Option<Arc<dyn Fn(u64) + Send + Sync>>,
) -> Vec<String> {
    let total = ips.len() as u64;
    if let Some(callback) = on_progress.as_ref() {
        callback(0);
    }
    let semaphore = Arc::new(tokio::sync::Semaphore::new(concurrency.max(1)));
    let healthy: Arc<tokio::sync::Mutex<Vec<String>>> =
        Arc::new(tokio::sync::Mutex::new(Vec::new()));
    let done = Arc::new(std::sync::atomic::AtomicU64::new(0));
    let mut tasks = Vec::new();
    for ip in ips {
        let semaphore = Arc::clone(&semaphore);
        let healthy = Arc::clone(&healthy);
        let done = Arc::clone(&done);
        let on_progress = on_progress.clone();
        let domain = domain.to_string();
        let ip = ip.clone();
        tasks.push(tokio::spawn(async move {
            let Ok(_permit) = semaphore.acquire().await else {
                return;
            };
            let ok = probe_upstream_ip(
                &ip,
                &domain,
                port,
                OPENCODE_PROBE_TIMEOUT_SECS,
                max_handshake_ms,
            )
            .await
            .unwrap_or(false);
            if ok {
                healthy.lock().await.push(ip);
            }
            let finished = done.fetch_add(1, std::sync::atomic::Ordering::Relaxed) + 1;
            if let Some(callback) = on_progress.as_ref() {
                callback(finished.min(total));
            }
        }));
    }
    for task in tasks {
        let _ = task.await;
    }
    let guard = healthy.lock().await;
    guard.clone()
}

/// 探测单个 IP：对 `ip:port` 做裸 TLS 握手（SNI = domain），再发一条带 OpenCode
/// 指纹的 `GET /inference/v1/models`，2xx/3xx 判为健康。
///
/// 扫描用的快路径：额外要求「连上到拿到响应首行」不超过 `max_handshake_ms`，
/// 把明显的慢节点挡在候选之外。阈值由调用方传入（provider 配置 > 环境变量 > 默认）。
pub(crate) async fn probe_upstream_ip(
    ip: &str,
    domain: &str,
    port: u16,
    timeout_secs: u64,
    max_handshake_ms: u64,
) -> Result<bool, GatewayError> {
    let Ok(Some(elapsed_ms)) = probe_upstream_ip_measured(ip, domain, port, timeout_secs).await
    else {
        return Ok(false);
    };
    Ok(elapsed_ms <= max_handshake_ms)
}

/// 同 [`probe_upstream_ip`]，但不做快路径阈值，只返回「连通时」的整轮耗时。
///
/// 验健康必须用它：那里的预算由 `verify_max_median_ms` 决定（默认 10 秒），
/// 如果这里先按 600ms 砍一遍，节点会在延迟被记录**之前**就被丢掉——
/// 实测这么做把 65 个可用节点误杀了 40 个。
///
/// **现状（2026-10-18）**：复验已改走 [`probe_upstream_ip_chat_timed`]（真实 chat，
/// 只有 200 才算健康），因为 `/models` 对「免费层被判死」零检出（实测 239 个 chat
/// 恒 403 的 IP 打 `/models` 全是 200）。这个函数保留，供将来的「models 快筛 +
/// chat 复核」两段式复用。
#[allow(dead_code)]
pub(crate) async fn probe_upstream_ip_timed(
    ip: &str,
    domain: &str,
    port: u16,
    timeout_secs: u64,
) -> Result<Option<u64>, GatewayError> {
    probe_upstream_ip_measured(ip, domain, port, timeout_secs).await
}

async fn probe_upstream_ip_measured(
    ip: &str,
    domain: &str,
    port: u16,
    timeout_secs: u64,
) -> Result<Option<u64>, GatewayError> {
    let ip = ip.trim().to_string();
    let domain = domain.trim().to_string();
    let Ok(parsed) = ip.parse::<IpAddr>() else {
        return Ok(None);
    };
    let address = std::net::SocketAddr::new(parsed, port);
    let handshake_started_at = std::time::Instant::now();
    let connect = tokio::time::timeout(
        std::time::Duration::from_secs(timeout_secs),
        tokio::net::TcpStream::connect(address),
    )
    .await;
    let stream = match connect {
        Ok(Ok(stream)) => stream,
        Ok(Err(error)) => {
            tracing::debug!(
                event_name = "opencode_probe_tcp_connect_failed",
                log_type = "ops",
                ip = %ip,
                domain = %domain,
                port,
                error = ?error.kind(),
                "opencode probe tcp connect failed"
            );
            return Ok(None);
        }
        Err(_) => {
            tracing::debug!(
                event_name = "opencode_probe_tcp_connect_timed_out",
                log_type = "ops",
                ip = %ip,
                domain = %domain,
                port,
                "opencode probe tcp connect timed out"
            );
            return Ok(None);
        }
    };
    let stream = stream
        .into_std()
        .map_err(|err| GatewayError::Internal(err.to_string()))?;
    let reachable = tokio::task::spawn_blocking(move || {
        probe_upstream_ip_blocking(stream, &domain, timeout_secs)
    })
    .await
    .map_err(|err| GatewayError::Internal(err.to_string()))??;
    if !reachable {
        return Ok(None);
    }
    // 整轮耗时（连接 + 握手 + 拿到响应首行）原样返回，不在这里做判定——
    // 阈值由调用方按各自的目的决定：扫描要快进快出，验健康要量出真实值。
    Ok(Some(handshake_started_at.elapsed().as_millis() as u64))
}

fn probe_upstream_ip_blocking(
    stream: std::net::TcpStream,
    domain: &str,
    timeout_secs: u64,
) -> Result<bool, GatewayError> {
    let timeout = std::time::Duration::from_secs(timeout_secs);
    // into_std() 之后 socket 仍是非阻塞的，这里改回阻塞模式再做阻塞式 TLS/HTTP 探测。
    stream
        .set_nonblocking(false)
        .map_err(|err| GatewayError::Internal(err.to_string()))?;
    stream
        .set_read_timeout(Some(timeout))
        .map_err(|err| GatewayError::Internal(err.to_string()))?;
    stream
        .set_write_timeout(Some(timeout))
        .map_err(|err| GatewayError::Internal(err.to_string()))?;

    let server_name = resolve_probe_server_name(domain).map_err(GatewayError::Internal)?;
    let connection = rustls::ClientConnection::new(build_probe_tls_config(), server_name)
        .map_err(|err| GatewayError::Internal(err.to_string()))?;
    let mut tls_stream = rustls::StreamOwned::new(connection, stream);
    let request = format!(
        "GET /inference/v1/models HTTP/1.1\r\n\
         Host: {domain}\r\n\
         User-Agent: {user_agent}\r\n\
         Authorization: Bearer public\r\n\
         Accept: application/json\r\n\
         x-opencode-session: {session_id}\r\n\
         Connection: close\r\n\r\n",
        user_agent = aether_provider_transport::opencode::opencode_user_agent(),
        session_id = aether_provider_transport::opencode::new_opencode_session_id(),
    );
    if let Err(err) = tls_stream.write_all(request.as_bytes()) {
        tracing::debug!(
            event_name = "opencode_probe_write_failed",
            log_type = "ops",
            domain,
            error = ?err,
            "opencode probe write failed"
        );
        return Ok(false);
    }
    let mut status_line = Vec::new();
    match read_probe_status_line(&mut tls_stream, &mut status_line) {
        Ok(true) => Ok(is_healthy_status_line(&status_line)),
        _ => Ok(false),
    }
}

/// 发一条**真实 chat** 探测（`POST /inference/v1/chat/completions`），只有 `200` 才算健康。
///
/// ## 为什么不能用 `/inference/v1/models`
///
/// 那个端点匿名可用。2026-10-17 对 `108.138.0.0/24` 做全量实测：254 个 IP 里
/// **239 个 chat 恒定 403 FreeTierError、0 个 200**，但同样这批 IP 打 `/models`
/// 有 239 个返回 200 —— 用 models 判健康，对「免费层被判死」的检出率是 0。
///
/// 返回 `Some(elapsed_ms)` 表示真的拿到 200；`None` 表示不可用（403/421/超时/其它）。
pub(crate) async fn probe_upstream_ip_chat_timed(
    ip: &str,
    domain: &str,
    port: u16,
    timeout_secs: u64,
    model: &str,
) -> Result<Option<u64>, GatewayError> {
    let parsed: IpAddr = match ip.trim().parse() {
        Ok(ip) => ip,
        Err(_) => return Ok(None),
    };
    let address = std::net::SocketAddr::new(parsed, port);
    let started_at = std::time::Instant::now();
    let connect = tokio::time::timeout(
        std::time::Duration::from_secs(timeout_secs),
        tokio::net::TcpStream::connect(address),
    )
    .await;
    let Ok(Ok(stream)) = connect else {
        return Ok(None);
    };
    let stream = stream
        .into_std()
        .map_err(|err| GatewayError::Internal(err.to_string()))?;
    let model = model.to_string();
    let domain = domain.to_string();
    let ok = tokio::task::spawn_blocking(move || {
        probe_chat_blocking(stream, &domain, timeout_secs, &model)
    })
    .await
    .map_err(|err| GatewayError::Internal(err.to_string()))??;
    if !ok {
        return Ok(None);
    }
    Ok(Some(started_at.elapsed().as_millis() as u64))
}

/// 阻塞式 chat 探测：TLS 握手 → 发 POST → 只读状态行 → `200` 才算健康。
fn probe_chat_blocking(
    stream: std::net::TcpStream,
    domain: &str,
    timeout_secs: u64,
    model: &str,
) -> Result<bool, GatewayError> {
    let timeout = std::time::Duration::from_secs(timeout_secs);
    stream
        .set_nonblocking(false)
        .map_err(|err| GatewayError::Internal(err.to_string()))?;
    stream
        .set_read_timeout(Some(timeout))
        .map_err(|err| GatewayError::Internal(err.to_string()))?;
    stream
        .set_write_timeout(Some(timeout))
        .map_err(|err| GatewayError::Internal(err.to_string()))?;

    let server_name = resolve_probe_server_name(domain).map_err(GatewayError::Internal)?;
    let connection = rustls::ClientConnection::new(build_probe_tls_config(), server_name)
        .map_err(|err| GatewayError::Internal(err.to_string()))?;
    let mut tls_stream = rustls::StreamOwned::new(connection, stream);

    // 请求体与真实流量同形：强制 stream + 四件工具桩（免费层准入要求）。
    let mut body = serde_json::json!({
        "model": model,
        "messages": [{"role": "user", "content": "ping"}],
        "max_tokens": 1,
        "stream": true,
    });
    aether_provider_transport::opencode::ensure_opencode_free_tier_tools(&mut body);
    let body = serde_json::to_string(&body).unwrap_or_else(|_| "{}".to_string());

    let session_id = aether_provider_transport::opencode::new_opencode_session_id();
    let request = format!(
        "POST /inference/v1/chat/completions HTTP/1.1\r\n\
         Host: {domain}\r\n\
         User-Agent: {user_agent}\r\n\
         Authorization: Bearer public\r\n\
         Accept: */*\r\n\
         Content-Type: application/json\r\n\
         Content-Length: {content_length}\r\n\
         x-opencode-client: cli\r\n\
         x-opencode-project: global\r\n\
         x-opencode-request: {request_id}\r\n\
         x-opencode-session: {session_id}\r\n\
         x-opencode-session-id: {session_id}\r\n\
         Connection: close\r\n\r\n{body}",
        user_agent = aether_provider_transport::opencode::opencode_user_agent(),
        content_length = body.len(),
        request_id = aether_provider_transport::opencode::new_opencode_request_id(),
    );
    if let Err(err) = tls_stream.write_all(request.as_bytes()) {
        tracing::debug!(
            event_name = "opencode_chat_probe_write_failed",
            log_type = "ops",
            domain,
            error = ?err,
            "opencode chat probe write failed"
        );
        return Ok(false);
    }
    let mut status_line = Vec::new();
    match read_probe_status_line(&mut tls_stream, &mut status_line) {
        Ok(true) => Ok(status_line_code(&status_line) == Some(200)),
        _ => Ok(false),
    }
}

/// 从 `HTTP/1.1 200 OK` 里取状态码。
fn status_line_code(status_line: &[u8]) -> Option<u16> {
    let space = status_line.iter().position(|byte| *byte == b' ')?;
    let rest = status_line.get(space + 1..space + 4)?;
    std::str::from_utf8(rest).ok()?.parse::<u16>().ok()
}

fn resolve_probe_server_name(host: &str) -> Result<rustls::pki_types::ServerName<'static>, String> {
    let host = host.trim().trim_start_matches('[').trim_end_matches(']');
    if let Ok(ip) = host.parse::<IpAddr>() {
        return Ok(rustls::pki_types::ServerName::from(ip));
    }
    rustls::pki_types::ServerName::try_from(host.to_string()).map_err(|err| err.to_string())
}

fn build_probe_tls_config() -> std::sync::Arc<rustls::ClientConfig> {
    let _ = rustls::crypto::ring::default_provider().install_default();
    let root_store =
        rustls::RootCertStore::from_iter(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());
    std::sync::Arc::new(
        rustls::ClientConfig::builder()
            .with_root_certificates(root_store)
            .with_no_client_auth(),
    )
}

/// 读取 HTTP 响应首行，EOF 或超长返回 false。
fn read_probe_status_line(
    stream: &mut rustls::StreamOwned<rustls::ClientConnection, std::net::TcpStream>,
    out: &mut Vec<u8>,
) -> Result<bool, std::io::Error> {
    let mut byte = [0u8; 1];
    loop {
        let read = stream.read(&mut byte)?;
        if read == 0 {
            return Ok(false);
        }
        if byte[0] == b'\n' {
            return Ok(true);
        }
        out.push(byte[0]);
        if out.len() > 1024 {
            return Ok(false);
        }
    }
}

/// `HTTP/1.1 2xx/3xx` 视为健康。
fn is_healthy_status_line(status_line: &[u8]) -> bool {
    let Some(space) = status_line.iter().position(|byte| *byte == b' ') else {
        return false;
    };
    let code_start = space + 1;
    if code_start + 2 >= status_line.len() {
        return false;
    }
    matches!(status_line[code_start], b'2' | b'3')
}

/// 解析前置代理域名的 A 记录，多采样取并集（供应商无关的候选来源）。
///
/// CDN 的边缘 IP 通常按轮询/地理调度下发，单次解析只拿到一小部分，所以采样多次
/// 再取并集。只收 IPv4：池里做 DNS 锚点时是按 `IpAddr` 直连的，IPv6 边缘节点
/// 在部分线路上不可达，收进来只会让复验白跑。
pub(crate) async fn resolve_domain_candidates(domain: &str, samples: usize) -> Vec<String> {
    let domain = domain.trim();
    if domain.is_empty() {
        return Vec::new();
    }
    let mut found = BTreeSet::new();
    for _ in 0..samples.max(1) {
        // 必须给每次解析加超时：`lookup_host` 本身没有超时，解析器一旦卡住（DNS 不可达、
        // 上游解析器丢包）这个 await 就永远不返回。2026-10-18 实测过一次：扫描卡在这里，
        // `scanning` 标志永久为 true，随后所有扫描/复验请求都被守卫挡成 400。
        match tokio::time::timeout(
            std::time::Duration::from_secs(DNS_LOOKUP_TIMEOUT_SECS),
            tokio::net::lookup_host((domain, 443u16)),
        )
        .await
        {
            Ok(Ok(addrs)) => {
                for addr in addrs {
                    if let std::net::IpAddr::V4(v4) = addr.ip() {
                        found.insert(v4.to_string());
                    }
                }
            }
            Ok(Err(_)) => {}
            Err(_) => {
                tracing::warn!(
                    event_name = "opencode_scan_dns_timeout",
                    log_type = "ops",
                    domain,
                    timeout_secs = DNS_LOOKUP_TIMEOUT_SECS,
                    "opencode scan domain resolution timed out"
                );
            }
        }
        // 给解析器/调度器一点间隔，让轮询能轮到不同的边缘 IP。
        tokio::time::sleep(std::time::Duration::from_millis(150)).await;
    }
    found.into_iter().collect()
}

fn now_unix_secs() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|duration| duration.as_secs())
        .unwrap_or_default()
}

fn now_string() -> String {
    chrono::Utc::now().to_rfc3339()
}

impl OpenCodeHealthConfig {
    /// 从 provider 的 `config` 读取 `opencode_health` 段。
    pub(crate) fn from_provider_config(config: &Option<Value>) -> Self {
        match config.as_ref().and_then(Value::as_object) {
            Some(object) => Self::from_config_object(object),
            None => Self::default(),
        }
    }

    /// 从已经拆成对象的 config 读取 `opencode_health` 段。
    ///
    /// 单独开一个入口是为了出池路径：它在 CAS 写回的回调里拿到的是**当前最新**的
    /// `config` 对象，再包一层 `Value` 只为解析会白白复制几十 KB（线上实测
    /// `providers.config` 已到 30KB，且每次健康更新整段重写）。
    pub(crate) fn from_config_object(object: &serde_json::Map<String, Value>) -> Self {
        let Some(section) = object.get("opencode_health").and_then(Value::as_object) else {
            return Self::default();
        };
        let mut result = Self::default();
        result.healthy = string_list(section.get("healthy"));
        result.degraded = string_list(section.get("degraded"));
        result.healthy_prev = string_list(section.get("healthy_prev"));
        if let Some(Value::Object(items)) = section.get("latencies") {
            result.latencies = items
                .iter()
                .filter_map(|(ip, value)| match value {
                    Value::Number(number) => number
                        .as_u64()
                        .map(|ms| (ip.trim().to_string(), ms))
                        .filter(|(ip, _)| !ip.is_empty()),
                    _ => None,
                })
                .collect();
        }
        result.abnormal = parse_abnormal_entries(section.get("abnormal"));
        result.blocked = string_list(section.get("blocked"));
        if let Some(Value::Bool(enabled)) = section.get("auto_verify_enabled") {
            result.auto_verify_enabled = *enabled;
        }
        if let Some(value) = section.get("verify_interval_hours").and_then(Value::as_u64) {
            result.verify_interval_hours = Some(value as u32);
        }
        if let Some(value) = section.get("verify_samples").and_then(Value::as_u64) {
            result.verify_samples = Some(value as usize);
        }
        if let Some(value) = section.get("verify_max_median_ms").and_then(Value::as_u64) {
            result.verify_max_median_ms = Some(value);
        }
        if let Some(value) = section.get("min_pool_size").and_then(Value::as_u64) {
            result.min_pool_size = Some(value as usize);
        }
        if let Some(Value::Bool(enabled)) = section.get("session_sticky_enabled") {
            result.session_sticky_enabled = *enabled;
        }
        if let Some(value) = section
            .get("session_sticky_min_pool")
            .and_then(Value::as_u64)
        {
            result.session_sticky_min_pool = Some(value as usize);
        }
        if let Some(value) = section.get("abnormal_max_age_days").and_then(Value::as_u64) {
            result.abnormal_max_age_days = Some(value as u32);
        }
        if let Some(Value::String(at)) = section.get("last_verify_at") {
            let trimmed = at.trim();
            if !trimmed.is_empty() {
                result.last_verify_at = Some(trimmed.to_string());
            }
        }
        if let Some(value) = section.get("last_verify_checked").and_then(Value::as_u64) {
            result.last_verify_checked = value;
        }
        if let Some(value) = section.get("last_verify_kept").and_then(Value::as_u64) {
            result.last_verify_kept = value;
        }
        if let Some(value) = section.get("last_verify_dropped").and_then(Value::as_u64) {
            result.last_verify_dropped = value;
        }
        result
    }

    /// 把请求体里 `opencode_health` 段出现的字段合并到已有配置上。
    ///
    /// 与扫描配置同样走部分更新：只调整阈值不应该把 healthy 列表打回空。
    pub(crate) fn merged_with_payload(
        existing: &Option<Value>,
        payload: &serde_json::Map<String, Value>,
    ) -> Self {
        let Some(section) = payload.get("opencode_health").and_then(Value::as_object) else {
            return Self::from_provider_config(existing);
        };
        let mut result = Self::from_provider_config(existing);
        if section.contains_key("healthy") {
            result.healthy = string_list(section.get("healthy"));
        }
        if section.contains_key("degraded") {
            result.degraded = string_list(section.get("degraded"));
        }
        if let Some(Value::Bool(enabled)) = section.get("auto_verify_enabled") {
            result.auto_verify_enabled = *enabled;
        }
        if section.contains_key("verify_interval_hours") {
            result.verify_interval_hours = section
                .get("verify_interval_hours")
                .and_then(Value::as_u64)
                .map(|value| value as u32);
        }
        if section.contains_key("verify_samples") {
            result.verify_samples = section
                .get("verify_samples")
                .and_then(Value::as_u64)
                .map(|value| value as usize);
        }
        if section.contains_key("verify_max_median_ms") {
            result.verify_max_median_ms =
                section.get("verify_max_median_ms").and_then(Value::as_u64);
        }
        if section.contains_key("min_pool_size") {
            result.min_pool_size = section
                .get("min_pool_size")
                .and_then(Value::as_u64)
                .map(|value| value as usize);
        }
        if let Some(Value::Bool(enabled)) = section.get("session_sticky_enabled") {
            result.session_sticky_enabled = *enabled;
        }
        if section.contains_key("session_sticky_min_pool") {
            result.session_sticky_min_pool = section
                .get("session_sticky_min_pool")
                .and_then(Value::as_u64)
                .map(|value| value as usize);
        }
        if section.contains_key("abnormal_max_age_days") {
            result.abnormal_max_age_days = section
                .get("abnormal_max_age_days")
                .and_then(Value::as_u64)
                .map(|value| value as u32);
        }
        result
    }

    /// 输出裸配置对象（不含 `opencode_health` 外层键）。
    pub(crate) fn to_provider_config_value(&self) -> Value {
        json!({
            "healthy": self.healthy.clone(),
            "degraded": self.degraded.clone(),
            "latencies": self.latencies.clone(),
            "abnormal": abnormal_entries_json(&self.abnormal),
            "blocked": self.blocked.clone(),
            "last_verify_at": self.last_verify_at.clone().unwrap_or_default(),
            "last_verify_checked": self.last_verify_checked,
            "last_verify_kept": self.last_verify_kept,
            "last_verify_dropped": self.last_verify_dropped,
            "auto_verify_enabled": self.auto_verify_enabled,
            "verify_interval_hours": self.verify_interval_hours.unwrap_or(0),
            "verify_samples": self.verify_samples(),
            "verify_max_median_ms": self.verify_max_median_ms(),
            "min_pool_size": self.min_pool_size(),
            "session_sticky_enabled": self.session_sticky_enabled,
            "session_sticky_min_pool": self.session_sticky_min_pool(),
            "abnormal_max_age_days": self.abnormal_max_age_days(),
        })
    }

    /// 自动验健康是否真正生效：开关打开且间隔大于 0。
    pub(crate) fn autoverify_effective(&self) -> bool {
        self.auto_verify_enabled && self.verify_interval_hours.unwrap_or(0) > 0
    }

    /// 首次迁移：线上池还写在 `opencode_scan.exit_pool` 里，
    /// 而生产轮转已经改读 `healthy`。没有这一步，部署瞬间池子就会变空。
    ///
    /// 同时把同一批 IP 播种进 `candidates`：验健康的待验集合是
    /// `candidates ∪ healthy ∪ pinned`，候选为空只会让候选栏看起来是空的，
    /// 但一旦有人手工删了 healthy 里的某个节点，它就没法再被找回。
    ///
    /// 幂等：`healthy` 非空时不做任何事，所以重复执行安全。
    pub(crate) fn migrated_from(&mut self, scan: &OpenCodeScanConfig) -> bool {
        if !self.healthy.is_empty() || scan.exit_pool.is_empty() {
            return false;
        }
        self.healthy = scan.exit_pool.clone();
        self.healthy_prev = scan.exit_pool.clone();
        true
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use aether_crypto::DEVELOPMENT_ENCRYPTION_KEY;
    use aether_data::repository::provider_catalog::InMemoryProviderCatalogReadRepository;
    use std::sync::Arc;

    const POOL_TEST_PROVIDER_ID: &str = "opencode-pool-write-test";
    // ---------------------------------------------------------------------------
    // trust-on-add：轮转池 = healthy ∪ (exit_pool − abnormal − blocked)
    // ---------------------------------------------------------------------------

    /// 组一份「已复验转正 + 已加入未验证 + 粗筛候选」的配置。
    fn pool_fixture(
        healthy: &[&str],
        exit_pool: &[&str],
        candidates: &[&str],
    ) -> (OpenCodeScanConfig, OpenCodeHealthConfig) {
        let mut scan = OpenCodeScanConfig::default();
        scan.exit_pool = exit_pool.iter().map(|ip| ip.to_string()).collect();
        scan.candidates = candidates.iter().map(|ip| ip.to_string()).collect();
        scan.pinned = Vec::new();
        scan.exit_pool_disabled = Vec::new();
        let mut health = OpenCodeHealthConfig::default();
        health.healthy = healthy.iter().map(|ip| ip.to_string()).collect();
        (scan, health)
    }

    /// 未验证（只在 `exit_pool`、不在 `abnormal`）的 IP 必须在轮转池里。
    ///
    /// 这是 trust-on-add 的全部意义：加进来不花一次验证（那是一次真实 chat，要消耗
    /// 它本就很少的免费额度），直接交给真实流量筛选；否则 194 → 2000 的扩容要 15 小时
    /// 探测，而且会把现存的老 IP 全踢出 healthy。
    #[test]
    fn unverified_exit_pool_ips_join_the_rotation_pool() {
        let (scan, health) =
            pool_fixture(&["108.138.0.10"], &["108.138.0.11", "108.138.0.12"], &[]);
        let (verified, trusted) = scan.rotation_pool_parts(&health);
        assert_eq!(verified, vec!["108.138.0.10".to_string()]);
        assert_eq!(
            trusted,
            vec!["108.138.0.11".to_string(), "108.138.0.12".to_string()]
        );
        assert_eq!(
            scan.effective_pool(&health),
            vec![
                "108.138.0.10".to_string(),
                "108.138.0.11".to_string(),
                "108.138.0.12".to_string()
            ]
        );
        assert_eq!(scan.trusted_on_add_count(&health), 2);
    }

    /// 已在异常池 / 已被人工拉黑的成员**不参与**轮转。
    ///
    /// 异常池是复验判过的问题 IP（探测已知失败），拉黑是人工否决。两者都必须在
    /// 组池这一步就出局——选点虽然也会跳过它们，但「池子里有多少个可用」这个对外
    /// 计数会说谎。
    #[test]
    fn abnormal_and_blocked_members_never_enter_the_rotation_pool() {
        let (scan, mut health) = pool_fixture(
            &["108.138.0.10"],
            &["108.138.0.11", "108.138.0.12", "108.138.0.13"],
            &[],
        );
        health.record_abnormal("108.138.0.11", "unreachable", None, "2026-10-21T00:00:00Z");
        health.blocked.push("108.138.0.12".to_string());
        assert_eq!(
            scan.effective_pool(&health),
            vec!["108.138.0.10".to_string(), "108.138.0.13".to_string()]
        );
        assert_eq!(scan.trusted_on_add_count(&health), 1);
    }

    /// `candidates` 绝不进轮转池。
    ///
    /// 候选只是「粗筛探通了」的产物——连得通不等于扛得住大请求，扫描即上线正是
    /// 线上 503 的根源。这里把它写死成断言，避免以后有人为了「池子不够大」把候选
    /// 顺手塞进轮转池。
    #[test]
    fn candidates_never_enter_the_rotation_pool() {
        let (scan, health) = pool_fixture(
            &["108.138.0.10"],
            &["108.138.0.11"],
            &["108.138.0.99", "108.138.0.98"],
        );
        let pool = scan.effective_pool(&health);
        assert!(!pool.iter().any(|ip| ip == "108.138.0.99"));
        assert!(!pool.iter().any(|ip| ip == "108.138.0.98"));
        assert_eq!(pool.len(), 2);
    }

    /// 回归：`exit_pool ⊆ healthy` 时（= 今天线上的形状：所有池内 IP 都验过），
    /// 轮转池必须**逐字节**等于 `healthy`，顺序也不变。
    ///
    /// 这条是「扩池不改变既有节点选点行为」的依据：前缀完全相同，游标/会话哈希
    /// 只是在池变长之后按新长度取模，没有重新排序、没有插入。
    #[test]
    fn verified_only_pools_keep_the_original_order() {
        let healthy = ["108.138.0.10", "108.138.0.11", "108.138.0.12"];
        let (scan, health) = pool_fixture(&healthy, &healthy, &["108.138.0.99"]);
        assert_eq!(scan.effective_pool(&health), health.healthy);
        assert_eq!(scan.trusted_on_add_count(&health), 0);
        // 重复项（healthy 与 exit_pool 同 IP）不会让池子变长。
        let mut duplicated = scan.clone();
        duplicated.exit_pool.push("108.138.0.10".to_string());
        assert_eq!(duplicated.effective_pool(&health), health.healthy);
    }

    /// 对外计数必须与新池同源：`rotation_pool_size`（= `effective_pool` 长度）与
    /// `in_use_count`（扣掉人工停用）都要跟着涨，`healthy_count` 仍是**已验**数量。
    #[test]
    fn rotation_pool_counts_follow_the_effective_pool() {
        let provider_id = "opencode-pool-counts-test";
        let mut scan = OpenCodeScanConfig::default();
        // 6 个已加入、其中 1 个已验过、1 个被停用：池子大于保底线 5，
        // 所以不会触发 `pool_below_floor` 告警。
        scan.exit_pool = (10..16).map(|index| format!("108.138.0.{index}")).collect();
        scan.exit_pool_disabled = vec!["108.138.0.15".to_string()];
        let mut health = OpenCodeHealthConfig::default();
        health.healthy = vec!["108.138.0.10".to_string()];

        let pool = scan.effective_pool(&health);
        assert_eq!(pool.len(), 6, "轮转池 = 1 个已验 + 5 个未验证");
        update_pool_status_counts(provider_id, &scan, &health, scan.exit_pool_disabled.len());
        let status = opencode_ip_pool_status_for(provider_id);
        assert_eq!(status.healthy_count, 1, "健康计数仍是已复验转正的数量");
        assert_eq!(
            status.in_use_count, 5,
            "在用计数 = 轮转池扣掉人工停用的那个"
        );
        assert_eq!(status.candidate_count, 0);
        assert!(!status.pool_below_floor, "在用 5 个正好等于保底线，不告警");
    }

    // ---------------------------------------------------------------------------
    // 选点：未验证的点真的会被抽中，异常的点永远抽不中
    // ---------------------------------------------------------------------------

    /// 未验证的 IP 会被**选点**选中（不只是出现在列表里）。
    #[tokio::test]
    async fn unverified_ip_is_actually_picked_by_the_anchor_selector() {
        let (scan, health) = pool_fixture(&["108.138.0.10"], &["108.138.0.11"], &[]);
        let pool = scan.effective_pool(&health);
        let provider = pool_test_provider(json!({}));
        let state = pool_test_state(provider);
        let mut picked: BTreeSet<String> = BTreeSet::new();
        for _ in 0..4 {
            let ip = crate::opencode_rotation::pick_anchor_ip(
                &state,
                POOL_TEST_PROVIDER_ID,
                &pool,
                &crate::opencode_rotation::OpenCodeAnchorSkip::default(),
                None,
            )
            .await
            .expect("池非空时必须选出一个锚点");
            picked.insert(ip);
        }
        assert_eq!(
            picked,
            BTreeSet::from(["108.138.0.10".to_string(), "108.138.0.11".to_string()]),
            "游标轮转两轮必须把「已验」和「未验证」的点都抽到：{picked:?}"
        );
    }

    /// 异常池里的 IP 不会被选中——即使调用方把池子算错了、把它塞进了切片。
    ///
    /// 双层保证：`effective_pool` 不产出它，选点也照样跳过它（`skip.abnormal`）。
    #[tokio::test]
    async fn abnormal_ip_is_never_picked_by_the_anchor_selector() {
        let mut health = OpenCodeHealthConfig::default();
        health.record_abnormal("108.138.0.11", "unreachable", None, "2026-10-21T00:00:00Z");
        let pool = vec!["108.138.0.10".to_string(), "108.138.0.11".to_string()];
        let skip = crate::opencode_rotation::OpenCodeAnchorSkip {
            abnormal: health.abnormal_ips().into_iter().collect(),
            ..Default::default()
        };
        let provider = pool_test_provider(json!({}));
        let state = pool_test_state(provider);
        for _ in 0..4 {
            let ip = crate::opencode_rotation::pick_anchor_ip(
                &state,
                POOL_TEST_PROVIDER_ID,
                &pool,
                &skip,
                None,
            )
            .await
            .expect("池里还有可用点时必须选出来");
            assert_eq!(ip, "108.138.0.10");
        }
    }

    // ---------------------------------------------------------------------------
    // 连续失败出池
    // ---------------------------------------------------------------------------

    /// 出池阈值：默认 3，可以调高，也可以显式关掉。
    ///
    /// `None`（没配过）与 `Some(0)`（明确关掉）必须分开——只用一个 `.filter(> 0)`
    /// 会把两者混成一个，那样就没办法在配额枯竭的日子里关掉自动出池。
    #[test]
    fn evict_threshold_defaults_to_three_and_zero_disables_it() {
        let mut config = OpenCodeScanConfig::default();
        assert_eq!(config.evict_fail_threshold(), OPENCODE_DEFAULT_EVICT_FAILS);
        assert_eq!(config.evict_fail_threshold(), 3);
        config.evict_fail_threshold = Some(6);
        assert_eq!(config.evict_fail_threshold(), 6);
        config.evict_fail_threshold = Some(0);
        assert_eq!(config.evict_fail_threshold(), 0);
        // 存进配置再读回来必须还是 6：否则面板上调的阈值根本不生效。
        let round_tripped = OpenCodeScanConfig::from_provider_config(&Some(json!({
            "opencode_scan": {"evict_fail_threshold": 6}
        })));
        assert_eq!(round_tripped.evict_fail_threshold(), 6);
    }

    /// 连续失败出池：`exit_pool` 与 `healthy` 两处一起删，之后再也抽不到。
    #[tokio::test]
    async fn eviction_removes_the_ip_from_the_pool_and_it_is_never_picked_again() {
        // 池子 7 个（> 保底线 5），所以保护线不会拦下这次出池。
        let initial = json!({
            "opencode_scan": {
                "exit_pool": [
                    "198.51.100.1", "198.51.100.2", "198.51.100.3", "198.51.100.4",
                    "198.51.100.5", "198.51.100.6", "198.51.100.7",
                ],
                "candidates": ["198.51.100.7", "198.51.100.6"],
            },
            "opencode_health": {
                "healthy": ["198.51.100.1", "198.51.100.7"],
                "abnormal": [
                    {"ip": "198.51.100.7", "since": "t1", "fails": 1,
                     "reason": "too_slow", "median_ms": 9000}
                ],
                "latencies": {"198.51.100.7": 9000, "198.51.100.1": 800},
            },
        });
        let provider = pool_test_provider(initial);
        let state = pool_test_state(provider);

        let outcome = evict_opencode_exit_ip(&state, POOL_TEST_PROVIDER_ID, "198.51.100.7")
            .await
            .expect("出池写回不该失败");
        assert_eq!(outcome, OpenCodeEvictOutcome::Removed);

        let stored = stored_config(&state).await;
        let scan = OpenCodeScanConfig::from_provider_config(&Some(stored.clone()));
        let health = OpenCodeHealthConfig::from_provider_config(&Some(stored.clone()));
        assert_eq!(
            scan.exit_pool,
            vec![
                "198.51.100.1".to_string(),
                "198.51.100.2".to_string(),
                "198.51.100.3".to_string(),
                "198.51.100.4".to_string(),
                "198.51.100.5".to_string(),
                "198.51.100.6".to_string()
            ]
        );
        assert!(!health.healthy.iter().any(|ip| ip == "198.51.100.7"));
        assert!(health.healthy.iter().any(|ip| ip == "198.51.100.1"));
        assert!(!health
            .abnormal
            .iter()
            .any(|entry| entry.ip == "198.51.100.7"));
        assert!(!health.latencies.contains_key("198.51.100.7"));
        assert!(
            health.latencies.contains_key("198.51.100.1"),
            "别的节点的延迟记录不能被顺手清掉"
        );
        assert!(
            !scan.candidates.is_empty(),
            "候选是扫描的原始产物，出池不删它（下一次复验可以从这里把它验回来）"
        );
        let pool = scan.effective_pool(&health);
        assert_eq!(pool.len(), 6);
        assert!(!pool.iter().any(|ip| ip == "198.51.100.7"));

        // 之后选点永远见不到它。
        for _ in 0..7 {
            let ip = crate::opencode_rotation::pick_anchor_ip(
                &state,
                POOL_TEST_PROVIDER_ID,
                &pool,
                &crate::opencode_rotation::OpenCodeAnchorSkip::default(),
                None,
            )
            .await
            .expect("池非空时必须选出一个锚点");
            assert_ne!(ip, "198.51.100.7");
        }
    }

    /// 出池的三道闸：人工保护、人工停用、保护线。
    ///
    /// 三者都必须留住 IP 并**说明原因**——「为什么它还在池里」必须能从返回值回答，
    /// 否则出池就成了猜谜。
    #[tokio::test]
    async fn eviction_respects_pinned_disabled_and_the_pool_floor() {
        // 1) 保护名单：人工声明要留着。
        let pinned = json!({
            "opencode_scan": {
                "exit_pool": [
                    "198.51.100.1", "198.51.100.2", "198.51.100.3", "198.51.100.4",
                    "198.51.100.5", "198.51.100.6", "198.51.100.7",
                ],
                "pinned": ["198.51.100.7"],
            },
        });
        let provider = pool_test_provider(pinned);
        let state = pool_test_state(provider);
        assert_eq!(
            evict_opencode_exit_ip(&state, POOL_TEST_PROVIDER_ID, "198.51.100.7")
                .await
                .expect("查询不该失败"),
            OpenCodeEvictOutcome::ProtectedPinned
        );

        // 2) 人工停用：尊重那个开关（停用是可撤销的意图，出池是删除）。
        let disabled = json!({
            "opencode_scan": {
                "exit_pool": [
                    "198.51.100.1", "198.51.100.2", "198.51.100.3", "198.51.100.4",
                    "198.51.100.5", "198.51.100.6", "198.51.100.7",
                ],
                "exit_pool_disabled": ["198.51.100.7"],
            },
        });
        let provider = pool_test_provider(disabled);
        let state = pool_test_state(provider);
        assert_eq!(
            evict_opencode_exit_ip(&state, POOL_TEST_PROVIDER_ID, "198.51.100.7")
                .await
                .expect("查询不该失败"),
            OpenCodeEvictOutcome::ProtectedDisabled
        );

        // 3) 保护线：池子已经小到保底下限，摘掉它只会让池更空。
        let tiny = json!({
            "opencode_scan": {"exit_pool": ["198.51.100.7", "198.51.100.8"]},
            "opencode_health": {"healthy": [], "min_pool_size": 5},
        });
        let provider = pool_test_provider(tiny);
        let state = pool_test_state(provider);
        assert_eq!(
            evict_opencode_exit_ip(&state, POOL_TEST_PROVIDER_ID, "198.51.100.7")
                .await
                .expect("查询不该失败"),
            OpenCodeEvictOutcome::ProtectedPoolFloor
        );

        // 已经不在池里：什么都不写。
        let absent = json!({ "opencode_scan": {"exit_pool": ["198.51.100.8"]} });
        let provider = pool_test_provider(absent);
        let state = pool_test_state(provider);
        assert_eq!(
            evict_opencode_exit_ip(&state, POOL_TEST_PROVIDER_ID, "198.51.100.7")
                .await
                .expect("查询不该失败"),
            OpenCodeEvictOutcome::NotInPool
        );
    }

    /// 运行时失败计数：累加到阈值、成功即清零。
    ///
    /// 这是出池判据的输入。`Transport` 类失败（连接超时 / TLS 失败 / 连接重置）与
    /// 上游状态行无关，确实归因到出口节点，所以它算数；记满 3 次就由后台任务把 IP
    /// 摘掉，成功一次计数器归零（"连续"二字全靠这一步）。
    #[tokio::test]
    async fn consecutive_runtime_failures_reach_the_eviction_threshold_and_reset_on_success() {
        let provider = pool_test_provider(json!({}));
        let state = pool_test_state(provider);
        let provider_id = POOL_TEST_PROVIDER_ID;
        let ip = "198.51.100.7";
        let tuning = crate::opencode_rotation::OpenCodeFailureTuning::default();
        assert_eq!(tuning.evict_threshold, 3, "默认出池阈值必须是 3 次连续失败");
        for expected in 1..=3u64 {
            let fails = crate::opencode_rotation::record_opencode_runtime_failure_tuned(
                &state,
                provider_id,
                ip,
                crate::opencode_rotation::OpenCodeFailureSource::Transport,
                tuning,
            )
            .await;
            assert_eq!(fails, Some(expected));
        }
        assert_eq!(
            crate::opencode_rotation::peek_opencode_ip_fail(&state, provider_id, ip).await,
            3
        );
        // 成功一次：计数清零，下一次失败又是从 1 开始。
        crate::opencode_rotation::clear_opencode_ip_fail(&state, provider_id, ip).await;
        assert_eq!(
            crate::opencode_rotation::peek_opencode_ip_fail(&state, provider_id, ip).await,
            0
        );
        let fails = crate::opencode_rotation::record_opencode_runtime_failure_tuned(
            &state,
            provider_id,
            ip,
            crate::opencode_rotation::OpenCodeFailureSource::Transport,
            tuning,
        )
        .await;
        assert_eq!(fails, Some(1));
    }

    /// 复验丢弃必须**同一次写**就把 IP 从 `exit_pool` 摘掉。
    ///
    /// 只清异常池的后果不是「留下脏数据」，而是「刚判死的 IP 立刻复活」：
    /// 轮转池 = healthy ∪ (exit_pool − abnormal − blocked)，清掉 abnormal 就等于
    /// 把它放回了生产。
    #[tokio::test]
    async fn verify_discard_evicts_in_the_same_write_as_the_health_section() {
        let initial = json!({
            "opencode_scan": {"exit_pool": ["198.51.100.7", "198.51.100.8"]},
            "opencode_health": {
                "healthy": ["198.51.100.8"],
                "abnormal": [
                    {"ip": "198.51.100.7", "since": "t1", "fails": 2,
                     "reason": "unreachable", "median_ms": null}
                ],
            },
        });
        let provider = pool_test_provider(initial);
        let state = pool_test_state(provider.clone());
        let mut health = OpenCodeHealthConfig::from_provider_config(&provider.config);
        // 复验的丢弃路径：先把异常条目清掉，再交给一次写入。
        health.clear_abnormal("198.51.100.7");
        write_pool_state_pair(
            &state,
            POOL_TEST_PROVIDER_ID,
            &health,
            &["198.51.100.7".to_string()],
        )
        .await
        .expect("写入不该失败");

        let stored = stored_config(&state).await;
        let scan = OpenCodeScanConfig::from_provider_config(&Some(stored.clone()));
        let after = OpenCodeHealthConfig::from_provider_config(&Some(stored));
        assert_eq!(scan.exit_pool, vec!["198.51.100.8".to_string()]);
        assert!(!after
            .abnormal
            .iter()
            .any(|entry| entry.ip == "198.51.100.7"));
        assert_eq!(
            scan.effective_pool(&after),
            vec!["198.51.100.8".to_string()],
            "被丢弃的 IP 不能因为异常条目被清掉而重新进池"
        );
    }

    // ---------------------------------------------------------------------------
    // 异常池过期清理
    // ---------------------------------------------------------------------------

    fn abnormal_since(days_ago: i64) -> String {
        (chrono::Utc::now() - chrono::Duration::days(days_ago)).to_rfc3339()
    }

    /// 老条目被清、新条目保留、第二次调用不再删任何东西（幂等）。
    #[test]
    fn expired_abnormal_entries_are_pruned_and_the_prune_is_idempotent() {
        let mut health = OpenCodeHealthConfig::default();
        health.record_abnormal("10.0.0.1", "too_slow", None, &abnormal_since(30));
        health.record_abnormal("10.0.0.2", "unreachable", None, &abnormal_since(8));
        health.record_abnormal("10.0.0.3", "partial_timeout", None, &abnormal_since(1));
        health.record_abnormal("10.0.0.4", "too_slow", None, &abnormal_since(0));

        let removed = health.prune_expired_abnormal_at(chrono::Utc::now());
        assert_eq!(
            removed,
            vec!["10.0.0.1".to_string(), "10.0.0.2".to_string()]
        );
        let remaining: Vec<&str> = health.abnormal.iter().map(|e| e.ip.as_str()).collect();
        assert_eq!(remaining, vec!["10.0.0.3", "10.0.0.4"]);

        // 幂等：再跑一次什么都不删。
        assert!(health
            .prune_expired_abnormal_at(chrono::Utc::now())
            .is_empty());
        assert_eq!(health.abnormal.len(), 2);
    }

    /// 已达出池阈值的条目不受过期影响，`0` 表示关掉过期清理，时间戳读不懂的条目也留着。
    #[test]
    fn abnormal_prune_keeps_entries_it_cannot_safely_drop() {
        let mut health = OpenCodeHealthConfig::default();
        // fails = 2 = 已达丢弃门槛：本该已被丢弃，还在就说明当时池子低于保护线，
        // 这种条目必须继续拦住这个 IP。
        health.abnormal.push(OpenCodeAbnormalIp {
            ip: "10.0.0.9".to_string(),
            since: abnormal_since(90),
            fails: OPENCODE_ABNORMAL_DISCARD_FAILS,
            reason: "unreachable".to_string(),
            median_ms: None,
        });
        // 时间戳读不懂：宁可留一条僵尸记录，也不要猜错方向把它放回轮转。
        health.abnormal.push(OpenCodeAbnormalIp {
            ip: "10.0.0.10".to_string(),
            since: "not-a-timestamp".to_string(),
            fails: 1,
            reason: "too_slow".to_string(),
            median_ms: None,
        });
        assert!(health
            .prune_expired_abnormal_at(chrono::Utc::now())
            .is_empty());
        assert_eq!(health.abnormal.len(), 2);

        // 关掉过期清理（0 天 = 永不过期）时，连正常的旧条目也不动。
        health.abnormal_max_age_days = Some(0);
        health.record_abnormal("10.0.0.11", "too_slow", None, &abnormal_since(365));
        assert!(health
            .prune_expired_abnormal_at(chrono::Utc::now())
            .is_empty());
        assert_eq!(health.abnormal.len(), 3);
        assert_eq!(health.abnormal_max_age_days(), 0);
    }

    /// 清理挂在健康更新上：写一次 `opencode_health` 就把过期条目带走。
    #[tokio::test]
    async fn writing_the_health_section_prunes_expired_abnormal_entries() {
        let initial = json!({
            "opencode_scan": {"exit_pool": ["198.51.100.7"]},
            "opencode_health": {
                "healthy": ["198.51.100.7"],
                "abnormal": [
                    {"ip": "198.51.100.70", "since": "2020-01-01T00:00:00+00:00", "fails": 1,
                     "reason": "too_slow", "median_ms": 9000}
                ],
            },
        });
        let provider = pool_test_provider(initial);
        let state = pool_test_state(provider.clone());
        let health = OpenCodeHealthConfig::from_provider_config(&provider.config);
        write_health_config(&state, &provider, &health)
            .await
            .expect("写入不该失败");
        let after = OpenCodeHealthConfig::from_provider_config(&Some(stored_config(&state).await));
        assert!(
            after.abnormal.is_empty(),
            "老于 7 天的异常条目必须在健康更新时被清掉：{:?}",
            after.abnormal
        );
        assert_eq!(after.healthy, vec!["198.51.100.7".to_string()]);
    }

    fn pool_test_provider(config: Value) -> StoredProviderCatalogProvider {
        StoredProviderCatalogProvider::new(
            POOL_TEST_PROVIDER_ID.to_string(),
            "OpenCode Pool Write Test".to_string(),
            None,
            "opencode".to_string(),
        )
        .expect("provider should build")
        .with_transport_fields(
            true,
            false,
            false,
            None,
            None,
            None,
            None,
            None,
            Some(config),
        )
    }

    fn pool_test_state(provider: StoredProviderCatalogProvider) -> AppState {
        let repository = Arc::new(InMemoryProviderCatalogReadRepository::seed(
            vec![provider],
            Vec::new(),
            Vec::new(),
        ));
        AppState::new()
            .expect("gateway state should build")
            .with_data_state_for_tests(
                crate::data::GatewayDataState::with_provider_catalog_repository_for_tests(
                    repository,
                )
                .with_encryption_key_for_tests(DEVELOPMENT_ENCRYPTION_KEY),
            )
    }

    async fn stored_config(state: &AppState) -> Value {
        state
            .read_provider_catalog_providers_by_ids(&[POOL_TEST_PROVIDER_ID.to_string()])
            .await
            .expect("provider should read")
            .into_iter()
            .next()
            .expect("provider should exist")
            .config
            .expect("provider should carry a config")
    }

    fn healthy_ips(config: &Value) -> Vec<String> {
        OpenCodeHealthConfig::from_provider_config(&Some(config.clone())).healthy
    }

    /// 池内 IP 一键复验的空池短路：`exit_pool` 为空（或只有空白项）时直接返回空
    /// 结果，不探测、不写配置——空池点「一键复验全部」应当秒回「检查 0 个」，
    /// 而不是去打上游或报错。
    #[tokio::test]
    async fn batch_verify_of_empty_pool_short_circuits_without_probing() {
        let initial = json!({
            "opencode_scan": { "cidrs": ["203.0.113.0/24"], "exit_pool": ["", "   "] }
        });
        let provider = pool_test_provider(initial);
        let state = pool_test_state(provider.clone());
        let outcomes = run_open_code_pool_verify_pool_ips(&state, &provider)
            .await
            .expect("空池必须直接返回而不是报错");
        assert!(outcomes.is_empty(), "空池不应产出任何复验结论");
    }

    /// 复现线上事故：复验先写 opencode_health，紧接着写 opencode_scan。
    ///
    /// 旧实现两个写函数都拿**任务开始时的 provider 快照**重建整个 config 再整行
    /// 写回，于是第二次写把刚写好的 healthy 覆盖回旧值。线上实测就是这个形状：
    /// 复验 checked=337 / kept=337 / dropped=0，而生产池仍是 65 个节点，
    /// latencies / degraded / rejections 一起回滚——健康门槛等于没生效。
    #[tokio::test]
    async fn scan_write_after_verify_write_keeps_the_new_health_section() {
        let initial = json!({
            "opencode_scan": { "candidates": ["198.51.100.1"], "cidrs": ["203.0.113.0/24"] },
            "opencode_health": { "healthy": ["198.51.100.1"] },
        });
        // 任务开始时的快照：两趟任务都拿着它。
        let stale_provider = pool_test_provider(initial.clone());
        let state = pool_test_state(stale_provider.clone());

        // 复验：337 个节点全部通过体检。
        let verified: Vec<String> = (0..337)
            .map(|index| format!("198.51.100.{}", index % 200))
            .collect();
        let mut health = OpenCodeHealthConfig::from_provider_config(&stale_provider.config);
        health.healthy = verified.clone();
        health.last_verify_kept = verified.len() as u64;
        write_health_config(&state, &stale_provider, &health)
            .await
            .expect("verify write should succeed");

        // 扫描：紧接着把候选写进 opencode_scan。
        let mut scan = OpenCodeScanConfig::from_provider_config(&stale_provider.config);
        scan.candidates = verified.clone();
        write_scan_config(&state, &stale_provider, &scan)
            .await
            .expect("scan write should succeed");

        let after = stored_config(&state).await;
        let healthy = healthy_ips(&after);
        assert_eq!(
            healthy.len(),
            verified.len(),
            "扫描写回把复验刚写入的健康池覆盖回了旧值：{healthy:?}"
        );
        let after_health = OpenCodeHealthConfig::from_provider_config(&Some(after.clone()));
        assert_eq!(after_health.last_verify_kept, verified.len() as u64);
        // 扫描自己的产出仍然要落进去，不能因为修了覆盖就不写了。
        let after_scan = OpenCodeScanConfig::from_provider_config(&Some(after));
        assert_eq!(after_scan.candidates.len(), verified.len());
    }

    /// 任务运行期间用户在界面上改的配置不能被任务的收尾写回吞掉。
    ///
    /// 扫描最长 50 分钟、复验约 3 分钟，这段时间里完全可能改会话粘性
    /// 或验健康阈值。旧实现用陈旧快照整行写回，这些修改会被静默还原。
    #[tokio::test]
    async fn pool_task_write_preserves_a_concurrent_admin_config_change() {
        let initial = json!({
            "opencode_scan": { "candidates": ["198.51.100.1"], "cidrs": ["203.0.113.0/24"] },
            "opencode_health": { "healthy": ["198.51.100.1"], "session_sticky_enabled": false },
        });
        let stale_provider = pool_test_provider(initial);
        let state = pool_test_state(stale_provider.clone());

        // 用户在扫描跑着的时候把会话粘性打开了。
        let mut user_config = stale_provider
            .config
            .clone()
            .and_then(|config| config.as_object().cloned())
            .unwrap_or_default();
        user_config.insert(
            "opencode_health".to_string(),
            json!({ "healthy": ["198.51.100.1"], "session_sticky_enabled": true }),
        );
        let mut user_provider = stale_provider.clone();
        user_provider.config = Some(Value::Object(user_config));
        state
            .update_provider_catalog_provider(&user_provider)
            .await
            .expect("admin save should succeed");

        // 扫描随后收尾写回——必须带着用户的新值，而不是把它按旧快照盖回去。
        let mut scan = OpenCodeScanConfig::from_provider_config(&stale_provider.config);
        scan.candidates = vec!["198.51.100.1".to_string(), "198.51.100.2".to_string()];
        write_scan_config(&state, &stale_provider, &scan)
            .await
            .expect("scan write should succeed");

        let after = stored_config(&state).await;
        let after_health = OpenCodeHealthConfig::from_provider_config(&Some(after));
        assert!(
            after_health.session_sticky_enabled,
            "扫描收尾把用户在任务期间打开的会话粘性覆盖回了关闭"
        );
    }

    /// 扫描任务只拥有池内容字段，网段/间隔/并发这些是用户的设置。
    #[test]
    fn scan_section_merge_keeps_user_owned_settings() {
        let mut produced = OpenCodeScanConfig::default();
        produced.cidrs = vec!["203.0.113.0/24".to_string()];
        produced.interval_hours = Some(6);
        produced.candidates = vec!["198.51.100.9".to_string()];

        let mut config_map = json!({
            "opencode_scan": {
                // 用户在任务运行期间把网段换掉了，并关掉了自动扫描。
                "cidrs": ["198.18.0.0/15"],
                "interval_hours": 0,
                "auto_enabled": false,
                "cooldown_minutes": 90,
                "proxy_domain": "opencode.fanjinlong.top",
                "candidates": ["198.51.100.1"],
            },
            "opencode_health": { "healthy": ["198.51.100.1"] },
        })
        .as_object()
        .cloned()
        .expect("object");

        merge_scan_section_into(&mut config_map, &produced);
        let merged = OpenCodeScanConfig::from_provider_config(&Some(Value::Object(config_map)));

        // 任务产出的字段用任务的值。
        assert_eq!(merged.candidates, vec!["198.51.100.9".to_string()]);
        // 用户设置的字段保持用户最新的值，不能被任务开始时的旧值盖回去。
        assert_eq!(merged.cidrs, vec!["198.18.0.0/15".to_string()]);
        assert_eq!(merged.interval_hours, Some(0));
        assert!(!merged.auto_enabled);
        assert_eq!(merged.cooldown_minutes, Some(90));
        assert_eq!(
            merged.proxy_domain.as_deref(),
            Some("opencode.fanjinlong.top")
        );
    }

    /// 段还不存在时退回整段写入：此时没有「用户的值」需要保留。
    #[test]
    fn scan_section_merge_falls_back_to_full_section_when_absent() {
        let mut produced = OpenCodeScanConfig::default();
        produced.cidrs = vec!["203.0.113.0/24".to_string()];
        produced.candidates = vec!["198.51.100.9".to_string()];

        let mut config_map = serde_json::Map::new();
        merge_scan_section_into(&mut config_map, &produced);
        let merged = OpenCodeScanConfig::from_provider_config(&Some(Value::Object(config_map)));

        assert_eq!(merged.cidrs, vec!["203.0.113.0/24".to_string()]);
        assert_eq!(merged.candidates, vec!["198.51.100.9".to_string()]);
    }

    /// 保存接口也不能把后台任务刚写的结果按旧值盖回去。
    ///
    /// 这是同一个 bug 的另一条路径：旧实现是「请求开始时读一次 → 合并 → 整行
    /// 写回」，没有 CAS。任务侧改成 CAS 之后方向反而是反的——任务撞上保存会
    /// CAS 失败重试（安全），保存撞上任务则静默覆盖（不安全）。窗口只有几十
    /// 毫秒，但命中的症状和线上那次事故一模一样：摘要 kept=337，池子还是 65。
    #[tokio::test]
    async fn pool_config_pair_write_keeps_a_concurrent_task_result() {
        let initial = json!({
            "opencode_scan": { "candidates": ["198.51.100.1"], "cidrs": ["203.0.113.0/24"] },
            "opencode_health": { "healthy": ["198.51.100.1"], "session_sticky_enabled": false },
        });
        let stale_provider = pool_test_provider(initial);
        let state = pool_test_state(stale_provider.clone());

        // 复验先提交：健康池从 1 个变成 337 个。
        let verified: Vec<String> = (0..337)
            .map(|i| format!("198.51.100.{}", i % 200))
            .collect();
        let mut health = OpenCodeHealthConfig::from_provider_config(&stale_provider.config);
        health.healthy = verified.clone();
        write_health_config(&state, &stale_provider, &health)
            .await
            .expect("verify write should succeed");

        // 保存接口随后到达，请求体只带会话粘性这一个开关（面板就是这么发的）。
        // 它绝不能把 healthy 退回读取快照时的 1 个。
        let payload = json!({
            "opencode_health": { "session_sticky_enabled": true },
        })
        .as_object()
        .cloned()
        .expect("payload should be an object");
        let outcome = write_pool_config_pair(&state, POOL_TEST_PROVIDER_ID, |latest| {
            let scan = OpenCodeScanConfig::merged_with_payload(latest, &payload);
            let health = OpenCodeHealthConfig::merged_with_payload(latest, &payload);
            Ok((
                scan.to_provider_config_value(),
                health.to_provider_config_value(),
            ))
        })
        .await
        .expect("save write should not error");

        assert!(
            matches!(outcome, PoolConfigWriteOutcome::Saved),
            "保存应成功落地，实际 {outcome:?}"
        );
        let after = stored_config(&state).await;
        let after_health = OpenCodeHealthConfig::from_provider_config(&Some(after));
        assert_eq!(
            after_health.healthy.len(),
            verified.len(),
            "保存把复验刚写入的健康池覆盖回了读取快照时的旧值"
        );
        // 用户这次真正想改的那个开关也必须生效。
        assert!(after_health.session_sticky_enabled);
    }

    /// 两段要一起提交：不能因为只改了一段就把另一段留在旧值上。
    #[tokio::test]
    async fn pool_config_pair_write_commits_both_sections_together() {
        let initial = json!({
            "opencode_scan": { "candidates": ["198.51.100.1"], "cidrs": ["203.0.113.0/24"] },
            "opencode_health": { "healthy": ["198.51.100.1"] },
        });
        let stale_provider = pool_test_provider(initial);
        let state = pool_test_state(stale_provider.clone());

        let payload = json!({
            "cidrs": ["198.18.0.0/15"],
            "opencode_health": { "min_pool_size": 7 },
        })
        .as_object()
        .cloned()
        .expect("payload should be an object");
        write_pool_config_pair(&state, POOL_TEST_PROVIDER_ID, |latest| {
            let scan = OpenCodeScanConfig::merged_with_payload(latest, &payload);
            let health = OpenCodeHealthConfig::merged_with_payload(latest, &payload);
            Ok((
                scan.to_provider_config_value(),
                health.to_provider_config_value(),
            ))
        })
        .await
        .expect("save write should not error");

        let after = stored_config(&state).await;
        let scan = OpenCodeScanConfig::from_provider_config(&Some(after.clone()));
        let health = OpenCodeHealthConfig::from_provider_config(&Some(after));
        assert_eq!(scan.cidrs, vec!["198.18.0.0/15".to_string()]);
        assert_eq!(health.min_pool_size, Some(7));
    }

    /// 字段越界要在写盘之前被拦下，并且带上指明是哪个字段的信息。
    #[tokio::test]
    async fn pool_config_pair_write_rejects_invalid_cidr_without_touching_storage() {
        let initial = json!({
            "opencode_scan": { "candidates": ["198.51.100.1"], "cidrs": ["203.0.113.0/24"] },
            "opencode_health": { "healthy": ["198.51.100.1"] },
        });
        let stale_provider = pool_test_provider(initial);
        let state = pool_test_state(stale_provider.clone());

        let payload = json!({ "cidrs": ["198.18.0.0/15", "not-an-ip/24"] })
            .as_object()
            .cloned()
            .expect("payload should be an object");
        let outcome = write_pool_config_pair(&state, POOL_TEST_PROVIDER_ID, |latest| {
            let scan = OpenCodeScanConfig::merged_with_payload(latest, &payload);
            for cidr in &scan.cidrs {
                if parse_cidr(cidr).is_none() {
                    return Err(format!("无效的 CIDR: {cidr}"));
                }
            }
            let health = OpenCodeHealthConfig::merged_with_payload(latest, &payload);
            Ok((
                scan.to_provider_config_value(),
                health.to_provider_config_value(),
            ))
        })
        .await
        .expect("validation failure is an outcome, not an error");

        match outcome {
            PoolConfigWriteOutcome::Invalid(detail) => {
                assert!(
                    detail.contains("not-an-ip/24"),
                    "报错要指到写错的那一项：{detail}"
                );
            }
            other => panic!("越界 CIDR 应被判为 Invalid，实际 {other:?}"),
        }
        // 没落盘：网段还是原来的。
        let after = stored_config(&state).await;
        let scan = OpenCodeScanConfig::from_provider_config(&Some(after));
        assert_eq!(scan.cidrs, vec!["203.0.113.0/24".to_string()]);
    }

    #[test]
    fn cidr_parsing_handles_valid_and_invalid_input() {
        let Some((network, bits)) = parse_cidr("203.0.113.192/26") else {
            panic!("valid cidr should parse");
        };
        assert_eq!(bits, 26);
        // 期望值必须与输入同一个网段。原来这里写的是 111.4.225.192
        // （另一个网段，明显是从别处复制过来的），于是这个断言永远失败，
        // 而它失败时唯一的结论是「parse_cidr 有问题」——会让人去查一个
        // 根本没坏的函数。/26 掩掉低 6 位，192 低 6 位本就是 0，
        // 所以结果仍应是 203.0.113.192。
        assert_eq!(
            network,
            u32::from(std::net::Ipv4Addr::new(203, 0, 113, 192))
        );
        // 真正需要掩码的情况：/24 会把主机位清掉。
        assert_eq!(
            parse_cidr("203.0.113.192/24").map(|(network, _)| network),
            Some(u32::from(std::net::Ipv4Addr::new(203, 0, 113, 0)))
        );
        assert_eq!(parse_cidr("not-an-ip/24"), None);
        assert_eq!(parse_cidr("1.2.3.4/33"), None);
        assert_eq!(parse_cidr("1.2.3.4"), None);
        assert_eq!(parse_cidr("1.2.3.4/0"), None);
    }

    #[test]
    fn candidate_ips_skip_network_broadcast_and_known() {
        let config = OpenCodeScanConfig {
            cidrs: vec!["192.168.1.0/29".to_string()],
            ..OpenCodeScanConfig::default()
        };
        let known: BTreeSet<String> = ["192.168.1.2".to_string()].into_iter().collect();
        let candidates = config.candidate_ips(&known);
        assert_eq!(
            candidates,
            vec![
                "192.168.1.1".to_string(),
                "192.168.1.3".to_string(),
                "192.168.1.4".to_string(),
                "192.168.1.5".to_string(),
                "192.168.1.6".to_string(),
            ]
        );
    }

    #[test]
    fn empty_cidr_config_yields_no_candidates() {
        assert!(OpenCodeScanConfig::default()
            .candidate_ips(&BTreeSet::new())
            .is_empty());
    }

    #[test]
    fn config_reads_opencode_scan_section() {
        let config = OpenCodeScanConfig::from_provider_config_object(
            json!({ "opencode_scan": { "cidrs": ["203.0.113.192/26"], "concurrency": 8 } })
                .as_object()
                .expect("object"),
        );
        assert_eq!(config.cidrs, vec!["203.0.113.192/26".to_string()]);
        assert_eq!(config.effective_concurrency(), 8);
    }

    #[test]
    fn config_reads_bare_section() {
        let config = OpenCodeScanConfig::from_provider_config_object(
            json!({ "cidrs": ["93.184.216.45.0/24"], "concurrency": 999 })
                .as_object()
                .expect("object"),
        );
        assert_eq!(config.cidrs, vec!["93.184.216.45.0/24".to_string()]);
        assert_eq!(
            config.effective_concurrency(),
            OPENCODE_SCAN_MAX_CONCURRENCY
        );
    }

    #[test]
    fn concurrency_defaults_and_clamps() {
        assert_eq!(
            OpenCodeScanConfig::default().effective_concurrency(),
            OPENCODE_SCAN_DEFAULT_CONCURRENCY
        );
        assert_eq!(
            OpenCodeScanConfig {
                cidrs: Vec::new(),
                interval_hours: None,
                concurrency: Some(0),
                ..OpenCodeScanConfig::default()
            }
            .effective_concurrency(),
            1
        );
    }

    #[test]
    fn scan_validation_bounds_the_new_tunables() {
        // 单轮上限：0 与超过硬上限都要挡。
        for value in [json!(0), json!(OPENCODE_SCAN_MAX_CANDIDATES_LIMIT + 1)] {
            let section = health_section(json!({ "max_candidates_per_round": value }));
            let err = OpenCodeScanConfig::validate_section(&section).expect_err("越界必须被拒绝");
            assert!(
                err.contains("max_candidates_per_round"),
                "报错要指名字段：{err}"
            );
        }
        // 阈值：低于下限（会把整池判空）与超过上限都要挡。
        for value in [
            json!(OPENCODE_PROBE_MIN_HANDSHAKE_MS - 1),
            json!(OPENCODE_PROBE_MAX_HANDSHAKE_MS_LIMIT + 1),
        ] {
            let section = health_section(json!({ "probe_max_handshake_ms": value }));
            let err = OpenCodeScanConfig::validate_section(&section).expect_err("越界必须被拒绝");
            assert!(
                err.contains("probe_max_handshake_ms"),
                "报错要指名字段：{err}"
            );
        }
        // 边界值放行：合法的生产配置不能被误拒。
        let high = health_section(json!({
            "max_candidates_per_round": OPENCODE_SCAN_MAX_CANDIDATES_LIMIT,
            "probe_max_handshake_ms": OPENCODE_PROBE_MAX_HANDSHAKE_MS_LIMIT
        }));
        assert_eq!(OpenCodeScanConfig::validate_section(&high), Ok(()));
        let low = health_section(json!({
            "max_candidates_per_round": 1,
            "probe_max_handshake_ms": OPENCODE_PROBE_MIN_HANDSHAKE_MS
        }));
        assert_eq!(OpenCodeScanConfig::validate_section(&low), Ok(()));
    }

    /// 429 换点的段预算：0 段 / 0 毫秒会让「优先换段」失去意义，必须挡住；
    /// 硬上限与 `opencode_rotation` 里的常量保持同一口径。
    #[test]
    fn scan_validation_bounds_the_429_segment_budget() {
        for (field, value) in [
            (
                crate::opencode_rotation::OPENCODE_SEGMENT_BUDGET_SEGMENTS_FIELD,
                json!(0),
            ),
            (
                crate::opencode_rotation::OPENCODE_SEGMENT_BUDGET_SEGMENTS_FIELD,
                json!(crate::opencode_rotation::MAX_OPENCODE_SEGMENT_BUDGET + 1),
            ),
            (
                crate::opencode_rotation::OPENCODE_SEGMENT_BUDGET_MS_FIELD,
                json!(0),
            ),
            (
                crate::opencode_rotation::OPENCODE_SEGMENT_BUDGET_MS_FIELD,
                json!(crate::opencode_rotation::MAX_OPENCODE_SEGMENT_BUDGET_MS + 1),
            ),
            (
                crate::opencode_rotation::OPENCODE_SEGMENT_BUDGET_ENABLED_FIELD,
                json!("yes"),
            ),
        ] {
            let mut payload = serde_json::Map::new();
            payload.insert(field.to_string(), value);
            let section = health_section(Value::Object(payload));
            let err = OpenCodeScanConfig::validate_section(&section).expect_err("越界必须被拒绝");
            assert!(err.contains(field), "报错要指名字段：{err}");
        }
        // 默认值与按默认值配置的生产形态都要放行。
        let ok = health_section(json!({
            "segment_budget_enabled": true,
            "segment_budget_segments": crate::opencode_rotation::OPENCODE_DEFAULT_SEGMENT_BUDGET,
            "segment_budget_ms": crate::opencode_rotation::OPENCODE_DEFAULT_SEGMENT_BUDGET_MS,
        }));
        assert_eq!(OpenCodeScanConfig::validate_section(&ok), Ok(()));
    }

    /// 429 / 配额型 403 的延迟重试（`quota_retry_*`）：0 值必须挡住，
    /// 上限与 `opencode_rotation` 里的常量同口径。
    #[test]
    fn scan_validation_bounds_the_429_quota_retry_policy() {
        for (field, value) in [
            (
                crate::opencode_rotation::OPENCODE_QUOTA_RETRY_BASE_MS_FIELD,
                json!(0),
            ),
            (
                crate::opencode_rotation::OPENCODE_QUOTA_RETRY_BASE_MS_FIELD,
                json!(crate::opencode_rotation::MAX_OPENCODE_QUOTA_RETRY_DELAY_MS + 1),
            ),
            (
                crate::opencode_rotation::OPENCODE_QUOTA_RETRY_MAX_MS_FIELD,
                json!(0),
            ),
            (
                crate::opencode_rotation::OPENCODE_QUOTA_RETRY_MULTIPLIER_FIELD,
                json!(0),
            ),
            (
                crate::opencode_rotation::OPENCODE_QUOTA_RETRY_MULTIPLIER_FIELD,
                json!(crate::opencode_rotation::MAX_OPENCODE_QUOTA_RETRY_MULTIPLIER + 1),
            ),
            (
                crate::opencode_rotation::OPENCODE_QUOTA_RETRY_MAX_ATTEMPTS_FIELD,
                json!(0),
            ),
            (
                crate::opencode_rotation::OPENCODE_QUOTA_RETRY_MAX_ATTEMPTS_FIELD,
                json!(crate::opencode_rotation::MAX_OPENCODE_QUOTA_RETRY_ATTEMPTS + 1),
            ),
            (
                crate::opencode_rotation::OPENCODE_QUOTA_RETRY_ENABLED_FIELD,
                json!("yes"),
            ),
        ] {
            let mut payload = serde_json::Map::new();
            payload.insert(field.to_string(), value);
            let section = health_section(Value::Object(payload));
            let err = OpenCodeScanConfig::validate_section(&section).expect_err("越界必须被拒绝");
            assert!(err.contains(field), "报错要指名字段：{err}");
        }
        // 默认值与按默认值配置的生产形态都要放行。
        let ok = health_section(json!({
            "quota_retry_enabled": true,
            "quota_retry_base_ms": crate::opencode_rotation::DEFAULT_OPENCODE_QUOTA_RETRY_BASE_MS,
            "quota_retry_multiplier": crate::opencode_rotation::DEFAULT_OPENCODE_QUOTA_RETRY_MULTIPLIER,
            "quota_retry_max_ms": crate::opencode_rotation::DEFAULT_OPENCODE_QUOTA_RETRY_MAX_MS,
            "quota_retry_max_attempts": crate::opencode_rotation::DEFAULT_OPENCODE_QUOTA_RETRY_MAX_ATTEMPTS,
        }));
        assert_eq!(OpenCodeScanConfig::validate_section(&ok), Ok(()));
    }

    #[test]
    fn scan_config_round_trips_the_new_tunables() {
        let source = json!({
            "opencode_scan": {
                "cidrs": ["203.0.113.0/24"],
                "max_candidates_per_round": 512,
                "probe_max_handshake_ms": 1500
            }
        });
        let config = OpenCodeScanConfig::from_provider_config(&Some(source));
        assert_eq!(config.effective_max_candidates_per_round(), 512);
        assert_eq!(config.effective_probe_max_handshake_ms(), 1500);
        let written = config.to_provider_config_value();
        assert_eq!(written["max_candidates_per_round"], json!(512));
        assert_eq!(written["probe_max_handshake_ms"], json!(1500));
        // 部分更新：请求体里没提这两个键时不能被重置。
        let merged = OpenCodeScanConfig::merged_with_payload(
            &Some(config.to_provider_config_value()),
            json!({ "proxy_domain": "cdn.example.com" })
                .as_object()
                .expect("object"),
        );
        assert_eq!(merged.effective_max_candidates_per_round(), 512);
        assert_eq!(merged.effective_probe_max_handshake_ms(), 1500);
    }

    #[test]
    fn probe_threshold_defaults_clamp_and_report_their_source() {
        // 未配置 -> 跟随环境变量/代码默认。这里不改进程环境，只比对同一个函数。
        let default_config = OpenCodeScanConfig::default();
        let expected = (probe_max_round_trip_ms() as u64).clamp(
            OPENCODE_PROBE_MIN_HANDSHAKE_MS,
            OPENCODE_PROBE_MAX_HANDSHAKE_MS_LIMIT,
        );
        assert_eq!(default_config.effective_probe_max_handshake_ms(), expected);
        let expected_source = if std::env::var(OPENCODE_PROBE_MAX_HANDSHAKE_ENV).is_ok() {
            "env"
        } else {
            "default"
        };
        assert_eq!(default_config.probe_max_handshake_source(), expected_source);
        // 配置了就以配置为准，来源标记为 config。
        let configured = OpenCodeScanConfig {
            probe_max_handshake_ms: Some(1500),
            ..OpenCodeScanConfig::default()
        };
        assert_eq!(configured.effective_probe_max_handshake_ms(), 1500);
        assert_eq!(configured.probe_max_handshake_source(), "config");
        // 防御性 clamp：即使绕过校验塞进越界值，生效值也不会失控。
        let too_small = OpenCodeScanConfig {
            probe_max_handshake_ms: Some(1),
            ..OpenCodeScanConfig::default()
        };
        assert_eq!(
            too_small.effective_probe_max_handshake_ms(),
            OPENCODE_PROBE_MIN_HANDSHAKE_MS
        );
        let too_large = OpenCodeScanConfig {
            probe_max_handshake_ms: Some(u64::MAX),
            ..OpenCodeScanConfig::default()
        };
        assert_eq!(
            too_large.effective_probe_max_handshake_ms(),
            OPENCODE_PROBE_MAX_HANDSHAKE_MS_LIMIT
        );
        let round_zero = OpenCodeScanConfig {
            max_candidates_per_round: Some(0),
            ..OpenCodeScanConfig::default()
        };
        assert_eq!(round_zero.effective_max_candidates_per_round(), 1);
        let round_huge = OpenCodeScanConfig {
            max_candidates_per_round: Some(usize::MAX),
            ..OpenCodeScanConfig::default()
        };
        assert_eq!(
            round_huge.effective_max_candidates_per_round(),
            OPENCODE_SCAN_MAX_CANDIDATES_LIMIT
        );
    }

    #[test]
    fn scan_cursor_ttl_covers_the_whole_sweep() {
        // 48h 间隔 + 每轮 100 个：250 个候选 = 3 轮，TTL 要覆盖 3×48h 再留 2 倍余量。
        let config = OpenCodeScanConfig {
            interval_hours: Some(48),
            max_candidates_per_round: Some(100),
            ..OpenCodeScanConfig::default()
        };
        assert_eq!(config.scan_cursor_ttl_seconds(250), 48 * 3600 * 3 * 2);
        assert_eq!(config.scan_cursor_ttl_seconds(200), 48 * 3600 * 2 * 2);
        // 一轮就够时取下限（7 天），不能比"跨天手动补扫"还短。
        assert_eq!(
            config.scan_cursor_ttl_seconds(50),
            OPENCODE_SCAN_CURSOR_MIN_TTL_SECONDS
        );
        // 只手动扫（间隔 0）同样有下限。
        let manual = OpenCodeScanConfig {
            interval_hours: Some(0),
            max_candidates_per_round: Some(100),
            ..OpenCodeScanConfig::default()
        };
        assert_eq!(
            manual.scan_cursor_ttl_seconds(250),
            OPENCODE_SCAN_CURSOR_MIN_TTL_SECONDS
        );
        // 默认配置下扫一个 /24：TTL 必须能活过下一次 48h 自动扫描。
        let default_like = OpenCodeScanConfig {
            interval_hours: Some(48),
            ..OpenCodeScanConfig::default()
        };
        assert_eq!(
            default_like.scan_cursor_ttl_seconds(254),
            OPENCODE_SCAN_CURSOR_MIN_TTL_SECONDS
        );
    }

    #[test]
    fn pool_key_ip_reads_upstream_metadata() {
        let key = StoredProviderCatalogKey::new(
            "k1".to_string(),
            "p1".to_string(),
            "CDN IP 1.2.3.4".to_string(),
            "api_key".to_string(),
            None,
            true,
        )
        .expect("key");
        assert_eq!(opencode_pool_key_ip(&key), None);
        let mut with_meta = key.clone();
        with_meta.upstream_metadata = Some(json!({ "opencode_exit_ip": "1.2.3.4" }));
        assert_eq!(
            opencode_pool_key_ip(&with_meta),
            Some("1.2.3.4".to_string())
        );
        let mut invalid = key;
        invalid.upstream_metadata = Some(json!({ "opencode_exit_ip": "999.1.1.1" }));
        assert_eq!(opencode_pool_key_ip(&invalid), None);
    }

    fn health_section(value: Value) -> serde_json::Map<String, Value> {
        value.as_object().cloned().expect("object")
    }

    #[test]
    fn health_validation_accepts_the_production_configuration() {
        // 生产当前值，任何一个被误拒都等于把线上配置锁死。
        let section = health_section(json!({
            "auto_verify_enabled": true,
            "verify_interval_hours": 3,
            "verify_max_median_ms": 10_000,
            "min_pool_size": 5,
            "session_sticky_enabled": true,
        }));
        assert_eq!(OpenCodeHealthConfig::validate_section(&section), Ok(()));
    }

    #[test]
    fn health_validation_rejects_an_absurd_min_pool_size() {
        // 线上实测过的值：原样落库且返回 saved:true，淘汰机制随之失效。
        let section = health_section(json!({ "min_pool_size": 999_999_999u64 }));
        let err =
            OpenCodeHealthConfig::validate_section(&section).expect_err("越界的保底线必须被拒绝");
        assert!(err.contains("min_pool_size"), "报错要指名字段：{err}");
        assert!(err.contains("512"), "报错要给出上界：{err}");
    }

    #[test]
    fn health_validation_rejects_negative_and_zero_counts() {
        // 这两个原先都被静默丢弃：请求体里有键，但读出来是 None，
        // 于是沿用旧值，响应照样是 saved:true。
        for value in [json!(-1), json!(0)] {
            let section = health_section(json!({ "min_pool_size": value }));
            assert!(
                OpenCodeHealthConfig::validate_section(&section).is_err(),
                "min_pool_size={value} 必须被拒绝"
            );
        }
        for field in ["verify_samples", "verify_max_median_ms"] {
            let section = health_section(json!({ field: 0 }));
            assert!(
                OpenCodeHealthConfig::validate_section(&section).is_err(),
                "{field}=0 必须被拒绝"
            );
        }
    }

    #[test]
    fn health_validation_allows_a_zero_verify_interval() {
        // 间隔 0 是有语义的取值：开关开着但永不自动执行，不能当成非法。
        let section = health_section(json!({ "verify_interval_hours": 0 }));
        assert_eq!(OpenCodeHealthConfig::validate_section(&section), Ok(()));
    }

    #[test]
    fn health_validation_rejects_wrongly_typed_values() {
        // 字符串 / 浮点 / null 都会让 `as_u64` 返回 None 而被静默忽略。
        for value in [json!("5"), json!(2.5), json!(null), json!([])] {
            let section = health_section(json!({ "verify_samples": value.clone() }));
            assert!(
                OpenCodeHealthConfig::validate_section(&section).is_err(),
                "verify_samples={value} 必须被拒绝"
            );
        }
        let section = health_section(json!({ "auto_verify_enabled": "true" }));
        assert!(OpenCodeHealthConfig::validate_section(&section).is_err());
    }

    #[test]
    fn health_validation_caps_verify_samples() {
        let section = health_section(json!({
            "verify_samples": OPENCODE_MAX_VERIFY_SAMPLES + 1
        }));
        assert!(OpenCodeHealthConfig::validate_section(&section).is_err());
        let ok = health_section(json!({ "verify_samples": OPENCODE_MAX_VERIFY_SAMPLES }));
        assert_eq!(OpenCodeHealthConfig::validate_section(&ok), Ok(()));
    }

    #[test]
    fn scan_validation_rejects_values_that_would_be_truncated() {
        // 超过 u32::MAX 的间隔在读取时被 `as u32` 截断成一个看似合理的
        // 数字，必须在入口挡住。
        let section = health_section(json!({ "interval_hours": 5_000_000_000u64 }));
        let err = OpenCodeScanConfig::validate_section(&section).expect_err("超大的间隔必须被拒绝");
        assert!(err.contains("interval_hours"), "报错要指名字段：{err}");
    }

    #[test]
    fn scan_validation_rejects_out_of_range_concurrency_and_cooldown() {
        for (field, value) in [
            ("concurrency", json!(0)),
            ("concurrency", json!(OPENCODE_SCAN_MAX_CONCURRENCY + 1)),
            ("cooldown_minutes", json!(0)),
        ] {
            let section = health_section(json!({ field: value.clone() }));
            assert!(
                OpenCodeScanConfig::validate_section(&section).is_err(),
                "{field}={value} 必须被拒绝"
            );
        }
        let section = health_section(json!({
            "concurrency": OPENCODE_SCAN_MAX_CONCURRENCY,
            "cooldown_minutes": 60,
            "interval_hours": 6
        }));
        assert_eq!(OpenCodeScanConfig::validate_section(&section), Ok(()));
    }

    #[test]
    fn scan_validation_ignores_fields_it_does_not_own() {
        // 验健康的键出现在扁平请求体里时不能被扫描段误判。
        let section = health_section(json!({
            "cidrs": ["1.2.3.0/24"],
            "auto_verify_enabled": true,
            "proxy_domain": "cdn.example.com"
        }));
        assert_eq!(OpenCodeScanConfig::validate_section(&section), Ok(()));
    }

    #[test]
    fn verify_summary_survives_a_config_round_trip() {
        // 摘要必须跟着 config 落盘，否则进程重启后界面显示「上次复验：无」
        // 却又列着一整屏 latencies。
        let config = json!({
            "opencode_health": {
                "healthy": ["1.2.3.4"],
                "last_verify_at": "2026-09-29T00:31:00+00:00",
                "last_verify_checked": 195,
                "last_verify_kept": 65,
                "last_verify_dropped": 130
            }
        });
        let health = OpenCodeHealthConfig::from_provider_config(&Some(config));
        assert_eq!(
            health.last_verify_at.as_deref(),
            Some("2026-09-29T00:31:00+00:00")
        );
        assert_eq!(health.last_verify_checked, 195);
        assert_eq!(health.last_verify_kept, 65);
        assert_eq!(health.last_verify_dropped, 130);

        let written = health.to_provider_config_value();
        let reread = OpenCodeHealthConfig::from_provider_config(&Some(json!({
            "opencode_health": written
        })));
        assert_eq!(reread.last_verify_at, health.last_verify_at);
        assert_eq!(reread.last_verify_checked, health.last_verify_checked);
        assert_eq!(reread.last_verify_kept, health.last_verify_kept);
        assert_eq!(reread.last_verify_dropped, health.last_verify_dropped);
    }

    #[test]
    fn saving_other_settings_preserves_the_verify_summary() {
        // PUT 是部分更新：改保底池大小不该把上次复验的摘要抹掉。
        let existing = json!({
            "opencode_health": {
                "min_pool_size": 5,
                "last_verify_at": "2026-09-29T00:31:00+00:00",
                "last_verify_checked": 195,
                "last_verify_kept": 65,
                "last_verify_dropped": 130
            }
        });
        let payload = json!({ "opencode_health": { "min_pool_size": 8 } })
            .as_object()
            .cloned()
            .expect("object");
        let merged = OpenCodeHealthConfig::merged_with_payload(&Some(existing), &payload);
        assert_eq!(merged.min_pool_size(), 8);
        assert_eq!(
            merged.last_verify_at.as_deref(),
            Some("2026-09-29T00:31:00+00:00")
        );
        assert_eq!(merged.last_verify_kept, 65);
    }

    #[test]
    fn a_provider_without_a_health_section_reports_no_verify_summary() {
        // 迁移前的老配置不能被当成「验过 0 个节点」。
        let health = OpenCodeHealthConfig::from_provider_config(&Some(json!({
            "opencode_scan": { "exit_pool": ["1.2.3.4"] }
        })));
        assert!(health.last_verify_at.is_none());
        assert_eq!(health.last_verify_checked, 0);
        assert_eq!(health.last_verify_kept, 0);
        assert_eq!(health.last_verify_dropped, 0);
    }

    #[test]
    fn healthy_status_line_recognises_2xx_and_3xx() {
        assert!(is_healthy_status_line(b"HTTP/1.1 200 OK"));
        assert!(is_healthy_status_line(b"HTTP/1.1 301 Moved"));
        assert!(!is_healthy_status_line(b"HTTP/1.1 403 Forbidden"));
        assert!(!is_healthy_status_line(b"garbage"));
    }

    #[test]
    fn status_map_is_per_provider() {
        update_opencode_ip_pool_status("pool-a", |status| status.scanning = true);
        assert!(opencode_ip_pool_status_for("pool-a").scanning);
        assert!(!opencode_ip_pool_status_for("pool-b").scanning);
        update_opencode_ip_pool_status("pool-a", |status| status.scanning = false);
    }
}

#[test]
fn scan_slice_starts_from_the_cursor_and_wraps_around() {
    let config = OpenCodeScanConfig::default();
    let candidates: Vec<String> = (0..10).map(|i| format!("10.0.0.{i}")).collect();
    // 从中间开始
    let (first, next) = config.scan_slice(&candidates, 4);
    assert_eq!(
        first,
        vec!["10.0.0.4", "10.0.0.5", "10.0.0.6", "10.0.0.7", "10.0.0.8", "10.0.0.9"]
    );
    assert_eq!(next, 0, "探到末尾后游标回绕");
    // 从 0 开始就是全部
    let (all, next) = config.scan_slice(&candidates, 0);
    assert_eq!(all.len(), 10);
    assert_eq!(next, 0);
}

#[test]
fn scan_slice_recovers_from_an_out_of_range_cursor() {
    let config = OpenCodeScanConfig::default();
    let candidates: Vec<String> = (0..3).map(|i| format!("10.0.0.{i}")).collect();
    // 网段被改小后旧游标越界，不能panic也不能漏
    let (picked, next) = config.scan_slice(&candidates, 99);
    assert_eq!(picked.len(), 3);
    assert_eq!(next, 0);
}

#[test]
fn scan_slice_on_empty_candidates_is_a_noop() {
    let config = OpenCodeScanConfig::default();
    assert_eq!(config.scan_slice(&[], 7), (Vec::new(), 0));
}

#[test]
fn scan_slice_caps_at_the_per_round_limit() {
    let config = OpenCodeScanConfig::default();
    let total = OPENCODE_SCAN_MAX_CANDIDATES + 500;
    let candidates: Vec<String> = (0..total)
        .map(|i| format!("10.0.{}.{}", i / 256, i % 256))
        .collect();
    let (first, next) = config.scan_slice(&candidates, 0);
    assert_eq!(first.len(), OPENCODE_SCAN_MAX_CANDIDATES);
    assert_eq!(
        next, OPENCODE_SCAN_MAX_CANDIDATES as u64,
        "游标要落到本轮结束处"
    );
    let (second, _) = config.scan_slice(&candidates, next);
    assert_eq!(second.len(), 500, "下一轮只探剩下的尾巴");
    assert_eq!(second[0], candidates[OPENCODE_SCAN_MAX_CANDIDATES]);
}

#[test]
fn scan_slice_honours_the_configured_per_round_limit() {
    let config = OpenCodeScanConfig {
        max_candidates_per_round: Some(10),
        ..OpenCodeScanConfig::default()
    };
    let candidates: Vec<String> = (0..25).map(|i| format!("10.0.0.{i}")).collect();
    let (first, next) = config.scan_slice(&candidates, 0);
    assert_eq!(first.len(), 10, "切片大小必须听配置，而不是写死的 4096");
    assert_eq!(next, 10);
    let (second, next2) = config.scan_slice(&candidates, next);
    assert_eq!(second.len(), 10);
    assert_eq!(next2, 20);
    let (third, next3) = config.scan_slice(&candidates, next2);
    assert_eq!(third.len(), 5, "最后一轮只探剩下的尾巴");
    // 游标回绕 0 才是「完整走完一轮」的信号，也只有这时才允许重建 candidates。
    assert_eq!(next3, 0);
}

/// 测试用：把 IP 字面量收成集合。
fn ip_set(ips: &[&str]) -> BTreeSet<String> {
    ips.iter().map(|ip| ip.to_string()).collect()
}

/// 测试用：把 IP 字面量收成列表。
fn ip_list(ips: &[&str]) -> Vec<String> {
    ips.iter().map(|ip| ip.to_string()).collect()
}

#[test]
fn round_completion_keeps_every_slice_not_just_the_last() {
    // 多切片轮：前面切片探到 a、b，本片探到 c，保护名单 d。
    // 修复前 `seen` 只是本片的局部变量，整表覆盖会把 a、b 一起抹掉。
    let merged = ip_set(&["a", "b", "c"]);
    let pinned = ip_list(&["d"]);
    let rebuilt = rebuild_candidates_on_round_completion(true, &merged, &pinned, false, false);
    assert_eq!(rebuilt, Some(ip_list(&["a", "b", "c", "d"])));
}

#[test]
fn round_completion_refuses_to_rebuild_when_the_seen_set_is_lost() {
    // 累积集合过期或被清（Redis 不可用）：整表替换会把前面切片探到的节点一起抹掉，
    // 所以必须放弃重建、保留旧候选。
    let merged = ip_set(&["c"]);
    let rebuilt = rebuild_candidates_on_round_completion(false, &merged, &[], false, false);
    assert!(rebuilt.is_none(), "累积集合丢了就不能做破坏性重建");
}

#[test]
fn round_completion_may_rebuild_when_the_whole_round_ran_in_one_call() {
    // 单切片轮：整轮都在这次调用里跑完，累积集合天然完整（`prior` 为空不代表丢失）。
    let merged = ip_set(&["c"]);
    let rebuilt = rebuild_candidates_on_round_completion(false, &merged, &[], true, false);
    assert_eq!(rebuilt, Some(ip_list(&["c"])));
}

#[test]
fn round_completion_with_empty_cidrs_rebuilds_to_pinned_only() {
    // 网段被清空：这一轮没有任何地址可探，结论确定——候选清到只剩保护名单。
    let merged = ip_set(&[]);
    let pinned = ip_list(&["p"]);
    let rebuilt = rebuild_candidates_on_round_completion(false, &merged, &pinned, false, true);
    assert_eq!(rebuilt, Some(ip_list(&["p"])));
}

#[test]
fn round_completion_dedupes_pinned_against_the_seen_set() {
    let merged = ip_set(&["a"]);
    let pinned = ip_list(&["a", "b"]);
    let rebuilt = rebuild_candidates_on_round_completion(true, &merged, &pinned, false, false);
    assert_eq!(rebuilt, Some(ip_list(&["a", "b"])));
}

/// 测试用：造一条异常池记录。
fn sample_abnormal(ip: &str, fails: u32) -> OpenCodeAbnormalIp {
    OpenCodeAbnormalIp {
        ip: ip.to_string(),
        since: "t0".to_string(),
        fails,
        reason: "unreachable".to_string(),
        median_ms: None,
    }
}

#[test]
fn abnormal_threshold_requires_two_failures() {
    // 单轮抖动不该丢节点：实测并发会把 p50 放大 3.9 倍，一次失败说明不了什么。
    assert!(!abnormal_reached_discard_threshold(1));
    assert!(abnormal_reached_discard_threshold(2));
    assert!(abnormal_reached_discard_threshold(3));
}

#[test]
fn soft_marks_switch_off_when_the_pool_is_small() {
    // 池小保护：池子小于保护线时，异常池与拉黑只记录、不参与选择。
    assert!(!soft_marks_active(4, 5));
    assert!(soft_marks_active(5, 5));
    assert!(soft_marks_active(9, 5));
    // 保护线写 0 时按 1 处理，避免「配置写 0」意外变成「标记全部失效」。
    assert!(soft_marks_active(1, 0));
    assert!(!soft_marks_active(0, 0));
}

#[test]
fn record_abnormal_accumulates_and_keeps_the_first_seen_time() {
    let mut health = OpenCodeHealthConfig::default();
    let first = health.record_abnormal("1.2.3.4", "too_slow", Some(12_000), "t1");
    assert_eq!(first, 1);
    assert_eq!(health.abnormal.len(), 1);
    assert_eq!(health.abnormal[0].since, "t1");
    // 第二轮：计数 +1、原因与延迟刷新，但 since 保持首次进入的时间。
    let second = health.record_abnormal("1.2.3.4", "unreachable", None, "t2");
    assert_eq!(second, 2);
    assert_eq!(health.abnormal.len(), 1);
    assert_eq!(health.abnormal[0].since, "t1");
    assert_eq!(health.abnormal[0].reason, "unreachable");
    assert_eq!(health.abnormal[0].median_ms, None);
    assert!(abnormal_reached_discard_threshold(second));
}

#[test]
fn clear_abnormal_zeroes_the_failure_count() {
    let mut health = OpenCodeHealthConfig::default();
    health.record_abnormal("1.2.3.4", "too_slow", Some(11_000), "t1");
    assert!(health.clear_abnormal("1.2.3.4"));
    assert!(health.abnormal.is_empty());
    // 复验通过后再次失败要从 1 重新开始，否则「通过一次」抵不掉旧账。
    let again = health.record_abnormal("1.2.3.4", "too_slow", None, "t3");
    assert_eq!(again, 1);
}

#[test]
fn abnormal_pool_is_capped_by_dropping_the_oldest() {
    let mut health = OpenCodeHealthConfig::default();
    for index in 0..(OPENCODE_ABNORMAL_MAX_ENTRIES + 5) {
        health.record_abnormal(&format!("10.0.0.{index}"), "too_slow", None, "t1");
    }
    assert_eq!(health.abnormal.len(), OPENCODE_ABNORMAL_MAX_ENTRIES);
    assert_eq!(health.abnormal[0].ip, "10.0.0.5".to_string());
}

#[test]
fn health_config_round_trips_the_three_states_and_drops_rejections() {
    let mut health = OpenCodeHealthConfig::default();
    health.abnormal.push(sample_abnormal("1.2.3.4", 2));
    health.blocked.push("5.6.7.8".to_string());
    let value = health.to_provider_config_value();
    // 旧的 rejections 字段不再写出：它没有消费者，留着只会让人以为它有用。
    assert!(value.get("rejections").is_none());
    let round_tripped =
        OpenCodeHealthConfig::from_provider_config(&Some(json!({ "opencode_health": value })));
    assert_eq!(round_tripped.abnormal, health.abnormal);
    assert_eq!(round_tripped.blocked, health.blocked);
}

#[test]
fn health_config_ignores_a_legacy_rejections_heading() {
    // 旧数据里残留的 rejections 键必须被安静忽略，而不是让整段配置读不出来。
    let health = OpenCodeHealthConfig::from_provider_config(&Some(json!({
        "opencode_health": {
            "healthy": ["1.2.3.4"],
            "rejections": { "5.6.7.8": { "reason": "unreachable" } }
        }
    })));
    assert_eq!(health.healthy, vec!["1.2.3.4".to_string()]);
    assert!(health.abnormal.is_empty());
    assert!(health.blocked.is_empty());
}

#[test]
fn blocked_and_abnormal_sets_are_trimmed_and_deduplicated() {
    let health = OpenCodeHealthConfig {
        blocked: vec![" 5.6.7.8 ".to_string(), "5.6.7.8".to_string()],
        abnormal: vec![sample_abnormal(" 1.2.3.4 ", 1)],
        ..OpenCodeHealthConfig::default()
    };
    assert!(health.is_blocked("5.6.7.8"));
    assert!(health.is_blocked(" 5.6.7.8 "));
    assert_eq!(health.blocked_ips().len(), 1);
    assert_eq!(health.abnormal_ips().len(), 1);
    assert!(health.abnormal_ips().contains("1.2.3.4"));
}

#[test]
fn protect_pool_floor_is_never_below_the_hard_floor() {
    let mut health = OpenCodeHealthConfig::default();
    assert_eq!(health.protect_pool_floor(), OPENCODE_PROTECT_POOL_FLOOR);
    health.min_pool_size = Some(12);
    assert_eq!(health.protect_pool_floor(), 12);
    // 保底线被人为调到 1 时，异常/拉黑的生效门槛仍不能被拉到 1：
    // 那等于让「立刻不用」在一个极小的池子里全部生效。
    health.min_pool_size = Some(1);
    assert_eq!(health.protect_pool_floor(), OPENCODE_PROTECT_POOL_FLOOR);
}

#[test]
fn reset_abnormal_clears_every_abnormal_entry() {
    let mut health = OpenCodeHealthConfig::default();
    health.abnormal.push(sample_abnormal("1.2.3.4", 2));
    health.abnormal.push(sample_abnormal("5.6.7.8", 1));
    // 人工拉黑不在这里的语义里：重置异常池不该顺手解禁。
    health.blocked.push("9.9.9.9".to_string());
    assert_eq!(health.reset_abnormal(), 2);
    assert!(health.abnormal.is_empty());
    assert_eq!(health.blocked, vec!["9.9.9.9".to_string()]);
}

/// 遗留的 `pool_mode` 字段必须被**忽略**且不再回写。
///
/// 这个开关已删除（key 只承担凭据，出口 IP 一律由 provider 级池决定）。但配置里
/// 可能残留过 `pool_mode`，所以两条一起保证：读配置不能因此报错，写配置不能再产出它。
/// 否则「删掉一个模式」会以一条历史字段的形式把供应商配置写坏。
#[test]
fn legacy_pool_mode_field_is_ignored_and_never_written_back() {
    let legacy = json!({
        "opencode_scan": { "pool_mode": "provider", "cidrs": ["203.0.113.0/24"] }
    });
    let parsed = OpenCodeScanConfig::from_provider_config(&Some(legacy.clone()));
    assert_eq!(parsed.cidrs, vec!["203.0.113.0/24".to_string()]);
    assert!(
        parsed.to_provider_config_value().get("pool_mode").is_none(),
        "配置回写不能再带 pool_mode：这个模式已经不存在了"
    );

    // 部分更新同理：请求体里带 pool_mode 也不能把它写进配置
    let payload = json!({ "pool_mode": "provider", "cidrs": ["198.51.100.0/24"] });
    let merged = OpenCodeScanConfig::merged_with_payload(
        &Some(legacy),
        payload.as_object().expect("payload 是对象"),
    );
    assert_eq!(merged.cidrs, vec!["198.51.100.0/24".to_string()]);
    assert!(merged.to_provider_config_value().get("pool_mode").is_none());
}

/// 已删除的丢弃留痕：老配置里残留的 `discarded_recent` 必须被忽略，且不再回写。
///
/// 丢弃现在是**事件**（一条可检索的日志），不是配置态。历史配置里可能还留着这份
/// 数组，所以两条一起保证：读它不能报错（否则整个 `opencode_health` 段读不出来，
/// 池会「凭空变空」），写它不能再产出（否则「删掉留痕」会一直挂在配置里）。
#[test]
fn legacy_discarded_recent_is_ignored_and_never_written_back() {
    let legacy = json!({
        "opencode_health": {
            "healthy": ["1.2.3.4"],
            "discarded_recent": [
                { "ip": "9.9.9.9", "at": "t1", "reason": "too_slow", "times": 3 }
            ]
        }
    });
    let parsed = OpenCodeHealthConfig::from_provider_config(&Some(legacy));
    assert_eq!(parsed.healthy, vec!["1.2.3.4".to_string()]);
    assert!(
        parsed
            .to_provider_config_value()
            .get("discarded_recent")
            .is_none(),
        "配置回写不能再带 discarded_recent：丢弃只写日志，不留配置态"
    );
}
