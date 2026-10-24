//! OpenCode 前置代理出口 IP 池扫描运行时。
//!
//! 与 MingLoong/Aether 参考实现的关键差异：**出口 IP 的唯一来源是 key 的
//! `upstream_metadata.opencode_exit_ip`**，而不是把 IP 明文塞进 `api_key`。
//! 池 key 的 `api_key` 只是一个唯一占位值（`public-<ip>`），因为 OpenCode 免费层
//! 认证固定为 `Bearer public`，由传输层强制注入。
//!
//! 扫描器从显式 CIDR 列表枚举候选 IP，对 `ip:port` 做裸 TLS 握手（SNI = 上游域名），
//! 再发一条带 OpenCode 指纹的 `GET /inference/v1/models`，2xx/3xx 视为健康；探通的 IP
//! 写进 `exit_pool` 立刻可用，失效节点由每 10 分钟的自动维护（失败计数 + 阈值）
//! 送进异常池并最终剔除——**没有**「一次性全池探测后失败即删」的清理轮次。

use std::collections::{BTreeMap, BTreeSet};
use std::io::{Read, Write};
use std::net::IpAddr;
use std::sync::{Arc, Mutex, OnceLock};

use aether_data_contracts::repository::provider_catalog::{
    ProviderCatalogProviderConfigCasUpdate, StoredProviderCatalogEndpoint,
    StoredProviderCatalogKey, StoredProviderCatalogProvider,
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
/// 中位数阈值的上限：10 分钟。再大就失去了「慢节点」的意义。
pub(crate) const OPENCODE_MAX_VERIFY_MAX_MEDIAN_MS: u64 = 600_000;
/// 复验间隔上限（小时）：一年。`0` 是合法值，表示不自动执行。
pub(crate) const OPENCODE_MAX_VERIFY_INTERVAL_HOURS: u32 = 8_760;

/// 异常池上限（条）。超出后从最旧的开始丢——异常池只表达「暂时不用」，
/// 不需要无限历史。
///
/// **必须大于池子规模。** 这个上限原来是 500，而 2026-10-23 的生产池有 1086 个
/// IP、每轮约 666 个不可达：超出部分每轮按「丢最旧」被裁掉，同一批 IP 于是在
/// 上限边缘反复进出，`fails` 永远停在 1，`maintenance_evict_failures = 3` 的
/// 剔除条件永远不成立——表现就是「维护在跑、异常在涨、池子一个也不减」。
/// 给到 4096 后仍有界（约 500 KB JSON），但足以容纳整池并完成多轮累计。
pub(crate) const OPENCODE_ABNORMAL_MAX_ENTRIES: usize = 4_096;
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
    /// 单次真实 chat 探测的耗时上限（毫秒）：超过它判「太慢」。
    ///
    /// 这是「验证健康」按钮唯一的阈值——后台维护 worker 用的零额度探针不看它
    /// （那边由 `maintenance_*` 四项控制）。
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
            "verify_max_median_ms",
            1,
            OPENCODE_MAX_VERIFY_MAX_MEDIAN_MS,
        )?;
        // 异常池过期天数：允许 0（永不过期），其余按天计。
        validate_bounded_uint(
            section,
            "abnormal_max_age_days",
            0,
            OPENCODE_MAX_ABNORMAL_MAX_AGE_DAYS as u64,
        )?;
        // 只剩一个布尔字段要校验，不再套循环：删掉自动复验后数组退化成了单元素，
        // Clippy 的 single_element_loop 会直接报错（CI 用 -D warnings）。
        validate_bool(section, "session_sticky_enabled")?;
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
    pub(crate) last_maintenance_at: Option<String>,
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
    /// 后台 CIDR 维护周期（秒），默认 600；与旧 interval_hours 独立。
    pub(crate) maintenance_interval_seconds: Option<u64>,
    /// 后台维护探测并发，默认 8。
    pub(crate) maintenance_concurrency: Option<usize>,
    /// 维护单轮失败熔断比例，默认 25%。
    pub(crate) maintenance_failure_threshold_percent: Option<u8>,
    /// 维护连续失败达到此次数后才剔除，默认 3。
    pub(crate) maintenance_evict_failures: Option<u32>,
    /// 轮转池跌破保底线时，是否自动按 CIDR / 前置域名补池，默认开。
    ///
    /// 没有它维护就只剔不补：池子会单调缩水到 0，然后所有请求退回系统 DNS
    /// 的单条路径，按 /24 分散失效（2026-10-24 提出的「靠 CIDR 维护」缺口）。
    pub(crate) maintenance_auto_refill: Option<bool>,
    /// 定期扫描间隔（秒），0 表示关闭，默认 0。
    ///
    /// 与 `maintenance_auto_refill` 的分工：补池是「跌破保底线才扫」的应急手段，
    /// 定期扫描是「按周期主动扩池」。默认关：扫描会打几千个目标，不该一上线就跑。
    pub(crate) scan_interval_seconds: Option<u64>,
    /// 扫描快筛阈值（毫秒）：连接 + TLS + 读到响应首行超过它判死。
    ///
    /// 未配置时回退全局环境变量 [`OPENCODE_PROBE_MAX_HANDSHAKE_ENV`]（默认
    /// [`OPENCODE_PROBE_MAX_HANDSHAKE_MS`]）。做成 provider 级配置，是因为实测
    /// 最优值与这台机器到 CDN 的基线延迟有关，全局一个值没法同时适配。
    pub(crate) probe_max_handshake_ms: Option<u64>,
    /// 是否启用「最少在途 + 游标轮转」选 key。
    pub(crate) rotation_enabled: bool,
    /// 配额型失败（`429` / 带额度文案的 `403`）给出口 IP 打的**固定**冷却时长（秒）。
    ///
    /// 默认 120，越界夹紧到 30–600（[`crate::opencode_rotation::MIN_OPENCODE_COOLDOWN_SECONDS`]
    /// ..=[`crate::opencode_rotation::MAX_OPENCODE_COOLDOWN_SECONDS`]）。上游的 `retry-after`
    /// 只在**更短**时被采纳，绝不因此延长——依据见
    /// [`crate::opencode_rotation::opencode_cooldown_ttl`]（2026-10-22 实测：那个头指的是
    /// 账户日额度刷新时间，而出口 IP 实际 2–3 分钟就恢复）。
    ///
    /// 历史上这个位置是 `cooldown_minutes`（默认 60 分钟，且会跟随 `retry-after` 放大），
    /// 已删除：读旧配置时该键被忽略，不会报错。
    pub(crate) cooldown_seconds: Option<u32>,
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
    ///
    /// 这是**生产列表的写入目标**：后台 CIDR 维护/手动扫描探通一个 IP 就直接写进
    /// 这里（IP 立刻可用，没有「候选 → 复验转正」的中间态）。轮转池 =
    /// `healthy`（历史复验转正，只读保留）∪ `exit_pool`，再剔除 `abnormal` / `blocked`。
    pub(crate) exit_pool: Vec<String>,
    /// provider 级池里被手动停用的 IP（不参与轮转，但仍保留在池中）。
    pub(crate) exit_pool_disabled: Vec<String>,
}

// 出口 IP 池只有**一个**模型：provider 级三态池（可用 → 异常 → 丢弃）。
// 扫描探针探通一个 IP 就直接写进 `exit_pool`（IP 立刻可用），因此历史上那层
// 「扫描产出候选 → 复验转正」的中间池已经删除：读旧配置里残留的 `candidates`
// 段时一律忽略，不会报错。
//
// 历史上还有一套「一 key 一 IP」的 `pool_mode` 开关，已删除。原因与迁移依据：
// - key 只承担**凭据**，出口 IP 一律由 provider 级池决定（`exit_pool` / `healthy`）；
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
    pub(crate) last_scan_at: Option<String>,
    pub(crate) last_maintenance_at: Option<String>,
    pub(crate) last_scan_at_unix_secs: Option<u64>,
    pub(crate) last_scan_targets: u64,
    pub(crate) last_scan_found: u64,
    pub(crate) last_scan_added: u64,
    /// 本轮长任务进度：已探 / 总数。大批量扫描要跑几十分钟，
    /// 没有这两个数面板上只会像卡死。
    pub(crate) progress_done: u64,
    pub(crate) progress_total: u64,
    pub(crate) progress_kind: Option<String>,
    /// 可用节点是否已跌破保底线（`healthy ≤ min_pool_size`）。
    ///
    /// 只用于**状态翻转时告警一次**：每个维护 tick 都打日志会刷屏，而跌破保底线
    /// 意味着池子已经很少、随时可能开始失败，必须有一条明确的告警。
    pub(crate) pool_low_alarm: bool,
    /// 分层计数：健康 / 实际在用。两个数放在一起才看得出停用了多少节点。
    pub(crate) healthy_count: u64,
    pub(crate) in_use_count: u64,
    pub(crate) degraded_count: u64,
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
        if let Some(Value::String(value)) = section.get("last_maintenance_at") {
            result.last_maintenance_at = Some(value.clone());
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
        if section.contains_key("maintenance_interval_seconds") {
            result.maintenance_interval_seconds = section
                .get("maintenance_interval_seconds")
                .and_then(Value::as_u64);
        }
        if section.contains_key("maintenance_concurrency") {
            result.maintenance_concurrency = section
                .get("maintenance_concurrency")
                .and_then(Value::as_u64)
                .map(|value| value as usize);
        }
        if section.contains_key("maintenance_failure_threshold_percent") {
            result.maintenance_failure_threshold_percent = section
                .get("maintenance_failure_threshold_percent")
                .and_then(Value::as_u64)
                .map(|value| value.min(100) as u8);
        }
        if section.contains_key("maintenance_evict_failures") {
            result.maintenance_evict_failures = section
                .get("maintenance_evict_failures")
                .and_then(Value::as_u64)
                .map(|value| value as u32);
        }
        if section.contains_key("maintenance_auto_refill") {
            result.maintenance_auto_refill = section
                .get("maintenance_auto_refill")
                .and_then(Value::as_bool);
        }
        if section.contains_key("scan_interval_seconds") {
            result.scan_interval_seconds =
                section.get("scan_interval_seconds").and_then(Value::as_u64);
        }
        if section.contains_key("probe_max_handshake_ms") {
            result.probe_max_handshake_ms = section
                .get("probe_max_handshake_ms")
                .and_then(Value::as_u64);
        }
        if let Some(Value::Bool(enabled)) = section.get("rotation_enabled") {
            result.rotation_enabled = *enabled;
        }
        if section.contains_key("cooldown_seconds") {
            result.cooldown_seconds = section
                .get("cooldown_seconds")
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
    /// `interval_hours` / `cooldown_seconds` 存的是 `u32`，读取时用
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
        // 配额型冷却（秒）：**越界夹紧而不是拒绝**（10 → 30、9999 → 600，见
        // `effective_cooldown_seconds`），所以这里只挡住会因 `as u32` 截断而变成
        // "看似合理"的数，不挡业务范围。
        validate_bounded_uint(section, "cooldown_seconds", 0, u64::from(u32::MAX))?;
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
        // 段内在途上限（`opencode_scan.segment_max_in_flight`）：0 会让「每个段都已满」、
        // 把选点直接打死，所以下限是 1；上限与 opencode_rotation 里的常量同口径。
        validate_bounded_uint(
            section,
            crate::opencode_rotation::OPENCODE_SEGMENT_MAX_IN_FLIGHT_FIELD,
            1,
            crate::opencode_rotation::MAX_OPENCODE_SEGMENT_MAX_IN_FLIGHT,
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
        if let Some(Value::String(value)) = section.get("last_maintenance_at") {
            result.last_maintenance_at = Some(value.clone());
        }
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
        result.maintenance_interval_seconds = section
            .get("maintenance_interval_seconds")
            .and_then(Value::as_u64);
        result.maintenance_concurrency = section
            .get("maintenance_concurrency")
            .and_then(Value::as_u64)
            .map(|value| value as usize);
        result.maintenance_failure_threshold_percent = section
            .get("maintenance_failure_threshold_percent")
            .and_then(Value::as_u64)
            .map(|value| value.min(100) as u8);
        result.maintenance_evict_failures = section
            .get("maintenance_evict_failures")
            .and_then(Value::as_u64)
            .map(|value| value as u32);
        if let Some(value) = section
            .get("maintenance_auto_refill")
            .and_then(Value::as_bool)
        {
            result.maintenance_auto_refill = Some(value);
        }
        result.scan_interval_seconds = section.get("scan_interval_seconds").and_then(Value::as_u64);
        if let Some(value) = section
            .get("probe_max_handshake_ms")
            .and_then(Value::as_u64)
        {
            result.probe_max_handshake_ms = Some(value);
        }
        if let Some(Value::Bool(enabled)) = section.get("rotation_enabled") {
            result.rotation_enabled = *enabled;
        }
        if let Some(value) = section.get("cooldown_seconds").and_then(Value::as_u64) {
            result.cooldown_seconds = Some(value as u32);
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
            "last_maintenance_at": self.last_maintenance_at,
            "pinned": self.pinned.clone(),
            "auto_enabled": self.auto_enabled,
            "interval_hours": self.interval_hours.unwrap_or(0),
            "concurrency": self.effective_concurrency(),
            "maintenance_interval_seconds": self.maintenance_interval_seconds(),
            "maintenance_concurrency": self.maintenance_concurrency(),
            "maintenance_failure_threshold_percent": self.maintenance_failure_threshold_percent(),
            "maintenance_evict_failures": self.maintenance_evict_failures(),
            "maintenance_auto_refill": self.maintenance_auto_refill(),
            "scan_interval_seconds": self.scan_interval_seconds(),
            "probe_max_handshake_ms": self.effective_probe_max_handshake_ms(),
            "rotation_enabled": self.rotation_enabled,
            "cooldown_seconds": self.effective_cooldown_seconds(),
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

    pub(crate) fn maintenance_interval_seconds(&self) -> u64 {
        self.maintenance_interval_seconds
            .unwrap_or(600)
            .clamp(30, 86_400)
    }

    pub(crate) fn maintenance_concurrency(&self) -> usize {
        // 默认 32：池子能长到一千多个 IP，一轮要探测全部；并发 8 时一轮十几分钟，
        // 比 600 秒的维护间隔还长，等于永远在追。
        self.maintenance_concurrency.unwrap_or(32).clamp(1, 64)
    }

    pub(crate) fn maintenance_failure_threshold_percent(&self) -> u8 {
        // 默认 90：这是「系统性故障」的判据（探针坏、域名配错、整网不通），
        // 不是「池子有多烂」的判据。2026-10-23 实测生产池只有 22% 的 IP
        // 真的服务这个域名，用 25% 当阈值会让清理永远不触发，死节点一直陪跑。
        self.maintenance_failure_threshold_percent
            .unwrap_or(90)
            .clamp(1, 100)
    }

    pub(crate) fn maintenance_evict_failures(&self) -> u32 {
        self.maintenance_evict_failures.unwrap_or(3).clamp(1, 100)
    }

    /// 池子跌破保底线时是否自动补池，默认开。
    pub(crate) fn maintenance_auto_refill(&self) -> bool {
        self.maintenance_auto_refill.unwrap_or(true)
    }

    /// 定期扫描间隔（秒）；0 = 关闭。上限一天，避免配出一个「永远不扫」的荒唐值。
    pub(crate) fn scan_interval_seconds(&self) -> u64 {
        self.scan_interval_seconds.unwrap_or(0).min(86_400)
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

    /// 配额型冷却的生效时长（秒）：配置优先，缺省 120，越界夹紧到 30–600。
    ///
    /// 夹紧（而不是拒绝）是刻意的：这个值只是"试下一次的间隔"，配得再离谱也不该
    /// 让保存失败；真正的语义保证在读侧（这里）。
    pub(crate) fn effective_cooldown_seconds(&self) -> u32 {
        self.cooldown_seconds
            .unwrap_or(crate::opencode_rotation::DEFAULT_OPENCODE_COOLDOWN_SECONDS)
            .clamp(
                crate::opencode_rotation::MIN_OPENCODE_COOLDOWN_SECONDS,
                crate::opencode_rotation::MAX_OPENCODE_COOLDOWN_SECONDS,
            )
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
    /// - 集合来源只有 `healthy`（历史复验转正、只读保留）与 `exit_pool`（扫描探通
    ///   即写入）；没有第三层「候选」中间态（2026-10 已删除）。
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

    /// 从 CIDR 枚举待探 IP，排除池中已有 IP 与网络/广播地址。
    ///
    /// 结果按字典序稳定排列，一轮全部探完（游标与分片已随候选池一起删除）。
    pub(crate) fn candidate_ips(&self, known_ips: &BTreeSet<String>) -> Vec<String> {
        let known_segments: BTreeSet<String> =
            known_ips.iter().map(|ip| ipv4_segment_key(ip)).collect();
        let mut candidates = BTreeMap::<String, String>::new();
        for cidr in &self.cidrs {
            let Some((prefix, bits)) = parse_cidr(cidr) else {
                continue;
            };
            let host_count = 1u64 << (32 - bits);
            let first = if bits <= 30 { 1 } else { 0 };
            let last = if bits <= 30 {
                host_count.saturating_sub(1)
            } else {
                host_count
            };
            for offset in first..last {
                let value = prefix as u64 + offset;
                let octets = [
                    (value >> 24) as u8,
                    (value >> 16) as u8,
                    (value >> 8) as u8,
                    value as u8,
                ];
                let ip = format!("{}.{}.{}.{}", octets[0], octets[1], octets[2], octets[3]);
                let segment = ipv4_segment_key(&ip);
                if !known_segments.contains(&segment) {
                    candidates.entry(segment).or_insert(ip);
                }
            }
        }
        candidates.into_values().collect()
    }
}

/// IPv4 前三段派生的配额段键。
pub(crate) fn ipv4_segment_key(ip: &str) -> String {
    let parts: Vec<&str> = ip.trim().split('.').collect();
    if parts.len() == 4 && parts.iter().all(|part| part.parse::<u8>().is_ok()) {
        format!("{}.{}.{}.0/24", parts[0], parts[1], parts[2])
    } else {
        ip.trim().to_string()
    }
}

/// 解析 IPv4 CIDR（`a.b.c.d/len`），返回 (网络地址, 前缀长度)。
pub(crate) fn parse_cidr(cidr: &str) -> Option<(u32, u32)> {
    let (addr_part, len_part) = cidr.split_once('/')?;
    let bits = len_part.trim().parse::<u32>().ok()?;
    if !(16..=32).contains(&bits) {
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
    // 节点必然 TLS 失败，于是扫描与自动维护会把整个池误判为失效。
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

/// 探测目标是否就是官方直连域名。这种情况下探测结果不可信，禁止用它判定节点健康。
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

/// 是否有池任务在跑（互斥用）。
///
/// 复验类入口都已删除，写 `provider.config` 的长任务只剩扫描这一条，所以这里只需要
/// 看 `scanning`。`cleaning` 已随「清理」入口一起删除——它与自动维护探针做的是同一
/// 件事，但它是「失败即删、无阈值、无熔断」，等于一个能一键大规模删池的危险入口，
/// 已由每 10 分钟的自动维护（`maintenance/runtime/opencode_ip_pool.rs`）取代。
fn any_pool_task_running(provider_id: &str) -> bool {
    opencode_ip_pool_status_for(provider_id).scanning
}

/// 标记扫描已开始，返回 false 表示已有扫描在跑。
///
/// 供「异步触发」入口使用：先同步占位再返回 202，避免客户端轮询到
/// `scanning=false` 的空窗期。真正的复位由 `ScanFlagGuard` 负责。
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

/// 单个出口 IP 的「验证健康」结论（面板行内按钮用）。
///
/// 这个动作是**一次真实 chat 探测**（成本 = 一个请求），因此只能由用户点击触发，
/// 不能挂在任何定时任务上——日常保洁由后台维护 worker 用 TLS + `GET /`（零额度）
/// 完成，两条路径的成本差一个数量级。
#[derive(Debug, Clone)]
pub struct OpenCodeIpVerifyOutcome {
    pub ip: String,
    /// 是否可用：只有拿到 `200` 才算。
    pub healthy: bool,
    /// 额度受限（`403` / `429`）：不是不可达，既不记失败也不清计数。
    pub quota_limited: bool,
    /// 不可用原因（`unreachable` / `quota_limited`）；可用时为 `None`。
    pub reason: Option<String>,
    /// 本次探测耗时（毫秒）；不可用时为 `None`。
    pub median_ms: Option<u64>,
    /// 异常池里累计的失败次数（通过后为 0）。
    pub fails: u32,
}

/// 验证**单个**出口 IP：发一次真实 chat，按维护 worker 的同一套账本落账。
///
/// 落账规则（与 `maintain_exit_pool` 逐条对齐，不另起一套）：
/// - `200` → 清掉异常计数，IP 立刻回到轮转池；顺带刷新它的延迟记录；
/// - `403` / `429` → 额度受限：既不算不可达、也不清旧计数（上游问题不是 IP 问题）；
/// - 其它失败 → 异常池计数 +1（累计到剔除阈值的剔除动作仍由 worker 负责）。
pub(crate) async fn verify_open_code_pool_ip(
    app: &AppState,
    provider: &StoredProviderCatalogProvider,
    ip: &str,
) -> Result<OpenCodeIpVerifyOutcome, GatewayError> {
    let ip = ip.trim().to_string();
    if ip.parse::<IpAddr>().is_err() {
        return Err(GatewayError::Internal(format!("无效的 IP：{ip}")));
    }
    let scan = OpenCodeScanConfig::from_provider_config(&provider.config);
    let (domain, port) = opencode_upstream_target(app, &provider.id, &scan).await?;
    if probe_target_is_official(&domain) {
        return Err(GatewayError::Internal(
            "未配置前置代理域名，无法判断节点是否健康；请先在前置代理池里填写并保存 CDN 域名，再执行验证"
                .to_string(),
        ));
    }
    let probe = probe_upstream_ip_chat_outcome(
        &ip,
        &domain,
        port,
        VERIFY_PROBE_TIMEOUT_SECS,
        &scan.probe_model(),
    )
    .await?;
    let mut health = OpenCodeHealthConfig::from_provider_config(&provider.config);
    let mut changed = false;
    let outcome = match probe {
        ChatProbeOutcome::Healthy(elapsed_ms) => {
            // 通过即回到轮转池：清异常计数没有任何前置条件，失败记录不阻止转正。
            health.clear_abnormal(&ip);
            health.latencies.insert(ip.clone(), elapsed_ms);
            changed = true;
            OpenCodeIpVerifyOutcome {
                ip: ip.clone(),
                healthy: true,
                quota_limited: false,
                reason: None,
                median_ms: Some(elapsed_ms),
                fails: 0,
            }
        }
        ChatProbeOutcome::QuotaLimited(status) => {
            tracing::info!(
                event_name = "opencode_ip_pool_single_verify_quota_limited",
                log_type = "ops",
                provider_id = %provider.id,
                ip = %ip,
                status,
                "single ip verify saw a quota-limited response; keeping the accounting untouched"
            );
            OpenCodeIpVerifyOutcome {
                ip: ip.clone(),
                healthy: false,
                quota_limited: true,
                reason: Some("quota_limited".to_string()),
                median_ms: None,
                fails: health
                    .abnormal
                    .iter()
                    .find(|entry| entry.ip == ip)
                    .map(|entry| entry.fails)
                    .unwrap_or_default(),
            }
        }
        ChatProbeOutcome::Unreachable => {
            let fails = health.record_abnormal(&ip, "unreachable", None, &now_string());
            changed = true;
            OpenCodeIpVerifyOutcome {
                ip: ip.clone(),
                healthy: false,
                quota_limited: false,
                reason: Some("unreachable".to_string()),
                median_ms: None,
                fails,
            }
        }
    };
    if changed {
        write_health_config(app, provider, &health).await?;
    }
    tracing::info!(
        event_name = "opencode_ip_pool_single_verify",
        log_type = "ops",
        provider_id = %provider.id,
        ip = %outcome.ip,
        healthy = outcome.healthy,
        quota_limited = outcome.quota_limited,
        fails = outcome.fails,
        "single ip verify finished"
    );
    Ok(outcome)
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
    // 已知 IP = 现有生产池 + 旧模型里仍带元数据的 key。它们不再重复计入 `added`。
    let known_ips: BTreeSet<String> = keys
        .iter()
        .filter_map(opencode_pool_key_ip)
        .chain(config.exit_pool.iter().cloned())
        .collect();
    let health = OpenCodeHealthConfig::from_provider_config(&provider.config);
    // 已在跟踪中的节点不再探：异常池的节点由维护 worker 负责到底，人工拉黑的是
    // 明确意图。**丢弃的不在此列**——丢弃的定义就是「靠下一次扫描回来」。
    let mut skip_ips: BTreeSet<String> = health.blocked_ips();
    skip_ips.extend(health.abnormal_ips());
    let mut all_candidates = config.candidate_ips(&known_ips);
    // 待探来源之二：前置代理域名的 DNS 解析结果（多采样取并集）。
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
    // 一轮把全部待探地址探完：没有游标、也没有分片。候选池删除之后，扫描的产出
    // 就是「探通即写 exit_pool」，不再需要跨轮累积「本轮已见」集合去重建候选列表。
    let target_count = all_candidates.len() as u64;
    update_opencode_ip_pool_status(&provider_id, |status| status.progress_total = target_count);
    tracing::info!(
        event_name = "opencode_ip_pool_scan_round",
        log_type = "ops",
        provider_id,
        targets = target_count,
        concurrency,
        max_handshake_ms,
        // 预计耗时 = 目标数 × 单探超时 ÷ 并发。直接打进日志，省得事后靠
        // progress_done 去反推「是卡住了，还是并发被配成了 1」
        // （2026-10-24 现场：3629 目标 × 4s ÷ 并发 1 ≈ 4 小时，看起来就是卡死）。
        eta_seconds =
            target_count.saturating_mul(OPENCODE_PROBE_TIMEOUT_SECS) / (concurrency.max(1) as u64),
        "opencode ip pool scan round started"
    );

    let healthy = probe_ips(
        &all_candidates,
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
    // 扫描只做「发现」：探通的 IP **直接写进 exit_pool**（IP 立刻可用）。
    // 唯一的例外是刚连着失败的节点——粗筛只看得见「连得通」，让它的冷静期过完
    // 再说，否则异常池会「候选 → 异常」地来回跳。
    for ip in healthy {
        // 刚连着失败的节点：扫描探通它并不能推翻「它有问题」——粗筛只看得见连得通。
        let suspect =
            crate::opencode_rotation::opencode_ip_suspect_reason(app, &provider_id, &ip).await;
        if suspect.is_some() {
            continue;
        }
        if known_ips.contains(&ip) {
            continue;
        }
        next_config.exit_pool.push(ip);
        added += 1;
    }
    // 落盘扫描完成时间：`autoscan` 必须按**落盘**时间判断间隔。用进程内存时间的话，
    // 每次重启都会立刻判定"该扫了"——2026-10-18 实测：重启后马上起了一轮扫描，
    // 卡在无超时的 DNS 解析上，`scanning` 永久 true，把复验全堵成 400。
    next_config.last_scan_at = Some(now_string());
    write_scan_config(app, provider, &next_config).await?;

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
    // exit_pool 只在迁移期被任务写入（生产列表已改由 opencode_health.healthy 承担），
    // 仍然属于任务产出，不能被用户在界面上没有对应输入框的旧值覆盖回去。
    merged.insert("exit_pool".to_string(), json!(produced.exit_pool.clone()));
    // 扫描完成时间也是任务产出：`autoscan` 靠它判断间隔，必须落盘。
    // （第一版漏了这里——`to_provider_config_value` 里加了字段，但这条写入路径
    // 走的是本函数按 key 合并，于是字段被静默丢弃，实测扫描后 last_scan_at 仍为空。）
    if let Some(stamp) = produced.last_scan_at.clone() {
        merged.insert("last_scan_at".to_string(), json!(stamp));
    }
    if let Some(stamp) = produced.last_maintenance_at.clone() {
        merged.insert("last_maintenance_at".to_string(), json!(stamp));
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

/// 把一个「运行时连续失败」的出口 IP 写进异常池。
///
/// 运行时失败原本只有两条**临时**处置：标 `suspect`（带 TTL）和进冷却（Redis TTL）。
/// 两者到期后 IP 会自动回到轮转，却没有任何地方回答「这个 IP 是不是反复失败」。
/// 异常池才是能被维护探针与行内验证重新判定、判定通过后自动回到可用池的那份名单，
/// 所以达到阈值时也要写进去——否则「失败 → 异常 → 验证回升」这条链是断的。
///
/// 已在异常池里时不重复写入：这个函数在一次请求失败的路径上被调用，重复改写
/// provider config 只会制造无谓的写竞争。
pub(crate) async fn mark_runtime_failed_exit_ip_abnormal(
    app: &AppState,
    provider_id: &str,
    ip: &str,
    fails: u64,
    threshold: u64,
) -> Result<bool, GatewayError> {
    // 调用点在请求失败路径上，手上只有 transport 快照里的 provider DTO；
    // 写回却需要存储实体，所以按 id 读一次。
    let Some(provider) = app
        .read_provider_catalog_providers_by_ids(std::slice::from_ref(&provider_id.to_string()))
        .await?
        .into_iter()
        .next()
    else {
        return Ok(false);
    };
    let mut health = OpenCodeHealthConfig::from_provider_config(&provider.config);
    if health.abnormal.iter().any(|entry| entry.ip == ip) {
        return Ok(false);
    }
    health.record_abnormal(ip, "runtime_fail", None, &chrono::Utc::now().to_rfc3339());
    write_health_config(app, &provider, &health).await?;
    tracing::info!(
        event_name = "opencode_exit_ip_runtime_failed_into_abnormal",
        log_type = "event",
        provider_id = %provider.id,
        ip,
        fails,
        threshold,
        "exit ip moved into the abnormal pool after repeated runtime failures"
    );
    Ok(true)
}

/// 健康段写入前的统一清理（目前只有异常池过期）。
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
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum MaintenanceProbeResult {
    Healthy,
    QuotaLimited,
    Unreachable,
}

/// 低额度维护探针：TLS + GET /。429/403 FreeUsageLimit 表示额度状态，不是不可达。
pub(crate) async fn probe_upstream_ip_maintenance(
    ip: &str,
    domain: &str,
    port: u16,
    timeout_secs: u64,
) -> Result<MaintenanceProbeResult, GatewayError> {
    let parsed: IpAddr = match ip.trim().parse() {
        Ok(value) => value,
        Err(_) => return Ok(MaintenanceProbeResult::Unreachable),
    };
    let address = std::net::SocketAddr::new(parsed, port);
    let connect = tokio::time::timeout(
        std::time::Duration::from_secs(timeout_secs),
        tokio::net::TcpStream::connect(address),
    )
    .await;
    let Ok(Ok(stream)) = connect else {
        return Ok(MaintenanceProbeResult::Unreachable);
    };
    let stream = stream
        .into_std()
        .map_err(|err| GatewayError::Internal(err.to_string()))?;
    let domain = domain.to_string();
    let result = tokio::task::spawn_blocking(move || {
        probe_upstream_ip_blocking_result(stream, &domain, timeout_secs)
    })
    .await
    .map_err(|err| GatewayError::Internal(err.to_string()))??;
    Ok(result)
}

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
/// **现状（2026-10-18）**：健康判定已改走 `probe_upstream_ip_chat_outcome`（真实 chat，
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

/// 维护探针发出去的 HTTP 请求。抽成函数是为了能被测试直接检查字节。
///
/// **这里的换行必须是真正的 CRLF。** 曾经把它写成 `\\r\\n`（Rust 里那是
/// 「反斜杠 + r」的字面文本），结果服务端永远等不到请求头结束，
/// 整个池 902 个 IP 全被判成不可达，只能靠失败率熔断挡住批量误删。
/// 分类测试喂的是状态行字符串，覆盖不到请求构造，所以当时全绿。
fn maintenance_probe_request(domain: &str, user_agent: &str) -> String {
    format!(
        "GET / HTTP/1.1\r\n\
         Host: {domain}\r\n\
         User-Agent: {user_agent}\r\n\
         Authorization: Bearer public\r\n\
         Accept: application/json\r\n\
         Connection: close\r\n\
         \r\n"
    )
}

fn probe_upstream_ip_blocking_result(
    stream: std::net::TcpStream,
    domain: &str,
    timeout_secs: u64,
) -> Result<MaintenanceProbeResult, GatewayError> {
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
    let request = maintenance_probe_request(
        domain,
        &aether_provider_transport::opencode::opencode_user_agent(),
    );
    if tls_stream.write_all(request.as_bytes()).is_err() {
        return Ok(MaintenanceProbeResult::Unreachable);
    }
    let mut status_line = Vec::new();
    if !read_probe_status_line(&mut tls_stream, &mut status_line).unwrap_or(false) {
        return Ok(MaintenanceProbeResult::Unreachable);
    }
    if is_healthy_status_line(&status_line) {
        return Ok(MaintenanceProbeResult::Healthy);
    }
    if is_quota_status_line(&status_line) {
        return Ok(MaintenanceProbeResult::QuotaLimited);
    }
    Ok(MaintenanceProbeResult::Unreachable)
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
        "GET / HTTP/1.1\r\n\
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

/// 一次真实 chat 探测的结论，按状态码三分。
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum ChatProbeOutcome {
    /// 拿到 `200`，值是从建连到读完整响应的耗时（毫秒）。
    Healthy(u64),
    /// 额度受限（`403` / `429`）：说明出口能通、账号被限，不是 IP 坏了。
    QuotaLimited(u16),
    /// 其它（超时 / 连接失败 / 其它状态码）。
    Unreachable,
}

/// 发一条**真实 chat** 探测（`POST /inference/v1/chat/completions`），只有 `200` 才算健康。
///
/// ## 为什么不能用 `/inference/v1/models`
///
/// 那个端点匿名可用。2026-10-17 对 `108.138.0.0/24` 做全量实测：254 个 IP 里
/// **239 个 chat 恒定 403 FreeTierError、0 个 200**，但同样这批 IP 打 `/models`
/// 有 239 个返回 200 —— 用 models 判健康，对「免费层被判死」的检出率是 0。
///
/// 只由面板上的行内「验证健康」按钮调用（一次点击 = 一次请求）；后台维护 worker
/// 走的是零额度的 TLS + `GET /` 探针，两者不共用这条路径。
async fn probe_upstream_ip_chat_outcome(
    ip: &str,
    domain: &str,
    port: u16,
    timeout_secs: u64,
    model: &str,
) -> Result<ChatProbeOutcome, GatewayError> {
    let parsed: IpAddr = match ip.trim().parse() {
        Ok(ip) => ip,
        Err(_) => return Ok(ChatProbeOutcome::Unreachable),
    };
    let address = std::net::SocketAddr::new(parsed, port);
    let started_at = std::time::Instant::now();
    let connect = tokio::time::timeout(
        std::time::Duration::from_secs(timeout_secs),
        tokio::net::TcpStream::connect(address),
    )
    .await;
    let Ok(Ok(stream)) = connect else {
        return Ok(ChatProbeOutcome::Unreachable);
    };
    let stream = stream
        .into_std()
        .map_err(|err| GatewayError::Internal(err.to_string()))?;
    let model = model.to_string();
    let domain = domain.to_string();
    let status = tokio::task::spawn_blocking(move || {
        probe_chat_blocking(stream, &domain, timeout_secs, &model)
    })
    .await
    .map_err(|err| GatewayError::Internal(err.to_string()))??;
    Ok(match status {
        Some(200) => ChatProbeOutcome::Healthy(started_at.elapsed().as_millis() as u64),
        Some(code) if code == 403 || code == 429 => ChatProbeOutcome::QuotaLimited(code),
        _ => ChatProbeOutcome::Unreachable,
    })
}

/// 阻塞式 chat 探测：TLS 握手 → 发 POST → 只读状态行，返回状态码。
///
/// 回状态码而不是 `bool`：`403` / `429` 是「额度受限」而不是「IP 坏了」，
/// 两者在生产上的处置完全相反（前者不动计数，后者记异常）。
fn probe_chat_blocking(
    stream: std::net::TcpStream,
    domain: &str,
    timeout_secs: u64,
    model: &str,
) -> Result<Option<u16>, GatewayError> {
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
        return Ok(None);
    }
    let mut status_line = Vec::new();
    match read_probe_status_line(&mut tls_stream, &mut status_line) {
        Ok(true) => Ok(status_line_code(&status_line)),
        _ => Ok(None),
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
fn is_quota_status_line(status_line: &[u8]) -> bool {
    let Some(space) = status_line.iter().position(|byte| *byte == b' ') else {
        return false;
    };
    let code_start = space + 1;
    code_start + 2 < status_line.len()
        && (status_line[code_start] == b'4'
            && (status_line[code_start + 1] == b'0' && status_line[code_start + 2] == b'3'
                || status_line[code_start + 1] == b'2' && status_line[code_start + 2] == b'9'))
}

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
            "verify_max_median_ms": self.verify_max_median_ms(),
            "min_pool_size": self.min_pool_size(),
            "session_sticky_enabled": self.session_sticky_enabled,
            "session_sticky_min_pool": self.session_sticky_min_pool(),
            "abnormal_max_age_days": self.abnormal_max_age_days(),
        })
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

    /// 组一份「已复验转正（healthy）+ 已加入未验证（exit_pool）」的配置。
    fn pool_fixture(
        healthy: &[&str],
        exit_pool: &[&str],
    ) -> (OpenCodeScanConfig, OpenCodeHealthConfig) {
        let mut scan = OpenCodeScanConfig::default();
        scan.exit_pool = exit_pool.iter().map(|ip| ip.to_string()).collect();
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
        let (scan, health) = pool_fixture(&["108.138.0.10"], &["108.138.0.11", "108.138.0.12"]);
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
        );
        health.record_abnormal("108.138.0.11", "unreachable", None, "2026-10-21T00:00:00Z");
        health.blocked.push("108.138.0.12".to_string());
        assert_eq!(
            scan.effective_pool(&health),
            vec!["108.138.0.10".to_string(), "108.138.0.13".to_string()]
        );
        assert_eq!(scan.trusted_on_add_count(&health), 1);
    }

    /// 回归：`exit_pool ⊆ healthy` 时（= 今天线上的形状：所有池内 IP 都验过），
    /// 轮转池必须**逐字节**等于 `healthy`，顺序也不变。
    ///
    /// 这条是「扩池不改变既有节点选点行为」的依据：前缀完全相同，游标/会话哈希
    /// 只是在池变长之后按新长度取模，没有重新排序、没有插入。
    #[test]
    fn verified_only_pools_keep_the_original_order() {
        let healthy = ["108.138.0.10", "108.138.0.11", "108.138.0.12"];
        let (scan, health) = pool_fixture(&healthy, &healthy);
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
        assert!(!status.pool_below_floor, "在用 5 个正好等于保底线，不告警");
    }

    // ---------------------------------------------------------------------------
    // 选点：未验证的点真的会被抽中，异常的点永远抽不中
    // ---------------------------------------------------------------------------

    /// 未验证的 IP 会被**选点**选中（不只是出现在列表里）。
    #[tokio::test]
    async fn unverified_ip_is_actually_picked_by_the_anchor_selector() {
        let (scan, health) = pool_fixture(&["108.138.0.10"], &["108.138.0.11"]);
        let pool = scan.effective_pool(&health);
        let provider = pool_test_provider(json!({}));
        let state = pool_test_state(provider);
        let mut picked: BTreeSet<String> = BTreeSet::new();
        // 两个点同属一个 /24 段（`108.138.0`），所以「段随机」只会固定选到这一段，
        // 段内两个 IP 由种子决定。抽 32 次才能把「两个点都抽到」变成确定事件
        // （单次命中每个 IP 的概率各 1/2）。
        for _ in 0..32 {
            let ip = crate::opencode_rotation::pick_anchor_ip(
                &state,
                POOL_TEST_PROVIDER_ID,
                &pool,
                &crate::opencode_rotation::OpenCodeAnchorSkip::default(),
                None,
            )
            .await
            .expect("池非空时必须选出一个锚点")
            .ip;
            picked.insert(ip);
        }
        assert_eq!(
            picked,
            BTreeSet::from(["108.138.0.10".to_string(), "108.138.0.11".to_string()]),
            "同一段内的两个 IP 都必须能被抽到：{picked:?}"
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
            .expect("池里还有可用点时必须选出来")
            .ip;
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
            .expect("池非空时必须选出一个锚点")
            .ip;
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

    /// 单 IP「验证健康」的入口校验：非法 IP 在发请求之前就被挡住。
    ///
    /// 这条路径是用户点出来的，参数来自 HTTP body——绝不能让一个手滑的字符串
    /// 走到上游，更不能让它落进异常池账本。
    #[tokio::test]
    async fn single_ip_verify_rejects_a_value_that_is_not_an_ip() {
        let provider = pool_test_provider(json!({
            "opencode_scan": { "cidrs": ["203.0.113.0/24"], "exit_pool": ["198.51.100.1"] },
            "opencode_health": { "abnormal": [
                { "ip": "198.51.100.1", "since": "t0", "fails": 2, "reason": "unreachable" }
            ] },
        }));
        let state = pool_test_state(provider.clone());

        let error = verify_open_code_pool_ip(&state, &provider, "203.0.113.999")
            .await
            .expect_err("非法 IP 必须直接报错");
        let message = format!("{error:?}");
        assert!(message.contains("无效的 IP"), "报错要说明原因：{message}");

        // 账本不能被这次调用动过。
        let after = OpenCodeHealthConfig::from_provider_config(&Some(stored_config(&state).await));
        assert_eq!(after.abnormal.len(), 1);
        assert_eq!(after.abnormal[0].fails, 2);
    }

    /// 没配前置代理域名时无法判断节点健康：必须在探测之前就拒绝，并告诉用户先配域名。
    ///
    /// 判断依据是「锚定目标是不是官方域名」——锚定到官方域名时 chat 请求根本没经
    /// 过这个出口 IP，探测结果与节点健康无关，报「健康」比报错更危险。
    #[tokio::test]
    async fn single_ip_verify_refuses_to_guess_without_a_proxy_domain() {
        let provider = pool_test_provider(json!({
            "opencode_scan": { "cidrs": ["203.0.113.0/24"], "exit_pool": ["198.51.100.1"] }
        }));
        // 端点就是官方域名：探它等于直连官方，与该出口 IP 无关。
        let state = pool_test_state_with_endpoint(provider.clone(), "https://opencode.ai/v1");

        let error = verify_open_code_pool_ip(&state, &provider, "198.51.100.1")
            .await
            .expect_err("没有前置代理域名时必须报错而不是猜");
        let message = format!("{error:?}");
        assert!(
            message.contains("前置代理域名"),
            "报错要指明该配什么：{message}"
        );
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

    /// 与 `pool_test_state` 同形，但额外挂一条端点。
    ///
    /// 解析探测目标时会读端点 base_url 兜底，所以「没有前置代理域名」这条分支
    /// 必须先有端点，否则会先在「解析不到上游域名」处退出。
    fn pool_test_state_with_endpoint(
        provider: StoredProviderCatalogProvider,
        base_url: &str,
    ) -> AppState {
        let endpoint = StoredProviderCatalogEndpoint::new(
            format!("{POOL_TEST_PROVIDER_ID}-ep"),
            provider.id.clone(),
            "openai".to_string(),
            Some("openai".to_string()),
            Some("chat".to_string()),
            true,
        )
        .expect("endpoint should build")
        .with_transport_fields(
            base_url.to_string(),
            None,
            None,
            None,
            None,
            None,
            None,
            None,
        )
        .expect("endpoint transport should build");
        let repository = Arc::new(InMemoryProviderCatalogReadRepository::seed(
            vec![provider],
            vec![endpoint],
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

    /// 复现线上事故：复验先写 opencode_health，紧接着写 opencode_scan。
    ///
    /// 旧实现两个写函数都拿**任务开始时的 provider 快照**重建整个 config 再整行
    /// 写回，于是第二次写把刚写好的 healthy 覆盖回旧值。线上实测就是这个形状：
    /// 复验 checked=337 / kept=337 / dropped=0，而生产池仍是 65 个节点，
    /// latencies / degraded / rejections 一起回滚——健康门槛等于没生效。
    #[tokio::test]
    async fn scan_write_after_verify_write_keeps_the_new_health_section() {
        let initial = json!({
            "opencode_scan": { "cidrs": ["203.0.113.0/24"], "exit_pool": ["198.51.100.1"] },
            "opencode_health": { "healthy": ["198.51.100.1"] },
        });
        // 任务开始时的快照：两趟任务都拿着它。
        let stale_provider = pool_test_provider(initial.clone());
        let state = pool_test_state(stale_provider.clone());

        // 健康段先写：337 个节点全部记为已验。
        let verified: Vec<String> = (0..337)
            .map(|index| format!("198.51.100.{}", index % 200))
            .collect();
        let mut health = OpenCodeHealthConfig::from_provider_config(&stale_provider.config);
        health.healthy = verified.clone();
        write_health_config(&state, &stale_provider, &health)
            .await
            .expect("health write should succeed");

        // 扫描紧接着写 exit_pool。
        let mut scan = OpenCodeScanConfig::from_provider_config(&stale_provider.config);
        scan.exit_pool = verified.clone();
        write_scan_config(&state, &stale_provider, &scan)
            .await
            .expect("scan write should succeed");

        let after = stored_config(&state).await;
        let healthy = healthy_ips(&after);
        assert_eq!(
            healthy.len(),
            verified.len(),
            "扫描写回把健康段刚写入的 healthy 覆盖回了旧值：{healthy:?}"
        );
        // 扫描自己的产出仍然要落进去，不能因为修了覆盖就不写了。
        let after_scan = OpenCodeScanConfig::from_provider_config(&Some(after));
        assert_eq!(after_scan.exit_pool.len(), verified.len());
    }

    /// 任务运行期间用户在界面上改的配置不能被任务的收尾写回吞掉。
    ///
    /// 扫描最长 50 分钟、复验约 3 分钟，这段时间里完全可能改会话粘性
    /// 或验健康阈值。旧实现用陈旧快照整行写回，这些修改会被静默还原。
    #[tokio::test]
    async fn pool_task_write_preserves_a_concurrent_admin_config_change() {
        let initial = json!({
            "opencode_scan": { "cidrs": ["203.0.113.0/24"], "exit_pool": ["198.51.100.1"] },
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
        scan.exit_pool = vec!["198.51.100.1".to_string(), "198.51.100.2".to_string()];
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
        produced.exit_pool = vec!["198.51.100.9".to_string()];

        let mut config_map = json!({
            "opencode_scan": {
                // 用户在任务运行期间把网段换掉了，并关掉了自动扫描。
                "cidrs": ["198.18.0.0/15"],
                "interval_hours": 0,
                "auto_enabled": false,
                "cooldown_seconds": 300,
                "proxy_domain": "opencode.fanjinlong.top",
                "exit_pool": ["198.51.100.1"],
            },
            "opencode_health": { "healthy": ["198.51.100.1"] },
        })
        .as_object()
        .cloned()
        .expect("object");

        merge_scan_section_into(&mut config_map, &produced);
        let merged = OpenCodeScanConfig::from_provider_config(&Some(Value::Object(config_map)));

        // 任务产出的字段用任务的值。
        assert_eq!(merged.exit_pool, vec!["198.51.100.9".to_string()]);
        // 用户设置的字段保持用户最新的值，不能被任务开始时的旧值盖回去。
        assert_eq!(merged.cidrs, vec!["198.18.0.0/15".to_string()]);
        assert_eq!(merged.interval_hours, Some(0));
        assert!(!merged.auto_enabled);
        assert_eq!(merged.cooldown_seconds, Some(300));
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
        produced.exit_pool = vec!["198.51.100.9".to_string()];

        let mut config_map = serde_json::Map::new();
        merge_scan_section_into(&mut config_map, &produced);
        let merged = OpenCodeScanConfig::from_provider_config(&Some(Value::Object(config_map)));

        assert_eq!(merged.cidrs, vec!["203.0.113.0/24".to_string()]);
        assert_eq!(merged.exit_pool, vec!["198.51.100.9".to_string()]);
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
            "opencode_scan": { "cidrs": ["203.0.113.0/24"], "exit_pool": ["198.51.100.1"] },
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
            "opencode_scan": { "cidrs": ["203.0.113.0/24"], "exit_pool": ["198.51.100.1"] },
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
            "opencode_scan": { "cidrs": ["203.0.113.0/24"], "exit_pool": ["198.51.100.1"] },
            "opencode_health": { "healthy": ["198.51.100.1"] },
        });
        let stale_provider = pool_test_provider(initial);
        let state = pool_test_state(stale_provider.clone());

        let payload = json!({ "cidrs": ["198.18.0.0/16", "not-an-ip/24"] })
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
        assert!(candidates.is_empty());
    }

    #[test]
    fn candidate_ips_deduplicate_by_24_segment_and_support_32() {
        let config = OpenCodeScanConfig {
            cidrs: vec!["192.168.1.0/30".into(), "192.168.2.7/32".into()],
            ..Default::default()
        };
        let candidates = config.candidate_ips(&BTreeSet::new());
        assert_eq!(candidates, vec!["192.168.1.1", "192.168.2.7"]);
        let known: BTreeSet<String> = ["192.168.1.99".into()].into_iter().collect();
        assert_eq!(config.candidate_ips(&known), vec!["192.168.2.7"]);
    }

    #[test]
    fn maintenance_config_defaults_and_parses() {
        let config = OpenCodeScanConfig::from_provider_config_object(
            json!({"opencode_scan": {
                "maintenance_interval_seconds": 900, "maintenance_concurrency": 4,
                "maintenance_failure_threshold_percent": 20, "maintenance_evict_failures": 3
            }})
            .as_object()
            .unwrap(),
        );
        assert_eq!(config.maintenance_interval_seconds(), 900);
        assert_eq!(config.maintenance_concurrency(), 4);
        assert_eq!(config.maintenance_failure_threshold_percent(), 20);
        assert_eq!(config.maintenance_evict_failures(), 3);
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
    fn scan_validation_bounds_the_probe_threshold() {
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
            "probe_max_handshake_ms": OPENCODE_PROBE_MAX_HANDSHAKE_MS_LIMIT
        }));
        assert_eq!(OpenCodeScanConfig::validate_section(&high), Ok(()));
        let low = health_section(json!({
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
                "probe_max_handshake_ms": 1500
            }
        });
        let config = OpenCodeScanConfig::from_provider_config(&Some(source));
        assert_eq!(config.effective_probe_max_handshake_ms(), 1500);
        let written = config.to_provider_config_value();
        assert_eq!(written["probe_max_handshake_ms"], json!(1500));
        // 部分更新：请求体里没提这个键时不能被重置。
        let merged = OpenCodeScanConfig::merged_with_payload(
            &Some(config.to_provider_config_value()),
            json!({ "proxy_domain": "cdn.example.com" })
                .as_object()
                .expect("object"),
        );
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
            "verify_max_median_ms": 10_000,
            "min_pool_size": 5,
            "session_sticky_enabled": true,
        }));
        assert_eq!(OpenCodeHealthConfig::validate_section(&section), Ok(()));
        // 旧库里的复验配置必须被静默忽略：真出现也不能让加载或保存报错。
        let legacy = health_section(json!({
            "verify_max_median_ms": 10_000,
            "min_pool_size": 5,
            "session_sticky_enabled": true,
            "auto_verify_enabled": true,
            "verify_interval_hours": 3,
            "verify_samples": 3,
            "last_verify_at": "2026-09-29T00:31:00+00:00",
            "last_verify_kept": 65,
        }));
        assert_eq!(OpenCodeHealthConfig::validate_section(&legacy), Ok(()));
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
        let section = health_section(json!({ "verify_max_median_ms": 0 }));
        assert!(
            OpenCodeHealthConfig::validate_section(&section).is_err(),
            "verify_max_median_ms=0 必须被拒绝"
        );
    }

    #[test]
    fn health_validation_rejects_wrongly_typed_values() {
        // 字符串 / 浮点 / null 都会让 `as_u64` 返回 None 而被静默忽略。
        for value in [json!("5"), json!(2.5), json!(null), json!([])] {
            let section = health_section(json!({ "verify_max_median_ms": value.clone() }));
            assert!(
                OpenCodeHealthConfig::validate_section(&section).is_err(),
                "verify_max_median_ms={value} 必须被拒绝"
            );
        }
        let section = health_section(json!({ "session_sticky_enabled": "true" }));
        assert!(OpenCodeHealthConfig::validate_section(&section).is_err());
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
            // 冷却（秒）越界是**夹紧**而不是拒绝，所以这里只挡会因 `as u32` 截断的巨值。
            ("cooldown_seconds", json!(5_000_000_000u64)),
        ] {
            let section = health_section(json!({ field: value.clone() }));
            assert!(
                OpenCodeScanConfig::validate_section(&section).is_err(),
                "{field}={value} 必须被拒绝"
            );
        }
        let section = health_section(json!({
            "concurrency": OPENCODE_SCAN_MAX_CONCURRENCY,
            "cooldown_seconds": 120,
            "interval_hours": 6
        }));
        assert_eq!(OpenCodeScanConfig::validate_section(&section), Ok(()));
        // 越界但可夹紧的值必须能存下去（10 → 30、9999 → 600 由读侧负责）。
        let clamped = health_section(json!({ "cooldown_seconds": 9_999 }));
        assert_eq!(OpenCodeScanConfig::validate_section(&clamped), Ok(()));
    }

    /// 配额型冷却（秒）：默认 120，读回与写回都走 `cooldown_seconds`，越界夹紧。
    ///
    /// 这里锁死的是"面板设了要生效"这条链路：`from_provider_config_object` 读、
    /// `to_provider_config_value` 写、`effective_cooldown_seconds` 夹紧。
    #[test]
    fn scan_cooldown_seconds_round_trips_and_clamps() {
        let scan = OpenCodeScanConfig::from_provider_config(&Some(json!({
            "opencode_scan": { "cooldown_seconds": 300 }
        })));
        assert_eq!(scan.effective_cooldown_seconds(), 300);
        assert_eq!(
            scan.to_provider_config_value()
                .get("cooldown_seconds")
                .and_then(Value::as_u64),
            Some(300)
        );
        // 缺省 120（不是旧的 60 分钟）。
        assert_eq!(
            OpenCodeScanConfig::default().effective_cooldown_seconds(),
            120
        );
        for (raw, expected) in [(10u64, 30u32), (9_999, 600), (0, 30)] {
            let clamped = OpenCodeScanConfig::from_provider_config(&Some(json!({
                "opencode_scan": { "cooldown_seconds": raw }
            })));
            assert_eq!(
                clamped.effective_cooldown_seconds(),
                expected,
                "cooldown_seconds={raw} 必须夹紧到 {expected}"
            );
        }
        // 旧键被静默忽略：不会因为库里还留着 `cooldown_minutes: 60` 就回到 1 小时。
        let legacy = OpenCodeScanConfig::from_provider_config(&Some(json!({
            "opencode_scan": { "cooldown_minutes": 60 }
        })));
        assert_eq!(legacy.cooldown_seconds, None);
        assert_eq!(legacy.effective_cooldown_seconds(), 120);
    }

    #[test]
    fn scan_validation_ignores_fields_it_does_not_own() {
        // 健康维护的键出现在扁平请求体里时不能被扫描段误判。
        let section = health_section(json!({
            "cidrs": ["1.2.3.0/24"],
            "verify_max_median_ms": 10_000,
            "proxy_domain": "cdn.example.com"
        }));
        assert_eq!(OpenCodeScanConfig::validate_section(&section), Ok(()));
    }

    /// 维护探针的请求必须是真正的 CRLF 分隔，而且以空行收尾。
    ///
    /// 这条测试存在的理由很具体：曾经把换行写成 `\\r\\n`（Rust 里是字面
    /// 反斜杠加 r），服务端收不到完整的请求头，于是整个池被判不可达。
    /// 只测分类函数永远发现不了这类问题——必须直接检查字节。
    #[test]
    fn maintenance_probe_request_uses_real_crlf() {
        let request = maintenance_probe_request("opencode.example.test", "ua/1.0");
        assert!(
            request.starts_with("GET / HTTP/1.1\r\n"),
            "起始行必须是 CRLF 结尾"
        );
        assert!(request.ends_with("\r\n\r\n"), "请求头必须以空行收尾");
        assert!(
            !request.contains('\\'),
            "请求里不允许出现字面反斜杠：{request:?}"
        );
        assert!(request.contains("\r\nHost: opencode.example.test\r\n"));
        assert!(request.contains("\r\nAuthorization: Bearer public\r\n"));
        // 行数自检：起始行 + 5 个请求头 + 结尾空行。
        assert_eq!(request.matches("\r\n").count(), 7, "{request:?}");
    }

    #[test]
    fn healthy_status_line_recognises_2xx_and_3xx() {
        assert!(is_healthy_status_line(b"HTTP/1.1 200 OK"));
        assert!(is_healthy_status_line(b"HTTP/1.1 301 Moved"));
        assert!(!is_healthy_status_line(b"HTTP/1.1 403 Forbidden"));
        assert!(!is_healthy_status_line(b"garbage"));
        assert!(is_quota_status_line(b"HTTP/1.1 403 Forbidden"));
        assert!(is_quota_status_line(b"HTTP/1.1 429 Too Many Requests"));
        assert!(!is_quota_status_line(b"HTTP/1.1 500 Server Error"));
    }

    #[test]
    fn status_map_is_per_provider() {
        update_opencode_ip_pool_status("pool-a", |status| status.scanning = true);
        assert!(opencode_ip_pool_status_for("pool-a").scanning);
        assert!(!opencode_ip_pool_status_for("pool-b").scanning);
        update_opencode_ip_pool_status("pool-a", |status| status.scanning = false);
    }
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

/// 池子比上限还大时，同一 IP 的失败次数必须仍能跨轮累加。
///
/// 回归 2026-10-24：上限原来是 500，生产池 1086 个 IP、每轮约 666 个不可达，
/// 超出部分按「丢最旧」被裁掉，同一批 IP 在上限边缘反复进出，`fails` 永远停在 1。
/// 于是 `maintenance_evict_failures = 3` 的剔除条件永远不成立——现象是「维护在跑、
/// 异常在涨、池子一个也不减」。
#[test]
fn abnormal_failures_accumulate_when_the_pool_outgrows_the_cap() {
    let mut health = OpenCodeHealthConfig::default();
    // 模拟一整轮探测：先塞进 1000 个失败条目（超过旧上限 500）
    for index in 0..1_000usize {
        health.record_abnormal(
            &format!("10.{}.{}.1", index / 256, index % 256),
            "unreachable",
            None,
            "t1",
        );
    }
    assert_eq!(
        health.abnormal.len(),
        1_000,
        "上限必须容得下整池，否则失败计数会被裁掉，剔除永远不触发"
    );

    let target = "203.0.113.7";
    for expected in 1..=3u32 {
        assert_eq!(
            health.record_abnormal(target, "unreachable", None, "t2"),
            expected,
            "同一 IP 连续失败必须累加"
        );
    }
    assert_eq!(health.abnormal.len(), 1_001);
    // 首次出现的时间不能被后续累加覆盖
    assert_eq!(
        health
            .abnormal
            .iter()
            .find(|entry| entry.ip == target)
            .map(|entry| entry.since.as_str()),
        Some("t2")
    );
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
