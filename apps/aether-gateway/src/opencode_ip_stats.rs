//! opencode 出口 IP 的**成功/失败计数**（每个 IP 一份，供管理面板展示）。
//!
//! 冷却/回避掩码回答的是「这个节点现在能不能用」，但没人回答「它今天到底跑了多少、
//! 失败了多少、失败是 429 还是 503」。这份计数只做这件事：给每个出口 IP 记
//! `ok` / `fail` / 按状态分类的 `by_status` 以及最后成功/失败时刻。
//!
//! 与 [`crate::opencode_cooldown_persist`] 同一套骨架（同步 record + 去抖后台刷写 +
//! `RuntimeState` 的 KV 读写 + 失败降级），刻意保持一致，减少新概念：
//!
//! - **热路径不加同步往返**：[`OpenCodeIpStats::record`] 是**同步**函数，只更新内存
//!   里的待写增量并唤醒后台刷写任务；真正的 Redis 读写发生在
//!   [`OpenCodeIpStats::spawn_flusher`] 里，带去抖（1 秒窗口内的几十条记录合并成
//!   一次批量写）。成功路径与失败路径都只多一次 `parking_lot` 加锁。
//! - **跨重启不丢**：刷写时是「读回 + 相加 + 写回」（读放在后台，不在热路径），
//!   所以进程重启后当天已有的计数仍然会继续累加，而不是从 0 开始。
//! - **过期自然消失**：每个键的 TTL 是 2 天（[`IPSTAT_TTL_SECONDS`]），跨天自动过期，
//!   不占空间。
//! - **持久化层不可用就降级**：没配置、连不上、读失败、写失败都只记日志 —— 计数留在
//!   内存里（面板读不到时返回空对象），请求路径完全不受影响。

use std::collections::BTreeMap;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::Duration;

use async_trait::async_trait;
use parking_lot::Mutex;
use tokio::sync::Notify;

use crate::clock::current_unix_secs;
use crate::AppState;

/// 计数键前缀，完整键是 `opencode_pool:ipstat:<provider_id>:<ip>`。
pub(crate) const IPSTAT_KEY_PREFIX: &str = "opencode_pool:ipstat:";
/// 计数的存活时间：2 天。
///
/// 只服务「当日可查」：跨天自然过期，不留历史，也不需要任何清理任务。刷新点固定在
/// 每次刷写，所以一直在用的节点不会中途掉键。
pub(crate) const IPSTAT_TTL_SECONDS: u64 = 2 * 24 * 60 * 60;
/// 后台刷写的去抖窗口。
///
/// 一次请求风暴里同一个 IP 可能被记几十次：逐条落盘等于把写入放大成几十次往返。去抖
/// 把同一窗口里的记录合并成一次批量写，代价是「写入后 1 秒内进程被 kill」会丢这一段
/// —— 相对「这一类计数本来就没有落点」可以接受，关服时还会补写一次。
const FLUSH_DEBOUNCE: Duration = Duration::from_millis(1_000);
/// 单条 Redis 命令的超时（沿用运行时 KV 的口径）。
const COMMAND_TIMEOUT_MS: u64 = 1_000;

/// 计数键。
pub(crate) fn ipstat_key(provider_id: &str, ip: &str) -> String {
    format!("{IPSTAT_KEY_PREFIX}{provider_id}:{ip}")
}

/// 失败状态码的分档。面板只区分 `429`（限流）、`503`（上游不可用）与其它。
pub(crate) fn ipstat_status_bucket(status_code: Option<u16>) -> &'static str {
    match status_code {
        Some(429) => "429",
        Some(503) => "503",
        _ => "other",
    }
}

/// 一次计数事件。
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum OpenCodeIpStatOutcome {
    /// 上游真的回了 2xx（带出口锚点的成功路径）。
    Success,
    /// 上游失败，`Option<u16>` 是能拿到的状态码（拿不到归到 `other`）。
    Failure(Option<u16>),
}

/// 单个出口 IP 的计数。字段名即落盘 JSON 的字段名。
#[derive(Debug, Default, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub(crate) struct OpenCodeIpStat {
    #[serde(default)]
    pub(crate) ok: u64,
    #[serde(default)]
    pub(crate) fail: u64,
    /// `{"429": n, "503": n, "other": n}` —— 只出现真正发生过的档位。
    #[serde(default)]
    pub(crate) by_status: BTreeMap<String, u64>,
    /// 最后成功时刻（unix 秒）；`0` = 还没有成功过。
    #[serde(default)]
    pub(crate) last_ok_at: u64,
    /// 最后失败时刻（unix 秒）；`0` = 还没有失败过。
    #[serde(default)]
    pub(crate) last_fail_at: u64,
}

impl OpenCodeIpStat {
    /// 把另一份计数**累加**进来（计数相加、时间戳取较新）。
    ///
    /// 两个用途共用同一份语义：内存增量叠到读回来的存量上，以及刷写失败时把这一批
    /// 增量放回待写表。
    fn absorb(&mut self, other: &Self) {
        self.ok = self.ok.saturating_add(other.ok);
        self.fail = self.fail.saturating_add(other.fail);
        for (bucket, count) in other.by_status.iter() {
            let slot = self.by_status.entry(bucket.clone()).or_insert(0);
            *slot = slot.saturating_add(*count);
        }
        self.last_ok_at = self.last_ok_at.max(other.last_ok_at);
        self.last_fail_at = self.last_fail_at.max(other.last_fail_at);
    }

    fn has_data(&self) -> bool {
        self.ok > 0 || self.fail > 0
    }
}

/// 解析落盘值：坏数据按「什么都没有」处理，绝不把一次解析失败升级成一次接口失败。
fn parse_stat(raw: Option<&str>) -> OpenCodeIpStat {
    raw.and_then(|value| serde_json::from_str::<OpenCodeIpStat>(value.trim()).ok())
        .unwrap_or_default()
}

/// 计数的持久化层。抽成 trait 是为了让「层不可用」「热路径无 IO」「批量写」都能在单测
/// 里直接断言，而不必依赖一个真 Redis。
#[async_trait]
pub(crate) trait OpenCodeIpStatStore: Send + Sync + 'static {
    /// 一次批量读（实现里应对应一次 `MGET` 或等价物）；缺失的键对应 `None`。
    async fn load_many(&self, keys: &[String]) -> Result<Vec<Option<String>>, String>;
    /// 一次批量写，`ttl_seconds` 是每个键的存活时间。
    async fn store_many(
        &self,
        entries: Vec<(String, String)>,
        ttl_seconds: u64,
    ) -> Result<(), String>;
}

/// 经 `RuntimeState` 的 KV 抽象读写 Redis 的实现。
///
/// 这里**不直接碰 Redis 客户端**：只持有 `aether_runtime_state::RuntimeState` 并用它的
/// KV 接口（`kv_get_many` / `kv_set`）。键位命名空间、连接超时、错误归类都与别处的
/// 运行时 KV 同源 —— Redis 访问权仍然只属于 runtime-state 这一层。
struct RuntimeStateIpStatStore {
    state: Arc<aether_runtime_state::RuntimeState>,
}

impl RuntimeStateIpStatStore {
    fn new(state: Arc<aether_runtime_state::RuntimeState>) -> Self {
        Self { state }
    }

    /// 用持久化层自己的 Redis URL / key 前缀造一个**独占**的 `RuntimeState`。
    /// 构造过程包含建连与 `PING`，连不上会立刻返回 `Err`，由调用方降级。
    async fn connect(url: &str, key_prefix: Option<&str>) -> Result<Self, String> {
        let state = aether_runtime_state::RuntimeState::redis(
            aether_runtime_state::RedisClientConfig {
                url: url.to_string(),
                key_prefix: key_prefix.map(ToOwned::to_owned),
            },
            Some(COMMAND_TIMEOUT_MS),
        )
        .await
        .map_err(|err| err.to_string())?;
        Ok(Self::new(Arc::new(state)))
    }
}

#[async_trait]
impl OpenCodeIpStatStore for RuntimeStateIpStatStore {
    async fn load_many(&self, keys: &[String]) -> Result<Vec<Option<String>>, String> {
        self.state
            .kv_get_many(keys)
            .await
            .map_err(|err| err.to_string())
    }

    async fn store_many(
        &self,
        entries: Vec<(String, String)>,
        ttl_seconds: u64,
    ) -> Result<(), String> {
        for (key, payload) in entries {
            // `kv_set` + TTL 就是 `SETEX`（runtime-state 内部走 PSETEX）。
            self.state
                .kv_set(
                    key.as_str(),
                    payload,
                    Some(Duration::from_secs(ttl_seconds.max(1))),
                )
                .await
                .map_err(|err| err.to_string())?;
        }
        Ok(())
    }
}

/// 没有任何可用持久化层时的落点：读写都返回 `Err`（只记一次 warn），于是计数只在内存里
/// 累加，管理接口读到 `Err` 就返回空对象 —— 请求路径完全不受影响。
struct DisabledIpStatStore;

#[async_trait]
impl OpenCodeIpStatStore for DisabledIpStatStore {
    async fn load_many(&self, _keys: &[String]) -> Result<Vec<Option<String>>, String> {
        Err("opencode ip stat store is not configured".to_string())
    }

    async fn store_many(
        &self,
        _entries: Vec<(String, String)>,
        _ttl_seconds: u64,
    ) -> Result<(), String> {
        Err("opencode ip stat store is not configured".to_string())
    }
}

/// 出口 IP 计数的累加器 + 去抖刷写器。
pub(crate) struct OpenCodeIpStats {
    store: Arc<dyn OpenCodeIpStatStore>,
    /// 还没落盘的增量：`(provider_id, ip) -> 计数增量`。
    pending: Mutex<BTreeMap<(String, String), OpenCodeIpStat>>,
    flush_signal: Notify,
    flushes: AtomicU64,
    failures: AtomicU64,
}

impl std::fmt::Debug for OpenCodeIpStats {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("OpenCodeIpStats")
            .field("pending_entries", &self.pending_entries())
            .field("flushes", &self.flush_count())
            .field("failures", &self.failure_count())
            .finish()
    }
}

impl OpenCodeIpStats {
    pub(crate) fn new(store: Arc<dyn OpenCodeIpStatStore>) -> Self {
        Self {
            store,
            pending: Mutex::new(BTreeMap::new()),
            flush_signal: Notify::new(),
            flushes: AtomicU64::new(0),
            failures: AtomicU64::new(0),
        }
    }

    /// 记一次计数。
    ///
    /// **同步、无 IO**：只更新内存增量 + 唤醒后台刷写。故意不是 `async` —— 调用点在
    /// 成功/失败热路径上，不该为计数多付一次跨进程往返。
    pub(crate) fn record(&self, provider_id: &str, ip: &str, outcome: OpenCodeIpStatOutcome) {
        let provider_id = provider_id.trim();
        let ip = ip.trim();
        if provider_id.is_empty() || ip.is_empty() {
            return;
        }
        let now = current_unix_secs();
        {
            let mut pending = self.pending.lock();
            let entry = pending
                .entry((provider_id.to_string(), ip.to_string()))
                .or_default();
            match outcome {
                OpenCodeIpStatOutcome::Success => {
                    entry.ok = entry.ok.saturating_add(1);
                    entry.last_ok_at = now;
                }
                OpenCodeIpStatOutcome::Failure(status_code) => {
                    entry.fail = entry.fail.saturating_add(1);
                    entry.last_fail_at = now;
                    let slot = entry
                        .by_status
                        .entry(ipstat_status_bucket(status_code).to_string())
                        .or_insert(0);
                    *slot = slot.saturating_add(1);
                }
            }
        }
        self.flush_signal.notify_one();
    }

    /// 把待写增量读回、与存量相加后写回。返回本次落盘的 IP 数。
    ///
    /// 读放在这里（后台）而不是 `record` 里，是「热路径零往返」的全部秘密；相加而不是
    /// 覆盖，则让进程重启后当天的计数继续累加。
    pub(crate) async fn flush(&self) -> Result<usize, String> {
        let batch = {
            let mut pending = self.pending.lock();
            std::mem::take(&mut *pending)
        };
        if batch.is_empty() {
            return Ok(0);
        }
        let planned: Vec<((String, String), String)> = batch
            .keys()
            .map(|(provider_id, ip)| {
                (
                    (provider_id.clone(), ip.clone()),
                    ipstat_key(provider_id.as_str(), ip.as_str()),
                )
            })
            .collect();
        let keys: Vec<String> = planned.iter().map(|(_, key)| key.clone()).collect();
        let loaded = match self.store.load_many(keys.as_slice()).await {
            Ok(values) => values,
            Err(err) => {
                // 读不回来就放回待写：内存里的计数一条都不丢，下一轮再试。
                self.restore(batch);
                self.failures.fetch_add(1, Ordering::Relaxed);
                return Err(err);
            }
        };
        let mut entries: Vec<(String, String)> = Vec::with_capacity(planned.len());
        for (index, (key_pair, key)) in planned.iter().enumerate() {
            let mut merged = parse_stat(
                loaded
                    .get(index)
                    .and_then(|value| value.as_deref())
                    .map(str::trim),
            );
            if let Some(delta) = batch.get(key_pair) {
                merged.absorb(delta);
            }
            if !merged.has_data() {
                continue;
            }
            match serde_json::to_string(&merged) {
                Ok(payload) => entries.push((key.clone(), payload)),
                Err(err) => {
                    self.restore(batch);
                    self.failures.fetch_add(1, Ordering::Relaxed);
                    return Err(err.to_string());
                }
            }
        }
        if entries.is_empty() {
            return Ok(0);
        }
        self.flushes.fetch_add(1, Ordering::Relaxed);
        let written = entries.len();
        match self.store.store_many(entries, IPSTAT_TTL_SECONDS).await {
            Ok(()) => Ok(written),
            Err(err) => {
                // 写失败同样把增量放回：Redis 抖动过去后这些计数还会补上。
                self.restore(batch);
                self.failures.fetch_add(1, Ordering::Relaxed);
                Err(err)
            }
        }
    }

    /// 读一批 IP 的计数（存量 + 尚未落盘的增量）。只返回真正有数据的 IP。
    ///
    /// 读失败返回 `Err`，由调用方转成「空对象」——状态接口不能因为计数读不到而整体挂掉。
    pub(crate) async fn sample(
        &self,
        provider_id: &str,
        ips: &[String],
    ) -> Result<BTreeMap<String, OpenCodeIpStat>, String> {
        let provider_id = provider_id.trim();
        if provider_id.is_empty() || ips.is_empty() {
            return Ok(BTreeMap::new());
        }
        let keys: Vec<String> = ips
            .iter()
            .map(|ip| ipstat_key(provider_id, ip.trim()))
            .collect();
        let loaded = match self.store.load_many(keys.as_slice()).await {
            Ok(values) => values,
            Err(err) => {
                self.failures.fetch_add(1, Ordering::Relaxed);
                return Err(err);
            }
        };
        let mut stats = BTreeMap::new();
        {
            let pending = self.pending.lock();
            for (index, ip) in ips.iter().enumerate() {
                let ip = ip.trim();
                let mut merged = parse_stat(
                    loaded
                        .get(index)
                        .and_then(|value| value.as_deref())
                        .map(str::trim),
                );
                // 去抖窗口内的记录还没落盘，但面板必须立刻看得见。
                if let Some(delta) = pending.get(&(provider_id.to_string(), ip.to_string())) {
                    merged.absorb(delta);
                }
                if merged.has_data() {
                    stats.insert(ip.to_string(), merged);
                }
            }
        }
        Ok(stats)
    }

    fn restore(&self, batch: BTreeMap<(String, String), OpenCodeIpStat>) {
        let mut pending = self.pending.lock();
        for (key, delta) in batch {
            pending.entry(key).or_default().absorb(&delta);
        }
    }

    /// 后台刷写任务：收到信号 → 去抖 → 批量落盘；失败只记日志（下一轮再试）。
    pub(crate) fn spawn_flusher(self: &Arc<Self>) -> tokio::task::JoinHandle<()> {
        let stats = Arc::clone(self);
        tokio::spawn(async move {
            loop {
                stats.flush_signal.notified().await;
                tokio::time::sleep(FLUSH_DEBOUNCE).await;
                match stats.flush().await {
                    Ok(written) => {
                        tracing::debug!(
                            written,
                            flushes = stats.flush_count(),
                            "opencode exit ip stats persisted"
                        );
                    }
                    Err(err) => {
                        // 持久化层长挂时不要每秒刷一条 warn：前三次 warn（现场看得见），
                        // 之后降到 debug —— 那期间计数一直在内存里，只是面板读不到。
                        if stats.failure_count() <= 3 {
                            tracing::warn!(
                                error = %err,
                                pending_entries = stats.pending_entries(),
                                "opencode exit ip stats could not be persisted; keeping counters in memory"
                            );
                        } else {
                            tracing::debug!(
                                error = %err,
                                pending_entries = stats.pending_entries(),
                                failures = stats.failure_count(),
                                "opencode exit ip stats still cannot be persisted"
                            );
                        }
                    }
                }
            }
        })
    }

    pub(crate) fn pending_entries(&self) -> usize {
        self.pending.lock().len()
    }

    pub(crate) fn flush_count(&self) -> u64 {
        self.flushes.load(Ordering::Relaxed)
    }

    pub(crate) fn failure_count(&self) -> u64 {
        self.failures.load(Ordering::Relaxed)
    }
}

/// 启动期装配入口（`main` 调用）：造持久化层 → 挂到 state → 起后台刷写。
///
/// 三条路径：
/// - 运行时 KV 已经是 Redis → 直接复用它（不额外建连）；
/// - 运行时是内存 → 按冷却镜像同一套环境变量自己连一个 Redis；
/// - 都拿不到 → [`DisabledIpStatStore`]：计数只在内存里累加，接口返回空对象。
///
/// 任何一条失败路径都只 warn，不影响启动。
pub async fn apply_opencode_ip_stats(state: &mut AppState) -> tokio::task::JoinHandle<()> {
    let store: Arc<dyn OpenCodeIpStatStore> = if state.runtime_state().is_redis() {
        tracing::info!("opencode exit ip stats reuse the durable runtime kv backend");
        Arc::new(RuntimeStateIpStatStore::new(Arc::clone(
            &state.runtime_state,
        )))
    } else {
        match crate::opencode_cooldown_persist::durable_redis_target_from_env() {
            Some((url, key_prefix)) => {
                match RuntimeStateIpStatStore::connect(url.as_str(), key_prefix.as_deref()).await {
                    Ok(store) => {
                        tracing::info!(
                            key_prefix = key_prefix.as_deref().unwrap_or("-"),
                            key_prefix_pattern = IPSTAT_KEY_PREFIX,
                            ttl_seconds = IPSTAT_TTL_SECONDS,
                            "opencode exit ip stats enabled"
                        );
                        Arc::new(store)
                    }
                    Err(err) => {
                        tracing::warn!(
                            error = %err,
                            "opencode exit ip stats store unavailable at startup; counters stay in memory"
                        );
                        Arc::new(DisabledIpStatStore)
                    }
                }
            }
            None => {
                tracing::info!("opencode exit ip stats stay in memory: no redis url configured");
                Arc::new(DisabledIpStatStore)
            }
        }
    };
    let stats = Arc::new(OpenCodeIpStats::new(store));
    state.opencode_ip_stats = Some(Arc::clone(&stats));
    stats.spawn_flusher()
}

/// 关服时把待写增量补写一次（去抖窗口里的最后几条也不丢）。
pub async fn flush_opencode_ip_stats(state: &AppState) -> bool {
    let Some(stats) = state.opencode_ip_stats.as_ref() else {
        return false;
    };
    match stats.flush().await {
        Ok(written) => {
            tracing::info!(
                written,
                flushes = stats.flush_count(),
                "flushed opencode exit ip stats before shutdown"
            );
            true
        }
        Err(err) => {
            tracing::warn!(
                error = %err,
                "opencode exit ip stats could not be flushed before shutdown"
            );
            false
        }
    }
}

/// 单测用的内存持久化层：能读到「最后一次落盘的 payload」，也能注入故障。
///
/// 放在模块级（而不是 `mod tests` 里）是为了让 `opencode_rotation` 与状态接口的测试也能
/// 装同一份假实现 —— 那两条断言的是「真实调用点确实写进了计数」。
#[cfg(test)]
#[derive(Default)]
pub(crate) struct TestIpStatStore {
    pub(crate) values: Mutex<BTreeMap<String, String>>,
    /// `store_many` 的**调用次数**（去抖批量写断言就看它）。
    puts: AtomicU64,
    /// 真正写下去的**键数**（批量写大小的断言看它）。
    writes: AtomicU64,
    ttl_seen: Mutex<Vec<u64>>,
    fail_load: AtomicU64,
    fail_store: AtomicU64,
}

#[cfg(test)]
impl TestIpStatStore {
    pub(crate) fn stored(&self, key: &str) -> Option<String> {
        self.values.lock().get(key).cloned()
    }

    pub(crate) fn put_count(&self) -> u64 {
        self.puts.load(Ordering::Relaxed)
    }

    pub(crate) fn write_count(&self) -> u64 {
        self.writes.load(Ordering::Relaxed)
    }

    pub(crate) fn ttls(&self) -> Vec<u64> {
        self.ttl_seen.lock().clone()
    }

    pub(crate) fn fail_loads(&self, fail: bool) {
        self.fail_load.store(u64::from(fail), Ordering::Relaxed);
    }

    pub(crate) fn fail_stores(&self, fail: bool) {
        self.fail_store.store(u64::from(fail), Ordering::Relaxed);
    }
}

#[cfg(test)]
#[async_trait]
impl OpenCodeIpStatStore for TestIpStatStore {
    async fn load_many(&self, keys: &[String]) -> Result<Vec<Option<String>>, String> {
        if self.fail_load.load(Ordering::Relaxed) != 0 {
            return Err("durable store is down".to_string());
        }
        let values = self.values.lock();
        Ok(keys
            .iter()
            .map(|key| values.get(key).cloned())
            .collect::<Vec<_>>())
    }

    async fn store_many(
        &self,
        entries: Vec<(String, String)>,
        ttl_seconds: u64,
    ) -> Result<(), String> {
        if self.fail_store.load(Ordering::Relaxed) != 0 {
            return Err("durable store is down".to_string());
        }
        self.puts.fetch_add(1, Ordering::Relaxed);
        self.ttl_seen.lock().push(ttl_seconds);
        let mut values = self.values.lock();
        for (key, payload) in entries {
            self.writes.fetch_add(1, Ordering::Relaxed);
            values.insert(key, payload);
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn stat_of(stats: &BTreeMap<String, OpenCodeIpStat>, ip: &str) -> OpenCodeIpStat {
        stats.get(ip).cloned().unwrap_or_default()
    }

    /// 成功/失败累加正确，按状态分档正确，最后时刻被写过。
    #[tokio::test]
    async fn success_and_failure_counters_classify_by_status() {
        let store = Arc::new(TestIpStatStore::default());
        let stats = OpenCodeIpStats::new(store.clone());
        let ip = "13.249.64.2";
        stats.record("provider", ip, OpenCodeIpStatOutcome::Success);
        stats.record("provider", ip, OpenCodeIpStatOutcome::Success);
        stats.record("provider", ip, OpenCodeIpStatOutcome::Failure(Some(429)));
        stats.record("provider", ip, OpenCodeIpStatOutcome::Failure(Some(503)));
        stats.record("provider", ip, OpenCodeIpStatOutcome::Failure(Some(503)));
        stats.record("provider", ip, OpenCodeIpStatOutcome::Failure(None));

        let sample = stats
            .sample("provider", &[ip.to_string()])
            .await
            .expect("sample should succeed");
        let stat = stat_of(&sample, ip);
        assert_eq!(stat.ok, 2);
        assert_eq!(stat.fail, 4);
        assert_eq!(stat.by_status.get("429"), Some(&1));
        assert_eq!(stat.by_status.get("503"), Some(&2));
        assert_eq!(stat.by_status.get("other"), Some(&1));
        assert!(stat.last_ok_at > 0, "成功时刻必须被记下来");
        assert!(stat.last_fail_at >= stat.last_ok_at);
    }

    /// 门面转档：429 / 503 / 其它。
    #[test]
    fn status_buckets_are_429_503_and_other() {
        assert_eq!(ipstat_status_bucket(Some(429)), "429");
        assert_eq!(ipstat_status_bucket(Some(503)), "503");
        assert_eq!(ipstat_status_bucket(Some(500)), "other");
        assert_eq!(ipstat_status_bucket(Some(403)), "other");
        assert_eq!(ipstat_status_bucket(None), "other");
    }

    /// `record` 必须是纯内存操作：单测里连 await 都用不上，说明热路径不可能多出一次
    /// 跨进程往返（这条断言靠类型成立，不靠注释）。
    #[test]
    fn record_is_synchronous_without_any_store_io() {
        let store = Arc::new(TestIpStatStore::default());
        let stats = OpenCodeIpStats::new(store.clone());
        for index in 0..25 {
            stats.record(
                "provider",
                format!("108.138.0.{index}").as_str(),
                OpenCodeIpStatOutcome::Failure(Some(429)),
            );
            stats.record(
                "provider",
                format!("108.138.0.{index}").as_str(),
                OpenCodeIpStatOutcome::Success,
            );
        }
        assert_eq!(stats.pending_entries(), 25);
        assert_eq!(store.put_count(), 0, "record 不得触发任何写入");
        assert_eq!(stats.flush_count(), 0, "record 不得触发任何写入");
    }

    /// 去抖批量写：多次记录合并成一次写。
    #[tokio::test]
    async fn debounced_flush_batches_many_records_into_one_write() {
        let store = Arc::new(TestIpStatStore::default());
        let stats = OpenCodeIpStats::new(store.clone());
        for index in 0..10 {
            let ip = format!("108.138.1.{index}");
            stats.record("provider", ip.as_str(), OpenCodeIpStatOutcome::Success);
            stats.record(
                "provider",
                ip.as_str(),
                OpenCodeIpStatOutcome::Failure(Some(429)),
            );
        }
        let written = stats.flush().await.expect("flush should succeed");
        assert_eq!(written, 10);
        assert_eq!(store.put_count(), 1, "20 条记录只落一次盘");
        assert_eq!(store.write_count(), 10, "但十个 IP 各一个键");

        // 再记一次、再刷一次：仍然是一次写，且是读回后相加（跨重启语义）。
        stats.record("provider", "108.138.1.0", OpenCodeIpStatOutcome::Success);
        stats.flush().await.expect("flush should succeed");
        assert_eq!(store.put_count(), 2);
        let raw = store
            .stored(&ipstat_key("provider", "108.138.1.0"))
            .expect("payload written");
        let stat: OpenCodeIpStat = serde_json::from_str(raw.as_str()).expect("valid json");
        assert_eq!(stat.ok, 2, "第二个进程刷写时必须与存量相加");
    }

    /// 后台任务确实会在去抖窗口（1 秒）之后落盘，而且是一批一次写。
    ///
    /// 不用 paused 时钟（本仓的 tokio 没开 `test-util`），所以这里真的等 1 秒多；为了
    /// 不变成 flaky 断言，循环轮询而不是睡死一个固定时长。
    #[tokio::test]
    async fn flusher_persists_after_the_debounce_window() {
        let store = Arc::new(TestIpStatStore::default());
        let stats = Arc::new(OpenCodeIpStats::new(store.clone()));
        let flusher = stats.spawn_flusher();
        stats.record("provider", "1.1.1.1", OpenCodeIpStatOutcome::Success);
        stats.record(
            "provider",
            "1.1.1.2",
            OpenCodeIpStatOutcome::Failure(Some(429)),
        );
        for _ in 0..30 {
            if store.put_count() > 0 {
                break;
            }
            tokio::time::sleep(Duration::from_millis(150)).await;
        }
        assert_eq!(store.put_count(), 1, "去抖窗口过后应当落一次盘");
        assert_eq!(store.write_count(), 2, "两条记录合并进同一次写");
        flusher.abort();
    }

    /// TTL：2 天。
    #[tokio::test]
    async fn flush_uses_the_two_day_ttl() {
        assert_eq!(IPSTAT_TTL_SECONDS, 172_800);
        let store = Arc::new(TestIpStatStore::default());
        let stats = OpenCodeIpStats::new(store.clone());
        stats.record("provider", "2.2.2.2", OpenCodeIpStatOutcome::Success);
        stats.flush().await.expect("flush should succeed");
        assert_eq!(store.ttls(), vec![IPSTAT_TTL_SECONDS]);
    }

    /// 落盘 JSON 的字段形状就是接口承诺的那份。
    #[tokio::test]
    async fn persisted_json_matches_the_documented_shape() {
        let store = Arc::new(TestIpStatStore::default());
        let stats = OpenCodeIpStats::new(store.clone());
        stats.record(
            "provider",
            "3.3.3.3",
            OpenCodeIpStatOutcome::Failure(Some(429)),
        );
        stats.flush().await.expect("flush should succeed");
        let raw = store
            .stored(&ipstat_key("provider", "3.3.3.3"))
            .expect("payload written");
        let value: serde_json::Value = serde_json::from_str(raw.as_str()).expect("valid json");
        assert_eq!(value["ok"], serde_json::json!(0));
        assert_eq!(value["fail"], serde_json::json!(1));
        assert_eq!(value["by_status"]["429"], serde_json::json!(1));
        assert!(value["last_ok_at"].is_u64());
        assert!(value["last_fail_at"].as_u64().unwrap_or(0) > 0);
    }

    /// Redis 不可用：计数进内存、刷写只报错、接口侧转成空对象（而不是整体失败）。
    #[tokio::test]
    async fn store_outage_keeps_counting_in_memory() {
        let store = Arc::new(TestIpStatStore::default());
        store.fail_loads(true);
        store.fail_stores(true);
        let stats = OpenCodeIpStats::new(store.clone());
        stats.record(
            "provider",
            "4.4.4.4",
            OpenCodeIpStatOutcome::Failure(Some(503)),
        );
        assert!(stats.flush().await.is_err());
        assert!(stats
            .sample("provider", &["4.4.4.4".to_string()])
            .await
            .is_err());
        assert_eq!(stats.failure_count(), 2);
        assert_eq!(stats.pending_entries(), 1, "增量必须留在内存里");

        // Redis 恢复后同一批计数补写成功。
        store.fail_loads(false);
        store.fail_stores(false);
        let written = stats.flush().await.expect("flush should recover");
        assert_eq!(written, 1);
        let raw = store
            .stored(&ipstat_key("provider", "4.4.4.4"))
            .expect("payload written");
        let stat: OpenCodeIpStat = serde_json::from_str(raw.as_str()).expect("valid json");
        assert_eq!(stat.fail, 1);
        assert_eq!(stat.by_status.get("503"), Some(&1));
    }

    /// 完全没配置持久化层：读返回空对象、写在内存里继续，不 panic 不阻塞。
    #[tokio::test]
    async fn disabled_store_reports_empty_instead_of_failing_the_status_call() {
        let stats = OpenCodeIpStats::new(Arc::new(DisabledIpStatStore));
        stats.record("provider", "5.5.5.5", OpenCodeIpStatOutcome::Success);
        let sample = stats.sample("provider", &["5.5.5.5".to_string()]).await;
        assert!(sample.is_err(), "调用方据此回空对象");
        assert!(stats.flush().await.is_err());
        assert_eq!(stats.pending_entries(), 1);
    }

    /// 坏数据按「什么都没有」处理，并被下一次刷写覆盖成合法 JSON。
    #[tokio::test]
    async fn corrupt_payload_is_treated_as_empty() {
        let store = Arc::new(TestIpStatStore::default());
        let key = ipstat_key("provider", "6.6.6.6");
        store
            .values
            .lock()
            .insert(key.clone(), "{not json".to_string());
        let stats = OpenCodeIpStats::new(store.clone());
        let sample = stats
            .sample("provider", &["6.6.6.6".to_string()])
            .await
            .expect("sample should succeed");
        assert!(sample.is_empty(), "坏数据要当没有，而不是当 1 条失败");

        stats.record("provider", "6.6.6.6", OpenCodeIpStatOutcome::Success);
        stats.flush().await.expect("flush should succeed");
        let raw = store.stored(&key).expect("payload rewritten");
        let stat: OpenCodeIpStat = serde_json::from_str(raw.as_str()).expect("valid json");
        assert_eq!(stat.ok, 1);
    }

    /// 只回有数据的 IP：池里干净节点的键根本不该出现在响应里。
    #[tokio::test]
    async fn sample_only_returns_ips_with_counters() {
        let store = Arc::new(TestIpStatStore::default());
        let stats = OpenCodeIpStats::new(store.clone());
        stats.record("provider", "7.7.7.1", OpenCodeIpStatOutcome::Success);
        let sample = stats
            .sample(
                "provider",
                &[
                    "7.7.7.1".to_string(),
                    "7.7.7.2".to_string(),
                    "7.7.7.3".to_string(),
                ],
            )
            .await
            .expect("sample should succeed");
        assert_eq!(sample.len(), 1);
        assert!(sample.contains_key("7.7.7.1"));
    }

    /// 真实 Redis 路径（没有 redis-server 时跳过）：批量写进去、TTL 是 2 天、换一个新
    /// 实例只从 Redis 读回来。
    #[tokio::test]
    async fn redis_backed_store_round_trips_and_sets_ttl() {
        let redis = match aether_test_support::ManagedRedisServer::start().await {
            Ok(server) => server,
            Err(err) if aether_testkit::is_missing_binary_error(err.as_ref()) => {
                eprintln!("skipping redis-backed opencode ip stat test: {err}");
                return;
            }
            Err(err) => panic!("start Redis: {err}"),
        };
        let store = Arc::new(
            RuntimeStateIpStatStore::connect(redis.redis_url(), Some("opencode-ipstat-test"))
                .await
                .expect("connect redis store"),
        );
        let writer = OpenCodeIpStats::new(store.clone());
        writer.record(
            "provider-x",
            "18.154.128.1",
            OpenCodeIpStatOutcome::Failure(Some(429)),
        );
        writer.flush().await.expect("flush to redis");

        let ttl = store
            .state
            .kv_ttl_seconds(ipstat_key("provider-x", "18.154.128.1").as_str())
            .await
            .expect("ttl should be readable")
            .expect("key should exist");
        assert!(
            (172_000..=172_800).contains(&ttl),
            "TTL 必须是 2 天，实际 {ttl}"
        );

        // 「重启」：新实例、只有 Redis 里的那份计数可用，且继续累加。
        let reader = OpenCodeIpStats::new(store.clone());
        let sample = reader
            .sample("provider-x", &["18.154.128.1".to_string()])
            .await
            .expect("load from redis");
        assert_eq!(stat_of(&sample, "18.154.128.1").fail, 1);
        reader.record("provider-x", "18.154.128.1", OpenCodeIpStatOutcome::Success);
        reader.flush().await.expect("flush second process");
        let sample = reader
            .sample("provider-x", &["18.154.128.1".to_string()])
            .await
            .expect("load from redis");
        let stat = stat_of(&sample, "18.154.128.1");
        assert_eq!(stat.ok, 1);
        assert_eq!(stat.fail, 1);
    }

    /// 连不上 Redis 必须变成一个 `Err`（由装配处降级），不能 panic、不能挂住。
    #[tokio::test]
    async fn unreachable_redis_is_reported_as_an_error() {
        let started = std::time::Instant::now();
        let result =
            RuntimeStateIpStatStore::connect("redis://127.0.0.1:1/0", Some("degrade")).await;
        assert!(result.is_err(), "连不上时必须返回错误供调用方降级");
        assert!(
            started.elapsed() < Duration::from_secs(10),
            "连接失败必须快速返回，不能把启动拖住"
        );
    }
}
