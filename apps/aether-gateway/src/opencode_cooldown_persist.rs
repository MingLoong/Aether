//! opencode 出口 IP「配额冷却 / 短期回避」状态的**持久化镜像**。
//!
//! 为什么要这份镜像：冷却判定落在运行时 KV 上
//! （`opencode_pool:cooldown:<provider>:<ip>` / `opencode_pool:avoid:<provider>:<ip>`），
//! 而生产机的运行时后端是 `memory` —— 掩码只活在进程内存里。2026-10-22 01:29 的一次
//! 部署重启把 17 分钟内被打成 6 小时冷却的 124 个出口 IP 一次性放回池子，紧接着它们
//! 又全部撞上同一个 429，于是按上游 `Retry-After` 又被钉了一遍。
//!
//! 这里只做一件事：把掩码额外抄一份到**独立的持久化 KV**（当前实现是 Redis），启动时
//! 把未到期的那部分回填进运行时 KV。运行时 KV 本身不动 —— 不切后端、不改任何冷却
//! 语义（TTL 计算、`retry-after` 对齐、60 分钟默认值都在原处），只是给「重启会丢」
//! 这件事补一个落点。运行时后端已经是 Redis 时这份镜像没有意义，调用方会跳过它。
//!
//! 三条硬约束：
//! - **热路径不加同步往返**：[`OpenCodeCooldownPersist::record`] 是**同步**函数，只更新
//!   内存快照并唤醒后台刷写任务；真正的写发生在
//!   [`OpenCodeCooldownPersist::spawn_flusher`] 的后台任务里，带去抖（一次 429 风暴里
//!   几十条记录只落一次盘）。失败路径上原本那次 `runtime_kv_setex` 一次都不用多付。
//! - **过期项不堆积**：写盘与加载都过滤已过期条目，加载后还会把清理过的快照写回。
//! - **持久化层不可用就降级**：没配置、连不上、读失败、写失败都只记日志 —— 启动不失败，
//!   判定照旧只看运行时 KV（即改动前的行为）。

use std::collections::BTreeMap;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::Duration;

use async_trait::async_trait;
use parking_lot::Mutex;
use tokio::sync::Notify;

use crate::clock::current_unix_ms;
use crate::AppState;

/// 持久化快照的键（落到 Redis 时还会带上实例命名空间前缀）。
const PERSIST_KEY: &str = "opencode_pool:persist:masks";
/// 快照自身的存活时间：远长于最长掩码（配额冷却 10 分钟 = `MAX_OPENCODE_COOLDOWN_SECONDS`、
/// 短期回避 3 分钟、suspect 最长按配置的分钟级），
/// 只要还有一条掩码没到期，这个键就不会先过期。
pub(crate) const PERSIST_TTL_SECONDS: u64 = 7 * 24 * 60 * 60;
/// 后台刷写的去抖窗口。
///
/// 429 风暴里几秒内会写下几十条掩码：逐条落盘等于把写入放大成几十次往返。去抖把同一
/// 窗口里的记录合并成一次写入，代价是「写入后 200ms 内进程被 kill」会丢这一条 —— 与
/// 「整个进程重启后全丢」相比可以接受。
const FLUSH_DEBOUNCE: Duration = Duration::from_millis(200);
/// 单条 Redis 命令的超时（沿用运行时 KV 的口径）。
const COMMAND_TIMEOUT_MS: u64 = 1_000;

/// 环境变量：`off` / `redis` / `auto`（默认）。
pub(crate) const PERSIST_MODE_ENV: &str = "AETHER_OPENCODE_COOLDOWN_PERSIST";
/// 环境变量：持久化层的 Redis URL（缺省回落到运行时/数据层那几个）。
pub(crate) const PERSIST_REDIS_URL_ENV: &str = "AETHER_OPENCODE_COOLDOWN_PERSIST_REDIS_URL";
/// 环境变量：持久化层的 Redis key 前缀（缺省回落到运行时那几个）。
pub(crate) const PERSIST_REDIS_KEY_PREFIX_ENV: &str =
    "AETHER_OPENCODE_COOLDOWN_PERSIST_REDIS_KEY_PREFIX";

/// 掩码种类。两种掩码的键空间、TTL 下限都在 `opencode_rotation` 里，这里只负责搬运。
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum OpenCodeMaskKind {
    /// 配额型冷却（429 / 免费额度耗尽的 403），**固定短冷却**（默认 120 秒，上限 600 秒）。
    Cooldown,
    /// 瞬时/上游全局失败的短期回避，分钟级。
    Avoid,
}

/// 从持久化层读回来的一条掩码（时间戳是绝对到期时刻，与进程启动时刻无关）。
#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct PersistedOpenCodeMask {
    pub(crate) kind: OpenCodeMaskKind,
    pub(crate) provider_id: String,
    pub(crate) ip: String,
    pub(crate) expires_at_ms: u64,
}

/// 落盘的快照结构。
///
/// `provider_id -> ip -> 到期时间戳(ms)`：绝对时间戳而不是剩余 TTL，这样重启后回填的
/// 剩余时长天然正确，不需要知道上次写入发生在什么时候。
#[derive(Debug, Default, Clone, serde::Serialize, serde::Deserialize)]
struct PersistPayload {
    #[serde(default)]
    version: u32,
    #[serde(default)]
    cooldowns: BTreeMap<String, BTreeMap<String, u64>>,
    #[serde(default)]
    avoids: BTreeMap<String, BTreeMap<String, u64>>,
}

const PERSIST_PAYLOAD_VERSION: u32 = 1;

impl PersistPayload {
    fn from_tables(tables: &MaskTables, now_ms: u64) -> Self {
        let mut payload = Self {
            version: PERSIST_PAYLOAD_VERSION,
            ..Self::default()
        };
        for ((provider_id, ip), expires_at_ms) in tables.cooldowns.iter() {
            if *expires_at_ms > now_ms {
                payload
                    .cooldowns
                    .entry(provider_id.clone())
                    .or_default()
                    .insert(ip.clone(), *expires_at_ms);
            }
        }
        for ((provider_id, ip), expires_at_ms) in tables.avoids.iter() {
            if *expires_at_ms > now_ms {
                payload
                    .avoids
                    .entry(provider_id.clone())
                    .or_default()
                    .insert(ip.clone(), *expires_at_ms);
            }
        }
        payload
    }

    /// 取出**未到期**的掩码，并统计丢弃了多少条已过期的。
    fn into_masks(self, now_ms: u64) -> (Vec<PersistedOpenCodeMask>, usize) {
        let mut masks = Vec::new();
        let mut pruned = 0usize;
        let mut collect = |kind: OpenCodeMaskKind,
                           table: BTreeMap<String, BTreeMap<String, u64>>,
                           masks: &mut Vec<PersistedOpenCodeMask>| {
            for (provider_id, entries) in table {
                for (ip, expires_at_ms) in entries {
                    if expires_at_ms > now_ms {
                        masks.push(PersistedOpenCodeMask {
                            kind,
                            provider_id: provider_id.clone(),
                            ip,
                            expires_at_ms,
                        });
                    } else {
                        pruned += 1;
                    }
                }
            }
        };
        collect(OpenCodeMaskKind::Cooldown, self.cooldowns, &mut masks);
        collect(OpenCodeMaskKind::Avoid, self.avoids, &mut masks);
        (masks, pruned)
    }
}

/// 内存里的当前快照（键是 `(provider_id, ip)`，值是绝对到期时间戳）。
#[derive(Debug, Default)]
struct MaskTables {
    cooldowns: BTreeMap<(String, String), u64>,
    avoids: BTreeMap<(String, String), u64>,
}

impl MaskTables {
    fn mask_key(provider_id: &str, ip: &str) -> (String, String) {
        (provider_id.to_string(), ip.to_string())
    }

    fn table_mut(&mut self, kind: OpenCodeMaskKind) -> &mut BTreeMap<(String, String), u64> {
        match kind {
            OpenCodeMaskKind::Cooldown => &mut self.cooldowns,
            OpenCodeMaskKind::Avoid => &mut self.avoids,
        }
    }

    fn upsert(&mut self, kind: OpenCodeMaskKind, provider_id: &str, ip: &str, expires_at_ms: u64) {
        let key = Self::mask_key(provider_id, ip);
        self.table_mut(kind).insert(key, expires_at_ms);
    }

    fn prune(&mut self, now_ms: u64) -> usize {
        let before = self.cooldowns.len() + self.avoids.len();
        self.cooldowns.retain(|_, expires| *expires > now_ms);
        self.avoids.retain(|_, expires| *expires > now_ms);
        before - self.cooldowns.len() - self.avoids.len()
    }

    fn len(&self) -> usize {
        self.cooldowns.len() + self.avoids.len()
    }
}

/// 持久化层抽象。抽成 trait 是为了让「层不可用」和「热路径没有同步往返」都能在单测里
/// 直接断言，而不必依赖一个真 Redis。
#[async_trait]
pub(crate) trait OpenCodeMaskDurableStore: Send + Sync + 'static {
    /// 读快照；`None` 表示从来没写过。
    async fn load_payload(&self) -> Result<Option<String>, String>;
    /// 写快照（整份覆盖），`ttl_seconds` 是快照自身的存活时间。
    async fn store_payload(&self, payload: String, ttl_seconds: u64) -> Result<(), String>;
}

/// 把掩码镜像到 Redis 的实现。
///
/// 这里**不直接碰 Redis 客户端**：只持有一个独立的、Redis 后端的
/// [`aether_runtime_state::RuntimeState`] 实例，并且只使用它的 KV 接口
/// （`kv_get` / `kv_set` / `kv_delete` …）。键位命名空间、连接超时、错误归类因此与别处的
/// 运行时 KV 完全同源 —— Redis 访问权仍然只属于 runtime-state 这一层。
struct RedisOpenCodeMaskStore {
    state: aether_runtime_state::RuntimeState,
}

impl RedisOpenCodeMaskStore {
    /// 用持久化层自己的 Redis URL / key 前缀，经 runtime-state 的公开构造入口造一个
    /// **独占**的 Redis 后端 `RuntimeState`。构造过程本身就包含建连与 `PING`，所以
    /// 连不上会立刻返回 `Err`，由调用方降级成内存态。
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
        Ok(Self { state })
    }
}

#[async_trait]
impl OpenCodeMaskDurableStore for RedisOpenCodeMaskStore {
    async fn load_payload(&self) -> Result<Option<String>, String> {
        self.state
            .kv_get(PERSIST_KEY)
            .await
            .map_err(|err| err.to_string())
    }

    async fn store_payload(&self, payload: String, ttl_seconds: u64) -> Result<(), String> {
        // `kv_set` + 显式 TTL 就是原来的 `SETEX`（runtime-state 内部走 PSETEX，秒级 TTL
        // 换算成等价的毫秒值），快照自身 7 天到期这一点保持不变。
        self.state
            .kv_set(
                PERSIST_KEY,
                payload,
                Some(Duration::from_secs(ttl_seconds.max(1))),
            )
            .await
            .map_err(|err| err.to_string())
    }
}

/// 冷却/回避掩码的持久化镜像。
pub(crate) struct OpenCodeCooldownPersist {
    durable: Arc<dyn OpenCodeMaskDurableStore>,
    tables: Mutex<MaskTables>,
    flush_signal: Notify,
    flushes: AtomicU64,
    failures: AtomicU64,
}

impl std::fmt::Debug for OpenCodeCooldownPersist {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("OpenCodeCooldownPersist")
            .field("pending_entries", &self.pending_entries())
            .field("flushes", &self.flush_count())
            .field("failures", &self.failure_count())
            .finish()
    }
}

impl OpenCodeCooldownPersist {
    pub(crate) fn new(durable: Arc<dyn OpenCodeMaskDurableStore>) -> Self {
        Self {
            durable,
            tables: Mutex::new(MaskTables::default()),
            flush_signal: Notify::new(),
            flushes: AtomicU64::new(0),
            failures: AtomicU64::new(0),
        }
    }

    /// 读环境变量构造持久化层。
    ///
    /// 返回 `None` 的三种情形都等于「保持改动前的行为」：显式 `off`、没有任何可用的
    /// Redis URL、或连接失败（只 warn，不阻断启动）。
    pub(crate) async fn from_env() -> Option<Arc<Self>> {
        match persist_mode_from_env().as_str() {
            "off" => {
                tracing::info!(
                    environment_variable = PERSIST_MODE_ENV,
                    "opencode cooldown persistence disabled by configuration"
                );
                return None;
            }
            "redis" | "auto" => {}
            other => {
                tracing::warn!(
                    environment_variable = PERSIST_MODE_ENV,
                    value = other,
                    "unknown opencode cooldown persistence mode; expected off, redis, or auto"
                );
                return None;
            }
        }
        let Some(url) = persist_redis_url_from_env() else {
            tracing::info!(
                "opencode cooldown persistence stays in memory: no redis url configured"
            );
            return None;
        };
        let key_prefix = persist_redis_key_prefix_from_env();
        match RedisOpenCodeMaskStore::connect(url.as_str(), key_prefix.as_deref()).await {
            Ok(durable) => {
                tracing::info!(
                    redis_url_configured = true,
                    key_prefix = key_prefix.as_deref().unwrap_or("-"),
                    key = PERSIST_KEY,
                    "opencode cooldown persistence enabled"
                );
                Some(Arc::new(Self::new(Arc::new(durable))))
            }
            Err(err) => {
                tracing::warn!(
                    error = %err,
                    "opencode cooldown persistence unavailable at startup; falling back to memory-only cooldowns"
                );
                None
            }
        }
    }

    /// 记一条掩码。
    ///
    /// **同步、无 IO**：只更新内存快照 + 唤醒后台刷写。故意不是 `async` —— 调用点
    /// （`mark_key_cooldown_seconds` / `mark_key_avoid_seconds`）已经在失败路径上了，
    /// 不该为持久化再多一次跨进程往返。
    pub(crate) fn record(
        &self,
        kind: OpenCodeMaskKind,
        provider_id: &str,
        ip: &str,
        ttl_seconds: u64,
    ) {
        if ip.trim().is_empty() || ttl_seconds == 0 {
            return;
        }
        let expires_at_ms = current_unix_ms().saturating_add(ttl_seconds.saturating_mul(1_000));
        self.tables
            .lock()
            .upsert(kind, provider_id, ip.trim(), expires_at_ms);
        self.flush_signal.notify_one();
    }

    /// 把当前快照写进持久化层（顺手丢掉已过期项）。返回写入的条目数。
    pub(crate) async fn flush(&self) -> Result<usize, String> {
        let payload = {
            let mut tables = self.tables.lock();
            tables.prune(current_unix_ms());
            let payload = PersistPayload::from_tables(&tables, current_unix_ms());
            serde_json::to_string(&payload).map_err(|err| err.to_string())?
        };
        self.flushes.fetch_add(1, Ordering::Relaxed);
        match self
            .durable
            .store_payload(payload, PERSIST_TTL_SECONDS)
            .await
        {
            Ok(()) => Ok(self.pending_entries()),
            Err(err) => {
                self.failures.fetch_add(1, Ordering::Relaxed);
                Err(err)
            }
        }
    }

    /// 读持久化快照，把**未到期**的条目装进内存快照并返回它们。
    ///
    /// 已过期条目在这里被丢掉（第二个返回值是丢弃条数），调用方随后调用一次
    /// [`Self::flush`] 就能把清理后的快照写回，不留堆积。
    pub(crate) async fn load(&self) -> Result<(Vec<PersistedOpenCodeMask>, usize), String> {
        let loaded = match self.durable.load_payload().await {
            Ok(payload) => payload,
            Err(err) => {
                self.failures.fetch_add(1, Ordering::Relaxed);
                return Err(err);
            }
        };
        let Some(raw) = loaded else {
            return Ok((Vec::new(), 0));
        };
        let payload: PersistPayload = match serde_json::from_str(raw.trim()) {
            Ok(payload) => payload,
            Err(err) => {
                self.failures.fetch_add(1, Ordering::Relaxed);
                return Err(format!(
                    "persisted opencode mask snapshot is not valid json: {err}"
                ));
            }
        };
        let now_ms = current_unix_ms();
        let (masks, pruned) = payload.into_masks(now_ms);
        {
            let mut tables = self.tables.lock();
            tables.prune(now_ms);
            for mask in masks.iter() {
                tables.upsert(
                    mask.kind,
                    mask.provider_id.as_str(),
                    mask.ip.as_str(),
                    mask.expires_at_ms,
                );
            }
        }
        Ok((masks, pruned))
    }

    /// 后台刷写任务：收到信号 → 去抖 → 落盘；失败只记日志（下一轮还会再试）。
    pub(crate) fn spawn_flusher(self: &Arc<Self>) -> tokio::task::JoinHandle<()> {
        let persist = Arc::clone(self);
        tokio::spawn(async move {
            loop {
                persist.flush_signal.notified().await;
                // 去抖：把同一窗口里的记录合并成一次写入。
                tokio::time::sleep(FLUSH_DEBOUNCE).await;
                let pending = persist.pending_entries();
                match persist.flush().await {
                    Ok(_) => {
                        tracing::debug!(
                            entries = pending,
                            flushes = persist.flush_count(),
                            "opencode cooldown masks persisted"
                        );
                    }
                    Err(err) => {
                        tracing::warn!(
                            error = %err,
                            entries = pending,
                            "opencode cooldown masks could not be persisted; keeping in-memory state"
                        );
                    }
                }
            }
        })
    }

    /// 当前快照里（未清理过期项前）的条目数，供日志与测试观测。
    pub(crate) fn pending_entries(&self) -> usize {
        self.tables.lock().len()
    }

    pub(crate) fn flush_count(&self) -> u64 {
        self.flushes.load(Ordering::Relaxed)
    }

    pub(crate) fn failure_count(&self) -> u64 {
        self.failures.load(Ordering::Relaxed)
    }
}

/// 启动期装配入口（`main` 调用）：建镜像 → 挂到 state → 回填未到期掩码 → 起后台刷写。
///
/// 返回的 `JoinHandle` 交给调用方持有：丢掉它任务会脱离并被继续跑，但让 `main` 一直
/// 攥着更符合本仓其它后台任务的写法。
///
/// 返回 `None` 的所有路径都等于「保持改动前的行为」：
/// - 运行时 KV 已经是 Redis（掩码本来就持久，镜像多余）；
/// - 显式关掉、没配 Redis URL、启动期连不上、或根本没有 TTL 键要持久化时的任何失败。
pub async fn apply_opencode_mask_persistence(
    state: &mut AppState,
) -> Option<tokio::task::JoinHandle<()>> {
    if !state.runtime_state().is_memory() {
        tracing::info!(
            runtime_backend = state.runtime_state().backend_kind().as_str(),
            "opencode cooldown persistence is not needed: runtime state backend is already durable"
        );
        return None;
    }
    let persist = OpenCodeCooldownPersist::from_env().await?;
    state.opencode_mask_persist = Some(Arc::clone(&persist));
    let restored =
        crate::opencode_rotation::restore_persisted_opencode_masks(state, &persist).await;
    let flusher = persist.spawn_flusher();
    tracing::info!(
        restored,
        pending_entries = persist.pending_entries(),
        "opencode cooldown masks are mirrored to the durable store"
    );
    Some(flusher)
}

/// 关服时把内存快照补写一次。
///
/// 部署重启是**优雅重启**（SIGTERM → 排空 → 退出），这一步让「最后一次记录还躺在去抖
/// 窗口里」的那几条掩码也不丢。没装配镜像时什么都不做，返回 `false`。
pub async fn flush_opencode_mask_persistence(state: &AppState) -> bool {
    let Some(persist) = state.opencode_mask_persist.as_ref() else {
        return false;
    };
    match persist.flush().await {
        Ok(entries) => {
            tracing::info!(
                entries,
                flushes = persist.flush_count(),
                "flushed opencode cooldown masks before shutdown"
            );
            true
        }
        Err(err) => {
            tracing::warn!(
                error = %err,
                "opencode cooldown masks could not be flushed before shutdown"
            );
            false
        }
    }
}

fn env_trimmed(name: &str) -> Option<String> {
    std::env::var(name)
        .ok()
        .map(|value| value.trim().to_string())
        .filter(|value| !value.is_empty())
}

fn persist_mode_from_env() -> String {
    env_trimmed(PERSIST_MODE_ENV)
        .unwrap_or_else(|| "auto".to_string())
        .to_ascii_lowercase()
}

/// 持久化层该连哪个 Redis（URL + key 前缀），供遵守同一套落盘约定的其它镜像复用
/// （当前是 `opencode_ip_stats` 的出口 IP 成功/失败计数）。
///
/// 两处共用同一个解析顺序，是为了「配一次就两处都生效」：否则多一个落盘点，就要多猜
/// 一组环境变量名。
pub(crate) fn durable_redis_target_from_env() -> Option<(String, Option<String>)> {
    let url = persist_redis_url_from_env()?;
    Some((url, persist_redis_key_prefix_from_env()))
}

fn persist_redis_url_from_env() -> Option<String> {
    env_trimmed(PERSIST_REDIS_URL_ENV)
        .or_else(|| env_trimmed("AETHER_RUNTIME_REDIS_URL"))
        .or_else(|| env_trimmed("AETHER_GATEWAY_DATA_REDIS_URL"))
        .or_else(|| env_trimmed("REDIS_URL"))
}

fn persist_redis_key_prefix_from_env() -> Option<String> {
    env_trimmed(PERSIST_REDIS_KEY_PREFIX_ENV)
        .or_else(|| env_trimmed("AETHER_RUNTIME_REDIS_KEY_PREFIX"))
        .or_else(|| env_trimmed("AETHER_GATEWAY_DATA_REDIS_KEY_PREFIX"))
}

/// 单测用的内存持久化层：可以在任意时刻读到「最后一次落盘的 payload」，也能注入故障。
///
/// 放在模块级（而不是 `mod tests` 里）是因为 `opencode_rotation` 的重启回填测试也要用
/// 同一份假实现——那条测试断言的是「写入 → 换一个新进程的 state → 回填后判定仍然成立」。
#[cfg(test)]
#[derive(Default)]
pub(crate) struct TestMaskDurableStore {
    pub(crate) payload: Mutex<Option<String>>,
    puts: AtomicU64,
    fail_load: AtomicU64,
    fail_store: AtomicU64,
}

#[cfg(test)]
impl TestMaskDurableStore {
    pub(crate) fn stored_payload(&self) -> Option<String> {
        self.payload.lock().clone()
    }

    pub(crate) fn set_stored_payload(&self, payload: String) {
        *self.payload.lock() = Some(payload);
    }

    pub(crate) fn put_count(&self) -> u64 {
        self.puts.load(Ordering::Relaxed)
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
impl OpenCodeMaskDurableStore for TestMaskDurableStore {
    async fn load_payload(&self) -> Result<Option<String>, String> {
        if self.fail_load.load(Ordering::Relaxed) != 0 {
            return Err("durable store is down".to_string());
        }
        Ok(self.stored_payload())
    }

    async fn store_payload(&self, payload: String, _ttl_seconds: u64) -> Result<(), String> {
        if self.fail_store.load(Ordering::Relaxed) != 0 {
            return Err("durable store is down".to_string());
        }
        self.puts.fetch_add(1, Ordering::Relaxed);
        self.set_stored_payload(payload);
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// `record` 必须是纯内存操作：单测里连 await 都用不上，说明热路径不可能多出
    /// 一次跨进程往返（这条断言靠类型成立，不靠注释）。
    #[test]
    fn record_is_synchronous_and_batched() {
        let durable = Arc::new(TestMaskDurableStore::default());
        let persist = OpenCodeCooldownPersist::new(durable.clone());
        for index in 0..25 {
            persist.record(
                OpenCodeMaskKind::Cooldown,
                "provider",
                format!("108.138.0.{index}").as_str(),
                3_600,
            );
        }
        assert_eq!(persist.pending_entries(), 25);
        assert_eq!(durable.put_count(), 0, "record 不得触发任何写入");
        assert_eq!(persist.flush_count(), 0, "record 不得触发任何写入");
    }

    #[tokio::test]
    async fn record_batches_into_a_single_write() {
        let durable = Arc::new(TestMaskDurableStore::default());
        let persist = OpenCodeCooldownPersist::new(durable.clone());
        for index in 0..10 {
            persist.record(
                OpenCodeMaskKind::Cooldown,
                "provider",
                format!("108.138.1.{index}").as_str(),
                600,
            );
        }
        let written = persist.flush().await.expect("flush should succeed");
        assert_eq!(written, 10);
        assert_eq!(durable.put_count(), 1, "10 条记录只落一次盘");
    }

    #[tokio::test]
    async fn expired_masks_are_pruned_on_write_and_load() {
        let durable = Arc::new(TestMaskDurableStore::default());
        let persist = OpenCodeCooldownPersist::new(durable.clone());
        persist.record(OpenCodeMaskKind::Cooldown, "provider", "1.1.1.1", 600);
        persist.flush().await.expect("flush should succeed");

        // 手工把一条记录改成「已过期」，模拟停机期间自然到期。
        let payload = durable.stored_payload().expect("payload written");
        let mut value: serde_json::Value = serde_json::from_str(payload.as_str()).unwrap();
        value["cooldowns"]["provider"]["1.1.1.1"] = serde_json::Value::from(1_000u64);
        value["cooldowns"]["provider"]["2.2.2.2"] = serde_json::Value::from(u64::MAX / 2);
        durable.set_stored_payload(value.to_string());

        let fresh = OpenCodeCooldownPersist::new(durable.clone());
        let (masks, pruned) = fresh.load().await.expect("load should succeed");
        assert_eq!(pruned, 1, "已过期的那条必须在加载时丢掉");
        assert_eq!(masks.len(), 1);
        assert_eq!(masks[0].ip, "2.2.2.2");

        // 清理后的快照写回，持久化层里不再留下过期项。
        fresh.flush().await.expect("flush should succeed");
        let rewritten = durable.stored_payload().expect("payload rewritten");
        assert!(!rewritten.contains("1.1.1.1"));
        assert!(rewritten.contains("2.2.2.2"));
    }

    #[tokio::test]
    async fn durable_store_failures_do_not_break_the_recorder() {
        let durable = Arc::new(TestMaskDurableStore::default());
        durable.fail_stores(true);
        durable.fail_loads(true);
        let persist = OpenCodeCooldownPersist::new(durable.clone());

        persist.record(OpenCodeMaskKind::Avoid, "provider", "3.3.3.3", 180);
        assert!(persist.flush().await.is_err());
        assert!(persist.load().await.is_err());
        assert_eq!(persist.failure_count(), 2);
        // 内存快照仍在：判定不受持久化层影响。
        assert_eq!(persist.pending_entries(), 1);
    }

    #[tokio::test]
    async fn missing_snapshot_loads_as_empty() {
        let durable = Arc::new(TestMaskDurableStore::default());
        let persist = OpenCodeCooldownPersist::new(durable);
        let (masks, pruned) = persist.load().await.expect("load should succeed");
        assert!(masks.is_empty());
        assert_eq!(pruned, 0);
    }

    /// 连不上 Redis 必须变成一个 `Err`（由调用方降级为内存态），不能 panic、不能挂住。
    #[tokio::test]
    async fn unreachable_redis_is_reported_as_an_error() {
        let started = std::time::Instant::now();
        // 端口 1 上不会有 Redis：连接被立刻拒绝。
        let result =
            RedisOpenCodeMaskStore::connect("redis://127.0.0.1:1/0", Some("degrade")).await;
        assert!(result.is_err(), "连不上时必须返回错误供调用方降级");
        assert!(
            started.elapsed() < std::time::Duration::from_secs(10),
            "连接失败必须快速返回，不能把启动拖住"
        );
    }

    /// 真实 Redis 路径（没有 redis-server 时跳过）：写进去、换一个新实例只从 Redis 读回来。
    ///
    /// 假实现只能证明「搬运逻辑对」，这条才证明运行时状态层那条路真的能用
    /// （带 TTL 的写 + 命名空间前缀 + 读）。
    #[tokio::test]
    async fn redis_backed_store_round_trips_the_snapshot() {
        let redis = match aether_test_support::ManagedRedisServer::start().await {
            Ok(server) => server,
            Err(err) if aether_testkit::is_missing_binary_error(err.as_ref()) => {
                eprintln!("skipping redis-backed opencode mask test: {err}");
                return;
            }
            Err(err) => panic!("start Redis: {err}"),
        };
        let store: Arc<dyn OpenCodeMaskDurableStore> = Arc::new(
            RedisOpenCodeMaskStore::connect(redis.redis_url(), Some("opencode-mask-persist-test"))
                .await
                .expect("connect redis store"),
        );
        assert!(store.load_payload().await.expect("load empty").is_none());

        let writer = OpenCodeCooldownPersist::new(Arc::clone(&store));
        writer.record(
            OpenCodeMaskKind::Cooldown,
            "provider-x",
            "18.154.128.1",
            3_600,
        );
        writer.flush().await.expect("flush to redis");

        // 「重启」：新实例、只有 Redis 里的那份快照可用。
        let reader = OpenCodeCooldownPersist::new(Arc::clone(&store));
        let (masks, pruned) = reader.load().await.expect("load from redis");
        assert_eq!(pruned, 0);
        assert_eq!(masks.len(), 1);
        assert_eq!(masks[0].provider_id, "provider-x");
        assert_eq!(masks[0].ip, "18.154.128.1");
        assert!(masks[0].expires_at_ms > current_unix_ms());
    }
}
