//! OpenCode 出口 IP 池的游标轮转、会话粘性与额度熔断。
//!
//! 与调度器内置排序的关系：调度器把候选排成**全序**（末尾用 key_id 兜底拆开，
//! 不存在并列），并且 planner 会在 scheduler 之后**再排一次**，真正决定选哪个 key
//! 的是 planner 层的 `candidates.first()`。因此本模块只提供与排序无关、
//! 可独立复用的能力：
//!
//! 1. 轮转游标：跨进程单调递增的整数（Redis kv，原子 GET+DEL 后写回）。
//! 2. 额度熔断：某个出口 IP 触发 403 FreeTierError / 429 后进入冷却，冷却期内被排除。
//! 3. 锚点选择：[`pick_anchor_ip`] 先按会话粘性（[`pick_session_anchor`]）挑，
//!    没有会话标识时按「/24 段**等概率**随机 → 段内随机」挑
//!    （[`pick_segment_random_ip`]），并对每个段施加在途上限
//!    （[`OpenCodeSegmentInFlight`]，配置键 `opencode_scan.segment_max_in_flight`）。
//!
//! Redis 键位（都走 RuntimeState 的 kv 原语，自动带实例命名空间）：
//!
//! ```text
//! opencode_pool:rotation:cursor:<provider_id>     轮转游标，带 TTL
//! opencode_pool:cooldown:<provider_id>:<冷却主体>   冷却标记，TTL = 冷却时长
//! ```
//!
//! 冷却主体在 provider 级 IP 池模型下是**出口 IP**，在旧的「一 key 一 IP」模型下才是
//! key_id；两者共用同一段键空间。

use aether_provider_transport::{
    opencode_key_exit_ip, parse_opencode_exit_ip, GatewayProviderTransportSnapshot,
    OPENCODE_PROVIDER_TYPE,
};

use crate::clock::current_unix_ms;
use crate::opencode_cooldown_persist::{OpenCodeCooldownPersist, OpenCodeMaskKind};
use crate::AppState;

/// 游标键的存活时间：足够跨过一次网关重启即可，过期后从 0 重新开始。
const ROTATION_CURSOR_TTL_SECONDS: u64 = 24 * 60 * 60;
/// 配额型（`429` / 带额度文案的 `403`）冷却的**固定** TTL 默认值（秒）。
///
/// 2026-10-22 起不再照抄上游 `retry-after`，判定依据见 [`opencode_cooldown_ttl`]。
pub(crate) const DEFAULT_OPENCODE_COOLDOWN_SECONDS: u32 = 120;
/// 固定冷却的下限（秒）：低于它等于没冷却（同一 IP 会被同一轮 429 风暴反复打中）。
pub(crate) const MIN_OPENCODE_COOLDOWN_SECONDS: u32 = 30;
/// 固定冷却的上限（秒）：实测整段恢复只要 2–3 分钟，10 分钟已经很保守。
pub(crate) const MAX_OPENCODE_COOLDOWN_SECONDS: u32 = 600;
/// 403 时用来识别「免费额度耗尽 / 被限流」的文案指纹（已转小写比较）。
const OPENCODE_FREE_TIER_MESSAGE_MARKERS: [&str; 4] =
    ["freetier", "free tier", "quota", "rate limit"];

fn cursor_key(provider_id: &str) -> String {
    format!("opencode_pool:rotation:cursor:{provider_id}")
}

fn cooldown_key(provider_id: &str, key_id: &str) -> String {
    format!("opencode_pool:cooldown:{provider_id}:{key_id}")
}

/// 冷却**清单**的键：`{ip: 到期时间戳(ms)}`。
///
/// 为什么要单独一份：冷却状态本身是「按 IP 一个 TTL 键」，而运行时 KV **没有前缀扫描**，
/// 面板因此无法回答「现在到底哪些节点在冷却」。这份 JSON 只服务于**显示**——
/// 判定（选点时是否跳过某个 IP）永远只看上面那个按 IP 的 TTL 键，清单丢了不影响行为。
fn exit_ip_cooldown_index_key(provider_id: &str) -> String {
    format!("opencode_pool:cooldown_index:{provider_id}")
}

/// 清单自身的存活时间：够长，避免写着写着整份过期；过期条目在读写时都会过滤掉。
const EXIT_IP_COOLDOWN_INDEX_TTL_SECONDS: u64 = 24 * 60 * 60;

/// 把「这个出口 IP 在冷却」记进清单（覆盖旧时间戳）。
///
/// 读改写有竞态：同一瞬间两处冷却可能互相覆盖，代价只是面板少显示一个节点
/// （判定不受影响）。显示用的清单不值得为它引锁。
async fn remember_exit_ip_cooldown(
    state: &AppState,
    provider_id: &str,
    exit_ip: &str,
    ttl_seconds: u64,
) {
    let now_ms = current_unix_ms();
    let mut entries = read_exit_ip_cooldown_index(state, provider_id, now_ms).await;
    let expires_at_ms = now_ms.saturating_add(ttl_seconds.max(60) * 1_000);
    entries.insert(exit_ip.to_string(), expires_at_ms);
    write_exit_ip_cooldown_index(
        state,
        provider_id,
        &entries,
        EXIT_IP_COOLDOWN_INDEX_TTL_SECONDS,
    )
    .await;
}

/// 整份覆盖冷却清单（已过期条目在这里被顺手丢掉）。
async fn write_exit_ip_cooldown_index(
    state: &AppState,
    provider_id: &str,
    entries: &std::collections::BTreeMap<String, u64>,
    ttl_seconds: u64,
) {
    let now_ms = current_unix_ms();
    let payload = serde_json::Value::Object(
        entries
            .iter()
            .filter(|(_, expires_at)| **expires_at > now_ms)
            .map(|(ip, expires_at)| (ip.clone(), serde_json::Value::from(*expires_at)))
            .collect(),
    )
    .to_string();
    if let Err(err) = state
        .runtime_kv_setex(
            &exit_ip_cooldown_index_key(provider_id),
            &payload,
            ttl_seconds,
        )
        .await
    {
        tracing::warn!(
            provider_id,
            error = ?err,
            "opencode exit ip cooldown index could not be written"
        );
    }
}

async fn read_exit_ip_cooldown_index(
    state: &AppState,
    provider_id: &str,
    now_ms: u64,
) -> std::collections::BTreeMap<String, u64> {
    let Some(raw) = state
        .runtime_kv_get(&exit_ip_cooldown_index_key(provider_id))
        .await
        .ok()
        .flatten()
    else {
        return std::collections::BTreeMap::new();
    };
    parse_exit_ip_cooldown_index(raw.trim(), now_ms)
}

/// 解析冷却清单并丢掉已过期的条目。
///
/// 过期条目在这里被过滤而不是清理写回：读路径要便宜，而清单本身有 TTL 兜底，
/// 写入时也会顺手丢掉过期项。
fn parse_exit_ip_cooldown_index(raw: &str, now_ms: u64) -> std::collections::BTreeMap<String, u64> {
    let Ok(value) = serde_json::from_str::<serde_json::Value>(raw) else {
        return std::collections::BTreeMap::new();
    };
    let Some(object) = value.as_object() else {
        return std::collections::BTreeMap::new();
    };
    object
        .iter()
        .filter_map(|(ip, expires_at)| {
            let expires_at = expires_at.as_u64()?;
            (expires_at > now_ms).then(|| (ip.clone(), expires_at))
        })
        .collect()
}

/// 当前仍在冷却的出口 IP → 剩余秒数（只读，供管理面板显示）。
pub(crate) async fn opencode_exit_ip_cooldown_remaining(
    state: &AppState,
    provider_id: &str,
) -> std::collections::BTreeMap<String, u64> {
    let now_ms = current_unix_ms();
    read_exit_ip_cooldown_index(state, provider_id, now_ms)
        .await
        .into_iter()
        .map(|(ip, expires_at)| (ip, expires_at.saturating_sub(now_ms) / 1000))
        .collect()
}

/// 重启后把持久化镜像里**未到期**的冷却/回避掩码回填进运行时 KV。
///
/// 为什么必须在开服前跑：冷却判定只看运行时 KV 的键在不在（[`key_in_cooldown`] /
/// [`key_in_avoid`]）。2026-10-22 那次重启就是「进程内存清空 → 已冷却 IP 全部回池 →
/// 立刻再撞 429 → 又被按 `Retry-After` 钉 6 小时」；回填放在起监听之前，就不会留下
/// 一段「池子看起来满血」的窗口。
///
/// 语义上只做搬运，不重新计算：
/// - 剩余时长直接取 `到期时刻 - 现在`（持久化层存的是绝对时间戳，不是剩余秒数），
///   所以不需要知道上次写入发生在什么时候，也不受「重启花了多久」影响；
/// - 已到期的条目在这里被跳过（持久化层那边由 [`OpenCodeCooldownPersist::load`] 的
///   第二个返回值告诉调用方要清理几项，随后一次 `flush` 把清理后的快照写回）；
/// - 冷却清单（面板显示用）跟着重建，否则重启后面板会显示「一个都没冷却」。
///
/// 返回回填成功的条目数。持久化层不可用时返回 0 —— 行为退回改动前（只有内存态）。
pub(crate) async fn restore_persisted_opencode_masks(
    state: &AppState,
    persist: &OpenCodeCooldownPersist,
) -> usize {
    let (masks, pruned) = match persist.load().await {
        Ok(loaded) => loaded,
        Err(err) => {
            tracing::warn!(
                error = %err,
                "persisted opencode cooldown masks could not be loaded; starting with in-memory state only"
            );
            return 0;
        }
    };
    let now_ms = current_unix_ms();
    let mut restored = 0usize;
    let mut cooldown_index: std::collections::BTreeMap<
        String,
        std::collections::BTreeMap<String, u64>,
    > = std::collections::BTreeMap::new();
    for mask in masks.iter() {
        let remaining_ms = mask.expires_at_ms.saturating_sub(now_ms);
        if remaining_ms == 0 {
            continue;
        }
        // 向上取整到秒：还差 300ms 到期的条目应该再活 1 秒，而不是被截成 0。
        let remaining_seconds = remaining_ms.div_ceil(1_000).max(1);
        let key = match mask.kind {
            OpenCodeMaskKind::Cooldown => cooldown_key(&mask.provider_id, &mask.ip),
            OpenCodeMaskKind::Avoid => avoid_key(&mask.provider_id, &mask.ip),
        };
        if state
            .runtime_kv_setex(&key, "1", remaining_seconds)
            .await
            .is_err()
        {
            continue;
        }
        if mask.kind == OpenCodeMaskKind::Cooldown {
            cooldown_index
                .entry(mask.provider_id.clone())
                .or_default()
                .insert(mask.ip.clone(), mask.expires_at_ms);
        }
        restored += 1;
    }
    for (provider_id, entries) in cooldown_index.iter() {
        let latest_expires_at_ms = entries.values().copied().max().unwrap_or(now_ms);
        let remaining_seconds = latest_expires_at_ms.saturating_sub(now_ms).div_ceil(1_000);
        write_exit_ip_cooldown_index(
            state,
            provider_id,
            entries,
            remaining_seconds
                .saturating_add(EXIT_IP_COOLDOWN_INDEX_TTL_SECONDS)
                .max(EXIT_IP_COOLDOWN_INDEX_TTL_SECONDS),
        )
        .await;
    }
    if pruned > 0 {
        // 加载时丢掉的过期项要真的从持久化层里消失，否则下次重启还要再丢一遍。
        if let Err(err) = persist.flush().await {
            tracing::warn!(
                error = %err,
                pruned,
                "pruned opencode cooldown masks could not be written back"
            );
        }
    }
    tracing::info!(
        restored,
        pruned,
        providers = cooldown_index.len(),
        "restored opencode cooldown and avoid masks from the persisted snapshot"
    );
    restored
}

/// 原子地推进轮转游标，返回推进后的值。
///
/// 实现说明：RuntimeState 没有 INCR 原语，这里用原子 `GET+DEL` 取出旧值再写回。
/// 首次调用取不到旧值时写入初值 1，保证游标真的会往前走；并发同时调用时最多有一个
/// 拿到旧值，另一个会写回 1，这只会让游标短暂跳号（顺序略有偏差），不会导致连续
/// 多次命中同一个出口 IP。
pub(crate) async fn next_rotation_cursor(state: &AppState, provider_id: &str) -> u64 {
    let key = cursor_key(provider_id);
    let taken = state.runtime_kv_getdel(&key).await.ok().flatten();
    let next = match taken
        .as_deref()
        .map(str::trim)
        .and_then(|raw| raw.parse::<u64>().ok())
    {
        Some(previous) => previous.wrapping_add(1),
        // 首次调用：写入初值，否则游标永远是 0。
        None => 1,
    };
    let _ = state
        .runtime_kv_setex(&key, &next.to_string(), ROTATION_CURSOR_TTL_SECONDS)
        .await;
    next
}

/// 读取当前游标（不推进），仅供面板展示。
pub(crate) async fn peek_rotation_cursor(state: &AppState, provider_id: &str) -> u64 {
    state
        .runtime_kv_get(&cursor_key(provider_id))
        .await
        .ok()
        .flatten()
        .and_then(|raw| raw.trim().parse::<u64>().ok())
        .unwrap_or_default()
}

fn last_exit_ip_key(provider_id: &str) -> String {
    format!("opencode_pool:last_exit_ip:{provider_id}")
}

/// 记录本次请求真正选中的出口 IP，仅供面板展示。
pub(crate) async fn remember_last_exit_ip(state: &AppState, provider_id: &str, ip: &str) {
    let _ = state
        .runtime_kv_setex(
            &last_exit_ip_key(provider_id),
            ip,
            ROTATION_CURSOR_TTL_SECONDS,
        )
        .await;
}

/// 读取上次选中的出口 IP，仅供面板展示。
pub(crate) async fn peek_last_exit_ip(state: &AppState, provider_id: &str) -> Option<String> {
    state
        .runtime_kv_get(&last_exit_ip_key(provider_id))
        .await
        .ok()
        .flatten()
        .map(|raw| raw.trim().to_string())
        .filter(|raw| !raw.is_empty())
}

/// 丢弃次数的保留时长：只用于排查「这个 IP 是不是反复出问题」，30 天足够。
const OPENCODE_DISCARD_COUNT_TTL_SECONDS: u64 = 30 * 24 * 60 * 60;

fn discard_count_key(provider_id: &str, ip: &str) -> String {
    format!("opencode_pool:discard_count:{provider_id}:{ip}")
}

fn suspect_audit_key(provider_id: &str, ip: &str) -> String {
    format!("opencode_pool:suspect:{provider_id}:{ip}")
}

/// 丢弃次数 +1，返回累加后的值。
///
/// `RuntimeState` 没有 INCR 原语（见 [`next_rotation_cursor`] 的说明），所以是
/// GET 之后写回。这里的并发窗口可以接受：复验是单例任务，同一个 IP 不会被两轮
/// 同时丢弃，最坏情况只是少记一次。
pub(crate) async fn bump_opencode_ip_discard_count(
    state: &AppState,
    provider_id: &str,
    ip: &str,
) -> u64 {
    let key = discard_count_key(provider_id, ip);
    let current = state
        .runtime_kv_get(&key)
        .await
        .ok()
        .flatten()
        .and_then(|raw| raw.trim().parse::<u64>().ok())
        .unwrap_or_default();
    let next = current.saturating_add(1);
    let _ = state
        .runtime_kv_setex(&key, &next.to_string(), OPENCODE_DISCARD_COUNT_TTL_SECONDS)
        .await;
    next
}

/// 读「刚刚连着失败」的短期标记（原因文本）；没有标记时返回 `None`。
///
/// 标记由运行时失败路径写入（阶段 3 的 `mark_opencode_ip_suspect`）。选择路径
/// **不读这个键**：写标记时会同时写一份短期冷却，跳不跳过由那一个键决定，
/// 这样热路径不必为每个候选多付一次 Redis 往返。这里读原因只给两条冷路径用：
/// 面板展示，以及扫描时不再把刚失败的节点重新收进候选。
pub(crate) async fn opencode_ip_suspect_reason(
    state: &AppState,
    provider_id: &str,
    ip: &str,
) -> Option<String> {
    state
        .runtime_kv_get(&suspect_audit_key(provider_id, ip))
        .await
        .ok()
        .flatten()
        .map(|raw| raw.trim().to_string())
        .filter(|reason| !reason.is_empty())
}

/// 运行时失败计数的窗口（秒）：1 小时。
///
/// 窗口太短会让偶发抖动直接触发「立刻不用」，太长则会把「上午失败过、下午其实
/// 已经好了」也累计进来。一小时 + 3 次，是「同一段时间里连续出问题」的最小可信样本。
const OPENCODE_RUNTIME_FAIL_WINDOW_SECONDS: u64 = 60 * 60;
/// 窗口内累计多少次运行时失败就写「立刻不用」。
const OPENCODE_RUNTIME_FAIL_SUSPECT_THRESHOLD: u64 = 3;
/// 「立刻不用」的时长（分钟）。
///
/// 刻意短：它是**先别用它**，不是「它坏了」——真正的判定交给下一轮复验（进异常池），
/// 由复验决定是转正还是丢弃。
const OPENCODE_SUSPECT_TTL_MINUTES: u32 = 20;

fn runtime_fail_key(provider_id: &str, ip: &str) -> String {
    format!("opencode_pool:fail:{provider_id}:{ip}")
}

/// 运行时失败的来源：**归因口径的唯一实现**。
///
/// 流式与同步两条路径都按它分类，而不是各自写一套 `matches!(status, ...)`——
/// 口径一旦分叉，两条路径会把同一类失败记成不同的东西，而池子的判定完全依赖这个口径。
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum OpenCodeFailureSource {
    /// 传输层没走通：连接超时 / TLS 失败 / 连接重置。
    Transport,
    /// 走通了但没在时限内答（我们自判的 502/504）。
    GatewayTimeout,
    /// 上游真的答了状态行（4xx / 5xx / 审核 / 鉴权）：不是出口 IP 的问题。
    UpstreamStatus,
    /// 额度类（429 / 403 免费额度）：走冷却，不进失败计数。
    Quota,
    /// 其它（下游断开、我们自己的 bug 等）：不记。
    Ignored,
}

impl OpenCodeFailureSource {
    /// 写日志与面板用的短标签。
    pub(crate) fn label(self) -> &'static str {
        match self {
            Self::Transport => "transport",
            Self::GatewayTimeout => "gateway_timeout",
            Self::UpstreamStatus => "upstream_status",
            Self::Quota => "quota",
            Self::Ignored => "ignored",
        }
    }
}

/// 把一次运行时失败归类。
///
/// `upstream_status_is_known`：状态码来自上游真实的状态行，而不是我们归类出来的。
/// 这个区分是整条口径的关键——上游自己报的错换个出口 IP 也一样，记进去只会让池子
/// 被应用的 Bug 掏空。`transport_failure` 由各路径的既有判据给出（流式有
/// `StreamFailureReport::transport_error`，同步看执行结果里有没有传输层错误）。
pub(crate) fn classify_opencode_failure(
    status_code: Option<u16>,
    upstream_status_is_known: bool,
    transport_failure: bool,
) -> OpenCodeFailureSource {
    if transport_failure {
        return OpenCodeFailureSource::Transport;
    }
    if upstream_status_is_known {
        return match status_code {
            Some(429 | 403) => OpenCodeFailureSource::Quota,
            _ => OpenCodeFailureSource::UpstreamStatus,
        };
    }
    match status_code {
        // 没有真实状态行、只有我们自判的超时：算。
        Some(502 | 504) => OpenCodeFailureSource::GatewayTimeout,
        Some(429 | 403) => OpenCodeFailureSource::Quota,
        // 连状态码都没有（例如纯粹的下游断开）：归因不了，不记。
        _ => OpenCodeFailureSource::Ignored,
    }
}

/// 该来源是否计入「这个出口 IP 的失败次数」。
pub(crate) fn opencode_failure_counts_for_ip(source: OpenCodeFailureSource) -> bool {
    matches!(
        source,
        OpenCodeFailureSource::Transport | OpenCodeFailureSource::GatewayTimeout
    )
}

/// 「配额/免费层被判」类失败要几次才把出口 IP 打成 suspect。
///
/// **默认 1 次**：`403 FreeTierError` 与 `429 Rate limit exceeded` 都是「换个出口就
/// 好」的强信号（2026-10-17 对 `108.138.0.0/24` 全量实测：254 个 IP 里 239 个 403、
/// 0 个 200）。误判代价只是该 IP 冷却 [`OPENCODE_SUSPECT_TTL_MINUTES`] 分钟，池里还有
/// 其它节点可用。
const OPENCODE_QUOTA_FAIL_THRESHOLD: u64 = 1;

/// 只有最近这么多秒内**有过成功**，才把配额类失败归到出口 IP 头上。
///
/// 防的是「我们自己的身份/body 坏了 → 所有 IP 都 403」：那种时候没有任何成功对照，
/// 一个 IP 都不能动（2026-10-17 15:00–19:20 就是这种全局故障）。
/// 运行时失败是否已达「立刻不用」的门槛。
pub(crate) fn opencode_failure_reached_suspect_threshold(fails: u64) -> bool {
    fails >= OPENCODE_RUNTIME_FAIL_SUSPECT_THRESHOLD
}

/// 读窗口内的运行时失败次数（读不到按 0）。
pub(crate) async fn peek_opencode_ip_fail(state: &AppState, provider_id: &str, ip: &str) -> u64 {
    state
        .runtime_kv_get(&runtime_fail_key(provider_id, ip))
        .await
        .ok()
        .flatten()
        .and_then(|raw| raw.trim().parse::<u64>().ok())
        .unwrap_or_default()
}

/// 运行时失败计数 +1（窗口 [`OPENCODE_RUNTIME_FAIL_WINDOW_SECONDS`]），返回累计值。
///
/// `RuntimeState` 没有 INCR 原语，所以是 GET 之后写回；并发窗口可以接受：最坏情况
/// 是少记一次失败，而门槛是 3 次、窗口是 1 小时，少记一次不会改变结论。
pub(crate) async fn bump_opencode_ip_fail(state: &AppState, provider_id: &str, ip: &str) -> u64 {
    bump_opencode_ip_fail_with_window(state, provider_id, ip, OPENCODE_RUNTIME_FAIL_WINDOW_SECONDS)
        .await
}

/// 指定窗口版本的失败计数 +1。
pub(crate) async fn bump_opencode_ip_fail_with_window(
    state: &AppState,
    provider_id: &str,
    ip: &str,
    window_seconds: u64,
) -> u64 {
    let current = peek_opencode_ip_fail(state, provider_id, ip).await;
    let next = current.saturating_add(1);
    let _ = state
        .runtime_kv_setex(
            &runtime_fail_key(provider_id, ip),
            &next.to_string(),
            window_seconds.max(60),
        )
        .await;
    next
}

/// 给出口 IP 打「刚刚连着失败」的短期标记。
///
/// 跳过与否由**冷却键**决定（写一份 [`OPENCODE_SUSPECT_TTL_MINUTES`] 分钟的冷却），
/// 原因另存 audit 键供面板展示——这样请求路径不必为每个候选多读一个键，池里 40 个
/// 节点就是 40 次额外的 Redis 往返。真正的判定交给下一轮复验。
pub(crate) async fn mark_opencode_ip_suspect(
    state: &AppState,
    provider_id: &str,
    ip: &str,
    source: OpenCodeFailureSource,
) {
    mark_opencode_ip_suspect_with_ttl(state, provider_id, ip, source, OPENCODE_SUSPECT_TTL_MINUTES)
        .await;
}

/// 指定冷却时长的 suspect 标记（时长来自配置 `opencode_scan.suspect_ttl_minutes`）。
pub(crate) async fn mark_opencode_ip_suspect_with_ttl(
    state: &AppState,
    provider_id: &str,
    ip: &str,
    source: OpenCodeFailureSource,
    ttl_minutes: u32,
) {
    let ttl_minutes = ttl_minutes.max(1);
    let reason = source.label();
    mark_key_cooldown(state, provider_id, ip, ttl_minutes).await;
    let _ = state
        .runtime_kv_setex(
            &suspect_audit_key(provider_id, ip),
            reason,
            u64::from(ttl_minutes) * 60,
        )
        .await;
    tracing::info!(
        event_name = "opencode_ip_suspect_marked",
        provider_id,
        ip,
        reason,
        ttl_minutes = ttl_minutes,
        "opencode exit ip marked suspect after repeated runtime failures"
    );
}

/// 记一次运行时失败；达门槛时写「立刻不用」。返回累计次数（不计入时 `None`）。
/// 带阈值/窗口/冷却时长的记账版本（取值来自 `opencode_scan` 配置）。
/// 单个 provider 每小时最多自动出池多少个 IP。
///
/// 为什么需要节流：出池由真实流量驱动，而上游抖动时失败是**成片**的。没有上限的话，
/// 一次网络抖动就能把 2000 个 IP 的池子打成个位数，而「池子塌了」比「留几个坏 IP」
/// 严重得多。超限时只记日志、不删配置——节流是可以自愈的，误删不是。
pub(crate) const OPENCODE_EVICT_MAX_PER_HOUR: u64 = 20;
/// 出池节流窗口（秒）：一小时。
const OPENCODE_EVICT_WINDOW_SECONDS: u64 = 3_600;

fn evict_count_key(provider_id: &str) -> String {
    format!("opencode_pool:evict_count:{provider_id}")
}

/// 节流闸：窗口内还没用完配额就放行并把计数 +1。
fn allow_eviction_now(count: u64) -> bool {
    count < OPENCODE_EVICT_MAX_PER_HOUR
}

/// 异步把「连续失败达阈值」的 IP 从轮转池摘掉（不阻塞请求路径）。
/// 按执行计划记一次运行时失败（两条请求路径的唯一入口）。
/// 读一个出口 IP 的运行时证据：`(窗口内失败次数, 可疑原因, 是否在冷却中)`。
///
/// 没有失败计数时返回 `None`，且**不去读另外两个键**：状态接口会被面板轮询，而池里
/// 绝大多数是健康节点，为它们各付三次 Redis 往返没必要。
pub(crate) async fn peek_opencode_ip_runtime_evidence(
    state: &AppState,
    provider_id: &str,
    ip: &str,
) -> Option<(u64, Option<String>, bool)> {
    let fails = peek_opencode_ip_fail(state, provider_id, ip).await;
    if fails == 0 {
        return None;
    }
    let suspect = opencode_ip_suspect_reason(state, provider_id, ip).await;
    let cooling = key_in_cooldown(state, provider_id, ip).await;
    Some((fails, suspect, cooling))
}

/// 标记某个 key 进入冷却（额度耗尽）。冷却到期由 Redis TTL 自动解除。
pub(crate) async fn mark_key_cooldown(
    state: &AppState,
    provider_id: &str,
    key_id: &str,
    cooldown_minutes: u32,
) {
    mark_key_cooldown_seconds(
        state,
        provider_id,
        key_id,
        u64::from(cooldown_minutes.max(1)) * 60,
    )
    .await;
}

/// key 不再熔断：一次失败只说明「这个出口这次不行」，换出口再试，不封 key。
///
/// 保留函数壳子只是为了不动调用点；真正的健康判定在出口 IP 侧
/// （`remember_exit_ip_cooldown`）与重试阶梯上。
async fn mark_key_cooldown_seconds(
    _state: &AppState,
    provider_id: &str,
    key_id: &str,
    ttl_seconds: u64,
) {
    tracing::debug!(
        provider_id,
        key_id,
        ttl_seconds,
        "opencode key 冷却已停用（改为换出口重试）"
    );
}

/// 一次配额型冷却的判定结果（含"上游提示是否被截断"，供日志对账）。
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct OpenCodeCooldownTtl {
    /// 配置解析后的固定冷却（秒），已夹紧到合法区间。
    pub(crate) configured_seconds: u64,
    /// 实际采用的冷却（秒）。
    pub(crate) ttl_seconds: u64,
    /// 上游 `retry-after` 是否**更长**因而被截断：`true` = 这次没听上游。
    pub(crate) retry_after_clipped: bool,
}

/// 这次配额型冷却该多久：**固定短冷却，`retry-after` 只能把它变短，不能变长。**
///
/// 规则（2026-10-22 决定，这是**行为变更**：以前听上游、现在不听，别再改回去）：
///
/// - 基线是固定值 `configured_seconds`（配置键 `opencode_scan.cooldown_seconds`，
///   默认 [`DEFAULT_OPENCODE_COOLDOWN_SECONDS`] = 120 秒，夹紧到
///   [`MIN_OPENCODE_COOLDOWN_SECONDS`]..=[`MAX_OPENCODE_COOLDOWN_SECONDS`]）；
/// - 上游 `retry-after` **只在更短时被采纳**（`min(retry_after, 固定值)`）；
/// - 没有 `retry-after` 时就用固定值；**没有"按上游放大"这条分支了**
///   （旧的 `s.min(86400)` 语义已删除）。
///
/// 为什么不再听上游（2026-10-22 一整轮实测，不要凭直觉改回去）：
///
/// 1. 打爆 `18.154.128.6` 后，同 `/24` 段的 `.1–.5` **立刻全部 429**，连**从未使用过**
///    的 `.7–.26`（20 个）也全 429 ⇒ 额度按 **/24 段共享**，不是单个 IP 的账；
/// 2. 异段同时**正常 200** ⇒ 不是账户级；
/// 3. **2–3 分钟后整段自动恢复 200**；
/// 4. 但所有 429 的 `retry-after` 都精确指向 **24:00 UTC（08:00 CST）**，即"距日重置
///    还剩多久"，与实际恢复时间（2–3 分钟）**完全不符**。
///
/// 旧实现（2026-10-16 引入）把这个头当冷却 TTL（上限 24h），后果是 2026-10-22 凌晨
/// **124 个 IP 被打了 6 小时冷却**，而它们 2–3 分钟就能用——白废整个池子一整夜。
/// 上游这个头的量级表达的是"账户日额度什么时候刷新"，不是"这个出口几分钟后能用"，
/// 所以它只能作为"比固定值更短"的补充信号，**不能**作为延长的依据。
///
/// 取舍：万一上游**真的**要求长冷却（例如整段真被封一天），我们会每 2 分钟试一次。
/// 代价可以接受——冷却到期后重试只是打一次普通请求，撞上了就再冷却 2 分钟；
/// 而"白白废掉整池一夜"（等于全站 429）不可接受。
pub(crate) fn opencode_cooldown_ttl(
    configured_seconds: u32,
    retry_after_seconds: Option<u64>,
) -> OpenCodeCooldownTtl {
    let configured = u64::from(
        configured_seconds.clamp(MIN_OPENCODE_COOLDOWN_SECONDS, MAX_OPENCODE_COOLDOWN_SECONDS),
    );
    let floor = u64::from(MIN_OPENCODE_COOLDOWN_SECONDS);
    match retry_after_seconds {
        // 上游更短：听上游，但不低于下限（0 秒等于没冷却）。
        Some(seconds) if seconds < configured => OpenCodeCooldownTtl {
            configured_seconds: configured,
            ttl_seconds: seconds.max(floor),
            retry_after_clipped: false,
        },
        // 上游更长或相等：一律用固定值，并记下"这次截断了上游"。
        Some(seconds) => OpenCodeCooldownTtl {
            configured_seconds: configured,
            ttl_seconds: configured,
            retry_after_clipped: seconds > configured,
        },
        None => OpenCodeCooldownTtl {
            configured_seconds: configured,
            ttl_seconds: configured,
            retry_after_clipped: false,
        },
    }
}

/// 从上游响应头里读 `retry-after`（秒）。
///
/// 只认整数秒：HTTP-date 形式在本上游没出现过，遇到就当作"没有"，退回固定短冷却
/// （宁可少冷却，也不要按一个解析错的日期把节点钉死一天）。
pub(crate) fn retry_after_seconds(
    headers: &std::collections::BTreeMap<String, String>,
) -> Option<u64> {
    headers
        .iter()
        .find(|(name, _)| name.eq_ignore_ascii_case("retry-after"))
        .and_then(|(_, value)| value.trim().parse::<u64>().ok())
}

/// key 熔断已停用：永远不认为某个 key 在冷却，失败由出口重试消化。
pub(crate) async fn key_in_cooldown(_state: &AppState, _provider_id: &str, _key_id: &str) -> bool {
    false
}

/// 会话锚点绑定的存活时间（秒）。
///
/// 半小时：足够覆盖一段连续对话（首字延迟可预期、连接可复用），又不至于把一个
/// 后来变坏的节点钉死太久——绑定节点一进冷却就自动不被认，这条只是上限。
pub(crate) const OPENCODE_SESSION_ANCHOR_TTL_SECONDS: u64 = 30 * 60;

fn session_anchor_key(provider_id: &str, session_key: &str) -> String {
    format!("opencode_pool:session_anchor:{provider_id}:{session_key}")
}

/// 会话键的**可关联短指纹**：FNV-1a 64 位取前 12 个十六进制字符。
///
/// 会话键是客户端标识，不该原样进日志；但排查「换点后到底粘没粘住」时必须把同一个
/// 会话的多条日志串起来。哈希只用于关联、不可逆，也不参与任何判定（选点用
/// `pick_session_anchor` 里那套 FNV-1a 取模）。
pub(crate) fn session_ref(session_key: &str) -> String {
    let mut hash: u64 = 0xcbf2_9ce4_8422_2325;
    for byte in session_key.trim().as_bytes() {
        hash ^= u64::from(*byte);
        hash = hash.wrapping_mul(0x0000_0100_0000_01b3);
    }
    format!("{hash:016x}")[..12].to_string()
}

/// 读「本会话当前绑在哪个节点」。
///
/// 空白/缺失的 session key 一律返回 `None`（没开粘性就没有会话维度可用）。
pub(crate) async fn read_opencode_session_anchor(
    state: &AppState,
    provider_id: &str,
    session_key: Option<&str>,
) -> Option<String> {
    let session_key = session_key.map(str::trim).filter(|key| !key.is_empty())?;
    state
        .runtime_kv_get(&session_anchor_key(provider_id, session_key))
        .await
        .ok()
        .flatten()
        .map(|value| value.trim().to_string())
        .filter(|value| !value.is_empty())
}

/// 把「本会话 → 这个节点」写进绑定表（覆盖旧绑定）。
pub(crate) async fn bind_opencode_session_anchor(
    state: &AppState,
    provider_id: &str,
    session_key: &str,
    exit_ip: &str,
    ttl_seconds: u64,
) {
    let session_key = session_key.trim();
    let exit_ip = exit_ip.trim();
    if session_key.is_empty() || exit_ip.is_empty() {
        return;
    }
    if let Err(err) = state
        .runtime_kv_setex(
            &session_anchor_key(provider_id, session_key),
            exit_ip,
            ttl_seconds.max(60),
        )
        .await
    {
        tracing::warn!(
            provider_id,
            error = ?err,
            "opencode session anchor binding could not be written"
        );
    }
}

/// 首字节成功（2xx）后确认绑定：这个节点对这个会话是好用的，粘住它。
///
/// 与 [`rotate_opencode_anchor_for_retry_plan`] 的分工：换点是**乐观**绑定（先写，
/// 失败就靠冷却自愈），这里是**确认**绑定（成功即刷新 TTL）。两者写同一个键，
/// 所以「换成功就一直用新节点」在两次请求之间也是成立的。
/// 从执行计划的 transport profile 里取出**本次请求实际使用**的出口 IP。
///
/// provider 级 IP 池模型下，IP 是规划阶段才抽出来注入候选 transport 快照的，
/// 目录里的 key metadata 上并没有它；真正落地的位置是
/// `plan.transport_profile.extra.opencode_dns_pin.ip`。
pub(crate) fn plan_opencode_exit_ip(
    plan: &aether_contracts::ExecutionPlan,
) -> Option<std::net::IpAddr> {
    let extra = plan.transport_profile.as_ref()?.extra.as_ref()?;
    let raw = extra
        .get("opencode_dns_pin")?
        .get("ip")?
        .as_str()?
        .trim()
        .to_string();
    parse_opencode_exit_ip(raw.as_str())
}

/// 判定一次上游失败是否需要给本次请求的出口 IP 打冷却。
///
/// 保守判定，宁可漏判不可误判：
/// - 只有 `provider_type = opencode` 才可能命中，其它 provider 恒为 `false`；
/// - `429` 直接命中（被限流）；
/// - `403` 必须额外在错误信息里看到免费额度/限流字样；
/// - 其它状态码一律不命中。
pub(crate) fn cooldown_triggered(
    provider_type: &str,
    status_code: u16,
    message: Option<&str>,
) -> bool {
    if !provider_type
        .trim()
        .eq_ignore_ascii_case(OPENCODE_PROVIDER_TYPE)
    {
        return false;
    }
    match status_code {
        429 => true,
        403 => message.is_some_and(|message| {
            let message = message.to_ascii_lowercase();
            OPENCODE_FREE_TIER_MESSAGE_MARKERS
                .iter()
                .any(|marker| message.contains(marker))
        }),
        _ => false,
    }
}

/// 上游失败后，给本次请求使用的出口 IP 打冷却标记。
///
/// 出口 IP 取自 `transport.key.upstream_metadata.opencode_exit_ip`（旧的一 key 一 IP
/// 模型）。provider 级 IP 池模型请改用 [`mark_opencode_exit_ip_cooldown_for_ip`]，
/// 由调用方从执行计划里把本次抽中的 IP 传进来。
pub(crate) async fn mark_opencode_exit_ip_cooldown(
    state: &AppState,
    transport: &GatewayProviderTransportSnapshot,
    status_code: u16,
    message: Option<&str>,
    retry_after_seconds: Option<u64>,
) {
    let Some(exit_ip) = opencode_key_exit_ip(transport) else {
        return;
    };
}

/// 同 [`mark_opencode_exit_ip_cooldown`]，但出口 IP 由调用方给出。
///
/// 冷却时长是**固定短冷却**，取 provider 的 `config.opencode_scan.cooldown_seconds`
/// （默认 120 秒）；上游 `retry-after` 只在更短时被采纳，见 [`opencode_cooldown_ttl`]。
/// 未命中判定条件时**什么都不做**。
/// 瞬时/上游全局失败时给出口 IP 打的**短期回避**时长（秒）。
///
/// 与配额冷却（`opencode_scan.cooldown_seconds`，默认 120 秒）刻意分开：
/// 上游打嗝、超时、`Endpoint is unavailable.`（422）这类失败**不是这个 IP 的错**——
/// 2026-10-16 实测：422 换 IP 之后照旧 422，回源 POP 始终是同一个。把健康节点关
/// 60 分钟只会侵蚀池子容量（那天 23 个 IP 被误关一小时），而"先别用它"几分钟就够：
/// 抖动过去后节点自动回到池子里。
pub(crate) const OPENCODE_AVOID_TTL_SECONDS: u64 = 3 * 60;

/// 一次上游失败该给本次请求的出口 IP 打哪种标记。
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum OpenCodeExitIpMark {
    /// 配额型（429，或带免费额度/限流文案的 403）：按固定短冷却进冷却（默认 120 秒）。
    Cooldown,
    /// 瞬时或上游全局失败（超时、5xx、422…）：短期回避，几分钟自愈。
    Avoid,
    /// 调用方自己的错（400/401/402/404/413/415、`invalid_request_error`）：与节点无关。
    None,
}

/// 判定该给出口 IP 打哪种标记（纯函数，便于单测）。
///
/// 三分支依据：**能不能归因到这个出口节点**。
/// - 配额型失败确实与节点相关 → 冷却（固定短冷却，`retry-after` 只能把它变短）；
/// - 瞬时/上游全局失败换节点也可能好，但不值得关一小时 → 短期回避；
/// - 调用方自己的错（请求体检不合格）换节点一定不好 → 什么都不打。
pub(crate) fn opencode_exit_ip_mark_for_failure(
    status_code: Option<u16>,
    message: Option<&str>,
) -> OpenCodeExitIpMark {
    if crate::orchestration::upstream_failure_is_client_fault(status_code.unwrap_or(0), message) {
        return OpenCodeExitIpMark::None;
    }
    match status_code {
        Some(429) => OpenCodeExitIpMark::Cooldown,
        // 403 只有确实是"免费额度/限流"文案时才算配额；其余按瞬时处理。
        Some(403) if cooldown_triggered(OPENCODE_PROVIDER_TYPE, 403, message) => {
            OpenCodeExitIpMark::Cooldown
        }
        // 422 / 408 / 5xx / 没有状态行的超时与连接失败：短期回避。
        _ => OpenCodeExitIpMark::Avoid,
    }
}

fn avoid_key(provider_id: &str, ip: &str) -> String {
    format!("opencode_pool:avoid:{provider_id}:{ip}")
}

async fn key_in_avoid(state: &AppState, provider_id: &str, ip: &str) -> bool {
    state
        .runtime_kv_exists(&avoid_key(provider_id, ip))
        .await
        .unwrap_or(false)
}

async fn mark_key_avoid_seconds(state: &AppState, provider_id: &str, ip: &str, ttl_seconds: u64) {
    let ttl_seconds = ttl_seconds.max(30);
    let _ = state
        .runtime_kv_setex(&avoid_key(provider_id, ip), "1", ttl_seconds)
        .await;
    // 与冷却同理：同步入镜像快照，后台任务负责落盘。
    state.record_opencode_mask(OpenCodeMaskKind::Avoid, provider_id, ip, ttl_seconds);
}

/// 给某个出口 IP 打一次**短期回避**。
///
/// 幂等：已经在回避中的 IP 只刷新 TTL、**不重复记日志**，所以
/// `opencode_exit_ip_avoid_marked` 的条数 = 被回避的 IP 次数，可以用来与失败次数对账。
pub(crate) async fn mark_opencode_exit_ip_avoid_for_ip(
    state: &AppState,
    provider_id: &str,
    exit_ip: std::net::IpAddr,
    reason: &str,
    status_code: Option<u16>,
    message: Option<&str>,
    request_id: Option<&str>,
) {
    let exit_ip = exit_ip.to_string();
    let already_avoided = key_in_avoid(state, provider_id, exit_ip.as_str()).await;
    mark_key_avoid_seconds(
        state,
        provider_id,
        exit_ip.as_str(),
        OPENCODE_AVOID_TTL_SECONDS,
    )
    .await;
    if already_avoided {
        return;
    }
    tracing::info!(
        event_name = "opencode_exit_ip_avoid_marked",
        log_type = "event",
        provider_id,
        exit_ip = exit_ip.as_str(),
        reason,
        status_code = status_code.unwrap_or(0),
        ttl_seconds = OPENCODE_AVOID_TTL_SECONDS,
        request_id = request_id.unwrap_or("-"),
        message = message.unwrap_or(""),
        "opencode exit ip marked for a short avoid after a transient or upstream-wide failure"
    );
}

/// 按标记种类给本次请求的出口 IP 落标记：唯一的落点，三个钩子共用。
async fn mark_opencode_exit_ip_for_plan_mark(
    state: &AppState,
    plan: &aether_contracts::ExecutionPlan,
    mark: OpenCodeExitIpMark,
    status_code: Option<u16>,
    message: Option<&str>,
    retry_after_seconds: Option<u64>,
    reason: &str,
) {
    if mark == OpenCodeExitIpMark::None {
        return;
    }
    let Ok(Some(transport)) = state
        .read_provider_transport_snapshot(&plan.provider_id, &plan.endpoint_id, &plan.key_id)
        .await
    else {
        return;
    };
    if !aether_provider_transport::is_opencode_provider_transport(&transport) {
        return;
    }
    let Some(exit_ip) = plan_opencode_exit_ip(plan) else {
        // 旧的一 key 一 IP 模型：出口 IP 来自目录 key 的 metadata。短期回避没有对应
        // 落点（那条模型的"池子"就是我们自己的 key 列表），只保留配额冷却。
        if mark == OpenCodeExitIpMark::Cooldown {
            if let Some(status) = status_code {
                mark_opencode_exit_ip_cooldown(
                    state,
                    &transport,
                    status,
                    message,
                    retry_after_seconds,
                )
                .await;
            }
        }
        return;
    };
    match mark {
        OpenCodeExitIpMark::Cooldown => {}
        OpenCodeExitIpMark::Avoid => {
            mark_opencode_exit_ip_avoid_for_ip(
                state,
                plan.provider_id.as_str(),
                exit_ip,
                reason,
                status_code,
                message,
                Some(plan.request_id.as_str()),
            )
            .await;
        }
        OpenCodeExitIpMark::None => {}
    }
}

/// 上游失败后，给**本次请求实际使用**的 opencode 出口 IP 打标记。
///
/// 出口 IP 由 `plan` 反查：provider 级 IP 池模型下，IP 是规划阶段才抽出来注入候选
/// transport 快照的，目录快照里取不到，只能从 plan 的 transport profile 读
/// （见 [`plan_opencode_exit_ip`]）。
///
/// **流式与同步两条路径共用这一个入口**。此前只有流式路径有这层钩子，同步（非流式）
/// 请求的 429/403 失败信号全部丢失——一半流量等于没有冷却保护。
///
/// 现在按 [`opencode_exit_ip_mark_for_failure`] 三分支：配额 → 冷却、瞬时/上游全局 →
/// 短期回避、调用方自己的错 → 什么都不打。**预取阶段的上游失败**也走这里（见
/// `execution_runtime::stream::execution_failures`），不再只有"换点"顺带标记。
pub(crate) async fn mark_opencode_exit_ip_cooldown_for_plan(
    state: &AppState,
    plan: &aether_contracts::ExecutionPlan,
    status_code: u16,
    message: Option<&str>,
    retry_after_seconds: Option<u64>,
) {
    let mark = opencode_exit_ip_mark_for_failure(Some(status_code), message);
    // 当日成败统计：**每一次上游失败**都在这里记一笔（同步、无 IO）。
    //
    // 只在这个「失败现场」的入口记，不在下面共用的落标记函数里记：那个函数还会被
    // 「候选耗尽时补一次标记」调用（`mark_terminal_opencode_exit_ip_for_plan`），标记
    // 本身幂等无所谓，但计数跟着它会同一个失败记两遍。
    //
    // 「调用方自己的错」（`OpenCodeExitIpMark::None`）不计：那是请求体/凭据的问题，
    // 记到出口 IP 头上会把面板的成功率带偏，也解释不了任何事。
    // 拿不到 exit_ip 的（旧的一 key 一 IP 模型、非 opencode 计划）直接跳过，不猜。
    mark_opencode_exit_ip_for_plan_mark(
        state,
        plan,
        mark,
        Some(status_code),
        message,
        retry_after_seconds,
        "upstream_failure",
    )
    .await;
}

/// 请求终结（候选耗尽）时，对**最后一次尝试实际使用的出口 IP** 补一次标记。
///
/// 为什么需要兜底：标记过去只在"换点"时发生，而换点只在**还有下一次重试**时才执行，
/// 于是每次请求的**最后一次失败没有任何标记**（2026-10-16 现场：4 次 429 只冷却了
/// 2 个 IP、最后两次用的 `.164`/`.167` 一直没进冷却表）。这里按最后一次失败的事实
/// 补一次；标记本身幂等，与别的钩子重复命中也不会二次计数。
pub(crate) async fn mark_terminal_opencode_exit_ip_for_plan(
    state: &AppState,
    plan: &aether_contracts::ExecutionPlan,
    status_code: Option<u16>,
    message: Option<&str>,
) {
    let mark = opencode_exit_ip_mark_for_failure(status_code, message);
    mark_opencode_exit_ip_for_plan_mark(
        state,
        plan,
        mark,
        status_code,
        message,
        None,
        "terminal_last_attempt",
    )
    .await;
}

/// 触发这次同 key 重试的失败事实。
///
/// 换点函数需要它回答三个问题：**该不该冷却旧节点**、**冷却多久**（配额型 429 按
/// 上游 `retry-after` 对齐）、以及**日志里记哪个状态码**。
/// 拿不到时（上下文缺失）一律按"未知"处理：行为退回改动之前（照常冷却、状态码 429、
/// 时长用配置值），不让信息缺失把已有的换点/冷却机制关掉。
#[derive(Clone, Debug, Default)]
pub(crate) struct OpenCodeRetryFailure {
    pub(crate) status_code: Option<u16>,
    pub(crate) message: Option<String>,
    /// 上游给的 `retry-after`（秒）。配额型 429 会带一个到"配额刷新"的秒数。
    pub(crate) retry_after_seconds: Option<u64>,
}

impl OpenCodeRetryFailure {
    /// 从 attempt 的报告上下文里取 `error_flow`（上游状态码 + 原文）。
    ///
    /// **不含 `retry-after`**：那个头只在失败现场写下的 KV 记录里，
    /// 调用方（换点函数）会把它补进来。
    pub(crate) fn from_report_context(report_context: Option<&serde_json::Value>) -> Self {
        let flow = report_context
            .and_then(|value| value.as_object())
            .and_then(|object| object.get("error_flow"))
            .and_then(|value| value.as_object());
        let Some(flow) = flow else {
            return Self::default();
        };
        Self {
            status_code: flow
                .get("status_code")
                .and_then(serde_json::Value::as_u64)
                .and_then(|value| u16::try_from(value).ok()),
            message: flow
                .get("message")
                .and_then(serde_json::Value::as_str)
                .map(|value| value.trim().to_string())
                .filter(|value| !value.is_empty()),
            retry_after_seconds: None,
        }
    }

    /// 这次失败是不是"调用方自己的错"。
    ///
    /// 三分支判据（配额 → 冷却 / 瞬时与上游全局 → 短期回避 / 调用方自己的错 → 不标记）
    /// 统一由 [`opencode_exit_ip_mark_for_failure`] 表达，这里只保留事实判定。
    pub(crate) fn is_client_fault(&self) -> bool {
        crate::orchestration::upstream_failure_is_client_fault(
            self.status_code.unwrap_or(0),
            self.message.as_deref(),
        )
    }

    fn to_json(&self) -> serde_json::Value {
        serde_json::json!({
            "status_code": self.status_code,
            "message": self.message,
            "retry_after_seconds": self.retry_after_seconds,
        })
    }

    fn from_json(value: &serde_json::Value) -> Self {
        Self {
            status_code: value
                .get("status_code")
                .and_then(serde_json::Value::as_u64)
                .and_then(|value| u16::try_from(value).ok()),
            message: value
                .get("message")
                .and_then(serde_json::Value::as_str)
                .map(|value| value.trim().to_string())
                .filter(|value| !value.is_empty()),
            retry_after_seconds: value
                .get("retry_after_seconds")
                .and_then(serde_json::Value::as_u64),
        }
    }
}

/// 失败事实在运行时 KV 里的键。
///
/// **按 `request_id` 而不是 candidate_id**：同 key 重试会换一个新的 candidate_id，
/// 键跟着换就找不回来了。
fn retry_failure_key(request_id: &str) -> String {
    format!("opencode_pool:retry_failure:{request_id}")
}

/// 失败事实的存活时间：只服务「紧接着的那次重试」与「耗尽时的客户端文案」，不做事后统计。
const OPENCODE_RETRY_FAILURE_TTL_SECONDS: u64 = 300;

/// 在上游失败的**现场**把状态码与原文记下来。
///
/// 为什么另存一份：attempt 的报告上下文里并没有 `error_flow`（它进的是 usage 报告与候选行），
/// 而运行时里的 `plan` 是**按值**传进去的，改动传不回 attempt。于是「同 key 重试要不要冷却
/// 旧节点」（换点函数）与「耗尽时给客户端看哪句话」（耗尽判定）这两个读者都需要一个
/// **在失败现场就写好**的地方。
pub(crate) async fn record_opencode_upstream_failure(
    state: &AppState,
    plan: &aether_contracts::ExecutionPlan,
    status_code: u16,
    response_text: Option<&str>,
    retry_after_seconds: Option<u64>,
) {
    // 只对带出口锚点的请求记录（其它 provider 的 plan 里没有 pin）。
    if plan_opencode_exit_ip(plan).is_none() {
        return;
    }
    let failure = OpenCodeRetryFailure {
        status_code: Some(status_code),
        message: crate::orchestration::local_failover_error_message(response_text)
            .map(|value| value.chars().take(400).collect::<String>()),
        retry_after_seconds,
    };
    let encoded = failure.to_json().to_string();
    if let Err(err) = state
        .runtime_kv_setex(
            &retry_failure_key(plan.request_id.as_str()),
            &encoded,
            OPENCODE_RETRY_FAILURE_TTL_SECONDS,
        )
        .await
    {
        tracing::warn!(
            provider_id = plan.provider_id.as_str(),
            error = ?err,
            "opencode retry failure record could not be written"
        );
    }
}

/// 读回「这个请求最近一次上游失败」的事实。
pub(crate) async fn read_opencode_upstream_failure(
    state: &AppState,
    request_id: &str,
) -> Option<OpenCodeRetryFailure> {
    let raw = state
        .runtime_kv_get(&retry_failure_key(request_id))
        .await
        .ok()
        .flatten()?;
    let value: serde_json::Value = serde_json::from_str(raw.trim()).ok()?;
    Some(OpenCodeRetryFailure::from_json(&value))
}

/// 一次「同 key 重试」的准备结果。
///
/// 从 `bool` 升级成多种状态，是因为多了「别再重试了」的分支：段预算耗尽、配额重试
/// 次数用尽、池里没有任何未冷却节点时，继续重试只会白烧别的节点或让客户端白等，
/// 必须让上层直接放弃这次重试，而不是照旧拿着原 plan 再撞一次。
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum OpenCodeAnchorRotation {
    /// pin 已改写：用改写后的 plan 重试。
    Rotated,
    /// 没换点（不是 opencode / 没开轮转 / 池子空 / 没有别的可用点）：沿用原 plan
    /// 重试一次，行为与改动前**完全一致**。
    Unchanged,
    /// **429 段预算耗尽**（已试满 N 个 /24 段或超过耗时上限）：立刻放弃重试。
    /// 段预算默认关闭，这条只有显式打开时才会出现。
    SegmentBudgetExhausted,
    /// **配额型失败的尝试次数已达 `max_attempts`**（默认 3，含第一次）：放弃重试。
    QuotaAttemptsExhausted,
    /// **池里没有任何未冷却的出口 IP**：宁可快速失败，也不退回挑一个正在被限流的节点。
    QuotaNoUsableIp,
}

impl OpenCodeAnchorRotation {
    /// 这次「同 key 重试」是否应当直接放弃。
    ///
    /// 三种「收尾」语义一致：都交给 attempt loop 继续下一个候选，或走既有的候选
    /// 耗尽路径——与「同 key 重试预算用尽」完全同一处理。
    pub(crate) fn stops_same_key_retry(self) -> bool {
        matches!(
            self,
            Self::SegmentBudgetExhausted | Self::QuotaAttemptsExhausted | Self::QuotaNoUsableIp
        )
    }
}

/// 上游**可重试失败**后，为「同 key 重试」换一个锚点 IP（就地改写 plan 的 pin）。
///
/// 为什么必须显式换：锚点是**规划期一次性**注入候选 transport 的，而同 key 重试只是
/// 把 attempt 重新编号——`next_same_key_retry_attempt` 只改 `retry_index` 与
/// `candidate_id`，transport / plan / pin 全部照抄。不换点就等于在同一个节点上反复撞
/// （2026-10-15 现场：21:18 两次 429、22:42 两次 422 都撞在同一 IP）。
///
/// 语义：
/// - **会话粘性不阻挡换点**：都已经被限流了，粘在同一个节点上没有意义；
/// - 旧 IP 立刻打标记：配额型（429/带额度文案的 403）按 `opencode_scan.cooldown_seconds`
///   （默认 120 秒的**固定短冷却**）进冷却；**瞬时/上游全局**（超时、5xx、422）只打几分钟的短期回避；
///   调用方自己的错什么都不打（判据见 [`opencode_exit_ip_mark_for_failure`]）；
/// - 新 IP 从池里抽且**排除旧 IP**；池里没有别的可用节点时返回
///   [`OpenCodeAnchorRotation::Unchanged`]，宁可在原地再试一次，也不把池抽空；
/// - **配额型失败（429 / 带额度文案的 403）先按延迟阶梯等一等**（见
///   [`opencode_quota_retry_step`]）：等完从「当前未冷却」的 IP 里**按 /24 段随机**
///   挑一个换点（[`pick_segment_aware_anchor`]，与主路径同一个函数、同样的在途上限），
///   总尝试次数封顶 `max_attempts`（默认 3，含第一次）。
///   次数用尽返回 [`OpenCodeAnchorRotation::QuotaAttemptsExhausted`]，池里没有未冷却
///   节点返回 [`OpenCodeAnchorRotation::QuotaNoUsableIp`]——两种情况都不再重试。
/// - 「按 /24 段优先」的段预算**默认关闭**（[`OpenCodeSegmentBudgetPolicy`]），显式打开
///   时行为与改动前一致。503 / 5xx / 超时走 Avoid，这两段逻辑整段跳过
///   （选点顺序与改动前完全一致）。
pub(crate) async fn rotate_opencode_anchor_for_retry_plan(
    state: &AppState,
    plan: &mut aether_contracts::ExecutionPlan,
    failure: OpenCodeRetryFailure,
    attempts_made: u32,
) -> OpenCodeAnchorRotation {
    // 出口 IP 池已移除，这里只剩一个判断：配额型失败要不要立刻放弃同 key 重试。
    if plan_opencode_exit_ip(plan).is_none() {
        return OpenCodeAnchorRotation::Unchanged;
    }
    let Ok(Some(transport)) = state
        .read_provider_transport_snapshot(&plan.provider_id, &plan.endpoint_id, &plan.key_id)
        .await
    else {
        return OpenCodeAnchorRotation::Unchanged;
    };
    if !aether_provider_transport::is_opencode_provider_transport(&transport) {
        return OpenCodeAnchorRotation::Unchanged;
    }
    let provider_config = transport.provider.config.clone();
    let mark = opencode_exit_ip_mark_for_failure(failure.status_code, failure.message.as_deref());
    let quota_policy = OpenCodeQuotaRetryPolicy::from_provider_config(&provider_config);
    // 延迟阶梯整条移除：配额型失败不再等待，立刻收尾交给下一个 key。
    // `attempts_made` 留在签名里只是为了不动调用点。
    let _ = attempts_made;
    if mark == OpenCodeExitIpMark::Cooldown && quota_policy.enabled {
        OpenCodeAnchorRotation::QuotaAttemptsExhausted
    } else {
        OpenCodeAnchorRotation::Unchanged
    }
}

/// 按标记种类给旧出口 IP 落标记（换点与「预算耗尽」两条路径共用）。
///
/// 标记本身幂等（冷却/回避都只刷新 TTL、不重复记日志），所以两条路径重复命中同一个
/// IP 也不会把统计口径弄脏。
async fn apply_opencode_retry_mark(
    state: &AppState,
    transport: &GatewayProviderTransportSnapshot,
    plan: &aether_contracts::ExecutionPlan,
    previous_ip: std::net::IpAddr,
    next_ip: Option<&str>,
    mark: OpenCodeExitIpMark,
    failure: &OpenCodeRetryFailure,
) {
    match mark {
        OpenCodeExitIpMark::Cooldown => {}
        OpenCodeExitIpMark::Avoid => {
            mark_opencode_exit_ip_avoid_for_ip(
                state,
                plan.provider_id.as_str(),
                previous_ip,
                "retry_rotation",
                failure.status_code,
                failure.message.as_deref(),
                Some(plan.request_id.as_str()),
            )
            .await;
        }
        OpenCodeExitIpMark::None => {
            tracing::info!(
                event_name = "opencode_anchor_rotated_without_marking",
                log_type = "event",
                provider_id = plan.provider_id.as_str(),
                previous_ip = previous_ip.to_string().as_str(),
                next_ip = next_ip.unwrap_or("-"),
                status_code = failure.status_code.unwrap_or(0),
                reason = "client_fault",
                request_id = plan.request_id.as_str(),
                "opencode anchor rotated for a same-key retry without marking the previous exit ip"
            );
        }
    }
}

/// 把 pin 的出口 IP 改写成 `next_ip`；结构不对（没有 profile / 不是对象）返回 false。
fn write_opencode_pin_ip(plan: &mut aether_contracts::ExecutionPlan, next_ip: &str) -> bool {
    let Some(profile) = plan.transport_profile.as_mut() else {
        return false;
    };
    let Some(extra) = profile
        .extra
        .get_or_insert_with(|| serde_json::json!({}))
        .as_object_mut()
    else {
        return false;
    };
    let Some(pin) = extra
        .entry("opencode_dns_pin".to_string())
        .or_insert_with(|| serde_json::json!({}))
        .as_object_mut()
    else {
        return false;
    };
    pin.insert(
        "ip".to_string(),
        serde_json::Value::String(next_ip.to_string()),
    );
    true
}

/// 换点用的池：**唯一**定义在 [`crate::opencode_pool::OpenCodeScanConfig::effective_pool`]
/// （`healthy` ∪ `exit_pool` 里未异常/未拉黑的成员）。
///
/// 这里以前又解析了一遍 JSON（`healthy` 非空就用它，否则退回 `exit_pool`），
/// 于是「池子怎么算」有两份实现：规划期与 429 换点各一份，谁改了另一份就看不见。
/// trust-on-add 之后这不再只是风格问题——未验证 IP 必须**同时**出现在两条路径上，
/// 否则「规划期抽得到、换点抽不到」会让重试回到一个已排除的池子里打转。
/// `opencode_scan.exit_pool_disabled`，与规划期 `disabled_exit_ips` 同解析。
fn opencode_retry_disabled_exit_ips(section: Option<&serde_json::Value>) -> Vec<String> {
    section
        .and_then(|section| section.get("exit_pool_disabled"))
        .and_then(serde_json::Value::as_array)
        .map(|items| {
            items
                .iter()
                .filter_map(serde_json::Value::as_str)
                .map(str::trim)
                .filter(|value| !value.is_empty())
                .map(str::to_string)
                .collect()
        })
        .unwrap_or_default()
}

/// 保底池大小：低于这个数量，任何机制都不允许把池子变小。
///
/// 会话粘性和被动降权的收益随池增大而升高，风险却随池减小而放大：
// 三个节点的池子里冷却掉一个就只剩两个，一个设备锁死一个节点就没有
// 分散可言。所以保底是硬约束，不提供关闭开关。
pub(crate) const OPENCODE_DEFAULT_MIN_POOL_SIZE: usize = 5;
// 会话粘性的最小可用池：低于此数量自动退回游标轮转。
pub(crate) const OPENCODE_DEFAULT_STICKY_MIN_POOL: usize = 10;

// 从 provider 快照读验健康配置；非 opencode 或读不到时返回 `None`。
// 拿不到配置就宁可不降权——宁可漏掉一次信号，也不要误伤一个好节点。

// ---------------------------------------------------------------------------
// 429 / 配额型 403 的「延迟重试 + 随机换点」：等待阶梯 + 尝试次数上限
// ---------------------------------------------------------------------------
//
// 2026-10 线上复盘：opencode 账户日额度耗尽后，每个出口 IP 收到 429 都被上游
// `retry-after` 打成约 6 小时冷却；而当时的 429 重试是「优先换 /24 段、预算 8 段 /
// 15 秒」，于是一个请求最多可能把 **8 个不同段的 IP** 一起钉进冷却——124 个节点
// 就是这么被逐个打死，成功率却没提高。配额是**账户维度**的，换 IP 不解决根本问题。
//
// 所以配额型失败（429 / 带额度文案的 403）改成**等待式**重试：
//
// 1. 先按阶梯等一段时间（默认 10s / 20s / 40s 的档位），再换点；
// 2. 换点只从**当前未冷却**的出口 IP 里按 **/24 段随机**挑一个（见
//    [`pick_segment_aware_anchor`]），不再按 /24 段顺序优先——顺序换点会围着同一段/
//    相邻段的兄弟 IP 打转，而它们的额度状态往往同步，等于换个 IP 继续撞同一堵墙；
//    按 IP 等概率随机会反向砸在大段上（5 IP/段 vs 1 IP/段），同样不行；
// 3. 尝试次数封顶 `max_attempts`（默认 3，**含第一次**）：用完即失败返回，
//    不靠「多打几个 IP」换成功率。默认配置下真正的两次等待是 10s、20s
//    （第 3 次尝试失败后就是终态；第 3 档 40s 留给把 `quota_retry_max_attempts`
//    调到 4 及以上的配置）。
//
// 与 `OpenCodeDelayedRetryPolicy`（上下文超限的延迟重试）同一套阶梯算法与校验口径，
// 区别是这里**自带次数上限**：429 是账户级限流，重试太多次只会让客户端白等。
//
// **503 / 5xx / 超时 / 调用方自己的错一行都不受影响**：它们的标记是
// [`OpenCodeExitIpMark::Avoid`] 或 `None`，进不到这个分支，选点顺序与改动前一致。

/// 429 延迟重试的第一档等待（毫秒）。
pub(crate) const DEFAULT_OPENCODE_QUOTA_RETRY_BASE_MS: u64 = 10_000;
/// 相邻两档之间的增长倍数。
pub(crate) const DEFAULT_OPENCODE_QUOTA_RETRY_MULTIPLIER: u64 = 2;
/// 单次等待的上限（毫秒）。默认正好是阶梯第三档，配置放大也不会睡过头。
pub(crate) const DEFAULT_OPENCODE_QUOTA_RETRY_MAX_MS: u64 = 40_000;
/// 一次请求在配额型失败上的**总尝试次数**上限（含第一次）。
pub(crate) const DEFAULT_OPENCODE_QUOTA_RETRY_MAX_ATTEMPTS: u32 = 3;
/// 校验框架接受的最大单次等待（毫秒）。比上下文超限那套（300s）更紧：
/// 429 是账户级限流，等不到额度刷新，等久了只是拖住客户端。
pub(crate) const MAX_OPENCODE_QUOTA_RETRY_DELAY_MS: u64 = 120_000;
/// 校验框架接受的最大增长倍数。
pub(crate) const MAX_OPENCODE_QUOTA_RETRY_MULTIPLIER: u64 = 100;
/// 校验框架接受的最大尝试次数（含第一次）。
pub(crate) const MAX_OPENCODE_QUOTA_RETRY_ATTEMPTS: u32 = 10;

/// `opencode_scan` 段里的总开关：关掉即完全退回「换点」路径（改动前的行为）。
pub(crate) const OPENCODE_QUOTA_RETRY_ENABLED_FIELD: &str = "quota_retry_enabled";
/// 第一档等待（毫秒）。
pub(crate) const OPENCODE_QUOTA_RETRY_BASE_MS_FIELD: &str = "quota_retry_base_ms";
/// 增长倍数。
pub(crate) const OPENCODE_QUOTA_RETRY_MULTIPLIER_FIELD: &str = "quota_retry_multiplier";
/// 单次等待上限（毫秒）。
pub(crate) const OPENCODE_QUOTA_RETRY_MAX_MS_FIELD: &str = "quota_retry_max_ms";
/// 总尝试次数上限（含第一次）。
pub(crate) const OPENCODE_QUOTA_RETRY_MAX_ATTEMPTS_FIELD: &str = "quota_retry_max_attempts";
/// 本次请求「已经试过哪些 IP」在 `plan.transport_profile.extra` 里的键。
const OPENCODE_QUOTA_RETRY_EXTRA_KEY: &str = "opencode_quota_retry";

/// 429 / 配额型 403 的延迟重试策略。
///
/// 语义是「**等一等，再从还没被限流的节点里随机换一个**」而不是「按段依次扩散」：
/// 配额型失败与出口节点无关，按顺序换点只会把同一段/相邻段的节点一起冷静掉。
/// `max_attempts` 让它同时是次数上限——默认 3 次（含第一次）之后直接失败返回。
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct OpenCodeQuotaRetryPolicy {
    /// 关掉之后完全退回改动前：不等待、不限制次数，交给换点路径。
    pub(crate) enabled: bool,
    /// 第一次等待。
    pub(crate) base_ms: u64,
    /// 每多一档乘这个倍数。
    pub(crate) multiplier: u64,
    /// 单次等待的上限。
    pub(crate) max_ms: u64,
    /// 总尝试次数上限（含第一次；`3` = 首次 + 两次重试）。
    pub(crate) max_attempts: u32,
}

impl Default for OpenCodeQuotaRetryPolicy {
    fn default() -> Self {
        Self {
            enabled: true,
            base_ms: DEFAULT_OPENCODE_QUOTA_RETRY_BASE_MS,
            multiplier: DEFAULT_OPENCODE_QUOTA_RETRY_MULTIPLIER,
            max_ms: DEFAULT_OPENCODE_QUOTA_RETRY_MAX_MS,
            max_attempts: DEFAULT_OPENCODE_QUOTA_RETRY_MAX_ATTEMPTS,
        }
    }
}

impl OpenCodeQuotaRetryPolicy {
    /// 从 provider 的 `config.opencode_scan` 读覆盖值；缺省即默认值。
    ///
    /// 越界就地夹紧（与 `OpenCodeSegmentBudgetPolicy` / `OpenCodeDelayedRetryPolicy`
    /// 同一口径：手改的配置不能变成一次无限等待或无限重试），写入时的边界由
    /// `OpenCodeScanConfig::validate_section` 拦。
    pub(crate) fn from_provider_config(config: &Option<serde_json::Value>) -> Self {
        let mut policy = Self::default();
        let Some(section) = config
            .as_ref()
            .and_then(|config| config.get("opencode_scan"))
        else {
            return policy;
        };
        if let Some(enabled) = section
            .get(OPENCODE_QUOTA_RETRY_ENABLED_FIELD)
            .and_then(serde_json::Value::as_bool)
        {
            policy.enabled = enabled;
        }
        if let Some(value) = section
            .get(OPENCODE_QUOTA_RETRY_MAX_MS_FIELD)
            .and_then(serde_json::Value::as_u64)
        {
            policy.max_ms = value.clamp(1, MAX_OPENCODE_QUOTA_RETRY_DELAY_MS);
        }
        if let Some(value) = section
            .get(OPENCODE_QUOTA_RETRY_BASE_MS_FIELD)
            .and_then(serde_json::Value::as_u64)
        {
            // 先按 clamp 后的 max_ms 收敛：base 大于 max 会让阶梯失去意义。
            policy.base_ms = value.min(policy.max_ms).max(1);
        }
        if let Some(value) = section
            .get(OPENCODE_QUOTA_RETRY_MULTIPLIER_FIELD)
            .and_then(serde_json::Value::as_u64)
        {
            policy.multiplier = value.clamp(1, MAX_OPENCODE_QUOTA_RETRY_MULTIPLIER);
        }
        if let Some(value) = section
            .get(OPENCODE_QUOTA_RETRY_MAX_ATTEMPTS_FIELD)
            .and_then(serde_json::Value::as_u64)
        {
            policy.max_attempts =
                value.clamp(1, u64::from(MAX_OPENCODE_QUOTA_RETRY_ATTEMPTS)) as u32;
        }
        policy
    }

    /// 拒绝会让延迟重试失去意义的配置（0 毫秒 / 0 次）。
    /// 关掉时不校验数值：允许在关闭状态下留一份半成品配置，与其它策略一致。
    pub(crate) fn validate(&self) -> Result<(), String> {
        if !self.enabled {
            return Ok(());
        }
        for (name, value) in [
            (OPENCODE_QUOTA_RETRY_BASE_MS_FIELD, self.base_ms),
            (OPENCODE_QUOTA_RETRY_MAX_MS_FIELD, self.max_ms),
        ] {
            if value == 0 || value > MAX_OPENCODE_QUOTA_RETRY_DELAY_MS {
                return Err(format!(
                    "opencode {name} must be between 1 and {MAX_OPENCODE_QUOTA_RETRY_DELAY_MS}"
                ));
            }
        }
        if self.base_ms > self.max_ms {
            return Err(format!(
                "opencode {OPENCODE_QUOTA_RETRY_BASE_MS_FIELD} must not exceed {OPENCODE_QUOTA_RETRY_MAX_MS_FIELD}"
            ));
        }
        if self.multiplier == 0 || self.multiplier > MAX_OPENCODE_QUOTA_RETRY_MULTIPLIER {
            return Err(format!(
                "opencode {OPENCODE_QUOTA_RETRY_MULTIPLIER_FIELD} must be between 1 and {MAX_OPENCODE_QUOTA_RETRY_MULTIPLIER}"
            ));
        }
        if self.max_attempts == 0 || self.max_attempts > MAX_OPENCODE_QUOTA_RETRY_ATTEMPTS {
            return Err(format!(
                "opencode {OPENCODE_QUOTA_RETRY_MAX_ATTEMPTS_FIELD} must be between 1 and {MAX_OPENCODE_QUOTA_RETRY_ATTEMPTS}"
            ));
        }
        Ok(())
    }

    /// 阶梯上第 `retry_index` 档（0 基）的等待，**不看次数上限**。
    ///
    /// `base_ms`、`base_ms * multiplier`、`base_ms * multiplier^2`… 封顶 `max_ms`。
    /// 越界就地夹紧，手改的配置不可能变成一次数小时的 sleep。
    pub(crate) fn delay_for_retry(&self, retry_index: u32) -> Option<std::time::Duration> {
        if !self.enabled {
            return None;
        }
        let max_ms = self.max_ms.clamp(1, MAX_OPENCODE_QUOTA_RETRY_DELAY_MS);
        let base_ms = self.base_ms.clamp(1, max_ms);
        let multiplier = self
            .multiplier
            .clamp(1, MAX_OPENCODE_QUOTA_RETRY_MULTIPLIER);
        let mut delay_ms = base_ms;
        // `retry_index` 来自重试链上的序号，仍然夹紧一次，保证循环边界与外部输入无关。
        for _ in 0..retry_index.min(32) {
            if delay_ms >= max_ms {
                break;
            }
            delay_ms = delay_ms.saturating_mul(multiplier).min(max_ms);
        }
        Some(std::time::Duration::from_millis(delay_ms.min(max_ms)))
    }
}

/// 本次请求在配额型失败上**已经试过的出口 IP**。
///
/// 存放位置与段预算状态同一个地方（`plan.transport_profile.extra`）：同 key 重试是
/// **克隆上一份 plan** 再重编号，所以写在 plan 里的集合天然被下一次重试读到，
/// 既不需要全局可变状态，也不会泄漏到别的请求。
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub(crate) struct OpenCodeQuotaRetryState {
    /// 已经试过的出口 IP（有序去重）。重试时**不再挑它们**。
    pub(crate) tried_ips: Vec<String>,
}

impl OpenCodeQuotaRetryState {
    /// 记一个 IP。重复命中去重：同一个 IP 试过多少次都只占一个名额。
    pub(crate) fn record(&mut self, ip: &str) {
        let ip = ip.trim();
        if ip.is_empty() || self.tried_ips.iter().any(|seen| seen == ip) {
            return;
        }
        self.tried_ips.push(ip.to_string());
    }

    fn to_json(&self) -> serde_json::Value {
        serde_json::json!({ "tried_ips": self.tried_ips })
    }

    fn from_json(value: &serde_json::Value) -> Self {
        let mut state = Self::default();
        if let Some(items) = value.get("tried_ips").and_then(serde_json::Value::as_array) {
            for item in items {
                if let Some(ip) = item.as_str() {
                    state.record(ip);
                }
            }
        }
        state
    }
}

/// 读回 plan 里的「已试 IP」记录；没有就返回空状态。
fn read_quota_retry_state(plan: &aether_contracts::ExecutionPlan) -> OpenCodeQuotaRetryState {
    plan.transport_profile
        .as_ref()
        .and_then(|profile| profile.extra.as_ref())
        .and_then(|extra| extra.get(OPENCODE_QUOTA_RETRY_EXTRA_KEY))
        .map(OpenCodeQuotaRetryState::from_json)
        .unwrap_or_default()
}

/// 把「已试 IP」写回 plan 的 transport profile extra；结构不对返回 `false`。
fn write_quota_retry_state(
    plan: &mut aether_contracts::ExecutionPlan,
    state: &OpenCodeQuotaRetryState,
) -> bool {
    let Some(profile) = plan.transport_profile.as_mut() else {
        return false;
    };
    let Some(extra) = profile
        .extra
        .get_or_insert_with(|| serde_json::json!({}))
        .as_object_mut()
    else {
        return false;
    };
    extra.insert(OPENCODE_QUOTA_RETRY_EXTRA_KEY.to_string(), state.to_json());
    true
}

/// FNV-1a 64 位哈希。只用于「按种子打散」，不参与任何安全判定。
fn fnv1a64(value: &str) -> u64 {
    let mut hash: u64 = 0xcbf2_9ce4_8422_2325;
    for byte in value.as_bytes() {
        hash ^= u64::from(*byte);
        hash = hash.wrapping_mul(0x0000_0100_0000_01b3);
    }
    hash
}

/// splitmix64 的收尾混合。
///
/// 为什么需要这一步：直接比 `fnv1a64("seed:ip")` 会在「种子只差一两个字符」时退化——
/// FNV 是逐字节乘加，前缀一变、后缀贡献是同一组线性变换，argmin 就会长期落在同一个
/// 候选上（实测 40 个相邻种子只命中 7/10）。先按 IP 取哈希、再和种子异或后过一遍雪崩
/// 混合，相邻种子的结果才真的互不相关。
fn mix64(mut value: u64) -> u64 {
    value ^= value >> 30;
    value = value.wrapping_mul(0xbf58_476d_1ce4_e5b9);
    value ^= value >> 27;
    value = value.wrapping_mul(0x94d0_49bb_1331_11eb);
    value ^ (value >> 31)
}

/// 从「当前未冷却」的候选里按种子**随机**挑一个的说明（已并入段随机选点）。
///
/// 2026-10 起这里不再是独立实现：按 IP 等概率随机会让「5 个 IP 的段」被点中的概率是
/// 「1 个 IP 的段」的 5 倍，而 429 额度是按 /24 段共享的——换到同段兄弟 IP 等于原地
/// 打转。429 重试换点现在与主路径共用 [`pick_segment_aware_anchor`]
/// （段等概率 + 段内在途上限），`seed` 仍然决定结果，因此同一请求的同一档重试**可复现**。
///
/// **不做**「全部冷却就退回挑一个冷却中的 IP」这种兜底：退回被限流的节点等于没有换点，
/// 调用方应当快速失败（见 `rotate_opencode_anchor_for_retry_plan`）。
///
/// 延迟重试的触发原因标签。
///
/// 日志事件 `opencode_delayed_retry` 同时服务三类触发（上下文超长的 400 在
/// `execution_runtime` 里记 `context_length`），这里补上配额型的两种，
/// 以后再排查「到底是谁在等」就不用靠状态码猜了。
fn opencode_delayed_retry_reason(status_code: Option<u16>) -> &'static str {
    match status_code {
        Some(429) => "quota_429",
        Some(403) => "quota_403",
        _ => "quota_other",
    }
}
//
// 2026-10 实测：opencode 出口 IP 的 429 是**按 /24 段共享额度**的——同一段的兄弟
// IP 会一起被限（18.154.128.1/2/5、23.228.247.1/4、65.8.192.5/6 同时冷却）。
// 于是「429 之后换到同段的另一个 IP」等于原地打转：当天 525 个请求的重试链是
// `429->429->429`（三次全灭），重试预算烧完了、段却只试过一个。
//
// 这里给 429 重试加一层**段维度**的记账与预算：
//
// 1. 每次配额型失败把「该 IP 所在段」记进本次请求的已试集合；
// 2. 下一次选点**优先选段没试过的 IP**，同段其它 IP 只降级、不排除；
// 3. 最多试 [`OPENCODE_DEFAULT_SEGMENT_BUDGET`] 个不同段、总耗时不超过
//    [`OPENCODE_DEFAULT_SEGMENT_BUDGET_MS`]，任一耗尽就立刻放弃重试。
//
// **503 一行都不受影响**：那类失败走 [`OpenCodeExitIpMark::Avoid`]（上游整体故障，
// 当天 56/57 个段一起 503），既不记段、不判预算、也不改选点顺序。
//
// **默认已关闭**（2026-10）：配额型失败现在走前面的「延迟重试 + 随机换点」，
// `OpenCodeSegmentBudgetPolicy::default()` 的 `enabled` 是 `false`——一个请求最多
// 只碰 3 个节点（还是随机挑的），不再按段扩散。代码与配置能力全部保留：显式把
// `opencode_scan.segment_budget_enabled` 打开即可恢复「按 /24 段优先」的老策略。
// 事件名 `opencode_segment_preferred` / `opencode_segment_budget_exhausted` 保持不变
// （有日志消费方按名字统计），但默认配置下不会再出现。

/// 一次请求最多换到多少个**不同 /24 段**（`opencode_scan.segment_budget_segments`）。
///
/// 这是**段预算被显式打开时**的档位：`OpenCodeSegmentBudgetPolicy::default()` 已经把
/// 总开关关掉了，429 现在走延迟重试 + 随机换点，不再靠换段多打 IP。
pub(crate) const OPENCODE_DEFAULT_SEGMENT_BUDGET: usize = 8;
/// 一次请求换点最多花多少毫秒（`opencode_scan.segment_budget_ms`）。
pub(crate) const OPENCODE_DEFAULT_SEGMENT_BUDGET_MS: u64 = 15_000;
/// 校验框架接受的最大段数。
pub(crate) const MAX_OPENCODE_SEGMENT_BUDGET: u64 = 64;
/// 校验框架接受的最大耗时（毫秒）。
pub(crate) const MAX_OPENCODE_SEGMENT_BUDGET_MS: u64 = 120_000;
/// `opencode_scan` 段里的开关：关掉即完全退回改动前的行为。
pub(crate) const OPENCODE_SEGMENT_BUDGET_ENABLED_FIELD: &str = "segment_budget_enabled";
/// `opencode_scan` 段里的段数上限。
pub(crate) const OPENCODE_SEGMENT_BUDGET_SEGMENTS_FIELD: &str = "segment_budget_segments";
/// `opencode_scan` 段里的耗时上限（毫秒）。
pub(crate) const OPENCODE_SEGMENT_BUDGET_MS_FIELD: &str = "segment_budget_ms";
/// 段预算状态在 `plan.transport_profile.extra` 里的键。
const OPENCODE_SEGMENT_BUDGET_EXTRA_KEY: &str = "opencode_segment_budget";

/// 出口 IP 的 /24 段 = 前三段 `a.b.c`（`1.2.3.4` → `1.2.3`）。
///
/// 非 IPv4 / 非法点分返回 `None`，调用方把「算不出段」当成「不参与段预算」：
/// 宁可少一次降级，也不要因为一段脏数据挡住一次重试或排除一个节点。
pub(crate) fn opencode_ip_segment(ip: &str) -> Option<String> {
    let octets = ip.trim().parse::<std::net::Ipv4Addr>().ok()?.octets();
    Some(format!("{}.{}.{}", octets[0], octets[1], octets[2]))
}

/// 429 换点的段预算配置（**默认关闭**）。
///
/// 2026-10 线上复盘之后，配额型失败改由「延迟重试 + 随机换点」接管：换段顺序会把
/// 同一段/相邻段的兄弟 IP 一起打进 6 小时冷却，而它们的额度状态往往同步，等于换个
/// IP 继续撞同一堵墙。这里保留全部代码与配置能力，只是默认 `enabled = false`；
/// 显式打开即恢复「8 段 / 15 秒」的老行为，配置只能收紧、不能放宽语义。
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct OpenCodeSegmentBudgetPolicy {
    /// 段优先与预算判定的总开关。**默认 false**：默认不再靠「多打几个段的 IP」
    /// 换成功率（配额型失败是账户维度的，多打 IP 只会把节点一起钉进冷却）。
    pub(crate) enabled: bool,
    /// 最多试多少个不同段（仅在 `enabled` 时生效）。
    pub(crate) max_segments: usize,
    /// 从首次配额型失败算起的总耗时上限（毫秒，仅在 `enabled` 时生效）。
    pub(crate) max_elapsed_ms: u64,
}

impl Default for OpenCodeSegmentBudgetPolicy {
    fn default() -> Self {
        Self {
            // 默认关闭：429 改走延迟重试 + 随机换点，段扩散只会多打 IP。
            enabled: false,
            max_segments: OPENCODE_DEFAULT_SEGMENT_BUDGET,
            max_elapsed_ms: OPENCODE_DEFAULT_SEGMENT_BUDGET_MS,
        }
    }
}

impl OpenCodeSegmentBudgetPolicy {
    /// 从 provider 的 `config.opencode_scan` 读覆盖值；缺省即默认值。
    ///
    /// 越界就地夹紧（与 `OpenCodeDelayedRetryPolicy` 同一口径：手改的配置不能变成
    /// 一次无限重试），写入时的边界由 `OpenCodeScanConfig::validate_section` 拦。
    pub(crate) fn from_provider_config(config: &Option<serde_json::Value>) -> Self {
        let mut policy = Self::default();
        let Some(section) = config
            .as_ref()
            .and_then(|config| config.get("opencode_scan"))
        else {
            return policy;
        };
        if let Some(enabled) = section
            .get(OPENCODE_SEGMENT_BUDGET_ENABLED_FIELD)
            .and_then(serde_json::Value::as_bool)
        {
            policy.enabled = enabled;
        }
        if let Some(value) = section
            .get(OPENCODE_SEGMENT_BUDGET_SEGMENTS_FIELD)
            .and_then(serde_json::Value::as_u64)
        {
            policy.max_segments = value.clamp(1, MAX_OPENCODE_SEGMENT_BUDGET) as usize;
        }
        if let Some(value) = section
            .get(OPENCODE_SEGMENT_BUDGET_MS_FIELD)
            .and_then(serde_json::Value::as_u64)
        {
            policy.max_elapsed_ms = value.clamp(1, MAX_OPENCODE_SEGMENT_BUDGET_MS);
        }
        policy
    }

    /// 拒绝会让段预算失去意义的配置（0 段 / 0 毫秒）。关掉时不校验数值：
    /// 允许在关闭状态下留一份半成品配置，和 `OpenCodeDelayedRetryPolicy` 一致。
    pub(crate) fn validate(&self) -> Result<(), String> {
        if !self.enabled {
            return Ok(());
        }
        if self.max_segments == 0 || self.max_segments as u64 > MAX_OPENCODE_SEGMENT_BUDGET {
            return Err(format!(
                "opencode segment budget segments must be between 1 and {MAX_OPENCODE_SEGMENT_BUDGET}"
            ));
        }
        if self.max_elapsed_ms == 0 || self.max_elapsed_ms > MAX_OPENCODE_SEGMENT_BUDGET_MS {
            return Err(format!(
                "opencode segment budget ms must be between 1 and {MAX_OPENCODE_SEGMENT_BUDGET_MS}"
            ));
        }
        Ok(())
    }
}

/// 本次请求的「已试段集合 + 预算起点」。
///
/// 存放位置：`plan.transport_profile.extra["opencode_segment_budget"]`——与出口 IP
/// 的 pin（`opencode_dns_pin`）同一个地方。同 key 重试是**克隆上一份 plan** 再重编号
/// （`AiExecutionAttempt::with_same_key_retry`），所以写在 plan 里的集合天然被下一次
/// 重试读到；既不需要全局可变状态，也不会泄漏到别的请求。
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub(crate) struct OpenCodeSegmentBudgetState {
    /// 已经试过的段（有序去重）。
    pub(crate) segments: Vec<String>,
    /// 预算起点（毫秒时间戳）；`0` = 还没起算。
    pub(crate) started_at_ms: u64,
}

impl OpenCodeSegmentBudgetState {
    /// 记一个段。同段重复命中**不重复计数**：一个段试过多少次都只占一个名额。
    pub(crate) fn record(&mut self, segment: Option<&str>) {
        let Some(segment) = segment.map(str::trim).filter(|value| !value.is_empty()) else {
            return;
        };
        if self.segments.iter().any(|seen| seen == segment) {
            return;
        }
        self.segments.push(segment.to_string());
    }

    fn to_json(&self) -> serde_json::Value {
        serde_json::json!({
            "segments": self.segments,
            "started_at_ms": self.started_at_ms,
        })
    }

    fn from_json(value: &serde_json::Value) -> Self {
        let mut state = Self {
            segments: Vec::new(),
            started_at_ms: value
                .get("started_at_ms")
                .and_then(serde_json::Value::as_u64)
                .unwrap_or(0),
        };
        if let Some(items) = value.get("segments").and_then(serde_json::Value::as_array) {
            for item in items {
                state.record(item.as_str());
            }
        }
        state
    }
}

/// 读回 plan 里的段预算状态；没有就返回空状态（= 一个段都没试过）。
fn read_segment_budget_state(plan: &aether_contracts::ExecutionPlan) -> OpenCodeSegmentBudgetState {
    plan.transport_profile
        .as_ref()
        .and_then(|profile| profile.extra.as_ref())
        .and_then(|extra| extra.get(OPENCODE_SEGMENT_BUDGET_EXTRA_KEY))
        .map(OpenCodeSegmentBudgetState::from_json)
        .unwrap_or_default()
}

/// 把段预算状态写回 plan 的 transport profile extra；结构不对返回 `false`。
fn write_segment_budget_state(
    plan: &mut aether_contracts::ExecutionPlan,
    state: &OpenCodeSegmentBudgetState,
) -> bool {
    let Some(profile) = plan.transport_profile.as_mut() else {
        return false;
    };
    let Some(extra) = profile
        .extra
        .get_or_insert_with(|| serde_json::json!({}))
        .as_object_mut()
    else {
        return false;
    };
    extra.insert(
        OPENCODE_SEGMENT_BUDGET_EXTRA_KEY.to_string(),
        state.to_json(),
    );
    true
}

/// 「这次失败要不要 / 还能不能再换一段」。
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum OpenCodeSegmentBudgetOutcome {
    /// 不是配额型失败（503 / 5xx / 超时 / 调用方自己的错）：段预算完全不参与，
    /// 段集合与选点顺序一字不动。
    NotApplicable,
    /// 还有预算，可以换点重试。
    Continue,
    /// 已试段数达到上限。
    ExhaustedSegments,
    /// 总耗时达到上限。
    ExhaustedElapsed,
}

impl OpenCodeSegmentBudgetOutcome {
    /// 预算是否耗尽（两种耗尽方式共用同一套失败语义）。
    pub(crate) fn is_exhausted(self) -> bool {
        matches!(self, Self::ExhaustedSegments | Self::ExhaustedElapsed)
    }

    /// 日志里的原因标签。
    pub(crate) fn reason(self) -> &'static str {
        match self {
            Self::NotApplicable => "not_applicable",
            Self::Continue => "continue",
            Self::ExhaustedSegments => "segments",
            Self::ExhaustedElapsed => "elapsed",
        }
    }
}

/// 配额型失败的段记账 + 预算判定（纯函数，便于单测）。
///
/// **只有 [`OpenCodeExitIpMark::Cooldown`]（429 / 带额度文案的 403）才记账**：
/// 503 这类上游整体故障走 `Avoid`，进不来这个函数的状态里，因此段集合、预算、
/// 选点顺序对它们完全无影响。
pub(crate) fn opencode_segment_budget_step(
    mark: OpenCodeExitIpMark,
    state: &mut OpenCodeSegmentBudgetState,
    failed_ip: &str,
    policy: OpenCodeSegmentBudgetPolicy,
    now_ms: u64,
) -> OpenCodeSegmentBudgetOutcome {
    if mark != OpenCodeExitIpMark::Cooldown || !policy.enabled {
        return OpenCodeSegmentBudgetOutcome::NotApplicable;
    }
    if state.started_at_ms == 0 {
        // 预算起点：本次请求的**第一次配额型失败**。首次尝试到此之间的差距只有
        // 「首个 attempt 的耗时」，用失败现场的时间戳当起点是保守的（不会放宽预算）。
        state.started_at_ms = now_ms;
    }
    state.record(opencode_ip_segment(failed_ip).as_deref());
    if state.segments.len() >= policy.max_segments.max(1) {
        return OpenCodeSegmentBudgetOutcome::ExhaustedSegments;
    }
    if now_ms.saturating_sub(state.started_at_ms) >= policy.max_elapsed_ms.max(1) {
        return OpenCodeSegmentBudgetOutcome::ExhaustedElapsed;
    }
    OpenCodeSegmentBudgetOutcome::Continue
}

/// 可用点按「段是否已试过」分组的结果。
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub(crate) struct OpenCodeSegmentSplit {
    /// 段还没试过的点：**优先**。
    pub(crate) untried: Vec<String>,
    /// 段已经试过的点：**降级保留而不是排除**。池子极端时（全池只剩一个段）
    /// 排除等于把请求打死，留一个同段兄弟 IP 至少还有一次机会。
    pub(crate) tried: Vec<String>,
}

impl OpenCodeSegmentSplit {
    /// 选点空间：有未试段就只在未试段里选，否则退回全部同段点。
    pub(crate) fn search_space(&self) -> &[String] {
        if self.untried.is_empty() {
            &self.tried
        } else {
            &self.untried
        }
    }

    /// 是否已经降级到「只能在已试段里选」。
    pub(crate) fn degraded_to_tried_segment(&self) -> bool {
        self.untried.is_empty() && !self.tried.is_empty()
    }

    /// 因为「优先未试段」被压后的同段候选数量（0 = 没有发生降级）。
    pub(crate) fn skipped_same_segment(&self) -> usize {
        if self.untried.is_empty() {
            0
        } else {
            self.tried.len()
        }
    }
}

/// 把可用点按段分组。`tried_segments` 为空时原样返回（= 改动前的行为）。
pub(crate) fn split_usable_by_segment(
    usable: &[String],
    tried_segments: &[String],
) -> OpenCodeSegmentSplit {
    let tried: std::collections::BTreeSet<&str> = tried_segments
        .iter()
        .map(|segment| segment.trim())
        .filter(|segment| !segment.is_empty())
        .collect();
    if tried.is_empty() {
        return OpenCodeSegmentSplit {
            untried: usable.to_vec(),
            tried: Vec::new(),
        };
    }
    let mut split = OpenCodeSegmentSplit::default();
    for ip in usable {
        match opencode_ip_segment(ip) {
            Some(segment) if tried.contains(segment.as_str()) => split.tried.push(ip.clone()),
            // 段算不出来的点当成「未试」：解析失败不该让它变成二等公民。
            _ => split.untried.push(ip.clone()),
        }
    }
    split
}

// ---------------------------------------------------------------------------
// /24 段等概率随机选点 + 段内在途上限
// ---------------------------------------------------------------------------
//
// 2026-10 实测（三条，结论稳定）：
//
// 1. **429 额度按 /24 段共享**：打爆 `18.154.128.6` 之后，同段 `.1`–`.5` 立刻全 429；
//    连**从未使用过**的 `.7`–`.26`（20 个）也全 429。段内有多少个 IP 都不影响额度包。
// 2. **触发靠并发不靠次数**：同一 IP 串行打 60 次全 200，14 路并发立刻 3 成功 / 11 个 429。
// 3. 池子现状：1086 个 IP / 694 个 /24 段，段规模极不均（CloudFront 平均 5 IP/段，
//    国内 1.1 IP/段）。
//
// 于是选点必须同时满足两条：
//
// - **段等概率**：按 IP 均匀随机会让「5 个 IP 的段」被点中的概率是「1 个 IP 的段」的
//   5 倍——大段（CloudFront）先被抽干，小段几乎没被用过。要的是先等概率选段、再在段内选。
// - **段内在途封顶**：同段并发就是上面第 2 条打爆的原因，每个段同时只放
//   [`OPENCODE_DEFAULT_SEGMENT_MAX_IN_FLIGHT`] 个请求进去。
//
// 顺序游标（`cursor + 1`）因此被换掉：池子从 124 个 IP 涨到 1086 个之后，游标推进速度
// 远慢于池子增长速度，新加进来的段「永远轮不到」。游标本身保留，现在只当**随机种子**用。

/// 每个 /24 段默认允许的在途请求数（`opencode_scan.segment_max_in_flight`）。
pub(crate) const OPENCODE_DEFAULT_SEGMENT_MAX_IN_FLIGHT: usize = 2;
/// 校验框架接受的在途上限；读取时越界就地夹紧到 `1..=`[`MAX_OPENCODE_SEGMENT_MAX_IN_FLIGHT`]。
pub(crate) const MAX_OPENCODE_SEGMENT_MAX_IN_FLIGHT: u64 = 16;
/// `opencode_scan` 段里的在途上限字段。
pub(crate) const OPENCODE_SEGMENT_MAX_IN_FLIGHT_FIELD: &str = "segment_max_in_flight";
/// 在途名额的有效期（毫秒）。
///
/// 规划期选点（planner 的 `post_rank_reorder`）拿不到「请求结束」这个时机——候选列表在
/// 计划物化之后就被丢掉了，没有能安全持有 [`OpenCodeSegmentLease`] 到响应结束的作用域。
/// 那条路径上的名额交给 TTL 回收：**每条记录都带过期时间**，所以即使某条记账漏掉释放，
/// 最多让一个段在 15 秒内少接几个请求，**绝不会**变成「这个段永久选不到」。
const OPENCODE_SEGMENT_IN_FLIGHT_TTL_MS: u64 = 15_000;
/// 「选段」与「占名额」之间没有锁，选中之后那段可能刚被别的请求占满：换下一个随机段重试。
const OPENCODE_SEGMENT_PICK_ATTEMPTS: usize = 4;

/// 段内在途上限的配置（`opencode_scan.segment_max_in_flight`，默认 2，范围 1–16）。
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct OpenCodeSegmentConcurrencyPolicy {
    /// 同一个 /24 段同时允许的在途请求数。
    pub(crate) max_in_flight: usize,
}

impl Default for OpenCodeSegmentConcurrencyPolicy {
    fn default() -> Self {
        Self {
            max_in_flight: OPENCODE_DEFAULT_SEGMENT_MAX_IN_FLIGHT,
        }
    }
}

impl OpenCodeSegmentConcurrencyPolicy {
    /// 从 provider 的 `config.opencode_scan` 读覆盖值；缺省即默认值。
    ///
    /// 越界就地夹紧（与 [`OpenCodeSegmentBudgetPolicy`] 同一口径：手改的配置不能变成
    /// 「一个段只放 0 个请求」这种自我封锁），写入时的边界由
    /// `OpenCodeScanConfig::validate_section` 拦。
    pub(crate) fn from_provider_config(config: &Option<serde_json::Value>) -> Self {
        let mut policy = Self::default();
        let Some(section) = config
            .as_ref()
            .and_then(|config| config.get("opencode_scan"))
        else {
            return policy;
        };
        if let Some(value) = section
            .get(OPENCODE_SEGMENT_MAX_IN_FLIGHT_FIELD)
            .and_then(serde_json::Value::as_u64)
        {
            policy.max_in_flight = value.clamp(1, MAX_OPENCODE_SEGMENT_MAX_IN_FLIGHT) as usize;
        }
        policy
    }

    /// 拒绝会让选点失去意义的配置（0 个在途 = 每个段都「已满」）。
    pub(crate) fn validate(&self) -> Result<(), String> {
        if self.max_in_flight == 0 || self.max_in_flight as u64 > MAX_OPENCODE_SEGMENT_MAX_IN_FLIGHT
        {
            return Err(format!(
                "opencode segment max in flight must be between 1 and {MAX_OPENCODE_SEGMENT_MAX_IN_FLIGHT}"
            ));
        }
        Ok(())
    }
}

/// 一条「段内在途」记录。`expires_at_ms` 是兜底回收线：名额的持有者即使没机会减计数
/// （规划期选点、请求被取消、进程内 panic），它也会在这之后自动失效。
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct OpenCodeSegmentInFlightEntry {
    token: u64,
    expires_at_ms: u64,
}

/// `/24` 段维度的在途登记表（进程内，按 provider 隔离）。
///
/// 为什么是进程内而不是运行时 KV：这里是**计数**而不是标记，Redis 上没有「加一/减一
/// 并判上限」的原子原语（同一原因见 [`next_rotation_cursor`] 的说明），而计数差一两个
/// 只会让并发上限松一点，不会造成功能错误。多实例部署时每个实例各有一份——这恰好是
/// 想要的语义：并发上限约束的是「本实例同时往这个段里塞了多少个请求」。
#[derive(Debug, Default)]
pub(crate) struct OpenCodeSegmentInFlight {
    entries:
        std::sync::Mutex<std::collections::BTreeMap<String, Vec<OpenCodeSegmentInFlightEntry>>>,
    next_token: std::sync::atomic::AtomicU64,
}

/// 记账键：`provider_id` + 分隔符 + 段。分隔符用单元分隔符，ID 里不可能出现。
fn segment_in_flight_key(provider_id: &str, segment: &str) -> String {
    format!("{}\u{1f}{}", provider_id.trim(), segment.trim())
}

impl OpenCodeSegmentInFlight {
    pub(crate) fn new() -> Self {
        Self::default()
    }

    fn locked(
        &self,
    ) -> std::sync::MutexGuard<
        '_,
        std::collections::BTreeMap<String, Vec<OpenCodeSegmentInFlightEntry>>,
    > {
        // 记录表里只有整数，不存在「写坏一半」的状态；中毒也照常取用，
        // 因为这里一旦 panic 抛出去就等于让整个选点不可用。
        self.entries
            .lock()
            .unwrap_or_else(|poison| poison.into_inner())
    }

    /// 清掉已过期的记录（每次读/写都顺手做，不需要后台任务）。
    fn sweep(
        map: &mut std::collections::BTreeMap<String, Vec<OpenCodeSegmentInFlightEntry>>,
        now_ms: u64,
    ) {
        map.retain(|_, entries| {
            entries.retain(|entry| entry.expires_at_ms > now_ms);
            !entries.is_empty()
        });
    }

    /// 某个段当前的在途数（先清理过期记录）。
    pub(crate) fn in_flight(&self, provider_id: &str, segment: &str, now_ms: u64) -> usize {
        let key = segment_in_flight_key(provider_id, segment);
        let mut map = self.locked();
        Self::sweep(&mut map, now_ms);
        map.get(&key).map(Vec::len).unwrap_or(0)
    }

    /// 本 provider 下所有段的在途数快照（一次加锁）。
    fn in_flight_snapshot(
        &self,
        provider_id: &str,
        now_ms: u64,
    ) -> std::collections::BTreeMap<String, usize> {
        let prefix = format!("{}\u{1f}", provider_id.trim());
        let mut map = self.locked();
        Self::sweep(&mut map, now_ms);
        let mut snapshot = std::collections::BTreeMap::new();
        for (key, entries) in map.iter() {
            let Some(segment) = key.strip_prefix(prefix.as_str()) else {
                continue;
            };
            snapshot.insert(segment.to_string(), entries.len());
        }
        snapshot
    }

    /// 在途数已达上限的段集合（选点时要跳过它们）。
    pub(crate) fn saturated_segments(
        &self,
        provider_id: &str,
        max_in_flight: usize,
        now_ms: u64,
    ) -> std::collections::BTreeSet<String> {
        let max_in_flight = max_in_flight.max(1);
        self.in_flight_snapshot(provider_id, now_ms)
            .into_iter()
            .filter(|(_, count)| *count >= max_in_flight)
            .map(|(segment, _)| segment)
            .collect()
    }

    /// 占一个名额。已满返回 `None`；成功返回 RAII guard（Drop 即减计数）。
    pub(crate) fn try_acquire(
        self: &std::sync::Arc<Self>,
        provider_id: &str,
        segment: &str,
        max_in_flight: usize,
        now_ms: u64,
        ttl_ms: u64,
    ) -> Option<OpenCodeSegmentLease> {
        let max_in_flight = max_in_flight.max(1);
        let key = segment_in_flight_key(provider_id, segment);
        let expires_at_ms = now_ms.saturating_add(ttl_ms.max(1));
        let token = self
            .next_token
            .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        {
            let mut map = self.locked();
            Self::sweep(&mut map, now_ms);
            // 先判满再插入：`or_default` 会顺手建一个空桶，满员时那样会留下垃圾。
            let full = map
                .get(&key)
                .map(|entries| entries.len() >= max_in_flight)
                .unwrap_or(false);
            if full {
                return None;
            }
            map.entry(key.clone())
                .or_default()
                .push(OpenCodeSegmentInFlightEntry {
                    token,
                    expires_at_ms,
                });
        }
        Some(OpenCodeSegmentLease {
            registry: std::sync::Arc::clone(self),
            key,
            token,
            expires_at_ms,
            detached: false,
        })
    }

    fn release(&self, key: &str, token: u64) {
        let mut map = self.locked();
        let Some(entries) = map.get_mut(key) else {
            return;
        };
        entries.retain(|entry| entry.token != token);
        if entries.is_empty() {
            map.remove(key);
        }
    }
}

/// 段内在途名额的 RAII guard：**Drop 时减计数**。
///
/// 成功、失败、early-return、`?` 提前退出、async 任务被取消——所有路径都会走 Drop，
/// 这就是「不会漏减」的唯一保证。唯一的例外是显式 [`Self::detach`]：调用方拿不到
/// 「请求结束」这个时机时（规划期选点），把名额交给租约到期回收。
pub(crate) struct OpenCodeSegmentLease {
    registry: std::sync::Arc<OpenCodeSegmentInFlight>,
    key: String,
    token: u64,
    expires_at_ms: u64,
    /// 已交给 TTL 回收：Drop 不再减计数。
    detached: bool,
}

impl std::fmt::Debug for OpenCodeSegmentLease {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("OpenCodeSegmentLease")
            .field("key", &self.key)
            .field("token", &self.token)
            .field("expires_at_ms", &self.expires_at_ms)
            .field("detached", &self.detached)
            .finish()
    }
}

impl OpenCodeSegmentLease {
    /// 占用到期的毫秒时间戳（给日志用）。
    pub(crate) fn expires_at_ms(&self) -> u64 {
        self.expires_at_ms
    }

    /// 放弃精确释放：名额留在登记表里，直到 `expires_at_ms` 到期被自动清掉。
    ///
    /// 只给「拿不到请求结束时机」的调用点用（规划期选点）。能拿到作用域的地方请
    /// **直接持有 guard**，别用这个。
    pub(crate) fn detach(mut self) {
        self.detached = true;
    }
}

impl Drop for OpenCodeSegmentLease {
    fn drop(&mut self) {
        if self.detached {
            return;
        }
        self.registry.release(self.key.as_str(), self.token);
    }
}

/// 进程内唯一的段在途登记表（生产代码用这个；单测各自 new 一个，互不干扰）。
fn segment_in_flight_registry() -> &'static std::sync::Arc<OpenCodeSegmentInFlight> {
    static REGISTRY: std::sync::OnceLock<std::sync::Arc<OpenCodeSegmentInFlight>> =
        std::sync::OnceLock::new();
    REGISTRY.get_or_init(|| std::sync::Arc::new(OpenCodeSegmentInFlight::new()))
}

/// 段随机选点的结果。
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct OpenCodeSegmentPick {
    /// 选中的 IP。
    pub(crate) ip: String,
    /// 选中的 /24 段；算不出段（脏数据）时是 `ip:<ip>` 这种自成一段的键。
    pub(crate) segment: String,
    /// 选点时有几个段因为在途超限被跳过。
    pub(crate) skipped_saturated: usize,
    /// 所有段都在途超限 → 降级放行（不能无点可选）。
    pub(crate) saturated_fallback: bool,
}

/// **唯一**的段随机选点实现（纯函数，无 I/O、无全局状态）。
///
/// 伪代码：
///
/// ```text
/// 按 /24 分组            → 段集合（段内保留原始顺序）
/// 剔除 saturated 段      → 候选段集合
/// 段 = argmin(hash(seed, 段))     ← 段等概率（每个段权重都是 1，与段内 IP 数无关）
/// IP = argmin(hash(seed, IP))     ← 段内等概率
/// ```
///
/// 「选中的段超限就换下一个随机段」在这里就是「在未满的段集合上做一次等概率抽取」：
/// min-hash 取最小等价于均匀随机，剔除后再抽等价于不放回抽样，因此不存在顺序扫描的
/// 位置偏差。用哈希而非 `rand` 是为了让同一 `seed` **可复现**（单测能断言）。
pub(crate) fn pick_segment_random_ip(
    candidates: &[String],
    seed: &str,
    saturated: &std::collections::BTreeSet<String>,
) -> Option<OpenCodeSegmentPick> {
    if candidates.is_empty() {
        return None;
    }
    let mut groups: std::collections::BTreeMap<String, Vec<&String>> =
        std::collections::BTreeMap::new();
    for ip in candidates {
        let trimmed = ip.trim();
        if trimmed.is_empty() {
            continue;
        }
        // 算不出段的 IP 自成一「段」：解析失败不该让它从此选不到，也不该让它跟
        // 别人共享额度。
        let segment = opencode_ip_segment(trimmed).unwrap_or_else(|| format!("ip:{trimmed}"));
        groups.entry(segment).or_default().push(ip);
    }
    if groups.is_empty() {
        return None;
    }
    let seed_hash = fnv1a64(seed);
    let total_segments = groups.len();
    let mut eligible: Vec<(&String, &Vec<&String>)> = groups
        .iter()
        .filter(|(segment, _)| !saturated.contains(segment.as_str()))
        .collect();
    let skipped_saturated = total_segments - eligible.len();
    let saturated_fallback = eligible.is_empty();
    if saturated_fallback {
        // 全部段都在途超限：降级为「允许超限」，否则请求无点可选。
        eligible = groups.iter().collect();
    }
    // 段等概率：所有段的权重都是 1，与段内有几个 IP 无关（min-hash = 均匀随机）。
    let mut chosen_segment: Option<&String> = None;
    let mut best_segment_hash = u64::MAX;
    for (segment, _) in eligible.iter() {
        let hash = mix64(seed_hash ^ fnv1a64(segment.as_str()));
        if hash < best_segment_hash {
            best_segment_hash = hash;
            chosen_segment = Some(*segment);
        }
    }
    let chosen_segment = chosen_segment?;
    let ips = groups.get(chosen_segment)?;
    // 段内等概率：同样用 min-hash，盐前缀和段名区分开，避免同名混淆。
    let mut chosen_ip: Option<&String> = None;
    let mut best_ip_hash = u64::MAX;
    for ip in ips.iter() {
        let salt = format!("ip:{}", ip.trim());
        let hash = mix64(seed_hash ^ fnv1a64(salt.as_str()));
        if hash < best_ip_hash {
            best_ip_hash = hash;
            chosen_ip = Some(*ip);
        }
    }
    let ip = chosen_ip?.trim().to_string();
    Some(OpenCodeSegmentPick {
        ip,
        segment: chosen_segment.to_string(),
        skipped_saturated,
        saturated_fallback,
    })
}

/// 一次选点 = 选中的 IP + 可选的在途名额。
#[derive(Debug)]
pub(crate) struct OpenCodeAnchorChoice {
    pub(crate) pick: OpenCodeSegmentPick,
    /// `None` = 没占名额（降级放行 / 段全满 / 竞态重试用尽）。
    pub(crate) lease: Option<OpenCodeSegmentLease>,
}

/// 段随机 + 在途上限的选点：**主路径与 429 重试路径共用这一处**。
///
/// 与 [`pick_segment_random_ip`] 的分工：这里只负责「占名额」和「占不到就换下一个
/// 随机段」，选段选 IP 的算法一点不少地走上面那个纯函数。
pub(crate) fn pick_segment_aware_anchor(
    registry: &std::sync::Arc<OpenCodeSegmentInFlight>,
    provider_id: &str,
    candidates: &[String],
    seed: &str,
    policy: OpenCodeSegmentConcurrencyPolicy,
    now_ms: u64,
) -> Option<OpenCodeAnchorChoice> {
    let max_in_flight = policy.max_in_flight.max(1);
    let mut saturated = registry.saturated_segments(provider_id, max_in_flight, now_ms);
    let mut last: Option<OpenCodeSegmentPick> = None;
    for attempt in 0..OPENCODE_SEGMENT_PICK_ATTEMPTS {
        let attempt_seed = if attempt == 0 {
            seed.to_string()
        } else {
            format!("{seed}#{attempt}")
        };
        let pick = pick_segment_random_ip(candidates, attempt_seed.as_str(), &saturated)?;
        if pick.saturated_fallback {
            tracing::warn!(
                event_name = "opencode_segment_in_flight_saturated",
                log_type = "event",
                provider_id,
                exit_ip = pick.ip.as_str(),
                segment = pick.segment.as_str(),
                candidates = candidates.len(),
                max_in_flight,
                "every /24 segment is at the in-flight cap: allowing one over-limit pick instead of returning no ip"
            );
            return Some(OpenCodeAnchorChoice { pick, lease: None });
        }
        if let Some(lease) = registry.try_acquire(
            provider_id,
            pick.segment.as_str(),
            max_in_flight,
            now_ms,
            OPENCODE_SEGMENT_IN_FLIGHT_TTL_MS,
        ) {
            if pick.skipped_saturated > 0 {
                tracing::debug!(
                    provider_id,
                    exit_ip = pick.ip.as_str(),
                    segment = pick.segment.as_str(),
                    skipped_saturated_segments = pick.skipped_saturated,
                    max_in_flight,
                    "opencode segment pick skipped /24 segments at the in-flight cap"
                );
            }
            return Some(OpenCodeAnchorChoice {
                pick,
                lease: Some(lease),
            });
        }
        // 竞态：这段刚被别的请求占满。记下来换下一个**随机**段（不是顺序扫描）。
        saturated.insert(pick.segment.clone());
        last = Some(pick);
    }
    // 重试上限用尽（极端并发）：仍然返回最后一次选中的点——宁可多打一个 IP，
    // 也不要让请求无点可选。
    let pick = last?;
    tracing::warn!(
        event_name = "opencode_segment_in_flight_race",
        log_type = "event",
        provider_id,
        exit_ip = pick.ip.as_str(),
        segment = pick.segment.as_str(),
        max_in_flight,
        attempts = OPENCODE_SEGMENT_PICK_ATTEMPTS,
        "opencode segment pick gave up reserving an in-flight slot after retries"
    );
    Some(OpenCodeAnchorChoice { pick, lease: None })
}

/// 选点时要跳过的集合、要降级的段，以及池小保护的阈值。
///
/// 打包成结构体而不是继续加位置参数：`pick_anchor_ip` 本来就有五个参数，
/// 继续加会让调用点变成一串看不出含义的列表与布尔值。
#[derive(Clone, Debug)]
pub(crate) struct OpenCodeAnchorSkip {
    /// 人工停用的 IP：**任何时候**都跳过，包括池里只剩它们的时候。
    pub(crate) disabled: Vec<String>,
    /// 人工拉黑：与异常池同样是「先别用」，池小保护生效时不参与跳过。
    pub(crate) blocked: Vec<String>,
    /// 异常池：复验判定有问题的节点。
    pub(crate) abnormal: Vec<String>,
    /// 池小保护下限：可用池小于它时，`blocked` / `abnormal` 不生效。
    pub(crate) protect_pool_floor: usize,
    /// 本次请求**已经试过的 /24 段**：这些段里的 IP 只降级、不排除。
    ///
    /// 空 = 不做段优先（规划期、以及 503 这类非配额型失败都是空的，选点顺序
    /// 与改动前完全一致）。
    pub(crate) tried_segments: Vec<String>,
    /// 每个 /24 段允许的在途请求数（`opencode_scan.segment_max_in_flight`）。
    ///
    /// 放在这里而不是再加一个位置参数：`pick_anchor_ip` 的参数已经够多了，而这本来
    /// 就是「选点时要跳过哪些点」的一部分。
    pub(crate) segment_max_in_flight: usize,
}

impl Default for OpenCodeAnchorSkip {
    fn default() -> Self {
        Self {
            disabled: Vec::new(),
            blocked: Vec::new(),
            abnormal: Vec::new(),
            protect_pool_floor: 0,
            tried_segments: Vec::new(),
            // 默认档位而不是 0：0 会让「每个段都已满」，把选点直接打死。
            segment_max_in_flight: OPENCODE_DEFAULT_SEGMENT_MAX_IN_FLIGHT,
        }
    }
}

/// 「人工停用」集合：**任何时候**都硬跳过（池小保护也不豁免）。
fn anchor_hard_skip(skip: &OpenCodeAnchorSkip) -> std::collections::BTreeSet<&str> {
    skip.disabled
        .iter()
        .map(|ip| ip.trim())
        .filter(|ip| !ip.is_empty())
        .collect()
}

/// 「软标记」集合（拉黑 + 异常池）：池子低于保护线时不生效。
///
/// 池小保护：池子低于保护线时，异常池与拉黑只记录、不参与选择——三个节点的池子里
/// 「立刻不用」等于把流量压到一两个节点上，那比用一个慢节点更难察觉，也更难恢复。
/// 纯过滤：剔除「停用 / 软标记 / 已冷却或回避」的 IP。
///
/// `unavailable` 是调用方从运行时 KV 读出来的「冷却或短期回避中」集合。抽成纯函数
/// 是为了让「随机换点只会落在未冷却的节点上」这条约束可以被单测直接断言，
/// 而不是只能靠集成环境验证。
/// 当前**可用**（可以立刻发起请求）的出口 IP 列表。
///
/// 与 [`pick_anchor_ip`] 共用同一套过滤口径：随机换点不能自己再写一遍判据，
/// 否则两处对「可用」的理解迟早分叉。**这里不做任何兜底**：空列表就是空列表，
/// 由调用方决定是降级挑一个（规划期）还是快速失败（配额型重试）。
/// 每次请求从 provider 级 IP 池里挑一个 CDN 节点作为 DNS 锚点。
///
/// **不要叫它 exit IP**：前置代理下，opencode 看到的出口 IP 永远是代理的，
/// 与池里选哪个节点无关。池的作用是分散到代理的不同入口节点，绕开单点限速。
///
/// 持久化键 `upstream_metadata["opencode_exit_ip"]` 是历史命名，保持不变。
///
/// 冷却中的 IP 会被跳过；池里只剩一个 IP 时不做随机（没有选择可言）。
/// 传了 `session_key` 时按会话稳定选取，同一会话全程命中同一节点。
///
/// `skip.tried_segments` 非空时（429 换点）先按 /24 段分组：**段没试过的 IP 优先**，
/// 同段其它 IP 只降级不排除；池里只剩同段 IP 时照常从同段里选（不制造死锁）。
///
/// 没有会话标识时按 [`pick_segment_random_ip`] 选点：**先等概率选 /24 段，再在段内
/// 随机**（不是按 IP 等概率，否则 5 IP/段 的 CloudFront 段被点中的概率是 1 IP/段的
/// 5 倍），并对每个段施加 `skip.segment_max_in_flight` 的在途上限。返回值里的
/// [`OpenCodeSegmentLease`] 由调用方决定持有到请求结束（精确释放）还是 `detach()`
/// 交给 TTL 回收。
/// [`pick_anchor_ip`] 的结果：选中的 IP + 该段在途名额的可选 guard。
#[derive(Debug)]
pub(crate) struct OpenCodeAnchorPick {
    pub(crate) ip: String,
    /// 选中的 /24 段（日志与断言用）。
    pub(crate) segment: String,
    /// 段在途名额。`None` = 没占名额（降级兜底 / 全段超限 / 会话粘性命中）。
    pub(crate) segment_lease: Option<OpenCodeSegmentLease>,
    /// 所有段都在途超限，降级放行。
    pub(crate) segment_saturated_fallback: bool,
}

impl OpenCodeAnchorPick {
    /// 不占名额的结果（兜底、单点、粘性命中）。
    fn without_lease(ip: String) -> Self {
        Self {
            segment: opencode_ip_segment(ip.as_str()).unwrap_or_default(),
            ip,
            segment_lease: None,
            segment_saturated_fallback: false,
        }
    }

    /// 拿走 IP，并把在途名额交给 TTL 回收。
    ///
    /// 生产选点在规划期（`post_rank_reorder`）执行，那里拿不到「请求结束」的时机：
    /// 候选列表在计划物化之后就被丢掉了，硬持有 guard 会在几毫秒后释放，等于没限流。
    /// 因此生产调用点统一走这里；能拿到作用域的地方（单测、以后的请求级钩子）
    /// 直接持有 `segment_lease` 即可。详见 [`OpenCodeSegmentLease`] 与
    /// `OPENCODE_SEGMENT_IN_FLIGHT_TTL_MS`。
    pub(crate) fn into_ip_detaching_lease(mut self) -> String {
        if let Some(lease) = self.segment_lease.take() {
            lease.detach();
        }
        self.ip
    }
}

/// 按会话标识稳定地选出一个节点。
///
/// 用 FNV-1a 哈希而不是随机数：必须保证同一会话每次算出同一个下标，
/// 任何随机化都会让「粘性」变成「碰运气」。
pub(crate) fn pick_session_anchor(usable: &[String], session_key: Option<&str>) -> Option<String> {
    if usable.is_empty() {
        return None;
    }
    let Some(key) = session_key.map(str::trim).filter(|key| !key.is_empty()) else {
        return None;
    };
    let mut hash: u64 = 0xcbf2_9ce4_8422_2325;
    for byte in key.as_bytes() {
        hash ^= u64::from(*byte);
        hash = hash.wrapping_mul(0x0000_0100_0000_01b3);
    }
    let start = (hash % usable.len() as u64) as usize;
    usable.get(start).cloned()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn retry_disabled_ips_are_parsed_like_the_planner() {
        let scan = serde_json::json!({
            "exit_pool_disabled": [" 108.138.0.99 ", "", 7, "108.138.0.98"],
        });
        assert_eq!(
            opencode_retry_disabled_exit_ips(Some(&scan)),
            vec!["108.138.0.99".to_string(), "108.138.0.98".to_string()]
        );
        assert!(opencode_retry_disabled_exit_ips(None).is_empty());
    }

    #[test]
    fn retry_failure_reads_status_and_message_from_the_report_context() {
        let context = serde_json::json!({
            "candidate_index": 0,
            "error_flow": {
                "status_code": 400,
                "message": "Upstream request failed: [invalid_request_error] Empty input messages",
                "safe_to_expose": true,
            },
        });
        let failure = OpenCodeRetryFailure::from_report_context(Some(&context));
        assert_eq!(failure.status_code, Some(400));
        assert!(failure
            .message
            .as_deref()
            .is_some_and(|value| value.contains("Empty input messages")));

        // 缺上下文 / 缺 error_flow：按"未知"处理，仍然要标记（绝不因为信息缺失少做一次），
        // 但种类是**短期回避**：未知失败归不到配额上，不该按小时隔离一个可能健康的节点。
        for context in [
            None,
            Some(serde_json::json!({})),
            Some(serde_json::json!({"error_flow": {"message": "   "}})),
        ] {
            let failure = OpenCodeRetryFailure::from_report_context(context.as_ref());
            assert_eq!(failure.status_code, None);
            assert!(failure.message.is_none());
            assert_eq!(
                opencode_exit_ip_mark_for_failure(failure.status_code, failure.message.as_deref()),
                OpenCodeExitIpMark::Avoid,
                "未知失败必须仍然标记，且按短期回避处理"
            );
        }
    }

    /// 三分支判据：**能不能归因到这个出口节点**。
    #[test]
    fn exit_ip_mark_follows_attribution() {
        let mark = |status: u16, message: &str| {
            opencode_exit_ip_mark_for_failure(Some(status), Some(message))
        };

        // 调用方自己的错：换点照旧（赌一次别的路由），但不标记旧节点。
        assert_eq!(
            mark(
                400,
                "Upstream request failed: [invalid_request_error] Empty input messages"
            ),
            OpenCodeExitIpMark::None
        );
        assert_eq!(mark(404, "not found"), OpenCodeExitIpMark::None);

        // 配额型：冷却（固定短冷却，`retry-after` 只能把它变短）。
        assert_eq!(mark(429, "rate limited"), OpenCodeExitIpMark::Cooldown);
        assert_eq!(
            mark(403, "FreeTierError: free tier exhausted"),
            OpenCodeExitIpMark::Cooldown
        );
        // 403 但文案不是额度：按瞬时处理，不关一小时。
        assert_eq!(mark(403, "forbidden"), OpenCodeExitIpMark::Avoid);

        // 上游全局 / 瞬时：**短期回避而不是 60 分钟冷却**——本次修的就是这一类
        //（现场：422 Endpoint is unavailable 换 IP 也一样，却把 23 个健康 IP 关了 1 小时）。
        assert_eq!(
            mark(422, "Upstream request failed: Endpoint is unavailable."),
            OpenCodeExitIpMark::Avoid
        );
        assert_eq!(mark(500, "internal error"), OpenCodeExitIpMark::Avoid);
        assert_eq!(mark(504, "gateway timeout"), OpenCodeExitIpMark::Avoid);
        assert_eq!(
            opencode_exit_ip_mark_for_failure(None, None),
            OpenCodeExitIpMark::Avoid
        );
    }

    /// 配额型冷却用**固定短冷却**：上游 `retry-after` 只能把它变短，绝不能把它放大。
    ///
    /// 依据见 [`opencode_cooldown_ttl`]——2026-10-22 实测上游那个头指的是"账户日额度
    /// 什么时候刷新"，而出口 IP 实际 2–3 分钟就恢复；照抄它曾经把 124 个 IP 冻了 6 小时。
    #[test]
    fn cooldown_ttl_is_a_fixed_short_window_and_never_follows_a_long_retry_after() {
        // 1) 现场值 23164s（≈6.4h）→ 实际冷却必须是 120s，绝不是 23164。
        let long = opencode_cooldown_ttl(120, Some(23_164));
        assert_eq!(long.ttl_seconds, 120, "上游再长也不延长固定冷却");
        assert_eq!(long.configured_seconds, 120);
        assert!(long.retry_after_clipped, "截断上游这件事必须记在判定结果里");

        // 2) 上游明显更短（45s < 120s）→ 采纳上游。
        let short = opencode_cooldown_ttl(120, Some(45));
        assert_eq!(short.ttl_seconds, 45);
        assert!(!short.retry_after_clipped);

        // 3) 没有 retry-after → 固定值。
        let none = opencode_cooldown_ttl(120, None);
        assert_eq!(none.ttl_seconds, 120);
        assert!(!none.retry_after_clipped);

        // 荒谬的超长值同样不生效（旧的 `s.min(86400)` 放大分支已删除）。
        let absurd = opencode_cooldown_ttl(120, Some(30 * 24 * 3600));
        assert_eq!(absurd.ttl_seconds, 120);
        assert!(absurd.retry_after_clipped);
    }

    /// 配置覆盖生效，越界夹紧：10 → 30、9999 → 600。
    #[test]
    fn cooldown_ttl_clamps_configured_seconds() {
        assert_eq!(opencode_cooldown_ttl(300, None).ttl_seconds, 300);
        assert_eq!(opencode_cooldown_ttl(10, None).ttl_seconds, 30);
        assert_eq!(opencode_cooldown_ttl(9_999, None).ttl_seconds, 600);
        // 夹紧之后再与上游取小：配置 9999 → 600，上游 700 也不许更长。
        assert_eq!(opencode_cooldown_ttl(9_999, Some(700)).ttl_seconds, 600);
        // 上游比下限还短时不会被压到 0（冷却键 TTL 有同样的下限）。
        assert_eq!(opencode_cooldown_ttl(120, Some(0)).ttl_seconds, 30);
        assert_eq!(opencode_cooldown_ttl(120, Some(5)).ttl_seconds, 30);
    }

    #[test]
    fn retry_after_header_is_read_case_insensitively_and_only_as_integer_seconds() {
        let mut headers = std::collections::BTreeMap::new();
        headers.insert("Retry-After".to_string(), " 41417 ".to_string());
        headers.insert("content-type".to_string(), "application/json".to_string());
        assert_eq!(retry_after_seconds(&headers), Some(41_417));

        // HTTP-date 形式（本上游没出现过）当作"没有"，退回固定短冷却。
        let mut dated = std::collections::BTreeMap::new();
        dated.insert(
            "retry-after".to_string(),
            "Wed, 21 Oct 2026 07:28:00 GMT".to_string(),
        );
        assert_eq!(retry_after_seconds(&dated), None);

        assert_eq!(
            retry_after_seconds(&std::collections::BTreeMap::new()),
            None
        );
    }

    #[test]
    fn cooldown_index_keeps_only_live_entries() {
        let now = 1_000_000_u64;
        // 一条还有 60 秒、一条刚过期、一条时间戳类型不对。
        let raw = r#"{"108.138.0.5": 1060000, "108.138.0.6": 999999, "108.138.0.7": "soon"}"#;
        let parsed = parse_exit_ip_cooldown_index(raw, now);
        assert_eq!(parsed.len(), 1, "只有未过期的那条应保留: {parsed:?}");
        assert_eq!(parsed.get("108.138.0.5").copied(), Some(1_060_000));
        assert!(!parsed.contains_key("108.138.0.6"), "已过期必须丢掉");
        assert!(!parsed.contains_key("108.138.0.7"), "非数字必须丢掉");

        // 坏输入不能让面板接口报错，只当"没有冷却"。
        for bad in ["", "{", "[]", "null", "\"x\""] {
            assert!(
                parse_exit_ip_cooldown_index(bad, now).is_empty(),
                "坏输入应得到空清单: {bad:?}"
            );
        }
    }

    #[test]
    fn session_ref_is_stable_short_and_distinct() {
        // 日志关联用：同一个会话必须永远算出同一个指纹，不同会话不能撞在一起，
        // 且不能长到把会话键本身暴露出去。
        let a1 = session_ref("ses_abc123");
        let a2 = session_ref("  ses_abc123  ");
        let b = session_ref("ses_abc124");
        assert_eq!(a1, a2, "同一会话（含首尾空白）必须得到同一指纹");
        assert_ne!(a1, b, "不同会话必须有不同指纹");
        assert_eq!(a1.len(), 12, "指纹长度固定 12 个十六进制字符");
        assert!(a1.chars().all(|c| c.is_ascii_hexdigit()));
    }

    #[test]
    fn empty_group_yields_no_exit_ip() {
        assert_eq!(
            pick_segment_random_ip(&[], "seed", &std::collections::BTreeSet::new()),
            None
        );
    }

    fn sticky_pool() -> Vec<String> {
        (0..8).map(|i| format!("10.0.0.{}", i + 1)).collect()
    }

    #[test]
    fn session_anchor_is_stable_for_the_same_session() {
        let pool = sticky_pool();
        let first = pick_session_anchor(&pool, Some("device-a")).expect("pool is not empty");
        for _ in 0..10 {
            assert_eq!(
                pick_session_anchor(&pool, Some("device-a")),
                Some(first.clone()),
                "the same session must never move to a different node"
            );
        }
    }

    #[test]
    fn session_anchor_spreads_across_distinct_sessions() {
        let pool = sticky_pool();
        let picks: std::collections::BTreeSet<String> = (0..64)
            .map(|i| {
                pick_session_anchor(&pool, Some(&format!("device-{i}"))).expect("pool is not empty")
            })
            .collect();
        // Not a uniformity assertion - hashing will not be perfect - but a
        // broken hash would collapse everything onto one node, which is the
        // failure this feature exists to avoid.
        assert!(
            picks.len() >= 4,
            "64 sessions spread over only {} of 8 nodes: {}",
            picks.len(),
            picks.len()
        );
    }

    #[test]
    fn session_anchor_falls_back_when_there_is_no_session() {
        let pool = sticky_pool();
        assert_eq!(pick_session_anchor(&pool, None), None);
        assert_eq!(pick_session_anchor(&pool, Some("   ")), None);
        assert_eq!(pick_session_anchor(&[], Some("device-a")), None);
    }

    const OPENCODE: &str = "opencode";

    #[test]
    fn rate_limited_opencode_exit_ip_is_marked_in_cooldown() {
        assert!(cooldown_triggered(OPENCODE, 429, None));
        assert!(cooldown_triggered(OPENCODE, 429, Some("too many requests")));
    }

    #[test]
    fn rate_limited_other_provider_is_never_marked_in_cooldown() {
        assert!(!cooldown_triggered("openai", 429, Some("FreeTierError")));
        assert!(!cooldown_triggered("anthropic", 429, None));
        assert!(!cooldown_triggered("", 429, None));
        // 大小写与空白都要归一化后再比较。
        assert!(cooldown_triggered("  OpenCode  ", 429, None));
    }

    #[test]
    fn forbidden_without_free_tier_fingerprint_is_not_marked_in_cooldown() {
        assert!(!cooldown_triggered(OPENCODE, 403, None));
        assert!(!cooldown_triggered(OPENCODE, 403, Some("forbidden")));
        assert!(!cooldown_triggered(
            OPENCODE,
            403,
            Some("{\"error\":{\"message\":\"invalid api key\"}}")
        ));
    }

    #[test]
    fn forbidden_with_free_tier_fingerprint_is_marked_in_cooldown() {
        for message in [
            "FreeTierError",
            "free tier quota exceeded",
            "You have hit your QUOTA limit",
            "rate limit reached for this session",
        ] {
            assert!(
                cooldown_triggered(OPENCODE, 403, Some(message)),
                "expected cooldown for {message}"
            );
        }
    }

    #[test]
    fn other_status_codes_are_never_marked_in_cooldown() {
        for status_code in [200u16, 400, 401, 404, 500, 502, 503, 504] {
            assert!(!cooldown_triggered(
                OPENCODE,
                status_code,
                Some("FreeTierError quota rate limit free tier")
            ));
        }
    }

    #[test]
    fn cooldown_triggered_ignores_private_pin_values() {
        // 出口 IP 缺失/非法时调用方直接跳过，本函数只做 provider + 状态码判定。
        assert!(cooldown_triggered(OPENCODE, 429, None));
        assert!(parse_opencode_exit_ip("127.0.0.1").is_none());
        assert_eq!(
            parse_opencode_exit_ip("1.2.3.4"),
            Some("1.2.3.4".parse::<std::net::IpAddr>().unwrap())
        );
    }

    #[test]
    fn opencode_dns_pin_extra_carries_the_exit_ip() {
        // 计划里的 profile.extra 是 serde_json::Value，消费侧按对象防御式读取；
        // 序列化后的字符串形态则由传输层自己的解析器消费。
        let extra = serde_json::json!({
            "opencode_dns_pin": { "host": "cdn.example.test", "ip": "1.2.3.4", "port": 443 }
        });
        let ip = extra
            .get("opencode_dns_pin")
            .and_then(|pin| pin.get("ip"))
            .and_then(serde_json::Value::as_str)
            .and_then(parse_opencode_exit_ip);
        assert_eq!(ip, Some("1.2.3.4".parse::<std::net::IpAddr>().unwrap()));
        assert!(aether_provider_transport::opencode_dns_pin_from_extra(Some(
            extra.to_string().as_str()
        ))
        .is_some());
    }

    /// 归因表的可执行版本：这张表决定「哪些失败算这个出口 IP 的」，
    /// 一旦和后端别处写的那套判据分叉，池子就会按错误的证据淘汰节点。
    #[test]
    fn runtime_failure_attribution_follows_the_agreed_table() {
        use OpenCodeFailureSource as Src;

        // 传输层根本没走通：连接超时 / TLS 失败 / 连接重置 → 算。
        assert_eq!(classify_opencode_failure(None, false, true), Src::Transport);
        assert_eq!(
            classify_opencode_failure(Some(502), false, true),
            Src::Transport
        );

        // 走通了但没在时限内答（我们自判的 502/504）→ 算。
        assert_eq!(
            classify_opencode_failure(Some(502), false, false),
            Src::GatewayTimeout
        );
        assert_eq!(
            classify_opencode_failure(Some(504), false, false),
            Src::GatewayTimeout
        );

        // 上游真的答了状态行：4xx / 5xx / 审核 / 鉴权都不是出口 IP 的问题 → 不算。
        assert_eq!(
            classify_opencode_failure(Some(500), true, false),
            Src::UpstreamStatus
        );
        assert_eq!(
            classify_opencode_failure(Some(400), true, false),
            Src::UpstreamStatus
        );
        assert_eq!(
            classify_opencode_failure(Some(404), true, false),
            Src::UpstreamStatus
        );

        // 额度类：走冷却，不进失败计数。
        assert_eq!(
            classify_opencode_failure(Some(429), true, false),
            Src::Quota
        );
        assert_eq!(
            classify_opencode_failure(Some(403), false, false),
            Src::Quota
        );

        // 连状态码都没有、又没有传输层错误：归因不了就不记（宁可不记，也别记错）。
        assert_eq!(classify_opencode_failure(None, false, false), Src::Ignored);
    }

    #[test]
    fn only_transport_and_gateway_timeout_count_against_the_ip() {
        use OpenCodeFailureSource as Src;

        for source in [Src::Transport, Src::GatewayTimeout] {
            assert!(
                opencode_failure_counts_for_ip(source),
                "{source:?} 应当计入"
            );
        }
        for source in [Src::UpstreamStatus, Src::Quota, Src::Ignored] {
            assert!(
                !opencode_failure_counts_for_ip(source),
                "{source:?} 不应当计入"
            );
        }
    }

    /// 只有「归因到节点本身」的失败才允许触发出池。
    ///
    /// 配额型（429 / 403 免费额度）按 /24 段共享：一次额度枯竭会让同段几十个 IP
    /// 一起 429。如果它们能触发出池，一次上游限流就会抹掉半个池子，而那些 IP
    /// 本身是好的——冷却到期就该回来。
    #[test]
    fn only_node_attributable_failures_may_evict_an_ip() {
        use OpenCodeFailureSource as Src;

        for source in [Src::Transport, Src::GatewayTimeout] {
            assert!(
                opencode_failure_counts_for_ip(source),
                "{source:?} 归因到节点，连续失败可以出池"
            );
        }
        for source in [Src::Quota, Src::UpstreamStatus, Src::Ignored] {
            assert!(
                !opencode_failure_counts_for_ip(source),
                "{source:?} 不该触发出池：配额是段共享的，上游状态行换 IP 也没用"
            );
        }
    }

    #[test]
    fn eviction_is_throttled_by_an_hourly_budget() {
        // 节流闸是最后一道保险：上游抖动时失败成片，没有上限的话一次抖动就能把
        // 2000 个 IP 的池子打成个位数。
        assert!(allow_eviction_now(0));
        assert!(allow_eviction_now(OPENCODE_EVICT_MAX_PER_HOUR - 1));
        assert!(!allow_eviction_now(OPENCODE_EVICT_MAX_PER_HOUR));
        assert!(!allow_eviction_now(OPENCODE_EVICT_MAX_PER_HOUR + 100));
    }

    #[test]
    fn suspect_needs_three_runtime_failures_in_the_window() {
        // 两次不够：一次抖动、两次偶发都不该把节点摘掉——那会让偶发网络抖动
        // 变成真实的容量损失。
        assert!(!opencode_failure_reached_suspect_threshold(0));
        assert!(!opencode_failure_reached_suspect_threshold(1));
        assert!(!opencode_failure_reached_suspect_threshold(2));
        assert!(opencode_failure_reached_suspect_threshold(3));
        assert!(opencode_failure_reached_suspect_threshold(9));
    }

    #[test]
    fn runtime_failure_keys_are_scoped_per_provider_and_ip() {
        // 键必须同时带 provider 与 IP：只带 IP 会让两个供应商的同名 CDN 段互相
        // 污染证据，而它们完全可能一个健康、一个不可用。
        assert_ne!(
            runtime_fail_key("provider-a", "1.2.3.4"),
            runtime_fail_key("provider-b", "1.2.3.4")
        );
        assert_ne!(
            runtime_fail_key("provider-a", "1.2.3.4"),
            runtime_fail_key("provider-a", "1.2.3.5")
        );
    }

    // ---- 429「优先换段」：段提取 / 段优先 / 预算 / 503 隔离 ----

    /// 段 = IP 前三段；同段兄弟 IP 必须算出同一个段（429 额度按段共享）。
    #[test]
    fn segment_is_the_first_three_octets() {
        assert_eq!(opencode_ip_segment("1.2.3.4").as_deref(), Some("1.2.3"));
        assert_eq!(
            opencode_ip_segment(" 18.154.128.1 ").as_deref(),
            Some("18.154.128")
        );
        assert_eq!(
            opencode_ip_segment("65.8.192.6").as_deref(),
            Some("65.8.192")
        );
        // 现场被一起限流的兄弟 IP 必须是同一个段。
        assert_eq!(
            opencode_ip_segment("18.154.128.1"),
            opencode_ip_segment("18.154.128.5")
        );
        assert_eq!(
            opencode_ip_segment("23.228.247.1"),
            opencode_ip_segment("23.228.247.4")
        );
        // 末段不同 = 不同段（99.84.106.5 与 99.84.107.5 不是同段）。
        assert_ne!(
            opencode_ip_segment("99.84.106.5"),
            opencode_ip_segment("99.84.107.5")
        );
        // 算不出段一律 None：脏数据既不能挡重试，也不能把节点排到二等。
        for bad in [
            "",
            "   ",
            "1.2.3",
            "1.2.3.4.5",
            "not-an-ip",
            "::1",
            "0x1.2.3.4",
        ] {
            assert_eq!(
                opencode_ip_segment(bad),
                None,
                "非法输入不得算出段: {bad:?}"
            );
        }
    }

    /// 试过某段之后，同段 IP 只降级、不排除；其它段优先被选到。
    #[test]
    fn tried_segment_siblings_are_deprioritised_not_excluded() {
        let usable = vec![
            "18.154.128.1".to_string(),
            "18.154.128.2".to_string(),
            "23.228.247.1".to_string(),
            "23.228.247.4".to_string(),
            "65.8.192.5".to_string(),
        ];
        let split = split_usable_by_segment(&usable, &["18.154.128".to_string()]);
        assert_eq!(split.untried.len(), 3, "未试段 23.228.247 / 65.8.192");
        assert_eq!(split.tried.len(), 2, "同段兄弟 IP 仍留在池里");
        assert_eq!(split.skipped_same_segment(), 2);
        assert!(!split.degraded_to_tried_segment(), "还有未试段可用");
        let space = split.search_space();
        assert_eq!(space.len(), 3);
        for ip in space {
            assert_ne!(
                opencode_ip_segment(ip).as_deref(),
                Some("18.154.128"),
                "选点空间里不得出现已试段的 IP: {ip}"
            );
        }
        // 会话粘性与段随机都只在未试段里挑，绝不会落回旧段。
        for session in ["device-a", "device-b", "device-c"] {
            let picked = pick_session_anchor(space, Some(session)).expect("space is not empty");
            assert_ne!(opencode_ip_segment(&picked).as_deref(), Some("18.154.128"));
        }
        for attempt in 0..12u32 {
            let seed = format!("req-{attempt}:1");
            let picked =
                pick_segment_random_ip(space, seed.as_str(), &std::collections::BTreeSet::new())
                    .expect("space is not empty");
            assert_ne!(Some(picked.segment.as_str()), Some("18.154.128"));
        }
    }

    /// 池里只剩同段 IP：降级选同段，而不是无点可选（不能制造死锁）。
    #[test]
    fn same_segment_pool_falls_back_instead_of_deadlocking() {
        let usable = vec![
            "18.154.128.1".to_string(),
            "18.154.128.2".to_string(),
            "18.154.128.5".to_string(),
        ];
        let split = split_usable_by_segment(&usable, &["18.154.128".to_string()]);
        assert!(split.untried.is_empty());
        assert!(split.degraded_to_tried_segment());
        assert_eq!(split.skipped_same_segment(), 0, "没有可跳过的点");
        assert_eq!(split.search_space().len(), 3, "同段点必须仍然可选");
        assert!(pick_segment_random_ip(
            split.search_space(),
            "req-1:1",
            &std::collections::BTreeSet::new()
        )
        .is_some());
        assert!(pick_session_anchor(split.search_space(), Some("device-a")).is_some());
    }

    /// 已试段达到上限 → 判定耗尽（上层据此立刻放弃重试，不再选点）。
    #[test]
    fn segment_budget_is_exhausted_by_the_segment_count() {
        let policy = OpenCodeSegmentBudgetPolicy {
            enabled: true,
            max_segments: 3,
            max_elapsed_ms: OPENCODE_DEFAULT_SEGMENT_BUDGET_MS,
        };
        let mut state = OpenCodeSegmentBudgetState::default();
        let now = 1_000_000;
        assert_eq!(
            opencode_segment_budget_step(
                OpenCodeExitIpMark::Cooldown,
                &mut state,
                "18.154.128.1",
                policy,
                now
            ),
            OpenCodeSegmentBudgetOutcome::Continue
        );
        assert_eq!(
            opencode_segment_budget_step(
                OpenCodeExitIpMark::Cooldown,
                &mut state,
                "23.228.247.1",
                policy,
                now
            ),
            OpenCodeSegmentBudgetOutcome::Continue
        );
        assert_eq!(
            opencode_segment_budget_step(
                OpenCodeExitIpMark::Cooldown,
                &mut state,
                "65.8.192.5",
                policy,
                now
            ),
            OpenCodeSegmentBudgetOutcome::ExhaustedSegments,
            "第 3 个段 = 上限，必须立刻停"
        );
        assert!(OpenCodeSegmentBudgetOutcome::ExhaustedSegments.is_exhausted());
        assert_eq!(state.segments.len(), 3);

        // 同段兄弟 IP 不重复占名额：一个段试多少次都只算一个。
        let mut siblings = OpenCodeSegmentBudgetState::default();
        let two = OpenCodeSegmentBudgetPolicy {
            max_segments: 2,
            ..policy
        };
        for ip in ["18.154.128.1", "18.154.128.2", "18.154.128.5"] {
            assert_eq!(
                opencode_segment_budget_step(
                    OpenCodeExitIpMark::Cooldown,
                    &mut siblings,
                    ip,
                    two,
                    now
                ),
                OpenCodeSegmentBudgetOutcome::Continue,
                "同段兄弟 IP 不能把预算烧完: {ip}"
            );
        }
        assert_eq!(siblings.segments, vec!["18.154.128".to_string()]);
    }

    /// 总耗时超限 → 同样立刻判定耗尽。
    ///
    /// 段预算默认是关的（429 走延迟重试），所以这里显式打开：这条测的是「能力还在」。
    #[test]
    fn segment_budget_is_exhausted_by_the_elapsed_time() {
        let policy = OpenCodeSegmentBudgetPolicy {
            enabled: true,
            ..OpenCodeSegmentBudgetPolicy::default()
        };
        let mut state = OpenCodeSegmentBudgetState::default();
        let start = 1_000_000;
        assert_eq!(
            opencode_segment_budget_step(
                OpenCodeExitIpMark::Cooldown,
                &mut state,
                "18.154.128.1",
                policy,
                start
            ),
            OpenCodeSegmentBudgetOutcome::Continue
        );
        assert_eq!(state.started_at_ms, start, "预算起点 = 首次配额型失败");
        assert_eq!(
            opencode_segment_budget_step(
                OpenCodeExitIpMark::Cooldown,
                &mut state,
                "23.228.247.1",
                policy,
                start + OPENCODE_DEFAULT_SEGMENT_BUDGET_MS - 1
            ),
            OpenCodeSegmentBudgetOutcome::Continue,
            "差 1 毫秒仍在预算内"
        );
        assert_eq!(
            opencode_segment_budget_step(
                OpenCodeExitIpMark::Cooldown,
                &mut state,
                "65.8.192.5",
                policy,
                start + OPENCODE_DEFAULT_SEGMENT_BUDGET_MS
            ),
            OpenCodeSegmentBudgetOutcome::ExhaustedElapsed,
            "刚好到 15 秒就停"
        );
        assert!(OpenCodeSegmentBudgetOutcome::ExhaustedElapsed.is_exhausted());
        assert_eq!(
            OpenCodeSegmentBudgetOutcome::ExhaustedElapsed.reason(),
            "elapsed"
        );
    }

    /// **503 路径完全不受影响**：不记段、不判预算、选点顺序一字不差。
    #[test]
    fn upstream_wide_failures_are_never_touched_by_the_segment_budget() {
        // 503 / 502 / 500 / 504 全部走 Avoid（短期回避），不是配额型。
        for status in [503_u16, 502, 500, 504] {
            let mark = opencode_exit_ip_mark_for_failure(Some(status), Some("unavailable"));
            assert_eq!(mark, OpenCodeExitIpMark::Avoid, "{status} 必须按瞬时处理");
            // 最严的预算：1 段、1 毫秒。即使是它也不该被 503 触发。
            let mut state = OpenCodeSegmentBudgetState::default();
            let policy = OpenCodeSegmentBudgetPolicy {
                enabled: true,
                max_segments: 1,
                max_elapsed_ms: 1,
            };
            assert_eq!(
                opencode_segment_budget_step(mark, &mut state, "18.154.128.1", policy, 1_000_000),
                OpenCodeSegmentBudgetOutcome::NotApplicable,
                "{status} 不得进入段预算"
            );
            assert!(state.segments.is_empty(), "{status} 不得记段");
            assert_eq!(state.started_at_ms, 0, "{status} 不得起算预算");
        }
        // 选点顺序：tried 为空时「段优先」退化成原样，绑定/会话/段随机三条路径逐字相同。
        let usable = vec![
            "18.154.128.1".to_string(),
            "18.154.128.2".to_string(),
            "23.228.247.1".to_string(),
            "65.8.192.5".to_string(),
        ];
        let split = split_usable_by_segment(&usable, &[]);
        assert_eq!(split.search_space(), usable.as_slice());
        assert!(split.tried.is_empty());
        assert_eq!(split.skipped_same_segment(), 0);
        assert!(!split.degraded_to_tried_segment());
        for session in ["device-a", "device-b", "device-c"] {
            assert_eq!(
                pick_session_anchor(split.search_space(), Some(session)),
                pick_session_anchor(&usable, Some(session)),
                "503 换点的会话选点必须与改动前一致"
            );
        }
        for attempt in 0..usable.len() as u32 {
            let seed = format!("req-{attempt}:1");
            assert_eq!(
                pick_segment_random_ip(
                    split.search_space(),
                    seed.as_str(),
                    &std::collections::BTreeSet::new()
                ),
                pick_segment_random_ip(&usable, seed.as_str(), &std::collections::BTreeSet::new()),
                "503 换点的段随机选点必须与改动前一致"
            );
        }
    }

    /// 关掉段预算 = 完全退回改动前：不记账、不判耗尽。
    #[test]
    fn disabled_segment_budget_leaves_the_retry_path_untouched() {
        let mut state = OpenCodeSegmentBudgetState::default();
        let policy = OpenCodeSegmentBudgetPolicy {
            enabled: false,
            max_segments: 1,
            max_elapsed_ms: 1,
        };
        assert_eq!(
            opencode_segment_budget_step(
                OpenCodeExitIpMark::Cooldown,
                &mut state,
                "18.154.128.1",
                policy,
                1_000_000
            ),
            OpenCodeSegmentBudgetOutcome::NotApplicable
        );
        assert!(state.segments.is_empty());
        assert_eq!(state.started_at_ms, 0);
        // 关闭状态下允许保留半成品配置（与 OpenCodeDelayedRetryPolicy 一致）。
        assert!(OpenCodeSegmentBudgetPolicy {
            enabled: false,
            max_segments: 0,
            max_elapsed_ms: 0,
        }
        .validate()
        .is_ok());
    }

    /// 默认值：**总开关关闭**（配额型失败改走「延迟重试 + 随机换点」），档位仍是
    /// 8 段 / 15 秒——显式打开即可恢复老行为，配置只能收紧。
    #[test]
    fn segment_budget_defaults_to_disabled_and_honours_overrides() {
        let default = OpenCodeSegmentBudgetPolicy::from_provider_config(&None);
        assert_eq!(default, OpenCodeSegmentBudgetPolicy::default());
        assert!(
            !default.enabled,
            "默认关闭：429 走延迟重试，不再靠按段换点多打 IP"
        );
        assert_eq!(default.max_segments, 8);
        assert_eq!(default.max_elapsed_ms, 15_000);
        assert!(default.validate().is_ok());

        // 显式打开 → 恢复原来的 8 段 / 15 秒行为（能力保留）。
        let switched_on = OpenCodeSegmentBudgetPolicy::from_provider_config(&Some(
            serde_json::json!({"opencode_scan": {"segment_budget_enabled": true}}),
        ));
        assert!(switched_on.enabled);
        assert_eq!(switched_on.max_segments, 8);
        assert_eq!(switched_on.max_elapsed_ms, 15_000);

        let tuned = OpenCodeSegmentBudgetPolicy::from_provider_config(&Some(serde_json::json!({
            "opencode_scan": {
                "segment_budget_enabled": false,
                "segment_budget_segments": 3,
                "segment_budget_ms": 5_000,
            }
        })));
        assert!(!tuned.enabled);
        assert_eq!(tuned.max_segments, 3);
        assert_eq!(tuned.max_elapsed_ms, 5_000);

        // 手改的超大值就地夹紧，不会变成无限重试。
        let huge = OpenCodeSegmentBudgetPolicy::from_provider_config(&Some(serde_json::json!({
            "opencode_scan": {
                "segment_budget_segments": 9_999,
                "segment_budget_ms": u64::MAX,
            }
        })));
        assert_eq!(huge.max_segments as u64, MAX_OPENCODE_SEGMENT_BUDGET);
        assert_eq!(huge.max_elapsed_ms, MAX_OPENCODE_SEGMENT_BUDGET_MS);
        assert!(huge.validate().is_ok());

        // 0 段 / 0 毫秒会让「优先换段」失去意义 → 拒绝。
        assert!(OpenCodeSegmentBudgetPolicy {
            enabled: true,
            max_segments: 0,
            max_elapsed_ms: 15_000,
        }
        .validate()
        .is_err());
        assert!(OpenCodeSegmentBudgetPolicy {
            enabled: true,
            max_segments: 8,
            max_elapsed_ms: 0,
        }
        .validate()
        .is_err());
    }

    fn segment_test_plan(extra: serde_json::Value) -> aether_contracts::ExecutionPlan {
        aether_contracts::ExecutionPlan {
            request_id: "req-segment-budget".to_string(),
            candidate_id: Some("candidate-a".to_string()),
            provider_name: None,
            provider_id: "provider-1".to_string(),
            endpoint_id: "endpoint-1".to_string(),
            key_id: "key-1".to_string(),
            method: "POST".to_string(),
            url: "https://cdn.example.test/v1/chat".to_string(),
            headers: Default::default(),
            content_type: None,
            content_encoding: None,
            body: aether_contracts::RequestBody {
                json_body: None,
                body_bytes_b64: None,
                body_ref: None,
            },
            stream: false,
            client_api_format: "openai:chat".to_string(),
            provider_api_format: "openai:chat".to_string(),
            model_name: None,
            proxy: None,
            transport_profile: Some(aether_contracts::ResolvedTransportProfile {
                profile_id: "opencode:cdn.example.test".to_string(),
                backend: aether_contracts::TRANSPORT_BACKEND_REQWEST_RUSTLS.to_string(),
                http_mode: aether_contracts::TRANSPORT_HTTP_MODE_AUTO.to_string(),
                pool_scope: aether_contracts::TRANSPORT_POOL_SCOPE_KEY.to_string(),
                header_fingerprint: None,
                extra: Some(extra),
            }),
            timeouts: None,
        }
    }

    /// 段预算状态跟着 plan 走：pin 不被破坏，读不到时退回空状态而不是 panic。
    #[test]
    fn segment_budget_state_round_trips_through_the_plan_extra() {
        let mut plan = segment_test_plan(serde_json::json!({
            "opencode_dns_pin": {"host": "cdn.example.test", "ip": "18.154.128.1", "port": 443}
        }));
        assert_eq!(
            read_segment_budget_state(&plan),
            OpenCodeSegmentBudgetState::default(),
            "新 plan 一个段都没试过"
        );
        let state = OpenCodeSegmentBudgetState {
            segments: vec!["18.154.128".to_string(), "23.228.247".to_string()],
            started_at_ms: 1_234_567,
        };
        assert!(write_segment_budget_state(&mut plan, &state));
        assert_eq!(read_segment_budget_state(&plan), state);
        // 段状态与 pin 同居一个 extra 对象，互不覆盖。
        assert_eq!(
            plan_opencode_exit_ip(&plan),
            Some("18.154.128.1".parse::<std::net::IpAddr>().unwrap())
        );
        // 坏数据只当"没有段"：绝不能让脏 JSON 把重试打挂。
        let mut broken = segment_test_plan(serde_json::json!({
            "opencode_segment_budget": {"segments": "not-an-array", "started_at_ms": "soon"}
        }));
        assert_eq!(
            read_segment_budget_state(&broken),
            OpenCodeSegmentBudgetState::default()
        );
        assert!(write_segment_budget_state(&mut broken, &state));
        // 没有 profile 时写不进去，读回默认值——静默退化，不影响重试。
        let mut bare = segment_test_plan(serde_json::json!({}));
        bare.transport_profile = None;
        assert!(!write_segment_budget_state(&mut bare, &state));
        assert_eq!(
            read_segment_budget_state(&bare),
            OpenCodeSegmentBudgetState::default()
        );
    }

    // ---- 429 / 配额型 403 的延迟重试（quota_retry_*） ----

    /// 阶梯：10s → 20s → 40s，封顶后不再翻倍。
    #[test]
    fn quota_retry_ladder_is_ten_twenty_forty_then_capped() {
        let policy = OpenCodeQuotaRetryPolicy::default();
        let secs = |index| policy.delay_for_retry(index).unwrap().as_secs();
        assert_eq!(secs(0), 10);
        assert_eq!(secs(1), 20);
        assert_eq!(secs(2), 40);
        // 封顶（max_ms = 40s）：不会继续翻倍，也不会溢出。
        assert_eq!(secs(3), 40);
        assert_eq!(secs(u32::MAX), 40);
        assert_eq!(
            policy.max_attempts,
            DEFAULT_OPENCODE_QUOTA_RETRY_MAX_ATTEMPTS
        );
    }

    /// 默认值、配置覆盖、越界夹紧与校验。
    #[test]
    fn quota_retry_policy_defaults_clamps_and_validates() {
        let default = OpenCodeQuotaRetryPolicy::from_provider_config(&None);
        assert_eq!(default, OpenCodeQuotaRetryPolicy::default());
        assert!(default.enabled);
        assert_eq!(default.base_ms, 10_000);
        assert_eq!(default.multiplier, 2);
        assert_eq!(default.max_ms, 40_000);
        assert_eq!(default.max_attempts, 3);
        assert!(default.validate().is_ok());

        let tuned = OpenCodeQuotaRetryPolicy::from_provider_config(&Some(serde_json::json!({
            "opencode_scan": {
                "quota_retry_enabled": false,
                "quota_retry_base_ms": 3_000,
                "quota_retry_multiplier": 3,
                "quota_retry_max_ms": 20_000,
                "quota_retry_max_attempts": 5,
            }
        })));
        assert!(!tuned.enabled);
        assert_eq!(tuned.base_ms, 3_000);
        assert_eq!(tuned.multiplier, 3);
        assert_eq!(tuned.max_ms, 20_000);
        assert_eq!(tuned.max_attempts, 5);

        // 手改的超大值就地夹紧：不可能变成一次数小时的等待或无限重试。
        let huge = OpenCodeQuotaRetryPolicy::from_provider_config(&Some(serde_json::json!({
            "opencode_scan": {
                "quota_retry_base_ms": u64::MAX,
                "quota_retry_multiplier": 99_999,
                "quota_retry_max_ms": u64::MAX,
                "quota_retry_max_attempts": 999,
            }
        })));
        assert_eq!(huge.max_ms, MAX_OPENCODE_QUOTA_RETRY_DELAY_MS);
        assert_eq!(huge.base_ms, MAX_OPENCODE_QUOTA_RETRY_DELAY_MS);
        assert_eq!(huge.multiplier, MAX_OPENCODE_QUOTA_RETRY_MULTIPLIER);
        assert_eq!(huge.max_attempts, MAX_OPENCODE_QUOTA_RETRY_ATTEMPTS);
        assert!(huge.validate().is_ok());

        for invalid in [
            OpenCodeQuotaRetryPolicy {
                base_ms: 0,
                ..OpenCodeQuotaRetryPolicy::default()
            },
            OpenCodeQuotaRetryPolicy {
                max_ms: 0,
                ..OpenCodeQuotaRetryPolicy::default()
            },
            OpenCodeQuotaRetryPolicy {
                base_ms: 90_000,
                max_ms: 10_000,
                ..OpenCodeQuotaRetryPolicy::default()
            },
            OpenCodeQuotaRetryPolicy {
                multiplier: 0,
                ..OpenCodeQuotaRetryPolicy::default()
            },
            OpenCodeQuotaRetryPolicy {
                max_attempts: 0,
                ..OpenCodeQuotaRetryPolicy::default()
            },
            OpenCodeQuotaRetryPolicy {
                max_attempts: MAX_OPENCODE_QUOTA_RETRY_ATTEMPTS + 1,
                ..OpenCodeQuotaRetryPolicy::default()
            },
        ] {
            assert!(
                invalid.validate().is_err(),
                "{invalid:?} should be rejected"
            );
        }
        // 关掉之后不校验数值：允许关闭状态下留一份半成品配置。
        assert!(OpenCodeQuotaRetryPolicy {
            enabled: false,
            base_ms: 0,
            multiplier: 0,
            max_ms: 0,
            max_attempts: 0,
        }
        .validate()
        .is_ok());
    }

    /// 选点的单测入口：没有饱和段时的段随机结果（取 IP）。
    fn pick_ip_for_test(candidates: &[String], seed: &str) -> Option<String> {
        pick_segment_random_ip(candidates, seed, &std::collections::BTreeSet::new())
            .map(|pick| pick.ip)
    }

    /// 「已试 IP」跟着 plan 走：去重、可读回，且不影响 pin。
    #[test]
    fn quota_retry_state_round_trips_and_dedupes() {
        let mut plan = segment_test_plan(serde_json::json!({
            "opencode_dns_pin": {"host": "cdn.example.test", "ip": "18.154.128.1", "port": 443}
        }));
        assert_eq!(
            read_quota_retry_state(&plan),
            OpenCodeQuotaRetryState::default()
        );
        let mut state = OpenCodeQuotaRetryState::default();
        state.record("18.154.128.1");
        state.record(" 18.154.128.1 ");
        state.record("23.228.247.9");
        state.record("");
        assert_eq!(
            state.tried_ips,
            vec!["18.154.128.1".to_string(), "23.228.247.9".to_string()]
        );
        assert!(write_quota_retry_state(&mut plan, &state));
        assert_eq!(read_quota_retry_state(&plan), state);
        // 与 pin 同居一个 extra 对象，互不覆盖。
        assert_eq!(
            plan_opencode_exit_ip(&plan),
            Some("18.154.128.1".parse::<std::net::IpAddr>().unwrap())
        );
        // 没有 profile 时写不进去，静默退化（不影响重试）。
        let mut bare = segment_test_plan(serde_json::json!({}));
        bare.transport_profile = None;
        assert!(!write_quota_retry_state(&mut bare, &state));
        assert_eq!(
            read_quota_retry_state(&bare),
            OpenCodeQuotaRetryState::default()
        );
    }

    /// 重启不丢冷却：写入 → 换一个「新进程」（新 `AppState`，运行时 KV 全空）→ 回填。
    ///
    /// 这是 2026-10-22 那次事故的回归测试：部署重启后未到期的掩码必须**立刻**生效，
    /// 而不是等下一次 429 才重新发现；同时验证已过期的条目不会被带回来、也不会在
    /// 持久化层里越积越多。
    #[tokio::test]
    async fn persisted_masks_survive_a_restart_and_expired_ones_are_dropped() {
        const PROVIDER: &str = "provider-a";
        let durable =
            std::sync::Arc::new(crate::opencode_cooldown_persist::TestMaskDurableStore::default());

        // ---- 重启前：两次上游失败，冷却 + 短期回避各一条 ----
        let mut before_state = crate::AppState::new().expect("state");
        let before = std::sync::Arc::new(
            crate::opencode_cooldown_persist::OpenCodeCooldownPersist::new(durable.clone()),
        );
        before_state.opencode_mask_persist = Some(std::sync::Arc::clone(&before));
        mark_key_cooldown_seconds(&before_state, PROVIDER, "108.138.0.10", 3_600).await;
        mark_key_avoid_seconds(&before_state, PROVIDER, "108.138.0.11", 180).await;
        // 热路径证据：标记本身**没有**产生任何一次持久化写入（写入只由后台任务发起）。
        assert_eq!(durable.put_count(), 0, "冷却写入不能同步落到持久化层");
        assert_eq!(before.flush_count(), 0, "冷却写入不能同步触发 flush");
        before.flush().await.expect("flush should succeed");

        // 停机期间自然到期的一条：注入到快照里，加载时必须被丢掉。
        let payload = durable.stored_payload().expect("payload written");
        let mut value: serde_json::Value = serde_json::from_str(payload.as_str()).unwrap();
        value["cooldowns"][PROVIDER]["108.138.0.99"] = serde_json::Value::from(1_000u64);
        durable.set_stored_payload(value.to_string());

        // ---- 「重启」：新的 AppState（运行时 KV 是空的）+ 新的镜像实例 ----
        let mut after_state = crate::AppState::new().expect("state");
        let after = std::sync::Arc::new(
            crate::opencode_cooldown_persist::OpenCodeCooldownPersist::new(durable.clone()),
        );
        after_state.opencode_mask_persist = Some(std::sync::Arc::clone(&after));
        assert!(
            !key_in_cooldown(&after_state, PROVIDER, "108.138.0.10").await,
            "重启后的新进程当然还没有冷却——这正是要修的窗口"
        );

        let restored = restore_persisted_opencode_masks(&after_state, &after).await;
        assert!(restored >= 1, "未到期的掩码要回填");
        // key 熔断已停用：即便持久化里有 key 冷却，恢复后也不再生效。
        assert!(!key_in_cooldown(&after_state, PROVIDER, "108.138.0.10").await);
        assert!(key_in_avoid(&after_state, PROVIDER, "108.138.0.11").await);
        assert!(
            !key_in_cooldown(&after_state, PROVIDER, "108.138.0.99").await,
            "已过期的条目不许被回填"
        );

        // TTL 按「剩余时长」回填，而不是重新起算一小时。
        let ttl = after_state
            .runtime_state()
            .kv_ttl_seconds(&cooldown_key(PROVIDER, "108.138.0.10"))
            .await
            .expect("ttl query")
            .expect("ttl present");
        assert!(
            (3_540..=3_600).contains(&ttl),
            "回填的 TTL 应该是剩余的 3600 秒左右，实际 {ttl}"
        );

        // 面板用的冷却清单跟着重建，否则重启后面板会显示「一个都没冷却」。
        let remaining = opencode_exit_ip_cooldown_remaining(&after_state, PROVIDER).await;
        assert!(remaining.contains_key("108.138.0.10"));

        // 清理过的快照写回：过期项不再留在持久化层里堆积。
        let rewritten = durable.stored_payload().expect("payload rewritten");
        assert!(!rewritten.contains("108.138.0.99"));
        assert!(rewritten.contains("108.138.0.10"));
    }

    /// 持久化层不可用时**降级为改动前的行为**：回填 0 条、不 panic、判定照旧看内存 KV。
    #[tokio::test]
    async fn restore_degrades_to_empty_when_the_durable_store_is_down() {
        const PROVIDER: &str = "provider-a";
        let durable =
            std::sync::Arc::new(crate::opencode_cooldown_persist::TestMaskDurableStore::default());
        durable.fail_loads(true);
        let mut state = crate::AppState::new().expect("state");
        let persist = std::sync::Arc::new(
            crate::opencode_cooldown_persist::OpenCodeCooldownPersist::new(durable.clone()),
        );
        state.opencode_mask_persist = Some(std::sync::Arc::clone(&persist));

        assert_eq!(restore_persisted_opencode_masks(&state, &persist).await, 0);
        assert!(!key_in_cooldown(&state, PROVIDER, "108.138.0.20").await);

        // key 熔断已停用：标记冷却不再改变判定。
        mark_key_cooldown_seconds(&state, PROVIDER, "108.138.0.20", 120).await;
        assert!(!key_in_cooldown(&state, PROVIDER, "108.138.0.20").await);
    }

    // -------------------------------------------------------------------------
    // /24 段等概率随机选点 + 段内在途上限
    // -------------------------------------------------------------------------

    /// 造「段 → N 个 IP」的候选集合（段规模刻意不均，与线上一致）。
    fn segments_fixture(spec: &[(&str, usize)]) -> Vec<String> {
        let mut pool = Vec::new();
        for (segment, count) in spec {
            for index in 1..=*count {
                pool.push(format!("{segment}.{index}"));
            }
        }
        pool
    }

    /// 1. 段等概率：3 个段分别 10 / 2 / 1 个 IP，各段被选中次数必须大致均等。
    ///
    /// 这条是整次改造的核心断言：若换成「按 IP 等概率」，10 个 IP 的段会拿到约
    /// 10/13 = 77% 的点，CloudFront 那种 5 IP/段的池子会被先抽干。
    #[test]
    fn segment_pick_is_uniform_across_segments_not_weighted_by_ip_count() {
        let candidates =
            segments_fixture(&[("18.154.128", 10), ("23.228.247", 2), ("65.8.192", 1)]);
        assert_eq!(candidates.len(), 13);
        const ROUNDS: usize = 600;
        let mut per_segment: std::collections::BTreeMap<String, usize> =
            std::collections::BTreeMap::new();
        for attempt in 0..ROUNDS {
            let seed = format!("req-{attempt}:1");
            let pick = pick_segment_random_ip(&candidates, seed.as_str(), &Default::default())
                .expect("候选非空必须选出点");
            *per_segment.entry(pick.segment).or_default() += 1;
        }
        assert_eq!(per_segment.len(), 3, "三个段都必须被点到：{per_segment:?}");
        let expected = ROUNDS / 3;
        for (segment, count) in per_segment.iter() {
            let drift = count.abs_diff(expected);
            assert!(
                drift <= expected / 5,
                "段 {segment} 被选中 {count} 次，期望约 {expected} 次（±20%）：{per_segment:?}"
            );
        }
        // 反向断言：不能是「按 IP 数加权」的结果。
        let biggest = *per_segment.get("18.154.128").expect("段必须出现过");
        assert!(
            biggest < ROUNDS / 2,
            "10 个 IP 的段拿到了 {biggest}/{ROUNDS}，说明选点仍按 IP 数加权"
        );
    }

    /// 2. 在途上限：某段达到上限后被跳过；降到上限以下后恢复可选。
    #[test]
    fn segment_in_flight_cap_skips_the_saturated_segment_then_recovers() {
        let registry = std::sync::Arc::new(OpenCodeSegmentInFlight::new());
        const PROVIDER: &str = "provider-in-flight-cap";
        const NOW: u64 = 1_000_000;
        let candidates = segments_fixture(&[("18.154.128", 2), ("23.228.247", 2)]);
        let policy = OpenCodeSegmentConcurrencyPolicy { max_in_flight: 2 };

        // 把 18.154.128 占满（上限 2）：第三个名额必须被拒。
        let first = registry
            .try_acquire(PROVIDER, "18.154.128", 2, NOW, 60_000)
            .expect("第 1 个名额");
        let second = registry
            .try_acquire(PROVIDER, "18.154.128", 2, NOW, 60_000)
            .expect("第 2 个名额");
        assert!(
            registry
                .try_acquire(PROVIDER, "18.154.128", 2, NOW, 60_000)
                .is_none(),
            "超过在途上限必须拒绝"
        );
        assert_eq!(registry.in_flight(PROVIDER, "18.154.128", NOW), 2);
        assert!(registry
            .saturated_segments(PROVIDER, 2, NOW)
            .contains("18.154.128"));

        // 选点：满了的段一律跳过，全都落到另一个段上。
        for attempt in 0..40u32 {
            let seed = format!("req-{attempt}:1");
            let choice = pick_segment_aware_anchor(
                &registry,
                PROVIDER,
                &candidates,
                seed.as_str(),
                policy,
                NOW,
            )
            .expect("必须选出一个点");
            assert_eq!(choice.pick.segment, "23.228.247", "满了的段必须被跳过");
            assert_eq!(choice.pick.skipped_saturated, 1);
            assert!(!choice.pick.saturated_fallback);
            // 立刻还名额，否则这个段跑两轮也满了（这里只验证「跳过」）。
            drop(choice.lease);
        }

        // 降回上限以下 → 18.154.128 恢复可选（此时该段只有 1 个在途，上限 2）。
        drop(first);
        assert_eq!(registry.in_flight(PROVIDER, "18.154.128", NOW), 1);
        let mut picked_segments: std::collections::BTreeSet<String> =
            std::collections::BTreeSet::new();
        for attempt in 0..80u32 {
            let seed = format!("req-recover-{attempt}:1");
            let choice = pick_segment_aware_anchor(
                &registry,
                PROVIDER,
                &candidates,
                seed.as_str(),
                policy,
                NOW,
            )
            .expect("必须选出一个点");
            picked_segments.insert(choice.pick.segment.clone());
            assert_eq!(
                choice.pick.skipped_saturated, 0,
                "两个段都有名额时不该有段被跳过"
            );
            drop(choice.lease);
        }
        assert!(
            picked_segments.contains("18.154.128"),
            "释放名额后必须重新可选：{picked_segments:?}"
        );
        drop(second);
    }

    /// 3. 所有段都在途超限：降级放行（不 panic、不返回 None），并标记出来打日志。
    #[test]
    fn segment_pick_degrades_instead_of_returning_nothing_when_every_segment_is_saturated() {
        let registry = std::sync::Arc::new(OpenCodeSegmentInFlight::new());
        const PROVIDER: &str = "provider-all-saturated";
        const NOW: u64 = 2_000_000;
        let candidates = segments_fixture(&[("18.154.128", 2), ("23.228.247", 1)]);
        let mut held = Vec::new();
        for segment in ["18.154.128", "23.228.247"] {
            for _ in 0..2 {
                held.push(
                    registry
                        .try_acquire(PROVIDER, segment, 2, NOW, 60_000)
                        .expect("占满两个段"),
                );
            }
        }
        assert_eq!(held.len(), 4);
        let choice = pick_segment_aware_anchor(
            &registry,
            PROVIDER,
            &candidates,
            "req-1:1",
            OpenCodeSegmentConcurrencyPolicy::default(),
            NOW,
        )
        .expect("全段超限也必须选出一个点（不能无点可选）");
        assert!(choice.pick.saturated_fallback, "降级必须被标记");
        assert_eq!(choice.pick.skipped_saturated, 2, "两个段都因超限被跳过");
        assert!(
            choice.lease.is_none(),
            "降级放行时不再占名额（否则会一直叠加）"
        );
        assert!(
            candidates.contains(&choice.pick.ip),
            "降级仍然必须选池内的点"
        );
    }

    /// 6. guard 在成功 / 失败 / early-return / 取消（作用域被丢）四条路径上都减计数。
    #[test]
    fn segment_lease_guard_decrements_on_every_exit_path() {
        let registry = std::sync::Arc::new(OpenCodeSegmentInFlight::new());
        const PROVIDER: &str = "provider-guard-paths";
        const SEGMENT: &str = "18.154.128";
        const NOW: u64 = 4_000_000;

        // 成功路径
        fn success_path(
            registry: &std::sync::Arc<OpenCodeSegmentInFlight>,
            provider: &str,
            segment: &str,
        ) -> Option<String> {
            let _lease = registry.try_acquire(provider, segment, 2, 4_000_000, 60_000)?;
            Some("ok".to_string())
        }
        // early-return 路径（`?` 提前退出）
        fn early_return_path(
            registry: &std::sync::Arc<OpenCodeSegmentInFlight>,
            provider: &str,
            segment: &str,
        ) -> Option<String> {
            let _lease = registry.try_acquire(provider, segment, 2, 4_000_000, 60_000)?;
            None
        }
        // 失败路径（错误往上传）
        fn failing_path(
            registry: &std::sync::Arc<OpenCodeSegmentInFlight>,
            provider: &str,
            segment: &str,
        ) -> Result<(), String> {
            let _lease = registry
                .try_acquire(provider, segment, 2, 4_000_000, 60_000)
                .ok_or_else(|| "段已满".to_string())?;
            Err("上游 429".to_string())
        }

        // 每条路径都先确认「占用期间计数为 1」，跑完必须回到 0。
        assert!(registry
            .try_acquire(PROVIDER, SEGMENT, 2, NOW, 60_000)
            .is_some());
        assert_eq!(
            registry.in_flight(PROVIDER, SEGMENT, NOW),
            0,
            "临时 guard 已被 drop"
        );

        assert_eq!(
            success_path(&registry, PROVIDER, SEGMENT),
            Some("ok".to_string())
        );
        assert_eq!(
            registry.in_flight(PROVIDER, SEGMENT, NOW),
            0,
            "成功路径漏减"
        );

        assert_eq!(early_return_path(&registry, PROVIDER, SEGMENT), None);
        assert_eq!(
            registry.in_flight(PROVIDER, SEGMENT, NOW),
            0,
            "early-return 漏减"
        );

        assert!(failing_path(&registry, PROVIDER, SEGMENT).is_err());
        assert_eq!(
            registry.in_flight(PROVIDER, SEGMENT, NOW),
            0,
            "失败路径漏减"
        );

        // 「取消 / 作用域被丢」：独立作用域里的 guard 随作用域结束而释放。
        {
            let _lease = registry
                .try_acquire(PROVIDER, SEGMENT, 2, NOW, 60_000)
                .expect("名额");
            assert_eq!(registry.in_flight(PROVIDER, SEGMENT, NOW), 1);
        }
        assert_eq!(
            registry.in_flight(PROVIDER, SEGMENT, NOW),
            0,
            "作用域结束漏减"
        );

        // 满员 → 反复申请失败也不能改变计数。
        let held_a = registry
            .try_acquire(PROVIDER, SEGMENT, 2, NOW, 60_000)
            .unwrap();
        let held_b = registry
            .try_acquire(PROVIDER, SEGMENT, 2, NOW, 60_000)
            .unwrap();
        for _ in 0..5 {
            assert!(registry
                .try_acquire(PROVIDER, SEGMENT, 2, NOW, 60_000)
                .is_none());
        }
        assert_eq!(
            registry.in_flight(PROVIDER, SEGMENT, NOW),
            2,
            "失败的申请不能加计数"
        );
        drop(held_a);
        drop(held_b);
        assert_eq!(registry.in_flight(PROVIDER, SEGMENT, NOW), 0);

        // 不同 provider 之间互不影响。
        let _other = registry.try_acquire("provider-other", SEGMENT, 2, NOW, 60_000);
        assert_eq!(registry.in_flight("provider-other", SEGMENT, NOW), 1);
        assert_eq!(registry.in_flight(PROVIDER, SEGMENT, NOW), 0);
    }

    /// 7. `detach()` 之后名额交给 TTL：到期自动回收——这是「漏减不会让段永久跳过」的保证。
    #[test]
    fn detached_lease_keeps_the_slot_only_until_it_expires() {
        let registry = std::sync::Arc::new(OpenCodeSegmentInFlight::new());
        const PROVIDER: &str = "provider-detach-ttl";
        const SEGMENT: &str = "18.154.128";
        let lease = registry
            .try_acquire(PROVIDER, SEGMENT, 1, 1_000, 500)
            .expect("第一个名额");
        lease.detach();
        assert_eq!(
            registry.in_flight(PROVIDER, SEGMENT, 1_000),
            1,
            "detach 不立即减"
        );
        assert_eq!(
            registry.in_flight(PROVIDER, SEGMENT, 1_499),
            1,
            "到期前仍占着"
        );
        assert!(
            registry
                .try_acquire(PROVIDER, SEGMENT, 1, 1_499, 500)
                .is_none(),
            "未到期时仍然算满"
        );
        assert_eq!(
            registry.in_flight(PROVIDER, SEGMENT, 1_500),
            0,
            "到期即回收"
        );
        assert!(
            registry
                .try_acquire(PROVIDER, SEGMENT, 1, 1_500, 500)
                .is_some(),
            "回收后必须可以重新占"
        );
    }

    /// 配置：默认 2，可覆盖，越界夹紧到 1..=16。
    #[test]
    fn segment_max_in_flight_defaults_clamps_and_validates() {
        let default = OpenCodeSegmentConcurrencyPolicy::from_provider_config(&None);
        assert_eq!(default, OpenCodeSegmentConcurrencyPolicy::default());
        assert_eq!(default.max_in_flight, 2);
        assert!(default.validate().is_ok());

        let tuned = OpenCodeSegmentConcurrencyPolicy::from_provider_config(&Some(
            serde_json::json!({"opencode_scan": {"segment_max_in_flight": 5}}),
        ));
        assert_eq!(tuned.max_in_flight, 5);

        // 0 夹紧到 1（0 等于「每个段都已满」，会直接把选点打死）。
        let zero = OpenCodeSegmentConcurrencyPolicy::from_provider_config(&Some(
            serde_json::json!({"opencode_scan": {"segment_max_in_flight": 0}}),
        ));
        assert_eq!(zero.max_in_flight, 1);

        let huge = OpenCodeSegmentConcurrencyPolicy::from_provider_config(&Some(
            serde_json::json!({"opencode_scan": {"segment_max_in_flight": 9_999}}),
        ));
        assert_eq!(
            huge.max_in_flight,
            MAX_OPENCODE_SEGMENT_MAX_IN_FLIGHT as usize
        );

        for invalid in [
            OpenCodeSegmentConcurrencyPolicy { max_in_flight: 0 },
            OpenCodeSegmentConcurrencyPolicy {
                max_in_flight: MAX_OPENCODE_SEGMENT_MAX_IN_FLIGHT as usize + 1,
            },
        ] {
            assert!(invalid.validate().is_err(), "{invalid:?} 必须被拒");
        }
    }

    /// 段随机的确定性：同一 `seed` 必须可复现（单测与排障都依赖这一点）。
    #[test]
    fn segment_pick_is_reproducible_for_the_same_seed() {
        let candidates = segments_fixture(&[("18.154.128", 3), ("23.228.247", 1)]);
        let first = pick_segment_random_ip(&candidates, "req-1:1", &Default::default());
        let second = pick_segment_random_ip(&candidates, "req-1:1", &Default::default());
        assert_eq!(first, second);
        // 不同种子必须真的换点（相邻种子不能退化到同一个候选）。
        let mut picked = std::collections::BTreeSet::new();
        for attempt in 1..=200u32 {
            let seed = format!("req-{attempt}:1");
            picked.insert(
                pick_segment_random_ip(&candidates, seed.as_str(), &Default::default())
                    .expect("候选非空")
                    .ip,
            );
        }
        assert_eq!(
            picked.len(),
            4,
            "200 个种子必须覆盖全部 4 个 IP：{picked:?}"
        );
    }
}
