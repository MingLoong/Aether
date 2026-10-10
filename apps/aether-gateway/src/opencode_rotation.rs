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
//!    没有会话标识时退回游标轮转（[`rotate_with_cursor`]）。
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

use crate::AppState;

/// 游标键的存活时间：足够跨过一次网关重启即可，过期后从 0 重新开始。
const ROTATION_CURSOR_TTL_SECONDS: u64 = 24 * 60 * 60;
/// 额度耗尽后的默认冷却时长（分钟）。
pub(crate) const DEFAULT_COOLDOWN_MINUTES: u32 = 60;
/// 403 时用来识别「免费额度耗尽 / 被限流」的文案指纹（已转小写比较）。
const OPENCODE_FREE_TIER_MESSAGE_MARKERS: [&str; 4] =
    ["freetier", "free tier", "quota", "rate limit"];

fn cursor_key(provider_id: &str) -> String {
    format!("opencode_pool:rotation:cursor:{provider_id}")
}

fn cooldown_key(provider_id: &str, key_id: &str) -> String {
    format!("opencode_pool:cooldown:{provider_id}:{key_id}")
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

fn scan_cursor_key(provider_id: &str) -> String {
    format!("opencode_pool:scan:cursor:{provider_id}")
}

/// 扫描切片游标：记录下一轮从候选列表的第几个开始探。
///
/// 没有它的话，候选超过 `OPENCODE_SCAN_MAX_CANDIDATES` 时，
/// 每轮都只会探字典序最靠前的那批（探不通的 IP 永远排在前面），
/// 后面的网段会被静默饿死。
pub(crate) async fn read_scan_cursor(state: &AppState, provider_id: &str) -> u64 {
    state
        .runtime_kv_get(&scan_cursor_key(provider_id))
        .await
        .ok()
        .flatten()
        .and_then(|raw| raw.trim().parse::<u64>().ok())
        .unwrap_or_default()
}

/// 推进扫描切片游标，返回写入后的值。
///
/// TTL 由调用方传入：一轮真实扫描可能跨多个 interval，写死 24h 会让游标在两轮
/// 之间过期，于是每轮都从第 0 个重来、超出单轮上限的网段永远轮不到。
/// 调用方按 `interval × 预期轮数 × 2` 计算（见 `OpenCodeScanConfig::scan_cursor_ttl_seconds`）。
pub(crate) async fn write_scan_cursor(
    state: &AppState,
    provider_id: &str,
    value: u64,
    ttl_seconds: u64,
) -> u64 {
    let _ = state
        .runtime_kv_setex(
            &scan_cursor_key(provider_id),
            &value.to_string(),
            ttl_seconds,
        )
        .await;
    value
}

fn scan_seen_key(provider_id: &str) -> String {
    format!("opencode_pool:scan:seen:{provider_id}")
}

/// 读「本轮已探通」集合。
///
/// **`None` 与 `Some(空集)` 必须区分**：`None` 表示键不存在（TTL 到期或被清），
/// 此时轮末**不能**按「本轮未见即淘汰」重建候选——累积集合本身都丢了，重建只会把
/// 前面所有切片探到的节点一起抹掉。`Some(空集)` 是合法状态：前面那些切片确实一个
/// 都没探通。
pub(crate) async fn read_scan_seen(
    state: &AppState,
    provider_id: &str,
) -> Option<std::collections::BTreeSet<String>> {
    let raw = state
        .runtime_kv_get(&scan_seen_key(provider_id))
        .await
        .ok()
        .flatten()?;
    serde_json::from_str::<std::collections::BTreeSet<String>>(&raw).ok()
}

/// 写回「本轮已探通」集合，返回是否落盘成功。
///
/// TTL 与扫描游标一致：两者要么同属一轮，要么一起过期——游标还在而集合先没了，
/// 会让轮末重建拿到不完整的输入。
pub(crate) async fn write_scan_seen(
    state: &AppState,
    provider_id: &str,
    seen: &std::collections::BTreeSet<String>,
    ttl_seconds: u64,
) -> bool {
    let Ok(encoded) = serde_json::to_string(seen) else {
        return false;
    };
    state
        .runtime_kv_setex(&scan_seen_key(provider_id), &encoded, ttl_seconds)
        .await
        .is_ok()
}

/// 清掉「本轮已探通」集合：新一轮开始时（游标回到 0）、或轮末重建完成后。
pub(crate) async fn clear_scan_seen(state: &AppState, provider_id: &str) {
    let _ = state.runtime_kv_del(&scan_seen_key(provider_id)).await;
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
    /// 成功但首字超过阈值：慢，是最典型的健康证据。
    SlowFirstByte,
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
            Self::SlowFirstByte => "slow_first_byte",
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
        OpenCodeFailureSource::Transport
            | OpenCodeFailureSource::GatewayTimeout
            | OpenCodeFailureSource::SlowFirstByte
    )
}

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
    let current = peek_opencode_ip_fail(state, provider_id, ip).await;
    let next = current.saturating_add(1);
    let _ = state
        .runtime_kv_setex(
            &runtime_fail_key(provider_id, ip),
            &next.to_string(),
            OPENCODE_RUNTIME_FAIL_WINDOW_SECONDS,
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
    let reason = source.label();
    mark_key_cooldown(state, provider_id, ip, OPENCODE_SUSPECT_TTL_MINUTES).await;
    let _ = state
        .runtime_kv_setex(
            &suspect_audit_key(provider_id, ip),
            reason,
            (OPENCODE_SUSPECT_TTL_MINUTES as u64) * 60,
        )
        .await;
    tracing::info!(
        event_name = "opencode_ip_suspect_marked",
        provider_id,
        ip,
        reason,
        ttl_minutes = OPENCODE_SUSPECT_TTL_MINUTES,
        "opencode exit ip marked suspect after repeated runtime failures"
    );
}

/// 记一次运行时失败；达门槛时写「立刻不用」。返回累计次数（不计入时 `None`）。
pub(crate) async fn record_opencode_runtime_failure(
    state: &AppState,
    provider_id: &str,
    ip: &str,
    source: OpenCodeFailureSource,
) -> Option<u64> {
    if !opencode_failure_counts_for_ip(source) {
        return None;
    }
    let fails = bump_opencode_ip_fail(state, provider_id, ip).await;
    if opencode_failure_reached_suspect_threshold(fails) {
        mark_opencode_ip_suspect(state, provider_id, ip, source).await;
    }
    Some(fails)
}

/// 按执行计划记一次运行时失败（两条请求路径的唯一入口）。
pub(crate) async fn note_opencode_runtime_failure_for_plan(
    state: &AppState,
    plan: &aether_contracts::ExecutionPlan,
    source: OpenCodeFailureSource,
) {
    if !opencode_failure_counts_for_ip(source) {
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
    // 只有 provider 级池模型才有「本次请求实际用了哪个出口 IP」。旧的一 key 一 IP
    // 模型里 IP 属于 key 本身，累计成「这个 key 不好用」是另一件事，这里不记
    // （那条路径仍有冷却与被动降权兜着）。
    let Some(exit_ip) = plan_opencode_exit_ip(plan).map(|ip| ip.to_string()) else {
        return;
    };
    let provider_id = transport.provider.id.as_str();
    let Some(fails) = record_opencode_runtime_failure(state, provider_id, &exit_ip, source).await
    else {
        return;
    };
    tracing::debug!(
        provider_id,
        exit_ip = exit_ip.as_str(),
        reason = source.label(),
        fails,
        "opencode runtime failure recorded for exit ip"
    );
}

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
    let ttl_seconds = u64::from(cooldown_minutes.max(1)) * 60;
    let _ = state
        .runtime_kv_setex(&cooldown_key(provider_id, key_id), "1", ttl_seconds)
        .await;
}

/// 判断某个 key 是否仍在冷却期内。
pub(crate) async fn key_in_cooldown(state: &AppState, provider_id: &str, key_id: &str) -> bool {
    state
        .runtime_kv_exists(&cooldown_key(provider_id, key_id))
        .await
        .unwrap_or(false)
}

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
) {
    let Some(exit_ip) = opencode_key_exit_ip(transport) else {
        return;
    };
    mark_opencode_exit_ip_cooldown_for_ip(state, transport, exit_ip, status_code, message).await;
}

/// 同 [`mark_opencode_exit_ip_cooldown`]，但出口 IP 由调用方给出。
///
/// 冷却时长取 provider 的 `config.opencode_scan.cooldown_minutes`，缺省
/// [`DEFAULT_COOLDOWN_MINUTES`]；未命中判定条件时**什么都不做**。
pub(crate) async fn mark_opencode_exit_ip_cooldown_for_ip(
    state: &AppState,
    transport: &GatewayProviderTransportSnapshot,
    exit_ip: std::net::IpAddr,
    status_code: u16,
    message: Option<&str>,
) {
    if !cooldown_triggered(
        transport.provider.provider_type.as_str(),
        status_code,
        message,
    ) {
        return;
    }
    let provider_id = transport.provider.id.as_str();
    let exit_ip = exit_ip.to_string();
    let cooldown_minutes =
        crate::opencode_pool::OpenCodeScanConfig::from_provider_config(&transport.provider.config)
            .effective_cooldown_minutes();
    mark_key_cooldown(state, provider_id, exit_ip.as_str(), cooldown_minutes).await;
    tracing::info!(
        event_name = "opencode_exit_ip_cooldown_marked",
        provider_id,
        exit_ip = exit_ip.as_str(),
        status_code,
        cooldown_minutes,
        "opencode exit ip marked in cooldown after free tier or rate limit failure"
    );
}

/// 上游失败后，给**本次请求实际使用**的 opencode 出口 IP 打冷却。
///
/// 出口 IP 由 `plan` 反查：provider 级 IP 池模型下，IP 是规划阶段才抽出来注入候选
/// transport 快照的，目录快照里取不到，只能从 plan 的 transport profile 读
/// （见 [`plan_opencode_exit_ip`]）。
///
/// **流式与同步两条路径共用这一个入口**。此前只有流式路径有这层钩子，同步（非流式）
/// 请求的 429/403 失败信号全部丢失——一半流量等于没有冷却保护。
pub(crate) async fn mark_opencode_exit_ip_cooldown_for_plan(
    state: &AppState,
    plan: &aether_contracts::ExecutionPlan,
    status_code: u16,
    message: Option<&str>,
) {
    // 早退：非 429/403 连 provider 快照都不读，其它 provider 的失败路径逐字节不变。
    if !matches!(status_code, 429 | 403) {
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
        // 旧的一 key 一 IP 模型：出口 IP 直接来自目录 key 的 metadata。
        mark_opencode_exit_ip_cooldown(state, &transport, status_code, message).await;
        return;
    };
    // provider 级 IP 池模型：IP 是本次请求才抽出来的。
    mark_opencode_exit_ip_cooldown_for_ip(state, &transport, exit_ip, status_code, message).await;
}

/// 保底池大小：低于这个数量，任何机制都不允许把池子变小。
///
/// 会话粘性和被动降权的收益随池增大而升高，风险却随池减小而放大：
/// 三个节点的池子里冷却掉一个就只剩两个，一个设备锁死一个节点就没有
/// 分散可言。所以保底是硬约束，不提供关闭开关。
pub(crate) const OPENCODE_DEFAULT_MIN_POOL_SIZE: usize = 5;
/// 会话粘性的最小可用池：低于此数量自动退回游标轮转。
pub(crate) const OPENCODE_DEFAULT_STICKY_MIN_POOL: usize = 10;

/// 被动降权首字节阈值的**下限**，同时是默认阈值（毫秒）。
///
/// 下限不是随手定的：线上实测 15 万 token 的流式请求首字节中位 6417 ms、最长
/// 12980 ms，也就是说一次完全正常的大请求本来就贴着 15 秒。阈值一旦允许调到
/// 10 秒或更低，上面这类请求会开始把自己的健康节点误判成慢节点——降权机制
/// 反而成了故障源。所以阈值只允许**调高**（更保守），不允许调低。
///
/// 这个常量还被流式看门狗当作粗筛门槛（见 execution_runtime/stream/execution.rs）：
/// 因为配置值不可能低于它，`elapsed > 下限` 是 `elapsed > 配置值` 的必要条件，
/// 粗筛因此不会漏判，同时让正常请求不必为每个流都起一个读快照的任务。
/// 这层依赖必须与校验下限保持一致，有测试钉住。
pub(crate) const OPENCODE_MIN_DEGRADE_FIRST_BYTE_MS: u64 = 15_000;
/// 首字节阈值上限（毫秒）：两分钟。再大就失去了「慢节点」的意义。
pub(crate) const OPENCODE_MAX_DEGRADE_FIRST_BYTE_MS: u64 = 120_000;
/// 被动降权冷却时长的默认值（分钟）。刻意短——节点应当尽快回来重新证明自己。
pub(crate) const OPENCODE_DEFAULT_DEGRADE_COOLDOWN_MINUTES: u32 = 15;
/// 冷却时长上限（分钟）：一天。再长就变成了人工禁用，不是自动降权。
pub(crate) const OPENCODE_MAX_DEGRADE_COOLDOWN_MINUTES: u32 = 1_440;

/// 成功但太慢的响应，把锚点节点降权。
///
/// 主动验健康每 3 小时采一次，中间有 3 小时盲期。慢节点在这段时间里被
/// 轮转到，用户就要等几十秒。真实请求已经量到了首字节，拿来当信号是
/// 零成本的：第一次撞上就降权，不必等下一轮复验。
///
/// 与 [`mark_opencode_exit_ip_cooldown_for_ip`] 的分工：后者针对上游明确
/// 返回的 429/403，这里针对**沉默的退化**——请求成功返回，只是慢得不合理。
pub(crate) async fn mark_opencode_anchor_slow(
    state: &AppState,
    plan: &aether_contracts::ExecutionPlan,
    transport: &GatewayProviderTransportSnapshot,
    status_code: u16,
    first_byte_ms: Option<u64>,
) {
    // 只看成功但慢的响应。失败已由 429/403 的冷却覆盖。
    if !(200..300).contains(&status_code) {
        return;
    }
    let Some(health) = opencode_health_config(transport) else {
        return;
    };
    // 阈值和冷却时长都读配置，不读常量：常量只是默认值。读常量的写法会让
    // 界面上的设置看起来生效、实际不生效——半接线的开关比没有开关更糟。
    let threshold_ms = health.passive_degrade_first_byte_ms();
    let cooldown_minutes = health.passive_degrade_cooldown_minutes();
    let Some(first_byte_ms) = first_byte_ms.filter(|ms| *ms > threshold_ms) else {
        return;
    };
    let Some(exit_ip) = plan_opencode_exit_ip(plan).map(|ip| ip.to_string()) else {
        return;
    };
    let exit_ip = exit_ip.as_str();
    // 池子已经偏小时不降权：冷却掉一个就少一个，三五个节点的池子经不起折腾。
    if !health.passive_degrade_active(health.healthy.len()) {
        return;
    }
    let provider_id = transport.provider.id.as_str();
    // 运行时证据：成功但太慢同样计入失败次数（「慢」是最典型的健康证据）。
    // 必须放在冷却早退**之前**：已经在冷却里的节点再慢一次，也应该让计数继续累积，
    // 否则「每次都慢」永远不会走到「进异常池」那一步。
    record_opencode_runtime_failure(
        state,
        provider_id,
        exit_ip,
        OpenCodeFailureSource::SlowFirstByte,
    )
    .await;
    if key_in_cooldown(state, provider_id, exit_ip).await {
        return;
    }
    mark_key_cooldown(state, provider_id, exit_ip, cooldown_minutes).await;
    tracing::info!(
        event_name = "opencode_anchor_degraded",
        log_type = "ops",
        provider_id,
        exit_ip,
        first_byte_ms,
        threshold_ms,
        cooldown_minutes,
        pool_size = health.healthy.len(),
        "opencode anchor answered successfully but too slowly; cooling it down"
    );
}

/// 从 provider 快照读验健康配置；非 opencode 或读不到时返回 `None`。
/// 拿不到配置就宁可不降权——宁可漏掉一次信号，也不要误伤一个好节点。
fn opencode_health_config(
    transport: &GatewayProviderTransportSnapshot,
) -> Option<crate::opencode_pool::OpenCodeHealthConfig> {
    if !aether_provider_transport::is_opencode_provider_transport(transport) {
        return None;
    }
    Some(
        crate::opencode_pool::OpenCodeHealthConfig::from_provider_config(
            &transport.provider.config,
        ),
    )
}

/// 在组内按游标轮转：记住上一次的位置，这次 +1。
pub(crate) fn rotate_with_cursor(group: &[String], cursor: u64) -> Option<String> {
    if group.is_empty() {
        return None;
    }
    let index = (cursor % group.len() as u64) as usize;
    group.get(index).cloned()
}

/// 选点时要跳过的集合，以及池小保护的阈值。
///
/// 打包成结构体而不是继续加位置参数：`pick_anchor_ip` 本来就有五个参数，
/// 继续加会让调用点变成一串看不出含义的列表与布尔值。
#[derive(Clone, Debug, Default)]
pub(crate) struct OpenCodeAnchorSkip {
    /// 人工停用的 IP：**任何时候**都跳过，包括池里只剩它们的时候。
    pub(crate) disabled: Vec<String>,
    /// 人工拉黑：与异常池同样是「先别用」，池小保护生效时不参与跳过。
    pub(crate) blocked: Vec<String>,
    /// 异常池：复验判定有问题的节点。
    pub(crate) abnormal: Vec<String>,
    /// 池小保护下限：可用池小于它时，`blocked` / `abnormal` 不生效。
    pub(crate) protect_pool_floor: usize,
}

/// 每次请求从 provider 级 IP 池里挑一个 CDN 节点作为 DNS 锚点。
///
/// **不要叫它 exit IP**：前置代理下，opencode 看到的出口 IP 永远是代理的，
/// 与池里选哪个节点无关。池的作用是分散到代理的不同入口节点，绕开单点限速。
///
/// 持久化键 `upstream_metadata["opencode_exit_ip"]` 是历史命名，保持不变。
///
/// 冷却中的 IP 会被跳过；池里只剩一个 IP 时不推进游标（没有轮换可言）。
/// 传了 `session_key` 时按会话稳定选取，同一会话全程命中同一节点。
pub(crate) async fn pick_anchor_ip(
    state: &AppState,
    provider_id: &str,
    exit_pool: &[String],
    skip: &OpenCodeAnchorSkip,
    session_key: Option<&str>,
) -> Option<String> {
    if exit_pool.is_empty() {
        return None;
    }
    let disabled: std::collections::BTreeSet<&str> = skip
        .disabled
        .iter()
        .map(|ip| ip.trim())
        .filter(|ip| !ip.is_empty())
        .collect();
    // 池小保护：池子低于保护线时，异常池与拉黑只记录、不参与选择——三个节点的
    // 池子里「立刻不用」等于把流量压到一两个节点上，那比用一个慢节点更难察觉，
    // 也更难恢复。
    let soft_marks_active =
        crate::opencode_pool::pool::soft_marks_active(exit_pool.len(), skip.protect_pool_floor);
    let soft_skip: std::collections::BTreeSet<&str> = if soft_marks_active {
        skip.blocked
            .iter()
            .chain(skip.abnormal.iter())
            .map(|ip| ip.trim())
            .filter(|ip| !ip.is_empty())
            .collect()
    } else {
        std::collections::BTreeSet::new()
    };
    let mut usable: Vec<String> = Vec::with_capacity(exit_pool.len());
    for ip in exit_pool {
        if disabled.contains(ip.trim()) {
            continue;
        }
        if soft_skip.contains(ip.trim()) {
            continue;
        }
        if !key_in_cooldown(state, provider_id, ip).await {
            usable.push(ip.clone());
        }
    }
    if usable.is_empty() {
        // 全部被停用/冷却：仍然放行一个，避免整池不可用导致完全打不开。
        //
        // 但必须跳过「被手工停用」的——回退到 disabled 的第一个，等于用
        // 一次故障掩盖掉用户明确表达的意图，而且看起来完全正常。
        // 冷却是可自愈的，停用不是。异常池/拉黑排在停用之后：它们比停用更
        // 值得让人看见（池子已经空了，此时"先别用"没有意义）。
        let mut fallback = exit_pool
            .iter()
            .find(|ip| !disabled.contains(ip.trim()) && !soft_skip.contains(ip.trim()))
            .cloned();
        if fallback.is_none() {
            fallback = exit_pool
                .iter()
                .find(|ip| !disabled.contains(ip.trim()))
                .cloned();
        }
        if fallback.is_none() {
            fallback = exit_pool.first().cloned();
        }
        if let Some(ip) = fallback.as_deref() {
            remember_last_exit_ip(state, provider_id, ip).await;
        }
        return fallback;
    }
    if usable.len() == 1 {
        let only = usable.first().cloned();
        if let Some(ip) = only.as_deref() {
            remember_last_exit_ip(state, provider_id, ip).await;
        }
        return only;
    }
    // 会话级粘性：同一个客户端落在同一个节点上。
    //
    // 每请求轮转会让同一段对话的每一轮首字时间都换一个量级——实测节点间
    // 6~201 秒，轮转的体感就是「同样的问题时快时慢」。固定住之后延迟可预期，
    // 连接也能复用。仍然保留游标轮转作为没有会话标识时的兜底。
    let picked = match pick_session_anchor(&usable, session_key) {
        Some(ip) => Some(ip),
        None => {
            let cursor = next_rotation_cursor(state, provider_id).await;
            rotate_with_cursor(&usable, cursor)
        }
    };
    if let Some(ip) = picked.as_deref() {
        remember_last_exit_ip(state, provider_id, ip).await;
    }
    picked
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
    fn empty_group_yields_no_exit_ip() {
        assert_eq!(rotate_with_cursor(&[], 3), None);
    }

    #[test]
    fn rotation_visits_every_member_then_wraps() {
        let group = vec![
            "key-a".to_string(),
            "key-b".to_string(),
            "key-c".to_string(),
        ];
        let visited: Vec<String> = (0..7)
            .map(|cursor| rotate_with_cursor(&group, cursor).expect("group is not empty"))
            .collect();
        assert_eq!(
            visited,
            vec!["key-a", "key-b", "key-c", "key-a", "key-b", "key-c", "key-a",]
        );
    }

    #[test]
    fn rotation_is_stable_for_large_cursor() {
        let group = vec!["key-a".to_string(), "key-b".to_string()];
        assert_eq!(
            rotate_with_cursor(&group, u64::MAX),
            rotate_with_cursor(&group, 1)
        );
    }

    #[test]
    fn zero_cursor_selects_first_member() {
        let group = vec!["key-a".to_string(), "key-b".to_string()];
        assert_eq!(rotate_with_cursor(&group, 0), Some("key-a".to_string()));
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
    fn only_transport_gateway_timeout_and_slow_count_against_the_ip() {
        use OpenCodeFailureSource as Src;

        for source in [Src::Transport, Src::GatewayTimeout, Src::SlowFirstByte] {
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
}
