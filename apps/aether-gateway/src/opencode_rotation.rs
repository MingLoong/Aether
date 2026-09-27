//! OpenCode 出口 IP 池的「最少在途 + 游标轮转」与额度熔断。
//!
//! 与调度器内置排序的关系：调度器把候选排成**全序**（末尾用 key_id 兜底拆开，
//! 不存在并列），并且 planner 会在 scheduler 之后**再排一次**，真正决定选哪个 key
//! 的是 planner 层的 `candidates.first()`。因此本模块只提供两块与排序无关、
//! 可独立复用的能力：
//!
//! 1. 轮转游标：跨进程单调递增的整数（Redis kv，原子 GET+DEL 后写回）。
//! 2. 额度熔断：某个 key 触发 403 FreeTierError / 429 后进入冷却，冷却期内被排除。
//!
//! 「取在途最少的一组 → 组内按游标轮转」这一步是纯函数 [`pick_min_inflight_group`]
//! + [`rotate_with_cursor`]，由 planner 层的排序后置钩子调用。
//!
//! Redis 键位（都走 RuntimeState 的 kv 原语，自动带实例命名空间）：
//!
//! ```text
//! opencode_pool:rotation:cursor:<provider_id>     轮转游标，带 TTL
//! opencode_pool:cooldown:<provider_id>:<key_id>   冷却标记，TTL = 冷却时长
//! ```

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
pub(crate) async fn write_scan_cursor(state: &AppState, provider_id: &str, value: u64) -> u64 {
    let _ = state
        .runtime_kv_setex(
            &scan_cursor_key(provider_id),
            &value.to_string(),
            ROTATION_CURSOR_TTL_SECONDS,
        )
        .await;
    value
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
    let cooldown_minutes = crate::handlers::admin::OpenCodeScanConfig::from_provider_config(
        &transport.provider.config,
    )
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

/// 批量过滤掉处于冷却期的 key，返回剩余 key_id。
pub(crate) async fn filter_cooled_down_keys(
    state: &AppState,
    provider_id: &str,
    key_ids: &[String],
) -> Vec<String> {
    let mut alive = Vec::with_capacity(key_ids.len());
    for key_id in key_ids {
        if !key_in_cooldown(state, provider_id, key_id).await {
            alive.push(key_id.clone());
        }
    }
    alive
}

/// 单个候选的轮转输入。
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct RotationCandidate {
    pub(crate) key_id: String,
    /// 当前在途请求数；越小越优先。
    pub(crate) in_flight: u64,
}

/// 取出「在途最少」的那一组，返回按 key_id 升序排列的 key_id 列表。
///
/// 调度器给的是全序而不是并列，所以这里按 `in_flight` 数值分组：最小值的所有候选
/// 构成一组。组内按 key_id 排序，保证游标取模的结果稳定可复现（不依赖候选入参顺序）。
pub(crate) fn pick_min_inflight_group(candidates: &[RotationCandidate]) -> Vec<String> {
    let Some(min) = candidates.iter().map(|item| item.in_flight).min() else {
        return Vec::new();
    };
    let mut group: Vec<String> = candidates
        .iter()
        .filter(|item| item.in_flight == min)
        .map(|item| item.key_id.clone())
        .collect();
    group.sort();
    group
}

/// 在组内按游标轮转：记住上一次的位置，这次 +1。
pub(crate) fn rotate_with_cursor(group: &[String], cursor: u64) -> Option<String> {
    if group.is_empty() {
        return None;
    }
    let index = (cursor % group.len() as u64) as usize;
    group.get(index).cloned()
}

/// 每次请求从 provider 级 IP 池里挑一个出口 IP 作为 DNS 锚点。
///
/// 冷却中的 IP 会被跳过；池里只剩一个 IP 时不推进游标（没有轮换可言）。
pub(crate) async fn pick_exit_ip(
    state: &AppState,
    provider_id: &str,
    exit_pool: &[String],
    disabled: &[String],
) -> Option<String> {
    if exit_pool.is_empty() {
        return None;
    }
    let disabled: std::collections::BTreeSet<&str> = disabled
        .iter()
        .map(|ip| ip.trim())
        .filter(|ip| !ip.is_empty())
        .collect();
    let mut usable: Vec<String> = Vec::with_capacity(exit_pool.len());
    for ip in exit_pool {
        if disabled.contains(ip.trim()) {
            continue;
        }
        if !key_in_cooldown(state, provider_id, ip).await {
            usable.push(ip.clone());
        }
    }
    if usable.is_empty() {
        // 全部被停用/冷却：仍然放行一个，避免整池不可用导致完全打不开。
        return exit_pool.first().cloned();
    }
    if usable.len() == 1 {
        return usable.first().cloned();
    }
    let cursor = next_rotation_cursor(state, provider_id).await;
    rotate_with_cursor(&usable, cursor)
}

/// 池候选槽位轮转：按「槽位顺序」返回新的 key_id 排列。
/// - 处于冷却期的 key 先从可选项里剔除；
/// - 可选项少于槽位数时只返回可选项，调用方保留其余槽位原样，不制造空洞；
/// - 游标由 [`next_rotation_cursor`] 推进，单候选时不消耗游标。
///
/// 返回 `None` 表示「不要动」，调用方应保持原顺序。
pub(crate) async fn rotate_pool_slots(
    state: &AppState,
    provider_id: &str,
    key_ids_in_slot_order: &[String],
) -> Option<Vec<String>> {
    if key_ids_in_slot_order.len() < 2 {
        return None;
    }
    let alive = filter_cooled_down_keys(state, provider_id, key_ids_in_slot_order).await;
    if alive.is_empty() {
        return None;
    }
    let cursor = next_rotation_cursor(state, provider_id).await;
    let rotated: Vec<String> = (0..alive.len() as u64)
        .filter_map(|offset| rotate_with_cursor(&alive, cursor.wrapping_add(offset)))
        .collect();
    (!rotated.is_empty()).then_some(rotated)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn candidate(key_id: &str, in_flight: u64) -> RotationCandidate {
        RotationCandidate {
            key_id: key_id.to_string(),
            in_flight,
        }
    }

    #[test]
    fn picks_only_the_least_loaded_group() {
        let group = pick_min_inflight_group(&[
            candidate("key-c", 3),
            candidate("key-a", 1),
            candidate("key-b", 1),
        ]);
        assert_eq!(group, vec!["key-a".to_string(), "key-b".to_string()]);
    }

    #[test]
    fn group_is_sorted_regardless_of_input_order() {
        let forward = pick_min_inflight_group(&[
            candidate("key-a", 0),
            candidate("key-b", 0),
            candidate("key-c", 0),
        ]);
        let reversed = pick_min_inflight_group(&[
            candidate("key-c", 0),
            candidate("key-b", 0),
            candidate("key-a", 0),
        ]);
        assert_eq!(forward, reversed);
    }

    #[test]
    fn empty_candidates_yield_empty_group() {
        assert!(pick_min_inflight_group(&[]).is_empty());
        assert_eq!(rotate_with_cursor(&[], 3), None);
    }

    #[test]
    fn all_busy_picks_the_single_busiest_free_slot() {
        // 全部都忙时退化为选在途最少的那个
        let group = pick_min_inflight_group(&[
            candidate("key-a", 9),
            candidate("key-b", 2),
            candidate("key-c", 5),
        ]);
        assert_eq!(group, vec!["key-b".to_string()]);
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
}
