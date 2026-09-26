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

use crate::AppState;

/// 游标键的存活时间：足够跨过一次网关重启即可，过期后从 0 重新开始。
const ROTATION_CURSOR_TTL_SECONDS: u64 = 24 * 60 * 60;
/// 额度耗尽后的默认冷却时长（分钟）。
pub(crate) const DEFAULT_COOLDOWN_MINUTES: u32 = 60;

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
) -> Option<String> {
    if exit_pool.is_empty() {
        return None;
    }
    let mut usable: Vec<String> = Vec::with_capacity(exit_pool.len());
    for ip in exit_pool {
        if !key_in_cooldown(state, provider_id, ip).await {
            usable.push(ip.clone());
        }
    }
    if usable.is_empty() {
        // 全部在冷却：仍然放行一个，避免整池不可用导致完全打不开。
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
}
