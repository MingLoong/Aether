//! AMD 供应商的 key 游标轮转。
//!
//! 与号池（`provider_key_pool`）互斥，也**不使用密钥熔断**：AMD 上游失败很常见，
//! 熔断会把「下次就能成功」的账号摘掉。这里只做一件事——记住上一次的位置，
//! 这次 +1；失败则在本次请求内换下一把（既有 failover 负责）。
//!
//! 与调度器内置排序的关系：调度器排出的顺序带负载均衡种子
//! （`load_balance_seed = current_unix_ms()`），每次请求都不一样，所以「上次的位置」
//! 在上面没有意义。本模块因此自带一个**与请求无关的稳定环**（[`key_ring_order`]），
//! 由 planner 的排序后置钩子按游标把环上的成员写回候选槽位。
//!
//! 注意 planner 的**已解析页缓存**：它的键里不含游标值，命中就会把轮转结果冻住，
//! 所以含 AMD 候选的页不进那层缓存（见 `candidate_materialization.rs` 的
//! `page_contains_amd_candidates`）。
//!
//! Redis 键（走 `RuntimeState` 的 kv 原语，自动带实例命名空间）：
//!
//! ```text
//! amd_key_cursor:<provider_id>   轮转游标，带 TTL
//! ```
//!
//! 判据只认 `provider_type == "amd"`，不认 base_url：旧的「custom + `/radeon/api/`」
//! 供应商保持原行为（要覆盖那批只需改 [`is_amd_provider_type`] 一个函数）。

use crate::AppState;

/// 游标存活时间：跨过一次网关重启即可，过期后从 0 重新开始。
const AMD_KEY_CURSOR_TTL_SECONDS: u64 = 24 * 60 * 60;

fn cursor_key(provider_id: &str) -> String {
    format!("amd_key_cursor:{provider_id}")
}

/// 是否是 AMD 供应商（本轮改造的唯一判据）。
///
/// 类型常量复用 `amd_load` 里的定义，不写字面量：provider 类型字符串散落各处时
/// 很容易漏改，架构守卫也会拦这类写法。
pub(crate) fn is_amd_provider_type(provider_type: &str) -> bool {
    provider_type
        .trim()
        .eq_ignore_ascii_case(crate::amd_load::poller::AMD_PROVIDER_TYPE)
}

/// 不按单把 key 记健康/开熔断的供应商类型。
///
/// 与 [`is_amd_provider_type`] 刻意分开，因为这是**两件事**：
///
/// - AMD 的密钥环、负载面板、轮转游标是 AMD 专属能力，判据仍是 [`is_amd_provider_type`]；
/// - 「不按单把 key 记健康、不开熔断」是**一类上游的共性**：这些上游的失败
///   是账号级/订阅级的，错记到单把 key 身上只会把可用凭据逐个熔断掉。
///   - `amd`：失败按账号轮换处理（见本模块的密钥环）。
///   - `cline`：官方上游的 401/403/402 是订阅与额度问题——实测免费凭据打
///     `cline-pass/*` 得到 403 `ENTITLEMENT_ERROR`，与某一把 key 的健康无关。
///
/// 号池豁免见 [`provider_type_exempt_from_generic_pool`]：cline 已恢复号池，
/// 只是走自己独立的调度逻辑，所以「健康豁免」与「号池豁免」不再是同一份名单。
///
/// 类型字符串取常量不写字面量（架构守卫会拦散落的字面量）。
pub(crate) fn provider_type_exempt_from_key_health(provider_type: &str) -> bool {
    let normalized = provider_type.trim();
    is_amd_provider_type(normalized)
        || normalized.eq_ignore_ascii_case(aether_provider_transport::cline::PROVIDER_TYPE)
}

/// 不接入**通用号池调度**的供应商类型（目前只有 `amd`）。
///
/// cline 已恢复号池：它的凭据进池，但调度走 [`crate::cline_pool`] 的独立逻辑
/// （反应式冷却 + round_robin/fill/random/least-used），不复用通用号池的评分/探测。
/// 因此这里不再包含 cline。
pub(crate) fn provider_type_exempt_from_generic_pool(provider_type: &str) -> bool {
    is_amd_provider_type(provider_type.trim())
}

/// 推进游标，返回**本次选择**的序号（首次为 0，之后 1、2、…）。
///
/// 实现：`RuntimeState` 没有 INCR 原语，只能 `GETDEL` 取旧值再 `SETEX` 写回——
/// **这不是严格原子的三步**。
/// 并发同时发起（或刚好跨 TTL 过期）时可能跳号，也可能两个请求读到同一个旧值而落到
/// 同一个位置：顺序是近似的，不会卡死，但不要把它当成严格互斥的轮转。
pub(crate) async fn next_amd_key_cursor(state: &AppState, provider_id: &str) -> u64 {
    let key = cursor_key(provider_id);
    let taken = state.runtime_kv_getdel(&key).await.ok().flatten();
    let next = match taken
        .as_deref()
        .map(str::trim)
        .and_then(|raw| raw.parse::<u64>().ok())
    {
        Some(previous) => previous.wrapping_add(1),
        // 首次调用返回 0（而不是 1）：槽位分配直接用 `cursor % n` 当起点，
        // 这样第一把命中的就是环上的第一个，不需要额外减一。
        None => 0,
    };
    let _ = state
        .runtime_kv_setex(&key, &next.to_string(), AMD_KEY_CURSOR_TTL_SECONDS)
        .await;
    next
}

/// 轮转环里的一个成员：决定「环上第几个是谁」。
///
/// 环必须与请求无关地稳定，否则「记住上次的位置」不可观测。排序键是**该格式的全局
/// 优先级**（`global_priority_by_format`，未配置排最后）→ 密钥内部优先级 → key_id。
///
/// 注意它**不等于面板里密钥列表的顺序**：面板按 `internal_priority` 排，所以某把 key
/// 配了按格式的全局优先级时两者会不同；同一 provider 的不同 api_format 也可能得到不同的环。
/// 这里刻意让全局优先级优先——它才是用户为该格式表达过的次序。
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct AmdKeyRingEntry {
    pub(crate) key_id: String,
    pub(crate) global_priority: Option<i32>,
    pub(crate) internal_priority: i32,
}

fn compare_ring_entries(left: &AmdKeyRingEntry, right: &AmdKeyRingEntry) -> std::cmp::Ordering {
    left.global_priority
        .unwrap_or(i32::MAX)
        .cmp(&right.global_priority.unwrap_or(i32::MAX))
        .then(left.internal_priority.cmp(&right.internal_priority))
        .then(left.key_id.cmp(&right.key_id))
}

/// 环顺序，返回**组内下标**：`entries[i]` 对应组内第 i 个候选。
///
/// 重复的 `key_id` 原样保留各自的槽位：槽位数量必须与候选数量一一对应，
/// 去重会让「换槽位里的人」少一个位置。
pub(crate) fn ring_order_indices(entries: &[AmdKeyRingEntry]) -> Vec<usize> {
    let mut indices: Vec<usize> = (0..entries.len()).collect();
    indices.sort_by(|left, right| compare_ring_entries(&entries[*left], &entries[*right]));
    indices
}

/// 环顺序，返回 `key_id` 序列。展示与断言用；选点走 [`ring_order_indices`]。
pub(crate) fn key_ring_order(entries: &[AmdKeyRingEntry]) -> Vec<String> {
    ring_order_indices(entries)
        .into_iter()
        .map(|index| entries[index].key_id.clone())
        .collect()
}

/// 槽位分配：第 i 个槽位放环上的第 `(i + cursor) % n` 个成员。
///
/// 返回的是「环下标」序列，长度恒等于 `slot_count`。`slot_count == 0` 返回空；
/// 调用方保证 `slot_count == 环长度`。
pub(crate) fn slot_ring_indices(slot_count: usize, cursor: u64) -> Vec<usize> {
    if slot_count == 0 {
        return Vec::new();
    }
    let len = slot_count as u64;
    let offset = cursor % len;
    (0..slot_count)
        .map(|index| ((index as u64 + offset) % len) as usize)
        .collect()
}

#[cfg(test)]
mod tests {
    use super::{
        cursor_key, is_amd_provider_type, key_ring_order, slot_ring_indices, AmdKeyRingEntry,
    };

    #[test]
    fn recognises_amd_provider_type_only() {
        assert!(is_amd_provider_type("amd"));
        assert!(is_amd_provider_type(" AMD "));
        assert!(is_amd_provider_type("Amd"));
        assert!(!is_amd_provider_type("custom"));
        assert!(!is_amd_provider_type("opencode"));
        assert!(!is_amd_provider_type(""));
    }

    #[test]
    fn cursor_key_is_namespaced_per_provider() {
        assert_eq!(cursor_key("abc"), "amd_key_cursor:abc");
        assert_ne!(cursor_key("a"), cursor_key("b"));
    }

    #[test]
    fn ring_order_follows_configured_key_order() {
        let entries = vec![
            AmdKeyRingEntry {
                key_id: "c".to_string(),
                global_priority: Some(3),
                internal_priority: 0,
            },
            AmdKeyRingEntry {
                key_id: "a".to_string(),
                global_priority: Some(1),
                internal_priority: 5,
            },
            // 未配置全局优先级：排最后，而不是当成 0 插到最前面。
            AmdKeyRingEntry {
                key_id: "b".to_string(),
                global_priority: None,
                internal_priority: 0,
            },
        ];

        assert_eq!(key_ring_order(&entries), vec!["a", "c", "b"]);
    }

    #[test]
    fn ring_order_keeps_duplicate_slots() {
        let entries = vec![
            AmdKeyRingEntry {
                key_id: "a".to_string(),
                global_priority: Some(1),
                internal_priority: 0,
            },
            AmdKeyRingEntry {
                key_id: "a".to_string(),
                global_priority: Some(1),
                internal_priority: 0,
            },
        ];

        assert_eq!(key_ring_order(&entries), vec!["a", "a"]);
    }

    #[test]
    fn slot_assignment_starts_at_the_ring_head_on_first_selection() {
        assert_eq!(slot_ring_indices(3, 0), vec![0, 1, 2]);
        assert_eq!(slot_ring_indices(3, 1), vec![1, 2, 0]);
        assert_eq!(slot_ring_indices(3, 2), vec![2, 0, 1]);
        // 回绕：每次请求 +1，位置始终落在环内。
        assert_eq!(slot_ring_indices(3, 3), vec![0, 1, 2]);
        assert_eq!(slot_ring_indices(3, 4), vec![1, 2, 0]);
    }

    #[test]
    fn slot_assignment_handles_empty_and_single_slot_groups() {
        assert!(slot_ring_indices(0, 7).is_empty());
        // 单槽位组：轮转没有意义，但分配仍然自洽（永远只有自己）。
        assert_eq!(slot_ring_indices(1, 7), vec![0]);
    }
}
