//! costTier 条件探索（面板 issue #136 方案 a′ 的等价物）。
//!
//! 面板口径（`internal/pool/pick.go:128-138` + `pool.go:28-39`）：
//! - 当**当前最优**账号是 **tier 0（已观测到免费）**、且存在 **tier 1（无观测）** 账号、
//!   且该账号距上次探索已超过 `cost_explore_interval`（默认 **30m**，`0` = 关停）时，
//!   就**改选这个未观测账号**——即「在免费层垄断时，定期搭一次车去探路」，
//!   避免免费号永久压住未知号（免费层垄断 → 永远不去验证别的号是否可用/是否更便宜）。
//!
//! tier 判据与面板的**本地成本台账**同源（Aether 用 key 上的累计用量）：
//! - `total_tokens == 0` → **tier 1**（从未观测）；
//! - 观测过且 `total_cost_usd <= 0` → **tier 0**（实测免费）；
//! - 观测过且 `total_cost_usd > 0` → **tier 2**（实测收费）。

/// 观测成本档（面板 `costTier`）。
pub const POOL_COST_TIER_FREE_OBSERVED: u8 = 0;
/// 无观测（面板 `costTier == 1`）。
pub const POOL_COST_TIER_UNOBSERVED: u8 = 1;
/// 实测收费（面板 `costTier == 2`）。
pub const POOL_COST_TIER_PAID_OBSERVED: u8 = 2;

/// 由账号累计用量判断成本档。
pub fn pool_member_cost_tier(total_tokens: u64, total_cost_usd: f64) -> u8 {
    if total_tokens == 0 {
        return POOL_COST_TIER_UNOBSERVED;
    }
    if total_cost_usd > 0.0 {
        POOL_COST_TIER_PAID_OBSERVED
    } else {
        POOL_COST_TIER_FREE_OBSERVED
    }
}

/// 条件探索决策：返回**要提到队首的候选下标**（没有则 `None`）。
///
/// 参数按候选的**既有排名顺序**给出：
/// - `tiers_in_order`：每个候选的成本档（见 [`pool_member_cost_tier`]）；
/// - `explore_due_in_order`：该候选是否已过探索窗口（调用方按账号维度的
///   「上次探索时间 + 间隔」判断；`true` 表示这次可以拿它去探路）。
///
/// 规则（逐条对齐面板）：
/// 1. `cost_explore_enabled == false`（间隔 <= 0）→ 不干预；
/// 2. 队首不是 **tier 0** → 不干预（只有「免费层垄断」才需要打破）；
/// 3. 取**排名最靠前**的、同时满足「tier 1 且已过窗口」的候选；
/// 4. 若该候选本来就在队首（队首自己就是 tier 1）→ 返回 `None`（无事可做）。
pub fn pool_cost_explore_promote_index(
    cost_explore_enabled: bool,
    tiers_in_order: &[u8],
    explore_due_in_order: &[bool],
) -> Option<usize> {
    if !cost_explore_enabled {
        return None;
    }
    let best_tier = *tiers_in_order.first()?;
    if best_tier != POOL_COST_TIER_FREE_OBSERVED {
        return None;
    }
    let index = tiers_in_order
        .iter()
        .enumerate()
        .position(|(index, tier)| {
            *tier == POOL_COST_TIER_UNOBSERVED
                && explore_due_in_order.get(index).copied().unwrap_or(false)
        })?;
    if index == 0 {
        return None;
    }
    Some(index)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn cost_tier_uses_tokens_then_cost() {
        assert_eq!(pool_member_cost_tier(0, 0.0), POOL_COST_TIER_UNOBSERVED);
        assert_eq!(pool_member_cost_tier(0, 1.0), POOL_COST_TIER_UNOBSERVED);
        assert_eq!(
            pool_member_cost_tier(100, 0.0),
            POOL_COST_TIER_FREE_OBSERVED
        );
        assert_eq!(
            pool_member_cost_tier(100, 0.02),
            POOL_COST_TIER_PAID_OBSERVED
        );
    }

    #[test]
    fn explore_only_breaks_free_observed_monopoly() {
        // 关停 → 不干预
        assert_eq!(
            pool_cost_explore_promote_index(false, &[0, 1], &[false, true]),
            None
        );
        // 队首已经是「未观测/收费」→ 不需要打破垄断
        assert_eq!(
            pool_cost_explore_promote_index(true, &[1, 0], &[true, false]),
            None
        );
        assert_eq!(
            pool_cost_explore_promote_index(true, &[2, 1], &[false, true]),
            None
        );
        // 免费层垄断 + 后面有到窗口的未观测号 → 提它到队首
        assert_eq!(
            pool_cost_explore_promote_index(true, &[0, 1, 2], &[false, true, false]),
            Some(1)
        );
        assert_eq!(
            pool_cost_explore_promote_index(true, &[0, 2, 1], &[false, false, true]),
            Some(2)
        );
        // 有未观测号但**还没到窗口** → 不干预
        assert_eq!(
            pool_cost_explore_promote_index(true, &[0, 1], &[false, false]),
            None
        );
        // 没有未观测号 → 不干预
        assert_eq!(
            pool_cost_explore_promote_index(true, &[0, 0, 2], &[true, true, true]),
            None
        );
        // 空列表 → 不干预
        assert_eq!(pool_cost_explore_promote_index(true, &[], &[]), None);
    }
}
