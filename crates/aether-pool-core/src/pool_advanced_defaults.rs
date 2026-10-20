//! `pool_advanced` 各旋钮的**默认值单一事实来源** ✓。
//!
//! 为什么单独一个模块（维护性审计 2026-10-17 ✗）：这批默认值此前散落在 4–5 处 ✗
//! —— 管理端解析函数、它的「非对象」兜底分支、调度运行时的**第二份**手写解析、
//! 测试夹具、以及前端对话框的 `??` 兜底。改一处忘一处就会出现
//! 「界面显示 A、运行时按 B」✗，而审计当天就抓到了**两次真实漂移** ✗：
//!
//! 1. 后端同一个函数的两条路径给出不同默认值（30/360/1800 vs 0/0/0）；
//! 2. 前端兜底值整体停留在旧口径（8/0/0/0/0 ✗），「打开对话框→保存」
//!    会把已对齐的默认值**静默写回旧值** ✗。
//!
//! 现在 ✓：后端所有落点都引用这里的常量；前端由
//! `frontend/src/features/pool/utils/__tests__/poolAdvancedDefaults.spec.ts`
//! **跨边界直接读本文件**核对 ✓，两边不一致时测试立刻红 ✓。
//!
//! ⚠️ 语义提醒 ✓：这些配置里的 **`0` 不是「未设置」** ✗ —— 对熔断三旋钮和
//! 在途上限而言 `0` 表示「沿用 Aether 历史值 / 不分档」，对成本探索表示「关停」。
//! 想恢复旧行为要**显式**写 `0`（见 `docs/operations/workbuddy-provider.md`）。

/// 连续失败多少次触发 key 级熔断（面板 `breaker_threshold`，面板口径 3）。
pub const BREAKER_THRESHOLD: u64 = 3;

/// 熔断**基础**探测间隔（分钟，面板 `breaker_cooldown`，面板口径 30 分钟）。
///
/// 显式 `0` = 回到 Aether 历史值 1 分钟（由 `orchestration/health.rs` 兜底）。
pub const BREAKER_COOLDOWN_MINUTES: u64 = 30;

/// 熔断指数退避**上限**（分钟，面板 `breaker_cooldown_max`，面板口径 6 小时）。
///
/// 显式 `0` = 回到 Aether 历史值 32 分钟；运行时另有 24h 硬天花板。
pub const BREAKER_COOLDOWN_MAX_MINUTES: u64 = 360;

/// costTier 条件探索窗口（秒，面板 `cost_explore_interval`，面板口径 30 分钟）。
///
/// 显式 `0` = 关停。
pub const COST_EXPLORE_INTERVAL_SECONDS: u64 = 1_800;

/// 单账号最大在途（并发，面板 `max_in_flight`）—— **所有域**的兜底档。
///
/// 显式 `0` = 不分档（回落账号自身的 `concurrent_limit`）。
pub const MAX_IN_FLIGHT: usize = 3;

/// 在途上限的**钳制上界**（审计 P1-2 ✗）：不改会把荒谬大数透给调度器，
/// 而 `i32::try_from` 失败会让生效上限**静默变成「不限」** ✗ —— 与配置意图相反 ✗。
pub const MAX_IN_FLIGHT_CAP: usize = 10_000;

/// WAF 出口 IP 拦截窗口（秒，面板同款 60；显式 `0` = 整项关停）。
pub const WAF_IP_COOLDOWN_SECONDS: u64 = 60;

/// WAF 拦截期是否**连新请求一起挡**（Aether 默认比面板严一档 ✓；
/// 设 `false` = 完全对齐面板，只停本次请求的轮转）。
pub const WAF_IP_BLOCK_NEW_REQUESTS: bool = true;

/// 池内账号是否**也计入** key 级熔断（面板口径：池就是全量账号 → `true`）。
pub const POOL_COUNTS_TOWARD_CIRCUIT_BREAKER: bool = true;

/// 积分保底（面板没有该功能 → `0` = 关闭）。
pub const CREDIT_FLOOR: i64 = 0;

#[cfg(test)]
mod tests {
    use super::*;

    /// 默认值必须落在「面板口径」上 ✓（用户 2026-10-16 确认「面板默认即默认」✓）。
    /// 这条钉子防的是「有人不小心把默认值改回 Aether 历史值」✗。
    ///
    /// `assertions_on_constants`：这里断言的就是**常量本身**（改动常量→测试红），
    /// clippy 看到 `const true` 会以为是死断言，故按断言目的显式放行。
    #[allow(clippy::assertions_on_constants)]
    #[test]
    fn defaults_are_panel_aligned() {
        assert_eq!(BREAKER_THRESHOLD, 3);
        assert_eq!(BREAKER_COOLDOWN_MINUTES, 30);
        assert_eq!(BREAKER_COOLDOWN_MAX_MINUTES, 360);
        assert_eq!(COST_EXPLORE_INTERVAL_SECONDS, 1_800);
        assert_eq!(MAX_IN_FLIGHT, 3);
        assert_eq!(WAF_IP_COOLDOWN_SECONDS, 60);
        assert!(WAF_IP_BLOCK_NEW_REQUESTS);
        assert!(POOL_COUNTS_TOWARD_CIRCUIT_BREAKER);
        assert_eq!(CREDIT_FLOOR, 0);
    }

    /// 内部一致性 ✓：退避上限不能低于基础时长（否则运行时会被 `.max(base)` 悄悄抬高 ✗），
    /// 国际域档不能高于兜底档，钳制上界要能容下所有档位 ✓。
    ///
    /// 同 `defaults_are_panel_aligned`：断言对象就是常量，按断言目的放行该 lint。
    #[allow(clippy::assertions_on_constants)]
    #[test]
    fn defaults_are_internally_consistent() {
        assert!(BREAKER_COOLDOWN_MAX_MINUTES >= BREAKER_COOLDOWN_MINUTES);
        assert!(MAX_IN_FLIGHT_CAP >= MAX_IN_FLIGHT);
        assert!(MAX_IN_FLIGHT_CAP > 0);
    }
}
