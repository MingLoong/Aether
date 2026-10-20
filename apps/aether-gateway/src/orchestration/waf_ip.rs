//! WAF 出口 IP 级拦截 fail-fast 状态机（面板 `internal/server/wafip.go` 的等价物）。
//!
//! 背景（面板实测 `BulidH`：3 个账号 1 秒内全 403）：WAF 403 拦的是**网关出口 IP**，
//! 不是某个账号。账号级软冷却（本仓已有：`WafBlock` → 只冷却、不标授权失效 ✓）在 IP 级
//! 拦截时不够——**继续换号只会把一次客户端请求放大成 MaxRotate 倍**，打同一个出口 IP
//! 只会加重风控 ✓。
//!
//! 判定：`WafBlock`（403 且**无业务信封** ✓）基础上的**短窗多号计数** ——
//! `WAF_IP_WINDOW_SECONDS` 滑动窗内 ≥ `WAF_IP_THRESHOLD` 个**不同账号**接连命中 →
//! 判定 IP 级拦截，激活到 `now + WAF_IP_WINDOW_SECONDS` ✓。
//!
//! 纪律（逐条对齐面板）：
//! - **只数不同账号** ✓：单号反复 403（账号级偶发）**永不触发** ✓；
//! - 激活期内新命中**不续期**（保守：不做主动探测，窗口自然解除 ✓）；
//! - 激活时**清空判定窗**（解除后需全新命中重新判定，不叠旧账 ✓）；
//! - 进程内状态、重启清零 ✓（窗口只有 60s，重建成本极低 ✓）。

use std::collections::BTreeMap;
use std::sync::Mutex;

/// 判定滑动窗 + 激活时长（秒）。
pub(crate) const WAF_IP_WINDOW_SECONDS: u64 = 60;
/// 判定阈值：窗内**不同账号**数达到该值即激活。
///
/// 取 2 —— 「多号」的最小定义：单号反复 403 永不触发（归账号级软冷却管 ✓），
/// 两个不同号在 60s 内接连被拦（同一出口 IP）已是 IP 级证据 ✓（面板同值 ✓）。
pub(crate) const WAF_IP_THRESHOLD: usize = 2;

/// 出口 IP 级 WAF 拦截状态机（纯状态，零值可用；调用方自行加锁）。
#[derive(Debug, Default)]
pub(crate) struct WafIpGate {
    /// account_id → 最近一次 WAF 403 时刻（判定窗内，惰性剪枝）。
    hits: BTreeMap<String, u64>,
    /// 激活截止时刻；0 = 未激活。
    until: u64,
}

impl WafIpGate {
    /// 记一次某账号的 WAF 403，返回**记账后** IP 级拦截是否激活
    /// （调用方据此 **fail-fast 终止轮转** ✓，优先于普通退避 ✓）。
    pub(crate) fn note_waf(&mut self, account_id: &str, now_unix_secs: u64) -> bool {
        if now_unix_secs < self.until {
            // 激活期内新命中：不续期、不记账（窗口期内不重置 —— 保守自然解除 ✓）。
            return true;
        }
        self.until = 0;
        self.hits.insert(account_id.to_string(), now_unix_secs);
        self.hits
            .retain(|_, hit_at| now_unix_secs.saturating_sub(*hit_at) <= WAF_IP_WINDOW_SECONDS);
        if self.hits.len() >= WAF_IP_THRESHOLD {
            self.until = now_unix_secs.saturating_add(WAF_IP_WINDOW_SECONDS);
            // 清空判定窗：解除后需全新命中重新判定，不叠旧账 ✓。
            self.hits.clear();
            return true;
        }
        false
    }

    /// 报告 IP 级拦截当前是否激活（末端错误文案区分 IP 级/账号级措辞用 ✓）。
    pub(crate) fn is_active(&self, now_unix_secs: u64) -> bool {
        now_unix_secs < self.until
    }
}

/// 进程级闸门（重启清零 ✓，窗口 60s 重建成本极低 ✓）。
fn waf_ip_gate() -> &'static Mutex<WafIpGate> {
    static GATE: std::sync::OnceLock<Mutex<WafIpGate>> = std::sync::OnceLock::new();
    GATE.get_or_init(|| Mutex::new(WafIpGate::default()))
}

/// 记账入口：返回 `true` = IP 级拦截已激活 → 调用方应**立即停止轮转** ✓。
pub(crate) fn note_waf_block(account_id: &str, now_unix_secs: u64) -> bool {
    match waf_ip_gate().lock() {
        Ok(mut gate) => gate.note_waf(account_id, now_unix_secs),
        // 锁中毒（前一次持锁 panic）：按「未激活」处理，绝不因此中断正常请求 ✓。
        Err(_) => false,
    }
}

/// 当前是否处于 IP 级拦截激活期 ✓。
pub(crate) fn waf_ip_block_active(now_unix_secs: u64) -> bool {
    match waf_ip_gate().lock() {
        Ok(gate) => gate.is_active(now_unix_secs),
        Err(_) => false,
    }
}

/// 从一次**失败效果**里判定并记账 WorkBuddy 的出口 IP 级 WAF 拦截 ✓。
///
/// 维护性审计 ③（2026-10-17 ✗）：这段判定原本内联在 `orchestration/effects.rs` 的
/// `record_pool_error_effect` 里（约 23 行，插在一个上游热点函数中间 ✗）——
/// 判定与记账本来就属于本模块 ✓，搬进来后 `effects.rs` 只剩一行调用 ✓，上游冲突面更小 ✓。
///
/// 只对 **WorkBuddy 计划**生效 ✓（靠出站内部标记头认出 provider ✓），
/// 且仅当失败分类是 [`WorkbuddyFailureKind::WafBlock`]（403 且**无业务信封** ✓）。
///
/// 返回 `true` = 记账后 IP 级拦截已激活（调用方据此 fail-fast ✓；当前调用方只记账 ✓）。
pub(crate) fn note_workbuddy_waf_block_from_failure(
    plan: &aether_contracts::ExecutionPlan,
    status_code: u16,
    error_body: Option<&str>,
) -> bool {
    if !aether_provider_transport::workbuddy::has_workbuddy_internal_header_map(&plan.headers) {
        return false;
    }
    use aether_provider_transport::workbuddy::failure::{
        classify_workbuddy_failure, WorkbuddyFailureKind,
    };
    if !matches!(
        classify_workbuddy_failure(status_code, error_body),
        WorkbuddyFailureKind::WafBlock
    ) {
        return false;
    }
    let now_unix_secs = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|elapsed| elapsed.as_secs())
        .unwrap_or(0);
    note_waf_block(plan.key_id.as_str(), now_unix_secs)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn single_account_repeated_blocks_never_activate() {
        let mut gate = WafIpGate::default();
        // 同一个号反复 403（账号级偶发）→ 永远不激活 ✓
        for step in 0..10 {
            assert!(!gate.note_waf("acct-a", 1_000 + step));
        }
        assert!(!gate.is_active(1_010));
    }

    #[test]
    fn two_distinct_accounts_within_window_activate_ip_level_block() {
        let mut gate = WafIpGate::default();
        assert!(!gate.note_waf("acct-a", 1_000));
        // 窗口内第二个不同号 → 激活
        assert!(gate.note_waf("acct-b", 1_030));
        assert!(gate.is_active(1_030));
        assert!(gate.is_active(1_089));
        // 到期自然解除（不续期）
        assert!(!gate.is_active(1_090));
    }

    #[test]
    fn hits_outside_the_window_are_pruned() {
        let mut gate = WafIpGate::default();
        assert!(!gate.note_waf("acct-a", 1_000));
        // 61s 后第二个号：第一个已滑出窗口 → 不激活
        assert!(!gate.note_waf("acct-b", 1_061));
        assert!(!gate.is_active(1_061));
        // 再一个不同号（与 acct-b 同窗）→ 激活
        assert!(gate.note_waf("acct-c", 1_070));
    }

    #[test]
    fn active_window_does_not_renew_and_clears_its_window() {
        let mut gate = WafIpGate::default();
        assert!(!gate.note_waf("acct-a", 2_000));
        assert!(gate.note_waf("acct-b", 2_010));
        // 激活期内新命中：仍报激活，但**不续期** ✓
        assert!(gate.note_waf("acct-c", 2_050));
        assert!(gate.note_waf("acct-d", 2_060));
        assert!(!gate.is_active(2_070));
        // 激活时已清窗：解除后必须**重新凑齐两个不同号**才再次激活 ✓
        assert!(!gate.note_waf("acct-e", 2_100));
        assert!(gate.note_waf("acct-f", 2_110));
    }

    #[test]
    fn repeated_hits_from_one_account_do_not_fill_the_threshold() {
        let mut gate = WafIpGate::default();
        // 同一个号在窗内连打多次：只算 1 个不同号 → 不激活 ✓
        for step in 0..5 {
            assert!(!gate.note_waf("acct-a", 3_000 + step));
        }
        assert!(!gate.is_active(3_005));
    }
}
