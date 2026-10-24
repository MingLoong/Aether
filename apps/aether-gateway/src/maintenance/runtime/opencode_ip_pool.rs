//! OpenCode 前置代理出口 IP 池的手动巡检。
//!
//! 由管理台面板上的「巡检」按钮触发（`POST .../pool/maintenance`），**一次调用 =
//! 一轮探针**：对 `exit_pool` 做 TLS + `GET /` 探测，Healthy 清计数、403/429 不剔除、
//! Unreachable 累计到阈值才剔除；失败率超过熔断比例时整轮不做批量剔除。
//!
//! 这里**没有**定时循环，所以也没有「多久跑一轮」「上次跑过没有」这类配置：手动触发
//! 天然有界（点一次跑一次），间隔与上次时间戳都只会变成面板上没人看的历史遗留。
//!
//! **不发 chat / inference**：这条路径是零额度的。真实 chat 探测只在用户点击
//! 面板上的「验证健康」按钮时发生（一次点击 = 一个请求）。
//!
//! 实际逻辑复用 `opencode_pool::pool`，与手动接口同一套实现。

// 领域层在 crate::opencode_pool，不在管理台下面：巡检是后台组件，不是 HTTP 接口的
// 附属品，从 handlers::admin 取它的类型会撞上上游的架构守卫
// （admin_external_usage_is_confined_to_admin_api）。
use crate::opencode_pool::{
    opencode_upstream_target, probe_target_is_official, probe_upstream_ip_maintenance,
    write_pool_state_pair, MaintenanceProbeResult, OpenCodeHealthConfig, OpenCodeScanConfig,
};
use crate::{AppState, GatewayError};

/// 单个 IP 的维护探测超时。
///
/// 5 秒而不是 10 秒：实测池里约六成 IP 是「连得上 TCP、TLS 之后没有响应」，
/// 每个都要耗满超时。1086 个 IP、并发 32，5 秒能给一轮定出约 3 分钟的上界；
/// 10 秒则翻倍，一次手动巡检就要等六分钟以上。
const MAINTENANCE_PROBE_TIMEOUT_SECS: u64 = 5;

/// 一轮手动巡检的统计，直接回给面板。
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub(crate) struct OpenCodeIpPoolMaintenanceSummary {
    /// 实际探测到的 IP 数（熔断或池空时为 0）。
    pub(crate) checked: usize,
    /// 其中判为不可达的数量。
    pub(crate) unreachable: usize,
    /// 本轮从池里剔除的数量。
    pub(crate) evicted: usize,
    /// 跑完后异常池的条目数。
    pub(crate) abnormal_total: usize,
    /// 整轮耗时（毫秒），面板用它解释「为什么按钮转了这么久」。
    pub(crate) elapsed_ms: u64,
}

/// 一轮探测的内部产出。
#[derive(Debug, Default)]
struct MaintenanceRound {
    checked: usize,
    unreachable: usize,
    evicted: Vec<String>,
    abnormal_total: usize,
}

/// 一轮维护要不要熔断（即放弃本轮的批量剔除）。
///
/// 抽成独立函数是为了能被测试。上一版把判据写成
/// `failure_pct > threshold || unreachable*2 > checked`，后半截把阈值架空成
/// 50%，不可测所以一直没被发现——生产池 61% 不可达时永远熔断，死节点清不掉。
fn should_open_circuit(checked: usize, unreachable: usize, threshold_percent: usize) -> bool {
    if checked == 0 {
        return false;
    }
    unreachable.saturating_mul(100) / checked > threshold_percent
}

/// 巡检当前 exit_pool：低额度响应（403/429）不视为不可达，只有连续失败达到
/// 阈值才剔除；失败率超过熔断比例时整轮不做批量剔除。
async fn maintain_exit_pool(
    app: &AppState,
    provider: &aether_data_contracts::repository::provider_catalog::StoredProviderCatalogProvider,
    scan: &OpenCodeScanConfig,
    health: &OpenCodeHealthConfig,
) -> Result<MaintenanceRound, GatewayError> {
    let round = MaintenanceRound {
        abnormal_total: health.abnormal.len(),
        ..MaintenanceRound::default()
    };
    if scan.exit_pool.is_empty() {
        return Ok(round);
    }
    let (domain, port) = opencode_upstream_target(app, &provider.id, scan).await?;
    if probe_target_is_official(&domain) {
        return Ok(round);
    }
    let concurrency = scan.maintenance_concurrency();
    let semaphore = std::sync::Arc::new(tokio::sync::Semaphore::new(concurrency));
    let mut tasks = Vec::new();
    for ip in scan.exit_pool.iter().cloned() {
        let semaphore = semaphore.clone();
        let domain = domain.clone();
        tasks.push(tokio::spawn(async move {
            let _permit = semaphore.acquire().await.ok();
            let result =
                probe_upstream_ip_maintenance(&ip, &domain, port, MAINTENANCE_PROBE_TIMEOUT_SECS)
                    .await
                    .unwrap_or(MaintenanceProbeResult::Unreachable);
            (ip, result)
        }));
    }
    let mut outcomes = Vec::new();
    for task in tasks {
        if let Ok(value) = task.await {
            outcomes.push(value);
        }
    }
    let checked = outcomes.len();
    if checked == 0 {
        return Ok(round);
    }
    let unreachable = outcomes
        .iter()
        .filter(|(_, result)| *result == MaintenanceProbeResult::Unreachable)
        .count();
    let failure_pct = unreachable.saturating_mul(100) / checked;
    let evict_limit = scan.maintenance_evict_failures();
    let threshold = scan.maintenance_failure_threshold_percent() as usize;
    // 熔断只用来挡「系统性故障」——探针自己坏了、域名配错、整网不通。
    // 它**不是**用来挡「池子本来就烂」的：2026-10-23 实测生产池 1086 个 IP
    // 里只有 22% 真的服务这个域名，60% 直接超时。当时这里还挂着一条写死的
    // `unreachable*2 > checked`（即 50%），把可配阈值架空了，于是永远熔断、
    // 死节点永远清不掉。现在只认配置值，默认 90%。
    if should_open_circuit(checked, unreachable, threshold) {
        tracing::warn!(event_name="opencode_ip_pool_maintenance_circuit_open", provider_id=%provider.id, checked, unreachable, failure_pct, threshold, "maintenance circuit opened; no bulk eviction");
        return Ok(MaintenanceRound {
            checked,
            unreachable,
            ..round
        });
    }
    let mut next_health = health.clone();
    let mut evict = Vec::new();
    for (ip, result) in outcomes {
        match result {
            MaintenanceProbeResult::Healthy | MaintenanceProbeResult::QuotaLimited => {
                if result == MaintenanceProbeResult::Healthy {
                    next_health.clear_abnormal(&ip);
                }
            }
            MaintenanceProbeResult::Unreachable => {
                let fails = next_health.record_abnormal(
                    &ip,
                    "unreachable",
                    None,
                    &chrono::Utc::now().to_rfc3339(),
                );
                if fails >= evict_limit && next_health.healthy.len() > health.protect_pool_floor() {
                    evict.push(ip);
                }
            }
        }
    }
    if !evict.is_empty() {
        write_pool_state_pair(app, &provider.id, &next_health, &evict).await?;
    } else if next_health != *health {
        crate::opencode_pool::write_health_config(app, provider, &next_health).await?;
    }
    Ok(MaintenanceRound {
        checked,
        unreachable,
        evicted: evict,
        abnormal_total: next_health.abnormal.len(),
    })
}

/// 对一个供应商跑一轮巡检。由面板按钮触发，不挂任何定时器。
///
/// 只是把 [`maintain_exit_pool`] 包一层统计：面板要知道「探了几个、几个不通、
/// 剔了几个、异常池现在多少条」，否则点完按钮只能靠翻日志猜到底发生了什么。
pub(crate) async fn run_opencode_ip_pool_maintenance_once(
    app: &AppState,
    provider: &aether_data_contracts::repository::provider_catalog::StoredProviderCatalogProvider,
) -> Result<OpenCodeIpPoolMaintenanceSummary, GatewayError> {
    let started_at = std::time::Instant::now();
    let scan = OpenCodeScanConfig::from_provider_config(&provider.config);
    let health = OpenCodeHealthConfig::from_provider_config(&provider.config);
    let round = maintain_exit_pool(app, provider, &scan, &health).await?;
    Ok(OpenCodeIpPoolMaintenanceSummary {
        checked: round.checked,
        unreachable: round.unreachable,
        evicted: round.evicted.len(),
        abnormal_total: round.abnormal_total,
        elapsed_ms: started_at.elapsed().as_millis() as u64,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    /// 熔断只认配置阈值，不允许再有写死的下限把它架空。
    ///
    /// 回归的是 2026-10-23 的真事故：生产池 1086 个 IP 中 667 个不可达（61%），
    /// 阈值已被调到 90%，却因为多了一条写死的 `unreachable*2 > checked`（50%）
    /// 而永远熔断，死节点一个都清不掉。
    #[test]
    fn circuit_opens_only_above_the_configured_threshold() {
        // 61% 不可达 + 阈值 90 → 不熔断，正常进入剔除流程
        assert!(!should_open_circuit(1086, 667, 90));
        // 90% 恰好等于阈值不算超过，仍要允许清理
        assert!(!should_open_circuit(100, 90, 90));
        // 91% 超过阈值 → 熔断
        assert!(should_open_circuit(100, 91, 90));
        // 全灭一定熔断（探针坏、域名配错的典型形态）
        assert!(should_open_circuit(902, 902, 90));
        // 老默认 25% 仍然有效，说明阈值本身没被写死
        assert!(should_open_circuit(100, 61, 25));
        assert!(!should_open_circuit(100, 0, 25));
        // 没探测任何 IP 时不该熔断（也没东西可剔）
        assert!(!should_open_circuit(0, 0, 25));
    }
}
