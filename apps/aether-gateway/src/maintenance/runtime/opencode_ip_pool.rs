//! OpenCode 前置代理出口 IP 池的定时维护 worker。
//!
//! 每 5 分钟醒一次，遍历所有 `provider_type = opencode` 的供应商：
//!
//! 扫描（成本高，产出是新候选）：
//! - `auto_enabled = true` 且配了 CIDR 才考虑；
//! - `interval_hours = 0` 时视为「只允许手动扫描」；
//! - 距上次扫描未满间隔时跳过。
//!
//! 维护（成本为零）：
//! - 每 `maintenance_interval_seconds`（默认 600）对 `exit_pool` 做一轮
//!   TLS + `GET /` 探针：Healthy 清计数、403/429 不剔除、Unreachable 累计到阈值才剔除；
//! - 失败率超过熔断比例时整轮不做批量剔除。
//!
//! **不发 chat / inference**：这条路径是零额度的。真实 chat 探测只在用户点击
//! 面板上的「验证健康」按钮时发生（一次点击 = 一个请求）。
//!
//! 扫描与维护都在扫描正在进行时跳过，单个供应商失败只记日志。
//! 实际逻辑复用 `ip_pool::pool`，与手动接口同一套实现。

use std::time::{Duration, SystemTime, UNIX_EPOCH};

// 领域层在 crate::opencode_pool，不在管理台下面：worker 是后台组件，不是 HTTP 接口的
// 附属品，从 handlers::admin 取它的类型会撞上上游的架构守卫
// （admin_external_usage_is_confined_to_admin_api）。
use crate::opencode_pool::{
    opencode_ip_pool_status_for, opencode_upstream_target, probe_upstream_ip_maintenance,
    run_open_code_pool_scan, update_opencode_ip_pool_status, write_pool_state_pair,
    write_scan_config, MaintenanceProbeResult, OpenCodeHealthConfig, OpenCodeScanConfig,
};
use crate::{AppState, GatewayError};

/// worker 心跳间隔：只做「到点了吗」的判断，真正的间隔由配置决定。
const OPENCODE_IP_POOL_TICK: Duration = Duration::from_secs(30);
/// 启动后的首次静默期，避免网关刚起来就发起一轮探测。
const OPENCODE_IP_POOL_STARTUP_GRACE: Duration = Duration::from_secs(90);
/// 单个 IP 的维护探测超时。
///
/// 5 秒而不是 10 秒：实测池里约六成 IP 是「连得上 TCP、TLS 之后没有响应」，
/// 每个都要耗满超时。1086 个 IP、并发 32，5 秒能给一轮定出约 3 分钟的上界；
/// 10 秒则翻倍，容易撞上 600 秒的维护间隔。
const MAINTENANCE_PROBE_TIMEOUT_SECS: u64 = 5;

fn now_unix_secs() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|duration| duration.as_secs())
        .unwrap_or_default()
}

/// 判断某个供应商此刻是否该自动扫描。
///
/// 上次扫描时间取自**落盘**的 `opencode_scan.last_scan_at`，而不是进程内状态：
/// 内存时间在每次重启后清零，于是「重启即该扫」——2026-10-18 实测：部署重启后
/// 立刻起了一轮扫描，卡在无超时的 DNS 解析上，`scanning` 永久 true，把整条
/// 扫描/复验链路堵成 400。
fn autoscan_due(config: &OpenCodeScanConfig) -> bool {
    if !config.autoscan_effective() || config.cidrs.is_empty() {
        return false;
    }
    let last = config
        .last_scan_at
        .as_deref()
        .and_then(parse_rfc3339_unix_secs);
    interval_elapsed(config.interval_hours.unwrap_or(0), last)
}
/// 间隔是否已过。`interval_hours = 0` 表示「即使开启也不自动执行」，
/// 与两个 `*_effective()` 的语义一致。
fn interval_elapsed_seconds(interval_seconds: u64, last_unix_secs: Option<u64>) -> bool {
    match last_unix_secs {
        None => true,
        Some(last) => now_unix_secs().saturating_sub(last) >= interval_seconds,
    }
}

fn interval_elapsed(interval_hours: u32, last_unix_secs: Option<u64>) -> bool {
    if interval_hours == 0 {
        return false;
    }
    let interval_secs = u64::from(interval_hours) * 3600;
    match last_unix_secs {
        // 从未执行过：立刻跑一轮。
        None => true,
        Some(last) => now_unix_secs().saturating_sub(last) >= interval_secs,
    }
}

/// 解析落盘时间戳（RFC3339）为 Unix 秒。解析失败按「从未执行过」，
/// 即宁可多跑一轮，也不要因为一个时间戳格式问题让维护永久停摆。
fn parse_rfc3339_unix_secs(value: &str) -> Option<u64> {
    chrono::DateTime::parse_from_rfc3339(value.trim())
        .ok()
        .and_then(|parsed| u64::try_from(parsed.timestamp()).ok())
}

pub(crate) fn spawn_opencode_ip_pool_worker(app: AppState) -> Option<tokio::task::JoinHandle<()>> {
    if !app.has_provider_catalog_data_reader() || !app.has_provider_catalog_data_writer() {
        return None;
    }

    Some(crate::task_runtime::spawn_singleton_worker(
        app,
        crate::task_runtime::TASK_KEY_OPENCODE_IP_POOL_AUTOSCAN,
        |app| async move {
            tokio::time::sleep(OPENCODE_IP_POOL_STARTUP_GRACE).await;
            let mut interval = tokio::time::interval(OPENCODE_IP_POOL_TICK);
            interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
            interval.tick().await;
            loop {
                interval.tick().await;
                if let Err(err) = run_opencode_ip_pool_maintenance_once(&app).await {
                    tracing::warn!(
                        event_name = "opencode_ip_pool_maintenance_failed",
                        log_type = "ops",
                        error = %err.into_message(),
                        "opencode ip pool maintenance tick failed"
                    );
                }
            }
        },
    ))
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

/// 一轮维护要不要触发补池。
///
/// 维护只负责剔除，补池是另一半：没有它池子会单调缩水到 0，之后所有请求退回
/// 系统 DNS 的单条路径，按 /24 分散完全失效。判据刻意只用「跌破保底线」——
/// 池子够用时不必去扫（扫描要打几千个目标，纯属浪费）。
fn should_auto_refill(enabled: bool, effective_len: usize, min_pool_size: usize) -> bool {
    enabled && effective_len < min_pool_size.max(1)
}

/// 定期扫描是否到期。间隔 0 表示关闭。
///
/// `now_unix_secs` 显式传入而不是在函数里取当前时间：否则测试只能把时间戳写成
/// 「当前时间减 N」，一旦写死成固定时间戳（比如 1_800_000_000），它在未来会变成
/// 负的 elapsed，测试结论就随系统时钟漂移。
fn should_periodic_scan(interval_seconds: u64, last_scan_unix: Option<u64>, now_unix: u64) -> bool {
    if interval_seconds == 0 {
        return false;
    }
    match last_scan_unix {
        None => true,
        Some(last) => now_unix.saturating_sub(last) >= interval_seconds,
    }
}

/// 维护当前 exit_pool：低额度响应（403/429）不视为不可达，只有连续失败达到
/// 阈值才剔除；失败率超过熔断比例时整轮不做批量剔除。
async fn maintain_exit_pool(
    app: &AppState,
    provider: &aether_data_contracts::repository::provider_catalog::StoredProviderCatalogProvider,
    scan: &OpenCodeScanConfig,
    health: &OpenCodeHealthConfig,
) -> Result<(), GatewayError> {
    if scan.exit_pool.is_empty() {
        return Ok(());
    }
    let (domain, port) = opencode_upstream_target(app, &provider.id, scan).await?;
    if crate::opencode_pool::probe_target_is_official(&domain) {
        return Ok(());
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
        return Ok(());
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
        return Ok(());
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
    Ok(())
}

pub(crate) async fn run_opencode_ip_pool_maintenance_once(
    app: &AppState,
) -> Result<usize, GatewayError> {
    let providers = app.list_provider_catalog_providers(true).await?;
    let mut scanned = 0_usize;
    for provider in providers {
        if !provider
            .provider_type
            .trim()
            .eq_ignore_ascii_case("opencode")
        {
            continue;
        }
        let status = opencode_ip_pool_status_for(&provider.id);
        // 只有扫描会同时写 `provider.config`，与它互斥即可（清理入口已删除）。
        if status.scanning {
            continue;
        }

        let config = OpenCodeScanConfig::from_provider_config(&provider.config);
        let health = OpenCodeHealthConfig::from_provider_config(&provider.config);
        if !interval_elapsed_seconds(
            config.maintenance_interval_seconds(),
            config
                .last_maintenance_at
                .as_deref()
                .and_then(parse_rfc3339_unix_secs),
        ) {
            continue;
        }
        if let Err(err) = maintain_exit_pool(app, &provider, &config, &health).await {
            tracing::warn!(event_name="opencode_ip_pool_maintenance_probe_failed", provider_id=%provider.id, error=%err.into_message(), "exit pool maintenance failed");
        }
        let mut maintenance_stamp = OpenCodeScanConfig::from_provider_config(&provider.config);
        maintenance_stamp.last_maintenance_at = Some(chrono::Utc::now().to_rfc3339());
        if let Err(err) = write_scan_config(app, &provider, &maintenance_stamp).await {
            tracing::warn!(event_name="opencode_ip_pool_maintenance_timestamp_write_failed", provider_id=%provider.id, error=%err.into_message(), "failed to persist maintenance timestamp");
        }

        // 补池：维护本身只会剔除。池子跌破保底线后如果没人补，就会一路缩到 0，
        // 之后所有请求退回系统 DNS 的单条路径，按 /24 分散失效——这正是
        // 「靠 CIDR 维护」缺的那一半。扫描自己带互斥锁（`scanning`），
        // 手动扫描正在进行时会直接返回错误，这里只记一条 debug。
        let pool_now = config.effective_pool(&health).len();
        let last_scan = config
            .last_scan_at
            .as_deref()
            .and_then(parse_rfc3339_unix_secs);
        let refill = should_auto_refill(
            config.maintenance_auto_refill(),
            pool_now,
            health.min_pool_size(),
        );
        // 定期扫描与补池走同一个入口，区别只是触发条件：前者按周期主动扩池，
        // 后者是跌破保底线的应急。两者同时成立时只扫一次。
        let periodic =
            should_periodic_scan(config.scan_interval_seconds(), last_scan, now_unix_secs());
        if refill || periodic {
            tracing::info!(
                event_name = "opencode_ip_pool_auto_scan_started",
                log_type = "ops",
                provider_id = %provider.id,
                pool_now,
                min_pool_size = health.min_pool_size(),
                refill,
                periodic,
                "scanning cidrs to grow the opencode ip pool"
            );
            match crate::opencode_pool::run_open_code_pool_scan(app, &provider).await {
                Ok(summary) => tracing::info!(
                    event_name = "opencode_ip_pool_auto_scan_done",
                    log_type = "ops",
                    provider_id = %provider.id,
                    targets = summary.targets,
                    "opencode ip pool auto scan finished"
                ),
                Err(err) => tracing::debug!(
                    event_name = "opencode_ip_pool_auto_scan_skipped",
                    provider_id = %provider.id,
                    error = %err.into_message(),
                    "opencode ip pool auto scan did not run"
                ),
            }
        }

        // 跌破保底线告警：只在状态翻转时打一条，避免每个 tick 刷屏。
        // 跌破保底线意味着淘汰保护已生效、池子不再自动清理，可用节点已经很少，
        // 随时可能开始失败——必须有一条明确告警，而不是等请求报错才发现。
        let healthy_now = health.healthy.len() as u64;
        let floor = health.min_pool_size() as u64;
        let low = healthy_now <= floor;
        if low != status.pool_low_alarm {
            update_opencode_ip_pool_status(&provider.id, |status| {
                status.pool_low_alarm = low;
            });
            if low {
                tracing::warn!(
                    event_name = "opencode_ip_pool_below_floor",
                    log_type = "ops",
                    provider_id = %provider.id,
                    healthy = healthy_now,
                    floor,
                    "opencode ip pool fell to or below the configured floor"
                );
            } else {
                tracing::info!(
                    event_name = "opencode_ip_pool_recovered_above_floor",
                    log_type = "ops",
                    provider_id = %provider.id,
                    healthy = healthy_now,
                    floor,
                    "opencode ip pool recovered above the configured floor"
                );
            }
        }
        let config = OpenCodeScanConfig::from_provider_config(&provider.config);
        if autoscan_due(&config) {
            match run_open_code_pool_scan(app, &provider).await {
                Ok(summary) => {
                    scanned += 1;
                    tracing::info!(
                        event_name = "opencode_ip_pool_autoscan_completed",
                        log_type = "ops",
                        provider_id = %provider.id,
                        targets = summary.targets,
                        added = summary.added,
                        "opencode ip pool autoscan completed"
                    );
                }
                Err(err) => {
                    tracing::warn!(
                        event_name = "opencode_ip_pool_autoscan_provider_failed",
                        log_type = "ops",
                        provider_id = %provider.id,
                        error = %err.into_message(),
                        "opencode ip pool autoscan provider failed"
                    );
                }
            }
        }
    }
    Ok(scanned)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn config(auto_enabled: bool, interval_hours: u32, cidrs: &[&str]) -> OpenCodeScanConfig {
        OpenCodeScanConfig {
            cidrs: cidrs.iter().map(|cidr| cidr.to_string()).collect(),
            auto_enabled,
            interval_hours: Some(interval_hours),
            concurrency: Some(8),
            ..OpenCodeScanConfig::default()
        }
    }

    /// 把 Unix 秒格式化成 `last_scan_at` 用的 RFC3339 字符串。
    fn stamp(unix_secs: u64) -> String {
        use chrono::TimeZone;
        chrono::Utc
            .timestamp_opt(unix_secs as i64, 0)
            .single()
            .expect("timestamp should be representable")
            .to_rfc3339()
    }

    #[test]
    fn autoscan_requires_switch_and_interval_and_cidrs() {
        assert!(autoscan_due(&config(true, 1, &["203.0.113.0/24"])));
        assert!(!autoscan_due(&config(false, 1, &["203.0.113.0/24"])));
        assert!(!autoscan_due(&config(true, 0, &["203.0.113.0/24"])));
        assert!(!autoscan_due(&config(true, 6, &[])));
    }

    #[test]
    fn autoscan_respects_elapsed_interval() {
        let now = now_unix_secs();
        // 6 小时间隔：1 小时前扫过 → 不到期；7 小时前扫过 → 到期。
        let mut recent = config(true, 6, &["203.0.113.0/24"]);
        recent.last_scan_at = Some(stamp(now - 3600));
        assert!(!autoscan_due(&recent));

        let mut old = config(true, 6, &["203.0.113.0/24"]);
        old.last_scan_at = Some(stamp(now - 7 * 3600));
        assert!(autoscan_due(&old));
    }

    #[test]
    fn autoscan_does_not_fire_before_interval_when_clock_skews() {
        let now = now_unix_secs();
        // 未来时间戳（时钟回拨）不应被当成永不过期，saturating_sub 会得到 0。
        let mut future = config(true, 6, &["203.0.113.0/24"]);
        future.last_scan_at = Some(stamp(now + 3600));
        assert!(!autoscan_due(&future));
    }

    #[test]
    fn a_zero_interval_never_elapses_even_with_an_old_timestamp() {
        assert!(!interval_elapsed(0, Some(0)));
        assert!(!interval_elapsed(0, None));
    }

    #[test]
    fn rfc3339_parsing_accepts_offsets_and_rejects_garbage() {
        // 期望值由 chrono 算出，不写死：手算 Unix 秒只会得到一个
        // 看起来合理的错数，而这正是本测试本该拦住的那类错误。
        let stamp = "2026-09-29T03:51:39.229006070+00:00";
        let expected = chrono::DateTime::parse_from_rfc3339(stamp)
            .expect("stamp parses")
            .timestamp() as u64;
        assert_eq!(parse_rfc3339_unix_secs(stamp), Some(expected));

        // 带非零时区偏移的同一时刻必须解析到同一个秒。
        assert_eq!(
            parse_rfc3339_unix_secs("2026-09-29T11:51:39+08:00"),
            parse_rfc3339_unix_secs("2026-09-29T03:51:39Z"),
            "时区偏移不能改变它代表的那一刻"
        );

        assert_eq!(parse_rfc3339_unix_secs(""), None);
        assert_eq!(parse_rfc3339_unix_secs("2026-13-99"), None);
        // 前后空白不应导致解析失败。
        assert!(parse_rfc3339_unix_secs("  2026-09-29T03:51:39Z  ").is_some());
    }

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

    /// 补池只由「跌破保底线」触发，关掉开关就完全不扫。
    #[test]
    fn auto_refill_fires_only_below_the_floor() {
        // 池子 600、保底 5：不去扫（扫描要打几千个目标）
        assert!(!should_auto_refill(true, 600, 5));
        // 跌到刚好等于保底线：仍然要补（`<= floor` 与告警口径一致）
        assert!(should_auto_refill(true, 4, 5));
        assert!(should_auto_refill(true, 0, 5));
        // 开关关掉时一律不补
        assert!(!should_auto_refill(false, 0, 5));
        // 保底线被配成 0 时按 1 处理，不能让「< 0」永远不成立
        assert!(!should_auto_refill(true, 1, 0));
        assert!(should_auto_refill(true, 0, 0));
    }

    /// 定期扫描：0 关闭，其余按间隔判定；从没扫过时立刻到期。
    #[test]
    fn periodic_scan_respects_interval_and_off_switch() {
        let now = 1_800_000_000u64;
        // 关闭
        assert!(!should_periodic_scan(0, Some(now - 10_000), now));
        assert!(!should_periodic_scan(0, None, now));
        // 从没扫过 → 到期
        assert!(should_periodic_scan(3_600, None, now));
        // 刚扫过 → 不到期
        assert!(!should_periodic_scan(3_600, Some(now - 60), now));
        // 超过间隔 → 到期
        assert!(should_periodic_scan(3_600, Some(now - 3_601), now));
        // 上次扫描时间在未来（时钟回拨/时区错写）→ 不到期，不能立刻再扫一次
        assert!(!should_periodic_scan(3_600, Some(now + 600), now));
    }
}
