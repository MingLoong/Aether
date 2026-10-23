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
            let result = probe_upstream_ip_maintenance(&ip, &domain, port, 10)
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
    if failure_pct > threshold || unreachable.saturating_mul(2) > checked {
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
}
