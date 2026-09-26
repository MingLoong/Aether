//! OpenCode 前置代理出口 IP 池的定时自动扫描 worker。
//!
//! 每 5 分钟醒一次，遍历所有 `provider_type = opencode` 且
//! `config.opencode_scan.auto_enabled = true` 的供应商：
//!
//! - `interval_hours = 0` 时视为「只允许手动扫描」；
//! - 距上次扫描未满间隔时跳过；
//! - 正在扫描/清理时跳过（避免与手动操作叠加）；
//! - 单个供应商扫描失败只记日志，不影响其它供应商。
//!
//! 扫描/清理的实际逻辑复用 `ip_pool::pool`，与手动接口同一套实现。

use std::time::{Duration, SystemTime, UNIX_EPOCH};

use crate::handlers::admin::{
    opencode_ip_pool_status_for, run_open_code_pool_scan, OpenCodeScanConfig,
};
use crate::{AppState, GatewayError};

/// worker 心跳间隔：只做「到点了吗」的判断，真正的间隔由 `interval_hours` 决定。
const OPENCODE_IP_POOL_TICK: Duration = Duration::from_secs(300);
/// 启动后的首次静默期，避免网关刚起来就发起一轮探测。
const OPENCODE_IP_POOL_STARTUP_GRACE: Duration = Duration::from_secs(90);

fn now_unix_secs() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|duration| duration.as_secs())
        .unwrap_or_default()
}

/// 判断某个供应商此刻是否该自动扫描。
fn autoscan_due(config: &OpenCodeScanConfig, last_scan_at_unix_secs: Option<u64>) -> bool {
    if !config.autoscan_effective() || config.cidrs.is_empty() {
        return false;
    }
    let interval_secs = u64::from(config.interval_hours.unwrap_or(0)) * 3600;
    match last_scan_at_unix_secs {
        // 从未扫描过：立刻跑一轮。
        None => true,
        Some(last) => now_unix_secs().saturating_sub(last) >= interval_secs,
    }
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
                if let Err(err) = run_opencode_ip_pool_autoscan_once(&app).await {
                    tracing::warn!(
                        event_name = "opencode_ip_pool_autoscan_failed",
                        log_type = "ops",
                        error = %err.into_message(),
                        "opencode ip pool autoscan tick failed"
                    );
                }
            }
        },
    ))
}

/// 执行一轮自动扫描，返回被扫描的供应商数量。
pub(crate) async fn run_opencode_ip_pool_autoscan_once(
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
        let config = OpenCodeScanConfig::from_provider_config(&provider.config);
        let status = opencode_ip_pool_status_for(&provider.id);
        if status.scanning || status.cleaning {
            continue;
        }
        if !autoscan_due(&config, status.last_scan_at_unix_secs) {
            continue;
        }
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

    #[test]
    fn autoscan_requires_switch_and_interval_and_cidrs() {
        assert!(autoscan_due(&config(true, 1, &["203.0.113.0/24"]), None));
        assert!(!autoscan_due(&config(false, 1, &["203.0.113.0/24"]), None));
        assert!(!autoscan_due(&config(true, 0, &["203.0.113.0/24"]), None));
        assert!(!autoscan_due(&config(true, 6, &[]), None));
    }

    #[test]
    fn autoscan_respects_elapsed_interval() {
        let now = now_unix_secs();
        // 6 小时间隔：1 小时前扫过 → 不到期；7 小时前扫过 → 到期。
        assert!(!autoscan_due(
            &config(true, 6, &["203.0.113.0/24"]),
            Some(now - 3600)
        ));
        assert!(autoscan_due(
            &config(true, 6, &["203.0.113.0/24"]),
            Some(now - 7 * 3600)
        ));
    }

    #[test]
    fn autoscan_does_not_fire_before_interval_when_clock_skews() {
        let now = now_unix_secs();
        // 未来时间戳（时钟回拨）不应被当成永不过期，saturating_sub 会得到 0。
        assert!(!autoscan_due(
            &config(true, 6, &["203.0.113.0/24"]),
            Some(now + 3600)
        ));
    }
}
