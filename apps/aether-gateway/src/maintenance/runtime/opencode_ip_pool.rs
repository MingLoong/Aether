//! Automatic OpenCode IP-pool scan worker.
//!
//! Periodically (every minute) scans the configured opencode providers for
//! auto-scan eligibility and triggers `run_open_code_pool_scan` when the
//! configured interval has elapsed.

use crate::maintenance::opencode_ip_pool::{
    opencode_ip_pool_status_for, run_open_code_pool_scan, OpenCodeScanConfig,
};
use crate::{AppState, GatewayError};

/// Interval at which the worker checks whether any provider is due for a scan.
const OPENCODE_IP_POOL_WORKER_TICK: std::time::Duration = std::time::Duration::from_secs(60);
/// Hard cap on auto scans kicked per tick (safety).
const OPENCODE_IP_POOL_MAX_SCANS_PER_TICK: usize = 4;

/// Spawns the periodic worker.
pub(crate) fn spawn_opencode_ip_pool_worker(app: AppState) -> Option<tokio::task::JoinHandle<()>> {
    Some(crate::task_runtime::spawn_singleton_worker(
        app.clone(),
        crate::task_runtime::TASK_KEY_OPENCODE_IP_POOL,
        |app| async move {
            let mut interval = tokio::time::interval(OPENCODE_IP_POOL_WORKER_TICK);
            interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
            interval.tick().await;
            loop {
                interval.tick().await;
                if let Err(err) = run_opencode_ip_pool_autoscan_once(&app).await {
                    tracing::warn!(
                        event_name = "maintenance_worker_failed",
                        log_type = "ops",
                        worker = "opencode_ip_pool",
                        phase = "tick",
                        error = ?err,
                        "gateway maintenance worker failed"
                    );
                }
            }
        },
    ))
}

/// One pass over opencode providers: runs scans whose configured interval has
/// elapsed.
pub(crate) async fn run_opencode_ip_pool_autoscan_once(app: &AppState) -> Result<(), GatewayError> {
    let providers = app.list_provider_catalog_providers(false).await?;
    let mut due = Vec::new();
    for provider in providers {
        if !provider
            .provider_type
            .trim()
            .eq_ignore_ascii_case("opencode")
        {
            continue;
        }
        let config = OpenCodeScanConfig::from_provider_config(&provider.config);
        if !config.auto_enabled {
            continue;
        }
        let interval = config.effective_interval_hours();
        if interval == 0 {
            continue;
        }
        let status = opencode_ip_pool_status_for(&provider.id);
        if status.scanning {
            continue;
        }
        let is_due = status
            .last_scan_at_unix_secs
            .map(|last| {
                let now = std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .map(|d| d.as_secs())
                    .unwrap_or_default();
                now >= last + (interval as u64) * 3600
            })
            .unwrap_or(true);
        if is_due {
            due.push(provider);
        }
    }
    for provider in due.into_iter().take(OPENCODE_IP_POOL_MAX_SCANS_PER_TICK) {
        if let Err(err) = run_open_code_pool_scan(app, &provider).await {
            tracing::warn!(
                event_name = "opencode_ip_pool_autoscan_failed",
                log_type = "ops",
                provider_id = %provider.id,
                error = ?err,
                "opencode ip pool autoscan failed"
            );
        }
    }
    Ok(())
}
