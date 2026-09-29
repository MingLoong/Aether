//! OpenCode 前置代理出口 IP 池的定时维护 worker。
//!
//! 每 5 分钟醒一次，遍历所有 `provider_type = opencode` 的供应商：
//!
//! 扫描（成本高，产出是新候选）：
//! - `auto_enabled = true` 且配了 CIDR 才考虑；
//! - `interval_hours = 0` 时视为「只允许手动扫描」；
//! - 距上次扫描未满间隔时跳过。
//!
//! 验健康（成本低，产出是当前可信集）：
//! - `auto_verify_enabled = true` 且 `verify_interval_hours > 0` 才考虑；
//! - 距上次复验未满间隔时跳过。
//!
//! 两者都在扫描/清理/复验正在进行时跳过，单个供应商失败只记日志。
//! 实际逻辑复用 `ip_pool::pool`，与手动接口同一套实现。

use std::time::{Duration, SystemTime, UNIX_EPOCH};

use crate::handlers::admin::{
    claim_verify_slot, opencode_ip_pool_status_for, run_claimed_open_code_pool_verify,
    run_open_code_pool_scan, OpenCodeHealthConfig, OpenCodeScanConfig,
};
use crate::{AppState, GatewayError};

/// worker 心跳间隔：只做「到点了吗」的判断，真正的间隔由配置决定。
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
    interval_elapsed(config.interval_hours.unwrap_or(0), last_scan_at_unix_secs)
}

/// 判断某个供应商此刻是否该自动验健康。
///
/// 上次复验时间取自**落盘**的 `opencode_health.last_verify_at` 而非进程内
/// 状态：进程重启会清空内存状态，若据此判断，一个 3 小时间隔的复验会在
/// 每次重启后立刻再跑一轮——部署越频繁，探测越密。
fn autoverify_due(health: &OpenCodeHealthConfig, scan: &OpenCodeScanConfig) -> bool {
    if !health.autoverify_effective() {
        return false;
    }
    // 没有任何可验的集合时跑了也是空转：verify 的目标是
    // candidates ∪ healthy ∪ pinned，三者皆空时 checked = 0。
    // 不看 last_verify_checked：池空是「走域名直连代理」这一合法模式，
    // 不是故障，对它跑复验既没有目标，也不该被当成待修复的事。
    if scan.effective_pool(health).is_empty()
        && scan.candidates.is_empty()
        && scan.pinned.is_empty()
    {
        return false;
    }
    let last = health
        .last_verify_at
        .as_deref()
        .and_then(parse_rfc3339_unix_secs);
    interval_elapsed(health.verify_interval_hours.unwrap_or(0), last)
}

/// 间隔是否已过。`interval_hours = 0` 表示「即使开启也不自动执行」，
/// 与两个 `*_effective()` 的语义一致。
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

/// 解析 `last_verify_at`（RFC3339）为 Unix 秒。解析失败按「从未执行过」，
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

/// 一轮维护：先验健康，后扫描。
///
/// 顺序有意为之。验健康只花 195 次探测却直接决定生产在用哪些节点，
/// 扫描要花几十分钟且产出只是候选。先做便宜且紧急的那个。
pub(crate) async fn run_opencode_ip_pool_maintenance_once(
    app: &AppState,
) -> Result<(usize, usize), GatewayError> {
    let providers = app.list_provider_catalog_providers(true).await?;
    let mut scanned = 0_usize;
    let mut verified = 0_usize;
    for provider in providers {
        if !provider
            .provider_type
            .trim()
            .eq_ignore_ascii_case("opencode")
        {
            continue;
        }
        let status = opencode_ip_pool_status_for(&provider.id);
        if status.scanning || status.cleaning || status.verifying {
            continue;
        }

        let config = OpenCodeScanConfig::from_provider_config(&provider.config);
        let health = OpenCodeHealthConfig::from_provider_config(&provider.config);
        if autoverify_due(&health, &config) {
            // 与手动接口共用同一把锁：claim 失败说明有人正在跑，直接跳过。
            if claim_verify_slot(&provider.id) {
                match run_claimed_open_code_pool_verify(app, &provider).await {
                    Ok(summary) => {
                        verified += 1;
                        tracing::info!(
                            event_name = "opencode_ip_pool_autoverify_completed",
                            log_type = "ops",
                            provider_id = %provider.id,
                            checked = summary.checked,
                            kept = summary.kept,
                            dropped = summary.dropped,
                            "opencode ip pool autoverify completed"
                        );
                    }
                    Err(err) => {
                        tracing::warn!(
                            event_name = "opencode_ip_pool_autoverify_failed",
                            log_type = "ops",
                            provider_id = %provider.id,
                            error = %err.into_message(),
                            "opencode ip pool autoverify failed"
                        );
                    }
                }
            }
        }

        let config = OpenCodeScanConfig::from_provider_config(&provider.config);
        if autoscan_due(&config, status.last_scan_at_unix_secs) {
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
    Ok((scanned, verified))
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

    fn scan() -> OpenCodeScanConfig {
        OpenCodeScanConfig::default()
    }

    fn health(
        auto_verify_enabled: bool,
        interval_hours: u32,
        healthy: &[&str],
    ) -> OpenCodeHealthConfig {
        OpenCodeHealthConfig {
            healthy: healthy.iter().map(|ip| ip.to_string()).collect(),
            auto_verify_enabled,
            verify_interval_hours: Some(interval_hours),
            ..OpenCodeHealthConfig::default()
        }
    }

    /// 把 `last_verify_at` 设成「距今 n 秒前」。
    fn health_verified_n_secs_ago(seconds_ago: u64) -> OpenCodeHealthConfig {
        let at = chrono::Utc::now() - chrono::Duration::seconds(seconds_ago as i64);
        OpenCodeHealthConfig {
            healthy: vec!["1.2.3.4".to_string()],
            auto_verify_enabled: true,
            verify_interval_hours: Some(3),
            last_verify_at: Some(at.to_rfc3339()),
            last_verify_checked: 65,
            last_verify_kept: 65,
            ..OpenCodeHealthConfig::default()
        }
    }

    #[test]
    fn autoverify_requires_switch_and_interval() {
        assert!(autoverify_due(&health(true, 3, &["1.2.3.4"]), &scan()));
        // 开关关 → 不跑，尽管摘要说上次跑过很久。
        assert!(!autoverify_due(&health(false, 3, &["1.2.3.4"]), &scan()));
        // 间隔 0 = 「开着但永不自动执行」。
        assert!(!autoverify_due(&health(true, 0, &["1.2.3.4"]), &scan()));
    }

    #[test]
    fn autoverify_respects_the_persisted_interval() {
        // 1 小时前跑过，间隔 3 小时 → 不到期。
        assert!(!autoverify_due(&health_verified_n_secs_ago(3600), &scan()));
        // 4 小时前跑过 → 到期。
        assert!(autoverify_due(
            &health_verified_n_secs_ago(4 * 3600),
            &scan()
        ));
    }

    #[test]
    fn autoverify_does_not_refire_on_every_restart() {
        // 上次时间取自落盘字段。若改用进程内状态，重启会清空它，
        // 于是每次部署后都会立刻补跑一轮 195 次探测。
        assert!(
            !autoverify_due(&health_verified_n_secs_ago(60), &scan()),
            "刚跑过 1 分钟，重启后不该立刻再来一轮"
        );
    }

    #[test]
    fn autoverify_survives_a_restart_after_the_interval_elapsed() {
        // 与上一个测试相反：落盘时间够老时，重启后仍应补跑。
        assert!(autoverify_due(
            &health_verified_n_secs_ago(4 * 3600),
            &scan()
        ));
    }

    #[test]
    fn autoverify_skips_when_there_is_nothing_to_verify() {
        // 空池 + 从未验过：verify 的目标集合为空，跑了只是空转。
        assert!(!autoverify_due(&health(true, 3, &[]), &scan()));
        // 空池但验过：仍然跳过——没有节点就没有质量可维持。
        let mut previously_verified = health_verified_n_secs_ago(4 * 3600);
        previously_verified.healthy.clear();
        assert!(!autoverify_due(&previously_verified, &scan()));
    }

    #[test]
    fn autoverify_runs_when_only_candidates_exist() {
        // 池空但有候选：验健康正是把候选变成 healthy 的那一步，
        // 此时跳过会让池子永远起不来。
        let scan = OpenCodeScanConfig {
            candidates: vec!["1.2.3.4".to_string()],
            ..OpenCodeScanConfig::default()
        };
        assert!(autoverify_due(&health(true, 3, &[]), &scan));
    }

    #[test]
    fn autoverify_treats_an_unparsable_timestamp_as_never_run() {
        // 时间戳坏掉时宁可多跑一轮，也不能让维护永久停摆——
        // 「一直在跑」只是多花探测，「一直不跑」是静默的质量滑坡。
        let health = OpenCodeHealthConfig {
            healthy: vec!["1.2.3.4".to_string()],
            auto_verify_enabled: true,
            verify_interval_hours: Some(3),
            last_verify_at: Some("not-a-timestamp".to_string()),
            ..OpenCodeHealthConfig::default()
        };
        assert!(autoverify_due(&health, &scan()));
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
