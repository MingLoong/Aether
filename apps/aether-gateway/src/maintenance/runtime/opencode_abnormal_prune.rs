//! 异常池的定时过期清理。
//!
//! 为什么需要这个定时器：`prune_expired_abnormal`（按 `opencode_health.abnormal_max_age_days`
//! 判过期，默认 7 天）是**惰性**的——只在写配置时顺带跑一次。出口 IP 池改成「手动维护 +
//! 手动巡检」之后，没人操作就不会有写，于是过期条目会一直挂在异常池里继续挡住那些 IP：
//! 轮转池 = healthy ∪ (exit_pool − abnormal − blocked)，一条僵尸记录等于一个永久不可用的
//! 节点，而界面上看不出任何异常。
//!
//! 这里**只做过期清理**：判断是纯内存的，命中时按段写回一次 `opencode_health`。
//! 不跑任何探针——探测只能由面板上的「巡检」按钮手动触发，这里跑的话等于把删掉的
//! 定时维护又偷偷装回来。
//!
//! 单轮里任何供应商失败只记 WARN 继续下一个：清理是尽力而为的保洁，不该因为一个
//! 供应商配置写不进去就整轮停摆。

use std::time::{Duration, Instant};

use crate::opencode_pool::{write_health_config, OpenCodeHealthConfig};
use crate::{AppState, GatewayError};

/// 一轮清理的间隔。
///
/// 1 小时而不是原维护 worker 的 600 秒：这里只做纯内存判断 + 偶发一次按段写回，
/// 不碰网络也不探任何 IP，快慢对池子健康毫无影响；它唯一要保证的事是
/// 「过期条目别在上面挂太久」。
const OPENCODE_ABNORMAL_PRUNE_INTERVAL: Duration = Duration::from_secs(60 * 60);
/// 启动后的首个静默期：网关刚起来时连接池与 provider 目录都在被抢着用，
/// 没必要为了清几条过期记录挤进这段高峰。
const OPENCODE_ABNORMAL_PRUNE_STARTUP_GRACE: Duration = Duration::from_secs(60);
/// 单条日志里最多列这么多个被清掉的 IP。
const OPENCODE_ABNORMAL_PRUNE_LOG_SAMPLE: usize = 10;

/// 一轮清理的统计。
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
struct AbnormalPruneRoundSummary {
    providers_scanned: usize,
    providers_changed: usize,
    expired_total: usize,
}

/// 一个供应商是否配过出口 IP 池。
///
/// 两段都算：异常池条目住在 `opencode_health`，而 `opencode_scan` 只是池成员与扫描配置；
/// 只认其中一段会漏掉「健康段被单独写过」的供应商。
fn has_pool_sections(config: &Option<serde_json::Value>) -> bool {
    config
        .as_ref()
        .and_then(serde_json::Value::as_object)
        .is_some_and(|object| {
            object.contains_key("opencode_scan") || object.contains_key("opencode_health")
        })
}

/// 跑一轮过期清理：只读配置 → 纯内存判过期 → 有变化才按段写回。
async fn run_abnormal_prune_once(
    app: &AppState,
) -> Result<AbnormalPruneRoundSummary, GatewayError> {
    let providers = app.list_provider_catalog_providers(true).await?;
    let mut summary = AbnormalPruneRoundSummary::default();
    for provider in providers {
        if !has_pool_sections(&provider.config) {
            continue;
        }
        summary.providers_scanned += 1;
        let mut health = OpenCodeHealthConfig::from_provider_config(&provider.config);
        let expired = health.prune_expired_abnormal();
        if expired.is_empty() {
            continue;
        }
        // 只写 `opencode_health` 一段：整段重写 config 会把扫描/面板正在写的
        // `exit_pool`、各种阈值一起按这份快照覆盖回去。
        if let Err(err) = write_health_config(app, &provider, &health).await {
            tracing::warn!(
                event_name = "opencode_abnormal_prune_provider_failed",
                log_type = "ops",
                provider_id = %provider.id,
                error = %err.into_message(),
                "failed to persist pruned opencode abnormal entries"
            );
            continue;
        }
        summary.providers_changed += 1;
        summary.expired_total += expired.len();
        let sample: Vec<&str> = expired
            .iter()
            .take(OPENCODE_ABNORMAL_PRUNE_LOG_SAMPLE)
            .map(String::as_str)
            .collect();
        tracing::info!(
            event_name = "opencode_abnormal_prune",
            log_type = "ops",
            provider_id = %provider.id,
            expired_count = expired.len(),
            expired_ips = ?sample,
            "pruned expired opencode abnormal entries"
        );
    }
    Ok(summary)
}

pub(crate) fn spawn_opencode_abnormal_prune_worker(
    app: AppState,
) -> Option<tokio::task::JoinHandle<()>> {
    if !app.has_provider_catalog_data_reader() || !app.has_provider_catalog_data_writer() {
        return None;
    }

    Some(crate::task_runtime::spawn_singleton_worker(
        app,
        crate::task_runtime::TASK_KEY_OPENCODE_ABNORMAL_PRUNE,
        |app| async move {
            tokio::time::sleep(OPENCODE_ABNORMAL_PRUNE_STARTUP_GRACE).await;
            let mut interval = tokio::time::interval(OPENCODE_ABNORMAL_PRUNE_INTERVAL);
            interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
            // 这里**不要**先 tick 一次：`tokio::time::interval` 的第一个 tick 是立即完成的，
            // 提前把它吃掉就等于把「启动后先清一轮」变成「等满一个周期才第一次清」。
            // 实测：部署后半小时日志里一条 prune 记录都没有，原因就是这个多余的空 tick。
            loop {
                interval.tick().await;
                let started_at = Instant::now();
                match run_abnormal_prune_once(&app).await {
                    Ok(summary) => tracing::info!(
                        event_name = "opencode_abnormal_prune_round_done",
                        log_type = "ops",
                        providers_scanned = summary.providers_scanned,
                        providers_changed = summary.providers_changed,
                        expired_total = summary.expired_total,
                        elapsed_ms = started_at.elapsed().as_millis() as u64,
                        "opencode abnormal prune round finished"
                    ),
                    Err(err) => tracing::warn!(
                        event_name = "opencode_abnormal_prune_round_failed",
                        log_type = "ops",
                        elapsed_ms = started_at.elapsed().as_millis() as u64,
                        error = %err.into_message(),
                        "opencode abnormal prune round failed"
                    ),
                }
            }
        },
    ))
}

#[cfg(test)]
mod tests {
    use crate::opencode_pool::pool::{OpenCodeAbnormalIp, OPENCODE_ABNORMAL_DISCARD_FAILS};

    use super::*;

    fn abnormal_ip(ip: &str, days_ago: i64, fails: u32) -> OpenCodeAbnormalIp {
        OpenCodeAbnormalIp {
            ip: ip.to_string(),
            since: (chrono::Utc::now() - chrono::Duration::days(days_ago)).to_rfc3339(),
            fails,
            reason: "unreachable".to_string(),
            median_ms: None,
        }
    }

    /// 清理只清「过期的普通条目」：新条目留着，已达出池阈值的旧条目也留着。
    ///
    /// 纯函数、`now` 由调用方给的判据是整个保洁逻辑里唯一有分支的地方，而它决定
    /// 「一个失败过的 IP 多久之后重新回到轮转」——改错了不会编译失败，只会让坏 IP
    /// 悄悄复活或者让僵尸记录永久占位。
    #[test]
    fn prune_drops_only_stale_entries_below_the_evict_threshold() {
        let mut health = OpenCodeHealthConfig::default();
        health.abnormal.push(abnormal_ip("10.0.0.1", 30, 1));
        health.abnormal.push(abnormal_ip("10.0.0.2", 1, 1));
        // 已达出池阈值：本该被丢弃，还在就说明当时池子低于保护线不允许丢，
        // 这种条目必须继续拦住这个 IP，不受过期影响。
        health
            .abnormal
            .push(abnormal_ip("10.0.0.3", 90, OPENCODE_ABNORMAL_DISCARD_FAILS));

        let removed = health.prune_expired_abnormal_at(chrono::Utc::now());
        assert_eq!(removed, vec!["10.0.0.1".to_string()]);
        let remaining: Vec<&str> = health.abnormal.iter().map(|e| e.ip.as_str()).collect();
        assert_eq!(remaining, vec!["10.0.0.2", "10.0.0.3"]);
    }
}
