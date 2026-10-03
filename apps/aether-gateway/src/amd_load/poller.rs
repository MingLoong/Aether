//! AMD 模型负载感知 —— 后台轮询 worker。
//!
//! 周期性拉取 AMD 的 fleet 级负载快照，写入 Redis，供管理端展示
//! （Step 1）与调度期过滤（Step 2）使用。
//!
//! 接线方式照 `maintenance/runtime/opencode_ip_pool.rs`：
//! `spawn_singleton_worker` 拿到集群级 Redis 租约（`task_runtime:singleton:<key>`），
//! 因此本 worker 在整个集群里只会有一个实例在跑。

use std::collections::{BTreeMap, HashMap};
use std::time::Duration;

use serde::Serialize;

use crate::amd_load::usage::{self, AmdUsageAccount, AmdUsageSnapshot, AmdUsageWindowSet};
use crate::{AppState, GatewayError};

use super::config::AmdLoadConfig;
use super::{now_unix_secs, snapshot_key, streak_key, AmdLoadSnapshot};

/// worker 心跳：只做「到点了吗」的粗判断，真正的间隔由每个供应商的
/// `poll_sec` 决定并逐轮检查。
const AMD_LOAD_TICK: Duration = Duration::from_secs(30);
/// 启动静默期，避免网关刚起来就发一轮 22 秒的请求。
const AMD_LOAD_STARTUP_GRACE: Duration = Duration::from_secs(90);

/// 响应体上限。上游实测约 1.5 KB，64 KB 足够且能挡住异常响应。
const AMD_LOAD_RESPONSE_BODY_LIMIT_BYTES: usize = 64 * 1024;

/// 单轮结果。
///
/// 带 `Serialize` 是因为管理接口的 `refresh` 会把摘要原样回给前端。手写一份字段
/// 映射的话，将来加字段就会出现「结构体里有、接口里没有」的静默不一致。
#[derive(Debug, Default, PartialEq, Serialize)]
pub(crate) struct PollSummary {
    pub providers_polled: usize,
    pub providers_skipped: usize,
    pub models_seen: usize,
    pub models_blocked: usize,
}

/// 是否是 AMD 上游。
///
/// 数据源路径是 AMD 专有的 `/radeon/api/tokenfactory/load`，只有把
/// `https://.../radeon/api/v1` 形式的 base_url 指向 AMD 才成立。
/// 不按 `provider_type` 判定：AMD 注册为通用的 `custom`。
pub(crate) fn is_amd_upstream(base_url: &str) -> bool {
    base_url.trim_end_matches('/').contains("/radeon/api/")
}

/// 从 AMD 的 `upstream_base` 推导负载端点。
///
/// 只做「截断到已知路径标记 + 拼接已知路径」的字符串手术，不引入任何外部输入，
/// 因此 origin 不会被改写——凭证不会被送到别的主机。
pub(crate) fn load_endpoint_url(base_url: &str) -> Option<String> {
    let trimmed = base_url.trim().trim_end_matches('/');
    if !trimmed.starts_with("https://") && !trimmed.starts_with("http://") {
        return None;
    }
    let marker = "/radeon/api/v1";
    let origin_and_prefix = trimmed.split_once(marker).map(|(head, _)| head)?;
    Some(format!("{origin_and_prefix}/radeon/api/tokenfactory/load"))
}

/// 启动 worker。数据层不具备 provider catalog 读写能力时返回 `None`（不启动）。
pub(crate) fn spawn_amd_load_worker(app: AppState) -> Option<tokio::task::JoinHandle<()>> {
    if !app.has_provider_catalog_data_reader() || !app.has_provider_catalog_data_writer() {
        return None;
    }

    Some(crate::task_runtime::spawn_singleton_worker(
        app,
        crate::task_runtime::TASK_KEY_AMD_LOAD_POLL,
        |app| async move {
            tokio::time::sleep(AMD_LOAD_STARTUP_GRACE).await;
            let mut interval = tokio::time::interval(AMD_LOAD_TICK);
            interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
            // 丢掉 interval 的立即首次 tick，让第一轮工作发生在一个完整周期之后。
            interval.tick().await;

            // 轮内记忆：每个供应商上次「尝试」的时刻。
            //
            // 用尝试时刻而不是成功时刻，是为了让失败也计入间隔——否则一次
            // 40 秒超时就可能紧跟着下一轮再打一次。放在进程内而非落盘是安全的：
            // 本 worker 由 Redis 租约保证集群内单实例，且 60 秒的间隔下
            // 「重启后立刻轮一轮」代价只是 22 秒一次请求。
            let mut last_attempt: HashMap<String, u64> = HashMap::new();

            loop {
                interval.tick().await;
                let now = now_unix_secs();
                if let Err(err) = run_amd_load_poll_once(&app, &mut last_attempt, now).await {
                    tracing::warn!(
                        event_name = "amd_load_poll_failed",
                        log_type = "ops",
                        error = %err.into_message(),
                        "amd load poll tick failed"
                    );
                }
            }
        },
    ))
}

/// 跑一轮：遍历所有 AMD 供应商，对到点的那几个各拉一次。
pub(crate) async fn run_amd_load_poll_once(
    app: &AppState,
    last_attempt: &mut HashMap<String, u64>,
    now_unix_secs: u64,
) -> Result<PollSummary, GatewayError> {
    let providers = app.list_provider_catalog_providers(true).await?;
    if providers.is_empty() {
        return Ok(PollSummary::default());
    }
    let provider_ids = providers
        .iter()
        .map(|provider| provider.id.clone())
        .collect::<Vec<_>>();
    let endpoints = app
        .list_provider_catalog_endpoints_by_provider_ids(&provider_ids)
        .await?;

    let mut summary = PollSummary::default();
    for provider in &providers {
        let config = AmdLoadConfig::from_provider_config(provider.config.as_ref());
        if !config.enabled {
            summary.providers_skipped += 1;
            continue;
        }
        let Some(base_url) = endpoints
            .iter()
            .filter(|endpoint| provider.id == endpoint.provider_id && endpoint.is_active)
            .map(|endpoint| endpoint.base_url.as_str())
            .find(|base_url| is_amd_upstream(base_url))
        else {
            // 不是 AMD 上游：未启用负荷感知是正常状态，不算错误。
            summary.providers_skipped += 1;
            continue;
        };
        if last_attempt
            .get(&provider.id)
            .is_some_and(|last| now_unix_secs.saturating_sub(*last) < config.poll_sec)
        {
            summary.providers_skipped += 1;
            continue;
        }
        // 先记尝试时刻再发请求：超时的那一次也要占掉一个间隔。
        last_attempt.insert(provider.id.clone(), now_unix_secs);

        // 配额与负载同一轮里抓，但**失败各自独立**：配额挂了不能影响负载刷新，反之亦然。
        // 两者打的是不同接口，失败原因也不同（配额可能是 rpm 限流）。
        if let Err(err) =
            fetch_usage_snapshot(app, &provider.id, base_url, &config, now_unix_secs).await
        {
            tracing::warn!(
                event_name = "amd_usage_poll_failed",
                log_type = "ops",
                provider_id = %provider.id,
                error = %err.into_message(),
                "amd usage poll failed"
            );
        }

        match poll_provider_once(app, &provider.id, base_url, &config, now_unix_secs).await {
            Ok(outcome) => {
                summary.providers_polled += 1;
                summary.models_seen += outcome.models_seen;
                summary.models_blocked += outcome.models_blocked;
                tracing::info!(
                    event_name = "amd_load_poll_completed",
                    log_type = "ops",
                    provider_id = %provider.id,
                    models_seen = outcome.models_seen,
                    models_blocked = outcome.models_blocked,
                    released_by_guard = outcome.released_by_guard.as_deref().unwrap_or(""),
                    "amd load poll completed"
                );
            }
            Err(err) => {
                // 单个供应商失败不中断整轮；旧快照按 TTL 自然过期后转为「不判定」。
                tracing::warn!(
                    event_name = "amd_load_poll_provider_failed",
                    log_type = "ops",
                    provider_id = %provider.id,
                    error = %err.into_message(),
                    "amd load poll failed for provider"
                );
            }
        }
    }
    Ok(summary)
}

struct PollOutcome {
    models_seen: usize,
    models_blocked: usize,
    released_by_guard: Option<String>,
}

async fn poll_provider_once(
    app: &AppState,
    provider_id: &str,
    base_url: &str,
    config: &AmdLoadConfig,
    now_unix_secs: u64,
) -> Result<PollOutcome, GatewayError> {
    let url = load_endpoint_url(base_url)
        .ok_or_else(|| GatewayError::Internal("无法从 base_url 推导负载端点".to_string()))?;

    let provider_ids = vec![provider_id.to_string()];
    let keys = app
        .list_provider_catalog_keys_by_provider_ids(&provider_ids)
        .await?;
    let endpoints = app
        .list_provider_catalog_endpoints_by_provider_ids(&provider_ids)
        .await?;
    let Some(endpoint) = endpoints
        .iter()
        .find(|endpoint| endpoint.is_active && is_amd_upstream(&endpoint.base_url))
    else {
        return Err(GatewayError::Internal("没有可用的 AMD 端点".to_string()));
    };

    // 依次尝试 enabled key。实测首个 key 偶发 504，换一把即恢复。
    let mut last_error: Option<GatewayError> = None;
    for key in keys.iter().filter(|key| key.is_active) {
        let Some(transport) = app
            .read_provider_transport_snapshot(&provider_ids[0], &endpoint.id, &key.id)
            .await?
        else {
            continue;
        };
        let secret = transport.key.decrypted_api_key.trim();
        if secret.is_empty() {
            continue;
        }
        match fetch_load_body(app, &url, secret, config).await {
            Ok(body) => {
                return store_snapshot(app, provider_id, &body, config, now_unix_secs).await;
            }
            Err(err) => last_error = Some(err),
        }
    }
    Err(last_error
        .unwrap_or_else(|| GatewayError::Internal("没有可用于负载探测的 enabled key".to_string())))
}

/// 拉一次账号配额（`/v1/usage`）并落到 Redis。
///
/// **逐个 enabled key 各拉一次** —— 10 个 key 就是 10 个独立 AMD 账号（实测 10 个互不相
/// 同的 `organization_id`，累计请求数 85~440 各不相同），各有独立的日限额。只拉第一把会让
/// 其余 9 个账号撞满时完全看不见，而额度面板存在的意义正是避免这件事。
///
/// 按 `organization_id` 去重：同账号配了多把 key 时只请求一次，复制快照给它们。`/usage`
/// 保守计入 RPM（参考实现每把之间 sleep 500ms），去重能省下真实配额。
///
/// 单个账号失败不影响其余账号：10 个里挂 1 个，另外 9 个的数据仍然有用。
pub(crate) async fn fetch_usage_snapshot(
    app: &AppState,
    provider_id: &str,
    base_url: &str,
    config: &AmdLoadConfig,
    now_unix_secs: u64,
) -> Result<(), GatewayError> {
    let url = usage_endpoint_url(base_url)
        .ok_or_else(|| GatewayError::Internal("无法从 base_url 推导配额端点".to_string()))?;
    let provider_ids = vec![provider_id.to_string()];
    let keys = app
        .list_provider_catalog_keys_by_provider_ids(&provider_ids)
        .await?;
    let endpoints = app
        .list_provider_catalog_endpoints_by_provider_ids(&provider_ids)
        .await?;
    let Some(endpoint) = endpoints
        .iter()
        .find(|endpoint| endpoint.is_active && is_amd_upstream(&endpoint.base_url))
    else {
        return Err(GatewayError::Internal("没有可用的 AMD 端点".to_string()));
    };

    let mut accounts: Vec<AmdUsageAccount> = Vec::new();
    let mut org_to_usage: HashMap<String, AmdUsageWindowSet> = HashMap::new();
    let mut fetched_requests: u32 = 0;
    let mut failed_accounts: u32 = 0;
    let mut deduped_keys: u32 = 0;

    for key in keys.iter().filter(|key| key.is_active) {
        let base = AmdUsageAccount {
            key_name: key.name.clone(),
            key_id: key.id.clone(),
            organization_id: None,
            usage: None,
            deduped: false,
            error: None,
        };

        let Some(transport) = app
            .read_provider_transport_snapshot(&provider_ids[0], &endpoint.id, &key.id)
            .await?
        else {
            failed_accounts += 1;
            accounts.push(AmdUsageAccount {
                error: Some("读不到密钥".to_string()),
                ..base
            });
            continue;
        };
        let secret = transport.key.decrypted_api_key.trim();
        if secret.is_empty() {
            failed_accounts += 1;
            accounts.push(AmdUsageAccount {
                error: Some("密钥为空".to_string()),
                ..base
            });
            continue;
        }

        fetched_requests += 1;
        let body = match fetch_load_body(app, &url, secret, config).await {
            Ok(body) => body,
            Err(err) => {
                failed_accounts += 1;
                accounts.push(AmdUsageAccount {
                    error: Some(err.into_message()),
                    ..base
                });
                continue;
            }
        };

        let org = AmdUsageSnapshot::extract_organization_id(&body);
        if let Some(org_id) = org.as_ref() {
            if let Some(existing) = org_to_usage.get(org_id).cloned() {
                // 同账号多 key：复制已有快照，不重复发请求。
                fetched_requests -= 1;
                deduped_keys += 1;
                accounts.push(AmdUsageAccount {
                    organization_id: org,
                    usage: Some(existing),
                    deduped: true,
                    ..base
                });
                continue;
            }
        }

        match AmdUsageSnapshot::parse_account_usage(&body, now_unix_secs) {
            Ok(set) => {
                if let Some(org_id) = org.as_ref() {
                    org_to_usage.insert(org_id.clone(), set.clone());
                }
                accounts.push(AmdUsageAccount {
                    organization_id: org,
                    usage: Some(set),
                    ..base
                });
            }
            Err(message) => {
                failed_accounts += 1;
                accounts.push(AmdUsageAccount {
                    organization_id: org,
                    error: Some(message),
                    ..base
                });
            }
        }
    }

    let snapshot = AmdUsageSnapshot {
        fetched_at: now_unix_secs,
        accounts,
        fetched_requests,
        failed_accounts,
        deduped_keys,
    };
    let encoded = serde_json::to_string(&snapshot)
        .map_err(|err| GatewayError::Internal(format!("序列化配额快照失败：{err}")))?;
    // 与负载快照同一个 TTL：都跟着 poll_sec 走即可，配额不需要活得更久。
    app.runtime_kv_setex(
        &usage::usage_key(provider_id),
        &encoded,
        config.snapshot_ttl_sec.max(300),
    )
    .await?;
    Ok(())
}

/// 从 `base_url` 推导配额端点：与负载端点同源，路径为 `/v1/usage`。
pub(crate) fn usage_endpoint_url(base_url: &str) -> Option<String> {
    let trimmed = base_url.trim().trim_end_matches('/');
    let marker = "/radeon/api/v1";
    let origin_and_prefix = trimmed.split_once(marker)?.0;
    Some(format!("{origin_and_prefix}/radeon/api/v1/usage"))
}

/// 读取配额快照，供管理端展示。
pub(crate) async fn read_usage_snapshot(
    app: &AppState,
    provider_id: &str,
) -> Option<crate::amd_load::AmdUsageSnapshot> {
    app.runtime_kv_get(&usage::usage_key(provider_id))
        .await
        .ok()
        .flatten()
        .and_then(|raw| serde_json::from_str(&raw).ok())
}

/// 拉一次上游负载响应，返回原始 JSON body 字符串。
async fn fetch_load_body(
    app: &AppState,
    url: &str,
    secret: &str,
    config: &AmdLoadConfig,
) -> Result<String, GatewayError> {
    let timeout_ms = config.timeout_sec.saturating_mul(1000);
    let plan = aether_contracts::ExecutionPlan {
        request_id: format!("amd-load-{}", now_unix_secs()),
        candidate_id: None,
        provider_name: Some("amd_load".to_string()),
        provider_id: String::new(),
        endpoint_id: String::new(),
        key_id: String::new(),
        method: "GET".to_string(),
        url: url.to_string(),
        headers: BTreeMap::from([("authorization".to_string(), format!("Bearer {secret}"))]),
        content_type: None,
        content_encoding: None,
        body: aether_contracts::RequestBody {
            json_body: None,
            body_bytes_b64: None,
            body_ref: None,
        },
        stream: false,
        client_api_format: "amd_load:probe".to_string(),
        provider_api_format: "amd_load:probe".to_string(),
        model_name: None,
        proxy: None,
        transport_profile: None,
        timeouts: Some(aether_contracts::ExecutionTimeouts {
            connect_ms: Some(timeout_ms),
            read_ms: Some(timeout_ms),
            write_ms: Some(timeout_ms),
            pool_ms: Some(timeout_ms),
            total_ms: Some(timeout_ms),
            ..Default::default()
        }),
    };
    let bounded = crate::execution_runtime::transport::with_upstream_response_body_limit(
        &plan,
        AMD_LOAD_RESPONSE_BODY_LIMIT_BYTES,
    );
    let result =
        crate::execution_runtime::execute_execution_runtime_sync_plan(app, None, &bounded).await?;

    // 先看传输层是否已解析成 JSON；否则从 base64 字节解。
    if let Some(json_body) = result.body.as_ref().and_then(|body| body.json_body.clone()) {
        if !(200..300).contains(&result.status_code) {
            return Err(GatewayError::Internal(format!(
                "负载接口返回 HTTP {}",
                result.status_code
            )));
        }
        return Ok(json_body.to_string());
    }
    let bytes = result.body.as_ref().and_then(|body| {
        body.body_bytes_b64.as_deref().and_then(|value| {
            crate::execution_runtime::transport::decode_base64_body_with_limit(
                value,
                AMD_LOAD_RESPONSE_BODY_LIMIT_BYTES,
            )
            .ok()
        })
    });
    let Some(bytes) = bytes else {
        return Err(GatewayError::Internal(format!(
            "负载接口返回 HTTP {} 且响应体无法解析",
            result.status_code
        )));
    };
    if !(200..300).contains(&result.status_code) {
        // 不把上游 body 原样带出去：可能含敏感信息。
        return Err(GatewayError::Internal(format!(
            "负载接口返回 HTTP {}",
            result.status_code
        )));
    }
    String::from_utf8(bytes)
        .map_err(|err| GatewayError::Internal(format!("负载接口响应不是 UTF-8: {err}")))
}

/// 解析、累加 streak、判定、全禁保护、落 Redis。
async fn store_snapshot(
    app: &AppState,
    provider_id: &str,
    body: &str,
    config: &AmdLoadConfig,
    now_unix_secs: u64,
) -> Result<PollOutcome, GatewayError> {
    let mut snapshot =
        AmdLoadSnapshot::parse_upstream(body, now_unix_secs).map_err(GatewayError::Internal)?;
    let previous_streaks = read_streaks(app, provider_id).await;

    for (name, entry) in snapshot.models.iter_mut() {
        let hot = entry.state == "full" || entry.utilization >= config.disable_threshold;
        let streak = if hot {
            previous_streaks
                .get(name)
                .copied()
                .unwrap_or(0)
                .saturating_add(1)
        } else {
            0
        };
        entry.streak = streak;
        // `block_models` 关闭时仍然记录 streak（面板要显示「连续越线次数」），但不把
        // blocked_prev 置真。判定留在这里而不在展示层，是为了保证「调度实际放行了什么」
        // 与「面板显示禁用了什么」永远一致——两处各自算一遍迟早会对不上。
        entry.blocked_prev = if !config.block_models {
            false
        } else if entry.state == "full" {
            true
        } else if entry.utilization >= config.disable_threshold {
            streak >= config.disable_streak
        } else if entry.utilization <= config.effective_recovery() {
            false
        } else {
            // 滞回带内：本条没有上一轮 blocked_prev 可继承（它来自上一次轮询写入的
            // 快照），所以这里从旧快照继承。
            previous_blocked(app, provider_id, name).await
        };
    }

    let released_by_guard = snapshot.apply_all_blocked_guard();
    let models_blocked = snapshot.blocked_models(config).len();
    let models_seen = snapshot.models.len();

    let serialized = serde_json::to_string(&snapshot)
        .map_err(|err| GatewayError::Internal(format!("快照序列化失败: {err}")))?;
    app.runtime_kv_setex(
        &snapshot_key(provider_id),
        &serialized,
        config.snapshot_ttl_sec,
    )
    .await?;

    let streaks = snapshot
        .models
        .iter()
        .map(|(name, entry)| (name.clone(), entry.streak))
        .collect::<BTreeMap<_, _>>();
    if let Ok(serialized) = serde_json::to_string(&streaks) {
        let _ = app
            .runtime_kv_setex(
                &streak_key(provider_id),
                &serialized,
                config.snapshot_ttl_sec.saturating_mul(4),
            )
            .await;
    }

    Ok(PollOutcome {
        models_seen,
        models_blocked,
        released_by_guard,
    })
}

async fn read_streaks(app: &AppState, provider_id: &str) -> BTreeMap<String, u32> {
    app.runtime_kv_get(&streak_key(provider_id))
        .await
        .ok()
        .flatten()
        .and_then(|raw| serde_json::from_str(&raw).ok())
        .unwrap_or_default()
}

/// 滞回带内需要继承上一轮的禁用结论。读旧快照拿不到就按放行处理（失败开放）。
async fn previous_blocked(app: &AppState, provider_id: &str, model: &str) -> bool {
    app.runtime_kv_get(&snapshot_key(provider_id))
        .await
        .ok()
        .flatten()
        .and_then(|raw| serde_json::from_str::<AmdLoadSnapshot>(&raw).ok())
        .and_then(|snapshot| snapshot.models.get(model).map(|entry| entry.blocked_prev))
        .unwrap_or(false)
}

/// 读取某供应商的当前负载快照，供管理端展示。
pub(crate) async fn read_snapshot(app: &AppState, provider_id: &str) -> Option<AmdLoadSnapshot> {
    app.runtime_kv_get(&snapshot_key(provider_id))
        .await
        .ok()
        .flatten()
        .and_then(|raw| serde_json::from_str(&raw).ok())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn derives_the_load_endpoint_from_the_amd_base_url() {
        assert_eq!(
            load_endpoint_url("https://developer.amd.com.cn/radeon/api/v1").as_deref(),
            Some("https://developer.amd.com.cn/radeon/api/tokenfactory/load")
        );
        assert_eq!(
            load_endpoint_url("https://developer.amd.com.cn/radeon/api/v1/").as_deref(),
            Some("https://developer.amd.com.cn/radeon/api/tokenfactory/load")
        );
        assert_eq!(
            load_endpoint_url("  https://x.test/radeon/api/v1  ").as_deref(),
            Some("https://x.test/radeon/api/tokenfactory/load")
        );
    }

    /// origin 必须原样保留——凭证不能被送到别的主机。
    #[test]
    fn never_changes_the_origin() {
        let derived = load_endpoint_url("https://developer.amd.com.cn/radeon/api/v1").unwrap();
        assert!(derived.starts_with("https://developer.amd.com.cn/"));
    }

    #[test]
    fn rejects_non_amd_and_malformed_base_urls() {
        assert_eq!(load_endpoint_url("https://api.openai.com/v1"), None);
        assert_eq!(load_endpoint_url("not a url"), None);
        assert_eq!(load_endpoint_url(""), None);
    }

    #[test]
    fn recognises_amd_upstreams() {
        assert!(is_amd_upstream(
            "https://developer.amd.com.cn/radeon/api/v1"
        ));
        assert!(is_amd_upstream(
            "https://developer.amd.com.cn/radeon/api/v1/"
        ));
        assert!(!is_amd_upstream("https://api.openai.com/v1"));
        assert!(!is_amd_upstream(""));
    }
}
