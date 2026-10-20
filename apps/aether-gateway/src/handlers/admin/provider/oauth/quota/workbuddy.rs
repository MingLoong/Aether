use super::shared::{
    build_provider_quota_execution_plan, build_quota_snapshot_payload,
    default_provider_quota_execution_timeouts, execute_provider_quota_plan,
    oauth_refresh_auto_removed_result, persist_provider_quota_refresh_state,
    quota_key_auto_removed, quota_refresh_success_invalid_state, ProviderQuotaExecutionOutcome,
};
use crate::handlers::admin::request::{AdminAppState, AdminGatewayProviderTransportSnapshot};
use crate::GatewayError;
use aether_admin::provider::quota::parse_workbuddy_balance_response;
use aether_admin::provider::redaction::admin_provider_metadata_bucket_safe_json;
use aether_contracts::ProxySnapshot;
use aether_data_contracts::repository::provider_catalog::{
    StoredProviderCatalogEndpoint, StoredProviderCatalogKey, StoredProviderCatalogProvider,
};
use aether_provider_pool::{
    build_workbuddy_pool_activity_report_request, build_workbuddy_pool_buddy_agreement_request,
    build_workbuddy_pool_buddy_first_request, build_workbuddy_pool_buddy_info_request,
    build_workbuddy_pool_claim_compensation_request, build_workbuddy_pool_claim_gift_request,
    build_workbuddy_pool_daily_checkin_request, build_workbuddy_pool_global_country_code_request,
    build_workbuddy_pool_global_register_status_request,
    build_workbuddy_pool_global_submit_region_request, build_workbuddy_pool_growth_heatmap_request,
    build_workbuddy_pool_growth_lottery_draw_request,
    build_workbuddy_pool_growth_lottery_summary_request,
    build_workbuddy_pool_growth_makeup_use_request, build_workbuddy_pool_growth_redeem_request,
    build_workbuddy_pool_growth_streak_request, build_workbuddy_pool_quota_request,
    build_workbuddy_pool_task_claim_mp_request, build_workbuddy_pool_task_claim_web_request,
    build_workbuddy_pool_tasks_accept_request, build_workbuddy_pool_tasks_list_request,
    build_workbuddy_pool_travel_claim_request, build_workbuddy_pool_travel_depart_request,
    build_workbuddy_pool_travel_status_request, build_workbuddy_pool_trial_claim_request,
};
use aether_provider_transport::workbuddy::failure::workbuddy_oauth_invalid_reason;
// 账号昵称刷新用（面板 issue #94）——这两个住在 pool 的 workbuddy 子模块里。
use aether_provider_pool::providers::workbuddy::{
    build_workbuddy_pool_account_profile_request, workbuddy_nickname_from_account_profile,
};
use aether_provider_transport::workbuddy::{
    classify_workbuddy_checkin_outcome, classify_workbuddy_global_register_status,
    classify_workbuddy_trial_outcome, decide_workbuddy_travel_action,
    filter_workbuddy_global_intl_countries, is_workbuddy_buddy_task_incomplete,
    is_workbuddy_growth_unavailable, is_workbuddy_report_accepted, parse_workbuddy_claim_credit,
    parse_workbuddy_claim_reward, parse_workbuddy_global_countries, parse_workbuddy_has_buddy,
    parse_workbuddy_heatmap_yesterday_missed, parse_workbuddy_lottery_chances,
    parse_workbuddy_streak_status, parse_workbuddy_tasks, parse_workbuddy_travel_state,
    workbuddy_billing_base_url, workbuddy_billing_path_candidates, workbuddy_cst_yesterday,
    workbuddy_identity, workbuddy_unwrap_envelope, WorkbuddyBillingEndpoint,
    WorkbuddyCheckinOutcome, WorkbuddyGlobalCountry, WorkbuddyGlobalRegisterStatus, WorkbuddyRealm,
    WorkbuddyTravelAction, WorkbuddyTrialOutcome,
};
use serde_json::{json, Value};
use std::time::{SystemTime, UNIX_EPOCH};

/// 对**成功响应**拆 `{code,msg,data}` 信封（面板 `doJSON` 同口径）。
///
/// 面板的 `doJSON` 在校验 `code == 0` 后统一返回 `env.Data`，所以面板里所有解析器
/// （余额 / 签到 / 连登 / 成长任务 / 旅行 / trial / 上报…）拿到的都是**已拆包**的形状。
/// Aether 侧原来把带信封的原始 body 直接交给解析器 → 真机（2026-10-15）表现为
/// 「上游 200 但解析不出字段」（余额响应实为
/// `{"code":0,"msg":"OK","data":{"Response":{"Data":{"Accounts":[…]}}}}`）。
///
/// **只对 2xx 且 `code == 0` 拆**：错误响应的 `code`/`msg` 在信封层，失败分类要用它们。
fn workbuddy_unwrap_success_payload(
    outcome: ProviderQuotaExecutionOutcome,
) -> ProviderQuotaExecutionOutcome {
    let ProviderQuotaExecutionOutcome::Response(mut result) = outcome else {
        return outcome;
    };
    if !(200..300).contains(&result.status_code) {
        return ProviderQuotaExecutionOutcome::Response(result);
    }
    if let Some(body) = result.body.as_mut() {
        if let Some(json) = body.json_body.as_mut() {
            let code = json
                .get("code")
                .and_then(serde_json::Value::as_i64)
                .unwrap_or(0);
            if code == 0 {
                if let Some(data) = json.get("data").cloned() {
                    *json = data;
                }
            }
        }
    }
    ProviderQuotaExecutionOutcome::Response(result)
}

/// 计费维护类调用的瞬时错误重试间隔（面板 `billingRetryDelay` = 2s：
/// 第 1 次重试等 2s、第 2 次等 4s）。
const WORKBUDDY_BILLING_RETRY_DELAY_MS: u64 = 2_000;

/// 传输层失败的固定文案（`execute_provider_quota_plan` 的 Err 分支产生）。
///
/// 面板口径（`isTransientBillingErr`）里「**非 `*Error` 的传输失败**」也算瞬时错误、
/// 值得有界重试；Aether 只有这条文案能把它与「origin 被拦」等**不该重试**的 Failure
/// 区分开。
const WORKBUDDY_TRANSPORT_FAILURE_MARKER: &str = "Provider quota request failed";

/// 这个结果是否值得**有界重试**（面板 `isTransientBillingErr` 同口径）：
/// 只有 **5xx** 与**传输层失败**；4xx / 业务错误 / 限流一律不重试
/// （面板原话：重试只会原样再失败一次）。
fn workbuddy_outcome_is_transient(outcome: &ProviderQuotaExecutionOutcome) -> bool {
    match outcome {
        ProviderQuotaExecutionOutcome::Response(result) => result.status_code >= 500,
        ProviderQuotaExecutionOutcome::Failure(message) => {
            message.trim() == WORKBUDDY_TRANSPORT_FAILURE_MARKER
        }
    }
}

/// 按候选路径依次执行，**只有 404 才换下一条**（面板 `billingMeterJSON` 的口径）。
///
/// 为什么不把「其他错误也换路径」：参数错 / 限流 / 风控 / 5xx 换路径只会原样再失败一次，
/// 还会把同一账号的请求量翻倍。返回**最后一次**的执行结果（调用方按它分类）。
/// 成长中心（`/activity/growth/*`）只有单条候选，也走这里，保持同一套 origin 白名单与超时。
///
/// 另外对**瞬时错误**做有界重试（面板 `retryBillingTransient`：最多补打 2 次、间隔 2s/4s）——
/// 上游偶发 5xx（实测 `code 10000 / API request failed with status code: 500`）不该让当天
/// 的签到/领奖直接作废。**只用于这些低频维护调用**；chat 热路径不走这里（它有自己的换号
/// 轮转语义，重试会放大在途请求）。
async fn execute_workbuddy_specs(
    state: &AdminAppState<'_>,
    transport: &AdminGatewayProviderTransportSnapshot,
    specs: Vec<aether_provider_pool::ProviderPoolQuotaRequestSpec>,
    proxy_override: Option<&ProxySnapshot>,
) -> Result<Option<ProviderQuotaExecutionOutcome>, GatewayError> {
    let proxy = match proxy_override {
        Some(proxy) => Some(proxy.clone()),
        None => {
            state
                .resolve_transport_proxy_snapshot_with_tunnel_affinity(transport)
                .await
        }
    };

    let total = specs.len();
    let mut last = None;
    for (index, spec) in specs.into_iter().enumerate() {
        let mut attempt = 0u64;
        let outcome = loop {
            let timeouts = state
                .resolve_transport_execution_timeouts(transport)
                .or(Some(default_provider_quota_execution_timeouts(
                    proxy.as_ref(),
                )));
            let plan = build_provider_quota_execution_plan(
                transport,
                spec.clone(),
                proxy.clone(),
                state.resolve_transport_profile(transport),
                timeouts,
            );
            let outcome = execute_provider_quota_plan(state, transport, plan, "workbuddy").await?;
            // 最多补打 2 次；首次成功或非瞬时错误立即返回。
            if attempt >= 2 || !workbuddy_outcome_is_transient(&outcome) {
                break workbuddy_unwrap_success_payload(outcome);
            }
            attempt += 1;
            tokio::time::sleep(std::time::Duration::from_millis(
                WORKBUDDY_BILLING_RETRY_DELAY_MS * attempt,
            ))
            .await;
        };
        let status_code = match &outcome {
            ProviderQuotaExecutionOutcome::Response(result) => Some(result.status_code),
            ProviderQuotaExecutionOutcome::Failure(_) => None,
        };
        last = Some(outcome);
        if status_code != Some(404) || index + 1 == total {
            break;
        }
    }
    Ok(last)
}

/// 抽奖每次跑的上限：面板无上限（按 chances 全抽完），但一次跑几十次抽奖对风控不友好，
/// 也给单次维护任务加了时间上界。剩余次数下一轮再抽（幂等）。
const WORKBUDDY_MAX_LOTTERY_DRAWS_PER_RUN: u32 = 20;

/// 连登兑换 + 抽奖（面板 `RunStreakBonusNow` 的核心闭环）。
///
/// 门控（面板同口径）：
/// - **企业号跳过**：无成长体系，`/activity/growth/*` 上游一律 403；
/// - **国际号跳过**：面板 D4 门控——global 没有 CN 任务体系（活跃上报是例外，那个照发）；
/// - 只在**当日首次签到成功后**跑（与活跃上报共用「今天」闸门，天然每天最多一次）。
///
/// 幂等：先读状态，只兑换状态既非 `locked` 也非 `claimed` 的档位（**不拿 403 当控制流**）；
/// 抽奖次数为 0 时不发请求。返回一段摘要进结果 payload。
async fn execute_workbuddy_streak_bonus(
    state: &AdminAppState<'_>,
    transport: &AdminGatewayProviderTransportSnapshot,
    authorization: (String, String),
    proxy_override: Option<&ProxySnapshot>,
) -> Option<serde_json::Value> {
    let identity = workbuddy_identity(transport);
    if identity.realm != WorkbuddyRealm::Cn {
        return None;
    }
    if identity
        .enterprise_id
        .as_deref()
        .map(str::trim)
        .is_some_and(|value| !value.is_empty())
    {
        return None;
    }

    // 成长中心走**对话域**（面板 `growthJSON` 用 `chatBase`）。
    let chat_base = transport.endpoint.base_url.clone();
    let billing_base = workbuddy_billing_base_url(identity.realm);

    // 一次「读连登状态」的封装：返回 (状态码, 解析后的状态)。
    let read_streak = || async {
        let spec = build_workbuddy_pool_growth_streak_request(
            &transport.key.id,
            &chat_base,
            &identity,
            authorization.clone(),
        );
        let outcome = execute_workbuddy_specs(state, transport, vec![spec], proxy_override)
            .await
            .ok()
            .flatten();
        match outcome {
            Some(ProviderQuotaExecutionOutcome::Response(result)) => {
                let status_code = result.status_code;
                let body = result
                    .body
                    .as_ref()
                    .and_then(|body| body.json_body.as_ref())
                    .cloned();
                let parsed = body.as_ref().and_then(parse_workbuddy_streak_status);
                (Some(status_code), body, parsed)
            }
            _ => (None, None, None),
        }
    };

    let (streak_status_code, mut streak_body, mut status) = read_streak().await;
    let Some(streak_status_code) = streak_status_code else {
        return None;
    };
    if is_workbuddy_growth_unavailable(
        streak_status_code,
        streak_body.as_ref().map(|body| body.to_string()).as_deref(),
    ) {
        // 没有成长体系（403）：静默跳过、不报警，但**记一个状态**——
        // 否则运维分不清「上游说没有成长体系」与「本次压根没跑」。
        return Some(json!({"status": "unavailable"}));
    }
    let Some(initial_status) = status.as_ref() else {
        return Some(json!({"status": "unparsable"}));
    };

    // 0. 补签保连登（面板 `makeupYesterday`）：昨日漏签且**有补签卡**才补——
    //    连登一断就要重攒 7 天，所以这一步在兑换之前。
    let yesterday = workbuddy_cst_yesterday(unix_now_secs());
    let mut makeup_used = false;
    if initial_status.makeup_cards > 0 {
        let heatmap_spec = build_workbuddy_pool_growth_heatmap_request(
            &transport.key.id,
            &chat_base,
            &identity,
            authorization.clone(),
        );
        let heatmap_outcome =
            execute_workbuddy_specs(state, transport, vec![heatmap_spec], proxy_override)
                .await
                .ok()
                .flatten();
        let missed = match &heatmap_outcome {
            Some(ProviderQuotaExecutionOutcome::Response(result))
                if (200..300).contains(&result.status_code) =>
            {
                result
                    .body
                    .as_ref()
                    .and_then(|body| body.json_body.as_ref())
                    .is_some_and(|body| parse_workbuddy_heatmap_yesterday_missed(body, &yesterday))
            }
            _ => false,
        };
        if missed {
            let makeup_spec = build_workbuddy_pool_growth_makeup_use_request(
                &transport.key.id,
                &chat_base,
                &identity,
                authorization.clone(),
                &yesterday,
            );
            let makeup_outcome =
                execute_workbuddy_specs(state, transport, vec![makeup_spec], proxy_override)
                    .await
                    .ok()
                    .flatten();
            makeup_used = matches!(
                makeup_outcome,
                Some(ProviderQuotaExecutionOutcome::Response(ref result))
                    if (200..300).contains(&result.status_code)
            );
            if makeup_used {
                // 补签后连登天数变了，档位可能刚解锁 → 重新读一次状态（一天最多一次）。
                let (_, refreshed_body, refreshed_status) = read_streak().await;
                if let Some(refreshed_status) = refreshed_status {
                    status = Some(refreshed_status);
                    if refreshed_body.is_some() {
                        streak_body = refreshed_body;
                    }
                }
            }
        }
    }

    // 0.5 新手礼包 / 活动补偿（面板顺序：礼包 → 补偿；每号一次，已领是业务错误，静默）。
    let mut gift_credit = None;
    let mut compensation_credit = None;
    for (kind, spec) in [
        (
            "gift",
            build_workbuddy_pool_claim_gift_request(
                &transport.key.id,
                billing_base,
                &identity,
                authorization.clone(),
            ),
        ),
        (
            "compensation",
            build_workbuddy_pool_claim_compensation_request(
                &transport.key.id,
                billing_base,
                &identity,
                authorization.clone(),
            ),
        ),
    ] {
        let outcome = execute_workbuddy_specs(state, transport, vec![spec], proxy_override)
            .await
            .ok()
            .flatten();
        let credit = match &outcome {
            Some(ProviderQuotaExecutionOutcome::Response(result))
                if (200..300).contains(&result.status_code) =>
            {
                result
                    .body
                    .as_ref()
                    .and_then(|body| body.json_body.as_ref())
                    .map(parse_workbuddy_claim_credit)
            }
            _ => None,
        };
        match kind {
            "gift" => gift_credit = credit,
            _ => compensation_credit = credit,
        }
    }

    let Some(status) = status else {
        return Some(json!({"status": "unparsable"}));
    };
    let redeemable =
        status.redeemable_tiers(streak_body.as_ref().unwrap_or(&serde_json::Value::Null));

    let mut redeemed = Vec::new();
    for tier in &redeemable {
        let spec = build_workbuddy_pool_growth_redeem_request(
            &transport.key.id,
            &chat_base,
            &identity,
            authorization.clone(),
            tier,
        );
        let outcome = execute_workbuddy_specs(state, transport, vec![spec], proxy_override)
            .await
            .ok()
            .flatten();
        let accepted = matches!(
            outcome,
            Some(ProviderQuotaExecutionOutcome::Response(ref result))
                if (200..300).contains(&result.status_code)
        );
        if accepted {
            redeemed.push(tier.clone());
        }
    }

    let summary_spec = build_workbuddy_pool_growth_lottery_summary_request(
        &transport.key.id,
        &chat_base,
        &identity,
        authorization.clone(),
    );
    let summary_outcome =
        execute_workbuddy_specs(state, transport, vec![summary_spec], proxy_override)
            .await
            .ok()
            .flatten();
    let chances = match &summary_outcome {
        Some(ProviderQuotaExecutionOutcome::Response(result))
            if (200..300).contains(&result.status_code) =>
        {
            result
                .body
                .as_ref()
                .and_then(|body| body.json_body.as_ref())
                .map(parse_workbuddy_lottery_chances)
                .unwrap_or(0)
        }
        _ => 0,
    };

    let mut draws = 0u32;
    for _ in 0..chances.min(WORKBUDDY_MAX_LOTTERY_DRAWS_PER_RUN) {
        let spec = build_workbuddy_pool_growth_lottery_draw_request(
            &transport.key.id,
            &chat_base,
            &identity,
            authorization.clone(),
        );
        let outcome = execute_workbuddy_specs(state, transport, vec![spec], proxy_override)
            .await
            .ok()
            .flatten();
        let accepted = matches!(
            outcome,
            Some(ProviderQuotaExecutionOutcome::Response(ref result))
                if (200..300).contains(&result.status_code)
        );
        if !accepted {
            break;
        }
        draws += 1;
    }

    Some(json!({
        "streak_days": status.days,
        "makeup_cards": status.makeup_cards,
        "makeup_used": makeup_used,
        "makeup_target_date": if makeup_used { json!(yesterday) } else { serde_json::Value::Null },
        "gift_credit": gift_credit,
        "compensation_credit": compensation_credit,
        "redeemable_tiers": redeemable,
        "redeemed_tiers": redeemed,
        "lottery_chances": chances,
        "lottery_draws": draws,
    }))
}
/// 领养链路里给上游处理「活跃上报」留的时间（面板 `adoptReportGap` = 1.05s，
/// 对齐脚本实测：上报后立刻调 `buddy/first` 会被判「任务未完成」）。
const WORKBUDDY_ADOPT_REPORT_GAP_MS: u64 = 1050;

/// 猫猫旅行巡检（面板 `RunTravelNow` 的单账号一趟）。
///
/// 门控：**国际号 / 企业号跳过**（面板同口径：global 无 CN 任务体系、企业号无成长体系）。
///
/// 状态机（面板 `travelOne`）：无猫 → 领养链路（先上报解锁 `first_buddy` → 等上游处理 →
/// `agreement` → `first`）；到站 → 领奖（必须带 `record_id`）；空闲且未达当日上限 → 派出；
/// 在途 / 已达上限 / 状态未知 → 跳过。**一趟只做一个动作、不轮询不等待**——
/// 派出的次日状态自然变成 `arrived`，跨天由下一次巡检推进。
///
/// 「领养门槛未达」是预期行为（当日无活跃上报时上游返回 400）：记一次
/// `first_buddy_incomplete` 就收工，当天不再重试（本函数本身每天最多跑一次）。
async fn execute_workbuddy_travel(
    state: &AdminAppState<'_>,
    transport: &AdminGatewayProviderTransportSnapshot,
    authorization: (String, String),
    proxy_override: Option<&ProxySnapshot>,
) -> Option<serde_json::Value> {
    let identity = workbuddy_identity(transport);
    if identity.realm != WorkbuddyRealm::Cn {
        return None;
    }
    if identity
        .enterprise_id
        .as_deref()
        .map(str::trim)
        .is_some_and(|value| !value.is_empty())
    {
        return None;
    }
    let chat_base = transport.endpoint.base_url.clone();

    // 一次请求的封装：返回 (状态码, 响应体)。
    let send = |spec: aether_provider_pool::ProviderPoolQuotaRequestSpec| async {
        let outcome = execute_workbuddy_specs(state, transport, vec![spec], proxy_override)
            .await
            .ok()
            .flatten();
        match outcome {
            Some(ProviderQuotaExecutionOutcome::Response(result)) => {
                let status_code = result.status_code;
                let body = result
                    .body
                    .as_ref()
                    .and_then(|body| body.json_body.as_ref())
                    .cloned();
                (Some(status_code), body)
            }
            _ => (None, None),
        }
    };

    // 1. 有猫吗？
    let (info_status, info_body) = send(build_workbuddy_pool_buddy_info_request(
        &transport.key.id,
        &chat_base,
        &identity,
        authorization.clone(),
    ))
    .await;
    let Some(info_status) = info_status else {
        return None;
    };
    if !(200..300).contains(&info_status) {
        return Some(
            json!({"action": "skip", "reason": "buddy_info_failed", "status_code": info_status}),
        );
    }
    let has_buddy = info_body.as_ref().is_some_and(parse_workbuddy_has_buddy);

    // 2a. 无猫 → 领养：先上报（解锁 first_buddy）→ 等上游处理 → agreement → first。
    if !has_buddy {
        let report_spec = build_workbuddy_pool_activity_report_request(
            &transport.key.id,
            workbuddy_billing_base_url(identity.realm),
            aether_provider_transport::workbuddy::WORKBUDDY_REPORT_PATH,
            &identity,
            authorization.clone(),
            identity.uid.as_deref().unwrap_or_default(),
            unix_now_millis(),
        );
        let _ = send(report_spec).await;
        tokio::time::sleep(std::time::Duration::from_millis(
            WORKBUDDY_ADOPT_REPORT_GAP_MS,
        ))
        .await;

        let (agreement_status, _) = send(build_workbuddy_pool_buddy_agreement_request(
            &transport.key.id,
            &chat_base,
            &identity,
            authorization.clone(),
        ))
        .await;
        if !agreement_status.is_some_and(|status| (200..300).contains(&status)) {
            return Some(json!({"action": "adopt", "result": "agreement_failed"}));
        }
        let (first_status, first_body) = send(build_workbuddy_pool_buddy_first_request(
            &transport.key.id,
            &chat_base,
            &identity,
            authorization.clone(),
        ))
        .await;
        let Some(first_status) = first_status else {
            return Some(json!({"action": "adopt", "result": "request_failed"}));
        };
        if (200..300).contains(&first_status) {
            return Some(json!({"action": "adopt", "result": "adopted"}));
        }
        let body_text = first_body.map(|body| body.to_string());
        let result = if is_workbuddy_buddy_task_incomplete(first_status, body_text.as_deref()) {
            "first_buddy_incomplete"
        } else {
            "failed"
        };
        return Some(json!({
            "action": "adopt",
            "result": result,
            "status_code": first_status,
        }));
    }

    // 2b. 有猫 → 看状态决定：到站领奖 / 空闲派出 / 其余跳过。
    let (status_status, status_body) = send(build_workbuddy_pool_travel_status_request(
        &transport.key.id,
        &chat_base,
        &identity,
        authorization.clone(),
    ))
    .await;
    let Some(status_status) = status_status else {
        return None;
    };
    if !(200..300).contains(&status_status) {
        return Some(
            json!({"action": "skip", "reason": "status_failed", "status_code": status_status}),
        );
    }
    let parsed = status_body.as_ref().and_then(parse_workbuddy_travel_state);
    match decide_workbuddy_travel_action(true, parsed.as_ref()) {
        WorkbuddyTravelAction::Claim { record_id } => {
            let (claim_status, claim_body) = send(build_workbuddy_pool_travel_claim_request(
                &transport.key.id,
                &chat_base,
                &identity,
                authorization.clone(),
                record_id,
            ))
            .await;
            let reward = claim_body.as_ref().map(parse_workbuddy_claim_credit);
            Some(json!({
                "action": "claim",
                "record_id": record_id,
                "reward_credit": reward,
                "accepted": claim_status.is_some_and(|status| (200..300).contains(&status)),
            }))
        }
        WorkbuddyTravelAction::Depart => {
            let (depart_status, _) = send(build_workbuddy_pool_travel_depart_request(
                &transport.key.id,
                &chat_base,
                &identity,
                authorization.clone(),
            ))
            .await;
            Some(json!({
                "action": "depart",
                "location_id": aether_provider_transport::workbuddy::WORKBUDDY_TRAVEL_LOCATION_ID,
                "accepted": depart_status.is_some_and(|status| (200..300).contains(&status)),
            }))
        }
        // 无猫分支已在上面处理；这里只剩 Skip。
        WorkbuddyTravelAction::Skip { reason } => Some(json!({"action": "skip", "reason": reason})),
        WorkbuddyTravelAction::Adopt => Some(json!({"action": "skip", "reason": "state_mismatch"})),
    }
}
///
/// 每轮最多领取的任务数（面板不设上限；这里给维护任务加个时间上界，剩余下轮再领，幂等）。
const WORKBUDDY_MAX_TASK_CLAIMS_PER_RUN: usize = 20;

/// 成长任务闭环（面板 `acceptPendingTasks` + 领奖）。
///
/// 顺序：**列表（默认口径 ∪ 小程序口径，按 task_code 去重）→ 批量报名 → 领取可领任务**。
///
/// 门控与连登/旅行一致：**国际号 / 企业号跳过**（任务体系只在 CN）。
///
/// 两个端点的选择有讲究（面板踩过坑）：
/// - **报名**：默认口径走对话域 `POST /v2/activity/growth/tasks/accept`；只在 mp 列表里
///   出现的任务要走 mp 口径（缺 `x-client-platform: miniprogram` 头上游返回 task not found）。
/// - **领奖**：普通任务走**官网域** `POST {web}/activity/growth/tasks/{code}/claim`
///   （task_code 在路径里、无 body、web 头族）——CLI 域那条
///   `/v2/activity/growth/tasks/reward/claim` **根本不存在**（面板实测一直 400）；
///   小程序码走对话域同路径 + mp 头，**400 时降级官网域**。
async fn execute_workbuddy_tasks(
    state: &AdminAppState<'_>,
    transport: &AdminGatewayProviderTransportSnapshot,
    authorization: (String, String),
    proxy_override: Option<&ProxySnapshot>,
) -> Option<serde_json::Value> {
    let identity = workbuddy_identity(transport);
    if identity.realm != WorkbuddyRealm::Cn {
        return None;
    }
    if identity
        .enterprise_id
        .as_deref()
        .map(str::trim)
        .is_some_and(|value| !value.is_empty())
    {
        return None;
    }
    let chat_base = transport.endpoint.base_url.clone();
    let web_base = aether_provider_transport::workbuddy::WORKBUDDY_WEB_BASE_URL_CN;

    // 一次「发一个 spec、拿 (状态码, body)」的封装。
    let send = |spec: aether_provider_pool::ProviderPoolQuotaRequestSpec| async {
        let outcome = execute_workbuddy_specs(state, transport, vec![spec], proxy_override)
            .await
            .ok()
            .flatten();
        match outcome {
            Some(ProviderQuotaExecutionOutcome::Response(result)) => {
                let status_code = result.status_code;
                let body = result
                    .body
                    .as_ref()
                    .and_then(|body| body.json_body.as_ref())
                    .cloned();
                (Some(status_code), body)
            }
            _ => (None, None),
        }
    };

    // 1. 两个口径的列表（mp 是默认口径的超集，按 task_code 去重，默认口径优先）。
    let mut tasks: Vec<aether_provider_transport::workbuddy::WorkbuddyTask> = Vec::new();
    let mut mp_only: std::collections::BTreeSet<String> = std::collections::BTreeSet::new();
    for miniprogram in [false, true] {
        let (status, body) = send(build_workbuddy_pool_tasks_list_request(
            &transport.key.id,
            &chat_base,
            &identity,
            authorization.clone(),
            miniprogram,
        ))
        .await;
        let Some(status) = status else {
            continue;
        };
        if !(200..300).contains(&status) {
            continue;
        }
        for task in body.as_ref().map(parse_workbuddy_tasks).unwrap_or_default() {
            if tasks.iter().any(|known| known.task_code == task.task_code) {
                continue;
            }
            if miniprogram {
                mp_only.insert(task.task_code.clone());
            }
            tasks.push(task);
        }
    }
    if tasks.is_empty() {
        return Some(json!({"listed": 0}));
    }

    // 2. 批量报名：默认口径与 mp 口径分开提交（mp 限定任务缺头会 task not found）。
    let (pending_default, pending_mp): (Vec<String>, Vec<String>) = tasks
        .iter()
        .filter(|task| task.needs_accept())
        .map(|task| task.task_code.clone())
        .partition(|code| !mp_only.contains(code));
    let mut accepted = 0usize;
    let pending_total = pending_default.len() + pending_mp.len();
    for (codes, miniprogram) in [(pending_default, false), (pending_mp, true)] {
        if codes.is_empty() {
            continue;
        }
        let (status, _) = send(build_workbuddy_pool_tasks_accept_request(
            &transport.key.id,
            &chat_base,
            &identity,
            authorization.clone(),
            &codes,
            miniprogram,
        ))
        .await;
        if status.is_some_and(|status| (200..300).contains(&status)) {
            accepted += codes.len();
        }
    }

    // 3. 领奖：只领 claimable 的；小程序码走 mp 端点、400 时降级官网域。
    let mut claimed = Vec::new();
    let mut credits = 0i64;
    for task in tasks.iter().filter(|task| task.claimable) {
        if claimed.len() >= WORKBUDDY_MAX_TASK_CLAIMS_PER_RUN {
            break;
        }
        let (status, body) = if mp_only.contains(&task.task_code) {
            let (status, body) = send(build_workbuddy_pool_task_claim_mp_request(
                &transport.key.id,
                &chat_base,
                &identity,
                authorization.clone(),
                &task.task_code,
            ))
            .await;
            // 对话域对部分任务/租户形态 400 → 降级官网域（面板实测可领）。
            if status == Some(400) {
                send(build_workbuddy_pool_task_claim_web_request(
                    &transport.key.id,
                    web_base,
                    &identity,
                    authorization.clone(),
                    &task.task_code,
                ))
                .await
            } else {
                (status, body)
            }
        } else {
            send(build_workbuddy_pool_task_claim_web_request(
                &transport.key.id,
                web_base,
                &identity,
                authorization.clone(),
                &task.task_code,
            ))
            .await
        };
        let Some(status) = status else {
            continue;
        };
        if !(200..300).contains(&status) {
            continue;
        }
        let (credit, energy, already_claimed) = body
            .as_ref()
            .map(parse_workbuddy_claim_reward)
            .unwrap_or((0, 0, false));
        credits += credit;
        claimed.push(json!({
            "task_code": task.task_code,
            "credit": credit,
            "energy": energy,
            "already_claimed": already_claimed,
        }));
    }

    Some(json!({
        "listed": tasks.len(),
        "pending": pending_total,
        "accepted": accepted,
        "claimable": tasks.iter().filter(|task| task.claimable).count(),
        "claimed": claimed,
        "credits": credits,
        // 任务**全量明细**（名称/奖励/进度/状态/类型）：任务表 UI 的数据源。
        "tasks_detail": workbuddy_tasks_detail(&tasks),
        "tasks_fetched_at": unix_now_secs(),
    }))
}

/// 任务明细序列化（面板 `upstream.Task` 的字段口径）——任务表 UI 的数据源。
/// `task_type == "single"` 标记一次性任务（批次 2 的桌面事件**绝不重发**依据之一）。
fn workbuddy_tasks_detail(
    tasks: &[aether_provider_transport::workbuddy::WorkbuddyTask],
) -> Vec<serde_json::Value> {
    tasks
        .iter()
        .map(|task| {
            json!({
                "task_code": task.task_code,
                "title": task.title,
                "description": task.description,
                "task_desc": task.task_desc,
                "credit": task.credit,
                "energy": task.energy,
                "has_reward": task.has_reward,
                "reward_buddy": task.reward_buddy,
                "jump_url": task.jump_url,
                "task_type": task.task_type,
                "tag": task.tag,
                "current": task.current,
                "target": task.target,
                "locked": task.locked,
                "claimable": task.claimable,
                "claimed": task.claimed,
                "accept_status": task.accept_status,
                "status": task.status,
            })
        })
        .collect()
}

/// **只读**任务目录刷新：只做两个口径的列表 GET（不报名、不领奖）。
///
/// 为什么需要它：报名/领奖是**动作**，必须守「当日首签」闸门（面板口径）；但任务
/// **目录**是只读数据，只在闸门内抓会造成一个真实的生产问题——如果用户自己的
/// 客户端先把今天的签到了，网关永远看不到 `first_checkin_today`，任务表就一直空着。
/// 所以目录允许在「缺失或超过 24h」时单独补一次 GET。
/// 账号昵称刷新（面板 `internal/upstream/profile.go`，issue #94：改名后**免重登**同步昵称）。
///
/// 只在**手动刷新**入口调用（后台余额轮询不调——面板同款约束）。
///
/// ⚠️ 隐私边界（与面板一致）：该接口响应含手机号等敏感信息，这里**只**取 `nickname`/`uid`，
/// 其余字段不解析、不落日志、不透传；`uid` 与凭证不一致 → 丢弃（防串号）。
///
/// 域处理：面板的 `webBase(a)` **是 realm 感知的**（global → `workbuddy.ai` ✓），所以这里也按域
/// 取官网 base ✓ 并让 Referer 与 base 同域 ✓（旧实现直接对国际域 `return None` ✗ —— 那是
/// 「宁缺勿错」的保守做法 ✓，但会让国际号永远没有昵称 ✗）。失败**返回原因**（调用方落库），
/// 不再静默吞掉 ✓。
pub(crate) async fn fetch_workbuddy_account_nickname(
    state: &AdminAppState<'_>,
    transport: &AdminGatewayProviderTransportSnapshot,
    authorization: (String, String),
    proxy_override: Option<&ProxySnapshot>,
) -> Result<String, String> {
    let identity = workbuddy_identity(transport);
    let web_base = match identity.realm {
        // 国际官网域与计费域同域（面板 `defaultGlobalBase`）。
        WorkbuddyRealm::Global => {
            aether_provider_transport::workbuddy::WORKBUDDY_BILLING_BASE_URL_GLOBAL
        }
        WorkbuddyRealm::Cn => aether_provider_transport::workbuddy::WORKBUDDY_WEB_BASE_URL_CN,
    };
    let expected_uid = identity.uid.clone().unwrap_or_default();
    let spec = build_workbuddy_pool_account_profile_request(
        &transport.key.id,
        web_base,
        &identity,
        authorization,
    );
    let outcome = execute_workbuddy_specs(state, transport, vec![spec], proxy_override)
        .await
        .ok()
        .flatten();
    let Some(ProviderQuotaExecutionOutcome::Response(result)) = outcome else {
        return Err("资料请求执行失败".to_string());
    };
    if !(200..300).contains(&result.status_code) {
        return Err(format!("资料接口 HTTP {}", result.status_code));
    }
    let body = result
        .body
        .as_ref()
        .and_then(|body| body.json_body.as_ref())
        .ok_or_else(|| "资料响应没有 JSON body".to_string())?;
    workbuddy_nickname_from_account_profile(body, expected_uid.as_str())
        .ok_or_else(|| "资料响应里没有可用昵称（或 uid 不一致）".to_string())
}

/// 该 metadata 里是否已有**非空**的 workbuddy 目录快照（决定要不要补拉 ✓）。
///
/// 空数组/空对象都算「没有」✓ —— 导入凭据进来的账号正是这种形态 ✓（用户实测）。
fn workbuddy_catalog_snapshot_present(metadata: Option<&Value>) -> bool {
    metadata
        .and_then(|metadata| metadata.get("workbuddy"))
        .and_then(|workbuddy| workbuddy.get("models"))
        .is_some_and(|models| match models {
            Value::Array(items) => !items.is_empty(),
            Value::Object(map) => !map.is_empty(),
            _ => false,
        })
}

/// 该账号还没有上游目录快照时**补拉一次**（复用管理端「查询上游模型」同一条链路 ✓）。
///
/// 为什么需要：上游目录是**按 key 拉**的 —— 走过登录流程的账号顺手带上了 ✓，而**导入凭据**
/// 进来的账号没人触发 ✗（用户实测：导入国际号后「上游模型能力与倍率」只显示国内模型 ✗）。
/// 幂等：已有非空快照直接返回 `None`（摘要里就是 `null` = 本次没跑 ✓）。
async fn ensure_workbuddy_catalog_snapshot(
    state: &AdminAppState<'_>,
    transport: &AdminGatewayProviderTransportSnapshot,
) -> Option<serde_json::Value> {
    if workbuddy_catalog_snapshot_present(transport.key.upstream_metadata.as_ref()) {
        return None;
    }
    let payload = json!({
        "provider_id": transport.key.provider_id,
        "api_key_id": transport.key.id,
        "force_refresh": true,
    });
    // 复用管理端那条链路（与后台「查询上游模型」按钮**同一个函数** ✓，行为一致 ✓）。
    // 注意：这里只报**调用结果**（HTTP 码 ✓）——目录到底有没有落盘，看快照/面板最准 ✓。
    match crate::handlers::admin::provider::query::models::
        build_admin_provider_query_models_response(state, &payload)
        .await
    {
        Ok(response) => Some(json!({
            "status": if response.status().is_success() { "ok" } else { "failed" },
            "http": response.status().as_u16(),
        })),
        Err(_) => Some(json!({"status": "failed"})),
    }
}

async fn fetch_workbuddy_tasks_catalog(
    state: &AdminAppState<'_>,
    transport: &AdminGatewayProviderTransportSnapshot,
    authorization: (String, String),
    proxy_override: Option<&ProxySnapshot>,
) -> Option<serde_json::Value> {
    let identity = workbuddy_identity(transport);
    if identity.realm != WorkbuddyRealm::Cn {
        return None;
    }
    if identity
        .enterprise_id
        .as_deref()
        .map(str::trim)
        .is_some_and(|value| !value.is_empty())
    {
        return None;
    }
    let chat_base = transport.endpoint.base_url.clone();

    let mut tasks: Vec<aether_provider_transport::workbuddy::WorkbuddyTask> = Vec::new();
    for miniprogram in [false, true] {
        let spec = build_workbuddy_pool_tasks_list_request(
            &transport.key.id,
            &chat_base,
            &identity,
            authorization.clone(),
            miniprogram,
        );
        let outcome = execute_workbuddy_specs(state, transport, vec![spec], proxy_override)
            .await
            .ok()
            .flatten();
        let Some(ProviderQuotaExecutionOutcome::Response(result)) = outcome else {
            continue;
        };
        if !(200..300).contains(&result.status_code) {
            continue;
        }
        let body = result
            .body
            .as_ref()
            .and_then(|body| body.json_body.as_ref())
            .cloned();
        for task in body.as_ref().map(parse_workbuddy_tasks).unwrap_or_default() {
            if tasks.iter().any(|known| known.task_code == task.task_code) {
                continue;
            }
            tasks.push(task);
        }
    }
    if tasks.is_empty() {
        return None;
    }
    Some(json!({
        "listed": tasks.len(),
        "tasks_detail": workbuddy_tasks_detail(&tasks),
        "tasks_fetched_at": unix_now_secs(),
    }))
}

/// 桌面动作需要的任务视图（守卫只看这几个字段）。
///
/// 之所以不直接用 `WorkbuddyTask`：任务目录可能是**本轮抓的**（typed），也可能是
/// **继承上一轮的 JSON**（`tasks_detail`）——两者都归一到这个视图，守卫逻辑只有一份。
#[derive(Debug, Clone)]
struct WorkbuddyDesktopTaskView {
    task_code: String,
    title: String,
    claimed: bool,
    current: i64,
    target: i64,
}

impl WorkbuddyDesktopTaskView {
    fn from_task(task: &aether_provider_transport::workbuddy::WorkbuddyTask) -> Self {
        Self {
            task_code: task.task_code.clone(),
            title: task.title.clone(),
            claimed: task.claimed,
            current: task.current,
            target: task.target,
        }
    }

    fn from_detail(value: &serde_json::Value) -> Self {
        Self {
            task_code: value
                .get("task_code")
                .and_then(serde_json::Value::as_str)
                .unwrap_or_default()
                .to_string(),
            title: value
                .get("title")
                .and_then(serde_json::Value::as_str)
                .unwrap_or_default()
                .to_string(),
            claimed: value
                .get("claimed")
                .and_then(serde_json::Value::as_bool)
                .unwrap_or(false),
            current: value
                .get("current")
                .and_then(serde_json::Value::as_i64)
                .unwrap_or(0),
            target: value
                .get("target")
                .and_then(serde_json::Value::as_i64)
                .unwrap_or(0),
        }
    }
}

/// 桌面动作是否该发（**防重复守卫**，抽成纯函数便于单测）。
///
/// 返回 `false` 表示**一个请求都不能发**。三条规则（对应用户最关心的问题
/// 「做过的一次性任务别重复做，有些要发请求」）：
///
/// 1. `claimed`（已领取，一次性任务的终态）→ 不再发；
/// 2. `target > 0 && current >= target`（进度已满）→ 不再发；
/// 3. 本地水位里有该 code（上游进度回写有延迟，只看状态可能重发）→ 不再发。
fn workbuddy_desktop_action_due(
    task: &WorkbuddyDesktopTaskView,
    sent: &std::collections::BTreeSet<String>,
) -> bool {
    if task.claimed {
        return false;
    }
    if task.target > 0 && task.current >= task.target {
        return false;
    }
    !sent.contains(&task.task_code)
}

/// 当天日期键（Asia/Shanghai，`YYYY-MM-DD`）——桌面动作「每天最多一轮」的闸门。
fn workbuddy_today_key() -> String {
    let offset = chrono::FixedOffset::east_opt(8 * 60 * 60).expect("CST offset");
    chrono::DateTime::from_timestamp(unix_now_secs() as i64, 0)
        .unwrap_or_else(|| chrono::DateTime::from_timestamp(0, 0).expect("epoch"))
        .with_timezone(&offset)
        .format("%Y-%m-%d")
        .to_string()
}

/// 桌面/Web **行为事件**上报（面板 `autoActions` 的纯事件子集）。
///
/// # 防重复（这是本模块最重要的约束）
///
/// 面板 `runAutoAll` 的守卫在这里**逐条复刻**，另加一道本地水位：
///
/// 1. 任务不在列表里 → 跳过；
/// 2. `claimed` 或 `current >= target`（`target > 0`）→ **跳过，一个请求都不发**；
/// 3. 本地水位 `already_sent` 里已有该 code → 跳过（上游进度回写有延迟，只靠状态可能重发）；
/// 4. 整个阶段每天最多一轮（`desktop_ran_on`，调用方判断）。
///
/// 一次性任务（`task_type == "single"`）完成后即终态，上层因此**绝不会**对已领取的任务
/// 重复发送行为事件。
///
/// 返回 `(结果摘要, 本轮新发过的 code)`；后者由调用方持久化进水位。
async fn execute_workbuddy_desktop_actions(
    state: &AdminAppState<'_>,
    transport: &AdminGatewayProviderTransportSnapshot,
    authorization: (String, String),
    proxy_override: Option<&ProxySnapshot>,
    tasks: &[WorkbuddyDesktopTaskView],
    already_sent: &std::collections::BTreeSet<String>,
) -> (serde_json::Value, Vec<String>) {
    use aether_provider_pool::providers::workbuddy as wb_pool;
    use aether_provider_transport::workbuddy::desktop as wb_desktop;

    let identity = workbuddy_identity(transport);
    if identity.realm != WorkbuddyRealm::Cn {
        return (json!({ "skipped": "非国内域" }), Vec::new());
    }
    if identity
        .enterprise_id
        .as_deref()
        .map(str::trim)
        .is_some_and(|value| !value.is_empty())
    {
        return (json!({ "skipped": "企业号无任务中心" }), Vec::new());
    }

    let chat_base = transport.endpoint.base_url.clone();
    let uid = identity.uid.clone().unwrap_or_default();
    let nickname = transport.key.name.clone();

    // 嵌套 async fn（不捕获外层，避免闭包 + async 的借用冲突）。
    //
    // 「发一个 spec、拿状态码」——与成长任务侧同一手法。
    async fn send_status(
        state: &AdminAppState<'_>,
        transport: &AdminGatewayProviderTransportSnapshot,
        proxy_override: Option<&ProxySnapshot>,
        spec: aether_provider_pool::ProviderPoolQuotaRequestSpec,
    ) -> Option<u16> {
        let outcome = execute_workbuddy_specs(state, transport, vec![spec], proxy_override)
            .await
            .ok()
            .flatten();
        match outcome {
            Some(ProviderQuotaExecutionOutcome::Response(result)) => Some(result.status_code),
            _ => None,
        }
    }

    // 桌面事件数组 → 上报（返回是否 2xx）。
    async fn report_desktop(
        state: &AdminAppState<'_>,
        transport: &AdminGatewayProviderTransportSnapshot,
        identity: &aether_provider_transport::workbuddy::WorkbuddyIdentity,
        chat_base: &str,
        uid: &str,
        nickname: &str,
        authorization: &(String, String),
        proxy_override: Option<&ProxySnapshot>,
        events: Vec<wb_desktop::WorkbuddyDesktopEvent>,
    ) -> bool {
        let now_millis = unix_now_millis() as i64;
        let payload =
            wb_desktop::workbuddy_desktop_event_payload(uid, nickname, now_millis, &events);
        let request_id_header = format!(
            "{}{}",
            wb_desktop::workbuddy_derive_id(uid, "req"),
            now_millis.unsigned_abs() % 1_000_000
        );
        let spec = wb_pool::build_workbuddy_pool_desktop_report_request(
            &transport.key.id,
            chat_base,
            identity,
            authorization.clone(),
            &request_id_header,
            payload,
        );
        send_status(state, transport, proxy_override, spec)
            .await
            .is_some_and(|status| (200..300).contains(&status))
    }

    let find_task = |code: &str| tasks.iter().find(|task| task.task_code == code);
    let mut results: Vec<serde_json::Value> = Vec::new();
    let mut sent_now: Vec<String> = Vec::new();

    // 顺序照面板 autoActions（依赖序）；每项都走同一套守卫。
    for code in [
        "RichMeow_Chat",
        "Buddy_App",
        "Buddy_App_QQ",
        "automation_1",
        "Library_read",
        "template_5",
        "playbook_prompt",
        "create_canvas",
        "Hp_Appearance",
        // Tier 2：需要**真实对话**取服务端 requestId 才能点亮（Tier 1 的纯事件对它们无效）。
        "skill_1",
        "Expert_lighthouse",
        "expert_5",
        "Expert_team_use_3",
        "black_cat",
    ] {
        let Some(task) = find_task(code) else {
            continue;
        };
        // 防重复守卫（纯函数，单测覆盖）：已领取 / 已达标 / 水位里有 → 一个请求都不发。
        if !workbuddy_desktop_action_due(task, already_sent) {
            let reason = if task.claimed {
                "已领取（一次性任务终态）"
            } else if task.target > 0 && task.current >= task.target {
                "进度已达标"
            } else {
                "本地水位：本轮之前已发送过行为事件"
            };
            results.push(json!({
                "task_code": code,
                "status": "skipped",
                "message": reason,
            }));
            continue;
        }

        let millis = unix_now_millis();
        let conversation_id = format!("aether-wb-{code}-{millis}");
        let request_id = format!("aether-wb-req-{millis}");
        let message_id = format!("aether-wb-msg-{millis}");

        let mut detail: Option<serde_json::Value> = None;
        let (ok, message) = match code {
            "RichMeow_Chat" => {
                let events = wb_desktop::workbuddy_desktop_chat_sequence(
                    &conversation_id,
                    &request_id,
                    &message_id,
                    "fast-model",
                    "fast-model",
                    millis as i64,
                );
                let ok = report_desktop(
                    state,
                    transport,
                    &identity,
                    &chat_base,
                    &uid,
                    &nickname,
                    &authorization,
                    proxy_override,
                    events,
                )
                .await;
                (
                    ok,
                    "桌面指纹对话事件链（agent_task_created → chat_request_response）",
                )
            }
            "Buddy_App" | "Buddy_App_QQ" => {
                let events = wb_desktop::workbuddy_desktop_buddy_app_sequence(
                    wb_desktop::WORKBUDDY_BUDDY_APP_ID,
                    wb_desktop::WORKBUDDY_BUDDY_APP_NAME,
                );
                let ok = report_desktop(
                    state,
                    transport,
                    &identity,
                    &chat_base,
                    &uid,
                    &nickname,
                    &authorization,
                    proxy_override,
                    events,
                )
                .await;
                (
                    ok,
                    "进入 Buddy 应用五连事件（同时覆盖 Buddy_App 与 Buddy_App_QQ）",
                )
            }
            "automation_1" => {
                let events =
                    wb_desktop::workbuddy_desktop_automation_create_event("Aether 自动化任务");
                let ok = report_desktop(
                    state,
                    transport,
                    &identity,
                    &chat_base,
                    &uid,
                    &nickname,
                    &authorization,
                    proxy_override,
                    events,
                )
                .await;
                (ok, "定时任务创建成功事件")
            }
            "Library_read" => {
                let now_millis = unix_now_millis() as i64;
                let payload = wb_desktop::workbuddy_web_event_payload(
                    "web_element_click",
                    wb_desktop::WORKBUDDY_LIBRARY_DOC_URL,
                    wb_desktop::WORKBUDDY_LIBRARY_ELEMENT_ID,
                    wb_desktop::WORKBUDDY_LIBRARY_ELEMENT_NAME,
                    &uid,
                    &nickname,
                    identity.enterprise_id.as_deref().unwrap_or_default(),
                    now_millis,
                );
                let spec = wb_pool::build_workbuddy_pool_web_report_request(
                    &transport.key.id,
                    aether_provider_transport::workbuddy::WORKBUDDY_WEB_BASE_URL_CN,
                    &identity,
                    authorization.clone(),
                    wb_desktop::WORKBUDDY_LIBRARY_DOC_URL,
                    payload,
                );
                let ok = send_status(state, transport, proxy_override, spec)
                    .await
                    .is_some_and(|status| (200..300).contains(&status));
                (ok, "资料库介绍页 web 事件（web 域 /v2/report）")
            }
            "template_5" => {
                // 面板：5 组不同模板一次上报即 5/5；这里按**缺口**补（避免多发）。
                let deficit = if task.target > 0 {
                    (task.target - task.current).max(0) as usize
                } else {
                    1
                };
                let templates = [
                    ("1", "深度研究"),
                    ("2", "周报生成"),
                    ("3", "竞品分析"),
                    ("4", "活动策划"),
                    ("5", "代码评审"),
                ];
                let mut ok = true;
                for (index, (template_id, template_name)) in
                    templates.iter().take(deficit.max(1)).enumerate()
                {
                    let millis = unix_now_millis();
                    let conversation = format!("aether-wb-tpl-{millis}-{index}");
                    let request = format!("aether-wb-tpl-req-{millis}-{index}");
                    let events = wb_desktop::workbuddy_desktop_template_use_sequence(
                        &conversation,
                        &request,
                        template_id,
                        template_name,
                        millis as i64,
                    );
                    if !report_desktop(
                        state,
                        transport,
                        &identity,
                        &chat_base,
                        &uid,
                        &nickname,
                        &authorization,
                        proxy_override,
                        events,
                    )
                    .await
                    {
                        ok = false;
                        break;
                    }
                }
                (
                    ok,
                    "模板使用事件组（agent_task_created_with_template + template_used）",
                )
            }
            "playbook_prompt" => {
                let events = wb_desktop::workbuddy_desktop_playbook_prompt_sequence(
                    &conversation_id,
                    &request_id,
                    "pm-gtm-launch-plan",
                    "新产品上市 GTM 发布计划一页纸",
                    millis as i64,
                );
                let ok = report_desktop(
                    state,
                    transport,
                    &identity,
                    &chat_base,
                    &uid,
                    &nickname,
                    &authorization,
                    proxy_override,
                    events,
                )
                .await;
                (ok, "灵感案例做同款事件组（playbook_prompt_send）")
            }
            "create_canvas" => {
                let events = wb_desktop::workbuddy_desktop_design_canvas_sequence(
                    &conversation_id,
                    &request_id,
                    millis as i64,
                );
                let ok = report_desktop(
                    state,
                    transport,
                    &identity,
                    &chat_base,
                    &uid,
                    &nickname,
                    &authorization,
                    proxy_override,
                    events,
                )
                .await;
                (
                    ok,
                    "设计创意画布事件组（wbx_design_canvas_task_create/open）",
                )
            }
            "Hp_Appearance" => {
                // 面板结论：`appearance/set` **单独调用不计分**，必须配上
                // `appearance_skin_apply` 事件（组合才点亮）。
                let spec = wb_pool::build_workbuddy_pool_appearance_set_request(
                    &transport.key.id,
                    &chat_base,
                    &identity,
                    authorization.clone(),
                    wb_desktop::WORKBUDDY_APPEARANCE_THEME_KEY,
                );
                let set_ok = send_status(state, transport, proxy_override, spec)
                    .await
                    .is_some_and(|status| (200..300).contains(&status));
                if !set_ok {
                    (false, "主题设置 API 失败")
                } else {
                    let events = vec![wb_desktop::workbuddy_desktop_appearance_apply_event(
                        wb_desktop::WORKBUDDY_APPEARANCE_THEME_KEY,
                    )];
                    let ok = report_desktop(
                        state,
                        transport,
                        &identity,
                        &chat_base,
                        &uid,
                        &nickname,
                        &authorization,
                        proxy_override,
                        events,
                    )
                    .await;
                    (ok, "主题设置 + 皮肤生效事件")
                }
            }
            // ------------------------------------------------------------------
            // Tier 2：需要**真实对话**（判据要求 requestId 必须是服务端返回的）
            // ------------------------------------------------------------------
            "skill_1" => {
                // 面板判据（row 209）：真实对话 + `skill_info` 事件，且把
                // `chat_message_response` 标成 `finishReason: tool_calls`（技能加载语义）。
                // 拿不到服务端 id 就**不发** skill_info —— 发了也不计数，纯浪费请求。
                match workbuddy_desktop_real_chat(
                    state,
                    transport,
                    authorization.clone(),
                    proxy_override,
                    None,
                )
                .await
                {
                    None => (false, "真实对话未取到服务端 requestId（已跳过 skill_info）"),
                    Some((conversation, server_request_id)) => {
                        let message_id = format!(
                            "msg-{}",
                            &server_request_id[server_request_id.len().saturating_sub(8)..]
                        );
                        let mut events = wb_desktop::workbuddy_desktop_chat_sequence(
                            &conversation,
                            &server_request_id,
                            &message_id,
                            "fast-model",
                            "fast-model",
                            unix_now_millis() as i64,
                        );
                        wb_desktop::workbuddy_desktop_mark_tool_calls(&mut events);
                        events.push(wb_desktop::workbuddy_desktop_skill_info_event(
                            &conversation,
                            &server_request_id,
                            &message_id,
                        ));
                        let ok = report_desktop(
                            state,
                            transport,
                            &identity,
                            &chat_base,
                            &uid,
                            &nickname,
                            &authorization,
                            proxy_override,
                            events,
                        )
                        .await;
                        (ok, "真实对话 + skill_info 技能加载事件（服务端 requestId）")
                    }
                }
            }
            "Expert_lighthouse" => {
                // 与 expert_5 同构，但真实样本（Sunny row 868）要求
                // `mode=LOCAL`、`type` 空、`cost=0`。
                let mut expert = wb_desktop::WorkbuddyMarketExpert {
                    expert_id: wb_desktop::WORKBUDDY_LIGHTHOUSE_EXPERT_ID.to_string(),
                    expert_type: "agent".to_string(),
                    display_name_zh: "腾讯轻量云专家".to_string(),
                    profession_zh: "腾讯轻量云专家".to_string(),
                    version: "1.0.0".to_string(),
                };
                // 市场列表命中就用服务端的权威信息（名称 / 版本）。
                for candidate in fetch_workbuddy_market_experts(
                    state,
                    transport,
                    authorization.clone(),
                    proxy_override,
                    "agent",
                )
                .await
                {
                    if candidate.expert_id == expert.expert_id {
                        expert = candidate;
                        break;
                    }
                }
                if !report_desktop(
                    state,
                    transport,
                    &identity,
                    &chat_base,
                    &uid,
                    &nickname,
                    &authorization,
                    proxy_override,
                    wb_desktop::workbuddy_desktop_expert_summon_sequence(&expert),
                )
                .await
                {
                    (false, "轻量云专家召唤链上报失败")
                } else {
                    match workbuddy_desktop_real_chat(
                        state,
                        transport,
                        authorization.clone(),
                        proxy_override,
                        Some(&expert.expert_id),
                    )
                    .await
                    {
                        None => (false, "轻量云专家真实对话未取到服务端 requestId"),
                        Some((conversation, server_request_id)) => {
                            let message_id = format!(
                                "msg-{}",
                                &server_request_id[server_request_id.len().saturating_sub(8)..]
                            );
                            let mut events = wb_desktop::workbuddy_desktop_chat_sequence(
                                &conversation,
                                &server_request_id,
                                &message_id,
                                "fast-model",
                                "fast-model",
                                unix_now_millis() as i64,
                            );
                            events.push(wb_desktop::workbuddy_desktop_expert_actual_use_event(
                                &expert,
                                &conversation,
                                &server_request_id,
                                "LOCAL",
                                "",
                                0,
                            ));
                            let ok = report_desktop(
                                state,
                                transport,
                                &identity,
                                &chat_base,
                                &uid,
                                &nickname,
                                &authorization,
                                proxy_override,
                                events,
                            )
                            .await;
                            (ok, "轻量云专家召唤 + 使用链（LOCAL / type 空 / cost 0）")
                        }
                    }
                }
            }
            "expert_5" | "Expert_team_use_3" => {
                // 必须是市场列表里**真实存在**的专家（编造 id 不计数），
                // 每位走「召唤链 → 真实对话 → expert_actual_use」，按缺口补足。
                let expert_type = if code == "expert_5" { "agent" } else { "team" };
                let deficit = if task.target > 0 {
                    (task.target - task.current).max(0) as usize
                } else {
                    1
                };
                let experts = fetch_workbuddy_market_experts(
                    state,
                    transport,
                    authorization.clone(),
                    proxy_override,
                    expert_type,
                )
                .await;
                if experts.is_empty() {
                    (false, "专家市场列表为空（编造 id 不计数，已跳过）")
                } else {
                    let mut done = 0usize;
                    let mut interrupted = false;
                    for expert in experts.iter().take(deficit.max(1)) {
                        if !report_desktop(
                            state,
                            transport,
                            &identity,
                            &chat_base,
                            &uid,
                            &nickname,
                            &authorization,
                            proxy_override,
                            wb_desktop::workbuddy_desktop_expert_summon_sequence(expert),
                        )
                        .await
                        {
                            interrupted = true;
                            break;
                        }
                        let Some((conversation, server_request_id)) = workbuddy_desktop_real_chat(
                            state,
                            transport,
                            authorization.clone(),
                            proxy_override,
                            Some(&expert.expert_id),
                        )
                        .await
                        else {
                            interrupted = true;
                            break;
                        };
                        let message_id = format!(
                            "msg-{}",
                            &server_request_id[server_request_id.len().saturating_sub(8)..]
                        );
                        let mut events = wb_desktop::workbuddy_desktop_chat_sequence(
                            &conversation,
                            &server_request_id,
                            &message_id,
                            "fast-model",
                            "fast-model",
                            unix_now_millis() as i64,
                        );
                        events.push(wb_desktop::workbuddy_desktop_expert_actual_use_event(
                            expert,
                            &conversation,
                            &server_request_id,
                            "craft",
                            "expert-all",
                            9000,
                        ));
                        if !report_desktop(
                            state,
                            transport,
                            &identity,
                            &chat_base,
                            &uid,
                            &nickname,
                            &authorization,
                            proxy_override,
                            events,
                        )
                        .await
                        {
                            interrupted = true;
                            break;
                        }
                        done += 1;
                    }
                    detail = Some(json!({
                        "done": done,
                        "deficit": deficit,
                        "expert_type": expert_type,
                    }));
                    (
                        done > 0,
                        if interrupted {
                            "真实专家链中断（已完成一部分）"
                        } else {
                            "真实专家召唤 + 使用链（服务端 requestId）"
                        },
                    )
                }
            }
            "black_cat" => {
                // 夜猫子：**只在 23:00–08:00（CST）窗口内**计数；窗口外一个请求都不发
                //（发了也不计分，纯浪费）。
                if !workbuddy_in_night_window() {
                    (false, "不在 23:00–08:00 计数窗口（已跳过，避免无谓请求）")
                } else {
                    let deficit = if task.target > 0 {
                        (task.target - task.current).max(0) as usize
                    } else {
                        1
                    };
                    let mut done = 0usize;
                    for _ in 0..deficit {
                        let Some((conversation, server_request_id)) = workbuddy_desktop_real_chat(
                            state,
                            transport,
                            authorization.clone(),
                            proxy_override,
                            None,
                        )
                        .await
                        else {
                            break;
                        };
                        let message_id = format!(
                            "msg-{}",
                            &server_request_id[server_request_id.len().saturating_sub(8)..]
                        );
                        let events = wb_desktop::workbuddy_desktop_chat_sequence(
                            &conversation,
                            &server_request_id,
                            &message_id,
                            "glm-5.2",
                            "glm-5.2",
                            unix_now_millis() as i64,
                        );
                        if report_desktop(
                            state,
                            transport,
                            &identity,
                            &chat_base,
                            &uid,
                            &nickname,
                            &authorization,
                            proxy_override,
                            events,
                        )
                        .await
                        {
                            done += 1;
                        }
                    }
                    detail = Some(json!({ "done": done, "deficit": deficit }));
                    (done > 0, "夜间真实对话（23:00–08:00 窗口内）")
                }
            }
            _ => continue,
        };

        if ok {
            sent_now.push(code.to_string());
        }
        results.push(json!({
            "task_code": code,
            "title": task.title,
            "status": if ok { "done" } else { "error" },
            "message": message,
        }));
        if let Some(detail) = detail.take() {
            if let Some(object) = results
                .last_mut()
                .and_then(serde_json::Value::as_object_mut)
            {
                object.insert("detail".to_string(), detail);
            }
        }
    }

    (
        json!({
            "ran_at": unix_now_secs(),
            "actions": results,
            "sent": sent_now,
        }),
        sent_now,
    )
}

///
/// 夜猫子计数窗口：`23:00–08:00`（Asia/Shanghai，面板 `InNightWindow` 同口径）。
///
/// 窗口外发对话**不计分**——所以网关只在窗口内补足，窗口外直接跳过（面板会提示稍后再试）。
fn workbuddy_in_night_window() -> bool {
    let offset = chrono::FixedOffset::east_opt(8 * 60 * 60).expect("CST offset");
    let hour = chrono::DateTime::from_timestamp(unix_now_secs() as i64, 0)
        .unwrap_or_else(|| chrono::DateTime::from_timestamp(0, 0).expect("epoch"))
        .with_timezone(&offset)
        .format("%H")
        .to_string();
    // 窗口 = `23:00–24:00` ∪ `00:00–08:00`，等价于「**不在** 08:00–23:00 里」。
    hour.parse::<u32>()
        .map(|hour| !(8..23).contains(&hour))
        .unwrap_or(false)
}

/// Tier 2：发一次**真实对话**并取回**服务端 `requestId`**（面板 `DesktopChatWithExpert` 等价物）。
///
/// 为什么必须真发：`expert_actual_use` / `skill_info` 这类 JOIN 事件的 `requestId`
/// **必须是真实对话的服务端 id**（自造 UUID 不计数，面板 Sunny row 2113 实证）。
/// SSE 响应走 sync 执行会落进 `ResponseBody.body_bytes_b64`（上限 64MB），解码后
/// 用 `workbuddy_parse_server_request_id` 抓 id。
///
/// 拿不到 id 就返回 `None`——调用方据此**不发**后续 JOIN 事件（发了也不计数，纯浪费请求）。
/// 返回 `(conversation_id, server_request_id)`。
///
/// **接线状态**：已接进 `execute_workbuddy_desktop_actions` 的五个 Tier-2 动作
/// （`skill_1` / `Expert_lighthouse` / `expert_5` / `Expert_team_use_3` / `black_cat`），
/// 且与 Tier-1 共用同一套防重复闸（`desktop_ran_on` 日戳 + 每任务 `due` 判断 + `desktop_sent` 水位）。
async fn workbuddy_desktop_real_chat(
    state: &AdminAppState<'_>,
    transport: &AdminGatewayProviderTransportSnapshot,
    authorization: (String, String),
    proxy_override: Option<&ProxySnapshot>,
    expert_id: Option<&str>,
) -> Option<(String, String)> {
    use aether_provider_pool::providers::workbuddy as wb_pool;
    use aether_provider_transport::workbuddy::desktop as wb_desktop;
    use base64::Engine as _;

    let identity = workbuddy_identity(transport);
    let chat_base = transport.endpoint.base_url.clone();
    let millis = unix_now_millis();
    let conversation_id = format!("aether-wb-conv-{millis}");
    let request_id = millis.to_string();
    let body = wb_desktop::workbuddy_desktop_chat_request_body("");
    let spec = wb_pool::build_workbuddy_pool_desktop_chat_request(
        &transport.key.id,
        &chat_base,
        &identity,
        authorization,
        &conversation_id,
        &request_id,
        expert_id,
        body,
    );
    let outcome = execute_workbuddy_specs(state, transport, vec![spec], proxy_override)
        .await
        .ok()
        .flatten()?;
    let ProviderQuotaExecutionOutcome::Response(result) = outcome else {
        return None;
    };
    if !(200..300).contains(&result.status_code) {
        return None;
    }

    // 先试 `json_body`（万一上游回 JSON），再试 `body_bytes_b64` 里的 SSE 文本。
    let mut candidates: Vec<String> = Vec::new();
    if let Some(body) = result.body.as_ref() {
        if let Some(json) = body.json_body.as_ref() {
            candidates.push(json.to_string());
        }
        if let Some(encoded) = body.body_bytes_b64.as_deref() {
            if let Ok(bytes) = base64::engine::general_purpose::STANDARD.decode(encoded) {
                candidates.push(String::from_utf8_lossy(&bytes).to_string());
            }
        }
    }
    for text in candidates {
        if let Some(server_request_id) = wb_desktop::workbuddy_parse_server_request_id(&text) {
            return Some((conversation_id, server_request_id));
        }
    }
    None
}

/// 专家市场列表（`expert_actual_use` 的 id 必须是平台**真实存在**的专家，编造不计数）。
async fn fetch_workbuddy_market_experts(
    state: &AdminAppState<'_>,
    transport: &AdminGatewayProviderTransportSnapshot,
    authorization: (String, String),
    proxy_override: Option<&ProxySnapshot>,
    expert_type: &str,
) -> Vec<aether_provider_transport::workbuddy::desktop::WorkbuddyMarketExpert> {
    use aether_provider_pool::providers::workbuddy as wb_pool;
    use aether_provider_transport::workbuddy::desktop as wb_desktop;

    let identity = workbuddy_identity(transport);
    let chat_base = transport.endpoint.base_url.clone();
    let spec = wb_pool::build_workbuddy_pool_expert_list_request(
        &transport.key.id,
        &chat_base,
        &identity,
        authorization,
        expert_type,
    );
    let outcome = execute_workbuddy_specs(state, transport, vec![spec], proxy_override)
        .await
        .ok()
        .flatten();
    let Some(ProviderQuotaExecutionOutcome::Response(result)) = outcome else {
        return Vec::new();
    };
    if !(200..300).contains(&result.status_code) {
        return Vec::new();
    }
    result
        .body
        .as_ref()
        .and_then(|body| body.json_body.as_ref())
        .map(wb_desktop::parse_workbuddy_market_experts)
        .unwrap_or_default()
}

/// trial 加油包（**global 专属**）：`POST {billingBase}/billing/ide/trial`，无 body。
///
/// 面板口径（`trial.go`）：**只有 global 账号**有这条（CN 无此端点）；幂等码 `14051`
/// = 已领取过 → **视为正常**，不是错误。global 没有签到、没有任务中心，所以这是它
/// 唯一天然的积分增益动作（面板 PLAN D4）。
async fn execute_workbuddy_trial_claim(
    state: &AdminAppState<'_>,
    transport: &AdminGatewayProviderTransportSnapshot,
    authorization: (String, String),
    proxy_override: Option<&ProxySnapshot>,
) -> Option<serde_json::Value> {
    let identity = workbuddy_identity(transport);
    if identity.realm != WorkbuddyRealm::Global {
        return None;
    }
    let spec = build_workbuddy_pool_trial_claim_request(
        &transport.key.id,
        workbuddy_billing_base_url(identity.realm),
        &identity,
        authorization,
    );
    let outcome = execute_workbuddy_specs(state, transport, vec![spec], proxy_override)
        .await
        .ok()
        .flatten();
    let Some(ProviderQuotaExecutionOutcome::Response(result)) = outcome else {
        return Some(json!({"status": "failed"}));
    };
    let body_text = result
        .body
        .as_ref()
        .and_then(|body| body.json_body.as_ref())
        .map(|body| body.to_string());
    Some(
        match classify_workbuddy_trial_outcome(result.status_code, body_text.as_deref()) {
            WorkbuddyTrialOutcome::Claimed => json!({"status": "claimed"}),
            // 幂等：已领过是正常结果，不是失败。
            WorkbuddyTrialOutcome::AlreadyClaimed => json!({"status": "already_claimed"}),
            WorkbuddyTrialOutcome::Failed => {
                json!({"status": "failed", "status_code": result.status_code})
            }
        },
    )
}

/// 国际版注册激活：**补注册地区 → 激活**（面板 `GlobalCompleteRegistration`）。
///
/// 为什么必须有这一环：新 global 号没补注册地区时，register 接口回 `code 500 / region required`，
/// 对话直接报 `14017 trial not activated`（面板 `global_register.go` 的动机）。
///
/// 顺序与面板一致：查状态 → 已激活**直接返回**（幂等，只打一次 GET）；需补地区则拉国际版
/// 白名单取**首个**（通常 HK）提交，再查一次状态确认。任何一步失败都**不阻断**后续
/// trial / 余额（面板同样「失败不阻断调用方」）。
///
/// 前置：`identity.uid` 必须存在（路径与 `x-user-id` 都要）；没有 uid 直接跳过。
async fn execute_workbuddy_global_registration(
    state: &AdminAppState<'_>,
    transport: &AdminGatewayProviderTransportSnapshot,
    authorization: (String, String),
    proxy_override: Option<&ProxySnapshot>,
) -> Option<serde_json::Value> {
    let identity = workbuddy_identity(transport);
    if identity.realm != WorkbuddyRealm::Global {
        return None;
    }
    if identity
        .uid
        .as_deref()
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .is_none()
    {
        return Some(json!({"status": "skipped", "message": "缺少 uid"}));
    }
    let web_base = workbuddy_billing_base_url(identity.realm);

    let Some((code, message)) = execute_workbuddy_global_register_status(
        state,
        transport,
        &identity,
        &authorization,
        web_base,
        proxy_override,
    )
    .await
    else {
        return Some(json!({"status": "failed", "step": "status"}));
    };
    match classify_workbuddy_global_register_status(code, &message) {
        WorkbuddyGlobalRegisterStatus::Activated => {
            return Some(json!({"status": "activated"}));
        }
        WorkbuddyGlobalRegisterStatus::NotActivated(message) => {
            return Some(json!({"status": "not_activated", "message": message}));
        }
        // 需补注册地区：继续往下走。
        WorkbuddyGlobalRegisterStatus::NeedsRegion(_) => {}
    }

    let Some(countries) = execute_workbuddy_global_countries(
        state,
        transport,
        &identity,
        &authorization,
        web_base,
        proxy_override,
    )
    .await
    else {
        return Some(json!({"status": "failed", "step": "countries"}));
    };
    let Some(country) = filter_workbuddy_global_intl_countries(&countries)
        .into_iter()
        .next()
    else {
        return Some(json!({
            "status": "failed",
            "step": "countries",
            "message": "国际版白名单内没有可用地区",
        }));
    };

    let submit = execute_workbuddy_global_submit_region(
        state,
        transport,
        &identity,
        &authorization,
        web_base,
        &country,
        proxy_override,
    )
    .await;
    if !submit.ok {
        return Some(json!({
            "status": "failed",
            "step": "submit_region",
            "country": country.ios2,
            "message": submit.message,
        }));
    }

    // 提交后复验：面板同样要求「再查一次状态」，否则提交成功但激活失败会被当成成功。
    let activated = match execute_workbuddy_global_register_status(
        state,
        transport,
        &identity,
        &authorization,
        web_base,
        proxy_override,
    )
    .await
    {
        Some((code, message)) => matches!(
            classify_workbuddy_global_register_status(code, &message),
            WorkbuddyGlobalRegisterStatus::Activated
        ),
        None => false,
    };
    Some(json!({
        "status": if activated { "activated" } else { "region_submitted" },
        "country": country.ios2,
        "activated": activated,
    }))
}

/// 执行一条 spec 并取回**原始 JSON body**。
async fn execute_workbuddy_global_envelope(
    state: &AdminAppState<'_>,
    transport: &AdminGatewayProviderTransportSnapshot,
    spec: aether_provider_pool::ProviderPoolQuotaRequestSpec,
    proxy_override: Option<&ProxySnapshot>,
) -> Option<Value> {
    let outcome = execute_workbuddy_specs(state, transport, vec![spec], proxy_override)
        .await
        .ok()
        .flatten();
    match outcome {
        Some(ProviderQuotaExecutionOutcome::Response(result)) => {
            result.body.as_ref().and_then(|body| body.json_body.clone())
        }
        _ => None,
    }
}

/// 信封里的 `code`（`-1` = 没有该字段；字符串形态也容忍）。
fn workbuddy_envelope_code(envelope: &Value) -> i64 {
    match envelope.get("code") {
        Some(Value::Number(number)) => number.as_i64().unwrap_or(-1),
        Some(Value::String(text)) => text.trim().parse::<i64>().unwrap_or(-1),
        _ => -1,
    }
}

fn workbuddy_envelope_message(envelope: &Value) -> String {
    envelope
        .get("msg")
        .and_then(Value::as_str)
        .unwrap_or_default()
        .trim()
        .to_string()
}

/// 注册状态查询 → `(code, msg)`。
///
/// ⚠️ register 端点的信封 code 是 **200/500**（不是 0），所以 `execute_workbuddy_specs` 里
/// 的 `workbuddy_unwrap_success_payload` **不会**拆它（那个只在 `code == 0` 时拆），
/// 这里能原样读到信封。
async fn execute_workbuddy_global_register_status(
    state: &AdminAppState<'_>,
    transport: &AdminGatewayProviderTransportSnapshot,
    identity: &aether_provider_transport::workbuddy::WorkbuddyIdentity,
    authorization: &(String, String),
    web_base: &str,
    proxy_override: Option<&ProxySnapshot>,
) -> Option<(i64, String)> {
    let spec = build_workbuddy_pool_global_register_status_request(
        &transport.key.id,
        web_base,
        identity,
        authorization.clone(),
    );
    let envelope =
        execute_workbuddy_global_envelope(state, transport, spec, proxy_override).await?;
    Some((
        workbuddy_envelope_code(&envelope),
        workbuddy_envelope_message(&envelope),
    ))
}

/// 拉可选注册地区列表。
///
/// 这里的信封 code 是 **0**，所以 `workbuddy_unwrap_success_payload` 会先把 `data` 拆出来
/// （面板 `globalRegisterJSON` 的等价物）——而 `data` 本身又是 **JSON 字符串**，
/// 由 `parse_workbuddy_global_countries` 负责二次拆包。
async fn execute_workbuddy_global_countries(
    state: &AdminAppState<'_>,
    transport: &AdminGatewayProviderTransportSnapshot,
    identity: &aether_provider_transport::workbuddy::WorkbuddyIdentity,
    authorization: &(String, String),
    web_base: &str,
    proxy_override: Option<&ProxySnapshot>,
) -> Option<Vec<WorkbuddyGlobalCountry>> {
    let spec = build_workbuddy_pool_global_country_code_request(
        &transport.key.id,
        web_base,
        identity,
        authorization.clone(),
    );
    let body = execute_workbuddy_global_envelope(state, transport, spec, proxy_override).await?;
    let countries = parse_workbuddy_global_countries(&body);
    (!countries.is_empty()).then_some(countries)
}

/// 提交注册地区的结果。
struct WorkbuddyGlobalSubmitOutcome {
    ok: bool,
    message: String,
}

/// 提交注册地区（幂等）。
///
/// ⚠️ 判定用**拆包推断**：信封 code 为 0 时 `workbuddy_unwrap_success_payload` 已经把 body
/// 换成 `data` ⇒ **没有 `code` 字段就说明上游 code 就是 0（成功）**；反之信封还在，
/// 就看它的 code 是否为 0。这样既不重复拆包，也不依赖 `data` 的形状。
async fn execute_workbuddy_global_submit_region(
    state: &AdminAppState<'_>,
    transport: &AdminGatewayProviderTransportSnapshot,
    identity: &aether_provider_transport::workbuddy::WorkbuddyIdentity,
    authorization: &(String, String),
    web_base: &str,
    country: &WorkbuddyGlobalCountry,
    proxy_override: Option<&ProxySnapshot>,
) -> WorkbuddyGlobalSubmitOutcome {
    let spec = build_workbuddy_pool_global_submit_region_request(
        &transport.key.id,
        web_base,
        identity,
        authorization.clone(),
        country,
    );
    let Some(body) =
        execute_workbuddy_global_envelope(state, transport, spec, proxy_override).await
    else {
        return WorkbuddyGlobalSubmitOutcome {
            ok: false,
            message: "提交地区请求执行失败".to_string(),
        };
    };
    let code = workbuddy_envelope_code(&body);
    WorkbuddyGlobalSubmitOutcome {
        // `code == -1` = 字段不存在 = 已拆包 = 上游 code 为 0。
        ok: code == 0 || code == -1,
        message: if code == 0 || code == -1 {
            String::new()
        } else {
            workbuddy_envelope_message(&body)
        },
    }
}

/// 活跃上报（`chat_request_send`）：面板口径每号每天 1 次即可。
///
/// 调用时机 = **当日首次签到成功后**（签到本身就是账号的「今天」闸门，天然每天最多一次）；
/// 企业号跳过（growth 体系对它们 403，上报是**静默无效**的零收益动作），uid 为空也跳过
/// （上游缺 `userId` 会 200 但静默丢弃）。
async fn execute_workbuddy_activity_report(
    state: &AdminAppState<'_>,
    transport: &AdminGatewayProviderTransportSnapshot,
    authorization: (String, String),
    proxy_override: Option<&ProxySnapshot>,
) -> Option<bool> {
    let identity = workbuddy_identity(transport);
    let is_enterprise = identity
        .enterprise_id
        .as_deref()
        .map(str::trim)
        .is_some_and(|value| !value.is_empty());
    let uid = identity
        .uid
        .as_deref()
        .map(str::trim)
        .filter(|value| !value.is_empty())?;
    if is_enterprise {
        return None;
    }

    let billing_base = workbuddy_billing_base_url(identity.realm);
    let specs = workbuddy_billing_path_candidates(WorkbuddyBillingEndpoint::Report, identity.realm)
        .into_iter()
        .map(|path| {
            build_workbuddy_pool_activity_report_request(
                &transport.key.id,
                billing_base,
                path,
                &identity,
                authorization.clone(),
                uid,
                unix_now_millis(),
            )
        })
        .collect();

    let outcome = execute_workbuddy_specs(state, transport, specs, proxy_override).await;
    match outcome {
        Ok(Some(ProviderQuotaExecutionOutcome::Response(result))) => {
            let body = result
                .body
                .as_ref()
                .and_then(|body| body.json_body.as_ref())
                .map(serde_json::Value::to_string);
            Some(is_workbuddy_report_accepted(
                result.status_code,
                body.as_deref(),
            ))
        }
        // 传输层失败 / 白名单拒绝 / 解析失败：记为「没报成」，不中断余额刷新。
        _ => Some(false),
    }
}

/// 每日签到：只对**非企业**账号发（面板同口径）。
///
/// 上游对企业号恒返回 `400 code 10001 企业账号不支持该操作`——发了只是每天白撞一次风控，
/// 所以按 `identity.enterprise_id` 直接跳过。签到失败**绝不影响**余额刷新：
/// 幂等拒绝（今天已签到）与「不支持」都算非失败，只有真失败才在结果里标记。
async fn execute_workbuddy_daily_checkin(
    state: &AdminAppState<'_>,
    transport: &AdminGatewayProviderTransportSnapshot,
    authorization: (String, String),
    proxy_override: Option<&ProxySnapshot>,
) -> WorkbuddyCheckinOutcome {
    let identity = workbuddy_identity(transport);
    let billing_base = workbuddy_billing_base_url(identity.realm);
    let specs =
        workbuddy_billing_path_candidates(WorkbuddyBillingEndpoint::DailyCheckin, identity.realm)
            .into_iter()
            .map(|path| {
                build_workbuddy_pool_daily_checkin_request(
                    &transport.key.id,
                    billing_base,
                    path,
                    &identity,
                    authorization.clone(),
                )
            })
            .collect();

    let outcome = execute_workbuddy_specs(state, transport, specs, proxy_override).await;
    match outcome {
        Ok(Some(ProviderQuotaExecutionOutcome::Response(result))) => {
            let body = result
                .body
                .as_ref()
                .and_then(|body| body.json_body.as_ref())
                .map(serde_json::Value::to_string);
            classify_workbuddy_checkin_outcome(result.status_code, body.as_deref())
        }
        // 传输层失败/解析失败：记为失败但不中断余额刷新。
        _ => WorkbuddyCheckinOutcome::Failed,
    }
}

/// WorkBuddy（腾讯 CodeBuddy）余额/额度刷新。
///
/// 上游两套口径由 key 的 `auth_config` 决定（个人资源包 / 企业分配额度），
/// 请求构造与解析都复用 transport / admin 里的同一份实现，这里只负责编排：
/// 取账号 → 发请求 → 解析 → 落 key 状态 → 汇总。
async fn execute_workbuddy_quota_plan(
    state: &AdminAppState<'_>,
    transport: &AdminGatewayProviderTransportSnapshot,
    authorization: (String, String),
    proxy_override: Option<&ProxySnapshot>,
) -> Result<Option<ProviderQuotaExecutionOutcome>, GatewayError> {
    let identity = workbuddy_identity(transport);
    let billing_base = workbuddy_billing_base_url(identity.realm);
    // 企业号走企业额度端点（单路径），个人号走资源包端点（国际域两条候选路径）。
    let endpoint_kind = if identity
        .enterprise_id
        .as_deref()
        .map(str::trim)
        .is_some_and(|value| !value.is_empty())
    {
        WorkbuddyBillingEndpoint::EnterpriseUsage
    } else {
        WorkbuddyBillingEndpoint::UserResource
    };
    let specs = workbuddy_billing_path_candidates(endpoint_kind, identity.realm)
        .into_iter()
        .map(|path| {
            build_workbuddy_pool_quota_request(
                &transport.key.id,
                billing_base,
                path,
                &identity,
                authorization.clone(),
                unix_now_secs(),
            )
        })
        .collect();

    execute_workbuddy_specs(state, transport, specs, proxy_override).await
}

pub(crate) async fn refresh_workbuddy_provider_quota_locally(
    state: &AdminAppState<'_>,
    provider: &StoredProviderCatalogProvider,
    endpoint: &StoredProviderCatalogEndpoint,
    keys: Vec<StoredProviderCatalogKey>,
    proxy_override: Option<ProxySnapshot>,
) -> Result<Option<serde_json::Value>, GatewayError> {
    let mut results = Vec::new();
    let mut success_count = 0usize;
    let mut failed_count = 0usize;
    let mut auto_removed_count = 0usize;

    for key in keys {
        let transport = match state
            .read_provider_transport_snapshot(&provider.id, &endpoint.id, &key.id)
            .await?
        {
            Some(transport) => transport,
            None => {
                failed_count += 1;
                results.push(json!({
                    "key_id": key.id,
                    "key_name": key.name,
                    "status": "error",
                    "message": "Provider transport snapshot unavailable",
                }));
                continue;
            }
        };

        let authorization = match state.resolve_local_oauth_header_auth(&transport).await? {
            Some(auth) => auth,
            _ => {
                if quota_key_auto_removed(state, &key.id).await? {
                    auto_removed_count += 1;
                    results.push(oauth_refresh_auto_removed_result(&key));
                    continue;
                }
                failed_count += 1;
                results.push(json!({
                    "key_id": key.id,
                    "key_name": key.name,
                    "status": "error",
                    "message": "缺少 OAuth 认证信息，请先授权/刷新 Token",
                }));
                continue;
            }
        };

        // 签到先做（面板 `accountCheckin` 的顺序：签到 → 余额）。
        // 企业号与 global 域都跳过：两边都没有个人签到体系（上游 400 10001 / 403）。
        let identity = workbuddy_identity(&transport);
        let is_enterprise = identity
            .enterprise_id
            .as_deref()
            .map(str::trim)
            .is_some_and(|value| !value.is_empty());
        let checkin_outcome = if is_enterprise || identity.realm == WorkbuddyRealm::Global {
            None
        } else {
            Some(
                execute_workbuddy_daily_checkin(
                    state,
                    &transport,
                    authorization.clone(),
                    proxy_override.as_ref(),
                )
                .await,
            )
        };

        // ---------------------------------------------------------------
        // 当日闸门：**Aether 自己的每日戳**（按上游日界 Asia/Shanghai ✓），
        // 不再是「今日首次签到成功」✗ —— 维护性修复 2026-10-17 ✓。
        //
        // 旧口径的洞 ✗：账号若在登录当天已被别处签到（`already_checked_in`：
        // 官方客户端 / 建号流程），下面这四件事**当天整套跳过** ✗ ——
        // 新号第一天永远跑不到成长任务 ✗（真机证据：新号 maintenance.checkin =
        // already_checked_in，tasks/travel/streak_bonus 全是 null ✗）。
        // 现在与下方「桌面/Web 行为事件」用同一套思路 ✓（那段注释早就指出：
        // 客户端先签到会让网关永远看不到首签 ✗，所以它自己记 `desktop_ran_on` ✓）。
        // 签到本身仍每轮照常调用 ✓（结果照旧记账 ✓，只是不再当闸门 ✗）。
        let daily_bundle_day = workbuddy_today_key();
        let previous_maintenance_bucket = key
            .upstream_metadata
            .as_ref()
            .and_then(|metadata| metadata.get("workbuddy"))
            .and_then(|workbuddy| workbuddy.get("maintenance"))
            .and_then(serde_json::Value::as_object);
        // 面板的**域/账号门控**（`IsGlobal()` 与 `IsEnterprise()` 并列，见面板
        // `internal/auth/auth.go:197` 的实测记录）：global 域与企业号都**没有个人成长体系**，
        // 签到 / 活跃上报 / 连登 / 猫猫旅行 / 成长任务 在上游一律被拒
        // （`400 code 10001 企业账号不支持该操作` / `403 growth system is only available for
        // personal users`）。既然如此就别天天发注定失败的请求（会白白写脏维护记录），
        // 只保留「额度刷新」与 global 专属动作（补注册、trial 加油包）。
        let growth_bundle_available = !is_enterprise && identity.realm != WorkbuddyRealm::Global;
        let daily_bundle_due = growth_bundle_available
            && aether_provider_pool::providers::workbuddy::workbuddy_daily_bundle_due(
                previous_maintenance_bucket
                    .and_then(|previous| previous.get("daily_bundle_day"))
                    .and_then(serde_json::Value::as_str),
                &daily_bundle_day,
            );

        let activity_reported = if daily_bundle_due {
            execute_workbuddy_activity_report(
                state,
                &transport,
                authorization.clone(),
                proxy_override.as_ref(),
            )
            .await
        } else {
            None
        };
        // 连登兑换 + 抽奖：同一个每日闸门（面板也是在签到排程末尾跑）。
        let streak_bonus = if daily_bundle_due {
            execute_workbuddy_streak_bonus(
                state,
                &transport,
                authorization.clone(),
                proxy_override.as_ref(),
            )
            .await
        } else {
            None
        };
        // 猫猫旅行巡检：同样一天一趟（面板另有 travel_hours 排程，这里复用每日闸门）。
        let travel = if daily_bundle_due {
            execute_workbuddy_travel(
                state,
                &transport,
                authorization.clone(),
                proxy_override.as_ref(),
            )
            .await
        } else {
            None
        };
        // 成长任务（报名 + 领奖）：同样一天一趟。
        let tasks = if daily_bundle_due {
            execute_workbuddy_tasks(
                state,
                &transport,
                authorization.clone(),
                proxy_override.as_ref(),
            )
            .await
        } else {
            None
        };
        // 国际版：**先补注册地区再激活**（面板 `GlobalCompleteRegistration`）。
        // 新 global 号没补地区时 register 回 `code 500 / region required`，对话直接报 14017。
        // 幂等：已激活时只打一次 GET。**必须排在 trial 之前**——trial 要求账号已激活。
        let global_registration = if identity.realm == WorkbuddyRealm::Global {
            execute_workbuddy_global_registration(
                state,
                &transport,
                authorization.clone(),
                proxy_override.as_ref(),
            )
            .await
        } else {
            None
        };

        // trial 加油包（**global 专属**）：global 没有签到/任务中心，这是它唯一的积分增益，
        // 所以**不受**「当日首次签到」闸门限制（global 号本就没有签到）。幂等码 14051
        // （已领过）视为正常，不算失败。提前到这里算：持久化 maintenance 摘要要用。
        let trial = if identity.realm == WorkbuddyRealm::Global {
            execute_workbuddy_trial_claim(
                state,
                &transport,
                authorization.clone(),
                proxy_override.as_ref(),
            )
            .await
        } else {
            None
        };

        // 上游目录自动补拉（**导入凭据**进来的账号没人触发过目录抓取 ✗ → 面板上那个域一个模型
        // 都没有 ✗）。兜底放在额度刷新里：发现该账号还没有 workbuddy 目录快照就补一次 ✓
        // （幂等：已有快照直接跳过 ✓；复用管理端「查询上游模型」同一条链路 ✓）。
        let catalog_fetched = ensure_workbuddy_catalog_snapshot(state, &transport).await;

        let result = match execute_workbuddy_quota_plan(
            state,
            &transport,
            // 后面 trial 还要用同一份授权头，所以这里不能 move。
            authorization.clone(),
            proxy_override.as_ref(),
        )
        .await?
        {
            Some(ProviderQuotaExecutionOutcome::Response(result)) => result,
            // 执行失败（含 origin 白名单拒绝）或没有候选路径：都按失败记账。
            Some(ProviderQuotaExecutionOutcome::Failure(_)) | None => {
                failed_count += 1;
                results.push(json!({
                    "key_id": key.id,
                    "key_name": key.name,
                    "status": "error",
                    "message": "余额查询请求执行失败",
                    "status_code": 502,
                }));
                continue;
            }
        };

        let now_unix_secs = unix_now_secs();
        let response_body = result
            .body
            .as_ref()
            .and_then(|body| body.json_body.as_ref());
        let (mut oauth_invalid_at_unix_secs, mut oauth_invalid_reason) =
            quota_refresh_success_invalid_state(&key);
        // 查询本身也可能撞上账号级终态（12153 会话失效 / 11140 授权故障）：
        // 与执行路径同一口径作废凭证，别让一个死会话一直挂在池子里。
        if result.status_code >= 400 {
            if let Some(reason) = workbuddy_oauth_invalid_reason(
                result.status_code,
                response_body.map(|body| body.to_string()).as_deref(),
            ) {
                oauth_invalid_at_unix_secs = Some(now_unix_secs);
                oauth_invalid_reason = Some(reason);
            }
        }

        let mut status = "error".to_string();
        let mut message = None::<String>;
        let mut metadata_update = None::<serde_json::Value>;

        if result.status_code == 200 {
            metadata_update = response_body
                .and_then(|body| parse_workbuddy_balance_response(body, now_unix_secs))
                .map(|metadata| json!({ "workbuddy": metadata }));
            if metadata_update.is_some() {
                status = "success".to_string();
            } else {
                status = "no_metadata".to_string();
                message = Some("响应中未包含余额/额度字段".to_string());
                // 真机排障用：上游 200 但解析不出余额字段时，把响应的**键路径摘要**打出来
                // （比截断正文有用：能直接看到额度字段的真实名字与嵌套层）。
                let preview = response_body
                    .map(workbuddy_json_path_summary)
                    .unwrap_or_else(|| "<无正文>".to_string());
                tracing::debug!(
                    key_id = %key.id,
                    endpoint_id = %transport.endpoint.id,
                    response_paths = %preview,
                    "gateway workbuddy balance response carried no quota fields"
                );
            }
        } else {
            message = Some(match result.status_code {
                401 => "余额查询返回 401，Token 可能已失效，请刷新 Token".to_string(),
                403 => "余额查询返回 403，该账号可能缺少查询权限".to_string(),
                429 => "余额查询被限流，请稍后重试".to_string(),
                code => format!("余额查询返回状态码 {code}"),
            });
        }

        // 把本次维护结果并进 `metadata_update` 的 `workbuddy.maintenance` 子对象，
        // 让 admin UI（账号卡片）能读到「今天签到/连登/任务/猫猫」的状态。
        // 注意这里只写 maintenance 子键，不动余额视图的其它字段（models / packages）。
        // 余额解析失败（metadata_update == None）也照样写——维护结果不该跟着丢。
        {
            let mut maintenance = serde_json::Map::new();
            maintenance.insert("ran_at".to_string(), json!(unix_now_secs()));
            maintenance.insert(
                "checkin".to_string(),
                checkin_outcome
                    .map(|outcome| json!(outcome.as_str()))
                    .unwrap_or(serde_json::Value::Null),
            );
            maintenance.insert("activity_reported".to_string(), json!(activity_reported));
            for (field, value) in [
                ("streak_bonus", streak_bonus.as_ref()),
                ("travel", travel.as_ref()),
                ("global_registration", global_registration.as_ref()),
                ("catalog_fetched", catalog_fetched.as_ref()),
                ("trial", trial.as_ref()),
            ] {
                maintenance.insert(
                    field.to_string(),
                    value.cloned().unwrap_or(serde_json::Value::Null),
                );
            }
            // 每日闸门戳 ✓：它必须每轮都写（含「今天已经跑过」那几轮 ✓）——
            // 上游 metadata 是**命名空间内浅合并**，漏写就等于把旧值冲掉 ✗，
            // 下一轮又会判成「今日未跑」→ 同一天反复打上游 ✗。
            // 之所以直接写 `daily_bundle_day` 而不是「跑了才写」：不跑的那几轮里
            // 旧值本来就等于今天 ✓，写同一个值语义一致 ✓。
            maintenance.insert("daily_bundle_day".to_string(), json!(daily_bundle_day));
            if let Some(tasks) = tasks.as_ref() {
                maintenance.insert("tasks".to_string(), tasks.clone());
            } else {
                // 本轮每日闸门没开（今天已经跑过）→ 报名/领奖不跑（面板口径 ✓）。
                // 但任务**目录**要保证 UI 有数据：缺失或超过 24h 就补一次**只读** GET，
                // 否则（用户自己的客户端先签到的情况下）任务表会一直空着。
                // 注意上游 metadata 是「命名空间内浅合并」，写新的 maintenance 会把整个
                // 旧对象换掉，所以**继承**字段是必须的，不能只写新值。
                let previous_maintenance = key
                    .upstream_metadata
                    .as_ref()
                    .and_then(|metadata| metadata.get("workbuddy"))
                    .and_then(|workbuddy| workbuddy.get("maintenance"))
                    .and_then(serde_json::Value::as_object);
                let stored_detail = previous_maintenance
                    .and_then(|previous| previous.get("tasks_detail"))
                    .and_then(serde_json::Value::as_array)
                    .filter(|detail| !detail.is_empty());
                let fetched_at = previous_maintenance
                    .and_then(|previous| previous.get("tasks_fetched_at"))
                    .and_then(serde_json::Value::as_u64)
                    .unwrap_or(0);
                let stale = unix_now_secs().saturating_sub(fetched_at) > 24 * 60 * 60;
                let refreshed = if stored_detail.is_none() || stale {
                    fetch_workbuddy_tasks_catalog(
                        state,
                        &transport,
                        authorization.clone(),
                        proxy_override.as_ref(),
                    )
                    .await
                } else {
                    None
                };
                if let Some(previous) = refreshed
                    .or_else(|| previous_maintenance.cloned().map(serde_json::Value::Object))
                {
                    for field in ["tasks", "tasks_detail", "tasks_fetched_at"] {
                        if let Some(value) = previous.get(field) {
                            maintenance.insert(field.to_string(), value.clone());
                        }
                    }
                }
                // 兜底继承 ✓：目录刷新返回的**形状里没有 `tasks`**（它只有 detail +
                // fetched_at ✗），所以闸门关闭那轮会把上一次「已领 13 个 / 1500 积分」
                // 的结果冲掉 ✗（真机复现：刷新后 `tasks` 变成 null ✗）。
                // maintenance 是**整桶替换**（命名空间浅合并 ✗），漏一个字段就是丢数据 ✗，
                // 这里显式从上一份把 `tasks` 补回来 ✓ —— 后台那张「维护存证」因此不会丢 ✓。
                if !maintenance.contains_key("tasks") {
                    if let Some(previous_tasks) =
                        previous_maintenance.and_then(|previous| previous.get("tasks"))
                    {
                        maintenance.insert("tasks".to_string(), previous_tasks.clone());
                    }
                }
            }

            // ---------------------------------------------------------------
            // 桌面/Web 行为事件（面板 `autoActions` 的纯事件子集）
            // ---------------------------------------------------------------
            //
            // 闸门与「成长任务报名/领奖」不同，这里**不依赖当日首签**：
            // 用户自己的客户端可能先签到，网关就永远看不到 `first_checkin_today`，
            // 那些「需电脑端」任务就一辈子点不亮。所以改用**自己的每日戳**
            // （`desktop_ran_on`）+ **每任务水位**（`desktop_sent`）双重收敛：
            // 每天最多一轮、每个任务 code 最多发一次，且**已领取/已达标的任务直接跳过**
            // （一个请求都不发）——一次性任务因此绝不会被重复触发。
            {
                let previous_maintenance = key
                    .upstream_metadata
                    .as_ref()
                    .and_then(|metadata| metadata.get("workbuddy"))
                    .and_then(|workbuddy| workbuddy.get("maintenance"))
                    .and_then(serde_json::Value::as_object);

                // 水位：历史已发过的 code（跨天保留，一次性任务终态即永久跳过）。
                let mut sent: std::collections::BTreeSet<String> = previous_maintenance
                    .and_then(|previous| previous.get("desktop_sent"))
                    .and_then(serde_json::Value::as_array)
                    .map(|codes| {
                        codes
                            .iter()
                            .filter_map(serde_json::Value::as_str)
                            .map(str::to_string)
                            .collect()
                    })
                    .unwrap_or_default();
                let ran_on = previous_maintenance
                    .and_then(|previous| previous.get("desktop_ran_on"))
                    .and_then(serde_json::Value::as_str)
                    .unwrap_or_default()
                    .to_string();
                let today = workbuddy_today_key();

                // 任务视图统一从目录明细来：本轮抓的 `tasks_detail` 或**继承的**上一份
                // 都已在 maintenance 里（上面的继承逻辑保证），守卫逻辑因此只有一份。
                let task_views: Vec<WorkbuddyDesktopTaskView> = maintenance
                    .get("tasks_detail")
                    .and_then(serde_json::Value::as_array)
                    .map(|detail| {
                        detail
                            .iter()
                            .map(WorkbuddyDesktopTaskView::from_detail)
                            .collect()
                    })
                    .unwrap_or_default();

                if ran_on != today && !task_views.is_empty() {
                    let (desktop_result, sent_now) = execute_workbuddy_desktop_actions(
                        state,
                        &transport,
                        authorization.clone(),
                        proxy_override.as_ref(),
                        &task_views,
                        &sent,
                    )
                    .await;
                    for code in sent_now {
                        sent.insert(code);
                    }
                    maintenance.insert("desktop_ran_on".to_string(), json!(today));
                    maintenance.insert("desktop_result".to_string(), desktop_result);
                }
                // 水位与戳始终写回（即使今天不跑，也要保留历史水位）。
                maintenance.insert(
                    "desktop_sent".to_string(),
                    json!(sent.into_iter().collect::<Vec<String>>()),
                );
            }
            let bucket = metadata_update
                .get_or_insert_with(|| json!({ "workbuddy": {} }))
                .get_mut("workbuddy")
                .and_then(|value| value.as_object_mut());
            if let Some(bucket) = bucket {
                bucket.insert(
                    "maintenance".to_string(),
                    serde_json::Value::Object(maintenance),
                );
            }
        }

        if !persist_provider_quota_refresh_state(
            state,
            &key.id,
            metadata_update.as_ref(),
            oauth_invalid_at_unix_secs,
            oauth_invalid_reason,
            None,
        )
        .await?
        {
            failed_count += 1;
            results.push(json!({
                "key_id": key.id,
                "key_name": key.name,
                "status": "error",
                "message": "Key 状态写入失败",
            }));
            continue;
        }

        if status == "success" {
            success_count += 1;
        } else {
            failed_count += 1;
        }

        let mut payload = serde_json::Map::new();
        payload.insert("key_id".to_string(), json!(key.id));
        payload.insert("key_name".to_string(), json!(key.name));
        payload.insert("status".to_string(), json!(status));
        // 签到结果单独一栏：企业号是 `null`（跳过），「今天已签到」不算失败。
        payload.insert(
            "checkin".to_string(),
            checkin_outcome
                .map(|outcome| json!(outcome.as_str()))
                .unwrap_or(serde_json::Value::Null),
        );
        // 活跃上报：`null` = 本次没报（企业号 / 今天已签到 / 没有 uid），否则 true/false。
        payload.insert(
            "activity_reported".to_string(),
            activity_reported.map_or(serde_json::Value::Null, |reported| json!(reported)),
        );
        // 连登兑换/抽奖摘要：`null` = 本次没跑（企业号 / 国际号 / 今天已签到 / 没有成长体系）。
        payload.insert(
            "streak_bonus".to_string(),
            streak_bonus.unwrap_or(serde_json::Value::Null),
        );
        // 猫猫旅行：`null` = 本次没跑（企业号 / 国际号 / 今天已签到）。
        payload.insert(
            "travel".to_string(),
            travel.unwrap_or(serde_json::Value::Null),
        );
        // 成长任务：`null` = 本次没跑（企业号 / 国际号 / 今天已签到）。
        payload.insert(
            "tasks".to_string(),
            tasks.unwrap_or(serde_json::Value::Null),
        );
        // trial 加油包（**global 专属**）：结果在前面已算好（maintenance 摘要也要用）。
        payload.insert(
            "trial".to_string(),
            trial.unwrap_or(serde_json::Value::Null),
        );
        // 国际版注册激活（**global 专属**）：`null` = 本次没跑（CN 号 / 不是 global）。
        payload.insert(
            "global_registration".to_string(),
            global_registration.unwrap_or(serde_json::Value::Null),
        );
        // 上游目录补拉：`null` = 本次没跑（该账号已有目录快照 ✓）。
        payload.insert(
            "catalog_fetched".to_string(),
            catalog_fetched.unwrap_or(serde_json::Value::Null),
        );
        if let Some(message) = message {
            payload.insert("message".to_string(), json!(message));
        }
        if let Some(metadata) = metadata_update
            .as_ref()
            .and_then(|value| value.get("workbuddy"))
        {
            payload.insert(
                "metadata".to_string(),
                admin_provider_metadata_bucket_safe_json("workbuddy", Some(metadata)),
            );
        }
        if let Some(quota_snapshot) = build_quota_snapshot_payload(
            "workbuddy",
            key.status_snapshot.as_ref(),
            metadata_update.as_ref(),
        ) {
            payload.insert("quota_snapshot".to_string(), quota_snapshot);
        }
        results.push(serde_json::Value::Object(payload));
    }

    Ok(Some(json!({
        "success": success_count,
        "failed": failed_count,
        "total": results.len(),
        "results": results,
        "message": format!("已处理 {} 个 Key", results.len()),
        "auto_removed": auto_removed_count,
    })))
}

fn unix_now_secs() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|duration| duration.as_secs())
        .unwrap_or(0)
}

/// 事件时间戳用毫秒（上游 `chat_request_send.timestamp` / `presentAt` 都是 ms）。
fn unix_now_millis() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|duration| duration.as_millis() as u64)
        .unwrap_or(0)
}

/// 把一个 JSON 响应压成「键路径 = 值」的紧凑摘要（排障用）。
///
/// 为什么不用截断正文：真机定位余额字段时，512 字符往往刚好截在字段名之前。
/// 键路径摘要能一眼看到**额度字段的真实名字与嵌套层**（如
/// `data.Response.Data.Accounts[0].CycleCapacityRemain = 12345`）。
fn workbuddy_json_path_summary(body: &serde_json::Value) -> String {
    fn walk(node: &serde_json::Value, path: &str, out: &mut Vec<String>) {
        match node {
            serde_json::Value::Object(map) => {
                for (key, value) in map {
                    walk(value, &format!("{path}.{key}"), out);
                }
            }
            serde_json::Value::Array(items) => {
                // 数组只看前两个元素，避免摘要过长。
                for (index, value) in items.iter().take(2).enumerate() {
                    walk(value, &format!("{path}[{index}]"), out);
                }
                if items.len() > 2 {
                    out.push(format!("{path}.len = {}", items.len()));
                }
            }
            other => {
                let text = other.to_string();
                let clipped: String = text.chars().take(40).collect();
                out.push(format!("{path} = {clipped}"));
            }
        }
    }

    let mut out = Vec::new();
    walk(body, "", &mut out);
    let joined = out.join(" | ");
    joined.chars().take(1800).collect()
}

#[cfg(test)]
mod tests {
    use super::{
        workbuddy_catalog_snapshot_present, workbuddy_desktop_action_due,
        workbuddy_outcome_is_transient, WorkbuddyDesktopTaskView,
        WORKBUDDY_TRANSPORT_FAILURE_MARKER,
    };
    use crate::handlers::admin::provider::oauth::quota::shared::ProviderQuotaExecutionOutcome;
    use std::collections::BTreeSet;

    /// 目录快照判定（决定额度刷新里要不要**补拉**上游目录 ✓）：只有**非空**数组/对象才算「有」✓。
    ///
    /// 导入凭据进来的账号是「命名空间里根本没有 `models`」→ 必须补拉 ✓
    /// （用户实测的 bug：导入国际号后「上游模型能力与倍率」一个国际模型都不显示 ✗）。
    #[test]
    fn catalog_snapshot_detection_treats_empty_as_missing() {
        use serde_json::json;
        // 没有 metadata / 没有 workbuddy 命名空间 / 没有 models → 都要补拉
        assert!(!workbuddy_catalog_snapshot_present(None));
        assert!(!workbuddy_catalog_snapshot_present(Some(&json!({}))));
        assert!(!workbuddy_catalog_snapshot_present(Some(
            &json!({"workbuddy": {}})
        )));
        // 空数组 / 空对象 = 「没有」（导入后的形态 ✓）
        assert!(!workbuddy_catalog_snapshot_present(Some(
            &json!({"workbuddy": {"models": []}})
        )));
        assert!(!workbuddy_catalog_snapshot_present(Some(
            &json!({"workbuddy": {"models": {}}})
        )));
        // 非空数组 / 非空对象 = 已有快照 → 不补拉（幂等 ✓）
        assert!(workbuddy_catalog_snapshot_present(Some(
            &json!({"workbuddy": {"models": [{"model_uid": "glm-5.3"}]}})
        )));
        assert!(workbuddy_catalog_snapshot_present(Some(
            &json!({"workbuddy": {"models": {"glm-5.3": {}}}})
        )));
        // 别的 provider 命名空间不干扰
        assert!(!workbuddy_catalog_snapshot_present(Some(
            &json!({"kiro": {"models": [1]}})
        )));
    }

    /// 桌面事件动作的**防重复守卫**——用户最关心的那条要求：
    /// 「做过的一次性任务别重复做，因为有些需要发请求」。
    ///
    /// 只有「未领取 && 未达标 && 不在本地水位」才允许发；其余一律 `false`
    /// （调用方连请求都不构造）。
    #[test]
    fn desktop_actions_never_repeat_finished_tasks() {
        let view = |claimed: bool, current: i64, target: i64| WorkbuddyDesktopTaskView {
            task_code: "template_5".to_string(),
            title: "使用 5 个模板".to_string(),
            claimed,
            current,
            target,
        };

        // 未领取、未达标、无水位 → 该发。
        assert!(workbuddy_desktop_action_due(
            &view(false, 0, 5),
            &BTreeSet::new()
        ));
        // 进度不够但已领取（一次性任务终态）→ 绝不重发。
        assert!(!workbuddy_desktop_action_due(
            &view(true, 0, 5),
            &BTreeSet::new()
        ));
        // 已达标（进度满）→ 绝不重发，哪怕上游还没标 claimed。
        assert!(!workbuddy_desktop_action_due(
            &view(false, 5, 5),
            &BTreeSet::new()
        ));
        assert!(!workbuddy_desktop_action_due(
            &view(false, 7, 5),
            &BTreeSet::new()
        ));
        // 本地水位命中（上游回写延迟的兜底）→ 不再发。
        let mut sent = BTreeSet::new();
        sent.insert("template_5".to_string());
        assert!(!workbuddy_desktop_action_due(&view(false, 0, 5), &sent));
        // 水位是**按 code** 的，不会误伤别的任务。
        assert!(workbuddy_desktop_action_due(
            &WorkbuddyDesktopTaskView {
                task_code: "automation_1".to_string(),
                title: "设置自动化任务".to_string(),
                claimed: false,
                current: 0,
                target: 1,
            },
            &sent,
        ));
        // `target == 0`（上游不给目标值）不能当成「已达标」。
        assert!(workbuddy_desktop_action_due(
            &view(false, 0, 0),
            &BTreeSet::new()
        ));
        // 真实场景：从 tasks_detail JSON 还原的已领取任务必须被挡住。
        let detail = serde_json::json!({
            "task_code": "template_5", "title": "使用 5 个模板",
            "claimed": true, "current": 5, "target": 5,
        });
        assert!(!workbuddy_desktop_action_due(
            &WorkbuddyDesktopTaskView::from_detail(&detail),
            &BTreeSet::new()
        ));
        // 缺字段的畸形明细：claimed 缺失按 false、进度 0/0 → 不误判为已完成。
        let malformed = serde_json::json!({ "task_code": "x" });
        let view = WorkbuddyDesktopTaskView::from_detail(&malformed);
        assert_eq!(view.task_code, "x");
        assert!(!view.claimed);
        assert!(workbuddy_desktop_action_due(&view, &BTreeSet::new()));
    }

    /// 瞬时错误判定（面板 `isTransientBillingErr` 同口径）：只有 5xx 与传输失败值得重试；
    /// 4xx / 业务错误 / origin 拦截一律不重试（重试只会原样再失败一次）。
    #[test]
    fn only_server_errors_and_transport_failures_are_retried() {
        // 5xx → 重试（面板实测上游偶发 `code 10000 / status 500`）。
        for status in [500u16, 502, 503, 504] {
            let outcome =
                ProviderQuotaExecutionOutcome::Response(execution_result_with_status(status));
            assert!(workbuddy_outcome_is_transient(&outcome), "{status} 应重试");
        }
        // 4xx / 2xx → 不重试（参数错、限流、业务错误、成功）。
        for status in [200u16, 400, 401, 402, 403, 404, 429] {
            let outcome =
                ProviderQuotaExecutionOutcome::Response(execution_result_with_status(status));
            assert!(
                !workbuddy_outcome_is_transient(&outcome),
                "{status} 不该重试"
            );
        }
        // 传输层失败（固定文案）→ 重试；origin 拦截等其它 Failure → 不重试。
        assert!(workbuddy_outcome_is_transient(
            &ProviderQuotaExecutionOutcome::Failure(WORKBUDDY_TRANSPORT_FAILURE_MARKER.to_string())
        ));
        assert!(!workbuddy_outcome_is_transient(
            &ProviderQuotaExecutionOutcome::Failure(
                "Provider quota request origin is not allowed".to_string()
            )
        ));
    }

    fn execution_result_with_status(status_code: u16) -> aether_contracts::ExecutionResult {
        aether_contracts::ExecutionResult {
            request_id: "req-1".to_string(),
            candidate_id: None,
            status_code,
            headers: std::collections::BTreeMap::new(),
            response_observation: None,
            body: None,
            telemetry: None,
            error: None,
        }
    }
}
