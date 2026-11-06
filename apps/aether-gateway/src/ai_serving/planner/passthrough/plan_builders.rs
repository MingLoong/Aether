use aether_contracts::RequestBody;

use super::{
    augment_sync_report_context, build_ai_execution_plan_from_decision,
    resolve_ai_passthrough_sync_request_body, take_ai_decision_plan_core, take_non_empty_string,
    AiExecutionPlanFromDecisionParts, AiStreamAttempt, AiSyncAttempt,
};
use crate::{AiExecutionDecision, GatewayError};

pub(crate) fn build_passthrough_sync_plan_from_decision(
    parts: &http::request::Parts,
    payload: AiExecutionDecision,
) -> Result<Option<AiSyncAttempt>, GatewayError> {
    let mut payload = payload;
    let Some(core) = take_ai_decision_plan_core(&mut payload) else {
        return Ok(None);
    };
    let Some(upstream_url) = take_non_empty_string(&mut payload.upstream_url) else {
        return Ok(None);
    };
    let mut provider_request_headers = std::mem::take(&mut payload.provider_request_headers);
    // Go relay（workbuddy2api / zcode2api）收到此控制头后，会在响应中回传其最终上游请求头。
    // 仅透传规划使用该机制；普通 provider 不会进入此 builder。
    provider_request_headers.insert("x-aether-echo".to_string(), "1".to_string());
    provider_request_headers.insert("x-aether-trace-id".to_string(), core.request_id.clone());
    let ignored_provider_request_body = serde_json::Value::Null;
    let report_context = augment_sync_report_context(
        payload.report_context.take(),
        &provider_request_headers,
        &ignored_provider_request_body,
    )?;
    let request_body = resolve_ai_passthrough_sync_request_body(
        payload.provider_request_body.take(),
        payload.provider_request_body_base64.take(),
    );
    let provider_request_method = take_non_empty_string(&mut payload.provider_request_method);
    let content_type = payload
        .content_type
        .take()
        .or_else(|| provider_request_headers.get("content-type").cloned());

    let plan = build_ai_execution_plan_from_decision(
        &mut payload,
        AiExecutionPlanFromDecisionParts {
            core,
            method: provider_request_method.unwrap_or_else(|| parts.method.to_string()),
            url: upstream_url,
            headers: provider_request_headers,
            content_type,
            body: request_body,
            stream: false,
        },
    );

    Ok(Some(AiSyncAttempt {
        plan,
        report_kind: payload.report_kind,
        report_context,
    }))
}

pub(crate) fn build_passthrough_stream_plan_from_decision(
    parts: &http::request::Parts,
    payload: AiExecutionDecision,
) -> Result<Option<AiStreamAttempt>, GatewayError> {
    let mut payload = payload;
    let Some(core) = take_ai_decision_plan_core(&mut payload) else {
        return Ok(None);
    };
    let Some(upstream_url) = take_non_empty_string(&mut payload.upstream_url) else {
        return Ok(None);
    };
    let mut provider_request_headers = std::mem::take(&mut payload.provider_request_headers);
    provider_request_headers.insert("x-aether-echo".to_string(), "1".to_string());
    provider_request_headers.insert("x-aether-trace-id".to_string(), core.request_id.clone());
    let content_type = payload
        .content_type
        .take()
        .or_else(|| provider_request_headers.get("content-type").cloned());
    let stream = payload.upstream_is_stream;
    let plan = build_ai_execution_plan_from_decision(
        &mut payload,
        AiExecutionPlanFromDecisionParts {
            core,
            method: parts.method.to_string(),
            url: upstream_url,
            headers: provider_request_headers,
            content_type,
            body: RequestBody {
                json_body: None,
                body_bytes_b64: None,
                body_ref: None,
            },
            stream,
        },
    );

    Ok(Some(AiStreamAttempt {
        plan,
        report_kind: payload.report_kind,
        report_context: payload.report_context,
    }))
}
