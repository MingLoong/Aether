mod agent_identity;
mod anthropic_compat;
pub mod antigravity;
pub mod auth;
mod auth_config;
mod cache;
pub mod claude_code;
pub mod client_identity;
pub mod cline;
pub use cline::{resolve_local_cline_request_auth, supports_local_cline_request_auth_resolution};
mod codex_fingerprint;
pub mod conversion;
mod diagnostics;
pub mod gemini_cli;
mod gemini_files;
mod generic_oauth;
pub mod grok;
mod headers;
pub mod kiro;
mod network;
pub mod oauth_refresh;
mod openai_image;
pub mod opencode;
mod outbound_request_policy;
pub mod policy;
pub mod provider_types;
mod request_body;
mod request_url;
pub mod rules;
pub mod same_format_provider;
pub mod snapshot;
mod standard;
pub mod url;
pub mod vertex;
mod video;
pub mod windsurf;
pub mod workbuddy;
pub mod xai;

pub use aether_oauth as oauth;
pub use agent_identity::{
    codex_agent_identity_auth_config_has_task_id,
    codex_agent_identity_authorization_matches_transport,
    codex_agent_identity_cached_entry_from_transport,
    codex_agent_identity_config_refresh_fingerprint, codex_agent_identity_credential_fingerprint,
    codex_agent_identity_entry_allows_task_rotation_from, codex_agent_identity_refresh_fingerprint,
    codex_agent_identity_transport_allows_task_rotation_from,
    codex_agent_identity_transport_credential_fingerprint,
    create_codex_agent_identity_from_access_token, create_codex_agent_identity_from_session_token,
    is_codex_agent_identity_auth_config_value, is_codex_agent_identity_authorization,
    is_codex_agent_identity_cached_entry, is_codex_agent_identity_invalid_task_response,
    is_codex_agent_identity_transport, register_codex_agent_identity_from_access_token,
    validate_codex_agent_identity_auth_config, CodexAgentIdentityEnrollmentError,
    CodexAgentIdentityRefreshAdapter, CodexAgentIdentityRegistrationOptions,
    CODEX_AGENT_IDENTITY_AGENT_REGISTRATION_REQUEST_ID, CODEX_AGENT_IDENTITY_AUTH_MODE,
    CODEX_AGENT_IDENTITY_CACHED_ENTRY_PROVIDER_TYPE, CODEX_AGENT_IDENTITY_PROVIDER_TYPE,
    CODEX_AGENT_IDENTITY_TASK_REGISTRATION_REQUEST_ID,
};
pub use anthropic_compat::{
    resolve_anthropic_compatibility_profile, validate_anthropic_compatibility_profile_config,
    AnthropicCompatibilityProfile, AnthropicCompatibilityProfileConfigError,
};
pub use auth::{build_passthrough_headers, ensure_upstream_auth_header};
pub use auth_config::apply_local_auth_config_header_overrides;
pub use cache::{provider_transport_snapshot_looks_refreshed, ProviderTransportSnapshotCacheKey};
pub use codex_fingerprint::{
    apply_codex_fingerprint_convergence, apply_codex_fingerprint_convergence_with_context,
    codex_fingerprint_convergence_enabled, CodexFingerprintConvergenceContext,
    CODEX_FINGERPRINT_CONFIG_NAMESPACE, CODEX_FINGERPRINT_ENABLED_CONFIG_KEY,
};
pub use conversion::{
    candidate_common_transport_skip_reason, candidate_transport_pair_skip_reason,
    request_conversion_direct_auth, request_conversion_enabled_for_transport,
    request_conversion_transport_supported, request_conversion_transport_unsupported_reason,
    request_pair_allowed_for_transport, request_pair_direct_auth,
    request_pair_transport_unsupported_reason, CandidateTransportPolicyFacts,
};
pub use diagnostics::{
    append_transport_diagnostics_to_value, build_request_trace_proxy_value,
    build_transport_diagnostics,
};
pub use gemini_cli::{
    build_gemini_cli_v1internal_request, build_gemini_cli_v1internal_url,
    classify_gemini_cli_v1internal_request_body, gemini_cli_v1internal_requires_upstream_streaming,
    is_gemini_cli_provider_transport, resolve_gemini_cli_project_id,
    resolve_local_gemini_cli_request_auth, GeminiCliRequestAuth, GeminiCliRequestAuthSupport,
    GeminiCliRequestAuthUnsupportedReason, GeminiCliRequestEnvelopeSupport,
    GeminiCliRequestEnvelopeUnsupportedReason, GeminiCliRequestUrlAction, GEMINI_CLI_PROVIDER_TYPE,
    GEMINI_CLI_RETRIEVE_USER_QUOTA_PATH, GEMINI_CLI_USER_AGENT,
    GEMINI_CLI_V1INTERNAL_ENVELOPE_NAME, GEMINI_CLI_V1INTERNAL_PATH_TEMPLATE,
};
pub use gemini_files::{
    build_gemini_files_headers, build_gemini_files_request_body, build_gemini_files_upstream_url,
    gemini_files_transport_unsupported_reason, resolve_gemini_files_auth, GeminiFilesHeadersInput,
    GeminiFilesRequestBodyError, GeminiFilesRequestBodyParts,
};
pub use generic_oauth::{
    resolve_local_generic_oauth_transport_authorization,
    supports_local_generic_oauth_request_auth_resolution, GenericOAuthRefreshAdapter,
};
pub use grok::{
    build_grok_app_chat_body, build_grok_browser_headers, build_grok_upstream_url, grok_base_url,
    grok_browser_profile_id_from_user_agent,
    grok_browser_profile_metadata_from_resolved_transport_profile,
    grok_browser_resolved_transport_profile,
    grok_browser_resolved_transport_profile_from_auth_config,
    grok_browser_transport_fingerprint_from_auth_config, is_grok_provider_transport,
    resolve_grok_session_auth, GrokBrowserProfileMetadata, GrokHeaderInput, GROK_CHAT_PATH,
    GROK_DEFAULT_BASE_URL, GROK_DEFAULT_BROWSER_PROFILE, GROK_DEFAULT_USER_AGENT,
    GROK_INTERNAL_HEADER, GROK_RATE_LIMITS_PATH,
};
pub use headers::{should_skip_request_header, should_skip_upstream_passthrough_header};
pub use network::{
    resolve_transport_execution_timeouts, resolve_transport_profile, resolve_transport_profile_id,
    resolve_transport_proxy_snapshot, resolve_transport_proxy_snapshot_with_tunnel_affinity,
    transport_profile_is_configured, transport_proxy_is_locally_supported,
    TransportTunnelAffinityLookup, TransportTunnelAttachmentOwner,
};
pub use oauth_refresh::{
    supports_local_oauth_request_auth_resolution, CachedOAuthEntry, LocalOAuthHttpExecutor,
    LocalOAuthHttpRequest, LocalOAuthHttpResponse, LocalOAuthRefreshCoordinator,
    LocalOAuthRefreshError, LocalOAuthResolution, LocalResolvedOAuthRequestAuth,
    ReqwestLocalOAuthHttpExecutor,
};
pub use openai_image::{
    build_openai_image_headers, build_openai_image_upstream_url,
    openai_image_transport_unsupported_reason, resolve_openai_image_auth,
    ProviderOpenAiImageHeadersInput,
};
pub use opencode::{
    apply_opencode_request_body_semantics, ensure_opencode_free_tier_tools,
    insert_opencode_request_headers_if_needed, is_opencode_provider_transport,
    new_opencode_session_id, opencode_dns_pin, opencode_dns_pin_from_extra, opencode_key_exit_ip,
    opencode_resolved_transport_profile, opencode_user_agent, parse_opencode_exit_ip,
    OPENCODE_BASE_URL, OPENCODE_CHAT_PATH, OPENCODE_DEFAULT_CLIENT_VERSION,
    OPENCODE_MIN_CLIENT_VERSION, OPENCODE_PROVIDER_TYPE,
};
pub use outbound_request_policy::{
    apply_provider_outbound_request_policies, ProviderOutboundRequestContext,
    ProviderOutboundRequestIdentityScope, ProviderOutboundRequestMutationScope,
    ProviderOutboundRequestPolicy, ProviderOutboundRequestPolicyOutcome,
    ProviderOutboundRequestPolicyReason, ProviderOutboundRequestPolicyResult,
    PROVIDER_OUTBOUND_CONTEXT_MAX_VALUE_BYTES,
};
pub use policy::{
    local_gemini_transport_unsupported_reason,
    local_gemini_transport_unsupported_reason_with_network,
    local_openai_chat_transport_unsupported_reason, local_standard_transport_unsupported_reason,
    local_standard_transport_unsupported_reason_with_network, supports_local_gemini_transport,
    supports_local_gemini_transport_with_network, supports_local_standard_transport,
};
pub use request_body::{
    apply_transport_request_body_semantics, TransportRequestBodySemanticsError,
};
pub use request_url::{
    build_cross_format_openai_chat_upstream_url, build_cross_format_openai_responses_upstream_url,
    build_kiro_cross_format_upstream_url, build_local_openai_chat_upstream_url,
    build_local_openai_responses_upstream_url, build_transport_request_url,
    build_transport_request_url_for_request_body, gemini_embedding_request_body_uses_batch,
    transport_supports_api_operation, TransportRequestUrlParams,
};
pub use rules::{
    apply_local_body_rules, apply_local_body_rules_with_request_headers, apply_local_header_rules,
    apply_local_header_rules_with_request_headers, body_rules_are_locally_supported,
    body_rules_handle_path, body_rules_have_enabled_rules, header_rules_are_locally_supported,
    header_rules_have_enabled_rules,
};
pub use same_format_provider::{
    build_same_format_provider_headers, build_same_format_provider_request_body,
    build_same_format_provider_request_body_for_operation,
    build_same_format_provider_request_body_with_compatibility_report,
    build_same_format_provider_request_body_with_compatibility_report_and_reasoning_replay_policy,
    build_same_format_provider_upstream_url, classify_same_format_provider_request_behavior,
    classify_same_format_provider_request_behavior_for_operation,
    enforce_same_format_provider_api_operation_body_policy,
    resolve_same_format_provider_direct_auth, same_format_provider_transport_supported,
    same_format_provider_transport_unsupported_reason,
    same_format_provider_transport_unsupported_reason_for_trace,
    should_try_same_format_provider_oauth_auth, SameFormatProviderCompatibilityEdit,
    SameFormatProviderCompatibilityEditAction, SameFormatProviderFamily,
    SameFormatProviderHeadersInput, SameFormatProviderRequestBehavior,
    SameFormatProviderRequestBehaviorParams, SameFormatProviderRequestBodyInput,
    SameFormatProviderRequestBodyOutput, SameFormatProviderUpstreamUrlParams,
};
pub use snapshot::{
    read_provider_transport_snapshot, GatewayProviderTransportSnapshot,
    ProviderTransportSnapshotSource,
};
pub use standard::{
    apply_standard_provider_request_body_rules,
    apply_standard_provider_request_body_rules_with_request_headers,
    build_standard_plan_fallback_headers, build_standard_plan_fallback_openai_chat_url,
    build_standard_plan_fallback_openai_responses_url, build_standard_provider_request_headers,
    StandardPlanFallbackAcceptPolicy, StandardPlanFallbackHeadersInput,
    StandardProviderRequestHeaders, StandardProviderRequestHeadersInput,
};
pub use vertex::{
    is_vertex_api_key_transport_context, is_vertex_service_account_transport_context,
    is_vertex_transport_context, uses_vertex_api_key_query_auth,
};
pub use video::{
    build_video_create_headers, build_video_create_request_body, build_video_create_upstream_url,
    reconstruct_local_video_task_snapshot, resolve_local_video_task_transport,
    resolve_video_create_auth, video_create_transport_unsupported_reason,
    ProviderVideoCreateFamily, ProviderVideoCreateHeadersInput, VideoTaskTransportSnapshotLookup,
};
pub use windsurf::{
    build_windsurf_cascade_headers, build_windsurf_cascade_request_body,
    build_windsurf_cascade_upstream_url, is_windsurf_provider_transport,
    local_windsurf_request_transport_unsupported_reason_with_network, GET_CHAT_MESSAGE_PATH,
    WINDSURF_ENVELOPE_NAME,
};
pub use workbuddy::failure::{
    classify_workbuddy_failure, workbuddy_oauth_invalid_reason, WorkbuddyFailureKind,
};
pub use workbuddy::refresh::{
    supports_local_workbuddy_request_auth_resolution, WorkbuddyOAuthRefreshAdapter,
};
pub use workbuddy::{
    apply_workbuddy_request_body_semantics, classify_workbuddy_checkin_outcome,
    derive_workbuddy_account_stable_id, insert_workbuddy_conversation_headers,
    insert_workbuddy_conversation_headers_if_needed, insert_workbuddy_request_headers,
    insert_workbuddy_request_headers_if_needed, is_workbuddy_global_domain,
    is_workbuddy_growth_unavailable, is_workbuddy_provider_transport, is_workbuddy_report_accepted,
    parse_workbuddy_lottery_chances, parse_workbuddy_streak_status, resolve_workbuddy_access_token,
    workbuddy_auth_config, workbuddy_billing_base_url, workbuddy_billing_path_candidates,
    workbuddy_client_token, workbuddy_identity, workbuddy_user_agent, WorkbuddyBillingEndpoint,
    WorkbuddyCheckinOutcome, WorkbuddyIdentity, WorkbuddyRealm, WorkbuddyStreakStatus,
    WorkbuddyStreakTier, WORKBUDDY_ACTIVITY_DEFAULT_MODEL_ID,
    WORKBUDDY_ACTIVITY_DEFAULT_MODEL_NAME, WORKBUDDY_AUTH_STATE_PATH, WORKBUDDY_AUTH_TOKEN_PATH,
    WORKBUDDY_BILLING_BASE_URL_CN, WORKBUDDY_BILLING_BASE_URL_GLOBAL, WORKBUDDY_CHAT_BASE_URL_CN,
    WORKBUDDY_CHAT_BASE_URL_GLOBAL, WORKBUDDY_CHAT_PATH, WORKBUDDY_DAILY_CHECKIN_PATH,
    WORKBUDDY_DAILY_CHECKIN_PATH_GLOBAL, WORKBUDDY_DEFAULT_CLIENT_VERSION,
    WORKBUDDY_DEFAULT_CLI_VERSION, WORKBUDDY_ENTERPRISE_USAGE_PATH,
    WORKBUDDY_GROWTH_LOTTERY_DRAW_PATH, WORKBUDDY_GROWTH_LOTTERY_SUMMARY_PATH,
    WORKBUDDY_GROWTH_REDEEM_PATH, WORKBUDDY_GROWTH_STREAK_PATH, WORKBUDDY_IDE_USER_AGENT,
    WORKBUDDY_LOGIN_ACCOUNT_PATH, WORKBUDDY_LOGIN_USER_AGENT, WORKBUDDY_MODELS_CONFIG_PATH,
    WORKBUDDY_ORIGIN_CN, WORKBUDDY_ORIGIN_GLOBAL, WORKBUDDY_PROVIDER_TYPE, WORKBUDDY_REFRESH_PATH,
    WORKBUDDY_REPORT_PATH, WORKBUDDY_REQUEST_LEVEL_ERROR_STOP_PATTERN,
    WORKBUDDY_USER_RESOURCE_PATH, WORKBUDDY_USER_RESOURCE_PATH_GLOBAL, WORKBUDDY_WEB_BASE_URL_CN,
};
pub use xai::{
    extract_xai_user_id_from_auth_config, extract_xai_user_id_from_value,
    insert_cli_identity_headers, insert_cli_identity_headers_if_needed, is_xai_provider_transport,
    resolved_xai_request_base_url, resolved_xai_upstream_base_url, set_xai_client_version,
    should_attach_cli_identity_headers, xai_auth_uses_api, xai_client_version,
    xai_uses_official_api, XAI_API_BASE_URL, XAI_CHAT_PROXY_BASE_URL, XAI_DEFAULT_CLIENT_VERSION,
    XAI_PROVIDER_TYPE,
};
