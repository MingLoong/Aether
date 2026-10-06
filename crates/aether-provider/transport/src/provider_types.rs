#[derive(Debug, Clone, Copy)]
pub struct ProviderOAuthTemplate {
    pub provider_type: &'static str,
    pub display_name: &'static str,
    pub authorize_url: &'static str,
    pub token_url: &'static str,
    pub client_id: &'static str,
    pub scopes: &'static [&'static str],
    pub redirect_uri: &'static str,
    pub use_pkce: bool,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FixedProviderEndpointConfigValue {
    String(&'static str),
    Bool(bool),
    I64(i64),
}

impl FixedProviderEndpointConfigValue {
    pub fn to_json_value(self) -> serde_json::Value {
        match self {
            Self::String(value) => serde_json::Value::String(value.to_string()),
            Self::Bool(value) => serde_json::Value::Bool(value),
            Self::I64(value) => serde_json::Value::Number(value.into()),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct FixedProviderEndpointConfigDefault {
    pub key: &'static str,
    pub value: FixedProviderEndpointConfigValue,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct FixedProviderEndpointTemplate {
    pub item_key: &'static str,
    pub api_format: &'static str,
    pub custom_path: Option<&'static str>,
    pub config_defaults: &'static [FixedProviderEndpointConfigDefault],
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ProviderApiFormatInheritance {
    None,
    OAuth,
    OAuthOrBearer,
    OAuthOrServiceAccount,
    OAuthOrConfiguredBearer,
}

impl ProviderApiFormatInheritance {
    pub fn key_inherits_api_formats(
        self,
        auth_type: &str,
        decrypted_auth_config: Option<&str>,
    ) -> bool {
        let auth_type = auth_type.trim().to_ascii_lowercase();
        match self {
            Self::None => false,
            Self::OAuth => auth_type == "oauth",
            Self::OAuthOrBearer => auth_type == "oauth" || auth_type == "bearer",
            Self::OAuthOrServiceAccount => {
                auth_type == "oauth" || auth_type == "service_account" || auth_type == "vertex_ai"
            }
            Self::OAuthOrConfiguredBearer => {
                auth_type == "oauth"
                    || auth_type == "bearer"
                        && decrypted_auth_config
                            .map(str::trim)
                            .is_some_and(|value| !value.is_empty())
            }
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ProviderLocalEmbeddingSupport {
    None,
    AnyKnown,
    OpenAi,
    Gemini,
    Jina,
    Doubao,
    Aliyun,
}

impl ProviderLocalEmbeddingSupport {
    pub fn supports_api_format(self, api_format: &str) -> bool {
        let api_format = aether_ai_formats::normalize_api_format_alias(api_format);
        match self {
            Self::None => false,
            Self::AnyKnown => matches!(
                api_format.as_str(),
                "openai:embedding"
                    | "openai:rerank"
                    | "gemini:embedding"
                    | "jina:embedding"
                    | "jina:rerank"
                    | "doubao:embedding"
                    | "aliyun:multimodal_embedding"
            ),
            Self::OpenAi => matches!(api_format.as_str(), "openai:embedding" | "openai:rerank"),
            Self::Gemini => api_format == "gemini:embedding",
            Self::Jina => matches!(api_format.as_str(), "jina:embedding" | "jina:rerank"),
            Self::Doubao => api_format == "doubao:embedding",
            Self::Aliyun => api_format == "aliyun:multimodal_embedding",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ProviderRuntimePolicy {
    pub fixed_provider: bool,
    pub api_format_inheritance: ProviderApiFormatInheritance,
    pub enable_format_conversion_by_default: bool,
    pub allow_auth_channel_mismatch_by_default: bool,
    pub oauth_is_bearer_like: bool,
    pub supports_model_fetch: bool,
    pub supports_local_openai_chat_transport: bool,
    pub supports_local_same_format_transport: bool,
    pub local_embedding_support: ProviderLocalEmbeddingSupport,
}

impl ProviderRuntimePolicy {
    pub const fn standard() -> Self {
        Self {
            fixed_provider: false,
            api_format_inheritance: ProviderApiFormatInheritance::None,
            enable_format_conversion_by_default: false,
            allow_auth_channel_mismatch_by_default: false,
            oauth_is_bearer_like: false,
            supports_model_fetch: true,
            supports_local_openai_chat_transport: true,
            supports_local_same_format_transport: true,
            local_embedding_support: ProviderLocalEmbeddingSupport::None,
        }
    }

    pub fn key_inherits_api_formats(
        self,
        auth_type: &str,
        decrypted_auth_config: Option<&str>,
    ) -> bool {
        self.api_format_inheritance
            .key_inherits_api_formats(auth_type, decrypted_auth_config)
    }

    pub fn supports_local_embedding_transport(self, api_format: &str) -> bool {
        self.local_embedding_support.supports_api_format(api_format)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct FixedProviderTemplate {
    pub provider_type: &'static str,
    pub version: u32,
    pub base_url: &'static str,
    pub endpoints: &'static [FixedProviderEndpointTemplate],
    pub runtime_policy: ProviderRuntimePolicy,
}

const EMPTY_ENDPOINT_CONFIG_DEFAULTS: &[FixedProviderEndpointConfigDefault] = &[];
const FORCE_STREAM_ENDPOINT_CONFIG_DEFAULTS: &[FixedProviderEndpointConfigDefault] =
    &[FixedProviderEndpointConfigDefault {
        key: "upstream_stream_policy",
        value: FixedProviderEndpointConfigValue::String("force_stream"),
    }];
const AUTO_STREAM_ENDPOINT_CONFIG_DEFAULTS: &[FixedProviderEndpointConfigDefault] =
    &[FixedProviderEndpointConfigDefault {
        key: "upstream_stream_policy",
        value: FixedProviderEndpointConfigValue::String("auto"),
    }];

const STANDARD_RUNTIME_POLICY: ProviderRuntimePolicy = ProviderRuntimePolicy::standard();
const CUSTOM_RUNTIME_POLICY: ProviderRuntimePolicy = ProviderRuntimePolicy {
    local_embedding_support: ProviderLocalEmbeddingSupport::AnyKnown,
    ..STANDARD_RUNTIME_POLICY
};
const OPENAI_RUNTIME_POLICY: ProviderRuntimePolicy = ProviderRuntimePolicy {
    local_embedding_support: ProviderLocalEmbeddingSupport::OpenAi,
    ..STANDARD_RUNTIME_POLICY
};
const GEMINI_RUNTIME_POLICY: ProviderRuntimePolicy = ProviderRuntimePolicy {
    local_embedding_support: ProviderLocalEmbeddingSupport::Gemini,
    ..STANDARD_RUNTIME_POLICY
};
const JINA_RUNTIME_POLICY: ProviderRuntimePolicy = ProviderRuntimePolicy {
    local_embedding_support: ProviderLocalEmbeddingSupport::Jina,
    ..STANDARD_RUNTIME_POLICY
};
const DOUBAO_RUNTIME_POLICY: ProviderRuntimePolicy = ProviderRuntimePolicy {
    local_embedding_support: ProviderLocalEmbeddingSupport::Doubao,
    ..STANDARD_RUNTIME_POLICY
};
const ALIYUN_RUNTIME_POLICY: ProviderRuntimePolicy = ProviderRuntimePolicy {
    local_embedding_support: ProviderLocalEmbeddingSupport::Aliyun,
    ..STANDARD_RUNTIME_POLICY
};

const CLAUDE_CODE_RUNTIME_POLICY: ProviderRuntimePolicy = ProviderRuntimePolicy {
    fixed_provider: true,
    api_format_inheritance: ProviderApiFormatInheritance::OAuth,
    enable_format_conversion_by_default: true,
    oauth_is_bearer_like: true,
    supports_model_fetch: false,
    supports_local_openai_chat_transport: false,
    supports_local_same_format_transport: false,
    ..STANDARD_RUNTIME_POLICY
};
const CODEX_RUNTIME_POLICY: ProviderRuntimePolicy = ProviderRuntimePolicy {
    fixed_provider: true,
    api_format_inheritance: ProviderApiFormatInheritance::OAuth,
    enable_format_conversion_by_default: true,
    supports_model_fetch: false,
    supports_local_openai_chat_transport: false,
    ..STANDARD_RUNTIME_POLICY
};
const CHATGPT_WEB_RUNTIME_POLICY: ProviderRuntimePolicy = ProviderRuntimePolicy {
    fixed_provider: true,
    api_format_inheritance: ProviderApiFormatInheritance::OAuthOrBearer,
    enable_format_conversion_by_default: true,
    oauth_is_bearer_like: true,
    supports_model_fetch: false,
    supports_local_openai_chat_transport: false,
    supports_local_same_format_transport: false,
    ..STANDARD_RUNTIME_POLICY
};
const GEMINI_CLI_RUNTIME_POLICY: ProviderRuntimePolicy = ProviderRuntimePolicy {
    fixed_provider: true,
    api_format_inheritance: ProviderApiFormatInheritance::OAuth,
    oauth_is_bearer_like: true,
    supports_local_openai_chat_transport: false,
    ..STANDARD_RUNTIME_POLICY
};
const VERTEX_AI_RUNTIME_POLICY: ProviderRuntimePolicy = ProviderRuntimePolicy {
    fixed_provider: true,
    api_format_inheritance: ProviderApiFormatInheritance::OAuthOrServiceAccount,
    enable_format_conversion_by_default: true,
    supports_model_fetch: false,
    supports_local_openai_chat_transport: false,
    supports_local_same_format_transport: false,
    local_embedding_support: ProviderLocalEmbeddingSupport::Gemini,
    ..STANDARD_RUNTIME_POLICY
};
const ANTIGRAVITY_RUNTIME_POLICY: ProviderRuntimePolicy = ProviderRuntimePolicy {
    fixed_provider: true,
    api_format_inheritance: ProviderApiFormatInheritance::OAuth,
    enable_format_conversion_by_default: true,
    oauth_is_bearer_like: true,
    supports_model_fetch: false,
    supports_local_openai_chat_transport: false,
    supports_local_same_format_transport: false,
    ..STANDARD_RUNTIME_POLICY
};
const GROK_RUNTIME_POLICY: ProviderRuntimePolicy = ProviderRuntimePolicy {
    fixed_provider: true,
    api_format_inheritance: ProviderApiFormatInheritance::OAuth,
    enable_format_conversion_by_default: true,
    supports_model_fetch: false,
    supports_local_openai_chat_transport: false,
    supports_local_same_format_transport: false,
    ..STANDARD_RUNTIME_POLICY
};

const WINDSURF_RUNTIME_POLICY: ProviderRuntimePolicy = ProviderRuntimePolicy {
    fixed_provider: true,
    api_format_inheritance: ProviderApiFormatInheritance::OAuthOrBearer,
    enable_format_conversion_by_default: true,
    oauth_is_bearer_like: true,
    supports_model_fetch: false,
    supports_local_openai_chat_transport: false,
    supports_local_same_format_transport: false,
    ..STANDARD_RUNTIME_POLICY
};

const XAI_RUNTIME_POLICY: ProviderRuntimePolicy = ProviderRuntimePolicy {
    fixed_provider: true,
    api_format_inheritance: ProviderApiFormatInheritance::OAuthOrBearer,
    enable_format_conversion_by_default: true,
    oauth_is_bearer_like: true,
    supports_model_fetch: false,
    supports_local_openai_chat_transport: false,
    supports_local_same_format_transport: true,
    ..STANDARD_RUNTIME_POLICY
};

const OPENCODE_RUNTIME_POLICY: ProviderRuntimePolicy = ProviderRuntimePolicy {
    // OpenCode is free-form so Endpoint.base_url can select the official
    // domain or a front-proxy CDN domain.
    fixed_provider: false,
    api_format_inheritance: ProviderApiFormatInheritance::None,
    enable_format_conversion_by_default: true,
    allow_auth_channel_mismatch_by_default: true,
    oauth_is_bearer_like: true,
    supports_model_fetch: true,
    supports_local_openai_chat_transport: true,
    supports_local_same_format_transport: true,
    local_embedding_support: ProviderLocalEmbeddingSupport::None,
};

const CLAUDE_CODE_FIXED_PROVIDER_TEMPLATE: FixedProviderTemplate = FixedProviderTemplate {
    provider_type: "claude_code",
    version: 2,
    base_url: "https://api.anthropic.com/v1",
    endpoints: &[FixedProviderEndpointTemplate {
        item_key: "claude:messages",
        api_format: "claude:messages",
        custom_path: None,
        config_defaults: EMPTY_ENDPOINT_CONFIG_DEFAULTS,
    }],
    runtime_policy: CLAUDE_CODE_RUNTIME_POLICY,
};

const CODEX_FIXED_PROVIDER_TEMPLATE: FixedProviderTemplate = FixedProviderTemplate {
    provider_type: "codex",
    version: 2,
    base_url: "https://chatgpt.com/backend-api/codex",
    endpoints: &[
        FixedProviderEndpointTemplate {
            item_key: "openai:responses",
            api_format: "openai:responses",
            custom_path: None,
            config_defaults: FORCE_STREAM_ENDPOINT_CONFIG_DEFAULTS,
        },
        FixedProviderEndpointTemplate {
            item_key: "openai:responses:compact",
            api_format: "openai:responses:compact",
            custom_path: None,
            config_defaults: EMPTY_ENDPOINT_CONFIG_DEFAULTS,
        },
        FixedProviderEndpointTemplate {
            item_key: "openai:search",
            api_format: "openai:search",
            custom_path: None,
            config_defaults: EMPTY_ENDPOINT_CONFIG_DEFAULTS,
        },
        FixedProviderEndpointTemplate {
            item_key: "openai:image",
            api_format: "openai:image",
            custom_path: None,
            config_defaults: EMPTY_ENDPOINT_CONFIG_DEFAULTS,
        },
        FixedProviderEndpointTemplate {
            item_key: "codex:live",
            api_format: "codex:live",
            custom_path: None,
            config_defaults: EMPTY_ENDPOINT_CONFIG_DEFAULTS,
        },
    ],
    runtime_policy: CODEX_RUNTIME_POLICY,
};

const CHATGPT_WEB_FIXED_PROVIDER_TEMPLATE: FixedProviderTemplate = FixedProviderTemplate {
    provider_type: "chatgpt_web",
    version: 1,
    base_url: "https://chatgpt.com",
    endpoints: &[FixedProviderEndpointTemplate {
        item_key: "openai:image",
        api_format: "openai:image",
        custom_path: None,
        config_defaults: FORCE_STREAM_ENDPOINT_CONFIG_DEFAULTS,
    }],
    runtime_policy: CHATGPT_WEB_RUNTIME_POLICY,
};

const KIRO_FIXED_PROVIDER_TEMPLATE: FixedProviderTemplate = FixedProviderTemplate {
    provider_type: "kiro",
    version: 1,
    base_url: "https://q.{region}.amazonaws.com",
    endpoints: &[FixedProviderEndpointTemplate {
        item_key: "claude:messages",
        api_format: "claude:messages",
        custom_path: None,
        config_defaults: EMPTY_ENDPOINT_CONFIG_DEFAULTS,
    }],
    runtime_policy: crate::kiro::RUNTIME_POLICY,
};

const GEMINI_CLI_FIXED_PROVIDER_TEMPLATE: FixedProviderTemplate = FixedProviderTemplate {
    provider_type: "gemini_cli",
    version: 3,
    base_url: "https://cloudcode-pa.googleapis.com",
    endpoints: &[FixedProviderEndpointTemplate {
        item_key: "gemini:generate_content",
        api_format: "gemini:generate_content",
        custom_path: Some("/v1internal:{action}"),
        config_defaults: AUTO_STREAM_ENDPOINT_CONFIG_DEFAULTS,
    }],
    runtime_policy: GEMINI_CLI_RUNTIME_POLICY,
};

const VERTEX_AI_FIXED_PROVIDER_TEMPLATE: FixedProviderTemplate = FixedProviderTemplate {
    provider_type: "vertex_ai",
    version: 2,
    base_url: "https://aiplatform.googleapis.com",
    endpoints: &[
        FixedProviderEndpointTemplate {
            item_key: "gemini:generate_content",
            api_format: "gemini:generate_content",
            custom_path: None,
            config_defaults: EMPTY_ENDPOINT_CONFIG_DEFAULTS,
        },
        FixedProviderEndpointTemplate {
            item_key: "gemini:embedding",
            api_format: "gemini:embedding",
            custom_path: None,
            config_defaults: EMPTY_ENDPOINT_CONFIG_DEFAULTS,
        },
    ],
    runtime_policy: VERTEX_AI_RUNTIME_POLICY,
};

const ANTIGRAVITY_FIXED_PROVIDER_TEMPLATE: FixedProviderTemplate = FixedProviderTemplate {
    provider_type: "antigravity",
    version: 2,
    base_url: "https://daily-cloudcode-pa.googleapis.com",
    endpoints: &[FixedProviderEndpointTemplate {
        item_key: "gemini:generate_content",
        api_format: "gemini:generate_content",
        custom_path: None,
        config_defaults: EMPTY_ENDPOINT_CONFIG_DEFAULTS,
    }],
    runtime_policy: ANTIGRAVITY_RUNTIME_POLICY,
};

const GROK_FIXED_PROVIDER_TEMPLATE: FixedProviderTemplate = FixedProviderTemplate {
    provider_type: "grok",
    version: 1,
    base_url: "https://grok.com",
    endpoints: &[
        FixedProviderEndpointTemplate {
            item_key: "openai:chat",
            api_format: "openai:chat",
            custom_path: None,
            config_defaults: EMPTY_ENDPOINT_CONFIG_DEFAULTS,
        },
        FixedProviderEndpointTemplate {
            item_key: "openai:responses",
            api_format: "openai:responses",
            custom_path: None,
            config_defaults: EMPTY_ENDPOINT_CONFIG_DEFAULTS,
        },
        FixedProviderEndpointTemplate {
            item_key: "claude:messages",
            api_format: "claude:messages",
            custom_path: None,
            config_defaults: EMPTY_ENDPOINT_CONFIG_DEFAULTS,
        },
        FixedProviderEndpointTemplate {
            item_key: "openai:image",
            api_format: "openai:image",
            custom_path: None,
            config_defaults: EMPTY_ENDPOINT_CONFIG_DEFAULTS,
        },
    ],
    runtime_policy: GROK_RUNTIME_POLICY,
};

const WINDSURF_FIXED_PROVIDER_TEMPLATE: FixedProviderTemplate = FixedProviderTemplate {
    provider_type: "windsurf",
    version: 1,
    base_url: "https://server.codeium.com",
    endpoints: &[FixedProviderEndpointTemplate {
        item_key: "openai:chat",
        api_format: "openai:chat",
        custom_path: None,
        config_defaults: EMPTY_ENDPOINT_CONFIG_DEFAULTS,
    }],
    runtime_policy: WINDSURF_RUNTIME_POLICY,
};

const XAI_FIXED_PROVIDER_TEMPLATE: FixedProviderTemplate = FixedProviderTemplate {
    provider_type: "xai",
    version: 2,
    base_url: crate::xai::XAI_CHAT_PROXY_BASE_URL,
    endpoints: &[
        FixedProviderEndpointTemplate {
            item_key: "openai:responses",
            api_format: "openai:responses",
            custom_path: None,
            config_defaults: FORCE_STREAM_ENDPOINT_CONFIG_DEFAULTS,
        },
        FixedProviderEndpointTemplate {
            item_key: "openai:responses:compact",
            api_format: "openai:responses:compact",
            custom_path: None,
            config_defaults: EMPTY_ENDPOINT_CONFIG_DEFAULTS,
        },
        FixedProviderEndpointTemplate {
            item_key: "openai:image",
            api_format: "openai:image",
            custom_path: None,
            config_defaults: EMPTY_ENDPOINT_CONFIG_DEFAULTS,
        },
        FixedProviderEndpointTemplate {
            item_key: "openai:video",
            api_format: "openai:video",
            custom_path: None,
            config_defaults: EMPTY_ENDPOINT_CONFIG_DEFAULTS,
        },
    ],
    runtime_policy: XAI_RUNTIME_POLICY,
};

/// AMD（Radeon）只有一个上游，地址固定，因此是 fixed provider。
///
/// 与 `opencode` 不同：`opencode` 不注册模板，是因为它要在「官方域名」与「前置 CDN
/// 域名」之间自由选择，`base_url` 不能锁死，前端也因此保留手填端点的表单。
///
/// AMD 恰好相反：`base_url` 被锁死，前端对 fixed provider 会隐藏「添加端点」表单
/// （端点由模板自动创建）。所以模板是必需的——缺了它，新建 AMD 供应商会得到零端点
/// 且无法手动添加的死胡同。
const AMD_FIXED_PROVIDER_TEMPLATE: FixedProviderTemplate = FixedProviderTemplate {
    provider_type: "amd",
    version: 1,
    // 与前端 `AMD_DEFAULT_BASE_URL` 保持一致。负载与配额两个面板都靠 base_url 里的
    // `/radeon/api/v1` 标记做字符串推导，改动这里必须同步改前端。
    base_url: "https://developer.amd.com.cn/radeon/api/v1",
    endpoints: &[FixedProviderEndpointTemplate {
        item_key: "openai:chat",
        api_format: "openai:chat",
        custom_path: None,
        config_defaults: EMPTY_ENDPOINT_CONFIG_DEFAULTS,
    }],
    runtime_policy: STANDARD_RUNTIME_POLICY,
};

/// OpenCode 官方直连域名。
pub const OPENCODE_ORIGINAL_DOMAIN: &str = "opencode.ai";

/// OpenCode 官方端点的完整 base_url。
///
/// 与 `OPENCODE_ORIGINAL_DOMAIN` 分开是有原因的：`build_admin_fixed_provider_endpoint_defaults`
/// 会把模板的 base_url 交给 `normalize_admin_base_url`，只给裸域名会失败——创建供应商直接
/// 500。第一版模板就踩了这个坑，故显式区分「域名」与「完整 URL」，并在测试里断言格式。
pub const OPENCODE_ORIGINAL_BASE_URL: &str = "https://opencode.ai/";

/// OpenCode 官方对话入口路径。
pub const OPENCODE_CHAT_CUSTOM_PATH: &str = "/zen/v1/chat/completions";

/// OpenCode 的固定端点模板。
///
/// 之前 opencode 故意不注册模板，导致新建供应商后一个端点都没有、不能直接用。这里补上，
/// 与其它类型一致。
///
/// **这不影响「官方域名 / 前置 CDN 域名自由切换」这个核心能力**，机制上有三道保障：
///
/// 1. 用户改 base_url 时 `apply_admin_fixed_provider_endpoint_template_overrides` 记录
///    `overrides`，reconcile 见 `overrides.contains(OVERRIDE_BASE_URL)` 就跳过该字段。
/// 2. reconcile 只「停用 + 标记 retired」模板外的端点，用户手加的（无模板元数据）直接跳过。
/// 3. `runtime_policy` 原样复用 `OPENCODE_RUNTIME_POLICY`，其中 `fixed_provider: false`
///    不变——所以 `provider_type_is_fixed("opencode")` 仍是 false，OAuth 与密钥继承行为
///    一字未改。模板只管端点 reconcile，不管密钥。
const OPENCODE_FIXED_PROVIDER_TEMPLATE: FixedProviderTemplate = FixedProviderTemplate {
    provider_type: "opencode",
    version: 1,
    base_url: OPENCODE_ORIGINAL_BASE_URL,
    endpoints: &[FixedProviderEndpointTemplate {
        item_key: "openai:chat",
        api_format: "openai:chat",
        // 取自生产环境 opencode-cdn 供应商的实际配置：对话入口在 /zen/ 下，不是
        // openai:responses。
        custom_path: Some(OPENCODE_CHAT_CUSTOM_PATH),
        config_defaults: EMPTY_ENDPOINT_CONFIG_DEFAULTS,
    }],
    runtime_policy: OPENCODE_RUNTIME_POLICY,
};

pub fn provider_type_is_fixed(provider_type: &str) -> bool {
    provider_runtime_policy(provider_type).fixed_provider
}

pub fn fixed_provider_key_inherits_api_formats(
    provider_type: &str,
    auth_type: &str,
    decrypted_auth_config: Option<&str>,
) -> bool {
    provider_runtime_policy(provider_type)
        .key_inherits_api_formats(auth_type, decrypted_auth_config)
}

pub fn provider_type_enables_format_conversion_by_default(provider_type: &str) -> bool {
    provider_runtime_policy(provider_type).enable_format_conversion_by_default
}

pub fn provider_type_allows_auth_channel_mismatch_by_default(provider_type: &str) -> bool {
    provider_runtime_policy(provider_type).allow_auth_channel_mismatch_by_default
}

pub fn provider_type_oauth_is_bearer_like(provider_type: &str) -> bool {
    provider_runtime_policy(provider_type).oauth_is_bearer_like
}

pub fn provider_runtime_policy(provider_type: &str) -> ProviderRuntimePolicy {
    if let Some(template) = fixed_provider_template(provider_type) {
        return template.runtime_policy;
    }

    match provider_type.trim().to_ascii_lowercase().as_str() {
        "custom" => CUSTOM_RUNTIME_POLICY,
        "openai" => OPENAI_RUNTIME_POLICY,
        "opencode" => OPENCODE_RUNTIME_POLICY,
        "gemini" | "google" => GEMINI_RUNTIME_POLICY,
        "jina" => JINA_RUNTIME_POLICY,
        "doubao" | "volcengine" => DOUBAO_RUNTIME_POLICY,
        "aliyun" | "dashscope" => ALIYUN_RUNTIME_POLICY,
        _ => STANDARD_RUNTIME_POLICY,
    }
}

pub fn fixed_provider_template(provider_type: &str) -> Option<&'static FixedProviderTemplate> {
    match provider_type.trim().to_ascii_lowercase().as_str() {
        "claude_code" => Some(&CLAUDE_CODE_FIXED_PROVIDER_TEMPLATE),
        "codex" => Some(&CODEX_FIXED_PROVIDER_TEMPLATE),
        "chatgpt_web" => Some(&CHATGPT_WEB_FIXED_PROVIDER_TEMPLATE),
        "kiro" => Some(&KIRO_FIXED_PROVIDER_TEMPLATE),
        "grok" => Some(&GROK_FIXED_PROVIDER_TEMPLATE),
        "gemini_cli" => Some(&GEMINI_CLI_FIXED_PROVIDER_TEMPLATE),
        "vertex_ai" => Some(&VERTEX_AI_FIXED_PROVIDER_TEMPLATE),
        "antigravity" => Some(&ANTIGRAVITY_FIXED_PROVIDER_TEMPLATE),
        "windsurf" => Some(&WINDSURF_FIXED_PROVIDER_TEMPLATE),
        "xai" => Some(&XAI_FIXED_PROVIDER_TEMPLATE),
        "amd" => Some(&AMD_FIXED_PROVIDER_TEMPLATE),
        "opencode" => Some(&OPENCODE_FIXED_PROVIDER_TEMPLATE),
        _ => None,
    }
}

pub fn fixed_provider_endpoint_template_by_api_format(
    provider_type: &str,
    api_format: &str,
) -> Option<&'static FixedProviderEndpointTemplate> {
    let normalized = aether_ai_formats::normalize_api_format_alias(api_format);
    fixed_provider_template(provider_type)?
        .endpoints
        .iter()
        .find(|item| item.api_format.eq_ignore_ascii_case(&normalized))
}

pub fn provider_type_supports_model_fetch(provider_type: &str) -> bool {
    provider_runtime_policy(provider_type).supports_model_fetch
}

pub fn provider_type_supports_local_openai_chat_transport(provider_type: &str) -> bool {
    provider_runtime_policy(provider_type).supports_local_openai_chat_transport
}

pub fn provider_type_supports_local_same_format_transport(provider_type: &str) -> bool {
    provider_runtime_policy(provider_type).supports_local_same_format_transport
}

pub fn provider_type_supports_local_embedding_transport(
    provider_type: &str,
    api_format: &str,
) -> bool {
    provider_runtime_policy(provider_type).supports_local_embedding_transport(api_format)
}

pub fn is_codex_cli_backend_url(url: &str) -> bool {
    let url = url.trim().to_ascii_lowercase();
    url.contains("/codex") && (url.contains("/backend-api/") || url.contains("/backendapi/"))
}

pub fn provider_type_is_fixed_for_admin_oauth(provider_type: &str) -> bool {
    provider_type_is_fixed(provider_type)
}

pub fn provider_type_admin_oauth_template(provider_type: &str) -> Option<ProviderOAuthTemplate> {
    match provider_type.trim().to_ascii_lowercase().as_str() {
        "claude_code" => Some(ProviderOAuthTemplate {
            provider_type: "claude_code",
            display_name: "Claude Code",
            authorize_url: aether_oauth::provider::providers::CLAUDE_CODE_AUTHORIZE_URL,
            token_url: aether_oauth::provider::providers::CLAUDE_CODE_TOKEN_URL,
            client_id: aether_oauth::provider::providers::CLAUDE_CODE_CLIENT_ID,
            scopes: aether_oauth::provider::providers::CLAUDE_CODE_OAUTH_SCOPES,
            redirect_uri: aether_oauth::provider::providers::CLAUDE_CODE_REDIRECT_URI,
            use_pkce: true,
        }),
        "codex" => Some(ProviderOAuthTemplate {
            provider_type: "codex",
            display_name: "Codex",
            authorize_url: "https://auth.openai.com/oauth/authorize",
            token_url: "https://auth.openai.com/oauth/token",
            client_id: "app_EMoamEEZ73f0CkXaXp7hrann",
            scopes: &["openid", "email", "profile", "offline_access"],
            redirect_uri: "http://localhost:1455/auth/callback",
            use_pkce: true,
        }),
        "chatgpt_web" => Some(ProviderOAuthTemplate {
            provider_type: "chatgpt_web",
            display_name: "ChatGPT Web",
            authorize_url: "https://auth.openai.com/oauth/authorize",
            token_url: "https://auth.openai.com/oauth/token",
            client_id: "app_EMoamEEZ73f0CkXaXp7hrann",
            scopes: &["openid", "email", "profile", "offline_access"],
            redirect_uri: "http://localhost:1455/auth/callback",
            use_pkce: true,
        }),
        "gemini_cli" => Some(ProviderOAuthTemplate {
            provider_type: "gemini_cli",
            display_name: "GeminiCli",
            authorize_url: "https://accounts.google.com/o/oauth2/v2/auth",
            token_url: "https://oauth2.googleapis.com/token",
            client_id: "681255809395-oo8ft2oprdrnp9e3aqf6av3hmdib135j.apps.googleusercontent.com",
            scopes: &[
                "https://www.googleapis.com/auth/cloud-platform",
                "https://www.googleapis.com/auth/userinfo.email",
                "https://www.googleapis.com/auth/userinfo.profile",
            ],
            redirect_uri: "http://localhost:8085/oauth2callback",
            use_pkce: false,
        }),
        "antigravity" => Some(ProviderOAuthTemplate {
            provider_type: "antigravity",
            display_name: "Antigravity",
            authorize_url: "https://accounts.google.com/o/oauth2/v2/auth",
            token_url: "https://oauth2.googleapis.com/token",
            client_id: "1071006060591-tmhssin2h21lcre235vtolojh4g403ep.apps.googleusercontent.com",
            scopes: &[
                "https://www.googleapis.com/auth/cloud-platform",
                "https://www.googleapis.com/auth/userinfo.email",
                "https://www.googleapis.com/auth/userinfo.profile",
                "https://www.googleapis.com/auth/cclog",
                "https://www.googleapis.com/auth/experimentsandconfigs",
            ],
            redirect_uri: "http://localhost:51121/oauth2callback",
            use_pkce: true,
        }),
        "windsurf" => Some(ProviderOAuthTemplate {
            provider_type: "windsurf",
            display_name: "Windsurf",
            authorize_url: "https://windsurf.com/windsurf/signin",
            token_url: "https://register.windsurf.com/exa.seat_management_pb.SeatManagementService/RegisterUser",
            client_id: "3GUryQ7ldAeKEuD2obYnppsnmj58eP5u",
            scopes: &[],
            redirect_uri: "show-auth-token",
            use_pkce: false,
        }),
        "xai" => Some(ProviderOAuthTemplate {
            provider_type: "xai",
            display_name: "xAI",
            authorize_url: aether_oauth::provider::providers::XAI_DEVICE_CODE_URL,
            token_url: aether_oauth::provider::providers::XAI_TOKEN_URL,
            client_id: aether_oauth::provider::providers::XAI_CLIENT_ID,
            scopes: aether_oauth::provider::providers::XAI_OAUTH_SCOPES,
            redirect_uri: "",
            use_pkce: false,
        }),
        _ => None,
    }
}

pub const ADMIN_PROVIDER_OAUTH_TEMPLATE_TYPES: &[&str] = &[
    "claude_code",
    "codex",
    "chatgpt_web",
    "gemini_cli",
    "antigravity",
    "windsurf",
];

#[cfg(test)]
mod tests {
    use super::{
        fixed_provider_endpoint_template_by_api_format, fixed_provider_key_inherits_api_formats,
        fixed_provider_template, provider_runtime_policy, provider_type_admin_oauth_template,
        provider_type_allows_auth_channel_mismatch_by_default, provider_type_is_fixed,
        provider_type_oauth_is_bearer_like, provider_type_supports_local_embedding_transport,
        provider_type_supports_local_same_format_transport, provider_type_supports_model_fetch,
        FixedProviderEndpointConfigValue, ADMIN_PROVIDER_OAUTH_TEMPLATE_TYPES,
        OPENCODE_CHAT_CUSTOM_PATH, OPENCODE_ORIGINAL_BASE_URL, OPENCODE_ORIGINAL_DOMAIN,
    };

    /// OpenCode 的「free-form」指 `provider_type_is_fixed` 为 false —— 即 OAuth、密钥继承
    /// 与格式继承仍按 opencode 的规则走，base_url 仍可由「前置代理池」面板改写。
    ///
    /// 它**不**意味着没有端点模板：模板只负责在创建时给出官方域名的起点端点，之后用户
    /// 改 CDN 域名会被记为 override 而不被 reconcile 冲掉。两者是不同维度。
    #[test]
    fn opencode_is_free_form_and_supports_model_fetch() {
        assert!(!provider_type_is_fixed("opencode"));
        assert!(provider_type_supports_model_fetch("opencode"));
        assert!(provider_runtime_policy("opencode").supports_local_same_format_transport);

        let template = fixed_provider_template("opencode").expect("opencode 应有起点端点模板");
        assert_eq!(template.base_url, OPENCODE_ORIGINAL_BASE_URL);
        assert_eq!(template.endpoints.len(), 1);
        assert_eq!(template.endpoints[0].api_format, "openai:chat");
        assert_eq!(
            template.endpoints[0].custom_path,
            Some(OPENCODE_CHAT_CUSTOM_PATH)
        );
        // 关键：模板不得把 opencode 变成 fixed provider，否则 OAuth 与密钥继承行为会变。
        assert!(!template.runtime_policy.fixed_provider);
    }

    #[test]
    fn amd_fixed_provider_uses_the_single_official_endpoint() {
        let template = fixed_provider_template("amd").expect("amd template should exist");

        // 前端 `AMD_DEFAULT_BASE_URL` 与本常量必须一致，且负载/配额两个面板都靠 base_url
        // 里的 `/radeon/api/v1` 标记做字符串推导。
        assert_eq!(
            template.base_url,
            "https://developer.amd.com.cn/radeon/api/v1"
        );
        assert_eq!(template.endpoints.len(), 1);
        assert_eq!(template.endpoints[0].api_format, "openai:chat");
    }

    /// 凡是前端会锁死 `base_url` 的类型，都必须有模板——否则用户既拿不到自动创建的
    /// 端点，又看不到「添加端点」表单（该表单对 fixed provider 是隐藏的），两头落空。
    ///
    /// 这正是 `amd` 漏注册模板时的症状：新建供应商后端点管理一片空白。
    /// `opencode` 是刻意的例外，它要自由选择官方域名或 CDN 域名。
    #[test]
    fn every_base_url_locked_type_has_a_fixed_template() {
        for provider_type in ["amd", "claude_code", "codex", "xai", "kiro", "windsurf"] {
            let template = fixed_provider_template(provider_type)
                .unwrap_or_else(|| panic!("{provider_type} 会锁死 base_url，却没有模板"));
            assert!(
                !template.endpoints.is_empty(),
                "{provider_type} 模板没有端点"
            );
        }
    }

    /// 模板的 base_url 必须是**可直接使用的完整 URL**。
    ///
    /// `build_admin_fixed_provider_endpoint_defaults` 会把它交给
    /// `normalize_admin_base_url`，裸域名（如 `opencode.ai`）过不了那一关，创建供应商时
    /// reconcile 报错、接口返回 500。之前的测试只断言 `base_url == 某个常量`——恒成立，
    /// 抓不到这类错误，所以这里断言它能被当成 URL 解析并带协议头。
    #[test]
    fn fixed_provider_template_base_urls_are_absolute_urls() {
        for provider_type in ["opencode", "amd", "codex", "claude_code", "kiro"] {
            let template = fixed_provider_template(provider_type)
                .unwrap_or_else(|| panic!("{provider_type} 应有模板"));
            let base_url = template.base_url;
            assert!(
                base_url.starts_with("https://") || base_url.starts_with("http://"),
                "{provider_type} 的模板 base_url 不是完整 URL（缺协议头？）：{base_url}"
            );
            assert!(
                !base_url.contains(' '),
                "{provider_type} 的模板 base_url 含空格：{base_url}"
            );
        }
    }

    /// opencode 注册了起点端点模板，但**不得**因此变成 fixed provider。
    ///
    /// 模板与 `fixed_provider` 是两个维度：模板只管端点创建与 reconcile，`fixed_provider`
    /// 管 OAuth、密钥继承与格式继承。opencode 要能自由切换官方域名与 CDN 域名，所以
    /// `fixed_provider` 必须保持 false——否则 OAuth 密钥会被当成 managed fixed key 处理。
    #[test]
    fn opencode_template_does_not_make_it_a_fixed_provider() {
        let template = fixed_provider_template("opencode").expect("opencode 应有起点端点模板");
        assert!(
            !template.runtime_policy.fixed_provider,
            "opencode 加了模板，但 fixed_provider 必须保持 false"
        );
        assert!(!provider_type_is_fixed("opencode"));
    }

    #[test]
    fn claude_code_fixed_provider_uses_messages_api_root_and_conversion_default() {
        let template =
            fixed_provider_template("claude_code").expect("claude code template should exist");

        assert_eq!(template.base_url, "https://api.anthropic.com/v1");
        assert_eq!(template.version, 2);
        assert!(template.runtime_policy.enable_format_conversion_by_default);
        assert!(!template.runtime_policy.supports_local_same_format_transport);
        assert!(!provider_type_supports_local_same_format_transport(
            "claude_code"
        ));
    }

    #[test]
    fn codex_fixed_provider_template_includes_codex_companion_endpoints() {
        let template = fixed_provider_template("codex").expect("codex template should exist");
        assert_eq!(template.base_url, "https://chatgpt.com/backend-api/codex");
        assert_eq!(template.version, 2);
        assert_eq!(
            template
                .endpoints
                .iter()
                .map(|item| item.api_format)
                .collect::<Vec<_>>(),
            vec![
                "openai:responses",
                "openai:responses:compact",
                "openai:search",
                "openai:image",
                "codex:live"
            ]
        );

        let image_template =
            fixed_provider_endpoint_template_by_api_format("codex", "openai:image")
                .expect("codex image endpoint should exist");
        assert!(image_template.config_defaults.is_empty());

        let search_template =
            fixed_provider_endpoint_template_by_api_format("codex", "openai:search")
                .expect("codex search endpoint should exist");
        assert!(search_template.config_defaults.is_empty());

        let live_template = fixed_provider_endpoint_template_by_api_format("codex", "codex:live")
            .expect("codex Live endpoint should exist");
        assert_eq!(live_template.item_key, "codex:live");
        assert_eq!(live_template.custom_path, None);
        assert!(live_template.config_defaults.is_empty());
    }

    #[test]
    fn chatgpt_web_fixed_provider_template_only_exposes_openai_image() {
        let template =
            fixed_provider_template("chatgpt_web").expect("chatgpt_web template should exist");
        assert_eq!(template.base_url, "https://chatgpt.com");
        assert_eq!(template.version, 1);
        assert_eq!(
            template
                .endpoints
                .iter()
                .map(|item| item.api_format)
                .collect::<Vec<_>>(),
            vec!["openai:image"]
        );

        let image_template =
            fixed_provider_endpoint_template_by_api_format("chatgpt_web", "openai:image")
                .expect("chatgpt_web image endpoint should exist");
        assert_eq!(
            image_template
                .config_defaults
                .iter()
                .map(|item| (item.key, item.value))
                .collect::<Vec<_>>(),
            vec![(
                "upstream_stream_policy",
                FixedProviderEndpointConfigValue::String("force_stream")
            )]
        );
    }

    #[test]
    fn grok_fixed_provider_template_exposes_chat_responses_messages_and_image() {
        let template = fixed_provider_template("grok").expect("grok template should exist");
        assert_eq!(template.base_url, "https://grok.com");
        assert_eq!(template.version, 1);
        assert_eq!(
            template
                .endpoints
                .iter()
                .map(|item| item.api_format)
                .collect::<Vec<_>>(),
            vec![
                "openai:chat",
                "openai:responses",
                "claude:messages",
                "openai:image"
            ]
        );
        assert!(!template.runtime_policy.supports_model_fetch);
        assert!(!template.runtime_policy.supports_local_openai_chat_transport);
        assert!(!template.runtime_policy.supports_local_same_format_transport);
    }

    #[test]
    fn gemini_cli_fixed_provider_template_uses_v1internal_endpoint_path() {
        let template =
            fixed_provider_template("gemini_cli").expect("gemini_cli template should exist");
        assert_eq!(template.base_url, "https://cloudcode-pa.googleapis.com");
        assert_eq!(template.version, 3);

        let endpoint =
            fixed_provider_endpoint_template_by_api_format("gemini_cli", "gemini:generate_content")
                .expect("gemini_cli generateContent endpoint should exist");
        assert_eq!(endpoint.custom_path, Some("/v1internal:{action}"));
        assert_eq!(
            endpoint
                .config_defaults
                .iter()
                .map(|item| (item.key, item.value))
                .collect::<Vec<_>>(),
            vec![(
                "upstream_stream_policy",
                FixedProviderEndpointConfigValue::String("auto")
            )]
        );
    }

    #[test]
    fn antigravity_fixed_provider_template_uses_daily_cloudcode_endpoint() {
        let template =
            fixed_provider_template("antigravity").expect("antigravity template should exist");
        assert_eq!(
            template.base_url,
            "https://daily-cloudcode-pa.googleapis.com"
        );
        assert_eq!(template.version, 2);

        let endpoint = fixed_provider_endpoint_template_by_api_format(
            "antigravity",
            "gemini:generate_content",
        )
        .expect("antigravity generateContent endpoint should exist");
        assert_eq!(endpoint.custom_path, None);
    }

    #[test]
    fn windsurf_fixed_provider_template_exposes_openai_chat() {
        let template = fixed_provider_template("windsurf").expect("windsurf template should exist");
        assert_eq!(template.provider_type, "windsurf");
        assert_eq!(template.base_url, "https://server.codeium.com");
        assert_eq!(template.version, 1);
        assert_eq!(
            template
                .endpoints
                .iter()
                .map(|item| item.api_format)
                .collect::<Vec<_>>(),
            vec!["openai:chat"]
        );
        assert!(
            fixed_provider_endpoint_template_by_api_format("windsurf", "openai:chat").is_some()
        );

        let policy = provider_runtime_policy("windsurf");
        assert!(policy.fixed_provider);
        assert!(policy.enable_format_conversion_by_default);
        assert!(policy.oauth_is_bearer_like);
        assert!(!policy.supports_model_fetch);
        assert!(!policy.supports_local_same_format_transport);
    }

    #[test]
    fn windsurf_admin_oauth_template_is_advertised() {
        let template =
            provider_type_admin_oauth_template("windsurf").expect("windsurf oauth template");

        assert_eq!(template.provider_type, "windsurf");
        assert_eq!(template.display_name, "Windsurf");
        assert_eq!(
            template.authorize_url,
            "https://windsurf.com/windsurf/signin"
        );
        assert_eq!(template.redirect_uri, "show-auth-token");
        assert!(ADMIN_PROVIDER_OAUTH_TEMPLATE_TYPES.contains(&"windsurf"));
    }

    #[test]
    fn xai_fixed_provider_template_exposes_responses_media_endpoints() {
        let template = fixed_provider_template("xai").expect("xai template should exist");
        assert_eq!(template.provider_type, "xai");
        assert_eq!(template.base_url, crate::xai::XAI_CHAT_PROXY_BASE_URL);
        assert_eq!(template.version, 2);
        assert_eq!(
            template
                .endpoints
                .iter()
                .map(|item| item.api_format)
                .collect::<Vec<_>>(),
            vec![
                "openai:responses",
                "openai:responses:compact",
                "openai:image",
                "openai:video"
            ]
        );

        let policy = provider_runtime_policy("xai");
        assert!(policy.fixed_provider);
        assert!(policy.enable_format_conversion_by_default);
        assert!(policy.oauth_is_bearer_like);
        assert!(!policy.supports_model_fetch);
        assert!(policy.supports_local_same_format_transport);
        assert!(!policy.supports_local_openai_chat_transport);
        assert!(fixed_provider_key_inherits_api_formats(
            "xai", "oauth", None
        ));
        assert!(fixed_provider_key_inherits_api_formats(
            "xai", "bearer", None
        ));

        let template = provider_type_admin_oauth_template("xai").expect("xai oauth template");
        assert_eq!(template.provider_type, "xai");
        assert_eq!(template.display_name, "xAI");
        assert_eq!(
            template.token_url,
            aether_oauth::provider::providers::XAI_TOKEN_URL
        );
        assert!(!ADMIN_PROVIDER_OAUTH_TEMPLATE_TYPES.contains(&"xai"));
    }

    #[test]
    fn fixed_provider_key_inheritance_keeps_oauth_and_kiro_configured_bearer_keys_open() {
        assert!(fixed_provider_key_inherits_api_formats(
            "codex", "oauth", None
        ));
        assert!(fixed_provider_key_inherits_api_formats(
            "chatgpt_web",
            "oauth",
            None
        ));
        assert!(fixed_provider_key_inherits_api_formats(
            "kiro",
            "bearer",
            Some("{}")
        ));
        assert!(fixed_provider_key_inherits_api_formats(
            "vertex_ai",
            "service_account",
            None
        ));
        assert!(!fixed_provider_key_inherits_api_formats(
            "kiro", "bearer", None
        ));
        assert!(!fixed_provider_key_inherits_api_formats(
            "custom", "oauth", None
        ));
    }

    #[test]
    fn kiro_allows_auth_channel_mismatch_by_default() {
        let policy = provider_runtime_policy("kiro");
        assert!(policy.fixed_provider);
        assert!(policy.enable_format_conversion_by_default);
        assert!(policy.oauth_is_bearer_like);
        assert!(policy.supports_model_fetch);
        assert!(!policy.supports_local_openai_chat_transport);
        assert!(!policy.supports_local_same_format_transport);
        assert!(policy.key_inherits_api_formats("oauth", None));
        assert!(policy.key_inherits_api_formats("bearer", Some("{}")));
        assert!(!policy.key_inherits_api_formats("bearer", None));

        assert!(provider_type_allows_auth_channel_mismatch_by_default(
            "kiro"
        ));
        assert!(provider_type_allows_auth_channel_mismatch_by_default(
            " KIRO "
        ));
        assert!(!provider_type_allows_auth_channel_mismatch_by_default(
            "claude_code"
        ));
        assert!(!provider_type_allows_auth_channel_mismatch_by_default(
            "custom"
        ));
    }

    #[test]
    fn runtime_policy_preserves_other_fixed_provider_behavior() {
        let codex = provider_runtime_policy("codex");
        assert!(codex.fixed_provider);
        assert!(codex.enable_format_conversion_by_default);
        assert!(!codex.oauth_is_bearer_like);
        assert!(!codex.supports_model_fetch);
        assert!(!codex.supports_local_openai_chat_transport);
        assert!(codex.supports_local_same_format_transport);

        let gemini_cli = provider_runtime_policy("gemini_cli");
        assert!(gemini_cli.fixed_provider);
        assert!(!gemini_cli.enable_format_conversion_by_default);
        assert!(provider_type_oauth_is_bearer_like("gemini_cli"));
        assert!(gemini_cli.supports_model_fetch);
        assert!(!gemini_cli.supports_local_openai_chat_transport);
        assert!(gemini_cli.supports_local_same_format_transport);
    }

    #[test]
    fn chatgpt_web_does_not_use_generic_same_format_transport() {
        assert!(!provider_type_supports_local_same_format_transport(
            "chatgpt_web"
        ));
    }

    #[test]
    fn provider_type_supports_only_matching_embedding_formats() {
        for (provider_type, api_format) in [
            ("openai", "openai:embedding"),
            ("custom", "openai:embedding"),
            ("gemini", "gemini:embedding"),
            ("google", "gemini:embedding"),
            ("vertex_ai", "gemini:embedding"),
            ("jina", "jina:embedding"),
            ("doubao", "doubao:embedding"),
            ("volcengine", "doubao:embedding"),
            ("aliyun", "aliyun:multimodal_embedding"),
            ("dashscope", "aliyun:multimodal_embedding"),
        ] {
            assert!(
                provider_type_supports_local_embedding_transport(provider_type, api_format),
                "{provider_type} should support {api_format}"
            );
        }

        for (provider_type, api_format) in [
            ("openai", "gemini:embedding"),
            ("gemini", "openai:embedding"),
            ("vertex_ai", "openai:embedding"),
            ("jina", "doubao:embedding"),
            ("doubao", "jina:embedding"),
            ("aliyun", "openai:embedding"),
            ("openai", "aliyun:multimodal_embedding"),
            ("claude_code", "openai:embedding"),
            ("openai", "openai:chat"),
        ] {
            assert!(
                !provider_type_supports_local_embedding_transport(provider_type, api_format),
                "{provider_type} should not support {api_format}"
            );
        }

        assert!(provider_type_supports_local_embedding_transport(
            " Google ",
            "GEMINI:EMBEDDING"
        ));
    }

    #[test]
    fn vertex_fixed_provider_template_exposes_only_implemented_gemini_endpoints() {
        let template =
            fixed_provider_template("vertex_ai").expect("vertex_ai template should exist");

        assert_eq!(template.version, 2);
        assert_eq!(
            template
                .endpoints
                .iter()
                .map(|item| item.api_format)
                .collect::<Vec<_>>(),
            vec!["gemini:generate_content", "gemini:embedding"]
        );

        assert!(
            fixed_provider_endpoint_template_by_api_format("vertex_ai", "gemini:embedding")
                .is_some()
        );
        assert!(
            fixed_provider_endpoint_template_by_api_format("vertex_ai", "claude:messages")
                .is_none()
        );
    }
}
