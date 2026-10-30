import type { ProviderKeyStatusSnapshot, QuotaResetCreditsSnapshot } from './statusSnapshot'

/**
 * 代理配置类型
 * 支持两种模式：
 * - 手动配置：设置 url/username/password
 * - 代理节点：设置 node_id（与 url 互斥）
 */
export interface ProxyConfig {
  url?: string
  username?: string
  password?: string
  node_id?: string    // 代理节点 ID（aether-tunnel 注册的节点，与 url 互斥）
  enabled?: boolean   // 是否启用代理（false 时保留配置但不使用）
  has_credentials?: boolean // 管理端脱敏响应：代理包含未返回的认证信息
}

export interface OAuthOrganizationInfo {
  id?: string | null
  title?: string | null
  is_default?: boolean | null
  role?: string | null
}

/**
 * 请求头规则类型
 * - set: 设置/覆盖请求头
 * - drop: 删除请求头
 * - rename: 重命名请求头（保留原值）
 */
export interface HeaderRuleSet {
  action: 'set'
  key: string
  value: string
  has_value?: boolean // value="***" 时表示保留服务端已有值
}

export interface HeaderRuleDrop {
  action: 'drop'
  key: string
}

export interface HeaderRuleRename {
  action: 'rename'
  from: string
  to: string
}

/**
 * 请求体规则类型
 * - set: 设置/覆盖字段
 * - drop: 删除字段
 * - rename: 重命名字段（保留原值）
 */
/**
 * 请求体规则 - 覆写字段
 *
 * - path 支持嵌套路径，如 "metadata.user.name"
 * - 使用 "\." 转义字面量点号，如 "config\.v1.enabled"
 */
export interface BodyRuleSet {
  action: 'set'
  path: string
  value: unknown
  has_value?: boolean // value="***" 时表示保留服务端已有值
}

/**
 * 请求体规则 - 删除字段
 *
 * - path 支持嵌套路径，如 "metadata.internal_flag"
 * - 使用 "\." 转义字面量点号，如 "config\.v1.enabled"
 */
export interface BodyRuleDrop {
  action: 'drop'
  path: string
}

/**
 * 请求体规则 - 重命名/移动字段
 *
 * - from/to 支持嵌套路径，如 "extra.old_config" -> "settings.new_config"
 * - 使用 "\." 转义字面量点号，如 "config\.v1.enabled"
 */
export interface BodyRuleRename {
  action: 'rename'
  from: string
  to: string
}

/**
 * 请求体规则 - 向数组追加元素
 *
 * - path 指向目标数组，如 "messages"
 * - value 为要追加的元素
 */
export interface BodyRuleAppend {
  action: 'append'
  path: string
  value: unknown
  has_value?: boolean
}

/**
 * 请求体规则 - 在数组指定位置插入元素
 *
 * - path 指向目标数组，如 "messages"
 * - index 为插入位置（支持负数）
 * - value 为要插入的元素
 */
export interface BodyRuleInsert {
  action: 'insert'
  path: string
  index: number
  value: unknown
  has_value?: boolean
}

/**
 * 请求体规则 - 正则替换字符串值
 *
 * - path 指向目标字符串字段，如 "messages[0].content"
 * - pattern 为正则表达式
 * - replacement 为替换字符串
 * - flags 可选，支持 i(忽略大小写)/m(多行)/s(dotall)
 * - count 替换次数，0=全部替换（默认）
 */
export interface BodyRuleRegexReplace {
  action: 'regex_replace'
  path: string
  pattern: string
  replacement: string
  has_pattern?: boolean
  has_replacement?: boolean
  flags?: string
  count?: number
}

export type BodyRuleConditionOp =
  | 'eq' | 'neq'
  | 'gt' | 'lt' | 'gte' | 'lte'
  | 'starts_with' | 'ends_with' | 'contains' | 'matches'
  | 'exists' | 'not_exists'
  | 'in' | 'type_is'

export interface BodyRuleConditionLeaf {
  path: string
  op: BodyRuleConditionOp
  value?: unknown  // exists / not_exists 不需要 value
  has_value?: boolean // value="***" 时表示保留服务端已有条件值
  source?: 'body' | 'current' | 'original' | 'request_headers' | 'headers'
}

export interface BodyRuleConditionAll {
  all: BodyRuleCondition[]
}

export interface BodyRuleConditionAny {
  any: BodyRuleCondition[]
}

export type BodyRuleCondition =
  | BodyRuleConditionLeaf
  | BodyRuleConditionAll
  | BodyRuleConditionAny

export type HeaderRule = (HeaderRuleSet | HeaderRuleDrop | HeaderRuleRename) & {
  condition?: BodyRuleCondition
  enabled?: boolean
}

export type BodyRule = (BodyRuleSet | BodyRuleDrop | BodyRuleRename | BodyRuleAppend | BodyRuleInsert | BodyRuleRegexReplace) & {
  condition?: BodyRuleCondition
  enabled?: boolean
}

/**
 * 格式接受策略配置
 * 用于控制端点是否接受来自不同 API 格式的请求，并自动进行格式转换
 */
export interface FormatAcceptanceConfig {
  enabled: boolean                // 是否启用格式转换
  accept_formats?: string[]       // 白名单：接受哪些格式的请求
  reject_formats?: string[]       // 黑名单：拒绝哪些格式（优先级高于白名单）
}

export interface ChatPiiRedactionProviderConfig {
  enabled: boolean
}

export interface CodexProviderConfig {
  fingerprint_convergence_enabled?: boolean
  [key: string]: unknown
}

export interface ResponsesWebSocketProviderConfig {
  enabled: boolean
}

export interface ProviderConfig {
  chat_pii_redaction?: ChatPiiRedactionProviderConfig
  codex?: CodexProviderConfig
  responses_websocket?: ResponsesWebSocketProviderConfig
  pool_advanced?: PoolAdvancedConfig
  failover_rules?: FailoverRulesConfig
  claude_code_advanced?: ClaudeCodeAdvancedConfig
  [key: string]: unknown
}

export interface ProviderEndpoint {
  id: string
  provider_id: string
  provider_name: string
  api_format: string
  base_url: string
  custom_path?: string  // 自定义请求路径（可选，为空则使用 API 格式默认路径）
  // 请求头配置
  header_rules?: HeaderRule[]  // 请求头规则列表，支持 set/drop/rename 操作
  // 请求体配置
  body_rules?: BodyRule[]  // 请求体规则列表，支持 set/drop/rename 操作
  max_retries: number
  is_active: boolean
  config?: Record<string, unknown>
  proxy?: ProxyConfig | null
  // 格式转换配置
  format_acceptance_config?: FormatAcceptanceConfig | null
  total_keys: number
  active_keys: number
  created_at: string
  updated_at: string
}

/**
 * 模型权限配置类型
 *
 * 使用示例：
 * 1. 不限制（允许所有模型）: null
 * 2. 白名单模式: ["gpt-4", "claude-3-opus"]
 */
export type AllowedModels = string[] | null

// AllowedModels 类型守卫函数
export function isAllowedModelsList(value: AllowedModels): value is string[] {
  return Array.isArray(value)
}

export interface EndpointAPIKey {
  id: string
  provider_id: string
  api_formats: string[]  // 支持的 endpoint signature 列表（如 "openai:chat"）
  api_key_masked: string
  api_key_plain?: string | null
  auth_type: 'api_key' | 'service_account' | 'oauth' | 'bearer'  // 认证类型（必返回）
  auth_type_by_format?: Record<string, 'api_key' | 'bearer'> | null
  allow_auth_channel_mismatch_formats?: string[] | null
  credential_kind?: 'raw_secret' | 'oauth_session' | 'service_account' | string | null
  runtime_auth_kind?: 'api_key' | 'bearer' | 'service_account' | 'mixed' | 'unknown' | string | null
  oauth_managed?: boolean
  agent_identity?: boolean
  oauth_header_auth?: boolean
  can_refresh_oauth?: boolean
  can_export_oauth?: boolean
  can_edit_oauth?: boolean
  name: string  // 密钥名称（必填，用于识别）
  rate_multipliers?: Record<string, number> | null  // 按 endpoint signature 的成本倍率
  internal_priority: number  // Key 内部优先级
  global_priority_by_format?: Record<string, number> | null  // 按 endpoint signature 的全局优先级
  rpm_limit?: number | null  // RPM 速率限制 (1-10000)，null 表示自适应模式
  concurrent_limit?: number | null  // 并发请求上限，null/0 表示不限制
  allowed_models?: AllowedModels  // 允许使用的模型列表（null=不限制）
  capabilities?: Record<string, boolean> | null  // 能力标签配置（如 cache_1h, context_1m）
  // 缓存与熔断配置
  cache_ttl_minutes: number  // 缓存 TTL（分钟），0=禁用
  max_probe_interval_minutes: number  // 熔断探测间隔（分钟）
  // 按 endpoint signature 的健康度数据
  health_by_format?: Record<string, FormatHealthData>
  circuit_breaker_by_format?: Record<string, FormatCircuitBreakerData>
  // 聚合字段（从 health_by_format 计算，用于列表显示）
  health_score: number
  circuit_breaker_open?: boolean
  consecutive_failures: number
  last_failure_at?: string
  request_count: number
  success_count: number
  error_count: number
  success_rate: number
  avg_response_time_ms: number
  is_active: boolean
  note?: string  // 备注说明（可选）
  last_used_at?: string
  created_at: string
  updated_at: string
  // 自适应 RPM 字段
  is_adaptive?: boolean  // 是否为自适应模式（rpm_limit=NULL）
  effective_limit?: number | null  // 当前有效 RPM 限制（自适应使用学习值，固定使用配置值，未学习时为 null）
  learned_rpm_limit?: number | null  // 学习到的 RPM 限制
  // 滑动窗口利用率采样
  utilization_samples?: Array<{ ts: number; util: number }>  // 利用率采样窗口
  last_probe_increase_at?: string  // 上次探测性扩容时间
  concurrent_429_count?: number
  rpm_429_count?: number
  last_429_at?: string
  last_429_type?: string
  // 单格式场景的熔断器字段
  circuit_breaker_open_at?: string
  next_probe_at?: string
  half_open_until?: string
  half_open_successes?: number
  half_open_failures?: number
  request_results_window?: Array<{ ts: number; ok: boolean }>  // 请求结果滑动窗口
  // 自动获取模型
  auto_fetch_models?: boolean  // 是否启用自动获取模型
  last_models_fetch_at?: string  // 最后获取模型时间
  last_models_fetch_error?: string  // 最后获取模型错误信息
  locked_models?: string[]  // 被锁定的模型列表
  // 模型过滤规则（仅当 auto_fetch_models=true 时生效）
  model_include_patterns?: string[]  // 模型包含规则（支持 * 和 ? 通配符）
  model_exclude_patterns?: string[]  // 模型排除规则（支持 * 和 ? 通配符）
  // OAuth 相关
  oauth_expires_at?: number | null  // OAuth Token 过期时间（Unix 时间戳）
  oauth_email?: string | null  // OAuth 授权的邮箱
  oauth_plan_type?: string | null  // Codex 订阅类型: plus/free/team/enterprise
  oauth_account_id?: string | null  // Codex ChatGPT 账号 ID
  oauth_account_user_id?: string | null  // Codex ChatGPT account-user 联合 ID
  oauth_account_name?: string | null
  oauth_organizations?: OAuthOrganizationInfo[] | null  // OAuth 关联组织/工作区摘要
  oauth_temporary?: boolean | null  // 是否为仅 Access Token 导入的临时 OAuth 账号
  oauth_invalid_at?: number | null  // 兼容字段；优先使用 status_snapshot.oauth
  oauth_invalid_reason?: string | null  // 兼容字段；优先使用 status_snapshot.oauth
  status_snapshot?: ProviderKeyStatusSnapshot | null
  // 上游元数据（由上游响应采集，如 Codex 额度信息 / Antigravity 配额信息）
  upstream_metadata?: UpstreamMetadata | null
  // Key 级别代理配置（覆盖 Provider 级别代理）
  proxy?: ProxyConfig | null
}

// Codex 上游元数据类型
export interface CodexUpstreamMetadata {
  credential_generation?: string
  updated_at?: number  // 更新时间（Unix 时间戳）
  plan_type?: string  // 套餐类型
  primary_used_percent?: number  // 周限额窗口使用百分比
  primary_reset_seconds?: number  // 周限额重置剩余秒数
  primary_reset_after_seconds?: number  // 周限额重置剩余秒数（兼容字段）
  primary_reset_at?: number  // 周限额重置时间（Unix 时间戳）
  primary_window_minutes?: number  // 周限额窗口大小（分钟）
  secondary_used_percent?: number  // 5H限额窗口使用百分比
  secondary_reset_seconds?: number  // 5H限额重置剩余秒数
  secondary_reset_after_seconds?: number  // 5H限额重置剩余秒数（兼容字段）
  secondary_reset_at?: number  // 5H限额重置时间（Unix 时间戳）
  secondary_window_minutes?: number  // 5H限额窗口大小（分钟）
  spark_primary_used_percent?: number  // Spark 5H限额窗口使用百分比
  spark_primary_reset_seconds?: number  // Spark 5H限额重置剩余秒数
  spark_primary_reset_after_seconds?: number  // Spark 5H限额重置剩余秒数（兼容字段）
  spark_primary_reset_at?: number  // Spark 5H限额重置时间（Unix 时间戳）
  spark_primary_window_minutes?: number  // Spark 5H限额窗口大小（分钟）
  spark_secondary_used_percent?: number  // Spark 周限额窗口使用百分比
  spark_secondary_reset_seconds?: number  // Spark 周限额重置剩余秒数
  spark_secondary_reset_after_seconds?: number  // Spark 周限额重置剩余秒数（兼容字段）
  spark_secondary_reset_at?: number  // Spark 周限额重置时间（Unix 时间戳）
  spark_secondary_window_minutes?: number  // Spark 周限额窗口大小（分钟）
  has_credits?: boolean  // 是否有积分
  credits_balance?: number  // 积分余额
  reset_credits?: QuotaResetCreditsSnapshot | null  // Codex earned rate-limit reset credits
  account_quota_reset_reservation?: {
    idempotency_key?: string | null
    generation?: number | null
  } | null
}

export interface AntigravityModelQuota {
  remaining_fraction?: number | string | null  // 剩余比例 (0.0-1.0)
  used_percent?: number | string | null  // 已用百分比 (0.0-100.0)
  remaining?: number | string | null
  total?: number | string | null
  reset_time?: string | null  // RFC3339
  reset_at?: number | string | null
  display_name?: string | null
  model_id?: string | null
  token_type?: string | null
  is_exhausted?: boolean | null
}

export interface AntigravityUpstreamMetadata {
  updated_at?: number  // Unix 时间戳（秒）
  quota_by_model?: Record<string, AntigravityModelQuota>
  is_forbidden?: boolean  // 账户是否被禁止访问
  forbidden_reason?: string  // 禁止访问原因
  forbidden_at?: number  // 禁止时间（Unix 时间戳，秒）
}

// Kiro 上游配额信息
export interface KiroUpstreamMetadata {
  subscription_title?: string  // 订阅类型 (如 "KIRO PRO+")
  current_usage?: number  // 当前使用量
  usage_limit?: number  // 使用限额
  remaining?: number  // 剩余额度
  usage_percentage?: number  // 使用百分比 (0-100)
  next_reset_at?: number  // 下次重置时间（Unix 时间戳，毫秒）
  email?: string  // 用户邮箱
  updated_at?: number  // Unix 时间戳（秒）
  is_banned?: boolean  // 账户是否被封禁
  ban_reason?: string  // 封禁原因
  banned_at?: number  // 封禁时间（Unix 时间戳，秒）
}

// Windsurf 上游配额信息
export interface WindsurfUpstreamMetadata {
  updated_at?: number
  plan_name?: string
  daily_remaining_percent?: number | null
  weekly_remaining_percent?: number | null
  daily_reset_at?: number | null
  weekly_reset_at?: number | null
  prompt_used?: number | null
  prompt_limit?: number | null
  prompt_remaining?: number | null
  flex_used?: number | null
  flex_limit?: number | null
  flex_remaining?: number | null
  allowed_models_count?: number | null
  models?: Array<{
    model_uid?: string | null
    label?: string | null
    provider?: string | null
    supports_images?: boolean | null
    credit_multiplier?: number | null
  }> | null
  rate_limit?: Record<string, unknown> | null
  last_error?: string | null
}

// WorkBuddy（腾讯 CodeBuddy）上游配额 + 每日维护摘要。
// 数据由额度刷新流程写入（余额来自 /v2/billing/meter/get-user-resource，
// maintenance 来自每日签到/连登/成长任务/猫猫/trial 的执行结果）。
export interface WorkbuddyPackage {
  name?: string | null
  size?: number | null
  remaining?: number | null
  expires_at?: number | null  // Unix 时间戳（秒）
}

export interface WorkbuddyTaskDetail {
  task_code?: string | null
  title?: string | null
  description?: string | null
  task_desc?: string | null
  credit?: number | null
  energy?: number | null
  has_reward?: boolean | null
  reward_buddy?: boolean | null     // 奖励与 Buddy 相关（UI 显示「+5 能 Buddy」）
  jump_url?: string | null
  task_type?: string | null      // single = 一次性任务
  tag?: string | null            // 端标记（PC / 小程序限定等）
  current?: number | null
  target?: number | null
  locked?: boolean | null
  claimable?: boolean | null
  claimed?: boolean | null
  accept_status?: string | null
  status?: string | null
}

export interface WorkbuddyMaintenance {
  ran_at?: number | null       // 本次维护执行时间（Unix 秒）
  checkin?: string | null      // checked_in | already_checked_in | enterprise_skipped | failed…
  activity_reported?: boolean | null
  streak_bonus?: Record<string, unknown> | null
  travel?: Record<string, unknown> | null
  tasks?: Record<string, unknown> | null
  trial?: Record<string, unknown> | null
  tasks_detail?: WorkbuddyTaskDetail[] | null
}

export interface WorkbuddyUpstreamMetadata {
  updated_at?: number  // Unix 时间戳（秒）
  /** 目录/锁定的域：'cn' | 'global'。一个账号的快照只属于一个域；旧快照无此键。 */
  realm?: string | null
  /**
   * 账号资料（面板 issue #94「改名后免重登」）：手动刷新额度时同步上游昵称。
   * 失败时记 `nickname_error`（不再静默吞掉 ✗，便于排查国际号为什么没有昵称）。
   */
  account?: {
    nickname?: string | null
    nickname_refreshed_at?: number | null
    nickname_error?: string | null
    nickname_attempted_at?: number | null
  } | null
  credits_limit?: number | null
  credits_remaining?: number | null
  credits_used?: number | null
  unlimited?: boolean | null
  expires_at?: number | null
  packages?: WorkbuddyPackage[] | null
  allowed_models_count?: number | null
  models?: Array<{
    model_uid?: string | null
    label?: string | null
    vendor?: string | null
    credits?: string | null
    is_default?: boolean | null
    /** 目录全字段（与面板 dynModelEntry→ModelInfo 同一套映射；旧快照无 = 未拉到新字段） */
    description?: string | null
    context_window?: number | null   // maxInputTokens
    max_tokens?: number | null       // maxOutputTokens
    max_allowed_size?: number | null
    supports_images?: boolean | null
    supports_reasoning?: boolean | null
    supports_tool_call?: boolean | null
    only_reasoning?: boolean | null
    can_disable_thinking?: boolean | null
    efforts?: string[] | null        // reasoning.supportedEfforts
    default_effort?: string | null   // reasoning.defaultEffort（老模型键回落 effort）
    tags?: string[] | null
    /**
     * 限时优惠（`/v3/config` 的 `data.modelPromotions`，面板 `applyModelPromotions`）：
     * `credits` 是**牌价**（转正后基准倍率），以下 `promo_*` 才是**当前生效价**。
     * 缺 `promo_factor` 时代表该类优惠没有机器可读折扣（如「错峰使用」），只透出徽章/说明。
     */
    promo_factor?: number | null     // discount.factor（0 = 限时免费）
    promo_credits?: string | null    // discount.discountedCredits（生效价原文，如 "0.40"）
    promo_label?: string | null      // badge.label（限时免费 / 夜间折扣 / 错峰使用）
    promo_note?: string | null       // hover.textZh（时段或日期说明）
    /** 官方客户端 modelTiers[].modelIds 的套餐分组（Pro Only 等） */
    model_tier?: {
      id?: string | null
      access_mode?: string | null
      tier?: string | null
      badge?: { label?: string | null; labelEn?: string | null; color?: string | null } | null
      hover?: { textZh?: string | null; textEn?: string | null; action?: Record<string, unknown> | null } | null
    } | null
    plan_restricted?: boolean | null
  }> | null
  maintenance?: WorkbuddyMaintenance | null
  /** 「账号×模型」锁定台账（11102 退避 / 6004 限流；面板 modelCooldowns 的等价物）。 */
  model_blocked?: Record<
    string,
    {
      until_unix_secs?: number | null
      reset_at_unix_secs?: number | null
      observed_at_unix_secs?: number | null
      hits?: number | null
      kind?: string | null        // model_unavailable（11102）| plan_blocked（11158）| rate_limit（6004）
      audit_only?: boolean | null // true = 只展示，不影响路由
      reason?: string | null
    }
  > | null
  last_error?: string | null
}

export interface ChatGPTWebUpstreamMetadata {
  updated_at?: number  // Unix 时间戳（秒）
  plan_type?: string | null
  default_model_slug?: string | null
  blocked_features?: string[] | null
  image_quota_feature_name?: string | null
  image_quota_remaining?: number | null
  image_quota_total?: number | null
  image_quota_used?: number | null
  image_quota_reset_at?: number | null
  image_quota_reset_after?: string | null
  image_quota_blocked?: boolean | null
  limits_progress?: Array<Record<string, unknown>> | null
  email?: string | null
  account_id?: string | null
  account_user_id?: string | null
  user_id?: string | null
}

export interface GrokUpstreamMetadata {
  updated_at?: number  // Unix 时间戳（秒）
  plan_type?: string | null
  pool_tier?: string | null
  is_banned?: boolean | null
  ban_reason?: string | null
  last_rate_limit_probe_at?: number | null
  clearance_state?: string | null
  email?: string | null
  account_id?: string | null
  account_user_id?: string | null
}

export interface XaiUpstreamMetadata {
  updated_at?: number
  subscription_title?: string
  usage_percentage?: number
  remaining_percentage?: number
  usage_label?: string
  usage_limit?: number
  current_usage?: number
  remaining?: number
  next_reset_at?: number
  prepaid_balance?: number
  on_demand_cap?: number
  on_demand_used?: number
  on_demand_remaining?: number
  period_type?: string
}

export interface GeminiCliTierMetadata {
  id?: string | null
  tierType?: string | null
  name?: string | null
  displayName?: string | null
  availableCredits?: number | string | null
  remainingCredits?: number | string | null
  consumedCredits?: number | string | null
  totalCredits?: number | string | null
  unlimited?: boolean | null
  hasCredits?: boolean | null
}

export interface GeminiCliCreditsMetadata {
  remaining?: number | string | null
  remainingCredits?: number | string | null
  available?: number | string | null
  availableCredits?: number | string | null
  balance?: number | string | null
  consumed?: number | string | null
  consumedCredits?: number | string | null
  total?: number | string | null
  totalCredits?: number | string | null
  has_credits?: boolean | null
  unlimited?: boolean | null
  trace_id?: string | null
  traceId?: string | null
  updated_at?: number | string | null
}

export interface GeminiCliModelQuota {
  remaining_fraction?: number | string | null
  used_percent?: number | string | null
  remaining?: number | string | null
  total?: number | string | null
  reset_at?: number | string | null
  display_name?: string | null
  is_exhausted?: boolean | null
}

export interface GeminiCliUpstreamMetadata {
  updated_at?: number | string | null
  plan_type?: string | null
  project_id?: string | null
  paidTier?: GeminiCliTierMetadata | string | null
  currentTier?: GeminiCliTierMetadata | string | null
  credits?: GeminiCliCreditsMetadata | null
  quota_by_model?: Record<string, GeminiCliModelQuota> | null
}

export interface ClaudeCodeUpstreamMetadata {
  updated_at?: number
  five_hour_used_percent?: number
  five_hour_reset_at?: number
  seven_day_used_percent?: number
  seven_day_reset_at?: number
  seven_day_sonnet_used_percent?: number
  seven_day_sonnet_reset_at?: number
  seven_day_fable_used_percent?: number
  seven_day_fable_reset_at?: number
  reset_credits?: QuotaResetCreditsSnapshot
}

export interface UpstreamMetadata {
  codex?: CodexUpstreamMetadata
  claude_code?: ClaudeCodeUpstreamMetadata
  antigravity?: AntigravityUpstreamMetadata
  kiro?: KiroUpstreamMetadata
  windsurf?: WindsurfUpstreamMetadata
  chatgpt_web?: ChatGPTWebUpstreamMetadata
  grok?: GrokUpstreamMetadata
  gemini_cli?: GeminiCliUpstreamMetadata
  xai?: XaiUpstreamMetadata
  workbuddy?: WorkbuddyUpstreamMetadata
}

// 按格式的健康度数据
export interface FormatHealthData {
  health_score: number
  error_rate: number
  window_size: number
  consecutive_failures: number
  last_failure_at?: string | null
  circuit_breaker: FormatCircuitBreakerData
}

// 按格式的熔断器数据
export interface FormatCircuitBreakerData {
  open: boolean
  reason?: string | null
  open_at?: string | null
  next_probe_at?: string | null
  next_probe_at_unix_secs?: number | null
  probe_interval_minutes?: number | null
  max_probe_interval_minutes?: number | null
  failure_count?: number | null
  consecutive_failures?: number | null
  last_failure_at?: string | null
  last_probe_failure_at?: string | null
  half_open_until?: string | null
  half_open_successes: number
  half_open_failures: number
  request_results_window?: Array<{ ts: number; ok: boolean }>
}

export interface EndpointAPIKeyUpdate {
  api_formats?: string[]  // 支持的 API 格式列表
  name?: string
  api_key?: string  // 仅在需要更新时提供
  auth_type?: 'api_key' | 'service_account' | 'oauth' | 'bearer'  // 认证类型
  auth_type_by_format?: Record<string, 'api_key' | 'bearer'> | null
  allow_auth_channel_mismatch_formats?: string[] | null
  auth_config?: Record<string, unknown>  // 认证配置（Vertex AI Service Account JSON）
  rate_multipliers?: Record<string, number> | null  // 按 API 格式的成本倍率
  internal_priority?: number
  global_priority_by_format?: Record<string, number> | null  // 按 API 格式的全局优先级
  rpm_limit?: number | null  // RPM 速率限制 (1-10000)，null 表示切换为自适应模式
  concurrent_limit?: number | null  // 并发请求上限，null/0 表示不限制
  allowed_models?: AllowedModels
  capabilities?: Record<string, boolean> | null
  cache_ttl_minutes?: number
  max_probe_interval_minutes?: number
  note?: string
  is_active?: boolean
  auto_fetch_models?: boolean  // 是否启用自动获取模型
  locked_models?: string[]  // 被锁定的模型列表
  // 模型过滤规则（仅当 auto_fetch_models=true 时生效）
  model_include_patterns?: string[]  // 模型包含规则（支持 * 和 ? 通配符）
  model_exclude_patterns?: string[]  // 模型排除规则（支持 * 和 ? 通配符）
  // Key 级别代理配置（覆盖 Provider 级别代理），null=清除
  proxy?: ProxyConfig | null
}

export interface EndpointHealthDetail {
  api_format: string
  health_score: number | null
  is_active: boolean
  total_keys?: number
  active_keys?: number
}

export interface EndpointHealthEvent {
  timestamp: string
  status: 'success' | 'failed' | 'skipped' | 'started'
  status_code?: number | null
  latency_ms?: number | null
  error_type?: string | null
  error_message?: string | null
}

export interface HealthTimelineDetail {
  segment_index?: number
  status?: string
  time_range_start?: string | null
  time_range_end?: string | null
  total_attempts?: number | null
  success_count?: number | null
  failed_count?: number | null
  success_rate?: number | null
  avg_latency_ms?: number | null
  avg_first_byte_ms?: number | null
  avg_tps?: number | null
}

export interface EndpointStatusMonitor {
  api_format: string
  total_attempts: number
  success_count: number
  failed_count: number
  skipped_count: number
  success_rate: number
  avg_latency_ms?: number | null
  avg_first_byte_ms?: number | null
  avg_tps?: number | null
  provider_count: number
  key_count: number
  last_event_at?: string | null
  events: EndpointHealthEvent[]
  timeline?: string[]
  timeline_details?: HealthTimelineDetail[]
  time_range_start?: string | null
  time_range_end?: string | null
}

export interface EndpointStatusMonitorResponse {
  generated_at: string
  formats: EndpointStatusMonitor[]
}

// 公开版事件（不含敏感信息如 provider_id, key_id）
export interface PublicHealthEvent {
  timestamp: string
  status: string
  status_code?: number | null
  latency_ms?: number | null
  error_type?: string | null
}

// 公开版端点状态监控类型（返回 events，前端复用 EndpointHealthTimeline 组件）
export interface PublicEndpointStatusMonitor {
  api_format: string
  api_path: string  // 本站入口路径
  total_attempts: number
  success_count: number
  failed_count: number
  skipped_count: number
  success_rate: number
  avg_latency_ms?: number | null
  avg_first_byte_ms?: number | null
  avg_tps?: number | null
  last_event_at?: string | null
  events: PublicHealthEvent[]
  timeline?: string[]
  timeline_details?: HealthTimelineDetail[]
  time_range_start?: string | null
  time_range_end?: string | null
}

export interface PublicEndpointStatusMonitorResponse {
  generated_at: string
  formats: PublicEndpointStatusMonitor[]
}

export interface ModelHealthEvent {
  timestamp: string
  status: 'success' | 'failed'
  status_code?: number | null
  latency_ms?: number | null
  first_byte_time_ms?: number | null
  error_type?: string | null
}

export interface ModelStatusMonitor {
  model: string
  display_name?: string | null
  total_attempts: number
  success_count: number
  failed_count: number
  success_rate: number
  avg_latency_ms?: number | null
  avg_first_byte_ms?: number | null
  avg_tps?: number | null
  provider_count?: number
  last_event_at?: string | null
  events: ModelHealthEvent[]
  timeline?: string[]
  timeline_details?: HealthTimelineDetail[]
  time_range_start?: string | null
  time_range_end?: string | null
}

export interface ModelStatusMonitorResponse {
  generated_at: string
  models: ModelStatusMonitor[]
}

export interface ProviderStatusMonitor {
  provider_id: string
  provider_name: string
  provider_type?: string | null
  is_active: boolean
  total_attempts: number
  success_count: number
  failed_count: number
  success_rate: number
  avg_latency_ms?: number | null
  avg_first_byte_ms?: number | null
  avg_tps?: number | null
  model_count: number
  last_event_at?: string | null
  timeline?: string[]
  timeline_details?: HealthTimelineDetail[]
  time_range_start?: string | null
  time_range_end?: string | null
  models: ModelStatusMonitor[]
}

export interface ProviderStatusMonitorResponse {
  generated_at: string
  providers: ProviderStatusMonitor[]
}

export type HealthMonitorRelatedDimension = 'endpoint' | 'model' | 'provider'

export interface HealthRelatedMonitor {
  kind: HealthMonitorRelatedDimension
  key: string
  display_name: string
  meta_text?: string | null
  total_attempts: number
  success_count: number
  failed_count: number
  success_rate: number
  avg_latency_ms?: number | null
  avg_first_byte_ms?: number | null
  avg_tps?: number | null
  last_event_at?: string | null
  timeline?: string[]
  timeline_details?: HealthTimelineDetail[]
  time_range_start?: string | null
  time_range_end?: string | null
}

export interface HealthRelatedMonitorResponse {
  generated_at: string
  dimension: HealthMonitorRelatedDimension
  value: string
  related_endpoints: HealthRelatedMonitor[]
  related_models: HealthRelatedMonitor[]
  related_providers: HealthRelatedMonitor[]
}

/**
 * 供应商类型。
 *
 * `amd` 是「上游厂商 + 自带面板」，而不是单纯的协议形态。
 * AMD 的识别**只认这个类型**（`isAmdTypedProvider`），与后端 `is_amd_provider_type` 同判据；
 * 早期那种「`custom` + base_url 指向 radeon」的兼容判据已删除（线上已无这类供应商）。
 *
 * `cline` 同样只认类型：上游固定为 api.cline.bot，指纹头由后端下发。它的两种用法
 * （贴 key / OAuth 登录）**共用这一种类型**，区别只在添加的凭据形状，所以前端不给它
 * 单独的模式开关——加什么凭据就是什么模式。
 *
 * `workbuddy`（腾讯 CodeBuddy）同理：上游是厂商私有入口，账号走 OAuth 设备授权。
 *
 * `relay`（面板显示「自定义透传」）：纯透传。一次请求只打一次上游（忽略 `max_retries`
 * 与路由策略的「错误重试次数」），429 / 5xx 不换候选、把上游响应原样回给客户端；
 * 健康分、号池、探测、模型映射、usage 统计与 `custom` 完全一致。
 */
export type ProviderType = 'custom' | 'claude_code' | 'codex' | 'chatgpt_web' | 'gemini_cli' | 'antigravity' | 'kiro' | 'grok' | 'xai' | 'windsurf' | 'vertex_ai' | 'amd' | 'cline' | 'workbuddy' | 'relay'

export interface ClaudeCodeAdvancedConfig {
  // 会话数量控制：null/undefined 表示不限制
  max_sessions?: number | null
  session_idle_timeout_minutes?: number | null
  // 会话 ID 伪装（固定 metadata.user_id 中 session 片段）
  session_id_masking_enabled?: boolean
  // Cache TTL 统一（强制所有 cache_control 使用相同 TTL 类型）
  cache_ttl_override_enabled?: boolean
  cache_ttl_override_target?: string
  // 仅允许 CLI 客户端
  cli_only_enabled?: boolean
}

export interface SchedulingPresetItem {
  preset: string
  enabled: boolean
  mode?: string | null
}

export interface PoolScoreWeights {
  manual_priority?: number | null
  health?: number | null
  probe_freshness?: number | null
  quota_remaining?: number | null
  latency?: number | null
  cost_lru?: number | null
}

export interface PoolScoreRules {
  weights?: PoolScoreWeights | null
  probe_freshness_ttl_seconds?: number | null
  unschedulable_score_cap?: number | null
  probe_failure_penalty?: number | null
  request_failure_penalty?: number | null
  probe_failure_cooldown_threshold?: number | null
}

export interface PoolAdvancedConfig {
  // deprecated: hidden from pool advanced dialog, retained for backward-compatible reads
  global_priority?: number | null
  // 会话粘性 TTL（秒，0=关闭）：调度策略含「粘性」维度时，同一会话在 TTL 内固定路由到
  // 同一账号；账号遇冷却立即重新分配。读取侧每请求解析，改动即时生效（无需重启）。
  sticky_session_ttl_seconds?: number | null
  load_threshold_percent?: number | null
  skip_exhausted_accounts?: boolean | null
  ignore_exhausted_accounts?: boolean | null
  // Codex only: treat remaining quota <= 1% as exhausted (default false).
  reserve_minimum_quota?: boolean
  // cline only: 独立选号策略（round_robin / fill / random / least_used，缺省 round_robin）。
  cline_strategy?: string | null
  // 旧字段（兼容读取）
  lru_enabled?: boolean
  scheduling_mode?: 'lru' | 'multi_score' | null
  // 新格式：对象列表；旧格式：字符串列表
  scheduling_presets?: SchedulingPresetItem[] | string[] | null
  scoring_weights?: {
    lru?: number
    latency?: number
    health?: number
    cost_remaining?: number
  } | null
  latency_window_seconds?: number | null
  latency_sample_limit?: number | null
  // deprecated: hidden from pool advanced dialog, retained for backward-compatible reads
  cost_window_seconds?: number | null
  // deprecated: hidden from pool advanced dialog, retained for backward-compatible reads
  cost_limit_per_key_tokens?: number | null
  // deprecated: hidden from pool advanced dialog, retained for backward-compatible reads
  cost_soft_threshold_percent?: number | null
  rate_limit_cooldown_seconds?: number | null
  /**
   * 429 软限流退避上限（秒，面板 `softRateMax`）：连续 429 且上游未给 Retry-After 时，
   * 基础冷却按 2 的幂放大到此上限；填 <= 基础冷却（或 0）= 关闭退避。
   */
  rate_limit_cooldown_max_seconds?: number | null
  overload_cooldown_seconds?: number | null
  /**
   * 积分保底（面板 `credit_floor`）：余额**严格低于**该值的账号不接收费模型；`0` = 关闭。
   */
  credit_floor?: number | null
  /**
   * 池内账号是否**也计入** key 级熔断（面板口径：池就是全量账号）。
   * Aether 默认 `false`（池内只降健康分）；`true` = 对齐面板。
   */
  pool_counts_toward_circuit_breaker?: boolean | null
  /**
   * 连续失败多少次触发 key 级熔断（面板 `breaker_threshold`，面板默认 3）。
   * Aether 历史默认 **8**（不静默改变既有部署）。
   */
  breaker_threshold?: number | null
  /**
   * 熔断基础探测间隔（分钟，面板 `breaker_cooldown`，面板默认 30）。`0` = 沿用 Aether 历史 1 分钟。
   */
  breaker_cooldown_minutes?: number | null
  /**
   * 熔断指数退避上限（分钟，面板 `breaker_cooldown_max`，面板默认 360 = 6h）。`0` = 沿用历史 32 分钟。
   */
  breaker_cooldown_max_minutes?: number | null
  /**
   * 
   */
  
  /**
   * **单账号最大在途**（并发，面板 `max_in_flight`，面板默认 **3**）—— 所有域的兜底档
   * （global 档优先）；`0` = 不分档（回落账号自身上限）。
   */
  max_in_flight?: number | null
  /**
   * costTier 条件探索窗口（秒，面板 `cost_explore_interval`，面板默认 1800）。`0` = 关停。
   */
  cost_explore_interval_seconds?: number | null
  /**
   * WAF **出口 IP 级**拦截窗口（秒）：窗口内 ≥2 个不同账号命中 WAF 403 → 判定出口 IP 被拦，
   * 激活期内选号层快速失败。**默认 60**（面板同值）；`0` = 关停。
   */
  waf_ip_cooldown_seconds?: number | null
  /**
   * 拦截期是否**连新请求一起挡**：`true`（默认）= Aether 现状，更严一档；
   * `false` = 对齐面板（只停本次请求的轮转，新请求照常走）。
   */
  waf_ip_block_new_requests?: boolean | null
  proactive_refresh_seconds?: number | null
  unschedulable_rules?: Array<Record<string, unknown>> | null
  batch_concurrency?: number | null
  probe_concurrency?: number | null
  score_top_n?: number | null
  score_fallback_scan_limit?: number | null
  score_rules?: PoolScoreRules | null
  probing_enabled?: boolean
  // deprecated: retained only for backward-compatible reads
  probing_target_percent?: number | null
  // deprecated: retained only for backward-compatible reads
  probing_target_count?: number | null
  account_self_check_enabled?: boolean
  account_self_check_interval_minutes?: number | null
  account_self_check_concurrency?: number | null
  auto_remove_banned_keys?: boolean
  auto_remove_quota_exhausted_keys?: boolean
  /**
   * 连败降权三件套：**未分类错误**连败 N 次后临时出池（阈值 0 = 关闭），
   * 重复连败按 2 的幂退避到上限。只作用于「未分类错误」分支，已分类路径行为不变。
   */
  request_demote_threshold?: number | null
  request_demote_seconds?: number | null
  request_demote_max_seconds?: number | null
  /**
   * 快过期积分优先路由（面板 `prefer_expiring`，默认 **true**）：开启且账号存在
   * 「窗口内即将过期」的积分时，给该账号一点**温和加分**（不是硬优先）。
   */
  prefer_expiring?: boolean
  /** 快过期积分窗口（秒，面板 `expiring_soon`，默认 604800 = 7 天；**0 = 关闭分桶**）。 */
  expiring_soon_seconds?: number | null
  /** 快过期加分（0..1 分值域，默认 0.10；**0 = 不加分**）。 */
  expiring_credit_bonus?: number | null
}

function isPlainObject(value: unknown): value is Record<string, unknown> {
  return typeof value === 'object' && value !== null && !Array.isArray(value)
}

export function normalizeChatPiiRedactionProviderConfig(value: unknown): ChatPiiRedactionProviderConfig {
  if (!isPlainObject(value) || typeof value.enabled !== 'boolean') {
    return { enabled: false }
  }
  return { enabled: value.enabled }
}

export function normalizePoolAdvancedConfig(value: unknown): PoolAdvancedConfig | null {
  if (value == null || value === false) return null
  if (value === true) return {}
  if (!isPlainObject(value)) return null
  return { ...value } as PoolAdvancedConfig
}

export interface FailoverRuleItem {
  pattern: string
  description?: string
  status_codes?: number[]
}

export interface FailoverRulesConfig {
  max_retries?: number
  /**
   * 一个请求内该供应商最多尝试几次；达到上限就跳过它其余候选，改试别的供应商。
   * **仅对 `provider_type === 'amd'` 生效**（其它供应商设了无效），未配置时 AMD 默认 1。
   */
  max_attempts_per_provider?: number
  stop_on_transport_errors?: boolean
  stop_status_codes?: number[]
  stop_on_status_codes?: number[]
  early_stop_status_codes?: number[]
  non_retryable_status_codes?: number[]
  continue_on_status_codes?: number[]
  retryable_status_codes?: number[]
  retry_on_status_codes?: number[]
  continue_status_codes?: number[]
  success_failover_patterns?: FailoverRuleItem[]
  error_stop_patterns?: FailoverRuleItem[]
}

export interface ProviderWithEndpointsSummary {
  id: string
  name: string
  provider_type?: ProviderType
  description?: string
  website?: string
  provider_priority: number
  keep_priority_on_conversion: boolean  // 格式转换时是否保持优先级
  enable_format_conversion: boolean  // 是否允许格式转换（提供商级别开关）
  billing_type?: 'monthly_quota' | 'pay_as_you_go' | 'free_tier'
  monthly_quota_usd?: number
  monthly_used_usd?: number
  quota_reset_day?: number
  quota_last_reset_at?: string  // 当前周期开始时间
  quota_expires_at?: string
  // 请求配置（从 Endpoint 迁移）
  max_retries?: number  // 最大重试次数
  max_transfer_count?: number  // 提供商内最大转移次数，0 表示不限制
  max_transfer_timeout_seconds?: number  // 提供商内最大转移时长，0 表示不限制
  proxy?: ProxyConfig | null  // 代理配置
  // 超时配置（秒），为空时使用全局配置
  stream_first_byte_timeout?: number  // 流式请求首字节超时
  request_timeout?: number  // 非流式请求整体超时
  concurrent_limit?: number | null  // 供应商级并发上限，0/空=不限制（账号级优先）
  is_active: boolean
  total_endpoints: number
  active_endpoints: number
  total_keys: number
  active_keys: number
  total_models: number
  active_models: number
  global_model_ids: string[]
  avg_health_score: number | null
  unhealthy_endpoints: number
  api_formats: string[]
  endpoint_health_details: EndpointHealthDetail[]
  claude_code_advanced?: ClaudeCodeAdvancedConfig | null
  chat_pii_redaction?: ChatPiiRedactionProviderConfig | null
  pool_advanced?: PoolAdvancedConfig | null
  /**
   * WorkBuddy 实例级域（`config.workbuddy.realm`，后端 summary 以同名窄字段暴露）。
   *
   * 「国内 / 国际」是两个上游，所以各自成实例；加账号时前端据此锁死「版本」，
   * 后端写侧也以它为准。`null` = 老实例，未声明域（行为保持原样）。
   */
  workbuddy_realm?: 'cn' | 'global' | null
  failover_rules?: FailoverRulesConfig | null
  ops_configured: boolean  // 是否配置了扩展操作（余额监控等）
  /**
   * 是否挂 AMD 负载感知面板。由后端按「配过 amd_load 段」或「有 AMD 上游端点」判定。
   *
   * 不能在前端用 provider_type 判：AMD 注册为通用的 `custom`，而所有自建上游都是
   * custom，那样每个自建供应商都会显示这张面板。
   */
  amd_load?: boolean
  ops_architecture_id?: string  // 扩展操作使用的架构 ID（如 cubence, anyrouter）
  codex_fingerprint_convergence_enabled?: boolean
  kiro_simulated_cache_enabled?: boolean
  responses_websocket_enabled?: boolean
  ops_quota_alert_enabled?: boolean
  created_at: string
  updated_at: string
}

export interface HealthStatus {
  endpoint_id?: string
  endpoint_health_score?: number
  endpoint_consecutive_failures?: number
  endpoint_last_failure_at?: string
  endpoint_is_active?: boolean
  key_id?: string
  key_health_score?: number
  key_consecutive_failures?: number
  key_last_failure_at?: string
  key_is_active?: boolean
  key_statistics?: Record<string, unknown>
}

export interface HealthSummary {
  endpoints: {
    total: number
    active: number
    unhealthy: number
  }
  keys: {
    total: number
    active: number
    unhealthy: number
  }
}

export interface KeyRpmStatus {
  key_id: string
  current_rpm: number
  rpm_limit?: number
}

export interface ProviderModelMapping {
  name: string
  priority: number  // 优先级（数字越小优先级越高）
  api_formats?: string[]  // 作用域（适用的 API 格式），为空表示对所有格式生效
  endpoint_ids?: string[]  // 作用域（适用的端点 ID），为空表示对所有端点生效
  operations?: string[]  // 作用域（适用的请求操作），为空表示对该格式的全部操作生效
}

// 保留别名以保持向后兼容
export type ProviderModelAlias = ProviderModelMapping

export interface AdaptiveStatsResponse {
  adaptive_mode: boolean
  current_limit: number | null
  learned_limit: number | null
  concurrent_429_count: number
  rpm_429_count: number
  last_429_at: string | null
  last_429_type: string | null
  adjustment_count: number
  recent_adjustments: Array<{
    timestamp: string
    old_limit: number
    new_limit: number
    reason: string
    [key: string]: unknown
  }>
}
