/**
 * Provider 类型判断工具函数。
 *
 * 区分"密钥型"和"OAuth 账号型"两类 Provider，影响前端显示标签和操作入口。
 */

const oauthAccountProviderTypes = new Set([
  'claude_code',
  'codex',
  'chatgpt_web',
  'gemini_cli',
  'antigravity',
  'kiro',
  'grok',
  'xai',
  'windsurf',
])

export const isOAuthAccountProviderType = (providerType?: string | null): boolean =>
  oauthAccountProviderTypes.has((providerType || '').toLowerCase())

export const isKeyManagedProviderType = (providerType?: string | null): boolean =>
  !isOAuthAccountProviderType(providerType)

/**
 * OpenCode 走「前置代理池」面板：Endpoint 的 base_url 可以填官方域名或
 * 前置 CDN 域名，池内每个出口 IP 独立承载一份每日配额。
 */
export const isOpenCodeProviderType = (providerType?: string | null): boolean =>
  (providerType || '').trim().toLowerCase() === 'opencode'

/**
 * OpenCode 官方直连域名（与后端 `OPENCODE_ORIGINAL_DOMAIN` 保持一致）。
 *
 * 新建 opencode 供应商时用它补一个默认端点：后端的 fixed provider 模板会把模板之外的
 * 端点删掉，而 opencode 要能在官方域名与前置 CDN 域名之间自由切换，所以只能在创建时
 * 补一个起点，用户随后可改。
 */
export const OPENCODE_ORIGINAL_DOMAIN = 'opencode.ai'

/**
 * AMD（Radeon）走「模型负载 + 账号配额」面板。
 *
 * 与 OpenCode 同为一等供应商类型：类型本身就是识别依据，不再依赖 provider config 里
 * 有没有 `amd_load` 段——那样判断的话，新建供应商时还没有 config，界面就看不出这个
 * 供应商该配什么。
 *
 * 兼容旧的 custom 类型 AMD：这类 provider 建于本类型加入之前，config 里带着
 * `amd_load` 段且 base_url 指向 `/radeon/api/v1`。判据用 base_url 而不是类型，
 * 因为 custom 是通用类型，不能只凭它就把所有自定义上游都当成 AMD。
 */
export const isAmdProviderType = (
  providerType?: string | null,
  baseUrl?: string | null,
): boolean => {
  if ((providerType || '').trim().toLowerCase() === 'amd') return true
  const url = (baseUrl || '').trim().toLowerCase()
  return url.includes('/radeon/api/')
}

/** AMD 上游的默认端点。选 AMD 类型时预填，省得用户去查地址。 */
export const AMD_DEFAULT_BASE_URL = 'https://developer.amd.com.cn/radeon/api/v1'
export const AMD_DEFAULT_API_FORMAT = 'openai:chat'

/**
 * 只按 `provider_type` 判断 AMD —— 与后端 `amd_rotation::is_amd_provider_type` 同一判据。
 *
 * 与 `isAmdProviderType()` 的区别：那个带 base_url 兼容分支，服务于「旧 custom + radeon
 * 也要能看负载面板」；而熔断、号池这类**行为**判据在后端只认类型，前端必须与之同判据，
 * 否则界面会与后端行为脱节（典型：给旧 custom 供应商藏掉其实仍然生效的熔断设置）。
 */
export const isAmdTypedProvider = (providerType?: string | null): boolean =>
  (providerType || '').trim().toLowerCase() === 'amd'

/**
 * 密钥是否处于「可恢复」状态：熔断打开，或健康度低于 0.5。
 *
 * AMD 恒为 false —— 后端对 AMD 的密钥既不记健康也不开熔断
 * （`orchestration/effects.rs` 的 `local_execution_plan_tracks_circuit_breaker()` 对 AMD 返回 false），
 * 所以 AMD 密钥身上这两个字段只可能来自管理侧动作、是陈旧值：实测线上有一把
 * `last_used_at` 为空（从未被使用）的 AMD key 健康度 0.4，因此长出一个点了也没有任何效果的
 * 「恢复健康」按钮。
 *
 * 判据用 `isAmdTypedProvider()`：这是**行为**判据，后端只认 `provider_type`。
 *
 * `health_score` 为 `null`/`undefined` 时按「未知」处理，不算可恢复 —— 修复了原先
 * `score !== undefined` 会把 `null` 当成 0 分（`null < 0.5` 为真）而误判的情况。
 */
export const isKeyHealthRecoverable = (
  providerType: string | null | undefined,
  key: { health_score?: number | null; circuit_breaker_open?: boolean | null },
): boolean => {
  if (isAmdTypedProvider(providerType)) return false
  const score = key.health_score
  return Boolean(key.circuit_breaker_open || (score != null && score < 0.5))
}
