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
