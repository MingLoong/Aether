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
