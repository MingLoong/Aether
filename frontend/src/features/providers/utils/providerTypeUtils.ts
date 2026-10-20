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
  'workbuddy',
])

export const isOAuthAccountProviderType = (providerType?: string | null): boolean =>
  oauthAccountProviderTypes.has((providerType || '').toLowerCase())

export const isKeyManagedProviderType = (providerType?: string | null): boolean =>
  !isOAuthAccountProviderType(providerType)

/** Cline：唯一一个**两种模式共存**的类型（加密钥 = Key 模式，加账号 = 账号模式）。 */
export const isClineProviderType = (providerType?: string | null): boolean =>
  (providerType || '').trim().toLowerCase() === 'cline'

/**
 * 是否要给它显示「添加账号（OAuth）」入口。
 *
 * 普通 OAuth 类型走的是账号模式，Cline 额外多一个入口（它的密钥模式入口不能被挤掉），
 * 所以这里不能直接用 `isOAuthAccountProviderType`。
 */
export const supportsOAuthAccountImportProviderType = (providerType?: string | null): boolean =>
  isOAuthAccountProviderType(providerType) || isClineProviderType(providerType)

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

/** AMD 上游的默认端点。选 AMD 类型时预填，省得用户去查地址。 */
export const AMD_DEFAULT_BASE_URL = 'https://developer.amd.com.cn/radeon/api/v1'
export const AMD_DEFAULT_API_FORMAT = 'openai:chat'

/**
 * 判断是不是 AMD —— **只认 `provider_type == 'amd'`**，与后端
 * `amd_rotation::is_amd_provider_type()` 同一判据。
 *
 * 为什么删掉了「类型或 base_url 含 `/radeon/api/`」的兼容分支：AMD 已成为一等供应商
 * 类型，类型本身就是识别依据；而熔断、号池、密钥健康这些**行为**在后端只认类型，
 * 前端若带上 base_url 兼容分支，就会出现「界面按 AMD 渲染、后端按普通供应商走号池与
 * 熔断」的脱节（典型：给一个其实仍然生效的熔断设置藏掉入口）。线上已无
 * `provider_type != 'amd'` 却带 radeon 端点的供应商，该分支已无对象。
 *
 * 端点推导（`/radeon/api/v1` → `/radeon/api/tokenfactory/load`）仍按 URL 路径标记做
 * 字符串手术——那是地址运算，不是身份判断，不受本判据影响。
 */
export const isAmdTypedProvider = (providerType?: string | null): boolean =>
  (providerType || '').trim().toLowerCase() === 'amd'

/**
 * 不按单把 key 记健康/开熔断的供应商类型：`amd` 与 `cline`。
 *
 * 与后端 `amd_rotation::provider_type_exempt_from_key_health` 同判据。两者成立的理由
 * 不同但结论一样：AMD 的失败按账号轮换处理；Cline 官方上游的 401/403/402 是订阅与额度问题
 * （免费凭据打 `cline-pass/*` 得到 403 `ENTITLEMENT_ERROR`），错记到单把 key 上只会把可用
 * 凭据逐个熔断掉、并在界面上长出点了也没用的「恢复健康」按钮。
 */
const noKeyHealthProviderTypes = new Set(['amd', 'cline'])

const hasNoKeyHealth = (providerType?: string | null): boolean =>
  noKeyHealthProviderTypes.has((providerType || '').trim().toLowerCase())

/**
 * 不接**通用号池**的供应商类型：目前只有 `amd`。
 *
 * cline 已恢复号池（走自己独立的调度逻辑），所以这里不再包含 cline；与后端
 * `amd_rotation::provider_type_exempt_from_generic_pool` 同判据。
 */
const noPoolProviderTypes = new Set(['amd'])

/** 是否不接号池：号池开关入口、切换类型时的强制关闭、提交时的剥离都用它。 */
export const isNoPoolProviderType = (providerType?: string | null): boolean =>
  noPoolProviderTypes.has((providerType || '').trim().toLowerCase())

/** 是否不记密钥健康/熔断：用于隐藏「恢复健康」这类无效入口。 */
export const isKeyHealthTrackingDisabledProviderType = (
  providerType?: string | null,
): boolean => hasNoKeyHealth(providerType)

/**
 * 密钥是否处于「可恢复」状态：熔断打开，或健康度低于 0.5。
 *
 * AMD 与 Cline 恒为 false —— 后端对它们的密钥既不记健康也不开熔断
 * （`orchestration/effects.rs` 的 `local_execution_plan_tracks_circuit_breaker()` 对这两类返回 false），
 * 所以它们密钥身上这两个字段只可能来自管理侧动作、是陈旧值：实测线上有一把
 * `last_used_at` 为空（从未被使用）的 AMD key 健康度 0.4，因此长出一个点了也没有任何效果的
 * 「恢复健康」按钮。
 *
 * 判据用类型（`isKeyHealthTrackingDisabledProviderType`）：这是**行为**判据，后端只认 `provider_type`。
 *
 * `health_score` 为 `null`/`undefined` 时按「未知」处理，不算可恢复 —— 修复了原先
 * `score !== undefined` 会把 `null` 当成 0 分（`null < 0.5` 为真）而误判的情况。
 */
export const isKeyHealthRecoverable = (
  providerType: string | null | undefined,
  key: { health_score?: number | null; circuit_breaker_open?: boolean | null },
): boolean => {
  if (isKeyHealthTrackingDisabledProviderType(providerType)) return false
  const score = key.health_score
  return Boolean(key.circuit_breaker_open || (score != null && score < 0.5))
}
