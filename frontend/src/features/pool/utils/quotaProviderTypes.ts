/**
 * 号池页「额度」相关能力的两份供应商名单 —— 收在一处 ✓。
 *
 * 为什么要有这个文件 ✓：名单原本在 `PoolManagement.vue` 里手写了两遍 ✗，
 * 2026-10-17 接入 `workbuddy` 时两处都漏了 ✗ —— 额度视图和进度条明明做好了 ✓，
 * 因为「配额」整列没对该供应商开放 ✗，界面上什么也看不到 ✗。
 * 这类「白名单副本没跟上」的坑，靠人肉检查是拦不住的 ✗，所以把副本收成一个常量 ✓，
 * 由 `__tests__/quotaProviderTypes.spec.ts` 钉住内容 ✓：漏了就是测试红 ✓。
 *
 * 真相在后端 ✓：`ProviderPoolService::supports_quota_refresh(<provider_type>)`
 * 才是「这个供应商能不能刷新额度」的权威答案 ✓（有 Rust 单测钉着 ✓）。
 * 前端这份只是渲染决策，新增供应商时必须同步 ✓。
 */

/**
 * 号池页要显示「配额」整列的供应商 ✓。
 * 判据是「有上游额度可看」✓ —— 不满足就别显示空列 ✗。
 */
export const ACCOUNT_QUOTA_PROVIDER_TYPES = [
  'codex',
  'claude_code',
  'gemini_cli',
  'kiro',
  'windsurf',
  'antigravity',
  'grok',
  'chatgpt_web',
  'xai',
  'workbuddy',
] as const

/**
 * 号池页要给「刷新额度」按钮的供应商 ✓。
 * 必须与后端 `supports_quota_refresh` 一致 ✓ —— 前端说支持、后端不认，按钮点了就是错 ✗。
 */
export const QUOTA_REFRESH_PROVIDER_TYPES = [
  'codex',
  'claude_code',
  'gemini_cli',
  'kiro',
  'windsurf',
  'antigravity',
  'grok',
  'chatgpt_web',
  'xai',
  'workbuddy',
] as const

const ACCOUNT_QUOTA_SET = new Set<string>(ACCOUNT_QUOTA_PROVIDER_TYPES)
const QUOTA_REFRESH_SET = new Set<string>(QUOTA_REFRESH_PROVIDER_TYPES)

/**
 * provider_type 在各处的写法并不统一（后端小写 ✓、URL 参数可能大写 ✗），
 * 这里统一规范化 ✓，免得再来一次「大小写不一致 → 名单不命中」✗。
 */
function normalize(providerType: string | null | undefined): string {
  return typeof providerType === 'string' ? providerType.trim().toLowerCase() : ''
}

/** 该供应商要不要显示「配额」整列 ✓（含移动端卡片 ✓）。 */
export function showsAccountQuotaColumn(providerType: string | null | undefined): boolean {
  const key = normalize(providerType)
  return key !== '' && ACCOUNT_QUOTA_SET.has(key)
}

/** 该供应商要不要显示「刷新额度」按钮 ✓。 */
export function supportsQuotaRefresh(providerType: string | null | undefined): boolean {
  const key = normalize(providerType)
  return key !== '' && QUOTA_REFRESH_SET.has(key)
}
