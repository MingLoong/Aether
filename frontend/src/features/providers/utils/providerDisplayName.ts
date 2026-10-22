/**
 * 供应商**对外显示名**（只影响展示，不改数据）。
 *
 * WorkBuddy 有两个完全不同的上游，品牌名也不同：
 * - 国内 `codebuddy.cn` → **CodeBuddy**
 * - 国际 `workbuddy.ai` → **WorkBuddy**
 *
 * 底层仍然是 `provider_type=workbuddy` + `config.workbuddy.realm`（软拆分，见
 * docs/operations/workbuddy-provider.md）。这里只把「系统预设名」翻译成品牌名，
 * **用户自己起过的名字永不覆盖** —— 与后端 `workbuddy_key_rename_target` 同精神。
 */
const WORKBUDDY_PRESET_NAMES = new Set(['workbuddy-cn', 'workbuddy-global'])

export function providerDisplayName(provider: {
  name?: string | null
  provider_type?: string | null
  workbuddy_realm?: 'cn' | 'global' | null
}): string {
  const name = (provider.name ?? '').trim()
  const providerType = (provider.provider_type ?? '').trim().toLowerCase()
  if (providerType === 'workbuddy' && WORKBUDDY_PRESET_NAMES.has(name.toLowerCase())) {
    return provider.workbuddy_realm === 'global' ? 'WorkBuddy' : 'CodeBuddy'
  }
  return name
}
