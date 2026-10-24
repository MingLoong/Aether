/**
 * WorkBuddy 双上游（CodeBuddy 国内 / WorkBuddy 国际）的「域」解析 —— 前端唯一入口。
 *
 * 两个区域在 provider 表里是**两个独立实例**：`provider_type` 都是 workbuddy，
 * 靠 `config.workbuddy.realm` 区分（summary 以 `workbuddy_realm` 窄字段下发）。
 *
 * 为什么必须有一个统一的解析器：加账号时弹窗要把区域**锁死**（后端设备授权只看
 * 请求里的 `login_option`，见 `oauth/dispatch/device/authorize.rs`，拿国内域去登国际号
 * 只会换来跨域 401）。而 realm 的取数有三条不同步的来源：provider 详情、summary 旁路、
 * 号池概览（只有 `provider_name`，没有 realm）。各页面各写一份「取不到就 null」的结果
 * 就是「首帧还能选区域」——所以这里统一成**永不返回「不知道就放行」**：
 * 声明值 → 名字线索 → 默认 cn，并用 `source` 说明这个域是哪来的，UI 据此提示。
 */
import { providerDisplayName } from './providerDisplayName'

export type WorkbuddyRealm = 'cn' | 'global'

/** 品牌名：国内 `codebuddy.cn` → CodeBuddy，国际 `workbuddy.ai` → WorkBuddy。 */
export const WORKBUDDY_BRAND: Record<WorkbuddyRealm, string> = {
  cn: 'CodeBuddy',
  global: 'WorkBuddy',
}

/** 区域后缀（调用方过 `legacyT`）：拼在品牌名后面就是「CodeBuddy 国内版 (CN)」。 */
export const WORKBUDDY_REGION_LABEL: Record<WorkbuddyRealm, string> = {
  cn: '国内版 (CN)',
  global: '国际版 (Global)',
}

export interface WorkbuddyRealmInput {
  provider_type?: string | null
  workbuddy_realm?: string | null
  name?: string | null
  /** 详情接口会带 config，summary 不带：两条都要认。 */
  config?: Record<string, unknown> | null
}

/** 域的来源：号池自己声明的 / 从号池名推出来的 / 兜底默认 CN。 */
export type WorkbuddyRealmSource = 'config' | 'name' | 'default'

export interface WorkbuddyRealmResolution {
  realm: WorkbuddyRealm
  source: WorkbuddyRealmSource
}

export function isWorkbuddyProviderType(providerType?: string | null): boolean {
  return (providerType ?? '').trim().toLowerCase() === 'workbuddy'
}

function asRealm(value: unknown): WorkbuddyRealm | null {
  if (typeof value !== 'string') return null
  const normalized = value.trim().toLowerCase()
  return normalized === 'cn' || normalized === 'global' ? normalized : null
}

/** 声明值优先 `workbuddy_realm`（后端窄字段），退一步读 `config.workbuddy.realm`。 */
function declaredRealmOf(source: WorkbuddyRealmInput): WorkbuddyRealm | null {
  const fromField = asRealm(source.workbuddy_realm)
  if (fromField) return fromField
  const bucket = source.config?.['workbuddy']
  if (bucket && typeof bucket === 'object') {
    return asRealm((bucket as Record<string, unknown>)['realm'])
  }
  return null
}

/**
 * 从号池名里读区域线索（用户改过名 / realm 缺失时的兜底）。
 *
 * 先认明确的区域词，再认品牌词：`workbuddy-cn` 这种预设名同时带品牌与区域，
 * 区域词优先才不会把它判成国际版。品牌词的含义沿用仓库既有口径
 * （`providerDisplayName`）：WorkBuddy = 国际，CodeBuddy = 国内。
 */
export function guessWorkbuddyRealmFromName(name?: string | null): WorkbuddyRealm | null {
  const raw = (name ?? '').trim()
  if (!raw) return null
  const lower = raw.toLowerCase()
  if (lower.includes('国际') || /\b(global|intl|international)\b/.test(lower)) return 'global'
  if (lower.includes('国内') || /\b(cn|china)\b/.test(lower)) return 'cn'
  if (lower.includes('workbuddy')) return 'global'
  if (lower.includes('codebuddy')) return 'cn'
  return null
}

/**
 * 解析某个 provider 实例的域。多个候选按顺序找「第一份能用的证据」，
 * 因此页面可以把手上的所有来源（详情 / summary / 概览）一起丢进来，
 * 谁先到就用谁 —— 不依赖某个请求的时序。
 *
 * 返回 `null` 只有一种情况：所有候选都不是 workbuddy 实例（非本功能范围）。
 */
export function resolveWorkbuddyRealm(
  ...sources: Array<WorkbuddyRealmInput | null | undefined>
): WorkbuddyRealmResolution | null {
  const candidates = sources.filter((item): item is WorkbuddyRealmInput => Boolean(item))
  if (!candidates.some(item => isWorkbuddyProviderType(item.provider_type))) return null
  for (const candidate of candidates) {
    const declared = declaredRealmOf(candidate)
    if (declared) return { realm: declared, source: 'config' }
  }
  for (const candidate of candidates) {
    const guessed = guessWorkbuddyRealmFromName(candidate.name)
    if (guessed) return { realm: guessed, source: 'name' }
  }
  return { realm: 'cn', source: 'default' }
}

/**
 * 上游展示名：预设名 → 纯品牌名；用户自己起过名字 → 「名字 · 品牌」，两者都不丢。
 * 只有 workbuddy 实例才有品牌；其余类型原样返回名字。
 *
 * 域是**默认兜底**推出来的（号池既没声明、名字也无线索）时不报品牌：报一家错的品牌
 * 比不报更坏 —— 会让人以为加的是那一家。
 */
export function upstreamBrandLabel(
  provider: WorkbuddyRealmInput | null | undefined,
  fallbackName = '',
): string {
  const name = (provider?.name ?? '').trim() || fallbackName.trim()
  const resolution = resolveWorkbuddyRealm(provider)
  if (!resolution || resolution.source === 'default') return name
  const brand = WORKBUDDY_BRAND[resolution.realm]
  const displayName = providerDisplayName({
    name,
    provider_type: 'workbuddy',
    workbuddy_realm: resolution.realm,
  })
  return displayName === brand ? brand : `${displayName} · ${brand}`
}
