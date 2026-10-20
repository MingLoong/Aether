/**
 * WorkBuddy 账号额度视图（号池管理「配额」列用 ✓）。
 *
 * 数据来自 key 的 `upstream_metadata.workbuddy`（额度刷新写入 ✓，**不是** Aether 自己的配额）：
 * - `credits_limit` / `credits_remaining` / `credits_used`：上游积分口径 ✓
 * - `unlimited: true`：上游标记为不限量 ✓
 * - `expires_at`：额度到期（unix 秒 ✓）
 * - `packages[]`：资源包（`{name, size, remaining, expires_at}` ✓）
 *
 * 之前号池管理**只显示** Aether 侧口径（gemini 特例 ✓），WorkBuddy 账号那一列是空的 ✗ ——
 * 线上实测这些字段其实一直有值（例如 `credits_remaining 2899 / credits_limit 2900` ✓），
 * 纯粹是前端没渲染 ✗。
 */

export interface WorkbuddyPackageView {
  name: string
  size: number | null
  remaining: number | null
  expiresAt: number | null
}

export interface WorkbuddyQuotaView {
  /** `2899 / 2900` 或 `不限量` ✓ */
  creditsText: string
  /** 0–100；未知为 0 ✓ */
  remainingPercent: number
  /** `10-31 到期`；没有到期时间则 `null` ✓ */
  expiresText: string | null
  /** 资源包个数（含已用完的 ✓，与上游列表一致 ✓） */
  packageCount: number
  /** 资源包剩余总量（用于一句话摘要 ✓） */
  packageRemainingTotal: number | null
  packages: WorkbuddyPackageView[]
  /** 配额列那句摘要 ✓ */
  summaryText: string
}

type JsonRecord = Record<string, unknown>

function asRecord(value: unknown): JsonRecord | null {
  return value && typeof value === 'object' && !Array.isArray(value) ? (value as JsonRecord) : null
}

function finiteNumber(value: unknown): number | null {
  const num = typeof value === 'number' ? value : typeof value === 'string' ? Number(value) : NaN
  return Number.isFinite(num) ? num : null
}

/** 上游给的是「最多两位小数」的积分数，显示时去掉多余的 `.0` ✓。 */
export function formatWorkbuddyCredits(value: number | null): string {
  if (value === null) return '-'
  if (Number.isInteger(value)) return String(value)
  return String(Number(value.toFixed(2)))
}

/** 上游额度到期按 **CST（UTC+8）** 展示 ✓ —— 与后端日界口径一致 ✓，也避免宿主机时区影响结果 ✗。 */
function formatExpiry(unixSeconds: number | null): string | null {
  if (unixSeconds === null || unixSeconds <= 0) return null
  const cstMillis = (unixSeconds + 8 * 60 * 60) * 1000
  const date = new Date(cstMillis)
  if (Number.isNaN(date.getTime())) return null
  const month = String(date.getUTCMonth() + 1).padStart(2, '0')
  const day = String(date.getUTCDate()).padStart(2, '0')
  return `${month}-${day} 到期`
}

function normalizePackages(raw: unknown): WorkbuddyPackageView[] {
  if (!Array.isArray(raw)) return []
  return raw.flatMap((entry) => {
    const record = asRecord(entry)
    if (!record) return []
    const name = typeof record.name === 'string' ? record.name.trim() : ''
    return [{
      name: name || '资源包',
      size: finiteNumber(record.size),
      remaining: finiteNumber(record.remaining),
      expiresAt: finiteNumber(record.expires_at),
    }]
  })
}

/**
 * 把 `upstream_metadata`（整个 key 的 ✓）解析成额度视图。
 *
 * 返回 `null` = **没有 WorkBuddy 额度数据** ✓（此时调用方应回落到其它口径 ✓，
 * 不要显示 `0 / 0` 这种误导性内容 ✗）。
 */
export function workbuddyQuotaView(
  upstreamMetadata: JsonRecord | null | undefined,
): WorkbuddyQuotaView | null {
  const bucket = asRecord(asRecord(upstreamMetadata)?.workbuddy)
  if (!bucket) return null

  const unlimited = bucket.unlimited === true
  const limit = finiteNumber(bucket.credits_limit)
  const remaining = finiteNumber(bucket.credits_remaining)
  const accountExpiresAt = finiteNumber(bucket.expires_at)
  const packages = normalizePackages(bucket.packages)
  // 账号到期显示应按“仍有余额的资源包”计算，取最早有效到期时间；
  // 已用完套餐不能把账号错误地显示成 10-31 到期。
  const packageExpiryCandidates = packages
    .filter((item) => (item.remaining ?? 0) > 0 && item.expiresAt !== null && item.expiresAt > 0)
    .map((item) => item.expiresAt as number)
  const expiresAt = packageExpiryCandidates.length > 0
    ? Math.min(...packageExpiryCandidates)
    : accountExpiresAt
  const packageRemainingTotal = packages.length
    ? packages.reduce((sum, item) => sum + (item.remaining ?? 0), 0)
    : null

  // 三者全无 → 判定「没有额度数据」✓（只有 maintenance/models 的账号不该显示额度 ✓）
  if (!unlimited && limit === null && remaining === null && packages.length === 0) {
    return null
  }

  const creditsText = unlimited
    ? '不限量'
    : `${formatWorkbuddyCredits(remaining)} / ${formatWorkbuddyCredits(limit)}`

  let remainingPercent = 0
  if (unlimited) {
    remainingPercent = 100
  } else if (limit !== null && limit > 0 && remaining !== null) {
    remainingPercent = Math.max(0, Math.min(100, (remaining / limit) * 100))
  } else if (packages.length && packageRemainingTotal !== null) {
    const total = packages.reduce((sum, item) => sum + (item.size ?? 0), 0)
    if (total > 0) {
      remainingPercent = Math.max(0, Math.min(100, (packageRemainingTotal / total) * 100))
    }
  }

  const expiresText = formatExpiry(expiresAt)
  const packageText = packages.length ? ` · ${packages.length} 个资源包` : ''
  const summaryText = `余额 ${creditsText}${packageText}`

  return {
    creditsText,
    remainingPercent,
    expiresText,
    packageCount: packages.length,
    packageRemainingTotal,
    packages,
    summaryText,
  }
}
