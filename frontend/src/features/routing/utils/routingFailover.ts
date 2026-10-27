export const MAX_ROUTING_FAILOVER_RULES = 64
export const MAX_ROUTING_FAILOVER_PATTERN_BYTES = 4096

export const DEFAULT_OPENCODE_DELAYED_RETRY_BASE_MS = 10_000
export const DEFAULT_OPENCODE_DELAYED_RETRY_MULTIPLIER = 2
export const DEFAULT_OPENCODE_DELAYED_RETRY_MAX_MS = 80_000
export const MAX_OPENCODE_DELAYED_RETRY_DELAY_MS = 300_000
export const MAX_OPENCODE_DELAYED_RETRY_MULTIPLIER = 100

export interface RoutingFailoverRule {
  pattern: string
  status_codes: number[]
}

export interface RoutingFailoverRules {
  success_failover_patterns: RoutingFailoverRule[]
  error_stop_patterns: RoutingFailoverRule[]
}

/**
 * opencode 的「延迟重试」阶梯。
 *
 * 这套阶梯同时服务两类**值得等一会儿再试**的失败：
 * - 上下文超长（400）：免费层模型（big-pickle 等）是自动路由的，同一条请求可能落到
 *   窗口不同的后端，延迟后重试有机会落到窗口更大的后端；
 * - 配额 / 限流（429、带额度文案的 403）：等待同样按这条阶梯走，但次数上限由供应商侧
 *   的 `opencode_scan.quota_retry_*` 兜住（默认最多 3 次，含第一次），换点只从
 *   **未冷却**的出口 IP 里随机挑。
 *
 * 这里只管**间隔**；上下文超长的次数仍由调度策略的「错误重试次数」控制。
 */
export interface OpenCodeDelayedRetryPolicy {
  enabled: boolean
  base_ms: number
  multiplier: number
  max_ms: number
}

export interface RoutingFailoverPolicy {
  max_transfer_count: number
  max_transfer_timeout_seconds: number
  failover_rules: RoutingFailoverRules
  opencode_delayed_retry: OpenCodeDelayedRetryPolicy
}

export function defaultOpenCodeDelayedRetryPolicy(): OpenCodeDelayedRetryPolicy {
  return {
    enabled: true,
    base_ms: DEFAULT_OPENCODE_DELAYED_RETRY_BASE_MS,
    multiplier: DEFAULT_OPENCODE_DELAYED_RETRY_MULTIPLIER,
    max_ms: DEFAULT_OPENCODE_DELAYED_RETRY_MAX_MS,
  }
}

function positiveIntOr(value: unknown, fallback: number): number {
  const parsed = Number(value)
  if (!Number.isFinite(parsed) || parsed <= 0) return fallback
  return Math.floor(parsed)
}

export function normalizeOpenCodeDelayedRetryPolicy(
  value?: Partial<OpenCodeDelayedRetryPolicy> | null,
): OpenCodeDelayedRetryPolicy {
  const base = defaultOpenCodeDelayedRetryPolicy()
  return {
    enabled: value?.enabled === undefined ? base.enabled : value.enabled === true,
    base_ms: Math.min(positiveIntOr(value?.base_ms, base.base_ms), MAX_OPENCODE_DELAYED_RETRY_DELAY_MS),
    multiplier: Math.min(positiveIntOr(value?.multiplier, base.multiplier), MAX_OPENCODE_DELAYED_RETRY_MULTIPLIER),
    max_ms: Math.min(positiveIntOr(value?.max_ms, base.max_ms), MAX_OPENCODE_DELAYED_RETRY_DELAY_MS),
  }
}

export function normalizeRoutingFailoverPolicy(value?: Partial<RoutingFailoverPolicy>): RoutingFailoverPolicy {
  const rules = value?.failover_rules
  const cloneRules = (entries?: RoutingFailoverRule[]): RoutingFailoverRule[] => (
    Array.isArray(entries) ? entries.map(rule => ({
      pattern: String(rule.pattern ?? ''),
      status_codes: Array.isArray(rule.status_codes) ? [...rule.status_codes] : [],
    })) : []
  )
  return {
    max_transfer_count: Number(value?.max_transfer_count ?? 0),
    max_transfer_timeout_seconds: Number(value?.max_transfer_timeout_seconds ?? 0),
    failover_rules: {
      success_failover_patterns: cloneRules(rules?.success_failover_patterns),
      error_stop_patterns: cloneRules(rules?.error_stop_patterns),
    },
    // 乱序字段必须整块克隆，否则面板上的编辑会直接写进父级 config。
    opencode_delayed_retry: normalizeOpenCodeDelayedRetryPolicy(value?.opencode_delayed_retry),
  }
}

export function validateRoutingFailoverPolicy(policy: RoutingFailoverPolicy): string | null {
  for (const [name, value] of [
    ['全局最大转移次数', policy.max_transfer_count],
    ['全局最大转移时间', policy.max_transfer_timeout_seconds],
  ] as const) {
    if (!Number.isSafeInteger(value) || value < 0) return `${name}必须是非负整数`
  }
  for (const [name, entries, success] of [
    ['成功转移规则', policy.failover_rules.success_failover_patterns, true],
    ['错误终止规则', policy.failover_rules.error_stop_patterns, false],
  ] as const) {
    if (entries.length > MAX_ROUTING_FAILOVER_RULES) return `${name}最多 ${MAX_ROUTING_FAILOVER_RULES} 条`
    for (const [index, rule] of entries.entries()) {
      if (!rule.pattern.trim() && (success || rule.status_codes.length === 0)) {
        return `${name}第 ${index + 1} 条需要${success ? '正则表达式' : '状态码或正则表达式'}`
      }
      if (new TextEncoder().encode(rule.pattern.trim()).length > MAX_ROUTING_FAILOVER_PATTERN_BYTES) {
        return `${name}第 ${index + 1} 条正则过长`
      }
      if (rule.status_codes.some(status => !Number.isInteger(status) || (success ? status !== 200 : status < 400 || status > 599))) {
        return `${name}第 ${index + 1} 条状态码必须为${success ? ' 200' : ' 400–599'}`
      }
    }
  }
  return null
}
