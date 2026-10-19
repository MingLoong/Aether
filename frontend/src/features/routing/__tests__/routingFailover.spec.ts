import { describe, expect, it } from 'vitest'
import { normalizeRoutingFailoverPolicy, validateRoutingFailoverPolicy } from '../utils/routingFailover'
import { createEmptyRoutingGroupConfig, getModelScheduling, normalizeRoutingGroupConfig, upsertModelSchedulingRule } from '../utils/routingPolicy'

describe('routing failover policy', () => {
  it('keeps legacy strategies unlimited with empty global rules', () => {
    const policy = normalizeRoutingGroupConfig({}).default_policy
    expect(policy.max_transfer_count).toBe(0)
    expect(policy.max_transfer_timeout_seconds).toBe(0)
    expect(policy.failover_rules).toEqual({ success_failover_patterns: [], error_stop_patterns: [] })
    expect(validateRoutingFailoverPolicy(policy)).toBeNull()
  })

  it('preserves global limits and rules across model edits without sharing mutable arrays', () => {
    const config = createEmptyRoutingGroupConfig()
    Object.assign(config.default_policy, {
      max_transfer_count: 3,
      max_transfer_timeout_seconds: 90,
      failover_rules: {
        success_failover_patterns: [{ pattern: '(?i)capacity', status_codes: [] }],
        error_stop_patterns: [{ pattern: '', status_codes: [400, 413] }],
      },
    })
    const updated = upsertModelSchedulingRule(config, 'model-a', { priority_mode: 'provider', scheduling_mode: 'fixed_order' })
    const policy = getModelScheduling(updated, 'model-a')
    expect(policy.max_transfer_count).toBe(3)
    expect(policy.max_transfer_timeout_seconds).toBe(90)
    expect(policy.failover_rules).toEqual(config.default_policy.failover_rules)
    expect(validateRoutingFailoverPolicy(policy)).toBeNull()
    policy.failover_rules.error_stop_patterns[0].status_codes.push(422)
    expect(config.default_policy.failover_rules.error_stop_patterns[0].status_codes).toEqual([400, 413])
  })

  it('rejects invalid budgets and ambiguous empty rules before saving', () => {
    const policy = normalizeRoutingFailoverPolicy()
    policy.max_transfer_count = -1
    expect(validateRoutingFailoverPolicy(policy)).toContain('非负整数')
    policy.max_transfer_count = 0
    policy.max_transfer_timeout_seconds = 0.5
    expect(validateRoutingFailoverPolicy(policy)).toContain('非负整数')
    policy.max_transfer_timeout_seconds = 0
    policy.failover_rules.error_stop_patterns.push({ pattern: '', status_codes: [] })
    expect(validateRoutingFailoverPolicy(policy)).toContain('状态码或正则')
    policy.failover_rules.error_stop_patterns[0].status_codes = [200]
    expect(validateRoutingFailoverPolicy(policy)).toContain('400–599')
    policy.failover_rules.error_stop_patterns[0].status_codes = [400]
    expect(validateRoutingFailoverPolicy(policy)).toBeNull()
  })

  it('defaults the opencode context retry ladder to 10s/×2/80s and keeps it on', () => {
    const policy = normalizeRoutingGroupConfig({}).default_policy
    expect(policy.opencode_context_retry).toEqual({
      enabled: true,
      base_ms: 10_000,
      multiplier: 2,
      max_ms: 80_000,
    })
    expect(validateRoutingFailoverPolicy(policy)).toBeNull()
  })

  it('clones the opencode retry config so panel edits never leak into the parent config', () => {
    const base = normalizeRoutingGroupConfig({})
    const config = normalizeRoutingGroupConfig({
      ...base,
      default_policy: {
        ...base.default_policy,
        opencode_context_retry: { enabled: true, base_ms: 5_000, multiplier: 3, max_ms: 30_000 },
      },
    })
    expect(config.default_policy.opencode_context_retry).toEqual({
      enabled: true,
      base_ms: 5_000,
      multiplier: 3,
      max_ms: 30_000,
    })
    const edited = normalizeRoutingFailoverPolicy(config.default_policy)
    edited.opencode_context_retry.base_ms = 1_000
    expect(config.default_policy.opencode_context_retry.base_ms).toBe(5_000)
  })

  it('rejects a nonsensical opencode ladder but ignores the numbers once switched off', () => {
    const policy = normalizeRoutingFailoverPolicy()
    policy.opencode_context_retry.base_ms = 0
    expect(validateRoutingFailoverPolicy(policy)).toContain('OpenCode 首次延迟')
    policy.opencode_context_retry.base_ms = 10_000
    policy.opencode_context_retry.max_ms = 9_999
    expect(validateRoutingFailoverPolicy(policy)).toContain('不能大于最大延迟')
    policy.opencode_context_retry.max_ms = 80_000
    policy.opencode_context_retry.multiplier = 0
    expect(validateRoutingFailoverPolicy(policy)).toContain('倍增倍数')
    policy.opencode_context_retry.multiplier = 2
    expect(validateRoutingFailoverPolicy(policy)).toBeNull()
    policy.opencode_context_retry.enabled = false
    policy.opencode_context_retry.base_ms = 0
    policy.opencode_context_retry.max_ms = 0
    expect(validateRoutingFailoverPolicy(policy)).toBeNull()
  })
})
