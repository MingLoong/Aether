import { describe, expect, it } from 'vitest'

import { normalizeBatchImportCredentials } from '@/api/endpoints/provider_oauth'
import {
  isAmdTypedProvider,
  isKeyHealthRecoverable,
  isKeyManagedProviderType,
  isNoPoolProviderType,
  isOAuthAccountProviderType,
} from '../providerTypeUtils'

describe('providerTypeUtils', () => {
  it('treats ChatGPT-Web as an OAuth account provider', () => {
    expect(isOAuthAccountProviderType('chatgpt_web')).toBe(true)
    expect(isOAuthAccountProviderType('ChatGPT_Web')).toBe(true)
    expect(isKeyManagedProviderType('chatgpt_web')).toBe(false)
  })

  it('treats Grok as an OAuth account provider', () => {
    expect(isOAuthAccountProviderType('grok')).toBe(true)
    expect(isOAuthAccountProviderType('GROK')).toBe(true)
    expect(isKeyManagedProviderType('grok')).toBe(false)
  })

  it('treats xAI as an OAuth account provider', () => {
    expect(isOAuthAccountProviderType('xai')).toBe(true)
    expect(isOAuthAccountProviderType('xAI')).toBe(true)
    expect(isKeyManagedProviderType('xai')).toBe(false)
  })

  it('treats Windsurf as an OAuth account provider', () => {
    expect(isOAuthAccountProviderType('windsurf')).toBe(true)
    expect(isOAuthAccountProviderType('Windsurf')).toBe(true)
    expect(isKeyManagedProviderType('windsurf')).toBe(false)
  })
})

describe('isAmdTypedProvider', () => {
  it('recognises AMD by provider_type alone, regardless of base_url', () => {
    expect(isAmdTypedProvider('amd')).toBe(true)
    expect(isAmdTypedProvider(' AMD ')).toBe(true)
    expect(isAmdTypedProvider('Amd')).toBe(true)
    // 判据只认类型：早期的「custom + radeon 地址」兼容分支已删除，base_url 不再是判据。
    expect(isAmdTypedProvider('custom')).toBe(false)
    expect(isAmdTypedProvider('opencode')).toBe(false)
    expect(isAmdTypedProvider('')).toBe(false)
    expect(isAmdTypedProvider(null)).toBe(false)
    expect(isAmdTypedProvider(undefined)).toBe(false)
  })
})

describe('isKeyHealthRecoverable', () => {
  it('marks a low-health or open-circuit key as recoverable for non-AMD providers', () => {
    expect(isKeyHealthRecoverable('codex', { health_score: 0.4 })).toBe(true)
    expect(isKeyHealthRecoverable('codex', { circuit_breaker_open: true, health_score: 1 })).toBe(true)
    expect(isKeyHealthRecoverable('codex', { health_score: 1 })).toBe(false)
  })

  it('never marks an AMD key as recoverable, whatever stale health it carries', () => {
    // 复现线上那条假记录：AMD 一把从未被使用过的 key 健康度 0.4。
    expect(isKeyHealthRecoverable('amd', { health_score: 0.4 })).toBe(false)
    expect(isKeyHealthRecoverable(' AMD ', { health_score: 0.4 })).toBe(false)
    expect(isKeyHealthRecoverable('amd', { health_score: 0 })).toBe(false)
    expect(isKeyHealthRecoverable('amd', { circuit_breaker_open: true })).toBe(false)
  })

  it('never marks a Cline key as recoverable either (same exemption family)', () => {
    // Cline 官方上游的失败是订阅/额度级的（403 ENTITLEMENT_ERROR），后端同样不记健康、不开熔断。
    expect(isKeyHealthRecoverable('cline', { health_score: 0.4 })).toBe(false)
    expect(isKeyHealthRecoverable(' CLINE ', { health_score: 0.2 })).toBe(false)
    expect(isKeyHealthRecoverable('cline', { circuit_breaker_open: true })).toBe(false)
  })

  it('keeps pool-disabled types out of pool scheduling', () => {
    expect(isNoPoolProviderType('amd')).toBe(true)
    expect(isNoPoolProviderType('cline')).toBe(true)
    expect(isNoPoolProviderType(' Cline ')).toBe(true)
    expect(isNoPoolProviderType('codex')).toBe(false)
    expect(isNoPoolProviderType('opencode')).toBe(false)
    expect(isNoPoolProviderType(null)).toBe(false)
  })

  it('keeps the legacy custom-typed AMD provider on the normal path', () => {
    // 行为判据只认 provider_type：旧 custom 供应商后端仍按普通供应商处理健康/熔断，
    // 前端不能只凭 base_url 就把它当成 AMD 藏掉。
    expect(isKeyHealthRecoverable('custom', { health_score: 0.4 })).toBe(true)
  })

  it('treats an unknown health score as not recoverable', () => {
    expect(isKeyHealthRecoverable('codex', { health_score: null })).toBe(false)
    expect(isKeyHealthRecoverable('codex', {})).toBe(false)
  })
})

describe('normalizeBatchImportCredentials', () => {
  it('converts JSON Lines objects into a JSON array payload', () => {
    const result = normalizeBatchImportCredentials([
      '{"refresh_token":"rt-1","email":"one@example.com"}',
      '{"token":"token-2","email":"two@example.com"}',
    ].join('\n'))

    expect(result).toEqual({
      ok: true,
      isBatch: true,
      credentials: JSON.stringify([
        { refresh_token: 'rt-1', email: 'one@example.com' },
        { token: 'token-2', email: 'two@example.com' },
      ]),
    })
  })

  it('rejects malformed JSON Lines instead of treating them as raw tokens', () => {
    const result = normalizeBatchImportCredentials('{"refresh_token":"rt-1"}\n{"refresh_token":')

    expect(result.ok).toBe(false)
    if (!result.ok) {
      expect(result.message).toContain('第 2 行')
    }
  })

  it('converts multiple raw token lines into a JSON array payload', () => {
    const result = normalizeBatchImportCredentials('token-a\n# comment\ntoken-b')

    expect(result).toEqual({
      ok: true,
      isBatch: true,
      credentials: JSON.stringify(['token-a', 'token-b']),
    })
  })
})
