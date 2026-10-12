import { describe, expect, it } from 'vitest'

import { normalizeBatchImportCredentials } from '@/api/endpoints/provider_oauth'
import {
  isKeyHealthRecoverable,
  isKeyManagedProviderType,
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
