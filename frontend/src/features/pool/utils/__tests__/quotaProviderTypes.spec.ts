import { describe, expect, it } from 'vitest'

import {
  ACCOUNT_QUOTA_PROVIDER_TYPES,
  QUOTA_REFRESH_PROVIDER_TYPES,
  showsAccountQuotaColumn,
  supportsQuotaRefresh,
} from '../quotaProviderTypes'

/**
 * 这两条用例是「防回归钉子」✓：
 * 名单内容一旦改动，测试必须同步改 ✓ —— 不允许悄悄漏掉某个供应商 ✗。
 *
 * 背景 ✗：2026-10-17 接入 `workbuddy` 时，额度视图（`workbuddyQuota.ts`）和进度条都做好了 ✓，
 * 但「配额」整列的名单里没有它 ✗ → 界面上什么都看不到 ✗，数据其实一直在 ✓。
 */
describe('quotaProviderTypes', () => {
  it('额度列名单被钉住（新增供应商必须显式修改本测试）', () => {
    expect([...ACCOUNT_QUOTA_PROVIDER_TYPES].sort()).toEqual([
      'antigravity',
      'chatgpt_web',
      'claude_code',
      'codex',
      'gemini_cli',
      'grok',
      'kiro',
      'windsurf',
      'workbuddy',
      'xai',
    ])
  })

  it('刷新额度名单被钉住', () => {
    expect([...QUOTA_REFRESH_PROVIDER_TYPES].sort()).toEqual([
      'antigravity',
      'chatgpt_web',
      'claude_code',
      'codex',
      'gemini_cli',
      'grok',
      'kiro',
      'windsurf',
      'workbuddy',
      'xai',
    ])
  })

  it('workbuddy 必须同时在两份名单里', () => {
    expect(ACCOUNT_QUOTA_PROVIDER_TYPES).toContain('workbuddy')
    expect(QUOTA_REFRESH_PROVIDER_TYPES).toContain('workbuddy')
    expect(showsAccountQuotaColumn('workbuddy')).toBe(true)
    expect(supportsQuotaRefresh('workbuddy')).toBe(true)
  })

  it('能刷额度但看不到列是不自洽的', () => {
    const missing = QUOTA_REFRESH_PROVIDER_TYPES.filter(
      (type) => !ACCOUNT_QUOTA_PROVIDER_TYPES.includes(type),
    )
    expect(missing).toEqual([])
  })

  it('provider_type 大小写与空白不影响命中', () => {
    expect(showsAccountQuotaColumn('WorkBuddy')).toBe(true)
    expect(showsAccountQuotaColumn('  WORKBUDDY ')).toBe(true)
    expect(supportsQuotaRefresh('Codex')).toBe(true)
  })

  it('未知供应商与空值一律不显示', () => {
    expect(showsAccountQuotaColumn('some_new_provider')).toBe(false)
    expect(supportsQuotaRefresh('some_new_provider')).toBe(false)
    expect(showsAccountQuotaColumn('')).toBe(false)
    expect(showsAccountQuotaColumn(null)).toBe(false)
    expect(showsAccountQuotaColumn(undefined)).toBe(false)
    expect(supportsQuotaRefresh(null)).toBe(false)
    expect(supportsQuotaRefresh(undefined)).toBe(false)
  })
})
