import { describe, expect, it } from 'vitest'
import { formatWorkbuddyCredits, workbuddyQuotaView } from '../workbuddyQuota'

/**
 * 号池管理「配额」列的 WorkBuddy 额度视图 ✓。
 * 线上实测的数据形状（`upstream_metadata.workbuddy` ✓）：
 * `credits_limit 2900 / credits_remaining 2899 / unlimited false / packages[5] / expires_at`。
 */
describe('workbuddyQuotaView', () => {
  it('用真实线上形状解析出余额、百分比与资源包数', () => {
    const view = workbuddyQuotaView({
      workbuddy: {
        credits_limit: 2900,
        credits_remaining: 2899,
        credits_used: 1,
        unlimited: false,
        expires_at: 1793462399,
        packages: [
          { name: 'CodeBuddy个人体验版', size: 500, remaining: 499, expires_at: 1793462399 },
          { name: '拉新权益包', size: 1500, remaining: 1500, expires_at: 1794900211 },
        ],
        models: [{ model_uid: 'auto' }],
        maintenance: { checkin: 'already_checked_in' },
      },
      codex: { whatever: true },
    })
    expect(view).not.toBeNull()
    expect(view?.creditsText).toBe('2899 / 2900')
    expect(view?.remainingPercent).toBeCloseTo((2899 / 2900) * 100, 5)
    expect(view?.packageCount).toBe(2)
    expect(view?.packageRemainingTotal).toBe(1999)
    expect(view?.summaryText).toBe('余额 2899 / 2900 · 2 个资源包')
    // 到期按 CST 展示 ✓（1793462399 = 2026-11-01T00:00Z 附近的 CST 日期）
    expect(view?.expiresText).toMatch(/^\d{2}-\d{2} 到期$/)
  })

  it('unlimited 显示「不限量」且百分比 100', () => {
    const view = workbuddyQuotaView({ workbuddy: { unlimited: true } })
    expect(view?.creditsText).toBe('不限量')
    expect(view?.remainingPercent).toBe(100)
    expect(view?.summaryText).toBe('余额 不限量')
  })

  it('只有资源包时按包的总量算百分比', () => {
    const view = workbuddyQuotaView({
      workbuddy: {
        packages: [
          { name: 'A', size: 100, remaining: 25 },
          { name: 'B', size: 100, remaining: 25 },
        ],
      },
    })
    expect(view?.creditsText).toBe('- / -')
    expect(view?.remainingPercent).toBe(25)
    expect(view?.packageCount).toBe(2)
  })

  it('没有额度数据时返回 null（不要显示 0/0 误导 ✗）', () => {
    expect(workbuddyQuotaView(null)).toBeNull()
    expect(workbuddyQuotaView({})).toBeNull()
    // 只有目录/维护信息、没有额度字段 → 不算有额度 ✓
    expect(workbuddyQuotaView({
      workbuddy: { models: [{ model_uid: 'auto' }], maintenance: { checkin: 'already_checked_in' } },
    })).toBeNull()
    expect(workbuddyQuotaView({ codex: { credits: { remaining: 5 } } })).toBeNull()
  })

  it('余额为 0 也要显示（真的用光了 ✓ 不是「没有数据」）', () => {
    const view = workbuddyQuotaView({ workbuddy: { credits_limit: 100, credits_remaining: 0 } })
    expect(view).not.toBeNull()
    expect(view?.creditsText).toBe('0 / 100')
    expect(view?.remainingPercent).toBe(0)
  })

  it('uses the earliest expiry among packages with remaining credits', () => {
    const view = workbuddyQuotaView({
      workbuddy: {
        credits_remaining: 100,
        credits_limit: 200,
        expires_at: 1_800_000_000,
        packages: [
          { name: '已用完旧包', size: 100, remaining: 0, expires_at: 1_700_000_000 },
          { name: '未用完晚到期', size: 100, remaining: 80, expires_at: 1_800_000_000 },
          { name: '未用完早到期', size: 100, remaining: 20, expires_at: 1_750_000_000 },
        ],
      },
    })
    expect(view?.expiresText).toBe('06-15 到期')
  })

  it('credits 文本去掉多余小数', () => {
    expect(formatWorkbuddyCredits(2900)).toBe('2900')
    expect(formatWorkbuddyCredits(2899)).toBe('2899')
    expect(formatWorkbuddyCredits(12.5)).toBe('12.5')
    expect(formatWorkbuddyCredits(12.666)).toBe('12.67')
    expect(formatWorkbuddyCredits(null)).toBe('-')
  })
})
