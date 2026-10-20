import { describe, expect, it } from 'vitest'
import { existsSync, readFileSync } from 'node:fs'
import { resolve } from 'node:path'
import { POOL_ADVANCED_DEFAULTS } from '../poolAdvancedDefaults'

/**
 * 维护性审计（2026-10-17）发现的**真实漂移** ✗：
 * 前端 `PoolAdvancedDialog` 的兜底值从旧的「Aether 历史默认」（8 / 0 / 0 / 0 / 0 / false）
 * 没跟上后端改成面板口径（3 / 30 / 360 / 2 / 1800 / true）✗ ——
 * 后果是「配置里缺这些键时，打开对话框再保存」会把默认值**静默写回旧值** ✗
 * （等于关掉国际号在途分档 + 成本探索 + 池计入熔断 ✗）。
 *
 * 这条测试**直接读后端源码**核对默认值 ✓，代价极低、跨边界有效 ✓。
 * 后端文件不存在时（例如前端被单独检出）自动跳过 ✓，不制造假失败 ✓。
 *
 * 后端真源：`crates/aether-pool-core/src/pool_advanced_defaults.rs` ✓
 * （网关的解析路径、调度运行时、前端都对着它 ✓ —— 单一事实来源 ✓）。
 */
const BACKEND_DEFAULTS_FILE = resolve(
  __dirname,
  '../../../../../../crates/aether-pool-core/src/pool_advanced_defaults.rs',
)

function backendSource(): string | null {
  if (!existsSync(BACKEND_DEFAULTS_FILE)) return null
  return readFileSync(BACKEND_DEFAULTS_FILE, 'utf8')
}

/** 取出 `pub const NAME: u64 = 3;` 里的字面量（下划线千分位也会被去掉 ✓）。 */
function backendConst(source: string, name: string): number | boolean | null {
  const pattern = new RegExp(`pub const ${name}:\\s*(?:u64|usize|i64|bool)\\s*=\\s*([0-9_]+|true|false);`)
  const match = pattern.exec(source)
  if (!match) return null
  const raw = match[1]
  if (raw === 'true') return true
  if (raw === 'false') return false
  return Number(raw.replace(/_/g, ''))
}

describe('poolAdvancedDefaults', () => {
  const source = backendSource()

  it('导出的是面板口径默认值，不含「0 当作没设置」的坑', () => {
    expect(POOL_ADVANCED_DEFAULTS.breakerThreshold).toBeGreaterThan(0)
    expect(POOL_ADVANCED_DEFAULTS.breakerCooldownMinutes).toBeGreaterThan(0)
    expect(POOL_ADVANCED_DEFAULTS.breakerCooldownMaxMinutes).toBeGreaterThanOrEqual(
      POOL_ADVANCED_DEFAULTS.breakerCooldownMinutes,
    )
    expect(POOL_ADVANCED_DEFAULTS.maxInFlight).toBeGreaterThan(0)
    expect(POOL_ADVANCED_DEFAULTS.costExploreIntervalSeconds).toBeGreaterThan(0)
    expect(POOL_ADVANCED_DEFAULTS.wafIpCooldownSeconds).toBeGreaterThan(0)
    expect(POOL_ADVANCED_DEFAULTS.poolCountsTowardCircuitBreaker).toBe(true)
    expect(POOL_ADVANCED_DEFAULTS.wafIpBlockNewRequests).toBe(true)
    // 积分保底**面板没有这个功能** → 0 = 关闭 ✓（唯一允许为 0 的项 ✓）。
    expect(POOL_ADVANCED_DEFAULTS.creditFloor).toBe(0)
  })

  it.runIf(source !== null)('与后端 pool_advanced_defaults.rs 的常量逐项一致', () => {
    const text = source as string
    // 每个前端字段都必须能在后端找到**同值**的常量 ✓（找不到 = null → 断言失败 ✓）。
    const pairs: Array<[string, number | boolean]> = [
      ['BREAKER_THRESHOLD', POOL_ADVANCED_DEFAULTS.breakerThreshold],
      ['BREAKER_COOLDOWN_MINUTES', POOL_ADVANCED_DEFAULTS.breakerCooldownMinutes],
      ['BREAKER_COOLDOWN_MAX_MINUTES', POOL_ADVANCED_DEFAULTS.breakerCooldownMaxMinutes],
      ['COST_EXPLORE_INTERVAL_SECONDS', POOL_ADVANCED_DEFAULTS.costExploreIntervalSeconds],
      ['MAX_IN_FLIGHT', POOL_ADVANCED_DEFAULTS.maxInFlight],
      
      ['WAF_IP_COOLDOWN_SECONDS', POOL_ADVANCED_DEFAULTS.wafIpCooldownSeconds],
      ['WAF_IP_BLOCK_NEW_REQUESTS', POOL_ADVANCED_DEFAULTS.wafIpBlockNewRequests],
      [
        'POOL_COUNTS_TOWARD_CIRCUIT_BREAKER',
        POOL_ADVANCED_DEFAULTS.poolCountsTowardCircuitBreaker,
      ],
      ['CREDIT_FLOOR', POOL_ADVANCED_DEFAULTS.creditFloor],
    ]
    for (const [name, expected] of pairs) {
      expect(backendConst(text, name), `后端常量 ${name} 与前端不一致`).toBe(expected)
    }
  })
})
