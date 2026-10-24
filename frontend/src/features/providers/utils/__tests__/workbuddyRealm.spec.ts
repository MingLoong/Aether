import { describe, expect, it } from 'vitest'

import {
  WORKBUDDY_BRAND,
  guessWorkbuddyRealmFromName,
  isWorkbuddyProviderType,
  resolveWorkbuddyRealm,
  upstreamBrandLabel,
} from '@/features/providers/utils/workbuddyRealm'

/**
 * 区域解析是「加号锁域」的唯一真相：解析结果错，账号就会被加到另一个号池里
 * （跨域凭据上游必 401）。这里把三条取数来源、三种兜底顺序全部钉死。
 */
describe('workbuddyRealm', () => {
  it('只把 workbuddy 当本功能范围', () => {
    expect(isWorkbuddyProviderType('WorkBuddy')).toBe(true)
    expect(isWorkbuddyProviderType(' codex ')).toBe(false)
    expect(resolveWorkbuddyRealm({ provider_type: 'codex', name: 'workbuddy-global' })).toBeNull()
    expect(resolveWorkbuddyRealm(null, undefined)).toBeNull()
  })

  it('声明值优先于任何名字线索', () => {
    expect(resolveWorkbuddyRealm({
      provider_type: 'workbuddy',
      workbuddy_realm: 'global',
      name: 'my-codebuddy-cn',
    })).toEqual({ realm: 'global', source: 'config' })
  })

  it('声明值容忍大小写与空白（后端存的是小写，历史数据未必）', () => {
    expect(resolveWorkbuddyRealm({
      provider_type: 'workbuddy',
      workbuddy_realm: ' GLOBAL ',
    })).toEqual({ realm: 'global', source: 'config' })
  })

  it('详情接口没窄字段时读 config.workbuddy.realm', () => {
    expect(resolveWorkbuddyRealm({
      provider_type: 'workbuddy',
      config: { workbuddy: { realm: 'global' } },
    })).toEqual({ realm: 'global', source: 'config' })
  })

  it('多份候选里任意一份声明了域就够（不依赖请求时序）', () => {
    expect(resolveWorkbuddyRealm(
      { provider_type: 'workbuddy', name: 'CodeBuddy' },
      { provider_type: 'workbuddy', workbuddy_realm: 'global' },
    )).toEqual({ realm: 'global', source: 'config' })
  })

  it('没声明时按名字线索，区域词优先于品牌词', () => {
    expect(guessWorkbuddyRealmFromName('workbuddy-global')).toBe('global')
    expect(guessWorkbuddyRealmFromName('workbuddy-cn')).toBe('cn')
    expect(guessWorkbuddyRealmFromName('WorkBuddy 国际版')).toBe('global')
    expect(guessWorkbuddyRealmFromName('CodeBuddy 国内版')).toBe('cn')
    expect(guessWorkbuddyRealmFromName('用户改过的名字')).toBeNull()
    expect(resolveWorkbuddyRealm({ provider_type: 'workbuddy', name: '我的 WorkBuddy' }))
      .toEqual({ realm: 'global', source: 'name' })
    expect(resolveWorkbuddyRealm({ provider_type: 'workbuddy', name: 'my-codebuddy' }))
      .toEqual({ realm: 'cn', source: 'name' })
  })

  it('既没声明也没线索：默认 CN，且标出 source 让界面能说明', () => {
    expect(resolveWorkbuddyRealm({ provider_type: 'workbuddy', name: '号池一' }))
      .toEqual({ realm: 'cn', source: 'default' })
  })

  it('展示名：预设名翻成品牌名，改过名则「名字 · 品牌」都保留', () => {
    expect(upstreamBrandLabel({ provider_type: 'workbuddy', workbuddy_realm: 'cn', name: 'workbuddy-cn' }))
      .toBe('CodeBuddy')
    expect(upstreamBrandLabel({ provider_type: 'workbuddy', workbuddy_realm: 'global', name: 'my-pool' }))
      .toBe('my-pool · WorkBuddy')
    // 非 workbuddy 原样返回
    expect(upstreamBrandLabel({ provider_type: 'codex', name: 'Codex 1' })).toBe('Codex 1')
    // 只有概览名（summary 还没回来）也要认出区域
    expect(upstreamBrandLabel({ provider_type: 'workbuddy', name: 'workbuddy-global' }))
      .toBe(WORKBUDDY_BRAND.global)
    // 域只能靠默认兜底：不报品牌（报错一家比不报更坏）
    expect(upstreamBrandLabel({ provider_type: 'workbuddy', name: '号池一' })).toBe('号池一')
  })
})
