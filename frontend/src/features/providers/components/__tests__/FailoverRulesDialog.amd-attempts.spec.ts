import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest'
import { createApp, nextTick, type App } from 'vue'

import type { FailoverRulesConfig, ProviderWithEndpointsSummary } from '@/api/endpoints/types'
import FailoverRulesDialog from '../FailoverRulesDialog.vue'

const endpointMocks = vi.hoisted(() => ({
  updateProvider: vi.fn(),
}))

vi.mock('@/api/endpoints', () => ({
  updateProvider: endpointMocks.updateProvider,
}))

vi.mock('@/composables/useToast', () => ({
  useToast: () => ({
    success: vi.fn(),
    error: vi.fn(),
  }),
}))

const mountedApps: Array<{ app: App, root: HTMLElement }> = []

function makeProvider(
  failoverRules: FailoverRulesConfig | null,
  providerType = 'amd',
): ProviderWithEndpointsSummary {
  return {
    id: 'provider-1',
    provider_type: providerType,
    failover_rules: failoverRules,
  } as ProviderWithEndpointsSummary
}

function mountDialog(failoverRules: FailoverRulesConfig | null = null, providerType = 'amd') {
  const root = document.createElement('div')
  document.body.appendChild(root)
  const app = createApp(FailoverRulesDialog, {
    open: true,
    provider: makeProvider(failoverRules, providerType),
    'onUpdate:open': vi.fn(),
  })
  app.mount(root)
  mountedApps.push({ app, root })
}

async function settle() {
  for (let index = 0; index < 6; index += 1) {
    await Promise.resolve()
    await nextTick()
  }
}

function attemptsInput(): HTMLInputElement | null {
  return document.body.querySelector<HTMLInputElement>('input[aria-label="AMD 单请求最多尝试次数"]')
}

async function typeAttempts(value: string) {
  const input = attemptsInput()
  if (!input) throw new Error('Missing AMD max-attempts input')
  input.value = value
  input.dispatchEvent(new Event('input'))
  input.dispatchEvent(new Event('change'))
  await settle()
}

function clickSave() {
  const button = [...document.body.querySelectorAll<HTMLButtonElement>('button')]
    .find(candidate => candidate.textContent?.trim() === '保存')
  if (!button) throw new Error('Missing save button')
  button.click()
}

function savedRules(): FailoverRulesConfig {
  const calls = endpointMocks.updateProvider.mock.calls
  const call = calls[calls.length - 1]
  if (!call) throw new Error('updateProvider was not called')
  // 所有规则都为空时后端收到的是 null（表示删除整个 failover_rules）——按空对象读取。
  return (call[1].failover_rules ?? {}) as FailoverRulesConfig
}

beforeEach(() => {
  endpointMocks.updateProvider.mockReset()
  endpointMocks.updateProvider.mockResolvedValue(makeProvider(null))
})

afterEach(() => {
  for (const { app, root } of mountedApps.splice(0)) {
    app.unmount()
    root.remove()
  }
  document.body.innerHTML = ''
})

describe('FailoverRulesDialog AMD 单请求尝试次数', () => {
  it('shows the current value for AMD providers', async () => {
    mountDialog({ max_attempts_per_provider: 3 })
    await settle()

    expect(attemptsInput()?.value).toBe('3')
    expect(document.body.textContent).toContain('单请求尝试次数')
  })

  it('hides the field for non-AMD providers', async () => {
    mountDialog({ max_attempts_per_provider: 3 }, 'openai')
    await settle()

    expect(attemptsInput()).toBeNull()
    expect(document.body.textContent).not.toContain('单请求尝试次数')
  })

  it('saves the edited value and keeps unrelated keys intact', async () => {
    mountDialog({ max_attempts_per_provider: 1, custom_flag: true } as unknown as FailoverRulesConfig)
    await settle()

    await typeAttempts('4')
    clickSave()
    await settle()

    const rules = savedRules() as unknown as Record<string, unknown>
    expect(rules.max_attempts_per_provider).toBe(4)
    expect(rules.custom_flag).toBe(true)
  })

  it('drops the key when cleared so AMD falls back to the default', async () => {
    mountDialog({ max_attempts_per_provider: 5 })
    await settle()

    await typeAttempts('')
    clickSave()
    await settle()

    expect(savedRules().max_attempts_per_provider).toBeUndefined()
  })

  it('rejects out-of-range values instead of saving them', async () => {
    mountDialog({ max_attempts_per_provider: 1 })
    await settle()

    await typeAttempts('11')
    clickSave()
    await settle()

    expect(endpointMocks.updateProvider).not.toHaveBeenCalled()
  })
})
