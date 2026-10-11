import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest'
import { createApp, nextTick, type App } from 'vue'

import type { EndpointAPIKey } from '@/api/endpoints/types'
import KeyFormDialog from '../KeyFormDialog.vue'

const keyMocks = vi.hoisted(() => ({
  addProviderKey: vi.fn(),
  updateProviderKey: vi.fn(),
}))

vi.mock('@/api/endpoints', async (importOriginal) => {
  const actual = await importOriginal<typeof import('@/api/endpoints')>()
  return {
    ...actual,
    addProviderKey: keyMocks.addProviderKey,
    updateProviderKey: keyMocks.updateProviderKey,
  }
})

vi.mock('@/composables/useToast', () => ({
  useToast: () => ({
    success: vi.fn(),
    error: vi.fn(),
    warning: vi.fn(),
    info: vi.fn(),
  }),
}))

const CIRCUIT_PROBE_LABEL = '熔断探测'
const PROBE_FIELD = 'max_probe_interval_minutes'

const mountedApps: Array<{ app: App, root: HTMLElement }> = []

function makeKey(overrides: Record<string, unknown> = {}): EndpointAPIKey {
  return {
    id: 'key-1',
    provider_id: 'provider-1',
    name: 'amd-account@example.com',
    api_formats: ['openai:chat'],
    auth_type: 'api_key',
    auth_type_by_format: null,
    allow_auth_channel_mismatch_formats: [],
    api_key_masked: 'rc-abcd1***2345',
    allowed_models: [],
    rate_multipliers: null,
    internal_priority: 10,
    rpm_limit: null,
    concurrent_limit: null,
    cache_ttl_minutes: 5,
    max_probe_interval_minutes: 17,
    is_active: true,
    auto_fetch_models: false,
    ...overrides,
  } as unknown as EndpointAPIKey
}

function mountDialog(providerType: string, editingKey: EndpointAPIKey | null = null): void {
  const root = document.createElement('div')
  document.body.appendChild(root)
  const app = createApp(KeyFormDialog, {
    open: true,
    endpoint: null,
    editingKey,
    providerId: 'provider-1',
    providerType,
    availableApiFormats: ['openai:chat'],
  })
  app.mount(root)
  mountedApps.push({ app, root })
}

async function settle(): Promise<void> {
  for (let index = 0; index < 6; index += 1) {
    await Promise.resolve()
    await nextTick()
  }
}

function clickButton(text: string): void {
  const button = [...document.body.querySelectorAll<HTMLButtonElement>('button')]
    .find(candidate => candidate.textContent?.trim() === text)
  if (!button) throw new Error(`Missing button: ${text}`)
  button.click()
}

async function setInput(selector: string, value: string): Promise<void> {
  const input = document.body.querySelector<HTMLInputElement>(selector)
  if (!input) throw new Error(`Missing input: ${selector}`)
  input.value = value
  input.dispatchEvent(new Event('input', { bubbles: true }))
  await nextTick()
}

/** 断言"真正发出去的请求体"：组件内部会放 `undefined` 占位，序列化时才被丢掉。 */
function wirePayload(payload: unknown): Record<string, unknown> {
  return JSON.parse(JSON.stringify(payload ?? {})) as Record<string, unknown>
}

beforeEach(() => {
  keyMocks.addProviderKey.mockReset()
  keyMocks.addProviderKey.mockResolvedValue(makeKey({ id: 'key-new' }))
  keyMocks.updateProviderKey.mockReset()
  keyMocks.updateProviderKey.mockResolvedValue(makeKey())
})

afterEach(() => {
  for (const { app, root } of mountedApps.splice(0)) {
    app.unmount()
    root.remove()
  }
  document.body.innerHTML = ''
})

describe('KeyFormDialog AMD circuit probe', () => {
  it('对 AMD 隐藏「熔断探测」，并且更新时不把该字段发出去', async () => {
    mountDialog('amd', makeKey())
    await settle()

    expect(document.body.textContent).not.toContain(CIRCUIT_PROBE_LABEL)

    clickButton('保存')
    await settle()

    expect(keyMocks.updateProviderKey).toHaveBeenCalledTimes(1)
    const wire = wirePayload(keyMocks.updateProviderKey.mock.calls[0]?.[1])
    expect(Object.keys(wire)).not.toContain(PROBE_FIELD)
    // 同一栏里其它字段必须照旧发出去（缓存 TTL 对 AMD 仍然有效）
    expect(wire).toMatchObject({ cache_ttl_minutes: 5, internal_priority: 10 })
  })

  it('对 AMD 新建密钥时同样不发送该字段（后端走默认值）', async () => {
    mountDialog('amd', null)
    await settle()

    expect(document.body.textContent).not.toContain(CIRCUIT_PROBE_LABEL)

    // 名称与密钥输入框的 id 带随机后缀（`key-name-*` / `api-key-*`），用前缀选择器。
    await setInput('input[id^="key-name-"]', 'amd-account@example.com')
    await setInput('input[id^="api-key-"]', 'rc-test-key-value')
    await settle()

    clickButton('添加')
    await settle()

    expect(keyMocks.addProviderKey).toHaveBeenCalledTimes(1)
    const wire = wirePayload(keyMocks.addProviderKey.mock.calls[0]?.[1])
    expect(Object.keys(wire)).not.toContain(PROBE_FIELD)
    expect(wire).toMatchObject({ name: 'amd-account@example.com', api_key: 'rc-test-key-value' })
  })

  it('其它供应商完全不受影响：字段照常显示、照常提交原值', async () => {
    mountDialog('custom', makeKey())
    await settle()

    expect(document.body.textContent).toContain(CIRCUIT_PROBE_LABEL)

    clickButton('保存')
    await settle()

    expect(keyMocks.updateProviderKey).toHaveBeenCalledTimes(1)
    const wire = wirePayload(keyMocks.updateProviderKey.mock.calls[0]?.[1])
    expect(wire[PROBE_FIELD]).toBe(17)
  })
})
