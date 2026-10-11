import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest'
import { createApp, nextTick, type App } from 'vue'

import type { ProviderWithEndpointsSummary } from '@/api/endpoints/types'
import ProviderFormDialog from '../ProviderFormDialog.vue'

const endpointMocks = vi.hoisted(() => ({
  createProvider: vi.fn(),
  updateProvider: vi.fn(),
}))

vi.mock('@/api/endpoints', () => ({
  createProvider: endpointMocks.createProvider,
  updateProvider: endpointMocks.updateProvider,
  normalizePoolAdvancedConfig: (value: unknown) => {
    if (value == null || value === false) return null
    if (value === true) return {}
    if (typeof value !== 'object' || Array.isArray(value)) return null
    return { ...value }
  },
}))

vi.mock('@/components/ui', async (importOriginal) => {
  const actual = await importOriginal<typeof import('@/components/ui')>()
  const { defineComponent, h } = await import('vue')
  const passthrough = (name: string) => defineComponent({
    name,
    setup: (_props, { slots }) => () => slots.default?.(),
  })

  return {
    ...actual,
    Select: defineComponent({
      name: 'SelectStub',
      props: {
        modelValue: String,
        disabled: Boolean,
      },
      emits: ['update:modelValue'],
      setup: (props, { emit, slots }) => () => h('select', {
        value: props.modelValue,
        disabled: props.disabled,
        onChange: (event: Event) => emit(
          'update:modelValue',
          (event.target as HTMLSelectElement).value,
        ),
      }, slots.default?.()),
    }),
    SelectTrigger: passthrough('SelectTriggerStub'),
    SelectValue: passthrough('SelectValueStub'),
    SelectContent: passthrough('SelectContentStub'),
    SelectItem: defineComponent({
      name: 'SelectItemStub',
      props: {
        value: { type: String, required: true },
        disabled: Boolean,
      },
      setup: (props, { slots }) => () => h('option', {
        value: props.value,
        disabled: props.disabled,
      }, slots.default?.()),
    }),
  }
})

vi.mock('@/composables/useToast', () => ({
  useToast: () => ({
    success: vi.fn(),
    error: vi.fn(),
  }),
}))

const mountedApps: Array<{ app: App, root: HTMLElement }> = []
const POOL_MODE_LABEL = '号池调度模式'

function makeProvider(
  overrides: Partial<ProviderWithEndpointsSummary> = {},
): ProviderWithEndpointsSummary {
  return {
    id: 'provider-1',
    name: 'Provider One',
    provider_type: 'custom',
    provider_priority: 100,
    keep_priority_on_conversion: false,
    enable_format_conversion: true,
    is_active: true,
    total_endpoints: 0,
    active_endpoints: 0,
    total_keys: 0,
    active_keys: 0,
    total_models: 0,
    active_models: 0,
    global_model_ids: [],
    avg_health_score: 1,
    unhealthy_endpoints: 0,
    api_formats: [],
    endpoint_health_details: [],
    ops_configured: false,
    created_at: '2026-07-26T00:00:00Z',
    updated_at: '2026-07-26T00:00:00Z',
    ...overrides,
  }
}

function mountDialog(provider?: ProviderWithEndpointsSummary | null) {
  const root = document.createElement('div')
  document.body.appendChild(root)
  const app = createApp(ProviderFormDialog, {
    modelValue: true,
    provider,
    'onUpdate:modelValue': vi.fn(),
  })
  app.mount(root)
  mountedApps.push({ app, root })
}

async function settle() {
  for (let index = 0; index < 4; index += 1) {
    await Promise.resolve()
    await nextTick()
  }
}

async function setInput(selector: string, value: string) {
  const input = document.body.querySelector<HTMLInputElement>(selector)
  if (!input) throw new Error(`Missing input: ${selector}`)
  input.value = value
  input.dispatchEvent(new Event('input', { bubbles: true }))
  await nextTick()
}

function clickButton(text: string) {
  const button = [...document.body.querySelectorAll<HTMLButtonElement>('button')]
    .find(candidate => candidate.textContent?.trim() === text)
  if (!button) throw new Error(`Missing button: ${text}`)
  button.click()
}

function providerTypeSelect(targetValue: string) {
  return [...document.body.querySelectorAll<HTMLSelectElement>('select')]
    .find(select => select.querySelector(`option[value="${targetValue}"]`))
}

beforeEach(() => {
  endpointMocks.createProvider.mockReset()
  endpointMocks.createProvider.mockResolvedValue({ id: 'provider-new', name: 'New Provider' })
  endpointMocks.updateProvider.mockReset()
  endpointMocks.updateProvider.mockResolvedValue(makeProvider())
})

afterEach(() => {
  for (const { app, root } of mountedApps.splice(0)) {
    app.unmount()
    root.remove()
  }
  document.body.innerHTML = ''
})

describe('ProviderFormDialog AMD pool mode', () => {
  it('hides the pool switch for an AMD provider and never submits pool_advanced', async () => {
    mountDialog(makeProvider({ provider_type: 'amd', pool_advanced: {} }))
    await settle()

    expect(document.body.textContent).not.toContain(POOL_MODE_LABEL)

    clickButton('保存')
    await settle()

    expect(endpointMocks.updateProvider).toHaveBeenCalledWith(
      'provider-1',
      expect.objectContaining({
        provider_type: 'amd',
        pool_advanced: null,
      }),
    )
  })

  it('keeps the pool switch for other provider types and preserves the config', async () => {
    mountDialog(makeProvider({ provider_type: 'custom', pool_advanced: {} }))
    await settle()

    expect(document.body.textContent).toContain(POOL_MODE_LABEL)

    clickButton('保存')
    await settle()

    const payload = endpointMocks.updateProvider.mock.calls[0]?.[1]
    expect(payload).toEqual(expect.objectContaining({ pool_advanced: {} }))
  })

  it('clears the switch after switching to AMD in the create dialog', async () => {
    mountDialog(null)
    await settle()

    const select = providerTypeSelect('amd')
    if (!select) throw new Error('Missing provider type select')
    expect(document.body.textContent).toContain(POOL_MODE_LABEL)

    select.value = 'amd'
    select.dispatchEvent(new Event('change', { bubbles: true }))
    await nextTick()

    expect(document.body.textContent).not.toContain(POOL_MODE_LABEL)

    await setInput('#name', 'AMD Provider')
    clickButton('创建')
    await settle()

    expect(endpointMocks.createProvider).toHaveBeenCalledWith(
      expect.objectContaining({
        provider_type: 'amd',
        pool_advanced: null,
      }),
    )
  })
})
