import { describe, expect, it, vi } from 'vitest'
import { createApp, defineComponent, h, nextTick, type App } from 'vue'

/**
 * OpenCodeContextRetryPanel 的行为测试。
 *
 * 这个面板跟别的设置不一样：它不写 provider config，而是**就地读写系统默认路由组**
 * 的 `default_policy.opencode_context_retry`。所以测试重点在
 * 「读到的值对不对」「保存时有没有只改这一个字段、并把 version 带上」。
 */

const groups = new Map<string, Record<string, unknown>>()

vi.mock('@/api/routing-profiles', () => ({
  listRoutingGroups: vi.fn(async () => ({
    items: [...groups.values()].map(group => ({
      id: group.id,
      name: group.name,
      is_system_default: group.is_system_default,
      config_json: group.config_json,
      version: group.version,
    })),
    total: groups.size,
  })),
  getRoutingGroup: vi.fn(async (id: string) => {
    const group = groups.get(id)
    if (!group) throw new Error('missing group')
    return group
  }),
  updateRoutingGroup: vi.fn(async (id: string, body: { config_json: unknown, expected_version: number }) => {
    const group = groups.get(id)
    if (!group) throw new Error('missing group')
    const updated = {
      ...group,
      config_json: body.config_json,
      version: body.expected_version + 1,
    }
    groups.set(id, updated)
    return updated
  }),
}))

vi.mock('@/i18n', async importOriginal => {
  // 只替换 legacyT：全局 setup 还要用 setI18nLocale，整块 mock 会把它弄丢。
  const actual = await importOriginal<typeof import('@/i18n')>()
  return {
    ...actual,
    useI18n: () => ({ ...actual.useI18n(), legacyT: (value: string) => value }),
  }
})

const mounted: App[] = []

function seedGroup(defaultPolicy: Record<string, unknown> | undefined) {
  groups.clear()
  groups.set('group-1', {
    id: 'group-1',
    name: '负载均衡',
    is_system_default: true,
    version: 7,
    config_json: { default_policy: defaultPolicy ?? {} },
  })
}

async function mount(): Promise<{ root: HTMLElement, unmount: () => void }> {
  const { default: Panel } = await import('../OpenCodeContextRetryPanel.vue')
  const host = document.createElement('div')
  document.body.appendChild(host)
  const app = createApp(defineComponent({ render: () => h(Panel) }))
  app.mount(host)
  mounted.push(app)
  // onMounted 里发了异步请求，等它落地。
  await new Promise(resolve => setTimeout(resolve, 0))
  await nextTick()
  return {
    root: host,
    unmount: () => {
      app.unmount()
      host.remove()
    },
  }
}

function byLabel<T extends HTMLElement>(root: HTMLElement, label: string): T {
  const found = root.querySelector<T>(`[aria-label="${label}"]`)
  if (!found) throw new Error(`missing control: ${label}`)
  return found
}

async function type(input: HTMLInputElement, value: string) {
  input.value = value
  input.dispatchEvent(new Event('input', { bubbles: true }))
  await nextTick()
}

describe('OpenCodeContextRetryPanel', () => {
  it('reads the ladder from the system default routing group', async () => {
    seedGroup({ opencode_context_retry: { enabled: true, base_ms: 3000, multiplier: 3, max_ms: 20000 } })
    const { root, unmount } = await mount()
    expect(byLabel<HTMLInputElement>(root, 'OpenCode 首次延迟').value).toBe('3000')
    expect(byLabel<HTMLInputElement>(root, 'OpenCode 倍增倍数').value).toBe('3')
    expect(byLabel<HTMLInputElement>(root, 'OpenCode 最大延迟').value).toBe('20000')
    // 3s → 9s → 20s（封顶）
    expect(root.textContent).toContain('3s → 9s → 20s')
    unmount()
  })

  it('falls back to the documented default when the group has no value', async () => {
    seedGroup({})
    const { root, unmount } = await mount()
    expect(byLabel<HTMLInputElement>(root, 'OpenCode 首次延迟').value).toBe('10000')
    expect(byLabel<HTMLInputElement>(root, 'OpenCode 倍增倍数').value).toBe('2')
    expect(byLabel<HTMLInputElement>(root, 'OpenCode 最大延迟').value).toBe('80000')
    expect(root.textContent).toContain('10s → 20s → 40s → 80s')
    unmount()
  })

  it('previews the ladder as the numbers change', async () => {
    seedGroup({ opencode_context_retry: { enabled: true, base_ms: 10000, multiplier: 2, max_ms: 80000 } })
    const { root, unmount } = await mount()
    await type(byLabel<HTMLInputElement>(root, 'OpenCode 首次延迟'), '5000')
    expect(root.textContent).toContain('5s → 10s → 20s → 40s → 80s')
    unmount()
  })

  it('disables the three inputs when the switch is off', async () => {
    seedGroup({ opencode_context_retry: { enabled: true, base_ms: 10000, multiplier: 2, max_ms: 80000 } })
    const { root, unmount } = await mount()
    expect(byLabel<HTMLInputElement>(root, 'OpenCode 首次延迟').disabled).toBe(false)
    byLabel<HTMLButtonElement>(root, 'OpenCode 上下文重试开关').click()
    await nextTick()
    expect(byLabel<HTMLInputElement>(root, 'OpenCode 首次延迟').disabled).toBe(true)
    expect(byLabel<HTMLInputElement>(root, 'OpenCode 倍增倍数').disabled).toBe(true)
    expect(byLabel<HTMLInputElement>(root, 'OpenCode 最大延迟').disabled).toBe(true)
    expect(root.textContent).toContain('已关闭')
    unmount()
  })

  it('refuses an impossible ladder instead of saving it', async () => {
    seedGroup({ opencode_context_retry: { enabled: true, base_ms: 10000, multiplier: 2, max_ms: 80000 } })
    const { root, unmount } = await mount()
    await type(byLabel<HTMLInputElement>(root, 'OpenCode 首次延迟'), '90000')
    expect(root.querySelector('[role="alert"]')?.textContent).toContain('首次延迟不能大于最大延迟')
    const save = [...root.querySelectorAll('button')]
      .find(button => button.textContent?.includes('保存重试设置'))
    expect(save?.disabled).toBe(true)
    unmount()
  })

  it('saves only opencode_context_retry and carries expected_version', async () => {
    seedGroup({
      max_transfer_count: 5,
      opencode_context_retry: { enabled: true, base_ms: 10000, multiplier: 2, max_ms: 80000 },
    })
    const { root, unmount } = await mount()
    await type(byLabel<HTMLInputElement>(root, 'OpenCode 首次延迟'), '4000')
    const save = [...root.querySelectorAll('button')]
      .find(button => button.textContent?.includes('保存重试设置'))
    save?.click()
    await new Promise(resolve => setTimeout(resolve, 0))
    await nextTick()

    const api = await import('@/api/routing-profiles')
    const call = vi.mocked(api.updateRoutingGroup).mock.calls.at(-1)
    expect(call?.[0]).toBe('group-1')
    expect(call?.[1].expected_version).toBe(7)
    const sent = call?.[1].config_json as { default_policy: Record<string, unknown> }
    expect(sent.default_policy.opencode_context_retry).toEqual({
      enabled: true,
      base_ms: 4000,
      multiplier: 2,
      max_ms: 80000,
    })
    // 同组其它字段不能被这次保存抹掉。
    expect(sent.default_policy.max_transfer_count).toBe(5)
    unmount()
  })

  it('does not enable the save button until something actually changed', async () => {
    seedGroup({ opencode_context_retry: { enabled: true, base_ms: 10000, multiplier: 2, max_ms: 80000 } })
    const { root, unmount } = await mount()
    const save = () => [...root.querySelectorAll('button')]
      .find(button => button.textContent?.includes('保存重试设置')) as HTMLButtonElement
    expect(save().disabled).toBe(true)
    await type(byLabel<HTMLInputElement>(root, 'OpenCode 倍增倍数'), '3')
    expect(save().disabled).toBe(false)
    unmount()
  })

  it('reports a missing routing group instead of showing fake defaults', async () => {
    groups.clear()
    const { root, unmount } = await mount()
    expect(root.textContent).toContain('没有可用的路由组')
    unmount()
  })
})
