import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest'
import { createApp, defineComponent, h, nextTick, reactive, type App } from 'vue'

import WorkbuddyUpstreamPanels from '../WorkbuddyUpstreamPanels.vue'
import { createI18n } from '@/i18n'
import type { EndpointAPIKey, Model, ProviderWithEndpointsSummary } from '@/api/endpoints'

/**
 * 「导入状态」列的行为契约：
 *  - 目录里**未导入**的模型必须给「导入」按钮（此前只有一个静态标签，没有入口）；
 *  - **已导入**的行不给按钮；
 *  - 点按钮 → 按 `model_uid` 调用导入接口（同名跨域**去重**）→ 成功后 emit('refresh')；
 *  - 卡片头部的批量按钮只在「有未导入模型」时出现。
 */

const modelMocks = vi.hoisted(() => ({
  importModelsFromUpstream: vi.fn(),
}))

const toastMocks = vi.hoisted(() => ({
  success: vi.fn(),
  error: vi.fn(),
}))

vi.mock('@/api/endpoints/models', () => modelMocks)
vi.mock('@/composables/useToast', () => ({
  useToast: () => toastMocks,
}))

// 账号目录：面板发现某账号没有上游目录快照时会自动补拉（走这个 composable）。
const catalogMocks = vi.hoisted(() => ({
  fetchModels: vi.fn(),
}))
vi.mock('@/features/providers/composables/useUpstreamModelsCache', () => ({
  useUpstreamModelsCache: () => ({ fetchModels: catalogMocks.fetchModels }),
}))

const mountedApps: Array<{ app: App, root: HTMLElement }> = []

function createProvider(): ProviderWithEndpointsSummary {
  return {
    id: 'provider-wb',
    name: 'WorkBuddy',
    provider_type: 'workbuddy',
  } as unknown as ProviderWithEndpointsSummary
}

function createKey(
  models: Array<Record<string, unknown>>,
  realm = 'cn',
): EndpointAPIKey {
  return {
    id: `key-${realm}`,
    is_active: true,
    upstream_metadata: { workbuddy: { realm, models } },
  } as unknown as EndpointAPIKey
}

function createImportedModel(providerModelName: string): Model {
  return { provider_model_name: providerModelName } as unknown as Model
}

async function settle() {
  for (let index = 0; index < 5; index += 1) {
    await Promise.resolve()
    await nextTick()
  }
}

function mountPanel(options?: { models?: Model[]; keys?: EndpointAPIKey[] }) {
  const root = document.createElement('div')
  document.body.appendChild(root)
  const onRefresh = vi.fn()
  const state = reactive({
    models: options?.models ?? [],
    keys: options?.keys ?? [],
  })
  const app = createApp(defineComponent({
    setup() {
      return () => h(WorkbuddyUpstreamPanels, {
        provider: createProvider(),
        models: state.models,
        providerKeys: state.keys,
        onRefresh,
      })
    },
  }))
  app.use(createI18n())
  app.mount(root)
  mountedApps.push({ app, root })
  return { root, state, onRefresh }
}

/** 定位「上游模型能力与倍率」表里某域某模型那一行（两个域可能出现同名模型）。 */
function catalogRow(root: HTMLElement, realm: string, modelUid: string): HTMLTableRowElement {
  const realmText = realm === 'cn' ? '国内' : '国际'
  const row = Array.from(root.querySelectorAll('tbody tr')).find((candidate) => {
    const text = candidate.textContent ?? ''
    return text.includes(modelUid) && text.includes(realmText)
  })
  if (!row) throw new Error(`找不到目录行 ${realm}:${modelUid}`)
  return row as HTMLTableRowElement
}

/** 「导入状态」列（最后一列）里的按钮；已导入行没有按钮。 */
function importButtonOf(row: HTMLTableRowElement): HTMLButtonElement | null {
  const cells = row.querySelectorAll('td')
  return cells[cells.length - 1]?.querySelector('button') ?? null
}

/**
 * 卡片头部那个批量导入按钮（未导入数为 0 时不应存在）。
 *
 * 必须按 `data-testid` 精确取：头部还有一个「强制刷新目录」按钮，
 * 早先「取 tbody 之外第一个 button」的写法会误命中它，导致断言假失败。
 */
function bulkImportButton(root: HTMLElement): HTMLButtonElement | null {
  return root.querySelector<HTMLButtonElement>('[data-testid="workbuddy-bulk-import"]')
}

async function click(button: HTMLButtonElement) {
  button.dispatchEvent(new MouseEvent('click', { bubbles: true }))
  await settle()
}

beforeEach(() => {
  modelMocks.importModelsFromUpstream.mockReset()
  modelMocks.importModelsFromUpstream.mockResolvedValue({
    success: [{ model_id: 'kimi-k3' }],
    errors: [],
  })
  toastMocks.success.mockReset()
  toastMocks.error.mockReset()
  catalogMocks.fetchModels.mockReset()
  catalogMocks.fetchModels.mockResolvedValue({ models: [{ id: 'glm-5.2' }] })
})

afterEach(() => {
  for (const { app, root } of mountedApps.splice(0)) {
    app.unmount()
    root.remove()
  }
})

describe('WorkbuddyUpstreamPanels 导入状态', () => {
  it('未导入的模型有导入按钮，已导入的没有', async () => {
    mountPanel({
      models: [createImportedModel('glm-5.2')],
      keys: [
        createKey([
          { model_uid: 'glm-5.2', label: 'GLM-5.2' },
          { model_uid: 'kimi-k3', label: 'Kimi K3' },
        ]),
      ],
    })
    await settle()
    const importedRow = catalogRow(document.body, 'cn', 'glm-5.2')
    const pendingRow = catalogRow(document.body, 'cn', 'kimi-k3')

    expect(importButtonOf(importedRow)).toBeNull()
    expect(importButtonOf(pendingRow)).not.toBeNull()
  })

  it('点行内导入 → 按模型名调用导入接口并请求父组件重载', async () => {
    const { root, onRefresh } = mountPanel({
      models: [],
      keys: [createKey([{ model_uid: 'kimi-k3' }])],
    })
    await settle()
    const button = importButtonOf(catalogRow(root, 'cn', 'kimi-k3'))
    expect(button).not.toBeNull()

    await click(button as HTMLButtonElement)

    expect(modelMocks.importModelsFromUpstream).toHaveBeenCalledTimes(1)
    expect(modelMocks.importModelsFromUpstream).toHaveBeenCalledWith('provider-wb', ['kimi-k3'])
    expect(toastMocks.success).toHaveBeenCalled()
    expect(onRefresh).toHaveBeenCalledTimes(1)
  })

  it('同名模型跨域只提交一次（按 model_uid 去重）', async () => {
    const { root } = mountPanel({
      models: [],
      keys: [
        createKey([{ model_uid: 'glm-5.2' }], 'cn'),
        createKey([{ model_uid: 'glm-5.2' }], 'global'),
      ],
    })
    await settle()
    const bulk = bulkImportButton(root)
    expect(bulk).not.toBeNull()

    await click(bulk as HTMLButtonElement)

    expect(modelMocks.importModelsFromUpstream).toHaveBeenCalledWith('provider-wb', ['glm-5.2'])
  })

  it('全部已导入时不显示批量导入按钮', async () => {
    const { root } = mountPanel({
      models: [createImportedModel('glm-5.2')],
      keys: [createKey([{ model_uid: 'glm-5.2' }])],
    })
    await settle()
    expect(bulkImportButton(root)).toBeNull()
  })

  it('导入接口报错时提示失败（且不抛到渲染层）', async () => {
    modelMocks.importModelsFromUpstream.mockResolvedValue({
      success: [],
      errors: [{ model_id: 'kimi-k3', error: 'upstream said no' }],
    })
    const { root } = mountPanel({
      models: [],
      keys: [createKey([{ model_uid: 'kimi-k3' }])],
    })
    await settle()

    await click(importButtonOf(catalogRow(root, 'cn', 'kimi-k3')) as HTMLButtonElement)

    expect(toastMocks.error).toHaveBeenCalledWith('upstream said no', expect.anything())
  })
})

/**
 * 模型格子第二行：上游 `worker` 的 `vendor` 实测是**单字母内部代码**
 * （e=GLM 家族 / f=DeepSeek·Kimi·MiniMax·Step / j=混元）——不该当厂牌名展示。
 */
describe('WorkbuddyUpstreamPanels 模型行副标题', () => {
  function subtitleOf(row: HTMLTableRowElement): HTMLElement | null {
    return row.querySelector('div.font-mono')
  }

  it('上游单字母厂牌代码不展示，但挂在 title 上仍可查', async () => {
    const { root } = mountPanel({
      models: [],
      keys: [createKey([{ model_uid: 'auto', label: 'Auto', vendor: 'f', is_default: true }])],
    })
    await settle()
    const subtitle = subtitleOf(catalogRow(root, 'cn', 'auto'))

    expect(subtitle?.textContent?.trim()).toBe('auto')
    expect(subtitle?.getAttribute('title')).toContain('上游厂牌代码：f')
  })

  it('上游给了可读厂牌名时照常展示', async () => {
    const { root } = mountPanel({
      models: [],
      keys: [createKey([{ model_uid: 'kimi-k3-1', vendor: 'moonshot' }])],
    })
    await settle()
    const subtitle = subtitleOf(catalogRow(root, 'cn', 'kimi-k3-1'))

    expect(subtitle?.textContent?.trim()).toBe('kimi-k3-1 · moonshot')
    expect(subtitle?.getAttribute('title')).toBe('kimi-k3-1 · moonshot')
  })
})

/**
 * 倍率展示：上游 0 倍率有 `x0.00`（前缀式）与 `0x`（后缀式）两种写法 —— 展示层要归一到
 * 「免费」，且**原价本来就是 0 时不得划删除线**（此前 hy3 显示成 `0x` + 划掉的 `x0.00`，
 * 看着像坏了）。
 */
describe('WorkbuddyUpstreamPanels 倍率展示', () => {
  /** 列顺序：域 | 模型 | 倍率 | 上下文/输出 | 能力 | 导入状态 */
  function multiplierCell(row: HTMLTableRowElement): HTMLElement {
    return row.querySelectorAll('td')[2] as HTMLElement
  }

  it('上游 0 倍率（牌价 x0.00 + 折后 0x）显示「免费」，且不划原价', async () => {
    const { root } = mountPanel({
      models: [],
      keys: [createKey([{
        model_uid: 'hy3',
        credits: 'x0.00',
        promo_factor: 0,
        promo_credits: '0x',
        promo_label: '限时免费',
        promo_note: '7月6日–10月31日，每日赠送免费额度。',
      }])],
    })
    await settle()
    const cell = multiplierCell(catalogRow(root, 'cn', 'hy3'))

    // 生效价那一格（第一个 span）就是「免费」
    expect(cell.querySelector('span')?.textContent?.trim()).toBe('免费')
    expect(cell.textContent).toContain('限时免费')
    expect(cell.querySelector('.line-through')).toBeNull()

    // 展示层归一了，但上游原始串不丢：悬浮提示里能核对到
    const title = cell.querySelector('[title]')?.getAttribute('title') ?? ''
    expect(title).toContain('上游牌价 x0.00')
    expect(title).toContain('上游折后价 0x')
  })

  it('原价非 0 的限免：显示「免费」+ 划掉的原价', async () => {
    const { root } = mountPanel({
      models: [],
      keys: [createKey([{
        model_uid: 'step-5-preview',
        credits: 'x0.43',
        promo_factor: 0,
        promo_credits: '0x',
        promo_label: '独家限免',
      }])],
    })
    await settle()
    const cell = multiplierCell(catalogRow(root, 'cn', 'step-5-preview'))

    expect(cell.querySelector('span')?.textContent?.trim()).toBe('免费')
    expect(cell.querySelector('.line-through')?.textContent?.trim()).toBe('×0.43')
  })

  it('普通倍率照常显示 ×N（上游两种写法都归一）', async () => {
    const { root } = mountPanel({
      models: [],
      keys: [createKey([
        { model_uid: 'glm-5.3', credits: 'x1.62' },
        { model_uid: 'kimi-k3-1', credits: '0.50x' },
      ])],
    })
    await settle()

    expect(multiplierCell(catalogRow(root, 'cn', 'glm-5.3')).textContent?.trim()).toBe('×1.62')
    expect(multiplierCell(catalogRow(root, 'cn', 'kimi-k3-1')).textContent?.trim()).toBe('×0.50')
  })
})

/**
 * 账号目录：上游模型目录是**按 key 拉**的 —— 走过登录流程的账号有目录 ✓，
 * 而**导入凭据**进来的账号没有 ✗，于是面板上那个域一个模型都不显示
 * （用户实测：导入国际号后只看到国内模型）。所以面板打开时自动补拉一次 ✓。
 */
describe('WorkbuddyUpstreamPanels 账号目录自动补拉', () => {
  function fetchCatalogButton(root: HTMLElement): HTMLButtonElement | null {
    return root.querySelector('[data-testid="workbuddy-fetch-catalog"]')
  }

  it('账号没有目录快照 → 自动补拉一次并请求父组件刷新', async () => {
    const { onRefresh } = mountPanel({ models: [], keys: [createKey([])] })
    await settle()

    expect(catalogMocks.fetchModels).toHaveBeenCalledTimes(1)
    expect(catalogMocks.fetchModels).toHaveBeenCalledWith('provider-wb', 'key-cn', true)
    expect(onRefresh).toHaveBeenCalledTimes(1)
  })

  it('已有目录快照的账号不触发补拉，也不显示按钮', async () => {
    const { root } = mountPanel({
      models: [],
      keys: [createKey([{ model_uid: 'glm-5.2' }])],
    })
    await settle()

    expect(catalogMocks.fetchModels).not.toHaveBeenCalled()
    expect(fetchCatalogButton(root)).toBeNull()
  })

  it('补拉失败：不请求刷新，并留下可手动重试的按钮', async () => {
    catalogMocks.fetchModels.mockResolvedValue({ models: [], error: 'boom' })
    const { root, onRefresh } = mountPanel({
      models: [],
      keys: [createKey([]), createKey([], 'global')],
    })
    await settle()

    // 两个账号各补一次
    expect(catalogMocks.fetchModels).toHaveBeenCalledTimes(2)
    expect(onRefresh).not.toHaveBeenCalled()
    expect(fetchCatalogButton(root)).not.toBeNull()
  })
})
