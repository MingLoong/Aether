import { afterEach, describe, expect, it } from 'vitest'
import { createApp, h, type App } from 'vue'

import UsageModelDisplay from '../UsageModelDisplay.vue'

/**
 * 这群用例钉住的是「同一个模型名不要显示三遍」这条规则。
 *
 * 用量记录里模型名有三个来源：客户端请求的、我们映射过去的、上游回报的。三者经常
 * 是同一个名字的不同写法（大小写、前后空白，或者 amd 那类会把请求名规范化后回显），
 * 逐行并排显示只会让人以为发生了三次映射。规则本身是纯逻辑，所以这里只断言 DOM：
 * 主名字、`映射模型` 行、`响应模型` 行分别出现还是消失。
 */
const mountedApps: Array<{ app: App, root: HTMLElement }> = []

afterEach(() => {
  for (const { app, root } of mountedApps.splice(0)) {
    app.unmount()
    root.remove()
  }
})

function mountDisplay(record: {
  model: string
  target_model?: string | null
  response_model?: string | null
}): HTMLElement {
  const root = document.createElement('div')
  document.body.appendChild(root)
  const app = createApp({
    render: () => h(UsageModelDisplay, { record }),
  })
  app.mount(root)
  mountedApps.push({ app, root })
  return root
}

function textOf(root: HTMLElement, selector: string): string | null {
  return root.querySelector(selector)?.textContent?.trim() ?? null
}

describe('UsageModelDisplay 模型名去重', () => {
  it('请求名与映射名只有大小写差异时，主名字用规范名且不再单列映射行', () => {
    // amd 会把请求模型名规范化后作为映射名回显，对调用方来说是同一个模型。
    const root = mountDisplay({
      model: 'deepseek-v4-flash-vision-exp',
      target_model: 'DeepSeek-V4-Flash-Vision-Exp',
    })

    expect(textOf(root, '[data-usage-model-source]')).toBe('DeepSeek-V4-Flash-Vision-Exp')
    expect(root.querySelector('[data-usage-model-mapping]')).toBeNull()
    expect(root.querySelector('[data-usage-model-response]')).toBeNull()
    // 一条事实都没有时不该渲染事实区。
    expect(root.querySelector('[data-usage-model-facts]')).toBeNull()
  })

  it('真正不同的映射名仍然单独显示一行', () => {
    const root = mountDisplay({
      model: 'gpt-4o',
      target_model: 'openai/gpt-4o-2024-08-06',
    })

    expect(textOf(root, '[data-usage-model-source]')).toBe('gpt-4o')
    expect(textOf(root, '[data-usage-model-mapping]')).toContain('openai/gpt-4o-2024-08-06')
    expect(root.querySelector('[data-usage-model-response]')).toBeNull()
  })

  it('响应模型与请求模型只有大小写差异时不显示响应行', () => {
    const root = mountDisplay({
      model: 'MiniCPM5-2B',
      response_model: 'minicpm5-2b',
    })

    expect(textOf(root, '[data-usage-model-source]')).toBe('MiniCPM5-2B')
    expect(root.querySelector('[data-usage-model-response]')).toBeNull()
  })

  it('响应模型等于映射模型时只保留映射行，避免同一份事实写两遍', () => {
    const root = mountDisplay({
      model: 'minicpm5-2b',
      target_model: 'self-dploy/MiniCPM5-2B',
      response_model: 'self-dploy/MiniCPM5-2B',
    })

    expect(textOf(root, '[data-usage-model-source]')).toBe('minicpm5-2b')
    expect(textOf(root, '[data-usage-model-mapping]')).toContain('self-dploy/MiniCPM5-2B')
    expect(root.querySelector('[data-usage-model-response]')).toBeNull()
  })

  it('三方都不同时三行信息都在（去重不能把真事实吃掉）', () => {
    const root = mountDisplay({
      model: 'minicpm5-2b',
      target_model: 'self-dploy/MiniCPM5-2B',
      response_model: 'self-dploy/MiniCPM5-2B-8bit',
    })

    expect(textOf(root, '[data-usage-model-source]')).toBe('minicpm5-2b')
    expect(textOf(root, '[data-usage-model-mapping]')).toContain('self-dploy/MiniCPM5-2B')
    expect(textOf(root, '[data-usage-model-response]')).toContain('self-dploy/MiniCPM5-2B-8bit')
    expect(root.querySelector('[data-usage-model-facts]')).not.toBeNull()
  })

  it('前后空白与空串按「没有这个事实」处理', () => {
    const root = mountDisplay({
      model: '  gpt-4o  ',
      target_model: '   ',
      response_model: '',
    })

    expect(textOf(root, '[data-usage-model-source]')).toBe('gpt-4o')
    expect(root.querySelector('[data-usage-model-mapping]')).toBeNull()
    expect(root.querySelector('[data-usage-model-response]')).toBeNull()
    expect(root.querySelector('[data-usage-model-facts]')).toBeNull()
  })
})
