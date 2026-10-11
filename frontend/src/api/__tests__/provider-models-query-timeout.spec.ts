import { beforeEach, describe, expect, it, vi } from 'vitest'

const { postMock } = vi.hoisted(() => ({
  postMock: vi.fn(),
}))

vi.mock('@/api/client', () => ({
  default: {
    post: postMock,
  },
}))

import { adminApi } from '@/api/admin'

/** 与 admin.ts 里的常量保持一致：访问上游的模型查询必须放宽到 5 分钟。 */
const PROVIDER_MODELS_QUERY_TIMEOUT_MS = 5 * 60 * 1000

describe('adminApi provider models query timeout', () => {
  beforeEach(() => {
    postMock.mockReset()
    postMock.mockResolvedValue({ data: {} })
  })

  it('uses an extended timeout when querying a provider model list', async () => {
    await adminApi.queryProviderModels('provider-1')

    expect(postMock).toHaveBeenCalledWith(
      '/api/admin/provider-query/models',
      { provider_id: 'provider-1', api_key_id: undefined, force_refresh: false },
      { timeout: PROVIDER_MODELS_QUERY_TIMEOUT_MS },
    )
  })

  it('uses an extended timeout when querying models for specific keys', async () => {
    await adminApi.queryProviderModelsForKeys('provider-1', ['key-1', 'key-2'], true)

    expect(postMock).toHaveBeenCalledWith(
      '/api/admin/provider-query/models',
      { provider_id: 'provider-1', api_key_ids: ['key-1', 'key-2'], force_refresh: true },
      { timeout: PROVIDER_MODELS_QUERY_TIMEOUT_MS },
    )
  })
})
