import client from '../client'

/** AMD 负载感知的生效配置。字段是后端套完默认值后的值，不是用户提交的原始值。 */
export interface AmdLoadConfigView {
  enabled: boolean
  poll_sec: number
  disable_threshold: number
  recovery_threshold: number | null
  disable_streak: number
  snapshot_ttl_sec: number
  timeout_sec: number
  has_hysteresis: boolean
  effective_recovery: number
}

/** 保存用的载荷。留空的字段表示「不改」，不是「置空」。 */
export interface AmdLoadConfigPayload {
  enabled?: boolean
  poll_sec?: number
  disable_threshold?: number
  recovery_threshold?: number | null
  disable_streak?: number
  snapshot_ttl_sec?: number
  timeout_sec?: number
}

export interface AmdLoadModelStatus {
  model: string
  utilization: number
  state: string
  blocked: boolean
  streak: number
  /**
   * 落在滞回带里，沿用上轮结论。单阈值模式下不会出现。
   *
   * 这个字段是「为什么这个模型还在禁用」的答案：占用已经回落到禁用阈值以下，
   * 但还没低到恢复阈值，所以继续禁用。不显示它，用户会以为判定没生效。
   */
  in_hysteresis_band?: boolean
}

export interface AmdLoadStatus {
  config: AmdLoadConfigView
  warnings: string[]
  is_amd_upstream: boolean
  load_endpoint: string | null
  snapshot_present: boolean
  snapshot_expired: boolean
  snapshot_fetched_at: number | null
  scope: string | null
  blocked_models: string[]
  models: AmdLoadModelStatus[]
}

/** 一次轮询的摘要。注意：轮询是全体 AMD 供应商一起跑的，这是聚合值。 */
export interface AmdLoadPollSummary {
  providers_polled: number
  providers_skipped: number
  models_seen: number
  models_blocked: number
}

export interface AmdLoadRefreshResult {
  summary: AmdLoadPollSummary
  snapshot_expired: boolean
  blocked_models: string[]
}

/**
 * 取某个供应商的 AMD 负载状态：快照、生效配置与判定结果。
 */
export async function getAmdLoadStatus(providerId: string): Promise<AmdLoadStatus> {
  const response = await client.get<AmdLoadStatus>(`/api/admin/amd-load/providers/${providerId}`)
  return response.data
}

/**
 * 保存 AMD 负载配置。
 *
 * 服务端用 CAS 写入：连续撞上并发修改会返回 409（"配置正在被后台负载轮询更新，
 * 请稍后重试"），这时该重试而不是当成保存失败。
 */
export interface AmdLoadSaveResult {
  saved: boolean
  config: AmdLoadConfigView
  warnings: string[]
}

export async function saveAmdLoadConfig(
  providerId: string,
  payload: AmdLoadConfigPayload,
): Promise<AmdLoadSaveResult> {
  const response = await client.put<AmdLoadSaveResult>(
    `/api/admin/amd-load/providers/${providerId}/config`,
    payload,
  )
  return response.data
}

/**
 * 立刻拉一次负载快照。
 *
 * 后端对全体 AMD 供应商跑一轮并按 provider 限速，所以返回值里的 summary 是聚合值，
 * 不能当成「只有这个供应商被刷新了」。
 */
export async function refreshAmdLoadSnapshot(providerId: string): Promise<AmdLoadRefreshResult> {
  const response = await client.post<AmdLoadRefreshResult>(
    `/api/admin/amd-load/providers/${providerId}/refresh`,
  )
  return response.data
}