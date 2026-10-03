import client from '../client'

/** AMD 负载感知的生效配置。字段是后端套完默认值后的值，不是用户提交的原始值。 */
export interface AmdLoadConfigView {
  enabled: boolean
  /**
   * 是否真的把模型挡在调度之外。默认 false：实测不支持「按负载禁用能改善首字节」，
   * 详见后端 `AmdLoadConfig::block_models`。
   */
  block_models: boolean
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

/** 一段窗口的用量统计（`today` / `last_24_hours` / `all_time` 同形）。 */
export interface AmdUsageWindowView {
  requests: number
  errors: number
  /** 0~100。请求数为 0 时后端返回 0，不是「100% 错误」。 */
  error_rate: number
  total_tokens: number
  cost: number
  kv_cache_hit_rate: number | null
  last_request_at: string | null
}

export interface AmdUsageByModelView {
  model: string
  requests: number
  errors: number
  cost: number
  /** 0~100 */
  error_rate: number
}

/**
 * 单个账号（key）的用量。
 *
 * **10 个 key 就是 10 个独立 AMD 账号**，各有独立的日限额（实测 10 个互不相同的
 * `organization_id`）。所以必须逐账号展示——只看合计就看不出「哪个账号快撞满」。
 */
export interface AmdUsageAccountView {
  key_name: string
  key_id: string
  /** 上游 organization_id，账号的真实标识。 */
  organization_id: string | null
  /** 因 organization_id 重复而未发起请求，usage 是复制来的。 */
  deduped: boolean
  /** 拉取失败原因。**此时 usage 相关字段为 null，不是 0。** */
  error: string | null
  /** 0~1，限额未知或拉取失败时为 null。 */
  usage_ratio: number | null
  daily_cost_limit_usd: number | null
  rpm_limit: number | null
  today: AmdUsageWindowView | null
  last_24_hours: AmdUsageWindowView | null
  all_time: AmdUsageWindowView | null
  /** 已按错误率降序。 */
  by_model: AmdUsageByModelView[]
  /** 死字段：上游未实现，界面不显示。 */
  daily_cost_used_usd: number | null
  daily_cost_remaining_usd: number | null
}

/**
 * 账号配额快照。
 *
 * 注意 `daily_cost_used_usd` / `daily_cost_remaining_usd` 不可信（上游未实现，
 * 10 个账号实测全部恒为 0 / 恒等于限额）。`usage_ratio` 是用 `today.cost /
 * daily_cost_limit_usd` 自己算的，不是上游给的余额。
 */
export interface AmdUsageView {
  fetched_at: number
  /** 本轮实际发起的 HTTP 请求数（去重后）。 */
  fetched_requests: number
  /** 拉取失败的账号数。 */
  failed_accounts: number
  /** 因 organization_id 重复而跳过请求的 key 数。 */
  deduped_keys: number
  /** 合计：只统计拉到数据的账号，不把「没查到」当成「没花钱」。 */
  total_today_cost: number
  total_today_requests: number
  total_today_errors: number
  /** 按 key 的配置顺序排列（稳定，不随用量变化跳来跳去）。 */
  accounts: AmdUsageAccountView[]
  /**
   * 用量比例最高的账号的 key_id，用于面板上高亮「谁最危险」。
   * 拉取失败或限额未知的账号不参与。
   */
  risky_account_key_id: string | null
  /** 上游未实现字段的说明文案。 */
  untrustworthy_fields: string[]
}

export interface AmdLoadStatus {
  config: AmdLoadConfigView
  warnings: string[]
  is_amd_upstream: boolean
  load_endpoint: string | null
  usage_endpoint: string | null
  /** 还没有抓到时为 null。 */
  usage: AmdUsageView | null
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