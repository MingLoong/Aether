import client from '../client'
import type { EndpointAPIKey, AllowedModels } from './types'
import type { QuotaStatusSnapshot } from './types'

// Re-export types for convenience
export type { EndpointAPIKey, AllowedModels }

// ---------------------------------------------------------------------------
// OpenCode 前置代理池（CDN 出口 IP 池）管理
// ---------------------------------------------------------------------------

export interface OpenCodeIpPoolStatus {
  provider_id: string
  scanning: boolean
  cleaning: boolean
  last_scan_at?: string | null
  last_scan_targets?: number
  last_scan_found?: number
  last_scan_added?: number
  last_clean_at?: string | null
  last_clean_checked?: number
  last_clean_removed?: number
  /** 长任务进度：已探 / 总数。大批量扫描要跑几十分钟，没有它面板上只会像卡死。 */
  progress_done?: number
  progress_total?: number
  progress_kind?: 'scan' | 'clean' | null
  /** 池里一共多少个锚点 IP（不含被停用/冷却的） */
  rotation_pool_size?: number
  /** 上次真正选中的锚点 IP，精确反映取模基数 */
  rotation_last_ip?: string | null
  auto_enabled?: boolean
  autoscan_effective?: boolean
  interval_hours?: number
  concurrency?: number
  /** 单轮扫描候选上限（分片大小）；候选总数超过它时按游标分多轮 */
  max_candidates_per_round?: number
  /** 生效的扫描快筛阈值（毫秒）：连接 + TLS + 响应首行超过它判死 */
  probe_max_handshake_ms?: number
  /** 阈值来源：config = 面板配置的，env = 环境变量兜底，default = 代码默认 */
  probe_max_handshake_source?: 'config' | 'env' | 'default'
  cidrs?: string[]
  proxy_domain?: string | null
  /** 用户填写过的前置代理域名（即使开关已关闭也保留，用于一键恢复） */
  saved_proxy_domain?: string | null
  /** 前置代理开关：开启时请求使用 saved_proxy_domain，关闭时用默认官方地址 */
  pool_source?: 'provider' | 'key'
  exit_pool?: string[]
  exit_pool_disabled?: string[]
  proxy_enabled?: boolean
  original_domain?: string | null
  /** 是否启用「记住上次 +1」的出口 IP 轮转 */
  rotation_enabled?: boolean
  rotation_effective?: boolean
  /** 额度耗尽后的冷却时长（分钟） */
  cooldown_minutes?: number
  /** 当前轮转游标：每命中一次 +1 */
  rotation_cursor?: number
  pool_ips?: Array<{ key_id: string; ip: string; is_active: boolean }>

  // ---- 验健康（与扫描分开的两套状态与调度）------------------------------
  verifying?: boolean
  last_verify_at?: string | null
  last_verify_checked?: number
  last_verify_kept?: number
  last_verify_dropped?: number
  /** 复验的进度独立于扫描：两个任务共用一组数字会互相覆盖 */
  verify_progress_done?: number
  verify_progress_total?: number
  /**
   * 本轮待验的 IP 数。`verify_progress_total` 是「IP 数 × 每 IP 采样次数」
   * （337 × 3 = 1011），单独摆出来会被读成有一千多个 IP，所以另给这一项。
   */
  verify_targets?: number
  auto_verify_enabled?: boolean
  autoverify_effective?: boolean
  verify_interval_hours?: number
  verify_samples?: number
  verify_max_median_ms?: number
  /** 保底池大小：低于此值不做任何淘汰 */
  min_pool_size?: number

  // ---- 分层计数：候选 / 健康 / 在用 -------------------------------------
  candidate_count?: number
  healthy_count?: number
  in_use_count?: number
  degraded_count?: number
  healthy?: string[]
  candidates?: string[]
  pinned?: string[]
  degraded?: string[]
  healthy_prev_count?: number
  /** 逐节点首字节中位数（毫秒）——没有它就看不出池里混进了慢节点 */
  latencies?: Record<string, number>
  // ---- 四态：候选 / 可用 / 异常 / 丢弃（2026-10 起替代 rejections）-------
  /**
   * 异常池：有嫌疑、**立刻不用**但仍在跟踪的节点。
   *
   * 出路只有两条：复验通过 → 回到 `healthy`（`fails` 清零），或连续 ≥2 轮不过 →
   * 被丢弃（删记录）。计数每个复验轮最多加一，所以 `fails >= 2` 天然等价于「跨轮」。
   */
  abnormal?: Array<{
    ip: string
    /** 首次进入异常池的时间（RFC3339）；不会被每轮复验刷新 */
    since: string
    fails: number
    /** `unreachable` / `partial_timeout` / `too_slow` */
    reason: string
    median_ms?: number | null
  }>
  abnormal_count?: number
  /** 人工拉黑：请求路径永远跳过，复验也不放回（可解禁） */
  blocked?: string[]
  blocked_count?: number
  /** 丢弃留痕：只展示，回答「它为什么总是出现又消失」 */
  discarded_recent?: Array<{
    ip: string
    /** 最近一次被丢弃的时间（RFC3339） */
    at: string
    reason: string
    /** 累计被丢弃次数（含本次） */
    times: number
  }>
  discarded_count?: number
  /**
   * 可用池骤缩告警：一轮复验把可用池砍掉一半以上时后端给出的告警文本
   * （形如 `pool_shrunk_by_verify(before=10,after=4)`）。`null` 表示正常。
   */
  pool_shrink_alarm?: string | null
  /**
   * 运行时证据：窗口（1 小时）内每个**池内**节点的失败次数、可疑原因与是否在冷却中。
   *
   * 后端只回传「有失败计数」的节点（健康节点一次 Redis 往返就跳过），所以这里没有
   * 的 IP 就是干净的。它回答的是「它刚刚为什么被跳过」——`fails` 到 3 会写一份
   * 20 分钟的 `suspect` 冷却，于是选择路径下一轮就绕开它。
   */
  runtime_evidence?: Array<{
    ip: string
    fails: number
    suspect_reason?: string | null
    cooling: boolean
  }>

  // ---- 规模自适应：自动降级的原因必须可见 --------------------------------
  session_sticky_enabled?: boolean
  session_sticky_active?: boolean
  /** 例：`pool_below_min(3<10)` 或 `disabled_by_operator` */
  session_sticky_disabled_reason?: string | null
  passive_degrade_enabled?: boolean
  passive_degrade_active?: boolean
  passive_degrade_disabled_reason?: string | null
  /**
   * 被动降权的首字节阈值（毫秒）与冷却时长（分钟）。后端给的是**生效值**
   * （已套用默认值），不是原始配置，所以界面上显示的就是真正在判定用的那个数。
   * 阈值不允许低于下限：线上 15 万 token 的正常流式请求首字节最长 12980 ms，
   * 调到 10 秒会让它们把自己的节点判成慢节点。
   */
  passive_degrade_first_byte_ms?: number
  passive_degrade_cooldown_minutes?: number
  pool_below_floor?: boolean
  pool_empty?: boolean
}

export interface OpenCodeIpPoolConfigPayload {
  cidrs?: string[]
  auto_enabled?: boolean
  interval_hours?: number
  concurrency?: number
  /** 单轮扫描候选上限（1–65536）；默认 4096 */
  max_candidates_per_round?: number
  /** 扫描快筛阈值（100–60000 毫秒）；不传时用环境变量，再退回默认 600 */
  probe_max_handshake_ms?: number
  /** 可选：更新前置代理域名（替换该供应商全部端点 base_url 的 host） */
  proxy_domain?: string
  /** 是否启用出口 IP 轮转 */
  rotation_enabled?: boolean
  /** 额度耗尽后的冷却时长（分钟） */
  cooldown_minutes?: number
  /** 前置代理开关 */
  pool_source?: 'provider' | 'key'
  exit_pool?: string[]
  exit_pool_disabled?: string[]
  proxy_enabled?: boolean
  /** 长任务进度：已探 / 总数 */
  progress_done?: number
  progress_total?: number
  progress_kind?: 'scan' | 'clean' | null
  /** 验健康域，与扫描域分开：两者不能互相覆盖 */
  opencode_health?: {
    auto_verify_enabled?: boolean
    verify_interval_hours?: number
    verify_max_median_ms?: number
    min_pool_size?: number
    session_sticky_enabled?: boolean
    passive_degrade_enabled?: boolean
    /** 首字节阈值（毫秒）。下限 15000，只能调高。 */
    passive_degrade_first_byte_ms?: number
    /** 冷却时长（分钟），1–1440。 */
    passive_degrade_cooldown_minutes?: number
  }
}

export async function getOpenCodeIpPoolStatus(providerId: string): Promise<OpenCodeIpPoolStatus> {
  const response = await client.get<OpenCodeIpPoolStatus>(
    `/api/admin/opencode-ip-pool/providers/${providerId}`,
  )
  return response.data
}

export async function saveOpenCodeIpPoolConfig(
  providerId: string,
  payload: OpenCodeIpPoolConfigPayload,
): Promise<{ provider_id: string; saved: boolean; proxy_domain_changed: number }> {
  const response = await client.put<{
    provider_id: string
    saved: boolean
    proxy_domain_changed: number
  }>(`/api/admin/opencode-ip-pool/providers/${providerId}/config`, payload)
  return response.data
}

/** 启动扫描。后端立刻 202 受理，真实结果用 `getOpenCodeIpPoolStatus` 轮询。 */
export async function runOpenCodeIpPoolScan(providerId: string): Promise<{
  provider_id: string
  started: boolean
  scanning: boolean
}> {
  const response = await client.post<{ provider_id: string; started: boolean; scanning: boolean }>(
    `/api/admin/opencode-ip-pool/providers/${providerId}/scan`,
  )
  return response.data
}

/**
 * 启动复验健康。后端立刻 202 受理，真实结果用 `getOpenCodeIpPoolStatus` 轮询。
 *
 * 与扫描分开：扫描产出候选（允许脏），复验产出生产使用的可信集合。
 */
export async function runOpenCodeIpPoolVerify(providerId: string): Promise<{
  provider_id: string
  started: boolean
  verifying: boolean
}> {
  const response = await client.post<{
    provider_id: string
    started: boolean
    verifying: boolean
  }>(`/api/admin/opencode-ip-pool/providers/${providerId}/verify`)
  return response.data
}

/** 启动清理。后端立刻 202 受理，真实结果用 `getOpenCodeIpPoolStatus` 轮询。 */
export async function runOpenCodeIpPoolClean(providerId: string): Promise<{
  provider_id: string
  started: boolean
  cleaning: boolean
}> {
  const response = await client.post<{ provider_id: string; started: boolean; cleaning: boolean }>(
    `/api/admin/opencode-ip-pool/providers/${providerId}/clean`,
  )
  return response.data
}

export async function restoreOpenCodeOriginalBaseUrl(providerId: string): Promise<{
  provider_id: string
  changed: number
  errors: string[]
}> {
  const response = await client.post<{
    provider_id: string
    changed: number
    errors: string[]
  }>(`/api/admin/opencode-ip-pool/providers/${providerId}/restore-original`)
  return response.data
}

interface KeyRequestOptions {
  timeout?: number
}

/**
 * 能力定义类型
 */
export interface CapabilityDefinition {
  name: string
  display_name: string
  description: string
  match_mode: 'exclusive' | 'compatible'
  config_mode?: 'user_configurable' | 'auto_detect' | 'request_param'
  short_name?: string
}

/**
 * 模型支持的能力响应类型
 */
export interface ModelCapabilitiesResponse {
  model: string
  global_model_id?: string
  global_model_name?: string
  supported_capabilities: string[]
  capability_details: CapabilityDefinition[]
  error?: string
}

/**
 * 获取所有能力定义
 */
export async function getAllCapabilities(): Promise<CapabilityDefinition[]> {
  const response = await client.get<{ capabilities: CapabilityDefinition[] }>('/api/capabilities')
  return response.data.capabilities
}

/**
 * 获取用户可配置的能力列表
 */
export async function getUserConfigurableCapabilities(): Promise<CapabilityDefinition[]> {
  const response = await client.get<{ capabilities: CapabilityDefinition[] }>('/api/capabilities/user-configurable')
  return response.data.capabilities
}

/**
 * 获取指定模型支持的能力列表
 */
export async function getModelCapabilities(modelName: string): Promise<ModelCapabilitiesResponse> {
  const response = await client.get<ModelCapabilitiesResponse>(`/api/capabilities/model/${encodeURIComponent(modelName)}`)
  return response.data
}

/**
 * 获取完整的 API Key（用于查看和复制）
 */
export interface RevealKeyResult {
  auth_type: 'api_key' | 'service_account' | 'oauth' | 'bearer'
  api_key?: string
  refresh_token?: string
  auth_config?: string | Record<string, unknown>
}

export async function revealEndpointKey(keyId: string): Promise<RevealKeyResult> {
  const response = await client.get<RevealKeyResult>(`/api/admin/endpoints/keys/${keyId}/reveal`)
  return response.data
}

/**
 * 导出 OAuth Key 凭据（扁平 JSON，用于跨实例迁移）
 */
export async function exportKey(keyId: string): Promise<Record<string, unknown>> {
  const response = await client.get<Record<string, unknown>>(`/api/admin/endpoints/keys/${keyId}/export`)
  return response.data
}

/**
 * 删除 Key
 */
export async function deleteEndpointKey(keyId: string): Promise<{ message: string }> {
  const response = await client.delete<{ message: string }>(`/api/admin/endpoints/keys/${keyId}`)
  return response.data
}

/**
 * 批量删除 Keys
 */
export interface BatchDeleteKeysResult {
  success_count: number
  failed_count: number
  failed: Array<{ id: string; error: string }>
}

export async function batchDeleteEndpointKeys(ids: string[]): Promise<BatchDeleteKeysResult> {
  const response = await client.post<BatchDeleteKeysResult>('/api/admin/endpoints/keys/batch-delete', { ids })
  return response.data
}


// ========== Provider 级别的 Keys API ==========


/**
 * 获取 Provider 的所有 Keys
 */
export interface ProviderKeysPageResponse {
  total: number
  page: number
  page_size: number
  keys: EndpointAPIKey[]
}

export interface ProviderKeysPageQuery {
  page?: number
  page_size?: number
}

type ProviderKeysPagePayload = ProviderKeysPageResponse | EndpointAPIKey[]

function normalizeProviderKeysPage(
  value: ProviderKeysPagePayload,
  page: number,
  pageSize: number,
): ProviderKeysPageResponse {
  if (Array.isArray(value)) {
    const start = value.length > pageSize ? (page - 1) * pageSize : 0
    const keys = value.slice(start, start + pageSize)
    return {
      total: value.length,
      page,
      page_size: pageSize,
      keys,
    }
  }

  const keys = Array.isArray(value.keys) ? value.keys : []
  return {
    total: typeof value.total === 'number' && Number.isFinite(value.total)
      ? value.total
      : keys.length,
    page: typeof value.page === 'number' && Number.isFinite(value.page)
      ? value.page
      : page,
    page_size: typeof value.page_size === 'number' && Number.isFinite(value.page_size)
      ? value.page_size
      : pageSize,
    keys,
  }
}

export async function getProviderKeysPage(
  providerId: string,
  params: ProviderKeysPageQuery = {},
): Promise<ProviderKeysPageResponse> {
  const page = params.page ?? 1
  const pageSize = params.page_size ?? 20
  const response = await client.get<ProviderKeysPagePayload>(
    `/api/admin/endpoints/providers/${providerId}/keys`,
    { params: { page, page_size: pageSize } },
  )
  return normalizeProviderKeysPage(response.data, page, pageSize)
}

export async function getProviderKeys(providerId: string): Promise<EndpointAPIKey[]> {
  // 后端默认 limit=100，这里主动分页拉取，避免账号数 >100 时前端被截断
  const pageSize = 1000
  let skip = 0
  const allKeys: EndpointAPIKey[] = []

  while (true) {
    const response = await client.get(`/api/admin/endpoints/providers/${providerId}/keys`, {
      params: { skip, limit: pageSize },
    })

    const batch = Array.isArray(response.data) ? (response.data as EndpointAPIKey[]) : []
    allKeys.push(...batch)

    if (batch.length < pageSize) break
    skip += pageSize
  }

  return allKeys
}

/**
 * 为 Provider 添加 Key
 */
export async function addProviderKey(
  providerId: string,
  data: {
    api_formats: string[]  // 支持的 API 格式列表（必填）
    api_key: string
    auth_type?: 'api_key' | 'service_account' | 'oauth' | 'bearer'  // 认证类型
    auth_type_by_format?: Record<string, 'api_key' | 'bearer'> | null
    allow_auth_channel_mismatch_formats?: string[] | null
    auth_config?: Record<string, unknown>  // 认证配置（Vertex AI Service Account JSON）
    name: string
    rate_multipliers?: Record<string, number> | null  // 按 API 格式的成本倍率
    internal_priority?: number
    rpm_limit?: number | null  // RPM 限制（留空=自适应模式）
    concurrent_limit?: number | null  // 并发请求上限（留空或 0=不限制）
    cache_ttl_minutes?: number
    max_probe_interval_minutes?: number
    allowed_models?: AllowedModels
    capabilities?: Record<string, boolean>
    note?: string
    auto_fetch_models?: boolean  // 是否启用自动获取模型
    model_include_patterns?: string[]  // 模型包含规则
    model_exclude_patterns?: string[]  // 模型排除规则
    /** Provider 专属上游元数据（如 OpenCode 的 opencode_exit_ip） */
    upstream_metadata?: Record<string, unknown>
  }
): Promise<EndpointAPIKey> {
  const response = await client.post<EndpointAPIKey>(`/api/admin/endpoints/providers/${providerId}/keys`, data)
  return response.data
}

/**
 * 更新 Key
 */
export async function updateProviderKey(
  keyId: string,
  data: Partial<{
    api_formats: string[]  // 支持的 API 格式列表
    api_key: string
    auth_type: 'api_key' | 'service_account' | 'oauth' | 'bearer'  // 认证类型
    auth_type_by_format: Record<string, 'api_key' | 'bearer'> | null
    allow_auth_channel_mismatch_formats: string[] | null
    auth_config: Record<string, unknown>  // 认证配置（Vertex AI Service Account JSON）
    name: string
    rate_multipliers: Record<string, number> | null  // 按 API 格式的成本倍率
    internal_priority: number
    global_priority_by_format: Record<string, number> | null  // 按 API 格式的全局优先级
    rpm_limit: number | null  // RPM 限制（留空=自适应模式）
    concurrent_limit: number | null  // 并发请求上限（留空或 0=不限制）
    cache_ttl_minutes: number
    max_probe_interval_minutes: number
    allowed_models: AllowedModels
    locked_models: string[]  // 被锁定的模型列表
    capabilities: Record<string, boolean> | null
    is_active: boolean
    note: string
    auto_fetch_models: boolean  // 是否启用自动获取模型
    model_include_patterns: string[]  // 模型包含规则
    model_exclude_patterns: string[]  // 模型排除规则
    proxy: import('./types').ProxyConfig | null  // Key 级别代理配置
    /** Provider 专属上游元数据（如 OpenCode 的 opencode_exit_ip） */
    upstream_metadata?: Record<string, unknown>
  }>,
  requestOptions?: KeyRequestOptions,
): Promise<EndpointAPIKey> {
  const response = await client.put<EndpointAPIKey>(
    `/api/admin/endpoints/keys/${keyId}`,
    data,
    requestOptions,
  )
  return response.data
}

/**
 * 清除 Key 的 OAuth 失效标记
 */
export async function clearOAuthInvalid(keyId: string): Promise<{ message: string }> {
  const response = await client.post<{ message: string }>(`/api/admin/endpoints/keys/${keyId}/clear-oauth-invalid`)
  return response.data
}

/**
 * 重置 Key 的当前周期统计起点（Codex 号池）
 */
export async function resetProviderKeyCycleStats(keyId: string): Promise<{
  message: string
  reset_at: number
  windows: number
}> {
  const response = await client.post<{
  message: string
  reset_at: number
  windows: number
}>(`/api/admin/endpoints/keys/${keyId}/reset-cycle-stats`)
  return response.data
}

/**
 * 刷新 Provider 的所有 Key 限额信息（Codex / Antigravity）
 */
export interface RefreshQuotaResult {
  success: number
  failed: number
  total: number
  results: Array<{
    key_id: string
    key_name: string
    status:
      | 'success'
      | 'no_metadata'
      | 'quota_exhausted'
      | 'workspace_deactivated'
      | 'auth_invalid'
      | 'forbidden'
      | 'banned'
      | 'error'
    // provider 级 bucket 数据；前端应按当前 provider_type 包装回 upstream_metadata.<provider_type>
    metadata?: Record<string, unknown>
    quota_snapshot?: QuotaStatusSnapshot
    message?: string
    status_code?: number
  }>
}

export async function refreshProviderQuota(
  providerId: string,
  keyIds?: string[],
): Promise<RefreshQuotaResult> {
  const body = keyIds && keyIds.length > 0 ? { key_ids: keyIds } : undefined
  const response = await client.post<RefreshQuotaResult>(
    `/api/admin/endpoints/providers/${providerId}/refresh-quota`,
    body,
    { timeout: 5 * 60 * 1000 },
  )
  return response.data
}

export interface ConsumeCodexResetCreditPayload {
  idempotency_key: string
  expected_credential_generation: string | null
}

export interface ConsumeCodexResetCreditResult {
  key_id: string
  status: 'success' | 'noop' | 'unknown' | 'error' | string
  outcome:
    | 'reset'
    | 'already_redeemed'
    | 'nothing_to_reset'
    | 'no_credit'
    | 'historical_replay'
    | 'credential_changed'
    | 'unknown'
    | 'error'
    | string
  idempotency_key: string
  refresh_status?: 'success' | 'failed' | string
  refresh_error?: string | null
  metadata?: Record<string, unknown>
  quota_snapshot?: QuotaStatusSnapshot
  message?: string
  status_code?: number
}

export async function consumeCodexResetCredit(
  keyId: string,
  payload: ConsumeCodexResetCreditPayload,
): Promise<ConsumeCodexResetCreditResult> {
  const response = await client.post<ConsumeCodexResetCreditResult>(
    `/api/admin/endpoints/keys/${keyId}/codex-reset-credit/consume`,
    payload,
    { timeout: 5 * 60 * 1000 },
  )
  return response.data
}

/**
 * 批量导入 OAuth 凭据（通用）
 * 支持的 Provider 类型：Codex、Antigravity、GeminiCli、ClaudeCode、Kiro
 */
export interface BatchImportResultItem {
  index: number
  status: 'success' | 'error'
  key_id?: string
  key_name?: string
  auth_method?: string
  error?: string
}

export interface BatchImportResult {
  total: number
  success: number
  failed: number
  results: BatchImportResultItem[]
}

export async function batchImportOAuth(
  providerId: string,
  credentials: string,
  proxyNodeId?: string
): Promise<BatchImportResult> {
  const response = await client.post<BatchImportResult>(`/api/admin/provider-oauth/providers/${providerId}/batch-import`, {
    credentials,
    proxy_node_id: proxyNodeId || undefined,
  })
  return response.data
}

/** provider 级出口 IP 池（不会创建/删除密钥） */
export async function addOpenCodeExitIp(
  providerId: string,
  ip: string,
): Promise<{ saved: boolean; duplicate?: boolean; ip?: string }> {
  const response = await client.post<{ saved: boolean; duplicate?: boolean; ip?: string }>(
    `/api/admin/opencode-ip-pool/providers/${providerId}/pool/ips/add`,
    { ip },
  )
  return response.data
}

export async function removeOpenCodeExitIp(
  providerId: string,
  ip: string,
): Promise<{ removed: boolean; ip?: string }> {
  const response = await client.post<{ removed: boolean; ip?: string }>(
    `/api/admin/opencode-ip-pool/providers/${providerId}/pool/ips/remove`,
    { ip },
  )
  return response.data
}

export async function updateOpenCodeExitIp(
  providerId: string,
  oldIp: string,
  newIp: string,
): Promise<{ updated: boolean }> {
  const response = await client.post<{ updated: boolean }>(
    `/api/admin/opencode-ip-pool/providers/${providerId}/pool/ips/update`,
    { old_ip: oldIp, new_ip: newIp },
  )
  return response.data
}

export async function toggleOpenCodeExitIp(
  providerId: string,
  ip: string,
  isActive: boolean,
): Promise<{ saved: boolean; is_active: boolean }> {
  const response = await client.post<{ saved: boolean; is_active: boolean }>(
    `/api/admin/opencode-ip-pool/providers/${providerId}/pool/ips/toggle`,
    { ip, is_active: isActive },
  )
  return response.data
}

/**
 * 人工拉黑：请求路径永远跳过，复验也不放回。
 *
 * 只写 `opencode_health.blocked`，不动 `healthy` / `candidates`——拉黑表达「别用它」，
 * 不是「删掉它」；一条命令就能解禁。
 */
export async function blockOpenCodeExitIp(
  providerId: string,
  ip: string,
): Promise<{ saved: boolean; ip: string; blocked: boolean }> {
  const response = await client.post<{ saved: boolean; ip: string; blocked: boolean }>(
    `/api/admin/opencode-ip-pool/providers/${providerId}/pool/ips/block`,
    { ip },
  )
  return response.data
}

/** 解除人工拉黑。 */
export async function unblockOpenCodeExitIp(
  providerId: string,
  ip: string,
): Promise<{ saved: boolean; ip: string; blocked: boolean }> {
  const response = await client.post<{ saved: boolean; ip: string; blocked: boolean }>(
    `/api/admin/opencode-ip-pool/providers/${providerId}/pool/ips/unblock`,
    { ip },
  )
  return response.data
}

/**
 * 只重验这一个：立刻拿**完整采样次数**的结论，不跑整轮复验。
 *
 * 与整轮复验的分工：整轮会重算可用池、并且有权按跨轮证据丢弃节点；单点复验只更新
 * 证据——通过就从异常池提出、放回可用池，不通过就给异常池计数 +1，**永不丢弃**。
 */
export async function reverifyOpenCodeExitIp(
  providerId: string,
  ip: string,
): Promise<{
  ip: string
  healthy: boolean
  reason?: string | null
  median_ms?: number | null
  fails: number
}> {
  const response = await client.post<{
    ip: string
    healthy: boolean
    reason?: string | null
    median_ms?: number | null
    fails: number
  }>(`/api/admin/opencode-ip-pool/providers/${providerId}/pool/ips/reverify`, { ip })
  return response.data
}

/**
 * 一键重置异常池（同时清掉可用池骤缩告警）。
 *
 * 丢弃留痕**不清**：它是历史记录，不是「当前不用」。
 */
export async function resetOpenCodeAbnormalIps(
  providerId: string,
): Promise<{ removed: number }> {
  const response = await client.post<{ removed: number }>(
    `/api/admin/opencode-ip-pool/providers/${providerId}/abnormal/reset`,
    {},
  )
  return response.data
}
