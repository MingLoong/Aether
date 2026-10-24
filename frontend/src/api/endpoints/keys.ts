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
  last_scan_at?: string | null
  last_scan_targets?: number
  last_scan_found?: number
  last_scan_added?: number
  /** 长任务进度：已探 / 总数。大批量扫描要跑几十分钟，没有它面板上只会像卡死。 */
  progress_done?: number
  progress_total?: number
  progress_kind?: 'scan' | null
  /** 池里一共多少个锚点 IP（不含被停用/冷却的） */
  rotation_pool_size?: number
  /** 上次真正选中的锚点 IP，精确反映取模基数 */
  rotation_last_ip?: string | null
  auto_enabled?: boolean
  autoscan_effective?: boolean
  interval_hours?: number
  concurrency?: number
  /** 生效的扫描快筛阈值（毫秒）：连接 + TLS + 响应首行超过它判死 */
  probe_max_handshake_ms?: number
  /** 阈值来源：config = 面板配置的，env = 环境变量兜底，default = 代码默认 */
  probe_max_handshake_source?: 'config' | 'env' | 'default'
  cidrs?: string[]
  proxy_domain?: string | null
  /** 用户填写过的前置代理域名（即使开关已关闭也保留，用于一键恢复） */
  saved_proxy_domain?: string | null
  /** 池模型：现在只有 provider 级四态池一种，此字段恒为 `provider`（保留以免破坏调用方） */
  pool_source?: 'provider' | 'key'
  /**
   * 出口 IP 池为空告警：为真表示当前**所有请求都不做 DNS 锚定**（走官方域名）。
   *
   * key 只承担上游凭据、不再自带出口 IP，所以空池没有兜底，必须显式提示。
   */
  pool_empty_alarm?: boolean
  exit_pool?: string[]
  exit_pool_disabled?: string[]
  proxy_enabled?: boolean
  original_domain?: string | null
  /** 是否启用「记住上次 +1」的出口 IP 轮转 */
  rotation_enabled?: boolean
  rotation_effective?: boolean
  /** 配额型失败的固定冷却时长（秒，默认 120，夹紧 30–600） */
  cooldown_seconds?: number
  /** 后台维护间隔（秒，默认 600，夹紧 30–86400） */
  maintenance_interval_seconds?: number
  /** 定期扫描间隔（秒，0 = 关闭，上限 86400） */
  scan_interval_seconds?: number
  /** 轮转池跌破 min_pool_size 时是否自动按 CIDR 补池（默认开） */
  maintenance_auto_refill?: boolean
  /** 真实请求连续失败多少次把该出口 IP 放进异常池（1–100，默认 3） */
  runtime_fail_threshold?: number
  /** 当前轮转游标：每命中一次 +1 */
  rotation_cursor?: number
  pool_ips?: Array<{ key_id: string; ip: string; is_active: boolean }>

  // ---- 验证健康（单个 IP，真实 chat 探测）-------------------------------
  /** 单次 chat 探测的首字节中位数上限（毫秒）：超过它判「太慢」 */
  verify_max_median_ms?: number
  /** 探测用的真实 chat 模型（默认 big-pickle） */
  probe_model?: string
  /** 相邻两次 chat 探测的最小间隔（毫秒；后端保留该配置，单 IP 验证不消费） */
  probe_interval_ms?: number
  /** 保底池大小：低于此值不做任何淘汰 */
  min_pool_size?: number

  // ---- 分层计数：健康 / 在用 -------------------------------------------
  healthy_count?: number
  in_use_count?: number
  degraded_count?: number
  healthy?: string[]
  pinned?: string[]
  degraded?: string[]
  healthy_prev_count?: number
  /** 逐节点首字节中位数（毫秒）——没有它就看不出池里混进了慢节点 */
  latencies?: Record<string, number>
  // ---- 三态：可用 / 异常 / 丢弃（2026-10 起替代 rejections）-------
  /**
   * 异常池：有嫌疑、**立刻不用**但仍在跟踪的节点。
   *
   * 出路只有两条：复验通过 → 回到 `healthy`（`fails` 清零），或连续 ≥2 轮不过 →
   * 被丢弃（删记录）。计数每个复验轮最多加一，所以 `fails >= 2` 天然等价于「跨轮」。
   * 丢弃只写一条 `opencode_ip_pool_ip_discarded` 事件日志，不再是可查询的状态。
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
    /** 冷却剩余秒数（配额型 429 会跟上游 `retry-after` 对齐，可能长达数小时）。 */
    cooldown_remaining_seconds?: number | null
  }>

  // ---- 当日成败计数（每个出口 IP 一份）-------------------------------------
  /**
   * `ip -> { ok, fail, by_status, last_ok_at, last_fail_at }`。
   *
   * 只含**池内且有计数**的 IP，读不到持久化层时是空对象（不是 null）。计数只服务
   * 面板可见性：它不参与冷却、出池或任何判定。TTL 2 天，跨天自然过期。
   */
  ip_stats?: Record<
    string,
    {
      ok?: number
      fail?: number
      /** `{ '429': n, '503': n, other: n }` —— 只出现真正发生过的档位 */
      by_status?: Record<string, number>
      /** 最后成功时刻（unix 秒）；0/缺失 = 还没成功过 */
      last_ok_at?: number
      /** 最后失败时刻（unix 秒）；0/缺失 = 还没失败过 */
      last_fail_at?: number
    }
  >

  // ---- 规模自适应：自动降级的原因必须可见 --------------------------------
  session_sticky_enabled?: boolean
  session_sticky_active?: boolean
  /** 例：`pool_below_min(3<10)` 或 `disabled_by_operator` */
  session_sticky_disabled_reason?: string | null
  pool_below_floor?: boolean
  pool_empty?: boolean
}

export interface OpenCodeIpPoolConfigPayload {
  cidrs?: string[]
  concurrency?: number
  /** 扫描快筛阈值（100–60000 毫秒）；不传时用环境变量，再退回默认 600 */
  probe_max_handshake_ms?: number
  /** 后台维护间隔（秒，默认 600，夹紧 30–86400） */
  maintenance_interval_seconds?: number
  /** 定期扫描间隔（秒，0 = 关闭，上限 86400） */
  scan_interval_seconds?: number
  /** 轮转池跌破 min_pool_size 时是否自动按 CIDR 补池（默认开） */
  maintenance_auto_refill?: boolean
  /** 真实请求连续失败多少次把该出口 IP 放进异常池（1–100，默认 3） */
  runtime_fail_threshold?: number
  /** 可选：更新前置代理域名（替换该供应商全部端点 base_url 的 host） */
  proxy_domain?: string
  /** 是否启用出口 IP 轮转 */
  rotation_enabled?: boolean
  /** 配额型失败的固定冷却时长（秒，默认 120，夹紧 30–600） */
  cooldown_seconds?: number
  /** 前置代理开关 */
  pool_source?: 'provider' | 'key'
  exit_pool?: string[]
  exit_pool_disabled?: string[]
  proxy_enabled?: boolean
  /** 长任务进度：已探 / 总数 */
  progress_done?: number
  progress_total?: number
  progress_kind?: 'scan' | null
  /** 健康维护域，与扫描域分开：两者不能互相覆盖 */
  opencode_health?: {
    verify_max_median_ms?: number
    min_pool_size?: number
    session_sticky_enabled?: boolean
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

/** 单次探测发出 / 收到的一条 HTTP 头（保持原样，不排序不去重）。 */
export type OpenCodeProbeHeader = {
  name: string
  value: string
}

/**
 * 单次「验证健康」探测的真实往返。
 *
 * 存在的意义是排查 403/429：结论字段只说明「不可用」，而这里保留的是上游原样的
 * 状态行、响应头与响应正文（例如 FreeTierError 的裸文本），能分清是免费层准入
 * 拒绝还是额度真的耗尽。正文一律按原文保留，不做 JSON 美化。
 */
export type OpenCodeProbeTrace = {
  ip: string
  /** 探测目标域名（前置代理域名）；为空表示直接按 IP 连 */
  domain: string
  port: number
  method: string
  path: string
  request_headers: OpenCodeProbeHeader[]
  request_body: string
  /** 没收到响应时为 null */
  status: number | null
  status_line: string
  response_headers: OpenCodeProbeHeader[]
  response_body: string
  elapsed_ms: number
  /** 传输层错误（连接失败 / 超时 / 中断）；没有错误时为 null */
  error: string | null
}

/** 单个池内 IP 的「验证健康」结论（一次真实 chat 探测）。 */
export type OpenCodeExitIpVerifyResult = {
  ip: string
  /** 拿到 200 才算可用 */
  healthy: boolean
  /** 403 / 429：额度受限，既不算不可达也不清异常计数 */
  quota_limited: boolean
  /** `unreachable` / `quota_limited`；可用时为 null */
  reason?: string | null
  /** 本次探测耗时（毫秒）；不可用时为 null */
  median_ms?: number | null
  /** 异常池里累计的失败次数（通过后为 0） */
  fails: number
  /** 这次探测真实发出的请求与收到的响应原文 */
  trace: OpenCodeProbeTrace
}

/**
 * 验证**单个**池内 IP：一次真实 chat 探测（成本 = 一个请求），用户点击才触发。
 *
 * 后台维护 worker 走的是 TLS + `GET /` 零额度探针，与这条路径无关。
 * 同步返回结论（一次探测最长 15 秒）。
 */
export async function verifyOpenCodeExitIp(
  providerId: string,
  ip: string,
): Promise<OpenCodeExitIpVerifyResult> {
  const response = await client.post<OpenCodeExitIpVerifyResult>(
    `/api/admin/opencode-ip-pool/providers/${providerId}/pool/ips/verify`,
    { ip },
  )
  return response.data
}

/**
 * 一键重置异常池（同时清掉可用池骤缩告警）。
 *
 * 人工拉黑**不清**：那是人工决定，出路是解禁，语义与「先别用它」不同。
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
