/**
 * `pool_advanced` 各旋钮的**后端默认值**（前端唯一事实来源 ✓，只读）。
 *
 * 必须与 `apps/aether-gateway/src/handlers/admin/provider/pool/config.rs` 里
 * `admin_provider_pool_config_from_config_value` 的解析默认值**逐项一致** ✓ ——
 * `__tests__/poolAdvancedDefaults.spec.ts` 会**直接读那个后端文件**核对 ✗→✓，
 * 任何一边改了忘了另一边，测试立刻红 ✓（本次维护性审计发现的漂移就是这么来的 ✗）。
 *
 * ⚠️ 语义提醒 ✓：这套配置里的 **`0` 不是「没设置」** ✓，而是
 * 「沿用 Aether 历史值」或「关停」✓（见后端同名注释 ✓）。
 * 所以前端兜底值**必须**是后端的真默认值，不能图省事写 `0` ✗ ——
 * 否则「打开对话框 → 保存」会把默认值静默改掉 ✗。
 */
export const POOL_ADVANCED_DEFAULTS = {
  /** 积分保底（0 = 关闭） */
  creditFloor: 0,
  /** 熔断阈值（连续失败次数） */
  breakerThreshold: 3,
  /** 熔断基础时长（分钟） */
  breakerCooldownMinutes: 30,
  /** 熔断退避上限（分钟，6h） */
  breakerCooldownMaxMinutes: 360,
  /** 单账号最大在途（所有域兜底） */
  maxInFlight: 3,
  /** 成本探索窗口（秒） */
  costExploreIntervalSeconds: 1800,
  /** WAF 出口 IP 拦截窗口（秒） */
  wafIpCooldownSeconds: 60,
  /** 池内账号是否计入 key 级熔断 */
  poolCountsTowardCircuitBreaker: true,
  /** WAF 拦截期是否连新请求一起挡 */
  wafIpBlockNewRequests: true,
} as const

/** 在途上限的输入上限（与后端钳制值一致 ✓，防止荒谬大数 ✗）。 */
export const POOL_ADVANCED_MAX_IN_FLIGHT = 10_000
