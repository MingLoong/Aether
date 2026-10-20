<template>
  <div class="space-y-4">
    <!-- 上游模型能力与倍率（独立成表，按域分开；不混进模型列表） -->
    <Card class="overflow-hidden">
      <div class="p-4 border-b border-border/60 flex flex-wrap items-center justify-between gap-3">
        <div class="flex min-w-0 flex-wrap items-center gap-2">
          <h3 class="shrink-0 whitespace-nowrap text-sm font-semibold">{{ $legacyT('上游模型能力与倍率') }}</h3>
          <span class="shrink-0 text-xs text-muted-foreground tabular-nums">
            {{ catalogRows.length }} {{ $legacyT('个') }}
          </span>
          <!-- 批量导入：把目录里还没导入的模型一次导进来（按 model_uid 去重） -->
          <Button
            v-if="pendingRows.length > 0"
            data-testid="workbuddy-bulk-import"
            variant="outline"
            size="sm"
            class="h-6 shrink-0 whitespace-nowrap px-2 text-[11px] font-medium"
            :disabled="importingAll || importingKeys.size > 0"
            @click="handleImportMissingRows"
          >
            <Loader2
              v-if="importingAll"
              class="mr-1 h-3 w-3 animate-spin"
            />
            {{ importingAll
              ? $legacyT('导入中')
              : `${$legacyT('导入未导入的')} ${pendingRows.length}` }}
          </Button>

          <Button
             variant="outline"
             size="sm"
             class="h-6 shrink-0 whitespace-nowrap px-2 text-[11px] font-medium"
             data-testid="workbuddy-force-refresh-catalog"
             :disabled="fetchingCatalog || forceRefreshing"
             :title="$legacyT('立即绕过缓存，刷新全部账号的上游模型目录')"
             @click="forceRefreshCatalogs"
           >
             <Loader2 v-if="forceRefreshing" class="mr-1 h-3 w-3 animate-spin" />
             {{ forceRefreshing ? $legacyT('强制刷新中') : $legacyT('强制刷新目录') }}
           </Button>

           <!-- 有账号还没拉过上游目录（该域在面板上一个模型都没有）→ 提示并允许重试 -->
          <Button
            v-if="missingCatalogKeys.length > 0"
            variant="outline"
            size="sm"
            class="h-6 shrink-0 whitespace-nowrap px-2 text-[11px] font-medium"
            data-testid="workbuddy-fetch-catalog"
            :disabled="fetchingCatalog"
            :title="$legacyT('该账号还没拉过上游目录（所以这个域一个模型都没有）——已自动为你拉取，失败可点左侧按钮重试。')"
            @click="fetchMissingCatalogs"
          >
            <Loader2
              v-if="fetchingCatalog"
              class="mr-1 h-3 w-3 animate-spin"
            />
            {{ fetchingCatalog
              ? $legacyT('拉取目录中')
              : `${$legacyT('拉取账号目录')} ${missingCatalogKeys.length}` }}
          </Button>
        </div>
        <span class="max-w-full text-[10px] text-muted-foreground">
          {{ $legacyT('每 6 小时轮询一个账号；手动强制刷新可立即更新；倍率/能力/上下文来自上游目录') }}
        </span>
      </div>

      <div
        v-if="catalogRows.length === 0"
        class="p-4 text-xs text-muted-foreground/70"
      >
        {{ $legacyT('暂无上游目录快照：正在自动为你拉取该账号的上游目录，失败可用上方按钮重试') }}
      </div>

      <div
        v-else
        class="overflow-x-auto"
      >
        <table class="w-full text-xs">
          <thead class="bg-muted/30 text-muted-foreground">
            <tr>
              <th class="text-left px-3 py-2 font-medium">{{ $legacyT('域') }}</th>
              <th class="text-left px-3 py-2 font-medium">{{ $legacyT('模型') }}</th>
              <th class="text-left px-3 py-2 font-medium">{{ $legacyT('倍率') }}</th>
              <th class="text-left px-3 py-2 font-medium">{{ $legacyT('上下文/输出') }}</th>
              <th class="text-left px-3 py-2 font-medium">{{ $legacyT('能力') }}</th>
              <th class="text-left px-3 py-2 font-medium">{{ $legacyT('导入状态') }}</th>
            </tr>
          </thead>
          <tbody>
            <tr
              v-for="row in catalogRows"
              :key="row.key"
              class="border-t border-border/40"
            >
              <td class="px-3 py-2 whitespace-nowrap">
                <span
                  class="rounded px-1.5 py-px text-[10px]"
                  :class="row.realm === 'global'
                    ? 'bg-sky-500/15 text-sky-700 dark:text-sky-300'
                    : (row.realm === 'cn'
                      ? 'bg-emerald-500/15 text-emerald-700 dark:text-emerald-300'
                      : 'bg-muted text-muted-foreground')"
                >{{ realmLabel(row.realm) }}</span>
              </td>
              <td class="px-3 py-2">
                <div class="flex items-center gap-1.5">
                  <span class="font-medium">{{ row.label || row.modelUid }}</span>
                  <span
                    v-if="row.isDefault"
                    class="rounded bg-primary/10 px-1 py-px text-[10px] text-primary"
                  >{{ $legacyT('默认') }}</span>
                </div>
                <div
                  class="font-mono text-[10px] text-muted-foreground truncate max-w-[16rem]"
                  :title="modelRowTitle(row)"
                >
                  {{ modelRowSubtitle(row) }}
                </div>
              </td>
              <td class="px-3 py-2 font-mono whitespace-nowrap">
                <template v-if="row.planRestricted || row.planBlocked">
                  <span
                    class="rounded bg-amber-500/15 px-1.5 py-px text-[10px] font-semibold text-amber-700 dark:text-amber-300"
                    :title="row.tierHoverText || $legacyT('该模型仅面向 Pro 用户开放')"
                  >{{ row.tierBadgeLabel || $legacyT('Pro Only') }}</span>
                  <span v-if="row.credits" class="ml-1 text-muted-foreground line-through">{{ formatMultiplier(row.credits) }}</span>
                </template>
                <template v-else-if="row.promoCredits || row.promoLabel">
                  <div class="flex flex-wrap items-center gap-1.5">
                    <span
                      class="text-primary"
                      :class="{ 'font-semibold': promoEffectiveLabel(row) === '免费' }"
                      :title="promoCellTitle(row)"
                    >{{ promoEffectiveLabel(row) }}</span>
                    <span
                      v-if="row.promoLabel"
                      class="rounded bg-primary/10 px-1 py-px text-[10px] text-primary"
                    >{{ row.promoLabel }}</span>
                  </div>
                  <div
                    v-if="promoOriginalLabel(row)"
                    class="text-[10px] text-muted-foreground line-through"
                  >{{ promoOriginalLabel(row) }}</div>
                </template>
                <span v-else-if="row.credits">{{ formatMultiplier(row.credits) }}</span>
                <span
                  v-else
                  class="text-muted-foreground/60"
                >—</span>
              </td>
              <td class="px-3 py-2 tabular-nums whitespace-nowrap text-muted-foreground">
                <span v-if="row.contextLabel" :title="$legacyT('上下文 / 最大输出')">{{ row.contextLabel }}</span>
                <span
                  v-else
                  class="text-muted-foreground/60"
                >—</span>
              </td>
              <td class="px-3 py-2">
                <div class="flex flex-wrap items-center gap-1">
                  <template v-if="row.capabilities.length > 0">
                    <span
                      v-for="capability in row.capabilities"
                      :key="capability"
                      class="rounded px-1 py-px text-[10px]"
                      :class="row.capabilityIsRaw
                        ? 'bg-muted text-muted-foreground font-mono'
                        : 'bg-primary/10 text-primary'"
                    >{{ capability }}</span>
                  </template>
                  <span
                    v-else
                    class="text-muted-foreground/60"
                  >{{ row.imported ? $legacyT('未声明能力') : $legacyT('未导入，能力未知') }}</span>
                </div>
              </td>
              <td class="px-3 py-2 whitespace-nowrap">
                <span
                  v-if="row.imported"
                  class="rounded bg-emerald-500/15 px-1.5 py-px text-[10px] text-emerald-700 dark:text-emerald-300"
                >{{ $legacyT('已导入') }}</span>
                <span
                  v-else
                  class="inline-flex items-center gap-1.5"
                >
                  <span class="text-muted-foreground/70">{{ $legacyT('未导入') }}</span>
                  <!-- 逐个导入：以前这里只有「未导入」三个字，没有入口，只能去别处批量导 -->
                  <Button
                    variant="outline"
                    size="sm"
                    class="h-6 shrink-0 whitespace-nowrap px-2 text-[11px] font-medium"
                    :disabled="importingAll || importingKeys.has(row.key)"
                    @click="handleImportRow(row)"
                  >
                    <Loader2
                      v-if="importingKeys.has(row.key)"
                      class="mr-1 h-3 w-3 animate-spin"
                    />
                    {{ importingKeys.has(row.key) ? $legacyT('导入中') : $legacyT('导入') }}
                  </Button>
                </span>
              </td>
            </tr>
          </tbody>
        </table>
      </div>
    </Card>

    <!-- 模型锁池（独立成表，按域分组；分母 = 该域可选号） -->
    <Card class="overflow-hidden">
      <div class="p-4 border-b border-border/60 flex items-center justify-between gap-3">
        <div class="flex items-center gap-2 min-w-0">
          <h3 class="text-sm font-semibold">{{ $legacyT('模型锁池') }}</h3>
        </div>
        <span
          v-if="lockRows.length > 0"
          class="text-[10px] tabular-nums text-amber-700 dark:text-amber-300 shrink-0"
        >{{ lockRows.length }} {{ $legacyT('个模型受限') }}</span>
      </div>

      <div
        v-if="lockRows.length === 0"
        class="p-4 text-xs text-muted-foreground/70"
      >
        {{ $legacyT('当前没有被锁定的模型') }}
      </div>

      <div
        v-else
        class="overflow-x-auto"
      >
        <table class="w-full text-xs">
          <thead class="bg-muted/30 text-muted-foreground">
            <tr>
              <th class="text-left px-3 py-2 font-medium">{{ $legacyT('域') }}</th>
              <th class="text-left px-3 py-2 font-medium">{{ $legacyT('模型') }}</th>
              <th class="text-left px-3 py-2 font-medium">{{ $legacyT('状态') }}</th>
              <th class="text-left px-3 py-2 font-medium">{{ $legacyT('锁定账号') }}</th>
              <th class="text-left px-3 py-2 font-medium">{{ $legacyT('解锁时刻') }}</th>
              <th class="text-left px-3 py-2 font-medium">{{ $legacyT('原因') }}</th>
            </tr>
          </thead>
          <tbody>
            <tr
              v-for="row in lockRows"
              :key="row.key"
              class="border-t border-border/40"
            >
              <td class="px-3 py-2 whitespace-nowrap">
                <span
                  class="rounded px-1.5 py-px text-[10px]"
                  :class="row.realm === 'global'
                    ? 'bg-sky-500/15 text-sky-700 dark:text-sky-300'
                    : (row.realm === 'cn'
                      ? 'bg-emerald-500/15 text-emerald-700 dark:text-emerald-300'
                      : 'bg-muted text-muted-foreground')"
                >{{ realmLabel(row.realm) }}</span>
              </td>
              <td class="px-3 py-2 font-mono truncate max-w-[14rem]">{{ row.model }}</td>
              <td class="px-3 py-2 whitespace-nowrap">
                <span
                  class="rounded px-1.5 py-px text-[10px]"
                  :class="lockStateClass(row)"
                >
                  {{ lockStateLabel(row) }}
                </span>
              </td>
              <td class="px-3 py-2 tabular-nums whitespace-nowrap">
                {{ row.lockedKeys }}/{{ row.totalKeys }} {{ $legacyT('号') }}
              </td>
              <td class="px-3 py-2 tabular-nums whitespace-nowrap">
                {{ row.auditOnly ? $legacyT('仅展示，不影响路由') : formatUnlock(row.firstUnlockAt) }}
              </td>
              <td class="px-3 py-2 text-muted-foreground truncate max-w-[18rem]" :title="row.reasons.join(' / ')">
                {{ row.reasons.join(' / ') || '—' }}
              </td>
            </tr>
          </tbody>
        </table>
      </div>
    </Card>
  </div>
</template>

<script setup lang="ts">
import { computed, onMounted, ref, watch } from 'vue'
import Card from '@/components/ui/card.vue'
import Button from '@/components/ui/button.vue'
import { Loader2 } from 'lucide-vue-next'
import { useI18n } from '@/i18n'
import { useToast } from '@/composables/useToast'
import { parseApiError } from '@/utils/errorParser'
import { importModelsFromUpstream } from '@/api/endpoints/models'
import { useUpstreamModelsCache } from '../../composables/useUpstreamModelsCache'
import type { EndpointAPIKey, Model, ProviderWithEndpointsSummary, UpstreamModel } from '@/api/endpoints/types'

const props = defineProps<{
  provider: ProviderWithEndpointsSummary
  models?: Model[]
  providerKeys?: EndpointAPIKey[]
}>()

const emit = defineEmits<{
  refresh: []
  'refresh-catalog': []
}>()

const { legacyT } = useI18n()
const { error: showError, success: showSuccess } = useToast()
const { fetchModels: fetchUpstreamModels } = useUpstreamModelsCache()

/** 正在导入的行（key = `${realm}:${modelUid}`）；模板里直接 `.has()` 用。 */
const importingKeys = ref<Set<string>>(new Set())
/** 批量导入进行中。 */
const importingAll = ref(false)

/**
 * 还没拉过上游目录的账号（`upstream_metadata.workbuddy.models` 为空）。
 *
 * 为什么需要这一步：目录是**按 key 拉**的 ✓（`aether-model-fetch` 的 workbuddy strategy
 * 会写 `realm` + `models` ✓）—— 走过**登录流程**的账号有目录 ✓，而**导入凭据**进来的账号
 * 没有 ✗，于是「上游模型能力与倍率」里那个域一个模型都不显示 ✗
 * （用户实测：导入国际号后只看到国内模型 ✓）。
 */
const missingCatalogKeys = computed(() => (props.providerKeys ?? []).filter((key) => {
  const models = key.upstream_metadata?.workbuddy?.models
  if (Array.isArray(models)) return models.length === 0
  if (models && typeof models === 'object') {
    return Object.keys(models as Record<string, unknown>).length === 0
  }
  return true
}))

/** 拉目录进行中。 */
const fetchingCatalog = ref(false)
const forceRefreshing = ref(false)
/** 本次会话已尝试过的 key（自动只试一次 ✓，失败后交给按钮手动重试 ✓）。 */
const catalogAttempted = ref<Set<string>>(new Set())
const liveCatalogModels = ref<Map<string, UpstreamModel[]>>(new Map())

// ---------------------------------------------------------------------------
// 域（realm）：一个账号的快照只属于一个域；旧快照没有 realm 键 → '' 按「未知」单独一组。
// ---------------------------------------------------------------------------
function realmLabel(realm: string): string {
  if (realm === 'cn') return '国内'
  if (realm === 'global') return '国际'
  return realm || '—'
}

function formatTokens(value?: number | null): string {
  if (!value || value <= 0) return ''
  return value >= 1024 ? `${Math.round(value / 1024)}K` : String(value)
}

/**
 * 倍率展示（统一口径）：
 *  - `0`（上游写 `x0.00` 或 `0x`）→ **「免费」**（这才是人看得懂的写法）；
 *  - 可解析 → `×0.43` / `×1.62`（保留上游的小数位）；
 *  - 解析不了 → 原样输出（不编造）。
 */
function formatMultiplier(raw: string | null): string | null {
  if (!raw) return null
  const text = raw.trim()
  const digits = text.toLowerCase().replace(/^x/, '').replace(/x$/, '').trim()
  const value = Number(digits)
  if (!digits || !Number.isFinite(value)) return text
  return value === 0 ? '免费' : `×${digits}`
}

/** 生效价：有折后价就用它，只有徽章（无折扣）时退回牌价。 */
function promoEffectiveLabel(row: CatalogRow): string {
  return formatMultiplier(row.promoCredits) ?? formatMultiplier(row.credits) ?? '—'
}

/**
 * 删除线里的**原价**：只在「真有折扣」且「原价不是 0」时才显示。
 *
 * 之所以要判 0：`hy3` 这类模型上游牌价本来就是 `x0.00`（免费）✓，再划掉一个「0」看着像坏了 ✗。
 */
function promoOriginalLabel(row: CatalogRow): string | null {
  if (!row.promoCredits && !row.promoLabel) return null
  const original = formatMultiplier(row.credits)
  // 原价本来就是 0/免费 → 不划（划掉一个「0」看着像坏了）
  if (!original || original === '免费') return null
  const effective = formatMultiplier(row.promoCredits)
  // 只有徽章、没有折后价 → 不划（不知道打了多少折，避免误导）
  if (!effective) return null
  // 折后价 == 原价（没真打折）→ 不划
  if (effective === original) return null
  // 到这里：原价非 0 且确实有折后价（折后价可能是「免费」）→ 划掉原价
  return original
}

/** 悬浮提示：把上游**原始串**与说明都带上（展示层归一了，原始值不丢）。 */
function promoCellTitle(row: CatalogRow): string | undefined {
  const parts: string[] = []
  if (row.credits) parts.push(`上游牌价 ${row.credits}`)
  if (row.promoCredits) parts.push(`上游折后价 ${row.promoCredits}`)
  if (row.promoFactor !== null) parts.push(`折扣系数 ${row.promoFactor}`)
  if (row.promoNote) parts.push(row.promoNote)
  return parts.length > 0 ? parts.join(' · ') : undefined
}

/**
 * 上游 `vendor` 值是否值得展示。
 *
 * 实测（2026-10-16 直读快照）：workbuddy 上游给的是**单字母内部代码** ——
 * `e` = GLM 家族、`f` = DeepSeek/Kimi/MiniMax/Step/Space、`j` = 混元家族。
 * 单字符对用户没有意义 → 不展示（但保留在悬浮提示里，不丢上游原始信息）。
 */
function isDisplayableVendor(vendor: string): boolean {
  return vendor.trim().length >= 2
}

/** 模型格子第二行：`模型 id`（+ 可读厂牌，若上游真给了名字）。 */
function modelRowSubtitle(row: { modelUid: string; vendor: string }): string {
  const parts = [row.modelUid]
  if (isDisplayableVendor(row.vendor)) parts.push(row.vendor.trim())
  return parts.join(' · ')
}

/** 悬浮提示：把被隐藏的上游厂牌代码也带上，方便核对。 */
function modelRowTitle(row: { modelUid: string; vendor: string }): string | undefined {
  const vendor = row.vendor.trim()
  if (!vendor) return undefined
  return isDisplayableVendor(vendor)
    ? `${row.modelUid} · ${vendor}`
    : `${row.modelUid} · 上游厂牌代码：${vendor}`
}

// ---------------------------------------------------------------------------
// 上游模型能力与倍率：按 (域, model_uid) 去重——同名模型在两个域是不同条目
//（目录/倍率/能力可能各不相同；一个域可能根本没有这个模型）。
// ---------------------------------------------------------------------------
interface CatalogRow {
  key: string
  realm: string
  modelUid: string
  label: string
  vendor: string
  credits: string | null
  isDefault: boolean
  imported: boolean
  capabilities: string[]
  /** 能力全部来自裸努力档名（老快照无能力字段时退回已导入模型的生效能力，其标签已本地化） */
  capabilityIsRaw: boolean
  contextLabel: string
  /** 限时优惠（若有）：`credits` 是牌价，`promoCredits` 是当前生效价。 */
  promoFactor: number | null
  promoCredits: string | null
  promoLabel: string | null
  promoNote: string | null
  planRestricted: boolean
  tierBadgeLabel: string | null
  tierBadgeColor: string | null
  tierHoverText: string | null
  planBlocked: boolean
}

// 官方 `/v3/config` 的 modelTiers=gpt-pro-only（国际版）；作为旧缓存的展示兜底。
// primary-model 是旧版别名，目录 tier 未列出但实测同样返回 11158。
const WORKBUDDY_PRO_ONLY_MODELS = new Set([
  'gpt-6-astra', 'gpt-6.1-sol', 'gpt-6-sol', 'gpt-6-luna', 'gpt-5.6-sol',
  'gpt-5.6-terra', 'gpt-5.6-luna', 'gpt-5.5', 'gpt-5.4', 'grok-4.7',
  'gemini-3.8-flash', 'gemini-3.5-flash', 'primary-model',
])

const catalogRows = computed<CatalogRow[]>(() => {
  const importedModels = new Map<string, Model>()
  for (const model of props.models ?? []) {
    importedModels.set(model.provider_model_name, model)
  }

  const rows: CatalogRow[] = []
  const seen = new Set<string>()
  // `models` 历史上有两种形态：拉目录写的是**数组**（含 model_uid），而另一条
  // efforts 缓存链写的是**按模型 id 键控的对象**——两种都读，避免形状一变表格就崩。
  const asEntryList = (models: unknown): Array<Record<string, unknown>> => {
    if (Array.isArray(models)) return models.filter((item): item is Record<string, unknown> => !!item && typeof item === 'object')
    if (models && typeof models === 'object') {
      return Object.entries(models as Record<string, unknown>)
        .filter(([, value]) => !!value && typeof value === 'object')
        .map(([id, value]) => ({ model_uid: id, ...(value as Record<string, unknown>) }))
    }
    return []
  }
  for (const key of props.providerKeys ?? []) {
    const wb = key.upstream_metadata?.workbuddy
    if (!wb) continue
    const realm = typeof wb.realm === 'string' ? wb.realm : ''
    const blocked = wb.model_blocked && typeof wb.model_blocked === 'object' ? wb.model_blocked : {}
    const currentModels = liveCatalogModels.value.get(key.id)
    const sourceModels = currentModels && currentModels.length > 0 ? currentModels : asEntryList(wb.models)
    for (const raw of sourceModels) {
      const entry = raw as {
        model_uid?: string
        label?: string
        vendor?: string
        credits?: string
        is_default?: boolean
        context_window?: number
        max_tokens?: number
        supports_images?: boolean
        supports_reasoning?: boolean
        supports_tool_call?: boolean
        only_reasoning?: boolean
        can_disable_thinking?: boolean
        efforts?: string[]
        default_effort?: string
        // 限时优惠（`credits` 是牌价，`promo_*` 是当前生效价）
        promo_factor?: number
        promo_credits?: string
        promo_label?: string
        promo_note?: string
        plan_restricted?: boolean
        model_blocked?: Record<string, { kind?: string; reason?: string; until_unix_secs?: number }>
        model_tier?: {
          badge?: { label?: string; labelEn?: string; color?: string }
          hover?: { textZh?: string; textEn?: string }
        }
      }
      const modelUid = typeof entry.model_uid === 'string' ? entry.model_uid : ''
      if (!modelUid) continue
      const rowKey = `${realm}:${modelUid}`
      if (seen.has(rowKey)) continue
      seen.add(rowKey)

      const model = importedModels.get(modelUid)
      const capabilities: string[] = []
      let capabilityIsRaw = false
      const snapshotHasCapability =
        entry.supports_images !== undefined ||
        entry.supports_reasoning !== undefined ||
        entry.supports_tool_call !== undefined ||
        entry.only_reasoning !== undefined ||
        (entry.efforts?.length ?? 0) > 0

      if (snapshotHasCapability) {
        // 新快照：直接来自上游目录（面板 dynModelEntry 同一套字段）
        capabilityIsRaw = true
        if (entry.only_reasoning === true) capabilities.push('纯推理')
        if (entry.supports_images === true) capabilities.push('视觉')
        if (entry.supports_tool_call === true) capabilities.push('函数调用')
        if (entry.supports_reasoning === true) capabilities.push('推理')
        if (entry.can_disable_thinking === true) capabilities.push('思考可关')
        for (const effort of entry.efforts ?? []) capabilities.push(effort)
        if (entry.default_effort) capabilities.push(`默认档:${entry.default_effort}`)
      } else if (model) {
        // 旧快照（未拉到新字段）：退回已导入模型的生效能力——有总比空白强。
        if (model.effective_supports_vision === true) capabilities.push('视觉')
        if (model.effective_supports_function_calling === true) capabilities.push('函数调用')
        if (model.effective_supports_streaming === true) capabilities.push('流式')
        if (model.effective_supports_extended_thinking === true) capabilities.push('扩展思考')
        if (model.effective_supports_image_generation === true) capabilities.push('图像生成')
        if (model.effective_supports_embedding === true) capabilities.push('嵌入')
      }

      const ctx = formatTokens(entry.context_window)
      const out = formatTokens(entry.max_tokens)

      rows.push({
        key: rowKey,
        realm,
        modelUid,
        label: typeof entry.label === 'string' ? entry.label : '',
        vendor: typeof entry.vendor === 'string' ? entry.vendor : '',
        credits: typeof entry.credits === 'string' ? entry.credits : null,
        isDefault: entry.is_default === true,
        // 限时优惠：牌价仍看 credits，生效价看 promo_credits（面板 applyModelPromotions）
        promoFactor: typeof entry.promo_factor === 'number' ? entry.promo_factor : null,
        promoCredits: typeof entry.promo_credits === 'string' ? entry.promo_credits : null,
        promoLabel: typeof entry.promo_label === 'string' ? entry.promo_label : null,
        promoNote: typeof entry.promo_note === 'string' ? entry.promo_note : null,
        planRestricted: entry.plan_restricted === true || (realm === 'global' && WORKBUDDY_PRO_ONLY_MODELS.has(modelUid)),
        planBlocked: Boolean((blocked as Record<string, { kind?: string }>)[modelUid]?.kind === 'plan_blocked'),
        tierBadgeLabel: typeof entry.model_tier?.badge?.label === 'string'
          ? entry.model_tier.badge.label
          : typeof entry.model_tier?.badge?.labelEn === 'string'
            ? entry.model_tier.badge.labelEn
            : null,
        tierBadgeColor: typeof entry.model_tier?.badge?.color === 'string' ? entry.model_tier.badge.color : null,
        tierHoverText: typeof entry.model_tier?.hover?.textZh === 'string'
          ? entry.model_tier.hover.textZh
          : typeof entry.model_tier?.hover?.textEn === 'string'
            ? entry.model_tier.hover.textEn
            : null,
        imported: Boolean(model),
        capabilities,
        capabilityIsRaw,
        contextLabel: [ctx, out].filter(Boolean).join(' / '),
      })
    }
  }

  const realmRank = (realm: string) => (realm === 'cn' ? 0 : realm === 'global' ? 1 : 2)
  return rows.sort(
    (a, b) =>
      realmRank(a.realm) - realmRank(b.realm) ||
      Number(b.isDefault) - Number(a.isDefault) ||
      a.modelUid.localeCompare(b.modelUid),
  )
})

/** 目录里**尚未导入**的行（供批量导入用）。 */
const pendingRows = computed<CatalogRow[]>(() =>
  catalogRows.value.filter(row => !row.imported),
)

// ---------------------------------------------------------------------------
// 模型锁池：按 (域, model) 分组。
// 分母 = **该域可选号**（is_active，面板口径「只看可选号」）；全无可用号 → starved。
// ---------------------------------------------------------------------------
interface LockRow {
  key: string
  realm: string
  model: string
  lockedKeys: number
  totalKeys: number
  firstUnlockAt: number
  fullyUnlockAt: number
  reasons: string[]
  auditOnly: boolean
  /** 该域连一个可选号都没有（不是模型被锁，而是域里没号可用） */
  starved: boolean
}

const lockRows = computed<LockRow[]>(() => {
  const nowSecs = Math.floor(Date.now() / 1000)
  const keys = props.providerKeys ?? []
  const isActive = (key: EndpointAPIKey) => key.is_active !== false

  // 每域可选号分母
  const activeByRealm = new Map<string, number>()
  for (const key of keys) {
    const realm = key.upstream_metadata?.workbuddy?.realm ?? ''
    if (!isActive(key)) continue
    activeByRealm.set(realm, (activeByRealm.get(realm) ?? 0) + 1)
  }

  const byRow = new Map<string, LockRow>()
  const seen = new Set<string>()
  for (const key of keys) {
    const wb = key.upstream_metadata?.workbuddy
    if (!wb) continue
    const entries = wb.model_blocked
    if (!entries || typeof entries !== 'object') continue
    const realm = typeof wb.realm === 'string' ? wb.realm : ''
    for (const [model, raw] of Object.entries(entries as Record<string, unknown>)) {
      if (!raw || typeof raw !== 'object') continue
      const entry = raw as Record<string, unknown>
      const until = typeof entry.until_unix_secs === 'number' ? entry.until_unix_secs : null
      const reason = typeof entry.reason === 'string' ? entry.reason : ''
      const auditOnly = entry.audit_only === true || until === null
      const active = !auditOnly && until !== null && until > nowSecs
      if (!auditOnly && !active) continue
      if (!isActive(key)) continue
      const rowKey = `${realm}:${model}`
      let row = byRow.get(rowKey)
      if (!row) {
        row = {
          key: rowKey,
          realm,
          model,
          lockedKeys: 0,
          totalKeys: activeByRealm.get(realm) ?? 0,
          firstUnlockAt: Number.MAX_SAFE_INTEGER,
          fullyUnlockAt: 0,
          reasons: [],
          auditOnly,
          starved: (activeByRealm.get(realm) ?? 0) === 0,
        }
        byRow.set(rowKey, row)
      }
      const dedupe = `${key.id}:${rowKey}`
      if (seen.has(dedupe)) continue
      seen.add(dedupe)
      row.lockedKeys += 1
      if (reason && !row.reasons.includes(reason)) row.reasons.push(reason)
      if (active && until !== null) {
        row.firstUnlockAt = Math.min(row.firstUnlockAt, until)
        row.fullyUnlockAt = Math.max(row.fullyUnlockAt, until)
      }
    }
  }

  const realmRank = (realm: string) => (realm === 'cn' ? 0 : realm === 'global' ? 1 : 2)
  return Array.from(byRow.values())
    .map(row => ({
      ...row,
      firstUnlockAt: row.firstUnlockAt === Number.MAX_SAFE_INTEGER ? 0 : row.firstUnlockAt,
      auditOnly: row.auditOnly && !row.starved,
    }))
    .sort(
      (a, b) =>
        realmRank(a.realm) - realmRank(b.realm) ||
        b.lockedKeys - a.lockedKeys ||
        a.model.localeCompare(b.model),
    )
})

function lockStateLabel(row: LockRow): string {
  if (row.starved) return '无可用号'
  if (row.auditOnly) return '仅展示'
  if (row.totalKeys > 0 && row.lockedKeys >= row.totalKeys) return '全部锁定'
  return '部分锁定'
}

function lockStateClass(row: LockRow): string {
  if (row.starved) return 'bg-zinc-500/15 text-zinc-600 dark:text-zinc-300'
  if (row.auditOnly) return 'bg-muted text-muted-foreground'
  if (row.totalKeys > 0 && row.lockedKeys >= row.totalKeys) {
    return 'bg-destructive/15 text-destructive'
  }
  return 'bg-amber-500/15 text-amber-700 dark:text-amber-300'
}

function formatUnlock(unixSecs: number): string {
  if (!unixSecs) return '—'
  const date = new Date(unixSecs * 1000)
  const pad = (value: number) => String(value).padStart(2, '0')
  return `${date.getMonth() + 1}-${pad(date.getDate())} ${pad(date.getHours())}:${pad(date.getMinutes())}`
}

// ---------------------------------------------------------------------------
// 账号目录（上游模型目录按 key 拉；导入进来的账号没有 → 这里自动补一次）
// ---------------------------------------------------------------------------
async function forceRefreshCatalogs(): Promise<void> {
  const providerId = props.provider?.id
  const keys = props.providerKeys ?? []
  if (!providerId || keys.length === 0 || forceRefreshing.value) return
  forceRefreshing.value = true
  try {
    for (const key of keys) {
      const result = await fetchUpstreamModels(providerId, key.id, true)
      if (!result.error && result.models.length > 0) {
        const next = new Map(liveCatalogModels.value)
        next.set(key.id, result.models)
        liveCatalogModels.value = next
      }
    }
    emit('refresh-catalog')
    showSuccess(legacyT('已强制刷新全部账号目录'))
  } catch (error) {
    showError(parseApiError(error))
  } finally {
    forceRefreshing.value = false
  }
}

async function fetchMissingCatalogs(): Promise<void> {
  const providerId = props.provider?.id
  const targets = missingCatalogKeys.value.filter(key => !catalogAttempted.value.has(key.id))
  if (!providerId || targets.length === 0 || fetchingCatalog.value) return

  fetchingCatalog.value = true
  targets.forEach(key => catalogAttempted.value.add(key.id))
  try {
    let fetched = 0
    for (const key of targets) {
      // `forceRefresh = true`：绕过后端缓存，确保拿到该域的最新目录。
      const result = await fetchUpstreamModels(providerId, key.id, true)
      if (!result.error) fetched += 1
    }
    // 目录变了 → 让父组件重载 keys/models（`realm` / `models` 都会更新）。
    if (fetched > 0) emit('refresh')
  } finally {
    fetchingCatalog.value = false
  }
}

// 面板一打开就补一次（每个 key 只自动试一次 ✓）；父组件刷新后 keys 变了会再检查 ✓。
onMounted(() => {
  void fetchMissingCatalogs()
})
watch(
  () => missingCatalogKeys.value.map(key => key.id).join(','),
  () => {
    void fetchMissingCatalogs()
  },
)

// ---------------------------------------------------------------------------
// 导入上游模型（目录里「未导入」的行 → 导入到本 provider 的模型列表）
//
// 说明：导入是 **provider 级** 的动作（一个 `model_uid` 导入一次，cn/global 两个域
// 就都算「已导入」了）——所以下面按 `model_uid` **去重**，避免同名两行重复提交。
// 导入成功后请求父组件重载（`models` 变了 `imported` 才会翻成「已导入」）。
// ---------------------------------------------------------------------------
async function importRows(rows: CatalogRow[]): Promise<void> {
  const modelIds = Array.from(new Set(rows.map(row => row.modelUid)))
  if (modelIds.length === 0) return

  const response = await importModelsFromUpstream(props.provider.id, modelIds)
  const okCount = response.success?.length ?? 0
  const failCount = response.errors?.length ?? 0

  if (okCount > 0 && failCount === 0) {
    showSuccess(legacyT(`成功导入 ${okCount} 个模型`), legacyT('导入成功'))
  } else if (okCount > 0) {
    showSuccess(legacyT(`成功导入 ${okCount} 个模型，${failCount} 个失败`), legacyT('导入成功'))
  } else {
    showError(response.errors?.[0]?.error || legacyT('导入失败'), legacyT('导入失败'))
  }
  emit('refresh')
}

async function handleImportRow(row: CatalogRow): Promise<void> {
  if (importingAll.value || importingKeys.value.has(row.key)) return
  importingKeys.value.add(row.key)
  try {
    await importRows([row])
  } catch (err: unknown) {
    showError(parseApiError(err, legacyT('导入失败')), legacyT('错误'))
  } finally {
    importingKeys.value.delete(row.key)
  }
}

async function handleImportMissingRows(): Promise<void> {
  if (importingAll.value || importingKeys.value.size > 0) return
  importingAll.value = true
  try {
    await importRows(pendingRows.value)
  } catch (err: unknown) {
    showError(parseApiError(err, legacyT('导入失败')), legacyT('错误'))
  } finally {
    importingAll.value = false
  }
}
</script>

<style scoped>
/* 表头一律不折行：「导入状态」这类列的内容（未导入/已导入）比表头短，表格被挤压时
   浏览器会优先把表头拆成两行。窄屏应该交给外层 `overflow-x-auto` 横向滚动。 */
th {
  white-space: nowrap;
}
</style>
