<template>
  <div class="px-4 sm:px-6 py-3 sm:py-3.5 border-b border-border/60">
    <div class="flex flex-col gap-3 xl:hidden">
      <div class="min-w-0">
        <div class="flex min-w-0 items-center gap-2">
          <h3 class="text-base font-semibold">
            {{ legacyT('号池管理') }}
          </h3>
          <!-- 当前上游：CodeBuddy / WorkBuddy 是两个实例，标题上必须一眼看出在哪个上游 -->
          <span
            v-if="upstreamLabel"
            class="shrink-0 rounded-full border border-primary/30 bg-primary/10 px-2 py-0.5 text-[10px] font-medium leading-4 text-primary"
            :title="upstreamDetailLabel || upstreamLabel"
            data-testid="pool-upstream-badge-mobile"
          >{{ upstreamLabel }}</span>
          <span
            v-if="selectedCount > 0"
            class="shrink-0 text-xs font-medium tabular-nums text-primary"
            aria-live="polite"
            data-testid="pool-selected-count-mobile"
          >
            {{ selectedCountLabel }}
          </span>
        </div>
        <p
          v-if="metaText"
          class="mt-1 text-xs text-muted-foreground"
        >
          {{ metaText }}
        </p>
      </div>

      <div class="grid grid-cols-3 items-center gap-2">
        <Select
          v-model="providerModel"
          :disabled="providerSelectDisabled"
        >
          <SelectTrigger
            class="h-9 text-xs border-border/60"
            :disabled="providerSelectDisabled"
          >
            <SelectValue :placeholder="legacyT('选择 Provider')" />
          </SelectTrigger>
          <SelectContent>
            <SelectItem
              v-for="item in providers"
              :key="item.provider_id"
              :value="item.provider_id"
            >
              {{ providerOptionLabel(item) }}
              <span class="text-muted-foreground ml-1">({{ item.total_keys }})</span>
              <span
                v-if="!item.pool_enabled"
                class="ml-1 text-[10px] text-amber-600"
              >{{ legacyT('未启用') }}</span>
            </SelectItem>
          </SelectContent>
        </Select>

        <Select v-model="statusModel">
          <SelectTrigger class="h-9 w-full text-xs border-border/60">
            <SelectValue :placeholder="legacyT('状态')" />
          </SelectTrigger>
          <SelectContent>
            <SelectItem
              v-for="item in statusOptions"
              :key="`mobile-${item.value}`"
              :value="item.value"
            >
              {{ legacyT(item.label) }}
            </SelectItem>
          </SelectContent>
        </Select>

        <div class="relative min-w-0">
          <Search class="absolute left-2.5 top-1/2 -translate-y-1/2 h-3.5 w-3.5 text-muted-foreground z-10 pointer-events-none" />
          <Input
            v-model="searchModel"
            type="text"
            :placeholder="legacyT('搜索账号...')"
            class="w-full pl-8 pr-3 h-9 text-sm bg-background/50 border-border/60"
          />
        </div>
      </div>

      <div
        v-if="hasSelectedProvider"
        class="flex items-center gap-1"
      >
        <div
          v-for="action in mobileActions"
          :key="action.key"
          class="min-w-0 flex-1 flex justify-center"
        >
          <Button
            variant="ghost"
            size="icon"
            class="h-8 w-8 shrink-0"
            :title="action.title"
            @pointerenter="action.key === 'viewProvider' && emit('prefetchProvider')"
            @focus="action.key === 'viewProvider' && emit('prefetchProvider')"
            @click="triggerAction(action.event)"
          >
            <component
              :is="action.icon"
              class="w-3.5 h-3.5"
            />
          </Button>
        </div>

        <div class="min-w-0 flex-1 flex justify-center">
          <Button
            variant="ghost"
            size="icon"
            class="h-8 w-8 shrink-0"
            :class="isAllFilteredSelected ? 'bg-primary/10 text-primary' : ''"
            :disabled="selectionDisabled"
            :aria-pressed="isAllFilteredSelected"
            :title="legacyT(isAllFilteredSelected ? '取消全选' : '全选')"
            data-testid="pool-select-all-mobile"
            @click="emit('toggleSelectAll')"
          >
            <SquareCheckBig class="h-3.5 w-3.5" />
          </Button>
        </div>

        <div class="min-w-0 flex-1 flex justify-center">
          <DropdownMenu :modal="false">
            <DropdownMenuTrigger
              as-child
              :disabled="batchActionsDisabled"
            >
              <Button
                variant="ghost"
                size="icon"
                class="h-8 w-8 shrink-0"
                :disabled="batchActionsDisabled"
                :title="legacyT('选择执行动作')"
                :aria-label="legacyT('选择执行动作')"
                data-testid="pool-batch-actions-mobile"
              >
                <ListChecks class="h-3.5 w-3.5" />
              </Button>
            </DropdownMenuTrigger>
            <DropdownMenuContent
              align="end"
              class="w-48"
            >
              <DropdownMenuItem
                v-for="action in visibleBatchActions"
                :key="`mobile-${action.value}`"
                :class="action.destructive ? 'text-destructive focus:text-destructive' : ''"
                :data-testid="`pool-batch-action-${action.value}-mobile`"
                @select="emit('batchAction', action.value)"
              >
                {{ legacyT(action.label) }}
              </DropdownMenuItem>
            </DropdownMenuContent>
          </DropdownMenu>
        </div>

        <div class="min-w-0 flex-1 flex justify-center">
          <RefreshButton
            :loading="refreshLoading"
            :title="refreshTitle"
            @click="emit('refresh')"
          />
        </div>
      </div>
    </div>

    <div class="hidden xl:flex items-center justify-between gap-4">
      <div class="flex items-center gap-2">
        <h3 class="text-base font-semibold">
          {{ legacyT('号池管理') }}
          <!-- 当前上游（CodeBuddy / WorkBuddy）：两个实例的名字常常看不出区别，这里点名 -->
          <span
            v-if="upstreamLabel"
            class="ml-2 rounded-full border border-primary/30 bg-primary/10 px-2 py-0.5 align-middle text-[10px] font-medium text-primary"
            :title="upstreamDetailLabel || upstreamLabel"
            data-testid="pool-upstream-badge-desktop"
          >{{ upstreamLabel }}</span>
          <span
            v-if="metaText"
            class="ml-2 text-xs font-normal text-muted-foreground"
          >
            | {{ metaText }}
          </span>
        </h3>
      </div>

      <div
        class="flex items-center gap-2"
        data-testid="pool-header-actions"
      >
        <Select
          v-model="providerModel"
          :disabled="providerSelectDisabled"
        >
          <SelectTrigger
            class="w-36 h-8 text-xs border-border/60"
            :disabled="providerSelectDisabled"
          >
            <SelectValue :placeholder="legacyT('选择 Provider')" />
          </SelectTrigger>
          <SelectContent>
            <SelectItem
              v-for="item in providers"
              :key="item.provider_id"
              :value="item.provider_id"
            >
              {{ providerOptionLabel(item) }}
              <span class="text-muted-foreground ml-1">({{ item.total_keys }})</span>
              <span
                v-if="!item.pool_enabled"
                class="ml-1 text-[10px] text-amber-600"
              >{{ legacyT('未启用') }}</span>
            </SelectItem>
          </SelectContent>
        </Select>

        <div class="h-4 w-px bg-border" />

        <div
          v-if="hasSelectedProvider"
          class="relative"
        >
          <Search class="absolute left-2.5 top-1/2 -translate-y-1/2 h-3.5 w-3.5 text-muted-foreground z-10 pointer-events-none" />
          <Input
            v-model="searchModel"
            type="text"
            :placeholder="legacyT('搜索账号...')"
            class="w-40 pl-8 pr-2 h-8 text-xs bg-background/50 border-border/60"
          />
        </div>

        <div
          v-if="hasSelectedProvider"
          class="h-4 w-px bg-border"
        />

        <button
          v-if="hasSelectedProvider"
          class="group inline-flex items-center gap-1.5 px-2.5 h-8 rounded-md border border-border/50 bg-muted/20 hover:bg-muted/40 hover:border-primary/40 transition-all duration-200 text-xs"
          type="button"
          :title="legacyT('点击调整号池调度')"
          @click="emit('scheduling')"
        >
          <span class="text-muted-foreground/80 hidden lg:inline">{{ legacyT('调度:') }}</span>
          <span class="font-medium text-foreground/90">{{ poolSchedulingLabel }}</span>
          <ChevronDown class="w-3 h-3 text-muted-foreground/70 group-hover:text-foreground transition-colors" />
        </button>

        <div
          v-if="hasSelectedProvider"
          class="h-4 w-px bg-border"
        />

        <Button
          v-for="action in desktopActions"
          v-show="hasSelectedProvider"
          :key="action.key"
          variant="ghost"
          size="icon"
          class="h-8 w-8"
          :data-testid="action.key === 'demandMetrics' ? 'pool-demand-metrics-button' : undefined"
          :title="action.title"
          @pointerenter="action.key === 'viewProvider' && emit('prefetchProvider')"
          @focus="action.key === 'viewProvider' && emit('prefetchProvider')"
          @click="triggerAction(action.event)"
        >
          <component
            :is="action.icon"
            class="w-3.5 h-3.5"
          />
        </Button>

        <Button
          v-if="hasSelectedProvider"
          variant="ghost"
          size="icon"
          class="h-8 w-8"
          :class="isAllFilteredSelected ? 'bg-primary/10 text-primary' : ''"
          :disabled="selectionDisabled"
          :aria-pressed="isAllFilteredSelected"
          :title="legacyT(isAllFilteredSelected ? '取消全选' : '全选')"
          data-testid="pool-select-all-desktop"
          @click="emit('toggleSelectAll')"
        >
          <SquareCheckBig class="h-3.5 w-3.5" />
        </Button>

        <DropdownMenu
          v-if="hasSelectedProvider"
          :modal="false"
        >
          <DropdownMenuTrigger
            as-child
            :disabled="batchActionsDisabled"
          >
            <Button
              variant="ghost"
              size="icon"
              class="h-8 w-8"
              :disabled="batchActionsDisabled"
              :title="legacyT('选择执行动作')"
              :aria-label="legacyT('选择执行动作')"
              data-testid="pool-batch-actions-desktop"
            >
              <ListChecks class="h-3.5 w-3.5" />
            </Button>
          </DropdownMenuTrigger>
          <DropdownMenuContent
            align="end"
            class="w-48"
          >
            <DropdownMenuItem
              v-for="action in visibleBatchActions"
              :key="`desktop-${action.value}`"
              :class="action.destructive ? 'text-destructive focus:text-destructive' : ''"
              :data-testid="`pool-batch-action-${action.value}-desktop`"
              @select="emit('batchAction', action.value)"
            >
              {{ legacyT(action.label) }}
            </DropdownMenuItem>
          </DropdownMenuContent>
        </DropdownMenu>

        <RefreshButton
          :loading="refreshLoading"
          :title="refreshTitle"
          @click="emit('refresh')"
        />
      </div>
    </div>
  </div>
</template>

<script setup lang="ts">
import { computed } from 'vue'
import {
  Activity,
  ChevronDown,
  Eye,
  ListChecks,
  Search,
  Settings2,
  SlidersHorizontal,
  SquareCheckBig,
  Upload,
} from 'lucide-vue-next'
import {
  Button,
  DropdownMenu,
  DropdownMenuContent,
  DropdownMenuItem,
  DropdownMenuTrigger,
  Input,
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
  SelectValue,
} from '@/components/ui'
import RefreshButton from '@/components/ui/refresh-button.vue'
import { useI18n } from '@/i18n'
import type { PoolOverviewItem } from '@/api/endpoints/pool'
import {
  POOL_BATCH_ACTION_OPTIONS,
  type PoolBatchActionValue,
} from '@/features/pool/utils/poolBatchActions'

type HeaderActionEvent =
  | 'import'
  | 'scheduling'
  | 'viewProvider'
  | 'demandMetrics'
  | 'advanced'

type HeaderActionKey =
  | 'import'
  | 'scheduling'
  | 'viewProvider'
  | 'demandMetrics'
  | 'advanced'

interface HeaderAction {
  key: HeaderActionKey
  title: string
  event: HeaderActionEvent
  icon: unknown
}

const props = withDefaults(defineProps<{
  providers: PoolOverviewItem[]
  providerId: string
  providerSelectDisabled: boolean
  status: string
  statusOptions: Array<{ value: string, label: string }>
  search: string
  metaText?: string
  poolSchedulingLabel: string
  showAdaptiveHotPoolMetricsButton: boolean
  selectedCount?: number
  isAllFilteredSelected: boolean
  selectionDisabled: boolean
  batchActionsDisabled: boolean
  refreshLoading: boolean
  refreshTitle: string
  /** 当前实例的上游品牌（CodeBuddy / WorkBuddy）；非 workbuddy 实例为空 */
  upstreamLabel?: string
  /**
   * 带区域的完整上游名（`CodeBuddy 国内版 (CN)` / `WorkBuddy 国际版 (Global)`）。
   *
   * 徽章上只放品牌（省地方），但「导入账号」的悬停提示要能一眼分清区域 ——
   * 两个实例挨着排，工具提示里少一个词就可能点到另一家。
   */
  upstreamDetailLabel?: string
  /** provider_id → 展示名（号池概览不带 realm，品牌名由页面侧补） */
  providerLabels?: Record<string, string>
}>(), {
  metaText: '',
  selectedCount: 0,
  upstreamLabel: '',
  upstreamDetailLabel: '',
  providerLabels: () => ({}),
})

const emit = defineEmits<{
  'update:providerId': [value: string]
  'update:status': [value: string]
  'update:search': [value: string]
  import: []
  prefetchProvider: []
  scheduling: []
  viewProvider: []
  demandMetrics: []
  advanced: []
  toggleSelectAll: []
  batchAction: [action: PoolBatchActionValue]
  refresh: []
}>()

function triggerAction(event: HeaderActionEvent) {
  const handlers = {
    import: () => emit('import'),
    scheduling: () => emit('scheduling'),
    viewProvider: () => emit('viewProvider'),
    demandMetrics: () => emit('demandMetrics'),
    advanced: () => emit('advanced'),
  }
  handlers[event]()
}

const { legacyT } = useI18n()

const providerModel = computed({
  get: () => props.providerId,
  set: value => emit('update:providerId', value),
})

const statusModel = computed({
  get: () => props.status,
  set: value => emit('update:status', value),
})

const searchModel = computed({
  get: () => props.search,
  set: value => emit('update:search', value),
})

const hasSelectedProvider = computed(() => Boolean(props.providerId))

// cline 走独立调度：高级设置里的评分/探测/自检等一律不适用，隐藏「高级设置」入口。
const selectedProviderType = computed(() => {
  const provider = props.providers.find(item => item.provider_id === props.providerId)
  return (provider?.provider_type || '').trim().toLowerCase()
})
const isClineSelected = computed(() => selectedProviderType.value === 'cline')

// cline 没有额度显示，去掉「刷新额度」批量动作；其余动作通用。
const visibleBatchActions = computed(() => (
  isClineSelected.value
    ? POOL_BATCH_ACTION_OPTIONS.filter(action => action.value !== 'refresh_quota')
    : POOL_BATCH_ACTION_OPTIONS
))

const selectedCountLabel = computed(() => legacyT(`已选 ${Math.max(0, props.selectedCount)} 个`))

/** 下拉项展示名：能拿到品牌就显示品牌（CodeBuddy / WorkBuddy），否则退回 provider_name。 */
function providerOptionLabel(item: PoolOverviewItem): string {
  return props.providerLabels?.[item.provider_id] || item.provider_name
}

/**
 * 「导入账号」的悬浮提示带上本次目标上游（含区域）。
 *
 * 为什么：两个上游是两个实例，点错一个就是加错号（后端会直接跨域拒掉）。
 * 没有上游概念（非 workbuddy）时保持原样，标题仍是「导入账号」。
 */
const importActionTitle = computed(() => {
  const target = props.upstreamDetailLabel || props.upstreamLabel
  return target ? `${legacyT('导入账号')} · ${target}` : legacyT('导入账号')
})

const mobileActions = computed<HeaderAction[]>(() => {
  const actions: HeaderAction[] = [
    { key: 'viewProvider', title: legacyT('查看详情'), event: 'viewProvider', icon: Eye },
    { key: 'import', title: importActionTitle.value, event: 'import', icon: Upload },
    { key: 'scheduling', title: legacyT('号池调度'), event: 'scheduling', icon: SlidersHorizontal },
  ]
  if (props.showAdaptiveHotPoolMetricsButton) {
    actions.push({ key: 'demandMetrics', title: legacyT('查看自适应热池指标'), event: 'demandMetrics', icon: Activity })
  }
  if (!isClineSelected.value) {
    actions.push(
      { key: 'advanced', title: legacyT('高级设置'), event: 'advanced', icon: Settings2 },
    )
  }
  return actions
})

const desktopActions = computed<HeaderAction[]>(() => {
  const actions: HeaderAction[] = [
    { key: 'viewProvider', title: legacyT('查看详情'), event: 'viewProvider', icon: Eye },
    { key: 'import', title: importActionTitle.value, event: 'import', icon: Upload },
  ]
  if (props.showAdaptiveHotPoolMetricsButton) {
    actions.push({ key: 'demandMetrics', title: legacyT('查看自适应热池指标'), event: 'demandMetrics', icon: Activity })
  }
  if (!isClineSelected.value) {
    actions.push(
      { key: 'advanced', title: legacyT('高级设置'), event: 'advanced', icon: Settings2 },
    )
  }
  return actions
})
</script>
