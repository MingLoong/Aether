<template>
  <div class="flex items-center gap-1 shrink-0">
    <Badge
      v-if="apiKey.circuit_breaker_open"
      variant="destructive"
      class="text-[10px] px-1.5 py-0 shrink-0"
      :title="circuitBreakerTitle"
      data-testid="provider-key-circuit-badge"
    >
      {{ legacyT('熔断') }}{{ circuitProbeCountdown }}
    </Badge>

    <!-- AMD / Cline 不显示健康度：后端执行路径对这两类的密钥从不记录健康/熔断
         （orchestration/effects.rs 的 record_health_failure_effect / record_health_success_effect
         都被 local_execution_plan_tracks_circuit_breaker 判为 false），这里能显示的值只可能
         来自管理侧动作，实测会把一把从未发过请求的 key 画成红色低健康。 -->
    <div
      v-if="showHealthScore"
      class="flex items-center gap-1 mr-1"
      data-testid="provider-key-health"
    >
      <div class="w-10 h-1.5 bg-border rounded-full overflow-hidden">
        <div
          class="h-full transition-all duration-300"
          :class="healthScoreBarClass"
          :style="{ width: `${healthScorePercent}%` }"
        />
      </div>
      <span
        class="text-[10px] font-medium tabular-nums"
        :class="healthScoreTextClass"
      >
        {{ healthScorePercent.toFixed(0) }}%
      </span>
    </div>

    <Button
      v-if="recoverable"
      variant="ghost"
      size="icon"
      class="h-7 w-7 text-green-600"
      :title="recoverTitle"
      @click="$emit('recover')"
    >
      <RefreshCw class="w-3.5 h-3.5" />
    </Button>

    <Button
      variant="ghost"
      size="icon"
      class="h-7 w-7"
      :title="legacyT('模型权限')"
      @click="$emit('permissions')"
    >
      <Shield class="w-3.5 h-3.5" />
    </Button>

    <Popover
      :open="proxyPopoverOpen"
      @update:open="$emit('update:proxyPopoverOpen', $event)"
    >
      <PopoverTrigger as-child>
        <Button
          variant="ghost"
          size="icon"
          class="h-7 w-7"
          :class="apiKey.proxy?.node_id ? 'text-blue-500' : ''"
          :disabled="savingProxy"
          :title="apiKey.proxy?.node_id ? `${legacyT('代理')}: ${proxyNodeName}` : legacyT('设置代理节点')"
          @click.stop
        >
          <Globe class="w-3.5 h-3.5" />
        </Button>
      </PopoverTrigger>
      <PopoverContent
        class="w-72 p-3"
        side="bottom"
        align="end"
      >
        <div class="space-y-2">
          <div class="flex items-center justify-between">
            <span class="text-xs font-medium">{{ legacyT('代理节点') }}</span>
            <Button
              v-if="apiKey.proxy?.node_id"
              variant="ghost"
              size="sm"
              class="h-6 px-2 text-[10px] text-muted-foreground"
              :disabled="savingProxy"
              @click="$emit('clearProxy')"
            >
              {{ legacyT('清除') }}
            </Button>
          </div>
          <ProxyNodeSelect
            :model-value="apiKey.proxy?.node_id || ''"
            trigger-class="h-8"
            @update:model-value="$emit('setProxy', $event)"
          />
          <p class="text-[10px] text-muted-foreground">
            {{ legacyT(apiKey.proxy?.node_id ? '当前使用独立代理' : '未设置，使用提供商级别代理') }}
          </p>
        </div>
      </PopoverContent>
    </Popover>

    <Button
      variant="ghost"
      size="icon"
      class="h-7 w-7"
      :title="legacyT('编辑密钥')"
      @click="$emit('edit')"
    >
      <Edit class="w-3.5 h-3.5" />
    </Button>

    <Button
      v-if="providerType === 'antigravity'"
      variant="ghost"
      size="icon"
      class="h-7 w-7"
      :title="legacyT('配额详情')"
      @click="$emit('openAntigravityQuota')"
    >
      <BarChart3 class="w-3.5 h-3.5" />
    </Button>

    <Button
      variant="ghost"
      size="icon"
      class="h-7 w-7"
      :disabled="toggling"
      :title="legacyT(apiKey.is_active ? '点击停用' : '点击启用')"
      :aria-label="legacyT(apiKey.is_active ? '点击停用' : '点击启用')"
      data-testid="provider-key-toggle-active"
      @click="$emit('toggleActive')"
    >
      <Power class="w-3.5 h-3.5" />
    </Button>

    <Button
      variant="ghost"
      size="icon"
      class="h-7 w-7"
      :title="legacyT('删除密钥')"
      @click="$emit('delete')"
    >
      <Trash2 class="w-3.5 h-3.5" />
    </Button>
  </div>
</template>

<script setup lang="ts">
import { computed } from 'vue'
import {
  BarChart3,
  Edit,
  Globe,
  Power,
  RefreshCw,
  Shield,
  Trash2,
} from 'lucide-vue-next'
import Button from '@/components/ui/button.vue'
import Badge from '@/components/ui/badge.vue'
import { Popover, PopoverTrigger, PopoverContent } from '@/components/ui'
import { useI18n } from '@/i18n'
import type { EndpointAPIKey } from '@/api/endpoints'
import ProxyNodeSelect from '@/features/providers/components/ProxyNodeSelect.vue'
import { isKeyHealthTrackingDisabledProviderType } from '@/features/providers/utils/providerTypeUtils'

const props = withDefaults(defineProps<{
  apiKey: EndpointAPIKey
  providerType?: string | null
  recoverable?: boolean
  recoverTitle?: string
  circuitBreakerTitle?: string
  circuitProbeCountdown?: string
  healthScoreBarClass?: string
  healthScoreTextClass?: string
  proxyPopoverOpen?: boolean
  proxyNodeName?: string
  savingProxy?: boolean
  toggling?: boolean
}>(), {
  providerType: null,
  recoverable: false,
  recoverTitle: '',
  circuitBreakerTitle: '',
  circuitProbeCountdown: '',
  healthScoreBarClass: '',
  healthScoreTextClass: '',
  proxyPopoverOpen: false,
  proxyNodeName: '',
  savingProxy: false,
  toggling: false,
})

defineEmits<{
  (e: 'recover'): void
  (e: 'permissions'): void
  (e: 'update:proxyPopoverOpen', value: boolean): void
  (e: 'clearProxy'): void
  (e: 'setProxy', nodeId: string): void
  (e: 'edit'): void
  (e: 'openAntigravityQuota'): void
  (e: 'toggleActive'): void
  (e: 'delete'): void
}>()

const { legacyT } = useI18n()

/**
 * 是否显示健康度：`amd` 与 `cline` 都不显示（判据 `isKeyHealthTrackingDisabledProviderType`，
 * 与后端 `amd_rotation::provider_type_exempt_from_key_health_and_pool` 同一份名单）。
 *
 * 后端执行路径对这两类的密钥既不记失败也不记成功
 * （`orchestration/effects.rs` 的 `local_execution_plan_tracks_circuit_breaker()` 返回 false），
 * 所以这里的 `health_score` 只可能是管理侧动作留下的陈旧值 —— 实测有一把
 * `last_used_at` 为空（从未被使用）的 AMD key 显示成 40%，Cline 验证时那把也停在 25%。
 * 显示它等于把「从未发过请求的账号」误报成不健康，因此这两类直接不画这条。
 *
 * 健康/熔断属于**行为**判据，后端只认 `provider_type`，带 base_url 兼容分支会让界面与后端脱节。
 */
const showHealthScore = computed(
  () =>
    !isKeyHealthTrackingDisabledProviderType(props.providerType)
    && props.apiKey.health_score !== undefined,
)

const healthScorePercent = computed(() => {
  const score = Number(props.apiKey.health_score ?? 0)
  if (!Number.isFinite(score)) return 0
  return Math.min(Math.max(score * 100, 0), 100)
})
</script>
