<template>
  <Card
    class="overflow-hidden"
    data-testid="opencode-context-retry-panel"
  >
    <div class="p-4 border-b border-border/60">
      <div class="flex items-center justify-between gap-3">
        <h3 class="text-sm font-semibold">
          {{ legacyT('上下文超长重试') }}
        </h3>
        <div class="flex items-center gap-2">
          <Loader2 v-if="loading" class="h-3.5 w-3.5 animate-spin text-muted-foreground" />
          <Switch
            :model-value="policy.enabled"
            :disabled="busy || loading"
            aria-label="OpenCode 上下文重试开关"
            @update:model-value="updatePolicy({ enabled: $event === true })"
          />
        </div>
      </div>
    </div>

    <div class="p-4 space-y-3">
      <p
        v-if="loadError"
        class="text-xs text-destructive"
      >
        {{ loadError }}
      </p>

      <template v-else>
        <div class="grid grid-cols-2 gap-3">
          <div>
            <label class="text-xs text-muted-foreground block mb-1.5">
              {{ legacyT('首次延迟 (毫秒)') }}
            </label>
            <Input
              :model-value="policy.base_ms"
              :disabled="disabled"
              type="number"
              min="1"
              :max="MAX_OPENCODE_CONTEXT_RETRY_DELAY_MS"
              step="1000"
              class="h-8"
              aria-label="OpenCode 首次延迟"
              @update:model-value="updatePolicy({ base_ms: Number($event) })"
            />
          </div>
          <div>
            <label class="text-xs text-muted-foreground block mb-1.5">
              {{ legacyT('倍增倍数') }}
            </label>
            <Input
              :model-value="policy.multiplier"
              :disabled="disabled"
              type="number"
              min="1"
              :max="MAX_OPENCODE_CONTEXT_RETRY_MULTIPLIER"
              step="1"
              class="h-8"
              aria-label="OpenCode 倍增倍数"
              @update:model-value="updatePolicy({ multiplier: Number($event) })"
            />
          </div>
          <div>
            <label class="text-xs text-muted-foreground block mb-1.5">
              {{ legacyT('最大延迟 (毫秒)') }}
            </label>
            <Input
              :model-value="policy.max_ms"
              :disabled="disabled"
              type="number"
              min="1"
              :max="MAX_OPENCODE_CONTEXT_RETRY_DELAY_MS"
              step="1000"
              class="h-8"
              aria-label="OpenCode 最大延迟"
              @update:model-value="updatePolicy({ max_ms: Number($event) })"
            />
          </div>
        </div>

        <p
          v-if="validationError"
          class="text-xs text-destructive"
          role="alert"
        >
          {{ validationError }}
        </p>
        <p
          v-if="saveError"
          class="text-xs text-destructive"
        >
          {{ saveError }}
        </p>

        <div class="flex items-center gap-2 pt-1">
          <span
            v-if="dirty"
            class="text-[11px] text-amber-600 dark:text-amber-500"
          >
            {{ legacyT('有未保存的修改') }}
          </span>
          <span
            v-else-if="savedHint"
            class="text-[11px] text-muted-foreground"
          >
            {{ savedHint }}
          </span>
          <Button
            variant="outline"
            size="sm"
            class="h-8 shrink-0 ml-auto"
            :disabled="busy || !dirty || Boolean(validationError)"
            @click="handleSave"
          >
            <Save v-if="!saving" class="mr-1.5 h-3.5 w-3.5" />
            <Loader2 v-else class="mr-1.5 h-3.5 w-3.5 animate-spin" />
            {{ legacyT('保存重试设置') }}
          </Button>
        </div>
      </template>
    </div>
  </Card>
</template>

<script setup lang="ts">
import { computed, onMounted, ref } from 'vue'
import { Loader2, Save } from 'lucide-vue-next'
import Button from '@/components/ui/button.vue'
import Card from '@/components/ui/card.vue'
import Input from '@/components/ui/input.vue'
import Switch from '@/components/ui/switch.vue'
import { useI18n } from '@/i18n'
import { getErrorMessage } from '@/types/api-error'
import {
  getRoutingGroup,
  listRoutingGroups,
  updateRoutingGroup,
  type RoutingGroupRecord,
} from '@/api/routing-profiles'
import {
  MAX_OPENCODE_CONTEXT_RETRY_DELAY_MS,
  MAX_OPENCODE_CONTEXT_RETRY_MULTIPLIER,
  defaultOpenCodeContextRetryPolicy,
  normalizeOpenCodeContextRetryPolicy,
  type OpenCodeContextRetryPolicy,
  type RoutingFailoverPolicy,
} from '@/features/routing/utils/routingFailover'

const { legacyT } = useI18n()

/**
 * 这段设置存在**系统默认路由组**的 `default_policy.opencode_context_retry` 里，
 * 不是 provider config。
 *
 * 为什么不跟别的 opencode 开关一起写进 provider config：后端读它走的是
 * 「请求的路由策略快照」（`execution_runtime::context_retry`），
 * 换存储位置要动执行路径与配置校验两块，收益只是省一次接口调用。
 * 所以这里就地把路由组读出来、只改这一个字段再写回去。
 */
const loading = ref(true)
const saving = ref(false)
const loadError = ref<string | null>(null)
const saveError = ref<string | null>(null)
const savedHint = ref<string | null>(null)
const groupId = ref<string | null>(null)
/** 服务端当前值，用来判断「有没有改过」。 */
const committed = ref<OpenCodeContextRetryPolicy>(defaultOpenCodeContextRetryPolicy())
const policy = ref<OpenCodeContextRetryPolicy>(defaultOpenCodeContextRetryPolicy())

const disabled = computed(() => !policy.value.enabled)
const busy = computed(() => loading.value || saving.value)

const dirty = computed(
  () => JSON.stringify(policy.value) !== JSON.stringify(committed.value),
)

const validationError = computed(() => {
  if (!policy.value.enabled) return null
  if (!Number.isSafeInteger(policy.value.base_ms) || policy.value.base_ms <= 0) {
    return legacyT('首次延迟必须是正整数')
  }
  if (!Number.isSafeInteger(policy.value.max_ms) || policy.value.max_ms <= 0) {
    return legacyT('最大延迟必须是正整数')
  }
  if (!Number.isSafeInteger(policy.value.multiplier) || policy.value.multiplier <= 0) {
    return legacyT('倍增倍数必须是正整数')
  }
  if (policy.value.base_ms > policy.value.max_ms) {
    return legacyT('首次延迟不能大于最大延迟')
  }
  // 后端还有一份区间校验，这里提前对上，免得白跑一次请求才知道被拒。
  if (policy.value.base_ms > MAX_OPENCODE_CONTEXT_RETRY_DELAY_MS
    || policy.value.max_ms > MAX_OPENCODE_CONTEXT_RETRY_DELAY_MS) {
    return legacyT(`延迟不能超过 ${MAX_OPENCODE_CONTEXT_RETRY_DELAY_MS} 毫秒`)
  }
  if (policy.value.multiplier > MAX_OPENCODE_CONTEXT_RETRY_MULTIPLIER) {
    return legacyT(`倍增倍数不能超过 ${MAX_OPENCODE_CONTEXT_RETRY_MULTIPLIER}`)
  }
  return null
})

function updatePolicy(patch: Partial<OpenCodeContextRetryPolicy>) {
  if (busy.value) return
  saveError.value = null
  savedHint.value = null
  policy.value = { ...policy.value, ...patch }
}

/** 找出承载这套设置的路由组：系统默认组优先，没有就退回第一个。 */
async function resolveGroup(): Promise<RoutingGroupRecord | null> {
  const list = await listRoutingGroups()
  const items = list.items ?? []
  const picked = items.find(group => group.is_system_default) ?? items[0]
  if (!picked) return null
  // 列表接口未必带全 config_json，按 id 再取一次更稳。
  return getRoutingGroup(picked.id)
}

async function loadPolicy() {
  loading.value = true
  loadError.value = null
  try {
    const group = await resolveGroup()
    if (!group) {
      loadError.value = legacyT('没有可用的路由组，无法读取重试设置')
      return
    }
    groupId.value = group.id
    const stored = (group.config_json as { default_policy?: Partial<RoutingFailoverPolicy> } | null)
      ?.default_policy?.opencode_context_retry
    const normalized = normalizeOpenCodeContextRetryPolicy(stored)
    committed.value = normalized
    policy.value = { ...normalized }
  } catch (err) {
    loadError.value = legacyT(`读取重试设置失败：${getErrorMessage(err)}`)
  } finally {
    loading.value = false
  }
}

async function handleSave() {
  if (!groupId.value || validationError.value) return
  saving.value = true
  saveError.value = null
  savedHint.value = null
  try {
    const group = await getRoutingGroup(groupId.value)
    // RoutingGroupConfig 没有索引签名，直接断言成 Record 会被 TS 判为「两边不重叠」。
    // 经 unknown 转一次，语义上就是「把这份配置当普通 JSON 对象改一个字段再写回」。
    const config = (group.config_json ?? {}) as unknown as Record<string, unknown> & {
      default_policy?: Record<string, unknown>
    }
    const nextConfig = {
      ...config,
      default_policy: {
        ...(config.default_policy ?? {}),
        opencode_context_retry: { ...policy.value },
      },
    }
    const saved = await updateRoutingGroup(groupId.value, {
      config_json: nextConfig as never,
      expected_version: group.version,
    })
    const normalized = normalizeOpenCodeContextRetryPolicy(
      (saved.config_json as { default_policy?: Partial<RoutingFailoverPolicy> } | null)
        ?.default_policy?.opencode_context_retry,
    )
    committed.value = normalized
    policy.value = { ...normalized }
    savedHint.value = legacyT('已保存')
  } catch (err) {
    const status = (err as { response?: { status?: number } })?.response?.status
    saveError.value = status === 409
      ? legacyT('该分组已被其他操作更新，请刷新后重试')
      : legacyT(`保存失败：${getErrorMessage(err)}`)
  } finally {
    saving.value = false
  }
}

onMounted(loadPolicy)

defineExpose({ reload: loadPolicy })
</script>
