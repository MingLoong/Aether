<template>
  <Card class="overflow-hidden">
    <div class="flex items-center justify-between px-4 py-3 border-b border-border/60">
      <div class="flex items-center gap-2">
        <Gauge class="h-4 w-4 text-muted-foreground" />
        <span class="text-sm font-medium">{{ legacyT('AMD 模型负载') }}</span>
        <Badge v-if="!loaded" variant="outline" class="text-[10px] h-4 px-1.5">
          {{ legacyT('读取中') }}
        </Badge>
        <Badge v-else-if="!status?.is_amd_upstream" variant="outline" class="text-[10px] h-4 px-1.5">
          {{ legacyT('非 AMD 上游') }}
        </Badge>
        <Badge v-else-if="status?.snapshot_expired" variant="outline" class="text-[10px] h-4 px-1.5">
          {{ legacyT('快照已过期') }}
        </Badge>
        <Badge v-else class="secondary" class="text-[10px] h-4 px-1.5">
          {{ legacyT('快照有效') }}
        </Badge>
      </div>
      <Button variant="outline" size="sm" :disabled="refreshing" @click="refreshNow">
        <Loader2 v-if="refreshing" class="h-3.5 w-3.5 animate-spin" />
        <RefreshCw v-else class="h-3.5 w-3.5" />
        {{ legacyT('立即刷新') }}
      </Button>
    </div>

    <div class="p-4 space-y-4">
      <!-- 上游地址不对时先说清原因，不然用户只会看到「刷新没反应」。 -->
      <p v-if="loaded && !status?.is_amd_upstream" class="text-[11px] text-amber-600">
        {{
          legacyT(
            '该供应商的端点不是 AMD 上游：负载接口只对 /radeon/api/v1 形式的地址有效。',
          )
        }}
      </p>

      <!-- 配置告警：阈值倒挂、采样太频繁这类问题放这里，而不是等到判定出错才发现。 -->
      <div v-if="warnings.length" class="rounded-md border border-amber-500/40 bg-amber-500/5 p-2.5">
        <p v-for="warning in warnings" :key="warning" class="text-[11px] text-amber-600">
          {{ warning }}
        </p>
      </div>

      <div class="flex items-center gap-2">
        <Switch v-model="enabled" />
        <span class="text-xs">{{ legacyT('启用负载感知') }}</span>
      </div>
      <p class="text-[11px] text-muted-foreground">
        {{
          legacyT(
            '按真实请求的首字节之外的另一路信号：定期拉取 AMD 的 fleet 级负载，容量占用持续越线的模型在这家供应商上被临时停用。',
          )
        }}
      </p>

      <div class="grid grid-cols-2 gap-3">
        <div>
          <label class="text-xs text-muted-foreground block mb-1.5">
            {{ legacyT('禁用阈值 (%)') }}
          </label>
          <Input v-model="disableThreshold" type="number" min="1" max="100" step="0.5" class="h-8" />
          <p class="text-[11px] text-muted-foreground mt-1">
            {{ legacyT('容量占用达到此值即进入禁用判定。state 为 full 时直接禁用，不看百分比。') }}
          </p>
        </div>
        <div>
          <label class="text-xs text-muted-foreground block mb-1.5">
            {{ legacyT('恢复阈值 (%)') }}
          </label>
          <Input v-model="recoveryThreshold" type="number" min="0" max="100" step="0.5" class="h-8" />
          <p class="text-[11px] text-muted-foreground mt-1">
            {{
              legacyT('留空表示单阈值模式：低于禁用阈值即放行。填了才启用滞回，避免模型在阈值附近反复进出。')
            }}
          </p>
        </div>
        <div>
          <label class="text-xs text-muted-foreground block mb-1.5">
            {{ legacyT('连续越线次数') }}
          </label>
          <Input v-model="disableStreak" type="number" min="1" max="10" class="h-8" />
          <p class="text-[11px] text-muted-foreground mt-1">
            {{ legacyT('连续这么多次越线才禁用。主力模型常常在阈值附近抖动，阻尼是必要的。') }}
          </p>
        </div>
        <div>
          <label class="text-xs text-muted-foreground block mb-1.5">
            {{ legacyT('轮询间隔 (秒)') }}
          </label>
          <Input v-model="pollSec" type="number" min="30" max="3600" class="h-8" />
          <p class="text-[11px] text-muted-foreground mt-1">
            {{ legacyT('负载接口单次要 20 秒以上，别设得比快照有效期还短。') }}
          </p>
        </div>
        <div>
          <label class="text-xs text-muted-foreground block mb-1.5">
            {{ legacyT('快照有效期 (秒)') }}
          </label>
          <Input v-model="snapshotTtlSec" type="number" min="30" max="3600" class="h-8" />
          <p class="text-[11px] text-muted-foreground mt-1">
            {{ legacyT('超过这个时间没拉到新快照，就不再参与判定（失败开放，不误伤）。') }}
          </p>
        </div>
        <div>
          <label class="text-xs text-muted-foreground block mb-1.5">
            {{ legacyT('请求超时 (秒)') }}
          </label>
          <Input v-model="timeoutSec" type="number" min="10" max="120" class="h-8" />
          <p class="text-[11px] text-muted-foreground mt-1">
            {{ legacyT('实测单次负载查询 20.5–23.3 秒，超时别低于这个量级。') }}
          </p>
        </div>
      </div>

      <!-- 模型负载 -->
      <div v-if="models.length" class="text-xs">
        <div class="flex items-center justify-between pb-1.5">
          <span class="text-muted-foreground">{{ legacyT('模型负载') }}</span>
          <span class="text-[11px] text-muted-foreground">
            <!-- 刻意用静态文案 + 数字，不做插值：翻译目录按字面量匹配，插值出来的
                 字符串永远查不到，英文界面就会露出中文。 -->
            {{ legacyT('已禁用') }} {{ blockedCount }}
          </span>
        </div>
        <!-- 表头三列与下面的行用同一套 grid，且行内粘在顶部，避免表格行多时表头随滚动消失。 -->
        <div class="max-h-64 overflow-y-auto">
          <div
            class="grid grid-cols-[1fr_5rem_4.5rem] items-center gap-2 py-1 sticky top-0 z-10 bg-card border-b border-border/40 text-muted-foreground"
          >
            <span>{{ legacyT('模型') }}</span>
            <span class="text-center">{{ legacyT('占用') }}</span>
            <span class="text-center">{{ legacyT('标记') }}</span>
          </div>
          <div
            v-for="row in models"
            :key="row.model"
            class="grid grid-cols-[1fr_5rem_4.5rem] items-center gap-2 py-1 border-b border-border/20 last:border-0"
          >
            <span class="truncate">{{ row.model }}</span>
            <span
              class="font-mono tabular-nums text-center"
              :class="row.blocked ? 'text-amber-600' : 'text-muted-foreground'"
            >
              {{ row.utilization.toFixed(1) }}%
            </span>
            <span class="flex justify-center">
              <Badge v-if="row.blocked" variant="outline" class="text-[10px] h-4 px-1.5">
                {{ legacyT('禁用') }}
              </Badge>
              <Badge v-else-if="row.state" variant="secondary" class="text-[10px] h-4 px-1.5">
                {{ row.state }}
              </Badge>
            </span>
          </div>
        </div>
      </div>
      <p v-else-if="loaded && status?.is_amd_upstream" class="text-[11px] text-muted-foreground">
        {{ legacyT('还没有负载快照：启用后点「立即刷新」拉一次。') }}
      </p>

      <!-- 保存按钮放在所有可改字段之后，而不是夹在配置块中间：它管的是整卡设置，
           用户改完最下面的输入框要往上翻才找得到，找不到就以为没生效。 -->
      <div class="flex items-center gap-2 pt-1">
        <Button size="sm" :disabled="saving || !dirty" @click="save">
          <Loader2 v-if="saving" class="h-3.5 w-3.5 animate-spin" />
          <Save v-else class="h-3.5 w-3.5" />
          {{ legacyT('保存') }}
        </Button>
        <span v-if="dirty" class="text-[11px] text-amber-600">{{ legacyT('有未保存的修改') }}</span>
      </div>
    </div>
  </Card>
</template>

<script setup lang="ts">
import { computed, onMounted, ref, watch } from 'vue'
import Badge from '@/components/ui/badge.vue'
import Button from '@/components/ui/button.vue'
import Card from '@/components/ui/card.vue'
import Input from '@/components/ui/input.vue'
import Switch from '@/components/ui/switch.vue'
import { Gauge, Loader2, RefreshCw, Save } from 'lucide-vue-next'
import { useI18n } from '@/i18n'
import {
  getAmdLoadStatus,
  refreshAmdLoadSnapshot,
  saveAmdLoadConfig,
  type AmdLoadConfigPayload,
  type AmdLoadModelStatus,
  type AmdLoadStatus,
} from '@/api/endpoints'
import type { ProviderWithEndpointsSummary } from '@/api/endpoints/types'
import { getErrorMessage } from '@/types/api-error'

const props = defineProps<{ provider: ProviderWithEndpointsSummary }>()
const { legacyT } = useI18n()

const status = ref<AmdLoadStatus | null>(null)
const lastServerStatus = ref<AmdLoadStatus | null>(null)
const loaded = ref(false)
const saving = ref(false)
const refreshing = ref(false)

const enabled = ref(false)
const disableThreshold = ref('85')
const recoveryThreshold = ref('')
const disableStreak = ref('2')
const pollSec = ref('60')
const snapshotTtlSec = ref('180')
const timeoutSec = ref('40')

const models = computed<AmdLoadModelStatus[]>(() => status.value?.models ?? [])
const blockedCount = computed(() => status.value?.blocked_models?.length ?? 0)
const warnings = computed<string[]>(() => status.value?.warnings ?? [])

/**
 * 用户改过、但还没保存的字段不能被一次后台刷新静默丢掉。
 *
 * 判据是「本地值是否还等于上次拿到的服务端值」：相等说明用户没动过，可以放心覆盖；
 * 不等就是他正在编辑，必须留着。保存成功后的下一次刷新会自动恢复同步——那时本地值
 * 已经等于新的服务端值——所以不需要额外的「已编辑」标记，也不会忘记复位。
 */
function keepUserEdit<T>(localValue: T, previousServerValue: T, nextServerValue: T): T {
  if (previousServerValue === undefined) return nextServerValue
  return localValue === previousServerValue ? nextServerValue : localValue
}

const currentPayload = computed<AmdLoadConfigPayload>(() => {
  // Input 的 emit 永远是 string（`update:modelValue: [value: string]`），所以
  // `v-model.number` 并不生效，得在这里显式 Number()。而且必须先判空串：
  // Number('') 是 0，直接转换会把「留空表示单阈值模式」变成恢复阈值 0。
  const threshold = Number(disableThreshold.value)
  const recovery = recoveryThreshold.value.trim()
  const streak = Number(disableStreak.value)
  const poll = Number(pollSec.value)
  const ttl = Number(snapshotTtlSec.value)
  const timeout = Number(timeoutSec.value)
  const payload: AmdLoadConfigPayload = {
    enabled: enabled.value,
    disable_streak: Number.isFinite(streak) && streak > 0 ? streak : undefined,
    poll_sec: Number.isFinite(poll) && poll > 0 ? poll : undefined,
    snapshot_ttl_sec: Number.isFinite(ttl) && ttl > 0 ? ttl : undefined,
    timeout_sec: Number.isFinite(timeout) && timeout > 0 ? timeout : undefined,
  }
  if (Number.isFinite(threshold) && threshold > 0) {
    payload.disable_threshold = threshold
  }
  if (recovery === '') {
    payload.recovery_threshold = null
  } else {
    const value = Number(recovery)
    if (Number.isFinite(value)) payload.recovery_threshold = value
  }
  return payload
})

const dirty = computed(() => {
  const server = lastServerStatus.value?.config
  if (!server) return false
  const mine = currentPayload.value
  if (mine.enabled !== server.enabled) return true
  if (mine.disable_threshold !== undefined && mine.disable_threshold !== server.disable_threshold) {
    return true
  }
  if (mine.disable_streak !== undefined && mine.disable_streak !== server.disable_streak) return true
  if (mine.poll_sec !== undefined && mine.poll_sec !== server.poll_sec) return true
  if (mine.snapshot_ttl_sec !== undefined && mine.snapshot_ttl_sec !== server.snapshot_ttl_sec) {
    return true
  }
  if (mine.timeout_sec !== undefined && mine.timeout_sec !== server.timeout_sec) return true
  // 服务端没配恢复阈值时是 null；用户填了任意数字都算改动。
  return mine.recovery_threshold !== server.recovery_threshold
})

async function loadStatus() {
  try {
    const next = await getAmdLoadStatus(props.provider.id)
    const previous = lastServerStatus.value
    const server = next.config
    enabled.value = keepUserEdit(enabled.value, previous?.config.enabled ?? false, server.enabled)
    disableThreshold.value = keepUserEdit(
      disableThreshold.value,
      previous?.config.disable_threshold === undefined
        ? undefined
        : String(previous.config.disable_threshold),
      String(server.disable_threshold),
    )
    recoveryThreshold.value = keepUserEdit(
      recoveryThreshold.value,
      previous === null
        ? undefined
        : previous.config.recovery_threshold === null
          ? ''
          : String(previous.config.recovery_threshold),
      server.recovery_threshold === null ? '' : String(server.recovery_threshold),
    )
    disableStreak.value = keepUserEdit(
      disableStreak.value,
      previous === null ? undefined : String(previous.config.disable_streak),
      String(server.disable_streak),
    )
    pollSec.value = keepUserEdit(
      pollSec.value,
      previous === null ? undefined : String(previous.config.poll_sec),
      String(server.poll_sec),
    )
    snapshotTtlSec.value = keepUserEdit(
      snapshotTtlSec.value,
      previous === null ? undefined : String(previous.config.snapshot_ttl_sec),
      String(server.snapshot_ttl_sec),
    )
    timeoutSec.value = keepUserEdit(
      timeoutSec.value,
      previous === null ? undefined : String(previous.config.timeout_sec),
      String(server.timeout_sec),
    )
    status.value = next
    lastServerStatus.value = next
    loaded.value = true
  } catch (error) {
    loaded.value = true
    // 取不到状态不该让整张抽屉报错；面板只提示未加载，其余照常。
    console.warn('AMD 负载状态读取失败', error)
  }
}

async function save() {
  saving.value = true
  try {
    const result = await saveAmdLoadConfig(props.provider.id, currentPayload.value)
    // 回显的是**生效值**（可能与提交值不同，例如恢复阈值留空时回退成禁用阈值），
    // 所以用响应覆盖本地，而不是把提交值当成已保存的样子。
    const server = result.config
    enabled.value = server.enabled
    disableThreshold.value = String(server.disable_threshold)
    recoveryThreshold.value =
      server.recovery_threshold === null ? '' : String(server.recovery_threshold)
    disableStreak.value = String(server.disable_streak)
    pollSec.value = String(server.poll_sec)
    snapshotTtlSec.value = String(server.snapshot_ttl_sec)
    timeoutSec.value = String(server.timeout_sec)
    await loadStatus()
  } catch (error) {
    window.alert(getErrorMessage(error))
  } finally {
    saving.value = false
  }
}

async function refreshNow() {
  refreshing.value = true
  try {
    await refreshAmdLoadSnapshot(props.provider.id)
    await loadStatus()
  } catch (error) {
    window.alert(getErrorMessage(error))
  } finally {
    refreshing.value = false
  }
}

watch(
  () => props.provider.id,
  () => {
    // 换供应商就换一份草稿，别把上一个的未保存改动带过去。
    lastServerStatus.value = null
    loaded.value = false
    void loadStatus()
  },
)

onMounted(() => {
  void loadStatus()
})
</script>