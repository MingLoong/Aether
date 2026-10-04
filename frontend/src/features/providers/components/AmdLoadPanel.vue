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
        <Badge v-else variant="secondary" class="text-[10px] h-4 px-1.5">
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

      <!--
        这段说明直接写实测结论，而不是复述功能设计。原先那句「按首字节之外的另一路
        信号…被临时停用」暗示这套机制能改善首字节，而实测不支持：慢请求（>10s）的负载
        中位数 53.1%、快请求 48.4%，只差 5 个百分点；负载 79% 的模型变异系数 0.18 是
        全场最稳的，负载 16% 的反而出过 22.8 秒长尾。禁用不改善首字节，所以默认关闭。
      -->
      <div class="rounded-md border border-border/60 bg-muted/30 p-2.5 text-[11px] text-muted-foreground">
        {{
          legacyT(
            '实测（2026-10-02，81 个首字节样本）：负载高低与首字节快慢没有对应关系，按负载禁用模型不会让请求更快。所以这里默认只展示、不禁用。需要更稳的响应请调首字节超时。',
          )
        }}
      </div>

      <div class="flex items-center gap-2">
        <Switch v-model="enabled" />
        <span class="text-xs">{{ legacyT('启用负载展示') }}</span>
      </div>

      <div class="grid grid-cols-2 gap-3">
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
            {{ legacyT('超过这个时间没拉到新快照，面板会标为过期。') }}
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

      <!--
        阈值与阻尼三项收进折叠区。它们现在不生效（block_models 默认关闭），但保留下来：
        判定逻辑还在代码里，将来若有新证据可以重新打开，而那时的配置值不必从零猜。
        摆在主视图里会让人以为调它有用。
      -->
      <details class="text-xs">
        <summary class="cursor-pointer text-muted-foreground select-none">
          {{ legacyT('高级：禁用阈值（当前不生效）') }}
        </summary>
        <div class="grid grid-cols-3 gap-3 mt-2">
          <div>
            <label class="text-xs text-muted-foreground block mb-1.5">
              {{ legacyT('禁用阈值 (%)') }}
            </label>
            <Input v-model="disableThreshold" type="number" min="1" max="100" step="0.5" class="h-8" />
          </div>
          <div>
            <label class="text-xs text-muted-foreground block mb-1.5">
              {{ legacyT('恢复阈值 (%)') }}
            </label>
            <Input v-model="recoveryThreshold" type="number" min="0" max="100" step="0.5" class="h-8" />
          </div>
          <div>
            <label class="text-xs text-muted-foreground block mb-1.5">
              {{ legacyT('连续越线次数') }}
            </label>
            <Input v-model="disableStreak" type="number" min="1" max="10" class="h-8" />
          </div>
        </div>
        <p class="text-[11px] text-muted-foreground mt-1.5">
          {{
            legacyT(
              '只有在按模型错误率判定时才需要调这几项。留空恢复阈值表示单阈值模式：低于禁用阈值即放行。',
            )
          }}
        </p>
      </details>

      <!-- 模型负载 -->
      <div v-if="models.length" class="text-xs">
        <div class="flex items-center justify-between pb-1.5">
          <span class="text-muted-foreground">{{ legacyT('模型负载') }}</span>
          <!--
            不再显示「已禁用 N」：禁用默认关闭，这个数字恒为 0，留着会让人以为功能坏了。
            改成显示快照年龄——这才是判断「这个占用数字新不新」的依据，而负载变化很快。
          -->
          <span v-if="snapshotAgeText" class="text-[11px] text-muted-foreground">
            {{ snapshotAgeText }}
          </span>
        </div>
        <!-- 表头三列与下面的行用同一套 grid，且行内粘在顶部，避免表格行多时表头随滚动消失。 -->
        <div class="max-h-64 overflow-y-auto">
          <div
            class="grid grid-cols-[1fr_5rem_4.5rem] items-center gap-2 py-1 sticky top-0 z-10 bg-card border-b border-border/40 text-muted-foreground"
          >
            <span>{{ legacyT('模型') }}</span>
            <span class="text-center">{{ legacyT('占用') }}</span>
            <span class="text-center">{{ legacyT('状态') }}</span>
          </div>
          <div
            v-for="row in models"
            :key="row.model"
            class="grid grid-cols-[1fr_5rem_4.5rem] items-center gap-2 py-1 border-b border-border/20 last:border-0"
          >
            <span class="truncate">{{ row.model }}</span>
            <span
              class="font-mono tabular-nums text-center"
              :class="row.state === 'full' ? 'text-amber-600' : 'text-muted-foreground'"
            >
              {{ row.utilization.toFixed(1) }}%
            </span>
            <span class="flex justify-center gap-1">
              <!--
                只显示上游自己给的 state，不显示「已禁用」。禁用默认关闭，这一列恒为空，
                放个永不出现的徽章等于让人以为功能坏了。full 仍然标出来：那是上游的
                判断，占用确实满了，只是我们不再据此拦请求。
              -->
              <Badge v-if="row.state" variant="secondary" class="text-[10px] h-4 px-1.5">
                {{ row.state }}
              </Badge>
            </span>
          </div>
        </div>
      </div>
      <p v-else-if="loaded && loaded && status?.is_amd_upstream" class="text-[11px] text-muted-foreground">
        {{ legacyT('还没有负载快照：启用后会自动拉取，也可以点「立即刷新」。') }}
      </p>

      <!-- 账号配额 -->
      <div class="border-t border-border/60 pt-3">
        <div class="flex items-center justify-between pb-2">
          <span class="text-xs text-muted-foreground">{{ legacyT('各账号额度') }}</span>
          <span v-if="status?.usage" class="text-[11px] text-muted-foreground">
            {{ legacyT('今日合计') }} {{ formatUsd(status.usage.total_today_cost) }}
            <span class="text-muted-foreground/70">
              / {{ formatUsd(totalDailyLimit) }}
            </span>
          </span>
        </div>

        <p v-if="!status?.usage" class="text-[11px] text-muted-foreground">
          {{ legacyT('还没有配额快照。') }}
        </p>
        <template v-else>
          <!--
            逐账号一行，**按 key 的配置顺序**——用量天天变，按它排会让 10 行每次刷新都
            跳来跳去，没人能记住第 3 行是哪个账号。

            **主信息只有额度**：今日消费 / 日限额 + 进度条。行尾附带今日请求数与错误数——
            两者放一起才读得懂「花了多少钱」：同样是 $0.05，一个账号 1000 次 0 错、
            一个 3 次 3 错，含义完全不同。并发（rpm）与历史累计不属于「今日额度」，不放。

            额度口径与 Go 参考实现一致（admin.go:280）：显示 `today.cost / 日限额`。
            **日额度每天重置，所以只有 today 才是额度指标**；`all_time.cost` 是历史累计
            消费，永不重置，拿它衡量额度是错的——今天花超了它也不动。
          -->
          <div class="border border-border/60 rounded-md overflow-hidden">
            <div
              v-for="account in status.usage.accounts"
              :key="account.key_id"
              class="px-2 py-1.5 border-b border-border/30 last:border-0"
              :class="account.key_id === status.usage.risky_account_key_id ? 'bg-amber-500/5' : ''"
            >
              <div class="flex items-baseline justify-between gap-2">
                <span class="text-xs truncate">
                  {{ account.key_name }}
                  <span
                    v-if="account.key_id === status.usage.risky_account_key_id"
                    class="text-[10px] text-amber-600"
                  >
                    {{ legacyT('今日最高') }}
                  </span>
                  <span v-else-if="account.deduped" class="text-[10px] text-muted-foreground">
                    {{ legacyT('（同账号）') }}
                  </span>
                </span>
                <span v-if="account.error" class="text-[11px] text-amber-600 shrink-0">
                  {{ legacyT('拉取失败') }}
                </span>
                <span v-else class="font-mono tabular-nums text-xs shrink-0">
                  {{ formatUsd(account.today?.cost) }}
                  <span class="text-muted-foreground">
                    / {{ formatUsd(account.daily_cost_limit_usd) }}
                  </span>
                </span>
              </div>

              <div v-if="!account.error" class="h-1 mt-1 rounded-full bg-muted overflow-hidden">
                <div
                  class="h-full rounded-full transition-all"
                  :class="accountBarClass(account.usage_ratio)"
                  :style="{ width: accountBarWidth(account.usage_ratio) }"
                />
              </div>

              <!--
                额度是主信息，这一行是它的解释：花了多少钱 = 发了多少次请求。请求数和错误
                数放在一起才读得懂——同样是 $0.05，一个账号 1000 次 0 错、一个 3 次 3 错，
                含义完全不同。并发（rpm）与历史累计不属于「今日额度」，不放这里。
              -->
              <div
                v-if="!account.error"
                class="flex gap-3 mt-1 text-[11px] text-muted-foreground"
              >
                <span>{{ legacyT('请求') }} {{ account.today?.requests ?? 0 }}</span>
                <span v-if="(account.today?.errors ?? 0) > 0" class="text-amber-600">
                  {{ legacyT('错误') }} {{ account.today?.errors }}
                </span>
              </div>
            </div>
          </div>

          <!--
            只在有账号拉取失败时出现。不作为常规统计展示——它是异常信号，不是额度信息。
          -->
          <p
            v-if="status.usage.failed_accounts > 0"
            class="mt-1.5 text-[11px] text-amber-600"
          >
            {{
              legacyT('有账号拉取失败，其额度未计入合计：')
            }}
            {{ status.usage.failed_accounts }} / {{ status.usage.accounts.length }}
          </p>

          <!--
            按错误率排序，这栏是整块里最该看的：它是 AMD 自己记的失败，不是我们从负载
            百分比推断的。实测里唯一出错的模型错误率 5%，其余全是 0%。取第一个有数据的
            账号即可——各账号的模型分布基本一致，逐个展开反而占版面。
          -->
          <div v-if="primaryAccount" class="mt-2.5">
            <div class="text-muted-foreground pb-1">
              {{ legacyT('按模型错误率') }}
              <span class="text-[10px]">（{{ primaryAccount.key_name }}）</span>
            </div>
            <div class="max-h-40 overflow-y-auto">
              <div
                v-for="row in primaryAccount.by_model"
                :key="row.model"
                class="grid grid-cols-[1fr_4rem_5rem] items-center gap-2 py-0.5 border-b border-border/20 last:border-0"
              >
                <span class="truncate">{{ row.model }}</span>
                <span class="font-mono tabular-nums text-right text-muted-foreground">
                  {{ row.requests }}
                </span>
                <span
                  class="font-mono tabular-nums text-right"
                  :class="row.error_rate > 0 ? 'text-amber-600' : 'text-muted-foreground'"
                >
                  {{ row.error_rate.toFixed(0) }}%
                </span>
              </div>
            </div>
          </div>

          <!-- 上游未实现的字段，明确标出来而不是藏起来：它们确实存在于接口里，
               有人会去查为什么界面上没有余额。 -->
          <p v-if="status.usage.untrustworthy_fields.length" class="mt-2 text-[11px] text-muted-foreground">
            {{ legacyT('注意：上游的「已用/剩余额度」字段未实现（恒为 0 / 恒等于限额），不可作为余额依据。') }}
          </p>
        </template>
      </div>

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
import { computed, onMounted, onUnmounted, ref, watch } from 'vue'
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
const warnings = computed<string[]>(() => status.value?.warnings ?? [])

/**
 * 10 个账号的日限额合计。
 *
 * 用于「今日合计 x / 总额度 y」——10 个账号各有 1 美元额度，池子是 10 美元。只加今天
 * 成功拉到数据的账号：限额缺失的按 0 计会让分母变小，比例虚高。
 */
const totalDailyLimit = computed(() => {
  const accounts = status.value?.usage?.accounts ?? []
  return accounts.reduce(
    (sum, account) => sum + (account.daily_cost_limit_usd ?? 0),
    0,
  )
})

/**
 * 用量比例最高的账号的模型错误率表。
 *
 * 各账号的模型分布基本一致（同一批模型、同一个 fleet），所以只展示一个账号的就够了——
 * 逐个展开 10 份重复内容会把版面占满却增加不了信息。取第一个有 by_model 的账号。
 */
const primaryAccount = computed(() => {
  const accounts = status.value?.usage?.accounts ?? []
  return accounts.find((account) => account.by_model.length > 0) ?? null
})

/**
 * 进度条宽度。
 *
 * 直接用百分比做宽度在低位看不见：实测 today.cost 量级在 0.003 美元，占用比例 0.3%，
 * 3 个百分点的条几乎分辨不出。所以给下限——**只影响显示不影响判断**，否则「用了一点」
 * 会被画成「用了很多」。
 */
function accountBarWidth(ratio: number | null): string {
  if (ratio === null || ratio <= 0) return '0%'
  const percent = ratio * 100
  if (percent >= 100) return '100%'
  return `${Math.max(percent, 0.8)}%`
}

function accountBarClass(ratio: number | null): string {
  const percent = (ratio ?? 0) * 100
  if (percent >= 90) return 'bg-red-500'
  if (percent >= 70) return 'bg-amber-500'
  return 'bg-primary'
}

/** 美元金额。极小值要能看清——实测 today.cost 量级在 0.003，两位小数会显示成 0.00。 */
function formatUsd(value: number | null | undefined): string {
  if (typeof value !== 'number') return '—'
  if (value === 0) return '$0'
  if (value < 0.0001) return '<$0.0001'
  if (value < 1) return `$${value.toFixed(4)}`
  return `$${value.toFixed(2)}`
}

/**
 * 快照年龄文案。
 *
 * 用「N 秒前 / N 分钟前」而不是绝对时间戳：管理员看的是「这个数字还新不新鲜」，
 * 绝对时刻要他自己做减法才有意义。
 *
 * 依赖 nowTick 秒级递增，所以数据本身不刷新时，年龄也会继续走——这正是要的效果：
 * 能看出面板的数字已经不再更新了。
 */
const nowTick = ref(Date.now())
const snapshotAgeText = computed(() => {
  const fetchedAt = status.value?.snapshot_fetched_at
  if (!fetchedAt) return ''
  const seconds = Math.max(0, Math.floor((nowTick.value - fetchedAt * 1000) / 1000))
  if (seconds < 10) return legacyT('刚刚更新')
  if (seconds < 60) return `${seconds}${legacyT('秒前更新')}`
  const minutes = Math.floor(seconds / 60)
  return `${minutes}${legacyT('分钟前更新')}`
})


/**
 * 用户改过、但还没保存的字段不能被一次后台刷新静默丢掉。
 *
 * 判据是「本地值是否还等于上次拿到的服务端值」：相等说明用户没动过，可以放心覆盖；
 * 不等就是他正在编辑，必须留着。保存成功后的下一次刷新会自动恢复同步——那时本地值
 * 已经等于新的服务端值——所以不需要额外的「已编辑」标记，也不会忘记复位。
 *
 * `previousServerValue` 显式收 `T | undefined`：首次加载时还没有「上次的值」，
 * 此时应当直接采用服务端值。签名若写成裸 `T`，调用处就必须先把 undefined 消掉，
 * 而这里消不掉——那些值本来就可能不存在（recovery_threshold 为 null 时上次就不存在）。
 */
function keepUserEdit<T>(
  localValue: T,
  previousServerValue: T | undefined,
  nextServerValue: T,
): T {
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

/**
 * 自动刷新间隔。
 *
 * 取 60 秒是权衡出来的：后台每 120 秒轮询一次上游，更快没有新数据可拿；再慢则
 * 界面会明显滞后于实际占用。60 秒意味着多数情况下能拿到上两轮里的最新一轮。
 */
const AUTO_REFRESH_MS = 60_000
let refreshTimer: ReturnType<typeof setInterval> | null = null
// 快照年龄每秒重算，与数据刷新分开。合成一个 60 秒的定时器会让年龄显示成
// 「60 秒前」不动的样子，而它恰恰是判断数据是否还新鲜的依据。
let clockTimer: ReturnType<typeof setInterval> | null = null

function stopAutoRefresh() {
  if (refreshTimer !== null) {
    clearInterval(refreshTimer)
    refreshTimer = null
  }
  if (clockTimer !== null) {
    clearInterval(clockTimer)
    clockTimer = null
  }
}

function startAutoRefresh() {
  stopAutoRefresh()
  refreshTimer = setInterval(() => {
    // 标签页在后台时不轮询：定时器会被浏览器节流，拉回来时还会补触发一轮，
    // 那一轮通常没有新数据，白白打一次接口。
    if (document.visibilityState === 'hidden') return
    // 用户正在编辑时也照常拉。loadStatus 内部按「本地值是否仍等于上次的服务端值」
    // 判断有没有被改过，没改过的字段会被自动刷新覆盖，改过的保留。
    void loadStatus()
  }, AUTO_REFRESH_MS)
}

/**
 * 页面从后台切回前台时立刻补一次。
 *
 * 不用只靠定时器：浏览器会把后台标签页的定时器节流到分钟级甚至冻结，用户切回来
 * 时看到的可能还是几分钟前的数据，而负载正是最需要看新值的场景。
 */
function onVisibilityChange() {
  if (document.visibilityState === 'visible') {
    void loadStatus()
  }
}

onMounted(() => {
  void loadStatus()
  startAutoRefresh()
  clockTimer = setInterval(() => {
    nowTick.value = Date.now()
  }, 1000)
  document.addEventListener('visibilitychange', onVisibilityChange)
})

// 抽屉关闭时组件卸载。不清理的话定时器和事件监听会一直留着，
// 而 loadStatus 里还有 props.provider 的引用——既是内存泄漏，也会在用户已经
// 关掉抽屉后继续打接口。
onUnmounted(() => {
  stopAutoRefresh()
  document.removeEventListener('visibilitychange', onVisibilityChange)
})
</script>