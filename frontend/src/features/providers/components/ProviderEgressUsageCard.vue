<template>
  <!-- 没配出口、或后端没有该视图时不占位 -->
  <Card
    v-if="visible"
    class="space-y-3 p-4"
  >
    <div class="flex flex-wrap items-center justify-between gap-2">
      <div class="text-sm font-semibold text-foreground">
        opencode 出口用量
      </div>
      <div class="text-[11px] text-muted-foreground">
        每 /64 预算 {{ data?.request_budget }} 次 · 段限速 {{ data?.segment_rpm }} rpm
        （突发 {{ data?.segment_burst }}）· 熔断阈值 {{ data?.segment_fail_threshold }} 个 /64
      </div>
    </div>

    <div
      v-if="loading && !data"
      class="text-xs text-muted-foreground"
    >
      加载中…
    </div>

    <div
      v-else-if="errorMessage"
      class="text-xs text-destructive"
    >
      {{ errorMessage }}
    </div>

    <template v-else-if="data">
      <!-- 段级状态：令牌桶与熔断 -->
      <div
        v-if="data.segments.length > 0"
        class="flex flex-wrap gap-2 text-[11px]"
      >
        <span
          v-for="segment in data.segments"
          :key="segment.segment"
          class="rounded border border-border/60 px-2 py-0.5"
          :class="segmentCooling(segment) ? 'text-destructive' : 'text-muted-foreground'"
        >
          {{ segment.segment }}
          · 令牌 {{ segment.tokens }}
          · 60s 内 429 出口 {{ segment.distinct_429_exits_60s }}
          <template v-if="segmentCooling(segment)">
            · 熔断中 {{ formatSeconds(segment.cooldown_seconds_left) }}
          </template>
        </span>
      </div>

      <!-- 出口列表：固定出口在前，动态 /64 按用量排序 -->
      <div class="overflow-x-auto">
        <table class="w-full text-xs">
          <thead class="text-muted-foreground">
            <tr class="text-left">
              <th class="py-1 pr-3 font-medium">
                出口
              </th>
              <th class="py-1 pr-3 font-medium">
                类型
              </th>
              <th class="py-1 pr-3 font-medium">
                请求/预算
              </th>
              <th class="py-1 pr-3 font-medium">
                429
              </th>
              <th class="py-1 pr-3 font-medium">
                状态
              </th>
            </tr>
          </thead>
          <tbody>
            <tr
              v-for="exit in sortedExits"
              :key="exit.name"
              class="border-t border-border/40"
            >
              <td class="py-1 pr-3 font-mono text-[11px]">
                {{ exit.exit_ip || exit.name }}
              </td>
              <td class="py-1 pr-3 text-muted-foreground">
                {{ exit.kind === 'dynamic' ? '动态' : '固定' }}
              </td>
              <td class="py-1 pr-3 tabular-nums">
                {{ exit.requests }}/{{ exit.budget }}
              </td>
              <td class="py-1 pr-3 tabular-nums">
                {{ exit.e429 }}
              </td>
              <td
                class="py-1 pr-3"
                :class="exitStateClass(exit)"
              >
                {{ exitStateLabel(exit) }}
              </td>
            </tr>
          </tbody>
        </table>
      </div>

      <div class="text-[11px] text-muted-foreground">
        预算周期按 UTC 日切（北京时间 08:00 重置）；用量落盘，重启不清零。
      </div>
    </template>
  </Card>
</template>

<script setup lang="ts">
import { computed, onBeforeUnmount, onMounted, ref, watch } from 'vue'
import Card from '@/components/ui/card.vue'
import { adminApi } from '@/api/admin'

type ExitUsageRow = Awaited<ReturnType<typeof adminApi.getProviderOpencodeExits>>['exits'][number]
type SegmentRow = Awaited<ReturnType<typeof adminApi.getProviderOpencodeExits>>['segments'][number]
type EgressReport = Awaited<ReturnType<typeof adminApi.getProviderOpencodeExits>>

const props = defineProps<{ providerId: string }>()

const data = ref<EgressReport | null>(null)
const loading = ref(false)
const errorMessage = ref('')
let timer: ReturnType<typeof setInterval> | null = null

// 接口 404 表示该供应商没配 opencode_egress，此时整块不显示。
const visible = computed(() => data.value !== null)

const sortedExits = computed<ExitUsageRow[]>(() => {
  const rows = data.value?.exits ?? []
  return [...rows].sort((a, b) => {
    if (a.kind !== b.kind) return a.kind === 'fixed' ? -1 : 1
    return b.requests - a.requests
  })
})

function exitStateLabel(exit: ExitUsageRow): string {
  const cooling = exit.cooling_seconds_left ?? 0
  if (cooling > 0) return `冷却 ${formatSeconds(cooling)}`
  const spent = exit.spent_seconds_left ?? 0
  if (spent > 0) return `用满 ${formatSeconds(spent)}`
  if (exit.exhausted) return '本周期用满'
  if (!exit.enabled) return '已停用'
  return '可用'
}

function exitStateClass(exit: ExitUsageRow): string {
  const label = exitStateLabel(exit)
  if (label === '可用') return 'text-emerald-500'
  if (label.startsWith('冷却') || label.startsWith('用满') || label === '本周期用满') {
    return 'text-amber-500'
  }
  return 'text-muted-foreground'
}

function formatSeconds(seconds: number | null | undefined): string {
  const total = Math.max(0, Math.floor(seconds ?? 0))
  if (total < 60) return `${total}s`
  const minutes = Math.floor(total / 60)
  if (minutes < 60) return `${minutes}m`
  const hours = Math.floor(minutes / 60)
  return `${hours}h${String(minutes % 60).padStart(2, '0')}m`
}

function segmentCooling(segment: SegmentRow): boolean {
  return (segment.cooldown_seconds_left ?? 0) > 0
}

async function load() {
  if (!props.providerId) return
  loading.value = true
  try {
    data.value = await adminApi.getProviderOpencodeExits(props.providerId)
    errorMessage.value = ''
  } catch (error) {
    // 404 = 没配出口，安静隐藏；其它错误给出提示但不影响页面其余部分。
    const status = (error as { response?: { status?: number } })?.response?.status
    if (status === 404) {
      data.value = null
    } else {
      errorMessage.value = '出口用量读取失败'
    }
  } finally {
    loading.value = false
  }
}

function startTimer() {
  stopTimer()
  timer = setInterval(() => {
    void load()
  }, 15_000)
}

function stopTimer() {
  if (timer) {
    clearInterval(timer)
    timer = null
  }
}

onMounted(() => {
  void load()
  startTimer()
})

watch(
  () => props.providerId,
  () => {
    data.value = null
    void load()
  },
)

onBeforeUnmount(stopTimer)
</script>
