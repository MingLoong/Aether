<template>
  <Card class="overflow-hidden" data-testid="opencode-ip-pool-panel">
    <!-- 头部：标题 + 行动按钮 -->
    <div class="p-4 border-b border-border/60">
      <div class="flex items-center justify-between">
        <h3 class="text-sm font-semibold">
          {{ legacyT('前置代理池') }}
        </h3>
        <div class="flex flex-wrap items-center justify-end gap-2">
          <Button
            variant="outline"
            size="sm"
            class="h-9"
            :disabled="status?.scanning || status?.cleaning || busy"
            @click="handleScan"
          >
            <Loader2 v-if="status?.scanning" class="mr-1.5 h-3.5 w-3.5 animate-spin" />
            <ScanSearch v-else class="mr-1.5 h-3.5 w-3.5" />
            {{ legacyT('扫描') }}
          </Button>
          <Button
            variant="outline"
            size="sm"
            class="h-9"
            :disabled="status?.scanning || status?.cleaning || busy"
            @click="handleClean"
          >
            <Loader2 v-if="status?.cleaning" class="mr-1.5 h-3.5 w-3.5 animate-spin" />
            <Sparkles v-else class="mr-1.5 h-3.5 w-3.5" />
            {{ legacyT('清理') }}
          </Button>
        </div>
      </div>
      <p class="text-xs text-muted-foreground mt-1.5">
        {{ legacyT('OpenCode CDN 出口 IP 池：每个 IP 独立承载一份每日配额，扫描结果自动加入请求轮换。') }}
      </p>
    </div>

    <!-- 前置代理域名与还原操作 -->
    <div v-if="status" class="px-4 py-3 border-b border-border/40 flex items-center justify-between gap-3">
      <div class="flex items-center gap-2 min-w-0">
        <Globe class="h-4 w-4 shrink-0 text-muted-foreground" />
        <span class="text-sm text-muted-foreground shrink-0">{{ legacyT('前置代理域名') }}</span>
        <span class="text-sm font-mono truncate font-semibold">{{ status.proxy_domain || '—' }}</span>
      </div>
      <Button
        v-if="status.proxy_domain && status.original_domain && !isOriginalDomain"
        variant="ghost"
        size="sm"
        class="h-8 shrink-0"
        :disabled="busy"
        @click="handleRestoreOriginal"
      >
        <RotateCcw class="mr-1.5 h-3.5 w-3.5" />
        {{ legacyT('还原原始链接') }}
        <span class="text-xs text-muted-foreground ml-1">{{ status.original_domain }}</span>
      </Button>
      <Badge
        v-else-if="isOriginalDomain"
        variant="outline"
        class="shrink-0 text-xs"
      >
        {{ legacyT('已使用原始链接') }}
      </Badge>
    </div>

    <!-- 配置区 -->
    <div class="px-4 py-3 border-b border-border/40 space-y-3">
      <div class="flex items-center justify-between">
        <h4 class="text-xs font-semibold text-muted-foreground uppercase tracking-wide">
          {{ legacyT('扫描配置') }}
        </h4>
      </div>

      <div>
        <label class="text-xs text-muted-foreground block mb-1.5">
          {{ legacyT('扫描网段 (CIDR)') }}
        </label>
        <div class="flex flex-wrap gap-1.5">
          <template v-for="(cidr, idx) in cidrInputs" :key="`${idx}-${cidr}`">
            <Badge
              variant="secondary"
              class="gap-1.5 pr-1 text-xs font-mono"
            >
              {{ cidr }}
              <button
                class="hover:text-destructive transition-colors"
                @click="removeCidr(idx)"
              >
                <X class="h-3 w-3" />
              </button>
            </Badge>
          </template>
          <input
            v-model="newCidr"
            class="bg-transparent text-xs font-mono outline-none w-28 placeholder:text-muted-foreground/50"
            placeholder="1.2.3.0/24"
            @keydown.enter.prevent="addCidr"
            @blur="addCidr"
          />
        </div>
      </div>

      <div class="grid grid-cols-2 gap-3">
        <div>
          <label class="text-xs text-muted-foreground block mb-1.5">
            {{ legacyT('自动扫描间隔 (小时)') }}
          </label>
          <Input
            v-model.number="intervalHours"
            type="number"
            min="0"
            class="h-8"
          />
        </div>
        <div>
          <label class="text-xs text-muted-foreground block mb-1.5">
            {{ legacyT('并发探测数') }}
          </label>
          <Input
            v-model.number="concurrency"
            type="number"
            min="1"
            max="128"
            class="h-8"
          />
        </div>
      </div>

      <div class="flex items-center justify-between">
        <div class="flex items-center gap-2">
          <Switch
            :checked="autoEnabled"
            @update:checked="autoEnabled = $event"
          />
          <span class="text-xs">{{ legacyT('自动扫描') }}</span>
        </div>
        <Button
          variant="outline"
          size="sm"
          class="h-8"
          :disabled="busy || configDirty === false"
          @click="handleSaveConfig"
        >
          <Save v-if="!savingConfig" class="mr-1.5 h-3.5 w-3.5" />
          <Loader2 v-else class="mr-1.5 h-3.5 w-3.5 animate-spin" />
          {{ legacyT('保存配置') }}
        </Button>
      </div>
    </div>

    <!-- 最近运行统计 -->
    <div class="px-4 py-3 border-b border-border/40 grid grid-cols-2 gap-x-4 gap-y-2 text-xs">
      <div class="flex items-center justify-between">
        <span class="text-muted-foreground">{{ legacyT('上次扫描') }}</span>
        <span class="font-mono">{{ status?.last_scan_at || '—' }}</span>
      </div>
      <div class="flex items-center justify-between">
        <span class="text-muted-foreground">{{ legacyT('上次清理') }}</span>
        <span class="font-mono">{{ status?.last_clean_at || '—' }}</span>
      </div>
      <div class="flex items-center justify-between">
        <span class="text-muted-foreground">{{ legacyT('探测目标') }}</span>
        <span class="font-mono">{{ status?.last_scan_targets ?? 0 }}</span>
      </div>
      <div class="flex items-center justify-between">
        <span class="text-muted-foreground">{{ legacyT('清理检查') }}</span>
        <span class="font-mono">{{ status?.last_clean_checked ?? 0 }}</span>
      </div>
      <div class="flex items-center justify-between">
        <span class="text-muted-foreground">{{ legacyT('新增 IP') }}</span>
        <span class="font-mono text-primary">{{ status?.last_scan_added ?? 0 }}</span>
      </div>
      <div class="flex items-center justify-between">
        <span class="text-muted-foreground">{{ legacyT('移除 IP') }}</span>
        <span class="font-mono text-destructive">{{ status?.last_clean_removed ?? 0 }}</span>
      </div>
    </div>

    <!-- IP 列表 -->
    <div class="px-4 py-3">
      <div class="flex items-center justify-between mb-2">
        <h4 class="text-xs font-semibold text-muted-foreground uppercase tracking-wide">
          {{ legacyT('池内 IP') }} ({{ poolIps.length }})
        </h4>
      </div>
      <div v-if="poolIps.length === 0" class="py-6 text-center">
        <Network class="w-10 h-10 mx-auto mb-2 opacity-40" />
        <p class="text-sm text-muted-foreground">
          {{ legacyT('暂无池内 IP，点击"扫描"从配置网段中发现可用出口 IP。') }}
        </p>
      </div>
      <div v-else class="divide-y divide-border/40 rounded-md border border-border/50 overflow-hidden">
        <div
          v-for="ip in pagedIps"
          :key="ip.key_id"
          class="px-3 py-2 flex items-center justify-between gap-2 hover:bg-muted/30"
        >
          <div class="flex items-center gap-2 min-w-0">
            <span
              class="inline-flex h-2 w-2 rounded-full shrink-0"
              :class="ip.healthy ? 'bg-emerald-500' : 'bg-red-400'"
            />
            <span class="text-sm font-mono">{{ ip.ip }}</span>
            <span v-if="!ip.is_active" class="text-xs text-muted-foreground">
              {{ legacyT('未启用') }}
            </span>
          </div>
          <Button
            variant="ghost"
            size="sm"
            class="h-7 px-2 text-muted-foreground hover:text-destructive"
            :disabled="busy"
            @click="handleDeleteIp(ip.key_id)"
          >
            <Trash2 class="h-3.5 w-3.5" />
          </Button>
        </div>
      </div>
      <!-- 分页：每页数量默认 50，可切换 -->
      <Pagination
        v-if="poolIps.length > 0"
        :current="ipPage"
        :total="poolIps.length"
        :page-size="ipPageSize"
        :page-size-options="[50, 100, 200]"
        :cache-key="`opencode-ip-pool-page-size-${props.provider.id}`"
        @update:current="ipPage = $event"
        @update:page-size="ipPageSize = $event"
      />
    </div>

    <!-- 错误提示 -->
    <div
      v-if="errorMessage"
      class="px-4 py-2.5 bg-destructive/10 text-destructive text-xs border-t border-destructive/20"
    >
      {{ errorMessage }}
    </div>
  </Card>
</template>

<script setup lang="ts">
import { computed, onMounted, ref, watch } from 'vue'
import Badge from '@/components/ui/badge.vue'
import Button from '@/components/ui/button.vue'
import Card from '@/components/ui/card.vue'
import Input from '@/components/ui/input.vue'
import Pagination from '@/components/ui/pagination.vue'
import Switch from '@/components/ui/switch.vue'
import { Loader2, ScanSearch, Sparkles, Globe, RotateCcw, Save, X, Network, Trash2 } from 'lucide-vue-next'
import { useI18n } from '@/i18n'
import {
  getOpenCodeIpPoolStatus,
  saveOpenCodeIpPoolConfig,
  runOpenCodeIpPoolScan,
  runOpenCodeIpPoolClean,
  restoreOpenCodeOriginalBaseUrl,
  type OpenCodeIpPoolStatus,
} from '@/api/endpoints'
import type { Provider } from '@/api/endpoints/types'

const props = defineProps<{
  provider: Provider
  keys?: Array<{ key: EndpointAPIKeyLike }>
}>()

const { legacyT } = useI18n()

interface EndpointAPIKeyLike {
  id: string
  api_key?: string | null
  is_active?: boolean
  auth_type?: string
}

interface PoolIpRow {
  key_id: string
  ip: string
  is_active: boolean
  healthy: boolean
}

const status = ref<OpenCodeIpPoolStatus | null>(null)
const cidrInputs = ref<string[]>([])
const newCidr = ref('')
const intervalHours = ref<number>(0)
const concurrency = ref<number>(32)
const autoEnabled = ref(false)
const savingConfig = ref(false)
const busy = ref(false)
const errorMessage = ref<string | null>(null)

// 池内 IP 分页
const ipPage = ref(1)
const ipPageSize = ref(50)
const pagedIps = computed<PoolIpRow[]>(() => {
  const start = (ipPage.value - 1) * ipPageSize.value
  return poolIps.value.slice(start, start + ipPageSize.value)
})

const isOriginalDomain = computed(() => {
  const proxy = (status.value?.proxy_domain || '').toLowerCase().trim()
  const original = (status.value?.original_domain || '').toLowerCase().trim()
  return original !== '' && proxy === original
})

const poolIps = computed<PoolIpRow[]>(() => {
  const rows: PoolIpRow[] = []
  if (!status.value?.pool_ips) return rows
  for (const row of status.value.pool_ips) {
    if (!row?.key_id || !row?.ip) continue
    rows.push({
      key_id: row.key_id,
      ip: row.ip,
      is_active: row.is_active !== false,
      healthy: row.is_active !== false,
    })
  }
  return rows
})

const configDirty = computed(
  () =>
    JSON.stringify(cidrInputs.value.sort()) !==
      JSON.stringify([...(status.value?.cidrs || [])].sort()) ||
    intervalHours.value !== (status.value?.interval_hours ?? 0) ||
    concurrency.value !== (status.value?.concurrency ?? 32) ||
    autoEnabled.value !== (status.value?.auto_enabled ?? false),
)

function addCidr() {
  const value = newCidr.value.trim()
  if (!value) return
  if (!/^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\/\d{1,2}$/.test(value)) {
    errorMessage.value = legacyT(`无效 CIDR：${value}`)
    return
  }
  if (!cidrInputs.value.includes(value)) {
    cidrInputs.value.push(value)
  }
  newCidr.value = ''
}

function removeCidr(index: number) {
  cidrInputs.value.splice(index, 1)
}

async function loadStatus() {
  try {
    status.value = await getOpenCodeIpPoolStatus(props.provider.id)
    cidrInputs.value = status.value?.cidrs || []
    intervalHours.value = status.value?.interval_hours ?? 0
    concurrency.value = status.value?.concurrency ?? 32
    autoEnabled.value = status.value?.auto_enabled ?? false
    // 池发生变化时收敛页码（scan/clean 后总页数可能变小）
    const totalPages = Math.max(1, Math.ceil((status.value?.pool_ips?.length ?? 0) / ipPageSize.value))
    if (ipPage.value > totalPages) {
      ipPage.value = totalPages
    }
    errorMessage.value = null
  } catch (err) {
    errorMessage.value = legacyT(`加载前置代理池状态失败：${err}`)
  }
}

async function handleSaveConfig() {
  savingConfig.value = true
  errorMessage.value = null
  try {
    await saveOpenCodeIpPoolConfig(props.provider.id, {
      cidrs: cidrInputs.value,
      auto_enabled: autoEnabled.value,
      interval_hours: intervalHours.value,
      concurrency: concurrency.value,
    })
    await loadStatus()
  } catch (err) {
    errorMessage.value = legacyT(`保存配置失败：${err}`)
  } finally {
    savingConfig.value = false
  }
}

async function handleScan() {
  busy.value = true
  errorMessage.value = null
  try {
    const result = await runOpenCodeIpPoolScan(props.provider.id)
    status.value = { ...status.value, ...result } as OpenCodeIpPoolStatus
    await loadStatus()
    emit('refresh')
  } catch (err) {
    errorMessage.value = legacyT(`扫描失败：${err}`)
  } finally {
    busy.value = false
  }
}

async function handleClean() {
  busy.value = true
  errorMessage.value = null
  try {
    const result = await runOpenCodeIpPoolClean(props.provider.id)
    status.value = { ...status.value, ...result } as OpenCodeIpPoolStatus
    await loadStatus()
    emit('refresh')
  } catch (err) {
    errorMessage.value = legacyT(`清理失败：${err}`)
  } finally {
    busy.value = false
  }
}

async function handleRestoreOriginal() {
  busy.value = true
  errorMessage.value = null
  try {
    const result = await restoreOpenCodeOriginalBaseUrl(props.provider.id)
    await loadStatus()
    emit('refresh')
    errorMessage.value = result.errors?.length
      ? legacyT(`还原完成，${result.errors.length} 个端点失败：${result.errors.join('；')}`)
      : legacyT(`已还原 ${result.changed} 个端点为原始链接`)
  } catch (err) {
    errorMessage.value = legacyT(`还原失败：${err}`)
  } finally {
    busy.value = false
  }
}

async function handleDeleteIp(keyId: string) {
  busy.value = true
  errorMessage.value = null
  try {
    const { deleteEndpointKey } = await import('@/api/endpoints')
    await deleteEndpointKey(keyId)
    emit('refresh')
  } catch (err) {
    errorMessage.value = legacyT(`删除 IP 失败：${err}`)
  } finally {
    busy.value = false
  }
}

const emit = defineEmits<{
  refresh: []
}>()

onMounted(() => {
  loadStatus()
})

watch(
  () => props.provider.id,
  () => loadStatus(),
)
</script>