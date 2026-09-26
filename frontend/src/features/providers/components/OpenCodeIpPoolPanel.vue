<template>
  <Card class="overflow-hidden" data-testid="opencode-ip-pool-panel">
    <!-- 头部：标题 + 扫描 / 清理 -->
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
        {{
          legacyT(
            'OpenCode CDN 出口 IP 池：每个 IP 独立承载一份每日配额，扫描结果自动加入请求轮换。',
          )
        }}
      </p>
    </div>

    <!-- 前置代理域名（面板首要配置项） -->
    <div v-if="status" class="px-4 py-3 border-b border-border/40 space-y-2 bg-muted/20">
      <div class="flex items-center justify-between gap-2">
        <div class="flex items-center gap-2 min-w-0">
          <Globe class="h-4 w-4 shrink-0 text-primary" />
          <span class="text-sm font-medium shrink-0">{{ legacyT('启用前置代理') }}</span>
          <Switch
            :model-value="proxyEnabled"
            :disabled="busy || savingConfig"
            @update:model-value="handleToggleProxy"
          />
          <Badge variant="secondary" class="font-mono text-[11px] truncate max-w-[220px]">
            {{ proxyEnabled && proxyDomainInput ? proxyDomainInput : status.original_domain || 'opencode.ai' }}
          </Badge>
        </div>
      </div>
      <div class="flex items-center gap-2">
        <Input
          v-model="proxyDomainInput"
          placeholder="cdn.example.com"
          class="h-8 font-mono text-sm"
          :disabled="busy || savingConfig"
          @keydown.enter.prevent="handleSaveConfig"
        />
        <Button
          variant="outline"
          size="sm"
          class="h-8 shrink-0"
          :disabled="busy || savingConfig || !proxyDomainDirty"
          @click="handleSaveConfig"
        >
          <Save v-if="!savingConfig" class="mr-1.5 h-3.5 w-3.5" />
          <Loader2 v-else class="mr-1.5 h-3.5 w-3.5 animate-spin" />
          {{ legacyT('保存') }}
        </Button>
      </div>
      <p class="text-[11px] text-muted-foreground">
        <template v-if="proxyEnabled && proxyDomainInput">
          {{
            legacyT(
              '开启：本次请求使用上方域名，配合池内 IP 分散每日免费额度。端点仍显示真实上游，不会被改写。',
            )
          }}
        </template>
        <template v-else-if="proxyEnabled">
          {{ legacyT('已开启但未填写域名，本次请求仍使用默认官方地址。') }}
        </template>
        <template v-else>
          {{ legacyT('关闭：本次请求使用默认官方地址。上方填写的域名会保留，随时可重新开启。') }}
        </template>
      </p>
    </div>

    <!-- 扫描配置 -->
    <div class="px-4 py-3 border-b border-border/40 space-y-3">
      <h4 class="text-xs font-semibold text-muted-foreground uppercase tracking-wide">
        {{ legacyT('扫描配置') }}
      </h4>

      <div>
        <label class="text-xs text-muted-foreground block mb-1.5">
          {{ legacyT('扫描网段 (CIDR)') }}
        </label>
        <div class="flex flex-wrap gap-1.5">
          <template v-for="(cidr, idx) in cidrInputs" :key="`${idx}-${cidr}`">
            <Badge variant="secondary" class="gap-1.5 pr-1 text-xs font-mono">
              {{ cidr }}
              <button class="hover:text-destructive transition-colors" @click="removeCidr(idx)">
                <X class="h-3 w-3" />
              </button>
            </Badge>
          </template>
          <span v-if="cidrInputs.length === 0" class="text-xs text-muted-foreground py-1">
            {{ legacyT('暂无网段，请添加') }}
          </span>
        </div>
        <div class="flex items-center gap-2 mt-1.5">
          <Input
            v-model="newCidr"
            class="h-8 font-mono text-sm"
            placeholder="203.0.113.0/24"
            @keydown.enter.prevent="addCidr"
          />
          <Button variant="outline" size="sm" class="h-8 shrink-0" :disabled="!newCidr.trim()" @click="addCidr">
            <Plus class="mr-1.5 h-3.5 w-3.5" />
            {{ legacyT('添加') }}
          </Button>
        </div>
      </div>

      <div class="grid grid-cols-2 gap-3">
        <div>
          <label class="text-xs text-muted-foreground block mb-1.5">
            {{ legacyT('并发探测数') }}
          </label>
          <Input v-model.number="concurrency" type="number" min="1" max="128" class="h-8" />
        </div>
        <div>
          <label class="text-xs text-muted-foreground block mb-1.5">
            {{ legacyT('自动扫描间隔 (小时)') }}
          </label>
          <Input
            v-model.number="intervalHours"
            type="number"
            min="0"
            :disabled="!autoEnabled"
            class="h-8"
          />
        </div>
      </div>

      <div class="grid grid-cols-2 gap-3">
        <div>
          <label class="text-xs text-muted-foreground block mb-1.5">
            {{ legacyT('额度冷却 (分钟)') }}
          </label>
          <Input
            v-model.number="cooldownMinutes"
            type="number"
            min="1"
            max="1440"
            class="h-8"
          />
        </div>
        <div>
          <label class="text-xs text-muted-foreground block mb-1.5">
            {{ legacyT('当前轮转游标') }}
          </label>
          <div class="h-8 flex items-center font-mono text-sm text-muted-foreground">
            {{ rotationCursor }}
          </div>
        </div>
      </div>

      <div class="flex items-center justify-between">
        <div class="flex items-center gap-2">
          <Switch v-model="autoEnabled" />
          <span class="text-xs">{{ legacyT('自动扫描') }}</span>
        </div>
        <Button
          variant="outline"
          size="sm"
          class="h-8"
          :disabled="busy || savingConfig || !configDirty"
          @click="handleSaveConfig"
        >
          <Save v-if="!savingConfig" class="mr-1.5 h-3.5 w-3.5" />
          <Loader2 v-else class="mr-1.5 h-3.5 w-3.5 animate-spin" />
          {{ legacyT('保存配置') }}
        </Button>
      </div>

      <div class="flex items-center justify-between border-t border-border/40 pt-3">
        <div class="flex items-center gap-2 min-w-0">
          <Repeat2 class="h-4 w-4 shrink-0 text-primary" />
          <span class="text-xs shrink-0">{{ legacyT('轮询规则') }}</span>
          <Switch v-model="rotationEnabled" />
          <Badge variant="secondary" class="text-[10px] h-4 px-1.5 shrink-0">
            {{
              rotationEnabled
                ? legacyT('记住上次出口，下次 +1')
                : legacyT('沿用系统默认调度')
            }}
          </Badge>
        </div>
        <p class="text-[11px] text-muted-foreground text-right">
          {{
            rotationEnabled
              ? legacyT('每次请求在池内 IP 间轮转，各自有独立免费额度')
              : legacyT('关闭时由系统调度策略决定用哪个 IP')
          }}
        </p>
      </div>
      <p v-if="autoEnabled && intervalHours <= 0" class="text-[11px] text-destructive">
        {{ legacyT('自动扫描已开启，但间隔为 0，不会自动执行。') }}
      </p>
    </div>

    <!-- 最近运行统计 -->
    <div class="px-4 py-3 border-b border-border/40 grid grid-cols-2 gap-x-4 gap-y-2 text-xs">
      <div class="flex items-center justify-between">
        <span class="text-muted-foreground">{{ legacyT('上次扫描') }}</span>
        <span class="font-mono">{{ formatTimestamp(status?.last_scan_at) }}</span>
      </div>
      <div class="flex items-center justify-between">
        <span class="text-muted-foreground">{{ legacyT('上次清理') }}</span>
        <span class="font-mono">{{ formatTimestamp(status?.last_clean_at) }}</span>
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

    <!-- 池内 IP -->
    <div class="px-4 py-3">
      <h4 class="text-xs font-semibold text-muted-foreground uppercase tracking-wide mb-2">
        {{ legacyT('池内 IP') }} ({{ poolIps.length }})
      </h4>

      <div class="flex items-center gap-2 mb-2">
        <Input
          v-model="newIpInput"
          class="h-8 font-mono text-sm"
          placeholder="203.0.113.118"
          @keydown.enter.prevent="handleAddIp"
        />
        <Button
          variant="outline"
          size="sm"
          class="h-8 shrink-0"
          :disabled="busy || !newIpInput.trim()"
          @click="handleAddIp"
        >
          <Plus class="mr-1.5 h-3.5 w-3.5" />
          {{ legacyT('手动添加 IP') }}
        </Button>
      </div>
      <p class="text-[11px] text-muted-foreground mb-2">
        {{
          legacyT(
            '每个 IP 对应一个密钥，出口 IP 记录在密钥的 upstream_metadata.opencode_exit_ip，不占用 API Key 字段。',
          )
        }}
      </p>

      <div v-if="poolIps.length === 0" class="py-6 text-center">
        <Network class="w-10 h-10 mx-auto mb-2 opacity-40" />
        <p class="text-sm text-muted-foreground">
          {{ legacyT('暂无池内 IP，点击"扫描"从配置网段中发现可用出口 IP，或在上方手动添加。') }}
        </p>
      </div>
      <div
        v-else
        class="divide-y divide-border/40 rounded-md border border-border/50 overflow-hidden"
      >
        <div
          v-for="ip in pagedIps"
          :key="ip.key_id"
          class="px-3 py-2 flex items-center justify-between gap-2 hover:bg-muted/30"
        >
          <div class="flex items-center gap-2 min-w-0">
            <span
              class="inline-flex h-2 w-2 rounded-full shrink-0"
              :class="ip.is_active ? 'bg-emerald-500' : 'bg-red-400'"
            />
            <template v-if="editingKeyId === ip.key_id">
              <Input
                v-model="editingIp"
                class="h-7 w-40 font-mono text-sm"
                @keydown.enter.prevent="commitEditIp(ip)"
                @keydown.esc="editingKeyId = null"
              />
              <Button variant="ghost" size="sm" class="h-7 px-2" :disabled="busy" @click="commitEditIp(ip)">
                <Check class="h-3.5 w-3.5" />
              </Button>
              <Button variant="ghost" size="sm" class="h-7 px-2" @click="editingKeyId = null">
                <X class="h-3.5 w-3.5" />
              </Button>
            </template>
            <span v-else class="text-sm font-mono truncate">{{ ip.ip }}</span>
            <span v-if="!ip.is_active" class="text-xs text-muted-foreground shrink-0">
              {{ legacyT('未启用') }}
            </span>
          </div>
          <div class="flex items-center gap-1 shrink-0">
            <Button
              variant="ghost"
              size="sm"
              class="h-7 px-2 text-muted-foreground"
              :disabled="busy"
              :title="ip.is_active ? legacyT('停用') : legacyT('启用')"
              @click="handleToggleIp(ip)"
            >
              <Power class="h-3.5 w-3.5" />
            </Button>
            <Button
              variant="ghost"
              size="sm"
              class="h-7 px-2 text-muted-foreground"
              :disabled="busy"
              :title="legacyT('修改 IP')"
              @click="startEditIp(ip)"
            >
              <Pencil class="h-3.5 w-3.5" />
            </Button>
            <Button
              variant="ghost"
              size="sm"
              class="h-7 px-2 text-muted-foreground hover:text-destructive"
              :disabled="busy"
              :title="legacyT('删除')"
              @click="handleDeleteIp(ip.key_id)"
            >
              <Trash2 class="h-3.5 w-3.5" />
            </Button>
          </div>
        </div>
      </div>
      <Pagination
        v-if="poolIps.length > 0"
        :current="ipPage"
        :total="poolIps.length"
        :page-size="ipPageSize"
        :page-size-options="[50, 100, 200]"
        :show-page-size-selector="false"
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
import {
  Check,
  Globe,
  Loader2,
  Network,
  Pencil,
  Plus,
  Power,
  Repeat2,
  RotateCcw,
  Save,
  ScanSearch,
  Sparkles,
  Trash2,
  X,
} from 'lucide-vue-next'
import { useI18n } from '@/i18n'
import {
  addProviderKey,
  deleteEndpointKey,
  getOpenCodeIpPoolStatus,
  restoreOpenCodeOriginalBaseUrl,
  runOpenCodeIpPoolClean,
  runOpenCodeIpPoolScan,
  saveOpenCodeIpPoolConfig,
  updateProviderKey,
  type OpenCodeIpPoolStatus,
} from '@/api/endpoints'
import type { ProviderWithEndpointsSummary } from '@/api/endpoints/types'

const props = defineProps<{
  provider: ProviderWithEndpointsSummary
}>()

const emit = defineEmits<{
  refresh: []
}>()

const { legacyT } = useI18n()

interface PoolIpRow {
  key_id: string
  ip: string
  is_active: boolean
}

const status = ref<OpenCodeIpPoolStatus | null>(null)
const cidrInputs = ref<string[]>([])
const newCidr = ref('')
const concurrency = ref<number>(32)
const intervalHours = ref<number>(0)
const rotationEnabled = ref(false)
const cooldownMinutes = ref<number>(60)
const rotationCursor = ref<number>(0)
const autoEnabled = ref(false)
const savingConfig = ref(false)
const busy = ref(false)
const errorMessage = ref<string | null>(null)
const proxyDomainInput = ref('')
const newIpInput = ref('')
const editingKeyId = ref<string | null>(null)
const editingIp = ref('')
const domainSyncHint = ref('')

const IPV4_PATTERN = /^(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})$/

/**
 * 时间戳只显示到秒。
 * 后端返回的是 RFC3339 纳秒精度，例如
 * `2026-09-26T15:49:50.682213785+00:00`，直接展示既占地方又读不出来。
 */
function formatTimestamp(value?: string | null): string {
  if (!value) return '—'
  const parsed = new Date(value)
  if (Number.isNaN(parsed.getTime())) {
    // 解析不了就退化成按空格截断，至少去掉纳秒部分
    return value.replace(/\.\d+/, '').replace('T', ' ').replace('Z', '').replace('+00:00', '')
  }
  const pad = (n: number) => String(n).padStart(2, '0')
  return (
    `${parsed.getFullYear()}-${pad(parsed.getMonth() + 1)}-${pad(parsed.getDate())} ` +
    `${pad(parsed.getHours())}:${pad(parsed.getMinutes())}:${pad(parsed.getSeconds())}`
  )
}

function normalizeIp(raw: string): string | null {
  const value = raw.trim()
  const match = IPV4_PATTERN.exec(value)
  if (!match) return null
  const octets = match.slice(1).map((part) => Number(part))
  if (octets.some((octet) => octet < 0 || octet > 255)) return null
  if (octets[0] === 10 || octets[0] === 127) return null
  if (octets[0] === 172 && octets[1] >= 16 && octets[1] <= 31) return null
  if (octets[0] === 192 && octets[1] === 168) return null
  if (octets[0] === 169 && octets[1] === 254) return null
  if (octets[0] >= 224) return null
  return octets.join('.')
}

const proxyDomainDirty = computed(() => {
  const next = proxyDomainInput.value.trim().toLowerCase()
  const current = (status.value?.proxy_domain || '').trim().toLowerCase()
  return next !== current
})

const isOriginalDomain = computed(() => {
  const proxy = (status.value?.proxy_domain || '').toLowerCase().trim()
  const original = (status.value?.original_domain || '').toLowerCase().trim()
  return original !== '' && proxy === original
})

/**
 * 前置代理开关状态。
 *
 * 独立于端点主机：端点 base_url 始终是真实上游，不会被开关改写。
 * 开关只决定「本次请求用输入框里的域名」还是「用默认官方域名」，
 * 而且**不会改写输入框**——输入框里的域名只归用户所有。
 */
const proxyEnabled = ref(false)

const ORIGINAL_DOMAIN_FALLBACK = 'opencode.ai'

const poolIps = computed<PoolIpRow[]>(() => {
  const rows: PoolIpRow[] = []
  for (const row of status.value?.pool_ips || []) {
    if (!row?.key_id || !row?.ip) continue
    rows.push({ key_id: row.key_id, ip: row.ip, is_active: row.is_active !== false })
  }
  return rows
})

const ipPage = ref(1)
const ipPageSize = ref(50)
const pagedIps = computed<PoolIpRow[]>(() => {
  const start = (ipPage.value - 1) * ipPageSize.value
  return poolIps.value.slice(start, start + ipPageSize.value)
})

const configDirty = computed(
  () =>
    JSON.stringify([...cidrInputs.value].sort()) !==
      JSON.stringify([...(status.value?.cidrs || [])].sort()) ||
    concurrency.value !== (status.value?.concurrency ?? 32) ||
    autoEnabled.value !== (status.value?.auto_enabled ?? false) ||
    intervalHours.value !== (status.value?.interval_hours ?? 0) ||
    rotationEnabled.value !== (status.value?.rotation_enabled ?? false) ||
    Math.max(1, Number(cooldownMinutes.value) || 60) !== (status.value?.cooldown_minutes ?? 60),
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
  errorMessage.value = null
}

function removeCidr(index: number) {
  cidrInputs.value.splice(index, 1)
}

async function loadStatus() {
  try {
    const next = await getOpenCodeIpPoolStatus(props.provider.id)
    status.value = next
    cidrInputs.value = [...(next.cidrs || [])]
    concurrency.value = next.concurrency ?? 32
    autoEnabled.value = next.auto_enabled ?? false
    intervalHours.value = next.interval_hours ?? 0
    rotationEnabled.value = next.rotation_enabled ?? false
    cooldownMinutes.value = next.cooldown_minutes ?? 60
    rotationCursor.value = next.rotation_cursor ?? 0
    proxyEnabled.value = next.proxy_enabled ?? false
    // 输入框只做「首次预填」：已有内容（包括用户刚输入但没保存的）一律不动，
    // 开关也不参与写入。域名只归用户所有。
    if (!proxyDomainInput.value.trim()) {
      proxyDomainInput.value = next.saved_proxy_domain || ''
    }
    const totalPages = Math.max(1, Math.ceil((next.pool_ips?.length ?? 0) / ipPageSize.value))
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
    const body: Record<string, unknown> = {
      cidrs: cidrInputs.value,
      auto_enabled: autoEnabled.value,
      interval_hours: intervalHours.value,
      concurrency: concurrency.value,
      rotation_enabled: rotationEnabled.value,
      cooldown_minutes: Math.max(1, Number(cooldownMinutes.value) || 60),
      proxy_enabled: proxyEnabled.value,
    }
    // 域名只在用户真的改过输入框时才提交，开关不参与。
    if (proxyDomainDirty.value) {
      body.proxy_domain = proxyDomainInput.value.trim()
    }
    const result = await saveOpenCodeIpPoolConfig(props.provider.id, body)
    domainSyncHint.value = legacyT('配置已保存')
    if (result.proxy_domain_changed > 0) {
      domainSyncHint.value = legacyT(`已保存（${result.proxy_domain_changed} 个端点与该域名一致）`)
    }
    await loadStatus()
    emit('refresh')
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
    await loadStatus()
    emit('refresh')
    errorMessage.value =
      result.added > 0
        ? null
        : legacyT(`扫描完成：目标 ${result.targets}，未发现新的可用 IP`)
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
    await loadStatus()
    emit('refresh')
    errorMessage.value = null
    if (result.removed > 0) {
      window.setTimeout(() => {
        errorMessage.value = legacyT(`已清理 ${result.removed} 个失效 IP（共检查 ${result.checked} 个）`)
      }, 0)
    }
  } catch (err) {
    errorMessage.value = legacyT(`清理失败：${err}`)
  } finally {
    busy.value = false
  }
}

/**
 * 切换前置代理开关。
 *
 * 只提交 `proxy_enabled`：**不改写输入框、不改写端点**。
 * 开启时若输入框为空，本次请求就按默认官方域名走（后端 effective_proxy_domain
 * 会返回空），并给出提示；等填好域名再开即可。
 */
async function handleToggleProxy(enabled: boolean) {
  busy.value = true
  errorMessage.value = null
  const previous = proxyEnabled.value
  proxyEnabled.value = enabled
  try {
    const domain = proxyDomainInput.value.trim()
    const body: Record<string, unknown> = { proxy_enabled: enabled }
    // 顺手把当前输入框里的域名一起存下来（只在有内容时），避免开关后域名丢失。
    if (domain && proxyDomainDirty.value) {
      body.proxy_domain = domain
    }
    await saveOpenCodeIpPoolConfig(props.provider.id, body)
    if (enabled && !domain) {
      domainSyncHint.value = legacyT('已开启，但未填写域名，本次请求仍走默认官方地址')
    } else {
      domainSyncHint.value = enabled
        ? legacyT('已开启：本次请求使用输入框中的域名')
        : legacyT('已关闭：本次请求使用默认官方地址')
    }
    await loadStatus()
    emit('refresh')
  } catch (err) {
    proxyEnabled.value = previous
    errorMessage.value = legacyT(`切换前置代理失败：${err}`)
    await loadStatus()
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

async function handleAddIp() {
  const ip = normalizeIp(newIpInput.value)
  if (!ip) {
    errorMessage.value = legacyT(`无效 IP：${newIpInput.value.trim()}`)
    return
  }
  if (poolIps.value.some((row) => row.ip === ip)) {
    errorMessage.value = legacyT(`IP ${ip} 已在池中`)
    return
  }
  busy.value = true
  errorMessage.value = null
  try {
    await addProviderKey(props.provider.id, {
      name: `CDN IP ${ip}`,
      api_key: `public-${ip}`,
      auth_type: 'api_key',
      api_formats: ['openai:chat'],
      auto_fetch_models: false,
      note: 'opencode ip pool (manual)',
      upstream_metadata: { opencode_exit_ip: ip },
    })
    newIpInput.value = ''
    await loadStatus()
    emit('refresh')
  } catch (err) {
    errorMessage.value = legacyT(`添加 IP 失败：${err}`)
  } finally {
    busy.value = false
  }
}

function startEditIp(row: PoolIpRow) {
  editingKeyId.value = row.key_id
  editingIp.value = row.ip
  errorMessage.value = null
}

async function commitEditIp(row: PoolIpRow) {
  const ip = normalizeIp(editingIp.value)
  if (!ip) {
    errorMessage.value = legacyT(`无效 IP：${editingIp.value.trim()}`)
    return
  }
  if (ip !== row.ip && poolIps.value.some((other) => other.ip === ip)) {
    errorMessage.value = legacyT(`IP ${ip} 已在池中`)
    return
  }
  busy.value = true
  errorMessage.value = null
  try {
    await updateProviderKey(row.key_id, {
      name: `CDN IP ${ip}`,
      upstream_metadata: { opencode_exit_ip: ip },
    })
    editingKeyId.value = null
    await loadStatus()
    emit('refresh')
  } catch (err) {
    errorMessage.value = legacyT(`修改 IP 失败：${err}`)
  } finally {
    busy.value = false
  }
}

async function handleToggleIp(row: PoolIpRow) {
  busy.value = true
  errorMessage.value = null
  try {
    await updateProviderKey(row.key_id, { is_active: !row.is_active })
    await loadStatus()
    emit('refresh')
  } catch (err) {
    errorMessage.value = legacyT(`${row.is_active ? '停用' : '启用'} IP 失败：${err}`)
  } finally {
    busy.value = false
  }
}

async function handleDeleteIp(keyId: string) {
  busy.value = true
  errorMessage.value = null
  try {
    await deleteEndpointKey(keyId)
    await loadStatus()
    emit('refresh')
  } catch (err) {
    errorMessage.value = legacyT(`删除 IP 失败：${err}`)
  } finally {
    busy.value = false
  }
}

onMounted(() => {
  loadStatus()
})

watch(
  () => props.provider.id,
  () => loadStatus(),
)
</script>
