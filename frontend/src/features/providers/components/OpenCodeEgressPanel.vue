<!--
  OpenCode 出口（SOCKS5 多出口）。

  数据存在供应商 config 的 `opencode_egress` 段里，与其他 opencode 配置一致；
  后端在 provider config 写入成功后把这段同步进运行时注册表，保存即生效。

  折叠样式与 CodeBuddy 账号里的「资源包」一致：原生 details/summary + ▸ 三角，
  点行头展开该出口的代理信息，零状态管理。
-->
<template>
  <Card class="overflow-hidden">
    <div class="p-4 border-b border-border/60">
      <div class="flex flex-wrap items-center justify-between gap-2">
        <div class="min-w-0 flex-1">
          <h3 class="text-sm font-semibold">出口（SOCKS5）</h3>
        </div>
        <!-- 抽屉窄的时候按钮不能被挤，否则「保存」会折成两行 -->
        <div class="flex shrink-0 items-center gap-2 whitespace-nowrap">
          <Button size="sm" class="h-8 whitespace-nowrap px-3" :disabled="saving" @click="save">
            {{ saving ? '保存中…' : '保存' }}
          </Button>
        </div>
      </div>
    </div>

    <div class="p-4 space-y-2">
      <div class="rounded-md border border-dashed border-border/60 p-3 text-[11px] text-muted-foreground">
        固定出口已从面板移除，统一由下面的「池子节点」按 /64 轮换。
        <template v-if="exits.length">
          配置里还有 {{ exits.length }} 个旧的固定出口仍在参与轮换，保存会原样保留（需要彻底清掉就手工编辑配置）。
        </template>
      </div>

      <div class="flex flex-wrap items-center gap-4 border-t border-border/60 pt-3 text-xs">
        <label class="flex items-center gap-2">
          <input v-model="fallbackIpv4" type="checkbox" class="h-3.5 w-3.5" />
          <span>出口全挂时回落直连</span>
        </label>
        <label class="flex items-center gap-2">
          <span class="text-muted-foreground">出口失败冷却（秒）</span>
          <Input v-model.number="downSeconds" type="number" min="5" max="3600" class="h-8 w-24" />
        </label>
        <label class="flex items-center gap-2">
          <span class="text-muted-foreground">每 /64 预算（次）</span>
          <Input v-model.number="requestBudget" type="number" min="1" max="1000" class="h-8 w-20" />
          <span class="text-muted-foreground/70">用满换点，不再撞同一个 /64</span>
        </label>
        <label class="flex items-center gap-2">
          <span class="text-muted-foreground">段限速（rpm）</span>
          <Input v-model.number="segmentRpm" type="number" min="0" max="600" class="h-8 w-20" />
          <span class="text-muted-foreground/70">每个 /48 每分钟上限，防突发被判异常</span>
        </label>
        <label class="flex items-center gap-2">
          <span class="text-muted-foreground">段突发</span>
          <Input v-model.number="segmentBurst" type="number" min="1" max="120" class="h-8 w-20" />
        </label>
        <label class="flex items-center gap-2">
          <span class="text-muted-foreground">熔断阈值（个 /64）</span>
          <Input v-model.number="segmentFailThreshold" type="number" min="1" max="100" class="h-8 w-20" />
          <span class="text-muted-foreground/70">60 秒内这么多 /64 都 429 就熔断整段</span>
        </label>
        <label class="flex items-center gap-2">
          <span class="text-muted-foreground">熔断时长（秒）</span>
          <Input v-model.number="segmentCooldownSeconds" type="number" min="30" max="86400" class="h-8 w-24" />
        </label>
      </div>

      <!-- 池子节点：填 /48（或 /64）后由网关自己分配 /64，不用再手工列地址 -->
      <div class="space-y-2 rounded-md border border-border/60 p-3">
        <div class="flex flex-wrap items-center justify-between gap-2">
          <div class="text-xs font-medium">
            池子节点（网关自己分配 /64）
          </div>
          <Button variant="outline" size="sm" class="h-7 whitespace-nowrap px-2" @click="addNode">
            新增节点
          </Button>
        </div>
        <p class="text-[11px] text-muted-foreground">
          填 he-ipv6-pool 的地址、用户名密码和它负责的前缀（如 <code>2001:470:2996::/48</code>，多个用逗号分隔）。
          每个 /64 用满预算或拿到 429 就换下一个，段级限速与熔断按这里的前缀算。
        </p>

        <div
          v-if="!nodes.length"
          class="rounded-md border border-dashed border-border/60 p-3 text-[11px] text-muted-foreground"
        >
          还没有池子节点：只能用上面手工列的固定出口。
        </div>

        <details
          v-for="(node, index) in nodes"
          :key="`node-${index}`"
          class="group rounded-md border border-border/60"
          :open="expandedNodes.has(index)"
          @toggle="onToggleNode(index, $event)"
        >
          <summary
            class="flex cursor-pointer select-none items-center gap-2 px-3 py-2 text-xs hover:bg-muted/40"
          >
            <span class="inline-block shrink-0 text-muted-foreground transition-transform group-open:rotate-90">▸</span>
            <span class="shrink-0 font-medium">{{ node.name.trim() || `节点 #${index + 1}` }}</span>
            <span class="min-w-0 flex-1 truncate text-muted-foreground tabular-nums">
              {{ node.addr.trim() || '未填地址' }}
              <template v-if="node.prefixes.trim()"> · {{ node.prefixes.trim() }}</template>
            </span>
            <span
              class="shrink-0 rounded-full px-2 py-0.5 text-[10px]"
              :class="node.enabled ? 'bg-emerald-500/10 text-emerald-600' : 'bg-muted text-muted-foreground'"
            >
              {{ node.enabled ? '启用' : '停用' }}
            </span>
            <Button
              variant="ghost"
              size="sm"
              class="h-7 shrink-0 text-xs"
              @click.stop.prevent="removeNode(index)"
            >
              删除
            </Button>
          </summary>

          <div class="space-y-2 border-t border-border/60 p-3">
            <div class="grid grid-cols-1 gap-2 sm:grid-cols-2">
              <label class="text-xs">
                <span class="text-muted-foreground">名称</span>
                <Input v-model="node.name" class="mt-1 h-8" placeholder="box3" />
              </label>
              <label class="text-xs">
                <span class="text-muted-foreground">SOCKS5 地址</span>
                <Input v-model="node.addr" class="mt-1 h-8" placeholder="47.86.176.10:13001" />
              </label>
              <label class="text-xs">
                <span class="text-muted-foreground">用户名</span>
                <Input v-model="node.user" class="mt-1 h-8" placeholder="opencode" />
              </label>
              <label class="text-xs">
                <span class="text-muted-foreground">密码</span>
                <Input
                  v-model="node.pass"
                  type="password"
                  class="mt-1 h-8"
                  :placeholder="node.pass ? '' : '留空表示不修改'"
                />
              </label>
              <label class="flex items-center gap-2 text-xs sm:col-span-2">
                <Switch v-model="node.enabled" />
                <span class="text-muted-foreground">启用该节点</span>
              </label>
            </div>
            <label class="block text-xs">
              <span class="text-muted-foreground">前缀（/48 或 /64，逗号分隔）</span>
              <Input
                v-model="node.prefixes"
                class="mt-1 h-8 w-full font-mono"
                placeholder="2001:470:2996::/48, 2001:470:848d::/48"
              />
            </label>
            <p
              v-if="node.prefixes.trim() && !prefixesValid(node.prefixes)"
              class="text-[11px] text-destructive"
            >
              前缀格式不对：要写成 xxxx::/48 或 xxxx:xxxx:xxxx:xxxx::/64
            </p>
          </div>
        </details>
      </div>

      <p
        v-if="noUsableExit && !fallbackIpv4"
        class="text-xs text-amber-600 dark:text-amber-400"
      >
        所有出口都已停用，且「出口全挂时回落直连」是关的：请求会直接失败，不会绕过出口。
      </p>

      <p v-if="message" class="text-xs" :class="failed ? 'text-destructive' : 'text-emerald-600'">
        {{ message }}
      </p>
    </div>

    <!-- 实时用量：每个 /64 用了多少、谁在冷却、段是否熔断 -->
    <ProviderEgressUsageCard :provider-id="provider.id" />
  </Card>
</template>

<script setup lang="ts">
import { computed, ref, watch } from 'vue'
import ProviderEgressUsageCard from '@/features/providers/components/ProviderEgressUsageCard.vue'
import Button from '@/components/ui/button.vue'
import Card from '@/components/ui/card.vue'
import Input from '@/components/ui/input.vue'
import Switch from '@/components/ui/switch.vue'
import { updateProvider } from '@/api/endpoints/providers'

interface EgressExit {
  name: string
  addr: string
  user: string
  pass: string
  weight: number
  rotate: boolean
  enabled: boolean
}

interface EgressNode {
  name: string
  addr: string
  user: string
  pass: string
  // 逗号/空格分隔的 /48 或 /64；保存时拆成数组
  prefixes: string
  enabled: boolean
}

interface EgressConfig {
  exits: EgressExit[]
  fallback_ipv4: boolean
  down_seconds: number
  // 2026-10-29 的预算/段级旋钮；面板没编辑的字段（nodes 等）保存时原样带回
  request_budget?: number
  segment_rpm?: number
  segment_burst?: number
  segment_fail_threshold?: number
  segment_cooldown_seconds?: number
  // 池子节点：给了 prefixes，网关就能自己从 /48 里挑 /64
  nodes?: Array<{
    name?: string
    addr?: string
    user?: string
    pass?: string
    prefixes?: string[]
    enabled?: boolean
  }>
}

const props = defineProps<{
  provider: { id: string; config?: Record<string, unknown> | null }
}>()

// 保存成功后让父级重新拉取 provider 快照：props 里还是保存前的 config，
// 不刷新的话下一次回填会把刚改的名称/开关打回旧值（看起来就是「保存没用」）。
const emit = defineEmits<{ refresh: [] }>()

const exits = ref<EgressExit[]>([])
const fallbackIpv4 = ref(true)
const downSeconds = ref(60)
// 2026-10-29 引入的预算/段级旋钮：默认值与后端 parse_config 保持一致。
const requestBudget = ref(10)
const segmentRpm = ref(8)
const segmentBurst = ref(3)
const segmentFailThreshold = ref(3)
const segmentCooldownSeconds = ref(900)
// 池子节点：给了前缀，网关就能自己从 /48 里挑 /64，而不是只能用手工列的固定出口。
const nodes = ref<EgressNode[]>([])
// 池子节点可折叠：默认全收起，一眼看完有几个节点。
const expandedNodes = ref<Set<number>>(new Set())

// 与后端 parse_config 的夹紧范围一致：存什么就该生效什么，
// 否则界面显示 0 而运行时用 5，排查时会被误导。
function clampWeight(value: unknown): number {
  const n = Math.round(Number(value) || 1)
  return Math.min(32, Math.max(1, n))
}

function clampNumber(value: unknown, fallback: number, min: number, max: number): number {
  const raw = Number(value)
  const n = Number.isFinite(raw) ? raw : fallback
  return Math.min(max, Math.max(min, n))
}

function clampDownSeconds(value: unknown): number {
  const raw = Number(value)
  const n = Number.isFinite(raw) && raw > 0 ? Math.round(raw) : 60
  return Math.min(3600, Math.max(5, n))
}
// 全部停用 + 不回落直连 = 请求必然失败：编辑时就提示，别等人发一次请求才发现。
const noUsableExit = computed(() => exits.value.length > 0 && exits.value.every(e => !e.enabled))

const saving = ref(false)
const message = ref('')
const failed = ref(false)
// 有未保存改动时，父级刷新（列表自动刷新/别的操作）不能把界面打回旧值——
// 否则「取消勾选 → 自动刷新打回 true → 保存」会把 true 又写回去。
const dirty = ref(false)
let loading = false

/// `EgressConfig.nodes` 是**落库形态**（prefixes 是数组），界面里要编辑成一行文本，
/// 所以 readConfig 返回的是把 nodes 换成界面形态的视图类型。
type EgressConfigView = Omit<EgressConfig, 'nodes'> & { nodes: EgressNode[] }

function readConfig(): EgressConfigView {
  const raw = (props.provider.config?.opencode_egress ?? null) as Partial<EgressConfig> | null
  const list = Array.isArray(raw?.exits) ? raw!.exits! : []
  return {
    exits: list.map(exit => ({
      name: String(exit?.name ?? ''),
      addr: String(exit?.addr ?? ''),
      user: String(exit?.user ?? ''),
      pass: String(exit?.pass ?? ''),
      weight: clampWeight(exit?.weight),
      rotate: (exit as { rotate?: unknown } | undefined)?.rotate === 'cidr64' || exit?.rotate === true,
      enabled: (exit as { enabled?: unknown } | undefined)?.enabled !== false,
    })),
    fallback_ipv4: raw?.fallback_ipv4 !== false,
    down_seconds: clampDownSeconds(raw?.down_seconds),
    request_budget: clampNumber(raw?.request_budget, 10, 1, 1000),
    segment_rpm: clampNumber(raw?.segment_rpm, 8, 0, 600),
    segment_burst: clampNumber(raw?.segment_burst, 3, 1, 120),
    segment_fail_threshold: clampNumber(raw?.segment_fail_threshold, 3, 1, 100),
    segment_cooldown_seconds: clampNumber(raw?.segment_cooldown_seconds, 900, 30, 86400),
    nodes: (Array.isArray(raw?.nodes) ? raw!.nodes! : []).map(node => ({
      name: String(node?.name ?? ''),
      addr: String(node?.addr ?? ''),
      user: String(node?.user ?? ''),
      pass: String(node?.pass ?? ''),
      prefixes: Array.isArray(node?.prefixes) ? node!.prefixes!.join(', ') : '',
      enabled: node?.enabled !== false,
    })),
  }
}

function load() {
  loading = true
  const config = readConfig()
  exits.value = config.exits
  fallbackIpv4.value = config.fallback_ipv4
  downSeconds.value = config.down_seconds
  requestBudget.value = config.request_budget ?? 10
  segmentRpm.value = config.segment_rpm ?? 8
  segmentBurst.value = config.segment_burst ?? 3
  segmentFailThreshold.value = config.segment_fail_threshold ?? 3
  segmentCooldownSeconds.value = config.segment_cooldown_seconds ?? 900
  nodes.value = config.nodes ?? []
  expandedNodes.value = new Set()
  message.value = ''
  // 让 watcher 在同一个 tick 之后才恢复，避免把这次回填当成用户改动。
  setTimeout(() => {
    loading = false
  }, 0)
}

// 用户改动（输入/勾选/增删）都置脏；只有 provider 换了才强制重载。
watch(
  [exits, nodes, fallbackIpv4, downSeconds, requestBudget, segmentRpm, segmentBurst, segmentFailThreshold, segmentCooldownSeconds],
  () => {
    if (!loading) dirty.value = true
  },
  { deep: true },
)

watch(
  () => props.provider.id,
  () => {
    dirty.value = false
    load()
  },
  { immediate: true },
)
watch(
  () => props.provider.config,
  () => {
    if (dirty.value || saving.value) return
    load()
  },
  { deep: true },
)

function addNode() {
  nodes.value.push({ name: '', addr: '', user: 'opencode', pass: '', prefixes: '', enabled: true })
  // 新增的节点直接展开，省一次点击。
  expandedNodes.value = new Set([...expandedNodes.value, nodes.value.length - 1])
}

function onToggleNode(index: number, event: Event) {
  const target = event.target as (HTMLElement & { open?: boolean }) | null
  if (!target) return
  const next = new Set(expandedNodes.value)
  if (target.open) {
    next.add(index)
  } else {
    next.delete(index)
  }
  expandedNodes.value = next
}

function removeNode(index: number) {
  nodes.value.splice(index, 1)
  // 下标会整体前移，折叠状态跟着重置，避免展开到别的节点上。
  expandedNodes.value = new Set()
}

/// 前缀校验：必须是 IPv6 前缀字面量 + /48 或 /64（后端也只接受 32..64）。
function prefixesValid(raw: string): boolean {
  const parts = raw.split(/[,;\s]+/).map(item => item.trim()).filter(Boolean)
  if (!parts.length) return false
  return parts.every(part => {
    const match = part.match(/^([0-9a-fA-F:]+)\/(\d{1,3})$/)
    if (!match) return false
    const length = Number(match[2])
    if (!(length >= 32 && length <= 64)) return false
    const addr = match[1]
    if (addr.includes(':::')) return false
    const groups = addr.split(':').filter(Boolean)
    return groups.length >= 2 && groups.length <= 8 && /^[0-9a-fA-F:]+$/.test(addr)
  })
}

async function save() {
  saving.value = true
  message.value = ''
  failed.value = false
  try {
    // 以现有配置为底再覆盖：`nodes`、`state_path` 等面板没编辑的字段必须原样保留，
    // 否则一次「保存」就把网关自己分配 /64 的配置抹掉了。
    const existing = (props.provider.config?.opencode_egress ?? {}) as Record<string, unknown>
    const payload = {
      ...existing,
      // 固定出口不再在面板里编辑：原样透传，避免一次保存把它们抹掉。
      exits: Array.isArray(existing.exits) ? existing.exits : [],
      fallback_ipv4: fallbackIpv4.value,
      down_seconds: Math.max(0, Number(downSeconds.value) || 0),
      request_budget: clampNumber(requestBudget.value, 10, 1, 1000),
      segment_rpm: clampNumber(segmentRpm.value, 8, 0, 600),
      segment_burst: clampNumber(segmentBurst.value, 3, 1, 120),
      segment_fail_threshold: clampNumber(segmentFailThreshold.value, 3, 1, 100),
      segment_cooldown_seconds: clampNumber(segmentCooldownSeconds.value, 900, 30, 86400),
      nodes: nodes.value
        .filter(node => node.addr.trim())
        .map(node => {
          // 密码留空 = 不修改：后端只对 `exits` 做了这层保护，nodes 得自己兜住，
          // 否则面板回填时密码框是空的，一保存就把密码清了。
          const previous = (existing.nodes as Array<{ addr?: string; pass?: string }> | undefined)?.find(
            item => item?.addr === node.addr.trim(),
          )
          return {
            name: node.name.trim() || node.addr.trim(),
            addr: node.addr.trim(),
            user: node.user.trim() || 'opencode',
            pass: node.pass.trim() ? node.pass : String(previous?.pass ?? ''),
            prefixes: node.prefixes
              .split(/[,;\s]+/)
              .map(item => item.trim())
              .filter(Boolean),
            enabled: node.enabled,
          }
        }),
    }
    const nextConfig = { ...(props.provider.config ?? {}), opencode_egress: payload }
    await updateProvider(props.provider.id, { config: nextConfig })
    // 以刚提交的值为准，并让父级拉一次新快照，避免下一次回填打回旧值。
    dirty.value = false
    emit('refresh')
    const active = payload.exits.filter(exit => exit.enabled).length
    message.value = payload.exits.length
      ? `已保存 ${active} 个启用出口，下一次请求生效`
      : '已清空出口，回到直连'
  } catch (error) {
    failed.value = true
    message.value = error instanceof Error ? error.message : '保存失败'
  } finally {
    saving.value = false
  }
}
</script>
