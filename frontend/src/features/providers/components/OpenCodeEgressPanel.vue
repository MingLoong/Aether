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
      <div class="flex items-center justify-between">
        <div>
          <h3 class="text-sm font-semibold">出口（SOCKS5）</h3>
          <p class="mt-1 text-xs text-muted-foreground">
            失败按权重换下一个出口；出口内部可按 /64 轮换出口 IP。停用的出口保留配置但不参与拨号。
          </p>
        </div>
        <div class="flex items-center gap-2">
          <Button variant="outline" size="sm" class="h-8" @click="addExit">新增出口</Button>
          <Button size="sm" class="h-8" :disabled="saving" @click="save">
            {{ saving ? '保存中…' : '保存' }}
          </Button>
        </div>
      </div>
    </div>

    <div class="p-4 space-y-2">
      <div v-if="!exits.length" class="rounded-md border border-dashed border-border/60 p-4 text-xs text-muted-foreground">
        还没有出口，当前请求直连。点「新增出口」填 SOCKS5 地址。
      </div>

      <details
        v-for="(exit, index) in exits"
        :key="index"
        class="group rounded-md border border-border/60"
        :open="expanded.has(index)"
        @toggle="onToggle(index, $event)"
      >
        <summary
          class="flex cursor-pointer select-none items-center gap-2 px-3 py-2 text-xs hover:bg-muted/40"
        >
          <span class="inline-block shrink-0 text-muted-foreground transition-transform group-open:rotate-90">▸</span>
          <span class="shrink-0 font-medium">{{ exit.name.trim() || `出口 #${index + 1}` }}</span>
          <span class="min-w-0 flex-1 truncate text-muted-foreground tabular-nums">
            {{ exit.addr.trim() || '未填地址' }}
          </span>
          <span
            class="shrink-0 rounded-full px-2 py-0.5 text-[10px]"
            :class="exit.enabled ? 'bg-emerald-500/10 text-emerald-600' : 'bg-muted text-muted-foreground'"
          >
            {{ exit.enabled ? '启用' : '停用' }}
          </span>
          <span class="shrink-0" @click.stop @mousedown.stop>
            <Switch v-model="exit.enabled" :aria-label="`启停 ${exit.name || index + 1}`" />
          </span>
          <Button
            variant="ghost"
            size="sm"
            class="h-7 shrink-0 text-xs"
            @click.stop.prevent="removeExit(index)"
          >
            删除
          </Button>
        </summary>

        <div class="grid grid-cols-1 gap-2 border-t border-border/60 p-3 sm:grid-cols-2">
          <label class="text-xs">
            <span class="text-muted-foreground">名称</span>
            <Input v-model="exit.name" class="mt-1 h-8" placeholder="he64" />
          </label>
          <label class="text-xs">
            <span class="text-muted-foreground">SOCKS5 地址</span>
            <Input v-model="exit.addr" class="mt-1 h-8" placeholder="1.2.3.4:13001" />
          </label>
          <label class="text-xs">
            <span class="text-muted-foreground">用户名</span>
            <Input v-model="exit.user" class="mt-1 h-8" placeholder="opencode" />
          </label>
          <label class="text-xs">
            <span class="text-muted-foreground">密码</span>
            <Input v-model="exit.pass" type="password" class="mt-1 h-8" placeholder="留空表示不改" />
          </label>
          <label class="text-xs">
            <span class="text-muted-foreground">权重</span>
            <Input v-model.number="exit.weight" type="number" min="1" class="mt-1 h-8" />
          </label>
          <label class="mt-5 flex items-center gap-2 text-xs">
            <input v-model="exit.rotate" type="checkbox" class="h-3.5 w-3.5" />
            <span>按 /64 轮换出口 IP（用户名加 -cidr-64）</span>
          </label>
        </div>
      </details>

      <div class="flex flex-wrap items-center gap-4 border-t border-border/60 pt-3 text-xs">
        <label class="flex items-center gap-2">
          <input v-model="fallbackIpv4" type="checkbox" class="h-3.5 w-3.5" />
          <span>出口全挂时回落直连</span>
        </label>
        <label class="flex items-center gap-2">
          <span class="text-muted-foreground">出口失败冷却（秒）</span>
          <Input v-model.number="downSeconds" type="number" min="0" class="h-8 w-24" />
        </label>
      </div>

      <p v-if="message" class="text-xs" :class="failed ? 'text-destructive' : 'text-emerald-600'">
        {{ message }}
      </p>
    </div>
  </Card>
</template>

<script setup lang="ts">
import { ref, watch } from 'vue'
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

interface EgressConfig {
  exits: EgressExit[]
  fallback_ipv4: boolean
  down_seconds: number
}

const props = defineProps<{
  provider: { id: string; config?: Record<string, unknown> | null }
}>()

const exits = ref<EgressExit[]>([])
const fallbackIpv4 = ref(true)
const downSeconds = ref(60)
const saving = ref(false)
const message = ref('')
const failed = ref(false)
// 哪些出口是展开的：默认全收起，一眼看完所有出口，点三角才看代理信息。
const expanded = ref<Set<number>>(new Set())

function readConfig(): EgressConfig {
  const raw = (props.provider.config?.opencode_egress ?? null) as Partial<EgressConfig> | null
  const list = Array.isArray(raw?.exits) ? raw!.exits! : []
  return {
    exits: list.map(exit => ({
      name: String(exit?.name ?? ''),
      addr: String(exit?.addr ?? ''),
      user: String(exit?.user ?? ''),
      pass: String(exit?.pass ?? ''),
      weight: Number(exit?.weight ?? 1) || 1,
      rotate: (exit as { rotate?: unknown } | undefined)?.rotate === 'cidr64' || exit?.rotate === true,
      enabled: (exit as { enabled?: unknown } | undefined)?.enabled !== false,
    })),
    fallback_ipv4: raw?.fallback_ipv4 !== false,
    down_seconds: Number(raw?.down_seconds ?? 60) || 60,
  }
}

function load() {
  const config = readConfig()
  exits.value = config.exits
  fallbackIpv4.value = config.fallback_ipv4
  downSeconds.value = config.down_seconds
  expanded.value = new Set()
  message.value = ''
}

watch(() => props.provider.id, load, { immediate: true })
watch(() => props.provider.config, load, { deep: true })

function onToggle(index: number, event: Event) {
  const target = event.target as (HTMLElement & { open?: boolean }) | null
  if (!target) return
  const next = new Set(expanded.value)
  if (target.open) {
    next.add(index)
  } else {
    next.delete(index)
  }
  expanded.value = next
}

function addExit() {
  exits.value.push({ name: '', addr: '', user: '', pass: '', weight: 1, rotate: true, enabled: true })
  // 新增的出口直接展开，省一次点击。
  expanded.value = new Set([...expanded.value, exits.value.length - 1])
}

function removeExit(index: number) {
  exits.value.splice(index, 1)
  expanded.value = new Set()
}

async function save() {
  saving.value = true
  message.value = ''
  failed.value = false
  try {
    const payload = {
      exits: exits.value
        .filter(exit => exit.addr.trim())
        .map(exit => ({
          name: exit.name.trim() || exit.addr.trim(),
          addr: exit.addr.trim(),
          user: exit.user.trim(),
          pass: exit.pass,
          weight: Math.max(1, Number(exit.weight) || 1),
          rotate: exit.rotate ? 'cidr64' : 'none',
          enabled: exit.enabled,
        })),
      fallback_ipv4: fallbackIpv4.value,
      down_seconds: Math.max(0, Number(downSeconds.value) || 0),
    }
    const nextConfig = { ...(props.provider.config ?? {}), opencode_egress: payload }
    await updateProvider(props.provider.id, { config: nextConfig })
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
