<template>
  <Dialog
    :open="open"
    :title="title"
    description="内嵌供应商管理面板（一次性免密链接，90 秒内有效）"
    :icon="TerminalSquare"
    size="xl"
    @update:open="handleOpenChange"
  >
    <!-- 头部右上角的关闭：Dialog 本身不提供关闭按钮，必须由调用方显式放一个 -->
    <template #header-actions>
      <Button
        variant="ghost"
        size="icon"
        class="h-8 w-8 shrink-0 text-muted-foreground hover:text-foreground"
        :title="legacyT('关闭')"
        :aria-label="legacyT('关闭')"
        @click="close"
      >
        <X class="h-4 w-4" />
      </Button>
    </template>

    <!-- 签发中 -->
    <div
      v-if="issuing"
      class="flex items-center justify-center gap-2 py-16 text-sm text-muted-foreground"
    >
      <Loader2 class="w-4 h-4 animate-spin" />
      正在签发控制台免密链接...
    </div>
    <!-- 签发失败 -->
    <div
      v-else-if="issueError"
      class="space-y-4 py-6"
    >
      <div class="rounded-lg border border-destructive/30 bg-destructive/5 p-3 text-sm text-destructive">
        {{ issueError }}
      </div>
      <!-- 缺密钥是最常见的失败原因，直接把配置位置写清楚，省得去猜 -->
      <div
        v-if="secretMissing"
        class="space-y-2 rounded-lg border border-border bg-muted/30 p-3 text-xs leading-5 text-muted-foreground"
      >
        <p class="font-medium text-foreground">
          配置位置
        </p>
        <p>
          1. 面板地址：供应商 → 端点 → 编辑，填 <code class="rounded bg-background px-1">base_url</code>
          （反代会去掉结尾的 <code class="rounded bg-background px-1">/v1</code> 后作为面板源站）。
        </p>
        <p>
          2. 共享密钥：供应商 config 里的
          <code class="rounded bg-background px-1">provider_ops.console_shared_secret</code>，
          必须与 Go 面板的 <code class="rounded bg-background px-1">-console-secret</code>
          （<code class="rounded bg-background px-1">/etc/opencode2api-console-secret</code>）完全一致。
        </p>
      </div>
      <div class="flex justify-end gap-2">
        <Button
          variant="outline"
          size="sm"
          @click="issueConsoleUrl"
        >
          <RotateCw class="w-3.5 h-3.5 mr-1.5" />
          重试
        </Button>
      </div>
    </div>
    <!-- 面板 iframe -->
    <div
      v-else-if="consoleUrl"
      class="space-y-2"
    >
      <iframe
        :key="iframeKey"
        :src="consoleUrl"
        :title="`${title} 面板`"
        class="w-full rounded-md border border-border bg-background"
        style="height: min(70vh, 680px)"
        referrerpolicy="no-referrer"
        allow="clipboard-write"
      />
      <p class="text-xs text-muted-foreground">
        面板在弹窗内直接操作；会话过期后面板自身会要求登录。关闭弹窗不会影响面板里已保存的配置。
      </p>
    </div>

    <template #footer>
      <Button
        variant="outline"
        @click="close"
      >
        {{ legacyT('关闭') }}
      </Button>
      <Button
        v-if="consoleUrl"
        variant="outline"
        @click="issueConsoleUrl"
      >
        <RotateCw class="mr-1.5 h-3.5 w-3.5" />
        重新加载面板
      </Button>
    </template>
  </Dialog>
</template>

<script setup lang="ts">
import { ref, computed, watch } from 'vue'
import { Loader2, RotateCw, TerminalSquare, X } from 'lucide-vue-next'
import { Dialog, Button } from '@/components/ui'
import client from '@/api/client'
import { parseApiError } from '@/utils/errorParser'
import { useI18n } from '@/i18n'
import type { ProviderWithEndpointsSummary } from '@/api/endpoints'

const props = defineProps<{
  open: boolean
  provider: ProviderWithEndpointsSummary | null
}>()

const emit = defineEmits<{
  (e: 'update:open', value: boolean): void
}>()

const { legacyT } = useI18n()

const issuing = ref(false)
const issueError = ref('')
const consoleUrl = ref('')
// 每次重新打开/重签都换 key，强制 iframe 重新加载（避免复用旧会话 DOM）
const iframeKey = ref(0)

// 缺密钥/缺 provider_ops 时顺手把配置位置展示出来
const secretMissing = computed(() => /console_shared_secret|provider_ops/.test(issueError.value))

const title = computed(() =>
  props.provider ? `控制台 · ${props.provider.name}` : '控制台'
)

watch(
  () => props.open,
  open => {
    if (open) {
      iframeKey.value += 1
      void issueConsoleUrl()
    } else {
      // 关闭即丢弃一次性 URL：不残留可重放的地址
      consoleUrl.value = ''
      issueError.value = ''
    }
  }
)

async function issueConsoleUrl(): Promise<void> {
  if (!props.provider) return
  issuing.value = true
  issueError.value = ''
  consoleUrl.value = ''
  iframeKey.value += 1
  try {
    const response = await client.post<{ url: string }>(
      `/api/admin/provider-ops/providers/${props.provider.id}/console-url`
    )
    consoleUrl.value = response.data.url
  } catch (error) {
    issueError.value = parseApiError(error)
  } finally {
    issuing.value = false
  }
}

function close(): void {
  emit('update:open', false)
}

function handleOpenChange(value: boolean): void {
  emit('update:open', value)
}
</script>
