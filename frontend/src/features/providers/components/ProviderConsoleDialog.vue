<template>
  <Dialog
    :open="open"
    :title="title"
    description="内嵌供应商管理面板（一次性免密链接，90 秒内有效）"
    :icon="TerminalSquare"
    size="xl"
    @update:open="handleOpenChange"
  >
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
      class="space-y-3 py-8"
    >
      <div class="text-sm text-destructive">
        {{ issueError }}
      </div>
      <div class="flex justify-end">
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
        class="w-full rounded-md border border-border bg-background"
        style="height: min(72vh, 720px)"
        referrerpolicy="no-referrer"
        allow="clipboard-write"
      />
      <p class="text-xs text-muted-foreground">
        面板在弹窗内直接操作；会话过期后面板自身会要求登录。关闭弹窗不会影响面板里已保存的配置。
      </p>
    </div>
  </Dialog>
</template>

<script setup lang="ts">
import { ref, computed, watch } from 'vue'
import { Loader2, RotateCw, TerminalSquare } from 'lucide-vue-next'
import { Dialog, Button } from '@/components/ui'
import client from '@/api/client'
import { parseApiError } from '@/utils/errorParser'
import type { ProviderWithEndpointsSummary } from '@/api/endpoints'

const props = defineProps<{
  open: boolean
  provider: ProviderWithEndpointsSummary | null
}>()

const emit = defineEmits<{
  (e: 'update:open', value: boolean): void
}>()

const issuing = ref(false)
const issueError = ref('')
const consoleUrl = ref('')
// 每次重新打开/重签都换 key，强制 iframe 重新加载（避免复用旧会话 DOM）
const iframeKey = ref(0)

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

function handleOpenChange(value: boolean): void {
  emit('update:open', value)
}
</script>
