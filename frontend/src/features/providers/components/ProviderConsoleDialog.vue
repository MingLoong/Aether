<template>
  <Dialog
    :open="open"
    :title="title"
    description="内嵌供应商管理面板（一次性免密链接，90 秒内有效）"
    :icon="TerminalSquare"
    size="7xl"
    @update:open="handleOpenChange"
  >
    <!-- 头部右上角的关闭：Dialog 本身不提供关闭按钮，必须由调用方显式放一个 -->
    <template #header-actions>
      <Button
        variant="ghost"
        size="icon"
        class="h-8 w-8 shrink-0 text-muted-foreground hover:text-foreground"
        :title="legacyT('设置')"
        :aria-label="legacyT('设置')"
        @click="settingsOpen = !settingsOpen"
      >
        <Settings class="h-4 w-4" />
      </Button>
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

    <!-- 设置面板：面板地址与共享密钥都在这里配 -->
    <div
      v-if="settingsOpen"
      class="space-y-4 border-b border-border pb-4"
    >
      <div class="space-y-1.5">
        <Label class="text-xs font-medium">
          面板地址
        </Label>
        <Input
          v-model="settingsForm.console_base_url"
          placeholder="https://panel.example.com（留空则用端点的 base_url 去掉 /v1）"
          spellcheck="false"
          autocomplete="off"
        />
        <p class="text-xs leading-5 text-muted-foreground">
          当前生效：<code class="rounded bg-muted px-1 py-0.5">{{ settings?.console_base_url_effective || '未配置' }}</code>
          <span v-if="settings?.console_base_url_source === 'endpoint'">（来自端点）</span>
          <span v-else-if="settings?.console_base_url_source === 'explicit'">（手动指定）</span>
        </p>
      </div>

      <div class="space-y-1.5">
        <Label class="text-xs font-medium">
          共享密钥
        </Label>
        <Input
          v-model="settingsForm.console_shared_secret"
          type="password"
          :placeholder="settings?.console_shared_secret_configured
            ? `已配置 ${settings.console_shared_secret_preview}，留空不修改`
            : '与 Go 面板 -console-secret 一致（留空不修改）'"
          spellcheck="false"
          autocomplete="new-password"
        />
        <p class="text-xs leading-5 text-muted-foreground">
          必须与面板侧的 <code class="rounded bg-muted px-1 py-0.5">-console-secret</code>
          （容器里通常是 <code class="rounded bg-muted px-1 py-0.5">/etc/opencode2api-console-secret</code>）完全一致。
          填 <code class="rounded bg-muted px-1 py-0.5">-</code> 并保存可清除已配置的密钥（清空后控制台入口会失效）。
        </p>
      </div>

      <div class="flex items-center justify-end gap-2">
        <Button
          variant="ghost"
          size="sm"
          :disabled="savingSettings"
          @click="settingsOpen = false"
        >
          取消
        </Button>
        <Button
          size="sm"
          :disabled="savingSettings || !settingsDirty"
          @click="saveSettings"
        >
          <Loader2
            v-if="savingSettings"
            class="mr-1.5 h-3.5 w-3.5 animate-spin"
          />
          {{ savingSettings ? '保存中...' : '保存设置' }}
        </Button>
      </div>
    </div>

    <!-- 签发中 -->
    <div
      v-if="issuing"
      class="flex items-center justify-center gap-2 py-16 text-sm text-muted-foreground"
    >
      <Loader2 class="h-4 w-4 animate-spin" />
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
      <div class="flex justify-end gap-2">
        <Button
          variant="outline"
          size="sm"
          @click="settingsOpen = true"
        >
          <Settings class="mr-1.5 h-3.5 w-3.5" />
          打开设置
        </Button>
        <Button
          variant="outline"
          size="sm"
          @click="issueConsoleUrl"
        >
          <RotateCw class="mr-1.5 h-3.5 w-3.5" />
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
        :style="{ height: settingsOpen ? 'min(56vh, 560px)' : 'min(70vh, 680px)' }"
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
import { ref, computed, watch, reactive } from 'vue'
import { Loader2, RotateCw, Settings, TerminalSquare, X } from 'lucide-vue-next'
import { Dialog, Button, Input, Label } from '@/components/ui'
import client from '@/api/client'
import { parseApiError } from '@/utils/errorParser'
import { useI18n } from '@/i18n'
import { useToast } from '@/composables/useToast'
import type { ProviderWithEndpointsSummary } from '@/api/endpoints'

/** 控制台设置：面板地址 + 共享密钥（后端 GET/PUT /console-settings） */
interface ConsoleSettings {
  provider_id: string
  console_base_url: string | null
  console_base_url_effective: string | null
  console_base_url_source: 'explicit' | 'endpoint' | 'missing'
  endpoint_base_url: string | null
  console_shared_secret_configured: boolean
  console_shared_secret_preview: string | null
}

const props = defineProps<{
  open: boolean
  provider: ProviderWithEndpointsSummary | null
}>()

const emit = defineEmits<{
  (e: 'update:open', value: boolean): void
}>()

const { legacyT } = useI18n()
const { success: showSuccess, error: showError } = useToast()

const issuing = ref(false)
const issueError = ref('')
const consoleUrl = ref('')
// 每次重新打开/重签都换 key，强制 iframe 重新加载（避免复用旧会话 DOM）
const iframeKey = ref(0)

const settingsOpen = ref(false)
const settings = ref<ConsoleSettings | null>(null)
const settingsLoading = ref(false)
const savingSettings = ref(false)
const settingsForm = reactive({
  console_base_url: '',
  console_shared_secret: '',
})

const title = computed(() =>
  props.provider ? `控制台 · ${props.provider.name}` : '控制台'
)

// 密钥输入框留空 = 不修改；地址框与当前值不同即视为有改动
const settingsDirty = computed(() => {
  if (!settings.value) return settingsForm.console_base_url.trim().length > 0
  const currentBase = settings.value.console_base_url ?? ''
  return (
    settingsForm.console_base_url.trim() !== currentBase ||
    settingsForm.console_shared_secret.trim().length > 0
  )
})

watch(
  () => props.open,
  open => {
    if (open) {
      iframeKey.value += 1
      settingsOpen.value = false
      void loadSettings().then(() => issueConsoleUrl())
    } else {
      // 关闭即丢弃一次性 URL：不残留可重放的地址
      consoleUrl.value = ''
      issueError.value = ''
      settings.value = null
      settingsForm.console_base_url = ''
      settingsForm.console_shared_secret = ''
    }
  }
)

async function loadSettings(): Promise<void> {
  if (!props.provider) return
  settingsLoading.value = true
  try {
    const response = await client.get<ConsoleSettings>(
      `/api/admin/provider-ops/providers/${props.provider.id}/console-settings`
    )
    settings.value = response.data
    settingsForm.console_base_url = response.data.console_base_url ?? ''
    settingsForm.console_shared_secret = ''
  } catch {
    // 设置读不到不阻塞面板本身：签发失败时用户会看到具体原因
    settings.value = null
  } finally {
    settingsLoading.value = false
  }
}

async function saveSettings(): Promise<void> {
  if (!props.provider) return
  const payload: Record<string, string> = {}
  const baseUrl = settingsForm.console_base_url.trim()
  const secret = settingsForm.console_shared_secret.trim()
  // 只在真的改了才提交：没传的字段后端视为「不修改」
  if (settings.value && baseUrl !== (settings.value.console_base_url ?? '')) {
    payload.console_base_url = baseUrl
  } else if (!settings.value && baseUrl) {
    payload.console_base_url = baseUrl
  }
  if (secret) {
    payload.console_shared_secret = secret === '-' ? '' : secret
  }
  if (Object.keys(payload).length === 0) {
    settingsOpen.value = false
    return
  }
  savingSettings.value = true
  try {
    const response = await client.put<ConsoleSettings>(
      `/api/admin/provider-ops/providers/${props.provider.id}/console-settings`,
      payload
    )
    settings.value = response.data
    settingsForm.console_base_url = response.data.console_base_url ?? ''
    settingsForm.console_shared_secret = ''
    settingsOpen.value = false
    showSuccess('控制台设置已保存')
    await issueConsoleUrl()
  } catch (error) {
    showError(parseApiError(error, '保存控制台设置失败'))
  } finally {
    savingSettings.value = false
  }
}

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
