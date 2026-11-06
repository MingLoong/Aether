<template>
  <Dialog
    :open="open"
    :title="title"
    description="内嵌供应商管理面板（一次性免密链接，90 秒内有效）"
    :icon="TerminalSquare"
    size="7xl"
    @update:open="handleOpenChange"
  >
    <template #header-actions>
      <Button
        variant="ghost"
        size="icon"
        :title="t('ui.consoleSettings')"
        :class="{ 'bg-accent text-accent-foreground': settingsOpen }"
        :aria-pressed="settingsOpen"
        @click="toggleSettings"
      >
        <Settings class="w-4 h-4" />
      </Button>
      <Button
        variant="ghost"
        size="icon"
        :title="t('ui.reloadPanel')"
        :disabled="issuing || settingsOpen"
        @click="reloadPanel"
      >
        <RotateCw class="w-4 h-4" />
      </Button>
      <Button
        variant="ghost"
        size="icon"
        :title="t('ui.close')"
        @click="handleOpenChange(false)"
      >
        <X class="w-4 h-4" />
      </Button>
    </template>

    <!-- 设置面板：面板地址 + 免密 SSO 密钥 -->
    <div
      v-if="settingsOpen"
      class="space-y-4"
    >
      <div class="space-y-1.5">
        <Label class="text-xs text-muted-foreground">面板地址（console_base_url）</Label>
        <Input
          v-model="settingsForm.console_base_url"
          size="sm"
          placeholder="http://host:port，留空则取首个启用端点地址并去掉 /v1"
        />
        <p class="text-xs text-muted-foreground">
          面板与 API 不同端口/不同域名时必须填。当前生效：{{ settings?.console_base_url_effective || '未配置' }}
        </p>
      </div>

      <div class="space-y-1.5">
        <Label class="text-xs text-muted-foreground">免密 SSO 密钥（console_shared_secret）</Label>
        <Input
          v-model="settingsForm.console_shared_secret"
          size="sm"
          type="password"
          :placeholder="settings?.console_shared_secret_configured
            ? `已配置 ${settings?.console_shared_secret_preview}，留空则不修改`
            : '与面板约定的 HMAC 密钥'"
        />
        <p class="text-xs text-muted-foreground">
          签名算法与面板一致：<code>hex(HMAC-SHA256(secret, "pid|exp|nonce"))</code>。密钥只写入不回显。
        </p>
      </div>

      <div class="flex items-center justify-end gap-2">
        <Button
          v-if="hasSavedSettings"
          variant="ghost"
          size="sm"
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
            class="w-3.5 h-3.5 mr-1.5 animate-spin"
          />
          <Save
            v-else
            class="w-3.5 h-3.5 mr-1.5"
          />
          保存设置
        </Button>
      </div>
    </div>

    <template v-else>
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
        <div class="flex justify-end gap-2">
          <Button
            variant="outline"
            size="sm"
            @click="settingsOpen = true"
          >
            <Settings class="w-3.5 h-3.5 mr-1.5" />
            填写面板地址 / 密钥
          </Button>
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
    </template>
  </Dialog>
</template>

<script setup lang="ts">
import { ref, computed, watch } from 'vue'
import { Loader2, RotateCw, Save, Settings, TerminalSquare, X } from 'lucide-vue-next'
import { Dialog, Button, Input, Label } from '@/components/ui'
import client from '@/api/client'
import { parseApiError } from '@/utils/errorParser'
import { useToast } from '@/composables/useToast'
import { useI18n } from '@/i18n'
import type { ProviderWithEndpointsSummary } from '@/api/endpoints'

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

const { success, error: showError } = useToast()
const { t } = useI18n()

const issuing = ref(false)
const issueError = ref('')
const consoleUrl = ref('')
// 每次重新打开/重签都换 key，强制 iframe 重新加载（避免复用旧会话 DOM）
const iframeKey = ref(0)

const settings = ref<ConsoleSettings | null>(null)
const settingsOpen = ref(false)
const savingSettings = ref(false)
const settingsForm = ref({ console_base_url: '', console_shared_secret: '' })

const title = computed(() =>
  props.provider ? `控制台 · ${props.provider.name}` : '控制台'
)

const hasSavedSettings = computed(() => settings.value?.console_shared_secret_configured === true)

const settingsDirty = computed(() => {
  const current = settings.value
  const baseUrlChanged =
    settingsForm.value.console_base_url.trim() !== (current?.console_base_url ?? '')
  // 密钥输入框留空 = 不修改，不算脏
  const secretChanged = settingsForm.value.console_shared_secret.trim().length > 0
  return baseUrlChanged || secretChanged
})

watch(
  () => props.open,
  async open => {
    if (open) {
      iframeKey.value += 1
      await loadSettings()
    } else {
      // 关闭即丢弃一次性 URL：不残留可重放的地址
      consoleUrl.value = ''
      issueError.value = ''
      settingsOpen.value = false
      settings.value = null
      settingsForm.value = { console_base_url: '', console_shared_secret: '' }
    }
  }
)

async function loadSettings(): Promise<void> {
  if (!props.provider) return
  settings.value = null
  try {
    const response = await client.get<ConsoleSettings>(
      `/api/admin/provider-ops/providers/${props.provider.id}/console-settings`
    )
    settings.value = response.data
    settingsForm.value = {
      console_base_url: response.data.console_base_url ?? '',
      console_shared_secret: '',
    }
    // 没配密钥 / 找不到面板地址时直接进设置，不然签发必然失败
    if (!response.data.console_shared_secret_configured
      || response.data.console_base_url_source === 'missing') {
      settingsOpen.value = true
      return
    }
    settingsOpen.value = false
    await issueConsoleUrl()
  } catch (error) {
    issueError.value = parseApiError(error)
  }
}

async function saveSettings(): Promise<void> {
  if (!props.provider) return
  savingSettings.value = true
  try {
    const payload: { console_base_url?: string; console_shared_secret?: string } = {}
    const baseUrl = settingsForm.value.console_base_url.trim()
    if (baseUrl !== (settings.value?.console_base_url ?? '')) {
      // 传空串 = 清除显式地址，回退到端点地址
      payload.console_base_url = baseUrl
    }
    const secret = settingsForm.value.console_shared_secret.trim()
    if (secret) {
      payload.console_shared_secret = secret
    }
    const response = await client.put<ConsoleSettings>(
      `/api/admin/provider-ops/providers/${props.provider.id}/console-settings`,
      payload
    )
    settings.value = response.data
    settingsForm.value = {
      console_base_url: response.data.console_base_url ?? '',
      console_shared_secret: '',
    }
    success('控制台设置已保存')
    settingsOpen.value = false
    await issueConsoleUrl()
  } catch (error) {
    showError(parseApiError(error), '保存失败')
  } finally {
    savingSettings.value = false
  }
}

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

/// 重新签发一次性 URL 并强制 iframe 重载（面板会话仍由面板自身维持）。
function reloadPanel(): void {
  iframeKey.value += 1
  void issueConsoleUrl()
}

/// 齿轮：按一下展开设置，再按收起；收起时若还没有面板内容就自动签发。
function toggleSettings(): void {
  settingsOpen.value = !settingsOpen.value
  if (!settingsOpen.value && !consoleUrl.value && hasSavedSettings.value) {
    void issueConsoleUrl()
  }
}

function handleOpenChange(value: boolean): void {
  emit('update:open', value)
}
</script>
