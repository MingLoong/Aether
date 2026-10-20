<template>
  <div class="flex flex-col min-w-0">
    <div class="flex items-center gap-1.5">
      <span
        class="text-sm font-medium truncate"
        :class="displayName ? 'cursor-pointer hover:text-primary transition-colors' : ''"
        :title="displayNameTitle"
        data-testid="provider-key-name"
        @click.stop="displayName && $emit('copyName', displayName)"
      >
        {{ displayName || legacyT('未命名密钥') }}
      </span>

      <Badge
        v-if="oauthPlanLabel"
        variant="outline"
        class="text-[10px] px-1.5 py-0 shrink-0"
        :class="oauthPlanClass"
        data-testid="provider-key-oauth-plan"
      >
        {{ oauthPlanLabel }}
      </Badge>

      <Badge
        v-if="oauthOrgBadge"
        variant="secondary"
        class="text-[9px] px-1 py-0 h-4 shrink-0"
        :title="oauthOrgBadge.title"
        data-testid="provider-key-oauth-org"
      >
        {{ oauthOrgBadge.label }}
      </Badge>

      <Badge
        v-if="workbuddyRealmBadge"
        variant="outline"
        class="text-[10px] px-1.5 py-0 shrink-0"
        :class="workbuddyRealmBadge.class"
        :title="workbuddyRealmBadge.title"
        data-testid="provider-key-workbuddy-realm"
      >
        {{ workbuddyRealmBadge.label }}
      </Badge>

      <Badge
        v-if="kiroSubscriptionLabel"
        variant="outline"
        class="text-[10px] px-1.5 py-0 shrink-0"
        :class="kiroSubscriptionClass"
        data-testid="provider-key-kiro-plan"
      >
        {{ kiroSubscriptionLabel }}
      </Badge>
    </div>

    <div class="flex items-center gap-1">
      <span class="text-[11px] font-mono text-muted-foreground">
        {{ maskedSecretLabel }}
      </span>

      <Button
        v-if="canExportCredential"
        variant="ghost"
        size="icon"
        class="h-4 w-4 shrink-0"
        :title="legacyT('下载 OAuth 授权文件')"
        @click.stop="$emit('downloadCredential')"
      >
        <Download class="w-2.5 h-2.5" />
      </Button>
      <Button
        v-else-if="apiKey.agent_identity !== true"
        variant="ghost"
        size="icon"
        class="h-4 w-4 shrink-0"
        :title="legacyT('复制密钥')"
        @click.stop="$emit('copyFullKey')"
      >
        <Copy class="w-2.5 h-2.5" />
      </Button>

      <template v-if="showOAuthRefreshControl">
        <template v-if="accountLevelBlock">
          <Badge
            variant="destructive"
            class="text-[10px] px-1.5 py-0 shrink-0 gap-0.5"
            :title="oauthStatusTitle"
            data-testid="provider-key-account-block"
          >
            <ShieldX class="w-2.5 h-2.5" />
            {{ legacyT('账号异常') }}
          </Badge>
          <Button
            variant="ghost"
            size="icon"
            class="h-4 w-4 shrink-0 text-destructive hover:text-destructive"
            :disabled="clearingOAuthInvalid"
            :title="legacyT('清除异常标记（确认账号已完成验证后使用）')"
            @click.stop="$emit('clearOAuthInvalid')"
          >
            <RefreshCw
              class="w-2.5 h-2.5"
              :class="{ 'animate-spin': clearingOAuthInvalid }"
            />
          </Button>
        </template>

        <template v-else>
          <span
            class="text-[10px]"
            :class="oauthStatusClass"
            :title="oauthStatusTitle"
            data-testid="provider-key-oauth-status"
          >
            {{ oauthStatus?.text }}
          </span>
          <Badge
            v-if="apiKey.oauth_temporary"
            variant="outline"
            class="text-[10px] px-1.5 py-0 shrink-0"
            :title="legacyT('仅通过 Access Token 导入，无法自动刷新，到期后需要重新导入')"
            data-testid="provider-key-temporary"
          >
            {{ legacyT('临时') }}
          </Badge>
          <Button
            variant="ghost"
            size="icon"
            class="h-4 w-4 shrink-0"
            :disabled="refreshingOAuth || !canRefreshCredential"
            :title="oauthRefreshButtonTitle"
            @click.stop="$emit('refreshOAuth')"
          >
            <RefreshCw
              class="w-2.5 h-2.5"
              :class="{ 'animate-spin': refreshingOAuth }"
            />
          </Button>
        </template>
      </template>

      <span
        v-if="antigravityInactive"
        class="text-[10px] text-orange-500 dark:text-orange-400"
        :title="legacyT('该账号尚未完成 Gemini Code Assist 激活，无法获取配额和使用模型')"
        data-testid="provider-key-antigravity-inactive"
      >
        {{ legacyT('账号未激活') }}
      </span>
    </div>
  </div>
</template>

<script setup lang="ts">
import { computed } from 'vue'
import { Copy, Download, RefreshCw, ShieldX } from 'lucide-vue-next'
import Button from '@/components/ui/button.vue'
import Badge from '@/components/ui/badge.vue'
import { useI18n } from '@/i18n'
import type { EndpointAPIKey } from '@/api/endpoints'
import type { OAuthStatusInfo } from '@/composables/useCountdownTimer'

interface OAuthOrgBadgeDisplay {
  label: string
  title: string
}

const props = withDefaults(defineProps<{
  apiKey: EndpointAPIKey
  maskedSecretLabel: string
  oauthPlanLabel?: string | null
  oauthPlanClass?: string
  oauthOrgBadge?: OAuthOrgBadgeDisplay | null
  kiroSubscriptionLabel?: string | null
  kiroSubscriptionClass?: string
  canExportCredential?: boolean
  showOAuthRefreshControl?: boolean
  accountLevelBlock?: boolean
  oauthStatus?: OAuthStatusInfo | null
  oauthStatusTitle?: string
  oauthRefreshButtonTitle?: string
  canRefreshCredential?: boolean
  clearingOAuthInvalid?: boolean
  refreshingOAuth?: boolean
  antigravityInactive?: boolean
}>(), {
  oauthPlanLabel: null,
  oauthPlanClass: '',
  oauthOrgBadge: null,
  kiroSubscriptionLabel: null,
  kiroSubscriptionClass: '',
  canExportCredential: false,
  showOAuthRefreshControl: false,
  accountLevelBlock: false,
  oauthStatus: null,
  oauthStatusTitle: '',
  oauthRefreshButtonTitle: '',
  canRefreshCredential: false,
  clearingOAuthInvalid: false,
  refreshingOAuth: false,
  antigravityInactive: false,
})

defineEmits<{
  (e: 'copyName', name: string): void
  (e: 'downloadCredential'): void
  (e: 'copyFullKey'): void
  (e: 'clearOAuthInvalid'): void
  (e: 'refreshOAuth'): void
}>()

const { legacyT } = useI18n()

const oauthStatusClass = computed(() => {
  const status = props.oauthStatus
  return {
    'text-destructive': status?.isInvalid || status?.isExpired,
    'text-warning': status?.isExpiringSoon && !status?.isExpired && !status?.isInvalid,
    'text-muted-foreground': !status?.isExpired && !status?.isExpiringSoon && !status?.isInvalid,
  }
})

/**
 * 卡片主标题：优先用**上游昵称**（面板同款信息 ✓，由手动刷新额度写入 `workbuddy.account` ✓），
 * 但**掩码值不用** ✗ —— CN 号的昵称本身就是 `132****1637` 这种掩码手机号，
 * 拿来当标题反而更差 ✗（用户自己起的账号名更清楚 ✓）。
 */
const displayName = computed(() => {
  const nickname = props.apiKey.upstream_metadata?.workbuddy?.account?.nickname
  const trimmed = typeof nickname === 'string' ? nickname.trim() : ''
  if (trimmed && !trimmed.includes('*')) return trimmed
  return props.apiKey.name || ''
})

/** 标题的悬浮提示：用了昵称就把**账号名**也带上（信息不丢 ✓），否则提示可点击复制 ✓。 */
const displayNameTitle = computed(() => {
  if (!displayName.value) return ''
  const name = props.apiKey.name || ''
  if (name && name !== displayName.value) {
    return `${legacyT('上游昵称')}（${legacyT('账号名')}：${name}）`
  }
  return legacyT('点击复制')
})

/**
 * WorkBuddy 账号的**版本标识**（国内版 / 国际版）。
 *
 * 取值口径与「上游模型能力与倍率」面板一致：`upstream_metadata.workbuddy.realm` ——
 * 它由**上游目录抓取**写入（`aether-model-fetch` 的 strategy ✓），所以刚导入、
 * 还没拉过目录的账号这里会是空 ✗（面板会提示并自动补拉 ✓，拉完标识就出来 ✓）。
 * 其它 provider 没有这个键 → 不渲染徽章（不影响现有界面 ✓）。
 */
const workbuddyRealmBadge = computed(() => {
  const realm = props.apiKey.upstream_metadata?.workbuddy?.realm
  if (realm === 'cn') {
    return {
      label: legacyT('国内版'),
      class: 'border-emerald-500/40 text-emerald-600 dark:text-emerald-400',
      title: legacyT('WorkBuddy 国内版账号（对话域 copilot.tencent.com / 计费域 codebuddy.cn）'),
    }
  }
  if (realm === 'global') {
    return {
      label: legacyT('国际版'),
      class: 'border-sky-500/40 text-sky-600 dark:text-sky-400',
      title: legacyT('WorkBuddy 国际版账号（独立域名 workbuddy.ai；端点、出站头与账号体系都与国内版不同）'),
    }
  }
  return null
})
</script>
