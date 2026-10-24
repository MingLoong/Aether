<template>
  <Dialog
    :open="open"
    size="3xl"
    :close-on-backdrop="false"
    @update:open="(val: boolean) => emit('update:open', val)"
  >
    <template #header>
      <div class="border-b border-border px-6 py-4">
        <div class="space-y-3">
          <div class="text-lg font-semibold text-foreground leading-tight">
            {{ legacyT('验证出口 IP 健康') }}
          </div>
          <p class="text-xs text-muted-foreground">
            {{ legacyT('以下是这次探测真实发出的 HTTP 往返。遇到 403 时看响应体正文，就能分清是「免费层准入拒绝」还是「额度真的耗尽」。') }}
          </p>
        </div>
      </div>
    </template>

    <div
      v-if="result"
      class="space-y-4"
    >
      <!-- 错误与部分响应可能同时存在（例如拿到状态行之后连接中断），所以这里只补一条提示，不隐藏下面的区块 -->
      <div
        v-if="errorText"
        class="break-all rounded-md border border-destructive/30 bg-destructive/10 px-3 py-2 text-xs text-destructive"
      >
        {{ errorText }}
      </div>

      <div class="flex flex-wrap items-center justify-between gap-3 rounded-lg border border-border/60 bg-muted/20 p-4">
        <Badge
          :variant="statusBadge.variant"
          :class="statusBadge.badgeClass"
        >
          {{ statusBadge.label }}
        </Badge>
        <div class="flex flex-wrap items-center gap-x-3 gap-y-1 font-mono text-xs tabular-nums text-muted-foreground">
          <span class="break-all">{{ result.ip }}</span>
          <span class="break-all">{{ targetText }}</span>
          <span>{{ elapsedText }}</span>
        </div>
      </div>

      <!-- 请求 -->
      <div class="space-y-3 rounded-lg border border-border/60 bg-muted/20 p-4">
        <div class="text-sm font-medium text-foreground">
          {{ legacyT('请求') }}
        </div>

        <div class="break-all rounded-md border border-border/60 bg-background/80 px-3 py-2 font-mono text-xs text-foreground">
          {{ requestLine }}
        </div>

        <div class="space-y-1.5">
          <div class="flex items-center justify-between gap-2">
            <span class="text-xs font-medium text-muted-foreground">{{ legacyT('请求头') }}</span>
            <button
              type="button"
              class="flex shrink-0 items-center gap-1 rounded px-1.5 py-0.5 text-[11px] text-muted-foreground transition-colors hover:bg-muted"
              :title="copiedSection === 'request-headers' ? legacyT('已复制') : legacyT('复制')"
              @click="copySection('request-headers', requestHeadersText)"
            >
              <Check
                v-if="copiedSection === 'request-headers'"
                class="h-3.5 w-3.5 text-green-500"
              />
              <Copy
                v-else
                class="h-3.5 w-3.5"
              />
              {{ copiedSection === 'request-headers' ? legacyT('已复制') : legacyT('复制') }}
            </button>
          </div>
          <div
            v-if="requestHeaders.length > 0"
            class="overflow-hidden rounded-md border border-border/60 bg-background/80"
          >
            <table class="w-full table-fixed text-xs">
              <tbody>
                <tr
                  v-for="(header, index) in requestHeaders"
                  :key="`request-${index}-${header.name}`"
                  class="border-b align-top last:border-b-0"
                >
                  <td class="w-[32%] break-all px-3 py-1.5 font-mono text-muted-foreground">
                    {{ header.name }}
                  </td>
                  <td class="break-all px-3 py-1.5 font-mono">
                    {{ header.value }}
                  </td>
                </tr>
              </tbody>
            </table>
          </div>
          <div
            v-else
            class="text-xs text-muted-foreground"
          >
            {{ legacyT('无请求头数据') }}
          </div>
        </div>

        <div class="space-y-1.5">
          <div class="flex items-center justify-between gap-2">
            <span class="text-xs font-medium text-muted-foreground">{{ legacyT('请求体') }}</span>
            <button
              type="button"
              class="flex shrink-0 items-center gap-1 rounded px-1.5 py-0.5 text-[11px] text-muted-foreground transition-colors hover:bg-muted"
              :title="copiedSection === 'request-body' ? legacyT('已复制') : legacyT('复制')"
              @click="copySection('request-body', result.trace.request_body)"
            >
              <Check
                v-if="copiedSection === 'request-body'"
                class="h-3.5 w-3.5 text-green-500"
              />
              <Copy
                v-else
                class="h-3.5 w-3.5"
              />
              {{ copiedSection === 'request-body' ? legacyT('已复制') : legacyT('复制') }}
            </button>
          </div>
          <!-- 请求体带着 tools 数组，通常几 KB：默认收起，避免把请求头挤到屏幕外 -->
          <details
            v-if="hasRequestBody"
            class="text-xs"
          >
            <summary class="cursor-pointer select-none text-muted-foreground">
              {{ requestBodySummary }}
            </summary>
            <pre class="mt-2 max-h-64 overflow-auto whitespace-pre-wrap break-all rounded-md border border-border/60 bg-background/80 p-3 font-mono text-[11px] leading-relaxed">{{ result.trace.request_body }}</pre>
          </details>
          <div
            v-else
            class="text-xs text-muted-foreground"
          >
            {{ legacyT('无请求体数据') }}
          </div>
        </div>
      </div>

      <!-- 响应 -->
      <div class="space-y-3 rounded-lg border border-border/60 bg-muted/20 p-4">
        <div class="text-sm font-medium text-foreground">
          {{ legacyT('响应') }}
        </div>

        <div
          class="break-all rounded-md border border-border/60 bg-background/80 px-3 py-2 font-mono text-xs"
          :class="statusLineClass"
        >
          {{ statusLineText }}
        </div>

        <div class="space-y-1.5">
          <div class="flex items-center justify-between gap-2">
            <span class="text-xs font-medium text-muted-foreground">{{ legacyT('响应头') }}</span>
            <button
              type="button"
              class="flex shrink-0 items-center gap-1 rounded px-1.5 py-0.5 text-[11px] text-muted-foreground transition-colors hover:bg-muted"
              :title="copiedSection === 'response-headers' ? legacyT('已复制') : legacyT('复制')"
              @click="copySection('response-headers', responseHeadersText)"
            >
              <Check
                v-if="copiedSection === 'response-headers'"
                class="h-3.5 w-3.5 text-green-500"
              />
              <Copy
                v-else
                class="h-3.5 w-3.5"
              />
              {{ copiedSection === 'response-headers' ? legacyT('已复制') : legacyT('复制') }}
            </button>
          </div>
          <div
            v-if="responseHeaders.length > 0"
            class="overflow-hidden rounded-md border border-border/60 bg-background/80"
          >
            <table class="w-full table-fixed text-xs">
              <tbody>
                <tr
                  v-for="(header, index) in responseHeaders"
                  :key="`response-${index}-${header.name}`"
                  class="border-b align-top last:border-b-0"
                >
                  <td class="w-[32%] break-all px-3 py-1.5 font-mono text-muted-foreground">
                    {{ header.name }}
                  </td>
                  <td class="break-all px-3 py-1.5 font-mono">
                    {{ header.value }}
                  </td>
                </tr>
              </tbody>
            </table>
          </div>
          <div
            v-else
            class="text-xs text-muted-foreground"
          >
            {{ legacyT('无响应头数据') }}
          </div>
        </div>

        <div class="space-y-1.5">
          <div class="flex items-center justify-between gap-2">
            <span class="text-xs font-medium text-muted-foreground">{{ legacyT('响应体') }}</span>
            <button
              type="button"
              class="flex shrink-0 items-center gap-1 rounded px-1.5 py-0.5 text-[11px] text-muted-foreground transition-colors hover:bg-muted"
              :title="copiedSection === 'response-body' ? legacyT('已复制') : legacyT('复制')"
              @click="copySection('response-body', result.trace.response_body)"
            >
              <Check
                v-if="copiedSection === 'response-body'"
                class="h-3.5 w-3.5 text-green-500"
              />
              <Copy
                v-else
                class="h-3.5 w-3.5"
              />
              {{ copiedSection === 'response-body' ? legacyT('已复制') : legacyT('复制') }}
            </button>
          </div>
          <!-- 不做 JSON 解析再美化：要判断的正是上游原样的错误正文（可能是 FreeTierError 的裸文本），重排会丢掉原文证据 -->
          <pre
            v-if="hasResponseBody"
            class="max-h-64 overflow-auto whitespace-pre-wrap break-all rounded-md border border-border/60 bg-background/80 p-3 font-mono text-[11px] leading-relaxed"
          >{{ result.trace.response_body }}</pre>
          <div
            v-else
            class="text-xs text-muted-foreground"
          >
            {{ legacyT('无响应体数据') }}
          </div>
        </div>
      </div>
    </div>

    <div
      v-else
      class="py-4 text-center text-sm text-muted-foreground"
    >
      {{ legacyT('暂无探测数据') }}
    </div>

    <template #footer>
      <Button
        variant="outline"
        @click="emit('update:open', false)"
      >
        {{ legacyT('关闭') }}
      </Button>
    </template>
  </Dialog>
</template>

<script setup lang="ts">
import { computed, onBeforeUnmount, ref } from 'vue'
import { Check, Copy } from 'lucide-vue-next'
import { Badge, Dialog } from '@/components/ui'
import Button from '@/components/ui/button.vue'
import { useI18n } from '@/i18n'
import { useClipboard } from '@/composables/useClipboard'

export interface ProbeHeader {
  name: string
  value: string
}

export interface ProbeTrace {
  ip: string
  domain: string
  port: number
  method: string
  path: string
  request_headers: ProbeHeader[]
  request_body: string
  status: number | null
  status_line: string
  response_headers: ProbeHeader[]
  response_body: string
  elapsed_ms: number
  error: string | null
}

export interface VerifyResult {
  ip: string
  healthy: boolean
  quota_limited: boolean
  reason: string | null
  median_ms: number | null
  fails: number
  trace: ProbeTrace
}

const props = defineProps<{
  open: boolean
  result: VerifyResult | null
}>()

const emit = defineEmits<{
  'update:open': [value: boolean]
}>()

const { legacyT } = useI18n()
const { copyToClipboard } = useClipboard()

const requestHeaders = computed<ProbeHeader[]>(() => props.result?.trace.request_headers ?? [])
const responseHeaders = computed<ProbeHeader[]>(() => props.result?.trace.response_headers ?? [])
const hasRequestBody = computed(() => (props.result?.trace.request_body ?? '').length > 0)
const hasResponseBody = computed(() => (props.result?.trace.response_body ?? '').length > 0)
const errorText = computed(() => props.result?.trace.error?.trim() ?? '')

const targetText = computed(() => {
  const trace = props.result?.trace
  if (!trace) return '-'
  if (!trace.domain) return `:${trace.port}`
  return `${trace.domain}:${trace.port}`
})

const elapsedText = computed(() => {
  const elapsed = props.result?.trace.elapsed_ms
  return elapsed == null ? '-' : `${elapsed} ms`
})

const statusBadge = computed(() => {
  const result = props.result
  if (result?.healthy) {
    // Badge 的 success 变体跟着主题色走（这里主色是橙棕色），可用状态必须固定为绿色
    const median = result.median_ms == null ? '' : ` · ${result.median_ms} ms`
    return {
      variant: 'success' as const,
      label: `${legacyT('可用')}${median}`,
      badgeClass: 'border-transparent bg-emerald-500 text-white hover:bg-emerald-600',
    }
  }
  if (result?.quota_limited) {
    return {
      variant: 'warning' as const,
      label: legacyT('额度受限'),
      badgeClass: 'border-transparent bg-amber-500 text-white hover:bg-amber-600',
    }
  }
  return {
    variant: 'destructive' as const,
    label: legacyT('不可用'),
    badgeClass: 'border-transparent bg-destructive text-destructive-foreground',
  }
})

const requestLine = computed(() => {
  const trace = props.result?.trace
  return trace ? `${trace.method} ${trace.path} HTTP/1.1` : ''
})

const statusLineText = computed(() => {
  const trace = props.result?.trace
  if (!trace) return '-'
  if (trace.status_line) return trace.status_line
  return trace.status == null ? legacyT('无状态行（未收到响应）') : `HTTP/1.1 ${trace.status}`
})

const statusLineClass = computed(() => {
  const status = props.result?.trace.status
  if (status == null) return 'text-muted-foreground'
  return status >= 400 ? 'text-destructive' : 'text-foreground'
})

const requestBodySummary = computed(() => {
  const length = props.result?.trace.request_body?.length ?? 0
  return legacyT(`展开请求体（${length} 字符，默认收起）`)
})

function formatHeaderLines(headers: ProbeHeader[]): string {
  return headers.map(header => `${header.name}: ${header.value}`).join('\n')
}

const requestHeadersText = computed(() => {
  const lines = formatHeaderLines(requestHeaders.value)
  return lines ? `${requestLine.value}\n${lines}` : requestLine.value
})

const responseHeadersText = computed(() => {
  const lines = formatHeaderLines(responseHeaders.value)
  return lines ? `${statusLineText.value}\n${lines}` : statusLineText.value
})

const copiedSection = ref<string | null>(null)
let copyTimer: ReturnType<typeof setTimeout> | null = null

function copySection(section: string, text: string) {
  if (!text) return
  // 静默复制：区块内已经有「已复制」反馈，不再叠一条全局 toast
  void copyToClipboard(text, false)
  copiedSection.value = section
  if (copyTimer) clearTimeout(copyTimer)
  copyTimer = setTimeout(() => {
    copiedSection.value = null
  }, 2000)
}

onBeforeUnmount(() => {
  if (copyTimer) clearTimeout(copyTimer)
})
</script>
