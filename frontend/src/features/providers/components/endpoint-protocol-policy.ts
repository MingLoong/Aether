import { normalizeEndpointApiFormat } from './endpoint-default-paths'

export type FixedUpstreamStreamPolicy = 'force_stream' | 'force_non_stream'

export function isWebSocketEndpointApiFormat(apiFormat: string): boolean {
  const normalizedApiFormat = normalizeEndpointApiFormat(apiFormat)
  return normalizedApiFormat === 'openai:realtime' || normalizedApiFormat === 'codex:live'
}

export function fixedEndpointUpstreamStreamPolicy(
  providerType: string | null | undefined,
  apiFormat: string,
): FixedUpstreamStreamPolicy | null {
  const normalizedApiFormat = normalizeEndpointApiFormat(apiFormat)
  if (normalizedApiFormat === 'openai:search') return 'force_non_stream'
  // OpenCode 免费层**必须**流式：后端在 `apply_opencode_request_body_semantics` 里
  // 无条件写 `stream: true`，并在 `force_upstream_streaming_for_provider` 里把
  // opencode + openai:chat 标记为强制上游流式（非流式客户端由网关聚合还原）。
  // 所以面板上的三态开关对它没有意义——这里标成固定值，UI 直接不显示该按钮。
  if (
    providerType?.trim().toLowerCase() === 'opencode' &&
    normalizedApiFormat === 'openai:chat'
  ) {
    return 'force_stream'
  }
  if (providerType?.trim().toLowerCase() !== 'codex') return null

  switch (normalizedApiFormat) {
    case 'openai:responses':
      return 'force_stream'
    default:
      return null
  }
}
