# 透传请求头记录改造 · 修改规划

目标：让 `provider_request_headers` 记录 **Go 侧改完请求头后回给 AE 的那一份**，而不是 AE 自己拼的。
`request_headers` 保持不动，永远是客户端发到 AE 的原始头。

配套设计：`docs/relay-upstream-echo-design.md`

---

## 阶段 0 · 契约冻结

| 项 | 内容 |
|---|---|
| 请求头 | `X-Aether-Echo: 1`、`X-Aether-Trace-Id: <request_id>` |
| 响应头 | `X-Aether-Provider-Request-Headers: <base64url(zlib(json))>`，压缩后 ≤ 8KB |
| JSON | `{v, service, version, method, path, headers, header_count, truncated}` |
| 脱敏 | `authorization` / `cookie` / `x-api-key` / `proxy-authorization` 只留前 6 后 4 |
| 两处必须剥离 | Go 侧不把 `X-Aether-Echo` 转发给真实上游；AE 不把 `X-Aether-Provider-Request-Headers` 透给客户端 |

产出：`docs/relay-upstream-echo-design.md`（已定稿）

---

## 阶段 1 · Go 侧回执（workbuddy2api）

仓库：`F:\code\AE-WorkBuddy2API\wbpanel`

| 文件 | 改动 |
|---|---|
| `internal/server/echo.go`（新增） | `EchoWriter`：包一层 `http.ResponseWriter`，把 `WriteHeader` 延后到首次 `Write`；由它统一注入回执头 |
| `internal/server/echo_payload.go`（新增） | 组装 JSON、脱敏、zlib 压缩、base64url、8KB 裁剪 |
| `internal/server/handler.go` | 在代理入口判断 `X-Aether-Echo`，命中则用 `EchoWriter` 包裹；记录**最终**发往上游的 header map（在加完整合后、`client.Do` 前） |
| `internal/server/echo_test.go`（新增） | 三条用例：正常回执、超限裁剪、不带 echo 头时零行为变化 |

关键点：

- 必须在 `WriteHeader` 之前 set 头 → 用延迟写入的 writer，流式响应才不会丢；
- 采集点是**加完所有中间件后**的 `req.Header`，不是入站原始 `r.Header`；
- 只对命中 `X-Aether-Echo` 的请求生效，其他请求零开销。

验收：

```bash
curl -sD - -o /dev/null -H 'X-Aether-Echo: 1' -H "<业务鉴权>" \
  http://127.0.0.1:7863/v1/chat/completions -d '{...}' | grep X-Aether
# 解 base64 → zlib → 能看到 host/authorization(脱敏)/content-type
```

---

## 阶段 2 · AE 侧解析与覆盖

仓库：`F:\code\Aether`（relay-only / main）

| 文件 | 改动 |
|---|---|
| `crates/aether-data/adapters/postgres/migrations/20261110000000_add_provider_headers_source.sql`（新增） | `ALTER TABLE usage_http_audits ADD COLUMN provider_headers_source varchar(16) NOT NULL DEFAULT 'local'` |
| `apps/aether-gateway/src/execution_runtime/relay_echo.rs`（新增） | 解析 `X-Aether-Provider-Request-Headers`：base64url → zlib 解压 → JSON → 校验 `v` / `trace-id` / 大小；返回 `Option<BTreeMap<String,String>>` |
| `apps/aether-gateway/src/execution_runtime/response_header_rules.rs` | 参照既有的 `attach_provider_response_headers_to_report_context`，新增 `attach_relay_echo_to_report_context`，把回执里的头写进 `report_context["provider_request_headers"]` 并打 `provider_headers_source` |
| `apps/aether-gateway/src/execution_runtime/stream/execution.rs` | 4 个 `attach_provider_response_headers_to_report_context` 调用点（约 3042 / 4497 / 4642 / 6067 行）后追加回执处理 |
| `apps/aether-gateway/src/handlers/proxy/finalize.rs` | 回给客户端前剥掉 `X-Aether-Provider-Request-Headers`，避免泄漏给调用方 |
| `crates/aether-data/adapters/postgres/src/usage/mod.rs` | 落库时带上 `provider_headers_source`（写入点约 8881 / 9078 行） |
| `apps/aether-gateway/src/handlers/admin/observability/usage/detail_routes.rs` | 详情响应加 `provider_headers_source` 字段 |

配置（`providers.config`）：

```json
{ "relay_echo": { "enabled": true, "trust": true, "max_bytes": 8192 } }
```

- `enabled`：是否注入 `X-Aether-Echo`；
- `trust`：是否接受回执（防上游伪造），默认 false；
- 默认只对 `provider_type = relay` 生效。

验收：

1. relay 供应商转发 → `usage_http_audits.provider_request_headers` 等于 Go 侧回执里的 headers，`provider_headers_source='upstream_echo'`；
2. 关掉 Go 侧回执 → `provider_headers_source='local'`，头仍是 AE 本地那份；
3. 客户端收到的响应里搜不到 `X-Aether-Provider-Request-Headers`。

---

## 阶段 3 · 前端展示

| 文件 | 改动 |
|---|---|
| `frontend/src/api/dashboard.ts` | DTO 加 `provider_headers_source` |
| `frontend/src/features/usage/components/RequestDetailDrawer.vue` | 请求头 tab 标题右侧加来源徽标：`上游回执` / `本地记录`；有回执时默认选中「提供商」档 |
| `frontend/src/i18n/ui-messages.ts` | 新增 `ui.headersSourceUpstream` / `ui.headersSourceLocal` |

验收：详情页一眼能看出这份头是上游给的还是 AE 估的。

---

## 阶段 4 · 联调与灰度

1. 154 上装新 wbpanel + 新 AE，先只给 `workbuddy2api` 供应商开 `relay_echo`；
2. 发 10 条真实请求，逐条比对「AE 详情页的头」与「Go 侧日志里的头」，要求 100% 一致；
3. 观察 24h：无 5xx 增量、无响应头体积异常；
4. 稳定后推广到其余 relay 供应商。

回滚：`providers.config.relay_echo.enabled=false` 即刻回到现状，无需回滚二进制。

---

## 阶段 5 · zcode2api（阻塞）

154 上 `AMD` 这个 relay 指向 `http://203.0.113.10:47823/v1`（zcode2api），但服务器上只有二进制，本地也没有源码。

**需要你给源码路径**，否则这个供应商的记录仍会是 AE 本地估算值。

---

## 工作量与顺序

| 阶段 | 内容 | 预估 |
|---|---|---|
| 1 | Go 侧回执（wbpanel） | 1 天 |
| 2 | AE 解析 + 落库 + 剥离 | 1.5 天 |
| 3 | 前端徽标 | 0.5 天 |
| 4 | 联调灰度 | 0.5 天 |
| 5 | zcode2api | 待源码 |

阶段 1 和 2 可以并行，但**阶段 2 依赖阶段 1 产出的头格式**，所以先冻结契约再动手。

---

## 明确不改的部分

- `request_headers`、`response_headers`、`client_response_headers` 的采集逻辑；
- body 抓取（`usage_body_blobs`）与清理策略；
- 透传的转发行为本身——回执只是旁路信息，不参与转发决策；
- 现有四份头的表结构，只加一列来源标记。
