# AE 自定义透传（relay）供应商接入手册

> 面向对象：需要把一个独立 Go/HTTP 服务接入 Aether 网关作为「自定义透传」供应商的 AI / 工程师。
> 适用版本：`oc-vertical-rm-20261030-2215`（含 relay 透传支持）。
> 生产示例：`opencode2api`（Go 服务）已作为 relay 接在 154 上，本手册以它为例。

---

## 1. 核心概念：relay 供应商是什么

在 Aether 网关面板的「添加提供商」里选 **「自定义透传」（存储值 `relay`）**，表示：

> 网关把客户端的请求**原样透传**给你自己的上游 HTTP 服务（Go 服务），不做任何格式转换、
> 不做候选切换、不做重试。Go 服务返回什么（包括 4xx/5xx），网关就原样回给客户端。

它专门用于「前面一个 Go 服务 / 代理 / 网关，AE 只做透传入口」的架构：
客户端 → **AE 网关**（relay 供应商）→ **你的 Go 服务** → 真正的模型上游。

### relay 与普通供应商的区别

| 能力 | relay | 普通（如 custom/claude_code） |
|---|---|---|
| 请求格式转换 | **不做**，原样透传 | 按 api_format 转换 |
| 错误候选切换 | **任何 4xx/5xx 都不换**，原样回传 | 4xx/5xx 触发换候选/重试 |
| 重试 | **类型级强制零重试**（一次请求只打一次上游） | 按 max_retries |
| 出口 IP 池 / 健康度熔断 | **绕开**（无号池、无健康门、无熔断） | 启用 |
| 键级 RPM/并发门 | **保留**（不绕过） | 启用 |
| 排序权重 | 保留 | 启用 |

一句话：**relay = 纯透传 + 只做 token 统计，其余控制逻辑全部关掉。**

---

## 2. 架构与数据流

```
客户端 (OpenAI 兼容)
   │  POST /v1/chat/completions  (Authorization: Bearer sk-aether-xxx)
   ▼
AE 网关 (relay 供应商, api_format=openai:chat)
   │  原样转发请求体 + 重写 Authorization 为你的上游 key
   ▼
你的 Go 服务  base_url = http://<你的服务>:<port>/v1
   │  处理请求，可能再转发到真正的模型上游
   ▼
模型上游
```

AE 从上游（你的 Go 服务）的响应里读取 `usage`（prompt_tokens / completion_tokens）
记入自己的 `usage` 表，用于 token 统计；其余响应字节原样透传给客户端。

---

## 3. 你的 Go 服务需要实现什么（协议约定）

因为 relay 是原样透传，**你的 Go 服务必须实现 OpenAI 兼容的 `/v1` 接口**，且与 AE 的
`api_format=openai:chat` 对齐。

### 3.1 必须实现的接口

| 方法 | 路径 | 说明 |
|---|---|---|
| `POST` | `/v1/chat/completions` | 对话补全（核心）。请求体为 OpenAI `chat.completion` 格式；**必须支持流式**（`stream:true` 返回 SSE） |
| `GET` | `/v1/models` | 模型列表（可选但建议）。AE 面板展示模型用 |
| `GET` | `/health` | 健康检查（可选）。便于运维 |

> **必须支持流式**。AE 透传时若客户端请求 `stream:true`，你的服务要返回
> `Content-Type: text/event-stream` + SSE `data: {...}`，并以 `data: [DONE]` 结尾。
> 若不支持流式，需在 Go 服务端把非流式响应聚合回 SSE，否则流式客户端会失败。

### 3.2 鉴权

- 客户端 → AE 网关：`Authorization: Bearer sk-aether-xxx`（AE 自己的 key）
- AE 网关 → 你的 Go 服务：**AE 会重写 Authorization**，用你在 AE 面板里为这个 relay
  供应商配置的「上游 API Key」（`Bearer sk-your-upstream-key`）
- 你的 Go 服务：校验这个上游 key，校验失败返回 `401`（AE 会原样透传给客户端）

### 3.3 请求体 / 响应体

- **请求体**：OpenAI `chat/completion` 格式。`model` 字段是你在 AE 面板为这个供应商
  登记的模型名。**透传时 AE 不改请求体字段**（除鉴权头）。
- **响应体**：OpenAI `chat.completion` 或 `chat.completion.chunk`（流式）。**必须含
  `usage` 字段**（`prompt_tokens`, `completion_tokens`, `total_tokens`），否则 AE
  的 token 统计拿不到数。

### 3.4 错误返回约定

因为 relay 关闭了重试和候选切换，**你的服务返回什么状态码，客户端就收到什么**：

| 场景 | 你该返回 |
|---|---|
| 上游 key 无效 | `401`（JSON: `{"error":{"type":"AuthError","message":"..."}}`） |
| 请求参数错 | `400` |
| 额度不足 / 限流 | `429`，**带 `Retry-After` 头**（秒），AE 原样回传 |
| 上游 5xx | `5xx`（AE 原样回传，不重试） |

> **务必带准确的 `Retry-After`**。relay 不消费它，但客户端（如 OpenAI SDK）会用它
> 决定何时重试。

---

## 4. 在 AE 面板接入（接线步骤）

### 4.1 建供应商

「添加提供商」→ 选 **「自定义透传」（relay）**，命名，保存。
面板「添加提供商」下拉里有「自定义透传」这一项（已在前端 + 后端启用）。

### 4.2 加端点（核心）

给这个 relay 供应商加一个端点，配置：

| 字段 | 值（示例，对齐 opencode2api） |
|---|---|
| `api_format` | `openai:chat` |
| `base_url` | `http://<你的Go服务>:<port>/v1` |
| `custom_path` | 留空 |
| `enabled` | true |

> 生产实据（154 上 `opencode2api`）：
> ```
> provider_type = relay
> api_format    = openai:chat
> base_url      = http://127.0.0.1:8000/v1
> ```

### 4.3 登记模型

在 `models` 表为这个供应商登记它支持的模型（`provider_model_name`）。
AE 会把请求体里的 `model` 与这些登记名比对、做路由。

### 4.4 配置上游 API Key

在供应商/端点的鉴权配置里填你的 Go 服务要的 key（`sk-your-upstream-key`）。
AE 会用这个 key 替换客户端发来的 `Authorization` 再去打你的服务。

---

## 5. 生产实据（154 上的 opencode2api）

以下是已被验证可用的接线（可作对照模板）：

```sql
-- providers
SELECT id, name, provider_type, enabled, config
FROM providers
WHERE provider_type='relay';
--  410847c2-... | opencode2api | relay | t | {"max_transfer_timeout_seconds": 600}

-- provider_endpoints
SELECT api_format, base_url, custom_path, api_family, endpoint_kind
FROM provider_endpoints
WHERE provider_id='410847c2-...';
--  openai:chat | http://127.0.0.1:8000/v1 | (null) | (null) | (null)
```

对应的 Go 服务（opencode2api）暴露：
```
POST /v1/chat/completions   （OpenAI 格式，支持流式 SSE）
GET  /v1/models
GET  /health
```

---

## 6. 连通性测试（无需自己开发，已内置）

面板「供应商 → 模型」页每个模型自带**测试按钮**（`ModelsTab.testModelConnection`），
对 relay 供应商同样可用——2026-10-31 已在生产实测通过：

```
POST /api/admin/provider-query/test-model
Authorization: Bearer <管理令牌，需 admin:provider_query:admin 权限>
{"provider_id":"<relay供应商id>","model_name":"big-pickle","api_format":"openai:chat"}

→ 200 {"success":true, "data":{"response":{...chat.completion..., "usage":{...}}},
       "provider":{"provider_type":"relay"}, "attempts":[{"retry_index":0,...}]}
```

原理：relay 继承 `standard()` 的 `supports_local_openai_chat_transport=true`
（`RELAY_RUNTIME_POLICY` 用 `..STANDARD_RUNTIME_POLICY` 展开），test-model 的
adapter 把 relay + `openai:chat` 归入 `ProviderQueryTestAdapter::Standard` 分支，
按标准 OpenAI 格式真实打一次你的 Go 服务。**零重试语义同样生效**（attempts 只有
`retry_index:0` 一次）。

管理令牌（`ae-` 前缀 Bearer）所需权限键：`admin:provider_query:admin`（POST 动作
按 `:write`/`:admin` 判定，test-model 属 admin 级）。权限不足返回 403 并带
`required_permission` 字段，可据此补权限。

### 6.1 端点 header_rules / body_rules 对 relay 生效

relay 走 openai:chat 本地透传路径，端点级 rules **已生效**（非占位）：

- `body_rules`：进入 `build_local_openai_chat_request_body`（request.rs:503-508），
  可改写/注入请求体字段
- `header_rules`：进入 `build_standard_provider_request_headers`（request.rs:585），
  可加自定义头（租户标识、签名等）
- 本地路径不支持的 rules 形态会在 transport 检查时报
  `transport_header_rules_unsupported` / `transport_body_rules_unsupported`

给自定义供应商加自定义头，**优先配端点 header_rules，不用改 AE 代码**。

---

## 7. providers.config 已支持的 knob（契约清单）

`providers.config` 是自由 JSON，**给自定义供应商加功能优先加 knob，不要加新的
provider_type**。已知 knob：

| knob | 位置 | 类型 | 默认 | 说明 |
|---|---|---|---|---|
| `max_transfer_timeout_seconds` | providers.config | number | 网关默认超时 | relay 透传的最长传输时间；长流式响应调大（生产 opencode2api 用 600） |

约定：

1. **未登记的 knob 会被静默忽略**——不会报错，所以拼写错误不会被发现，改完要实测。
2. 新 knob 的规范流程：在 `crates/aether-provider/transport` 的 policy 层读取 +
   单测锁定 + 本表登记，三处同步。
3. 类型级行为（重试/切换/排除）走 `ProviderRuntimePolicy`（代码），**不**走 config；
   config 只放「数值型运维参数」（超时、上限之类）。

---

## 8. 排障速查

| 症状 | 原因 / 检查 |
|---|---|
| 面板「添加提供商」看不到「自定义透传」 | 前端没更新。后端 `provider_type` 支持列表在 `normalize.rs` 的 `SUPPORTED_PROVIDER_TYPES`，前端下拉在 `ProviderFormDialog.vue`。都需含 `relay`。 |
| 创建 relay 被拒 | `provider_type` 传错（应为 `relay`）。后端拒绝会返回 400 + 支持列表。 |
| 401 透传 | 你 Go 服务的上游 key 和 AE 里配的对不上。 |
| 429 但客户端拿不到 `Retry-After` | 你 Go 服务没返回该头。relay 原样透传，没头就没头。 |
| 流式客户端失败 | 你 Go 服务没支持流式，或 SSE 格式不对（要 `[DONE]` 结尾）。 |
| token 统计为 0 | 你 Go 服务响应没带 `usage` 字段。 |
| 502（网关侧） | 网关重启瞬间的瞬时雪崩（隧道节点重连），非持续故障。等网关 ready（health 200）即可。 |

---

## 9. 代码位置（如需改透传行为）

| 逻辑 | 文件 |
|---|---|
| relay 运行时策略（零重试、停失败切换、绕健康门等） | `crates/aether-provider/transport/src/provider_types.rs`（`RELAY_RUNTIME_POLICY`） |
| 任何 4xx/5xx → `StopLocalFailover` | `apps/aether-gateway/src/orchestration/recovery.rs` |
| 类型级强制零重试 + `stop_failover_on_error` | `apps/aether-gateway/src/orchestration/policy.rs` |
| 透传类型候选 `sticky_key_attempts=1` | `apps/aether-gateway/src/ai_serving/planner/candidate_resolution.rs` |
| 绕开号池额度信号（reserve/credit-floor） | `apps/aether-gateway/src/dispatch/pool_scheduler.rs` |
| 忽略键健康度/熔断排除（保留 RPM/并发门） | `crates/aether-scheduler-core/src/candidate/selectability.rs` |
| 供应商类型白名单 | `apps/aether-gateway/src/handlers/admin/provider/write/normalize.rs`（`SUPPORTED_PROVIDER_TYPES`） |

> 注意：改这些逻辑需要重新构建后端 + 部署，且要过 CI（`gateway-build` + `Rust CI`）。
> relay 的能力位都是「意图声明」，多数对普通类型是无操作（no-op），只对 relay 生效。