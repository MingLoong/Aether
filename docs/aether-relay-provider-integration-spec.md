# AE 自定义透传（relay）供应商 + 内嵌控制台面板 —— 接入规约

> **给实现方的自包含规约。** 只读这一份，即可从零实现一个「OpenAI 兼容的 relay 上游服务 +
> 内嵌到 AE 网关的管理面板」，并让它与 AE 完成免密 SSO 对接。无需再参考其它文档。
>
> 规约分四部分：**A. relay 服务端接口契约**（供 `/v1` API 透传，含 A.5 上游请求头回执
> relay echo v1）；**B. 管理面板与 AE 的内嵌/SSO 契约**（供供应商管理弹窗直通）；
> **C. 在 AE 中注册与配置**（接线步骤与 `providers.config` 配置项）；
> **D. 联调与验收**（四级验证阶梯、抓包判据、故障定位表、证据留档、部署与回滚约束）。

**目录**

- [A. relay 服务端接口契约](#a-relay-服务端接口契约)
  - [A.1 必须实现的接口](#a1-必须实现的接口) · [A.2 鉴权](#a2-鉴权) · [A.3 请求体 / 响应体](#a3-请求体--响应体) · [A.4 错误返回约定](#a4-错误返回约定) · [**A.5 上游请求头回执（relay echo v1）**](#a5-上游请求头回执relay-echo-v1) · [A.6 上游请求体回执（relay echo body v2）](#a6-上游请求体回执relay-echo-body-v2)
- [B. 管理面板与 AE 的内嵌 / SSO 契约](#b-管理面板与-ae-的内嵌--sso-契约)
- [C. 在 AE 中注册与配置](#c-在-ae-中注册与配置接线步骤)
- [**D. 联调与验收**](#d-联调与验收改完必跑)
- [快速自检清单](#快速自检清单改完必须逐条核对)

---

## A. relay 服务端接口契约

AE 对 `provider_type = relay` 的供应商是**原样透传**：不改请求体（除鉴权头）、不重试、不切换
候选。因此你的服务必须实现 OpenAI 兼容的 `/v1` 接口，并与 AE 配置的 `api_format=openai:chat`
对齐。

### A.1 必须实现的接口

| 方法 | 路径 | 说明 |
|---|---|---|
| `POST` | `/v1/chat/completions` | 对话补全（核心）。请求体为 OpenAI `chat.completion` 格式；**必须支持流式**（`stream:true` 返回 SSE） |
| `GET` | `/v1/models` | 模型列表（可选但建议）。AE 面板展示模型用 |
| `GET` | `/health` | 健康检查（可选）。便于运维 |

**必须支持流式。** AE 透传时若客户端请求 `stream:true`，服务要返回
`Content-Type: text/event-stream` + SSE `data: {...}`，并以 `data: [DONE]` 结尾。
若不支持流式，需在服务端把非流式响应聚合回 SSE，否则流式客户端会失败。

### A.2 鉴权

- 客户端 → AE 网关：`Authorization: Bearer sk-aether-xxx`（AE 自己的 key）
- AE 网关 → 你的服务：**AE 重写 Authorization**，用你在 AE 面板为这个 relay 供应商配置的
  「上游 API Key」（`Bearer sk-your-upstream-key`）
- 你的服务：校验这个上游 key，校验失败返回 `401`（AE 原样透传给客户端）

### A.3 请求体 / 响应体

- **请求体**：OpenAI `chat/completion` 格式。`model` 是你在 AE 面板为这个供应商登记的模型名。
  **透传时 AE 不改请求体字段**（除鉴权头）。
- **响应体**：OpenAI `chat.completion` 或 `chat.completion.chunk`（流式）。**必须含
  `usage`**（`prompt_tokens`, `completion_tokens`, `total_tokens`），否则 AE 的 token
  统计拿不到数。

### A.4 错误返回约定

relay 关闭了重试和候选切换，**你返回什么状态码，客户端就收到什么**：

| 场景 | 该返回 |
|---|---|
| 上游 key 无效 | `401`（JSON: `{"error":{"type":"AuthError","message":"..."}}`） |
| 请求参数错 | `400` |
| 额度不足 / 限流 | `429`，**带 `Retry-After` 头**（秒），AE 原样回传 |
| 上游 5xx | `5xx`（AE 原样回传，不重试） |

> **务必带准确的 `Retry-After`**。relay 不消费它，但客户端（如 OpenAI SDK）会用它决定何时重试。

### A.5 上游请求头回执（relay echo v1）

**为什么需要。** AE 只知道自己发出去的请求头；relay 往往会在中间重写一大批头（换 UA、加
CodeBuddy/WorkBuddy 会话头、gzip、注入上游 token）。不把这些头带回来，AE 侧看到的“上游请求”
就是假的。echo 协议让 relay 把**真正发给上游的那一份头**回传，AE 落库留证。

**只在 `provider_type = relay` 时启用**，其它 provider 完全不受影响。

#### 控制头（AE → relay）

| 头 | 值 | 说明 |
|---|---|---|
| `X-Aether-Echo` | `1` | 请求回执。缺省或非 `1` = 不要求，relay 行为与以前完全一致 |
| `X-Aether-Trace-Id` | AE 的 `request_id`（UUID） | relay 必须原样回填到 payload 的 `trace_id` |

#### 回执头（relay → AE）

```
X-Aether-Provider-Request-Headers: <base64url( zlib( json ) )>
```

编码链路：**JSON → zlib（deflate）→ base64url（无 `=` 填充）**。

#### payload schema（`v = 1`）

| 字段 | 类型 | 必填 | 说明 |
|---|---|---|---|
| `v` | int | 是 | 协议版本，当前固定 `1`。AE 只接受 `1`，其它值走本地兜底 |
| `service` | string | 否 | 服务名，如 `workbuddy2api`，仅供排障 |
| `version` | string | 否 | relay 版本号，仅供排障 |
| `method` | string | 否 | 实际发往上游的方法，通常 `POST` |
| `path` | string | 否 | 实际发往上游的路径，如 `/v1/chat/completions` |
| `trace_id` | string | 是 | 必须等于请求里的 `X-Aether-Trace-Id`，否则 AE 拒收 |
| `headers` | object | 是 | 最终上游请求头，键统一小写；不得为空 |
| `header_count` | int | 否 | 采集时的头数量（裁剪前） |
| `truncated` | bool | 否 | 是否因体积超限发生裁剪 |

#### 硬限制

| 限制 | 值 | 超限行为 |
|---|---|---|
| 编码后（base64url 串）长度 | ≤ **8192** 字节 | relay 自行裁剪；裁到放不下则**不返回回执头** |
| AE 接受的最大编码长度 | 16384 字节 | 超过直接丢弃，按本地兜底 |
| AE 解压后上限 | 64 KB | 超过丢弃 |
| 单个头值长度 | 1024 runes | 截断并追加 `…` |

#### 脱敏与裁剪

- **必须脱敏**的头（大小写不敏感）：`authorization`、`proxy-authorization`、`cookie`、
  `set-cookie`、`x-api-key`、`api-key`、`x-goog-api-key`。
  掩码规则：保留认证前缀（如 `Bearer `）+ 前 6 字符 + `****` + 后 4 字符；主体 ≤10 字符时只留
  `前缀 + ****`。
- 裁剪顺序：先丢低价值头（`x-stainless-*`、`sec-*`、`accept-language`、`priority`、`dnt`、
  `cache-control`、`pragma`、`te`、`upgrade-insecure-requests`、`x-forwarded-*`、`x-real-ip`、
  `eo-*`），仍超限再按字典序从尾部整条丢弃，并置 `truncated=true`。

#### relay 侧必须做的四件事

1. 识别 `X-Aether-Echo: 1`。
2. 在**所有改写完成之后、`http.Client.Do` 之前**采集最终头表（不是客户端原始头）。
3. **把 `X-Aether-Echo` 与 `X-Aether-Trace-Id` 从上游请求里删掉**——它们是 AE↔relay 的内部
   控制头，泄漏给真实上游属于协议违规。
4. 在写响应体之前把回执头塞进响应头（HTTP 头一旦写出就不能再改）。

#### AE 侧校验与兜底

按顺序校验：`v == 1` → `trace_id` 与本次请求一致 → `headers` 非空 → 头表里**不得**再出现
`x-aether-echo` / `x-aether-trace-id` / `x-aether-provider-request-headers`。任一不满足即判定
回执无效。

| 结果 | `provider_headers_source` | `provider_request_headers` |
|---|---|---|
| 回执有效 | `upstream_echo` | relay 回传的真实上游头（已脱敏） |
| 无回执 / 解码失败 / 校验失败 | `local` | AE 自己算出来的那份头 |

**两者永不混用**：要么整份来自 relay，要么整份来自 AE。回执头在返回客户端前会被剥掉，
客户端永远看不到它。

#### 落库字段语义（`usage_http_audits`）

| 字段 | 含义 |
|---|---|
| `request_headers` | 客户端 → AE 的原始请求头 |
| `provider_request_headers` | AE 最终发往上游的头（echo 成功时替换为 relay 回传的那份） |
| `provider_headers_source` | `upstream_echo` = 来自 relay 回执；`local` = AE 本地计算（兜底） |

> `provider_headers_source = local` 不代表请求失败，只代表**这次没拿到回执**。排障时先看它，
> 再决定是查 relay 实现还是查 AE 过滤链。

### A.6 上游请求体回执（relay echo body v2）

**与请求头同一条通道、同一份 payload，只是多带 body。** AE 侧最终效果是
`provider_request_body_ref` 被 relay 真货覆盖——不是新增一份，而是替换。

#### 控制头（AE → relay，仅当 `request_record_level=full`）

| 头 | 值 | 说明 |
|---|---|---|
| `X-Aether-Echo-Body` | `1` | 请求体回执 |
| `X-Aether-Echo-Body-Max` | 字节数 | 等于 `request_record_max_body_size_kb × 1024`；`0` = **不限制** |
| `X-Aether-Echo-Body-Compact-Images` | `0`/`1` | 与 `request_record_compact_base64_images` 同值 |

#### payload 新增字段（`v = 2`）

| 字段 | 说明 |
|---|---|
| `body_mode` | `inline` / `staged` / `none` |
| `body_sha256` / `body_bytes` | 按**实际写到网络的字节**（gzip 后）计算 |
| `body_stored_bytes` | 按 `Body-Max` 截断后的长度 |
| `body_content_type` / `body_encoding` | 通常 `application/json` / `identity` 或 `gzip` |
| `body_truncated` | 是否被 `Body-Max` 截断 |
| `body_rewritten` / `body_diff` | relay 比对**进站 vs 出站**后的结论与字段差异 |
| `body_inline_b64` | 仅 `inline`：原文（≤4 KB JSON） |
| `body_stage_id` / `body_stage_exp` / `body_stage_sig` | 仅 `staged`：取回凭据 |

> **透传前提**：AE → relay 不改 body，所以 relay 的进站 body 就是 AE 出站 body。差异比较在
> relay 侧完成，AE 不需要回传自己的副本。

#### 大 body 暂存与取回

- 仅内存/临时文件（0600），TTL **10 分钟**，容量 512 MiB，超出按最旧淘汰
- 取走后保留 10 秒重试窗，之后删除；进程重启即丢

```
GET /_aether/echo/body/{stage_id}?exp=<unix>&sig=<hex>&trace=<trace_id>
```

- `sig = HMAC-SHA256(echo_secret, stage_id + "|" + exp + "|" + trace_id)`
- `200`，响应体编码必须与 payload 的 `body_encoding` 一致：`gzip` 就压、`identity` 就明文。
  AE 按 `body_encoding` 决定是否解压，两边必须成对，只改一边会导致 body 被丢弃
- `403` 签名不符；`404` 不存在；`410` 已过期

#### AE 侧处理

1. 响应头到达时解析 v2；`staged` 立刻后台拉取（3 s 超时），不阻塞客户端
2. 解析 JSON 后写入 report context 的 `provider_request_body`
3. 落库时**原地覆盖** `provider_request_body_ref`（不新增列：曾试加 `provider_body_source`，已由 `20261104000001` 回滚）
4. 任何一步失败 → 保留 AE 自己那份，标 `local`，业务请求不受影响

---

## B. 管理面板与 AE 的内嵌 / SSO 契约

配好 `provider_ops.console_shared_secret` 后，AE 把供应商的管理面板以 iframe 弹窗打开（免登录）。
AE 侧路由与面板侧行为必须**逐字节一致**，否则弹窗会跳回登录页。

### B.1 AE 侧接口（实现方了解即可，由 AE 网关提供）

| 路由 | 说明 |
|---|---|
| `POST /api/admin/provider-ops/providers/{id}/console-url` | 签发一次性免密 URL（90 秒、no-store）。校验 relay + 已配 secret，返回 `{"url": "/console/{id}/console-sso?pid=..&exp=..&n=..&sig=..", "expires_at": ..}` |
| `GET /api/admin/provider-ops/providers/{id}/console-settings` | 读面板地址与密钥状态：`console_base_url`、`console_base_url_effective`、`console_base_url_source`（`explicit`/`endpoint`/`missing`）、`console_shared_secret_configured`、`console_shared_secret_preview`（首尾各 4 字符掩码）。**密钥明文永不回传** |
| `PUT /api/admin/provider-ops/providers/{id}/console-settings` | 保存面板地址 / 共享密钥。请求体两个可选字段：`console_base_url`（完整 http(s) URL，空串=清除）、`console_shared_secret`（8..256 可见 ASCII，空串=清除）。不传=不改 |
| `GET/POST/PUT ... /console/{provider_id}/*` | 本地反代：剥掉 `/console/{id}` 前缀转发到面板源站，注入 `X-Console-Base: /console/{id}` 请求头。**不经 AE admin 会话**——面板鉴权由服务自己的 session/SSO 承担 |

反代错误语义（便于排障）：provider 不存在或非 relay → `404 {"detail":"console provider not found"}` /
`400`；既无 `console_base_url` 又无启用端点 → `502`；上游连不上 → `502`。

### B.2 面板源站优先级

`provider_ops.console_base_url`（原样使用，仅去尾部斜杠）> 首个启用端点 `base_url` 去掉结尾
`/v1`。所以面板与 API **可以**不在同一地址/端口。

### B.3 共享密钥（两侧可改，注意优先级）

| 侧 | 位置 | 优先级 |
|---|---|---|
| AE | 供应商「控制台」弹窗 ⚙ → 面板地址 / 共享密钥 | AE 侧现值，改完立刻用于下一次签发 |
| Go 面板 | 「控制台免密 SSO」卡片 | `config.json` 的 `console_secret` **优先**；`-console-secret` 只在配置缺它时首次播种，重启不覆盖 |

**规约：** `GET /api/config` 只回 `"***"` + `console_secret_configured` + `console_secret_preview`
（首尾各 4 字符），**永不回明文**。`POST /api/config`：`"***"`=不改、空串=清除、长度 8..256 否则 400。
两边不一致的唯一表现是「弹窗打开后跳回登录页」——先核对两边的掩码是否同源。

### B.4 SSO 签名契约（AE 与 Go 必须逐字节一致）

```
sig = hex(HMAC-SHA256(secret, pid + "|" + exp + "|" + nonce))
```

- URL：`/console-sso?pid=<provider_id>&exp=<unix秒>&n=<nonce>&sig=<hex>`
- `exp` Unix 秒，TTL **90 秒**；`nonce` **一次性**，用后作废（重放返回 401）
- secret 为空 → `/console-sso` 一律 **404**（入口禁用）
- 通过后种 `session` cookie 并 **302 回面板根**（代理下为 `/console/{id}/`，直连为 `/`），行为与密码登录一致

**服务端校验顺序：** ① secret 空 → 404；② `pid/nonce/sig` 缺 → 400；③ `exp` 过期/非法 → 401；
④ 签名不符 → 401；⑤ nonce 已用过 → 401；⑥ 通过 → 种 cookie + 302。

### B.5 前缀与嵌入兼容（面板侧必须满足）

- 面板所有资源 / API 链接**必须是文档相对路径**：`fetch('api/...')`、`action="login"`、
  重定向 `./`。**不得有任何绝对根路径**（如 `href="/x"`、`src="/y"`），否则反代下会跳出前缀。
- 反代注入 `X-Console-Base: /console/{id}`。面板**必须**以此头（或 `Sec-Fetch-Dest: iframe`）
  识别「被 AE 内嵌」，并切换为嵌入版：给 `<body>` 加 `class="embedded"`。
- 面板种 `session` cookie 时用 `Path=/` 即可：AE 反代会把上游 `Set-Cookie` 的 `Path=/`
  重写为 `Path=/console/{id}`，并剥掉 AE 自己的 `aether_refresh_token` 等 cookie。面板**不需要**
  自己拼前缀，也不应依赖 AE 的 cookie。

### B.6 嵌入版自适应（面板侧必须满足）

```
body.embedded header{display:none}              /* 隐藏自带 header，与 AE 弹窗标题重复 */
body.embedded .container{max-width:none;padding:14px 16px 10px}
body.embedded .card{min-width:0}
body.embedded table.tbl{table-layout:fixed;width:100%}   /* 防 min-content 撑破栅格 */
@media(max-width:1100px){.config-grid{grid-template-columns:minmax(0,1fr)}}   /* 单列 */
@media(max-width:620px){ 卡片标题/按钮组纵向、输入与按钮整宽、表格 min-width 缩到 560px }
@media(max-width:400px){ 手机密度：正文 13px、卡片 padding 12px 10px }
```

面板 HTML 与登录 HTML **必须**带 `Cache-Control: no-store, must-revalidate`——它们是逐请求渲染的
（嵌入版与独立版 HTML 不同），启发式缓存会导致升级后仍看到旧界面。

---

## C. 在 AE 中注册与配置（接线步骤）

服务跑起来后，还需要在 AE 侧登记成 relay 供应商。以下字段是**必须**的，缺一个就不通。

### C.1 建供应商

AE 面板「添加提供商」→ 选 **「自定义透传」（relay）**，命名，保存。
（后端 `provider_type` 支持列表在 `normalize.rs` 的 `SUPPORTED_PROVIDER_TYPES`；
前端下拉在 `ProviderFormDialog.vue`。两者都须含 `relay`，否则下拉里看不到。）

### C.2 加端点（核心）

| 字段 | 值 | 说明 |
|---|---|---|
| `api_format` | `openai:chat` | 决定请求/响应翻译格式 |
| `base_url` | `http://<host>:<port>/v1` | **带 `/v1`**；面板源站会去掉该后缀（见 B.2） |
| `custom_path` | 留空 | relay 用 base_url 原样透传 |
| `enabled` | `true` | — |

生产实据（154）：`provider_type=relay`、`api_format=openai:chat`、
`base_url=http://127.0.0.1:8000/v1`。

### C.3 登记模型

在 `models` 表（或面板「模型」页）为该供应商登记它支持的模型名（`provider_model_name`）。
AE 会把请求体里的 `model` 与登记名比对后路由；**没登记的模型请求会 404/400**。

### C.4 配置上游 API Key

在供应商/端点鉴权配置里填你的服务要的 key（`sk-your-upstream-key`）。
AE 会用它在转发时替换客户端发来的 `Authorization`（见 A.2）。

### C.5 providers.config 配置项（自由 JSON，未登记的 key 会被静默忽略）

| key（路径） | 类型 | 默认 | 说明 |
|---|---|---|---|
| `max_transfer_timeout_seconds` | number | 网关默认超时 | relay 透传的最长传输时间。**长流式响应必须调大**（生产用 600） |
| `provider_ops.console_shared_secret` | string | 无 | 面板直通的 HMAC 共享密钥（见 B.3/B.4）。**没有它就没有「打开控制台」入口** |
| `provider_ops.console_base_url` | string | 端点 `base_url` 去 `/v1` | 面板源站地址；面板与 API 不同地址/端口时填这里 |

> 这三个 key 必须在 `providers.config` 里，拼错不会报错，只会「没生效」——改完务必实测。

### C.6 安全：面板端口不要对外

面板与 `/v1` 同进程时，`-port` 只绑回环（如 `127.0.0.1:8000`），让 AE 反代和本机访问，
**不要**绑 `0.0.0.0` 暴露公网，否则等于绕过 AE 直连管理面板。若必须同端口对外，至少确保
面板登录密码足够强、且不响应外部直连（用防火墙只放行 AE 所在主机）。

---

## D. 联调与验收（改完必跑）

原则只有一条：**验收只认“实际发出去的字节 + 落库结果”，不认“代码看起来对”。**

### D.1 四级验证阶梯

| 级别 | 做什么 | 能证明什么 | 不能证明什么 |
|---|---|---|---|
| 1. 单测 | Go `go test ./internal/relayecho ./internal/upstream ./internal/server` | 编解码、脱敏、裁剪、控制头剥离逻辑正确 | 头有没有真的发出去 |
| 2. 直连探针 | 直接打 relay，带 `X-Aether-Echo: 1`，看响应头 | relay 实现了回执 | AE 有没有注入/保留 |
| 3. 抓包 | `tcpdump -i lo -A -n "tcp port <relay_port>"` | 请求里到底有没有控制头、响应里到底有没有回执头 | 落库对不对 |
| 4. 落库 | 查 `usage_http_audits` | 端到端结果与来源标记 | — |

> **第 3 级不能省。** 本次故障就是“计划里有 echo 头、发出去却没有”，只做 1、2、4 会一直
> 在 `local` 上打转。

### D.2 一键验收脚本

```bash
# 需要：一个可用的 AE API Key；可选 PSQL_URL 做落库断言
AETHER_BASE_URL=http://127.0.0.1:8084 \
AETHER_API_KEY=sk-aether-xxx \
RELAY_MODEL=hy3 \
PSQL_URL='postgresql://aether:${AETHER_DB_PASSWORD}@127.0.0.1:5432/aether' \
  bash scripts/relay-conformance.sh
```

脚本依次断言：请求 `200` → 响应头里**没有**回执头泄漏 → 落库
`provider_headers_source = upstream_echo` 且头表非空。任一失败即非零退出并打印定位提示。

### D.3 抓包判据

请求方向（AE → relay）必须看到：

```
x-aether-echo: 1
x-aether-trace-id: <uuid>
```

响应方向（relay → AE）必须看到：

```
X-Aether-Provider-Request-Headers: eJ...
```

同时，**relay → 真实上游**的请求里不得出现任何 `x-aether-*`。

### D.4 故障定位表

| 现象 | 最可能原因 | 怎么确认 |
|---|---|---|
| 刚发完请求查库是 `NULL` | 审计行异步落库 | 等 5–10 秒再查 |
| 稳定 `local`，抓包请求里无 `x-aether-echo` | AE 没注入，或被请求头过滤链拦掉 | 查计划构造器是否覆盖该执行路径；查 `should_skip_request_header` / `should_skip_upstream_passthrough_header` |
| 请求有控制头、响应无回执头 | relay 未实现，或 AE 响应头过滤把 `x-aether-*` 丢了 | 查 `should_skip_response_header` 是否放行 `x-aether-provider-request-headers` |
| 响应有回执头但仍 `local` | payload 校验失败（`v`、`trace_id`、空 headers、内嵌控制头） | 解码回执串逐字段比对 |
| 回执头很大 / `truncated=true` | 触发 8 KB 裁剪 | 正常现象；关注是否有必需头被丢 |
| relay 返回 5xx / 502 | relay 进程挂了或端口不通 | relay 服务日志 + `/health` |
| **Tokens 全空、请求体显示「正文暂不可用」、记录只剩请求头/请求体/元数据三块** | **审计 upsert 的 bind 数与 SQL 占位符数不一致**，整条审计写入报错，terminal usage 事务回滚，只剩 first-byte 的部分记录 | 数 `upsert_usage_http_audit_sql.sql` 的列数与 `$N` 最大值是否相等；单测 `single_row_audit_sql_column_and_placeholder_counts_match` |

### D.5 证据留档

每个改动在 PR / 交付说明里贴三样东西，缺一不可：

1. 抓包片段（请求控制头 + 响应回执头各一行）；
2. 落库 SQL 结果（`provider_headers_source` 与头表存在性）；
3. CI 结论（Rust CI + Relay Build / Go `go test`）。

---

### D.6 部署与回滚约束（迁移是单向门）

**结论：一旦新版本带了数据库迁移，就不能再回滚到不含该迁移的旧二进制。**

sqlx 迁移在启动时做版本预检：DB 的 `_sqlx_migrations` 里存在、而当前二进制内嵌的迁移集合里没有的版本，会直接触发

```
Error: VersionMissing(20261104000000)
```

进程 `exit 1`，systemd 反复重启 → 「readyz 空 + 端口不监听」的假死循环，重启计数会持续上涨。这**不是崩溃**，是版本对不上。

#### 上线前必做

1. 确认本次改动是否新增迁移：`git diff <上次部署 sha>..HEAD --stat -- '*migrations*'`。
2. 若新增，**明确记录本次发布是不可回滚点**；旧 release 留在磁盘仅供取证，不要再启动。
3. 首次启动盯 `systemctl status` 与 `journalctl -u aether-gateway` 的迁移日志，确认 `VersionMissing` 不出现。

#### 回滚策略（按优先级）

| 情况 | 做法 |
|---|---|
| 新版本有功能 bug、但仍需保留迁移 | **向前修复**：改代码重新构建部署；不要切回旧 release |
| 迁移本身是错的（如多加了一列） | **追加补偿迁移**（如 `20261104000001_drop_provider_body_source.sql`）走正常发布；不要手改 DB |
| 极端情况必须回到旧二进制 | 只能先手工处理 `_sqlx_migrations`（删行）+ 执行反向 DDL，属高危操作，需单独评审并留档 |

#### 已验证案例（2026-11-04）

`bc95e6e9e` 引入 `20261104000000`（加 `provider_body_source`）→ 回滚到 `98b53cf37`（无该迁移）→ 触发 `VersionMissing` 无限重启。正确处置是把 `current` 指回含该迁移的版本，之后再追加 `20261104000001` 把多余的列删掉。

#### 顺带教训：加列时必须同步的位置

`provider_body_source` 那次故障的根因不是迁移，而是**只改了 bind 没改 SQL**：

| 位置 | 是否必须同步 |
|---|---|
| `queries/upsert_usage_http_audit_sql.sql` 列清单 + `$N` 占位符 | ✅ 单行 upsert 路径 |
| `mod.rs` 批量 `INSERT` 的列清单 + `push_bind` + `ON CONFLICT` | ✅ 批量路径 |
| `UsageHttpAuditHeaders` / `PreparedUsageUpsert` 结构体与字面量 | ✅ 编译期会报 |
| `metadata_policy.rs` 白名单 | 仅当需要投影到 `request_metadata` |

单行 SQL 的 bind 数是**运行期**错误，编译期查不出来 —— 依赖单测兜底。

---

## 快速自检清单（改完必须逐条核对）

1. `POST /v1/chat/completions` 支持 `stream:true` 返回 SSE，`data: [DONE]` 结尾
2. 响应带 `usage`；429 带 `Retry-After`
3. `/console-sso` 按 B.4 验签：正确→302+session，错误→401，重放→401，空密钥→404
4. 无任何绝对根路径链接/跳转
5. 带 `X-Console-Base` 时返回 `body class="embedded"`，header 隐藏
6. 520px iframe 下无横向溢出、按钮/输入整宽、表格横向滚动而非压扁
7. 面板 HTML 返回 `Cache-Control: no-store`
8. 两侧密钥掩码一致；保存 Go 侧密钥后下次 SSO 即用新值（无需重启）
9. AE 端点 `base_url` 带 `/v1`、`api_format=openai:chat`、模型已登记、上游 key 已配
10. 长流式已把 `max_transfer_timeout_seconds` 调大（如 600）
11. 面板端口只绑回环，未对公网暴露
12. 带 `X-Aether-Echo: 1` 时返回 `X-Aether-Provider-Request-Headers`，且 payload 的 `trace_id` 等于请求头
13. 回执头里的 `authorization` / `cookie` 等已脱敏，且不含 `x-aether-echo`、`x-aether-trace-id`
14. 发往真实上游的请求**不含**任何 `x-aether-*`（抓包确认）
15. `usage_http_audits.provider_headers_source = upstream_echo`，`scripts/relay-conformance.sh` 全绿
16. `provider_request_body` 落库内容与 relay 实际发往上游的 body 逐字节一致（含 relay 注入的 `stream_options` / `prompt_cache_key`）
17. `usage.total_tokens` 非空且 `usage_body_blobs` 中存在 `provider_request_body`（缺任一即为审计写入失败，见 D.6）
18. 本次发布是否新增迁移已确认；若新增，已在交付说明里标注「不可回滚点」
