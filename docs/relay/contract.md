# relay 服务端接口契约 + 面板对接契约

> 给实现方的自包含规约：只读这一份，即可从零实现一个「OpenAI 兼容的 relay 上游服务 + 内嵌到 AE
> 网关的管理面板」，并让它与 AE 完成免密 SSO 对接。
>
> 本文覆盖两部分：**A. relay 服务端接口契约**（供 `/v1` API 透传）、**B. 管理面板与 AE 的内嵌 /
> SSO 契约**（供供应商管理弹窗直通）。
>
> 上游回执（echo）协议见 [echo.md](echo.md)；在 AE 里注册配置与联调验收见 [deploy.md](deploy.md)。

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

### A.5 上游回执（echo）

如果希望 AE 记录「你真正发给上游的请求头 / 请求体」，需实现回执协议：识别 `X-Aether-Echo`
控制头，用响应头 `X-Aether-Provider-Request-Headers` 回传。完整契约见 [echo.md](echo.md)。

不实现也完全可用——AE 会退回本地记录并标 `local`，只是那份头是估算值。

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
