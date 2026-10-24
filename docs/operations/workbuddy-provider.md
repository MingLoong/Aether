# WorkBuddy（腾讯 CodeBuddy）供应商

`provider_type = "workbuddy"`：Aether 直连腾讯 CodeBuddy / WorkBuddy 的**私有对话入口**，
自己管账号池（不走任何中转面板）。上游协议、URL 与判定口径的事实来源是开源面板
`linguo2625469/workbuddy2api-panel`——本文每条都标注了对应文件/符号，便于回查。

> **阅读约定（2026-10-17 维护性审计后修订 ✓）**
> - **本文只描述「当前行为」** ✓。正文里形如 `v23` / `v35.1` / `v36–v38` 的标注是
>   **作者自己的迭代轮次**（整批改动是**一个**未提交的 patch），**不代表发布版本**，
>   也不该被当成兼容性承诺 ✗。历史过程见
>   [`.agents/notes/implemented/feature/2026-10-13-workbuddy-provider.md`](../../../.agents/notes/implemented/feature/2026-10-13-workbuddy-provider.md)。
> - 审计前本文出过两类错 ✗，已修：**差距表里 5 行「未做」其实早已实现** ✗；
>   **旋钮默认值停留在旧口径** ✗（后端已改成面板口径）。凡涉及默认值，**以
>   `crates/aether-pool-core/src/pool_advanced_defaults.rs` 为唯一事实来源** ✓。
> - 跨仓引用（面板 `*.go:行号`）**只作线索** ✓：上游改一行即失效 ✗，本仓无法验证 ✗；
>   仓内引用优先用**符号名**而非行号 ✓。
> - **不写测试条数** ✗（写过，且已经漂了 ✗）：只给命令，数值以实际运行为准 ✓。

---

## 1. 上游协议事实

### 1.1 域与入口

| 用途 | 路径 | 方法 | 说明 |
| --- | --- | --- | --- |
| 对话 | `/v2/chat/completions` | POST | CN 与国际**共用**一条（国际版的 `/console/...` 已被上游 WAF 按请求体内容拦掉，面板也因此固定用 `/v2`） |
| 目录 | `/v3/config` | GET | 模型目录。**对 UA 敏感**：必须带官方 IDE 段，否则 `400 code=12403`（对话域） |
| 成长 | `/activity/growth/{streak,redeem,lottery/summary,lottery/draw,heatmap,makeup-cards/use}` | GET/POST | 连登兑换、抽奖、漏签判断与补签（**对话域** + 计费头族） |
| 旅行 | `/activity/growth/buddy/{info,travel/status,travel/depart,travel/claim,agreement,first}` | GET/POST | 猫猫旅行的状态机与领养链路（**对话域**） |
| 礼包/补偿 | `/billing/meter/claim-gift`、`/billing/meter/claim-compensation` | POST | 新手礼包与活动补偿（**计费域**，无 `/v2` 前缀） |
| 余额（个人） | `/v2/billing/meter/get-user-resource` | POST | 国际域首选无 `/v2` 前缀的 `/billing/meter/get-user-resource` |
| 余额（企业） | `/v2/billing/meter/get-enterprise-user-usage` | POST | `enterpriseId` 非空时走这条；body `{}` |
| 设备授权 | `/v2/plugin/auth/state?platform=CLI`、`/v2/plugin/auth/token?state=`、`/v2/plugin/login/account?state=` | POST/GET | 建会话 / 轮询 / 取账号信息 |
| 刷新 | `/v2/plugin/auth/token/refresh` | POST | **无 body**，`X-Refresh-Token` 头 + `X-Auth-Refresh-Source: plugin` |

两个域：CN `https://copilot.tencent.com`、国际 `https://www.workbuddy.ai`。
realm 判定：`auth_config.realm == "global"` 显式优先，否则账号域以 `workbuddy.ai` 结尾算国际，其余 CN。

### 1.2 出站头族（缺一个就可能是 `403 code 11140`）

- `X-CodeBuddy-Request: 1`（风控闸门头，所有 API 请求必带）；
- `X-User-Id`、`X-Enterprise-Id` / `X-No-Enterprise-Id`、`X-Domain` / `X-No-Department-Info`；
- `Origin` / `Referer` 按 realm；`Accept-Language` 按 realm（`zh-CN` / `en-US`）；
- **三段式 UA**：`WorkBuddy/{ver} {WorkBuddy|workbuddy-ai}/{ver} CLI/{cli}`；
- `X-Machine-ID` / `X-Session-ID`：`sha256("wb2a:" + purpose + ":" + uid)` 取前 18 字节 hex（36 个 hex 字符）。

**UA 分两类**（面板 `ChatHeaders` / `BillingHeaders` 口径，上游对 UA 敏感）：
- **对话端点**（`/v2/chat/completions`、官网领奖）：三段式
  `WorkBuddy/{ver} {WorkBuddy|workbuddy-ai}/{ver} CLI/{cli}`；
- **计费/成长端点**（余额 / 签到 / 活跃上报 / 成长中心 / 猫猫旅行 / 成长任务，即所有走
  `BillingHeaders` 的请求）：**单段** `WorkBuddy/{ver}`——官方 banner 显式覆写形态，
  **不带 CLI 段、也不带 realm 平台段**。

**`X-Device-Token`（有就注入）**：面板 `device_token.go` 读的是**桌面端 Turing Shield SDK
落盘的文件**（容器里没有 SDK → 读不到就**优雅降级不注入**，不影响主流程）。Aether 没有
SDK 也没有那个文件，因此提供等价旋钮：provider config 的
**`workbuddy_device_token`**（字符串，≤1 KiB，超长视为异常不注入），配置了就随**对话与
计费/成长两类请求**一起发；不配就照常发（与面板同为优雅降级）。

**这些头由网关覆盖客户端同名值**（与 xai 的「缺失才补」相反）：它们描述的是账号身份，
客户端自带的 `origin` / `user-agent` / `x-user-id` 必须换成账号真实值。

> **会话/链路头族（已做，2026-10 补齐）**：面板 `headers.go::injectConversationHeaders` 还会
> **自己生成**一整套官方客户端「会话/链路」头族（面板注释标为「必发」，用于上游后台把同一轮
> 对话聚合为一条，issue #35）。Aether 侧由
> `insert_workbuddy_conversation_headers_if_needed` 生成，接线在 standard 对话计划的
> **同格式与跨格式两条分支**（`planner/standard/openai/chat/decision/request.rs`）以及
> passthrough 同格式路径，**用 trace id 当聚合主键的稳定种子**：
>
> | 头 | 规则 |
> | --- | --- |
> | `X-Conversation-Request-ID` | 聚合主键，**必发**；客户端值优先，否则把 trace id 归一成 32 hex（sha256 前 16 字节），再没有才现生成 |
> | `X-Conversation-Message-ID` = `X-Request-ID` | 消息级，每次尝试新生成 32 hex（UUID v4 去横线） |
> | `X-Root-Request-ID` | = 聚合主键 |
> | `X-Trace-ID` | 入站透传优先，否则 = 聚合主键 |
> | `X-B3-TraceId` / `X-B3-SpanId` / `X-B3-Sampled` | 聚合主键合法（16/32 hex）时用它，否则回落消息 id；SpanId = 消息 id 前 16 hex；Sampled = `1` |
> | `X-Conversation-ID` | 客户端给了才发；**国际域例外：缺失时现生成 UUID**（见 §1.2.1） |

#### 1.2.1 国际域的「渠道校验」：三个头缺一即全站不可用（2026-10 实测定位）

**症状**：`workbuddy-global` 全部对话 `HTTP 400 {"code":11128,"msg":"request illegal"}`，
`displayTips` 为「这次调用没通过渠道校验，可能不是官方客户端发出的」——
表现为「国际号导入成功、额度正常、就是不能聊」。

**定位方法**（可复用）：官方国际版桌面端 `D:\Program Files\WorkBuddyAI` 的 chat 由
`app.asar\cli` 的 Node CLI 发出，**不经过 Electron `webRequest`**（挂 `session.webRequest`
只能抓到遥测）。有效手段是给 `resources\app.asar.unpacked\cli\bin\codebuddy` 临时插入一行
`require(<hook>)`（改前备份、抓完还原），在 hook 里包 `http/https.request` 打出真实出站头。

**结论**（逐项二分，同一账号同一令牌）：

| 头 / 条件 | 是否必需 |
| --- | --- |
| `X-Conversation-ID`（UUID 形态） | **必需** |
| `X-Conversation-Request-ID` + `X-Conversation-Message-ID` | **必需**（各单独出现不够） |
| `X-Root-Request-ID` / `X-Request-ID` | 随上两者同值即可 |
| body **首条消息是 `system`** | **必需**（否则 `400 first message is not system prompt`） |
| 必须流式 | **必需**（非流式恒 `400 code 11101`） |
| `X-Device-Token`、`x-stainless-*`、`traceparent`/`b3`/`X-B3-*`、`X-Requested-With`、gzip 请求体 | **非必需**（去掉均 200） |

取值**无需服务端真实会话**：随机 UUID + 32 hex 均实测通过。CN 域无此校验，故维持
「客户端给了才发」的原规则不变（零回归）。

#### 1.2.2 国际域 UA 平台段是 `workbuddy-ai`（不是 `WorkBuddy AI`）——同时决定模型目录

官方国际版桌面端出站 UA 实测为
`WorkBuddy/5.8.4 workbuddy-ai/5.8.4 CLI/2.161.0`（版本段也随之为 5.8.4 / 2.161.0）。
早期实现写的 `WorkBuddy AI`（来自 intl 逆向笔记）与实测不符。

**平台段写错的连带后果**：上游按「客户端版本」下发 `/v3/config` 目录，UA 不匹配时只返回
**旧客户端的 8 个别名**（`auto-chat` / `balanced-model` / `default-model` / `enhance-1.0` /
`fast-model` / `hy4-preview-f` / `o4-mini` / `primary-model`），其中 4 个对话端点还会
`11102 service info not found`。改正后同一接口返回 **24 个**真实模型
（`glm-5.2` / `glm-5.3` / `kimi-k2.6` / `kimi-k3` / `gemini-3.5-flash` / `gpt-5.5` …），
`glm-5.2`、`kimi-k2.6` 等实测 200 可用。

CN 域版本段/平台段一律不动（`5.5.4` / `WorkBuddy`），改动只在国际域生效。

> **另有一类 400 不是缺陷**：`11158 model [...] is not allowed for user type
> [personal_free_user]` 是**套餐权限**（免费账号无权用 `gpt-5.5` / `gemini-3.5-flash` 等），
> `11134 the model provider is temporarily unavailable` 是上游临时故障。
> 两者都应视作上游侧结论，不要当成本地配置问题排查。

#### 1.2.3 出站头白名单：默认不外传第三方客户端归属头（2026-10 加固）

**问题**：出站头本是「入站头**全量透传** + 覆盖身份头」——`build_complete_passthrough_headers_with_auth`
先把客户端入站头几乎全量拷出去（`auth.rs::collect_complete_passthrough_headers`），再由
`insert_workbuddy_request_headers` **覆盖** `origin` / `user-agent` / `x-user-id` 等身份头。
结果：身份头被正确覆盖，但**第三方客户端自带的归属/遥测头照样透传**给腾讯。真机抓包（ZCode
客户端 → Aether → 上游）实测泄露出 `x-zcode-agent` / `x-zcode-app-version` /
`x-zcode-session-type` / `x-zcode-trace-id` / `x-title: Z Code@electron` /
`http-referer: https://zcode.z.ai` / `sec-fetch-mode` / `x-query-id`——既泄露真实客户端归属，
又造成「官方 UA + 外家头」的自相矛盾指纹（上游本就按指纹做风控，缺头即 `11140`）。

**根因**：默认黑名单只挡逐跳头 / 转发元数据 / 凭证 / `x-aether-*` / 路由覆写头
（`headers.rs::should_skip_upstream_complete_passthrough_header`），**不覆盖第三方身份头**；
端点 `header_rules` 虽有 `drop` 动作（`provider_compat/proxy/rules.rs`）但逐端点手动配、默认不启用。

**机制**：白名单 `sanitize_workbuddy_outbound_headers`（`transport/src/workbuddy/mod.rs`）挂在
`insert_workbuddy_request_headers_if_needed` 的两道门（本 provider + `openai:*` 格式）之后，
standard 与 passthrough **两条出站路径共用此入口**，因此一次覆盖到位。只留白名单内、
**白名单外任何未知头默认丢弃**。保留三类（全部「官方真实」）：

| 类别 | 头 | 取值 |
| --- | --- | --- |
| 身份头族 | `origin` / `referer` / `user-agent` / `x-codebuddy-request` / `x-user-id` / `x-machine-id` / `x-session-id` / `x-domain` / `x-no-enterprise-id` / `x-agent-purpose` / `x-ide-*` / `x-product` / `x-device-token` … | 由 `insert_workbuddy_request_headers` **按账号真值覆盖**（绝不透传外家值） |
| 会话/链路 + 协议基础 | `x-conversation-*` / `x-root-request-id` / `x-request-id` / `x-trace-id` / `x-b3-*` / `authorization` / `accept` / `accept-encoding` / `content-type` | 会话入站值**保留**供随后 `insert_workbuddy_conversation_headers_if_needed` 按「客户端值优先」消费 |
| 中性桌面遥测 | `x-client-language` / `x-client-timezone` / `x-os-category` / `x-os-version` / `x-platform` / `x-release-channel` | **保留真实机值**——官方客户端在同一台机器上发的正是这些值，硬编码反而更假 |

**丢弃**：上表之外（含全部 `x-zcode-*` / `x-title` / `http-referer` / `sec-fetch-*` / `x-query-id`）。

**两个关键时序**（都在 `insert_workbuddy_request_headers_if_needed` 内）：
1. **过滤在身份头写入之前** → 身份头与内部标记 `x-aether-workbuddy-runtime`（响应侧 DSML
   还原认 provider 用）在过滤**之后**写入，不被白名单误删；
2. **过滤在会话头注入之前** → 会话入站值先被白名单保留，后续会话注入再处理；会话头输出
   在过滤之后追加，天然安全。

**已知取舍**：端点 `header_rules` 的 `set` **先于**本过滤执行，因此只有落在白名单内的自定义键
才会保留（官方头族之外的自定义转发头会被这道门挡掉）——这是刻意的「默认不外传」取舍。
钉住行为的单测：`workbuddy::tests::outbound_allowlist_strips_third_party_client_identity_headers`
（归属头逐条断言删除、身份/会话/遥测/内部标记逐条断言保留）。


### 1.3 请求体与响应体

- **请求**：上游是 OpenAI Chat Completions 的**窄子集**——role 白名单不含 `developer`；
  只认 `max_tokens`（`max_completion_tokens` 被忽略、长回答静默截断）；`tool_choice`
  只认字符串；`image_url` 只接受对象形态（字符串形态 `400 code 11101`）。
- **响应**：工具调用不是结构化字段，而是内联 `‖DSML‖` 标记文本——只有当请求声明了
  `tools` 时上游才把它转成 `tool_calls`；某一跳丢了 `tools`，标记就落进 assistant 正文，
  执行工具的客户端会把标记当散文收下、**回合直接结束**。
- **失败语义藏在业务 code 里**：`12153` 会话失效、`11140` 账号级授权风控、
  `14017` 试用未激活、`11102` 该后端无此模型、`6004` 模型级限流、`14018` 积分耗尽、
  `11101`/`11115`/`11135` 请求级错误。

### 1.4 候选 SQL：**每个 OR 链都要有 workbuddy arm**（真机踩过的坑）

Aether 的候选查询（`crates/aether-data/adapters/postgres/src/candidate_selection.rs`）
每条 SQL 里有**两个** provider 类型白名单 OR 链：

1. **内层**（`provider_api_keys` 的 LATERAL 子查询）：决定「这个 provider 的 key 能不能选」；
2. **外层**（主查询的 provider/api_format 兼容性）：决定「这个 provider 配不配这个请求格式」。

两条链都是**白名单式**的：除了少数特例 arm，最后的兜底分支要求
`provider_type NOT IN (…) AND auth_type <> 'oauth'`——workbuddy 是 **OAuth 账号**，
所以**两条链都必须有它自己的 arm**，只加内层会出现：

> key 选得出来 → 外层把它筛掉 → 客户端 `/v1/chat/completions` 报
> 「没有可用提供商支持模型 X」，日志里 `local_execution_runtime_miss_reason=candidate_list_empty`，
> 而**后台的 `test-model`（`mode: global`）却完全正常**——因为那条路径不走这份公开候选 SQL。

真机实测（2026-10-15）就是这个形态：`glm-5.2` / `hy3` / `deepseek-v4-flash` 在客户端全部零候选，
而同名模型用后台测试接口一发就通。修复后同一份 SQL 在库里返回 **17 条 workbuddy 候选**。

> 教训：只断言「SQL 里含 `= 'workbuddy'`」的测试**放过了**这个缺陷（内层满足即可通过）。
> 现在测试按 **arm 出现次数** 钉住（exact=2、global_model=2、pool_keys=1、requested_model=2），
> 即「每个 OR 链都要有」。

---

## 2. Aether 侧实现

| 文件 | 职责 |
| --- | --- |
| `crates/aether-provider/transport/src/workbuddy/mod.rs` | 身份解析（uid / 企业 / 域 / realm）、`sha256("wb2a:…")` 稳定指纹、三段式 UA、**CodeBuddy 出站头族**、**出站请求体归一化与两层防误报**、降级闸门、访问令牌解析 |
| `crates/aether-provider/transport/src/workbuddy/failure.rs` | 上游失败分类（13 类，顺序照面板 `Classify`）+ 凭证作废判定 |
| `crates/aether-provider/transport/src/workbuddy/refresh.rs` | 本地 OAuth 刷新适配器（无 body + 刷新令牌头）+ 本地计划解析门 |
| `crates/aether-provider/transport/src/provider_types.rs` | 固定模板（base_url / `custom_path` / force-stream 默认）+ 运行时策略 + 后台 OAuth 模板 |
| `crates/aether-provider/pool/src/providers/workbuddy.rs` | 池适配：`quota_refresh` 能力 + 余额查询请求构造 |
| `crates/aether-provider/pool/src/{lib.rs,service.rs}` | 适配器注册（`provider_types_for_capability` 因此包含 workbuddy） |
| `crates/aether-ai/formats/src/provider_compat/workbuddy_dsml/` | 响应侧 DSML 还原（整段 + 流式 + 内部标记头常量），见 §2.2 |
| `crates/aether-admin/src/provider/quota.rs` | 余额解析（个人 / 企业两套口径归一） |
| `crates/aether-oauth/src/provider/providers/workbuddy.rs` | 设备授权 / 刷新 / 凭据导入（面板 `auths/*.json` 两种形态、毫秒→秒） |
| `apps/aether-gateway/src/handlers/admin/provider/oauth/dispatch/device/workbuddy.rs` | 设备授权端到端（建会话 → 轮询 → 建 key） |
| `apps/aether-gateway/src/handlers/admin/provider/oauth/quota/workbuddy.rs`、`quota/dispatch.rs` | 余额刷新编排 + 注册 |
| `apps/aether-gateway/src/handlers/shared/catalog.rs` | 额度快照投影（计数值窗口） |
| `apps/aether-gateway/src/orchestration/effects.rs` | 凭证作废 + pool 硬状态（按 provider 分类） |
| `apps/aether-gateway/src/ai_serving/finalize/internal/{sync_finalize.rs,stream_rewrite.rs}` | 非流式 / 流式 DSML 接线点 |
| `crates/aether-model-fetch/src/{strategy.rs,transport.rs,logic.rs}` | 模型目录拉取策略 + 计划构造 + 解析 |
| `apps/aether-gateway/src/ai_serving/transport.rs`、`planner/**/request.rs` 等 | 出站头注入点、请求体归一化入口、门面 |

### 2.1 出站请求体：协议兼容 + 两层防误报

`apply_workbuddy_request_body_semantics`（两个入口：`request_body.rs` 的转换路径、
`planner/standard/openai/chat/decision/request.rs` 的主路径）按顺序做三件事：

1. **窄子集协议兼容**（顺序对齐面板 `prepareBody`）：
   `max_completion_tokens`→`max_tokens`（别名只删，显式 `max_tokens` 优先）→
   **gpt 系 `max_tokens` 下限钳制到 16**（面板 `clampGPTMinMaxTokens`）→
   **缺省补 `stream_options.include_usage = true`**（面板 D7：官方 CLI 流式必发，上游据此在
   末帧返回 usage；**缺了就没有用量数据**，显式带则不覆盖）→
   `tool_choice` 对象→字符串（`none` 连 `tools` 一起去掉）→
   **tool schema 里 `\_` 还原成 `_`**（`pattern` 值与 `patternProperties` 键都要，面板
   `normalizeToolPatterns`）→ `developer`→`system` → `image_url` 字符串→对象 →
   **tool 配对三步**（见下）；
2. **提示词替换**：客户端（Claude Code / Codex 形态）注入的 system 是固定模板句，
   上游按**逐字精确匹配**整单拦截 → 默认用网关自有提示词替换掉；
3. **指纹脱敏**（逐条对齐面板 `sanitize.go`，**以字节码点为准**）：
   ① **模板句改写表**（每句只改一个词、语义不变）：身份句 `…official CLI for Claude`
   → 插 `tool `；`Main branch (…)` → `Default branch (…)`；Codex 首段 `…Codex CLI,`
   → 插 ` tool`；反馈句 `give` → `provide`；
   ② 剥离 `x-anthropic-billing-hdr: …;` 键值段（键名即触发，与值无关）；
   ③ 循环清掉尾随 `cc_*=…;`；
   ④ 把上游反探测的**五位**错误码 `11-128` 改写成插入 U+002D 的六字符形态（零宽字符会被
   上游归一化，实测无效，必须换可见字符）；
   ⑤ 残留裸键名换成 U+2011 同形变体（面板这里用的是与模式串相同的替换串，等于空操作；
   本实现刻意更严）。

> **tool 配对三步（已做，2026-10）**：`normalize_workbuddy_tool_pairing`，顺序与面板
> `tool_pairing.go` 一致——**合并 → 重排 → 清孤儿**（顺序不能换）。为什么必须有：
> OpenAI 兼容协议要求带 `tool_calls` 的 assistant 之后紧跟它自己的 `role: tool` 结果，
> 缺任一侧或中间插了别的消息，上游就 **HTTP 400 拒整单**；而客户端把失败的工具调用
> 持久化进历史后，**之后每条消息都会 400，整条会话报废**（换号也无效，不是账号问题）。
>
> 1. **合并**：背靠背的 `assistant.tool_calls` 合成一条（部分客户端回放时把同一批并行
>    调用拆成多条紧邻 assistant → 上游 `11148 tool_call_sequence_broken`）；另有一条
>    反向形态：纯正文 assistant 紧跟「带 tool_calls 且无正文」的 assistant → 正文折进前一条。
>    合并时 `reasoning_content` 不丢（两边都有则换行拼接）。
> 2. **重排**：把插在 assistant 与同批 tool 结果之间的非 tool 消息（如 Codex 的
>    `image_resize_notice`）挪到整组之后，**只调顺序不改内容**；下一组
>    `assistant.tool_calls` 是新组头，绝不当插入物吞掉。
> 3. **清孤儿**：按 id **两侧对称裁剪**（只留有结果的调用、只留调用被保留的结果，
>    不留半截配对）；`function.name` 为空的调用一律不删则删（上游判
>    `11133 model_param_invalid`，带不带结果都拒）。

> **DeepSeek 思维链（已做，2026-10）**：`inject_workbuddy_thinking` +
> `backfill_workbuddy_reasoning_content` 按面板 `thinking.go` 落地（**仅 deepseek 系模型**）：
> ① 无 `thinking` → 注入 `type=enabled` 并补默认档（默认档缺失时回退硬编码 `high`，与面板
> 一致）；显式 `disabled` → 尊重并删掉两个 effort 字段；显式 `enabled` 缺档 → 补默认档；
> 已有档位**不覆盖**。② 多轮一致性：`thinking.enabled` 或有 reasoning 痕迹时，给每条
> assistant 补齐 `reasoning_content`（已是字符串不覆盖；否则复制 `reasoning`；皆无补空串），
> 并把 `reasoning` 镜像成非空（皆空写**单个空格**——上游只校验 `len > 0`）。
>
> **档位降级的数据源也已接通**（面板 `efforts` / `defaultEfforts` 缓存的等价物）：
> 模型拉取时 `model_catalog_upstream_metadata` 的 workbuddy 分支把
> `{workbuddy: {models: {<模型>: {efforts, default_effort}}}}` 写进 key 元数据
> （`persist_key_fetch_success`），请求路径按它降级：请求档在支持列表里透传；否则取
> **≤ 请求档的最高支持档**；支持档全高则取最低支持档。读不到就不降级（与面板
> 「目录缓存未命中一律透传」同口径）。
>
> ⚠️ **共用命名空间的坑（已修）**：`workbuddy` 命名空间被两条链路写（额度刷新写
> `credits_*` / `updated_at` / `packages`，模型目录写 `models`），而
> `merge_upstream_metadata` 默认是**整桶替换** → 会互相抹掉。已照 codex/antigravity 先例
> 给该命名空间加**逐字段保留**规则（incoming 带的字段照旧覆盖），并有测试钉住两个方向。

provider `config` 开关：

| 键 | 默认 | 说明 |
| --- | --- | --- |
| `workbuddy_prompt_mode` | `custom` | `custom` = 删除全部 system/developer 并插入网关提示词（**会覆盖客户端人格**）；`append` = 在开头连续 system/developer 之后追加；`passthrough` = 原样透传 |
| `workbuddy_prompt_text` | 空 | 空 = 内置提示词（移植自面板 `internal/prompt/defaultprompt.md`） |
| `workbuddy_sanitize_fingerprints` | `true` | 指纹脱敏总开关 |

> **prompt_cache_key 注入（已做，2026-10）**：面板 `cache_key.go` 的 **P0 费用优化**。
> 逆向实测（面板注释）：同一段 8k token 前缀，不带该字段 `prompt_cache_hit_tokens=0`、
> credit≈0.34；带上则命中 7808、credit≈0.02——**费用降约 17×**。
>
> 键格式 `wb2a-<uid8>-<convHex>`：`uid8` 是账号 UID 前 8 字符，`convHex` =
> `sha256(uid + "|" + conversation)` 前 16 字节 hex。**uid 是硬性安全隔离因子**——
> 跨账号复用同一 cache key 会让上游命中**错账号**的前缀缓存、泄露对方对话。
> 优先级：① body 已有非空 `prompt_cache_key` → **原值保留**；② body 的
> `conversation_id` / `conversationId`；③ 入站 `X-Conversation-ID`（**当前未接这一级**，
> 因为 body 语义入口拿不到入站头；②优先于③，常见路径行为一致）；④ 全空 → convHex 为
> 定值（账号内复用前缀，账号隔离段仍在）。
>
> **global 档位静态兜底（已做，2026-10）**：global 上游可能**不下发** `supportedEfforts`，
> 而往 WorkBuddy 上游发不支持的档位是**非法参数 400**（面板 issue #84：`deepseek-v4.1-flash`
> 国际版只认 `high`，客户端传 `low`/`max` 必须降级）。Aether 按面板 `globalEffortFallback`
> 内置了**产品级静态兜底表**（18 个模型），规则：远端桶非空即权威，否则落静态表；
> **只在 global realm 生效**（CN 只用远端桶，与面板 `prepareBody` 一致）。注意该表与 CN 面
> **刻意不同**（同 id 两域档位集合不一样），绝不可混用。

> **实现记录（踩过的坑）**：`sanitize.go` 里这些字符串**看起来**可能与右侧相同——早期版本
> 因此判断「面板的改写表是空操作/差异是不可见字符」而**没有移植**，并且把错误码写成了
> 「带连字符的六字符形态 → U+2011」（**方向与字符都错**：上游拦的是**五位** `11-128`）。
> 实测办法：**只信码点**——`ReadAllLines`/终端渲染会吞掉长行中间一段（例如
> `(?i)x-anthropic-billing-hdr:[^;\n]*;?\s*` 被显示成 `(?i)\n]*;?\s*`），
> 任何「两串看起来一样」的判断都必须用码点/长度/字节比较来复核。
> 因此改写表在代码里是**结构化**的（`prefix + search/replace + suffix`），
> 并有 `template_rewrites_actually_change_something` 与
> `every_template_rewrite_rewrites_its_own_search_form` 两条测试防止它退化成空操作。

### 2.2 DSML 工具调用还原（含截断与用量规范化）

实现在**格式 crate**的 `provider_compat/workbuddy_dsml/`：流改写矩阵必须由格式 crate 拥有
（`tests/architecture/ai_serving.rs` 禁止 gateway 的 `stream_rewrite.rs` 解析
`client_api_format` 一类字段），而 `provider_compat` 正是 provider 私有响应兼容的归处
（`kiro_stream.rs` 先例）；transport 依赖 formats、反向不行，所以这块只能住 formats。

**截断清理**（`drop_truncated_workbuddy_tool_calls`，面板 `truncation.go`）：
`finish_reason == "length"`（模型撞 `max_tokens` 提前中止）时，工具调用的 `arguments`
会只剩半截 JSON——原样下发会让客户端解析非法 JSON **卡死会话**，所以**丢弃**这些调用
（不是补成 `{}` 伪造合法外观）。判定只看 `arguments`：空串/纯空白（无参工具）**保留**、
非空且解析失败**丢弃**、能解析（含 `null`/标量/数组）保留。

> **与面板的一处已知差异**：面板的触发条件还有「流没收 `[DONE]`」，那需要**聚合整条流**
> 才有的信息（面板就是这么做的：内部把流聚合成一条 `chat.completion` 再发出）。
> Aether 的流式路径是**逐帧透传**，无法收回已经发给客户端的 delta，所以只在
> `finish_reason == "length"` 时清理（同步/聚合路径两者都覆盖）。取舍：保住流式延迟，
> 代价是「上游连接被截断且未发收尾帧」时原生 `tool_calls` 的残缺参数仍会透传。

**用量规范化**（`usage.rs`，面板 `usage.go` + `sse.go::ensureUsageTotal`），同步与流式都做：

**流式终止符与 tool_call 名字收敛**（面板 `sse.go::Stream` / `stripToolCallNames`）：

- **保证至少一个 `[DONE]`**：上游被截断、或没发 `[DONE]` 就结束时，`finish()` 补一个——
  否则等 `[DONE]` 的标准客户端会一直挂住（面板同款保证；已见过 `[DONE]` 则不重复补）。
- **`tool_calls` 的 `name` 每个 index 只出现一次**：首片保留 `function.name`，同一 index 的
  后续分片**删掉该键**（无论上游给空串还是重复非空串）。这是 OpenAI 官方流的真实形态，也是
  两类客户端的**共同祖先行为**：累加型（`name += … || ""`）不会把名字拼成 `BashBash…`
  （面板 issue #82），覆盖型（`name ?? state.name`）不会被空串清空工具名。只动 `name`，
  `id` / `type` / `arguments` 原样透传。
  > **真机探测记录（2026-10-15）**：对 `auto` / `hy3` / `glm-5.2` / `space-bunny` 四个模型发
  > 同一套 tools 请求，**四个都返回原生 `tool_calls`，没有一个把调用写在正文里** → 也就是说
  > **DSML 还原链路在真机上尚未被触发**（目前只有单测覆盖；触发条件待更多客户端/模型组合确认）。
  > 其中 `glm-5.2` / `space-bunny` 的 `function.name` **正常**（`get_weather`）→ 证明上面这套
  > 收敛逻辑**不会破坏名字**；而 `auto` / `hy3` 的 name 是**空串**——那是**上游/模型侧行为**
  > （面板同样如此），不是收敛逻辑造成的。真机上也没有观测到「名字在后续分片才到」的形态，
  > 因此这里**保持与面板逐字一致**，不为未证实的场景引入分叉。

- **缓存命中别名对齐**：上游可能把真实命中写在 `prompt_tokens_details.cached_tokens`，
  同时发 `cache_read_input_tokens: 0` / `cached_tokens: 0` 兼容别名；严格客户端会读那些 0
  → **命中被丢掉**。按可信度顺序（`prompt_tokens_details.cached_tokens` →
  `prompt_cache_hit_tokens` → `cache_read_input_tokens` → `cached_tokens` →
  `input_tokens_details.cached_tokens`）取**第一个正数**，回写到全部别名；
  `input_tokens_details` **只在客户端给了才回写**（不给 Chat-only 客户端凭空造 Responses 形态）。
- **`total_tokens` 补齐**：严格按 schema 校验的客户端要求 usage 必含 `total_tokens`；
  只在 prompt/completion **都在**且缺 total 时补和，单边有值**不臆造**。

- `repair_workbuddy_dsml_text`：整块闭合、invoke/parameter 之间只有空白、≥1 个 invoke、
  声明清单非空则严格校验名字（清单为空退化成形状校验）、超 256 KiB 未闭合直接放弃；
  **任一条不满足就返回 `None`，调用方原样保留文本（含开标签）——绝不吞字节**。
  标记识别与面板**逐字对齐**：开/闭标记是固定串，而 invoke/parameter **头内部**用 `\s+`
  容忍任意空白（多空格/制表/换行）；工具调用 id 用 `call_<纳秒>_<序号>`（跨响应唯一，
  否则客户端会把多轮的工具结果配错）；非流式 `tool_calls` **不带** `index`（严格校验的
  客户端会挑刺）。
- `WorkbuddyDsmlStreamRepair`：流式状态机。标记会被切在任意字节位置，所以带回退缓冲：  只在「可能是标记开头」时扣住正文（普通文本即时放行），完整块闭合后在收尾帧挂
  `tool_calls` 并把 `finish_reason` 改成 `tool_calls`；上游没给收尾帧就自己补一帧；
  未闭合块 / 超限块 / 结尾半截标记都在 `finish()` 原样补发。

**识别方式**：出站头带内部标记 `x-aether-workbuddy-runtime: 1`（grok 同款手法）——
finalize 层拿不到 `provider_type`，而守卫禁止在 planner/finalize 内联 provider 类型判断。
**接线位置**：非流式挂 `sync_finalize.rs` 的同格式成功分支（四条前置条件：带标记、
`client_api_format == openai:chat`、无结构化 `tool_calls`、`finish_reason == "stop"`）；
流式挂 `LocalStreamRewriter` 枚举的新分支——`execution_runtime/stream/execution.rs` 的
所有分片处理点与收尾点**一行没改**。两处调用都经 `ai_serving/transport.rs` 的
`workbuddy_dsml` 门面转一层（gateway 只允许从 `ai_serving` 根接缝引用 `aether_ai_formats::`）。

### 2.3 降级重试（degrade）

状态机 `WorkbuddyDegradeGate`（面板 `degradeGate` 同款）：进程内、重启清零；触发后有效到
**次日 00:00 CST**（固定 +08:00 计算，不看宿主机时区）；期内再次触发**不续期**。

| 模式 | 未降级 | 降级期内 |
| --- | --- | --- |
| `custom`（默认） | 网关提示词替换客户端 system | 不变（指纹本来已被替换） |
| `append` | 在开头 system/developer 块之后追加 | **换极简中性提示词并退化为替换** |
| `passthrough` | 原样透传 | **换极简中性提示词** |

触发点两处（判定在 transport crate）：同步 `execution_runtime/sync/execution.rs` 的
`status_code >= 400` 分支、流式 `record_stream_sync_failure`；只有本 provider 的计划
（内部标记头）+ 命中面板那三个审核 marker 才触发。

**与面板的差异（已核实，勿照旧版本）**：面板在**同一个请求内**换降级提示词重试一次。
Aether 的对应物是「**默认就会为 4xx 换号重试**」——`retry_client_errors_by_default` 对
`openai:chat` 为真（`api_format_defaults_to_client_error_failover`，只有 `openai:search`
例外），而 400 内容拦截不落在任何 stop 规则里 → 分类为 `RetryUpstreamFailure` →
`NextCandidate` 重试；**降级闸门在第一次失败时就已置位**，所以重试那一跳的出站 system
已经是中性提示词 → 等价于面板的「同请求内救援」。**前提是还有下一个候选**（单账号池
则仍会把这个 400 透传给客户端）。

> 这里曾写过一条**错误**建议：让端点配 `routing_rules.success_failover_patterns`
> （`status_codes: [400, 403]`）。`success_failover_patterns` 只在 HTTP **200** 时参与判定
> （`classify_local_failover` 里有 `status_code == 200` 守卫），配 4xx 永远不会生效。
> 正确的旋钮是下面那条 `failover_rules.error_stop_patterns`。

**provider config 默认值**（**已由模板自动下发**，无需手工配）：建供应商时
`apply_fixed_provider_default_config` 会把下面这条补进 provider config——**只补操作者没
显式给的键**（显式配置永远优先）。定义在 transport 的
`fixed_provider_default_provider_config`（provider 级没有模板字段，用按类型查表，与
`fixed_provider_template` 同一形态），正则常量是
`WORKBUDDY_REQUEST_LEVEL_ERROR_STOP_PATTERN`：

```json
{
  "failover_rules": {
    "error_stop_patterns": [{
      "pattern": "Unmarshal chat params failed|\"code\"\\s*:\\s*\"?11101|prompt is too long|\"code\"\\s*:\\s*\"?11115|invalid image_url content|invalid_image_data|replace the image|\"code\"\\s*:\\s*\"?11135",
      "status_codes": [400]
    }]
  }
}
```

两个测试盯着它：transport 侧 `fixed_provider_default_provider_config_only_covers_workbuddy`
（形状 + 只覆盖 workbuddy）、网关侧
`workbuddy_recommended_failover_rules_stop_rotation_for_request_level_errors`
（**直接取这个默认值**跑分类：请求级 → 停、内容拦截 → 仍可重试）与
`fixed_provider_defaults_fill_missing_keys_without_overriding_explicit_config`
（显式配置优先）。注意它必须放在 **provider** config 的 `failover_rules` 下——策略只读
`transport.provider.config.failover_rules`，端点级 config 读不到。

### 2.4 上游失败分类与凭证作废

`workbuddy/failure.rs` 照面板 `Classify` 的**顺序**实现 13 类（顺序本身就是语义）：

| 分类 | 触发 | Aether 侧含义 |
| --- | --- | --- |
| `model_blocked` | 400/404 + 结构化 code `11102` 或 `service info not found` | 该后端无此模型 → **按 (账号, 模型) 记负缓存**（见下） |
| `hard_credit` | 402；或 429 + `14018`；或余额文案 | 余额/积分耗尽 |
| `session_dead` | `12153` / `Offline user session not found` | **作废凭证强制刷新** |
| `account_fault` | `request illegal`(11140) / `14017` | **需重新登录** |
| `soft_rate` | 429（非 14018）；或限流文案 | 软限流 |
| `prompt_too_long` / `image_invalid` / `bad_params` | 11115 / 11135 / 11101 与文案 | 请求级错误：**不罚号不轮转** |
| `waf_block` | 403 且**无**业务信封（`"code":`/`"msg":` 都没有） | 边缘层拦截，不是账号问题 |
| `content_blocked` | 审核文案 | 走 §2.3 降级 |
| `not_found` / `server` / `client` | 404 / 5xx / 其它 4xx | 通用语义 |

顺序敏感处：429+余额文案按限流（否则白扔号 12h）；429+14018 按欠费；账号级终态先于 429；
403 无信封按 WAF；`11102` 只比结构化字段（`requestId` 里撞上不算）。

**已接线效果**（两处，均靠内部标记头认 provider，判定在 transport crate）：

1. `resolve_local_oauth_invalid_reason` 的 `"workbuddy"` 分支：只有 `session_dead` /
   `account_fault` 作废凭证（`[OAUTH_EXPIRED]` → 强制刷新；刷不回来就换号）。
   传的是**原始响应体**——`12153` 藏在 JSON 的 `code` 字段里，只看抽取后的 `msg` 会漏判。
2. `pool_score_hard_state_for_plan`：`hard_credit` → `QuotaExhausted`（429+14018 原先被当
   软限流）；`waf_block` → `Cooldown`（原先 403 一律 `AuthInvalid`，把被 WAF 拦的健康号标死）；
   请求级错误与内容误报 → **不罚号**（通用映射看到 body 里的 `blocked` 会判 `Banned`，
   而 `blocked by security policy` 恰好命中）；`model_blocked` → **不碰账号硬状态**（见下一条）。
3. **`11102` 的「账号×模型」负缓存**（`orchestration/workbuddy_model_breaker.rs` 写 +
   池适配器 `WorkbuddyProviderPoolAdapter::quota_hard_blocked` 读）：
   上游的 `11102`（该后端无此模型）是**确定性**答复——同一个 (账号, 模型) 再试结果不变，
   但账号对别的模型完全正常，所以只排除这一格：

   - **写**：失败路径（`record_pool_error_effect`，刻意放在池化判定**之前**，不因该供应商
     没开高级号池而失效）把 `upstream_metadata.workbuddy.model_blocked.<模型>` 记成
     `{until_unix_secs, hits, reason:"11102 model not available"}`；退避照面板
     `pool.BlockModelBackoff`：**6h 起、每再失败一次翻倍、封顶 24h**；到点自动失效，
     下次允许再试（半开探测）。
     同步与**流式**失败路径都会记（workbuddy 强制流式，真实流量走后者——有专门的测试
     `workbuddy_model_blocked_cache_is_recorded_from_the_stream_failure_path`）。
   - **模型名取哪个**：用**出站 body 里的 `model`**（那正是上游看到的、也是调度器
     `candidate.selected_provider_model_name` 读到的名字），而不是 `plan.model_name`——
     后者是**客户端请求**的模型，chat 路径填的是 `input.requested_model`，可能带 `-high`
     之类的指令后缀，用错就永远命不中缓存（这是实现时自查抓到的真 bug）。
   - **读**：调度器评估候选时本来就会问 `admin_pool_key_model_quota_hard_blocked` →
     池适配器的 `quota_hard_blocked`——**所以这条链路不需要改调度器**。
   - 效果：该账号不会被反复路由到它不支持的模型，而**账号本身照常服务其它模型**
     （不误杀）；有可执行文档测试
     `workbuddy_model_blocked_cache_is_recorded_and_scoped_to_the_model` 钉住。

### 2.5 余额/额度刷新（含定时自检）

> **统一拆信封（真机修复，2026-10-15）**：面板的 `doJSON` 在 `code == 0` 时**统一返回
> `env.Data`**，所以面板里所有解析器（余额 / 签到 / 连登 / 成长任务 / 旅行 / trial / 上报）
> 拿到的都是**已拆包**的形状。Aether 侧原本把**带信封的原始 body** 直接交给解析器 →
> 真机表现为「上游 200 但解析不出任何字段」：余额响应实际是
> `{"code":0,"msg":"OK","data":{"Response":{"Data":{"Accounts":[…]}}}}`，而解析器按面板
> 口径找的是 `Response.Data.Accounts`（即 `data` 那层**之内**）。
> **修复位置**：`execute_workbuddy_specs` 的**唯一执行出口**——对 **2xx 且 `code == 0`** 的
> 响应拆 `data`；**错误响应保留信封**（错误码在信封层，失败分类要用它）。
> 另外 `parse_workbuddy_balance_response` 自带一层容错（新旧两种嵌套都吃），并用
> **真机响应原文**加了单测钉住。
>
> 真机实测结果（同一账号）：`credits_limit=4500`、`credits_remaining=3090`、
> `credits_used=1410`、`packages=22 个`（含「个人体验版 / 拉新权益包 / 运营裂变包」等）。

> **瞬时错误有界重试（已做，2026-10）**：面板 `retryBillingTransient` 对**低频维护调用**
> （签到 / 余额 / 上报 / 成长 / 任务）遇**瞬时错误**最多补打 2 次、间隔 **2s / 4s**。
> 判定同面板 `isTransientBillingErr`：只有 **5xx**（实测偶发 `code 10000 / status 500`）
> 与**传输层失败**重试；**4xx / 业务错误 / 限流一律不重试**（面板原话：重试只会原样再失败
> 一次）。chat 热路径**不走**这条（它有自己的换号轮转语义，重试会放大在途请求）。
> 实现位置：`execute_workbuddy_specs`（所有 workbuddy 维护类请求的唯一出口）；
> 传输失败靠固定文案 `Provider quota request failed` 与「origin 被拦」等**不该重试**的
> Failure 区分，有单测钉住。

| 账号 | 端点（**计费域**：CN `www.codebuddy.cn`、国际 `www.workbuddy.ai`） | 响应 |
| --- | --- | --- |
| 个人 | `/v2/billing/meter/get-user-resource`（国际域首选无 `/v2`） | `Response.Data.Accounts[]`：`CycleCapacityRemain/CycleCapacitySize`（周期口径优先，缺失退回总量口径） |
| 企业 | `/v2/billing/meter/get-enterprise-user-usage` | `{credit, limitNum, cycleEndTime}`——`credit` 是**已用**，`limitNum < 0` = 不限量 |

> 域必须用 `workbuddy_billing_base_url(realm)`，**不能**用端点的 `base_url`
> （那是对话域 `copilot.tencent.com`，面板的计费端点在另一个域，见 §2.7 的修正说明）。

个人口径请求体带分页 + **CST 墙钟**的套餐到期时间范围（`ProductCode: p_tcaca`、`Status: [0,3]`）；
计费域头族与对话域一致（Bearer + 指纹头 + `X-Enterprise-Id` / `X-Tenant-Id` / `X-Domain`），
因此请求头直接复用 transport 的头注入，不另写一套。

四层实现：池适配（能力 + 请求构造）→ 纯解析（`parse_workbuddy_balance_response`，归一成
`credits_used/limit/remaining/unlimited/expires_at`）→ 编排（取账号 → 发请求 → 解析 → 落 key；
查询撞上账号级终态时按 §2.4 作废凭证）→ 快照（**计数值窗口**，重置时刻取 `expires_at`）。

**定时从哪来**：注册进 `ProviderPoolService::with_builtin_adapters()` 后
`provider_type_supports_quota_refresh("workbuddy")` 为真，于是「刷新额度」入口与
`maintenance/runtime/account_self_check.rs` 的**定时账号自检**都会走这条链路。

已知取舍：额度快照对 `quota` 是白名单投影，`unlimited` / 套餐明细不进快照（留在
`upstream_metadata` 的 `workbuddy` 桶里）；「不限量」由「没有上限 → 不判 exhausted」表达。

**路径候选与 404 回退**：`/billing/meter` 族在国际域有新旧两条路径（无 `/v2` 前缀优先），
由 `workbuddy_billing_path_candidates(endpoint, realm)` 给出候选序列，调用方
（`execute_workbuddy_billing_specs`）**只有 404 才换下一条**——其他错误（参数错 / 限流 /
风控 / 5xx）换路径只会原样再失败一次，还把同一账号的请求量翻倍。CN 单路径；
企业额度与 `/v2/report` 在面板里走的是单路径 `billingJSON`，**不回退**。

> **必须同时在 origin 白名单里放行这些域**：`execute_provider_quota_plan` 有一张
> per-provider 的 host 白名单（`provider_quota_url_has_allowed_origin`），workbuddy 需要
> 计费域（`www.codebuddy.cn` / `www.workbuddy.ai`）**与对话域**（`copilot.tencent.com`，
> 成长中心走它）。漏了任何一条，对应请求**在入口就被拒**（日志
> `gateway provider quota request blocked by origin policy`，后台只看到
> 「余额查询请求执行失败」）——这正是本项目踩过的坑：编译与单测都过，真机才暴露。
> 官网域（`www.workbuddy.cn`）目前没有用到的端点，**故意不放行**，避免白名单过宽。

**量在号池页怎么显示**：`frontend/src/features/pool/utils/workbuddyQuota.ts` 把
`upstream_metadata.workbuddy` 的 `credits_remaining / credits_limit`、`packages`、
`expires_at` 投影成「余额 X / Y · N 个资源包」+ 进度条（到期时间按 CST 渲染）。

> ⚠️ **新增有额度的供应商要改一处常量**：号池页「配额」整列与「刷新额度」按钮的名单
> 收在 `frontend/src/features/pool/utils/quotaProviderTypes.ts`（`ACCOUNT_QUOTA_PROVIDER_TYPES`
> / `QUOTA_REFRESH_PROVIDER_TYPES`），由 `__tests__/quotaProviderTypes.spec.ts` 钉住内容，
> 漏了会**测试红**。这是踩过的坑 ✗：workbuddy 的额度视图和进度条都做好了，但名单里没有它，
> 整列不渲染 → 界面上什么都看不到（数据其实一直在，接口实测有 `credits_limit`）。
> 判据来自后端 `ProviderPoolService::supports_quota_refresh(<provider_type>)`，前端这份是副本。

### 2.6 每日签到

`POST /v2/billing/meter/daily-checkin`（国际域首选无 `/v2` 的 `/billing/meter/daily-checkin`），
**空 body `{}`**，计费域头族与余额查询完全一致。

分类 `classify_workbuddy_checkin_outcome`（面板 `IsAlreadyCheckin` + `auth.go` 的实测口径）：

| 结果 | 触发 | 处理 |
| --- | --- | --- |
| `checked_in` | 2xx 且业务码为 0/缺省 | 正常 |
| `already_checked_in` | 正文含「已签到」/`already`（上游重复签到是 `code != 0`） | **算非失败**（幂等） |
| `not_supported` | 正文含「企业账号不支持」一类文案 | **算非失败**；企业号根本不该调用 |
| `failed` | 其余（401、5xx、未知业务码） | 记为失败，但**不中断余额刷新** |

两个刻意的取舍：

1. **企业号跳过签到**：上游对 `enterpriseId` 非空的账号恒返回
   `400 code 10001 企业账号不支持该操作`（面板 `auth.go` 实测；企业号也没有成长体系，
   growth 端点一律 403）——发了只是每天白撞一次风控，所以调用方按
   `identity.enterprise_id` 直接跳过。
2. `code 10001` **不能单独用来判定**：个人号「今天已签到」与企业号「不支持」共用这个码，
   只能靠文案区分，因此判定顺序是「不支持文案 → 已签到文案 → 2xx 业务码 0」。

**接线位置**：`handlers/admin/provider/oauth/quota/workbuddy.rs` 的账号循环里，
**签到先做、余额后做**（面板 `accountCheckin` 的顺序），签到结果单独一栏
`checkin`（企业号是 `null`；签到任何结果都不改余额刷新的 `status`）。因为余额刷新被三处调用
（手动「刷新额度」、定时额度探针 `pool_quota_probe.rs`、定时账号自检 `account_self_check.rs`），
**签到随之自动定时化**——这就是本 provider 的「每日签到」。

> 与面板的差异：面板把「单号签到」(`accountCheckin`) 与「单号余额」(`accountBalance`)
> 分成两个入口，我们的余额刷新总会顺带签到一次（幂等，最多每天真正生效一次）。

**global 专属：trial 加油包**（面板 `trial.go`）：`POST {计费域}/billing/ide/trial`，
**无 body**，**只有 global 账号有**（CN 无此端点）。面板注释写明这是 global **唯一天然的
积分增益动作**——global 没有签到、没有任务中心（PLAN D4），所以这条对国际号是刚需。
**幂等码 `14051` = 已领取过 → 视为正常，不是失败**（面板按两种文案指纹匹配
`code=14051` / `"code":14051`；Aether 手上是原始正文，先按 JSON 读 `code == 14051`，
再退回文案匹配，容忍 JSON 空白）。结果记在 payload 的 `trial`
（`claimed` / `already_claimed` / `failed` / `null`=本次没跑即非 global 号）。

### 2.7 保活与活跃上报

**保活（token 刷新）不需要新代码**：设备授权落库的就是 `auth_type = "oauth"` 的 Bearer 会话，
而 `provider_uses_bearer_oauth_runtime` 含 `workbuddy`（`provider_key_auth.rs`）→
workbuddy 账号天然是 **oauth-managed 可刷新**，于是定时任务
`maintenance/runtime/oauth_token_refresh.rs` 会把它们算作候选（临近过期或曾刷新失败时刷新），
本地刷新走 §2.9 的适配器。这条链路由 `recognizes_workbuddy_oauth_as_refreshable_bearer_runtime`
测试钉住——`provider_uses_bearer_oauth_runtime` 一旦漏掉本类型，workbuddy 会**静默退出保活**。
（没有刷新令牌、只导入了 `accessToken` 的账号不作候选，避免空刷。）

**活跃上报**（`POST /v2/report`，**计费域**）：body 是**长度为 1 的 `chat_request_send` 事件数组**，
必须**全字段**（照抄客户端事件形状，防上游加严；最小三字段会被判无效），`userId` 必填——
缺了上游 **200 但静默丢弃**（所以 uid 为空时我们直接跳过，不发无效请求）。

- 触发时机：**当日首次签到成功之后**（签到本身就是账号的「今天」闸门，天然每天最多一次；
  重复签到 `already_checked_in` 时不再补报，符合面板「每号每天 1 次即可」的口径）。
- **企业号跳过**：`/v2/report` 对它们虽然返回 200，但唯一作用是点亮 growth 连登/领养前置，
  而 growth 体系对企业号一律 403——**静默无效**的零收益动作，面板也显式跳过。
- 国际号**照常上报**（面板实测国际版 `/v2/report` 可用，跳过会让国际号永远点不亮连登）。
- 结果记在结果 payload 的 `activity_reported`（`null` = 未上报：企业号 / 今天已签到 / 无 uid）。

> **本轮修掉的一个真实缺陷**：第 8/10 轮的余额与签到请求用的是**端点的 base**
> （对话域 `copilot.tencent.com`），而面板这三个计费端点走的是**另一个域**
> （CN `www.codebuddy.cn`、国际 `www.workbuddy.ai`，面板 `billingBase()`）。
> 现已改为 `workbuddy_billing_base_url(realm)`，对话域仍用于 `/v2/chat/completions`
> 与 `/v3/config`（后者在面板里也是 `chatBase`）。

### 2.8 成长中心：连登兑换 + 抽奖

**域**：`/activity/growth/*` 走**对话域**（面板 `growthJSON` 用 `chatBase`；`streak.go` 顶部
注释写的 `www.workbuddy.cn` 与实现不符，以 `growthJSON` 为准），头族与计费域相同。

| 端点 | 方法 | 域 | 作用 |
| --- | --- | --- | --- |
| `/activity/growth/streak` | GET | 对话 | 连登状态：连续天数、补签卡余额、三档状态与奖励（credit/energy/卡/抽奖次数） |
| `/activity/growth/redeem` | POST | 对话 | 兑换档位，body `{"tier":"7d","client_token":"<uuid>"}` |
| `/activity/growth/lottery/summary` | GET | 对话 | 当前抽奖次数 |
| `/activity/growth/lottery/draw` | POST | 对话 | 抽奖一次，body `{"client_token":"<uuid>"}` |
| `/activity/growth/heatmap` | GET | 对话 | 签到热力图（判断昨日是否漏签） |
| `/activity/growth/makeup-cards/use` | POST | 对话 | 补签，body `{"target_date":"YYYY-MM-DD"}` |
| `/billing/meter/claim-gift` | POST | 计费 | 新手礼包（**无 `/v2` 前缀**，与 get-user-resource 那族不同，面板如此） |
| `/billing/meter/claim-compensation` | POST | 计费 | 活动补偿（同样无 `/v2` 前缀） |

`client_token` 是前端同款幂等令牌（UUID v4）；补签的 `target_date` 是 **CST 自然日**的
「昨天」（上游每日重置按 CST 00:00，用宿主机时区会补错日子）。

**闭环**（面板 `RunStreakBonusNow` 的顺序）：读状态 → **补签保连登**（昨日漏签**且**有
补签卡才补；补签后**重读一次状态**，因为连登天数变了、档位可能刚解锁）→ 新手礼包 →
活动补偿 → **只兑换状态既非 `locked` 也非 `claimed` 的档位**（不拿 403 当控制流）→
读抽奖次数 → 抽完。抽奖有**每次跑的上限**（20 次）：面板无上限，但一次跑几十次对风控不友好，
也给维护任务加了时间上界，剩余次数下一轮再抽（幂等）。

**门控**（面板同口径，两条都是「零收益」判断）：

- **企业号跳过**：无成长体系，`/activity/growth/*` 上游一律 403（连登/旅行/夜猫子同样被拒）；
- **国际号跳过**：面板 D4 门控——global 没有 CN 任务体系（**活跃上报是例外**，那个照发）。

**触发时机**：与活跃上报共用「当日首次签到成功」这个闸门（面板也是在签到排程末尾跑），
因此天然每天最多一次。结果记在 payload 的 `streak_bonus`（`null` = 本次没跑；
`{"status":"unavailable"}` = 上游说没有成长体系；摘要里含 `makeup_used` / `makeup_target_date` /
`gift_credit` / `compensation_credit` / `redeemed_tiers` / `lottery_chances` / `lottery_draws`）。

**已做（v15）**：夜猫子对话（`blackcat.go`）——23:00–08:00 窗口内按缺口发 glm-5.2 真实对话；
窗口外不发请求（发了也不计分）。它是本 provider 唯一会消耗额度的奖励动作，接在同一套防重复闸之后。

### 2.9 成长任务（报名 + 领奖）

面板 `tasks.go` + `panel/taskcenter.go` 的闭环，全部在**对话域**（成长域）与**官网域**：

| 端点 | 域 | 方法 | 作用 |
| --- | --- | --- | --- |
| `/v2/activity/growth/tasks` | 对话 | GET | 任务列表（`progress` 支持 `{current,target}` 与平铺两种形态） |
| `/v2/activity/growth/tasks/accept` | 对话 | POST | 批量报名，body `{"task_codes":[…]}`（幂等） |
| `/activity/growth/tasks/{code}/claim` | **官网** | POST | 领奖：task_code 在**路径**里、**无 body**、`x-client-platform: web` |
| `/activity/growth/tasks/{code}/claim` | 对话 | POST | 小程序口径领奖（+ `x-client-platform: miniprogram`），400 时降级官网域 |

**流程**（每号每天一趟，与连登/旅行共用「当日首次签到成功」闸门）：
① 拉**默认口径 + 小程序口径**两份列表（mp 是默认的超集，按 `task_code` 去重，默认优先）；
② 批量报名：`!claimed && !locked && accept_status ∉ {accepted, completed}` 的任务，
**按口径分组提交**（mp 限定任务缺 `x-client-platform: miniprogram` 头会返回 task not found）；
③ 领奖：只领 `claimable`（进度达标且未领取）的，普通任务走官网域、mp 码走对话域 mp 端点
（400 降级官网域），**每轮上限 20 个**（给维护任务加时间上界，剩余下轮再领，幂等）。
结果记在 payload 的 `tasks`（`listed` / `pending` / `accepted` / `claimable` / `claimed` / `credits`）。

> **两个踩过的坑（面板注释原话）**：
> ① CLI 域的 `/v2/activity/growth/tasks/reward/claim`（task_code 放 body）**这条路径不存在**，
> 一直返回 400「task not completed」——这就是面板早期领奖失败的真实原因，正确端点在官网域。
> ② 因此 **origin 白名单必须放行 `www.workbuddy.cn`**（§1.2 提到过：漏一条就是入口 403）。

**任务表 UI 的数据源**：payload 里另带 `tasks_detail[]`——**面板 `upstream.Task` 的全字段口径**
（`task_code` / `title` / `description` / `task_desc` / `reward_credit` / `reward_energy` /
`has_reward` / `reward_buddy` / `jump_url` / `task_type` / `tag` / `current` / `target` /
`locked` / `claimable` / `claimed` / `accept_status` / `status`），由额度刷新流程写进
`upstream_metadata.workbuddy.maintenance`，账号卡片上的「任务中心」直接渲染（按
**可领取 / 进行中 / 已领取 / 未解锁** 分组，还原腾讯任务中心的视图）。
`task_type == "single"` 标记**一次性任务**——这是后续「桌面事件模拟**绝不重发**」的判据之一。

> **目录与动作分开**（真机踩到的坑）：报名/领奖是**动作**，必须守「当日首签」闸门（面板口径）；
> 但任务**目录**是只读数据，只在闸门内抓会造成真实的生产问题——**用户自己的客户端先把今天的
> 签到了，网关就永远看不到 `first_checkin_today`，任务表会一直空着**。所以目录允许在
> 「本地没有目录 / 超过 24h」时单独补一次**只读** GET（`fetch_workbuddy_tasks_catalog`，
> 只发两条列表请求，不报名不领奖）。已抓到的目录另存 `tasks_fetched_at` 作为新鲜度依据。
>
> 另一个坑：上游 metadata 是**命名空间内浅合并**（`merge_upstream_metadata`），所以在
> maintenance 这个**嵌套对象**上写新值时，必须**继承**上一份的 `tasks` / `tasks_detail` /
> `tasks_fetched_at`——否则每次非首签刷新都会把任务表抹掉（UI 表现为「任务中心突然变空」）。

**未做**：开学季限时活动（`school.go`，活动期 2026-09-13~09-24 已过；其中 `share-complete`
与转盘抽奖是纯 API，但价值随时间归零）。

### 2.10 猫猫旅行

全部在**对话域**（面板 `travel.go` 顶部即写明「全部走 chatBase + BillingHeaders」）：

| 端点 | 方法 | 作用 |
| --- | --- | --- |
| `/activity/growth/buddy/info` | GET | 猫档案（`buddy` 为 `null` = 无猫） |
| `/activity/growth/buddy/travel/status` | GET | 旅行状态：`state`(idle/traveling/arrived)、`daily_limit_reached`、`record_id`、`reward_credit` |
| `/activity/growth/buddy/travel/depart` | POST | 派出，body `{"location_id":4}` |
| `/activity/growth/buddy/travel/claim` | POST | 到站领奖，body `{"record_id":N}` |
| `/activity/growth/buddy/agreement` | POST | 同意领养协议，body `{"agree":true}`（幂等） |
| `/activity/growth/buddy/first` | POST | 领养第一只猫，body `{}`（+300 积分） |

**状态机**（`decide_workbuddy_travel_action`，纯函数、单测覆盖）：无猫 → 领养；`arrived` →
领奖；`idle` 且未达当日上限 → 派出；`traveling` / 已达上限 / 状态未知 → 跳过。
两处「宁可不做」的判断：**到站但 `record_id == 0` 不领**（领奖必须带记录 id）、
**今日已派出不重复派**（每日 1 次，CST 00:00 重置）。地点固定 4：四个地点收益/时长区间
完全相同，没有最优解。

**领养链路**（面板 `travelAdopt`）：先发一条 `chat_request_send` 上报解锁 `first_buddy`
（**未上报时 `buddy/first` 会 400「first_buddy task not completed yet」**——门槛的真实来源是
「当日无活跃上报」，不是账号问题）→ **等 1.05s** 给上游处理事件 → `agreement` → `first`。
门槛未达属预期：记 `first_buddy_incomplete` 收工，当天不再重试。

**触发时机**：与连登/活跃上报共用「当日首次签到成功」闸门（面板另有 `travel_hours` 排程，
这里复用签到闸门，一天一趟）。一趟**只做一个动作、不轮询不等待**——派出的次日状态自然
变成 `arrived`，跨天由下一次巡检推进。结果记在 payload 的 `travel`。

**与面板的差异**：面板在账号间限速 800ms；Aether 的刷新循环本身顺序执行但**没有额外限速**，
账号很多时巡检会比面板更密集（需要的话可在端点/供应商配置里加节流）。

**已做（v15）**：夜猫子（`blackcat.go`）——**只在 23:00–08:00（CST）窗口内**按缺口发
glm-5.2 短对话 + 事件上报；**窗口外一个请求都不发**（发了也不计分，纯浪费）。它是本 provider
唯一会消耗额度来换任务奖励的动作，所以接在**同一套防重复闸**之后（`desktop_ran_on` 日戳 +
每任务 `due` 判断 + `desktop_sent` 水位）——已领取的一次性任务不会触发它。

### 2.13 桌面端行为事件（`desktop.go` 的纯事件子集）

「需电脑端」类成长任务点亮的**不是独立端点**，而是同一 `POST {chatBase}/v2/report`
通道上的**另一套客户端指纹**（面板结论原话）。Aether 侧实现分两层：

| 层 | 文件 | 内容 |
| --- | --- | --- |
| 构造器 | `crates/aether-provider/transport/src/workbuddy/desktop.rs` | 指纹（`workbuddy_desktop_fingerprint`）、`deriveID`（`hex(sha256(salt+":"+uid))[:36]` ✓ 逐字节对齐）、chat 六事件链、五连 Buddy、模板/灵感/画布、专家召唤+使用、主题生效事件、Web 浏览器指纹事件 |
| 请求 | `crates/aether-provider/pool/src/providers/workbuddy.rs` | 桌面上报（桌面 UA + `X-Product: SaaS`）、Web 上报（浏览器 UA + `x-client-platform: web`）、`appearance/set`、专家市场列表 |
| 编排 | `apps/aether-gateway/.../quota/workbuddy.rs` | `execute_workbuddy_desktop_actions`：9 个纯事件动作 + 防重复守卫 |

**已覆盖的动作**（纯事件、**不消耗积分**）：`RichMeow_Chat`、`Buddy_App`、`Buddy_App_QQ`、
`automation_1`、`Library_read`、`template_5`、`playbook_prompt`、`create_canvas`、`Hp_Appearance`
（主题任务必须 **`appearance/set` API + `appearance_skin_apply` 事件组合**才计分——面板早期
「纯 API set 不计分」的结论不准确）。

**防重复三道闸**（用户明确要求「做过的一次性任务别重复做，因为有些需要发请求」）：

1. `claimed`（一次性任务终态）→ 跳过；
2. `target > 0 && current >= target`（进度已满）→ 跳过；
3. 本地水位 `maintenance.desktop_sent[]` 命中该 `task_code` → 跳过
   （上游进度回写有延迟，只靠状态可能重发）。

三条都收敛在纯函数 `workbuddy_desktop_action_due` 上（有单测），**守卫不过就连请求都不构造**。
再加一道每日戳 `maintenance.desktop_ran_on`：整个阶段每天最多一轮——**刻意不依赖「当日首签」**
（用户自己的客户端可能先签到，网关就永远看不到 `first_checkin_today`，那些任务一辈子点不亮）。

真机首跑（2026-10-15，`v10`）：`desktop_ran_on = 2026-10-15`、8 个动作**全部 skipped**、
`desktop_sent` **为空**——即**一个请求都没发**（该账号的一次性任务早已全部领取）。

**已做（v15，Tier 2）**：需要**真实对话**才能点亮的那几个——`skill_1`、`expert_5`、
`Expert_team_use_3`、`Expert_lighthouse`、`black_cat`（夜猫子）。硬约束是 **`requestId` 必须是
服务端返回的**（自造 UUID 不计数，面板 Sunny row 2113 实证），所以每个动作先发一次**流式对话**、
从 SSE 里取服务端 id，再发 JOIN 事件；**取不到 id 就不发**（发了也不计数，纯浪费请求）。
细节按面板抓包对齐：

| 动作 | 事件链（v15） |
| --- | --- |
| `skill_1` | 真实对话（把 `chat_message_response` 标成 `finishReason: tool_calls`）+ `skill_info`：技能名 / `skillId` / `skillVersion` / `toolStatus:"success"` / `source:"workbuddy-desktop"`，且 `conversationId`/`requestId`/`traceId` 三项都用**服务端那条**（面板 row 209 判据） |
| `Expert_lighthouse` | 市场列表命中轻量云专家（`ex_2cvvUZQhDyeJ`，命中就用服务端权威名称/版本）→ 召唤链 → 真实对话 → `expert_actual_use`（**`mode=LOCAL` / `type` 空 / `cost=0`**，对齐 Sunny row 868） |
| `expert_5` / `Expert_team_use_3` | 按缺口取市场里**真实存在**的专家（编造 id 不计数）→ 每位走「召唤链 → 真实对话 → `expert_actual_use(mode=craft, type=expert-all, cost=9000)`」 |
| `black_cat`（夜猫子） | 仅 23:00–08:00 窗口内、按缺口发 glm-5.2 真实对话 |

接线与 Tier-1 共用同一套防重复闸；每日维护每账号最多一轮（`desktop_ran_on`），
所以「任务早已全部领取」的账号**本轮实际发出 0 个请求**（与 Tier-1 首跑实测一致）。

### 2.11 模型目录拉取

`GET /v3/config`，策略 `ModelFetchStrategyKind::Workbuddy`：

- 计划构造（`aether-model-fetch/src/transport.rs`）：**先注入对话域头族、再覆盖本端点专属值**
  ——顺序不能反，注入是 `set`，而本端点要的是 IDE 形态 UA + `X-Product: SaaS`
  （UA 不对上游直接 `400 code=12403`），并移除对话域的 `x-agent-purpose`；
- 令牌解析走 provider 自己的 `resolve_workbuddy_access_token`（key 是 `oauth` 类型，
  通用 OpenAI bearer 解析器只认 `api_key`/`bearer`）——与本地刷新适配器同一事实来源；
- 解析（`logic.rs::parse_workbuddy_v3_config_response`）：`code != 0` 视为失败（绝不把错误
  信封当空目录清空模型）；目录为空同样失败；**试用横幅**
  （`data.productFeaturesConfig.ModelTrialBanner.banners[]`）里的模型只出现在横幅里但
  实际可调用 → 补齐，能力从 `targetModelId` 继承，`credits`/`tags` 不继承；
- **非对话模型过滤**：id 前缀 `nes-`/`completion-`/`codewise-`、`maxOutputTokens ∈ (0,256]`、
  tags 带 `text-to-image`/`image-to-image`/`text-to-video`/`image-to-video` 的条目
  **不进对话模型列表**（它们不能用 `openai:chat` 调用，列出来只会让用户选中后失败）；
  试用横幅同样过滤；
- **global 侧两路探测**（CN 单路，面板同口径）：面板实测该端点**对 UA 敏感**——IDE UA 与
  CLI UA 下发的模型集合**不同**（「两路各有独有模型，缺一不可」），所以 global 账号会用
  `build_workbuddy_v3_config_execution_plan_with_user_agent` 各探一次，**按 id 合并、主路
  （IDE）优先**；**第二路失败不影响主路结果**（面板同款「两路独立容错」）。

### 2.12 为什么不复用 `GenericOAuthRefreshAdapter`

那条路只认标准 `grant_type=refresh_token` 表单/JSON 授权（`generic.rs:290-415`），
而 WorkBuddy 刷新是**无 body + `X-Refresh-Token` 头 + 官方指纹头族**，表达不了；
因此像 kiro 一样自带 `LocalOAuthRefreshAdapter`。

---

## 3. 使用流程（后台）

1. 新建供应商，类型选 **WorkBuddy**。后端按模板自动建一个 `openai:chat` 端点：
   `base_url = https://copilot.tencent.com/`、`custom_path = /v2/chat/completions`、
   `upstream_stream_policy = force_stream`。
   - 国际账号把 `base_url` 改成 `https://www.workbuddy.ai`：模板会把改动记进 endpoint 的
     `overrides`，reconcile 不会冲回 CN 域。
2. 「账号管理」→ 添加账号 → **设备授权**：弹窗展示授权链接（本 provider 没有设备码），
   浏览器完成登录后弹窗轮询到 `authorized` 并落库成 key。需要国际域时 `login_option` 传 `global`。
   - **单次轮询上游有 20s 预算**（`workbuddy_device_poll_budget`，
     `dispatch/device/workbuddy.rs`）：超预算按 `pending` 回报并记
     `workbuddy device poll did not answer within budget`。这不是优化而是必须——
     出站默认总超时与浏览器侧等待上限同为 30s 量级，两者相等时上游一卡住，
     浏览器先拿到 504、本轮结果被丢弃，界面就会永远停在「等待授权」
     （真机 2026-10-24 事故：25 分钟、每 34s 一次 504 循环）。
3. 或用「导入凭据」粘贴面板的 `auths/workbuddy-<uid>.json`（嵌套形态）或扁平 JSON
   （`accessToken` / `refreshToken` / `expiresAt`（毫秒会归一成秒）/ `domain` / `uid` /
   `enterpriseId` / `nickname`）。
4. 「刷新额度」或等定时自检：余额/额度进后台；「拉取模型」走 `/v3/config`。
5. **CN 与国际号必须拆成两个供应商实例**（真机复现，2026-10-17）：一个供应商只有一个
   **对话端点 base**，而 token 刷新域虽然由账号 `realm` 自动决定，**对话域却跟着端点走**。
   把国际号混挂在 CN 供应商里，请求会打到 `copilot.tencent.com` 并拿到 **401**（日志可见
   `url=https://copilot.tencent.com/v2/chat/completions upstream_status=401`）。所以：

   - 建两个 WorkBuddy 供应商：CN 一个（模板默认 `copilot.tencent.com`）、国际一个
     （`base_url` 改成 `https://www.workbuddy.ai`，改动会记进 endpoint 的 `overrides`）；
   - 各自只挂本域的号；客户端用不同 API key（或用不同模型名）分流到两个供应商；
   - 号池的熔断/冷却/额度/自检**按供应商实例各自独立**，互不影响。

   **界面上的拆分（已内置）**：添加供应商时 WorkBuddy 直接给两个选项 ——
   **「WorkBuddy（国内版）」/「WorkBuddy（国际版）」**，选完自动：

   | 项 | 国内版 | 国际版 |
   | --- | --- | --- |
   | 供应商名字（空着时预填） | `workbuddy-cn` | `workbuddy-global` |
   | `config.workbuddy.realm`（实例级真相） | `cn` | `global` |
   | 对话端点 `base_url` | 模板默认 `copilot.tencent.com` | 自动切 `www.workbuddy.ai` 并记 `overrides` |

   两者在后端仍是同一个 `provider_type=workbuddy`（不新增类型，避免 18 处类型注册漏改）。
   加了实例级 `realm` 后，供应商详情/列表会以窄字段 `workbuddy_realm` 暴露它 ✓，
   前端据此把「添加账号」里的**版本选择整块隐藏** —— 国内实例看不到「国际版」，
   国际实例也看不到「国内版」，从界面这一层就堵住跨域加号。

   > ✅ 已经补上（v50）：**导入凭据**路径也不再只是「人工注意」—— 跨域凭据会被后端直接拒绝，
   > 判定点在**共享漏斗** `create_provider_oauth_catalog_key`（`oauth/provisioning.rs`），
   > 设备授权 / 单条导入 / 批量导入三条路一次覆盖，文案是
   > 「该供应商固定为{cn|global}版，不能添加{...}账号：请到对应区域的供应商实例里添加」。
   > 老实例（没有 `config.workbuddy.realm` 的）不拦，行为与从前一致。

   **国际域没有个人成长体系**：签到 / 活跃上报 / 连登 / 猫猫旅行 / 成长任务 在国际域
   一律被上游拒绝（面板实测 `400 code 10001` / `403 growth system is only available for
   personal users`），所以与企业号并列跳过（`growth_bundle_available`），只保留额度刷新、
   补注册与 trial 加油包；界面把该行显示成「国际版无签到体系」而不是「未签到」。

---

## 4. 与面板的能力差距

> **口径**：对齐范围是「面板（`workbuddy2api-panel`）的 **workbuddy 能力面**」。Aether 本身是
> 更广的多供应商网关，面板没有的能力不在此列。最近一次核对：**2026-10-17**（维护性审计后：差距表
> 5 行「未做」已纠正为「已做」✓、默认值已对齐 `pool_advanced_defaults.rs` ✓、测试条数不再写死 ✓）。

### 4.0 对齐度总览（一页看完）

**已经对齐**（面板的主要能力 Aether 都有）：设备授权 / 刷新 / 导入导出 · 余额 + 签到 +
活跃上报 + 连登兑换 + 补签 + 新手礼包 + 补偿 + trial 加油包 · 猫猫旅行（状态机 + 领养）·
成长任务（双口径去重 → 分组报名 → 领奖） · **桌面事件 9 个动作 + 三道防重复闸** ·
**`6004` 模型级限流（只锁「账号×模型」）** · **模型锁池视图（分域 / 四态 / 该域可选号分母）** ·
**上游目录全字段 + `realm` 分域** · global 两路探测 · 非对话模型过滤 · 保活 ·
额度面板 + 维护徽章 + 任务中心 UI + 模型倍率列。

**缺口清单（§4.0 的 12 项现**已全部消除** ✓，逐项证据见下方「已做」块与各条真机验证）**：

| # | 缺口 | 状态 | 备注 |
| --- | --- | --- | --- |
| 1 | 成本探索窗口（垄断破除） | **已做** v27 | 端到端无真机证据（现网只有 1 个已观测账号）|
| 2 | WAF 403 出口 IP 维度冷却 | **已做** v32 | 激活态无真机证据；比面板更严（新请求也挡 60s）|
| 3 | `error.gateway_hint` | **已做** v30+v31 | 业务码族无真机证据；未知模型也带 hint（刻意近似）|
| 4 | 昵称刷新 | **已做** v29 | 该账号上游 nickname 本身是掩码手机号；UI 标题仍用 key 名 |
| 5 | `context`/输出上限静态兜底 | **已做** v28 | 单看快照分不清值来自上游还是兜底 |
| 6 | global 区域向导 | **已对齐** ⑪ | 面板=CLI 交互式选域；Aether=登录 region 参数，域语义一致 |
| 7 | 开学季活动（`internal/upstream/school.go`） | 范围外 | **活动期已过**（2026-09-13～09-24）✓ |

**已做（v15）**：**Tier-2 五个真实对话动作**（`skill_1` / `expert_5` / `Expert_team_use_3` /
`Expert_lighthouse` / 夜猫子）——先发流式对话取服务端 `requestId`，再发 JOIN 事件；
窗口/缺口/防重复闸都照面板口径（详见 §2.12、§2.13）。

**已做（v16）**：**快过期积分加权 + 优先开关**——面板 `prefer_expiring`（默认 true）+
`expiring_soon`（默认 7 天）的等价物：账号卡片所在的 workbuddy 元数据桶里，
`packages[].expires_at` 落在窗口内**且仍在未来**的剩余积分计入 `expiring_credits`，
选号打分时给这类账号一点**温和加分**（默认 0.10，不是硬优先；面板用 `expiringVirtualSlots = 3`
的虚拟实例权重表达同一意图）。窗口填 0 = 关闭分桶；开关关闭 = 窗口照算但不加分。

**已做（v17）**：**限时优惠 `modelPromotions`**——拉目录时按面板口径算出**当前生效**的优惠
（`enabled` + `validFrom`/`validUntil` + `daily` 时段，**支持跨午夜** 23:00→07:50，时区恒
Asia/Shanghai；同模型多条取 `priority` 最高），落成 `promo_factor` / `promo_credits` /
`promo_label` / `promo_note` 四个字段；**条目 `credits` 仍是牌价**，前端「上游模型能力与倍率」
的倍率列改为「生效价 + 徽章 + **划线牌价**」，hover 显示时段说明。
没有 `discount` 的条目（「错峰使用」类）**不编造** `promo_factor`，只透出徽章 ✓。

**已对齐（⑪）**：**global 区域向导**（本轮对照取证，不新增代码）。
- 面板侧实现位置 = `cmd/login/main.go` ✓ —— 它是 **CLI 工具**，所以「区域向导」就是登录命令行的
  **交互式选域**：`resolveRealmInput` / `promptRealm` ✓（`1`/`cn` → cn ✓、`2`/`global` → global ✓、
  非法输入警告后**回落 cn** ✓、EOF/非交互也回落 cn ✓）；realm 写进 state 文件、`poll` 时
  **校验同域**（防混域 ✓）；`realmConfig(realm)` 按域切上行 base 与 Origin/Referer ✓。
- Aether 侧等价物（**已存在** ✓）：设备授权登录按 **realm 参数**工作 ✓ ——
  `oauth/dispatch/device/workbuddy.rs:58-62` 按域推导 base（`WORKBUDDY_CHAT_BASE_GLOBAL` / `_CN` ✓）、
  `:86-90` 切适配器（`with_global_realm()` ✓）、`:161` 轮询时「region 承载 realm」重建 base 与出站头 ✓；
  文本域 realm 判定与本仓 `workbuddy_identity` 同口径 ✓（显式 `realm == "global"` 优先 → 其次按
  domain 推断 → 空值回落 cn ✓，与面板 `auth.Realm()` 同款 ✓）。
- **结论** ✓：两侧**网关能力面已对齐** ✓（域判定 / 按域端点 / 按域头部 / 防混域 ✓），
  唯一差异是**交互面**（面板 CLI 提示 ✓ vs 管理端登录表单的 region 参数 ✓）。
- ⚠️ **本节初版有个判断错了、已在 v33 更正** ✗：当时写「『注册』本身两侧都**没有**网关代码」 ✗ ——
  事实是面板**有**（`internal/upstream/global_register.go` ✓：补注册地区 → 激活 ✓），
  Aether 当时**没有** ✗ → 已在 **v33** 补齐 ✓（见下方 v33 块 ✓）。
  真正"两侧都没有"的只是**去官网注册账号**这一步 ✓（用户侧动作 ✓）。

**已做（v36–v38）**：**默认值全面对齐面板 + `max_in_flight` + 安全审计修复 + key 名用登录账号名**。

- **v36 · 补齐面板 `max_in_flight`（单账号最大在途，默认 3）** ✓：此前只实现了 global 分档 ✗
  —— 面板其实是**三段式**（`pool.go:260-267`：global 档优先 ✓，其余含国内/未知域回落
  `max_in_flight` ✓，各档 `0` = 不限 ✓）。现在 `workbuddy_in_flight_limit(base, global_tier,
  max_in_flight, metadata)` 与面板逐字对应 ✓，`pool_advanced.max_in_flight` 贯通
  admin 解析 / 调度运行时解析 / UI 旋钮 ✓。
- **v37 · 用户口径「面板默认即默认」** ✓：`breaker_threshold` **3** ✓（原 8）、
  `breaker_cooldown_minutes` **30m** ✓、`breaker_cooldown_max_minutes` **360m=6h** ✓、
  `max_in_flight_global` **2** ✓、`max_in_flight` **3** ✓、
  `pool_counts_toward_circuit_breaker` **true** ✓、`cost_explore_interval_seconds` **1800s** ✓、
  WAF `60s` + 连新请求一起挡 ✓。**显式配置仍可回到历史值** ✓（能力不删 ✓，只是不再是默认 ✓）；
  单测 `parses_breaker_knobs` 按新口径重写 ✓（含「钳到 1 万」✓）。
- **v37 · 安全审计（无 P0）两个 P1 已修** ✓：
  1. **上游原文回流** ✗→✓：响应体**不是 JSON** 时（WAF 的 HTML 拦截页最典型 ✓）
     `workbuddy_readable_message` 不再回显原文 ✓，改用固定文案「上游返回了非 JSON 响应」✓
     —— 否则上游可控文本会落库 `oauth_invalid_reason` 并渲染到后台 ✗。JSON 信封的
     `msg`/`message` 照常透出 ✓（既有行为 ✓）。回归测试构造带假手机号的 HTML 页 ✓，
     断言结果**不含**手机号 ✓。
  2. **在途上限类型陷阱** ✗→✓：配置成荒谬大数会 `i32::try_from` 失败 → 上限**静默变无限** ✗
     （与配置意图相反 ✗）。现在解析层**钳到 1 万** ✓（admin ✓ + 调度运行时 ✓）、转换失败
     **回落账号自身上限** ✓、UI 输入框加 `max="10000"` ✓。
  - 审计**干净**的部分 ✓：新增端点都在管理端鉴权后 ✓、SQL 参数化 ✓、无命令执行 ✓、
    无 SSRF ✓（base 全为编译期常量 ✓、token URL 覆盖仅 `#[cfg(test)]` ✓）、
    `/console/account` 只取昵称+uid ✓（手机号不落库不进 UI ✓）、前端无 `v-html` 渲染用户数据 ✓、
    日志只记 token 长度 ✓。P2 挂账 ✓（`upstream_metadata` 读改写竞态 ✓、余额解析失败时的
     日志回显 ✓）。

**已做（维护性审计整改 2026-10-17）** ✓ —— 独立审计给的结论是「能读、但不好维护」✓，
按推荐顺序处理如下（每步都要求：补丁可应用 ✓ + `cargo fmt --all --check` 通过 ✓ +
相关单测通过 ✓ + 必要时真机验证 ✓）：

1. **默认值单一事实来源** ✓：11 个 `pool_advanced` 默认值收进
   [`aether-pool-core/src/pool_advanced_defaults.rs`](../../../crates/aether-pool-core/src/pool_advanced_defaults.rs) ✓；
   管理端解析的两条路径（对象 / 非对象）与**调度运行时**全部读它 ✓ ——
   运行时原来那份**手写第二份解析已被删除** ✗，改为消费 `admin_provider_pool_config_for_provider` ✓。
   测试：pool-core 2 条 ✓（面板口径 + 内部一致性）、**非对象分支**逐字段同口径 1 条 ✓、
   前端跨边界钉子 2 条 ✓（前端直接读后端文件比对 ✓）。
2. **文档纠错** ✓：差距表 5 行「未做」→「已做」✓、4 行过期默认值 ✓、删掉逐字重复的整段 ✓、
   删掉写死的测试条数（38 行 ✗）✓、补「阅读约定」（`vN` 是作者迭代轮次 ≠ 版本 ✗）✓、
   部署文档的「64 个文件 / 6 项已知未做」纠正 ✓。
3. **拆大文件 / 隔离冲突面** ✓：`model-fetch/logic.rs` 的 WorkBuddy 目录解析拆到
   [`logic/workbuddy.rs`](../../../crates/aether-model-fetch/src/logic/workbuddy.rs)（**615 行** ✓，
   原文件 **3061 → 2202 行** ✓，对外只留一行重导出 ✓，既有测试原地不动 ✓）；
   `effects.rs` 的 WAF 判定段搬进 [`waf_ip.rs`](../../../apps/aether-gateway/src/orchestration/waf_ip.rs) ✓
   （`effects.rs` 只剩一行调用 ✓）。
4. **关键路径测试** ✓：改名决策抽成纯函数 `workbuddy_key_rename_target` ✓（6 组断言 ✓：
   空昵称不动手 ✓ / **用户起过的名字永不覆盖** ✓ / 120 字符截断 ✓）；
   global 注册状态机的分类与国家白名单**本来就有 5 条测试** ✓（`global_register.rs` ✓）。
5. **协议常量单一来源** ✓：权威定义在 `aether-oauth`（下层 ✓，依赖方向本来就是
   `transport → oauth` ✓），transport 改为 `pub use` **重导出并保留原公开名** ✓
   （下游零改动 ✓）；新增钉子测试断言「完整 URL == base + 路径」✓（4 个端点 ✓）。

**有意不做（附证据 ✗）**：
- **裸字符串 `"workbuddy"` 全量替换成 `WORKBUDDY_PROVIDER_TYPE`** ✗：普查发现
  transport/pool 两个 crate 里的 63 处中，**绝大多数是测试夹具**（`sample_transport("workbuddy")`）
  或**元数据命名空间键**（`metadata.get("workbuddy")`）—— 后者与 `provider_type`
  **不是同一个事实** ✗，盲替换会把「命名空间」和「供应商类型」两个概念混为一谈 ✗。
  真要收敛应单独引入 `WORKBUDDY_METADATA_NAMESPACE` ✓（属另一件事，未做）。
- **OAuth dispatch 的 if 链改成注册表** ✗：`start.rs` 里**同形状**的分支早已表化 ✓
  （`DEVICE_AUTH_ONLY_HINTS`）；而 `authorize.rs` / `poll.rs` 的分支各自调用**签名不同**的
  handler（xai 7 参 / workbuddy 8 参带 realm / windsurf 形状又不同 ✗，且都是 `async fn`
  ✗ —— Rust 里没有稳定的 async fn 指针 ✓），表化要么引入 trait + 关联 payload，
  要么把每支包成闭包 ✗ —— 比现在的 if 链**更难读** ✗，故保留（结论已写进 `start.rs` 注释 ✓）。
- `effects.rs` 的 `workbuddy_pool_hard_state` 搬进 `workbuddy_model_breaker.rs`：收益仅是
  少 40 行 ✓，且该函数已被 1 条测试钉住 ✓ —— 低收益，暂不动 ✓。

- **v38 · key 名按登录账号名显示** ✓（用户要求「key 里面的账号名称按登录的账号名称显示」✓）：
  1. **新建即用账号名** ✓：`admin_provider_oauth_key_name_from_auth_config` 加 workbuddy 分支 ✓
     —— 登录第三步上游就给 `{uid, enterpriseId, nickname}` ✓（`aether-oauth` 落 `auth_config.nickname`
     ✓），直接拿它当 key 名 ✓（截断 120 字符 ✓）；**其它供应商不受影响** ✓。
  2. **存量自动改名** ✓：额度刷新（手动）拿到昵称后，若 key 名**仍是系统生成的**
     `账号_<unix秒>[_<序号>]`（纯函数 `workbuddy_system_generated_key_name` 判定 ✓）→
     换成账号名 ✓；**用户手动命名过的 key 一律不动** ✓。走的是与后台「重命名 key」**同一条**
     管理端 CAS 通道 ✓（强读最新版本 ✓ → 并发输 CAS 就静默跳过 ✓ → 改名失败**绝不影响额度刷新** ✓）。

> **v38 真机验证** ✓（2026-10-17，测试机 `<测试机 IP>`）：线上二进制 md5 `b5b82505eafb5fd13f90777a2bd6ddb8` ✓、
> `active` ✓、`/health` 200 ✓。**实测触发一次额度刷新后两个 key 自动改名成功** ✓✓：
> `账号_1791995213` → **`132****1637`** ✓（国内号 ✓）、`账号_1792139031` → **`fanj***@gmail.com`** ✓（国际号 ✓）。
> 面板默认值也已上线 ✓：阈值 3 ✓、基础 30m ✓、上限 360m ✓、国际号并发 2 ✓、单账号在途 3 ✓、
> 池计入熔断 ✓、成本探索 1800s ✓、「忽略额度耗尽」已关 ✓（审计建议 ✓ —— 耗尽号不再被反复派单 ✓）。

**已做（v35）**：**国际号昵称 + WAF 开关 + 目录自动补拉 + 首字节超时 + 前端构建修复**
（用户 2026-10-16「全都做」；生产 154 部署按用户要求**不做** ✗）。
- **① 国际号昵称（真机已通 ✓）**：此前 `fetch_workbuddy_account_nickname` 对国际域**直接 `return None`** ✗
  （「宁缺勿错」的保守做法 ✓），且 Referer 硬编码 CN 域 ✗（跨域 Referer 会被上游当异常请求 ✗）。
  现在：base 按域取（global → `workbuddy.ai` ✓）、**Referer 与 base 同域推导** ✓、去掉 CN-only 守卫 ✓、
  失败**落库原因**（`account.nickname_error` ✓，不再静默吞掉 ✗）。
- **② WAF「更严一档」开关** ✓：新增 `pool_advanced.waf_ip_block_new_requests` ✓
  （**默认 `true` = 现状**，更严一档保留 ✓）；置 `false` 即**完全对齐面板**（只停本次请求的轮转 ✓，
  账号级软冷却仍在 ✓）；`waf_ip_cooldown_seconds = 0` 仍可整项关停 ✓。后台「调度高级设置」里已集中
  **全部**面板对齐旋钮 ✓（v35.1 补齐 UI：熔断阈值/基础时长/退避上限、池计入熔断、积分保底、
  国际号在途上限、成本探索窗口 —— 此前后端能认但 UI 没露 ✗）。
- **③ 网关侧自动补上游目录** ✓：额度刷新时发现该账号**没有**非空 `models` 快照 → 复用管理端
  「查询上游模型」**同一个函数**补拉一次 ✓（幂等 ✓，结果落 `maintenance.catalog_fetched` ✓）。
  与 v34 的前端自动补拉**两层互补** ✓。
- **④ 首字节超时 → 120s** ✓：provider 级 `stream_first_byte_timeout`（未配置默认 30s ✗ →
  长思考模型可能被看门狗掐 ✓）。
- **⑤ 前端标准构建修复** ✓：`sync-vscodex.mjs` 里 `spawnSync('npm.cmd')` 在 Node ≥18.17 的 Windows 上
  必须带 `shell`（CVE-2024-27980 的修复 ✗）→ 加 `shell: process.platform === 'win32'` ✓。
- **⑥ 账号卡片标题用上游昵称** ✓：有可读昵称就用它 ✓，**掩码值（含 `*`）不用** ✗
  （CN 号昵称本身就是 `132****1637` ✗ → 仍显示用户自己的账号名 ✓），账号名进 tooltip ✓。
- **单测** ✓：pool 2 条（国际域 Referer ✓ / 昵称解析 ✓）、gateway 3 条（目录快照判定 ✓ / WAF 开关 ✓）、
  前端 8 条（版本标识 ✓ / 昵称标题 ✓）。

> **v35 真机验证** ✓（2026-10-16，测试机 `<测试机 IP>`）：
> - 部署 ✓：线上二进制 md5 `e1a06954cf3e7c8c181aabc72f8330dc` ✓、dist **246** 文件 ✓、`active` ✓、
>   `/health` 200 ✓、`/` 200 ✓；**新符号 `waf_ip_block_new_requests` 在线上二进制里** ✓。
> - **国际号端到端真跑通一次对话** ✓✓：挑出**只有国际目录有**的模型 `mimo-v2.6-pro` ✓ → 导入 ✓ →
>   `POST /v1/chat/completions` → **HTTP 200，回复「可以」** ✓（usage 541 tokens、credit 0.05 ✓）
>   —— 这条同时补上了「国际号能不能真出话」的空白 ✓。
> - 昵称 ✓（国际号 `fanj***@gmail.com` ✓ / 国内号掩码 `132****1637` ✓）；
>   自动补目录 ✓（清掉快照 → 刷新 → 17 个模型自动回来 ✓ + `{"http":200,"status":"ok"}` ✓）；
>   首字节超时 `(null)` → **120** ✓；`npm run build` 的 prebuild 不再 EINVAL ✓。
> - ⚠️ **⑥ 成本探索仍无真机证据** ✗（这次**尝试过** ✓：打开 `cost_explore_interval_seconds=60` ✓、
>   确有一个 `request_count = 0` 的未观测账号 ✓，但请求仍由国内号服务 ✗）
>   —— 两个账号**分属不同域** ✓，很可能根本不在同一个池里 ✓（域级池），"搭车探索"这个场景
>   用现有账号构造不出来 ✗；该项继续由单测背书 ✓。

**已做（v34·纯前端）**：**账号列表「国内版 / 国际版」标识** + **面板自动补拉账号上游目录**
（用户 2026-10-16 追加）。
- **用户报告的 bug**：导入的国际号在「上游模型能力与倍率」里**一个模型都没有** ✗ → 只看到国内模型 ✓。
  **根因**（直读现网库）：上游目录是**按 key 拉**的 ✓（`aether-model-fetch` 的 workbuddy strategy
  会写 `realm` + `models` ✓，见 `strategy.rs:696-699` ✓）—— 走过**登录流程**的账号顺手带上了目录 ✓，
  而**导入凭据**进来的账号**没人触发** ✗ → `upstream_metadata.workbuddy` 里连 `realm` 都没有 ✗。
  **不是抓不到** ✓：手动调 `POST /api/admin/provider-query/models {force_refresh:true}` 一次即返回
  **34 个模型** ✓，并落库 `realm=global` / `models=18` / `allowed_models_count=18` ✓。
- **修法（纯前端 ✓，不动网关二进制）**：面板打开时，对**没有目录快照**的账号**自动补拉一次** ✓
  （每个 key 只自动试一次 ✓，成功即让父组件重载 ✓）；失败或想重试时，卡片头部的
  「拉取账号目录 N」按钮可手动再拉 ✓；空状态文案同步改成「正在自动拉取」 ✓。
  为什么放前端而不是登录/刷新流程 ✓：现有管理接口本来就是**按 key 拉** ✓（前端早已在用 ✓），
  这样不用重发网关 ✓，且覆盖一切导入方式（导入 JSON / 批量导入 ✓）。
- **账号标识**：`ProviderKeyIdentityBlock.vue` 加 `国内版` / `国际版` 徽章 ✓，
  取值 = `upstream_metadata.workbuddy.realm` ✓（与面板同口径 ✓）；**没有该键时不渲染** ✓
  （刚导入、还没拉目录的账号会在自动补拉完成、父组件重载后出现标识 ✓）。
- **单测**：`ProviderKeyIdentityBlock.spec.ts` 3 条 ✓（国内 ✓ / 国际 ✓ / 无 `realm` 不渲染 ✓）+
  `WorkbuddyUpstreamPanels.import.spec.ts` 3 条 ✓（无快照 → 自动拉并请求刷新 ✓ / 有快照 → 不拉也不显示按钮 ✓ /
  拉取失败 → 不刷新且留按钮 ✓）→ 两个 spec 共 **19 passed** ✓。

> **真机验证** ✓（2026-10-16）：线上 bundle 已含两个新标记 ✓（`provider-key-workbuddy-realm` ✓、
> `workbuddy-fetch-catalog` ✓）；两个账号落库为 `cn | 17 模型` ✓ 与 `global | 18 模型` ✓；
> 国际号维护摘要 `global_registration = {"status":"activated"}` ✓
> —— 这同时**补上了 v33 唯一缺的那块端到端真机证据** ✓（真国际号上「补注册地区 → 激活」跑通 ✓）。
> ⚠️ 诚实说明 ✓：**国际号这次的目录是我手动触发的一次** ✓（走的就是面板自动补拉的同一条接口 ✓），
> 之后新导入的账号由面板自动补拉 ✓；「自动」这一步的浏览器侧表现请以打开面板为准 ✓。

**已做（v33）**：**国际版（global）补注册地区 + 激活**（面板 `internal/upstream/global_register.go`
的 `GlobalCompleteRegistration`）——**用户 2026-10-16 追加**的缺口（本仓编号 ⑬ ✓，不在原 12 项里 ✓）。
- **为什么必须有**：新 global 号没补注册地区时，register 接口回 `code 500 / region required` ✓，
  对话直接报 `14017 trial not activated` ✗（面板文件头的动机原话 ✓）。Aether 此前**只有**
  trial 加油包（`execute_workbuddy_trial_claim` ✓）、**没有**补地区/激活这一环 ✗。
- **面板链路**（代码里**实际调用**的三步 ✓）：
  - `GET {webBase}/auth/realms/copilot/overseas/user/register?userId=<uid>` ✓
    （**路径 query 与 `x-user-id` 头都要** ✓）→ 信封 `code 200` = 已激活 ✓；
    `code 500` 或 msg 含 `region required`（大小写不敏感 ✓）= 需补地区 ✓
  - `POST {webBase}/billing/area/get-country-code {filterForbidden:1}` ✓ → 地区列表 ✓；
    **响应的 `data` 是 JSON 字符串（双层信封 ✓）**，要拆两次 ✓
  - `POST {webBase}/console/login/account {attributes:{countryCode,countryFullName,countryName}}` ✓
    —— 三个值都是**单元素数组** ✓（面板逐字口径 ✓）；幂等 ✓（`code 0` = 成功 ✓）
- **刻意不做的部分** ✓：面板文件头注释还写了 `POST /billing/area/get-user-area-info
  {action:getUserAreaInfo}` 当"检测当前地区"用 ✓，但**面板代码里从没调用过它** ✗
  （grep 全仓只命中注释 ✓）→ Aether 同样**不实现** ✓（不编造未被验证的请求 ✓）。
- **Aether 实现**：
  - 纯函数 `crates/aether-provider/transport/src/workbuddy/global_register.rs` ✓：
    `classify_workbuddy_global_register_status`（三分类 ✓ 面板同口径 ✓）、
    `parse_workbuddy_global_countries`（双层信封 ✓ + 大小写不敏感键 ✓ + 数字码容忍 ✓）、
    `filter_workbuddy_global_intl_countries`（白名单 **HK→MO→SG→TH→PH→MY→ID，顺序即优先级** ✓）、
    请求体构造 ✓。
  - 请求构造（pool ✓）：`build_workbuddy_pool_global_{register_status,country_code,submit_region}_request` ✓
    —— **官网域 + 浏览器指纹** ✓（面板 `globalWebUA` = Chrome/120 ✓、`Origin` = 官网根 ✓、
    `Referer` = 官网根 + `/` ✓），**不带**桌面端的 `x-client-platform` / `x-domain` / 设备头族 ✓（面板也没带 ✓）。
  - 网关侧 `execute_workbuddy_global_registration` ✓（`oauth/quota/workbuddy.rs` ✓）：
    查状态 → 已激活**直接返回** ✓（**幂等** ✓，只打一次 GET ✓）→ 需补地区则取白名单**首个**提交 →
    **再查一次状态确认** ✓（面板同样要求复验 ✓）；任何一步失败都**不阻断**后续 trial / 余额 ✓。
  - **顺序**：排在 trial **之前** ✓（领取加油包要求账号已激活 ✓）；结果落进维护摘要
    `maintenance.global_registration` ✓ 与额度接口 payload 的 `global_registration` ✓（便于真机核对 ✓）；
    CN 号一律 `null` ✓（零回归 ✓）。
- **单测**：transport 5 条 ✓（三分类 ✓ / 双层信封 ✓ / 形状容错 ✓ / 白名单顺序 ✓ / 请求体数组 ✓）+
  pool 4 条 ✓（路径 query + `x-user-id` ✓ / `{filterForbidden:1}` ✓ / 地区数组体 ✓ / request_id 分步命名 ✓）。

> **v33 真机验证** ✓（2026-10-16，`<测试机 IP>`）：
> - **部署** ✓：线上二进制 md5 `21bb5e4de7735c9a034c4871c9f918a7` ✓、dist 240 文件 ✓、服务 `active` ✓、
>   `/health` 200 ✓、`/` 200 ✓；**新符号在线上二进制的字符串表里出现 5 次** ✓
>   （`workbuddy_global_register_status` ✓）→ 新代码确实上了线 ✓。
> - **CN 零回归** ✓：手动刷新现网 CN 号（`refresh-quota` ✓）→ `status: success` ✓、维护摘要 `ran_at`
>   刷新 ✓、`checkin: already_checked_in` ✓、**`global_registration: null`** ✓
>   —— 新字段确实在写 ✓，CN 号行为与 v32 完全一致 ✓（CN 分支直接返回 `None` ✓）。
> - ⚠️ **诚实缺口** ✗：**global 分支没有端到端真机证据** —— 现网只有 CN 号 ✓，而 key 的 realm 存在
>   **加密的** `auth_config` 里 ✗（`aether-provider-catalog-credential-v2:…` ✓，SQL 注入改不了 ✓），
>   造一个能跑通「补地区 → 激活」两步的 key 需要**真 global 账号** ✗
>   —— 正是用户接下来会用新选择器新加的东西 ✓。因此三段请求形状（路径 query + `x-user-id` ✓ /
>   `{filterForbidden:1}` ✓ / 地区**单元素数组**体 ✓）、状态三分类 ✓、白名单顺序 ✓ 全部由 **9 条单测**
>   （transport 5 + pool 4 ✓）背书 ✓；「提交地区后真的激活」这一步只有在真 global 号上才能验 ✓。

**已做（v32）**：**WAF 出口 IP 级拦截 fail-fast**（缺口 ⑦，面板 `internal/server/wafip.go`）。
- 面板口径：WAF 403 判定 = **403 且 body 无业务信封**（无 `"code":`/`"msg":` ✓；本仓**早已有**
  `is_waf_blocked` ✓，且**早已**只做账号级软冷却、不标授权失效 ✓）；面板新增的是 **IP 级**判定 ——
  `60s` 滑动窗内 **≥2 个不同账号**接连命中 → 判定出口 IP 被拦 ✓，激活到 `now+60s` ✓；
  **激活期内新命中不续期** ✓；**激活时清空判定窗**（解除后需全新命中 ✓）；进程内状态、重启清零 ✓；
  效果 = **停止轮转（fail-fast）** ✓ —— 继续换号只会把一次请求放大 `MaxRotate` 倍打同一出口 IP ✓。
- Aether 实现：新纯模块 `apps/aether-gateway/src/orchestration/waf_ip.rs` ✓
  （`WafIpGate` 状态机 `note_waf(account_id, now) -> bool` / `is_active(now)` ✓ + 进程级闸门
  `note_waf_block` / `waf_ip_block_active` ✓，锁中毒按未激活处理、绝不中断正常请求 ✓；
  常量 `WAF_IP_WINDOW_SECONDS = 60` ✓、`WAF_IP_THRESHOLD = 2` ✓ 面板同值 ✓）；
  记账点 = `orchestration/effects.rs` 失败反馈路径 ✓（**只对 WorkBuddy 计划**生效 ✓，
  与账号级硬状态同源：`classify_workbuddy_failure` → `WafBlock` ✓）；
  快速失败 = 选号层 `dispatch/pool_scheduler.rs` ✓（闸门激活期直接返回**空候选** = 无可用号 ✓，
  配合批次 J 的 `gateway_hint` 客户端仍能拿到中性提示 ✓）；
  配置 `pool_advanced.waf_ip_cooldown_seconds` ✓（**默认 60** = 面板同款行为 ✓；`0` = 关停 ✓）。
- 单测：`orchestration::waf_ip::tests` ✓ 5 条 —— 单号反复 403 **永不激活** ✓；窗口内两个不同号
  **激活**且到期自然解除 ✓；窗外命中被剪枝 ✓；**激活期不续期**且**清窗后需重新凑齐两个不同号** ✓；
  同号连打不凑够阈值 ✓。

> **v32 真机验证** ✓：`waf_ip_cooldown_seconds` 往返 60 / 0 ✓；闸门未激活时常规请求 `glm-5.3`
> → **HTTP 200** ✓（默认行为零回归 ✓）。
> ⚠️ 诚实标注：**闸门激活态无真机证据** ✗ —— 触发它得让上游真的对两个不同账号连发 WAF 403 ✓
> （做不到也不该做 ✓）；激活/剪枝/不续期/清窗全部由 5 条单测背书 ✓。
> 另一处**刻意差异** ✓：面板只停「本次请求的轮转」✓，Aether 连**新请求**也一起挡 60s ✓ ——
> 更严一档（避免继续打已被拦的出口 IP ✓），默认窗口只有 60s ✓，代价可控 ✓。

**已做（v30+v31）**：**`error.gateway_hint`**（缺口 ⑩，面板 `internal/upstream/hint.go`）。
- 面板口径：`error.message` **永远是原文** ✓；`gateway_hint` 只做**并列**补充 ✓（绝不替换/包装 ✓）；
  文案**集中一处**（kind 表 + 上游业务码 11133/11135 形态 ✓），**未覆盖形态不带字段** ✓；
  措辞**英文** ✓；SSE error 帧同款 ✓。
- Aether 实现：新模块 `crates/aether-ai/formats/src/formats/shared/gateway_hint.rs` ✓（单一事实来源 ✓）
  —— `gateway_hint(kind, message)` ✓：先判 **11133 家族**（`"code":11133` / `"code": 11133` /
  `"code":"11133"` / `model_param_invalid` / `invalid request parameters` ✓）与 **11135 家族**
  （`invalid_image_data` / `replace the image` ✓）与 `prompt is too long` ✓，再走 kind 表
  （`ContextLengthExceeded` / `RequestTooLarge` / `RateLimit` / `Overloaded` ✓）；
  **其余 kind 一律 `None`**（不编造 ✓）。挂载点 = 单一 choke point
  `build_core_error_body_for_client_format`（`error_body.rs` ✓）→ openai / claude / gemini **三种格式**
  的 error 对象都带上 ✓（SSE 错误帧也走这里 ✓）。
- **v31 补的真缺口** ✓：`api/response.rs::build_local_error_payload` 对**非 claude 格式**直接返回
  fallback ✗ → openai 客户端拿不到 hint ✗；现已在 fallback 上补（幂等 `or_insert` ✓，
  只在已有 `error` 对象时补、**不编造新形状** ✓）。
- 单测：`gateway_hint::tests` ✓（业务码优先于 kind ✓ 容差形态 ✓ 只覆盖无歧义 kind ✓ 未覆盖 → None ✓）
  + `error_body::core_error_body_carries_gateway_hint_only_when_covered` ✓（三格式都带 ✓ message 原样 ✓
  未覆盖不带 ✓）+ `api::response::local_overloaded_error_body_carries_gateway_hint` ✓。

> **v30/v31 真机验证** ✓：触发 503（未知模型 ✓ 与池内熔断冷启动 ✓ 两条路）→ 响应体
> `error.gateway_hint` = 「the gateway is overloaded or has no healthy account; retry after a short backoff」✓，
> `error.message` **仍是原文**（「没有可用提供商支持模型 … 的同步请求」✓）→ **纪律成立** ✓。
> ⚠️ 诚实标注：① 上游业务码族（11133/11135）**无真机证据** ✗ —— 实测给纯文本模型发图上游**照收**（200 ✓），
> 触发不了 ✓，该族只由单测背书 ✓；② Aether 路由层把「模型不存在」与「池内无可用号」**归成同一 kind** ✓
> → 两者都带 hint ✓（面板对「模型不存在」不给 hint ✗）——**刻意近似**：措辞已中性化为
> 「overloaded **or** has no healthy account」✓ 不至于误导 ✓。

**已做（v29）**：**昵称刷新（改名后免重登）**（缺口 ⑨，面板 issue #94）。
- 面板口径（`internal/upstream/profile.go`）：`GET {webBase}/console/account` + `Bearer` +
  **`x-client-platform: web`** + 资料页 `Referer`（实测无需 Web 会话 cookie）；**只解析 `nickname` 与 `uid`**，
  手机号等敏感字段**不解析、不落日志、不透传**；`uid` 与凭证不一致 → 丢弃（**防串号**）；
  **只在手动「刷新」时触发**，后台余额轮询**不调**该接口。
- Aether 实现：传输常量 `WORKBUDDY_ACCOUNT_PROFILE_PATH` ✓ + **Referer 按 web 域同域推导**
  （`{web_base_url}/profile/account-settings`，**没有硬编码常量** —— 硬编码国内域会让国际域的
  Referer 跨域，被上游当异常请求）
  （`WORKBUDDY_WEB_BASE_URL_CN` / `CLIENT_PLATFORM_WEB` 复用既有 ✓）；请求构造
  `build_workbuddy_pool_account_profile_request`（GET + web 域 + web 平台头 + Referer）✓；
  **只取昵称**的解析器 `workbuddy_nickname_from_account_profile` ✓（信封/裸对象兼容 ✓
  uid 双侧非空且不一致 → `None` 防串号 ✓ 昵称空/缺失 → `None` 不覆盖成空 ✓ 其余字段当场丢弃 ✓）；
  触发点 = `refresh-quota` **手动**处理器 ✓ → 刷新额度后逐个 key 拉昵称 ✓ →
  写进 `upstream_metadata.workbuddy.account.nickname`（继承 account 原有字段，避免浅合并冲掉 ✓）；
  失败静默、不影响额度结果 ✓；**只做 CN 域** ✓（国际域不猜路径 ✓）。
- 单测：`account_profile_parses_only_nickname_and_guards_uid` ✓（7 组断言：信封 ✓ 裸对象 ✓
  防串号 ✓ 单侧 uid 缺失不拦 ✓ 昵称缺失/空白 → None ✓ 空白裁剪 ✓ 请求构造 GET/web 域/平台头/Referer ✓）。

> **v29 真机验证** ✓：`POST …/refresh-quota {key_ids:[…]}` → HTTP 200（`success:1/total:1` ✓）→
> PG 直读 `upstream_metadata.workbuddy.account.nickname` = **`132****1637`** ✓（刷新前为空 ✓）→ **同步生效** ✓。
> ⚠️ 诚实标注：该账号上游 `nickname` 本身就是**掩码手机号**（不是显示名 ✓）——面板取同一字段、
> 同样会存它 ✓，**行为与参考实现一致** ✓；另：Aether 的**账号卡片标题**仍用 key 名 ✓，
> 昵称落在 key 的 metadata 里 ✓（是否让 UI 改用该昵称属产品选择 ✓，未擅自改 ✓）。

**已做（v28）**：**`context`/输出上限静态兜底**（缺口 ⑧）。
- 面板口径（`internal/upstream/context_catalog.go` + `handler.go:370-394`）：`context_length` 三级查找
  —— 上游 `maxInputTokens`（`> 0` 权威）→ **静态知识表** `contextCapFallback` → **1M 兜底**
  （**宁可高估不可低估**，避免下游按自己的小默认值**提前截断**；面板明确「绝不再透出假 131072」）；
  `max_output_tokens` 同链，但**知识表没有就省略字段**（不编造）。
- Aether 实现：`crates/aether-model-fetch/src/logic.rs` 的 `workbuddy_metadata_model` ✓
  —— 上游值 `> 0` 时权威 ✓；否则查静态表 `WORKBUDDY_CONTEXT_CAP_FALLBACK` ✓（照抄面板条目与来源注释：
  GLM/Kimi/MiniMax·混元/DeepSeek/auto 共 19 条 ✓）；表里没有 → `context_window = 1_000_000` ✓；
  输出上限「表里有才补、没有就**删字段**」✓；上游给 `0`/负数视为缺字段 ✓。
- 单测：`workbuddy_context_and_output_fall_back_to_the_static_table` ✓（表命中 ✓ 表外 1M + 输出省略 ✓
  面板标注「输出未知」条目 ✓ 上游值权威 ✓ 上游 0/负数走兜底 ✓ 大小写空白不敏感 ✓）
  → model-fetch workbuddy **14 passed** ✓。

> **v28 真机验证** ✓（强制刷新目录后 **PG 直读** 17 个模型的最终快照）：
> **缺上下文窗口 = 无** ✓、**非法输出上限 = 无** ✓（输出上限要么是正数、要么字段省略 ✓）；
> 样本：`auto 256000/32000`、`deepseek-v4-pro 1000000/393216`、`glm-5.2 1000000/131072`、
> `glm-5.3 1000000/131072`、`hy3 192000/64000`、`kimi-k3-1 1000000/1048576` ✓。
> ⚠️ 诚实标注：单看快照**分不清**某个值是「上游给的」还是「知识表兜底」✗（上游多数模型本来就带值 ✓）；
> 兜底逻辑本身由单测逐条钉住 ✓。

**已做（v27）**：**成本探索窗口**（缺口 ⑥，面板 issue #136 方案 a′）。
- 面板口径（`config.go:197-202,292,517-524` + `pool.go:28-39,149-174` + `pick.go:128-138`）：
  `cost_explore_interval` **默认 30m**、**0/负值 = 关停**；规则 = 当**当前最优是 tier 0（已观测免费）**、
  池中存在 **tier 1（无观测）**账号、且该账号距上次探索已超过窗口时，**改选未观测账号去探路**
  （打破「免费层垄断 → 永远不去验证别的号」）；`/status` 透出 `cost_explore` 事件数。
- Aether 实现：新纯模块 `crates/aether-pool-core/src/cost_explore.rs` ✓
  （`pool_member_cost_tier`（`total_tokens == 0` = 未观测 ✓；观测过且成本 > 0 = 收费 ✓；否则免费 ✓）+
  `pool_cost_explore_promote_index` ✓ 逐条对齐面板规则 ✓）；候选上带 key 累计用量 ✓
  （`PoolMemberSignals` 加 `total_tokens`/`total_cost_usd` ✓，两处生产者都从 key 填 ✓）；
  网关侧进程内探索台账（key → 上次探索时刻 ✓，**从未探索 = 立即到期** ✓ 面板同款语义 ✓）+
  **排名之后、返回之前**做顺序调整 ✓（只改顺序、不改硬过滤 ✓ 不会让不可选的号被选中 ✓）。
- 配置：`pool_advanced.cost_explore_interval_seconds` ✓（**默认 1800 = 30 分钟** ✓ = 面板口径，
  见 `aether-pool-core/src/pool_advanced_defaults.rs` ✓；显式 `0` = 关停 ✓；
  别名 `cost_explore_interval` 也认 ✓）。
- 单测：`cost_tier_uses_tokens_then_cost` ✓ + `explore_only_breaks_free_observed_monopoly` ✓
  （关停 ✓／队首非免费档不干预 ✓／免费垄断 + 到期未观测号 → 提它 ✓／未到期不干预 ✓／
  无未观测号不干预 ✓／空列表 ✓）+ 配置解析断言 ✓。

> ⚠️ **诚实标注**：本项**端到端真机证据缺失** ✗ —— 需要「池里 ≥2 个号、其中含未观测号」才能观察到改道 ✓，
> 而现网只有 **1 个已观测账号** ✗；本项由纯函数单测 + 配置往返背书 ✓。

**已做（v26）**：**熔断基础时长 + 退避上限可配**（缺口 ⑫ 的后半，面板 `breaker_cooldown` / `breaker_cooldown_max`）。
- 面板口径（`config.go:179-180,282-283` + `entry.go:504-505`）：**基础熔断时长默认 30m**、
  **指数退避封顶默认 6h**；退避式 `d = min(base × 2^retryCount, max)` ✓。
- Aether 现状：退避是「熔断后按 `probe_interval_minutes` 探测、每次翻倍」✓，历史默认
  **基础 1 分钟 / 上限 32 分钟** ✓（上限还由 key 的 `max_probe_interval_minutes` 收紧 ✓）。
- 本次实现：`pool_advanced.breaker_cooldown_minutes`（基础，**默认 30 分钟 = 面板口径** ✓；
  显式 `0` = 沿用历史 1 分钟 ✓）+
  `pool_advanced.breaker_cooldown_max_minutes`（退避上限，**默认 360 分钟 = 6h = 面板口径** ✓；
  显式 `0` = 沿用历史 32 分钟 ✓；**显式配置时受 24h 安全天花板夹住** ✓ 防误配成「永不重试」）→
  两者随阈值一起注入
  `project_local_key_circuit_failure(...)` ✓（同一个 provider 配置读取 ✓）。
  想完全对齐面板就把两个都配上（`breaker_cooldown_minutes: 30` + `breaker_cooldown_max_minutes: 360`）✓，
  同时把 key 的 `max_probe_interval_minutes` 放到 360 ✓ —— **上限的语义是「key 值的上界」** ✓
  （key 更紧时以 key 为准 ✓）。
- 单测：`circuit_base_and_ceiling_are_configurable` ✓（基础 30 → 首闸 30 ✓ 翻倍 60 ✓ 上限 360 ✓
  key 更紧时以 key 为准 ✓ 未配置 → 回到历史 1 分钟 ✓）+ 配置解析断言 ✓（orchestration::health 8 passed ✓）。

> **v26 真机验证** ✓：`pool_advanced` 往返含 `breaker_cooldown_minutes=30` / `breaker_cooldown_max_minutes=360` ✓；
> 并回归批次 D 的对照实验（注入熔断 + 开关 true → 503 ✓ / false → 200 ✓ / 还原后 200 ✓）✓ 未回归 ✓。
> ⚠️ 诚实标注：**退避时长本身**没做真机端到端证据 ✗（要制造连续 5xx 才能看到翻倍 ✓ 无法安全触发 ✓），
> 由单测（首闸/翻倍/上限/key 收紧/未配置五档 ✓）+ 配置往返背书 ✓。

**已做（v25）**：**闲置补偿评分旋钮**（缺口 ⑫ 的前半，面板 `idle_weight_per_hour` / `idle_weight_max`）。
- 面板口径（`config.go:186-187`）：**每小时未用 +0.5 权重**（默认 `0.5`）、**封顶 5.0**（默认 `5.0`），
  在加权路由里生效（`pick.go` 的短名单也是按**权重**截断，否则闲置补偿根本进不了短名单）。
- Aether 实现：`pool_advanced.idle_weight_per_hour` / `idle_weight_max` ✓（顶层键优先、其次 `score_rules.*` ✓；
  `idle_weight_max = 0` = **关闭闲置补偿** ✓ 显式语义）→ 打分器 `score_pool_member_with_rules` ✓ 里
  作为 `idle_bonus` 加在惩罚之后、不可调度上限之前 ✓（**不会把不可调度账号抬起来** ✓，与快过期加分同一位置 ✓）；
  `score_reason.factors` 带 `idle_seconds` / `idle_bonus` ✓、`rules` 回显两个旋钮 ✓ 便于真机核对 ✓。
- 单测：`idle_bonus_grows_hourly_and_caps` ✓（0h→0 ✓ 2h→1.0 ✓ 10h→封顶 5.0 ✓ 100h 仍封顶 ✓
  `idle_weight_max=0` 关闭 ✓ 规则回显 ✓）。
- ⚠️ **与面板的一处有意差异** ✗：**从未使用过**的账号面板按「满额闲置」计 ✓（全新号天然占优），
  Aether 按 **0** 计 ✓ —— 因为 `last_used_at` 缺失既可能是新号、也可能是数据未回填，
  满额补偿会把一批无历史账号突然抬高，风险大于收益 ✓；池内老账号都有 `last_used_at`，补偿照常生效 ✓。

**已做（v24）**：**国际版（global 域）在途上限按域分档**（缺口 ⑤，面板 P1-1）。
- 面板口径（`config.go:176-177,280` + `pool.go:260-266`）：`max_in_flight` 单账号在途上限默认 3；
  **`max_in_flight_global` = global 域单账号在途上限，面板默认 2**（global 域 WAF 风控更紧 → 压低并发）；
  生效式 `realm == "global" ? maxInFlightGlobal : maxInFlight`；分档值 <= 0 = 未设置 → 回落账号自身上限。
- Aether 实现：`pool_advanced.max_in_flight_global`（**默认 0 = 不分档** ✓ 零回归；面板默认 2 已记档 ✓）
  + 纯函数 `workbuddy_in_flight_limit(base, tier, metadata)` ✓ 与 `workbuddy_key_realm` ✓
  （读 `upstream_metadata.workbuddy.realm`，PG 实测现网为 `cn` ✓）。接线沿用「零签名改动」手法 ——
  构造候选快照时按 realm **改写该 key 的生效并发上限** ✓，后续并发判定自然生效 ✓。
  **注意这里不需要 `quota_hard_blocked`**：并发判定**没有被 `!pool_group` 门控** ✓（与保底/熔断不同 ✓）。
- 单测：`in_flight_limit_tiers_global_realm_only` ✓（未配置零回归 ✓ global 用分档 ✓ CN/未知/无元数据回落 ✓
  `0`＝不限也被压住 ✓ 大小写空白不敏感 ✓）+ `parses_breaker_knobs` 加分档断言 ✓（pool workbuddy 15 passed ✓）。

> **v24 真机验证** ✓：`pool_advanced` 往返含 `max_in_flight_global=2` ✓；并**回归**了批次 D 的对照实验
> （注入熔断 + 开关 true → **503** ✓ / 开关 false → 200 ✓ / 还原后 200 ✓）✓ 未回归 ✓。
> ⚠️ **诚实标注**：分档的**效果**（global 账号真被压到 2 并发）**没有真机证据** ✗ —— 现网账号是 **CN** 域 ✓，
> 且没有接口透出「生效并发上限」✗；该半由纯函数单测 + 配置往返背书 ✓。

**已做（v23）**：**连败熔断阈值可配 + 池内是否计入熔断**（缺口 ④）。
- `pool_advanced.breaker_threshold`（面板 `breaker_threshold`，**面板默认 3** ✓；Aether 默认沿用历史值
  **8** ✓ 不静默改变既有部署；`0`/缺失 = 8 ✓ 避免误配成「永不熔断」✓）→ 接入
  `project_local_key_circuit_failure(..., failure_threshold, ...)` ✓，熔断 reason 也随之变成
  `consecutive_failures_{阈值}` ✓。
- `pool_advanced.pool_counts_toward_circuit_breaker`（**面板口径 = 是** ✓：面板的熔断是**账号级**
  信号 ✓，任一 format 熔断即该账号不可选 ✓）→ 在池调度里落成硬排除 ✓
  （`quota_hard_blocked` → 候选被 skip ✓）。
- 单测：`parses_breaker_knobs` ✓（默认 8/关 ✓ 面板值 3/开 ✓ 0 回退 8 ✓）+ `orchestration::health` 7 passed ✓。

> **v23 真机对照实验（2026-10-16 05:2x）** ✓（往 PG 注入「熔断中」的 key 状态，再切换开关）：
> ```
> 基线（无熔断）                             glm-5.3 -> 200 ✓
> 注入熔断 + 开关=true  （面板口径）          -> 503 ✓ 池内账号被拦住
> 注入熔断 + 开关=false （Aether 默认）       -> 200 ✓ 不受熔断约束
> 还原（清熔断 + pool_advanced={}）           -> 200 ✓
> 对照结论：✓ 开关确实决定池内是否受熔断约束（因果成立）
> ```
> ⚠️ **诚实标注**：阈值的**端到端**效果（连败几次真的开闸）没有真机证据 —— 需要制造 3 次真实
> 上游 5xx ✗，无法安全触发；该半只用**配置往返 + 单测**背书 ✓。
>
> **第三次踩到同一类陷阱** ✗（见上文两条教训）：`enforce_key_circuit_breaker`
> （`scheduler/candidate/runtime.rs` 的 `!pool_group` 分支）**同样不是池内候选的生效通道** ✗ ——
> 第一版改它，真机对照**直接证伪** ✓；改走池调度的 `quota_hard_blocked` 才生效 ✓。
> **结论固化**：**凡是「池内账号该被硬排除」的策略，一律落在 `dispatch/pool_scheduler.rs`
> 的 `quota_hard_blocked` 上** ✓，别在 `scheduler/candidate/runtime.rs` 的 `!pool_group` 分支里加 ✗。

**已做（v18→v21）**：**积分保底 `credit_floor`**（面板 `pool.credit_floor` / `floorBlockedForModel` 的等价物）
——`pool_advanced.credit_floor`（**默认 0 = 关闭**，负值钳 0）> 0 时，余额**严格低于**该值的账号
（`credits == floor` 放行）不再接**收费**模型；免费/未知倍率一律放行（「保底保的正是还能用免费模型」）。
收费判据 = 目录倍率兜底 `workbuddy_catalog_model_rate`（**优先取生效价 `promo_credits`**，
折扣到 0 的模型不该被拦 ✓），倍率文本**前后缀两种 x 写法都认** ✓（上游实测是 `x1.62` 前缀形态 ✓），
`unlimited` 不构成限制 ✓；落点是**池内硬排除** ✓（`quota_hard_blocked` → 候选被 skip；池内无候选即 503 ✓）。
共 16 条保底断言 + 1 条配置断言 + 1 条倍率形态回归钉子 ✓。

> **v18/v19 真机实测（2026-10-16 03:0x CST）——⚠️ 拦截侧未生效**：
> 把 `credit_floor` 设成 **10⁶**（账号余额 **2292**，远超保底）后：
> - `hy3`（promo `0x` 限免）/ `step-5-preview`（promo `0x` 限免）/ `hy4-preview-f`（无倍率=未知）
>   → **全部 200** ✓ 即「免费/未知放行」这一半**符合预期** ✓；
> - `kimi-k3-1`（`x1.62` 收费）/ `glm-5.3`（`x0.79` 收费）→ **仍是 200** ✗ **没被拦住** ✗。
>
> **根因（已确证，2026-10-16 03:4x）** ✓✓：判定**算对了**，但**没人用它** ——
> `scheduler/candidate/runtime.rs:218` 把这张表整段短路了：
> ```rust
> account_quota_exhausted: !pool_group        // ← 池内候选：整段被跳过 ✗
>     && snapshot.key_account_quota_exhausted.get(candidate.key_id)…,
> ```
> 配了 `pool_advanced` 的供应商 `pool_enabled = true` → `pool_group = true` → **`!pool_group` 为假**，
> 于是同一处布尔表达式里我新加的 `credit_floor_blocks_here` **被丢弃** ✗。
> 诊断日志是决定性证据（临时打开该 target 后抓到）：
> `{"model":"kimi-k3-1","floor":1000000,"has_metadata":true,"blocked":true}` ——
> 判定为「拦」✓，请求仍 200 ✗。
>
> ⚠️ **同时纠正上一轮的错误结论** ✗：模型级负缓存 `model_blocked` **对池内账号同样被这段
> `!pool_group` 跳过** ✗ —— 2026-10-16 那次「注入锁 → 503」是**巧合**（很可能上游当时就报错 ✓），
> 我当时把它当成因果证据 ✗。Aether 的既有设计是「池内账号交给池机制（健康分/池调度）」✓，
> 而面板对**模型锁与积分保底都是硬拦** ✓ → 这正是 §4.0 要对齐的口径差异 ✓。
>
> **已修（v21）** ✓：做成**池内硬排除** ✓，而且比原计划更省——**零签名改动** ✓：
> 1. `AdminProviderPoolConfig` 加 `credit_floor: i64` ✓（解析：缺失/0 = 关闭 ✓ 负值钳 0 ✓ 字符串数字也认 ✓
>    带单测 ✓）；
> 2. `dispatch/pool_scheduler.rs` 的 `read_pool_catalog_key_contexts_by_ids` 里，
>    在**既有「1% 保底」同一处**把保底结果 OR 进 `quota_hard_blocked` ✓
>    （复用 `workbuddy_credit_floor_blocked` ✓）→ `pool-core/scheduler.rs:228` 直接 skip 候选 ✓
>    → 池内无候选即 503 ✓。
>
> **v21 真机证据（2026-10-16 04:2x，风险可控的对照实验）** ✓：
> ```
> 基线（保底关）       kimi-k3-1 200 / glm-5.3 200 / hy3 200 / step-5-preview 200 / hy4-preview-f 200
> 触底（floor=10^6，
>       账号余额 2292） kimi-k3-1 x1.62 → 503 ✓被拦   glm-5.3 x0.79 → 503 ✓被拦
>                        hy3(0x 限免) → 200 ✓放行      step-5-preview(0x 限免) → 200 ✓放行
>                        hy4-preview-f(无倍率=未知) → 200 ✓放行
> 判定：5/5 全部符合预期 ✓；探针结束已还原 pool_advanced={}
> ```
> 503 正文 `没有可用提供商支持模型 kimi-k3-1 的同步请求` ✓ 正是面板「宁可 503 也不打穿保底」✓。
>
> **两条给后来人的教训** ✓：
> 1. **同一个布尔表达式 ≠ 同一个生效路径** ✗：`scheduler/candidate/runtime.rs` 的
>    `!pool_group` 会把池内候选整段短路 ✗ —— 池内账号的硬排除必须落在**池调度**那条路上
>    （`quota_hard_blocked`），别在非池分支里“顺手加一项”✗。
> 2. **日志 target 要能被现有 `RUST_LOG` 覆盖** ✗：本仓配的是 `aether_gateway=debug` ✓，
>    自定义 target（如 `xxx_diag`）会被静默过滤 ✗，排查时会白等一轮 ✓；现在诊断日志继承模块
>    target ✓（只在保底开启时打 ✓）。
> 3. **注入式对照实验必须先清进程内缓存** ✗（2026-10-16 第 11 轮踩到 ✓）：网关对 key 的健康/熔断
>    状态有**进程内缓存** ✓，所以「先跑一次成功请求、再从数据库外部注入『熔断中』」会被忽略 ✗，
>    同一探针会**时灵时不灵** ✗，极易误判成「代码回归」✓。**正确做法**：注入后**重启网关**
>    （清缓存）再请求 ✓。冷启动后的确定性结果：`open=true` + 开关 on → **503** ✓ /
>    `open=true` + 开关 off → **200** ✓（v27 实测 ✓，脚本 `remote/144-cold-cache-check.sh` ✓）
>    → 结论：**批次 D 机制正常、v27 无回归** ✓。
>
> 旁证：**v17 的优惠解析其实成功了** ✓——PG 直读证明快照里 **4 个模型带 `promo_*`**
> （`hy3` 限时免费 / `step-5-preview` 独家限免 / `hy4-preview` 夜间免费 / `glm-5.2` 夜间折扣 `0.50x`），
> 另有 `deepseek-v4-pro` / `deepseek-v4-flash` 的**纯徽章「错峰使用」**（无 factor ✓ 未编造 ✓）。
> 之前「上游没下发优惠」的结论**是错的**——错在读了不返回目录元数据的 `provider-query` 接口 ✗。
> 正确读法：`docker exec aether-deploy-postgres psql` 直读 `provider_api_keys.upstream_metadata`
> （容器内 `/usr/bin/psql` ✓，主机没装 psql ✗；库在 **15432** ✓ 不是 5432 ✗；表名 **`provider_api_keys`** ✓）。

> **v17 实测（2026-10-16 02:0x CST）**：本账号 CN 侧 `/v3/config` 当前**未下发**
> `modelPromotions`——同一次重拉解析出 **17** 个模型（15 条带 `credits`），而 `promo_*`
> **0 条**。判定方法：优惠映射与模型列表读的是**同一个 `data` 对象**，所以「模型有、promo 无」
> 只能是上游没下发（面板 2026-09-23 观测到的 7 条——deepseek 错峰五折 / glm-5.2 夜间五折 /
> hy3·hy4 限时免费——此后已被上游撤下）。**上游一旦重新下发，倍率列会自动变成
> 「生效价 + 徽章 + 划线牌价」**，无需再发版。

**池化参数的口径提醒**：面板「熔断基础时长 / 退避上限」「闲置补偿」与 Aether 的实现**口径不同**
（Aether 是「探测间隔 + LRU 排序制」），不是简单缺参数——要做需先统一口径（见 §4 逐条表）。
已做：单账号在途 · 软限流冷却基数 · **会话粘性 TTL** · **连败降权三件套** ·
**`429` 软限流退避上限**（另额外暴露「供应商级并发上限」）。

**建议顺序**：① 成本探索窗口 → ② context/输出上限静态兜底 → ③ 昵称刷新 / error.gateway_hint → ④ WAF 出口 IP 冷却 / global 向导（成本高或属范围外）。
（Tier-2 在 **v15**、快过期加权在 **v16**、限时优惠在 **v17**、积分保底在 **v21**、连败熔断与池内计入在 **v23** 完成。）

下表是**逐条**现状与后果（比总览更细，含已做项）：

| 能力 | 现状 | 不做的后果 |
| --- | --- | --- |
| 窄子集协议兼容 | **已做**（含 gpt 下限钳制、`stream_options.include_usage` 补全、tool schema 转义还原、global 兜底 system） | 不做：`400 code 11-128` / 长回答静默截断 / 工具选择被拒 / `400 code 11101` |
| tool 配对三步（合并/repack/清孤儿） | **已做**（§2.1；顺序与面板一致，含 `function.name` 空值裁剪与 `reasoning_content` 合并） | 不做：**不完整配对会让上游对之后每条消息都返 400**——长对话带工具调用时可能整段失效 |
| DeepSeek 思维链（thinking 注入 / reasoning 回填） | **已做**（§2.1，仅 deepseek 系模型；含多轮一致性回填） | 不做：deepseek 系模型不返回思维链、多轮请求可能 400 |
| DeepSeek 档位降级（`reasoning_effort`） | **已做**（§2.1：模型拉取写档位表 → 请求路径降级；`workbuddy` 命名空间已加逐字段保留，避免与余额字段互抹） | 不做：客户端档位与模型支持档不匹配时上游可能 400 |
| 提示词替换 + 指纹脱敏 | **已做**（§2.1） | 不做：客户端固定模板句被逐字比对，`400 blocked by security policy` |
| 会话/链路头族（`X-Conversation-*` / `X-B3-*`） | **已做**（§1.2：聚合主键用 trace id 稳定派生，接线 standard 两条分支 + passthrough） | 不做：上游后台把一轮对话聚成碎片，官方指纹完整度少一块 |
| 计费/成长域**单段 UA** 区分 | **已做**（§1.2：对话与官网领奖三段式，其余单段，与面板 `billingUA()` 一致） | 不做：计费/成长请求带着对话形态的 UA，与官方 banner 形态不符 |
| `X-Device-Token` 设备风控头 | **已做**（§1.2：provider config `workbuddy_device_token`，有就注入、没有照常发） | 不做：该头缺失（面板同样「读不到就不注入」，属优雅降级） |
| `prompt_cache_key` 注入（P0 费用优化） | **已做**（§2.1：账号隔离键 `wb2a-<uid8>-<convHex>`，客户端值不覆盖；入站 `X-Conversation-ID` 那一级未接） | 不做：上游前缀缓存命中率为 0，**费用约 17 倍**（面板逆向实测） |
| global 档位静态兜底表 | **已做**（§2.1：18 个模型的产品级兜底，仅 global 生效；远端非空则权威） | 不做：global 账号发不支持的档位 → **非法参数 400** |
| 截断工具调用清理 | **已做**（§2.2：`length` 截断时丢弃参数残缺的调用，避免客户端解析非法 JSON 卡死会话） | 不做：客户端可能收到半截 JSON 参数 |
| 用量规范化（缓存命中别名 / `total_tokens`） | **已做**（§2.2：同步与流式都做；别名回写取第一个正数命中，total 只在两边都在时补） | 不做：缓存命中被 0 别名盖掉、严格 schema 客户端缺 `total_tokens` |
| 流式「未收 `[DONE]`」的原生 `tool_calls` 截断清理 | **未做**（需聚合整条流；与逐帧透传冲突，取舍见 §2.2） | 上游连接被截断且未发收尾帧时，残缺参数仍可能透传 |
| DSML 工具调用还原（非流式 + 流式） | **已做**（§2.2） | 不做：工具调用落成正文、**工具一次都不执行**且回合直接结束（静默失败） |
| 内容被拦后的降级 | **已做**（§2.3） | 不做：`append`/`passthrough` 模式下模板句一直撞 400 |
| 面板那种**同请求内**换降级提示词重试 | **已等价覆盖**（§2.3：Aether 默认为 4xx 换号重试，降级闸门让重试那一跳带上中性提示词；**单账号池除外**） | 单账号池时仍可能把 400 透传一次 |
| 请求级错误（11101/11115/11135）不换号 | **已做**（§2.3：由 provider config 默认值自动下发，建供应商即生效；显式配置优先） | 不做的话这类错误也会换号，白白消耗健康账号的额度 |
| 失败分类 + 凭证作废 + pool 硬状态 | **已做**（§2.4） | 未接的部分见下面两行 |
| `11102` 的「账号×模型」负缓存 | **已做**（§2.4 第 3 条：按 (账号, 模型) 排除 6h→24h 退避，账号本身照常服务其它模型；写失败路径 + 池适配器读取，**无需改调度器**） | 不做：同一账号会被反复路由到它不支持的模型，每次白撞一次上游 |
| WAF 403 的**出口 IP** 维度冷却 | **已做**（`orchestration/waf_ip.rs` + `dispatch/pool_scheduler.rs`：60s 滑窗内**两个不同账号**接连命中 WAF 403 → 判定出口 IP 被拦；默认比面板更严一档**连新请求一起挡**，可用 `waf_ip_block_new_requests=false` 完全对齐面板，`waf_ip_cooldown_seconds=0` 整项关停） | 跨进程多实例部署时该状态是**进程内**的（单实例部署无影响） |
| 按 `Retry-After` 精确算冷却时长 | **已由通用机制覆盖**（`parse_retry_after_seconds` → `resolve_transient_cooldown_ttl`，作用于 429/503） | 402/14018 走的 `QuotaExhausted` 不用 Retry-After（按额度重置处理） |
| 余额/额度刷新（个人 + 企业） | **已做**（§2.5，随账号自检定时执行） | 不做：后台看不到余额、耗尽的号不被避开 |
| 每日签到（`daily-checkin`） | **已做**（§2.6：随余额刷新自动执行；企业号跳过，「今天已签到」算非失败） | 不做：每日赠送积分不会自动领取 |
| global trial 加油包（`/billing/ide/trial`） | **已做**（§2.6：global 专属、无 body；幂等码 14051 视为正常） | 不做：**国际号唯一的积分增益动作**缺失（global 无签到、无任务中心） |
| 保活（token 刷新） | **已做**（§2.7：复用通用定时刷新，附测试钉子） | 不做：access token 过期只能等下一次请求触发刷新 |
| 活跃上报（`/v2/report`） | **已做**（§2.7：随当日首次签到触发，企业号跳过） | 不做：growth 连登点不亮、first_buddy 领养前置不满足 |
| 成长中心：连登兑换 + 抽奖 | **已做**（§2.8：随当日首次签到触发，企业/国际号跳过） | 不做：连登档位的 credit/energy/抽奖次数领不到 |
| 成长中心：补签保连登 / 新手礼包 / 补偿 | **已做**（§2.8：补签在兑换之前，礼包/补偿各一次） | 不做：漏签一天就要重攒 7 天连登；礼包与补偿积分不会自动领 |
| 成长任务（报名 + 领奖） | **已做**（§2.9：双口径列表去重 → 分组报名 → 领奖走官网域，每轮上限 20） | 不做：任务积分不会自动领 |
| 猫猫旅行（`travel.go`） | **已做**（§2.10：状态机 + 领养链路，随当日首次签到触发，企业/国际号跳过） | 不做：派遣与到站奖励（积分）拿不到，也没有领养的那 300 分 |
| 开学季限时活动（`school.go`） | **未做**（活动期 2026-09-13~09-24 已过） | 分享 +100c / 转盘抽奖不会跑（限时活动，价值随时间归零） |
| 夜猫子（`blackcat.go`） | **已做**（v15：仅 23:00–08:00 窗口内按缺口发 glm-5.2 真实对话；窗口外不发请求） | —— |
| 桌面事件模拟动作（`desktop.go`） | **已做**（纯事件子集，§2.13）| —— |
| 桌面事件里**需真实对话**的动作（`skill_1` / `expert_5` / `Expert_team_use_3` / `Expert_lighthouse`） | **已做**（v15，Tier 2：先发流式对话取**服务端 `requestId`**，再发 `skill_info` / `expert_actual_use`；取不到 id 就不发） | —— |
| `6004` **模型级限流** → 只锁 (账号, 模型) | **已做** | —— |
| 模型锁池**聚合视图** + UI 表 | **已做**（前端从 keys 元数据聚合，面板 `ModelLockView` 等价物；v11 起按 **(域, 模型)** 分组、分母=**该域可选号**、四态：全部锁定/部分锁定/仅展示/无可用号 starved） | —— |
| 上游目录**能力/倍率/上下文全字段 + realm 分域** | **已做**（v11：快照存 `realm` + `supports_images/reasoning/tool_call` + `efforts/default_effort/can_disable_thinking` + `context_window/max_tokens/max_allowed_size` + `tags/description`；前端独立表「上游模型能力与倍率」按域列 + 能力徽章 + 上下文/输出；强制重拉目录 `POST /api/admin/provider-query/models {force_refresh:true}` 后 17/17 模型带字段） | 不做的话：能力列只能显示「未声明能力」（Aether `effective_supports_*` 对导入模型全 false，数据在上游 `/v3/config` 目录里） |
| global 账号注册 / 区域选择（`global_register.go`） | **已做**（`aether-provider/transport/src/workbuddy/global_register.rs` + 额度刷新的自动补注册：检出未注册的 global 账号 → 按**白名单国家**补注册 → 激活；真机验证 `global_registration = {"status":"activated"}`） | —— |
| `error.gateway_hint` 错误补充字段（`hint.go`） | **已做**（`aether-ai/formats/src/formats/shared/gateway_hint.rs`：**不替换** `message`、未覆盖形态**不带字段**、措辞一律英文；`api/response.rs` 与 `formats/shared/error_body.rs` 两条路径都接了） | 只覆盖已知形态；新形态需要同步补表 |
| 昵称刷新（`profile.go`：改名后免重登同步） | **已做**（`oauth/quota/workbuddy.rs` 拉 `/console/account` + `endpoint_keys/quota.rs` 落库 `account.nickname`；失败原因也落库 `account.nickname_error` 便于排查；**只取昵称+uid**，手机号等其它字段不落库） | 只在**手动刷新额度**时执行（与面板同款约束） |
| 模型目录拉取（`/v3/config`） | **已做**（§2.11） | 不做：模型只能手工维护，上游新增模型不会自动出现 |
| 非对话模型过滤 | **已做**（§2.11：补全类前缀 / 输出上限 ≤256 / 图片视频 tag 一律不进对话模型列表） | 不做：用户选中补全或图片模型后必然失败 |
| global 侧 `/v3/config` **两路探测** | **已做**（§2.11：global 用 IDE UA + CLI UA 各探一次，按 id 合并、主路优先；第二路失败不影响主路） | 不做：global 账号会**少看到 CLI 专属模型**（如 `deepseek-v4.1-flash` / `gpt-6-astra`） |
| context/输出上限的静态兜底 | **已做**（见下方「池化：context/输出上限静态兜底」一行：上游值 >0 权威 → 静态知识表 → 上下文 1M 兜底、输出未知则省略字段） | 单看快照分不清值来自上游还是兜底 |
| 额度/积分面板 + 任务中心 | **已做**（方案 A：账号卡片额度进度/资源包/维护徽章 + 任务中心明细表，含真实 `tasks_detail` 18 条；v11 起与目录快照同桶共存、互相不抹） | 旅行/夜猫子等**养成数据**仍未单独展示（无 UI 需求确认） |
| 池化：会话粘性 TTL | **已做**（v12：高级设置新增「会话粘性」区块；后端本来就每请求解析 → 改动即时生效、**无需重启**） | 不做：粘性 TTL 只能手改原始 JSON |
| 池化：连败降权三件套（阈值 / 时长 / 上限） | **已做**（v13：只作用于**「未分类错误」分支**——该分支此前完全空转，所以已分类路径零改动；计数器带 TTL 自衰减、成功即打断、可超过 32 分钟全局封顶） | 不做：账号持续回未分类错误也不会被临时出池 |
| 池化：`429` 软限流退避上限（面板 `softRateMax`） | **已做**（v14：`Retry-After` 优先、不参与退避；`上限 ≤ 基础冷却` = 关闭退避 = 与旧行为逐字节一致） | 不做：连续 429 的账号永远只按固定基数冷却 |
| 池化：快过期路由窗口 + 快过期积分优先 | **已做**（v16：窗口默认 7 天、加分默认 0.10；判据 = `packages[].expires_at` 在窗口内**且仍在未来**；窗口 0 = 关闭分桶，开关关闭 = 不加分；`score_reason` 里带 `expiring_credits` / `expiring_bonus` 便于核对） | —— |
| 池化：限时优惠 `modelPromotions`（生效价/折扣/徽章） | **已做**（v17：解析 `modelPromotions`（含 `discount` 与 `daily` 时段）→ 写进目录快照 → 前端列展示**生效价**（划线牌价 + 徽章）；真机 PG 直读证实 4 个模型带 `promo_*`） | —— |
| 池化：积分保底 `credit_floor`（绝对余额下限 + 只拦收费模型） | **已做**（v21：默认 0=关闭、边界不拦、免费/未知倍率放行；收费判据取**生效价**，前缀/后缀 `x` 两种倍率写法都认；落在**池内硬排除**，池内无候选即 503；真机对照 5/5 ✓） | —— |
| 池化：连败熔断阈值可配 + 池内是否计入熔断 | **已做**（`breaker_threshold` **默认 3** ✓、`pool_counts_toward_circuit_breaker` **默认 true** ✓ —— 两者默认值都已改成**面板口径**，显式值仍可回到旧行为；真机对照实验**因果成立** ✓） | 阈值的端到端效果无真机证据（无法安全制造连续 5xx）|
| 池化：global 域在途上限分档 + 单账号最大在途 | **已做**（`max_in_flight_global` **默认 2** ✓、`max_in_flight` **默认 3** ✓ —— 均为面板口径，三段式与面板 `inFlightLimit` 逐字对应；按 `realm` 改写该 key 生效并发上限；单测 + 配置往返 ✓；真机已看到 global 号被压到 2 ✓） | —— |
| 池化：闲置补偿（加权路由） | **已做**（v25：`idle_weight_per_hour` 默认 0.5、`idle_weight_max` 默认 5.0（面板同款）；`0`=关闭；落在打分器的 `idle_bonus`，位于惩罚之后、不可调度上限之前；`score_reason` 透出 `idle_seconds`/`idle_bonus`） | **有意差异**：从未使用过的账号按 0 计（面板按满额），见正文说明 |
| 池化：熔断基础时长 / 退避上限 | **已做**（`breaker_cooldown_minutes` **默认 30 分钟** ✓、`breaker_cooldown_max_minutes` **默认 360 分钟 = 6h** ✓ —— 均为面板口径；显式 `0` 才回到历史值 1 分钟 / 32 分钟；另有 24h 安全天花板） | 退避时长无真机端到端证据（无法安全制造连续 5xx）|
| 池化：成本探索窗口（costTier 条件探索） | **已做**（`cost_explore_interval_seconds` **默认 1800 秒 = 30 分钟** ✓ = 面板口径，显式 `0` = 关停；免费层垄断 + 未观测号到期时改选它去探路；纯函数单测 + 配置断言） | 端到端无真机证据（现网两个账号分属不同域，构造不出该场景）|
| 池化：context/输出上限静态兜底 | **已做**（v28：上游值 >0 权威 → 静态知识表 19 条（照抄面板）→ 上下文 1M 兜底；输出上限未知则**省略字段**；真机 17 个模型「缺上下文 = 无、非法输出 = 无」✓） | 单看快照分不清值来自上游还是兜底 |

---

## 5. 验证

```powershell
# 工具链（本机实测环境；脚本在仓库上一级目录，由 vcvars64 生成，勿提交）
. ..\dev-env.ps1            # MSVC + cargo + NASM + LIBCLANG_PATH
cargo check -p aether-gateway --lib

# 本次改动相关的单测（**只列命令，不写条数** —— 写死数字必然随迭代漂掉 ✗）
cargo test -p aether-oauth --lib workbuddy
cargo test -p aether-provider-transport --lib workbuddy
cargo test -p aether-provider-pool --lib workbuddy
cargo test -p aether-admin --lib workbuddy_balance
cargo test -p aether-model-fetch --lib workbuddy
cargo test -p aether-ai-formats --lib workbuddy_dsml
cargo test -p aether-gateway --lib workbuddy
cargo test -p aether-data-postgres --lib candidate_selection
cargo test -p aether-gateway --test architecture_guard
cd frontend && npm run type-check                              # vue-tsc
cd frontend && npm run test:run -- src/features/pool/utils/__tests__/poolAdvancedDefaults.spec.ts
```

CI：`gateway-build.yml`（push main / PR / 手动派发）与 `rust-ci.yml`。
**功能分支 push 不触发 `gateway-build.yml`**，需要二进制时显式派发：

```powershell
gh workflow run gateway-build.yml -R MingLoong/Aether --ref <branch> -f target=aether-gateway
```

部署：按 `docs/operations/MAINTENANCE.md`——生产 `<部署机 IP>`、`aether-gateway.service`、
端口 8084、`/opt/aether/current`；前端改动需要 `vue-tsc -b --force` + `vite build` 后
部署 `dist`。

**上线与真机验证的操作单**（补丁应用 → CI 派发 → 发布布局 → 逐步验证清单 → 失败排查表 →
回滚）见 [`workbuddy-deployment.md`](./workbuddy-deployment.md)。

---

## 6. 已知边界与风险

- **上游不可测**：本机无法直连 `copilot.tencent.com`，所有上游契约来自面板源码与注释；
  首次上线应先用一个真实账号验证：设备授权、一次对话（含工具调用）、余额刷新、目录拉取。
- **面板模板句改写表未移植**（§2.1）：只做了结构化剥离 + 裸 `11-128` 改写。
- **默认 `custom` 会覆盖客户端 system 提示词**：想保留客户端人格就把
  `workbuddy_prompt_mode` 设成 `append`/`passthrough`，代价是模板句误报重新出现。
- **降级不是同请求内重试**（§2.3）：本次请求仍可能返回 400。
- **额度快照白名单**（§2.5）：`unlimited` 等自定义字段不进快照。
- **计费域与对话域不是一个域**（§2.5 / §2.7）：余额、签到、活跃上报走
  `www.codebuddy.cn`（国际 `www.workbuddy.ai`），对话与 `/v3/config` 走
  `copilot.tencent.com`；两者混用会 404 或被 origin 白名单拒。
- **`X-Machine-ID` / `X-Session-ID` 是派生值**而非真机指纹：面板用真机指纹，
  我们用 `sha256("wb2a:" + purpose + ":" + uid)` 稳定派生——同一账号每次一致，
  但跨账号不同（刻意如此：避免把同一台机器的指纹复制给所有账号）。
- **配置漂移**：`base_url` 改动会被固定模板记进 `overrides`（reconcile 不会冲掉），
  但 `custom_path` / stream 策略是模板强制的，改动会在 reconcile 时被拉回。
