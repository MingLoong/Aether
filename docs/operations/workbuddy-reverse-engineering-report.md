# WorkBuddy（腾讯 CodeBuddy）协议逆向工程报告

> 目的：记录本项目如何在**没有官方公开 API 文档**的前提下，还原腾讯 CodeBuddy / WorkBuddy
> 私有对话协议，并落地为一等供应商 `provider_type = "workbuddy"`。
> 事实来源与实现细节见 [`workbuddy-provider.md`](./workbuddy-provider.md)；本报告聚焦
> **逆向方法论与关键发现**。文中标「实测」的是真机证据，标「面板」的是从开源面板源码
> 得到、本仓未直接验证的契约，标「无真机证据」的是尚未在真机触发的推断。

---

## 1. 背景与目标

WorkBuddy / 腾讯 CodeBuddy 是一款 AI 编程助手，只提供**官方客户端**，不开放公开 API。
它的对话入口走的是一套**私有协议**：自定义域、强制请求头族、窄化的 OpenAI 兼容请求体、
业务错误码、以及内联在正文里的专有工具调用标记。

目标是让 Aether 能**直连上游**、自己管理账号池，对外暴露标准的
`/v1/chat/completions`（OpenAI 兼容）接口，等价于官方客户端的能力。

难点在于：上游协议**对客户端指纹敏感**——头、UA、请求体形态任一处不对，就会被
WAF / 业务码拦下，且错误往往藏在 HTTP 200 的业务 `code` 里，不是 HTTP 状态码。

---

## 2. 逆向的三层信息来源

逆向不是单点突破，而是三层证据互相印证、逐符号对齐：

### 2.1 第一层：开源面板（事实来源）

上游协议、URL、头族与判定口径的**主要来源**是开源项目
`linguo2625469/workbuddy2api-panel`（Go 实现）。它已经把同一套上游协议完整实现过一遍，
本仓按其源码与注释逐符号移植，重点参考文件：

- `internal/panel/login.go` — 登录 / 设备授权
- `internal/upstream/headers.go` — 出站头族（含会话/链路头生成）
- `internal/upstream/client.go` — 出站请求与请求体归一化（`prepareBody`）
- `internal/auth/auth.go` — 失败分类、签到口径
- `internal/upstream/{sanitize,tool_pairing,thinking,truncation,usage,sse}.go` — 指纹脱敏、
  工具配对、思维链、截断清理、用量与流式终止符规范化

**价值**：省去了从零猜协议的成本，并提供了大量「上游为什么这样要求」的注释。
**局限**：面板自身也会随上游漂移；本仓约定跨仓 `*.go:行号` 只作线索，仓内引用一律用
**符号名**而非行号（上游改一行行号即失效）。

### 2.2 第二层：官方桌面客户端静态分析

官方国际版桌面端安装在 `D:\Program Files\WorkBuddyAI`，是 Electron 应用。通过解包
`resources\app.asar` 得到客户端逻辑，确认：

- 对话由 `app.asar\cli` 里的 **Node CLI** 发出（不是渲染进程的 `fetch`）；
- 三段式 UA 的真实形态、版本段（如 `WorkBuddy/5.8.4 workbuddy-ai/5.8.4 CLI/2.161.0`）；
- 各端点的路径与请求体模板。

这一步纠正了早期仅凭「intl 逆向笔记」写错的 UA 平台段（详见 §3.4）。

### 2.3 第三层：动态插桩 + 对照实验（真机证据）

静态分析看不到**真正发出去的字节**，于是做动态插桩：

- **为什么不挂 Electron `webRequest`**：对话走 Node CLI，不经过 Electron 的
  `session.webRequest`——挂上去只能抓到遥测，抓不到有效对话头（实测结论）。
- **有效手段**：给 `resources\app.asar.unpacked\cli\bin\codebuddy` 临时插入一行
  `require(<hook>)`（**改前备份、抓完还原**），在 hook 里包装 `http/https.request`，
  把真实出站头逐条打印出来。
- **对照实验**：拿到真实头后，用**同一账号同一令牌**对上游逐项做二分测试
  （加 / 去某个头 → 看是否 200），确定每个头是否必需。

---

## 3. 关键发现（按逆向难度排序）

### 3.1 两个域，且「对话域」与「计费域」不是同一个域

- 对话 / 模型目录 / 成长：CN `https://copilot.tencent.com`，国际 `https://www.workbuddy.ai`
- 余额 / 签到 / 活跃上报（计费）：CN `www.codebuddy.cn`，国际 `www.workbuddy.ai`
- **混用会 404 或被 origin 白名单拒**——这是靠面板 + 实测撞出来的边界。

realm 判定：`auth_config.realm == "global"` 显式优先，否则账号域以 `workbuddy.ai` 结尾
算国际，其余 CN。

### 3.2 出站头族：缺一个就可能是 `403 code 11140`

所有 API 请求必带 `X-CodeBuddy-Request: 1`（风控闸门头），再叠加身份头
（`X-User-Id` / `X-Enterprise-Id` / `X-Domain`）、按 realm 的 `Origin`/`Referer`/
`Accept-Language`，以及**派生指纹**：

- `X-Machine-ID` / `X-Session-ID` = `sha256("wb2a:" + purpose + ":" + uid)`
  取前 **18 字节 hex**（36 个 hex 字符）。
- 与面板差异：面板用真机指纹，本仓刻意用**账号派生**值——同一账号每次一致、跨账号不同，
  避免把同一台机器指纹复制给所有账号。

**UA 分两类**（上游对 UA 敏感）：对话端点用**三段式**
`WorkBuddy/{ver} {WorkBuddy|workbuddy-ai}/{ver} CLI/{cli}`；计费/成长端点用**单段**
`WorkBuddy/{ver}`（官方 banner 显式覆写形态）。

### 3.3 国际域「渠道校验」——一次典型的插桩定位（案例）

**症状**：`workbuddy-global` 导入成功、额度正常，但所有对话返回
`HTTP 400 {"code":11128,"msg":"request illegal"}`（displayTips：「没通过渠道校验，
可能不是官方客户端发出的」）。

**定位**：按 §2.3 插桩官方 CLI 捕获真实出站头，再**逐项二分**（同一账号同一令牌）：

| 头 / 条件 | 是否必需 |
| --- | --- |
| `X-Conversation-ID`（UUID 形态） | 必需 |
| `X-Conversation-Request-ID` + `X-Conversation-Message-ID` | 必需（各单独出现不够） |
| `X-Root-Request-ID` / `X-Request-ID` | 随上两者同值即可 |
| body **首条消息是 `system`** | 必需（否则 `400 first message is not system prompt`） |
| 必须流式 | 必需（非流式恒 `400 code 11101`） |
| `X-Device-Token`、`x-stainless-*`、`traceparent`/`b3`、gzip 请求体 | 非必需（去掉均 200） |

**结论**：取值**无需服务端真实会话**——随机 UUID + 32 hex 实测通过。CN 域无此校验。
这一套「插桩抓真头 → 逐项二分」的方法可复用到任何对客户端指纹敏感的上游。

### 3.4 UA 平台段决定「模型目录」（8 个 vs 24 个）

上游按**客户端版本**下发 `GET /v3/config` 模型目录。早期实现把国际域平台段写成
`WorkBuddy AI`（来自 intl 逆向笔记），与插桩实测不符——真实值是 `workbuddy-ai`。

**写错的连带后果**：UA 不匹配时，同一接口只返回**旧客户端的 8 个别名**
（`auto-chat` / `balanced-model` / `primary-model` …），其中 4 个对话端点还会
`11102 service info not found`。改成 `workbuddy-ai` 后同一接口返回 **24 个真实模型**
（`glm-5.2` / `kimi-k2.6` / `gpt-5.5` …），`glm-5.2` 等实测 200 可用。

> 教训：**一个字符的指纹差异会静默地改变后端能力面**，且不报错——只能靠真机对照才发现。

### 3.5 认证：无 client_id / 无 PKCE / 无 user_code 的设备授权

- 建会话：`POST /v2/plugin/auth/state?platform=CLI` → `{state, authUrl}`
- 轮询：`GET /v2/plugin/auth/token?state=`（**pending 用业务 code ≠ 0 表达**，不是 HTTP 状态）
- 取账号：`GET /v2/plugin/login/account?state=` → uid
- 刷新：`POST /v2/plugin/auth/token/refresh`，**无 body**，凭证在 `X-Refresh-Token` 头 +
  `X-Auth-Refresh-Source: plugin`——通用 OAuth 刷新适配器（只认
  `grant_type=refresh_token`）表达不了，因此自建 `LocalOAuthRefreshAdapter`。

### 3.6 请求体：OpenAI 的「窄子集」+ 两层防误报

上游是 OpenAI Chat Completions 的窄子集，靠**逐字段实测**摸清边界：

- role 白名单**不含 `developer`**（要改写成 `system`）；
- 只认 `max_tokens`（`max_completion_tokens` 被忽略、长回答静默截断）；gpt 系还有下限 16；
- `tool_choice` 只认字符串；`image_url` 只接受对象形态；
- 缺 `stream_options.include_usage = true` 就**没有用量数据**（官方 CLI 流式必发）。

**两层防误报**（因为上游按指纹/模板句拦截，且失败藏在业务码里）：
1. **提示词替换**：客户端（Claude Code / Codex 形态）注入的 system 是固定模板句，
   上游**逐字精确匹配**整单拦截 → 默认用网关自有提示词覆盖；
2. **指纹脱敏**：剥离 `x-anthropic-billing-hdr` 键值段、循环清掉 `cc_*=…;`、把上游
   反探测的五位错误码 `11-128` 改写成插入 `U+002D` 的六字符形态（**零宽字符会被上游
   归一化，实测无效，必须用可见字符**）。

### 3.7 响应侧：工具调用是内联 `‖DSML‖` 文本，不是结构化字段

上游不直接返回 `tool_calls`，而是把调用写成正文里的 `‖DSML‖` 标记文本——只有当请求
声明了 `tools` 时上游才转成 `tool_calls`；某一跳丢了 `tools`，标记就落进正文，执行工具的
客户端会把标记当散文收下、**回合直接结束（静默失败）**。

本仓实现 `provider_compat/workbuddy_dsml/`：整块闭合校验、流式带回退缓冲的状态机、
`finish_reason=length` 时丢弃半截 JSON 参数、用量别名按可信度归一、保证至少一个
`[DONE]`、`tool_calls.name` 每个 index 只出现一次。**真机探测（4 个模型）目前都返回
原生 `tool_calls`，DSML 链路尚未在真机触发**——只有单测覆盖，触发条件待更多组合确认。

### 3.8 业务错误码语义（失败藏在 HTTP 200 里）

逆向出的关键码族（顺序照面板 `Classify`）：

| code | 含义 | 处置 |
| --- | --- | --- |
| `11158` | 套餐权限（免费号无权用 `gpt-5.5` 等） | 模型不可用，**非本地配置问题** |
| `11102` | 该后端无此模型（`service info not found`） | 账号×模型负缓存 |
| `12153` | 会话失效 | 作废凭证、强制刷新 |
| `11140` | 账号级授权风控 | 账号级拦截 |
| `14017` / `14018` | 试用未激活 / 积分耗尽 | `QuotaExhausted` |
| `11101` / `11115` / `11135` | 请求级错误 | **不罚号** |
| `11134` | 上游临时故障 | 短暂重试 |
| `6004` | 模型级限流 | 软限流 |

分类必须**顺序敏感**（如 429+余额文案按限流、429+14018 按欠费、403 无信封按 WAF），
否则会把「被 WAF 拦的健康号」误标死、或把「内容误报」当成账号封禁。

---

## 4. 逆向方法论小结（可复用）

1. **先找已有的等价实现**（开源面板），逐符号移植，省掉从零猜协议；但只当线索，
   关键契约仍要自己验。
2. **静态分析官方客户端**拿 UA / 版本 / 端点模板；**动态插桩**（hook `http/https.request`）
   拿真正出站的字节——尤其当流量不走常规 `webRequest`/`fetch` 时。
3. **逐项二分 + 对照实验**：同一账号同一令牌，只改一个变量（头 / UA / body 字段），
   看上游反应，把「必需 / 非必需」分清楚。
4. **失败语义要顺着业务码挖**：上游把失败藏在 HTTP 200 的 `code` 里，不能只看状态码；
   分类顺序本身也是被逆向出来的契约。
5. **诚实标注证据等级**：面板来的、真机实测的、无真机证据的，分开写——避免把推断
   当成契约（本仓文档大量使用「实测 ✓ / 面板 / 无真机证据 ✗」标注）。
6. **警惕静默的能力差异**：一个 UA 字符就让目录从 8 个变 24 个模型（§3.4），
   不报错，只能靠对照发现。

---

## 5. 关键踩坑记录

- **国际域渠道校验 11128**：三个会话头缺一即全站不可用（§3.3）——「能导入、有额度、
  就是不能聊」的根因。
- **UA 平台段 `workbuddy-ai`**：写成 `WorkBuddy AI` 导致目录只剩 8 个别名（§3.4）。
- **模型目录端点对 UA 敏感**：`GET /v3/config` 必须带官方 IDE 段，否则 `400 code=12403`；
  而对话域头注入会 `set` 覆盖同名头 → 必须**先注入头族、再覆盖** IDE UA。
- **候选 SQL 的两条 OR 白名单链都要有 workbuddy arm**：只加内层会出现「后台 test-model
  正常、客户端零候选」的诡异现象（外层把 key 筛掉了）。
- **工具配对三步顺序不能换**（合并 → 重排 → 清孤儿）：否则上游 `400` 拒整单，且失败的
  工具调用持久化进历史后，**之后每条消息都 400、整条会话报废**（换号也没用）。
- **`prompt_cache_key`**：面板逆向实测上游前缀缓存命中率为 0，不带该字段费用约 **17 倍**。
- **两域混用**：对话域与计费域不是同一域，混用 404 / 被 origin 白名单拒（§3.1）。

---

## 6. 验证方式

- 单测按 provider 符号分组（命令见 `workbuddy-provider.md` §5），**只列命令不写条数**
  （条数会随迭代漂移）。
- 架构护栏：`cargo test -p aether-gateway --test architecture_guard`
  （如「流改写矩阵必须由格式 crate 拥有」）。
- 前端：`vue-tsc` 类型检查 + vitest（号池高级默认值等）。
- 真机验证单见 [`workbuddy-deployment.md`](./workbuddy-deployment.md)：
  设备授权 → 一次对话（含工具调用）→ 余额刷新 → 目录拉取。

---

## 7. 诚实边界

- **上游不可测**：开发机无法直连 `copilot.tencent.com`，大量契约来自面板源码与注释；
  真机证据来自部署后的对照实验。
- **DSML 还原链路真机未触发**（§3.7）：只有单测覆盖。
- **WAF 出口 IP 闸门激活态无真机证据**：触发它得让上游真的对两个不同账号连发 WAF 403。
- **面板模板句改写表未完全移植**：目前只做结构化剥离 + 裸 `11-128` 改写。
- 本报告为**协议互操作性分析**文档，用于让自建网关与官方客户端在同一下游 API 上兼容，
  不包含绕过授权 / 访问控制的内容。
