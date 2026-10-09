# TypeSafe System One（OpenCode Jev）接入说明

> 状态：**已实现、已部署、已验证**。本文描述线上行为，不是规划。

本文回答：Aether 是怎么调用 OpenCode Zen 上的 `jev-1.13-free` 的，以及接入一个
同类格式时要动哪些地方。

---

## 1. 它不是对话模型

OpenCode Zen 提供 `jev-1.13-free`（免费）与 `jev-1.13`（付费）。它们是 TypeSafe AI
的 **System One** 模型：把一段 `state` 对着若干**类型化问题**求值，返回可被程序直接
消费的**数值与概率**，不生成自由文本。

因此它在 Aether 里是一种**独立的 api_format**：`typesafe:systemone`，走
`POST /v1/systemone`。

| 维度 | 普通 chat 模型 | System One |
| --- | --- | --- |
| 上游端点 | `/zen/v1/chat/completions` | `/zen/v1/systemone` |
| 请求体 | `messages` 数组 | `state` + `questions` 映射 |
| 响应体 | `choices[].message.content` | `answers.<qid>` + `usage` |
| 流式 | 支持 | **不支持** |
| 多余字段 | 容忍 | **严格拒绝** |

`state` 与全部问题合计的上下文预算为 64k tokens（`state` 加最长单问 32k）。
响应不含 request id，SDK 从响应头 `x-typesafe-request-id` 取。

---

## 2. 上游实测契约

以下结果均来自生产机直连 `https://opencode.ai` 的真实请求（脚本 `jevprobe.py` /
`jevprobe2.py`），**与官方文档不一致处已标注**。

### 2.1 鉴权

| 请求 | 结果 |
| --- | --- |
| `Authorization: Bearer public` + `jev-1.13-free` | **200** |
| 配置中的真实 provider key + `jev-1.13-free` | **401** `AuthError: Invalid API key.` |
| `Bearer public` + `jev-1.13`（付费） | **401** `Missing API key.` |
| 错误 model id | **401** `ModelError: Model no-such-model is not supported` |

免费模型走固定的 `Bearer public`；库中存储的 opencode 凭据是信封，打过去必 401。
**这也是当前无法支持付费 `jev-1.13` 的唯一原因**（没有可用的 console key）。

### 2.2 指纹：不需要

不带 `x-session-id`、或把 `User-Agent` 换成 `curl/8.5.0`，响应字节完全相同。
即：systemone **不做** chat 那套 UA/session 指纹校验。这让注入面比 chat 小得多，
只需覆盖 `Authorization`。

### 2.3 严格模式：拒绝任何多余字段

| 请求 | 结果 |
| --- | --- |
| 正常 `state` + `questions` | 200 |
| 多加任意顶层字段 | **400** `{"detail":{"error_type":"api_usage_error","message":"Invalid request."}}` |
| 发 `messages` | 400（同上） |
| 加 `stream: true` | 400（同上） |
| 未知问题 `type` | 400（同上） |

> ⚠️ 错误形状不统一：`score` 超过 10 级返回 **400** 但 body 是纯字符串
> `{"detail":"Too many score levels. Must have at most 10 levels."}`；
> 缺 `state` / `questions` / `questions:{}` 返回 **422** 且文案为
> `{"error":{"type":"server_error","message":"Upstream request failed: Endpoint is unavailable."}}`，
> 与实际原因无关、有误导性。
> **文档与实现不符**：文档称 `score.criteria` 需 2–10 级，实测 1 级返回 200（下限未强制），
> 11 级返回 400（上限强制）。

这直接排除了"复用 `openai:chat`"：Aether 现有的 chat 注入（`stream: true` +
免费额度 4 个 tools + 指纹）一旦作用到 systemone 请求上会立刻 400。

### 2.4 响应样例（一次三问）

```json
{"model":"jev-1.13-free",
 "answers":{
   "department":{"type":"choice","choice":"returns","confidence":1,
                 "probabilities":{"returns":1,"shipping":0,"billing":0}},
   "frustration":{"type":"score","score":0.99,"confidence":0.98,
                  "legend":{"0":"Calm","1":"Frustrated","2":"Very angry"},
                  "probabilities":{"0":0.01,"1":0.99,"2":0}},
   "is_urgent":{"type":"noul","noul":0.72}},
 "usage":{"input_tokens":406,"output_tokens":73}}
```

- `noul` 是**概率浮点 0..1，不是布尔值**。
- `choice.criteria` 是 **map**（选项键 → 说明），`score.criteria` 是**有序数组**，
  `noul` 不需要 `criteria` 而用 `instructions`。
- `qid` 由调用方自定，不发给模型，只在响应回填。
- `instructions` 可以是字符串、对象或数组。

---

## 3. Aether 侧行为

### 3.1 客户端路由与请求校验

`POST /v1/systemone` 由 `classify_ai_public_route` 分类为
`route_class=ai_public`、`route_family=typesafe`、`route_kind=systemone`、
`auth_endpoint_signature=typesafe:systemone`，且是 execution runtime 候选。

**请求在网关侧先校验，不合格直接 400，不打上游**（避免把上游那个误导性的 422 传回给调用方）。拒绝条件：

| 条件 | detail |
| --- | --- |
| content-type 不是 `application/json` | `Systemone request content type must be application/json` |
| body 为空 / 不是合法 JSON 对象 | `Systemone request JSON body is invalid` |
| 缺 `model` 或非非空字符串 | `Systemone request model is required` |
| 缺 `state` | `Systemone request state is required` |
| `questions` 不是非空对象 | `Systemone request questions must be a non-empty object` |
| 存在白名单外的顶层键 | `Systemone request carries a field the endpoint does not accept` |

顶层白名单只有 4 个：`model`、`state`、`questions`、`instructions`。
`state` 只要求**键存在**，值可以是任意类型（字符串/对象/数组均可，与上游一致）。

### 3.2 同格式透传与鉴权覆盖

新格式按 `openai:rerank` 范式登记：

- `FormatFamily::Typesafe` / `FormatId::TypesafeSystemone`，`as_str()` 为
  `typesafe:systemone`；`FromStr` 同时接受 `typesafe_systemone` 与 `/v1/systemone`。
- `api_format_defaults_to_non_stream` 命中，**不使用** body 的 `stream` 字段。
- 同格式候选表只含自身，**不做任何跨格式转换**（`request_conversion_kind` 双向皆 `None`）。
- 计划类型 `typesafe_systemone_sync`，只注册同步 plan，**没有流式 plan**。
- 无 finalize 报告类型（与 rerank 相同），唯一成功报告类型是
  `typesafe_systemone_sync_success`。

opencode 上游 header 覆盖是**独占分支**：只插入 `authorization: Bearer public`，
**不注入** `User-Agent`、`x-session-id`、`accept`，body 语义也完全不改
（`apply_opencode_request_body_semantics` 对非 `openai:chat` 自然早退）。

### 3.3 端点模板与 reconcile

opencode 固定供应商模板 `OPENCODE_FIXED_PROVIDER_TEMPLATE` 由 version 1 提升到
**version 2**，新增第 2 个端点项：

```
item_key   typesafe:systemone
api_format typesafe:systemone
custom_path /zen/v1/systemone
```

版本号一升，固定供应商 reconcile 任务（`maintenance.provider.fixed_template.reconcile`）
就会把该端点补到已有供应商上。**实测：重启后 5 秒自动出现，且既有 chat 端点未被停用。**

### 3.4 身份解析（曾经踩过的坑）

`control/auth/credentials.rs` 的 `select_primary_credential` 按 auth endpoint
signature 的**前缀**分派。`typesafe:` 原本不匹配任何家族，落到
`select_generic_credential`，而 generic 会**优先**把 `Authorization: Bearer`
提升为 `BearerToken` → `DeferredBearerToken` → 只有 Antigravity bearer 桥能解析，
且桥要求签名恰为 `antigravity:v1internal` → 返回 `None` → 永远拿不到 API-key
principal，表现为 `decision_input_unavailable` + HTTP 503（`auth_user_id` 为空）。

现在 `typesafe:` 与 `openai:` 同路径：`Authorization: Bearer` 被分类为
**provider API key**，走 key-hash 查库。

> 这条路径**没有**调用点报错兜底 —— 编译器不会因为一个前缀没登记而报错。

---

## 4. 数据与配置（新增同类模型时的必做项）

三件事，缺一不可：

1. **端点**：靠模板 version bump + reconcile 自动创建，无需手工插入。
2. **全局模型**：`global_models` 增加模型行。
3. **provider 模型行**：`models` 下挂到对应供应商，`provider_model_name` 与
   `global_model_name` 一致。

**最容易漏的一项 —— 供应商密钥的 `api_formats`**：
`provider_api_keys.api_formats` 是格式白名单，若只写 `["openai:chat"]`，
新格式端点在路由预览里会显示 `total_keys = 0`、`active_keys = 0`，候选直接被跳过。
必须追加：

```sql
UPDATE provider_api_keys
   SET api_formats = '["openai:chat","typesafe:systemone"]'::json, updated_at = now()
 WHERE id = '<opencode-key-id>' AND api_formats::text = '["openai:chat"]';
```

> 这一项只影响数据面，编译与单测都不覆盖它 —— 只能靠路由预览或端到端验证发现。

---

## 5. 验证（可证伪）

### 5.1 网关侧校验（不打上游）

| 用例 | 期望 | 实测 |
| --- | --- | --- |
| `stream: true` | 400 | 400 `carries a field the endpoint does not accept` |
| `messages` | 400 | 400 `state is required` |
| 缺 `state` | 400 | 400 `state is required` |
| `questions: {}` | 400 | 400 `questions must be a non-empty object` |
| 未知顶层字段 | 400 | 400 `carries a field the endpoint does not accept` |

判据：这 5 条必须是网关返回的 detail 文案，且**上游零调用**；若返回上游的 422
或带 `api_usage_error` 的 400，说明校验器没生效、是上游在回话。

### 5.2 正例

| 用例 | 期望 | 实测 |
| --- | --- | --- |
| noul + choice + score 三问 | 200，3 个 answers 键，token > 0 | **200**，`department`=returns / `frustration`=0.99 / `is_urgent`=0.72，`input_tokens=406`、`output_tokens=73` |
| `instructions` 为数组 | 200 | **200**，`input_tokens=281`、`output_tokens=20` |

### 5.3 用量落库

| 断言 | 实测 |
| --- | --- |
| `usage.api_format` / `endpoint_api_format` = `typesafe:systemone` | ✅ |
| `api_family` = `typesafe`、`endpoint_kind` = `systemone` | ✅ |
| `has_format_conversion` = `false` | ✅ |
| `user_id` / `api_key_id` 已填充 | ✅ |
| `provider_endpoint_id` = 新建的 systemone 端点 | ✅ `2379e37c-…` |
| 成功后 `status=completed`、`billing_status=settled`、`finalized_at` 非空 | ✅ |
| **token 非零落库** | ✅ `406/73` 与 `281/20` |
| 失败请求 `status=failed`、`billing_status=void` | ✅ |

> 注意 `finalize` 是**异步**的。请求完成后立刻查会看到 `input_tokens=0`、
> `status=pending/streaming`，几秒后再查才是 `completed/settled`。
> 用"查早了"的快照判定用量链路断裂会得出错误结论。

### 5.4 报告类型

`submit_sync_report` 只处理 `is_local_ai_sync_report_kind` 认识的报告类型，不认识就
丢弃并打 `execution_report_dropped` 警告。若 `typesafe_systemone_sync_success` 未登记，
**每次成功请求都会打一条警告**，并跳过报告效果。

判据：按 `report_kind` 分组统计 24 小时内的 `execution_report_dropped`，**必须为空**。
修复前该分组里只有 `typesafe_systemone_sync_success`（2 条），其他格式一条都没有 ——
这证明它是本功能引入的缺陷，而不是 rerank 也有的既有行为。

---

## 6. 已知限制与未解

| 项 | 说明 |
| --- | --- |
| 付费 `jev-1.13` 不可用 | 库中 opencode 凭据是信封，打过去 401；需真实 console key |
| 免费额度限时 | OpenCode 标注"限时免费"，可能随时下线 |
| 免费额度限额未公开 | 实测连续调用无 429；TypeSafe 文档列出 429/529，是否透出**未测** |
| 无流式 | 不提供 SSE；`require_streaming: false` |
| `request_type` 记为 `chat` | `infer_request_type` 只区分 `video`/`image`，其余默认 `chat`；rerank、embedding 同样记为 `chat`，**非本格式特有** |
| `openai:rerank` 的报告类型同样未登记 | `report.rs` 的 `is_local_ai_sync_report_kind` 里也没有 `openai_rerank_sync_success`。属既有问题，与本功能无关，**未改**（无法在生产验证 rerank 是否真的在跑） |
| 前端一等公民（候选格式矩阵、下拉、i18n） | 未做，属 P2 |

---

## 7. 资料来源

- OpenCode 模型与端点表、Jev 章节、定价、免费模型说明：<https://opencode.ai/v2/docs/console/models>
- TypeSafe API 契约与错误码：<https://docs.typesafe.ai/api>
- 三个原语（noul / choice / score）响应结构：<https://docs.typesafe.ai/primitives>
- 模型清单与限额：<https://docs.typesafe.ai/models>
- LiteLLM 的既有实现（provider 命名 `typesafe/jev-latest`，印证家族名用 `typesafe`）：<https://docs.litellm.ai/docs/decisions>
- OpenRouter 模型页（命名参考）：<https://openrouter.ai/typesafe-ai/jev-1.13>
- 社区实现交叉参考：<https://github.com/FFatTiger/new-api-plugin-typesafe>
- §2 全部实测：生产机脚本 `jevprobe.py` / `jevprobe2.py`（直连 `https://opencode.ai`，未经 Aether）
- §5 全部实测：生产机脚本 `jevdeploy2.sh` / `jevdata.sh` / `jeve2e.sh` / `jevusage.sh` / `jevwarn.sh`（经 Aether）
