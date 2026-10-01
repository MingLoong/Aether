# 模型负载控制（Model Load Control）规划书

> 状态：设计定稿，未实施
> 适用范围：`aether-gateway`（Rust workspace `Aether/`）
> 首次实测：2026-09-29
> 相关：`docs/operations/routing-scheduling.md`、`docs/operations/opencode-ip-pool-rebuild-plan.md`

---

## 1. 概要

给供应商增加一层**平台级模型负载感知**：上游平台会公开报告每个模型当前的容量占用
百分比，网关周期性拉取这个快照，负载超过阈值的模型在**该供应商上**被临时停用，
不再进入调度候选；负载回落后自动恢复。

粒度是 **供应商 × 模型**。同一个模型如果在别的供应商上有，该供应商不受影响。

> 设计约束：模型即使已经在管理端添加完成、也处于启用状态，负载判定仍然生效。
> 负载判定是运行时覆盖，不修改任何持久化配置。

> **本功能是 AMD 专用，不是通用框架。** 负载数据源
> `GET /radeon/api/tokenfactory/load`、URL 推导规则、fleet 级语义、
> `state` 的 idle/busy/full 取值，全部是 AMD 的专有约定。
> 不做供应商插件化、不做适配器层、不预留其他厂商的接入点。
> 模块、配置节点、结构体、Redis 键一律带 `amd_` 前缀，
> 目的是让任何读到代码的人立刻知道它的适用范围。
>
> 这个前缀**沿用 opencode 的既有实现**。`docs/operations/MAINTENANCE.md`
> 写明「所有新增逻辑均以 `provider_type == "opencode"` 守卫」，
> 现有代码已有 `opencode_proxy.rs` / `opencode_rotation.rs` /
> `transport/src/opencode.rs` / `provider.config.opencode_scan` /
> `OPENCODE_*` env / `opencode_pool:*` Redis 键。
>
> 需要说明的是，opencode 是**同构的先例，不是铺开的规范**。工程里
> 按 provider 拆配置节点的有 opencode / codex / kiro / claude_code 四个，
> 拆后台 worker 的有 opencode / codex / gemini 三个，
> 但**只有 opencode 一家**同时做到了：带 provider 名的 Redis 命名空间、
> 调度路径上的守卫、独立的 admin 路由与权限。
>
> 之所以照抄它，是因为本功能与 opencode 在架构形态上完全同构——
> 「上游平台级状态 → 运行时 Redis → 调度期过滤 → 后台轮询 → 独立管理面」，
> 这条链在工程里只出现过一次，就是 opencode。其余供应商的专属逻辑
> （codex 的客户端 profile、kiro 的缓存、claude_code 的高级选项）
> 都不涉及调度期过滤，形态不同，不能作为参照。

---

## 2. 背景

目标上游（AMD Radeon Cloud）是一个按 key 计费的免费额度平台，特点是：

- 模型目录**实时变化**，数小时内会上下架
- 模型可用性**时好时坏**，不是配额耗尽，而是平台侧推理容量波动
- 平台提供一个 fleet 级负载接口，报告每个模型的实时容量占用

已有的 `provider_api_keys.locked_models` 字段名字像是模型级禁用，但**调度器从不读它**
（只被模型抓取过滤和管理端 payload 使用）。因此 Aether 当前**不存在**任何
模型粒度的运行时禁用机制，本功能是新增的粒度。

已存在的运行时禁用机制粒度对照：

| 机制 | 作用域 | 检查位置 |
|---|---|---|
| `provider_quota_blocked` | 供应商 | `scheduler/candidate/runtime.rs:250` |
| `provider_concurrency_limit_reached` | 供应商 | `runtime.rs:247` |
| `oauth_invalid` | key | `runtime.rs:272` |
| `key_circuit_open` | key × api_format | `scheduler-core/health.rs:287` |
| `key_rpm_exhausted` | key | `health.rs:201` |
| `key_health_score_zero` | key × api_format | `health.rs:234` |
| `account_quota_exhausted` | key × 模型 | `runtime.rs:416-449` |
| **amd_model_load_high（本功能）** | **供应商 × 模型** | **新增** |

本功能不放在 `pool_group` 判断分支内，池供应商同样生效。

---

## 3. 实测依据

2026-09-29 用真实 `rc-` key 对目标上游实测，结论如下。**这些数字是阈值默认值的依据。**

### 3.1 负载接口

```
GET https://developer.amd.com.cn/radeon/api/tokenfactory/load
Authorization: Bearer <任意一把 enabled key>
```

响应：

```json
{"models":{"DeepSeek-V4-Flash":{"state":"busy","label":"Busy","utilization":77.4}},
 "scope":"fleet"}
```

`scope=fleet` 表示平台级，与具体 key 无关，取任意一把 key 即可。

**接口延迟：15 次采样 min=20.5s / p50=22.3s / max=23.3s。** 非常稳定地慢。
这一条直接决定轮询间隔下限与超时设置。

**模型会实时上下架：** 15 次采样中 `MinerU2.5-Pro` 在前 12 次的响应里缺失，
第 13 次重新出现。因此「目录里有模型但负载快照里没有」是正常状态，不能当作故障。

### 3.2 负载分布（15 次采样，约 5.5 分钟窗口）

| 模型 | min | p50 | max | mean | stdev | state |
|---|---|---|---|---|---|---|
| DeepSeek-V4-Flash | 66.1 | 78.6 | 88.0 | 77.4 | 6.1 | busy |
| DeepSeek-V4-Flash-Vision-Exp | 79.7 | 87.5 | 100.0 | 89.6 | 6.5 | busy, full |
| DeepSeek-V4.1-Flash | 100.0 | 100.0 | 100.0 | 100.0 | 0.0 | full |
| GLM-5.3-Flash | 100.0 | 100.0 | 100.0 | 100.0 | 0.0 | full |
| Qwen3.8-Flash-Next | 95.3 | 100.0 | 100.0 | 99.4 | 1.5 | full |
| MiMo-V2.6-Flash | 46.1 | 57.0 | 76.6 | 60.1 | 9.8 | busy, idle |
| Qwen3.8-27B | 11.7 | 13.1 | 14.6 | 13.5 | 0.9 | idle |
| MinerU2.5-Pro | 4.7 | 7.1 | 9.4 | 7.1 | 2.4 | idle |
| MiniCPM5-2B | 4.7 | 5.5 | 7.8 | 5.9 | 0.8 | idle |

各阈值下的越线率（样本中 utilization ≥ 阈值的比例）：

| 模型 | ≥70 | ≥75 | ≥80 | ≥85 | ≥90 |
|---|---|---|---|---|---|
| DeepSeek-V4-Flash | 87% | 73% | **27%** | **7%** | 0% |
| DeepSeek-V4-Flash-Vision-Exp | 100% | 100% | 93% | 80% | 47% |
| DeepSeek-V4.1-Flash | 100% | 100% | 100% | 100% | 100% |
| GLM-5.3-Flash | 100% | 100% | 100% | 100% | 100% |
| Qwen3.8-Flash-Next | 100% | 100% | 100% | 100% | 100% |
| MiMo-V2.6-Flash | 20% | 7% | 0% | 0% | 0% |
| 其余三个 | 0% | 0% | 0% | 0% | 0% |

**阈值选取依据：**

主力文本模型 `DeepSeek-V4-Flash` 的 p50=78.6、stdev=6.1，阈值 80 正好切在分布中部，
会导致 **27% 的轮询被禁用**——这是不可接受的抖动。阈值 85 将其降到 7%。

同时每轮可用模型数：

```
阈值 80 → 3~5 个，均值 3.9
阈值 85 → 3~5 个，均值 4.1
```

**85 的可用性略高且抖动降低到 1/4，严格更优。** 故默认 85。

### 3.3 state 与 utilization 不等价

`DeepSeek-V4-Flash-Vision-Exp` 曾出现 `state=full` 但 `utilization=80`。
**`state` 是 AMD 控制台自己的口径，比百分比更严格。** 判定时 state 优先。

### 3.4 HTTP/2（不构成阻塞）

amd 参考实现记录「HTTP/2 POST 被 nginx 拦成 400 HTML」。本次实测**未复现**：

```
HTTP/2    ok=8/8   median=1.46s
HTTP/1.1  ok=8/8   median=1.63s
```

仅首次冷启动出现过一次 70s 无响应（同期 HTTP/1.1 首次请求 27.4s，属冷启动）。
样本量小，不排除偶发，但**没有理由为此专门开发**。

Aether 已有现成开关，无需新增代码：

```rust
// crates/aether-contracts/src/plan.rs:137-139
TRANSPORT_HTTP_MODE_AUTO             = "auto"
TRANSPORT_HTTP_MODE_HTTP1_ONLY       = "http1_only"
TRANSPORT_HTTP_MODE_H2C_PRIOR_KNOWLEDGE = "h2c_prior_knowledge"
```

`http1_only` 会把 ALPN 限制为 `["http/1.1"]`（`crates/aether-ai/serving/src/decision_payload.rs:151-155`），
并在真实请求路径生效（`apps/aether-gateway/src/execution_runtime/transport.rs:4329`）。

**建供应商时填上 `http_mode: "http1_only"` 当保险，不作为必需项。**

### 3.5 账号配额接口（字段仍然损坏）

`GET /v1/usage` 可用，但：

```text
daily_cost_limit_usd      1
daily_cost_used_usd       0      ← 恒为 0，不可用
daily_cost_remaining_usd  1      ← 恒等于限额，不可用
today.cost                0.195  ← 真实值
rpm_limit                 20
```

参考实现的文档写「配额余量判断用 daily_cost_remaining_usd」，**这是错的**。
该接口目前只能用于展示。配额驱动的自动停用不在本功能范围内。

---

## 4. 范围与非目标

### 做

- 后台轮询 fleet 级负载快照
- 按阈值在**请求路径**上判定供应商 × 模型是否可用
- 判定结果进入调度跳过原因与遥测
- 管理端配置与展示
- 人工强制启用（带 TTL）

### 不做

- 不修改任何持久化的模型启用配置
- 不做模型目录的自动增删（目录刷新是独立功能）
- 不做账号配额驱动的停用（见 3.5）
- 不做跨供应商的模型级下线
- **不做通用化**：不为「其他供应商也许有负载接口」预留抽象
- 不主动探活模型（上游探针会消耗 RPM 且产生假信号，这是参考实现已踩过的坑）

---

## 5. 架构总览

```
┌──────────────────────────────────────────────────────────────┐
│  轮询任务（新增，每 provider 一条）                            │
│  间隔 poll_sec（默认 60s），单飞，不允许重叠                    │
│  超时 timeout_sec（默认 40s）                                  │
│  失败时依次换池内 enabled key 重试                              │
│  全部失败 → 保留旧快照 + 日志，不做任何启停决策                  │
└───────────────────────┬──────────────────────────────────────┘
                        │ 写入
                        ▼
        Redis  amd_load:<provider_id>       (hash, TTL 180s)
               amd_load_at:<provider_id>    (string)
               存原始值：state / util / at，不做阈值判定
                        │
                        │ 读取（每个请求一次，按 provider 去重）
                        ▼
┌──────────────────────────────────────────────────────────────┐
│  scheduler/candidate/runtime.rs                               │
│  :35  read_amd_load_block_map()    ← 新增，每 provider 一次    │
│  :24  CandidateRuntimeSelectionSnapshot                       │
│          + amd_load_blocks: BTreeMap<String, BTreeSet<String>> │
│  :242 current_candidate_runtime_skip_reason()                 │
│          + if 命中 → return Some("amd_model_load_high")       │
└───────────────────────┬──────────────────────────────────────┘
                        │
                        ▼
        候选列表中该供应商的该模型被剔除
        同一模型在其它供应商上不受影响
```

**阈值在读取时判定，不在轮询时判定。** 好处：

1. 改配置立即生效，不用等下一次 22s 的轮询
2. Redis 存原始值，面板可以同时显示「当前 78.4」和「阈值 85 → 未禁用」，调参有实时反馈

---

## 6. 配置规格

### 6.1 存储位置

`providers.config`（**json text，不是 jsonb**——`json_set` / `json_array_length` 不可用，
必须走 Python 往返或 `$$...$$` SQL 字面量）。

```json
{
  "amd_load": {
    "enabled": true,
    "poll_sec": 60,
    "disable_threshold": 85,
    "recovery_threshold": null,
    "disable_streak": 2,
    "snapshot_ttl_sec": 180,
    "timeout_sec": 40
  }
}
```

配置节点名为 `amd_load`，只有 AMD 供应商会带这个节点。

### 6.2 字段定义

| 字段 | 含义 | 默认 | 范围 | env 兜底 |
|---|---|---|---|---|
| `enabled` | 总开关 | `false` | bool | `AMD_LOAD_ENABLED` |
| `poll_sec` | 轮询间隔（秒） | `60` | `30..3600` | `AMD_LOAD_POLL_SEC` |
| `disable_threshold` | 禁用阈值（%） | `85.0` | `(0, 100]` | `AMD_LOAD_DISABLE_THRESHOLD` |
| `recovery_threshold` | 恢复阈值（%） | `null` → 同 `disable_threshold` | `null` 或 `(0, 100]` | `AMD_LOAD_RECOVERY_THRESHOLD` |
| `disable_streak` | 连续几次越线才禁用 | `2` | `1..10` | `AMD_LOAD_DISABLE_STREAK` |
| `snapshot_ttl_sec` | 快照有效期（秒） | `180` | `>= poll_sec * 2` | `AMD_LOAD_SNAPSHOT_TTL_SEC` |
| `timeout_sec` | 单次请求超时（秒） | `40` | `10..120` | `AMD_LOAD_TIMEOUT_SEC` |

`poll_sec` 下限 30 是硬约束：接口本身要 22s，低于 30 会导致请求堆叠。

provider 未配置 `amd_load` 节点时整块走 env 默认值。

### 6.3 配置结构

```rust
pub(crate) struct AmdLoadConfig {
    pub enabled: bool,
    pub poll_sec: u64,
    pub disable_threshold: f64,
    pub recovery_threshold: Option<f64>,
    pub disable_streak: u32,
    pub snapshot_ttl_sec: u64,
    pub timeout_sec: u64,
}

impl AmdLoadConfig {
    /// 有效恢复阈值：未配置时等于禁用阈值（即单阈值，无滞回）
    pub fn effective_recovery(&self) -> f64;
    /// 合并 payload 与 env 默认值，参考 OpenCodeScanConfig::merged_with_payload
    pub fn merged_with_payload(&self, payload: Option<&Value>) -> Self;
}
```

### 6.4 校验规则

保存时拒绝：

- `disable_threshold` 或 `recovery_threshold` 不在 `(0, 100]`
- `poll_sec` < 30
- `snapshot_ttl_sec` < `poll_sec * 2`（否则快照会在下一次轮询完成前过期）
- `disable_streak` < 1

保存时告警但不拒绝：

- `recovery_threshold >= disable_threshold`（反向滞回，会造成抖动）
- `disable_threshold < 50`（按 3.2 的分布，几乎所有模型都会被禁用）

---

## 7. 判定规则

对候选 `(provider_id, selected_provider_model_name)`：

```
1. provider 未启用 amd_load           → 放行
2. 快照不存在                          → 放行（无数据不判定）
3. 快照过期（now - at > ttl）            → 放行（过期不判定）
4. 该模型在快照中缺失                    → 放行（可能刚上架或下架）
5. state == "full"                      → 禁用
6. util >= disable_threshold            → 禁用
7. util <= recovery_threshold           → 放行
8. 介于两者之间                          → 保持当前状态（仅在配置了 recovery 时存在）
```

单阈值模式下（`recovery_threshold` 为空）7 与 8 合并为 `util < disable_threshold → 放行`。

### 7.1 disable_streak 的状态保持

`disable_streak` 需要在**轮询侧**维护连续越线计数，计数存 Redis：

```
amd_load_streak:<provider_id>   hash   model -> 连续越线次数
```

每次轮询写入后：计数 ≥ `disable_streak` 才写进禁用集合，否则清零。

若改为**在读取时用快照历史判定**则需要保留多次历史，复杂度更高。
本方案采用轮询侧计数，实现简单，代价是改 `disable_streak` 需要下一轮才生效。

**注意：这与「阈值在读取时判定」不冲突**——阈值在读取时判定，连续次数在轮询时累计，
两者最终都落在禁用集合的构造上。

### 7.2 全禁保护

轮询结束后若该 provider 的**全部**模型都在禁用集合中，
保留 utilization 最低的那一个，从禁用集合中移除。

按 3.2 的数据，各阈值下每轮最少可用模型数为 3，该保护不会常态触发，作为兜底。

### 7.3 人工覆盖

`POST .../model-load/force-enable` 设置：

```
amd_load_override:<provider_id>   hash   model -> 过期时间戳
TTL = force_ttl_sec（默认 300）
```

覆盖生效期间该模型无条件放行。TTL 到期自动回到自动判定。

### 7.4 与既有冷却机制的关系

本功能与既有冷却**不冲突**，四个维度全部不同：

| | 本功能 | 既有冷却 |
|---|---|---|
| 粒度 | 供应商 × 模型 | 供应商 / key / key × api_format |
| 信号 | 上游平台容量报告 | 账号配额 / RPM / 熔断 |
| 存储 | Redis 快照 | DB 列（`status_snapshot` / `health_by_format` / `circuit_breaker_by_format`） |
| 出口 reason | `amd_model_load_high` | `account_quota_exhausted` / `key_circuit_open` 等 |

在 `current_candidate_runtime_skip_reason` 中它们是同一个 `Option<&'static str>`
的不同返回路径。任意一个命中即挡住候选，reason 字符串只影响遥测归类，不影响行为。
两者可同时命中，无互斥、无覆盖。

#### 既有实现的一处限制（不修改，但需规避配置）

`runtime.rs:408-454` 的 `read_key_account_quota_exhaustion_map`
虽然把 `candidate.selected_provider_model_name` 传给了
`..._model_quota_exhausted(...)`，但返回值被折叠成 `BTreeMap<String, bool>`，
**仅以 `key_id` 为键**（`runtime.rs:451`）。

同一把 key 服务多个模型、其中仅一个配额耗尽时，会产生两个同键结果，
`collect()` 时后者覆盖前者。`quota.rs:76-120` 的模型桶解析在调度路径上因此退化为
key 级判定，且哪个模型被误判取决于候选迭代顺序。

**本功能不依赖该路径**，且本功能用 `BTreeMap<provider_id, BTreeSet<model>>`
（集合而非布尔），不存在该问题。

**AMD 池模式配置决策：开池。**

10 把 key 是 10 个独立组织，各 `rpm_limit=20`、`$1/天`，把它们当一个池来调度
正是该供应商的价值所在。池模式提供在途感知、负载最小优先、粘性会话等 key 选择质量；
不开池虽然 10 把 key 仍是 10 个独立候选（每 `key_id` 一行），但选 key 退化为普通轮询，
没有在途感知。

开池的代价与补偿：

```text
开池 →  pool_group == true
     →  runtime.rs:272 的 !pool_group 使 account_quota_exhausted 整条失效
     →  失去「配额预判」（429 之前就知道 key 已死）
     →  换来「429 冷却兜底」（收到 429 后冷却该 key × 模型）
```

**这使 429 模型级冷却从可选增强变成开池模式的必要配套**，详见第 16 节。

因此 `pool_advanced.skip_exhausted_accounts` 在开池时**不参与判断**
（`!pool_group` 已先将其短路），无需配置。

另一项无关项：AMD 注册为 `provider_type: custom`，走 `provider.rs:66-91` 默认适配器，
其 `quota_hard_blocked` 恒为 `false`（`provider.rs:88-90`），无需担心 hard block 分支。

---

## 8. 存储设计

**引擎的 Redis 层没有 hash 原语**——`RuntimeState` 只暴露 `kv_set` / `kv_get` /
`kv_getdel` / `kv_exists` / `kv_delete` / `kv_ttl_seconds`（`crates/aether-runtime/state/src/lib.rs:358-467`），
底层 `RedisKvRunner` 只实现 `SETEX` / `GET` / `GETDEL` / `EXISTS` / `DEL`，
全仓无 `.hset(` / `.hgetall(`。因此**所有结构化数据序列化成 JSON 存进单个 string 键**，
这与 `upstream_models:{provider_id}:{key_id}` 的既有做法一致
（`handlers/admin/provider/query/models/mod.rs:403-424`）。

| 键 | 内容 | TTL |
|---|---|---|
| `amd_load:<provider_id>` | 负载快照 JSON，见下 | `snapshot_ttl_sec`（180） |
| `amd_load_streak:<provider_id>` | 连续越线计数 JSON | `snapshot_ttl_sec * 4` |

```json
{
  "fetched_at": 1790682923,
  "scope": "fleet",
  "models": {
    "DeepSeek-V4-Flash": {
      "state": "busy", "utilization": 77.4,
      "streak": 1, "blocked_prev": false
    }
  }
}
```

**`blocked_prev` 为什么要在快照里**：滞回带内（`recovery < util < disable`）
判定为「保持当前状态」，需要知道上一轮的结论。它存在快照里，读取时按当前阈值重算，
这样**改阈值仍然立即生效**（只有 `disable_streak` 需要等下一轮，已在 7.1 说明）。

`amd_load_at` 单独键不需要——`fetched_at` 已在快照内。

**为什么放 Redis 不放 DB**：每次请求都要读（热路径），数据量小，TTL 天然过期。
面板展示直接读同一个键即可，初版不额外落库。

---

## 9. 轮询器

### 9.1 URL 推导

目标上游 `upstream_base` 形如 `https://.../radeon/api/v1`，
负载端点在同源的 `/radeon/api/tokenfactory/load`。

```rust
fn token_factory_load_url(base: &str) -> String {
    let base = base.trim_end_matches('/');
    match base.find("/radeon/api/v1") {
        Some(i) => format!("{}/radeon/api/tokenfactory/load", &base[..i]),
        None => format!("{}/tokenfactory/load", base),  // 兜底，失败仅告警
    }
}
```

### 9.2 轮询流程

```
1. 取该 provider 的 enabled key 列表
2. 依次尝试，首个成功即采用
3. 全部失败 → 保留旧快照，打日志，退出
4. 解析 {"models": {...}}
5. 对每个模型：
     state == "full" 或 util >= disable_threshold
       → streak[model] += 1
       → streak >= disable_streak 时加入禁用集合
     否则 streak[model] = 0
6. 应用全禁保护
7. 写入 Redis，写入 amd_load_at
```

**单飞：** 同一 provider 的轮询不允许重叠。上一轮未结束时跳过本轮。

### 9.3 认证

`Authorization: Bearer <key>`。负载接口是 fleet 级，**任意一把 enabled key 即可**，
不需要遍历所有 key。

### 9.4 与既有轮询机制的关系

既有 maintenance worker 共九个，其中三个是 provider 专属：

```text
maintenance.codex.client.profile       codex
maintenance.gemini.files.cleanup       gemini
maintenance.opencode.ip_pool.autoscan  opencode
```

本功能照第三种形状：自建 worker + 自建 `TASK_KEY_AMD_LOAD_*` + 自建 Redis 命名空间。

**不挂靠 pool quota probe 机制。** `ProviderPoolService::with_builtin_adapters()`
按 `provider_type` 查适配器，`crates/aether-provider/pool/src/providers/` 下只有
antigravity / kiro / grok / codex / xai / chatgpt_web / windsurf 七个，
**没有 `custom`**。AMD 注册为 `custom`，走 `provider.rs:66-91` 默认适配器，
它不认识 `/radeon/api/tokenfactory/load`。轮询器必须自包含。

**单飞实现沿用既有写法**（`maintenance/runtime/pool_quota_probe.rs:1944-1946`）：

```rust
let mut interval = tokio::time::interval(config.scan_interval);
interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
```

比自行实现「上一轮未结束则跳过」更简洁，且与工程一致。

**间隔不随压力调频。** `pool_quota_probe_auto_interval_seconds`
（`pool_quota_probe.rs:382`）按请求压力动态调间隔，那是配额探测的需求——
负载是上游容量，与本机请求压力无关，固定 60s 即可。
但 22s 的接口耗时必须计入：`poll_sec` 下限 30 是硬约束。

---

## 10. 调度接入

### 10.1 改动点

| 位置 | 改动 |
|---|---|
| `src/amd_load/config.rs` | **新建** `AmdLoadConfig` + 校验 + env 兜底 |
| `src/amd_load/mod.rs` | **新建** 快照类型 + `read_amd_load_block_map()` + `is_amd_load_blocked()` |
| `src/amd_load/poller.rs` | **新建** 轮询任务 |
| `src/scheduler/candidate/runtime.rs:24` | `CandidateRuntimeSelectionSnapshot` 增加 `amd_load_blocks: BTreeMap<String, BTreeSet<String>>` |
| `src/scheduler/candidate/runtime.rs:35` | `read_candidate_runtime_selection_snapshot` 中调用 `read_amd_load_block_map` |
| `src/scheduler/candidate/runtime.rs:242` | `current_candidate_runtime_skip_reason` 开头早返回 `Some("amd_model_load_high")` |

### 10.2 判定依据的字段

```rust
// crates/aether-scheduler-core/src/candidate/types.rs:12,27
candidate.provider_id                     // 供应商作用域
candidate.selected_provider_model_name   // 上游真实模型名
```

与既有的 `account_quota_exhausted`（`runtime.rs:423,435,445`）使用同一对字段，语义对齐。

### 10.3 覆盖范围

`collect_selectable_enumerated_candidates_with_skip_reasons`
（`selection.rs:222`）是**唯一**的运行时过滤入口，
`resolve_scheduler_candidate_selectability`（`resolution.rs:8`）只被 `selection.rs:287` 调用一次。

因此一处改动覆盖全部请求路径：

- 标准流式 / 同步（`planner/state/scheduler.rs:79`）
- 透传（`planner/passthrough/provider/family/candidates.rs:133,242`）
- 专用 image / video / files（`planner/specialized/*/support.rs`）
- 分页预选（`planner/candidate_source.rs:1282`）
- 鉴权并发重试循环（`runtime.rs:167`）

`resolution.rs` 无需改动——它已在循环内逐候选调用
`current_candidate_runtime_skip_reason`，返回值会自动写入
`SchedulerSkippedCandidate.skip_reason` 并进入遥测。

### 10.4 读取开销

候选矩阵中同一 provider 可能出现数十次（key × endpoint × api_format 组合）。
`read_amd_load_block_map` **必须按 `provider_id` 去重，每个 provider 一次 Redis 读**，
不得按候选逐个读。

### 10.5 架构测试红线

`apps/aether-gateway/tests/architecture/runtime_and_security.rs` 钉死了文件布局：

- `runtime.rs` **必须保留** `CandidateRuntimeSelectionSnapshot`、
  `read_candidate_runtime_selection_snapshot`、`should_skip_provider_quota`
- `runtime.rs` **禁止出现** `SchedulerAffinityTarget` / `AppState`
- `selection.rs` **禁止出现**各类 `read_*` 函数 → 所以过滤放 `runtime.rs` 不放 `selection.rs`
- `candidate/mod.rs` **禁止出现** `selected.push(candidate);`

CI 的 `unit-tests` job 会校验。新增读取函数放在 `runtime.rs` 内部，不新增 `use`。

---

## 11. 管理端

### 11.1 配置表单

```
模型负载控制

  ☑ 启用模型负载感知

  轮询间隔(秒)        [  60 ]   范围 30-3600
  禁用阈值(%)         [  85 ]   范围 (0, 100]
  恢复阈值(%)         [      ]   留空 = 同禁用阈值
  连续几次才禁用      [   2 ]   范围 1-10
  快照有效期(秒)      [ 180 ]   需 >= 轮询间隔 × 2
  请求超时(秒)        [  40 ]   范围 10-120

  当前生效：禁用 >= 85   恢复 < 85   连续 2 次
```

占位符显示当前生效值（config 与 env 合并后的结果）。

### 11.2 模型负载展示区

供应商详情页新增，30s 自动刷新：

| 模型 | 负载 | state | 状态 | 操作 |
|---|---|---|---|---|
| DeepSeek-V4-Flash | ████████░░ 78.4% | Busy | 正常 | — |
| GLM-5.3-Flash | ██████████ 100.0% | At capacity | 负载过高（已自动禁用） | 强制启用 |
| MinerU2.5-Pro | ░ 5.1% | Idle | 正常 | — |
| MiniCPM5-2B | ░ 3.1% | Idle | 强制启用中（剩余 4:12） | 取消 |

状态三态：

- **正常** — 负载未达阈值
- **负载过高（已自动禁用）** — 命中判定
- **强制启用中（剩余 mm:ss）** — 人工覆盖生效中

配色沿用参考实现：full=红 / busy=橙 / idle=绿，百分比条同色。

**人工覆盖必须有**，否则自动判错时唯一的处理手段是改代码重启。

---

## 12. 异常与边界

| 情况 | 处理 |
|---|---|
| 负载接口整体失败 | 保留旧快照，**不做任何启停决策** |
| 快照超过 TTL | 不采信，视为无数据，放行 |
| 目录有模型但负载快照缺该模型 | 放行；触发一次目录重拉（模型可能刚上下架） |
| 轮询上一轮未结束 | 跳过本轮（单飞） |
| 某把 key 请求失败 | 换下一把 enabled key |
| 全部 key 失败 | 保留旧快照 + 日志 |
| Redis 不可用 | 视为无快照，全部放行（**失败开放**，不因监控故障影响业务） |
| 该 provider 全部模型被禁 | 保留利用率最低的一个 |
| 人工覆盖与自动判定冲突 | 覆盖优先 |
| 负载判定导致候选为空 | 由既有的「无可用候选」路径处理，本功能不额外兜底 |

**失败开放原则：** 监控设施故障不得导致业务失败。每一处异常都倾向放行而非禁用。

---

## 13. 可观测性

- 跳过原因 `amd_model_load_high` 自动进入 `SchedulerSkippedCandidate` 与跳过遥测
- `runtime.rs:242` 早返回前打一条 `tracing::debug`，含
  `provider_id` / `selected_provider_model_name` / `util` / `threshold`
- 轮询器日志：成功、换 key 重试、全部失败、模型上下架、全禁保护触发
- 面板展示最近一次成功拉取时间

排障入口：某模型没被选中 → 查遥测里的 `skip_reason` 是否为 `amd_model_load_high`
→ 查面板上的当前负载与生效阈值。

---

## 14. 实施顺序

分四步，每步独立可验证，**不合并**。

```
Step 1  存储 + 轮询 + 面板显示，不接调度
        验：负载条有数据；延迟约 22s；模型上下架能被观察到

Step 2  接调度，阈值临时设 99.9（等价于不拦）
        验：遥测里 amd_model_load_high 字段链路通；无实际拦截

Step 3  阈值降到 85
        验：真实高负载时该供应商该模型从候选中消失，请求落到别家

Step 4  429 key × 模型冷却
        验：单把 key 的并发配额耗尽时，轮询自动绕开该 key
        这是开池模式下丢失的 account_quota_exhausted 的唯一兜底（见 7.4、16）
```

**Step 1 单独跑一轮是刻意的。** 该接口的一切行为（延迟、结构、上下架）
都是本设计的假设来源，Step 1 是唯一能证伪这些假设的环节。
一旦与调度改动混在一起，判据出问题时无法区分是接口变了还是判定逻辑错了。

**Step 4 紧接 Step 3，不拖到下一轮。** Step 3 验证「高负载时请求落到别家」时，
若 429 层已上线，该现象将无法归因——分不清是负载层拦截还是 429 冷却生效。
两层分开验证会得到互相污染的结论。

---

## 15. 验收标准

Step 1

- [ ] 面板显示全部目录模型的负载条与 state
- [ ] 单次轮询延迟落在 20-25s 区间
- [ ] 能观察到至少一次模型上下架导致的快照字段增删
- [ ] 关闭 `enabled` 后轮询停止，无 Redis 写入

Step 2

- [ ] 遥测中出现 `amd_model_load_high` skip_reason
- [ ] 阈值 99.9 时实际拦截次数为 0
- [ ] 每个请求对同一 provider 只产生 1 次 Redis 读

Step 3

- [ ] `GLM-5.3-Flash`（100% full）在候选中被剔除
- [ ] `MiniCPM5-2B`（3.1% idle）正常进入候选
- [ ] 同一模型在其他供应商上不受影响
- [ ] 改阈值后**无需等待下一次轮询**即生效
- [ ] 负载接口挂掉时业务不受影响
- [ ] `enabled=false` 时行为与改动前完全一致（回滚验证）

Step 4

- [ ] 单把 key 撞 429 后，遥测出现该 key × 模型的冷却记录
- [ ] 冷却期内同 key 同模型被跳过，同 key 其它模型不受影响
- [ ] 冷却到期自动恢复，无需人工干预
- [ ] 优先采用上游 `retry-after` 头，缺省才用固定 60s
- [ ] 10 把 key 中单把耗尽 `$1/天` 配额后，轮询不再选中它

---

## 16. 风险

| 风险 | 缓解 |
|---|---|
| 负载接口形状变化 | 解析失败时保留旧快照；Step 1 阶段先观察 |
| 阈值需要随时间调整 | 已做成可配置项，改配置立即生效 |
| 轮询器给上游增加 22s 请求 | 间隔 60s，单飞；负载接口是否计入 RPM 待观察 |
| Redis 故障影响业务 | 失败开放，见第 12 节 |
| 与 429 模型级冷却混淆 | 两者粒度不同（供应商 × 模型 vs key × 模型），取交集，见下 |

### 与 429 冷却的关系

本功能与「429 驱动的 key × 模型短冷却」是**两条正交的轴**：

```
平台负载   供应商 × 模型   fleet 级    预测性（轮询，22s 周期）
429 冷却   key × 模型      账号级      反应性（收到 429 才触发）
```

模型可用 = 平台未因负载禁用 该供应商
**AND** 该 key 上的该模型不在 429 冷却
**AND** 该 key 健康

三层取交集。**两层缺一不可**，但缺失的后果不同：

- 缺 429 层 → 负载 30% 但这把 key 恰好满了，会直接失败
- 缺负载层 → 负载 90% 时先撞 429，白烧一次配额和一次重试

Aether 当前**没有** 429 模型级冷却（`locked_models` 不参与调度）。

**该项从「建议一起做」上调为「开池模式的必要配套」**（见 7.4 的池模式决策）：
AMD 开池后 `account_quota_exhausted` 失效，配额预判缺失，429 冷却是唯一兜底。
本功能不实现它，但它不是可选项。

实施顺序与验收标准见第 14、15 节的 Step 4。

---

## 17. 附录：上游端点参考

```
POST /radeon/api/v1/chat/completions        聊天（支持流式，`: ping` 心跳，`data: [DONE]` 收尾）
GET  /radeon/api/v1/models                  模型目录（当前 9 个模型）
GET  /radeon/api/v1/usage                   账号配额（daily_cost_* 字段损坏，仅展示）
GET  /radeon/api/v1/messages                Anthropic 信封
GET  /radeon/api/tokenfactory/load          fleet 级负载（本功能数据源，约 22s）
```

限流响应头：

```
x-ratelimit-limit-user-rpm: 20
x-ratelimit-remaining-user-rpm: 19
x-ratelimit-used-user-daily-usd: 0.0
```

并发超限 429：

```json
{"error":{"code":"model_concurrency_rate_limit_exceeded",
          "message":"Model 'X' is at its concurrency limit (32); please retry later or use another model",
          "type":"rate_limit_error"}}
```

注意：并发限制是**模型维度**的（32），不是 key 维度。这是 429 冷却必须按
key × 模型粒度设计的原因。
