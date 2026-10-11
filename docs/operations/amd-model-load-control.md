# AMD provider and model-load control

AMD（Radeon Cloud，`https://developer.amd.com.cn/radeon/api/v1`）在 Aether 里是一个
**固定模板供应商**，并额外带一层**平台级模型负载感知**：上游公开报告每个模型当前的容量
占用百分比，网关周期性拉取快照，超阈值的模型在该供应商上被排除出调度候选。

粒度是 **供应商 × 模型**。同一个模型若挂在别的供应商上，不受影响。

本模块**只服务 AMD**，不做供应商抽象：数据源、URL 推导规则、fleet 级语义、`state` 的
取值全部是 AMD 的专有约定。模块、配置节点、结构体、Redis 键一律带 `amd_` / `AMD_` 前缀。

## Provider type

| 项 | 值 | 位置 |
| --- | --- | --- |
| 类型名 | `amd` | `SUPPORTED_PROVIDER_TYPES`（`handlers/admin/provider/write/normalize.rs:21`） |
| 默认 Base URL | `https://developer.amd.com.cn/radeon/api/v1` | `AMD_FIXED_PROVIDER_TEMPLATE`（`crates/aether-provider/transport/src/provider_types.rs:515`） |
| 模板端点 | 单个 `openai:chat` | 同上 |
| Runtime policy | `STANDARD_RUNTIME_POLICY`（固定供应商） | 同上 |

`amd` 登记在 `fixed_provider_template()` 与 `provider_type_is_fixed` / `provider_runtime_policy`
的固定类型列表里，因此**创建时就带好端点**，且端点的 Base URL 不可编辑
（`frontend/.../EndpointFormDialog.vue` 把 `amd` 当固定供应商用例处理）。

供应商识别用 `is_amd_provider(provider_type, base_url)`（`apps/aether-gateway/src/amd_load/poller.rs:49`）：

```text
provider_type 等于 "amd"（忽略大小写）  或  base_url 含 "/radeon/api/"
```

**保留 OR 分支是有意的**：在 `amd` 成为一等类型之前，已有以 `custom` 类型、AMD Base URL
建成的供应商，它们必须继续被负载感知覆盖。前端的 `isAmdProviderType()`
（`frontend/src/features/providers/utils/providerTypeUtils.ts:42`）用同一规则，
`AMD_DEFAULT_BASE_URL` / `AMD_DEFAULT_API_FORMAT` 与后端模板保持一致。

## 管理接口

前缀 `const AMD_LOAD_PATH_PREFIX = "/api/admin/amd-load/providers/"`，
route family `amd_load_manage`，scope `admin:amd_load`
（`apps/aether-gateway/src/control/route/admin/amd_load_routes.rs:5`）。

| 方法 | 路径 | route_kind | 作用 |
| --- | --- | --- | --- |
| GET | `/api/admin/amd-load/providers/{id}` | `get_amd_load_status` | 快照 + 生效配置 + 判定结果 |
| PUT | `/api/admin/amd-load/providers/{id}/config` | `save_amd_load_config` | 保存阈值与轮询配置 |
| POST | `/api/admin/amd-load/providers/{id}/refresh` | `refresh_amd_load_snapshot` | 立刻拉一次快照 |

分类器**只做前缀与后缀匹配，不解析 `{id}`、不校验长度**。这是刻意的回归红线
（`classifies_regardless_of_provider_id_shape`）：opencode 的同类分类器强制 id 长度等于 36，
id 形态不符时整条链只返回 501，症状看起来像「接口没实现」，真因却是 id 不合长度。

`GET` 的响应体：

```text
config              生效配置（见下，已套默认值）
warnings            配置告警（如阈值过低）
is_amd_upstream     base_url 是否命中 AMD 规则
load_endpoint       推导出的负载接口地址
usage_endpoint      推导出的用量接口地址
usage               额度快照（见「额度面板」，无数据时为 null）
snapshot_present / snapshot_expired / snapshot_fetched_at / scope
blocked_models      当前被判定为超阈值的模型名
models              逐模型 {name, state, utilization, streak, blocked, ...}
```

`config` 回显的是**生效值**而不是用户提交的原始值——界面上显示的必须是真正参与判定的那个数。
它包含 `has_hysteresis` 与 `effective_recovery` 两个派生字段，用于让界面直接判断当前是单阈值
还是滞回模式。

`PUT /config` 接受带或不带外层 `amd_load` 键的请求体，先校验再合并，通过
`write_provider_config_section_with` 做**分段 CAS 写**（最多 8 次重试）；持续冲突返回 409，
而不是静默覆盖。`POST /refresh` 会先校验供应商存在、上游是 AMD、且 `enabled` 为真，
再调用轮询器（轮询器一次遍历所有 AMD 供应商）。

## 负载快照

数据源是 AMD 专有的 `GET {origin}/radeon/api/tokenfactory/load`，由 provider Base URL
**字符串推导**（保留 origin，不动 path）：`base_url` 含 `/radeon/api/v1` 时得到
`{origin}/radeon/api/tokenfactory/load`（`poller.rs:66`）。

快照记录 `fetched_at`、`scope`（fleet 级）与逐模型条目
`AmdLoadModelEntry { state, utilization, streak, blocked_prev }`（`amd_load/mod.rs`）。
`state` 取上游的 `idle` / `busy` / `full`。

持久化在 Redis，按供应商分键：

```text
amd_load:{provider_id}          快照
amd_load_streak:{provider_id}   连续越线计数
```

判定规则：

- 只有 `enabled` 为真时轮询与判定才运行。
- 连续 `disable_streak` 次（默认 2）越线才禁用，避免单次抖动就摘掉模型。
- 阈值 `disable_threshold` 默认 85%；`recovery_threshold` 留空表示**单阈值模式**
  （`< disable_threshold` 即放行，不设滞回），两者都设才是滞回。
- **全禁保护**（`apply_all_blocked_guard`）：如果一轮判定会把所有模型都禁掉，则放弃这一轮，
  宁可放行也不把供应商打成不可用。
- 快照超过 `snapshot_ttl_sec` 视为过期；过期快照不参与判定，业务按「无负载信息」走。
- 负载接口挂掉或解析失败时保留旧快照，不因上游异常改变调度结果。

**`block_models` 默认关闭：默认只展示，不禁用模型。** 实测（2026-10-02，48 个首字节样本
＋60 个负载时刻）**没有支持**「按负载禁用模型能改善首字节」这个前提：慢请求（>10s）的负载
中位 53.1% 对快请求 48.4%，只差 5 个百分点且慢请求散布在整个区间（最低 1.6%）；负载 79.3%
的 `Qwen3.8-Flash-Next` 变异系数 0.18 是全场最稳的，而负载 16.4% 的 `Qwen3.8-27B` 反而出现
22.8 秒长尾；满载的 `DeepSeek-V4.1-Flash` 实测 10/10 成功。也就是说禁用换不来首字节改善，
只会拦掉用户其实用得动的模型——真正该调的是首字节超时。

保留开关而不删判定逻辑，是因为快照与展示本身有用，且将来若有新证据（例如改按
`by_model.errors` 而不是 `utilization` 判定）可以重新打开。

## 轮询器

单例后台 worker，tick 30 秒、启动宽限 90 秒；每个供应商按自己的 `poll_sec` 限流，
各供应商的失败互相独立（一个拉不到不影响其他）。用量接口是 `{origin}/radeon/api/v1/usage`，
按活跃 key 逐个拉取，**按 `organization_id` 去重**（同一组织多个 key 只算一次，
重复的计入 `deduped_keys` 而不重复计数），结果写入 `amd_usage:{provider_id}`。

`poll_sec` 下限 30 秒是硬约束：该接口单次实测耗时 20.5s–23.3s（p50 22.3s），
间隔再低就会请求堆叠。单请求超时默认 40 秒，约为实测耗时的 1.7 倍余量。

## 配置

配置存在 provider 的 `config.amd_load` 段，环境变量仅作兜底。

| 字段 | 默认 | 边界 | 含义 |
| --- | --- | --- | --- |
| `enabled` | `false` | — | 总开关。装好 key 之前不应有任何行为 |
| `block_models` | `false` | — | 是否真的把超阈值模型挡在调度外；默认只展示 |
| `poll_sec` | `60` | 30–3600 | 轮询间隔 |
| `disable_threshold` | `85.0` | — | 禁用阈值（%） |
| `recovery_threshold` | 空 | — | 留空＝单阈值；填了才是滞回 |
| `disable_streak` | `2` | ≤10 | 连续越线几次才禁用 |
| `snapshot_ttl_sec` | `180` | ≥ `poll_sec × 2` | 快照有效期 |
| `timeout_sec` | `40` | 10–120 | 单次请求超时 |

阈值取 85 的依据：15 次采样（约 5.5 分钟窗口）里主力文本模型 `DeepSeek-V4-Flash`
的 p50 为 78.6、stdev 6.1。阈值 80 正好切在分布中部，会让 27% 的轮询被禁用；85 降到 7%，
而每轮可用模型数反而略升（80 → 均值 3.9，85 → 均值 4.1）。

环境变量兜底（仅在配置段缺该字段时生效）：
`AMD_LOAD_ENABLED`、`AMD_LOAD_POLL_SEC`、`AMD_LOAD_DISABLE_THRESHOLD`、
`AMD_LOAD_RECOVERY_THRESHOLD`、`AMD_LOAD_DISABLE_STREAK`、`AMD_LOAD_SNAPSHOT_TTL_SEC`、
`AMD_LOAD_TIMEOUT_SEC`。

保存时校验并给出告警：`disable_threshold` 低于 50 会告警——按实测分布，那样几乎所有模型
都会被禁用。

## 额度面板

额度接口按**逐账号**返回（`accounts[]`），因为 10 个 key 就是 10 个独立 AMD 账号、各有独立
日限额；只回合计会让「哪个账号快撞满」完全不可见，而那正是这个面板的用途。

账号顺序用 `accounts_in_key_order()`，即**按 key 的配置顺序**而不是按用量排序——用量天天变，
按它排会让每次刷新时这些行跳来跳去。

两个字段上游**未实现**，实测（2026-10-02，10 个账号逐个查过）`daily_cost_used_usd` 恒为 0、
`daily_cost_remaining_usd` 恒等于限额。它们照实回传并附在 `untrustworthy_fields` 里说明，
**刻意不隐藏**：接口里真实存在的东西悄悄消失，会让人以为是我们读错了。参考实现曾用
`daily_cost_remaining_usd` 判断余量，那会在真正撞满时仍然显示满额。

`usage_ratio` 是本地用 `today.cost / daily_cost_limit_usd` 算的，不来自上游。
合计值只统计**拉到数据的账号**，不把「没查到」当成「没花钱」。

面板由 `frontend/src/features/providers/components/AmdLoadPanel.vue` 渲染，
供应商详情抽屉在 `isAmdProviderType(provider_type, base_url)` 为真时挂载它；
API 封装与类型在 `frontend/src/api/endpoints/amd-load.ts`。

## key 轮转与「无熔断」

AMD 的账号（key）**不接号池、也不用密钥熔断**，改走纯游标轮转：

- **游标**：`amd_key_cursor:{provider_id}`（Redis，TTL 24 小时）。每请求每 provider 只推进一次，
  同一 provider 的多个 (endpoint × api_format) 组共用该值（循环外按 provider 缓存，见
  `apply_amd_key_rotation`）；组内候选不足 2 个时不消耗游标。
- **环**：组内 key 按 `(global_priority_by_format, internal_priority, key_id)` 升序确定，并且
  **与请求无关**——调度器的 `load_balance_seed` 是 `current_unix_ms()`，直接拿排名结果当环会让
  「上次的位置」不可观测。注意它**不等于面板里密钥列表的顺序**：面板按 `internal_priority` 排，
  某把 key 配了按格式的全局优先级时两者会不同；不同 api_format 也可能得到不同的环。
- **落点**：planner 的排序后置钩子 `post_rank_reorder`（`candidate_ranking.rs`）里、opencode
  轮转之后调用 `apply_amd_key_rotation`。实现是「换槽位里的人」：组内槽位在候选列表中的位置
  不变，只把轮转后的成员写回，因此不破坏它与其它 Provider 候选的相对次序。
- **与已解析页缓存互斥**：`CandidateResolvedPageCacheKey` 里不含游标值，命中就会把轮转结果
  冻住（`FixedOrder` 下 fresh 250ms / stale 300s 内必然命中）。因此**含 AMD 候选的页不进这层
  缓存**（`page_contains_amd_candidates`），代价只是 AMD 请求少一层 planner 缓存。
- **失败处理**：失败就换下一把（既有 failover：`LocalFailoverDecision::RetryNextCandidate`）；
  同一请求内的重试**不再**推进游标，也**不**给 key 打任何禁用标记。注意 failover 只对
  `retryable / failover_recommended` 的错误生效，被判定为不可重试的上游错误仍会直接结束该请求
  ——这是既有语义，不是 AMD 专属行为。
- **不记录也不判定熔断**：写侧 `local_execution_plan_tracks_circuit_breaker` 对 AMD 返回 false
  （不写 `circuit_breaker_by_format`），判定侧 `enforce_key_circuit_breaker` 对 AMD 为 false。
  健康分照常写，但有 `LOCAL_HEALTH_SCORE_FLOOR = 0.2` 下限，`key_health_score_zero` 因此实际
  不会触发。读不到传输快照时按非池处理（记录熔断）——刻意的 fail-open，宁可多记也不误摘。
- **保留的跳过项**：本地 RPM 上限（`key_rpm_exhausted`）与账号额度耗尽
  （`account_quota_exhausted`）照旧生效——它们是真实约束，不是失败惩罚。
- **并发语义**：游标推进是 `GETDEL` + `SETEX` 两步（`RuntimeState` 没有 INCR 原语），并发下
  可能跳号或重复命中同一个位置；顺序是近似的，不做严格互斥保证。
- **与号池互斥**：AMD 永不接入号池。读取侧 `admin_provider_pool_config_for_provider` 对它一律
  返回 `None`（管理端与维护任务的调用点都走它），选择期 `pool_enabled` 另有 `!is_amd` 判据，
  写入侧 create/update 直接剥离 `pool_advanced`（类型可以从别的类型改成 `amd`，旧键会跟着留下）。
  前端供应商表单对 AMD 隐藏「号池调度模式」开关，提交时强制 `pool_advanced: null`。
  **SQL 侧也已对齐**：Postgres 候选查询判断「是否池内」用的是
  `(config -> 'pool_advanced') IS NOT NULL AND provider_type <> 'amd'`
  （`crates/aether-data/adapters/postgres/src/candidate_selection.rs`，两个 SQL 常量各两处：
  选出 `provider_pool_enabled` 列 + 收窄候选的 `LIMIT`），与 Rust 侧 `is_amd_provider_type`
  同一判据。因此即使 AMD 供应商被写入 `pool_advanced`（历史脏数据、直接改库、备份导入），
  候选也不会被收窄成「每模型只剩一把 key」，轮转与 failover 不受影响；SQL 把它们分到
  `WHERE NOT provider_pool_enabled` 那一支。

代码：`apps/aether-gateway/src/amd_rotation.rs`（游标、环、槽位分配）与
`apps/aether-gateway/src/ai_serving/planner/candidate_ranking.rs`（`apply_amd_key_rotation`）。

## 已删除的概念

以下字段/概念**不存在于代码中**（若在旧文档或旧截图里见到，那是过期信息）：

```text
risky_account_key_id     「风险账号」高亮（已随「今日最高」一并移除）
most_used / 今日最高      最常用账号统计与界面列
today_max                同上
```

## 测试

```sh
cargo test -p aether-gateway --lib amd_load
```

覆盖：上游负载响应解析、滞回与 `disable_streak`、快照过期、全禁保护、Redis 键形状、
配置默认值/合并/钳制/校验/告警、端点 URL 推导（保留 origin）、供应商识别，
以及 `usage.rs` 中「死字段照实回传」与「按 key 顺序返回」的断言。

key 轮转与去熔断另由这些用例覆盖：`amd_rotation` 的游标/环/槽位分配单测、
`scheduler::candidate` 的 `amd_provider_ignores_key_circuit_open_runtime_skip`、
`pool::config` 的 `amd_provider_never_joins_the_pool`，前端为
`ProviderFormDialog.amd-pool-mode.spec.ts`。
固定模板与「`amd` 不是自由形态供应商」另由 `crates/aether-provider/transport/src/provider_types.rs`
的测试覆盖；路由分类由 `classify_admin_amd_load_routes` 的三个测试覆盖。
