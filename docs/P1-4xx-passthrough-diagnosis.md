# P1「上游 4xx 透传」诊断记录

> 状态：**已修复、已部署、已端到端验证**（同步与流式两条路径）。
>
> 修复提交：`72db136c6`（同步）、`4209fa047`（流式）。
> 线上验证：非流式与流式的非法参数均返回上游 4xx（原先都是 503），合法请求仍 200，
> `gateway_returns_error_body_when_prefetch_detects_embedded_stream_error` 仍断言 503。
>
> 记录时间：2026-10-08
> 提交：`d66d419e3`（合并后 `a1686ee7a`）
> CI：run `37713207086`（workflow_dispatch，head_sha 已核对为 `a1686ee7a`）
> 线上二进制：部署于 2026-10-08 09:47:35，备份 `binary-backup-20261008-094538`

---

## 0. 真正的根因（2026-10-09/10 用时间戳对齐重新定位，修正本文档原先的结论）

本文档最初把「P1 未生效」归因于「耗尽判定时最后一次候选还没异步落库」，并提出了
§9 的 `drain_pending` 屏障方案。**这个根因是错的，§9 的方案没有实施也不需要实施。**

复现证据（`temperature=999`，上游返回 400）：

- 11 条候选行在响应写出前 **1.8 秒**就已全部落库（`finished_at` 最晚 21:48:02.77，
  响应 21:48:04.5），不存在可见性竞争；
- 消费端闸门（§2 的 `error_type == retryable_upstream_status`）当时**已经上线**。

真正的缺口是：**只有流式运行时会写 `retryable_upstream_status` 这个哨兵**，
同步运行时把它漏了，后来流式也有一条路径漏了。

### 闸门为什么非有不可

消费端只认 `error_type == "retryable_upstream_status"`，是因为 `upstream_status_code`
有两种来源：上游真实的状态行，以及网关从 **200 响应体**里解析归类出的状态（prefetch
检出 `rate_limit_error` → 429）。后者不能冒充上游事实发给客户端，否则会把「调用方参数
有问题」和「网关自己的归类」混为一谈。

### 同步那半（`72db136c6`）

`sync/execution.rs` 记候选时只写响应体里的 error type。amd-fleet 的 400 body 没有
顶层 `error.type`，于是落 `NULL` → 闸门永不匹配 → 所有同步 4xx 被吞成 503。
实测全库 582 个 4xx 候选里 428 个带哨兵（全部来自流式），同步的全是 `NULL`。

### 流式那半（`4209fa047`）

链路是：

1. `build_stream_failure_from_provider_error_body` 按 `type` / **`code`** / `status`
   取错误类型。amd 用 `code` 表达错误身份，而 `invalid_parameter`、`model_not_found`
   等都不在 `REQUEST_CANDIDATE_ERROR_TYPES` 白名单里；
2. `StreamFailureReport::into_body_jsons` 把这个值写进归一化 body 的 `error.type`，
   成为 `client_body_json`；`stream_failure_body_field` 优先读它；
3. `sanitize_request_candidate_error_type` 把任何未知值归一化成 `unclassified_error`，
   而这个兜底值**本身也不在已知类型里**，耗尽判定时再 sanitize 一次仍是它 ——
   于是流式 4xx 一律无法通过闸门。

实测：amd 流式 4xx 候选 44 条**全部**是 `unclassified_error`、0 条哨兵；opencode
流式 4xx 428 条带哨兵。机制本身是通的，只是这条路径产不出哨兵。

**一个反复踩到的陷阱**：`local_stream_candidate_retry_scheduled` 这个事件名有 5 个
产生点，看到它触发**不能**据此推断哨兵分支执行过。

### 两半的修法相同

`candidate_status_code` / `result.status_code` 来自 `failure.upstream_status_code`，
只有上游真的返回了状态行才为 `Some`，因此判据天然满足「不能拿归类状态冒充上游事实」。
只对**请求本身不合法**的状态打哨兵（400/404/405/409/413/415/422）；401/403（上游
凭据/权限）与 429（上游限流）仍走原有 503 —— 否则客户端会收到一句「请检查客户端请求
体与配置」，把排查方向带偏。

哨兵只写进候选行，客户端可见的响应体由 `StreamFailureReport` 构建、未被改动，
所以 `encode_openai_image_failed_event` 等处不会把内部标记泄给客户端。

---

## 1. 要解决的问题

调用方发了非法参数时，上游返回 400，网关却对客户端报 **503**：

```
{"error":{"type":"http_error",
  "message":"已尝试所有本地执行候选提供商，但没有任何候选成功完成请求"}}
```

503 的语义是「服务不可用、请稍后重试」，导致两个后果：

1. 调用方会去重试一个**永远不可能成功**的请求
2. 操作侧的排查方向被引到基础设施，而真正的那行错误配置没人会去看

**实测案例**：调用方把 `max_completion_tokens` 设成 `485456`，上游返回
`{"model":"big-pickle"}` + `x-cache: Error from cloudfront`。
回放该请求 8 次 **0 成功**；只去掉这一个字段后 **8 次全成功** —— 归因在请求参数，不在服务可用性。

用户决策：**只做透传（P1），不做裁剪（P2/P3）、不做重试策略调整（P2）**——
理由是「只要能返回错误、知道问题，就能通过修改客户端配置改正配置」。

---

## 2. 已实现的改动

```rust
// handlers/proxy/mod.rs
fn local_execution_runtime_miss_status(
    provider_key_capacity_limited: bool,
    upstream_status: Option<u16>,
) -> http::StatusCode {
    if !provider_key_capacity_limited {
        if let Some(status) = upstream_status {
            if matches!(status, 400..=499) {
                if let Ok(code) = http::StatusCode::from_u16(status) {
                    return code;
                }
            }
        }
    }
    if provider_key_capacity_limited { TOO_MANY_REQUESTS } else { SERVICE_UNAVAILABLE }
}
```

取值处：

```rust
let upstream_status_code = local_execution_exhaustion
    .as_ref()
    // 只认「上游真实返回的状态行」
    .filter(|e| e.upstream_error_type.as_deref() == Some("retryable_upstream_status"))
    .and_then(|e| e.upstream_status_code);
```

### 为什么加 `error_type` 这道门

`upstream_status_code` 有两种来源，必须区分：

| 来源 | 例子 | 是否透传 |
|---|---|---|
| 上游真实 HTTP 状态行 | 上游直接回 400 | ✅ |
| 网关从 **200 响应体**里解析归类出的状态 | prefetch 检出 `rate_limit_error` → 429 | ❌ 网关自己的判断，不能冒充上游事实 |

反例由既有测试锁定：
`tests::ai_execute::lifecycle::gateway_returns_error_body_when_prefetch_detects_embedded_stream_error`
—— 其 mock 上游返回 `200`，body 内嵌 `rate_limit_error`，候选被记为 429，
**断言客户端拿 503**。该测试在本改动后必须仍然通过（现已通过）。

### 已加测试

- `upstream_client_error_is_passed_through_instead_of_service_unavailable`
- `upstream_server_error_keeps_service_unavailable`
- `missing_upstream_status_keeps_legacy_status`

**全量**：`aether-gateway --lib` 5246 passed / 3 failed（3 个均为
`temporary PostgreSQL should start: program not found`，本机未装 PostgreSQL，与改动无关）。
`cargo fmt --all --check` 通过。

---

## 3. 端到端验证失败

部署后回放 `orig_req.json`（44239 字节，含 `max_completion_tokens=485456`）：

```
#1  HTTP 503  7995ms
#2  HTTP 503  6168ms
#3  HTTP 503  5791ms
#4  HTTP 503  7288ms
对照（去掉该字段）：#1 HTTP 200 / #2 HTTP 200
```

**P1 的 4xx 透传路径一次都没生效。**

### 排除掉的可能

| 怀疑 | 验证方法 | 结果 |
|---|---|---|
| 改动没部署 | `gh api .../runs/37713207086` 的 `head_sha` | = `a1686ee7a`，**确实构建了我的提交** |
| 二进制是旧的 | 文件大小/时间 | 当前 221472616 vs 备份 221470328，时间 09:47:35，**确实换了** |
| `error_type` 被 sanitizer 改写 | 读 `sanitize_request_candidate_error_type` | `retryable_upstream_status` 在 known 列表（types.rs:141），**原样保留** |
| 读候选失败 | 日志 `failed to load request candidates` | **0 次** |
| gate 选错候选 | `select_last_failed_request_candidate` 按 `max(retry_index, candidate_index, finished_at)` | 对 `b4d02036` 选中 `retry=1 / 400`，**应该通过** |

**三个条件在数据库里全部满足，客户端却仍是 503。**

---

## 4. 根因（已确认）

**耗尽判定发生时，最后一次候选还没异步落库。**

`b4d02036` 的 journal 时间线：

```
10:40:41.961  retry_scheduled   status=500   ← 第一次失败
10:40:42.284  async_flush_completed           ← retry=0 的 500 已入 DB
10:40:43.413  persisted         retry=1
10:40:43.413  retry_scheduled   status=400    ← 400 发生
10:40:43.437  candidates_exhausted            ← 耗尽判定（400 后 24ms）
10:40:43.622  async_flush_completed           ★ 400 这条落库，比耗尽晚 185ms
10:40:44.532  http_request_failed 503
```

`build_local_execution_exhaustion` 走
`state.read_request_candidates_by_request_id()` 重读数据库：

```
耗尽时刻可见的候选 = { retry0: 500 }      （retry1 的 400 尚未落库）
max(retry_index, ...)  → 500
upstream_status_code = 500  → 不在 400..=499 → 落回 503
```

**这解释了全部矛盾**：事后查库能看到 400（185ms 后落库成功），
但**响应生成的那一刻读不到它**。

### 方法论教训

> 连续三轮用「事后查数据库」验证一个「响应生成时刻的可见性」问题——
> 这种验证方法**无法证伪假设**，反而导致反复得出「条件都满足却不生效」的困惑结论。
> 正确做法是**一开始就对齐 journal 时间戳**，而不是只看最终状态。

### 另一个已犯的错误

部署校验用 `strings | grep -q 'retryable_upstream_status'` 是**恒真**的——
该字符串在改动前就存在于 `stream/execution.rs`，不能证明新代码已部署。
真正的确认只能靠 `head_sha` 核对 + 文件差异。

---

## 5. 两个修复方案（均已评估可行性）

### B1 — 读库前先 drain 队列

`request_candidate_queue.rs` 现有公开 API：

```
enqueue_or_fallback / try_enqueue_priority_status
pending_writes() -> usize          ← 只能读数量，没有 drain / await / flush
```

**队列没有「等所有写完成」的 API，需要新增。**

- ✅ 语义明确（「读之前先确保写完」）
- ✅ 不改 trait 签名，不碰架构测试
- ⚠️ 185ms 延迟，但**只发生在已经失败的请求上**，不影响成功路径
- ❗ **下一轮必须先确认**：队列能否按 `request_id` **局部 drain**（只等当前请求的写）。
  若只能全局 drain，会阻塞其他请求的候选写入，就不能用。

### B2 — 用内存态，不重读数据库

耗尽构造点（`executor/candidate_loop.rs`）：

```
:449   同步路径   Ok(build_local_execution_exhaustion(self.state, &last_plan, ...))
:1452  流式路径   同上
:2471  测试桩     build_exhaustion(last_plan, last_report_context)
```

三处都只传了 `(state, last_plan, last_report_context)`，
**最后一个状态码没有传出来** —— 它在循环内部（打 `retry_scheduled status=400` 处）是已知的。

- ✅ 不增加延迟
- ✅ 语义更对：响应应基于**执行时实际看到的状态**，而非最终落库数据
- ❌ 要给 `build_exhaustion` trait 方法加参数，而该 trait 被架构测试锁定签名
  （`tests/architecture/ai_serving.rs:2052/2076/2085`）

**倾向**：B1 更小更稳，但**前提是局部 drain 可行**；否则选 B2 并同步改架构测试。

---

## 6. 相关背景数据

### 上游有两种不同失败

```
400  body {"model":"big-pickle"}           x-cache: Error from cloudfront   ← 参数问题
500  body {"error":{"message":"Internal server error"}}                      ← 服务端

按天分布：
10-08 | 500 |   8          10-07 | 500 |  61   400 |  61
10-06 | 400 |  53   500 |   9        10-05 | 400 | 117
10-04 | 400 |  86          10-03 | 400 |  76
```

本次验证期间上游主要返回 **500**，按设计 5xx → 503 是**正确行为**，
因此 503 本身不代表 P1 的 bug；真正暴露问题的是那条 400 候选也返回了 503。

### 上游状态与本次改动无关的两条（排查时勿混淆）

- **大体积 / SSL / 加密**：已实测推翻。59KB 中文请求经真实客户端路径全部 200；
  `role: developer`、`tools`、`store`、`reasoning_effort` 单独使用也全部 200。
- **`max_completion_tokens` 是触发 400 的参数**，但 P1 只做透传，不改它；
  修客户端配置是调用方的事。

---

## 7. 复现与验证工具

```
C:\Users\Administrator\Desktop\ae\orig_req.json    原始请求 44239B（触发 400/503）
C:\Users\Administrator\Desktop\ae\sys_req.json     对照（role 改 system）
C:\Users\Administrator\Desktop\ae\loop.ps1         每组 8 次回放
C:\Users\Administrator\Desktop\ae\verify.ps1       A/B 对照回放
C:\Users\Administrator\Desktop\ae\deploy_p1.sh     部署脚本（需补 file 校验）
C:\Users\Administrator\Desktop\ae\gotoci.sh        下载 CI artifact + file 校验 + 部署
```

回放路径：SSH 隧道 `18084` → 管理 API 建临时客户端 key →
`POST /v1/chat/completions`（model `big-pickle`）→ **测试完删 key**。

**验收标准**：回放 `orig_req.json` 返回 **400**（现在是 503）；
同时既有 prefetch 测试仍断言 503。

---

## 8. 回滚

线上行为与改动前**完全一致**（都是 503），服务健康，因此**当前不需要回滚**。
如需回滚：`/opt/aether-deploy/target/debug/aether-gateway.binary-backup-20261008-094538`
（停服务 → `cp` → `mv` → `strings` 校验 → 启服务）。

---

## 9. B1 可行性确认（2026-10-08 追加）

> ⚠️ **本节已被推翻，不要实施。** 它建立在「耗尽判定读不到刚落库的候选」这个前提上，
> 而复现证据（见 §0）表明 11 条候选行在响应前 1.8 秒就已全部落库，前提不成立。
> P1 的真实缺口是运行时**漏写 `retryable_upstream_status` 哨兵**，已在
> `72db136c6`（同步）与 `4209fa047`（流式）修复并验证。以下 B1 设计保留作为记录。

**结论：B1 可行，且不需要按 `request_id` 分片。**

### 队列已有屏障基础设施，只是全部私有

```rust
// apps/aether-gateway/src/request_candidate_queue.rs
enum RequestCandidateActiveQueueMessage { Barrier(Arc<RequestCandidateTerminalBarrier>), ... }
// :159
struct RequestCandidateTerminalBarrier { ready: AtomicBool }
//   .new() / .is_ready() / .release()

release_terminal_barriers(&mut active_barriers, &metrics)   // :1259 :1285 :1304 :1425
active_permit.send(Barrier(...))                            // :500 :567
```

同时已有指标 `terminal_barrier_pending` / `terminal_barrier_max_pending`（:131 :132），
以及测试 `failed_active_retry_keeps_terminal_barrier_closed`（:4202）。

**「等写完成」的机制已经存在，缺的只是一个 `pub(crate)` 的对外入口。**
`enqueue_priority_or_fallback`（:393）当前没有 `pub`。

### 为什么不需要按 request_id 分片（上一轮的顾虑作废）

屏障是作为一条消息**插进队列**，worker 按序释放 —— 天然的 **FIFO 语义**：

```
入队屏障 → 只等「排在它前面的写」完成
```

排在前面的只有一两个批次（实测 ~185ms），
且**只发生在已经失败的请求上**，成功路径零影响。

### 改动位置

```rust
// ① request_candidate_queue.rs：新增
pub(crate) async fn drain_until_barrier(&self) {
    let barrier = Arc::new(RequestCandidateTerminalBarrier::new());
    // 复用 RequestCandidateActiveQueueMessage::Barrier 通道入队
    // 轮询/等待 barrier.is_ready()
}

// ② executor/outcome.rs:231 读库之前
state.candidate_queue().drain_until_barrier().await;   // ← 新增这一行
let last_failed = state.read_request_candidates_by_request_id(...).await;
```

- ✅ 不改 trait 签名，不碰 `tests/architecture/ai_serving.rs:2052/2076/2085`
- ✅ 复用现有私有机制，不重构队列
- ⚠️ 需要把 :500/:567 两处私有入队路径暴露出来，或加薄封装

### 验证方法（必须遵守）

```
回放 orig_req.json  → 必须拿到 400（现在是 503）
既有 prefetch 测试   → 必须仍是 503
journal 时间戳       → 耗尽判定时刻，那条 400 是否已可见
```

**对齐 journal 时间戳，不要用事后查库来验证「响应时刻的可见性」**（见第 4 节教训）。

### B1 语义假设已验证（代码级证据）

第 9 节提出的唯一未验证假设——「屏障释放是否严格晚于排在它前面的记录完成 DB flush」——**已确认成立**：

```rust
// run_worker 内
collect_active_micro_batch(...).await;                 // :1238 收集记录 + 屏障（FIFO 出队）
let had_active_records = !active_batch.is_empty();
if had_active_records {
    flush_batch(..., &mut active_batch, ...).await;     // :1247 先落库
}
if active_batch.is_empty() {
    release_terminal_barriers(&mut active_barriers, &metrics);   // :1259 落库后才释放
}
```

`release_terminal_barriers` **只在 `active_batch.is_empty()` 时调用**，而 `flush_batch`
正是把 `active_batch` 清空的操作——所以屏障释放 ⟹ 与其同批或更早的记录已写入 DB。

再加上 `:983` 确认独立的 `Barrier` 消息可以被收集（不必挂在终态记录上），
B1 的三个要素全部具备：

| 要素 | 结论 | 位置 |
|---|---|---|
| 屏障基础设施存在 | ✅ | :159 结构、:1259/:1285/:1304/:1425 释放点 |
| 独立 Barrier 消息可入队 | ✅ | :983 收集、:500/:567 入队 |
| 释放晚于前置记录落库 | ✅ | :1247 flush → :1259 release |

**B1 设计至此无未知项，可直接实现。**

> 注意 `:1261-1264` 的注释：连续屏障流会让 biased select 永久偏向 active lane
> 而饿死终态记录——说明设计上已把屏障视为 active lane 的工作项，
> 实现 `drain_until_barrier` 时**单次请求只入队一个屏障**即可，不要制造屏障流。

### 关键实现约束：worker 路由按记录哈希（不得入单个 worker）

```rust
// :924
fn worker_index_for(&self, record: &UpsertRequestCandidateRecord) -> usize {
    if worker_count <= 1 { return 0; }
    (request_candidate_slot_hash(record) % worker_count as u64) as usize
}
```

记录是按 `request_candidate_slot_hash(record) % workers` 路由的。
**因此「往某一个 worker 塞屏障」是错的**——多 worker 时屏障可能落到别的 worker，
等不到本请求那条正在排队的记录，drain 形同虚设，且**测试很难发现**（单 worker 配置下全绿）。

`outcome.rs:231` 处只有 `plan`，拿不到可以复算 slot hash 的记录，
所以**不要试图对准某个 worker**。

**正确设计：对每个 worker 各入队一个屏障并等待全部就绪。**

```rust
// RequestCandidateQueueRuntime 新增
pub(crate) async fn drain_pending(&self) {
    for sender in &self.active_senders {
        let barrier = Arc::new(RequestCandidateTerminalBarrier::new());
        // sender.try_reserve() → send(RequestCandidateActiveQueueMessage::Barrier(...))
        // 轮询 barrier.is_ready()（当前只有 AtomicBool，无 Notify，需 sleep 轮询）
    }
}
```

- 对任意 worker 数量都正确（某 worker 队列为空时其屏障会在下一轮批次释放，很快）
- 一次请求发 `workers` 个屏障，均非连续屏障流，不触发 `:1261` 的饿死警告
- `workers` 上限 32（`:98` clamp），开销有界

### 仍未实现（下一轮直接照此写）

> ⚠️ **已作废。** 根因不成立（见 §0），P1 已由 `72db136c6`（同步）+ `4209fa047`
> （流式）修复并端到端验证，不需要加 `drain_pending`。以下任务清单仅作记录。

```
1. request_candidate_queue.rs   加 pub(crate) async fn drain_pending(&self)
2. executor/outcome.rs:231      读库前调 state.xxx().drain_pending().await
3. 单测                          多 worker 配置下，drain 后能看到最新候选状态
4. 回归                          既有 prefetch 测试仍断言 503
5. 验证                          回放 orig_req.json → 400（现在是 503）
                                 并对齐 journal 时间戳确认耗尽判定时刻 400 已可见
```



