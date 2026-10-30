# 方案 B：occtl —— opencode 出口的调度控制面

> 目标：把「选哪个出口、预算剩多少、被限流后冷却多久、段要不要熔断」从 Rust 网关搬到独立的 Go 服务，
> 网关只负责**拨号、传输、日志、统计**。
> 关键约束：**数据面不搬家**。所以日志仍在网关侧第一时间产生，非流请求不会多一层等待。

---

## 1. 目标 / 非目标

### 目标

| 项 | 现状 | 目标 |
|---|---|---|
| 改一条调度策略的周期 | 本地编译 11–19 min + CI 12 min + 部署 1 min ≈ 30 min | `go build` 3 s + `systemctl restart occtl` 0.3 s |
| 策略调参 | 改代码 + 面板保存触发 reload | 改 `config.json` + `SIGHUP`，或面板保存后由网关推送 |
| 重启后状态 | 网关重启清空内存冷却与账本（已现场验证） | Go 账本落盘，重启不丢 |
| 决策可观测 | 只有 `被跳过的出口（预算/熔断/限速）` 一条汇总 | 每次 lease 都有结构化决策记录（候选、跳过原因、预算余额） |

### 非目标（明确不做）

- 不做数据面代理。TLS 仍由网关自己发（`tls13_upstream.rs` 不动），he-pool 仍由网关用 `opencode-ip-<addr>` 绑地址。
- 不接管上游协议细节：SSE 解析、usage 提取、错误改写都在网关。
- 不做多 provider 的通用调度引擎（先只服务 opencode，接口留 provider_id 以便将来扩）。

---

## 2. 架构

```
                        ┌──────────────────────────── Aether 网关（Rust，现有代码）────────────────────────────┐
客户端 ──HTTP──> │ 路由/鉴权 → 执行运行时 → tls13_upstream → 日志 · usage · 面板 · 重试(delayed_retry)  │
                        └───────▲─────────────────────────────┬──────────────────────────────────────────────┘
                                │  /v1/lease  /v1/report      │  TLS + 源地址绑定（经 he-pool SOCKS5）
                                │  /v1/cancel /v1/state       ▼
                    ┌───────────┴───────────┐        he-ipv6-pool (127.0.0.1:13001)
                    │  occtl (Go, :19001)   │        user = opencode-ip-<encoded addr>
                    │  ledger + scheduler   │        （池子只负责绑地址，不参与决策）
                    └───────────────────────┘
```

不变的部分（这是本方案的核心价值）：

- `opencode 出口建连成功`、`opencode 出站请求`、`opencode_exit_rate_limited` 三条日志**仍由网关写**，字段不变
- usage 记录的 `exit` / `exit_ip` 不变（网关自己知道自己拨了哪个地址）
- 非流请求的等待时间不变（没有中间缓冲、没有第二层超时）
- 现有面板卡片、`check-429.sh` 等脚本继续可用（数据源从内存账本换成 `/v1/state`，字段同名）

---

## 3. 协议

传输：`127.0.0.1:19001`（可选 Unix socket `/run/occtl.sock`，延迟更低且不走 TCP 栈）。
编码：JSON，`Content-Type: application/json`。
所有请求带 `X-Occtl-Version: 1`；服务端不兼容时返回 426。

### 3.1 `POST /v1/lease` —— 申请出口

```json
{
  "provider_id": "bea505db-92e2-47d1-adf5-405e7c249a95",
  "want": 1,
  "exclude": ["2001:470:2996:f3ad::1"],
  "req_id": "r-01HQ8Z9K3M",
  "deadline_ms": 45000
}
```

- `want`：一次要几个（默认 1；预热式重试可要 2–3，避免每次重试都往返）
- `exclude`：本次请求已经试过的出口（网关维护，Go 不需要猜）
- `deadline_ms`：网关打算等多久；Go 内部据此决定要不要为了等一个冷段解冻而阻塞（**永远不阻塞**，够不上就直接 409）

成功 `200`：

```json
{
  "leases": [
    {
      "lease_id": "l-01HQ8Z9K3N",
      "exit_ip": "2001:470:848d:95c1::1",
      "exit_name": "2001:470:848d:95c1::1",
      "segment": "2001:470:848d::/48",
      "dynamic": true,
      "budget_left": 7,
      "lease_expires_at": 1793320060
    }
  ]
}
```

无可用出口 `409`：

```json
{
  "code": "no_exit",
  "detail": {
    "candidates": 4096,
    "skipped": { "spent": 12, "cooling": 3, "segment_blocked": 1, "segment_rate_limited": 0 },
    "retry_after_ms": 18000,
    "fallback": "direct"
  }
}
```

网关拿 `409` 时的行为与现在「出口全部处于冷却中」一致：按 `opencode_egress.fallback_ipv4` 决定回落直连还是报错，并把 `retry_after_ms` 透给上层的延迟重试。

**lease 语义**：一条 lease 表示「这个 /64 的这个预算名额被该请求占住，60 秒有效」。
未 `report` 且未 `cancel` 的 lease 到期自动释放，**不计入 requests**（避免网关崩溃导致预算被吃掉）。

### 3.2 `POST /v1/report` —— 回填结果

```json
{
  "provider_id": "bea505db-92e2-47d1-adf5-405e7c249a95",
  "lease_id": "l-01HQ8Z9K3N",
  "req_id": "r-01HQ8Z9K3M",
  "attempt": 1,
  "result": "rate_limited",
  "status": 429,
  "ttfb_ms": 3063,
  "bytes": 0,
  "retry_after": 25681
}
```

`result` 取值：

| result | 语义 | 账本动作（对齐现有 Rust 语义） |
|---|---|---|
| `ok` | 建连成功（拨通即算，不等响应） | `requests += 1`，清 `last_status` |
| `rate_limited` | 上游 429 | `e429 += 1`、`last_status = 429`、`spent_until = now + clamp(retry_after, 60, 86400)`；段事件 +1，达阈值则整段冷却 |
| `dial_failed` | TCP/TLS 建连失败 | `cooldowns[exit] = now + down_seconds` |
| `client_aborted` | 客户端提前断开 | 只释放 lease，不动账本 |

响应：

```json
{
  "exit_ip": "2001:470:2996:f3ad::1",
  "budget_left": 6,
  "cooling_until": null,
  "segment_cooling_until": 1793318400,
  "e429_total": 1
}
```

**幂等**：`(lease_id, attempt)` 是幂等键，重复上报只记 warn 不重复记账。
**顺序**：允许乱序到达（并发请求多），账本用「单调推进」的 `spent_until = max(existing, new)`。

### 3.3 `POST /v1/cancel`

```json
{ "provider_id": "...", "lease_id": "l-01HQ8Z9K3N", "reason": "client_closed" }
```

### 3.4 `GET /v1/state?provider_id=...`

返回结构与现有 `usage_report` **同构**（字段名逐一对齐，前端一行不用改）：

```json
{
  "provider_id": "...",
  "request_budget": 10,
  "budget_reset_utc_hour": 0,
  "segment_rpm": 8,
  "segment_burst": 3,
  "segment_fail_threshold": 3,
  "segment_cooldown_seconds": 900,
  "exits": [
    { "name": "...95c1::1", "kind": "dynamic", "segment": "2001:470:848d::/48",
      "enabled": true, "exit_ip": "...95c1::1", "requests": 3, "e429": 1,
      "last_status": 429, "budget": 10, "exhausted": false,
      "spent_until_unix": 1793318400, "spent_seconds_left": 25498,
      "cooling_seconds_left": 0 }
  ],
  "segments": [
    { "segment": "2001:470:848d::/48", "distinct_429_exits_60s": 1,
      "cooldown_seconds_left": 0, "tokens": 7.5 }
  ]
}
```

### 3.5 `POST /v1/reset?scope=segments|exits|all`

语义与现有 `POST /api/admin/providers/{id}/opencode-exits/reset` 完全一致（面板「清除熔断」按钮背后就是它）。

### 3.6 `POST /v1/config` —— 面板改配置后由网关推送

```json
{
  "provider_id": "...",
  "nodes": [ { "name": "local", "addr": "127.0.0.1:13001", "user": "opencode",
               "prefixes": ["2001:470:848d::/48"], "enabled": true } ],
  "request_budget": 10,
  "budget_reset_utc_hour": 0,
  "segment_rpm": 8,
  "segment_burst": 3,
  "segment_fail_threshold": 3,
  "segment_cooldown_seconds": 900,
  "down_seconds": 60,
  "fallback_ipv4": false
}
```

**配置归属**：唯一事实来源仍是 provider 的 `opencode_egress`（面板编辑）。网关在 `set_provider_egress` 之后调用本接口推送；occtl 启动时也允许从自己的 `config.json` 读一份（用于不带网关单独跑测试）。

### 3.7 `GET /healthz`

```json
{ "ok": true, "uptime_s": 8123, "state_file": "/var/lib/occtl/state.json",
  "lease_inflight": 2, "last_persist_s_ago": 3 }
```

---

## 4. occtl 内部模型

```go
type ExitState struct {
    Name        string
    Segment     string
    Dynamic     bool
    Requests    int
    E429        int
    LastStatus  int
    SpentUntil  int64 // 本周期用满 / 429 冷却
    CooldownEnd int64 // 建连失败冷却
}

type SegmentState struct {
    Tokens      float64
    RefilledAt  int64
    Events      []event // 最近 60s 内的 (ts, exit_ip)
    CoolingEnd  int64
}

type Lease struct {
    ID       string
    ExitIP   string
    ReqID    string
    Expires  int64
    Consumed bool
}
```

- **周期**：`period = "d" + utc_days(budget_reset_utc_hour)`；跨周期时 `prune_stale_periods` 只保留新周期的键（与现有实现一致）
- **落盘**：`tmp + rename` 原子写 `state.json`；每次 report 后 debounce 200 ms 写一次，退出时强制写
- **迁移**：首次启动若发现 `/opt/aether/state/opencode-exit-usage.json`，导入一次（结构与字段名兼容），之后以 Go 为准
- **锁**：单进程 `sync.Mutex`；`/v1/lease` 与 `/v1/report` 在同一把锁下临界区极短（< 50 µs），不做异步队列

---

## 5. 关键路径时序

### 5.1 正常请求

```
客户端 → 网关: POST /v1/chat/completions
网关 → occtl:  POST /v1/lease {want:1}
occtl → 网关:  200 {exit_ip: 2001:470:848d:95c1::1, budget_left: 7}
网关 → he-pool: SOCKS5 user=opencode-ip-2001-470-848d-95c1--1  → opencode.ai:443
网关日志:      opencode 出口建连成功  ← 这一行仍然发生在网关，时间点与现在完全相同
网关 → occtl:  POST /v1/report {result: ok, status: 200, ttfb_ms: 812}
网关日志:      opencode 出站请求 status=200
```

### 5.2 429 后换出口

```
… 上游 429, retry-after: 25681
网关 → occtl:  POST /v1/report {result: rate_limited, retry_after: 25681}
occtl:         e429+1, spent_until = now+25681, 段事件+1（可能整段熔断）
网关:          等待 delayed_retry 退避 → 下一轮
网关 → occtl:  POST /v1/lease {exclude:[已试过的]}
occtl → 网关:  200 {exit_ip: 另一个 /64}
```

### 5.3 客户端中途断开

```
网关 → occtl:  POST /v1/cancel {lease_id, reason:"client_closed"}
（若是已拨通的连接 → 改用 /v1/report {result:"client_aborted"}）
```

### 5.4 occtl 不可用

网关在 lease 上设 **200 ms** 超时；超时或连接失败 → 走**本地降级实现**（现有 Rust 逻辑保留一个版本周期），并打一条 WARN：

```
event_name="occtl_unavailable_fallback_local" log_type="ops" provider_id=... err=...
```

降级不是永久切换：每 30 s 探测一次 `/healthz`，恢复后自动回到 occtl 决策。

---

## 6. Rust 侧改动清单

只改 `apps/aether-gateway/src/execution_runtime/`，不动传输层。

| 文件:位置 | 动作 |
|---|---|
| `opencode_egress.rs:1316 dial()` | 保留函数签名与「拨号 + 记录日志 + 失败 mark_down」骨架；把 `1361–1390` 的候选遍历/冷却/预算/段令牌判断替换为 `occtl.lease()`。拿到 `exit_ip` 后仍用 `socks5_connect` 拨号 |
| `opencode_egress.rs:836 record_exit_request` | 不再在 dial 里调用（记账权交 Go）；函数保留，供 fallback 与影子模式 |
| `opencode_egress.rs:934 apply_exit_rate_limit` | 改为 `occtl.report(result=rate_limited, retry_after)`；fallback 时走原逻辑 |
| `opencode_egress.rs:816/1192/1206/1278` | `is_spent` / `segment_cooling_seconds` / `segment_take_token` / `is_cooling` 仅在 fallback 与影子模式使用 |
| `opencode_egress.rs:1050 usage_report` | 先取 `/v1/state`；失败则回落本地账本（保证面板永远有数据） |
| `opencode_egress.rs:1003/1016` | `clear_segment_breakers` / `clear_exit_cooldowns` 转发 `/v1/reset` |
| `opencode_egress.rs:280 set_provider_egress` | 装配配置后调用 `occtl.push_config()`（异步、失败只 warn） |
| **新增** `execution_runtime/occtl.rs` | HTTP 客户端：连接复用、200 ms 超时、3 次失败熔断 30 s、`routing` 模式判定（`local` / `shadow` / `occtl`） |
| `opencode_egress.rs` 配置解析 | 新增 `routing` 字段（默认 `local`，灰度期显式设 `shadow`） |

**不动的部分**：`tls13_upstream.rs` 全部、`transport.rs` 的 exit 上报、usage metadata 钩子、`opencode_rotation.rs` 的 legacy SOCKS5 路径、延迟重试策略。

改动量估计：修改 ~200 行，新增 ~150 行（客户端 + 影子日志 + 配置字段）。

---

## 7. Go 侧结构

```
cmd/occtl/main.go                 装配 + 信号处理（SIGHUP 热加载、SIGTERM 落盘）
internal/api/server.go            /v1/lease /v1/report /v1/cancel /v1/state /v1/reset /v1/config /healthz
internal/api/handlers_test.go
internal/sched/sched.go           候选生成（/48 → 随机 /64）、exclude、跳过原因统计
internal/sched/segment.go         令牌桶 + 60s 事件窗口 + 熔断
internal/ledger/ledger.go         ExitState/SegmentState、report 记账、周期切换
internal/ledger/persist.go        tmp+rename 原子写、debounce、启动导入旧账本
internal/config/config.go         JSON 配置、默认值、校验
internal/observe/log.go           结构化 JSON 日志（字段名与网关事件对齐）
internal/observe/metrics.go       Prometheus 文本格式（可选）
```

目标代码量：1200–1600 行含测试。

---

## 8. 配置示例

`/etc/occtl/config.json`

```json
{
  "listen": "127.0.0.1:19001",
  "state_file": "/var/lib/occtl/state.json",
  "log_file": "/var/log/occtl/occtl.log",
  "lease_ttl_seconds": 60,
  "persist_debounce_ms": 200,
  "providers": {
    "bea505db-92e2-47d1-adf5-405e7c249a95": {
      "nodes": [
        { "name": "local", "addr": "127.0.0.1:13001", "user": "opencode",
          "prefixes": ["2001:470:848d::/48"], "enabled": true },
        { "name": "box3", "addr": "47.86.176.10:13001", "user": "opencode",
          "prefixes": ["2001:470:2996::/48"], "enabled": true }
      ],
      "request_budget": 10,
      "budget_reset_utc_hour": 0,
      "segment_rpm": 8,
      "segment_burst": 3,
      "segment_fail_threshold": 3,
      "segment_cooldown_seconds": 900,
      "down_seconds": 60
    }
  }
}
```

systemd：

```ini
[Unit]
Description=occtl - opencode egress scheduler
After=network-online.target

[Service]
ExecStart=/opt/occtl/occtl -config /etc/occtl/config.json
Restart=always
RestartSec=1
StateDirectory=occtl
ExecReload=/bin/kill -HUP $MAINPID

[Install]
WantedBy=multi-user.target
```

---

## 9. 灰度切换

| 阶段 | 网关 `routing` | occtl | 判定 |
|---|---|---|---|
| 0 影子 | `shadow` | 只回 lease，**结果不采用** | 网关同时算本地决定和 occtl 决定，差异写 `occtl_lease_diff` 事件；要求连续 6 小时差异 0 |
| 1 双记 | `occtl`，本地账本继续写 | 记账生效 | 每日对账脚本比 `requests`/`e429`/`spent_until`，要求完全一致 |
| 2 单记 | `occtl`，本地只读 | 唯一账本 | 面板与 `/v1/state` 一致性对比 |
| 3 收尾 | 删除本地决策（保留 fallback 一个版本） | — | — |

阶段 0 的对照脚本（无需改生产逻辑）：

```bash
# 从日志里取同一次 dial 的两条决定
journalctl -u aether-gateway --since -1h | grep -E "occtl_lease_diff" | wc -l   # 目标 0
```

---

## 10. 回滚

任一层都能单独回：

1. 面板/DB 把 `opencode_egress.routing` 改回 `local` → 网关立刻用本地逻辑，occtl 可保留运行
2. `systemctl stop occtl` → 网关在 200 ms 超时后降级，日志出现 `occtl_unavailable_fallback_local`
3. 回滚网关版本：`ln -sfn /opt/aether/releases/<上一个> /opt/aether/current && systemctl restart aether-gateway`

无数据迁移风险：occtl 账本文件与现有 `opencode-exit-usage.json` 同构，只读导入，不删原文件。

---

## 11. 验收标准

1. **日志零丢失**：`opencode 出口建连成功` / `出站请求` / `exit_rate_limited` 三条事件的字段与条数与切换前一致（同一时段对比）
2. **账本一致**：`/v1/state` 与现面板 JSON 字段名 diff 为空；`e429` 合计与日志里 `status=429` 条数一致（今天这个闭环刚修好，正是回归基线）
3. **延迟**：`/v1/lease` p99 < 2 ms（UDS）/ < 5 ms（TCP 回环）；请求总耗时 p50 变化 < 5 ms
4. **非流不受影响**：构造一个 40 s 上游（用 137 KB 大响应那次的复现脚本），切换前后首字节时间一致
5. **降级可用**：`systemctl stop occtl` 后 100 个请求成功率无下降，日志有且仅有降级 WARN
6. **热调参**：改 `request_budget` 后 `SIGHUP`，下一个 lease 生效，网关零重启

---

## 12. 风险与对策

| 风险 | 影响 | 对策 |
|---|---|---|
| occtl 单点 | 决策失败 | 网关保留本地 fallback + 200 ms 超时 + 自动恢复探测；fallback 路径本身已有完整单测 |
| 两套账本漂移 | 统计不可信 | 阶段 1 每日对账脚本，不一致则告警并按 Go 为准重建本地 |
| 配置双写 | 面板改了不生效 | 配置唯一来源是 provider；`/v1/config` 推送 + occtl 启动自检（版本号/时间戳），不一致时日志 WARN |
| 时钟/跨日 | 预算提前或延后重置 | 沿现有 `budget_reset_utc_hour` 逻辑，UTC 计算；`/v1/state` 暴露 `next_reset_unix` 供核对 |
| lease 泄漏 | 预算被占 | TTL 60 s 自动释放 + `/v1/cancel`；并发上限保护 |
| 未来要扩到其它 provider | 结构不适配 | 所有端点都带 `provider_id`，内部状态按 provider 分片 |

---

## 13. 里程碑

| 阶段 | 交付 | 估时 |
|---|---|---|
| M1 | Go：ledger + sched + api + 单测；用今天的 `opencode-exit-usage.json` 做导入与回放测试 | 1 天 |
| M2 | Rust：`occtl.rs` 客户端 + `shadow` 模式 + 差异日志；部署影子跑 6 小时 | 1 天（含一次 CI） |
| M3 | 切 `routing=occtl`，双记对账 1 天 | 0.5 天 |
| M4 | 面板改读 `/v1/state`（后端已透传，前端不用动）、脚本改 URL、文档 | 0.5 天 |
| M5 | 收尾：删本地决策（保 fallback）、回归 | 0.5 天 |

合计约 **3.5 天**，其中只有 M2 需要一次 12 分钟的 CI。

---

## 14. 附：与方案 A 的差别（为什么不做数据面代理）

| | B（本方案） | A（数据面代理） |
|---|---|---|
| 日志位置 | 网关（不变） | 侧车，需要事件回推 + header 回填 |
| 非流延迟 | 不变 | 多一层缓冲与超时 |
| TLS 指纹 | 不变 | Go 的指纹，风险未知 |
| 一次性 Rust 改动 | ~350 行 | ~30 行 + 协议消费端 |
| 之后迭代速度 | Go 3 s | Go 3 s（但排查要跨两套日志） |
