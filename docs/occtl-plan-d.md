# 方案 D：AE 只做透明代理，opencode 逻辑与记录全在 Go

> 目标：Aether 侧只填「接口地址 + 模型 + key」，其余（出口选择、预算、429 冷却、重试、记录）
> 全在 Go 服务 `occtl` 里。AE 把客户端请求原样转发给 occtl，把 occtl 的响应原样回给客户端。
>
> 前置门禁：**Go 直连 opencode 能否拿到 200**（TLS 指纹）。不过则整个方案不成立。

---

## 1. 架构

```
客户端 ──> AE（通用 OpenAI 兼容供应商，零特判）
              │  base_url=http://127.0.0.1:19000/v1
              │  max_retries=0，仅空闲超时
              ▼
            occtl (Go)
              ├─ 选出口（/48 → 随机 /64，排除已试过的）
              ├─ 经 he-pool SOCKS5 绑源地址（user=opencode-ip-<addr>）
              ├─ TLS 出站 opencode.ai
              ├─ 预算 / 429 冷却（retry-after）/ 段限速 / 段熔断 / 内部重试
              ├─ 记录（分层保留）
              └─ 查询接口（/records /summary /state）
```

不变量：

- AE 不再有 `opencode_egress` / 出口卡片 / TLS13 出站（代码保留但不再被该 provider 使用，后续删）
- AE 的 usage 行仍是「客户端视角」：provider、model、tokens、总耗时、最终状态
- attempt 级明细（出口、每次尝试的 status/ttfb/retry-after）唯一来源是 occtl

---

## 2. 接口契约

### 2.1 数据面

```
POST {base_url}/chat/completions
Authorization: Bearer <provider key>
X-Aether-Request-Id: <AE request_id>      # 可选，用于 join
Content-Type: application/json
```

响应透传：状态码、`Content-Type`、`Retry-After`、`X-Egress-Exit`、`X-Egress-Attempts` 原样。
SSE 逐块转发，不缓冲、不改写；非流请求由 occtl 聚合后一次性返回。

```
GET {base_url}/models
```

### 2.2 记录面

```
GET {records_url}/records
    ?since=2026-10-30T10:00:00%2B08:00
    &until=...
    &status=429            # 可选，支持 200/429/5xx 或 "error"
    &exit=2001:470:848d:95c1::1
    &model=big-pickle
    &req_id=r-01HQ8Z9K3M
    &cursor=<base64>
    &limit=200             # 默认 100，最大 1000
→ 200
{
  "items": [ { ...记录行... } ],
  "next_cursor": null,
  "server_time": "2026-10-30T10:58:01+08:00",
  "retention": { "success_s": 600, "error_s": 604800, "slow_s": 86400 }
}

GET {records_url}/records/{req_id}
→ { "req_id": "...", "model": "big-pickle", "stream": true,
    "final_status": 200, "attempts": [ {...}, {...} ] }

GET {records_url}/summary?from=&to=
→ { "requests": 124, "success": 112, "rate_limited": 9, "failed": 3,
    "exits_used": 7, "budget_used": 27, "budget_total": 160,
    "ttfb_p50_ms": 640, "ttfb_p95_ms": 812,
    "top_429_exits": [{"exit_ip":"...","e429":4}],
    "segments_cooling": 1, "next_reset_unix": 1793318400 }
```

记录行：

```json
{ "req_id": "r-01HQ8Z9K3M", "ts": "2026-10-30T10:02:11.412+08:00",
  "model": "big-pickle", "stream": true, "attempt": 1,
  "exit_ip": "2001:470:848d:95c1::1", "segment": "2001:470:848d::/48",
  "status": 200, "ttfb_ms": 812, "dur_ms": 4210, "bytes": 18342,
  "retry_after": null, "error_type": null, "error_excerpt": null,
  "budget_left": 6, "cooldown_until": null }
```

`error_excerpt`：非 200 时取上游 body 前 512 B（用于区分 `FreeUsageLimitError` 等类型）。

### 2.3 控制面（内部）

```
GET  /healthz
GET  /state?provider_id=...        # 出口表 + 段状态 + 预算，字段对齐现有面板
POST /reset?scope=segments|exits|all
POST /config                       # 配置热更新（SIGHUP 的 HTTP 等价物）
```

---

## 3. 记录保留：分层

```json
"records": {
  "keep_success_seconds": 600,      // 成功记录 10 分钟（内存环形，不落盘）
  "keep_error_seconds":   604800,   // 非 200 / 有重试 / 被限流：7 天（落盘）
  "keep_slow_seconds":    86400,    // ttfb > slow_threshold_ms：1 天
  "slow_threshold_ms":    5000,
  "max_memory_entries":   50000,
  "jsonl_dir": "/var/log/occtl/records",
  "jsonl_rotate": "hour",
  "excerpt_bytes": 512
}
```

规则：

| 类别 | 判据 | 保留 | 存储 |
|---|---|---|---|
| 成功 | `status == 200 && !slow && attempt == 1` | 600 s | 仅内存环形 |
| 慢 | `ttfb_ms > slow_threshold_ms` | 86400 s | 内存 + JSONL |
| 失败/限流 | `status != 200` 或 `attempt > 1` | 604800 s | 内存索引 + JSONL |

其他不受保留策略影响：

- **出口账本**（每 /64 的 `requests`/`e429`/`spent_until`/`last_status`）：跟日切周期走，落 `state.json`
- **小时级聚合**（`hourly.json`：请求数、成功率、429 数、p95 ttfb）：保留 7 天，体积几十 KB

查询实现：先扫内存环形，命中不足则按时间窗读对应小时的 JSONL 文件；`cursor` 是 `(文件, 偏移)` 的 base64。

---

## 4. Go 侧结构

```
cmd/occtl/main.go                 装配、SIGHUP 热加载、SIGTERM 落盘
internal/config/config.go         JSON 配置 + 校验 + 默认值
internal/sched/sched.go           候选生成（/48 → /64）、排除、跳过原因
internal/sched/segment.go         令牌桶 + 60s 429 窗口 + 熔断
internal/ledger/ledger.go         出口账本、周期切换、report 记账
internal/ledger/persist.go        tmp+rename 原子写、debounce、导入旧账本
internal/proxy/upstream.go        TLS 出站、源地址绑定（he-pool）、超时
internal/proxy/completions.go     请求改写、SSE 透传、非流聚合、重试循环
internal/records/store.go         环形内存 + JSONL 写 + 查询（过滤/分页）
internal/records/summary.go       小时聚合
internal/api/server.go            数据面 + 记录面 + 控制面路由
internal/observe/log.go           结构化日志（字段与现网关事件对齐）
```

估计 1300–1600 行含测试。

---

## 5. 计划

### M0 门禁验证（先做，0.5 小时）

- 用 Go 绑一个 /48 内的 /64，向 `opencode.ai/inference/v1/chat/completions` 发一次 1-token 请求
- 判据：返回 200 且 usage 正常；若返回 403/被拦，则**停止**，方案改回 B（AE 自己拨号）
- 成本：1 次上游请求

### M1 数据面 MVP（1.5 天）

- `POST /v1/chat/completions`（SSE 透传、非流聚合）、`GET /v1/models`
- 出口绑定（先只支持 he-pool SOCKS5，不做直接 bind）
- 单出口、无重试、无预算（先打通链路）
- 验收：`curl -N` 直连 occtl，SSE 逐块到达；`usage` 字段正确

### M2 决策 + 账本（1 天）

- 选路（轮转 + 排除 + 段级过滤）、预算、429 冷却（retry-after 夹取 60..86400）、段令牌桶与熔断
- 账本落盘 + 启动导入 `opencode-exit-usage.json`
- 内部重试（次数、退避 10/20/40s、换出口）
- 验收：与现网同一天的账本对比 `e429`/`spent_until` 一致；人为触发 429 后该出口不再被选中

### M3 记录与查询（1 天）

- 分层保留、JSONL 落盘、`/records`、`/records/{id}`、`/summary`
- 验收：一次 429 重试请求能在 `/records/{req_id}` 看到 2 个 attempt；成功记录 10 分钟后查不到，失败记录仍在

### M4 接入 AE（0.5 天）

- AE 新建 provider：`base_url=http://127.0.0.1:19000/v1`、key、模型映射、`max_retries=0`、空闲超时 ≥300s
- 路由组权重 10 → 50 → 100
- 验收四条透传检查（见第 6 节）
- 回滚：权重归零，用回原 provider

### M5 观测收尾（0.5 天）

- 脚本迁移：`check-429.sh` 等改读 `/records`、`/state`
- 文档：`docs/occtl-plan-d.md`（本文）+ 运维手册（启停、热加载、对账）
- 可选档 2：前端加「上游记录」表读 nginx 暴露的 `/ext/occtl/v1/records`（只改前端）

**合计约 4.5 天**，其中只有 M4 需要 AE 侧一次配置（无 Rust 编译）。

---

## 6. 透传验收（M4 必做）

| # | 检查 | 判据 |
|---|---|---|
| 1 | 流式与首字节 | `curl -N` 直连 occtl 与经 AE 各一次，首字节时间差 < 5 ms，块边界不被合并 |
| 2 | 429 透传 | 客户端收到 `429` + `Retry-After` + 上游原文 body（不是 AE 包装的 500） |
| 3 | 出口头 | `X-Egress-Exit`、`X-Egress-Attempts` 出现在客户端响应头 |
| 4 | 记录 join | AE 日志里的 request_id 能在 `/records/{req_id}` 查到完整 attempt 轨迹 |

第 2 条需要先确认 AE 通用 provider 路径是否改写上游错误；若改写，在 provider 上开「原样透传错误」——通用开关，不是 opencode 特判。

---

## 7. 风险

| 风险 | 影响 | 对策 |
|---|---|---|
| Go TLS 指纹被上游识别 | 方案不成立 | M0 先验；不过则回退方案 B |
| occtl 单点 | 该 provider 全挂 | `Restart=always` + `RestartSec=0.3`；AE 路由权重可快速归零 |
| AE 侧重试叠乘 | 上游请求倍增 | `max_retries=0`，并在验收里数上游请求数 |
| 超时错配 | 长响应被 AE 掐断 | AE 空闲超时 ≥300 s，总时长由 occtl 控 |
| 记录丢失（10 分钟窗口） | 追查困难 | 失败/慢请求保留 7 天/1 天；账本与小时聚合不受影响 |
| 账本双份 | 统计对不上 | 以 occtl 为唯一账本，AE 只记客户端视角，不做 attempt 统计 |

---

## 8. 迁移与回滚

1. **上线**：新 provider + 路由权重灰度；原 `opencode` provider 保留不动
2. **回滚**：路由权重归零 → 流量回原 provider；`systemctl stop occtl` 不影响其它供应商
3. **清理（稳定一周后）**：删除 AE 侧 `opencode_egress` 配置与出口卡片

无数据迁移风险：occtl 只读导入现有账本文件，不删除。
