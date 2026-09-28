# OpenCode 出口 IP 池改造计划

> 状态：进行中（阶段 0 已上线，批次 1 待实施）
> 更新：2026-09-28

## 背景

150K token 的请求经 AE 网关稳定 503（123 秒，100% 失败），
而同一份 payload 直连上游只要 4.5 秒（100% 成功）。

## 根因

三层结构性问题叠加：

1. **池里钉错了 CDN**
   代理域名走 AWS CloudFront，而池里是 43.x / 112.x / 113.x / 124.x 这类
   国内 CDN 段。同样是 150K 请求，实测国内段 92~201 秒，CloudFront 6~9.5 秒。
   60 秒 watchdog 必砍，候选耗尽 → 503。

2. **扫描只看「能不能连通」**
   探测是 TCP 连接 + TLS 握手，不测真实响应时间。
   实测 12 个池内 IP 在 150K 下需要 92~201 秒，全部通过了当时的扫描。
   小请求（8K）测所有节点都是 3~11 秒，完全测不出差别。

3. **每请求新建 session**
   `x-session-id` 每次请求重新生成，上游把每轮对话都当成新会话开始。
   实测改为会话级复用后中位 -512ms、抖动 -3.4s。

## 阶段 0（已上线）

| 项 | 内容 |
|---|---|
| 池替换 | 145 个国内 IP → 65 个实测健康的 CloudFront IP |
| watchdog | 60s → 120s（`providers.stream_first_byte_timeout`） |
| session id | 每请求新建 → 按 `x-client-device-id` 会话级复用 |
| 扫描阈值 | 握手 > 600ms 判死（`OPENCODE_PROBE_MAX_HANDSHAKE_MS`） |
| CIDR | 156 个国内 /26 → 148 个 CloudFront /24 |

**效果**：150K 请求从「123 秒 503，100% 失败」→「7 秒 200，100% 成功」。

---

# 计划一：数据模型与任务重构（批次 1）

## 决策

| 决策点 | 结论 |
|---|---|
| A. pinned 不达标 | 保留 + 标记降级 |
| B. 自动复验 | 开启，6 小时一轮 |
| C. 健康阈值 | 10 秒（env 可调） |
| D. 选 IP 逻辑 | 会话级粘性，游标作兜底 |
| E. 已知 bug | 修复「全池冷却时返回被停用 IP」 |

## 1.1 数据模型

```rust
candidates: Vec<String>,   // 新增，扫描产物
healthy:    Vec<String>,   // 新增，生产唯一列表
pinned:     Vec<String>,   // 新增，手工保护名单
disabled:   Vec<String>,   // 沿用 exit_pool_disabled
exit_pool:  Vec<String>,   // 废弃，迁移后清空
```

集合语义：

```
in_use = healthy − disabled − 冷却

手工加 IP  = 写 candidates + 标记 pinned，立刻可用
手工删 IP  = 从 candidates / healthy / pinned 移除
pinned     = 只影响「是否被自动淘汰」，不影响是否使用
```

**为什么去掉独立的手工池**：任何绕过定期复验的集合都会随时间腐烂。
手工池的定义是「人工加的，不参与自动淘汰」，但人工加的时候是好的、
三个月后未必，而这个状态没有任何信号能暴露出来。`pinned` 只影响淘汰，
不影响可见性——保的东西状态依然是可见的。

## 1.2 数据迁移

```
healthy    ← 现有 exit_pool 的 65 个
candidates ← 65 个
pinned     ← 空
degraded   ← 空
exit_pool  ← 保留字段但不再参与计算
```

## 1.3 验健康任务

```
新增 POST /pool/verify
  输入 candidates
  每 IP 采样 3 次
  中位数 < 10000ms  → 保留在 healthy
  pinned 豁免淘汰，标记 degraded
  写 healthy 前备份到 healthy_prev
  任务失败不覆盖现有 healthy（幂等）
与 scan 互斥，复用 scanning 标志位
```

## 1.4 自动复验

```
auto_enabled  = true
interval_hours = 6
concurrency   = 32
```

## 1.5 选 IP 逻辑改写

### 会话级粘性

```rust
pick_session_anchor(usable, session_key)
  hash(device_id) % len  → 稳定节点
  命中已停用/冷却       → 顺延到下一个可用
  无 session_key        → 退回 rotate_with_cursor（游标兜底）
```

调用点 `candidate_ranking.rs` 透传 `x-client-device-id`。

**收益**：同一设备/会话全程落在同一节点，首字时间可预期，连接可复用。
**代价**：设备数少时集中度更高，等价于「每设备一份配额」。

### 修复既有 bug

```rust
// 现在：全池冷却时 return exit_pool.first()
// 该 IP 可能是被手工 disabled 的，绕过了停用意图
// 改为：返回一个未被 disabled 的（哪怕它正在冷却）
```

## 1.6 状态字段

```
candidate_count  healthy_count  in_use_count
degraded_count   last_verify_at
```

## 1.7 涉及文件

```
apps/aether-gateway/src/handlers/admin/provider/ip_pool/pool.rs
    字段 + 迁移 + verify 任务 + 分层统计
apps/aether-gateway/src/handlers/admin/provider/ip_pool/mod.rs
    状态接口 + /pool/verify 路由
apps/aether-gateway/src/control/route/admin/opencode_ip_pool_routes.rs
    分类 /pool/verify
apps/aether-gateway/src/handlers/shared/request_utils.rs
    allowlist 增加 verify
apps/aether-gateway/src/ai_serving/planner/candidate_ranking.rs
    会话粘性 + 修 bug
apps/aether-gateway/src/opencode_rotation.rs
    新增 pick_session_anchor
frontend/src/api/endpoints/keys.ts
    类型 + verifyOpenCodeIpPool()
```

## 验证方式

```
迁移后    healthy=65、in_use=65，首字仍约 7 秒
手工加    in_use +1
手工停用  in_use −1
跑 verify 计数变化，healthy 只留达标项
清空池    回退普通 DNS，不报错
会话粘性  同一 device-id 连续 5 次请求落在同一节点
冷却兜底  全池冷却时不返回被 disabled 的 IP
```

---

# 计划二：扫描改造（批次 1 的一部分）

## 现状

```
CIDR 展开 → 每 IP 探测 → 通过的直接写进 exit_pool（生产列表）
```

候选直接变生产，扫描即上线，脏数据零成本进池。

## 改后

```
CIDR 展开 → 两级探测 → 写 candidates（只增不删，定期整体刷新）
     ↓
验健康（独立任务）= candidates → 多采样 → healthy（生产列表）
```

**扫描不再有生产影响。**

## 2.1 网段规模

```
148 个 /24 = 148 × 256 = 37,888 个地址
按 OPENCODE_SCAN_MAX_CANDIDATES = 4096，需要约 10 轮扫完
（游标机制已存在，可中断续跑）
```

## 2.2 两级探测

### 第一级：TCP 连接 + TLS 握手

```
SNI = proxy_domain
超时 2s（从 4s 收紧）
握手 > 600ms 判慢，淘汰
→ 快速拒绝绝大多数非目标地址
```

### 第二级：真实 HTTP 请求（仅对第一级通过的）

```
GET /zen/v1/models
Authorization: Bearer public
x-session-id: ses_<26位>
超时 4s，判 2xx
→ 排除「能握手但不服务我们域名」的地址
```

**为什么需要第二级**：只做第一级会放进大量「是 CloudFront 但不承载我们域名」
的 IP。第二级成本低（通过第一级的本来就少），显著提升候选纯度。

## 2.3 吞吐估算

```
第一级  37,888 个
        70% 不可达 → 2s 超时
        30% 可达   → <600ms
        并发 32 ≈ 48 分钟

第二级  约 11,000 个通过
        并发 32 ≈ 1~2 分钟

一轮全量 ≈ 50 分钟，分 10 个分片
```

## 2.4 可调参数

| 参数 | 值 | 环境变量 |
|---|---|---|
| concurrency | 32 → 48 | — |
| 第一级超时 | 2s | `OPENCODE_SCAN_CONNECT_TIMEOUT_SECS` |
| 握手阈值 | 600ms | `OPENCODE_PROBE_MAX_HANDSHAKE_MS` |
| 每轮上限 | 4096 | `OPENCODE_SCAN_MAX_CANDIDATES` |
| 刷新周期 | 6h | `interval_hours` |

## 2.5 candidates 更新策略

```
一轮扫描开始时   记录本轮起点时间戳
一轮扫描结束时   删除 candidates 中「本轮未再见到」的条目
                 但 pinned 的 IP 即使本轮没扫到也要保留
```

## 2.6 与验健康的衔接

```
扫描      → candidates        （贵，约 50 分钟/轮）
验健康    → healthy           （轻，65 × 3 次探测）
```

**生产质量主要靠验健康维持，扫描只负责补充候选池。**
建议先只开自动验健康，扫描保持手工触发；跑顺后再考虑自动扫描。

## 2.7 界面

```
按钮  「扫描候选」  只刷 candidates，不动生产
      「复验健康」  candidates → healthy
      两者分别显示进度与淘汰数
```

---

# 批次 2：前端界面

```
状态条   候选 214 → 健康 65 → 在用 63（降级 2）
         本轮淘汰 149（超时 / 延迟超标）
Tab      在用 63 | 候选 214 | 已淘汰
         在用表加「延迟」「状态」列
         候选/淘汰表显示淘汰原因
按钮     扫描候选 | 复验健康 | 回滚上一版
手工     加 IP = 入候选 + 保护；删 IP = 移出
```

---

# 风险

| 风险 | 保护 |
|---|---|
| 迁移瞬间池空 | healthy ← exit_pool 双重保险 |
| verify 误杀全部 | 先备份 healthy_prev，UI 可回滚 |
| auto_verify 失败 | 幂等，失败不覆盖 |
| 会话粘性降低分散度 | 设备数 ≥ 20 时与轮转等效 |
| 扫描与验健康竞争 | 共用 scanning 标志位互斥 |
| 前端改动大 | 独立批次 |

---

# 附带事项

```
□ 清理 /tmp 下的测试脚本
□ 吊销临时 API key（ttft-probe-temp）
□ 吊销 3 个已泄露的 GitHub PAT
□ RUST_LOG 改回 info
□ 修改管理后台密码 + 上 HTTPS
```

---

# 待确认

`auto_enabled` 的语义调整：

```
原义   自动 = 自动扫描
建议   改成「自动验健康」，扫描保持手工触发
       （因为扫描 50 分钟/轮，验健康才是维持质量的主力）
       这会影响面板上的开关文案
```
