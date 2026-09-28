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

### 配置拆分：扫描域与验健康域分离

两者频率差 10 倍以上，混在一个开关下无法各自调节。

```rust
// 扫描域：找新节点（慢，产出「新的可能性」）
config.opencode_scan = {
    cidrs,                    // 扫描源
    candidates,               // 扫描产物
    auto_scan_enabled,        // 默认 false
    scan_interval_hours,      // 默认 168（7 天）
}

// 验健康域：筛坏节点（快，产出「当前可信集」）
config.opencode_health = {
    healthy,                  // 生产唯一列表
    degraded,                 // pinned 但不达标
    auto_verify_enabled,      // 默认 true
    verify_interval_hours,    // 默认 3
    verify_samples,           // 默认 3
    verify_max_median_ms,     // 默认 10000
}

// 共用
config.opencode_scan.disabled = [...]   // 沿用 exit_pool_disabled
config.opencode_scan.pinned    = [...]   // 手工保护
```

**为什么是两个不同的周期：**

| | 扫描 | 验健康 |
|---|---|---|
| 单轮成本 | 37,888 次探测 ≈ 50 分钟 | 65 × 3 = 195 次探测 ≈ 2~5 分钟 |
| 产出 | candidates（补充新节点） | healthy（维持质量） |
| 何时需要 | AWS 扩容新网段时 | 节点质量漂移时 |
| 漂移尺度 | 月级 | 小时级（实测 8s ↔ 200s） |

扫描每日跑是 37,888 次/天；验健康每 3 小时是 780 次/天。差 48 倍。
**扫太勤反而有害**：candidates 会积攒「握手通但不服务我们域名」的噪声。

### 状态拆分

```rust
status = {
    // 扫描
    scanning, scan_progress_done, scan_progress_total,
    // 验健康
    verifying, verify_progress_done, verify_progress_total,
    // 清理
    cleaning,
    // 共用统计
    candidate_count, healthy_count, in_use_count, degraded_count,
}
```

现状是共用一个 `progress_done/total`，两个任务同时跑会互相覆盖进度，
界面显示的数字会错。

### 共享的部分（不拆）

```
candidates    两边都读，天然共享
pinned        验健康读，扫描写时保留
探测原语       probe_upstream_ip 两边复用
冷却/停用      共用同一份判定
互斥标志       扫描与验健康仍需互斥（并发探测同一批 IP 没意义）
```

**拆的是「配置归属」和「状态展示」，不是「执行资源」。**

## 1.2 集合语义

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

## 1.4 自动调度

```text
自动验健康   开，3 小时一轮（195 次探测，开销可忽略）
自动扫描     关（37,888 次/天的代价换不来等价的收益）
按需触发     healthy 数 < 32 时面板提示「建议执行一次候选扫描」
```

扫描默认关是有意的：它的产出是「新节点的可能性」，变化以月计；
而质量维持靠的是 3 小时一轮的验健康。需要补池时手工触发一次即可。

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
扫描      → candidates        （贵，50 分钟/轮，7 天一次或按需）
验健康    → healthy           （轻，195 次探测，3 小时一次）
```

**生产质量完全由验健康维持，扫描只负责在需要时补充候选池。**
两个任务共用 `scanning` 标志位互斥，避免并发探测同一批 IP。

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
开关     自动验健康（3 小时）  ← 默认开
         自动扫描（7 天）      ← 默认关
进度     扫描和验健康各自独立的进度条
按钮     扫描候选 | 复验健康 | 回滚上一版
         healthy < 32 时提示「建议执行一次候选扫描」
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

# 决策记录

| 决策点 | 结论 |
|---|---|
| A. pinned 不达标 | 保留 + 标记降级 |
| B. 自动调度 | 验健康开（3 小时），扫描关（按需触发） |
| C. 健康阈值 | 10 秒（`verify_max_median_ms`，env 可调） |
| D. 选 IP 逻辑 | 会话级粘性，游标作兜底 |
| E. 已知 bug | 修复「全池冷却时返回被停用 IP」 |
| F. 任务分离 | 扫描与验健康在配置、状态、调度、开关上完全分开 |
| G. 手工池 | 去掉独立层，改为 `pinned` 保护名单 |
