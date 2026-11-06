# relay 请求体回执（relay echo body v2）—— 设计方案

> 配套契约：`docs/aether-relay-provider-integration-spec.md` A.5（请求头回执）。
> 本文是**请求体**回执的完整设计，含大 body 暂存通道。
> 状态：待评审（三个待定项见 §12）。

## 1. 目标与不变量

| # | 不变量 |
|---|---|
| 1 | **替换不追加**：`provider_request_body_ref` 覆盖为 relay 真实上游 body；blob 数量不变 |
| 2 | **跟随系统策略**：`request_record_level`、`request_record_max_body_size_kb`、`request_record_compact_base64_images`，不新增开关 |
| 3 | **不双存**：relay 暂存是短 TTL 中转，AE 取走即覆盖，relay 随后删除 |
| 4 | **旁路失败不影响业务**：拿不到 body 只降级状态，请求照常返回 |
| 5 | **可回滚**：旧 relay 只回 v1，新 AE 必须兼容；新 relay 在未收到 body 请求时不产生任何开销 |

## 2. 策略联动（按系统实际语义）

`system_configs.request_record_level` 有三个取值，但代码只把 `full` 当成“采集 body”：

| 取值 | 实际行为 | 说明 |
|---|---|---|
| `headers`（**生产现值**） | 四个 body 字段全部 `disabled`，只存请求头/响应头 | 与 `basic` 等价 |
| `basic`（默认值） | 同上 | 代码：非 `full` 一律按 Basic 处理 |
| `full` | 按 `request_record_max_body_size_kb` 采集四个 body | 未知取值也 fail-closed 回落到 Basic |

因此 echo 的开关不是新开关，而是**跟随 `request_record_level`**：

| `request_record_level` | AE 发给 relay | relay 行为 | AE 落库 |
|---|---|---|---|
| `headers` / `basic` | 只带 `X-Aether-Echo: 1` | 只回请求头 | 四个 body 字段保持 `disabled`（reason `request_record_level_basic`） |
| `full` | 追加 `X-Aether-Echo-Body: 1` 等三个头 | 采集最终 body，按 §4 决定 inline / staged | `provider_request_body_ref` 覆盖；状态见 §7 |

策略在**请求开始时读一次**并向下传递，避免中途变更导致同一请求口径不一致。

### 2.1 生产现状（2026-11-04 已切换）

| 键 | 值 |
|---|---|
| `request_record_level` | `"full"`（已切） |
| `request_record_max_body_size_kb` | `0`（不限，按系统设置语义） |
| `request_record_compact_base64_images` | `true` |
| `max_request_body_size` | 5242880（legacy，已不参与 openai chat 采集） |

`0 = 不限制`：AE 侧不截断，relay 也不自行加业务上限；暂存按容量淘汰（§5.1），
淘汰或超时则降级为 `unavailable`。

### 2.2 透传前提：进站 body 就是 AE 出站 body

AE → relay 是原样透传（只换鉴权头），所以：

- relay 的**进站 body** ≡ AE 的**出站 body**（也就是 AE 自己记录的 `provider_request_body`）
- relay 的**出站 body** 才是真正发往上游的那份

因此**差异比较在 relay 侧完成**，AE 不需要回传自己的副本：relay 拿进站与出站两份 body
逐顶层字段比对，回执里带 `body_rewritten` + `body_diff{added,removed,changed}`。
AE 只负责把出站 body **原地覆盖**写入 `provider_request_body_ref`，不新增列。

这同时解决了“替换就看不到原样”的问题：原文不需要留，字段级差异已经指明 relay 改了什么。

## 3. 协议 v2

### 3.1 请求头（仅 full 模式）

| 头 | 值 | 说明 |
|---|---|---|
| `X-Aether-Echo` | `1` | 已有 |
| `X-Aether-Echo-Trace` | `<uuid>` | 已有（`X-Aether-Trace-Id`） |
| `X-Aether-Echo-Body` | `1` | 新增：请求 body 回执 |
| `X-Aether-Echo-Body-Max` | 字节数 | 新增：等于 `request_record_max_body_size_kb × 1024`；为 `0` 表示**不限制**（AE 与 relay 都不截断） |
| `X-Aether-Echo-Body-Compact-Images` | `0`/`1` | 新增：与 `request_record_compact_base64_images` 同值 |

### 3.2 回执 payload（`X-Aether-Provider-Request-Headers`）

```json
{
  "v": 2,
  "service": "workbuddy2api",
  "version": "dcc45e3",
  "method": "POST",
  "path": "/v1/chat/completions",
  "trace_id": "…",
  "headers": { "...": "..." },
  "header_count": 22,
  "truncated": false,

  "body_mode": "inline | staged | none",
  "body_sha256": "hex(64)",
  "body_bytes": 1245678,
  "body_stored_bytes": 1048576,
  "body_content_type": "application/json",
  "body_encoding": "gzip",
  "body_truncated": true,
  "body_attempts": 1,

  "body_inline_b64": "…",
  "body_stage_id": "9f1c…",
  "body_stage_exp": 1793721000,
  "body_stage_sig": "hex(64)"
}
```

**字节口径（必须统一）**：`body_sha256` / `body_bytes` 都按**实际写到网络上的字节**计算（即 gzip 之后的字节流，与 `Content-Encoding` 一致）；`body_stored_bytes` 是 relay 按 `Body-Max` 截断后的长度。AE 侧不做二次解压重算。

**多尝试**：relay 内部若重试上游，只回**最后一次实际产生响应的那次尝试**的 body，并在 `body_attempts` 写明尝试次数。

**非 JSON / 二进制**（multipart、音频、图片）：只回 hash + 长度，`body_mode=none`，不 inline、不暂存——避免把二进制塞进回执。

### 3.3 8 KB 预算分配（relay 侧固定顺序）

1. 先放 `headers`（必须完整，沿用 v1 裁剪规则）
2. 再放 body 元数据（约 300 B，必须完整）
3. 剩余空间放 `body_inline_b64`
4. 放不下 → 改为 `staged`（若暂存可用），否则 `none`

## 4. 小 body / 大 body 判定

```
if body 非 JSON          → none（只回 hash）
elif 编码后 ≤ 剩余预算      → inline
elif 暂存可用             → staged
else                     → none（只回 hash）
```

`staged` 与 `inline` 的 body 都必须先按 `Body-Max` 截断（`body_truncated=true`）。

## 5. 暂存通道

### 5.1 存储

- 仅内存，不上磁盘；key = 128-bit 随机 `stage_id`
- TTL 默认 **600 秒**（覆盖长流式；见 §6）
- 容量：单实例 64 MiB 或 200 条，LRU 淘汰
- 取走后保留 **10 秒**重试窗，之后删除
- 进程重启即丢 → AE 记 `unavailable`

### 5.2 取回接口（relay 侧，绑回环）

```
GET /_aether/echo/body/{stage_id}?exp=<unix>&sig=<hex>&trace=<trace_id>
```

- `sig = HMAC-SHA256(echo_secret, stage_id + "|" + exp + "|" + trace_id)`
- `echo_secret = HMAC-SHA256(console_shared_secret, "echo-body")` —— 复用现有共享密钥派生，**不新增配置项**
- 返回 `200` + `Content-Encoding: gzip` + 原始字节
- `403` 签名不符；`404` 不存在/已过期；`410` 已取走且超出重试窗
- 访问日志只记 `stage_id` 前缀与长度，不记内容

### 5.3 并发与幂等

- 同一 `stage_id` 在重试窗内可重复取（返回相同字节）
- 多 AE 实例场景由签名 + 一次性语义兜住；不做实例绑定

## 6. 流式场景（关键修正）

**不能在 usage 收尾时才拉取。** 长流式响应可能持续数分钟，等到收尾时 stage 早已过期。正确做法：

```
收到 relay 响应头
  → 解析出 body_mode
  → 若 staged：立刻起一个后台任务拉取（超时 2s，重试 1 次）
  → 拉到的字节暂存在本次请求上下文（内存，≤ Body-Max）
  → usage 事件构造时直接取用，不再发网络请求
```

这样 TTL 只需覆盖“响应头到后台任务完成”的几秒，600 秒是宽松上限。

拉取失败不阻塞流式输出；本次请求记 `unavailable` + reason。

## 7. 落库与状态机

| 场景 | `provider_request_body_state` | reason（`request_metadata`） |
|---|---|---|
| basic | `disabled` | `request_record_level_basic` |
| full + inline 成功 | `reference` | — |
| full + staged 拉取成功 | `reference` | — |
| 超过 `Body-Max` | `truncated` | `echo_body_truncated` |
| stage 过期 / 被淘汰 / relay 重启 | `unavailable` | `echo_body_stage_missing` |
| 拉取超时或签名失败 | `unavailable` | `echo_body_fetch_failed` |
| relay 只回 v1 | `unavailable` | `echo_body_unsupported` |

**写入语义**：`usage_body_blobs` 唯一键是 `(request_id, body_field)`，覆盖写必须是 **UPSERT**，不能 INSERT 冲突。

不新增列：`provider_request_body_ref` 本身就是出站请求体字段，覆盖即可。曾试加 `provider_body_source`（与 `provider_headers_source` 对称），因单行 upsert 漏绑导致审计写入全线失败，已回滚。
迁移：`20261104000000_add_provider_body_source.sql`（加列）+ `20261104000001_drop_provider_body_source.sql`（回滚删列），最终无此列。

## 8. 失败矩阵

| 故障 | 业务请求 | 落库 | 告警 |
|---|---|---|---|
| relay 不认 body 头 | 正常 | `unavailable / unsupported` | 无 |
| 暂存满被淘汰 | 正常 | `unavailable / stage_missing` | 计数 > 0.5% 告警 |
| 拉取超时 | 正常 | `unavailable / fetch_failed` | 计数 > 1% 告警 |
| 签名密钥不一致 | 正常 | `unavailable / fetch_failed` | 立即告警（配置错误） |
| relay 重启 | 正常 | `unavailable / stage_missing` | 无 |

## 9. 可观测性

指标（relay）：`echo_body_inline_total`、`echo_body_staged_total`、`echo_body_skipped_total{reason}`、`echo_stage_evicted_total`、`echo_stage_bytes`。
指标（AE）：`relay_echo_body_total{mode,result}`、`relay_echo_body_fetch_seconds`。

审计字段已可查：`provider_request_body_ref`（指向 relay 真货）、`provider_headers_source=upstream_echo`、`provider_request_body_state`。

## 10. 安全

- 取回接口只监听回环，不对外暴露
- 签名绑定 `stage_id + exp + trace_id`，无法跨请求读取
- 暂存不上盘、TTL 到期即删；AE 侧 blob 沿用现有保留策略
- body 内容不写 relay 访问日志
- `basic` 模式下 relay 完全不采集 body，避免无谓持有用户内容

## 11. 灰度与回滚

1. 先上 relay（v2 能力），AE 仍发 v1 请求 → 行为不变
2. AE 打开 `relay_echo_body` 开关，先对单个 provider 生效，观察 24h
3. 全量；异常时关开关即可回到 v1 路径（relay 侧无需改动）
4. 数据回滚：不新增列，历史行与读取路径完全不受影响

## 12. 已定决策

| # | 问题 | 结论 |
|---|---|---|
| 1 | `request_record_level` | **已切 `full`**（2026-11-04） |
| 2 | body 大小上限 | **跟随系统设置 `request_record_max_body_size_kb`，`0` = 不限制** |
| 3 | 存哪一份 | **存 relay 真货**（覆盖 `provider_request_body_ref`），差异由 relay 侧比对 |
| 4 | 暂存容量 | 512 MiB / 10 分钟 TTL，超出按最旧淘汰（实现值，可配） |

## 13. 实施拆分

| PR | 内容 | 验证 |
|---|---|---|
| 1 | Go：采集最终 body、v2 payload、inline 通道、单测 | 直连探针解出 body |
| 2 | Go：暂存池 + 签名 + 取回接口 + 单测（过期/重放/淘汰/并发） | curl 取回后 410 |
| 3 | AE：v2 解析 + 响应头即拉取 + 覆盖 blob（UPSERT）+ 迁移列 + 单测 | 落库为 relay 真货 |
| 4 | 策略联动 + 前端来源/原因展示 + 开关 | 切 basic/full 行为变化 |
| 5 | 契约文档 A.6 + Go README + conformance 两模式 + 故障表 | 脚本全绿 |

## 14. 测试矩阵

| 维度 | 用例 |
|---|---|
| 策略 | basic / full |
| body 大小 | 1 KB / 100 KB / 2 MB |
| 类型 | JSON / 非 JSON |
| 响应 | 同步 / 流式（长流 > 5 分钟） |
| relay 行为 | 正常 / 重试 1 次 / 重启 / 暂存淘汰 |
| 异常 | 签名错 / 过期 / 拉取超时 |
| 兼容 | 旧 relay 只回 v1 |
