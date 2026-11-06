# relay 上游回执（echo）协议 v1 / v2

> 让 AE 记录「relay 真正发给上游的请求头和请求体」，而不是 AE 自己拼的估算值。
>
> 本文是 relay 侧实现契约 + AE 侧处理语义的合集。v1 = 请求头回执，v2 = 在 v1 通道上追加请求体。
> 接口与面板契约见 [contract.md](contract.md)，注册与联调见 [deploy.md](deploy.md)。

## 1. 为什么需要

AE 现在记录四份头：

| 字段 | 实际含义 |
|---|---|
| `request_headers` | 客户端发到 AE 的原始头（可信） |
| `provider_request_headers` | **AE 构造的 header map**，不是线上真实字节 |
| `provider_response_headers` | 上游响应头（可信） |
| `client_response_headers` | AE 回给客户端的头（可信） |

`provider_request_headers` 失真来源：

1. **HTTP 客户端补全**：`Host`、`Content-Length`、`Accept-Encoding` 由 reqwest/hyper 在发送时补，不在 map 里；
2. **协议层改写**：HTTP/2 强制小写、加伪头 `:method/:path/:authority`，HTTP/1.1 才有的头会被丢弃；
3. **中间层改写**：CDN / 反代 / 隧道可能重写 `X-Forwarded-*`、`Via`；
4. **最重要**：透传目标是 Go 网关时，Go 侧自己还会再加工一层——换真实上游 key、注入账号指纹、改写 path、替换 model、加自己的 UA。这些 AE 完全看不到。

所以详情页现在显示的“请求头”，在透传场景下是**估算值**，不是事实。请求体同理。

## 2. 语义定死

两个字段的语义就此固定，不再有歧义：

| 字段 | 语义 |
|---|---|
| `request_headers` | **客户端发到 AE 的原始头**，AE 收到什么记什么，一个字都不改 |
| `provider_request_headers` | **Go 侧改完请求头后回给 AE 的那一份**，即 Go 网关真正拿去打上游的头 |
| `provider_request_body_ref` | 有回执时**原地覆盖**为 relay 真正发往上游的 body（不新增列） |

拿不到回执时退回 AE 本地构造，并标注“本地记录”，不能假装是事实；不改变现有透传行为，Go 侧未升级时自动降级。

**通道选型**：用同步响应头回执，不用异步上报或按需拉取——同步无时序竞态、天然与本次请求绑定、无需新接口和鉴权。代价是受 8 KB 响应头预算限制，所以大 body 走暂存通道（§5.4）。

## 3. v1：请求头回执

**只在 `provider_type = relay` 时启用**，其它 provider 完全不受影响。

### 3.1 控制头（AE → relay）

| 头 | 值 | 说明 |
|---|---|---|
| `X-Aether-Echo` | `1` | 请求回执。缺省或非 `1` = 不要求，relay 行为与以前完全一致 |
| `X-Aether-Trace-Id` | AE 的 `request_id`（UUID） | relay 必须原样回填到 payload 的 `trace_id` |

### 3.2 回执头（relay → AE）

```
X-Aether-Provider-Request-Headers: <base64url( zlib( json ) )>
```

编码链路：**JSON → zlib（deflate）→ base64url（无 `=` 填充）**。

### 3.3 payload schema（`v = 1`）

| 字段 | 类型 | 必填 | 说明 |
|---|---|---|---|
| `v` | int | 是 | 协议版本，当前固定 `1`。AE 只接受 `1`，其它值走本地兜底 |
| `service` | string | 否 | 服务名，如 `workbuddy2api`，仅供排障 |
| `version` | string | 否 | relay 版本号，仅供排障 |
| `method` | string | 否 | 实际发往上游的方法，通常 `POST` |
| `path` | string | 否 | 实际发往上游的路径，如 `/v1/chat/completions` |
| `trace_id` | string | 是 | 必须等于请求里的 `X-Aether-Trace-Id`，否则 AE 拒收 |
| `headers` | object | 是 | 最终上游请求头，键统一小写；不得为空 |
| `header_count` | int | 否 | 采集时的头数量（裁剪前） |
| `truncated` | bool | 否 | 是否因体积超限发生裁剪 |

### 3.4 硬限制

| 限制 | 值 | 超限行为 |
|---|---|---|
| 编码后（base64url 串）长度 | ≤ **8192** 字节 | relay 自行裁剪；裁到放不下则**不返回回执头** |
| AE 接受的最大编码长度 | 16384 字节 | 超过直接丢弃，按本地兜底 |
| AE 解压后上限 | 64 KB | 超过丢弃 |
| 单个头值长度 | 1024 runes | 截断并追加 `…` |

### 3.5 脱敏与裁剪

- **必须脱敏**的头（大小写不敏感）：`authorization`、`proxy-authorization`、`cookie`、
  `set-cookie`、`x-api-key`、`api-key`、`x-goog-api-key`。
  掩码规则：保留认证前缀（如 `Bearer `）+ 前 6 字符 + `****` + 后 4 字符；主体 ≤10 字符时只留
  `前缀 + ****`。
- 裁剪顺序：先丢低价值头（`x-stainless-*`、`sec-*`、`accept-language`、`priority`、`dnt`、
  `cache-control`、`pragma`、`te`、`upgrade-insecure-requests`、`x-forwarded-*`、`x-real-ip`、
  `eo-*`），仍超限再按字典序从尾部整条丢弃，并置 `truncated=true`。

### 3.6 relay 侧必须做的四件事

1. 识别 `X-Aether-Echo: 1`。
2. 在**所有改写完成之后、`http.Client.Do` 之前**采集最终头表（不是客户端原始头）。
3. **把 `X-Aether-Echo` 与 `X-Aether-Trace-Id` 从上游请求里删掉**——它们是 AE↔relay 的内部
   控制头，泄漏给真实上游属于协议违规。
4. 在写响应体之前把回执头塞进响应头（HTTP 头一旦写出就不能再改）。

> Go 实现要点：`WriteHeader` 必须延后到首次 `Write`，用一层 recorder 包住 `http.ResponseWriter`；
> 采集点是**加完所有中间件后**的 `req.Header`。只对命中 `X-Aether-Echo` 的请求生效，其他请求零开销。

### 3.7 AE 侧校验与兜底

按顺序校验：`v == 1` → `trace_id` 与本次请求一致 → `headers` 非空 → 头表里**不得**再出现
`x-aether-echo` / `x-aether-trace-id` / `x-aether-provider-request-headers`。任一不满足即判定
回执无效。

| 结果 | `provider_headers_source` | `provider_request_headers` |
|---|---|---|
| 回执有效 | `upstream_echo` | relay 回传的真实上游头（已脱敏） |
| 无回执 / 解码失败 / 校验失败 | `local` | AE 自己算出来的那份头 |

**两者永不混用**：要么整份来自 relay，要么整份来自 AE。回执头在返回客户端前会被剥掉，
客户端永远看不到它。

### 3.8 落库字段语义（`usage_http_audits`）

| 字段 | 含义 |
|---|---|
| `request_headers` | 客户端 → AE 的原始请求头 |
| `provider_request_headers` | AE 最终发往上游的头（echo 成功时替换为 relay 回传的那份） |
| `provider_headers_source` | `upstream_echo` = 来自 relay 回执；`local` = AE 本地计算（兜底） |

> `provider_headers_source = local` 不代表请求失败，只代表**这次没拿到回执**。排障时先看它，
> 再决定是查 relay 实现还是查 AE 过滤链。

## 4. v2：请求体回执

与请求头同一条通道、同一份 payload，只是多带 body。AE 侧最终效果是
`provider_request_body_ref` 被 relay 真货覆盖——不是新增一份，而是替换。

### 4.1 不变量

| # | 不变量 |
|---|---|
| 1 | **替换不追加**：`provider_request_body_ref` 覆盖为 relay 真实上游 body；blob 数量不变 |
| 2 | **跟随系统策略**：`request_record_level`、`request_record_max_body_size_kb`、`request_record_compact_base64_images`，不新增开关 |
| 3 | **不双存**：relay 暂存是短 TTL 中转，AE 取走即覆盖，relay 随后删除 |
| 4 | **旁路失败不影响业务**：拿不到 body 只降级状态，请求照常返回 |
| 5 | **可回滚**：旧 relay 只回 v1，新 AE 必须兼容；新 relay 在未收到 body 请求时不产生任何开销 |

### 4.2 策略联动

`system_configs.request_record_level` 有三个取值，但代码只把 `full` 当成“采集 body”：

| 取值 | 实际行为 | 说明 |
|---|---|---|
| `headers` | 四个 body 字段全部 `disabled`，只存请求头/响应头 | 与 `basic` 等价 |
| `basic`（默认值） | 同上 | 代码：非 `full` 一律按 Basic 处理 |
| `full` | 按 `request_record_max_body_size_kb` 采集四个 body | 未知取值也 fail-closed 回落到 Basic |

因此 echo 的开关不是新开关，而是**跟随 `request_record_level`**：

| `request_record_level` | AE 发给 relay | relay 行为 | AE 落库 |
|---|---|---|---|
| `headers` / `basic` | 只带 `X-Aether-Echo: 1` | 只回请求头 | 四个 body 字段保持 `disabled`（reason `request_record_level_basic`） |
| `full` | 追加 `X-Aether-Echo-Body: 1` 等三个头 | 采集最终 body，按 §4.4 决定 inline / staged | `provider_request_body_ref` 覆盖；状态见 §4.7 |

策略在**请求开始时读一次**并向下传递，避免中途变更导致同一请求口径不一致。

`request_record_max_body_size_kb = 0` 表示**不限制**：AE 侧不截断，relay 也不自行加业务上限；暂存按容量淘汰（§4.5.1），淘汰或超时则降级为 `unavailable`。

### 4.3 透传前提：进站 body 就是 AE 出站 body

AE → relay 是原样透传（只换鉴权头），所以：

- relay 的**进站 body** ≡ AE 的**出站 body**（也就是 AE 自己记录的 `provider_request_body`）
- relay 的**出站 body** 才是真正发往上游的那份

因此**差异比较在 relay 侧完成**，AE 不需要回传自己的副本：relay 拿进站与出站两份 body
逐顶层字段比对，回执里带 `body_rewritten` + `body_diff{added,removed,changed}`。
AE 只负责把出站 body **原地覆盖**写入 `provider_request_body_ref`，不新增列。

这同时解决了“替换就看不到原样”的问题：原文不需要留，字段级差异已经指明 relay 改了什么。

### 4.4 协议

#### 控制头（AE → relay，仅当 `request_record_level=full`）

| 头 | 值 | 说明 |
|---|---|---|
| `X-Aether-Echo` | `1` | 已有 |
| `X-Aether-Trace-Id` | `<uuid>` | 已有 |
| `X-Aether-Echo-Body` | `1` | 请求 body 回执 |
| `X-Aether-Echo-Body-Max` | 字节数 | 等于 `request_record_max_body_size_kb × 1024`；为 `0` 表示**不限制**（AE 与 relay 都不截断） |
| `X-Aether-Echo-Body-Compact-Images` | `0`/`1` | 与 `request_record_compact_base64_images` 同值 |

#### payload 新增字段（`v = 2`）

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

#### 8 KB 预算分配（relay 侧固定顺序）

1. 先放 `headers`（必须完整，沿用 v1 裁剪规则）
2. 再放 body 元数据（约 300 B，必须完整）
3. 剩余空间放 `body_inline_b64`
4. 放不下 → 改为 `staged`（若暂存可用），否则 `none`

#### 小 body / 大 body 判定

```
if body 非 JSON          → none（只回 hash）
elif 编码后 ≤ 剩余预算      → inline
elif 暂存可用             → staged
else                     → none（只回 hash）
```

`staged` 与 `inline` 的 body 都必须先按 `Body-Max` 截断（`body_truncated=true`）。

### 4.5 暂存通道

#### 4.5.1 存储

- 仅内存，不上磁盘；key = 128-bit 随机 `stage_id`
- TTL 默认 **600 秒**（覆盖长流式；见 §4.6）
- 容量：单实例 64 MiB 或 200 条，LRU 淘汰
- 取走后保留 **10 秒**重试窗，之后删除
- 进程重启即丢 → AE 记 `unavailable`

#### 4.5.2 取回接口（relay 侧，绑回环）

```
GET /_aether/echo/body/{stage_id}?exp=<unix>&sig=<hex>&trace=<trace_id>
```

- `sig = HMAC-SHA256(echo_secret, stage_id + "|" + exp + "|" + trace_id)`
- `echo_secret = HMAC-SHA256(console_shared_secret, "echo-body")` —— 复用现有共享密钥派生，**不新增配置项**
- 返回 `200` + 原始字节；响应体编码必须与 payload 的 `body_encoding` 一致：`gzip` 就压、`identity` 就明文。
  AE 按 `body_encoding` 决定是否解压，**两边必须成对，只改一边会导致 body 被丢弃**
- `403` 签名不符；`404` 不存在/已过期；`410` 已取走且超出重试窗
- 访问日志只记 `stage_id` 前缀与长度，不记内容

#### 4.5.3 并发与幂等

- 同一 `stage_id` 在重试窗内可重复取（返回相同字节）
- 多 AE 实例场景由签名 + 一次性语义兜住；不做实例绑定

### 4.6 流式场景（关键）

**不能在 usage 收尾时才拉取。** 长流式响应可能持续数分钟，等到收尾时 stage 早已过期。正确做法：

```
收到 relay 响应头
  → 解析出 body_mode
  → 若 staged：立刻起一个后台任务拉取（3 s 超时，重试 1 次）
  → 拉到的字节暂存在本次请求上下文（内存，≤ Body-Max）
  → usage 事件构造时直接取用，不再发网络请求
```

这样 TTL 只需覆盖“响应头到后台任务完成”的几秒，600 秒是宽松上限。

拉取失败不阻塞流式输出；本次请求记 `unavailable` + reason。

### 4.7 落库与状态机

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

不新增列：`provider_request_body_ref` 本身就是出站请求体字段，覆盖即可。曾试加 `provider_body_source`（与 `provider_headers_source` 对称），因单行 upsert 漏绑导致审计写入全线失败，已回滚（`20261104000000` 加列 → `20261104000001` 删列，最终无此列）。

## 5. 失败矩阵

| 故障 | 业务请求 | 落库 | 告警 |
|---|---|---|---|
| relay 不认 echo 头 | 正常 | `local` / `unavailable:unsupported` | 无 |
| 回执 > 8KB | 正常 | 裁剪后 `upstream_echo`，`truncated=true` | 无 |
| 回执 trace-id 不匹配（伪造） | 正常 | `local`，留审计 | 无 |
| 暂存满被淘汰 | 正常 | `unavailable / stage_missing` | 计数 > 0.5% 告警 |
| 拉取超时 | 正常 | `unavailable / fetch_failed` | 计数 > 1% 告警 |
| 签名密钥不一致 | 正常 | `unavailable / fetch_failed` | 立即告警（配置错误） |
| relay 重启 | 正常 | `unavailable / stage_missing` | 无 |
| 供应商未开 `relay_echo` | 正常 | 不注入、行为同以前 | 无 |

## 6. 安全

- 取回接口只监听回环，不对外暴露
- 签名绑定 `stage_id + exp + trace_id`，无法跨请求读取
- 暂存不上盘、TTL 到期即删；AE 侧 blob 沿用现有保留策略
- body 内容不写 relay 访问日志
- `basic` 模式下 relay 完全不采集 body，避免无谓持有用户内容
- `config.relay_echo.trust = true` 的供应商才接受回执（默认关闭，避免任意上游注入）
- 回执头在返回客户端前剥掉，客户端永远看不到

## 7. 可观测性

指标（relay）：`echo_body_inline_total`、`echo_body_staged_total`、`echo_body_skipped_total{reason}`、`echo_stage_evicted_total`、`echo_stage_bytes`。
指标（AE）：`relay_echo_body_total{mode,result}`、`relay_echo_body_fetch_seconds`。

审计字段已可查：`provider_request_headers`（+ `provider_headers_source`）、`provider_request_body_ref`、`provider_request_body_state`。

## 8. 验收标准

1. 对 relay 发一条透传请求，AE 详情页「上游实收」里的 `host`、`path`、`authorization`（脱敏后）与 relay 日志完全一致；
2. relay 删掉回执逻辑重建后，同一页面自动退回「AE 发出」并显示「本地记录」标注；
3. 回执 > 8KB 时页面显示 `truncated` 标记，不报错；
4. 伪造 `X-Aether-Provider-Request-Headers`（trace-id 不匹配）被丢弃并留审计；
5. 发往真实上游的请求**不含**任何 `x-aether-*`（抓包确认）；
6. `provider_request_body` 落库内容与 relay 实际发往上游的 body 逐字节一致（含 relay 注入的 `stream_options` / `prompt_cache_key`）。

## 9. 测试矩阵

| 维度 | 用例 |
|---|---|
| 策略 | basic / full |
| body 大小 | 1 KB / 100 KB / 2 MB |
| 类型 | JSON / 非 JSON |
| 响应 | 同步 / 流式（长流 > 5 分钟） |
| relay 行为 | 正常 / 重试 1 次 / 重启 / 暂存淘汰 |
| 异常 | 签名错 / 过期 / 拉取超时 |
| 兼容 | 旧 relay 只回 v1 |

## 10. 已定决策

| # | 问题 | 结论 |
|---|---|---|
| 1 | 回执通道 | **同步响应头**（`X-Aether-Provider-Request-Headers`），不用异步上报或按需拉取 |
| 2 | `request_record_level` | **已切 `full`**（2026-11-04） |
| 3 | body 大小上限 | **跟随系统设置 `request_record_max_body_size_kb`，`0` = 不限制** |
| 4 | 存哪一份 | **存 relay 真货**（覆盖 `provider_request_body_ref`），差异由 relay 侧比对 |
| 5 | 暂存容量 | 512 MiB / 10 分钟 TTL，超出按最旧淘汰（实现值，可配） |
| 6 | 是否新增列 | 头加 `provider_headers_source`；body **不加**（试过，已回滚） |

## 11. 实施记录

### 已完成（AE 侧，v0.7.21-rc.1）

| 内容 | 落点 |
|---|---|
| `provider_headers_source` 列 | `crates/aether-data/adapters/postgres/migrations/20261103000000_add_provider_headers_source.sql` |
| 加列后又回滚（body 那份） | `20261104000000_add_provider_body_source.sql` + `20261104000001_drop_provider_body_source.sql` |
| v1 / v2 回执解析 | `apps/aether-gateway/src/execution_runtime/relay_echo.rs` |
| 落库带 `provider_headers_source` | `crates/aether-data/adapters/postgres/src/usage/mod.rs` |
| 审计列/占位符一致性守卫 | 单测 `single_row_audit_sql_column_and_placeholder_counts_match` |
| 一致性校验脚本 | `scripts/relay-conformance.sh` |

### 未完成

| 事项 | 说明 |
|---|---|
| 前端「上游实收」来源徽标 | `RequestDetailDrawer.vue` 尚未展示 `provider_headers_source`；接口已返回，前端未消费 |
| zcode2api 侧回执 | **阻塞**：154 上该 relay 指向 `http://203.0.113.10:47823/v1`，服务器上只有二进制，无源码 |

## 12. 已知坑

| 坑 | 后果 | 防法 |
|---|---|---|
| `body_encoding` 与响应体编码不成对 | AE 按 payload 解压失败，整份 body 被丢弃 | 两边必须成对改；抓包比对 `Content-Encoding` |
| 单行 upsert 只加 bind 不改 SQL | 占位符数对不上 → 整条审计写入报错、usage 事务回滚，只剩请求头/请求体/元数据三块 | 改列必须同步 SQL 与 bind，靠单测兜底（见 [deploy.md](deploy.md) D.6） |
| 流式请求在 usage 收尾时才拉 stage | 长流结束时 stage 已过期，恒为 `unavailable` | 收到响应头就起后台拉取（§4.6） |
| 回执超过 8KB | 头被裁或整份丢弃 | 按 §4.4 预算分配，优先保 headers |
