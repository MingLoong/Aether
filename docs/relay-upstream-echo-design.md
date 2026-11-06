# 透传（relay）请求记录改为「上游实收回执」

状态：设计稿，待评审
适用：`provider_type = relay`（自定义透传），以及地址指向本机 Go 网关的 `custom` 供应商

## 1. 现状为什么不正确

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

所以详情页现在显示的“请求头”，在透传场景下是**估算值**，不是事实。

## 2. 目标（语义定死）

两个字段的语义就此固定，不再有歧义：

| 字段 | 语义 |
|---|---|
| `request_headers` | **客户端发到 AE 的原始头**，AE 收到什么记什么，一个字都不改 |
| `provider_request_headers` | **Go 侧改完请求头后回给 AE 的那一份**，即 Go 网关真正拿去打上游的头 |

也就是说 `provider_request_headers` 不再由 AE 自己拼，而是**以上游回执为准**。
拿不到回执时退回 AE 本地构造，并标注“本地记录”，不能假装是事实；
不改变现有透传行为，Go 侧未升级时自动降级。

## 3. 方案比较

| 方案 | 做法 | 优点 | 缺点 |
|---|---|---|---|
| **A 同步回执（推荐）** | Go 侧把“我收到了什么”压进响应头 `X-Aether-Observed` | 同步、无时序问题、无需新接口、天然与本次请求绑定 | 受响应头大小限制（8KB 上限，headers 够用，body 只能放摘要） |
| B 异步上报 | Go 侧 POST 到 AE `/api/admin/relay-trace` | 可传完整 body、可带更多元数据 | 需要新接口 + 鉴权 + 重放保护；上报与记录存在时序竞态 |
| C 按需拉取 | UI 用 `x-trace-id` 去查 Go 面板的请求日志 | Go 侧几乎不用改 | 依赖 Go 侧有查询 API、保留期不一致、跨服务鉴权 |

**推荐 A 为主，C 作为历史回溯补充。**

## 4. 方案 A 契约

### 4.1 AE → 上游（请求头）

```
X-Aether-Echo: 1
X-Aether-Trace-Id: <usage.request_id>        # 已有 x-trace-id，复用
X-Aether-Echo-Want: headers,body-digest      # 可选，默认 headers,body-digest
```

仅当 `provider_type=relay` 且 `config.relay_echo.enabled=true` 时注入。

### 4.2 上游 → AE（响应头）

```
X-Aether-Provider-Request-Headers: <base64url(zlib(json))>   ≤ 8KB
X-Aether-Observed-Digest: sha256:<hex>                       # 可选，校验用
```

解压后的 JSON（v1）就是 Go 侧**最终发给上游的那份请求头**：

```json
{
  "v": 1,
  "service": "workbuddy2api",
  "version": "0.9.3",
  "received_at": "2026-11-03T16:40:12.331+08:00",
  "method": "POST",
  "path": "/v1/chat/completions",
  "headers": {
    "host": "open.bigmodel.cn",
    "authorization": "Bearer ****abcd",
    "content-type": "application/json",
    "user-agent": "workbuddy/5.8.1",
    "x-trace-id": "b5d0b297-…"
  },
  "header_count": 18,
  "truncated": false
}
```

约束：

- 压缩后 ≤ 8KB；超限按 `x-stainless-*`、`accept-*` 等低价值头裁剪，置 `truncated:true`；
- 敏感头脱敏：`authorization` / `cookie` / `x-api-key` / `proxy-authorization` 只留前 6 后 4；
- 服务不支持则**什么也不返回**，AE 自动降级；
- 回执里的 `x-trace-id`（若存在）必须等于本次 `request_id`，否则丢弃。

### 4.3 AE 侧落库

不新增请求头字段，直接覆盖原有列：

```sql
-- 只加一个来源标记，用于 UI 说明这份头是谁给的
ALTER TABLE usage_http_audits
  ADD COLUMN provider_headers_source varchar(16) NOT NULL DEFAULT 'local';
-- 'upstream_echo' | 'local'
```

写入规则：

1. 响应里带 `X-Aether-Provider-Request-Headers` 且解析成功 → 写入 `provider_request_headers`，`provider_headers_source='upstream_echo'`；
2. 没有该头 / 解析失败 / trace-id 不匹配 → 保留 AE 本地构造的 map，`provider_headers_source='local'`；
3. `request_headers` 永远不动，就是客户端原始头。

`config.relay_echo.trust = true` 的供应商才接受回执（默认关闭，避免任意上游注入）。

### 4.4 前端

请求头 tab 的数据源从两档变三档：

```
[客户端原始]  [AE 发出]  [上游实收]        ← 默认选「上游实收」
```

- 有 `upstream_observed` → 默认「上游实收」，并给 `service@version` 徽标；
- 没有 → 默认仍是「AE 发出」，标题旁标灰字「本地记录，未经上游确认」；
- 「对比」模式支持任意两档 diff，重点看 `upstream` 那档多出来/少了哪些头。

## 5. Go 侧参考实现（约 40 行）

```go
func observedMiddleware(next http.Handler) http.Handler {
    return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
        if r.Header.Get("X-Aether-Echo") != "1" {
            next.ServeHTTP(w, r)
            return
        }
        body, _ := io.ReadAll(r.Body)
        r.Body = io.NopCloser(bytes.NewReader(body))

        rec := newRecorder(w)          // 包一层，拿到状态码与已写字节
        next.ServeHTTP(rec, r)

        obs := buildObserved(r, body, rec.Status())
        if payload, err := encodeObserved(obs); err == nil && len(payload) <= 8192 {
            w.Header().Set("X-Aether-Observed", payload)
        }
    })
}
```

注意：必须在写响应体**之前**设置响应头，所以 recorder 要把 header 写入延后到 `WriteHeader`。

## 6. 兼容与降级

| 情况 | 行为 |
|---|---|
| Go 侧老版本，不认 `X-Aether-Echo` | 无回执 → `capture_source='local'`，前端标注，功能不变 |
| 回执超过 8KB | 裁剪后返回，标 `truncated` |
| 回执 trace-id 不匹配 | 丢弃，记审计，保持 local |
| 供应商未开启 `relay_echo` | 不注入请求头，行为同现在 |

## 7. 验收标准

1. 对 `zcode2api` 发一条透传请求，AE 详情页「上游实收」里的 `host`、`path`、`authorization`（脱敏后）与 Go 侧日志完全一致；
2. Go 侧删掉回执逻辑重建后，同一页面自动退回「AE 发出」并显示「本地记录」标注；
3. 回执 > 8KB 时页面显示 `truncated` 标记，不报错；
4. 伪造 `X-Aether-Observed`（trace-id 不匹配）被丢弃并留审计。

## 8. 实施顺序

1. AE：schema + 回执解析 + 落库 + detail API 返回（1 个迁移 + 1 个解析模块）；
2. AE：前端三档数据源 + 来源徽标；
3. Go：`zcode2api`、`workbuddy2api` 加中间件（各自的仓库）；
4. 灰度：先给 `workbuddy2api` 打开 `relay_echo`，验证后推广。
