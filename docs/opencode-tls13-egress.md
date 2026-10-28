# opencode TLS 1.3 出口：现状与接入任务单

> 状态：**TLS 客户端已完成并验证；尚未接入网关出站链路。**

## 1. 为什么需要这个

`opencode.ai` 免费层按 **TLS 客户端指纹**放行。实测对照（同机、同分钟、同一份
官方 body、同样 9 项请求头）：

| 客户端 | 结果 |
|---|---|
| Rust 手写 ClientHello（复刻目标 JA3） | **HTTP/1.1 200 OK** |
| curl / OpenSSL 3.0.20 | 429 `FreeUsageLimitError` |

所以指纹是硬门槛，且**纯 Rust 能做到**，不需要 Go 侧车、不需要 boring/rquest。

目标 JA3：`1523504b38f0fae0d881d4b6554aac1b`

## 2. 已完成（均已合入 main）

| 提交 | 内容 |
|---|---|
| `5ce05cc` | 手写 TLS 1.3 客户端（ClientHello / 握手 / AES-128-GCM / SSE 读取） |
| `396199e` | 证书链 + 主机名 + `CertificateVerify` 验签 |
| `fd954fd` | 收成库 API `tls13::connect()` |
| `d4d9106` | 删除施工中的 `tls_bridge` bin |

代码位置：

```
crates/aether-tls-hello/src/lib.rs            ClientHello 构造 + JA3 校验（4 个单测）
crates/aether-tls-hello/src/tls13.rs          握手 / 证书校验 / TlsStream（Read+Write）
crates/aether-tls-hello/examples/handshake_probe.rs   命令行探针（回归对照用）
crates/aether-tls-hello/examples/lib_smoke.rs         库 API 冒烟
```

用法：

```rust
let mut tls = aether_tls_hello::tls13::connect("opencode.ai", 443)?;
tls.write_all(request.as_bytes())?;   // 记录层自动分片（≤16000 字节/条）
tls.read(&mut buf)?;                  // 阻塞式 Read/Write
```

验证命令：

```bash
cargo build -p aether-tls-hello --example lib_smoke
./target/debug/examples/lib_smoke opencode.ai 443 /inference/v1/models
# 期望输出：握手完成（含证书校验） / 第一行: HTTP/1.1 200 OK
```

## 3. 关键坑（都已踩过，别重复）

### 3.1 rustc 1.95 的 ICE

现象：`cargo build` 直接 panic，`slice index starts at 23 but ends at 21`。

根因：**`dead_code` 告警的输出让 rustc 崩**（生成告警片段时按字节切源码，
遇到多字节字符越界）。逐 lint 验证结果：

```
dead_code          OK      ← 只 allow 它就能编过
unused_imports     ICE
unused_variables   ICE
non_snake_case     ICE
```

处理：`crates/aether-tls-hello/src/lib.rs` 顶部 `#![allow(dead_code)]`。
**不需要更换 toolchain。**

### 3.2 TLS 实现层面的五个真 bug（都表现为"解不开 / 被断开"）

1. `Hkdf::new(None, secret)` 会再 Extract 一次；TLS 的 secret 已是 PRK → 用 `from_prk`
2. transcript 里混进了 5 字节 record 头
3. 客户端 Finished 计入 transcript 后才算应用密钥（RFC 只算到服务端 Finished）
4. 加密路径的 AAD 长度写死 `0x0000`（必须等于密文长度）→ 服务端 `decode_error`
5. 单条记录塞 32KB 明文（TLS 上限 16384）→ 服务端静默 FIN
6. `Certificate` / `CertificateVerify` 未进 transcript → 服务端 Finished 校验必失败

### 3.3 上游要求（实测）

- 共享密钥顺序：**ML-KEM‖X25519**（4588 组）
- 除 TLS 外，**9 项请求头缺一不可**，尤其 `x-opencode-session` / `x-opencode-session-id` /
  `x-opencode-request`（少这三个直接 429，TLS 再对也没用）
- body 必须含：官方系统提示词（9539 字）、11 个 legacy 工具名、`stream:true`、
  `stream_options.include_usage:true`

## 4. 待做：接进网关出站

发送层已定位：

```
apps/aether-gateway/src/execution_runtime/transport.rs     10,105 行
  ├─ resolve_execution_dns_addresses()                 DNS + 出口地址策略
  ├─ resolve_execution_target_addresses_with_policy()  地址校验（SSRF 防护，别绕过）
  ├─ format_upstream_request_error(reqwest::Error)     reqwest
  └─ format_wreq_upstream_request_error(wreq::Error)   wreq（第二个客户端）
```

注意：`crates/aether-provider/transport/src/opencode.rs`（1634 行）**不是发送层**，
只有出口 IP 池 / 配置 / 选路；`apps/aether-gateway/src/ai_serving/transport.rs` 只是再导出壳。

接入步骤：

1. 在 `transport.rs` 里定位"按 plan 发请求"的函数（找 `reqwest` / `wreq` 的 `Client` 使用点，
   不是 `format_*_error`）
2. 加分支：`provider == opencode` 且开关开启 → `tokio::task::spawn_blocking` 包
   `tls13::connect()`（我们的实现是阻塞 `std::net`）
3. 保留既有 DNS / 地址校验逻辑
4. body 整形同处落地：提示词、11 工具名、`stream` + `include_usage`、9 项头、`ses_/msg_` ID
5. 回归：
   - 本地 `handshake_probe` 打 `/inference/v1/models` → 200
   - 154 生产打一次真实 chat 请求 → 200（不是 429）

## 4.1 已定位的 reqwest Client 构造点（`transport.rs`）

下一步只需从这些点往上找调用方，即可拿到"按 plan 发请求"的函数：

```
164    clients: Vec<reqwest::Client>            客户端池
172    fn new(clients, target_len, warming)     池初始化
182    fn select(&self) -> reqwest::Client       选择客户端
3285   -> Result<reqwest::Client, ...>           （构造函数 A）
3292   -> Result<reqwest::Client, ...>           （构造函数 B）
3294   reqwest::Client::builder()
3683   -> Result<reqwest::Client, ...>
3858   -> Result<reqwest::Client, ...>
4290   -> Result<reqwest::Client, ...>
4295   reqwest::Client::builder().no_proxy()
4352   builder: reqwest::ClientBuilder
4354   -> reqwest::ClientBuilder
```

搜索建议：`grep -n 'select()' apps/aether-gateway/src/execution_runtime/transport.rs`
从 `select()` 的调用点往上走，就是真正发请求的位置。

## 4.2 发送通道不止一套（读代码前先看这张表）

`apps/aether-gateway/src/execution_runtime/transport.rs` 里按场景并存三套发送通道：

| 位置 | 通道 | 说明 |
|---|---|---|
| `clients: Vec<reqwest::Client>`（164/172/182） | reqwest 池 | `select()` 轮询选一个 |
| `build_direct_h2c_client_from_cache_key`（~2690） | hyper h2c 直连池 | `HyperLegacyClient::builder().http2_only(true)`，明文 HTTP/2 |
| `format_wreq_upstream_request_error`（717） | wreq | 第三个客户端 |

`select()` 的调用点：

```
2429   Ok(entry.select())           reqwest 池（缓存命中）
2645   return Ok(entry.select());   h2c 池（缓存命中）
2660   let client = entry.select(); h2c 池（新建后）
3873   let client = entry.select(); 另一套池（未展开）
3915   let client = entry.select(); 同上
```

opencode（标准 HTTPS + SSE）走哪一条**还没确认**，这是接入前第一件要查的事。

## 4.3 接入执行单（可直接照做）

```
1. 读 transport.rs:3860-3960
   → 确认 3873/3915 那两套池的用途，判断 opencode 实际走哪条

2. 搜 ExecutionPlan 定义（含 url / method / headers / body / stream 等字段）
   → 弄清 plan 如何变成真实 HTTP 请求、响应又如何变回 StreamFrame

3. 在"按 plan 发请求"的函数里加分支：
      if provider == Opencode && env("AETHER_OPENCODE_TLS13") 开启 {
          tokio::task::spawn_blocking(move || {
              let mut tls = aether_tls_hello::tls13::connect(host, port)?;
              tls.write_all(&request_bytes)?;
              // 读响应，按现有通道的返回类型包装
          })
      } else { 现有逻辑 }
   注意：
   - 我们的 TlsStream 是阻塞 std::net，必须 spawn_blocking，不能直接在 async 里 await
   - 保留 resolve_execution_target_addresses_with_policy 的地址校验（SSRF 防护）
   - 失败**不要**静默回退 reqwest，否则 429 会被掩盖

4. 回归
   a) cargo build -p aether-gateway
   b) ./target/debug/examples/lib_smoke opencode.ai 443 /inference/v1/models  → 期望 HTTP/1.1 200 OK
   c) 154 生产打一次真实 chat 请求 → 期望 200，不是 429
```

## 4.4 确切插入点（已经找到）

`apps/aether-gateway/src/execution_runtime/transport.rs`，**第 1905–1960 行**是
"按 plan 发请求"的真实函数（日志事件名 `outbound_upstream_request`）。顺序是：

```
1890  出站诊断日志（header_names_for_diagnostics）
1905  if let Some(node_id) = resolve_tunnel_node_id(plan.proxy)  → send_via_tunnel_relay
1918  if direct_h2c_fast_path_applies(...)                        → send_via_direct_h2c_fast_path
1928  let client = build_client(&plan.url, &plan.key_id, ...)     ← 普通 reqwest 通道
1940  let mut request = client.request(method, &plan.url);
1942  request = request.headers(headers).body(body_bytes);
1953  let send_result = send_reqwest_request(request, stream_first_byte_timeout).await
        .map(DirectHttpResponse::Reqwest);                        ← 真正发出
```

**插入位置：1928（`build_client`）之前**，紧跟 tunnel 与 h2c 两个 fast-path 之后：

```rust
if plan_is_opencode_tls13_eligible(plan) {
    return send_via_tls13(plan, method, headers, body_bytes,
                          total_timeout, stream_first_byte_timeout)
        .await;
}
```

### 唯一的结构障碍

返回值类型 `DirectHttpResponse` 目前只有两个变体：

```rust
enum DirectHttpResponse { Reqwest(...), HyperH2c(...) }
```

新增 TLS 通道必须**再加一个变体**（例如 `Tls13(...)`），并让所有消费该枚举的地方
（状态码、响应头读取、body 流 → `StreamFrame` 的映射）都支持它。这是接入的**主要工作量**，
不是 TLS 那部分——TLS 已经完成。

### 最小可行路径（建议）

不要一步做到"完整响应流"，先做**非流式验证**：

1. 新变体先只支持"把整个响应体读进内存"（非流式）
2. `stream == true` 的请求暂时仍走 reqwest（保持现状）
3. 用一次非流式 chat 请求验证能拿到 200
4. 确认可行后，再补 SSE 流式映射（`TlsStream` 已是 `Read`，逐块转成 `StreamFrame::Data` 即可）
5. 最后把流式开关打开

这样每一步都能编译、能验证，不会出现"改到一半编译不过"的状态。

### 配置开关

建议用环境变量门控，默认关闭，便于回滚：

```
AETHER_OPENCODE_TLS13=1        启用 TLS 13 通道
AETHER_OPENCODE_TLS13_STREAM=1 启用流式（第二阶段）
```

## 4.5 新变体要改的全部位置（已枚举，共 10 处）

`DirectHttpResponse` 定义在 `transport.rs:1991`，现有三个变体：
`Reqwest` / `HyperH2c` / `BrowserWreq`。

新增第四个变体（`Tls13`）需要补齐下面所有 match 分支：

```
transport.rs:1991         枚举定义
transport.rs:1997         impl DirectHttpResponse（状态码/响应头访问器）

execution_runtime/sync/execution.rs
  1616  DirectHttpResponse::Reqwest(response)
  1638  DirectHttpResponse::HyperH2c(response)
  1660  DirectHttpResponse::BrowserWreq(response)
  → 非流式响应体的三处映射，需加第四臂

execution_runtime/grok.rs
  527 / 545 / 561   grok 响应状态与头处理（三臂）
  611–634          grok_response_body_stream（三臂，把响应变成 body stream）
  → 注意：grok 是另一家供应商，可以只加一个 unreachable!() 分支，
    因为我们只在 opencode 分支里产生 Tls13 变体
```

工作量估计：新变体 + 三处消费点各加一臂；grok 的臂可以是
`unreachable!("Tls13 仅用于 opencode")`，减少实现负担。

### 还需要的一段适配器

`TlsStream` 是阻塞 `std::net`，而 `DirectHttpResponse` 的 body 需要
`impl Stream<Item = Result<Bytes, _>>`（tokio 生态）。所以要写一个：
`spawn_blocking` + `tokio::sync::mpsc` 的桥接，把 `Read` 变成 `Stream`。

这约 80–120 行，是接入里唯一的"新代码"，其余都是加 match 臂。

## 5. 安全边界

- 证书校验已实现（webpki 链 + 主机名 + `CertificateVerify`），不是裸连接
- 反例未实测：本地 `openssl s_server` 自签证书那张，我们的客户端在握手阶段就断了
  （s_server 报文布局兼容性问题，与本改动无关），所以"证书错误必须拒绝"目前只有代码路径、
  没有实测证据。建议补：用 `webpki` 单测构造伪造链
- 接入后必须确认失败时**不静默回退**到 reqwest（否则 429 问题会原样回来，且掩盖故障）

## 6. 下一轮开工顺序（照抄即可）

当前完成度：

| 层 | 状态 |
|---|---|
| 手写 TLS 1.3 客户端（ClientHello / 握手 / 证书校验） | ✅ 实测 `opencode.ai` 200 |
| 库 API `aether_tls_hello::tls13::connect()` | ✅ 1.95 可编，有单测 |
| 出站通道 `execution_runtime::tls13_upstream::send()` | ✅ 已写、编译通过、3 个单测 |
| 接进 `DirectHttpResponse` | ⛔ 差这一步 |
| body 整形（提示词 / 11 工具 / 9 头 / ID） | ⛔ 未做 |

### 开工步骤

```
1. transport.rs:1991   加变体  Tls13(Tls13Response)
2. transport.rs:1997   补状态码 / 响应头访问器
3. sync/execution.rs:1616 / 1638 / 1660   三处非流式响应体映射，各加一臂
4. grok.rs:527 / 545 / 561 / 611-634      六处可写 unreachable!("Tls13 仅用于 opencode")
5. transport.rs:1928 之前插入分支：
      if plan_is_opencode(plan) && env_flag("AETHER_OPENCODE_TLS13") {
          return tls13_upstream::send(&plan.url, method.as_str(), &headers, body_bytes)
              .await
              .map(DirectHttpResponse::Tls13)
              .map_err(ExecutionRuntimeTransportError::from);
      }
6. body 整形（同一分支内，发送前）：
      - 官方系统提示词（9539 字，两份模板变量：MODEL 两处、DATE 一处）
      - 11 个 legacy 工具名：bash/edit/glob/grep/read/skill/task/todowrite/webfetch/websearch/write
      - stream: true + stream_options.include_usage: true
      - 9 项请求头（含 x-opencode-session / -session-id / -request，ID 形如 ses_/msg_ + 12 位 hex + 14 位随机）
7. 回归：
      cargo check -p aether-gateway
      ./target/debug/examples/lib_smoke opencode.ai 443 /inference/v1/models   → 200
      154 生产一次真实 chat 请求                                             → 200（不是 429）
```

### 硬性要求

- **失败路径不许静默回退 reqwest。** 回退会把 429 藏起来，让你以为改动生效、
  实际仍在旧通道上——这是之前排查绕弯最久的地方。
- 保留 `resolve_execution_target_addresses_with_policy` 的地址校验（SSRF 防护）。
- 开关默认开启；`AETHER_OPENCODE_TLS13=0` 即时退回 reqwest（kill switch，不需要重新部署）。
- 只对 `provider == opencode` 生效，其他供应商一律不动。

### 仍待补的验证

证书**反例**未实测（本地 `openssl s_server` 自签证书那张卡在握手兼容性，
走不到验签）。建议用 `webpki` 单测构造伪造链补上。

## 7. 阶段二：已接入出站（2026-10-26）

`tls13_upstream::send()` 已经接进网关出站，**默认关闭**，线上行为不变。

### 改动清单

| 位置 | 改动 |
| --- | --- |
| `transport.rs` | 新增 `DirectHttpResponse::Tls13` 与 `DirectUpstreamResponse::Tls13` |
| `transport.rs` | 6 个访问器（`status_code` / `headers` / `content_length` / `bytes_with_limit` / `bytes_with_stream_timeout` / `into_direct_upstream_response`）各补一臂 |
| `transport.rs` | `opencode_tls13_egress_enabled()`：环境变量 + 主机双条件 |
| `transport.rs` | `send_request_inner` 在 `build_client` 之前拦截；失败直接报错，不回退 |
| `sync/execution.rs` · `grok.rs` · `stream/execution.rs` · `stream_pump.rs` | 各消费点补一臂 |

开关（默认就开，不用配置；只有要回滚时才设）：

```
AETHER_OPENCODE_TLS13=0
```

只对 `host == opencode.ai`（含 `*.opencode.ai`）生效，其它供应商完全不受影响。
流式请求没有总超时，这条通道自带 600s 上限，避免挂死的 TCP 长期占住
`spawn_blocking` 线程。

### 三个语义差异（接入后才知道的，别踩）

1. **响应体整段缓冲**：通道内一次读完再交给上层，SSE 不会逐块下发，客户端会
   收到一个完整响应。功能可用，但失去首字延迟优势。
2. **没有自动解压**：reqwest 的 `gzip/brotli/deflate` 特性在这条路径上不生效。
   非流式路径还能由 `decode_response_body_bytes_with_limit` 按
   `content-encoding` 解码；**流式路径不会**，会拿到压缩字节。opencode 的 SSE
   实测是明文，换端点时要留意。
3. **主机判断依赖 `plan.url` 保持官方域名**：若以后重新启用 IP 池注入、把 URL
   主机改成 IP，这个分支就不再命中，流量会静默回到 reqwest。那时必须把
   「连接地址」与「SNI/Host」拆开传，否则 SNI 会变成 IP、证书校验也会失败。

### body 整形仍未做

现在打开开关只换了一条 TLS 通道，请求体仍是网关自己拼的。如果上游 429 的判定
里含 body 特征，打开开关依旧 429——需要先做 §6 第 6 步（9539 字官方提示词、
11 个 legacy 工具名、`stream_options.include_usage`、9 项请求头）。
## 8. body 也是硬门槛（实测矩阵，2026-10-26）

宿主机 `8.134.156.173`，工具 `/tmp/replay_amd64 <body.json>`：TLS 指纹与 9 个官方头
固定不变，唯一变量是请求体。基准 `official_body.json` 是官方 1.19.x 抓包，32601 字节。

| 变体 | 改动 | 结果 |
| --- | --- | --- |
| `c_base` | 原样重排（字节完全一致） | **200** |
| `c_sys_plus_space` | 系统提示词尾部加一个空格 | **200** |
| `c_user_short` / `c_user_zh` | 只改用户消息 | **200** |
| `d_sys_append` | 官方提示词后追加「始终用简体中文回答」 | **200** |
| `d_extra_system` | 官方提示词后再加一条独立 system 消息 | **200** |
| `d_extra_tool` | 官方 11 工具后追加一个自定义工具 | **200** |
| `d_multiturn` | 官方提示词 + 多轮历史 | **200** |
| `c_nosystem` | 换掉官方系统提示词 | 429 |
| `c_notools` | 删掉 tools / tool_choice | 429 |
| `v_onetool` | 系统提示词保留，tools 只留 bash | 429 |
| `plain_body` | 裸 body（124 字节） | 429 |

### 结论

判定规则是「**底座必须在，内容可叠加**」：

* 硬底座：官方系统提示词（9539 字）+ 官方 11 个工具（22.7KB JSON）；
* 可叠加：用户消息、多轮历史、追加的 system 消息、追加的自定义工具；
* 不是逐字节哈希——系统提示词尾部多一个空格仍然 200。

所以网关可以在**保留用户语义**的前提下通过：官方提示词在前，用户内容按原顺序跟上。

### 实现

`apps/aether-gateway/src/execution_runtime/opencode_body.rs`，资源落在
`apps/aether-gateway/assets/opencode/{system_prompt.txt,tools.json}`（`include_str!`）。

* 客户端 system 消息合并成一条，紧跟在官方提示词之后；
* 官方 11 工具在前，客户端工具按名字去重后追加，重名用官方版本；
* `tool_choice`/`stream`/`stream_options` 强制成官方取值，`max_tokens` 缺省补 32000；
* 空 body（GET `/models`）不改写。

### 代价

每个请求多出 9539 字符系统提示词 + 22.7KB 工具表（约 7k tokens 上行），会计入上游用量。
这是拿到 200 的必要成本，不是可选优化。
## 9. 上线记录（2026-10-26 16:06 CST）

* 提交：`840ec5ac2`（TLS 1.3 出口默认开启），CI run `40288846465` 成功
* 部署：`/opt/aether/releases/840ec5a+tls13-20261026-160540`，只换二进制、前端未动，
  `healthz=200`、`service=active`
* 部署脚本按本次独有标记验完工件才换：`opencode tls13 upstream timed out after`、
  `tls13_body_read_failed`、以及内嵌的官方提示词 `You are opencode, an interactive CLI tool`

### 实测结果

用 `big-pickle` 连打三次真实 chat（`/v1/chat/completions`）：

```
第 1 次: http=200 t=5.99s '收到' prompt=2358 total=2374
第 2 次: http=200 t=7.91s '收到' prompt=2358 total=2367
第 3 次: http=200 t=7.09s '收到' prompt=2358 total=2374
```

`prompt_tokens≈2358` 正好对应「官方 9539 字提示词 + 11 个工具」之后的上行量，
可以作为「body 整形确实生效」的旁证。改之前同一模型是 100% 429（FreeUsageLimitError）。

### 仍然存在的 429

日志里同一个 trace 偶尔先出现 `local_sync_candidate_retry_scheduled status_code=429
provider_name="OpenCode"`，重试到别的候选后成功。这类 429 是上游账号额度/频率限制，
不是 TLS 指纹问题——同一条通道换个 key 就 200。

### 一个遗留配置

供应商 config 里仍有 `opencode_scan.proxy_domain = opencode.fanjinlong.top`，但两个
`provider_endpoints.base_url` 都是 `https://opencode.ai`，出站不读它，属于前缀残留。
真要彻底清干净可以删掉这个键；删不删都不影响出站（主机判断看的是 `plan.url`）。
## 10. 前置 CDN 出口池的拆除进度（2026-10-26）

| 提交 | 内容 |
| --- | --- |
| `2e326df` | 删前端面板 `OpenCodeIpPoolPanel.vue`（1792 行）+ `keys.ts` 里整段 pool 客户端；重新构建并就地替换 154 的 `frontend/` |
| `ef63e45` | 删管理端：`handlers/admin/provider/ip_pool/`（886 行）、`opencode_ip_pool_routes.rs`（158 行）、`management_token_permissions` 里的 `opencode_ip_pool` scope |
| `76a6495` | 规划期不再注出站 IP：删 `apply_opencode_pool_rotation` / `health_session_sticky_active` / `disabled_exit_ips`（206 行） |

线上验证（`76a6495` 部署后）：`/api/admin/opencode-ip-pool/...` → 501（路由已不存在），
`/api/admin/providers` → 401（对照，路由正常），`/healthz` 200，chat `big-pickle` → 200。

### 还没删的（需要重写轮换）

`opencode_pool/pool.rs`（4980 行）与 `opencode_rotation.rs`（5651 行）仍然互相咬合：

* `opencode_rotation` 用 `OpenCodeScanConfig` / `OpenCodeHealthConfig` 决定换哪个出口 IP；
* 429 重试换点走 `pick_anchor_ip` + `OpenCodeSegmentConcurrencyPolicy`；
* 失败/驱逐走 `evict_opencode_exit_ip`、`mark_runtime_failed_exit_ip_abnormal`、
  `soft_marks_active`。

要删掉扫描器，得先把这些改写成**纯 key 维度**（不再有出口 IP 概念），再删
`pool.rs` 的扫描/探针与 `maintenance/runtime/opencode_ip_pool.rs`、
`opencode_abnormal_prune.rs` 两个 worker。这是一次独立重构，不要和别的东西混在一起做。
## 11. 剩余拆除：IP 叠加层（待执行）

当前 main = `9b39aeda6`，线上 = `9b39aed+tls13-20261026-200607`。

已删干净：前端面板与 API 客户端、管理端路由/handler/权限 scope、池巡检 worker、
异常池清理 worker、规划期 IP 注入、IP 成败统计。

**只剩两处引用 `opencode_pool`：**

| 文件 | 规模 | 说明 |
| --- | --- | --- |
| `opencode_pool/pool.rs` | 4980 行 | 扫描器 + IP 探针 + `OpenCodeScanConfig` / `OpenCodeHealthConfig` |
| `opencode_rotation.rs` | 5635 行（259 行直接提到 IP） | anchor 选点、段并发、驱逐、异常标记、会话锚点、IP 级 KV |

`handlers/admin/provider/amd_load/mod.rs` 只用 `write_provider_config_section_with`，
把这个通用写配置函数挪到别处后，`pool.rs` 即可整块删除。

### 执行顺序（每个子步骤单独 `cargo check` + 提交）

1. `opencode_rotation.rs`：429 配额重试里的 anchor 选择块
   （从 `let concurrency_policy = OpenCodeSegmentConcurrencyPolicy::...` 到该分支返回
   `QuotaRetryDelayed`），连同 `OpenCodeAnchorSkip` 构造、`pick_anchor_ip` 调用、
   `opencode_retry_disabled_exit_ips`。
2. 驱逐与异常标记：`evict_opencode_exit_ip`、`mark_runtime_failed_exit_ip_abnormal`、
   `soft_marks_active`、`OpenCodeEvictOutcome`。
3. 会话锚点与 IP 级 KV：`session_anchor`、`last_exit_ip`、`discard_count`、`suspect`、
   `fail`、`avoid` 这些键及其读写函数。
4. `OpenCodeScanConfig` / `OpenCodeHealthConfig` 的读取点（`from_provider_config`、
   `effective_pool`、`abnormal_ips`、`protect_pool_floor`）随引用一起删。
5. 把 `write_provider_config_section_with` 移出 `pool.rs`，删 `opencode_pool` 整个模块
   与 `lib.rs` 的 `mod opencode_pool;`。

### 每步的验证

- `cargo check -p aether-gateway`（零 error、零 warning）
- CI `unit-tests` 必须绿（小心 `request_candidate_queue` 那个已知 flaky，失败先重跑）
- 线上：`verify_after_delete_154.sh` 四项 + 一次真实 chat 必须 200
- 429 恢复抽查：找一个已被限流的 key 发请求，确认能换到下一个 key 并最终 200

### 环境注意事项

- 直连 154 的 SSH 自 2026-10-26 17:50 起握手超时（TCP/8084 正常），
  部署与验证一律走 `handoff/scripts/deploy_via_134.sh` / `verify_via_134.sh`（8.134 跳板）。
- 双跳下 `/v1/chat/completions` 验证偶尔超过 10 分钟无输出，属链路慢，不是服务异常。
## 12. 最后一块：整块删除 `opencode_pool`（13 个引用点）

小步删除已到头：`pick_anchor_ip` 剩下的三个调用点全在 `pool.rs` 的扫描器里，
所以 anchor 层与 `pool.rs` 只能一起删。实测删除 `opencode_pool/` 并去掉
`lib.rs` 的 `mod opencode_pool;` 后，编译只报 **13 个引用点**：

```
handlers/admin/provider/amd_load/mod.rs:21
opencode_rotation.rs:598  847  851  923  956  1330  1866  1995  1996  2030  2035  3271
```

### 落地步骤

1. 删 `apps/aether-gateway/src/opencode_pool/`，去掉 `lib.rs` 的 `mod opencode_pool;`
2. `cargo check -p aether-gateway`，按上面 13 个行号处理：
   - `amd_load/mod.rs:21` → 把 `write_provider_config_section_with` 复制进 `amd_load`
     （它只需要「按段写供应商配置」这一件事）
   - `opencode_rotation.rs` 12 处 → 每处所在函数都属于 anchor / 驱逐 / 异常标记 /
     会话锚点 / IP 级 KV，按函数整块删（用花括号配对，不要按行号切）
3. 反复 `cargo check` 直到零 error、零 warning（连带引用会分 2–3 批暴露）
4. CI → `handoff/scripts/push_deploy_*.sh`（走 8.134 跳板）→ `verify_no_delay_154.sh`
5. 最后清数据：供应商 config 里的 `opencode_scan` / `opencode_health` 两个段

### 已完成的进度（2026-10-26）

删除顺序：前端面板与 API 客户端 → 管理端路由/handler/权限 scope → 池巡检 worker →
异常池清理 worker → 规划期 IP 注入 → IP 成败统计 → 429 重试里的 IP 换点 →
429 段预算与 Avoid 记账。累计约 3400 行，每步都编过、过了 CI、上过线。

429 延迟重试也已去掉（`ac07e3674`）：实测三次 chat 全部 200，耗时
6.7s / 2.1s / 2.1s（此前同类请求 10–38 秒）。
## 13. IPv6 出口（HE 隧道 / SOCKS5）

### 动机

opencode 按出口 IP 计额度，IPv4 上被限流后只能换 key。HE 的 6in4 隧道给一个
Routed /48（65536 个 /64），按 /64 换源地址即等于换出口 IP 段。

### 实现：只换 TCP，不碰握手

`tls13_upstream` 先用 `opencode_egress::dial()` 建一条 TCP，再交给
`tls13::connect_over()` 完成握手。握手字节与直连逐字节一致，所以指纹不变。

- `crates/aether-tls-hello/src/tls13.rs`：`connect` 拆成 `connect` + `connect_over`
- `apps/aether-gateway/src/execution_runtime/opencode_egress.rs`：SOCKS5 客户端、
  出口选择、失败冷却、直连回落
- `apps/aether-gateway/src/execution_runtime/tls13_upstream.rs`：唯一接线点

### 配置

**唯一真源是数据库**：供应商 config 里的 `opencode_egress` 段，在面板「出口（SOCKS5）」
里编辑。环境变量 `AETHER_OPENCODE_EGRESS` 已废弃并移除——那份配置界面看不见，
只会造成「面板显示一份、进程在跑另一份」的误判。

```json
{"exits":[
  {"name":"local","addr":"127.0.0.1:13001","user":"opencode","pass":"***","weight":2,"rotate":"cidr64","enabled":true},
  {"name":"external","addr":"104.129.15.247:13001","user":"he-icarus","pass":"***","weight":1,"rotate":"cidr64","enabled":false}
],"fallback_ipv4":true,"down_seconds":60}
```

- 启动时按库回填运行时注册表；面板保存后立即刷新，不需要重启进程
- 该段不存在 / 解析为空 → 完全直连，行为与没有出口时一致
- `enabled: false` → 出口保留配置但不参与拨号；全部停用等于直连
- `rotate: "cidr64"` → 用户名追加 `-cidr-64`，由 he-ipv6-pool 按 /64 换源
- CONNECT 发**域名**，DNS 在出口侧解析，否则拿不到 AAAA
- 出口失败冷却 `down_seconds`；全灭时 `fallback_ipv4` 决定回落还是报错
- 密码留空 = 不修改（面板只显示占位符）；显式填新值才覆盖

### 154 的实测结论（2026-10-27）

| 路径 | 结果 |
|---|---|
| 外置 `104.129.15.247:13001` | ✅ 可用，出口在 `2001:470:2995::/48` 与 `2001:470:1f19:324::/64` 间轮换 |
| 本地 6in4（server `72.52.104.74`） | ❌ 只有**隧道链路地址** `2001:470:1f04:142::2` 能跑完整 HTTPS；routed /64 与 /48 都是 TCP 握手成功、TLS 阶段断（rc=35/56），ICMP 和大包 ping 均正常 |

上面那条「本地 6in4 只有链路地址能用」的结论**已被推翻**（2026-10-28）。
真正卡住的不是 routed 前缀，而是当时的实现方式——改用 `he-ipv6-pool` 之后，
routed /64 与 /48 都能跑完整 HTTPS，只是必须配 routed /48（见第 14 节）。

不要再建内核隧道设备。`he-ipv6-pool` 用 **raw socket `ip4:41` + gVisor netstack**
在用户态组包，不创建、也不使用任何网卡：

```
tunnel/tunnel.go: net.ListenPacket("ip4:41", local) → gvisor ipv6 stack
```

154 上那个早期手工建的 `sit` 设备（`he-ipv6@ens17`，含 `2001:470:1f04:142::2/64`
与 IPv6 默认路由）已于 2026-10-28 删除：它和池子无关，留着只会在排查时误导。
回滚脚本存在 `/root/he-ipv6-restore.sh`。

`he-ipv6-pool` 的部署要点只有三条：安装二进制与 unit、`config.json` 里写
`prefixes`（routed /48）、`access_log_dir`。验活看启动日志的
`隧道检查通过 prefix=…` 即可，不看内核路由表。

### 线上验证（d3e087b+tls13-20261027-091911）

```
INFO | opencode 出口已启用 | exits=["external"] fallback_ipv4=true
无「opencode 出口失败」「出口全部不可用，回落直连」日志
三次 chat：http=200  t=10.09s / 7.24s / 6.85s
```

## 14. 429 的粒度是 /64：出口池必须配 routed /48（2026-10-28）

### 现象

每个请求的第一次尝试都吃 429，换下一个出口就 200；429 的响应体是：

```
error.type    = FreeUsageLimitError
error.message = Free usage limit reached. Free models work in OpenCode ...
```

### 定位

池子对每个请求都换了新地址（日志里 121 次请求 = 121 个不同 IPv6），依然 429，
说明 opencode 的免费额度**不是按单个地址计**，而是按更粗的粒度（实测为 /64）。
只配 `Routed /64` 时，`-cidr-64` 的候选子网只有 1 个，等于原地打转：

```
"prefixes": ["2001:470:67:45::/64"]      # 12 次里 10 次 429
```

### 修法

在 tunnelbroker 里给 tunnel 分配 `Routed /48`，池子配置改成 /48：

```
"prefixes": ["2001:470:67:45::/64", "2001:470:49d8::/48"]    # 38.207.163.7
"prefixes": ["2001:470:1f05:142::/64", "2001:470:848d::/48"] # 154
```

`tunnel/pool.go` 的 `spread(cidr, i)` 把「比 cidr 更长的前缀」当作一个子网单位，
用黄金比例步长跳，所以配 /48 后 `-cidr-64` 就是每次换一个 /64，65536 个额度桶。
程序不用改，Aether 侧也不用改（它一直发 `-cidr-64`）。

### 验证

```
# 3 次请求 3 个不同 /64，全部 200
2001:470:49d8:b3aa:ddc2:5f2d:f685:b74e  ok 103ms
2001:470:49d8:8bf7:227b:2fa2:bcbc:cea6  ok 104ms
2001:470:49d8:6444:92bc:a9b:3f1e:2390    ok 123ms
```

### 另一个坑：慢不等于卡

有一个请求 `dur_ms=50688`，看着像重试了 50 秒，其实 trace 里只有一次出站，池侧同一个
连接 `dur_ms=50722 down=137666`——上游生成 137KB 非流式响应本身就花了 50 秒。
排查耗时先看 trace 里有几次出站，再看池侧的 `dur_ms` 是否一致。

### 追加：还有一层「账户级」日额度（2026-10-28 14:50）

同日 13:33 起，两个 /48 出口、每次都是全新 /64，chat 依然全部 429，而同一个出口打
`GET https://opencode.ai/inference/v1/models` 仍是 200。绕过网关直接用 curl 发一条
chat，拿到的是：

```
HTTP/1.1 429 Too Many Requests
Retry-After: 61776
{"type":"error","error":{"type":"FreeUsageLimitError", ... "subscribe to OpenCode Go ..."}}
```

`Retry-After` 折算下来正好对齐到次日 00:00 UTC（08:00 CST）。也就是说免费额度有两层：

- **按 /64 计**的免费用量（第 14 节，换 /64 能恢复）
- **按账户/token 计**的日上限（换 IP 无效，只能等 `Retry-After`）

区分方法很简单：**换 IP 还是 429、但同 IP 打 `/inference/v1/models` 是 200** ⇒ 账户级额度用完，
别再折腾出口池了。

### 更正：额度桶是 /48，而且 **curl 测出来的 429 不能信**（2026-10-28 15:35）

先记教训：我一开始用 `curl`（OpenSSL 指纹）逐地址探测，全部拿到 429 `FreeUsageLimitError`，
于是得出「连 IPv4 都 429 ⇒ 与地址无关、是账户级」的结论 —— **这个结论是错的**。

改走 `opencode2api`（utls 指纹 + 真实登录态，和官方 CLI 一致）之后，同一个地址结果完全不同：

```
走 opencode2api：
  2001:470:1f05:142::1   (154 Routed /64)     200  ✓
  2001:470:1f05:142::2   同 /64 第二个地址    200  ✓
  2001:470:848d:abcd::1  (154 /48 内全新 /64) 429
  2001:470:67:45::1      (新机 Routed /64)    429
  2001:470:67:45::beef   同 /64 换主机位      429
  2001:470:67:45::7      同 /64 第三个地址    429
  49d8 /48 内随机 /64                         429

走 curl（同一批地址，包括上面成功的 1f05:142::1）：全部 429
```

**同一个地址，curl 429 / opencode2api 200** ⇒ curl 拿到的 429 是上游对「非官方客户端」的
判定（body 借用同一个 `FreeUsageLimitError`），不是额度信号。**以后测额度只能用
opencode2api 或网关自己，禁用 curl 结论。**

### 修正后的模型：桶在 /48 这一档（严格说：/40–/48 之间，/48 最可能）

```
2001:470:1f05::/48  ← 200（今天用得少，还有额度）
2001:470:848d::/48  ← 429（今天 33 次成功后耗尽）
2001:470:49d8::/48  ← 429
2001:470:67::/48    ← 429（新机 Routed /64 的父 /48，今早被 he64 出口打光）
```

**已经能确定的**（这批实验足以支撑）：

1. 桶比单个地址粗：同一 `/64` 里换主机位、换 `/64` 都不产生新额度。
2. 桶比 `/64` 和 `/56` 粗：`848d:abcd::1` 和 `848d:dec0::1` 分属不同 `/56`，都 429。
3. 桶比 `/32` 细：`848d`（429）和 `1f05`（200）同在 `2001:470::/32`。
4. 不是按 tunnel 分：`848d::/48` 和 `1f05:142::/64` 走的是**同一条** 154 隧道，
   一个 429 一个 200 ⇒ 区分它们的只有源前缀。
5. 所以「在同一个 routed /48 里换 /64 拿不到新额度」这条**可以直接当规则用**。

**还不能确定的**：精确位数。`/40`、`/44`、`/48` 都符合上面所有观测；`/48` 最可能
（RFC 6177 的 site 边界、也是 HE 分配的天然单位），但没有直接证据排除 `/40`。

**一个附带风险**：`1f05:142::/64` 位于 HE 自己的 `/48`（不是我们独占），如果桶确实是
`/48`，这个桶是**和同段其他 HE 客户共用**的 —— 容量不可控，随时可能被别人抽干。
它今天还活着不代表明天可用。

若要钉死位数，只有一条路：再要一个 routed `/48`（或第二条 tunnel），做跨 `/48`、
同 `/48` 跨 `/56` 的对照实验。




## 15. 流式请求曾经全程白屏（2026-10-28 修复）

### 现象

「感觉回复很慢」。用临时 key 打自己的网关量三次流式请求：

```
第1次: 建连=0.0002s 首字节=5.518s 总计=5.528s  12 个 SSE 事件
第2次: 建连=0.0003s 首字节=2.388s 总计=2.388s   9 个 SSE 事件
第3次: 建连=0.0002s 首字节=5.272s 总计=5.290s  10 个 SSE 事件
```

首字节 ≈ 总时长（差 9–18ms）：所有事件是模型生成完之后一次性刷过来的，
客户端在生成期间一个 token 都收不到。长回答（`elapsed_ms=57.6s`）就是干等 57 秒。

### 原因

阶段一的通道是**非流式**实现，两处都按「整段」处理：

```
transport.rs:2015          let pending = tls13_upstream::send(...)   // 读完整个响应才返回
stream/execution.rs:1689   DirectUpstreamResponse::Tls13 => 把整块 body 当一个 chunk 吐出
```

所以 TTFB 等于上游整个生成时间。这不是出口、429 或负载问题（同期 429=0、换出口=0、
load 0.48），也不是回归——改造前每小时中位耗时一直在 5.8–8.6s 同一量级。

### 修法：增量转发

- `tls13_upstream::send_stream()`：读完响应头就返回（oneshot 交出 head），响应体由
  后台 blocking 线程增量解码后推进 `mpsc` channel；chunked 半包留在 decoder 里等下次
- `transport.rs`：`plan.stream` 时走 `send_stream`，首字节上限用
  `resolve_stream_first_byte_timeout`；新增 `DirectHttpResponse::Tls13Stream` 与
  `DirectUpstreamResponse::Tls13Stream`
- `stream/execution.rs`：`next_direct_upstream_response_chunk` 从 channel 逐块取
- `aether-tls-hello`：`TlsStream::set_read_timeout`，body 阶段读超时放宽到 300s
  （注意该实现的 `fill` 把读错误当 EOF，所以超时表现为流提前结束而不是报错）

非流式路径（sync 执行、错误体预取）行为不变：`send()` 复用同一套建连/读头实现，
`collect_tls13_stream_body()` 负责把流式通道收齐。

### 验证方法

```
curl -s -N -o /tmp/s.txt -w "首字节=%{time_starttransfer}s 总计=%{time_total}s\n" \
  -X POST http://127.0.0.1:8084/v1/chat/completions \
  -H "Authorization: Bearer <临时 key>" -H "Content-Type: application/json" \
  -d '{"model":"big-pickle","stream":true,"messages":[{"role":"user","content":"…"}]}'
```

修好之后首字节应明显小于总时长；日志里该请求打 `opencode 出站请求 … ttfb_ms=… stream=true`。

