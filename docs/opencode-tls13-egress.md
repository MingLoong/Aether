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
- 开关默认关闭（`AETHER_OPENCODE_TLS13`），便于回滚。
- 只对 `provider == opencode` 生效，其他供应商一律不动。

### 仍待补的验证

证书**反例**未实测（本地 `openssl s_server` 自签证书那张卡在握手兼容性，
走不到验签）。建议用 `webpki` 单测构造伪造链补上。
