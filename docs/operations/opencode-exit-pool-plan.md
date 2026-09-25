# OpenCode 出口 IP 池（CDN 前置代理）实现规划

> 状态：规划定稿，待实施
> 分支基线：`v0.1.0-opencode`（本分支已具备 OpenCode provider 支持）
> 需求来源：OpenCode 免费层按**出口 IP** 计每日配额；通过前置 CDN + 多出口 IP 分散请求，使每个 IP 独立消耗额度。

---

## 1. 背景与目标

- OpenCode 免费层（`opencode.ai/zen/*`）按**出口公网 IP** 做每日免费额度/限流。
  实测：匿名 `Authorization: Bearer public` + 每请求 `x-session-id` 即可用；额度挂在出口 IP 上。
- 目标：网关对 opencode 上游的请求**分散到多个出口 IP**，等效放大每日免费额度（×N，N=可用出口 IP 数）。
- 当前可用出口池：25 个公网可达 IP（见 §4）。CDN 域名：`opencode.fanjinlong.top`。

## 2. 已验证事实（2026-09-25 实测）

| 项 | 结果 |
|---|---|
| `https://opencode.fanjinlong.top/zen/v1/models`（默认解析） | HTTP 200，反代 opencode.ai 正常 |
| 25 个候选出口 IP（§4 列表）直连 443 + SNI=`opencode.fanjinlong.top` | 全部 HTTP 200 |
| 反例 `1.56.100.x` 段 | 443 全不通，**不可用，放弃** |
| opencode 指纹要求（403 FreeTierError 触发点） | UA 必须 `opencode/<ver>`；body 必须带 `bash/glob/grep/read` 4 个 tools；body `stream:true` |
| 上游认证 | 固定 `Bearer public`（匿名），与出口 IP 无关 |

## 3. 设计决策

### 3.1 核心机制：连接目标 pin 到出口 IP，TLS/SNI 与 HTTP Host 保持 CDN 域名

```
请求 https://opencode.fanjinlong.top/zen/v1/chat/completions
  TCP 连接目标  = 出口 IP:443   （由 key 配置决定）
  TLS SNI       = opencode.fanjinlong.top （证书校验正常）
  HTTP Host     = opencode.fanjinlong.top （上游按域名路由）
```

实现载体：reqwest `Client::builder().resolve_to_addrs(host, &[SocketAddr::new(ip, port)])`
（reqwest 唯一"连 A 但 SNI/Host 用 B"的入口，属于协议层事实，不可回避。）

### 3.2 配置模型：**不复用 API Key 字段**，使用结构化字段

在 **key 级** `upstream_metadata`（现有字段，JSON 对象）中新增：

```json
upstream_metadata = {
  "opencode_exit_ip": "111.4.225.217"
}
```

- key 的 API Key 字段**仍是密钥语义**，保持干净（MingLoong fork 复用 API Key 字段填 IP，语义混乱，不采纳）。
- 缺省（未配置 `opencode_exit_ip`）→ 无 pin → 行为与现状完全一致（**零破坏是硬约束**）。
- 可选：provider 级默认池（§3.3 增强）`provider.config.opencode_exit_ips = [...]`。

### 3.3 出口选择：两级

- **L1 key 级固定出口（必做）**：25 个 key，每个配一个 `opencode_exit_ip`。
  复用 Aether 既有 key 池路由（优先级+failover）→ key 池即 IP 池。
- **L2 provider 级出口池 + 请求级选择（增强，可后置）**：一个 key + provider 配置 IP 池，
  执行层 round-robin / 最小使用 / 配额感知（跟踪 429/403 次数）选 IP。
  本期文档覆盖 L1；L2 见 §7 预留设计，不阻塞 L1。

## 4. 可用出口 IP 池（25 个，均已验证 200）

```
111.4.225.217   111.4.225.63    111.4.225.64
111.42.114.101  111.42.114.181  111.42.114.182  111.42.114.54  111.42.114.68  111.42.114.71
111.51.158.119  111.51.158.138  111.51.158.181  111.51.158.187  111.51.158.55  111.51.158.61
112.84.131.118  112.84.131.193  112.84.131.199  112.84.131.209  112.84.131.228  112.84.131.71
113.142.27.118  113.142.27.122  113.142.27.126  113.142.27.188
```

（`1.56.100.x` 段已证实不可达，勿使用。）

## 5. 实现明细（本分支文件级）

> 所有改动保持向后兼容：未配置 exit_ip 时，各函数返回 `None`，链路不变。

### 5.1 `crates/aether-provider/transport/src/opencode.rs`（新增 4 个 pub 函数）

参照同文件现有 `is_opencode_provider_transport` / `insert_opencode_request_headers_if_needed` 风格。

```rust
/// 从 key.upstream_metadata 解析出口 IP（Key 级）。
/// upstream_metadata 为 JSON 对象，取 "opencode_exit_ip" 字符串并 parse::<IpAddr>()。
/// 非法/缺失 → None。
pub fn opencode_key_exit_ip(transport: &GatewayProviderTransportSnapshot) -> Option<std::net::IpAddr>;

/// 构造 DNS pin：(host, ip, port)。host 取 endpoint.base_url 的域名，
/// ip 取 §5.1-1，port 取 base_url.port_or_known_default()。
pub fn opencode_dns_pin(transport: &GatewayProviderTransportSnapshot)
    -> Option<(String, std::net::IpAddr, u16)>;

/// 生成 ResolvedTransportProfile，extra = {"opencode_dns_pin": {"host":..,"ip":..,"port":..}}，
/// pool_scope = TRANSPORT_POOL_SCOPE_KEY（保证不同 key 连接池隔离）。
pub fn opencode_resolved_transport_profile(transport: &GatewayProviderTransportSnapshot)
    -> Option<aether_contracts::ResolvedTransportProfile>;

/// 从 profile.extra（Option<&str>，JSON 字符串）解析 pin。
pub fn opencode_dns_pin_from_extra(extra: Option<&str>)
    -> Option<(String, std::net::IpAddr, u16)>;
```

**单测要点**（mod tests 内）：
- `upstream_metadata` 含合法 IP → `opencode_key_exit_ip` 返回该 IP
- 含非法字符串 / 缺失 → `None`
- `opencode_resolved_transport_profile` 在非 opencode provider / 未配 exit_ip → `None`
- `opencode_dns_pin_from_extra` 对 `None` / 非 JSON / 缺字段 → `None`（消费侧防御）

### 5.2 `crates/aether-provider/transport/src/network.rs`（profile 注入）

现有 `resolve_transport_profile`（153 行）已按 provider 特判：`resolve_claude_code_transport_profile` / `resolve_grok_browser_transport_profile`。

**照此模式新增**：

```rust
fn resolve_opencode_transport_profile(
    transport: &GatewayProviderTransportSnapshot,
) -> Option<ResolvedTransportProfile> {
    if !crate::opencode::is_opencode_provider_transport(transport) {
        return None;
    }
    crate::opencode::opencode_resolved_transport_profile(transport)  // 内部处理 None
}
```

并在 `resolve_transport_profile` 的链尾追加 `.or_else(|| resolve_opencode_transport_profile(transport))`。
同时确认 `resolve_transport_profile_id` 自动覆盖（它调用 `resolve_transport_profile`，无需改）。

**单测要点**：opencode transport 带 exit_ip → profile 非 None 且 `extra` 含 pin；
不带 exit_ip → profile 与现状一致（None 或其它）。

### 5.3 `apps/aether-gateway/src/execution_runtime/transport.rs`（执行层消费）

目标函数为 direct upstream reqwest client 构建（约 4242 行起，
签名含 `cache_key: &DirectReqwestClientCacheKey`）。
在 `apply_transport_profile_cache_key(...)` 之后、`if let Some(proxy_url)` 之前插入：

```rust
if let Some((host, ip, port)) = cache_key
    .transport_profile
    .as_ref()
    .and_then(|profile| crate::ai_serving::transport::opencode::opencode_dns_pin_from_extra(
        profile.extra.as_deref(),
    ))
{
    // OpenCode 前置 CDN pin：连接目标 = key 出口 IP，TLS/SNI 与 Host 保持 CDN 域名。
    builder = builder.resolve_to_addrs(
        host.as_str(),
        &[std::net::SocketAddr::new(ip, port)],
    );
}
```

注意：
- 该 builder 在 `proxy_url.is_none()` 时已设置 `dns_resolver(ExecutionSafeDnsResolver)`；
  `resolve_to_addrs` 为其上的静态映射，优先级更高、可共存（reqwest 文档行为）。
- 若 `ai_serving::transport::opencode` 模块在本分支不可直接引用（模块路径不同），
  改为从 `aether_provider_transport` crate 引入同名字/同签名函数。

**封装建议（降低上游同步冲突面）**：把"解析 pin + 修改 builder"整体封装为
`execution_runtime/transport.rs` 内的私有函数，调用点只留一行：

```rust
fn apply_opencode_dns_pin(
    builder: reqwest::ClientBuilder,
    cache_key: &DirectReqwestClientCacheKey,
) -> reqwest::ClientBuilder {
    let Some((host, ip, port)) = cache_key
        .transport_profile.as_ref()
        .and_then(|profile| crate::opencode_dns_pin_from_extra(profile.extra.as_deref()))
    else {
        return builder;
    };
    builder.resolve_to_addrs(host.as_str(), &[std::net::SocketAddr::new(ip, port)])
}
// 调用点：
builder = apply_opencode_dns_pin(builder, cache_key);
```

pin 解析函数（`opencode_dns_pin_from_extra`）留在 `aether_provider_transport` crate
（opencode.rs），与协议逻辑同居；builder 层面的封装留在 execution 层。上游若重构
reqwest 构建，只移动这一行调用点，pin 逻辑整体不动。

### 5.4 key 配置写入（验证用即可）

不强制新增 API。验证阶段用现有管理 API 更新 key 的 `upstream_metadata`：
`PUT /api/admin/.../keys/:id` body 含 `upstream_metadata: {"opencode_exit_ip": "<ip>"}`
（实现者先通过前端/接口确认字段可写路径；若不可写，在 §5.5 补充允许写入的校验）。

### 5.5 前端/API（可选，不阻塞 L1）

ProviderFormDialog / Key 编辑表单增加 `opencode_exit_ip` 输入提示（仅 opencode 类型显示）。
后端校验：`upstream_metadata.opencode_exit_ip` 必须是合法 IPv4/IPv6，否则拒绝。

## 6. 分阶段任务与验收

### S1 传输层（5.1 + 5.2）
- [ ] `opencode.rs` 4 函数 + 单测
- [ ] `network.rs` profile 注入 + 单测
- **验收**：`cargo test -p aether-provider-transport`（或对应 crate）全绿；新增测试通过。
  编译检查：`cargo check -p aether-provider-transport`。

### S2 执行层（5.3）
- [ ] `execution_runtime/transport.rs` resolve_to_addrs 接线
- **验收**：`cargo check -p aether-gateway` 通过。
  集成实测：配一个 key（upstream_metadata.opencode_exit_ip = 111.4.225.217），
  调 chat/test-model，观察请求到达 CDN（对端视角出口为 111.4.225.217；沙箱内可
  通过网关日志确认候选 key / 通过抓包或 CDN 访问日志确认连向目标 IP）。

### S3 端到端配池
- [ ] 建立 25 个 key（各配一个 exit_ip），或 1 key + L2 池配置
- [ ] 逐个 `test-model` 验证 25 个 IP 均可用（复用 §7.3 脚本）
- **验收**：连续多次请求分散到 ≥3 个不同出口 IP（CDN 侧日志或网关侧多 key 候选）。
  单日额度耗尽一个 IP 时，其它 IP 候选继续工作（failover）。

## 7. 预留设计：L2 provider 级出口池（本期不实现）

- provider.config.`opencode_exit_ips: [ip,...]`（JSON 数组）。
- 执行层/路由层在选择候选时抽一个未耗尽 IP 注入 pin；配额感知 = 跟踪每个 IP 的
  403/429 计数（`FreeTierError` 是配额耗尽主信号），冷却后恢复。
- 落地位置建议：候选选择逻辑（`aether-routing-core` 或 execution 候选构建处），
  或简化版：key 池本身承担轮换（25 key 方案已满足），L2 纯属"少配 key"的运维优化。

## 8. 风险与边界

1. 额度上限 = 出口 IP 池数量（25）。CDN 节点增减时 IP 列表需同步维护（文档化）。
2. `resolve_to_addrs` 与自定义 `dns_resolver` 共存依赖 reqwest 行为，S2 集成测试必须覆盖。
3. 免费层对**匿名额度**可能也有总量/并发限制（非仅按 IP），25 池后仍可能触发；
   届时需观察 429/503 形态决定是否加限速/退避。
4. 密钥语义：key 是 key、exit_ip 是 exit_ip，审计日志中不得把 IP 当凭据处理。
5. `1.56.100.x` 不可达，勿再尝试。

## 9. 测试与验证环境

- 项目路径：`/root/job-envs/sandboxes/deepseek-harness-1790254355/Aether`
- 编译环境变量（见 `docs/operations/MAINTENANCE.md` §2）：
  `PATH/CARGO_HOME/RUSTUP_HOME/LIBCLANG_PATH/LD_LIBRARY_PATH/BINDGEN_EXTRA_CLANG_ARGS`
- 网关运行于 `127.0.0.1:8084`（管理 token 见会话 `/tmp/aether-test-token`）
- 单测命令：`cargo test -p aether-provider-transport`、`cargo test -p aether-model-fetch`
- 手动验证快捷命令（任何 IP）：
  ```bash
  curl -s --max-time 10 --resolve opencode.fanjinlong.top:443:<IP> \
    https://opencode.fanjinlong.top/zen/v1/models -H "User-Agent: opencode/1.18.31" \
    -o /dev/null -w "%{http_code}\n"
  ```

## 10. 参考资料

- 本分支现状：`docs/operations/MAINTENANCE.md`（环境、编译、测试、故障排查）
- 参考 fork（思路对照，非照抄）：`https://github.com/MingLoong/Aether`（commit `3b79b19`）：
  - `crates/aether-provider/transport/src/opencode/mod.rs`（`opencode_key_upstream_ip` 等 4 函数）
  - `apps/aether-gateway/src/execution_runtime/transport.rs`（`resolve_to_addrs` pin 消费）
  - 其配置模型（API Key 字段填 IP）**本规划不采纳**，见 §3.2 理由。


## 11. 上游同步影响与冲突预案

> 目标：与 `github.com/fawney19/Aether` 的 `main` 保持低摩擦同步。

### 11.1 冲突预期（按文件）

| 文件 | 上游是否含 | rebase 冲突可能 | 处理预案 |
|---|---|---|---|
| `crates/aether-provider/transport/src/opencode.rs` | 否（本分支新增） | **零冲突** | 无需处理 |
| `crates/aether-provider/transport/src/network.rs` | 是 | 低（仅当上游改 resolver 链） | 重贴 `or_else(resolve_opencode_transport_profile)` 一行 + 检查函数签名 |
| `apps/aether-gateway/src/execution_runtime/transport.rs` | 是 | 低（仅当上游改 reqwest 构建） | 重贴 `apply_opencode_dns_pin(...)` 调用一行；函数本体在 §5.3 封装中整体保留 |
| `crates/aether-model-fetch/src/logic.rs`、`transport.rs` | 是 | 低（仅当上游动 model-fetch 特判区） | 重贴 opencode 分支（均有 `provider_type=="opencode"` 守卫） |
| `frontend/.../ProviderFormDialog.vue` 等 | 是 | 低 | 重贴 opencode 类型分支 |

### 11.2 降低冲突的操作纪律

1. **分文件/分主题提交**：每个上游文件的增量独立 commit（feat/fix 分开），rebase 时可针对单个提交处理。
2. **执行层封装**：按 §5.3 封装 `apply_opencode_dns_pin`，`execution_runtime/transport.rs` 只留调用行。
3. **定期 rebase**：`git fetch origin && git rebase origin/main`，频率越高冲突越少。
4. **守卫隔离**：所有分支逻辑必须带 `provider_type == "opencode"` / opencode 判断，解冲突时以守卫块为锚点。

### 11.3 长期路线

- 功能稳定后，将整个 OpenCode 支持（含本出口池特性）整理为 PR 提回上游；
  合入后本分支增量可"上游化"，长期零维护。
- 在此之前保持 fork + rebase 线性历史，维护文档见 `docs/operations/MAINTENANCE.md`。
