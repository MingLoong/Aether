# OpenCode 出口 IP 池 —— 设计与运维

> 本文描述的功能已在生产环境验证。文中不含任何具体主机、端口、账号或出口 IP 清单。

## 1. 为什么需要

OpenCode 的免费额度按**请求的出口公网 IP** 计算：同一个账号、同一个凭据，从不同出口
IP 发出的请求各自消耗独立额度。所以「把出口 IP 摊开」就等于「把额度摊开」。

真实测量：`/28` 段 14 个候选只有 1 个能连通；一次灌入 71 个 CDN 地址，探活后剩 44 个。
**探活产出率远低于 1，必须实测，不能假设。**

## 2. 数据模型

### 2.1 IP 池挂在 provider 上，不挂在 key 上

```json
provider.config.opencode_scan = {
  "cidrs": ["203.0.113.112/28"],
  "auto_enabled": true,
  "interval_hours": 6,
  "concurrency": 16,
  "rotation_enabled": true,
  "cooldown_minutes": 60,
  "proxy_domain": "opencode-proxy.example.com",
  "exit_pool": ["203.0.113.118", "198.51.100.7", "..."]
}
```

**为什么不是「一个 IP 一个 key」**：那是实现约束下的妥协——`opencode_dns_pin` 从
`key.upstream_metadata.opencode_exit_ip` 读 IP，所以在旧模型里「多个 IP」只能表达成
「多个 key」。代价是几十条密钥记录、概念泄漏到密钥管理层、且轮转必须去改全网关共用的
排序路径（还要满足「候选数 ≥ 2」这种在单 key 场景下永远不成立的前提）。provider 级
池子没有这些问题。

### 2.2 凭据与 IP 是叠加关系

```text
凭据(key)  = 照常按系统调度规则轮换，免费 / 付费一视同仁，行为不变
IP 池      = 额外叠加的一层，每次请求再抽一个 CDN IP 当 DNS 锚点
```

两层独立，不隔离、不区分、不互相排斥。

### 2.3 传输层约定

```text
池里的 IP      →  provider.config.opencode_scan.exit_pool
本次请求的锚点  →  候选 transport.key.upstream_metadata.opencode_exit_ip（请求级注入）
最终 pin       →  connect(锚点IP:443)，TLS SNI + Host = endpoint.base_url 的域名
```

## 3. 请求链路

```text
1. 调度器按系统规则（默认 cache_affinity）选 key，行为不变
2. 排序落地后的后置钩子 post_rank_reorder：
     读 provider.config.opencode_scan
     exit_pool 非空 → INCR 游标 → 过滤冷却中的 IP → 取下一个
     写入候选 transport 快照的 opencode_exit_ip
     （Arc::make_mut，共享时自动克隆，不会把本次选择泄漏给其它请求）
3. 下游 34 处 resolve_transport_profile() 原样读取，零改动
4. 传输层 opencode_dns_pin() 生成 pin，连接锚点 IP
```

## 4. 关键约束（都是实际踩过的坑）

| 坑 | 现象 | 结论 |
|---|---|---|
| admin 前门请求体白名单 | PUT 保存报「请求体不能为空」 | 新增 PUT 路由必须登记到 `handlers/shared/request_utils.rs` 的 `(route_family, method, route_kind)` 白名单 |
| 直连官方域名时仍套 pin | 关掉前置代理开关后整池不可用 | `opencode_dns_pin` 必须在 host == `opencode.ai` 时返回 `None` |
| 游标首次不写入 | `cursor` 永远是 0，Redis 键从不创建 | 游标是 `GET+DEL` + 写回，首次取不到旧值时**必须写初值**，否则轮转形同虚设 |
| 排序是全序 | 误以为存在「并列组」 | `compare_candidate_identity_for_ranking` 末尾用 key_id 兜底，不存在并列 |
| 只改 scheduler 层不生效 | 排序结果被 planner 覆盖 | planner 会二次排序，真正决定选谁的是 `candidates.first()` |
| 域名不持久化 | 开关一关，填过的域名消失 | 域名写入 `opencode_scan.proxy_domain`，与端点 host 分离存储 |
| 端点可编辑 | 两个地方改同一个值，开关保存时静默覆盖 | opencode 端点的 Base URL 锁定，唯一入口是前置代理池开关 |

## 5. 熔断与冷却

```text
Redis 键  opencode_pool:cooldown:<provider_id>:<ip>   TTL = cooldown_minutes
写入方    上游返回 403 FreeTierError / 429
读取方    pick_exit_ip 过滤；全池冷却时放行一个，避免彻底打不开
游标      opencode_pool:rotation:cursor:<provider_id>   TTL 24h
```

## 6. 构建

```text
Windows 本地：需要 LIBCLANG_PATH + BINDGEN_EXTRA_CLANG_ARGS=--target=x86_64-w64-windows-gnu
Linux CI：    .github/workflows/gateway-build.yml
前端：        只能跑在 Linux（本地 node_modules 软链形态与 Windows 不兼容）
改动 crates/aether-ai/serving 会触发整条下游依赖链重编，耗时显著高于只改 app
```

## 7. 验收标准

```text
GET  status   → exit_pool 长度 = 存活 IP 数，saved_proxy_domain 有值
POST clean    → checked/removed 数字合理（探活会剔除黑洞）
8 次请求后    → rotation_cursor 递增到 8
ss 抓网关连接 → 对端 IP 落在 exit_pool 内且有多个不同值
关掉开关      → base_url 回到官方域名，请求仍 200（此时不使用 IP 池）
```
