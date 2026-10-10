# OpenCode 供应商与 CDN 出口 IP 池（行为文档）

> 本文描述**代码中已实现**的行为，不是计划。所有结论都标注出处（`file:line`）。
> 未能从代码确认的事项集中列在第 8 节，请勿把那一节当作已实现。
> 事实提炼自 2026-10 工作区快照；改动相关代码后请同步更新本文。

---

## 0. 为什么需要出口 IP 池

OpenCode 的免费额度按**请求的出口公网 IP** 计算：同一账号、同一凭据，从不同出口 IP 发出的
请求各自消耗独立额度。所以「把出口 IP 摊开」等于「把额度摊开」。

探活产出率远低于 1，**必须实测、不能假设**：一次 `/28` 段 14 个候选只有 1 个能连通；
一次灌入 71 个 CDN 地址，探活后剩 44 个。

因此设计上是「凭据 × IP 两层叠加」：凭据照常按系统调度规则轮换（免费/付费一视同仁），
IP 池只是额外再抽一个 CDN IP 当 DNS 锚点。两层独立，不隔离、不互相排斥。

**池挂在 provider 上而不是「一个 IP 一个 key」**：后者是旧实现约束下的妥协——出口 IP 从
`key.upstream_metadata.opencode_exit_ip` 读，所以「多个 IP」只能表达成「多个 key」，代价是
几十条密钥记录、概念泄漏到密钥层，且轮转必须改全网关共用的排序路径。provider 级池没有这些
问题。全仓库 `*.sql` 里搜不到任何 `opencode` 相关内容——池的持久化完全在 provider 的
`config` JSON 内（`opencode_scan` / `opencode_health` 两段）。

---

## 1. 供应商类型 `provider_type == "opencode"`

### 1.1 注册与校验

| 位置 | 事实 |
|---|---|
| `crates/aether-provider/transport/src/opencode.rs:31` | `pub const OPENCODE_PROVIDER_TYPE: &str = "opencode"`，类型字面量的唯一来源 |
| `crates/aether-provider/transport/src/lib.rs:132-133` | 从 transport crate 再导出 `OPENCODE_PROVIDER_TYPE` |
| `apps/aether-gateway/src/handlers/admin/provider/write/normalize.rs:7-22` | 白名单 `SUPPORTED_PROVIDER_TYPES`；`"opencode"` 在 :19，`"amd"` 在 :21 |
| `apps/aether-gateway/src/handlers/admin/provider/write/normalize.rs:24-33` | `normalize_provider_type_input()`：`trim + to_ascii_lowercase` 后查白名单（:26）；报错文案复用同一份列表（:31），不会再次漂移 |
| `apps/aether-gateway/src/handlers/admin/provider/write/provider/create.rs:40` | 新建供应商走该校验，缺省值 `"custom"` |
| `apps/aether-gateway/src/handlers/admin/provider/write/provider/update.rs:62` | 更新供应商走同一校验 |
| `crates/aether-provider/transport/src/provider_types.rs:289-301` | `OPENCODE_RUNTIME_POLICY` |
| `crates/aether-provider/transport/src/provider_types.rs:604` | `provider_runtime_policy()` 分派 `"opencode"` |
| `crates/aether-provider/transport/src/provider_types.rs:626` | `fixed_provider_template()` 分派 `"opencode"` |

`OPENCODE_RUNTIME_POLICY` 的实际取值（`provider_types.rs:289-301`）：`fixed_provider: false`、
`api_format_inheritance: None`、`enable_format_conversion_by_default: true`、
`allow_auth_channel_mismatch_by_default: true`、`oauth_is_bearer_like: true`、
`supports_model_fetch: true`、`supports_local_openai_chat_transport: true`、
`supports_local_same_format_transport: true`、`local_embedding_support: None`。

**`fixed_provider: false` 是有意的**：opencode 的 `endpoint.base_url` 必须能在「官方域名」与
「前置 CDN 域名」之间自由选择。模板（:556-569）只负责**端点 reconcile**，不改变 OAuth、
密钥继承与格式继承行为（:548-555）。

### 1.2 `upstream_metadata` 校验

- `normalize.rs:65-103` — `normalize_opencode_upstream_metadata()`。
- `normalize.rs:73-75` — 非 opencode 供应商传 `upstream_metadata` 直接拒绝。
- `normalize.rs:79-81` — 只允许 `opencode_exit_ip` 一个键。
- `normalize.rs:97-98` — 值必须能被 `aether_provider_transport::parse_opencode_exit_ip` 解析成合法公网 IP。
- 调用点：`.../write/keys/create.rs:53`、`.../write/keys/update.rs:383`。

### 1.3 前端

- `frontend/src/api/endpoints/types/provider.ts:800` — `ProviderType` 联合类型含 `'opencode'`。
- `frontend/src/features/providers/components/ProviderFormDialog.vue:81`、`:127` — 类型下拉含 `<SelectItem value="opencode">`。
- `frontend/src/features/providers/utils/providerTypeUtils.ts:29-30` — `isOpenCodeProviderType()`。
- `frontend/src/features/providers/components/EndpointFormDialog.vue:1910-1917` — `isFixedProvider` 对 `opencode` 显式返回 `false`（:1915）。

---

## 2. 默认 endpoint / base URL

| 常量 | 值 | 出处 |
|---|---|---|
| `OPENCODE_ORIGINAL_DOMAIN` | `opencode.ai` | `provider_types.rs:531`、`transport/src/opencode.rs:36` |
| `OPENCODE_ORIGINAL_BASE_URL` | `https://opencode.ai/` | `provider_types.rs:538` |
| `OPENCODE_CHAT_CUSTOM_PATH` | `/zen/v1/chat/completions` | `provider_types.rs:541` |
| `OPENCODE_CHAT_PATH` | `/zen/v1/chat/completions` | `transport/src/opencode.rs:38` |
| `OPENCODE_BASE_URL` | `https://opencode.ai` | `transport/src/opencode.rs:34` |
| 模型列表 URL | `{base}/zen/v1/models` | `crates/aether-model-fetch/src/logic.rs:888-894` |

- 固定端点模板 `OPENCODE_FIXED_PROVIDER_TEMPLATE`（`provider_types.rs:556-569`）：`version: 1`，
  `base_url = OPENCODE_ORIGINAL_BASE_URL`，单个端点 `item_key/api_format = "openai:chat"`，
  `custom_path = Some(OPENCODE_CHAT_CUSTOM_PATH)`。
- 端点 base_url 与域名刻意分成两个常量：模板 base_url 会交给 `normalize_admin_base_url`，
  裸域名过不了那一关，创建会直接 500（`provider_types.rs:533-538`）。
- 模型列表在 `provider_type == "opencode"` 且 `api_format` 以 `openai:` 开头时走 zen 路径
  （`aether-model-fetch/src/logic.rs:89-90`）；匿名请求头：UA `opencode/<version>`、
  `x-opencode-session: ses_…`、`Authorization: Bearer public`
  （`aether-model-fetch/src/transport.rs:129,143-149,160-165`）。
- 对话路径请求指纹：`transport/src/opencode.rs:165-166`（UA）、`:230-263`（头注入）、
  `:265-321`（补齐 free-tier 工具 `bash/glob/grep/read`）；挂载点
  `transport/src/standard/mod.rs:404` 与 `transport/src/request_body.rs:38`。
- 官方域名不套 pin：`transport/src/opencode.rs:115`。

---

## 3. 出口 IP 池：实现位置

| 文件 | 职责 |
|---|---|
| `apps/aether-gateway/src/opencode_pool/mod.rs` | 领域层入口（29 行），导出配置类型与任务函数（:24-29） |
| `apps/aether-gateway/src/opencode_pool/pool.rs` | 扫描 / 复验 / 清理 / 配置 CAS 写入（3265 行） |
| `apps/aether-gateway/src/opencode_rotation.rs` | 游标轮转、会话粘性、额度冷却、被动降权（623 行） |
| `apps/aether-gateway/src/opencode_proxy.rs` | 请求路径上的前置代理 host 改写（100 行） |
| `apps/aether-gateway/src/maintenance/runtime/opencode_ip_pool.rs` | 定时维护 worker（386 行） |
| `apps/aether-gateway/src/handlers/admin/provider/ip_pool/mod.rs` | HTTP 层（726 行） |

> **路径更正**：旧计划文档把池子的领域逻辑写成
> `apps/aether-gateway/src/handlers/admin/provider/ip_pool/pool.rs`。**该文件不存在**。
> 领域逻辑在 `apps/aether-gateway/src/opencode_pool/pool.rs`；`handlers/.../ip_pool/` 下只剩
> `mod.rs`（HTTP 层）。原因见 `opencode_pool/mod.rs:1-20`：架构守卫
> `apps/aether-gateway/tests/architecture/admin_shared.rs::admin_external_usage_is_confined_to_admin_api`
> 禁止非管理台文件以完整路径引用管理台内部。

接线点：

- `apps/aether-gateway/src/lib.rs:66-68` — `mod opencode_pool; mod opencode_proxy; mod opencode_rotation;`
- `apps/aether-gateway/src/maintenance/runtime.rs:23-24,84-85` — `#[path]` 声明与再导出。
- `apps/aether-gateway/src/maintenance/mod.rs:15,18` — 再导出 worker 与单轮入口。
- `apps/aether-gateway/src/state/core.rs:2371`（导入在 :67）— 启动时拉起 worker。
- `apps/aether-gateway/src/task_runtime/mod.rs:51` — 单例 worker 键 `maintenance.opencode.ip_pool.autoscan`。
- `apps/aether-gateway/src/handlers/admin/provider/routes.rs:17-25` — `ip_pool::maybe_build_local_admin_opencode_ip_pool_response(...)`。
- `apps/aether-gateway/src/ai_serving/planner/candidate_ranking.rs:124-135` — 排序后置钩子 `post_rank_reorder`。

---

## 4. 管理接口（全部 10 条）

分类器：`apps/aether-gateway/src/control/route/admin/opencode_ip_pool_routes.rs`（前缀常量 :5，
分类函数 :14-51），在 `control/route/admin.rs:83-84` 挂进路由表。统一标记路由族
`opencode_ip_pool_manage`、权限 scope `admin:opencode_ip_pool`（:44-50）。

| # | 方法 + 路径 | `route_kind` | 处理器 |
|---|---|---|---|
| 1 | `GET /api/admin/opencode-ip-pool/providers/{id}` | `get_opencode_ip_pool_status` | `ip_pool/mod.rs:94` → `build_status_response` :302 |
| 2 | `PUT /api/admin/opencode-ip-pool/providers/{id}/config` | `save_opencode_ip_pool_config` | `ip_pool/mod.rs:95` → `save_config` :454 |
| 3 | `POST /api/admin/opencode-ip-pool/providers/{id}/scan` | `run_opencode_ip_pool_scan` | `ip_pool/mod.rs:96` → `run_scan` :561，返回 **202** |
| 4 | `POST /api/admin/opencode-ip-pool/providers/{id}/verify` | `run_opencode_ip_pool_verify` | `ip_pool/mod.rs:97` → `run_verify` :601，返回 **202** |
| 5 | `POST /api/admin/opencode-ip-pool/providers/{id}/clean` | `run_opencode_ip_pool_clean` | `ip_pool/mod.rs:98` → `run_clean` :634，返回 **202** |
| 6 | `POST /api/admin/opencode-ip-pool/providers/{id}/restore-original` | `restore_opencode_original_base_url` | `ip_pool/mod.rs:99` → `restore_original_base_url` :665 |
| 7 | `POST /api/admin/opencode-ip-pool/providers/{id}/pool/ips/add` | `add_opencode_exit_ip` | `ip_pool/mod.rs:100` → :125 |
| 8 | `POST /api/admin/opencode-ip-pool/providers/{id}/pool/ips/remove` | `remove_opencode_exit_ip` | `ip_pool/mod.rs:101` → :151 |
| 9 | `POST /api/admin/opencode-ip-pool/providers/{id}/pool/ips/update` | `update_opencode_exit_ip` | `ip_pool/mod.rs:102` → :179 |
| 10 | `POST /api/admin/opencode-ip-pool/providers/{id}/pool/ips/toggle` | `toggle_opencode_exit_ip` | `ip_pool/mod.rs:103` → :226 |

三条长任务（scan / verify / clean）都是「同步占位占锁 → `tokio::spawn` 后台执行 → 立刻 202」，
真实进度由前端轮询 `GET` 状态接口取得（`ip_pool/mod.rs:565-567,588-596`；同形状见 :610-631、:641-662）。

### 4.1 必须同步登记的配套项

- **请求体白名单**：`apps/aether-gateway/src/handlers/shared/request_utils.rs:327-352` —
  PUT `save_opencode_ip_pool_config` 与 4 条 POST `*_exit_ip`（:328-331、:333-337、:338-342、:343-347、:348-352）。
  漏登记的症状是拿到空 body，看起来像「接口没实现」。
- **管理令牌权限组**：`apps/aether-gateway/src/control/management_token_permissions.rs:105-112`
  （scope `opencode_ip_pool`）与 :664-667（`read|write|admin` → `admin:opencode_ip_pool:*`）。
- **provider id 解析**：`ip_pool/mod.rs:259-266` — **强制**首段长度等于 36（:262），否则返回 `None`；
  回归测试 `provider_id_parsing_accepts_action_suffix`（:708）断言 `.../providers/short` 解析失败（:721-723）。
  对比 `control/route/admin/amd_load_routes.rs:12-13,70,98-101`：AMD 分类器刻意不做长度校验。

### 4.2 路径动作语义

- `restore-original`（`ip_pool/mod.rs:665-701`）：把 host 不等于 `opencode.ai` 的端点 base_url
  改写回官方域名，返回 `{provider_id, changed, errors[]}`。
- `pool/ips/*`：操作 **`exit_pool`**，不创建、不删除密钥。`add` 查重后 push（:141-147，重复返回
  `{saved:true,duplicate:true}`）；`remove` 同时从 `exit_pool` 与 `exit_pool_disabled` 摘除（:167-175）；
  `update` 改名并同步 `exit_pool_disabled`（:202-222，重名 400）；`toggle` 写 `exit_pool_disabled`（:246-255）。

---

## 5. 配置字段（JSON 键，全部来自代码）

### 5.1 `provider.config.opencode_scan`

结构体 `OpenCodeScanConfig`（`opencode_pool/pool.rs:294-341`）；读取 `from_provider_config_object`
:611-660；部分更新合并 `merged_with_payload` :502-540；写回 `to_provider_config_value` :663-680；
校验 `validate_section` :577-604；生效值辅助 `effective_*` / `scan_cursor_ttl_seconds` :682-733。
（行号为 2026-10 新增两个可调项后的快照。）

| 字段 | 类型 | 默认 / 约束 | 出处 |
|---|---|---|---|
| `cidrs` | `string[]` | 空即「未配置扫描网段」 | :296, :511, :617 |
| `candidates` | `string[]` | 扫描产物，**不是**生产列表 | :299, :548, :618 |
| `pinned` | `string[]` | 只豁免淘汰，不影响是否使用 | :303, :554, :619 |
| `auto_enabled` | `bool` | 缺省 `false` | :305, :514, :620 |
| `interval_hours` | `u32` | 缺省 0（= 只允许手动）；上界 8760 | :307, :517, :584 |
| `concurrency` | `usize` | 默认 32，合法区间 1–128 | :312, :523, :578-583 |
| `max_candidates_per_round` | `usize` | 默认 `OPENCODE_SCAN_MAX_CANDIDATES`(4096)，合法区间 1–`OPENCODE_SCAN_MAX_CANDIDATES_LIMIT`(65536) | :319, :529-534, :591-596, :689-693 |
| `probe_max_handshake_ms` | `u64` | 未配置时回退环境变量 `OPENCODE_PROBE_MAX_HANDSHAKE_MS`，再回退 600；合法区间 100–60000 | :325, :535-538, :597-602, :696-703 |
| `rotation_enabled` | `bool` | 缺省 `false` | :327, :529, :583 |
| `cooldown_minutes` | `u32` | 默认 60，合法区间 1–10080 | :329, :532, :590 |
| `proxy_domain` | `string` | 空串按未设置；开关关闭也保留 | :332, :553, :589 |
| `proxy_enabled` | `bool` | 缺省 `false`；**不写回** `endpoint.base_url` | :335, :550, :604 |
| `exit_pool` | `string[]` | 生产轮换的**兜底**列表（迁移期） | :339, :538, :630 |
| `exit_pool_disabled` | `string[]` | 手工停用，条目仍保留 | :341, :541, :631 |

> **`probe_max_handshake_ms` 的两个要点**（2026-10 实测，数据见
> `handoff/docs/OPENCODE-POOL-DIAGNOSIS.md`）：
> ① 它与 `concurrency` **强耦合**——并发是自己造的争用，同一批节点在 32 路并发下实测
> p50 从 ~670ms 抬到 ~2.6s，于是「并发调高 → 通过率下降」。实测 40 个 CloudFront 地址：
> 并发 1 时 600ms 过 9/40；并发 8 时 600ms 过 0/40、1500ms 过 40/40。
> ② `to_provider_config_value` 写出的是**生效值**（与 `concurrency` 同款语义），所以一旦
> 保存过，环境变量对这家 provider 就不再起作用；状态接口额外回传
> `probe_max_handshake_source`（`config` / `env` / `default`），面板据此说明数字来源。

`exit_pool` 与 `candidates` 不同：扫描**只写 candidates**（`pool.rs:1394-1406`）；
`exit_pool` 只在「旧模型 + 非 provider 池」分支里由 `create_ip_pool_key` 写入（:1392, :1407）。

### 5.2 `provider.config.opencode_health`

结构体 `OpenCodeHealthConfig`（`pool.rs:101-159`）；读取 :2212-2305；合并 :2307-2379；写回 :2381-2406；
校验 :227-278。

| 字段 | 类型 | 默认 / 约束 | 出处 |
|---|---|---|---|
| `healthy` | `string[]` | 生产唯一列表；空则回退 `exit_pool` | :110, :2222 |
| `degraded` | `string[]` | pinned 或保底捞回但未达标 | :112, :2223 |
| `healthy_prev` | `string[]` | **只读回、不回写**，见第 8 节 | :114, :2224, :2426 |
| `latencies` | `object<ip, ms>` | 逐节点首字节中位数 | :120, :2225-2236 |
| `rejections` | `object<ip,{reason,median_ms,samples_ok,samples_total}>` | 上轮淘汰原因 | :122, :2237-2243 |
| `last_verify_at` | RFC3339 字符串 | 落盘，进程重启后仍可用 | :129, :2289-2294 |
| `last_verify_checked` / `_kept` / `_dropped` | `u64` | 上次复验摘要 | :131-135, :2295-2303 |
| `auto_verify_enabled` | `bool` | 缺省 `false` | :137, :2244 |
| `verify_interval_hours` | `u32` | 缺省 0（= 开着也不自动跑）；上界 8760 | :139, :2247, :248-253 |
| `verify_samples` | `usize` | 默认 3，上界 10 | :141, :168-172, :93 |
| `verify_max_median_ms` | `u64` | 默认 10000，上界 600000 | :143, :174-178, :95 |
| `min_pool_size` | `usize` | 默认 5，合法区间 1–512 | :145, :162-166, :91 |
| `passive_degrade_enabled` | `bool` | 缺省 `false` | :147, :2259 |
| `passive_degrade_min_pool` | `usize` | 缺省 = `min_pool_size` | :149, :180-184 |
| `passive_degrade_first_byte_ms` | `u64` | 默认/下限 15000，上限 120000 | :152, :191-195 |
| `passive_degrade_cooldown_minutes` | `u32` | 默认 15，上限 1440 | :154, :198-202 |
| `session_sticky_enabled` | `bool` | 缺省 `false` | :156, :2280 |
| `session_sticky_min_pool` | `usize` | 默认 10 | :158, :204-208 |

### 5.3 Redis 键（经 `RuntimeState` kv 原语，自动带实例命名空间）

| 键 | 用途 | 出处 |
|---|---|---|
| `opencode_pool:rotation:cursor:<provider_id>` | 轮转游标，TTL 24h | `opencode_rotation.rs:29,38` |
| `opencode_pool:cooldown:<provider_id>:<key_id>` | 冷却标记，TTL = 冷却分钟 | `opencode_rotation.rs:42,194-205` |
| `opencode_pool:last_exit_ip:<provider_id>` | 面板展示「上次锚点」，TTL 24h | `opencode_rotation.rs:81,86-105` |
| `opencode_pool:scan:cursor:<provider_id>` | 扫描分片游标；TTL = `interval × 预期轮数 × 2`，下限 7 天 | `opencode_rotation.rs:107,116-145` |
| `opencode_pool:scan:seen:<provider_id>` | 「本轮已探通」累积集合（JSON 数组），TTL 与扫描游标一致 | `opencode_rotation.rs:147-191` |

`scan:seen` 是**跨切片**的累积集合：候选地址超过单轮上限时一轮扫描会分多次调用，而轮末
「本轮未见即淘汰」必须按**整轮**累积重建——只拿本片结果整表覆盖，会把前面所有切片探到的
节点一起抹掉。集合丢失（TTL 到期 / Redis 抖动）时**故意放弃重建**并记
`opencode_ip_pool_scan_rebuild_skipped` 告警，宁可保留旧候选也不清错。手工删掉这个键是
安全的：只会让当前这一轮跳过重建。

冷却的记账主体在池模型下是**出口 IP**（`mark_opencode_exit_ip_cooldown_for_ip` :226-253 传入
IP 字符串），读取侧 `pick_anchor_ip` 也按 IP 查（:391）。旧「一 key 一 IP」模型下才是 key_id。

### 5.4 环境变量

**只有一个，且现在只是「兜底」而不是唯一入口**：

| 变量 | 默认 | 作用 | 出处 |
|---|---|---|---|
| `OPENCODE_PROBE_MAX_HANDSHAKE_MS` | `600` | 扫描粗筛：往返 > 该值判慢，挡在候选之外。**provider 配了 `opencode_scan.probe_max_handshake_ms` 时以配置为准** | `pool.rs:44-64`；生效值 `effective_probe_max_handshake_ms` :696-703；使用于 :2081-2150 |

> 旧计划文档提到的 `OPENCODE_SCAN_CONNECT_TIMEOUT_SECS`（计划文档 :560）**在仓库里不存在**。
> 探测超时是硬编码常量 `OPENCODE_PROBE_TIMEOUT_SECS = 4`（`pool.rs:26`）。

### 5.5 池键的物化约定

- 出口 IP 写在 **`key.upstream_metadata.opencode_exit_ip`**（`pool.rs:67`、:747-758、:1815）。
- `api_key` 只是逐 IP 唯一的占位值 `public-<ip>`（:65、:1789）；`auth_type` 固定 `api_key`（:63）；
  `api_formats` 固定 `["openai:chat"]`（:61）。上游认证由传输层强制 `Bearer public`
  （`transport/src/opencode.rs:48,252`）。
- DNS pin：`transport/src/opencode.rs:96-163` 生成 `opencode_dns_pin`，`network.rs:162-218` 合并进 profile，
  reqwest 侧在 `execution_runtime/transport.rs:4351-4364` 还原。
- 列表来源：`list_opencode_pool_ips`（`pool.rs:762-817`）优先读 `exit_pool`（`source: "provider"`），
  否则回退扫 key 元数据（`source: "key"`），供旧数据兼容。
- 配置写入是**分段 CAS**（`write_provider_config_section_with` :1600、`write_scan_config` :1677、
  `write_health_config` :1693、`write_pool_config_pair` :1727）：保存接口把两段合在一次 CAS 里，
  避免「新的一段 + 旧的一段」。

---

## 6. 轮转、会话粘性、被动降权

### 6.1 请求路径的三种运行模式

规划阶段逐候选执行（`candidate_ranking.rs:206-333`）：

1. 先无条件应用前置代理域名：`crate::opencode_proxy::apply_front_proxy_domain(...)`（:274-277）。
   `front_proxy_domain` 在「开关关闭 / 未填域名 / 填的就是 `opencode.ai`」三种情况返回 `None`，
   端点 base_url 永不被回写（`opencode_proxy.rs:15-57`）。
2. 生产集合 = `opencode_health.healthy`；为空时回退 `opencode_scan.exit_pool`（:244-263）。
3. 集合为空 → 不锚定，走域名自身 DNS（模式 ②，正常状态）。
4. 集合非空但 `rotation_enabled != true` → **`continue`，该候选被整条跳过**（:283-285）。
   注意这**不是**「不锚定、退回域名直连」——`continue` 跳过的是候选本身，所以「池非空 +
   轮转关闭」时这家供应商等于不提供候选。想要不 pin 而走域名直连，应当清空池，而不是关
   `rotation_enabled`。
5. 集合非空且开启 → `pick_anchor_ip(...)` 选一个 IP 写入候选的 `upstream_metadata.opencode_exit_ip`
   （:286-325）。

| 模式 | 条件 | 锚点来源 |
|---|---|---|
| ① 锚定 | 生产集合非空且 `rotation_enabled = true` | 池内按会话/游标选 |
| ② 直连代理 | 生产集合为空 | 不做 DNS pin，走域名 DNS |
| ③ 候选被跳过 | 池非空但 `rotation_enabled = false` | —（该候选不参与本次请求） |

池空是正常运行模式，不是故障：用户可以主动清空池来选择模式 ②。

**排序是全序**，不存在「并列组」：`compare_candidate_identity_for_ranking` 末尾用 key_id 兜底，
真正决定选哪个 key 的是 planner 层的 `candidates.first()`——只改 scheduler 层排序不会生效。

### 6.2 选点顺序（`opencode_rotation.rs:371-434`）

1. 过滤 `exit_pool_disabled` 与处于冷却的 IP（:381-394）。
2. 可用集合为空 → 回退放行一个**未被手工停用**的（:395-410）。冷却是可自愈的，停用不是；
   回退到 disabled 的第一个等于用一次故障抹掉用户的明确意图，且表面上完全正常（:396-400）。
3. 可用集合只剩一个 → 直接用，不推进游标（:411-417）。
4. 有 `session_key` → `pick_session_anchor`：FNV-1a 哈希 `% len` 取下标（:440-454），同一会话恒定同节点。
5. 无 `session_key` → `next_rotation_cursor`（Redis `GET+DEL` 后写回，**首次写初值 1**，:50-66）
   + `rotate_with_cursor`（:355-361）。
6. 每次选中都写 `opencode_pool:last_exit_ip:<provider_id>`（:83-92），供面板展示。

会话粘性是**两道门**：

- 配置门：`opencode_health.session_sticky_enabled`（缺省 false）。
- 规模门：可用 IP 数 ≥ `session_sticky_min_pool`（缺省 10）。
  实现在 `candidate_ranking.rs:142-185`（`health_session_sticky_active`）与 `pool.rs:216-220`；
  低于门槛时退回游标轮转。

`session_key` 来自客户端亲和性（`candidate_ranking.rs:130-132` 取
`client_session_affinity.session_key`）；opencode 侧会话头在
`client_session_affinity.rs:492-506`（`x-opencode-session-id` / `x-opencode-agent-id`）。

### 6.3 冷却来源一：上游明确限流

- `cooldown_triggered`（`opencode_rotation.rs:182-203`）：`429` 直接命中；`403` 需要错误文案含
  `freetier` / `free tier` / `quota` / `rate limit`（:33-34）；非 opencode 供应商恒为 `false`。
- 冷却时长取 `opencode_scan.cooldown_minutes`，缺省 `DEFAULT_COOLDOWN_MINUTES = 60`（:31、:242-245）。
- 调用点：**流式与同步共用同一个入口**
  `opencode_rotation::mark_opencode_exit_ip_cooldown_for_plan`（`opencode_rotation.rs:321-352`）：
  - 流式：`execution_runtime/stream/execution_failures.rs`（`record_stream_sync_failure` 内）；
  - 同步：`execution_runtime/sync/execution.rs:3009-3016`（非流式重试分支）。

  > 同步路径此前**完全没有**这层钩子，非流式请求的 429/403 失败信号全丢（2026-10 修）。
  > 同步侧只在 429/403 时才序列化响应体：其它状态码连标记函数都会早退，不值得为它付一次序列化。

### 6.4 冷却来源二：被动降权（成功但太慢）

- `mark_opencode_anchor_slow`（`opencode_rotation.rs:292-337`）。
- 只处理 `2xx`（:300-302）；首字节严格大于阈值才降权（:310-312）。
- 阈值与冷却时长都读 `opencode_health` 的**生效值**，不读常量——读常量会让界面上的设置
  看起来生效、实际不生效（:306-309）。
- 池子低于 `passive_degrade_min_pool` 时不降权（:318-320）；已在冷却中不重复写（:322-324）。
- 锚点 IP 从执行计划读：`plan_opencode_exit_ip`（:162-173，读
  `plan.transport_profile.extra.opencode_dns_pin.ip`）。
- 已接的两个调用点：
  - 同步路径 `execution_runtime/sync/execution.rs:2630-2646`；
  - 流式路径 `execution_runtime/stream/execution.rs:2707`；看门狗
    `opencode_stream_degrade_watch` 定义于 :2723-2744，挂载于 :3277 与 :3342，
    粗筛门槛复用常量 `OPENCODE_MIN_DEGRADE_FIRST_BYTE_MS`（:2658）。

### 6.5 规模自适应与相关常量

| 常量 | 值 | 出处 |
|---|---|---|
| `OPENCODE_DEFAULT_MIN_POOL_SIZE` | 5 | `opencode_rotation.rs:261` |
| `OPENCODE_DEFAULT_STICKY_MIN_POOL` | 10 | :263 |
| `OPENCODE_MIN_DEGRADE_FIRST_BYTE_MS` | 15000 | :276 |
| `OPENCODE_MAX_DEGRADE_FIRST_BYTE_MS` | 120000 | :278 |
| `OPENCODE_DEFAULT_DEGRADE_COOLDOWN_MINUTES` | 15 | :280 |
| `OPENCODE_MAX_DEGRADE_COOLDOWN_MINUTES` | 1440 | :282 |
| `OPENCODE_SCAN_MAX_CANDIDATES` | 4096 | `pool.rs:59` |
| `OPENCODE_SCAN_DEFAULT_CONCURRENCY` / `MAX` | 32 / 128 | `pool.rs:55,57` |

`min_pool_size` 是硬下限：复验时 `kept.len() < min_pool_size` 会把人捞回来（`pool.rs:1142-1175`），
`pool_below_floor` / `pool_empty` 由状态接口实时计算（`ip_pool/mod.rs:448-449`）。
自动停用时状态接口回传原因（`disabled_by_operator` 或 `pool_below_min(n<m)`，:326-347）。

---

## 7. 任务与测试覆盖

### 7.1 任务

- worker：`maintenance/runtime/opencode_ip_pool.rs:96-122`，心跳 300s（:29），启动静默 90s（:31），
  单例键 `maintenance.opencode.ip_pool.autoscan`（`task_runtime/mod.rs:51`）。
- 单轮顺序：**先复验、后扫描**（:124-205）——复验便宜且直接决定生产集合。
- 自动扫描条件 `autoscan_due`（:41-46）：`auto_enabled` 且 `interval_hours > 0` 且配了 CIDR 且间隔已过。
- 自动复验条件 `autoverify_due`（:53-72）：`auto_verify_enabled` 且 `verify_interval_hours > 0`，
  且 `candidates ∪ healthy ∪ pinned` 非空，且距**落盘的** `last_verify_at` 已过间隔
  （用内存态会导致每次重启补跑一轮）。
- 扫描分片：按 `opencode_pool:scan:cursor` 切片，单轮上限取
  `opencode_scan.max_candidates_per_round`（默认 4096，切片见 `pool.rs:820-837`）；
  只有**完整走完一轮**（`next_cursor == 0`）时才按「本轮未见即淘汰」重建 `candidates`，
  `pinned` 豁免，而且**必须用整轮累积**（`opencode_pool:scan:seen`，跨切片累加）：只拿本片
  结果整表覆盖会把前面所有切片探到的节点一起抹掉（2026-10 修，见 8.0）。累积集合丢失时
  **故意跳过重建**并记 `opencode_ip_pool_scan_rebuild_skipped`——宁可保留旧候选，也不清错；
  判定集中在 `rebuild_candidates_on_round_completion`（`pool.rs:1441-1464`）。
  **游标 TTL 不再是写死的 24h**，而是按「一整轮扫描」计算
  （`scan_cursor_ttl_seconds` :724-733 = `interval × ceil(候选总数/单轮上限) × 2`，下限 7 天）：
  若 `interval_hours` 大于 TTL，游标每轮都会过期、永远从第 0 个重来，超出单轮上限的
  网段会被静默饿死且 `candidates` 永不重建。探测目标是前置代理域名；目标是官方域名时
  扫描 / 复验 / 清理（`run_open_code_pool_scan_inner`、`run_open_code_pool_verify_inner`、
  `run_open_code_pool_clean_inner`）一律报错拒绝，避免把整池误判为失效。
- 探活阈值：握手往返 > `OPENCODE_PROBE_MAX_HANDSHAKE_MS` 判死（`pool.rs:2012-2023`）；
  复验用 `verify_samples` 次采样的中位数对 `verify_max_median_ms` 判定（:1889-1962、:1864）。
- 扫描 / 复验 / 清理互斥，且都有 `Drop` 兜底复位标志位（:883-888、:1454-1457、:1033）。

### 7.2 相关测试（按文件）

- `crates/aether-provider/transport/src/opencode.rs`：`user_agent_parses_to_opencode_version`(:578)、
  `header_injection_targets_opencode_chat_only`(:585)、
  `header_injection_replaces_existing_user_agent_with_opencode_ua`(:615)、
  `is_opencode_provider_transport_matches_case_insensitively`(:640)；pin 相关 :388-499。
- `crates/aether-provider/transport/src/network.rs`：`resolves_opencode_exit_ip_transport_profile`(:718)、
  `configured_opencode_profile_keeps_exit_pin`(:749)、
  `opencode_profile_without_valid_metadata_cannot_keep_forged_pin_marker`(:784)、
  `non_opencode_profile_cannot_inject_exit_pin_marker`(:806)、
  `invalid_opencode_exit_metadata_does_not_create_profile`(:827)。
- `crates/aether-provider/transport/src/provider_types.rs`：`opencode_is_free_form_and_supports_model_fetch`(:783)、
  `opencode_template_does_not_make_it_a_fixed_provider`(:860)。
- `crates/aether-model-fetch/src/logic.rs`：`opencode_models_fetch_url_uses_zen_v1_path`(:1212)；
  `.../src/transport.rs`：`builds_opencode_models_fetch_plan_with_zen_path_and_anonymous_headers`(:963)。
- `apps/aether-gateway/src/control/route/admin/opencode_ip_pool_routes.rs`：
  `classifies_all_opencode_ip_pool_routes`(:63)、`classifies_provider_level_exit_ip_routes`(:93)、
  `ignores_other_admin_paths_and_methods`(:115)。
- `apps/aether-gateway/src/handlers/admin/provider/ip_pool/mod.rs`：`provider_id_parsing_accepts_action_suffix`(:708)。
- `apps/aether-gateway/src/maintenance/runtime/opencode_ip_pool.rs`：
  `autoscan_requires_switch_and_interval_and_cidrs`(:222)、`autoscan_respects_elapsed_interval`(:230)、
  `autoscan_does_not_fire_before_interval_when_clock_skews`(:244)、`autoverify_requires_switch_and_interval`(:285)、
  `autoverify_respects_the_persisted_interval`(:294)、`autoverify_does_not_refire_on_every_restart`(:305)、
  `autoverify_survives_a_restart_after_the_interval_elapsed`(:315)、
  `autoverify_skips_when_there_is_nothing_to_verify`(:324)、`autoverify_runs_when_only_candidates_exist`(:334)、
  `autoverify_treats_an_unparsable_timestamp_as_never_run`(:345)、
  `a_zero_interval_never_elapses_even_with_an_old_timestamp`(:359)、
  `rfc3339_parsing_accepts_offsets_and_rejects_garbage`(:365)。
- `apps/aether-gateway/src/opencode_pool/pool.rs`（:2438-3265）：CAS 与迁移
  `scan_write_after_verify_write_keeps_the_new_health_section`(:2500)、
  `pool_task_write_preserves_a_concurrent_admin_config_change`(:2546)、
  `scan_section_merge_keeps_user_owned_settings`(:2588)、
  `scan_section_merge_falls_back_to_full_section_when_absent`(:2628)、
  `pool_config_pair_write_keeps_a_concurrent_task_result`(:2648)、
  `pool_config_pair_write_commits_both_sections_together`(:2702)、
  `pool_config_pair_write_rejects_invalid_cidr_without_touching_storage`(:2737)；
  校验 `degrade_first_byte_threshold_rejects_values_below_the_floor`(:2786)、
  `degrade_cooldown_minutes_is_bounded`(:2813)、
  `degrade_accessors_fall_back_to_the_same_defaults_validation_accepts`(:2836)、
  `degrade_times_round_trip_through_the_health_section`(:2859)、
  `health_validation_accepts_the_production_configuration`(:3015)、
  `health_validation_rejects_an_absurd_min_pool_size`(:3029)、
  `health_validation_rejects_negative_and_zero_counts`(:3039)、
  `health_validation_allows_a_zero_verify_interval`(:3059)、
  `health_validation_rejects_wrongly_typed_values`(:3066)、
  `health_validation_caps_verify_samples`(:3080)、
  `scan_validation_rejects_values_that_would_be_truncated`(:3090)、
  `scan_validation_rejects_out_of_range_concurrency_and_cooldown`(:3099)、
  `scan_validation_ignores_fields_it_does_not_own`(:3120)；
  配置往返 `verify_summary_survives_a_config_round_trip`(:3131)、
  `saving_other_settings_preserves_the_verify_summary`(:3163)、
  `a_provider_without_a_health_section_reports_no_verify_summary`(:3188)；
  纯函数 `cidr_parsing_handles_valid_and_invalid_input`(:2892)、
  `candidate_ips_skip_network_broadcast_and_known`(:2918)、`empty_cidr_config_yields_no_candidates`(:2938)、
  `config_reads_opencode_scan_section`(:2945)、`config_reads_bare_section`(:2956)、
  `concurrency_defaults_and_clamps`(:2970)、`pool_key_ip_reads_upstream_metadata`(:2988)、
  `healthy_status_line_recognises_2xx_and_3xx`(:3200)、`status_map_is_per_provider`(:3208)、
  `scan_slice_starts_from_the_cursor_and_wraps_around`(:3217)、
  `scan_slice_recovers_from_an_out_of_range_cursor`(:3234)、`scan_slice_on_empty_candidates_is_a_noop`(:3244)、
  `scan_slice_caps_at_the_per_round_limit`(:3250)。
- `apps/aether-gateway/src/opencode_rotation.rs`（:456 起）：`empty_group_yields_no_exit_ip`(:461)、
  `rotation_visits_every_member_then_wraps`(:466)、`rotation_is_stable_for_large_cursor`(:482)、
  `zero_cursor_selects_first_member`(:491)、`session_anchor_is_stable_for_the_same_session`(:501)、
  `rate_limited_opencode_exit_ip_is_marked_in_cooldown`(:543)、
  `opencode_dns_pin_extra_carries_the_exit_ip`(:606)。
- `apps/aether-gateway/src/opencode_proxy.rs`：`disabled_switch_yields_no_domain`(:69)、
  `enabled_with_domain_yields_that_domain`(:77)、`enabled_without_domain_yields_none`(:85)、
  `official_domain_is_treated_as_disabled`(:90)、`missing_section_yields_none`(:96)。
- `apps/aether-gateway/src/execution_runtime/stream/execution.rs`：
  `opencode_stream_degrade_ignores_chunks_below_threshold`(:16506)、
  `opencode_stream_degrade_fires_just_above_threshold`(:16518)、
  `opencode_stream_degrade_ignores_empty_chunks`(:16531)、
  `opencode_stream_degrade_ignores_errors_and_missing_items`(:16540)、
  `opencode_stream_degrade_threshold_matches_opencode_constant`(:16553)。
- `apps/aether-gateway/src/execution_runtime/transport.rs`：
  `direct_reqwest_cache_key_preserves_opencode_dns_pin`(:6596)。
- `apps/aether-gateway/src/handlers/admin/provider/write/normalize.rs`：
  `normalize_opencode_upstream_metadata_merges_and_validates_exit_ip`(:661)、
  `..._rejects_private_or_unknown_fields`(:680)、`..._can_remove_exit_ip`(:700)。
- `apps/aether-gateway/src/client_session_affinity.rs`：`opencode_adapter_keeps_agent_dimension`(:1473)。
- `crates/aether-ai/formats/src/formats/shared/request.rs`：`forces_streaming_for_opencode_openai_chat`(:245)。
- 前端：仅 `frontend/src/features/api-keys/utils/__tests__/ccswitchImport.spec.ts:124` 提到 opencode；
  `OpenCodeIpPoolPanel.vue` **没有**单元测试。

常用命令：

```sh
cargo test -p aether-gateway --lib opencode
cargo test -p aether-provider-transport --lib opencode
cargo test -p aether-model-fetch --lib opencode
```

> 上表是「源码中存在该测试」的事实清单。本次盘点**未运行**测试，因此无法断言哪些通过。

---

## 8. 已知坑、尚未实现与文档不一致

### 8.0 已经踩过的坑（都别重复踩）

| 坑 | 现象 | 结论 |
|---|---|---|
| admin 前门请求体白名单 | PUT 保存报「请求体不能为空」 | 新增 PUT 路由必须登记到 `handlers/shared/request_utils.rs` 的 `(route_family, method, route_kind)` 白名单 |
| 直连官方域名时仍套 pin | 关掉前置代理开关后整池不可用 | `opencode_dns_pin` 必须在 host 为 `opencode.ai` 时返回 `None` |
| 游标首次不写入 | 游标永远是 0，Redis 键从不创建 | 游标是 `GET+DEL` 后写回，首次取不到旧值时**必须写初值 1**，否则轮转形同虚设 |
| 游标 TTL 短于扫描间隔 | `interval_hours=48` 而 TTL 写死 24h → 每轮都从第 0 个重来，超出单轮上限的网段永远轮不到、`candidates` 永不重建（表现为「后加的网段怎么也扫不到」） | TTL 要覆盖「一整轮扫描」而不是一个 interval；已改为按轮数计算（`scan_cursor_ttl_seconds`，下限 7 天） |
| 多切片轮末重建丢候选 | 候选地址 > 单轮上限时一轮分多次调用；跑完最后一片时用**本片**结果整表覆盖 `candidates`，把前面所有切片探到的节点一起抹掉（表现为候选忽多忽少、后段网段的发现总丢） | 轮末重建必须用**跨切片累积**（`opencode_pool:scan:seen`）；累积集合丢失时宁可跳过重建也不清错。根因是 `seen` 曾是本片局部变量，2026-10 修 |
| 同步路径没有 IP 冷却 | 非流式请求撞上 429/403 后，出口 IP 不进冷却、下一次照样选它 | 冷却打标要放在**两条路径共用的入口**（`mark_opencode_exit_ip_cooldown_for_plan`），别在流式里就地实现；2026-10 修 |
| 阈值与并发分开调 | 并发从 1 调到 32 后原本能通过的节点被 600ms 快筛全砍（实测 p50 从 ~670ms 抬到 ~2.6s，通过率 9/40 → 0/40） | 两者在同一个 `opencode_scan` 段里一起调；阈值已开放为 provider 级配置 |
| 排序是全序 | 误以为存在「并列组」 | `compare_candidate_identity_for_ranking` 末尾用 key_id 兜底，不存在并列 |
| 只改 scheduler 层不生效 | 排序结果被 planner 覆盖 | planner 会二次排序，真正决定选谁的是 `candidates.first()` |
| 域名不持久化 | 开关一关，填过的域名消失 | 域名写入 `opencode_scan.proxy_domain`，与端点 host 分离存储 |
| 池非空 + 轮转关闭 | 该供应商请求全部失败 | `continue` 跳过候选（见 6.1 模式 ③），不是退回直连 |

### 8.1 尚未实现 / 与代码不一致（请勿按已实现描述）

1. **`pick_min_inflight_group` 不存在**。`opencode_rotation.rs:11` 的模块注释引用了这个纯函数，
   但全仓库只有这一处提及。实际选点是 `pick_anchor_ip`(:371) + `pick_session_anchor`(:440)
   + `rotate_with_cursor`(:355)；注释里描述的「最少在途（least in-flight）」分组逻辑没有实现。
2. **`OPENCODE_SCAN_CONNECT_TIMEOUT_SECS` 不存在**（仅出现在计划文档 :560）。
   唯一支持的环境变量是 `OPENCODE_PROBE_MAX_HANDSHAKE_MS`（`pool.rs:45`）。
3. **`healthy_prev` 只写不读**：`pool.rs:1179-1183` 与迁移 :2426 会填它，读取器 :2224 也认它，
   但 `to_provider_config_value`(:2382-2406) **不输出**该键，因此一次 `opencode_health` 段写入
   就会丢掉它；状态接口也只暴露 `healthy_prev_count`（`ip_pool/mod.rs:425`、`keys.ts:85`）。
   所谓「UI 一键回滚上一版健康池」**没有实现**（面板里没有回滚控件）。
4. **手工加 IP 不会写 `pinned`**：`add_exit_ip`（`ip_pool/mod.rs:125-148`）只 push 到 `exit_pool`，
   既不写 `candidates` 也不写 `pinned`。计划文档 :249 的「手工加 IP = 写 candidates + 标记 pinned」
   与代码不符；`pinned` 目前只有读取方，没有写入方。前端 `OpenCodeIpPoolPanel.vue:573,936,952`
   会渲染 `pinned` 徽标，但没有任何界面动作能设置它。
5. **端点 base_url 并未锁定**：早期设计文档曾称「opencode 端点的 Base URL 锁定，唯一入口是
   前置代理池开关」，与 `provider_types.rs:292`（`fixed_provider: false`）和
   `EndpointFormDialog.vue:1915`（对 opencode 返回 `false`）矛盾。该设计文档已并入本文并删除，
   结论留在这里以免再被当成事实。
6. **超大池自适应样本数未实现**：计划文档 :239-242 的 `clamp(pool/20, 3, 10)` 没有对应代码；
   `verify_samples` 直接取配置，默认 3（`pool.rs:168-172`）。
7. **注释/常量级的陈旧项**：
   - `frontend/src/features/providers/components/OpenCodeIpPoolPanel.vue:849` 注释写
     `opencode_rotation::pick_opencode_exit_ip`，实际函数名是 `plan_opencode_exit_ip`（:162）。
   - `crates/aether-provider/transport/src/opencode.rs:34,38,41`（`OPENCODE_BASE_URL`、
     `OPENCODE_CHAT_PATH`、`OPENCODE_MIN_CLIENT_VERSION`）经 `lib.rs:132-133` 导出，
     但仓库内没有其它消费者；不排除外部使用。
8. **未确认项**：本次盘点没有读 `pool.rs:1515-1600`（清理任务的 provider 池分支）与
   `verify_ips`/`probe_*` 的完整实现细节，故本文不描述清理的具体判定阈值来源。
   另外「池空不告警」的说法（计划文档 :77-78）未逐条核对日志语句，本文不做断言。

---

## 9. 事实来源清单

本文每一节的内容分别提炼自下列文件（括号内为主要使用的行区间）。**行号会随改动漂移**：
凡能用函数名 / 常量名定位的，这里优先用名字；只有确实需要精确位置时才写行号（属于
2026-10 快照）。

| 文件 | 提取的事实 |
|---|---|
| `crates/aether-provider/transport/src/opencode.rs` | 类型常量（:31）、base URL 常量（:34,36,38,41）、UA/头注入（:165-263）、free-tier 工具（:265-321）、exit-IP 读取与 DNS pin（:67-163） |
| `crates/aether-provider/transport/src/lib.rs` | 再导出清单（:127-133） |
| `crates/aether-provider/transport/src/provider_types.rs` | runtime policy（:289-301）、域名/URL/路径常量（:531-541）、固定端点模板（:556-569）、分派（:604,626）、测试（:783,860） |
| `crates/aether-provider/transport/src/network.rs` | pin 合并进 transport profile（:162-218）、pin 测试（:718-832） |
| `crates/aether-model-fetch/src/logic.rs` | `/zen/v1/models` URL 构造（:888-894）与分派（:89-90）、测试（:1212） |
| `crates/aether-model-fetch/src/transport.rs` | 模型列表匿名请求头（:129-165）、测试（:963） |
| `apps/aether-gateway/src/handlers/admin/provider/write/normalize.rs` | 类型白名单（:7-33）、`upstream_metadata` 校验（:65-103）、测试（:661-706） |
| `apps/aether-gateway/src/handlers/admin/provider/write/provider/{create,update}.rs` | 校验调用点（:40 / :62） |
| `apps/aether-gateway/src/handlers/admin/provider/write/keys/{create,update}.rs` | `upstream_metadata` 归一化调用点（:53 / :383） |
| `apps/aether-gateway/src/control/route/admin/opencode_ip_pool_routes.rs` | 10 条路由的 method/path/route_kind/scope（全文） |
| `apps/aether-gateway/src/control/route/admin.rs` | 路由表挂载（:83-84） |
| `apps/aether-gateway/src/handlers/admin/provider/routes.rs` | HTTP 分发（:17-25） |
| `apps/aether-gateway/src/handlers/admin/provider/ip_pool/mod.rs` | 状态响应字段（:302-451）、保存与 400/409（:454-559）、三条长任务的 202 语义（:561-663）、恢复官方域名（:665-701）、池 IP 增删改启停（:109-266）、id 解析（:259-266）、测试（:708） |
| `apps/aether-gateway/src/opencode_pool/mod.rs` | 分层与架构守卫原因（:1-29） |
| `apps/aether-gateway/src/opencode_pool/pool.rs` | 探测与扫描常量；`OpenCodeScanConfig` / `OpenCodeHealthConfig`（字段、读取、合并、校验、生效值、`scan_cursor_ttl_seconds`）；`rebuild_candidates_on_round_completion`（轮末重建裁决）；`run_open_code_pool_scan_inner`、`run_claimed_open_code_pool_verify`、`run_open_code_pool_clean_inner`；`probe_ips` / `probe_upstream_ip*`；`write_scan_config` / `write_health_config`；`candidate_ips` / `scan_slice` / `parse_cidr`；`list_opencode_pool_ips`；状态映射；`mod tests` 与文件尾部测试 |
| `apps/aether-gateway/src/opencode_rotation.rs` | Redis 键构造函数与轮转/扫描状标（`next_rotation_cursor`、`read_scan_cursor` / `write_scan_cursor`、`read_scan_seen` / `write_scan_seen` / `clear_scan_seen`）；冷却判定与记账（`cooldown_triggered`、`mark_key_cooldown`、`mark_opencode_exit_ip_cooldown*`，含两条路径共用的 `..._for_plan`）；常量；被动降权 `mark_opencode_anchor_slow`；选点与粘性（`pick_anchor_ip` / `pick_session_anchor` / `rotate_with_cursor`）；`mod tests` |
| `apps/aether-gateway/src/opencode_proxy.rs` | 前置代理 host 改写与三条返回 `None` 的条件（:15-57）、测试（:59-100） |
| `apps/aether-gateway/src/maintenance/runtime/opencode_ip_pool.rs` | worker 心跳与静默（:29-31）、单例启动（:96-122）、扫描/复验到期判定（:40-94）、单轮顺序（:124-205）、测试（:207-386） |
| `apps/aether-gateway/src/maintenance/{mod.rs,runtime.rs}`、`src/state/core.rs`、`src/task_runtime/mod.rs`、`src/lib.rs` | 模块声明、worker 启动与单例键（:15-18 / :23-24,84-85 / :67,2371 / :51 / :66-68） |
| `apps/aether-gateway/src/ai_serving/planner/candidate_ranking.rs` | 排序后置钩子（:124-135）、粘性规模门（:142-185）、池轮转与锚点注入全流程（:197-335） |
| `apps/aether-gateway/src/client_session_affinity.rs` | opencode 会话头与 client_family（:492-506） |
| `apps/aether-gateway/src/execution_runtime/sync/execution.rs` | 同步路径被动降权调用点；非流式重试分支的 IP 冷却打标（`mark_opencode_exit_ip_cooldown_for_plan`，2026-10 新增） |
| `apps/aether-gateway/src/execution_runtime/stream/execution.rs` | 流式看门狗与降权调用点（:2642-2744, :3277, :3342）、测试（:16506-16577） |
| `apps/aether-gateway/src/execution_runtime/stream/execution_failures.rs` | 失败路径（`record_stream_sync_failure`）；IP 冷却打标已上移到 `opencode_rotation::mark_opencode_exit_ip_cooldown_for_plan`，两条路径共用 |
| `apps/aether-gateway/src/execution_runtime/transport.rs` | reqwest DNS pin 落地（:4333-4364）、测试（:6596） |
| `apps/aether-gateway/src/handlers/shared/request_utils.rs` | 请求体白名单（:327-352） |
| `apps/aether-gateway/src/control/management_token_permissions.rs` | 权限组与 key 映射（:105-112, :664-667, :754-756） |
| `apps/aether-gateway/src/control/route/admin/amd_load_routes.rs` | 与 opencode 的 id 长度差异（:12-13,70,98-101） |
| `frontend/src/api/endpoints/types/provider.ts` | `ProviderType` 联合（:800） |
| `frontend/src/api/endpoints/keys.ts` | 响应/请求负载类型（:60-152）、6 个池接口（:154-226）、池 IP CRUD（:627-662） |
| `frontend/src/features/providers/components/OpenCodeIpPoolPanel.vue` | 面板结构、保存负载（:1248-1304）、加/改/启停/删 IP（:1490-1600）、分页缓存键（:742） |
| `frontend/src/features/providers/components/ProviderDetailDrawer.vue` | 面板挂载条件（:72-77, :1111） |
| `frontend/src/features/providers/components/EndpointFormDialog.vue` | `isFixedProvider` 对 opencode 为例外（:1910-1923） |
| `frontend/src/features/providers/components/ProviderFormDialog.vue` | 类型下拉选项（:81, :127） |
| `frontend/src/features/providers/utils/providerTypeUtils.ts` | 类型判定与默认域名常量（:29-39） |
| 原 `docs/operations/opencode-exit-pool-plan.md`、原 `opencode-ip-pool-rebuild-plan.md`、`docs/operations/MAINTENANCE.md` | **仅用于比对哪些表述已过期**（第 8 节）；本文行为描述不取自这几份文档 |

### 文档沿革

本文件由两份计划文档合并而来，原文已被本文取代并删除：

- 原 `docs/operations/opencode-ip-pool-rebuild-plan.md` → 改名为本文件。
  其计划内容中「`handlers/.../ip_pool/pool.rs` 文件路径」「`OPENCODE_SCAN_CONNECT_TIMEOUT_SECS`
  环境变量」「超大池样本数 `clamp(pool/20,3,10)`」「手工加 IP = 写 candidates + 标记 pinned」
  「UI 一键回滚上一版健康池」均已核对为**与代码不符**，见第 3、5.4、7.1、8.1 节。
- 原 `docs/operations/opencode-exit-pool-plan.md` → 已并入本文件的第 0 节（为什么需要）与
  第 8.0 节（已经踩过的坑），原文件删除。其中「端点 Base URL 锁定」一条与代码矛盾，
  已在 8.1 第 5 条纠正。

`docs/operations/MAINTENANCE.md` 是分支维护手册（不是本功能的说明），其测试文件名与路径
按本文第 7 节校正。

### 2026-10 变更记录

- **扫描轮末重建**：修复「多切片轮末用本片结果整表覆盖候选」的缺陷。新增 Redis 键
  `opencode_pool:scan:seen:<provider_id>` 做跨切片累积；累积集合丢失时**跳过**重建并告警
  （`rebuild_candidates_on_round_completion`）。见 §5.3、§7.1、§8.0。
- **扫描游标 TTL**：不再写死 24h，改为 `scan_cursor_ttl_seconds`（`interval × 轮数 × 2`，下限 7 天）。
- **IP 冷却打标**：上移为两条路径共用的 `mark_opencode_exit_ip_cooldown_for_plan`；同步（非流式）
  路径此前**完全缺失**这层钩子，本次补齐。见 §6.3。
- **新增 `opencode_scan` 可调项**：`probe_max_handshake_ms`（100–60000）、
  `max_candidates_per_round`（1–65536）；状态接口多回传 `probe_max_handshake_source`。见 §5.1、§5.4。
