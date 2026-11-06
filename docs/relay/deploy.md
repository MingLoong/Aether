# relay 接线、联调与发版

> 服务侧接口实现见 [contract.md](contract.md)，回执协议见 [echo.md](echo.md)。
> 本文覆盖：在 AE 里注册配置（C）、联调验收（D）、部署与回滚约束、离线安装包。

---

## C. 在 AE 中注册与配置（接线步骤）

服务跑起来后，还需要在 AE 侧登记成 relay 供应商。以下字段是**必须**的，缺一个就不通。

### C.1 建供应商

AE 面板「添加提供商」→ 选 **「自定义透传」（relay）**，命名，保存。
（后端 `provider_type` 支持列表在 `normalize.rs` 的 `SUPPORTED_PROVIDER_TYPES`；
前端下拉在 `ProviderFormDialog.vue`。两者都须含 `relay`，否则下拉里看不到。）

### C.2 加端点（核心）

| 字段 | 值 | 说明 |
|---|---|---|
| `api_format` | `openai:chat` | 决定请求/响应翻译格式 |
| `base_url` | `http://<host>:<port>/v1` | **带 `/v1`**；面板源站会去掉该后缀（见 contract.md B.2） |
| `custom_path` | 留空 | relay 用 base_url 原样透传 |
| `enabled` | `true` | — |

生产实据（154）：`provider_type=relay`、`api_format=openai:chat`、
`base_url=http://127.0.0.1:8000/v1`。

### C.3 登记模型

在 `models` 表（或面板「模型」页）为该供应商登记它支持的模型名（`provider_model_name`）。
AE 会把请求体里的 `model` 与登记名比对后路由；**没登记的模型请求会 404/400**。

### C.4 配置上游 API Key

在供应商/端点鉴权配置里填你的服务要的 key（`sk-your-upstream-key`）。
AE 会用它在转发时替换客户端发来的 `Authorization`（见 contract.md A.2）。

### C.5 providers.config 配置项（自由 JSON，未登记的 key 会被静默忽略）

| key（路径） | 类型 | 默认 | 说明 |
|---|---|---|---|
| `max_transfer_timeout_seconds` | number | 网关默认超时 | relay 透传的最长传输时间。**长流式响应必须调大**（生产用 600） |
| `provider_ops.console_shared_secret` | string | 无 | 面板直通的 HMAC 共享密钥（见 contract.md B.3/B.4）。**没有它就没有「打开控制台」入口** |
| `provider_ops.console_base_url` | string | 端点 `base_url` 去 `/v1` | 面板源站地址；面板与 API 不同地址/端口时填这里 |
| `relay_echo.enabled` | bool | 按 `request_record_level` | 是否注入 `X-Aether-Echo`；`full` 时自动带上 body 控制头 |
| `relay_echo.trust` | bool | `false` | 是否接受上游回执（防伪造），默认关闭 |
| `relay_echo.max_bytes` | number | 8192 | 回执头大小上限 |

> 这些 key 必须在 `providers.config` 里，拼错不会报错，只会「没生效」——改完务必实测。

### C.6 安全：面板端口不要对外

面板与 `/v1` 同进程时，`-port` 只绑回环（如 `127.0.0.1:8000`），让 AE 反代和本机访问，
**不要**绑 `0.0.0.0` 暴露公网，否则等于绕过 AE 直连管理面板。若必须同端口对外，至少确保
面板登录密码足够强、且不响应外部直连（用防火墙只放行 AE 所在主机）。

---

## D. 联调与验收（改完必跑）

原则只有一条：**验收只认“实际发出去的字节 + 落库结果”，不认“代码看起来对”。**

### D.1 四级验证阶梯

| 级别 | 做什么 | 能证明什么 | 不能证明什么 |
|---|---|---|---|
| 1. 单测 | Go `go test ./internal/relayecho ./internal/upstream ./internal/server` | 编解码、脱敏、裁剪、控制头剥离逻辑正确 | 头有没有真的发出去 |
| 2. 直连探针 | 直接打 relay，带 `X-Aether-Echo: 1`，看响应头 | relay 实现了回执 | AE 有没有注入/保留 |
| 3. 抓包 | `tcpdump -i lo -A -n "tcp port <relay_port>"` | 请求里到底有没有控制头、响应里到底有没有回执头 | 落库对不对 |
| 4. 落库 | 查 `usage_http_audits` | 端到端结果与来源标记 | — |

> **第 3 级不能省。** 曾出现“计划里有 echo 头、发出去却没有”，只做 1、2、4 会一直
> 在 `local` 上打转。

### D.2 一键验收脚本

```bash
# 需要：一个可用的 AE API Key；可选 PSQL_URL 做落库断言
AETHER_BASE_URL=http://127.0.0.1:8084 \
AETHER_API_KEY=sk-aether-xxx \
RELAY_MODEL=hy3 \
PSQL_URL='postgresql://aether:${AETHER_DB_PASSWORD}@127.0.0.1:5432/aether' \
  bash scripts/relay-conformance.sh
```

脚本依次断言：请求 `200` → 响应头里**没有**回执头泄漏 → 落库
`provider_headers_source = upstream_echo` 且头表非空。任一失败即非零退出并打印定位提示。

### D.3 抓包判据

请求方向（AE → relay）必须看到：

```
x-aether-echo: 1
x-aether-trace-id: <uuid>
```

响应方向（relay → AE）必须看到：

```
X-Aether-Provider-Request-Headers: eJ...
```

同时，**relay → 真实上游**的请求里不得出现任何 `x-aether-*`。

### D.4 故障定位表

| 现象 | 最可能原因 | 怎么确认 |
|---|---|---|
| 刚发完请求查库是 `NULL` | 审计行异步落库 | 等 5–10 秒再查 |
| 稳定 `local`，抓包请求里无 `x-aether-echo` | AE 没注入，或被请求头过滤链拦掉 | 查计划构造器是否覆盖该执行路径；查 `should_skip_request_header` / `should_skip_upstream_passthrough_header` |
| 请求有控制头、响应无回执头 | relay 未实现，或 AE 响应头过滤把 `x-aether-*` 丢了 | 查 `should_skip_response_header` 是否放行 `x-aether-provider-request-headers` |
| 响应有回执头但仍 `local` | payload 校验失败（`v`、`trace_id`、空 headers、内嵌控制头） | 解码回执串逐字段比对 |
| 回执头很大 / `truncated=true` | 触发 8 KB 裁剪 | 正常现象；关注是否有必需头被丢 |
| relay 返回 5xx / 502 | relay 进程挂了或端口不通 | relay 服务日志 + `/health` |
| **Tokens 全空、请求体显示「正文暂不可用」、记录只剩请求头/请求体/元数据三块** | **审计 upsert 的 bind 数与 SQL 占位符数不一致**，整条审计写入报错，terminal usage 事务回滚，只剩 first-byte 的部分记录 | 数 `upsert_usage_http_audit_sql.sql` 的列数与 `$N` 最大值是否相等；单测 `single_row_audit_sql_column_and_placeholder_counts_match` |

### D.5 证据留档

每个改动在 PR / 交付说明里贴三样东西，缺一不可：

1. 抓包片段（请求控制头 + 响应回执头各一行）；
2. 落库 SQL 结果（`provider_headers_source` 与头表存在性）；
3. CI 结论（Rust CI + Relay Build / Go `go test`）。

### D.6 部署与回滚约束（迁移是单向门）

**结论：一旦新版本带了数据库迁移，就不能再回滚到不含该迁移的旧二进制。**

sqlx 迁移在启动时做版本预检：DB 的 `_sqlx_migrations` 里存在、而当前二进制内嵌的迁移集合里没有的版本，会直接触发

```
Error: VersionMissing(20261104000000)
```

进程 `exit 1`，systemd 反复重启 → 「readyz 空 + 端口不监听」的假死循环，重启计数会持续上涨。这**不是崩溃**，是版本对不上。

#### 上线前必做

1. 确认本次改动是否新增迁移：`git diff <上次部署 sha>..HEAD --stat -- '*migrations*'`。
2. 若新增，**明确记录本次发布是不可回滚点**；旧 release 留在磁盘仅供取证，不要再启动。
3. 首次启动盯 `systemctl status` 与 `journalctl -u aether-gateway` 的迁移日志，确认 `VersionMissing` 不出现。

#### 回滚策略（按优先级）

| 情况 | 做法 |
|---|---|
| 新版本有功能 bug、但仍需保留迁移 | **向前修复**：改代码重新构建部署；不要切回旧 release |
| 迁移本身是错的（如多加了一列） | **追加补偿迁移**（如 `20261104000001_drop_provider_body_source.sql`）走正常发布；不要手改 DB |
| 极端情况必须回到旧二进制 | 只能先手工处理 `_sqlx_migrations`（删行）+ 执行反向 DDL，属高危操作，需单独评审并留档 |

#### 已验证案例（2026-11-04）

`bc95e6e9e` 引入 `20261104000000`（加 `provider_body_source`）→ 回滚到 `98b53cf37`（无该迁移）→ 触发 `VersionMissing` 无限重启。正确处置是把 `current` 指回含该迁移的版本，之后再追加 `20261104000001` 把多余的列删掉。

#### 顺带教训：加列时必须同步的位置

`provider_body_source` 那次故障的根因不是迁移，而是**只改了 bind 没改 SQL**：

| 位置 | 是否必须同步 |
|---|---|
| `queries/upsert_usage_http_audit_sql.sql` 列清单 + `$N` 占位符 | ✅ 单行 upsert 路径 |
| `mod.rs` 批量 `INSERT` 的列清单 + `push_bind` + `ON CONFLICT` | ✅ 批量路径 |
| `UsageHttpAuditHeaders` / `PreparedUsageUpsert` 结构体与字面量 | ✅ 编译期会报 |
| `metadata_policy.rs` 白名单 | 仅当需要投影到 `request_metadata` |

单行 SQL 的 bind 数是**运行期**错误，编译期查不出来 —— 依赖单测兜底。

---

## E. 离线安装包

内置二进制、前端静态资源、systemd 单元与安装脚本，无需联网即可安装。
包内自带同名 README（`deploy/relay/README.md`），随 tarball 分发；以下是速查。

| 项 | 值 |
|---|---|
| 安装目录 | `/opt/aether`（`PREFIX=` 可改），`releases/<版本>/` + `current` 软链 |
| 配置文件 | `/etc/aether/aether-gateway.env`（升级保留） |
| 服务名 | `aether-gateway` |

```bash
tar -xzf aether-gateway-<版本>-linux-amd64.tar.gz
cd aether-gateway-<版本>-linux-amd64
sudo ./install.sh                 # 安装并启动；--no-start 只装不启
sudo ./uninstall.sh               # 删服务与程序，保留 /etc/aether；--purge 连配置删
sha256sum -c SHA256SUMS           # 校验
systemctl status aether-gateway   # 运行状态
journalctl -u aether-gateway -f
curl -s localhost:8084/_gateway/health
```

首次安装会自动生成 `JWT_SECRET_KEY`、`ENCRYPTION_KEY` 和初始管理员密码并打印出来。
**安装前请先确认配置里的 `AETHER_DATABASE_URL` 指向可用的 PostgreSQL。**

> 版本号由仓库根 `VERSION` 文件（或 git tag）决定，安装包名与二进制内版本始终一致。

---

## 快速自检清单（改完必须逐条核对）

1. `POST /v1/chat/completions` 支持 `stream:true` 返回 SSE，`data: [DONE]` 结尾
2. 响应带 `usage`；429 带 `Retry-After`
3. `/console-sso` 按 contract.md B.4 验签：正确→302+session，错误→401，重放→401，空密钥→404
4. 无任何绝对根路径链接/跳转
5. 带 `X-Console-Base` 时返回 `body class="embedded"`，header 隐藏
6. 520px iframe 下无横向溢出、按钮/输入整宽、表格横向滚动而非压扁
7. 面板 HTML 返回 `Cache-Control: no-store`
8. 两侧密钥掩码一致；保存 Go 侧密钥后下次 SSO 即用新值（无需重启）
9. AE 端点 `base_url` 带 `/v1`、`api_format=openai:chat`、模型已登记、上游 key 已配
10. 长流式已把 `max_transfer_timeout_seconds` 调大（如 600）
11. 面板端口只绑回环，未对公网暴露
12. 带 `X-Aether-Echo: 1` 时返回 `X-Aether-Provider-Request-Headers`，且 payload 的 `trace_id` 等于请求头
13. 回执头里的 `authorization` / `cookie` 等已脱敏，且不含 `x-aether-echo`、`x-aether-trace-id`
14. 发往真实上游的请求**不含**任何 `x-aether-*`（抓包确认）
15. `usage_http_audits.provider_headers_source = upstream_echo`，`scripts/relay-conformance.sh` 全绿
16. `provider_request_body` 落库内容与 relay 实际发往上游的 body 逐字节一致（含 relay 注入的 `stream_options` / `prompt_cache_key`）
17. `usage.total_tokens` 非空且 `usage_body_blobs` 中存在 `provider_request_body`（缺任一即为审计写入失败，见 D.6）
18. 本次发布是否新增迁移已确认；若新增，已在交付说明里标注「不可回滚点」
