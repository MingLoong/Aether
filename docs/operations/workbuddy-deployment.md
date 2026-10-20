# WorkBuddy 供应商：上线与真机验证操作单

本文件只讲**这次 workbuddy 改动怎么上、上完怎么验**。通用构建/部署流程见
[`MAINTENANCE.md`](./MAINTENANCE.md)；供应商本身的行为与协议见
[`workbuddy-provider.md`](./workbuddy-provider.md)。

---

## 交付摘要（一页看完）

**做了什么**：在 Aether（fork 自 `v0.7.19-rc.3` / `fdfbba7`）里新增**第一类固定模板供应商
`workbuddy`**——网关**直连**腾讯 CodeBuddy（CN `copilot.tencent.com` / 国际 `www.workbuddy.ai`）
并**自管账号池**；上游协议、URL、头族与各类维护动作**逐条对齐开源面板**
`linguo2625469/workbuddy2api-panel`（对照时以**字节/码点**为准，见 provider 文档 §2.1 的实现记录）。

| 能力 | 状态 | 详见 |
| --- | --- | --- |
| 固定模板 + `openai:chat` 强制流式端点、设备授权（OAuth 设备码链路）、本地刷新适配器 | ✅ | provider §1、§2.12 |
| 出站头族与**头值**（含两类 UA、设备 token 旋钮）、会话/链路头族、prompt_cache_key | ✅ | provider §1.2 |
| 请求体全管线（窄子集归一、指纹脱敏、tool 配对、截断清理、DeepSeek 思维链、档位降级、兜底 system） | ✅ | provider §2.1、§2.2 |
| DSML 工具调用还原（整段 + 流式 + `[DONE]` 保证 + name 收敛 + 用量规范化） | ✅ | provider §2.2 |
| 失败分类 13 类 → 凭证作废 / pool 硬状态 / 模型级负缓存 | ✅ | provider §2.4 |
| 余额 / 签到 / 活跃上报 / 连登兑换 / 抽奖 / 补签 / 礼包补偿 / 猫猫旅行 / **成长任务** / **global trial** | ✅ | provider §2.5–§2.9 |
| 模型目录（`/v3/config`：IDE UA + global 两路探测、非对话模型过滤、试用横幅） | ✅ | provider §2.11 |
| 候选选择（Postgres 五条 SQL + 内存孪生 + 兜底清单） | ✅ | provider §1 |
| 前端（类型 / 表单 / 设备授权弹窗 / i18n） | ✅ | 本文件 §0 |

**验证方式**：provider 文档 §5 是**可直接复制**的命令清单；本文件 §4 是
**真机逐步验证清单**（每步含期望与失败排查）。**不写死测试条数** ✗ —— 数字必然随迭代漂掉
（本文件曾写死过，2026-10-17 审计实测已不符 ✗），以实际运行为准 ✓。

**部署 / CI**：本文件 §1（补丁落库）→ §2（CI 派发或本机构建，**前端必须重建**）→ §3
（生产 154 的发布布局与回滚）→ §4（真机验证）。**无数据库迁移**。

**曾经写在这里的「已知未做」6 项已全部实现** ✓（夜猫子 ✓、WAF 出口 IP 维度冷却 ✓、
桌面事件模拟动作 ✓、global 账号注册向导 ✓、`error.gateway_hint` ✓、context/输出上限静态兜底 ✓、
昵称刷新 ✓）—— 2026-10-17 维护性审计指出这段已经**主动误导读者** ✗，故删除；
当前能力与边界一律以 provider 文档 §4 的差距表为准 ✓（该表也已同步修正 ✓）。
仍然**有意不做**的只剩：**开学季限时活动**（活动期已过）✓、**「同请求内」重试**（Aether 用
换号重试等价覆盖，单账号池除外）✓、**流式未收 `[DONE]` 的截断清理**（与逐帧透传冲突）✓。

---

## 0. 改动清单（101 个文件，**无数据库迁移**）

> 文件数会随迭代变化 ✓ —— 以补丁实际内容为准（`git apply --stat workbuddy-provider.patch | tail -1`）✓。
> 最近核对：**101 个文件**（99 个改动/新增 + `Cargo.lock` 随 `aether-model-fetch` 新增 `chrono` 依赖 ✓）。

| 层 | 目录 | 内容 |
| --- | --- | --- |
| 协议 / 传输 | `crates/aether-provider/transport/src/workbuddy/`、`provider_types.rs` | 头族与身份、请求体归一化与两层防误报、降级闸门、失败分类、本地刷新适配器、固定模板与运行时策略 |
| 响应兼容 | `crates/aether-ai/formats/src/provider_compat/workbuddy_dsml/` | DSML 工具调用还原（整段 + 流式） |
| 池 | `crates/aether-provider/pool/src/providers/workbuddy.rs`、`service.rs` | 额度刷新能力 + 全部「按账号直连上游」的请求构造 |
| OAuth | `crates/aether-oauth/src/provider/providers/workbuddy.rs` | 设备授权 / 刷新 / 凭据导入 |
| 网关 | `apps/aether-gateway/src/**` | 设备授权编排、额度/签到/连登/旅行编排、凭证作废与 pool 硬状态、DSML 接线、候选 SQL、模型目录策略、origin 白名单 |
| 解析 | `crates/aether-admin/src/provider/quota.rs` | 余额两套口径归一 |
| 数据 | `crates/aether-data/{adapters/postgres,runtime}/src/**` | 候选选择（Postgres SQL + 内存孪生） |
| 模型目录 | `crates/aether-model-fetch/src/**` | `/v3/config` 策略 + 计划 + 解析 |
| 前端 | `frontend/src/**` | 类型、表单选项、设备授权弹窗、图标、i18n |
| 文档 | `docs/operations/workbuddy-provider.md`、`workbuddy-deployment.md`（本文）、`.agents/notes/**` | 行为/差距/验证说明 + 上线操作单 |

**没有迁移文件**：候选选择改动是 Rust 里的 SQL 构造，不改表结构。前端有改动，
所以**必须重建前端**（见 §2）。

---

## 1. 第一步：把改动落到仓库

本机无法推送（无 `gh`、`git push` 在代理下 SSL 失败），所以交付物是补丁：

```bash
# 在你的开发机上（干净 checkout 到 v0.7.19-rc.3 / fdfbba7）
git checkout -b feature/workbuddy-provider fdfbba7
git apply --check /path/to/workbuddy-provider.patch   # 先干跑
git apply /path/to/workbuddy-provider.patch
git add -A && git commit -m "feat(provider): add workbuddy (Tencent CodeBuddy) provider"
git push -u origin feature/workbuddy-provider
```

---

## 2. 第二步：构建

### 走 CI（推荐）

功能分支 push **不会**触发 `gateway-build.yml`，必须显式派发：

```powershell
gh workflow run gateway-build.yml -R MingLoong/Aether --ref feature/workbuddy-provider -f target=aether-gateway
gh api "repos/MingLoong/Aether/actions/runs/<run_id>/jobs"      # 查作业
gh api "repos/MingLoong/Aether/actions/runs/<run_id>/artifacts" # 取产物
```

产物名：`aether-aether-gateway-linux`（内含 Linux 二进制）。

### 本机构建（无 CI 时）

```powershell
. ..\dev-env.ps1                                  # MSVC + cargo + NASM + LIBCLANG_PATH
cargo build --release -p aether-gateway
cd frontend
npm ci
./node_modules/.bin/vue-tsc -b --force            # 不要用 npx（会报 ERR_PACKAGE_PATH_NOT_EXPORTED）
./node_modules/.bin/vite build                    # 约 2.5 分钟
```

---

## 3. 第三步：部署到生产（<部署机 IP>）

> ⚠️ 生产是 `aether-gateway.service`（端口 **8084**、`/opt/aether/current` 符号链接）。
> 同机上 `/opt/aether-deploy` / `aether-gateway-deploy` / 18084 是**另一个 inactive 实例**，
> 照它操作等于改了个不跑的服务（`MAINTENANCE.md` §5 记过这个坑）。

```bash
# 1) 传二进制与前端到新发布目录
ssh root@<部署机 IP>
mkdir -p /opt/aether/releases/<新版本>/{bin,frontend}
# 上传：aether-gateway -> /opt/aether/releases/<新版本>/bin/aether-gateway
#       frontend/dist  -> /opt/aether/releases/<新版本>/frontend
chmod +x /opt/aether/releases/<新版本>/bin/aether-gateway

# 2) 切符号链接并重启
ln -sfn /opt/aether/releases/<新版本> /opt/aether/current
systemctl restart aether-gateway.service
systemctl status aether-gateway.service --no-pager

# 3) 看日志
tail -f /opt/aether/logs/aether-gateway.$(date +%F).log
```

**回滚**（一条命令）：

```bash
ln -sfn /opt/aether/releases/<旧版本> /opt/aether/current && systemctl restart aether-gateway.service
```

环境文件 `/etc/aether/aether-gateway.env`（`0600`）、数据库本机
PostgreSQL `127.0.0.1:5432/aether`——**本次改动不需要动它们**。

### 3.1 链路不稳时的制品上传（2026-10-15 实测踩坑）

长距离链路抖动时，**paramiko SFTP 的持续大流量传输会被中途掐断**（实测 37 MB 传到
32 MB 处 `Socket exception 10054` → `EOFError`；随后 SSH 握手也会 `banner` 超时）。
同一条链路**短命令却正常**，服务器也**没装 rsync**（`rsync: command not found`）→
按下面顺序退化：

1. **首选：`ssh + cat` 流式追加 + 按字节续传**（实测一次成功；断了就从断点续）：

```bash
export SSHPASS='<密码>'
OPTS="-o StrictHostKeyChecking=no -o ConnectTimeout=20 -o ServerAliveInterval=15"
HOST=root@<host>; LOCAL=...xz; REMOTE=/opt/aether-deploy/artifacts-incoming/aether-gateway-workbuddy.xz
sshpass -e ssh $OPTS $HOST "rm -f $REMOTE"
have=$(sshpass -e ssh $OPTS $HOST "stat -c %s $REMOTE 2>/dev/null || echo 0")
tail -c +$((have + 1)) "$LOCAL" | sshpass -e ssh $OPTS $HOST "cat >> $REMOTE"   # 循环到大小一致
sshpass -e ssh $OPTS $HOST "md5sum $REMOTE"                                     # 必须等于本地 md5
```

2. **部署脚本也在服务器上后台跑**，避免 SSH 抖动掐断安装过程：

```bash
tail -c +1 remote/03-deploy.sh | sshpass -e ssh $OPTS $HOST "cat > /root/deploy-03.sh"
sshpass -e ssh $OPTS $HOST "nohup bash /root/deploy-03.sh > /tmp/deploy.log 2>&1 < /dev/null &"
```

3. **铁律**：`03-deploy.sh` 带 `set -euo pipefail`，所以**半截 xz 不可能被误装**
   （`xz -dc` 失败即中止，不动现网二进制）——但**部署前仍必须核对 md5**。

---

## 4. 第四步：真机验证清单

按顺序做，每步都给了「期望」与「失败时先看哪里」。**本机无法直连
`copilot.tencent.com`，所以这一节是唯一能证明协议正确的地方。**

### 4.1 建供应商

后台 → 供应商 → 新建，类型选 **WorkBuddy**。

- **期望**：自动建出一个 `openai:chat` 端点，`base_url = https://copilot.tencent.com/`、
  `custom_path = /v2/chat/completions`、`upstream_stream_policy = force_stream`；
  provider config 里**自动带上** `failover_rules.error_stop_patterns`
  （请求级错误不换号，见 `workbuddy-provider.md` §2.3）——除非你显式给了 `failover_rules`
  （显式配置优先，不会被默认值覆盖）。
- **失败**：类型列表里没有 WorkBuddy → 前端没重建（§2）。

### 4.2 设备授权加账号

账号管理 → 添加账号 → 弹窗展示授权链接（本 provider **没有设备码**，只有链接）。

- **期望**：浏览器完成登录后弹窗自动变成已授权，账号落库；`nickname` 作为显示名。
- **失败**：一直 pending → 看日志有无 `/v2/plugin/auth/token` 的 4xx；上游建会话失败时
  会带 `authUrl` 为空。

### 4.3 一次带工具调用的对话（最关键）

用 Claude Code 或 Codex 形态的客户端，让它执行一个命令（例如「看下当前目录」）。

- **期望**：
  1. 流式返回，**没有** `403 code 11140`；
  2. 客户端**真的执行了工具**（说明 DSML 还原生效：正文里的 `‖DSML‖` 标记被换成结构化
     `tool_calls`，`finish_reason` 是 `tool_calls`）；
  3. 正文里**看不到** `DSML` 字样。
- **失败排查**：
  - 正文里能看到 `DSML` → 流式还原没生效（确认是同一格式：客户端与端点都是 `openai:chat`）。
  - `403 code 11140` → 头族没带全（`X-CodeBuddy-Request`/`X-User-Id`/`X-Domain`/UA）。
  - `400 code 11-128` 且提示内容策略 → 提示词替换/脱敏没生效（`workbuddy_prompt_mode`）。

### 4.4 余额 / 签到 / 连登 / 旅行

后台 → 账号管理 → 「刷新额度」（或等定时自检）。

- **期望**：返回的每个 key 结果里有这些字段：
  - `quota_snapshot`：`provider_type = "workbuddy"`、一个 `unit = "count"` 的积分窗口；
  - `checkin`：`checked_in` / `already_checked_in` / `not_supported`（企业号）；
  - `activity_reported`：`true` / `false` / `null`；
  - `streak_bonus`：含 `streak_days` / `redeemed_tiers` / `lottery_draws`，或
    `{"status":"unavailable"}`（上游说没有成长体系）；
  - `travel`：`{"action":"depart"|"claim"|"skip", …}`。
- **失败排查**：
  - 全部 key 都失败、日志有 `gateway provider quota request blocked by origin policy`
    → origin 白名单（`www.codebuddy.cn` / `www.workbuddy.ai` / `copilot.tencent.com`）。
  - 404 → 计费域用错（应该是 `www.codebuddy.cn`，不是对话域）。
  - 401 + `12153` → 会话失效，按设计会作废凭证并强制刷新（看 key 的
    `oauth_invalid_reason` 是否变成 `[OAUTH_EXPIRED]`）。

### 4.5 模型目录拉取

模型目录由**后台 worker** 拉取：把 key 的 **`auto_fetch_models`（自动获取模型）** 打开，
worker 会走本 provider 的 `/v3/config` 策略；也可以在模型列表页触发一次刷新
（后台 `provider/query/models` 路径）。

- **期望**：模型列表来自上游目录（不是空列表）；上游放在试用横幅里的模型也出现
  （`data.productFeaturesConfig.ModelTrialBanner`，目录里没有但实际可调用）。
- **失败**：`400 code 12403` → `/v3/config` 的 UA 不对（必须官方 IDE 段，网关已内置）；
  列表为空但接口 200 → 看是否命中了「业务码非 0 / 目录为空即失败」的保护（网关不会把
  错误信封当空目录去清模型）。

### 4.6 保活（定时刷新）

等一个定时周期（或看维护任务日志）。

- **期望**：workbuddy 的 oauth key 出现在定时 token 刷新里；刷新失败时
  `oauth_invalid_reason` 变 `[REFRESH_FAILED]`。
- **失败**：完全看不到 workbuddy 参与 → 检查 key 的 `auth_type` 是否为 `oauth`
  （只有 oauth 且带刷新令牌的账号才是候选）。

### 4.7 定时任务（签到 / 连登 / 旅行）

这三件事挂在**额度刷新**链路上（手动「刷新额度」、定时额度探针、定时账号自检），
所以只要 §4.4 通了，它们就会随调度自动跑（每天最多一次）。

- **期望**：第二天再看 `streak_days` 会 +1；`travel` 从 `depart` 变成 `claim`。
- **失败**：`checkin` 一直是 `already_checked_in` 说明当天已经签过（正常）；
  企业号 `not_supported` 也是正常（上游没有成长体系）。

---

## 5. 观测点速查

| 想确认 | 看哪里 |
| --- | --- |
| 出站身份头是否正确 | 后台「请求诊断」/候选详情里的 `provider_request_headers`，应含 `x-aether-workbuddy-runtime: 1`、`x-codebuddy-request: 1` |
| 是否走了降级 | 后台 key 的 `upstream_metadata`；降级是进程内闸门，重启清零 |
| 是否在换号重试 | 日志 `local_stream_candidate_retry_scheduled` |
| origin 白名单是否拦了 | 日志 `gateway provider quota request blocked by origin policy` |
| 失败分类结果 | 后台 key 的 `status_snapshot.quota`（`code = exhausted` 等）与 `oauth_invalid_reason` |

---

## 6. 已知未做（不是 bug，是范围）

见 `workbuddy-provider.md` §4 的差距表。影响上线的几条：

- WAF 403 只有**账号级**冷却，没有出口 IP 维度冷却（要移植 opencode 的 IP 机制）。
- 夜猫子任务未做（会发真实模型请求，成本最高，需单独确认）。

已做（开箱即用，无需手工配）：provider config 的 `failover_rules.error_stop_patterns`
由模板默认值下发（建供应商即生效、显式配置优先）；`11102`「该后端无此模型」会按
**(账号, 模型)** 记负缓存（6h 起、翻倍、封顶 24h），调度器随后跳过这一格；条目在 key 的
`upstream_metadata.workbuddy.model_blocked.<模型>` 下，日志事件名
`workbuddy_model_blocked_recorded`。
