# Aether 维护文档（OpenCode 增强分支）

> 分支基线：`v0.1.0-opencode`（位于本地提交链顶端）
> 上游：`https://github.com/fawney19/Aether`（remote：`origin`）
> 本分支 fork 镜像：`https://gitcode.com/endless_loop/Aether`（remote：`gitcode`，需认证）

---

## 1. 分支概况

相对上游 `origin/main`（基线 `d30268f80`）的本分支改动，全部围绕 **OpenCode provider 支持与修复**：

| 提交 | 内容 | 类型 |
|---|---|---|
| `d93a86b20` | OpenCode provider transport 支持（UA/session 指纹、URL、body 语义、前端表单、类型注册、网关接线） | 新增 |
| `038c4634d` | GitCode CI：push 时编译检查 OpenCode 改动 | 新增 |
| `e9f214920` | UA 无条件替换为 `opencode/<version>`（修 403 FreeTierError） | 修复 |
| `1bc42eb9b` | 模型列表 URL `/zen/v1/models` + 匿名 Bearer 头（修 404） | 修复 |
| `191fcc616` | test-model 注入 UA/session/tools 指纹（修模型测试 403） | 修复 |

**对原始工程的侵入面**：所有新增逻辑均以 `provider_type == "opencode"` 守卫，openai / anthropic / gemini 路径不变。

---

## 2. 环境与工具链（本沙箱实测）

| 项 | 值 |
|---|---|
| 项目路径 | `/root/job-envs/sandboxes/deepseek-harness-1790254355/Aether` |
| cargo | `/root/job-envs/sandboxes/deepseek-harness-1790254355/.cargo/bin/cargo`（rust 1.95.0） |
| rustup home | `/root/job-envs/sandboxes/deepseek-harness-1790254355/.rustup` |
| LLVM（bindgen 需要） | `/root/job-envs/sandboxes/deepseek-harness-1790254355/llvm-root/usr/lib64` |
| 数据库 | Postgres `127.0.0.1:5432/aether`（`DATABASE_MODE=auto`） |
| 运行时后端 | `AETHER_RUNTIME_BACKEND=memory` |
| 网关端口 | `8084`（API + 前端静态托管） |

编译前必须设置的环境变量：

```bash
export PATH=/root/job-envs/sandboxes/deepseek-harness-1790254355/.cargo/bin:$PATH
export CARGO_HOME=/root/job-envs/sandboxes/deepseek-harness-1790254355/.cargo
export RUSTUP_HOME=/root/job-envs/sandboxes/deepseek-harness-1790254355/.rustup
export LIBCLANG_PATH=/root/job-envs/sandboxes/deepseek-harness-1790254355/llvm-root/usr/lib64
export LD_LIBRARY_PATH=/root/job-envs/sandboxes/deepseek-harness-1790254355/llvm-root/usr/lib64:$LD_LIBRARY_PATH
export BINDGEN_EXTRA_CLANG_ARGS="-isystem .../llvm-root/usr/lib64/clang/12.0.1/include -isystem /usr/lib/gcc/aarch64-linux-gnu/10.3.1/include -isystem /usr/include"
```

> 说明：`LIBCLANG_PATH` / `LD_LIBRARY_PATH` / `BINDGEN_EXTRA_CLANG_ARGS` 缺失会导致 boring-sys2 编译失败（找不到 libclang 或 stddef.h）。

---

## 3. 编译

```bash
# 单 crate 检查（快）
cargo check -p aether-model-fetch

# 完整网关二进制
cargo build -p aether-gateway -j4
# 产物：target/debug/aether-gateway
```

**已知坑（OOM）**：`aether-gateway` 单 crate 编译峰值内存 **>4.2GB**。当宿主 `free` 的 `available` < 4.5G 时会被 cgroup OOM 杀（signal 9）。曾观察到 `shared` 常驻 6G 导致 `available` 只有 ~4G。缓解手段：
- 等待内存宽裕窗口（`available` ≥ 8G 时一次编译约 3 分钟）
- 低配尝试：`CARGO_PROFILE_DEV_DEBUG=0 CARGO_INCREMENTAL=0 RUSTFLAGS="-C codegen-units=1" cargo build -p aether-gateway -j1`（仍可能过不了峰值）
- 编译前可临时停止非关键进程（记得恢复）

**前端构建**（Node 22.20.0 位于 `/opt/node-v22.20.0-linux-arm64`，系统 node 20.18 不满足 Vite 7）：

```bash
cd frontend
export PATH=/opt/node-v22.20.0-linux-arm64/bin:$PATH
npm run build        # 产物 frontend/dist
```

---

## 4. 测试

```bash
cargo test -p aether-model-fetch     # 85 个测试全绿（含 opencode URL / plan headers）
```

OpenCode 相关重点单测：
- `logic::tests::opencode_models_fetch_url_uses_zen_v1_path`
- `transport::tests::builds_opencode_models_fetch_plan_with_zen_path_and_anonymous_headers`
- `opencode.rs` 的 `header_injection_replaces_existing_user_agent_with_opencode_ua`

**手动回归清单**（改动 opencode 相关后必做）：
1. 拉上游模型：`POST /api/admin/provider-query/models` → 应返回 80 个模型
2. 模型测试：`POST /api/admin/provider-query/test-model`（big-pickle）→ `success:true`
3. chat：`POST /v1/chat/completions` 带 curl UA → 200

---

## 5. 部署 / 启动

```bash
cd /root/job-envs/sandboxes/deepseek-harness-1790254355/Aether
# 旧进程先停（按 PID，勿用 pgrep -f 全串匹配，会误杀 shell）
# 用 /tmp/aether-gw.env 里保存的完整环境变量启动（含加密密钥，不要打印）
set -a; while IFS= read -r line; do export "$line"; done < /tmp/aether-gw.env; set +a
export AETHER_GATEWAY_STATIC_DIR=/root/job-envs/sandboxes/deepseek-harness-1790254355/Aether/frontend/dist
nohup ./target/debug/aether-gateway >> /tmp/aether-gw-8084.log 2>&1 &
```

- 健康检查：`curl http://127.0.0.1:8084/_gateway/health`
- 前端 + API 同端口 8084
- 登录凭据（**开发默认，生产必须改**）：`admin@example.com` / 密码见 `.env` 中 `ADMIN_PASSWORD`
- 公网暴露：DevBridge 隧道（见 `huawei-cloud-jobenv-devbridge-tunnel` skill），隧道匿名公开时用后即删

---

## 6. 与上游同步（rebase 流程）

```bash
git fetch origin                 # fawney19/Aether main
git rebase origin/main           # 本地提交挪到上游最新之上，保持线性
# 冲突预期：opencode.rs 是新增文件基本不冲突；
# aether-model-fetch/transport.rs、request.rs 若上游改动会小冲突，均在 opencode 守卫内，解决较简单
```

维护铁律：
- 改动继续遵循 **增量 + opencode 守卫**，不要动其他 provider 的旧逻辑
- 每次改动后跑第 4 节回归清单
- CI（`.gitcode/workflows/ci.yml`）会在 push 时编译检查，需保持绿

**可选路线**：整理好的提交可提 PR 回 `fawney19/Aether`；被合并后本分支即可退化为薄维护。

---

## 7. 故障排查

| 症状 | 原因 | 处理 |
|---|---|---|
| 创建模型测试失败 `403 FreeTierError` | 请求缺 opencode UA 或 body 缺 `bash/glob/grep/read` tools | 已修复（191fcc616）；回归清单第 2 步 |
| 拉上游模型 `404 endpoint not found` | URL 用了 `/v1/models`，上游在 `/zen/v1/models` | 已修复（1bc42eb9b） |
| chat 200 但模型测试 403 | test-model 路径未走 opencode 指纹 | 已修复（191fcc616） |
| `jev-1.13-free` 模型测试 500 | 模型已不在官方目录（疑似下线/改名） | 改用 `big-pickle` 或官方 free 模型 |
| 部分模型（claude 系）401 | provider key 无该 tier 权限 | 用 key 有权限的模型（big-pickle / `*-free`） |
| 编译 OOM（signal 9） | 内存 available < 4.2G | 见第 3 节 |
| `cargo: not found` | PATH 未含沙箱 cargo | 见第 2 节环境变量 |
| chat `503 candidate_list_empty` | 请求模型不在 provider 模型列表 | 到 provider 管理加回模型 |
| 网关起不来 | 端口被占 / 日志尾部报错 | 按日志排错；确认 `target/debug` 二进制存在 |

---

## 8. 测试/临时资源清理

会话中创建的临时资源（用后应清理）：
- 测试 API key `opencode-uat`（`/tmp/aether-test-apikey` 存有实际值）
- DevBridge 隧道（`xuoyabra-8084...`，匿名公开 72h）：`db_process_stop` + `db_delete`
- provider 模型：如不需要 `big-pickle` 可移除；`jev-1.13-free` 已失效建议移除

**安全提醒**：`/tmp/aether-gw.env` 含加密密钥，勿外传；AK/SK 不应写入仓库或日志。