# Aether 维护手册（fork：MingLoong/Aether）

本 fork 在上游 `fawney19/Aether` 之上维护 OpenCode 与 AMD 两个供应商相关的能力：
OpenCode 的 CDN 出口 IP 池、以及 AMD 的模型负载感知。功能行为见
[opencode-ip-pool.md](opencode-ip-pool.md) 与 [amd-model-load-control.md](amd-model-load-control.md)；
本文只讲**怎么改、怎么验、怎么发**。

## 1. 仓库与分支

| 远端 | 地址 | 用途 |
| --- | --- | --- |
| `origin` / `upstream` | `github.com/fawney19/Aether` | 上游，**只读，永不推送** |
| `mingloong` | `github.com/MingLoong/Aether` | 本 fork，发布与 CI 都走这里 |

fork 上只保留 `main` 一个分支。版本基线跟随上游：当前 `v0.7.19-rc.2`
（`apps/aether-gateway/Cargo.toml`）。**上游版本 + `-rc.N`** 的命名是有意的，代价见第 6 节。

## 2. 本地构建（Windows）

本地只用来跑检查和单测；**服务器二进制必须来自 CI**（本地编出的是 Windows PE，装不上 Debian）。
gnu 工具链、sysroot、clang 都由脚本钉死：

```powershell
. "C:\Users\Administrator\Desktop\ae\aether-env.ps1"     # CARGO_HOME / RUSTUP_HOME / PATH / LIBCLANG_PATH
& "$env:CARGO_HOME\bin\cargo.exe" check -p aether-gateway --lib
& "$env:CARGO_HOME\bin\cargo.exe" test  -p aether-gateway --lib
```

环境变量在脚本里已经设好：`RUSTUP_TOOLCHAIN=stable-x86_64-pc-windows-gnu`、
`CARGO_TARGET_DIR`（提交前记得确认没有污染仓库）、`CARGO_PROFILE_DEV_DEBUG=0`。

跑测试必须给足栈，否则会在 `async_stream` 的嵌套 poll 上直接 abort：

```powershell
$env:RUST_MIN_STACK = 8388608
```

**依赖镜像**：`.cargo/config.toml`（被 gitignore）把 crates-io 换成
`sparse+http://127.0.0.1:18787/`。该镜像不在时，`cargo` 会失败在
`os_info`（`aether-ai/formats` 的依赖，`Cargo.lock` 里有但本地缓存可能没有），症状是
`unable to update registry crates-io`。临时绕过：把 `[source.local-proxy].registry`
指向 `sparse+https://rsproxy.cn/index/` 后 `cargo fetch`，或先把镜像起起来。

## 3. 测试基线

- `cargo test -p aether-gateway --lib`：全量约 5380 个用例。**有 3 个用例依赖本机 PostgreSQL**
  （`ManagedPostgresServer` 拉起临时库），没有本地 PostgreSQL 时固定失败，属已知基线，不是回归。
- 架构守卫在 `apps/aether-gateway/tests/architecture/`，CI 的 `Test (Integration Scenarios)` 跑它们。
  这类守卫大量使用「读源码文本 + 断言包含/不包含」，改文件路径、函数可见性或注释措辞都可能踩到。
- 改动供应商相关代码后，重点回归：

```powershell
& "$env:CARGO_HOME\bin\cargo.exe" test -p aether-gateway --lib opencode
& "$env:CARGO_HOME\bin\cargo.exe" test -p aether-gateway --lib amd_load
& "$env:CARGO_HOME\bin\cargo.exe" test -p aether-provider-transport --lib
& "$env:CARGO_HOME\bin\cargo.exe" test -p aether-model-fetch --lib
```

## 4. CI

两个 workflow，第三方 action **必须固定到 commit SHA**
（`tests/release_supply_chain_test.sh` 会拒绝可变引用，如 `@v4`）：

| workflow | 触发 | 作业 |
| --- | --- | --- |
| `.github/workflows/gateway-build.yml` | `push: main`、`pull_request`、`workflow_dispatch` | `build-linux-binary`、`cargo-check`、`unit-tests`、`frontend-typecheck` |
| `.github/workflows/rust-ci.yml` | 按改动范围 | Clippy / Test / Format 多分片 + `Shell security fixtures` |

**注意：功能分支 push 不会触发 `gateway-build.yml`。** 需要二进制时显式派发：

```powershell
gh workflow run gateway-build.yml -R MingLoong/Aether --ref <branch> -f target=aether-gateway
```

`gh` 必须带 `-R MingLoong/Aether`（否则会打到上游）。查运行/作业用 API，`gh run view --json`
对某些字段会报错：

```powershell
gh api "repos/MingLoong/Aether/actions/runs/<run_id>/jobs"
gh api "repos/MingLoong/Aether/actions/runs/<run_id>/artifacts"
```

产物名：`aether-aether-gateway-linux` / `aether-aether-tunnel-linux`。

## 5. 部署

目标机：Debian 12 (bookworm)、glibc 2.36、x86_64、内存 3.8 GiB。
CI 在 `debian:12` 容器里构建，正是为了对齐 glibc——本地跨平台产物不要用。

| 项 | 值 |
| --- | --- |
| 服务 | `systemctl {status,restart} aether-gateway-deploy` |
| 单元文件 | `/etc/systemd/system/aether-gateway-deploy.service`（`Restart=always`） |
| 环境文件 | `/etc/aether-gateway-deploy.env`（`0600`，含 JWT/加密密钥，勿打印） |
| 二进制 | `/opt/aether-deploy/target/debug/aether-gateway` |
| 工作目录 | `/opt/aether-deploy/runtime` |
| 端口 | `18084` |
| 前端静态目录 | 由 `AETHER_GATEWAY_STATIC_DIR` 指定 |
| 数据 | docker：`aether-deploy-postgres`（127.0.0.1:15432）、`aether-deploy-redis`（127.0.0.1:16379） |

**换二进制**（部署脚本的固定动作）：下载 artifact → 校验是 ELF → 校验唯一标记 → 备份
`<binary>.binary-backup-<stamp>` → `stop` → 落盘 `.new` 后 `mv`（避免 Text file busy）→
`start` → 验接口。

标记校验要选**本次改动独有**的字符串。踩过的坑：拿一个改动前就存在的字符串当标记，
等于什么都没验。

**前端**：没有任何流程会自动更新服务器上的前端产物。改了 `frontend/` 必须单独在服务器上重建：

```bash
export PATH=/opt/node/bin:$PATH          # v22.14.0
cd /opt/aether-deploy/frontend
./node_modules/.bin/vue-tsc -b --force   # 不要用 npx，会报 ERR_PACKAGE_PATH_NOT_EXPORTED
./node_modules/.bin/vite build           # 约 2.5 分钟
systemctl restart aether-gateway-deploy
```

**回滚**：`cp` 回对应 `binary-backup-*` 再 `restart`；备份按时间戳命名，保留最近若干份。

## 6. 版本与发布

`build.rs` 的版本优先级：`AETHER_BUILD_VERSION` > `AETHER_VERSION` > `GITHUB_REF_NAME` >
`git describe` > `CARGO_PKG_VERSION`。`gateway-build.yml` 会从 `Cargo.toml` 读出真实版本注入
`AETHER_VERSION`，否则分支构建会把 `/api/admin/system/version` 报成分支名。

发布走 tag `v<版本>`，`release.yml` 产出
`aether-v<版本>-linux-{amd64,arm64}.tar.gz`、`aether-vscodex-*.vsix`、`install.sh`、
`SHA256SUMS`、`AETHER_RELEASE_PROVENANCE.sigstore.json`。

**`-rc.N` 后缀会让版本号排在上游正式版之前**：semver 里 `0.7.19-rc.2 < 0.7.19`，
而 `/api/admin/system/check-update` 是拿本机版本和上游 release 比较
（`latest > current`，`crates/aether-admin/src/system.rs`）。所以只要上游存在正式版
`v0.7.19`，面板就会一直显示「有新版本 v0.7.19」。这不是 bug，是命名方式的直接结果；
要消掉它就得让本 fork 的版本号真正大于上游（例如 `v0.7.20-rc.1`），或发布正式版。
`updatable` 为 `false`（源码构建不支持在线更新），所以它不会真的自动升级。

## 7. 常见故障

| 症状 | 原因 | 处理 |
| --- | --- | --- |
| `git push` 卡住或 `Failed to connect ... via 127.0.0.1` | 仓库配的 HTTP 代理不可用 | `git -c http.proxy= -c https.proxy= push ...` |
| `gh workflow run` 404 | 没带 `-R`，打到了上游 | 加 `-R MingLoong/Aether` |
| `cargo` 报 `unable to update registry crates-io` | 本地依赖镜像 127.0.0.1:18787 未启动 | 见第 2 节 |
| `cargo test` 报 `thread has overflowed its stack` | 没设 `RUST_MIN_STACK` | 设为 8388608 |
| 单测报 `temporary PostgreSQL should start: program not found` | 本机没有 PostgreSQL | 已知基线，非回归 |
| 改了前端但界面没变 | 没有在服务器上重建前端 | 见第 5 节 |
| 接口 404 说「供应商不存在」，但 `/summary` 正常 | 列表读取失败被误报成不存在 | 见 opencode-ip-pool.md 的思路：区分「不存在」与「读失败」；查服务日志里的 repository 错误 |
| 接口 501 `admin proxy route not implemented in rust frontdoor` | 该 admin 路由没在 Rust 前门实现，或路径动作没被分类器识别 | 对照 `control/route/admin/` 下的分类器与 `handlers/shared/request_utils.rs` 白名单 |

## 8. 排查手法（本项目踩出来的）

- **先复现，再推理**：直接打接口/查库，比读代码猜要快得多，也不会得出无法证伪的结论。
- **一次只改一个变量**：改动前后各测一次，能给出因果而不是相关。
- **验证要能证伪**：拿「日志里没有 4xx」当证据是无效的——日志格式里可能根本没有那个字面量，
  这个检查无论假设真假都会通过。
- **注意 `set -o pipefail` + `grep -q`**：`grep` 命中后提前退出会让上游进程收到 SIGPIPE，
  整条管道被判失败，于是「命中」被报成「未命中」。要断言存在性就别用管道，先落盘再 grep。
- **PowerShell 5.1 读 UTF-8 中文文件**会按 GBK 解码，行数与内容都可能出错；
  核对中文文件用 `read` 工具或 `[System.IO.File]::ReadAllLines($f,[Text.Encoding]::UTF8)`。
- **本地编出的是 Windows PE**，别拿去部署 Linux；部署脚本必须校验 ELF。
