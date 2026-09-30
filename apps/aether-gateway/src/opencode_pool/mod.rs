//! OpenCode 前置代理出口 IP 池的领域逻辑。
//!
//! 这里只放与 HTTP 无关的部分：配置结构、网段扫描、健康复验、冷却记账。
//! 它不依赖 `handlers::admin` 里的任何东西——管理接口只是它的一个调用方，
//! 定时 worker 也是。所以它住在自己的模块下，而不是挂在管理台目录里。
//!
//! 分层原因是一条上游的架构守卫：`apps/aether-gateway/tests/architecture/
//! admin_shared.rs::admin_external_usage_is_confined_to_admin_api` 规定，
//! `apps/aether-gateway/src` 下除管理台本身以外的文件，不得以完整路径引用管理台内部。
//! 这套池子最初整体放在 `handlers/admin/provider/ip_pool/` 下，于是 `opencode_rotation.rs`
//! 与 `maintenance/runtime/opencode_ip_pool.rs` 都只能从管理台内部取配置类型，两个守卫
//! 文件一起变红。领域逻辑因此挪到这里，管理台那边保留
//! `handlers/admin/provider/ip_pool/mod.rs` 作为 HTTP 层。
//!
//! 顺带一提：那条守卫是纯文本搜索，注释里写出那个路径同样会被判违规，所以这段说明
//! 也得绕开写。
//!
//! 不要为了省事把 HTTP handler 也搬进来：它依赖 `AdminAppState` 与
//! `AdminRequestContext`，那两个是管理台请求层的类型，搬进来等于换个方向再
//! 越界一次。

pub(crate) mod pool;

pub(crate) use pool::{
    claim_verify_slot, list_opencode_pool_ips, opencode_ip_pool_status_for, opencode_pool_key_ip,
    parse_cidr, run_claimed_open_code_pool_verify, run_open_code_pool_clean,
    run_open_code_pool_scan, OpenCodeHealthConfig, OpenCodeScanConfig,
    OPENCODE_SCAN_DEFAULT_CONCURRENCY,
};
