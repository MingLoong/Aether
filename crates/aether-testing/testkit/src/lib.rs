mod fixtures;
mod redis;
mod server;
mod tracing;
mod wait;

#[cfg(feature = "gateway")]
mod execution_runtime;
#[cfg(feature = "gateway")]
mod gateway;
#[cfg(feature = "postgres")]
mod postgres;
#[cfg(feature = "gateway")]
mod tunnel;

pub use aether_loadtools::{
    fetch_prometheus_samples, find_metric_value_u64, parse_prometheus_samples, PrometheusSample,
};
pub use aether_loadtools::{
    json_body, run_http_load_probe, run_multi_url_http_load_probe, test_http_client,
    test_http_client_config, HttpLoadProbeConfig, HttpLoadProbeResponseMode, HttpLoadProbeResult,
    MultiUrlHttpLoadProbeResult,
};
pub use aether_loadtools::{BenchmarkRuntimeSampler, BenchmarkRuntimeSnapshot};
pub use fixtures::test_trace_id;
pub use redis::ManagedRedisServer;
pub use server::{reserve_local_port, SpawnedServer};
pub use tracing::{init_test_runtime, init_test_runtime_for, test_runtime_config};
pub use wait::wait_until;

/// 判断一个错误是不是「本机没装这个可执行文件」。
///
/// 之前调用方靠匹配 Unix 的错误文案 `"No such file or directory"` 来识别，
/// 于是在 Windows 上同样的情况（`program not found`）不会被识别，测试
/// 从「跳过」变成「panic」。同一个缺陷让本地永远红、CI 永远绿——而 CI
/// 那条流水线还额外按名字过滤，根本没跑到这些用例。
///
/// 这里按 `io::ErrorKind::NotFound` 判断，与平台无关；文案匹配只作为
/// 兜底，因为经过 `Box<dyn Error>` 之后 downcast 到 io::Error 并不总是可靠。
pub fn is_missing_binary_error(error: &(dyn std::error::Error + 'static)) -> bool {
    let mut current: Option<&(dyn std::error::Error + 'static)> = Some(error);    while let Some(err) = current {
        if let Some(io_error) = err.downcast_ref::<std::io::Error>() {
            if io_error.kind() == std::io::ErrorKind::NotFound {
                return true;
            }
        }
        current = err.source();
    }
    let rendered = error.to_string();
    [
        "No such file or directory",
        "program not found",
        "The system cannot find the file specified",
        "cannot find the file",
    ]
    .iter()
    .any(|needle| rendered.contains(needle))
}

#[cfg(feature = "gateway")]
pub use execution_runtime::{ExecutionRuntimeHarness, ExecutionRuntimeHarnessConfig};
#[cfg(feature = "gateway")]
pub use gateway::{GatewayHarness, GatewayHarnessConfig, GATEWAY_HARNESS_API_KEY};
#[cfg(feature = "postgres")]
pub use postgres::{prepare_aether_postgres_schema, ManagedPostgresServer};
#[cfg(feature = "gateway")]
pub use tunnel::{
    insert_tunnel_harness_auth_headers, TunnelHarness, TunnelHarnessConfig,
    TUNNEL_HARNESS_GENERATION, TUNNEL_HARNESS_MANAGEMENT_TOKEN, TUNNEL_HARNESS_NODE_ID,
};
