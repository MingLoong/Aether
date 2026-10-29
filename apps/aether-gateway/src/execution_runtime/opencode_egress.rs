//! opencode 出站 TCP 通道：可选经 SOCKS5（HE IPv6 出口）建连，TLS 仍在本地完成。
//!
//! 设计要点：**只换 TCP 传输路径，不碰握手字节**。TLS 1.3 握手仍由
//! [`crate::execution_runtime::tls13_upstream`] 里的 `aether_tls_hello` 完成，
//! 所以客户端指纹与直连时完全一致。
//!
//! 配置**只来自数据库**里该供应商的 provider config（`opencode_egress` 段）：
//! 启动时按库回填一次，之后每次保存供应商配置就刷新一次。环境变量
//! `AETHER_OPENCODE_EGRESS` 已经废弃——它只在内存里生效、和界面看到的不是同一份
//! 数据，排查时极易被「面板显示 A、进程跑 B」误导。
//!
//! ```json
//! {
//!   "exits": [
//!     {"name":"local","addr":"127.0.0.1:13001","user":"opencode","pass":"opencode","weight":2,"rotate":"cidr64"},
//!     {"name":"external","addr":"104.129.15.247:13001","user":"he-icarus","pass":"***","weight":1,"rotate":"cidr64"}
//!   ],
//!   "fallback_ipv4": true,
//!   "down_seconds": 60
//! }
//! ```
//!
//! - 该段不存在 → 完全直连，行为与改动前一致
//! - `rotate: "cidr64"` → 用户名追加 `-cidr-64`（he-ipv6-pool 按 /64 轮换出口）
//! - 单个出口失败后冷却 `down_seconds`；全部不可用时按 `fallback_ipv4` 决定回落还是报错

use std::collections::HashMap;
use std::io::{Read, Write};
use std::net::{TcpStream, ToSocketAddrs};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Mutex, OnceLock};
use std::time::{Duration, Instant};

const CONNECT_TIMEOUT: Duration = Duration::from_secs(10);
const IO_TIMEOUT: Duration = Duration::from_secs(120);

#[derive(Debug, Clone)]
pub(crate) struct Exit {
    pub name: String,
    pub addr: String,
    pub user: String,
    pub pass: String,
    pub rotate_cidr64: bool,
    /// 面板上的启停开关：停用的出口保留在配置里（下次打开界面还在），
    /// 但不参与拨号。
    pub enabled: bool,
}

#[derive(Clone, Debug)]
pub(crate) struct EgressConfig {
    /// 按 weight 展开后的轮转顺序（同一个出口出现多次）。
    order: Vec<usize>,
    exits: Vec<Exit>,
    fallback_ipv4: bool,
    down_for: Duration,
    /// 每个出口（≈ 一个 /64）在同一预算周期内最多发多少请求。
    ///
    /// 2026-10-29：opencode 免费层按 /64 计请求数（量级几十次），打满当天就废。
    /// 到量主动换点，而不是等上游 429 再换。默认 10。
    request_budget: u32,
    /// 预算周期在 UTC 的哪个整点重置（0 = 北京时间 08:00，与上游日额度重置一致）。
    budget_reset_utc_hour: u32,
    /// 429 且上游没给 `retry-after` 时的冷却时长。
    rate_limit_cooldown: Duration,
    /// 429 后换点重试前的第一档等待；为 0 表示不等。
    rate_limit_backoff: Duration,
    /// 等待阶梯上限（每档翻倍）。
    rate_limit_backoff_max: Duration,
    /// 用量落盘路径（重启后预算不丢）。
    state_path: Option<std::path::PathBuf>,
}

/// 运行时配置表：provider_id -> 出口配置。
///
/// 值只来自该供应商的 provider config（`opencode_egress` 段）：启动时由
/// [`prewarm_from_providers`] 从库里回填一次，之后每次保存配置由
/// [`set_provider_egress`] 刷新。没有 env 兜底——那份数据界面看不见，
/// 只会让「面板显示的和进程实际在用的」对不上。
fn registry() -> &'static Mutex<HashMap<String, EgressConfig>> {
    static REG: OnceLock<Mutex<HashMap<String, EgressConfig>>> = OnceLock::new();
    REG.get_or_init(|| Mutex::new(HashMap::new()))
}

/// 由 admin 写 provider config 之后调用：None 表示该供应商关掉出口。
pub(crate) fn set_provider_egress(provider_id: &str, config: Option<EgressConfig>) {
    let mut reg = match registry().lock() {
        Ok(guard) => guard,
        Err(poisoned) => poisoned.into_inner(),
    };
    match config {
        Some(cfg) => {
            let names: Vec<&str> = cfg.exits.iter().map(|e| e.name.as_str()).collect();
            tracing::info!(provider_id, exits = ?names, fallback_ipv4 = cfg.fallback_ipv4, "opencode 出口已更新");
            reg.insert(provider_id.to_string(), cfg);
        }
        None => {
            reg.remove(provider_id);
            tracing::info!(provider_id, "opencode 出口已关闭");
        }
    }
}

/// 从 provider config 的 `opencode_egress` 段解析出配置。
pub(crate) fn config_from_provider(provider_config: &serde_json::Value) -> Option<EgressConfig> {
    let section = provider_config.get("opencode_egress")?;
    if section.is_null() {
        return None;
    }
    parse_config(&section.to_string())
}

fn config_for(provider_id: &str) -> Option<EgressConfig> {
    let reg = match registry().lock() {
        Ok(guard) => guard,
        Err(poisoned) => poisoned.into_inner(),
    };
    reg.get(provider_id).cloned()
}

/// 启动期回填：把库里所有带 `opencode_egress` 段的供应商灌进运行时注册表。
///
/// 返回成功装配的供应商数量。读库失败只记 warn（进程照常起来，出口按直连处理），
/// 因为出口配置属于可选增强，不该阻断启动。
pub(crate) async fn prewarm_from_providers(
    providers: Vec<(String, Option<serde_json::Value>)>,
) -> usize {
    let mut bound = 0usize;
    for (provider_id, config) in providers {
        let Some(config) = config else { continue };
        let Some(cfg) = config_from_provider(&config) else {
            continue;
        };
        let names: Vec<String> = cfg.exits.iter().map(|e| e.name.clone()).collect();
        tracing::info!(
            provider_id = %provider_id,
            exits = ?names,
            fallback_ipv4 = cfg.fallback_ipv4,
            "opencode 出口已从数据库装载"
        );
        set_provider_egress(&provider_id, Some(cfg));
        bound += 1;
    }
    bound
}

/// 面板保存配置时的密码保留规则：出口的 `pass` 传空字符串表示「不修改」。
///
/// 面板上密码框显示 `••••••`，用户不动它时提交的是空串；原来直接写库，等于把
/// 出口密码清空，之后所有请求认证失败。这里按 `name`（缺失时按 `addr`）把旧密码
/// 补回去，只有显式给了非空值才覆盖。
pub(crate) fn preserve_exit_secrets(
    new_section: &mut serde_json::Value,
    old_section: Option<&serde_json::Value>,
) {
    let Some(old_section) = old_section else {
        return;
    };
    let Some(new_exits) = new_section
        .get_mut("exits")
        .and_then(|value| value.as_array_mut())
    else {
        return;
    };
    let old_exits = old_section
        .get("exits")
        .and_then(|value| value.as_array())
        .cloned()
        .unwrap_or_default();
    for exit in new_exits.iter_mut() {
        let Some(exit) = exit.as_object_mut() else {
            continue;
        };
        let blank = exit
            .get("pass")
            .and_then(|value| value.as_str())
            .is_none_or(str::is_empty);
        if !blank {
            continue;
        }
        let name = exit.get("name").and_then(|value| value.as_str());
        let addr = exit.get("addr").and_then(|value| value.as_str());
        let matched = old_exits.iter().find(|old| {
            let old = match old.as_object() {
                Some(map) => map,
                None => return false,
            };
            match (name, addr) {
                (Some(name), _) => old.get("name").and_then(|value| value.as_str()) == Some(name),
                (None, Some(addr)) => {
                    old.get("addr").and_then(|value| value.as_str()) == Some(addr)
                }
                (None, None) => false,
            }
        });
        let Some(old_pass) = matched
            .and_then(|old| old.get("pass"))
            .and_then(|value| value.as_str())
            .filter(|pass| !pass.is_empty())
        else {
            continue;
        };
        exit.insert(
            "pass".to_string(),
            serde_json::Value::String(old_pass.to_string()),
        );
    }
}

fn parse_config(raw: &str) -> Option<EgressConfig> {
    if raw.is_empty() {
        return None;
    }
    let value: serde_json::Value = serde_json::from_str(raw).ok()?;
    let mut exits = Vec::new();
    let mut order = Vec::new();
    for entry in value.get("exits")?.as_array()? {
        let addr = entry.get("addr")?.as_str()?.trim().to_string();
        if addr.is_empty() {
            continue;
        }
        let rotate = entry
            .get("rotate")
            .and_then(|v| v.as_str())
            .map(|v| v.eq_ignore_ascii_case("cidr64"))
            .unwrap_or(false);
        let enabled = entry
            .get("enabled")
            .and_then(|v| v.as_bool())
            .unwrap_or(true);
        let index = exits.len();
        exits.push(Exit {
            name: entry
                .get("name")
                .and_then(|v| v.as_str())
                .unwrap_or(addr.as_str())
                .to_string(),
            addr,
            user: entry
                .get("user")
                .and_then(|v| v.as_str())
                .unwrap_or_default()
                .to_string(),
            pass: entry
                .get("pass")
                .and_then(|v| v.as_str())
                .unwrap_or_default()
                .to_string(),
            rotate_cidr64: rotate,
            enabled,
        });
        // 停用的出口不进轮转序列：配置留着，但不会被拨号。
        if enabled {
            let weight = entry
                .get("weight")
                .and_then(|v| v.as_u64())
                .unwrap_or(1)
                .clamp(1, 32) as usize;
            for _ in 0..weight {
                order.push(index);
            }
        }
    }
    // 注意：这里不再对「没有出口 / 全部停用」返回 None。
    // 返回 None 会被 dial 当成「这个供应商没配出口」→ 直接走 IPv4 直连，
    // 于是「停掉所有出口 + 关掉回落直连」反而绕过了出口，与设置相反。
    // 现在只要求配置里有 exits 段；能不能拨号由 order 是否为空表达。
    Some(EgressConfig {
        order,
        exits,
        fallback_ipv4: value
            .get("fallback_ipv4")
            .and_then(|v| v.as_bool())
            .unwrap_or(true),
        down_for: Duration::from_secs(
            value
                .get("down_seconds")
                .and_then(|v| v.as_u64())
                .unwrap_or(60)
                .clamp(5, 3600),
        ),
        request_budget: value
            .get("request_budget")
            .and_then(|v| v.as_u64())
            .unwrap_or(10)
            .clamp(1, 1000) as u32,
        budget_reset_utc_hour: (value
            .get("budget_reset_utc_hour")
            .and_then(|v| v.as_u64())
            .unwrap_or(0)
            % 24) as u32,
        rate_limit_cooldown: Duration::from_secs(
            value
                .get("rate_limit_cooldown_seconds")
                .and_then(|v| v.as_u64())
                .unwrap_or(600)
                .clamp(30, 86_400),
        ),
        rate_limit_backoff: Duration::from_millis(
            value
                .get("rate_limit_backoff_ms")
                .and_then(|v| v.as_u64())
                .unwrap_or(1000)
                .clamp(0, 30_000),
        ),
        rate_limit_backoff_max: Duration::from_millis(
            value
                .get("rate_limit_backoff_max_ms")
                .and_then(|v| v.as_u64())
                .unwrap_or(4000)
                .clamp(0, 60_000),
        ),
        state_path: value
            .get("state_path")
            .and_then(|v| v.as_str())
            .map(|path| std::path::PathBuf::from(path.trim()))
            .filter(|path| !path.as_os_str().is_empty())
            .or_else(|| {
                Some(std::path::PathBuf::from(
                    "/opt/aether/state/opencode-exit-usage.json",
                ))
            }),
    })
}

/// 单个出口的用量（按预算周期）。
#[derive(Clone, Debug, Default, serde::Serialize, serde::Deserialize)]
struct ExitUsage {
    requests: u32,
    ok: u32,
    e429: u32,
    last_status: Option<u16>,
    /// 该出口被判"用满 / 被限流"直到哪个 unix 秒。
    spent_until: Option<u64>,
    /// 用量所属的预算周期（UTC 日期 + 归零小时）。
    period: String,
}

fn usage_store() -> &'static Mutex<HashMap<String, ExitUsage>> {
    static STORE: OnceLock<Mutex<HashMap<String, ExitUsage>>> = OnceLock::new();
    STORE.get_or_init(|| Mutex::new(HashMap::new()))
}

/// 拨号成功时记下「出口 IP → 出口名」。429 发生在建连之后，调用方手里只有
/// SOCKS5 应答里的 BND.ADDR，靠这张表把冷却打到正确的出口上。
fn ip_to_exit() -> &'static Mutex<HashMap<String, String>> {
    static MAP: OnceLock<Mutex<HashMap<String, String>>> = OnceLock::new();
    MAP.get_or_init(|| Mutex::new(HashMap::new()))
}

fn usage_loaded() -> &'static Mutex<bool> {
    static LOADED: OnceLock<Mutex<bool>> = OnceLock::new();
    LOADED.get_or_init(|| Mutex::new(false))
}

fn now_unix() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|duration| duration.as_secs())
        .unwrap_or(0)
}

fn usage_state_path() -> Option<std::path::PathBuf> {
    let reg = match registry().lock() {
        Ok(guard) => guard,
        Err(poisoned) => poisoned.into_inner(),
    };
    reg.values().find_map(|cfg| cfg.state_path.clone())
}

/// 预算周期标识：以 `reset_utc_hour` 为分界的 UTC 天数。只用于「是否同一周期」比较。
fn budget_period(reset_utc_hour: u32) -> String {
    let shifted = now_unix().saturating_sub(u64::from(reset_utc_hour % 24) * 3600);
    format!("d{}", shifted / 86_400)
}

fn next_budget_reset_unix(reset_utc_hour: u32) -> u64 {
    let hour = u64::from(reset_utc_hour % 24);
    let now = now_unix();
    let today_reset = (now / 86_400) * 86_400 + hour * 3600;
    if today_reset > now {
        today_reset
    } else {
        today_reset + 86_400
    }
}

fn ensure_usage_loaded() {
    {
        let guard = match usage_loaded().lock() {
            Ok(guard) => guard,
            Err(poisoned) => poisoned.into_inner(),
        };
        if *guard {
            return;
        }
    }
    if let Some(path) = usage_state_path() {
        if let Ok(raw) = std::fs::read_to_string(&path) {
            if let Ok(map) = serde_json::from_str::<HashMap<String, ExitUsage>>(&raw) {
                let mut store = match usage_store().lock() {
                    Ok(guard) => guard,
                    Err(poisoned) => poisoned.into_inner(),
                };
                tracing::info!(
                    path = %path.display(),
                    exits = map.len(),
                    "opencode 出口用量已从磁盘恢复"
                );
                *store = map;
            }
        }
    }
    let mut guard = match usage_loaded().lock() {
        Ok(guard) => guard,
        Err(poisoned) => poisoned.into_inner(),
    };
    *guard = true;
}

fn persist_usage() {
    let Some(path) = usage_state_path() else {
        return;
    };
    let snapshot = {
        let store = match usage_store().lock() {
            Ok(guard) => guard.clone(),
            Err(poisoned) => poisoned.into_inner().clone(),
        };
        match serde_json::to_string_pretty(&store) {
            Ok(json) => json,
            Err(error) => {
                tracing::warn!(error = %error, "opencode 出口用量序列化失败");
                return;
            }
        }
    };
    if let Some(parent) = path.parent() {
        let _ = std::fs::create_dir_all(parent);
    }
    let tmp = path.with_extension("json.tmp");
    if let Err(error) = std::fs::write(&tmp, snapshot.as_bytes()) {
        tracing::warn!(
            path = %tmp.display(),
            error = %error,
            "opencode 出口用量写入失败（预算只在内存里生效）"
        );
        return;
    }
    if let Err(error) = std::fs::rename(&tmp, &path) {
        tracing::warn!(path = %path.display(), error = %error, "opencode 出口用量落盘失败");
    }
}

/// 该出口在本预算周期内是否已经用满 / 被上游限流。
fn is_spent(name: &str, budget: u32, reset_utc_hour: u32) -> bool {
    ensure_usage_loaded();
    let period = budget_period(reset_utc_hour);
    let store = match usage_store().lock() {
        Ok(guard) => guard,
        Err(poisoned) => poisoned.into_inner(),
    };
    let Some(usage) = store.get(name) else {
        return false;
    };
    if usage.period != period {
        return false;
    }
    if usage.spent_until.is_some_and(|until| until > now_unix()) {
        return true;
    }
    usage.requests >= budget
}

/// 拨号成功后记一笔用量；到量就把该出口标成「本周期用满」。
fn record_exit_request(name: &str, budget: u32, reset_utc_hour: u32) {
    ensure_usage_loaded();
    let period = budget_period(reset_utc_hour);
    let (requests, exhausted) = {
        let mut store = match usage_store().lock() {
            Ok(guard) => guard,
            Err(poisoned) => poisoned.into_inner(),
        };
        let usage = store.entry(name.to_string()).or_default();
        if usage.period != period {
            *usage = ExitUsage {
                period: period.clone(),
                ..ExitUsage::default()
            };
        }
        usage.requests = usage.requests.saturating_add(1);
        usage.last_status = usage.last_status.or(Some(200));
        let reached = usage.requests >= budget;
        if reached && usage.spent_until.is_none() {
            usage.spent_until = Some(next_budget_reset_unix(reset_utc_hour));
        }
        (usage.requests, reached)
    };
    persist_usage();
    if exhausted {
        tracing::info!(
            event_name = "opencode_exit_budget_exhausted",
            log_type = "ops",
            exit = name,
            requests,
            budget,
            "出口请求数达到预算，本周期内不再使用"
        );
    }
}

/// 429 之后换点重试前该等多久：`rate_limit_backoff_ms` × 2^档位，封顶
/// `rate_limit_backoff_max_ms`。返回 `None` 表示不等。
pub(crate) fn rate_limit_backoff(provider_id: &str, attempt_index: u32) -> Option<Duration> {
    let cfg = config_for(provider_id)?;
    let base = cfg.rate_limit_backoff.as_millis() as u64;
    if base == 0 {
        return None;
    }
    let cap = (cfg.rate_limit_backoff_max.as_millis() as u64).max(base);
    let mut delay = base;
    for _ in 0..attempt_index.min(8) {
        if delay >= cap {
            break;
        }
        delay = delay.saturating_mul(2).min(cap);
    }
    Some(Duration::from_millis(delay.min(cap)))
}

/// 429 之后给**实际使用的那个出口**落冷却，并标成用满。
///
/// 冷却时长优先用上游 `retry-after`（指向额度刷新点），没有就退回
/// `rate_limit_cooldown_seconds`（默认 600 秒）；夹紧 60 秒 ~ 24 小时。
pub(crate) fn note_exit_rate_limited(
    provider_id: &str,
    exit_ip: &str,
    retry_after_seconds: Option<u64>,
) -> bool {
    ensure_usage_loaded();
    let name = {
        let map = match ip_to_exit().lock() {
            Ok(guard) => guard,
            Err(poisoned) => poisoned.into_inner(),
        };
        map.get(exit_ip).cloned()
    };
    let Some(name) = name else {
        tracing::warn!(
            event_name = "opencode_exit_rate_limited_unknown_ip",
            log_type = "ops",
            provider_id,
            exit_ip,
            "429 无法归因到已知出口，本次不落冷却"
        );
        return false;
    };
    let configured_fallback = config_for(provider_id)
        .map(|cfg| cfg.rate_limit_cooldown)
        .unwrap_or(Duration::from_secs(600));
    let ttl = match retry_after_seconds {
        Some(seconds) => Duration::from_secs(seconds.clamp(60, 86_400)),
        None => configured_fallback,
    };
    mark_down(&name, ttl);
    let until = now_unix().saturating_add(ttl.as_secs());
    {
        let mut store = match usage_store().lock() {
            Ok(guard) => guard,
            Err(poisoned) => poisoned.into_inner(),
        };
        let usage = store.entry(name.clone()).or_default();
        usage.e429 = usage.e429.saturating_add(1);
        usage.last_status = Some(429);
        usage.spent_until = Some(match usage.spent_until {
            Some(existing) if existing > until => existing,
            _ => until,
        });
    }
    persist_usage();
    tracing::info!(
        event_name = "opencode_exit_rate_limited",
        log_type = "ops",
        provider_id,
        exit = name.as_str(),
        exit_ip,
        ttl_seconds = ttl.as_secs(),
        source = if retry_after_seconds.is_some() {
            "retry_after"
        } else {
            "configured"
        },
        "出口被上游限流，已冷却"
    );
    true
}

fn cooldowns() -> &'static Mutex<HashMap<String, Instant>> {
    static DOWN: OnceLock<Mutex<HashMap<String, Instant>>> = OnceLock::new();
    DOWN.get_or_init(|| Mutex::new(HashMap::new()))
}

fn cursor() -> &'static AtomicUsize {
    static CURSOR: OnceLock<AtomicUsize> = OnceLock::new();
    CURSOR.get_or_init(|| AtomicUsize::new(0))
}

fn is_cooling(name: &str) -> bool {
    let mut map = match cooldowns().lock() {
        Ok(guard) => guard,
        Err(poisoned) => poisoned.into_inner(),
    };
    match map.get(name) {
        Some(until) if *until > Instant::now() => true,
        Some(_) => {
            map.remove(name);
            false
        }
        None => false,
    }
}

fn mark_down(name: &str, for_how_long: Duration) {
    let mut map = match cooldowns().lock() {
        Ok(guard) => guard,
        Err(poisoned) => poisoned.into_inner(),
    };
    map.insert(name.to_string(), Instant::now() + for_how_long);
}

/// 为 `host:port` 建一条 TCP 连接：有配置时按顺序尝试出口，失败按配置回落直连。
/// 建好的一条出站 TCP 连接，外加「它实际从哪个地址出去的」。
///
/// `exit_ip` 来自 SOCKS5 应答里的 BND.ADDR：出口池按 /64 随机选源地址，这个值是我们
/// 唯一能拿到「本次用了哪个 IPv6」的来源。有了它，上游 429/403 才能按 IP 归因
/// （池子自己的访问日志只看得见连接层）。
/// 「配置层面就发不出请求」的错误前缀：上层据此给出 503 + 可读原因，而不是 500。
pub(crate) const EGRESS_UNAVAILABLE_PREFIX: &str = "opencode 出口已全部停用";

pub(crate) struct Dialed {
    pub stream: TcpStream,
    pub exit_name: String,
    pub exit_ip: Option<String>,
}

pub(crate) fn dial(host: &str, port: u16, provider_id: &str) -> Result<Dialed, String> {
    let Some(cfg) = config_for(provider_id) else {
        return direct(host, port).map(|stream| Dialed {
            stream,
            exit_name: "direct".to_string(),
            exit_ip: None,
        });
    };
    if cfg.order.is_empty() {
        if cfg.fallback_ipv4 {
            tracing::warn!(provider_id, "opencode 出口已全部停用，回落直连");
            return direct(host, port).map(|stream| Dialed {
                stream,
                exit_name: "direct".to_string(),
                exit_ip: None,
            });
        }
        // 配置层面就发不出请求：留一条 error 级日志，否则上层只看到 internal server error。
        tracing::error!(
            provider_id,
            host,
            port,
            "opencode 出口已全部停用且回落直连已关闭，本次请求失败"
        );
        return Err(format!("{EGRESS_UNAVAILABLE_PREFIX}（回落直连已关闭）"));
    }
    let start = cursor().fetch_add(1, Ordering::Relaxed);
    let mut last_error = String::new();
    let mut skipped_spent = 0usize;
    for step in 0..cfg.order.len() {
        let index = cfg.order[(start + step) % cfg.order.len()];
        let exit = &cfg.exits[index];
        if is_cooling(&exit.name) {
            continue;
        }
        // 预算到量 / 被上游限流过的出口：本周期内不再拨。
        // 2026-10-29：opencode 免费层按 /64 计请求数，用满当天就废；不拦住就会
        // 反复撞同一个已打满的 /64（现场：abcd 连撞 4 次）。
        if is_spent(&exit.name, cfg.request_budget, cfg.budget_reset_utc_hour) {
            skipped_spent += 1;
            continue;
        }
        match socks5_connect(exit, host, port) {
            Ok((stream, exit_ip)) => {
                tracing::debug!(
                    exit = exit.name.as_str(),
                    host,
                    port,
                    exit_ip = exit_ip.as_deref().unwrap_or(""),
                    "opencode 出口建连成功"
                );
                if let Some(ip) = exit_ip.as_deref() {
                    if let Ok(mut map) = ip_to_exit().lock() {
                        map.insert(ip.to_string(), exit.name.clone());
                    }
                }
                record_exit_request(&exit.name, cfg.request_budget, cfg.budget_reset_utc_hour);
                return Ok(Dialed {
                    stream,
                    exit_name: exit.name.clone(),
                    exit_ip,
                });
            }
            Err(error) => {
                tracing::warn!(
                    exit = exit.name.as_str(),
                    host,
                    port,
                    error = error.as_str(),
                    "opencode 出口失败"
                );
                mark_down(&exit.name, cfg.down_for);
                last_error = error;
            }
        }
    }
    if skipped_spent > 0 {
        tracing::info!(
            event_name = "opencode_exits_budget_exhausted",
            log_type = "ops",
            provider_id,
            skipped_spent,
            total = cfg.order.len(),
            budget = cfg.request_budget,
            "本次跳过用满预算的出口"
        );
    }
    if cfg.fallback_ipv4 {
        tracing::warn!(
            host,
            port,
            error = last_error.as_str(),
            "出口全部不可用，回落直连"
        );
        return direct(host, port).map(|stream| Dialed {
            stream,
            exit_name: "direct".to_string(),
            exit_ip: None,
        });
    }
    Err(if last_error.is_empty() {
        "opencode 出口全部处于冷却中".to_string()
    } else {
        last_error
    })
}

fn direct(host: &str, port: u16) -> Result<TcpStream, String> {
    let addrs: Vec<_> = (host, port)
        .to_socket_addrs()
        .map_err(|e| format!("解析 {host} 失败: {e}"))?
        .collect();
    let mut last = String::from("没有可用地址");
    for addr in addrs {
        match TcpStream::connect_timeout(&addr, CONNECT_TIMEOUT) {
            Ok(stream) => {
                stream.set_read_timeout(Some(IO_TIMEOUT)).ok();
                stream.set_write_timeout(Some(IO_TIMEOUT)).ok();
                return Ok(stream);
            }
            Err(error) => last = format!("{addr}: {error}"),
        }
    }
    Err(format!("直连 {host}:{port} 失败: {last}"))
}

fn socks5_connect(
    exit: &Exit,
    host: &str,
    port: u16,
) -> Result<(TcpStream, Option<String>), String> {
    let addr = exit
        .addr
        .to_socket_addrs()
        .map_err(|e| format!("解析出口 {} 失败: {e}", exit.addr))?
        .next()
        .ok_or_else(|| format!("出口 {} 没有可用地址", exit.addr))?;
    let mut stream = TcpStream::connect_timeout(&addr, CONNECT_TIMEOUT)
        .map_err(|e| format!("连出口失败: {e}"))?;
    stream.set_read_timeout(Some(CONNECT_TIMEOUT)).ok();
    stream.set_write_timeout(Some(CONNECT_TIMEOUT)).ok();

    // 认证方式协商：只支持用户名密码（0x02）。
    if exit.user.is_empty() {
        stream.write_all(&[0x05, 0x01, 0x00]).map_err(io_err)?;
    } else {
        stream.write_all(&[0x05, 0x01, 0x02]).map_err(io_err)?;
    }
    let mut reply = [0u8; 2];
    stream.read_exact(&mut reply).map_err(io_err)?;
    if reply[0] != 0x05 {
        return Err(format!("SOCKS5 版本异常: {}", reply[0]));
    }
    match reply[1] {
        0x00 => {}
        0x02 if !exit.user.is_empty() => {
            let user = if exit.rotate_cidr64 {
                format!("{}-cidr-64", exit.user)
            } else {
                exit.user.clone()
            };
            if user.len() > 255 || exit.pass.len() > 255 {
                return Err("SOCKS5 凭据过长".to_string());
            }
            let mut auth = Vec::with_capacity(3 + user.len() + exit.pass.len());
            auth.push(0x01);
            auth.push(user.len() as u8);
            auth.extend_from_slice(user.as_bytes());
            auth.push(exit.pass.len() as u8);
            auth.extend_from_slice(exit.pass.as_bytes());
            stream.write_all(&auth).map_err(io_err)?;
            let mut ok = [0u8; 2];
            stream.read_exact(&mut ok).map_err(io_err)?;
            if ok[1] != 0x00 {
                return Err(format!("SOCKS5 认证被拒: {}", ok[1]));
            }
        }
        0xFF => return Err("SOCKS5 不接受任何认证方式".to_string()),
        other => return Err(format!("SOCKS5 认证方式异常: {other}")),
    }

    // CONNECT：发域名而不是解析后的 IP —— 由出口侧做 DNS，才能拿到 AAAA。
    if host.len() > 255 {
        return Err("主机名过长".to_string());
    }
    let mut req = Vec::with_capacity(7 + host.len());
    req.extend_from_slice(&[0x05, 0x01, 0x00, 0x03]);
    req.push(host.len() as u8);
    req.extend_from_slice(host.as_bytes());
    req.extend_from_slice(&port.to_be_bytes());
    stream.write_all(&req).map_err(io_err)?;

    let mut head = [0u8; 4];
    stream.read_exact(&mut head).map_err(io_err)?;
    if head[0] != 0x05 {
        return Err(format!("SOCKS5 响应版本异常: {}", head[0]));
    }
    if head[1] != 0x00 {
        return Err(format!("SOCKS5 CONNECT 失败: code={}", head[1]));
    }
    // BND.ADDR 就是出口侧实际使用的源地址：he-ipv6-pool 会把它填成本次选的 IPv6。
    let exit_ip = match head[3] {
        0x01 => {
            let mut buf = [0u8; 4 + 2];
            stream.read_exact(&mut buf).map_err(io_err)?;
            Some(std::net::Ipv4Addr::new(buf[0], buf[1], buf[2], buf[3]).to_string())
        }
        0x04 => {
            let mut buf = [0u8; 16 + 2];
            stream.read_exact(&mut buf).map_err(io_err)?;
            let mut octets = [0u8; 16];
            octets.copy_from_slice(&buf[..16]);
            Some(std::net::Ipv6Addr::from(octets).to_string())
        }
        0x03 => {
            let mut len = [0u8; 1];
            stream.read_exact(&mut len).map_err(io_err)?;
            let mut skip = vec![0u8; len[0] as usize + 2];
            stream.read_exact(&mut skip).map_err(io_err)?;
            None
        }
        other => return Err(format!("SOCKS5 地址类型异常: {other}")),
    };
    // 0.0.0.0 / :: 表示出口没填（有些实现如此），当作未知。
    let exit_ip = exit_ip.filter(|ip| ip != "0.0.0.0" && ip != "::");
    stream.set_read_timeout(Some(IO_TIMEOUT)).ok();
    stream.set_write_timeout(Some(IO_TIMEOUT)).ok();
    Ok((stream, exit_ip))
}

fn io_err(error: std::io::Error) -> String {
    format!("SOCKS5 握手: {error}")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_keeps_order_and_weights() {
        let cfg = parse_config(
            r#"{"exits":[
                {"name":"a","addr":"1.1.1.1:1","user":"u","pass":"p","weight":2,"rotate":"cidr64"},
                {"name":"b","addr":"2.2.2.2:2"}
            ],"fallback_ipv4":false,"down_seconds":30}"#,
        )
        .expect("应当解析成功");
        assert_eq!(cfg.exits.len(), 2);
        // a 权重 2 → 在轮转序列里出现两次
        assert_eq!(cfg.order.iter().filter(|i| **i == 0).count(), 2);
        assert!(cfg.exits[0].rotate_cidr64);
        assert!(!cfg.fallback_ipv4);
        assert_eq!(cfg.down_for, Duration::from_secs(30));
    }

    #[test]
    fn parse_rejects_empty_and_broken() {
        assert!(parse_config("").is_none());
        assert!(parse_config("not json").is_none());
        // 空 exits 段仍然算「配置了出口」，只是没有可用出口：不能当成没配。
        let empty = parse_config(r#"{"exits":[]}"#).expect("空 exits 段应解析成功");
        assert!(empty.order.is_empty());
    }

    /// 新加的三个旋钮都有默认值，缺省时行为与「10 次一换、429 等 1s」一致。
    #[test]
    fn parse_sets_budget_and_backoff_defaults() {
        let cfg =
            parse_config(r#"{"exits":[{"name":"a","addr":"1.1.1.1:1"}]}"#).expect("应当解析成功");
        assert_eq!(cfg.request_budget, 10);
        assert_eq!(cfg.rate_limit_backoff, Duration::from_millis(1000));
        assert_eq!(cfg.rate_limit_backoff_max, Duration::from_millis(4000));
        assert_eq!(cfg.rate_limit_cooldown, Duration::from_secs(600));
        assert_eq!(cfg.budget_reset_utc_hour, 0);
        // 夹紧：0 次 / 0 秒这类无意义值不允许穿透。
        let clamped = parse_config(
            r#"{"exits":[{"name":"a","addr":"1.1.1.1:1"}],"request_budget":0,
                "rate_limit_backoff_ms":999999,"rate_limit_cooldown_seconds":1}"#,
        )
        .expect("应当解析成功");
        assert_eq!(clamped.request_budget, 1);
        assert_eq!(clamped.rate_limit_backoff, Duration::from_millis(30_000));
        assert_eq!(clamped.rate_limit_cooldown, Duration::from_secs(30));
    }

    /// 每出口用满 10 次就该被跳过；未到量不该跳。
    #[test]
    fn exit_budget_marks_the_exit_spent() {
        let name = "unit-budget-exit";
        let budget = 3;
        assert!(!is_spent(name, budget, 0), "还没用过的出口不该被判用满");
        for _ in 0..budget {
            record_exit_request(name, budget, 0);
        }
        assert!(
            is_spent(name, budget, 0),
            "用满预算后必须判为用满，否则会继续撞同一个 /64"
        );
    }

    /// 429 冷却阶梯：第 0 档 1s，之后翻倍，封顶 4s。
    #[test]
    fn rate_limit_backoff_ladder_doubles_and_caps() {
        let provider = "unit-backoff-provider";
        let cfg = parse_config(
            r#"{"exits":[{"name":"a","addr":"1.1.1.1:1"}],
                "rate_limit_backoff_ms":1000,"rate_limit_backoff_max_ms":4000}"#,
        )
        .expect("应当解析成功");
        set_provider_egress(provider, Some(cfg));
        assert_eq!(
            rate_limit_backoff(provider, 0),
            Some(Duration::from_millis(1000))
        );
        assert_eq!(
            rate_limit_backoff(provider, 1),
            Some(Duration::from_millis(2000))
        );
        assert_eq!(
            rate_limit_backoff(provider, 2),
            Some(Duration::from_millis(4000))
        );
        // 封顶：再往后不再增长。
        assert_eq!(
            rate_limit_backoff(provider, 9),
            Some(Duration::from_millis(4000))
        );
        // 关掉（第一档 0）就不等。
        let off = parse_config(
            r#"{"exits":[{"name":"a","addr":"1.1.1.1:1"}],"rate_limit_backoff_ms":0}"#,
        )
        .expect("应当解析成功");
        set_provider_egress(provider, Some(off));
        assert_eq!(rate_limit_backoff(provider, 1), None);
        set_provider_egress(provider, None);
    }

    #[test]
    fn blank_password_keeps_the_stored_one() {
        let old = serde_json::json!({"exits":[
            {"name":"he64","addr":"1.1.1.1:1","user":"opencode","pass":"real-secret"}
        ]});
        // 面板把「留空表示不改」实现成提交空串；不改的话密码就被清掉了。
        let mut new = serde_json::json!({"exits":[
            {"name":"he64","addr":"1.1.1.1:1","user":"opencode","pass":"","weight":3}
        ]});
        preserve_exit_secrets(&mut new, Some(&old));
        assert_eq!(new["exits"][0]["pass"], "real-secret");
        assert_eq!(new["exits"][0]["weight"], 3);
    }

    #[test]
    fn explicit_password_overrides_and_unknown_exits_keep_blank() {
        let old = serde_json::json!({"exits":[
            {"name":"he64","addr":"1.1.1.1:1","pass":"old"}
        ]});
        let mut new = serde_json::json!({"exits":[
            {"name":"he64","addr":"1.1.1.1:1","pass":"brand-new"},
            {"name":"other","addr":"2.2.2.2:2","pass":""}
        ]});
        preserve_exit_secrets(&mut new, Some(&old));
        assert_eq!(new["exits"][0]["pass"], "brand-new");
        assert_eq!(new["exits"][1]["pass"], "");
    }

    #[test]
    fn registry_is_the_only_source_of_egress_config() {
        // 没有回填过就没有出口配置：不再有 env 兜底，避免「界面一份、进程一份」。
        assert!(config_for("provider-without-egress").is_none());
    }

    #[test]
    fn all_disabled_keeps_config_but_empty_order() {
        let cfg = parse_config(
            r#"{"exits":[
                {"name":"a","addr":"1.1.1.1:1","enabled":false},
                {"name":"b","addr":"2.2.2.2:2","enabled":false}
            ],"fallback_ipv4":false}"#,
        )
        .expect("全部停用仍应解析出配置");
        assert_eq!(cfg.exits.len(), 2);
        assert!(cfg.order.is_empty());
        assert!(!cfg.fallback_ipv4);
    }

    #[test]
    fn cooldown_marks_and_expires() {
        mark_down("unit-test-exit", Duration::from_millis(50));
        assert!(is_cooling("unit-test-exit"));
        std::thread::sleep(Duration::from_millis(80));
        assert!(!is_cooling("unit-test-exit"));
    }
}
