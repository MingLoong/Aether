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
    if exits.is_empty() {
        return None;
    }
    // 全部停用 = 当前没有可用出口 → 退回直连，而不是拿着空序列去拨号。
    if order.is_empty() {
        return None;
    }
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
    })
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
    let start = cursor().fetch_add(1, Ordering::Relaxed);
    let mut last_error = String::new();
    for step in 0..cfg.order.len() {
        let index = cfg.order[(start + step) % cfg.order.len()];
        let exit = &cfg.exits[index];
        if is_cooling(&exit.name) {
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

fn socks5_connect(exit: &Exit, host: &str, port: u16) -> Result<(TcpStream, Option<String>), String> {
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
        assert!(parse_config(r#"{"exits":[]}"#).is_none());
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
    fn cooldown_marks_and_expires() {
        mark_down("unit-test-exit", Duration::from_millis(50));
        assert!(is_cooling("unit-test-exit"));
        std::thread::sleep(Duration::from_millis(80));
        assert!(!is_cooling("unit-test-exit"));
    }
}
