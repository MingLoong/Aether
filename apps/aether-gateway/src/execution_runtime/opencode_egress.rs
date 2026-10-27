//! opencode 出站 TCP 通道：可选经 SOCKS5（HE IPv6 出口）建连，TLS 仍在本地完成。
//!
//! 设计要点：**只换 TCP 传输路径，不碰握手字节**。TLS 1.3 握手仍由
//! [`crate::execution_runtime::tls13_upstream`] 里的 `aether_tls_hello` 完成，
//! 所以客户端指纹与直连时完全一致。
//!
//! 配置来源是环境变量 `AETHER_OPENCODE_EGRESS`（首次使用时解析一次）：
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
//! - 变量不存在 / 解析失败 → 完全直连，行为与改动前一致
//! - `rotate: "cidr64"` → 用户名追加 `-cidr-64`（he-ipv6-pool 按 /64 轮换出口）
//! - 单个出口失败后冷却 `down_seconds`；全部不可用时按 `fallback_ipv4` 决定回落还是报错

use std::collections::HashMap;
use std::io::{Read, Write};
use std::net::{TcpStream, ToSocketAddrs};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Mutex, OnceLock};
use std::time::{Duration, Instant};

const ENV_KEY: &str = "AETHER_OPENCODE_EGRESS";
const CONNECT_TIMEOUT: Duration = Duration::from_secs(10);
const IO_TIMEOUT: Duration = Duration::from_secs(120);

#[derive(Debug, Clone)]
pub(crate) struct Exit {
    pub name: String,
    pub addr: String,
    pub user: String,
    pub pass: String,
    pub rotate_cidr64: bool,
}

#[derive(Debug)]
pub(crate) struct EgressConfig {
    /// 按 weight 展开后的轮转顺序（同一个出口出现多次）。
    order: Vec<usize>,
    exits: Vec<Exit>,
    fallback_ipv4: bool,
    down_for: Duration,
}

fn config() -> Option<&'static EgressConfig> {
    static CFG: OnceLock<Option<EgressConfig>> = OnceLock::new();
    CFG.get_or_init(|| {
        let raw = std::env::var(ENV_KEY).ok()?;
        let parsed = parse_config(raw.trim());
        match parsed {
            Some(cfg) => {
                let names: Vec<&str> = cfg.exits.iter().map(|e| e.name.as_str()).collect();
                tracing::info!(
                    exits = ?names,
                    fallback_ipv4 = cfg.fallback_ipv4,
                    "opencode 出口已启用"
                );
                Some(cfg)
            }
            None => {
                tracing::warn!("{ENV_KEY} 解析失败，保持直连");
                None
            }
        }
    })
    .as_ref()
}

fn parse_config(raw: &str) -> Option<EgressConfig> {
    if raw.is_empty() {
        return None;
    }
    let value: serde_json::Value = serde_json::from_str(raw).ok()?;
    let mut exits = Vec::new();
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
        });
    }
    if exits.is_empty() {
        return None;
    }
    let mut order = Vec::new();
    for (index, entry) in value.get("exits")?.as_array()?.iter().enumerate() {
        let weight = entry
            .get("weight")
            .and_then(|v| v.as_u64())
            .unwrap_or(1)
            .clamp(1, 32) as usize;
        // 只对真正落进 exits 的条目加权：被跳过的空地址不会占位。
        if exits.iter().any(|e| {
            e.addr
                == entry
                    .get("addr")
                    .and_then(|v| v.as_str())
                    .unwrap_or_default()
                    .trim()
        }) {
            for _ in 0..weight {
                order.push(index.min(exits.len().saturating_sub(1)));
            }
        }
    }
    if order.is_empty() {
        order.extend(0..exits.len());
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
pub(crate) fn dial(host: &str, port: u16) -> Result<TcpStream, String> {
    let Some(cfg) = config() else {
        return direct(host, port);
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
            Ok(stream) => {
                tracing::debug!(
                    exit = exit.name.as_str(),
                    host,
                    port,
                    "opencode 出口建连成功"
                );
                return Ok(stream);
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
        return direct(host, port);
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

fn socks5_connect(exit: &Exit, host: &str, port: u16) -> Result<TcpStream, String> {
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
    match head[3] {
        0x01 => {
            let mut skip = [0u8; 4 + 2];
            stream.read_exact(&mut skip).map_err(io_err)?;
        }
        0x04 => {
            let mut skip = [0u8; 16 + 2];
            stream.read_exact(&mut skip).map_err(io_err)?;
        }
        0x03 => {
            let mut len = [0u8; 1];
            stream.read_exact(&mut len).map_err(io_err)?;
            let mut skip = vec![0u8; len[0] as usize + 2];
            stream.read_exact(&mut skip).map_err(io_err)?;
        }
        other => return Err(format!("SOCKS5 地址类型异常: {other}")),
    }
    stream.set_read_timeout(Some(IO_TIMEOUT)).ok();
    stream.set_write_timeout(Some(IO_TIMEOUT)).ok();
    Ok(stream)
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
    fn cooldown_marks_and_expires() {
        mark_down("unit-test-exit", Duration::from_millis(50));
        assert!(is_cooling("unit-test-exit"));
        std::thread::sleep(Duration::from_millis(80));
        assert!(!is_cooling("unit-test-exit"));
    }
}
