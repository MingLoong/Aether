#![allow(warnings)]
// 独立子进程形态的 TLS 出口：本进程只做 HTTP CONNECT 代理，
// 真正的握手由手写 TLS 客户端完成（bin target，避开 rustc 1.95 的 lib ICE）。
use aes_gcm::aead::{Aead, KeyInit};
use aes_gcm::{Aes128Gcm, Nonce};
use hkdf::Hkdf;
use hmac::{Hmac, Mac};
use ml_kem::kem::{Decapsulate, Encapsulate};
use ml_kem::{EncodedSizeUser, KemCore, MlKem768};
use sha2::{Digest, Sha256};
use std::io::{self, Read, Write};
use std::net::TcpStream;
use x25519_dalek::{PublicKey, StaticSecret};

use aether_tls_hello::tls13::*;

fn main() {
    use std::net::TcpListener;

    let addr = std::env::args()
        .nth(1)
        .unwrap_or_else(|| "127.0.0.1:18080".to_string());
    let listener = match TcpListener::bind(&addr) {
        Ok(l) => l,
        Err(e) => {
            eprintln!("bind {addr} 失败: {e}");
            std::process::exit(1);
        }
    };
    eprintln!("tls_bridge 监听 {addr}（HTTP CONNECT）");

    for conn in listener.incoming() {
        match conn {
            Ok(c) => {
                std::thread::spawn(move || {
                    if let Err(e) = handle(c) {
                        eprintln!("连接结束: {e}");
                    }
                });
            }
            Err(e) => eprintln!("accept 失败: {e}"),
        }
    }
}

fn handle(mut client: TcpStream) -> Result<(), String> {
    // 读 CONNECT 请求头
    let mut head = Vec::new();
    let mut buf = [0u8; 4096];
    loop {
        let n = client.read(&mut buf).map_err(|e| e.to_string())?;
        if n == 0 {
            return Ok(());
        }
        head.extend_from_slice(&buf[..n]);
        if head.windows(4).any(|w| w == b"\r\n\r\n") {
            break;
        }
        if head.len() > 65536 {
            return Err("请求头过大".into());
        }
    }

    let text = String::from_utf8_lossy(&head).to_string();
    let first = text.lines().next().unwrap_or("").to_string();
    let mut parts = first.split(' ');
    let method = parts.next().unwrap_or("");
    let authority = parts.next().unwrap_or("");
    if !method.eq_ignore_ascii_case("CONNECT") {
        let _ = client.write_all(b"HTTP/1.1 405 Method Not Allowed\r\nContent-Length: 0\r\n\r\n");
        return Err(format!("只支持 CONNECT，收到 {method}"));
    }
    let (host, port) = match authority.rsplit_once(':') {
        Some((h, p)) => (h.to_string(), p.parse::<u16>().unwrap_or(443)),
        None => (authority.to_string(), 443),
    };

    let mut tls = connect(&host, port)?;
    client
        .write_all(b"HTTP/1.1 200 Connection Established\r\n\r\n")
        .map_err(|e| e.to_string())?;

    // 隧道建立后，客户端会发一条完整 HTTP 请求。整条读完再转发，
    // 避免为双向流引入锁（响应方向仍然是流式的，SSE 不受影响）。
    let req = read_http_request(&mut client)?;
    tls.write_all(&req).map_err(|e| e.to_string())?;
    tls.flush().ok();

    let mut b = [0u8; 16384];
    loop {
        match tls.read(&mut b) {
            Ok(0) => break,
            Ok(n) => {
                if client.write_all(&b[..n]).is_err() {
                    break;
                }
                let _ = client.flush();
            }
            Err(e) if e.kind() == io::ErrorKind::WouldBlock => continue,
            Err(_) => break,
        }
    }
    tls.shutdown();
    Ok(())
}

/// 读一条完整 HTTP 请求（头 + 按 Content-Length 的 body）。
fn read_http_request(c: &mut TcpStream) -> Result<Vec<u8>, String> {
    let mut buf = Vec::new();
    let mut tmp = [0u8; 8192];
    let head_end = loop {
        if let Some(i) = buf.windows(4).position(|w| w == b"\r\n\r\n") {
            break i + 4;
        }
        if buf.len() > 1 << 20 {
            return Err("请求头超过 1MB".into());
        }
        let n = c.read(&mut tmp).map_err(|e| e.to_string())?;
        if n == 0 {
            return Err("客户端提前关闭".into());
        }
        buf.extend_from_slice(&tmp[..n]);
    };

    let head = String::from_utf8_lossy(&buf[..head_end]).to_string();
    let clen: usize = head
        .lines()
        .find_map(|l| {
            let ll = l.to_ascii_lowercase();
            ll.starts_with("content-length:")
                .then(|| l.split(':').nth(1).map(|v| v.trim().parse::<usize>().ok()))
                .flatten()
                .flatten()
        })
        .unwrap_or(0);

    while buf.len() < head_end + clen {
        let n = c.read(&mut tmp).map_err(|e| e.to_string())?;
        if n == 0 {
            break;
        }
        buf.extend_from_slice(&tmp[..n]);
    }
    Ok(buf)
}
