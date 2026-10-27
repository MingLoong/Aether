//! opencode 专用 TLS 1.3 出站通道（阶段一：非流式）。
//!
//! 背景见 `docs/opencode-tls13-egress.md`。这里只做两件事：
//! 1. 把阻塞的 `aether_tls_hello::tls13::TlsStream` 包成 tokio 可用的响应
//! 2. 提供 `send()`，供 `transport.rs` 在 opencode 分支调用
//!
//! 尚未接进 `DirectHttpResponse`（需要加变体 + 10 处 match 臂），
//! 所以本模块目前只有 `send()` 与其单元测试，不改变任何既有出站行为。

use std::io::{Read, Write};

/// 一次 TLS 13 出站请求的结果。
pub(crate) struct Tls13Response {
    pub status: u16,
    pub headers: Vec<(String, String)>,
    pub body: Vec<u8>,
}

impl Tls13Response {
    pub(crate) fn header(&self, name: &str) -> Option<&str> {
        self.headers
            .iter()
            .find(|(k, _)| k.eq_ignore_ascii_case(name))
            .map(|(_, v)| v.as_str())
    }
}

/// 用 TLS 13 通道发一条 HTTP/1.1 请求（阻塞实现，内部负责线程调度）。
pub(crate) async fn send(
    url: &str,
    method: &str,
    headers: &[(String, String)],
    body: Vec<u8>,
) -> Result<Tls13Response, String> {
    let url = url.to_string();
    let method = method.to_string();
    let headers = headers.to_vec();
    tokio::task::spawn_blocking(move || send_blocking(&url, &method, &headers, body))
        .await
        .map_err(|e| format!("tls13 task join: {e}"))?
}

fn send_blocking(
    url: &str,
    method: &str,
    headers: &[(String, String)],
    body: Vec<u8>,
) -> Result<Tls13Response, String> {
    let (host, port, path) = split_url(url)?;
    // TCP 可以走 SOCKS5 出口（HE IPv6），TLS 握手仍在这里本地完成，指纹不变。
    let sock = super::opencode_egress::dial(&host, port)?;
    let mut tls = aether_tls_hello::tls13::connect_over(sock, &host)?;

    let mut req = format!("{method} {path} HTTP/1.1\r\nHost: {host}\r\n");
    let mut has_length = false;
    for (k, v) in headers {
        if k.eq_ignore_ascii_case("host") {
            continue;
        }
        if k.eq_ignore_ascii_case("content-length") {
            has_length = true;
        }
        req.push_str(k);
        req.push_str(": ");
        req.push_str(v);
        req.push_str("\r\n");
    }
    if !body.is_empty() && !has_length {
        req.push_str(&format!("Content-Length: {}\r\n", body.len()));
    }
    req.push_str("\r\n");

    let mut payload = req.into_bytes();
    payload.extend_from_slice(&body);
    tls.write_all(&payload)
        .map_err(|e| format!("写请求: {e}"))?;
    tls.flush().ok();

    read_response(&mut tls)
}

fn read_response(tls: &mut aether_tls_hello::tls13::TlsStream) -> Result<Tls13Response, String> {
    let mut buf: Vec<u8> = Vec::new();
    let mut tmp = [0u8; 8192];

    // 读响应头
    let head_end = loop {
        if let Some(i) = find_head_end(&buf) {
            break i;
        }
        if buf.len() > 1 << 20 {
            return Err("响应头超过 1MB".into());
        }
        match tls.read(&mut tmp) {
            Ok(0) => return Err("连接在响应头之前关闭".into()),
            Ok(n) => buf.extend_from_slice(&tmp[..n]),
            Err(e) => return Err(format!("读响应头: {e}")),
        }
    };

    let head = String::from_utf8_lossy(&buf[..head_end]).to_string();
    let mut lines = head.lines();
    let status_line = lines.next().ok_or("空响应")?;
    let status: u16 = status_line
        .split_whitespace()
        .nth(1)
        .and_then(|s| s.parse().ok())
        .ok_or_else(|| format!("状态行无法解析: {status_line}"))?;

    let mut headers: Vec<(String, String)> = Vec::new();
    for line in lines {
        if let Some((k, v)) = line.split_once(':') {
            headers.push((k.trim().to_string(), v.trim().to_string()));
        }
    }

    let mut body_bytes: Vec<u8> = buf[head_end..].to_vec();
    let chunked = headers
        .iter()
        .any(|(k, v)| k.eq_ignore_ascii_case("transfer-encoding") && v.contains("chunked"));
    let content_length: Option<usize> = headers
        .iter()
        .find(|(k, _)| k.eq_ignore_ascii_case("content-length"))
        .and_then(|(_, v)| v.parse().ok());

    // 读 body（最多 32MB 保护）
    loop {
        let done = if chunked {
            chunked_complete(&body_bytes)
        } else if let Some(len) = content_length {
            body_bytes.len() >= len
        } else {
            false
        };
        if done || body_bytes.len() > 32 << 20 {
            break;
        }
        match tls.read(&mut tmp) {
            Ok(0) => break,
            Ok(n) => body_bytes.extend_from_slice(&tmp[..n]),
            Err(_) => break,
        }
    }

    let body = if chunked {
        decode_chunked(&body_bytes)
    } else if let Some(len) = content_length {
        body_bytes.truncate(len.min(body_bytes.len()));
        body_bytes
    } else {
        body_bytes
    };

    Ok(Tls13Response {
        status,
        headers,
        body,
    })
}

fn find_head_end(buf: &[u8]) -> Option<usize> {
    buf.windows(4).position(|w| w == b"\r\n\r\n").map(|i| i + 4)
}

fn split_url(url: &str) -> Result<(String, u16, String), String> {
    let rest = url
        .strip_prefix("https://")
        .or_else(|| url.strip_prefix("http://"))
        .ok_or_else(|| format!("只支持 http(s):// URL: {url}"))?;
    let (authority, path) = match rest.find('/') {
        Some(i) => (&rest[..i], &rest[i..]),
        None => (rest, "/"),
    };
    let (host, port) = match authority.rsplit_once(':') {
        Some((h, p)) => (
            h.to_string(),
            p.parse::<u16>().map_err(|_| format!("端口无效: {p}"))?,
        ),
        None => (authority.to_string(), 443),
    };
    Ok((host, port, path.to_string()))
}

fn chunked_complete(buf: &[u8]) -> bool {
    buf.windows(5).any(|w| w == b"0\r\n\r\n")
}

fn decode_chunked(buf: &[u8]) -> Vec<u8> {
    let mut out = Vec::new();
    let mut i = 0usize;
    while i < buf.len() {
        let line_end = match buf[i..].windows(2).position(|w| w == b"\r\n") {
            Some(p) => i + p,
            None => break,
        };
        let size_str = String::from_utf8_lossy(&buf[i..line_end]).to_string();
        let size = match usize::from_str_radix(size_str.trim().split(';').next().unwrap_or(""), 16)
        {
            Ok(0) => break,
            Ok(n) => n,
            Err(_) => break,
        };
        let start = line_end + 2;
        let end = (start + size).min(buf.len());
        out.extend_from_slice(&buf[start..end]);
        i = end + 2;
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn splits_https_url() {
        let (h, p, path) = split_url("https://opencode.ai/inference/v1/models").unwrap();
        assert_eq!(
            (h.as_str(), p, path.as_str()),
            ("opencode.ai", 443, "/inference/v1/models")
        );
    }

    #[test]
    fn splits_url_with_port_and_no_path() {
        let (h, p, path) = split_url("https://example.com:8443").unwrap();
        assert_eq!((h.as_str(), p, path.as_str()), ("example.com", 8443, "/"));
    }

    #[test]
    fn decodes_chunked_body() {
        let raw = b"5\r\nhello\r\n6\r\n world\r\n0\r\n\r\n";
        assert_eq!(decode_chunked(raw), b"hello world");
    }
}
