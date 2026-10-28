//! opencode 专用 TLS 1.3 出站通道。
//!
//! 两条路，共用同一套「建连 → 握手 → 发请求 → 读响应头」：
//!
//! - [`send`]：读完整个响应体再返回。给非流式（sync）执行路径用。
//! - [`send_stream`]：读完响应头就返回，响应体由后台 blocking 线程按块推进 channel。
//!   流式请求必须走这条：走 `send` 的话首字节要等上游把整段生成完，
//!   客户端全程白屏，观感就是「回复很慢」。
//!
//! 背景见 `docs/opencode-tls13-egress.md`。

use std::io::{Read, Write};
use std::time::{Duration, Instant};

/// 流式 body 读取的空闲上限。上游生成慢时要留够时间，但不能无限挂着。
const STREAM_READ_TIMEOUT: Duration = Duration::from_secs(300);
/// body 分块 channel 容量：够吸收突发，又不会把整个响应攒进内存。
const STREAM_CHANNEL_CAPACITY: usize = 16;
/// 非流式路径的响应体上限，防上游失控。
const BUFFERED_BODY_LIMIT: usize = 32 << 20;

/// 一次 TLS 13 出站请求的结果（响应体已整段读完）。
pub(crate) struct Tls13Response {
    pub status: u16,
    pub headers: Vec<(String, String)>,
    pub body: Vec<u8>,
    /// 本次用的出口名（direct 表示直连）。
    pub exit_name: String,
    /// 出口侧实际使用的源地址（SOCKS5 BND.ADDR）。有它才能把上游 429/403 归因到具体 IP。
    pub exit_ip: Option<String>,
}

impl Tls13Response {
    pub(crate) fn header(&self, name: &str) -> Option<&str> {
        header_value(&self.headers, name)
    }
}

/// 流式出站响应：响应头已就绪，body 通过 channel 增量到达。
///
/// `body` 收到 `None` 表示正常结束，收到 `Err` 表示中途失败（其后不会再有数据）。
pub(crate) struct Tls13StreamResponse {
    pub status: u16,
    pub headers: Vec<(String, String)>,
    pub exit_name: String,
    pub exit_ip: Option<String>,
    pub body: tokio::sync::mpsc::Receiver<Result<Vec<u8>, String>>,
}

impl Tls13StreamResponse {
    pub(crate) fn header(&self, name: &str) -> Option<&str> {
        header_value(&self.headers, name)
    }
}

fn header_value<'a>(headers: &'a [(String, String)], name: &str) -> Option<&'a str> {
    headers
        .iter()
        .find(|(k, _)| k.eq_ignore_ascii_case(name))
        .map(|(_, v)| v.as_str())
}

/// 响应头的解析结果。
struct Tls13Head {
    status: u16,
    headers: Vec<(String, String)>,
    exit_name: String,
    exit_ip: Option<String>,
    mode: BodyMode,
}

/// 响应体的边界形式。
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
enum BodyMode {
    Chunked,
    Length(usize),
    UntilEof,
}

/// 用 TLS 13 通道发一条 HTTP/1.1 请求，等整段响应读完再返回。
pub(crate) async fn send(
    url: &str,
    method: &str,
    headers: &[(String, String)],
    body: Vec<u8>,
    provider_id: &str,
) -> Result<Tls13Response, String> {
    let url = url.to_string();
    let method = method.to_string();
    let headers = headers.to_vec();
    let provider_id = provider_id.to_string();
    tokio::task::spawn_blocking(move || send_blocking(&url, &method, &headers, body, &provider_id))
        .await
        .map_err(|e| format!("tls13 task join: {e}"))?
}

/// 用 TLS 13 通道发一条 HTTP/1.1 请求，读完响应头就返回，响应体随后按块到达。
pub(crate) async fn send_stream(
    url: &str,
    method: &str,
    headers: &[(String, String)],
    body: Vec<u8>,
    provider_id: &str,
) -> Result<Tls13StreamResponse, String> {
    let url = url.to_string();
    let method = method.to_string();
    let headers = headers.to_vec();
    let provider_id = provider_id.to_string();
    let (head_tx, head_rx) = tokio::sync::oneshot::channel::<Result<Tls13Head, String>>();
    let (body_tx, body_rx) =
        tokio::sync::mpsc::channel::<Result<Vec<u8>, String>>(STREAM_CHANNEL_CAPACITY);

    tokio::task::spawn_blocking(move || {
        stream_blocking(
            &url,
            &method,
            &headers,
            body,
            &provider_id,
            head_tx,
            body_tx,
        );
    });

    let head = head_rx
        .await
        .map_err(|e| format!("tls13 流式任务提前结束: {e}"))??;
    Ok(Tls13StreamResponse {
        status: head.status,
        headers: head.headers,
        exit_name: head.exit_name,
        exit_ip: head.exit_ip,
        body: body_rx,
    })
}

fn send_blocking(
    url: &str,
    method: &str,
    headers: &[(String, String)],
    body: Vec<u8>,
    provider_id: &str,
) -> Result<Tls13Response, String> {
    let started = Instant::now();
    let (mut tls, head, leftover) = open_request(url, method, headers, &body, provider_id, None)?;

    let mut raw = leftover;
    let mut tmp = [0u8; 16384];
    loop {
        let done = match head.mode {
            BodyMode::Chunked => chunked_complete(&raw),
            BodyMode::Length(len) => raw.len() >= len,
            BodyMode::UntilEof => false,
        };
        if done || raw.len() > BUFFERED_BODY_LIMIT {
            break;
        }
        match tls.read(&mut tmp) {
            Ok(0) => break,
            Ok(n) => raw.extend_from_slice(&tmp[..n]),
            Err(_) => break,
        }
    }

    let body = match head.mode {
        BodyMode::Chunked => decode_chunked(&raw),
        BodyMode::Length(len) => {
            raw.truncate(len.min(raw.len()));
            raw
        }
        BodyMode::UntilEof => raw,
    };

    let response = Tls13Response {
        status: head.status,
        headers: head.headers,
        body,
        exit_name: head.exit_name,
        exit_ip: head.exit_ip,
    };
    log_request_outcome(provider_id, url, &response, started.elapsed());
    Ok(response)
}

/// 后台线程：读头 → 交出头部 → 把 body 一块块推进 channel。
fn stream_blocking(
    url: &str,
    method: &str,
    headers: &[(String, String)],
    body: Vec<u8>,
    provider_id: &str,
    head_tx: tokio::sync::oneshot::Sender<Result<Tls13Head, String>>,
    body_tx: tokio::sync::mpsc::Sender<Result<Vec<u8>, String>>,
) {
    let started = Instant::now();
    // 流式 body 可能长时间没有新数据（模型在思考），读超时按体的标准放宽。
    let (mut tls, head, leftover) = match open_request(
        url,
        method,
        headers,
        &body,
        provider_id,
        Some(STREAM_READ_TIMEOUT),
    ) {
        Ok(parts) => parts,
        Err(error) => {
            let _ = head_tx.send(Err(error));
            return;
        }
    };
    let mode = head.mode;
    log_head(provider_id, url, &head, started.elapsed());
    if head_tx.send(Ok(head)).is_err() {
        // 调用方已经放弃（例如首字节超时），没必要继续拉 body。
        return;
    }

    match pump_body(&mut tls, &body_tx, mode, leftover) {
        Ok(bytes) => tracing::debug!(
            provider_id,
            bytes,
            dur_ms = started.elapsed().as_millis() as u64,
            "opencode 出站流结束"
        ),
        Err(error) => {
            let _ = body_tx.blocking_send(Err(error));
        }
    }
}

/// 一次性的建连：拨号 → TLS 握手 → 发请求 → 读响应头。
fn open_request(
    url: &str,
    method: &str,
    headers: &[(String, String)],
    body: &[u8],
    provider_id: &str,
    read_timeout: Option<Duration>,
) -> Result<(aether_tls_hello::tls13::TlsStream, Tls13Head, Vec<u8>), String> {
    let (host, port, path) = split_url(url)?;
    // TCP 可以走 SOCKS5 出口（HE IPv6），TLS 握手仍在这里本地完成，指纹不变。
    let dialed = super::opencode_egress::dial(&host, port, provider_id)?;
    let exit_name = dialed.exit_name;
    let exit_ip = dialed.exit_ip;
    if let Some(timeout) = read_timeout {
        dialed.stream.set_read_timeout(Some(timeout)).ok();
    }
    let mut tls = aether_tls_hello::tls13::connect_over(dialed.stream, &host).map_err(|e| {
        // TLS 都没握上：这次失败的归属只能记到出口名上，没有 BND.ADDR 之外的线索。
        tracing::warn!(
            provider_id,
            exit = exit_name.as_str(),
            exit_ip = exit_ip.as_deref().unwrap_or(""),
            host,
            error = %e,
            "opencode 出站 TLS 握手失败"
        );
        e
    })?;

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
    payload.extend_from_slice(body);

    tls.write_all(&payload)
        .map_err(|e| format!("写请求: {e}"))?;
    tls.flush().ok();

    let (status, response_headers, leftover) = read_head(&mut tls)?;
    let mode = body_mode(&response_headers);
    Ok((
        tls,
        Tls13Head {
            status,
            headers: response_headers,
            exit_name,
            exit_ip,
            mode,
        },
        leftover,
    ))
}

fn body_mode(headers: &[(String, String)]) -> BodyMode {
    if headers.iter().any(|(k, v)| {
        k.eq_ignore_ascii_case("transfer-encoding") && v.to_ascii_lowercase().contains("chunked")
    }) {
        return BodyMode::Chunked;
    }
    if let Some(len) = headers
        .iter()
        .find(|(k, _)| k.eq_ignore_ascii_case("content-length"))
        .and_then(|(_, v)| v.trim().parse::<usize>().ok())
    {
        return BodyMode::Length(len);
    }
    BodyMode::UntilEof
}

/// 读完响应头，返回 (状态码, 头, 已经读到的 body 开头部分)。
fn read_head(
    tls: &mut aether_tls_hello::tls13::TlsStream,
) -> Result<(u16, Vec<(String, String)>, Vec<u8>), String> {
    let mut buf: Vec<u8> = Vec::new();
    let mut tmp = [0u8; 8192];
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
    Ok((status, headers, buf[head_end..].to_vec()))
}

/// 把 body 一块块推给 channel，返回推出去的总字节数。
///
/// 接收方提前关闭（客户端断开 / 首字节超时）时立即停止并返回已推字节数——
/// 没人要的数据没必要继续从上游拉。
fn pump_body(
    tls: &mut aether_tls_hello::tls13::TlsStream,
    body_tx: &tokio::sync::mpsc::Sender<Result<Vec<u8>, String>>,
    mode: BodyMode,
    leftover: Vec<u8>,
) -> Result<u64, String> {
    let mut total: u64 = 0;
    let mut tmp = vec![0u8; 16 * 1024];
    match mode {
        BodyMode::Chunked => {
            let mut decoder = ChunkedDecoder::new(leftover);
            loop {
                let ready = decoder.take_ready();
                if !ready.is_empty() {
                    total += ready.len() as u64;
                    if body_tx.blocking_send(Ok(ready)).is_err() {
                        return Ok(total);
                    }
                }
                if decoder.finished() {
                    break;
                }
                match tls.read(&mut tmp) {
                    Ok(0) => break,
                    Ok(n) => decoder.push(&tmp[..n]),
                    Err(e) => return Err(format!("读响应体: {e}")),
                }
            }
        }
        BodyMode::Length(len) => {
            let mut remaining = len;
            let mut emit = |bytes: &[u8], total: &mut u64, remaining: &mut usize| -> bool {
                let take = bytes.len().min(*remaining);
                if take == 0 {
                    return *remaining > 0;
                }
                *remaining -= take;
                *total += take as u64;
                if body_tx.blocking_send(Ok(bytes[..take].to_vec())).is_err() {
                    return false;
                }
                *remaining > 0
            };
            if !emit(&leftover, &mut total, &mut remaining) {
                return Ok(total);
            }
            while remaining > 0 {
                match tls.read(&mut tmp) {
                    Ok(0) => break,
                    Ok(n) => {
                        if !emit(&tmp[..n], &mut total, &mut remaining) {
                            break;
                        }
                    }
                    Err(e) => return Err(format!("读响应体: {e}")),
                }
            }
        }
        BodyMode::UntilEof => {
            if !leftover.is_empty() {
                total += leftover.len() as u64;
                if body_tx.blocking_send(Ok(leftover)).is_err() {
                    return Ok(total);
                }
            }
            loop {
                match tls.read(&mut tmp) {
                    Ok(0) => break,
                    Ok(n) => {
                        total += n as u64;
                        if body_tx.blocking_send(Ok(tmp[..n].to_vec())).is_err() {
                            return Ok(total);
                        }
                    }
                    Err(e) => return Err(format!("读响应体: {e}")),
                }
            }
        }
    }
    Ok(total)
}

/// 增量 chunked 解码：数据一段段喂进来，能解出来的立刻吐出去。
struct ChunkedDecoder {
    buf: Vec<u8>,
    done: bool,
}

impl ChunkedDecoder {
    fn new(initial: Vec<u8>) -> Self {
        Self {
            buf: initial,
            done: false,
        }
    }

    fn push(&mut self, data: &[u8]) {
        self.buf.extend_from_slice(data);
    }

    fn finished(&self) -> bool {
        self.done
    }

    /// 取出当前能完整解出的所有字节，剩下的半包留在 `buf` 里等下次。
    fn take_ready(&mut self) -> Vec<u8> {
        let mut out = Vec::new();
        loop {
            if self.done {
                self.buf.clear();
                break;
            }
            let Some(line_end) = find_crlf(&self.buf) else {
                break;
            };
            let size_text = String::from_utf8_lossy(&self.buf[..line_end]).to_string();
            let size =
                match usize::from_str_radix(size_text.trim().split(';').next().unwrap_or(""), 16) {
                    Ok(size) => size,
                    Err(_) => {
                        // 上游给了非法的 chunk 头：当作结束，避免无限等待。
                        self.done = true;
                        self.buf.clear();
                        break;
                    }
                };
            if size == 0 {
                self.done = true;
                self.buf.clear();
                break;
            }
            let start = line_end + 2;
            if self.buf.len() < start + size + 2 {
                break;
            }
            out.extend_from_slice(&self.buf[start..start + size]);
            self.buf.drain(..start + size + 2);
        }
        out
    }
}

fn find_crlf(buf: &[u8]) -> Option<usize> {
    buf.windows(2).position(|w| w == b"\r\n")
}

fn log_head(provider_id: &str, url: &str, head: &Tls13Head, ttfb: Duration) {
    let ttfb_ms = ttfb.as_millis() as u64;
    let exit_ip = head.exit_ip.as_deref().unwrap_or("");
    // 200 走 info，其余走 warn：出问题时默认日志级别就能看到是哪个 IP。
    if head.status == 200 {
        tracing::info!(
            provider_id,
            exit = head.exit_name.as_str(),
            exit_ip,
            url,
            status = head.status,
            ttfb_ms,
            stream = true,
            "opencode 出站请求"
        );
    } else {
        tracing::warn!(
            provider_id,
            exit = head.exit_name.as_str(),
            exit_ip,
            url,
            status = head.status,
            ttfb_ms,
            stream = true,
            "opencode 出站请求"
        );
    }
}

fn log_request_outcome(provider_id: &str, url: &str, response: &Tls13Response, elapsed: Duration) {
    let dur_ms = elapsed.as_millis() as u64;
    let exit_ip = response.exit_ip.as_deref().unwrap_or("");
    if response.status == 200 {
        tracing::info!(
            provider_id,
            exit = response.exit_name.as_str(),
            exit_ip,
            url,
            status = response.status,
            dur_ms,
            stream = false,
            "opencode 出站请求"
        );
    } else {
        tracing::warn!(
            provider_id,
            exit = response.exit_name.as_str(),
            exit_ip,
            url,
            status = response.status,
            dur_ms,
            stream = false,
            "opencode 出站请求"
        );
    }
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

    #[test]
    fn picks_body_mode_from_headers() {
        assert_eq!(
            body_mode(&[("Transfer-Encoding".to_string(), "chunked".to_string())]),
            BodyMode::Chunked
        );
        assert_eq!(
            body_mode(&[("Content-Length".to_string(), "42".to_string())]),
            BodyMode::Length(42)
        );
        assert_eq!(body_mode(&[]), BodyMode::UntilEof);
    }

    #[test]
    fn chunked_decoder_handles_split_boundaries() {
        // 模拟网络把同一个 chunk 拆成多次到达：解码器不能提前吐出半包数据。
        let mut decoder = ChunkedDecoder::new(Vec::new());
        assert!(decoder.take_ready().is_empty());
        decoder.push(b"5\r\nhe");
        assert!(decoder.take_ready().is_empty());
        decoder.push(b"llo\r\n");
        assert_eq!(decoder.take_ready(), b"hello".to_vec());
        decoder.push(b"6\r\n wor");
        assert!(decoder.take_ready().is_empty());
        decoder.push(b"ld\r\n0\r\n\r\n");
        assert_eq!(decoder.take_ready(), b" world".to_vec());
        assert!(decoder.finished());
    }

    #[test]
    fn chunked_decoder_emits_multiple_chunks_at_once() {
        let mut decoder = ChunkedDecoder::new(b"3\r\nabc\r\n3\r\ndef\r\n0\r\n\r\n".to_vec());
        assert_eq!(decoder.take_ready(), b"abcdef".to_vec());
        assert!(decoder.finished());
    }

    #[test]
    fn chunked_decoder_stops_on_bad_size_line() {
        let mut decoder = ChunkedDecoder::new(b"zz\r\nabc\r\n".to_vec());
        assert!(decoder.take_ready().is_empty());
        assert!(decoder.finished());
    }
}
