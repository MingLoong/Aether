//! 库 API 冒烟：connect() 建连后直接发 HTTP，验证收成库后仍然可用。

use std::io::{Read, Write};

fn main() {
    let mut args = std::env::args().skip(1);
    let host = args.next().unwrap_or_else(|| "opencode.ai".into());
    let port: u16 = args.next().and_then(|p| p.parse().ok()).unwrap_or(443);
    let path = args.next().unwrap_or_else(|| "/inference/v1/models".into());

    let mut tls = aether_tls_hello::tls13::connect(&host, port).expect("握手失败");
    println!("握手完成（含证书校验）");

    let req = format!(
        "GET {path} HTTP/1.1\r\nHost: {host}\r\nAuthorization: Bearer public\r\nAccept: */*\r\nUser-Agent: opencode/1.19.4\r\nConnection: close\r\n\r\n"
    );
    tls.write_all(req.as_bytes()).expect("写请求失败");
    tls.flush().ok();

    let mut out = Vec::new();
    let mut buf = [0u8; 4096];
    loop {
        match tls.read(&mut buf) {
            Ok(0) => break,
            Ok(n) => {
                out.extend_from_slice(&buf[..n]);
                if out.len() > 8192 {
                    break;
                }
            }
            Err(e) => {
                println!("读失败: {e}");
                break;
            }
        }
    }
    let text = String::from_utf8_lossy(&out);
    println!("第一行: {}", text.lines().next().unwrap_or("(空)"));
}
