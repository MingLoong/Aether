//! rustls 栈探针：用与网关完全相同的 reqwest(rustls) 发已知可通的 opencode 请求。
//! 用法: cargo run -p aether-http --example rustls_probe
//!
//! 期望对照：Go(crypto/tls)/curl(OpenSSL)/浏览器(BoringSSL) 打同一请求均 200，
//! 若此处 rustls → 403 FreeTierError，则证明上游按 TLS 栈(JA3/JA4)放行。
use std::time::{SystemTime, UNIX_EPOCH};

const ALNUM: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789";

const BODY: &str = r#"{"model":"big-pickle","messages":[{"role":"user","content":"Hello! This is a test message."}],"max_tokens":30,"stream":true,"stream_options":{"include_usage":true},"tools":[{"type":"function","function":{"name":"bash","description":"Run a shell command","parameters":{"type":"object","properties":{"command":{"type":"string"}},"required":["command"]}}},{"type":"function","function":{"name":"glob","description":"Find files","parameters":{"type":"object","properties":{"pattern":{"type":"string"}},"required":["pattern"]}}},{"type":"function","function":{"name":"grep","description":"Search file contents with a regular expression","parameters":{"type":"object","properties":{"pattern":{"type":"string"}},"required":["pattern"]}}},{"type":"function","function":{"name":"read","description":"Read the contents of a file","parameters":{"type":"object","properties":{"file_path":{"type":"string"}},"required":["file_path"]}}}]}"#;

fn session_id(prefix: &str) -> String {
    let ms = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_millis() as u64;
    let v = !(ms.wrapping_mul(0x1000)) & 0xFFFFFFFFFFFF;
    let hex = format!("{v:012x}");
    let tail: String = (0..14)
        .map(|i| {
            let nanos = SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .subsec_nanos() as usize;
            ALNUM[(nanos + i * 7919) % ALNUM.len()] as char
        })
        .collect();
    format!("{prefix}_{hex}{tail}")
}

async fn probe(label: &str, http1_only: bool) {
    let url = "https://opencode.ai/inference/v1/chat/completions";
    let mut builder = reqwest::Client::builder();
    if http1_only {
        builder = builder.http1_only();
    }
    let client = builder.build().expect("client build");
    let sid = session_id("ses");
    let resp = client
        .post(url)
        .header("content-type", "application/json")
        .header("accept", "*/*")
        .header("authorization", "Bearer public")
        .header(
            "user-agent",
            "opencode/1.19.0 ai-sdk/provider-utils/4.0.23 runtime/bun/1.3.14",
        )
        .header("x-opencode-client", "cli")
        .header("x-opencode-project", "global")
        .header("x-opencode-request", session_id("msg"))
        .header("x-opencode-session", sid.as_str())
        .header("x-opencode-session-id", sid.as_str())
        .body(BODY.to_string())
        .send()
        .await;
    match resp {
        Ok(r) => {
            let status = r.status().as_u16();
            let text = r.text().await.unwrap_or_default();
            println!(
                "  {:28} -> {}  {}",
                label,
                status,
                text.chars().take(80).collect::<String>().replace('\n', " ")
            );
        }
        Err(e) => println!("  {label:28} -> 错误 {e}"),
    }
}

#[tokio::main]
async fn main() {
    probe("reqwest+rustls h2(默认)", false).await;
    probe("reqwest+rustls http1_only", true).await;
}
