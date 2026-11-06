use std::collections::BTreeMap;
use std::io::{Cursor, Read};
use std::time::Duration;

use base64::Engine as _;
use flate2::read::{GzDecoder, ZlibDecoder};
use serde::Deserialize;
use serde_json::{Map, Value};
use url::Url;

const ECHO_REQUEST_HEADER: &str = "x-aether-echo";
const ECHO_TRACE_HEADER: &str = "x-aether-trace-id";
pub(crate) const ECHO_RESPONSE_HEADER: &str = "x-aether-provider-request-headers";
const MAX_DECODED_BYTES: usize = 64 * 1024;
const MAX_BODY_BYTES: usize = 64 * 1024 * 1024;
const FETCH_TIMEOUT: Duration = Duration::from_secs(3);

#[derive(Debug, Deserialize)]
struct EchoPayload {
    v: u8,
    #[serde(default)]
    trace_id: String,
    headers: BTreeMap<String, String>,
    #[serde(default)]
    body_mode: Option<String>,
    #[serde(default)]
    body_encoding: Option<String>,
    #[serde(default)]
    body_rewritten: Option<bool>,
    #[serde(default)]
    body_diff: Option<Value>,
    #[serde(default)]
    body_inline_b64: Option<String>,
    #[serde(default)]
    body_stage_id: Option<String>,
    #[serde(default)]
    body_stage_exp: Option<i64>,
    #[serde(default)]
    body_stage_sig: Option<String>,
}

fn decode_echo_payload(
    response_headers: &BTreeMap<String, String>,
    expected_trace_id: &str,
) -> Option<EchoPayload> {
    let encoded = response_headers
        .iter()
        .find(|(name, _)| name.eq_ignore_ascii_case(ECHO_RESPONSE_HEADER))
        .map(|(_, value)| value.trim())?;
    if encoded.len() > 16 * 1024 || expected_trace_id.trim().is_empty() {
        return None;
    }
    let compressed = base64::engine::general_purpose::URL_SAFE_NO_PAD
        .decode(encoded)
        .ok()?;
    let mut decoder = ZlibDecoder::new(Cursor::new(compressed));
    let mut decoded = Vec::new();
    decoder
        .take((MAX_DECODED_BYTES + 1) as u64)
        .read_to_end(&mut decoded)
        .ok()?;
    if decoded.len() > MAX_DECODED_BYTES {
        return None;
    }
    let payload: EchoPayload = serde_json::from_slice(&decoded).ok()?;
    if !(payload.v == 1 || payload.v == 2)
        || payload.trace_id != expected_trace_id
        || payload.headers.is_empty()
    {
        return None;
    }
    if payload.headers.keys().any(|name| {
        name.eq_ignore_ascii_case(ECHO_RESPONSE_HEADER)
            || name.eq_ignore_ascii_case(ECHO_REQUEST_HEADER)
            || name.eq_ignore_ascii_case(ECHO_TRACE_HEADER)
    }) {
        return None;
    }
    Some(payload)
}

pub(crate) fn parse_echo_headers(
    response_headers: &BTreeMap<String, String>,
    expected_trace_id: &str,
) -> Option<BTreeMap<String, String>> {
    decode_echo_payload(response_headers, expected_trace_id).map(|payload| payload.headers)
}

pub(crate) fn remove_echo_response_header(headers: &mut BTreeMap<String, String>) {
    headers.retain(|name, _| !name.eq_ignore_ascii_case(ECHO_RESPONSE_HEADER));
}

/// 解析回执并把「上游实收」覆盖进 report context：
/// 请求头 → `provider_request_headers`，请求体 → `provider_request_body`（与请求头同一条路）。
pub(crate) async fn attach_echo_to_report_context(
    report_context: Option<Value>,
    response_headers: &BTreeMap<String, String>,
    expected_trace_id: &str,
    upstream_url: Option<&str>,
) -> Option<Value> {
    let parsed = decode_echo_payload(response_headers, expected_trace_id);
    let mut object = match report_context {
        Some(Value::Object(object)) => object,
        Some(other) => Map::from_iter([("seed".to_string(), other)]),
        None => Map::new(),
    };
    let Some(payload) = parsed else {
        object
            .entry("provider_headers_source".to_string())
            .or_insert_with(|| Value::String("local".into()));
        return Some(Value::Object(object));
    };
    object.insert(
        "provider_request_headers".to_string(),
        serde_json::json!(payload.headers.clone()),
    );
    object.insert(
        "provider_headers_source".to_string(),
        Value::String("upstream_echo".into()),
    );

    let body_decoded = decode_echo_body(&payload, upstream_url, expected_trace_id).await;
    if let Some(bytes) = body_decoded {
        if let Ok(value) = serde_json::from_slice::<Value>(&bytes) {
            object.insert("provider_request_body".to_string(), value);
            if let Some(rewritten) = payload.body_rewritten {
                object.insert(
                    "provider_body_rewritten".to_string(),
                    Value::Bool(rewritten),
                );
            }
            if let Some(diff) = payload.body_diff.clone() {
                object.insert("provider_body_diff".to_string(), diff);
            }
        }
    }
    Some(Value::Object(object))
}

/// 旧入口：只处理请求头（保留给不关心 body 的调用点与测试）。
pub(crate) fn attach_echo_headers_to_report_context(
    report_context: Option<Value>,
    response_headers: &BTreeMap<String, String>,
    expected_trace_id: &str,
) -> Option<Value> {
    let parsed = decode_echo_payload(response_headers, expected_trace_id);
    let mut object = match report_context {
        Some(Value::Object(object)) => object,
        Some(other) => Map::from_iter([("seed".to_string(), other)]),
        None => Map::new(),
    };
    if let Some(payload) = parsed {
        object.insert(
            "provider_request_headers".to_string(),
            serde_json::json!(payload.headers),
        );
        object.insert(
            "provider_headers_source".to_string(),
            Value::String("upstream_echo".into()),
        );
    } else {
        object
            .entry("provider_headers_source".to_string())
            .or_insert_with(|| Value::String("local".into()));
    }
    Some(Value::Object(object))
}

async fn decode_echo_body(
    payload: &EchoPayload,
    upstream_url: Option<&str>,
    trace_id: &str,
) -> Option<Vec<u8>> {
    let raw = match payload.body_mode.as_deref() {
        Some("inline") => {
            let encoded = payload.body_inline_b64.as_deref()?;
            base64::engine::general_purpose::STANDARD_NO_PAD
                .decode(encoded.trim())
                .or_else(|_| base64::engine::general_purpose::STANDARD.decode(encoded.trim()))
                .ok()?
        }
        Some("staged") => {
            let origin = upstream_origin(upstream_url?)?;
            fetch_staged_body(&origin, payload, trace_id).await?
        }
        _ => return None,
    };
    if raw.len() > MAX_BODY_BYTES {
        return None;
    }
    if payload.body_encoding.as_deref() == Some("gzip") {
        return gunzip(&raw);
    }
    Some(raw)
}

fn upstream_origin(url: &str) -> Option<String> {
    let parsed = Url::parse(url).ok()?;
    Some(format!("{}://{}", parsed.scheme(), parsed.authority()))
}

async fn fetch_staged_body(origin: &str, payload: &EchoPayload, trace_id: &str) -> Option<Vec<u8>> {
    let id = payload.body_stage_id.as_deref()?;
    let exp = payload.body_stage_exp?;
    let sig = payload.body_stage_sig.as_deref()?;
    let url = format!("{origin}/_aether/echo/body/{id}?exp={exp}&sig={sig}&trace={trace_id}");
    let client = reqwest::Client::builder()
        .timeout(FETCH_TIMEOUT)
        .build()
        .ok()?;
    let response = client.get(url).send().await.ok()?;
    if !response.status().is_success() {
        return None;
    }
    let bytes = response.bytes().await.ok()?.to_vec();
    if bytes.len() > MAX_BODY_BYTES {
        return None;
    }
    if bytes.starts_with(&[0x1f, 0x8b]) {
        return gunzip(&bytes);
    }
    Some(bytes)
}

fn gunzip(raw: &[u8]) -> Option<Vec<u8>> {
    let mut decoder = GzDecoder::new(Cursor::new(raw));
    let mut out = Vec::new();
    decoder
        .take((MAX_BODY_BYTES + 1) as u64)
        .read_to_end(&mut out)
        .ok()?;
    if out.len() > MAX_BODY_BYTES {
        return None;
    }
    Some(out)
}

#[cfg(test)]
mod tests {
    use super::*;
    use flate2::{write::ZlibEncoder, Compression};
    use std::io::Write;

    #[test]
    fn rejects_wrong_trace() {
        let mut headers = BTreeMap::new();
        headers.insert(ECHO_RESPONSE_HEADER.into(), encode("other"));
        assert!(parse_echo_headers(&headers, "expected").is_none());
    }

    #[test]
    fn accepts_sanitized_echo() {
        let mut headers = BTreeMap::new();
        headers.insert(ECHO_RESPONSE_HEADER.into(), encode("trace-1"));
        let parsed = parse_echo_headers(&headers, "trace-1").unwrap();
        assert_eq!(parsed.get("authorization").unwrap(), "Bearer sk-****");
    }

    #[test]
    fn inline_body_is_decoded_into_provider_request_body() {
        let inline =
            base64::engine::general_purpose::STANDARD.encode(br#"{"model":"hy3","stream":true}"#);
        let raw = serde_json::json!({
            "v": 2,
            "trace_id": "trace-2",
            "headers": {"content-type": "application/json"},
            "body_mode": "inline",
            "body_encoding": "identity",
            "body_rewritten": true,
            "body_inline_b64": inline,
        });
        let mut out = ZlibEncoder::new(Vec::new(), Compression::default());
        out.write_all(raw.to_string().as_bytes()).unwrap();
        let encoded =
            base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(out.finish().unwrap());
        let mut headers = BTreeMap::new();
        headers.insert(ECHO_RESPONSE_HEADER.into(), encoded);

        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap();
        let context = runtime.block_on(attach_echo_to_report_context(
            None, &headers, "trace-2", None,
        ));
        let context = context.unwrap();
        assert_eq!(context["provider_request_body"]["stream"], true);
    }

    fn encode(trace_id: &str) -> String {
        let raw = serde_json::json!({"v":1,"trace_id":trace_id,"headers":{"authorization":"Bearer sk-****","content-type":"application/json"}});
        let mut out = ZlibEncoder::new(Vec::new(), Compression::default());
        out.write_all(raw.to_string().as_bytes()).unwrap();
        base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(out.finish().unwrap())
    }
}
