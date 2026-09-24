//! OpenCode front-proxy IP pool scanning runtime.
//!
//! Each pool key carries one front-proxy exit IP (fixed daily quota); the
//! scanner probes candidate IPs from an explicit CIDR list with a raw TLS
//! connection to `ip:443` (SNI = the upstream domain) followed by a
//! plain-text `GET /zen/v1/models` request, treating 2xx/3xx responses as
//! healthy (`probeUpstreamIP` behaviour from opencode2api).  Healthy new IPs
//! are materialised as pool keys whose `api_key` is the IP literal; stale
//! keys are dropped by a clean pass.
//!
//! This module is self-contained: it only depends on `AppState` data access
//! (provider catalog) and the shared transport constants, so both the admin
//! API handlers and the automatic maintenance worker can call it.

use aether_data_contracts::repository::provider_catalog::StoredProviderCatalogKey;
use serde_json::{json, Value};
use std::collections::{BTreeMap, BTreeSet};
use std::io::{Read, Write};
use std::net::IpAddr;
use std::sync::{Arc, Mutex, OnceLock};
use uuid::Uuid;

use crate::{AppState, GatewayError};

/// Number of seconds to wait for a single probe (TCP + TLS + first byte).
pub(crate) const OPENCODE_PROBE_TIMEOUT_SECS: u64 = 4;
/// Default number of concurrent probes when the config does not specify one.
pub(crate) const OPENCODE_SCAN_DEFAULT_CONCURRENCY: usize = 32;
/// Default CIDR list applied when the provider has no explicit config.
pub(crate) const OPENCODE_SCAN_DEFAULT_CIDRS: &[&str] = &["1.56.100.0/24"];
/// Hard cap on concurrently in-flight probes (safety valve).
pub(crate) const OPENCODE_SCAN_MAX_CONCURRENCY: usize = 128;
/// Maximum number of candidate IPs scanned in a single run.
pub(crate) const OPENCODE_SCAN_MAX_CANDIDATES: usize = 4096;
/// api_formats assigned to IP pool keys created by a scan.
const OPENCODE_POOL_KEY_API_FORMATS: &[&str] = &["openai:chat", "openai:responses"];

/// Configuration for the IP pool scanner, stored on the provider `config`.
#[derive(Clone, Debug, Default, PartialEq, Eq, Hash)]
pub(crate) struct OpenCodeScanConfig {
    /// Explicit CIDR list to probe (e.g. `["1.56.100.0/24"]`).
    pub(crate) cidrs: Vec<String>,
    /// Whether an automatic scan should be scheduled by the maintenance worker.
    pub(crate) auto_enabled: bool,
    /// Hours between automatic scans (0 = disabled even when auto_enabled).
    pub(crate) interval_hours: Option<u32>,
    /// Maximum concurrent probes during a scan.
    pub(crate) concurrency: Option<usize>,
}

/// Live status of the scanner for a provider (in-memory, per gateway process).
#[derive(Clone, Debug, Default)]
pub(crate) struct OpenCodeIpPoolStatus {
    pub(crate) scanning: bool,
    pub(crate) cleaning: bool,
    pub(crate) last_scan_at: Option<String>,
    /// Unix seconds of the last completed scan (used for interval checks).
    pub(crate) last_scan_at_unix_secs: Option<u64>,
    pub(crate) last_scan_targets: u64,
    pub(crate) last_scan_found: u64,
    pub(crate) last_scan_added: u64,
    pub(crate) last_clean_at: Option<String>,
    pub(crate) last_clean_checked: u64,
    pub(crate) last_clean_removed: u64,
}

/// Summary of a completed scan, returned to the API layer for the response.
#[derive(Debug, Default, Clone)]
pub(crate) struct ScanSummary {
    pub(crate) targets: u64,
    pub(crate) found: u64,
    pub(crate) added: u64,
}

/// Summary of a completed clean, returned to the API layer for the response.
#[derive(Debug, Default, Clone)]
pub(crate) struct CleanSummary {
    pub(crate) checked: u64,
    pub(crate) removed: u64,
}

static OPENCODE_IP_POOL_STATUSES: OnceLock<Arc<Mutex<BTreeMap<String, OpenCodeIpPoolStatus>>>> =
    OnceLock::new();

fn opencode_ip_pool_status_map_locked(
) -> std::sync::MutexGuard<'static, BTreeMap<String, OpenCodeIpPoolStatus>> {
    OPENCODE_IP_POOL_STATUSES
        .get_or_init(|| Arc::new(Mutex::new(BTreeMap::new())))
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner())
}

/// Returns the in-memory scanner status for a provider (empty when absent).
pub(crate) fn opencode_ip_pool_status_for(provider_id: &str) -> OpenCodeIpPoolStatus {
    opencode_ip_pool_status_map_locked()
        .get(provider_id)
        .cloned()
        .unwrap_or_default()
}

fn update_opencode_ip_pool_status(
    provider_id: &str,
    patch: impl FnOnce(&mut OpenCodeIpPoolStatus),
) {
    let mut map = opencode_ip_pool_status_map_locked();
    let mut status = map.get(provider_id).cloned().unwrap_or_default();
    patch(&mut status);
    map.insert(provider_id.to_string(), status);
}

impl OpenCodeScanConfig {
    pub(crate) fn from_provider_config(config: &Option<Value>) -> OpenCodeScanConfig {
        match config.as_ref().and_then(Value::as_object) {
            Some(object) => Self::from_provider_config_object(object),
            None => Self::default(),
        }
    }

    /// Reads an `OpenCodeScanConfig` from a JSON object.  When the object
    /// already has an `opencode_scan` section it is used as-is; otherwise the
    /// object is treated as the section itself (used by the PUT config body).
    pub(crate) fn from_provider_config_object(
        object: &serde_json::Map<String, Value>,
    ) -> OpenCodeScanConfig {
        let mut result = Self::default();
        let section = object
            .get("opencode_scan")
            .and_then(Value::as_object)
            .unwrap_or(object);
        if let Some(Value::Array(cidrs)) = section.get("cidrs") {
            result.cidrs = cidrs
                .iter()
                .filter_map(Value::as_str)
                .map(str::trim)
                .filter(|c| !c.is_empty())
                .map(|c| c.to_string())
                .collect();
        }
        if let Some(Value::Bool(enabled)) = section.get("auto_enabled") {
            result.auto_enabled = *enabled;
        }
        if let Some(value) = section.get("interval_hours").and_then(Value::as_u64) {
            result.interval_hours = Some(value as u32);
        }
        if let Some(value) = section.get("concurrency").and_then(Value::as_u64) {
            result.concurrency = Some(value as usize);
        }
        if result.cidrs.is_empty() {
            result.cidrs = OPENCODE_SCAN_DEFAULT_CIDRS
                .iter()
                .map(|c| c.to_string())
                .collect();
        }
        result
    }

    pub(crate) fn to_provider_config_value(&self) -> Value {
        // 返回裸配置对象（不含外层 opencode_scan key），由调用方决定存放位置。
        json!({
            "cidrs": self.cidrs,
            "auto_enabled": self.auto_enabled,
            "interval_hours": self.interval_hours.unwrap_or(0),
            "concurrency": self.concurrency.unwrap_or(OPENCODE_SCAN_DEFAULT_CONCURRENCY),
        })
    }

    pub(crate) fn effective_interval_hours(&self) -> u32 {
        self.interval_hours.unwrap_or(0)
    }

    pub(crate) fn effective_concurrency(&self) -> usize {
        self.concurrency
            .unwrap_or(OPENCODE_SCAN_DEFAULT_CONCURRENCY)
            .clamp(1, OPENCODE_SCAN_MAX_CONCURRENCY)
    }

    /// Enumerates candidate IPs from the configured CIDR list, excluding
    /// addresses already present in `known_ips`.  Skips network/broadcast
    /// addresses (`x.x.x.0` and `x.x.x.255`).
    pub(crate) fn candidate_ips(&self, known_ips: &BTreeSet<String>) -> Vec<String> {
        let mut candidates = BTreeSet::new();
        for cidr in &self.cidrs {
            let Some((prefix, bits)) = parse_cidr(cidr) else {
                continue;
            };
            let host_bits = (32 - bits).max(1);
            let host_count = (1u32 << host_bits.min(30)) as u64;
            let base = prefix as u64;
            for offset in 1..host_count - 1 {
                let value = base + offset;
                let mut octets = [0u8; 4];
                octets[0] = (value >> 24) as u8;
                octets[1] = (value >> 16) as u8;
                octets[2] = (value >> 8) as u8;
                octets[3] = value as u8;
                let ip = format!("{}.{}.{}.{}", octets[0], octets[1], octets[2], octets[3]);
                if !known_ips.contains(&ip) {
                    candidates.insert(ip);
                }
            }
        }
        candidates
            .into_iter()
            .take(OPENCODE_SCAN_MAX_CANDIDATES)
            .collect()
    }
}

/// Parses an IPv4 CIDR (`a.b.c.d/len`) into (network uint32, prefix bits).
/// Returns `None` for invalid input.
pub(crate) fn parse_cidr(cidr: &str) -> Option<(u32, u32)> {
    let Some((addr_part, len_part)) = cidr.split_once('/') else {
        return None;
    };
    let Some(bits) = len_part.trim().parse::<u32>().ok() else {
        return None;
    };
    if bits == 0 || bits > 32 {
        return None;
    }
    let ipv4 = match addr_part.trim().parse::<IpAddr>() {
        Ok(IpAddr::V4(ipv4)) => ipv4,
        _ => return None,
    };
    let value = u32::from(ipv4);
    let mask = if bits == 0 {
        0u32
    } else {
        u32::MAX << (32 - bits)
    };
    Some((value & mask, bits))
}

/// Runs a scan for the given opencode provider: probes configured CIDRs,
/// creates a pool key for each healthy new IP.
pub(crate) async fn run_open_code_pool_scan(
    app: &AppState,
    provider: &aether_data_contracts::repository::provider_catalog::StoredProviderCatalogProvider,
) -> Result<ScanSummary, GatewayError> {
    let provider_id = provider.id.clone();
    let config = OpenCodeScanConfig::from_provider_config(&provider.config);

    if opencode_ip_pool_status_for(&provider_id).scanning {
        return Err(GatewayError::Internal("扫描正在进行中".to_string()));
    }
    update_opencode_ip_pool_status(&provider_id, |status| status.scanning = true);

    let (domain, port) = opencode_upstream_target(app, &provider_id).await?;
    let concurrency = config.effective_concurrency();
    let keys = app
        .list_provider_catalog_keys_by_provider_ids(std::slice::from_ref(&provider_id))
        .await?;
    let known_ips: BTreeSet<String> = keys
        .iter()
        .filter_map(|key| opencode_key_ip(app, key))
        .collect();
    let candidates = config.candidate_ips(&known_ips);
    let target_count = candidates.len() as u64;

    let healthy = probe_ips(&candidates, &domain, port, concurrency).await;
    let healthy_set: BTreeSet<String> = BTreeSet::from_iter(healthy);

    // Create one pool key per healthy new IP.
    let mut added = 0u64;
    for ip in healthy_set {
        if known_ips.contains(&ip) {
            continue;
        }
        if create_ip_pool_key(app, provider, &ip).await.is_ok() {
            added += 1;
        }
    }

    update_opencode_ip_pool_status(&provider_id, |status| {
        status.scanning = false;
        status.last_scan_targets = target_count;
        status.last_scan_found = added;
        status.last_scan_added = added;
        status.last_scan_at = Some(now_string());
        status.last_scan_at_unix_secs = Some(now_unix_secs());
    });
    tracing::info!(
        event_name = "opencode_ip_pool_scan_completed",
        log_type = "ops",
        provider_id,
        targets = target_count,
        added,
        "opencode ip pool scan completed"
    );
    Ok(ScanSummary {
        targets: target_count,
        found: added,
        added,
    })
}

/// Runs a clean pass: probe existing pool-key IPs and delete unhealthy ones.
pub(crate) async fn run_open_code_pool_clean(
    app: &AppState,
    provider: &aether_data_contracts::repository::provider_catalog::StoredProviderCatalogProvider,
) -> Result<CleanSummary, GatewayError> {
    let provider_id = provider.id.clone();
    if opencode_ip_pool_status_for(&provider_id).cleaning {
        return Err(GatewayError::Internal("清理正在进行中".to_string()));
    }
    update_opencode_ip_pool_status(&provider_id, |status| status.cleaning = true);

    let (domain, port) = opencode_upstream_target(app, &provider_id).await?;
    let concurrency =
        OpenCodeScanConfig::from_provider_config(&provider.config).effective_concurrency();
    let keys = app
        .list_provider_catalog_keys_by_provider_ids(std::slice::from_ref(&provider_id))
        .await?;
    let entries: Vec<(String, String)> = keys
        .iter()
        .filter_map(|key| opencode_key_ip(app, key).map(|ip| (key.id.clone(), ip)))
        .collect();
    let checked = entries.len() as u64;

    let ips: Vec<String> = entries.iter().map(|(_, ip)| ip.clone()).collect();
    let healthy_map: BTreeSet<String> =
        BTreeSet::from_iter(probe_ips(&ips, &domain, port, concurrency.min(32)).await);

    let mut removed = 0u64;
    for (key_id, ip) in entries {
        if !healthy_map.contains(&ip) && app.delete_provider_catalog_key(&key_id).await.is_ok() {
            removed += 1;
        }
    }

    update_opencode_ip_pool_status(&provider_id, |status| {
        status.cleaning = false;
        status.last_clean_checked = checked;
        status.last_clean_removed = removed;
        status.last_clean_at = Some(now_string());
    });
    tracing::info!(
        event_name = "opencode_ip_pool_clean_completed",
        log_type = "ops",
        provider_id,
        checked,
        removed,
        "opencode ip pool clean completed"
    );
    Ok(CleanSummary { checked, removed })
}

/// Creates a pool key whose api_key is the given IP literal.  Uses the same
/// storage path as the admin create-key endpoint (sealed credential +
/// `create_provider_catalog_key`), but bypasses the HTTP handler plumbing.
async fn create_ip_pool_key(
    app: &AppState,
    provider: &aether_data_contracts::repository::provider_catalog::StoredProviderCatalogProvider,
    ip: &str,
) -> Result<(), GatewayError> {
    let key_id = Uuid::new_v4().to_string();
    let encrypted_api_key = app
        .seal_provider_catalog_key_api_key(&provider.id, &key_id, ip)
        .map_err(|err| {
            GatewayError::Internal(format!("gateway 未配置 provider key 加密密钥: {err:?}"))
        })?;
    let api_formats = json!(OPENCODE_POOL_KEY_API_FORMATS);
    let mut key = StoredProviderCatalogKey::new(
        key_id,
        provider.id.clone(),
        format!("CDN IP {ip}"),
        "bearer".to_string(),
        None,
        true,
    )
    .map_err(|err| GatewayError::Internal(err.to_string()))?
    .with_transport_fields(
        Some(api_formats),
        Some(encrypted_api_key),
        None,
        None,
        None,
        None,
        None,
        None,
        None,
    )
    .map_err(|err| GatewayError::Internal(err.to_string()))?;
    key.note = Some("opencode ip pool (auto-scanned)".to_string());
    let created = app.create_provider_catalog_key(&key).await?;
    if created.is_none() {
        return Err(GatewayError::Internal(
            "创建池密钥失败：无返回记录".to_string(),
        ));
    }
    Ok(())
}

/// Extracts the IP literal from a pool key's api_key (decrypted).
pub(crate) fn opencode_key_ip(app: &AppState, key: &StoredProviderCatalogKey) -> Option<String> {
    app.decrypt_provider_catalog_key_api_key(key)
        .ok()
        .flatten()
        .map(|value| value.trim().to_string())
        .filter(|value| value.parse::<IpAddr>().is_ok())
}

/// Resolves the upstream domain + port from the provider's endpoints.
pub(crate) async fn opencode_upstream_target(
    app: &AppState,
    provider_id: &str,
) -> Result<(String, u16), GatewayError> {
    let endpoints = app
        .list_provider_catalog_endpoints_by_provider_ids(&[provider_id.to_string()])
        .await?;
    for endpoint in endpoints {
        if let Ok(url) = url::Url::parse(endpoint.base_url.trim()) {
            if let Some(host) = url.host_str() {
                if let Some(port) = url.port_or_known_default() {
                    return Ok((host.to_string(), port));
                }
            }
        }
    }
    Err(GatewayError::Internal(
        "无法从供应商端点解析上游域名/端口，请先配置端点".to_string(),
    ))
}

/// Probes a list of IPs concurrently with a bounded semaphore.
async fn probe_ips(ips: &[String], domain: &str, port: u16, concurrency: usize) -> Vec<String> {
    let sem = Arc::new(tokio::sync::Semaphore::new(concurrency.max(1)));
    let healthy: Arc<tokio::sync::Mutex<Vec<String>>> =
        Arc::new(tokio::sync::Mutex::new(Vec::new()));
    let mut tasks = Vec::new();
    for ip in ips {
        let sem = Arc::clone(&sem);
        let healthy = Arc::clone(&healthy);
        let domain = domain.to_string();
        let ip = ip.clone();
        tasks.push(tokio::spawn(async move {
            let _permit = sem.acquire().await;
            let ok = probe_upstream_ip(&ip, &domain, port, OPENCODE_PROBE_TIMEOUT_SECS)
                .await
                .unwrap_or(false);
            if ok {
                healthy.lock().await.push(ip);
            }
        }));
    }
    for task in tasks {
        let _ = task.await;
    }
    let mut result = Vec::new();
    let guard = healthy.lock().await;
    result = guard.clone();
    result
}

/// Probes a single IP: TLS handshake to `ip:port` with SNI = domain, then a
/// raw `GET /zen/v1/models` request, returning true on 2xx/3xx.  The
/// blocking TLS/HTTP portion runs on a blocking thread.
pub(crate) async fn probe_upstream_ip(
    ip: &str,
    domain: &str,
    port: u16,
    timeout_secs: u64,
) -> Result<bool, GatewayError> {
    let ip = ip.trim().to_string();
    let domain = domain.trim().to_string();
    if ip.parse::<IpAddr>().is_err() {
        return Ok(false);
    }
    let address = match (ip.parse::<IpAddr>(), port) {
        (Ok(IpAddr::V4(v4)), port) => std::net::SocketAddr::new(std::net::IpAddr::V4(v4), port),
        (Ok(IpAddr::V6(v6)), port) => std::net::SocketAddr::new(std::net::IpAddr::V6(v6), port),
        _ => return Ok(false),
    };
    let stream = tokio::time::timeout(std::time::Duration::from_secs(timeout_secs), async {
        tokio::net::TcpStream::connect(address)
            .await
            .map_err(|error| {
                GatewayError::Internal(format!("probe tcp connect failed ({})", error.kind()))
            })
    })
    .await
    .map_err(|_| GatewayError::Internal("probe tcp connect timed out".to_string()))??
    .into_std()
    .map_err(|err| GatewayError::Internal(err.to_string()))?;
    let result = tokio::task::spawn_blocking(move || {
        probe_upstream_ip_blocking(stream, &ip, &domain, port, timeout_secs)
    })
    .await
    .map_err(|err| GatewayError::Internal(err.to_string()))?;
    result
}

fn probe_upstream_ip_blocking(
    stream: std::net::TcpStream,
    ip: &str,
    domain: &str,
    port: u16,
    timeout_secs: u64,
) -> Result<bool, GatewayError> {
    let _ = (ip, port);
    let timeout = std::time::Duration::from_secs(timeout_secs);
    // `tokio::net::TcpStream::into_std()` leaves the socket non-blocking;
    // revert it so the blocking TLS/HTTP probe below can read/write normally.
    stream
        .set_nonblocking(false)
        .map_err(|err| GatewayError::Internal(err.to_string()))?;
    stream
        .set_read_timeout(Some(timeout))
        .map_err(|err| GatewayError::Internal(err.to_string()))?;
    stream
        .set_write_timeout(Some(timeout))
        .map_err(|err| GatewayError::Internal(err.to_string()))?;
    let server_name = match resolve_probe_server_name(domain) {
        Ok(name) => name,
        Err(err) => {
            tracing::warn!(
                event_name = "opencode_probe_server_name_failed",
                log_type = "ops",
                ip,
                domain,
                error = ?err,
                "opencode probe resolve server name failed"
            );
            return Err(GatewayError::Internal(err));
        }
    };
    let tls_config = build_probe_tls_config();
    let connection = match rustls::ClientConnection::new(tls_config, server_name) {
        Ok(conn) => conn,
        Err(err) => {
            tracing::warn!(
                event_name = "opencode_probe_tls_init_failed",
                log_type = "ops",
                ip,
                domain,
                error = ?err,
                "opencode probe tls init failed"
            );
            return Err(GatewayError::Internal(err.to_string()));
        }
    };
    let mut tls_stream = rustls::StreamOwned::new(connection, stream);
    let request = format!(
        "GET /zen/v1/models HTTP/1.1\r\nHost: {domain}\r\nUser-Agent: aether-ip-scanner\r\nConnection: close\r\n\r\n"
    );
    if let Err(err) = tls_stream.write_all(request.as_bytes()) {
        tracing::warn!(
            event_name = "opencode_probe_write_failed",
            log_type = "ops",
            ip,
            domain,
            error = ?err,
            "opencode probe write failed"
        );
        return Err(GatewayError::Internal(format!(
            "probe write failed: {err:?}"
        )));
    }
    let mut status_line = Vec::new();
    let read_ok = match read_probe_status_line(&mut tls_stream, &mut status_line) {
        Ok(ok) => ok,
        Err(err) => {
            tracing::warn!(
                event_name = "opencode_probe_read_failed",
                log_type = "ops",
                ip,
                domain,
                error = ?err,
                status_line = ?String::from_utf8_lossy(&status_line),
                "opencode probe read failed"
            );
            return Err(GatewayError::Internal(err.to_string()));
        }
    };
    if read_ok && !is_healthy_status_line(&status_line) {
        tracing::debug!(
            event_name = "opencode_probe_unhealthy_status",
            log_type = "ops",
            ip,
            domain,
            status_line = ?String::from_utf8_lossy(&status_line),
            "opencode probe unhealthy status line"
        );
    }
    Ok(read_ok && is_healthy_status_line(&status_line))
}

fn resolve_probe_server_name(host: &str) -> Result<rustls::pki_types::ServerName<'static>, String> {
    let host = host.trim().trim_start_matches('[').trim_end_matches(']');
    if let Ok(ip) = host.parse::<IpAddr>() {
        return Ok(rustls::pki_types::ServerName::from(ip));
    }
    rustls::pki_types::ServerName::try_from(host.to_string()).map_err(|err| err.to_string())
}

fn build_probe_tls_config() -> std::sync::Arc<rustls::ClientConfig> {
    let _ = rustls::crypto::ring::default_provider().install_default();
    let root_store =
        rustls::RootCertStore::from_iter(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());
    std::sync::Arc::new(
        rustls::ClientConfig::builder()
            .with_root_certificates(root_store)
            .with_no_client_auth(),
    )
}

/// Reads the first HTTP response line, returning false on EOF/oversize.
fn read_probe_status_line(
    stream: &mut rustls::StreamOwned<rustls::ClientConnection, std::net::TcpStream>,
    out: &mut Vec<u8>,
) -> Result<bool, std::io::Error> {
    let mut byte = [0u8; 1];
    loop {
        let read = stream.read(&mut byte)?;
        if read == 0 {
            return Ok(false);
        }
        if byte[0] == b'\n' {
            return Ok(true);
        }
        out.push(byte[0]);
        if out.len() > 1024 {
            return Ok(false);
        }
    }
}

/// A status line like `HTTP/1.1 200 OK` is healthy when the code starts
/// with `2` or `3`.
fn is_healthy_status_line(status_line: &[u8]) -> bool {
    let Some(space) = status_line.iter().position(|b| *b == b' ') else {
        return false;
    };
    let code_start = space + 1;
    if code_start + 2 >= status_line.len() {
        return false;
    }
    let first = status_line[code_start];
    first == b'2' || first == b'3'
}

fn now_unix_secs() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|duration| duration.as_secs())
        .unwrap_or_default()
}

fn now_string() -> String {
    chrono::Utc::now().to_rfc3339()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn cidr_parsing_handles_valid_and_invalid_input() {
        let Some((network, bits)) = parse_cidr("1.56.100.0/24") else {
            panic!("valid cidr should parse");
        };
        assert_eq!(bits, 24);
        assert_eq!(network, 0x01386400);
        assert_eq!(parse_cidr("not-an-ip/24"), None);
        assert_eq!(parse_cidr("1.2.3.4/33"), None);
        assert_eq!(parse_cidr("1.2.3.4"), None);
        assert_eq!(parse_cidr("1.2.3.4/0"), None);
    }

    #[test]
    fn candidates_exclude_known_and_network_addresses() {
        let mut known = BTreeSet::new();
        known.insert("1.56.100.15".to_string());
        known.insert("1.56.100.1".to_string());
        let config = OpenCodeScanConfig {
            cidrs: vec!["1.56.100.0/30".to_string()],
            auto_enabled: false,
            interval_hours: None,
            concurrency: None,
        };
        let candidates = config.candidate_ips(&known);
        // /30 → host_bits = 2 → offsets 1..2 → 1.56.100.1 and .2, minus .1 → .2
        assert_eq!(candidates, vec!["1.56.100.2".to_string()]);
    }

    #[test]
    fn config_defaults_and_round_trip() {
        let value = OpenCodeScanConfig {
            cidrs: vec!["1.2.3.0/24".to_string()],
            auto_enabled: true,
            interval_hours: Some(6),
            concurrency: Some(16),
        }
        .to_provider_config_value();
        let restored = OpenCodeScanConfig::from_provider_config(&Some(value));
        assert_eq!(restored.cidrs, vec!["1.2.3.0/24".to_string()]);
        assert!(restored.auto_enabled);
        assert_eq!(restored.interval_hours, Some(6));
        assert_eq!(restored.concurrency, Some(16));
    }

    #[test]
    fn status_line_health_classification() {
        assert!(is_healthy_status_line(b"HTTP/1.1 200 OK\r"));
        assert!(is_healthy_status_line(b"HTTP/1.1 302 Found\r"));
        assert!(!is_healthy_status_line(b"HTTP/1.1 404 Not Found\r"));
        assert!(!is_healthy_status_line(b""));
        assert!(!is_healthy_status_line(b"garbage"));
        assert!(!is_healthy_status_line(b"HTTP/1.1 99 nope\r"));
    }

    #[test]
    fn status_map_round_trips() {
        update_opencode_ip_pool_status("p-1", |status| {
            status.last_scan_added = 3;
        });
        assert_eq!(opencode_ip_pool_status_for("p-1").last_scan_added, 3);
        update_opencode_ip_pool_status("p-1", |status| status.scanning = true);
        assert!(opencode_ip_pool_status_for("p-1").scanning);
        assert_eq!(opencode_ip_pool_status_for("p-2").last_scan_added, 0);
    }
}
