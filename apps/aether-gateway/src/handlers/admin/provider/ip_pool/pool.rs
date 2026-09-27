//! OpenCode 前置代理出口 IP 池扫描运行时。
//!
//! 与 MingLoong/Aether 参考实现的关键差异：**出口 IP 的唯一来源是 key 的
//! `upstream_metadata.opencode_exit_ip`**，而不是把 IP 明文塞进 `api_key`。
//! 池 key 的 `api_key` 只是一个唯一占位值（`public-<ip>`），因为 OpenCode 免费层
//! 认证固定为 `Bearer public`，由传输层强制注入。
//!
//! 扫描器从显式 CIDR 列表枚举候选 IP，对 `ip:port` 做裸 TLS 握手（SNI = 上游域名），
//! 再发一条带 OpenCode 指纹的 `GET /zen/v1/models`，2xx/3xx 视为健康；健康的新 IP
//! 会被物化成池 key，清理轮次会删除探测失败的陈旧 key。

use std::collections::{BTreeMap, BTreeSet};
use std::io::{Read, Write};
use std::net::IpAddr;
use std::sync::{Arc, Mutex, OnceLock};

use aether_data_contracts::repository::provider_catalog::{
    StoredProviderCatalogKey, StoredProviderCatalogProvider,
};
use serde_json::{json, Value};
use uuid::Uuid;

use crate::{AppState, GatewayError};

/// 单次探测（TCP + TLS + 首字节）的超时秒数。
pub(crate) const OPENCODE_PROBE_TIMEOUT_SECS: u64 = 4;
/// 未配置时每轮扫描的默认并发。
pub(crate) const OPENCODE_SCAN_DEFAULT_CONCURRENCY: usize = 32;
/// 并发硬上限（安全阀）。
pub(crate) const OPENCODE_SCAN_MAX_CONCURRENCY: usize = 128;
/// 单轮扫描的候选 IP 上限。
pub(crate) const OPENCODE_SCAN_MAX_CANDIDATES: usize = 4096;
/// 池 key 使用的 api_format 集合。
const OPENCODE_POOL_KEY_API_FORMATS: &[&str] = &["openai:chat"];
/// 池 key 的 auth_type（上游认证固定为 Bearer public，与 auth_type 无关）。
const OPENCODE_POOL_KEY_AUTH_TYPE: &str = "api_key";
/// 池 key 的 api_key 占位前缀，必须逐 IP 唯一（同名会触发去重拒绝）。
const OPENCODE_POOL_KEY_API_KEY_PREFIX: &str = "public-";
/// 池 key 上记录出口 IP 的 metadata 字段名。
const OPENCODE_EXIT_IP_METADATA_KEY: &str = "opencode_exit_ip";

/// 扫描配置，存放在 provider `config.opencode_scan`。
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub(crate) struct OpenCodeScanConfig {
    /// 显式 CIDR 列表；为空表示未配置扫描网段。
    pub(crate) cidrs: Vec<String>,
    /// 是否允许维护 worker 自动扫描。
    pub(crate) auto_enabled: bool,
    /// 自动扫描间隔（小时）；`0` 表示即使开启也不自动执行。
    pub(crate) interval_hours: Option<u32>,
    /// 单轮扫描最大并发探测数。
    pub(crate) concurrency: Option<usize>,
    /// 是否启用「最少在途 + 游标轮转」选 key。
    pub(crate) rotation_enabled: bool,
    /// 额度耗尽后的冷却时长（分钟）。
    pub(crate) cooldown_minutes: Option<u32>,
    /// 用户填写过的前置代理域名。持久化后即使开关关闭也保留，
    /// 输入框内容永远由用户决定，不会被开关联动改写。
    pub(crate) proxy_domain: Option<String>,
    /// 前置代理开关。开启时本次请求用 `proxy_domain` 作为 host，
    /// 关闭时用默认的官方域名。**不写回 endpoint.base_url**。
    pub(crate) proxy_enabled: bool,
    /// provider 级出口 IP 池：每次请求从这里挑一个 IP 作为 DNS 锚点。
    /// 与「一个 IP 一个 key」的旧模型不同，这里池子挂在 provider 上，
    /// 密钥管理只需 1 个 key。
    pub(crate) exit_pool: Vec<String>,
    /// provider 级池里被手动停用的 IP（不参与轮转，但仍保留在池中）。
    pub(crate) exit_pool_disabled: Vec<String>,
}

/// 扫描器运行期状态（进程内、按 Provider 维度）。
#[derive(Clone, Debug, Default)]
pub(crate) struct OpenCodeIpPoolStatus {
    pub(crate) scanning: bool,
    pub(crate) cleaning: bool,
    pub(crate) last_scan_at: Option<String>,
    pub(crate) last_scan_at_unix_secs: Option<u64>,
    pub(crate) last_scan_targets: u64,
    pub(crate) last_scan_found: u64,
    pub(crate) last_scan_added: u64,
    pub(crate) last_clean_at: Option<String>,
    pub(crate) last_clean_checked: u64,
    pub(crate) last_clean_removed: u64,
    /// 本轮长任务进度：已探 / 总数。大批量扫描要跑几十分钟，
    /// 没有这两个数面板上只会像卡死。
    pub(crate) progress_done: u64,
    pub(crate) progress_total: u64,
    pub(crate) progress_kind: Option<String>,
}

/// 一轮扫描的结果摘要。
#[derive(Debug, Default, Clone)]
pub(crate) struct ScanSummary {
    pub(crate) targets: u64,
    pub(crate) found: u64,
    pub(crate) added: u64,
}

/// 一轮清理的结果摘要。
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

/// 读取某 Provider 的扫描器状态（缺省返回全零状态）。
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

/// 从 JSON 数组里收集非空字符串（trim 后）。
fn string_list(value: Option<&Value>) -> Vec<String> {
    value
        .and_then(Value::as_array)
        .map(|items| {
            items
                .iter()
                .filter_map(Value::as_str)
                .map(str::trim)
                .filter(|item| !item.is_empty())
                .map(str::to_string)
                .collect()
        })
        .unwrap_or_default()
}

impl OpenCodeScanConfig {
    /// 从 provider 的 `config` 读取扫描配置。
    pub(crate) fn from_provider_config(config: &Option<Value>) -> Self {
        match config.as_ref().and_then(Value::as_object) {
            Some(object) => Self::from_provider_config_object(object),
            None => Self::default(),
        }
    }

    /// 把请求体里**出现的**字段合并到已有配置上。
    ///
    /// PUT config 是部分更新：只改域名不应该把 CIDR、自动扫描、轮转开关、冷却时长
    /// 全部打回默认值。做法是从已存配置出发，逐个检查请求体里有没有对应键。
    pub(crate) fn merged_with_payload(
        existing: &Option<Value>,
        payload: &serde_json::Map<String, Value>,
    ) -> Self {
        let section = payload
            .get("opencode_scan")
            .and_then(Value::as_object)
            .unwrap_or(payload);
        let mut result = Self::from_provider_config(existing);
        if section.contains_key("cidrs") {
            result.cidrs = string_list(section.get("cidrs"));
        }
        if let Some(Value::Bool(enabled)) = section.get("auto_enabled") {
            result.auto_enabled = *enabled;
        }
        if section.contains_key("interval_hours") {
            result.interval_hours = section
                .get("interval_hours")
                .and_then(Value::as_u64)
                .map(|v| v as u32);
        }
        if section.contains_key("concurrency") {
            result.concurrency = section
                .get("concurrency")
                .and_then(Value::as_u64)
                .map(|value| value as usize);
        }
        if let Some(Value::Bool(enabled)) = section.get("rotation_enabled") {
            result.rotation_enabled = *enabled;
        }
        if section.contains_key("cooldown_minutes") {
            result.cooldown_minutes = section
                .get("cooldown_minutes")
                .and_then(Value::as_u64)
                .map(|value| value as u32);
        }
        if section.contains_key("exit_pool") {
            result.exit_pool = string_list(section.get("exit_pool"));
        }
        if section.contains_key("exit_pool_disabled") {
            result.exit_pool_disabled = string_list(section.get("exit_pool_disabled"));
        }
        if let Some(Value::Bool(enabled)) = section.get("proxy_enabled") {
            result.proxy_enabled = *enabled;
        }
        if let Some(Value::String(domain)) = section.get("proxy_domain") {
            let trimmed = domain.trim();
            if !trimmed.is_empty() {
                result.proxy_domain = Some(trimmed.to_string());
            }
        }
        result
    }

    /// 从 JSON 对象读取扫描配置。存在 `opencode_scan` 段时用该段，
    /// 否则把对象本身当作配置段（PUT config 的请求体走这条路径）。
    pub(crate) fn from_provider_config_object(object: &serde_json::Map<String, Value>) -> Self {
        let mut result = Self::default();
        let section = object
            .get("opencode_scan")
            .and_then(Value::as_object)
            .unwrap_or(object);
        result.cidrs = string_list(section.get("cidrs"));
        if let Some(Value::Bool(enabled)) = section.get("auto_enabled") {
            result.auto_enabled = *enabled;
        }
        if let Some(value) = section.get("interval_hours").and_then(Value::as_u64) {
            result.interval_hours = Some(value as u32);
        }
        if let Some(value) = section.get("concurrency").and_then(Value::as_u64) {
            result.concurrency = Some(value as usize);
        }
        if let Some(Value::Bool(enabled)) = section.get("rotation_enabled") {
            result.rotation_enabled = *enabled;
        }
        if let Some(value) = section.get("cooldown_minutes").and_then(Value::as_u64) {
            result.cooldown_minutes = Some(value as u32);
        }
        if let Some(value) = section.get("proxy_domain").and_then(Value::as_str) {
            let trimmed = value.trim();
            if !trimmed.is_empty() {
                result.proxy_domain = Some(trimmed.to_string());
            }
        }
        if let Some(Value::Array(items)) = section.get("exit_pool") {
            result.exit_pool = items
                .iter()
                .filter_map(Value::as_str)
                .map(str::trim)
                .filter(|value| !value.is_empty())
                .map(str::to_string)
                .collect();
        }
        if let Some(Value::Bool(enabled)) = section.get("proxy_enabled") {
            result.proxy_enabled = *enabled;
        }
        result
    }

    /// 输出裸配置对象（不含 `opencode_scan` 外层键），由调用方决定存放位置。
    pub(crate) fn to_provider_config_value(&self) -> Value {
        json!({
            "cidrs": self.cidrs,
            "auto_enabled": self.auto_enabled,
            "interval_hours": self.interval_hours.unwrap_or(0),
            "concurrency": self.effective_concurrency(),
            "rotation_enabled": self.rotation_enabled,
            "cooldown_minutes": self.effective_cooldown_minutes(),
            "proxy_domain": self.proxy_domain.clone().unwrap_or_default(),
            "proxy_enabled": self.proxy_enabled,
            "exit_pool": self.exit_pool.clone(),
            "exit_pool_disabled": self.exit_pool_disabled.clone(),
        })
    }

    pub(crate) fn effective_concurrency(&self) -> usize {
        self.concurrency
            .unwrap_or(OPENCODE_SCAN_DEFAULT_CONCURRENCY)
            .clamp(1, OPENCODE_SCAN_MAX_CONCURRENCY)
    }

    /// 自动扫描是否真正生效：开关打开且间隔大于 0。
    pub(crate) fn autoscan_effective(&self) -> bool {
        self.auto_enabled && self.interval_hours.unwrap_or(0) > 0
    }

    /// 冷却时长（分钟），带默认值与下限保护。
    pub(crate) fn effective_cooldown_minutes(&self) -> u32 {
        self.cooldown_minutes
            .unwrap_or(crate::opencode_rotation::DEFAULT_COOLDOWN_MINUTES)
            .max(1)
    }

    /// 轮转是否可用：开关打开且池内确实有配置了出口 IP 的 key。
    pub(crate) fn rotation_effective(&self) -> bool {
        self.rotation_enabled
    }

    /// 本次请求应该使用的前置代理 host。
    ///
    /// 开关关闭、或没填域名时返回 `None`——此时应当直连默认官方域名。
    /// 这个值只在请求路径上生效，绝不写回 `endpoint.base_url`。
    pub(crate) fn effective_proxy_domain(&self) -> Option<String> {
        if !self.proxy_enabled {
            return None;
        }
        self.proxy_domain
            .as_deref()
            .map(str::trim)
            .filter(|domain| !domain.is_empty())
            .map(str::to_string)
    }

    /// 从 CIDR 枚举候选 IP，排除池中已有 IP 与网络/广播地址。
    ///
    /// 结果按字典序稳定排列，交给 [`Self::scan_slice`] 按游标切片。
    pub(crate) fn candidate_ips(&self, known_ips: &BTreeSet<String>) -> Vec<String> {
        let mut candidates = BTreeSet::new();
        for cidr in &self.cidrs {
            let Some((prefix, bits)) = parse_cidr(cidr) else {
                continue;
            };
            let host_bits = (32 - bits).max(1);
            let host_count = (1u32 << host_bits.min(30)) as u64;
            let base = prefix as u64;
            for offset in 1..host_count.saturating_sub(1) {
                let value = base + offset;
                let octets = [
                    (value >> 24) as u8,
                    (value >> 16) as u8,
                    (value >> 8) as u8,
                    value as u8,
                ];
                let ip = format!("{}.{}.{}.{}", octets[0], octets[1], octets[2], octets[3]);
                if !known_ips.contains(&ip) {
                    candidates.insert(ip);
                }
            }
        }
        candidates.into_iter().collect()
    }

    /// 按游标切出本轮要探的一段，并算出下一轮的游标。
    ///
    /// 没有游标时，候选超过 [`OPENCODE_SCAN_MAX_CANDIDATES`] 会让每轮只探字典序
    /// 最靠前的同一批（探不通的 IP 永远排在前面），后面的网段被静默饿死。
    pub(crate) fn scan_slice(&self, candidates: &[String], cursor: u64) -> (Vec<String>, u64) {
        let total = candidates.len();
        if total == 0 {
            return (Vec::new(), 0);
        }
        let start = if (cursor as usize) < total {
            cursor as usize
        } else {
            0
        };
        let end = start
            .saturating_add(OPENCODE_SCAN_MAX_CANDIDATES)
            .min(total);
        let selected = candidates[start..end].to_vec();
        // 本轮探完整段则回到开头，否则接着往后走。
        let next_cursor = if end >= total { 0 } else { end as u64 };
        (selected, next_cursor)
    }
}

/// 解析 IPv4 CIDR（`a.b.c.d/len`），返回 (网络地址, 前缀长度)。
pub(crate) fn parse_cidr(cidr: &str) -> Option<(u32, u32)> {
    let (addr_part, len_part) = cidr.split_once('/')?;
    let bits = len_part.trim().parse::<u32>().ok()?;
    if bits == 0 || bits > 32 {
        return None;
    }
    let IpAddr::V4(ipv4) = addr_part.trim().parse::<IpAddr>().ok()? else {
        return None;
    };
    let value = u32::from(ipv4);
    let mask = u32::MAX << (32 - bits);
    Some((value & mask, bits))
}

/// 读取池 key 上配置的出口 IP。
///
/// 唯一来源是 `upstream_metadata.opencode_exit_ip`（本仓库既有约定）。
pub(crate) fn opencode_pool_key_ip(key: &StoredProviderCatalogKey) -> Option<String> {
    let raw = key
        .upstream_metadata
        .as_ref()
        .and_then(|metadata| metadata.get(OPENCODE_EXIT_IP_METADATA_KEY))
        .and_then(Value::as_str)?
        .trim()
        .to_string();
    if raw.is_empty() || raw.parse::<IpAddr>().is_err() {
        return None;
    }
    Some(raw)
}

/// 列出 Provider 的池 IP，供状态接口渲染，不暴露任何凭据。
pub(crate) async fn list_opencode_pool_ips(
    app: &AppState,
    provider_id: &str,
    config: &OpenCodeScanConfig,
) -> Result<Vec<Value>, GatewayError> {
    // provider 级 IP 池是权威来源：IP 属于「池」，不属于「密钥」。
    // 密钥只负责鉴权，凭据数量和 IP 数量本来就不该相等。
    if !config.exit_pool.is_empty() {
        let keys = app
            .list_provider_catalog_keys_by_provider_ids(&[provider_id.to_string()])
            .await?;
        let disabled: BTreeSet<String> = config
            .exit_pool_disabled
            .iter()
            .map(|ip| ip.trim().to_string())
            .filter(|ip| !ip.is_empty())
            .collect();
        return Ok(config
            .exit_pool
            .iter()
            .map(|ip| ip.trim())
            .filter(|ip| !ip.is_empty())
            .map(|ip| {
                // key_id 仅用于兼容旧前端：只有当某个 key 仍带着这个 IP 的元数据时才回填
                let key_id = keys
                    .iter()
                    .find(|key| opencode_pool_key_ip(key).as_deref() == Some(ip))
                    .map(|key| Value::String(key.id.clone()))
                    .unwrap_or(Value::String(String::new()));
                json!({
                    "key_id": key_id,
                    "ip": ip,
                    "is_active": !disabled.contains(ip),
                    "source": "provider",
                })
            })
            .collect());
    }

    // 兼容旧数据：IP 存在 key 元数据里。
    let keys = app
        .list_provider_catalog_keys_by_provider_ids(&[provider_id.to_string()])
        .await?;
    Ok(keys
        .iter()
        .filter_map(|key| {
            let ip = opencode_pool_key_ip(key)?;
            Some(json!({
                "key_id": key.id,
                "ip": ip,
                "is_active": key.is_active,
                "source": "key",
            }))
        })
        .collect())
}

/// 从 Provider 的 Endpoint 解析上游域名与端口。
pub(crate) async fn opencode_upstream_target(
    app: &AppState,
    provider_id: &str,
    config: &OpenCodeScanConfig,
) -> Result<(String, u16), GatewayError> {
    // 探测目标必须是**前置代理域名**。池里的 IP 都是该域名背后的 CDN 节点，
    // 如果拿当前端点主机去探：开关关闭时端点是官方域名，用官方域名的 SNI 连这些
    // 节点必然 TLS 失败，于是「清理」会把整个池误判为失效并全部删除。
    // 因此优先使用配置里记住的代理域名，端点主机只作为没有配置时的兜底。
    if let Some(domain) = config
        .proxy_domain
        .as_deref()
        .map(str::trim)
        .filter(|domain| !domain.is_empty())
    {
        let port = config
            .proxy_domain
            .as_deref()
            .and_then(|domain| url::Url::parse(&format!("https://{domain}")).ok())
            .and_then(|url| url.port_or_known_default())
            .unwrap_or(443);
        return Ok((domain.to_string(), port));
    }
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

/// 探测目标是否就是官方直连域名。这种情况下探测结果不可信，禁止执行清理。
pub(crate) fn probe_target_is_official(domain: &str) -> bool {
    domain
        .trim()
        .eq_ignore_ascii_case(aether_provider_transport::opencode::OPENCODE_ORIGINAL_DOMAIN)
}

/// 扫描一轮：探测配置的网段，为每个健康新 IP 建一个池 key。
pub(crate) async fn run_open_code_pool_scan(
    app: &AppState,
    provider: &StoredProviderCatalogProvider,
) -> Result<ScanSummary, GatewayError> {
    let provider_id = provider.id.clone();
    let config = OpenCodeScanConfig::from_provider_config(&provider.config);
    if config.cidrs.is_empty() {
        return Err(GatewayError::Internal(
            "未配置扫描网段，请先在扫描配置中添加 CIDR".to_string(),
        ));
    }
    if opencode_ip_pool_status_for(&provider_id).scanning {
        return Err(GatewayError::Internal("扫描正在进行中".to_string()));
    }
    update_opencode_ip_pool_status(&provider_id, |status| status.scanning = true);
    // 兜底闸：任务被取消（tokio abort）或 unwind panic 时，正常的收尾代码不会执行，
    // `scanning` 就会永远卡在 true —— 表现为「每次进供应商都显示扫描中」，
    // 而且再也点不动扫描。靠 Drop 保证任何退出路径都会复位。
    let _guard = ScanFlagGuard {
        provider_id: provider_id.clone(),
    };

    let outcome = run_open_code_pool_scan_inner(app, provider, &config).await;

    update_opencode_ip_pool_status(&provider_id, |status| {
        status.scanning = false;
        if let Ok(summary) = &outcome {
            status.last_scan_targets = summary.targets;
            status.last_scan_found = summary.found;
            status.last_scan_added = summary.added;
            status.last_scan_at = Some(now_string());
            status.last_scan_at_unix_secs = Some(now_unix_secs());
        }
    });
    outcome
}

/// 扫描结束时（正常/取消/panic）都复位 `scanning` 标志。
struct ScanFlagGuard {
    provider_id: String,
}

impl Drop for ScanFlagGuard {
    fn drop(&mut self) {
        update_opencode_ip_pool_status(&self.provider_id, |status| {
            if status.scanning {
                tracing::warn!(
                    event_name = "opencode_ip_pool_scan_abandoned",
                    log_type = "ops",
                    provider_id = self.provider_id.as_str(),
                    "opencode ip pool scan exited without clearing its flag; reset"
                );
            }
            status.scanning = false;
        });
    }
}

/// 标记扫描已开始，返回 false 表示已有扫描在跑。
///
/// 供「异步触发」入口使用：先同步占位再返回 202，避免客户端轮询到
/// `scanning=false` 的空窗期。真正的清理由 `ScanFlagGuard` 负责。
pub(crate) fn claim_scan_slot(provider_id: &str) -> bool {
    if opencode_ip_pool_status_for(provider_id).scanning {
        return false;
    }
    update_opencode_ip_pool_status(provider_id, |status| {
        status.scanning = true;
        status.progress_done = 0;
        status.progress_total = 0;
        status.progress_kind = Some("scan".to_string());
    });
    true
}

/// 标记清理已开始，返回 false 表示已有清理在跑。
pub(crate) fn claim_clean_slot(provider_id: &str) -> bool {
    if opencode_ip_pool_status_for(provider_id).cleaning {
        return false;
    }
    update_opencode_ip_pool_status(provider_id, |status| {
        status.cleaning = true;
        status.progress_done = 0;
        status.progress_total = 0;
        status.progress_kind = Some("clean".to_string());
    });
    true
}

/// 扫描主体。调用方必须已用 [`claim_scan_slot`] 占位（同步或异步触发都算）。
pub(crate) async fn run_claimed_open_code_pool_scan(
    app: &AppState,
    provider: &StoredProviderCatalogProvider,
) -> Result<ScanSummary, GatewayError> {
    let provider_id = provider.id.clone();
    let config = OpenCodeScanConfig::from_provider_config(&provider.config);
    let _guard = ScanFlagGuard {
        provider_id: provider_id.clone(),
    };
    let outcome = run_open_code_pool_scan_inner(app, provider, &config).await;
    update_opencode_ip_pool_status(&provider_id, |status| {
        if let Ok(summary) = &outcome {
            status.last_scan_targets = summary.targets;
            status.last_scan_found = summary.found;
            status.last_scan_added = summary.added;
            status.last_scan_at = Some(now_string());
            status.last_scan_at_unix_secs = Some(now_unix_secs());
        }
    });
    outcome
}

/// 清理主体。调用方必须已用 [`claim_clean_slot`] 占位。
pub(crate) async fn run_claimed_open_code_pool_clean(
    app: &AppState,
    provider: &StoredProviderCatalogProvider,
) -> Result<CleanSummary, GatewayError> {
    let provider_id = provider.id.clone();
    let _guard = CleanFlagGuard {
        provider_id: provider_id.clone(),
    };
    let outcome = run_open_code_pool_clean_inner(app, provider).await;
    update_opencode_ip_pool_status(&provider_id, |status| {
        if let Ok(summary) = &outcome {
            status.last_clean_checked = summary.checked;
            status.last_clean_removed = summary.removed;
            status.last_clean_at = Some(now_string());
        }
    });
    outcome
}

async fn run_open_code_pool_scan_inner(
    app: &AppState,
    provider: &StoredProviderCatalogProvider,
    config: &OpenCodeScanConfig,
) -> Result<ScanSummary, GatewayError> {
    let provider_id = provider.id.clone();
    let (domain, port) = opencode_upstream_target(app, &provider_id, config).await?;
    if probe_target_is_official(&domain) {
        return Err(GatewayError::Internal(
            "未配置前置代理域名，无法判断出口 IP 是否可用；请先在前置代理池里填写并保存 CDN 域名，再执行扫描"
                .to_string(),
        ));
    }
    let concurrency = config.effective_concurrency();
    let keys = app
        .list_provider_catalog_keys_by_provider_ids(std::slice::from_ref(&provider_id))
        .await?;
    // 已知 IP = provider 级池 + 旧模型里仍带元数据的 key，取并集。
    let known_ips: BTreeSet<String> = keys
        .iter()
        .filter_map(opencode_pool_key_ip)
        .chain(config.exit_pool.iter().cloned())
        .collect();
    let all_candidates = config.candidate_ips(&known_ips);
    // 按 Redis 游标切片：候选总数超过单轮上限时，下一轮从这一轮结束处继续，
    // 避免「字典序靠前的死 IP 永远霸占名额、后面的网段饿死」。
    let cursor = crate::opencode_rotation::read_scan_cursor(app, &provider_id).await;
    let (candidates, next_cursor) = config.scan_slice(&all_candidates, cursor);
    let target_count = candidates.len() as u64;
    update_opencode_ip_pool_status(&provider_id, |status| status.progress_total = target_count);
    tracing::info!(
        event_name = "opencode_ip_pool_scan_slice",
        log_type = "ops",
        provider_id,
        total_candidates = all_candidates.len(),
        from = cursor,
        probing = target_count,
        next_cursor,
        "opencode ip pool scan slice"
    );

    let healthy = probe_ips(&candidates, &domain, port, concurrency, scan_progress(&provider_id)).await;
    // found = 本轮探通的总数（含已在池中的）；added = 真正新加入的。
    // 两者分开报，否则「网段里可达 IP 都已入库」会被误读成扫描失败。
    let found_count = healthy.len() as u64;
    let mut added = 0u64;
    // provider 级池已经是主模型：新 IP 直接进池，不再为每个 IP 造一个 key。
    let provider_pool_mode = !config.exit_pool.is_empty();
    let mut next_config = config.clone();
    for ip in healthy {
        if known_ips.contains(&ip) {
            continue;
        }
        if provider_pool_mode {
            next_config.exit_pool.push(ip);
            added += 1;
        } else if create_ip_pool_key(app, provider, &ip).await.is_ok() {
            added += 1;
        }
    }
    if added > 0 && provider_pool_mode {
        write_scan_config(app, provider, &next_config).await?;
    }
    // 无论本轮有没有新增，都要把游标推进，否则会一直重复探同一片。
    crate::opencode_rotation::write_scan_cursor(app, &provider_id, next_cursor).await;

    tracing::info!(
        event_name = "opencode_ip_pool_scan_completed",
        log_type = "ops",
        provider_id,
        targets = target_count,
        found = found_count,
        added,
        "opencode ip pool scan completed"
    );
    Ok(ScanSummary {
        targets: target_count,
        found: found_count,
        added,
    })
}

/// 清理一轮：探测已有池 key 的 IP，删除不健康的。
pub(crate) async fn run_open_code_pool_clean(
    app: &AppState,
    provider: &StoredProviderCatalogProvider,
) -> Result<CleanSummary, GatewayError> {
    let provider_id = provider.id.clone();
    if opencode_ip_pool_status_for(&provider_id).cleaning {
        return Err(GatewayError::Internal("清理正在进行中".to_string()));
    }
    update_opencode_ip_pool_status(&provider_id, |status| status.cleaning = true);
    // 与扫描同理：取消/panic 也要复位，否则「清理」按钮会永久显示进行中。
    let _guard = CleanFlagGuard {
        provider_id: provider_id.clone(),
    };

    let outcome = run_open_code_pool_clean_inner(app, provider).await;

    update_opencode_ip_pool_status(&provider_id, |status| {
        status.cleaning = false;
        if let Ok(summary) = &outcome {
            status.last_clean_checked = summary.checked;
            status.last_clean_removed = summary.removed;
            status.last_clean_at = Some(now_string());
        }
    });
    outcome
}

/// 清理结束时（正常/取消/panic）都复位 `cleaning` 标志。
struct CleanFlagGuard {
    provider_id: String,
}

impl Drop for CleanFlagGuard {
    fn drop(&mut self) {
        update_opencode_ip_pool_status(&self.provider_id, |status| {
            status.cleaning = false;
        });
    }
}

async fn run_open_code_pool_clean_inner(
    app: &AppState,
    provider: &StoredProviderCatalogProvider,
) -> Result<CleanSummary, GatewayError> {
    let provider_id = provider.id.clone();
    let config = OpenCodeScanConfig::from_provider_config(&provider.config);
    let (domain, port) = opencode_upstream_target(app, &provider_id, &config).await?;
    // 安全闸：探测目标是官方直连域名时结果不可信，此时执行清理会把整个池删光。
    if probe_target_is_official(&domain) {
        return Err(GatewayError::Internal(
            "未配置前置代理域名，无法判断出口 IP 是否可用；请先在前置代理池里填写并保存 CDN 域名，再执行清理"
                .to_string(),
        ));
    }
    let concurrency = config.effective_concurrency().min(32);

    // provider 级池：IP 存在配置里，剔除的是「池里的 IP」，不涉及删除密钥。
    if !config.exit_pool.is_empty() {
        let ips = config.exit_pool.clone();
        let checked = ips.len() as u64;
        update_opencode_ip_pool_status(&provider_id, |status| status.progress_total = checked);
        let healthy: BTreeSet<String> =
            BTreeSet::from_iter(
                probe_ips(&ips, &domain, port, concurrency, clean_progress(&provider_id)).await,
            );
        let kept: Vec<String> = ips
            .iter()
            .filter(|ip| healthy.contains(*ip))
            .cloned()
            .collect();
        let removed = (ips.len() - kept.len()) as u64;
        if removed > 0 {
            let mut next = config.clone();
            next.exit_pool = kept;
            write_scan_config(app, provider, &next).await?;
        }
        tracing::info!(
            event_name = "opencode_ip_pool_clean_completed",
            log_type = "ops",
            provider_id,
            checked,
            removed,
            source = "provider",
            "opencode ip pool clean completed"
        );
        return Ok(CleanSummary { checked, removed });
    }

    // 兼容旧数据：IP 在 key 元数据里，剔除时删除对应 key。
    let keys = app
        .list_provider_catalog_keys_by_provider_ids(std::slice::from_ref(&provider_id))
        .await?;
    let entries: Vec<(String, String)> = keys
        .iter()
        .filter_map(|key| opencode_pool_key_ip(key).map(|ip| (key.id.clone(), ip)))
        .collect();
    let checked = entries.len() as u64;
    let ips: Vec<String> = entries.iter().map(|(_, ip)| ip.clone()).collect();
    let healthy: BTreeSet<String> =
        BTreeSet::from_iter(probe_ips(&ips, &domain, port, concurrency, None).await);

    let mut removed = 0u64;
    for (key_id, ip) in entries {
        if !healthy.contains(&ip) && app.delete_provider_catalog_key(&key_id).await.is_ok() {
            removed += 1;
        }
    }

    tracing::info!(
        event_name = "opencode_ip_pool_clean_completed",
        log_type = "ops",
        provider_id,
        checked,
        removed,
        source = "key",
        "opencode ip pool clean completed"
    );
    Ok(CleanSummary { checked, removed })
}

/// 把扫描配置写回 provider。
pub(crate) async fn write_scan_config(
    app: &AppState,
    provider: &StoredProviderCatalogProvider,
    config: &OpenCodeScanConfig,
) -> Result<(), GatewayError> {
    let mut config_map = provider
        .config
        .as_ref()
        .and_then(Value::as_object)
        .cloned()
        .unwrap_or_default();
    config_map.insert(
        "opencode_scan".to_string(),
        config.to_provider_config_value(),
    );
    let mut updated = provider.clone();
    updated.config = Some(Value::Object(config_map));
    app.update_provider_catalog_provider(&updated).await?;
    Ok(())
}

/// 为一个健康 IP 创建池 key。
///
/// 出口 IP 写在 `upstream_metadata.opencode_exit_ip`；`api_key` 只是逐 IP 唯一的
/// 占位值（`public-<ip>`），上游认证由传输层强制为 `Bearer public`。
async fn create_ip_pool_key(
    app: &AppState,
    provider: &StoredProviderCatalogProvider,
    ip: &str,
) -> Result<(), GatewayError> {
    let key_id = Uuid::new_v4().to_string();
    let encrypted_api_key = app
        .seal_provider_catalog_key_api_key(
            &provider.id,
            &key_id,
            &format!("{OPENCODE_POOL_KEY_API_KEY_PREFIX}{ip}"),
        )
        .map_err(|err| {
            GatewayError::Internal(format!("gateway 未配置 provider key 加密密钥: {err:?}"))
        })?;
    let mut key = StoredProviderCatalogKey::new(
        key_id,
        provider.id.clone(),
        format!("CDN IP {ip}"),
        OPENCODE_POOL_KEY_AUTH_TYPE.to_string(),
        None,
        true,
    )
    .map_err(|err| GatewayError::Internal(err.to_string()))?
    .with_transport_fields(
        Some(json!(OPENCODE_POOL_KEY_API_FORMATS)),
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
    key.upstream_metadata = Some(json!({ OPENCODE_EXIT_IP_METADATA_KEY: ip }));
    key.note = Some("opencode ip pool (auto-scanned)".to_string());
    if app.create_provider_catalog_key(&key).await?.is_none() {
        return Err(GatewayError::Internal(
            "创建池密钥失败：无返回记录".to_string(),
        ));
    }
    Ok(())
}

/// 并发探测一批 IP，返回健康列表。
/// 生成一个把进度写进池状态的回调（扫描用）。
fn scan_progress(provider_id: &str) -> Arc<dyn Fn(u64) + Send + Sync> {
    let provider_id = provider_id.to_string();
    Arc::new(move |done| {
        update_opencode_ip_pool_status(&provider_id, |status| {
            status.progress_done = done;
            status.progress_kind = Some("scan".to_string());
        });
    })
}

/// 生成一个把进度写进池状态的回调（清理用）。
fn clean_progress(provider_id: &str) -> Arc<dyn Fn(u64) + Send + Sync> {
    let provider_id = provider_id.to_string();
    Arc::new(move |done| {
        update_opencode_ip_pool_status(&provider_id, |status| {
            status.progress_done = done;
            status.progress_kind = Some("clean".to_string());
        });
    })
}

/// 探测一批 IP，返回可达的那些。
/// `on_progress` 每完成一个探测就回调一次（已探数量），用来给面板显示进度——
/// 大批量扫描要跑几十分钟，没有进度用户只会以为卡死。
async fn probe_ips(
    ips: &[String],
    domain: &str,
    port: u16,
    concurrency: usize,
    on_progress: Option<Arc<dyn Fn(u64) + Send + Sync>>,
) -> Vec<String> {
    let total = ips.len() as u64;
    if let Some(callback) = on_progress.as_ref() {
        callback(0);
    }
    let semaphore = Arc::new(tokio::sync::Semaphore::new(concurrency.max(1)));
    let healthy: Arc<tokio::sync::Mutex<Vec<String>>> =
        Arc::new(tokio::sync::Mutex::new(Vec::new()));
    let done = Arc::new(std::sync::atomic::AtomicU64::new(0));
    let mut tasks = Vec::new();
    for ip in ips {
        let semaphore = Arc::clone(&semaphore);
        let healthy = Arc::clone(&healthy);
        let done = Arc::clone(&done);
        let on_progress = on_progress.clone();
        let domain = domain.to_string();
        let ip = ip.clone();
        tasks.push(tokio::spawn(async move {
            let Ok(_permit) = semaphore.acquire().await else {
                return;
            };
            let ok = probe_upstream_ip(&ip, &domain, port, OPENCODE_PROBE_TIMEOUT_SECS)
                .await
                .unwrap_or(false);
            if ok {
                healthy.lock().await.push(ip);
            }
            let finished = done.fetch_add(1, std::sync::atomic::Ordering::Relaxed) + 1;
            if let Some(callback) = on_progress.as_ref() {
                callback(finished.min(total));
            }
        }));
    }
    for task in tasks {
        let _ = task.await;
    }
    let guard = healthy.lock().await;
    guard.clone()
}

/// 探测单个 IP：对 `ip:port` 做裸 TLS 握手（SNI = domain），再发一条带 OpenCode
/// 指纹的 `GET /zen/v1/models`，2xx/3xx 判为健康。
pub(crate) async fn probe_upstream_ip(
    ip: &str,
    domain: &str,
    port: u16,
    timeout_secs: u64,
) -> Result<bool, GatewayError> {
    let ip = ip.trim().to_string();
    let domain = domain.trim().to_string();
    let Ok(parsed) = ip.parse::<IpAddr>() else {
        return Ok(false);
    };
    let address = std::net::SocketAddr::new(parsed, port);
    let connect = tokio::time::timeout(
        std::time::Duration::from_secs(timeout_secs),
        tokio::net::TcpStream::connect(address),
    )
    .await;
    let stream = match connect {
        Ok(Ok(stream)) => stream,
        Ok(Err(error)) => {
            tracing::debug!(
                event_name = "opencode_probe_tcp_connect_failed",
                log_type = "ops",
                ip = %ip,
                domain = %domain,
                port,
                error = ?error.kind(),
                "opencode probe tcp connect failed"
            );
            return Ok(false);
        }
        Err(_) => {
            tracing::debug!(
                event_name = "opencode_probe_tcp_connect_timed_out",
                log_type = "ops",
                ip = %ip,
                domain = %domain,
                port,
                "opencode probe tcp connect timed out"
            );
            return Ok(false);
        }
    };
    let stream = stream
        .into_std()
        .map_err(|err| GatewayError::Internal(err.to_string()))?;
    tokio::task::spawn_blocking(move || probe_upstream_ip_blocking(stream, &domain, timeout_secs))
        .await
        .map_err(|err| GatewayError::Internal(err.to_string()))?
}

fn probe_upstream_ip_blocking(
    stream: std::net::TcpStream,
    domain: &str,
    timeout_secs: u64,
) -> Result<bool, GatewayError> {
    let timeout = std::time::Duration::from_secs(timeout_secs);
    // into_std() 之后 socket 仍是非阻塞的，这里改回阻塞模式再做阻塞式 TLS/HTTP 探测。
    stream
        .set_nonblocking(false)
        .map_err(|err| GatewayError::Internal(err.to_string()))?;
    stream
        .set_read_timeout(Some(timeout))
        .map_err(|err| GatewayError::Internal(err.to_string()))?;
    stream
        .set_write_timeout(Some(timeout))
        .map_err(|err| GatewayError::Internal(err.to_string()))?;

    let server_name = resolve_probe_server_name(domain).map_err(GatewayError::Internal)?;
    let connection = rustls::ClientConnection::new(build_probe_tls_config(), server_name)
        .map_err(|err| GatewayError::Internal(err.to_string()))?;
    let mut tls_stream = rustls::StreamOwned::new(connection, stream);
    let request = format!(
        "GET /zen/v1/models HTTP/1.1\r\n\
         Host: {domain}\r\n\
         User-Agent: {user_agent}\r\n\
         Authorization: Bearer public\r\n\
         Accept: application/json\r\n\
         x-opencode-session: {session_id}\r\n\
         Connection: close\r\n\r\n",
        user_agent = aether_provider_transport::opencode::opencode_user_agent(),
        session_id = aether_provider_transport::opencode::new_opencode_session_id(),
    );
    if let Err(err) = tls_stream.write_all(request.as_bytes()) {
        tracing::debug!(
            event_name = "opencode_probe_write_failed",
            log_type = "ops",
            domain,
            error = ?err,
            "opencode probe write failed"
        );
        return Ok(false);
    }
    let mut status_line = Vec::new();
    match read_probe_status_line(&mut tls_stream, &mut status_line) {
        Ok(true) => Ok(is_healthy_status_line(&status_line)),
        _ => Ok(false),
    }
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

/// 读取 HTTP 响应首行，EOF 或超长返回 false。
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

/// `HTTP/1.1 2xx/3xx` 视为健康。
fn is_healthy_status_line(status_line: &[u8]) -> bool {
    let Some(space) = status_line.iter().position(|byte| *byte == b' ') else {
        return false;
    };
    let code_start = space + 1;
    if code_start + 2 >= status_line.len() {
        return false;
    }
    matches!(status_line[code_start], b'2' | b'3')
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
        let Some((network, bits)) = parse_cidr("203.0.113.192/26") else {
            panic!("valid cidr should parse");
        };
        assert_eq!(bits, 26);
        assert_eq!(
            network,
            u32::from(std::net::Ipv4Addr::new(111, 4, 225, 192))
        );
        assert_eq!(parse_cidr("not-an-ip/24"), None);
        assert_eq!(parse_cidr("1.2.3.4/33"), None);
        assert_eq!(parse_cidr("1.2.3.4"), None);
        assert_eq!(parse_cidr("1.2.3.4/0"), None);
    }

    #[test]
    fn candidate_ips_skip_network_broadcast_and_known() {
        let config = OpenCodeScanConfig {
            cidrs: vec!["192.168.1.0/29".to_string()],
            ..OpenCodeScanConfig::default()
        };
        let known: BTreeSet<String> = ["192.168.1.2".to_string()].into_iter().collect();
        let candidates = config.candidate_ips(&known);
        assert_eq!(
            candidates,
            vec![
                "192.168.1.1".to_string(),
                "192.168.1.3".to_string(),
                "192.168.1.4".to_string(),
                "192.168.1.5".to_string(),
                "192.168.1.6".to_string(),
            ]
        );
    }

    #[test]
    fn empty_cidr_config_yields_no_candidates() {
        assert!(OpenCodeScanConfig::default()
            .candidate_ips(&BTreeSet::new())
            .is_empty());
    }

    #[test]
    fn config_reads_opencode_scan_section() {
        let config = OpenCodeScanConfig::from_provider_config_object(
            json!({ "opencode_scan": { "cidrs": ["203.0.113.192/26"], "concurrency": 8 } })
                .as_object()
                .expect("object"),
        );
        assert_eq!(config.cidrs, vec!["203.0.113.192/26".to_string()]);
        assert_eq!(config.effective_concurrency(), 8);
    }

    #[test]
    fn config_reads_bare_section() {
        let config = OpenCodeScanConfig::from_provider_config_object(
            json!({ "cidrs": ["93.184.216.45.0/24"], "concurrency": 999 })
                .as_object()
                .expect("object"),
        );
        assert_eq!(config.cidrs, vec!["93.184.216.45.0/24".to_string()]);
        assert_eq!(
            config.effective_concurrency(),
            OPENCODE_SCAN_MAX_CONCURRENCY
        );
    }

    #[test]
    fn concurrency_defaults_and_clamps() {
        assert_eq!(
            OpenCodeScanConfig::default().effective_concurrency(),
            OPENCODE_SCAN_DEFAULT_CONCURRENCY
        );
        assert_eq!(
            OpenCodeScanConfig {
                cidrs: Vec::new(),
                interval_hours: None,
                concurrency: Some(0),
                ..OpenCodeScanConfig::default()
            }
            .effective_concurrency(),
            1
        );
    }

    #[test]
    fn pool_key_ip_reads_upstream_metadata() {
        let key = StoredProviderCatalogKey::new(
            "k1".to_string(),
            "p1".to_string(),
            "CDN IP 1.2.3.4".to_string(),
            "api_key".to_string(),
            None,
            true,
        )
        .expect("key");
        assert_eq!(opencode_pool_key_ip(&key), None);
        let mut with_meta = key.clone();
        with_meta.upstream_metadata = Some(json!({ "opencode_exit_ip": "1.2.3.4" }));
        assert_eq!(
            opencode_pool_key_ip(&with_meta),
            Some("1.2.3.4".to_string())
        );
        let mut invalid = key;
        invalid.upstream_metadata = Some(json!({ "opencode_exit_ip": "999.1.1.1" }));
        assert_eq!(opencode_pool_key_ip(&invalid), None);
    }

    #[test]
    fn healthy_status_line_recognises_2xx_and_3xx() {
        assert!(is_healthy_status_line(b"HTTP/1.1 200 OK"));
        assert!(is_healthy_status_line(b"HTTP/1.1 301 Moved"));
        assert!(!is_healthy_status_line(b"HTTP/1.1 403 Forbidden"));
        assert!(!is_healthy_status_line(b"garbage"));
    }

    #[test]
    fn status_map_is_per_provider() {
        update_opencode_ip_pool_status("pool-a", |status| status.scanning = true);
        assert!(opencode_ip_pool_status_for("pool-a").scanning);
        assert!(!opencode_ip_pool_status_for("pool-b").scanning);
        update_opencode_ip_pool_status("pool-a", |status| status.scanning = false);
    }
}

#[test]
fn scan_slice_starts_from_the_cursor_and_wraps_around() {
    let config = OpenCodeScanConfig::default();
    let candidates: Vec<String> = (0..10).map(|i| format!("10.0.0.{i}")).collect();
    // 从中间开始
    let (first, next) = config.scan_slice(&candidates, 4);
    assert_eq!(
        first,
        vec!["10.0.0.4", "10.0.0.5", "10.0.0.6", "10.0.0.7", "10.0.0.8", "10.0.0.9"]
    );
    assert_eq!(next, 0, "探到末尾后游标回绕");
    // 从 0 开始就是全部
    let (all, next) = config.scan_slice(&candidates, 0);
    assert_eq!(all.len(), 10);
    assert_eq!(next, 0);
}

#[test]
fn scan_slice_recovers_from_an_out_of_range_cursor() {
    let config = OpenCodeScanConfig::default();
    let candidates: Vec<String> = (0..3).map(|i| format!("10.0.0.{i}")).collect();
    // 网段被改小后旧游标越界，不能panic也不能漏
    let (picked, next) = config.scan_slice(&candidates, 99);
    assert_eq!(picked.len(), 3);
    assert_eq!(next, 0);
}

#[test]
fn scan_slice_on_empty_candidates_is_a_noop() {
    let config = OpenCodeScanConfig::default();
    assert_eq!(config.scan_slice(&[], 7), (Vec::new(), 0));
}

#[test]
fn scan_slice_caps_at_the_per_round_limit() {
    let config = OpenCodeScanConfig::default();
    let total = OPENCODE_SCAN_MAX_CANDIDATES + 500;
    let candidates: Vec<String> = (0..total)
        .map(|i| format!("10.0.{}.{}", i / 256, i % 256))
        .collect();
    let (first, next) = config.scan_slice(&candidates, 0);
    assert_eq!(first.len(), OPENCODE_SCAN_MAX_CANDIDATES);
    assert_eq!(
        next, OPENCODE_SCAN_MAX_CANDIDATES as u64,
        "游标要落到本轮结束处"
    );
    let (second, _) = config.scan_slice(&candidates, next);
    assert_eq!(second.len(), 500, "下一轮只探剩下的尾巴");
    assert_eq!(second[0], candidates[OPENCODE_SCAN_MAX_CANDIDATES]);
}
