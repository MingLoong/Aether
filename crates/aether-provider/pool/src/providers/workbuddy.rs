//! WorkBuddy（腾讯 CodeBuddy）在号池里的适配：额度刷新能力 + 余额查询请求构造。
//!
//! 上游两套余额口径（面板 `internal/upstream/client.go`）：
//!
//! - **个人**：`POST /v2/billing/meter/get-user-resource`（国际域首选无 `/v2` 前缀的
//!   `/billing/meter/get-user-resource`），body 是分页 + 套餐到期时间范围；
//!   响应里 `Accounts[].CycleCapacityRemain/CycleCapacitySize` 是各套餐的剩余/总量。
//! - **企业**（`enterpriseId` 非空）：`POST /v2/billing/meter/get-enterprise-user-usage`，
//!   body `{}`，响应 `{credit, limitNum, cycleEndTime}`——`credit` 是**已用**。
//!
//! 计费域的头族与对话域基本一致（面板 `BillingHeaders`）：Bearer + 官方指纹头 +
//! `X-User-Id` / `X-Enterprise-Id` / `X-Tenant-Id` / `X-Domain`，因此这里直接复用
//! transport crate 的头注入（`insert_workbuddy_request_headers`），避免两处漂移。

use std::collections::BTreeMap;

use aether_data_contracts::repository::provider_catalog::StoredProviderCatalogEndpoint;
use aether_provider_transport::workbuddy::desktop::{
    WORKBUDDY_DESKTOP_APPEARANCE_SET_PATH, WORKBUDDY_DESKTOP_IDE_VERSION,
    WORKBUDDY_DESKTOP_REPORT_PATH, WORKBUDDY_DESKTOP_USER_AGENT, WORKBUDDY_EXPERT_LIST_PATH,
};
use aether_provider_transport::workbuddy::{
    apply_workbuddy_billing_user_agent, insert_workbuddy_request_headers, WorkbuddyIdentity,
};
use serde_json::Value;

use crate::capability::ProviderPoolCapabilities;
use crate::provider::{
    provider_pool_endpoint_format_matches, provider_pool_matching_endpoint, ProviderPoolAdapter,
    ProviderPoolMemberInput,
};
use crate::quota_refresh::ProviderPoolQuotaRequestSpec;

/// 上游套餐到期时间的墙钟格式（UTC+8，与解析口径一致）。
const WORKBUDDY_PACKAGE_TIME_LAYOUT: &str = "%Y-%m-%d %H:%M:%S";
/// 上游只卖 100 年内的套餐：范围上界给足即可（面板同口径）。
const WORKBUDDY_PACKAGE_RANGE_DAYS: i64 = 365 * 101;
/// 上游 product code（面板实测常量）。
const WORKBUDDY_RESOURCE_PRODUCT_CODE: &str = "p_tcaca";

/// 「账号×模型」不可用负缓存（11102）在 `upstream_metadata.workbuddy` 下的键名。
pub const WORKBUDDY_MODEL_BLOCKED_METADATA_KEY: &str = "model_blocked";

/// 积分保底（面板 `pool.credit_floor` / `floorBlockedForModel` 的等价物）。
///
/// 语义（逐条对齐面板）：
/// - `credit_floor <= 0` = **关闭**（面板默认 0；负值同样不拦）；
/// - 模型名为空 = 不拦（无法判定收费性）；
/// - **边界不拦**：`credits == floor` 放行，只有**严格低于**才拦；
/// - 不限量（`unlimited`）不构成限制 → 放行（面板 `client.go` 同款：不限量两处都
///   「不构成限制」）；
/// - 「收费」判据用**目录倍率兜底**：目录未覆盖该模型（未知倍率）→ 放行；倍率为 0 →
///   免费放行；倍率 > 0 → 拦。倍率优先取**生效价**（限时优惠后的
///   `promo_credits`），因为它才是本轮真正会扣的值——折扣到 0 的模型不该被拦。
///
/// 与面板的差异（已知且有意）：面板还有「本地实测台账」一档（tier 2），Aether 侧
/// 没有 per-(账号, 模型) 的成本台账，所以只保留「目录倍率」这一档；方向是**偏放行**
/// （未知即放行），即不会比面板更严格。
pub fn workbuddy_credit_floor_blocked(
    metadata: Option<&Value>,
    model_name: &str,
    credit_floor: i64,
) -> bool {
    if credit_floor <= 0 {
        return false;
    }
    let normalized = model_name.trim().to_ascii_lowercase();
    if normalized.is_empty() {
        return false;
    }
    let Some(bucket) = metadata.and_then(|metadata| metadata.get("workbuddy")) else {
        return false;
    };
    if bucket.get("unlimited").and_then(Value::as_bool) == Some(true) {
        return false;
    }
    let credits = bucket
        .get("credits_remaining")
        .and_then(json_number_i64)
        .unwrap_or(0);
    if credits >= credit_floor {
        return false;
    }
    match workbuddy_catalog_model_rate(bucket, &normalized) {
        // 目录没这个模型 → 无从判定收费，放行（面板：未知倍率放行）
        None => false,
        // 免费（0 / "0.00" / "0x"）→ 放行：保底的目的正是「留点余额让免费模型还能用」
        Some(rate) if rate <= 0.0 => false,
        Some(_) => true,
    }
}

/// 目录里某个模型的积分倍率（**优先生效价**）。
///
/// 兼容两种快照形态：`models` 为**数组**（拉目录时写的全字段形态）或**对象**（按 id
/// 索引的档位形态）。倍率取 `promo_credits`（限时优惠生效价）优先，其次 `credits`（牌价）。
fn workbuddy_catalog_model_rate(bucket: &Value, normalized_model: &str) -> Option<f64> {
    let models = bucket.get("models")?;
    // 数组形态：模型 id 在条目里的 `model_uid`；对象形态：**键就是** model id，
    // 值里可能只有 `efforts` 这类档位信息。两种都要认。
    let candidates: Vec<(Option<&str>, &Value)> = match models {
        Value::Array(items) => items.iter().map(|item| (None, item)).collect(),
        Value::Object(map) => map
            .iter()
            .map(|(key, value)| (Some(key.as_str()), value))
            .collect(),
        _ => return None,
    };
    for (key_model_id, entry) in candidates {
        let model_uid = entry
            .get("model_uid")
            .and_then(Value::as_str)
            .or(key_model_id);
        let Some(model_uid) = model_uid else {
            continue;
        };
        if model_uid.trim().to_ascii_lowercase() != normalized_model {
            continue;
        }
        for key in ["promo_credits", "credits"] {
            if let Some(rate) = entry.get(key).and_then(json_rate_f64) {
                return Some(rate);
            }
        }
        // 命中了模型但没有倍率字段 → 未知（放行，不要因为「没写」就当收费）
        return None;
    }
    None
}

/// 上游账号区域（`upstream_metadata.workbuddy.realm`）。
pub fn workbuddy_key_realm(metadata: Option<&Value>) -> Option<String> {
    metadata
        .and_then(|metadata| metadata.get("workbuddy"))
        .and_then(|bucket| bucket.get("realm"))
        .and_then(Value::as_str)
        .map(|realm| realm.trim().to_ascii_lowercase())
        .filter(|realm| !realm.is_empty())
}

/// 「每日维护包」今天该不该跑 —— 只比**日期键** ✓（`YYYY-MM-DD`，上游日界 CST ✓）。
///
/// 维护性修复（2026-10-17 ✗）：活跃上报 / 连登兑换 / 猫猫旅行 / 成长任务（报名+领奖）
/// 原本挂在**「今日首次签到成功」**上 ✗ —— 账号若在登录当天已被别处签到
/// （`already_checked_in`：官方客户端、建号流程），这一整套当天就**全部跳过** ✗，
/// 新号第一天永远跑不到任务 ✗。改成 Aether 自己的每日戳后 ✓：
/// - 与谁先签到无关 ✓（同一套思路，`desktop_ran_on` 早就这么做了 ✓）；
/// - 每个账号每个自然日**恰好一趟** ✓（`None`/空串 = 从没跑过 → 跑 ✓）；
/// - 跨日自动放开 ✓（日期键变了就是新的一天 ✓）。
pub fn workbuddy_daily_bundle_due(previous_day: Option<&str>, today: &str) -> bool {
    let today = today.trim();
    !matches!(
        previous_day.map(str::trim),
        Some(day) if !day.is_empty() && day == today
    )
}

/// 账号名刷新后**该不该把 key 名换成账号名** —— 返回 `Some(新名)` 才动手 ✓。
///
/// 维护性审计 ④（2026-10-17 ✗）：这条写路径（刷新时自动改名 + 管理端 CAS）原先
/// **零测试** ✗ —— 只有「名字是不是系统生成的」这个子判定有测试 ✓。这里把**整条决策**
/// 收成一个纯函数 ✓，于是「空白昵称不动手 ✓ / 用户起过的名字永不覆盖 ✓ / 截断上限 ✓」
/// 全都能离线钉住 ✓（CAS 那部分仍由真机验证覆盖 ✓）。
///
/// 规则：
/// - 昵称 trim 后为空 → `None` ✓（拿不到账号名就不改 ✓）；
/// - 当前名字**不是**系统生成的（= 用户手动命名过）→ `None` ✓（永不覆盖人的意图 ✓）；
/// - 其它 → `Some(昵称，截断到 120 字符)` ✓（与建号路径同一个上限 ✓）。
pub fn workbuddy_key_rename_target(current_name: &str, nickname: &str) -> Option<String> {
    let nickname = nickname.trim();
    if nickname.is_empty() || !workbuddy_system_generated_key_name(current_name) {
        return None;
    }
    Some(nickname.chars().take(120).collect())
}

/// 这个 key 名是否**是系统自动生成的**（`账号_<unix秒>` / `账号_<unix秒>_<批次序号>`）。
///
/// 用途：账号名刷新成功后，只有当名字**仍然没被用户改过**时才自动换成上游账号名 ✓；
/// 用户手动命名过的 key 一律不动 ✓（避免覆盖人的意图 ✗）。
pub fn workbuddy_system_generated_key_name(name: &str) -> bool {
    let Some(rest) = name.trim().strip_prefix("账号_") else {
        return false;
    };
    let mut parts = rest.split('_');
    let seconds = parts.next().unwrap_or_default();
    if seconds.is_empty() || !seconds.bytes().all(|byte| byte.is_ascii_digit()) {
        return false;
    }
    match (parts.next(), parts.next()) {
        // 只认这两种形态：`账号_<秒>` 与 `账号_<秒>_<序号>` ✓。
        (None, None) => true,
        (Some(index), None) => !index.is_empty() && index.bytes().all(|byte| byte.is_ascii_digit()),
        _ => false,
    }
}

/// 单账号**生效在途（并发）上限**（面板 `Pool.inFlightLimit` 的等价物）。
///
/// 面板口径（`pool.go:260-267`）：
/// - 所有 realm 统一使用 `max_in_flight`（单账号最大在途，面板默认 3）；
/// - `<= 0` = 未设置/不限，回落账号自身上限。
pub fn workbuddy_in_flight_limit(
    base_limit: usize,
    max_in_flight: usize,
    _metadata: Option<&Value>,
) -> usize {
    if max_in_flight > 0 {
        max_in_flight
    } else {
        base_limit
    }
}

/// 倍率文本 → 数值。
///
/// **两种 x 写法都要认**（2026-10-16 PG 直读实测并存）：
/// - `"x0.29"`（**前缀 x**，上游 `/v3/config` 里 `credits` 的真实形态）；
/// - `"0.50x"` / `"0x"`（**后缀 x**，面板抓包与 `discountedCredits` 的形态）。
///
/// 纯数字也认；空/坏值 → `None`（调用方按「未知」放行）。
fn json_rate_f64(value: &Value) -> Option<f64> {
    match value {
        Value::Number(number) => number.as_f64(),
        Value::String(text) => {
            let trimmed = text
                .trim()
                .trim_start_matches(['x', 'X'])
                .trim_end_matches(['x', 'X'])
                .trim();
            if trimmed.is_empty() {
                return None;
            }
            trimmed.parse::<f64>().ok()
        }
        _ => None,
    }
}

fn json_number_i64(value: &Value) -> Option<i64> {
    match value {
        Value::Number(number) => number
            .as_i64()
            .or_else(|| number.as_f64().map(|value| value as i64)),
        Value::String(text) => text.trim().parse::<i64>().ok(),
        _ => None,
    }
}

/// 该 (账号, 模型) 是否仍在负缓存期内。
///
/// **为什么按 (账号, 模型) 而不是按账号**：上游 `11102`（该后端无此模型）是**确定性**答复——
/// 同一个 (账号, 模型) 再试结果不变，但账号对别的模型完全正常，把账号标成坏号会误杀。
/// 到点自动失效（半开探测）：到期后允许再试一次，失败则退避时间翻倍（见网关侧写入）。
pub fn workbuddy_model_blocked_at(
    upstream_metadata: Option<&Value>,
    model_name: &str,
    now_unix_secs: u64,
) -> bool {
    let normalized = normalize_workbuddy_model_key(model_name);
    if normalized.is_empty() {
        return false;
    }
    let Some(entries) = upstream_metadata
        .and_then(Value::as_object)
        .and_then(|metadata| metadata.get("workbuddy"))
        .and_then(Value::as_object)
        .and_then(|bucket| bucket.get(WORKBUDDY_MODEL_BLOCKED_METADATA_KEY))
        .and_then(Value::as_object)
    else {
        return false;
    };
    entries.iter().any(|(model, entry)| {
        normalize_workbuddy_model_key(model) == normalized
            && entry
                .get("until_unix_secs")
                .and_then(Value::as_u64)
                .is_some_and(|until| until > now_unix_secs)
    })
}

fn normalize_workbuddy_model_key(value: &str) -> String {
    value.trim().to_ascii_lowercase()
}

#[derive(Debug, Clone, Default)]
pub struct WorkbuddyProviderPoolAdapter;

impl ProviderPoolAdapter for WorkbuddyProviderPoolAdapter {
    fn provider_type(&self) -> &'static str {
        "workbuddy"
    }

    fn capabilities(&self) -> ProviderPoolCapabilities {
        ProviderPoolCapabilities {
            quota_refresh: true,
            quota_expiry: true,
            ..ProviderPoolCapabilities::default()
        }
    }

    fn quota_refresh_endpoint(
        &self,
        endpoints: &[StoredProviderCatalogEndpoint],
        include_inactive: bool,
    ) -> Option<StoredProviderCatalogEndpoint> {
        provider_pool_matching_endpoint(endpoints, include_inactive, |endpoint| {
            provider_pool_endpoint_format_matches(endpoint, "openai:chat")
        })
    }

    fn quota_refresh_missing_endpoint_message(&self) -> String {
        "找不到有效的 openai:chat 端点".to_string()
    }

    /// 模型级硬排除：`11102` 负缓存期内，该 (账号, 模型) 不可选。
    ///
    /// 调度器在评估候选时本来就会问这个方法（`read_key_account_quota_exhaustion_map` →
    /// `admin_pool_key_model_quota_hard_blocked`），所以这里实现完就**不需要改调度器**。
    fn quota_hard_blocked(&self, input: &ProviderPoolMemberInput<'_>) -> bool {
        let Some(model_name) = input.provider_model_name else {
            return false;
        };
        let now_unix_secs = crate::quota::provider_pool_current_unix_secs().unwrap_or(0);
        workbuddy_model_blocked_at(
            input.key.upstream_metadata.as_ref(),
            model_name,
            now_unix_secs,
        )
    }
}

/// 构造余额/额度查询请求。
///
/// `billing_base_url` 必须是**计费域**（CN `https://www.codebuddy.cn`、国际
/// `https://www.workbuddy.ai`），用 `workbuddy_billing_base_url(realm)` 取——
/// **不能拿端点的 base 代替**：端点 base 是对话域（CN `copilot.tencent.com`），
/// 混用会让请求打到错误的域上（面板 `billingBase()`）。
///
/// `path` 由调用方按 `workbuddy_billing_path_candidates(...)` 逐个传入：
/// 国际域有新旧两条路径，**只有 404 才换下一条**（面板 `billingMeterJSON`）。
pub fn build_workbuddy_pool_quota_request(
    key_id: &str,
    billing_base_url: &str,
    path: &str,
    identity: &WorkbuddyIdentity,
    authorization: (String, String),
    now_unix_secs: u64,
) -> ProviderPoolQuotaRequestSpec {
    let enterprise_id = identity
        .enterprise_id
        .as_deref()
        .map(str::trim)
        .filter(|value| !value.is_empty());
    let base = billing_base_url.trim().trim_end_matches('/');
    // 企业额度与个人资源包是两套口径：企业端点没有分页请求体。
    let body = match enterprise_id {
        Some(_) => serde_json::json!({}),
        None => workbuddy_user_resource_body(now_unix_secs),
    };

    let mut headers = BTreeMap::new();
    headers.insert(authorization.0.trim().to_ascii_lowercase(), authorization.1);
    headers.insert("accept".to_string(), "application/json".to_string());
    headers.insert("content-type".to_string(), "application/json".to_string());
    insert_workbuddy_request_headers(identity, &mut headers);
    // 计费/成长域用**单段** UA（面板 BillingHeaders / illingUA()），与对话端点区分。
    apply_workbuddy_billing_user_agent(&mut headers);
    // 计费域额外带租户头（面板 BillingHeaders 的三件套之一）。
    if let Some(enterprise_id) = enterprise_id {
        headers.insert("x-tenant-id".to_string(), enterprise_id.to_string());
    }

    ProviderPoolQuotaRequestSpec {
        request_id: format!("workbuddy-quota:{key_id}"),
        provider_name: "workbuddy".to_string(),
        quota_kind: "workbuddy".to_string(),
        method: "POST".to_string(),
        url: format!("{base}{path}"),
        headers,
        content_type: Some("application/json".to_string()),
        json_body: Some(body),
        client_api_format: "openai:chat".to_string(),
        provider_api_format: "workbuddy:billing".to_string(),
        model_name: None,
    }
}

/// 构造每日签到请求。
///
/// 面板口径：`POST {path}` + **空 body `{}`**，头族与余额查询完全一致（**计费域**，
/// 不是对话域）；`path` 同样由调用方按 `workbuddy_billing_path_candidates(...)`
/// 逐个传入（国际域两条路径，404 才回退）。企业号**不要调用**——上游对它们恒返回
/// `400 code 10001 企业账号不支持该操作`，调用方应先按 `identity.enterprise_id` 跳过。
pub fn build_workbuddy_pool_daily_checkin_request(
    key_id: &str,
    billing_base_url: &str,
    path: &str,
    identity: &WorkbuddyIdentity,
    authorization: (String, String),
) -> ProviderPoolQuotaRequestSpec {
    let base = billing_base_url.trim().trim_end_matches('/');

    let mut headers = BTreeMap::new();
    headers.insert(authorization.0.trim().to_ascii_lowercase(), authorization.1);
    headers.insert("accept".to_string(), "application/json".to_string());
    headers.insert("content-type".to_string(), "application/json".to_string());
    insert_workbuddy_request_headers(identity, &mut headers);
    // 计费/成长域用**单段** UA（面板 BillingHeaders / illingUA()），与对话端点区分。
    apply_workbuddy_billing_user_agent(&mut headers);
    if let Some(enterprise_id) = identity
        .enterprise_id
        .as_deref()
        .map(str::trim)
        .filter(|value| !value.is_empty())
    {
        headers.insert("x-tenant-id".to_string(), enterprise_id.to_string());
    }

    ProviderPoolQuotaRequestSpec {
        request_id: format!("workbuddy-checkin:{key_id}"),
        provider_name: "workbuddy".to_string(),
        // 复用同一套「按账号直连上游」的请求描述；kind 只用于日志与诊断。
        quota_kind: "workbuddy_checkin".to_string(),
        method: "POST".to_string(),
        url: format!("{base}{path}"),
        headers,
        content_type: Some("application/json".to_string()),
        json_body: Some(serde_json::json!({})),
        client_api_format: "openai:chat".to_string(),
        provider_api_format: "workbuddy:billing".to_string(),
        model_name: None,
    }
}

/// 构造活跃上报请求（`chat_request_send` 事件，计费域 `/v2/report`）。
///
/// 面板口径：body 是**长度为 1 的事件数组**，字段必须**全字段**（照抄客户端事件形状，
/// 防上游后续加严；最小 3 字段会被判无效）；`userId` 必填——缺了上游 200 但静默丢弃。
/// 上游建议**每号每天 1 次**，不做多时点高频上报；企业号零收益（growth 体系 403），
/// 调用方应先跳过。
pub fn build_workbuddy_pool_activity_report_request(
    key_id: &str,
    billing_base_url: &str,
    path: &str,
    identity: &WorkbuddyIdentity,
    authorization: (String, String),
    uid: &str,
    now_unix_millis: u64,
) -> ProviderPoolQuotaRequestSpec {
    let base = billing_base_url.trim().trim_end_matches('/');
    let conversation_id = format!("wb2a-{now_unix_millis}");

    let mut headers = BTreeMap::new();
    headers.insert(authorization.0.trim().to_ascii_lowercase(), authorization.1);
    headers.insert("accept".to_string(), "application/json".to_string());
    headers.insert("content-type".to_string(), "application/json".to_string());
    insert_workbuddy_request_headers(identity, &mut headers);
    // 计费/成长域用**单段** UA（面板 BillingHeaders / illingUA()），与对话端点区分。
    apply_workbuddy_billing_user_agent(&mut headers);
    if let Some(enterprise_id) = identity
        .enterprise_id
        .as_deref()
        .map(str::trim)
        .filter(|value| !value.is_empty())
    {
        headers.insert("x-tenant-id".to_string(), enterprise_id.to_string());
    }

    ProviderPoolQuotaRequestSpec {
        request_id: format!("workbuddy-activity:{key_id}"),
        provider_name: "workbuddy".to_string(),
        quota_kind: "workbuddy_activity".to_string(),
        method: "POST".to_string(),
        url: format!("{base}{path}"),
        headers,
        content_type: Some("application/json".to_string()),
        json_body: Some(serde_json::json!([workbuddy_activity_event(
            uid,
            now_unix_millis,
            &conversation_id,
        )])),
        client_api_format: "openai:chat".to_string(),
        provider_api_format: "workbuddy:billing".to_string(),
        model_name: None,
    }
}

/// 一条 `chat_request_send` 事件（字段与面板 `chatRequestEvent` 一一对应）。
fn workbuddy_activity_event(uid: &str, now_unix_millis: u64, conversation_id: &str) -> Value {
    serde_json::json!({
        "eventCode": "chat_request_send",
        "timestamp": now_unix_millis,
        "reportDelay": 0,
        "mode": "craft",
        "conversationId": conversation_id,
        "requestId": conversation_id,
        "inputLength": 12,
        "requestModelId": aether_provider_transport::workbuddy::WORKBUDDY_ACTIVITY_DEFAULT_MODEL_ID,
        "requestModelName": aether_provider_transport::workbuddy::WORKBUDDY_ACTIVITY_DEFAULT_MODEL_NAME,
        "isPlan": false,
        "isAutoExecuteTerminal": false,
        "isAutoModify": false,
        "codebaseEnable": false,
        "maxToken": 0,
        "maxSteps": 0,
        "temperature": 0,
        "maxRetries": 0,
        "mentionContexts": [],
        "knowledgeId": [],
        "knowledgeName": [],
        "codebaseId": "",
        "mentionContextCount": 0,
        "command": "",
        "expertId": "",
        "recommendId": "",
        "skillId": "",
        "skillCount": 0,
        "totalCount": 0,
        "fileUri": "",
        "presentAt": now_unix_millis,
        "traceId": "",
        "rootRequestId": conversation_id,
        "parentConversationId": conversation_id,
        "agentName": "default",
        "agentType": "conversation",
        "userId": uid,
    })
}

/// 成长中心（`/activity/growth/*`）的请求构造。
///
/// 这些端点走**对话域**（面板 `growthJSON` 用 `chatBase`，不是计费域也不是官网域——
/// 面板 `streak.go` 顶部注释写的 `www.workbuddy.cn` 与实现不符，以 `growthJSON` 为准），
/// 头族与计费域相同。
pub fn build_workbuddy_pool_growth_streak_request(
    key_id: &str,
    chat_base_url: &str,
    identity: &WorkbuddyIdentity,
    authorization: (String, String),
) -> ProviderPoolQuotaRequestSpec {
    build_workbuddy_growth_spec(
        key_id,
        chat_base_url,
        aether_provider_transport::workbuddy::WORKBUDDY_GROWTH_STREAK_PATH,
        identity,
        authorization,
        "workbuddy_growth_streak",
        "GET",
        None,
    )
}

/// 兑换连登档位（`tier`: `7d` / `14d` / `28d`）。
pub fn build_workbuddy_pool_growth_redeem_request(
    key_id: &str,
    chat_base_url: &str,
    identity: &WorkbuddyIdentity,
    authorization: (String, String),
    tier: &str,
) -> ProviderPoolQuotaRequestSpec {
    build_workbuddy_growth_spec(
        key_id,
        chat_base_url,
        aether_provider_transport::workbuddy::WORKBUDDY_GROWTH_REDEEM_PATH,
        identity,
        authorization,
        "workbuddy_growth_redeem",
        "POST",
        Some(serde_json::json!({
            "tier": tier,
            // 前端同款幂等令牌（`randomUUID`）。
            "client_token": aether_provider_transport::workbuddy::workbuddy_client_token(),
        })),
    )
}

/// 抽奖次数。
pub fn build_workbuddy_pool_growth_lottery_summary_request(
    key_id: &str,
    chat_base_url: &str,
    identity: &WorkbuddyIdentity,
    authorization: (String, String),
) -> ProviderPoolQuotaRequestSpec {
    build_workbuddy_growth_spec(
        key_id,
        chat_base_url,
        aether_provider_transport::workbuddy::WORKBUDDY_GROWTH_LOTTERY_SUMMARY_PATH,
        identity,
        authorization,
        "workbuddy_growth_lottery_summary",
        "GET",
        None,
    )
}

/// 抽奖一次（每次消耗 1 次 chances）。
pub fn build_workbuddy_pool_growth_lottery_draw_request(
    key_id: &str,
    chat_base_url: &str,
    identity: &WorkbuddyIdentity,
    authorization: (String, String),
) -> ProviderPoolQuotaRequestSpec {
    build_workbuddy_growth_spec(
        key_id,
        chat_base_url,
        aether_provider_transport::workbuddy::WORKBUDDY_GROWTH_LOTTERY_DRAW_PATH,
        identity,
        authorization,
        "workbuddy_growth_lottery_draw",
        "POST",
        Some(serde_json::json!({
            "client_token": aether_provider_transport::workbuddy::workbuddy_client_token(),
        })),
    )
}

/// 领取新手礼包（计费域，**无 `/v2` 前缀**——面板 `claim-gift` 就是这条路径；
/// 每号一次，已领返回业务错误）。
pub fn build_workbuddy_pool_claim_gift_request(
    key_id: &str,
    billing_base_url: &str,
    identity: &WorkbuddyIdentity,
    authorization: (String, String),
) -> ProviderPoolQuotaRequestSpec {
    build_workbuddy_billing_spec(
        key_id,
        billing_base_url,
        aether_provider_transport::workbuddy::WORKBUDDY_CLAIM_GIFT_PATH,
        identity,
        authorization,
        "workbuddy_claim_gift",
        "POST",
        Some(serde_json::json!({})),
    )
}

/// 领取活动补偿（计费域，无 `/v2` 前缀；有则领，无则业务错误）。
pub fn build_workbuddy_pool_claim_compensation_request(
    key_id: &str,
    billing_base_url: &str,
    identity: &WorkbuddyIdentity,
    authorization: (String, String),
) -> ProviderPoolQuotaRequestSpec {
    build_workbuddy_billing_spec(
        key_id,
        billing_base_url,
        aether_provider_transport::workbuddy::WORKBUDDY_CLAIM_COMPENSATION_PATH,
        identity,
        authorization,
        "workbuddy_claim_compensation",
        "POST",
        Some(serde_json::json!({})),
    )
}

/// 签到热力图（对话域，用来判断昨日是否漏签）。
pub fn build_workbuddy_pool_growth_heatmap_request(
    key_id: &str,
    chat_base_url: &str,
    identity: &WorkbuddyIdentity,
    authorization: (String, String),
) -> ProviderPoolQuotaRequestSpec {
    build_workbuddy_growth_spec(
        key_id,
        chat_base_url,
        aether_provider_transport::workbuddy::WORKBUDDY_GROWTH_HEATMAP_PATH,
        identity,
        authorization,
        "workbuddy_growth_heatmap",
        "GET",
        None,
    )
}

/// 对指定日期使用补签卡（对话域；`target_date` 为 CST 自然日 `YYYY-MM-DD`）。
pub fn build_workbuddy_pool_growth_makeup_use_request(
    key_id: &str,
    chat_base_url: &str,
    identity: &WorkbuddyIdentity,
    authorization: (String, String),
    target_date: &str,
) -> ProviderPoolQuotaRequestSpec {
    build_workbuddy_growth_spec(
        key_id,
        chat_base_url,
        aether_provider_transport::workbuddy::WORKBUDDY_GROWTH_MAKEUP_USE_PATH,
        identity,
        authorization,
        "workbuddy_growth_makeup_use",
        "POST",
        Some(serde_json::json!({"target_date": target_date})),
    )
}

/// 猫猫档案（对话域；`buddy` 为 null 表示无猫）。
pub fn build_workbuddy_pool_buddy_info_request(
    key_id: &str,
    chat_base_url: &str,
    identity: &WorkbuddyIdentity,
    authorization: (String, String),
) -> ProviderPoolQuotaRequestSpec {
    build_workbuddy_growth_spec(
        key_id,
        chat_base_url,
        aether_provider_transport::workbuddy::WORKBUDDY_BUDDY_INFO_PATH,
        identity,
        authorization,
        "workbuddy_buddy_info",
        "GET",
        None,
    )
}

/// 猫猫旅行状态。
pub fn build_workbuddy_pool_travel_status_request(
    key_id: &str,
    chat_base_url: &str,
    identity: &WorkbuddyIdentity,
    authorization: (String, String),
) -> ProviderPoolQuotaRequestSpec {
    build_workbuddy_growth_spec(
        key_id,
        chat_base_url,
        aether_provider_transport::workbuddy::WORKBUDDY_TRAVEL_STATUS_PATH,
        identity,
        authorization,
        "workbuddy_travel_status",
        "GET",
        None,
    )
}

/// 派出旅行（地点固定 4）。
pub fn build_workbuddy_pool_travel_depart_request(
    key_id: &str,
    chat_base_url: &str,
    identity: &WorkbuddyIdentity,
    authorization: (String, String),
) -> ProviderPoolQuotaRequestSpec {
    build_workbuddy_growth_spec(
        key_id,
        chat_base_url,
        aether_provider_transport::workbuddy::WORKBUDDY_TRAVEL_DEPART_PATH,
        identity,
        authorization,
        "workbuddy_travel_depart",
        "POST",
        Some(serde_json::json!({
            "location_id": aether_provider_transport::workbuddy::WORKBUDDY_TRAVEL_LOCATION_ID,
        })),
    )
}

/// 到站领奖（`record_id` 必带）。
pub fn build_workbuddy_pool_travel_claim_request(
    key_id: &str,
    chat_base_url: &str,
    identity: &WorkbuddyIdentity,
    authorization: (String, String),
    record_id: i64,
) -> ProviderPoolQuotaRequestSpec {
    build_workbuddy_growth_spec(
        key_id,
        chat_base_url,
        aether_provider_transport::workbuddy::WORKBUDDY_TRAVEL_CLAIM_PATH,
        identity,
        authorization,
        "workbuddy_travel_claim",
        "POST",
        Some(serde_json::json!({"record_id": record_id})),
    )
}

/// 同意领养协议（幂等）。
pub fn build_workbuddy_pool_buddy_agreement_request(
    key_id: &str,
    chat_base_url: &str,
    identity: &WorkbuddyIdentity,
    authorization: (String, String),
) -> ProviderPoolQuotaRequestSpec {
    build_workbuddy_growth_spec(
        key_id,
        chat_base_url,
        aether_provider_transport::workbuddy::WORKBUDDY_BUDDY_AGREEMENT_PATH,
        identity,
        authorization,
        "workbuddy_buddy_agreement",
        "POST",
        Some(serde_json::json!({"agree": true})),
    )
}

/// 领养第一只猫（门槛未达标时上游返回 400，属预期）。
pub fn build_workbuddy_pool_buddy_first_request(
    key_id: &str,
    chat_base_url: &str,
    identity: &WorkbuddyIdentity,
    authorization: (String, String),
) -> ProviderPoolQuotaRequestSpec {
    build_workbuddy_growth_spec(
        key_id,
        chat_base_url,
        aether_provider_transport::workbuddy::WORKBUDDY_BUDDY_FIRST_PATH,
        identity,
        authorization,
        "workbuddy_buddy_first",
        "POST",
        Some(serde_json::json!({})),
    )
}

/// 桌面客户端事件上报（**对话域** `{chatBase}/v2/report`，body 是事件数组）。
///
/// 与计费/成长请求的头族差异（面板 `ReportDesktopEvent`）：
/// - UA 用**桌面客户端** `WorkBuddy/5.5.6 …`（不是计费单段 UA，也不是对话三段式）；
/// - `Accept: application/json, text/plain, */*`、`Content-Type: …;charset=UTF-8`；
/// - 另有 `X-Product: SaaS` 与 `X-Request-ID`（后者由调用方按面板口径拼）。
///
/// `payload` 由 [`aether_provider_transport::workbuddy::desktop::workbuddy_desktop_event_payload`]
/// 生成（已把指纹铺进每个事件）。
pub fn build_workbuddy_pool_desktop_report_request(
    key_id: &str,
    chat_base_url: &str,
    identity: &WorkbuddyIdentity,
    authorization: (String, String),
    request_id_header: &str,
    payload: Value,
) -> ProviderPoolQuotaRequestSpec {
    let base = chat_base_url.trim().trim_end_matches('/');
    let mut headers = BTreeMap::new();
    headers.insert(authorization.0.trim().to_ascii_lowercase(), authorization.1);
    insert_workbuddy_request_headers(identity, &mut headers);
    headers.insert(
        "accept".to_string(),
        "application/json, text/plain, */*".to_string(),
    );
    headers.insert(
        "content-type".to_string(),
        "application/json;charset=UTF-8".to_string(),
    );
    headers.insert(
        "user-agent".to_string(),
        WORKBUDDY_DESKTOP_USER_AGENT.to_string(),
    );
    headers.insert("x-product".to_string(), "SaaS".to_string());
    headers.insert("x-domain".to_string(), base.to_string());
    headers.insert("x-request-id".to_string(), request_id_header.to_string());
    if let Some(uid) = identity
        .uid
        .as_deref()
        .map(str::trim)
        .filter(|value| !value.is_empty())
    {
        headers.insert("x-user-id".to_string(), uid.to_string());
    }

    ProviderPoolQuotaRequestSpec {
        request_id: format!("workbuddy_desktop_report:{key_id}"),
        provider_name: "workbuddy".to_string(),
        quota_kind: "workbuddy_desktop_report".to_string(),
        method: "POST".to_string(),
        url: format!("{base}{WORKBUDDY_DESKTOP_REPORT_PATH}"),
        headers,
        content_type: Some("application/json;charset=UTF-8".to_string()),
        json_body: Some(payload),
        client_api_format: "openai:chat".to_string(),
        provider_api_format: "workbuddy:desktop".to_string(),
        model_name: None,
    }
}

/// Web 端事件上报（**官网域** `{webBase}/v2/report`，浏览器指纹）。
///
/// 用于页面行为类任务（`Library_read`）：面板 `ReportWebEvent` 用的是浏览器形状头族
/// （`x-client-platform: web` + `Origin`/`Referer` 指向页面 + Chrome UA）。
pub fn build_workbuddy_pool_web_report_request(
    key_id: &str,
    web_base_url: &str,
    identity: &WorkbuddyIdentity,
    authorization: (String, String),
    page_url: &str,
    payload: Value,
) -> ProviderPoolQuotaRequestSpec {
    let base = web_base_url.trim().trim_end_matches('/');
    let browser_ua = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/152.0.0.0 Safari/537.36";
    let mut headers = BTreeMap::new();
    headers.insert(authorization.0.trim().to_ascii_lowercase(), authorization.1);
    headers.insert("accept".to_string(), "application/json".to_string());
    headers.insert("content-type".to_string(), "application/json".to_string());
    headers.insert("user-agent".to_string(), browser_ua.to_string());
    headers.insert("x-client-platform".to_string(), "web".to_string());
    headers.insert("origin".to_string(), base.to_string());
    headers.insert("referer".to_string(), page_url.to_string());
    headers.insert("x-domain".to_string(), base.to_string());
    if let Some(uid) = identity
        .uid
        .as_deref()
        .map(str::trim)
        .filter(|value| !value.is_empty())
    {
        headers.insert("x-user-id".to_string(), uid.to_string());
    }

    ProviderPoolQuotaRequestSpec {
        request_id: format!("workbuddy_web_report:{key_id}"),
        provider_name: "workbuddy".to_string(),
        quota_kind: "workbuddy_web_report".to_string(),
        method: "POST".to_string(),
        url: format!("{base}{WORKBUDDY_DESKTOP_REPORT_PATH}"),
        headers,
        content_type: Some("application/json".to_string()),
        json_body: Some(payload),
        client_api_format: "openai:chat".to_string(),
        provider_api_format: "workbuddy:desktop".to_string(),
        model_name: None,
    }
}

/// 外观主题设置（`Hp_Appearance` 的 API 留痕那一步；事件另发 `appearance_skin_apply`）。
pub fn build_workbuddy_pool_appearance_set_request(
    key_id: &str,
    chat_base_url: &str,
    identity: &WorkbuddyIdentity,
    authorization: (String, String),
    theme_key: &str,
) -> ProviderPoolQuotaRequestSpec {
    let base = chat_base_url.trim().trim_end_matches('/');
    let mut headers = BTreeMap::new();
    headers.insert(authorization.0.trim().to_ascii_lowercase(), authorization.1);
    insert_workbuddy_request_headers(identity, &mut headers);
    headers.insert(
        "accept".to_string(),
        "application/json, text/plain, */*".to_string(),
    );
    headers.insert(
        "content-type".to_string(),
        "application/json;charset=UTF-8".to_string(),
    );
    headers.insert(
        "user-agent".to_string(),
        WORKBUDDY_DESKTOP_USER_AGENT.to_string(),
    );
    headers.insert("x-product".to_string(), "SaaS".to_string());
    headers.insert("x-domain".to_string(), base.to_string());

    ProviderPoolQuotaRequestSpec {
        request_id: format!("workbuddy_appearance_set:{key_id}"),
        provider_name: "workbuddy".to_string(),
        quota_kind: "workbuddy_appearance_set".to_string(),
        method: "POST".to_string(),
        url: format!("{base}{WORKBUDDY_DESKTOP_APPEARANCE_SET_PATH}"),
        headers,
        content_type: Some("application/json;charset=UTF-8".to_string()),
        json_body: Some(serde_json::json!({
            "kind": "theme",
            "resource_key": theme_key,
        })),
        client_api_format: "openai:chat".to_string(),
        provider_api_format: "workbuddy:desktop".to_string(),
        model_name: None,
    }
}

/// 专家市场列表（`expert_actual_use` 的 id 必须是平台**真实存在**的专家，编造不计数）。
pub fn build_workbuddy_pool_expert_list_request(
    key_id: &str,
    chat_base_url: &str,
    identity: &WorkbuddyIdentity,
    authorization: (String, String),
    expert_type: &str,
) -> ProviderPoolQuotaRequestSpec {
    let base = chat_base_url.trim().trim_end_matches('/');
    let mut headers = BTreeMap::new();
    headers.insert(authorization.0.trim().to_ascii_lowercase(), authorization.1);
    insert_workbuddy_request_headers(identity, &mut headers);
    headers.insert("accept".to_string(), "application/json".to_string());
    headers.insert("content-type".to_string(), "application/json".to_string());
    headers.insert(
        "user-agent".to_string(),
        WORKBUDDY_DESKTOP_USER_AGENT.to_string(),
    );
    headers.insert("x-product".to_string(), "SaaS".to_string());
    headers.insert("x-domain".to_string(), base.to_string());

    let mut body = serde_json::json!({
        "page": 1,
        "page_size": 20,
        "sort_by": "reco_rank",
        "sort_order": "desc",
    });
    if !expert_type.trim().is_empty() {
        body["expert_type"] = Value::String(expert_type.trim().to_string());
    }

    ProviderPoolQuotaRequestSpec {
        request_id: format!("workbuddy_expert_list:{key_id}"),
        provider_name: "workbuddy".to_string(),
        quota_kind: "workbuddy_expert_list".to_string(),
        method: "POST".to_string(),
        url: format!("{base}{WORKBUDDY_EXPERT_LIST_PATH}"),
        headers,
        content_type: Some("application/json".to_string()),
        json_body: Some(body),
        client_api_format: "openai:chat".to_string(),
        provider_api_format: "workbuddy:desktop".to_string(),
        model_name: None,
    }
}

/// 桌面端**真实对话**请求（Tier 2：`skill_1` / `expert_*` / `black_cat` 的判据来源）。
///
/// 用途不是拿回答，而是**拿服务端 `requestId`**：`expert_actual_use` / `skill_info` 这类
/// JOIN 事件的 requestId 必须是真实对话的服务端 id（自造 UUID 不计数，面板 Sunny row 2113 实证）。
/// 响应是 SSE 文本，走 sync 执行会落进 `ResponseBody.body_bytes_b64`，调用方解码后
/// 用 `workbuddy_parse_server_request_id` 抓 id。
///
/// 头族按面板 `DesktopChatWithExpert` 逐条对应（桌面 UA + 会话/请求 id + agent 意图 + IDE 标识；
/// 带专家时额外 `X-Expert-Id`）。
#[allow(clippy::too_many_arguments)]
pub fn build_workbuddy_pool_desktop_chat_request(
    key_id: &str,
    chat_base_url: &str,
    identity: &WorkbuddyIdentity,
    authorization: (String, String),
    conversation_id: &str,
    request_id: &str,
    expert_id: Option<&str>,
    body: Value,
) -> ProviderPoolQuotaRequestSpec {
    let base = chat_base_url.trim().trim_end_matches('/');
    let mut headers = BTreeMap::new();
    headers.insert(authorization.0.trim().to_ascii_lowercase(), authorization.1);
    headers.insert("content-type".to_string(), "application/json".to_string());
    headers.insert("accept".to_string(), "text/event-stream".to_string());
    headers.insert(
        "user-agent".to_string(),
        WORKBUDDY_DESKTOP_USER_AGENT.to_string(),
    );
    headers.insert("x-domain".to_string(), base.to_string());
    headers.insert("x-product".to_string(), "SaaS".to_string());
    headers.insert("x-conversation-id".to_string(), conversation_id.to_string());
    headers.insert("x-request-id".to_string(), request_id.to_string());
    headers.insert("x-agent-intent".to_string(), "craft".to_string());
    headers.insert("x-agent-type".to_string(), "main".to_string());
    headers.insert("x-ide-name".to_string(), "WorkBuddy".to_string());
    headers.insert("x-ide-type".to_string(), "WorkBuddy".to_string());
    headers.insert(
        "x-ide-version".to_string(),
        WORKBUDDY_DESKTOP_IDE_VERSION.to_string(),
    );
    headers.insert("x-codebuddy-request".to_string(), "1".to_string());
    if let Some(expert_id) = expert_id.map(str::trim).filter(|value| !value.is_empty()) {
        headers.insert("x-expert-id".to_string(), expert_id.to_string());
    }
    if let Some(uid) = identity
        .uid
        .as_deref()
        .map(str::trim)
        .filter(|value| !value.is_empty())
    {
        headers.insert("x-user-id".to_string(), uid.to_string());
    }

    ProviderPoolQuotaRequestSpec {
        request_id: format!("workbuddy_desktop_chat:{key_id}"),
        provider_name: "workbuddy".to_string(),
        quota_kind: "workbuddy_desktop_chat".to_string(),
        method: "POST".to_string(),
        url: format!("{base}/v2/chat/completions"),
        headers,
        content_type: Some("application/json".to_string()),
        json_body: Some(body),
        client_api_format: "openai:chat".to_string(),
        provider_api_format: "workbuddy:desktop".to_string(),
        model_name: None,
    }
}

/// Web 控制台账号资料（面板 `internal/upstream/profile.go`，issue #94：改名后免重登同步昵称）。
///
/// `GET {web_base}/console/account` + `x-client-platform: web`（与 tasks/claim 同一鉴权形态；
/// 实测无需 Web 会话 cookie）。`web_base_url` 必须是**web 域**（CN `https://www.workbuddy.cn`），
/// **不是**对话域端点 base。
///
/// ⚠️ 响应含手机号等敏感信息：本 spec **只**供 `workbuddy_nickname_from_account_profile`
/// 解析 nickname/uid，其余字段不得落日志、不得透传。
pub fn build_workbuddy_pool_account_profile_request(
    key_id: &str,
    web_base_url: &str,
    identity: &WorkbuddyIdentity,
    authorization: (String, String),
) -> ProviderPoolQuotaRequestSpec {
    let mut spec = build_workbuddy_growth_spec(
        key_id,
        web_base_url,
        aether_provider_transport::workbuddy::WORKBUDDY_ACCOUNT_PROFILE_PATH,
        identity,
        authorization,
        "workbuddy_account_profile",
        "GET",
        None,
    );
    let headers = &mut spec.headers;
    headers.insert(
        aether_provider_transport::workbuddy::WORKBUDDY_CLIENT_PLATFORM_HEADER.to_string(),
        aether_provider_transport::workbuddy::WORKBUDDY_CLIENT_PLATFORM_WEB.to_string(),
    );
    // Referer 按**同一个域名**推导：面板 `profile.go` 用的是 `webBase(a) + /profile/account-settings`
    // 的形态（CN 域硬编码是面板的疏漏 ✓），这里两家域都自洽 —— 跨域 Referer 会被上游当异常请求。
    headers.insert(
        "Referer".to_string(),
        format!(
            "{}/profile/account-settings",
            web_base_url.trim().trim_end_matches('/')
        ),
    );
    spec
}

/// 从 `/console/account` 响应里**只**取昵称（面板同款隐私边界 + 防串号）。
///
/// - 兼容 `{code,msg,data:{uid,nickname}}` 信封与裸对象；
/// - `uid` 与预期不一致（两边都非空时）→ `None`（**防串号**：绝不把别人的昵称写到自己账号上）；
/// - 昵称为空/缺失 → `None`（调用方保持原值，不覆盖成空）。
pub fn workbuddy_nickname_from_account_profile(
    body: &serde_json::Value,
    expected_uid: &str,
) -> Option<String> {
    let data = body.get("data").unwrap_or(body);
    let nickname = data
        .get("nickname")
        .and_then(serde_json::Value::as_str)
        .map(str::trim)
        .filter(|value| !value.is_empty())?;
    let uid = data
        .get("uid")
        .and_then(serde_json::Value::as_str)
        .map(str::trim)
        .unwrap_or("");
    let expected_uid = expected_uid.trim();
    if !uid.is_empty() && !expected_uid.is_empty() && uid != expected_uid {
        return None;
    }
    Some(nickname.to_string())
}

/// 成长任务列表（对话域 + 计费头族；`miniprogram` 口径才会下发小程序限定任务）。
pub fn build_workbuddy_pool_tasks_list_request(
    key_id: &str,
    chat_base_url: &str,
    identity: &WorkbuddyIdentity,
    authorization: (String, String),
    miniprogram: bool,
) -> ProviderPoolQuotaRequestSpec {
    let mut spec = build_workbuddy_growth_spec(
        key_id,
        chat_base_url,
        aether_provider_transport::workbuddy::WORKBUDDY_TASKS_LIST_PATH,
        identity,
        authorization,
        "workbuddy_tasks_list",
        "GET",
        None,
    );
    if miniprogram {
        spec.headers.insert(
            aether_provider_transport::workbuddy::WORKBUDDY_CLIENT_PLATFORM_HEADER.to_string(),
            aether_provider_transport::workbuddy::WORKBUDDY_CLIENT_PLATFORM_MINIPROGRAM.to_string(),
        );
    }
    spec
}

/// 批量报名成长任务（幂等：已报名的重复提交不算致命错误）。
pub fn build_workbuddy_pool_tasks_accept_request(
    key_id: &str,
    chat_base_url: &str,
    identity: &WorkbuddyIdentity,
    authorization: (String, String),
    task_codes: &[String],
    miniprogram: bool,
) -> ProviderPoolQuotaRequestSpec {
    let mut spec = build_workbuddy_growth_spec(
        key_id,
        chat_base_url,
        aether_provider_transport::workbuddy::WORKBUDDY_TASKS_ACCEPT_PATH,
        identity,
        authorization,
        "workbuddy_tasks_accept",
        "POST",
        Some(serde_json::json!({"task_codes": task_codes})),
    );
    if miniprogram {
        spec.headers.insert(
            aether_provider_transport::workbuddy::WORKBUDDY_CLIENT_PLATFORM_HEADER.to_string(),
            aether_provider_transport::workbuddy::WORKBUDDY_CLIENT_PLATFORM_MINIPROGRAM.to_string(),
        );
    }
    spec
}

/// 领取任务奖励（**官网域**：`{web}/activity/growth/tasks/{code}/claim`，无 body）。
///
/// 头族**刻意覆盖** `Origin`/`Referer` 为官网成长中心、并带 `x-client-platform: web`：
/// 面板实测这就是 Web 成长中心的真实请求形状（CLI 域那条
/// `/v2/activity/growth/tasks/reward/claim` 根本不存在，一直 400）。
pub fn build_workbuddy_pool_task_claim_web_request(
    key_id: &str,
    web_base_url: &str,
    identity: &WorkbuddyIdentity,
    authorization: (String, String),
    task_code: &str,
) -> ProviderPoolQuotaRequestSpec {
    let base = web_base_url.trim().trim_end_matches('/');
    let path = format!(
        "{}{}/claim",
        aether_provider_transport::workbuddy::WORKBUDDY_TASKS_CLAIM_PATH_PREFIX,
        task_code.trim()
    );
    let mut spec = build_workbuddy_growth_spec(
        key_id,
        base,
        &path,
        identity,
        authorization,
        "workbuddy_task_claim_web",
        "POST",
        None,
    );
    spec.headers.insert(
        "origin".to_string(),
        aether_provider_transport::workbuddy::WORKBUDDY_WEB_BASE_URL_CN.to_string(),
    );
    spec.headers.insert(
        "referer".to_string(),
        format!(
            "{}/profile/growth-center",
            aether_provider_transport::workbuddy::WORKBUDDY_WEB_BASE_URL_CN
        ),
    );
    spec.headers.insert(
        aether_provider_transport::workbuddy::WORKBUDDY_CLIENT_PLATFORM_HEADER.to_string(),
        aether_provider_transport::workbuddy::WORKBUDDY_CLIENT_PLATFORM_WEB.to_string(),
    );
    // 官网领奖用的是**对话域三段式 UA**（面板 `ClaimReward` 取 `c.userAgent(a)`），
    // 所以把 growth 助手里刚换上的单段计费 UA 换回来。
    spec.headers.insert(
        "user-agent".to_string(),
        aether_provider_transport::workbuddy::workbuddy_user_agent(identity.realm),
    );
    spec
}

/// 领取任务奖励（**小程序口径**：对话域同路径 + mp 头；上游 400 时调用方降级到官网域）。
pub fn build_workbuddy_pool_task_claim_mp_request(
    key_id: &str,
    chat_base_url: &str,
    identity: &WorkbuddyIdentity,
    authorization: (String, String),
    task_code: &str,
) -> ProviderPoolQuotaRequestSpec {
    let path = format!(
        "{}{}/claim",
        aether_provider_transport::workbuddy::WORKBUDDY_TASKS_CLAIM_MP_PATH_PREFIX,
        task_code.trim()
    );
    let mut spec = build_workbuddy_growth_spec(
        key_id,
        chat_base_url,
        &path,
        identity,
        authorization,
        "workbuddy_task_claim_mp",
        "POST",
        None,
    );
    spec.headers.insert(
        aether_provider_transport::workbuddy::WORKBUDDY_CLIENT_PLATFORM_HEADER.to_string(),
        aether_provider_transport::workbuddy::WORKBUDDY_CLIENT_PLATFORM_MINIPROGRAM.to_string(),
    );
    spec
}

/// 领取一次性 trial 加油包（**global 专属**，计费域，无 body）。
///
/// 面板口径：这是 global 账号**唯一天然的积分增益动作**（global 无签到 / 无任务中心，
/// 见 PLAN D4）。已领过时上游返回幂等码 `14051`，调用方按
/// `classify_workbuddy_trial_outcome` 视为正常。
pub fn build_workbuddy_pool_trial_claim_request(
    key_id: &str,
    billing_base_url: &str,
    identity: &WorkbuddyIdentity,
    authorization: (String, String),
) -> ProviderPoolQuotaRequestSpec {
    build_workbuddy_billing_spec(
        key_id,
        billing_base_url,
        aether_provider_transport::workbuddy::WORKBUDDY_TRIAL_PATH,
        identity,
        authorization,
        "workbuddy_trial_claim",
        "POST",
        None,
    )
}

/// 国际版注册链路（**官网域 + 浏览器指纹**；面板 `globalRegisterReq`）。
///
/// 与计费域的差别（面板逐字口径）：UA 是 Chrome 浏览器形态（`globalWebUA`）、
/// `Accept` 带 `text/plain`、`Origin` = 官网根、`Referer` = 官网根 + `/`；
/// **不**带桌面端的 `x-client-platform` / `x-domain` / 设备头族。
#[allow(clippy::too_many_arguments)]
fn build_workbuddy_pool_global_register_spec(
    key_id: &str,
    web_base_url: &str,
    path: &str,
    method: &str,
    quota_kind: &str,
    identity: &WorkbuddyIdentity,
    authorization: (String, String),
    json_body: Option<Value>,
    with_user_id_header: bool,
) -> ProviderPoolQuotaRequestSpec {
    let base = web_base_url.trim().trim_end_matches('/');
    let mut headers = BTreeMap::new();
    headers.insert(authorization.0.trim().to_ascii_lowercase(), authorization.1);
    headers.insert(
        "accept".to_string(),
        "application/json, text/plain, */*".to_string(),
    );
    headers.insert("content-type".to_string(), "application/json".to_string());
    // 面板 globalWebUA：注册完善页走 **web 指纹**，不是桌面端 CLI 指纹。
    headers.insert(
        "user-agent".to_string(),
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 \
         (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36"
            .to_string(),
    );
    headers.insert("origin".to_string(), base.to_string());
    headers.insert("referer".to_string(), format!("{base}/"));
    if with_user_id_header {
        if let Some(uid) = identity
            .uid
            .as_deref()
            .map(str::trim)
            .filter(|value| !value.is_empty())
        {
            headers.insert("x-user-id".to_string(), uid.to_string());
        }
    }

    ProviderPoolQuotaRequestSpec {
        request_id: format!("{quota_kind}:{key_id}"),
        provider_name: "workbuddy".to_string(),
        quota_kind: quota_kind.to_string(),
        method: method.to_string(),
        url: format!("{base}{path}"),
        headers,
        content_type: Some("application/json".to_string()),
        json_body,
        client_api_format: "openai:chat".to_string(),
        provider_api_format: "workbuddy:desktop".to_string(),
        model_name: None,
    }
}

/// 注册状态查询（面板 `GlobalRegisterStatus`）：`GET …/overseas/user/register?userId=<uid>`。
///
/// 路径里的 `userId` 与 `x-user-id` 头**都要**（面板两处都写了）。
pub fn build_workbuddy_pool_global_register_status_request(
    key_id: &str,
    web_base_url: &str,
    identity: &WorkbuddyIdentity,
    authorization: (String, String),
) -> ProviderPoolQuotaRequestSpec {
    let uid = identity
        .uid
        .as_deref()
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .unwrap_or_default();
    let path = format!(
        "{}?userId={uid}",
        aether_provider_transport::workbuddy::global_register::WORKBUDDY_GLOBAL_REGISTER_PATH
    );
    build_workbuddy_pool_global_register_spec(
        key_id,
        web_base_url,
        &path,
        "GET",
        "workbuddy_global_register_status",
        identity,
        authorization,
        None,
        true,
    )
}

/// 可选注册地区列表（面板 `GlobalFetchCountries`）：`POST /billing/area/get-country-code`。
pub fn build_workbuddy_pool_global_country_code_request(
    key_id: &str,
    web_base_url: &str,
    identity: &WorkbuddyIdentity,
    authorization: (String, String),
) -> ProviderPoolQuotaRequestSpec {
    build_workbuddy_pool_global_register_spec(
        key_id,
        web_base_url,
        aether_provider_transport::workbuddy::global_register::WORKBUDDY_GLOBAL_COUNTRY_CODE_PATH,
        "POST",
        "workbuddy_global_country_code",
        identity,
        authorization,
        Some(
            aether_provider_transport::workbuddy::global_register::
                build_workbuddy_global_country_code_body(),
        ),
        false,
    )
}

/// 提交注册地区（面板 `GlobalSubmitRegion`）：`POST /console/login/account`（幂等）。
pub fn build_workbuddy_pool_global_submit_region_request(
    key_id: &str,
    web_base_url: &str,
    identity: &WorkbuddyIdentity,
    authorization: (String, String),
    country: &aether_provider_transport::workbuddy::global_register::WorkbuddyGlobalCountry,
) -> ProviderPoolQuotaRequestSpec {
    build_workbuddy_pool_global_register_spec(
        key_id,
        web_base_url,
        aether_provider_transport::workbuddy::global_register::WORKBUDDY_GLOBAL_SUBMIT_REGION_PATH,
        "POST",
        "workbuddy_global_submit_region",
        identity,
        authorization,
        Some(
            aether_provider_transport::workbuddy::global_register::
                build_workbuddy_global_submit_region_body(country),
        ),
        false,
    )
}

#[cfg(test)]
mod global_register_tests {
    use super::*;
    use aether_provider_transport::workbuddy::global_register::{
        WorkbuddyGlobalCountry, WORKBUDDY_GLOBAL_COUNTRY_CODE_PATH, WORKBUDDY_GLOBAL_REGISTER_PATH,
        WORKBUDDY_GLOBAL_SUBMIT_REGION_PATH,
    };
    // `WorkbuddyRealm` 在本文件根部没有导入（各测试模块各自引），这里显式引一次。
    use aether_provider_transport::workbuddy::WorkbuddyRealm;

    fn identity(realm: WorkbuddyRealm) -> WorkbuddyIdentity {
        WorkbuddyIdentity {
            realm,
            uid: Some("uid-1".to_string()),
            enterprise_id: None,
            domain: None,
            device_token: None,
        }
    }

    fn country() -> WorkbuddyGlobalCountry {
        WorkbuddyGlobalCountry {
            en_name: "Hong Kong".to_string(),
            name: "中国香港".to_string(),
            ios2: "HK".to_string(),
            ios3: "HKG".to_string(),
            code: "344".to_string(),
        }
    }

    #[test]
    fn register_status_request_carries_user_id_in_path_and_header() {
        let spec = build_workbuddy_pool_global_register_status_request(
            "key-1",
            "https://www.workbuddy.ai",
            &identity(WorkbuddyRealm::Global),
            ("authorization".to_string(), "Bearer t".to_string()),
        );
        assert_eq!(spec.method, "GET");
        assert_eq!(
            spec.url,
            format!("https://www.workbuddy.ai{WORKBUDDY_GLOBAL_REGISTER_PATH}?userId=uid-1")
        );
        assert_eq!(spec.json_body, None);
        assert_eq!(
            spec.headers.get("x-user-id").map(String::as_str),
            Some("uid-1")
        );
        assert_eq!(
            spec.headers.get("authorization").map(String::as_str),
            Some("Bearer t")
        );
        // web 指纹：Chrome UA + 官网 Origin/Referer
        assert!(spec
            .headers
            .get("user-agent")
            .is_some_and(|ua| ua.contains("Chrome/120.0.0.0")));
        assert_eq!(
            spec.headers.get("origin").map(String::as_str),
            Some("https://www.workbuddy.ai")
        );
        assert_eq!(
            spec.headers.get("referer").map(String::as_str),
            Some("https://www.workbuddy.ai/")
        );
        // 不带桌面端专属头
        assert!(!spec.headers.contains_key("x-client-platform"));
        assert!(!spec.headers.contains_key("x-domain"));
    }

    #[test]
    fn country_code_request_posts_filter_forbidden() {
        let spec = build_workbuddy_pool_global_country_code_request(
            "key-1",
            "https://www.workbuddy.ai/",
            &identity(WorkbuddyRealm::Global),
            ("authorization".to_string(), "Bearer t".to_string()),
        );
        assert_eq!(spec.method, "POST");
        // base 末尾斜杠要被归一，不能拼出 `//billing`
        assert_eq!(
            spec.url,
            format!("https://www.workbuddy.ai{WORKBUDDY_GLOBAL_COUNTRY_CODE_PATH}")
        );
        assert_eq!(
            spec.json_body,
            Some(serde_json::json!({"filterForbidden": 1}))
        );
    }

    #[test]
    fn submit_region_request_posts_the_single_element_arrays() {
        let spec = build_workbuddy_pool_global_submit_region_request(
            "key-1",
            "https://www.workbuddy.ai",
            &identity(WorkbuddyRealm::Global),
            ("authorization".to_string(), "Bearer t".to_string()),
            &country(),
        );
        assert_eq!(spec.method, "POST");
        assert_eq!(
            spec.url,
            format!("https://www.workbuddy.ai{WORKBUDDY_GLOBAL_SUBMIT_REGION_PATH}")
        );
        let body = spec.json_body.expect("body");
        assert_eq!(body["attributes"]["countryName"], serde_json::json!(["HK"]));
        assert_eq!(
            body["attributes"]["countryCode"],
            serde_json::json!(["344"])
        );
    }

    #[test]
    fn request_ids_are_namespaced_per_step() {
        let identity = identity(WorkbuddyRealm::Global);
        let authorization = ("authorization".to_string(), "Bearer t".to_string());
        let status = build_workbuddy_pool_global_register_status_request(
            "key-1",
            "https://www.workbuddy.ai",
            &identity,
            authorization.clone(),
        );
        let countries = build_workbuddy_pool_global_country_code_request(
            "key-1",
            "https://www.workbuddy.ai",
            &identity,
            authorization.clone(),
        );
        assert_eq!(status.request_id, "workbuddy_global_register_status:key-1");
        assert_eq!(countries.request_id, "workbuddy_global_country_code:key-1");
    }
}

/// 计费域的通用请求构造（头族与余额查询一致；路径由调用方给定）。
#[allow(clippy::too_many_arguments)]
fn build_workbuddy_billing_spec(
    key_id: &str,
    billing_base_url: &str,
    path: &str,
    identity: &WorkbuddyIdentity,
    authorization: (String, String),
    quota_kind: &str,
    method: &str,
    json_body: Option<Value>,
) -> ProviderPoolQuotaRequestSpec {
    let base = billing_base_url.trim().trim_end_matches('/');
    let mut headers = BTreeMap::new();
    headers.insert(authorization.0.trim().to_ascii_lowercase(), authorization.1);
    headers.insert("accept".to_string(), "application/json".to_string());
    headers.insert("content-type".to_string(), "application/json".to_string());
    insert_workbuddy_request_headers(identity, &mut headers);
    // 计费/成长域用**单段** UA（面板 BillingHeaders / illingUA()），与对话端点区分。
    apply_workbuddy_billing_user_agent(&mut headers);
    if let Some(enterprise_id) = identity
        .enterprise_id
        .as_deref()
        .map(str::trim)
        .filter(|value| !value.is_empty())
    {
        headers.insert("x-tenant-id".to_string(), enterprise_id.to_string());
    }

    ProviderPoolQuotaRequestSpec {
        request_id: format!("{quota_kind}:{key_id}"),
        provider_name: "workbuddy".to_string(),
        quota_kind: quota_kind.to_string(),
        method: method.to_string(),
        url: format!("{base}{path}"),
        headers,
        content_type: Some("application/json".to_string()),
        json_body,
        client_api_format: "openai:chat".to_string(),
        provider_api_format: "workbuddy:billing".to_string(),
        model_name: None,
    }
}

#[allow(clippy::too_many_arguments)]
fn build_workbuddy_growth_spec(
    key_id: &str,
    chat_base_url: &str,
    path: &str,
    identity: &WorkbuddyIdentity,
    authorization: (String, String),
    quota_kind: &str,
    method: &str,
    json_body: Option<Value>,
) -> ProviderPoolQuotaRequestSpec {
    let base = chat_base_url.trim().trim_end_matches('/');
    let mut headers = BTreeMap::new();
    headers.insert(authorization.0.trim().to_ascii_lowercase(), authorization.1);
    headers.insert("accept".to_string(), "application/json".to_string());
    headers.insert("content-type".to_string(), "application/json".to_string());
    insert_workbuddy_request_headers(identity, &mut headers);
    // 计费/成长域用**单段** UA（面板 BillingHeaders / illingUA()），与对话端点区分。
    apply_workbuddy_billing_user_agent(&mut headers);
    if let Some(enterprise_id) = identity
        .enterprise_id
        .as_deref()
        .map(str::trim)
        .filter(|value| !value.is_empty())
    {
        headers.insert("x-tenant-id".to_string(), enterprise_id.to_string());
    }

    ProviderPoolQuotaRequestSpec {
        request_id: format!("{quota_kind}:{key_id}"),
        provider_name: "workbuddy".to_string(),
        quota_kind: quota_kind.to_string(),
        method: method.to_string(),
        url: format!("{base}{path}"),
        headers,
        content_type: Some("application/json".to_string()),
        json_body,
        client_api_format: "openai:chat".to_string(),
        provider_api_format: "workbuddy:growth".to_string(),
        model_name: None,
    }
}

/// 个人口径的请求体：分页 + 只取未过期/已冻结的套餐（面板同字段）。
fn workbuddy_user_resource_body(now_unix_secs: u64) -> serde_json::Value {
    let offset = chrono::FixedOffset::east_opt(8 * 60 * 60).expect("CST offset");
    let now = chrono::DateTime::from_timestamp(now_unix_secs as i64, 0)
        .unwrap_or_else(|| chrono::DateTime::from_timestamp(0, 0).expect("epoch"))
        .with_timezone(&offset);
    let begin = now.format(WORKBUDDY_PACKAGE_TIME_LAYOUT).to_string();
    let end = (now + chrono::Duration::days(WORKBUDDY_PACKAGE_RANGE_DAYS))
        .format(WORKBUDDY_PACKAGE_TIME_LAYOUT)
        .to_string();
    serde_json::json!({
        "PageNumber": 1,
        "PageSize": 100,
        "ProductCode": WORKBUDDY_RESOURCE_PRODUCT_CODE,
        "Status": [0, 3],
        "PackageEndTimeRangeBegin": begin,
        "PackageEndTimeRangeEnd": end,
    })
}

#[cfg(test)]
mod tests {
    use aether_provider_transport::workbuddy::{
        workbuddy_billing_path_candidates, WorkbuddyBillingEndpoint, WorkbuddyIdentity,
        WorkbuddyRealm, WORKBUDDY_ENTERPRISE_USAGE_PATH, WORKBUDDY_REPORT_PATH,
        WORKBUDDY_USER_RESOURCE_PATH, WORKBUDDY_USER_RESOURCE_PATH_GLOBAL,
    };

    use super::{
        build_workbuddy_pool_quota_request, workbuddy_key_realm, WorkbuddyProviderPoolAdapter,
    };
    use crate::provider::ProviderPoolAdapter;

    fn cn_identity(enterprise_id: Option<&str>) -> WorkbuddyIdentity {
        WorkbuddyIdentity {
            realm: WorkbuddyRealm::Cn,
            uid: Some("uid-1".to_string()),
            enterprise_id: enterprise_id.map(str::to_string),
            domain: Some("example.com".to_string()),
            device_token: None,
        }
    }

    #[test]
    fn adapter_advertises_quota_refresh() {
        let adapter = WorkbuddyProviderPoolAdapter;
        assert_eq!(adapter.provider_type(), "workbuddy");
        assert!(adapter.supports_quota_refresh());
    }

    /// 个人口径：打个人资源包端点（**计费域**，不是对话域），body 带分页与 CST 时间范围，
    /// 头族复用对话域注入。
    #[test]
    fn personal_request_targets_the_user_resource_endpoint_on_the_billing_host() {
        use aether_provider_transport::workbuddy::workbuddy_billing_base_url;

        let spec = build_workbuddy_pool_quota_request(
            "key-1",
            workbuddy_billing_base_url(WorkbuddyRealm::Cn),
            WORKBUDDY_USER_RESOURCE_PATH,
            &cn_identity(None),
            ("authorization".to_string(), "Bearer token-1".to_string()),
            1_791_892_800,
        );
        assert_eq!(spec.method, "POST");
        assert_eq!(
            spec.url,
            format!("https://www.codebuddy.cn{WORKBUDDY_USER_RESOURCE_PATH}")
        );
        assert_eq!(
            spec.headers.get("authorization").map(String::as_str),
            Some("Bearer token-1")
        );
        // 官方指纹头族随请求带上（风控闸门头 + 身份头 + 三段式 UA）。
        assert_eq!(
            spec.headers.get("x-codebuddy-request").map(String::as_str),
            Some("1")
        );
        assert_eq!(
            spec.headers.get("x-user-id").map(String::as_str),
            Some("uid-1")
        );
        assert!(
            spec.headers
                .get("user-agent")
                .is_some_and(|value| value.starts_with("WorkBuddy/")),
            "headers={:?}",
            spec.headers
        );
        // 个人口径不带租户头。
        assert!(!spec.headers.contains_key("x-tenant-id"));

        let body = spec.json_body.expect("body");
        assert_eq!(body["PageNumber"], serde_json::json!(1));
        assert_eq!(body["PageSize"], serde_json::json!(100));
        assert_eq!(body["Status"], serde_json::json!([0, 3]));
        // 2026-10-13 12:00 UTC = 20:00 CST。
        assert_eq!(
            body["PackageEndTimeRangeBegin"],
            serde_json::json!("2026-10-13 20:00:00")
        );
    }

    /// 企业口径：打企业额度端点、body 为空、带 X-Enterprise-Id / X-Tenant-Id。
    #[test]
    fn enterprise_request_targets_the_enterprise_usage_endpoint() {
        let spec = build_workbuddy_pool_quota_request(
            "key-2",
            "https://www.workbuddy.ai",
            WORKBUDDY_ENTERPRISE_USAGE_PATH,
            &cn_identity(Some("ent-9")),
            ("authorization".to_string(), "Bearer token-2".to_string()),
            1_791_892_800,
        );
        assert_eq!(
            spec.url,
            format!("https://www.workbuddy.ai{WORKBUDDY_ENTERPRISE_USAGE_PATH}")
        );
        assert_eq!(spec.json_body, Some(serde_json::json!({})));
        assert_eq!(
            spec.headers.get("x-enterprise-id").map(String::as_str),
            Some("ent-9")
        );
        assert_eq!(
            spec.headers.get("x-tenant-id").map(String::as_str),
            Some("ent-9")
        );
    }

    /// 11102 负缓存：只在 (账号, 模型) 维度生效、到点失效；别的模型/别的 provider 不受影响。
    #[test]
    fn model_blocked_negative_cache_is_scoped_to_the_model_and_expires() {
        use super::{workbuddy_model_blocked_at, WORKBUDDY_MODEL_BLOCKED_METADATA_KEY};

        let metadata = serde_json::json!({
            "workbuddy": {
                WORKBUDDY_MODEL_BLOCKED_METADATA_KEY: {
                    "GLM-5.2": {"until_unix_secs": 2_000u64, "hits": 2}
                }
            }
        });
        // 期内命中（大小写不敏感）。
        assert!(workbuddy_model_blocked_at(
            Some(&metadata),
            "glm-5.2",
            1_000
        ));
        assert!(workbuddy_model_blocked_at(
            Some(&metadata),
            " GLM-5.2 ",
            1_000
        ));
        // 到期即失效（半开探测：允许再试一次）。
        assert!(!workbuddy_model_blocked_at(
            Some(&metadata),
            "glm-5.2",
            2_000
        ));
        // 别的模型不受影响——这正是「不误杀账号」的关键。
        assert!(!workbuddy_model_blocked_at(
            Some(&metadata),
            "deepseek-v4-flash",
            1_000
        ));
        // 其它 provider 的元数据、空模型名、畸形结构都当「没被排除」。
        assert!(!workbuddy_model_blocked_at(
            Some(
                &serde_json::json!({"codex": {"model_blocked": {"glm-5.2": {"until_unix_secs": 9_999}}}})
            ),
            "glm-5.2",
            1_000
        ));
        assert!(!workbuddy_model_blocked_at(Some(&metadata), "  ", 1_000));
        assert!(!workbuddy_model_blocked_at(None, "glm-5.2", 1_000));
        assert!(!workbuddy_model_blocked_at(
            Some(&serde_json::json!({"workbuddy": {"model_blocked": "oops"}})),
            "glm-5.2",
            1_000
        ));
        // 缺 until 字段 → 不视为排除。
        assert!(!workbuddy_model_blocked_at(
            Some(&serde_json::json!({"workbuddy": {"model_blocked": {"glm-5.2": {"hits": 1}}}})),
            "glm-5.2",
            1_000
        ));
    }

    /// 适配器把负缓存接到 `quota_hard_blocked`（调度器评估候选时问的就是它）。
    #[test]
    fn adapter_reports_model_hard_block_from_metadata() {
        use crate::provider::ProviderPoolMemberInput;

        let mut key =
            aether_data_contracts::repository::provider_catalog::StoredProviderCatalogKey::new(
                "key-1".to_string(),
                "provider-1".to_string(),
                "key-1".to_string(),
                "oauth".to_string(),
                None,
                true,
            )
            .expect("key should build");
        let future = crate::quota::provider_pool_current_unix_secs().unwrap_or(0) + 3_600;
        key.upstream_metadata = Some(serde_json::json!({
            "workbuddy": {"model_blocked": {"glm-5.2": {"until_unix_secs": future}}}
        }));

        let adapter = WorkbuddyProviderPoolAdapter;
        let input = ProviderPoolMemberInput {
            provider_type: "workbuddy",
            key: &key,
            auth_config: None,
            provider_model_name: Some("glm-5.2"),
        };
        assert!(adapter.quota_hard_blocked(&input));

        // 别的模型可选。
        let input = ProviderPoolMemberInput {
            provider_model_name: Some("deepseek-v4-flash"),
            ..input
        };
        assert!(!adapter.quota_hard_blocked(&input));
        // 没有模型信息时不排除（宁可让它试，也不误杀）。
        let input = ProviderPoolMemberInput {
            provider_model_name: None,
            ..input
        };
        assert!(!adapter.quota_hard_blocked(&input));
    }

    /// 签到请求：空 body、**计费域**、头族与余额查询一致；
    /// 路径按 realm 的候选序列逐个构造（国际域首条是无 `/v2` 前缀的那条）。
    #[test]
    fn daily_checkin_request_uses_the_realm_path_and_empty_body() {
        use super::build_workbuddy_pool_daily_checkin_request;
        use aether_provider_transport::workbuddy::{
            workbuddy_billing_base_url, WorkbuddyBillingEndpoint, WorkbuddyRealm,
            WORKBUDDY_DAILY_CHECKIN_PATH,
        };

        let candidates = workbuddy_billing_path_candidates(
            WorkbuddyBillingEndpoint::DailyCheckin,
            WorkbuddyRealm::Cn,
        );
        assert_eq!(candidates, vec![WORKBUDDY_DAILY_CHECKIN_PATH]);
        let spec = build_workbuddy_pool_daily_checkin_request(
            "key-1",
            workbuddy_billing_base_url(WorkbuddyRealm::Cn),
            candidates[0],
            &cn_identity(None),
            ("authorization".to_string(), "Bearer token-1".to_string()),
        );
        assert_eq!(spec.method, "POST");
        assert_eq!(
            spec.url,
            format!("https://www.codebuddy.cn{WORKBUDDY_DAILY_CHECKIN_PATH}")
        );
        assert_eq!(spec.json_body, Some(serde_json::json!({})));
        assert_eq!(
            spec.headers.get("x-codebuddy-request").map(String::as_str),
            Some("1")
        );

        // 国际域：两条候选，首条无 `/v2` 前缀、次条带前缀（404 才回退）。
        let mut global_identity = cn_identity(None);
        global_identity.realm = WorkbuddyRealm::Global;
        let candidates = workbuddy_billing_path_candidates(
            WorkbuddyBillingEndpoint::DailyCheckin,
            WorkbuddyRealm::Global,
        );
        assert_eq!(candidates.len(), 2);
        let spec = build_workbuddy_pool_daily_checkin_request(
            "key-2",
            workbuddy_billing_base_url(WorkbuddyRealm::Global),
            candidates[0],
            &global_identity,
            ("authorization".to_string(), "Bearer token-2".to_string()),
        );
        assert_eq!(
            spec.url,
            "https://www.workbuddy.ai/billing/meter/daily-checkin"
        );
        let fallback = build_workbuddy_pool_daily_checkin_request(
            "key-2",
            workbuddy_billing_base_url(WorkbuddyRealm::Global),
            candidates[1],
            &global_identity,
            ("authorization".to_string(), "Bearer token-2".to_string()),
        );
        assert_eq!(
            fallback.url,
            "https://www.workbuddy.ai/v2/billing/meter/daily-checkin"
        );
    }

    /// 活跃上报：长度为 1 的事件数组、全字段、`userId` 必填、计费域 `/v2/report`。
    #[test]
    fn activity_report_carries_a_full_chat_request_send_event() {
        use super::build_workbuddy_pool_activity_report_request;
        use aether_provider_transport::workbuddy::{workbuddy_billing_base_url, WorkbuddyRealm};

        let spec = build_workbuddy_pool_activity_report_request(
            "key-1",
            workbuddy_billing_base_url(WorkbuddyRealm::Cn),
            WORKBUDDY_REPORT_PATH,
            &cn_identity(None),
            ("authorization".to_string(), "Bearer token-1".to_string()),
            "uid-1",
            1_791_892_800_000,
        );
        assert_eq!(spec.method, "POST");
        assert_eq!(spec.url, "https://www.codebuddy.cn/v2/report");

        let body = spec.json_body.expect("body");
        let events = body.as_array().expect("events array");
        assert_eq!(events.len(), 1, "上游按数组解析，长度必须为 1");
        let event = &events[0];
        assert_eq!(event["eventCode"], serde_json::json!("chat_request_send"));
        // userId 缺了上游 200 但静默丢弃 —— 这里必须是账号 uid 本身。
        assert_eq!(event["userId"], serde_json::json!("uid-1"));
        assert_eq!(event["timestamp"], serde_json::json!(1_791_892_800_000u64));
        assert_eq!(event["presentAt"], serde_json::json!(1_791_892_800_000u64));
        // 全字段形状（抽查几个容易被「最小化」掉的字段）。
        for key in [
            "mode",
            "conversationId",
            "requestId",
            "requestModelId",
            "requestModelName",
            "inputLength",
            "mentionContexts",
            "knowledgeId",
            "knowledgeName",
            "agentName",
            "agentType",
            "rootRequestId",
            "parentConversationId",
        ] {
            assert!(event.get(key).is_some(), "missing field {key}: {event}");
        }
        assert_eq!(event["agentType"], serde_json::json!("conversation"));
        assert_eq!(
            event["mentionContexts"],
            serde_json::json!([]),
            "空数组字段不能被省略"
        );
    }

    /// trial 加油包：**global 专属**、计费域、无 body（CN 无此端点）。
    #[test]
    fn trial_claim_request_targets_the_billing_host_without_a_body() {
        use super::build_workbuddy_pool_trial_claim_request;

        let identity = cn_identity(None);
        let spec = build_workbuddy_pool_trial_claim_request(
            "key-1",
            "https://www.workbuddy.ai",
            &identity,
            ("authorization".to_string(), "Bearer token-1".to_string()),
        );
        assert_eq!(spec.method, "POST");
        assert_eq!(spec.url, "https://www.workbuddy.ai/billing/ide/trial");
        assert_eq!(spec.json_body, None, "trial 无请求体");
        assert_eq!(spec.quota_kind, "workbuddy_trial_claim");
        // 计费域口径：单段 UA（不是对话域三段式）。
        assert_eq!(
            spec.headers.get("user-agent").map(String::as_str),
            Some(aether_provider_transport::workbuddy::workbuddy_billing_user_agent().as_str())
        );
    }

    /// 成长任务：列表（默认/mp 两种口径）、批量报名、官网域与小程序口径领奖。
    #[test]
    fn growth_task_requests_match_the_panel_endpoints() {
        use super::{
            build_workbuddy_pool_task_claim_mp_request,
            build_workbuddy_pool_task_claim_web_request, build_workbuddy_pool_tasks_accept_request,
            build_workbuddy_pool_tasks_list_request,
        };

        let identity = cn_identity(None);
        let authorization = ("authorization".to_string(), "Bearer token-1".to_string());
        let chat = "https://copilot.tencent.com";
        let web = "https://www.workbuddy.cn";

        let list = build_workbuddy_pool_tasks_list_request(
            "key-1",
            chat,
            &identity,
            authorization.clone(),
            false,
        );
        assert_eq!(list.method, "GET");
        assert_eq!(list.url, format!("{chat}/v2/activity/growth/tasks"));
        assert!(!list.headers.contains_key("x-client-platform"));
        // 成长域（BillingHeaders 口径）用**单段**计费 UA。
        assert_eq!(
            list.headers.get("user-agent").map(String::as_str),
            Some(aether_provider_transport::workbuddy::workbuddy_billing_user_agent().as_str())
        );

        let list_mp = build_workbuddy_pool_tasks_list_request(
            "key-1",
            chat,
            &identity,
            authorization.clone(),
            true,
        );
        assert_eq!(
            list_mp.headers.get("x-client-platform").map(String::as_str),
            Some("miniprogram")
        );

        let accept = build_workbuddy_pool_tasks_accept_request(
            "key-1",
            chat,
            &identity,
            authorization.clone(),
            &["a".to_string(), "b".to_string()],
            false,
        );
        assert_eq!(
            accept.url,
            format!("{chat}/v2/activity/growth/tasks/accept")
        );
        assert_eq!(
            accept.json_body.expect("body")["task_codes"],
            serde_json::json!(["a", "b"])
        );

        // 官网域领奖：task_code 在**路径**里、无 body，且头族覆盖为官网成长中心。
        let claim = build_workbuddy_pool_task_claim_web_request(
            "key-1",
            web,
            &identity,
            authorization.clone(),
            "chat_3_times",
        );
        assert_eq!(
            claim.url,
            "https://www.workbuddy.cn/activity/growth/tasks/chat_3_times/claim"
        );
        assert_eq!(claim.json_body, None);
        assert_eq!(
            claim.headers.get("origin").map(String::as_str),
            Some("https://www.workbuddy.cn")
        );
        assert_eq!(
            claim.headers.get("referer").map(String::as_str),
            Some("https://www.workbuddy.cn/profile/growth-center")
        );
        assert_eq!(
            claim.headers.get("x-client-platform").map(String::as_str),
            Some("web")
        );
        // 官网领奖用的是**对话域三段式 UA**（面板 `ClaimReward` 取 `c.userAgent(a)`）。
        assert_eq!(
            claim.headers.get("user-agent").map(String::as_str),
            Some(
                aether_provider_transport::workbuddy::workbuddy_user_agent(identity.realm).as_str()
            )
        );
        assert!(
            claim
                .headers
                .get("user-agent")
                .is_some_and(|value| value.contains("CLI/")),
            "官网领奖应带 CLI 段：{:?}",
            claim.headers
        );

        // 小程序口径领奖：对话域同路径 + mp 头。
        let claim_mp = build_workbuddy_pool_task_claim_mp_request(
            "key-1",
            chat,
            &identity,
            authorization,
            "Sequential_Tasks_1",
        );
        assert_eq!(
            claim_mp.url,
            "https://copilot.tencent.com/activity/growth/tasks/Sequential_Tasks_1/claim"
        );
        assert_eq!(
            claim_mp
                .headers
                .get("x-client-platform")
                .map(String::as_str),
            Some("miniprogram")
        );
    }

    #[test]
    fn makeup_and_claim_requests_match_the_panel_paths() {
        use super::{
            build_workbuddy_pool_claim_compensation_request,
            build_workbuddy_pool_claim_gift_request, build_workbuddy_pool_growth_heatmap_request,
            build_workbuddy_pool_growth_makeup_use_request,
        };

        let identity = cn_identity(None);
        let authorization = ("authorization".to_string(), "Bearer token-1".to_string());

        let heatmap = build_workbuddy_pool_growth_heatmap_request(
            "key-1",
            "https://copilot.tencent.com",
            &identity,
            authorization.clone(),
        );
        assert_eq!(heatmap.method, "GET");
        assert_eq!(
            heatmap.url,
            "https://copilot.tencent.com/activity/growth/heatmap"
        );

        let makeup = build_workbuddy_pool_growth_makeup_use_request(
            "key-1",
            "https://copilot.tencent.com",
            &identity,
            authorization.clone(),
            "2026-10-12",
        );
        assert_eq!(makeup.method, "POST");
        assert_eq!(
            makeup.url,
            "https://copilot.tencent.com/activity/growth/makeup-cards/use"
        );
        assert_eq!(
            makeup.json_body.expect("body")["target_date"],
            serde_json::json!("2026-10-12")
        );

        // 计费域 + **无 `/v2` 前缀**（面板 `claim-gift` / `claim-compensation` 就是这样）。
        let gift = build_workbuddy_pool_claim_gift_request(
            "key-1",
            "https://www.codebuddy.cn",
            &identity,
            authorization.clone(),
        );
        assert_eq!(
            gift.url,
            "https://www.codebuddy.cn/billing/meter/claim-gift"
        );
        assert_eq!(gift.json_body, Some(serde_json::json!({})));

        let compensation = build_workbuddy_pool_claim_compensation_request(
            "key-1",
            "https://www.codebuddy.cn",
            &identity,
            authorization,
        );
        assert_eq!(
            compensation.url,
            "https://www.codebuddy.cn/billing/meter/claim-compensation"
        );
    }

    /// 成长中心请求：**对话域** + 计费头族；兑换/抽奖带幂等令牌，查询是 GET。
    #[test]
    fn growth_requests_target_the_chat_host_with_idempotency_tokens() {
        use super::{
            build_workbuddy_pool_growth_lottery_draw_request,
            build_workbuddy_pool_growth_lottery_summary_request,
            build_workbuddy_pool_growth_redeem_request, build_workbuddy_pool_growth_streak_request,
        };

        let identity = cn_identity(None);
        let authorization = ("authorization".to_string(), "Bearer token-1".to_string());
        let streak = build_workbuddy_pool_growth_streak_request(
            "key-1",
            "https://copilot.tencent.com/",
            &identity,
            authorization.clone(),
        );
        assert_eq!(streak.method, "GET");
        assert_eq!(
            streak.url,
            "https://copilot.tencent.com/activity/growth/streak"
        );
        assert_eq!(streak.json_body, None);
        assert_eq!(
            streak
                .headers
                .get("x-codebuddy-request")
                .map(String::as_str),
            Some("1")
        );

        let redeem = build_workbuddy_pool_growth_redeem_request(
            "key-1",
            "https://copilot.tencent.com",
            &identity,
            authorization.clone(),
            "14d",
        );
        assert_eq!(redeem.method, "POST");
        assert_eq!(
            redeem.url,
            "https://copilot.tencent.com/activity/growth/redeem"
        );
        let body = redeem.json_body.expect("body");
        assert_eq!(body["tier"], serde_json::json!("14d"));
        let token = body["client_token"].as_str().expect("client_token");
        assert_eq!(token.len(), 36, "幂等令牌必须是 UUID 形态");

        let summary = build_workbuddy_pool_growth_lottery_summary_request(
            "key-1",
            "https://copilot.tencent.com",
            &identity,
            authorization.clone(),
        );
        assert_eq!(summary.method, "GET");
        assert_eq!(
            summary.url,
            "https://copilot.tencent.com/activity/growth/lottery/summary"
        );

        let draw = build_workbuddy_pool_growth_lottery_draw_request(
            "key-1",
            "https://copilot.tencent.com",
            &identity,
            authorization,
        );
        assert_eq!(draw.method, "POST");
        assert_eq!(
            draw.url,
            "https://copilot.tencent.com/activity/growth/lottery/draw"
        );
        assert!(draw.json_body.expect("body").get("client_token").is_some());
    }

    /// 猫猫旅行：全部在对话域；派出固定地点 4；领奖带 record_id；协议/领养 body 形态固定。
    #[test]
    fn travel_requests_match_the_panel_paths_and_bodies() {
        use super::{
            build_workbuddy_pool_buddy_agreement_request, build_workbuddy_pool_buddy_first_request,
            build_workbuddy_pool_buddy_info_request, build_workbuddy_pool_travel_claim_request,
            build_workbuddy_pool_travel_depart_request, build_workbuddy_pool_travel_status_request,
        };

        let identity = cn_identity(None);
        let authorization = ("authorization".to_string(), "Bearer token-1".to_string());
        let base = "https://copilot.tencent.com";

        let info = build_workbuddy_pool_buddy_info_request(
            "key-1",
            base,
            &identity,
            authorization.clone(),
        );
        assert_eq!(info.method, "GET");
        assert_eq!(info.url, format!("{base}/activity/growth/buddy/info"));

        let status = build_workbuddy_pool_travel_status_request(
            "key-1",
            base,
            &identity,
            authorization.clone(),
        );
        assert_eq!(
            status.url,
            format!("{base}/activity/growth/buddy/travel/status")
        );

        let depart = build_workbuddy_pool_travel_depart_request(
            "key-1",
            base,
            &identity,
            authorization.clone(),
        );
        assert_eq!(depart.method, "POST");
        assert_eq!(
            depart.url,
            format!("{base}/activity/growth/buddy/travel/depart")
        );
        assert_eq!(
            depart.json_body.expect("body")["location_id"],
            serde_json::json!(4)
        );

        let claim = build_workbuddy_pool_travel_claim_request(
            "key-1",
            base,
            &identity,
            authorization.clone(),
            77,
        );
        assert_eq!(
            claim.url,
            format!("{base}/activity/growth/buddy/travel/claim")
        );
        assert_eq!(
            claim.json_body.expect("body")["record_id"],
            serde_json::json!(77)
        );

        let agreement = build_workbuddy_pool_buddy_agreement_request(
            "key-1",
            base,
            &identity,
            authorization.clone(),
        );
        assert_eq!(
            agreement.url,
            format!("{base}/activity/growth/buddy/agreement")
        );
        assert_eq!(
            agreement.json_body.expect("body")["agree"],
            serde_json::json!(true)
        );

        let first =
            build_workbuddy_pool_buddy_first_request("key-1", base, &identity, authorization);
        assert_eq!(first.url, format!("{base}/activity/growth/buddy/first"));
        assert_eq!(first.json_body, Some(serde_json::json!({})));
    }

    /// 国际域个人口径：候选首条是无 `/v2` 前缀的路径（面板 `billingMeterPaths` 的首选），
    /// 第二条才是带前缀的兜底。
    #[test]
    fn global_realm_uses_the_prefixed_free_path() {
        let mut identity = cn_identity(None);
        identity.realm = WorkbuddyRealm::Global;
        let candidates = workbuddy_billing_path_candidates(
            WorkbuddyBillingEndpoint::UserResource,
            WorkbuddyRealm::Global,
        );
        assert_eq!(
            candidates,
            vec![
                WORKBUDDY_USER_RESOURCE_PATH_GLOBAL,
                WORKBUDDY_USER_RESOURCE_PATH
            ]
        );
        let spec = build_workbuddy_pool_quota_request(
            "key-3",
            "https://www.workbuddy.ai/",
            candidates[0],
            &identity,
            ("authorization".to_string(), "Bearer token-3".to_string()),
            1_791_892_800,
        );
        assert_eq!(
            spec.url,
            format!("https://www.workbuddy.ai{WORKBUDDY_USER_RESOURCE_PATH_GLOBAL}")
        );
        // 计费域的 UA 是**单段** `WorkBuddy/<ver>`（面板 `billingUA()`，realm 无关）：
        // 官方 banner 覆写形态，不带 CLI 段，也没有 realm 平台段。
        assert_eq!(
            spec.headers.get("user-agent").map(String::as_str),
            Some(aether_provider_transport::workbuddy::workbuddy_billing_user_agent().as_str()),
            "headers={:?}",
            spec.headers
        );
        assert!(
            !spec
                .headers
                .get("user-agent")
                .is_some_and(|value| value.contains("WorkBuddy AI")),
            "计费域不该带 realm 平台段：{:?}",
            spec.headers
        );
    }

    /// 积分保底（面板 `credit_floor`）：只拦「触底 + 收费」，其余一律放行。
    #[test]
    fn credit_floor_blocks_paid_only_and_is_off_by_default() {
        use super::workbuddy_credit_floor_blocked;

        let metadata = serde_json::json!({
            "workbuddy": {
                "credits_remaining": 50,
                "models": [
                    {"model_uid": "glm-5.2", "credits": "0.79"},
                    {"model_uid": "hy3", "credits": "0"},
                    {"model_uid": "promo-free", "credits": "0.5", "promo_credits": "0x"},
                    {"model_uid": "no-rate"}
                ]
            }
        });
        let metadata = Some(&metadata);

        // 0 / 负值 = 关闭（面板默认 0，负值钳 0）
        assert!(!workbuddy_credit_floor_blocked(metadata, "glm-5.2", 0));
        assert!(!workbuddy_credit_floor_blocked(metadata, "glm-5.2", -5));
        // 未触底——**等于 floor 也不拦**（面板边界语义）
        assert!(!workbuddy_credit_floor_blocked(metadata, "glm-5.2", 50));
        assert!(!workbuddy_credit_floor_blocked(metadata, "glm-5.2", 40));
        // 上游**真实形态**：`credits` 是**前缀 x** 的 `"x0.29"`（2026-10-16 PG 直读发现）。
        // 只剥后缀 x 的老实现会把收费模型判成「未知倍率」→ 保底形同虚设，故加此钉子。
        let prefix_form = serde_json::json!({
            "workbuddy": {
                "credits_remaining": 10,
                "models": [
                    {"model_uid": "kimi-k3-1", "credits": "x1.62"},
                    {"model_uid": "hy3", "credits": "x0.00"},
                    {"model_uid": "step-5-preview", "credits": "x0.43", "promo_credits": "0x"},
                    {"model_uid": "glm-5.2", "credits": "x0.79", "promo_credits": "0.50x"}
                ]
            }
        });
        let prefix_form = Some(&prefix_form);
        assert!(
            workbuddy_credit_floor_blocked(prefix_form, "kimi-k3-1", 100),
            "前缀 x 的收费模型必须被拦"
        );
        assert!(
            !workbuddy_credit_floor_blocked(prefix_form, "hy3", 100),
            "x0.00 = 免费"
        );
        assert!(
            !workbuddy_credit_floor_blocked(prefix_form, "step-5-preview", 100),
            "生效价 0x = 限免，不该拦"
        );
        assert!(
            workbuddy_credit_floor_blocked(prefix_form, "glm-5.2", 100),
            "0.50x 折扣仍是收费（>0）"
        );

        // 触底 + 收费 → 拦（大小写与空格不敏感）
        assert!(workbuddy_credit_floor_blocked(metadata, "GLM-5.2", 100));
        assert!(workbuddy_credit_floor_blocked(metadata, " glm-5.2 ", 100));
        // 触底 + 免费（倍率 0）→ 放行：保底就是要留住免费模型
        assert!(!workbuddy_credit_floor_blocked(metadata, "hy3", 100));
        // 触底 + 限时免费（生效价 `0x`）→ 放行（按**生效价**判收费）
        assert!(!workbuddy_credit_floor_blocked(metadata, "promo-free", 100));
        // 触底 + 目录没有该模型 → 未知 → 放行
        assert!(!workbuddy_credit_floor_blocked(
            metadata,
            "not-in-catalog",
            100
        ));
        // 触底 + 有模型但没倍率字段 → 未知 → 放行（不编造收费）
        assert!(!workbuddy_credit_floor_blocked(metadata, "no-rate", 100));
        // 空模型名 / 无元数据 → 放行
        assert!(!workbuddy_credit_floor_blocked(metadata, "   ", 100));
        assert!(!workbuddy_credit_floor_blocked(None, "glm-5.2", 100));

        // 不限量不构成限制（面板 `client.go` 同款）
        let unlimited =
            serde_json::json!({"workbuddy": {"unlimited": true, "credits_remaining": 1}});
        assert!(!workbuddy_credit_floor_blocked(
            Some(&unlimited),
            "glm-5.2",
            100
        ));

        // 对象形态的 models（按 id 索引的档位快照）：键即模型 id
        let object_form = serde_json::json!({
            "workbuddy": {"credits_remaining": 5, "models": {"glm-5.2": {"credits": "0.30"}}}
        });
        assert!(workbuddy_credit_floor_blocked(
            Some(&object_form),
            "glm-5.2",
            100
        ));
        let object_form_no_rate = serde_json::json!({
            "workbuddy": {"credits_remaining": 5, "models": {"glm-5.2": {"efforts": ["high"]}}}
        });
        assert!(!workbuddy_credit_floor_blocked(
            Some(&object_form_no_rate),
            "glm-5.2",
            100
        ));
    }

    /// 刷新时自动改名的**整条决策**（维护性审计 ④：这条写路径原先零测试 ✗）。
    #[test]
    fn key_rename_target_only_touches_untouched_system_names() {
        use super::workbuddy_key_rename_target as target;

        // 系统生成名 + 真昵称 → 换成昵称 ✓
        assert_eq!(
            target("账号_1792139031", "fanjinlong1994@gmail.com"),
            Some("fanjinlong1994@gmail.com".to_string())
        );
        assert_eq!(
            target("  账号_1792139031_2 ", "  132****1637  "),
            Some("132****1637".to_string()),
            "两侧空白都要 trim ✓"
        );
        // 昵称空白（上游没给）→ 不动手 ✓
        assert_eq!(target("账号_1792139031", ""), None);
        assert_eq!(target("账号_1792139031", "   "), None);
        // 用户起过的名字 → **永不覆盖** ✓（这是本功能的铁律 ✓）
        assert_eq!(target("我的主力号", "fanjinlong1994@gmail.com"), None);
        assert_eq!(target("132****1637", "新昵称"), None);
        // 截断上限 120 字符 ✓（与建号路径同一个上限 ✓）
        let long = "x".repeat(300);
        assert_eq!(
            target("账号_1", &long).map(|name| name.chars().count()),
            Some(120)
        );
    }

    /// 「每日维护包」闸门（维护性修复：新号第一天也要能跑任务 ✓）。
    #[test]
    fn daily_bundle_runs_once_per_day_and_ignores_who_checked_in_first() {
        use super::workbuddy_daily_bundle_due as due;

        // 从没跑过 → 跑 ✓（新号 / 升级后第一轮 ✓）
        assert!(due(None, "2026-10-17"));
        assert!(due(Some(""), "2026-10-17"));
        assert!(due(Some("   "), "2026-10-17"));
        // 今天已经跑过 → 不再跑 ✓（当天最多一趟 ✓）
        assert!(!due(Some("2026-10-17"), "2026-10-17"));
        // 跨日 → 放开 ✓
        assert!(due(Some("2026-10-16"), "2026-10-17"));
        assert!(due(Some("2026-12-31"), "2027-01-01"));
        // 两侧空白都要容忍 ✓（上游/旧数据可能带空白）
        assert!(!due(Some(" 2026-10-17 "), "2026-10-17"));
    }

    /// 系统自动生成的 key 名判定（只有这种才允许被账号名自动替换）。
    #[test]
    fn system_generated_key_names_are_recognised_and_user_names_are_not() {
        use super::workbuddy_system_generated_key_name as is_generated;

        // 系统生成的两形态（`账号_<秒>` / `账号_<秒>_<序号>`）✓
        assert!(is_generated("账号_1791995213"));
        assert!(is_generated("账号_1792139031_2"));
        assert!(is_generated("  账号_1792139031  "));
        // 用户自己起的名字（含上游账号名）一律不认 ✗ —— 绝不覆盖人的意图 ✓
        assert!(!is_generated("132****1637"));
        assert!(!is_generated("fanjinlong1994@gmail.com"));
        assert!(!is_generated("我的主力号"));
        assert!(!is_generated("账号_abc"));
        assert!(!is_generated("账号_1792139031_x"));
        assert!(!is_generated("账号_"));
        assert!(!is_generated("账号_1792139031_2_3"));
        assert!(!is_generated("账号账号_1792139031"));
        assert!(!is_generated(""));
    }

    /// 单账号在途上限统一使用共享配置。
    #[test]
    fn in_flight_limit_uses_one_shared_realm_limit() {
        use super::workbuddy_in_flight_limit;

        assert_eq!(workbuddy_in_flight_limit(0, 0, None), 0);
        assert_eq!(workbuddy_in_flight_limit(5, 0, None), 5);
        assert_eq!(workbuddy_in_flight_limit(5, 3, None), 3);
        assert_eq!(
            workbuddy_in_flight_limit(
                5,
                3,
                Some(&serde_json::json!({"workbuddy":{"realm":"global"}}))
            ),
            3
        );
        assert_eq!(
            workbuddy_in_flight_limit(5, 3, Some(&serde_json::json!({"workbuddy":{"realm":"cn"}}))),
            3
        );
        let spaced = serde_json::json!({"workbuddy": {"realm": "  GLOBAL "}});
        assert_eq!(
            workbuddy_key_realm(Some(&spaced)).as_deref(),
            Some("global")
        );
        let cn_key = serde_json::json!({"workbuddy": {"realm": "cn"}});
        let unknown_key = serde_json::json!({"workbuddy": {"realm": "  "}});
        assert_eq!(workbuddy_key_realm(Some(&cn_key)).as_deref(), Some("cn"));
        assert_eq!(workbuddy_key_realm(Some(&unknown_key)), None);
        assert_eq!(workbuddy_key_realm(None), None);
    }

    /// 账号资料解析（面板 `profile.go` 的隐私边界与防串号语义）。
    #[test]
    fn account_profile_parses_only_nickname_and_guards_uid() {
        use super::workbuddy_nickname_from_account_profile;
        use serde_json::json;

        // ① 信封形态：只取 nickname，手机号等敏感字段一律被丢弃（返回值里不可能出现）
        let envelope = json!({
            "code": 0,
            "msg": "OK",
            "data": {"uid": "u-1", "nickname": "新名字", "phoneNumber": "13800000000"}
        });
        assert_eq!(
            workbuddy_nickname_from_account_profile(&envelope, "u-1").as_deref(),
            Some("新名字")
        );

        // ② 裸对象（无 data 信封）也认
        let bare = json!({"uid": "u-1", "nickname": "裸名"});
        assert_eq!(
            workbuddy_nickname_from_account_profile(&bare, "u-1").as_deref(),
            Some("裸名")
        );

        // ③ 串号防护：uid 与凭证不一致 → 丢弃（绝不把别人的昵称写到自己账号上）
        let other = json!({"data": {"uid": "someone-else", "nickname": "别人"}});
        assert_eq!(workbuddy_nickname_from_account_profile(&other, "u-1"), None);

        // ④ 任一侧 uid 缺失时不拦（面板同款：两边都非空才比对）
        let no_uid = json!({"data": {"nickname": "没 uid"}});
        assert_eq!(
            workbuddy_nickname_from_account_profile(&no_uid, "u-1").as_deref(),
            Some("没 uid")
        );
        let no_expected = json!({"data": {"uid": "u-9", "nickname": "没预期"}});
        assert_eq!(
            workbuddy_nickname_from_account_profile(&no_expected, "").as_deref(),
            Some("没预期")
        );

        // ⑤ 昵称缺失/空白 → None（调用方保持原值，不覆盖成空）
        assert_eq!(
            workbuddy_nickname_from_account_profile(&json!({"data": {"uid": "u-1"}}), "u-1"),
            None
        );
        assert_eq!(
            workbuddy_nickname_from_account_profile(&json!({"data": {"nickname": "   "}}), "u-1"),
            None
        );

        // ⑥ 首尾空白会被裁掉
        assert_eq!(
            workbuddy_nickname_from_account_profile(
                &json!({"data": {"nickname": "  空格名  "}}),
                "u-1"
            )
            .as_deref(),
            Some("空格名")
        );

        // ⑦ 请求构造：走 web 域 + web 平台头 + 资料页 Referer，且是 GET
        let spec = super::build_workbuddy_pool_account_profile_request(
            "key-1",
            "https://www.workbuddy.cn",
            &aether_provider_transport::workbuddy::WorkbuddyIdentity {
                realm: aether_provider_transport::workbuddy::WorkbuddyRealm::Cn,
                uid: Some("u-1".to_string()),
                enterprise_id: None,
                domain: None,
                device_token: None,
            },
            ("Bearer".to_string(), "token-1".to_string()),
        );
        assert_eq!(spec.method, "GET");
        assert_eq!(spec.url, "https://www.workbuddy.cn/console/account");
        assert_eq!(
            spec.headers.get("x-client-platform").map(String::as_str),
            Some("web")
        );
        assert_eq!(
            spec.headers.get("Referer").map(String::as_str),
            Some("https://www.workbuddy.cn/profile/account-settings")
        );
    }

    /// 国际号也要能拿昵称 ✓：Referer 必须与**同域**推导 ✓
    /// （旧实现直接对国际域 `return None` ✗，且 Referer 硬编码 CN 域 —— 跨域 Referer 会被
    /// 上游当异常请求 ✗）。
    #[test]
    fn account_profile_request_derives_referer_from_the_same_domain() {
        let spec = super::build_workbuddy_pool_account_profile_request(
            "key-1",
            "https://www.workbuddy.ai",
            &aether_provider_transport::workbuddy::WorkbuddyIdentity {
                realm: aether_provider_transport::workbuddy::WorkbuddyRealm::Global,
                uid: Some("u-1".to_string()),
                enterprise_id: None,
                domain: None,
                device_token: None,
            },
            ("Bearer".to_string(), "token-1".to_string()),
        );
        assert_eq!(spec.method, "GET");
        assert_eq!(spec.url, "https://www.workbuddy.ai/console/account");
        assert_eq!(
            spec.headers.get("x-client-platform").map(String::as_str),
            Some("web")
        );
        assert_eq!(
            spec.headers.get("Referer").map(String::as_str),
            Some("https://www.workbuddy.ai/profile/account-settings")
        );
    }
}
