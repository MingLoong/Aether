//! WorkBuddy（腾讯 CodeBuddy）上游失败分类。
//!
//! **为什么需要**：Aether 通用的失败分类只认状态码与少数通用文案，而 CodeBuddy 的
//! 语义大量藏在**业务 code** 里——`12153`（离线会话失效）、`11140`（账号级授权风控）、
//! `14017`（试用未激活）、`11102`（该后端无此模型）、`6004`（模型级限流）、
//! `14018`（积分耗尽）、`11101`/`11115`/`11135`（请求级错误）。不翻译这些码，
//! 死会话账号会一直被选中、限流与余额耗尽的账号不会被正确避让。
//!
//! 判定顺序**逐条照抄**面板 `internal/upstream/client.go` 的 `Classify`——
//! 顺序本身就是语义（例如「429 + 余额文案」必须按限流而不是硬欠费处理，
//! 否则会把健康号白扔 12 小时）。
//!
//! 事实来源：开源面板 `linguo2625469/workbuddy2api-panel`。

use std::sync::LazyLock;

use regex::Regex;
use serde_json::Value;

/// 上游失败分类（与面板 `ErrKind` 一一对应）。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum WorkbuddyFailureKind {
    /// 成功 / 非错误。
    None,
    /// 余额耗尽（402 / 14018 / 余额文案）→ 长冷却（面板扣到次日 04:00）。
    HardCredit,
    /// 软限流（429 / 限流文案）→ 短冷却。
    SoftRate,
    /// 离线会话失效（`12153` / `Offline user session not found`）→ 禁用 / 强制重登。
    SessionDead,
    /// 404 上游偶发 → 短冷却，不累计错误计数（防雪崩）。
    NotFound,
    /// 5xx 上游故障。
    Server,
    /// 内容策略拦截（审核文案）→ 不罚账号，走降级重试（见模块 `mod.rs`）。
    ContentBlocked,
    /// 请求体解析失败（11101）→ 请求级错误：不罚号、不轮转。
    BadParams,
    /// 账号级授权/配额故障（11140 / 14017）→ 冷却轮换，不无限重试。
    AccountFault,
    /// 该后端无此模型（11102）→ (账号, 模型) 负缓存避让。
    ModelBlocked,
    /// 套餐权限不足（11158 / personal_free_user）→ 仅记录在该账号×模型上。
    PlanBlocked,
    /// 模型级限流（`6004`）→ 只锁「账号×模型」这一格，**不冷却账号**。
    ///
    /// 为什么必须单独一类：没有它时 `6004` 会掉进下面的 `429` 兜底变成 [`Self::SoftRate`]，
    /// 而所有下游惩罚（自适应 RPM 学习、健康分、号池冷却）都是**账号维度**的——一个模型的
    /// 限额就把整个账号打停，正是「模型到上限 → 账号进冷却 → 其它模型也用不了」的根因。
    ModelRateLimit,
    /// 403 且无业务信封（WAF 拦截页 / 空体）→ 账号软冷却 + 抖动退避。
    WafBlock,
    /// 上下文超限（11115）→ 请求级错误：不罚号、不轮转。
    PromptTooLong,
    /// 图片格式/数据无效（11135）→ 请求级错误：不罚号、不轮转。
    ImageInvalid,
    /// 其它 4xx / 业务错误。
    Client,
}

impl WorkbuddyFailureKind {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::None => "none",
            Self::HardCredit => "hard_credit",
            Self::SoftRate => "soft_rate",
            Self::SessionDead => "session_dead",
            Self::NotFound => "not_found",
            Self::Server => "server",
            Self::ContentBlocked => "content_blocked",
            Self::BadParams => "bad_params",
            Self::AccountFault => "account_fault",
            Self::ModelBlocked => "model_blocked",
            Self::PlanBlocked => "plan_blocked",
            Self::ModelRateLimit => "model_rate_limit",
            Self::WafBlock => "waf_block",
            Self::PromptTooLong => "prompt_too_long",
            Self::ImageInvalid => "image_invalid",
            Self::Client => "client",
        }
    }
}

/// 会话失效 marker（**大小写敏感**，面板同款 `strings.Contains`）。
const SESSION_DEAD_MARKERS: [&str; 2] = ["Offline user session not found", "12153"];
/// 账号级授权/配额故障 marker（大小写不敏感）。
///
/// 注意 `11140` **不能**按 code 判定：同一个 code 也承载「模型级限流」文案，
/// 那种情况必须保持软限流语义。所以这里只收 `auth_forbidden` 的真实文案。
const ACCOUNT_FAULT_MARKERS: [&str; 3] = [
    "request illegal",
    "trial not activated",
    "trial version is not yet activated",
];
/// 余额/积分耗尽 marker（大小写不敏感）。
const HARD_CREDIT_MARKERS: [&str; 16] = [
    "insufficient credit",
    "no credit",
    "credit exhausted",
    "credits exhausted",
    "out of credit",
    "quota exceeded",
    "quota exhaust",
    "payment required",
    "credit not enough",
    "not enough credit",
    "积分不足",
    "额度不足",
    "余额不足",
    "积分用完",
    "额度用尽",
    "没有积分",
];
/// 限流 marker（大小写不敏感）。
const SOFT_RATE_MARKERS: [&str; 8] = [
    "rate limit",
    "rate-limiting",
    "rate-limited",
    "too many requests",
    "too many",
    "usage limit",
    "请求过于频繁",
    "限流",
];
/// 上下文超限 marker（其中三条是 code 形态，须保留原始大小写）。
const PROMPT_TOO_LONG_MARKERS: [&str; 4] = [
    r#""code":11115"#,
    r#""code": 11115"#,
    r#""code":"11115""#,
    "prompt is too long",
];
const CONTENT_BLOCKED_MARKERS: [&str; 3] = [
    "blocked by security policy",
    "unapproved channel",
    "illegal api invocation",
];
const INVALID_IMAGE_MARKERS: [&str; 3] = [
    "invalid image_url content",
    "invalid_image_data",
    "replace the image",
];
const IMAGE_INVALID_CODE: &str = "11135";
const BAD_PARAMS_MARKER_MSG: &str = "Unmarshal chat params failed";
const BAD_PARAMS_MARKER_CODE: &str = r#""code":11101"#;
const MODEL_BLOCK_CODE: &str = "11102";
const MODEL_BLOCK_MSG_MARKER: &str = "service info not found";
const PLAN_BLOCK_CODE: &str = "11158";
const PLAN_BLOCK_MSG_MARKER: &str = "not allowed for user type";
const HARD_CREDIT_BUSINESS_CODE: &str = "14018";

/// `"code"\s*:\s*"?11135"?`（JSON 空白容差）。
static IMAGE_INVALID_CODE_RE: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r#""code"\s*:\s*"?11135"?"#).expect("workbuddy image-invalid code regex")
});

/// 上游业务码 `6004` = **模型级限流**（面板 `IsModelRateLimit`）。
///
/// 与「账号级限流」的区别是**锁的粒度**：6004 明确说「是这个模型的用量受限」，
/// 账号对别的模型完全正常——所以应该只锁 (账号, 模型) 这一格，而不是把账号整体冷却
/// （面板 handler 在 6004 且能解析出重置时间时**只**写 `modelCooldowns[model]`）。
const MODEL_RATE_LIMIT_CODE: &str = "6004";

/// `"code"\s*:\s*"?6004"?`（JSON 空白与引号形态都容差）。
static MODEL_RATE_LIMIT_RE: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(&format!(r#""code"\s*:\s*"?{MODEL_RATE_LIMIT_CODE}"?"#))
        .expect("workbuddy model-rate-limit code regex")
});

/// 中文限流文案里的重置时间：`将在 <时间> 重置`（面板 `softRateResetPatternCN`）。
static RATE_RESET_CN_RE: LazyLock<Regex> =
    LazyLock::new(|| Regex::new("将在 (.+?) 重置").expect("workbuddy CN rate reset regex"));

/// 英文限流文案里的重置时间：`reset at <时间>`（面板 `softRateResetPatternEN`）。
static RATE_RESET_EN_RE: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"(?i)reset at (\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2})")
        .expect("workbuddy EN rate reset regex")
});

/// 响应体是否明确指向**模型级限流**（业务码 `6004`）。
pub fn workbuddy_body_is_model_rate_limit(body: &str) -> bool {
    MODEL_RATE_LIMIT_RE.is_match(body)
}

/// 从限流响应体里解析**权威重置墙钟**（unix 秒）。
///
/// 面板 `ParseRateReset` 的逐条对应：CN 文案「将在 YYYY-MM-DD HH:MM:SS 重置」、
/// global 英文「reset at YYYY-MM-DD HH:MM:SS」；时间**固定 UTC+8**（可能带 ` UTC+8` 后缀）。
/// 解析不出来就返回 `None`——面板此时**不按模型锁路由**（只记一条 AuditOnly 展示项）。
pub fn workbuddy_parse_rate_reset_unix_secs(body: &str) -> Option<u64> {
    let captured = RATE_RESET_CN_RE
        .captures(body)
        .or_else(|| RATE_RESET_EN_RE.captures(body))?
        .get(1)?
        .as_str()
        .trim()
        .to_string();
    let stamp = captured.strip_suffix(" UTC+8").unwrap_or(&captured).trim();
    let naive = chrono::NaiveDateTime::parse_from_str(stamp, "%Y-%m-%d %H:%M:%S").ok()?;
    // 上游文案里的时间按 UTC+8 解释（面板 `softRateResetLoc`）。
    let unix = naive.and_utc().timestamp() - 8 * 60 * 60;
    u64::try_from(unix).ok()
}

/// 分类一次上游失败。`status_code` < 400 且没有业务错误时返回 `None`。
pub fn classify_workbuddy_failure(
    status_code: u16,
    body_text: Option<&str>,
) -> WorkbuddyFailureKind {
    let body = body_text.unwrap_or_default();
    // 0. 11158 是账号套餐/用户类型权限拒绝，必须与 11102 区分：前者同模型可能在
    // 另一个 Pro 账号可用，所以由上层按 key×model 记账，不能做全局模型负缓存。
    if is_plan_blocked(status_code, body) {
        return WorkbuddyFailureKind::PlanBlocked;
    }
    // 1. 11102「该后端无此模型」最先判：语义比计费/限流都更具体，不先判会被更宽的
    //    4xx 兜底吞掉，坏号会留在池里反复被选中。
    if is_model_blocked(status_code, body) {
        return WorkbuddyFailureKind::ModelBlocked;
    }
    // 2. 402：真正的余额耗尽状态码，最严、最不可自愈，最先判。
    if status_code == 402 {
        return WorkbuddyFailureKind::HardCredit;
    }
    let lowered = body.to_ascii_lowercase();
    // 3./4. 会话失效与账号故障先于 429：账号级终态等不来自愈，限流状态码不得掩盖它们。
    if SESSION_DEAD_MARKERS
        .iter()
        .any(|marker| body.contains(marker))
    {
        return WorkbuddyFailureKind::SessionDead;
    }
    if ACCOUNT_FAULT_MARKERS
        .iter()
        .any(|marker| lowered.contains(marker))
    {
        return WorkbuddyFailureKind::AccountFault;
    }
    // 5. 14018 是明确的「账号积分耗尽」业务码，必须先于通用 429 兜底，
    //    否则会被误判成可自愈的软限流、在全池冷却时反复兜底选中。
    if status_code == 429 && has_business_code(body, HARD_CREDIT_BUSINESS_CODE) {
        return WorkbuddyFailureKind::HardCredit;
    }
    // 5.5 `6004` 是**模型级限流**：必须判在通用 429 兜底之前。它明确说的是「这个模型
    //     的用量受限」，账号对别的模型完全正常；归成 `SoftRate` 会让账号维度的惩罚
    //     （自适应 RPM、健康分、号池冷却）全部落到整号上。
    //     放在 14018 之后：积分耗尽是账号终态，比模型限流更严、更不可自愈。
    if workbuddy_body_is_model_rate_limit(body) {
        return WorkbuddyFailureKind::ModelRateLimit;
    }
    // 6. 429 先于余额文案：限流响应体高频携带 "quota exceeded" 一类跨界措辞，
    //    先判余额会把限流误归硬欠费、白扔号约 12 小时。
    if status_code == 429 {
        return WorkbuddyFailureKind::SoftRate;
    }
    if HARD_CREDIT_MARKERS
        .iter()
        .any(|marker| lowered.contains(marker))
    {
        return WorkbuddyFailureKind::HardCredit;
    }
    if SOFT_RATE_MARKERS
        .iter()
        .any(|marker| lowered.contains(marker))
    {
        return WorkbuddyFailureKind::SoftRate;
    }
    // 9. 11115：请求级语义最具体（上下文超限），须先于 404/5xx/通用 4xx 兜底。
    if matches!(status_code, 400 | 404 | 413)
        && PROMPT_TOO_LONG_MARKERS
            .iter()
            .any(|marker| body.contains(marker))
    {
        return WorkbuddyFailureKind::PromptTooLong;
    }
    if status_code == 404 {
        return WorkbuddyFailureKind::NotFound;
    }
    if status_code >= 500 {
        return WorkbuddyFailureKind::Server;
    }
    // 12. WAF 403（无业务信封）必须判在通用 4xx 兜底之前：否则落 Client 就是
    //     「只换号不罚」，连环 403 的根因。
    if is_waf_blocked(status_code, body) {
        return WorkbuddyFailureKind::WafBlock;
    }
    if status_code == 400
        && (IMAGE_INVALID_CODE_RE.is_match(body) || lowered.contains(IMAGE_INVALID_CODE))
    {
        return WorkbuddyFailureKind::ImageInvalid;
    }
    if status_code == 400
        && INVALID_IMAGE_MARKERS
            .iter()
            .any(|marker| lowered.contains(marker))
    {
        return WorkbuddyFailureKind::ImageInvalid;
    }
    if status_code >= 400 {
        if CONTENT_BLOCKED_MARKERS
            .iter()
            .any(|marker| lowered.contains(marker))
        {
            return WorkbuddyFailureKind::ContentBlocked;
        }
        if body.contains(BAD_PARAMS_MARKER_MSG) || body.contains(BAD_PARAMS_MARKER_CODE) {
            return WorkbuddyFailureKind::BadParams;
        }
        return WorkbuddyFailureKind::Client;
    }
    WorkbuddyFailureKind::None
}

/// 上游响应里是否带业务信封（`"code":` / `"msg":` 之一的 JSON 字段）。
fn has_business_envelope(body: &str) -> bool {
    body.contains(r#""code":"#) || body.contains(r#""msg":"#)
}

/// 403 且无业务信封（HTML 拦截页 / 空体 / 纯文本）= APISIX WAF 拦截形态。
fn is_waf_blocked(status_code: u16, body: &str) -> bool {
    status_code == 403 && !has_business_envelope(body)
}

/// 11158 套餐权限拒绝：响应会包含 `code=11158` 与 `not allowed for user type`。
fn is_plan_blocked(status_code: u16, body: &str) -> bool {
    if status_code != 400 || body.is_empty() {
        return false;
    }
    let lower = body.to_ascii_lowercase();
    lower.contains(PLAN_BLOCK_CODE) && lower.contains(PLAN_BLOCK_MSG_MARKER)
}

/// 11102「该后端无此模型」：只看 400/404，且只比独立字段，不做整段子串匹配
/// （错误体里的 requestId 也可能含 "11102"，整段匹配会误避让一个能用的模型）。
fn is_model_blocked(status_code: u16, body: &str) -> bool {
    if !matches!(status_code, 400 | 404) || body.is_empty() {
        return false;
    }
    if !body.contains(MODEL_BLOCK_CODE)
        && !body.to_ascii_lowercase().contains(MODEL_BLOCK_MSG_MARKER)
    {
        return false;
    }
    let Ok(root) = serde_json::from_str::<Value>(body) else {
        return false;
    };
    let mut nodes = vec![&root];
    if let Some(inner) = root.get("error") {
        nodes.push(inner);
    }
    for node in nodes {
        for key in ["code", "errCode", "error_code"] {
            if let Some(value) = node.get(key) {
                if json_scalar_equals(value, MODEL_BLOCK_CODE) {
                    return true;
                }
            }
        }
        for key in ["msg", "message"] {
            if let Some(Value::String(message)) = node.get(key) {
                if message
                    .to_ascii_lowercase()
                    .contains(MODEL_BLOCK_MSG_MARKER)
                {
                    return true;
                }
            }
        }
    }
    false
}

/// 业务信封里是否有 `code` 精确等于 `want`（顶层与嵌套 `error`/`data` 都看）。
fn has_business_code(body: &str, want: &str) -> bool {
    let Ok(mut root) = serde_json::from_str::<Value>(body) else {
        return false;
    };
    let mut stack = vec![std::mem::take(&mut root)];
    while let Some(value) = stack.pop() {
        match value {
            Value::Object(object) => {
                if let Some(code) = object.get("code") {
                    if json_scalar_equals(code, want) {
                        return true;
                    }
                }
                stack.extend(object.into_iter().map(|(_, value)| value));
            }
            Value::Array(items) => stack.extend(items),
            _ => {}
        }
    }
    false
}

fn json_scalar_equals(value: &Value, want: &str) -> bool {
    match value {
        Value::String(text) => text.trim() == want,
        Value::Number(number) => number.to_string() == want,
        _ => false,
    }
}

/// 这次失败是否应当让 **OAuth 凭证作废**（Aether 侧的效果 = 标记 key 失效并强制刷新，
/// 刷新不回来就换号）。
///
/// 入参是**原始响应体**（不是抽取后的 msg）：`12153` 这类身份藏在 JSON 的 `code`
/// 字段里，只看 msg 会漏判。
///
/// 只收两类账号级终态：
/// - 会话失效（`12153`）：access token 已死，走刷新能救回来；
/// - 账号级授权故障（`11140 request illegal` / `14017`）：需重新登录，短冷却只能
///   阻止继续送死。
///
/// 其余分类（欠费、限流、模型不可用、请求级错误）**不作废凭证**——它们是账号/模型/
/// 请求维度的状态，作废凭证会把健康号误杀。
pub fn workbuddy_oauth_invalid_reason(
    status_code: u16,
    response_text: Option<&str>,
) -> Option<String> {
    let kind = classify_workbuddy_failure(status_code, response_text);
    let message = workbuddy_readable_message(response_text);
    match kind {
        WorkbuddyFailureKind::SessionDead => Some(format!(
            "[OAUTH_EXPIRED] {}",
            if message.is_empty() {
                "WorkBuddy 会话已失效（12153）".to_string()
            } else {
                message
            }
        )),
        WorkbuddyFailureKind::AccountFault => Some(format!(
            "[OAUTH_EXPIRED] 账号级授权故障，需重新登录：{}",
            if message.is_empty() {
                "11140/14017".to_string()
            } else {
                message
            }
        )),
        _ => None,
    }
}

/// 从响应体里取一段**可读**的错误文案进后台（优先 JSON 的 `msg`/`message`），
/// 抹平换行并收敛长度——它会进后台与调度判定。
///
/// 安全边界（审计 P1-1，2026-10-16）：**响应体不是 JSON 时绝不回显原文** ✗ ——
/// 那可能是 WAF 的 HTML 拦截页，原文回显会把上游可控文本写进
/// `key.oauth_invalid_reason` 并渲染到管理界面 ✗。此时改用固定类别文案 ✓；
/// JSON 信封里的 `msg`/`message` 是上游结构化字段，仍照常透出 ✓（并钳长度 ✓）。
fn workbuddy_readable_message(response_text: Option<&str>) -> String {
    let raw = response_text.unwrap_or_default().trim();
    if raw.is_empty() {
        return String::new();
    }
    let message = serde_json::from_str::<Value>(raw)
        .ok()
        .and_then(|value| {
            ["msg", "message", "error_description"]
                .iter()
                .find_map(|key| {
                    value
                        .get(key)
                        .and_then(Value::as_str)
                        .map(str::to_string)
                        .or_else(|| {
                            value
                                .get("error")
                                .and_then(|error| error.get(key))
                                .and_then(Value::as_str)
                                .map(str::to_string)
                        })
                })
        })
        // 非 JSON（HTML 拦截页 / 纯文本）→ 固定文案，不回显原文 ✓。
        .unwrap_or_else(|| "上游返回了非 JSON 响应".to_string());
    message
        .replace(['\r', '\n'], " ")
        .trim()
        .chars()
        .take(200)
        .collect()
}

#[cfg(test)]
mod tests {
    use super::{
        classify_workbuddy_failure, workbuddy_body_is_model_rate_limit,
        workbuddy_oauth_invalid_reason, workbuddy_parse_rate_reset_unix_secs, WorkbuddyFailureKind,
    };

    fn kind(status: u16, body: &str) -> WorkbuddyFailureKind {
        classify_workbuddy_failure(status, Some(body))
    }

    /// 6004 = **模型级限流**（面板 `IsModelRateLimit`）：只认结构化 code，不是关键词包含。
    #[test]
    fn model_rate_limit_is_detected_structurally() {
        // 三种 JSON 形态都命中（面板正则容许空白与引号）。
        for body in [
            r#"{"code":6004,"msg":"该模型使用人数过多"}"#,
            r#"{"code": 6004, "msg":"x"}"#,
            r#"{"code":"6004"}"#,
        ] {
            assert!(
                workbuddy_body_is_model_rate_limit(body),
                "应识别为模型级限流：{body}"
            );
        }
        // 账号级限流（429 无 6004）**不是**模型级：否则会把整号误锁。
        assert!(!workbuddy_body_is_model_rate_limit(
            r#"{"code":429,"msg":"rate limit exceeded"}"#
        ));
        // 其它业务码不误判（11140 账号级风控、11102 模型不可用）。
        assert!(!workbuddy_body_is_model_rate_limit(r#"{"code":11140}"#));
        assert!(!workbuddy_body_is_model_rate_limit(r#"{"code":11102}"#));
        assert!(!workbuddy_body_is_model_rate_limit(""));
    }

    /// `6004` 必须归成**模型级**限流，不能被通用 429 兜底吞成账号级软限流。
    ///
    /// 这条钉住的是「惩罚维度」：分类一旦落到 `SoftRate`，自适应 RPM / 健康分 / 号池冷却
    /// 会全部按账号维度记账——一个模型的限额就把整号打停。
    #[test]
    fn model_rate_limit_classifies_before_generic_429() {
        assert_eq!(
            kind(
                429,
                r#"{"code":6004,"msg":"当前模型使用人数过多，将在 2026-10-15 20:00:00 重置"}"#
            ),
            WorkbuddyFailureKind::ModelRateLimit
        );
        // 积分耗尽（14018）更严、更不可自愈，仍须先判。
        assert_eq!(
            kind(429, r#"{"code":14018,"msg":"积分不足"}"#),
            WorkbuddyFailureKind::HardCredit
        );
        // 没有业务码的 429 仍是账号级软限流（无法证明是模型级，不能放过）。
        assert_eq!(
            kind(429, "too many requests"),
            WorkbuddyFailureKind::SoftRate
        );
    }

    /// 重置墙钟解析：CN / EN 两种文案、UTC+8 语义、` UTC+8` 后缀，以及解析不出来的情况。
    #[test]
    fn rate_reset_is_parsed_as_utc8_wall_clock() {
        // CN 文案（真机形态）：将在 2026-10-15 20:00:00 重置 → UTC+8 20:00 = 12:00 UTC。
        let cn = r#"{"code":6004,"msg":"当前模型使用人数过多，将在 2026-10-15 20:00:00 重置"}"#;
        assert_eq!(
            workbuddy_parse_rate_reset_unix_secs(cn),
            Some(1_792_065_600),
            "2026-10-15 20:00:00 UTC+8 的 unix 秒"
        );
        // 英文文案（global）：reset at <时间>，大小写不敏感。
        let en =
            r#"{"code":6004,"msg":"Rate limit reached, will reset at 2026-10-15 20:00:00 UTC+8"}"#;
        assert_eq!(
            workbuddy_parse_rate_reset_unix_secs(en),
            Some(1_792_065_600)
        );
        // 前缀带 ` UTC+8` 后缀也走同一时间轴。
        let suffix = r#"{"msg":"will Reset At 2026-10-15 20:00:00 UTC+8"}"#;
        assert_eq!(
            workbuddy_parse_rate_reset_unix_secs(suffix),
            Some(1_792_065_600)
        );
        // 解析不出来（面板此时只记 AuditOnly 展示项，**不按模型锁路由**）。
        assert_eq!(
            workbuddy_parse_rate_reset_unix_secs(r#"{"code":6004,"msg":"稍后再试"}"#),
            None
        );
        assert_eq!(
            workbuddy_parse_rate_reset_unix_secs(
                r#"{"code":6004,"msg":"reset at the end of the day"}"#
            ),
            None,
            "「end of the day」这类没有固定格式时间的文案不猜"
        );
        assert_eq!(workbuddy_parse_rate_reset_unix_secs(""), None);
        // 非时间字符串不 panic、不误解析。
        assert_eq!(
            workbuddy_parse_rate_reset_unix_secs(r#"{"code":6004,"msg":"将在 稍后 重置"}"#),
            None
        );
    }

    #[test]
    fn success_and_missing_body_classify_as_none() {
        assert_eq!(
            kind(200, r#"{"code":0,"msg":"ok"}"#),
            WorkbuddyFailureKind::None
        );
        assert_eq!(
            classify_workbuddy_failure(200, None),
            WorkbuddyFailureKind::None
        );
    }

    #[test]
    fn account_level_terminals_win_over_rate_limit_markers() {
        // 401 + 12153 混排 "rate limit" 文案也必须判会话失效。
        assert_eq!(
            kind(
                401,
                r#"{"code":12153,"msg":"Offline user session not found, rate limit"}"#
            ),
            WorkbuddyFailureKind::SessionDead
        );
        // 429 + 14017 必须判账号故障，不是限流。
        assert_eq!(
            kind(
                429,
                r#"{"code":14017,"msg":"The trial version is not yet activated"}"#
            ),
            WorkbuddyFailureKind::AccountFault
        );
        // 11140 的模型级限流文案不能被当成账号故障（panel 明确要求）。
        assert_eq!(
            kind(
                429,
                r#"{"code":11140,"msg":"The model provider is rate-limiting requests."}"#
            ),
            WorkbuddyFailureKind::SoftRate
        );
    }

    #[test]
    fn plan_block_is_detected_as_per_account_entitlement() {
        assert_eq!(
            kind(
                400,
                r#"{"code":11158,"msg":"model [gpt-5.5] is not allowed for user type [personal_free_user]"}"#
            ),
            WorkbuddyFailureKind::PlanBlocked
        );
        assert_eq!(
            kind(
                400,
                r#"{"code":11158,"msg":"model [gpt-5.5] is not allowed for user type [personal_free_user]","requestId":"req-11158"}"#
            ),
            WorkbuddyFailureKind::PlanBlocked
        );
        assert_ne!(
            kind(400, r#"{"code":11158,"msg":"bad request"}"#),
            WorkbuddyFailureKind::PlanBlocked
        );
    }

    #[test]
    fn model_block_is_detected_structurally_not_by_substring() {
        assert_eq!(
            kind(400, r#"{"code":11102,"msg":"service info not found"}"#),
            WorkbuddyFailureKind::ModelBlocked
        );
        assert_eq!(
            kind(404, r#"{"error":{"error_code":"11102"}}"#),
            WorkbuddyFailureKind::ModelBlocked
        );
        // requestId 里带 11102 不算（否则会误避让一个能用的模型）。
        assert_eq!(
            kind(400, r#"{"code":10000,"requestId":"req-11102-abc"}"#),
            WorkbuddyFailureKind::Client
        );
        // 429 带 11102 属限流语义。
        assert_eq!(
            kind(429, r#"{"code":11102,"msg":"service info not found"}"#),
            WorkbuddyFailureKind::SoftRate
        );
    }

    #[test]
    fn balance_and_rate_limit_are_split_by_status_and_code() {
        // 402 最严：先于任何文案。
        assert_eq!(
            kind(402, r#"{"msg":"rate limit"}"#),
            WorkbuddyFailureKind::HardCredit
        );
        // 429 + 14018（积分耗尽）＝硬欠费，而不是软限流。
        assert_eq!(
            kind(429, r#"{"code":14018,"msg":"credits exhausted"}"#),
            WorkbuddyFailureKind::HardCredit
        );
        // 429 携带跨界文案仍是软限流（状态码比关键词权威）。
        assert_eq!(
            kind(429, r#"{"msg":"quota exceeded"}"#),
            WorkbuddyFailureKind::SoftRate
        );
        // 非 429 的余额文案才走硬欠费。
        assert_eq!(
            kind(400, r#"{"msg":"Insufficient credit"}"#),
            WorkbuddyFailureKind::HardCredit
        );
        // HTTP 200 但业务 code 非 0 且含余额关键词：面板同样按硬欠费捕获
        // （Classify 里 hardMarkers 在状态码兜底之前）。
        assert_eq!(
            kind(200, r#"{"msg":"余额不足"}"#),
            WorkbuddyFailureKind::HardCredit
        );
    }

    #[test]
    fn request_level_errors_stay_request_level() {
        assert_eq!(
            kind(400, r#"{"code":11115,"msg":"prompt is too long"}"#),
            WorkbuddyFailureKind::PromptTooLong
        );
        assert_eq!(
            kind(400, r#"{"msg":"Unmarshal chat params failed: xxx"}"#),
            WorkbuddyFailureKind::BadParams
        );
        assert_eq!(
            kind(400, r#"{"code":11101,"msg":"bad request"}"#),
            WorkbuddyFailureKind::BadParams
        );
        assert_eq!(
            kind(400, r#"{"code": 11135,"msg":"invalid image"}"#),
            WorkbuddyFailureKind::ImageInvalid
        );
        assert_eq!(
            kind(
                400,
                r#"{"msg":"Parse message failed: invalid image_url content"}"#
            ),
            WorkbuddyFailureKind::ImageInvalid
        );
    }

    #[test]
    fn waf_block_needs_403_without_a_business_envelope() {
        assert_eq!(kind(403, ""), WorkbuddyFailureKind::WafBlock);
        assert_eq!(
            kind(403, "<html><title>403 Forbidden</title></html>"),
            WorkbuddyFailureKind::WafBlock
        );
        // 带信封的 403 走既有分类链（这里是内容拦截）。
        assert_eq!(
            kind(403, r#"{"code":11-128,"msg":"blocked by security policy"}"#),
            WorkbuddyFailureKind::ContentBlocked
        );
    }

    #[test]
    fn content_blocked_and_client_are_the_tail_of_the_chain() {
        assert_eq!(
            kind(400, r#"{"code":11-128,"msg":"blocked by security policy"}"#),
            WorkbuddyFailureKind::ContentBlocked
        );
        assert_eq!(
            kind(400, "Illegal API invocation from an unapproved channel"),
            WorkbuddyFailureKind::ContentBlocked
        );
        assert_eq!(
            kind(400, r#"{"msg":"unknown business error"}"#),
            WorkbuddyFailureKind::Client
        );
        assert_eq!(kind(404, ""), WorkbuddyFailureKind::NotFound);
        assert_eq!(kind(503, "upstream down"), WorkbuddyFailureKind::Server);
    }

    #[test]
    fn only_account_level_terminals_invalidate_the_credential() {
        // 会话失效与账号故障 → 作废凭证（触发强制刷新）。
        assert!(
            workbuddy_oauth_invalid_reason(401, Some(r#"{"code":12153}"#))
                .expect("session dead should invalidate")
                .starts_with("[OAUTH_EXPIRED]")
        );
        assert!(workbuddy_oauth_invalid_reason(
            400,
            Some(r#"{"code":11140,"msg":"request illegal"}"#)
        )
        .expect("account fault should invalidate")
        .contains("需重新登录"));
        // 审计 P1-1：**非 JSON 响应体（WAF HTML 拦截页）绝不回显原文** ✗ ——
        // 否则上游可控文本会落库 `oauth_invalid_reason` 并渲染到管理界面。
        // 场景：WAF 拦截页里**恰好带了**触发会话失效判定的标记（上游可控 ✓）。
        let html_reason = workbuddy_oauth_invalid_reason(
            403,
            Some(
                r#"<html><body>error 12153 Offline user session not found, account=13800138000</body></html>"#,
            ),
        )
        .expect("session dead should invalidate");
        assert!(html_reason.contains("非 JSON 响应"), "{html_reason}");
        assert!(!html_reason.contains("13800138000"), "{html_reason}");
        // JSON 信封的结构化 `msg` 仍照常透出（既有行为 ✓）。
        assert!(workbuddy_oauth_invalid_reason(
            400,
            Some(r#"{"code":11140,"msg":"request illegal"}"#)
        )
        .expect("json msg passes through")
        .contains("request illegal"));
        // 其它分类都不许动凭证——否则会把健康号误杀。
        for (status, body) in [
            (402u16, r#"{"msg":"Insufficient credit"}"#),
            (429, r#"{"msg":"rate limit"}"#),
            (400, r#"{"code":11102,"msg":"service info not found"}"#),
            (400, r#"{"code":11115,"msg":"prompt is too long"}"#),
            (400, r#"{"msg":"blocked by security policy"}"#),
            (403, ""),
        ] {
            assert!(
                workbuddy_oauth_invalid_reason(status, Some(body)).is_none(),
                "{status} {body} 不该作废凭证"
            );
        }
    }

    /// 失败原因会进后台与调度判定：换行必须被抹平、长度必须收敛。
    #[test]
    fn invalid_reason_is_sanitized_for_the_admin_surface() {
        let reason = workbuddy_oauth_invalid_reason(
            401,
            Some(&format!(
                "Offline user session not found\n{}",
                "x".repeat(500)
            )),
        )
        .expect("reason");
        assert!(!reason.contains('\n'));
        assert!(reason.len() <= 220, "reason too long: {}", reason.len());
    }
}
