//! WorkBuddy（腾讯 CodeBuddy）供应商传输层。
//!
//! 上游是腾讯 CodeBuddy / WorkBuddy 的私有对话入口，**协议形态是 OpenAI Chat
//! Completions 的一个子集**，但带一层官方桌面端指纹头族：网关必须把
//! `Origin` / `Referer` / `User-Agent` / `X-CodeBuddy-Request` / `X-User-Id` /
//! `X-Domain` 等头按账号补齐，否则会被上游按「非官方客户端」拦掉
//! （`403 code 11140 request illegal` 一类）。
//!
//! 本模块只负责**身份与出站头**，不负责 OAuth（见 `aether-oauth` 的
//! `providers::workbuddy`）：账号凭证由 provider-oauth 流程写进 key 的
//! `auth_config`，这里从快照里把它读回来，派生本 provider 需要的头。
//!
//! 事实来源：开源面板 `linguo2625469/workbuddy2api-panel`
//! （`internal/upstream/headers.go`、`internal/panel/login.go`、
//! `internal/auth/auth.go`）。

use std::collections::BTreeMap;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::LazyLock;

use regex::Regex;
use serde_json::{json, Value};
use sha2::{Digest, Sha256};

use crate::snapshot::GatewayProviderTransportSnapshot;

/// `aether-oauth` 侧的 domain 枚举：三段式 UA 的平台段 / 版本段与
/// `workbuddy_user_agent` 的**权威定义**都在那边（本 crate 只委托）。
use aether_oauth::provider::providers::WorkbuddyOAuthRealm as OAuthWorkbuddyRealm;

pub mod desktop;
pub mod failure;
pub mod global_register;
pub mod refresh;

// 国际版注册链路的纯函数在子模块里；这里再导出一次，方便调用方按 `workbuddy::` 根路径引用
// （与 `classify_workbuddy_trial_outcome` 等直接住在 mod.rs 的符号风格保持一致）。
pub use global_register::{
    build_workbuddy_global_country_code_body, build_workbuddy_global_submit_region_body,
    classify_workbuddy_global_register_status, filter_workbuddy_global_intl_countries,
    parse_workbuddy_global_countries, WorkbuddyGlobalCountry, WorkbuddyGlobalRegisterStatus,
    WORKBUDDY_GLOBAL_COUNTRY_CODE_PATH, WORKBUDDY_GLOBAL_INTL_COUNTRY_WHITELIST,
    WORKBUDDY_GLOBAL_REGISTER_PATH, WORKBUDDY_GLOBAL_SUBMIT_REGION_PATH,
};

/// 内部标记头的定义归格式 crate 的响应兼容模块所有（流改写矩阵归它管），
/// 这里只重导出，保证请求侧注入与响应侧识别用的是同一个常量。
pub use aether_ai_formats::provider_compat::workbuddy_dsml::WORKBUDDY_INTERNAL_HEADER;

/// Aether 内部的 provider_type 标识 + 对话域 + 设备授权端点路径 + UA 版本段。
///
/// 维护性审计 ⑤（2026-10-17 ✗）：这些值此前在本文件与 `aether-oauth` 的
/// `providers::workbuddy` 里**各写一份** ✗（本文件旧注释甚至写着「改上游路径时两处都要改」✗）。
/// 依赖方向本来就是 `transport → oauth` ✓，所以**权威定义放在下层 aether-oauth** ✓，
/// 这里只重导出（名字保持本 crate 既有公开名 ✓，下游零改动 ✓）。
///
/// **CN 对话域已切到 `www.workbuddy.cn`**（报告 §10.1/§10.3.1，5.8.x 把 chat/report/
/// account/config/traces 收敛到同一个域）；`WORKBUDDY_CHAT_BASE_URL_CN` 因此等于
/// `WORKBUDDY_WEB_BASE_URL_CN`。
///
/// 版本段（`5.5.4` / `2.137.1` / 国际 `5.8.4` / `2.161.0`）同样归 `aether-oauth` 所有：
/// UA 由那边的 `workbuddy_user_agent_for(realm, 端点类型, 调用形态)` 统一构造，
/// 刷新路径（oauth）与对话路径（本 crate）共用同一个出口 —— 两边各留一份字面量
/// 曾导致国际号 refresh 的 UA 与 chat 漂移 ✗。
pub use aether_oauth::provider::providers::{
    WORKBUDDY_AUTH_STATE_PATH, WORKBUDDY_AUTH_TOKEN_PATH,
    WORKBUDDY_CHAT_BASE_CN as WORKBUDDY_CHAT_BASE_URL_CN,
    WORKBUDDY_CHAT_BASE_GLOBAL as WORKBUDDY_CHAT_BASE_URL_GLOBAL,
    WORKBUDDY_CLIENT_VERSION as WORKBUDDY_DEFAULT_CLIENT_VERSION,
    WORKBUDDY_CLI_VERSION as WORKBUDDY_DEFAULT_CLI_VERSION, WORKBUDDY_GLOBAL_CLIENT_VERSION,
    WORKBUDDY_GLOBAL_CLI_VERSION, WORKBUDDY_LOGIN_ACCOUNT_PATH, WORKBUDDY_LOGIN_USER_AGENT,
    WORKBUDDY_ORIGIN_CN, WORKBUDDY_ORIGIN_GLOBAL, WORKBUDDY_PROVIDER_TYPE, WORKBUDDY_REFRESH_PATH,
};

/// 对话路径：CN 与国际共用同一条（国际版的 `/console/chat/completions`
/// 已被上游 WAF 按请求体内容规则拦掉，面板也因此固定用 `/v2`）。
pub const WORKBUDDY_CHAT_PATH: &str = "/v2/chat/completions";

/// CN 模型目录探测路径（`/v3/config`）。
pub const WORKBUDDY_MODELS_CONFIG_PATH: &str = "/v3/config";
/// CN 计费域（签到 / 余额 / 活跃上报）。
pub const WORKBUDDY_BILLING_BASE_URL_CN: &str = "https://www.codebuddy.cn";
/// 国际计费域（与 CN 不同域！面板 `globalBillingBase` 默认值）。
pub const WORKBUDDY_BILLING_BASE_URL_GLOBAL: &str = "https://www.workbuddy.ai";
/// CN web 域（成长任务领奖）。
pub const WORKBUDDY_WEB_BASE_URL_CN: &str = "https://www.workbuddy.cn";
/// Web 控制台账号资料路径（面板 `internal/upstream/profile.go`，issue #94：
/// 改名后**免重登**同步昵称）。
///
/// ⚠️ 该接口响应含手机号等敏感信息：调用方**只许解析 `nickname` 与 `uid`**，
/// 其余字段不解析、不落日志、不透传（面板同款隐私边界）。
pub const WORKBUDDY_ACCOUNT_PROFILE_PATH: &str = "/console/account";

/// 计费域 base（签到 / 余额 / 活跃上报都用它）。
///
/// **不能拿端点的 `base_url` 代替**：端点的 base 是**对话域**（CN 现在也是
/// `www.workbuddy.cn`，但语义不同：计费/上报是另一条链路），而计费/上报走的是
/// 另一个域（CN `www.codebuddy.cn`、国际 `www.workbuddy.ai`，面板 `billingBase()`）。
/// 混用会让请求打到错误的域上。
pub const fn workbuddy_billing_base_url(realm: WorkbuddyRealm) -> &'static str {
    match realm {
        WorkbuddyRealm::Global => WORKBUDDY_BILLING_BASE_URL_GLOBAL,
        WorkbuddyRealm::Cn => WORKBUDDY_BILLING_BASE_URL_CN,
    }
}

/// `/v3/config` 模型目录探测要求的 UA（必须能解析出 CodeBuddy 版本号）。
pub const WORKBUDDY_IDE_USER_AGENT: &str = "CodeBuddyIDE/4.12.0 CodeBuddy/4.12.0";

/// 账号稳定标识的派生盐（与面板 `deriveAccountStableID` 完全一致）。
const WORKBUDDY_ACCOUNT_ID_SALT: &str = "wb2a:";

/// 个人资源包/余额查询路径（CN 现状）。
pub const WORKBUDDY_USER_RESOURCE_PATH: &str = "/v2/billing/meter/get-user-resource";
/// 个人资源包/余额查询路径（国际域首选，无 `/v2` 前缀）。
pub const WORKBUDDY_USER_RESOURCE_PATH_GLOBAL: &str = "/billing/meter/get-user-resource";
/// 企业额度查询路径（面板不对它做路径回退）。
pub const WORKBUDDY_ENTERPRISE_USAGE_PATH: &str = "/v2/billing/meter/get-enterprise-user-usage";
/// 每日签到路径（CN）。
pub const WORKBUDDY_DAILY_CHECKIN_PATH: &str = "/v2/billing/meter/daily-checkin";
/// 每日签到路径（国际域首选，无 `/v2` 前缀）。
pub const WORKBUDDY_DAILY_CHECKIN_PATH_GLOBAL: &str = "/billing/meter/daily-checkin";
/// 活跃上报路径（`chat_request_send` 事件，计费域）。
pub const WORKBUDDY_REPORT_PATH: &str = "/v2/report";
/// 成长中心：连登完整状态（**对话域** + 计费头族，面板 `growthJSON` 走 `chatBase`）。
pub const WORKBUDDY_GROWTH_STREAK_PATH: &str = "/activity/growth/streak";
/// 成长中心：兑换连登档位（body `{"tier":"7d","client_token":"…"}`）。
pub const WORKBUDDY_GROWTH_REDEEM_PATH: &str = "/activity/growth/redeem";
/// 成长中心：抽奖次数。
pub const WORKBUDDY_GROWTH_LOTTERY_SUMMARY_PATH: &str = "/activity/growth/lottery/summary";
/// 成长中心：抽奖一次（body `{"client_token":"…"}`）。
pub const WORKBUDDY_GROWTH_LOTTERY_DRAW_PATH: &str = "/activity/growth/lottery/draw";
/// 成长中心：签到热力图（判断昨日是否漏签）。
pub const WORKBUDDY_GROWTH_HEATMAP_PATH: &str = "/activity/growth/heatmap";

/// 成长任务：列表（`GET`，chat 域 + 计费头族）。
pub const WORKBUDDY_TASKS_LIST_PATH: &str = "/v2/activity/growth/tasks";
/// 成长任务：批量报名（`POST {"task_codes":[…]}`）。
pub const WORKBUDDY_TASKS_ACCEPT_PATH: &str = "/v2/activity/growth/tasks/accept";
/// 成长任务：**官网域**领奖路径前缀（`{前缀}{task_code}/claim`，task_code 在**路径**里）。
///
/// 面板踩过的坑：CLI 域的 `/v2/activity/growth/tasks/reward/claim`（task_code 放 body）
/// **这条路径不存在**，一直 400「task not completed」；正确端点是官网域
/// `POST https://www.workbuddy.cn/activity/growth/tasks/<task_code>/claim`（无 body）。
pub const WORKBUDDY_TASKS_CLAIM_PATH_PREFIX: &str = "/activity/growth/tasks/";
/// 成长任务：**对话域**的小程序口径领奖路径前缀（`{前缀}{task_code}/claim` + mp 头）。
pub const WORKBUDDY_TASKS_CLAIM_MP_PATH_PREFIX: &str = "/activity/growth/tasks/";
/// 小程序口径标记头名（小程序限定任务的列表/报名/领奖全链路都要求它）。
pub const WORKBUDDY_CLIENT_PLATFORM_HEADER: &str = "x-client-platform";
/// 小程序口径头值。
pub const WORKBUDDY_CLIENT_PLATFORM_MINIPROGRAM: &str = "miniprogram";
/// 官网（Web 成长中心）口径头值。
pub const WORKBUDDY_CLIENT_PLATFORM_WEB: &str = "web";

/// 单个成长任务的**对外视图**（只保留驱动决策需要的字段）。
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct WorkbuddyTask {
    pub task_code: String,
    /// 任务名（如「和 AI 聊天 5 次」）。
    pub title: String,
    /// 操作指引（含跳转说明，上游 description）。
    pub description: String,
    /// 达成条件简述（上游 task_desc）。
    pub task_desc: String,
    /// 奖励积分（上游 reward_credit）。
    pub credit: i64,
    /// 奖励能量（上游 reward_energy）。
    pub energy: i64,
    /// 是否带奖励（上游 has_reward）。
    pub has_reward: bool,
    /// 是否奖励 Buddy 相关（上游 reward_buddy；任务表里的「+5 能 Buddy」）。
    pub reward_buddy: bool,
    /// 客户端跳转协议（上游 jump_url，如 workbuddy://…）。
    pub jump_url: String,
    /// 上游任务类型：`single` = **一次性任务**（完成即终态，模拟事件**绝不重发**的依据之一）。
    pub task_type: String,
    /// 端标记（PC / 小程序限定等）。
    pub tag: String,
    pub accept_status: String,
    pub status: String,
    pub current: i64,
    pub target: i64,
    pub locked: bool,
    /// 进度达标且未领取（**本地推算**：`target > 0 && current >= target && !claimed`）。
    pub claimable: bool,
    /// `accept_status == "claimed"`。
    pub claimed: bool,
}

impl WorkbuddyTask {
    /// 是否需要报名（面板 `acceptPendingTasks` 的过滤条件）。
    pub fn needs_accept(&self) -> bool {
        !self.claimed
            && !self.locked
            && !matches!(self.accept_status.as_str(), "accepted" | "completed")
    }
}

/// 解析任务列表（面板 `parseGrowthTasks` 的宽松口径）。
///
/// `progress` 可能是 `{current,target}` 对象、也可能是平铺的 `current`/`target` 字段——
/// 两种都试；对象形态只在「target 或 current 为正」时覆盖平铺值（面板同款防御）。
pub fn parse_workbuddy_tasks(body: &Value) -> Vec<WorkbuddyTask> {
    let Some(tasks) = body.get("tasks").and_then(Value::as_array) else {
        return Vec::new();
    };
    tasks
        .iter()
        .filter_map(|task| {
            let task = task.as_object()?;
            let mut current = workbuddy_map_i64(task, "current");
            let mut target = workbuddy_map_i64(task, "target");
            if let Some(progress) = task.get("progress").and_then(Value::as_object) {
                let progress_current = workbuddy_map_i64(progress, "current");
                let progress_target = workbuddy_map_i64(progress, "target");
                if progress_target > 0 || progress_current > 0 {
                    current = progress_current;
                    target = progress_target;
                }
            }
            let accept_status = task
                .get("accept_status")
                .and_then(Value::as_str)
                .unwrap_or_default()
                .trim()
                .to_string();
            let claimed = accept_status == "claimed";
            Some(WorkbuddyTask {
                task_code: workbuddy_map_str(task, "task_code"),
                title: workbuddy_map_str(task, "title"),
                description: workbuddy_map_str(task, "description"),
                task_desc: workbuddy_map_str(task, "task_desc"),
                credit: workbuddy_map_i64(task, "reward_credit"),
                energy: workbuddy_map_i64(task, "reward_energy"),
                has_reward: task
                    .get("has_reward")
                    .and_then(Value::as_bool)
                    .unwrap_or(false),
                reward_buddy: task
                    .get("reward_buddy")
                    .and_then(Value::as_bool)
                    .unwrap_or(false),
                jump_url: workbuddy_map_str(task, "jump_url"),
                task_type: workbuddy_map_str(task, "task_type"),
                tag: workbuddy_map_str(task, "tag"),
                status: task
                    .get("status")
                    .and_then(Value::as_str)
                    .unwrap_or_default()
                    .trim()
                    .to_string(),
                locked: task.get("locked").and_then(Value::as_bool).unwrap_or(false),
                claimable: !claimed && target > 0 && current >= target,
                current,
                target,
                claimed,
                accept_status,
            })
        })
        .filter(|task| !task.task_code.is_empty())
        .collect()
}

/// 解析领奖响应（面板 `parseClaimReward`）：`(credit, energy, already_claimed)`。
pub fn parse_workbuddy_claim_reward(body: &Value) -> (i64, i64, bool) {
    (
        workbuddy_json_i64(body, "credit"),
        workbuddy_json_i64(body, "energy"),
        body.get("already_claimed")
            .and_then(Value::as_bool)
            .unwrap_or(false),
    )
}

/// 成长中心：对指定日期使用补签卡（body `{"target_date":"YYYY-MM-DD"}`）。
pub const WORKBUDDY_GROWTH_MAKEUP_USE_PATH: &str = "/activity/growth/makeup-cards/use";
/// 计费域：新手礼包（**无 `/v2` 前缀**，与 get-user-resource 那族不同，面板如此）。
pub const WORKBUDDY_CLAIM_GIFT_PATH: &str = "/billing/meter/claim-gift";
/// 计费域：活动补偿（同样无 `/v2` 前缀）。
pub const WORKBUDDY_CLAIM_COMPENSATION_PATH: &str = "/billing/meter/claim-compensation";
/// 计费域：**global 专属**的一次性 trial 加油包（CN 无此端点）。
pub const WORKBUDDY_TRIAL_PATH: &str = "/billing/ide/trial";
/// trial 的幂等码：`14051` = 已领取过（**视为正常，不是错误**）。
pub const WORKBUDDY_TRIAL_ALREADY_CLAIMED_CODE: i64 = 14051;

/// trial 领取结果。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum WorkbuddyTrialOutcome {
    /// 本次新领成功。
    Claimed,
    /// 已经领过（幂等码 14051）——正常，不算失败。
    AlreadyClaimed,
    /// 其它失败（调用方按状态码/正文自行分类）。
    Failed,
}

/// 判定 trial 响应是不是「已经领过」（面板 `trialAlreadyErr`）。
///
/// 面板按错误文案匹配两种指纹（`code=14051` 是 HTTP 200 + 业务码非 0 时拼出的形态，
/// `"code":14051` 是 HTTP ≥400 时直接塞原始 body 的形态）。Aether 手上是**原始正文**，
/// 所以更稳：先按 JSON 读 `code == 14051`，再退回两种文案匹配（容忍 JSON 空白）。
pub fn classify_workbuddy_trial_outcome(
    status_code: u16,
    body_text: Option<&str>,
) -> WorkbuddyTrialOutcome {
    if (200..300).contains(&status_code) {
        return WorkbuddyTrialOutcome::Claimed;
    }
    let Some(body) = body_text else {
        return WorkbuddyTrialOutcome::Failed;
    };
    if serde_json::from_str::<Value>(body)
        .ok()
        .and_then(|value| value.get("code").and_then(Value::as_i64))
        == Some(WORKBUDDY_TRIAL_ALREADY_CLAIMED_CODE)
    {
        return WorkbuddyTrialOutcome::AlreadyClaimed;
    }
    let compact: String = body.chars().filter(|c| !c.is_whitespace()).collect();
    if body.contains("code=14051") || compact.contains("\"code\":14051") {
        return WorkbuddyTrialOutcome::AlreadyClaimed;
    }
    WorkbuddyTrialOutcome::Failed
}
/// 成长中心：猫猫档案（`buddy` 为 null = 无猫）。
pub const WORKBUDDY_BUDDY_INFO_PATH: &str = "/activity/growth/buddy/info";
/// 成长中心：猫猫旅行状态。
pub const WORKBUDDY_TRAVEL_STATUS_PATH: &str = "/activity/growth/buddy/travel/status";
/// 成长中心：派出旅行（body `{"location_id":4}`）。
pub const WORKBUDDY_TRAVEL_DEPART_PATH: &str = "/activity/growth/buddy/travel/depart";
/// 成长中心：到站领奖（body `{"record_id":N}`）。
pub const WORKBUDDY_TRAVEL_CLAIM_PATH: &str = "/activity/growth/buddy/travel/claim";
/// 成长中心：同意领养协议（body `{"agree":true}`，幂等）。
pub const WORKBUDDY_BUDDY_AGREEMENT_PATH: &str = "/activity/growth/buddy/agreement";
/// 成长中心：领养第一只猫（body `{}`）。
pub const WORKBUDDY_BUDDY_FIRST_PATH: &str = "/activity/growth/buddy/first";
/// 派出地点固定 4（古镇客栈）：四个地点收益/时长区间完全相同，没有最优解。
pub const WORKBUDDY_TRAVEL_LOCATION_ID: i64 = 4;
/// 领养门槛未达标的业务文案（HTTP 400）——属预期，不当失败。
pub const WORKBUDDY_BUDDY_TASK_INCOMPLETE_MARKER: &str = "first_buddy task not completed yet";

/// 猫猫旅行状态（`GET /activity/growth/buddy/travel/status` 的投影）。
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct WorkbuddyTravelState {
    pub state: String,
    pub daily_limit_reached: bool,
    pub record_id: i64,
    pub reward_credit: i64,
}

/// 本轮该对这个账号做什么（面板 `travelOne` 的决策）。
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum WorkbuddyTravelAction {
    /// 没有猫 → 走领养链路（先上报解锁 `first_buddy`，再 agreement → first）。
    Adopt,
    /// 到站 → 领奖（必须带 `record_id`）。
    Claim { record_id: i64 },
    /// 空闲且今日未派出 → 派出。
    Depart,
    /// 本轮不动（在途 / 今日已达上限 / 状态缺失或未知）。
    Skip { reason: &'static str },
}

/// 决策：无猫 → 领养；到站 → 领奖；空闲且未达当日上限 → 派出；其余跳过。
///
/// 逐条对齐面板 `travelOne` / `travelDepart`，包括两处「宁可不做」的判断：
/// 到站但 `record_id == 0` 不领（领奖必须带记录 id）、今日已派出不重复派。
pub fn decide_workbuddy_travel_action(
    has_buddy: bool,
    state: Option<&WorkbuddyTravelState>,
) -> WorkbuddyTravelAction {
    if !has_buddy {
        return WorkbuddyTravelAction::Adopt;
    }
    let Some(state) = state else {
        return WorkbuddyTravelAction::Skip { reason: "no_state" };
    };
    match state.state.trim().to_ascii_lowercase().as_str() {
        "arrived" => {
            if state.record_id == 0 {
                WorkbuddyTravelAction::Skip {
                    reason: "arrived_without_record",
                }
            } else {
                WorkbuddyTravelAction::Claim {
                    record_id: state.record_id,
                }
            }
        }
        "idle" => {
            if state.daily_limit_reached {
                WorkbuddyTravelAction::Skip {
                    reason: "daily_limit",
                }
            } else {
                WorkbuddyTravelAction::Depart
            }
        }
        "traveling" => WorkbuddyTravelAction::Skip {
            reason: "traveling",
        },
        _ => WorkbuddyTravelAction::Skip {
            reason: "unknown_state",
        },
    }
}

/// `buddy` 为 null / 缺字段 / 非对象都算「无猫」（面板 `BuddyInfo` 同口径）。
pub fn parse_workbuddy_has_buddy(body: &Value) -> bool {
    match body.get("buddy") {
        Some(Value::Object(object)) => !object.is_empty(),
        _ => false,
    }
}

/// 解析旅行状态：响应必须是对象（否则返回 `None`，调用方按「状态缺失」跳过）。
pub fn parse_workbuddy_travel_state(body: &Value) -> Option<WorkbuddyTravelState> {
    let object = body.as_object()?;
    Some(WorkbuddyTravelState {
        state: object
            .get("state")
            .and_then(Value::as_str)
            .unwrap_or_default()
            .trim()
            .to_string(),
        daily_limit_reached: object
            .get("daily_limit_reached")
            .and_then(Value::as_bool)
            .unwrap_or(false),
        record_id: workbuddy_json_i64(body, "record_id"),
        reward_credit: workbuddy_json_i64(body, "reward_credit"),
    })
}

/// 领养被上游以「`first_buddy` 任务未完成」拒绝（HTTP 400）——预期行为，当天不再重试。
pub fn is_workbuddy_buddy_task_incomplete(status_code: u16, body_text: Option<&str>) -> bool {
    status_code == 400
        && body_text
            .unwrap_or_default()
            .to_ascii_lowercase()
            .contains(WORKBUDDY_BUDDY_TASK_INCOMPLETE_MARKER)
}

/// CST（UTC+8）自然日的 `YYYY-MM-DD`。
///
/// 上游每日重置按 CST 00:00，**不能用宿主机本地时区**（容器时区不确定）——
/// 补签/漏签判断差一天就会去补错的日子。
pub fn workbuddy_cst_date(unix_secs: u64) -> String {
    let offset = chrono::FixedOffset::east_opt(8 * 60 * 60).expect("CST offset");
    let time = chrono::DateTime::from_timestamp(unix_secs as i64, 0)
        .unwrap_or_else(|| chrono::DateTime::from_timestamp(0, 0).expect("epoch"))
        .with_timezone(&offset);
    time.format("%Y-%m-%d").to_string()
}

/// CST 视角的「昨天」。
pub fn workbuddy_cst_yesterday(unix_secs: u64) -> String {
    workbuddy_cst_date(unix_secs.saturating_sub(24 * 60 * 60))
}

/// 热力图里「昨天」是否漏签（`score == 0`）。
///
/// 面板口径：找不到昨天那一格 → **不算漏签**（宁可少补一次，也不去补一个上游没记录的日子）。
pub fn parse_workbuddy_heatmap_yesterday_missed(body: &Value, yesterday: &str) -> bool {
    body.get("cells")
        .and_then(Value::as_array)
        .is_some_and(|cells| {
            cells.iter().any(|cell| {
                cell.get("date")
                    .and_then(Value::as_str)
                    .map(|date| date.trim())
                    .filter(|date| date.len() >= 10)
                    .is_some_and(|date| &date[..10] == yesterday)
                    && workbuddy_json_i64(cell, "score") == 0
            })
        })
}

/// 礼包/补偿响应里的积分（缺字段按 0，不猜）。
pub fn parse_workbuddy_claim_credit(body: &Value) -> i64 {
    workbuddy_json_i64(body, "credit")
}

/// 幂等令牌（面板 `clientToken` 用 `randomUUID` 同款语义：v4 UUID 字符串）。
pub fn workbuddy_client_token() -> String {
    uuid::Uuid::new_v4().to_string()
}

/// 连登档位（7d/14d/28d）。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WorkbuddyStreakTier {
    pub tier: String,
    pub days: i64,
    pub credit: i64,
    pub energy: i64,
    pub cards: i64,
    pub chances: i64,
}

/// 连登状态（成长中心 `GET /activity/growth/streak` 的投影）。
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct WorkbuddyStreakStatus {
    pub days: i64,
    pub month_total_days: i64,
    pub next_tier: Option<String>,
    pub next_tier_remaining: i64,
    pub makeup_cards: i64,
    pub tiers: Vec<WorkbuddyStreakTier>,
}

impl WorkbuddyStreakStatus {
    /// 可兑换的档位（状态既不是 `locked` 也不是 `claimed`）。
    ///
    /// 面板口径：档位状态由 `redemption_status.tier_{7d,14d,28d}_status` 给出，
    /// 未解锁时服务端兑换会 403「连续登录天数不足」——所以**先看状态再兑换**，
    /// 不要靠 403 当控制流。
    pub fn redeemable_tiers(&self, raw: &Value) -> Vec<String> {
        let statuses = raw
            .get("redemption_status")
            .and_then(Value::as_object)
            .cloned()
            .unwrap_or_default();
        self.tiers
            .iter()
            .filter(|tier| {
                let status = statuses
                    .get(&format!("tier_{}_status", tier.tier))
                    .and_then(Value::as_str)
                    .unwrap_or_default()
                    .trim()
                    .to_ascii_lowercase();
                status != "locked" && status != "claimed"
            })
            .map(|tier| tier.tier.clone())
            .collect()
    }
}

/// 解析连登状态。缺 `streak` 字段视为不可解析（不猜）。
pub fn parse_workbuddy_streak_status(body: &Value) -> Option<WorkbuddyStreakStatus> {
    let streak = body.get("streak")?.as_object()?;
    let status = body.get("redemption_status");
    let tiers = status
        .and_then(|status| status.get("tiers"))
        .and_then(Value::as_array)
        .map(|tiers| {
            tiers
                .iter()
                .filter_map(|tier| {
                    let tier_name = tier.get("tier").and_then(Value::as_str)?.trim().to_string();
                    if tier_name.is_empty() {
                        return None;
                    }
                    Some(WorkbuddyStreakTier {
                        tier: tier_name,
                        days: workbuddy_json_i64(tier, "days"),
                        credit: workbuddy_json_i64(tier, "credit"),
                        energy: workbuddy_json_i64(tier, "energy"),
                        cards: workbuddy_json_i64(tier, "cards"),
                        chances: workbuddy_json_i64(tier, "chances"),
                    })
                })
                .collect()
        })
        .unwrap_or_default();
    Some(WorkbuddyStreakStatus {
        days: workbuddy_json_i64(body.get("streak").unwrap_or(&Value::Null), "days"),
        month_total_days: workbuddy_json_i64(
            body.get("streak").unwrap_or(&Value::Null),
            "month_total_days",
        ),
        next_tier: streak
            .get("next_tier")
            .and_then(Value::as_str)
            .map(str::trim)
            .filter(|value| !value.is_empty())
            .map(ToOwned::to_owned),
        next_tier_remaining: workbuddy_json_i64(
            body.get("streak").unwrap_or(&Value::Null),
            "next_tier_remaining",
        ),
        makeup_cards: workbuddy_json_i64(
            body.get("makeup_cards").unwrap_or(&Value::Null),
            "balance",
        ),
        tiers,
    })
}

fn workbuddy_json_i64(value: &Value, key: &str) -> i64 {
    value
        .as_object()
        .map(|object| workbuddy_map_i64(object, key))
        .unwrap_or(0)
}

/// 从对象取整数（容忍数字与数字字符串两种形态）。
fn workbuddy_map_i64(object: &serde_json::Map<String, Value>, key: &str) -> i64 {
    object
        .get(key)
        .and_then(|value| match value {
            Value::Number(number) => number.as_i64(),
            Value::String(text) => text.trim().parse::<i64>().ok(),
            _ => None,
        })
        .unwrap_or(0)
}

fn workbuddy_map_str(object: &serde_json::Map<String, Value>, key: &str) -> String {
    object
        .get(key)
        .and_then(Value::as_str)
        .map(str::trim)
        .unwrap_or_default()
        .to_string()
}

/// 抽奖次数（`GET /activity/growth/lottery/summary`）。
pub fn parse_workbuddy_lottery_chances(body: &Value) -> u32 {
    body.get("chances")
        .and_then(|value| match value {
            Value::Number(number) => number.as_u64(),
            Value::String(text) => text.trim().parse::<u64>().ok(),
            _ => None,
        })
        .unwrap_or(0)
        .min(u32::MAX as u64) as u32
}

/// 成长中心对该账号是否**不可用**（企业号 / 国际号：上游一律 403）。
///
/// 面板对这两类账号**根本不发起调用**；这里作为兜底：真收到 403 就当「没有成长体系」，
/// 不报警、不重试。
pub fn is_workbuddy_growth_unavailable(status_code: u16, body_text: Option<&str>) -> bool {
    if status_code != 403 {
        return false;
    }
    let body = body_text.unwrap_or_default().to_ascii_lowercase();
    body.contains("growth")
        || body.contains("personal")
        || body.contains("连续登录")
        || body.is_empty()
}

/// 活跃上报的默认模型（面板 `ReportChatActivity` 的缺省）。
pub const WORKBUDDY_ACTIVITY_DEFAULT_MODEL_ID: &str = "deepseek-v4-flash";
pub const WORKBUDDY_ACTIVITY_DEFAULT_MODEL_NAME: &str = "DeepSeek V4 Flash";

/// 计费域端点。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum WorkbuddyBillingEndpoint {
    /// 个人资源包 / 余额。
    UserResource,
    /// 企业额度。
    EnterpriseUsage,
    /// 每日签到。
    DailyCheckin,
    /// 活跃上报。
    Report,
}

/// 该端点在给定 realm 下的**路径候选序列**（按顺序尝试）。
///
/// 面板口径（`billingMeterJSON`）：`/billing/meter` 族在国际域有新旧两条路径
/// （无 `/v2` 前缀优先，**只有 404 才换下一个**——其他错误直接返回，避免把参数错、
/// 限流、风控当成「路径不对」反复打）；CN 单路径。企业额度与 `/v2/report` 用的是
/// `billingJSON`（单路径，不回退）。
pub fn workbuddy_billing_path_candidates(
    endpoint: WorkbuddyBillingEndpoint,
    realm: WorkbuddyRealm,
) -> Vec<&'static str> {
    match endpoint {
        WorkbuddyBillingEndpoint::UserResource => match realm {
            WorkbuddyRealm::Global => vec![
                WORKBUDDY_USER_RESOURCE_PATH_GLOBAL,
                WORKBUDDY_USER_RESOURCE_PATH,
            ],
            WorkbuddyRealm::Cn => vec![WORKBUDDY_USER_RESOURCE_PATH],
        },
        WorkbuddyBillingEndpoint::DailyCheckin => match realm {
            WorkbuddyRealm::Global => vec![
                WORKBUDDY_DAILY_CHECKIN_PATH_GLOBAL,
                WORKBUDDY_DAILY_CHECKIN_PATH,
            ],
            WorkbuddyRealm::Cn => vec![WORKBUDDY_DAILY_CHECKIN_PATH],
        },
        WorkbuddyBillingEndpoint::EnterpriseUsage => vec![WORKBUDDY_ENTERPRISE_USAGE_PATH],
        WorkbuddyBillingEndpoint::Report => vec![WORKBUDDY_REPORT_PATH],
    }
}

/// 活跃上报是否被上游接受（2xx 且业务码为 0/缺省）。
///
/// 注意：上游在事件缺 `userId` 时是「200 但静默丢弃」，所以「接受」只说明请求本身成功，
/// 不代表连登一定被点亮——这也是我们把 uid 当必填、缺了就跳过上报的原因。
pub fn is_workbuddy_report_accepted(status_code: u16, body_text: Option<&str>) -> bool {
    (200..300).contains(&status_code)
        && workbuddy_business_code_is_zero(body_text.unwrap_or_default())
}

/// 签到结果。
///
/// 面板把「重复签到」与「企业号不支持」都当成**非失败**：前者说明今天已经签过，
/// 后者说明这个账号根本没有个人成长体系（`auth.go` 实测：企业号 POST
/// `/v2/billing/meter/daily-checkin` 恒返回 `400 code 10001 企业账号不支持该操作`，
/// 因此面板对 `IsEnterprise()` 的账号**直接跳过**签到）。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum WorkbuddyCheckinOutcome {
    /// 本次签到成功。
    CheckedIn,
    /// 今天已签到（上游幂等拒绝）。
    AlreadyCheckedIn,
    /// 企业号等不支持签到的账号。
    NotSupported,
    /// 真失败（网络/服务端/未知业务错误）——调用方可以记为失败，但不该因此中断余额刷新。
    Failed,
}

impl WorkbuddyCheckinOutcome {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::CheckedIn => "checked_in",
            Self::AlreadyCheckedIn => "already_checked_in",
            Self::NotSupported => "not_supported",
            Self::Failed => "failed",
        }
    }

    /// 是否算「非失败」（重复签到、企业号不支持都不该报警）。
    pub const fn is_ok(self) -> bool {
        !matches!(self, Self::Failed)
    }
}

/// 「今天已签到」文案（大小写不敏感匹配 `already`，中文按原文匹配）。
const ALREADY_CHECKIN_MARKERS: [&str; 2] = ["已签到", "already"];
/// 企业号不支持签到（上游文案/码的识别串）。
const CHECKIN_NOT_SUPPORTED_MARKERS: [&str; 3] = [
    "企业账号不支持",
    "only available for personal",
    "not supported for enterprise",
];

/// 判定一次签到响应的结果。
///
/// 顺序：**「不支持」文案优先**（`code 10001` 在两个语境里都出现，只能靠文案区分：
/// 个人号重复签到是「今天已签到」，企业号是「企业账号不支持该操作」）→ 已签到文案 →
/// 2xx 且业务码为 0/缺省 → 成功 → 其余失败。
pub fn classify_workbuddy_checkin_outcome(
    status_code: u16,
    body_text: Option<&str>,
) -> WorkbuddyCheckinOutcome {
    let body = body_text.unwrap_or_default();
    let lowered = body.to_ascii_lowercase();
    if CHECKIN_NOT_SUPPORTED_MARKERS
        .iter()
        .any(|marker| lowered.contains(marker))
    {
        return WorkbuddyCheckinOutcome::NotSupported;
    }
    if ALREADY_CHECKIN_MARKERS
        .iter()
        .any(|marker| body.contains(marker) || lowered.contains(marker))
    {
        return WorkbuddyCheckinOutcome::AlreadyCheckedIn;
    }
    if (200..300).contains(&status_code) && workbuddy_business_code_is_zero(body) {
        return WorkbuddyCheckinOutcome::CheckedIn;
    }
    WorkbuddyCheckinOutcome::Failed
}

/// 业务信封的 `code` 是否为 0（或响应体里没有业务码）。
fn workbuddy_business_code_is_zero(body: &str) -> bool {
    let trimmed = body.trim();
    if trimmed.is_empty() {
        return true;
    }
    let Ok(value) = serde_json::from_str::<Value>(trimmed) else {
        // 非 JSON 体（例如空体/纯文本）无法判业务码：交给状态码决定。
        return true;
    };
    let Some(code) = value.get("code") else {
        return true;
    };
    match code {
        Value::Number(number) => number.as_i64() == Some(0),
        Value::String(text) => text.trim().parse::<i64>().ok() == Some(0),
        Value::Null => true,
        _ => false,
    }
}

/// 请求级错误（上游解析不了请求体 / 上下文超限 / 图片格式错）的 **stop 正则**。
///
/// 这些错误换号重试是**白费**：同一个 body 换哪个账号结果都一样，只会白白消耗健康账号的
/// 额度（面板对它们也是「不罚号、不轮转」）。网关把它作为 provider config 的
/// `failover_rules.error_stop_patterns`（配 `status_codes: [400]`）默认值下发。
///
/// **不能改用 `success_failover_patterns`**：那个字段只在 HTTP **200** 时参与判定
/// （`classify_local_failover` 里有 `status_code == 200` 守卫），配 4xx 永远不会生效。
///
/// 覆盖文案与业务码两种形态（码形态容忍 JSON 空白）：
/// `11101` 参数解析失败、`11115` 上下文超限、`11135` 图片无效。
pub const WORKBUDDY_REQUEST_LEVEL_ERROR_STOP_PATTERN: &str = r#"Unmarshal chat params failed|"code"\s*:\s*"?11101|prompt is too long|"code"\s*:\s*"?11115|invalid image_url content|invalid_image_data|replace the image|"code"\s*:\s*"?11135"#;

/// 官方客户端「会话 / 链路」头族的注入（面板 `headers.go::injectConversationHeaders`）。
///
/// 面板注释（issue #35）说明这套头是给**上游后台聚合**用的：一轮对话里的所有
/// tool call / 重试 / 换号 / 降级要复用同一个 `X-Conversation-Request-ID`，
/// 后台才会把它们聚合成一条而不是碎片。
///
/// 规则逐条对齐面板：
/// - `X-Conversation-ID`：**客户端给了才发**，绝不伪造（伪造会让上游建错会话）。
///   ⚠️ **国际域例外（实测）**：上游对 global 的 chat 做渠道校验，该头缺失即
///   `400 code 11128 request illegal`；故 global 域在客户端没给时现生成 UUID
///   （实测该值不校验服务端会话存在性）。CN 域维持原规则不变。
/// - `X-Conversation-Request-ID`：聚合主键，**必发**。优先透传客户端值；否则用
///   `conversation_request_id`（调用方给的**一轮内稳定**值，Aether 传 trace id）
///   归一成 32 hex；再没有就现生成一个；
/// - `X-Conversation-Message-ID` = `X-Request-ID`：消息级，每次尝试新生成 32 hex；
/// - `X-Root-Request-ID` = 聚合主键；
/// - `X-Trace-ID`：入站透传优先，否则 = 聚合主键；
/// - `X-B3-TraceId`：聚合主键**合法**（16/32 hex）时用它，否则回落消息 id（恒 32 hex）；
///   `X-B3-SpanId` = 消息 id 前 16 hex；`X-B3-Sampled: 1`。
pub fn insert_workbuddy_conversation_headers_if_needed(
    transport: &GatewayProviderTransportSnapshot,
    api_format: &str,
    headers: &mut BTreeMap<String, String>,
    conversation_request_id: Option<&str>,
) {
    if !is_workbuddy_provider_transport(transport) {
        return;
    }
    if !api_format
        .trim()
        .to_ascii_lowercase()
        .starts_with("openai:")
    {
        return;
    }
    insert_workbuddy_conversation_headers(
        workbuddy_identity(transport).realm,
        headers,
        conversation_request_id,
    );
}

/// 头族本体（拆出来便于单测，不依赖完整快照）。
///
/// **ID 族已改 ULID**（报告 §10.2 / §10.3.4）：5.8.x 的 `X-Conversation-*` /
/// `X-Request-ID` / `X-Root-Request-ID` 不再是「UUID v4 去横线的 32 hex」，
/// 而是 **ULID（毫秒时间戳前缀）**。§10.2 的相等关系逐条保持（单测
/// `conversation_ids_keep_the_documented_equalities` 钉住）：
/// `X-Request-ID == X-Conversation-Message-ID`、
/// `X-Root-Request-ID == X-Conversation-Request-ID`、`X-Trace-ID == X-B3-TraceId`。
///
/// ⚠️ **B3 族刻意仍是 hex，不是 ULID**：`X-B3-TraceId`/`SpanId` 与 `traceparent`
/// 有硬格式（trace 32 hex、span 16 hex），塞 ULID 进去连 `traceparent` 都构造不出来。
/// 报告只给了「ID 族是 ULID」与「X-Trace-ID == X-B3-TraceId」两条，**没有**给出
/// 「官方把 ULID 写进 X-B3-TraceId」的真机证据，故取可执行的解释：会话族用 ULID，
/// B3 族由聚合主键**确定性派生**成 hex（同一轮内稳定，聚合语义不丢）。
pub fn insert_workbuddy_conversation_headers(
    realm: WorkbuddyRealm,
    headers: &mut BTreeMap<String, String>,
    conversation_request_id: Option<&str>,
) {
    let client_value = |headers: &BTreeMap<String, String>, name: &str| {
        headers
            .iter()
            .find(|(key, _)| key.eq_ignore_ascii_case(name))
            .map(|(_, value)| value.trim().to_string())
            .filter(|value| !value.is_empty())
    };

    // 聚合主键：客户端值优先（面板同款），其次调用方给的稳定种子（派生 ULID），最后现生成。
    let aggregate_key = client_value(headers, "x-conversation-request-id")
        .or_else(|| {
            conversation_request_id
                .map(str::trim)
                .filter(|value| !value.is_empty())
                .map(workbuddy_ulid_from_seed)
        })
        .unwrap_or_else(workbuddy_new_ulid);
    // 消息级 id：每次尝试新生成一个 ULID（重试/换号不得复用）。
    let message_id = workbuddy_new_ulid();

    if let Some(conversation_id) = client_value(headers, "x-conversation-id") {
        set_header(headers, "x-conversation-id", conversation_id);
    } else if realm.is_global() {
        // 国际域例外（实测，2026-10 对齐官方 `WorkBuddyAI 5.8.4` 出站请求二分）：
        // 上游对 global 的 chat 做**渠道校验**，`X-Conversation-ID` 缺失即
        // `HTTP 400 {"code":11128,"msg":"request illegal"}`
        // （displayTips「这次调用没通过渠道校验，可能不是官方客户端发出的」）。
        // 而 Aether 的入站客户端（OpenAI SDK / Cursor 等）从不带这个头，
        // 于是 global 域此前**所有** chat 都被拦掉——这是「国际号不可用」的根因。
        //
        // 实测：该头取值不校验服务端会话存在性，现生成 UUID 即可通过；
        // 故此处覆盖上面「客户端给了才发」的通用规则，仅在 global 域生效
        // （CN 域维持原规则，零回归）。
        set_header(
            headers,
            "x-conversation-id",
            uuid::Uuid::new_v4().to_string(),
        );
    }
    set_header(headers, "x-conversation-request-id", aggregate_key.clone());
    set_header(headers, "x-conversation-message-id", message_id.clone());
    set_header(headers, "x-request-id", message_id.clone());
    set_header(headers, "x-root-request-id", aggregate_key.clone());

    // ---- B3 + W3C trace 上下文 ----
    // 报告 §10.3.4：旧实现只有 `X-B3-TraceId/SpanId/Sampled` 三件，5.8.x 是**全族**
    // （`traceparent` + `b3` 单头 + `X-B3-ParentSpanId` 都在）。
    let trace_id = workbuddy_b3_trace_id(&aggregate_key);
    let span_id = workbuddy_b3_span_id(&message_id, "span");
    // 父 span：入站给了合法 16 hex 就用，否则由聚合主键确定性派生（同一轮内恒定）。
    let parent_span_id = client_value(headers, "x-b3-parentspanid")
        .filter(|value| is_workbuddy_b3_span_id(value))
        .map(|value| value.to_ascii_lowercase())
        .unwrap_or_else(|| workbuddy_b3_span_id(&aggregate_key, "parent"));

    // §10.2：「X-Trace-ID == X-B3-TraceId」这条相等关系必须保持（单测钉住）。
    set_header(headers, "x-trace-id", trace_id.clone());
    set_header(headers, "x-b3-traceid", trace_id.clone());
    set_header(headers, "x-b3-spanid", span_id.clone());
    set_header(headers, "x-b3-parentspanid", parent_span_id);
    set_header(headers, "x-b3-sampled", "1");
    // `traceparent`：W3C 形态 `00-<32hex trace>-<16hex span>-<flags>`，采样位与 B3 同值。
    set_header(
        headers,
        "traceparent",
        format!("00-{trace_id}-{span_id}-01"),
    );
    // `b3` 单头：`<trace>-<span>-<sampling>`，取值与上面 B3 多头完全一致。
    set_header(headers, "b3", format!("{trace_id}-{span_id}-1"));
}

/// Crockford base32 字母表（ULID 规范；刻意不含 `I`/`L`/`O`/`U` 的歧义形态）。
const WORKBUDDY_ULID_ALPHABET: &[u8; 32] = b"0123456789ABCDEFGHJKMNPQRSTVWXYZ";
/// ULID 编码长度：26 个 base32 字符 = 130 bit（最高 2 bit 恒 0，正好装下 128 bit）。
const WORKBUDDY_ULID_LEN: usize = 26;

/// 当前毫秒时间戳（ULID 的时间戳前缀）。
fn workbuddy_now_ms() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|elapsed| elapsed.as_millis() as u64)
        .unwrap_or(0)
}

/// 生成一个 **ULID**：48 位毫秒时间戳 + 80 位随机（报告 §10.2「ID 族为 ULID」）。
///
/// 为什么自己实现而不加依赖：ULID 就是「时间戳前缀 + 随机尾巴」的 26 字符编码，
/// 纯函数二十行写完；为一个字符串多引一个 crate 不划算。随机源复用已有依赖
/// `uuid::Uuid::new_v4()`（122 bit 随机，取前 80 bit 足够）。
pub fn workbuddy_new_ulid() -> String {
    let mut randomness = [0u8; 10];
    randomness.copy_from_slice(&uuid::Uuid::new_v4().into_bytes()[..10]);
    workbuddy_ulid_from_parts(workbuddy_now_ms(), randomness)
}

/// 由稳定种子派生**同一个** ULID（`sha256("wb2a:ulid:" + seed)` 填满 48 bit 时间戳 + 80 bit 随机）。
///
/// 用途：聚合主键（`X-Conversation-Request-ID`）要求「一轮内稳定、跨尝试不变」，
/// 而调用方给的种子（Aether 传的是入站 trace id）不是 ULID 形态。
///
/// ⚠️ 这条 ULID 的**时间戳段也来自哈希**，不是当前时间：它的语义是「同一种子恒等」，
/// 掺当前毫秒就会让同一轮里的两次尝试拿到不同聚合主键、上游把一次对话拆成多条。
/// 真实时间戳只用于消息级 id（`workbuddy_new_ulid`，每次尝试新生成）。
pub fn workbuddy_ulid_from_seed(seed: &str) -> String {
    let digest = sha256_bytes(&format!("wb2a:ulid:{seed}"));
    let mut timestamp_bytes = [0u8; 8];
    timestamp_bytes[2..].copy_from_slice(&digest[..6]);
    let mut randomness = [0u8; 10];
    randomness.copy_from_slice(&digest[6..16]);
    workbuddy_ulid_from_parts(u64::from_be_bytes(timestamp_bytes), randomness)
}

fn workbuddy_ulid_from_parts(timestamp_ms: u64, randomness: [u8; 10]) -> String {
    let mut tail: u128 = 0;
    for byte in randomness {
        tail = (tail << 8) | u128::from(byte);
    }
    // 128 bit = 48 bit 毫秒时间戳 << 80 | 80 bit 随机。
    let mut value = (u128::from(timestamp_ms & 0x0000_FFFF_FFFF_FFFF) << 80) | tail;
    let mut chars = [b'0'; WORKBUDDY_ULID_LEN];
    for index in (0..WORKBUDDY_ULID_LEN).rev() {
        chars[index] = WORKBUDDY_ULID_ALPHABET[(value & 0x1F) as usize];
        value >>= 5;
    }
    String::from_utf8(chars.to_vec()).expect("Crockford base32 全是 ASCII")
}

/// 形态校验：26 个 Crockford 字符，且首字符 ≤ `7`（保证 128 bit 不溢出到 130 bit 的表示）。
pub fn is_workbuddy_ulid(value: &str) -> bool {
    if value.len() != WORKBUDDY_ULID_LEN {
        return false;
    }
    let bytes = value.as_bytes();
    if !WORKBUDDY_ULID_ALPHABET.contains(&bytes[0]) || u32::from(bytes[0]) > u32::from(b'7') {
        return false;
    }
    bytes
        .iter()
        .all(|byte| WORKBUDDY_ULID_ALPHABET.contains(byte))
}

/// 取出 ULID 的毫秒时间戳前缀（单测用：把「毫秒时间戳前缀」这条钉成可验证的事实）。
pub fn workbuddy_ulid_timestamp_ms(value: &str) -> Option<u64> {
    if !is_workbuddy_ulid(value) {
        return None;
    }
    let mut accum: u64 = 0;
    for byte in value.as_bytes().iter().take(10) {
        let digit = WORKBUDDY_ULID_ALPHABET
            .iter()
            .position(|candidate| candidate == byte)? as u64;
        accum = (accum << 5) | digit;
    }
    // 前 10 个字符共 50 bit，其中高位 2 bit 恒 0 → 低 48 bit 才是时间戳。
    Some(accum & 0x0000_FFFF_FFFF_FFFF)
}

fn sha256_bytes(seed: &str) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(seed.as_bytes());
    let digest = hasher.finalize();
    let mut out = [0u8; 32];
    out.copy_from_slice(&digest);
    out
}

fn hex_prefix_of_sha256(seed: &str, bytes: usize) -> String {
    sha256_bytes(seed)[..bytes]
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect()
}

/// B3 / W3C 的 trace id：**恒 32 hex**，且在同一聚合主键上确定性。
///
/// - 已是 32 hex → 原样用（小写）；
/// - 16 hex（64 位 trace id）→ 左补 0 到 32 hex（W3C traceparent 对 64 位 id 的规定）；
/// - 其它（ULID 等）→ `sha256` 前 16 字节，保证同一聚合主键恒得同一个 trace id。
fn workbuddy_b3_trace_id(aggregate_key: &str) -> String {
    let is_hex = |value: &str| value.chars().all(|character| character.is_ascii_hexdigit());
    if aggregate_key.len() == 32 && is_hex(aggregate_key) {
        return aggregate_key.to_ascii_lowercase();
    }
    if aggregate_key.len() == 16 && is_hex(aggregate_key) {
        return format!("0000000000000000{}", aggregate_key.to_ascii_lowercase());
    }
    hex_prefix_of_sha256(aggregate_key, 16)
}

/// B3 的 span id：**恒 16 hex**（64 位），按 `(seed, purpose)` 确定性派生。
fn workbuddy_b3_span_id(seed: &str, purpose: &str) -> String {
    hex_prefix_of_sha256(&format!("wb2a:span:{purpose}:{seed}"), 8)
}

/// 入站 `X-B3-ParentSpanId` 的合法性：16 hex。
fn is_workbuddy_b3_span_id(value: &str) -> bool {
    value.len() == 16 && value.chars().all(|character| character.is_ascii_hexdigit())
}

/// 取 WorkBuddy 的**访问令牌**（Bearer 值本体，不带前缀）。
///
/// 与本地刷新适配器同一事实来源：provider-oauth 落库时把 access token 写进 key 的
/// 加密密钥字段；密钥为空时回退 `auth_config` 的 `accessToken`/`access_token`
/// （导入面板凭据的形态）。
///
/// 供模型目录拉取（`GET /v3/config`）等「按账号直连上游」的路径使用——
/// 那些路径拿不到通用的 OpenAI bearer 解析器（它只认 `api_key`/`bearer` 两种
/// `auth_type`，而本 provider 是 `oauth`）。
pub fn resolve_workbuddy_access_token(
    transport: &GatewayProviderTransportSnapshot,
) -> Option<String> {
    let token = transport.key.decrypted_api_key.trim();
    if !token.is_empty() {
        return Some(token.to_string());
    }
    let config = workbuddy_auth_config(transport)?;
    ["access_token", "accessToken"].iter().find_map(|field| {
        config
            .get(*field)
            .and_then(Value::as_str)
            .map(str::trim)
            .filter(|value| !value.is_empty())
            .map(ToOwned::to_owned)
    })
}

/// 请求体里带 `conversationId` 时用到的头名。
pub const WORKBUDDY_CODEBUDDY_REQUEST_HEADER: &str = "x-codebuddy-request";

/// CN / 国际两个域。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum WorkbuddyRealm {
    Cn,
    Global,
}

impl WorkbuddyRealm {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Cn => "cn",
            Self::Global => "global",
        }
    }

    pub fn is_global(self) -> bool {
        matches!(self, Self::Global)
    }

    /// 该域的对话入口 base_url。
    pub fn chat_base_url(self) -> &'static str {
        match self {
            Self::Cn => WORKBUDDY_CHAT_BASE_URL_CN,
            Self::Global => WORKBUDDY_CHAT_BASE_URL_GLOBAL,
        }
    }

    /// 该域的 `Origin` / `Referer` 基础域。
    pub fn origin(self) -> &'static str {
        match self {
            Self::Cn => WORKBUDDY_ORIGIN_CN,
            Self::Global => WORKBUDDY_ORIGIN_GLOBAL,
        }
    }

    /// 该域的 `Accept-Language`。
    pub fn accept_language(self) -> &'static str {
        match self {
            Self::Cn => "zh-CN",
            Self::Global => "en-US",
        }
    }

    /// 本 crate 的 realm ⇄ `aether-oauth` 的 realm。
    ///
    /// 两个枚举值域一一对应（`cn` / `global`），三段式 UA 的平台段与版本段的
    /// **权威定义**在 `aether-oauth` 侧，这里只做转接，不保存第二份值。
    pub fn oauth_realm(self) -> OAuthWorkbuddyRealm {
        match self {
            Self::Cn => OAuthWorkbuddyRealm::Cn,
            Self::Global => OAuthWorkbuddyRealm::Global,
        }
    }

    /// 该域三段式 UA 的平台段：CN `WorkBuddy`，国际 `workbuddy-ai`。
    ///
    /// 委托 `aether-oauth`（刷新路径用的就是同一份定义）。国际段逐字取自官方国际版
    /// 桌面端实测 UA（`WorkBuddy/5.8.4 workbuddy-ai/5.8.4 CLI/2.161.0`）：早期实现
    /// 写的是带空格的旧品牌名（源自 intl 逆向笔记），与实际出站值不一致。
    pub fn user_agent_platform(self) -> &'static str {
        self.oauth_realm().user_agent_platform()
    }

    /// 该域出站 UA / `x-ide-version` 使用的客户端版本段（委托 `aether-oauth`）。
    pub fn client_version(self) -> &'static str {
        self.oauth_realm().client_version()
    }

    /// 该域出站 UA 的 `CLI/<ver>` 段（委托 `aether-oauth`）。
    pub fn cli_version(self) -> &'static str {
        self.oauth_realm().cli_version()
    }
}

/// 从 key 的 `auth_config` 里解析出的账号身份。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WorkbuddyIdentity {
    pub realm: WorkbuddyRealm,
    pub uid: Option<String>,
    pub enterprise_id: Option<String>,
    pub domain: Option<String>,
    /// 设备风控 token（来自 **provider config**，不是 auth config）：有就随请求注入
    /// `X-Device-Token`，没有就不发（面板 `device_token.go` 同款「优雅降级」语义）。
    pub device_token: Option<String>,
}

impl WorkbuddyIdentity {
    /// 无任何身份信息时的缺省：CN 域、uid / 企业 / 域全空、无设备 token。
    pub fn cn_default() -> Self {
        Self {
            realm: WorkbuddyRealm::Cn,
            uid: None,
            enterprise_id: None,
            domain: None,
            device_token: None,
        }
    }

    pub fn with_realm(mut self, realm: WorkbuddyRealm) -> Self {
        self.realm = realm;
        self
    }
}

/// 判断快照是否属于本 provider。
pub fn is_workbuddy_provider_transport(transport: &GatewayProviderTransportSnapshot) -> bool {
    transport
        .provider
        .provider_type
        .trim()
        .eq_ignore_ascii_case(WORKBUDDY_PROVIDER_TYPE)
}

/// 解析 key 的 `decrypted_auth_config`（JSON 字符串）为对象。
///
/// 非法 JSON / 非对象一律返回 `None`，调用方按「无身份」降级处理——
/// 与其它 provider 的既有约定一致（不因配置脏数据直接失败）。
pub fn workbuddy_auth_config(transport: &GatewayProviderTransportSnapshot) -> Option<Value> {
    let raw = transport.key.decrypted_auth_config.as_deref()?;
    let parsed: Value = serde_json::from_str(raw.trim()).ok()?;
    parsed.is_object().then_some(parsed)
}

/// 读一个字符串字段，同时接受 camelCase 与 snake_case 两种写法。
///
/// 账号文件在两个生态里都有：面板/CLI 写 camelCase（`accessToken` /
/// `enterpriseId`），导入导出工具常写 snake_case，两者都要认。
fn auth_config_string(config: &Value, snake: &str, camel: &str) -> Option<String> {
    let object = config.as_object()?;
    let value = object.get(snake).or_else(|| object.get(camel))?;
    value
        .as_str()
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .map(ToOwned::to_owned)
}

/// 域是否为国际域（`workbuddy.ai` 及其子域）。
pub fn is_workbuddy_global_domain(domain: &str) -> bool {
    let normalized = domain.trim().to_ascii_lowercase();
    normalized == "workbuddy.ai" || normalized.ends_with(".workbuddy.ai")
}

/// 从 auth_config 解析账号身份。
///
/// 域判定与面板 `Realm()` 同口径：显式 `realm == "global"` 优先，其次看
/// `domain` 是否落在 `workbuddy.ai`，两者都不是即 CN。
pub fn workbuddy_identity(transport: &GatewayProviderTransportSnapshot) -> WorkbuddyIdentity {
    // 设备 token 来自 **provider config**（不是 auth config），先读出来——没有 auth config
    // 的早退路径同样要带上它。
    let device_token = transport
        .provider
        .config
        .as_ref()
        .and_then(|config| config.get(WORKBUDDY_DEVICE_TOKEN_CONFIG_KEY))
        .and_then(Value::as_str)
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .filter(|value| value.len() <= WORKBUDDY_DEVICE_TOKEN_MAX_BYTES)
        .map(ToOwned::to_owned);
    let Some(config) = workbuddy_auth_config(transport) else {
        return WorkbuddyIdentity {
            device_token,
            ..WorkbuddyIdentity::cn_default()
        };
    };
    let domain = auth_config_string(&config, "domain", "domain");
    let explicit_realm = auth_config_string(&config, "realm", "realm");
    let realm = if explicit_realm
        .as_deref()
        .is_some_and(|value| value.trim().eq_ignore_ascii_case("global"))
        || domain.as_deref().is_some_and(is_workbuddy_global_domain)
    {
        WorkbuddyRealm::Global
    } else {
        WorkbuddyRealm::Cn
    };
    WorkbuddyIdentity {
        realm,
        uid: auth_config_string(&config, "uid", "uid")
            .or_else(|| auth_config_string(&config, "user_id", "userId")),
        enterprise_id: auth_config_string(&config, "enterprise_id", "enterpriseId"),
        domain,
        device_token,
    }
}

/// 对话端点出站 UA：**两段式** `CLI/{cli} WorkBuddy/{cli}`（CLI headless 形态）。
///
/// **委托** `aether_oauth::provider::providers::workbuddy_user_agent`：UA 的唯一出口
/// 在 `aether-oauth`（依赖方向 `transport → oauth`），刷新路径（OAuth 刷新请求）与
/// 对话路径（本函数 → 头注入）因此送出**同一个字符串**。本文件**不得**再出现 UA 字面量。
///
/// 报告 §10.1：我们扮演的是 **CLI 裸跑（headless `-p`）**，官方这种形态出站是两段式
/// （旧实现的三段式是桌面端形态，两者被上游当成不同客户端）。
pub fn workbuddy_user_agent(realm: WorkbuddyRealm) -> String {
    aether_oauth::provider::providers::workbuddy_user_agent(realm.oauth_realm())
}

/// 桌面端形态的三段式 UA（`WorkBuddy/{ver} {platform}/{ver} CLI/{cli}`）。
///
/// 我们**不是**桌面端（没有 Electron/Chromium 那一层），默认出站不走这里；
/// 保留它是为了让「形态」可切换、可对照（报告 §10.1 把 UA 拆成两种形态）。
pub fn workbuddy_desktop_user_agent(realm: WorkbuddyRealm) -> String {
    aether_oauth::provider::providers::workbuddy_user_agent_for(
        realm.oauth_realm(),
        aether_oauth::provider::providers::WorkbuddyEndpointKind::Conversation,
        aether_oauth::provider::providers::WorkbuddyCallForm::Desktop,
    )
}

/// 按 `uid + 用途` 稳定派生 36 位 hex 账号标识。
///
/// 与面板 `deriveAccountStableID` 逐字节一致：`sha256("wb2a:" + purpose +
/// ":" + uid)` 取前 18 字节的 hex。用途固定两种：
/// `machine` → `X-Machine-ID`，`session` → `X-Session-ID`。
///
/// 为什么必须跨重启恒定：这两个头表达的是「同一个账号始终是同一台虚拟设备」，
/// 每次启动换值等于把多号关联风控的指纹漂移送上去。
pub fn derive_workbuddy_account_stable_id(uid: &str, purpose: &str) -> Option<String> {
    let uid = uid.trim();
    if uid.is_empty() {
        return None;
    }
    let mut hasher = Sha256::new();
    hasher.update(WORKBUDDY_ACCOUNT_ID_SALT.as_bytes());
    hasher.update(purpose.as_bytes());
    hasher.update(b":");
    hasher.update(uid.as_bytes());
    let digest = hasher.finalize();
    let mut out = String::with_capacity(36);
    for byte in digest.iter().take(18) {
        out.push(hex_digit(byte >> 4));
        out.push(hex_digit(byte & 0x0f));
    }
    Some(out)
}

fn hex_digit(nibble: u8) -> char {
    match nibble {
        0..=9 => (b'0' + nibble) as char,
        _ => (b'a' + (nibble - 10)) as char,
    }
}

/// 按 provider 规则补齐 CodeBuddy 出站头。
///
/// 只在「本 provider + OpenAI 系 api_format」时生效，其它情况零改动
/// （与 `insert_opencode_request_headers_if_needed` 同一约定）。
pub fn insert_workbuddy_request_headers_if_needed(
    transport: &GatewayProviderTransportSnapshot,
    api_format: &str,
    headers: &mut BTreeMap<String, String>,
) {
    if !is_workbuddy_provider_transport(transport) {
        return;
    }
    if !api_format
        .trim()
        .to_ascii_lowercase()
        .starts_with("openai:")
    {
        return;
    }
    // ① 白名单：先挡掉第三方客户端自带的身份/遥测头（x-zcode-* / x-title /
    //    http-referer / sec-fetch-* …），避免把真实客户端归属泄露给上游、
    //    也避免「官方 UA + 外家头」的自相矛盾指纹触发风控。
    sanitize_workbuddy_outbound_headers(headers);
    // ② 再写入官方身份头族（含内部标记 x-aether-workbuddy-runtime，必须在过滤之后，
    //    否则会被白名单误删、响应侧 DSML 还原认不出本 provider）。
    let identity = workbuddy_identity(transport);
    insert_workbuddy_request_headers(&identity, headers);
}

/// 出站头**白名单**：只保留官方客户端头族 + 协议基础 + 凭证 + 会话链路 + 中性桌面遥测，
/// 其余（尤其是第三方客户端的归属头）一律不转发。
///
/// - **在身份头写入之前**调用：白名单含会话/链路入站头（`x-conversation-*` /
///   `x-trace-id` / `x-b3-*` / `x-request-id` / `x-root-request-id`），要留给随后的
///   `insert_workbuddy_conversation_headers_if_needed` 按「客户端值优先」消费；
///   身份头与内部标记都在本过滤**之后**由 `insert_workbuddy_request_headers` 写入，不受影响。
/// - **中性桌面遥测**（`x-client-language` / `x-client-timezone` / `x-os-*` /
///   `x-platform` / `x-release-channel`）是官方桌面端也会发的、**不含客户端产品归属**的
///   字段，保留以维持指纹完整；真正暴露归属的 `x-zcode-*` / `x-title` / `http-referer` /
///   `sec-fetch-*` / `x-query-id` 不在白名单 → 被丢弃。
/// - 未在白名单内的**任何未知头**默认丢弃（这是「默认不外传」的取舍）；端点
///   `header_rules` 的 `set` 先于本过滤执行，因此只有白名单内的自定义键才会保留。
fn sanitize_workbuddy_outbound_headers(headers: &mut BTreeMap<String, String>) {
    const ALLOWED: &[&str] = &[
        // 协议基础
        "accept",
        "accept-encoding",
        "accept-language",
        "content-type",
        // 凭证（上层同时单独携带 auth_header/auth_value，这里保留是双保险）
        "authorization",
        // 官方身份头族（随后被 insert_workbuddy_request_headers 覆盖为账号真值）
        "origin",
        "referer",
        "user-agent",
        "x-requested-with",
        "x-codebuddy-request",
        "x-user-id",
        "x-no-user-id",
        "x-enterprise-id",
        "x-no-enterprise-id",
        "x-domain",
        "x-no-department-info",
        "x-agent-purpose",
        "x-agent-intent",
        "x-agent-type",
        "x-private-data",
        "x-ide-name",
        "x-ide-type",
        "x-ide-version",
        "x-product",
        "x-device-token",
        // 注：`x-machine-id` / `x-session-id` **已移出白名单**（报告 §10.1/§10.3.6：
        // 5.8.x 对话请求根本不发这两个头；旧实现是自己在注入，这里连入站透传也一起关掉，
        // 避免第三方客户端带进来的值被原样转给上游）。
        // 会话/链路入站头（供随后 insert_workbuddy_conversation_headers 「客户端值优先」消费）
        "x-conversation-id",
        "x-conversation-request-id",
        "x-conversation-message-id",
        "x-root-request-id",
        "x-request-id",
        "x-trace-id",
        "x-b3-traceid",
        "x-b3-spanid",
        "x-b3-parentspanid",
        "x-b3-sampled",
        // W3C / B3 单头：入站带了就参与派生（父 span 优先用入站值），不带就现生成
        "traceparent",
        "b3",
        // 中性桌面遥测（官方桌面端也发、不含客户端产品归属）
        "x-client-language",
        "x-client-timezone",
        "x-os-category",
        "x-os-version",
        "x-platform",
        "x-release-channel",
    ];
    let allowed: std::collections::BTreeSet<&str> = ALLOWED.iter().copied().collect();
    headers.retain(|name, _| allowed.contains(name.trim().to_ascii_lowercase().as_str()));
}

/// 头族本体（拆出来便于单测，不依赖完整快照）。
pub fn insert_workbuddy_request_headers(
    identity: &WorkbuddyIdentity,
    headers: &mut BTreeMap<String, String>,
) {
    let realm = identity.realm;
    let origin = realm.origin();

    // 设备风控头：有配置就注入（对话与计费/成长两类请求都要，面板同口径）。
    insert_workbuddy_device_token(identity, headers);
    // 报告 §10.3.6：`Accept` 从 `application/json, text/event-stream` 改成 `application/json`
    // （5.8.x 真机的 chat 请求就是只声明 JSON；SSE 仍照常回流）。
    set_header(headers, "accept", "application/json");
    // 报告 §10.2「不变的」：`Accept-Encoding: gzip, compress, deflate, br`。
    // 旧形态发 `identity` 是**指纹异常**（对照见报告该条）。上游响应侧会按此压缩，
    // 转发层本身已支持解码（否则对话早就坏了）。
    set_header(headers, "accept-encoding", "gzip, compress, deflate, br");
    set_header(headers, "x-requested-with", "XMLHttpRequest");
    set_header(headers, "origin", origin);
    set_header(headers, "referer", format!("{origin}/"));
    set_header(headers, "user-agent", workbuddy_user_agent(realm));
    // 官方客户端的风控闸门头：所有 API 请求必带。
    set_header(headers, WORKBUDDY_CODEBUDDY_REQUEST_HEADER, "1");
    // 内部标记：响应侧据此走 DSML 还原（grok 同款手法）。
    set_header(headers, WORKBUDDY_INTERNAL_HEADER, "1");
    set_header(headers, "accept-language", realm.accept_language());

    match identity.uid.as_deref() {
        Some(uid) => {
            set_header(headers, "x-user-id", uid);
            // 报告 §10.3.6：**不再发** `X-Machine-ID` / `X-Session-ID`。
            // 5.8.x 的两份真机抓包（CN CLI + Global 桌面）里对话请求都没有这两个头，
            // 而旧实现按 `sha256("wb2a:"+purpose+":"+uid)` 派生 36 位 hex 一直在发
            // ——这是最容易被当成「非官方客户端」的一处形态差。
        }
        None => {
            set_header(headers, "x-no-user-id", "1");
        }
    }

    if realm.is_global() {
        // 国际版：无企业 + 显式声明国际域，且不回落到登录域的原始值。
        set_header(headers, "x-no-enterprise-id", "1");
        set_header(headers, "x-domain", "www.workbuddy.ai");
    } else {
        match identity.enterprise_id.as_deref() {
            Some(enterprise_id) => {
                set_header(headers, "x-enterprise-id", enterprise_id);
            }
            None => {
                set_header(headers, "x-no-enterprise-id", "1");
            }
        }
        match identity.domain.as_deref() {
            Some(domain) => {
                set_header(headers, "x-domain", domain);
            }
            None => {
                set_header(headers, "x-no-department-info", "1");
            }
        }
    }

    // 用量归属头：对齐官方出站形态，避免上游把请求归因成「网关特征」。
    set_header(headers, "x-agent-purpose", "conversation");
    // 报告 §10.3.4：新增三头（5.8.x 真机必带，旧实现完全没有）。
    // `X-Agent-Intent: craft` / `X-Agent-Type: main` 是上游划分 agent 形态的标记；
    // `X-Private-Data: true` 是隐私开关（官方默认开）。
    set_header(headers, "x-agent-intent", "craft");
    set_header(headers, "x-agent-type", "main");
    set_header(headers, "x-private-data", "true");
    // 报告 §10.1/§10.3.3：`X-IDE-*` 按**调用形态**取值。我们扮演 CLI headless，
    // 官方这种形态是 `CLI/CLI/{cli 版本}`（桌面端才是 `WorkBuddy/WorkBuddy/{桌面版本}`）。
    set_header(headers, "x-ide-name", "CLI");
    set_header(headers, "x-ide-type", "CLI");
    set_header(headers, "x-ide-version", realm.cli_version());
    // 报告 §10.1：`X-Product` **两端都是 `SaaS`**（旧实现 CN 发 `WorkBuddy`，是错的）。
    set_header(headers, "x-product", "SaaS");
    // 报告 §10.1 末行：`x-stainless-*` 七个（openai-node 6.25.0 指纹）。
    // 官方 CLI 是 Node 程序、出站由 openai-node SDK 生成，所以这七个头是「真机形状」的一部分；
    // 运行时版本取报告 §10.4 里 CN CLI 的 Node 版本（v24.15.0）。
    insert_workbuddy_stainless_headers(headers);
}

/// `x-stainless-*` 七个头（openai-node 6.25.0 指纹，报告 §10.1 末行 / §10.3.3）。
///
/// 取值说明：
/// - `package-version` = `6.25.0`：报告点名的 openai-node 版本；
/// - `runtime=node` + `runtime-version=v24.15.0`：与报告 §10.4 里 **CN CLI 的 Node 运行时**
///   （Node v24.15.0 / OpenSSL 3.5.x）一致；
/// - `os=Linux` / `arch=x64`：154 上生产网关的实际平台，与官方 Linux 版 CLI 同形；
/// - `lang=js`：openai-node 恒定值；
/// - `retry-count=0`：单次尝试（Aether 自己的重试在更外层，不在这里累加）。
///
/// 这七个头**不是**必需头（报告 §3.3 对照实验：去掉均 200），加它们纯粹是为了
/// 让指纹更接近官方客户端，属于「防御性对齐」。
fn insert_workbuddy_stainless_headers(headers: &mut BTreeMap<String, String>) {
    set_header(headers, "x-stainless-arch", "x64");
    set_header(headers, "x-stainless-lang", "js");
    set_header(headers, "x-stainless-os", "Linux");
    set_header(headers, "x-stainless-package-version", "6.25.0");
    set_header(headers, "x-stainless-runtime", "node");
    set_header(headers, "x-stainless-runtime-version", "v24.15.0");
    set_header(headers, "x-stainless-retry-count", "0");
}

/// 写入头，并保证大小写不敏感的唯一性。
///
/// 与 xai 的「只在缺失时补」不同，这里**刻意覆盖**：这些头是上游的身份判据，
/// 客户端自带的 `origin` / `user-agent` / `x-user-id` 必须被账号真实值替换，
/// 否则就会出现「以网关自己的域名冒充官方客户端」的组合——正是上游
/// `403 code 11140 request illegal` 想拦的形态。顺手清掉大小写不同的重复键，
/// 避免转发层同时发出两个只差大小写的同名头。
fn set_header(headers: &mut BTreeMap<String, String>, name: &str, value: impl Into<String>) {
    let duplicates: Vec<String> = headers
        .keys()
        .filter(|existing| existing.eq_ignore_ascii_case(name))
        .cloned()
        .collect();
    for duplicate in duplicates {
        headers.remove(&duplicate);
    }
    headers.insert(name.to_string(), value.into());
}

/// WorkBuddy 出站请求体的**协议兼容**归一化。
///
/// 上游的 OpenAI 子集比标准窄，四条差异都会直接 400 或静默失效（面板
/// `internal/upstream/payload.go` 的对应步骤）：
///
/// 1. role 白名单不含 `developer`（送上去是 `400 code 11-128`）→ 归一成 `system`；
/// 2. 只认 `max_tokens`；`max_completion_tokens` 会被忽略并落回上游默认上限
///    （表现为长回答被静默截断）→ 别名删除，正整数值翻译过去；
/// 3. `tool_choice` 只认字符串：`{"type":"auto"}` 一类对象会被拒 →
///    摊平成 `"auto"` / `"required"` / 函数名；`none` 连 `tools` 一起去掉；
/// 4. `image_url` 只接受对象形态（字符串形态是 `400 code 11101`）→ 包一层 `url`。
///
/// 只对本 provider 的 `openai:*` 格式生效；非对象 body、缺字段、类型不符
/// 一律原样返回（协议层绝不因为脏数据抛错）。
pub fn apply_workbuddy_request_body_semantics(
    transport: &GatewayProviderTransportSnapshot,
    api_format: &str,
    body: &mut Value,
) {
    if !is_workbuddy_provider_transport(transport) {
        return;
    }
    if !api_format
        .trim()
        .to_ascii_lowercase()
        .starts_with("openai:")
    {
        return;
    }
    // prompt_cache_key 注入（P0 费用优化）：放在最前，之后所有归一都不影响它。
    // 入站会话头这一级当前未接（见函数注释的优先级 3），而 body 里的会话字段优先于它，
    // 所以常见路径的行为与面板一致。
    apply_workbuddy_prompt_cache_key(transport, api_format, body, None);
    let Some(object) = body.as_object_mut() else {
        return;
    };

    // 顺序对齐面板 `PrepareBodyOptWithEffortsAndDefault`：
    // 别名翻译 → gpt 下限钳制 → stream_options → tool_choice → tool pattern → role → image。
    normalize_max_completion_tokens(object);
    clamp_workbuddy_gpt_max_tokens(object);
    ensure_workbuddy_stream_options(object);
    normalize_tool_choice(object);
    unescape_workbuddy_tool_patterns(object);
    normalize_developer_roles(object);
    normalize_image_urls(object);
    // tool 配对三步（合并 → 重排 → 清孤儿）：面板把它放在所有归一之后、脱敏之前。
    normalize_workbuddy_tool_pairing(object);
    // DeepSeek 思维链三件套（顺序同面板）：注入开关 → 档位降级 → reasoning 回填。
    // 档位信息取自 key 元数据；读不到就与面板「目录缓存未命中」同口径（不降级）。
    let model = object
        .get("model")
        .and_then(Value::as_str)
        .unwrap_or_default()
        .to_string();
    let (supported_efforts, default_effort) = workbuddy_reasoning_metadata(transport, &model);
    // global 域：远端桶非空即权威，否则落**产品静态兜底表**（面板 issue #84：global 上游
    // 可能不下发 supportedEfforts，而发不支持的档位是非法参数 400）。CN 只用远端桶。
    let (supported_efforts, default_effort) =
        if workbuddy_identity(transport).realm == WorkbuddyRealm::Global {
            workbuddy_global_effort_cap(&model, &supported_efforts, default_effort.as_deref())
        } else {
            (supported_efforts, default_effort)
        };
    inject_workbuddy_thinking(object, default_effort.as_deref());
    normalize_workbuddy_reasoning_effort(object, &supported_efforts);
    backfill_workbuddy_reasoning_content(object);
    // 两层防护，互不替代（面板 prompt.go + sanitize.go 的分工）：
    // 1. 提示词体系解决 system/developer 来源的模板句误报；
    // 2. 指纹脱敏兜底 user/assistant/tool 消息里的黑名单串。
    apply_workbuddy_prompt_policy(
        object,
        transport.provider.config.as_ref(),
        WORKBUDDY_DEGRADE_GATE.active(),
    );
    apply_workbuddy_fingerprint_sanitization(object, transport.provider.config.as_ref());
    // 最后一步对齐面板顺序（`prepareBody` → `ensureConsoleSystem`）：global 域兜底 system。
    ensure_workbuddy_global_console_system(object, workbuddy_identity(transport).realm);
}

/// 设备风控头 `X-Device-Token` 的 provider config 键。
///
/// 面板 `device_token.go` 的实现是**读桌面端 Turing Shield SDK 落盘的文件**（容器里没有
/// SDK，读不到就**优雅降级不注入**，不影响主流程）。Aether 没有 SDK 也没有那个文件，
/// 所以提供等价旋钮：操作者把 token 填进 provider config，有就注入、没有就照常发。
pub const WORKBUDDY_DEVICE_TOKEN_CONFIG_KEY: &str = "workbuddy_device_token";

/// 设备 token 的最大长度（面板 `deviceTokenFileMaxLen` = 1 KiB；超长视为异常不注入）。
const WORKBUDDY_DEVICE_TOKEN_MAX_BYTES: usize = 1024;

/// 有配置就注入 `X-Device-Token`（对话与计费两类请求都注入，面板同口径）。
fn insert_workbuddy_device_token(
    identity: &WorkbuddyIdentity,
    headers: &mut BTreeMap<String, String>,
) {
    let Some(token) = identity
        .device_token
        .as_deref()
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .filter(|value| value.len() <= WORKBUDDY_DEVICE_TOKEN_MAX_BYTES)
    else {
        return;
    };
    set_header(headers, "x-device-token", token);
}

/// 拆 WorkBuddy 响应的 `{code,msg,data}` 信封，返回**业务载荷**（面板 `doJSON` 同口径）。
///
/// 面板的 `doJSON` 在校验 `code == 0` 之后**统一返回 `env.Data`**，所以面板里所有解析器
/// 拿到的都是**已拆包**的形状。Aether 侧原本把带信封的原始 body 直接交给解析器 →
/// 真机（2026-10-15）表现为「上游 200 但解析不出任何字段」：余额响应实际是
/// `{"code":0,"msg":"OK","data":{"Response":{"Data":{"Accounts":[…]}}}}`，而解析器按面板
/// 口径找的是 `Response.Data.Accounts`（即 `data` 那一层**之内**）。
///
/// 兼容策略：`data` 存在就返回它；否则原样返回（有的端点直接返回业务对象，没有信封）。
/// **`code != 0` 的错误响应用它之前先分类**——错误码在信封层，别被拆掉。
pub fn workbuddy_unwrap_envelope(body: &Value) -> &Value {
    body.get("data").unwrap_or(body)
}

/// 计费/成长域出站的**单段 UA** 前缀（面板 `billingUA()`）。
///
/// 面板口径：`BillingHeaders`（覆盖 report / travel / balance / checkin，以及所有
/// `growthJSON` 请求）用的 UA 是**单段** `WorkBuddy/<clientVersion>`——这是官方 banner
/// 显式覆写的形态，**不带 CLI 段**；只有对话端点用三段式 chat UA。上游对 UA 敏感
/// （`/v3/config` 的 `12403` 就是例子），所以这里分开。
pub const WORKBUDDY_BILLING_USER_AGENT_PREFIX: &str = "WorkBuddy/";

/// DeepSeek 默认档位（面板 `defaultDeepSeekEffort`）。
pub const WORKBUDDY_DEFAULT_DEEPSEEK_EFFORT: &str = "high";

/// 计费/成长域的单段 UA（面板 `billingUA()`）。
///
/// 报告 §3.2 / §10.1：这一类端点用**单段** `WorkBuddy/{ver}`（官方 banner 显式覆写整串，
/// 不带 CLI 段），是「按端点类型分 UA」的另一半；两段式/三段式只用于对话端点。
///
/// ⚠️ 已知遗留：面板实现里这条不带 realm，恒用 **CN 客户端版本**（`5.5.4`）。
/// 国际实例的计费请求因此也送 CN 版本号——报告没有国际计费 UA 的真机数据，
/// 这里**刻意保持原样**（改它属于无证据的回归风险）。
pub fn workbuddy_billing_user_agent() -> String {
    aether_oauth::provider::providers::workbuddy_billing_user_agent(
        aether_oauth::provider::providers::WorkbuddyOAuthRealm::Cn,
    )
}

/// 把已插入的头族里的 `user-agent` 换成**计费域单段形态**。
///
/// 只在计费/成长域的请求上调用；对话端点保持三段式 chat UA。
pub fn apply_workbuddy_billing_user_agent(headers: &mut BTreeMap<String, String>) {
    let billing = workbuddy_billing_user_agent();
    match headers
        .iter_mut()
        .find(|(name, _)| name.eq_ignore_ascii_case("user-agent"))
    {
        Some((_, value)) => *value = billing,
        None => {
            headers.insert("user-agent".to_string(), billing);
        }
    }
}

/// global / WorkBuddy 国际版面的**产品级静态兜底档位表**（面板 `globalEffortFallback`）。
///
/// 为什么必须有：global 上游可能**不下发** `supportedEfforts`，而往 WorkBuddy 上游发
/// 不支持的档位是**非法参数 400**（面板 issue #84：`deepseek-v4.1-flash` 国际版只认
/// `high`，客户端传 `low`/`max` 必须降级到 `high`）。
///
/// 注意这张表与 CN 面**刻意不同**（同 id 在两个 realm 的档位集合不一样，例如
/// `deepseek-v4.1-flash`：CN 三档 `low/high/max`，global 仅 `high`），所以
/// **只在 global realm 生效**（CN 只用远端桶，与面板 `prepareBody` 一致）。
const WORKBUDDY_GLOBAL_EFFORT_FALLBACK: &[(&str, &[&str], Option<&str>)] = &[
    ("fast-model", &["medium"], None),
    ("balanced-model", &["medium"], None),
    ("primary-model", &["high"], None),
    ("hy4-preview-f", &["high"], Some("high")),
    ("hy3", &["low", "high"], Some("high")),
    ("deepseek-v4.1-flash", &["high"], None),
    (
        "gpt-6-astra",
        &["low", "medium", "high", "xhigh", "max"],
        Some("high"),
    ),
    (
        "gpt-5.6-sol",
        &["low", "medium", "high", "xhigh", "max"],
        Some("high"),
    ),
    (
        "gpt-5.6-terra",
        &["low", "medium", "high", "xhigh", "max"],
        Some("high"),
    ),
    (
        "gpt-5.6-luna",
        &["low", "medium", "high", "xhigh", "max"],
        Some("high"),
    ),
    ("gpt-5.5", &["low", "medium", "high", "xhigh"], Some("high")),
    ("gpt-5.4", &["low", "medium", "high", "xhigh"], Some("high")),
    ("gpt-5.3-codex", &["medium"], None),
    ("gemini-3.5-flash", &["medium"], None),
    ("glm-5.3", &["low", "high", "max"], Some("high")),
    ("glm-5.2", &["high", "xhigh"], Some("high")),
    ("kimi-k3", &["medium"], None),
    ("kimi-k2.6", &["medium"], None),
];

/// global 域的档位能力：**远端桶非空即权威**，否则落产品静态兜底表（面板 `globalEffortMap`）。
fn workbuddy_global_effort_cap(
    model: &str,
    remote_efforts: &[String],
    remote_default: Option<&str>,
) -> (Vec<String>, Option<String>) {
    if !remote_efforts.is_empty() {
        return (
            remote_efforts.to_vec(),
            remote_default.map(ToOwned::to_owned),
        );
    }
    match WORKBUDDY_GLOBAL_EFFORT_FALLBACK
        .iter()
        .find(|(id, _, _)| *id == model)
    {
        Some((_, efforts, default)) => (
            efforts.iter().map(|value| (*value).to_string()).collect(),
            default.map(ToOwned::to_owned),
        ),
        None => (Vec::new(), None),
    }
}

/// 注入上游 `prompt_cache_key`（面板 `cache_key.go`，**P0 费用优化**）。
///
/// 逆向实测（面板注释）：同一段 8k token 前缀——不带该字段 `prompt_cache_hit_tokens=0`、
/// credit≈0.34；带上则命中 7808、credit≈0.02，**费用降约 17×**。
///
/// **安全约束（硬性）**：键格式 `wb2a-<uid8>-<convHex>`，`uid8` 是账号 UID 前 8 字符——
/// 跨账号复用同一 cache key 会让上游命中**错账号**的前缀缓存、泄露对方对话，所以 uid
/// 是硬隔离因子，绝不能省。
///
/// 优先级（面板同款）：
/// 1. body 已带非空 `prompt_cache_key` → **原值保留**（客户端自知复用哪个键）；
/// 2. body 的 `conversation_id` / `conversationId` → 作会话哈希源；
/// 3. 都没有 → 用调用方给的 `conversation_id`（入站 `X-Conversation-ID`）；
/// 4. 全空 → convHex 为定值（账号内复用前缀，仍保留账号隔离段）。
pub fn apply_workbuddy_prompt_cache_key(
    transport: &GatewayProviderTransportSnapshot,
    api_format: &str,
    body: &mut Value,
    conversation_id: Option<&str>,
) -> bool {
    if !is_workbuddy_provider_transport(transport) {
        return false;
    }
    if !api_format
        .trim()
        .to_ascii_lowercase()
        .starts_with("openai:")
    {
        return false;
    }
    let Some(object) = body.as_object_mut() else {
        return false;
    };
    if object
        .get("prompt_cache_key")
        .and_then(Value::as_str)
        .is_some_and(|value| !value.is_empty())
    {
        return false;
    }
    let conversation = ["conversation_id", "conversationId"]
        .iter()
        .find_map(|key| {
            object
                .get(*key)
                .and_then(Value::as_str)
                .map(str::trim)
                .filter(|value| !value.is_empty())
        })
        .or_else(|| {
            conversation_id
                .map(str::trim)
                .filter(|value| !value.is_empty())
        })
        .unwrap_or_default()
        .to_string();
    let uid = workbuddy_identity(transport).uid.unwrap_or_default();
    object.insert(
        "prompt_cache_key".to_string(),
        Value::String(workbuddy_prompt_cache_key(&uid, &conversation)),
    );
    true
}

/// 生成 `wb2a-<uid8>-<convHex>`（面板 `buildCacheKey` 逐字口径）。
///
/// `convHex` = `sha256(uid + "|" + conversation)` 前 16 字节的 hex：同账号同会话稳定、
/// 不同会话不同；会话源为空时仍由 uid 参与哈希（跨账号绝不碰撞）。
fn workbuddy_prompt_cache_key(uid: &str, conversation: &str) -> String {
    use sha2::{Digest, Sha256};

    let uid8 = if uid.is_empty() {
        "-".to_string()
    } else {
        uid.chars().take(8).collect::<String>()
    };
    let mut hasher = Sha256::new();
    hasher.update(format!("{uid}|{conversation}").as_bytes());
    let digest = hasher.finalize();
    let conv_hex: String = digest[..16]
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect();
    format!("wb2a-{uid8}-{conv_hex}")
}

/// console 域兜底 system 的正文（面板 `ensureConsoleSystem` 逐字：`You are a helpful assistant.`）。
pub const WORKBUDDY_CONSOLE_FALLBACK_SYSTEM_PROMPT: &str = "You are a helpful assistant.";

/// DeepSeek 系模型判定：模型名以 `deepseek` 开头（不区分大小写、去空白）。
///
/// 与官方 `thinkingFormat:"deepseek"` 的口径一致；覆盖 `deepseek-v4.1-flash` /
/// `deepseek-v4-pro` / `deepseek-r1` 等变体。
fn is_workbuddy_deepseek_model(model: &str) -> bool {
    model.trim().to_ascii_lowercase().starts_with("deepseek")
}

/// 档位高低（面板 `effortRank`）：`off` < `minimal` < `low` < `medium` < `high` < `xhigh` < `max`。
fn workbuddy_effort_rank(value: &str) -> Option<i32> {
    match value.trim().to_ascii_lowercase().as_str() {
        "off" => Some(0),
        "minimal" => Some(1),
        "low" => Some(2),
        "medium" => Some(3),
        "high" => Some(4),
        "xhigh" => Some(5),
        "max" => Some(6),
        _ => None,
    }
}

/// 从 key 元数据读某模型的推理档位信息。
///
/// 形状（与 codex 把模型能力挂在 `key.upstream_metadata` 同一模式）：
/// `upstream_metadata.workbuddy.models.<模型>.{efforts|supported_efforts, default_effort}`。
/// **读不到就返回空**——与面板「目录缓存未命中一律透传」同口径（此时档位不做降级）。
fn workbuddy_reasoning_metadata(
    transport: &GatewayProviderTransportSnapshot,
    model: &str,
) -> (Vec<String>, Option<String>) {
    let Some(entry) = transport
        .key
        .upstream_metadata
        .as_ref()
        .and_then(Value::as_object)
        .and_then(|metadata| metadata.get("workbuddy"))
        .and_then(Value::as_object)
        .and_then(|bucket| bucket.get("models"))
        .and_then(Value::as_object)
        .and_then(|models| models.get(model))
        .and_then(Value::as_object)
    else {
        return (Vec::new(), None);
    };
    let efforts = ["efforts", "supported_efforts", "supportedEfforts"]
        .iter()
        .find_map(|key| entry.get(*key).and_then(Value::as_array))
        .map(|values| {
            values
                .iter()
                .filter_map(Value::as_str)
                .map(str::trim)
                .filter(|value| !value.is_empty())
                .map(ToOwned::to_owned)
                .collect::<Vec<String>>()
        })
        .unwrap_or_default();
    let default_effort = ["default_effort", "defaultEffort"]
        .iter()
        .find_map(|key| entry.get(*key).and_then(Value::as_str))
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .map(ToOwned::to_owned);
    (efforts, default_effort)
}

/// 缺 effort 档位时补默认档（面板 `ensureDeepSeekEffort`）：snake 优先、camel 兜底，
/// **已有任一 effort 就不覆盖**（显式档位只交给降级管线）。
fn ensure_workbuddy_deepseek_effort(
    object: &mut serde_json::Map<String, Value>,
    default_effort: Option<&str>,
) {
    if object.contains_key("reasoning_effort") || object.contains_key("reasoningEffort") {
        return;
    }
    let effort = default_effort
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .unwrap_or(WORKBUDDY_DEFAULT_DEEPSEEK_EFFORT);
    object.insert(
        "reasoning_effort".to_string(),
        Value::String(effort.to_string()),
    );
}

/// 注入 DeepSeek 思维链开关（面板 `injectThinking`），**仅 deepseek 系模型**：
/// - 显式 `thinking.type` 非空 → 不改 type；`disabled` 时删掉两个 effort 字段；
///   `enabled` 缺 effort 时补默认档；
/// - 无 `thinking` / type 为空 → 注入 `enabled` 并补默认档（已有 effort 不覆盖）。
pub fn inject_workbuddy_thinking(
    object: &mut serde_json::Map<String, Value>,
    default_effort: Option<&str>,
) {
    let model = object
        .get("model")
        .and_then(Value::as_str)
        .unwrap_or_default();
    if !is_workbuddy_deepseek_model(model) {
        return;
    }
    let explicit = object
        .get("thinking")
        .and_then(Value::as_object)
        .and_then(|thinking| thinking.get("type"))
        .and_then(Value::as_str)
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .map(ToOwned::to_owned);
    if let Some(explicit) = explicit {
        if explicit.eq_ignore_ascii_case("disabled") {
            object.remove("reasoning_effort");
            object.remove("reasoningEffort");
            return;
        }
        ensure_workbuddy_deepseek_effort(object, default_effort);
        return;
    }
    match object.get_mut("thinking").and_then(Value::as_object_mut) {
        Some(thinking) => {
            thinking.insert("type".to_string(), Value::String("enabled".to_string()));
        }
        None => {
            object.insert("thinking".to_string(), json!({"type": "enabled"}));
        }
    }
    ensure_workbuddy_deepseek_effort(object, default_effort);
}

/// 按模型支持的档位降级 `reasoning_effort`（面板 `normalizeReasoningEffort`）。
///
/// 规则（`supported` 为空即整段跳过，与面板「模型未缓存一律透传」一致）：
/// - 请求档位在支持列表里 → 原样透传；
/// - 否则取「**≤ 请求档的最高支持档**」（降级）；
/// - 支持档全部高于请求档 → 取**最低支持档**（偏离最小）；
/// - 未知档位 / 未携带字段 → 透传。
pub fn normalize_workbuddy_reasoning_effort(
    object: &mut serde_json::Map<String, Value>,
    supported: &[String],
) {
    if supported.is_empty() {
        return;
    }
    let key = if object.contains_key("reasoning_effort") {
        "reasoning_effort"
    } else if object.contains_key("reasoningEffort") {
        "reasoningEffort"
    } else {
        return;
    };
    let Some(requested) = object
        .get(key)
        .and_then(Value::as_str)
        .map(str::trim)
        .map(ToOwned::to_owned)
    else {
        return;
    };
    let Some(requested_rank) = workbuddy_effort_rank(&requested) else {
        return;
    };
    let mut best: Option<(&str, i32)> = None;
    for candidate in supported {
        let Some(rank) = workbuddy_effort_rank(candidate) else {
            continue;
        };
        if rank <= requested_rank && best.is_none_or(|(_, best_rank)| rank > best_rank) {
            best = Some((candidate.as_str(), rank));
        }
    }
    let replacement = match best {
        Some((candidate, _)) => {
            if candidate.eq_ignore_ascii_case(requested.trim()) {
                return;
            }
            candidate.to_string()
        }
        None => {
            // 支持档全部高于请求档 → 取最低支持档（偏离最小）。
            let Some((lowest, _)) = supported
                .iter()
                .filter_map(|candidate| {
                    workbuddy_effort_rank(candidate).map(|rank| (candidate.as_str(), rank))
                })
                .min_by_key(|(_, rank)| *rank)
            else {
                return;
            };
            lowest.to_string()
        }
    };
    object.insert(key.to_string(), Value::String(replacement));
}

/// DeepSeek 多轮一致性：给每条 assistant 补齐 `reasoning_content` 并镜像 `reasoning`
/// （面板 `backfillReasoningContent`）。
///
/// 门控（对齐官方 `thinkingEnabled || hasTrace`）：`thinking.type == enabled` 或有任何
/// reasoning 痕迹才动手；**非 deepseek 一律零改动**。补齐规则：`reasoning_content` 已是
/// 字符串则不覆盖；否则复制 `reasoning`；两者皆无补空串。镜像规则：`reasoning` 已非空则
/// 不动，否则写 `reasoning_content` 的值，皆空时写**单个空格**（上游只校验 `len > 0`）。
pub fn backfill_workbuddy_reasoning_content(object: &mut serde_json::Map<String, Value>) {
    let model = object
        .get("model")
        .and_then(Value::as_str)
        .unwrap_or_default();
    if !is_workbuddy_deepseek_model(model) {
        return;
    }
    let thinking_enabled = object
        .get("thinking")
        .and_then(Value::as_object)
        .and_then(|thinking| thinking.get("type"))
        .and_then(Value::as_str)
        .is_some_and(|value| value.trim().eq_ignore_ascii_case("enabled"));
    let Some(messages) = object.get_mut("messages").and_then(Value::as_array_mut) else {
        return;
    };
    if messages.is_empty() {
        return;
    }
    let has_trace = messages.iter().any(|message| {
        let Some(message) = message.as_object() else {
            return false;
        };
        message
            .get("reasoning")
            .and_then(Value::as_str)
            .is_some_and(|value| !value.is_empty())
            || message.contains_key("reasoning_content")
    });
    if !thinking_enabled && !has_trace {
        return;
    }
    for message in messages.iter_mut() {
        let Some(message) = message.as_object_mut() else {
            continue;
        };
        if message.get("role").and_then(Value::as_str) != Some("assistant") {
            continue;
        }
        let existing_reasoning = message
            .get("reasoning")
            .and_then(Value::as_str)
            .map(ToOwned::to_owned);
        let reasoning_content = match message.get("reasoning_content").and_then(Value::as_str) {
            Some(existing) => existing.to_string(),
            None => match existing_reasoning {
                Some(reasoning) => {
                    message.insert(
                        "reasoning_content".to_string(),
                        Value::String(reasoning.clone()),
                    );
                    reasoning
                }
                None => {
                    message.insert(
                        "reasoning_content".to_string(),
                        Value::String(String::new()),
                    );
                    String::new()
                }
            },
        };
        if message
            .get("reasoning")
            .and_then(Value::as_str)
            .is_some_and(|value| !value.is_empty())
        {
            continue;
        }
        let mirror = if reasoning_content.is_empty() {
            " ".to_string()
        } else {
            reasoning_content
        };
        message.insert("reasoning".to_string(), Value::String(mirror));
    }
}

/// tool 配对三步（面板 `tool_pairing.go`）：**合并 → 重排 → 清孤儿**，顺序不能换。
///
/// 背景（面板注释）：OpenAI 兼容协议要求带 `tool_calls` 的 assistant 之后紧跟它自己的
/// `role: tool` 结果；缺任一侧、或中间插了别的消息，上游都会 **HTTP 400 拒整单**——
/// 而客户端把失败的工具调用持久化进历史后，**之后每条消息都会 400，整条会话报废**
/// （换号也无效，因为不是账号问题）。网关是最后一道防线：宁可丢一轮工具上下文，
/// 也好过整条会话死亡。
///
/// 三步各自的作用：
/// 1. **合并**（`mergeAdjacentToolCalls`）：把**背靠背**的 `assistant.tool_calls` 合成一条
///    （部分 agent 客户端回放历史时把同一批并行调用拆成多条紧邻 assistant，上游判
///    `11148 tool_call_sequence_broken`）。另有一条反向形态：纯正文 assistant 紧跟
///    「带 tool_calls 但无正文」的 assistant → 把正文折进前一条。
/// 2. **重排**（`repackToolResultBlocks`）：把插在 assistant 与同批 tool 结果之间的非 tool
///    消息（如 Codex 的 `image_resize_notice`）挪到整组之后，**只调顺序不改内容**。
/// 3. **清孤儿**（`cleanupOrphanToolCalls`）：按 id **两侧对称裁剪**——只留有结果的调用、
///    只留调用被保留的结果；`function.name` 为空的调用一律不保留（上游判
///    `11133 model_param_invalid`，带不带结果都拒）。
pub fn normalize_workbuddy_tool_pairing(object: &mut serde_json::Map<String, Value>) {
    let Some(Value::Array(messages)) = object.remove("messages") else {
        return;
    };
    let (messages, _) = merge_workbuddy_adjacent_tool_calls(messages);
    let (messages, _) = repack_workbuddy_tool_result_blocks(messages);
    let (messages, _) = cleanup_workbuddy_orphan_tool_calls(messages);
    object.insert("messages".to_string(), Value::Array(messages));
}

/// `content` 是否为空（缺失 / null / 空串 / 空数组）。
///
/// 空数组也算空：有客户端把「没有正文」发成 `content: []`，漏了它会漏合并 →
/// 正是第 1 步要挡的形态。非空数组仍视为有内容（宁可漏合并，也不丢内容）。
fn workbuddy_empty_content(value: Option<&Value>) -> bool {
    match value {
        None | Some(Value::Null) => true,
        Some(Value::String(text)) => text.is_empty(),
        Some(Value::Array(items)) => items.is_empty(),
        _ => false,
    }
}

/// `tool_calls[]` 单项的 `function.name` 是否为空白。
///
/// 只在 `function` 对象与 `name` 字段**都存在**且为空白时判真；缺字段判假
/// （历史报文里有不带 `function` 的占位条目，上游不因此拒参，不扩大打击面）。
fn workbuddy_tool_call_name_empty(call: &serde_json::Map<String, Value>) -> bool {
    let Some(function) = call.get("function").and_then(Value::as_object) else {
        return false;
    };
    let Some(name) = function.get("name").and_then(Value::as_str) else {
        return false;
    };
    name.trim().is_empty()
}

/// 把 `src` 的 `reasoning_content` 并入 `dst`（两边都有则换行拼接）。
fn workbuddy_merge_reasoning_content(
    dst: &mut serde_json::Map<String, Value>,
    src: &serde_json::Map<String, Value>,
) {
    let Some(incoming) = src
        .get("reasoning_content")
        .and_then(Value::as_str)
        .filter(|value| !value.is_empty())
    else {
        return;
    };
    let merged = match dst
        .get("reasoning_content")
        .and_then(Value::as_str)
        .filter(|value| !value.is_empty())
    {
        Some(previous) => format!("{previous}\n{incoming}"),
        None => incoming.to_string(),
    };
    dst.insert("reasoning_content".to_string(), Value::String(merged));
}

/// 第 1 步：合并背靠背的 `assistant.tool_calls`（含反向形态）。
fn merge_workbuddy_adjacent_tool_calls(messages: Vec<Value>) -> (Vec<Value>, bool) {
    if messages.len() < 2 {
        return (messages, false);
    }
    let mut out: Vec<Value> = Vec::with_capacity(messages.len());
    let mut changed = false;
    for message in messages {
        let is_assistant = message.get("role").and_then(Value::as_str) == Some("assistant");
        if is_assistant && !out.is_empty() {
            let Some(current) = message.as_object() else {
                out.push(message);
                continue;
            };
            let has_calls = current
                .get("tool_calls")
                .and_then(Value::as_array)
                .is_some_and(|calls| !calls.is_empty());
            // 形态一：本条是「带 tool_calls 且无正文」的 assistant → 并入上一条同形态消息。
            if has_calls && workbuddy_empty_content(current.get("content")) {
                if let Some(previous) = out.last_mut().and_then(Value::as_object_mut) {
                    if previous.get("role").and_then(Value::as_str) == Some("assistant")
                        && previous
                            .get("tool_calls")
                            .and_then(Value::as_array)
                            .is_some_and(|calls| !calls.is_empty())
                    {
                        let extra = current
                            .get("tool_calls")
                            .and_then(Value::as_array)
                            .cloned()
                            .unwrap_or_default();
                        if let Some(Value::Array(previous_calls)) = previous.get_mut("tool_calls") {
                            previous_calls.extend(extra);
                        }
                        workbuddy_merge_reasoning_content(previous, current);
                        changed = true;
                        continue;
                    }
                }
            }
            // 形态二（反向）：本条是「纯字符串正文、无 tool_calls」的 assistant，上一条是
            // 「带 tool_calls 且无正文」的 assistant → 把正文折进上一条。
            if !current.contains_key("tool_calls") {
                if let Some(text) = current
                    .get("content")
                    .and_then(Value::as_str)
                    .filter(|text| !text.is_empty())
                {
                    if let Some(previous) = out.last_mut().and_then(Value::as_object_mut) {
                        if previous.get("role").and_then(Value::as_str) == Some("assistant")
                            && previous
                                .get("tool_calls")
                                .and_then(Value::as_array)
                                .is_some_and(|calls| !calls.is_empty())
                            && workbuddy_empty_content(previous.get("content"))
                        {
                            previous.insert("content".to_string(), Value::String(text.to_string()));
                            workbuddy_merge_reasoning_content(previous, current);
                            changed = true;
                            continue;
                        }
                    }
                }
            }
        }
        out.push(message);
    }
    if !changed {
        // 未改动时 `out` 与原顺序、内容完全一致（这里只能返回重建结果，原 vec 已被消费）。
        (out, false)
    } else {
        (out, true)
    }
}

/// 第 2 步：把插在 assistant 与同批 tool 结果之间的非 tool 消息挪到整组之后。
fn repack_workbuddy_tool_result_blocks(messages: Vec<Value>) -> (Vec<Value>, bool) {
    if messages.len() < 3 {
        return (messages, false);
    }
    let mut out: Vec<Value> = Vec::with_capacity(messages.len());
    let mut changed = false;
    let mut index = 0;
    while index < messages.len() {
        let Some(message) = messages[index].as_object() else {
            out.push(messages[index].clone());
            index += 1;
            continue;
        };
        let is_group_head = message.get("role").and_then(Value::as_str) == Some("assistant")
            && message
                .get("tool_calls")
                .and_then(Value::as_array)
                .is_some_and(|calls| !calls.is_empty());
        if !is_group_head {
            out.push(messages[index].clone());
            index += 1;
            continue;
        }
        let want: std::collections::BTreeSet<String> = message
            .get("tool_calls")
            .and_then(Value::as_array)
            .into_iter()
            .flatten()
            .filter_map(|call| call.get("id").and_then(Value::as_str))
            .filter(|id| !id.is_empty())
            .map(ToOwned::to_owned)
            .collect();
        out.push(messages[index].clone());
        index += 1;
        let mut results: Vec<Value> = Vec::new();
        let mut between: Vec<Value> = Vec::new();
        let mut saw_non_tool = false;
        while index < messages.len() {
            let Some(candidate) = messages[index].as_object() else {
                break;
            };
            let role = candidate.get("role").and_then(Value::as_str).unwrap_or("");
            if role == "tool" {
                let id = candidate
                    .get("tool_call_id")
                    .and_then(Value::as_str)
                    .unwrap_or("");
                if !want.contains(id) {
                    break;
                }
                results.push(messages[index].clone());
                if saw_non_tool {
                    changed = true;
                }
                index += 1;
                continue;
            }
            if results.is_empty() {
                // assistant 后没有结果：交给第 3 步清孤儿。
                break;
            }
            // 下一组 assistant.tool_calls 是新组头，绝不能当插入物吞掉（否则它那批结果
            // 永远得不到重排）：交还外层循环。
            if role == "assistant"
                && candidate
                    .get("tool_calls")
                    .and_then(Value::as_array)
                    .is_some_and(|calls| !calls.is_empty())
            {
                break;
            }
            between.push(messages[index].clone());
            saw_non_tool = true;
            index += 1;
        }
        out.extend(results);
        out.extend(between);
    }
    if !changed {
        (messages, false)
    } else {
        (out, true)
    }
}

/// 第 3 步：按 id 两侧对称裁剪，剔除无法配对的 tool 调用与结果。
fn cleanup_workbuddy_orphan_tool_calls(messages: Vec<Value>) -> (Vec<Value>, bool) {
    if messages.is_empty() {
        return (messages, false);
    }
    let mut call_ids: std::collections::BTreeSet<String> = std::collections::BTreeSet::new();
    let mut result_ids: std::collections::BTreeSet<String> = std::collections::BTreeSet::new();
    let mut name_bad_ids: std::collections::BTreeSet<String> = std::collections::BTreeSet::new();
    let mut has_traffic = false;
    for message in &messages {
        let Some(message) = message.as_object() else {
            continue;
        };
        match message.get("role").and_then(Value::as_str) {
            Some("tool") => {
                if let Some(id) = message
                    .get("tool_call_id")
                    .and_then(Value::as_str)
                    .filter(|id| !id.is_empty())
                {
                    result_ids.insert(id.to_string());
                    has_traffic = true;
                }
            }
            Some("assistant") => {
                if let Some(calls) = message.get("tool_calls").and_then(Value::as_array) {
                    for call in calls {
                        let Some(call) = call.as_object() else {
                            continue;
                        };
                        if let Some(id) = call
                            .get("id")
                            .and_then(Value::as_str)
                            .filter(|id| !id.is_empty())
                        {
                            call_ids.insert(id.to_string());
                            if workbuddy_tool_call_name_empty(call) {
                                name_bad_ids.insert(id.to_string());
                            }
                            has_traffic = true;
                        }
                    }
                }
            }
            _ => {}
        }
    }
    if !has_traffic {
        return (messages, false);
    }
    let keep_calls: std::collections::BTreeSet<String> = call_ids
        .iter()
        .filter(|id| !name_bad_ids.contains(*id) && result_ids.contains(*id))
        .cloned()
        .collect();

    let mut changed = false;
    let mut kept: Vec<Value> = Vec::with_capacity(messages.len());
    for mut message in messages {
        let mut keep = true;
        if let Some(object) = message.as_object_mut() {
            match object.get("role").and_then(Value::as_str) {
                Some("assistant") => {
                    if let Some(calls) = object.get("tool_calls").and_then(Value::as_array) {
                        if !calls.is_empty() {
                            let trimmed: Vec<Value> = calls
                                .iter()
                                .filter(|call| {
                                    call.get("id")
                                        .and_then(Value::as_str)
                                        .is_some_and(|id| keep_calls.contains(id))
                                })
                                .cloned()
                                .collect();
                            if trimmed.len() != calls.len() {
                                changed = true;
                                if trimmed.is_empty() {
                                    object.remove("tool_calls");
                                } else {
                                    object.insert("tool_calls".to_string(), Value::Array(trimmed));
                                }
                            }
                        }
                    }
                }
                Some("tool") => {
                    let id = object
                        .get("tool_call_id")
                        .and_then(Value::as_str)
                        .unwrap_or("");
                    if !keep_calls.contains(id) {
                        changed = true;
                        keep = false;
                    }
                }
                _ => {}
            }
        }
        if keep {
            kept.push(message);
        }
    }
    if !changed {
        // 未改动时 `kept` 与原顺序、内容完全一致（原 vec 已被消费）。
        (kept, false)
    } else {
        (kept, true)
    }
}

/// GPT 系上游接受的 `max_tokens` 下限（面板 `gptMinMaxTokens`）。
pub const WORKBUDDY_GPT_MIN_MAX_TOKENS: i64 = 16;

/// 把 GPT 系模型过小的 `max_tokens` 抬到下限（面板 `clampGPTMinMaxTokens`）。
///
/// 只认模型名里含 `gpt-` 的；非数值 / 缺字段一律不动。
fn clamp_workbuddy_gpt_max_tokens(object: &mut serde_json::Map<String, Value>) {
    let model = object
        .get("model")
        .and_then(Value::as_str)
        .unwrap_or_default()
        .to_ascii_lowercase();
    if !model.contains("gpt-") {
        return;
    }
    let Some(value) = object.get("max_tokens").and_then(Value::as_i64) else {
        return;
    };
    if value < WORKBUDDY_GPT_MIN_MAX_TOKENS {
        object.insert(
            "max_tokens".to_string(),
            json!(WORKBUDDY_GPT_MIN_MAX_TOKENS),
        );
    }
}

/// 缺省补 `stream_options.include_usage = true`（面板 D7）。
///
/// 官方 CLI 流式请求必发该字段，上游据此在**末帧**返回 usage；缺了就没有用量数据
/// （Aether 侧表现为该 provider 的用量统计为空）。**显式带则绝不覆盖**。
fn ensure_workbuddy_stream_options(object: &mut serde_json::Map<String, Value>) {
    if object.contains_key("stream_options") {
        return;
    }
    object.insert("stream_options".to_string(), json!({"include_usage": true}));
}

/// 递归把 JSON-schema 里的 `\_` 还原成 `_`（面板 `normalizeToolPatterns`）。
///
/// `pattern` 值直接改；`patternProperties` 的**键**也是正则、且 map 键不能原地改，
/// 命中时重建该层。上游对这类转义处理不当会 400。
fn unescape_workbuddy_tool_patterns(object: &mut serde_json::Map<String, Value>) {
    let Some(tools) = object.get_mut("tools").and_then(Value::as_array_mut) else {
        return;
    };
    for tool in tools.iter_mut() {
        let Some(tool) = tool.as_object_mut() else {
            continue;
        };
        if let Some(function) = tool.get_mut("function").and_then(Value::as_object_mut) {
            if let Some(parameters) = function.get_mut("parameters") {
                unescape_workbuddy_pattern_escapes(parameters);
            }
        }
        if let Some(parameters) = tool.get_mut("parameters") {
            unescape_workbuddy_pattern_escapes(parameters);
        }
    }
}

fn unescape_workbuddy_pattern_escapes(node: &mut Value) {
    match node {
        Value::Object(map) => {
            if let Some(Value::String(pattern)) = map.get_mut("pattern") {
                if pattern.contains(r"\_") {
                    *pattern = pattern.replace(r"\_", "_");
                }
            }
            if let Some(Value::Object(properties)) = map.get_mut("patternProperties") {
                if properties.keys().any(|key| key.contains(r"\_")) {
                    let rebuilt: serde_json::Map<String, Value> = properties
                        .iter()
                        .map(|(key, value)| (key.replace(r"\_", "_"), value.clone()))
                        .collect();
                    *properties = rebuilt;
                }
            }
            for value in map.values_mut() {
                unescape_workbuddy_pattern_escapes(value);
            }
        }
        Value::Array(items) => {
            for item in items.iter_mut() {
                unescape_workbuddy_pattern_escapes(item);
            }
        }
        _ => {}
    }
}

/// global 域兜底 system 注入（面板 `ensureConsoleSystem`，吸收 PR #45）。
///
/// console 域（global realm）上游对**首条消息不是 system** 的请求会以 `code 11-128`
/// 拦截；在 messages 最前补一条 fallback system 即可。规则逐条对齐面板：
/// - **仅 global**：CN 现状不动；
/// - 首条已是 `system`（大小写/空白容差）→ 不重复注入；
/// - `messages` 缺失 / 为空 / 首条不是对象 → 不动（坏 body 不在这里二次错误化）。
pub fn ensure_workbuddy_global_console_system(
    object: &mut serde_json::Map<String, Value>,
    realm: WorkbuddyRealm,
) {
    if realm != WorkbuddyRealm::Global {
        return;
    }
    let Some(messages) = object.get_mut("messages").and_then(Value::as_array_mut) else {
        return;
    };
    if messages.is_empty() {
        return;
    }
    let first_is_system = messages
        .first()
        .and_then(Value::as_object)
        .and_then(|message| message.get("role"))
        .and_then(Value::as_str)
        .is_some_and(|role| role.trim().eq_ignore_ascii_case("system"));
    if first_is_system {
        return;
    }
    messages.insert(
        0,
        json!({
            "role": "system",
            "content": WORKBUDDY_CONSOLE_FALLBACK_SYSTEM_PROMPT,
        }),
    );
}

/// 内置默认系统提示词（移植自面板 `internal/prompt/defaultprompt.md`）。
///
/// 为什么要有它：客户端（Claude Code / Codex 形态）注入的 system 提示词是固定
/// 模板句，上游内容审核按**逐字精确匹配**整单拦截（`400 blocked by security
/// policy` / `11-128`）。用网关自有提示词替换掉，是从源头消灭这类误报。
pub const WORKBUDDY_DEFAULT_SYSTEM_PROMPT: &str = r#"# 系统提示词

你是一名工程助手，帮助用户完成软件工程任务。以下原则指导你的行为。

## 核心立场
- 你的价值是让用户的工程目标更快达成，而非展示你自己的能力边界。
- 当用户的方向有更优解时，直接指出并给出替代方案；不必逢迎。
- 对不确定的事保持诚实：宁可说"我不确定，需要验证"，也不编造看似合理的答案。

## 语言与风格
- 跟随用户的提问语言：用户用中文则用中文，用英文则用英文。
- 简洁直接，不说废话；不用客套开场与总结，不重复用户已说过的内容。
- 技术术语精确，不为了通俗而牺牲准确性。

## 工程行为
- 先看代码再动手：理解上下文、既有模式与约定，避免破坏一致性。
- 最小改动：只改必要的部分，不做无关重构或风格统一。
- 改动后验证闭环：运行测试或构建确认结果，不假设"应该没问题"。
- 遇到不确定的边界，先确认再执行，不擅自扩大范围或假设需求。
- 修改共享代码前，先看它被谁依赖，避免连锁影响。

## 任务分解
- 复杂任务先拆步骤，按依赖顺序推进；每步可独立验证。
- 给出改动清单与影响面，让用户能判断是否继续。
- 失败时如实报告原因，给出下一步建议，不掩盖、不粉饰。

## 输出格式
- 用 Markdown 组织结构。
- 代码块标注语言（```go / ```bash / ```json 等）。
- 复杂度与任务匹配：简单问题一句话答完，复杂问题分步骤说明。
- 关键决策给出依据，不堆砌理由；不写你已经知道答案却还要绕的解释。
- 引用代码时用 `file:line` 形式，便于用户跳转。

## 边界
- 不臆造未给定的 API、字段或行为；不确定时如实说明并给出验证路径。
- 安全敏感操作（删除、覆盖、发布）先确认，除非已被明确授权。
- 错误与失败如实报告，不为了让结果"好看"而省略或美化。
- 保留对方案的质疑空间：如果用户的方案有明显问题，指出并提供更优替代。"#;

/// 降级提示词：被上游内容策略拦过之后用来替换客户端 system 的**极简中性**提示词
/// （移植自面板 `prompt.Degraded`）。
///
/// 为什么要有它：客户端注入的固定模板句被上游逐字比对拦掉时，把 system 换成这句
/// 就能绕开误报；它不改变用户指令的合法性语义，只是误报处理，不是对抗框架。
pub const WORKBUDDY_DEGRADED_SYSTEM_PROMPT: &str = "You are a helpful assistant. Respond in the user's language, follow the user's instructions, and be direct and concise.";

/// 内容策略拦截关键词（大小写不敏感子串匹配，移植自面板 `contentBlockedMarkers`）。
///
/// 命中就是**误报**信号：账号本身健康（没欠费、没限流、session 没死），所以只降级重试，
/// 不罚账号。
///
/// 判定走完整分类器（`failure::classify_workbuddy_failure`）而不是直接比字符串：
/// 面板的分类**顺序**本身就是语义——例如「429 + 审核文案」必须先按限流处理，
/// 否则等于把限流号当成内容误报去降级。
/// 上游响应是否属于「内容策略拦截」（HTTP >= 400 + 审核文案）。
pub fn is_workbuddy_content_blocked(status_code: u16, body_text: Option<&str>) -> bool {
    failure::classify_workbuddy_failure(status_code, body_text)
        == failure::WorkbuddyFailureKind::ContentBlocked
}

/// 降级闸门：被内容策略拦过之后，`append` / `passthrough` 两种模式改用极简中性提示词，
/// 直到**次日 00:00 CST** 重置（面板 `degradeGate` 同款状态机：进程内、重启清零、
/// 降级期内再次触发**不续期**——保持最早触发点的重置时刻）。
#[derive(Debug, Default)]
pub struct WorkbuddyDegradeGate {
    until_unix_secs: AtomicU64,
}

impl WorkbuddyDegradeGate {
    pub const fn new() -> Self {
        Self {
            until_unix_secs: AtomicU64::new(0),
        }
    }

    /// 给定时刻是否处于降级期。
    pub fn active_at(&self, now_unix_secs: u64) -> bool {
        self.until_unix_secs.load(Ordering::Relaxed) > now_unix_secs
    }

    /// 触发降级（到次日 00:00 CST）。已在降级期内不续期。
    pub fn trigger_at(&self, now_unix_secs: u64) {
        let current = self.until_unix_secs.load(Ordering::Relaxed);
        if current > now_unix_secs {
            return;
        }
        self.until_unix_secs.store(
            next_cst_midnight_unix_secs(now_unix_secs),
            Ordering::Relaxed,
        );
    }

    /// 当前是否处于降级期。
    pub fn active(&self) -> bool {
        self.active_at(unix_now_secs())
    }

    /// 以当前时刻触发降级。
    pub fn trigger(&self) {
        self.trigger_at(unix_now_secs());
    }

    /// 清空（只给测试用，避免全局闸门污染同进程的其它用例）。
    #[cfg(test)]
    pub fn clear(&self) {
        self.until_unix_secs.store(0, Ordering::Relaxed);
    }
}

/// 进程内降级闸门（与面板一样是进程级状态：多实例网关各自降级，可接受）。
static WORKBUDDY_DEGRADE_GATE: WorkbuddyDegradeGate = WorkbuddyDegradeGate::new();

pub fn workbuddy_degrade_gate() -> &'static WorkbuddyDegradeGate {
    &WORKBUDDY_DEGRADE_GATE
}

/// 触发降级期（供 gateway 在识别到内容策略拦截后调用）。
pub fn trigger_workbuddy_degrade_window() {
    WORKBUDDY_DEGRADE_GATE.trigger();
}

/// 次日 00:00 **CST（UTC+8）** 的 unix 秒。
///
/// 用固定 +08:00 偏移计算，不依赖宿主机时区（容器时区不确定）；边界与面板一致：
/// 23:59 → 几秒后；恰好 00:00 → 次日 00:00。
pub fn next_cst_midnight_unix_secs(now_unix_secs: u64) -> u64 {
    const CST_OFFSET_SECS: u64 = 8 * 60 * 60;
    const DAY_SECS: u64 = 24 * 60 * 60;
    let cst = now_unix_secs + CST_OFFSET_SECS;
    let day_start = cst - (cst % DAY_SECS);
    // `day_start + DAY_SECS` 一定 > cst（含 cst 恰好是 00:00 的情况）。
    (day_start + DAY_SECS) - CST_OFFSET_SECS
}

fn unix_now_secs() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|duration| duration.as_secs())
        .unwrap_or_default()
}

/// 观察一次上游响应：若这是本 provider 的计划且被内容策略拦了，触发降级期。
///
/// 返回 `true` 表示本次调用触发了降级期。
pub fn observe_workbuddy_upstream_failure(
    provider_request_headers: Option<&Value>,
    status_code: u16,
    body_text: Option<&str>,
) -> bool {
    if !has_workbuddy_internal_marker(provider_request_headers) {
        return false;
    }
    if !is_workbuddy_content_blocked(status_code, body_text) {
        return false;
    }
    WORKBUDDY_DEGRADE_GATE.trigger();
    true
}

/// 出站头里是否带 workbuddy 内部标记（大小写不敏感，值必须是 "1"）。
pub fn has_workbuddy_internal_marker(headers: Option<&Value>) -> bool {
    headers.and_then(Value::as_object).is_some_and(|headers| {
        headers.iter().any(|(name, value)| {
            name.eq_ignore_ascii_case(WORKBUDDY_INTERNAL_HEADER)
                && value.as_str().map(str::trim) == Some("1")
        })
    })
}

/// 同上，但直接吃执行计划里的出站头 map（`ExecutionPlan.headers` 的形态），
/// 省掉为判定而构造一次 JSON。
pub fn has_workbuddy_internal_header_map(headers: &BTreeMap<String, String>) -> bool {
    headers.iter().any(|(name, value)| {
        name.eq_ignore_ascii_case(WORKBUDDY_INTERNAL_HEADER) && value.trim() == "1"
    })
}

/// 执行路径形态的上游失败观察：`ExecutionPlan.headers` + 状态码 + 响应正文。
///
/// 供 gateway 的执行路径调用（同步与流式的失败分类处各一处）——判定全在本 crate，
/// gateway 只传数据（架构守卫禁止在 gateway 里内联 provider 类型判断）。
pub fn observe_workbuddy_upstream_failure_for_header_map(
    headers: &BTreeMap<String, String>,
    status_code: u16,
    body_text: Option<&str>,
) -> bool {
    observe_workbuddy_upstream_failure_for_header_map_with_gate(
        &WORKBUDDY_DEGRADE_GATE,
        headers,
        status_code,
        body_text,
    )
}

/// 同上，但吃一个显式闸门——单测用本地闸门，避免污染同进程的其它用例
/// （全局闸门是进程级状态，测试并行跑，碰它就会让别的用例看到降级期）。
pub fn observe_workbuddy_upstream_failure_for_header_map_with_gate(
    gate: &WorkbuddyDegradeGate,
    headers: &BTreeMap<String, String>,
    status_code: u16,
    body_text: Option<&str>,
) -> bool {
    if !has_workbuddy_internal_header_map(headers) {
        return false;
    }
    if !is_workbuddy_content_blocked(status_code, body_text) {
        return false;
    }
    gate.trigger();
    true
}

/// 提示词模式（provider `config.workbuddy_prompt_mode`）。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum WorkbuddyPromptMode {
    /// 删掉全部 system / developer，头部插入一条网关提示词（默认，面板同款）。
    Custom,
    /// 在开头连续的 system / developer 之后插入一条网关提示词，既有消息逐字不动。
    Append,
    /// 原样透传客户端 system（不解决模板句误报，只给「我就要自己的提示词」用）。
    Passthrough,
}

impl WorkbuddyPromptMode {
    fn parse(value: Option<&Value>) -> Self {
        match value
            .and_then(Value::as_str)
            .map(|value| value.trim().to_ascii_lowercase())
            .as_deref()
        {
            Some("append") => Self::Append,
            Some("passthrough") => Self::Passthrough,
            // custom 与未知值都按 custom：与面板「空 = custom」同口径。
            _ => Self::Custom,
        }
    }
}

/// 提示词改写：`config.workbuddy_prompt_mode` + `config.workbuddy_prompt_text`。
///
/// `degrade_active` 是「本进程刚被上游内容策略拦过」的闸门状态（见 [`WorkbuddyDegradeGate`]）。
/// 裁决顺序照面板 `handler.go`：
/// 1. `custom` → 一律用网关提示词替换（客户端指纹已经不在了，降级无从叠加）；
/// 2. `append` 且**未**降级 → 在开头 system/developer 块之后追加；
/// 3. `passthrough` 且**未**降级 → 原样透传；
/// 4. `append` / `passthrough` 且**已**降级 → 换成极简中性提示词。
///
/// 第 4 条是关键的取舍：带着指纹原文重试是**确定性再撞墙**，所以降级期里
/// `append` 会退化成「替换」，这是面板 issue #129 的设计结论。
fn apply_workbuddy_prompt_policy(
    object: &mut serde_json::Map<String, Value>,
    config: Option<&Value>,
    degrade_active: bool,
) {
    let mode =
        WorkbuddyPromptMode::parse(config.and_then(|value| value.get("workbuddy_prompt_mode")));
    if mode == WorkbuddyPromptMode::Passthrough && !degrade_active {
        return;
    }
    let prompt = if degrade_active && mode != WorkbuddyPromptMode::Custom {
        WORKBUDDY_DEGRADED_SYSTEM_PROMPT.to_string()
    } else {
        config
            .and_then(|value| value.get("workbuddy_prompt_text"))
            .and_then(Value::as_str)
            .map(str::trim)
            .filter(|value| !value.is_empty())
            .unwrap_or(WORKBUDDY_DEFAULT_SYSTEM_PROMPT)
            .to_string()
    };
    let Some(messages) = object.get_mut("messages").and_then(Value::as_array_mut) else {
        return;
    };

    match mode {
        // 未降级的 append：只在开头追加，客户端 system 逐字保留。
        WorkbuddyPromptMode::Append if !degrade_active => {
            let leading = messages
                .iter()
                .take_while(|message| {
                    message
                        .get("role")
                        .and_then(Value::as_str)
                        .is_some_and(is_system_like_role)
                })
                .count();
            messages.insert(
                leading,
                serde_json::json!({"role": "system", "content": prompt}),
            );
        }
        // 其余一律是「替换」：custom 本来如此；passthrough / append 在**降级期**退化为替换
        // （见函数文档第 4 条：带着指纹原文重试是确定性再撞墙）。
        _ => replace_system_messages(messages, &prompt),
    }
}

/// 删除全部 system / developer 消息，在头部插入一条提示词（面板 `prompt.Rewrite`）。
fn replace_system_messages(messages: &mut Vec<Value>, prompt: &str) {
    messages.retain(|message| {
        !message
            .get("role")
            .and_then(Value::as_str)
            .is_some_and(is_system_like_role)
    });
    messages.insert(0, serde_json::json!({"role": "system", "content": prompt}));
}

fn is_system_like_role(role: &str) -> bool {
    let role = role.trim();
    role.eq_ignore_ascii_case("system") || role.eq_ignore_ascii_case("developer")
}

/// 指纹脱敏（`config.workbuddy_sanitize_fingerprints`，默认开）。
///
/// 逐条对齐面板 `sanitize.go`（**以字节码点为准**，见下面的常量注释）：
/// 先跑**模板句改写表**（每句只改一个词，语义不变），再结构化剥离 header 键值段与
/// `cc_*` 尾随键值，最后把残留裸键名换成同形变体。
///
/// 为什么必须逐字对齐：上游内容审核是**逐字精确匹配**（非语义审核），一字之差即放行，
/// 但漏掉一条就等于那条指纹原样出站 → `400 code 11128`。
fn apply_workbuddy_fingerprint_sanitization(
    object: &mut serde_json::Map<String, Value>,
    config: Option<&Value>,
) {
    let enabled = config
        .and_then(|value| value.get("workbuddy_sanitize_fingerprints"))
        .and_then(Value::as_bool)
        .unwrap_or(true);
    if !enabled {
        return;
    }
    let Some(messages) = object.get_mut("messages").and_then(Value::as_array_mut) else {
        return;
    };
    for message in messages.iter_mut() {
        let Some(entry) = message.as_object_mut() else {
            continue;
        };
        if let Some(content) = entry.get_mut("content") {
            sanitize_workbuddy_content(content);
        }
        for key in ["reasoning_content", "reasoning"] {
            if let Some(Value::String(text)) = entry.get_mut(key) {
                let sanitized = sanitize_workbuddy_text(text);
                *text = sanitized;
            }
        }
        if let Some(tool_calls) = entry.get_mut("tool_calls").and_then(Value::as_array_mut) {
            for call in tool_calls.iter_mut() {
                let Some(arguments) = call
                    .get_mut("function")
                    .and_then(|function| function.get_mut("arguments"))
                    .and_then(|arguments| arguments.as_str())
                    .map(str::to_string)
                else {
                    continue;
                };
                let sanitized = sanitize_workbuddy_text(&arguments);
                if sanitized != arguments {
                    if let Some(function) = call.get_mut("function").and_then(Value::as_object_mut)
                    {
                        function.insert("arguments".to_string(), Value::String(sanitized));
                    }
                }
            }
        }
    }
}

fn sanitize_workbuddy_content(content: &mut Value) {
    match content {
        Value::String(text) => {
            let sanitized = sanitize_workbuddy_text(text);
            *text = sanitized;
        }
        Value::Array(parts) => {
            for part in parts.iter_mut() {
                let Some(entry) = part.as_object_mut() else {
                    continue;
                };
                if let Some(Value::String(text)) = entry.get_mut("text") {
                    let sanitized = sanitize_workbuddy_text(text);
                    *text = sanitized;
                }
            }
        }
        _ => {}
    }
}

/// 单段文本脱敏。预检不中即原样返回（普通请求零改动）。
///
/// 顺序与面板一致：**改写 → header 剥离 → cc_ 剥离 → 裸键名兜底 → trim**。
fn sanitize_workbuddy_text(text: &str) -> String {
    if !has_workbuddy_fingerprint(text) {
        return text.to_string();
    }
    let mut sanitized = text.to_string();
    for rewrite in WORKBUDDY_TEMPLATE_REWRITES {
        let search = rewrite.search_text();
        if sanitized.contains(&search) {
            sanitized = sanitized.replace(&search, &rewrite.replace_text());
        }
    }
    // 五位错误码：插一个 U+002D 连字符（面板同款；零宽字符会被上游归一化，故必须换可见字符）。
    if sanitized.contains(WORKBUDDY_BLOCKED_ERROR_CODE) {
        sanitized = sanitized.replace(WORKBUDDY_BLOCKED_ERROR_CODE, WORKBUDDY_ERROR_CODE_VARIANT);
    }
    sanitized = HDR_KV_RE.replace_all(&sanitized, "").to_string();
    if sanitized.contains("cc_") {
        let mut previous = String::new();
        while previous != sanitized {
            previous = sanitized.clone();
            sanitized = CC_KV_RE.replace_all(&sanitized, "").to_string();
        }
    }
    sanitized = BARE_HDR_RE
        .replace_all(&sanitized, WORKBUDDY_HDR_NAME_VARIANT)
        .to_string();
    sanitized.trim().to_string()
}

/// 面板 `sanitizeRewrites` 的五条改写，**结构化表达**。
///
/// 为什么不写成 `(search, replace)` 两个长字符串：这个仓库已经踩过多次「两串看起来不同、
/// 实际字节相同」的事故（面板源码、本文件、乃至手写常量都被同一个渲染/输入陷阱命中过），
/// 那样写出来的表会静默退化成**空操作**。这里把差异放进**独立的中间段**：
/// `search = prefix + search + suffix`、`replace = prefix + replace + suffix`，
/// 并由单测 `template_rewrites_actually_change_something` 强制 `search != replace`。
#[derive(Debug)]
struct WorkbuddyRewrite {
    prefix: &'static str,
    /// 中间段：命中形态（空串 = 纯插入）。
    search: &'static str,
    /// 中间段：替换形态。
    replace: &'static str,
    suffix: &'static str,
}

impl WorkbuddyRewrite {
    fn search_text(&self) -> String {
        format!("{}{}{}", self.prefix, self.search, self.suffix)
    }

    fn replace_text(&self) -> String {
        format!("{}{}{}", self.prefix, self.replace, self.suffix)
    }
}

/// 五条改写（顺序即面板顺序；每条只改一个词、语义不变）。
///
/// 面板原表里这五条的 `from`/`to` 差异分别是：插 `tool `、`Main`→`Default`、插 ` tool`、
/// `give`→`provide`、给五位错误码插一个 U+002D。
const WORKBUDDY_TEMPLATE_REWRITES: &[WorkbuddyRewrite] = &[
    // 1) 身份句：`...official CLI for Claude` → 插 `tool `。
    //    匹配串**不带结尾标点**：CLI 版以句号收尾、桌面版（Agent SDK）以逗号接后继内容，
    //    去掉结尾标点后两种形态一并覆盖（替换串同样不带标点，原有标点原样保留）。
    WorkbuddyRewrite {
        prefix: "You are Claude Code, Anthropic's official CLI ",
        search: "",
        replace: "tool ",
        suffix: "for Claude",
    },
    // 2) 注入指令句：`Main branch (...)` → `Default branch (...)`。
    WorkbuddyRewrite {
        prefix: "",
        search: "Main ",
        replace: "Default ",
        suffix: "branch (you will usually use this for PRs)",
    },
    // 3) Codex instructions 首段：`...Codex CLI, a terminal-based...` → 插 ` tool`。
    WorkbuddyRewrite {
        prefix: "You are a coding agent running in the Codex CLI",
        search: "",
        replace: " tool",
        suffix: ", a terminal-based coding assistant.",
    },
    // 4) 反馈句（整句带 Anthropic 仓库链接；只留链接或只留半边均不拦，实测需整句同时出现）：
    //    `give` → `provide`。
    WorkbuddyRewrite {
        prefix: "To ",
        search: "give",
        replace: "provide",
        suffix: " feedback, users should report the issue at https://github.com/anthropics/claude-code/issues",
    },
];

/// 与原名只差不可见连字符（U+2011）：破坏逐字匹配、可读性不变。
///
/// 面板这里用的是「与模式串完全相同」的替换串（等于空操作，裸键名照原样出站）；
/// 本实现**刻意做得更严**：换成 U+2011 变体，真正破坏逐字匹配。
const WORKBUDDY_HDR_NAME_VARIANT: &str = "x\u{2011}anthropic\u{2011}billing\u{2011}hdr";

/// 上游反探测的裸错误码：**五位数字 `11128`**（码点 `31 31 31 32 38`，**没有连字符**）。
///
/// 只要请求体里逐字出现这五位数字就整单拦截（与上下文无关：`code=11128`、裸 `11128`、
/// 错误信息里回显的 `11128` 全部命中；相邻的 `11101`/`11115`/`11135` 均放行）。
/// 面板的改写是**插入一个 U+002D 连字符**得到六字符形态（码点 `31 31 2D 31 32 38`）。
const WORKBUDDY_BLOCKED_ERROR_CODE: &str = "11128";
/// 插入 U+002D 后的可读形态（码点 `31 31 2D 31 32 38`）。
const WORKBUDDY_ERROR_CODE_VARIANT: &str = "11-128";

/// 面板 `sanitizeFeatures` 的特征预检（命中任一才进入净化，普通请求零改动）。
const WORKBUDDY_FINGERPRINT_FEATURES: &[&str] = &[
    "x-anthropic-billing-hdr",
    // 裸五位错误码（同上，码点 `31 31 31 32 38`）。
    "11128",
    "You are Claude Code",
    "Main branch (",
    "You are a coding agent running in the Codex CLI",
    "github.com/anthropics/",
];

fn has_workbuddy_fingerprint(text: &str) -> bool {
    // 面板把 `cc_` 留在净化内部判断（只含 cc_ 的文本会被它的预检跳过）；这里放进预检，
    // 严格更安全——多做的只是「按面板同款规则剥掉 cc_ 尾随键值」。
    text.contains("cc_")
        || WORKBUDDY_FINGERPRINT_FEATURES
            .iter()
            .any(|feature| text.contains(feature))
        || BARE_HDR_RE.is_match(text)
}

static HDR_KV_RE: LazyLock<Regex> = LazyLock::new(|| {
    // `x-anthropic-billing-hdr: <value>;`（键名即触发，与值无关，整段删除）。
    Regex::new(r"(?i)x-anthropic-billing-hdr\s*[:=]\s*[^\n;]*;?[ \t]*\n?")
        .expect("workbuddy header fingerprint regex must compile")
});
static BARE_HDR_RE: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"(?i)x-anthropic-billing-hdr")
        .expect("workbuddy bare header fingerprint regex must compile")
});
static CC_KV_RE: LazyLock<Regex> = LazyLock::new(|| {
    // 尾随裸键值 `cc_xxx=...;`（循环清理，直到不再变化）。
    Regex::new(r"(?i)\bcc_[a-z0-9_]+=[^\n;]*;?[ \t]*").expect("workbuddy cc kv regex must compile")
});

/// `developer` → `system`（大小写不敏感；其它 role 一律不动）。
fn normalize_developer_roles(object: &mut serde_json::Map<String, Value>) {
    let Some(messages) = object.get_mut("messages").and_then(Value::as_array_mut) else {
        return;
    };
    for message in messages.iter_mut() {
        let Some(entry) = message.as_object_mut() else {
            continue;
        };
        let is_developer = entry
            .get("role")
            .and_then(Value::as_str)
            .is_some_and(|role| role.trim().eq_ignore_ascii_case("developer"));
        if is_developer {
            entry.insert("role".to_string(), Value::String("system".to_string()));
        }
    }
}

/// `max_completion_tokens` → `max_tokens`：别名总是删除；只有正整数值才翻译，
/// 且显式 `max_tokens` 优先。
fn normalize_max_completion_tokens(object: &mut serde_json::Map<String, Value>) {
    let alias = object.remove("max_completion_tokens");
    if object.contains_key("max_tokens") {
        return;
    }
    let Some(value) = alias else {
        return;
    };
    let is_positive_integer = value.as_i64().is_some_and(|number| number > 0)
        || value.as_u64().is_some_and(|number| number > 0);
    if is_positive_integer {
        object.insert("max_tokens".to_string(), value);
    }
}

/// `tool_choice` 摊平成上游接受的字符串形态。
fn normalize_tool_choice(object: &mut serde_json::Map<String, Value>) {
    let Some(tool_choice) = object.get("tool_choice") else {
        return;
    };
    let normalized = match tool_choice {
        Value::String(value) => match value.trim().to_ascii_lowercase().as_str() {
            "none" => None,
            "auto" | "required" => Some(value.trim().to_ascii_lowercase()),
            // 字符串形式的函数名：原样保留（上游按名字选择工具）。
            _ => return,
        },
        Value::Object(entry) => {
            let kind = entry
                .get("type")
                .and_then(Value::as_str)
                .map(|value| value.trim().to_ascii_lowercase())
                .unwrap_or_default();
            match kind.as_str() {
                "none" => None,
                "auto" | "required" => Some(kind),
                "function" => entry
                    .get("function")
                    .and_then(|function| function.get("name"))
                    .and_then(Value::as_str)
                    .map(str::trim)
                    .filter(|name| !name.is_empty())
                    .map(ToOwned::to_owned)
                    .or_else(|| Some("auto".to_string())),
                _ => None,
            }
        }
        _ => None,
    };

    match normalized {
        Some(value) => {
            object.insert("tool_choice".to_string(), Value::String(value));
        }
        None => {
            object.remove("tool_choice");
            // `none` 的语义是「这次别调工具」：把声明也一起去掉，避免上游
            // 仍按 tools[].strict/auto 走工具分支。
            object.remove("tools");
            object.remove("functions");
        }
    }
}

/// `image_url` 字符串 → `{"url": …}`（对象形态原样保留）。
fn normalize_image_urls(object: &mut serde_json::Map<String, Value>) {
    let Some(messages) = object.get_mut("messages").and_then(Value::as_array_mut) else {
        return;
    };
    for message in messages.iter_mut() {
        let Some(content) = message
            .as_object_mut()
            .and_then(|entry| entry.get_mut("content"))
            .and_then(Value::as_array_mut)
        else {
            continue;
        };
        for part in content.iter_mut() {
            let Some(entry) = part.as_object_mut() else {
                continue;
            };
            let is_image_part = entry
                .get("type")
                .and_then(Value::as_str)
                .is_some_and(|kind| kind.trim().eq_ignore_ascii_case("image_url"));
            if !is_image_part {
                continue;
            }
            let Some(Value::String(url)) = entry.get("image_url") else {
                continue;
            };
            if url.trim().is_empty() {
                continue;
            }
            entry.insert("image_url".to_string(), serde_json::json!({ "url": url }));
        }
    }
}

#[cfg(test)]
mod tests {
    use super::{
        apply_workbuddy_prompt_policy, apply_workbuddy_request_body_semantics,
        derive_workbuddy_account_stable_id, insert_workbuddy_request_headers,
        insert_workbuddy_request_headers_if_needed, is_workbuddy_content_blocked,
        is_workbuddy_global_domain, is_workbuddy_provider_transport, next_cst_midnight_unix_secs,
        observe_workbuddy_upstream_failure_for_header_map_with_gate, unix_now_secs,
        workbuddy_billing_user_agent, workbuddy_identity, workbuddy_user_agent,
        WorkbuddyDegradeGate, WorkbuddyIdentity, WorkbuddyRealm, WORKBUDDY_CHAT_BASE_URL_CN,
        WORKBUDDY_CHAT_PATH, WORKBUDDY_DEFAULT_SYSTEM_PROMPT, WORKBUDDY_DEGRADED_SYSTEM_PROMPT,
        WORKBUDDY_INTERNAL_HEADER,
    };
    use crate::snapshot::{
        GatewayProviderTransportEndpoint, GatewayProviderTransportKey,
        GatewayProviderTransportProvider, GatewayProviderTransportSnapshot,
    };
    use serde_json::json;
    use std::collections::BTreeMap;

    #[test]
    fn provider_identity_uses_the_fixed_chat_entry() {
        // 报告 §10.1/§10.3.1：CN 对话域已是 `www.workbuddy.cn`（旧的 copilot.tencent.com 由
        // 报告判定为「全部收敛到同一个域」）。**与 `X-Domain` 无关**：那个仍是登录域
        // `www.codebuddy.cn`（见 `identity_headers_...` 那组断言）。
        assert_eq!(WORKBUDDY_CHAT_BASE_URL_CN, "https://www.workbuddy.cn");
        assert_eq!(WORKBUDDY_CHAT_PATH, "/v2/chat/completions");
    }

    #[test]
    fn provider_type_matching_is_case_insensitive() {
        let mut transport = sample_transport("workbuddy");
        assert!(is_workbuddy_provider_transport(&transport));
        transport.provider.provider_type = "  WorkBuddy ".to_string();
        assert!(is_workbuddy_provider_transport(&transport));
        transport.provider.provider_type = "opencode".to_string();
        assert!(!is_workbuddy_provider_transport(&transport));
    }

    /// 派生必须与面板 `deriveAccountStableID` 逐字节一致：36 位小写 hex，
    /// 同账号同用途恒定、跨用途互异、跨账号互异。
    #[test]
    fn account_stable_id_is_stable_and_distinct() {
        let machine = derive_workbuddy_account_stable_id("uid-1", "machine").expect("machine id");
        let session = derive_workbuddy_account_stable_id("uid-1", "session").expect("session id");
        assert_eq!(machine.len(), 36);
        assert_eq!(session.len(), 36);
        assert_ne!(machine, session);
        assert_eq!(
            machine,
            derive_workbuddy_account_stable_id("uid-1", "machine").expect("stable")
        );
        assert_ne!(
            machine,
            derive_workbuddy_account_stable_id("uid-2", "machine").expect("other account")
        );
        assert!(derive_workbuddy_account_stable_id("   ", "machine").is_none());
    }

    #[test]
    fn realm_follows_explicit_flag_then_domain_suffix() {
        let mut transport = sample_transport("workbuddy");
        transport.key.decrypted_auth_config =
            Some(json!({"uid": "u1", "realm": "cn", "domain": "www.codebuddy.cn"}).to_string());
        assert_eq!(workbuddy_identity(&transport).realm, WorkbuddyRealm::Cn);

        transport.key.decrypted_auth_config =
            Some(json!({"uid": "u1", "realm": "global"}).to_string());
        assert_eq!(workbuddy_identity(&transport).realm, WorkbuddyRealm::Global);

        transport.key.decrypted_auth_config =
            Some(json!({"uid": "u1", "domain": "workbuddy.ai"}).to_string());
        assert_eq!(workbuddy_identity(&transport).realm, WorkbuddyRealm::Global);

        assert!(is_workbuddy_global_domain("x.workbuddy.ai"));
        assert!(!is_workbuddy_global_domain("workbuddy.ai.evil.com"));
    }

    #[test]
    fn identity_reads_camel_and_snake_case_fields() {
        let mut transport = sample_transport("workbuddy");
        transport.key.decrypted_auth_config = Some(
            json!({
                "uid": "uid-camel",
                "enterpriseId": "ent-1",
                "domain": "www.codebuddy.cn"
            })
            .to_string(),
        );
        let identity = workbuddy_identity(&transport);
        assert_eq!(identity.uid.as_deref(), Some("uid-camel"));
        assert_eq!(identity.enterprise_id.as_deref(), Some("ent-1"));
        assert_eq!(identity.domain.as_deref(), Some("www.codebuddy.cn"));

        transport.key.decrypted_auth_config =
            Some(json!({"uid": "uid-snake", "enterprise_id": "ent-2"}).to_string());
        let identity = workbuddy_identity(&transport);
        assert_eq!(identity.uid.as_deref(), Some("uid-snake"));
        assert_eq!(identity.enterprise_id.as_deref(), Some("ent-2"));
    }

    #[test]
    fn identity_degrades_to_cn_defaults_on_dirty_config() {
        let mut transport = sample_transport("workbuddy");
        transport.key.decrypted_auth_config = Some("not json".to_string());
        assert_eq!(
            workbuddy_identity(&transport),
            WorkbuddyIdentity::cn_default()
        );
        transport.key.decrypted_auth_config = None;
        assert_eq!(
            workbuddy_identity(&transport),
            WorkbuddyIdentity::cn_default()
        );
    }

    #[test]
    fn chat_headers_carry_the_codebuddy_fingerprint_family() {
        let identity = WorkbuddyIdentity {
            realm: WorkbuddyRealm::Cn,
            uid: Some("uid-1".to_string()),
            enterprise_id: None,
            domain: Some("www.codebuddy.cn".to_string()),
            device_token: None,
        };
        let mut headers = BTreeMap::new();
        insert_workbuddy_request_headers(&identity, &mut headers);

        assert_eq!(
            headers.get("x-codebuddy-request").map(String::as_str),
            Some("1")
        );
        assert_eq!(
            headers.get("origin").map(String::as_str),
            Some("https://www.codebuddy.cn")
        );
        assert_eq!(
            headers.get("referer").map(String::as_str),
            Some("https://www.codebuddy.cn/")
        );
        assert_eq!(
            headers.get("user-agent").map(String::as_str),
            // 报告 §10.1：CLI 裸跑（headless `-p`）是**两段式**，两段都取 CLI 版本。
            Some("CLI/2.137.1 WorkBuddy/2.137.1")
        );
        // 报告 §10.3.6：`Accept` 只声明 JSON；`Accept-Encoding` 对齐真机（不再发 identity）。
        assert_eq!(
            headers.get("accept").map(String::as_str),
            Some("application/json")
        );
        assert_eq!(
            headers.get("accept-encoding").map(String::as_str),
            Some("gzip, compress, deflate, br")
        );
        assert_eq!(
            headers.get("accept-language").map(String::as_str),
            Some("zh-CN")
        );
        assert_eq!(headers.get("x-user-id").map(String::as_str), Some("uid-1"));
        assert_eq!(
            headers.get("x-domain").map(String::as_str),
            Some("www.codebuddy.cn")
        );
        assert_eq!(
            headers.get("x-no-enterprise-id").map(String::as_str),
            Some("1")
        );
        assert!(!headers.contains_key("x-enterprise-id"));
        // 报告 §10.1/§10.3.6：5.8.x 对话请求**不发**这两个头。
        assert!(
            !headers.contains_key("x-machine-id"),
            "X-Machine-ID 必须不再发"
        );
        assert!(
            !headers.contains_key("x-session-id"),
            "X-Session-ID 必须不再发"
        );
        assert_eq!(
            headers.get("x-agent-purpose").map(String::as_str),
            Some("conversation")
        );
        // 报告 §10.3.4：新增三头。
        assert_eq!(
            headers.get("x-agent-intent").map(String::as_str),
            Some("craft")
        );
        assert_eq!(
            headers.get("x-agent-type").map(String::as_str),
            Some("main")
        );
        assert_eq!(
            headers.get("x-private-data").map(String::as_str),
            Some("true")
        );
        // 报告 §10.1：`X-IDE-*` 按 CLI 形态（`CLI/CLI/{cli 版本}`）。
        assert_eq!(headers.get("x-ide-name").map(String::as_str), Some("CLI"));
        assert_eq!(headers.get("x-ide-type").map(String::as_str), Some("CLI"));
        assert_eq!(
            headers.get("x-ide-version").map(String::as_str),
            Some("2.137.1")
        );
        // 报告 §10.1：`X-Product` 两端都是 SaaS（旧实现 CN 发 WorkBuddy）。
        assert_eq!(headers.get("x-product").map(String::as_str), Some("SaaS"));
        // 报告 §10.1 末行：`x-stainless-*` 七个（openai-node 6.25.0 指纹）。
        for (name, expected) in [
            ("x-stainless-arch", "x64"),
            ("x-stainless-lang", "js"),
            ("x-stainless-os", "Linux"),
            ("x-stainless-package-version", "6.25.0"),
            ("x-stainless-runtime", "node"),
            ("x-stainless-runtime-version", "v24.15.0"),
            ("x-stainless-retry-count", "0"),
        ] {
            assert_eq!(
                headers.get(name).map(String::as_str),
                Some(expected),
                "缺 {name}"
            );
        }
        // 内部标记头：响应侧靠它认出 workbuddy 计划（不内联 provider_type 判断）。
        assert_eq!(
            headers.get(WORKBUDDY_INTERNAL_HEADER).map(String::as_str),
            Some("1")
        );
    }

    #[test]
    fn global_realm_overrides_identity_headers() {
        let identity = WorkbuddyIdentity {
            realm: WorkbuddyRealm::Global,
            uid: Some("uid-1".to_string()),
            enterprise_id: Some("ent-should-be-ignored".to_string()),
            domain: Some("www.codebuddy.cn".to_string()),
            device_token: None,
        };
        let mut headers = BTreeMap::new();
        insert_workbuddy_request_headers(&identity, &mut headers);

        assert_eq!(
            headers.get("origin").map(String::as_str),
            Some("https://www.workbuddy.ai")
        );
        assert_eq!(
            headers.get("user-agent").map(String::as_str),
            // 报告 §10.1：两段式 CLI UA，国际段的 CLI 版本是 2.161.0。
            Some("CLI/2.161.0 WorkBuddy/2.161.0")
        );
        assert_eq!(
            headers.get("x-domain").map(String::as_str),
            Some("www.workbuddy.ai")
        );
        // 报告 §10.1：`X-IDE-*` 跟随 CLI 形态，`X-Product` 两端都是 SaaS。
        assert_eq!(headers.get("x-ide-name").map(String::as_str), Some("CLI"));
        assert_eq!(
            headers.get("x-ide-version").map(String::as_str),
            Some("2.161.0")
        );
        assert_eq!(headers.get("x-product").map(String::as_str), Some("SaaS"));
        assert_eq!(
            headers.get("accept-language").map(String::as_str),
            Some("en-US")
        );
        assert!(!headers.contains_key("x-enterprise-id"));
        assert!(!headers.contains_key("x-machine-id"));
        assert!(!headers.contains_key("x-session-id"));
    }

    #[test]
    fn missing_identity_declares_anonymous_headers() {
        let identity = WorkbuddyIdentity::cn_default();
        let mut headers = BTreeMap::new();
        insert_workbuddy_request_headers(&identity, &mut headers);
        assert_eq!(headers.get("x-no-user-id").map(String::as_str), Some("1"));
        assert_eq!(
            headers.get("x-no-department-info").map(String::as_str),
            Some("1")
        );
        assert!(!headers.contains_key("x-machine-id"));
    }

    /// 国际域 chat 必须带 `X-Conversation-ID`：上游渠道校验缺它即
    /// `400 {"code":11128,"msg":"request illegal"}`。这是国际域此前完全不可用的根因
    /// —— 入站客户端（OpenAI SDK / Cursor 等）从不带这个头，而旧规则
    /// 「客户端给了才发、绝不伪造」使它永远缺失。
    /// CN 域维持原规则（不伪造），零回归。
    #[test]
    fn global_chat_always_gets_a_conversation_id() {
        use super::insert_workbuddy_conversation_headers_if_needed;

        let global = sample_transport_with_realm("workbuddy", WorkbuddyRealm::Global);
        let mut headers = BTreeMap::new();
        insert_workbuddy_conversation_headers_if_needed(
            &global,
            "openai:chat",
            &mut headers,
            Some("trace-abc"),
        );

        // 硬闸门三件套必须都在，且非空。
        for name in [
            "x-conversation-id",
            "x-conversation-request-id",
            "x-conversation-message-id",
        ] {
            let value = headers
                .get(name)
                .unwrap_or_else(|| panic!("{name} 必须注入"));
            assert!(!value.trim().is_empty(), "{name} 不得为空");
        }
        // 形态：会话 ID 是 UUID v4（36 带连字符，报告 §10.2 记的 Global 桌面端取值），
        // 消息/请求级是 **ULID**（26 字符，报告 §10.2「ID 族为 ULID」）。
        assert_eq!(headers.get("x-conversation-id").map(String::len), Some(36));
        assert_eq!(
            headers.get("x-conversation-message-id").map(String::len),
            Some(26)
        );
        assert_eq!(
            headers.get("x-conversation-request-id").map(String::len),
            Some(26)
        );

        // 每次请求新生成：复用会被上游按「同一会话」聚合。
        let mut second = BTreeMap::new();
        insert_workbuddy_conversation_headers_if_needed(
            &global,
            "openai:chat",
            &mut second,
            Some("trace-abc"),
        );
        assert_ne!(
            headers.get("x-conversation-id"),
            second.get("x-conversation-id")
        );

        // 客户端自带会话 ID 时原样透传（不覆盖）。
        let mut passthrough = BTreeMap::new();
        passthrough.insert("x-conversation-id".to_string(), "client-conv".to_string());
        insert_workbuddy_conversation_headers_if_needed(
            &global,
            "openai:chat",
            &mut passthrough,
            Some("trace-abc"),
        );
        assert_eq!(
            passthrough.get("x-conversation-id").map(String::as_str),
            Some("client-conv")
        );

        // CN 零回归：不伪造会话 ID，其余聚合头照旧。
        let cn = sample_transport("workbuddy");
        let mut cn_headers = BTreeMap::new();
        insert_workbuddy_conversation_headers_if_needed(
            &cn,
            "openai:chat",
            &mut cn_headers,
            Some("trace-abc"),
        );
        assert!(!cn_headers.contains_key("x-conversation-id"));
        assert!(cn_headers.contains_key("x-conversation-request-id"));
    }

    /// 只有本 provider 的 OpenAI 系格式才注入头：其它 provider / 其它
    /// 协议族必须零改动（否则会把 CodeBuddy 指纹带到别人的请求上）。
    #[test]
    fn headers_are_scoped_to_workbuddy_openai_formats() {
        let transport = sample_transport("workbuddy");
        let mut headers = BTreeMap::new();
        insert_workbuddy_request_headers_if_needed(&transport, "claude:messages", &mut headers);
        assert!(headers.is_empty(), "非 openai 系格式不应注入");

        let mut headers = BTreeMap::new();
        insert_workbuddy_request_headers_if_needed(&transport, "openai:chat", &mut headers);
        assert!(headers.contains_key("x-codebuddy-request"));

        let other = sample_transport("opencode");
        let mut headers = BTreeMap::new();
        insert_workbuddy_request_headers_if_needed(&other, "openai:chat", &mut headers);
        assert!(headers.is_empty(), "其它 provider 不应注入");
    }

    /// 出站头白名单：第三方客户端自带的**归属头**（x-zcode-* / x-title / http-referer /
    /// sec-fetch-* / x-query-id）不得泄露给上游；官方身份头族、会话链路头与中性桌面遥测保留。
    #[test]
    fn outbound_allowlist_strips_third_party_client_identity_headers() {
        let transport = sample_transport("workbuddy");
        let mut headers = BTreeMap::from([
            // 第三方归属头 → 必须被丢弃
            ("x-zcode-agent".to_string(), "glm".to_string()),
            ("x-zcode-app-version".to_string(), "3.14.5".to_string()),
            ("x-title".to_string(), "Z Code@electron".to_string()),
            ("http-referer".to_string(), "https://zcode.z.ai".to_string()),
            ("sec-fetch-mode".to_string(), "cors".to_string()),
            (
                "x-query-id".to_string(),
                "01a15428-2464-7b0d-9205".to_string(),
            ),
            // 官方/会话/遥测头 → 必须保留
            ("origin".to_string(), "https://www.codebuddy.cn".to_string()),
            ("content-type".to_string(), "application/json".to_string()),
            ("x-conversation-id".to_string(), "client-conv".to_string()),
            (
                "x-trace-id".to_string(),
                "8c420b10-6459-4904-997f".to_string(),
            ),
            ("x-client-language".to_string(), "zh-CN".to_string()),
            ("x-os-version".to_string(), "10.0.19045".to_string()),
        ]);
        insert_workbuddy_request_headers_if_needed(&transport, "openai:chat", &mut headers);

        // 归属头被丢弃
        assert!(!headers.contains_key("x-zcode-agent"));
        assert!(!headers.contains_key("x-zcode-app-version"));
        assert!(!headers.contains_key("x-title"));
        assert!(!headers.contains_key("http-referer"));
        assert!(!headers.contains_key("sec-fetch-mode"));
        assert!(!headers.contains_key("x-query-id"));
        // 身份头族注入成功
        assert!(headers.contains_key("x-codebuddy-request"));
        assert_eq!(
            headers.get("origin").map(String::as_str),
            Some("https://www.codebuddy.cn")
        );
        // 会话入站值保留（供随后会话头注入「客户端值优先」消费）
        assert_eq!(
            headers.get("x-conversation-id").map(String::as_str),
            Some("client-conv")
        );
        assert_eq!(
            headers.get("x-trace-id").map(String::as_str),
            Some("8c420b10-6459-4904-997f")
        );
        // 中性桌面遥测保留
        assert_eq!(
            headers.get("x-client-language").map(String::as_str),
            Some("zh-CN")
        );
        assert_eq!(
            headers.get("x-os-version").map(String::as_str),
            Some("10.0.19045")
        );
        // 内部标记必须在过滤之后写入、不被白名单误删
        assert!(headers.contains_key("x-aether-workbuddy-runtime"));
    }

    /// 客户端自带的同名头必须被账号真实值覆盖（大小写不敏感），且不能留下
    /// 只差大小写的重复键——否则转发层会同时发出两个同名头。
    #[test]
    fn identity_headers_override_client_supplied_duplicates() {
        let identity = WorkbuddyIdentity {
            realm: WorkbuddyRealm::Cn,
            uid: Some("uid-1".to_string()),
            enterprise_id: None,
            domain: None,
            device_token: None,
        };
        let mut headers = BTreeMap::from([
            ("Origin".to_string(), "https://evil.example".to_string()),
            ("USER-AGENT".to_string(), "curl/8.5.0".to_string()),
            ("X-User-Id".to_string(), "someone-else".to_string()),
        ]);
        insert_workbuddy_request_headers(&identity, &mut headers);

        assert_eq!(
            headers.get("origin").map(String::as_str),
            Some("https://www.codebuddy.cn")
        );
        assert_eq!(
            headers.get("user-agent").map(String::as_str),
            Some("CLI/2.137.1 WorkBuddy/2.137.1")
        );
        assert_eq!(headers.get("x-user-id").map(String::as_str), Some("uid-1"));
        assert!(!headers.contains_key("Origin"));
        assert!(!headers.contains_key("USER-AGENT"));
        assert!(!headers.contains_key("X-User-Id"));
    }

    /// UA 的两个轴：**调用形态**（CLI headless = 两段式 / 桌面端 = 三段式）+ **端点类型**
    /// （对话跟随形态 / 计费单段）。报告 §10.1 把原来的「一段三段式」更正成这套分法。
    #[test]
    fn user_agent_shape_follows_call_form_and_endpoint_kind() {
        use super::workbuddy_desktop_user_agent;
        use aether_oauth::provider::providers::{
            workbuddy_user_agent_for, WorkbuddyCallForm, WorkbuddyEndpointKind,
        };

        // ① 默认形态（我们扮演的 CLI headless）= 两段式，两段都取 CLI 版本。
        assert_eq!(
            workbuddy_user_agent(WorkbuddyRealm::Cn),
            "CLI/2.137.1 WorkBuddy/2.137.1"
        );
        assert_eq!(
            workbuddy_user_agent(WorkbuddyRealm::Global),
            "CLI/2.161.0 WorkBuddy/2.161.0"
        );
        // ② 桌面端形态仍可交付（三段式，平台段小写连字符 `workbuddy-ai`）。
        assert_eq!(
            workbuddy_desktop_user_agent(WorkbuddyRealm::Cn),
            "WorkBuddy/5.5.4 WorkBuddy/5.5.4 CLI/2.137.1"
        );
        assert_eq!(
            workbuddy_desktop_user_agent(WorkbuddyRealm::Global),
            "WorkBuddy/5.8.4 workbuddy-ai/5.8.4 CLI/2.161.0"
        );
        // ③ 计费/成长端点 = 单段，且与调用形态无关。
        let oauth_cn = WorkbuddyRealm::Cn.oauth_realm();
        let oauth_global = WorkbuddyRealm::Global.oauth_realm();
        for form in [WorkbuddyCallForm::CliHeadless, WorkbuddyCallForm::Desktop] {
            assert_eq!(
                workbuddy_user_agent_for(oauth_cn, WorkbuddyEndpointKind::Billing, form),
                "WorkBuddy/5.5.4"
            );
            assert_eq!(
                workbuddy_user_agent_for(oauth_global, WorkbuddyEndpointKind::Billing, form),
                "WorkBuddy/5.8.4"
            );
        }
        // ④ 默认调用形态就是 CLI（防止有人把 Desktop 设成默认）。
        assert_eq!(WorkbuddyCallForm::default(), WorkbuddyCallForm::CliHeadless);
        // ⑤ 计费单段 UA 与端点类型轴同源（`workbuddy_billing_user_agent` 不再自带字面量）。
        assert_eq!(workbuddy_billing_user_agent(), "WorkBuddy/5.5.4");
        assert!(!workbuddy_billing_user_agent().contains("CLI/"));
    }

    /// **本次修复的核心断言**：对话路径（本 crate 的头注入）与刷新路径
    /// （`aether-oauth` 的 OAuth 刷新请求）在 **CN 与国际两个域**下必须送出同一个 UA。
    ///
    /// 两边都只是 `aether_oauth::provider::providers::workbuddy_user_agent(realm)` 的
    /// 不同调用点；任何一侧再抄一份字面量，这里就会红（历史缺陷：国际号的 refresh
    /// 用的是旧平台段 + CN 版本号，与 chat 的 UA 不一致）。
    #[test]
    fn chat_and_refresh_share_one_user_agent_in_both_realms() {
        for (realm, expected) in [
            (WorkbuddyRealm::Cn, "CLI/2.137.1 WorkBuddy/2.137.1"),
            (WorkbuddyRealm::Global, "CLI/2.161.0 WorkBuddy/2.161.0"),
        ] {
            let identity = WorkbuddyIdentity {
                realm,
                ..WorkbuddyIdentity::cn_default()
            };
            let mut headers = BTreeMap::new();
            insert_workbuddy_request_headers(&identity, &mut headers);
            let chat_user_agent = headers.get("user-agent").map(String::as_str);

            // 刷新路径用的就是这一个函数（oauth 侧 `refresh_with_token` 直接调用它）。
            let refresh_user_agent =
                aether_oauth::provider::providers::workbuddy_user_agent(realm.oauth_realm());
            assert_eq!(
                chat_user_agent,
                Some(refresh_user_agent.as_str()),
                "对话路径与刷新路径的 UA 必须同源：realm={realm:?}"
            );
            // 再钉死字面量：两边一起漂移也会红。
            assert_eq!(chat_user_agent, Some(expected), "realm={realm:?}");
        }
    }

    /// 四条协议兼容归一化必须都在：上游的 role 白名单 / 参数形态比标准窄。
    #[test]
    fn request_body_semantics_normalize_the_upstream_subset() {
        let transport = sample_transport("workbuddy");
        let mut body = json!({
            "model": "deepseek-v4-flash",
            "max_completion_tokens": 4096,
            "tool_choice": {"type": "function", "function": {"name": "exec_command"}},
            "messages": [
                {"role": "Developer", "content": "be terse"},
                {"role": "user", "content": [
                    {"type": "image_url", "image_url": "https://example.test/a.png"}
                ]}
            ]
        });
        apply_workbuddy_request_body_semantics(&transport, "openai:chat", &mut body);

        assert_eq!(body["messages"][0]["role"], "system");
        // 别名必须消失（留着会被上游忽略，表现为长回答被静默截断）。
        assert!(body.get("max_completion_tokens").is_none());
        assert_eq!(body["max_tokens"], 4096);
        assert_eq!(body["tool_choice"], "exec_command");
        assert_eq!(
            body["messages"][1]["content"][0]["image_url"]["url"],
            "https://example.test/a.png"
        );
    }

    #[test]
    fn request_body_semantics_flatten_and_drop_tool_choice_objects() {
        let transport = sample_transport("workbuddy");

        let mut auto = json!({"tool_choice": {"type": "auto"}});
        apply_workbuddy_request_body_semantics(&transport, "openai:chat", &mut auto);
        assert_eq!(auto["tool_choice"], "auto");

        // 函数名缺失 → 退化成 auto（上游不接受空名字）。
        let mut unnamed = json!({"tool_choice": {"type": "function", "function": {}}});
        apply_workbuddy_request_body_semantics(&transport, "openai:chat", &mut unnamed);
        assert_eq!(unnamed["tool_choice"], "auto");

        // none：连 tools 一起去掉，否则上游仍可能走工具分支。
        let mut none = json!({
            "tool_choice": {"type": "none"},
            "tools": [{"type": "function", "function": {"name": "exec_command"}}]
        });
        apply_workbuddy_request_body_semantics(&transport, "openai:chat", &mut none);
        assert!(none.get("tool_choice").is_none());
        assert!(none.get("tools").is_none());
    }

    #[test]
    fn request_body_semantics_keep_valid_shapes_untouched() {
        let transport = sample_transport("workbuddy");
        let mut body = json!({
            "model": "glm-5.2",
            "max_tokens": 1024,
            "max_completion_tokens": 4096,
            "tool_choice": "auto",
            "messages": [
                {"role": "system", "content": "keep"},
                {"role": "user", "content": [
                    {"type": "image_url", "image_url": {"url": "https://example.test/b.png"}}
                ]}
            ]
        });
        apply_workbuddy_request_body_semantics(&transport, "openai:chat", &mut body);

        // 显式 max_tokens 优先：别名删除但值不动。
        assert_eq!(body["max_tokens"], 1024);
        assert!(body.get("max_completion_tokens").is_none());
        assert_eq!(body["tool_choice"], "auto");
        assert_eq!(body["messages"][0]["role"], "system");
        // 已经是对象形态：不重复包一层。
        assert_eq!(
            body["messages"][1]["content"][0]["image_url"]["url"],
            "https://example.test/b.png"
        );
    }

    /// 作用域：只对 workbuddy 的 openai 系格式生效，且非对象 body 不抛错。
    #[test]
    fn request_body_semantics_are_scoped_and_tolerant() {
        let body_value = json!({
            "messages": [{"role": "developer", "content": "x"}]
        });

        let other = sample_transport("opencode");
        let mut untouched = body_value.clone();
        apply_workbuddy_request_body_semantics(&other, "openai:chat", &mut untouched);
        assert_eq!(untouched, body_value, "其它 provider 必须零改动");

        let transport = sample_transport("workbuddy");
        let mut wrong_format = body_value.clone();
        apply_workbuddy_request_body_semantics(&transport, "claude:messages", &mut wrong_format);
        assert_eq!(wrong_format, body_value, "非 openai 系格式必须零改动");

        let mut not_an_object = json!([1, 2, 3]);
        apply_workbuddy_request_body_semantics(&transport, "openai:chat", &mut not_an_object);
        assert_eq!(not_an_object, json!([1, 2, 3]));
    }

    /// 默认模式（custom）必须把客户端 system / developer 换成网关提示词：
    /// 这是消灭「模板句被逐字比对拦截」的那一层。
    #[test]
    fn prompt_policy_replaces_client_system_by_default() {
        let mut transport = sample_transport("workbuddy");
        transport.provider.config = None;
        let mut body = json!({
            "messages": [
                {"role": "system", "content": "You are Claude Code, Anthropic's official CLI tool for Claude."},
                {"role": "developer", "content": "prefer terse answers"},
                {"role": "user", "content": "hi"}
            ]
        });
        apply_workbuddy_request_body_semantics(&transport, "openai:chat", &mut body);

        let messages = body["messages"].as_array().expect("messages");
        assert_eq!(messages.len(), 2, "两条 system/developer 应被替换为一条");
        assert_eq!(messages[0]["role"], "system");
        assert_eq!(messages[0]["content"], WORKBUDDY_DEFAULT_SYSTEM_PROMPT);
        assert_eq!(messages[1]["role"], "user");
        assert!(!body.to_string().contains("Anthropic's official CLI tool"));
    }

    #[test]
    fn prompt_policy_supports_append_and_passthrough() {
        let mut transport = sample_transport("workbuddy");
        transport.provider.config = Some(json!({
            "workbuddy_prompt_mode": "append",
            "workbuddy_prompt_text": "GATEWAY"
        }));
        let mut body = json!({
            "messages": [
                {"role": "system", "content": "keep-me"},
                {"role": "user", "content": "hi"}
            ]
        });
        apply_workbuddy_request_body_semantics(&transport, "openai:chat", &mut body);
        let messages = body["messages"].as_array().expect("messages");
        assert_eq!(messages.len(), 3);
        assert_eq!(messages[0]["content"], "keep-me");
        assert_eq!(messages[1]["content"], "GATEWAY");
        assert_eq!(messages[2]["role"], "user");

        transport.provider.config = Some(json!({"workbuddy_prompt_mode": "passthrough"}));
        let mut untouched = json!({
            "messages": [{"role": "system", "content": "client prompt"}]
        });
        apply_workbuddy_request_body_semantics(&transport, "openai:chat", &mut untouched);
        assert_eq!(untouched["messages"][0]["content"], "client prompt");
    }

    /// 指纹脱敏：header 键值段整段剥离、`cc_*` 尾随键值清掉、裸 `11-128` 破坏成
    /// 逐字不同的可读形态；tool_calls 参数与 reasoning 同样覆盖。
    #[test]
    fn fingerprint_sanitization_strips_blacklisted_markers() {
        use super::{WORKBUDDY_BLOCKED_ERROR_CODE, WORKBUDDY_ERROR_CODE_VARIANT};

        let mut transport = sample_transport("workbuddy");
        // 只验证脱敏：提示词策略设 passthrough，避免 custom 插入 system 改变下标。
        transport.provider.config = Some(json!({"workbuddy_prompt_mode": "passthrough"}));
        // 被拦错误码用常量拼（手写 5 位/6 位极易打混，断言会空过）。
        let mut body = json!({
            "messages": [
                {
                    "role": "assistant",
                    "content": format!("x-anthropic-billing-hdr: abc123;\n残留正文 {WORKBUDDY_BLOCKED_ERROR_CODE}"),
                    "reasoning_content": format!("cc_billing=1; 推理 {WORKBUDDY_BLOCKED_ERROR_CODE}"),
                    "tool_calls": [{
                        "id": "call_1",
                        "function": {
                            "name": "exec_command",
                            "arguments": format!("{{\"cmd\":\"echo {WORKBUDDY_BLOCKED_ERROR_CODE}\"}}")
                        }
                    }]
                },
                {
                    "role": "tool",
                    "tool_call_id": "call_1",
                    "content": "结果"
                },
                {
                    "role": "user",
                    "content": [{"type": "text", "text": "普通文本不动"}]
                }
            ]
        });
        apply_workbuddy_request_body_semantics(&transport, "openai:chat", &mut body);

        let content = body["messages"][0]["content"].as_str().expect("content");
        assert!(!content.contains("x-anthropic-billing-hdr:"));
        assert!(!content.contains(WORKBUDDY_BLOCKED_ERROR_CODE));
        assert!(
            content.contains(WORKBUDDY_ERROR_CODE_VARIANT),
            "应改写成插了连字符的形态：{content}"
        );
        assert!(content.contains("残留正文"), "正文本身要保留");

        let reasoning = body["messages"][0]["reasoning_content"]
            .as_str()
            .expect("reasoning");
        assert!(!reasoning.contains("cc_billing=1;"));
        assert!(reasoning.contains("推理"));

        let arguments = body["messages"][0]["tool_calls"][0]["function"]["arguments"]
            .as_str()
            .expect("arguments");
        assert!(!arguments.contains(WORKBUDDY_BLOCKED_ERROR_CODE));

        assert_eq!(body["messages"][2]["content"][0]["text"], "普通文本不动");
    }

    #[test]
    fn fingerprint_sanitization_can_be_disabled_and_is_idempotent() {
        let mut transport = sample_transport("workbuddy");
        transport.provider.config = Some(json!({
            "workbuddy_prompt_mode": "passthrough",
            "workbuddy_sanitize_fingerprints": false
        }));
        let mut body = json!({
            "messages": [{"role": "user", "content": "x-anthropic-billing-hdr: abc; 11-128"}]
        });
        apply_workbuddy_request_body_semantics(&transport, "openai:chat", &mut body);
        assert!(body["messages"][0]["content"]
            .as_str()
            .expect("content")
            .contains("11-128"));

        // 打开后再跑两次：结果必须稳定（幂等），不能反复插入变体字符。
        transport.provider.config = Some(json!({"workbuddy_prompt_mode": "passthrough"}));
        let mut body = json!({
            "messages": [{"role": "user", "content": "hello 11-128 world"}]
        });
        apply_workbuddy_request_body_semantics(&transport, "openai:chat", &mut body);
        let once = body["messages"][0]["content"]
            .as_str()
            .expect("content")
            .to_string();
        apply_workbuddy_request_body_semantics(&transport, "openai:chat", &mut body);
        assert_eq!(
            body["messages"][0]["content"].as_str().expect("content"),
            once
        );
    }

    /// 签到结果判定：企业号「不支持」优先于「已签到」（`code 10001` 两语境共用，
    /// 只能靠文案区分），2xx + 业务码 0 才算成功。
    #[test]
    fn checkin_outcomes_follow_the_panel_semantics() {
        use super::{classify_workbuddy_checkin_outcome, WorkbuddyCheckinOutcome};

        assert_eq!(
            classify_workbuddy_checkin_outcome(200, Some(r#"{"code":0,"msg":"ok"}"#)),
            WorkbuddyCheckinOutcome::CheckedIn
        );
        // 个人号重复签到：code 10001 + 「今天已签到」→ 幂等成功。
        assert_eq!(
            classify_workbuddy_checkin_outcome(200, Some(r#"{"code":10001,"msg":"今天已签到"}"#)),
            WorkbuddyCheckinOutcome::AlreadyCheckedIn
        );
        assert_eq!(
            classify_workbuddy_checkin_outcome(
                400,
                Some(r#"{"code":10001,"msg":"Already checked in"}"#)
            ),
            WorkbuddyCheckinOutcome::AlreadyCheckedIn
        );
        // 企业号：同一个 10001，但文案是「企业账号不支持该操作」→ 不算失败。
        assert_eq!(
            classify_workbuddy_checkin_outcome(
                400,
                Some(r#"{"code":10001,"msg":"企业账号不支持该操作"}"#)
            ),
            WorkbuddyCheckinOutcome::NotSupported
        );
        // 真失败：401 / 5xx / 未知业务码。
        assert_eq!(
            classify_workbuddy_checkin_outcome(401, Some(r#"{"code":12153}"#)),
            WorkbuddyCheckinOutcome::Failed
        );
        assert_eq!(
            classify_workbuddy_checkin_outcome(500, Some("upstream down")),
            WorkbuddyCheckinOutcome::Failed
        );
        assert_eq!(
            classify_workbuddy_checkin_outcome(200, Some(r#"{"code":999,"msg":"weird"}"#)),
            WorkbuddyCheckinOutcome::Failed
        );
        // 非失败语义：只有 Failed 算失败。
        assert!(WorkbuddyCheckinOutcome::AlreadyCheckedIn.is_ok());
        assert!(WorkbuddyCheckinOutcome::NotSupported.is_ok());
        assert!(!WorkbuddyCheckinOutcome::Failed.is_ok());
    }

    /// 计费端点的路径候选：只有 `/billing/meter` 族在国际域有新旧两条（无 `/v2` 优先），
    /// CN 单路径；企业额度与 `/v2/report` 不回退（面板用 `billingJSON` 单路径）。
    #[test]
    fn billing_path_candidates_follow_the_panel_fallback_chain() {
        use super::{
            workbuddy_billing_path_candidates, WorkbuddyBillingEndpoint, WorkbuddyRealm,
            WORKBUDDY_DAILY_CHECKIN_PATH, WORKBUDDY_DAILY_CHECKIN_PATH_GLOBAL,
            WORKBUDDY_ENTERPRISE_USAGE_PATH, WORKBUDDY_REPORT_PATH, WORKBUDDY_USER_RESOURCE_PATH,
            WORKBUDDY_USER_RESOURCE_PATH_GLOBAL,
        };

        assert_eq!(
            workbuddy_billing_path_candidates(
                WorkbuddyBillingEndpoint::UserResource,
                WorkbuddyRealm::Global
            ),
            vec![
                WORKBUDDY_USER_RESOURCE_PATH_GLOBAL,
                WORKBUDDY_USER_RESOURCE_PATH
            ]
        );
        assert_eq!(
            workbuddy_billing_path_candidates(
                WorkbuddyBillingEndpoint::UserResource,
                WorkbuddyRealm::Cn
            ),
            vec![WORKBUDDY_USER_RESOURCE_PATH]
        );
        assert_eq!(
            workbuddy_billing_path_candidates(
                WorkbuddyBillingEndpoint::DailyCheckin,
                WorkbuddyRealm::Global
            ),
            vec![
                WORKBUDDY_DAILY_CHECKIN_PATH_GLOBAL,
                WORKBUDDY_DAILY_CHECKIN_PATH
            ]
        );
        assert_eq!(
            workbuddy_billing_path_candidates(
                WorkbuddyBillingEndpoint::DailyCheckin,
                WorkbuddyRealm::Cn
            ),
            vec![WORKBUDDY_DAILY_CHECKIN_PATH]
        );
        // 企业额度与活跃上报：单路径（不回退）。
        assert_eq!(
            workbuddy_billing_path_candidates(
                WorkbuddyBillingEndpoint::EnterpriseUsage,
                WorkbuddyRealm::Global
            ),
            vec![WORKBUDDY_ENTERPRISE_USAGE_PATH]
        );
        assert_eq!(
            workbuddy_billing_path_candidates(WorkbuddyBillingEndpoint::Report, WorkbuddyRealm::Cn),
            vec![WORKBUDDY_REPORT_PATH]
        );
    }

    /// 连登状态解析 + 可兑换档位筛选：`locked`/`claimed` 必须排除（面板先看状态再兑换，
    /// 不拿 403 当控制流）；抽奖次数容忍数字/字符串/缺失。
    #[test]
    fn streak_status_and_lottery_chances_follow_the_panel_shape() {
        use super::{
            is_workbuddy_growth_unavailable, parse_workbuddy_lottery_chances,
            parse_workbuddy_streak_status,
        };

        let body = json!({
            "streak": {"days": 14, "month_total_days": 20, "next_tier": "28d", "next_tier_remaining": 14},
            "makeup_cards": {"balance": 2, "max": 3},
            "redemption_status": {
                "tier_7d_status": "claimed",
                "tier_14d_status": "unlocked",
                "tier_28d_status": "locked",
                "tiers": [
                    {"tier": "7d", "days": 7, "credit": 100, "energy": 5, "cards": 1, "chances": 1},
                    {"tier": "14d", "days": 14, "credit": 200, "energy": 10, "cards": 2, "chances": 2},
                    {"tier": "28d", "days": 28, "credit": 500, "energy": 20, "cards": 3, "chances": 3}
                ]
            }
        });
        let status = parse_workbuddy_streak_status(&body).expect("parsed");
        assert_eq!(status.days, 14);
        assert_eq!(status.month_total_days, 20);
        assert_eq!(status.makeup_cards, 2);
        assert_eq!(status.next_tier.as_deref(), Some("28d"));
        assert_eq!(status.next_tier_remaining, 14);
        assert_eq!(status.tiers.len(), 3);
        assert_eq!(status.tiers[1].credit, 200);
        // 只有 14d 既没 claimed 也没 locked。
        assert_eq!(status.redeemable_tiers(&body), vec!["14d".to_string()]);

        // 缺 streak 字段 → 不猜。
        assert!(parse_workbuddy_streak_status(&json!({"redemption_status": {}})).is_none());

        assert_eq!(parse_workbuddy_lottery_chances(&json!({"chances": 3})), 3);
        assert_eq!(parse_workbuddy_lottery_chances(&json!({"chances": "2"})), 2);
        assert_eq!(parse_workbuddy_lottery_chances(&json!({})), 0);

        // 403 = 没有成长体系（企业号 / 国际号）：不报警不重试。
        assert!(is_workbuddy_growth_unavailable(
            403,
            Some("growth system is only available for personal users")
        ));
        assert!(is_workbuddy_growth_unavailable(403, None));
        assert!(!is_workbuddy_growth_unavailable(403, Some("forbidden")));
        assert!(!is_workbuddy_growth_unavailable(500, Some("growth")));
    }

    /// **防退化保险**：任何一条改写若 `search == replace`（历史事故形态——两串看起来不同、
    /// 字节却相同，整条规则静默变空操作），这条测试立刻失败。
    #[test]
    fn template_rewrites_actually_change_something() {
        use super::WORKBUDDY_TEMPLATE_REWRITES;

        assert_eq!(WORKBUDDY_TEMPLATE_REWRITES.len(), 4);
        for rewrite in WORKBUDDY_TEMPLATE_REWRITES {
            assert_ne!(
                rewrite.search_text(),
                rewrite.replace_text(),
                "改写规则退化成空操作：{rewrite:?}"
            );
        }
    }

    /// 每条改写规则都必须**真的改写它自己的命中形态**（面板四条模板句测试的等价物）。
    ///
    /// 用规则自带的 `search_text()` 当输入、`replace_text()` 当期望：既不依赖手写近乎相同的
    /// 长串（本项目已多次因此写出「空过」的测试——输入写成替换形态、断言平凡通过），
    /// 又保证规则一旦退化成空操作就立刻失败。
    #[test]
    fn every_template_rewrite_rewrites_its_own_search_form() {
        use super::{sanitize_workbuddy_text, WORKBUDDY_TEMPLATE_REWRITES};

        for rewrite in WORKBUDDY_TEMPLATE_REWRITES {
            let search = rewrite.search_text();
            let replace = rewrite.replace_text();
            let out = sanitize_workbuddy_text(&search);
            assert_eq!(out, replace, "规则没生效：{search} -> {out}");
            assert!(!out.contains(&search), "命中形态必须消失：{out}");
        }
    }

    /// 身份句：CLI 版（句号收尾）与桌面版（逗号接 Agent SDK）都要改写，且**结尾标点保留**。
    /// 对齐面板 `TestIdentityRewritten` / `TestIdentityDesktopVariantRewritten`。
    #[test]
    fn identity_sentence_is_rewritten_in_both_cli_and_desktop_forms() {
        use super::sanitize_workbuddy_text;

        let cli = "You are Claude Code, Anthropic's official CLI for Claude.";
        let out = sanitize_workbuddy_text(cli);
        assert!(out.contains("official CLI tool for Claude"), "{out}");
        assert!(!out.contains("official CLI for Claude"), "{out}");
        assert!(out.ends_with('.'), "结尾标点必须原样保留：{out}");

        let desktop = "You are Claude Code, Anthropic's official CLI for Claude, running within the Claude Agent SDK.";
        let out = sanitize_workbuddy_text(desktop);
        assert!(
            out.contains("official CLI tool for Claude, running"),
            "{out}"
        );
    }

    /// 注入指令句 `Main branch (...)` → `Default branch (...)`（面板 `TestBranchRewritten`）。
    #[test]
    fn branch_sentence_is_rewritten() {
        use super::sanitize_workbuddy_text;

        let out = sanitize_workbuddy_text(&super::WORKBUDDY_TEMPLATE_REWRITES[1].search_text());
        assert_eq!(out, super::WORKBUDDY_TEMPLATE_REWRITES[1].replace_text());
    }

    /// 反馈句 `give` → `provide`（面板 `TestFeedbackSentenceRewritten`）。
    #[test]
    fn feedback_sentence_is_rewritten() {
        use super::sanitize_workbuddy_text;

        let out = sanitize_workbuddy_text(
            "To give feedback, users should report the issue at https://github.com/anthropics/claude-code/issues",
        );
        assert!(out.contains("To provide feedback"), "{out}");
        assert!(!out.contains("To give feedback"), "{out}");
    }

    /// Codex instructions 首段插 ` tool`（面板 `TestCodexInstructionsRewritten`）。
    #[test]
    fn codex_instructions_are_rewritten() {
        use super::sanitize_workbuddy_text;

        let out = sanitize_workbuddy_text(
            "You are a coding agent running in the Codex CLI, a terminal-based coding assistant.",
        );
        assert!(out.contains("Codex CLI tool,"), "{out}");
        assert!(!out.contains("Codex CLI,"), "{out}");
    }

    /// 上游反探测的**五位**错误码要改成插连字符的六字符形态；相邻错误码放行。
    /// 对齐面板 `TestUpstreamErrorCodeRewritten`（面板断言：输出**不含**裸五位码、**含**连字符形态）。
    #[test]
    fn upstream_error_code_is_rewritten_to_the_hyphenated_form() {
        use super::{
            sanitize_workbuddy_text, WORKBUDDY_BLOCKED_ERROR_CODE, WORKBUDDY_ERROR_CODE_VARIANT,
        };

        assert_ne!(WORKBUDDY_BLOCKED_ERROR_CODE, WORKBUDDY_ERROR_CODE_VARIANT);
        let input =
            format!("upstream returned code={WORKBUDDY_BLOCKED_ERROR_CODE} for this request");
        let out = sanitize_workbuddy_text(&input);
        assert!(!out.contains(WORKBUDDY_BLOCKED_ERROR_CODE), "{out}");
        assert!(out.contains(WORKBUDDY_ERROR_CODE_VARIANT), "{out}");

        // 相邻的 11101 / 11115 / 11135 不受影响（面板实测均放行）。
        let untouched = "code 11101 / 11115 / 11135";
        assert_eq!(sanitize_workbuddy_text(untouched), untouched);
    }

    /// 没有指纹的普通文本原样返回（面板 `TestNoFeatureReturnsSameString` / `TestUserFreeTextNotTouched`）。
    #[test]
    fn free_text_without_fingerprint_is_untouched() {
        use super::sanitize_workbuddy_text;

        for text in [
            "帮我写一个二分查找",
            "https://github.com/anthropics/claude-code/issues",
            "普通正文，没有指纹",
        ] {
            assert_eq!(sanitize_workbuddy_text(text), text);
        }
    }

    /// header 键值段整段剥离：与值无关、大小写不敏感（面板 `TestBillingHeaderStrippedValueIrrelevant` / `TestBillingHeaderCaseInsensitive`）。
    #[test]
    fn billing_header_is_stripped_regardless_of_value_and_case() {
        use super::sanitize_workbuddy_text;

        for text in [
            "x-anthropic-billing-hdr: abc123;\n正文",
            "X-Anthropic-Billing-Hdr: whatever-value;\n正文",
            "X-ANTHROPIC-BILLING-HDR: 1; 正文",
        ] {
            let out = sanitize_workbuddy_text(text);
            assert!(
                !out.to_ascii_lowercase().contains("billing-hdr"),
                "{text} -> {out}"
            );
        }
    }

    /// `cc_*` 尾随键值循环剥离（面板 `TestTrailingKVStripped`）。
    #[test]
    fn trailing_cc_kv_is_stripped() {
        use super::sanitize_workbuddy_text;

        let out = sanitize_workbuddy_text("cc_billing=1; 正文 cc_foo=2;");
        assert!(!out.contains("cc_billing"), "{out}");
        assert!(!out.contains("cc_foo"), "{out}");
        assert!(out.contains("正文"), "{out}");
    }

    /// 工具调用参数与 `reasoning`/`reasoning_content` 都要净化（面板
    /// `TestToolCallArgumentsSanitized` / `TestSanitizeMessagesScrubsReasoningField`）。
    #[test]
    fn tool_call_arguments_and_reasoning_fields_are_sanitized() {
        use super::{apply_workbuddy_fingerprint_sanitization, WORKBUDDY_BLOCKED_ERROR_CODE};

        // 错误码用常量拼：手写时极易把 5 位形态与插了连字符的 6 位形态打混，
        // 那样断言会**空过**（输入里根本没有被拦形态，测了等于没测）。
        let mut body = json!({
            "messages": [
                {
                    "role": "assistant",
                    "content": null,
                    "reasoning_content": "cc_billing=1; 推理",
                    "reasoning": format!("上游 returned code={WORKBUDDY_BLOCKED_ERROR_CODE}"),
                    "tool_calls": [{
                        "id": "call_1",
                        "type": "function",
                        "function": {
                            "name": "run",
                            "arguments": format!("{{\"cmd\":\"echo {WORKBUDDY_BLOCKED_ERROR_CODE}\"}}")
                        }
                    }]
                }
            ]
        });
        apply_workbuddy_fingerprint_sanitization(body.as_object_mut().expect("object"), None);
        let message = &body["messages"][0];
        let reasoning_content = message["reasoning_content"].as_str().expect("string");
        assert!(
            !reasoning_content.contains("cc_billing"),
            "{reasoning_content}"
        );
        assert!(reasoning_content.contains("推理"), "{reasoning_content}");
        let reasoning = message["reasoning"].as_str().expect("string");
        assert!(
            !reasoning.contains(WORKBUDDY_BLOCKED_ERROR_CODE),
            "{reasoning}"
        );
        assert!(
            reasoning.contains(super::WORKBUDDY_ERROR_CODE_VARIANT),
            "{reasoning}"
        );
        let arguments = message["tool_calls"][0]["function"]["arguments"]
            .as_str()
            .expect("string");
        assert!(
            !arguments.contains(WORKBUDDY_BLOCKED_ERROR_CODE),
            "{arguments}"
        );
        assert!(
            arguments.contains(super::WORKBUDDY_ERROR_CODE_VARIANT),
            "{arguments}"
        );
    }

    /// 多模态只动 `text` part，其它 part（图片等）不碰（面板 `TestMultimodalTextPartOnly`）。
    #[test]
    fn multimodal_only_text_parts_are_sanitized() {
        use super::apply_workbuddy_fingerprint_sanitization;

        let mut body = json!({
            "messages": [{
                "role": "user",
                "content": [
                    {"type": "text", "text": "cc_billing=1; 看图"},
                    {"type": "image_url", "image_url": {"url": "data:image/png;base64,cc_billing=1;"}}
                ]
            }]
        });
        apply_workbuddy_fingerprint_sanitization(body.as_object_mut().expect("object"), None);
        let parts = body["messages"][0]["content"].as_array().expect("array");
        assert!(!parts[0]["text"]
            .as_str()
            .expect("string")
            .contains("cc_billing"));
        // 图片 part 原样（面板只动 text part）。
        assert!(parts[1]["image_url"]["url"]
            .as_str()
            .expect("string")
            .contains("cc_billing"));
    }

    /// 指纹脱敏可关（`workbuddy_sanitize_fingerprints=false`）。
    #[test]
    fn fingerprint_sanitization_can_be_disabled() {
        use super::apply_workbuddy_fingerprint_sanitization;

        let mut body = json!({
            "messages": [{"role": "user", "content": "cc_billing=1; 正文"}]
        });
        apply_workbuddy_fingerprint_sanitization(
            body.as_object_mut().expect("object"),
            Some(&json!({"workbuddy_sanitize_fingerprints": false})),
        );
        assert!(body["messages"][0]["content"]
            .as_str()
            .expect("string")
            .contains("cc_billing"));
    }

    /// 会话/链路头族：ULID 形态 + 报告 §10.2 的三条相等关系 + §10.3.4 的 B3 全族。
    #[test]
    fn conversation_headers_follow_the_panel_rules() {
        use super::{
            insert_workbuddy_conversation_headers, is_workbuddy_b3_span_id, is_workbuddy_ulid,
        };
        use std::collections::BTreeMap;

        // ① 客户端什么都没给：用调用方给的稳定种子（trace id）派聚合主键，消息级现生成。
        let mut headers = BTreeMap::new();
        insert_workbuddy_conversation_headers(WorkbuddyRealm::Cn, &mut headers, Some("trace-abc"));
        let conv_req = headers
            .get("x-conversation-request-id")
            .expect("聚合主键必发")
            .clone();
        // 报告 §10.2：「ID 族为 ULID（毫秒时间戳前缀），不再是 UUID v4 simple」。
        assert!(
            is_workbuddy_ulid(&conv_req),
            "聚合主键必须是 ULID: {conv_req}"
        );
        let message_id = headers
            .get("x-conversation-message-id")
            .expect("消息级")
            .clone();
        assert!(is_workbuddy_ulid(&message_id), "消息级 id 必须是 ULID");
        assert_eq!(headers.get("x-request-id"), Some(&message_id));
        assert_eq!(headers.get("x-root-request-id"), Some(&conv_req));

        // §10.2 的三条相等关系：X-Request-ID == X-Conversation-Message-ID、
        // X-Root-Request-ID == X-Conversation-Request-ID、X-Trace-ID == X-B3-TraceId。
        let trace_id = headers.get("x-trace-id").expect("trace id").clone();
        assert_eq!(headers.get("x-b3-traceid"), Some(&trace_id));
        assert_eq!(trace_id.len(), 32, "B3 trace id 必须 32 hex");
        assert!(trace_id.chars().all(|c| c.is_ascii_hexdigit()));

        // §10.3.4：B3 全族（trace / span / parent span / sampled）+ W3C traceparent + b3 单头。
        let span_id = headers.get("x-b3-spanid").expect("span id").clone();
        assert!(is_workbuddy_b3_span_id(&span_id), "span id 必须 16 hex");
        let parent_span_id = headers.get("x-b3-parentspanid").expect("父 span 必须补齐");
        assert!(
            is_workbuddy_b3_span_id(parent_span_id),
            "父 span 必须 16 hex"
        );
        assert_ne!(parent_span_id, &span_id, "父 span 与自身 span 不应相同");
        assert_eq!(headers.get("x-b3-sampled").map(String::as_str), Some("1"));
        assert_eq!(
            headers.get("traceparent").map(String::as_str),
            Some(format!("00-{trace_id}-{span_id}-01").as_str())
        );
        assert_eq!(
            headers.get("b3").map(String::as_str),
            Some(format!("{trace_id}-{span_id}-1").as_str())
        );
        // 客户端没给会话 id → 不伪造。
        assert!(!headers.contains_key("x-conversation-id"));

        // ② 同一轮内稳定：同一种子两次调用得到同一个聚合主键（消息级各自新生成）。
        let mut again = BTreeMap::new();
        insert_workbuddy_conversation_headers(WorkbuddyRealm::Cn, &mut again, Some("trace-abc"));
        assert_eq!(
            again.get("x-conversation-request-id"),
            Some(&conv_req),
            "同一轮内聚合主键必须稳定"
        );
        assert_eq!(
            again.get("x-b3-traceid"),
            Some(&trace_id),
            "聚合主键稳定 ⇒ B3 trace id 也必须稳定（否则上游拆会话）"
        );
        assert_ne!(
            again.get("x-conversation-message-id"),
            headers.get("x-conversation-message-id"),
            "消息级每次尝试应新生成"
        );

        // ③ 客户端给了就透传（会话 id 与聚合主键都优先用客户端的）。
        let mut client = BTreeMap::from([
            ("x-conversation-id".to_string(), "conv-1".to_string()),
            (
                "x-conversation-request-id".to_string(),
                "abcdefabcdefabcdefabcdefabcdefab".to_string(),
            ),
        ]);
        insert_workbuddy_conversation_headers(WorkbuddyRealm::Cn, &mut client, Some("trace-abc"));
        assert_eq!(
            client.get("x-conversation-id").map(String::as_str),
            Some("conv-1")
        );
        assert_eq!(
            client.get("x-conversation-request-id").map(String::as_str),
            Some("abcdefabcdefabcdefabcdefabcdefab")
        );
        // 客户端给的是 32 hex → B3 trace id 原样用它（聚合语义不丢）。
        assert_eq!(
            client.get("x-b3-traceid").map(String::as_str),
            Some("abcdefabcdefabcdefabcdefabcdefab")
        );

        // ④ 聚合主键非法（非 hex / 长度不对）→ 由它确定性派生 32 hex，而不是回落消息 id。
        let mut dirty = BTreeMap::from([(
            "x-conversation-request-id".to_string(),
            "not-a-hex-value".to_string(),
        )]);
        insert_workbuddy_conversation_headers(WorkbuddyRealm::Cn, &mut dirty, None);
        let dirty_trace = dirty.get("x-b3-traceid").expect("trace id").clone();
        assert_eq!(dirty_trace.len(), 32);
        assert_ne!(
            Some(&dirty_trace),
            dirty.get("x-conversation-message-id"),
            "trace id 不应再回落成消息 id（两者语义不同）"
        );
        // 没有任何种子时也能生成（不 panic、形状合法）。
        let mut bare = BTreeMap::new();
        insert_workbuddy_conversation_headers(WorkbuddyRealm::Cn, &mut bare, None);
        assert!(is_workbuddy_ulid(
            bare.get("x-conversation-request-id").expect("聚合主键")
        ));
    }

    /// §10.2「ID 族为 ULID（毫秒时间戳前缀）」+ §10.3.4 的相等关系，独立钉一遍。
    ///
    /// 与会话头测试分开：那条测的是「头怎么发」，这条测的是「id 本身长什么样」，
    /// 任何一边回归都会单独变红。
    #[test]
    fn conversation_ids_are_ulids_with_millisecond_prefix() {
        use super::{
            is_workbuddy_ulid, workbuddy_new_ulid, workbuddy_ulid_from_seed,
            workbuddy_ulid_timestamp_ms,
        };

        // ① 形态：26 个 Crockford 字符。
        let ulid = workbuddy_new_ulid();
        assert!(is_workbuddy_ulid(&ulid), "ULID 形态非法: {ulid}");
        // ② 毫秒时间戳前缀：解出来的毫秒值必须贴着当前时间（±120s 容忍 CI 慢机）。
        let now_ms = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .expect("system clock")
            .as_millis() as u64;
        let stamped = workbuddy_ulid_timestamp_ms(&ulid).expect("ULID 必须带时间戳前缀");
        assert!(
            stamped.abs_diff(now_ms) < 120_000,
            "ULID 时间戳前缀不贴当前时间: {stamped} vs {now_ms}"
        );
        // ③ 单调：后生成的 ULID 时间戳不小于先生成的。
        let later = workbuddy_new_ulid();
        assert!(workbuddy_ulid_timestamp_ms(&later).expect("later") >= stamped);

        // ④ 种子派生是确定的（同一轮聚合主键必须恒等），且形态仍是 ULID。
        assert_eq!(
            workbuddy_ulid_from_seed("trace-1"),
            workbuddy_ulid_from_seed("trace-1")
        );
        assert_ne!(
            workbuddy_ulid_from_seed("trace-1"),
            workbuddy_ulid_from_seed("trace-2")
        );
        assert!(is_workbuddy_ulid(&workbuddy_ulid_from_seed("trace-1")));

        // ⑤ 非法形态一律拒绝（大写以外的字符、长度不对、首字符溢出）。
        assert!(!is_workbuddy_ulid(""));
        assert!(!is_workbuddy_ulid("abcdefabcdefabcdefabcdefab"));
        assert!(!is_workbuddy_ulid("0000000000000000000000000U"));
        assert!(!is_workbuddy_ulid("80000000000000000000000000"));
    }

    /// 门控：会话/链路头族只对 workbuddy 的 openai 系格式生效，别的 provider/格式一律不碰。
    #[test]
    fn conversation_header_wrapper_is_gated_to_workbuddy_openai_formats() {
        use super::insert_workbuddy_conversation_headers_if_needed;
        use std::collections::BTreeMap;

        let workbuddy = sample_transport("workbuddy");
        let mut headers = BTreeMap::new();
        insert_workbuddy_conversation_headers_if_needed(
            &workbuddy,
            "openai:chat",
            &mut headers,
            Some("trace-1"),
        );
        assert!(headers.contains_key("x-conversation-request-id"));
        assert!(headers.contains_key("x-b3-traceid"));

        // 非本 provider：空操作。
        let foreign = sample_transport("codex");
        let mut untouched = BTreeMap::new();
        insert_workbuddy_conversation_headers_if_needed(
            &foreign,
            "openai:chat",
            &mut untouched,
            Some("trace-1"),
        );
        assert!(untouched.is_empty());

        // 本 provider 但非 openai 系格式：空操作。
        let mut claude = BTreeMap::new();
        insert_workbuddy_conversation_headers_if_needed(
            &workbuddy,
            "claude:messages",
            &mut claude,
            Some("trace-1"),
        );
        assert!(claude.is_empty());
    }

    /// global 域兜底 system（面板 `ensureConsoleSystem`）：仅 global、首条非 system 才注入、
    /// 首条已是 system 不重复、空/缺失 messages 不动。
    #[test]
    fn global_realm_gets_a_console_fallback_system() {
        use super::{
            ensure_workbuddy_global_console_system, WorkbuddyRealm,
            WORKBUDDY_CONSOLE_FALLBACK_SYSTEM_PROMPT,
        };

        // global + 首条是 user → 注入到最前。
        let mut body = json!({"messages": [{"role": "user", "content": "hi"}]});
        ensure_workbuddy_global_console_system(
            body.as_object_mut().expect("object"),
            WorkbuddyRealm::Global,
        );
        let messages = body["messages"].as_array().expect("array");
        assert_eq!(messages.len(), 2);
        assert_eq!(messages[0]["role"], json!("system"));
        assert_eq!(
            messages[0]["content"],
            json!(WORKBUDDY_CONSOLE_FALLBACK_SYSTEM_PROMPT)
        );
        assert_eq!(messages[1]["role"], json!("user"));

        // global + 首条已是 system（大小写/空白容差）→ 不重复注入。
        let mut body = json!({"messages": [{"role": " System ", "content": "已有"}]});
        ensure_workbuddy_global_console_system(
            body.as_object_mut().expect("object"),
            WorkbuddyRealm::Global,
        );
        assert_eq!(body["messages"].as_array().expect("array").len(), 1);

        // CN → 现状不动（面板：仅对 global 请求调用）。
        let mut body = json!({"messages": [{"role": "user", "content": "hi"}]});
        ensure_workbuddy_global_console_system(
            body.as_object_mut().expect("object"),
            WorkbuddyRealm::Cn,
        );
        assert_eq!(body["messages"].as_array().expect("array").len(), 1);

        // 空 / 缺失 / 畸形 messages → 不动，不 panic。
        for mut body in [
            json!({"messages": []}),
            json!({}),
            json!({"messages": "oops"}),
            json!({"messages": [42]}),
        ] {
            ensure_workbuddy_global_console_system(
                body.as_object_mut().expect("object"),
                WorkbuddyRealm::Global,
            );
        }
    }

    /// 面板 `prepareBody` 里我先前漏掉的三步：gpt 下限钳制、`stream_options` 补全、
    /// tool pattern 转义还原。
    #[test]
    fn body_normalization_matches_the_panel_pipeline() {
        use super::{
            clamp_workbuddy_gpt_max_tokens, ensure_workbuddy_stream_options,
            unescape_workbuddy_tool_patterns, WORKBUDDY_GPT_MIN_MAX_TOKENS,
        };

        // ① gpt 系 max_tokens 过小 → 抬到下限；非 gpt 系不动。
        let mut body = json!({"model": "gpt-5-mini", "max_tokens": 4});
        clamp_workbuddy_gpt_max_tokens(body.as_object_mut().expect("object"));
        assert_eq!(body["max_tokens"], json!(WORKBUDDY_GPT_MIN_MAX_TOKENS));

        let mut body = json!({"model": "GLM-5.2", "max_tokens": 4});
        clamp_workbuddy_gpt_max_tokens(body.as_object_mut().expect("object"));
        assert_eq!(body["max_tokens"], json!(4), "非 gpt 系不该被改");

        let mut body = json!({"model": "gpt-5", "max_tokens": 4096});
        clamp_workbuddy_gpt_max_tokens(body.as_object_mut().expect("object"));
        assert_eq!(body["max_tokens"], json!(4096), "已达标不该被改");

        // ② stream_options：缺省补 include_usage，显式带则原样保留。
        let mut body = json!({"model": "glm-5.2"});
        ensure_workbuddy_stream_options(body.as_object_mut().expect("object"));
        assert_eq!(body["stream_options"], json!({"include_usage": true}));

        let mut body = json!({"stream_options": {"include_usage": false}});
        ensure_workbuddy_stream_options(body.as_object_mut().expect("object"));
        assert_eq!(
            body["stream_options"],
            json!({"include_usage": false}),
            "显式值必须保留"
        );

        // ③ tool pattern：`pattern` 值与 `patternProperties` 键里的 `\_` 都要还原。
        let mut body = json!({
            "tools": [{
                "type": "function",
                "function": {
                    "name": "f",
                    "parameters": {
                        "type": "object",
                        "properties": {"name": {"type": "string", "pattern": "^a\\_b$"}},
                        "patternProperties": {"^x\\_y$": {"type": "string"}}
                    }
                }
            }]
        });
        unescape_workbuddy_tool_patterns(body.as_object_mut().expect("object"));
        let parameters = &body["tools"][0]["function"]["parameters"];
        assert_eq!(parameters["properties"]["name"]["pattern"], json!("^a_b$"));
        assert!(
            parameters["patternProperties"]
                .as_object()
                .expect("object")
                .contains_key("^x_y$"),
            "patternProperties 的键也要还原：{}",
            parameters["patternProperties"]
        );
    }

    /// tool 配对三步（面板 `tool_pairing.go`）：合并背靠背声明、重排插入物、清孤儿。
    /// 每步都钉住面板注释里点名的反例形态。
    #[test]
    fn tool_pairing_normalization_follows_the_panel() {
        use super::normalize_workbuddy_tool_pairing;

        // ① 合并：背靠背两条 assistant.tool_calls（Codex Desktop 报文形态）→ 合成一条，
        //    调用顺序保持；reasoning_content 两边都有则换行拼接。
        let mut body = json!({"messages": [
            {"role": "assistant", "content": null, "reasoning_content": "r1",
             "tool_calls": [{"id": "c00", "type": "function", "function": {"name": "a", "arguments": "{}"}}]},
            {"role": "assistant", "content": [], "reasoning_content": "r2",
             "tool_calls": [{"id": "c01", "type": "function", "function": {"name": "b", "arguments": "{}"}}]},
            {"role": "tool", "tool_call_id": "c00", "content": "ok"},
            {"role": "tool", "tool_call_id": "c01", "content": "ok"}
        ]});
        normalize_workbuddy_tool_pairing(body.as_object_mut().expect("object"));
        let messages = body["messages"].as_array().expect("array");
        assert_eq!(messages.len(), 3, "两条 assistant 应合成一条：{messages:?}");
        let calls = messages[0]["tool_calls"].as_array().expect("calls");
        assert_eq!(calls.len(), 2);
        assert_eq!(calls[0]["id"], json!("c00"));
        assert_eq!(calls[1]["id"], json!("c01"));
        assert_eq!(messages[0]["reasoning_content"], json!("r1\nr2"));

        // ② 反向形态：纯正文 assistant 紧跟「带 tool_calls 且无正文」的 assistant → 折进前一条。
        let mut body = json!({"messages": [
            {"role": "assistant", "content": null,
             "tool_calls": [{"id": "c1", "type": "function", "function": {"name": "a", "arguments": "{}"}}]},
            {"role": "assistant", "content": "正文说明"},
            {"role": "tool", "tool_call_id": "c1", "content": "ok"}
        ]});
        normalize_workbuddy_tool_pairing(body.as_object_mut().expect("object"));
        let messages = body["messages"].as_array().expect("array");
        assert_eq!(messages.len(), 2);
        assert_eq!(messages[0]["content"], json!("正文说明"));
        assert_eq!(
            messages[0]["tool_calls"].as_array().expect("calls").len(),
            1
        );

        // ③ 重排：tool 结果中间插了非 tool 消息（Codex image_resize_notice）→ 挪到整组之后。
        let mut body = json!({"messages": [
            {"role": "user", "content": "hi"},
            {"role": "assistant", "content": null,
             "tool_calls": [
                {"id": "c1", "type": "function", "function": {"name": "a", "arguments": "{}"}},
                {"id": "c2", "type": "function", "function": {"name": "b", "arguments": "{}"}}
             ]},
            {"role": "tool", "tool_call_id": "c1", "content": "r1"},
            {"role": "developer", "content": "<image_resize_notice>"},
            {"role": "tool", "tool_call_id": "c2", "content": "r2"}
        ]});
        normalize_workbuddy_tool_pairing(body.as_object_mut().expect("object"));
        let messages = body["messages"].as_array().expect("array");
        let roles: Vec<&str> = messages
            .iter()
            .map(|message| message["role"].as_str().unwrap_or(""))
            .collect();
        assert_eq!(
            roles,
            vec!["user", "assistant", "tool", "tool", "developer"]
        );
        assert_eq!(messages[3]["tool_call_id"], json!("c2"));

        // ④ 清孤儿：无结果的调用被裁掉；无调用的结果被删；function.name 为空的调用一律删。
        let mut body = json!({"messages": [
            {"role": "assistant", "content": null,
             "tool_calls": [
                {"id": "c1", "type": "function", "function": {"name": "a", "arguments": "{}"}},
                {"id": "c2", "type": "function", "function": {"name": "b", "arguments": "{}"}},
                {"id": "c3", "type": "function", "function": {"name": "   ", "arguments": "{}"}}
             ]},
            {"role": "tool", "tool_call_id": "c1", "content": "r1"},
            {"role": "tool", "tool_call_id": "c3", "content": "r3"},
            {"role": "tool", "tool_call_id": "c9", "content": "孤儿结果"}
        ]});
        normalize_workbuddy_tool_pairing(body.as_object_mut().expect("object"));
        let messages = body["messages"].as_array().expect("array");
        let calls = messages[0]["tool_calls"].as_array().expect("calls");
        assert_eq!(calls.len(), 1, "只保留有结果且 name 非空的调用：{calls:?}");
        assert_eq!(calls[0]["id"], json!("c1"));
        let tool_ids: Vec<&str> = messages
            .iter()
            .filter(|message| message["role"] == json!("tool"))
            .map(|message| message["tool_call_id"].as_str().unwrap_or(""))
            .collect();
        assert_eq!(tool_ids, vec!["c1"], "孤儿结果与无主结果都要删");

        // ⑤ 整批无结果：整个 tool_calls 键被删（不留半截配对）。
        let mut body = json!({"messages": [
            {"role": "assistant", "content": null,
             "tool_calls": [{"id": "c1", "type": "function", "function": {"name": "a", "arguments": "{}"}}]},
            {"role": "user", "content": "接着来"}
        ]});
        normalize_workbuddy_tool_pairing(body.as_object_mut().expect("object"));
        assert!(
            body["messages"][0].get("tool_calls").is_none(),
            "无结果的整批调用要删键：{}",
            body["messages"][0]
        );

        // ⑥ 没有工具流量 → 一字不动。
        let mut body = json!({"messages": [
            {"role": "user", "content": "hi"},
            {"role": "assistant", "content": "hello"}
        ]});
        let before = body.clone();
        normalize_workbuddy_tool_pairing(body.as_object_mut().expect("object"));
        assert_eq!(body, before);
    }

    /// DeepSeek 思维链三件套（面板 `thinking.go`）：注入开关、档位降级、reasoning 回填。
    #[test]
    fn deepseek_thinking_chain_follows_the_panel() {
        use super::{
            backfill_workbuddy_reasoning_content, inject_workbuddy_thinking,
            normalize_workbuddy_reasoning_effort, WORKBUDDY_DEFAULT_DEEPSEEK_EFFORT,
        };

        // ① 注入：无 thinking 的 deepseek 请求 → enabled + 默认档；非 deepseek 一字不动。
        let mut body = json!({"model": "deepseek-v4-pro", "messages": []});
        inject_workbuddy_thinking(body.as_object_mut().expect("object"), None);
        assert_eq!(body["thinking"], json!({"type": "enabled"}));
        assert_eq!(
            body["reasoning_effort"],
            json!(WORKBUDDY_DEFAULT_DEEPSEEK_EFFORT)
        );

        let mut body = json!({"model": "glm-5.2"});
        inject_workbuddy_thinking(body.as_object_mut().expect("object"), None);
        assert!(body.get("thinking").is_none(), "非 deepseek 不注入：{body}");

        // ② 显式 disabled → 尊重并删掉两个 effort 字段（snake/camel 都删）。
        let mut body = json!({
            "model": "deepseek-v4-pro",
            "thinking": {"type": "disabled"},
            "reasoning_effort": "high",
            "reasoningEffort": "low"
        });
        inject_workbuddy_thinking(body.as_object_mut().expect("object"), None);
        assert_eq!(body["thinking"]["type"], json!("disabled"));
        assert!(body.get("reasoning_effort").is_none());
        assert!(body.get("reasoningEffort").is_none());

        // ③ 显式 enabled 缺档 → 补模型声明的默认档；已有档 → 不覆盖。
        let mut body = json!({"model": "deepseek-v4.1-flash", "thinking": {"type": "enabled"}});
        inject_workbuddy_thinking(body.as_object_mut().expect("object"), Some("medium"));
        assert_eq!(body["reasoning_effort"], json!("medium"));

        let mut body = json!({"model": "deepseek-r1", "reasoning_effort": "low"});
        inject_workbuddy_thinking(body.as_object_mut().expect("object"), Some("high"));
        assert_eq!(body["reasoning_effort"], json!("low"), "显式档位不覆盖");

        // ④ 档位降级：支持列表为空 → 透传；不支持 → 取 ≤ 请求档的最高档；全高 → 取最低档。
        let mut body = json!({"model": "deepseek-v4-pro", "reasoning_effort": "max"});
        normalize_workbuddy_reasoning_effort(body.as_object_mut().expect("object"), &[]);
        assert_eq!(body["reasoning_effort"], json!("max"), "无数据时不降级");

        let supported = vec!["low".to_string(), "high".to_string()];
        let mut body = json!({"model": "deepseek-v4-pro", "reasoning_effort": "max"});
        normalize_workbuddy_reasoning_effort(body.as_object_mut().expect("object"), &supported);
        assert_eq!(body["reasoning_effort"], json!("high"));

        let mut body = json!({"model": "deepseek-v4-pro", "reasoningEffort": "minimal"});
        normalize_workbuddy_reasoning_effort(body.as_object_mut().expect("object"), &supported);
        assert_eq!(body["reasoningEffort"], json!("low"), "全高时取最低支持档");

        let mut body = json!({"model": "deepseek-v4-pro", "reasoning_effort": "unknown-tier"});
        normalize_workbuddy_reasoning_effort(body.as_object_mut().expect("object"), &supported);
        assert_eq!(
            body["reasoning_effort"],
            json!("unknown-tier"),
            "未知档位透传"
        );

        // ⑤ 回填：deepseek + enabled → 每条 assistant 都有非空 reasoning 与非 string 归一。
        let mut body = json!({
            "model": "deepseek-v4-pro",
            "thinking": {"type": "enabled"},
            "messages": [
                {"role": "user", "content": "hi"},
                {"role": "assistant", "content": "a1", "reasoning": "思维链"},
                {"role": "assistant", "content": "a2", "reasoning_content": null}
            ]
        });
        backfill_workbuddy_reasoning_content(body.as_object_mut().expect("object"));
        let messages = body["messages"].as_array().expect("array");
        assert_eq!(
            messages[1]["reasoning_content"],
            json!("思维链"),
            "从 reasoning 复制"
        );
        assert_eq!(messages[1]["reasoning"], json!("思维链"));
        // null 不算「已有」→ 归一成字符串；两字段都空时 reasoning 补单个空格。
        assert_eq!(messages[2]["reasoning_content"], json!(""));
        assert_eq!(messages[2]["reasoning"], json!(" "));

        // 非 deepseek → 零改动。
        let mut body = json!({
            "model": "glm-5.2",
            "thinking": {"type": "enabled"},
            "messages": [{"role": "assistant", "content": "a"}]
        });
        let before = body.clone();
        backfill_workbuddy_reasoning_content(body.as_object_mut().expect("object"));
        assert_eq!(body, before);

        // deepseek + disabled + 无痕迹 → 零改动。
        let mut body = json!({
            "model": "deepseek-v4-pro",
            "thinking": {"type": "disabled"},
            "messages": [{"role": "assistant", "content": "a"}]
        });
        let before = body.clone();
        backfill_workbuddy_reasoning_content(body.as_object_mut().expect("object"));
        assert_eq!(body, before);
    }

    /// 端到端：key 元数据带档位表时，请求体的 `reasoning_effort` 被降级到模型支持的档位。
    /// （模型目录 → `upstream_metadata.workbuddy.models` → 请求体降级，整条链路。）
    #[test]
    fn request_body_downgrades_effort_from_key_metadata() {
        use super::apply_workbuddy_request_body_semantics;

        let mut transport = sample_transport("workbuddy");
        transport.provider.config = Some(json!({"workbuddy_prompt_mode": "passthrough"}));
        transport.key.upstream_metadata = Some(json!({
            "workbuddy": {
                "credits_used": 1.5,
                "models": {
                    "deepseek-v4-pro": {"efforts": ["low", "high"], "default_effort": "low"}
                }
            }
        }));
        let mut body = json!({
            "model": "deepseek-v4-pro",
            "reasoning_effort": "max",
            "messages": [{"role": "user", "content": "hi"}]
        });
        apply_workbuddy_request_body_semantics(&transport, "openai:chat", &mut body);
        assert_eq!(body["reasoning_effort"], json!("high"), "应按支持档降级");

        // 元数据里没有该模型 → 不降级（与面板「目录未命中一律透传」同口径）。
        let mut body = json!({
            "model": "glm-5.2",
            "reasoning_effort": "max",
            "messages": [{"role": "user", "content": "hi"}]
        });
        apply_workbuddy_request_body_semantics(&transport, "openai:chat", &mut body);
        assert_eq!(body["reasoning_effort"], json!("max"));

        // deepseek + 元数据里声明默认档 → 无 thinking 时注入 enabled 并补该默认档。
        let mut body = json!({
            "model": "deepseek-v4-pro",
            "messages": [{"role": "user", "content": "hi"}]
        });
        apply_workbuddy_request_body_semantics(&transport, "openai:chat", &mut body);
        assert_eq!(body["thinking"]["type"], json!("enabled"));
        assert_eq!(body["reasoning_effort"], json!("low"), "用模型声明的默认档");
    }

    /// prompt_cache_key 注入（面板 `cache_key.go`）：账号隔离、会话稳定、客户端值不覆盖。
    #[test]
    fn prompt_cache_key_is_injected_with_account_isolation() {
        use super::{apply_workbuddy_prompt_cache_key, workbuddy_prompt_cache_key};

        // 键形状：`wb2a-<uid8>-<32 hex>`，同账号同会话稳定、不同会话不同、跨账号不同。
        let key = workbuddy_prompt_cache_key("1234567890", "conv-1");
        assert!(key.starts_with("wb2a-12345678-"), "{key}");
        assert_eq!(key.len(), "wb2a-".len() + 8 + 1 + 32);
        assert_eq!(key, workbuddy_prompt_cache_key("1234567890", "conv-1"));
        assert_ne!(key, workbuddy_prompt_cache_key("1234567890", "conv-2"));
        assert_ne!(
            workbuddy_prompt_cache_key("1234567890", "conv-1"),
            workbuddy_prompt_cache_key("0987654321", "conv-1"),
            "跨账号必须不同（否则会命中别人的前缀缓存）"
        );

        // 注入：body 的会话字段优先；客户端已有 key 则绝不覆盖；非 workbuddy 不碰。
        let mut transport = sample_transport("workbuddy");
        transport.key.decrypted_auth_config =
            Some(json!({"uid": "u-123", "domain": "www.codebuddy.cn"}).to_string());
        let mut body = json!({"model": "glm-5.2", "conversation_id": "conv-a"});
        assert!(apply_workbuddy_prompt_cache_key(
            &transport,
            "openai:chat",
            &mut body,
            Some("header-conv")
        ));
        assert_eq!(
            body["prompt_cache_key"],
            json!(workbuddy_prompt_cache_key("u-123", "conv-a")),
            "body 的 conversation_id 优先于入站头"
        );

        let mut body = json!({"prompt_cache_key": "client-key"});
        assert!(!apply_workbuddy_prompt_cache_key(
            &transport,
            "openai:chat",
            &mut body,
            None
        ));
        assert_eq!(body["prompt_cache_key"], json!("client-key"));

        let foreign = sample_transport("codex");
        let mut body = json!({});
        assert!(!apply_workbuddy_prompt_cache_key(
            &foreign,
            "openai:chat",
            &mut body,
            None
        ));
        assert!(body.get("prompt_cache_key").is_none());
    }

    /// global 档位静态兜底：远端缺失时按产品表降级（CN 不吃这张表）。
    #[test]
    fn global_realm_uses_the_static_effort_fallback() {
        use super::{apply_workbuddy_request_body_semantics, workbuddy_global_effort_cap};

        // 表命中：deepseek-v4.1-flash 国际版只认 high → max 必须降级。
        let (efforts, default) = workbuddy_global_effort_cap("deepseek-v4.1-flash", &[], None);
        assert_eq!(efforts, vec!["high".to_string()]);
        assert_eq!(default, None);

        // 远端权威：非空时覆盖静态表。
        let (efforts, default) = workbuddy_global_effort_cap(
            "deepseek-v4.1-flash",
            &["low".to_string(), "high".to_string()],
            Some("low"),
        );
        assert_eq!(efforts, vec!["low".to_string(), "high".to_string()]);
        assert_eq!(default, Some("low".to_string()));

        // 表外模型：空（不降级）。
        let (efforts, _) = workbuddy_global_effort_cap("unknown-model", &[], None);
        assert!(efforts.is_empty());

        // 端到端：global realm 的账号（auth_config 里域为 workbuddy.ai）→ max 被降到 high。
        let mut transport = sample_transport("workbuddy");
        transport.provider.config = Some(json!({"workbuddy_prompt_mode": "passthrough"}));
        transport.endpoint.base_url = "https://www.workbuddy.ai".to_string();
        transport.key.decrypted_auth_config =
            Some(json!({"uid": "u-1", "domain": "www.workbuddy.ai"}).to_string());
        let mut body = json!({
            "model": "deepseek-v4.1-flash",
            "reasoning_effort": "max",
            "messages": [{"role": "user", "content": "hi"}]
        });
        apply_workbuddy_request_body_semantics(&transport, "openai:chat", &mut body);
        assert_eq!(
            body["reasoning_effort"],
            json!("high"),
            "global 域必须按静态表降级（否则上游 400）"
        );
    }

    /// 成长任务：列表宽松解析（progress 对象/平铺两种形态）、报名过滤、领奖解析。
    #[test]
    fn growth_tasks_parse_and_filter_like_the_panel() {
        use super::{parse_workbuddy_claim_reward, parse_workbuddy_tasks};

        let body = json!({"tasks": [
            // 平铺 progress，已达标未领 → claimable，且需要报名。
            {"task_code": "chat_3_times", "accept_status": "not_accepted",
             "current": 3, "target": 3, "reward_credit": 100},
            // progress 对象覆盖平铺字段（对象里 target 为正才覆盖）。
            {"task_code": "share_invite", "accept_status": "accepted",
             "current": 0, "target": 0, "progress": {"current": 1, "target": 2}},
            // 已领取 → 既不 claimable 也不需要报名。
            {"task_code": "RichMeow", "accept_status": "claimed", "current": 5, "target": 5},
            // 锁定 → 不报名。
            {"task_code": "Sequential_Tasks_1", "accept_status": "not_accepted", "locked": true},
            // 已完成（accept_status=completed）→ 不报名。
            {"task_code": "done_task", "accept_status": "completed", "current": 1, "target": 1},
            // 空 task_code → 丢弃。
            {"task_code": "  ", "accept_status": "not_accepted"}
        ]});
        let tasks = parse_workbuddy_tasks(&body);
        assert_eq!(tasks.len(), 5, "空 task_code 应被丢弃");

        let chat = &tasks[0];
        assert!(chat.claimable, "3/3 且未领 → 可领");
        assert!(chat.needs_accept(), "not_accepted → 需报名");

        let share = &tasks[1];
        assert_eq!(
            (share.current, share.target),
            (1, 2),
            "progress 对象覆盖平铺"
        );
        assert!(!share.claimable);
        assert!(!share.needs_accept(), "accepted → 不需报名");

        assert!(!tasks[2].claimable && !tasks[2].needs_accept(), "已领取");
        assert!(!tasks[3].needs_accept(), "锁定不报名");
        assert!(!tasks[4].needs_accept(), "completed 不报名");

        // 无 tasks / 畸形 → 空列表，不 panic。
        assert!(parse_workbuddy_tasks(&json!({})).is_empty());
        assert!(parse_workbuddy_tasks(&json!({"tasks": "oops"})).is_empty());

        // 领奖响应：credit/energy/already_claimed（数字与字符串都容忍）。
        assert_eq!(
            parse_workbuddy_claim_reward(&json!({"credit": 100, "energy": 5})),
            (100, 5, false)
        );
        assert_eq!(
            parse_workbuddy_claim_reward(&json!({"already_claimed": true, "credit": "0"})),
            (0, 0, true)
        );
    }

    /// 任务表 UI 的数据源：**面板同款字段**（`title` / `task_desc` / `reward_credit` /
    /// `reward_energy` / `task_type` / `tag` / `reward_buddy` / `jump_url`）都要解析出来。
    ///
    /// 用例取自真机任务中心（2026-10-15 用户贴出的实际清单），确认：
    /// - 一次性任务（`task_type == "single"`）能被识别——批次 2 的桌面事件**绝不重发**靠它；
    /// - `reward_buddy` 对应 UI 上的「+5 能 Buddy」；
    /// - 已领取 / 未解锁 的状态判定与列表一致。
    #[test]
    fn growth_tasks_parse_carries_the_catalog_fields_for_the_task_table() {
        use super::parse_workbuddy_tasks;

        let body = json!({"tasks": [
            {
                "task_code": "chat_5",
                "title": "和 AI 聊天 5 次",
                "task_desc": "累计发起 5 次对话",
                "description": "在对话框发送任意内容",
                "reward_credit": 100,
                "reward_energy": 5,
                "has_reward": true,
                "reward_buddy": false,
                "task_type": "single",
                "tag": "",
                "accept_status": "claimed",
                "current": 5,
                "target": 5
            },
            {
                "task_code": "template_5",
                "title": "使用 5 个模板",
                "reward_credit": 100,
                "reward_energy": 5,
                "task_type": "single",
                "tag": "PC",
                "accept_status": "claimed",
                "current": 5,
                "target": 5,
                "jump_url": "workbuddy://template"
            },
            {
                "task_code": "first_buddy",
                "title": "领取一只 Buddy",
                "reward_credit": 300,
                "reward_energy": 8,
                "reward_buddy": true,
                "task_type": "single",
                "accept_status": "claimed",
                "current": 1,
                "target": 1
            },
            {
                "task_code": "wb_wechat_oa_subscribe_task",
                "title": "关注「腾讯 WorkBuddy」官方公众号",
                "reward_credit": 100,
                "reward_energy": 5,
                "task_type": "single",
                "accept_status": "not_accepted",
                "current": 0,
                "target": 1
            },
            {
                "task_code": "Sequential_Tasks_6",
                "title": "完成 10次对话",
                "reward_credit": 100,
                "reward_energy": 5,
                "task_type": "single",
                "tag": "小程序限定",
                "accept_status": "not_accepted",
                "locked": true,
                "current": 0,
                "target": 10
            }
        ]});

        let tasks = parse_workbuddy_tasks(&body);
        assert_eq!(tasks.len(), 5);

        let chat = &tasks[0];
        assert_eq!(chat.title, "和 AI 聊天 5 次");
        assert_eq!(chat.task_desc, "累计发起 5 次对话");
        assert_eq!(chat.description, "在对话框发送任意内容");
        assert_eq!((chat.credit, chat.energy), (100, 5));
        assert!(chat.has_reward);
        assert!(!chat.reward_buddy);
        assert_eq!(chat.task_type, "single");
        assert!(chat.claimed, "accept_status=claimed");
        assert!(!chat.claimable, "已领取不算可领");

        let template = &tasks[1];
        assert_eq!(template.title, "使用 5 个模板");
        assert_eq!(template.tag, "PC");
        assert_eq!(template.jump_url, "workbuddy://template");

        let buddy = &tasks[2];
        assert!(buddy.reward_buddy, "reward_buddy 对应 UI 的「+5 能 Buddy」");
        assert_eq!((buddy.credit, buddy.energy), (300, 8));

        let subscribe = &tasks[3];
        assert_eq!(subscribe.title, "关注「腾讯 WorkBuddy」官方公众号");
        assert!(!subscribe.claimed && !subscribe.locked);
        assert!(!subscribe.claimable, "0/1 未达标");

        let chained = &tasks[4];
        assert!(chained.locked, "连锁任务未解锁");
        assert_eq!(chained.tag, "小程序限定");
        assert!(!chained.needs_accept(), "锁定任务不报名");
    }

    /// 设备风控头：provider config 里有就注入（对话与计费/成长都注入），没有/超长就不发。
    #[test]
    fn device_token_is_injected_only_when_configured() {
        use super::{insert_workbuddy_request_headers, workbuddy_identity};

        let mut transport = sample_transport("workbuddy");
        transport.key.decrypted_auth_config =
            Some(json!({"uid": "u-1", "domain": "www.codebuddy.cn"}).to_string());

        // 未配置 → 不发。
        let mut headers = std::collections::BTreeMap::new();
        insert_workbuddy_request_headers(&workbuddy_identity(&transport), &mut headers);
        assert!(!headers.contains_key("x-device-token"));

        // 配置了 → 两类请求都带上（头族本体统一注入，所以对话与计费走同一处）。
        transport.provider.config = Some(json!({"workbuddy_device_token": "  tok-123  "}));
        let mut headers = std::collections::BTreeMap::new();
        insert_workbuddy_request_headers(&workbuddy_identity(&transport), &mut headers);
        assert_eq!(
            headers.get("x-device-token").map(String::as_str),
            Some("tok-123")
        );

        // 超长（>1 KiB，面板视为异常）→ 不注入，但其它头照常。
        transport.provider.config = Some(json!({
            "workbuddy_device_token": "x".repeat(2048)
        }));
        let mut headers = std::collections::BTreeMap::new();
        insert_workbuddy_request_headers(&workbuddy_identity(&transport), &mut headers);
        assert!(!headers.contains_key("x-device-token"));
        assert!(headers.contains_key("x-codebuddy-request"));

        // 空白值 → 不注入。
        transport.provider.config = Some(json!({"workbuddy_device_token": "   "}));
        let mut headers = std::collections::BTreeMap::new();
        insert_workbuddy_request_headers(&workbuddy_identity(&transport), &mut headers);
        assert!(!headers.contains_key("x-device-token"));
    }

    /// 计费/成长域用**单段** UA，对话与官网领奖用三段式（面板 `billingUA()` 口径）。
    #[test]
    fn billing_scope_uses_the_single_segment_user_agent() {
        use super::{
            apply_workbuddy_billing_user_agent, workbuddy_billing_user_agent, workbuddy_user_agent,
            WorkbuddyRealm,
        };
        use std::collections::BTreeMap;

        let mut headers = BTreeMap::from([(
            "user-agent".to_string(),
            workbuddy_user_agent(WorkbuddyRealm::Cn),
        )]);
        apply_workbuddy_billing_user_agent(&mut headers);
        assert_eq!(
            headers.get("user-agent").map(String::as_str),
            Some(workbuddy_billing_user_agent().as_str())
        );
        assert!(!workbuddy_billing_user_agent().contains("CLI/"));
        assert!(workbuddy_user_agent(WorkbuddyRealm::Cn).contains("CLI/"));

        // 头族里没有 user-agent 时也要补上。
        let mut headers = BTreeMap::new();
        apply_workbuddy_billing_user_agent(&mut headers);
        assert!(headers.contains_key("user-agent"));
    }

    /// trial 判定（面板 `trialAlreadyErr`）：2xx = 新领成功；幂等码 14051（JSON 或文案
    /// 两种形态）算「已领过」；其余算失败。
    #[test]
    fn trial_outcome_follows_the_panel_idempotency_rule() {
        use super::{classify_workbuddy_trial_outcome, WorkbuddyTrialOutcome};

        assert_eq!(
            classify_workbuddy_trial_outcome(200, None),
            WorkbuddyTrialOutcome::Claimed
        );
        assert_eq!(
            classify_workbuddy_trial_outcome(204, Some("")),
            WorkbuddyTrialOutcome::Claimed
        );

        // 已领过：JSON 形态（含带空白的形态）与文案形态都要认。
        for body in [
            r#"{"code":14051,"msg":"already claimed"}"#,
            r#"{ "code" : 14051 }"#,
            r#"claim trial failed: code=14051"#,
        ] {
            assert_eq!(
                classify_workbuddy_trial_outcome(400, Some(body)),
                WorkbuddyTrialOutcome::AlreadyClaimed,
                "{body}"
            );
        }

        // 其它失败：不误判成幂等。
        for body in [
            r#"{"code":14000,"msg":"bad request"}"#,
            r#"{"code":14052}"#,
            "network error",
        ] {
            assert_eq!(
                classify_workbuddy_trial_outcome(400, Some(body)),
                WorkbuddyTrialOutcome::Failed,
                "{body}"
            );
        }
        assert_eq!(
            classify_workbuddy_trial_outcome(500, None),
            WorkbuddyTrialOutcome::Failed
        );
    }

    /// 旅行状态机：无猫→领养；到站→领奖（无 record_id 不领）；空闲且未达上限→派出；
    /// 在途/上限/未知→跳过。两处「宁可不做」的判断必须钉住。
    #[test]
    fn travel_action_follows_the_panel_state_machine() {
        use super::{
            decide_workbuddy_travel_action, parse_workbuddy_has_buddy,
            parse_workbuddy_travel_state, WorkbuddyTravelAction, WorkbuddyTravelState,
        };

        // 无猫 → 领养（即使上游给了状态也不看）。
        assert_eq!(
            decide_workbuddy_travel_action(false, None),
            WorkbuddyTravelAction::Adopt
        );
        // 有猫但状态缺失 → 跳过，不乱发请求。
        assert_eq!(
            decide_workbuddy_travel_action(true, None),
            WorkbuddyTravelAction::Skip { reason: "no_state" }
        );

        let arrived = WorkbuddyTravelState {
            state: "arrived".to_string(),
            record_id: 77,
            ..Default::default()
        };
        assert_eq!(
            decide_workbuddy_travel_action(true, Some(&arrived)),
            WorkbuddyTravelAction::Claim { record_id: 77 }
        );
        // 到站但没有 record_id：领奖必须带记录 id → 不领。
        let arrived_without_record = WorkbuddyTravelState {
            state: "arrived".to_string(),
            record_id: 0,
            ..Default::default()
        };
        assert_eq!(
            decide_workbuddy_travel_action(true, Some(&arrived_without_record)),
            WorkbuddyTravelAction::Skip {
                reason: "arrived_without_record"
            }
        );

        let idle = WorkbuddyTravelState {
            state: "idle".to_string(),
            ..Default::default()
        };
        assert_eq!(
            decide_workbuddy_travel_action(true, Some(&idle)),
            WorkbuddyTravelAction::Depart
        );
        // 今日已派出 → 不重复派（每日 1 次，CST 00:00 重置）。
        let idle_limited = WorkbuddyTravelState {
            state: "idle".to_string(),
            daily_limit_reached: true,
            ..Default::default()
        };
        assert_eq!(
            decide_workbuddy_travel_action(true, Some(&idle_limited)),
            WorkbuddyTravelAction::Skip {
                reason: "daily_limit"
            }
        );

        let traveling = WorkbuddyTravelState {
            state: "traveling".to_string(),
            ..Default::default()
        };
        assert_eq!(
            decide_workbuddy_travel_action(true, Some(&traveling)),
            WorkbuddyTravelAction::Skip {
                reason: "traveling"
            }
        );
        // 大小写/空白容差。
        let shouty = WorkbuddyTravelState {
            state: " ARRIVED ".to_string(),
            record_id: 5,
            ..Default::default()
        };
        assert_eq!(
            decide_workbuddy_travel_action(true, Some(&shouty)),
            WorkbuddyTravelAction::Claim { record_id: 5 }
        );

        // 解析：buddy 为 null / 缺字段 / 空对象都算无猫；有对象算有猫。
        assert!(!parse_workbuddy_has_buddy(&json!({"buddy": null})));
        assert!(!parse_workbuddy_has_buddy(&json!({})));
        assert!(!parse_workbuddy_has_buddy(&json!({"buddy": {}})));
        assert!(parse_workbuddy_has_buddy(
            &json!({"buddy": {"id": 1, "name": "喵"}})
        ));

        let parsed = parse_workbuddy_travel_state(&json!({
            "state": "arrived",
            "daily_limit_reached": true,
            "record_id": 12,
            "reward_credit": 30
        }))
        .expect("parsed");
        assert_eq!(parsed.state, "arrived");
        assert!(parsed.daily_limit_reached);
        assert_eq!(parsed.record_id, 12);
        assert_eq!(parsed.reward_credit, 30);
        // 非对象响应 → None（不猜）。
        assert!(parse_workbuddy_travel_state(&json!([1, 2])).is_none());

        // 领养门槛未达标：HTTP 400 + 固定文案；其它 400 不算。
        assert!(super::is_workbuddy_buddy_task_incomplete(
            400,
            Some(r#"{"code":400,"msg":"first_buddy task not completed yet"}"#)
        ));
        assert!(!super::is_workbuddy_buddy_task_incomplete(
            400,
            Some("invalid parameter")
        ));
        assert!(!super::is_workbuddy_buddy_task_incomplete(200, None));
    }

    /// CST 自然日与「昨天」：必须按 UTC+8 算，不能用宿主机时区（差一天就补错日子）。
    #[test]
    fn cst_dates_follow_utc_plus_eight() {
        use super::{workbuddy_cst_date, workbuddy_cst_yesterday};

        // 2026-10-13 12:00 UTC = 20:00 CST → 还是 13 号。
        assert_eq!(workbuddy_cst_date(1_791_892_800), "2026-10-13");
        // 2026-10-13 20:00 UTC = 次日 04:00 CST → 已经是 14 号。
        assert_eq!(workbuddy_cst_date(1_791_921_600), "2026-10-14");
        // 边界：2026-10-13 16:00 UTC = 14 号 00:00 CST。
        assert_eq!(workbuddy_cst_date(1_791_907_200), "2026-10-14");

        assert_eq!(workbuddy_cst_yesterday(1_791_892_800), "2026-10-12");
        // 跨 CST 午夜时「昨天」也要跟着翻。
        assert_eq!(workbuddy_cst_yesterday(1_791_921_600), "2026-10-13");
    }

    /// 漏签判断：只看昨天那一格且 `score == 0`；找不到那一格不算漏签。
    #[test]
    fn heatmap_yesterday_missed_requires_a_zero_score_cell() {
        use super::parse_workbuddy_heatmap_yesterday_missed;

        let body = json!({"cells": [
            {"date": "2026-10-11", "score": 3},
            {"date": "2026-10-12T00:00:00", "score": 0},
            {"date": "2026-10-13", "score": 1}
        ]});
        assert!(parse_workbuddy_heatmap_yesterday_missed(
            &body,
            "2026-10-12"
        ));

        let signed = json!({"cells": [{"date": "2026-10-12", "score": 2}]});
        assert!(!parse_workbuddy_heatmap_yesterday_missed(
            &signed,
            "2026-10-12"
        ));
        // 没有昨天那一格：不算漏签（宁可少补一次）。
        let missing = json!({"cells": [{"date": "2026-10-11", "score": 0}]});
        assert!(!parse_workbuddy_heatmap_yesterday_missed(
            &missing,
            "2026-10-12"
        ));
        assert!(!parse_workbuddy_heatmap_yesterday_missed(
            &json!({}),
            "2026-10-12"
        ));
    }

    #[test]
    fn claim_credit_tolerates_number_and_string() {
        use super::parse_workbuddy_claim_credit;

        assert_eq!(parse_workbuddy_claim_credit(&json!({"credit": 100})), 100);
        assert_eq!(parse_workbuddy_claim_credit(&json!({"credit": "50"})), 50);
        assert_eq!(parse_workbuddy_claim_credit(&json!({})), 0);
    }

    /// 幂等令牌：必须是 UUID 形态（面板 `randomUUID` 同款），且每次不同。
    #[test]
    fn client_token_is_a_fresh_uuid() {
        use super::workbuddy_client_token;

        let first = workbuddy_client_token();
        let second = workbuddy_client_token();
        assert_ne!(first, second, "每次调用都必须是新令牌");
        assert_eq!(first.len(), 36);
        assert_eq!(first.matches('-').count(), 4);
    }

    /// 降级闸门：触发后有效到次日 00:00 CST；期内再次触发**不续期**（面板同款）。
    #[test]
    fn degrade_gate_lasts_until_next_cst_midnight_without_extension() {
        let gate = WorkbuddyDegradeGate::new();
        // 2026-10-13 12:00:00 UTC = 20:00 CST → 次日 00:00 CST = 2026-10-13 16:00:00 UTC。
        let noon_utc = 1_791_892_800u64;
        assert!(!gate.active_at(noon_utc));
        gate.trigger_at(noon_utc);
        assert!(gate.active_at(noon_utc));
        assert!(gate.active_at(noon_utc + 3 * 3600));
        assert!(!gate.active_at(noon_utc + 4 * 3600), "应当已过期");
        assert_eq!(next_cst_midnight_unix_secs(noon_utc), noon_utc + 4 * 3600);

        // 降级期内再次触发：不续期（保持最早触发点的重置时刻）。
        let gate = WorkbuddyDegradeGate::new();
        gate.trigger_at(noon_utc);
        gate.trigger_at(noon_utc + 3600);
        assert!(!gate.active_at(noon_utc + 4 * 3600), "不续期：到期即失效");

        // 过期后再次触发：重新开一个窗口。
        gate.trigger_at(noon_utc + 5 * 3600);
        assert!(gate.active_at(noon_utc + 5 * 3600));
    }

    /// 边界：恰好 00:00 CST 触发 → 次日 00:00（不是「几秒后」）。
    #[test]
    fn next_cst_midnight_handles_the_midnight_boundary() {
        // 2026-10-13 00:00:00 CST = 2026-10-12 16:00:00 UTC。
        let midnight_cst = 1_791_820_800u64;
        assert_eq!(
            next_cst_midnight_unix_secs(midnight_cst),
            midnight_cst + 86_400
        );
        // 23:59:59 CST → 1 秒后。
        assert_eq!(
            next_cst_midnight_unix_secs(midnight_cst + 86_399),
            midnight_cst + 86_400
        );
    }

    /// 内容策略拦截判定：面板那三个 marker，HTTP >= 400 才算。
    #[test]
    fn content_blocked_detection_follows_the_panel_markers() {
        assert!(is_workbuddy_content_blocked(
            400,
            Some(r#"{"code":11-128,"msg":"blocked by security policy"}"#)
        ));
        assert!(is_workbuddy_content_blocked(
            400,
            Some("Illegal API invocation from an unapproved channel")
        ));
        // 403 的判定按面板顺序：**无业务信封**的 403 是 WAF 拦截形态，不是内容误报
        // （WAF 是 IP/边缘层问题，换提示词救不回来）；带信封的 403 才走内容策略。
        assert!(!is_workbuddy_content_blocked(
            403,
            Some("unapproved channel")
        ));
        assert!(is_workbuddy_content_blocked(
            403,
            Some(r#"{"code":11-128,"msg":"blocked by security policy"}"#)
        ));
        // 200 不算（哪怕是回显的正文）；无关的错误文案也不算。
        assert!(!is_workbuddy_content_blocked(
            200,
            Some("blocked by security policy")
        ));
        assert!(!is_workbuddy_content_blocked(400, Some("invalid model")));
        assert!(!is_workbuddy_content_blocked(400, None));
        // 429 + 审核文案：限流语义优先（状态码比关键词权威），不触发降级。
        assert!(!is_workbuddy_content_blocked(
            429,
            Some("blocked by security policy")
        ));
    }

    /// 降级期里的提示词裁决：append / passthrough 换成极简中性提示词并退化为替换；
    /// custom 不受影响（客户端指纹本来就已经被替换掉了）。
    #[test]
    fn degrade_window_swaps_append_and_passthrough_to_the_neutral_prompt() {
        let config = json!({
            "workbuddy_prompt_mode": "append",
            "workbuddy_prompt_text": "GATEWAY"
        });
        let body = || {
            json!({
                "messages": [
                    {"role": "system", "content": "You are Claude Code"},
                    {"role": "user", "content": "hi"}
                ]
            })
        };

        // 未降级：append 保留客户端 system。
        let mut object = body().as_object().cloned().expect("object");
        apply_workbuddy_prompt_policy(&mut object, Some(&config), false);
        let messages = object["messages"].as_array().expect("messages");
        assert_eq!(messages[0]["content"], "You are Claude Code");
        assert_eq!(messages[1]["content"], "GATEWAY");

        // 已降级：客户端 system 被中性提示词**替换**（带着指纹重试是确定性再撞墙）。
        let mut object = body().as_object().cloned().expect("object");
        apply_workbuddy_prompt_policy(&mut object, Some(&config), true);
        let messages = object["messages"].as_array().expect("messages");
        assert_eq!(messages.len(), 2);
        assert_eq!(messages[0]["content"], WORKBUDDY_DEGRADED_SYSTEM_PROMPT);
        assert_eq!(messages[1]["role"], "user");
        assert!(!serde_json::to_string(&object)
            .expect("json")
            .contains("Claude Code"));

        // passthrough + 降级：同样换成中性提示词。
        let passthrough = json!({"workbuddy_prompt_mode": "passthrough"});
        let mut object = body().as_object().cloned().expect("object");
        apply_workbuddy_prompt_policy(&mut object, Some(&passthrough), true);
        assert_eq!(
            object["messages"][0]["content"],
            WORKBUDDY_DEGRADED_SYSTEM_PROMPT
        );

        // custom：降级期不改变行为（仍用配置的提示词）。
        let custom = json!({"workbuddy_prompt_mode": "custom", "workbuddy_prompt_text": "MINE"});
        let mut object = body().as_object().cloned().expect("object");
        apply_workbuddy_prompt_policy(&mut object, Some(&custom), true);
        assert_eq!(object["messages"][0]["content"], "MINE");
    }

    /// 触发入口：只有「本 provider 的计划 + 内容拦截」才开窗口；本地闸门验证，
    /// 不碰进程级全局闸门（否则并行的提示词用例会看到降级期）。
    #[test]
    fn upstream_failure_observation_only_triggers_for_workbuddy_blocks() {
        let gate = WorkbuddyDegradeGate::new();
        let headers = std::collections::BTreeMap::from([(
            WORKBUDDY_INTERNAL_HEADER.to_string(),
            "1".to_string(),
        )]);

        // 无关的 4xx：不开窗口。
        assert!(
            !observe_workbuddy_upstream_failure_for_header_map_with_gate(
                &gate,
                &headers,
                400,
                Some(r#"{"msg":"invalid model"}"#)
            )
        );
        assert!(!gate.active_at(unix_now_secs()));

        // 内容策略拦截：开窗口。
        assert!(observe_workbuddy_upstream_failure_for_header_map_with_gate(
            &gate,
            &headers,
            400,
            Some(r#"{"code":11-128,"msg":"blocked by security policy"}"#)
        ));
        assert!(gate.active_at(unix_now_secs()));

        // 别的 provider 的计划（没有内部标记头）即使撞上同样的文案也不开窗口。
        let gate = WorkbuddyDegradeGate::new();
        let foreign = std::collections::BTreeMap::from([(
            "x-aether-grok-runtime".to_string(),
            "1".to_string(),
        )]);
        assert!(
            !observe_workbuddy_upstream_failure_for_header_map_with_gate(
                &gate,
                &foreign,
                400,
                Some("blocked by security policy")
            )
        );
        assert!(!gate.active_at(unix_now_secs()));
    }

    /// 构造指定域的样例快照（realm 由 key 的 `auth_config.realm` 解析）。
    fn sample_transport_with_realm(
        provider_type: &str,
        realm: WorkbuddyRealm,
    ) -> GatewayProviderTransportSnapshot {
        let mut transport = sample_transport(provider_type);
        transport.key.decrypted_auth_config =
            Some(json!({"uid": "uid-1", "realm": realm.as_str()}).to_string());
        transport
    }

    fn sample_transport(provider_type: &str) -> GatewayProviderTransportSnapshot {
        GatewayProviderTransportSnapshot {
            provider: GatewayProviderTransportProvider {
                id: "provider-1".to_string(),
                name: "Provider".to_string(),
                provider_type: provider_type.to_string(),
                website: None,
                is_active: true,
                keep_priority_on_conversion: false,
                enable_format_conversion: true,
                concurrent_limit: None,
                max_retries: None,
                proxy: None,
                request_timeout_secs: None,
                stream_first_byte_timeout_secs: None,
                config: None,
            },
            endpoint: GatewayProviderTransportEndpoint {
                id: "endpoint-1".to_string(),
                provider_id: "provider-1".to_string(),
                api_format: "openai:chat".to_string(),
                api_family: Some("openai".to_string()),
                endpoint_kind: Some("chat".to_string()),
                is_active: true,
                base_url: WORKBUDDY_CHAT_BASE_URL_CN.to_string(),
                header_rules: None,
                body_rules: None,
                max_retries: None,
                custom_path: Some(WORKBUDDY_CHAT_PATH.to_string()),
                config: None,
                format_acceptance_config: None,
                proxy: None,
            },
            key: GatewayProviderTransportKey {
                id: "key-1".to_string(),
                provider_id: "provider-1".to_string(),
                name: "Key".to_string(),
                auth_type: "oauth".to_string(),
                is_active: true,
                api_formats: Some(vec!["openai:chat".to_string()]),
                auth_type_by_format: None,
                allow_auth_channel_mismatch_formats: None,
                allowed_models: None,
                capabilities: None,
                rate_multipliers: None,
                global_priority_by_format: None,
                expires_at_unix_secs: None,
                proxy: None,
                fingerprint: None,
                upstream_metadata: None,
                decrypted_api_key: String::new(),
                decrypted_auth_config: Some(json!({"uid": "uid-1"}).to_string()),
            },
        }
    }
}
