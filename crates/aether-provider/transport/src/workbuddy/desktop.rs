//! 桌面客户端（WorkBuddy Desktop）行为指纹上报。
//!
//! 面板 `internal/upstream/desktop.go` 的 Rust 移植。**用途**：点亮「需电脑端」类
//! 成长任务（`RichMeow_Chat` / `template_5` / `create_canvas` / `expert_5` /
//! `Hp_Appearance` / `Library_read` …）。
//!
//! 关键认识（面板结论原话）：点亮这些任务的**不是**独立端点，而是**同一
//! `POST {chatBase}/v2/report` 通道上的不同客户端指纹**——每个事件除业务字段外
//! 必带桌面指纹（`ideName`/`ideType` = WorkBuddy、`extName` = workbuddy-desktop …），
//! 且**业务字段覆盖指纹**（面板 `ReportDesktopEvent` 先铺指纹再覆盖 ✓）。
//!
//! # 版本组合为什么是 5.5.6
//!
//! 桌面事件的指纹字段是一组**互相绑定**的常量：UA `WorkBuddy/5.5.6 …`、`ideVersion`/
//! `extVersion` = 5.5.6、`releaseDate` = 1789036585355、`commit` = `5f9692…`。
//! 面板正是在这套组合下三账号实测点亮的，所以这里**逐字段照抄**，而不是把我方
//! 对话通道的 5.5.4 混进来（混搭版本会自相矛盾，反而更像伪造）。
//!
//! # 一个重要的安全边界
//!
//! 这些事件是**模拟行为**：我们向上游声称「桌面端发生了这些动作」。调用方必须
//! **只对未完成且未领取的一次性任务**发一次（面板 `runAutoAll` 的守卫）：
//!
//! ```text
//! if before == nil                       → 跳过（该账号没有这个任务）
//! if before.Claimed || current >= target → 跳过（**一个请求都不发**）
//! ```
//!
//! 我方在 gateway 侧还有第二道闸：`maintenance.desktop_sent[]` 水位（发过就不再发），
//! 因为有些任务的进度回写有延迟，单靠任务状态可能在下一轮重复触发。

use serde_json::{json, Map, Value};
use sha2::{Digest, Sha256};
use std::sync::LazyLock;

use regex::Regex;

/// 桌面上报路径（对话域 `chatBase`，**不是**计费域——面板 `desktopBase` = chatBase）。
pub const WORKBUDDY_DESKTOP_REPORT_PATH: &str = "/v2/report";
/// 外观主题设置路径（同域）。
pub const WORKBUDDY_DESKTOP_APPEARANCE_SET_PATH: &str = "/v2/user-asset/appearance/set";
/// 专家市场列表路径（同域；`expert_actual_use` 的 id 必须是**平台真实存在**的专家）。
pub const WORKBUDDY_EXPERT_LIST_PATH: &str = "/portal/operation-platform/market/expert/list";

/// 桌面客户端 UA（面板实测值；与指纹里的 5.5.6 成套）。
pub const WORKBUDDY_DESKTOP_USER_AGENT: &str = "WorkBuddy/5.5.6 WorkBuddy/5.5.6 CLI/2.137.1";
/// 指纹里的桌面版本（与 UA 成套）。
const DESKTOP_IDE_VERSION: &str = "5.5.6";
/// 桌面版本（公开常量：请求头 `X-IDE-Version` 与 UA/指纹必须成套）。
pub const WORKBUDDY_DESKTOP_IDE_VERSION: &str = DESKTOP_IDE_VERSION;
/// 指纹里的桌面构建时间/提交（面板实测值，**不要单独改**）。
const DESKTOP_RELEASE_DATE: i64 = 1_789_036_585_355;
const DESKTOP_COMMIT: &str = "5f9692923c93033111c51ad7b003eb80204a9b75";

/// 桌面端事件：业务字段任意，公共指纹由 [`workbuddy_desktop_event_payload`] 注入。
pub type WorkbuddyDesktopEvent = Map<String, Value>;

/// 稳定派生 36 位 hex 设备标识（面板 `deriveID`：`hex(sha256(salt + ":" + uid))[:36]`）。
///
/// 幂等：同一 uid 每次得到同一设备指纹（模拟固定设备，而不是每轮换设备）。
pub fn workbuddy_derive_id(uid: &str, salt: &str) -> String {
    let mut hasher = Sha256::new();
    hasher.update(format!("{salt}:{uid}").as_bytes());
    let digest = hasher.finalize();
    let hex: String = digest.iter().map(|byte| format!("{byte:02x}")).collect();
    hex.chars().take(36).collect()
}

/// 公共桌面指纹（面板 `desktopFingerprint` 的逐字段对应）。
pub fn workbuddy_desktop_fingerprint(
    uid: &str,
    nickname: &str,
    now_millis: i64,
) -> WorkbuddyDesktopEvent {
    let mut event = Map::new();
    event.insert("timezone".to_string(), json!("Asia/Shanghai"));
    event.insert("reportDelay".to_string(), json!(2000));
    event.insert("userId".to_string(), json!(uid));
    event.insert("username".to_string(), json!(nickname));
    event.insert("userNickname".to_string(), json!(nickname));
    event.insert("product".to_string(), json!("SaaS"));
    event.insert("releaseDate".to_string(), json!(DESKTOP_RELEASE_DATE));
    event.insert("commit".to_string(), json!(DESKTOP_COMMIT));
    event.insert("ideName".to_string(), json!("WorkBuddy"));
    event.insert("ideType".to_string(), json!("WorkBuddy"));
    event.insert("ideVersion".to_string(), json!(DESKTOP_IDE_VERSION));
    event.insert(
        "machineId".to_string(),
        json!(workbuddy_derive_id(uid, "machine")),
    );
    event.insert(
        "sessionId".to_string(),
        json!(workbuddy_derive_id(uid, "session")),
    );
    event.insert("extName".to_string(), json!("workbuddy-desktop"));
    event.insert("extVersion".to_string(), json!(DESKTOP_IDE_VERSION));
    event.insert("os".to_string(), json!("win32"));
    event.insert("arch".to_string(), json!("x64"));
    event.insert("osVersion".to_string(), json!("10.0.26220"));
    event.insert("cpuCores".to_string(), json!(20));
    event.insert("memorySize".to_string(), json!(24));
    event.insert("timestamp".to_string(), json!(now_millis));
    event.insert("presentAt".to_string(), json!(now_millis));
    event
}

/// 把一组业务事件合成上报体：每个事件**先铺指纹、再覆盖业务字段**
/// （面板 `ReportDesktopEvent` 的同一顺序——业务字段里可以覆盖 `machineId` 等）。
pub fn workbuddy_desktop_event_payload(
    uid: &str,
    nickname: &str,
    now_millis: i64,
    events: &[WorkbuddyDesktopEvent],
) -> Value {
    let fingerprint = workbuddy_desktop_fingerprint(uid, nickname, now_millis);
    let merged: Vec<Value> = events
        .iter()
        .map(|event| {
            let mut combined = fingerprint.clone();
            for (key, value) in event {
                combined.insert(key.clone(), value.clone());
            }
            Value::Object(combined)
        })
        .collect();
    Value::Array(merged)
}

/// helper：构造一个事件（`eventCode` + 业务字段）。
fn event(code: &str, extra: Value) -> WorkbuddyDesktopEvent {
    let mut map = Map::new();
    map.insert("eventCode".to_string(), json!(code));
    if let Value::Object(extra) = extra {
        for (key, value) in extra {
            map.insert(key, value);
        }
    }
    map
}

/// 桌面端「成功对话」完整事件链（6 事件）。
///
/// 面板实测该链点亮 `RichMeow_Chat`（「桌面端对话1次」）；`isSuccessful=true` 与
/// `chat_message_status` 是判据的一部分（服务端对事件链有真实性校验倾向）。
pub fn workbuddy_desktop_chat_sequence(
    conversation_id: &str,
    request_id: &str,
    message_id: &str,
    model_id: &str,
    model_name: &str,
    now_millis: i64,
) -> Vec<WorkbuddyDesktopEvent> {
    let assistant_message = format!("{message_id}-assistant");
    let context = |extra: Value| {
        let mut base = json!({
            "traceId": request_id,
            "rootRequestId": request_id,
            "parentConversationId": conversation_id,
            "agentName": "cli",
            "agentType": "main",
        });
        if let (Value::Object(base_map), Value::Object(extra_map)) = (&mut base, extra) {
            for (key, value) in extra_map {
                base_map.insert(key, value);
            }
        }
        base
    };
    vec![
        event(
            "agent_task_created",
            json!({
                "source": "LOCAL", "name": "working", "task_target": "local", "mode": "craft",
                "requestModelId": model_id, "requestModelName": model_name,
                "has_repo": false, "repo_type": "none", "workspace_type": "empty",
                "has_connector": false, "connector_types": [],
                "has_mention": false, "mention_types": [],
                "has_template": false, "action": "", "template_name": "",
                "has_expert": false, "expert_id": "", "expert_name": "", "expert_industry_id": "",
                "has_skill": false, "skill_names": [],
                "conversationId": conversation_id, "messageId": message_id,
                "buddyId": "", "buddyName": "",
            }),
        ),
        event(
            "chat_message_send",
            context(json!({
                "messageId": assistant_message, "historyCount": 0,
                "isContextTruncated": false, "currentStepCount": 1,
            })),
        ),
        event(
            "chat_request_send",
            context(json!({
                "inputLength": 24, "isPlan": false, "isAutoExecuteTerminal": false,
                "isAutoModify": false, "codebaseEnable": false, "maxToken": 0,
                "maxSteps": 500, "temperature": 0, "maxRetries": 0,
                "mentionContexts": [], "knowledgeId": [], "knowledgeName": [],
                "codebaseId": "", "mentionContextCount": 0, "command": "",
                "recommendId": "", "skillId": "", "skillCount": 0, "totalCount": 0,
                "codebuddy.session_id": conversation_id,
                "codebuddy.conversation_request_id": request_id,
            })),
        ),
        event(
            "chat_message_response",
            context(json!({
                "messageId": assistant_message, "responseModelId": model_id,
                "inputToken": 120, "outputToken": 80, "totalToken": 200,
                "cachedTokens": 0, "cachedWriteTokens": 0, "cachedMissTokens": 0,
                "isSuccessful": true, "messageErrorCode": "", "finishReason": "stop",
                "firstTokenAt": now_millis, "conversationId": conversation_id,
                "codebuddy.session_id": conversation_id,
                "codebuddy.conversation_request_id": request_id,
            })),
        ),
        event(
            "chat_message_status",
            context(json!({
                "messageId": assistant_message, "messageErrorCode": "0",
            })),
        ),
        event(
            "chat_request_response",
            context(json!({
                "mode": "craft", "toolCallCount": 0,
                "inputToken": 120, "outputToken": 80, "totalToken": 200,
                "cachedTokens": 0, "cachedWriteTokens": 0, "cachedMissTokens": 0,
                "isSuccessful": true, "messageErrorCode": "", "finishReason": "stop",
            })),
        ),
    ]
}

/// 「进入 Buddy 应用」五连事件（点亮 `Buddy_App` 与 `Buddy_App_QQ`）。
///
/// 面板用**企鹅教师助手**（`cb_y5Dy46tPQGGWtueMxXbe`）作载体：它同时是
/// `Buddy_App_QQ` 的判据应用，又满足 `Buddy_App`「进入任一应用」。
pub fn workbuddy_desktop_buddy_app_sequence(
    buddy_id: &str,
    buddy_name: &str,
) -> Vec<WorkbuddyDesktopEvent> {
    let element = || json!({ "elementId": buddy_id, "elementName": buddy_name });
    let mut show = element();
    show["position"] = json!(2);
    let mut enter = element();
    enter["position"] = json!(2);
    enter["isFirstPage"] = json!("1");
    vec![
        event("buddyapp_discover_click", json!({ "mode": "LOCAL" })),
        event(
            "buddyapp_show",
            json!({ "mode": "LOCAL", "buddyId": buddy_id, "buddyName": buddy_name, "elementId": buddy_id, "elementName": buddy_name, "position": 2 }),
        ),
        event(
            "buddyapp_enter_click",
            json!({ "mode": "LOCAL", "buddyId": buddy_id, "buddyName": buddy_name, "elementId": buddy_id, "elementName": buddy_name, "position": 2, "isFirstPage": "1" }),
        ),
        event(
            "buddyapp_auth_confirm_click",
            json!({ "mode": "LOCAL", "buddyId": buddy_id, "buddyName": buddy_name, "elementId": buddy_id, "elementName": buddy_name }),
        ),
        event(
            "buddyapp_bindaccount_skip_click",
            json!({ "mode": "LOCAL", "buddyId": buddy_id, "buddyName": buddy_name, "elementId": buddy_id, "elementName": buddy_name }),
        ),
    ]
}

/// 「定时任务创建成功」事件（点亮 `automation_1`，**无需真实创建**）。
pub fn workbuddy_desktop_automation_create_event(name: &str) -> Vec<WorkbuddyDesktopEvent> {
    vec![event(
        "automated_task_create_suc",
        json!({
            "name": name, "source": "manually", "modelId": "fast-model",
            "modelIsThinking": true, "connectorCount": 0, "skills": "",
            "skillCount": 0, "scheduleType": "once", "mode": "LOCAL",
        }),
    )]
}

/// 「使用模板创建任务」事件组（`agent_task_created_with_template` + `template_used`
/// 接在完整 chat 链之后）。面板实测 5 组一次上报即 `template_5` 5/5。
pub fn workbuddy_desktop_template_use_sequence(
    conversation_id: &str,
    request_id: &str,
    template_id: &str,
    template_name: &str,
    now_millis: i64,
) -> Vec<WorkbuddyDesktopEvent> {
    let mut events = workbuddy_desktop_chat_sequence(
        conversation_id,
        request_id,
        &format!("msg-{template_id}"),
        "fast-model",
        "fast-model",
        now_millis,
    );
    events.push(event(
        "agent_task_created_with_template",
        json!({
            "mode": "working", "isCustomModel": false, "id": template_id,
            "name": template_name, "requestId": request_id,
        }),
    ));
    events.push(event(
        "template_used",
        json!({ "template_id": template_id, "task_mode": "working" }),
    ));
    events
}

/// 「灵感案例做同款」事件组（`web_element_click(playbook_ctaClick)` +
/// `playbook_cta_click` + `playbook_prompt_send`，接在 chat 链之后）。
pub fn workbuddy_desktop_playbook_prompt_sequence(
    conversation_id: &str,
    request_id: &str,
    case_id: &str,
    case_name: &str,
    now_millis: i64,
) -> Vec<WorkbuddyDesktopEvent> {
    let mut events = workbuddy_desktop_chat_sequence(
        conversation_id,
        request_id,
        "msg-pb",
        "fast-model",
        "fast-model",
        now_millis,
    );
    let case = json!({
        "id": case_id, "name": case_name, "type": "document",
        "categoryId": "", "categoryName": "",
    });
    events.push(event(
        "web_element_click",
        json!({
            "pageName": "playbook_detail", "elementId": "playbook_ctaClick",
            "elementName": case_name, "source": "discover",
        }),
    ));
    let mut cta = json!({ "source": "discover", "position": 0 });
    if let (Value::Object(cta_map), Value::Object(case_map)) = (&mut cta, case.clone()) {
        for (key, value) in case_map {
            cta_map.insert(key, value);
        }
    }
    events.push(event("playbook_cta_click", cta));
    let mut send = json!({ "conversationId": conversation_id, "requestId": request_id });
    if let (Value::Object(send_map), Value::Object(case_map)) = (&mut send, case) {
        for (key, value) in case_map {
            send_map.insert(key, value);
        }
    }
    events.push(event("playbook_prompt_send", send));
    events
}

/// 「设计创意画布」事件组（`wbx_design_canvas_task_create` + `wbx_design_canvas_open`，
/// 接在 chat 链之后）。点亮 `create_canvas`（+300 分）。
pub fn workbuddy_desktop_design_canvas_sequence(
    conversation_id: &str,
    request_id: &str,
    now_millis: i64,
) -> Vec<WorkbuddyDesktopEvent> {
    let mut events = workbuddy_desktop_chat_sequence(
        conversation_id,
        request_id,
        "msg-canvas",
        "fast-model",
        "fast-model",
        now_millis,
    );
    events.push(event(
        "wbx_design_canvas_task_create",
        json!({
            "conversationId": conversation_id, "requestId": request_id,
            "source": "summon_keyword", "cost": 12000, "isSuccessful": true,
        }),
    ));
    let suffix = request_id
        .chars()
        .rev()
        .take(8)
        .collect::<String>()
        .chars()
        .rev()
        .collect::<String>();
    events.push(event(
        "wbx_design_canvas_open",
        json!({
            "conversationId": conversation_id, "requestId": request_id,
            "id": format!("ardot-file-{suffix}"), "source": "summon_keyword",
            "type": "page", "cost": 13000, "isSuccessful": true,
        }),
    ));
    events
}

/// 专家市场的一个专家（`/portal/operation-platform/market/expert/list` 响应子集）。
#[derive(Debug, Clone, Default)]
pub struct WorkbuddyMarketExpert {
    pub expert_id: String,
    pub expert_type: String,
    pub display_name_zh: String,
    pub profession_zh: String,
    pub version: String,
}

impl WorkbuddyMarketExpert {
    /// 面板 `MarketExpertList` 的宽松解析（字段缺失即空串）。
    pub fn from_value(value: &Value) -> Self {
        let text = |key: &str| {
            value
                .get(key)
                .and_then(Value::as_str)
                .unwrap_or_default()
                .trim()
                .to_string()
        };
        Self {
            expert_id: text("expert_id"),
            expert_type: text("expert_type"),
            display_name_zh: text("display_name_zh"),
            profession_zh: text("profession_zh"),
            version: text("version"),
        }
    }

    fn version_or_default(&self) -> &str {
        if self.version.trim().is_empty() {
            "1.0.0"
        } else {
            &self.version
        }
    }
}

/// 从专家列表响应里解出专家数组（面板 `MarketExpertList` 的 `experts` 字段）。
pub fn parse_workbuddy_market_experts(body: &Value) -> Vec<WorkbuddyMarketExpert> {
    body.get("experts")
        .and_then(Value::as_array)
        .map(|experts| {
            experts
                .iter()
                .map(WorkbuddyMarketExpert::from_value)
                .collect()
        })
        .unwrap_or_default()
}

/// 「召唤平台专家」事件组（`web_element_click` + `expert_summon_click` + `expert_summoned`）。
pub fn workbuddy_desktop_expert_summon_sequence(
    expert: &WorkbuddyMarketExpert,
) -> Vec<WorkbuddyDesktopEvent> {
    let version = expert.version_or_default().to_string();
    vec![
        event(
            "web_element_click",
            json!({
                "source": expert.expert_id, "type": "expert-all", "version": version,
                "elementId": "expert_summon_click", "elementName": "召唤专家",
                "pageURL": "/C:/Program%20Files/WorkBuddy/resources/app.asar/renderer/index.html",
            }),
        ),
        event(
            "expert_summon_click",
            json!({
                "id": expert.expert_id, "name": expert.display_name_zh,
                "expertTitle": expert.profession_zh, "type": "expert-all", "position": 0,
                "expertType": expert.expert_type, "version": version, "mode": "LOCAL",
            }),
        ),
        event(
            "expert_summoned",
            json!({
                "id": expert.expert_id, "name": expert.display_name_zh,
                "expertTitle": expert.profession_zh, "type": "expert-all",
            }),
        ),
    ]
}

/// `expert_actual_use` 事件。
///
/// **`request_id` 必须是真实对话的服务端 id**（自造 UUID 不计数，面板 Sunny row 2113
/// 实证）；`mode` 为 `craft`（`expert_5`/`Expert_team_use_3`）或 `LOCAL`
/// （`Expert_lighthouse`，其 `type` 为空、`cost` 为 0）。
pub fn workbuddy_desktop_expert_actual_use_event(
    expert: &WorkbuddyMarketExpert,
    conversation_id: &str,
    request_id: &str,
    mode: &str,
    expert_type_label: &str,
    cost: i64,
) -> WorkbuddyDesktopEvent {
    let version = expert.version_or_default().to_string();
    let suffix = request_id
        .chars()
        .rev()
        .take(8)
        .collect::<String>()
        .chars()
        .rev()
        .collect::<String>();
    event(
        "expert_actual_use",
        json!({
            "id": expert.expert_id, "name": expert.display_name_zh,
            "expertTitle": expert.profession_zh, "type": expert_type_label,
            "expertType": expert.expert_type, "source": "builtin", "version": version,
            "cost": cost, "characterCount": 14,
            "conversationId": conversation_id, "requestId": request_id,
            "messageId": format!("msg-{suffix}"),
            "requestModelId": "fast-model", "requestModelName": "fast-model",
            "mode": mode,
        }),
    )
}

/// 皮肤生效事件（`appearance_skin_apply`）——`Hp_Appearance` 的判据。
///
/// 面板结论（早前「纯 API set 不计分」的说法**不准确**）：真相是当时只调了
/// `appearance/set` 而没发这个事件；**组合**（set API 留痕 + 事件上报）才点亮。
pub fn workbuddy_desktop_appearance_apply_event(theme_key: &str) -> WorkbuddyDesktopEvent {
    event(
        "appearance_skin_apply",
        json!({
            "action": "apply", "source": "settings_close", "id": theme_key,
            "vipLevel": 0, "series": "", "type": "unknown",
        }),
    )
}

/// `Hp_Appearance` 判据主题（和平精英激战金秋）。
pub const WORKBUDDY_APPEARANCE_THEME_KEY: &str = "theme-tkmw7j";
/// `Buddy_App` 载体应用（企鹅教师助手，同时满足 `Buddy_App_QQ`）。
pub const WORKBUDDY_BUDDY_APP_ID: &str = "cb_y5Dy46tPQGGWtueMxXbe";
pub const WORKBUDDY_BUDDY_APP_NAME: &str = "企鹅教师助手";
/// `Expert_lighthouse` 判据专家（腾讯轻量云专家）。
pub const WORKBUDDY_LIGHTHOUSE_EXPERT_ID: &str = "ex_2cvvUZQhDyeJ";

/// Web 端事件（浏览器形状指纹，**另一个域**：`www.workbuddy.cn/v2/report`）。
///
/// 用于 `Library_read` 这类**页面行为**任务：面板实测 `library_doc_intro_click` 4 秒点亮。
///
/// 参数多是因为这一个事件的形状本身就宽（事件码 + 页面 + 元素 + 用户身份三元组 + 时间戳），
/// 打包成结构体只会在唯一调用点来回拆包，故平铺并 allow（与 oauth 侧 `refresh_with_token` 同款处理）。
#[allow(clippy::too_many_arguments)]
pub fn workbuddy_web_event_payload(
    event_code: &str,
    page_url: &str,
    element_id: &str,
    element_name: &str,
    uid: &str,
    nickname: &str,
    enterprise_id: &str,
    now_millis: i64,
) -> Value {
    let user_agent = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/152.0.0.0 Safari/537.36";
    json!([{
        "eventCode": event_code,
        "timestamp": now_millis,
        "reportDelay": 0,
        "pageURL": page_url,
        "elementId": element_id,
        "elementName": element_name,
        "os": "Win32",
        "arch": "",
        "osVersion": "10.0",
        "userAgent": user_agent,
        "machineId": workbuddy_derive_id(uid, "webmachine"),
        "userId": uid,
        "userNickname": nickname,
        "enterpriseId": enterprise_id,
    }])
}

/// `Library_read` 判据文档页（面板实测值）。
pub const WORKBUDDY_LIBRARY_DOC_URL: &str =
    "https://www.workbuddy.cn/space/d/o0KWYeynteVv06UnAZqIFm";
pub const WORKBUDDY_LIBRARY_ELEMENT_ID: &str = "library_doc_intro_click";
pub const WORKBUDDY_LIBRARY_ELEMENT_NAME: &str = "WorkBuddy资料库介绍";

// ---------------------------------------------------------------------------
// Tier 2：需要**真实对话**才能点亮的动作（`skill_1` / `expert_*` / `black_cat`）
// ---------------------------------------------------------------------------
//
// 硬约束（面板 Sunny row 2113 实证）：`expert_actual_use` 这类 JOIN 事件的
// `requestId` **必须是真实对话的服务端 id**（`cmb-…` 或 32 位 hex）——自造 UUID
// 不计数。所以流程是「真发一次对话 → 从 SSE 流里取服务端 id → 再用它发事件」。

/// `skill_1`（尝鲜热门技能）用的技能（面板抓包 row 209 原文，实测能点亮）。
pub const WORKBUDDY_SKILL_INFO_NAME: &str = "润泽小馆·日报撰写";
pub const WORKBUDDY_SKILL_INFO_ID: &str = "skill_2097350077599879168";
pub const WORKBUDDY_SKILL_INFO_VERSION: &str = "1.0.0";

/// `skill_1` 的 `skill_info` 事件。
///
/// 判据（面板 `autotask.go:905-909`，2026-09-12 人工抓包 row 209）：
/// **只有** `skill_info` 这一种形状能点亮——面板原话「此前的 `skill_request_send` /
/// `skill_installed` / `skill_action` **全是错误方向**」；且必须 JOIN 真实会话
/// （`conversationId` / `requestId` = 服务端 id）。
pub fn workbuddy_desktop_skill_info_event(
    conversation_id: &str,
    request_id: &str,
    message_id: &str,
) -> WorkbuddyDesktopEvent {
    event(
        "skill_info",
        json!({
            "id": WORKBUDDY_SKILL_INFO_NAME,
            "skillId": WORKBUDDY_SKILL_INFO_ID,
            "skillVersion": WORKBUDDY_SKILL_INFO_VERSION,
            "toolStatus": "success",
            "fileCount": 56,
            "source": "workbuddy-desktop",
            "conversationId": conversation_id,
            "requestId": request_id,
            "messageId": message_id,
            "requestModelId": "fast-model",
            "requestModelName": "fast-model",
            "traceId": request_id,
        }),
    )
}

/// 把 `chat_message_response` 标成 `finishReason: "tool_calls"`（技能加载语义，面板同款）。
pub fn workbuddy_desktop_mark_tool_calls(events: &mut [WorkbuddyDesktopEvent]) {
    for event in events.iter_mut() {
        if event.get("eventCode").and_then(Value::as_str) == Some("chat_message_response") {
            event.insert("finishReason".to_string(), json!("tool_calls"));
        }
    }
}

/// Tier 2 真实对话的请求体（面板 `DesktopChatWithExpert` 逐字段对应）。
///
/// 刻意用最小对话（`1+1` 级别）与 `fast-model`：这类请求的目的是**拿到服务端 id**，
/// 不是为了回答质量；`stream: true` + `stream_options.include_usage` 与面板一致。
pub fn workbuddy_desktop_chat_request_body(prompt: &str) -> Value {
    json!({
        "model": "fast-model",
        "messages": [
            {
                "role": "system",
                "content": "You are a helpful assistant. 当前处于中文环境，使用简体中文回答。",
            },
            {
                "role": "user",
                "content": if prompt.trim().is_empty() { "1+1等于几？直接回答。" } else { prompt },
            },
        ],
        "agent": "cli",
        "temperature": 1,
        "stream": true,
        "stream_options": { "include_usage": true },
    })
}

/// 判断一个 id 是否是上游**服务端**的 requestId 形态（面板 `idRegex`）。
pub fn workbuddy_is_server_request_id(value: &str) -> bool {
    static RE: LazyLock<Regex> = LazyLock::new(|| {
        // `^(cmb-)?[0-9a-f]{32}$`（面板 idRegex 逐字节对应）。
        Regex::new(r"^(cmb-)?[0-9a-f]{32}$").expect("workbuddy server request id regex")
    });
    RE.is_match(value.trim())
}

/// 从 SSE 文本里取**第一个**匹配服务端形态的 `"id":"<id>"`。
///
/// 面板的坑（`DesktopChatWithExpert` 注释原话）：SSE 里 `"id":"` 可能先出现在
/// **消息 id** 等字段上；若不推进搜索偏移，首个不匹配的 id 会让循环永远命中同一位置、
/// 读满缓冲后误报「未找到 requestId」。所以这里**每命中一次就推进一格**再继续找。
pub fn workbuddy_parse_server_request_id(sse_text: &str) -> Option<String> {
    let mut search_from = 0usize;
    while let Some(offset) = sse_text[search_from..].find("\"id\":\"") {
        let start = search_from + offset + "\"id\":\"".len();
        let rest = &sse_text[start..];
        if let Some(end) = rest.find('"') {
            let candidate = &rest[..end];
            if workbuddy_is_server_request_id(candidate) {
                return Some(candidate.trim().to_string());
            }
            // 不匹配 → 推进到该 id 之后，避免在同一位置反复命中（面板同款）。
            search_from = start + end.max(1);
            continue;
        }
        break;
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;

    /// `deriveID` 必须与面板逐字节一致：`hex(sha256(salt + ":" + uid))[:36]`。
    #[test]
    fn derive_id_matches_the_panel_formula() {
        let uid = "uid-abc";
        let mut hasher = Sha256::new();
        hasher.update(b"machine:uid-abc");
        let digest = hasher.finalize();
        let expected: String = digest
            .iter()
            .map(|byte| format!("{byte:02x}"))
            .collect::<String>()
            .chars()
            .take(36)
            .collect();
        assert_eq!(workbuddy_derive_id(uid, "machine"), expected);
        assert_eq!(workbuddy_derive_id(uid, "machine").len(), 36);
        // 幂等 + 换盐换值（固定设备语义）。
        assert_eq!(
            workbuddy_derive_id(uid, "machine"),
            workbuddy_derive_id(uid, "machine")
        );
        assert_ne!(
            workbuddy_derive_id(uid, "machine"),
            workbuddy_derive_id(uid, "session")
        );
        assert_ne!(
            workbuddy_derive_id(uid, "machine"),
            workbuddy_derive_id("uid-other", "machine")
        );
    }

    /// 指纹字段与面板逐项对应；业务字段**覆盖**指纹（面板同款顺序）。
    #[test]
    fn fingerprint_fields_match_the_panel_and_business_fields_win() {
        let fingerprint = workbuddy_desktop_fingerprint("uid-1", "昵称", 1_700_000_000_000);
        for key in [
            "timezone",
            "reportDelay",
            "userId",
            "username",
            "userNickname",
            "product",
            "releaseDate",
            "commit",
            "ideName",
            "ideType",
            "ideVersion",
            "machineId",
            "sessionId",
            "extName",
            "extVersion",
            "os",
            "arch",
            "osVersion",
            "cpuCores",
            "memorySize",
            "timestamp",
            "presentAt",
        ] {
            assert!(fingerprint.contains_key(key), "指纹缺字段 {key}");
        }
        assert_eq!(fingerprint["ideName"], json!("WorkBuddy"));
        assert_eq!(fingerprint["extName"], json!("workbuddy-desktop"));
        assert_eq!(fingerprint["ideVersion"], json!("5.5.6"));
        assert_eq!(fingerprint["releaseDate"], json!(1_789_036_585_355i64));
        assert_eq!(fingerprint["cpuCores"], json!(20));

        // 业务字段覆盖指纹：同名键以业务值为准。
        let payload = workbuddy_desktop_event_payload(
            "uid-1",
            "昵称",
            1_700_000_000_000,
            &[event("machine", json!({ "machineId": "business-wins" }))],
        );
        let first = &payload.as_array().expect("数组")[0];
        assert_eq!(first["machineId"], json!("business-wins"));
        assert_eq!(first["eventCode"], json!("machine"));
    }

    /// 桌面 chat 链：6 事件的顺序与关键判据字段（`isSuccessful` / `finishReason`）。
    #[test]
    fn desktop_chat_sequence_matches_the_panel_event_chain() {
        let events = workbuddy_desktop_chat_sequence(
            "conv-1",
            "req-1",
            "msg-1",
            "fast-model",
            "fast-model",
            1_700_000_000_000,
        );
        let codes: Vec<&str> = events
            .iter()
            .map(|event| event["eventCode"].as_str().unwrap_or_default())
            .collect();
        assert_eq!(
            codes,
            vec![
                "agent_task_created",
                "chat_message_send",
                "chat_request_send",
                "chat_message_response",
                "chat_message_status",
                "chat_request_response",
            ]
        );
        assert_eq!(events[0]["conversationId"], json!("conv-1"));
        assert_eq!(events[0]["mode"], json!("craft"));
        assert_eq!(events[0]["has_expert"], json!(false));
        assert_eq!(events[3]["isSuccessful"], json!(true));
        assert_eq!(events[3]["finishReason"], json!("stop"));
        assert_eq!(events[3]["responseModelId"], json!("fast-model"));
        assert_eq!(events[4]["messageErrorCode"], json!("0"));
        assert_eq!(events[5]["isSuccessful"], json!(true));
        // chat 上下文一致：rootRequestId / parentConversationId 贯穿。
        for index in [1, 2, 3, 4, 5] {
            assert_eq!(events[index]["rootRequestId"], json!("req-1"));
            assert_eq!(events[index]["parentConversationId"], json!("conv-1"));
        }
        assert_eq!(
            events[2]["codebuddy.conversation_request_id"],
            json!("req-1")
        );
    }

    /// 五连 / 单事件 / 主题 / 模板 / 灵感 / 画布：形状与关键字段。
    #[test]
    fn desktop_action_payloads_match_the_panel() {
        let buddy =
            workbuddy_desktop_buddy_app_sequence(WORKBUDDY_BUDDY_APP_ID, WORKBUDDY_BUDDY_APP_NAME);
        assert_eq!(buddy.len(), 5);
        assert_eq!(buddy[0]["eventCode"], json!("buddyapp_discover_click"));
        assert_eq!(
            buddy[4]["eventCode"],
            json!("buddyapp_bindaccount_skip_click")
        );
        assert_eq!(buddy[1]["elementId"], json!(WORKBUDDY_BUDDY_APP_ID));

        let automation = workbuddy_desktop_automation_create_event("wb2api 自动化");
        assert_eq!(automation.len(), 1);
        assert_eq!(
            automation[0]["eventCode"],
            json!("automated_task_create_suc")
        );
        assert_eq!(automation[0]["mode"], json!("LOCAL"));

        let appearance = workbuddy_desktop_appearance_apply_event(WORKBUDDY_APPEARANCE_THEME_KEY);
        assert_eq!(appearance["eventCode"], json!("appearance_skin_apply"));
        assert_eq!(appearance["action"], json!("apply"));
        assert_eq!(appearance["source"], json!("settings_close"));
        assert_eq!(appearance["id"], json!("theme-tkmw7j"));

        let template = workbuddy_desktop_template_use_sequence(
            "conv-t",
            "req-t",
            "1",
            "深度研究",
            1_700_000_000_000,
        );
        assert_eq!(template.len(), 8, "6 条 chat 链 + 模板 2 条");
        assert_eq!(
            template[6]["eventCode"],
            json!("agent_task_created_with_template")
        );
        assert_eq!(template[6]["id"], json!("1"));
        assert_eq!(template[7]["eventCode"], json!("template_used"));
        assert_eq!(template[7]["template_id"], json!("1"));

        let playbook = workbuddy_desktop_playbook_prompt_sequence(
            "conv-p",
            "req-p",
            "pm-gtm-launch-plan",
            "新产品上市 GTM 发布计划一页纸",
            1_700_000_000_000,
        );
        assert_eq!(playbook[6]["elementId"], json!("playbook_ctaClick"));
        assert_eq!(playbook[7]["eventCode"], json!("playbook_cta_click"));
        assert_eq!(playbook[7]["id"], json!("pm-gtm-launch-plan"));
        assert_eq!(playbook[8]["eventCode"], json!("playbook_prompt_send"));
        assert_eq!(playbook[8]["requestId"], json!("req-p"));

        let canvas =
            workbuddy_desktop_design_canvas_sequence("conv-c", "req-abcdefgh", 1_700_000_000_000);
        assert_eq!(
            canvas[6]["eventCode"],
            json!("wbx_design_canvas_task_create")
        );
        assert_eq!(canvas[7]["eventCode"], json!("wbx_design_canvas_open"));
        assert_eq!(canvas[7]["id"], json!("ardot-file-abcdefgh"));
    }

    /// 专家链：召唤三连 + `actual_use`（mode/type/cost 可区分灯塔与普通专家）。
    #[test]
    fn desktop_expert_payloads_match_the_panel() {
        let expert = WorkbuddyMarketExpert {
            expert_id: "ex_2cvvUZQhDyeJ".to_string(),
            expert_type: "agent".to_string(),
            display_name_zh: "腾讯轻量云专家".to_string(),
            profession_zh: "腾讯轻量云专家".to_string(),
            version: "1.0.2".to_string(),
        };
        let summon = workbuddy_desktop_expert_summon_sequence(&expert);
        assert_eq!(summon.len(), 3);
        assert_eq!(summon[0]["eventCode"], json!("web_element_click"));
        assert_eq!(summon[0]["elementId"], json!("expert_summon_click"));
        assert_eq!(summon[1]["eventCode"], json!("expert_summon_click"));
        assert_eq!(summon[1]["version"], json!("1.0.2"));
        assert_eq!(summon[2]["eventCode"], json!("expert_summoned"));

        let use_event = workbuddy_desktop_expert_actual_use_event(
            &expert,
            "conv-e",
            "cmb-0123456789abcdef0123456789abcdef",
            "craft",
            "expert-all",
            9000,
        );
        assert_eq!(use_event["eventCode"], json!("expert_actual_use"));
        assert_eq!(use_event["source"], json!("builtin"));
        assert_eq!(use_event["cost"], json!(9000));
        assert_eq!(
            use_event["requestId"],
            json!("cmb-0123456789abcdef0123456789abcdef")
        );
        assert_eq!(use_event["messageId"], json!("msg-89abcdef"));

        // 灯塔专家：LOCAL + type 空 + cost 0（面板对齐真实样本）。
        let lighthouse =
            workbuddy_desktop_expert_actual_use_event(&expert, "conv-l", "req-l", "LOCAL", "", 0);
        assert_eq!(lighthouse["mode"], json!("LOCAL"));
        assert_eq!(lighthouse["type"], json!(""));
        assert_eq!(lighthouse["cost"], json!(0));

        // 版本缺失回落 1.0.0（面板同款）。
        let mut bare = expert.clone();
        bare.version = String::new();
        let bare_summon = workbuddy_desktop_expert_summon_sequence(&bare);
        assert_eq!(bare_summon[1]["version"], json!("1.0.0"));

        // 列表解析 + 畸形容忍。
        let parsed = parse_workbuddy_market_experts(&json!({
            "experts": [
                {"expert_id": "ex_1", "expert_type": "agent", "display_name_zh": "专家一",
                 "profession_zh": "职业一", "version": "2.0.0"},
                {"expert_id": "ex_2"}
            ]
        }));
        assert_eq!(parsed.len(), 2);
        assert_eq!(parsed[0].expert_id, "ex_1");
        assert_eq!(parsed[1].expert_type, "");
        assert!(parse_workbuddy_market_experts(&json!({})).is_empty());
    }

    /// Web 事件用**浏览器指纹**（与桌面指纹不同族），字段与面板一致。
    #[test]
    fn web_event_payload_uses_the_browser_fingerprint() {
        let payload = workbuddy_web_event_payload(
            "web_element_click",
            WORKBUDDY_LIBRARY_DOC_URL,
            WORKBUDDY_LIBRARY_ELEMENT_ID,
            WORKBUDDY_LIBRARY_ELEMENT_NAME,
            "uid-web",
            "昵称",
            "ent-1",
            1_700_000_000_000,
        );
        let first = &payload.as_array().expect("数组")[0];
        assert_eq!(first["eventCode"], json!("web_element_click"));
        assert_eq!(first["os"], json!("Win32"));
        assert_eq!(first["osVersion"], json!("10.0"));
        assert_eq!(first["elementId"], json!("library_doc_intro_click"));
        assert_eq!(first["userId"], json!("uid-web"));
        assert_eq!(first["enterpriseId"], json!("ent-1"));
        assert_eq!(
            first["machineId"],
            json!(workbuddy_derive_id("uid-web", "webmachine"))
        );
        assert!(first["userAgent"]
            .as_str()
            .unwrap_or_default()
            .contains("Chrome/"));
        // 浏览器指纹里**不应**出现桌面字段（两族指纹必须分开）。
        assert!(first.get("ideName").is_none());
        assert!(first.get("extName").is_none());
    }

    /// Tier 2 的真实对话请求体：与面板 `DesktopChatWithExpert` 同字段。
    #[test]
    fn tier2_chat_body_matches_the_panel_shape() {
        let body = workbuddy_desktop_chat_request_body("");
        assert_eq!(body["model"], json!("fast-model"));
        assert_eq!(body["agent"], json!("cli"));
        assert_eq!(body["temperature"], json!(1));
        assert_eq!(body["stream"], json!(true));
        assert_eq!(body["stream_options"]["include_usage"], json!(true));
        let messages = body["messages"].as_array().expect("messages");
        assert_eq!(messages.len(), 2);
        assert_eq!(messages[0]["role"], json!("system"));
        assert_eq!(messages[1]["role"], json!("user"));
        // 空 prompt 回落默认短提问（拿 id 为目的，不追求回答质量）。
        assert_eq!(messages[1]["content"], json!("1+1等于几？直接回答。"));
        // 有 prompt 就用它。
        let custom = workbuddy_desktop_chat_request_body("写一句恭喜发财");
        assert_eq!(custom["messages"][1]["content"], json!("写一句恭喜发财"));
    }

    /// 服务端 id 形态判定：`cmb-` + 32 hex，或裸 32 hex；其余一律不算。
    #[test]
    fn server_request_id_shape_is_enforced() {
        assert!(workbuddy_is_server_request_id(
            "0123456789abcdef0123456789abcdef"
        ));
        assert!(workbuddy_is_server_request_id(
            "cmb-0123456789abcdef0123456789abcdef"
        ));
        // 面板 idRegex 的反例。
        assert!(!workbuddy_is_server_request_id(""));
        assert!(!workbuddy_is_server_request_id("req-1"));
        assert!(!workbuddy_is_server_request_id("aether-wb-req-123"));
        assert!(!workbuddy_is_server_request_id(
            "0123456789abcdef0123456789abcde"
        )); // 31 位
        assert!(!workbuddy_is_server_request_id(
            "0123456789ABCDEF0123456789ABCDEF"
        )); // 大写不算
        assert!(!workbuddy_is_server_request_id(
            "cmb-0123456789abcdef0123456789abcde"
        ));
    }

    /// SSE 抓 id：**跳过不匹配的 `"id":"`**（消息 id 等）再命中服务端 id。
    ///
    /// 这正是面板注释里那个坑：不推进偏移就会卡在首个不匹配的 id 上，读满缓冲后误报。
    #[test]
    fn sse_request_id_extraction_skips_non_matching_ids() {
        let sse = concat!(
            "data: {\"type\":\"message_start\",\"message\":{\"id\":\"msg_abc\",\"role\":\"assistant\"}}\n\n",
            "data: {\"id\":\"not-an-id\"}\n\n",
            "data: {\"type\":\"content_block_delta\",\"id\":\"aether-wb-req-123\"}\n\n",
            "data: {\"id\":\"cmb-0123456789abcdef0123456789abcdef\",\"choices\":[]}\n\n",
            "data: [DONE]\n\n"
        );
        assert_eq!(
            workbuddy_parse_server_request_id(sse).as_deref(),
            Some("cmb-0123456789abcdef0123456789abcdef")
        );

        // 裸 32 hex 也认。
        let bare = r#"data: {"id":"0123456789abcdef0123456789abcdef"}"#;
        assert_eq!(
            workbuddy_parse_server_request_id(bare).as_deref(),
            Some("0123456789abcdef0123456789abcdef")
        );

        // 一个都没有 → None（调用方据此判定「拿不到 id 就不发 actual_use 事件」）。
        assert_eq!(
            workbuddy_parse_server_request_id(r#"data: {"id":"msg_1"}"#),
            None
        );
        assert_eq!(workbuddy_parse_server_request_id(""), None);
        // 截断的 JSON（流中途断了）不 panic。
        assert_eq!(
            workbuddy_parse_server_request_id("data: {\"id\":\"cmb-0123"),
            None
        );
        // 取**第一个**匹配的（面板语义：SSE 里首个服务端 id 就是本次请求的 id）。
        let two = r#"{"id":"cmb-aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"} {"id":"cmb-bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"}"#;
        assert_eq!(
            workbuddy_parse_server_request_id(two).as_deref(),
            Some("cmb-aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa")
        );
    }

    #[test]
    fn skill_info_event_matches_panel_capture() {
        let server_id = "cmb-0123456789abcdef0123456789abcdef";
        let event = workbuddy_desktop_skill_info_event("conv-1", server_id, "msg-abcdef12");
        // 面板抓包 row 209 的字段口径
        assert_eq!(
            event.get("eventCode").and_then(Value::as_str),
            Some("skill_info")
        );
        assert_eq!(
            event.get("skillId").and_then(Value::as_str),
            Some(WORKBUDDY_SKILL_INFO_ID)
        );
        assert_eq!(
            event.get("skillVersion").and_then(Value::as_str),
            Some("1.0.0")
        );
        assert_eq!(
            event.get("toolStatus").and_then(Value::as_str),
            Some("success")
        );
        assert_eq!(
            event.get("source").and_then(Value::as_str),
            Some("workbuddy-desktop")
        );
        // JOIN：三项都必须是**真实对话的服务端 id**（自造 UUID 不计数）
        assert_eq!(
            event.get("conversationId").and_then(Value::as_str),
            Some("conv-1")
        );
        assert_eq!(
            event.get("requestId").and_then(Value::as_str),
            Some(server_id)
        );
        assert_eq!(
            event.get("traceId").and_then(Value::as_str),
            Some(server_id)
        );
    }

    #[test]
    fn mark_tool_calls_only_touches_chat_message_response() {
        let mut events =
            workbuddy_desktop_chat_sequence("c", "r", "m", "fast-model", "fast-model", 0);
        // 对话链里本来就可能有别的事件自带 finishReason，先记下它们的位置。
        let pre_marked: Vec<usize> = events
            .iter()
            .enumerate()
            .filter(|(_, event)| event.get("finishReason").is_some())
            .map(|(index, _)| index)
            .collect();
        workbuddy_desktop_mark_tool_calls(&mut events);
        let mut saw_chat_message_response = false;
        for (index, event) in events.iter().enumerate() {
            let code = event
                .get("eventCode")
                .and_then(Value::as_str)
                .unwrap_or_default();
            if code == "chat_message_response" {
                saw_chat_message_response = true;
                assert_eq!(
                    event.get("finishReason").and_then(Value::as_str),
                    Some("tool_calls")
                );
            } else if !pre_marked.contains(&index) {
                assert!(
                    event.get("finishReason").is_none(),
                    "不该给 {code} 加 finishReason"
                );
            }
        }
        assert!(
            saw_chat_message_response,
            "对话链里应有 chat_message_response"
        );
    }
}
