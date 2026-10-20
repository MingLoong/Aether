//! 国际版（global realm）**新账号注册激活**：补注册地区 → 激活。
//!
//! 背景（面板 `internal/upstream/global_register.go` 的逆向结论）：新 global 账号必须先
//! 补注册地区（`/console/login/account` 提交 `countryCode`/`countryFullName`/`countryName`），
//! 再调 register 接口激活 Trial，否则对话直接报 `14017 trial not activated`。
//!
//! 面板**代码里实际调用**的链路只有三步：
//!
//! ```text
//! GET  {base}/auth/realms/copilot/overseas/user/register?userId=<uid>
//!        → code 200 已激活；code 500 或 msg 含 "region required" = 需补地区
//! POST {base}/billing/area/get-country-code  {filterForbidden:1}
//!        → 可选地区列表；**data 是 JSON 字符串（双层信封）**，解析要二次拆包
//! POST {base}/console/login/account  {attributes:{countryCode,countryFullName,countryName}}
//!        → 提交地区（幂等，code 0 成功）
//! ```
//!
//! ⚠️ 面板文件头注释里还写了 `POST /billing/area/get-user-area-info {action:getUserAreaInfo}`
//! 当"检测当前地区"用，但**面板代码里从没调用过它**——我们同样不实现：不编造未被验证的请求。
//!
//! 本模块只放**纯函数**（分类 / 解析 / 请求体构造）；HTTP 形状（头族、URL）在
//! `aether-provider-pool` 的 `build_workbuddy_pool_global_*` 里。

use serde_json::{json, Value};

/// 注册状态查询（GET，需 Bearer + `x-user-id`）。
pub const WORKBUDDY_GLOBAL_REGISTER_PATH: &str = "/auth/realms/copilot/overseas/user/register";
/// 可选注册地区列表（POST）。
pub const WORKBUDDY_GLOBAL_COUNTRY_CODE_PATH: &str = "/billing/area/get-country-code";
/// 提交注册地区（POST，幂等）。
pub const WORKBUDDY_GLOBAL_SUBMIT_REGION_PATH: &str = "/console/login/account";

/// 国际版 web 白名单（面板 `GlobalFetchCountries(intlOnly=true)` 的展示集，**顺序即优先级**）。
///
/// 面板取白名单**首个**可达地区作为默认提交值（通常 HK），所以顺序不能改。
pub const WORKBUDDY_GLOBAL_INTL_COUNTRY_WHITELIST: [&str; 7] =
    ["HK", "MO", "SG", "TH", "PH", "MY", "ID"];

/// 国际版可选注册地区（面板 `GlobalCountry`）。
///
/// 字段名对齐面板结构体 tag（`EnName` / `Name` / `IOS2` / `IOS3` / `Code`）；解析时
/// 大小写不敏感，且容忍数字码（上游偶发给 number）。
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct WorkbuddyGlobalCountry {
    /// 英文全名 → `countryFullName`。
    pub en_name: String,
    /// 显示名（仅用于展示/日志）。
    pub name: String,
    /// 二字码 → `countryName`（白名单过滤也用它）。
    pub ios2: String,
    /// 三字码。
    pub ios3: String,
    /// 数字码 → `countryCode`。
    pub code: String,
}

/// 注册状态（面板 `GlobalRegisterStatus` 的三分类）。
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum WorkbuddyGlobalRegisterStatus {
    /// `code == 200`：已激活可用。
    Activated,
    /// `code == 500` 或文案含 `region required`：需补注册地区。
    NeedsRegion(String),
    /// 其它：未激活且不是"缺地区"（面板原样上抛 msg）。
    NotActivated(String),
}

/// 注册激活状态分类（面板 `GlobalRegisterStatus`）。
pub fn classify_workbuddy_global_register_status(
    code: i64,
    msg: &str,
) -> WorkbuddyGlobalRegisterStatus {
    if code == 200 {
        return WorkbuddyGlobalRegisterStatus::Activated;
    }
    // 面板：`case code == 500 || strings.Contains(strings.ToLower(m), "region required")`
    if code == 500 || msg.to_ascii_lowercase().contains("region required") {
        return WorkbuddyGlobalRegisterStatus::NeedsRegion(msg.to_string());
    }
    WorkbuddyGlobalRegisterStatus::NotActivated(msg.to_string())
}

/// `get-country-code` 请求体（面板 `{"filterForbidden": 1}`）。
pub fn build_workbuddy_global_country_code_body() -> Value {
    json!({ "filterForbidden": 1 })
}

/// `console/login/account` 请求体：**值是单元素数组**（面板逐字口径）。
pub fn build_workbuddy_global_submit_region_body(country: &WorkbuddyGlobalCountry) -> Value {
    json!({
        "attributes": {
            "countryCode": [country.code],
            "countryFullName": [country.en_name],
            "countryName": [country.ios2],
        }
    })
}

/// 取对象里大小写不敏感的字符串字段（容忍 number → 文本）。
fn workbuddy_global_field(object: &Value, key: &str) -> String {
    let Some(map) = object.as_object() else {
        return String::new();
    };
    for (name, value) in map {
        if !name.eq_ignore_ascii_case(key) {
            continue;
        }
        return match value {
            Value::String(text) => text.trim().to_string(),
            Value::Number(number) => number.to_string(),
            _ => String::new(),
        };
    }
    String::new()
}

/// 解析单个地区对象。
fn parse_workbuddy_global_country(object: &Value) -> WorkbuddyGlobalCountry {
    WorkbuddyGlobalCountry {
        en_name: workbuddy_global_field(object, "EnName"),
        name: workbuddy_global_field(object, "Name"),
        ios2: workbuddy_global_field(object, "IOS2"),
        ios3: workbuddy_global_field(object, "IOS3"),
        code: workbuddy_global_field(object, "Code"),
    }
}

/// 解析 `get-country-code` 的列表。
///
/// 入参用 [`crate::workbuddy::workbuddy_unwrap_envelope`] 拆过外层 `{code,msg,data}` 的
/// `data`——**它可能是 JSON 字符串**（面板注释点名的双层信封），所以这里再拆一次，
/// 然后依次尝试 `.data.list` / `.list` / 裸数组（面板口径是 `.data.list`）。
pub fn parse_workbuddy_global_countries(envelope_data: &Value) -> Vec<WorkbuddyGlobalCountry> {
    let inner = match envelope_data {
        Value::String(text) => serde_json::from_str::<Value>(text).unwrap_or(Value::Null),
        other => other.clone(),
    };
    let list = inner
        .get("data")
        .and_then(|data| data.get("list"))
        .or_else(|| inner.get("list"))
        .or_else(|| inner.as_array().map(|_| &inner));
    let Some(list) = list.and_then(Value::as_array) else {
        return Vec::new();
    };
    list.iter()
        .map(parse_workbuddy_global_country)
        .filter(|country| !country.ios2.is_empty() || !country.code.is_empty())
        .collect()
}

/// 按国际版白名单过滤（面板 `intlOnly=true`），**顺序 = 白名单顺序**（即默认地区优先级）。
pub fn filter_workbuddy_global_intl_countries(
    countries: &[WorkbuddyGlobalCountry],
) -> Vec<WorkbuddyGlobalCountry> {
    let mut picked = Vec::new();
    for code in WORKBUDDY_GLOBAL_INTL_COUNTRY_WHITELIST {
        if let Some(country) = countries
            .iter()
            .find(|country| country.ios2.eq_ignore_ascii_case(code))
        {
            picked.push(country.clone());
        }
    }
    picked
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn register_status_follows_the_panel_classification() {
        assert_eq!(
            classify_workbuddy_global_register_status(200, "ok"),
            WorkbuddyGlobalRegisterStatus::Activated
        );
        // code 500 或文案含 region required（大小写不敏感）都算"需补地区"
        assert!(matches!(
            classify_workbuddy_global_register_status(500, ""),
            WorkbuddyGlobalRegisterStatus::NeedsRegion(_)
        ));
        assert!(matches!(
            classify_workbuddy_global_register_status(0, "Region Required"),
            WorkbuddyGlobalRegisterStatus::NeedsRegion(_)
        ));
        assert!(matches!(
            classify_workbuddy_global_register_status(403, "forbidden"),
            WorkbuddyGlobalRegisterStatus::NotActivated(_)
        ));
    }

    #[test]
    fn country_list_parses_the_double_envelope() {
        // 面板实测：data 是 JSON 字符串，解开后仍是 {"data":{"list":[…]}}
        let envelope_data = json!(
            r#"{"data":{"list":[{"EnName":"Hong Kong","Name":"中国香港","IOS2":"HK","IOS3":"HKG","Code":"344"}]}}"#
        );
        let countries = parse_workbuddy_global_countries(&envelope_data);
        assert_eq!(countries.len(), 1);
        assert_eq!(countries[0].ios2, "HK");
        assert_eq!(countries[0].en_name, "Hong Kong");
        assert_eq!(countries[0].code, "344");
    }

    #[test]
    fn country_list_also_accepts_object_and_bare_array_shapes() {
        let object = json!({"data": {"list": [{"IOS2": "SG", "Code": "702"}]}});
        assert_eq!(parse_workbuddy_global_countries(&object).len(), 1);

        let bare = json!([{"IOS2": "MY", "Code": 458, "enName": "Malaysia"}]);
        let countries = parse_workbuddy_global_countries(&bare);
        assert_eq!(countries.len(), 1);
        assert_eq!(countries[0].ios2, "MY");
        // 数字码容忍成文本，且大小写不敏感的键也能取到
        assert_eq!(countries[0].code, "458");
        assert_eq!(countries[0].en_name, "Malaysia");

        assert!(parse_workbuddy_global_countries(&json!("not json")).is_empty());
    }

    #[test]
    fn intl_filter_keeps_whitelist_order_and_drops_others() {
        let countries = vec![
            WorkbuddyGlobalCountry {
                ios2: "US".into(),
                ..Default::default()
            },
            WorkbuddyGlobalCountry {
                ios2: "sg".into(),
                code: "702".into(),
                ..Default::default()
            },
            WorkbuddyGlobalCountry {
                ios2: "HK".into(),
                code: "344".into(),
                ..Default::default()
            },
            WorkbuddyGlobalCountry {
                ios2: "JP".into(),
                ..Default::default()
            },
            WorkbuddyGlobalCountry {
                ios2: "ID".into(),
                code: "360".into(),
                ..Default::default()
            },
        ];
        let picked = filter_workbuddy_global_intl_countries(&countries);
        // 白名单顺序 HK → MO → SG → TH → PH → MY → ID：大小写不敏感命中，未收录的被丢掉
        let codes: Vec<&str> = picked.iter().map(|c| c.ios2.as_str()).collect();
        assert_eq!(codes, vec!["HK", "sg", "ID"]);
    }

    #[test]
    fn submit_region_body_matches_the_panel_shape() {
        let country = WorkbuddyGlobalCountry {
            en_name: "Hong Kong".into(),
            name: "中国香港".into(),
            ios2: "HK".into(),
            ios3: "HKG".into(),
            code: "344".into(),
        };
        let body = build_workbuddy_global_submit_region_body(&country);
        // 面板是**单元素数组**，不能写成裸字符串
        assert_eq!(body["attributes"]["countryCode"], json!(["344"]));
        assert_eq!(body["attributes"]["countryFullName"], json!(["Hong Kong"]));
        assert_eq!(body["attributes"]["countryName"], json!(["HK"]));

        assert_eq!(
            build_workbuddy_global_country_code_body(),
            json!({"filterForbidden": 1})
        );
    }
}
