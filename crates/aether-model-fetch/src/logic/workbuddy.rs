//! WorkBuddy（腾讯 CodeBuddy）`GET /v3/config` 目录解析 —— 从 `logic.rs` 拆出 ✓。
//!
//! 为什么单独一个模块（维护性审计 ③，2026-10-17 ✗）：这 604 行原本整块塞在共享的
//! `logic.rs` 里，紧跟在 windsurf 解析之后 ✗ —— 既让该文件涨到 3000+ 行，也让补丁在
//! 上游热点文件上留了一整块冲突面 ✗。拆开后 `logic.rs` 只保留一行重导出 ✓。
//!
//! 对外入口仍是 `logic::parse_workbuddy_v3_config_response` ✓（重导出，调用点不用改 ✓）。

use super::*;

/// 解析 WorkBuddy（腾讯 CodeBuddy）`GET /v3/config` 的模型目录。
///
/// 上游信封：`{"code":0,"data":{"models":[…]}}`；每个条目的能力字段见面板
/// `dynModelEntry`（`id/name/credits/tags/vendor/maxInputTokens/maxOutputTokens/
/// supportsImages/supportsReasoning/supportsToolCall/reasoning{supportedEfforts,
/// defaultEffort,effort,…}`）。
///
/// 两处必须照面板的细节：
/// 1. `code != 0` 视为失败（业务错误不从目录里挑模型）；
/// 2. **试用横幅**（`data.productFeaturesConfig.ModelTrialBanner.banners[]`）里的
///    模型只出现在这里、`data.models` 里没有，但**实际可调用**——漏掉它等于少一个
///    能用的模型（面板实测 global 侧 `hy4-preview-f` 即如此）。
pub fn parse_workbuddy_v3_config_response(
    body: &Value,
    updated_at_unix_secs: u64,
) -> Result<(ModelsFetchSuccess, Value), String> {
    let code = body.get("code").and_then(Value::as_i64).unwrap_or(0);
    if code != 0 {
        return Err(format!("v3/config code={code}"));
    }
    let data = body
        .get("data")
        .and_then(Value::as_object)
        .ok_or_else(|| "v3/config response is missing data".to_string())?;
    let entries = data
        .get("models")
        .and_then(Value::as_array)
        .cloned()
        .unwrap_or_default();
    // 当前生效的限时优惠（`data.modelPromotions`）：条目里的 `credits` 是**牌价**，
    // 这里按面板口径算出「生效价」字段，随后按模型 id 挂到元数据上。
    let promotions = workbuddy_active_model_promotions(data, updated_at_unix_secs);
    // 客户端「Pro Only」角标的权威来源：data.modelTiers[].modelIds。
    // 它不是单模型条目字段，而是套餐分组；保留 badge/hover 供前端展示。
    let model_tiers = workbuddy_model_tier_index(data);

    let mut cached_models = Vec::new();
    let mut metadata_models = Vec::new();
    let mut seen = BTreeSet::new();
    for entry in &entries {
        let Some(model_id) = workbuddy_model_string(entry, &["id", "modelId", "model"]) else {
            continue;
        };
        // 非对话模型（补全 / 图片 / 视频 / 超小输出上限）不进对话模型列表。
        if workbuddy_entry_is_non_chat(entry) {
            continue;
        }
        if !seen.insert(model_id.clone()) {
            continue;
        }
        if let Some(mut model) = workbuddy_cached_model(entry, &model_id) {
            if let Some(tier) = model_tiers.get(&model_id) {
                if let Some(object) = model.as_object_mut() {
                    object.insert("model_tier".to_string(), tier.clone());
                    if tier.get("access_mode").and_then(Value::as_str) == Some("exclusive") {
                        object.insert("plan_restricted".to_string(), json!(true));
                    }
                }
            }
            metadata_models.push(workbuddy_metadata_model(
                entry,
                &model_id,
                promotions.get(&model_id),
                model_tiers.get(&model_id),
            ));
            cached_models.push(model);
        }
    }

    // 试用横幅模型：能力从它的「转正目标」条目继承，Credits/Tags 显式清空
    // （它们描述的是转正后的计费与营销信息）。
    let target_by_id: BTreeMap<String, &Value> = entries
        .iter()
        .filter_map(|entry| {
            workbuddy_model_string(entry, &["id", "modelId", "model"]).map(|id| (id, entry))
        })
        .collect();
    let banners = data
        .get("productFeaturesConfig")
        .and_then(|config| config.get("ModelTrialBanner"))
        .and_then(|banner| banner.get("banners"))
        .and_then(Value::as_array)
        .cloned()
        .unwrap_or_default();
    for banner in &banners {
        let Some(trial_id) = workbuddy_model_string(banner, &["modelId"]) else {
            continue;
        };
        // 试用横幅同样只收对话模型。
        if workbuddy_entry_is_non_chat(banner) {
            continue;
        }
        if !seen.insert(trial_id.clone()) {
            continue;
        }
        let target = workbuddy_model_string(banner, &["targetModelId"])
            .and_then(|target_id| target_by_id.get(&target_id).copied())
            .unwrap_or(banner);
        if let Some(model) = workbuddy_cached_model(target, &trial_id) {
            // 试用模型不继承计费/营销字段（它们描述的是转正后的形态）。
            let mut model = model;
            if let Some(object) = model.as_object_mut() {
                object.remove("credits");
                object.remove("tags");
            }
            let mut metadata_model =
                workbuddy_metadata_model(target, &trial_id, None, model_tiers.get(&trial_id));
            if let Some(object) = metadata_model.as_object_mut() {
                object.insert("trial".to_string(), json!(true));
                object.insert("credits".to_string(), Value::Null);
                object.insert("tags".to_string(), Value::Array(Vec::new()));
            }
            metadata_models.push(metadata_model);
            cached_models.push(model);
        }
    }

    if cached_models.is_empty() {
        return Err("v3/config returned no usable models".to_string());
    }

    let mut workbuddy_metadata = serde_json::Map::new();
    workbuddy_metadata.insert("updated_at".to_string(), json!(updated_at_unix_secs));
    workbuddy_metadata.insert(
        "allowed_models_count".to_string(),
        json!(metadata_models.len() as u64),
    );
    workbuddy_metadata.insert("models".to_string(), Value::Array(metadata_models));

    Ok((
        ModelsFetchSuccess {
            fetched_model_ids: collect_cached_model_ids(&cached_models),
            cached_models,
        },
        json!({ "workbuddy": workbuddy_metadata }),
    ))
}

/// 面板 `nonChatModel`：该条目是不是**非对话模型**。
///
/// 为什么必须过滤：这些模型在目录里也带 `id`，但**不能用 `openai:chat` 调用**——把它们
/// 列进对话模型列表，用户（或按名字模式挑模型的客户端）会选中并直接失败。判定三条：
/// ① id 前缀是补全类（`nes-` / `completion-` / `codewise-`）；
/// ② `maxOutputTokens` 在 `(0, 256]`（输出上限这么小的不是对话模型）；
/// ③ tags 里带图片/视频生成标记（`text-to-image` / `image-to-image` / `text-to-video` /
/// `image-to-video`）。
pub(super) fn workbuddy_entry_is_non_chat(entry: &Value) -> bool {
    let id = workbuddy_model_string(entry, &["id", "modelId", "model"])
        .unwrap_or_default()
        .trim()
        .to_ascii_lowercase();
    if ["nes-", "completion-", "codewise-"]
        .iter()
        .any(|prefix| id.starts_with(prefix))
    {
        return true;
    }
    if let Some(max_output) = workbuddy_model_i64(entry, &["maxOutputTokens", "max_output_tokens"])
    {
        if max_output > 0 && max_output <= 256 {
            return true;
        }
    }
    entry
        .get("tags")
        .and_then(Value::as_array)
        .is_some_and(|tags| {
            tags.iter().filter_map(Value::as_str).any(|tag| {
                matches!(
                    tag,
                    "text-to-image" | "image-to-image" | "text-to-video" | "image-to-video"
                )
            })
        })
}

/// 把一个上游条目投影成缓存模型（`id` + 能力字段；未知字段留给元数据）。
pub(super) fn workbuddy_cached_model(entry: &Value, model_id: &str) -> Option<Value> {
    let mut model = serde_json::Map::new();
    model.insert("id".to_string(), json!(model_id));
    model.insert("object".to_string(), json!("model"));
    model.insert("model_uid".to_string(), json!(model_id));
    model.insert(
        "display_name".to_string(),
        json!(
            workbuddy_model_string(entry, &["name", "displayName"]).unwrap_or(model_id.to_string())
        ),
    );
    model.insert(
        "owned_by".to_string(),
        json!(workbuddy_model_string(entry, &["vendor", "provider"])
            .unwrap_or("workbuddy".to_string())),
    );
    // 对话域固定走 openai:chat（模板的 custom_path 就是 /v2/chat/completions）。
    model.insert("api_formats".to_string(), json!(["openai:chat"]));
    for (target, keys) in [
        ("description", &["descriptionZh", "description"][..]),
        ("credits", &["credits"][..]),
    ] {
        if let Some(value) = workbuddy_model_string(entry, keys) {
            model.insert(target.to_string(), json!(value));
        }
    }
    if let Some(tags) = entry.get("tags").filter(|value| !value.is_null()) {
        model.insert("tags".to_string(), tags.clone());
    }
    let efforts = workbuddy_reasoning_efforts(entry);
    if !efforts.is_empty() {
        model.insert("efforts".to_string(), json!(efforts));
    }
    for (target, keys) in [
        (
            "context_window",
            &["maxInputTokens", "max_input_tokens"][..],
        ),
        ("max_tokens", &["maxOutputTokens", "max_output_tokens"][..]),
    ] {
        if let Some(value) = workbuddy_model_i64(entry, keys) {
            model.insert(target.to_string(), json!(value));
        }
    }
    for (target, keys) in [
        (
            "supports_images",
            &["supportsImages", "supports_images"][..],
        ),
        (
            "supports_reasoning",
            &["supportsReasoning", "supports_reasoning"][..],
        ),
        (
            "supports_tool_call",
            &["supportsToolCall", "supports_tool_call"][..],
        ),
    ] {
        if let Some(value) = workbuddy_model_bool(entry, keys) {
            model.insert(target.to_string(), json!(value));
        }
    }
    if let Some(default_effort) = workbuddy_default_effort(entry) {
        model.insert("default_effort".to_string(), json!(default_effort));
    }
    Some(Value::Object(model))
}

// ---------------------------------------------------------------------------
// 套餐分组（`data.modelTiers`，官方客户端 Pro Only 角标来源）
// ---------------------------------------------------------------------------

/// 将上游组级套餐配置展开为 model id → 展示对象。
/// 只保留 enabled 且带 modelIds 的 tier；badge/hover 结构原样保留。
pub(super) fn workbuddy_model_tier_index(
    data: &serde_json::Map<String, Value>,
) -> BTreeMap<String, Value> {
    let mut out = BTreeMap::new();
    let Some(tiers) = data.get("modelTiers").and_then(Value::as_array) else {
        return out;
    };
    for tier in tiers {
        if tier.get("enabled").and_then(Value::as_bool) == Some(false) {
            continue;
        }
        let Some(ids) = tier.get("modelIds").and_then(Value::as_array) else {
            continue;
        };
        let Some(object) = tier.as_object() else {
            continue;
        };
        let mut record = serde_json::Map::new();
        for (source, target) in [
            ("id", "id"),
            ("accessMode", "access_mode"),
            ("tier", "tier"),
            ("badge", "badge"),
            ("hover", "hover"),
        ] {
            if let Some(value) = object.get(source) {
                record.insert(target.to_string(), value.clone());
            }
        }
        let record = Value::Object(record);
        for id in ids
            .iter()
            .filter_map(Value::as_str)
            .map(str::trim)
            .filter(|id| !id.is_empty())
        {
            out.insert(id.to_string(), record.clone());
        }
    }
    out
}

// ---------------------------------------------------------------------------
// 限时优惠（`/v3/config` 的 `data.modelPromotions`，面板 `applyModelPromotions`）
// ---------------------------------------------------------------------------
//
// 口径（面板 2026-09-23 实测 7 条：deepseek 系错峰五折、glm-5.2 夜间五折、
// hy3 / hy4-preview-f 限时免费）：
// - 条目里的 `credits` 是**牌价**（转正后基准倍率）；`promo_*` 才是当前生效价；
// - `discount` 只在部分条目上存在——「错峰使用」类只有时段文案、**没有**机器可读折扣，
//   所以只透出标签/说明，`promo_factor` 保持缺省（前端据此只显示徽章）；
// - 生效判据 = `enabled` + `validFrom`/`validUntil` 区间内 + 落在任一 `daily` 时段
//   （支持跨午夜，如 23:00→07:50），时区恒 Asia/Shanghai（UTC+8，无夏令时）；
// - 同模型多条命中取 `priority` **最高**（面板 glm-5.2 靠 priority + daily 双轨切换）。
const WORKBUDDY_PROMO_UTC_OFFSET_SECONDS: i64 = 8 * 3600;

/// 解析 `"HH:MM"` 为当日分钟数；坏值返回 `None`。
pub(super) fn workbuddy_promo_clock(hhmm: &str) -> Option<i64> {
    let (hour, minute) = hhmm.trim().split_once(':')?;
    let hour: i64 = hour.trim().parse().ok()?;
    let minute: i64 = minute.trim().parse().ok()?;
    if !(0..=24).contains(&hour) || !(0..=59).contains(&minute) {
        return None;
    }
    Some(hour * 60 + minute)
}

/// 优惠在 `now_unix_secs` 是否生效（面板 `promoActive` 等价物）。
pub(super) fn workbuddy_promo_active(promotion: &Value, now_unix_secs: u64) -> bool {
    if !promotion
        .get("enabled")
        .and_then(Value::as_bool)
        .unwrap_or(false)
    {
        return false;
    }
    let Some(schedule) = promotion.get("schedule").and_then(Value::as_object) else {
        return true; // 无 schedule = 全天生效
    };
    // validFrom / validUntil（RFC3339，可缺省；解析不了的按「不限」处理，与面板一致）
    for (key, is_upper_bound) in [("validFrom", false), ("validUntil", true)] {
        let bound = schedule
            .get(key)
            .and_then(Value::as_str)
            .map(str::trim)
            .filter(|text| !text.is_empty())
            .and_then(|text| chrono::DateTime::parse_from_rfc3339(text).ok())
            .map(|bound| bound.timestamp().max(0) as u64);
        if let Some(bound) = bound {
            if is_upper_bound {
                if now_unix_secs >= bound {
                    return false;
                }
            } else if now_unix_secs < bound {
                return false;
            }
        }
    }
    let Some(daily) = schedule.get("daily").and_then(Value::as_array) else {
        return true;
    };
    if daily.is_empty() {
        return true;
    }
    // 当前「上海时间」的当日分钟数：上游恒 UTC+8 且无夏令时，所以不需要 tz 数据库。
    let minute_of_day =
        (now_unix_secs as i64 + WORKBUDDY_PROMO_UTC_OFFSET_SECONDS).rem_euclid(86_400) / 60;
    daily.iter().any(|window| {
        let start = window
            .get("start")
            .and_then(Value::as_str)
            .and_then(workbuddy_promo_clock);
        let end = window
            .get("end")
            .and_then(Value::as_str)
            .and_then(workbuddy_promo_clock);
        match (start, end) {
            (Some(start), Some(end)) if start <= end => {
                minute_of_day >= start && minute_of_day < end
            }
            // 跨午夜（23:00 → 07:50）
            (Some(start), Some(end)) => minute_of_day >= start || minute_of_day < end,
            _ => false,
        }
    })
}

/// 当前生效的优惠 → `model_id → promo 字段` 映射（同模型取 `priority` 最高，打平先到先得）。
pub(super) fn workbuddy_active_model_promotions(
    data: &serde_json::Map<String, Value>,
    now_unix_secs: u64,
) -> BTreeMap<String, Value> {
    let Some(promotions) = data.get("modelPromotions").and_then(Value::as_array) else {
        return BTreeMap::new();
    };
    let mut best: BTreeMap<String, (i64, Value)> = BTreeMap::new();
    for promotion in promotions {
        if !workbuddy_promo_active(promotion, now_unix_secs) {
            continue;
        }
        let priority = promotion
            .get("priority")
            .and_then(Value::as_i64)
            .unwrap_or(0);
        let mut fields = serde_json::Map::new();
        if let Some(label) = promotion
            .get("badge")
            .and_then(|badge| badge.get("label"))
            .and_then(Value::as_str)
            .map(str::trim)
            .filter(|label| !label.is_empty())
        {
            fields.insert("promo_label".to_string(), json!(label));
        }
        if let Some(note) = promotion
            .get("hover")
            .and_then(|hover| hover.get("textZh"))
            .and_then(Value::as_str)
            .map(str::trim)
            .filter(|note| !note.is_empty())
        {
            fields.insert("promo_note".to_string(), json!(note));
        }
        if let Some(discount) = promotion.get("discount") {
            if let Some(factor) = discount.get("factor").and_then(Value::as_f64) {
                fields.insert("promo_factor".to_string(), json!(factor));
            }
            if let Some(credits) = discount
                .get("discountedCredits")
                .and_then(Value::as_str)
                .map(str::trim)
                .filter(|credits| !credits.is_empty())
            {
                fields.insert("promo_credits".to_string(), json!(credits));
            }
        }
        if fields.is_empty() {
            continue;
        }
        let Some(model_ids) = promotion.get("modelIds").and_then(Value::as_array) else {
            continue;
        };
        for model_id in model_ids.iter().filter_map(Value::as_str) {
            let candidate = (priority, Value::Object(fields.clone()));
            match best.get(model_id) {
                Some(existing) if existing.0 >= priority => {}
                _ => {
                    best.insert(model_id.to_string(), candidate);
                }
            }
        }
    }
    best.into_iter()
        .map(|(model_id, (_, fields))| (model_id, fields))
        .collect()
}

/// 知识表也未收录的模型：上下文窗口兜底 **1M**（面板 `DefaultContextWindow`；
/// 高估优于低估——宁可让上游拒绝，也不要下游提前截断）。
const WORKBUDDY_DEFAULT_CONTEXT_WINDOW: i64 = 1_000_000;

/// 上下文窗口 / 输出上限的静态知识表（面板 `contextCapFallback` 的 workbuddy 相关条目）。
///
/// 每条都照抄面板的来源标注（实测 / models.dev / 同族外推）；`max_output = 0`
/// 表示**输出上限未知**（此时字段省略，不编造）。
const WORKBUDDY_CONTEXT_CAP_FALLBACK: &[(&str, i64, i64)] = &[
    // GLM 家族
    ("glm-5.2", 1_000_000, 131_072),
    ("glm-5.1", 200_000, 131_072),
    ("glm-5.3", 1_000_000, 131_072),
    ("glm-5.3-flash", 1_000_000, 131_072),
    ("glm-5v-turbo", 200_000, 131_072),
    // Kimi 家族
    ("kimi-k2.7", 256_000, 65_536),
    ("kimi-k2.6", 256_000, 262_144),
    ("kimi-k2.5", 164_000, 262_144),
    ("kimi-k3", 1_048_576, 131_072),
    ("kimi-k2.8-preview", 1_048_576, 0),
    // MiniMax / 混元
    ("minimax-m3", 512_000, 512_000),
    ("hy3", 192_000, 64_000),
    ("hy3-preview", 262_144, 64_000),
    ("hy4-preview", 1_000_000, 64_000),
    ("hy4-preview-x", 1_000_000, 64_000),
    // DeepSeek 家族
    ("deepseek-v4-pro", 1_000_000, 384_000),
    ("deepseek-v4-flash", 1_000_000, 384_000),
    ("deepseek-v4.1-flash", 1_000_000, 384_000),
    // 路由别名
    ("auto", 168_000, 0),
];

pub(super) fn workbuddy_context_cap(model_id: &str) -> Option<(i64, i64)> {
    let normalized = model_id.trim().to_ascii_lowercase();
    WORKBUDDY_CONTEXT_CAP_FALLBACK
        .iter()
        .find(|(model, _, _)| *model == normalized)
        .map(|(_, context, max_output)| (*context, *max_output))
}

pub(super) fn workbuddy_context_window_fallback(model_id: &str) -> i64 {
    workbuddy_context_cap(model_id)
        .map(|(context, _)| context)
        .filter(|context| *context > 0)
        .unwrap_or(WORKBUDDY_DEFAULT_CONTEXT_WINDOW)
}

pub(super) fn workbuddy_max_output_fallback(model_id: &str) -> Option<i64> {
    workbuddy_context_cap(model_id)
        .map(|(_, max_output)| max_output)
        .filter(|max_output| *max_output > 0)
}

pub(super) fn workbuddy_metadata_model(
    entry: &Value,
    model_id: &str,
    promotion: Option<&Value>,
    tier: Option<&Value>,
) -> Value {
    let mut metadata = serde_json::Map::new();
    metadata.insert("model_uid".to_string(), json!(model_id));
    if let Some(name) = workbuddy_model_string(entry, &["name", "displayName"]) {
        metadata.insert("label".to_string(), json!(name));
    }
    if let Some(vendor) = workbuddy_model_string(entry, &["vendor", "provider"]) {
        metadata.insert("vendor".to_string(), json!(vendor));
    }
    if let Some(credits) = workbuddy_model_string(entry, &["credits"]) {
        metadata.insert("credits".to_string(), json!(credits));
    }
    if let Some(is_default) = entry.get("isDefault").and_then(Value::as_bool) {
        metadata.insert("is_default".to_string(), json!(is_default));
    }
    if let Some(disabled) = entry.get("disabled").and_then(Value::as_bool) {
        metadata.insert("disabled".to_string(), json!(disabled));
    }
    // 模型目录全字段（面板 `dynModelEntry` → `ModelInfo` 的同一套映射）。
    // 「能力」原本两处都没有数据（Aether 的 effective_supports_* 对导入模型全是 false，
    // 目录快照又只存了名字/厂牌/倍率）——所以这些字段必须在**拉目录时**存下来，
    // 前端的能力列表才有内容可显示。
    for (target, keys) in [
        ("description", &["descriptionZh", "description"][..]),
        ("context_window", &["maxInputTokens"][..]),
        ("max_tokens", &["maxOutputTokens"][..]),
        ("max_allowed_size", &["maxAllowedSize"][..]),
        ("supports_images", &["supportsImages"][..]),
        ("supports_reasoning", &["supportsReasoning"][..]),
        ("supports_tool_call", &["supportsToolCall"][..]),
        ("only_reasoning", &["onlyReasoning"][..]),
    ] {
        if let Some(value) = workbuddy_model_value(entry, keys) {
            metadata.insert(target.to_string(), value);
        }
    }
    // 上游缺字段时的**静态兜底**（面板 `internal/upstream/context_catalog.go` 的等价物）：
    // 上游值权威（`> 0`）→ 静态知识表 → **1M 兜底**（宁可高估不可低估，避免下游按自己的
    // 小默认值**提前截断**）；输出上限则「知识表没有就**省略字段**」——不编造。
    if metadata
        .get("context_window")
        .and_then(Value::as_i64)
        .is_none_or(|value| value <= 0)
    {
        metadata.insert(
            "context_window".to_string(),
            json!(workbuddy_context_window_fallback(model_id)),
        );
    }
    if metadata
        .get("max_tokens")
        .and_then(Value::as_i64)
        .is_none_or(|value| value <= 0)
    {
        match workbuddy_max_output_fallback(model_id) {
            Some(max_output) => {
                metadata.insert("max_tokens".to_string(), json!(max_output));
            }
            // 知识表未收录输出上限 → **删掉字段**（面板同款：不编造）。
            None => {
                metadata.remove("max_tokens");
            }
        }
    }
    if let Some(tags) = entry.get("tags").and_then(Value::as_array) {
        let tags: Vec<Value> = tags
            .iter()
            .filter_map(Value::as_str)
            .map(str::trim)
            .filter(|tag| !tag.is_empty())
            .map(|tag| json!(tag))
            .collect();
        if !tags.is_empty() {
            metadata.insert("tags".to_string(), Value::Array(tags));
        }
    }
    // 思考档位（`reasoning.supportedEfforts` / `defaultEffort`，老模型键回落 `effort`）
    // 与「思考可关」——选模型时最有用的一档信息。
    let efforts = workbuddy_reasoning_efforts(entry);
    if !efforts.is_empty() {
        metadata.insert("efforts".to_string(), json!(efforts));
    }
    if let Some(default_effort) = workbuddy_default_effort(entry) {
        metadata.insert("default_effort".to_string(), json!(default_effort));
    }
    if let Some(can_disable) = entry
        .get("reasoning")
        .and_then(|reasoning| reasoning.get("canDisableThinking"))
        .and_then(Value::as_bool)
    {
        metadata.insert("can_disable_thinking".to_string(), json!(can_disable));
    }
    // 限时优惠（若有）：**牌价仍在 `credits` 里**，这里只叠加当前生效的 promo_* 字段——
    // 前端据此显示「生效价 + 徽章 + 划线牌价」。
    if let Some(fields) = promotion.and_then(Value::as_object) {
        for (key, value) in fields {
            metadata.insert(key.clone(), value.clone());
        }
    }
    // 客户端 Pro Only 同款信息：来自 data.modelTiers[].modelIds 的组级权限配置。
    if let Some(tier) = tier {
        metadata.insert("model_tier".to_string(), tier.clone());
        if tier.get("access_mode").and_then(Value::as_str) == Some("exclusive") {
            metadata.insert("plan_restricted".to_string(), json!(true));
        }
    }
    Value::Object(metadata)
}

/// 按候选键顺序取一个标量（字符串 / 数字 / 布尔都接受）。
pub(super) fn workbuddy_model_value(entry: &Value, keys: &[&str]) -> Option<Value> {
    for key in keys {
        match entry.get(*key) {
            Some(Value::String(text)) => {
                let trimmed = text.trim();
                if !trimmed.is_empty() {
                    return Some(json!(trimmed));
                }
            }
            Some(value @ (Value::Number(_) | Value::Bool(_))) => return Some(value.clone()),
            _ => {}
        }
    }
    None
}

pub(super) fn workbuddy_reasoning_efforts(entry: &Value) -> Vec<String> {
    entry
        .get("reasoning")
        .and_then(|reasoning| reasoning.get("supportedEfforts"))
        .and_then(Value::as_array)
        .map(|efforts| {
            efforts
                .iter()
                .filter_map(Value::as_str)
                .map(|effort| effort.trim().to_string())
                .filter(|effort| !effort.is_empty())
                .collect()
        })
        .unwrap_or_default()
}

pub(super) fn workbuddy_default_effort(entry: &Value) -> Option<String> {
    let reasoning = entry.get("reasoning")?;
    for key in ["defaultEffort", "effort"] {
        if let Some(effort) = reasoning
            .get(key)
            .and_then(Value::as_str)
            .map(str::trim)
            .filter(|effort| !effort.is_empty())
        {
            return Some(effort.to_string());
        }
    }
    None
}

pub(super) fn workbuddy_model_string(entry: &Value, keys: &[&str]) -> Option<String> {
    keys.iter().find_map(|key| {
        entry
            .get(*key)
            .and_then(Value::as_str)
            .map(str::trim)
            .filter(|value| !value.is_empty())
            .map(ToOwned::to_owned)
    })
}

pub(super) fn workbuddy_model_i64(entry: &Value, keys: &[&str]) -> Option<i64> {
    keys.iter().find_map(|key| {
        entry.get(*key).and_then(|value| match value {
            Value::Number(number) => number.as_i64(),
            Value::String(text) => text.trim().parse::<i64>().ok(),
            _ => None,
        })
    })
}

pub(super) fn workbuddy_model_bool(entry: &Value, keys: &[&str]) -> Option<bool> {
    keys.iter().find_map(|key| {
        entry.get(*key).and_then(|value| match value {
            Value::Bool(flag) => Some(*flag),
            Value::String(text) => match text.trim().to_ascii_lowercase().as_str() {
                "true" | "1" => Some(true),
                "false" | "0" => Some(false),
                _ => None,
            },
            _ => None,
        })
    })
}

/// WorkBuddy：把每个模型的推理档位写进 key 元数据（`workbuddy.models.<模型>`）。
///
/// 这是面板 `efforts` / `defaultEfforts` 缓存（`FetchModels` 刷新）的等价物——
/// 请求体做 `reasoning_effort` 降级时要按模型支持的档位裁剪。**只收有档位信息的模型**；
/// 一个都没有时返回 `None`（不写空桶，避免无意义地改 key 元数据）。
///
/// 注意与额度刷新共用 `workbuddy` 命名空间，`merge_upstream_metadata` 里已为该命名空间
/// 加了逐字段保留规则，所以两边不会互相抹掉。
const WORKBUDDY_PRO_ONLY_MODEL_IDS: &[&str] = &[
    "gpt-6-astra",
    "gpt-6.1-sol",
    "gpt-6-sol",
    "gpt-6-luna",
    "gpt-5.6-sol",
    "gpt-5.6-terra",
    "gpt-5.6-luna",
    "gpt-5.5",
    "gpt-5.4",
    "grok-4.7",
    "gemini-3.8-flash",
    "gemini-3.5-flash",
];

fn workbuddy_pro_only_tier() -> Value {
    json!({
        "id": "gpt-pro-only",
        "access_mode": "exclusive",
        "tier": "standard",
        "badge": {"color": "#009273", "label": "Pro Only", "labelEn": "Pro Only"},
        "hover": {"textZh": "模型仅面向 Pro 用户开放。", "textEn": "Exclusive to Pro subscribers.", "action": {"labelZh": "升级 Pro", "labelEn": "Upgrade to Pro", "type": "upgrade"}}
    })
}

pub(super) fn workbuddy_model_catalog_metadata(cached_models: &[Value]) -> Option<Value> {
    let mut models = serde_json::Map::new();
    for model in cached_models {
        let Some(object) = model.as_object() else {
            continue;
        };
        let Some(model_id) = object
            .get("id")
            .and_then(Value::as_str)
            .map(str::trim)
            .filter(|value| !value.is_empty())
        else {
            continue;
        };
        let mut entry = serde_json::Map::new();
        for field in [
            "label",
            "display_name",
            "vendor",
            "credits",
            "description",
            "context_window",
            "max_tokens",
            "max_allowed_size",
            "supports_images",
            "supports_reasoning",
            "supports_tool_call",
            "only_reasoning",
            "can_disable_thinking",
            "tags",
            "model_test_capabilities",
            "promo_factor",
            "promo_credits",
            "promo_label",
            "promo_note",
        ] {
            if let Some(value) = object.get(field) {
                entry.insert(field.to_string(), value.clone());
            }
        }
        if WORKBUDDY_PRO_ONLY_MODEL_IDS.contains(&model_id) {
            entry.insert("model_tier".to_string(), workbuddy_pro_only_tier());
            entry.insert("plan_restricted".to_string(), json!(true));
        }
        if let Some(efforts) = object
            .get("efforts")
            .and_then(Value::as_array)
            .filter(|values| !values.is_empty())
        {
            entry.insert("efforts".to_string(), Value::Array(efforts.clone()));
        }
        for field in ["model_tier", "plan_restricted"] {
            if let Some(value) = object.get(field) {
                entry.insert(field.to_string(), value.clone());
            }
        }
        if let Some(default_effort) = object
            .get("default_effort")
            .and_then(Value::as_str)
            .map(str::trim)
            .filter(|value| !value.is_empty())
        {
            entry.insert(
                "default_effort".to_string(),
                Value::String(default_effort.to_string()),
            );
        }
        if !entry.is_empty() {
            models.insert(model_id.to_string(), Value::Object(entry));
        }
    }
    if models.is_empty() {
        return None;
    }
    Some(json!({"workbuddy": {"models": Value::Object(models)}}))
}
