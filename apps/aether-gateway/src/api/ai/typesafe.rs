pub(crate) fn normalized_signature(api_format: &str) -> Option<&'static str> {
    match crate::ai_serving::normalize_api_format_alias(api_format).as_str() {
        "typesafe:systemone" => Some("typesafe:systemone"),
        _ => None,
    }
}

pub(crate) fn local_path(api_format: &str) -> Option<&'static str> {
    match crate::ai_serving::normalize_api_format_alias(api_format).as_str() {
        "typesafe:systemone" => Some("/v1/systemone"),
        _ => None,
    }
}
