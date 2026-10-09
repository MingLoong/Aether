use crate::handlers::admin::provider::shared::model_test_capabilities::{
    admin_provider_model_supports_image_generation, admin_provider_model_test_capabilities_payload,
};
use crate::handlers::admin::request::AdminAppState;
use crate::GatewayError;
use aether_admin::provider::models as admin_provider_models_pure;
use aether_data_contracts::repository::global_models::{
    AdminProviderModelListQuery, StoredAdminProviderModel,
};
use aether_data_contracts::repository::provider_catalog::StoredProviderCatalogProvider;
use std::time::{SystemTime, UNIX_EPOCH};

pub(super) fn admin_provider_model_effective_input_price(
    model: &StoredAdminProviderModel,
) -> Option<f64> {
    admin_provider_models_pure::admin_provider_model_effective_input_price(model)
}

pub(super) fn admin_provider_model_effective_output_price(
    model: &StoredAdminProviderModel,
) -> Option<f64> {
    admin_provider_models_pure::admin_provider_model_effective_output_price(model)
}

pub(super) fn admin_provider_model_effective_capability(
    model: &StoredAdminProviderModel,
    capability: &str,
) -> bool {
    admin_provider_models_pure::admin_provider_model_effective_capability(model, capability)
}

pub(super) fn build_admin_provider_model_response(
    provider: &StoredProviderCatalogProvider,
    model: &StoredAdminProviderModel,
    now_unix_secs: u64,
) -> serde_json::Value {
    let mut payload =
        admin_provider_models_pure::build_admin_provider_model_response(model, now_unix_secs);
    let fallback_supports_image_generation = payload
        .get("effective_supports_image_generation")
        .and_then(serde_json::Value::as_bool)
        .unwrap_or(false);
    let supports_image_generation = admin_provider_model_supports_image_generation(
        &provider.provider_type,
        &model.provider_model_name,
        fallback_supports_image_generation,
    );
    if let Some(object) = payload.as_object_mut() {
        object.insert(
            "model_test_capabilities".to_string(),
            admin_provider_model_test_capabilities_payload(
                &provider.provider_type,
                &model.provider_model_name,
                supports_image_generation,
            ),
        );
    }
    payload
}

/// Builds the admin provider model list payload.
///
/// `Ok(None)` means the provider itself does not exist; a data-layer failure is reported as
/// `Err` so the caller can answer with a truthful "data unavailable" response instead of
/// pretending the provider is missing.
pub(super) async fn build_admin_provider_models_payload(
    state: &AdminAppState<'_>,
    provider_id: &str,
    skip: usize,
    limit: usize,
    is_active: Option<bool>,
) -> Result<Option<serde_json::Value>, GatewayError> {
    if !state.has_provider_catalog_data_reader() || !state.has_global_model_data_reader() {
        return Err(admin_provider_models_data_unavailable_error());
    }
    let Some(provider) = state
        .read_provider_catalog_providers_by_ids(&[provider_id.to_string()])
        .await?
        .into_iter()
        .next()
    else {
        return Ok(None);
    };
    let provider_id = provider.id.clone();
    let mut models = state
        .list_admin_provider_models(&AdminProviderModelListQuery {
            provider_id,
            is_active,
            offset: skip,
            limit,
        })
        .await?;
    models.sort_by(|left, right| {
        left.provider_model_name
            .cmp(&right.provider_model_name)
            .then_with(|| left.id.cmp(&right.id))
    });
    let now_unix_secs = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .ok()
        .map(|duration| duration.as_secs())
        .unwrap_or(0);
    Ok(Some(serde_json::Value::Array(
        models
            .iter()
            .map(|model| build_admin_provider_model_response(&provider, model, now_unix_secs))
            .collect(),
    )))
}

/// Builds one admin provider model payload.
///
/// `Ok(None)` means the provider or the model id does not exist; a data-layer failure is
/// reported as `Err` instead of being folded into the same "not found" answer.
pub(super) async fn build_admin_provider_model_payload(
    state: &AdminAppState<'_>,
    provider_id: &str,
    model_id: &str,
) -> Result<Option<serde_json::Value>, GatewayError> {
    if !state.has_provider_catalog_data_reader() || !state.has_global_model_data_reader() {
        return Err(admin_provider_models_data_unavailable_error());
    }
    let Some(provider) = state
        .read_provider_catalog_providers_by_ids(&[provider_id.to_string()])
        .await?
        .into_iter()
        .next()
    else {
        return Ok(None);
    };
    let Some(model) = state
        .get_admin_provider_model(provider_id, model_id)
        .await?
    else {
        return Ok(None);
    };
    let now_unix_secs = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .ok()
        .map(|duration| duration.as_secs())
        .unwrap_or(0);
    Ok(Some(build_admin_provider_model_response(
        &provider,
        &model,
        now_unix_secs,
    )))
}

/// Mirrors the provider CRUD data-unavailable answer: a read failure must not be reported as
/// "Provider ... 不存在".
pub(super) fn admin_provider_models_data_unavailable_error() -> GatewayError {
    GatewayError::Internal(ADMIN_PROVIDER_MODELS_DATA_UNAVAILABLE_DETAIL.to_string())
}

pub(super) const ADMIN_PROVIDER_MODELS_DATA_UNAVAILABLE_DETAIL: &str =
    "Admin provider models data unavailable";

pub(super) async fn admin_provider_model_name_exists(
    state: &AdminAppState<'_>,
    provider_id: &str,
    provider_model_name: &str,
    exclude_model_id: Option<&str>,
) -> Result<bool, GatewayError> {
    state
        .admin_provider_model_name_exists(provider_id, provider_model_name, exclude_model_id)
        .await
}
