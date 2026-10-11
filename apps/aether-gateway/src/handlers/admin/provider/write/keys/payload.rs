use crate::handlers::admin::request::AdminAppState;
use crate::provider_key_auth::provider_key_effective_api_formats;
use aether_data_contracts::repository::provider_catalog::{
    ProviderCatalogKeyListOrder, ProviderCatalogKeyListQuery,
};
use serde_json::{json, Value};
use std::time::{SystemTime, UNIX_EPOCH};

async fn build_admin_provider_key_items_payload(
    state: &AdminAppState<'_>,
    provider_id: &str,
    skip: usize,
    limit: usize,
) -> Option<(Vec<Value>, usize)> {
    if !state.has_provider_catalog_data_reader() {
        tracing::debug!(
            provider_id,
            "provider catalog reader is not configured; provider keys payload unavailable"
        );
        return None;
    }
    // 读失败与「真的不存在」在调用方眼里都是 None → 404「Provider {id} 不存在」，
    // 但两者的排查方向完全不同，所以真因必须落日志。
    // 2026-10 为此绕过好几圈：catalog 密文按 (provider_id, key_id) 绑定，跨 provider
    // 搬行会让校验失败，而对外表现却是「这个 provider 不存在」。
    let provider = match state
        .read_provider_catalog_providers_by_ids(&[provider_id.to_string()])
        .await
    {
        Ok(mut providers) => providers.drain(..).next(),
        Err(err) => {
            tracing::warn!(
                provider_id,
                error = ?err,
                "provider catalog provider read failed while building provider keys payload"
            );
            None
        }
    }?;
    let key_page = match state
        .list_provider_catalog_key_page(&ProviderCatalogKeyListQuery {
            provider_id: provider.id.clone(),
            search: None,
            is_active: None,
            offset: skip,
            limit,
            order: ProviderCatalogKeyListOrder::CreatedAt,
        })
        .await
    {
        Ok(page) => page,
        Err(err) => {
            tracing::warn!(
                provider_id,
                error = ?err,
                "provider catalog key page read failed while building provider keys payload"
            );
            return None;
        }
    };
    let endpoints = state
        .list_provider_catalog_endpoints_by_provider_ids(std::slice::from_ref(&provider.id))
        .await
        .ok()
        .unwrap_or_default();
    let now_unix_secs = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .ok()
        .map(|duration| duration.as_secs())
        .unwrap_or(0);
    let keys = key_page.items;

    let items = keys
        .into_iter()
        .map(|key| {
            let api_formats =
                provider_key_effective_api_formats(&key, &provider.provider_type, &endpoints);
            state.build_admin_provider_key_response(
                &key,
                &provider.provider_type,
                &api_formats,
                now_unix_secs,
            )
        })
        .collect();
    Some((items, key_page.total))
}

pub(crate) async fn build_admin_provider_keys_payload(
    state: &AdminAppState<'_>,
    provider_id: &str,
    skip: usize,
    limit: usize,
) -> Option<Value> {
    let (items, _) =
        build_admin_provider_key_items_payload(state, provider_id, skip, limit).await?;
    Some(Value::Array(items))
}

pub(crate) async fn build_admin_provider_keys_page_payload(
    state: &AdminAppState<'_>,
    provider_id: &str,
    page: usize,
    page_size: usize,
) -> Option<Value> {
    let skip = page.saturating_sub(1).saturating_mul(page_size);
    let (items, total) =
        build_admin_provider_key_items_payload(state, provider_id, skip, page_size).await?;
    Some(json!({
        "total": total,
        "page": page,
        "page_size": page_size,
        "keys": items,
    }))
}
