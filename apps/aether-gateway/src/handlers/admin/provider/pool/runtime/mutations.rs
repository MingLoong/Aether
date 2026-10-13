use super::keys::{pool_cooldown_index_key, pool_cooldown_key};
use crate::handlers::admin::request::AdminAppState;

pub(crate) async fn clear_admin_provider_pool_cooldown(
    state: &AdminAppState<'_>,
    provider_id: &str,
    key_id: &str,
) {
    let _ = state
        .runtime_state()
        .kv_delete(&pool_cooldown_key(provider_id, key_id))
        .await;
    let _ = state
        .runtime_state()
        .set_remove(&pool_cooldown_index_key(provider_id), key_id)
        .await;
    // cline：额外清除 403 模型级冷却（独立 runtime_kv，与通用池 402/429 冷却分开存）。
    crate::cline_pool::clear_cline_cooldown(state.runtime_state(), provider_id, key_id).await;
}

pub(crate) async fn reset_admin_provider_pool_cost(
    state: &AdminAppState<'_>,
    provider_id: &str,
    key_id: &str,
) {
    let _ = state
        .runtime_state()
        .score_remove_by_score(&format!("ap:{provider_id}:cost:{key_id}"), f64::INFINITY)
        .await;
}
