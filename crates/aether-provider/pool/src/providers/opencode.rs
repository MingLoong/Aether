use crate::provider::ProviderPoolAdapter;

/// Pool adapter for the `opencode` provider type.
///
/// OpenCode upstreams share a fixed `Bearer public` credential across all
/// keys; each pool key represents one front-proxy exit IP that carries a
/// fixed daily quota.  The default adapter behaviour (health/round-robin
/// scheduling, per-key cooldown, quota snapshots) already provides the
/// rotation and failure isolation needed for an IP pool, so no custom quota
/// hooks are required.
#[derive(Debug, Clone, Default)]
pub struct OpenCodeProviderPoolAdapter;

impl ProviderPoolAdapter for OpenCodeProviderPoolAdapter {
    fn provider_type(&self) -> &'static str {
        "opencode"
    }
}
