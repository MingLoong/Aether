#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ProviderPoolCapability {
    PlanTier,
    QuotaReset,
    QuotaRefresh,
    QuotaExpiry,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct ProviderPoolCapabilities {
    pub plan_tier: bool,
    pub quota_reset: bool,
    pub quota_refresh: bool,
    pub quota_expiry: bool,
}

impl ProviderPoolCapabilities {
    pub fn supports(self, capability: ProviderPoolCapability) -> bool {
        match capability {
            ProviderPoolCapability::PlanTier => self.plan_tier,
            ProviderPoolCapability::QuotaReset => self.quota_reset,
            ProviderPoolCapability::QuotaRefresh => self.quota_refresh,
            ProviderPoolCapability::QuotaExpiry => self.quota_expiry,
        }
    }
}
