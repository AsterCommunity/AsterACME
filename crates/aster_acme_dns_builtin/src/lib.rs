//! Feature-selected provider state machines. No HTTP clients or filesystem access.
#![cfg_attr(
    not(test),
    deny(
        clippy::unwrap_used,
        clippy::expect_used,
        clippy::panic,
        clippy::unreachable,
        clippy::unimplemented,
        clippy::todo
    )
)]
pub mod provider;
pub mod rrset;

#[cfg(test)]
mod tests {
    #[test]
    fn linked_inventory_matches_the_vendor_feature_set() {
        let registry = aster_acme_dns::backend::ProviderRegistry::linked().unwrap();
        let descriptors = registry.descriptors();
        assert_eq!(
            descriptors
                .iter()
                .any(|backend| backend.id == "com.astercosm.acme.dns.cloudflare"),
            cfg!(feature = "cloudflare")
        );
        assert_eq!(descriptors.len(), usize::from(cfg!(feature = "cloudflare")));
    }
}
