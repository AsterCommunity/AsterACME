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
        let vendors = [
            (
                "com.astercosm.acme.dns.google-cloud-dns",
                cfg!(feature = "google_cloud_dns"),
            ),
            (
                "com.astercosm.acme.dns.cloudflare",
                cfg!(feature = "cloudflare"),
            ),
            ("com.astercosm.acme.dns.aliyun", cfg!(feature = "aliyun")),
            (
                "com.astercosm.acme.dns.tencent-cloud",
                cfg!(feature = "tencent_cloud"),
            ),
            (
                "com.astercosm.acme.dns.huawei-cloud",
                cfg!(feature = "huawei_cloud"),
            ),
        ];
        for (id, enabled) in vendors {
            assert_eq!(descriptors.iter().any(|backend| backend.id == id), enabled);
        }
        assert_eq!(
            descriptors.len(),
            vendors.iter().filter(|(_, enabled)| *enabled).count()
        );
    }
}
