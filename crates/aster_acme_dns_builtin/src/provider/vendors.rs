//! Provider-specific DNS API adapters.
#[cfg(feature = "aliyun")]
pub mod aliyun;
#[cfg(feature = "cloudflare")]
pub mod cloudflare;
#[cfg(feature = "google_cloud_dns")]
pub mod google_cloud_dns;
#[cfg(feature = "huawei_cloud")]
pub mod huawei_cloud;
#[cfg(feature = "tencent_cloud")]
pub mod tencent_cloud;
