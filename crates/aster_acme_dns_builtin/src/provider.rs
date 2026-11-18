//! Feature-selected DNS provider backends; each vendor is an independent feature.
#[cfg(feature = "aliyun")]
pub mod aliyun;
#[cfg(feature = "cloudflare")]
pub mod cloudflare;
#[cfg(feature = "huawei_cloud")]
pub mod huawei_cloud;
#[cfg(feature = "tencent_cloud")]
pub mod tencent_cloud;

#[cfg(any(feature = "aliyun", feature = "tencent_cloud"))]
mod individual;
#[cfg(any(
    feature = "aliyun",
    feature = "tencent_cloud",
    feature = "huawei_cloud"
))]
mod rpc;
#[cfg(all(test, any(feature = "aliyun", feature = "tencent_cloud")))]
mod tests;
