//! Vendor features automatically enable the shared capabilities they use.
#[cfg(feature = "_http")]
mod retry;

#[cfg(feature = "aliyun")]
pub mod aliyun;
#[cfg(feature = "cloudflare")]
pub mod cloudflare;
#[cfg(feature = "huawei_cloud")]
pub mod huawei_cloud;
#[cfg(feature = "tencent_cloud")]
pub mod tencent_cloud;

#[cfg(feature = "_individual-records")]
mod individual;
#[cfg(feature = "_signed-api")]
mod rpc;
#[cfg(all(test, feature = "_individual-records"))]
mod tests;
