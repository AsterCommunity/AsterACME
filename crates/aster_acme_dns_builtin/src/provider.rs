//! Feature-selected DNS provider backends; each vendor is an independent feature.

#[derive(Clone, Copy)]
pub(super) enum HttpMethod {
    Get,
    Post,
    Put,
    Delete,
}

impl HttpMethod {
    pub(super) const fn wire(self) -> &'static str {
        match self {
            Self::Get => "GET",
            Self::Post => "POST",
            Self::Put => "PUT",
            Self::Delete => "DELETE",
        }
    }
}
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
