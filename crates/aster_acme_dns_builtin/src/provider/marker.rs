#[cfg(any(
    feature = "aliyun",
    feature = "cloudflare",
    feature = "huawei_cloud",
    feature = "tencent_cloud"
))]
pub(super) fn publication(id: &str) -> String {
    format!("asteracme:{id}")
}

#[cfg(feature = "huawei_cloud")]
pub(super) fn publication_value(id: &str, value: &str) -> String {
    format!(
        "{}={}",
        publication(id),
        crate::provider::rpc::sha256(value.as_bytes())
    )
}
