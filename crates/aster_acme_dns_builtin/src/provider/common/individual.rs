//! Contracts and durable lifecycle for APIs that manage individual DNS records.
pub(in crate::provider) mod api;
pub(in crate::provider) mod lifecycle;
#[cfg(test)]
mod tests;
