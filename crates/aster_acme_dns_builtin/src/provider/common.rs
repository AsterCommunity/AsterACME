//! Provider-neutral capabilities shared by vendor implementations.
#[cfg(feature = "_individual-records")]
pub(in crate::provider) mod individual;
#[cfg(feature = "_publication-markers")]
pub(in crate::provider) mod marker;
#[cfg(feature = "_http")]
pub(in crate::provider) mod retry;
#[cfg(feature = "_rpc")]
pub(in crate::provider) mod rpc;
#[cfg(all(test, feature = "_individual-records"))]
pub(in crate::provider) mod tests;
#[cfg(feature = "_txt")]
pub(in crate::provider) mod txt;
