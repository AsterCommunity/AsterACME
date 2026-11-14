//! Domain/key/account-bound hashed URI construction and prefix validation for draft-02.
use crate::{
    challenge::{ChallengeError, dns_persist::invalid},
    identifier::DnsIdentifier,
};
use aster_acme_protocol::{directory::DirectoryMeta, url::AcmeUrl};
use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use sha2::{Digest as _, Sha256};

pub(super) fn derive(
    identifier: &DnsIdentifier,
    account_url: &AcmeUrl,
    jwk_thumbprint: &str,
    prefix: &str,
) -> Result<String, ChallengeError> {
    if !account_url.as_str().is_ascii() {
        return Err(invalid("account URL must be an ASCII URI"));
    }
    if jwk_thumbprint.len() != 43
        || URL_SAFE_NO_PAD
            .decode(jwk_thumbprint)
            .map_or(true, |bytes| bytes.len() != 32)
    {
        return Err(ChallengeError::InvalidThumbprint);
    }
    let domain = identifier.name().as_str();
    let length =
        u8::try_from(domain.len()).map_err(|_| invalid("domain exceeds hash length limit"))?;
    let mut digest = Sha256::new();
    digest.update([length]);
    digest.update(domain.as_bytes());
    digest.update(jwk_thumbprint.as_bytes());
    digest.update(account_url.as_str().as_bytes());
    let hashed_uri = format!(
        "{prefix}sha-256/{}",
        URL_SAFE_NO_PAD.encode(digest.finalize())
    );
    Ok(hashed_uri)
}

// The prefix is mandatory even for interactive challenges. Validate it before
// newOrder as well as derivation so unsupported CAs do not consume an order.
pub(crate) fn validate_prefix(meta: &DirectoryMeta) -> Result<&str, ChallengeError> {
    meta.account_hash_prefix
        .as_deref()
        .filter(|prefix| valid_uri(&format!("{prefix}sha-256/{}", "A".repeat(43))))
        .ok_or_else(|| invalid("missing or invalid directory accountHashPrefix"))
}

pub(super) fn matches_prefix(value: &str, prefix: &str) -> bool {
    value
        .strip_prefix(prefix)
        .and_then(|value| value.strip_prefix("sha-256/"))
        .is_some_and(|hash| {
            hash.len() == 43
                && URL_SAFE_NO_PAD
                    .decode(hash)
                    .is_ok_and(|bytes| bytes.len() == 32)
        })
}

fn valid_uri(value: &str) -> bool {
    let mut bytes = value.bytes();
    while let Some(byte) = bytes.next() {
        if byte == b'%' {
            if !bytes.next().is_some_and(|byte| byte.is_ascii_hexdigit())
                || !bytes.next().is_some_and(|byte| byte.is_ascii_hexdigit())
            {
                return false;
            }
        } else if !byte.is_ascii_alphanumeric() && !b"-._~:/?#[]@!$&'()*+,=".contains(&byte) {
            return false;
        }
    }
    url::Url::parse(value).is_ok()
}
