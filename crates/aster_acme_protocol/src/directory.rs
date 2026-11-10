//! RFC 8555 directory discovery; endpoints are supplied by the CA, never fixed paths.
use crate::url::AcmeUrl;
use serde::{Deserialize, Serialize};

/// Public production CA presets. Only the entry-point directory is predefined;
/// resource paths and EAB requirements must still be discovered from the server.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum Provider {
    /// Let's Encrypt production.
    Letsencrypt,
    /// `ZeroSSL` production.
    Zerossl,
    /// Google Trust Services production.
    Google,
}

impl Provider {
    /// Available production providers in display order; no test-environment presets.
    pub const ALL: [Self; 3] = [Self::Letsencrypt, Self::Zerossl, Self::Google];

    /// Stable provider identifier for configuration and CLI input.
    #[must_use]
    pub const fn name(self) -> &'static str {
        match self {
            Self::Letsencrypt => "letsencrypt",
            Self::Zerossl => "zerossl",
            Self::Google => "google",
        }
    }

    /// Public production directory URL, without assumptions about its resource paths.
    #[must_use]
    pub const fn directory(self) -> &'static str {
        match self {
            Self::Letsencrypt => "https://acme-v02.api.letsencrypt.org/directory",
            Self::Zerossl => "https://acme.zerossl.com/v2/DV90",
            Self::Google => "https://dv.acme-v02.api.pki.goog/directory",
        }
    }

    /// Parse an exact public provider identifier without accepting arbitrary aliases.
    #[must_use]
    pub fn from_name(name: &str) -> Option<Self> {
        Self::ALL
            .into_iter()
            .find(|provider| provider.name() == name)
    }
}

/// Directory fields used by the account client; extension fields are ignored.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Directory {
    /// HEAD endpoint for fresh nonces.
    pub new_nonce: AcmeUrl,
    /// Account creation and key-based lookup endpoint.
    pub new_account: AcmeUrl,
    /// Optional RFC 8555 keyChange endpoint; absent means rotation is unsupported.
    #[serde(default)]
    pub key_change: Option<AcmeUrl>,
    /// Optional server metadata.
    #[serde(default)]
    pub meta: DirectoryMeta,
}

/// RFC 8555 directory metadata relevant to account registration.
#[derive(Debug, Clone, Default, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct DirectoryMeta {
    /// Terms must be accepted explicitly before creating an account.
    pub terms_of_service: Option<AcmeUrl>,
    /// Whether registration requires EAB credentials.
    #[serde(default)]
    pub external_account_required: bool,
}
