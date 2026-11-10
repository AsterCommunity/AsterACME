//! RFC 8555 section 7.6 certificate revocation wire payload.
use serde::{Deserialize, Serialize};

/// Revocation request; DER leaf bytes use unpadded base64url, never PEM or the full chain.
#[derive(Debug, Serialize, Deserialize)]
pub struct RevocationRequest {
    /// Issued leaf certificate in base64url DER form.
    pub certificate: String,
    /// RFC 5280 reason code, omitted when the operator has not selected one.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub reason: Option<RevocationReason>,
}

/// RFC 5280 section 5.3.1 reason codes. Seven is unassigned; CA policy may reject
/// any code. removeFromCRL is a CRL delta mechanism, not an ACME unrevocation API.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(try_from = "u8", into = "u8")]
pub enum RevocationReason {
    /// No specific reason (0).
    Unspecified,
    /// Subject private key compromised (1).
    KeyCompromise,
    /// Issuing CA private key compromised (2).
    CaCompromise,
    /// Subject affiliation changed (3).
    AffiliationChanged,
    /// Replaced by another certificate (4).
    Superseded,
    /// No longer used (5).
    CessationOfOperation,
    /// Certificate hold (6); CA-specific support.
    CertificateHold,
    /// Removal entry for delta CRLs (8); does not reactivate a certificate through ACME.
    RemoveFromCrl,
    /// Privileges withdrawn (9).
    PrivilegeWithdrawn,
    /// Attribute authority compromised (10).
    AaCompromise,
}

impl RevocationReason {
    /// Assigned reason values; not a statement of acceptance by any CA.
    pub const ALL: [Self; 10] = [
        Self::Unspecified,
        Self::KeyCompromise,
        Self::CaCompromise,
        Self::AffiliationChanged,
        Self::Superseded,
        Self::CessationOfOperation,
        Self::CertificateHold,
        Self::RemoveFromCrl,
        Self::PrivilegeWithdrawn,
        Self::AaCompromise,
    ];

    /// Numeric wire code defined by RFC 5280.
    #[must_use]
    pub const fn code(self) -> u8 {
        match self {
            Self::Unspecified => 0,
            Self::KeyCompromise => 1,
            Self::CaCompromise => 2,
            Self::AffiliationChanged => 3,
            Self::Superseded => 4,
            Self::CessationOfOperation => 5,
            Self::CertificateHold => 6,
            Self::RemoveFromCrl => 8,
            Self::PrivilegeWithdrawn => 9,
            Self::AaCompromise => 10,
        }
    }

    /// Stable human/CLI name.
    #[must_use]
    pub const fn name(self) -> &'static str {
        match self {
            Self::Unspecified => "unspecified",
            Self::KeyCompromise => "key-compromise",
            Self::CaCompromise => "ca-compromise",
            Self::AffiliationChanged => "affiliation-changed",
            Self::Superseded => "superseded",
            Self::CessationOfOperation => "cessation-of-operation",
            Self::CertificateHold => "certificate-hold",
            Self::RemoveFromCrl => "remove-from-crl",
            Self::PrivilegeWithdrawn => "privilege-withdrawn",
            Self::AaCompromise => "aa-compromise",
        }
    }

    /// Parse the exact assigned reason name.
    #[must_use]
    pub fn from_name(value: &str) -> Option<Self> {
        Self::ALL.into_iter().find(|reason| reason.name() == value)
    }
}

impl From<RevocationReason> for u8 {
    fn from(value: RevocationReason) -> Self {
        value.code()
    }
}
impl TryFrom<u8> for RevocationReason {
    type Error = &'static str;
    fn try_from(value: u8) -> Result<Self, Self::Error> {
        Self::ALL
            .into_iter()
            .find(|reason| reason.code() == value)
            .ok_or("unassigned certificate revocation reason")
    }
}

impl std::fmt::Display for RevocationReason {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{} ({})", self.name(), self.code())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn all_assigned_reason_codes_roundtrip_and_unassigned_codes_are_rejected() {
        for reason in RevocationReason::ALL {
            assert_eq!(serde_json::to_value(reason).unwrap(), reason.code());
            assert_eq!(
                serde_json::from_value::<RevocationReason>(serde_json::json!(reason.code()))
                    .unwrap(),
                reason
            );
            assert_eq!(RevocationReason::from_name(reason.name()), Some(reason));
        }
        for invalid in [7, 11, 255] {
            assert!(RevocationReason::try_from(invalid).is_err());
        }
        assert!(serde_json::from_str::<RevocationReason>("-1").is_err());
        assert!(serde_json::from_str::<RevocationReason>("256").is_err());
    }
}
