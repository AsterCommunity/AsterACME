//! Lossless wire resource status parsing.

use aster_forge_macros::wire_enum;

wire_enum! {
    /// Server account status (RFC 8555 §7.1.2).
    pub enum AccountStatus {
        /// Active account.
        Valid => "valid",
        /// Account deactivated by the client.
        Deactivated => "deactivated",
        /// Account revoked by the server.
        Revoked => "revoked",
    }
}
wire_enum! {
    /// Server order status (RFC 8555 §7.1.3).
    pub enum OrderStatus {
        /// Authorizations are outstanding.
        Pending => "pending",
        /// The order can be finalized.
        Ready => "ready",
        /// The CA is issuing the certificate.
        Processing => "processing",
        /// The certificate is available.
        Valid => "valid",
        /// The order failed.
        Invalid => "invalid",
    }
}
wire_enum! {
    /// Server authorization status (RFC 8555 §7.1.4).
    pub enum AuthorizationStatus {
        /// Identifier validation is outstanding.
        Pending => "pending",
        /// The identifier is authorized.
        Valid => "valid",
        /// Validation failed.
        Invalid => "invalid",
        /// Client deactivated the authorization.
        Deactivated => "deactivated",
        /// Authorization expired.
        Expired => "expired",
        /// Server revoked the authorization.
        Revoked => "revoked",
    }
}
wire_enum! {
    /// Server challenge status (RFC 8555 §7.1.5).
    pub enum ChallengeStatus {
        /// Challenge has not been acknowledged.
        Pending => "pending",
        /// Validation is running.
        Processing => "processing",
        /// Validation succeeded.
        Valid => "valid",
        /// Validation failed.
        Invalid => "invalid",
    }
}
