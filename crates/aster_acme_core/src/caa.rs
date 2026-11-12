//! Advisory CAA policy evaluation (RFC 8659 §§3–4, RFC 8657 §§3–4).
//! A local observation never authorizes or prevents a CA operation.

/// Raw CAA property; keep opaque values so unknown tags remain observable.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Property {
    /// RFC 8659 issuer-critical bit (128), distinct from reserved flag bits.
    pub critical: bool,
    /// Case-insensitive property tag.
    pub tag: String,
    /// Original property value bytes.
    pub value: Vec<u8>,
}

/// Inputs known from directory, account and selected challenge method.
pub struct Request<'a> {
    /// RFC 8555 §7.1.1 alternatives, not a list of required records.
    pub issuers: &'a [String],
    /// Exact account resource URL, if known.
    pub account_uri: Option<&'a str>,
    /// ACME wire label (dns-01, http-01, tls-alpn-01).
    pub method: &'a str,
    /// Whether the original identifier begins with *.
    pub wildcard: bool,
}

/// Local evidence only; CA extension support and DNS perspective can differ.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Observation {
    /// No applicable issue/issuewild restriction exists.
    Unrestricted,
    /// At least one record matches known inputs.
    Matches,
    /// No applicable record matches known inputs; warn, never reject issuance.
    NoMatch,
    /// Missing issuer metadata or unknown critical/parameter semantics.
    Unknown,
}

/// Evaluate one effective `RRset`, never merge child and parent sets.
#[must_use]
pub fn evaluate(properties: &[Property], request: &Request<'_>) -> Observation {
    // RFC 8659 §4.1: only a CA can know whether an unknown critical tag
    // is supported. A client must not claim unrestricted/allowed in that case.
    if properties.iter().any(|p| {
        p.critical
            && !["issue", "issuewild", "iodef"]
                .iter()
                .any(|tag| p.tag.eq_ignore_ascii_case(tag))
    }) {
        return Observation::Unknown;
    }
    let tag = if request.wildcard
        && properties
            .iter()
            .any(|p| p.tag.eq_ignore_ascii_case("issuewild"))
    {
        "issuewild"
    } else {
        "issue"
    };
    let applicable = properties
        .iter()
        .filter(|p| p.tag.eq_ignore_ascii_case(tag))
        .collect::<Vec<_>>();
    if applicable.is_empty() {
        return Observation::Unrestricted;
    }
    if request.issuers.is_empty() {
        return Observation::Unknown;
    }
    let mut unknown = false;
    for property in applicable {
        match matches_property(&property.value, request) {
            Observation::Matches => return Observation::Matches,
            Observation::Unknown => unknown = true,
            Observation::Unrestricted | Observation::NoMatch => {}
        }
    }
    if unknown {
        Observation::Unknown
    } else {
        Observation::NoMatch
    }
}

fn matches_property(bytes: &[u8], request: &Request<'_>) -> Observation {
    let Ok(value) = std::str::from_utf8(bytes) else {
        return Observation::NoMatch;
    };
    let mut fields = value.split(';');
    let issuer = fields.next().unwrap_or("").trim_matches([' ', '\t']);
    // RFC 8659 §4.2: malformed/empty issue values authorize no issuer.
    if !domain(issuer)
        || !request
            .issuers
            .iter()
            .any(|id| id.eq_ignore_ascii_case(issuer))
    {
        return Observation::NoMatch;
    }
    let mut account = false;
    let mut method = false;
    let mut unknown = false;
    for field in fields {
        let field = field.trim_matches([' ', '\t']);
        if field.is_empty() {
            continue;
        }
        let Some((key, value)) = field.split_once('=') else {
            return Observation::NoMatch;
        };
        let key = key.trim_matches([' ', '\t']);
        let value = value.trim_matches([' ', '\t']);
        if !label(key)
            || !value
                .bytes()
                .all(|b| (0x21..=0x7e).contains(&b) && b != b';')
        {
            return Observation::NoMatch;
        }
        match key {
            "accounturi" => {
                if account {
                    return Observation::NoMatch;
                }
                account = true;
                match request.account_uri {
                    Some(uri) if value == uri => {}
                    Some(_) => return Observation::NoMatch,
                    None => unknown = true,
                }
            }
            "validationmethods" => {
                if method {
                    return Observation::NoMatch;
                }
                method = true;
                if !value.split(',').all(|method| {
                    !method.is_empty()
                        && method
                            .bytes()
                            .all(|b| b.is_ascii_alphanumeric() || b == b'-')
                }) || !value.split(',').any(|m| m == request.method)
                {
                    return Observation::NoMatch;
                }
            }
            _ => unknown = true,
        }
    }
    if unknown {
        Observation::Unknown
    } else {
        Observation::Matches
    }
}
fn label(value: &str) -> bool {
    !value.is_empty()
        && value
            .as_bytes()
            .first()
            .is_some_and(u8::is_ascii_alphanumeric)
        && value
            .as_bytes()
            .last()
            .is_some_and(u8::is_ascii_alphanumeric)
        && value
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'-')
}
fn domain(value: &str) -> bool {
    !value.is_empty() && value.split('.').all(label)
}

#[cfg(test)]
mod tests;
