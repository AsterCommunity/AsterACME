//! Shared classification for recursive DNS observations; server errors are not absence.
pub(crate) fn empty_answer(error: &hickory_resolver::net::NetError) -> bool {
    matches!(error, hickory_resolver::net::NetError::Dns(
        hickory_resolver::net::DnsError::NoRecordsFound(records)
    ) if matches!(records.response_code, hickory_resolver::proto::op::ResponseCode::NoError | hickory_resolver::proto::op::ResponseCode::NXDomain))
}

#[cfg(test)]
mod tests {
    use crate::dns::empty_answer;
    use hickory_resolver::proto::rr::RecordType;
    #[test]
    fn dns_negative_answers_distinguish_nodata_nxdomain_and_servfail() {
        use hickory_resolver::{
            net::{NetError, NoRecords},
            proto::{
                op::{Query, ResponseCode},
                rr::Name,
            },
        };
        for (code, empty) in [
            (ResponseCode::NoError, true),
            (ResponseCode::NXDomain, true),
            (ResponseCode::ServFail, false),
            (ResponseCode::Refused, false),
        ] {
            let error = NetError::from(NoRecords::new(
                Query::query(Name::from_ascii("example.com.").unwrap(), RecordType::CAA),
                code,
            ));
            assert_eq!(empty_answer(&error), empty);
        }
    }
}
