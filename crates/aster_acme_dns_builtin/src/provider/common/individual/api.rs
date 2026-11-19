//! Provider-neutral types and interface for individual DNS records.
use crate::provider::common::{
    marker::{is_publication_marker, matches_publication, publication},
    rpc::invalid,
};
use aster_acme_dns::{
    CleanupStatus, DnsRecord, ProviderError,
    backend::configuration_error,
    operation::{HttpRequest, HttpResponse},
    routing::absolute_name,
};
use serde::{Deserialize, Serialize};
pub(in crate::provider) const PAGE_SIZE: u32 = 100;

#[derive(Clone, Debug, Deserialize, PartialEq, Eq, Serialize)]
#[serde(deny_unknown_fields)]
pub(in crate::provider) struct Zone {
    pub id: String,
    pub name: String, // Absolute normalized owner.
}

impl Zone {
    pub(in crate::provider) fn new(id: String, name: &str) -> Result<Self, ProviderError> {
        if id.is_empty()
            || id.len() > 80
            || !id.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'-')
        {
            return Err(invalid(false));
        }
        Ok(Self {
            id,
            name: absolute_name(name).map_err(|_| invalid(false))?,
        })
    }

    pub(in crate::provider) fn relative<'a>(&self, owner: &'a str) -> Option<&'a str> {
        if owner == self.name {
            Some("@")
        } else {
            owner.strip_suffix(&self.name)?.strip_suffix('.')
        }
    }
}

pub(in crate::provider) struct Record {
    pub id: String,
    pub relative_name: String,
    pub kind: String,
    pub value: String,
    pub marker: Option<String>,
    pub ttl: u32,
    pub enabled: bool,
    pub default_line: bool,
}

pub(in crate::provider) struct Page<T> {
    pub entries: Vec<T>,
    pub total: u32,
}

#[derive(Clone, Copy, PartialEq, Eq)]
pub(in crate::provider) enum RecordMarking {
    Inline,
    AfterCreate,
}

pub(in crate::provider) trait IndividualApi: Send + Sync {
    const MARKING: RecordMarking;
    fn marker(&self, publication_id: &str) -> String {
        publication(publication_id)
    }
    fn validate_marker(&self, _marker: &str) -> Result<(), ProviderError> {
        Ok(())
    }
    fn owns_marker(&self, marker: &str, publication_id: &str) -> bool {
        matches_publication(marker, publication_id)
    }
    fn is_publication_marker(&self, marker: &str) -> bool {
        is_publication_marker(marker)
    }
    fn set_remark(&self, _id: &str, _marker: &str) -> Result<HttpRequest, ProviderError> {
        Err(configuration_error(
            "provider does not support a separate remark request",
        ))
    }
    fn remarked(&self, _response: HttpResponse) -> Result<(), ProviderError> {
        Err(invalid(true))
    }
    fn discover(&self, page: u32) -> Result<HttpRequest, ProviderError>;
    fn zones(&self, response: HttpResponse, page: u32) -> Result<Page<Zone>, ProviderError>;
    fn verify_zone(&self, _zone: &Zone) -> Result<Option<HttpRequest>, ProviderError> {
        Ok(None)
    }
    fn checked_zone(&self, _response: HttpResponse, _zone: &Zone) -> Result<u32, ProviderError> {
        Err(invalid(false))
    }
    fn list(&self, zone: &Zone, relative: &str, page: u32) -> Result<HttpRequest, ProviderError>;
    fn records(
        &self,
        response: HttpResponse,
        zone: &Zone,
        page: u32,
    ) -> Result<Page<Record>, ProviderError>;
    fn inspect(&self, zone: &Zone, id: &str) -> Result<HttpRequest, ProviderError>;
    fn inspected(
        &self,
        response: HttpResponse,
        zone: &Zone,
    ) -> Result<Option<Record>, ProviderError>;
    fn create(
        &self,
        zone: &Zone,
        relative: &str,
        record: &DnsRecord,
        marker: &str,
        minimum_ttl: u32,
    ) -> Result<HttpRequest, ProviderError>;
    fn created(&self, response: HttpResponse) -> Result<String, ProviderError>;
    fn delete(&self, zone: &Zone, id: &str) -> Result<HttpRequest, ProviderError>;
    fn deleted(&self, response: HttpResponse, id: &str) -> Result<CleanupStatus, ProviderError>;
}

pub(in crate::provider) fn valid_id(id: &str) -> bool {
    id.len() <= 24
        && id.bytes().all(|b| b.is_ascii_digit())
        && id.as_bytes().first().is_some_and(|b| *b != b'0')
}
