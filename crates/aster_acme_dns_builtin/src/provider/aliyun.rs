//! Alibaba Cloud DNS RPC, API version 2015-01-09, signed with ACS3.
use crate::provider::{
    individual::{
        IndividualApi, IndividualFactory, PAGE_SIZE, Page, Record, RecordMarking, Zone, valid_id,
    },
    marker::publication,
    rpc::{
        api_error, decode, hex, hmac256, invalid, key_field, query, settings, sha256, validate_keys,
    },
};
use aster_acme_dns::operation::HttpMethod;
use aster_acme_dns::{
    CleanupStatus, DnsRecord, ProviderError, ProviderErrorCode,
    backend::{
        BackendConfig, BackendDescriptor, BackendImplementation, BackendRegistration, DnsBackend,
        MutationModel, configuration_error,
    },
    operation::{HttpRequest, HttpResponse},
    routing::absolute_name,
};
use serde::Deserialize;
use serde_json::Value;
use std::sync::Arc;
use time::OffsetDateTime;
use zeroize::ZeroizeOnDrop;

pub const BACKEND_ID: &str = "com.astercosm.acme.dns.aliyun";
const HOST: &str = "alidns.aliyuncs.com";
const VERSION: &str = "2015-01-09";
const MAX_TTL: u32 = 86400;

#[derive(Clone, Copy)]
enum AliyunAction {
    DescribeDomains,
    DescribeDomainInfo,
    DescribeDomainRecords,
    DescribeDomainRecordInfo,
    AddDomainRecord,
    UpdateDomainRecordRemark,
    DeleteDomainRecord,
}

impl AliyunAction {
    const fn wire(self) -> &'static str {
        match self {
            Self::DescribeDomains => "DescribeDomains",
            Self::DescribeDomainInfo => "DescribeDomainInfo",
            Self::DescribeDomainRecords => "DescribeDomainRecords",
            Self::DescribeDomainRecordInfo => "DescribeDomainRecordInfo",
            Self::AddDomainRecord => "AddDomainRecord",
            Self::UpdateDomainRecordRemark => "UpdateDomainRecordRemark",
            Self::DeleteDomainRecord => "DeleteDomainRecord",
        }
    }
}

const FIELDS: &[aster_acme_dns::backend::ConfigField] = &[
    key_field("access_key_id", "Alibaba Cloud AccessKey ID"),
    key_field("access_key_secret", "Alibaba Cloud AccessKey secret"),
];

#[linkme::distributed_slice(aster_acme_dns::backend::BACKENDS)]
static REGISTRATION: BackendRegistration = BackendRegistration {
    create: || Arc::new(AliyunBackend),
};

pub struct AliyunBackend;

#[derive(Deserialize, ZeroizeOnDrop)]
#[serde(deny_unknown_fields)]
struct Keys {
    access_key_id: String,
    access_key_secret: String,
}

fn keys(config: &BackendConfig) -> Result<Keys, ProviderError> {
    let keys: Keys = settings(config)?;
    validate_keys(&keys.access_key_id, &keys.access_key_secret)?;
    Ok(keys)
}

impl DnsBackend for AliyunBackend {
    fn descriptor(&self) -> BackendDescriptor {
        BackendDescriptor {
            id: BACKEND_ID,
            label: "Alibaba Cloud DNS",
            config_version: 1,
            executable: false,
            mutation_model: MutationModel::IndividualRecords,
            fields: FIELDS,
        }
    }

    fn validate(&self, config: &BackendConfig) -> Result<(), ProviderError> {
        keys(config).map(|_| ())
    }

    fn binding(&self, config: &BackendConfig) -> Result<String, ProviderError> {
        keys(config)?;
        Ok("alidns-public".into())
    }

    fn create(&self, config: &BackendConfig) -> Result<BackendImplementation, ProviderError> {
        Ok(BackendImplementation::Native(Arc::new(IndividualFactory(
            Arc::new(keys(config)?),
        ))))
    }
}

impl Keys {
    fn request(
        &self,
        action: AliyunAction,
        parameters: &[(&str, &str)],
        mutation: bool,
    ) -> Result<HttpRequest, ProviderError> {
        let now = OffsetDateTime::now_utc()
            .replace_nanosecond(0)
            .map_err(|_| configuration_error("invalid ACS3 request time"))?;
        let date = now
            .format(&time::format_description::well_known::Rfc3339)
            .map_err(|_| configuration_error("cannot format ACS3 request time"))?;
        let mut nonce = [0; 16];
        aws_lc_rs::rand::fill(&mut nonce)
            .map_err(|_| configuration_error("cannot generate ACS3 request nonce"))?;
        Ok(self.signed(action, parameters, &date, &hex(&nonce), mutation))
    }

    fn signed(
        &self,
        action: AliyunAction,
        parameters: &[(&str, &str)],
        date: &str,
        nonce: &str,
        mutation: bool,
    ) -> HttpRequest {
        let query = query(parameters);
        let payload = sha256(b"");
        let signed =
            "host;x-acs-action;x-acs-content-sha256;x-acs-date;x-acs-signature-nonce;x-acs-version";
        let canonical = format!(
            "GET\n/\n{query}\nhost:{HOST}\nx-acs-action:{}\nx-acs-content-sha256:{payload}\nx-acs-date:{date}\nx-acs-signature-nonce:{nonce}\nx-acs-version:{VERSION}\n\n{signed}\n{payload}",
            action.wire()
        );
        let to_sign = format!("ACS3-HMAC-SHA256\n{}", sha256(canonical.as_bytes()));
        let signature =
            hex(hmac256(self.access_key_secret.as_bytes(), to_sign.as_bytes()).as_ref());
        HttpRequest {
            method: HttpMethod::Get,
            url: format!("https://{HOST}/?{query}"),
            headers: vec![
                ("host".into(), HOST.into()),
                ("accept".into(), "application/json".into()),
                ("cache-control".into(), "no-store".into()),
                ("x-acs-action".into(), action.wire().into()),
                ("x-acs-content-sha256".into(), payload),
                ("x-acs-date".into(), date.into()),
                ("x-acs-signature-nonce".into(), nonce.into()),
                ("x-acs-version".into(), VERSION.into()),
                (
                    "authorization".into(),
                    format!(
                        "ACS3-HMAC-SHA256 Credential={},SignedHeaders={signed},Signature={signature}",
                        self.access_key_id
                    ),
                ),
            ],
            body: Vec::new(),
            mutation,
        }
    }
}

#[derive(Deserialize)]
#[serde(rename_all = "PascalCase")]
struct ListedZone {
    domain_id: String,
    domain_name: String,
    #[serde(default)]
    puny_code: String,
}

impl ListedZone {
    fn zone(self) -> Result<Zone, ProviderError> {
        let name = if self.puny_code.is_empty() {
            &self.domain_name
        } else {
            &self.puny_code
        };
        Zone::new(self.domain_id, name)
    }
}

#[derive(Deserialize)]
#[serde(rename_all = "PascalCase")]
struct DomainInfo {
    #[serde(flatten)]
    zone: ListedZone,
    min_ttl: u32,
}

#[derive(Deserialize)]
enum RecordStatus {
    #[serde(alias = "ENABLE")]
    Enable,
    #[serde(alias = "DISABLE")]
    Disable,
    #[serde(other)]
    Unknown,
}

#[derive(Deserialize)]
#[serde(rename_all = "PascalCase")]
struct AliRecord {
    record_id: String,
    domain_name: String,
    #[serde(default)]
    puny_code: String,
    #[serde(rename = "RR")]
    rr: String,
    #[serde(rename = "Type")]
    kind: String,
    value: String,
    #[serde(rename = "TTL")]
    ttl: u32,
    status: RecordStatus,
    line: String,
    #[serde(rename = "Remark")]
    remark: Option<String>,
}

#[derive(Deserialize)]
#[serde(rename_all = "PascalCase")]
struct RecordInfo {
    #[serde(flatten)]
    record: AliRecord,
    // The live API can omit DomainId even though the documentation lists it.
    domain_id: Option<String>,
}

impl AliRecord {
    fn into_record(self, zone: &Zone) -> Result<Record, ProviderError> {
        let name = if self.puny_code.is_empty() {
            &self.domain_name
        } else {
            &self.puny_code
        };
        let name = absolute_name(name).map_err(|_| invalid(false))?;
        if zone.name != name {
            return Err(invalid(false));
        }
        Ok(Record {
            id: self.record_id,
            relative_name: self.rr,
            kind: self.kind,
            value: self.value,
            ttl: self.ttl,
            marker: self.remark,
            enabled: matches!(self.status, RecordStatus::Enable),
            default_line: self.line == "default",
        })
    }
}

#[derive(Deserialize)]
#[serde(rename_all = "PascalCase")]
struct Pagination {
    total_count: u32,
    page_number: u32,
    page_size: u32,
}

impl Pagination {
    fn total(&self, page: u32) -> Result<u32, ProviderError> {
        if self.page_number != page || self.page_size != PAGE_SIZE {
            return Err(invalid(false));
        }
        Ok(self.total_count)
    }
}

impl IndividualApi for Keys {
    const MARKING: RecordMarking = RecordMarking::AfterCreate;

    fn marker(&self, publication_id: &str) -> String {
        // A compact, deterministic marker also fits short vendor remark fields.
        publication(publication_id)
    }

    fn set_remark(&self, id: &str, marker: &str) -> Result<HttpRequest, ProviderError> {
        self.request(
            AliyunAction::UpdateDomainRecordRemark,
            &[("RecordId", id), ("Remark", marker)],
            true,
        )
    }

    fn remarked(&self, response: HttpResponse) -> Result<(), ProviderError> {
        #[derive(Deserialize)]
        #[serde(rename_all = "PascalCase")]
        struct UpdatedRemark {
            request_id: String,
        }
        let result: UpdatedRemark = decode(payload(&response, true)?, true)?;
        if result.request_id.is_empty() {
            return Err(invalid(true));
        }
        Ok(())
    }

    fn discover(&self, page: u32) -> Result<HttpRequest, ProviderError> {
        self.request(
            AliyunAction::DescribeDomains,
            &[
                ("PageNumber", &page.to_string()),
                ("PageSize", &PAGE_SIZE.to_string()),
            ],
            false,
        )
    }

    fn zones(&self, response: HttpResponse, page: u32) -> Result<Page<Zone>, ProviderError> {
        #[derive(Deserialize)]
        struct Zones {
            #[serde(rename = "Domain")]
            entries: Vec<ListedZone>,
        }
        #[derive(Deserialize)]
        struct Listing {
            #[serde(flatten)]
            pagination: Pagination,
            #[serde(rename = "Domains")]
            domains: Zones,
        }
        let body: Listing = decode(payload(&response, false)?, false)?;
        Ok(Page {
            total: body.pagination.total(page)?,
            entries: body
                .domains
                .entries
                .into_iter()
                .map(ListedZone::zone)
                .collect::<Result<_, _>>()?,
        })
    }

    fn verify_zone(&self, zone: &Zone) -> Result<Option<HttpRequest>, ProviderError> {
        self.request(
            AliyunAction::DescribeDomainInfo,
            &[
                ("DomainName", zone.name.trim_end_matches('.')),
                ("NeedDetailAttributes", "true"),
            ],
            false,
        )
        .map(Some)
    }

    fn checked_zone(&self, response: HttpResponse, zone: &Zone) -> Result<u32, ProviderError> {
        let observed: DomainInfo = decode(payload(&response, false)?, false)?;
        if observed.zone.zone()? != *zone || !(1..=MAX_TTL).contains(&observed.min_ttl) {
            return Err(invalid(false));
        }
        Ok(observed.min_ttl)
    }

    fn list(&self, zone: &Zone, relative: &str, page: u32) -> Result<HttpRequest, ProviderError> {
        self.request(
            AliyunAction::DescribeDomainRecords,
            &[
                ("DomainName", zone.name.trim_end_matches('.')),
                ("RRKeyWord", relative),
                ("Type", "TXT"),
                ("SearchMode", "COMBINATION"),
                ("PageNumber", &page.to_string()),
                ("PageSize", &PAGE_SIZE.to_string()),
            ],
            false,
        )
    }

    fn records(
        &self,
        response: HttpResponse,
        zone: &Zone,
        page: u32,
    ) -> Result<Page<Record>, ProviderError> {
        #[derive(Deserialize)]
        struct Records {
            #[serde(rename = "Record")]
            entries: Vec<AliRecord>,
        }
        #[derive(Deserialize)]
        struct Listing {
            #[serde(flatten)]
            pagination: Pagination,
            #[serde(rename = "DomainRecords")]
            records: Records,
        }
        let body: Listing = decode(payload(&response, false)?, false)?;
        Ok(Page {
            total: body.pagination.total(page)?,
            entries: body
                .records
                .entries
                .into_iter()
                .map(|record| record.into_record(zone))
                .collect::<Result<_, _>>()?,
        })
    }

    fn inspect(&self, _: &Zone, id: &str) -> Result<HttpRequest, ProviderError> {
        self.request(
            AliyunAction::DescribeDomainRecordInfo,
            &[("RecordId", id)],
            false,
        )
    }

    fn inspected(
        &self,
        response: HttpResponse,
        zone: &Zone,
    ) -> Result<Option<Record>, ProviderError> {
        if missing(&response) {
            return Ok(None);
        }
        let body: RecordInfo = decode(payload(&response, false)?, false)?;
        if body.domain_id.as_ref().is_some_and(|id| id != &zone.id) {
            return Err(invalid(false));
        }
        body.record.into_record(zone).map(Some)
    }

    fn create(
        &self,
        zone: &Zone,
        relative: &str,
        record: &DnsRecord,
        _: &str,
        minimum_ttl: u32,
    ) -> Result<HttpRequest, ProviderError> {
        let ttl = record
            .ttl_seconds
            .unwrap_or(600)
            .clamp(minimum_ttl, MAX_TTL);
        self.request(
            AliyunAction::AddDomainRecord,
            &[
                ("DomainName", zone.name.trim_end_matches('.')),
                ("RR", relative),
                ("Type", "TXT"),
                ("Value", &record.value),
                ("Line", "default"),
                ("TTL", &ttl.to_string()),
            ],
            true,
        )
    }

    fn created(&self, response: HttpResponse) -> Result<String, ProviderError> {
        record_id(&response)
    }

    fn delete(&self, _: &Zone, id: &str) -> Result<HttpRequest, ProviderError> {
        self.request(AliyunAction::DeleteDomainRecord, &[("RecordId", id)], true)
    }

    fn deleted(&self, response: HttpResponse, id: &str) -> Result<CleanupStatus, ProviderError> {
        if missing(&response) {
            return Ok(CleanupStatus::AlreadyAbsent);
        }
        if record_id(&response)? != id {
            return Err(invalid(true));
        }
        Ok(CleanupStatus::Removed)
    }
}

fn record_id(response: &HttpResponse) -> Result<String, ProviderError> {
    let body = payload(response, true)?;
    body["RecordId"]
        .as_str()
        .filter(|id| valid_id(id))
        .map(str::to_owned)
        .ok_or_else(|| invalid(true))
}

fn missing(response: &HttpResponse) -> bool {
    matches!(response.status, 400 | 404)
        && serde_json::from_slice::<Value>(&response.body).is_ok_and(|body| {
            matches!(
                body["Code"].as_str(),
                Some("InvalidRecordId.NotFound" | "InvalidRR.NoExist")
            )
        })
}

fn payload(response: &HttpResponse, mutation: bool) -> Result<Value, ProviderError> {
    let body = serde_json::from_slice::<Value>(&response.body);
    let code = body.as_ref().ok().and_then(|body| body["Code"].as_str());
    if response.status == 200 && code.is_none() {
        return body.map_err(|_| invalid(mutation));
    }
    Err(api_error(response, mutation, classify(code)))
}

fn classify(code: Option<&str>) -> Option<(ProviderErrorCode, &'static str)> {
    use ProviderErrorCode::{
        AuthenticationFailed, AuthorizationDenied, InvalidRequest, RateLimited, RecordConflict,
        ZoneNotFound,
    };
    Some(match code? {
        "Throttling" | "Throttling.User" | "Throttling.Api" | "Throttling.System" => {
            (RateLimited, "Throttling")
        }
        "InvalidAccessKeyId.NotFound"
        | "SignatureDoesNotMatch"
        | "InvalidSecurityToken.Expired" => (AuthenticationFailed, "AuthenticationFailed"),
        "Forbidden.RAM" | "Forbidden.AccessDenied" | "Forbidden.NoPermission" => {
            (AuthorizationDenied, "AccessDenied")
        }
        "InvalidDomainName.NoExist" => (ZoneNotFound, "InvalidDomainName.NoExist"),
        "DomainRecordDuplicate" | "DomainRecordConflict" => {
            (RecordConflict, "DomainRecordConflict")
        }
        "InvalidRR" | "InvalidValue" | "InvalidType" | "InvalidTTL" | "InvalidLine" => {
            (InvalidRequest, "InvalidRecordParameter")
        }
        _ => return None,
    })
}

#[cfg(test)]
mod tests;
