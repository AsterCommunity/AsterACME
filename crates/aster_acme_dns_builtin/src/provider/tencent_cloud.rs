//! Tencent Cloud `DNSPod` API 2021-03-23 using TC3-HMAC-SHA256.
use crate::provider::{
    individual::{IndividualApi, IndividualFactory, PAGE_SIZE, Page, Record, Zone},
    rpc::{api_error, decode, hex, hmac256, invalid, key_field, settings, sha256, validate_keys},
};
use aster_acme_dns::operation::HttpMethod;
use aster_acme_dns::{
    CleanupStatus, DnsRecord, ProviderError, ProviderErrorCode,
    backend::{
        BackendConfig, BackendDescriptor, BackendImplementation, BackendRegistration, DnsBackend,
        MutationModel, configuration_error,
    },
    operation::{HttpRequest, HttpResponse},
};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::sync::Arc;
use time::OffsetDateTime;
use zeroize::{ZeroizeOnDrop, Zeroizing};

pub const BACKEND_ID: &str = "com.astercosm.acme.dns.tencent-cloud";
const HOST: &str = "dnspod.tencentcloudapi.com";
const SERVICE: &str = "dnspod";
const VERSION: &str = "2021-03-23";
const DEFAULT_LINE: &str = "0";

#[derive(Clone, Copy)]
enum DnsPodAction {
    DescribeDomainList,
    DescribeRecordList,
    DescribeRecord,
    CreateTxtRecord,
    DeleteRecord,
}

#[derive(Serialize)]
#[serde(rename_all = "PascalCase")]
struct DescribeDomainListRequest {
    offset: u32,
    limit: u32,
}

#[derive(Serialize)]
#[serde(rename_all = "PascalCase")]
struct DescribeRecordListRequest<'a> {
    domain: &'a str,
    domain_id: u64,
    sub_domain: &'a str,
    record_type: &'static str,
    offset: u32,
    limit: u32,
    error_on_empty: &'static str,
}

#[derive(Serialize)]
#[serde(rename_all = "PascalCase")]
struct DescribeRecordRequest<'a> {
    domain: &'a str,
    domain_id: u64,
    record_id: u64,
}

#[derive(Serialize)]
#[serde(rename_all = "PascalCase")]
struct DeleteRecordRequest<'a> {
    domain: &'a str,
    domain_id: u64,
    record_id: u64,
}

impl DnsPodAction {
    fn wire(self) -> &'static str {
        match self {
            Self::DescribeDomainList => "DescribeDomainList",
            Self::DescribeRecordList => "DescribeRecordList",
            Self::DescribeRecord => "DescribeRecord",
            Self::CreateTxtRecord => "CreateTXTRecord",
            Self::DeleteRecord => "DeleteRecord",
        }
    }
}

#[derive(Serialize)]
#[serde(rename_all = "PascalCase")]
struct CreateTxtRecordRequest<'a> {
    domain: &'a str,
    domain_id: u64,
    sub_domain: &'a str,
    record_line: &'static str,
    record_line_id: &'static str,
    value: &'a str,
    #[serde(rename = "TTL")]
    ttl: u32,
    status: &'static str,
    remark: &'a str,
}

const FIELDS: &[aster_acme_dns::backend::ConfigField] = &[
    key_field("secret_id", "Tencent Cloud SecretID"),
    key_field("secret_key", "Tencent Cloud SecretKey"),
];

#[linkme::distributed_slice(aster_acme_dns::backend::BACKENDS)]
static REGISTRATION: BackendRegistration = BackendRegistration {
    create: || Arc::new(TencentCloudBackend),
};

pub struct TencentCloudBackend;

#[derive(Deserialize, ZeroizeOnDrop)]
#[serde(deny_unknown_fields)]
struct Keys {
    secret_id: String,
    secret_key: String,
}

fn keys(config: &BackendConfig) -> Result<Keys, ProviderError> {
    let keys: Keys = settings(config)?;
    validate_keys(&keys.secret_id, &keys.secret_key)?;
    Ok(keys)
}

impl DnsBackend for TencentCloudBackend {
    fn descriptor(&self) -> BackendDescriptor {
        BackendDescriptor {
            id: BACKEND_ID,
            label: "Tencent Cloud DNSPod",
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
        Ok("dnspod-public".into())
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
        action: DnsPodAction,
        body: &impl Serialize,
        mutation: bool,
    ) -> Result<HttpRequest, ProviderError> {
        let body = serde_json::to_vec(body)
            .map_err(|_| configuration_error("cannot encode DNSPod request"))?;
        let timestamp = OffsetDateTime::now_utc().unix_timestamp();
        let authorization = self.authorization(HOST, SERVICE, action.wire(), timestamp, &body)?;
        Ok(HttpRequest {
            method: HttpMethod::Post,
            url: format!("https://{HOST}/"),
            body,
            mutation,
            headers: vec![
                ("host".into(), HOST.into()),
                (
                    "content-type".into(),
                    "application/json; charset=utf-8".into(),
                ),
                ("x-tc-action".into(), action.wire().into()),
                ("x-tc-timestamp".into(), timestamp.to_string()),
                ("x-tc-version".into(), VERSION.into()),
                ("authorization".into(), authorization),
            ],
        })
    }

    fn authorization(
        &self,
        host: &str,
        service: &str,
        action: &str,
        timestamp: i64,
        body: &[u8],
    ) -> Result<String, ProviderError> {
        const SIGNED: &str = "content-type;host;x-tc-action";
        let date = OffsetDateTime::from_unix_timestamp(timestamp)
            .map_err(|_| configuration_error("invalid TC3 request time"))?
            .date();
        let action = action.to_ascii_lowercase();
        let canonical = format!(
            "POST\n/\n\ncontent-type:application/json; charset=utf-8\nhost:{host}\nx-tc-action:{action}\n\n{SIGNED}\n{}",
            sha256(body)
        );
        let scope = format!("{date}/{service}/tc3_request");
        let to_sign = format!(
            "TC3-HMAC-SHA256\n{timestamp}\n{scope}\n{}",
            sha256(canonical.as_bytes())
        );
        let key = Zeroizing::new(format!("TC3{}", self.secret_key));
        let date_key = hmac256(key.as_bytes(), date.to_string().as_bytes());
        let service_key = hmac256(date_key.as_ref(), service.as_bytes());
        let signing_key = hmac256(service_key.as_ref(), b"tc3_request");
        let signature = hex(hmac256(signing_key.as_ref(), to_sign.as_bytes()).as_ref());
        Ok(format!(
            "TC3-HMAC-SHA256 Credential={}/{scope}, SignedHeaders={SIGNED}, Signature={signature}",
            self.secret_id
        ))
    }
}

#[derive(Deserialize)]
#[serde(rename_all = "PascalCase")]
struct ListedZone {
    domain_id: u64,
    name: String,
    #[serde(default)]
    punycode: String,
}

#[derive(Deserialize)]
struct ListedRecord {
    #[serde(rename = "RecordId")]
    id: u64,
    #[serde(rename = "Name")]
    name: String,
    #[serde(rename = "Type")]
    kind: String,
    #[serde(rename = "Value")]
    value: String,
    #[serde(rename = "Remark")]
    remark: Option<String>,
    #[serde(rename = "TTL")]
    ttl: u32,
    #[serde(rename = "Status")]
    status: String,
    #[serde(rename = "LineId")]
    line_id: String,
}

#[derive(Deserialize)]
struct InspectedRecord {
    #[serde(rename = "DomainId")]
    domain_id: u64,
    #[serde(rename = "Id")]
    id: u64,
    #[serde(rename = "SubDomain")]
    name: String,
    #[serde(rename = "RecordType")]
    kind: String,
    #[serde(rename = "Value")]
    value: String,
    #[serde(rename = "Remark")]
    remark: Option<String>,
    #[serde(rename = "TTL")]
    ttl: u32,
    #[serde(rename = "Enabled")]
    enabled: u32,
    #[serde(rename = "RecordLineId")]
    line_id: String,
}

impl IndividualApi for Keys {
    const MARKED: bool = true;

    fn discover(&self, page: u32) -> Result<HttpRequest, ProviderError> {
        self.request(
            DnsPodAction::DescribeDomainList,
            &DescribeDomainListRequest {
                offset: (page - 1) * PAGE_SIZE,
                limit: PAGE_SIZE,
            },
            false,
        )
    }

    fn zones(&self, response: HttpResponse, _: u32) -> Result<Page<Zone>, ProviderError> {
        #[derive(Deserialize)]
        struct Count {
            #[serde(rename = "DomainTotal")]
            total: u32,
        }
        #[derive(Deserialize)]
        struct Listing {
            #[serde(rename = "DomainCountInfo")]
            count: Count,
            #[serde(rename = "DomainList")]
            domains: Vec<ListedZone>,
        }
        let body: Listing = decode(payload(&response, false)?, false)?;
        Ok(Page {
            total: body.count.total,
            entries: body
                .domains
                .into_iter()
                .map(|domain| {
                    if domain.domain_id == 0 {
                        return Err(invalid(false));
                    }
                    let name = if domain.punycode.is_empty() {
                        &domain.name
                    } else {
                        &domain.punycode
                    };
                    Zone::new(domain.domain_id.to_string(), name)
                })
                .collect::<Result<_, _>>()?,
        })
    }

    fn list(&self, zone: &Zone, relative: &str, page: u32) -> Result<HttpRequest, ProviderError> {
        self.request(
            DnsPodAction::DescribeRecordList,
            &DescribeRecordListRequest {
                domain: zone.name.strip_suffix('.').unwrap_or(&zone.name),
                domain_id: number(&zone.id)?,
                sub_domain: relative,
                record_type: "TXT",
                offset: (page - 1) * PAGE_SIZE,
                limit: PAGE_SIZE,
                error_on_empty: "no",
            },
            false,
        )
    }

    fn records(
        &self,
        response: HttpResponse,
        _: &Zone,
        _: u32,
    ) -> Result<Page<Record>, ProviderError> {
        #[derive(Deserialize)]
        struct Count {
            #[serde(rename = "TotalCount")]
            total: u32,
            #[serde(rename = "ListCount")]
            returned: usize,
        }
        #[derive(Deserialize)]
        struct Listing {
            #[serde(rename = "RecordCountInfo")]
            count: Count,
            #[serde(rename = "RecordList")]
            records: Vec<ListedRecord>,
        }
        let body: Listing = decode(payload(&response, false)?, false)?;
        if body.count.returned != body.records.len() {
            return Err(invalid(false));
        }
        Ok(Page {
            total: body.count.total,
            entries: body
                .records
                .into_iter()
                .map(|record| Record {
                    id: record.id.to_string(),
                    relative_name: record.name,
                    kind: record.kind,
                    marker: record.remark,
                    ttl: record.ttl,
                    value: record.value,
                    enabled: record.status == "ENABLE",
                    default_line: record.line_id == DEFAULT_LINE,
                })
                .collect(),
        })
    }

    fn inspect(&self, zone: &Zone, id: &str) -> Result<HttpRequest, ProviderError> {
        self.request(
            DnsPodAction::DescribeRecord,
            &DescribeRecordRequest {
                domain: zone.name.strip_suffix('.').unwrap_or(&zone.name),
                domain_id: number(&zone.id)?,
                record_id: number(id)?,
            },
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
        let mut body = payload(&response, false)?;
        let record: InspectedRecord = decode(body["RecordInfo"].take(), false)?;
        if record.domain_id != number(&zone.id)? {
            return Err(invalid(false));
        }
        Ok(Some(Record {
            id: record.id.to_string(),
            relative_name: record.name,
            kind: record.kind,
            marker: record.remark,
            ttl: record.ttl,
            value: record.value,
            enabled: record.enabled == 1,
            default_line: record.line_id == DEFAULT_LINE,
        }))
    }

    fn create(
        &self,
        zone: &Zone,
        relative: &str,
        record: &DnsRecord,
        marker: &str,
        _: u32,
    ) -> Result<HttpRequest, ProviderError> {
        self.request(
            DnsPodAction::CreateTxtRecord,
            &CreateTxtRecordRequest {
                domain: zone.name.strip_suffix('.').unwrap_or(&zone.name),
                domain_id: number(&zone.id)?,
                sub_domain: relative,
                record_line: "默认",
                record_line_id: DEFAULT_LINE,
                value: &record.value,
                ttl: record.ttl_seconds.unwrap_or(600).clamp(600, 604_800),
                status: "ENABLE",
                remark: marker,
            },
            true,
        )
    }

    fn created(&self, response: HttpResponse) -> Result<String, ProviderError> {
        let body = payload(&response, true)?;
        body["RecordId"]
            .as_u64()
            .filter(|id| *id > 0)
            .map(|id| id.to_string())
            .ok_or_else(|| invalid(true))
    }

    fn delete(&self, zone: &Zone, id: &str) -> Result<HttpRequest, ProviderError> {
        self.request(
            DnsPodAction::DeleteRecord,
            &DeleteRecordRequest {
                domain: zone.name.strip_suffix('.').unwrap_or(&zone.name),
                domain_id: number(&zone.id)?,
                record_id: number(id)?,
            },
            true,
        )
    }

    fn deleted(&self, response: HttpResponse, _: &str) -> Result<CleanupStatus, ProviderError> {
        if missing(&response) {
            return Ok(CleanupStatus::AlreadyAbsent);
        }
        payload(&response, true)?;
        Ok(CleanupStatus::Removed)
    }
}

fn number(id: &str) -> Result<u64, ProviderError> {
    id.parse::<u64>()
        .ok()
        .filter(|n| *n > 0 && n.to_string() == id)
        .ok_or_else(|| invalid(false))
}

fn missing(response: &HttpResponse) -> bool {
    matches!(response.status, 200 | 400 | 404)
        && serde_json::from_slice::<Value>(&response.body).is_ok_and(|body| {
            body["Response"]["Error"]["Code"].as_str() == Some("ResourceNotFound.NoDataOfRecord")
        })
}

fn payload(response: &HttpResponse, mutation: bool) -> Result<Value, ProviderError> {
    let body: Value = serde_json::from_slice(&response.body).unwrap_or(Value::Null);
    let body = body.get("Response").cloned().unwrap_or(Value::Null);
    if response.status == 200
        && body.get("Error").is_none()
        && body["RequestId"].as_str().is_some_and(|id| !id.is_empty())
    {
        return Ok(body);
    }
    Err(api_error(
        response,
        mutation,
        classify(body["Error"]["Code"].as_str()),
    ))
}

fn classify(code: Option<&str>) -> Option<(ProviderErrorCode, &'static str)> {
    use ProviderErrorCode::{
        AuthenticationFailed, AuthorizationDenied, InvalidRequest, RateLimited, RecordConflict,
        ZoneNotFound,
    };
    let code = code?;
    Some(match code {
        "RequestLimitExceeded"
        | "RequestLimitExceeded.GlobalRegionUinLimitExceeded"
        | "RequestLimitExceeded.IPLimitExceeded"
        | "RequestLimitExceeded.UinLimitExceeded" => (RateLimited, "RequestLimitExceeded"),
        "AuthFailure.SignatureFailure"
        | "AuthFailure.SecretIdNotFound"
        | "AuthFailure.SignatureExpire" => (AuthenticationFailed, "AuthFailure"),
        "UnauthorizedOperation" | "AuthFailure.UnauthorizedOperation" => {
            (AuthorizationDenied, "UnauthorizedOperation")
        }
        "ResourceNotFound.NoDataOfDomain" => (ZoneNotFound, "ResourceNotFound.NoDataOfDomain"),
        "InvalidParameter.RecordExist" | "InvalidParameterValue.RecordExist" => {
            (RecordConflict, "RecordExist")
        }
        "InvalidParameter" | "InvalidParameterValue" | "InvalidParameterValue.TTLTooSmall" => {
            (InvalidRequest, "InvalidParameter")
        }
        _ => return None,
    })
}

#[cfg(test)]
mod tests;
