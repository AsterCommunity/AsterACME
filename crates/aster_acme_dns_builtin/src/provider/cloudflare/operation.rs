//! Cloudflare publication reconciliation and exact-object cleanup transitions.
use crate::provider::{
    HttpMethod,
    cloudflare::{API, Cloudflare, CloudflareConfig, valid_token, valid_zone},
};
use aster_acme_dns::{
    CleanupStatus, ProviderError, ProviderErrorCode, PublicationReceipt, RecordOwnership,
    SideEffect,
    backend::configuration_error,
    operation::{
        HttpRequest, HttpResponse, OperationFactory, ProviderAction, ProviderEffect, ProviderEvent,
        ProviderOperation, ProviderOutcome, RecoveryState,
    },
};
use serde::Deserialize;
use serde_json::{Value, json};

impl OperationFactory for Cloudflare {
    fn start(
        &self,
        action: ProviderAction,
        saved: Option<RecoveryState>,
    ) -> Result<Box<dyn ProviderOperation>, ProviderError> {
        let mut config = self.config.clone();
        let mut phase = None;
        if let Some(state) = &saved {
            if state.version != 1 {
                return Err(configuration_error("unsupported Cloudflare recovery state"));
            }
            let object = state
                .data
                .as_object()
                .ok_or_else(|| configuration_error("invalid Cloudflare recovery state"))?;
            if let Some(zone) = object.get("zone_id") {
                let zone = zone
                    .as_str()
                    .filter(|zone| valid_zone(zone))
                    .ok_or_else(|| configuration_error("invalid saved Cloudflare zone"))?;
                if !config.zone_id.is_empty() && !config.zone_id.eq_ignore_ascii_case(zone) {
                    return Err(configuration_error("saved Cloudflare zone changed"));
                }
                config.zone_id = zone.to_ascii_lowercase();
            }
            for name in [
                "zone_resolved",
                "create_intent",
                "delete_intent",
                "create_rejected",
            ] {
                if object.get(name) == Some(&Value::Bool(true)) && phase.replace(name).is_some() {
                    return Err(configuration_error("invalid Cloudflare recovery state"));
                }
            }
            if phase.is_none()
                || object.len() != 1 + usize::from(object.contains_key("zone_id"))
                || (self.config.zone_id.is_empty() && !object.contains_key("zone_id"))
            {
                return Err(configuration_error("unsupported Cloudflare recovery state"));
            }
        }
        if phase == Some("delete_intent") && matches!(action, ProviderAction::Present(_)) {
            return Err(configuration_error(
                "cannot present a publication whose cleanup has started",
            ));
        }
        let record = match &action {
            ProviderAction::Present(record) => record,
            ProviderAction::Cleanup(request) => &request.record,
        };
        if record.publication_id.is_empty()
            || record.publication_id.len() > 90
            || !record
                .publication_id
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'-' | b'_'))
            || record.value.is_empty()
            || record.value.len() > 255
        {
            return Err(configuration_error(
                "invalid Cloudflare publication identity or TXT value",
            ));
        }
        Ok(Box::new(Operation {
            config,
            action,
            stage: Stage::Start,
            page: 1,
            found: Vec::new(),
            token: self.config.api_token.clone(),
            creation_uncertain: phase == Some("create_intent"),
            automatic: self.config.zone_id.is_empty(),
            candidate: 0,
            rejection: None,
        }))
    }
}

#[derive(Clone, Copy)]
enum Stage {
    Start,
    Secret,
    Zone,
    Discover,
    SaveZone,
    List,
    Intent,
    Create,
    Inspect,
    DeleteIntent,
    SaveRejection,
    Delete,
    Done,
}

#[derive(Clone, Copy)]
enum CloudflareAction {
    GetZone,
    DiscoverZones,
    ListTxtRecords,
    GetTxtRecord,
    CreateTxtRecord,
    DeleteTxtRecord,
}

impl CloudflareAction {
    const fn method(self) -> HttpMethod {
        match self {
            Self::GetZone | Self::DiscoverZones | Self::ListTxtRecords | Self::GetTxtRecord => {
                HttpMethod::Get
            }
            Self::CreateTxtRecord => HttpMethod::Post,
            Self::DeleteTxtRecord => HttpMethod::Delete,
        }
    }
}

struct Operation {
    config: CloudflareConfig,
    action: ProviderAction,
    stage: Stage,
    page: u32,
    found: Vec<Record>,
    token: Option<String>,
    creation_uncertain: bool,
    rejection: Option<ProviderError>,
    automatic: bool,
    candidate: usize,
}

#[derive(Deserialize)]
struct Record {
    id: String,
    name: String,
    content: String,
    #[serde(rename = "type")]
    kind: String,
    comment: Option<String>,
}

#[derive(Deserialize)]
struct Envelope<T> {
    success: bool,
    result: Option<T>,
    result_info: Option<PageInfo>,
}
#[derive(Deserialize)]
struct PageInfo {
    page: u32,
    total_pages: u32,
}

impl Operation {
    fn inspect_response(
        &mut self,
        response: Result<HttpResponse, aster_acme_dns::operation::HttpFailure>,
    ) -> Result<ProviderEffect, ProviderError> {
        if response.as_ref().is_ok_and(missing_record) {
            return Ok(self.finish_cleanup(CleanupStatus::AlreadyAbsent));
        }
        let response: Envelope<Record> = decode_response(response, false)?;
        let record = response.result.ok_or_else(invalid_response)?;
        let ProviderAction::Cleanup(request) = &self.action else {
            return Err(invalid_response());
        };
        if record.id != request.receipt.record_id
            || !self.same_record(&record)
            || record.comment.as_deref() != Some(&self.tag())
        {
            return Err(error(
                ProviderErrorCode::RecordNotOwned,
                "Cloudflare TXT record changed or ownership cannot be proved",
                SideEffect::None,
            ));
        }
        self.stage = Stage::DeleteIntent;
        Ok(ProviderEffect::Checkpoint(RecoveryState {
            version: 1,
            data: self.checkpoint("delete_intent"),
        }))
    }

    fn list_response(
        &mut self,
        response: Result<HttpResponse, aster_acme_dns::operation::HttpFailure>,
    ) -> Result<ProviderEffect, ProviderError> {
        let page: Envelope<Vec<Record>> = decode_response(response, false)?;
        self.found.extend(page.result.ok_or_else(invalid_response)?);
        if self.found.len() > 10000 {
            return Err(invalid_response());
        }
        {
            let info = page.result_info.ok_or_else(invalid_response)?;
            if info.page != self.page || info.total_pages > 100 {
                return Err(invalid_response());
            }
            if self.page < info.total_pages {
                self.page += 1;
                return self.list();
            }
        }
        let tag = self.tag();
        let mut candidates = Vec::new();
        for record in std::mem::take(&mut self.found) {
            if record.comment.as_deref() == Some(&tag) && !self.same_record(&record) {
                return Err(error(
                    ProviderErrorCode::RecordConflict,
                    "Cloudflare publication tag refers to a different record",
                    SideEffect::None,
                ));
            }
            if self.same_record(&record) {
                candidates.push(record);
            }
        }
        if candidates.len() > 1 {
            return Err(error(
                ProviderErrorCode::RecordConflict,
                "multiple matching Cloudflare TXT records",
                SideEffect::None,
            ));
        }
        if let Some(record) = candidates.pop() {
            let ownership = if record.comment.as_deref() == Some(&tag) {
                RecordOwnership::Created
            } else if self.creation_uncertain {
                return Err(uncertain_creation());
            } else if record
                .comment
                .as_ref()
                .is_some_and(|comment| comment.starts_with("asteracme:"))
            {
                return Err(error(
                    ProviderErrorCode::RecordConflict,
                    "TXT value belongs to another active publication",
                    SideEffect::None,
                ));
            } else {
                RecordOwnership::Preexisting
            };
            return self.receipt(record, ownership);
        }
        if self.creation_uncertain {
            return Err(uncertain_creation());
        }
        self.stage = Stage::Intent;
        Ok(ProviderEffect::Checkpoint(RecoveryState {
            version: 1,
            data: self.checkpoint("create_intent"),
        }))
    }

    fn zone_response(
        &mut self,
        response: Result<HttpResponse, aster_acme_dns::operation::HttpFailure>,
    ) -> Result<ProviderEffect, ProviderError> {
        #[derive(Deserialize)]
        struct Zone {
            id: String,
            name: String,
        }
        let zone: Envelope<Zone> = decode_response(response, false)?;
        let zone = zone.result.ok_or_else(invalid_response)?;
        let target = self
            .record()
            .name
            .trim_end_matches('.')
            .to_ascii_lowercase();
        let suffix = zone.name.trim_end_matches('.').to_ascii_lowercase();
        if !zone.id.eq_ignore_ascii_case(&self.config.zone_id)
            || suffix.is_empty()
            || !(target == suffix || target.ends_with(&format!(".{suffix}")))
        {
            return Err(error(
                ProviderErrorCode::ZoneNotFound,
                "Cloudflare zone does not contain publication target",
                SideEffect::None,
            ));
        }
        match &self.action {
            ProviderAction::Present(_) => self.list(),
            ProviderAction::Cleanup(request) => {
                if !valid_record_id(&request.receipt.record_id) {
                    return Err(configuration_error("invalid Cloudflare cleanup record ID"));
                }
                let id = request.receipt.record_id.clone();
                self.stage = Stage::Inspect;
                self.request(
                    CloudflareAction::GetTxtRecord,
                    &format!("/dns_records/{id}"),
                    None,
                    false,
                )
            }
        }
    }

    fn checkpoint(&self, phase: &str) -> Value {
        let mut state = serde_json::Map::new();
        state.insert(phase.into(), Value::Bool(true));
        if self.automatic {
            state.insert("zone_id".into(), json!(self.config.zone_id));
        }
        Value::Object(state)
    }
    fn begin_zone(&mut self) -> Result<ProviderEffect, ProviderError> {
        if !self.config.zone_id.is_empty() {
            self.stage = Stage::Zone;
            return self.request(CloudflareAction::GetZone, "", None, false);
        }
        self.discover()
    }
    fn discover(&mut self) -> Result<ProviderEffect, ProviderError> {
        let name = self
            .record()
            .name
            .trim_end_matches('.')
            .to_ascii_lowercase();
        aster_acme_dns::routing::absolute_name(&name)
            .map_err(|_| configuration_error("invalid Cloudflare DNS name"))?;
        let labels: Vec<_> = name.split('.').collect();
        if self.candidate + 1 >= labels.len() || labels.len() > 127 {
            return Err(error(
                ProviderErrorCode::ZoneNotFound,
                "no Cloudflare zone contains publication target",
                SideEffect::None,
            ));
        }
        let candidate = labels[self.candidate..].join(".");
        self.stage = Stage::Discover;
        self.raw_request(
            CloudflareAction::DiscoverZones,
            &format!("{API}/zones?name={candidate}&status=active&per_page=50&page=1"),
            None,
            false,
        )
    }
    fn discovered(
        &mut self,
        response: Result<HttpResponse, aster_acme_dns::operation::HttpFailure>,
    ) -> Result<ProviderEffect, ProviderError> {
        #[derive(Deserialize)]
        struct Zone {
            id: String,
            name: String,
        }
        let page: Envelope<Vec<Zone>> = decode_response(response, false)?;
        let zones = page.result.ok_or_else(invalid_response)?;
        let info = page.result_info.ok_or_else(invalid_response)?;
        if info.page != 1 || info.total_pages > 1 {
            return Err(invalid_response());
        }
        if zones.is_empty() {
            self.candidate += 1;
            return self.discover();
        }
        let name = self
            .record()
            .name
            .trim_end_matches('.')
            .to_ascii_lowercase();
        let expected = name
            .split('.')
            .skip(self.candidate)
            .collect::<Vec<_>>()
            .join(".");
        if zones.len() != 1
            || !valid_zone(&zones[0].id)
            || !zones[0]
                .name
                .trim_end_matches('.')
                .eq_ignore_ascii_case(&expected)
        {
            return Err(error(
                ProviderErrorCode::RecordConflict,
                "Cloudflare zone discovery was ambiguous or inconsistent",
                SideEffect::None,
            ));
        }
        self.config.zone_id = zones[0].id.to_ascii_lowercase();
        self.stage = Stage::SaveZone;
        Ok(ProviderEffect::Checkpoint(RecoveryState {
            version: 1,
            data: self.checkpoint("zone_resolved"),
        }))
    }
    fn record(&self) -> &aster_acme_dns::DnsRecord {
        match &self.action {
            ProviderAction::Present(record) => record,
            ProviderAction::Cleanup(request) => &request.record,
        }
    }
    fn tag(&self) -> String {
        format!("asteracme:{}", self.record().publication_id)
    }
    fn request(
        &self,
        action: CloudflareAction,
        path: &str,
        body: Option<Value>,
        mutation: bool,
    ) -> Result<ProviderEffect, ProviderError> {
        self.raw_request(
            action,
            &format!("{API}/zones/{}{path}", self.config.zone_id),
            body,
            mutation,
        )
    }
    fn raw_request(
        &self,
        action: CloudflareAction,
        url: &str,
        body: Option<Value>,
        mutation: bool,
    ) -> Result<ProviderEffect, ProviderError> {
        let token = self.token.as_ref().ok_or_else(|| {
            error(
                ProviderErrorCode::CredentialsUnavailable,
                "Cloudflare token unavailable",
                SideEffect::None,
            )
        })?;
        let body = body
            .map(|body| serde_json::to_vec(&body))
            .transpose()
            .map_err(|_| configuration_error("cannot encode Cloudflare request"))?
            .unwrap_or_default();
        Ok(ProviderEffect::Http(HttpRequest {
            method: action.method().wire().into(),
            url: url.into(),
            headers: vec![
                ("Authorization".into(), format!("Bearer {token}")),
                ("Content-Type".into(), "application/json".into()),
            ],
            body,
            mutation,
        }))
    }
    fn list(&mut self) -> Result<ProviderEffect, ProviderError> {
        self.stage = Stage::List;
        // DNS owner validation rejects all query delimiters; the trailing dot is presentation-only.
        let name = self.record().name.trim_end_matches('.');
        aster_acme_dns::routing::absolute_name(name)
            .map_err(|_| configuration_error("invalid Cloudflare DNS name"))?;
        self.request(
            CloudflareAction::ListTxtRecords,
            &format!(
                "/dns_records?type=TXT&name={name}&per_page=100&page={}",
                self.page
            ),
            None,
            false,
        )
    }
    fn receipt(
        &mut self,
        record: Record,
        ownership: RecordOwnership,
    ) -> Result<ProviderEffect, ProviderError> {
        if !valid_record_id(&record.id) || !self.same_record(&record) {
            return Err(error(
                ProviderErrorCode::RecordConflict,
                "Cloudflare returned a mismatched TXT record",
                SideEffect::Unknown,
            ));
        }
        let plan = self.record();
        let receipt = PublicationReceipt {
            effective_ttl_seconds: None,
            record_id: record.id,
            ownership,
            record_name: plan.name.clone(),
            cname_chain: plan.cname_chain.clone(),
        };
        self.stage = Stage::Done;
        Ok(ProviderEffect::Complete(ProviderOutcome::Presented(
            receipt,
        )))
    }
    fn same_record(&self, record: &Record) -> bool {
        record.kind == "TXT"
            && record
                .name
                .trim_end_matches('.')
                .eq_ignore_ascii_case(self.record().name.trim_end_matches('.'))
            && record.content == self.record().value
    }
    fn finish_cleanup(&mut self, status: CleanupStatus) -> ProviderEffect {
        self.stage = Stage::Done;
        ProviderEffect::Complete(ProviderOutcome::Cleaned(status))
    }
}

impl ProviderOperation for Operation {
    fn advance(&mut self, event: ProviderEvent) -> Result<ProviderEffect, ProviderError> {
        match (self.stage, event) {
            (Stage::Start, ProviderEvent::Start) => {
                if let ProviderAction::Cleanup(request) = &self.action {
                    if request.publication_id != request.record.publication_id
                        || request.receipt.record_name != request.record.name
                        || request.receipt.cname_chain != request.record.cname_chain
                    {
                        return Err(configuration_error("Cloudflare cleanup identity mismatch"));
                    }
                    if request.receipt.ownership == RecordOwnership::Preexisting {
                        return Ok(self.finish_cleanup(CleanupStatus::Retained));
                    }
                }
                if let Some(path) = &self.config.token_file {
                    self.stage = Stage::Secret;
                    return Ok(ProviderEffect::ReadSecret(path.clone()));
                }
                self.begin_zone()
            }
            (Stage::Secret, ProviderEvent::Secret(token)) => {
                if !valid_token(&token) {
                    return Err(error(
                        ProviderErrorCode::CredentialsUnavailable,
                        "invalid Cloudflare token file",
                        SideEffect::None,
                    ));
                }
                self.token = Some(token);
                self.begin_zone()
            }
            (Stage::Discover, ProviderEvent::Http(response)) => self.discovered(response),
            (Stage::SaveZone, ProviderEvent::CheckpointSaved) => self.begin_zone(),
            (Stage::Zone, ProviderEvent::Http(response)) => self.zone_response(response),
            (Stage::List, ProviderEvent::Http(response)) => self.list_response(response),
            (Stage::Intent, ProviderEvent::CheckpointSaved) => {
                self.stage = Stage::Create;
                self.request(CloudflareAction::CreateTxtRecord, "/dns_records", Some(json!({"type":"TXT", "name": self.record().name.trim_end_matches('.'),
                    "content": self.record().value, "ttl": self.record().ttl_seconds.unwrap_or(120).clamp(60,86400), "comment": self.tag()})), true)
            }
            (Stage::Create, ProviderEvent::Http(response)) => {
                let response: Envelope<Record> = match decode_response(response, true) {
                    Ok(response) => response,
                    Err(error) if error.side_effect == SideEffect::None => {
                        self.rejection = Some(error);
                        self.stage = Stage::SaveRejection;
                        return Ok(ProviderEffect::Checkpoint(RecoveryState {
                            version: 1,
                            data: self.checkpoint("create_rejected"),
                        }));
                    }
                    Err(error) => return Err(error),
                };
                let record = response.result.ok_or_else(invalid_response)?;
                if record.comment.as_deref() != Some(&self.tag()) {
                    return Err(invalid_response());
                }
                self.receipt(record, RecordOwnership::Created)
            }
            (Stage::Inspect, ProviderEvent::Http(response)) => self.inspect_response(response),
            (Stage::SaveRejection, ProviderEvent::CheckpointSaved) => {
                Err(self.rejection.take().ok_or_else(invalid_response)?)
            }
            (Stage::DeleteIntent, ProviderEvent::CheckpointSaved) => {
                let ProviderAction::Cleanup(request) = &self.action else {
                    return Err(invalid_response());
                };
                let id = request.receipt.record_id.clone();
                self.stage = Stage::Delete;
                self.request(
                    CloudflareAction::DeleteTxtRecord,
                    &format!("/dns_records/{id}"),
                    None,
                    true,
                )
            }
            (Stage::Delete, ProviderEvent::Http(response)) => {
                let response: Envelope<Value> = decode_response(response, true)?;
                let ProviderAction::Cleanup(request) = &self.action else {
                    return Err(invalid_response());
                };
                if response
                    .result
                    .as_ref()
                    .and_then(|value| value.get("id"))
                    .and_then(Value::as_str)
                    != Some(&request.receipt.record_id)
                {
                    return Err(invalid_response());
                }
                Ok(self.finish_cleanup(CleanupStatus::Removed))
            }
            _ => Err(configuration_error(
                "invalid Cloudflare state machine event",
            )),
        }
    }
}

fn decode_response<T: serde::de::DeserializeOwned>(
    response: Result<HttpResponse, aster_acme_dns::operation::HttpFailure>,
    mutation: bool,
) -> Result<Envelope<T>, ProviderError> {
    let response = response.map_err(|failure| {
        error(
            failure.code,
            "Cloudflare HTTP execution failed",
            failure.side_effect,
        )
    })?;
    let side_effect = if mutation {
        SideEffect::Unknown
    } else {
        SideEffect::None
    };
    let code = match response.status {
        401 => Some(ProviderErrorCode::AuthenticationFailed),
        403 => Some(ProviderErrorCode::AuthorizationDenied),
        429 => Some(ProviderErrorCode::RateLimited),
        500..=599 => Some(ProviderErrorCode::ProviderUnavailable),
        200..=299 => None,
        _ => Some(ProviderErrorCode::RecordConflict),
    };
    if let Some(code) = code {
        let mut failure = error(code, "Cloudflare API rejected the operation", side_effect);
        let provider_code = cloudflare_provider_code(&response.body);
        let request_id = cloudflare_request_id(&response.headers);
        failure.message = cloudflare_message(
            response.status,
            provider_code.as_deref(),
            request_id.as_deref(),
        );
        failure.provider_code = provider_code;
        // Only an authenticated, parsed rejection can narrow unknown mutation effects.
        if response.status < 500
            && serde_json::from_slice::<Value>(&response.body)
                .is_ok_and(|v| v.get("success") == Some(&Value::Bool(false)))
        {
            failure.side_effect = SideEffect::None;
        }
        if code == ProviderErrorCode::RateLimited {
            failure.retry_after_seconds = response
                .headers
                .iter()
                .find(|(name, _)| name.eq_ignore_ascii_case("retry-after"))
                .and_then(|(_, bytes)| std::str::from_utf8(bytes).ok())
                .and_then(|value| value.parse::<u64>().ok())
                .map(|value| value.clamp(1, 86400));
        }
        return Err(failure);
    }
    let decoded: Envelope<T> = serde_json::from_slice(&response.body).map_err(|_| {
        error(
            ProviderErrorCode::InternalError,
            "invalid Cloudflare API response",
            side_effect,
        )
    })?;
    if !decoded.success {
        let mut failure = error(
            ProviderErrorCode::RecordConflict,
            "Cloudflare API did not confirm success",
            side_effect,
        );
        let provider_code = cloudflare_provider_code(&response.body);
        let request_id = cloudflare_request_id(&response.headers);
        failure.message = cloudflare_message(
            response.status,
            provider_code.as_deref(),
            request_id.as_deref(),
        );
        failure.provider_code = provider_code;
        return Err(failure);
    }
    Ok(decoded)
}

fn cloudflare_message(
    status: u16,
    provider_code: Option<&str>,
    request_id: Option<&str>,
) -> String {
    let mut message = match provider_code {
        Some(provider_code) => format!(
            "Cloudflare API rejected or did not confirm the operation (HTTP {status}, provider code {provider_code})"
        ),
        None => format!(
            "Cloudflare API rejected or did not confirm the operation (HTTP {status}; provider code unavailable)"
        ),
    };
    if let Some(request_id) = request_id {
        use std::fmt::Write as _;
        let _ = write!(message, ", request ID {request_id}");
    }
    message
}

fn cloudflare_request_id(headers: &[(String, Vec<u8>)]) -> Option<String> {
    let value = headers
        .iter()
        .find(|(name, _)| name.eq_ignore_ascii_case("cf-ray"))
        .and_then(|(_, value)| std::str::from_utf8(value).ok())?;
    if (1..=128).contains(&value.len())
        && value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_'))
    {
        Some(value.to_owned())
    } else {
        None
    }
}

fn cloudflare_provider_code(body: &[u8]) -> Option<String> {
    let body = serde_json::from_slice::<Value>(body).ok()?;
    let code = body
        .get("errors")
        .and_then(Value::as_array)
        .and_then(|errors| errors.first())
        .and_then(|error| error.get("code"))?;
    let code = code
        .as_u64()
        .map(|code| code.to_string())
        .or_else(|| code.as_str().map(str::to_owned))?;
    if (1..=128).contains(&code.len())
        && code
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'_' | b'-'))
    {
        Some(code)
    } else {
        None
    }
}

fn valid_record_id(value: &str) -> bool {
    value.len() == 32 && value.bytes().all(|byte| byte.is_ascii_hexdigit())
}

fn invalid_response() -> ProviderError {
    error(
        ProviderErrorCode::InternalError,
        "Cloudflare returned an inconsistent response",
        SideEffect::Unknown,
    )
}
fn error(code: ProviderErrorCode, message: &'static str, side_effect: SideEffect) -> ProviderError {
    ProviderError {
        code,
        message: message.into(),
        side_effect,
        retry_after_seconds: None,
        provider_code: None,
    }
}

fn missing_record(response: &HttpResponse) -> bool {
    response.status == 404
        && serde_json::from_slice::<Value>(&response.body).is_ok_and(|value| {
            value.get("success") == Some(&Value::Bool(false))
                && value
                    .get("errors")
                    .and_then(Value::as_array)
                    .is_some_and(|errors| {
                        errors
                            .iter()
                            .any(|error| error.get("code").and_then(Value::as_u64) == Some(81044))
                    })
        })
}

fn uncertain_creation() -> ProviderError {
    error(
        ProviderErrorCode::RecordNotOwned,
        "Cloudflare create outcome remains unknown and no owned tag is visible; inspect remote DNS before retrying",
        SideEffect::Unknown,
    )
}
