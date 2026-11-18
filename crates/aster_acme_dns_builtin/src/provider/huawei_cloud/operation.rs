//! Best-effort Huawei `RRset` lifecycle; it never invents an atomic revision.
use crate::provider::{
    huawei_cloud::{
        Config,
        api::{SignedRequest, decode_body, marker_from_next, payload},
        txt::{add_marker, has_foreign_marker, has_marker, remove_marker, txt_decode, txt_encode},
    },
    retry::ReadRetry,
    rpc::{error, invalid, sha256},
};
use aster_acme_dns::operation::HttpMethod;
use aster_acme_dns::{
    CleanupStatus, DnsRecord, ProviderError, ProviderErrorCode, RecordOwnership, SideEffect,
    backend::configuration_error,
    operation::{
        HttpFailure, HttpRequest, HttpResponse, OperationFactory, ProviderAction, ProviderEffect,
        ProviderEvent, ProviderOperation, ProviderOutcome, RecoveryState,
    },
    routing::absolute_name,
};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use std::collections::BTreeSet;
use time::OffsetDateTime;
const MAX_PAGES: usize = 100;
pub(super) struct Factory {
    pub(super) config: Config,
}

#[derive(Clone, Serialize, Deserialize)]
#[serde(rename_all = "snake_case", tag = "phase", deny_unknown_fields)]
enum Checkpoint {
    ProjectResolved {
        project_id: String,
    },
    ZoneResolved {
        zone_id: String,
        zone_name: String,
    },
    PresentIntent {
        zone_id: String,
        zone_name: String,
        recordset_id: Option<String>,
        original_description: String,
    },
    Presented {
        zone_id: String,
        zone_name: String,
        recordset_id: String,
        original_description: String,
        created: bool,
    },
    CleanupIntent {
        zone_id: String,
        zone_name: String,
        recordset_id: String,
        original_description: String,
    },
    Cleaned {
        recordset_id: String,
        status: CleanupStatusWire,
    },
    Rejected {
        zone_id: String,
        zone_name: String,
    },
}

#[derive(Clone, Copy, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
enum CleanupStatusWire {
    Removed,
    Retained,
    AlreadyAbsent,
}

impl From<CleanupStatusWire> for CleanupStatus {
    fn from(value: CleanupStatusWire) -> Self {
        match value {
            CleanupStatusWire::Removed => Self::Removed,
            CleanupStatusWire::Retained => Self::Retained,
            CleanupStatusWire::AlreadyAbsent => Self::AlreadyAbsent,
        }
    }
}

impl From<CleanupStatus> for CleanupStatusWire {
    fn from(value: CleanupStatus) -> Self {
        match value {
            CleanupStatus::Removed => Self::Removed,
            CleanupStatus::Retained => Self::Retained,
            CleanupStatus::AlreadyAbsent => Self::AlreadyAbsent,
        }
    }
}

#[derive(Clone, Copy)]
enum Stage {
    Start,
    Project,
    SaveProject,
    ZonePage(usize),
    SaveZone,
    Recordsets(usize),
    SaveIntent,
    Write,
    SaveOutcome,
    Poll,
    Done,
}

#[derive(Clone, Copy)]
enum HuaweiAction {
    ListProjects,
    ListZones,
    ListRecordsets,
    CreateRecordset,
    UpdateRecordset,
    DeleteRecordset,
}

impl HuaweiAction {
    const fn method(self) -> HttpMethod {
        match self {
            Self::ListProjects | Self::ListZones | Self::ListRecordsets => HttpMethod::Get,
            Self::CreateRecordset => HttpMethod::Post,
            Self::UpdateRecordset => HttpMethod::Put,
            Self::DeleteRecordset => HttpMethod::Delete,
        }
    }
}

struct Operation {
    config: Config,
    action: ProviderAction,
    saved: Option<Checkpoint>,
    stage: Stage,
    zones: Vec<Zone>,
    recordsets: Vec<Recordset>,
    next_marker: Option<String>,
    recordset: Option<Recordset>,
    desired: BTreeSet<String>,
    original_description: String,
    write_kind: WriteKind,
    outcome: Option<ProviderOutcome>,
    failure: Option<ProviderError>,
    read_retry: ReadRetry,
    writes: u8,
    confirm_cleanup: bool,
}

#[derive(Clone, Deserialize)]
struct IamProject {
    id: String,
    name: String,
}

#[derive(Clone, Deserialize)]
struct Zone {
    id: String,
    name: String,
}

#[derive(Clone, Deserialize)]
struct Recordset {
    id: String,
    name: String,
    #[serde(rename = "type")]
    kind: String,
    #[serde(default)]
    description: String,
    records: Vec<String>,
    #[serde(default)]
    ttl: u32,
    status: String,
    zone_id: String,
    #[serde(default)]
    line: Option<String>,
}

#[derive(Clone, Copy)]
enum WriteKind {
    Create,
    Update,
    Delete,
}

impl OperationFactory for Factory {
    #[expect(
        clippy::too_many_lines,
        reason = "Validates the recovery identity and ownership contract before an operation exists."
    )]
    fn start(
        &self,
        action: ProviderAction,
        saved: Option<RecoveryState>,
    ) -> Result<Box<dyn ProviderOperation>, ProviderError> {
        let record = match &action {
            ProviderAction::Present(record) => record,
            ProviderAction::Cleanup(request) => &request.record,
        };
        absolute_name(&record.name).map_err(|_| configuration_error("invalid Huawei DNS owner"))?;
        if record.publication_id.is_empty()
            || record.publication_id.len() > 90
            || !record
                .publication_id
                .bytes()
                .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_'))
            || record.value.is_empty()
            || record.value.len() > 255
        {
            return Err(configuration_error(
                "invalid Huawei DNS publication identity or value",
            ));
        }
        let saved = saved
            .map(|state| {
                if state.version != 1 {
                    return Err(configuration_error(
                        "unsupported Huawei DNS checkpoint version",
                    ));
                }
                let mut data = state.data;
                let project_id = match data
                    .as_object_mut()
                    .and_then(|object| object.remove("resolved_project_id"))
                {
                    Some(value) => {
                        Some(value.as_str().map(str::to_owned).ok_or_else(|| {
                            configuration_error("invalid saved Huawei project ID")
                        })?)
                    }
                    None => None,
                };
                let checkpoint = serde_json::from_value::<Checkpoint>(data)
                    .map_err(|_| configuration_error("invalid Huawei DNS checkpoint"))?;
                Ok((checkpoint, project_id))
            })
            .transpose()?;
        let (saved, saved_project) = match saved {
            Some((state, project_id)) => (Some(state), project_id),
            None => (None, None),
        };
        let mut config = self.config.clone();
        let checkpoint_project = saved.as_ref().and_then(|state| match state {
            Checkpoint::ProjectResolved { project_id } => Some(project_id.as_str()),
            _ => None,
        });
        if let (Some(saved_project), Some(checkpoint_project)) =
            (saved_project.as_deref(), checkpoint_project)
            && saved_project != checkpoint_project
        {
            return Err(configuration_error(
                "saved Huawei project checkpoint is inconsistent",
            ));
        }
        if let (Some(configured), Some(saved_project)) =
            (config.project_id.as_deref(), saved_project.as_deref())
            && configured != saved_project
        {
            return Err(configuration_error(
                "saved Huawei project differs from current configuration",
            ));
        }
        if let (Some(configured), Some(checkpoint_project)) =
            (config.project_id.as_deref(), checkpoint_project)
            && configured != checkpoint_project
        {
            return Err(configuration_error(
                "saved Huawei project differs from current configuration",
            ));
        }
        if config.project_id.is_none() {
            config.project_id = saved_project.or_else(|| checkpoint_project.map(str::to_owned));
        }
        if saved.is_some() && config.project_id.is_none() {
            return Err(configuration_error(
                "saved Huawei checkpoint is missing its resolved project",
            ));
        }
        if let Some(state) = &saved {
            validate_checkpoint(state, record)?;
        }
        if matches!(&action, ProviderAction::Present(_))
            && matches!(
                &saved,
                Some(Checkpoint::CleanupIntent { .. } | Checkpoint::Cleaned { .. })
            )
        {
            return Err(configuration_error(
                "cannot present Huawei DNS publication after cleanup starts",
            ));
        }
        if let ProviderAction::Cleanup(request) = &action {
            if request.publication_id != record.publication_id
                || request.receipt.record_name != record.name
                || request.receipt.cname_chain != record.cname_chain
                || !valid_id(&request.receipt.record_id)
            {
                return Err(configuration_error("invalid Huawei DNS cleanup identity"));
            }
            let recordset_id = match saved.as_ref() {
                Some(
                    Checkpoint::Presented {
                        recordset_id,
                        created: true,
                        ..
                    }
                    | Checkpoint::CleanupIntent { recordset_id, .. }
                    | Checkpoint::Cleaned { recordset_id, .. },
                ) => recordset_id,
                _ if request.receipt.ownership == RecordOwnership::Preexisting => {
                    return Ok(Box::new(Operation::new(config, action, saved)));
                }
                _ => return Err(not_owned()),
            };
            if request.receipt.ownership == RecordOwnership::Created
                && request.receipt.record_id != *recordset_id
                || request.receipt.record_name != request.record.name
                || request.receipt.cname_chain != request.record.cname_chain
            {
                return Err(configuration_error(
                    "Huawei DNS cleanup receipt does not match publication",
                ));
            }
        }
        Ok(Box::new(Operation::new(config, action, saved)))
    }
}

impl Operation {
    fn saved_id(&self) -> Option<&str> {
        match &self.saved {
            Some(Checkpoint::PresentIntent { recordset_id, .. }) => recordset_id.as_deref(),
            Some(
                Checkpoint::Presented { recordset_id, .. }
                | Checkpoint::CleanupIntent { recordset_id, .. }
                | Checkpoint::Cleaned { recordset_id, .. },
            ) => Some(recordset_id),
            _ => None,
        }
    }

    fn poll(&mut self) -> Result<ProviderEffect, ProviderError> {
        let until = self.read_retry.next().ok_or_else(|| {
            error(
                ProviderErrorCode::ProviderUnavailable,
                "Huawei DNS RRset remains pending",
                SideEffect::Unknown,
            )
        })?;
        self.stage = Stage::Poll;
        Ok(ProviderEffect::WaitUntil(until))
    }

    fn write_failure(&mut self, failure: ProviderError) -> Result<ProviderEffect, ProviderError> {
        if failure.side_effect != SideEffect::None
            || !matches!(self.action, ProviderAction::Present(_))
        {
            return Err(failure);
        }
        let zone = self.zone()?;
        if failure.code == ProviderErrorCode::RecordConflict && self.writes < 4 {
            return self.checkpoint(
                Checkpoint::Rejected {
                    zone_id: zone.id,
                    zone_name: zone.name,
                },
                Stage::SaveZone,
            );
        }
        self.failure = Some(failure);
        self.checkpoint(
            Checkpoint::Rejected {
                zone_id: zone.id,
                zone_name: zone.name,
            },
            Stage::SaveOutcome,
        )
    }
    fn new(config: Config, action: ProviderAction, saved: Option<Checkpoint>) -> Self {
        Self {
            config,
            action,
            saved,
            stage: Stage::Start,
            zones: Vec::new(),
            recordsets: Vec::new(),
            next_marker: None,
            recordset: None,
            desired: BTreeSet::new(),
            original_description: String::new(),
            write_kind: WriteKind::Create,
            outcome: None,
            failure: None,
            read_retry: ReadRetry::new(8, std::time::Duration::from_secs(1)),
            writes: 0,
            confirm_cleanup: false,
        }
    }

    fn record(&self) -> &DnsRecord {
        match &self.action {
            ProviderAction::Present(record) => record,
            ProviderAction::Cleanup(request) => &request.record,
        }
    }

    fn marker(&self) -> String {
        format!(
            "asteracme:{}={}",
            self.record().publication_id,
            sha256(self.record().value.as_bytes())
        )
    }

    fn endpoint(&self) -> String {
        format!("https://dns.{}.myhuaweicloud.com", self.config.region)
    }

    fn request(
        &self,
        action: HuaweiAction,
        path: &str,
        query: &[(&str, &str)],
        body: &[u8],
        mutation: bool,
    ) -> Result<HttpRequest, ProviderError> {
        let date = hws_date();
        SignedRequest {
            endpoint: &self.endpoint(),
            method: action.method(),
            path,
            query,
            body,
            mutation,
            project_id: self.config.project_id.as_deref(),
        }
        .sign(
            &self.config.access_key_id,
            &self.config.access_key_secret,
            &date,
        )
    }

    fn discover_project(&mut self) -> Result<ProviderEffect, ProviderError> {
        self.stage = Stage::Project;
        let endpoint = iam_endpoint(&self.config.region);
        let date = hws_date();
        SignedRequest {
            endpoint: &endpoint,
            method: HuaweiAction::ListProjects.method(),
            path: "/v3/projects",
            query: &[("name", self.config.region.as_str())],
            body: &[],
            mutation: false,
            project_id: None,
        }
        .sign(
            &self.config.access_key_id,
            &self.config.access_key_secret,
            &date,
        )
        .map(ProviderEffect::Http)
    }

    fn project_response(
        &mut self,
        response: &HttpResponse,
    ) -> Result<ProviderEffect, ProviderError> {
        let body = payload(response, false)?;
        let projects: Vec<IamProject> =
            decode_body(body.get("projects").cloned().unwrap_or_default(), false)?;
        let mut matches = projects
            .into_iter()
            .filter(|project| project.name == self.config.region)
            .collect::<Vec<_>>();
        if matches.len() != 1 || !super::valid_project_id(&matches[0].id) {
            return Err(error(
                ProviderErrorCode::RecordConflict,
                "Huawei IAM project discovery returned zero or multiple projects for this region",
                SideEffect::None,
            ));
        }
        let project_id = matches.remove(0).id;
        self.config.project_id = Some(project_id.clone());
        self.checkpoint(
            Checkpoint::ProjectResolved { project_id },
            Stage::SaveProject,
        )
    }

    fn checkpoint(
        &mut self,
        state: Checkpoint,
        next: Stage,
    ) -> Result<ProviderEffect, ProviderError> {
        let mut data = serde_json::to_value(&state)
            .map_err(|_| configuration_error("cannot encode Huawei DNS checkpoint"))?;
        if let Some(project_id) = &self.config.project_id {
            data.as_object_mut()
                .ok_or_else(|| configuration_error("invalid Huawei DNS checkpoint"))?
                .insert("resolved_project_id".into(), json!(project_id));
        }
        self.saved = Some(state);
        self.stage = next;
        Ok(ProviderEffect::Checkpoint(RecoveryState {
            version: 1,
            data,
        }))
    }

    fn discover(&mut self, page: usize) -> Result<ProviderEffect, ProviderError> {
        let marker = self.next_marker.clone().unwrap_or_default();
        if page == 1 {
            self.zones.clear();
            self.next_marker = None;
        }
        self.stage = Stage::ZonePage(page);
        self.request(
            HuaweiAction::ListZones,
            "/v2/zones",
            &[
                ("type", "public"),
                ("limit", "500"),
                ("marker", marker.as_str()),
            ],
            &[],
            false,
        )
        .map(ProviderEffect::Http)
    }

    fn parse_zones(
        &mut self,
        response: &HttpResponse,
        page: usize,
    ) -> Result<ProviderEffect, ProviderError> {
        let body = payload(response, false)?;
        let entries: Vec<Zone> =
            decode_body(body.get("zones").cloned().unwrap_or_default(), false)?;
        if page > MAX_PAGES || entries.iter().any(|zone| zone.id.is_empty()) {
            return Err(invalid(false));
        }
        if entries.len() > 500 || self.zones.len() + entries.len() > 10000 {
            return Err(invalid(false));
        }
        for zone in &entries {
            if !valid_id(&zone.id)
                || absolute_name(&zone.name).is_err()
                || self.zones.iter().any(|prior| prior.id == zone.id)
            {
                return Err(invalid(false));
            }
        }
        self.zones.extend(entries);
        let next = body
            .pointer("/links/next")
            .and_then(Value::as_str)
            .filter(|value| !value.is_empty())
            .map(str::to_owned);
        if let Some(next) = next {
            if page >= MAX_PAGES {
                return Err(invalid(false));
            }
            let marker = marker_from_next(&next, &self.endpoint())?;
            if self.next_marker.as_ref() == Some(&marker) {
                return Err(invalid(false));
            }
            self.next_marker = Some(marker);
            return self.discover(page + 1);
        }
        let owner = absolute_name(&self.record().name).map_err(|_| invalid(false))?;
        let mut matches = self
            .zones
            .iter()
            .filter(|zone| {
                let Ok(name) = absolute_name(&zone.name) else {
                    return false;
                };
                owner == name || owner.ends_with(&format!(".{name}"))
            })
            .cloned()
            .collect::<Vec<_>>();
        for zone in &mut matches {
            zone.name = absolute_name(&zone.name).map_err(|_| invalid(false))?;
        }
        matches.sort_by_key(|zone| std::cmp::Reverse(zone.name.len()));
        if matches.is_empty()
            || matches
                .get(1)
                .is_some_and(|second| second.name.len() == matches[0].name.len())
        {
            return Err(ProviderError {
                code: if matches.is_empty() {
                    ProviderErrorCode::ZoneNotFound
                } else {
                    ProviderErrorCode::ZoneAmbiguous
                },
                message: "Huawei DNS zone discovery was missing or ambiguous".into(),
                side_effect: SideEffect::None,
                retry_after_seconds: None,
                provider_code: None,
            });
        }
        let zone = matches.into_iter().next().ok_or_else(|| invalid(false))?;
        self.checkpoint(
            Checkpoint::ZoneResolved {
                zone_id: zone.id,
                zone_name: zone.name,
            },
            Stage::SaveZone,
        )
    }

    fn list_recordsets(&mut self) -> Result<ProviderEffect, ProviderError> {
        self.list_recordsets_page(1)
    }

    fn list_recordsets_page(&mut self, page: usize) -> Result<ProviderEffect, ProviderError> {
        let zone = self.zone()?;
        if page == 1 {
            self.recordsets.clear();
            self.next_marker = None;
        }
        let marker = self.next_marker.clone().unwrap_or_default();
        self.stage = Stage::Recordsets(page);
        self.request(
            HuaweiAction::ListRecordsets,
            &format!("/v2/zones/{}/recordsets", zone.id),
            &[
                ("name", self.record().name.trim_end_matches('.')),
                ("type", "TXT"),
                ("search_mode", "equal"),
                ("limit", "500"),
                ("marker", marker.as_str()),
            ],
            &[],
            false,
        )
        .map(ProviderEffect::Http)
    }

    fn parse_recordsets(
        &mut self,
        response: &HttpResponse,
        page: usize,
    ) -> Result<ProviderEffect, ProviderError> {
        let body = payload(response, false)?;
        if page > MAX_PAGES {
            return Err(invalid(false));
        }
        let entries = decode_body::<Vec<Recordset>>(
            body.get("recordsets").cloned().unwrap_or_default(),
            false,
        )?;
        let zone_id = self.zone()?.id;
        for entry in &entries {
            if !valid_id(&entry.id)
                || entry.zone_id != zone_id
                || entry.ttl == 0
                || entry.ttl > 2_147_483_647
                || absolute_name(&entry.name).is_err()
                || self.recordsets.iter().any(|prior| prior.id == entry.id)
                || entry.records.len() > 1000
            {
                return Err(invalid(false));
            }
        }
        if entries.len() > 500 || self.recordsets.len() + entries.len() > 10000 {
            return Err(invalid(false));
        }
        self.recordsets.extend(entries);
        if let Some(next) = body
            .pointer("/links/next")
            .and_then(Value::as_str)
            .filter(|value| !value.is_empty())
        {
            if page >= MAX_PAGES {
                return Err(invalid(false));
            }
            let marker = marker_from_next(next, &self.endpoint())?;
            if self.next_marker.as_ref() == Some(&marker) {
                return Err(invalid(false));
            }
            self.next_marker = Some(marker);
            return self.list_recordsets_page(page + 1);
        }
        let owner = absolute_name(&self.record().name).map_err(|_| invalid(false))?;
        let mut found = self
            .recordsets
            .drain(..)
            .filter(|recordset| {
                absolute_name(&recordset.name).ok().as_deref() == Some(&owner)
                    && recordset.kind == "TXT"
                    && recordset
                        .line
                        .as_deref()
                        .is_none_or(|line| line == "default_view")
            })
            .collect::<Vec<_>>();
        if found.len() > 1 {
            return Err(conflict("multiple Huawei TXT RRsets match the owner"));
        }
        self.plan(found.pop())
    }

    fn plan(&mut self, recordset: Option<Recordset>) -> Result<ProviderEffect, ProviderError> {
        if let Some(current) = &recordset {
            if current.status.starts_with("PENDING_") {
                return self.poll();
            }
            if current.status != "ACTIVE" {
                return Err(conflict("Huawei DNS RRset is not active"));
            }
        }
        let target = txt_encode(&self.record().value);
        let mut desired = recordset.as_ref().map_or_else(BTreeSet::new, |set| {
            set.records.iter().cloned().collect::<BTreeSet<_>>()
        });
        let matching = desired
            .iter()
            .filter_map(|wire| txt_decode(wire).map(|logical| (wire.clone(), logical)))
            .filter(|(_, logical)| logical == self.record().value.as_bytes())
            .map(|(wire, _)| wire)
            .collect::<Vec<_>>();
        // Reject malformed TXT observations rather than rewriting a lossy set.
        if desired.iter().any(|wire| txt_decode(wire).is_none()) || matching.len() > 1 {
            return Err(invalid(false));
        }
        let exists = !matching.is_empty();
        let marker = self.marker();
        let owned = recordset
            .as_ref()
            .is_some_and(|set| has_marker(&set.description, &marker));
        let foreign_same_value = recordset
            .as_ref()
            .is_some_and(|set| has_foreign_marker(&set.description, &marker));
        if self
            .saved_id()
            .is_some_and(|id| recordset.as_ref().is_some_and(|set| set.id != id))
        {
            return Err(not_owned());
        }
        match &self.action {
            ProviderAction::Present(_) if exists => {
                if foreign_same_value {
                    return Err(conflict("Huawei TXT value belongs to another publication"));
                }
                match self.saved.as_ref() {
                    Some(
                        Checkpoint::PresentIntent { .. }
                        | Checkpoint::Presented { created: true, .. },
                    ) if !owned => return Err(not_owned()),
                    Some(Checkpoint::ZoneResolved { .. } | Checkpoint::Rejected { .. })
                        if owned =>
                    {
                        return Err(not_owned());
                    }
                    _ => {}
                }
                return self.presented(recordset.ok_or_else(|| invalid(false))?, owned);
            }
            ProviderAction::Cleanup(_) if !exists => {
                return self.cleaned(if self.confirm_cleanup {
                    CleanupStatus::Removed
                } else {
                    CleanupStatus::AlreadyAbsent
                });
            }
            ProviderAction::Present(_) => {
                if matches!(
                    self.saved,
                    Some(Checkpoint::PresentIntent { .. } | Checkpoint::Presented { .. })
                ) {
                    return Err(not_owned());
                }
                desired.insert(target);
                self.write_kind = if recordset.is_some() {
                    WriteKind::Update
                } else {
                    WriteKind::Create
                };
            }
            ProviderAction::Cleanup(_) => {
                if !owned || foreign_same_value {
                    return Err(not_owned());
                }
                if self.confirm_cleanup {
                    return Err(not_owned());
                }
                for value in matching {
                    desired.remove(&value);
                }
                self.write_kind = if desired.is_empty() {
                    WriteKind::Delete
                } else {
                    WriteKind::Update
                };
            }
        }
        self.save_mutation(recordset, desired)
    }

    fn save_mutation(
        &mut self,
        recordset: Option<Recordset>,
        desired: BTreeSet<String>,
    ) -> Result<ProviderEffect, ProviderError> {
        self.recordset = recordset;
        self.desired = desired;
        self.original_description = self
            .recordset
            .as_ref()
            .map_or_else(String::new, |value| value.description.clone());
        let zone = self.zone()?;
        let checkpoint = match self.action {
            ProviderAction::Present(_) => Checkpoint::PresentIntent {
                zone_id: zone.id.clone(),
                zone_name: zone.name.clone(),
                recordset_id: self.recordset.as_ref().map(|value| value.id.clone()),
                original_description: self.original_description.clone(),
            },
            ProviderAction::Cleanup(_) => Checkpoint::CleanupIntent {
                zone_id: zone.id.clone(),
                zone_name: zone.name.clone(),
                recordset_id: self.recordset_id()?,
                original_description: self.original_description.clone(),
            },
        };
        self.checkpoint(checkpoint, Stage::SaveIntent)
    }

    fn write(&mut self) -> Result<ProviderEffect, ProviderError> {
        let zone = self.zone()?;
        let owner = absolute_name(&self.record().name).map_err(|_| invalid(false))?;
        let marker = self.marker();
        let body = match self.write_kind {
            WriteKind::Create => json!({
                "name": owner,
                "type": "TXT",
                "ttl": self.record().ttl_seconds.unwrap_or(300).clamp(300, 2_147_483_647),
                "records": self.desired.iter().collect::<Vec<_>>(),
                "description": add_marker(&self.original_description, &marker)?,
            }),
            WriteKind::Update => json!({
                "records": self.desired.iter().collect::<Vec<_>>(),
                "description": if matches!(self.action, ProviderAction::Cleanup(_)) {
                    remove_marker(&self.original_description, &marker)
                } else {
                    add_marker(&self.original_description, &marker)?
                },
            }),
            WriteKind::Delete => Value::Null,
        };
        let body_bytes = if matches!(self.write_kind, WriteKind::Delete) {
            Vec::new()
        } else {
            serde_json::to_vec(&body).map_err(|_| invalid(true))?
        };
        self.stage = Stage::Write;
        match self.write_kind {
            WriteKind::Create => self.request(
                HuaweiAction::CreateRecordset,
                &format!("/v2/zones/{}/recordsets", zone.id),
                &[],
                &body_bytes,
                true,
            ),
            WriteKind::Update => self.request(
                HuaweiAction::UpdateRecordset,
                &format!("/v2/zones/{}/recordsets/{}", zone.id, self.recordset_id()?),
                &[],
                &body_bytes,
                true,
            ),
            WriteKind::Delete => self.request(
                HuaweiAction::DeleteRecordset,
                &format!("/v2/zones/{}/recordsets/{}", zone.id, self.recordset_id()?),
                &[],
                &[],
                true,
            ),
        }
        .map(ProviderEffect::Http)
    }

    fn zone(&self) -> Result<Zone, ProviderError> {
        match &self.saved {
            Some(
                Checkpoint::ZoneResolved { zone_id, zone_name }
                | Checkpoint::Rejected { zone_id, zone_name }
                | Checkpoint::PresentIntent {
                    zone_id, zone_name, ..
                }
                | Checkpoint::Presented {
                    zone_id, zone_name, ..
                }
                | Checkpoint::CleanupIntent {
                    zone_id, zone_name, ..
                },
            ) => Ok(Zone {
                id: zone_id.clone(),
                name: zone_name.clone(),
            }),
            _ => Err(configuration_error("missing Huawei DNS zone checkpoint")),
        }
    }

    fn recordset_id(&self) -> Result<String, ProviderError> {
        self.recordset
            .as_ref()
            .map(|set| set.id.clone())
            .or_else(|| self.saved_id().map(str::to_owned))
            .ok_or_else(not_owned)
    }

    fn presented(
        &mut self,
        recordset: Recordset,
        created: bool,
    ) -> Result<ProviderEffect, ProviderError> {
        let zone = self.zone()?;
        self.recordset = Some(recordset.clone());
        self.outcome = Some(ProviderOutcome::Presented(
            aster_acme_dns::PublicationReceipt {
                record_id: recordset.id.clone(),
                ownership: if created {
                    RecordOwnership::Created
                } else {
                    RecordOwnership::Preexisting
                },
                record_name: self.record().name.clone(),
                cname_chain: self.record().cname_chain.clone(),
                effective_ttl_seconds: Some(recordset.ttl),
            },
        ));
        self.checkpoint(
            Checkpoint::Presented {
                zone_id: zone.id,
                zone_name: zone.name,
                recordset_id: recordset.id,
                original_description: self.original_description.clone(),
                created,
            },
            Stage::SaveOutcome,
        )
    }

    fn cleaned(&mut self, status: CleanupStatus) -> Result<ProviderEffect, ProviderError> {
        self.outcome = Some(ProviderOutcome::Cleaned(status));
        let ProviderAction::Cleanup(request) = &self.action else {
            return Err(not_owned());
        };
        let id = request.receipt.record_id.clone();
        self.checkpoint(
            Checkpoint::Cleaned {
                recordset_id: id,
                status: status.into(),
            },
            Stage::SaveOutcome,
        )
    }

    fn finish_write(
        &mut self,
        response: Result<HttpResponse, HttpFailure>,
    ) -> Result<ProviderEffect, ProviderError> {
        let response = match response {
            Ok(response) => response,
            Err(failure) => return self.write_failure(transport(failure)),
        };
        if response.status / 100 != 2 {
            return self.write_failure(
                payload(&response, true)
                    .err()
                    .ok_or_else(|| invalid(true))?,
            );
        }
        if !matches!(self.write_kind, WriteKind::Delete) {
            let observed: Recordset = decode_body(payload(&response, true)?, true)?;
            if !valid_id(&observed.id)
                || observed.zone_id != self.zone()?.id
                || absolute_name(&observed.name).ok() != absolute_name(&self.record().name).ok()
                || observed.kind != "TXT"
                || self.saved_id().is_some_and(|id| id != observed.id)
            {
                return Err(invalid(true));
            }
            let zone = self.zone()?;
            let id = observed.id;
            let saved = match &self.action {
                ProviderAction::Present(_) => Checkpoint::PresentIntent {
                    zone_id: zone.id,
                    zone_name: zone.name,
                    recordset_id: Some(id),
                    original_description: self.original_description.clone(),
                },
                ProviderAction::Cleanup(_) => Checkpoint::CleanupIntent {
                    zone_id: zone.id,
                    zone_name: zone.name,
                    recordset_id: id,
                    original_description: self.original_description.clone(),
                },
            };
            self.confirm_cleanup = matches!(self.action, ProviderAction::Cleanup(_));
            return self.checkpoint(saved, Stage::SaveZone);
        }
        self.confirm_cleanup = true;
        self.list_recordsets()
    }
}

impl ProviderOperation for Operation {
    fn advance(&mut self, event: ProviderEvent) -> Result<ProviderEffect, ProviderError> {
        match (self.stage, event) {
            (Stage::Start, ProviderEvent::Start) => {
                if matches!(&self.action, ProviderAction::Cleanup(request) if request.receipt.ownership == RecordOwnership::Preexisting)
                {
                    return self.cleaned(CleanupStatus::Retained);
                }
                match &self.saved {
                    Some(Checkpoint::Cleaned { status, .. }) => Ok(ProviderEffect::Complete(
                        ProviderOutcome::Cleaned((*status).into()),
                    )),
                    Some(Checkpoint::ZoneResolved { .. } | Checkpoint::Rejected { .. }) => {
                        self.list_recordsets()
                    }
                    Some(Checkpoint::ProjectResolved { .. }) => self.discover(1),
                    Some(
                        Checkpoint::PresentIntent { .. }
                        | Checkpoint::Presented { .. }
                        | Checkpoint::CleanupIntent { .. },
                    ) => self.list_recordsets(),
                    None if self.config.project_id.is_some() => self.discover(1),
                    None => self.discover_project(),
                }
            }
            (Stage::Project, ProviderEvent::Http(response)) => {
                self.project_response(&response.map_err(transport)?)
            }
            (Stage::SaveProject, ProviderEvent::CheckpointSaved) => self.discover(1),
            (Stage::ZonePage(page), ProviderEvent::Http(response)) => {
                self.parse_zones(&response.map_err(transport)?, page)
            }
            (Stage::SaveZone, ProviderEvent::CheckpointSaved)
            | (Stage::Poll, ProviderEvent::Timer) => self.list_recordsets(),
            (Stage::Recordsets(page), ProviderEvent::Http(response)) => {
                self.parse_recordsets(&response.map_err(transport)?, page)
            }
            (Stage::SaveIntent, ProviderEvent::CheckpointSaved) => {
                self.writes += 1;
                self.write()
            }
            (Stage::Write, ProviderEvent::Http(response)) => self.finish_write(response),
            (Stage::SaveOutcome, ProviderEvent::CheckpointSaved) => {
                self.stage = Stage::Done;
                if let Some(error) = self.failure.take() {
                    return Err(error);
                }
                Ok(ProviderEffect::Complete(self.outcome.take().ok_or_else(
                    || configuration_error("missing Huawei DNS outcome"),
                )?))
            }
            _ => Err(configuration_error(
                "invalid Huawei DNS state machine event",
            )),
        }
    }
}

fn transport(failure: HttpFailure) -> ProviderError {
    error(
        failure.code,
        "Huawei DNS HTTP exchange failed",
        failure.side_effect,
    )
}

fn conflict(message: &'static str) -> ProviderError {
    error(ProviderErrorCode::RecordConflict, message, SideEffect::None)
}

fn not_owned() -> ProviderError {
    error(
        ProviderErrorCode::RecordNotOwned,
        "Huawei DNS RRset ownership cannot be proved",
        SideEffect::Unknown,
    )
}

fn valid_id(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 80
        && value
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'-')
}

fn validate_checkpoint(state: &Checkpoint, record: &DnsRecord) -> Result<(), ProviderError> {
    let (zone_id, zone_name, id, description) = match state {
        Checkpoint::ProjectResolved { project_id } => {
            return if super::valid_project_id(project_id) {
                Ok(())
            } else {
                Err(configuration_error("invalid Huawei IAM project checkpoint"))
            };
        }
        Checkpoint::ZoneResolved { zone_id, zone_name }
        | Checkpoint::Rejected { zone_id, zone_name } => (zone_id, zone_name, None, ""),
        Checkpoint::PresentIntent {
            zone_id,
            zone_name,
            recordset_id,
            original_description,
        } => (
            zone_id,
            zone_name,
            recordset_id.as_deref(),
            original_description.as_str(),
        ),
        Checkpoint::Presented {
            zone_id,
            zone_name,
            recordset_id,
            original_description,
            ..
        }
        | Checkpoint::CleanupIntent {
            zone_id,
            zone_name,
            recordset_id,
            original_description,
        } => (
            zone_id,
            zone_name,
            Some(recordset_id.as_str()),
            original_description.as_str(),
        ),
        Checkpoint::Cleaned { recordset_id, .. } => {
            return if valid_id(recordset_id) {
                Ok(())
            } else {
                Err(not_owned())
            };
        }
    };
    let zone = absolute_name(zone_name).map_err(|_| not_owned())?;
    let owner = absolute_name(&record.name).map_err(|_| not_owned())?;
    if !valid_id(zone_id)
        || (owner != zone && !owner.ends_with(&format!(".{zone}")))
        || id.is_some_and(|id| !valid_id(id))
        || description.len() > 255
    {
        return Err(configuration_error(
            "invalid Huawei DNS saved zone or RRset identity",
        ));
    }
    Ok(())
}

fn hws_date() -> String {
    let now = OffsetDateTime::now_utc();
    format!(
        "{:04}{:02}{:02}T{:02}{:02}{:02}Z",
        now.year(),
        u8::from(now.month()),
        now.day(),
        now.hour(),
        now.minute(),
        now.second()
    )
}

fn iam_endpoint(region: &str) -> String {
    const REGIONS: &[&str] = &[
        "cn-north-2",
        "cn-north-4",
        "cn-north-1",
        "cn-east-2",
        "cn-east-3",
        "cn-south-1",
        "cn-south-2",
        "cn-southwest-2",
        "ap-southeast-1",
        "ap-southeast-2",
        "ap-southeast-3",
        "af-south-1",
        "sa-brazil-1",
        "la-south-2",
        "na-mexico-1",
        "la-north-2",
        "cn-north-9",
        "eu-west-0",
        "my-kualalumpur-1",
        "ru-moscow-1",
        "me-east-1",
        "ap-southeast-4",
        "ae-ad-1",
        "cn-east-4",
        "cn-east-5",
        "tr-west-1",
        "cn-north-12",
    ];
    if REGIONS.contains(&region) {
        format!("https://iam.{region}.myhuaweicloud.com")
    } else {
        "https://iam.myhuaweicloud.com".into()
    }
}
