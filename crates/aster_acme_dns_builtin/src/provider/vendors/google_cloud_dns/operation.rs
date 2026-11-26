//! Durable changes lifecycle. Unknown writes never authorize replay or adoption.
use crate::provider::{
    common::{
        retry::ReadRetry,
        rpc::{error, invalid},
        txt::txt_encode,
    },
    vendors::google_cloud_dns::{
        Config,
        api::{self, Change, Plan, Rrset, Rrsets, Zone, Zones},
        auth::{self, Token},
        safe_id,
    },
};
use aster_acme_dns::{
    CleanupStatus, DnsRecord, ProviderError, ProviderErrorCode, PublicationReceipt,
    RecordOwnership, SideEffect,
    backend::configuration_error,
    operation::{
        HttpFailure, HttpMethod, HttpRequest, HttpResponse, OperationFactory, ProviderAction,
        ProviderEffect, ProviderEvent, ProviderOperation, ProviderOutcome, RecoveryState,
    },
    routing::absolute_name,
};
use serde::{Deserialize, Serialize};
use std::{
    collections::{BTreeMap, BTreeSet},
    sync::{Arc, Mutex},
    time::{Duration, Instant},
};
use time::OffsetDateTime;

pub(super) struct Factory {
    pub config: Config,
    pub token: Arc<Mutex<Option<Token>>>,
}

#[derive(Clone, Copy, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
enum Phase {
    Resolved,
    PresentIntent,
    Presented,
    CleanupIntent,
    Cleaned,
}

#[derive(Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct Checkpoint {
    zone: Zone,
    phase: Phase,
    plan: Option<Plan>,
    change_id: Option<String>,
    effective_ttl: Option<u32>,
    retry_at: Option<i64>,
    cleanup_removed: bool,
}

#[derive(Clone, Copy)]
enum Request {
    Zones,
    Rrsets,
    Submit,
    Poll,
}

enum Stage {
    Start,
    Token(Request),
    Http(Request),
    Save(Request),
    SaveOutcome,
    Wait,
    Done,
}

struct Operation {
    config: Config,
    token: Arc<Mutex<Option<Token>>>,
    action: ProviderAction,
    saved: Option<Checkpoint>,
    stage: Stage,
    zones: BTreeMap<String, Zone>,
    rrsets: Vec<Rrset>,
    pages: BTreeSet<String>,
    page: String,
    writes: u8,
    poll: ReadRetry,
    failure: Option<ProviderError>,
    outcome: Option<ProviderOutcome>,
}

impl OperationFactory for Factory {
    fn start(
        &self,
        action: ProviderAction,
        saved: Option<RecoveryState>,
    ) -> Result<Box<dyn ProviderOperation>, ProviderError> {
        let record = match &action {
            ProviderAction::Present(r) => r,
            ProviderAction::Cleanup(r) => &r.record,
        };
        let owner = absolute_name(&record.name)
            .map_err(|_| configuration_error("invalid Google DNS owner"))?;
        if !safe_id(&record.publication_id)
            || record.value.is_empty()
            || record.value.len() > 255
            || !record.value.is_ascii()
        {
            return Err(configuration_error("invalid Google DNS publication"));
        }
        let saved = saved
            .map(|state| {
                if state.version != 1 {
                    return Err(configuration_error(
                        "unsupported Google DNS checkpoint version",
                    ));
                }
                let state: Checkpoint = serde_json::from_value(state.data)
                    .map_err(|_| configuration_error("invalid Google DNS checkpoint"))?;
                validate(&state, record, &owner)?;
                Ok(state)
            })
            .transpose()?;
        if let ProviderAction::Cleanup(request) = &action {
            if request.publication_id != record.publication_id
                || request.receipt.record_name != record.name
                || request.receipt.cname_chain != record.cname_chain
                || request.receipt.ownership != RecordOwnership::Created
                || saved.as_ref().is_none_or(|s| {
                    !matches!(
                        s.phase,
                        Phase::Presented | Phase::CleanupIntent | Phase::Cleaned
                    ) || request.receipt.record_id != identity(&s.zone, &owner)
                })
            {
                return Err(not_owned());
            }
        } else if saved
            .as_ref()
            .is_some_and(|s| matches!(s.phase, Phase::CleanupIntent | Phase::Cleaned))
        {
            return Err(not_owned());
        }
        Ok(Box::new(Operation {
            config: self.config.clone(),
            token: self.token.clone(),
            action,
            saved,
            stage: Stage::Start,
            zones: BTreeMap::new(),
            rrsets: Vec::new(),
            pages: BTreeSet::new(),
            page: String::new(),
            writes: 0,
            poll: ReadRetry::new(8, Duration::from_secs(1)),
            failure: None,
            outcome: None,
        }))
    }
}

impl Operation {
    fn record(&self) -> &DnsRecord {
        match &self.action {
            ProviderAction::Present(r) => r,
            ProviderAction::Cleanup(r) => &r.record,
        }
    }

    fn owner(&self) -> Result<String, ProviderError> {
        absolute_name(&self.record().name).map_err(|_| invalid(false))
    }

    fn state(&self) -> Result<&Checkpoint, ProviderError> {
        self.saved
            .as_ref()
            .ok_or_else(|| configuration_error("missing Google DNS checkpoint"))
    }

    fn checkpoint(
        &mut self,
        state: Checkpoint,
        next: Stage,
    ) -> Result<ProviderEffect, ProviderError> {
        let data = serde_json::to_value(&state)
            .map_err(|_| configuration_error("cannot encode Google DNS checkpoint"))?;
        self.saved = Some(state);
        self.stage = next;
        Ok(ProviderEffect::Checkpoint(RecoveryState {
            version: 1,
            data,
        }))
    }

    fn request(&mut self, kind: Request) -> Result<ProviderEffect, ProviderError> {
        let bearer = self
            .token
            .lock()
            .map_err(|_| configuration_error("Google token cache unavailable"))?
            .as_ref()
            .filter(|t| t.expires > Instant::now())
            .map(|t| t.value.to_string());
        let Some(bearer) = bearer else {
            self.stage = Stage::Token(kind);
            return match auth::request(
                &self.config.service_account,
                OffsetDateTime::now_utc().unix_timestamp(),
            ) {
                Ok(request) => Ok(ProviderEffect::Http(request)),
                Err(failure) if matches!(kind, Request::Submit) => self.rejected(failure),
                Err(failure) => Err(failure),
            };
        };
        let mut url = url::Url::parse("https://dns.googleapis.com/dns/v1/projects/")
            .map_err(|_| invalid(false))?;
        {
            let mut path = url.path_segments_mut().map_err(|()| invalid(false))?;
            path.pop_if_empty()
                .push(&self.config.service_account.project_id)
                .push("managedZones");
            match kind {
                Request::Zones => {}
                Request::Rrsets => {
                    path.push(&self.state()?.zone.id).push("rrsets");
                }
                Request::Submit => {
                    path.push(&self.state()?.zone.id).push("changes");
                }
                Request::Poll => {
                    path.push(&self.state()?.zone.id)
                        .push("changes")
                        .push(self.state()?.change_id.as_deref().ok_or_else(not_owned)?);
                }
            }
        }
        if matches!(kind, Request::Zones | Request::Rrsets) {
            let mut query = url.query_pairs_mut();
            query.append_pair("maxResults", "100");
            if !self.page.is_empty() {
                query.append_pair("pageToken", &self.page);
            }
            if matches!(kind, Request::Rrsets) {
                query
                    .append_pair("name", &self.owner()?)
                    .append_pair("type", "TXT");
            }
        }
        let mutation = matches!(kind, Request::Submit);
        let body = if mutation {
            serde_json::to_vec(self.state()?.plan.as_ref().ok_or_else(not_owned)?)
                .map_err(|_| invalid(false))?
        } else {
            Vec::new()
        };
        self.stage = Stage::Http(kind);
        Ok(ProviderEffect::Http(HttpRequest {
            operation: Some(
                match kind {
                    Request::Zones => "ListManagedZones",
                    Request::Rrsets => "ListRrsets",
                    Request::Submit => "CreateChange",
                    Request::Poll => "GetChange",
                }
                .into(),
            ),
            method: if mutation {
                HttpMethod::Post
            } else {
                HttpMethod::Get
            },
            url: url.into(),
            headers: vec![
                ("Authorization".into(), format!("Bearer {bearer}")),
                ("Content-Type".into(), "application/json".into()),
            ],
            body,
            mutation,
        }))
    }

    fn next_page(
        &mut self,
        next: String,
        kind: Request,
    ) -> Result<Option<ProviderEffect>, ProviderError> {
        if next.is_empty() {
            self.page.clear();
            self.pages.clear();
            return Ok(None);
        }
        if next.len() > 4096 || self.pages.len() >= 100 || !self.pages.insert(next.clone()) {
            return Err(invalid(false));
        }
        self.page = next;
        self.request(kind).map(Some)
    }

    fn zones(&mut self, response: &HttpResponse) -> Result<ProviderEffect, ProviderError> {
        let result: Zones = api::decode(response, false)?;
        let owner = self.owner()?;
        for mut zone in result.zones {
            if !safe_id(&zone.id) || self.zones.contains_key(&zone.id) {
                return Err(invalid(false));
            }
            zone.dns_name = absolute_name(&zone.dns_name).map_err(|_| invalid(false))?;
            self.zones.insert(zone.id.clone(), zone);
        }
        if let Some(next) = self.next_page(result.next, Request::Zones)? {
            return Ok(next);
        }
        let mut matching: Vec<_> = self
            .zones
            .values()
            .filter(|z| {
                z.visibility == "public"
                    && (owner == z.dns_name || owner.ends_with(&format!(".{}", z.dns_name)))
            })
            .cloned()
            .collect();
        matching.sort_by_key(|z| std::cmp::Reverse(z.dns_name.len()));
        let zone = matching
            .first()
            .cloned()
            .ok_or_else(|| configuration_error("no public Google DNS zone matches final owner"))?;
        if matching.get(1).is_some_and(|z| z.dns_name == zone.dns_name) {
            return Err(configuration_error("ambiguous Google DNS zones"));
        }
        self.checkpoint(
            Checkpoint {
                zone,
                phase: Phase::Resolved,
                plan: None,
                change_id: None,
                effective_ttl: None,
                retry_at: None,
                cleanup_removed: false,
            },
            Stage::Save(Request::Rrsets),
        )
    }

    fn rrsets(&mut self, response: &HttpResponse) -> Result<ProviderEffect, ProviderError> {
        let result: Rrsets = api::decode(response, false)?;
        for set in result.rrsets {
            set.validate(&self.owner()?)?;
            self.rrsets.push(set);
        }
        if self.rrsets.len() > 1 {
            return Err(invalid(false));
        }
        if let Some(next) = self.next_page(result.next, Request::Rrsets)? {
            return Ok(next);
        }
        let current = self.rrsets.pop();
        let found = current
            .as_ref()
            .map(|set| set.matches(&self.record().value))
            .transpose()?
            .flatten();
        let mut state = self.state()?.clone();
        if state.phase == Phase::PresentIntent {
            if found.is_none() {
                return Err(not_owned());
            }
            state.phase = Phase::Presented;
            state.plan = None;
            state.change_id = None;
            state.effective_ttl = current.as_ref().map(|s| s.ttl);
            self.outcome = Some(ProviderOutcome::Presented(self.receipt(&state)?));
            return self.checkpoint(state, Stage::SaveOutcome);
        }
        if state.phase == Phase::CleanupIntent {
            if found.is_some() {
                return Err(not_owned());
            }
            return self.cleaned(state, CleanupStatus::Removed);
        }
        match &self.action {
            ProviderAction::Present(_) if state.phase == Phase::Presented => {
                if found.is_none() {
                    return Err(not_owned());
                }
                state.effective_ttl = current.as_ref().map(|s| s.ttl);
                self.outcome = Some(ProviderOutcome::Presented(self.receipt(&state)?));
                return self.checkpoint(state, Stage::SaveOutcome);
            }
            ProviderAction::Present(_) if found.is_some() => {
                return Err(error(
                    ProviderErrorCode::RecordConflict,
                    "Google TXT value already exists without this publication's ownership",
                    SideEffect::None,
                ));
            }
            ProviderAction::Cleanup(_) if found.is_none() => {
                return self.cleaned(state, CleanupStatus::AlreadyAbsent);
            }
            _ => {}
        }
        let mut desired = current.clone().unwrap_or(Rrset {
            name: self.owner()?,
            kind: "TXT".into(),
            ttl: self.record().ttl_seconds.unwrap_or(120).min(2_147_483_647),
            rrdatas: BTreeSet::new(),
            extra: serde_json::Map::new(),
        });
        match &self.action {
            ProviderAction::Present(_) => {
                desired.rrdatas.insert(txt_encode(&self.record().value));
                state.phase = Phase::PresentIntent;
            }
            ProviderAction::Cleanup(_) => {
                desired.rrdatas.remove(&found.ok_or_else(not_owned)?);
                state.phase = Phase::CleanupIntent;
            }
        }
        state.plan = Some(Plan {
            deletions: current.into_iter().collect(),
            additions: if desired.rrdatas.is_empty() {
                vec![]
            } else {
                vec![desired]
            },
        });
        state.change_id = None;
        state.retry_at = None;
        self.checkpoint(state, Stage::Save(Request::Submit))
    }

    fn receipt(&self, state: &Checkpoint) -> Result<PublicationReceipt, ProviderError> {
        Ok(PublicationReceipt {
            record_id: identity(&state.zone, &self.owner()?),
            ownership: RecordOwnership::Created,
            record_name: self.record().name.clone(),
            cname_chain: self.record().cname_chain.clone(),
            effective_ttl_seconds: state.effective_ttl,
        })
    }

    fn cleaned(
        &mut self,
        mut state: Checkpoint,
        status: CleanupStatus,
    ) -> Result<ProviderEffect, ProviderError> {
        state.phase = Phase::Cleaned;
        state.cleanup_removed = status == CleanupStatus::Removed;
        state.plan = None;
        state.change_id = None;
        self.outcome = Some(ProviderOutcome::Cleaned(status));
        self.checkpoint(state, Stage::SaveOutcome)
    }

    fn change(
        &mut self,
        response: &HttpResponse,
        submit: bool,
    ) -> Result<ProviderEffect, ProviderError> {
        if response.status != 200 {
            let failure = api::failure(response, submit);
            if submit && failure.side_effect == SideEffect::None {
                return self.rejected(failure);
            }
            return Err(failure);
        }
        let change: Change = api::decode(response, submit)?;
        let mut state = self.state()?.clone();
        if !change.verifies(state.plan.as_ref().ok_or_else(not_owned)?)
            || state.change_id.as_ref().is_some_and(|id| *id != change.id)
        {
            return Err(invalid(submit));
        }
        if submit {
            state.change_id = Some(change.id);
            return self.checkpoint(state, Stage::Save(Request::Poll));
        }
        if change.status == "done" {
            self.request(Request::Rrsets)
        } else {
            self.stage = Stage::Wait;
            Ok(ProviderEffect::WaitUntil(self.poll.next().ok_or_else(
                || {
                    error(
                        ProviderErrorCode::ProviderUnavailable,
                        "Google DNS change remains pending",
                        SideEffect::Unknown,
                    )
                },
            )?))
        }
    }

    fn rejected(&mut self, failure: ProviderError) -> Result<ProviderEffect, ProviderError> {
        let mut state = self.state()?.clone();
        state.phase = if state.phase == Phase::CleanupIntent {
            Phase::Presented
        } else {
            Phase::Resolved
        };
        state.plan = None;
        state.change_id = None;
        if let Some(seconds) = failure.retry_after_seconds {
            state.retry_at = Some(
                OffsetDateTime::now_utc()
                    .unix_timestamp()
                    .saturating_add(i64::try_from(seconds).unwrap_or(i64::MAX)),
            );
        }
        if failure.code == ProviderErrorCode::RecordConflict && self.writes < 4 {
            return self.checkpoint(state, Stage::Save(Request::Rrsets));
        }
        self.failure = Some(failure);
        self.checkpoint(state, Stage::SaveOutcome)
    }

    fn token_response(
        &mut self,
        kind: Request,
        result: Result<HttpResponse, HttpFailure>,
    ) -> Result<ProviderEffect, ProviderError> {
        let token = result.map_err(transport).and_then(|response| {
            if response.status != 200 {
                return Err(api::failure(&response, false));
            }
            auth::token(&response.body)
        });
        let token = match token {
            Ok(token) => token,
            Err(mut failure) if matches!(kind, Request::Submit) => {
                // Only OAuth has run: the DNS mutation is provably not sent.
                failure.side_effect = SideEffect::None;
                return self.rejected(failure);
            }
            Err(failure) => return Err(failure),
        };
        *self
            .token
            .lock()
            .map_err(|_| configuration_error("Google token cache unavailable"))? = Some(token);
        self.request(kind)
    }
}

impl ProviderOperation for Operation {
    fn advance(&mut self, event: ProviderEvent) -> Result<ProviderEffect, ProviderError> {
        match (&self.stage, event) {
            (Stage::Start, ProviderEvent::Start) => {
                let kind = match &self.saved {
                    None => Request::Zones,
                    Some(s) => {
                        if s.phase == Phase::Cleaned {
                            return Ok(ProviderEffect::Complete(ProviderOutcome::Cleaned(
                                if s.cleanup_removed {
                                    CleanupStatus::Removed
                                } else {
                                    CleanupStatus::AlreadyAbsent
                                },
                            )));
                        }
                        if let Some(until) = s
                            .retry_at
                            .filter(|until| *until > OffsetDateTime::now_utc().unix_timestamp())
                        {
                            let mut failure = error(
                                ProviderErrorCode::RateLimited,
                                "Google DNS retry floor has not elapsed",
                                SideEffect::None,
                            );
                            failure.retry_after_seconds =
                                u64::try_from(until - OffsetDateTime::now_utc().unix_timestamp())
                                    .ok();
                            return Err(failure);
                        }
                        if matches!(s.phase, Phase::PresentIntent | Phase::CleanupIntent) {
                            if s.change_id.is_none() {
                                return Err(not_owned());
                            }
                            Request::Poll
                        } else {
                            Request::Rrsets
                        }
                    }
                };
                self.request(kind)
            }
            (Stage::Token(kind), ProviderEvent::Http(result)) => self.token_response(*kind, result),
            (Stage::Save(kind), ProviderEvent::CheckpointSaved) => {
                let kind = *kind;
                if matches!(kind, Request::Submit) {
                    self.writes += 1;
                }
                self.request(kind)
            }
            (Stage::Http(kind), ProviderEvent::Http(result)) => {
                let kind = *kind;
                let response = match result {
                    Ok(response) => response,
                    Err(failure)
                        if matches!(kind, Request::Submit)
                            && failure.side_effect == SideEffect::None =>
                    {
                        return self.rejected(transport(failure));
                    }
                    Err(failure) => return Err(transport(failure)),
                };
                if response.status == 401 {
                    *self
                        .token
                        .lock()
                        .map_err(|_| configuration_error("Google token cache unavailable"))? = None;
                }
                match kind {
                    Request::Zones => self.zones(&response),
                    Request::Rrsets => self.rrsets(&response),
                    Request::Submit => self.change(&response, true),
                    Request::Poll => self.change(&response, false),
                }
            }
            (Stage::Wait, ProviderEvent::Timer) => self.request(Request::Poll),
            (Stage::SaveOutcome, ProviderEvent::CheckpointSaved) => {
                self.stage = Stage::Done;
                if let Some(failure) = self.failure.take() {
                    return Err(failure);
                }
                Ok(ProviderEffect::Complete(
                    self.outcome.take().ok_or_else(|| invalid(false))?,
                ))
            }
            _ => Err(configuration_error(
                "invalid Google DNS state machine event",
            )),
        }
    }
}

fn validate(state: &Checkpoint, record: &DnsRecord, owner: &str) -> Result<(), ProviderError> {
    let zone = absolute_name(&state.zone.dns_name).map_err(|_| not_owned())?;
    if !safe_id(&state.zone.id)
        || state.zone.visibility != "public"
        || (owner != zone && !owner.ends_with(&format!(".{zone}")))
        || state.change_id.as_ref().is_some_and(|id| !safe_id(id))
        || state.effective_ttl.is_some_and(|ttl| ttl > 2_147_483_647)
        || (state.cleanup_removed && state.phase != Phase::Cleaned)
    {
        return Err(not_owned());
    }
    let intent = matches!(state.phase, Phase::PresentIntent | Phase::CleanupIntent);
    if intent != state.plan.is_some() || (!intent && state.change_id.is_some()) {
        return Err(not_owned());
    }
    if let Some(plan) = &state.plan {
        if plan.additions.len() > 1
            || plan.deletions.len() > 1
            || (plan.additions.is_empty() && plan.deletions.is_empty())
        {
            return Err(not_owned());
        }
        for set in plan.additions.iter().chain(&plan.deletions) {
            set.validate(owner)?;
        }
        let before = plan
            .deletions
            .first()
            .map(|s| s.rrdatas.clone())
            .unwrap_or_default();
        let after = plan
            .additions
            .first()
            .map(|s| s.rrdatas.clone())
            .unwrap_or_default();
        let mut expected = before.clone();
        if state.phase == Phase::PresentIntent {
            if plan
                .deletions
                .first()
                .map(|s| s.matches(&record.value))
                .transpose()?
                .flatten()
                .is_some()
            {
                return Err(not_owned());
            }
            expected.insert(txt_encode(&record.value));
        } else {
            let wire = plan
                .deletions
                .first()
                .ok_or_else(not_owned)?
                .matches(&record.value)?
                .ok_or_else(not_owned)?;
            expected.remove(&wire);
        }
        if expected != after {
            return Err(not_owned());
        }
        if let (Some(before), Some(after)) = (plan.deletions.first(), plan.additions.first())
            && (before.ttl != after.ttl || before.extra != after.extra)
        {
            return Err(not_owned());
        }
    }
    Ok(())
}

fn identity(zone: &Zone, owner: &str) -> String {
    format!("{}/{}", zone.id, owner)
}

fn not_owned() -> ProviderError {
    error(
        ProviderErrorCode::RecordNotOwned,
        "Google DNS change ownership or outcome cannot be proved; retained without replay",
        SideEffect::Unknown,
    )
}

fn transport(failure: HttpFailure) -> ProviderError {
    error(
        failure.code,
        "Google DNS HTTP exchange failed",
        failure.side_effect,
    )
}
