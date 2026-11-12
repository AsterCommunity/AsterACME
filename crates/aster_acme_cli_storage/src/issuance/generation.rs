//! Managed-definition creation, scheduled renewal and restart-safe generation preparation.
use crate::account::StorageError;
use crate::issuance::{
    AccountRecord, Arc, CertificateConfig, CertificateName, CertificateSelection, CliIssueStore,
    IssuancePhase, IssueError, IssueRecord, IssueRequest, RenewalPreparation, Session,
    SubmissionState, atomic_write, certificate, check_material, failure, fs, material_digest,
    new_operation_id, private_dir, read_generations, selection, write_journal, write_selection,
};
use crate::issuance::{publication, removal};
use crate::toml_file::{ensure_real_dir, read_private};
use std::path::Path;

impl CliIssueStore {
    pub(super) async fn initialize(
        &self,
        input: Initialization,
        account: &AccountRecord,
    ) -> Result<RenewalPreparation, IssueError> {
        match &input {
            Initialization::New(request) => validate_request(request, account)?,
            Initialization::Renewal(_) | Initialization::Scheduled { .. }
                if !account.is_usable() =>
            {
                return Err(failure("renewal requires an active account"));
            }
            Initialization::Renewal(_) | Initialization::Scheduled { .. } => {}
        }
        let name = match &input {
            Initialization::New(request) => &request.name,
            Initialization::Renewal(name) | Initialization::Scheduled { name, .. } => name,
        };
        let lease = self.lease(name).await?;
        let slot = self.slot(name);
        let account = account.clone();
        tokio::task::spawn_blocking(move || {
            if let Initialization::Scheduled {
                expected_in_use,
                immediate,
                ..
            } = &input
                && let Some(in_use) = check_renewal_schedule(&slot, expected_in_use, *immediate)?
            {
                return Ok(RenewalPreparation::NotDue(Box::new(in_use)));
            }
            let renewal_of = prepare_initialization(&slot, &input)?;
            let request = initialize_definition(&slot, input, &account)?;
            let generations = read_generations(&slot, &request.name)?;
            if let Some(record) = existing_renewal(&generations, renewal_of.as_ref())? {
                let generation = slot.join(record.generation_name());
                check_material(&generation, &record)?;
                return Ok(RenewalPreparation::Ready(Box::new(Session {
                    slot,
                    generation,
                    lease,
                    initial: record,
                    io: Arc::new(tokio::sync::Mutex::new(())),
                })));
            }
            if generations.len() >= 1024 {
                return Err(failure("certificate generation limit reached"));
            }
            let operation_id = new_operation_id()?;
            let material = certificate::generate(&request.identifiers, request.key_algorithm)?;
            let record = IssueRecord {
                is_in_use: false,
                deployment_count: None,
                renewal_of,
                solver_id: request.solver_id.clone(),
                challenge: request.challenge,
                solver_config: request.solver_config.clone(),
                operation_id,
                name: request.name,
                created_at: time::OffsetDateTime::now_utc(),
                account_name: request.account_name,
                account_id: account.account_id,
                directory: account.directory_url,
                account_url: account
                    .account_url
                    .ok_or_else(|| failure("missing account URL"))?,
                account_thumbprint: account.key_thumbprint,
                key_algorithm: request.key_algorithm,
                identifiers: request.identifiers,
                phase: IssuancePhase::CreatingOrder,
                creation_submitted: false,
                creation_failure: None,
                submitted_replaces: None,
                order_url: None,
                order: None,
                authorizations: Vec::new(),
                finalize_submitted: SubmissionState::NotSubmitted,
                finalize_rejection: None,
                next_poll_at: None,
                poll_wait_source: None,
                certificate_not_after: None,
                renewal: None,
                revocation: aster_acme::revocation::RevocationRecord::default(),
            };
            let generation = slot.join(record.generation_name());
            fs::create_dir(&generation)
                .map_err(|_| failure("cannot create unique issuance generation"))?;
            private_dir(&generation)?;
            // Make the generation visible before writing private material. An interrupted
            // initialization is listed and fails closed on resume, never generates a new key.
            write_journal(&generation.join("operation.toml"), &record)?;
            write_material(&generation, &material)?;
            write_journal(&generation.join("operation.toml"), &record)?;
            Ok(RenewalPreparation::Ready(Box::new(Session {
                slot,
                generation,
                lease,
                initial: record,
                io: Arc::new(tokio::sync::Mutex::new(())),
            })))
        })
        .await
        .map_err(|_| failure("issuance initialization worker failed"))?
    }
}

pub(super) fn check_renewal_schedule(
    slot: &Path,
    expected_in_use: &str,
    immediate: bool,
) -> Result<Option<IssueRecord>, IssueError> {
    use aster_acme_core::renewal::{RenewalDecision, renewal_decision};
    removal::ensure_idle(slot)?;
    let config = selection(slot)?;
    if config.cert.in_use.as_deref() != Some(expected_in_use) {
        return Err(failure(
            "in_use changed while selecting renewal; inspect cert show before retrying",
        ));
    }
    let records = read_generations(slot, &config.cert.name)?;
    let mut in_use = records
        .iter()
        .find(|record| record.operation_id == expected_in_use)
        .cloned()
        .ok_or_else(|| failure("in_use certificate is missing"))?;
    if in_use.unfinished() || !publication::NATIVE.matches(slot, &in_use)? {
        return Err(failure(
            "in_use certificate selection is inconsistent; refusing renewal",
        ));
    }
    in_use.is_in_use = true;
    let pending = records.iter().any(|record| {
        record.unfinished()
            && record
                .renewal_of
                .as_ref()
                .is_some_and(|previous| previous.operation_id == expected_in_use)
    });
    let due = in_use
        .renewal
        .as_ref()
        .map(|plan| plan.renew_at)
        .ok_or_else(|| failure("in_use certificate has no renewal plan"))?;
    match renewal_decision(
        pending,
        in_use.revocation.state,
        due.unix_timestamp(),
        time::OffsetDateTime::now_utc().unix_timestamp(),
        immediate,
    ) {
        RenewalDecision::NotDue => Ok(Some(in_use)),
        RenewalDecision::Start | RenewalDecision::Resume => Ok(None),
        RenewalDecision::RevocationUncertain => Err(failure(
            "certificate revocation is unconfirmed; resolve it before renewing",
        )),
    }
}

// Validate the live selection under the object lease before key generation.
fn prepare_initialization(
    slot: &Path,
    input: &Initialization,
) -> Result<Option<aster_acme::issuance::RenewalPredecessor>, IssueError> {
    match input {
        Initialization::New(_) => {
            fs::create_dir_all(slot).map_err(|_| failure("cannot create certificate directory"))?;
        }
        Initialization::Renewal(_) | Initialization::Scheduled { .. } => {}
    }
    ensure_real_dir(slot)?;
    private_dir(slot)?;
    removal::ensure_idle(slot)?;
    let renewal_of = match input {
        Initialization::New(_) => None,
        Initialization::Renewal(_) | Initialization::Scheduled { .. } => predecessor(slot)?,
    };
    Ok(renewal_of)
}

// Persist the immutable key/CSR pair and digest together while the caller holds
// the certificate lease; a partially written set remains non-resumable.
fn write_material(
    generation: &Path,
    material: &certificate::CertificateMaterial,
) -> Result<(), IssueError> {
    atomic_write(&generation.join("private-key.pk8"), &material.key)
        .map_err(|_| failure("cannot persist certificate key"))?;
    atomic_write(&generation.join("request.der"), &material.csr)
        .map_err(|_| failure("cannot persist fixed CSR"))?;
    atomic_write(
        &generation.join("material.sha256"),
        material_digest(&material.key, &material.csr).as_bytes(),
    )
    .map_err(|_| failure("cannot persist key/CSR manifest"))?;
    Ok(())
}

fn existing_renewal(
    generations: &[IssueRecord],
    previous: Option<&aster_acme::issuance::RenewalPredecessor>,
) -> Result<Option<IssueRecord>, IssueError> {
    let Some(previous) = previous else {
        return Ok(None);
    };
    let mut pending = generations
        .iter()
        .filter(|record| record.unfinished() && record.renewal_of.as_ref() == Some(previous));
    let first = pending.next();
    if pending.next().is_some() {
        return Err(failure(
            "several unfinished renewals match in_use; select an exact operation",
        ));
    }
    Ok(first.cloned())
}

fn predecessor(
    slot: &Path,
) -> Result<Option<aster_acme::issuance::RenewalPredecessor>, IssueError> {
    let config = selection(slot)?;
    let Some(in_use) = config.cert.in_use else {
        return Ok(None);
    };
    let record = read_generations(slot, &config.cert.name)?
        .into_iter()
        .find(|record| record.operation_id == in_use)
        .ok_or_else(|| failure("in_use generation is missing"))?;
    let chain = read_private(
        &slot.join(record.generation_name()).join("fullchain.pem"),
        1024 * 1024,
    )
    .map_err(|_| failure("in_use certificate is missing or unsafe"))?;
    let plan = aster_acme::renewal::RenewalPlan::from_certificate(&chain)?;
    Ok(Some(aster_acme::issuance::RenewalPredecessor {
        operation_id: in_use,
        certificate_id: plan.certificate_id,
    }))
}

pub(super) enum Initialization {
    New(IssueRequest),
    Renewal(CertificateName),
    Scheduled {
        name: CertificateName,
        expected_in_use: String,
        immediate: bool,
    },
}

fn validate_request(request: &IssueRequest, account: &AccountRecord) -> Result<(), IssueError> {
    request.validate()?;
    if !account.is_usable() {
        return Err(failure("issuance requires an active account"));
    }
    Ok(())
}

// The certificate lease covers definition lookup, name claiming and generation writes.
fn initialize_definition(
    slot: &Path,
    input: Initialization,
    account: &AccountRecord,
) -> Result<IssueRequest, IssueError> {
    match input {
        Initialization::New(request) => {
            match read_private(&slot.join("cert.toml"), 64 * 1024) {
                Ok(_) => {
                    selection(slot)?;
                    return Err(IssueError::NameAlreadyExists(request.name));
                }
                Err(StorageError::NotFound) => {}
                Err(_) => return Err(failure("unsafe certificate configuration")),
            }
            if !read_generations(slot, &request.name)?.is_empty() {
                return Err(IssueError::NameAlreadyExists(request.name));
            }
            write_selection(
                slot,
                &CertificateConfig {
                    version: 1,
                    cert: CertificateSelection {
                        name: request.name.clone(),
                        identifiers: request.identifiers.clone(),
                        key_algorithm: request.key_algorithm,
                        account_name: request.account_name.clone(),
                        account_id: account.account_id.clone(),
                        directory: account.directory_url.clone(),
                        solver_id: request.solver_id.clone(),
                        challenge: request.challenge,
                        solver_config: request.solver_config.clone(),
                        in_use: None,
                        deployments: Vec::new(),
                    },
                },
            )?;
            Ok(request)
        }
        Initialization::Renewal(name) | Initialization::Scheduled { name, .. } => {
            let config = selection(slot)?;
            if config.cert.name != name
                || config.cert.account_id != account.account_id
                || config.cert.directory != account.directory_url
            {
                return Err(failure(
                    "renewal definition does not match the selected account",
                ));
            }
            if read_generations(slot, &name)?
                .iter()
                .any(|record| !config.cert.matches_record(record))
            {
                return Err(failure(
                    "saved generations do not match the managed certificate definition",
                ));
            }
            let request = IssueRequest {
                challenge: config.cert.challenge,
                solver_id: config.cert.solver_id,
                solver_config: config.cert.solver_config,
                name,
                identifiers: config.cert.identifiers,
                key_algorithm: config.cert.key_algorithm,
                account_name: config.cert.account_name,
            };
            validate_request(&request, account)?;
            Ok(request)
        }
    }
}
