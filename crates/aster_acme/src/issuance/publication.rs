//! Durable publication plans, provider receipts, and terminal owned-resource cleanup.
use crate::{
    challenge::PublicationLifetime,
    issuance::{AuthorizationRecord, IssueError, IssueRecord, ValidationRequirement},
    solver::{ChallengePublication, ChallengeSolver},
    storage::issuance::IssueSession,
};
use aster_acme_core::workflow::SubmissionState;

pub(super) async fn prepare(
    session: &dyn IssueSession,
    record: &mut IssueRecord,
    solver: &dyn ChallengeSolver,
    execution: &crate::solver::ExecutionContext,
) -> Result<(), IssueError> {
    check_retry(record)?;
    execution.check().map_err(IssueError::from)?;
    let publications = record
        .authorizations
        .iter()
        .filter(|auth| auth.validation_requirement.is_some())
        .map(publication)
        .collect::<Result<Vec<_>, _>>()?;
    let plans = solver.prepare(&publications, execution).await?;
    if plans.is_empty() {
        return Ok(());
    }
    let mut updated = record.clone();
    let mut seen = std::collections::BTreeSet::new();
    for update in plans {
        if !seen.insert(update.publication_id.clone()) {
            return Err(IssueError::InvalidInput("duplicate DNS plan identity"));
        }
        let auth = updated
            .authorizations
            .iter_mut()
            .find(|auth| auth.publication_id.as_ref() == Some(&update.publication_id))
            .ok_or(IssueError::InvalidInput("unknown DNS plan identity"))?;
        let Some(ValidationRequirement::Dns01 { name, value }) = &auth.validation_requirement
        else {
            return Err(IssueError::InvalidInput("DNS route for non-DNS material"));
        };
        if update.plan.publication_id != update.publication_id
            || update.plan.value != *value
            || update.plan.challenge_name.trim_end_matches('.') != name.trim_end_matches('.')
            || (!update.plan.cname_chain.is_empty()
                && (update.plan.cname_chain.first() != Some(&update.plan.challenge_name)
                    || update.plan.cname_chain.last() != Some(&update.plan.name)))
            || auth
                .publication_plan
                .as_ref()
                .is_some_and(|old| old != &update.plan)
        {
            return Err(IssueError::InvalidInput(
                "DNS plan changed saved publication identity",
            ));
        }
        auth.publication_plan = Some(update.plan);
    }
    session.save(&updated).await?;
    *record = updated;
    Ok(())
}

pub(super) fn publication(auth: &AuthorizationRecord) -> Result<ChallengePublication, IssueError> {
    let identifier = crate::identifier::authorization_identifier(
        auth.resource.identifier.clone(),
        auth.resource.wildcard,
    )?;
    Ok(ChallengePublication {
        identifier,
        publication_id: auth
            .publication_id
            .clone()
            .ok_or(IssueError::InvalidInput("missing stable publication ID"))?,
        requirement: auth
            .validation_requirement
            .clone()
            .ok_or(IssueError::InvalidInput("missing validation requirement"))?,
        receipt: auth.publication_receipt.clone(),
        plan: auth.publication_plan.clone(),
    })
}

pub(super) fn outstanding_publications(
    record: &IssueRecord,
    requirements: &[ValidationRequirement],
) -> Result<Vec<ChallengePublication>, IssueError> {
    let mut selected = std::collections::BTreeSet::new();
    requirements
        .iter()
        .map(|requirement| {
            let auth = record
                .authorizations
                .iter()
                .find(|auth| {
                    auth.validation_requirement.as_ref() == Some(requirement)
                        && matches!(auth.acknowledgement, SubmissionState::NotSubmitted)
                        && auth
                            .publication_id
                            .as_ref()
                            .is_some_and(|id| selected.insert(id.clone()))
                })
                .ok_or(IssueError::InvalidInput(
                    "publication requirement has no authorization checkpoint",
                ))?;
            publication(auth)
        })
        .collect()
}

pub(super) fn apply_receipts(
    record: &mut IssueRecord,
    updates: &[crate::solver::PublicationReceiptUpdate],
) -> Result<bool, IssueError> {
    let mut next = record.clone();
    let mut seen = std::collections::BTreeSet::new();
    let mut changed = false;
    for update in updates {
        if !seen.insert(update.publication_id.as_str()) {
            return Err(IssueError::InvalidInput(
                "publication solver returned a duplicate receipt ID",
            ));
        }
        let auth = next
            .authorizations
            .iter_mut()
            .find(|auth| auth.publication_id.as_deref() == Some(update.publication_id.as_str()))
            .ok_or(IssueError::InvalidInput(
                "publication solver returned an unknown receipt ID",
            ))?;
        if auth.publication_plan.is_none()
            || update.receipt.record_id.is_empty()
            || update.receipt.record_id.len() > 1024
            || update.receipt.record_id.chars().any(char::is_control)
            || auth.publication_plan.as_ref().is_some_and(|plan| {
                plan.name != update.receipt.record_name
                    || plan.cname_chain != update.receipt.cname_chain
            })
            || auth.validation_requirement.is_none()
            || auth
                .publication_receipt
                .as_ref()
                .is_some_and(|previous| previous != &update.receipt)
        {
            return Err(IssueError::InvalidInput(
                "publication solver changed a saved provider receipt",
            ));
        }
        if auth.publication_receipt.is_none() {
            auth.publication_receipt = Some(update.receipt.clone());
            changed = true;
        }
    }
    *record = next;
    Ok(changed)
}

/// Retry owned temporary-publication cleanup without ACME requests or signing keys.
/// # Errors
/// Rejects nonterminal CA state, invalid receipts, cancellation and provider failures.
/// Successful per-record cleanup is durably retained even when another record fails.
pub async fn cleanup(
    session: &dyn IssueSession,
    solver: &dyn ChallengeSolver,
    execution: &crate::solver::ExecutionContext,
) -> Result<IssueRecord, IssueError> {
    let mut record = session.record().await?;
    if solver.kind() != record.challenge
        || !record.publication_cleanup_eligible(time::OffsetDateTime::now_utc())
    {
        return Err(IssueError::InvalidInput(
            "cleanup requires a terminal CA outcome and the saved solver",
        ));
    }
    cleanup_saved(session, &mut record, solver, execution).await?;
    Ok(record)
}

pub(super) async fn cleanup_saved(
    session: &dyn IssueSession,
    record: &mut IssueRecord,
    solver: &dyn ChallengeSolver,
    execution: &crate::solver::ExecutionContext,
) -> Result<(), IssueError> {
    execution.check().map_err(IssueError::from)?;
    check_retry(record)?;
    let pending = record
        .authorizations
        .iter()
        .filter(|auth| auth.cleanup_pending)
        .filter(|auth| {
            auth.validation_requirement
                .as_ref()
                .is_some_and(|material| {
                    material.kind().publication_lifetime() == PublicationLifetime::Temporary
                })
        })
        .map(publication)
        .collect::<Result<Vec<_>, _>>()?;
    if pending.is_empty() {
        return Ok(());
    }
    if solver.requires_receipt() {
        let recover = pending
            .iter()
            .filter(|publication| publication.receipt.is_none() && publication.plan.is_some())
            .cloned()
            .collect::<Vec<_>>();
        if !recover.is_empty() {
            let result = solver.ready(&recover, execution).await?;
            if checkpoint(record, &result.receipts, result.retry_at)? {
                session.save(record).await?;
            }
            if let Some(error) = result.failure {
                return Err(error);
            }
            check_retry(record)?;
        }
    }
    let pending = record
        .authorizations
        .iter()
        .filter(|auth| auth.cleanup_pending)
        .filter(|auth| {
            auth.validation_requirement
                .as_ref()
                .is_some_and(|material| {
                    material.kind().publication_lifetime() == PublicationLifetime::Temporary
                })
        })
        .map(publication)
        .collect::<Result<Vec<_>, _>>()?;
    let result = solver.cleanup(&pending, execution).await?;
    if checkpoint(record, &[], result.retry_at)? {
        session.save(record).await?;
    }
    let expected = pending
        .iter()
        .map(|publication| publication.publication_id.as_str())
        .collect::<std::collections::BTreeSet<_>>();
    let completed = result
        .completed
        .iter()
        .map(String::as_str)
        .collect::<std::collections::BTreeSet<_>>();
    if completed.len() != result.completed.len() || !completed.is_subset(&expected) {
        return Err(IssueError::InvalidInput(
            "solver returned unknown or duplicate cleanup identities",
        ));
    }
    if !completed.is_empty() {
        let mut next = record.clone();
        for auth in &mut next.authorizations {
            if auth
                .publication_id
                .as_deref()
                .is_some_and(|id| completed.contains(id))
            {
                auth.cleanup_pending = false;
            }
        }
        session.save(&next).await?;
        *record = next;
    }
    if let Some(error) = result.failure {
        return Err(error);
    }
    Ok(())
}

/// Persist receipt and rate-limit observations before any subsequent provider operation.
pub(super) fn checkpoint(
    record: &mut IssueRecord,
    updates: &[crate::solver::PublicationReceiptUpdate],
    retry_at: Option<time::OffsetDateTime>,
) -> Result<bool, IssueError> {
    let mut changed = apply_receipts(record, updates)?;
    if let Some(retry_at) = retry_at {
        for auth in record
            .authorizations
            .iter_mut()
            .filter(|auth| auth.cleanup_pending)
        {
            if auth
                .publication_retry_at
                .is_none_or(|saved| saved < retry_at)
            {
                auth.publication_retry_at = Some(retry_at);
                changed = true;
            }
        }
    }
    Ok(changed)
}
fn check_retry(record: &IssueRecord) -> Result<(), IssueError> {
    if let Some(retry_at) = record
        .authorizations
        .iter()
        .filter_map(|auth| auth.publication_retry_at)
        .max()
        && retry_at > time::OffsetDateTime::now_utc()
    {
        return Err(IssueError::DnsRetryAt(retry_at));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use crate::{issuance::publication::apply_receipts, solver::PublicationReceiptUpdate};
    use aster_acme_dns::{PublicationReceipt, RecordOwnership};

    fn record() -> crate::issuance::IssueRecord {
        serde_json::from_value(serde_json::json!({
            "operation_id":"a".repeat(43),"name":"web","created_at":"2026-11-12T00:00:00Z",
            "account_name":"default","account_id":"a".repeat(43),
            "directory":"https://ca.example/directory","account_url":"https://ca.example/account/1",
            "account_thumbprint":"a".repeat(43),"key_algorithm":"ecdsa-p256",
            "identifiers":["example.com"],"solver_id":"provider","solver_config":{},
            "challenge":"dns-01","phase":"authorizing","new_order_intent_saved":true,
            "authorizations":[{
                "url":"https://ca.example/auth/1",
                "resource":{"identifier":{"type":"dns","value":"example.com"},"status":"pending","challenges":[]},
                "challenge_url":null,
                "validation_requirement":{"method":"dns-01","name":"_acme-challenge.example.com","value":"expected"},
                "publication_id":"publication-1",
                "publication_plan":{"publication_id":"publication-1","challenge_name":"_acme-challenge.example.com.","cname_chain":["_acme-challenge.example.com.","target.example.net."],"name":"target.example.net.","value":"expected","ttl_seconds":120},
                "publication_receipt":null,"publication_retry_at":null,"cleanup_pending":false,
                "acknowledgement":"not_submitted"
            }],"finalize_submitted":"not_submitted"
        })).unwrap()
    }

    fn update() -> PublicationReceiptUpdate {
        PublicationReceiptUpdate {
            publication_id: "publication-1".into(),
            receipt: PublicationReceipt {
                record_id: "provider-record-1".into(),
                effective_ttl_seconds: Some(120),
                ownership: RecordOwnership::Created,
                record_name: "target.example.net.".into(),
                cname_chain: vec![
                    "_acme-challenge.example.com.".into(),
                    "target.example.net.".into(),
                ],
            },
        }
    }

    #[test]
    fn receipt_checkpoint_accepts_exact_plan_and_is_idempotent() {
        let mut saved = record();
        assert!(apply_receipts(&mut saved, &[update()]).unwrap());
        assert_eq!(
            saved.authorizations[0].publication_receipt,
            Some(update().receipt)
        );
        assert!(!apply_receipts(&mut saved, &[update()]).unwrap());
    }

    #[test]
    fn invalid_receipt_batches_are_atomic_and_reject_boundary_violations() {
        let baseline = record();
        let mut duplicate = update();
        duplicate.receipt.record_id = "second".into();
        let mut unknown = update();
        unknown.publication_id = "unknown".into();
        let mut empty_id = update();
        empty_id.receipt.record_id.clear();
        let mut long_id = update();
        long_id.receipt.record_id = "x".repeat(1025);
        let mut control_id = update();
        control_id.receipt.record_id = "record\n1".into();
        let mut wrong_name = update();
        wrong_name.receipt.record_name = "other.example.net.".into();
        let mut wrong_chain = update();
        wrong_chain.receipt.cname_chain.pop();

        for batch in [
            vec![update(), duplicate],
            vec![unknown],
            vec![empty_id],
            vec![long_id],
            vec![control_id],
            vec![wrong_name],
            vec![wrong_chain],
        ] {
            let mut saved = baseline.clone();
            assert!(apply_receipts(&mut saved, &batch).is_err());
            assert_eq!(saved.authorizations[0].publication_receipt, None);
        }
    }
}
