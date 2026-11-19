use crate::provider::common::{
    individual::{
        api::{IndividualApi, RecordMarking, Zone, valid_id},
        lifecycle::{
            Checkpoint, IndividualFactory, MAX_SNAPSHOT, Operation, Phase, Stage,
            invalid_checkpoint, not_owned,
        },
    },
    retry::ReadRetry,
};
use aster_acme_dns::{
    ProviderError, RecordOwnership,
    backend::configuration_error,
    operation::{OperationFactory, ProviderAction, ProviderOperation, RecoveryState},
    routing::absolute_name,
};
use std::{collections::BTreeSet, time::Duration};
impl<A: IndividualApi + 'static> OperationFactory for IndividualFactory<A> {
    fn start(
        &self,
        action: ProviderAction,
        saved: Option<RecoveryState>,
    ) -> Result<Box<dyn ProviderOperation>, ProviderError> {
        let record = match &action {
            ProviderAction::Present(record) => record,
            ProviderAction::Cleanup(request) => &request.record,
        };
        let owner =
            absolute_name(&record.name).map_err(|_| configuration_error("invalid DNS owner"))?;
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
                "invalid publication identity or TXT value",
            ));
        }
        let saved = saved
            .map(|state| {
                if state.version != 1 {
                    return Err(invalid_checkpoint());
                }
                let checkpoint: Checkpoint =
                    serde_json::from_value(state.data).map_err(|_| invalid_checkpoint())?;
                if Zone::new(checkpoint.zone.id.clone(), &checkpoint.zone.name)? != checkpoint.zone
                    || checkpoint.zone.relative(&owner).is_none()
                {
                    return Err(invalid_checkpoint());
                }
                let valid_phase = match &checkpoint.phase {
                    Phase::Preexisting { ids } => {
                        !ids.is_empty()
                            && ids.len() <= MAX_SNAPSHOT
                            && ids.iter().all(|id| valid_id(id))
                    }
                    Phase::Created { id } => A::MARKING == RecordMarking::Inline && valid_id(id),
                    Phase::RemarkIntent { id } | Phase::Marked { id } => {
                        A::MARKING == RecordMarking::AfterCreate && valid_id(id)
                    }
                    Phase::DeleteIntent { id } => valid_id(id),
                    _ => true,
                };
                if !valid_phase {
                    return Err(invalid_checkpoint());
                }
                Ok(checkpoint)
            })
            .transpose()?;
        let phase = saved.as_ref().map(|saved| &saved.phase);
        match &action {
            ProviderAction::Present(_) if matches!(phase, Some(Phase::DeleteIntent { .. })) => {
                return Err(invalid_checkpoint());
            }
            ProviderAction::Cleanup(request) => {
                let receipt = &request.receipt;
                if request.publication_id != record.publication_id
                    || receipt.record_name != record.name
                    || receipt.cname_chain != record.cname_chain
                    || !valid_id(&receipt.record_id)
                {
                    return Err(configuration_error(
                        "DNS cleanup receipt does not match publication",
                    ));
                }
                if receipt.ownership == RecordOwnership::Created
                    && !matches!(phase, Some(Phase::Created { id } | Phase::Marked { id } | Phase::DeleteIntent { id }) if id == &receipt.record_id)
                {
                    return Err(not_owned(false));
                }
            }
            ProviderAction::Present(_) => {}
        }
        let marker = self.0.marker(&record.publication_id);
        self.0.validate_marker(&marker)?;
        Ok(Box::new(Operation {
            api: self.0.clone(),
            action,
            owner,
            marker,
            saved,
            stage: Stage::Start,
            best_zone: None,
            ambiguous_zone: false,
            seen: BTreeSet::new(),
            same_value: BTreeSet::new(),
            marked: None,
            borrowable: None,
            total: None,
            minimum_ttl: 0,
            read_retry: ReadRetry::new(6, Duration::from_secs(5)),
        }))
    }
}
