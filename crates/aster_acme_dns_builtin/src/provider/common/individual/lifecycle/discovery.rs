//! Zone discovery and complete pagination before publication.
use crate::provider::common::{
    individual::{
        api::{IndividualApi, PAGE_SIZE, Page},
        lifecycle::{Checkpoint, MAX_PAGES, Operation, Phase, Stage},
    },
    rpc::{error, invalid},
};
use aster_acme_dns::{
    ProviderError, ProviderErrorCode, SideEffect,
    operation::{HttpResponse, ProviderEffect},
};
impl<A: IndividualApi> Operation<A> {
    pub(super) fn discover(&mut self, page: u32) -> Result<ProviderEffect, ProviderError> {
        let request = self.api.discover(page)?;
        Ok(self.http(request, Stage::Zones(page)))
    }

    pub(super) fn discovered(
        &mut self,
        response: HttpResponse,
        page: u32,
    ) -> Result<ProviderEffect, ProviderError> {
        let Page { entries, total } = self.api.zones(response, page)?;
        let more = self.has_more(page, entries.len(), total)?;
        for zone in entries {
            if !self.seen.insert(zone.id.clone()) {
                return Err(invalid(false));
            }
            if zone.relative(&self.owner).is_none() {
                continue;
            }
            let size = zone.name.len();
            match self
                .best_zone
                .as_ref()
                .map(|best| size.cmp(&best.name.len()))
            {
                None | Some(std::cmp::Ordering::Greater) => {
                    self.best_zone = Some(zone);
                    self.ambiguous_zone = false;
                }
                Some(std::cmp::Ordering::Equal) => self.ambiguous_zone = true,
                Some(std::cmp::Ordering::Less) => {}
            }
        }
        if more {
            return self.discover(page + 1);
        }
        if self.ambiguous_zone {
            return Err(error(
                ProviderErrorCode::ZoneAmbiguous,
                "multiple DNS zones match the publication target",
                SideEffect::None,
            ));
        }
        let zone = self.best_zone.take().ok_or_else(|| {
            error(
                ProviderErrorCode::ZoneNotFound,
                "no DNS zone contains the publication target",
                SideEffect::None,
            )
        })?;
        self.seen.clear();
        self.total = None;
        self.save(
            Checkpoint {
                zone,
                phase: Phase::Resolved,
            },
            Stage::Start,
        )
    }

    pub(super) fn has_more(
        &mut self,
        page: u32,
        len: usize,
        total: u32,
    ) -> Result<bool, ProviderError> {
        let offset = (page - 1) * PAGE_SIZE;
        let expected = total.saturating_sub(offset).min(PAGE_SIZE);
        if total > MAX_PAGES * PAGE_SIZE
            || self.total.is_some_and(|previous| previous != total)
            || usize::try_from(expected).ok() != Some(len)
        {
            return Err(invalid(false));
        }
        self.total = Some(total);
        Ok(total > offset + PAGE_SIZE)
    }
}
