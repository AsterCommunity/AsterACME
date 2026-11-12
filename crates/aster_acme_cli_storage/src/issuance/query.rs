//! Bounded file query planner: narrow names and generation prefixes before journal reads.
use crate::issuance::{
    CertificateName, IssueError, IssueRecord, ensure_real_dir, failure, managed_file_present,
    read_journal, selection, valid_operation_id,
};
use aster_acme::storage::query::{IssueQuery, IssueView};
use std::{
    collections::HashSet,
    fs,
    path::{Path, PathBuf},
};

pub(super) fn read(root: &Path, query: &IssueQuery) -> Result<Vec<IssueRecord>, IssueError> {
    if query
        .operation_id
        .as_deref()
        .is_some_and(|id| !valid_operation_id(id))
    {
        return Err(failure("invalid issuance operation ID filter"));
    }
    if !root
        .try_exists()
        .map_err(|_| failure("cannot inspect certificate catalog"))?
    {
        return Ok(Vec::new());
    }
    ensure_real_dir(root)?;
    let slots = match &query.name {
        Some(name) => vec![root.join(name.as_str())],
        None => directories(root, 1024)?,
    };
    let mut records = Vec::new();
    let mut scanned = 0;
    for slot in slots {
        records.extend(read_identity(&slot, query, &mut scanned)?);
    }
    records.sort_by(|a, b| {
        b.created_at
            .cmp(&a.created_at)
            .then(a.operation_id.cmp(&b.operation_id))
    });
    if query.view == IssueView::Managed {
        records.sort_by(|a, b| a.name.as_str().cmp(b.name.as_str()));
    }
    Ok(records)
}

fn read_identity(
    slot: &Path,
    query: &IssueQuery,
    scanned: &mut usize,
) -> Result<Vec<IssueRecord>, IssueError> {
    if !managed_file_present(&slot.join("cert.toml"))? {
        return Ok(Vec::new());
    }
    ensure_real_dir(slot)?;
    let config = selection(slot)?;
    let name = CertificateName::new(
        slot.file_name()
            .and_then(|n| n.to_str())
            .ok_or_else(|| failure("invalid certificate directory name"))?,
    )?;
    if config.cert.name != name {
        return Err(failure("certificate catalog name mismatch"));
    }
    if query.in_use == Some(true) && config.cert.in_use.is_none() {
        return Ok(Vec::new());
    }
    let operation = match query.view {
        IssueView::All => query.operation_id.as_deref().or_else(|| {
            if query.in_use == Some(true) {
                config.cert.in_use.as_deref()
            } else {
                None
            }
        }),
        IssueView::Managed | IssueView::CurrentOrUnfinished => config.cert.in_use.as_deref(),
    };
    let mut versions = Vec::new();
    let mut seen = HashSet::new();
    for path in directories(slot, 4096)? {
        if let Some(id) = operation {
            let suffix = &id[..8];
            if !path
                .file_name()
                .and_then(|n| n.to_str())
                .is_some_and(|n| n.ends_with(suffix))
            {
                continue;
            }
        }
        if !managed_file_present(&path.join("operation.toml"))? {
            continue;
        }
        *scanned += 1;
        if *scanned > 4096 {
            return Err(failure("issuance listing exceeds 4096 records"));
        }
        let mut record = read_journal(&path.join("operation.toml"))?;
        if record.name != name
            || path.file_name().and_then(|n| n.to_str()) != Some(record.generation_name().as_str())
        {
            return Err(failure("managed certificate generation identity mismatch"));
        }
        if !seen.insert(record.operation_id.clone()) {
            return Err(failure("duplicate managed operation ID"));
        }
        record.is_in_use = config.cert.in_use.as_deref() == Some(record.operation_id.as_str());
        record.deployment_count = Some(config.cert.deployments.len());
        versions.push(record);
    }
    if let Some(selected) = config.cert.in_use.as_ref()
        && (query.in_use == Some(true) || !matches!(query.view, IssueView::All))
        && !versions
            .iter()
            .any(|record| &record.operation_id == selected)
    {
        return Err(failure("selected certificate generation missing"));
    }
    Ok(query
        .view
        .project(versions)?
        .into_iter()
        .filter(|record| query.matches(record))
        .collect())
}

fn directories(root: &Path, limit: usize) -> Result<Vec<PathBuf>, IssueError> {
    let mut paths = Vec::new();
    for (index, entry) in fs::read_dir(root)
        .map_err(|_| failure("cannot enumerate catalog"))?
        .enumerate()
    {
        if index >= limit {
            return Err(failure("certificate catalog scan limit exceeded"));
        }
        let entry = entry.map_err(|_| failure("invalid catalog entry"))?;
        if entry
            .file_type()
            .map_err(|_| failure("cannot inspect catalog entry"))?
            .is_dir()
        {
            paths.push(entry.path());
        }
    }
    Ok(paths)
}
