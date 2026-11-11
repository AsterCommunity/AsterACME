//! Typed CLI JSON contracts, distinct from the CA's wire protocol and local storage schema.
use super::report::AccountReport;
use aster_acme::account::AcmeAccount;
use aster_acme::crypto::key_algorithm::KeyAlgorithm;
use aster_acme_core::account::{AccountRecordState, DeactivationState};
use aster_acme_core::protocol::AccountStatus;
use aster_acme_protocol::url::AcmeUrl;
use serde::Serialize;

#[derive(Serialize)]
#[serde(untagged)]
pub(super) enum Output<'a> {
    KeyRotated {
        key_algorithm: KeyAlgorithm,
        name: &'a str,
        account_url: Option<&'a AcmeUrl>,
        key_thumbprint: &'a str,
        rotated: bool,
    },
    Local(SavedAccount<'a>),
    Remote(Remote<'a>),
    List(List<'a>),
    Deactivated(Deactivated<'a>),
    Removed {
        name: &'a str,
        directory: &'a AcmeUrl,
        removed_locally: bool,
        ca_request_performed: bool,
    },
    Switched {
        default_account: &'a str,
        directory: &'a AcmeUrl,
    },
}

#[derive(Serialize)]
pub(super) struct SavedAccount<'a> {
    key_algorithm: Option<KeyAlgorithm>,
    user_agent: Option<&'a str>,
    key_rotation: Option<&'a aster_acme_core::account::KeyRotation>,
    #[serde(flatten)]
    times: aster_acme::account::AccountTimes,
    name: &'a str,
    ca_query: AccountQuery,
    directory: &'a AcmeUrl,
    key_thumbprint: &'a str,
    account_id: Option<&'a str>,
    account_url: Option<&'a AcmeUrl>,
    local_state: Option<AccountRecordState>,
    status: Option<AccountStatus>,
    last_status: Option<&'a AccountStatus>,
    deactivation: Option<DeactivationState>,
    contacts: &'a [String],
    server_contacts: Option<&'a [String]>,
    accepted_terms_url: Option<&'a AcmeUrl>,
}

#[derive(Serialize)]
struct AccountQuery {
    account_refreshed: bool,
}

#[derive(Serialize)]
struct Identity<'a> {
    key_algorithm: KeyAlgorithm,
    #[serde(flatten)]
    times: aster_acme::account::AccountTimes,
    name: &'a str,
    source: &'static str,
    verified: bool,
    account_id: &'a str,
    directory: &'a AcmeUrl,
    account_url: &'a AcmeUrl,
    status: &'a AccountStatus,
    contacts: &'a [String],
}

impl<'a> Identity<'a> {
    fn new(name: &'a str, account: &'a AcmeAccount, verified: bool) -> Self {
        Self {
            key_algorithm: account.key_algorithm,
            times: account.times,
            name,
            source: if verified { "remote" } else { "local" },
            verified,
            account_id: &account.account_id,
            directory: &account.directory_url,
            account_url: &account.account_url,
            status: &account.status,
            contacts: &account.contacts,
        }
    }
}

#[derive(Serialize)]
pub(super) struct Remote<'a> {
    #[serde(flatten)]
    identity: Identity<'a>,
    action: super::report::RemoteAction,
    recovered: bool,
    reused: bool,
}

#[derive(Serialize)]
pub(super) struct Deactivated<'a> {
    #[serde(flatten)]
    identity: Identity<'a>,
    deactivated: bool,
}

#[derive(Serialize)]
pub(super) struct List<'a> {
    ca_query: AccountListQuery,
    default_account: &'a str,
    verification: Option<&'a [super::report::AccountVerification]>,
    accounts: Vec<ListEntry<'a>>,
}

/// Counts describe successful resource refreshes without marking local fields remote.
#[derive(Serialize)]
struct AccountListQuery {
    requested: bool,
    refreshed: usize,
    failed: usize,
}

impl AccountListQuery {
    fn from_results(results: Option<&[super::report::AccountVerification]>) -> Self {
        let (refreshed, failed) =
            results
                .unwrap_or_default()
                .iter()
                .fold((0, 0), |(ok, failed), result| {
                    match (&result.status, &result.error) {
                        (Some(_), None) => (ok + 1, failed),
                        (_, Some(_)) | (None, None) => (ok, failed + 1),
                    }
                });
        Self {
            requested: results.is_some(),
            refreshed,
            failed,
        }
    }
}

#[derive(Serialize)]
struct ListEntry<'a> {
    key_algorithm: KeyAlgorithm,
    key_rotation: Option<&'a aster_acme_core::account::KeyRotation>,
    #[serde(flatten)]
    times: aster_acme::account::AccountTimes,
    name: &'a str,
    directory: &'a AcmeUrl,
    local_state: AccountRecordState,
    last_status: Option<&'a AccountStatus>,
    deactivation: DeactivationState,
    usable_locally: bool,
    is_default: bool,
}

impl<'a> From<&'a AccountReport> for Output<'a> {
    fn from(report: &'a AccountReport) -> Self {
        match report {
            AccountReport::KeyRotated { name, record } => Self::KeyRotated {
                key_algorithm: record.key_algorithm,
                name,
                account_url: record.account_url.as_ref(),
                key_thumbprint: &record.key_thumbprint,
                rotated: true,
            },
            AccountReport::Removed { name, directory } => Self::Removed {
                name,
                directory,
                removed_locally: true,
                ca_request_performed: false,
            },
            AccountReport::Local(local) => {
                let record = local.record.as_ref();
                Self::Local(SavedAccount {
                    key_algorithm: record.map(|record| record.key_algorithm),
                    user_agent: record.and_then(|record| record.user_agent.as_deref()),
                    key_rotation: record.and_then(|record| record.key_rotation.as_ref()),
                    times: record
                        .map_or_else(aster_acme::account::AccountTimes::default, |record| {
                            record.times
                        }),
                    name: &local.name,
                    ca_query: AccountQuery {
                        account_refreshed: local.verified,
                    },
                    directory: &local.directory,
                    key_thumbprint: &local.key_thumbprint,
                    account_id: record.map(|record| record.account_id.as_str()),
                    account_url: record.and_then(|record| record.account_url.as_ref()),
                    local_state: record.map(|record| record.state),
                    status: if local.verified {
                        record.and_then(|record| record.last_status.clone())
                    } else {
                        None
                    },
                    last_status: record.and_then(|record| record.last_status.as_ref()),
                    deactivation: record.map(|record| record.deactivation),
                    contacts: record.map_or(&[], |record| record.contacts.as_slice()),
                    server_contacts: record.and_then(|record| record.server_contacts.as_deref()),
                    accepted_terms_url: record
                        .and_then(|record| record.accepted_terms_url.as_ref()),
                })
            }
            AccountReport::Remote {
                action,
                name,
                account,
                reused,
            } => Self::Remote(Remote {
                action: *action,
                identity: Identity::new(name, account, true),
                recovered: account.recovered,
                reused: *reused,
            }),
            AccountReport::Deactivated {
                name,
                account,
                verified,
            } => Self::Deactivated(Deactivated {
                identity: Identity::new(name, account, *verified),
                deactivated: true,
            }),
            AccountReport::Switched { name, directory } => Self::Switched {
                default_account: name,
                directory,
            },
            AccountReport::List {
                accounts,
                default,
                verification,
            } => Self::List(List {
                ca_query: AccountListQuery::from_results(verification.as_deref()),
                default_account: default,
                verification: verification.as_deref(),
                accounts: accounts
                    .iter()
                    .map(|account| ListEntry {
                        key_algorithm: account.key_algorithm,
                        key_rotation: account.key_rotation.as_ref(),
                        times: account.times,
                        name: &account.name,
                        directory: &account.directory,
                        local_state: account.state,
                        last_status: account.last_status.as_ref(),
                        deactivation: account.deactivation,
                        usable_locally: account.usable,
                        is_default: account.name == *default,
                    })
                    .collect(),
            }),
        }
    }
}
