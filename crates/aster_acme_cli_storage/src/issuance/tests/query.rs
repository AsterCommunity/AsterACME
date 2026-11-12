//! Storage predicates, projection order and bounded path pruning.
use crate::issuance::tests::{completed_generation, fixture, request};
use aster_acme::storage::{
    issuance::IssueStore,
    query::{IssueQuery, IssueView},
};
use aster_acme_core::{revocation::RevocationState, workflow::IssuancePhase};

#[tokio::test]
async fn query_predicates_are_conjunctive_and_projection_preserves_current_selection() {
    let f = fixture().await;
    let old = completed_generation(&f).await;
    let current = completed_generation(&f).await;
    let session = f.store.renew(&current.name, &f.account).await.unwrap();
    let pending = session.record().await.unwrap();
    drop(session);
    let all = f.store.query(IssueQuery::default()).await.unwrap();
    assert_eq!(all.len(), 3);
    for (query, ids) in [
        (
            IssueQuery {
                in_use: Some(true),
                ..IssueQuery::default()
            },
            vec![current.operation_id.clone()],
        ),
        (
            IssueQuery {
                unfinished: Some(true),
                ..IssueQuery::default()
            },
            vec![pending.operation_id.clone()],
        ),
        (
            IssueQuery {
                view: IssueView::Managed,
                ..IssueQuery::default()
            },
            vec![current.operation_id.clone()],
        ),
        (
            IssueQuery {
                view: IssueView::CurrentOrUnfinished,
                ..IssueQuery::default()
            },
            vec![current.operation_id.clone()],
        ),
        (
            IssueQuery {
                in_use: Some(false),
                phase: Some(IssuancePhase::Completed),
                ..IssueQuery::default()
            },
            vec![old.operation_id.clone()],
        ),
        (
            IssueQuery {
                in_use: Some(true),
                unfinished: Some(true),
                ..IssueQuery::default()
            },
            Vec::new(),
        ),
        (
            IssueQuery {
                view: IssueView::Managed,
                unfinished: Some(true),
                ..IssueQuery::default()
            },
            Vec::new(),
        ),
        (
            IssueQuery {
                view: IssueView::Managed,
                operation_id: Some(old.operation_id.clone()),
                ..IssueQuery::default()
            },
            Vec::new(),
        ),
        (
            IssueQuery {
                revocation: Some(RevocationState::Confirmed),
                ..IssueQuery::default()
            },
            Vec::new(),
        ),
    ] {
        let actual = f
            .store
            .query(query)
            .await
            .unwrap()
            .into_iter()
            .map(|r| r.operation_id)
            .collect::<Vec<_>>();
        assert_eq!(actual, ids);
    }
}

#[tokio::test]
async fn narrow_queries_never_parse_unrelated_certificates_or_history() {
    let f = fixture().await;
    let old = completed_generation(&f).await;
    let current = completed_generation(&f).await;
    let mut other = request();
    other.name = aster_acme::issuance::CertificateName::new("unrelated").unwrap();
    let session = f.store.create(&other, &f.account).await.unwrap();
    drop(session);
    std::fs::write(f.temp.path().join("certs/unrelated/cert.toml"), "corrupt").unwrap();
    let scoped = IssueQuery {
        name: Some(current.name.clone()),
        in_use: Some(true),
        ..IssueQuery::default()
    };
    assert_eq!(
        f.store.query(scoped.clone()).await.unwrap()[0].operation_id,
        current.operation_id
    );
    std::fs::write(
        f.temp
            .path()
            .join("certs")
            .join(old.name.as_str())
            .join(old.generation_name())
            .join("operation.toml"),
        "corrupt",
    )
    .unwrap();
    assert_eq!(
        f.store.query(scoped).await.unwrap()[0].operation_id,
        current.operation_id
    );
    for view in [IssueView::Managed, IssueView::CurrentOrUnfinished] {
        assert_eq!(
            f.store
                .query(IssueQuery {
                    name: Some(current.name.clone()),
                    view,
                    ..IssueQuery::default()
                })
                .await
                .unwrap()[0]
                .operation_id,
            current.operation_id
        );
    }

    assert_eq!(
        f.store
            .query(IssueQuery {
                name: Some(current.name.clone()),
                operation_id: Some(current.operation_id.clone()),
                ..IssueQuery::default()
            })
            .await
            .unwrap()
            .len(),
        1
    );
    assert!(
        f.store
            .query(IssueQuery {
                name: Some(current.name),
                ..IssueQuery::default()
            })
            .await
            .is_err()
    );
    assert!(f.store.query(IssueQuery::default()).await.is_err());
}

#[tokio::test]
async fn resume_queries_exclude_terminal_observations_but_leave_them_inspectable() {
    let f = fixture().await;
    let session = f.store.create(&request(), &f.account).await.unwrap();
    let mut saved = session.record().await.unwrap();
    saved.creation_failure = Some(aster_acme::issuance::RequestFailure {
        status: 400,
        retry_at: None,
        problem: None,
    });
    session.save(&saved).await.unwrap();
    drop(session);
    assert_eq!(
        f.store
            .query(IssueQuery {
                resumable: Some(true),
                ..IssueQuery::default()
            })
            .await
            .unwrap()
            .len(),
        0
    );
    assert_eq!(
        f.store
            .query(IssueQuery {
                resumable: Some(false),
                ..IssueQuery::default()
            })
            .await
            .unwrap()
            .len(),
        1
    );
    assert_eq!(
        f.store
            .query(IssueQuery {
                view: IssueView::Managed,
                ..IssueQuery::default()
            })
            .await
            .unwrap()
            .len(),
        1
    );
}

#[test]
fn random_operation_ids_keep_the_existing_portable_format_without_key_generation() {
    let mut seen = std::collections::HashSet::new();
    for _ in 0..256 {
        let id = crate::issuance::new_operation_id().unwrap();
        assert!(crate::issuance::valid_operation_id(&id));
        assert!(seen.insert(id));
    }
}

#[tokio::test]
async fn invalid_or_missing_operation_filters_never_select_a_different_request() {
    let f = fixture().await;
    completed_generation(&f).await;
    assert!(
        f.store
            .query(IssueQuery {
                operation_id: Some("../escape".into()),
                ..IssueQuery::default()
            })
            .await
            .is_err()
    );
    assert_eq!(
        f.store
            .query(IssueQuery {
                operation_id: Some("z".repeat(43)),
                ..IssueQuery::default()
            })
            .await
            .unwrap()
            .len(),
        0
    );
}

#[tokio::test]
async fn missing_catalog_selection_is_inconsistent_instead_of_an_empty_managed_view() {
    let f = fixture().await;
    completed_generation(&f).await;
    let current = completed_generation(&f).await;
    std::fs::remove_file(
        f.temp
            .path()
            .join("certs")
            .join(current.name.as_str())
            .join(current.generation_name())
            .join("operation.toml"),
    )
    .unwrap();
    assert!(
        f.store
            .query(IssueQuery {
                view: IssueView::Managed,
                ..IssueQuery::default()
            })
            .await
            .is_err()
    );
}
