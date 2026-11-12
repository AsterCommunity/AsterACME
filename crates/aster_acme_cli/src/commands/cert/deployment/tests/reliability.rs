//! Cross-generation barriers, deployment artifact validation and batch cancellation.
use crate::commands::cert::deployment::tests::{Fixture, child_command};
use crate::commands::cert::deployment::*;

#[tokio::test]
async fn wrong_certificate_is_rejected_and_private_pem_is_derived_from_the_verified_der() {
    let fixture = Fixture::new().await;
    fixture.add("checked", Vec::new(), 0).await;
    let record = fixture
        .store
        .query(IssueQuery {
            name: Some(fixture.name.clone()),
            in_use: Some(true),
            ..IssueQuery::default()
        })
        .await
        .unwrap()
        .remove(0);
    let source = fixture
        .temp
        .path()
        .join("certs/web")
        .join(record.generation_name());
    let expected = std::fs::read(source.join("private-key.pem")).unwrap();
    aster_acme_cli_storage::state_file::StateDirectory::open(&source)
        .unwrap()
        .atomic_write("private-key.pem", b"unrelated key")
        .unwrap();
    let session = fixture
        .store
        .open_deployment(&fixture.name, "checked")
        .await
        .unwrap();
    assert_eq!(session.artifacts().private_key.as_slice(), expected);
    drop(session);
    let der = std::fs::read(source.join("private-key.pk8")).unwrap();
    let matching_key = rcgen::KeyPair::try_from(der.as_slice()).unwrap();
    let other_key = rcgen::KeyPair::generate().unwrap();
    // Isolate SAN and public-key checks: either guard must reject its own
    // mismatch even if the other guard is removed accidentally.
    for (domain, key) in [
        ("other.example.com", &matching_key),
        ("example.com", &other_key),
    ] {
        let wrong = rcgen::CertificateParams::new(vec![domain.into()])
            .unwrap()
            .self_signed(key)
            .unwrap();
        aster_acme_cli_storage::state_file::StateDirectory::open(&source)
            .unwrap()
            .atomic_write("fullchain.pem", wrong.pem().as_bytes())
            .unwrap();
        assert!(
            fixture
                .store
                .open_deployment(&fixture.name, "checked")
                .await
                .is_err(),
            "{domain}"
        );
    }
}

#[tokio::test]
async fn uncertain_reload_survives_configuration_update_and_a_new_generation() {
    for phase in [DeploymentPhase::Reloading, DeploymentPhase::ReloadUncertain] {
        let fixture = Fixture::new().await;
        fixture.add("barrier", child_command("success"), 0).await;
        let mut session = fixture
            .store
            .open_deployment(&fixture.name, "barrier")
            .await
            .unwrap();
        session
            .save_state(phase, 2, Some("unconfirmed command".into()))
            .await
            .unwrap();
        let old = session.definition().clone();
        drop(session);
        let patched = fixture
            .store
            .update_deployment(
                &fixture.name,
                "barrier",
                DeploymentPatch {
                    timeout_seconds: Some(60),
                    ..DeploymentPatch::default()
                },
            )
            .await
            .unwrap();
        assert_eq!(patched.phase, old.phase);
        assert_eq!(patched.generation, old.generation);
        fixture.complete(true).await;
        let automatic = fixture.automatic(&fixture.store).await;
        assert_eq!(automatic[0], patched);
        let explicit = run_one(&fixture.store, &fixture.name, "barrier", true, None, None)
            .await
            .unwrap();
        assert_eq!(explicit.binding.phase, DeploymentPhase::Deployed);
    }
}
