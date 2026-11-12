//! Exercise Windows-style complete-copy publication on every test host.
use crate::issuance::publication::*;
use crate::issuance::write_journal;

fn generation(slot: &Path, letter: char) -> IssueRecord {
    let record: IssueRecord = serde_json::from_value(serde_json::json!({
        "key_algorithm":"ecdsa-p256","challenge":"dns-01","solver_config":{},"solver_id":"manual_dns","operation_id":letter.to_string().repeat(43),"name":"example.com",
        "created_at":"2026-01-01T00:00:00Z","account_name":"default","account_id":"id","account_thumbprint":"key",
        "directory":"https://ca.example/directory","account_url":"https://ca.example/account","identifiers":["example.com"],
        "phase":"completed","creation_submitted":true,"authorizations":[],"finalize_submitted":"submitted"
    })).unwrap();
    let path = slot.join(record.generation_name());
    fs::create_dir(&path).unwrap();
    private_dir(&path).unwrap();
    write_journal(&path.join("operation.toml"), &record).unwrap();
    for name in FILES {
        atomic_write(&path.join(name), format!("{letter}:{name}").as_bytes()).unwrap();
    }
    record
}

#[test]
fn empty_unmarked_copy_staging_and_backup_are_recoverable_but_user_content_is_retained() {
    let temp = tempfile::tempdir().unwrap();
    let publication = Publication {
        kind: ViewKind::Copy,
    };
    let record = generation(temp.path(), 'a');
    let stage = temp.path().join(format!(".in_use-{}", record.operation_id));
    fs::create_dir(&stage).unwrap();
    private_dir(&stage).unwrap();
    publication.publish(temp.path(), &record).unwrap();
    let backup = temp.path().join(PREVIOUS);
    fs::create_dir(&backup).unwrap();
    private_dir(&backup).unwrap();
    publication
        .recover(temp.path(), Some(&record.generation_name()))
        .unwrap();
    assert!(!backup.exists());
    fs::create_dir(&backup).unwrap();
    private_dir(&backup).unwrap();
    fs::write(backup.join("user"), b"retain").unwrap();
    assert!(
        publication
            .recover(temp.path(), Some(&record.generation_name()))
            .is_err()
    );
    assert_eq!(fs::read(backup.join("user")).unwrap(), b"retain");
}

#[cfg(unix)]
#[test]
fn link_recovery_restores_actual_catalog_selection_after_uncommitted_promotion() {
    let temp = tempfile::tempdir().unwrap();
    let publication = Publication {
        kind: ViewKind::Link,
    };
    let first = generation(temp.path(), 'a');
    let second = generation(temp.path(), 'b');
    publication.publish(temp.path(), &first).unwrap();
    publication.publish(temp.path(), &second).unwrap();
    publication
        .recover(temp.path(), Some(&first.generation_name()))
        .unwrap();
    assert!(publication.matches(temp.path(), &first).unwrap());
    publication.recover(temp.path(), None).unwrap();
    assert!(!temp.path().join("in_use").exists());
    assert!(temp.path().join(second.generation_name()).is_dir());
}

#[test]
fn copy_publication_switches_complete_sets_and_retains_backup_until_catalog_commit() {
    let temp = tempfile::tempdir().unwrap();
    let publication = Publication {
        kind: ViewKind::Copy,
    };
    let first = generation(temp.path(), 'a');
    let second = generation(temp.path(), 'b');
    publication.publish(temp.path(), &first).unwrap();
    assert!(publication.matches(temp.path(), &first).unwrap());
    publication
        .recover(temp.path(), Some(&first.generation_name()))
        .unwrap();
    publication.publish(temp.path(), &second).unwrap();
    assert!(publication.matches(temp.path(), &second).unwrap());
    assert!(temp.path().join(PREVIOUS).is_dir());
    publication
        .recover(temp.path(), Some(&second.generation_name()))
        .unwrap();
    assert!(!temp.path().join(PREVIOUS).exists());
    for name in FILES {
        assert_eq!(
            fs::read(temp.path().join("in_use").join(name)).unwrap(),
            format!("b:{name}").as_bytes()
        );
    }
    assert!(!temp.path().join("in_use/operation.toml").exists());
    publication.remove(&temp.path().join("in_use")).unwrap();
    assert!(!temp.path().join("in_use").exists());
    assert!(temp.path().join(first.generation_name()).is_dir());
}

#[test]
fn interrupted_copy_swaps_roll_back_to_catalog_selection_at_each_directory_boundary() {
    for missing_active in [false, true] {
        let temp = tempfile::tempdir().unwrap();
        let publication = Publication {
            kind: ViewKind::Copy,
        };
        let first = generation(temp.path(), 'a');
        let second = generation(temp.path(), 'b');
        publication.publish(temp.path(), &first).unwrap();
        if missing_active {
            fs::rename(temp.path().join("in_use"), temp.path().join(PREVIOUS)).unwrap();
        } else {
            publication.publish(temp.path(), &second).unwrap();
        }
        publication
            .recover(temp.path(), Some(&first.generation_name()))
            .unwrap();
        assert!(publication.matches(temp.path(), &first).unwrap());
        assert!(!temp.path().join(PREVIOUS).exists());
    }
    let temp = tempfile::tempdir().unwrap();
    let publication = Publication {
        kind: ViewKind::Copy,
    };
    let first = generation(temp.path(), 'a');
    publication.publish(temp.path(), &first).unwrap();
    publication.recover(temp.path(), None).unwrap();
    assert!(!temp.path().join("in_use").exists());
}

#[test]
fn incomplete_source_or_user_content_never_replaces_the_existing_copy() {
    let temp = tempfile::tempdir().unwrap();
    let publication = Publication {
        kind: ViewKind::Copy,
    };
    let first = generation(temp.path(), 'a');
    let second = generation(temp.path(), 'b');
    publication.publish(temp.path(), &first).unwrap();
    let key = temp
        .path()
        .join(second.generation_name())
        .join("private-key.pem");
    fs::remove_file(&key).unwrap();
    assert!(publication.publish(temp.path(), &second).is_err());
    assert!(publication.matches(temp.path(), &first).unwrap());
    atomic_write(&key, b"b:private-key.pem").unwrap();
    fs::write(temp.path().join("in_use/user.txt"), b"keep").unwrap();
    assert!(publication.publish(temp.path(), &second).is_err());
    assert_eq!(
        fs::read(temp.path().join("in_use/user.txt")).unwrap(),
        b"keep"
    );
    assert!(publication.remove(&temp.path().join("in_use")).is_err());
    assert!(publication.matches(temp.path(), &first).unwrap());
}

#[test]
fn copy_markers_and_actual_artifacts_are_checked_before_trusting_or_removing_views() {
    let temp = tempfile::tempdir().unwrap();
    let publication = Publication {
        kind: ViewKind::Copy,
    };
    let record = generation(temp.path(), 'a');
    publication.publish(temp.path(), &record).unwrap();
    atomic_write(&temp.path().join("in_use/cert.pem"), b"tampered").unwrap();
    assert!(!publication.matches(temp.path(), &record).unwrap());
    atomic_write(&temp.path().join("in_use/.generation"), b"../outside").unwrap();
    assert!(publication.target(&temp.path().join("in_use")).is_err());
    assert!(publication.remove(&temp.path().join("in_use")).is_err());
    assert!(temp.path().join("in_use/private-key.pem").exists());
}
