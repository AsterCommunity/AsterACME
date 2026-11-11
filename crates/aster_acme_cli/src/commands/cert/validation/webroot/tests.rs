//! Real filesystem ownership checks, with no public HTTP or CA request.
use super::*;
const OP: &str = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
const TOKEN: &str = "abcdefghijklmnopqrstuvwxyz012345";
fn requirement() -> ValidationRequirement {
    ValidationRequirement::Http01 {
        url: format!("http://example.com/.well-known/acme-challenge/{TOKEN}"),
        path: format!("/.well-known/acme-challenge/{TOKEN}"),
        content: format!("{TOKEN}.account-thumbprint"),
    }
}

#[test]
fn publish_reconcile_and_cleanup_use_exact_bytes_and_durable_identity() {
    let temp = tempfile::tempdir().unwrap();
    let requirement = requirement();
    publish(temp.path(), OP, &requirement).unwrap();
    let (target, receipt, content) = paths(temp.path(), OP, &requirement, false).unwrap();
    assert_eq!(fs::read(&target).unwrap(), content.as_bytes());
    assert!(receipt.is_file());
    assert!(
        state_file::same_file(
            &File::open(&target).unwrap(),
            &File::open(&receipt).unwrap()
        )
        .unwrap()
    );
    publish(temp.path(), OP, &requirement).unwrap();
    remove_owned(temp.path(), OP, &requirement).unwrap();
    assert!(!target.exists() && !receipt.exists());
    remove_owned(temp.path(), OP, &requirement).unwrap();
    assert!(target.parent().unwrap().is_dir());
}

#[test]
fn identical_preexisting_files_are_borrowed_and_conflicts_are_not_overwritten() {
    for identical in [false, true] {
        let temp = tempfile::tempdir().unwrap();
        let requirement = requirement();
        let (target, receipt, content) = paths(temp.path(), OP, &requirement, true).unwrap();
        let original = if identical {
            content.as_bytes()
        } else {
            b"user data"
        };
        fs::write(&target, original).unwrap();
        let outcome = publish(temp.path(), OP, &requirement);
        assert_eq!(outcome.is_ok(), identical);
        if identical {
            assert!(!receipt.exists());
            remove_owned(temp.path(), OP, &requirement).unwrap();
        }
        assert_eq!(fs::read(&target).unwrap(), original);
    }
}

#[test]
fn cleanup_never_deletes_changed_or_replaced_files() {
    for replace in [false, true] {
        let temp = tempfile::tempdir().unwrap();
        let requirement = requirement();
        publish(temp.path(), OP, &requirement).unwrap();
        let (target, receipt, content) = paths(temp.path(), OP, &requirement, false).unwrap();
        if replace {
            fs::remove_file(&target).unwrap();
            fs::write(&target, content.as_bytes()).unwrap();
            remove_owned(temp.path(), OP, &requirement).unwrap();
            assert!(!receipt.exists());
        } else {
            fs::write(&target, b"user modified").unwrap();
            assert!(remove_owned(temp.path(), OP, &requirement).is_err());
        }
        assert!(target.is_file());
    }
}

#[test]
fn restart_after_intent_before_final_link_reuses_the_same_publication_identity() {
    let temp = tempfile::tempdir().unwrap();
    let requirement = requirement();
    let (target, receipt, content) = paths(temp.path(), OP, &requirement, true).unwrap();
    fs::write(&receipt, content.as_bytes()).unwrap();
    publish(temp.path(), OP, &requirement).unwrap();
    assert!(
        state_file::same_file(&File::open(target).unwrap(), &File::open(receipt).unwrap()).unwrap()
    );
}

#[test]
fn invalid_paths_wrong_methods_changed_receipts_and_nonregular_files_are_rejected() {
    let temp = tempfile::tempdir().unwrap();
    for path in [
        "../../key",
        "/.well-known/acme-challenge/../../key",
        "/.well-known/acme-challenge/",
    ] {
        let mut bad = requirement();
        if let ValidationRequirement::Http01 { path: stored, .. } = &mut bad {
            *stored = path.into();
        }
        assert!(publish(temp.path(), OP, &bad).is_err());
    }
    assert!(publish(temp.path(), "../bad", &requirement()).is_err());
    assert!(
        publish(
            temp.path(),
            OP,
            &ValidationRequirement::Dns01 {
                name: "example.com".into(),
                value: "value".into()
            }
        )
        .is_err()
    );
    let requirement = requirement();
    let (_, receipt, _) = paths(temp.path(), OP, &requirement, true).unwrap();
    fs::write(&receipt, b"incomplete or changed").unwrap();
    assert!(publish(temp.path(), OP, &requirement).is_err());
    assert_eq!(fs::read(&receipt).unwrap(), b"incomplete or changed");
}

#[cfg(unix)]
#[test]
fn symlinked_challenge_directories_and_files_are_not_followed() {
    use std::os::unix::fs::symlink;
    let temp = tempfile::tempdir().unwrap();
    let outside = tempfile::tempdir().unwrap();
    symlink(outside.path(), temp.path().join(".well-known")).unwrap();
    assert!(publish(temp.path(), OP, &requirement()).is_err());
    assert_eq!(fs::read_dir(outside.path()).unwrap().count(), 0);
    fs::remove_file(temp.path().join(".well-known")).unwrap();
    let (target, _, _) = paths(temp.path(), OP, &requirement(), true).unwrap();
    let key = outside.path().join("key");
    fs::write(&key, b"retain").unwrap();
    symlink(&key, &target).unwrap();
    assert!(publish(temp.path(), OP, &requirement()).is_err());
    assert_eq!(fs::read(key).unwrap(), b"retain");
}

#[test]
fn overlong_tokens_and_control_or_oversized_contents_fail_without_creating_files() {
    let temp = tempfile::tempdir().unwrap();
    for (token, content) in [
        ("a".repeat(256), "body".into()),
        (TOKEN.into(), "line\nsecret".into()),
        (TOKEN.into(), "a".repeat(4097)),
    ] {
        let requirement = ValidationRequirement::Http01 {
            url: "http://example.com/unused".into(),
            path: format!("/.well-known/acme-challenge/{token}"),
            content,
        };
        assert!(publish(temp.path(), OP, &requirement).is_err());
        assert_eq!(fs::read_dir(temp.path()).unwrap().count(), 0);
    }
}

#[cfg(unix)]
#[test]
fn only_new_public_files_get_serving_permissions_and_existing_user_modes_are_retained() {
    use std::os::unix::fs::PermissionsExt as _;
    let temp = tempfile::tempdir().unwrap();
    publish(temp.path(), OP, &requirement()).unwrap();
    let (target, _, _) = paths(temp.path(), OP, &requirement(), false).unwrap();
    assert_eq!(
        fs::metadata(&target).unwrap().permissions().mode() & 0o777,
        0o644
    );
    assert_eq!(
        fs::metadata(target.parent().unwrap())
            .unwrap()
            .permissions()
            .mode()
            & 0o777,
        0o755
    );
    remove_owned(temp.path(), OP, &requirement()).unwrap();
    fs::write(&target, format!("{TOKEN}.account-thumbprint")).unwrap();
    fs::set_permissions(&target, fs::Permissions::from_mode(0o600)).unwrap();
    publish(temp.path(), OP, &requirement()).unwrap();
    remove_owned(temp.path(), OP, &requirement()).unwrap();
    assert_eq!(
        fs::metadata(&target).unwrap().permissions().mode() & 0o777,
        0o600
    );
}

#[test]
fn effects_distinguish_created_reused_borrowed_removed_and_retained_files() {
    let temp = tempfile::tempdir().unwrap();
    let requirement = requirement();
    let (target, _, content) = paths(temp.path(), OP, &requirement, true).unwrap();
    assert_eq!(
        publish(temp.path(), OP, &requirement).unwrap(),
        FileAction::Published
    );
    assert_eq!(
        publish(temp.path(), OP, &requirement).unwrap(),
        FileAction::Reused
    );
    assert_eq!(
        remove_owned(temp.path(), OP, &requirement).unwrap(),
        FileAction::Removed
    );
    fs::write(&target, content).unwrap();
    assert_eq!(
        publish(temp.path(), OP, &requirement).unwrap(),
        FileAction::Borrowed
    );
    assert_eq!(
        remove_owned(temp.path(), OP, &requirement).unwrap(),
        FileAction::Retained
    );
    assert!(
        FileAction::Published
            .message(&target)
            .contains(&target.display().to_string())
    );
}
