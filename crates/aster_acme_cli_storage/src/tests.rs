//! Local durability, locking, permissions and key identity tests.
use super::toml_file::open_lock;
use super::*;
use aster_acme_core::account::AccountRecordState;
use tokio::time::sleep;

#[tokio::test]
async fn timestamp_metadata_roundtrips_without_inventing_unknown_values() {
    let temp = tempfile::tempdir().unwrap();
    let store = CliAccountStore::open(temp.path(), "work", Duration::from_secs(1)).unwrap();
    let directory = AcmeUrl::new("https://ca.example/directory").unwrap();
    let mut record = fixture(&directory, &"t".repeat(43));
    let at = time::OffsetDateTime::from_unix_timestamp(123).unwrap();
    record.times.registered_at = Some(at);
    record.times.last_status_at = Some(at);
    store.save(&record).await.unwrap();
    let text = fs::read_to_string(store.account_slot().join("account.toml")).unwrap();
    assert!(text.contains("1970-01-01T00:02:03Z"));
    assert!(!text.contains("last_used_at"));
    assert_eq!(
        store
            .load(&directory, &record.key_thumbprint)
            .await
            .unwrap(),
        Some(record.clone())
    );
    assert_eq!(
        accounts(temp.path().into()).await.unwrap()[0].times,
        record.times
    );
    atomic_write(
        &store.account_slot().join("account.toml"),
        text.replace("1970-01-01T00:02:03Z", "invalid").as_bytes(),
    )
    .unwrap();
    assert!(
        store
            .load(&directory, &record.key_thumbprint)
            .await
            .is_err()
    );
}

#[tokio::test]
async fn local_removal_is_scoped_and_does_not_require_a_valid_key() {
    let temp = tempfile::tempdir().unwrap();
    let ca = AcmeUrl::new("https://ca.example/directory").unwrap();
    let store = CliAccountStore::open(temp.path(), "personal", Duration::from_secs(1)).unwrap();
    let other = CliAccountStore::open(temp.path(), "work", Duration::from_secs(1)).unwrap();
    store.signer(&ca, "personal", true).await.unwrap();
    other.signer(&ca, "work", true).await.unwrap();
    let untouched = fs::read(other.account_slot().join("account-key.pk8")).unwrap();
    atomic_write(&store.account_slot().join("account-key.pk8"), b"corrupt").unwrap();
    store.remove().await.unwrap();
    assert!(!store.account_slot().exists());
    assert!(!temp.path().join("accounts/.personal.removing").exists());
    assert_eq!(
        fs::read(other.account_slot().join("account-key.pk8")).unwrap(),
        untouched
    );
    assert!(store.remove().await.is_err());
    assert_eq!(accounts(temp.path().into()).await.unwrap().len(), 1);
}

#[tokio::test]
async fn removal_lock_timeout_and_cleanup_collision_preserve_account() {
    let temp = tempfile::tempdir().unwrap();
    let ca = AcmeUrl::new("https://ca.example/directory").unwrap();
    let store = CliAccountStore::open(temp.path(), "personal", Duration::from_millis(30)).unwrap();
    let thumb = store
        .signer(&ca, "personal", true)
        .await
        .unwrap()
        .jwk()
        .unwrap()
        .thumbprint()
        .unwrap();
    let key_path = store.account_slot().join("account-key.pk8");
    let before = fs::read(&key_path).unwrap();
    let held = store.lock_account(&ca, &thumb).await.unwrap();
    assert!(store.remove().await.is_err());
    drop(held);
    fs::create_dir(temp.path().join("accounts/.personal.removing")).unwrap();
    assert!(store.remove().await.is_err());
    assert_eq!(fs::read(key_path).unwrap(), before);
}

#[cfg(unix)]
#[tokio::test]
async fn removal_rejects_key_links_without_touching_the_target() {
    use std::os::unix::fs::symlink;
    let temp = tempfile::tempdir().unwrap();
    let store = CliAccountStore::open(temp.path(), "personal", Duration::from_secs(1)).unwrap();
    let ca = AcmeUrl::new("https://ca.example/directory").unwrap();
    store.signer(&ca, "personal", true).await.unwrap();
    let key_path = store.account_slot().join("account-key.pk8");
    fs::remove_file(&key_path).unwrap();
    let outside = temp.path().join("outside");
    atomic_write(&outside, b"untouched").unwrap();
    symlink(&outside, &key_path).unwrap();
    assert!(store.remove().await.is_err());
    assert_eq!(fs::read(outside).unwrap(), b"untouched");
    assert!(store.account_slot().join("account.toml").exists());
}

fn fixture(directory: &AcmeUrl, thumbprint: &str) -> AccountRecord {
    AccountRecord {
        user_agent: None,
        times: aster_acme::account::AccountTimes::default(),
        account_id: "a".repeat(43),
        directory_url: directory.clone(),
        key_thumbprint: thumbprint.to_owned(),
        account_url: None,
        contacts: vec![],
        server_contacts: None,
        last_status: None,
        deactivation: aster_acme_core::account::DeactivationState::NotRequested,
        key_rotation: None,
        accepted_terms_url: None,
        state: AccountRecordState::RegistrationPending,
    }
}

#[tokio::test]
async fn listing_is_offline_sorted_filters_uninitialized_and_rejects_corrupt_entries() {
    let temp = tempfile::tempdir().unwrap();
    assert_eq!(accounts(temp.path().into()).await.unwrap().len(), 0);
    assert!(!temp.path().join("accounts").exists());
    let ca = AcmeUrl::new("https://ca.example/directory").unwrap();
    for name in ["zebra", "alpha"] {
        let store = CliAccountStore::open(temp.path(), name, Duration::from_secs(1)).unwrap();
        let thumb = store
            .signer(&ca, name, true)
            .await
            .unwrap()
            .jwk()
            .unwrap()
            .thumbprint()
            .unwrap();
        if name == "alpha" {
            let mut record = store.load(&ca, &thumb).await.unwrap().unwrap();
            record.state = AccountRecordState::Registered;
            record.account_url = Some(AcmeUrl::new("https://ca.example/account/1").unwrap());
            store.save(&record).await.unwrap();
        }
    }
    fs::create_dir(temp.path().join("accounts/empty")).unwrap();
    let listed = accounts(temp.path().into()).await.unwrap();
    assert_eq!(
        listed
            .iter()
            .map(|account| account.name.as_str())
            .collect::<Vec<_>>(),
        ["alpha", "zebra"]
    );
    assert!(listed[0].usable);
    assert!(!listed[1].usable);
    assert_eq!(listed[0].directory, ca);
    atomic_write(&temp.path().join("accounts/alpha/account.toml"), b"invalid").unwrap();
    assert!(accounts(temp.path().into()).await.is_err());
}

#[cfg(unix)]
#[tokio::test]
async fn listing_ignores_unmanaged_symlink_but_explicit_account_open_rejects_it() {
    use std::os::unix::fs::symlink;
    let temp = tempfile::tempdir().unwrap();
    let outside = tempfile::tempdir().unwrap();
    fs::create_dir(temp.path().join("accounts")).unwrap();
    symlink(outside.path(), temp.path().join("accounts/alias")).unwrap();
    assert_eq!(accounts(temp.path().into()).await.unwrap().len(), 0);
    let store = CliAccountStore::open(temp.path(), "alias", Duration::from_secs(1)).unwrap();
    assert!(
        store
            .signer(
                &AcmeUrl::new("https://ca.example/directory").unwrap(),
                "alias",
                true
            )
            .await
            .is_err()
    );
}

#[tokio::test]
async fn named_account_is_one_directory_and_missing_identity_or_key_is_an_error() {
    let temp = tempfile::tempdir().unwrap();
    let store = CliAccountStore::open(temp.path(), "personal", Duration::from_secs(1)).unwrap();
    let ca = AcmeUrl::new("https://ca.example/directory").unwrap();
    let key = store.signer(&ca, "personal", true).await.unwrap();
    let thumb = key.jwk().unwrap().thumbprint().unwrap();
    let slot = temp.path().join("accounts/personal");
    assert_eq!(store.account_slot(), slot);
    assert!(slot.join("account.toml").is_file());
    assert!(slot.join("account-key.pk8").is_file());
    assert_eq!(
        fs::read_dir(temp.path().join("accounts")).unwrap().count(),
        1
    );
    assert!(!slot.join("initialized").exists());
    let record = fs::read(slot.join("account.toml")).unwrap();
    let private_key = fs::read(slot.join("account-key.pk8")).unwrap();
    fs::remove_file(slot.join("account.toml")).unwrap();
    assert!(store.signer(&ca, "personal", true).await.is_err());
    assert_eq!(fs::read(slot.join("account-key.pk8")).unwrap(), private_key);
    atomic_write(&slot.join("account.toml"), &record).unwrap();
    fs::remove_file(slot.join("account-key.pk8")).unwrap();
    assert!(store.signer(&ca, "personal", true).await.is_err());
    assert_eq!(fs::read(slot.join("account.toml")).unwrap(), record);
    atomic_write(
        &slot.join("account-key.pk8"),
        &AccountKey::generate().unwrap().to_pkcs8().unwrap(),
    )
    .unwrap();
    assert!(store.signer(&ca, "personal", true).await.is_err());
    assert!(
        store
            .load(
                &AcmeUrl::new("https://other.example/directory").unwrap(),
                &thumb
            )
            .await
            .is_err()
    );
}

#[tokio::test]
async fn key_is_durable_and_ca_and_name_scoped_and_recover_never_creates() {
    let temp = tempfile::tempdir().unwrap();
    let directory = AcmeUrl::new("https://staging.example/directory").unwrap();
    let store = CliAccountStore::open(temp.path().join("state"), "default", Duration::from_secs(1))
        .unwrap();
    assert!(store.signer(&directory, "default", false).await.is_err());
    let key = store.signer(&directory, "default", true).await.unwrap();
    let jwk = key.jwk().unwrap();
    let reopened =
        CliAccountStore::open(temp.path().join("state"), "default", Duration::from_secs(1))
            .unwrap();
    assert_eq!(
        reopened
            .signer(&directory, "default", false)
            .await
            .unwrap()
            .jwk()
            .unwrap(),
        jwk
    );
    let other_ca = AcmeUrl::new("https://production.example/directory").unwrap();
    assert!(store.signer(&other_ca, "default", true).await.is_err());
    let other =
        CliAccountStore::open(temp.path().join("state"), "other", Duration::from_secs(1)).unwrap();
    assert_ne!(
        other
            .signer(&other_ca, "other", true)
            .await
            .unwrap()
            .jwk()
            .unwrap(),
        jwk
    );
    for name in ["", "../escape", "a/b", "space name", "名字"] {
        assert!(
            CliAccountStore::open(temp.path().join("state"), name, Duration::from_secs(1)).is_err()
        );
    }
    assert!(
        CliAccountStore::open(
            temp.path().join("state"),
            &"x".repeat(65),
            Duration::from_secs(1)
        )
        .is_err()
    );
    assert!(
        CliAccountStore::open(
            temp.path().join("state"),
            &"x".repeat(64),
            Duration::from_secs(1)
        )
        .is_ok()
    );
}

#[tokio::test]
async fn concurrent_first_key_initialization_reuses_one_identity() {
    let temp = tempfile::tempdir().unwrap();
    let store = CliAccountStore::open(temp.path(), "default", Duration::from_secs(5)).unwrap();
    let directory = AcmeUrl::new("https://ca.example/directory").unwrap();
    let mut tasks = tokio::task::JoinSet::new();
    for _ in 0..16 {
        let store = store.clone();
        let directory = directory.clone();
        tasks.spawn(async move {
            store
                .signer(&directory, "default", true)
                .await
                .unwrap()
                .jwk()
                .unwrap()
        });
    }
    let expected = tasks.join_next().await.unwrap().unwrap();
    while let Some(result) = tasks.join_next().await {
        assert_eq!(result.unwrap(), expected);
    }
}

#[tokio::test]
async fn metadata_roundtrips_atomically_and_rejects_corrupt_unknown_and_oversized_data() {
    let temp = tempfile::tempdir().unwrap();
    let store = CliAccountStore::open(temp.path(), "default", Duration::from_secs(1)).unwrap();
    let directory = AcmeUrl::new("https://ca.example/directory").unwrap();
    let thumb = "t".repeat(43);
    assert!(store.load(&directory, &thumb).await.unwrap().is_none());
    let mut record = fixture(&directory, &thumb);
    store.save(&record).await.unwrap();
    assert_eq!(
        store.load(&directory, &thumb).await.unwrap(),
        Some(record.clone())
    );
    record.account_url = Some(AcmeUrl::new("https://ca.example/account/1").unwrap());
    record.state = AccountRecordState::Registered;
    store.save(&record).await.unwrap();
    assert_eq!(
        store.load(&directory, &thumb).await.unwrap(),
        Some(record.clone())
    );
    let path = store.account_slot().join("account.toml");
    for bytes in [
        b"invalid".to_vec(),
        toml::to_string(&StoredAccount {
            version: 2,
            account: record,
        })
        .unwrap()
        .into_bytes(),
        vec![
            0;
            aster_forge_utils::numbers::u64_to_usize(MAX_ACCOUNT_FILE, "account limit").unwrap()
                + 1
        ],
    ] {
        atomic_write(&path, &bytes).unwrap();
        assert!(store.load(&directory, &thumb).await.is_err());
    }
    let malformed = fixture(&directory, "short");
    assert!(store.save(&malformed).await.is_err());
}

#[tokio::test]
async fn locks_timeout_release_and_allow_waiting_contenders() {
    let temp = tempfile::tempdir().unwrap();
    let store = CliAccountStore::open(temp.path(), "default", Duration::from_millis(60)).unwrap();
    let directory = AcmeUrl::new("https://ca.example/directory").unwrap();
    let thumb = "t".repeat(43);
    let held = store.lock_account(&directory, &thumb).await.unwrap();
    let start = tokio::time::Instant::now();
    assert!(store.lock_account(&directory, &thumb).await.is_err());
    assert!(start.elapsed() >= Duration::from_millis(60));
    drop(held);
    let held = store.lock_account(&directory, &thumb).await.unwrap();
    drop(held);
    let long_store = CliAccountStore::open(temp.path(), "default", Duration::from_secs(1)).unwrap();
    let held = long_store.lock_account(&directory, &thumb).await.unwrap();
    let handle = tokio::spawn({
        let s = long_store.clone();
        let d = directory.clone();
        let t = thumb.clone();
        async move { s.lock_account(&d, &t).await }
    });
    sleep(Duration::from_millis(50)).await;
    assert!(!handle.is_finished());
    drop(held);
    assert!(handle.await.unwrap().is_ok());
}

#[tokio::test]
async fn malformed_or_lost_private_keys_are_not_silently_replaced() {
    let temp = tempfile::tempdir().unwrap();
    let store = CliAccountStore::open(temp.path(), "default", Duration::from_secs(1)).unwrap();
    let directory = AcmeUrl::new("https://ca.example/directory").unwrap();
    store.signer(&directory, "default", true).await.unwrap();
    let path = store.account_slot().join("account-key.pk8");
    atomic_write(&path, b"corrupt").unwrap();
    assert!(store.signer(&directory, "default", true).await.is_err());
    fs::remove_file(&path).unwrap();
    assert!(store.signer(&directory, "default", true).await.is_err());
    atomic_write(
        &path,
        &vec![0; aster_forge_utils::numbers::u64_to_usize(MAX_KEY_FILE, "key limit").unwrap() + 1],
    )
    .unwrap();
    assert!(store.signer(&directory, "default", false).await.is_err());
}

#[cfg(unix)]
#[tokio::test]
async fn private_permissions_and_symlink_boundaries_are_enforced() {
    use std::os::unix::fs::{PermissionsExt, symlink};
    let temp = tempfile::tempdir().unwrap();
    let root = temp.path().join("state");
    let store = CliAccountStore::open(&root, "default", Duration::from_secs(1)).unwrap();
    let directory = AcmeUrl::new("https://ca.example/directory").unwrap();
    let key = store.signer(&directory, "default", true).await.unwrap();
    let path = store.account_slot().join("account-key.pk8");
    assert_eq!(
        fs::metadata(&root).unwrap().permissions().mode() & 0o777,
        0o700
    );
    assert_eq!(
        fs::metadata(&path).unwrap().permissions().mode() & 0o777,
        0o600
    );
    fs::set_permissions(&path, fs::Permissions::from_mode(0o644)).unwrap();
    assert!(store.signer(&directory, "default", false).await.is_err());
    fs::remove_file(&path).unwrap();
    let target = temp.path().join("untouched");
    fs::write(&target, b"private target").unwrap();
    symlink(&target, &path).unwrap();
    assert!(store.signer(&directory, "default", true).await.is_err());
    assert_eq!(fs::read(&target).unwrap(), b"private target");
    let alias = temp.path().join("alias");
    symlink(&root, &alias).unwrap();
    assert!(CliAccountStore::open(alias, "default", Duration::from_secs(1)).is_err());
    assert_eq!(key.jwk().unwrap().thumbprint().unwrap().len(), 43);
}

#[test]
fn lock_timeout_options_are_bounded() {
    let temp = tempfile::tempdir().unwrap();
    for timeout in [Duration::ZERO, Duration::from_secs(301)] {
        assert!(CliAccountStore::open(temp.path(), "default", timeout).is_err());
    }
}

#[cfg(unix)]
#[test]
fn state_reads_reject_hardlinks_and_enforce_exact_limit() {
    use std::os::unix::fs::PermissionsExt;
    let temp = tempfile::tempdir().unwrap();
    let path = temp.path().join("private");
    atomic_write(&path, b"1234").unwrap();
    assert_eq!(read_private(&path, 4).unwrap(), b"1234");
    assert!(matches!(
        read_private(&path, 3),
        Err(StorageError::TooLarge)
    ));
    let alias = temp.path().join("alias");
    fs::hard_link(&path, &alias).unwrap();
    assert!(matches!(
        read_private(&path, 4),
        Err(StorageError::InsecurePath)
    ));
    assert!(open_lock(&path).is_err());
    let unsafe_dir = temp.path().join("unsafe");
    fs::create_dir(&unsafe_dir).unwrap();
    fs::set_permissions(&unsafe_dir, fs::Permissions::from_mode(0o777)).unwrap();
    assert!(CliAccountStore::open(&unsafe_dir, "default", Duration::from_secs(1)).is_err());
}

#[tokio::test]
async fn removal_only_deletes_managed_files_and_retains_user_contents_and_lock() {
    let temp = tempfile::tempdir().unwrap();
    let directory = AcmeUrl::new("https://ca.example/directory").unwrap();
    let store = CliAccountStore::open(temp.path(), "work", Duration::from_secs(1)).unwrap();
    store.signer(&directory, "work", true).await.unwrap();
    let slot = store.account_slot();
    fs::write(slot.join("notes.txt"), b"user notes").unwrap();
    fs::create_dir(slot.join("backup")).unwrap();
    fs::write(slot.join("backup/own-file"), b"retain").unwrap();
    store.remove().await.unwrap();
    assert_eq!(fs::read(slot.join("notes.txt")).unwrap(), b"user notes");
    assert_eq!(fs::read(slot.join("backup/own-file")).unwrap(), b"retain");
    assert!(slot.join("account.lock").exists());
    assert!(!slot.join("account.toml").exists());
    assert!(!slot.join("account-key.pk8").exists());
    assert!(accounts(temp.path().into()).await.unwrap().is_empty());
    // The leftover directory is uninitialized, and future explicit registration can
    // use the retained lock without touching user contents.
    store.signer(&directory, "work", true).await.unwrap();
    assert_eq!(fs::read(slot.join("notes.txt")).unwrap(), b"user notes");
}
