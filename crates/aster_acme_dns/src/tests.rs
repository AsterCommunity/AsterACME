use crate::{
    DnsRecord, ProviderContext, ProviderExecution,
    propagation::{PropagationError, PropagationPolicy},
    routing::{
        DnsLookup, LookupError, RouteError, absolute_name, allowed_zone, resolve, validate_chain,
    },
};
use async_trait::async_trait;
use std::{
    collections::BTreeMap,
    sync::atomic::{AtomicUsize, Ordering},
    time::{Duration, Instant},
};
use tokio_util::sync::CancellationToken;

struct Lookup {
    aliases: BTreeMap<String, String>,
    values: Vec<Vec<u8>>,
    reads: AtomicUsize,
    delay: Duration,
}
impl Default for Lookup {
    fn default() -> Self {
        Self {
            aliases: BTreeMap::new(),
            values: Vec::new(),
            reads: AtomicUsize::new(0),
            delay: Duration::ZERO,
        }
    }
}
#[async_trait]
impl DnsLookup for Lookup {
    async fn cname(&self, name: &str) -> Result<Option<String>, LookupError> {
        self.reads.fetch_add(1, Ordering::SeqCst);
        tokio::time::sleep(self.delay).await;
        Ok(self.aliases.get(name).cloned())
    }
    async fn txt(&self, _: &str) -> Result<Vec<Vec<u8>>, LookupError> {
        self.reads.fetch_add(1, Ordering::SeqCst);
        tokio::time::sleep(self.delay).await;
        Ok(self.values.clone())
    }
}
fn execution() -> ProviderExecution {
    ProviderExecution {
        cancellation: CancellationToken::new(),
        deadline: Instant::now() + Duration::from_secs(2),
    }
}
fn record() -> DnsRecord {
    DnsRecord {
        publication_id: "pub-1".into(),
        challenge_name: "_acme-challenge.example.com.".into(),
        cname_chain: vec!["_acme-challenge.example.com.".into()],
        name: "_acme-challenge.example.com.".into(),
        value: "expected".into(),
        ttl_seconds: Some(120),
    }
}

#[test]
fn names_and_allowed_zones_are_validated_at_label_boundaries() {
    assert_eq!(
        absolute_name("_acme-challenge.Example.COM").unwrap(),
        "_acme-challenge.example.com."
    );
    for name in [
        "",
        ".",
        "example.com..",
        "*.example.com",
        "a..example",
        "-bad.example",
        "a/b.example",
        "中文.example",
    ] {
        assert!(absolute_name(name).is_err(), "{name}");
    }
    assert!(absolute_name(&format!("{}.com", "x".repeat(64))).is_err());
    assert!(allowed_zone(
        "_acme-challenge.Example.com.",
        &["example.com".into()]
    ));
    assert!(!allowed_zone("notexample.com", &["example.com".into()]));
    assert!(!allowed_zone(
        "example.com.attacker.example",
        &["example.com".into()]
    ));
    assert!(allowed_zone("example.com", &[]));
    assert!(!allowed_zone("bad..name", &[]));
}
#[tokio::test]
async fn cname_routes_direct_and_delegated_names_without_mutations() {
    let mut lookup = Lookup::default();
    lookup.aliases.insert(
        "_acme-challenge.example.com.".into(),
        "acme.validation.net.".into(),
    );
    let chain = resolve(
        &lookup,
        "_acme-challenge.example.com",
        &["validation.net".into()],
        &execution(),
    )
    .await
    .unwrap();
    assert_eq!(
        chain,
        ["_acme-challenge.example.com.", "acme.validation.net."]
    );
    assert_eq!(lookup.reads.load(Ordering::SeqCst), 2);
    assert!(matches!(
        resolve(
            &lookup,
            "_acme-challenge.example.com",
            &["example.com".into()],
            &execution()
        )
        .await,
        Err(RouteError::ZoneNotAllowed)
    ));
    assert_eq!(
        resolve(
            &Lookup::default(),
            "direct.example.com",
            &["example.com".into()],
            &execution()
        )
        .await
        .unwrap()
        .len(),
        1
    );
}
#[tokio::test]
async fn cname_exact_depth_limit_and_loops_fail_closed() {
    let mut lookup = Lookup::default();
    for index in 0..8 {
        lookup.aliases.insert(
            format!("n{index}.example.com."),
            format!("n{}.example.com.", index + 1),
        );
    }
    assert_eq!(
        resolve(
            &lookup,
            "n0.example.com",
            &["example.com".into()],
            &execution()
        )
        .await
        .unwrap()
        .len(),
        9
    );
    lookup
        .aliases
        .insert("n8.example.com.".into(), "n9.example.com.".into());
    assert!(matches!(
        resolve(
            &lookup,
            "n0.example.com",
            &["example.com".into()],
            &execution()
        )
        .await,
        Err(RouteError::CnameChainTooLong)
    ));
    lookup
        .aliases
        .insert("n1.example.com.".into(), "n0.example.com.".into());
    assert!(matches!(
        resolve(
            &lookup,
            "n0.example.com",
            &["example.com".into()],
            &execution()
        )
        .await,
        Err(RouteError::CnameLoop)
    ));
}
#[tokio::test]
async fn route_queries_obey_cancellation_and_deadline() {
    let lookup = Lookup {
        delay: Duration::from_secs(5),
        ..Lookup::default()
    };
    let mut scope = execution();
    scope.cancellation.cancel();
    assert!(matches!(
        resolve(&lookup, "example.com", &["example.com".into()], &scope).await,
        Err(RouteError::Interrupted)
    ));
    assert_eq!(lookup.reads.load(Ordering::SeqCst), 0);
    scope.cancellation = CancellationToken::new();
    scope.deadline = Instant::now() + Duration::from_millis(20);
    assert!(matches!(
        resolve(&lookup, "example.com", &["example.com".into()], &scope).await,
        Err(RouteError::Interrupted)
    ));
}
#[test]
fn saved_routes_cannot_be_redirected_or_exceed_boundaries() {
    let chain = vec![
        "source.example.com.".into(),
        "target.validation.net.".into(),
    ];
    assert!(
        validate_chain(
            "source.example.com",
            "target.validation.net",
            &chain,
            &["validation.net".into()]
        )
        .is_ok()
    );
    assert!(
        validate_chain(
            "wrong.example.com",
            "target.validation.net",
            &chain,
            &["validation.net".into()]
        )
        .is_err()
    );
    assert!(
        validate_chain(
            "source.example.com",
            "target.validation.net",
            &chain,
            &["example.com".into()]
        )
        .is_err()
    );
    assert!(
        validate_chain(
            "source.example.com",
            "source.example.com",
            &[chain[0].clone(), chain[0].clone()],
            &["example.com".into()]
        )
        .is_err()
    );
}
#[tokio::test]
async fn propagation_requires_each_exact_logical_txt_value() {
    let policy = PropagationPolicy {
        interval: Duration::from_millis(5),
        timeout: Duration::from_millis(30),
    };
    let lookup = Lookup {
        values: vec![b"unrelated".to_vec(), b"expected".to_vec()],
        ..Lookup::default()
    };
    policy
        .wait(&lookup, &[record()], &execution())
        .await
        .unwrap();
    let mut second = record();
    second.value = "expected2".into();
    second.publication_id = "pub-2".into();
    assert!(matches!(
        policy
            .wait(&lookup, &[record(), second], &execution())
            .await,
        Err(PropagationError::NotVisible)
    ));
    let scope = execution();
    scope.cancellation.cancel();
    assert!(matches!(
        policy.wait(&lookup, &[record()], &scope).await,
        Err(PropagationError::Interrupted)
    ));
    assert!(matches!(
        PropagationPolicy {
            interval: Duration::ZERO,
            ..policy
        }
        .wait(&lookup, &[record()], &execution())
        .await,
        Err(PropagationError::InvalidPolicy)
    ));
}
#[test]
fn sensitive_context_does_not_leak_through_debug() {
    let context = ProviderContext {
        provider_instance_id: "prod".into(),
        provider_profile_version: 1,
        provider_custom: BTreeMap::from([("token".into(), serde_json::json!("secret-sentinel"))]),
    };
    assert!(!format!("{context:?}").contains("secret-sentinel"));
    assert!(
        serde_json::to_string(&context)
            .unwrap()
            .contains("secret-sentinel")
    );
}

#[tokio::test]
async fn default_zone_policy_allows_cross_zone_cname_but_explicit_policy_still_restricts() {
    let mut lookup = Lookup::default();
    lookup.aliases.insert(
        "_acme-challenge.example.com.".into(),
        "txt.different.net.".into(),
    );
    assert_eq!(
        resolve(&lookup, "_acme-challenge.example.com", &[], &execution())
            .await
            .unwrap(),
        ["_acme-challenge.example.com.", "txt.different.net."]
    );
    assert!(
        validate_chain(
            "_acme-challenge.example.com",
            "txt.different.net",
            &[
                "_acme-challenge.example.com.".into(),
                "txt.different.net.".into()
            ],
            &[]
        )
        .is_ok()
    );
    assert!(matches!(
        resolve(
            &lookup,
            "_acme-challenge.example.com",
            &["example.com".into()],
            &execution()
        )
        .await,
        Err(RouteError::ZoneNotAllowed)
    ));
}
