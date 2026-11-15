use crate::{
    DnsRecord, ProviderContext, ProviderExecution,
    propagation::{PropagationError, PropagationEvent, PropagationPolicy},
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
    fail_txt: bool,
    cancel_on_txt: Option<CancellationToken>,
}
impl Default for Lookup {
    fn default() -> Self {
        Self {
            aliases: BTreeMap::new(),
            values: Vec::new(),
            reads: AtomicUsize::new(0),
            delay: Duration::ZERO,
            fail_txt: false,
            cancel_on_txt: None,
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
        if let Some(token) = &self.cancel_on_txt {
            token.cancel();
        }
        if self.fail_txt {
            return Err(LookupError {
                stage: "TXT query failed",
                cause: Box::new(std::io::Error::other("test resolver unavailable")),
            });
        }
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
async fn propagation_requires_each_exact_value_and_only_missing_values_wait_again() {
    let policy = PropagationPolicy {
        initial_delay: Duration::from_millis(10),
        fallback_delay: Duration::from_millis(20),
        timeout: Duration::from_millis(30),
    };
    let lookup = Lookup {
        values: vec![b"unrelated".to_vec(), b"expected".to_vec()],
        ..Lookup::default()
    };
    let events = std::sync::Mutex::new(Vec::new());
    let started = Instant::now();
    assert!(
        policy
            .wait(&lookup, &[record()], &execution(), |event| {
                assert!(matches!(event, PropagationEvent::WaitingToCheck(_)));
                assert_eq!(lookup.reads.load(Ordering::SeqCst), 0);
                events.lock().unwrap().push(event);
            })
            .await
            .unwrap()
    );
    assert!(started.elapsed() >= policy.initial_delay);
    assert_eq!(
        *events.lock().unwrap(),
        [PropagationEvent::WaitingToCheck(policy.initial_delay)]
    );
    assert_eq!(lookup.reads.load(Ordering::SeqCst), 1);
    let mut second = record();
    second.value = "expected2".into();
    second.publication_id = "pub-2".into();
    let started = Instant::now();
    assert!(
        !policy
            .wait(&lookup, &[record(), second], &execution(), |event| {
                events.lock().unwrap().push(event);
            })
            .await
            .unwrap()
    );
    assert!(started.elapsed() >= policy.initial_delay + policy.fallback_delay);
    assert_eq!(lookup.reads.load(Ordering::SeqCst), 2);
    assert_eq!(
        events.lock().unwrap().last(),
        Some(&PropagationEvent::WaitingForCa(policy.fallback_delay))
    );
    assert_eq!(
        PropagationPolicy::default().initial_delay,
        Duration::from_secs(5)
    );
    assert_eq!(
        PropagationPolicy::default().fallback_delay,
        Duration::from_secs(10)
    );
}

#[tokio::test]
async fn propagation_probe_timeout_is_advisory_but_operation_expiry_is_not() {
    let policy = PropagationPolicy {
        initial_delay: Duration::from_millis(2),
        fallback_delay: Duration::from_millis(3),
        timeout: Duration::from_millis(5),
    };
    let lookup = Lookup {
        delay: Duration::from_secs(1),
        ..Lookup::default()
    };
    assert!(
        !policy
            .wait(&lookup, &[record()], &execution(), |_| {})
            .await
            .unwrap()
    );
    for stage in [0, 1] {
        let scope = execution();
        let result = policy
            .wait(&Lookup::default(), &[record()], &scope, |event| {
                if matches!(
                    (stage, event),
                    (0, PropagationEvent::WaitingToCheck(_))
                        | (1, PropagationEvent::WaitingForCa(_))
                ) {
                    scope.cancellation.cancel();
                }
            })
            .await;
        assert!(matches!(result, Err(PropagationError::Interrupted)));
    }
    let scope = ProviderExecution {
        deadline: Instant::now() + Duration::from_millis(5),
        ..execution()
    };
    assert!(matches!(
        policy.wait(&lookup, &[record()], &scope, |_| {}).await,
        Err(PropagationError::Interrupted)
    ));
    assert!(matches!(
        PropagationPolicy {
            timeout: Duration::ZERO,
            ..policy
        }
        .wait(&lookup, &[record()], &execution(), |_| {})
        .await,
        Err(PropagationError::InvalidPolicy)
    ));
}

#[tokio::test]
async fn propagation_errors_empty_inputs_and_execution_boundaries() {
    let policy = PropagationPolicy {
        initial_delay: Duration::ZERO,
        fallback_delay: Duration::from_millis(10),
        timeout: Duration::from_millis(20),
    };
    let lookup = Lookup {
        fail_txt: true,
        ..Lookup::default()
    };
    let start = Instant::now();
    assert!(
        !policy
            .wait(&lookup, &[record()], &execution(), |_| {})
            .await
            .unwrap()
    );
    assert!(start.elapsed() >= policy.fallback_delay);
    assert_eq!(lookup.reads.load(Ordering::SeqCst), 1);
    assert!(
        policy
            .wait(&lookup, &[], &execution(), |_| panic!(
                "no work must not wait"
            ))
            .await
            .unwrap()
    );
    for stage in [0, 1, 2] {
        let scope = execution();
        let policy = match stage {
            0 => PropagationPolicy {
                initial_delay: Duration::from_secs(1),
                ..policy
            },
            1 => PropagationPolicy {
                timeout: Duration::from_secs(1),
                ..policy
            },
            _ => PropagationPolicy {
                fallback_delay: Duration::from_secs(1),
                ..policy
            },
        };
        let lookup = Lookup {
            delay: if stage == 1 {
                Duration::from_secs(1)
            } else {
                Duration::ZERO
            },
            ..Lookup::default()
        };
        let scope = ProviderExecution {
            deadline: Instant::now() + Duration::from_millis(10),
            ..scope
        };
        assert!(matches!(
            policy.wait(&lookup, &[record()], &scope, |_| {}).await,
            Err(PropagationError::Interrupted)
        ));
    }
    let scope = execution();
    let lookup = Lookup {
        cancel_on_txt: Some(scope.cancellation.clone()),
        ..Lookup::default()
    };
    assert!(matches!(
        policy.wait(&lookup, &[record()], &scope, |_| {}).await,
        Err(PropagationError::Interrupted)
    ));
    for policy in [
        PropagationPolicy {
            initial_delay: Duration::MAX,
            ..policy
        },
        PropagationPolicy {
            timeout: Duration::MAX,
            ..policy
        },
        PropagationPolicy {
            fallback_delay: Duration::MAX,
            ..policy
        },
    ] {
        assert!(matches!(
            policy
                .wait(&Lookup::default(), &[record()], &execution(), |_| {})
                .await,
            Err(PropagationError::InvalidPolicy)
        ));
    }
}

#[tokio::test]
async fn propagation_cancels_while_initial_wait_probe_or_fallback_is_in_flight() {
    for stage in [0, 1, 2] {
        let scope = execution();
        let token = scope.cancellation.clone();
        let cancel = tokio::spawn(async move {
            tokio::time::sleep(Duration::from_millis(20)).await;
            token.cancel();
        });
        let policy = PropagationPolicy {
            initial_delay: if stage == 0 {
                Duration::from_secs(1)
            } else {
                Duration::ZERO
            },
            timeout: Duration::from_secs(1),
            fallback_delay: Duration::from_secs(1),
        };
        let lookup = Lookup {
            delay: if stage == 1 {
                Duration::from_secs(1)
            } else {
                Duration::ZERO
            },
            ..Lookup::default()
        };
        assert!(matches!(
            policy.wait(&lookup, &[record()], &scope, |_| {}).await,
            Err(PropagationError::Interrupted)
        ));
        cancel.await.unwrap();
        assert_eq!(lookup.reads.load(Ordering::SeqCst), usize::from(stage != 0));
    }
}

struct AlternatingLookup(AtomicUsize);
#[async_trait]
impl DnsLookup for AlternatingLookup {
    async fn cname(&self, _: &str) -> Result<Option<String>, LookupError> {
        Ok(None)
    }
    async fn txt(&self, _: &str) -> Result<Vec<Vec<u8>>, LookupError> {
        let value = if self.0.fetch_add(1, Ordering::SeqCst).is_multiple_of(2) {
            b"first".to_vec()
        } else {
            b"second".to_vec()
        };
        Ok(vec![value])
    }
}

#[tokio::test]
async fn propagation_uses_one_dns_answer_for_all_values_at_the_same_owner() {
    let policy = PropagationPolicy {
        initial_delay: Duration::ZERO,
        fallback_delay: Duration::ZERO,
        timeout: Duration::from_millis(12),
    };
    let mut first = record();
    first.value = "first".into();
    let mut second = first.clone();
    second.publication_id = "pub-2".into();
    second.value = "second".into();
    let lookup = AlternatingLookup(AtomicUsize::new(0));
    assert!(
        !policy
            .wait(&lookup, &[first, second], &execution(), |_| {})
            .await
            .unwrap()
    );
    assert_eq!(lookup.0.load(Ordering::SeqCst), 1);
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
