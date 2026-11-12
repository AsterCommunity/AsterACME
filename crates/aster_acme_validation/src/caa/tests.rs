//! Injected recursive answers exercise tree climbing without external DNS.
use crate::caa::*;
use std::{collections::HashMap, sync::Mutex};
struct Fake {
    values: HashMap<String, Vec<Property>>,
    queries: Mutex<Vec<String>>,
    fails: bool,
}
#[async_trait]
impl Lookup for Fake {
    async fn lookup(&self, name: &str) -> Result<Vec<Property>, LookupError> {
        self.queries.lock().unwrap().push(name.into());
        if self.fails {
            return Err(LookupError);
        }
        Ok(self.values.get(name).cloned().unwrap_or_default())
    }
}
fn record(tag: &str, value: &str) -> Property {
    Property {
        critical: false,
        tag: tag.into(),
        value: value.as_bytes().into(),
    }
}
#[tokio::test]
async fn nearest_nonempty_set_wins_and_is_never_merged_with_parent() {
    let fake = Fake {
        values: HashMap::from([
            ("example.com.".into(), vec![record("issue", "ca.example")]),
            ("com.".into(), vec![record("issue", ";")]),
        ]),
        queries: Mutex::new(vec![]),
        fails: false,
    };
    let issuers = vec!["ca.example".into()];
    let req = Request {
        issuers: &issuers,
        account_uri: None,
        method: "dns-01",
        wildcard: false,
    };
    let report = check(&fake, "sub.example.com", &req).await.unwrap();
    assert_eq!(report.source.as_deref(), Some("example.com"));
    assert_eq!(report.observation, Observation::Matches);
    assert_eq!(
        *fake.queries.lock().unwrap(),
        ["sub.example.com.", "example.com."]
    );
}
#[tokio::test]
async fn empty_alias_result_climbs_original_name_not_alias_target_parents() {
    // Each fake answer represents a fully chased recursive query. An alias
    // yielding no CAA still climbs example.com, never alias.provider.example.
    let fake = Fake {
        values: HashMap::from([(
            "example.com.".into(),
            vec![record("iodef", "mailto:ops@example.com")],
        )]),
        queries: Mutex::new(vec![]),
        fails: false,
    };
    let req = Request {
        issuers: &[],
        account_uri: None,
        method: "dns-01",
        wildcard: true,
    };
    let report = check(&fake, "*.alias.example.com", &req).await.unwrap();
    assert_eq!(report.observation, Observation::Unrestricted);
    assert_eq!(
        *fake.queries.lock().unwrap(),
        ["alias.example.com.", "example.com."]
    );
}
#[tokio::test]
async fn empty_tree_queries_tld_but_not_root_and_errors_do_not_mean_unrestricted() {
    let mut fake = Fake {
        values: HashMap::new(),
        queries: Mutex::new(vec![]),
        fails: false,
    };
    let req = Request {
        issuers: &[],
        account_uri: None,
        method: "http-01",
        wildcard: false,
    };
    assert_eq!(
        check(&fake, "a.example.com", &req)
            .await
            .unwrap()
            .observation,
        Observation::Unrestricted
    );
    assert_eq!(
        *fake.queries.lock().unwrap(),
        ["a.example.com.", "example.com.", "com."]
    );
    fake.fails = true;
    assert!(check(&fake, "example.com", &req).await.is_err());
    assert!(check(&fake, "../bad", &req).await.is_err());
}

#[tokio::test]
async fn recursive_wire_lookup_chases_alias_and_preserves_critical_flag() {
    use hickory_resolver::{
        config::{NameServerConfig, ResolverConfig},
        net::runtime::TokioRuntimeProvider,
        proto::{
            op::{Message, MessageType, OpCode},
            rr::{
                Name, Record,
                rdata::{CAA, CNAME},
            },
        },
    };
    let socket = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let address = socket.local_addr().unwrap();
    let server = tokio::spawn(async move {
        let mut buffer = [0; 4096];
        for _ in 0..2 {
            let (length, peer) = socket.recv_from(&mut buffer).await.unwrap();
            let request = Message::from_vec(&buffer[..length]).unwrap();
            let query = request.queries[0].clone();
            let mut response =
                Message::new(request.metadata.id, MessageType::Response, OpCode::Query);
            response.metadata.recursion_desired = true;
            response.metadata.recursion_available = true;
            response.add_query(query.clone());
            let owner = query.name().to_ascii();
            if owner == "alias.example.com." {
                response.add_answer(Record::from_rdata(
                    query.name().clone(),
                    30,
                    RData::CNAME(CNAME(Name::from_ascii("target.provider.example.").unwrap())),
                ));
            } else {
                assert_eq!(owner, "target.provider.example.");
                response.add_answer(Record::from_rdata(
                    query.name().clone(),
                    30,
                    RData::CAA(CAA::new_issue(
                        true,
                        Some(Name::from_ascii("ca.example").unwrap()),
                        vec![],
                    )),
                ));
            }
            socket
                .send_to(&response.to_vec().unwrap(), peer)
                .await
                .unwrap();
        }
    });
    let mut nameserver = NameServerConfig::udp(address.ip());
    nameserver.connections[0].port = address.port();
    let lookup = SystemLookup(
        Resolver::builder_with_config(
            ResolverConfig::from_parts(None, vec![], vec![nameserver]),
            TokioRuntimeProvider::default(),
        )
        .build()
        .unwrap(),
    );
    let issuers = vec!["ca.example".into()];
    let req = Request {
        issuers: &issuers,
        account_uri: None,
        method: "http-01",
        wildcard: false,
    };
    let report = tokio::time::timeout(
        std::time::Duration::from_secs(3),
        check(&lookup, "alias.example.com", &req),
    )
    .await
    .unwrap()
    .unwrap();
    assert_eq!(report.observation, Observation::Matches);
    assert!(report.properties[0].critical);
    server.await.unwrap();
}

#[tokio::test]
async fn nonrestricting_child_set_shadows_restricting_parent_and_wildcard_comes_from_identifier() {
    let fake = Fake {
        values: HashMap::from([
            (
                "child.example.com.".into(),
                vec![record("iodef", "mailto:ops@example.com")],
            ),
            (
                "example.com.".into(),
                vec![record("issue", "ca.example"), record("issuewild", ";")],
            ),
        ]),
        queries: Mutex::new(vec![]),
        fails: false,
    };
    let issuers = vec!["ca.example".into()];
    let req = Request {
        issuers: &issuers,
        account_uri: None,
        method: "dns-01",
        wildcard: false,
    };
    assert_eq!(
        check(&fake, "child.example.com", &req)
            .await
            .unwrap()
            .observation,
        Observation::Unrestricted
    );
    assert_eq!(*fake.queries.lock().unwrap(), ["child.example.com."]);
    assert_eq!(
        check(&fake, "*.example.com", &req)
            .await
            .unwrap()
            .observation,
        Observation::NoMatch
    );
}
