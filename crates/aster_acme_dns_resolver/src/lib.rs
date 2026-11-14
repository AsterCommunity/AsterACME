//! System-recursive DNS observations for `AsterACME` routing and propagation.
#![cfg_attr(
    not(test),
    deny(
        clippy::unwrap_used,
        clippy::expect_used,
        clippy::panic,
        clippy::unreachable,
        clippy::unimplemented,
        clippy::todo
    )
)]
use aster_acme_dns::routing::{DnsLookup, LookupError};
use async_trait::async_trait;
use hickory_resolver::{
    Resolver, TokioResolver,
    net::NetError,
    proto::rr::{Name, RData, RecordType},
};

/// Resolver adapter. No provider API calls or DNS mutation take place here.
pub struct SystemDns(tokio::sync::OnceCell<TokioResolver>);
impl SystemDns {
    /// Use the configured system resolver, preserving initialization failures.
    /// # Errors
    /// Does not filter/repair invalid nameservers or fall back to public DNS.
    #[must_use]
    pub const fn new() -> Self {
        Self(tokio::sync::OnceCell::const_new())
    }

    async fn resolver(&self) -> Result<&TokioResolver, LookupError> {
        self.0
            .get_or_try_init(|| async {
                let mut builder = Resolver::builder_tokio()
                    .map_err(|error| lookup_error("cannot load system DNS configuration", error))?;
                builder.options_mut().cache_size = 0;
                builder
                    .build()
                    .map_err(|error| lookup_error("cannot build local DNS resolver", error))
            })
            .await
    }

    /// Inject an already-configured resolver (for embedded hosts and loopback tests).
    #[must_use]
    pub fn with_resolver(resolver: TokioResolver) -> Self {
        Self(tokio::sync::OnceCell::new_with(Some(resolver)))
    }
}
#[async_trait]
impl DnsLookup for SystemDns {
    async fn cname(&self, name: &str) -> Result<Option<String>, LookupError> {
        let owner = Name::from_ascii(name).map_err(|error| LookupError {
            stage: "invalid DNS owner",
            cause: Box::new(error),
        })?;
        match self
            .resolver()
            .await?
            .lookup(owner.clone(), RecordType::CNAME)
            .await
        {
            Ok(answer) => {
                let mut targets = answer
                    .answers()
                    .iter()
                    .filter(|record| record.name == owner)
                    .filter_map(|record| match &record.data {
                        RData::CNAME(target) => Some(target.0.to_ascii()),
                        _ => None,
                    });
                let target = targets.next();
                if targets.any(|next| Some(&next) != target.as_ref()) {
                    return Err(lookup_error(
                        "conflicting CNAME answers",
                        NetError::from("multiple CNAME targets at owner"),
                    ));
                }
                Ok(target)
            }
            Err(error) if empty_answer(&error) => Ok(None),
            Err(error) => Err(lookup_error("CNAME query failed", error)),
        }
    }
    async fn txt(&self, name: &str) -> Result<Vec<Vec<u8>>, LookupError> {
        match self.resolver().await?.txt_lookup(name).await {
            Ok(answer) => Ok(answer
                .answers()
                .iter()
                .filter_map(|record| match &record.data {
                    RData::TXT(txt) => Some(
                        txt.txt_data
                            .iter()
                            .flat_map(|chunk| chunk.iter().copied())
                            .collect(),
                    ),
                    _ => None,
                })
                .collect()),
            Err(error) if empty_answer(&error) => Ok(Vec::new()),
            Err(error) => Err(lookup_error("TXT query failed", error)),
        }
    }
}
fn lookup_error(stage: &'static str, cause: NetError) -> LookupError {
    LookupError {
        stage,
        cause: Box::new(cause),
    }
}
fn empty_answer(error: &NetError) -> bool {
    matches!(error, NetError::Dns(hickory_resolver::net::DnsError::NoRecordsFound(records))
        if matches!(records.response_code, hickory_resolver::proto::op::ResponseCode::NoError | hickory_resolver::proto::op::ResponseCode::NXDomain))
}

impl Default for SystemDns {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use crate::SystemDns;
    use aster_acme_dns::{ProviderExecution, routing::DnsLookup, routing::resolve};
    use hickory_resolver::{
        Resolver,
        config::{NameServerConfig, ResolverConfig},
        net::runtime::TokioRuntimeProvider,
        proto::{
            op::{Message, MessageType, OpCode, ResponseCode},
            rr::{
                Name, RData, Record, RecordType,
                rdata::{CNAME, TXT},
            },
        },
    };
    #[tokio::test]
    async fn loopback_dns_preserves_cname_owner_and_joins_txt_chunks_per_rr() {
        let socket = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let address = socket.local_addr().unwrap();
        let server = tokio::spawn(async move {
            let mut bytes = [0_u8; 4096];
            loop {
                let (length, peer) = socket.recv_from(&mut bytes).await.unwrap();
                let request = Message::from_vec(&bytes[..length]).unwrap();
                let query = request.queries[0].clone();
                let mut response =
                    Message::new(request.metadata.id, MessageType::Response, OpCode::Query);
                response.metadata.recursion_desired = true;
                response.metadata.recursion_available = true;
                response.add_query(query.clone());
                match query.query_type() {
                    RecordType::CNAME
                        if query.name().to_ascii() == "_acme-challenge.example.com." =>
                    {
                        response.add_answer(Record::from_rdata(
                            query.name().clone(),
                            0,
                            RData::CNAME(CNAME(
                                Name::from_ascii("delegated.validation.net.").unwrap(),
                            )),
                        ));
                    }
                    RecordType::TXT => {
                        response.add_answer(Record::from_rdata(
                            query.name().clone(),
                            0,
                            RData::TXT(TXT::new(vec!["expected".into(), "-value".into()])),
                        ));
                        response.add_answer(Record::from_rdata(
                            query.name().clone(),
                            0,
                            RData::TXT(TXT::new(vec!["unrelated".into()])),
                        ));
                    }
                    _ => {
                        response.metadata.response_code = ResponseCode::NoError;
                    }
                }
                socket
                    .send_to(&response.to_vec().unwrap(), peer)
                    .await
                    .unwrap();
            }
        });
        let mut server_config = NameServerConfig::udp(address.ip());
        server_config.connections[0].port = address.port();
        let resolver = Resolver::builder_with_config(
            ResolverConfig::from_parts(None, vec![], vec![server_config]),
            TokioRuntimeProvider::default(),
        )
        .build()
        .unwrap();
        let lookup = SystemDns::with_resolver(resolver);
        let scope = ProviderExecution {
            cancellation: tokio_util::sync::CancellationToken::new(),
            deadline: std::time::Instant::now() + std::time::Duration::from_secs(5),
        };
        let chain = resolve(
            &lookup,
            "_acme-challenge.example.com",
            &["validation.net".into()],
            &scope,
        )
        .await
        .unwrap();
        assert_eq!(
            chain,
            ["_acme-challenge.example.com.", "delegated.validation.net."]
        );
        assert_eq!(
            lookup.txt("delegated.validation.net.").await.unwrap(),
            [b"expected-value".to_vec(), b"unrelated".to_vec()]
        );
        server.abort();
    }
}
