//! Optional TXT precheck adapter with one resolver shared across the stage.
use aster_acme::{
    issuance::ValidationRequirement,
    precheck::{Check, Failure},
    solver::ExecutionContext,
};
use async_trait::async_trait;
use hickory_resolver::{Resolver, TokioResolver};

/// No publication, mutation or CA validation is performed.
pub struct Txt {
    resolver: TokioResolver,
}
impl Txt {
    /// Inject an existing resolver, including application-specific DNS configuration.
    #[must_use]
    pub const fn new(resolver: TokioResolver) -> Self {
        Self { resolver }
    }

    /// Load the operator's recursive resolver configuration; no DNS query yet.
    /// # Errors
    /// Returns unavailable when system configuration cannot be loaded.
    pub fn system() -> Result<Self, Failure> {
        Ok(Self {
            resolver: Resolver::builder_tokio()
                .map_err(|_| Failure::Unavailable)?
                .build()
                .map_err(|_| Failure::Unavailable)?,
        })
    }
}
#[async_trait]
impl Check for Txt {
    type Input = ValidationRequirement;
    type Output = bool;
    async fn observe(&self, input: &Self::Input, _: &ExecutionContext) -> Result<bool, Failure> {
        let ValidationRequirement::Dns01 { name, value } = input else {
            return Err(Failure::UnsupportedInput);
        };
        crate::dns01::visibility::observe_lookup(
            self.resolver.txt_lookup(format!("{name}.")).await,
            value,
        )
        .map_err(|_| Failure::LookupFailed)
    }
}

#[cfg(test)]
mod tests {
    use crate::txt::*;
    use aster_acme::precheck::Runner;
    use hickory_resolver::{
        config::{NameServerConfig, ResolverConfig},
        net::runtime::TokioRuntimeProvider,
        proto::{
            op::{Message, MessageType, OpCode},
            rr::{RData, Record, rdata::TXT},
        },
    };
    #[tokio::test]
    async fn embedded_txt_checker_uses_injected_resolver_and_reports_mismatch_without_rejection() {
        let socket = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let address = socket.local_addr().unwrap();
        let server = tokio::spawn(async move {
            let mut bytes = [0; 4096];
            for _ in 0..2 {
                let (length, peer) = socket.recv_from(&mut bytes).await.unwrap();
                let request = Message::from_vec(&bytes[..length]).unwrap();
                let query = request.queries[0].clone();
                let mut response =
                    Message::new(request.metadata.id, MessageType::Response, OpCode::Query);
                response.metadata.recursion_desired = true;
                response.metadata.recursion_available = true;
                response.add_query(query.clone());
                response.add_answer(Record::from_rdata(
                    query.name().clone(),
                    0,
                    RData::TXT(TXT::new(vec!["token".into(), ".thumb".into()])),
                ));
                socket
                    .send_to(&response.to_vec().unwrap(), peer)
                    .await
                    .unwrap();
            }
        });
        let mut nameserver = NameServerConfig::udp(address.ip());
        nameserver.connections[0].port = address.port();
        let resolver = Resolver::builder_with_config(
            ResolverConfig::from_parts(None, vec![], vec![nameserver]),
            TokioRuntimeProvider::default(),
        )
        .build()
        .unwrap();
        let check = Txt::new(resolver);
        let inputs = [
            ValidationRequirement::Dns01 {
                name: "_acme-challenge.one.example".into(),
                value: "token.thumb".into(),
            },
            ValidationRequirement::Dns01 {
                name: "_acme-challenge.two.example".into(),
                value: "wrong".into(),
            },
            ValidationRequirement::Http01 {
                url: "http://example.com/".into(),
                path: "/".into(),
                content: "token.thumb".into(),
            },
        ];
        let execution = ExecutionContext {
            cancellation: tokio_util::sync::CancellationToken::new(),
            deadline: std::time::Instant::now() + std::time::Duration::from_secs(3),
        };
        let report = Runner::default()
            .run(&check, &inputs, &execution)
            .await
            .unwrap();
        assert_eq!(report.observations[0].result, Ok(true));
        assert_eq!(report.observations[1].result, Ok(false));
        assert_eq!(
            report.observations[2].result,
            Err(Failure::UnsupportedInput)
        );
        server.await.unwrap();
    }
}
