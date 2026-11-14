//! Explicit embedding example; this observes DNS but never contacts an ACME CA.
use aster_acme::{precheck::Runner, solver::ExecutionContext};
use aster_acme_core::caa::Request;
use aster_acme_validation::caa::{Caa, SystemLookup};
use std::time::{Duration, Instant};

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let names = vec!["example.com".to_owned()];
    // Supply the actual directory's caaIdentities and your actual account URL.
    let issuers = vec!["letsencrypt.org".to_owned()];
    let lookup = SystemLookup::new()?;
    let check = Caa::new(
        &lookup,
        Request {
            issuers: &issuers,
            account_uri: None,
            method: "dns-01",
            wildcard: false,
        },
    );
    let execution = ExecutionContext {
        cancellation: tokio_util::sync::CancellationToken::new(),
        deadline: Instant::now() + Duration::from_secs(30),
    };
    let report = Runner::default().run(&check, &names, &execution).await?;
    // Interpret/report the evidence as needed. Neither NoMatch nor DNS failure
    // authorizes the client to replace the CA's own issuance decision.
    println!("{report:?}");
    Ok(())
}
