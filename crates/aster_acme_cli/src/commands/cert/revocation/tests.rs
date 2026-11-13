use crate::{
    app::{Args, Command},
    commands::cert::args::CertCommand,
};
use aster_acme::revocation::RevocationSigningMethod;
use clap::Parser as _;

#[test]
fn explicit_signing_modes_are_scoped_and_account_remains_the_default() {
    for (flags, expected) in [
        (vec![], RevocationSigningMethod::Account),
        (
            vec!["--sign-with", "certificate-key"],
            RevocationSigningMethod::CertificateKey,
        ),
    ] {
        let args = Args::try_parse_from(
            ["aster-acme", "cert", "revoke", "web"]
                .into_iter()
                .chain(flags),
        )
        .unwrap();
        let Command::Cert {
            command: CertCommand::Revoke(args),
        } = args.command
        else {
            panic!("expected revoke");
        };
        assert_eq!(args.sign_with, expected);
    }
    assert!(
        Args::try_parse_from([
            "aster-acme",
            "cert",
            "revoke",
            "web",
            "--sign-with",
            "automatic"
        ])
        .is_err()
    );
    for command in ["show", "issue", "renew", "remove"] {
        assert!(
            Args::try_parse_from([
                "aster-acme",
                "cert",
                command,
                "--sign-with",
                "certificate-key"
            ])
            .is_err()
        );
    }
}

mod flow;
