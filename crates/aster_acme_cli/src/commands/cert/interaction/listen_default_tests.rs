//! Listener default by validation port and identifier address family.

use crate::commands::cert::interaction::listen_default;
use aster_acme::identifier::IpIdentifier;

#[test]
fn serves_the_address_family_the_ca_will_dial() {
    let addresses = |literals: &[&str]| {
        literals
            .iter()
            .map(|address| IpIdentifier::new(address).unwrap())
            .collect::<Vec<_>>()
    };
    // Pure IPv4 keeps the historical wildcard.
    assert_eq!(
        listen_default(80, &addresses(&["192.0.2.10", "198.51.100.7"])),
        "0.0.0.0:80"
    );
    // Pure IPv6 and mixed IPv4+IPv6: the CA dials the IPv6 literal, so the
    // default must be the dual-stack address.
    assert_eq!(listen_default(80, &addresses(&["2001:db8::1"])), "[::]:80");
    assert_eq!(
        listen_default(443, &addresses(&["192.0.2.10", "2001:db8::1"])),
        "[::]:443"
    );
    // No address input (DNS-only issuance keeps no IP entry) defaults to the
    // historical IPv4 wildcard.
    assert_eq!(listen_default(80, &addresses(&[])), "0.0.0.0:80");
}
