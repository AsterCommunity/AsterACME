# aster_acme_dns_resolver

Hickory adapter for the read-only `aster_acme_dns::routing::DnsLookup` port.

`SystemDns::new` lazily loads the host resolver configuration. `with_resolver` injects a resolver for embedding and loopback tests. CNAME and TXT observations preserve resolver stages and causes; confirmed NODATA/NXDOMAIN is distinct from resolver failure. The adapter does not modify system DNS, filter nameservers, add public fallback resolvers, or mutate provider records.

The crate is used by the CLI external DNS path and is independent of optional advisory precheck features in the embedded client.

```sh
cargo test -p aster_acme_dns_resolver --locked
```

License: MIT OR Apache-2.0.
