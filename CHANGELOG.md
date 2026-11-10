# Changelog

## [Unreleased]

### Added

- Pure ACME resource-state decisions and upper-layer DNS identifiers, challenge selection/material derivation, and injectable solver contracts with versioned recovery receipts. Known and unknown wire values, input boundaries, and selection combinations have regression coverage; network issuance and concrete solvers remain unimplemented.

- Rust workspace with protocol core, client orchestration, DNS solver, and CLI crate boundaries. Dependencies and Forge-aligned strict lints are managed at the workspace root. Certificate operations are not implemented yet.

[Unreleased]: https://github.com/AsterCommunity/AsterACME/commits/main/
