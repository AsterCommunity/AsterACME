# Security Policy

Thank you for helping keep AsterACME and its users safe. AsterACME stores account keys, certificate private keys, DNS provider credentials, and CA interactions on the operator's machine, so security reports are most useful when they clearly describe the affected version, platform, and how the data directory was configured.

## Supported Versions

AsterACME is still evolving quickly and has not reached a stable release. Security fixes are handled for the active development line and the latest tagged release.

| Version or branch | Security support |
| --- | --- |
| `main` | Supported for current development |
| Latest tagged release (including `0.1.0-alpha.*`) | Supported |
| Older releases | Best effort only; upgrade is recommended |

Pre-release versions may change local file formats and APIs between tags. If a vulnerability affects an older release and the fix is low risk, maintainers may provide backport guidance. Otherwise, upgrade to the latest release containing the fix.

## Reporting a Vulnerability

Please do not report security vulnerabilities through public GitHub issues, pull requests, discussions, or review comments.

Use one of these private channels instead:

- GitHub Private Vulnerability Reporting, if it is available for this repository
- Email: `report@esaps.net` with a subject starting with `[AsterACME Security]`

Include as much of the following as you reasonably can:

- affected AsterACME version, git commit, or container image tag
- platform (Linux, macOS, Windows) and how AsterACME was installed and run (CLI, resident daemon, cron, systemd, or container)
- the vulnerable command, crate, or code path, if known
- data directory layout details that matter, such as unusual `--data-dir` placement, mounted volumes, or non-default file permissions
- clear reproduction steps or a minimal proof of concept
- expected impact, such as private key disclosure, credential leakage, unintended file writes outside deployment targets, command execution beyond configured reload commands, DNS record tampering, or denial of service
- relevant logs, command output, or stack traces with secrets and private keys redacted

Do not include real account keys, certificate private keys, DNS provider tokens, EAB credentials, or files copied from systems you do not own. Redact sensitive values before sending logs or command output.

## Response Expectations

Maintainers aim to:

- acknowledge a report within 5 business days
- provide an initial triage result within 14 business days when enough information is available
- keep the reporter updated when a fix is being prepared
- coordinate disclosure timing before publishing details

These are targets, not service-level guarantees. Small self-hosted projects can have uneven maintainer availability, but actionable private reports will be handled in good faith.

## Disclosure Process

The usual process is:

1. The reporter sends a private report.
2. Maintainers confirm whether the behavior is a security issue.
3. Maintainers prepare and test a fix.
4. A patched release, advisory, or mitigation note is published.
5. Public details can be discussed after users have had a reasonable chance to upgrade or apply mitigations.

Please do not publish exploit details, working proof-of-concept code, or broad scanning instructions before a fix or mitigation is available.

## Scope

Security reports are in scope when they affect AsterACME itself, including:

- handling, permissions, and storage of account keys and certificate private keys in the data directory, including lock files, `.removing` markers, and interrupted-operation recovery
- protection of DNS provider profiles and settings files, including API tokens, `token_file` reads, and `provider_custom` secrets that must not appear in logs, journals, or public output
- EAB credential handling during registration
- path handling in certificate deployment, including symlink, hard-link, and reparse-point behavior of target directories and published files
- execution of configured reload commands: running processes beyond the configured argv, unbounded output collection, or unintended retries
- the temporary standalone HTTP-01 and TLS-ALPN-01 listeners serving content or certificates beyond the saved challenge material
- the external DNS provider protocol (ADPP) boundary, including stdin context inheritance and handling of external executables
- unintended certificate issuance, revocation, account modification, or DNS writes triggered by interrupted operations or recovery paths
- sensitive information disclosure through logs, JSON output, `--debug` diagnostics, `crash.log`, saved journals, or command results
- container image integrity, including published tags, signing, and SBOM/provenance attestations
- exploitable dependency issues in the Rust crates AsterACME ships

The following are usually out of scope unless they demonstrate a concrete exploit against AsterACME:

- vulnerabilities only present in unsupported old releases
- misconfigured deployments, such as world-readable data directories, exporting `/data` volumes with unintended permissions, or mounting deployment targets into unrelated services
- the content or behavior of operator-supplied reload commands and DNS provider executables, beyond AsterACME failing to enforce its own execution boundaries
- CA-side behavior, policy decisions, rate limits, or problems with Let's Encrypt, ZeroSSL, Google Trust Services, or any other certificate authority
- generic dependency CVEs with no reachable or practical impact in AsterACME
- denial-of-service reports based only on unrealistic traffic volume or resource exhaustion without a specific application flaw
- social engineering, phishing, or attacks against third-party services not controlled by the project
- the removal of DNS TXT records by operators or external automation, which AsterACME explicitly does not own after cleanup completes

## Research Rules

When testing AsterACME:

- test only systems you own or where you have explicit permission
- use ACME staging environments and DNS zones you control; do not issue certificates for domains you do not administer
- prefer local or disposable test deployments with a dedicated `--data-dir`
- keep proof-of-concept payloads minimal and non-destructive
- do not exfiltrate, publish, or reuse private keys, account credentials, or DNS provider tokens discovered during testing
- do not modify or delete DNS records outside the zones you own
- stop testing and report privately if you discover access to data or capabilities outside your authorization

Good-faith research that follows this policy helps the project. Activity that harms users, damages systems, or exposes private data is not acceptable.

## Security Advisories

Published security advisories are listed at [GitHub Security Advisories](https://github.com/AsterCommunity/AsterACME/security/advisories).

## Security Updates

Security fixes may be released as normal patch releases, GitHub security advisories, release notes, or mitigation guidance, depending on severity and available information.

Users running public or shared deployments should:

- keep AsterACME updated
- keep the data directory private to the service user; Unix key files are written with `0600` and parent directories are not loosened by the CLI
- restrict DNS provider tokens to the minimum zone scope the automation needs
- review configured reload commands and deployment targets after suspected compromise
- revoke affected certificates with `cert revoke` and rotate account keys with `account rotate-key` when keys or credentials are suspected to have leaked
