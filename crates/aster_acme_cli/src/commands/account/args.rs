//! Command-specific argument groups; registration flags never appear on local commands.
//! Shared groups are composed in declaration order, matching the public help sequence.

use crate::common::args::{HttpArgs, LocalArgs, parse_account_name};
use aster_acme::crypto::key_algorithm::KeyAlgorithm;
use clap::Subcommand;
use std::path::PathBuf;

#[derive(Subcommand)]
pub(crate) enum AccountCommand {
    /// List saved accounts and the default selection without contacting a CA.
    #[command(group(clap::ArgGroup::new("list_verification_http").args(["user_agent", "request_timeout"]).multiple(true).requires("verify")))]
    List(ListArgs),
    /// Inspect local metadata; --verify queries the CA; --profiles lists the
    /// advertised certificate profiles.
    #[command(group(clap::ArgGroup::new("verification_http").args(["user_agent", "request_timeout"]).multiple(true).requires("verify")))]
    Show {
        #[command(flatten)]
        options: NetworkArgs,
        #[arg(long)]
        /// Query the current CA status instead of only viewing local data.
        verify: bool,
        /// List the certificate profiles the CA advertises
        /// ([draft-ietf-acme-profiles](https://datatracker.ietf.org/doc/html/draft-ietf-acme-profiles));
        /// contacts the CA directory.
        #[arg(long)]
        profiles: bool,
    },
    /// Select a registered local account as the default, without HTTP.
    Default(LocalTargetArgs),
    /// Register a new account or confirm reuse of a saved identity.
    Register(RegisterArgs),
    /// Find an existing CA account using its saved key; never create one.
    Recover(NetworkArgs),
    /// Update account preferences: CA contacts, the default certificate
    /// profile, or the future terms delegation.
    Update(UpdateArgs),
    /// Rotate the account signing key, or resume its saved rollover transaction.
    RotateKey(RotateKeyArgs),
    /// Remove local account metadata and private key; --deactivate also
    /// irreversibly deactivates the account at the CA.
    Remove(RemoveArgs),
}

/// Replace contacts, set or clear the default certificate profile, and/or
/// change the future terms delegation. Contact changes update the CA account;
/// profile and delegation preferences are local metadata (the delegation is
/// validated against the live directory before it is enabled). All scopes may
/// be combined. Skipping terms confirmation requires an explicit terms flag
/// plus `--yes`; otherwise an interactive terminal asks separately.
#[expect(
    clippy::struct_excessive_bools,
    reason = "Independent contact, profile, delegation and confirmation switches"
)]
#[derive(clap::Args, Default)]
pub(crate) struct UpdateArgs {
    #[command(flatten)]
    pub(crate) network: NetworkArgs,
    /// Complete replacement contact list; repeat for multiple email addresses.
    #[arg(short = 'm', long, conflicts_with = "clear_contacts")]
    pub(crate) contact: Vec<String>,
    /// Remove all CA contacts explicitly.
    #[arg(long)]
    pub(crate) clear_contacts: bool,
    /// Profile name to set; the CA directory must advertise it.
    #[arg(
        long,
        value_name = "NAME",
        value_parser = crate::commands::cert::args::parse_profile,
        conflicts_with = "clear_profile"
    )]
    pub(crate) profile: Option<String>,
    /// Remove the saved default profile so new issues use the CA default.
    #[arg(long)]
    pub(crate) clear_profile: bool,
    /// Accept the CA's current terms and automatically accept future terms URL
    /// updates; stored locally without a CA account request. Combinable with
    /// contact and profile changes. Use `--yes` with this flag to skip the
    /// separate terms confirmation; otherwise confirm interactively.
    #[arg(long, conflicts_with = "clear_auto_accept_new_terms")]
    pub(crate) auto_accept_new_terms: bool,
    /// Stop automatically accepting future terms URL updates; the saved
    /// accepted terms URL is retained (local metadata only).
    #[arg(long)]
    pub(crate) clear_auto_accept_new_terms: bool,
    /// Confirm this update without prompting.
    #[arg(short = 'y', long)]
    pub(crate) yes: bool,
}

impl UpdateArgs {
    /// Any contact replacement intent, including an explicit clear.
    pub(crate) fn contact_set(&self) -> bool {
        !self.contact.is_empty()
    }

    /// Any profile preference intent, including an explicit clear.
    pub(crate) fn profile_set(&self) -> bool {
        self.profile.is_some()
    }
}

#[derive(Clone, clap::Args, Default)]
pub(crate) struct NameArgs {
    /// Local account name; omit to select interactively or use the configured default.
    #[arg(index = 1, value_name = "NAME", conflicts_with = "name", value_parser = parse_account_name)]
    pub(crate) positional_name: Option<String>,
    /// Local account name; omit to select interactively or use the configured default.
    #[arg(short = 'n', long, value_parser = parse_account_name)]
    pub(crate) name: Option<String>,
}

impl NameArgs {
    fn resolve(self) -> Option<String> {
        self.positional_name.or(self.name)
    }
}

#[derive(clap::Args, Default)]
pub(crate) struct LocalTargetArgs {
    #[command(flatten)]
    pub(crate) identity: NameArgs,
    #[command(flatten)]
    pub(crate) local: LocalArgs,
}

#[derive(clap::Args)]
pub(crate) struct RemoveArgs {
    #[command(flatten)]
    pub(crate) target: LocalTargetArgs,
    /// Also deactivate the account at the CA; this cannot be undone and
    /// requires the account key.
    #[arg(long)]
    pub(crate) deactivate: bool,
    #[command(flatten)]
    pub(crate) network_only_http: HttpArgs,
    /// Confirm deletion of local account metadata and private key without prompting.
    #[arg(short = 'y', long)]
    pub(crate) yes: bool,
}

impl From<RemoveArgs> for AccountArgs {
    fn from(args: RemoveArgs) -> Self {
        Self {
            yes: args.yes,
            user_agent: args.network_only_http.user_agent,
            request_timeout: args.network_only_http.request_timeout,
            ..args.target.into()
        }
    }
}

impl From<LocalTargetArgs> for AccountArgs {
    fn from(args: LocalTargetArgs) -> Self {
        Self {
            name: args.identity.resolve(),
            ..args.local.into()
        }
    }
}

#[derive(Clone, clap::Args, Default)]
pub(crate) struct CaArgs {
    /// Public CA preset; letsencrypt, zerossl or google.
    #[arg(long, value_parser = crate::ca::ProviderParser, conflicts_with = "ca_directory")]
    pub(crate) ca: Option<aster_acme_protocol::directory::Provider>,
    /// Full ACME directory URL; must match an existing account's bound CA.
    #[arg(long, value_name = "URL", conflicts_with = "ca")]
    pub(crate) ca_directory: Option<String>,
}

#[derive(clap::Args, Default)]
#[group(id = "list_options", multiple = true)]
pub(crate) struct ListArgs {
    /// Query each account's CA; keep other results when an account fails verification.
    #[arg(long)]
    pub(crate) verify: bool,
    #[command(flatten)]
    pub(crate) http: HttpArgs,
    #[command(flatten)]
    pub(crate) local: LocalArgs,
}

impl From<LocalArgs> for ListArgs {
    fn from(local: LocalArgs) -> Self {
        Self {
            local,
            ..Self::default()
        }
    }
}

#[derive(Clone, clap::Args, Default)]
pub(crate) struct NetworkArgs {
    #[command(flatten)]
    pub(crate) identity: NameArgs,
    #[command(flatten)]
    pub(crate) ca: CaArgs,
    #[command(flatten)]
    pub(crate) http: HttpArgs,
    #[command(flatten)]
    pub(crate) local: LocalArgs,
}

#[derive(clap::Args, Default)]
pub(crate) struct RegisterArgs {
    #[command(flatten)]
    pub(crate) identity: NameArgs,
    /// Contact email; repeat for multiple addresses (mailto: is also accepted).
    #[arg(short = 'm', long)]
    pub(crate) contact: Vec<String>,
    /// Account signing key; new accounts default to ecdsa-p256, existing keys must match.
    #[arg(short = 'k', long = "key-type", value_parser = crate::common::args::key_algorithm_parser())]
    pub(crate) key_algorithm: Option<KeyAlgorithm>,
    #[command(flatten)]
    pub(crate) ca: CaArgs,
    /// Explicitly accept the selected CA's current terms; otherwise ask interactively.
    #[arg(long)]
    pub(crate) accept_terms: bool,
    /// Accept the current terms and persist consent to future CA terms URL updates.
    #[arg(long)]
    pub(crate) auto_accept_new_terms: bool,
    #[command(flatten)]
    pub(crate) http: HttpArgs,
    /// Default certificate profile for this account; the CA directory must
    /// advertise it (see account profiles). cert issue --profile overrides it.
    #[arg(long, value_parser = crate::commands::cert::args::parse_profile)]
    pub(crate) profile: Option<String>,
    /// Confirm existing account reuse; does not accept terms or disable other prompts.
    #[arg(short = 'y', long)]
    pub(crate) yes: bool,
    #[command(flatten)]
    pub(crate) local: LocalArgs,
    /// EAB credential ID issued by the CA.
    #[arg(
        long,
        requires = "eab_key_file",
        help_heading = "Advanced registration (EAB)"
    )]
    pub(crate) eab_kid: Option<String>,
    /// File containing the base64url EAB secret; never put secrets in arguments.
    #[arg(
        long,
        requires = "eab_kid",
        value_name = "PATH",
        help_heading = "Advanced registration (EAB)"
    )]
    pub(crate) eab_key_file: Option<PathBuf>,
}

#[derive(clap::Args, Default)]
pub(crate) struct RotateKeyArgs {
    /// New account key type; omit to keep the old type or resume the staged key.
    #[arg(short = 'k', long = "key-type", value_parser = crate::common::args::key_algorithm_parser())]
    pub(crate) key_algorithm: Option<KeyAlgorithm>,
    #[command(flatten)]
    pub(crate) network: NetworkArgs,
    /// Confirm key rotation or reconciliation without prompting.
    #[arg(short = 'y', long)]
    pub(crate) yes: bool,
}

/// Resolved execution input, shared by CLI parsing and interactive completion.
#[expect(
    clippy::struct_excessive_bools,
    reason = "These booleans are independent command-wide output and confirmation switches"
)]
#[derive(Default)]
pub(crate) struct AccountArgs {
    pub(crate) key_algorithm: Option<KeyAlgorithm>,
    /// Confirm this command's action only; never accept terms or bypass validation.
    pub(crate) yes: bool,
    /// Explicit ACME directory URL (default: Let's Encrypt).
    pub(crate) ca_directory: Option<String>,
    /// Unified state root (default: the system configuration directory for com.astercosm.acme).
    pub(crate) data_dir: Option<PathBuf>,
    /// Use this account for this invocation; does not change the saved default.
    pub(crate) name: Option<String>,
    /// Account email address, e.g. admin@example.org; repeatable (mailto: also accepted).
    pub(crate) contact: Vec<String>,
    /// Agree to the current terms published by the selected CA (register only).
    pub(crate) accept_terms: bool,
    /// Default certificate profile to save on a new account (register only).
    pub(crate) profile: Option<String>,
    /// Accept current terms and future terms URL updates (register only).
    pub(crate) auto_accept_new_terms: bool,
    /// EAB key ID; use --eab-key-file for its base64url HMAC key.
    pub(crate) eab_kid: Option<String>,
    /// Read the EAB secret from a file; never put the secret itself in CLI arguments.
    pub(crate) eab_key_file: Option<PathBuf>,
    /// Custom HTTP User-Agent (default: AsterACME/version).
    pub(crate) user_agent: Option<String>,
    /// Single HTTP request timeout in seconds (1–300).
    pub(crate) request_timeout: Option<u64>,
    /// Plain structured JSON; no terminal styling.
    pub(crate) json: bool,
}

impl From<LocalArgs> for AccountArgs {
    fn from(args: LocalArgs) -> Self {
        Self {
            data_dir: args.data_dir,
            json: args.json,
            ..Self::default()
        }
    }
}

impl From<NetworkArgs> for AccountArgs {
    fn from(args: NetworkArgs) -> Self {
        Self {
            name: args.identity.resolve(),
            ca_directory: args
                .ca
                .ca
                .map(|ca| ca.directory().to_owned())
                .or(args.ca.ca_directory),
            user_agent: args.http.user_agent,
            request_timeout: args.http.request_timeout,
            ..args.local.into()
        }
    }
}

impl From<RegisterArgs> for AccountArgs {
    fn from(args: RegisterArgs) -> Self {
        Self {
            yes: args.yes,
            key_algorithm: args.key_algorithm,
            contact: args.contact,
            accept_terms: args.accept_terms,
            profile: args.profile,
            auto_accept_new_terms: args.auto_accept_new_terms,
            eab_kid: args.eab_kid,
            eab_key_file: args.eab_key_file,
            ..NetworkArgs {
                identity: args.identity,
                ca: args.ca,
                http: args.http,
                local: args.local,
            }
            .into()
        }
    }
}

impl AccountCommand {
    pub(crate) fn json(&self) -> bool {
        match self {
            Self::RotateKey(args) => args.network.local.json,
            Self::Update(args) => args.network.local.json,
            Self::Remove(args) => args.target.local.json,
            Self::List(args) => args.local.json,
            Self::Register(args) => args.local.json,
            Self::Recover(args) | Self::Show { options: args, .. } => args.local.json,
            Self::Default(args) => args.local.json,
        }
    }
}
