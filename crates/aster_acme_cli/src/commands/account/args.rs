//! Command-specific argument groups; registration flags never appear on local commands.
//! Shared groups are composed in declaration order, matching the public help sequence.

use clap::Subcommand;
use std::path::PathBuf;

#[derive(Subcommand)]
pub(crate) enum AccountCommand {
    /// List saved accounts and the default selection without contacting a CA.
    #[command(group(clap::ArgGroup::new("list_verification_http").args(["user_agent", "timeout"]).multiple(true).requires("verify")))]
    List(ListArgs),
    /// Inspect local metadata; --verify explicitly queries the CA.
    #[command(group(clap::ArgGroup::new("verification_http").args(["user_agent", "timeout"]).multiple(true).requires("verify")))]
    Show {
        #[command(flatten)]
        options: NetworkArgs,
        #[arg(long)]
        /// Query the current CA status instead of only viewing local data.
        verify: bool,
    },
    /// Select a registered local account as the default, without HTTP.
    Switch(LocalTargetArgs),
    /// Register a new account or confirm reuse of a saved identity.
    Register(RegisterArgs),
    /// Find an existing CA account using its saved key; never create one.
    Recover(NetworkArgs),
    /// Replace or clear the contact addresses on an existing CA account.
    UpdateContact(UpdateContactArgs),
    /// Rotate the account signing key, or resume its saved rollover transaction.
    RotateKey(RotateKeyArgs),
    /// Permanently deactivate a CA account; this cannot be undone.
    Deactivate(DeactivateArgs),
    /// Remove local account metadata and private key; does not deactivate the CA account.
    Remove(RemoveArgs),
}

#[derive(clap::Args, Default)]
pub(crate) struct LocalArgs {
    /// Unified state root (default: system directory for com.astercosm.acme).
    #[arg(long, value_name = "PATH", help_heading = "Storage and output")]
    pub(crate) data_dir: Option<PathBuf>,
    /// Structured JSON; disables interactive prompts and terminal styling.
    #[arg(long, help_heading = "Storage and output")]
    pub(crate) json: bool,
}

#[derive(clap::Args, Default)]
pub(crate) struct NameArgs {
    /// Local account name; omit to select interactively or use the configured default.
    #[arg(index = 1, value_name = "NAME", conflicts_with = "name", value_parser = parse_name)]
    pub(crate) positional_name: Option<String>,
    /// Local account name; omit to select interactively or use the configured default.
    #[arg(long, value_parser = parse_name)]
    pub(crate) name: Option<String>,
}

impl NameArgs {
    fn resolve(self) -> Option<String> {
        self.positional_name.or(self.name)
    }
}

fn parse_name(value: &str) -> Result<String, String> {
    if aster_acme_cli_storage::valid_account_name(value) {
        Ok(value.to_owned())
    } else {
        Err("Use 1–64 ASCII letters, digits, hyphens or underscores for the account name.".into())
    }
}

#[derive(clap::Args, Default)]
pub(crate) struct LocalTargetArgs {
    #[command(flatten)]
    pub(crate) identity: NameArgs,
    #[command(flatten)]
    pub(crate) local: LocalArgs,
}

#[derive(clap::Args, Default)]
pub(crate) struct RemoveArgs {
    #[command(flatten)]
    pub(crate) target: LocalTargetArgs,
    /// Confirm deletion of local account metadata and private key without prompting.
    #[arg(long)]
    pub(crate) yes: bool,
}

impl From<RemoveArgs> for AccountArgs {
    fn from(args: RemoveArgs) -> Self {
        Self {
            yes: args.yes,
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

#[derive(clap::Args, Default)]
pub(crate) struct CaArgs {
    /// Public CA preset; letsencrypt, zerossl or google.
    #[arg(long, value_parser = crate::ca::ProviderParser, conflicts_with = "ca_directory")]
    pub(crate) ca: Option<aster_acme_protocol::directory::Provider>,
    /// Full ACME directory URL; must match an existing account's bound CA.
    #[arg(long, value_name = "URL", conflicts_with = "ca")]
    pub(crate) ca_directory: Option<String>,
}

#[derive(clap::Args, Default)]
pub(crate) struct HttpArgs {
    /// HTTP User-Agent override; an explicit value during registration is saved for this account.
    #[arg(long)]
    pub(crate) user_agent: Option<String>,
    /// Whole-request timeout in seconds (1–300); used only for HTTP.
    #[arg(long, value_parser = clap::value_parser!(u64).range(1..=300))]
    pub(crate) timeout: Option<u64>,
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

#[derive(clap::Args, Default)]
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
    #[arg(long)]
    pub(crate) contact: Vec<String>,
    #[command(flatten)]
    pub(crate) ca: CaArgs,
    /// Explicitly accept the selected CA's current terms; otherwise ask interactively.
    #[arg(long)]
    pub(crate) accept_terms: bool,
    #[command(flatten)]
    pub(crate) http: HttpArgs,
    /// Confirm existing account reuse; does not accept terms or disable other prompts.
    #[arg(long)]
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
pub(crate) struct DeactivateArgs {
    #[command(flatten)]
    pub(crate) network: NetworkArgs,
    /// Confirm irreversible CA account deactivation without an interactive prompt.
    #[arg(long)]
    pub(crate) yes: bool,
}

#[derive(clap::Args, Default)]
pub(crate) struct UpdateContactArgs {
    #[command(flatten)]
    pub(crate) network: NetworkArgs,
    /// Complete replacement contact list; repeat for multiple email addresses.
    #[arg(long, conflicts_with = "clear_contacts")]
    pub(crate) contact: Vec<String>,
    /// Remove all CA contacts explicitly.
    #[arg(long)]
    pub(crate) clear_contacts: bool,
    /// Confirm this contact update without prompting.
    #[arg(long)]
    pub(crate) yes: bool,
}

#[derive(clap::Args, Default)]
pub(crate) struct RotateKeyArgs {
    #[command(flatten)]
    pub(crate) network: NetworkArgs,
    /// Confirm key rotation or reconciliation without prompting.
    #[arg(long)]
    pub(crate) yes: bool,
}

/// Resolved execution input, shared by CLI parsing and interactive completion.
#[derive(Default)]
pub(crate) struct AccountArgs {
    /// Confirm reuse of an existing local account without an interactive prompt (register only).
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
    /// EAB key ID; use --eab-key-file for its base64url HMAC key.
    pub(crate) eab_kid: Option<String>,
    /// Read the EAB secret from a file; never put the secret itself in CLI arguments.
    pub(crate) eab_key_file: Option<PathBuf>,
    /// Custom HTTP User-Agent (default: AsterACME/version).
    pub(crate) user_agent: Option<String>,
    /// Whole-request timeout in seconds (1–300).
    pub(crate) timeout: Option<u64>,
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
            timeout: args.http.timeout,
            ..args.local.into()
        }
    }
}

impl From<RegisterArgs> for AccountArgs {
    fn from(args: RegisterArgs) -> Self {
        Self {
            yes: args.yes,
            contact: args.contact,
            accept_terms: args.accept_terms,
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

impl From<DeactivateArgs> for AccountArgs {
    fn from(args: DeactivateArgs) -> Self {
        Self {
            yes: args.yes,
            ..args.network.into()
        }
    }
}

impl AccountCommand {
    pub(crate) fn json(&self) -> bool {
        match self {
            Self::UpdateContact(args) => args.network.local.json,
            Self::RotateKey(args) => args.network.local.json,
            Self::Remove(args) => args.target.local.json,
            Self::List(args) => args.local.json,
            Self::Deactivate(args) => args.network.local.json,
            Self::Register(args) => args.local.json,
            Self::Recover(args) | Self::Show { options: args, .. } => args.local.json,
            Self::Switch(args) => args.local.json,
        }
    }
}
