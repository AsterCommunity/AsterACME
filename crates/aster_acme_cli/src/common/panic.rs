//! Executable-owned Forge hook: private redacted reports and one safe final diagnostic.
//!
//! Install before the Tokio runtime starts. A panic is diagnostic evidence, never
//! authorization to retry an ACME mutation or delete a saved key/checkpoint.
use super::{error::CliResult, session::OutputSession};
use aster_forge_panic::{
    DiagnosticSink, PanicHookConfig, PanicOutput, PublicDiagnostic, ReportWriter,
};
use std::{
    io::{self, Seek as _, Write as _},
    path::PathBuf,
    sync::{
        Arc,
        atomic::{AtomicBool, Ordering},
    },
};

/// Kept outside the panic payload: main uses this flag to fail even if a worker
/// catches its panic or its `JoinError` was translated into an ordinary error.
pub(crate) struct PanicState {
    occurred: Arc<AtomicBool>,
    output: OutputSession,
    path: Option<PathBuf>,
    written: AtomicBool,
}

impl PanicState {
    pub(crate) fn install(output: OutputSession, root: Option<PathBuf>) -> Arc<Self> {
        let path = root.as_ref().map(|root| root.join("crash.log"));
        let state = Arc::new(Self {
            occurred: Arc::new(AtomicBool::new(false)),
            output,
            path,
            written: AtomicBool::new(false),
        });
        let writer = PrivateReports::open(root, state.occurred.clone());
        let config = PanicHookConfig::new(
            "AsterACME",
            concat!(
                env!("CARGO_PKG_VERSION"),
                " revision=",
                env!("ASTER_BUILD_REVISION"),
                " dirty=",
                env!("ASTER_BUILD_DIRTY")
            ),
            env!("CARGO_PKG_REPOSITORY"),
        )
        .with_issue_template("issues/new")
        .with_timestamp(|| super::time::timestamp(Some(time::OffsetDateTime::now_utc())))
        .with_report_writer(Arc::new(writer))
        .with_output(PanicOutput::Sink(state.clone()));
        aster_forge_panic::install_panic_hook(config);
        state
    }

    pub(crate) fn occurred(&self) -> bool {
        self.occurred.load(Ordering::Acquire)
    }
}

impl DiagnosticSink for PanicState {
    fn emit(&self, diagnostic: &PublicDiagnostic) -> io::Result<()> {
        self.occurred.store(true, Ordering::Release);
        self.written
            .store(diagnostic.report_written, Ordering::Release);
        self.report()
    }
}

impl PanicState {
    /// Retry only safe diagnostic delivery after unwinding releases a busy output
    /// lock; never retry the panic, report-file mutation or ACME operation.
    pub(crate) fn report(&self) -> io::Result<()> {
        let hint = match (&self.path, self.written.load(Ordering::Acquire)) {
            (Some(path), true) => format!("Private crash report: {}. Retain saved keys and requests; report this at {}/issues/new.", path.display(), env!("CARGO_PKG_REPOSITORY")),
            _ => "Private crash report unavailable. Retain saved keys and requests; check --data-dir and permissions.".into(),
        };
        self.output.panic_notice(&hint)
    }
}

/// Preopen the shared storage adapter; crash.log itself is created only on panic.
/// Unix applies private modes; Windows inherits directory permissions without ACL management.
struct PrivateReports {
    occurred: Arc<AtomicBool>,
    directory: Option<aster_acme_cli_storage::state_file::StateDirectory>,
}
impl PrivateReports {
    fn open(root: Option<PathBuf>, occurred: Arc<AtomicBool>) -> Self {
        Self {
            occurred,
            directory: root.and_then(|root| {
                aster_acme_cli_storage::state_file::StateDirectory::open(root).ok()
            }),
        }
    }
}

impl ReportWriter for PrivateReports {
    fn write_report(&self, report: &str) -> io::Result<()> {
        // Record failure before filesystem I/O: command finalization must not race
        // a worker whose panic report is still being written.
        self.occurred.store(true, Ordering::Release);
        let directory = self
            .directory
            .as_ref()
            .ok_or_else(|| io::Error::other("private crash directory unavailable"))?;
        // open_lock never truncates or follows a link; check confidentiality
        // too, since generic lock files permit owner-controlled read access.
        let mut file = directory.open_private("crash.log")?;
        // Nonblocking process locking avoids waiting on a different crashing process.
        if file.try_lock().is_err() {
            return Err(io::Error::new(
                io::ErrorKind::WouldBlock,
                "crash report busy",
            ));
        }
        let result = (|| {
            let metadata = file.metadata()?;
            // Panic payloads may contain a secret supplied to a third-party panic.
            // Keep build/thread/location/backtrace, omit the entire raw message,
            // including multiline payloads. Fail closed if the upstream layout changes.
            let (prefix, _) = report
                .split_once("\nMessage:")
                .ok_or_else(|| io::Error::other("unknown crash report format"))?;
            let (_, backtrace) = report
                .rsplit_once("\nBacktrace:\n")
                .ok_or_else(|| io::Error::other("unknown crash report format"))?;
            let redacted = format!(
                "{prefix}\nMessage:   <redacted>\nReport:    {}/issues/new\nBacktrace:\n{backtrace}",
                env!("CARGO_PKG_REPOSITORY")
            );
            // Bound diagnostic disk usage without truncating an existing report.
            if metadata
                .len()
                .saturating_add(u64::try_from(redacted.len()).unwrap_or(u64::MAX))
                > 1024 * 1024
            {
                return Err(io::Error::other("crash report limit reached"));
            }
            file.seek(io::SeekFrom::End(0))?;
            file.write_all(redacted.as_bytes())?;
            file.flush()
        })();
        // Explicitly release before closing: immediate subsequent reports must
        // not depend on delayed descriptor-close behavior on the filesystem.
        let unlocked = file.unlock();
        result.and(unlocked)
    }
}

/// Resolve only the storage override; this must not read/create config or load keys.
/// Version remains side-effect-free, and help exits in clap before hook installation.
pub(crate) fn data_root(args: &crate::app::Args) -> CliResult<Option<PathBuf>> {
    use crate::{
        app::Command,
        commands::{account::args::AccountCommand, cert::args::CertCommand},
    };
    let explicit = match &args.command {
        Command::Version { .. } => return Ok(None),
        Command::Account { command } => match command {
            AccountCommand::List(args) => &args.local.data_dir,
            AccountCommand::Show { options, .. } | AccountCommand::Recover(options) => {
                &options.local.data_dir
            }
            AccountCommand::Switch(args) => &args.local.data_dir,
            AccountCommand::Register(args) => &args.local.data_dir,
            AccountCommand::UpdateContact(args) => &args.network.local.data_dir,
            AccountCommand::RotateKey(args) => &args.network.local.data_dir,
            AccountCommand::Deactivate(args) => &args.network.local.data_dir,
            AccountCommand::Remove(args) => &args.target.local.data_dir,
        },
        Command::Cert { command } => match command {
            CertCommand::Issue(args) => &args.run.local.data_dir,
            CertCommand::Renew(args) => &args.run.local.data_dir,
            CertCommand::List { local, .. }
            | CertCommand::Show { local, .. }
            | CertCommand::Revoke { local, .. }
            | CertCommand::Remove { local, .. } => &local.data_dir,
        },
    };
    explicit.clone().map_or_else(
        || crate::config::default_data_dir().map(Some),
        |root| Ok(Some(root)),
    )
}

#[cfg(test)]
mod tests;
