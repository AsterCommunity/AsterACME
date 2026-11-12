//! Unix publication stays relative to opened directories, never reopens by path.
use crate::issuance::deployment::publication::{inspect_destination, parent};
use crate::issuance::{IssueError, failure};
use rustix::fs::{AtFlags, Mode, OFlags, open, openat, renameat, statat, unlinkat};
use std::{
    ffi::OsString,
    fs::{self, File},
    io,
    os::unix::fs::MetadataExt as _,
    path::Path,
};

#[cfg(test)]
use std::path::PathBuf;

pub(super) struct Temporary {
    directory: File,
    file: File,
    name: OsString,
    destination: OsString,
    #[cfg(test)]
    path: PathBuf,
    committed: bool,
}

impl Temporary {
    pub(super) fn create(path: &Path) -> Result<Self, IssueError> {
        // Initial resolution requires trusted ancestors, as before. Open only
        // the final directory: the kernel needs search permission on ancestors,
        // not read permission. O_NOFOLLOW rejects replacement of the final
        // component with a symlink; all later IO stays on the retained handle.
        let resolved =
            fs::canonicalize(parent(path)?).map_err(|error| failure(&error.to_string()))?;
        let directory = File::from(
            open(
                &resolved,
                OFlags::RDONLY | OFlags::DIRECTORY | OFlags::NOFOLLOW | OFlags::CLOEXEC,
                Mode::empty(),
            )
            .map_err(io::Error::from)
            .map_err(|error| failure(&error.to_string()))?,
        );
        let name = OsString::from(format!(
            ".aster-acme-deploy-{}",
            crate::issuance::new_operation_id()?
        ));
        let file = File::from(
            openat(
                &directory,
                &name,
                OFlags::WRONLY | OFlags::CREATE | OFlags::EXCL | OFlags::NOFOLLOW | OFlags::CLOEXEC,
                Mode::RUSR | Mode::WUSR,
            )
            .map_err(io::Error::from)
            .map_err(|e| failure(&e.to_string()))?,
        );
        Ok(Self {
            directory,
            file,
            #[cfg(test)]
            path: parent(path)?.join(&name),
            name,
            destination: path
                .file_name()
                .ok_or_else(|| failure("deployment destination has no filename"))?
                .into(),
            committed: false,
        })
    }

    pub(super) fn as_file(&self) -> &File {
        &self.file
    }
    pub(super) fn as_file_mut(&mut self) -> &mut File {
        &mut self.file
    }
    #[cfg(test)]
    pub(super) fn path(&self) -> &Path {
        &self.path
    }

    pub(super) fn inspect(&self, path: &Path) -> Result<(), IssueError> {
        // Rechecking the configured path catches visible replacements early;
        // security comes from the retained descriptor, not this path check.
        inspect_destination(path)?;
        let current = fs::metadata(parent(path)?).map_err(|error| failure(&error.to_string()))?;
        let opened = self
            .directory
            .metadata()
            .map_err(|error| failure(&error.to_string()))?;
        if (current.dev(), current.ino()) != (opened.dev(), opened.ino()) {
            return Err(failure(
                "deployment parent directory changed after preparation",
            ));
        }
        match statat(
            &self.directory,
            &self.destination,
            AtFlags::SYMLINK_NOFOLLOW,
        ) {
            Ok(stat) if rustix::fs::FileType::from_raw_mode(stat.st_mode).is_file() => Ok(()),
            Ok(_) => Err(failure("deployment destination is not a regular file")),
            Err(rustix::io::Errno::NOENT) => Ok(()),
            Err(error) => Err(failure(&error.to_string())),
        }
    }

    pub(super) fn persist(mut self, path: &Path) -> Result<(), IssueError> {
        renameat(
            &self.directory,
            &self.name,
            &self.directory,
            &self.destination,
        )
        .map_err(|error| {
            failure(&format!(
                "deployment replace destination failed at {}: {error}",
                path.display()
            ))
        })?;
        self.committed = true;
        self.directory
            .sync_all()
            .map_err(|error| failure(&format!("deployment sync parent directory failed: {error}")))
    }
}

impl Drop for Temporary {
    fn drop(&mut self) {
        if !self.committed {
            // Even after the original pathname is replaced, remove only our
            // temporary entry in the originally opened directory.
            let _ = unlinkat(&self.directory, &self.name, AtFlags::empty());
        }
    }
}
