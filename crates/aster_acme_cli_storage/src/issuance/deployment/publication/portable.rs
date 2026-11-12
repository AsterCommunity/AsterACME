//! Platforms without descriptor-relative replacement require trusted parents.
use crate::issuance::IssueError;
use crate::issuance::deployment::publication::{inspect_destination, parent, path_error};
use std::{fs::File, path::Path};

pub(super) struct Temporary(tempfile::NamedTempFile);
impl Temporary {
    pub(super) fn create(path: &Path) -> Result<Self, IssueError> {
        tempfile::Builder::new()
            .prefix(".aster-acme-deploy-")
            .tempfile_in(parent(path)?)
            .map(Self)
            .map_err(|error| path_error("stage file", path, &error))
    }
    pub(super) fn as_file(&self) -> &File {
        self.0.as_file()
    }
    pub(super) fn as_file_mut(&mut self) -> &mut File {
        self.0.as_file_mut()
    }
    #[cfg(test)]
    pub(super) fn path(&self) -> &Path {
        self.0.path()
    }
    pub(super) fn inspect(&self, path: &Path) -> Result<(), IssueError> {
        // Same-directory staging is required for replacement without a
        // cross-filesystem copy. Check the owned temporary as well as the target.
        if self.0.path().parent() != Some(parent(path)?) {
            return Err(crate::issuance::failure(
                "deployment temporary and destination directories differ",
            ));
        }
        inspect_destination(path)
    }
    pub(super) fn persist(self, path: &Path) -> Result<(), IssueError> {
        self.0
            .persist(path)
            .map_err(|error| path_error("replace destination", path, &error.error))?;
        crate::state_file::sync_directory(parent(path)?)
            .map_err(|error| path_error("sync parent directory", path, &error))
    }
}
