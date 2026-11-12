//! Ordinary Unix permission modes; no implicit Windows ACL translation.
use crate::issuance::{IssueError, deployment::DeploymentPermissions, failure};

pub(super) fn validate(permissions: &DeploymentPermissions) -> Result<(), IssueError> {
    if permissions
        .file_mode
        .into_iter()
        .chain(permissions.key_mode)
        .any(|mode| mode > 0o777)
    {
        return Err(failure(
            "file mode must contain only ordinary octal permission bits (000-777)",
        ));
    }
    #[cfg(not(unix))]
    if permissions.file_mode.is_some() || permissions.key_mode.is_some() {
        return Err(failure(
            "Unix file modes are unsupported on this platform; inherited platform permissions apply",
        ));
    }
    Ok(())
}
