//! Public challenge IO anchored to a trusted root and no-follow child directories.
//! Unix handles constrain every write, chmod, link, rename and removal.
use base64::Engine as _;
use rustix::fs::{self as at, AtFlags, Mode, OFlags};
use std::os::unix::fs::{MetadataExt as _, PermissionsExt as _};
use std::{
    fs::File,
    io::{self, Read as _, Write as _},
    path::{Path, PathBuf},
};

pub struct PublicDirectory {
    file: File,
    path: PathBuf,
}
impl PublicDirectory {
    /// Open an operator-selected root. Ancestors of this root must be trusted.
    /// # Errors
    /// Rejects a missing, linked or non-directory root.
    pub fn open(path: &Path) -> io::Result<Self> {
        Ok(Self {
            file: File::from(at::open(
                path,
                OFlags::RDONLY | OFlags::DIRECTORY | OFlags::NOFOLLOW | OFlags::CLOEXEC,
                Mode::empty(),
            )?),
            path: path.into(),
        })
    }
    /// Open or exclusively create a child without following links; chmod uses its handle.
    /// # Errors
    /// Rejects unsafe components and linked or inaccessible children.
    pub fn child(&self, name: &str, create: bool) -> io::Result<Self> {
        component(name)?;
        let created = if create {
            match at::mkdirat(&self.file, name, Mode::RWXU) {
                Ok(()) => true,
                Err(rustix::io::Errno::EXIST) => false,
                Err(error) => return Err(error.into()),
            }
        } else {
            false
        };
        let file = File::from(at::openat(
            &self.file,
            name,
            OFlags::RDONLY | OFlags::DIRECTORY | OFlags::NOFOLLOW | OFlags::CLOEXEC,
            Mode::empty(),
        )?);
        if created {
            file.set_permissions(std::fs::Permissions::from_mode(0o755))?;
            self.file.sync_all()?;
        }
        Ok(Self {
            file,
            path: self.path.join(name),
        })
    }
    /// Read one bounded regular public file, preserving its actual file identity.
    /// # Errors
    /// Rejects symlinks, special files and content larger than 4096 bytes.
    pub fn read(&self, name: &str) -> io::Result<Option<(File, Vec<u8>)>> {
        component(name)?;
        let mut file = match at::openat(
            &self.file,
            name,
            OFlags::RDONLY | OFlags::NOFOLLOW | OFlags::NONBLOCK | OFlags::CLOEXEC,
            Mode::empty(),
        ) {
            Ok(file) => File::from(file),
            Err(rustix::io::Errno::NOENT) => return Ok(None),
            Err(error) => return Err(error.into()),
        };
        if !file.metadata()?.is_file() || file.metadata()?.len() > 4096 {
            return Err(io::Error::other(
                "challenge file is not bounded regular content",
            ));
        }
        let mut bytes = Vec::new();
        (&mut file).take(4097).read_to_end(&mut bytes)?;
        if bytes.len() > 4096 {
            return Err(io::Error::other("challenge content exceeds limit"));
        }
        Ok(Some((file, bytes)))
    }
    /// Exclusively write a receipt. Existing entries are never overwritten.
    /// # Errors
    /// Reports creation, permissions, write and sync failures.
    pub fn create(&self, name: &str, bytes: &[u8]) -> io::Result<File> {
        component(name)?;
        let mut file = File::from(at::openat(
            &self.file,
            name,
            OFlags::RDWR | OFlags::CREATE | OFlags::EXCL | OFlags::NOFOLLOW | OFlags::CLOEXEC,
            Mode::RUSR | Mode::WUSR,
        )?);
        file.set_permissions(std::fs::Permissions::from_mode(0o644))?;
        file.write_all(bytes)?;
        file.sync_all()?;
        self.file.sync_all()?;
        Ok(file)
    }
    /// Link two sibling entries without following either parent again.
    /// # Errors
    /// Rejects invalid components, existing destinations and unavailable hard links.
    pub fn link(&self, source: &str, target: &str) -> io::Result<()> {
        component(source)?;
        component(target)?;
        at::linkat(&self.file, source, &self.file, target, AtFlags::empty())?;
        self.file.sync_all()
    }
    /// Isolate the actual entry, verify its identity/content, then remove it.
    /// # Errors
    /// Unowned objects are restored without overwrite, or retained for inspection.
    pub fn remove_owned(&self, name: &str, expected: &File, content: &[u8]) -> io::Result<bool> {
        component(name)?;
        let mut random = [0; 16];
        aws_lc_rs::rand::fill(&mut random)
            .map_err(|_| io::Error::other("cleanup randomness unavailable"))?;
        let private = format!(
            ".aster-acme-cleanup-{}",
            base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(random)
        );
        at::mkdirat(&self.file, private.as_str(), Mode::RWXU)?;
        let isolated = Self {
            file: File::from(at::openat(
                &self.file,
                private.as_str(),
                OFlags::RDONLY | OFlags::DIRECTORY | OFlags::NOFOLLOW | OFlags::CLOEXEC,
                Mode::empty(),
            )?),
            path: self.path.join(&private),
        };
        // The public directory can be writable by a different service user.
        // If it replaced our new quarantine before openat, do not move content
        // into that user's directory. Later IO remains on this checked handle.
        let metadata = isolated.file.metadata()?;
        if metadata.uid() != rustix::process::geteuid().as_raw()
            || metadata.permissions().mode() & 0o077 != 0
        {
            return Err(io::Error::other("HTTP cleanup isolation directory changed"));
        }
        match at::renameat(&self.file, name, &isolated.file, "entry") {
            Ok(()) => {}
            Err(rustix::io::Errno::NOENT) => {
                at::unlinkat(&self.file, private.as_str(), AtFlags::REMOVEDIR)?;
                return Ok(false);
            }
            Err(error) => return Err(error.into()),
        }
        let actual = isolated.read("entry");
        let owned = match &actual {
            Ok(Some((file, bytes))) => {
                bytes == content && crate::state_file::same_file(expected, file)?
            }
            _ => false,
        };
        if !owned {
            // Never hard-link an isolated symlink back into the public path.
            if !matches!(actual, Ok(Some(_)))
                || at::linkat(&isolated.file, "entry", &self.file, name, AtFlags::empty()).is_err()
            {
                return Err(io::Error::other(format!(
                    "HTTP cleanup path changed; retained isolated content at {}",
                    isolated.path.display()
                )));
            }
        }
        at::unlinkat(&isolated.file, "entry", AtFlags::empty())?;
        at::unlinkat(&self.file, private.as_str(), AtFlags::REMOVEDIR)?;
        self.file.sync_all()?;
        Ok(owned)
    }
}
fn component(name: &str) -> io::Result<()> {
    if name.is_empty() || matches!(name, "." | "..") || name.contains(['/', '\\', '\0']) {
        return Err(io::Error::other("invalid directory-relative component"));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use crate::state_file::public_directory::*;
    #[test]
    fn child_replacement_cannot_redirect_creation_link_or_cleanup() {
        let temp = tempfile::tempdir().unwrap();
        let root = PublicDirectory::open(temp.path()).unwrap();
        let child = root.child("child", true).unwrap();
        let outside = temp.path().join("outside");
        std::fs::create_dir(&outside).unwrap();
        let moved = temp.path().join("moved");
        std::fs::rename(temp.path().join("child"), &moved).unwrap();
        std::os::unix::fs::symlink(&outside, temp.path().join("child")).unwrap();
        assert!(root.child("child", false).is_err());
        let owned = child.create("receipt", b"token").unwrap();
        child.link("receipt", "public").unwrap();
        assert!(child.remove_owned("public", &owned, b"token").unwrap());
        assert!(child.remove_owned("receipt", &owned, b"token").unwrap());
        assert_eq!(std::fs::read_dir(outside).unwrap().count(), 0);
        assert_eq!(std::fs::read_dir(moved).unwrap().count(), 0);
    }
}
