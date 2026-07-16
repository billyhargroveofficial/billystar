use std::ffi::{OsStr, OsString};
use std::fs::{self, File, Metadata, OpenOptions};
use std::io::{self, Read, Write};
use std::path::{Path, PathBuf};

use anyhow::{Context, Result};
use rand::rngs::OsRng;
use rand::RngCore;
use zeroize::Zeroizing;

pub const ED25519_SEED_BYTES: usize = 32;
pub const MAX_JSON_BYTES: usize = 256 * 1024;
pub const OUTPUT_MODE: u32 = 0o600;

pub struct SecretSeed(Zeroizing<[u8; ED25519_SEED_BYTES]>);

impl SecretSeed {
    pub fn generate() -> Result<Self> {
        let mut seed = Zeroizing::new([0u8; ED25519_SEED_BYTES]);
        OsRng
            .try_fill_bytes(seed.as_mut())
            .context("obtain Ed25519 seed entropy")?;
        Ok(Self(seed))
    }

    pub fn as_bytes(&self) -> &[u8; ED25519_SEED_BYTES] {
        &self.0
    }

    #[cfg(test)]
    pub fn from_test_bytes(bytes: [u8; ED25519_SEED_BYTES]) -> Self {
        Self(Zeroizing::new(bytes))
    }
}

#[cfg(unix)]
fn effective_uid() -> u32 {
    // SAFETY: geteuid takes no arguments and has no preconditions.
    unsafe { libc::geteuid() }
}

#[cfg(not(unix))]
fn effective_uid() -> u32 {
    0
}

fn parent(path: &Path) -> Result<&Path> {
    if path.file_name().is_none() {
        anyhow::bail!("output path has no file name: {}", path.display());
    }
    Ok(match path.parent() {
        Some(candidate) if !candidate.as_os_str().is_empty() => candidate,
        _ => Path::new("."),
    })
}

struct OutputDirectory {
    path: PathBuf,
    file: File,
}

fn output_name(path: &Path) -> Result<&OsStr> {
    path.file_name().context("output path has no file name")
}

fn open_output_directory(path: &Path) -> Result<OutputDirectory> {
    let mut options = OpenOptions::new();
    options.read(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.custom_flags(libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC);
    }
    let file = options
        .open(path)
        .with_context(|| format!("open output directory {}", path.display()))?;
    let metadata = file
        .metadata()
        .with_context(|| format!("stat opened output directory {}", path.display()))?;
    anyhow::ensure!(
        metadata.file_type().is_dir(),
        "output parent is not a directory: {}",
        path.display()
    );
    #[cfg(unix)]
    {
        use std::os::unix::fs::{MetadataExt, PermissionsExt};
        anyhow::ensure!(
            metadata.uid() == effective_uid(),
            "output directory {} is owned by UID {}, expected {}",
            path.display(),
            metadata.uid(),
            effective_uid()
        );
        let mode = metadata.permissions().mode() & 0o777;
        anyhow::ensure!(
            mode & 0o022 == 0,
            "output directory {} is group/world writable ({mode:04o})",
            path.display()
        );
    }
    Ok(OutputDirectory {
        path: path.to_path_buf(),
        file,
    })
}

fn open_readonly_nofollow(path: &Path) -> Result<File> {
    let mut options = OpenOptions::new();
    options.read(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK | libc::O_CLOEXEC);
    }
    options
        .open(path)
        .with_context(|| format!("open {}", path.display()))
}

fn validate_input_metadata(path: &Path, metadata: &Metadata, maximum: usize) -> Result<()> {
    anyhow::ensure!(
        metadata.file_type().is_file(),
        "input is not a regular file: {}",
        path.display()
    );
    anyhow::ensure!(
        metadata.len() <= maximum as u64,
        "input {} is {} bytes; maximum is {maximum}",
        path.display(),
        metadata.len()
    );
    #[cfg(unix)]
    {
        use std::os::unix::fs::{MetadataExt, PermissionsExt};
        anyhow::ensure!(
            metadata.uid() == effective_uid(),
            "input {} is owned by UID {}, expected {}",
            path.display(),
            metadata.uid(),
            effective_uid()
        );
        anyhow::ensure!(
            metadata.nlink() == 1,
            "input {} has {} hard links; expected one",
            path.display(),
            metadata.nlink()
        );
        let mode = metadata.permissions().mode() & 0o777;
        anyhow::ensure!(
            mode & 0o022 == 0,
            "input {} is group/world writable ({mode:04o})",
            path.display()
        );
    }
    Ok(())
}

pub fn read_public_file(path: &Path, maximum: usize) -> Result<Vec<u8>> {
    let file = open_readonly_nofollow(path)?;
    let metadata = file
        .metadata()
        .with_context(|| format!("stat opened input {}", path.display()))?;
    validate_input_metadata(path, &metadata, maximum)?;
    let mut bytes = Vec::with_capacity(metadata.len() as usize);
    file.take(maximum as u64 + 1)
        .read_to_end(&mut bytes)
        .with_context(|| format!("read {}", path.display()))?;
    anyhow::ensure!(
        bytes.len() <= maximum,
        "input {} grew beyond its {maximum}-byte bound",
        path.display()
    );
    Ok(bytes)
}

pub fn ensure_absent(path: &Path) -> Result<()> {
    match fs::symlink_metadata(path) {
        Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(()),
        Err(error) => Err(error).with_context(|| format!("inspect output {}", path.display())),
        Ok(_) => anyhow::bail!(
            "output already exists and will not be overwritten: {}",
            path.display()
        ),
    }
}

pub fn read_secret_seed(path: &Path) -> Result<SecretSeed> {
    #[cfg(not(unix))]
    anyhow::bail!("secure Ed25519 seed custody is supported on Unix only");

    let file = open_readonly_nofollow(path)?;
    let metadata = file
        .metadata()
        .with_context(|| format!("stat opened seed {}", path.display()))?;
    anyhow::ensure!(
        metadata.file_type().is_file(),
        "seed is not a regular file: {}",
        path.display()
    );
    #[cfg(unix)]
    {
        use std::os::unix::fs::{MetadataExt, PermissionsExt};
        let mode = metadata.permissions().mode() & 0o777;
        anyhow::ensure!(
            metadata.uid() == effective_uid(),
            "seed {} is owned by UID {}, expected {}",
            path.display(),
            metadata.uid(),
            effective_uid()
        );
        anyhow::ensure!(
            metadata.nlink() == 1,
            "seed {} has {} hard links; expected one",
            path.display(),
            metadata.nlink()
        );
        anyhow::ensure!(
            mode == OUTPUT_MODE,
            "seed {} has mode {mode:04o}; expected {OUTPUT_MODE:04o}",
            path.display()
        );
    }
    anyhow::ensure!(
        metadata.len() == ED25519_SEED_BYTES as u64,
        "seed {} is {} bytes; expected exactly {ED25519_SEED_BYTES}",
        path.display(),
        metadata.len()
    );
    let mut seed = Zeroizing::new([0u8; ED25519_SEED_BYTES]);
    let mut reader = file.take(ED25519_SEED_BYTES as u64 + 1);
    reader
        .read_exact(seed.as_mut())
        .with_context(|| format!("read seed {}", path.display()))?;
    let mut trailing = [0u8; 1];
    anyhow::ensure!(
        reader
            .read(&mut trailing)
            .context("check seed trailing byte")?
            == 0,
        "seed {} has trailing bytes",
        path.display()
    );
    #[cfg(unix)]
    {
        use std::os::unix::fs::{MetadataExt, PermissionsExt};
        let completed = reader
            .get_ref()
            .metadata()
            .with_context(|| format!("re-stat seed after read {}", path.display()))?;
        anyhow::ensure!(
            completed.dev() == metadata.dev()
                && completed.ino() == metadata.ino()
                && completed.uid() == metadata.uid()
                && completed.nlink() == 1
                && completed.permissions().mode() & 0o777 == OUTPUT_MODE
                && completed.len() == ED25519_SEED_BYTES as u64,
            "seed metadata changed while it was being read: {}",
            path.display()
        );
    }
    Ok(SecretSeed(seed))
}

struct PendingEntry {
    directory: File,
    directory_path: PathBuf,
    name: OsString,
    keep: bool,
}

impl Drop for PendingEntry {
    fn drop(&mut self) {
        if !self.keep {
            let _ = remove_entry(&self.directory, &self.directory_path, &self.name);
        }
    }
}

#[cfg(unix)]
fn c_name(name: &OsStr) -> io::Result<std::ffi::CString> {
    use std::os::unix::ffi::OsStrExt;
    std::ffi::CString::new(name.as_bytes())
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "file name contains NUL"))
}

#[cfg(unix)]
fn remove_entry(directory: &File, _directory_path: &Path, name: &OsStr) -> io::Result<()> {
    use std::os::fd::AsRawFd;
    let name = c_name(name)?;
    // SAFETY: directory is an open directory fd and name is a live C string.
    let status = unsafe { libc::unlinkat(directory.as_raw_fd(), name.as_ptr(), 0) };
    if status == 0 {
        Ok(())
    } else {
        Err(io::Error::last_os_error())
    }
}

#[cfg(not(unix))]
fn remove_entry(_directory: &File, directory_path: &Path, name: &OsStr) -> io::Result<()> {
    fs::remove_file(directory_path.join(name))
}

fn secure_create_new(directory: &OutputDirectory, name: &OsStr) -> Result<File> {
    #[cfg(unix)]
    let file = {
        use std::os::fd::{AsRawFd, FromRawFd};
        let c_name = c_name(name)?;
        // SAFETY: directory is a valid directory fd, name is NUL-terminated,
        // and a successful descriptor is immediately owned by File.
        let descriptor = unsafe {
            libc::openat(
                directory.file.as_raw_fd(),
                c_name.as_ptr(),
                libc::O_WRONLY | libc::O_CREAT | libc::O_EXCL | libc::O_NOFOLLOW | libc::O_CLOEXEC,
                OUTPUT_MODE,
            )
        };
        if descriptor < 0 {
            return Err(io::Error::last_os_error()).with_context(|| {
                format!("securely create {}", directory.path.join(name).display())
            });
        }
        // SAFETY: openat returned a new owned descriptor.
        unsafe { File::from_raw_fd(descriptor) }
    };

    #[cfg(not(unix))]
    let file = {
        let mut options = OpenOptions::new();
        options.write(true).create_new(true);
        options
            .open(directory.path.join(name))
            .context("securely create output")?
    };

    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let validation = (|| -> Result<()> {
            file.set_permissions(fs::Permissions::from_mode(OUTPUT_MODE))
                .context("chmod newly created output")?;
            use std::os::unix::fs::MetadataExt;
            let metadata = file.metadata().context("stat newly created output")?;
            anyhow::ensure!(
                metadata.file_type().is_file()
                    && metadata.uid() == effective_uid()
                    && metadata.nlink() == 1,
                "new output failed regular-file/owner/link validation"
            );
            Ok(())
        })();
        if let Err(error) = validation {
            drop(file);
            remove_entry(&directory.file, &directory.path, name)
                .context("remove output that failed post-create validation")?;
            return Err(error);
        }
    }
    Ok(file)
}

pub fn write_secret_seed_create_new(path: &Path, seed: &SecretSeed) -> Result<()> {
    #[cfg(not(unix))]
    anyhow::bail!("secure Ed25519 seed custody is supported on Unix only");

    let directory = open_output_directory(parent(path)?)?;
    let name = output_name(path)?;
    let pending_directory = directory
        .file
        .try_clone()
        .context("clone output directory handle for rollback")?;
    let mut file = secure_create_new(&directory, name)?;
    let mut pending = PendingEntry {
        directory: pending_directory,
        directory_path: directory.path.clone(),
        name: name.to_os_string(),
        keep: false,
    };
    file.write_all(seed.as_bytes())
        .with_context(|| format!("write seed {}", path.display()))?;
    file.sync_all()
        .with_context(|| format!("fsync seed {}", path.display()))?;
    let metadata = file.metadata().context("stat completed seed")?;
    anyhow::ensure!(
        metadata.len() == ED25519_SEED_BYTES as u64,
        "completed seed has unexpected length"
    );
    drop(file);
    directory
        .file
        .sync_all()
        .with_context(|| format!("fsync directory {}", directory.path.display()))?;
    pending.keep = true;
    Ok(())
}

fn temporary_name(target_name: &OsStr) -> Result<OsString> {
    let mut nonce = [0u8; 16];
    OsRng
        .try_fill_bytes(&mut nonce)
        .context("obtain output temp-name entropy")?;
    let mut name = OsString::from(".");
    name.push(target_name);
    name.push(format!(
        ".{}-{}.tmp",
        std::process::id(),
        hex::encode(nonce)
    ));
    Ok(name)
}

#[cfg(target_os = "linux")]
fn publish_noreplace(directory: &File, from: &OsStr, to: &OsStr) -> io::Result<()> {
    use std::os::fd::AsRawFd;
    let from = c_name(from)?;
    let to = c_name(to)?;
    // SAFETY: directory is a valid directory fd and both C strings live for
    // the syscall and contain no interior NUL.
    let status = unsafe {
        libc::syscall(
            libc::SYS_renameat2,
            directory.as_raw_fd(),
            from.as_ptr(),
            directory.as_raw_fd(),
            to.as_ptr(),
            libc::RENAME_NOREPLACE,
        )
    };
    if status == 0 {
        Ok(())
    } else {
        Err(io::Error::last_os_error())
    }
}

#[cfg(target_os = "macos")]
fn publish_noreplace(directory: &File, from: &OsStr, to: &OsStr) -> io::Result<()> {
    use std::os::fd::AsRawFd;
    let from = c_name(from)?;
    let to = c_name(to)?;
    // SAFETY: directory is a valid directory fd and both names are live C
    // strings. RENAME_EXCL makes publication atomic and fail-if-present.
    let status = unsafe {
        libc::renameatx_np(
            directory.as_raw_fd(),
            from.as_ptr(),
            directory.as_raw_fd(),
            to.as_ptr(),
            libc::RENAME_EXCL,
        )
    };
    if status == 0 {
        Ok(())
    } else {
        Err(io::Error::last_os_error())
    }
}

#[cfg(all(unix, not(any(target_os = "linux", target_os = "macos"))))]
fn publish_noreplace(directory: &File, from: &OsStr, to: &OsStr) -> io::Result<()> {
    use std::os::fd::AsRawFd;
    let from = c_name(from)?;
    let to = c_name(to)?;
    // SAFETY: directory is a valid directory fd and both names are live C
    // strings. linkat is fail-if-present; unlinkat removes only the staged name.
    let linked = unsafe {
        libc::linkat(
            directory.as_raw_fd(),
            from.as_ptr(),
            directory.as_raw_fd(),
            to.as_ptr(),
            0,
        )
    };
    if linked != 0 {
        return Err(io::Error::last_os_error());
    }
    // SAFETY: same anchored directory fd and live staged-name C string.
    if unsafe { libc::unlinkat(directory.as_raw_fd(), from.as_ptr(), 0) } != 0 {
        let error = io::Error::last_os_error();
        // SAFETY: best-effort rollback of the just-created destination name.
        let _ = unsafe { libc::unlinkat(directory.as_raw_fd(), to.as_ptr(), 0) };
        return Err(error);
    }
    Ok(())
}

#[cfg(not(unix))]
fn publish_noreplace(
    _directory: &File,
    directory_path: &Path,
    from: &OsStr,
    to: &OsStr,
) -> io::Result<()> {
    let from = directory_path.join(from);
    let to = directory_path.join(to);
    fs::hard_link(&from, &to)?;
    if let Err(error) = fs::remove_file(&from) {
        let _ = fs::remove_file(&to);
        return Err(error);
    }
    Ok(())
}

pub fn atomic_write_new(path: &Path, bytes: &[u8]) -> Result<()> {
    let directory = open_output_directory(parent(path)?)?;
    let target_name = output_name(path)?;
    for _ in 0..32 {
        let temporary = temporary_name(target_name)?;
        let pending_directory = directory
            .file
            .try_clone()
            .context("clone output directory handle for rollback")?;
        let mut file = match secure_create_new(&directory, &temporary) {
            Ok(file) => file,
            Err(error)
                if error
                    .downcast_ref::<io::Error>()
                    .is_some_and(|source| source.kind() == io::ErrorKind::AlreadyExists) =>
            {
                continue;
            }
            Err(error) => return Err(error),
        };
        let mut pending = PendingEntry {
            directory: pending_directory,
            directory_path: directory.path.clone(),
            name: temporary.clone(),
            keep: false,
        };
        file.write_all(bytes)
            .with_context(|| format!("write staged output for {}", path.display()))?;
        file.sync_all()
            .with_context(|| format!("fsync staged output for {}", path.display()))?;
        anyhow::ensure!(
            file.metadata().context("stat staged output")?.len() == bytes.len() as u64,
            "staged output has unexpected length"
        );
        drop(file);
        #[cfg(unix)]
        publish_noreplace(&directory.file, &temporary, target_name)
            .with_context(|| format!("publish output without overwrite: {}", path.display()))?;
        #[cfg(not(unix))]
        publish_noreplace(&directory.file, &directory.path, &temporary, target_name)
            .with_context(|| format!("publish output without overwrite: {}", path.display()))?;
        // Publication renamed/unlinked the staged name. Until the directory
        // fsync succeeds, rollback must target the final entry instead.
        pending.name = target_name.to_os_string();
        directory
            .file
            .sync_all()
            .with_context(|| format!("fsync directory {}", directory.path.display()))?;
        pending.keep = true;
        return Ok(());
    }
    anyhow::bail!("output temp-name collision limit reached")
}
