//! The single client path resolver.
//!
//! `bw-agent` and `bw-proxy` must agree on the socket path or the pair breaks
//! with no error at all. v1 had `ipc.rs` honouring `XDG_CACHE_HOME` while
//! `proxy.rs` hardcoded `$HOME/.cache`; setting that variable silently
//! disconnected them. There is now exactly one function.
//!
//! State lives under `$XDG_STATE_HOME`, never `~/.cache`: cache directories are
//! precisely what naive backup and sync tools replicate, which is the blob
//! exfiltration threat verbatim.

use std::path::PathBuf;

pub const IDENTITY_FILE: &str = "identity.key";
pub const BLOB_FILE: &str = "blob";
pub const DEVICE_FILE: &str = "device.toml";
pub const SOCKET_FILE: &str = "s.bw";

fn home() -> PathBuf {
    std::env::var("HOME")
        .map(PathBuf::from)
        .unwrap_or_else(|_| PathBuf::from("/tmp"))
}

/// `$XDG_STATE_HOME/bw-agent`, falling back to `$HOME/.local/state/bw-agent`.
/// Does not touch the filesystem; see [`ensure_state_dir`].
pub fn state_dir() -> PathBuf {
    let base = match std::env::var("XDG_STATE_HOME") {
        Ok(v) if !v.is_empty() => PathBuf::from(v),
        _ => home().join(".local").join("state"),
    };
    base.join("bw-agent")
}

/// Create the state directory `0700` if it does not exist, and mark it for
/// backup exclusion on macOS.
pub fn ensure_state_dir() -> std::io::Result<PathBuf> {
    let dir = state_dir();
    let existed = dir.exists();
    std::fs::create_dir_all(&dir)?;

    use std::os::unix::fs::PermissionsExt;
    std::fs::set_permissions(&dir, std::fs::Permissions::from_mode(0o700))?;

    if !existed {
        exclude_from_backup(&dir);
    }
    Ok(dir)
}

pub fn socket_path() -> PathBuf {
    state_dir().join(SOCKET_FILE)
}

pub fn blob_path() -> PathBuf {
    state_dir().join(BLOB_FILE)
}

pub fn identity_path() -> PathBuf {
    state_dir().join(IDENTITY_FILE)
}

pub fn device_path() -> PathBuf {
    state_dir().join(DEVICE_FILE)
}

/// Best-effort Time Machine exclusion. The attribute value is a binary plist
/// holding the boolean `true`, which is what `CSBackupSetItemExcluded` writes.
/// Failure is not an error: the README documents manual exclusion for Restic,
/// Borg, rsync and Time Machine regardless.
#[cfg(target_os = "macos")]
fn exclude_from_backup(dir: &std::path::Path) {
    use std::ffi::CString;
    use std::os::unix::ffi::OsStrExt;

    const BPLIST_TRUE: [u8; 42] = [
        0x62, 0x70, 0x6c, 0x69, 0x73, 0x74, 0x30, 0x30, 0x09, 0x08, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x01, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x09,
    ];
    const NAME: &[u8] = b"com.apple.metadata:com_apple_backup_excludeItem\0";

    let Ok(path) = CString::new(dir.as_os_str().as_bytes()) else {
        return;
    };
    unsafe {
        libc::setxattr(
            path.as_ptr(),
            NAME.as_ptr() as *const libc::c_char,
            BPLIST_TRUE.as_ptr() as *const libc::c_void,
            BPLIST_TRUE.len(),
            0,
            0,
        );
    }
}

#[cfg(not(target_os = "macos"))]
fn exclude_from_backup(_dir: &std::path::Path) {}
