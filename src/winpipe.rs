//! Named-pipe transport for Windows, shared by bw-agent (server end) and
//! bw-proxy (client end). Pipe names are machine-wide, so both ends check
//! that the process on the other side runs as the same user.

use std::fs::File;
use std::io;
use std::os::windows::io::{AsRawHandle, FromRawHandle, OwnedHandle, RawHandle};
use std::ptr;
use std::time::{Duration, Instant};

use windows_sys::core::BOOL;
use windows_sys::Win32::Foundation::{
    GetLastError, LocalFree, ERROR_BROKEN_PIPE, ERROR_FILE_NOT_FOUND, ERROR_IO_PENDING,
    ERROR_NO_DATA, ERROR_PIPE_BUSY, ERROR_PIPE_CONNECTED, GENERIC_READ, GENERIC_WRITE, HANDLE,
    INVALID_HANDLE_VALUE,
};
use windows_sys::Win32::Security::Authorization::{
    ConvertSidToStringSidW, ConvertStringSecurityDescriptorToSecurityDescriptorW, SDDL_REVISION_1,
};
use windows_sys::Win32::Security::{
    GetLengthSid, GetTokenInformation, TokenUser, PSECURITY_DESCRIPTOR, SECURITY_ATTRIBUTES,
    TOKEN_QUERY, TOKEN_USER,
};
use windows_sys::Win32::Storage::FileSystem::{
    CreateFileW, ReadFile, WriteFile, FILE_FLAG_FIRST_PIPE_INSTANCE, FILE_FLAG_OVERLAPPED,
    OPEN_EXISTING, PIPE_ACCESS_DUPLEX, SECURITY_IDENTIFICATION, SECURITY_SQOS_PRESENT,
};
use windows_sys::Win32::System::Pipes::{
    ConnectNamedPipe, CreateNamedPipeW, GetNamedPipeClientProcessId, GetNamedPipeServerProcessId,
    WaitNamedPipeW, PIPE_READMODE_BYTE, PIPE_REJECT_REMOTE_CLIENTS, PIPE_TYPE_BYTE,
    PIPE_UNLIMITED_INSTANCES, PIPE_WAIT,
};
use windows_sys::Win32::System::Threading::{
    CreateEventW, GetCurrentProcess, OpenProcess, OpenProcessToken,
    PROCESS_QUERY_LIMITED_INFORMATION,
};
use windows_sys::Win32::System::IO::{GetOverlappedResult, OVERLAPPED};

const BUFFER: u32 = 64 * 1024;
const CONNECT_TIMEOUT: Duration = Duration::from_secs(2);

fn wide(s: &str) -> Vec<u16> {
    s.encode_utf16().chain(std::iter::once(0)).collect()
}

fn os_error(code: u32) -> io::Error {
    io::Error::from_raw_os_error(code as i32)
}

fn owned(h: HANDLE) -> io::Result<OwnedHandle> {
    if h.is_null() || h == INVALID_HANDLE_VALUE {
        return Err(io::Error::last_os_error());
    }
    Ok(unsafe { OwnedHandle::from_raw_handle(h as RawHandle) })
}

fn raw(h: &OwnedHandle) -> HANDLE {
    h.as_raw_handle() as HANDLE
}

fn token_user(process: HANDLE) -> io::Result<Vec<u8>> {
    let mut token: HANDLE = ptr::null_mut();
    if unsafe { OpenProcessToken(process, TOKEN_QUERY, &mut token) } == 0 {
        return Err(io::Error::last_os_error());
    }
    let token = owned(token)?;

    let mut len = 0u32;
    unsafe { GetTokenInformation(raw(&token), TokenUser, ptr::null_mut(), 0, &mut len) };
    // u64 backing keeps TOKEN_USER suitably aligned.
    let mut buf = vec![0u64; (len as usize).div_ceil(8)];
    if unsafe { GetTokenInformation(raw(&token), TokenUser, buf.as_mut_ptr().cast(), len, &mut len) }
        == 0
    {
        return Err(io::Error::last_os_error());
    }
    let sid = unsafe { &*(buf.as_ptr() as *const TOKEN_USER) }.User.Sid;
    let n = unsafe { GetLengthSid(sid) } as usize;
    Ok(unsafe { std::slice::from_raw_parts(sid as *const u8, n) }.to_vec())
}

/// The SID of the user this process runs as.
pub fn current_user() -> io::Result<Vec<u8>> {
    token_user(unsafe { GetCurrentProcess() })
}

fn process_user(pid: u32) -> io::Result<Vec<u8>> {
    let process = owned(unsafe { OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, 0, pid) })?;
    token_user(raw(&process))
}

fn sid_string(sid: &[u8]) -> io::Result<String> {
    let mut out: *mut u16 = ptr::null_mut();
    if unsafe { ConvertSidToStringSidW(sid.as_ptr() as *mut _, &mut out) } == 0 {
        return Err(io::Error::last_os_error());
    }
    let len = (0..).take_while(|&i| unsafe { *out.add(i) } != 0).count();
    let s = String::from_utf16_lossy(unsafe { std::slice::from_raw_parts(out, len) });
    unsafe { LocalFree(out.cast()) };
    Ok(s)
}

type PeerQuery = unsafe extern "system" fn(HANDLE, *mut u32) -> BOOL;

fn peer_is(pipe: &OwnedHandle, query: PeerQuery, user: &[u8]) -> bool {
    let mut pid = 0u32;
    if unsafe { query(raw(pipe), &mut pid) } == 0 {
        return false;
    }
    process_user(pid).map(|sid| sid == user).unwrap_or(false)
}

pub struct Listener {
    name: Vec<u16>,
    sd: PSECURITY_DESCRIPTOR,
    user: Vec<u8>,
    next: Option<OwnedHandle>,
}

impl Listener {
    /// Creates the first instance of the pipe, failing if anyone (any user)
    /// already owns the name.
    pub fn bind(name: &str) -> io::Result<Self> {
        let user = current_user()?;
        // A protected DACL with a single entry: this user, full access.
        let sddl = wide(&format!("D:P(A;;GA;;;{})", sid_string(&user)?));
        let mut sd: PSECURITY_DESCRIPTOR = ptr::null_mut();
        if unsafe {
            ConvertStringSecurityDescriptorToSecurityDescriptorW(
                sddl.as_ptr(),
                SDDL_REVISION_1,
                &mut sd,
                ptr::null_mut(),
            )
        } == 0
        {
            return Err(io::Error::last_os_error());
        }

        let mut listener = Self {
            name: wide(name),
            sd,
            user,
            next: None,
        };
        listener.next = Some(listener.instance(true)?);
        Ok(listener)
    }

    fn instance(&self, first: bool) -> io::Result<OwnedHandle> {
        let sa = SECURITY_ATTRIBUTES {
            nLength: std::mem::size_of::<SECURITY_ATTRIBUTES>() as u32,
            lpSecurityDescriptor: self.sd,
            bInheritHandle: 0,
        };
        let mut open_mode = PIPE_ACCESS_DUPLEX;
        if first {
            open_mode |= FILE_FLAG_FIRST_PIPE_INSTANCE;
        }
        owned(unsafe {
            CreateNamedPipeW(
                self.name.as_ptr(),
                open_mode,
                PIPE_TYPE_BYTE | PIPE_READMODE_BYTE | PIPE_WAIT | PIPE_REJECT_REMOTE_CLIENTS,
                PIPE_UNLIMITED_INSTANCES,
                BUFFER,
                BUFFER,
                0,
                &sa,
            )
        })
    }

    /// Waits for a client. Returns the connection and whether the client
    /// process runs as the same user as this one.
    pub fn accept(&mut self) -> io::Result<(File, bool)> {
        loop {
            let pipe = match self.next.take() {
                Some(p) => p,
                None => self.instance(false)?,
            };
            if unsafe { ConnectNamedPipe(raw(&pipe), ptr::null_mut()) } == 0 {
                match unsafe { GetLastError() } {
                    ERROR_PIPE_CONNECTED => {}
                    // The client came and went before we got to it.
                    ERROR_NO_DATA => continue,
                    err => return Err(os_error(err)),
                }
            }
            // Have the next instance waiting before this one is handed off,
            // so a second client doesn't find the name missing.
            self.next = self.instance(false).ok();
            let same_user = peer_is(&pipe, GetNamedPipeClientProcessId, &self.user);
            return Ok((File::from(pipe), same_user));
        }
    }
}

impl Drop for Listener {
    fn drop(&mut self) {
        unsafe { LocalFree(self.sd) };
    }
}

/// Client end. Overlapped, because synchronous I/O on one pipe handle is
/// serialised: a reader blocked on one thread would stall writes from another.
pub struct Pipe {
    handle: OwnedHandle,
}

impl Pipe {
    pub fn connect(name: &str) -> io::Result<Self> {
        let wname = wide(name);
        let deadline = Instant::now() + CONNECT_TIMEOUT;
        let handle = loop {
            let h = unsafe {
                CreateFileW(
                    wname.as_ptr(),
                    GENERIC_READ | GENERIC_WRITE,
                    0,
                    ptr::null(),
                    OPEN_EXISTING,
                    // Identification only: the server may not impersonate us.
                    FILE_FLAG_OVERLAPPED | SECURITY_SQOS_PRESENT | SECURITY_IDENTIFICATION,
                    ptr::null_mut(),
                )
            };
            if h != INVALID_HANDLE_VALUE {
                break owned(h)?;
            }
            let err = unsafe { GetLastError() };
            if Instant::now() >= deadline || (err != ERROR_PIPE_BUSY && err != ERROR_FILE_NOT_FOUND) {
                return Err(os_error(err));
            }
            if err == ERROR_PIPE_BUSY {
                unsafe { WaitNamedPipeW(wname.as_ptr(), 500) };
            } else {
                std::thread::sleep(Duration::from_millis(50));
            }
        };

        if !peer_is(&handle, GetNamedPipeServerProcessId, &current_user()?) {
            return Err(io::Error::new(
                io::ErrorKind::PermissionDenied,
                "the pipe is held by a process running as a different user",
            ));
        }
        Ok(Self { handle })
    }

    fn overlapped(&self, start: impl FnOnce(HANDLE, *mut OVERLAPPED) -> BOOL) -> io::Result<usize> {
        let h = raw(&self.handle);
        let event = owned(unsafe { CreateEventW(ptr::null(), 1, 0, ptr::null()) })?;
        let mut ov: OVERLAPPED = unsafe { std::mem::zeroed() };
        ov.hEvent = raw(&event);

        if start(h, &mut ov) == 0 {
            let err = unsafe { GetLastError() };
            if err != ERROR_IO_PENDING {
                return eof_or(err);
            }
        }
        let mut n = 0u32;
        if unsafe { GetOverlappedResult(h, &ov, &mut n, 1) } == 0 {
            return eof_or(unsafe { GetLastError() });
        }
        Ok(n as usize)
    }
}

fn eof_or(err: u32) -> io::Result<usize> {
    if err == ERROR_BROKEN_PIPE {
        Ok(0)
    } else {
        Err(os_error(err))
    }
}

impl io::Read for &Pipe {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        let len = buf.len().min(u32::MAX as usize) as u32;
        self.overlapped(|h, ov| unsafe { ReadFile(h, buf.as_mut_ptr(), len, ptr::null_mut(), ov) })
    }
}

impl io::Write for &Pipe {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        let len = buf.len().min(u32::MAX as usize) as u32;
        self.overlapped(|h, ov| unsafe { WriteFile(h, buf.as_ptr(), len, ptr::null_mut(), ov) })
    }

    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}
