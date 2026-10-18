//! Starting the background agent on demand (Windows): used by bw-proxy when
//! the browser connects before the agent is up, and by `bw-agent enroll`.

use std::io;
use std::os::windows::process::CommandExt;
use std::path::Path;
use std::process::{Command, Stdio};

use windows_sys::Win32::Foundation::{
    GetLastError, SetHandleInformation, ERROR_FILE_NOT_FOUND, HANDLE_FLAG_INHERIT,
};
use windows_sys::Win32::System::Console::{
    GetStdHandle, STD_ERROR_HANDLE, STD_INPUT_HANDLE, STD_OUTPUT_HANDLE,
};
use windows_sys::Win32::System::Pipes::WaitNamedPipeW;
use windows_sys::Win32::System::Threading::CREATE_BREAKAWAY_FROM_JOB;

pub const LAUNCHER: &str = "bw-agentw.exe";

/// Whether an agent is listening, without connecting to it.
pub fn agent_running() -> bool {
    let name: Vec<u16> = bw_proto::paths::pipe_name()
        .encode_utf16()
        .chain(std::iter::once(0))
        .collect();
    unsafe { WaitNamedPipeW(name.as_ptr(), 1) != 0 || GetLastError() != ERROR_FILE_NOT_FOUND }
}

/// Starts `bw-agentw.exe` from `dir`. Returns `Ok(false)` if it isn't there.
pub fn start_agent(dir: &Path) -> io::Result<bool> {
    let launcher = dir.join(LAUNCHER);
    if !launcher.is_file() {
        return Ok(false);
    }

    // Our stdio may be the browser's pipes; a child holding them open would
    // keep the browser from ever seeing this host exit.
    for which in [STD_INPUT_HANDLE, STD_OUTPUT_HANDLE, STD_ERROR_HANDLE] {
        unsafe { SetHandleInformation(GetStdHandle(which), HANDLE_FLAG_INHERIT, 0) };
    }

    let spawn = |flags: u32| {
        Command::new(&launcher)
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .creation_flags(flags)
            .spawn()
    };
    // Browsers run native hosts in a job that is killed along with them; the
    // agent has to break away to outlive this process. If the job forbids
    // that, it still runs for as long as the job does.
    spawn(CREATE_BREAKAWAY_FROM_JOB).or_else(|_| spawn(0))?;
    Ok(true)
}
