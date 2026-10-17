//! A minimal native password dialog, the Windows counterpart of the
//! osascript / zenity prompts.

use std::cell::RefCell;
use std::ffi::c_void;
use std::ptr;
use std::sync::Once;

use zeroize::Zeroize;

use windows_sys::Win32::Foundation::{HINSTANCE, HWND, LPARAM, LRESULT, RECT, WPARAM};
use windows_sys::Win32::Graphics::Gdi::{
    CreateFontIndirectW, DeleteObject, GetSysColorBrush, COLOR_BTNFACE, HFONT,
};
use windows_sys::Win32::System::LibraryLoader::GetModuleHandleW;
use windows_sys::Win32::System::Threading::{AttachThreadInput, GetCurrentThreadId};
use windows_sys::Win32::UI::HiDpi::{
    GetDpiForSystem, SetThreadDpiAwarenessContext, DPI_AWARENESS_CONTEXT_SYSTEM_AWARE,
};
use windows_sys::Win32::UI::Input::KeyboardAndMouse::SetFocus;
use windows_sys::Win32::UI::WindowsAndMessaging::{
    AdjustWindowRectEx, BringWindowToTop, CreateWindowExW, DefWindowProcW, DestroyWindow,
    DispatchMessageW, GetDlgItem, GetForegroundWindow, GetMessageW, GetSystemMetrics,
    GetWindowTextLengthW, GetWindowTextW, GetWindowThreadProcessId, IsDialogMessageW, LoadCursorW,
    PostQuitMessage, RegisterClassExW, SendMessageW, SetForegroundWindow, SetWindowTextW,
    ShowWindow, SystemParametersInfoW, TranslateMessage, BS_DEFPUSHBUTTON, BS_PUSHBUTTON,
    ES_AUTOHSCROLL, ES_PASSWORD, IDCANCEL, IDC_ARROW, IDOK, MSG, NONCLIENTMETRICSW, SM_CXSCREEN,
    SM_CYSCREEN, SPI_GETNONCLIENTMETRICS, SW_SHOW, WM_CLOSE, WM_COMMAND, WM_DESTROY, WM_SETFONT,
    WNDCLASSEXW, WS_CAPTION, WS_CHILD, WS_EX_CLIENTEDGE, WS_EX_CONTROLPARENT,
    WS_EX_DLGMODALFRAME, WS_EX_TOPMOST, WS_OVERLAPPED, WS_SYSMENU, WS_TABSTOP, WS_VISIBLE,
};

const ID_EDIT: i32 = 100;

fn wide(s: &str) -> Vec<u16> {
    s.encode_utf16().chain(std::iter::once(0)).collect()
}

fn class_name() -> Vec<u16> {
    wide("BwAgentPrompt")
}

thread_local! {
    static ANSWER: RefCell<Option<String>> = const { RefCell::new(None) };
}

/// Shows the dialog on the calling thread and blocks until it closes.
/// Returns `None` on Cancel, Esc, close, or an empty entry.
pub fn prompt(message: &str) -> Option<String> {
    unsafe {
        let previous = SetThreadDpiAwarenessContext(DPI_AWARENESS_CONTEXT_SYSTEM_AWARE);
        let answer = dialog(message);
        if !previous.is_null() {
            SetThreadDpiAwarenessContext(previous);
        }
        answer
    }
}

unsafe fn dialog(message: &str) -> Option<String> {
    let instance = GetModuleHandleW(ptr::null());
    register_class(instance);

    let dpi = GetDpiForSystem() as i32;
    let px = |v: i32| v * dpi / 96;

    let style = WS_OVERLAPPED | WS_CAPTION | WS_SYSMENU;
    let ex_style = WS_EX_TOPMOST | WS_EX_DLGMODALFRAME | WS_EX_CONTROLPARENT;
    let mut rect = RECT {
        left: 0,
        top: 0,
        right: px(340),
        bottom: px(128),
    };
    AdjustWindowRectEx(&mut rect, style, 0, ex_style);
    let (w, h) = (rect.right - rect.left, rect.bottom - rect.top);
    let x = (GetSystemMetrics(SM_CXSCREEN) - w) / 2;
    let y = (GetSystemMetrics(SM_CYSCREEN) - h) / 2;

    let class = class_name();
    let title = wide("Bitwarden");
    let hwnd = CreateWindowExW(
        ex_style,
        class.as_ptr(),
        title.as_ptr(),
        style,
        x,
        y,
        w,
        h,
        ptr::null_mut(),
        ptr::null_mut(),
        instance,
        ptr::null(),
    );
    if hwnd.is_null() {
        return None;
    }

    let child = |class: &str, text: &str, style: u32, ex: u32, r: (i32, i32, i32, i32), id: i32| {
        let class = wide(class);
        let text = wide(text);
        CreateWindowExW(
            ex,
            class.as_ptr(),
            text.as_ptr(),
            WS_CHILD | WS_VISIBLE | style,
            px(r.0),
            px(r.1),
            px(r.2),
            px(r.3),
            hwnd,
            id as isize as *mut c_void,
            instance,
            ptr::null(),
        )
    };
    let label = child("STATIC", message, 0, 0, (16, 16, 308, 20), 0);
    let edit = child(
        "EDIT",
        "",
        WS_TABSTOP | ES_PASSWORD as u32 | ES_AUTOHSCROLL as u32,
        WS_EX_CLIENTEDGE,
        (16, 42, 308, 24),
        ID_EDIT,
    );
    let ok = child("BUTTON", "OK", WS_TABSTOP | BS_DEFPUSHBUTTON as u32, 0, (152, 84, 80, 28), IDOK);
    let cancel = child("BUTTON", "Cancel", WS_TABSTOP | BS_PUSHBUTTON as u32, 0, (244, 84, 80, 28), IDCANCEL);

    let font = message_font();
    if !font.is_null() {
        for control in [label, edit, ok, cancel] {
            SendMessageW(control, WM_SETFONT, font as WPARAM, 1);
        }
    }

    ANSWER.with(|a| a.borrow_mut().take());
    ShowWindow(hwnd, SW_SHOW);
    bring_to_front(hwnd, edit);

    let mut msg: MSG = std::mem::zeroed();
    while GetMessageW(&mut msg, ptr::null_mut(), 0, 0) > 0 {
        if IsDialogMessageW(hwnd, &msg) == 0 {
            TranslateMessage(&msg);
            DispatchMessageW(&msg);
        }
    }

    if !font.is_null() {
        DeleteObject(font);
    }
    ANSWER.with(|a| a.borrow_mut().take()).filter(|s| !s.is_empty())
}

unsafe fn register_class(instance: HINSTANCE) {
    static REGISTER: Once = Once::new();
    REGISTER.call_once(|| {
        let class = class_name();
        let wc = WNDCLASSEXW {
            cbSize: std::mem::size_of::<WNDCLASSEXW>() as u32,
            style: 0,
            lpfnWndProc: Some(window_proc),
            cbClsExtra: 0,
            cbWndExtra: 0,
            hInstance: instance,
            hIcon: ptr::null_mut(),
            hCursor: LoadCursorW(ptr::null_mut(), IDC_ARROW),
            hbrBackground: GetSysColorBrush(COLOR_BTNFACE),
            lpszMenuName: ptr::null(),
            lpszClassName: class.as_ptr(),
            hIconSm: ptr::null_mut(),
        };
        RegisterClassExW(&wc);
    });
}

unsafe fn message_font() -> HFONT {
    let mut metrics: NONCLIENTMETRICSW = std::mem::zeroed();
    metrics.cbSize = std::mem::size_of::<NONCLIENTMETRICSW>() as u32;
    if SystemParametersInfoW(
        SPI_GETNONCLIENTMETRICS,
        metrics.cbSize,
        &mut metrics as *mut _ as *mut c_void,
        0,
    ) == 0
    {
        return ptr::null_mut();
    }
    CreateFontIndirectW(&metrics.lfMessageFont)
}

// A background process may not take the foreground on its own; borrowing the
// foreground thread's input state lets the prompt come up focused.
unsafe fn bring_to_front(hwnd: HWND, focus: HWND) {
    let me = GetCurrentThreadId();
    let foreground = GetWindowThreadProcessId(GetForegroundWindow(), ptr::null_mut());
    let attached = foreground != 0 && foreground != me && AttachThreadInput(me, foreground, 1) != 0;
    BringWindowToTop(hwnd);
    SetForegroundWindow(hwnd);
    SetFocus(focus);
    if attached {
        AttachThreadInput(me, foreground, 0);
    }
}

unsafe fn take_text(edit: HWND) -> String {
    let len = GetWindowTextLengthW(edit).max(0) as usize;
    let mut buf = vec![0u16; len + 1];
    let n = GetWindowTextW(edit, buf.as_mut_ptr(), buf.len() as i32).max(0) as usize;
    let text = String::from_utf16_lossy(&buf[..n]);
    buf.zeroize();
    // Scrub the control's own copy before the window goes away.
    SetWindowTextW(edit, [0u16].as_ptr());
    text
}

unsafe extern "system" fn window_proc(hwnd: HWND, msg: u32, wparam: WPARAM, lparam: LPARAM) -> LRESULT {
    match msg {
        WM_COMMAND => match (wparam & 0xffff) as i32 {
            IDOK => {
                let text = take_text(GetDlgItem(hwnd, ID_EDIT));
                ANSWER.with(|a| *a.borrow_mut() = Some(text));
                DestroyWindow(hwnd);
                0
            }
            IDCANCEL => {
                DestroyWindow(hwnd);
                0
            }
            _ => DefWindowProcW(hwnd, msg, wparam, lparam),
        },
        WM_CLOSE => {
            DestroyWindow(hwnd);
            0
        }
        WM_DESTROY => {
            PostQuitMessage(0);
            0
        }
        _ => DefWindowProcW(hwnd, msg, wparam, lparam),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::{Duration, Instant};
    use windows_sys::Win32::UI::Input::KeyboardAndMouse::{VK_ESCAPE, VK_RETURN};
    use windows_sys::Win32::UI::WindowsAndMessaging::{FindWindowW, PostMessageW, WM_KEYDOWN, WM_SETTEXT};

    fn wait_for_dialog() -> HWND {
        let class = class_name();
        let deadline = Instant::now() + Duration::from_secs(5);
        loop {
            let hwnd = unsafe { FindWindowW(class.as_ptr(), ptr::null()) };
            if !hwnd.is_null() {
                return hwnd;
            }
            assert!(Instant::now() < deadline, "the dialog never appeared");
            std::thread::sleep(Duration::from_millis(20));
        }
    }

    fn answer_with(text: &str, key: u16) -> Option<String> {
        let shown = std::thread::spawn(|| prompt("Enter PIN:"));
        let hwnd = wait_for_dialog();
        unsafe {
            let edit = GetDlgItem(hwnd, ID_EDIT);
            let text = wide(text);
            SendMessageW(edit, WM_SETTEXT, 0, text.as_ptr() as LPARAM);
            PostMessageW(edit, WM_KEYDOWN, key as WPARAM, 0);
        }
        shown.join().unwrap()
    }

    #[test]
    fn enter_returns_the_pin_and_escape_cancels() {
        assert_eq!(answer_with("1234", VK_RETURN).as_deref(), Some("1234"));
        assert_eq!(answer_with("5678", VK_ESCAPE), None);
        assert_eq!(answer_with("", VK_RETURN), None);
    }
}
