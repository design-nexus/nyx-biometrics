//! Run one real PAM authentication against a service, to test a change before keeping it.

use std::ffi::{CStr, CString, c_char, c_int, c_void};

#[repr(C)]
struct PamMessage {
    msg_style: c_int,
    msg: *const c_char,
}

#[repr(C)]
struct PamResponse {
    resp: *mut c_char,
    resp_retcode: c_int,
}

#[repr(C)]
struct PamConv {
    conv: extern "C" fn(c_int, *mut *const PamMessage, *mut *mut PamResponse, *mut c_void) -> c_int,
    appdata_ptr: *mut c_void,
}

const PAM_SUCCESS: c_int = 0;
const PAM_BUF_ERR: c_int = 5;
const PAM_CONV_ERR: c_int = 19;
const PAM_PROMPT_ECHO_OFF: c_int = 1;
const PAM_PROMPT_ECHO_ON: c_int = 2;

#[link(name = "pam")]
unsafe extern "C" {
    fn pam_start(service: *const c_char, user: *const c_char, conv: *const PamConv, handle: *mut *mut c_void) -> c_int;
    fn pam_authenticate(handle: *mut c_void, flags: c_int) -> c_int;
    fn pam_end(handle: *mut c_void, status: c_int) -> c_int;
    fn pam_open_session(handle: *mut c_void, flags: c_int) -> c_int;
    fn pam_close_session(handle: *mut c_void, flags: c_int) -> c_int;
    fn pam_strerror(handle: *mut c_void, errnum: c_int) -> *const c_char;
}

/// What a module asked or said.
pub enum Prompt<'a> {
    /// A secret (password, PIN): answer without echo.
    Secret(&'a str),
    Visible(&'a str),
    /// Information such as "Touch your security key"; no answer.
    Info(&'a str),
}

type Responder<'a> = dyn FnMut(Prompt) -> Option<String> + 'a;

extern "C" fn conv(n: c_int, msgs: *mut *const PamMessage, resp: *mut *mut PamResponse, data: *mut c_void) -> c_int {
    // SAFETY: PAM passes `n` messages and frees the calloc'd response array and strings;
    // `data` points at the responder in `authenticate`, alive for the whole call.
    unsafe {
        if n <= 0 {
            return PAM_CONV_ERR;
        }
        let responder = &mut *(data as *mut &mut Responder);
        let out = libc::calloc(n as usize, std::mem::size_of::<PamResponse>()) as *mut PamResponse;
        if out.is_null() {
            return PAM_BUF_ERR;
        }
        for i in 0..n as usize {
            let m = &**msgs.add(i);
            let text = if m.msg.is_null() { String::new() } else { CStr::from_ptr(m.msg).to_string_lossy().into_owned() };
            let answer = match m.msg_style {
                PAM_PROMPT_ECHO_OFF => responder(Prompt::Secret(&text)),
                PAM_PROMPT_ECHO_ON => responder(Prompt::Visible(&text)),
                _ => {
                    responder(Prompt::Info(&text));
                    continue;
                }
            };
            let Some(answer) = answer.and_then(|a| CString::new(a).ok()) else {
                for j in 0..i {
                    libc::free((*out.add(j)).resp as *mut c_void);
                }
                libc::free(out as *mut c_void);
                return PAM_CONV_ERR;
            };
            (*out.add(i)).resp = libc::strdup(answer.as_ptr());
        }
        *resp = out;
        PAM_SUCCESS
    }
}

/// `Ok` when PAM accepted; otherwise PAM's reason.
pub fn authenticate(service: &str, user: &str, responder: impl FnMut(Prompt) -> Option<String>) -> Result<(), String> {
    run(service, user, responder, false)
}

/// As `authenticate`, then open and close a session, as sudo does after a sign-in.
pub fn authenticate_and_open_session(
    service: &str,
    user: &str,
    responder: impl FnMut(Prompt) -> Option<String>,
) -> Result<(), String> {
    run(service, user, responder, true)
}

fn run(service: &str, user: &str, mut responder: impl FnMut(Prompt) -> Option<String>, session: bool) -> Result<(), String> {
    let service = CString::new(service).map_err(|_| "bad service")?;
    let user = CString::new(user).map_err(|_| "bad user")?;
    let mut dynamic: &mut Responder = &mut responder;
    let conversation = PamConv { conv, appdata_ptr: &mut dynamic as *mut &mut Responder as *mut c_void };
    let mut handle = std::ptr::null_mut();
    // SAFETY: every pointer refers to a value that outlives the PAM handle.
    unsafe {
        let rc = pam_start(service.as_ptr(), user.as_ptr(), &conversation, &mut handle);
        if rc != PAM_SUCCESS {
            return Err(format!("pam_start failed ({rc})"));
        }
        let mut rc = pam_authenticate(handle, 0);
        if rc == PAM_SUCCESS && session {
            rc = pam_open_session(handle, 0);
            if rc == PAM_SUCCESS {
                pam_close_session(handle, 0);
            }
        }
        let reason = CStr::from_ptr(pam_strerror(handle, rc)).to_string_lossy().into_owned();
        pam_end(handle, rc);
        if rc == PAM_SUCCESS { Ok(()) } else { Err(reason) }
    }
}

/// Read a line from the terminal with echo off.
pub fn read_secret(prompt: &str) -> Option<String> {
    use std::io::{BufRead, Write};
    let tty = std::fs::OpenOptions::new().read(true).write(true).open("/dev/tty").ok()?;
    let fd = std::os::fd::AsRawFd::as_raw_fd(&tty);
    // SAFETY: termios calls on an open tty descriptor with a zeroed struct they fill.
    let saved = unsafe {
        let mut t: libc::termios = std::mem::zeroed();
        if libc::tcgetattr(fd, &mut t) != 0 {
            return None;
        }
        let saved = t;
        t.c_lflag &= !libc::ECHO;
        libc::tcsetattr(fd, libc::TCSANOW, &t);
        saved
    };
    let mut w = &tty;
    let _ = write!(w, "{prompt}");
    let _ = w.flush();
    let mut line = String::new();
    let read = std::io::BufReader::new(&tty).read_line(&mut line);
    // SAFETY: restoring the attributes read above.
    unsafe { libc::tcsetattr(fd, libc::TCSANOW, &saved) };
    let _ = writeln!(w);
    read.ok()?;
    Some(line.trim_end_matches(['\n', '\r']).to_string())
}
