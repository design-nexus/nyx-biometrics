//! Run by pam_exec in front of each face, fingerprint or key line. Exit 0 skips that line.

use std::path::Path;
use std::process::ExitCode;

use nyx_auth_hw::SystemRunner;
use nyx_auth_pam::gate::{self, Context, Kind};

/// Exit 0 skips the method, so a gate that panics skips it too, rather than letting a
/// remote session reach the sensors. (A missing gate binary can't be caught here; the
/// helper refuses to write a stack while the gate isn't installed.)
fn main() -> ExitCode {
    std::panic::set_hook(Box::new(|_| {}));
    std::panic::catch_unwind(run).unwrap_or(ExitCode::SUCCESS)
}

fn run() -> ExitCode {
    let kind = std::env::args().nth(1).as_deref().and_then(Kind::parse);
    let Some(kind) = kind else { return ExitCode::SUCCESS };
    let proc = Path::new("/proc");
    // pam_exec's child: the parent is the program running PAM (sudo, the polkit helper, …).
    let caller = std::os::unix::process::parent_id();
    let user = std::env::var("PAM_USER").unwrap_or_default();
    let service = std::env::var("PAM_SERVICE").unwrap_or_default();
    let password_first = service == "polkit-1" && uid_of(&user).is_some_and(|uid| {
        let managed = Path::new("/run/nyx-auth/password-first").join(&user).join("request");
        gate::fresh_password_marker(&managed, uid) || gate::password_first(Path::new("/run/user"), uid)
    });
    let ctx = Context {
        service,
        rhost: std::env::var("PAM_RHOST").unwrap_or_default(),
        ancestors: gate::ancestors(proc, caller),
        caller_session_remote: gate::session_remote(proc, &SystemRunner, caller),
        local_display: gate::local_display(&SystemRunner, &user),
        lid_closed: gate::lid_closed(proc),
        password_first,
    };
    match gate::decide(kind, &ctx) {
        Some(_) => ExitCode::SUCCESS,
        None => ExitCode::FAILURE,
    }
}

/// The account's user ID, from the password database.
fn uid_of(user: &str) -> Option<u32> {
    let name = std::ffi::CString::new(user).ok()?;
    let mut pw: libc::passwd = unsafe { std::mem::zeroed() };
    let mut buf = vec![0 as libc::c_char; 4096];
    let mut out: *mut libc::passwd = std::ptr::null_mut();
    // SAFETY: getpwnam_r writes only into pw and buf, whose sizes it's told.
    let rc = unsafe { libc::getpwnam_r(name.as_ptr(), &mut pw, buf.as_mut_ptr(), buf.len(), &mut out) };
    (rc == 0 && !out.is_null()).then_some(pw.pw_uid)
}
