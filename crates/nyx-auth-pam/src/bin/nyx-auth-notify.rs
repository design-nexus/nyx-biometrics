//! Run by pam_exec around a terminal face, fingerprint or key check:
//!   nyx-auth-notify start|failed|done face|fingerprint|key|any
//! Always exits 0: it only tells the shell what to show.

use std::ffi::CString;
use std::path::Path;
use std::process::{Command, ExitCode, Stdio};
use std::time::{Duration, Instant};

use nyx_auth_pam::notify;

fn uid_of(user: &str) -> Option<u32> {
    let name = CString::new(user).ok()?;
    // SAFETY: getpwnam returns static storage or null; the uid is read at once.
    unsafe {
        let pw = libc::getpwnam(name.as_ptr());
        (!pw.is_null()).then(|| (*pw).pw_uid)
    }
}

fn main() -> ExitCode {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let (Some(event), Some(method)) = (args.first(), args.get(1)) else { return ExitCode::SUCCESS };
    // In sudo's session step PAM_USER is the target account (often root); the person at
    // the screen is the one who asked.
    let user = std::env::var("PAM_RUSER")
        .ok()
        .filter(|u| !u.is_empty() && u != "root")
        .or_else(|| std::env::var("PAM_USER").ok())
        .unwrap_or_default();
    let service = std::env::var("PAM_SERVICE").unwrap_or_default();
    let Some(uid) = uid_of(&user) else { return ExitCode::SUCCESS };
    // The sign-in waits on this; never more than a second in all.
    let deadline = Instant::now() + Duration::from_secs(1);
    for display in notify::displays(Path::new(&format!("/run/user/{uid}"))) {
        if let Some(argv) = notify::command(event, method, &service, &user, uid, &display) {
            deliver(&argv, deadline);
        }
    }
    ExitCode::SUCCESS
}

fn deliver(argv: &[String], deadline: Instant) {
    let Ok(mut child) = Command::new(&argv[0])
        .args(&argv[1..])
        .env_clear()
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
    else {
        return;
    };
    loop {
        match child.try_wait() {
            Ok(Some(_)) | Err(_) => break,
            Ok(None) if Instant::now() >= deadline => {
                let _ = child.kill();
                let _ = child.wait();
                break;
            }
            Ok(None) => std::thread::sleep(Duration::from_millis(10)),
        }
    }
}
