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
    let ctx = Context {
        service: std::env::var("PAM_SERVICE").unwrap_or_default(),
        rhost: std::env::var("PAM_RHOST").unwrap_or_default(),
        ancestors: gate::ancestors(proc, caller),
        caller_session_remote: gate::session_remote(proc, &SystemRunner, caller),
        local_display: gate::local_display(&SystemRunner, &user),
        lid_closed: gate::lid_closed(proc),
    };
    match gate::decide(kind, &ctx) {
        Some(_) => ExitCode::SUCCESS,
        None => ExitCode::FAILURE,
    }
}
