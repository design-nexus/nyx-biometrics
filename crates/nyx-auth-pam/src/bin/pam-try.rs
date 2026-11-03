//! Test harness: `pam-try SERVICE USER PASSWORD` runs one real PAM authentication (and,
//! with `session`, opens a session when it succeeds) and exits 0 on success. Used only inside the test container.

use std::process::ExitCode;

use nyx_auth_pam::pamtest::{Prompt, authenticate, authenticate_and_open_session};

fn main() -> ExitCode {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let (service, user, password, session) = match args.as_slice() {
        [s, u, p] => (s, u, p, false),
        [s, u, p, flag] if flag == "session" => (s, u, p, true),
        _ => {
            eprintln!("usage: pam-try SERVICE USER PASSWORD [session]");
            return ExitCode::from(2);
        }
    };
    let respond = |p: Prompt| match p {
        Prompt::Secret(t) | Prompt::Visible(t) => {
            eprintln!("prompt: {t}");
            Some(password.clone())
        }
        Prompt::Info(t) => {
            eprintln!("message: {t}");
            None
        }
    };
    let result =
        if session { authenticate_and_open_session(service, user, respond) } else { authenticate(service, user, respond) };
    match result {
        Ok(()) => ExitCode::SUCCESS,
        Err(e) => {
            eprintln!("result: {e}");
            ExitCode::FAILURE
        }
    }
}
