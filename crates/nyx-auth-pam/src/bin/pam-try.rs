//! Test harness: `pam-try SERVICE USER PASSWORD` runs one real PAM authentication and
//! exits 0 on success. Used only inside the test container.

use std::process::ExitCode;

use nyx_auth_pam::pamtest::{Prompt, authenticate};

fn main() -> ExitCode {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let [service, user, password] = args.as_slice() else {
        eprintln!("usage: pam-try SERVICE USER PASSWORD");
        return ExitCode::from(2);
    };
    let result = authenticate(service, user, |p| match p {
        Prompt::Secret(t) | Prompt::Visible(t) => {
            eprintln!("prompt: {t}");
            Some(password.clone())
        }
        Prompt::Info(t) => {
            eprintln!("message: {t}");
            None
        }
    });
    match result {
        Ok(()) => ExitCode::SUCCESS,
        Err(e) => {
            eprintln!("result: {e}");
            ExitCode::FAILURE
        }
    }
}
