use std::collections::HashMap;
use std::io::{self, Read};
use std::process::{Command, Stdio};
use std::sync::Mutex;
use std::time::{Duration, Instant};

/// What a command printed and how it ended.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct Output {
    pub status: Option<i32>,
    pub stdout: String,
    pub stderr: String,
}

impl Output {
    pub fn ok(stdout: &str) -> Self {
        Self { status: Some(0), stdout: stdout.into(), stderr: String::new() }
    }

    pub fn failed(code: i32, stderr: &str) -> Self {
        Self { status: Some(code), stdout: String::new(), stderr: stderr.into() }
    }

    pub fn success(&self) -> bool {
        self.status == Some(0)
    }
}

#[derive(Debug, thiserror::Error)]
pub enum RunError {
    #[error("{0} isn't installed")]
    Missing(String),
    #[error("{0} didn't answer in time")]
    TimedOut(String),
    #[error("{program}: {source}")]
    Io { program: String, source: io::Error },
}

/// Runs a program by absolute path (see [`nyx_auth_core::system::path`]).
pub trait Runner {
    fn run(&self, program: &str, args: &[&str], timeout: Duration) -> Result<Output, RunError>;

    fn exists(&self, program: &str) -> bool;
}

/// Runs real programs with a cleared environment and a time limit.
pub struct SystemRunner;

const KEEP_ENV: &[&str] = &["PATH", "LANG", "LC_ALL", "XDG_RUNTIME_DIR", "DBUS_SESSION_BUS_ADDRESS", "HOME", "USER"];

impl Runner for SystemRunner {
    fn run(&self, program: &str, args: &[&str], timeout: Duration) -> Result<Output, RunError> {
        if !self.exists(program) {
            return Err(RunError::Missing(program.into()));
        }
        let mut cmd = Command::new(nyx_auth_core::system::path(program));
        cmd.args(args).env_clear().stdin(Stdio::null()).stdout(Stdio::piped()).stderr(Stdio::piped());
        for key in KEEP_ENV {
            if let Ok(v) = std::env::var(key) {
                cmd.env(key, v);
            }
        }
        cmd.env("LC_ALL", "C");
        let io_err = |source| RunError::Io { program: program.into(), source };
        let mut child = cmd.spawn().map_err(io_err)?;
        let stdout = child.stdout.take().expect("piped");
        let stderr = child.stderr.take().expect("piped");
        // Read on threads that report over channels, so a grandchild still holding a pipe
        // open can't keep this waiting past the deadline.
        let reader = |mut pipe: Box<dyn Read + Send>| {
            let (tx, rx) = std::sync::mpsc::channel();
            std::thread::spawn(move || {
                let mut s = String::new();
                let _ = pipe.read_to_string(&mut s);
                let _ = tx.send(s);
            });
            rx
        };
        let out_rx = reader(Box::new(stdout));
        let err_rx = reader(Box::new(stderr));
        let deadline = Instant::now() + timeout;
        let status = loop {
            if let Some(status) = child.try_wait().map_err(io_err)? {
                break status;
            }
            if Instant::now() >= deadline {
                let _ = child.kill();
                let _ = child.wait();
                return Err(RunError::TimedOut(program.into()));
            }
            std::thread::sleep(Duration::from_millis(15));
        };
        let collect = |rx: std::sync::mpsc::Receiver<String>| {
            // A child that exits right at the deadline still gets a moment for its output.
            let left = deadline.saturating_duration_since(Instant::now()).max(Duration::from_millis(100));
            rx.recv_timeout(left).map_err(|_| RunError::TimedOut(program.into()))
        };
        let stdout = collect(out_rx)?;
        let stderr = collect(err_rx).unwrap_or_default();
        Ok(Output { status: status.code(), stdout, stderr })
    }

    fn exists(&self, program: &str) -> bool {
        std::fs::metadata(nyx_auth_core::system::path(program)).map(|m| m.is_file()).unwrap_or(false)
    }
}

/// Replays recorded output, keyed by the full command line.
#[derive(Default)]
pub struct FakeRunner {
    replies: Mutex<HashMap<String, Result<Output, String>>>,
    installed: Vec<String>,
}

impl FakeRunner {
    pub fn new() -> Self {
        Self::default()
    }

    /// Mark a program as installed without recording any reply.
    pub fn installed(mut self, program: &str) -> Self {
        self.installed.push(program.into());
        self
    }

    pub fn reply(mut self, command: &str, output: Output) -> Self {
        let program = command.split(' ').next().unwrap_or_default().to_string();
        if !self.installed.contains(&program) {
            self.installed.push(program);
        }
        self.replies.get_mut().unwrap().insert(command.into(), Ok(output));
        self
    }

    pub fn time_out(mut self, command: &str) -> Self {
        let program = command.split(' ').next().unwrap_or_default().to_string();
        if !self.installed.contains(&program) {
            self.installed.push(program);
        }
        self.replies.get_mut().unwrap().insert(command.into(), Err(command.into()));
        self
    }
}

impl Runner for FakeRunner {
    fn run(&self, program: &str, args: &[&str], _timeout: Duration) -> Result<Output, RunError> {
        if !self.exists(program) {
            return Err(RunError::Missing(program.into()));
        }
        let key = std::iter::once(program).chain(args.iter().copied()).collect::<Vec<_>>().join(" ");
        match self.replies.lock().unwrap().get(&key) {
            Some(Ok(out)) => Ok(out.clone()),
            Some(Err(_)) => Err(RunError::TimedOut(program.into())),
            None => Ok(Output::failed(127, &format!("no recorded reply for: {key}"))),
        }
    }

    fn exists(&self, program: &str) -> bool {
        self.installed.iter().any(|p| p == program)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn system_runner_captures_output_and_times_out() {
        let out = SystemRunner.run("/bin/sh", &["-c", "echo hi; echo err >&2; exit 3"], Duration::from_secs(5)).unwrap();
        assert_eq!(out.stdout, "hi\n");
        assert_eq!(out.stderr, "err\n");
        assert_eq!(out.status, Some(3));
        assert!(matches!(
            SystemRunner.run("/bin/sh", &["-c", "sleep 5"], Duration::from_millis(100)),
            Err(RunError::TimedOut(_))
        ));
        assert!(matches!(SystemRunner.run("/nonexistent/tool", &[], Duration::from_secs(1)), Err(RunError::Missing(_))));
    }

    #[test]
    fn a_grandchild_holding_the_pipe_does_not_outlast_the_deadline() {
        let started = Instant::now();
        let r = SystemRunner.run("/bin/sh", &["-c", "sleep 5 & echo hi"], Duration::from_millis(500));
        assert!(matches!(r, Err(RunError::TimedOut(_))), "{r:?}");
        assert!(started.elapsed() < Duration::from_secs(3), "took {:?}", started.elapsed());
    }

    #[test]
    fn system_runner_clears_the_environment() {
        // SAFETY: tests in this module don't read this variable concurrently.
        unsafe { std::env::set_var("NYX_AUTH_SECRET_TEST", "leak") };
        let out = SystemRunner.run("/bin/sh", &["-c", "echo ${NYX_AUTH_SECRET_TEST:-clean}"], Duration::from_secs(5)).unwrap();
        assert_eq!(out.stdout.trim(), "clean");
    }
}
