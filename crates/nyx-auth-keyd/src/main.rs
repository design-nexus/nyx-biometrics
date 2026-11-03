//! Started by systemd for one connection (`nyx-auth-keyd.socket`, Accept=yes): the socket
//! is standard input and output.

use std::io::{BufRead, BufReader, Read, Write};
use std::os::fd::FromRawFd;
use std::path::PathBuf;
use std::time::Duration;

use nyx_auth_hw::{Runner, SystemRunner};
use nyx_auth_keyd::{Keyd, Peer, STATE, System, installed};
use nyx_auth_proto::keyd::{MAX_LINE, Reply, Request};
use zeroize::Zeroizing;

const PKCHECK: &str = "/usr/bin/pkcheck";
const SYSTEMD_CREDS: &str = "/usr/bin/systemd-creds";

struct Real;

impl System for Real {
    fn authorize(&self, peer: &Peer, action: &str, message: &str) -> Result<bool, String> {
        let process = format!("{},{},{}", peer.pid, peer.start_time, peer.uid);
        let out = SystemRunner
            .run(
                PKCHECK,
                &[
                    "--action-id",
                    action,
                    "--process",
                    &process,
                    "--allow-user-interaction",
                    "--detail",
                    "polkit.message",
                    message,
                ],
                Duration::from_secs(90),
            )
            .map_err(|e| e.to_string())?;
        // 0 authorized; 1 not authorized; 2 the user dismissed the dialog; 3 error.
        match out.status {
            Some(0) => Ok(true),
            Some(1 | 2) => Ok(false),
            _ => Err(format!("polkit: {}", out.stderr.trim())),
        }
    }

    fn seal(&self, credential: &str, secret: &[u8]) -> Result<Vec<u8>, String> {
        creds(&["encrypt", "--with-key=tpm2", &format!("--name={credential}"), "-", "-"], secret).map(|v| v.to_vec())
    }

    fn unseal(&self, credential: &str, blob: &[u8]) -> Result<Zeroizing<Vec<u8>>, String> {
        creds(&["decrypt", &format!("--name={credential}"), "-", "-"], blob)
    }
}

/// systemd-creds with the secret on stdin, never on the command line.
fn creds(args: &[&str], input: &[u8]) -> Result<Zeroizing<Vec<u8>>, String> {
    use std::process::{Command, Stdio};
    let mut child = Command::new(SYSTEMD_CREDS)
        .args(args)
        .env_clear()
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .spawn()
        .map_err(|e| e.to_string())?;
    child.stdin.take().expect("piped").write_all(input).map_err(|e| e.to_string())?;
    let out = child.wait_with_output().map_err(|e| e.to_string())?;
    let data = Zeroizing::new(out.stdout);
    if out.status.success() { Ok(data) } else { Err("the TPM couldn't seal or open the secret".into()) }
}

fn peer(fd: i32) -> Result<Peer, String> {
    let mut cred = libc::ucred { pid: 0, uid: 0, gid: 0 };
    let mut len = std::mem::size_of::<libc::ucred>() as libc::socklen_t;
    // SAFETY: SO_PEERCRED fills exactly one ucred on a connected Unix socket.
    let rc = unsafe { libc::getsockopt(fd, libc::SOL_SOCKET, libc::SO_PEERCRED, &mut cred as *mut _ as *mut _, &mut len) };
    if rc != 0 || cred.pid <= 0 {
        return Err("no peer credentials".into());
    }
    let pid = cred.pid as u32;
    let start = |pid: u32| {
        let stat = std::fs::read_to_string(format!("/proc/{pid}/stat")).ok()?;
        stat[stat.rfind(')')? + 1..].split_whitespace().nth(19)?.parse::<u64>().ok()
    };
    let start_time = start(pid).ok_or("the peer is gone")?;
    let path = std::fs::read_link(format!("/proc/{pid}/exe"))
        .map(|p| PathBuf::from(p.to_string_lossy().trim_end_matches(" (deleted)")))
        .map_err(|_| "can't see the peer's program")?;
    let home = home_of(cred.uid).ok_or("the peer's user has no home")?;
    if !installed(&path, &home) {
        return Err("this program isn't installed where the suite installs it".into());
    }
    let exe = path.file_name().map(|n| n.to_string_lossy().to_string()).ok_or("can't see the peer's program")?;
    // Read the start time again: if the pid was reused meanwhile, it changed.
    if start(pid) != Some(start_time) {
        return Err("the peer changed".into());
    }
    Ok(Peer { uid: cred.uid, pid, start_time, exe })
}

/// The user's home directory from the password database.
fn home_of(uid: u32) -> Option<PathBuf> {
    // SAFETY: `passwd` is plain data; all-zero is a valid value to be filled in.
    let mut pwd: libc::passwd = unsafe { std::mem::zeroed() };
    let mut buf = vec![0u8; 4096];
    let mut found: *mut libc::passwd = std::ptr::null_mut();
    // SAFETY: `pwd`, `buf` and `found` are valid for writes of the sizes given; on success
    // `pw_dir` points into `buf`, which outlives its use here.
    let rc = unsafe { libc::getpwuid_r(uid, &mut pwd, buf.as_mut_ptr().cast(), buf.len(), &mut found) };
    if rc != 0 || found.is_null() || pwd.pw_dir.is_null() {
        return None;
    }
    // SAFETY: getpwuid_r returned a NUL-terminated string inside `buf`.
    let dir = unsafe { std::ffi::CStr::from_ptr(pwd.pw_dir) };
    use std::os::unix::ffi::OsStrExt;
    Some(PathBuf::from(std::ffi::OsStr::from_bytes(dir.to_bytes())))
}

fn main() {
    // SAFETY: systemd hands the accepted connection over as fd 0 and 1; each is wrapped
    // once.
    let input = unsafe { std::fs::File::from_raw_fd(0) };
    let mut output = unsafe { std::fs::File::from_raw_fd(1) };
    let reply = match peer(0) {
        Err(e) => Reply::err("refused", e),
        Ok(peer) => {
            let mut line = Zeroizing::new(String::new());
            match BufReader::new(input).take(MAX_LINE as u64).read_line(&mut line) {
                Ok(_) => match serde_json::from_str::<Request>(&line) {
                    Ok(request) => Keyd { state: STATE.into(), system: &Real }.handle(&peer, request),
                    Err(_) => Reply::err("bad-request", "not a request"),
                },
                Err(e) => Reply::err("bad-request", e.to_string()),
            }
        }
    };
    let mut text = Zeroizing::new(serde_json::to_string(&reply).expect("reply serializes"));
    text.push('\n');
    let _ = output.write_all(text.as_bytes());
    if let Some(mut s) = reply.secret {
        zeroize::Zeroize::zeroize(&mut s);
    }
}

#[cfg(test)]
mod tests {
    #[test]
    fn home_of_this_user() {
        // SAFETY: getuid has no preconditions.
        let uid = unsafe { libc::getuid() };
        // From the password database, not $HOME (which a container or the caller may set).
        let home = super::home_of(uid).expect("this user has a home");
        assert!(home.is_absolute(), "{}", home.display());
        assert!(super::home_of(u32::MAX - 1).is_none(), "no such user");
    }
}
