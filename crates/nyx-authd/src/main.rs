//! Serves `io.github.design_nexus.nyx.Auth1` on the session bus, started by D-Bus when a Nyx
//! app first asks, and gone again after a quiet while.

use std::path::PathBuf;
use std::sync::Arc;
use std::time::{Duration, Instant};

use futures_util::StreamExt;
use nyx_auth_proto::{BUS_NAME, MethodStatus, OBJECT_PATH, Reply, Request};
use nyx_authd::{Broker, Caller, Check, Decision, POLKIT_ACTION, check_from_status, known_caller, load_policy, methods};
use tokio::sync::Mutex;
use zbus::message::Header;
use zbus::{Connection, fdo, interface};

const PKCHECK: &str = "/usr/bin/pkcheck";
/// The person has this long to answer the prompt.
const PROMPT_TIMEOUT: Duration = Duration::from_secs(120);
/// Exit after this long with nothing to do and no grant to keep.
const IDLE: Duration = Duration::from_secs(600);

struct State {
    broker: Broker,
    /// The running pkcheck, so the caller that asked can cancel it.
    prompt: Option<(String, u32)>,
    last_used: Instant,
}

struct Service {
    state: Arc<Mutex<State>>,
    home: PathBuf,
    policy: PathBuf,
}

fn start_time(pid: u32) -> Option<u64> {
    let stat = std::fs::read_to_string(format!("/proc/{pid}/stat")).ok()?;
    stat[stat.rfind(')')? + 1..].split_whitespace().nth(19)?.parse().ok()
}

impl Service {
    /// Who sent this call, from the bus's record of the connection: same user, a known
    /// program in a known place, and the same process before and after looking.
    async fn caller(&self, conn: &Connection, header: &Header<'_>) -> fdo::Result<Caller> {
        let sender = header.sender().ok_or_else(|| fdo::Error::AccessDenied("no sender".into()))?;
        let creds = fdo::DBusProxy::new(conn).await?.get_connection_credentials(sender.clone().into()).await?;
        let (Some(pid), Some(uid)) = (creds.process_id(), creds.unix_user_id()) else {
            return Err(fdo::Error::AccessDenied("no credentials".into()));
        };
        // SAFETY: getuid has no preconditions.
        if uid != unsafe { libc::getuid() } {
            return Err(fdo::Error::AccessDenied("another user".into()));
        }
        let before = start_time(pid).ok_or_else(|| fdo::Error::AccessDenied("the caller is gone".into()))?;
        let exe =
            std::fs::read_link(format!("/proc/{pid}/exe")).map_err(|_| fdo::Error::AccessDenied("unknown program".into()))?;
        if start_time(pid) != Some(before) {
            return Err(fdo::Error::AccessDenied("the caller changed".into()));
        }
        let exe = PathBuf::from(exe.to_string_lossy().trim_end_matches(" (deleted)"));
        known_caller(&exe, &self.home).ok_or_else(|| fdo::Error::AccessDenied("this program may not ask".into()))
    }
}

/// Asks polkit about this process, letting it show the prompt. Returns how it ended.
async fn confirm(state: Arc<Mutex<State>>, caller: &str) -> Check {
    let subject = match start_time(std::process::id()) {
        // SAFETY: getuid has no preconditions.
        Some(start) => format!("{},{start},{}", std::process::id(), unsafe { libc::getuid() }),
        None => return Check::Failed,
    };
    let child = tokio::process::Command::new(PKCHECK)
        .args(["--action-id", POLKIT_ACTION, "--process", &subject, "--allow-user-interaction"])
        .env_clear()
        .stdin(std::process::Stdio::null())
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .kill_on_drop(true)
        .spawn();
    let Ok(mut child) = child else { return Check::Failed };
    if let Some(pid) = child.id() {
        state.lock().await.prompt = Some((caller.to_string(), pid));
    }
    let result = tokio::time::timeout(PROMPT_TIMEOUT, child.wait()).await;
    state.lock().await.prompt = None;
    match result {
        Ok(Ok(status)) => check_from_status(status.code()),
        Ok(Err(_)) => Check::Failed,
        Err(_) => Check::TimedOut,
    }
}

#[interface(name = "io.github.design_nexus.nyx.Auth1")]
impl Service {
    async fn authenticate(
        &self,
        #[zbus(connection)] conn: &Connection,
        #[zbus(header)] header: Header<'_>,
        request: Request,
    ) -> fdo::Result<Reply> {
        let caller = self.caller(conn, &header).await?;
        let policy = load_policy(&self.policy);
        let decision = {
            let mut st = self.state.lock().await;
            st.last_used = Instant::now();
            st.broker.begin(&caller, &request, &policy, Instant::now())
        };
        match decision {
            Decision::Answer(reply) => Ok(reply),
            Decision::Prompt => {
                let check = confirm(self.state.clone(), caller.name).await;
                let mut st = self.state.lock().await;
                st.last_used = Instant::now();
                Ok(st.broker.finish(&caller, &request, check, Instant::now()))
            }
        }
    }

    async fn check(
        &self,
        #[zbus(connection)] conn: &Connection,
        #[zbus(header)] header: Header<'_>,
        action: String,
    ) -> fdo::Result<u32> {
        let caller = self.caller(conn, &header).await?;
        Ok(self.state.lock().await.broker.check(&caller, &action, Instant::now()))
    }

    async fn revoke(
        &self,
        #[zbus(connection)] conn: &Connection,
        #[zbus(header)] header: Header<'_>,
        action: String,
    ) -> fdo::Result<()> {
        let caller = self.caller(conn, &header).await?;
        self.state.lock().await.broker.revoke(&caller, &action);
        Ok(())
    }

    /// Closes the prompt this caller opened. Ending pkcheck withdraws polkit's request, so
    /// the dialog goes away.
    async fn cancel(&self, #[zbus(connection)] conn: &Connection, #[zbus(header)] header: Header<'_>) -> fdo::Result<()> {
        let caller = self.caller(conn, &header).await?;
        let st = self.state.lock().await;
        if let Some((owner, pid)) = &st.prompt
            && owner == caller.name
        {
            // SAFETY: signalling our own child, which is still running while recorded.
            unsafe { libc::kill(*pid as i32, libc::SIGTERM) };
        }
        Ok(())
    }

    async fn methods(
        &self,
        #[zbus(connection)] conn: &Connection,
        #[zbus(header)] header: Header<'_>,
    ) -> fdo::Result<Vec<MethodStatus>> {
        self.caller(conn, &header).await?;
        Ok(methods(&load_policy(&self.policy)))
    }
}

/// Grants end when any session locks or the computer is about to sleep.
async fn watch_lock_and_sleep(state: Arc<Mutex<State>>) {
    let Ok(system) = Connection::system().await else { return };
    let rules = [
        "type='signal',interface='org.freedesktop.login1.Session',member='Lock'",
        "type='signal',interface='org.freedesktop.login1.Manager',member='PrepareForSleep'",
    ];
    let proxy = match fdo::DBusProxy::new(&system).await {
        Ok(p) => p,
        Err(_) => return,
    };
    for rule in rules {
        if let Ok(rule) = zbus::MatchRule::try_from(rule) {
            let _ = proxy.add_match_rule(rule).await;
        }
    }
    let mut stream = zbus::MessageStream::from(&system);
    while let Some(Ok(msg)) = stream.next().await {
        let header = msg.header();
        let member = header.member().map(|m| m.as_str().to_string());
        if matches!(member.as_deref(), Some("Lock" | "PrepareForSleep")) {
            state.lock().await.broker.forget_all();
        }
    }
}

fn state_dir() -> PathBuf {
    std::env::var_os("XDG_STATE_HOME")
        .filter(|v| !v.is_empty())
        .map(PathBuf::from)
        .or_else(|| std::env::var_os("HOME").map(|h| PathBuf::from(h).join(".local/state")))
        .unwrap_or_default()
}

fn config_dir() -> PathBuf {
    std::env::var_os("XDG_CONFIG_HOME")
        .filter(|v| !v.is_empty())
        .map(PathBuf::from)
        .or_else(|| std::env::var_os("HOME").map(|h| PathBuf::from(h).join(".config")))
        .unwrap_or_default()
}

#[tokio::main(flavor = "current_thread")]
async fn main() -> zbus::Result<()> {
    let home = PathBuf::from(std::env::var_os("HOME").unwrap_or_default());
    let state = Arc::new(Mutex::new(State {
        broker: Broker::new(Some(state_dir().join("nyx/auth/audit.jsonl"))),
        prompt: None,
        last_used: Instant::now(),
    }));
    let service = Service { state: state.clone(), home, policy: config_dir().join("nyx/auth/policy.toml") };
    let conn = zbus::connection::Builder::session()?.name(BUS_NAME)?.serve_at(OBJECT_PATH, service)?.build().await?;
    tokio::spawn(watch_lock_and_sleep(state.clone()));
    loop {
        tokio::time::sleep(Duration::from_secs(30)).await;
        let st = state.lock().await;
        if st.prompt.is_none() && !st.broker.busy() && !st.broker.has_grants(Instant::now()) && st.last_used.elapsed() > IDLE {
            break;
        }
    }
    drop(conn);
    Ok(())
}
