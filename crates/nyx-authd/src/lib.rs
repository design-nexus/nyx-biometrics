//! nyx-authd: the broker Nyx apps ask before a sensitive action.
//!
//! A caller is known by the program it runs (from the bus connection, never the request)
//! and may only ask for actions under its own prefix. The person confirms through polkit's
//! "authenticate as yourself" action (`app-action`), so the face card, fingerprint, key or
//! password the computer is set up for answers, and nothing here sees which. There is no
//! way to approve a request: only that confirmation grants. Grants are per caller and
//! action, last at most five minutes, and end when the screen locks or the computer
//! sleeps. One prompt at a time, a few requests a minute per caller, and an audit line for
//! each, without the purpose (it can name the person's data).

use std::collections::HashMap;
use std::io::Write;
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};

use nyx_auth_core::{Assurance, MethodKind, PolicySet, Surface};
use nyx_auth_proto::{MAX_GRANT_SECS, MethodStatus, Outcome, Reply, Request};

pub const POLKIT_ACTION: &str = "io.github.design_nexus.nyx.auth.app-action";
/// Requests one caller may make in a minute, prompts or not.
pub const REQUESTS_PER_MINUTE: usize = 6;

/// A program allowed to ask, and the actions it may ask for.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Caller {
    /// Shown in the audit log.
    pub name: &'static str,
    pub prefix: &'static str,
}

/// Programs by executable name, and where they may be installed.
const CALLERS: &[(&str, Caller)] = &[
    ("nyx-passwordsd", Caller { name: "Nyx Passwords", prefix: "io.github.design_nexus.nyx.passwords." }),
    ("nyx-assistantd", Caller { name: "Nyx Assistant", prefix: "io.github.design_nexus.nyx.assistant." }),
    ("nyx-authctl", Caller { name: "nyx-authctl", prefix: "io.github.design_nexus.nyx.authctl." }),
];

/// The caller for an executable, if it's one of the suite's and installed where the suite
/// installs: the user's `~/.local/bin`, or the system's.
pub fn known_caller(exe: &Path, home: &Path) -> Option<Caller> {
    let dir = exe.parent()?;
    let installed = dir == home.join(".local/bin") || dir == Path::new("/usr/bin") || dir == Path::new("/usr/local/bin");
    if !installed {
        return None;
    }
    let name = exe.file_name()?.to_str()?;
    CALLERS.iter().find(|(n, _)| *n == name).map(|(_, c)| c.clone())
}

/// How polkit's check ended.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Check {
    Granted,
    Denied,
    Dismissed,
    TimedOut,
    Failed,
}

/// What to do with a request before anything is shown.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Decision {
    /// Ask the person.
    Prompt,
    /// Answer now, without a prompt.
    Answer(Reply),
}

fn reply(outcome: Outcome, grant_secs: u32) -> Reply {
    let granted = outcome == Outcome::Granted;
    Reply {
        outcome,
        assurance: if granted { Assurance::SingleFactor } else { Assurance::Presence },
        methods: Vec::new(),
        grant_secs,
    }
}

/// The broker's state. Times come from the caller, so tests can move the clock.
pub struct Broker {
    grants: HashMap<(String, String), Instant>,
    recent: HashMap<String, Vec<Instant>>,
    prompting: Option<String>,
    audit: Option<PathBuf>,
}

impl Broker {
    pub fn new(audit: Option<PathBuf>) -> Self {
        Self { grants: HashMap::new(), recent: HashMap::new(), prompting: None, audit }
    }

    /// Seconds left on `caller`'s grant for `action`, or 0.
    pub fn check(&mut self, caller: &Caller, action: &str, now: Instant) -> u32 {
        let key = (caller.name.to_string(), action.to_string());
        match self.grants.get(&key) {
            Some(until) if *until > now => until.duration_since(now).as_secs().max(1) as u32,
            Some(_) => {
                self.grants.remove(&key);
                0
            }
            None => 0,
        }
    }

    pub fn revoke(&mut self, caller: &Caller, action: &str) {
        self.grants.remove(&(caller.name.to_string(), action.to_string()));
    }

    /// Every grant ends: the screen locked or the computer is going to sleep.
    pub fn forget_all(&mut self) {
        self.grants.clear();
    }

    pub fn has_grants(&self, now: Instant) -> bool {
        self.grants.values().any(|until| *until > now)
    }

    pub fn busy(&self) -> bool {
        self.prompting.is_some()
    }

    /// Checks a request and decides whether to prompt. A prompt marks the broker busy until
    /// [`Broker::finish`].
    pub fn begin(&mut self, caller: &Caller, request: &Request, policy: &PolicySet, now: Instant) -> Decision {
        let times = self.recent.entry(caller.name.to_string()).or_default();
        times.retain(|t| now.duration_since(*t) < Duration::from_secs(60));
        if times.len() >= REQUESTS_PER_MINUTE {
            return self.answer(caller, request, Outcome::Busy, "rate-limited");
        }
        times.push(now);
        if request.validate(caller.prefix).is_err() {
            return self.answer(caller, request, Outcome::Denied, "invalid");
        }
        if !reachable(policy.get(request.surface)) {
            return self.answer(caller, request, Outcome::Unavailable, "policy");
        }
        let left = self.check(caller, &request.action, now);
        if left > 0 {
            return self.answer(caller, request, Outcome::Granted, "existing-grant").with_grant(left);
        }
        if self.prompting.is_some() {
            return self.answer(caller, request, Outcome::Busy, "busy");
        }
        self.prompting = Some(caller.name.to_string());
        Decision::Prompt
    }

    /// Records how the prompt ended and answers.
    pub fn finish(&mut self, caller: &Caller, request: &Request, check: Check, now: Instant) -> Reply {
        self.prompting = None;
        let outcome = match check {
            Check::Granted => Outcome::Granted,
            Check::Denied => Outcome::Denied,
            Check::Dismissed => Outcome::Cancelled,
            Check::TimedOut => Outcome::TimedOut,
            Check::Failed => Outcome::Unavailable,
        };
        let grant = if outcome == Outcome::Granted { request.grant_secs.min(MAX_GRANT_SECS) } else { 0 };
        if grant > 0 {
            self.grants.insert((caller.name.to_string(), request.action.clone()), now + Duration::from_secs(u64::from(grant)));
        }
        self.log(caller, &request.action, outcome, "prompt");
        reply(outcome, grant)
    }

    fn answer(&mut self, caller: &Caller, request: &Request, outcome: Outcome, why: &str) -> Decision {
        self.log(caller, &request.action, outcome, why);
        Decision::Answer(reply(outcome, 0))
    }

    /// One JSON line: when, who, which action, how it ended. Never the purpose.
    fn log(&self, caller: &Caller, action: &str, outcome: Outcome, via: &str) {
        let Some(path) = &self.audit else { return };
        let action = if action.len() <= 255 && action.chars().all(|c| c.is_ascii_graphic()) { action } else { "(invalid)" };
        let line = serde_json::json!({
            "time": std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).map(|d| d.as_secs()).unwrap_or(0),
            "caller": caller.name,
            "action": action,
            "outcome": outcome,
            "via": via,
        });
        if let Some(dir) = path.parent() {
            let _ = std::fs::create_dir_all(dir);
        }
        use std::os::unix::fs::OpenOptionsExt;
        if let Ok(mut f) = std::fs::OpenOptions::new().append(true).create(true).mode(0o600).open(path) {
            let _ = writeln!(f, "{line}");
        }
    }
}

trait WithGrant {
    fn with_grant(self, secs: u32) -> Self;
}

impl WithGrant for Decision {
    fn with_grant(self, secs: u32) -> Self {
        match self {
            Decision::Answer(mut r) => {
                r.grant_secs = secs;
                Decision::Answer(r)
            }
            d => d,
        }
    }
}

/// Whether one confirmation through polkit can meet this surface's policy: a single method
/// on its own. A policy that wants two methods together can't be met by one system prompt,
/// so it is refused rather than passed on a weaker check.
pub fn reachable(policy: &nyx_auth_core::SurfacePolicy) -> bool {
    policy.require_all.is_empty() && !policy.methods.is_empty() && policy.minimum <= Assurance::VerifiedPossession
}

/// The policy file, or the defaults when it's missing or can't be read.
pub fn load_policy(path: &Path) -> PolicySet {
    std::fs::read_to_string(path).ok().and_then(|t| PolicySet::from_toml(&t).ok()).unwrap_or_default()
}

/// The methods the `app-action` policy lists. The broker can't see the hardware: it reports
/// what Sign-in & Security set up, and the password always.
pub fn methods(policy: &PolicySet) -> Vec<MethodStatus> {
    let p = policy.get(Surface::AppAction);
    MethodKind::ALL
        .iter()
        .map(|&kind| {
            let listed = kind == MethodKind::Password || p.methods.contains(&kind);
            MethodStatus {
                kind,
                available: listed,
                assurance: Assurance::SingleFactor,
                note: if listed { String::new() } else { "Not set up for Nyx apps in Sign-in & Security".into() },
            }
        })
        .collect()
}

/// polkit's exit status for `pkcheck --allow-user-interaction`.
pub fn check_from_status(code: Option<i32>) -> Check {
    match code {
        Some(0) => Check::Granted,
        Some(1) => Check::Denied,
        Some(2) => Check::Dismissed,
        _ => Check::Failed,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn passwords() -> Caller {
        known_caller(Path::new("/home/u/.local/bin/nyx-passwordsd"), Path::new("/home/u")).unwrap()
    }

    fn req(action: &str, grant_secs: u32) -> Request {
        Request { action: action.into(), purpose: "Copy a protected login".into(), surface: Surface::AppAction, grant_secs }
    }

    fn policy() -> PolicySet {
        let mut p = PolicySet::default();
        p.get_mut(Surface::AppAction).methods = vec![MethodKind::Face, MethodKind::Password];
        p
    }

    const COPY: &str = "io.github.design_nexus.nyx.passwords.copy-protected";

    #[test]
    fn callers_are_known_by_program_and_place() {
        let home = Path::new("/home/u");
        assert_eq!(passwords().prefix, "io.github.design_nexus.nyx.passwords.");
        assert!(known_caller(Path::new("/usr/bin/nyx-assistantd"), home).is_some());
        assert!(known_caller(Path::new("/tmp/nyx-passwordsd"), home).is_none());
        assert!(known_caller(Path::new("/home/u/.local/bin/stranger"), home).is_none());
        assert!(known_caller(Path::new("/home/u/.local/bin/sub/nyx-passwordsd"), home).is_none());
    }

    #[test]
    fn prompts_then_grants_for_the_asked_time_only() {
        let (mut b, now, c) = (Broker::new(None), Instant::now(), passwords());
        assert_eq!(b.begin(&c, &req(COPY, 60), &policy(), now), Decision::Prompt);
        assert!(b.busy());
        let r = b.finish(&c, &req(COPY, 60), Check::Granted, now);
        assert_eq!((r.outcome, r.grant_secs), (Outcome::Granted, 60));
        assert!(!b.busy());
        match b.begin(&c, &req(COPY, 60), &policy(), now + Duration::from_secs(10)) {
            Decision::Answer(r) => assert_eq!((r.outcome, r.grant_secs), (Outcome::Granted, 50)),
            d => panic!("{d:?}"),
        }
        assert_eq!(b.check(&c, COPY, now + Duration::from_secs(61)), 0);
        assert_eq!(b.begin(&c, &req(COPY, 60), &policy(), now + Duration::from_secs(61)), Decision::Prompt);
    }

    #[test]
    fn once_means_no_grant_and_lock_ends_grants() {
        let (mut b, now, c) = (Broker::new(None), Instant::now(), passwords());
        b.begin(&c, &req(COPY, 0), &policy(), now);
        assert_eq!(b.finish(&c, &req(COPY, 0), Check::Granted, now).grant_secs, 0);
        assert_eq!(b.check(&c, COPY, now), 0);
        b.begin(&c, &req(COPY, 300), &policy(), now);
        b.finish(&c, &req(COPY, 300), Check::Granted, now);
        assert!(b.check(&c, COPY, now) > 0);
        b.forget_all();
        assert_eq!(b.check(&c, COPY, now), 0);
    }

    #[test]
    fn refusals_never_prompt() {
        let (mut b, now, c) = (Broker::new(None), Instant::now(), passwords());
        let answer = |d: Decision| match d {
            Decision::Answer(r) => r.outcome,
            d => panic!("{d:?}"),
        };
        // Another app's action.
        assert_eq!(answer(b.begin(&c, &req("io.github.design_nexus.nyx.settings.x", 0), &policy(), now)), Outcome::Denied);
        // A system surface.
        let mut sudo = req(COPY, 0);
        sudo.surface = Surface::Sudo;
        assert_eq!(answer(b.begin(&c, &sudo, &policy(), now)), Outcome::Denied);
        // Two methods together can't be one system prompt.
        let mut two = policy();
        two.get_mut(Surface::AppAction).require_all = vec![MethodKind::Password, MethodKind::SecurityKey];
        two.get_mut(Surface::AppAction).minimum = Assurance::MultiFactor;
        assert_eq!(answer(b.begin(&c, &req(COPY, 0), &two, now)), Outcome::Unavailable);
        // Denials don't grant.
        assert_eq!(b.begin(&c, &req(COPY, 60), &policy(), now), Decision::Prompt);
        assert_eq!(b.finish(&c, &req(COPY, 60), Check::Dismissed, now).outcome, Outcome::Cancelled);
        assert_eq!(b.check(&c, COPY, now), 0);
    }

    #[test]
    fn one_prompt_at_a_time_and_a_few_a_minute() {
        let (mut b, now) = (Broker::new(None), Instant::now());
        let assistant = known_caller(Path::new("/usr/bin/nyx-assistantd"), Path::new("/home/u")).unwrap();
        assert_eq!(b.begin(&passwords(), &req(COPY, 0), &policy(), now), Decision::Prompt);
        let other = req("io.github.design_nexus.nyx.assistant.secret", 0);
        assert!(matches!(b.begin(&assistant, &other, &policy(), now), Decision::Answer(r) if r.outcome == Outcome::Busy));
        b.finish(&passwords(), &req(COPY, 0), Check::Denied, now);
        let mut seen = Vec::new();
        for _ in 0..REQUESTS_PER_MINUTE + 1 {
            let d = b.begin(&assistant, &other, &policy(), now);
            if d == Decision::Prompt {
                b.finish(&assistant, &other, Check::Denied, now);
            }
            seen.push(d);
        }
        // One already used above while busy.
        assert!(matches!(seen.last(), Some(Decision::Answer(r)) if r.outcome == Outcome::Busy));
        assert_eq!(b.begin(&assistant, &other, &policy(), now + Duration::from_secs(61)), Decision::Prompt);
    }

    #[test]
    fn the_audit_log_never_holds_the_purpose() {
        let dir = tempfile::tempdir().unwrap();
        let log = dir.path().join("nyx/auth/audit.jsonl");
        let (mut b, now, c) = (Broker::new(Some(log.clone())), Instant::now(), passwords());
        let mut r = req(COPY, 0);
        r.purpose = "Copy the password for secret-bank.example".into();
        b.begin(&c, &r, &policy(), now);
        b.finish(&c, &r, Check::Granted, now);
        let text = std::fs::read_to_string(&log).unwrap();
        assert!(text.contains("\"granted\"") && text.contains("Nyx Passwords") && text.contains(COPY), "{text}");
        assert!(!text.contains("secret-bank"));
        use std::os::unix::fs::PermissionsExt;
        assert_eq!(std::fs::metadata(&log).unwrap().permissions().mode() & 0o777, 0o600);
    }

    #[test]
    fn polkit_statuses() {
        assert_eq!(check_from_status(Some(0)), Check::Granted);
        assert_eq!(check_from_status(Some(1)), Check::Denied);
        assert_eq!(check_from_status(Some(2)), Check::Dismissed);
        assert_eq!(check_from_status(Some(127)), Check::Failed);
        assert_eq!(check_from_status(None), Check::Failed);
    }

    #[test]
    fn methods_follow_the_policy_and_always_include_the_password() {
        let m = methods(&policy());
        let face = m.iter().find(|s| s.kind == MethodKind::Face).unwrap();
        let fp = m.iter().find(|s| s.kind == MethodKind::Fingerprint).unwrap();
        assert!(face.available && !fp.available);
        assert!(m.iter().any(|s| s.kind == MethodKind::Password && s.available));
    }
}
