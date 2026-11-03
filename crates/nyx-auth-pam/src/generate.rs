//! Turning a resolved policy into PAM files, from fixed templates.

use nyx_auth_core::{KeyCheck, Method, MethodKind, Plan, Selection, Surface};
use nyx_auth_hw::face::Backend;
use thiserror::Error;

use crate::block;

pub const GATE: &str = "/usr/lib/nyx-biometrics/nyx-auth-gate";
pub const NOTIFY: &str = "/usr/lib/nyx-biometrics/nyx-auth-notify";
pub const AUTHFILE: &str = "/etc/nyx-biometrics/u2f_keys";
/// Lets the socket-activated polkit helper open security keys, and nothing else new.
pub const POLKIT_DROPIN: &str = "/etc/systemd/system/polkit-agent-helper@.service.d/50-nyx-security-keys.conf";
pub const POLKIT_DROPIN_TEXT: &str = "# Nyx Biometrics: let pam_u2f reach security keys during administrator prompts.
# Remove this file (and run systemctl daemon-reload) to undo.
[Service]
PrivateDevices=no
DevicePolicy=closed
DeviceAllow=char-hidraw rw
";

/// Which PAM modules to emit for each method.
#[derive(Debug, Clone)]
pub struct Modules {
    pub face: Option<Backend>,
    pub gate: String,
    /// Tells the shell a terminal sign-in is scanning, so it can show the overlay. Used
    /// for sudo only: polkit and the lock screen draw their own.
    pub notify: Option<String>,
    pub authfile: String,
    /// For container tests: every method becomes `pam_exec.so quiet <dir>/<method>`.
    pub mock_dir: Option<String>,
    /// Remove Omarchy's own `pam_u2f` and `pam_fprintd` lines from targets, so a method
    /// never runs twice. Without it, finding them is an error.
    pub migrate_omarchy: bool,
}

impl Modules {
    pub fn system(face: Option<Backend>) -> Self {
        Self {
            face,
            gate: GATE.into(),
            notify: Some(NOTIFY.into()),
            authfile: AUTHFILE.into(),
            mock_dir: None,
            migrate_omarchy: false,
        }
    }

    pub fn mock(dir: &str) -> Self {
        Self {
            face: Some(Backend::Irlume),
            gate: format!("{dir}/gate"),
            notify: Some(format!("{dir}/notify")),
            authfile: AUTHFILE.into(),
            mock_dir: Some(dir.into()),
            migrate_omarchy: false,
        }
    }

    /// `module args` for a method, or `None` for the password (the target's own stack).
    ///
    /// At login and the lock screen Irlume runs `ondemand`: an empty answer starts one face
    /// attempt, anything else is the password. At sudo and polkit its consent setting
    /// decides, so the module takes no argument.
    pub fn line(&self, method: Method, timeout: u32, surface: Surface) -> Result<Option<String>, GenError> {
        if let Some(dir) = &self.mock_dir {
            let name = match method {
                Method::Password => return Ok(None),
                Method::Face { .. } => "face",
                Method::Fingerprint => "fingerprint",
                Method::SecurityKey { check: KeyCheck::Touch } => "key",
                Method::SecurityKey { check: KeyCheck::Verified } => "key-pin",
            };
            return Ok(Some(format!("pam_exec.so quiet {dir}/{name}")));
        }
        Ok(Some(match method {
            Method::Password => return Ok(None),
            Method::Face { .. } => {
                let module = self.face.ok_or(GenError::NoFaceBackend)?.pam_module();
                let on_demand = self.face == Some(Backend::Irlume) && matches!(surface, Surface::Login | Surface::LockScreen);
                if on_demand { format!("{module} ondemand") } else { module.to_string() }
            }
            Method::Fingerprint => format!("pam_fprintd.so max-tries=2 timeout={}", timeout.clamp(5, 60)),
            Method::SecurityKey { check } => {
                let pin = if check == KeyCheck::Verified { " pinverification=1" } else { "" };
                format!("pam_u2f.so cue authfile={}{pin}", self.authfile)
            }
        }))
    }

    fn notify_kind(method: Method) -> &'static str {
        match method {
            Method::Face { .. } => "face",
            Method::Fingerprint => "fingerprint",
            _ => "key",
        }
    }

    fn gate_kind(method: Method) -> &'static str {
        match method {
            Method::SecurityKey { .. } => "local",
            _ => "built-in",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Error)]
pub enum GenError {
    #[error("{} isn't wired through PAM", .0.label())]
    NotSystem(Surface),
    #[error("a face method is set but no face backend is chosen")]
    NoFaceBackend,
    #[error("a combination must include the password on {0}")]
    CombinationWithoutPassword(&'static str),
    #[error("a password-plus combination can't sit beside the password on its own")]
    RedundantCombination,
    #[error("{0} has no PAM file to build on")]
    NoBaseFile(String),
    #[error("{0} has an auth line Nyx Biometrics doesn't recognise as its own inside its marked block")]
    ForeignLineInBlock(String),
    #[error("{0} already has Omarchy's {1} line; move it into Nyx Biometrics first")]
    OmarchyLines(String, &'static str),
    #[error("{0} has no auth lines")]
    NoAuth(String),
}

/// One file under `/etc/pam.d` (or the polkit drop-in) and what it should become.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FileChange {
    /// An absolute path.
    pub path: String,
    /// `None` removes the file.
    pub contents: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Changes {
    pub surface: Surface,
    pub files: Vec<FileChange>,
}

/// Reads the current files: `/etc/pam.d/<name>` and `/usr/lib/pam.d/<name>`.
pub trait Files {
    fn etc(&self, name: &str) -> Option<String>;
    fn vendor(&self, name: &str) -> Option<String>;
}

pub const PAM_DIR: &str = "/etc/pam.d";

fn etc_path(name: &str) -> String {
    format!("{PAM_DIR}/{name}")
}

fn header(what: &str) -> String {
    format!(
        "#%PAM-1.0\n# Nyx Biometrics: {what}.\n# Generated from ~/.config/nyx/auth/policy.toml; change it with nyx-authctl, not here.\n"
    )
}

/// The PAM changes for one surface.
pub fn generate(plan: &Plan, modules: &Modules, files: &dyn Files) -> Result<Changes, GenError> {
    match plan.surface {
        Surface::Sudo => sequential(plan, modules, files, "sudo"),
        Surface::Polkit => sequential(plan, modules, files, "polkit-1"),
        Surface::Login => sequential(plan, modules, files, "sddm"),
        Surface::LockScreen => lock(plan, modules),
        s => Err(GenError::NotSystem(s)),
    }
}

/// Face, fingerprint, key: the standard order when the policy doesn't set one.
fn rank(m: &Method) -> u8 {
    match m.kind() {
        MethodKind::Face => 0,
        MethodKind::Fingerprint => 1,
        MethodKind::SecurityKey => 2,
        MethodKind::Password => 3,
    }
}

fn sequential(plan: &Plan, modules: &Modules, files: &dyn Files, target: &'static str) -> Result<Changes, GenError> {
    let mut singles: Vec<Method> = plan.alternatives.iter().filter(|a| a.len() == 1).map(|a| a[0]).collect();
    if plan.selection != Selection::Ordered {
        singles.sort_by_key(rank);
    }
    let password_alone = singles.contains(&Method::Password);
    singles.retain(|m| *m != Method::Password);

    let combos: Vec<&Vec<Method>> = plan.alternatives.iter().filter(|a| a.len() > 1).collect();
    let mut required = Vec::new();
    for combo in &combos {
        if !combo.contains(&Method::Password) {
            return Err(GenError::CombinationWithoutPassword(target));
        }
        if password_alone {
            return Err(GenError::RedundantCombination);
        }
        required.extend(combo.iter().copied().filter(|m| *m != Method::Password));
    }

    let pre_name = format!("nyx-auth-{target}");
    let post_name = format!("nyx-auth-{target}-required");
    let session_name = format!("nyx-auth-{target}-session");
    let mut out = Vec::new();

    let pre = if singles.is_empty() {
        None
    } else {
        let mut text = header(&format!("{}, methods tried before the password", plan.surface.label()));
        let notify = modules.notify.as_deref().filter(|_| plan.surface == Surface::Sudo);
        for m in &singles {
            let line = modules.line(*m, plan.timeout_secs, plan.surface)?.expect("not the password");
            // The gate exits 0 to skip its group: a remote session, or a closed lid. In a
            // terminal the group also tells the shell when a scan starts and when it didn't
            // succeed; those lines are optional and can't change the result.
            let group = if notify.is_some() { 3 } else { 1 };
            text.push_str(&format!(
                "auth  [success={group} default=ignore]  pam_exec.so quiet {} {}\n",
                modules.gate,
                Modules::gate_kind(*m)
            ));
            if let Some(n) = notify {
                text.push_str(&format!("auth  optional  pam_exec.so quiet {n} start {}\n", Modules::notify_kind(*m)));
            }
            text.push_str(&format!("auth  sufficient  {line}\n"));
            if let Some(n) = notify {
                text.push_str(&format!("auth  optional  pam_exec.so quiet {n} failed {}\n", Modules::notify_kind(*m)));
            }
        }
        Some(text)
    };
    let post = if required.is_empty() {
        None
    } else {
        let mut text = header(&format!("{}, required after the password", plan.surface.label()));
        for m in &required {
            let line = modules.line(*m, plan.timeout_secs, plan.surface)?.expect("not the password");
            text.push_str(&format!("auth  required  {line}\n"));
        }
        Some(text)
    };

    let (base, created) = match files.etc(target) {
        Some(t) => (t, false),
        None => (files.vendor(target).ok_or_else(|| GenError::NoBaseFile(target.into()))?, true),
    };
    let base = if created { format!("{}{base}", block::CREATED_MARK) } else { base };
    let mut lines = block::strip(&base, &etc_path(target))?;
    lines = block::omarchy(lines, &etc_path(target), modules.migrate_omarchy)?;
    let lines = block::insert(lines, pre.as_ref().map(|_| pre_name.as_str()), post.as_ref().map(|_| post_name.as_str()), target)?;
    // After a terminal sign-in succeeds, its session opens: the shell's cue that a scan
    // it showed is done.
    let session = match (&pre, modules.notify.as_deref()) {
        (Some(_), Some(n)) if plan.surface == Surface::Sudo => Some(format!(
            "{}session  optional  pam_exec.so quiet {n} done any\n",
            header("Terminal (sudo), tells the shell a sign-in finished")
        )),
        _ => None,
    };
    let lines = match &session {
        Some(_) => block::insert_session(lines, &session_name, target)?,
        None => lines,
    };
    let new_target = crate::parse::render(&lines);

    let untouched = pre.is_none() && post.is_none() && block::is_created(&new_target);
    out.push(FileChange { path: etc_path(target), contents: if untouched { None } else { Some(new_target) } });
    out.push(FileChange { path: etc_path(&pre_name), contents: pre });
    out.push(FileChange { path: etc_path(&post_name), contents: post });
    out.push(FileChange { path: etc_path(&session_name), contents: session });

    if plan.surface == Surface::Polkit {
        let uses_keys = singles.iter().chain(&required).any(|m| m.kind() == MethodKind::SecurityKey);
        out.push(FileChange { path: POLKIT_DROPIN.into(), contents: uses_keys.then(|| POLKIT_DROPIN_TEXT.into()) });
    }

    // A file that would be removed and doesn't exist is no change at all.
    out.retain(|c| c.contents.is_some() || files_exists(files, &c.path));
    Ok(Changes { surface: plan.surface, files: out })
}

fn files_exists(files: &dyn Files, path: &str) -> bool {
    path.strip_prefix("/etc/pam.d/").map(|n| files.etc(n).is_some()).unwrap_or(true)
}

/// The lock screen runs one PAM service per method at once, as Omarchy's lock does. The
/// password (`omarchy-lock-password`) and fingerprint (`omarchy-lock-fingerprint`) services
/// stay Omarchy's own. Face uses `omarchy-lock-face`, the name Irlume recognises as a lock
/// screen; security keys use `nyx-lock-key`.
pub const LOCK_SERVICES: [(&str, MethodKind); 2] =
    [("omarchy-lock-face", MethodKind::Face), ("nyx-lock-key", MethodKind::SecurityKey)];

fn lock(plan: &Plan, modules: &Modules) -> Result<Changes, GenError> {
    let methods: Vec<Method> = plan.alternatives.iter().filter(|a| a.len() == 1).map(|a| a[0]).collect();
    let mut files = Vec::new();
    for (name, kind) in LOCK_SERVICES {
        let contents = match methods.iter().find(|m| m.kind() == kind) {
            None => None,
            Some(m) => {
                let line = modules.line(*m, plan.timeout_secs, Surface::LockScreen)?.expect("not the password");
                Some(format!(
                    "{}auth       required                    {line}\naccount    include                     system-local-login\n",
                    header(&format!("lock screen, {}", kind.label().to_lowercase()))
                ))
            }
        };
        files.push(FileChange { path: etc_path(name), contents });
    }
    Ok(Changes { surface: Surface::LockScreen, files })
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;
    use nyx_auth_core::{Assurance, Camera, FaceCapability, Inventory, KeyInfo, PolicySet, SurfacePolicy};
    use std::collections::HashMap;

    pub struct Mem(pub HashMap<String, String>, pub HashMap<String, String>);
    impl Files for Mem {
        fn etc(&self, name: &str) -> Option<String> {
            self.0.get(name).cloned()
        }
        fn vendor(&self, name: &str) -> Option<String> {
            self.1.get(name).cloned()
        }
    }

    pub const SUDO: &str = "#%PAM-1.0\nauth\t\tinclude\t\tsystem-auth\naccount\t\tinclude\t\tsystem-auth\nsession\t\tinclude\t\tsystem-auth\nsession\t\toptional\tpam_systemd.so class=none\n";
    pub const POLKIT_VENDOR: &str = "#%PAM-1.0\n\nauth       include      system-auth\naccount    include      system-auth\npassword   include      system-auth\nsession    include      system-auth\n";

    pub fn files() -> Mem {
        Mem(HashMap::from([("sudo".into(), SUDO.into())]), HashMap::from([("polkit-1".into(), POLKIT_VENDOR.into())]))
    }

    pub fn inventory() -> Inventory {
        Inventory {
            password: true,
            fingerprint: true,
            face: Some(FaceCapability { camera: Camera::Infrared, liveness: true }),
            keys: vec![KeyInfo { name: "A".into(), verification: true }, KeyInfo { name: "B".into(), verification: true }],
        }
    }

    fn plan(surface: Surface, p: &SurfacePolicy) -> Plan {
        p.plan(surface, &inventory()).unwrap()
    }

    fn get<'a>(c: &'a Changes, path: &str) -> Option<&'a str> {
        c.files.iter().find(|f| f.path == path).and_then(|f| f.contents.as_deref())
    }

    #[test]
    fn sudo_with_face_fingerprint_and_key() {
        let set = PolicySet::recommended(&inventory());
        let c = generate(&plan(Surface::Sudo, &set.sudo), &Modules::system(Some(Backend::Irlume)), &files()).unwrap();
        let pre = get(&c, "/etc/pam.d/nyx-auth-sudo").unwrap();
        let rules: Vec<&str> = pre.lines().filter(|l| l.starts_with("auth")).collect();
        let gate = "auth  [success=3 default=ignore]  pam_exec.so quiet /usr/lib/nyx-biometrics/nyx-auth-gate";
        let notify = "auth  optional  pam_exec.so quiet /usr/lib/nyx-biometrics/nyx-auth-notify";
        assert_eq!(
            rules,
            vec![
                format!("{gate} built-in"),
                format!("{notify} start face"),
                "auth  sufficient  pam_irlume.so".to_string(),
                format!("{notify} failed face"),
                format!("{gate} built-in"),
                format!("{notify} start fingerprint"),
                "auth  sufficient  pam_fprintd.so max-tries=2 timeout=30".to_string(),
                format!("{notify} failed fingerprint"),
                format!("{gate} local"),
                format!("{notify} start key"),
                "auth  sufficient  pam_u2f.so cue authfile=/etc/nyx-biometrics/u2f_keys".to_string(),
                format!("{notify} failed key"),
            ]
        );
        let target = get(&c, "/etc/pam.d/sudo").unwrap();
        assert!(
            target.contains(
                "# BEGIN nyx-biometrics\nauth  include  nyx-auth-sudo\n# END nyx-biometrics\nauth\t\tinclude\t\tsystem-auth"
            ),
            "{target}"
        );
        assert!(
            target.contains("# BEGIN nyx-biometrics\nsession  include  nyx-auth-sudo-session\n# END nyx-biometrics\nsession"),
            "{target}"
        );
        assert!(
            get(&c, "/etc/pam.d/nyx-auth-sudo-session")
                .unwrap()
                .contains("session  optional  pam_exec.so quiet /usr/lib/nyx-biometrics/nyx-auth-notify done any\n")
        );
        assert!(get(&c, "/etc/pam.d/nyx-auth-sudo-required").is_none());

        // Only sudo tells the shell; polkit and the lock screen draw their own.
        let p = generate(&plan(Surface::Polkit, &set.polkit), &Modules::system(Some(Backend::Irlume)), &files()).unwrap();
        let polkit = get(&p, "/etc/pam.d/nyx-auth-polkit-1").unwrap();
        assert!(!polkit.contains("nyx-auth-notify") && polkit.contains("[success=1 default=ignore]"));
    }

    #[test]
    fn password_only_removes_everything() {
        let set = PolicySet::recommended(&inventory());
        let c = generate(&plan(Surface::Sudo, &set.sudo), &Modules::system(Some(Backend::Irlume)), &files()).unwrap();
        let mut f = files();
        for ch in &c.files {
            if let (Some(name), Some(text)) = (ch.path.strip_prefix("/etc/pam.d/"), &ch.contents) {
                f.0.insert(name.into(), text.clone());
            }
        }
        let undo = generate(&plan(Surface::Sudo, &SurfacePolicy::password_only()), &Modules::system(None), &f).unwrap();
        assert_eq!(get(&undo, "/etc/pam.d/sudo"), Some(SUDO));
        assert!(undo.files.iter().any(|x| x.path == "/etc/pam.d/nyx-auth-sudo" && x.contents.is_none()));
    }

    #[test]
    fn password_and_key_required() {
        let p = SurfacePolicy {
            methods: vec![],
            require_all: vec![MethodKind::Password, MethodKind::SecurityKey],
            minimum: Assurance::MultiFactor,
            security_key: KeyCheck::Verified,
            ..SurfacePolicy::password_only()
        };
        let c = generate(&plan(Surface::Sudo, &p), &Modules::system(None), &files()).unwrap();
        assert!(get(&c, "/etc/pam.d/nyx-auth-sudo").is_none());
        let post = get(&c, "/etc/pam.d/nyx-auth-sudo-required").unwrap();
        assert!(post.contains("auth  required  pam_u2f.so cue authfile=/etc/nyx-biometrics/u2f_keys pinverification=1\n"));
        let target = get(&c, "/etc/pam.d/sudo").unwrap();
        let auth_include = target.find("include\t\tsystem-auth").unwrap();
        let post_block = target.find("nyx-auth-sudo-required").unwrap();
        assert!(post_block > auth_include, "the key comes after the password:\n{target}");
        assert!(post_block < target.find("account").unwrap());
    }

    #[test]
    fn polkit_is_created_from_the_vendor_file_and_needs_hidraw_for_keys() {
        let set = PolicySet::recommended(&inventory());
        let c = generate(&plan(Surface::Polkit, &set.polkit), &Modules::system(Some(Backend::Irlume)), &files()).unwrap();
        let target = get(&c, "/etc/pam.d/polkit-1").unwrap();
        assert!(target.starts_with(block::CREATED_MARK));
        assert!(target.contains("auth  include  nyx-auth-polkit-1"));
        assert_eq!(get(&c, POLKIT_DROPIN), Some(POLKIT_DROPIN_TEXT));

        let mut f = files();
        f.0.insert("polkit-1".into(), target.into());
        let undo = generate(&plan(Surface::Polkit, &SurfacePolicy::password_only()), &Modules::system(None), &f).unwrap();
        assert!(
            undo.files.iter().any(|x| x.path == "/etc/pam.d/polkit-1" && x.contents.is_none()),
            "created file is removed again"
        );
    }

    #[test]
    fn ordered_selection_keeps_the_listed_order() {
        let p = SurfacePolicy {
            selection: Selection::Ordered,
            methods: vec![MethodKind::SecurityKey, MethodKind::Fingerprint, MethodKind::Password],
            ..SurfacePolicy::password_only()
        };
        let c = generate(&plan(Surface::Sudo, &p), &Modules::system(None), &files()).unwrap();
        let pre = get(&c, "/etc/pam.d/nyx-auth-sudo").unwrap();
        assert!(pre.find("pam_u2f").unwrap() < pre.find("pam_fprintd").unwrap());
    }

    #[test]
    fn omarchy_lines_must_be_migrated() {
        let mut f = files();
        f.0.insert("sudo".into(), format!("auth    sufficient pam_u2f.so cue authfile=/etc/fido2/fido2\n{SUDO}"));
        let set = PolicySet::recommended(&inventory());
        let p = plan(Surface::Sudo, &set.sudo);
        assert!(matches!(generate(&p, &Modules::system(Some(Backend::Irlume)), &f), Err(GenError::OmarchyLines(..))));
        let migrate = Modules { migrate_omarchy: true, ..Modules::system(Some(Backend::Irlume)) };
        let c = generate(&p, &migrate, &f).unwrap();
        assert!(!get(&c, "/etc/pam.d/sudo").unwrap().contains("/etc/fido2/fido2"));
    }

    #[test]
    fn lock_screen_services() {
        let set = PolicySet::recommended(&inventory());
        let c =
            generate(&plan(Surface::LockScreen, &set.lock_screen), &Modules::system(Some(Backend::Irlume)), &files()).unwrap();
        assert!(
            get(&c, "/etc/pam.d/omarchy-lock-face")
                .unwrap()
                .contains("auth       required                    pam_irlume.so ondemand\n")
        );
        assert!(get(&c, "/etc/pam.d/nyx-lock-key").unwrap().contains("pam_u2f.so"));
        // Omarchy keeps its own password and fingerprint services.
        assert!(c.files.iter().all(|f| !f.path.contains("omarchy-lock-password") && !f.path.contains("fingerprint")));

        let only =
            generate(&plan(Surface::LockScreen, &SurfacePolicy::password_only()), &Modules::system(None), &files()).unwrap();
        assert!(get(&only, "/etc/pam.d/omarchy-lock-face").is_none());
    }

    #[test]
    fn face_arguments_follow_the_surface() {
        let m = Modules::system(Some(Backend::Irlume));
        let face = Method::Face { camera: nyx_auth_core::Camera::Infrared, liveness: true };
        assert_eq!(m.line(face, 15, Surface::Login).unwrap().unwrap(), "pam_irlume.so ondemand");
        assert_eq!(m.line(face, 15, Surface::Sudo).unwrap().unwrap(), "pam_irlume.so");
        let gaze = Modules::system(Some(Backend::Gaze));
        assert_eq!(gaze.line(face, 15, Surface::LockScreen).unwrap().unwrap(), "pam_gaze.so");
    }

    #[test]
    fn mock_modules() {
        let set = PolicySet::recommended(&inventory());
        let c = generate(&plan(Surface::Sudo, &set.sudo), &Modules::mock("/mock"), &files()).unwrap();
        let pre = get(&c, "/etc/pam.d/nyx-auth-sudo").unwrap();
        assert!(pre.contains("auth  [success=3 default=ignore]  pam_exec.so quiet /mock/gate built-in\nauth  optional  pam_exec.so quiet /mock/notify start face\nauth  sufficient  pam_exec.so quiet /mock/face\nauth  optional  pam_exec.so quiet /mock/notify failed face\n"));
    }
}
