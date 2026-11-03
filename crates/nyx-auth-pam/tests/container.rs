//! Real Linux-PAM, in a throwaway Arch container. Nothing touches the host's /etc/pam.d.
//!
//! Run with: `cargo test -p nyx-auth-pam --test container -- --ignored`
//! (needs Docker and the `archlinux:latest` image).
//!
//! Face, fingerprint, key and the gate are `pam_exec` scripts that read their result from
//! /mock/state and record each call, so every case can check both the outcome and which
//! methods actually ran.

use std::collections::HashMap;
use std::fs;
use std::os::unix::fs::PermissionsExt;
use std::process::Command;

use nyx_auth_core::{
    Assurance, Camera, FaceCapability, Inventory, KeyCheck, KeyInfo, MethodKind, PolicySet, Surface, SurfacePolicy,
};
use nyx_auth_pam::check::verify;
use nyx_auth_pam::generate::{Changes, Files, Modules, generate};

const SUDO: &str =
    "#%PAM-1.0\nauth\t\tinclude\t\tsystem-auth\naccount\t\tinclude\t\tsystem-auth\nsession\t\tinclude\t\tsystem-auth\n";
const POLKIT: &str = "#%PAM-1.0\n\nauth       include      system-auth\naccount    include      system-auth\npassword   include      system-auth\nsession    include      system-auth\n";
const SYSTEM_AUTH: &str = "auth required pam_faillock.so preauth\n-auth [success=2 default=ignore] pam_systemd_home.so\nauth [success=1 default=bad] pam_unix.so try_first_pass nullok\nauth [default=die] pam_faillock.so authfail\nauth optional pam_permit.so\nauth required pam_env.so\nauth required pam_faillock.so authsucc\n";

struct Fixed(HashMap<String, String>);
impl Files for Fixed {
    fn etc(&self, name: &str) -> Option<String> {
        self.0.get(name).cloned()
    }
    fn vendor(&self, name: &str) -> Option<String> {
        (name == "polkit-1").then(|| POLKIT.to_string())
    }
}

fn inventory() -> Inventory {
    Inventory {
        password: true,
        fingerprint: true,
        face: Some(FaceCapability { camera: Camera::Infrared, liveness: true }),
        keys: vec![KeyInfo { name: "A".into(), verification: true }, KeyInfo { name: "B".into(), verification: true }],
    }
}

fn changes(surface: Surface, policy: &SurfacePolicy, files: &Fixed) -> Changes {
    let modules = Modules::mock("/mock");
    let plan = policy.plan(surface, &inventory()).unwrap();
    let c = generate(&plan, &modules, files).unwrap();
    verify(&c, files, &modules).unwrap();
    c
}

const MOCK: &str = r#"#!/bin/sh
name=$(basename "$0")
echo "$name" >> /mock/state/calls
case "$(cat /mock/state/$name 2>/dev/null)" in
  match) exit 0 ;;
  timeout) sleep 2; exit 1 ;;
  *) exit 1 ;;
esac
"#;

const GATE: &str = r#"#!/bin/sh
echo "gate-$1" >> /mock/state/calls
[ "$(cat /mock/state/remote 2>/dev/null)" = yes ] && exit 0
[ "$1" = built-in ] && [ "$(cat /mock/state/lid 2>/dev/null)" = closed ] && exit 0
exit 1
"#;

/// service, password, state (name=value,...), expect success, methods that must have run, methods that must not.
const CASES: &[(&str, &str, &str, bool, &str, &str)] = &[
    // Password still works, and a wrong one still fails, with nothing matching.
    ("sudo", "correct horse", "", true, "face,fingerprint,key", ""),
    ("sudo", "wrong", "", false, "", ""),
    // Each method alone is enough, and stops the stack there.
    ("sudo", "wrong", "face=match", true, "face", "fingerprint,key"),
    ("sudo", "wrong", "fingerprint=match", true, "fingerprint", "key"),
    ("sudo", "wrong", "key=match", true, "key", ""),
    // A timeout falls through to the password.
    ("sudo", "correct horse", "face=timeout", true, "face,fingerprint,key", ""),
    ("sudo", "wrong", "face=timeout", false, "", ""),
    // Remote: nothing but the password runs, even if it would match.
    ("sudo", "wrong", "remote=yes,face=match,fingerprint=match,key=match", false, "", "face,fingerprint,key"),
    ("sudo", "correct horse", "remote=yes,face=match", true, "", "face,fingerprint,key"),
    // Lid closed: built-in sensors are skipped, the key still works.
    ("sudo", "wrong", "lid=closed,face=match,fingerprint=match", false, "", "face,fingerprint"),
    ("sudo", "wrong", "lid=closed,key=match", true, "key", "face,fingerprint"),
    // Password plus a verified key, on polkit.
    ("polkit-1", "correct horse", "key-pin=match", true, "key-pin", ""),
    ("polkit-1", "correct horse", "", false, "key-pin", ""),
    ("polkit-1", "wrong", "key-pin=match", false, "", ""),
    // A plain touch doesn't satisfy the PIN rule.
    ("polkit-1", "correct horse", "key=match", false, "", "key"),
    // Lock screen services, one method each.
    ("nyx-lock-password", "correct horse", "", true, "", "face"),
    ("nyx-lock-password", "wrong", "", false, "", ""),
    ("nyx-lock-face", "wrong", "face=match", true, "face", ""),
    ("nyx-lock-face", "correct horse", "", false, "face", ""),
    ("nyx-lock-key", "", "key=match", true, "key", ""),
    // After restoring, sudo is the stock stack again: matches aren't consulted.
    ("sudo-restored", "wrong", "face=match", false, "", "face,gate-built-in"),
    ("sudo-restored", "correct horse", "", true, "", "face"),
];

#[test]
#[ignore = "needs Docker"]
fn real_pam_in_a_container() {
    let dir = tempfile::tempdir().unwrap();
    let root = dir.path();
    let pamd = root.join("pam.d");
    let mock = root.join("mock");
    fs::create_dir_all(&pamd).unwrap();
    fs::create_dir_all(mock.join("state")).unwrap();

    let files = Fixed(HashMap::from([("sudo".into(), SUDO.into()), ("system-auth".into(), SYSTEM_AUTH.into())]));
    let set = PolicySet::recommended(&inventory());
    let both = SurfacePolicy {
        methods: vec![],
        require_all: vec![MethodKind::Password, MethodKind::SecurityKey],
        minimum: Assurance::MultiFactor,
        security_key: KeyCheck::Verified,
        ..SurfacePolicy::password_only()
    };
    let mut lock = set.lock_screen.clone();
    lock.methods = vec![MethodKind::Face, MethodKind::SecurityKey, MethodKind::Password];
    let all = [
        changes(Surface::Sudo, &set.sudo, &files),
        changes(Surface::Polkit, &both, &files),
        changes(Surface::LockScreen, &lock, &files),
    ];
    for c in &all {
        for f in &c.files {
            if let (Some(name), Some(text)) = (f.path.strip_prefix("/etc/pam.d/"), &f.contents) {
                fs::write(pamd.join(name), text).unwrap();
            }
        }
    }

    // Apply, then restore to password only, and install the result as its own service.
    let mut applied = files.0.clone();
    applied.insert("sudo".into(), fs::read_to_string(pamd.join("sudo")).unwrap());
    applied.insert("nyx-auth-sudo".into(), fs::read_to_string(pamd.join("nyx-auth-sudo")).unwrap());
    let undo = changes(Surface::Sudo, &SurfacePolicy::password_only(), &Fixed(applied));
    let restored = undo.files.iter().find(|f| f.path == "/etc/pam.d/sudo").unwrap().contents.clone().unwrap();
    assert_eq!(restored, SUDO);
    fs::write(pamd.join("sudo-restored"), restored).unwrap();

    for name in ["face", "fingerprint", "key", "key-pin"] {
        fs::write(mock.join(name), MOCK).unwrap();
    }
    fs::write(mock.join("gate"), GATE).unwrap();
    for e in fs::read_dir(&mock).unwrap() {
        let p = e.unwrap().path();
        if p.is_file() {
            fs::set_permissions(&p, fs::Permissions::from_mode(0o755)).unwrap();
        }
    }

    let mut script =
        String::from("set -u\nuseradd -m tester\nprintf 'tester:%s\\n' 'correct horse' | chpasswd\ncp /in/pam.d/* /etc/pam.d/\n");
    for (i, (service, password, state, _, _, _)) in CASES.iter().enumerate() {
        script.push_str("rm -f /mock/state/*; touch /mock/state/calls; faillock --user tester --reset 2>/dev/null\n");
        for kv in state.split(',').filter(|s| !s.is_empty()) {
            let (k, v) = kv.split_once('=').unwrap();
            script.push_str(&format!("echo {v} > /mock/state/{k}\n"));
        }
        script.push_str(&format!(
            "/in/pam-try {service} tester '{password}' 2>/tmp/log; echo \"case {i} $? $(tr '\\n' ' ' < /mock/state/calls)\"\n"
        ));
    }
    fs::write(root.join("run.sh"), script).unwrap();
    fs::copy(env!("CARGO_BIN_EXE_pam-try"), root.join("pam-try")).unwrap();

    let out = Command::new("docker")
        .args(["run", "--rm", "--network=none", "-v"])
        .arg(format!("{}:/in:ro", root.display()))
        .arg("-v")
        .arg(format!("{}:/mock", mock.display()))
        .args(["archlinux:latest", "sh", "/in/run.sh"])
        .output()
        .expect("docker runs");
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(out.status.success(), "container failed:\n{stdout}\n{}", String::from_utf8_lossy(&out.stderr));

    let mut failures = Vec::new();
    for (i, (service, password, state, expect, ran, skipped)) in CASES.iter().enumerate() {
        let line = stdout
            .lines()
            .find(|l| l.starts_with(&format!("case {i} ")))
            .unwrap_or_else(|| panic!("case {i} missing:\n{stdout}"));
        let mut words = line.split_whitespace().skip(2);
        let code: i32 = words.next().unwrap().parse().unwrap();
        let calls: Vec<&str> = words.collect();
        let desc = format!("#{i} {service} pw={password:?} state={state:?}: exit {code}, calls {calls:?}");
        if (code == 0) != *expect {
            failures.push(format!("{desc}: expected {}", if *expect { "success" } else { "failure" }));
        }
        for m in ran.split(',').filter(|s| !s.is_empty()) {
            if !calls.contains(&m) {
                failures.push(format!("{desc}: {m} should have run"));
            }
        }
        for m in skipped.split(',').filter(|s| !s.is_empty()) {
            if calls.contains(&m) {
                failures.push(format!("{desc}: {m} should not have run"));
            }
        }
    }
    if std::env::var_os("NYX_PAM_SHOW").is_some() {
        eprintln!("{stdout}");
    }
    assert!(failures.is_empty(), "{}\n\nfull output:\n{stdout}", failures.join("\n"));
}
