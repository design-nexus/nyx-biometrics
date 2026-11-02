//! Checks on generated changes, run before anything is written. They re-read the output
//! rather than trusting the generator: a bug there must not reach `/etc/pam.d`.

use std::collections::HashMap;

use crate::block::{BEGIN, END};
use crate::generate::{Changes, Files, Modules, PAM_DIR};
use crate::parse::{self, Line, Rule};

const METHOD_MODULES: &[&str] = &["pam_fprintd.so", "pam_u2f.so", "pam_irlume.so", "pam_gaze.so"];

fn is_gate(rule: &Rule, modules: &Modules) -> bool {
    rule.module == "pam_exec.so"
        && rule.control == "[success=1 default=ignore]"
        && rule.args.len() == 3
        && rule.args[0] == "quiet"
        && rule.args[1] == modules.gate
        && matches!(rule.args[2].as_str(), "built-in" | "local")
}

fn is_method(rule: &Rule, modules: &Modules) -> bool {
    match &modules.mock_dir {
        Some(dir) => rule.module == "pam_exec.so" && rule.args.len() == 2 && rule.args[1].starts_with(&format!("{dir}/")),
        None => METHOD_MODULES.contains(&rule.module.as_str()),
    }
}

/// Every problem found, or nothing.
pub fn verify(changes: &Changes, files: &dyn Files, modules: &Modules) -> Result<(), Vec<String>> {
    let mut errors = Vec::new();
    let mut view: HashMap<String, Option<String>> = HashMap::new();
    for c in &changes.files {
        if let Some(name) = c.path.strip_prefix(&format!("{PAM_DIR}/")) {
            view.insert(name.into(), c.contents.clone());
        }
    }

    for c in &changes.files {
        let Some(name) = c.path.strip_prefix(&format!("{PAM_DIR}/")) else { continue };
        let Some(text) = &c.contents else { continue };
        let lines = parse::parse(text);
        let lock_service = crate::generate::LOCK_SERVICES.iter().any(|(n, _)| *n == name);
        if name.starts_with("nyx-auth-") {
            check_generated(name, &lines, modules, &mut errors);
        } else if lock_service {
            let auth: Vec<&Rule> = lines.iter().filter_map(Line::rule).filter(|r| r.kind == "auth").collect();
            if auth.len() != 1 || auth[0].control != "required" || !is_method(auth[0], modules) {
                errors.push(format!("{name}: must be exactly one required method line"));
            }
        } else {
            check_target(name, &lines, &mut errors);
        }
        if !name.starts_with("nyx-auth-") || name.ends_with("-required") {
            let stack = expand(name, &view, files, 0, &mut errors);
            let needs_password = !lock_service && !name.ends_with("-required");
            if needs_password && !stack.iter().any(|r| r.module == "pam_unix.so") {
                errors.push(format!("{name}: the password (pam_unix) is no longer reachable"));
            }
            for r in &stack {
                let ends_stack = r.control == "sufficient" || r.bracket_value("success") == Some("done");
                if r.module == "pam_permit.so" && ends_stack {
                    errors.push(format!("{name}: pam_permit would let anyone in"));
                }
            }
        }
    }
    if errors.is_empty() { Ok(()) } else { Err(errors) }
}

fn check_generated(name: &str, lines: &[Line], modules: &Modules, errors: &mut Vec<String>) {
    let required = name.ends_with("-required");
    let rules: Vec<&Rule> = lines.iter().filter_map(Line::rule).collect();
    if rules.is_empty() {
        errors.push(format!("{name}: empty"));
    }
    let mut i = 0;
    while i < rules.len() {
        let r = rules[i];
        if r.kind != "auth" {
            errors.push(format!("{name}: only auth lines belong here"));
        } else if required {
            if r.control != "required" || !is_method(r, modules) {
                errors.push(format!("{name}: line {} must be a required method", i + 1));
            }
        } else if is_gate(r, modules) {
            match rules.get(i + 1) {
                Some(next) if next.control == "sufficient" && is_method(next, modules) => i += 1,
                _ => errors.push(format!("{name}: a gate must be followed by exactly one method")),
            }
        } else {
            errors.push(format!("{name}: {} {} has no gate in front of it", r.control, r.module));
        }
        i += 1;
    }
}

fn check_target(name: &str, lines: &[Line], errors: &mut Vec<String>) {
    let mut blocks = Vec::new();
    let mut inside = None;
    for (i, l) in lines.iter().enumerate() {
        let raw = l.raw().trim();
        if raw.starts_with(BEGIN) {
            inside = Some(i);
        } else if raw.starts_with(END)
            && let Some(start) = inside.take()
        {
            blocks.push((start, i));
        }
    }
    if inside.is_some() {
        errors.push(format!("{name}: a block isn't closed"));
    }
    if blocks.len() > 2 {
        errors.push(format!("{name}: more than two Nyx blocks"));
    }
    let auth_outside: Vec<usize> = lines
        .iter()
        .enumerate()
        .filter(|(i, l)| l.rule().is_some_and(|r| r.kind == "auth") && !blocks.iter().any(|(s, e)| i > s && i < e))
        .map(|(i, _)| i)
        .collect();
    let (Some(&first), Some(&last)) = (auth_outside.first(), auth_outside.last()) else {
        errors.push(format!("{name}: no auth lines of its own"));
        return;
    };
    for (start, end) in &blocks {
        let include = lines[start + 1..*end].iter().filter_map(Line::rule).next();
        let Some(inc) = include else {
            errors.push(format!("{name}: an empty block"));
            continue;
        };
        let post = inc.module.ends_with("-required");
        if post && *start < last {
            errors.push(format!("{name}: required methods must come after the password"));
        }
        if !post && *end > first {
            errors.push(format!("{name}: methods tried first must come before the password"));
        }
    }
}

/// The auth lines of a service, with includes followed (depth-limited).
fn expand(
    name: &str,
    view: &HashMap<String, Option<String>>,
    files: &dyn Files,
    depth: u8,
    errors: &mut Vec<String>,
) -> Vec<Rule> {
    if depth > 8 {
        errors.push(format!("{name}: includes nest too deeply"));
        return Vec::new();
    }
    let text = match view.get(name) {
        Some(Some(t)) => Some(t.clone()),
        Some(None) => files.vendor(name),
        None => files.etc(name).or_else(|| files.vendor(name)),
    };
    let Some(text) = text else {
        errors.push(format!("{name}: included but missing"));
        return Vec::new();
    };
    let mut out = Vec::new();
    for r in parse::parse(&text).iter().filter_map(Line::rule).filter(|r| r.kind == "auth") {
        if r.is_include() {
            out.extend(expand(&r.module, view, files, depth + 1, errors));
        } else {
            out.push(r.clone());
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::generate::{FileChange, generate};
    use nyx_auth_core::{PolicySet, Surface};
    use nyx_auth_hw::face::Backend;
    use std::collections::HashMap;

    struct Mem(HashMap<String, String>, HashMap<String, String>);
    impl Files for Mem {
        fn etc(&self, n: &str) -> Option<String> {
            self.0.get(n).cloned()
        }
        fn vendor(&self, n: &str) -> Option<String> {
            self.1.get(n).cloned()
        }
    }

    const SYSTEM_AUTH: &str = "auth required pam_faillock.so preauth\nauth [success=1 default=bad] pam_unix.so try_first_pass nullok\nauth [default=die] pam_faillock.so authfail\nauth optional pam_permit.so\n";

    fn files() -> Mem {
        Mem(
            HashMap::from([
                ("sudo".into(), "auth include system-auth\naccount include system-auth\n".into()),
                ("system-auth".into(), SYSTEM_AUTH.into()),
                ("sddm".into(), "auth include system-login\n".into()),
                ("system-login".into(), "auth include system-auth\n".into()),
            ]),
            HashMap::from([("polkit-1".into(), "auth include system-auth\n".into())]),
        )
    }

    fn inv() -> nyx_auth_core::Inventory {
        crate::generate::tests::inventory()
    }

    #[test]
    fn generated_changes_pass() {
        let set = PolicySet::recommended(&inv());
        let m = Modules::system(Some(Backend::Irlume));
        for s in [Surface::Sudo, Surface::Polkit, Surface::Login, Surface::LockScreen] {
            let plan = set.get(s).plan(s, &inv()).unwrap();
            let c = generate(&plan, &m, &files()).unwrap();
            verify(&c, &files(), &m).unwrap_or_else(|e| panic!("{s:?}: {e:?}"));
        }
    }

    fn tamper(path: &str, text: &str) -> Changes {
        Changes {
            surface: Surface::Sudo,
            files: vec![FileChange { path: format!("/etc/pam.d/{path}"), contents: Some(text.into()) }],
        }
    }

    #[test]
    fn catches_dangerous_output() {
        let m = Modules::system(None);
        let gate = "auth  [success=1 default=ignore]  pam_exec.so quiet /usr/lib/nyx-biometrics/nyx-auth-gate local\n";

        let permit = tamper("nyx-auth-sudo", &format!("{gate}auth sufficient pam_permit.so\n"));
        assert!(verify(&permit, &files(), &m).is_err());

        let ungated = tamper("nyx-auth-sudo", "auth sufficient pam_u2f.so cue\n");
        assert!(verify(&ungated, &files(), &m).unwrap_err()[0].contains("no gate"));

        let double = tamper("nyx-auth-sudo", &format!("{gate}auth sufficient pam_u2f.so\nauth sufficient pam_fprintd.so\n"));
        assert!(verify(&double, &files(), &m).is_err());

        let no_password = tamper("sudo", &format!("{BEGIN}\nauth  include  nyx-auth-sudo\n{END}\naccount include system-auth\n"));
        assert!(verify(&no_password, &files(), &m).is_err());

        let wrong_place = tamper("sudo", &format!("auth include system-auth\n{BEGIN}\nauth  include  nyx-auth-sudo\n{END}\n"));
        assert!(verify(&wrong_place, &files(), &m).unwrap_err().iter().any(|e| e.contains("before the password")));

        let lock = tamper("omarchy-lock-face", "auth sufficient pam_permit.so\n");
        assert!(verify(&lock, &files(), &m).is_err());
    }
}
