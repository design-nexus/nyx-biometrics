//! The marked lines Nyx adds to a target file, and Omarchy's lines it replaces.

use crate::generate::GenError;
use crate::parse::{self, Line};

pub const BEGIN: &str = "# BEGIN nyx-biometrics";
pub const END: &str = "# END nyx-biometrics";
/// First line of a target file Nyx created from the vendor copy (`/usr/lib/pam.d`).
pub const CREATED_MARK: &str = "# Created by Nyx Biometrics from the vendor file; removed when Nyx no longer needs it.\n";

pub fn is_created(text: &str) -> bool {
    text.starts_with(CREATED_MARK) && !text.contains(BEGIN)
}

/// Remove existing blocks. Only Nyx's own include lines may sit between the markers.
pub fn strip(text: &str, path: &str) -> Result<Vec<Line>, GenError> {
    let mut out = Vec::new();
    let mut inside = false;
    for line in parse::parse(text) {
        let raw = line.raw().trim();
        if raw.starts_with(BEGIN) {
            inside = true;
            continue;
        }
        if raw.starts_with(END) {
            inside = false;
            continue;
        }
        if inside {
            match line.rule() {
                Some(r)
                    if matches!(r.kind.as_str(), "auth" | "session")
                        && r.control == "include"
                        && r.module.starts_with("nyx-auth-") =>
                {
                    continue;
                }
                None => continue,
                Some(_) => return Err(GenError::ForeignLineInBlock(path.into())),
            }
        }
        out.push(line);
    }
    Ok(out)
}

/// Omarchy's FIDO2 and fingerprint lines, and its lid gate in front of `pam_fprintd`.
fn omarchy_kind(line: &Line) -> Option<&'static str> {
    let r = line.rule()?;
    if r.kind != "auth" {
        return None;
    }
    match r.module.as_str() {
        "pam_u2f.so" if r.args.iter().any(|a| a == "authfile=/etc/fido2/fido2") => Some("FIDO2"),
        "pam_fprintd.so" => Some("fingerprint"),
        "pam_exec.so" if r.args.iter().any(|a| a.ends_with("omarchy-hw-laptop-closed")) => Some("fingerprint gate"),
        _ => None,
    }
}

pub fn omarchy(lines: Vec<Line>, path: &str, migrate: bool) -> Result<Vec<Line>, GenError> {
    if let Some(kind) = lines.iter().find_map(omarchy_kind)
        && !migrate
    {
        return Err(GenError::OmarchyLines(path.into(), kind));
    }
    Ok(lines.into_iter().filter(|l| omarchy_kind(l).is_none()).collect())
}

fn block(name: &str) -> Vec<Line> {
    parse::parse(&format!("{BEGIN}\nauth  include  {name}\n{END}"))
}

fn session_block(name: &str) -> Vec<Line> {
    parse::parse(&format!("{BEGIN}\nsession  include  {name}\n{END}"))
}

/// Put a session block before the first session line, or at the end when there's none.
pub fn insert_session(mut lines: Vec<Line>, name: &str, _target: &str) -> Result<Vec<Line>, GenError> {
    let at = lines.iter().position(|l| l.rule().is_some_and(|r| r.kind == "session")).unwrap_or(lines.len());
    lines.splice(at..at, session_block(name));
    Ok(lines)
}

/// Put the pre block before the first auth line and the post block after the last one.
pub fn insert(mut lines: Vec<Line>, pre: Option<&str>, post: Option<&str>, target: &str) -> Result<Vec<Line>, GenError> {
    let auth: Vec<usize> =
        lines.iter().enumerate().filter(|(_, l)| l.rule().is_some_and(|r| r.kind == "auth")).map(|(i, _)| i).collect();
    let (Some(&first), Some(&last)) = (auth.first(), auth.last()) else {
        return Err(GenError::NoAuth(target.into()));
    };
    if let Some(name) = post {
        lines.splice(last + 1..last + 1, block(name));
    }
    if let Some(name) = pre {
        lines.splice(first..first, block(name));
    }
    Ok(lines)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn strip_refuses_foreign_lines_inside_markers() {
        let text = format!("{BEGIN}\nauth sufficient pam_permit.so\n{END}\nauth include system-auth\n");
        assert!(matches!(strip(&text, "/etc/pam.d/sudo"), Err(GenError::ForeignLineInBlock(_))));
        let ours = format!("{BEGIN}\nauth  include  nyx-auth-sudo\n{END}\nauth include system-auth\n");
        assert_eq!(parse::render(&strip(&ours, "x").unwrap()), "auth include system-auth\n");
    }

    #[test]
    fn omarchy_fingerprint_with_gate() {
        let text = "auth      [success=1 default=ignore] pam_exec.so quiet /usr/bin/omarchy-hw-laptop-closed\nauth      sufficient pam_fprintd.so\nauth include system-auth\n";
        let lines = parse::parse(text);
        assert!(matches!(omarchy(lines.clone(), "p", false), Err(GenError::OmarchyLines(_, "fingerprint gate"))));
        assert_eq!(parse::render(&omarchy(lines, "p", true).unwrap()), "auth include system-auth\n");
    }
}
