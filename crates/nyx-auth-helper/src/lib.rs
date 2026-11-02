//! The root helper's operations, kept apart from the binary so they can be tested in a
//! temporary directory.
//!
//! Every operation acts only for the user polkit authenticated (`PKEXEC_UID`), never for a
//! user named in the arguments, and writes only Nyx's own files.

pub mod fsx;
pub mod keys;
pub mod pam;

pub const HELPER_VERSION: u32 = 4;
pub const INSTALL_PATH: &str = "/usr/local/lib/nyx-biometrics/nyx-auth-helper";
pub const POLICY_FILE: &str = "/usr/share/polkit-1/actions/io.github.design_nexus.nyx.auth.policy";
pub const POLICY: &str = include_str!("../data/io.github.design_nexus.nyx.auth.policy");
pub const LOG_FILE: &str = "/var/log/nyx-biometrics/helper.log";

/// Today's date as `YYYY-MM-DD`, in UTC.
pub fn today() -> String {
    let secs = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).map(|d| d.as_secs()).unwrap_or(0);
    civil(secs / 86_400)
}

/// Days since 1970-01-01 to a calendar date (Howard Hinnant's algorithm).
fn civil(days: u64) -> String {
    let z = days as i64 + 719_468;
    let era = z.div_euclid(146_097);
    let doe = z.rem_euclid(146_097);
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = doy - (153 * mp + 2) / 5 + 1;
    let m = if mp < 10 { mp + 3 } else { mp - 9 };
    let y = yoe + era * 400 + i64::from(m <= 2);
    format!("{y:04}-{m:02}-{d:02}")
}

#[cfg(test)]
mod tests {
    #[test]
    fn civil_dates() {
        assert_eq!(super::civil(0), "1970-01-01");
        assert_eq!(super::civil(20_759), "2026-11-02");
        assert_eq!(super::civil(11_016), "2000-02-29");
    }

    #[test]
    fn policy_has_one_action_per_verb() {
        for verb in ["keys-add", "keys-remove", "keys-rename", "keys-import-omarchy", "pam-apply", "pam-confirm", "pam-restore"] {
            assert!(
                super::POLICY.contains(&format!("<annotate key=\"org.freedesktop.policykit.exec.argv1\">{verb}</annotate>")),
                "{verb}"
            );
        }
        assert!(!super::POLICY.contains("<allow_active>yes</allow_active>"));
    }
}
