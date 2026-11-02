//! A PAM configuration file as lines, keeping everything it doesn't understand verbatim.

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Rule {
    /// `auth`, `account`, `password` or `session`.
    pub kind: String,
    /// A leading `-`: ignore the line if the module is missing.
    pub quiet_missing: bool,
    /// `required`, `sufficient`, `include`, `[success=1 default=ignore]`, …
    pub control: String,
    pub module: String,
    pub args: Vec<String>,
}

impl Rule {
    pub fn is_include(&self) -> bool {
        matches!(self.control.as_str(), "include" | "substack")
    }

    /// The jump on success in a bracketed control, such as 1 in `[success=1 default=ignore]`.
    pub fn success_jump(&self) -> Option<usize> {
        self.bracket_value("success").and_then(|v| v.parse().ok())
    }

    pub fn bracket_value(&self, key: &str) -> Option<&str> {
        let inner = self.control.strip_prefix('[')?.strip_suffix(']')?;
        inner.split_whitespace().find_map(|kv| kv.split_once('=').filter(|(k, _)| *k == key).map(|(_, v)| v))
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Line {
    Rule {
        rule: Rule,
        raw: String,
    },
    /// Comments, blank lines and anything that didn't parse, kept as written.
    Other(String),
}

impl Line {
    pub fn rule(&self) -> Option<&Rule> {
        match self {
            Line::Rule { rule, .. } => Some(rule),
            Line::Other(_) => None,
        }
    }

    pub fn raw(&self) -> &str {
        match self {
            Line::Rule { raw, .. } | Line::Other(raw) => raw,
        }
    }
}

const KINDS: &[&str] = &["auth", "account", "password", "session"];

pub fn parse(text: &str) -> Vec<Line> {
    text.lines().map(parse_line).collect()
}

pub fn render(lines: &[Line]) -> String {
    let mut out: String = lines.iter().map(|l| format!("{}\n", l.raw())).collect();
    if out.is_empty() {
        out.push('\n');
    }
    out
}

fn parse_line(raw: &str) -> Line {
    let other = || Line::Other(raw.to_string());
    let content = raw.split('#').next().unwrap_or("").trim();
    if content.is_empty() {
        return other();
    }
    let (kind_field, rest) = split_word(content);
    let quiet_missing = kind_field.starts_with('-');
    let kind = kind_field.trim_start_matches('-');
    if !KINDS.contains(&kind) {
        return other();
    }
    let rest = rest.trim_start();
    let (control, rest) = if rest.starts_with('[') {
        match rest.find(']') {
            Some(end) => (rest[..=end].split_whitespace().collect::<Vec<_>>().join(" "), &rest[end + 1..]),
            None => return other(),
        }
    } else {
        let (c, r) = split_word(rest);
        (c.to_string(), r)
    };
    let mut words = rest.split_whitespace();
    let Some(module) = words.next() else { return other() };
    Line::Rule {
        rule: Rule { kind: kind.into(), quiet_missing, control, module: module.into(), args: words.map(String::from).collect() },
        raw: raw.to_string(),
    }
}

fn split_word(s: &str) -> (&str, &str) {
    match s.find(char::is_whitespace) {
        Some(i) => (&s[..i], &s[i..]),
        None => (s, ""),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const SYSTEM_AUTH: &str = "#%PAM-1.0

auth       required                    pam_faillock.so preauth silent deny=10 unlock_time=120
-auth      [success=2 default=ignore]  pam_systemd_home.so
auth       [success=1 default=bad]     pam_unix.so          try_first_pass nullok
auth       [default=die]               pam_faillock.so authfail deny=10 unlock_time=120
auth       optional                    pam_permit.so
account    required                    pam_unix.so
";

    #[test]
    fn parses_arch_system_auth() {
        let lines = parse(SYSTEM_AUTH);
        let rules: Vec<&Rule> = lines.iter().filter_map(Line::rule).collect();
        assert_eq!(rules.len(), 6);
        assert_eq!(rules[1].module, "pam_systemd_home.so");
        assert!(rules[1].quiet_missing);
        assert_eq!(rules[1].success_jump(), Some(2));
        assert_eq!(rules[2].control, "[success=1 default=bad]");
        assert_eq!(rules[2].args, vec!["try_first_pass", "nullok"]);
        assert_eq!(rules[3].bracket_value("default"), Some("die"));
        assert_eq!(render(&lines), SYSTEM_AUTH);
    }

    #[test]
    fn comments_and_garbage_are_kept() {
        let text = "# BEGIN x\nauth include system-auth # trailing\nnonsense line\nauth [broken pam_x.so\n";
        let lines = parse(text);
        assert!(matches!(lines[0], Line::Other(_)));
        assert_eq!(lines[1].rule().unwrap().module, "system-auth");
        assert!(lines[1].rule().unwrap().is_include());
        assert!(matches!(lines[2], Line::Other(_)));
        assert!(matches!(lines[3], Line::Other(_)));
        assert_eq!(render(&lines), text);
    }
}
