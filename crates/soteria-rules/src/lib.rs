//! Detection rules (SRS 5.3 "Detection engine", FR-021).
//!
//! Every alert names the rule that raised it. The catalogue has two parts:
//!
//! - **Built-in rules** (`FIM-*`, `EXE-*`, `INT-*`), implemented in the
//!   agent. Administrators can disable them or fix their severity.
//! - **Administrator rules**, declared in TOML files in the rules directory
//!   (`/etc/soteria/rules.d/*.toml`). They match baseline deviations of
//!   files (`on = "file"`) or program executions (`on = "execution"`) and
//!   raise their own alert at the severity they declare.
//!
//! Rule files are parsed strictly, like the configuration (FR-043): an
//! unknown key, an unknown rule in an override, a duplicate id or an empty
//! matcher is an error, and the daemon refuses to start rather than run
//! with rules silently missing.
//!
//! ```toml
//! [[override]]
//! rule = "FIM-011"
//! enabled = false
//!
//! [[rule]]
//! id = "LOCAL-001"
//! title = "SSH server configuration changed"
//! on = "file"
//! severity = "critical"
//! paths = ["/etc/ssh/sshd_config", "/etc/ssh/sshd_config.d/**"]
//! changes = ["content_modified", "permission_modified", "new"]
//! reason = "The SSH server configuration differs from the approved baseline."
//! recommendation = "Review the change with the administrator who made it."
//! ```

use std::collections::{BTreeMap, HashSet};
use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};
use soteria_core::Severity;

mod builtin;
mod glob;

pub use builtin::{BUILTIN, Builtin, builtin};
pub use glob::glob_match;

/// Where administrator rules live (SRS 8.1).
pub const DEFAULT_RULES_DIRECTORY: &str = "/etc/soteria/rules.d";

/// Baseline change kinds a file rule can name (see `soteria-integrity`).
pub const CHANGE_KINDS: [&str; 11] = [
    "new",
    "missing",
    "type_changed",
    "content_modified",
    "permission_modified",
    "owner_modified",
    "capability_modified",
    "security_label_modified",
    "symlink_target_modified",
    "executable_status_modified",
    "metadata_modified",
];

/// Execution classifications an execution rule can name (FR-010).
pub const CLASSIFICATIONS: [&str; 5] = [
    "trusted",
    "known_modified",
    "unknown",
    "suspicious",
    "unverified",
];

/// What a rule looks at.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Category {
    /// Baseline deviations of files.
    File,
    /// Program executions.
    Execution,
    /// Soteria's own baseline and database integrity.
    Integrity,
}

impl Category {
    pub fn as_str(self) -> &'static str {
        match self {
            Category::File => "file",
            Category::Execution => "execution",
            Category::Integrity => "integrity",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum Origin {
    Builtin,
    Admin,
}

impl Origin {
    pub fn as_str(self) -> &'static str {
        match self {
            Origin::Builtin => "builtin",
            Origin::Admin => "admin",
        }
    }
}

/// Matches baseline deviations of files.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct FileMatcher {
    /// Glob patterns on the absolute path: `*` and `?` stay within one path
    /// component, `**` crosses components.
    pub paths: Vec<String>,
    /// Change kinds; empty means any change.
    pub changes: Vec<String>,
}

impl FileMatcher {
    pub fn matches(&self, path: &[u8], changes: &[&str]) -> bool {
        self.paths.iter().any(|p| glob_match(p.as_bytes(), path))
            && (self.changes.is_empty()
                || changes.iter().any(|c| self.changes.iter().any(|m| m == c)))
    }
}

/// The facts about one execution an execution rule can test.
#[derive(Debug, Clone, Copy, Default)]
pub struct ExecFacts<'a> {
    pub exe: Option<&'a [u8]>,
    pub comm: Option<&'a str>,
    /// Script run by an interpreter, if any.
    pub script: Option<&'a [u8]>,
    pub parent_exe: Option<&'a [u8]>,
    pub parent_comm: Option<&'a str>,
    pub uid: u32,
    pub euid: u32,
    pub classification: &'a str,
    pub argv: &'a [Vec<u8>],
}

/// Matches program executions. Every non-empty list must match.
#[derive(Debug, Clone, PartialEq, Eq, Default, Serialize)]
pub struct ExecMatcher {
    /// A pattern with a `/` is a glob on the program or script path;
    /// otherwise it is the program name.
    pub programs: Vec<String>,
    /// Same, for the parent process.
    pub parents: Vec<String>,
    /// Real or effective user IDs.
    pub uids: Vec<u32>,
    pub classifications: Vec<String>,
    /// Substrings, any of which appears in any argument (after argv[0]).
    pub arguments: Vec<String>,
}

fn base_name(path: &[u8]) -> &[u8] {
    path.rsplit(|b| *b == b'/').next().unwrap_or(path)
}

fn program_matches(
    patterns: &[String],
    path: Option<&[u8]>,
    comm: Option<&str>,
    extra: Option<&[u8]>,
) -> bool {
    patterns.iter().any(|p| {
        if p.contains('/') {
            [path, extra]
                .into_iter()
                .flatten()
                .any(|x| glob_match(p.as_bytes(), x))
        } else {
            [path, extra]
                .into_iter()
                .flatten()
                .any(|x| glob_match(p.as_bytes(), base_name(x)))
                || comm.is_some_and(|c| glob_match(p.as_bytes(), c.as_bytes()))
        }
    })
}

impl ExecMatcher {
    pub fn matches(&self, f: &ExecFacts<'_>) -> bool {
        (self.programs.is_empty() || program_matches(&self.programs, f.exe, f.comm, f.script))
            && (self.parents.is_empty()
                || program_matches(&self.parents, f.parent_exe, f.parent_comm, None))
            && (self.uids.is_empty() || self.uids.contains(&f.uid) || self.uids.contains(&f.euid))
            && (self.classifications.is_empty()
                || self.classifications.iter().any(|c| c == f.classification))
            && (self.arguments.is_empty()
                || f.argv.iter().skip(1).any(|a| {
                    self.arguments
                        .iter()
                        .any(|s| a.windows(s.len()).any(|w| w == s.as_bytes()))
                }))
    }

    fn is_empty(&self) -> bool {
        self.programs.is_empty()
            && self.parents.is_empty()
            && self.uids.is_empty()
            && self.classifications.is_empty()
            && self.arguments.is_empty()
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(tag = "on", rename_all = "snake_case")]
pub enum Matcher {
    File(FileMatcher),
    Execution(ExecMatcher),
}

/// One rule as in effect: built-in or administrator, with overrides applied.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct Rule {
    pub id: String,
    pub title: String,
    pub category: Category,
    pub origin: Origin,
    pub enabled: bool,
    /// The severity this rule raises at. For built-in rules whose severity
    /// depends on the object, `None` unless an administrator fixed it.
    pub severity: Option<Severity>,
    /// How the built-in severity is chosen, when it varies.
    pub severity_note: Option<String>,
    /// When the rule fires.
    pub description: String,
    /// Reason given in alerts (administrator rules).
    pub reason: Option<String>,
    pub recommendation: String,
    pub matcher: Option<Matcher>,
    /// The file that defines or overrides this rule.
    pub file: Option<PathBuf>,
}

impl Rule {
    /// Severity to raise at, given the one the built-in logic computed.
    pub fn severity_for(&self, computed: Severity) -> Severity {
        self.severity.unwrap_or(computed)
    }

    /// Stable JSON definition, stored with the rule and its version.
    pub fn definition(&self) -> serde_json::Value {
        serde_json::to_value(self).expect("rules are serializable")
    }
}

/// A problem in a rule file.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct Problem {
    pub file: PathBuf,
    pub message: String,
}

impl std::fmt::Display for Problem {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}: {}", self.file.display(), self.message)
    }
}

#[derive(Debug, thiserror::Error)]
#[error("invalid detection rules: {}", .0.iter().map(ToString::to_string).collect::<Vec<_>>().join("; "))]
pub struct RulesError(pub Vec<Problem>);

/// The rules in effect.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RuleSet {
    rules: BTreeMap<String, Rule>,
    /// Files read, in order.
    pub files: Vec<PathBuf>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct RuleFile {
    #[serde(default, rename = "override")]
    overrides: Vec<OverrideDef>,
    #[serde(default, rename = "rule")]
    rules: Vec<RuleDef>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct OverrideDef {
    rule: String,
    enabled: Option<bool>,
    severity: Option<Severity>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct RuleDef {
    id: String,
    title: String,
    on: Category,
    severity: Severity,
    #[serde(default = "yes")]
    enabled: bool,
    reason: Option<String>,
    recommendation: Option<String>,
    // file
    #[serde(default)]
    paths: Vec<String>,
    #[serde(default)]
    changes: Vec<String>,
    // execution
    #[serde(default)]
    programs: Vec<String>,
    #[serde(default)]
    parents: Vec<String>,
    #[serde(default)]
    uids: Vec<u32>,
    #[serde(default)]
    classifications: Vec<String>,
    #[serde(default)]
    arguments: Vec<String>,
}

fn yes() -> bool {
    true
}

fn valid_id(id: &str) -> bool {
    !id.is_empty()
        && id.len() <= 64
        && id
            .bytes()
            .all(|b| b.is_ascii_uppercase() || b.is_ascii_digit() || b == b'-' || b == b'_')
}

impl Default for RuleSet {
    fn default() -> Self {
        Self::builtin()
    }
}

impl RuleSet {
    /// Only the built-in rules, with their defaults.
    pub fn builtin() -> RuleSet {
        let rules = BUILTIN
            .iter()
            .map(|b| {
                (
                    b.id.to_owned(),
                    Rule {
                        id: b.id.into(),
                        title: b.title.into(),
                        category: b.category,
                        origin: Origin::Builtin,
                        enabled: true,
                        severity: b.severity,
                        severity_note: b.severity_note.map(Into::into),
                        description: b.description.into(),
                        reason: None,
                        recommendation: b.recommendation.into(),
                        matcher: None,
                        file: None,
                    },
                )
            })
            .collect();
        RuleSet {
            rules,
            files: Vec::new(),
        }
    }

    /// Built-in rules plus the `*.toml` files in `dir`, in name order. A
    /// missing directory means no administrator rules.
    pub fn load(dir: &Path) -> Result<RuleSet, RulesError> {
        let mut set = RuleSet::builtin();
        let mut problems = Vec::new();
        let entries = match std::fs::read_dir(dir) {
            Ok(e) => e,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(set),
            Err(e) => {
                return Err(RulesError(vec![Problem {
                    file: dir.to_owned(),
                    message: format!("cannot read the rules directory: {e}"),
                }]));
            }
        };
        let mut files: Vec<PathBuf> = entries
            .filter_map(|e| e.ok().map(|e| e.path()))
            .filter(|p| p.extension().is_some_and(|x| x == "toml"))
            .collect();
        files.sort();
        for f in files {
            match std::fs::read_to_string(&f) {
                Ok(text) => set.add_file(&f, &text, &mut problems),
                Err(e) => problems.push(Problem {
                    file: f.clone(),
                    message: format!("cannot read: {e}"),
                }),
            }
            set.files.push(f);
        }
        if problems.is_empty() {
            Ok(set)
        } else {
            Err(RulesError(problems))
        }
    }

    /// Parse one rule file into the set (tests and [`RuleSet::load`]).
    pub fn add_toml(&mut self, file: &Path, text: &str) -> Result<(), RulesError> {
        let mut problems = Vec::new();
        self.add_file(file, text, &mut problems);
        if problems.is_empty() {
            Ok(())
        } else {
            Err(RulesError(problems))
        }
    }

    fn add_file(&mut self, file: &Path, text: &str, problems: &mut Vec<Problem>) {
        let mut problem = |message: String| {
            problems.push(Problem {
                file: file.to_owned(),
                message,
            })
        };
        let parsed: RuleFile = match toml::from_str(text) {
            Ok(p) => p,
            Err(e) => return problem(e.to_string().trim_end().to_owned()),
        };
        let mut overridden = HashSet::new();
        for o in parsed.overrides {
            let Some(rule) = self.rules.get_mut(&o.rule) else {
                problem(format!("override of unknown rule '{}'", o.rule));
                continue;
            };
            if rule.origin != Origin::Builtin {
                problem(format!(
                    "'{}' is an administrator rule; change its definition instead of overriding it",
                    o.rule
                ));
                continue;
            }
            if !overridden.insert(o.rule.clone()) || rule.file.is_some() {
                problem(format!("rule '{}' is overridden more than once", o.rule));
                continue;
            }
            if o.enabled.is_none() && o.severity.is_none() {
                problem(format!(
                    "override of '{}' changes nothing; set enabled or severity",
                    o.rule
                ));
                continue;
            }
            if let Some(e) = o.enabled {
                rule.enabled = e;
            }
            if let Some(s) = o.severity {
                rule.severity = Some(s);
            }
            rule.file = Some(file.to_owned());
        }
        for d in parsed.rules {
            if !valid_id(&d.id) {
                problem(format!(
                    "rule id '{}' must be 1 to 64 upper-case letters, digits, '-' or '_'",
                    d.id
                ));
                continue;
            }
            if let Some(existing) = self.rules.get(&d.id) {
                problem(match &existing.file {
                    _ if existing.origin == Origin::Builtin => {
                        format!("rule id '{}' is built in; choose another id", d.id)
                    }
                    Some(f) => format!("rule id '{}' is already defined in {}", d.id, f.display()),
                    None => format!("rule id '{}' is defined twice", d.id),
                });
                continue;
            }
            if d.title.trim().is_empty() {
                problem(format!("rule '{}' needs a title", d.id));
                continue;
            }
            let matcher = match d.on {
                Category::File => {
                    let mut bad = false;
                    if !d.programs.is_empty()
                        || !d.parents.is_empty()
                        || !d.uids.is_empty()
                        || !d.classifications.is_empty()
                        || !d.arguments.is_empty()
                    {
                        problem(format!(
                            "rule '{}': programs, parents, uids, classifications and arguments apply to execution rules only",
                            d.id
                        ));
                        bad = true;
                    }
                    if d.paths.is_empty() {
                        problem(format!("rule '{}' must list at least one path", d.id));
                        bad = true;
                    }
                    for p in &d.paths {
                        if !p.starts_with('/') {
                            problem(format!(
                                "rule '{}': path pattern '{p}' must be absolute",
                                d.id
                            ));
                            bad = true;
                        }
                    }
                    for c in &d.changes {
                        if !CHANGE_KINDS.contains(&c.as_str()) {
                            problem(format!(
                                "rule '{}': unknown change '{c}'; expected one of {}",
                                d.id,
                                CHANGE_KINDS.join(", ")
                            ));
                            bad = true;
                        }
                    }
                    if bad {
                        continue;
                    }
                    Matcher::File(FileMatcher {
                        paths: d.paths,
                        changes: d.changes,
                    })
                }
                Category::Execution => {
                    let mut bad = false;
                    if !d.paths.is_empty() || !d.changes.is_empty() {
                        problem(format!(
                            "rule '{}': paths and changes apply to file rules only; use programs",
                            d.id
                        ));
                        bad = true;
                    }
                    for c in &d.classifications {
                        if !CLASSIFICATIONS.contains(&c.as_str()) {
                            problem(format!(
                                "rule '{}': unknown classification '{c}'; expected one of {}",
                                d.id,
                                CLASSIFICATIONS.join(", ")
                            ));
                            bad = true;
                        }
                    }
                    if d.arguments.iter().any(String::is_empty) {
                        problem(format!("rule '{}': an argument pattern is empty", d.id));
                        bad = true;
                    }
                    let m = ExecMatcher {
                        programs: d.programs,
                        parents: d.parents,
                        uids: d.uids,
                        classifications: d.classifications,
                        arguments: d.arguments,
                    };
                    if m.is_empty() {
                        problem(format!(
                            "rule '{}' would match every execution; give programs, parents, uids, classifications or arguments",
                            d.id
                        ));
                        bad = true;
                    }
                    if bad {
                        continue;
                    }
                    Matcher::Execution(m)
                }
                Category::Integrity => {
                    problem(format!(
                        "rule '{}': 'on' must be \"file\" or \"execution\"",
                        d.id
                    ));
                    continue;
                }
            };
            let reason = d
                .reason
                .filter(|r| !r.trim().is_empty())
                .unwrap_or_else(|| {
                    format!(
                        "Matched administrator rule {}: {}.",
                        d.id,
                        d.title.trim_end_matches('.')
                    )
                });
            self.rules.insert(
                d.id.clone(),
                Rule {
                    description: d.title.clone(),
                    id: d.id,
                    title: d.title,
                    category: d.on,
                    origin: Origin::Admin,
                    enabled: d.enabled,
                    severity: Some(d.severity),
                    severity_note: None,
                    reason: Some(reason),
                    recommendation: d.recommendation.unwrap_or_else(|| {
                        "Review the matched object or process against your site's change records.".into()
                    }),
                    matcher: Some(matcher),
                    file: Some(file.to_owned()),
                },
            );
        }
    }

    pub fn get(&self, id: &str) -> Option<&Rule> {
        self.rules.get(id)
    }

    /// All rules, ordered by id.
    pub fn iter(&self) -> impl Iterator<Item = &Rule> {
        self.rules.values()
    }

    /// The severity a built-in detection raises at, or `None` when the rule
    /// is disabled. Unknown ids keep the computed severity.
    pub fn effective(&self, id: &str, computed: Severity) -> Option<Severity> {
        match self.rules.get(id) {
            Some(r) if !r.enabled => None,
            Some(r) => Some(r.severity_for(computed)),
            None => Some(computed),
        }
    }

    /// Enabled administrator file rules matching this change.
    pub fn file_matches<'a>(
        &'a self,
        path: &'a [u8],
        changes: &'a [&'a str],
    ) -> impl Iterator<Item = &'a Rule> + 'a {
        self.rules.values().filter(move |r| {
            r.enabled && matches!(&r.matcher, Some(Matcher::File(m)) if m.matches(path, changes))
        })
    }

    /// Enabled administrator execution rules matching this execution.
    pub fn exec_matches<'a>(
        &'a self,
        facts: &'a ExecFacts<'a>,
    ) -> impl Iterator<Item = &'a Rule> + 'a {
        self.rules.values().filter(move |r| {
            r.enabled && matches!(&r.matcher, Some(Matcher::Execution(m)) if m.matches(facts))
        })
    }

    /// Whether any administrator execution rule is enabled.
    pub fn has_exec_rules(&self) -> bool {
        self.rules
            .values()
            .any(|r| r.enabled && matches!(r.matcher, Some(Matcher::Execution(_))))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn set(text: &str) -> Result<RuleSet, RulesError> {
        let mut s = RuleSet::builtin();
        s.add_toml(Path::new("/etc/soteria/rules.d/t.toml"), text)?;
        Ok(s)
    }

    #[test]
    fn builtins_are_complete_and_unique() {
        let s = RuleSet::builtin();
        assert_eq!(s.iter().count(), BUILTIN.len());
        for id in ["FIM-001", "FIM-011", "EXE-001", "EXE-005", "INT-001"] {
            let r = s.get(id).unwrap();
            assert!(r.enabled && !r.recommendation.is_empty(), "{id}");
        }
        assert_eq!(
            s.effective("EXE-001", Severity::Medium),
            Some(Severity::Medium)
        );
        assert_eq!(s.effective("NOPE", Severity::Low), Some(Severity::Low));
    }

    #[test]
    fn overrides_disable_or_fix_severity() {
        let s = set(r#"
            [[override]]
            rule = "FIM-011"
            enabled = false
            [[override]]
            rule = "EXE-001"
            severity = "high"
            "#)
        .unwrap();
        assert_eq!(s.effective("FIM-011", Severity::Info), None);
        assert_eq!(
            s.effective("EXE-001", Severity::Medium),
            Some(Severity::High)
        );
        assert!(s.get("EXE-001").unwrap().file.is_some());
    }

    #[test]
    fn admin_rules_match_files_and_executions() {
        let s = set(r#"
            [[rule]]
            id = "LOCAL-001"
            title = "SSH server configuration changed"
            on = "file"
            severity = "critical"
            paths = ["/etc/ssh/sshd_config", "/etc/ssh/sshd_config.d/**"]
            changes = ["content_modified"]

            [[rule]]
            id = "LOCAL-002"
            title = "Netcat with a shell"
            on = "execution"
            severity = "high"
            programs = ["nc", "ncat", "/opt/*/bin/socat"]
            arguments = ["-e"]
            "#)
        .unwrap();
        let hits: Vec<_> = s
            .file_matches(b"/etc/ssh/sshd_config.d/50-x.conf", &["content_modified"])
            .map(|r| r.id.as_str())
            .collect();
        assert_eq!(hits, ["LOCAL-001"]);
        assert_eq!(
            s.file_matches(b"/etc/ssh/sshd_config", &["owner_modified"])
                .count(),
            0
        );
        assert_eq!(
            s.file_matches(b"/etc/ssh/ssh_config", &["content_modified"])
                .count(),
            0
        );

        let argv = vec![b"nc".to_vec(), b"-e".to_vec(), b"/bin/sh".to_vec()];
        let mut f = ExecFacts {
            exe: Some(b"/usr/bin/nc"),
            classification: "trusted",
            argv: &argv,
            ..Default::default()
        };
        assert_eq!(s.exec_matches(&f).count(), 1);
        f.exe = Some(b"/opt/tools/bin/socat");
        assert_eq!(s.exec_matches(&f).count(), 1);
        f.exe = Some(b"/usr/bin/socat");
        assert_eq!(s.exec_matches(&f).count(), 0);
        let quiet = vec![b"nc".to_vec(), b"host".to_vec()];
        f.exe = Some(b"/usr/bin/nc");
        f.argv = &quiet;
        assert_eq!(s.exec_matches(&f).count(), 0);
        assert!(s.has_exec_rules());
        assert_eq!(
            s.get("LOCAL-002").unwrap().reason.as_deref(),
            Some("Matched administrator rule LOCAL-002: Netcat with a shell.")
        );
    }

    #[test]
    fn invalid_rules_are_errors() {
        for (text, expect) in [
            (
                "[[override]]\nrule = \"NOPE\"\nenabled = false",
                "unknown rule",
            ),
            ("[[override]]\nrule = \"FIM-001\"", "changes nothing"),
            (
                "[[override]]\nrule = \"FIM-001\"\nenabled = false\nseverity = \"loud\"",
                "unknown variant",
            ),
            (
                "[[rule]]\nid = \"FIM-001\"\ntitle = \"x\"\non = \"file\"\nseverity = \"low\"\npaths = [\"/x\"]",
                "built in",
            ),
            (
                "[[rule]]\nid = \"bad id\"\ntitle = \"x\"\non = \"file\"\nseverity = \"low\"\npaths = [\"/x\"]",
                "upper-case",
            ),
            (
                "[[rule]]\nid = \"A\"\ntitle = \"x\"\non = \"file\"\nseverity = \"low\"",
                "at least one path",
            ),
            (
                "[[rule]]\nid = \"A\"\ntitle = \"x\"\non = \"file\"\nseverity = \"low\"\npaths = [\"etc\"]",
                "absolute",
            ),
            (
                "[[rule]]\nid = \"A\"\ntitle = \"x\"\non = \"file\"\nseverity = \"low\"\npaths = [\"/x\"]\nchanges = [\"eaten\"]",
                "unknown change",
            ),
            (
                "[[rule]]\nid = \"A\"\ntitle = \"x\"\non = \"execution\"\nseverity = \"low\"",
                "every execution",
            ),
            (
                "[[rule]]\nid = \"A\"\ntitle = \"x\"\non = \"execution\"\nseverity = \"low\"\npaths = [\"/x\"]",
                "file rules only",
            ),
            (
                "[[rule]]\nid = \"A\"\ntitle = \"x\"\non = \"integrity\"\nseverity = \"low\"",
                "must be",
            ),
            (
                "[[rule]]\nid = \"A\"\ntitle = \"x\"\non = \"file\"\nseverity = \"low\"\npaths = [\"/x\"]\ncolour = 1",
                "unknown field",
            ),
        ] {
            let err = set(text).unwrap_err().to_string();
            assert!(err.contains(expect), "{text}: {err}");
        }
    }

    #[test]
    fn load_reads_toml_files_in_order_and_reports_all_problems() {
        let d = tempfile::tempdir().unwrap();
        assert_eq!(
            RuleSet::load(&d.path().join("missing")).unwrap(),
            RuleSet::builtin()
        );
        std::fs::write(
            d.path().join("10-a.toml"),
            "[[rule]]\nid = \"A-1\"\ntitle = \"a\"\non = \"file\"\nseverity = \"low\"\npaths = [\"/a\"]\n",
        )
        .unwrap();
        std::fs::write(d.path().join("README"), "not a rule file").unwrap();
        let s = RuleSet::load(d.path()).unwrap();
        assert!(s.get("A-1").is_some());
        assert_eq!(s.files.len(), 1);

        std::fs::write(
            d.path().join("20-b.toml"),
            "[[rule]]\nid = \"A-1\"\ntitle = \"a\"\non = \"file\"\nseverity = \"low\"\npaths = [\"/a\"]\n\
             [[override]]\nrule = \"X\"\nenabled = false\n",
        )
        .unwrap();
        let err = RuleSet::load(d.path()).unwrap_err();
        assert_eq!(err.0.len(), 2, "{err}");
        assert!(
            err.0
                .iter()
                .any(|p| p.message.contains("already defined in")),
            "{err}"
        );
    }
}
