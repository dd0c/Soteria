//! Platform detection and OS adapters (SRS 1.4, 5.3, 9).
//!
//! Core components never look at distribution names or conventions directly.
//! They ask the [`PlatformAdapter`] for the active host, which knows its
//! package manager, mandatory access control framework and OS-specific paths.
//!
//! All probes read through a [`HostRoot`], so tests can point them at a fake
//! filesystem tree instead of the real `/`.

use std::fmt;
use std::path::PathBuf;

use serde::Serialize;

/// Root of the filesystem the probes read from. `/` in production.
#[derive(Debug, Clone)]
pub struct HostRoot(PathBuf);

impl Default for HostRoot {
    fn default() -> Self {
        HostRoot(PathBuf::from("/"))
    }
}

impl HostRoot {
    pub fn new(root: impl Into<PathBuf>) -> Self {
        HostRoot(root.into())
    }

    /// Resolve an absolute host path below this root.
    pub fn path(&self, abs: &str) -> PathBuf {
        self.0.join(abs.trim_start_matches('/'))
    }

    fn read(&self, abs: &str) -> Option<String> {
        std::fs::read_to_string(self.path(abs)).ok()
    }

    fn exists(&self, abs: &str) -> bool {
        self.path(abs).exists()
    }
}

/// Parsed `/etc/os-release` (os-release(5)).
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize)]
pub struct OsRelease {
    pub id: String,
    pub id_like: Vec<String>,
    pub version_id: String,
    pub pretty_name: String,
}

impl OsRelease {
    pub fn parse(text: &str) -> OsRelease {
        let mut os = OsRelease::default();
        for line in text.lines() {
            let line = line.trim();
            if line.starts_with('#') {
                continue;
            }
            let Some((key, value)) = line.split_once('=') else {
                continue;
            };
            let value = unquote(value.trim());
            match key.trim() {
                "ID" => os.id = value.to_ascii_lowercase(),
                "ID_LIKE" => {
                    os.id_like = value
                        .split_whitespace()
                        .map(|s| s.to_ascii_lowercase())
                        .collect()
                }
                "VERSION_ID" => os.version_id = value,
                "PRETTY_NAME" => os.pretty_name = value,
                _ => {}
            }
        }
        os
    }

    /// Major version number, such as `9` for `VERSION_ID="9.4"`.
    pub fn major_version(&self) -> Option<u32> {
        self.version_id.split('.').next()?.parse().ok()
    }

    fn is_like(&self, family: &str) -> bool {
        self.id == family || self.id_like.iter().any(|l| l == family)
    }
}

fn unquote(v: &str) -> String {
    let v = v
        .strip_prefix('"')
        .and_then(|s| s.strip_suffix('"'))
        .or_else(|| v.strip_prefix('\'').and_then(|s| s.strip_suffix('\'')))
        .unwrap_or(v);
    v.replace("\\\"", "\"").replace("\\\\", "\\")
}

/// Distribution family, which selects the adapter.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum Family {
    Rhel,
    Debian,
    Unknown,
}

/// Whether this exact OS is a supported target (SRS 1.4).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum SupportLevel {
    /// RHEL 9, RHEL 10 or Debian 13.
    Supported,
    /// Same family as a supported OS (for example a RHEL rebuild or another
    /// Debian release); expected to work but not tested or supported.
    Compatible,
    Unsupported,
}

impl fmt::Display for SupportLevel {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            SupportLevel::Supported => "supported",
            SupportLevel::Compatible => "compatible, not officially supported",
            SupportLevel::Unsupported => "unsupported",
        })
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum PackageManager {
    Rpm,
    Dpkg,
    Unknown,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum MacFramework {
    SELinux,
    AppArmor,
    None,
}

impl fmt::Display for MacFramework {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            MacFramework::SELinux => "SELinux",
            MacFramework::AppArmor => "AppArmor",
            MacFramework::None => "none",
        })
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum MacMode {
    Enforcing,
    Permissive,
    Enabled,
    Disabled,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
pub struct MacStatus {
    pub framework: MacFramework,
    pub mode: MacMode,
}

impl fmt::Display for MacStatus {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let mode = match self.mode {
            MacMode::Enforcing => "enforcing",
            MacMode::Permissive => "permissive",
            MacMode::Enabled => "enabled",
            MacMode::Disabled => "disabled",
        };
        if self.framework == MacFramework::None {
            f.write_str("none detected")
        } else {
            write!(f, "{} ({mode})", self.framework)
        }
    }
}

/// OS-specific behaviour behind a common interface (SRS 5.3).
///
/// Later milestones extend this with package inventory and verification,
/// audit configuration and service discovery.
pub trait PlatformAdapter: Send + Sync {
    fn family(&self) -> Family;
    fn package_manager(&self) -> PackageManager;
    /// The MAC framework this platform is expected to use.
    fn expected_mac(&self) -> MacFramework;
    /// Login shell for the service account (SRS 8.2).
    fn nologin_shell(&self) -> &'static str;
    /// Security-sensitive locations specific to this family, added to the
    /// common set (FR-019).
    fn extra_sensitive_paths(&self) -> &'static [&'static str];
}

struct RhelAdapter;
struct DebianAdapter;
struct GenericAdapter;

impl PlatformAdapter for RhelAdapter {
    fn family(&self) -> Family {
        Family::Rhel
    }
    fn package_manager(&self) -> PackageManager {
        PackageManager::Rpm
    }
    fn expected_mac(&self) -> MacFramework {
        MacFramework::SELinux
    }
    fn nologin_shell(&self) -> &'static str {
        "/usr/sbin/nologin"
    }
    fn extra_sensitive_paths(&self) -> &'static [&'static str] {
        &[
            "/etc/sysconfig",
            "/etc/selinux",
            "/etc/dnf",
            "/etc/yum.repos.d",
            "/etc/pki/rpm-gpg",
            "/etc/firewalld",
        ]
    }
}

impl PlatformAdapter for DebianAdapter {
    fn family(&self) -> Family {
        Family::Debian
    }
    fn package_manager(&self) -> PackageManager {
        PackageManager::Dpkg
    }
    fn expected_mac(&self) -> MacFramework {
        MacFramework::AppArmor
    }
    fn nologin_shell(&self) -> &'static str {
        "/usr/sbin/nologin"
    }
    fn extra_sensitive_paths(&self) -> &'static [&'static str] {
        &[
            "/etc/default",
            "/etc/apparmor",
            "/etc/apparmor.d",
            "/etc/apt",
            "/etc/network",
        ]
    }
}

impl PlatformAdapter for GenericAdapter {
    fn family(&self) -> Family {
        Family::Unknown
    }
    fn package_manager(&self) -> PackageManager {
        PackageManager::Unknown
    }
    fn expected_mac(&self) -> MacFramework {
        MacFramework::None
    }
    fn nologin_shell(&self) -> &'static str {
        "/usr/sbin/nologin"
    }
    fn extra_sensitive_paths(&self) -> &'static [&'static str] {
        &[]
    }
}

/// The detected host platform.
pub struct Platform {
    pub os: OsRelease,
    pub support: SupportLevel,
    adapter: Box<dyn PlatformAdapter>,
    root: HostRoot,
}

impl fmt::Debug for Platform {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Platform")
            .field("os", &self.os)
            .field("support", &self.support)
            .field("family", &self.adapter.family())
            .finish()
    }
}

#[derive(Debug, thiserror::Error)]
pub enum PlatformError {
    #[error("cannot identify the operating system: {0} is missing or unreadable")]
    NoOsRelease(PathBuf),
}

impl Platform {
    /// Detect the platform of the running host.
    pub fn detect() -> Result<Platform, PlatformError> {
        Platform::detect_at(HostRoot::default())
    }

    /// Detect the platform of the filesystem tree at `root`.
    pub fn detect_at(root: HostRoot) -> Result<Platform, PlatformError> {
        let text = root
            .read("/etc/os-release")
            .or_else(|| root.read("/usr/lib/os-release"))
            .ok_or_else(|| PlatformError::NoOsRelease(root.path("/etc/os-release")))?;
        let os = OsRelease::parse(&text);
        let major = os.major_version();

        let (adapter, support): (Box<dyn PlatformAdapter>, SupportLevel) = if os.is_like("rhel") {
            let supported = os.id == "rhel" && matches!(major, Some(9 | 10));
            (Box::new(RhelAdapter), support_level(supported))
        } else if os.is_like("debian") {
            let supported = os.id == "debian" && major == Some(13);
            (Box::new(DebianAdapter), support_level(supported))
        } else {
            (Box::new(GenericAdapter), SupportLevel::Unsupported)
        };

        Ok(Platform {
            os,
            support,
            adapter,
            root,
        })
    }

    pub fn adapter(&self) -> &dyn PlatformAdapter {
        self.adapter.as_ref()
    }

    /// Display name, such as "RHEL 9" or "Debian 13".
    pub fn display_name(&self) -> String {
        match (
            self.adapter.family(),
            self.os.id.as_str(),
            self.os.major_version(),
        ) {
            (Family::Rhel, "rhel", Some(v)) => format!("RHEL {v}"),
            (Family::Debian, "debian", Some(v)) => format!("Debian {v}"),
            _ if !self.os.pretty_name.is_empty() => self.os.pretty_name.clone(),
            _ => format!("{} {}", self.os.id, self.os.version_id),
        }
    }

    /// Current state of the mandatory access control framework.
    pub fn mac_status(&self) -> MacStatus {
        // SELinux exposes its mode through selinuxfs.
        if let Some(enforce) = self.root.read("/sys/fs/selinux/enforce") {
            let mode = if enforce.trim() == "1" {
                MacMode::Enforcing
            } else {
                MacMode::Permissive
            };
            return MacStatus {
                framework: MacFramework::SELinux,
                mode,
            };
        }
        if let Some(enabled) = self.root.read("/sys/module/apparmor/parameters/enabled") {
            let mode = if enabled.trim() == "Y" {
                MacMode::Enabled
            } else {
                MacMode::Disabled
            };
            return MacStatus {
                framework: MacFramework::AppArmor,
                mode,
            };
        }
        MacStatus {
            framework: self.adapter.expected_mac(),
            mode: MacMode::Disabled,
        }
    }

    /// Runtime capability probes, reported by `status` and `verify` so that
    /// unavailable functionality is never shown as active (SRS 4.7).
    pub fn probe(&self) -> Vec<Probe> {
        let mut probes = Vec::new();

        let kernel = self
            .root
            .read("/proc/sys/kernel/osrelease")
            .map(|s| s.trim().to_owned());
        probes.push(match kernel {
            Some(k) => Probe::available("kernel", k),
            None => Probe::unknown("kernel", "kernel release unreadable"),
        });

        probes.push(if self.root.exists("/run/systemd/system") {
            Probe::available("systemd", "systemd is the service manager")
        } else {
            Probe::unavailable(
                "systemd",
                "systemd is not running; the service cannot be managed",
            )
        });

        let (tool, path) = match self.adapter.package_manager() {
            PackageManager::Rpm => ("rpm", "/usr/bin/rpm"),
            PackageManager::Dpkg => ("dpkg", "/usr/bin/dpkg-query"),
            PackageManager::Unknown => ("package manager", ""),
        };
        probes.push(if !path.is_empty() && self.root.exists(path) {
            Probe::available("package_manager", format!("{tool} found at {path}"))
        } else {
            Probe::unavailable(
                "package_manager",
                format!("{tool} not found; package provenance checks are unavailable"),
            )
        });

        let mac = self.mac_status();
        probes.push(match mac.mode {
            MacMode::Disabled => Probe::unavailable(
                "mac",
                format!(
                    "{} is not active; security labels are not collected",
                    match mac.framework {
                        MacFramework::None => "no MAC framework".to_owned(),
                        f => f.to_string(),
                    }
                ),
            ),
            _ => Probe::available("mac", mac.to_string()),
        });

        probes.push(if self.root.exists("/proc/self/loginuid") {
            Probe::available(
                "audit",
                "kernel audit support present (sensor arrives in a later release)",
            )
        } else {
            Probe::unavailable(
                "audit",
                "kernel audit support not detected; execution monitoring will be unavailable",
            )
        });

        probes
    }
}

fn support_level(supported: bool) -> SupportLevel {
    if supported {
        SupportLevel::Supported
    } else {
        SupportLevel::Compatible
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum ProbeState {
    Available,
    Unavailable,
    Unknown,
}

/// Result of one capability probe.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct Probe {
    pub name: &'static str,
    pub state: ProbeState,
    pub detail: String,
}

impl Probe {
    fn available(name: &'static str, detail: impl Into<String>) -> Probe {
        Probe {
            name,
            state: ProbeState::Available,
            detail: detail.into(),
        }
    }
    fn unavailable(name: &'static str, detail: impl Into<String>) -> Probe {
        Probe {
            name,
            state: ProbeState::Unavailable,
            detail: detail.into(),
        }
    }
    fn unknown(name: &'static str, detail: impl Into<String>) -> Probe {
        Probe {
            name,
            state: ProbeState::Unknown,
            detail: detail.into(),
        }
    }
}

/// Hostname of the running system, used in alerts (FR-029).
pub fn hostname() -> String {
    hostname_at(&HostRoot::default())
}

fn hostname_at(root: &HostRoot) -> String {
    root.read("/proc/sys/kernel/hostname")
        .or_else(|| root.read("/etc/hostname"))
        .map(|s| s.trim().to_owned())
        .filter(|s| !s.is_empty())
        .unwrap_or_else(|| "unknown".to_owned())
}

#[cfg(test)]
mod tests {
    use super::*;

    const RHEL9: &str = r#"NAME="Red Hat Enterprise Linux"
VERSION="9.4 (Plow)"
ID="rhel"
ID_LIKE="fedora"
VERSION_ID="9.4"
PRETTY_NAME="Red Hat Enterprise Linux 9.4 (Plow)"
"#;
    const RHEL10: &str = "ID=\"rhel\"\nID_LIKE=\"centos fedora\"\nVERSION_ID=\"10.0\"\nPRETTY_NAME=\"Red Hat Enterprise Linux 10.0 (Coughlan)\"\n";
    const DEBIAN13: &str = "PRETTY_NAME=\"Debian GNU/Linux 13 (trixie)\"\nNAME=\"Debian GNU/Linux\"\nVERSION_ID=\"13\"\nVERSION_CODENAME=trixie\nID=debian\n";
    const ROCKY9: &str = "ID=\"rocky\"\nID_LIKE=\"rhel centos fedora\"\nVERSION_ID=\"9.4\"\nPRETTY_NAME=\"Rocky Linux 9.4 (Blue Onyx)\"\n";
    const UBUNTU: &str =
        "ID=ubuntu\nID_LIKE=debian\nVERSION_ID=\"24.04\"\nPRETTY_NAME=\"Ubuntu 24.04 LTS\"\n";
    const ARCH: &str = "ID=arch\nPRETTY_NAME=\"Arch Linux\"\n";

    fn fake_host(os_release: &str, files: &[(&str, &str)]) -> (tempfile::TempDir, Platform) {
        let dir = tempfile::tempdir().unwrap();
        let root = HostRoot::new(dir.path());
        let write = |abs: &str, content: &str| {
            let p = root.path(abs);
            std::fs::create_dir_all(p.parent().unwrap()).unwrap();
            std::fs::write(p, content).unwrap();
        };
        write("/etc/os-release", os_release);
        for (p, c) in files {
            write(p, c);
        }
        let platform = Platform::detect_at(root).unwrap();
        (dir, platform)
    }

    #[test]
    fn parses_quoted_and_unquoted_values() {
        let os = OsRelease::parse(DEBIAN13);
        assert_eq!(os.id, "debian");
        assert_eq!(os.version_id, "13");
        assert_eq!(os.pretty_name, "Debian GNU/Linux 13 (trixie)");
        let os = OsRelease::parse("ID='rhel'\n# comment\nVERSION_ID=\"9.4\"\n");
        assert_eq!(os.id, "rhel");
        assert_eq!(os.major_version(), Some(9));
    }

    #[test]
    fn detects_supported_targets() {
        for (text, name, family) in [
            (RHEL9, "RHEL 9", Family::Rhel),
            (RHEL10, "RHEL 10", Family::Rhel),
            (DEBIAN13, "Debian 13", Family::Debian),
        ] {
            let (_d, p) = fake_host(text, &[]);
            assert_eq!(p.support, SupportLevel::Supported, "{name}");
            assert_eq!(p.display_name(), name);
            assert_eq!(p.adapter().family(), family);
        }
    }

    #[test]
    fn family_members_are_compatible_not_supported() {
        let (_d, p) = fake_host(ROCKY9, &[]);
        assert_eq!(p.support, SupportLevel::Compatible);
        assert_eq!(p.adapter().package_manager(), PackageManager::Rpm);
        assert_eq!(p.display_name(), "Rocky Linux 9.4 (Blue Onyx)");

        let (_d, p) = fake_host(UBUNTU, &[]);
        assert_eq!(p.support, SupportLevel::Compatible);
        assert_eq!(p.adapter().package_manager(), PackageManager::Dpkg);

        let (_d, p) = fake_host(&RHEL9.replace("9.4", "8.10"), &[]);
        assert_eq!(p.support, SupportLevel::Compatible);
    }

    #[test]
    fn other_distributions_are_unsupported() {
        let (_d, p) = fake_host(ARCH, &[]);
        assert_eq!(p.support, SupportLevel::Unsupported);
        assert_eq!(p.adapter().family(), Family::Unknown);
    }

    #[test]
    fn missing_os_release_is_an_error() {
        let dir = tempfile::tempdir().unwrap();
        assert!(Platform::detect_at(HostRoot::new(dir.path())).is_err());
    }

    #[test]
    fn detects_selinux_mode() {
        let (_d, p) = fake_host(RHEL9, &[("/sys/fs/selinux/enforce", "1\n")]);
        assert_eq!(
            p.mac_status(),
            MacStatus {
                framework: MacFramework::SELinux,
                mode: MacMode::Enforcing
            }
        );
        let (_d, p) = fake_host(RHEL9, &[("/sys/fs/selinux/enforce", "0\n")]);
        assert_eq!(p.mac_status().mode, MacMode::Permissive);
    }

    #[test]
    fn detects_apparmor() {
        let (_d, p) = fake_host(
            DEBIAN13,
            &[("/sys/module/apparmor/parameters/enabled", "Y\n")],
        );
        assert_eq!(p.mac_status().framework, MacFramework::AppArmor);
        assert_eq!(p.mac_status().mode, MacMode::Enabled);
    }

    #[test]
    fn missing_mac_is_reported_unavailable() {
        let (_d, p) = fake_host(RHEL9, &[]);
        let mac = p.probe().into_iter().find(|pr| pr.name == "mac").unwrap();
        assert_eq!(mac.state, ProbeState::Unavailable);
        assert!(mac.detail.contains("SELinux"), "{}", mac.detail);
    }

    #[test]
    fn probes_report_missing_tools() {
        let (_d, p) = fake_host(
            DEBIAN13,
            &[
                ("/proc/sys/kernel/osrelease", "6.12.0\n"),
                ("/usr/bin/dpkg-query", ""),
            ],
        );
        let probes = p.probe();
        let get = |n: &str| probes.iter().find(|pr| pr.name == n).unwrap().clone();
        assert_eq!(get("kernel").detail, "6.12.0");
        assert_eq!(get("package_manager").state, ProbeState::Available);
        assert_eq!(get("systemd").state, ProbeState::Unavailable);
    }

    #[test]
    fn hostname_falls_back_to_etc_hostname() {
        let dir = tempfile::tempdir().unwrap();
        let root = HostRoot::new(dir.path());
        assert_eq!(hostname_at(&root), "unknown");
        std::fs::create_dir_all(root.path("/etc")).unwrap();
        std::fs::write(root.path("/etc/hostname"), "web-01\n").unwrap();
        assert_eq!(hostname_at(&root), "web-01");
    }
}
