# Soteria — Software Requirements Specification (SRS)

**Version:** 1.0 Draft  
**Status:** Proposed  
**Project:** Soteria Linux Host Intrusion Detection and Integrity Monitoring  
**Document purpose:** Define product scope, requirements, architecture constraints, interfaces, and acceptance criteria for Soteria's initial release.

---

## 1. Project Overview

### 1.1 Purpose
Soteria is a Linux host-based intrusion detection and integrity monitoring system (HIDS). It establishes a reviewed baseline of system files and security-relevant state, continuously monitors execution and changes, detects deviations and suspicious activity, and provides local evidence and alerts for administrator investigation.

Soteria focuses on system integrity, execution telemetry, configuration and persistence monitoring, detection-rule evaluation, event correlation, and sensor-health visibility. It is not intended to automatically remediate incidents in the initial release.

### 1.2 Objectives
- Detect unauthorized creation, modification, replacement, deletion, or metadata changes involving monitored system files.
- Monitor executable and script launch activity and retain useful process context.
- Maintain an administrator-reviewed, versioned baseline of system state.
- Detect changes to security-sensitive configuration and persistence mechanisms.
- Correlate related observations into actionable alerts.
- Report monitoring gaps, failures, and coverage limitations.
- Operate locally without requiring internet or cloud connectivity.
- Minimize resource use and protect the service, its configuration, and data using least privilege.

### 1.3 Intended users
- Linux system administrators
- Security engineers and incident responders
- SOC analysts
- Infrastructure and platform engineers
- Operators responsible for production Linux systems

### 1.4 Supported operating systems (initial release)
All three operating systems are first-class supported platforms from the initial release:
- Red Hat Enterprise Linux 9 (RHEL 9)
- Red Hat Enterprise Linux 10 (RHEL 10)
- Debian GNU/Linux 13 (Trixie)

Platform-specific functionality must be abstracted so that the core detection, integrity, correlation, database, alerting, and CLI functionality remains consistent. Differences in package management, file locations, audit tooling, security frameworks, and system integration are handled by platform adapters.

### 1.5 Scope of initial release
The initial release includes:
1. System inventory and file classification.
2. Cryptographic hashing and metadata collection.
3. Administrator-reviewed baseline creation and versioning.
4. File integrity monitoring and periodic reconciliation scans.
5. Process execution monitoring and process relationship context.
6. Configuration, account, service, and persistence monitoring.
7. Detection rules, event correlation, and severity assignment.
8. Local event and alert storage.
9. CLI status, scan, baseline, inventory, events, alerts, rules, configuration, verification, and report commands.
10. Systemd service, OS-specific packages, and installation/uninstallation procedures.
11. Sensor/service health and monitoring coverage reporting.

### 1.6 Out of scope for initial release
- Antivirus or malware signature scanning
- Automatic process termination, quarantine, remediation, or rollback
- Firewall management
- Network intrusion detection
- Vulnerability scanning
- Machine-learning-based detection
- Web UI or dashboard
- Central management server or fleet orchestration
- Mandatory cloud connectivity
- Automatic baseline approval

---

## 2. Design Principles

Soteria shall follow these principles:
- **Local-first:** Core monitoring, storage, and detection run on the monitored host.
- **Baseline-based trust:** Deviations from reviewed system state are detected, not silently trusted.
- **Event-driven:** Use supported event sources for prompt detection, supplemented by periodic scans.
- **Least privilege:** Components run with the minimum privileges required.
- **Tamper awareness:** Monitor Soteria's own files, configuration, service, and sensor health.
- **Explainable detections:** Alerts include a reason, evidence, and relevant rule.
- **Platform parity:** Supported OSes receive equivalent core capabilities, with limitations clearly reported.
- **Modular design:** OS integrations and sensors are separable from core processing.
- **No silent coverage failure:** Loss of monitoring or incomplete scans must be reported.

## 3. Functional Requirements

Priority definitions:
- **P0 — Critical:** Required for the initial release.
- **P1 — High:** Important for a production-ready release; may be staged after core P0 functionality.
- **P2 — Medium:** Planned enhancement.

### 3.1 Inventory and baseline

**FR-001 — File discovery (P0).** Soteria shall discover files in configurable locations, including system binaries, libraries, configuration, boot files, kernel modules, service definitions, scheduled tasks, security configuration, and other selected paths. Include paths and exclusions must be configurable.

**FR-002 — File classification (P0).** Soteria shall classify discovered objects where possible, including executable binary, shared library, script, kernel image, kernel module, configuration, service unit, scheduled job, security-sensitive file, symlink, and other.

**FR-003 — Cryptographic hashes (P0).** Soteria shall calculate SHA-256 hashes for eligible regular files. The design shall allow additional algorithms to be added in later releases.

**FR-004 — Metadata collection (P0).** For indexed objects, Soteria shall collect path, file type, hash, size, UID/GID, mode, timestamps (including modification and change time where available), inode, device, symlink target, file capabilities where available, SELinux context or other platform security label where available, first-seen time, and last-verified time.

**FR-005 — Baseline creation (P0).** Baseline creation shall be an explicit operation. Baseline records shall be versioned and timestamped, with approval provenance. Initial discovery alone shall not be represented as proof that the host is clean.

**FR-006 — Baseline protection (P0).** Baseline data shall have cryptographic integrity protection. The design shall consider key separation and shall document that local root compromise can undermine purely local protections.

**FR-007 — Baseline comparison (P0).** Soteria shall detect new, missing, content-modified, metadata-modified, permission-modified, owner/group-modified, capability-modified, security-label-modified, symlink-target-modified, and executable-status-modified objects.

**FR-008 — Baseline version history (P1).** Soteria shall retain baseline history and support comparison between baseline versions.

### 3.2 Execution monitoring

**FR-009 — Process execution events (P0).** Soteria shall monitor executable launches and record timestamp, executable path, hash when obtainable, PID, PPID, UID, effective UID, GID, process name, command-line arguments subject to privacy settings, working directory where obtainable, and source sensor.

**FR-010 — Execution classification (P0).** Execution shall be classified as trusted, known-modified, unknown, suspicious, or unverified, with rationale and limitations.

**FR-011 — Unusual execution locations (P0).** Soteria shall flag executions from temporary, shared-memory, user-writable, hidden, newly created, or otherwise configured unusual locations. Location alone shall not establish maliciousness.

**FR-012 — Parent-child relationships (P1).** Soteria shall track process lineage to support detection of suspicious execution chains, such as service-to-shell or interpreter execution of recently changed files.

**FR-013 — Execution history and search (P0).** Administrators shall be able to search execution history by executable, path, user, PID, time range, severity, and classification.

### 3.3 File integrity monitoring

**FR-014 — Filesystem event monitoring (P0).** Soteria shall detect monitored file creation, modification, deletion, rename, ownership, permission, and link changes using suitable supported mechanisms.

**FR-015 — Event verification (P0).** After a filesystem event, Soteria shall re-read and verify the affected object and compare it with the current approved baseline.

**FR-016 — Periodic reconciliation (P0).** Event monitoring shall be supplemented by scheduled scans to identify changes missed due to event-source limitations, downtime, or queue overflow.

**FR-017 — Coverage reporting (P0).** Soteria shall report inaccessible paths, files not hashed, unsupported filesystem conditions, exclusions, queue overflow, lost events, sensor downtime, and incomplete scans.

**FR-018 — Event correlation (P1).** Soteria shall associate related file, execution, identity, service, and persistence events into incidents where sufficient context exists.

### 3.4 Configuration and persistence monitoring

**FR-019 — Security configuration monitoring (P0).** Soteria shall monitor selected security-sensitive configuration files and locations, including SSH, PAM, sudoers, system-wide environment, systemd, cron, network, firewall, SELinux/AppArmor, account/group databases, package manager, bootloader, and audit configuration.

**FR-020 — Persistence mechanisms (P1).** Soteria shall monitor systemd services/timers, cron, startup scripts, shell startup files, SSH authorized keys, user-created services, boot configuration, privileged account creation, and sudo privilege changes.

**FR-021 — Sensitive-change severity (P0).** Changes to configurable security-sensitive objects shall generate alerts at appropriate severity.

### 3.5 Kernel and boot integrity

**FR-022 — Kernel inventory (P1).** Soteria shall record the running kernel, installed kernel packages/images, relevant modules, module activity where supported, and related configuration.

**FR-023 — Kernel comparison (P1).** Installed kernel and module inventory shall be compared against recorded state.

**FR-024 — Boot context (P1).** Soteria shall record boot time, kernel version, boot parameters, Secure Boot state where available, boot configuration changes, and related file changes.

### 3.6 User, privilege, and authentication monitoring

**FR-025 — Account monitoring (P1).** Soteria shall monitor user and group creation/deletion, membership, UID/GID changes, privileged group membership, sudo access, shell changes, and SSH key changes.

**FR-026 — Privilege monitoring (P1).** Soteria shall detect configured privileged activity and changes to setuid/setgid permissions, file capabilities, and privilege transitions.

**FR-027 — Authentication anomalies (P2).** Soteria may detect patterns from local authentication sources, including repeated failures, failure followed by success, unusual account activity, and authentication configuration changes. Availability and format of sources must be platform-aware.

### 3.7 Alerts and incidents

**FR-028 — Severity levels (P0).** Events and alerts shall use Critical, High, Medium, Low, and Info severity levels.

**FR-029 — Alert evidence (P0).** Alerts shall include unique ID, timestamp, severity, type, hostname, affected object/process, previous and current state where available, hashes, user context, detection rule, reason, and recommended investigation steps.

**FR-030 — Alert lifecycle (P0).** Administrators shall view, search, filter, acknowledge, mark investigated, add notes, suppress known benign detections, and export alerts. Acknowledgement shall not delete or alter original evidence.

**FR-031 — Notifications (P1).** Optional notifications shall support local terminal output, journald, email, and webhook. Core monitoring shall not depend on external services.

### 3.8 Scanning and reports

**FR-032 — Scheduled scans (P0).** Defaults shall be configurable: continuous event monitoring; critical-file verification every six hours; full inventory daily; kernel/boot review at startup and daily; baseline integrity verification at service startup. The defaults are proposed and must be performance-tested.

**FR-033 — Manual scans (P0).** Administrators shall initiate full, directory, file, baseline, and kernel/boot scans.

**FR-034 — Scan reports (P0).** Reports shall include scan ID, type, start/end time, duration, checked/skipped/error counts, changes detected, and result.

**FR-035 — Export formats (P1).** Export shall support JSON, text, and CSV. HTML/PDF may be considered later.

### 3.9 Self-protection and health

**FR-036 — Self-integrity monitoring (P0).** Soteria shall monitor its executable, configuration, service unit, helper components, database, and relevant logs.

**FR-037 — Service health (P0).** Soteria shall detect/report unexpected stop, disablement, configuration changes, sensor disablement, database tampering indicators, monitoring interruption, and health-check failures.

**FR-038 — Tamper-evident storage (P0).** Database and baseline integrity shall be checked. Soteria shall document that a local privileged attacker may tamper with locally stored information and shall support future remote forwarding.

**FR-039 — Health status (P0).** The service shall expose a local health status including sensor state, last event received, scan state, queue health, database health, coverage gaps, and overall monitoring status.

### 3.10 CLI and administration

**FR-040 — CLI (P0).** The CLI shall provide `status`, `init`, `scan`, `baseline`, `inventory`, `events`, `alerts`, `processes`, `rules`, `config`, `report`, and `verify` subcommands.

**FR-041 — Human-readable and JSON output (P0).** Commands shall provide readable text output and machine-readable JSON where applicable.

**FR-042 — Exit codes (P0).** CLI commands shall use documented exit codes suitable for scripts and automation.

**FR-043 — Configuration validation (P0).** Soteria shall validate configuration and clearly identify errors. Invalid settings must not silently disable protections.

**FR-044 — Baseline approval (P0).** Baseline updates shall require explicit administrator approval, be logged, retain prior versions, and identify the approving user. Changes shall never be silently accepted.

---

## 4. Non-Functional Requirements

### 4.1 Performance

- **NFR-001:** Average idle CPU target below 1% on a representative server.
- **NFR-002:** Normal memory target below 150 MB.
- **NFR-003:** Initial and full scans shall be configurable and avoid sustained excessive resource use.
- **NFR-004:** Event processing should normally complete within two seconds of event receipt, subject to load and sensor constraints.
- **NFR-005:** Monitoring should not materially degrade monitored workload performance.
- **NFR-006:** Event queues shall be bounded; overload shall be surfaced as a health/coverage alert.
- **NFR-007:** Incremental scanning shall be used where safe and practical.
- Targets shall be validated by repeatable benchmarks on supported systems.

### 4.2 Security
- **NFR-008:** Main daemon shall run under a dedicated non-login system user `soteria` wherever possible.
- **NFR-009:** The main daemon shall not run unrestricted as root by default.
- **NFR-010:** State, configuration, sockets, and database permissions shall be restrictive.
- **NFR-011:** Collection shall minimize sensitive data, especially command-line arguments, according to configurable privacy controls.
- **NFR-012:** Communication between privileged components and daemon shall be authenticated and access-controlled.
- **NFR-013:** Modern cryptographic algorithms shall be used.
- **NFR-014:** Untrusted data shall not be passed to shell execution.
- **NFR-015:** Package and update integrity shall be verified; update signing is a release requirement when update functionality is introduced.
- **NFR-016:** Service hardening and OS security policy shall be applied without breaking required monitoring.

### 4.3 Reliability
- Start automatically at boot.
- Recover after unexpected termination.
- Use transactional database operations.
- Record monitoring gaps and sensor failures.
- Recover or report interrupted scans.
- Detect database integrity issues.
- Avoid silent event loss.

### 4.4 Scalability
The first release targets a single host. Interfaces and data model should allow future central management of hundreds or thousands of hosts without redesigning the local agent. Fleet management is not part of initial release.

### 4.5 Usability
- Provide straightforward CLI commands and consistent options.
- Use readable output with color where appropriate; disable color when piped.
- Provide JSON output and documented exit codes.
- Give clear error messages and actionable alert explanations.
- Installation, upgrade, and removal must be documented.
- Users should not need to query the database directly for ordinary operations.

### 4.6 Maintainability
- Modular code and clear component boundaries.
- Versioned configuration and database schema.
- Automated unit, integration, and security tests.
- Documented sensor limitations and detection rules.
- Reproducible builds where practical.
- Detection rules should be separable from monitoring sensors.

### 4.7 Portability and platform parity
Core components shall remain portable across RHEL 9, RHEL 10, and Debian 13. OS-specific integrations shall be isolated behind adapters. Feature availability shall be detected at runtime, documented, and reported; unsupported functionality must not be silently represented as active.

---

## 5. System Architecture

### 5.1 High-level components
1. **CLI:** Administrative interface and output formatting.
2. **Core agent:** Service lifecycle, orchestration, event processing.
3. **Inventory engine:** File discovery, classification, metadata and hashing.
4. **Integrity engine:** Baseline creation, comparison, verification.
5. **Execution sensor:** Process launch telemetry and context.
6. **Filesystem sensor:** File change events.
7. **System sensors:** Account, service, persistence, kernel/boot and security context observations.
8. **Detection engine:** Rule evaluation and severity.
9. **Correlation engine:** Group related events into incidents.
10. **Alert manager:** Alert state and notification dispatch.
11. **Storage layer:** SQLite persistence, migrations, indexes and retention.
12. **Health monitor:** Sensor status, queue overflow, coverage and service health.
13. **Platform adapters:** OS-specific package, security, audit, and filesystem integrations.

### 5.2 Recommended technology stack
- **Language:** Rust
- **CLI framework:** Clap
- **Database:** SQLite
- **Hashing:** SHA-256 (initial), extensible
- **Service:** systemd
- **Logging:** journald, with optional local log files
- **Execution telemetry:** Linux Audit subsystem where available and appropriately configured
- **Filesystem monitoring:** Fanotify and/or inotify based on coverage, requirements, and permissions; periodic scans supplement event monitoring
- **Package integration:** RPM on RHEL; DEB on Debian
- **Security integration:** SELinux on RHEL; AppArmor where enabled on Debian; Linux capabilities and system security interfaces
- **Configuration:** TOML

Rust is selected for a long-running system security agent due to native performance, memory safety, concurrency support, and deployment as a native executable.

### 5.3 Platform abstraction
Platform adapters shall provide common interfaces for:
- OS and release identification
- Package inventory and package verification
- Audit sensor configuration and status
- Filesystem sensor capabilities
- Security labels and mandatory access control status
- Service and persistence discovery
- OS-specific path sets and defaults
- Package installation, upgrade, and removal integration

Core detections shall not directly depend on one distribution's package manager or directory conventions.

### 5.4 Privilege model
Preferred model:
- Main daemon runs as `soteria`, with no interactive login.
- Main daemon uses narrowly scoped capabilities or permitted interfaces when possible.
- Required privileged collection is isolated in a small, restricted component if unprivileged access is insufficient.
- Privileged helper uses a fixed, narrow interface; it must not allow arbitrary commands or unrestricted file writes.
- Communication uses protected local IPC (for example, a Unix domain socket) with peer identity checks and restrictive permissions.
- Exact privileges and helper design shall be determined through a capability analysis and validated on all target OSes.

Soteria must not claim full system monitoring solely because the daemon runs as its service user. Access limitations must be tested and displayed.

### 5.5 Monitoring strategy
Soteria shall combine:
1. Event-driven monitoring for timely detection.
2. Periodic integrity scans for reconciliation.
3. Sensor health checks and coverage accounting.
4. Startup and recovery scans when needed.
5. Event correlation and deduplication.

No single event API shall be treated as infallible. Event queue overflow, sensor downtime, unsupported mounts, or access errors shall produce explicit coverage-gap records and alerts.

### 5.6 Database
SQLite is the initial local database. It shall use transactions, schema versioning, indexes for common queries, retention settings, integrity checks, and export/backup support. WAL mode may be used after validating durability and access requirements.

Proposed tables:
- `files`: current inventory and file state.
- `baseline_versions`: baseline version metadata and approval provenance.
- `baseline_entries`: approved file states per baseline version.
- `events`: raw sensor and system events.
- `alerts`: detection findings and alert lifecycle.
- `processes`: execution records and process context.
- `rules`: rule definitions, versions, and enabled state.
- `scan_history`: scan results, counts, duration, and errors.
- `sensor_health`: sensor status and coverage gaps.
- `suppression_rules`: administrator-approved suppressions.

Database integrity controls are not a substitute for remote storage against a local root attacker.

---

## 6. CLI Interface Requirements

Primary executable: `soteria`

| Command | Purpose |
|---|---|
| `soteria status` | Protection and monitoring status |
| `soteria init` | Initial inventory and baseline workflow |
| `soteria scan` | Run integrity scans |
| `soteria baseline` | View, compare, approve, and manage baseline versions |
| `soteria inventory` | List indexed objects |
| `soteria events` | Search monitoring events |
| `soteria alerts` | Search and manage alerts |
| `soteria processes` | View execution history |
| `soteria rules` | List and inspect detection rules |
| `soteria config` | Display and validate configuration |
| `soteria report` | Generate reports |
| `soteria verify` | Verify service, database, baseline, sensors, and coverage |

All commands shall support help. JSON output should be supported for status, scan, inventory, events, alerts, processes, rules, verification, and reports where applicable. Exact option names and exit-code mapping shall be defined in the CLI design document.

### 6.1 Example status output (illustrative)
```text
SOTERIA HOST SECURITY
Host: rhel-prod-01 | OS: RHEL 9
Protection: ACTIVE | Baseline: ESTABLISHED
Integrity: VERIFIED | Monitoring: ACTIVE
Indexed files: 48,291
Open alerts: 3 (1 High, 2 Medium)\nLast full scan: 2026-11-21 14:02:15
Last integrity verification: 2026-11-21 14:48:10
Coverage: 98.7% (2 gaps; see `soteria verify`)
```

### 6.2 Example alert output (illustrative)
```text
Alert: 10042 | Severity: HIGH | Status: OPEN
Type: File integrity violation
Path: /usr/bin/example
Baseline SHA-256: <digest>
Current SHA-256: <digest>
Reason: File content differs from approved baseline.
Investigation: Verify package provenance, review change history,
and determine whether this change was authorized.
```

---

## 7. Configuration

Configuration file: `/etc/soteria/soteria.toml` (canonical path; distribution-specific packaging shall not change it).

Example:
```toml
[general]
log_level = "info"
database = "/var/lib/soteria/soteria.db"
event_retention_days = 90

[monitoring]
execution = true
file_integrity = true
configuration = true
kernel = true
persistence = true
users = true

[scanning]
full_scan_interval = "24h"
critical_scan_interval = "6h"
startup_scan = true

[paths]
include = [
  "/etc", "/usr/bin", "/usr/sbin", "/usr/lib", "/usr/lib64",
  "/boot", "/bin", "/sbin", "/lib", "/lib64", "/usr/local/bin",
  "/usr/local/sbin"
]
exclude = ["/proc", "/sys", "/dev", "/run"]

[alerts]
minimum_severity = "low"
journal = true
email = false
webhook = false
```

Configuration shall be validated on startup and via CLI. Invalid configuration shall produce a clear error and shall not silently turn off monitoring. Paths and monitoring capabilities must be platform-aware; non-existent paths are not necessarily errors but shall be handled and reported appropriately.

---

## 8. Filesystem Layout and Service Account

### 8.1 Proposed filesystem layout
| Path | Purpose |
|---|---|
| `/usr/bin/soteria` | CLI and daemon executable (if single-binary design is used) |
| `/usr/libexec/soteria/` | Restricted helper, if required |
| `/etc/soteria/` | Configuration and administrator rules |
| `/var/lib/soteria/` | Database and persistent state |
| `/var/log/soteria/` | Optional dedicated logs; journald preferred initially |
| `/run/soteria/` | Runtime sockets and temporary state |
| `/usr/lib/systemd/system/soteria.service` | Systemd unit (package-managed) |

### 8.2 Service identity
- User: `soteria`
- Group: `soteria`
- Login shell: `/usr/sbin/nologin` or platform-equivalent
- No interactive login and no unnecessary home directory
- Main executable and configuration owned by root and not writable by the daemon account
- State directory owned by `soteria`, with restrictive permissions

### 8.3 Service management
Soteria shall be installed and managed as `soteria.service`. It shall start at boot, restart on unexpected failure, shut down cleanly, and expose service health. Systemd hardening settings shall be applied and tested against required monitoring interfaces. The service must not be hardened with settings that accidentally disable necessary sensors without reporting the resulting coverage loss.

---

## 9. Packaging and OS Integration

### 9.1 RHEL 9 and RHEL 10
- RPM packaging
- DNF integration for package inventory and provenance checks
- SELinux integration and policy support
- Systemd integration
- Linux Audit integration
- Validate dependencies and path conventions separately for RHEL 9 and RHEL 10

### 9.2 Debian 13
- DEB packaging
- APT/dpkg integration for package inventory and provenance checks
- AppArmor awareness where enabled; support security labels and report framework state
- Systemd integration
- Linux Audit integration
- Validate Debian-specific dependencies, paths, and defaults

### 9.3 Cross-platform parity
All supported platforms must pass common acceptance tests. Platform-specific features may differ only where unavoidable, and every difference must be documented and surfaced in `soteria status` or `soteria verify`.

---

## 10. Security and Threat Model

### 10.1 Threats addressed
- Unauthorized system binary replacement or modification
- Unexpected executable/script installation and execution
- Security configuration tampering
- Unauthorized service or timer creation
- Persistence via cron, systemd, startup files, or SSH keys
- Account and privilege changes
- Suspicious privilege transitions
- Kernel, module, or boot configuration changes (within supported visibility)
- Monitoring disablement, service interruption, or event loss

### 10.2 Limitations
- A local attacker with unrestricted root or kernel compromise may evade, disable, or falsify local monitoring.
- Hash differences do not inherently prove malware.
- Legitimate maintenance may trigger alerts.
- Filesystem and audit sensors have platform and configuration limitations.
- Some files or events may be inaccessible due to permissions, mount options, namespaces, or sensor constraints.
- Soteria is a detection system and does not guarantee system safety.

### 10.3 Baseline lifecycle
1. Discover host and files.
2. Collect hashes, metadata, packages, and security context.
3. Present baseline review and coverage information.
4. Administrator explicitly approves baseline.
5. Seal baseline version with cryptographic integrity protection.
6. Monitor and compare continuously.
7. Investigate deviations.
8. Explicitly approve authorized changes into a new baseline version.

Baseline updates shall never be automatic. Previous baseline versions shall remain available for comparison and audit. Approval must record the approving identity and time.

---

## 11. Installation, Upgrade, and Removal

### 11.1 Installation
Install packages shall:
- Create the system account/group if absent.
- Install executable(s), configuration defaults, service unit, and platform policy files.
- Create state/runtime directories with appropriate ownership and permissions.
- Avoid overwriting administrator configuration.
- Check dependencies and report available monitoring capabilities.
- Enable service only according to documented installation policy; baseline initialization remains explicit.

### 11.2 Initialization
The administrator shall run an explicit initialization workflow (for example, `sudo soteria init`) to verify prerequisites, detect platform capabilities, create the database, inventory the system, prepare the baseline, report coverage, and obtain explicit baseline approval.

### 11.3 Upgrade
Upgrades shall preserve configuration, baselines and baseline history, alert/event history within retention policy, and administrator rules/suppressions. Database migrations shall be versioned, transactional where practical, and recoverable.

### 11.4 Uninstallation
Uninstallation shall remove package-managed software and service files. Persistent security data shall not be silently deleted. Removal shall provide a documented, deliberate option for retaining or deleting configuration, database, baseline, events, and logs.

---

## 12. Testing and Verification

### 12.1 Unit tests
Test hashing, file classification, metadata collection, baseline comparison, rule evaluation, severity, configuration validation, serialization, and storage operations.

### 12.2 Integration tests
Test initial inventory, baseline creation, file creation/modification/deletion, metadata changes, execution detection, process context, alert generation, persistence, service startup/shutdown, event queue recovery, and interrupted scan handling.

### 12.3 Security tests
Test baseline/database tampering indicators, service disablement, sensor interference, unauthorized configuration changes, permission boundaries, privilege transitions, corrupt database, event queue overflow, and access restrictions.

### 12.4 Performance tests
Benchmark on each supported OS using representative small and large inventories, high process-launch rates, heavy file activity, concurrent scans, and log volume. Measure CPU, memory, scan duration, event latency, queue growth, and dropped-event handling.

### 12.5 Platform test matrix
Every release candidate must be tested on:
- RHEL 9
- RHEL 10
- Debian 13

Common functionality must pass on all three. Platform-specific deviations and unavailable sensors shall be recorded in test reports.

---

## 13. Acceptance Criteria for Initial Release

The initial release is acceptable when:
- Inventory can discover and index configured system files on all supported OSes.
- SHA-256 hashes and required metadata are stored in the local database.
- Baseline creation requires explicit review and approval.
- Baseline integrity is verifiable.
- File creation, modification, deletion, and relevant metadata changes are detected.
- Execution telemetry is collected with executable path, PID, PPID, and user context when available.
- Unknown and modified executions can be classified and alerted.
- Monitoring coverage and sensor failures are reported.
- Alerts include evidence, rationale, severity, and investigation guidance.
- CLI status, scan, baseline, inventory, events, alerts, verify, and JSON output work as documented.
- Service starts at boot and recovers from unexpected termination.
- Main daemon runs as dedicated `soteria` user wherever possible; required privilege exceptions are documented and constrained.
- RPM packages install/upgrade/remove correctly on RHEL 9 and RHEL 10.
- DEB package installs/upgrades/removes correctly on Debian 13.
- Unit, integration, and security tests pass on the support matrix.
- Performance targets are benchmarked and results documented.
- Documentation covers install, initialize, baseline approval, alert investigation, upgrade, and uninstall.

---

## 14. Development Roadmap

### Phase 1 — Foundation
Project structure, Rust toolchain, CLI, configuration, platform detection, systemd service, SQLite schema and migrations.

### Phase 2 — Inventory and Baseline
File discovery, classification, metadata, hashing, baseline creation, approval, versioning, and integrity protection.

### Phase 3 — Integrity Monitoring
Filesystem sensors, event verification, reconciliation scans, coverage accounting, and integrity alerts.

### Phase 4 — Execution Monitoring
Audit integration, execution records, executable classification, process context, and suspicious-location rules.

### Phase 5 — Detection and Incident Handling
Rules engine, severity, event correlation, alert lifecycle, suppression, retention, and exports.

### Phase 6 — System Monitoring and Hardening
Configuration/persistence/account monitoring, self-integrity, sensor health, privilege separation, SELinux/AppArmor integration, and systemd hardening.

### Phase 7 — Packaging and Release
RPM for RHEL 9/10, DEB for Debian 13, cross-platform testing, benchmarks, documentation, and v1 release.

### Future Phase — Central Management
Optional remote event forwarding, multi-host management, fleet baselines, central alerting, and web interface.

---

## 15. Initial Design Decisions

| Decision | Initial selection |
|---|---|
| Product type | Linux host intrusion detection and integrity monitor |
| Initial OS support | RHEL 9, RHEL 10, Debian 13 |
| Language | Rust |
| CLI | Clap-based command line |
| Database | SQLite |
| Hash | SHA-256 |
| Service manager | Systemd |
| Execution sensor | Linux Audit, subject to platform capability validation |
| Filesystem sensor | Fanotify and/or inotify, with periodic reconciliation scans |
| Packaging | RPM (RHEL), DEB (Debian) |
| Configuration | TOML |
| Logging | Journald initially |
| Security model | Least privilege; dedicated `soteria` user; restricted privileged helper only if required |
| Detection | Rules-based and explainable |
| Baseline | Versioned, integrity-protected, explicitly approved |
| Response | Alert and evidence only; no automatic remediation in v1 |
| Connectivity | No cloud or internet dependency |

---

## 16. Long-Term Vision

Soteria aims to become a trustworthy Linux host security guardian that provides administrators with a continuously updated view of system integrity and behavior. Its value is the combination of knowing what is installed, what changed, what executed, who executed it, how it started, what it affected, and whether monitoring itself remains healthy.

The long-term question Soteria should help answer is:


> **Can I trust the current state of this server—and if not, what changed, what happened, and why should I be concerned?**

---

## 17. Glossary

| Term | Definition |
|---|---|
| HIDS | Host-based intrusion detection system |
| Baseline | Administrator-approved reference state used for comparison |
| Integrity monitoring | Detection of changes to files or system state |
| Sensor | Component that collects monitoring data |
| Event | Raw observation from a sensor or system source |
| Alert | Detection finding generated from one or more events |
| Incident | Grouped related alerts/events for investigation |
| Coverage gap | Condition where monitoring is incomplete, unavailable, or unable to verify an object |
| Platform adapter | OS-specific integration isolated from the core application |
| Persistence | Mechanism that causes software or access to remain after reboot or session changes |
| PPID | Parent process identifier |
| SELinux | Linux mandatory access control system commonly used on RHEL |
| AppArmor | Linux application access-control framework available on Debian and other distributions |

---

**End of Soteria SRS v1.0 Draft**
