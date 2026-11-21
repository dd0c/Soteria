# Soteria implementation plan

This plan maps SOTERIA_SRS_v1.0.md onto a Rust codebase and a sequence of
milestones. Each milestone lands as its own pull request so it can be reviewed
on its own. Requirement IDs (FR-xxx, NFR-xxx) refer to the SRS.

## Workspace layout

A Cargo workspace with one crate per SRS component (SRS 5.1). Core crates have
no dependency on a specific distribution; everything OS-specific sits behind the
traits in `soteria-platform` (SRS 5.3, 4.7).

| Crate | SRS component | Responsibility |
|---|---|---|
| `soteria-core` | shared | Domain types: severity, file kinds, file state, events, alerts, IDs, exit codes, common errors |
| `soteria-config` | config | TOML loading, defaults, validation with precise error locations (FR-043) |
| `soteria-platform` | platform adapters | OS/release detection, RHEL/Debian adapters, package inventory/verification, MAC status, security labels, default path sets |
| `soteria-store` | storage layer | SQLite schema, versioned transactional migrations, repositories, retention, integrity checks (5.6) |
| `soteria-inventory` | inventory engine | Discovery, classification, metadata, SHA-256 hashing (FR-001..004) |
| `soteria-integrity` | integrity engine | Baseline build, review, approval, sealing, verification, comparison, version history (FR-005..008, FR-044) |
| `soteria-sensors` | filesystem, execution, system sensors | fanotify/inotify, Linux Audit execution sensor, account/service/persistence/kernel/boot observers |
| `soteria-detect` | detection + correlation | Rule engine, severity, execution classification, correlation into incidents |
| `soteria-agent` | core agent, alert manager, health monitor | Daemon lifecycle, bounded queues, scheduler, alert lifecycle, notifications, health status, local IPC |
| `soteria` (bin) | CLI | Clap CLI, text/JSON output, exit codes; `soteria daemon` runs the agent |

Crates are added when their milestone starts; milestone 1 creates `core`,
`config`, `platform`, `store` and the `soteria` binary (in `crates/soteria-cli`).

Single binary: `/usr/bin/soteria` is both CLI and daemon (`soteria daemon`,
started by `soteria.service`), as SRS 8.1 allows. A small privileged helper in
`/usr/libexec/soteria/` is added in M6 only for collection the `soteria` user
cannot do.

## Milestones

| # | Milestone | SRS phase | Main requirements | Deliverable |
|---|---|---|---|---|
| M1 | Foundation | 1 | FR-040..043, 5.6, 8.3, 4.6 | Workspace, CLI with all 12 subcommands (help, `--json`, exit codes), config load/validate, platform detection, SQLite schema v1 with migrations, systemd unit, CI (fmt, clippy, tests) |
| M2 | Inventory and baseline | 2 | FR-001..008, FR-033/034, FR-044, 10.3 | Discovery, classification, metadata (caps, SELinux/AppArmor labels), SHA-256, `init`, `inventory`, `scan`, `baseline create/review/approve/diff/list`, sealed baselines, `verify baseline` |
| M3 | Integrity monitoring | 3 | FR-014..017, FR-032, FR-036..039, NFR-006 | Daemon, fanotify with inotify fallback, bounded queues, event re-verification, scheduled reconciliation, coverage gaps, integrity alerts, `status`, health |
| M4 | Execution monitoring | 4 | FR-009..013 | Audit netlink execution sensor, process records, classification, unusual-location detection, lineage, `processes` search |
| M5 | Detection and incidents | 5 | FR-018, FR-021, FR-028..031, FR-035 | TOML rule engine, severity, correlation, alert lifecycle (ack, investigated, notes, suppress), retention, JSON/CSV/text export, journald/email/webhook notifications |
| M6 | System monitoring and hardening | 6 | FR-019/020, FR-022..027, NFR-008..016 | Config, persistence, account, kernel/boot monitoring, self-integrity, privileged helper with authenticated IPC, SELinux policy module, AppArmor profile, systemd hardening |
| M7 | Packaging and release | 7 | 9, 11, 12, 13 | RPM (RHEL 9/10), DEB (Debian 13), install/upgrade/remove scripts, container-based test matrix, benchmarks, admin documentation |

## Key design choices (proposed)

- **Database:** `rusqlite` with bundled SQLite, so behaviour is identical on all
  three distributions. Schema version tracked in `PRAGMA user_version`; each
  migration runs in one transaction.
- **Baseline sealing (FR-006), decided:** each baseline version is serialized
  canonically, hashed with SHA-256, and signed with an Ed25519 key that only
  root can read (`/etc/soteria/keys/baseline.key`, `root:root 0600`).
  Approval (`sudo soteria baseline approve`) signs; the daemon holds only the
  public key and verifies. A compromised `soteria` account therefore cannot
  forge a baseline, though local root still can (SRS 10.2).
- **Execution sensor (FR-009):** subscribe to the kernel audit multicast group
  over netlink (`CAP_AUDIT_READ`). This coexists with `auditd` instead of
  replacing it, and needs no log parsing.
- **Filesystem sensor (FR-014):** fanotify with `FAN_REPORT_FID`-style
  directory events where the kernel and privileges allow it, inotify otherwise.
  Whichever is active is reported in `status`/`verify`, and queue overflow
  becomes a coverage gap plus a forced reconciliation scan.
- **Rules (FR-021, 4.6):** built-in rules ship in the binary; administrator
  rules live in `/etc/soteria/rules.d/*.toml`, separate from sensors.
- **Exit codes (FR-042):** `0` OK, `1` findings present (alerts/changes),
  `2` usage error, `3` configuration invalid, `4` integrity verification
  failed, `5` not initialized, `6` permission denied, `7` unavailable on this
  platform or build, `10` internal error. See [CLI.md](CLI.md).
- **Privilege (5.4):** daemon runs as `soteria` with
  `AmbientCapabilities=CAP_DAC_READ_SEARCH CAP_AUDIT_READ`; anything more
  (fanotify needs `CAP_SYS_ADMIN`) goes through the M6 helper. Until then,
  missing capabilities are reported as coverage gaps, not hidden.

## Additions and interpretations of the SRS

1. SRS 6.1 sample output contains a literal `\n` between "Open alerts" and
   "Last full scan"; treated as a typo.
2. Configuration gains a top-level `version = 1` (SRS 4.6, versioned
   configuration) and `scanning.kernel_scan_interval` (FR-032 asks for a
   daily kernel/boot review but the SRS 7 example has no key for it).
3. Schema adds `meta`, `schema_migrations`, `incidents`, `alert_history` and
   `coverage_gaps` to the tables proposed in SRS 5.6.
4. `soteria verify` also checks that the agent is alive, using a heartbeat
   the daemon writes to the database.
