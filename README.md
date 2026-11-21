# Soteria
Soteria - The greek goddess of safety, salvation, and preservation from harm.

Soteria is a Linux host-based intrusion detection and integrity monitoring
system (HIDS) for RHEL 9, RHEL 10 and Debian 13, written in Rust. It keeps an
administrator-approved, signed baseline of system state, watches file changes
and program execution, and reports deviations and monitoring gaps locally.

- Website and installation guide: https://soteria.akuadora.net (source in [site/](site/))
- Administration guide: [docs/ADMIN.md](docs/ADMIN.md)
- Requirements: [SOTERIA_SRS_v1.0.md](SOTERIA_SRS_v1.0.md)
- Implementation plan and milestones: [docs/IMPLEMENTATION_PLAN.md](docs/IMPLEMENTATION_PLAN.md)
- CLI reference and exit codes: [docs/CLI.md](docs/CLI.md)
- Detection rules and rule files: [docs/RULES.md](docs/RULES.md)
- Benchmarks: [docs/BENCHMARKS.md](docs/BENCHMARKS.md)

## Status

All seven milestones are in place: CLI, configuration validation, platform
detection, SQLite storage, the daemon and systemd unit, file inventory
(classification, metadata, SHA-256), signed baselines and baseline
comparison, live file integrity monitoring with scheduled reconciliation,
execution monitoring through the kernel audit stream (classification,
unusual locations, lineage, search), and detection handling: configurable
rules, alert lifecycle and suppression, incidents, retention, exports,
reports, and email and webhook notifications, persistence, account,
kernel and boot monitoring, self-integrity, and SELinux and AppArmor
confinement (`packaging/selinux`, `packaging/apparmor`). Releases ship RPM
packages for RHEL 9 and 10 and a DEB package for Debian 13
(`packaging/rpm`, `packaging/deb`), tested for install, upgrade and removal
in CI.

To install on a server, follow [docs/ADMIN.md](docs/ADMIN.md).

Execution monitoring needs auditd and the rules file
`packaging/audit/soteria.rules` (see [docs/CLI.md](docs/CLI.md#execution-monitoring)).

## Building

```sh
cargo build --release
cargo test --workspace
```

The binary is `target/release/soteria`. SQLite is bundled, so the only build
requirement besides Rust is a C compiler.

## Trying it without installing

```sh
soteria config default \
  | sed 's#/var/lib/soteria#/tmp/soteria#; s#/etc/soteria/keys#/tmp/soteria/keys#' > /tmp/soteria.toml
export SOTERIA_CONFIG=/tmp/soteria.toml
sudo -E soteria init          # inventories, then asks you to approve the baseline
soteria status
sudo -E soteria scan --baseline   # rescan and list deviations from the baseline
sudo cp packaging/audit/soteria.rules /etc/audit/rules.d/ && sudo augenrules --load
sudo -E soteria daemon &          # live monitoring in the foreground
soteria alerts list; soteria events --since 10m; soteria processes --since 10m
soteria alerts incidents; soteria report summary
sudo -E soteria scan --kernel     # kernel, boot parameters, Secure Boot, modules
```

## Layout

| Path | Purpose |
|---|---|
| `crates/soteria-core` | Shared types: severity, file kinds, exit codes |
| `crates/soteria-config` | TOML configuration loading and validation |
| `crates/soteria-platform` | OS detection and RHEL/Debian adapters |
| `crates/soteria-store` | SQLite schema, migrations and storage |
| `crates/soteria-inventory` | File discovery, classification, metadata and hashing |
| `crates/soteria-integrity` | Scans, signed baselines and comparison |
| `crates/soteria-sensors` | Event sensors: inotify filesystem sensor, kernel audit execution sensor |
| `crates/soteria-rules` | Detection rule catalogue, overrides and administrator rules |
| `crates/soteria-notify` | Email (SMTP over TLS) and HTTPS webhook delivery |
| `crates/soteria-agent` | Monitoring agent: event verification, alerts, scheduled scans, health |
| `crates/soteria-cli` | The `soteria` binary (CLI and daemon) |
| `packaging/config/soteria.toml` | Default `/etc/soteria/soteria.toml` |
| `packaging/systemd/soteria.service` | Hardened systemd unit |
| `packaging/audit/soteria.rules` | auditd rule that reports program executions |
| `packaging/selinux/` | SELinux policy module (`make -f /usr/share/selinux/devel/Makefile soteria.pp && semodule -i soteria.pp && restorecon -R /usr/bin/soteria /etc/soteria /var/lib/soteria`) |
| `packaging/apparmor/usr.bin.soteria` | AppArmor profile (`apparmor_parser -r`) |
| `packaging/rpm/`, `packaging/deb/` | RPM spec and DEB build script (`build.sh <binary> <outdir>`) |
| `packaging/sysusers/soteria.conf` | The `soteria` system account |
| `packaging/test/install-test.sh` | Install, upgrade and removal test, run in disposable containers |
| `site/` | Static website for soteria.akuadora.net |

## Security limitations

Soteria protects its database and baselines against accidental change and
against a compromised service account: alert evidence and sealed baselines
are immutable in the schema, and baselines are signed with a key only root
can read. A local attacker with unrestricted root or kernel access can still
evade, disable or falsify local monitoring (SRS 10.2). Forwarding events to a
remote system is the planned mitigation.

## License

GPL-3.0-or-later. See [LICENSE](LICENSE).
