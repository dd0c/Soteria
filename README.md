# Soteria
Soteria - The greek goddess of safety, salvation, and preservation from harm.

Soteria is a Linux host-based intrusion detection and integrity monitoring
system (HIDS) for RHEL 9, RHEL 10 and Debian 13, written in Rust. It keeps an
administrator-approved, signed baseline of system state, watches file changes
and program execution, and reports deviations and monitoring gaps locally.

- Requirements: [SOTERIA_SRS_v1.0.md](SOTERIA_SRS_v1.0.md)
- Implementation plan and milestones: [docs/IMPLEMENTATION_PLAN.md](docs/IMPLEMENTATION_PLAN.md)
- CLI reference and exit codes: [docs/CLI.md](docs/CLI.md)

## Status

Milestones 1 and 2 are in place: CLI, configuration validation, platform
detection, SQLite storage, the daemon lifecycle and systemd unit, plus file
inventory (classification, metadata, SHA-256), signed baselines and baseline
comparison. Continuous monitoring arrives in the following milestones;
commands that are not available yet say so and exit with code 7.

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
| `crates/soteria-cli` | The `soteria` binary (CLI and daemon) |
| `packaging/config/soteria.toml` | Default `/etc/soteria/soteria.toml` |
| `packaging/systemd/soteria.service` | Hardened systemd unit |

## Security limitations

Soteria protects its database and baselines against accidental change and
against a compromised service account: alert evidence and sealed baselines
are immutable in the schema, and baselines are signed with a key only root
can read. A local attacker with unrestricted root or kernel access can still
evade, disable or falsify local monitoring (SRS 10.2). Forwarding events to a
remote system is the planned mitigation.

## License

GPL-3.0-or-later. See [LICENSE](LICENSE).
