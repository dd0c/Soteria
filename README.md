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

Milestone 1 (foundation) is in place: CLI, configuration validation, platform
detection, SQLite schema and migrations, the daemon lifecycle and the systemd
unit. Monitoring features arrive in the following milestones; commands that
are not available yet say so and exit with code 7.

## Building

```sh
cargo build --release
cargo test --workspace
```

The binary is `target/release/soteria`. SQLite is bundled, so the only build
requirement besides Rust is a C compiler.

## Trying it without installing

```sh
soteria config default | sed 's#/var/lib/soteria#/tmp/soteria#' > /tmp/soteria.toml
export SOTERIA_CONFIG=/tmp/soteria.toml
soteria init
soteria status
soteria verify
```

## Layout

| Path | Purpose |
|---|---|
| `crates/soteria-core` | Shared types: severity, file kinds, exit codes |
| `crates/soteria-config` | TOML configuration loading and validation |
| `crates/soteria-platform` | OS detection and RHEL/Debian adapters |
| `crates/soteria-store` | SQLite schema, migrations and storage |
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
