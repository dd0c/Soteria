# Soteria CLI reference

Primary executable: `soteria` (SRS 6). Every command supports `--help`.

## Global options

| Option | Meaning |
|---|---|
| `--config PATH` | Configuration file. Default `/etc/soteria/soteria.toml`; also read from `SOTERIA_CONFIG`. |
| `--json` | Machine-readable JSON on stdout. Errors are also JSON (`{"status":"error","exit_code":N,"kind":...,"message":...}`). |
| `--color auto\|always\|never` | Colors in text output. `auto` colors only on a terminal and honours `NO_COLOR`. |

## Exit codes (FR-042)

These values are a stable interface for scripts.

| Code | Name | Meaning |
|---|---|---|
| 0 | `ok` | Success, nothing needs attention |
| 1 | `findings` | Success, findings reported: changes, open alerts, warnings or coverage gaps |
| 2 | `usage` | Invalid command-line usage |
| 3 | `config_invalid` | Configuration missing or invalid |
| 4 | `integrity_failure` | Database, baseline or self-integrity verification failed, or the agent stopped responding |
| 5 | `not_initialized` | Soteria is not initialized on this host (`soteria init` has not run) |
| 6 | `permission_denied` | Insufficient privileges (for example, reading the database without sudo) |
| 7 | `unavailable` | Feature unavailable on this platform or in this build |
| 10 | `internal` | Internal error |

When a command performs several checks, it exits with the most serious
result: internal > integrity failure > config invalid > permission denied >
usage > not initialized > unavailable > findings > ok.

## Commands

| Command | Status in this build |
|---|---|
| `soteria status` | Available. Host, OS support level, protection state, baseline, agent liveness, counts, coverage gaps. |
| `soteria init` | Available: prerequisites, platform capabilities, database creation and migration. Inventory and baseline approval arrive in milestone 2. |
| `soteria config show\|validate\|default` | Available. |
| `soteria verify [--component config,platform,database,baseline,service,sensors]` | Available. Checks belonging to later milestones are listed as `SKIP` with the reason. |
| `soteria daemon` | Available; started by `soteria.service`. |
| `soteria scan`, `baseline`, `inventory` | Milestone 2. Exit 7 until then. |
| `soteria events` | Milestone 3. Exit 7 until then. |
| `soteria processes` | Milestone 4. Exit 7 until then. |
| `soteria alerts`, `rules`, `report` | Milestone 5. Exit 7 until then. |

## Agent liveness

The daemon records start and stop in the database and refreshes a heartbeat
every 15 seconds. `status` and `verify` report:

- `running`: heartbeat within the last 90 seconds.
- `not_responding`: last recorded state is running but the heartbeat is stale,
  meaning the daemon died without a clean shutdown. `verify` fails (exit 4).
- `stopped`: the daemon shut down cleanly.
- `never_started`.
