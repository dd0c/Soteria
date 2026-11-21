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
| `soteria status` | Host, OS support level, protection state, baseline and seal state, agent liveness, counts, coverage gaps. |
| `soteria init [--yes \| --non-interactive]` | Prerequisites, platform capabilities, database, signing key, full inventory, draft baseline with review, and approval. Without a terminal or `--yes` the draft is kept for later approval. |
| `soteria scan [--full \| --dir PATH \| --file PATH \| --baseline]` | Inventory scans. `--baseline` first verifies the approved baseline's seal, then rescans and lists every deviation with a severity. `--kernel` arrives with milestone 6. |
| `soteria inventory [--kind K] [--path P] [--sha256 H] [--limit N]` | Lists indexed objects. |
| `soteria baseline list\|show\|create\|review\|approve\|diff` | Baseline lifecycle; see below. |
| `soteria config show\|validate\|default` | Configuration. |
| `soteria verify [--component config,platform,database,baseline,service,sensors]` | Runs every check and lists each result. Checks that belong to later milestones are listed as `SKIP` with the reason. |
| `soteria daemon` | Started by `soteria.service`. Verifies the baseline seal at startup. |
| `soteria events` | Milestone 3. Exit 7 until then. |
| `soteria processes` | Milestone 4. Exit 7 until then. |
| `soteria alerts`, `rules`, `report` | Milestone 5. Exit 7 until then. |

## Baselines

A baseline is the administrator-approved state of the host (SRS 10.3).

1. `soteria baseline create [--note TEXT]` snapshots the current inventory
   into a draft and shows a review: object counts by kind, open coverage gaps
   and differences from the approved baseline. There is at most one draft;
   creating another replaces it.
2. `soteria baseline review [VERSION]` shows the same review again.
3. `sudo soteria baseline approve VERSION [--yes]` asks for confirmation
   (or takes `--yes`), then seals the draft: a SHA-256 digest over the host
   ID, the version header (including who approved it and when) and every
   entry is signed with the Ed25519 key in `[baseline] signing_key`. The
   previous approved version becomes `superseded` and stays available.
   Approval requires root because only root can read the signing key.
4. `soteria baseline show [VERSION]` displays a version and verifies its seal.
5. `soteria baseline diff FROM [TO]` compares two versions, or a version with
   the current inventory.

Detected change types (FR-007): `new`, `missing`, `type_changed`,
`content_modified`, `permission_modified`, `owner_modified`,
`capability_modified`, `security_label_modified`, `symlink_target_modified`,
`executable_status_modified` and `metadata_modified` (size, mtime, inode or
device changed with nothing else; reported at `info`). A change of ctime
alone is not reported. Gaining a setuid or setgid bit is `critical`; content
changes to binaries, libraries, kernel files and security-sensitive files are
`high`.

## Agent liveness

The daemon records start and stop in the database and refreshes a heartbeat
every 15 seconds. `status` and `verify` report:

- `running`: heartbeat within the last 90 seconds.
- `not_responding`: last recorded state is running but the heartbeat is stale,
  meaning the daemon died without a clean shutdown. `verify` fails (exit 4).
- `stopped`: the daemon shut down cleanly.
- `never_started`.
