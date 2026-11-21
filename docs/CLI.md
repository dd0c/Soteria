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
| `soteria status` | Host, OS support level, protection state, baseline and seal state, agent liveness, sensor states, counts, last event, coverage gaps. |
| `soteria init [--yes \| --non-interactive]` | Prerequisites, platform capabilities, database, signing key, full inventory, draft baseline with review, and approval. Without a terminal or `--yes` the draft is kept for later approval. |
| `soteria scan [--full \| --dir PATH \| --file PATH \| --baseline]` | Inventory scans. `--baseline` first verifies the approved baseline's seal, then rescans and lists every deviation with a severity. `--kernel` arrives with milestone 6. |
| `soteria inventory [--kind K] [--path P] [--sha256 H] [--limit N]` | Lists indexed objects. |
| `soteria baseline list\|show\|create\|review\|approve\|diff` | Baseline lifecycle; see below. |
| `soteria config show\|validate\|default` | Configuration. |
| `soteria verify [--component config,platform,database,baseline,service,sensors]` | Runs every check and lists each result. Checks that belong to later milestones are listed as `SKIP` with the reason. |
| `soteria daemon` | Started by `soteria.service`. Runs live monitoring; see below. |
| `soteria events [--since T] [--until T] [--type TYPE] [--severity S] [--limit N]` | Event history, oldest first (the newest `N` when more match). `T` is an RFC 3339 time or an age such as `30m` or `2h`. `--type file` matches `file.created`, `file.modified` and `file.deleted`. `--severity S` means `S` and above. |
| `soteria alerts list [--since T] [--until T] [--severity S] [--status S] [--limit N]` | Alerts, newest first. |
| `soteria alerts show ID` | One alert with its evidence (approved and current state, change kinds, source), recommendation and history. |
| `soteria alerts ack\|investigate\|note\|suppress\|export` | Milestone 5. Exit 7 until then. |
| `soteria processes` | Milestone 4. Exit 7 until then. |
| `soteria rules`, `report` | Milestone 5. Exit 7 until then. |

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

## Live monitoring

`soteria daemon` (normally `soteria.service`) does the following:

- **Startup.** Verifies the approved baseline's seal. A baseline that fails
  verification is not used for comparison and raises critical alert
  `INT-001`; the agent keeps running and reporting.
- **Filesystem events (FR-014, FR-015).** Watches every directory under
  `[paths] include` with inotify, including directories created later. Each
  changed path is re-read once its events have settled (250 ms, at most
  1.5 s after the first event), the inventory is updated, a `file.*` event is
  recorded, and any difference from the approved baseline raises an alert.
- **Lost events (FR-017, NFR-006).** The event queue is bounded. If it fills,
  or the kernel's inotify queue overflows, the loss opens an `overflow`
  coverage gap and forces a full reconciliation scan, which closes the gap.
  Directories that cannot be watched (for example when
  `fs.inotify.max_user_watches` is too low) are listed as `unwatched` gaps.
- **Reconciliation (FR-016).** A full rescan at startup (unless
  `scanning.startup_scan = false`) and every `scanning.full_scan_interval`
  compares everything with the baseline, so changes made while the agent
  was stopped, or that no event reported, are still found. Scans record
  `file.*` events (sensor `scanner`) for the changes they find.
- **Critical files (FR-032).** Every `scanning.critical_scan_interval`, the
  baselined binaries, libraries, scripts, kernel files, service units,
  scheduled jobs and security-sensitive files are re-verified.
- **Alerts.** One alert per deviation: rule `FIM-001` (new) to `FIM-011`
  (metadata only), with the severity from the comparison. The same deviation
  is not raised again while its alert is open, acknowledged or investigated.
  Alerts below `alerts.minimum_severity` are not raised; with
  `alerts.journal = true` each alert is also logged to the journal.
- **Not yet monitored.** Execution, kernel, persistence and account
  monitoring arrive in later milestones. While they are enabled in the
  configuration, `status` lists them as `UNAVAILABLE`, and protection shows
  `DEGRADED` rather than `ACTIVE`.

## Agent liveness

The daemon records start and stop in the database and refreshes a heartbeat
every 15 seconds. `status` and `verify` report:

- `running`: heartbeat within the last 90 seconds, or a scan is in progress
  that started while the heartbeat was fresh and has run for less than 30
  minutes (a scan holds the database, so it delays the heartbeat).
- `not_responding`: last recorded state is running but the heartbeat is stale,
  meaning the daemon died without a clean shutdown. `verify` fails (exit 4).
- `stopped`: the daemon shut down cleanly.
- `never_started`.

The systemd watchdog is fed from a separate thread for as long as the
monitoring loop makes progress; if it makes none for 30 minutes, the
watchdog lapses and systemd restarts the service.
