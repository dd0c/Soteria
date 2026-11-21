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
| `soteria config show\|validate\|default` | Configuration. `validate` also checks the administrator rule files. |
| `soteria config test-notifications` | Sends a test message to each enabled notification channel; exit 1 if one fails. |
| `soteria verify [--component config,platform,database,baseline,service,sensors]` | Runs every check and lists each result. Checks that belong to later milestones are listed as `SKIP` with the reason. |
| `soteria daemon` | Started by `soteria.service`. Runs live monitoring; see below. |
| `soteria events [--since T] [--until T] [--type TYPE] [--severity S] [--limit N]` | Event history, oldest first (the newest `N` when more match). `T` is an RFC 3339 time or an age such as `30m` or `2h`. `--type file` matches `file.created`, `file.modified` and `file.deleted`. `--severity S` means `S` and above. |
| `soteria alerts list [--since T] [--until T] [--severity S] [--status S] [--rule ID] [--object TEXT] [--incident N] [--limit N]` | Alerts, newest first. |
| `soteria alerts show ID` | One alert with its evidence (approved and current state, change kinds, source), recommendation and history. |
| `soteria alerts ack\|investigate\|close\|reopen ID [--note TEXT]` | Change an alert's status; see [Alert handling](#alert-handling). |
| `soteria alerts note ID TEXT` | Add a note to an alert's history. |
| `soteria alerts suppress ID --reason TEXT [--all-objects] [--expires AGE]` | Stop raising this detection (rule on this object, or on every object). |
| `soteria alerts suppressions [--all]`, `alerts unsuppress SID` | List or remove suppressions. |
| `soteria alerts incidents [--all]`, `alerts incident N` | Groups of related alerts; see [Incidents](#incidents). |
| `soteria alerts export [--format json\|csv\|text] [filters] [--output FILE]` | Alerts with evidence and history (FR-035). A file is created with mode 0600. |
| `soteria processes [--since T] [--until T] [--exe NAME\|PATH] [--user USER\|UID] [--pid N] [--severity S] [--classification C] [--limit N]` | Execution history (FR-013), oldest first (the newest `N` when more match). `--exe` with a `/` matches the program or script path, or everything under a directory; without one it matches the program name. `--user` matches the real, effective or login user. |
| `soteria rules list\|show ID\|validate` | Detection rules in effect; see [Detection rules](#detection-rules). |
| `soteria report scan ID\|UUID\|latest`, `report scans [--since T] [--limit N]` | Scan reports (FR-034): type, times, duration, checked, skipped and error counts, changes, baseline deviations, gaps and result. |
| `soteria report summary [--since T] [--until T]` | Host summary for a period (default 7 days): alerts by severity, status, rule and object, incidents, suppressed detections, executions by classification, file changes, scans, open coverage gaps and notification failures. |

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
  `alerts.journal = true` each alert is also logged to the journal. Rules can
  be disabled or given a fixed severity; see
  [Detection rules](#detection-rules).
- **Executions (FR-009..FR-012).** See below.
- **Not yet monitored.** Kernel, persistence and account monitoring arrive
  in a later milestone. While they are enabled in the
  configuration, `status` lists them as `UNAVAILABLE`, and protection shows
  `DEGRADED` rather than `ACTIVE`.

## Execution monitoring

The daemon reads the kernel audit stream (it needs only `CAP_AUDIT_READ`
and works alongside auditd). The kernel reports executions only when an
audit rule asks for them. That rule ships as
`packaging/audit/soteria.rules`, installed as
`/etc/audit/rules.d/soteria.rules` and loaded by auditd. auditd is installed
by default on RHEL; on Debian install it with `apt install auditd`.

At startup the agent runs `/bin/true` and checks that it shows up in the
stream. If it doesn't, the rule is not loaded: the `execution` sensor
reports `degraded`, a `no_exec_rule` coverage gap is opened, and the test is
retried every 10 minutes.

Each execution is stored with time, PID, parent PID, real, effective and
login user, group, terminal, session, program path and SHA-256, the script
(when an interpreter runs one), command line, working directory and parent
program. It is classified (FR-010) as:

| Classification | Meaning |
|---|---|
| `trusted` | The program is in the approved baseline and its hash matches. |
| `known_modified` | The program is in the baseline but its content differs. |
| `unknown` | The program is not in the baseline. |
| `suspicious` | A rule below matched. |
| `unverified` | It could not be checked: no approved baseline, or the file could not be hashed. |

| Rule | Severity | Raised when |
|---|---|---|
| `EXE-001` | medium; high with a second signal | A program or script runs from a configured unusual location (`[execution] unusual_paths`, default `/tmp`, `/var/tmp`, `/dev/shm`, `/run/user`, `/dev/mqueue`, `/home`, `/root`), a hidden path, or a file or directory writable by a non-root user; or an unknown program created or changed within `recent_change` runs. High when the location is unusual and the program is also unknown, new or hidden. |
| `EXE-002` | high | A program whose content differs from the baseline runs. |
| `EXE-003` | high | A program runs that was deleted from disk, or exists only in memory (memfd). |
| `EXE-004` | high | A network service (web, database, mail, DNS, file-sharing servers and similar) starts a shell. |
| `EXE-005` | medium | An interpreter runs a script created or changed within `recent_change`. |

The same detection (rule, program and hash) is not raised again while its
alert is open. Command lines are stored according to `[execution]
arguments` (NFR-011). The default, `redacted`, replaces values that look like
secrets: `--password=…`, the value after `--token`, `KEY=…` assignments
with secret-like names, and passwords in URLs. `full` keeps everything, and
`none` keeps only the program name. Command lines are cut to
`max_argument_bytes`.

Lost executions cannot be recovered by a scan. A full queue or audit
socket overrun opens an `overflow` coverage gap, which closes after an hour
without further loss.

## Alert handling

Alerts move between `open`, `acknowledged`, `investigated`, `closed` and
`suppressed` (FR-030). Every change and note is appended to the alert's
history with the user who made it (through `sudo`, recorded as
`root (via sudo from alice)`); the history cannot be edited, and an alert's
evidence can never change, so acknowledging or closing an alert never alters
what was detected. Changing an alert needs write access to the database
(root).

`suppress` records an administrator decision that a detection is benign: the
alert becomes `suppressed`, and matching detections (the same rule on the
same object, or with `--all-objects` on any object) are recorded as
`alert.suppressed` events instead of alerts, until the suppression expires
(`--expires 30d`) or is removed. Suppressions are listed with
`alerts suppressions`. Removing one does not change the alerts it
suppressed.

`export` writes all matching alerts, oldest first, with evidence and
history. CSV cells that start with `=`, `+`, `-`, `@`, a tab or a carriage return are
prefixed with `'`
so spreadsheets do not run them as formulas.

## Incidents

Related alerts are grouped into incidents (FR-018). Two alerts are related
when they were raised within `alerts.correlation_window` (default 1 hour) of
each other and:

- concern the same file or program;
- one is a file change and the other an execution of that file (for example
  a program written to `/usr/local/bin` and then run);
- are executions in the same login session by the same login user; or
- one execution is the parent process of the other.

A single alert is not an incident; the second related alert creates one, and
later related alerts join it. The incident's severity is the highest of its
alerts, and it closes when all its alerts are closed or suppressed (a new
related alert reopens it). Grouping is noted in each alert's history.
Notifications include the incident number.

## Detection rules

`soteria rules list` shows every rule with its state and severity, and
`rules show ID` explains when it fires and how to investigate. Built-in rules
are `FIM-001` to `FIM-011` (file integrity), `EXE-001` to `EXE-005`
(execution) and `INT-001` (baseline seal). Administrators add rules and
overrides in `*.toml` files in `general.rules_directory` (default
`/etc/soteria/rules.d`); see [RULES.md](RULES.md). Invalid rule files fail
`soteria config validate` and `rules validate` (exit 3), and the daemon
refuses to start with them rather than run with rules missing. Rule
definitions and versions are recorded in the database when the daemon
starts. Restart the daemon to apply changes.

## Notifications

Besides the journal, new alerts can be sent by email and to a webhook
(FR-031). Both are off by default and switched on with `alerts.email` and
`alerts.webhook`; settings are in `[notifications.email]` and
`[notifications.webhook]`.

- **Email** goes to an SMTP relay, always encrypted: `tls = "starttls"`
  (port 587 unless given) or `"implicit"` (port 465). A relay that does not
  offer STARTTLS is refused rather than used in the clear. A login uses
  `AUTH PLAIN` with the password read from `password_file`.
- **Webhooks** receive a JSON `POST` over HTTPS:
  `{"source": "soteria", "version", "hostname", "alerts": [...]}`, each alert
  with id, uuid, time, severity, type, status, host, object, rule, reason,
  recommendation and incident. `token_file` adds `Authorization: Bearer`.
  Any 2xx answer counts as delivered; redirects are not followed.

Certificates are checked against the system trust store, or `ca_file`.
Each channel has its own `minimum_severity` (default `high`), sends up to 50
alerts per message, and remembers in the database the last alert it
delivered, so restarts neither lose nor repeat alerts. Only alerts raised
after a channel is switched on are sent. Delivery runs on its own thread, so
a slow or unreachable server never delays monitoring. A failed attempt is
logged, recorded as a `notification.failed` event, shown as `failing` in
`soteria status`, and retried after 30 seconds, doubling up to 30 minutes.
`soteria config test-notifications` sends a test message.

## Retention

Every hour the daemon deletes events and execution records older than
`general.event_retention_days` (default 90), and records a
`retention.pruned` event. Alerts, their history, incidents, suppressions,
baselines and scan reports are kept, and so are the events and execution
records an alert cites.

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
