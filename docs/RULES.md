# Detection rules

Every alert names the rule that raised it. `soteria rules list` shows the
rules in effect, and `soteria rules show ID` describes one.

## Built-in rules

| Rule | Applies to | Severity | Raised when |
|---|---|---|---|
| `FIM-001` | file | by object | Object is not in the approved baseline |
| `FIM-002` | file | by object | Baselined object is missing |
| `FIM-003` | file | by object | File content changed |
| `FIM-004` | file | by object | Permissions changed |
| `FIM-005` | file | by object | Owner or group changed |
| `FIM-006` | file | by object | File capabilities changed |
| `FIM-007` | file | by object | SELinux label changed |
| `FIM-008` | file | by object | Symbolic link target changed |
| `FIM-009` | file | by object | Executable permission changed |
| `FIM-010` | file | by object | Object type changed |
| `FIM-011` | file | info | Only size, time or inode changed |
| `EXE-001` | execution | medium, high with a second signal | Program run from an unusual location, or a new unknown program run |
| `EXE-002` | execution | high | Program that differs from the baseline run |
| `EXE-003` | execution | high | Deleted or memory-only program run |
| `EXE-004` | execution | high | Network service started a shell |
| `EXE-005` | execution | medium | Interpreter ran a recently changed script |
| `INT-001` | integrity | critical | Approved baseline failed verification |

"By object" severities depend on the object's category and the change; see
[CLI.md](CLI.md#baselines).

## Rule files

Rule files are `*.toml` files in `general.rules_directory` (default
`/etc/soteria/rules.d`), read in name order. Keep them owned by root and not
writable by others: they decide what is reported. Check them with
`soteria rules validate`, then restart the daemon
(`systemctl restart soteria`).

Parsing is strict. An unknown key, an override of an unknown rule, a
duplicate id, a rule that would match everything, or a relative path is an
error, and the daemon refuses to start until it is fixed.

### Overriding a built-in rule

```toml
# Metadata-only changes are noise on this host.
[[override]]
rule = "FIM-011"
enabled = false

# Treat any program run from an unusual location as high.
[[override]]
rule = "EXE-001"
severity = "high"
```

`enabled` and `severity` are both optional, but an override must set one.
A fixed severity replaces the one the rule would compute. Each rule can be
overridden once across all files.

### File rules

A file rule raises its own alert, at its own severity, for a baseline
deviation of a matching path, next to the built-in `FIM-*` alert.

```toml
[[rule]]
id = "SITE-001"
title = "SSH server configuration changed"
on = "file"
severity = "critical"
paths = ["/etc/ssh/sshd_config", "/etc/ssh/sshd_config.d/*"]
# Optional; any change when left out.
changes = ["content_modified", "permission_modified", "owner_modified", "new", "missing"]
reason = "The SSH server configuration differs from the approved baseline."
recommendation = "Confirm the change with the change record; check for new AllowUsers, PermitRootLogin or AuthorizedKeysFile settings."
```

Paths must be inside `paths.include` to be monitored at all. Patterns are
globs on the absolute path: `*` and `?` stay within one path component, and
`**` crosses components (`/etc/sudoers.d/**`). Change kinds are `new`,
`missing`, `type_changed`, `content_modified`, `permission_modified`,
`owner_modified`, `capability_modified`, `security_label_modified`,
`symlink_target_modified`, `executable_status_modified` and
`metadata_modified`.

### Execution rules

An execution rule raises an alert when a program run matches every list it
gives:

```toml
[[rule]]
id = "SITE-002"
title = "Reverse shell tool run"
on = "execution"
severity = "high"
# A pattern with a "/" matches the program or script path; otherwise the name.
programs = ["nc", "ncat", "socat", "/opt/*/bin/socat"]
# Any argument containing one of these.
arguments = ["-e", "exec:"]

[[rule]]
id = "SITE-003"
title = "Unknown program run as root"
on = "execution"
severity = "medium"
uids = [0]                       # real or effective user
classifications = ["unknown"]    # trusted, known_modified, unknown, suspicious, unverified
```

`parents` matches the parent process the same way as `programs`. Arguments
are matched before redaction, but the stored command line follows
`[execution] arguments`.

### Common fields

| Field | Required | Meaning |
|---|---|---|
| `id` | yes | 1 to 64 upper-case letters, digits, `-` or `_`; not a built-in id |
| `title` | yes | Short name |
| `on` | yes | `file` or `execution` |
| `severity` | yes | `info`, `low`, `medium`, `high` or `critical` |
| `enabled` | no | Default `true` |
| `reason` | no | Alert reason; default "Matched administrator rule ID: title." |
| `recommendation` | no | Investigation guidance shown with the alert |

Administrator alerts are de-duplicated, suppressed, grouped into incidents and
notified like built-in ones.
