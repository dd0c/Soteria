# Soteria administration guide

This guide takes a host from nothing to monitored, and covers daily
operation, upgrades and removal. Command details are in [CLI.md](CLI.md),
detection rules in [RULES.md](RULES.md).

Supported: RHEL 9, RHEL 10 and Debian 13, x86_64. Other systemd
distributions work but are reported as "compatible, not officially
supported".

## 1. Before you install

- **auditd** reports program executions to Soteria. It is installed by
  default on RHEL; on Debian run `sudo apt install auditd`. Without it,
  everything except execution monitoring works, and `soteria status` shows
  the execution sensor as unavailable.
- **A trusted starting point.** The first baseline records the host as it is
  when you approve it. Install Soteria on a freshly built or verified host,
  not on one you suspect.
- **Disk:** the database grows with the number of monitored files (about
  600 bytes each, so 15 MB for 25,000 files) plus events within the retention
  period (90 days by default).

## 2. Install

Download the package for your release from the project's GitHub releases
page and check it against `SHA256SUMS` from the same release:

```sh
sha256sum --check --ignore-missing SHA256SUMS
```

**RHEL 9 / RHEL 10**

```sh
sudo dnf install ./soteria-<version>-1.el9.x86_64.rpm ./soteria-selinux-<version>-1.el9.noarch.rpm
```

(`el10` packages on RHEL 10.) `soteria-selinux` installs the SELinux policy
that confines the daemon; install it whenever SELinux is enabled.

**Debian 13**

```sh
sudo apt install ./soteria_<version>_amd64.deb
```

The AppArmor profile is loaded automatically where AppArmor is enabled.

**What the package does**

- creates the system account `soteria` (no login shell);
- installs `/usr/bin/soteria`, the `soteria.service` unit, the default
  configuration `/etc/soteria/soteria.toml`, the audit rule
  `/etc/audit/rules.d/soteria.rules` and the SELinux or AppArmor policy;
- creates `/var/lib/soteria` and `/var/log/soteria`, owned by `soteria`;
- loads the audit rule if auditd is running.

It does **not** start monitoring: initialization is a deliberate step.

If auditd was installed after Soteria, load the rule with
`sudo augenrules --load`.

## 3. Configure (optional)

The defaults monitor system binaries, libraries, `/etc`, `/boot`,
persistence locations (SSH keys, shell startup files, user services, cron)
and Soteria's own files. Review `/etc/soteria/soteria.toml`; common changes:

- `[paths] include / exclude`: add application directories such as `/opt/app`;
- `[execution] unusual_paths`: where program execution is suspicious;
- `[alerts]`: minimum severity, email and webhook delivery
  (see [CLI.md](CLI.md#notifications));
- `[general] event_retention_days`.

Check your changes with `sudo soteria config validate`. Invalid
configuration stops the service rather than running with weaker defaults.

## 4. Initialize and approve the baseline

```sh
sudo soteria init
```

`init` checks prerequisites, creates the database and the baseline signing
key (`/etc/soteria/keys/baseline.key`, readable by root only), inventories
the host (a typical server takes 10 to 60 seconds), and shows the draft
baseline: objects by kind and any coverage gaps.

Review it, then answer `y` to approve. Approval signs the baseline with the
root-held key; the daemon only ever has the public key, so it cannot forge an
approval. To approve later instead:

```sh
sudo soteria init --non-interactive    # leaves a draft
sudo soteria baseline review 1
sudo soteria baseline approve 1
```

## 5. Start monitoring

```sh
sudo systemctl enable --now soteria
soteria status
sudo soteria verify
```

`status` should show `Protection: ACTIVE`. Anything else is explained by the
sensor list and `soteria verify`, which names every coverage gap (for
example an unloaded audit rule, or paths the daemon cannot read).

The service restarts automatically if it stops unexpectedly. The next start
raises a `SELF-002` alert and runs a full reconciliation scan, so changes made
while it was down are still found.

## 6. Daily operation

**Alerts**

```sh
soteria alerts list                 # open alerts, highest severity first
soteria alerts show <id>            # evidence, reason and investigation steps
sudo soteria alerts ack <id>        # you are looking at it
sudo soteria alerts close <id> --note "package update, change ticket 123"
soteria alerts incidents            # related alerts grouped together
```

Every alert names the rule that fired, why, the approved and current state,
and what to check next. `soteria rules show <rule>` explains a rule.

**Approving authorized changes**

After planned maintenance (package updates, configuration changes), fold the
changes into a new baseline. Baselines are never updated automatically.

```sh
sudo soteria scan --baseline        # list deviations from the approved baseline
sudo soteria baseline create        # draft from the current state
sudo soteria baseline diff <approved> <draft>
sudo soteria baseline approve <draft>
```

Changes to Soteria's own configuration, rules and keys raise a critical
`SELF-001` alert; approve a new baseline once the change is confirmed.

**Noise**

Suppress a known benign detection for an object instead of disabling a
rule (`soteria alerts suppress --help`), or tune rules in
`/etc/soteria/rules.d/` ([RULES.md](RULES.md)).

**Other views**

```sh
soteria events --since 1h           # everything observed
soteria processes --since 1h        # program executions
sudo soteria scan --kernel          # kernel, boot parameters, Secure Boot, modules
soteria report summary --since 7d
```

## 7. Upgrade

Install the newer package the same way as in step 2. The package keeps your
configuration and rules, and restarts a running daemon. If the new version
changes the database schema, the daemon first copies the database to
`/var/lib/soteria/soteria.db.schema-<N>.bak`, then migrates it. Baselines,
alerts, events and suppressions are kept.

To undo an upgrade: stop the service, install the previous package, and put
the copy back:

```sh
sudo systemctl stop soteria
sudo cp /var/lib/soteria/soteria.db.schema-<N>.bak /var/lib/soteria/soteria.db
sudo chown soteria:soteria /var/lib/soteria/soteria.db
sudo systemctl start soteria
```

## 8. Remove

```sh
sudo dnf remove soteria soteria-selinux     # RHEL
sudo apt remove soteria                     # Debian (purge also removes the configuration file)
```

Removal stops the service and removes the program, but keeps the database,
baselines, keys, rules and logs. Security records are never deleted
silently. To delete them deliberately:

```sh
sudo rm -rf /var/lib/soteria /etc/soteria /var/log/soteria
sudo userdel soteria
```

Remove `/etc/audit/rules.d/soteria.rules` and run `sudo augenrules --load`
if auditd should stop reporting executions.

## 9. Troubleshooting

| Symptom | Check |
|---|---|
| Service fails with exit code 3 | `sudo soteria config validate` |
| Service fails with exit code 5 | `sudo soteria init` was not run |
| Execution sensor unavailable | auditd running? `sudo augenrules --load` |
| Kernel sensor degraded | `/proc/modules` unreadable (containers) |
| `inotify watch limit reached` | raise `fs.inotify.max_user_watches` (sysctl) |
| SELinux denials | `sudo ausearch -m avc -c soteria`, then report them |

Logs: `journalctl -u soteria`.

## 10. Security notes

- The daemon runs as `soteria` with two read-only capabilities
  (`CAP_DAC_READ_SEARCH` to read root-only files, `CAP_AUDIT_READ` for the
  execution stream). There is no privileged helper.
- The baseline signing key never leaves root; keep a copy offline if you need
  to re-verify old baselines after a rebuild.
- A local attacker with unrestricted root or kernel access can still evade or
  disable local monitoring. Forward alerts (email or webhook) so they leave
  the host as they happen.
