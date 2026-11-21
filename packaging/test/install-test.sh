#!/bin/sh
# Install, initialize, run, upgrade and remove a Soteria package on this
# host (SRS 11, 13). Meant for disposable CI containers: it changes the
# system and needs root.
#   packaging/test/install-test.sh <package> [<package>...] -- <upgrade package> [...]
set -eu

step() { printf '\n=== %s\n' "$*"; }
fail() { echo "FAIL: $*" >&2; exit 1; }

first=""
upgrade=""
target=first
for a in "$@"; do
	if [ "$a" = "--" ]; then target=upgrade; continue; fi
	if [ $target = first ]; then first="$first $a"; else upgrade="$upgrade $a"; fi
done

if command -v dnf >/dev/null; then
	install() { dnf install -y "$@"; }
	remove() { dnf remove -y soteria soteria-selinux; }
	purge() { :; }
else
	export DEBIAN_FRONTEND=noninteractive
	install() { apt-get install -y "$@"; }
	remove() { apt-get remove -y soteria; }
	purge() { apt-get purge -y soteria; }
fi

step "install"
# shellcheck disable=SC2086
install $first
id soteria
[ "$(stat -c %U:%G /var/lib/soteria)" = soteria:soteria ] || fail "state directory ownership"
[ "$(stat -c %a:%G /etc/soteria/soteria.toml)" = 640:soteria ] || fail "configuration permissions"
soteria --version
soteria config validate

step "initialize"
# 1: initialized with warnings, such as auditd missing.
soteria init --yes || [ $? -eq 1 ] || fail "init failed"
[ "$(stat -c %U /var/lib/soteria/soteria.db)" = soteria ] || fail "database not owned by soteria"
[ "$(stat -c %a /etc/soteria/keys/baseline.key)" = 600 ] || fail "signing key permissions"

step "run as the soteria user"
# No systemd in a container: start the daemon as the unit would.
timeout -s TERM 20 setpriv --reuid=soteria --regid=soteria --init-groups \
	--inh-caps=+dac_read_search,+audit_read --ambient-caps=+dac_read_search,+audit_read \
	soteria daemon || [ $? -eq 124 ] || fail "daemon exited early"
soteria status || true   # not ACTIVE: no systemd, no auditd here
# 1: warnings (coverage gaps in a container); 4 would be a failed seal.
soteria verify --component database --component baseline || [ $? -eq 1 ] || fail "verification failed"

step "detect a change"
echo "# tampered" >> /etc/hosts
soteria scan --baseline && fail "a changed /etc/hosts went unnoticed" || [ $? -eq 1 ]

step "upgrade"
echo "keep me" > /etc/soteria/rules.d/admin-note.txt
sed -i 's/^log_level = .*/log_level = "debug"/' /etc/soteria/soteria.toml
# shellcheck disable=SC2086
install $upgrade
soteria --version
grep -q '^log_level = "debug"' /etc/soteria/soteria.toml || fail "configuration overwritten on upgrade"
[ -f /etc/soteria/rules.d/admin-note.txt ] || fail "rules directory changed on upgrade"
soteria baseline list | grep -q approved || fail "baseline lost on upgrade"

step "remove"
remove
[ ! -e /usr/bin/soteria ] || fail "program not removed"
[ -f /var/lib/soteria/soteria.db ] || fail "database deleted on removal"
[ -f /etc/soteria/keys/baseline.key ] || fail "signing key deleted on removal"
purge
[ -f /var/lib/soteria/soteria.db ] || fail "database deleted on purge"

step "all package checks passed"
