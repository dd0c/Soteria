# Soteria RPM for RHEL 9 and RHEL 10 (SRS 9.1, 11).
#
# Built by packaging/rpm/build.sh from a source tarball of the repository
# and a release binary built on the target release (Source1), so the
# binary links against that release's glibc.

%global selinuxtype targeted
# The binary is built by cargo before rpmbuild; there are no sources to
# extract debug information from.
%global debug_package %{nil}

Name:           soteria
Version:        %{soteria_version}
Release:        1%{?dist}
Summary:        Host intrusion detection and integrity monitoring
License:        GPL-3.0-or-later
URL:            https://github.com/dd0c/Soteria
Source0:        soteria-%{version}.tar.gz
Source1:        soteria
Source2:        soteria.sysusers

BuildRequires:  systemd-rpm-macros
BuildRequires:  selinux-policy-devel
BuildRequires:  make
Requires:       systemd
Recommends:     audit
Recommends:     (%{name}-selinux if selinux-policy-%{selinuxtype})
%{?systemd_requires}
%{?sysusers_requires_compat}

%description
Soteria inventories a host, seals an approved baseline, and watches files,
program executions, persistence locations, accounts, the kernel and boot
configuration for deviations, with alerts, incidents and reports.

%package selinux
Summary:        SELinux policy module for Soteria
BuildArch:      noarch
Requires:       selinux-policy-%{selinuxtype}
Requires(post): selinux-policy-%{selinuxtype}
Requires(post): policycoreutils
Requires(postun): policycoreutils

%description selinux
Confines the Soteria daemon in the soteria_t domain: it may read the
filesystem it monitors and write only its own state.

%prep
%autosetup -n soteria-%{version}

%build
make -f %{_datadir}/selinux/devel/Makefile -C packaging/selinux soteria.pp
bzip2 -9 packaging/selinux/soteria.pp

%install
install -D -m 0755 %{SOURCE1} %{buildroot}%{_bindir}/soteria
install -D -m 0644 packaging/systemd/soteria.service %{buildroot}%{_unitdir}/soteria.service
install -D -m 0644 packaging/sysusers/soteria.conf %{buildroot}%{_sysusersdir}/soteria.conf
install -D -m 0640 packaging/config/soteria.toml %{buildroot}%{_sysconfdir}/soteria/soteria.toml
install -d -m 0755 %{buildroot}%{_sysconfdir}/soteria/rules.d
install -d -m 0750 %{buildroot}%{_sysconfdir}/soteria/keys
install -D -m 0640 packaging/audit/soteria.rules %{buildroot}%{_sysconfdir}/audit/rules.d/soteria.rules
install -d -m 0750 %{buildroot}/var/lib/soteria %{buildroot}%{_localstatedir}/log/soteria
install -D -m 0644 packaging/selinux/soteria.pp.bz2 %{buildroot}%{_datadir}/selinux/packages/%{selinuxtype}/soteria.pp.bz2
install -D -m 0644 packaging/selinux/soteria.if %{buildroot}%{_datadir}/selinux/devel/include/distributed/soteria.if

%pre
%{?sysusers_create_compat:%sysusers_create_compat %{SOURCE2}}

%post
%systemd_post soteria.service
# Execution monitoring needs the audit rule loaded by auditd.
if [ -x /usr/sbin/augenrules ] && systemctl is-active --quiet auditd 2>/dev/null; then
    augenrules --load >/dev/null 2>&1 || :
fi
if [ $1 -eq 1 ]; then
    cat <<'MSG'

Soteria is installed but not monitoring yet. Next:
  sudo soteria init                 # inventory the host and approve a baseline
  sudo systemctl enable --now soteria
MSG
fi

%preun
%systemd_preun soteria.service

%postun
# A running daemon restarts on upgrade and migrates its database, keeping a
# copy of the old one.
%systemd_postun_with_restart soteria.service
if [ $1 -eq 0 ]; then
    cat <<'MSG'
Soteria's database, baselines, keys, rules and logs were kept:
  /var/lib/soteria  /etc/soteria  /var/log/soteria
To delete them deliberately:
  sudo rm -rf /var/lib/soteria /etc/soteria /var/log/soteria && sudo userdel soteria
MSG
fi

%pre selinux
%selinux_relabel_pre -s %{selinuxtype}

%post selinux
%selinux_modules_install -s %{selinuxtype} %{_datadir}/selinux/packages/%{selinuxtype}/soteria.pp.bz2
%selinux_relabel_post -s %{selinuxtype}
if [ $1 -eq 1 ]; then
    systemctl try-restart soteria.service >/dev/null 2>&1 || :
fi

%postun selinux
if [ $1 -eq 0 ]; then
    %selinux_modules_uninstall -s %{selinuxtype} soteria
    %selinux_relabel_post -s %{selinuxtype}
fi

%files
%license LICENSE
%doc README.md docs/CLI.md docs/RULES.md docs/ADMIN.md
%{_bindir}/soteria
%{_unitdir}/soteria.service
%{_sysusersdir}/soteria.conf
%dir %{_sysconfdir}/soteria
%config(noreplace) %attr(0640,root,soteria) %{_sysconfdir}/soteria/soteria.toml
%dir %{_sysconfdir}/soteria/rules.d
%dir %attr(0750,root,soteria) %{_sysconfdir}/soteria/keys
%config(noreplace) %{_sysconfdir}/audit/rules.d/soteria.rules
%dir %attr(0750,soteria,soteria) /var/lib/soteria
%dir %attr(0750,soteria,soteria) %{_localstatedir}/log/soteria

%files selinux
%{_datadir}/selinux/packages/%{selinuxtype}/soteria.pp.bz2
%{_datadir}/selinux/devel/include/distributed/soteria.if

%changelog
* Sat Nov 21 2026 Soteria maintainers <noreply@akuadora.net> - 0.1.0-1
- First packaged release.
