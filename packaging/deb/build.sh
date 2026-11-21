#!/bin/sh
# Build the Debian package from a release binary.
#   packaging/deb/build.sh <path/to/soteria> <output-dir>
# Run from the repository root. Needs dpkg-deb.
set -eu

bin=$1
out=$2
version=$(sed -n 's/^version = "\(.*\)"/\1/p' Cargo.toml | head -n 1)
arch=$(dpkg --print-architecture)
stage=$(mktemp -d)
trap 'rm -rf "$stage"' EXIT
chmod 0755 "$stage"

install -D -m 0755 "$bin" "$stage/usr/bin/soteria"
install -D -m 0644 packaging/systemd/soteria.service "$stage/usr/lib/systemd/system/soteria.service"
install -D -m 0644 packaging/sysusers/soteria.conf "$stage/usr/lib/sysusers.d/soteria.conf"
install -D -m 0640 packaging/config/soteria.toml "$stage/etc/soteria/soteria.toml"
install -D -m 0640 packaging/audit/soteria.rules "$stage/etc/audit/rules.d/soteria.rules"
install -D -m 0644 packaging/apparmor/usr.bin.soteria "$stage/etc/apparmor.d/usr.bin.soteria"
for doc in README.md docs/CLI.md docs/RULES.md docs/ADMIN.md; do
	[ -f "$doc" ] && install -D -m 0644 "$doc" "$stage/usr/share/doc/soteria/$(basename "$doc")"
done
install -D -m 0644 LICENSE "$stage/usr/share/doc/soteria/copyright" 2>/dev/null || true

install -d "$stage/DEBIAN"
size=$(du -sk "$stage" | cut -f1)
sed -e "s/@VERSION@/$version/" -e "s/@ARCH@/$arch/" -e "s/@SIZE@/$size/" \
	packaging/deb/control.in > "$stage/DEBIAN/control"
for s in postinst prerm postrm; do
	install -m 0755 "packaging/deb/$s" "$stage/DEBIAN/$s"
done
# Administrator changes to these survive upgrades (SRS 11.1).
cat > "$stage/DEBIAN/conffiles" <<CONF
/etc/soteria/soteria.toml
/etc/audit/rules.d/soteria.rules
/etc/apparmor.d/usr.bin.soteria
CONF
(cd "$stage" && find usr etc -type f -exec md5sum {} + > DEBIAN/md5sums)

mkdir -p "$out"
dpkg-deb --root-owner-group --build "$stage" "$out/soteria_${version}_${arch}.deb"
