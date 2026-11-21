#!/bin/sh
# Build the RPMs from a release binary.
#   packaging/rpm/build.sh <path/to/soteria> <output-dir>
# Run from the repository root of a git checkout. Needs rpmbuild and
# selinux-policy-devel.
set -eu

bin=$1
out=$(realpath -m "$2")
version=$(sed -n 's/^version = "\(.*\)"/\1/p' Cargo.toml | head -n 1)
top=$(mktemp -d)
trap 'rm -rf "$top"' EXIT

mkdir -p "$top/SOURCES" "$out"
git archive --format=tar.gz --prefix="soteria-$version/" -o "$top/SOURCES/soteria-$version.tar.gz" HEAD
install -m 0755 "$bin" "$top/SOURCES/soteria"
rpmbuild -bb packaging/rpm/soteria.spec \
	--define "_topdir $top" \
	--define "soteria_version $version" \
	--define "_rpmdir $out" \
	--define "_build_name_fmt %%{NAME}-%%{VERSION}-%%{RELEASE}.%%{ARCH}.rpm"
