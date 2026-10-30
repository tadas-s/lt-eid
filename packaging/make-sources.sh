#!/bin/bash
# Put what packaging/lt-eid.spec needs into the rpmbuild SOURCES directory:
# a tarball of this tree (uncommitted changes included), the vendored Rust
# crates, the OpenSC patches and, if missing, the OpenSC snapshot.
set -euo pipefail
cd "$(dirname "$0")/.."

version=$(sed -n 's/^version = "\(.*\)"$/\1/p' Cargo.toml | head -n1)
opensc_commit=$(sed -n 's/^%global opensc_commit //p' packaging/lt-eid.spec)
opensc_version=0.27.1^$(sed -n 's/^%global opensc_snapdate //p' packaging/lt-eid.spec)git$opensc_commit
out=${SOURCES:-$(rpm --eval %_sourcedir)}
name=lt-eid-$version
tmp=$(mktemp -d)
trap 'rm -rf "$tmp"' EXIT
mkdir -p "$out"

git ls-files --cached --others --exclude-standard -z |
	tar --null -T - --transform "s,^,$name/," -czf "$out/$name.tar.gz"

cargo vendor --locked --quiet "$tmp/vendor" >/dev/null
tar -C "$tmp" -cJf "$out/$name-vendor.tar.xz" vendor

cp packaging/*.patch "$out/"

opensc_tar="$out/opensc-$opensc_version.tar.gz"
if [ ! -e "$opensc_tar" ]; then
	git -C "${OPENSC_SRC:-$HOME/src/OpenSC}" archive --prefix=opensc-0.27.1/ \
		-o "$opensc_tar" "$opensc_commit"
fi

ls -l "$out/$name.tar.gz" "$out/$name-vendor.tar.xz" "$opensc_tar"
