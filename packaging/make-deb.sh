#!/bin/bash
# Build the lt-eid .deb for the Debian or Ubuntu release this runs on, from
# this tree (uncommitted changes included), into target/deb. Needs the
# Build-Depends of packaging/debian/control, and OpenSC's git tree in
# $OPENSC_SRC (default ~/src/OpenSC).
#
# The version, the OpenSC commit and its patches are those of
# packaging/lt-eid.spec, so the .deb and the RPM are made of the same things.
set -euo pipefail
cd "$(dirname "$0")/.."

# Ubuntu installs a Rust newer than the release's own outside $PATH.
rust=$(ls -d /usr/lib/rust-*/bin 2>/dev/null | sort -V | tail -n1)
[ -z "$rust" ] || PATH=$rust:$PATH

spec=packaging/lt-eid.spec
version=$(sed -n 's/^version = "\(.*\)"$/\1/p' Cargo.toml | head -n1)
release=$(sed -n 's/^Release: *\([0-9]*\).*/\1/p' $spec)
opensc_commit=$(sed -n 's/^%global opensc_commit //p' $spec)
# One package per release, and the newer release's is the newer package.
. /etc/os-release
debversion=$version-$release~$ID$VERSION_ID

out=$PWD/target/deb
tree=$out/build/lt-eid-$version
rm -rf "$out"
mkdir -p "$tree"

git ls-files --cached --others --exclude-standard -z |
	tar --null -T - -c | tar -x -C "$tree"

cargo vendor --locked --quiet "$tree/vendor" >/dev/null
mkdir "$tree/.cargo"
cat > "$tree/.cargo/config.toml" <<'EOF'
[source.crates-io]
replace-with = "vendored-sources"

[source.vendored-sources]
directory = "vendor"
EOF

git -C "${OPENSC_SRC:-$HOME/src/OpenSC}" archive --prefix=opensc/ "$opensc_commit" |
	tar -x -C "$tree"
for patch in $(sed -n 's/^Patch[0-9]*: *//p' $spec); do
	patch -d "$tree/opensc" -p1 -F0 -s --no-backup-if-mismatch < "packaging/$patch"
done

cp -r packaging/debian "$tree/debian"
cat > "$tree/debian/changelog" <<EOF
lt-eid ($debversion) ${VERSION_CODENAME:-unstable}; urgency=medium

  * Built by packaging/make-deb.sh. The changes are in the %changelog of
    packaging/lt-eid.spec.

 -- $(sed -n 's/^Maintainer: //p' packaging/debian/control)  $(git log -1 --format=%cD)
EOF

(cd "$tree" && dpkg-buildpackage -b -us -uc)

# Debug symbols are a .ddeb on Ubuntu, a -dbgsym .deb on Debian.
find "$out/build" -maxdepth 1 \( -name '*.deb' -o -name '*.ddeb' \) -exec mv -t "$out" {} +
rm -rf "$out/build"
ls -l "$out"
