# Sources: run packaging/make-sources.sh first.

%global ltdir /opt/lt-eid

%global opensc_commit 58e466043
%global opensc_snapdate 20261021
%global opensc_version 0.27.1^%{opensc_snapdate}git%{opensc_commit}

# Everything under /opt/lt-eid is private: provide nothing to other packages.
%global __provides_exclude_from ^%{ltdir}/.*$

Name:           lt-eid
Version:        0.1.0
Release:        14%{?dist}
Summary:        Lithuanian eID card access through one central daemon

# lt-eid: LGPL-2.1-or-later. Bundled OpenSC: LGPL-2.1-or-later AND BSD-3-Clause.
# Rust crates compiled in: Apache-2.0 (cryptoki, cryptoki-sys, openssl), ISC (libloading), MIT,
# MIT OR Apache-2.0, Unlicense OR MIT; cargo-licenses.txt has the tally.
License:        LGPL-2.1-or-later AND BSD-3-Clause AND Apache-2.0 AND ISC AND MIT AND (MIT OR Apache-2.0) AND (Unlicense OR MIT)
Source0:        %{name}-%{version}.tar.gz
Source1:        %{name}-%{version}-vendor.tar.xz
Source2:        opensc-%{opensc_version}.tar.gz
# Build libopensc into opensc-pkcs11.so and the tools; install no libopensc.so.
Patch0:         opensc-static-libopensc.patch
# Notice a card removed and inserted again between two token list queries.
Patch1:         opensc-pcsc-card-replaced.patch
# lteid-tool --new-pin, so lt-eidd can change the PIN.
Patch2:         opensc-lteid-tool-new-pin.patch
# The lteid driver never deletes the cached CAN.
Patch3:         opensc-lteid-keep-cached-can.patch

ExclusiveArch:  %{rust_arches}

BuildRequires:  cargo
BuildRequires:  rust
BuildRequires:  gcc
BuildRequires:  make
BuildRequires:  autoconf automake libtool
BuildRequires:  pcsc-lite-devel
BuildRequires:  openssl-devel
BuildRequires:  readline-devel
BuildRequires:  zlib-ng-devel
BuildRequires:  openpace-devel >= 1.1.3
BuildRequires:  systemd-rpm-macros

# OpenSC loads libpcsclite with dlopen(), so no automatic dependency.
Requires:       pcsc-lite
Requires:       pcsc-lite-libs%{?_isa}
Requires:       openpace%{?_isa} >= 1.1.3
Requires:       pinentry
Recommends:     pinentry-gnome3
Requires:       p11-kit

Provides:       bundled(opensc) = %{opensc_version}

%description
Applications (browsers, signing tools) load a small PKCS#11 module that
forwards to lt-eidd, a per-user daemon. The daemon owns the only connection
to the Lithuanian eID card through a private OpenSC build, asks for PINs
itself and lets applications use the card only with the user's approval.

lt-eid-signing-server stands in for Elpako Signer, the local web service
Elpako-based sites (epaslaugos.lt) use to log in with the eID.

%prep
%setup -q -a 1
%setup -q -T -D -a 2
mv opensc-0.27.1 opensc
%patch -P0 -p1 -d opensc
%patch -P1 -p1 -d opensc
%patch -P2 -p1 -d opensc
%patch -P3 -p1 -d opensc
mkdir -p .cargo
cat > .cargo/config.toml <<'EOF'
[source.crates-io]
replace-with = "vendored-sources"

[source.vendored-sources]
directory = "vendor"
EOF

%build
pushd opensc
autoreconf -fvi
%set_build_flags
./configure \
  --build=%{_build} --host=%{_host} \
  --prefix=%{ltdir} \
  --libdir=%{ltdir}/lib \
  --sysconfdir=%{ltdir}/etc \
  --enable-p11_system_config_modules=%{ltdir}/share/p11-kit/modules \
  --with-completiondir=%{ltdir}/share/bash-completion/completions \
  --disable-doc \
  --disable-notify \
  --disable-autostart-items \
  --disable-tests \
  --enable-pcsc \
  --enable-sm
%make_build
popd

RUSTFLAGS='%{build_rustflags}' cargo build --release --offline --locked

%install
# OpenSC, pruned to the PKCS#11 module and the tools worth having.
%make_install -C opensc
tools="opensc-tool opensc-explorer pkcs11-tool pkcs15-tool lteid-tool"
r=%{buildroot}%{ltdir}
find $r/lib -mindepth 1 -maxdepth 1 ! -name opensc-pkcs11.so -exec rm -rf {} +
for d in bin share/bash-completion/completions; do
  for f in $r/$d/*; do
    case " $tools " in *" $(basename $f) "*) ;; *) rm -f $f ;; esac
  done
done
rm -rf $r/share/opensc $r/share/applications $r/share/p11-kit $r/share/doc $r/share/man
# Terminal certificates for the German eID (EAC); the Lithuanian card needs none.
rm -rf %{buildroot}%{_sysconfdir}/eac
install -pm 0644 packaging/opensc.conf $r/etc/opensc.conf

install -Dpm 0755 target/release/lt-eidd $r/bin/lt-eidd
install -Dpm 0755 target/release/lt-eid-signing-server $r/bin/lt-eid-signing-server
install -Dpm 0755 target/release/lt-eid $r/bin/lt-eid
# Cargo names it lib<crate>.so; install it under the name it is known by.
install -Dpm 0755 target/release/liblt_eid_pkcs11.so $r/lib/lt-eid-pkcs11.so

install -Dpm 0644 systemd/lt-eidd.socket %{buildroot}%{_userunitdir}/lt-eidd.socket
install -Dpm 0644 systemd/lt-eidd.service %{buildroot}%{_userunitdir}/lt-eidd.service
install -Dpm 0644 systemd/lt-eid-signing-server.socket %{buildroot}%{_userunitdir}/lt-eid-signing-server.socket
install -Dpm 0644 systemd/lt-eid-signing-server.service %{buildroot}%{_userunitdir}/lt-eid-signing-server.service
install -Dpm 0644 packaging/80-lt-eid.preset %{buildroot}%{_userpresetdir}/80-lt-eid.preset
install -Dpm 0644 packaging/lt-eid.module %{buildroot}%{_datadir}/p11-kit/modules/lt-eid.module
install -Dpm 0644 packaging/lt-eid-change-pin.desktop %{buildroot}%{_datadir}/applications/lt-eid-change-pin.desktop
install -Dpm 0644 packaging/lt-eid.svg %{buildroot}%{_datadir}/icons/hicolor/scalable/apps/lt-eid.svg

cp -p opensc/COPYING COPYING.opensc
cat vendor/*/Cargo.toml | sed -n 's/^license = //p' | sort | uniq -c > cargo-licenses.txt

%post
%systemd_user_post lt-eidd.socket lt-eidd.service lt-eid-signing-server.socket lt-eid-signing-server.service

%preun
%systemd_user_preun lt-eidd.socket lt-eidd.service lt-eid-signing-server.socket lt-eid-signing-server.service

%files
%license LICENSE COPYING.opensc cargo-licenses.txt
%doc README.md
%dir %{ltdir}
%dir %{ltdir}/bin
%dir %{ltdir}/lib
%dir %{ltdir}/etc
%{ltdir}/bin/lt-eidd
%{ltdir}/bin/lt-eid-signing-server
%{ltdir}/bin/lt-eid
%{ltdir}/bin/opensc-tool
%{ltdir}/bin/opensc-explorer
%{ltdir}/bin/pkcs11-tool
%{ltdir}/bin/pkcs15-tool
%{ltdir}/bin/lteid-tool
%{ltdir}/lib/opensc-pkcs11.so
%{ltdir}/lib/lt-eid-pkcs11.so
%config(noreplace) %{ltdir}/etc/opensc.conf
%{ltdir}/share
%{_userunitdir}/lt-eidd.socket
%{_userunitdir}/lt-eidd.service
%{_userunitdir}/lt-eid-signing-server.socket
%{_userunitdir}/lt-eid-signing-server.service
%{_userpresetdir}/80-lt-eid.preset
%{_datadir}/p11-kit/modules/lt-eid.module
%{_datadir}/applications/lt-eid-change-pin.desktop
%{_datadir}/icons/hicolor/scalable/apps/lt-eid.svg

%changelog
* Wed Nov 04 2026 Tadas Sasnauskas <tadas@yoyo.lt> - 0.1.0-14
- Applications see a new token after a PIN change, a CAN or a PIN resume
  (the daemon's OpenSC restarts); Firefox no longer needs a restart
- Desktop entry renamed "Change Lithuanian eID PIN", with the lt-eid icon
- Dialogs have headings ("PIN changed", "Allow eID use", ...) instead of
  pinentry's "Message"
- Bundled OpenSC: the cached CAN is kept when PACE fails, e.g. on a bad
  contact or a card pulled out

* Tue Nov 03 2026 Tadas Sasnauskas <tadas@yoyo.lt> - 0.1.0-13
- Change the PIN (eID PIN and PIN.QES together) with lt-eid change-pin, or
  the "Change eID PIN" desktop entry; lt-eidd shows the dialogs
- Bundled OpenSC: lteid-tool --new-pin

* Tue Nov 03 2026 Tadas Sasnauskas <tadas@yoyo.lt> - 0.1.0-12
- Resume the eID PIN suspended after two wrong tries with the cached CAN as
  part of the next login, instead of failing with CKR_PIN_LOCKED

* Tue Nov 03 2026 Tadas Sasnauskas <tadas@yoyo.lt> - 0.1.0-11
- Drop PACE capable pin pad reader support (lteid driver patch and PIN entry
  on the reader): no such readers for general use

* Fri Oct 30 2026 Tadas Sasnauskas <tadas@yoyo.lt> - 0.1.0-10
- Bundled OpenSC: notice a card removed and inserted again while no
  application used it; it failed with CKR_DEVICE_REMOVED until seen absent

* Fri Oct 30 2026 Tadas Sasnauskas <tadas@yoyo.lt> - 0.1.0-9
- With a PIN pad reader, let the reader ask for PINs and show a notification
  pointing there; fall back to the PIN dialog where the reader can't do it

* Fri Oct 30 2026 Tadas Sasnauskas <tadas@yoyo.lt> - 0.1.0-8
- Bundled OpenSC: support PACE capable pin pad readers in the lteid driver

* Wed Oct 28 2026 Tadas Sasnauskas <tadas@yoyo.lt> - 0.1.0-7
- Cache the token list in lt-eidd: OpenSC reads the PIN retry counters from
  the card for every token query, which made listing tokens take seconds

* Wed Oct 28 2026 Tadas Sasnauskas <tadas@yoyo.lt> - 0.1.0-6
- Log lt-eidd clients, dialogs and their outcomes, logins and signatures

* Tue Oct 27 2026 Tadas Sasnauskas <tadas@yoyo.lt> - 0.1.0-5
- Start lt-eid-signing-server only through its socket, not at login

* Tue Oct 27 2026 Tadas Sasnauskas <tadas@yoyo.lt> - 0.1.0-4
- Add lt-eid-signing-server, the Elpako Signer stand-in from lithuanian-eid,
  ported to Rust and using the card through the lt-eid PKCS#11 module

* Mon Oct 26 2026 Tadas Sasnauskas <tadas@yoyo.lt> - 0.1.0-3
- License lt-eid under LGPL-2.1-or-later, like OpenSC

* Mon Oct 26 2026 Tadas Sasnauskas <tadas@yoyo.lt> - 0.1.0-2
- Ask for the CAN when a card the cached CAN does not open is inserted
- Run lt-eidd (and its socket) only in a regular user's desktop session

* Sat Oct 24 2026 Tadas Sasnauskas <tadas@yoyo.lt> - 0.1.0-1
- First package: proxy module, lt-eidd and a private OpenSC in /opt/lt-eid
