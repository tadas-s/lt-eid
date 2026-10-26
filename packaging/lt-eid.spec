# Sources: run packaging/make-sources.sh first.

%global ltdir /opt/lt-eid

%global opensc_commit 58e466043
%global opensc_snapdate 20261021
%global opensc_version 0.27.1^%{opensc_snapdate}git%{opensc_commit}

# Everything under /opt/lt-eid is private: provide nothing to other packages.
%global __provides_exclude_from ^%{ltdir}/.*$

Name:           lt-eid
Version:        0.1.0
Release:        1%{?dist}
Summary:        Lithuanian eID card access through one central daemon

# lt-eid itself: not chosen yet. OpenSC: LGPL-2.1-or-later AND BSD-3-Clause.
# Vendored Rust crates: see cargo-licenses.txt.
License:        LicenseRef-TBD AND LGPL-2.1-or-later AND BSD-3-Clause
Source0:        %{name}-%{version}.tar.gz
Source1:        %{name}-%{version}-vendor.tar.xz
Source2:        opensc-%{opensc_version}.tar.gz
# Build libopensc into opensc-pkcs11.so and the tools; install no libopensc.so.
Patch0:         opensc-static-libopensc.patch

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
BuildRequires:  openpace-devel >= 1.1.4
BuildRequires:  systemd-rpm-macros

# OpenSC loads libpcsclite with dlopen(), so no automatic dependency.
Requires:       pcsc-lite
Requires:       pcsc-lite-libs%{?_isa}
# The version tested with the lteid driver.
Requires:       openpace%{?_isa} >= 1.1.4
Requires:       pinentry
Recommends:     pinentry-gnome3
Requires:       p11-kit

Provides:       bundled(opensc) = %{opensc_version}

%description
Applications (browsers, signing tools) load a small PKCS#11 module that
forwards to lt-eidd, a per-user daemon. The daemon owns the only connection
to the Lithuanian eID card through a private OpenSC build, asks for PINs
itself and lets applications use the card only with the user's approval.

%prep
%setup -q -a 1
%setup -q -T -D -a 2
mv opensc-0.27.1 opensc
%patch -P0 -p1 -d opensc
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
# Cargo names it lib<crate>.so; install it under the name it is known by.
install -Dpm 0755 target/release/liblt_eid_pkcs11.so $r/lib/lt-eid-pkcs11.so

install -Dpm 0644 systemd/lt-eidd.socket %{buildroot}%{_userunitdir}/lt-eidd.socket
install -Dpm 0644 systemd/lt-eidd.service %{buildroot}%{_userunitdir}/lt-eidd.service
install -Dpm 0644 packaging/80-lt-eid.preset %{buildroot}%{_userpresetdir}/80-lt-eid.preset
install -Dpm 0644 packaging/lt-eid.module %{buildroot}%{_datadir}/p11-kit/modules/lt-eid.module

cp -p opensc/COPYING COPYING.opensc
cat vendor/*/Cargo.toml | sed -n 's/^license = //p' | sort | uniq -c > cargo-licenses.txt

%post
%systemd_user_post lt-eidd.socket

%preun
%systemd_user_preun lt-eidd.socket

%files
%license COPYING.opensc cargo-licenses.txt
%doc README.md
%dir %{ltdir}
%dir %{ltdir}/bin
%dir %{ltdir}/lib
%dir %{ltdir}/etc
%{ltdir}/bin/lt-eidd
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
%{_userpresetdir}/80-lt-eid.preset
%{_datadir}/p11-kit/modules/lt-eid.module

%changelog
* Sat Oct 24 2026 Tadas Sasnauskas <tadas@yoyo.lt> - 0.1.0-1
- First package: proxy module, lt-eidd and a private OpenSC in /opt/lt-eid
