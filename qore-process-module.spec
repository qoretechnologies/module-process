# Copyright (C) 2026 Qore Technologies, s.r.o.
# SPDX-License-Identifier: MIT
# Use the pinned source epoch for RPM headers and installed file timestamps.
%global source_date_epoch_from_changelog 1
%global use_source_date_epoch_as_buildtime 1
%if v"%{rpmversion}" >= v"4.20"
%global build_mtime_policy clamp_to_source_date_epoch
%else
%global clamp_mtime_to_source_date_epoch 1
%endif
%bcond_without tests
%bcond_without docs
%if 0%{?fedora}
%bcond_without system_boost
%else
%bcond_with system_boost
%endif
Name: qore-process-module
Version: 2.1.0
Release: 1%{?dist}
Summary: Child process control and system process information for Qore
License: MIT AND BSL-1.0
URL: https://github.com/qoretechnologies/module-process
Source0: %{name}-%{version}.tar.xz
BuildRequires: cmake >= 3.8
BuildRequires: make
BuildRequires: gcc-c++
%if %{with system_boost}
# Match the patched Boost.Process implementation's exact dependency release.
BuildRequires: boost-devel = 1.90.0
Provides: bundled(boost-process) = 1.90.0
%else
# EL10 and Leap provide older Boost releases; retain the matched vendored tree.
Provides: bundled(boost) = 1.90.0
%endif
%if %{with tests}
BuildRequires: python3
BuildRequires: procps
%endif
BuildRequires: qore-devel >= 3.0.0~
BuildRequires: qore-rpm-macros >= 3.0.0~
%if %{with docs}
BuildRequires: doxygen
%if 0%{?suse_version}
BuildRequires: util-linux
%else
BuildRequires: util-linux-core
%endif
%endif

%description
Child process creation, input/output streams, environment management, signals,
pipelines and process resource information. The package retains the patched
Boost.Process implementation needed for correct process argument handling.

%if %{with docs}
%package doc
Summary: Process module reference documentation and examples
BuildArch: noarch
%description doc
API reference and examples for Qore's process control module.
%endif

%prep
%autosetup
%build
%{?set_build_flags}
. %{_rpmconfigdir}/qore/module-env.sh
qore_set_source_prefix_maps "%{qore_debug_source_dir}"
cmake -S . -B build -G 'Unix Makefiles' \
  -DCMAKE_BUILD_TYPE=Release -DCMAKE_CXX_FLAGS_RELEASE=-DNDEBUG \
  -DCMAKE_INSTALL_PREFIX=%{_prefix} \
  -DUSE_SYSTEM_BOOST_DEPENDENCIES=%{?with_system_boost:ON}%{!?with_system_boost:OFF} \
  -DCMAKE_SKIP_RPATH=ON -DCMAKE_IGNORE_PREFIX_PATH=/usr/local \
  -DQore_DIR=%{_libdir}/cmake/Qore -DQORE_EXECUTABLE=/usr/bin/qore \
  -DQORE_QPP_EXECUTABLE=/usr/bin/qpp \
  -DCMAKE_DISABLE_FIND_PACKAGE_Doxygen=%{!?with_docs:ON}%{?with_docs:OFF}
cmake --build build -- %{?_smp_mflags}
%if %{with docs}
printf "\nWARN_AS_ERROR = FAIL_ON_WARNINGS\n" >> build/Doxyfile
cmake --build build --target docs -- %{?_smp_mflags}
%endif
%install
DESTDIR=%{buildroot} cmake --install build
chmod 755 %{buildroot}%{_libdir}/qore-modules/process-api-*.qmod
%if %{with docs}
install -d %{buildroot}%{_docdir}/%{name}-doc
cp -a build/docs/process/html %{buildroot}%{_docdir}/%{name}-doc/
install -d %{buildroot}%{_docdir}/%{name}-doc/examples/test
install -m644 test/*.qtest test/*.q %{buildroot}%{_docdir}/%{name}-doc/examples/test/
hardlink -t -O %{buildroot}%{_docdir}/%{name}-doc
%endif
%check
%if %{with tests}
. %{_rpmconfigdir}/qore/module-env.sh
timeout 600 /usr/bin/qore -b --enable-debug \
  -l "$PWD/build/process-api-$(/usr/bin/qore --latest-module-api).qmod" test/process.qtest -v
%endif
%files
%license COPYING 3rd_party/boost/LICENSE_1_0.txt
%doc README
%{_libdir}/qore-modules/process-api-*.qmod
%dir %{_datadir}/qore/metadata/process
%{_datadir}/qore/metadata/process/*.meta.json
%if %{with docs}
%files doc
%license COPYING
%doc %{_docdir}/%{name}-doc/
%endif
%changelog
* Thu Oct 01 2026 David Nichols <david@qore.org> - 2.1.0-1
- Package process control, metadata, documentation and the complete local suite.
