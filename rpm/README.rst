RPM packaging
=============

Copyright 2026 Qore Technologies, s.r.o.

The canonical qore-process-module.spec supports Fedora, Enterprise Linux and
openSUSE. It requires the Qore 3.0 SDK and qore-rpm-macros from the same repository.
The default build includes module tests and a separate documentation package.
Dependencies on the installed Qore ABI and SDK version are generated from the
built module; do not replace them with an unversioned qore dependency.

Prepare a pinned source bundle with qore-packaging, then build it in the target
distribution with networking disabled::

    python3 tools/packaging.py prepare --repo ../module-process --ref COMMIT \
      --name qore-process-module --version 2.1.0 \
      --spec qore-process-module.spec --output work/process-source
    python3 tools/build-local.py --source work/process-source \
      --image TARGET_SDK_IMAGE --output results/process-build --jobs 2

These commands run from the qore-packaging repository. Source preparation uses
the committed tree. Install the SDK's language documentation index for complete
Doxygen cross-references. --without docs and --without tests are available for
local diagnosis; repository qualification uses the defaults and also runs the
suite against installed RPMs outside the checkout. Native modules retain the
distribution's normal ELF stripping and separate debug packages.

To verify installed RPMs from a checkout without loading its module sources::

    QORE_RPM_TEST_TMP=/tmp/process-installed rpm/tests-installed/runtime

Use a fresh temporary directory. This copies only the tests and their child
process helpers, clears development search paths and runs the complete suite
against the installed module. Run this in a minimal runtime image without the
Qore SDK as well as in the build image.

Fedora uses Boost 1.90 headers and Boost.Filesystem from the distribution, with
the patched Boost.Process implementation retained privately. EL10 (Boost 1.83)
and Leap 16 (Boost 1.86) use the committed, matched Boost 1.90 tree. No separate
Boost library is installed. The --with/--without system_boost option selects the
path explicitly; an exact CMake version check prevents mixing incompatible
headers. Both paths pass the same 57-case process suite on the Fedora candidate
SDK; qualification on the other targets remains required.

The vendored implementation contains Linux empty-command-line and macOS argument
parsing fixes absent from upstream Boost 1.90. Do not replace it with an unpatched
system Boost.Process library. Runtime notices include the Boost Software License.
The complete local suite exercises process lifetime, signals, pipes, environment,
resource limits, sandboxing and error cases. No service or network access is needed.
