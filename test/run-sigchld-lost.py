#!/usr/bin/env python3
# Copyright 2026 Qore Technologies, s.r.o.; SPDX-License-Identifier: MIT
"""Check that the end of a child is reported when no SIGCHLD reaches a handler (see sigchld-lost-fixture.c)."""
import argparse
import os
from pathlib import Path
import platform
import subprocess
import sys
import tempfile

parser = argparse.ArgumentParser(description=__doc__)
parser.add_argument("--module", required=True, type=Path)
parser.add_argument("--qore", default="qore")
parser.add_argument("--exec-mode", action="append", dest="exec_modes",
                    help="Qore execution modes to run (default: ast, ir, jit, tiered)")
parser.add_argument("--valgrind", action="store_true")
parser.add_argument("--timeout", type=int, default=300,
                    help="seconds after which a run counts as hung (a wait that missed its child never ends)")
args = parser.parse_args()
source = Path(__file__).resolve().parent
darwin = platform.system() == "Darwin"
with tempfile.TemporaryDirectory(prefix="qore-process-sigchld-") as temporary:
    library = Path(temporary) / ("fixture.dylib" if darwin else "fixture.so")
    build = ["cc", "-std=c11", "-O2", "-g", "-Wall", "-Wextra", "-Werror", str(source / "sigchld-lost-fixture.c"),
             "-o", str(library)]
    build[1:1] = ["-dynamiclib"] if darwin else ["-shared", "-fPIC"]
    if not darwin:
        build.append("-ldl")
    subprocess.run(build, check=True)
    failed = []
    for mode in args.exec_modes or ("ast", "ir", "jit", "tiered"):
        report = Path(temporary) / f"report-{mode}.txt"
        command = [args.qore, "-b", "--enable-debug", f"--exec-mode={mode}", "-l", str(args.module.resolve()),
                   str(source / "sigchld-lost.qtest"), "-v"]
        if args.valgrind:
            command = ["valgrind", "--leak-check=full", "--show-leak-kinds=all",
                       "--errors-for-leak-kinds=definite,indirect,possible",
                       "--error-exitcode=97", "--track-fds=yes", *command]
        environment = {**os.environ, "SIGCHLD_LOST_FIXTURE_REPORT": str(report),
                       ("DYLD_INSERT_LIBRARIES" if darwin else "LD_PRELOAD"): str(library)}
        print("Checking exec mode", mode, flush=True)
        try:
            rc = subprocess.run(command, env=environment, timeout=args.timeout).returncode
        except subprocess.TimeoutExpired:
            print(f"{mode}: hung (no result after {args.timeout}s)", flush=True)
            failed.append(mode)
            continue
        # the fixture must have been active (it reports at exit), and where a SIGCHLD handler was installed, the
        # children's ends raised SIGCHLD and every one was dropped; where the end of a child is watched with a process
        # descriptor (Linux with pidfd_open()), no handler is installed
        fields = report.read_text().split() if report.exists() else []
        installed = sum(int(n) for n in fields[1::3])
        dropped = sum(int(n) for n in fields[2::3])
        status = f"SIGCHLD handlers installed: {installed}, SIGCHLD dropped by the fixture: {dropped}"
        if rc or not fields or (installed and not dropped):
            print(f"{mode}: exit code {rc}, report: {bool(fields)}, {status}", flush=True)
            failed.append(mode)
        else:
            print(f"{mode}: OK ({status})", flush=True)
    if failed:
        sys.exit("failed: " + ", ".join(failed))
