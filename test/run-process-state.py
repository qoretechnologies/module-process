#!/usr/bin/env python3
# Copyright 2026 Qore Technologies, s.r.o.; SPDX-License-Identifier: MIT
"""Exercise Linux PID disappearance through the built module's public API."""
import argparse
import os
from pathlib import Path
import subprocess
import tempfile

parser = argparse.ArgumentParser(description=__doc__)
parser.add_argument("--module", required=True, type=Path)
parser.add_argument("--qore", default="qore")
parser.add_argument("--valgrind", action="store_true")
args = parser.parse_args()
source = Path(__file__).resolve().parent
with tempfile.TemporaryDirectory(prefix="qore-process-state-") as temporary:
    library = Path(temporary) / "fixture.so"
    subprocess.run(["cc", "-std=c11", "-O2", "-g", "-Wall", "-Wextra", "-Werror",
                    "-shared", "-fPIC", str(source / "process-state-fixture.c"),
                    "-ldl", "-o", str(library)], check=True)
    command = [args.qore, "-b", "--enable-debug", "-l", str(args.module.resolve()),
               str(source / "process-state.qtest"), "-v"]
    if args.valgrind:
        command = ["valgrind", "--leak-check=full", "--show-leak-kinds=all",
                   "--errors-for-leak-kinds=definite,indirect,possible",
                   "--error-exitcode=97", "--track-fds=yes", *command]
    for scenario in ("missing", "removed", "removed-after-open", "zombie", "dead",
                     "parentheses", "running", "sleeping", "denied", "unavailable", "malformed",
                     "truncated", "empty"):
        environment = {**os.environ, "LD_PRELOAD": str(library), "PROCESS_STAT_FIXTURE": scenario}
        print("Checking", scenario, flush=True)
        subprocess.run(command, env=environment, check=True, timeout=120)
