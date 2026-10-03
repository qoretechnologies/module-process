#!/usr/bin/env python3
# Copyright (C) 2026 Qore Technologies, s.r.o.
# SPDX-License-Identifier: LGPL-2.1-or-later
"""Black-box Linux parent-exit ownership checks against a built process module.

Usage: python3 test/parent-exit.py --qore /path/to/qore --module-dir build
Every test owns its supervisor and leaf processes; pidfds protect cleanup against
PID reuse, and this runner acts as their subreaper so no zombies are left behind.
"""
import argparse
import ctypes
import json
import os
from pathlib import Path
import select
import signal
import subprocess
import tempfile
import time


def wait_ready(path, parent):
    end = time.monotonic() + 5
    while time.monotonic() < end:
        if parent.poll() is not None:
            raise AssertionError('supervisor exited before readiness: ' + parent.stderr.read().decode())
        if path.exists():
            text = path.read_text()
            if text.endswith('\n'):
                return int(text)
        time.sleep(0.01)
    raise AssertionError('no process readiness record')


def reap_owned_children():
    """Remove direct and newly adopted descendants of this dedicated subreaper."""
    deadline = time.monotonic() + 10
    children_file = Path(f'/proc/self/task/{os.getpid()}/children')
    while time.monotonic() < deadline:
        children = [int(value) for value in children_file.read_text().split()]
        if not children:
            return
        for pid in children:
            try:
                fd = os.pidfd_open(pid)
            except ProcessLookupError:
                continue
            try:
                try:
                    signal.pidfd_send_signal(fd, signal.SIGKILL)
                except ProcessLookupError:
                    pass
                if select.select([fd], [], [], 0.1)[0]:
                    try:
                        os.waitpid(pid, os.WNOHANG)
                    except ChildProcessError:
                        pass
            finally:
                os.close(fd)
    raise AssertionError('owned descendants remain after cleanup')


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--qore', type=Path, required=True)
    parser.add_argument('--module-dir', type=Path, required=True)
    args = parser.parse_args()
    if not hasattr(os, 'pidfd_open') or not hasattr(signal, 'pidfd_send_signal'):
        raise SystemExit('Linux pidfds are required')
    libc = ctypes.CDLL(None, use_errno=True)
    if libc.prctl(36, 1, 0, 0, 0):  # PR_SET_CHILD_SUBREAPER: this test process only
        raise OSError(ctypes.get_errno(), 'cannot become test subreaper')
    qore = str(args.qore.resolve(strict=True))
    env = {**os.environ, 'QORE_MODULE_DIR': str(args.module_dir.resolve(strict=True))}
    with tempfile.TemporaryDirectory(prefix='process-parent-exit-') as tmp:
        root = Path(tmp)
        for mode in ('disabled', 'enabled', 'cascade', 'thread-exit'):
            enabled = 'False' if mode == 'disabled' else 'True'
            leaves = []
            directory = root / mode
            directory.mkdir()
            records = [directory / 'child']
            command, arguments = '/bin/sleep', '("300",)'
            if mode == 'cascade':
                records.append(directory / 'grandchild')
                child_code = ('%modern\n%requires process >= 2.2\n'
                    'Process leaf("/bin/sleep", ("300",), {"kill_on_parent_exit": True});\n'
                    'File f(); f.open2(' + json.dumps(str(records[1])) + ', O_CREAT|O_EXCL|O_WRONLY, 0600); '
                    'f.write(sprintf("%d\\n", leaf.id())); f.close(); leaf.wait();')
                command, arguments = qore, '("-e", ' + json.dumps(child_code) + ')'
            spawn = ('Process child(' + json.dumps(command) + ', ' + arguments + ', '
                '{"kill_on_parent_exit": ' + enabled + '});\n'
                'File f(); f.open2(' + json.dumps(str(records[0])) + ', O_CREAT|O_EXCL|O_WRONLY, 0600); '
                'f.write(sprintf("%d\\n", child.id())); f.close();\n')
            source = '%modern\n%requires process >= 2.2\n'
            if mode == 'thread-exit':
                # The child remains attached until the driver records its pidfd, then stdin releases this
                # launching thread. detach() alone does not cancel the kernel lifetime binding.
                source += ('Counter ready(1); Counter release(1); Counter done(1);\n'
                    'background sub () {' + spawn + 'ready.dec(); release.waitForZero(); child.detach(); done.dec();}();\n'
                    'ready.waitForZero(); File input(); input.open2("/dev/stdin", O_RDONLY); input.read(1); '
                    'release.dec(); done.waitForZero(); Counter keep(1); keep.waitForZero();')
            else:
                source += spawn + 'child.wait();'
            parent = subprocess.Popen([qore, '-e', source], env=env, stdin=subprocess.PIPE,
                                      stdout=subprocess.DEVNULL, stderr=subprocess.PIPE)
            try:
                for record in records:
                    pid = wait_ready(record, parent)
                    fd = os.pidfd_open(pid)
                    leaves.append((pid, fd))
                if mode == 'thread-exit':
                    parent.stdin.write(b'x');parent.stdin.flush()
                else:
                    parent.kill();parent.wait(timeout=5)
                for pid, fd in leaves:
                    dead = bool(select.select([fd], [], [], 0.2 if mode == 'disabled' else 5)[0])
                    assert dead == (mode != 'disabled'), (mode, 'unexpected child lifetime', pid)
                if mode == 'thread-exit':
                    assert parent.poll() is None, 'the process must outlive the launching thread'
                print('PASS', mode, flush=True)
            finally:
                if parent.poll() is None:
                    parent.kill()
                parent.wait(timeout=5)
                for _, fd in leaves:
                    os.close(fd)
                reap_owned_children()
                parent.stdin.close();parent.stderr.close()
        # Invalid option types are rejected before launching an executable.
        source = '%modern\n%requires process >= 2.2\nProcess p("/bin/true", {"kill_on_parent_exit": "yes"});'
        result = subprocess.run([qore, '-e', source], env=env, capture_output=True, text=True, timeout=5)
        assert result.returncode != 0 and 'PROCESS-OPTION-ERROR' in result.stderr
        print('PASS invalid option rejected')
    print('All parent-exit checks passed; owned processes reaped and files removed')


if __name__ == '__main__':
    main()
