// Copyright 2026 Qore Technologies, s.r.o.; SPDX-License-Identifier: MIT
// Test interposer: the SIGCHLD handlers installed with sigaction() never see SIGCHLD.
//
// A process-directed SIGCHLD is delivered to one thread only.  A thread that accepts it without running the handler
// takes it from every other consumer: the signal thread of the Qore library waits for SIGCHLD with sigwait() and
// discards it, and on macOS the kernel hands the signal to that thread whenever the first thread of the process has
// it blocked (for example while it runs a signal handler).  Several children ending while one SIGCHLD is pending also
// raise it once.  This interposer makes that loss deterministic: every SIGCHLD is counted and dropped before it
// reaches the handler that was installed, as if another thread had taken it.  At exit, the number of signals dropped
// is written to the file named by SIGCHLD_LOST_FIXTURE_REPORT, so that the runner can check that the fixture was
// active: a line with the PID, the number of SIGCHLD handlers installed, and the number of signals dropped.  Where
// the end of a child is watched with a process descriptor (Linux with pidfd_open()), no SIGCHLD handler is installed.
#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <signal.h>
#include <stdatomic.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#ifndef __APPLE__
#include <dlfcn.h>
#endif

static atomic_int installed;
static atomic_int dropped;

static void drop_sigchld(int sig) {
    (void)sig;
    atomic_fetch_add(&dropped, 1);
}

static void drop_sigchld_info(int sig, siginfo_t* info, void* context) {
    (void)info;
    (void)context;
    drop_sigchld(sig);
}

#ifdef __APPLE__
#define REAL_SIGACTION sigaction
static int fixture_sigaction(int sig, const struct sigaction* act, struct sigaction* oact)
#else
static int (*real_sigaction)(int, const struct sigaction*, struct sigaction*);
#define REAL_SIGACTION real_sigaction
int sigaction(int sig, const struct sigaction* act, struct sigaction* oact)
#endif
{
#ifndef __APPLE__
    if (!real_sigaction) {
        real_sigaction = (int (*)(int, const struct sigaction*, struct sigaction*))dlsym(RTLD_NEXT, "sigaction");
        if (!real_sigaction) {
            errno = ENOSYS;
            return -1;
        }
    }
#endif
    if (sig == SIGCHLD && act) {
        struct sigaction replacement = *act;
        if (act->sa_flags & SA_SIGINFO) {
            atomic_fetch_add(&installed, 1);
            replacement.sa_sigaction = drop_sigchld_info;
            return REAL_SIGACTION(sig, &replacement, oact);
        }
        if (act->sa_handler != SIG_DFL && act->sa_handler != SIG_IGN) {
            atomic_fetch_add(&installed, 1);
            replacement.sa_handler = drop_sigchld;
            return REAL_SIGACTION(sig, &replacement, oact);
        }
    }
    return REAL_SIGACTION(sig, act, oact);
}

#ifdef __APPLE__
__attribute__((used, section("__DATA,__interpose"))) static const struct {
    const void* replacement;
    const void* replaced;
} fixture_interpose[] = {
    {(const void*)fixture_sigaction, (const void*)sigaction},
};
#endif

__attribute__((destructor)) static void report_dropped(void) {
    const char* path = getenv("SIGCHLD_LOST_FIXTURE_REPORT");
    if (!path || !*path) {
        return;
    }
    int fd = open(path, O_WRONLY | O_CREAT | O_APPEND | O_CLOEXEC, 0600);
    if (fd == -1) {
        return;
    }
    char buf[64];
    int len = snprintf(buf, sizeof buf, "%d %d %d\n", (int)getpid(), atomic_load(&installed), atomic_load(&dropped));
    if (len > 0) {
        (void)!write(fd, buf, (size_t)len);
    }
    close(fd);
}
