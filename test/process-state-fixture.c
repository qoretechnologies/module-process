// Copyright 2026 Qore Technologies, s.r.o.; SPDX-License-Identifier: MIT
// Linux test interposer: model /proc races after a successful kill(pid, 0).
#define _GNU_SOURCE
#include <assert.h>
#include <dlfcn.h>
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

static _Thread_local int disappeared;

int kill(pid_t pid, int signal) {
    if (pid == getpid() && signal == 0 && disappeared) {
        errno = ESRCH;
        return -1;
    }
    int (*real_kill)(pid_t, int) = dlsym(RTLD_NEXT, "kill");
    assert(real_kill);
    return real_kill(pid, signal);
}

static ssize_t disappeared_read(void* cookie, char* buffer, size_t size) {
    (void)cookie;
    (void)buffer;
    (void)size;
    disappeared = 1;
    errno = ESRCH;
    return -1;
}

FILE* fopen(const char* path, const char* mode) {
    char target[64];
    snprintf(target, sizeof(target), "/proc/%d/stat", getpid());
    const char* scenario = getenv("PROCESS_STAT_FIXTURE");
    if (scenario && strcmp(path, target) == 0 && strcmp(mode, "r") == 0) {
        if (strcmp(scenario, "missing") == 0 || strcmp(scenario, "removed") == 0
                || strcmp(scenario, "denied") == 0 || strcmp(scenario, "unavailable") == 0) {
            disappeared = strcmp(scenario, "missing") == 0 || strcmp(scenario, "removed") == 0;
            errno = strcmp(scenario, "missing") == 0 ? ENOENT
                : strcmp(scenario, "removed") == 0 ? ESRCH
                : strcmp(scenario, "unavailable") == 0 ? ENOENT : EACCES;
            return NULL;
        }
        if (strcmp(scenario, "removed-after-open") == 0) {
            cookie_io_functions_t functions = {.read = disappeared_read};
            return fopencookie(NULL, "r", functions);
        }
        const char* content;
        if (strcmp(scenario, "zombie") == 0) {
            content = "123 (child) Z 1 2 3\n";
        } else if (strcmp(scenario, "dead") == 0) {
            content = "123 (child) X 1 2 3\n";
        } else if (strcmp(scenario, "parentheses") == 0) {
            content = "123 (child (with) parens) X 1 2 3\n";
        } else if (strcmp(scenario, "running") == 0) {
            content = "123 (child) R 1 2 3\n";
        } else if (strcmp(scenario, "sleeping") == 0) {
            content = "123 (child) S 1 2 3\n";
        } else if (strcmp(scenario, "malformed") == 0) {
            content = "123 no-command-field\n";
        } else if (strcmp(scenario, "truncated") == 0) {
            content = "123 (child) ";
        } else {
            assert(strcmp(scenario, "empty") == 0);
            content = "";
        }
        return fmemopen((void*)content, strlen(content), "r");
    }
    FILE* (*real_fopen)(const char*, const char*) = dlsym(RTLD_NEXT, "fopen");
    assert(real_fopen);
    return real_fopen(path, mode);
}
