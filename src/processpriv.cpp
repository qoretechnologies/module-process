/*
    Qore Programming Language process Module

    Copyright (C) 2003 - 2026 Qore Technologies, s.r.o.

    Permission is hereby granted, free of charge, to any person obtaining a
    copy of this software and associated documentation files (the "Software"),
    to deal in the Software without restriction, including without limitation
    the rights to use, copy, modify, merge, publish, distribute, sublicense,
    and/or sell copies of the Software, and to permit persons to whom the
    Software is furnished to do so, subject to the following conditions:

    The above copyright notice and this permission notice shall be included in
    all copies or substantial portions of the Software.

    THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
    IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
    FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
    AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
    LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING
    FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER
    DEALINGS IN THE SOFTWARE.
*/

#include "processpriv.h"

#include <unistd.h>
#include <dirent.h>
#include <sched.h>

// std
#include <chrono>
#include <exception>
#include <cctype>
#include <stdexcept>

// boost
#include <boost/numeric/conversion/cast.hpp>
#include <boost/process/v2/ext/cmd.hpp>
#include <boost/process/v2/ext/exe.hpp>

// module
#include "unix-config.h"

DLLLOCAL extern const TypedHashDecl* hashdeclMemorySummaryInfo;
DLLLOCAL extern const TypedHashDecl* hashdeclSystemMemoryInfo;

//! Checks that an active sandbox allows the given access to a file or directory
/** @param path the path
    @param mode the access mode (ex: \c QSEC_READ)
    @param xsink if access is denied, a \c FILESYSTEM-ACCESS-DENIED exception is raised here

    @return 0 if access is allowed, -1 if it is denied
*/
static int check_sandbox_access(const char* path, int mode, ExceptionSink* xsink) {
    QoreSandboxManagerHelper smh(QoreSandboxManagerHelper::Policy);
    if (smh && !smh->checkFilesystemAccess(path, mode, xsink)) {
        return -1;
    }
    return 0;
}

//! Checks that an active sandbox allows the given file or directory to be read
static int check_sandbox_read(const char* path, ExceptionSink* xsink) {
    return check_sandbox_access(path, QSEC_READ, xsink);
}

//! Returns true if an active sandbox allows the given file or directory to be read; raises no exception
/** Used when scanning /proc, where a sandbox can hide entries without failing the scan
*/
static bool sandbox_allows_read(const char* path) {
    ExceptionSink xsink;
    if (check_sandbox_read(path, &xsink)) {
        xsink.clear();
        return false;
    }
    return true;
}

static int page_size = sysconf(_SC_PAGESIZE);

// default I/O buffer size
static constexpr unsigned process_buf_size = 4096;

// Resource limit settings
struct resource_limits {
    bool hasMemory = false;
    rlim_t memory = 0;
    bool hasData = false;
    rlim_t data = 0;
    bool hasStack = false;
    rlim_t stack = 0;
    bool hasCore = false;
    rlim_t core = 0;
    bool hasCpu = false;
    rlim_t cpu = 0;
    bool hasFiles = false;
    rlim_t files = 0;
    bool hasProcesses = false;
    rlim_t processes = 0;
};

struct callback_initializer {
    ResolvedCallReferenceNode* f_on_success;
    ResolvedCallReferenceNode* f_on_setup;
    ResolvedCallReferenceNode* f_on_error;
    ResolvedCallReferenceNode* f_on_fork_error;
    ResolvedCallReferenceNode* f_on_exec_setup;
    ResolvedCallReferenceNode* f_on_exec_error;
    ExceptionSink* xsink;
    bool setNice = false;
    int niceValue = 0;
    resource_limits limits;

    template<typename Launcher = bp::posix::default_launcher>
    DLLLOCAL void on_success(Launcher& launcher, const bp::filesystem::path& executable,
            const char* const* (&cmd_line)) {
        call("on_success", launcher, executable, f_on_success);
    }

    template<typename Launcher = bp::posix::default_launcher>
    DLLLOCAL bp::error_code on_setup(Launcher& launcher, const bp::filesystem::path& executable,
            const char* const* (&cmd_line)) {
        call("on_setup", launcher, executable, f_on_setup);
        return bp::error_code();
    }

    template<typename Launcher = bp::posix::default_launcher>
    DLLLOCAL void on_error(Launcher& launcher, const bp::filesystem::path& executable,
            const char* const* (&cmd_line), const bp::error_code& ec) {
        call("on_error", launcher, executable, f_on_error, ec);
    }

    template<typename Launcher = bp::posix::default_launcher>
    DLLLOCAL void on_fork_error(Launcher& launcher, const bp::filesystem::path& executable,
            const char* const* (&cmd_line), const bp::error_code& ec) {
        call("on_fork_error", launcher, executable, f_on_fork_error, ec);
    }

    template<typename Launcher = bp::posix::default_launcher>
    DLLLOCAL bp::error_code on_exec_setup(Launcher& launcher, const bp::filesystem::path& executable,
            const char* const* (&cmd_line)) {
        // Make this process its own process group leader to isolate it from the parent's
        // process group. This prevents signals sent to the child's process group from
        // affecting the parent and other processes in the parent's group.
        setpgid(0, 0);

        // Set process priority if requested
        if (setNice) {
            errno = 0;
            if (nice(niceValue) == -1 && errno != 0) {
                // nice() can return -1 on success if the new priority is -1
                // so we need to check errno
                return bp::error_code(errno, boost::system::system_category());
            }
        }

        // Set resource limits if requested
        struct rlimit rl;

        if (limits.hasMemory) {
            rl.rlim_cur = rl.rlim_max = limits.memory;
            if (setrlimit(RLIMIT_AS, &rl) != 0) {
#ifdef __APPLE__
                // macOS can reject RLIMIT_AS with EINVAL even for valid values; treat it as unsupported
                if (errno != EINVAL) {
                    return bp::error_code(errno, boost::system::system_category());
                }
#else
                return bp::error_code(errno, boost::system::system_category());
#endif
            }
        }

        if (limits.hasData) {
            rl.rlim_cur = rl.rlim_max = limits.data;
            if (setrlimit(RLIMIT_DATA, &rl) != 0) {
                return bp::error_code(errno, boost::system::system_category());
            }
        }

        if (limits.hasStack) {
            rl.rlim_cur = rl.rlim_max = limits.stack;
            if (setrlimit(RLIMIT_STACK, &rl) != 0) {
                return bp::error_code(errno, boost::system::system_category());
            }
        }

        if (limits.hasCore) {
            rl.rlim_cur = rl.rlim_max = limits.core;
            if (setrlimit(RLIMIT_CORE, &rl) != 0) {
                return bp::error_code(errno, boost::system::system_category());
            }
        }

        if (limits.hasCpu) {
            rl.rlim_cur = rl.rlim_max = limits.cpu;
            if (setrlimit(RLIMIT_CPU, &rl) != 0) {
                return bp::error_code(errno, boost::system::system_category());
            }
        }

        if (limits.hasFiles) {
            rl.rlim_cur = rl.rlim_max = limits.files;
            if (setrlimit(RLIMIT_NOFILE, &rl) != 0) {
                return bp::error_code(errno, boost::system::system_category());
            }
        }

#ifdef RLIMIT_NPROC
        if (limits.hasProcesses) {
            rl.rlim_cur = rl.rlim_max = limits.processes;
            if (setrlimit(RLIMIT_NPROC, &rl) != 0) {
                return bp::error_code(errno, boost::system::system_category());
            }
        }
#endif

        call("on_exec_setup", launcher, executable, f_on_exec_setup);
        return bp::error_code();
    }

    template<typename Launcher = bp::posix::default_launcher>
    DLLLOCAL void on_exec_error(Launcher& launcher, const bp::filesystem::path& executable,
            const char* const* (&cmd_line)) {
        call("on_exec_error", launcher, executable, f_on_exec_error);
    }

private:
    template<typename Launcher = bp::posix::default_launcher>
    DLLLOCAL void call(const char* type, Launcher& launcher, const bp::filesystem::path& executable,
            const ResolvedCallReferenceNode* callref,
            const bp::error_code& ec) const {
        if (!callref) {
            //printd(5, "no handler installed for '%s'\n", executable.c_str());
            return;
        }

        ReferenceHolder<QoreHashNode> report(new QoreHashNode(autoTypeInfo), xsink);
        report->setKeyValue("name", new QoreStringNode(type), xsink);
        report->setKeyValue("exe", new QoreStringNode(executable.c_str()), xsink);
        report->setKeyValue("pid", launcher.pid, xsink);

        // error_code to hash too
        report->setKeyValue("error_code", ec.value(), xsink);
        report->setKeyValue("error_message", new QoreStringNode(ec.message()), xsink);
        report->setKeyValue("error_category", new QoreStringNode(ec.category().name()), xsink);

        ReferenceHolder<QoreListNode> args(new QoreListNode(autoTypeInfo), xsink);
        args->push(report.release(), xsink);
        callref->execValue(*args, xsink);
    }

    template<typename Launcher = bp::posix::default_launcher>
    DLLLOCAL void call(const char* type, Launcher& launcher, const bp::filesystem::path& executable,
            const ResolvedCallReferenceNode* callref) const {
        if (!callref) {
            //printd(5, "no handler installed for '%s'\n", executable.c_str());
            return;
        }

        ReferenceHolder<QoreHashNode> report(new QoreHashNode(autoTypeInfo), xsink);
        report->setKeyValue("name", new QoreStringNode(type), xsink);
        report->setKeyValue("exe", new QoreStringNode(executable.c_str()), xsink);
        report->setKeyValue("pid", launcher.pid, xsink);

        ReferenceHolder<QoreListNode> args(new QoreListNode(autoTypeInfo), xsink);
        args->push(report.release(), xsink);
        callref->execValue(*args, xsink);
    }
};

ProcessPriv::ProcessPriv(pid_t pid, ExceptionSink* xsink) :
        m_asio_ctx(),
        m_in_pipe(m_asio_ctx),
        m_out_pipe(m_asio_ctx),
        m_err_pipe(m_asio_ctx),

        m_in_buf(&bg_xsink),
        m_out_buf(&bg_xsink),
        m_err_buf(&bg_xsink),

        m_in_asiobuf(boost::asio::buffer(m_in_vec)),
        m_out_asiobuf(boost::asio::buffer(m_out_vec)),
        m_err_asiobuf(boost::asio::buffer(m_err_vec)) {
    try {
        if (pid <= 0) {
            throw std::runtime_error("Process PID must be a positive integer");
        }
#ifdef __APPLE__
        // check if process is valid and throw an exception is not
        if (kill(pid, 0)) {
            throw std::runtime_error("Process with PID " + std::to_string(pid) + " does not exist");
        }
#endif
        //printd(5, "ProcessPriv::ProcessPriv(pid: %d)\n", pid);
        m_process = new bp::process(m_asio_ctx.get_executor(), (boost::process::v2::pid_type)pid);
    } catch (const std::exception& ex) {
        xsink->raiseException("PROCESS-CONSTRUCTOR-ERROR", ex.what());
    }
}

ProcessPriv::ProcessPriv(const char* command, const QoreListNode* arguments, const QoreHashNode *opts,
        ExceptionSink* xsink) :
        m_asio_ctx(),
        m_in_pipe(m_asio_ctx),
        m_out_pipe(m_asio_ctx),
        m_err_pipe(m_asio_ctx),

        m_in_buf(&bg_xsink),
        m_out_buf(&bg_xsink),
        m_err_buf(&bg_xsink),

        m_out_vec(process_buf_size),
        m_err_vec(process_buf_size),

        m_in_asiobuf(boost::asio::buffer(m_in_vec)),
        m_out_asiobuf(boost::asio::buffer(m_out_vec)),
        m_err_asiobuf(boost::asio::buffer(m_err_vec)) {
    // parse options
    env_t env = optsEnv(opts, xsink);
    std::string cwd = optsCwd(opts, xsink);

    if (xsink->isException()) {
        return;
    }

    if (opts && opts->existsKey("encoding")) {
        QoreValue n = opts->getKeyValue("encoding");
        if (n.getType() != NT_STRING) {
            xsink->raiseException("PROCESS-OPTION-ERROR", "Process option 'encoding' requires a 'string' argument; "
                "type '%s' instead", n.getTypeName());
            return;
        }
        QoreStringValueHelper str(n);
        enc = QEM.findCreate(str->c_str());
    }

    // Handle shell option - wrap command in sh -c
    // Check this BEFORE optsPath since shell commands shouldn't be searched in PATH
    bool useShell = false;
    std::string shellCommand;
    if (opts && opts->existsKey("shell")) {
        QoreValue n = opts->getKeyValue("shell");
        useShell = n.getAsBool();
    }

    // Get executable path - skip PATH search if using shell
    boost::filesystem::path p;
    if (useShell) {
        // When using shell, the command is passed to /bin/sh -c, not executed directly
        p = command;
    } else {
        p = optsPath(command, opts, xsink);
        if (xsink->isException()) {
            return;
        }
    }

    // Handle nice option
    int niceValue = 0;
    bool setNice = false;
    if (opts && opts->existsKey("nice")) {
        QoreValue n = opts->getKeyValue("nice");
        if (n.getType() != NT_INT) {
            xsink->raiseException("PROCESS-OPTION-ERROR", "Process option 'nice' requires an 'int' argument; "
                "type '%s' instead", n.getTypeName());
            return;
        }
        niceValue = (int)n.getAsBigInt();
        setNice = true;
        // Validate nice range
        if (niceValue < -20 || niceValue > 19) {
            xsink->raiseException("PROCESS-OPTION-ERROR", "Process option 'nice' must be between -20 and 19; "
                "got %d", niceValue);
            return;
        }
    }

    // Handle resource limits option
    resource_limits limits;
    if (opts && opts->existsKey("limits")) {
        QoreValue n = opts->getKeyValue("limits");
        if (n.getType() != NT_HASH) {
            xsink->raiseException("PROCESS-OPTION-ERROR", "Process option 'limits' requires a 'hash' argument; "
                "type '%s' instead", n.getTypeName());
            return;
        }
        const QoreHashNode* limitsHash = n.get<const QoreHashNode>();

        // Helper lambda to get and validate limit values
        auto getLimit = [&](const char* key, bool& hasFlag, rlim_t& value) -> bool {
            if (limitsHash->existsKey(key)) {
                int64 v = limitsHash->getKeyValue(key).getAsBigInt();
                if (v < 0) {
                    xsink->raiseException("PROCESS-OPTION-ERROR",
                        "Process option 'limits.%s' must be a non-negative integer (got " QLLD ")",
                        key, v);
                    return false;
                }
                hasFlag = true;
                value = static_cast<rlim_t>(v);
            }
            return true;
        };

        if (!getLimit("memory", limits.hasMemory, limits.memory)) return;
        if (!getLimit("data", limits.hasData, limits.data)) return;
        if (!getLimit("stack", limits.hasStack, limits.stack)) return;
        if (!getLimit("core", limits.hasCore, limits.core)) return;
        if (!getLimit("cpu", limits.hasCpu, limits.cpu)) return;
        if (!getLimit("files", limits.hasFiles, limits.files)) return;
        if (!getLimit("processes", limits.hasProcesses, limits.processes)) return;
    }

    // not yet supported; not possible to read from an input stream with a timeout or to read all data available
    //optsStdin(opts, xsink);

    int stdoutFD = optsStdout("stdout", opts, xsink);
    int stderrFD = optsStdout("stderr", opts, xsink);
    if (xsink->isException()) {
        return;
    }

    FILE* stdoutFile = nullptr;
    FILE* stderrFile = nullptr;
    if (stdoutFD != -1) {
        stdoutFile = fdopen(stdoutFD, "w");
        if (!stdoutFile) {
            close(stdoutFD);
            xsink->raiseErrnoException("PROCESS-CONSTRUCTOR-ERROR", errno, "failed to create stdout FILE stream");
            return;
        }
    }
    if (stderrFD != -1) {
        stderrFile = fdopen(stderrFD, "w");
        if (!stderrFile) {
            if (stdoutFile) {
                fclose(stdoutFile);
            }
            close(stderrFD);
            xsink->raiseErrnoException("PROCESS-CONSTRUCTOR-ERROR", errno, "failed to create stderr FILE stream");
            return;
        }
    }

    // process exe arguments
    std::vector<std::string> exeArgs;
    boost::filesystem::path effectivePath = p;

    if (useShell) {
        // Build shell command: sh -c "command arg1 arg2 ..."
        shellCommand = p.string();
        if (arguments) {
            ConstListIterator li(arguments);
            while (li.next()) {
                shellCommand += " ";
                QoreStringValueHelper str(li.getValue());
                shellCommand += str->c_str();
            }
        }
        // Use shell as the executable
        effectivePath = "/bin/sh";
        exeArgs.push_back("-c");
        exeArgs.push_back(shellCommand);
    } else {
        processArgs(arguments, exeArgs);
    }

    // the program must be executable and the working directory readable in any sandbox, and the process is not
    // started if the call is cancelled; the output files are closed in all of these cases
    if (check_sandbox_access(effectivePath.string().c_str(), QSEC_EXECUTE, xsink)
            || (opts && opts->existsKey("cwd") && check_sandbox_read(cwd.c_str(), xsink))
            || qore_check_cancel(xsink, "Process::constructor")) {
        if (stdoutFile) {
            fclose(stdoutFile);
        }
        if (stderrFile) {
            fclose(stderrFile);
        }
        return;
    }

    // setup stdout, stderr and stdin closures
    prepareClosures();

    // launch child process
    try {
        launchChild(xsink, effectivePath, exeArgs, env, cwd.c_str(), stdoutFile, stderrFile, opts, setNice, niceValue, limits);
    } catch (const std::exception& ex) {
        // Clean up FILE handles on error
        if (stdoutFile) {
            fclose(stdoutFile);
            stdoutFile = nullptr;
        }
        if (stderrFile) {
            fclose(stderrFile);
            stderrFile = nullptr;
        }
        xsink->raiseException("PROCESS-CONSTRUCTOR-ERROR", ex.what());
    }

    // stop async I/O thread immediately before obliteration if an exception was thrown
    if (*xsink) {
        // Clean up FILE handles on error from launchChild (if not already closed)
        if (stdoutFile) {
            fclose(stdoutFile);
        }
        if (stderrFile) {
            fclose(stderrFile);
        }
        finalizeStreams(xsink);
    }
}

ProcessPriv::~ProcessPriv() {
    // The background I/O thread runs handlers that use the pipes, buffers, and closures of this object and the child
    // process object.  Members are destroyed in reverse order of declaration, which destroys all of them before the
    // future that joins the thread, so the thread must be stopped and joined here, before anything it uses is
    // destroyed.
    if (m_asio_ctx_run_future.valid()) {
        m_asio_ctx.stop();
        m_asio_ctx_run_future.wait();
    }
    // in case the object is obliterated (exception in constructor), the destructor is not run
    delete m_process;
    assert(!bg_xsink);
}

int ProcessPriv::destructor(ExceptionSink* xsink) {
    // rethrows any background exceptions
    finalizeStreams(xsink);

    // delete child process
    if (m_process) {
        delete m_process;
        m_process = nullptr;
    }

    return *xsink ? -1 : 0;
}

ResolvedCallReferenceNode* ProcessPriv::optsExecutor(const char* name, const QoreHashNode* oh, ExceptionSink* xsink) {
    ResolvedCallReferenceNode* ret = nullptr;

    if (oh) {
        if (oh->existsKey(name)) {
            QoreValue n = oh->getKeyValue(name);
            if (n.getType() != NT_RUNTIME_CLOSURE && n.getType() != NT_FUNCREF) {
                xsink->raiseException("PROCESS-OPTION-ERROR",
                    "executor '%s' required code as value, got: '%s'(%d)",
                    name,
                    n.getTypeName(),
                    n.getType()
                );
                return ret;
            }

            ret = n.get<ResolvedCallReferenceNode>();
            ret->refSelf();
        }
    }

    return ret;
}

env_t ProcessPriv::optsEnv(const QoreHashNode* opts, ExceptionSink* xsink) {
    // As agreed - we are not merging current process env. We are replacing.
    // The "merge" can be done with global ENV hash.
    // bp::process_environment ret = bp::environment::current();
    env_t ret;

    if (opts && opts->existsKey("env")) {
        QoreValue n = opts->getKeyValue("env");
        if (n.getType() != NT_HASH) {
            xsink->raiseException("PROCESS-OPTION-ERROR",
                "Environment variables option must be a hash, got: '%s'(%d)",
                n.getTypeName(),
                n.getType()
            );
            return ret;
        }

        ConstHashIterator it(n.get<const QoreHashNode>());
        while (it.next()) {
            QoreStringValueHelper val(it.get());
            ret[it.getKey()] = bp::environment::value(val->c_str());
        }

        return ret;
    }

    for (const auto& i : bp::environment::current()) {
        // copy the environment variables from the current process
        ret[i.key()] = i.value();
    }
    return ret;
}

std::string ProcessPriv::optsCwd(const QoreHashNode* opts, ExceptionSink* xsink) {
    std::string ret(".");

    if (opts && opts->existsKey("cwd")) {
        QoreValue n = opts->getKeyValue("cwd");
        if (n.getType() != NT_STRING) {
            xsink->raiseException("PROCESS-OPTION-ERROR",
                "Working dir 'cwd' option must be a string, got: '%s'(%d)",
                n.getTypeName(),
                n.getType()
            );
            return ret;
        }
        QoreStringValueHelper s(n);
        ret = s->c_str();
    }

    return ret;
}

void ProcessPriv::optsStdin(const QoreHashNode* opts, ExceptionSink* xsink) {
    if (!opts || !opts->existsKey("stdin")) {
        return;
    }
    QoreValue n = opts->getKeyValue("stdin");
    if (n.getType() != NT_OBJECT) {
        xsink->raiseException("PROCESS-OPTION-ERROR",
            "Process constructor option 'stdin' must be an "
            "InputStream object; got type '%s' instead",
            n.getTypeName()
        );
        return;
    }

    // if the above returns NT_OBJECT, then the following line must succeed
    QoreObject* obj = n.get<QoreObject>();

    // see if a usable class is accessible in this call
    ClassAccess access;
    bool in_hierarchy = obj->getClass()->inHierarchy(*QC_INPUTSTREAM, access);
    if (!in_hierarchy || access != Public) {
        xsink->raiseException("PROCESS-OPTION-ERROR", "Process constructor option 'stdin' expecting an object "
            "of class 'OutputStream'; got an object of class '%s' instead",
            obj->getClassName());
        return;
    }

    PrivateDataRefHolder<InputStream> stream(obj, CID_INPUTSTREAM, xsink);
    if (*xsink) {
        // an exception has already been thrown here
        xsink->appendLastDescription(" (while processing Process constructor option 'stdin' expecting "
            "a valid Inputstream object)");
        return;
    }
    stream->unassignThread(xsink);
    m_in_buf.setStream(stream.release());
}

int ProcessPriv::optsStdout(const char* keyName, const QoreHashNode* opts, ExceptionSink* xsink) {
    int ret = -1;

    if (opts && opts->existsKey(keyName)) {
        QoreValue n = opts->getKeyValue(keyName);
        if (n.getType() != NT_OBJECT) {
            xsink->raiseException("PROCESS-OPTION-ERROR",
                "Process constructor option '%s' must be a File object (open for writing) or an "
                "OutputStream object; got type '%s' instead",
                keyName,
                n.getTypeName()
            );
            return -1;
        }

        // if the above returns NT_OBJECT, then the following line must succeed
        QoreObject* obj = n.get<QoreObject>();

        // see if a usable class is accessible in this call
        {
            ClassAccess access;
            bool in_hierarchy = obj->getClass()->inHierarchy(*QC_FILE, access);
            if (!in_hierarchy || access != Public) {
                in_hierarchy = obj->getClass()->inHierarchy(*QC_OUTPUTSTREAM, access);
                if (in_hierarchy && access == Public) {
                    PrivateDataRefHolder<OutputStream> stream(obj, CID_OUTPUTSTREAM, xsink);
                    if (*xsink) {
                        // an exception has already been thrown here
                        xsink->appendLastDescription(" (while processing Process constructor option '%s' expecting "
                            "a valid OutputStream object)", keyName);
                        return -1;
                    }
                    stream->unassignThread(xsink);
                    if (!strcmp(keyName, "stdout")) {
                        m_out_buf.setStream(stream.release());
                    } else {
                        m_err_buf.setStream(stream.release());
                    }
                    return -1;
                } else {
                    xsink->raiseException("PROCESS-OPTION-ERROR", "Process constructor option '%s' expecting an object "
                        "of class 'File' or 'OutputStream'; got an object of class '%s' instead",
                        keyName,
                        obj->getClassName());
                    return -1;
                }
            }
        }

        PrivateDataRefHolder<File> file(obj, CID_FILE, xsink);
        if (*xsink) {
            // an exception has already been thrown here
            xsink->appendLastDescription(" (while processing Process constructor option '%s' expecting a valid File "
                "object open for writing)", keyName);
            return -1;
        }

        if (!file->isOpen()) {
            xsink->raiseException("PROCESS-OPTION-ERROR",
                "Process constructor option '%s' must be an open File object; the File object "
                "passed is not open for writing",
                keyName
            );
            return -1;
        }
        ret = file->detachFd();
    }

    return ret;
}

boost::filesystem::path ProcessPriv::optsPath(const char* command, const QoreHashNode* opts, ExceptionSink* xsink) {
    boost::filesystem::path ret;

    try {
        if (opts && opts->existsKey("path")) {
            QoreValue n = opts->getKeyValue("path");
            if (n.getType() != NT_LIST) {
                xsink->raiseException("PROCESS-OPTION-ERROR",
                    "Path option must be a list of strings, got: '%s'(%d)",
                    n.getTypeName(),
                    n.getType()
                );
                return ret;
            }

            const QoreListNode* l = n.get<const QoreListNode>();
            std::string paths;

            for (qore_size_t i = 0; i < l->size(); i++) {
                QoreStringValueHelper s(l->retrieveEntry(i));
                if (i) {
                    paths.append(":");
                }
                paths.append(s->c_str());
            }

            std::unordered_map<bp::environment::key, bp::environment::value> my_env = {
                {"PATH", bp::environment::value(paths)},
            };

            ret = bp::environment::find_executable(command, my_env);
        } else {
            ret = bp::environment::find_executable(command);
        }
    } catch (std::runtime_error& ex) {
        xsink->raiseException("PROCESS-SEARCH-PATH-ERROR", ex.what());
    	return ret;
    }

    if (ret.empty()) {
        // issue #2524 if the command is already absolute, then use it
        ret = command;
        if (ret.is_absolute())
            return ret;

        ret.clear();
        xsink->raiseException("PROCESS-SEARCH-PATH-ERROR", "Command '%s' cannot be found in PATH", command);
    }
    try {
        ret = boost::filesystem::absolute(ret);
        // searching the path reveals files, so the file found must be readable in any sandbox
        if (check_sandbox_read(ret.string().c_str(), xsink)) {
            ret.clear();
        }
        return ret;
    } catch (const std::exception& ex) {
        xsink->raiseException("PROCESS-DIRECTORY-ERROR", ex.what());
        return ret;
    }
}

bool ProcessPriv::processCheck(ExceptionSink* xsink) {
    if (!m_process) {
        if (xsink) {
            xsink->raiseException("PROCESS-CHECK-ERROR", "Process is not initialized");
        }
        return false;
    }
    return true;
}

bool ProcessPriv::processReadStdoutCheck(ExceptionSink* xsink) {
    if (!processCheck(xsink)) {
        return false;
    }
    if (m_out_buf.hasStream()) {
        if (xsink) {
            xsink->raiseException("PROCESS-STREAM-ERROR", "stdout cannot be read from the process as it's attached " \
                "to an output stream");
        }
        return false;
    }
    return true;
}

bool ProcessPriv::processReadStderrCheck(ExceptionSink* xsink) {
    if (!processCheck(xsink)) {
        return false;
    }
    if (m_err_buf.hasStream()) {
        if (xsink) {
            xsink->raiseException("PROCESS-STREAM-ERROR", "stderr cannot be read from the process as it's attached " \
                "to an output stream");
        }
        return false;
    }
    return true;
}

void ProcessPriv::processArgs(const QoreListNode* arguments, std::vector<std::string>& out) {
    if (arguments) {
        for (qore_size_t i = 0; i < arguments->size(); i++) {
            QoreStringNodeValueHelper s(arguments->retrieveEntry(i));
            // ignore empty args; causes an assert on RHEL 8 in boost arg processing
            if (!s->empty()) {
                out.push_back(s->c_str());
            }
        }
    }
}

void ProcessPriv::prepareStdinBuffer() {
    // fill stdin vector
    m_in_buf.extract(m_in_vec, 4096);

    // create new ASIO buffer
    m_in_asiobuf = boost::asio::buffer(m_in_vec);
}

void ProcessPriv::prepareClosures() {
    // stdout setup
    m_on_stdout_complete = [this](const boost::system::error_code& ec, size_t n) {
        // append read data to output buffer
        m_out_buf.append(m_out_vec.data(), n);

        // continue reading if no error
        if (!ec) {
            boost::asio::async_read(m_out_pipe, m_out_asiobuf, boost::asio::transfer_at_least(1),
                m_on_stdout_complete);
        }
    };

    // stderr setup
    m_on_stderr_complete = [this](const boost::system::error_code& ec, size_t n) {
        // append read data to output buffer
        m_err_buf.append(m_err_vec.data(), n);

        // continue reading if no error
        if (!ec) {
            boost::asio::async_read(m_err_pipe, m_err_asiobuf, boost::asio::transfer_at_least(1),
                m_on_stderr_complete);
        }
    };

    // stdin setup
    m_on_stdin_complete = [this](const boost::system::error_code& ec, size_t n) {
        std::lock_guard<std::mutex> lock(m_async_write_mtx);

        // delete already written data from stdin vector
        m_in_vec.erase(m_in_vec.begin(), m_in_vec.begin() + n);

        // check error
        if (ec) {
            --m_async_write_running;
            return;
        }

        // if there is remaining data, try to write it
        if (m_in_vec.size()) {
            m_in_asiobuf = boost::asio::buffer(m_in_vec);
            boost::asio::async_write(m_in_pipe, m_in_asiobuf, m_on_stdin_complete);
            return;
        }

        // check if there is new data ready to be written
        if (m_in_buf.size()) {
            prepareStdinBuffer();
            boost::asio::async_write(m_in_pipe, m_in_asiobuf, m_on_stdin_complete);
            return;
        }

        --m_async_write_running;
    };
}

/*
struct PreservedFds : boost::process::detail::handler, boost::process::detail::uses_handles {
    std::vector<int> fds;
    PreservedFds() : fds({0, 1, 2}) {
    }

    std::vector<int>& get_used_handles() {
        return fds;
    }
};
*/

void ProcessPriv::launchChild(ExceptionSink* xsink,
        boost::filesystem::path p,
        std::vector<std::string>& args,
        env_t env,
        const char* cwd,
        FILE* stdoutFile,
        FILE* stderrFile,
        const QoreHashNode* opts,
        bool setNice,
        int niceValue,
        const resource_limits& limits) {
    // get handler pointers
    ReferenceHolder<ResolvedCallReferenceNode> f_on_success(optsExecutor("on_success", opts, xsink), xsink);
    if (*xsink) {
        return;
    }
    ReferenceHolder<ResolvedCallReferenceNode> f_on_setup(optsExecutor("on_setup", opts, xsink), xsink);
    if (*xsink) {
        return;
    }
    ReferenceHolder<ResolvedCallReferenceNode> f_on_error(optsExecutor("on_error", opts, xsink), xsink);
    if (*xsink) {
        return;
    }
    ReferenceHolder<ResolvedCallReferenceNode> f_on_fork_error(optsExecutor("on_fork_error", opts, xsink), xsink);
    if (*xsink) {
        return;
    }
    ReferenceHolder<ResolvedCallReferenceNode> f_on_exec_setup(optsExecutor("on_exec_setup", opts, xsink), xsink);
    if (*xsink) {
        return;
    }
    ReferenceHolder<ResolvedCallReferenceNode> f_on_exec_error(optsExecutor("on_exec_error", opts, xsink), xsink);
    if (*xsink) {
        return;
    }

    callback_initializer cbi{
        *f_on_success,
        *f_on_setup,
        *f_on_error,
        *f_on_fork_error,
        *f_on_exec_setup,
        *f_on_exec_error,
        xsink,
        setNice,
        niceValue,
        limits
    };

    bp::process_environment penv = bp::process_environment(env);

    if (stdoutFile && stderrFile) {
        m_process = new bp::process(m_asio_ctx, p.string(), args, cbi,
            bp::process_stdio{m_in_pipe, stdoutFile, stderrFile},
            bp::process_start_dir(cwd),
            penv
        );
    } else if (stdoutFile) {
        m_process = new bp::process(m_asio_ctx, p.string(), args, cbi,
            bp::process_stdio{m_in_pipe, stdoutFile, m_err_pipe},
            bp::process_start_dir(cwd),
            penv
        );
    } else if (stderrFile) {
        m_process = new bp::process(m_asio_ctx, p.string(), args, cbi,
            bp::process_stdio{m_in_pipe, m_out_pipe, stderrFile},
            bp::process_start_dir(cwd),
            penv
        );
    } else {
        m_process = new bp::process(m_asio_ctx, p.string(), args, cbi,
            bp::process_stdio{m_in_pipe, m_out_pipe, m_err_pipe},
            bp::process_start_dir(cwd),
            penv
        );
    }

    m_process->async_wait(
        [this](boost::system::error_code ec, int e) {
            this->setExitCode(ec, e);
        }
    );

    {
        std::unique_lock<std::mutex> lock(mtx_process_status);
        assert(!running_flag);
        running_flag = true;
    }

    // create async read operations
    if (!stdoutFile) {
        boost::asio::async_read(m_out_pipe, m_out_asiobuf, boost::asio::transfer_at_least(1),
            m_on_stdout_complete);
    }
    if (!stderrFile) {
        boost::asio::async_read(m_err_pipe, m_err_asiobuf, boost::asio::transfer_at_least(1),
            m_on_stderr_complete);
    }

    // increment counter before launching thread
    stream_cnt.inc();

    // issue #4303: to avoid a race condition in async I/O where a "dup2() failed" error is raised,
    // we wait until the I/O thread is running before continuing
    QoreCounter started(1);

    // launch async operations
    m_asio_ctx_run_future = std::async(std::launch::async, [this, &started]{
        q_register_foreign_thread();
        ON_BLOCK_EXIT(q_deregister_foreign_thread);

        m_out_buf.reassignThread();
        m_err_buf.reassignThread();

        try {
            // do one non-blocking poll to ensure that everything is in place
            m_asio_ctx.poll_one();
            // signal the parent thread that background I/O is up and running
            started.dec(nullptr);
            // run the background I/O in blocking mode in the dedicated I/O thread
            m_asio_ctx.run();
        } catch (const std::exception& ex) {
            printd(0, "exception in m_asio_ctx.run() in m_asio_ctx_run_future: %s", ex.what());
        }

        m_out_buf.unassignThread();
        m_err_buf.unassignThread();

        // signal that the I/O thread has terminated
        stream_cnt.dec(nullptr);
    });

    // wait for background I/O to be up and running before continuing
    started.waitForZero(nullptr);
}

void ProcessPriv::setExitCode(boost::system::error_code ec, int e) {
    std::unique_lock<std::mutex> lock(mtx_process_status);
    //printd(5, "process::async_wait() (%d: %s) %s; setting running_flag = false (waiting: %d)\n", ec.value(),
    //    ec.category().name(), ec.message().c_str(), process_status_waiting);
    assert(running_flag);
    running_flag = false;
    if (!ec) {
        // Note: boost::process v2 already evaluates the exit code before passing it to the handler
        // (see process.hpp async_wait_op_::operator() which calls evaluate_exit_code())
        // so we should NOT call evaluate_exit_code() again here
        exit_code = e;
    }
    // Cancel pending stdout/stderr reads now that the child has exited. If the child
    // forked grandchildren that inherited the stdio pipes (e.g. "cmd & wait"), those
    // grandchildren keep the write ends open and our async_read would never see EOF,
    // leaving finalizeStreams() blocked in m_asio_ctx_run_future.get() until they
    // eventually exit. Already-delivered data in m_out_buf / m_err_buf is preserved.
    {
        boost::system::error_code cancel_ec;
        m_out_pipe.cancel(cancel_ec);
        m_err_pipe.cancel(cancel_ec);
    }
    if (process_status_waiting) {
        cond_process_status.notify_all();
    }
}

int ProcessPriv::exitCode(ExceptionSink* xsink) {
    if (!processCheck(xsink)) {
        return -1;
    }

    std::lock_guard<std::mutex> lock(mtx_process_status);
    return exit_code;
}

int ProcessPriv::id(ExceptionSink* xsink) {
    if (!processCheck(xsink)) {
        return -1;
    }

    try {
        return detached_pid ? detached_pid : m_process->id();
    } catch (const std::exception& ex) {
        xsink->raiseException("PROCESS-ID-ERROR", ex.what());
    }

    return -1;
}

bool ProcessPriv::valid(ExceptionSink* xsink) {
    if (!processCheck(xsink)) {
        return false;
    }

    return m_process->is_open();
}

bool ProcessPriv::running(ExceptionSink* xsink) {
    if (!processCheck(xsink)) {
        //printd(5, "ProcessPriv::running() processCheck() failed\n");
        return false;
    }

    std::lock_guard<std::mutex> lock(mtx_process_status);
    if (exit_code != -1) {
        return false;
    }

    if (detached_pid) {
        int code = 0;
        while (true) {
            int res = ::waitpid(detached_pid, &code, WNOHANG);
            //printd(5, "ProcessPriv::running() detached PID %d; waitpid() result: %d code: %d exited: %d signaled: %d\n",
            //    detached_pid, res, code, (int)WIFEXITED(code), (int)WIFSIGNALED(code));
            if (res == -1) {
                if (errno == EINTR) {
                    // interrupted by a signal, try again
                    continue;
                }
                // if waitpid() returns -1 with errno == ECHILD, then the process has already exited
                if (errno != ECHILD) {
                    xsink->raiseException("PROCESS-RUNNING-ERROR", "Cannot check detached process with PID %d: %s",
                        detached_pid, strerror(errno));
                }
                return false;
            } else if (!res) {
                return true;
            }
            break;
        }

        if (!WIFEXITED(code) && !WIFSIGNALED(code)) {
            return true;
        }
        //printd(5, "ProcessPriv::running() detached PID %d is not running; exit code: %d\n", detached_pid, code);
        exit_code = WEXITSTATUS(code);

        return false;
    }

    boost::system::error_code ec;
    bool rc = m_process->running(ec);
    // ECHILD is raised with processes created from a PID, so we check it manually
    if (!rc && (ec == std::errc::no_child_process)) {
        //printd(5, "ProcessPriv::running() ECHILD; checking manually\n");
        return checkPid(m_process->id(), xsink);
    }
    //printd(5, "ProcessPriv::running() returning %s\n", rc ? "true" : "false");
    return rc;
}

void ProcessPriv::finalizeStreams(ExceptionSink* xsink) {
    // the asio context is stopped in the process handler unless the process has been detached
    if (detached_pid) {
        m_asio_ctx.stop();
        try {
            m_asio_ctx.run();
        } catch (const std::exception& ex) {
            printd(0, "exception in m_asio_ctx.run() in ProcessPriv::finalizeStreams(): %s", ex.what());
        }
    }

    // wait for future
    if (!m_out_vec.empty() && m_asio_ctx_run_future.valid()) {
        m_asio_ctx_run_future.get();
    }

    stream_cnt.waitForZero(xsink);

    ReferenceHolder<OutputStream> out(xsink);
    ReferenceHolder<OutputStream> err(xsink);

    {
        AutoLocker al(bg_lck);
        if (bg_xsink) {
            xsink->assimilate(bg_xsink);
        }

        out = m_out_buf.finalize(xsink);
        err = m_err_buf.finalize(xsink);
    }
}

QoreStringNode* ProcessPriv::getString(QoreStringNode* str) {
    if (!enc->isMultiByte()) {
        return str;
    }

    // first prepend any buffered bytes to the string
    {
        AutoLocker al(bg_lck);
        if (!charbuf->empty()) {
            str->prepend((const char*)charbuf->getPtr(), charbuf->size());
            charbuf->clear();
        }
    }

    // check for an invalid trailing char
    bool invalid = false;
    size_t len = enc->getLength(str->c_str(), str->c_str() + str->size(), invalid);
    if (invalid) {
        printd(5, "ProcessPriv::getString() INVALID str: '%s' size: %d len: %d\n", str->c_str(), (int)str->size(), (int)len);
        assert(str->size() > len);
        // move invalid bytes to buffer
        charbuf->append(str->c_str() + len, str->size() - len);
        if (!len) {
            str->deref();
            return nullptr;
        }
        str->terminate(len);
    }
    return str;
}

void ProcessPriv::getExitCode(ExceptionSink* xsink) {
    std::lock_guard<std::mutex> lock(mtx_process_status);
    if (exit_code != -1) {
        return;
    }

    assert(m_process);
    try {
        exit_code = m_process->exit_code();
    } catch (const std::exception& ex) {
        xsink->raiseException("PROCESS-EXITCODE-ERROR", ex.what());
    }
}

bool ProcessPriv::wait(ExceptionSink* xsink) {
    if (!processCheck(xsink)) {
        return false;
    }

    // if the child has already exited, only the background I/O needs to finish; without waiting for it, output
    // could still be incomplete, and the I/O thread could still be running when this object is destroyed
    {
        bool exited;
        {
            std::lock_guard<std::mutex> lock(mtx_process_status);
            exited = exit_code != -1;
        }
        if (exited) {
            // rethrows any background exceptions
            finalizeStreams(xsink);
            return true;
        }
    }

    //printd(0, "ProcessPriv::wait() is_open: %d detached_pid: %d exit_code: %d\n", m_process->is_open(),
    //    detached_pid, exit_code);

    try {
        // check for interrupt before blocking wait
        if (qore_check_cancel(xsink, "Process::wait")) {
            return false;
        }

        // wait on detached process
        if (detached_pid) {
            int wstatus;
            while (true) {
                if (waitpid(detached_pid, &wstatus, 0) == -1) {
                    if (errno == ECHILD) {
                        return false;
                    }
                    if (errno == EINTR) {
                        continue;
                    }
                    xsink->raiseException("PROCESS-WAIT-ERROR", "Cannot get exit code for detached process with "
                        "PID %d: %s", detached_pid, strerror(errno));
                    return false;
                }
                break;
            }
            std::unique_lock<std::mutex> lock(mtx_process_status);
            //printd(5, "process::async_wait() (%d: %s) %s; setting running_flag = false (waiting: %d)\n", ec.value(),
            //    ec.category().name(), ec.message().c_str(), process_status_waiting);
            exit_code = WEXITSTATUS(wstatus);
            if (process_status_waiting) {
                cond_process_status.notify_all();
            }
        } else {
            boost::system::error_code ec;
            m_process->wait(ec);
            if (ec && ec != std::errc::no_child_process) {
                xsink->raiseException("PROCESS-WAIT-ERROR", "cannot wait on process: %s", ec.message().c_str());
                return false;
            }

            if (exit_code == -1) {
                // get exit code if possible
                getExitCode(xsink);
            }
        }

        // rethrows any background exceptions
        finalizeStreams(xsink);
        return true;
    } catch (const std::exception& ex) {
        const char* err = ex.what();
        xsink->raiseException("PROCESS-WAIT-ERROR", err);
    }

    return false;
}

bool ProcessPriv::wait(int64 t, ExceptionSink* xsink) {
    if (!processCheck(xsink)) {
        return false;
    }

    // if the child has already exited, only the background I/O needs to finish; without waiting for it, output
    // could still be incomplete, and the I/O thread could still be running when this object is destroyed
    {
        bool exited;
        {
            std::lock_guard<std::mutex> lock(mtx_process_status);
            exited = exit_code != -1;
        }
        if (exited) {
            // rethrows any background exceptions
            finalizeStreams(xsink);
            return true;
        }
    }

    try {
        std::unique_lock<std::mutex> lock(mtx_process_status);
        if (running_flag) {
            // wait for the process to finish
            ++process_status_waiting;
            // use a predicate to handle spurious wakeups
            cond_process_status.wait_for(lock, std::chrono::milliseconds(t),
                [this] {
                    return !running_flag;
                });
            --process_status_waiting;

            if (running_flag) {
                return false;
            }
        }
        // rethrows any background exceptions
        finalizeStreams(xsink);
        return true;
    } catch (const std::exception& ex) {
        const char* err = ex.what();
        xsink->raiseException("PROCESS-WAIT-ERROR", err);
    }

    return false;
}

bool ProcessPriv::detach(ExceptionSink* xsink) {
    if (!processCheck(xsink)) {
        return false;
    }

    try {
        detached_pid = m_process->id();
        m_process->detach();
    } catch (const std::exception& ex) {
        const char* err = ex.what();
        xsink->raiseException("PROCESS-WAIT-ERROR", err);
        detached_pid = 0;
        return false;
    }
    return true;
}

bool ProcessPriv::sendSignal(int sig, ExceptionSink* xsink) {
    if (!processCheck(xsink)) {
        return false;
    }

#ifdef HAVE_KILL
    int pid = detached_pid ? detached_pid : m_process->id();
    // CRITICAL: Validate PID before calling kill()
    // If pid is -1 (invalid/moved-from process), kill(-1, sig) would kill ALL user processes!
    // pid=0 would send signal to all processes in the process group.
    if (pid <= 0) {
        xsink->raiseException("PROCESS-SIGNAL-ERROR",
            "cannot send signal: PID must be positive (got %d); non-positive PIDs have special meanings to kill()",
            pid);
        return false;
    }
    if (kill(pid, sig) == -1) {
        switch (errno) {
            case EPERM:
                xsink->raiseException("PROCESS-SIGNAL-ERROR", "insufficient permissions to send signal %d to PID %d",
                    sig, pid);
                break;
            case ESRCH:
                xsink->raiseException("PROCESS-SIGNAL-ERROR", "process with PID %d does not exist", pid);
                break;
            default:
                xsink->raiseErrnoException("PROCESS-SIGNAL-ERROR", errno, "cannot send signal %d to PID %d", sig, pid);
                break;
        }
        return false;
    }
    return true;
#else
    xsink->raiseException("PROCESS-SIGNAL-UNSUPPORTED-ERROR", "sending signals is not supported on this platform");
    return false;
#endif
}

bool ProcessPriv::terminate(ExceptionSink* xsink) {
    if (!processCheck(xsink)) {
        return false;
    }

    if (detached_pid) {
        // CRITICAL: Validate PID before calling kill()
        if (detached_pid <= 0) {
            xsink->raiseException("PROCESS-TERMINATE-ERROR", "cannot terminate invalid process (pid=%d)", detached_pid);
            return false;
        }
        if (kill(detached_pid, SIGKILL) == -1) {
            xsink->raiseException("PROCESS-TERMINATE-ERROR", "Cannot terminate process: %s",
                strerror(errno));
            return false;
        }
        return true;
    }

    // CRITICAL: Validate PID before calling boost::process terminate
    // boost::process::terminate() directly calls kill(pid, SIGKILL) without validation
    // If pid is -1 (invalid/moved-from process), this would kill ALL user processes!
    int pid = m_process->id();
    if (pid <= 0) {
        xsink->raiseException("PROCESS-TERMINATE-ERROR", "cannot terminate invalid process (pid=%d)", pid);
        return false;
    }

    boost::system::error_code ec;
    m_process->terminate(ec);

    //printd(5, "ProcessPriv::terminate() ec: %d (%s): %s\n", ec.value(), ec.category().name(),
    //    ec.message().c_str());

    if (ec) {
        // ECHILD is raised with the wait() call after the process has been terminated
        if (ec.value() == ECHILD) {
            std::lock_guard<std::mutex> lock(mtx_process_status);
            if (exit_code == -1) {
                // Process was killed by signal, set exit code to indicate termination
                exit_code = 128 + SIGKILL;
            }
            return true;
        }
        xsink->raiseException("PROCESS-TERMINATE-ERROR", "Cannot terminate process: (%d: %s) %s",
            ec.value(), ec.category().name(), ec.message().c_str());
        return false;
    }
    return true;
}

QoreStringNode* ProcessPriv::readStderr(size_t n, ExceptionSink* xsink) {
    if (!processReadStderrCheck(xsink)) {
        return nullptr;
    }

    // check size to read
    if (n <= 0)
        return nullptr;

    try {
        SimpleRefHolder<QoreStringNode> str(new QoreStringNode(enc));
        size_t read = m_err_buf.read(*str, n);
        if (read)
            return getString(str.release());
    } catch (const std::exception& ex) {
        xsink->raiseException("PROCESS-READ-ERROR", ex.what());
    }

    return nullptr;
}

QoreStringNode* ProcessPriv::readStderrTimeout(size_t n, int64 millis, ExceptionSink* xsink) {
    if (!processReadStderrCheck(xsink)) {
        return nullptr;
    }

    // check size to read
    if (n <= 0)
        return nullptr;

    try {
        SimpleRefHolder<QoreStringNode> str(new QoreStringNode(enc));
        size_t read = m_err_buf.readTimeout(*str, n, millis);
        if (read)
            return getString(str.release());
    } catch (const std::exception& ex) {
        xsink->raiseException("PROCESS-READ-ERROR", ex.what());
    }

    return nullptr;
}

QoreStringNode* ProcessPriv::readStdout(size_t n, ExceptionSink* xsink) {
    if (!processReadStdoutCheck(xsink)) {
        return nullptr;
    }

    // check size to read
    if (n <= 0)
        return nullptr;

    try {
        SimpleRefHolder<QoreStringNode> str(new QoreStringNode(enc));
        size_t read = m_out_buf.read(*str, n);
        if (read)
            return getString(str.release());
    } catch (const std::exception& ex) {
        xsink->raiseException("PROCESS-READ-ERROR", ex.what());
    }

    return nullptr;
}

QoreStringNode* ProcessPriv::readStdoutTimeout(size_t n, int64 millis, ExceptionSink* xsink) {
    if (!processReadStdoutCheck(xsink)) {
        return nullptr;
    }

    // check size to read
    if (n <= 0)
        return nullptr;

    try {
        SimpleRefHolder<QoreStringNode> str(new QoreStringNode(enc));
        size_t read = m_out_buf.readTimeout(*str, n, millis);
        if (read)
            return getString(str.release());
    } catch (const std::exception& ex) {
        xsink->raiseException("PROCESS-READ-ERROR", ex.what());
    }

    return nullptr;
}

BinaryNode* ProcessPriv::readStderrBinary(size_t n, ExceptionSink* xsink) {
    if (!processReadStderrCheck(xsink)) {
        return nullptr;
    }

    // check size to read
    if (n <= 0)
        return nullptr;

    try {
        SimpleRefHolder<BinaryNode> bin(new BinaryNode);
        size_t read = m_err_buf.read(*bin, n);
        if (read)
            return bin.release();
    } catch (const std::exception& ex) {
        xsink->raiseException("PROCESS-READ-ERROR", ex.what());
    }

    return nullptr;
}

BinaryNode* ProcessPriv::readStderrBinaryTimeout(size_t n, int64 millis, ExceptionSink* xsink) {
    if (!processReadStderrCheck(xsink)) {
        return nullptr;
    }

    // check size to read
    if (n <= 0)
        return nullptr;

    try {
        SimpleRefHolder<BinaryNode> bin(new BinaryNode);
        size_t read = m_err_buf.readTimeout(*bin, n, millis);
        if (read)
            return bin.release();
    } catch (const std::exception& ex) {
        xsink->raiseException("PROCESS-READ-ERROR", ex.what());
    }

    return nullptr;
}

BinaryNode* ProcessPriv::readStdoutBinary(size_t n, ExceptionSink* xsink) {
    if (!processReadStdoutCheck(xsink)) {
        return nullptr;
    }

    // check size to read
    if (n <= 0)
        return nullptr;

    try {
        SimpleRefHolder<BinaryNode> bin(new BinaryNode);
        size_t read = m_out_buf.read(*bin, n);
        if (read)
            return bin.release();
    } catch (const std::exception& ex) {
        xsink->raiseException("PROCESS-READ-ERROR", ex.what());
    }

    return nullptr;
}

BinaryNode* ProcessPriv::readStdoutBinaryTimeout(size_t n, int64 millis, ExceptionSink* xsink) {
    if (!processReadStdoutCheck(xsink)) {
        return nullptr;
    }

    // check size to read
    if (n <= 0)
        return nullptr;

    try {
        SimpleRefHolder<BinaryNode> bin(new BinaryNode);
        size_t read = m_out_buf.readTimeout(*bin, n, millis);
        if (read)
            return bin.release();
    } catch (const std::exception& ex) {
        xsink->raiseException("PROCESS-READ-ERROR", ex.what());
    }

    return nullptr;
}

void ProcessPriv::write(const char* val, size_t n, ExceptionSink* xsink) {
    if (!processCheck(xsink)) {
        return;
    }

    if (!val || !n)
        return;

    // write data to internal buffer
    m_in_buf.write(val, n);

    // check if there is async_write operation running
    std::lock_guard<std::mutex> lock(m_async_write_mtx);
    if (m_async_write_running)
        return;

    // if there is not, start a new one
    prepareStdinBuffer();
    boost::asio::async_write(m_in_pipe, m_in_asiobuf, m_on_stdin_complete);
    ++m_async_write_running;
}

void ProcessPriv::closeStdin(ExceptionSink* xsink) {
    if (!processCheck(xsink)) {
        return;
    }

    // wait for any pending writes to complete
    {
        std::unique_lock<std::mutex> lock(m_async_write_mtx);
        // wait for pending writes to complete (simple spin with sleep)
        while (m_async_write_running > 0) {
            lock.unlock();
            usleep(1000);  // 1ms
            lock.lock();
        }
    }

    // close the stdin pipe
    boost::system::error_code ec;
    m_in_pipe.close(ec);
    if (ec) {
        xsink->raiseException("PROCESS-CLOSESTDIN-ERROR", "failed to close stdin pipe: %s", ec.message().c_str());
    }
}

#ifdef __linux__
#include <cstring>
#include <inttypes.h>
#include <sys/user.h>

constexpr size_t BUFSIZE = 4096;
constexpr int TIMEOUT_MS = 1000; // 1 second timeout for reading

QoreHashNode* ProcessPriv::getMemorySummaryInfoLinux(int pid, ExceptionSink* xsink) {
    // open memory map for file
    QoreFile f(QCS_USASCII);

    {
        QoreStringMaker str("/proc/%d/statm", pid);
        if (f.open(str.c_str())) {
            xsink->raiseErrnoException("PROCESS-GETMEMORYINFO-ERROR", errno, "could not read process status for "
                "PID %d", pid);
            return nullptr;
        }
    }

    int64 vsz = 0;
    int64 rss = 0;

    QoreString l;
    if (!f.readLine(l)) {
        // format: vsz rss shared text lib data dt
        // find space after vsz
        qore_offset_t pos = l.find(' ');
        assert(pos != -1);
        // find space after rss
        qore_offset_t pos1 = l.find(' ', pos + 1);
        l.terminate(pos1);
        rss = strtoll(l.c_str() + pos + 1, nullptr, 10) * page_size;
        l.terminate(pos);
        vsz = l.toBigInt() * page_size;
    }

    ReferenceHolder<QoreHashNode> rv(new QoreHashNode(hashdeclMemorySummaryInfo, xsink), xsink);

    rv->setKeyValue("vsz", vsz, xsink);
    rv->setKeyValue("rss", rss, xsink);

    {
        // see if this kernel support /proc/PID/smaps_rollup
        QoreStringMaker str("/proc/%d/smaps_rollup", pid);
        if (f.open(str.c_str())) {
            // if not, try to read /proc/PID/smaps
            return getMemorySummaryInfoLinuxSmaps(xsink, pid, f, rv);
        }
    }

    SimpleRefHolder<QoreStringNode> str(new QoreStringNode(QCS_USASCII));
    char buf[BUFSIZE];

    while (true) {
        size_t len = f.read(buf, BUFSIZE, TIMEOUT_MS, xsink);
        if (*xsink) {
            return nullptr;
        }
        if (!len) {
            break;
        }
        str->concat(buf, len);
    }

    if (!str->size()) {
        xsink->raiseException("PROCESS-GETMEMORYINFO-ERROR", "Could not read memory map for PID %d", pid);
        return nullptr;
    }

    ssize_t pos = str->find("Pss:");
    if (pos == -1) {
        xsink->raiseException("PROCESS-GETMEMORYINFO-ERROR", "Could not find PSS in memory map for PID %d", pid);
        return nullptr;
    }
    // get PSS value
    pos += 2; // skip "PSS:"
    char c;
    do {
        ++pos;
        c = (**str)[pos];
        if (!c) {
            xsink->raiseException("PROCESS-GETMEMORYINFO-ERROR", "PSS value missing in memory map for PID %d", pid);
            return nullptr;
        }
    } while (!isdigit(c));

    // read in PSS value
    int64 pss = strtoll(str->c_str() + pos, nullptr, 10) * 1024; // convert to bytes

    rv->setKeyValue("priv", pss, xsink);

    return rv.release();
}

QoreHashNode* ProcessPriv::getMemorySummaryInfoLinuxSmaps(ExceptionSink* xsink, int pid, QoreFile& f,
        ReferenceHolder<QoreHashNode>& rv) {
    {
        QoreStringMaker str("/proc/%d/smaps", pid);
        if (f.open(str.c_str())) {
            xsink->raiseErrnoException("PROCESS-GETMEMORYINFO-ERROR", errno, "could not read virtual shared memory "
                "map '%s' for PID %d", str.c_str(), pid);
            return nullptr;
        }
    }

    int64 priv_size = 0;
    bool need_line = true;

    // FIXME: reading smaps line by line will result in an inconsistnt result; the entire smap needs to be read into
    // a single buffer in one read, but the kernel buffer is not big enough to allow this in many cases, so this
    // version if inherently unreliable in any case
    while (true) {
        QoreString l;
        if (need_line && f.readLine(l)) {
            break;
        }

        // smaps map line format: 0=start-end 1=perms 2=offset 3=device 4=inode 5=pathname
        // ex: 01f1c000-01f3d000 rw-p 00000000 00:00 0                                  [heap]

        // find memory range separator
        qore_offset_t pos = l.find('-');
        assert(pos != -1);

        // find end of memory range
        qore_offset_t pos1 = l.find(' ', pos + 1);
        assert(pos1 != -1);

        int64 segment_size = 0;

        size_t start;
        {
            QoreString num(&l, pos);
            start = strtoll(num.c_str(), nullptr, 16);
        }

        size_t end;
        {
            QoreString num(l.c_str() + pos + 1, pos1 - pos - 1);
            end = strtoll(num.c_str(), nullptr, 16);
        }

        // get end of offset
        pos = l.find(' ', pos1 + 6);
        assert(pos != -1);

        // get end of device
        pos = l.find(' ', pos + 1);
        assert(pos != -1);

        // get end of inode
        pos1 = l.find(' ', ++pos);

        segment_size = (end - start);

        // read in segment attributes
        size_t pss = 0;
        bool eof = false;
        while (true) {
            if (f.readLine(l)) {
                eof = true;
                break;
            }

            if (islower(l[0])) {
                need_line = false;
                break;
            }

            if (segment_size && l.equalPartial("Pss:")) {
                QoreString num(l.c_str() + 4);
                pss = strtoll(num.c_str(), nullptr, 10);
                priv_size += pss * 1024;
                //printd(5, "smaps: segment referenced size: %lld '%s'\n", priv_size, num.c_str());
                continue;
            }

            if (l.equalPartial("VmFlags:")) {
                break;
            }
        }
        if (eof) {
            break;
        }
    }

    rv->setKeyValue("priv", priv_size, xsink);

    return rv.release();
}
#endif

#if defined(__APPLE__) && defined(__MACH__)
#include <libproc.h>

#include <mach/mach_init.h>
#include <mach/mach_host.h>
#include <mach/host_priv.h>
#include <mach/mach_error.h>
#include <mach/mach_traps.h>
#include <mach/mach_vm.h>
#include <mach/mach_port.h>
#include <mach/vm_region.h>
#include <mach/vm_page_size.h>
#include <mach/task.h>
#include <mach/task_info.h>

QoreHashNode* ProcessPriv::getMemorySummaryInfoDarwin(int pid, ExceptionSink* xsink) {
    // we use proc_taskinfo() to get VSZ and RSS, but only PRIV is interesting for us
    struct proc_taskinfo taskinfo;

    int rc = proc_pidinfo(pid, PROC_PIDTASKINFO, 0, &taskinfo, sizeof(taskinfo));
    if (rc <= 0) {
        xsink->raiseException("PROCESS-GETMEMORYINFO-ERROR", "proc_pidinfo() returned %d", rc);
        return nullptr;
    }

    //printd(5, "proc_pidinfo() rc %d vsz: " QLLD " rss: " QLLD "\n", rc, taskinfo.pti_virtual_size,
    //    taskinfo.pti_resident_size);

    ReferenceHolder<QoreHashNode> rv(new QoreHashNode(hashdeclMemorySummaryInfo, xsink), xsink);

    rv->setKeyValue("vsz", taskinfo.pti_virtual_size, xsink);
    rv->setKeyValue("rss", taskinfo.pti_resident_size, xsink);

    // NOTE: task_for_pid() requires special permissions to get a task port for any task except
    // the current PID; root can do it, or the process can have a special entitlement that allows
    // any task to be acquired.  The entitlement required for this is: com.apple.system-task-ports
    // (ex: codesign -d --entitlements - /usr/bin/vmmap)
    mach_port_t task;
    // do not free the port allocated here
    kern_return_t kr = task_for_pid(mach_task_self(), pid, &task);
    if (kr != KERN_SUCCESS) {
        xsink->raiseException("PROCESS-GETMEMORYINFO-ERROR", "task_for_pid() returned %d: %s", (int)kr,
            mach_error_string(kr));
        return nullptr;
    }

    size_t priv_size = 0;
    mach_vm_address_t addr = 0;

    while (true) {
        // this approach of determining private memory per process is taken from the Darwin top sources:
        // https://opensource.apple.com/source/top/top-111.1.1/
        vm_region_top_info_data_t info;
        mach_msg_type_number_t count = VM_REGION_TOP_INFO_COUNT;
        mach_vm_size_t vmsize = 0;
        memory_object_name_t object_name;

        kr = mach_vm_region(task, &addr, &vmsize, VM_REGION_TOP_INFO,
            (vm_region_info_t)&info, &count, &object_name);
        if (kr == KERN_INVALID_ADDRESS)
            break;
        if (kr != KERN_SUCCESS) {
            xsink->raiseException("PROCESS-GETMEMORYINFO-ERROR", "mach_vm_region() returned %d: %s", (int)kr,
                mach_error_string(kr));
            return nullptr;
        }
        //printd(0, "addr: %p size: %ld share_mode: %d\n", addr, vmsize, info.share_mode);
        // should not happen
        if (!vmsize) {
            xsink->raiseException("PROCESS-GETMEMORYINFO-ERROR", "mach_vm_region() returned vmsize 0");
            return nullptr;
        }

        if (info.share_mode == SM_COW && info.ref_count == 1) {
            // Treat single reference SM_COW as SM_PRIVATE
            info.share_mode = SM_PRIVATE;
        }

        switch (info.share_mode) {
            case SM_LARGE_PAGE:
                // Treat SM_LARGE_PAGE the same as SM_PRIVATE
                // since they are not shareable and are wired.
            case SM_PRIVATE:
                priv_size += vmsize;
                break;

            // Darwin's top has a more complicated method of processing SM_COW
            // but we are not interested in kernel processes etc
            case SM_COW:
                priv_size += info.private_pages_resident * vm_kernel_page_size;
                break;
        }

        addr = addr + vmsize;
        if (!addr)
            break;
    }

    rv->setKeyValue("priv", priv_size, xsink);

    return rv.release();
}

#endif

#ifdef __sun__
#include <libproc.h>
#include <procfs.h>
QoreHashNode* ProcessPriv::getMemorySummaryInfoSolaris(int pid, ExceptionSink* xsink) {
    psinfo_t psp;
    prmap_t prp;
    size_t vsz, rss;
    size_t priv_size = 0;
    ssize_t read_ret;
    int prmap_fd;

    if (proc_get_psinfo(pid, &psp) == -1) {
        xsink->raiseException("PROCESS-GETMEMORYINFO-ERROR", "proc_get_psinfo could not read process status for "
            "PID %d", pid);
        return nullptr;
    }

    QoreStringMaker prmap_path("/proc/%d/map", pid);
    if (check_sandbox_read(prmap_path.c_str(), xsink)) {
        return nullptr;
    }
    prmap_fd = open(prmap_path.c_str(), O_RDONLY);
    if (prmap_fd == -1) {
        xsink->raiseErrnoException("PROCESS-GETMEMORYINFO-ERROR", errno, "could not open virtual shared memory "
            "map '%s' for PID %d", prmap_path.c_str(), pid);
        return nullptr;
    }

    while ((read_ret = read(prmap_fd, &prp, sizeof(prp))) == sizeof(prp)) {
        if ((prp.pr_mflags & MA_SHARED) == 0) {
            priv_size += prp.pr_size;
        }
    }

    switch (read_ret) {
        case 0:
            break;
        case -1:
            xsink->raiseErrnoException("PROCESS-GETMEMORYINFO-ERROR", errno, "could not read virtual shared memory "
                "map '%s' for PID %d", prmap_path.c_str(), pid);
            close(prmap_fd);
            return nullptr;
            break;
        default:
            xsink->raiseException("PROCESS-GETMEMORYINFO-ERROR", "failed to read a prmap structure from '%s' for "
                "PID %d, only read %d bytes\n", prmap_path.c_str(), pid, read_ret);
            close(prmap_fd);
            return nullptr;
    }

    close(prmap_fd);

    vsz = psp.pr_size * 1024;
    rss = psp.pr_rssize * 1024;

    ReferenceHolder<QoreHashNode> rv(new QoreHashNode(hashdeclMemorySummaryInfo, xsink), xsink);

    rv->setKeyValue("vsz", vsz, xsink);
    rv->setKeyValue("rss", rss, xsink);
    rv->setKeyValue("priv", priv_size, xsink);

    return rv.release();
}
#endif

QoreHashNode* ProcessPriv::getMemorySummaryInfo(int pid, ExceptionSink* xsink) {
#ifdef __linux__
    return getMemorySummaryInfoLinux(pid, xsink);
#elif defined(__APPLE__) && defined(__MACH__)
    return getMemorySummaryInfoDarwin(pid, xsink);
#elif defined(__sun__)
    return getMemorySummaryInfoSolaris(pid, xsink);
#else
    xsink->raiseException("PROCESS-GETMEMORYINFO-UNSUPPORTED-ERROR", "this call is not supported on this platform");
    return nullptr;
#endif
}

#if defined(__linux__)
#include <cstdio>

//! Check if a process is a zombie by reading /proc/<pid>/stat
/** @return true if the process is a zombie, false otherwise (including if /proc is unavailable)
*/
static bool isZombie(int pid) {
    char path[32];
    snprintf(path, sizeof(path), "/proc/%d/stat", pid);

    // a process that a sandbox does not allow to be inspected is not reported as a zombie
    if (!sandbox_allows_read(path)) {
        return false;
    }
    FILE* f = fopen(path, "r");
    if (!f) {
        return false;
    }

    char buf[512];
    size_t n = fread(buf, 1, sizeof(buf) - 1, f);
    fclose(f);

    if (!n) {
        return false;
    }
    buf[n] = '\0';

    // Parse /proc/PID/stat: "pid (comm) state ..."
    // comm can contain spaces and parentheses, so find the LAST ')'
    const char* end_paren = strrchr(buf, ')');
    if (!end_paren || end_paren[1] != ' ') {
        return false;
    }

    // State character is right after ") "
    return end_paren[2] == 'Z';
}

#elif defined(__APPLE__) && defined(__MACH__)
#include <sys/sysctl.h>

//! Check if a process is a zombie via sysctl (macOS/Darwin)
static bool isZombie(int pid) {
    struct kinfo_proc kp;
    size_t len = sizeof(kp);
    int mib[4] = {CTL_KERN, KERN_PROC, KERN_PROC_PID, pid};
    if (sysctl(mib, 4, &kp, &len, nullptr, 0) == -1 || len == 0) {
        return false;
    }
    return kp.kp_proc.p_stat == SZOMB;
}

#elif defined(__FreeBSD__) || defined(__DragonFly__)
#include <sys/sysctl.h>
#include <sys/user.h>

//! Check if a process is a zombie via sysctl (FreeBSD/DragonFlyBSD)
static bool isZombie(int pid) {
    struct kinfo_proc kp;
    size_t len = sizeof(kp);
    int mib[4] = {CTL_KERN, KERN_PROC, KERN_PROC_PID, pid};
    if (sysctl(mib, 4, &kp, &len, nullptr, 0) == -1 || len == 0) {
        return false;
    }
    return kp.ki_stat == SZOMB;
}

#elif defined(__NetBSD__)
#include <sys/sysctl.h>

//! Check if a process is a zombie via sysctl (NetBSD)
static bool isZombie(int pid) {
    struct kinfo_proc2 kp;
    size_t len = sizeof(kp);
    int mib[6] = {CTL_KERN, KERN_PROC2, KERN_PROC_PID, pid, (int)sizeof(kp), 1};
    if (sysctl(mib, 6, &kp, &len, nullptr, 0) == -1 || len == 0) {
        return false;
    }
    return kp.p_stat == SZOMB;
}

#elif defined(__OpenBSD__)
#include <sys/sysctl.h>

//! Check if a process is a zombie via sysctl (OpenBSD)
static bool isZombie(int pid) {
    struct kinfo_proc kp;
    size_t len = sizeof(kp);
    int mib[6] = {CTL_KERN, KERN_PROC, KERN_PROC_PID, pid, (int)sizeof(kp), 1};
    if (sysctl(mib, 6, &kp, &len, nullptr, 0) == -1 || len == 0) {
        return false;
    }
    return kp.p_stat == SZOMB;
}
#endif

bool ProcessPriv::checkPid(int pid, ExceptionSink* xsink) {
#ifdef HAVE_KILL
    // CRITICAL: Validate PID before calling kill()
    // pid <= 0 has special meanings to kill() and must be rejected
    if (pid <= 0) {
        xsink->raiseException("PROCESS-CHECKPID-ERROR",
            "cannot check invalid PID: PID must be positive (got %d)", pid);
        return false;
    }
    if (kill(pid, 0)) {
        return false;
    }
#if defined(__linux__) || (defined(__APPLE__) && defined(__MACH__)) || defined(__FreeBSD__) \
    || defined(__DragonFly__) || defined(__NetBSD__) || defined(__OpenBSD__)
    // kill(pid, 0) returns success for zombie processes because the PID still exists
    // in the process table; check the process state for zombie status
    if (isZombie(pid)) {
        return false;
    }
#endif
    return true;
#else
    xsink->raiseException("PROCESS-CHECKPID-UNSUPPORTED-ERROR", "this call is not supported on this platform");
    return false;
#endif
}

#ifdef HAVE_KILL
#include <unistd.h>
#include <sys/wait.h>

// 250ms poll interval when waiting for a process to terminate
#define WAIT_POLL_US 250000
#endif

void ProcessPriv::terminate(int pid, ExceptionSink* xsink) {
#ifdef HAVE_KILL
    // CRITICAL: Validate PID before calling kill()
    // If pid <= 0, kill() has special meanings:
    //   pid = -1: kill ALL processes we can signal (CATASTROPHIC!)
    //   pid = 0: kill all processes in our process group
    //   pid < -1: kill all processes in process group |pid|
    if (pid <= 0) {
        xsink->raiseException("PROCESS-TERMINATE-ERROR",
            "cannot terminate invalid process: PID must be positive (got %d); "
            "non-positive PIDs have special meanings to kill()", pid);
        return;
    }
    if (kill(pid, SIGKILL)) {
        switch (errno) {
            case EPERM:
                xsink->raiseException("PROCESS-TERMINATE-ERROR", "insufficient permissions to terminate PID %d", pid);
                break;
            case ESRCH:
            default:
                xsink->raiseErrnoException("PROCESS-INVALID-PID", errno, "no process with PID %d can be found", pid);
                break;
        }
    }
    // now we call waitpid in case the program killed was a child process
    // in case not, errors are ignored here
    int status;
    while (true) {
        int res = ::waitpid(pid, &status, 0);
        if ((res == -1) && (errno == EINTR)) {
            continue;
        }
        break;
    }
#else
    xsink->raiseException("PROCESS-TERMINATE-UNSUPPORTED-ERROR", "this call is not supported on this platform");
#endif
}

void ProcessPriv::waitForTermination(int pid, ExceptionSink* xsink) {
#ifdef HAVE_KILL
    // CRITICAL: Validate PID before calling kill()
    // pid <= 0 has special meanings to kill() and must be rejected
    if (pid <= 0) {
        xsink->raiseException("PROCESS-WAITFORTERMINATION-ERROR",
            "cannot wait for invalid PID: PID must be positive (got %d)", pid);
        return;
    }
    while (true) {
        // check for interrupt during poll wait
        if (qore_check_cancel(xsink, "Process::waitForTermination")) {
            return;
        }
        if (kill(pid, 0)) {
            break;
        }
#if defined(__linux__) || (defined(__APPLE__) && defined(__MACH__)) || defined(__FreeBSD__) \
    || defined(__DragonFly__) || defined(__NetBSD__) || defined(__OpenBSD__)
        // kill(pid, 0) returns success for zombie processes; check process state
        if (isZombie(pid)) {
            break;
        }
#endif
        usleep(WAIT_POLL_US);
    }
#else
    xsink->raiseException("PROCESS-WAITFORTERMINATION-UNSUPPORTED-ERROR", "this call is not supported on this "
        "platform");
#endif
}

#if defined(__linux__)
#include <sys/stat.h>

int64 ProcessPriv::getDescriptorCount(ExceptionSink* xsink, int pid) {
    // NOTE from https://docs.kernel.org/filesystems/proc.html
    // "The number of open files for the process is stored in ‘size’ member of stat() output for /proc/<pid>/fd for
    // fast access"
    QoreStringMaker dir("/proc/%d/fd", pid);
    if (check_sandbox_read(dir.c_str(), xsink)) {
        return -1;
    }
    struct stat statbuf;
    int rc = stat(dir.c_str(), &statbuf);
    if (rc < 0) {
        xsink->raiseErrnoException("PROCESS-GETDESCRIPTORCOUNT-ERROR", errno, "could not read file descriptor count "
            "for PID %d", pid);
        return -1;
    }
    return statbuf.st_size;
}
#endif

#if defined(__APPLE__) && defined(__MACH__)
#include <libproc.h>

int64 ProcessPriv::getDescriptorCount(ExceptionSink* xsink, int pid) {
    int count;
    while (true) {
        int bufsize = proc_pidinfo(pid, PROC_PIDLISTFDS, 0, nullptr, 0);
        if (bufsize <= 0) {
            xsink->raiseErrnoException("PROCESS-GETDESCRIPTORCOUNT-ERROR", errno, "could not read file descriptor "
                "count for PID %d", pid);
            return -1;
        }
        // we have the max allocated size, now we need to find the actual number of descriptors by making a real call
        void* buf = malloc(bufsize);
        if (!buf) {
            xsink->raiseException("PROCESS-GETDESCRIPTORCOUNT-ERROR", "could not allocate memory for file descriptor "
                "buffer for PID %d", pid);
            return -1;
        }
        ON_BLOCK_EXIT(free, buf);
        count = proc_pidinfo(pid, PROC_PIDLISTFDS, 0, buf, bufsize);
        if (count <= 0) {
            xsink->raiseErrnoException("PROCESS-GETDESCRIPTORCOUNT-ERROR", errno, "could not read file descriptor "
                "count for PID %d", pid);
            return -1;
        }
        if (count > bufsize) {
            printd(0, "ProcessPriv::getDescriptorCount() count %d > bufsize %d for PID %d; retrying\n", count,
                bufsize, pid);
            continue;
        }
        break;
    }

    return count / sizeof(proc_fdinfo);
}
#endif

#if !defined(__linux__) && (!defined(__APPLE__) || !defined(__MACH__))
int64 ProcessPriv::getDescriptorCount(ExceptionSink* xsink, int pid) {
    xsink->raiseException("PROCESS-GETDESCRIPTORCOUNT-UNSUPPORTED-ERROR", "this call is not supported on this "
        "platform");
    return -1;
}
#endif

#include <sys/resource.h>

static QoreHashNode* rusageToHash(const struct rusage& ru, ExceptionSink* xsink) {
    ReferenceHolder<QoreHashNode> rv(new QoreHashNode(autoTypeInfo), xsink);

    // Convert timeval to float seconds
    double user_time = ru.ru_utime.tv_sec + (ru.ru_utime.tv_usec / 1000000.0);
    double system_time = ru.ru_stime.tv_sec + (ru.ru_stime.tv_usec / 1000000.0);

    rv->setKeyValue("user_time", user_time, xsink);
    rv->setKeyValue("system_time", system_time, xsink);

    // On Linux, ru_maxrss is in kilobytes; on macOS it's in bytes
#if defined(__APPLE__) && defined(__MACH__)
    rv->setKeyValue("max_rss", (int64)ru.ru_maxrss, xsink);
#else
    rv->setKeyValue("max_rss", (int64)ru.ru_maxrss * 1024, xsink);
#endif

    rv->setKeyValue("shared_size", (int64)ru.ru_ixrss, xsink);
    rv->setKeyValue("unshared_data_size", (int64)ru.ru_idrss, xsink);
    rv->setKeyValue("unshared_stack_size", (int64)ru.ru_isrss, xsink);
    rv->setKeyValue("minor_faults", (int64)ru.ru_minflt, xsink);
    rv->setKeyValue("major_faults", (int64)ru.ru_majflt, xsink);
    rv->setKeyValue("swaps", (int64)ru.ru_nswap, xsink);
    rv->setKeyValue("block_input", (int64)ru.ru_inblock, xsink);
    rv->setKeyValue("block_output", (int64)ru.ru_oublock, xsink);
    rv->setKeyValue("messages_sent", (int64)ru.ru_msgsnd, xsink);
    rv->setKeyValue("messages_received", (int64)ru.ru_msgrcv, xsink);
    rv->setKeyValue("signals_received", (int64)ru.ru_nsignals, xsink);
    rv->setKeyValue("voluntary_context_switches", (int64)ru.ru_nvcsw, xsink);
    rv->setKeyValue("involuntary_context_switches", (int64)ru.ru_nivcsw, xsink);

    return rv.release();
}

QoreHashNode* ProcessPriv::getResourceUsage(ExceptionSink* xsink) {
    if (!processCheck(xsink)) {
        return nullptr;
    }

    // For child processes, use RUSAGE_CHILDREN
    struct rusage ru;
    if (getrusage(RUSAGE_CHILDREN, &ru) == -1) {
        xsink->raiseErrnoException("PROCESS-GETRESOURCEUSAGE-ERROR", errno, "getrusage() failed");
        return nullptr;
    }

    return rusageToHash(ru, xsink);
}

QoreHashNode* ProcessPriv::getResourceUsage(int pid, ExceptionSink* xsink) {
    // For a specific PID, we can only get resource usage if:
    // 1. It's the current process (use RUSAGE_SELF)
    // 2. It's our child (use RUSAGE_CHILDREN)
    // 3. On Linux, we can read /proc/PID/stat

    if (pid == getpid()) {
        struct rusage ru;
        if (getrusage(RUSAGE_SELF, &ru) == -1) {
            xsink->raiseErrnoException("PROCESS-GETRESOURCEUSAGE-ERROR", errno, "getrusage() failed");
            return nullptr;
        }
        return rusageToHash(ru, xsink);
    }

#ifdef __linux__
    // On Linux, we can read from /proc/PID/stat
    QoreStringMaker path("/proc/%d/stat", pid);
    QoreFile f;
    if (f.open(path.c_str())) {
        xsink->raiseException("PROCESS-GETRESOURCEUSAGE-ERROR", "cannot open %s: %s", path.c_str(), strerror(errno));
        return nullptr;
    }

    QoreStringNodeHolder content(f.read(-1, -1, xsink));
    if (*xsink) {
        return nullptr;
    }

    // Parse /proc/PID/stat - fields are space-separated
    // We need: utime (14), stime (15), rss (24), minflt (10), majflt (12)
    // Field numbering starts at 1
    const char* p = content->c_str();

    // Skip past the command name (in parentheses) since it may contain spaces
    const char* start = strchr(p, '(');
    const char* end = strrchr(p, ')');
    if (!start || !end) {
        xsink->raiseException("PROCESS-GETRESOURCEUSAGE-ERROR", "cannot parse /proc/%d/stat", pid);
        return nullptr;
    }
    p = end + 2;  // Skip ") "

    // Parse remaining fields (starting at field 3)
    int64 utime = 0, stime = 0, minflt = 0, majflt = 0, rss = 0;
    int field = 3;
    while (*p) {
        // Skip whitespace
        while (*p == ' ') p++;
        if (!*p) break;

        // Read field value
        char* endptr;
        long long val = strtoll(p, &endptr, 10);

        switch (field) {
            case 10: minflt = val; break;  // minflt
            case 12: majflt = val; break;  // majflt
            case 14: utime = val; break;   // utime (clock ticks)
            case 15: stime = val; break;   // stime (clock ticks)
            case 24: rss = val; break;     // rss (pages)
        }

        // Move to next field
        p = endptr;
        field++;
        if (field > 24) break;
    }

    // Convert clock ticks to seconds
    long ticks_per_sec = sysconf(_SC_CLK_TCK);
    long page_size = sysconf(_SC_PAGESIZE);

    ReferenceHolder<QoreHashNode> rv(new QoreHashNode(autoTypeInfo), xsink);
    rv->setKeyValue("user_time", (double)utime / ticks_per_sec, xsink);
    rv->setKeyValue("system_time", (double)stime / ticks_per_sec, xsink);
    rv->setKeyValue("max_rss", rss * page_size, xsink);
    rv->setKeyValue("shared_size", (int64)0, xsink);
    rv->setKeyValue("unshared_data_size", (int64)0, xsink);
    rv->setKeyValue("unshared_stack_size", (int64)0, xsink);
    rv->setKeyValue("minor_faults", minflt, xsink);
    rv->setKeyValue("major_faults", majflt, xsink);
    rv->setKeyValue("swaps", (int64)0, xsink);
    rv->setKeyValue("block_input", (int64)0, xsink);
    rv->setKeyValue("block_output", (int64)0, xsink);
    rv->setKeyValue("messages_sent", (int64)0, xsink);
    rv->setKeyValue("messages_received", (int64)0, xsink);
    rv->setKeyValue("signals_received", (int64)0, xsink);
    rv->setKeyValue("voluntary_context_switches", (int64)0, xsink);
    rv->setKeyValue("involuntary_context_switches", (int64)0, xsink);

    return rv.release();
#else
    xsink->raiseException("PROCESS-GETRESOURCEUSAGE-UNSUPPORTED-ERROR",
        "getting resource usage for arbitrary PIDs is only supported on Linux");
    return nullptr;
#endif
}

QoreListNode* ProcessPriv::getChildPids(ExceptionSink* xsink) {
    if (!processCheck(xsink)) {
        return nullptr;
    }

    int pid = detached_pid ? detached_pid : m_process->id();
    return getChildPids(pid, xsink);
}

QoreListNode* ProcessPriv::getChildPids(int pid, ExceptionSink* xsink) {
    // Safety check: never allow getting children of PID 1 (init) or invalid PIDs
    // This prevents accidentally killing system processes
    if (pid <= 1) {
        xsink->raiseException("PROCESS-GETCHILDPIDS-ERROR",
            "refusing to get children of PID %d (must be > 1)", pid);
        return nullptr;
    }

#ifdef __linux__
    // On Linux, read /proc/PID/task/PID/children if available (kernel 3.5+)
    // or parse all /proc/*/stat files looking for parent PID
    QoreStringMaker childrenPath("/proc/%d/task/%d/children", pid, pid);
    QoreFile f;

    ReferenceHolder<QoreListNode> rv(new QoreListNode(bigIntTypeInfo), xsink);

    if (f.open(childrenPath.c_str()) == 0) {
        // Modern kernel with /proc/PID/task/PID/children support
        QoreStringNodeHolder content(f.read(-1, -1, xsink));
        if (*xsink) {
            return nullptr;
        }

        // Handle empty file (process has no children) or nullptr
        if (!content || !content->size()) {
            return rv.release();
        }

        const char* p = content->c_str();
        while (*p) {
            // Skip whitespace
            while (*p == ' ' || *p == '\t' || *p == '\n') p++;
            if (!*p) break;

            // Read PID
            char* endptr;
            long childPid = strtol(p, &endptr, 10);
            if (endptr > p) {
                rv->push(childPid, xsink);
            }
            p = endptr;
        }
    } else {
        // Fallback: scan all /proc/*/stat files
        if (check_sandbox_read("/proc", xsink)) {
            return nullptr;
        }
        DIR* procdir = opendir("/proc");
        if (!procdir) {
            xsink->raiseErrnoException("PROCESS-GETCHILDPIDS-ERROR", errno, "cannot open /proc");
            return nullptr;
        }

        struct dirent* entry;
        unsigned count = 0;
        while ((entry = readdir(procdir)) != nullptr) {
            // there is one entry for each process in the system
            if (!(++count % 100) && qore_check_cancel(xsink, "Process::getChildPids")) {
                closedir(procdir);
                return nullptr;
            }
            // Check if entry is a number (PID)
            char* endptr;
            long entryPid = strtol(entry->d_name, &endptr, 10);
            if (*endptr != '\0' || entryPid <= 0) {
                continue;
            }

            // Read /proc/PID/stat
            QoreStringMaker statPath("/proc/%ld/stat", entryPid);
            QoreFile statFile;
            if (statFile.open(statPath.c_str()) != 0) {
                continue;
            }

            QoreStringNodeHolder statContent(statFile.read(-1, -1, xsink));
            if (*xsink) {
                xsink->clear();  // Ignore errors reading individual stat files
                continue;
            }

            // Safety check for null or empty content
            if (!statContent || !statContent->size()) {
                continue;
            }

            // Parse stat file to get PPID (field 4)
            const char* p = statContent->c_str();
            const char* end = strrchr(p, ')');
            if (!end) continue;
            p = end + 2;  // Skip ") "

            // Skip state (field 3)
            while (*p == ' ') p++;
            while (*p && *p != ' ') p++;
            while (*p == ' ') p++;

            // Read PPID (field 4)
            long ppid = strtol(p, &endptr, 10);
            if (ppid == pid) {
                rv->push(entryPid, xsink);
            }
        }
        closedir(procdir);
    }

    return rv.release();
#elif defined(__APPLE__) && defined(__MACH__)
    // On macOS, use libproc to get child PIDs
    ReferenceHolder<QoreListNode> rv(new QoreListNode(bigIntTypeInfo), xsink);

    // Get list of all PIDs
    int numPids = proc_listpids(PROC_ALL_PIDS, 0, nullptr, 0);
    if (numPids <= 0) {
        return rv.release();  // Return empty list
    }

    std::vector<pid_t> pids(numPids);
    numPids = proc_listpids(PROC_ALL_PIDS, 0, pids.data(), numPids * sizeof(pid_t));
    numPids /= sizeof(pid_t);

    for (int i = 0; i < numPids; i++) {
        struct proc_bsdinfo info;
        int size = proc_pidinfo(pids[i], PROC_PIDTBSDINFO, 0, &info, sizeof(info));
        if (size == sizeof(info) && info.pbi_ppid == pid) {
            rv->push((int64)pids[i], xsink);
        }
    }

    return rv.release();
#else
    xsink->raiseException("PROCESS-GETCHILDPIDS-UNSUPPORTED-ERROR",
        "getting child PIDs is not supported on this platform");
    return nullptr;
#endif
}

bool ProcessPriv::terminateTree(ExceptionSink* xsink) {
    if (!processCheck(xsink)) {
        return false;
    }

    // NOTE: Currently this method only terminates the main process and does NOT
    // terminate any child processes. Its behavior is effectively the same as
    // calling terminate(). Child process termination is temporarily disabled.
    //
    // TEMPORARILY DISABLED: Child process killing is disabled due to a bug that causes
    // incorrect PIDs to be killed.
    // TODO: Fix the getChildPids implementation and re-enable child killing.
    //
    // The issue is that getChildPids or the PPID verification is somehow returning
    // or approving incorrect PIDs, leading to killing unrelated processes like
    // systemd, ssh sessions, etc.

    // Just terminate the main process for now; this is equivalent to terminate()
    return terminate(xsink);
}

QoreStringNode* ProcessPriv::getCommandLine(int pid, ExceptionSink* xsink) {
    if (pid <= 0) {
        xsink->raiseException("PROCESS-GETCOMMANDLINE-ERROR", "PID must be positive (got %d)", pid);
        return nullptr;
    }

    // Retry on empty result: when a process is launched via a shebang script (e.g. #!/usr/bin/env qore),
    // the kernel performs two exec() calls.  The CLOEXEC pipe (boost::process startup sync) closes on the
    // first exec, but /proc/PID/cmdline is transiently empty during the second exec.  The empty window
    // lasts for the kernel's execve() processing time (typically <1ms, but potentially longer under heavy
    // load or with cold caches).  We use a wall-clock-bounded retry with exponential backoff to handle
    // this reliably regardless of CPU speed or system load.
    constexpr int64_t timeout_us = 5'000'000;  // 5 second total timeout
    constexpr int yield_attempts = 10;          // initial fast sched_yield attempts
    constexpr int64_t initial_sleep_us = 1000;  // 1ms initial sleep after yields
    constexpr int64_t max_sleep_us = 100'000;   // 100ms max sleep interval

    auto start = std::chrono::steady_clock::now();
    int attempt = 0;

#ifdef __linux__
    // Boost reads /proc/PID/cmdline on Linux
    {
        QoreStringMaker path("/proc/%d/cmdline", pid);
        if (check_sandbox_read(path.c_str(), xsink)) {
            return nullptr;
        }
    }
#endif
    while (true) {
        boost::system::error_code ec;
        auto sh = boost::process::v2::ext::cmd(pid, ec);
        if (ec) {
            if (ec.value() == ENOTSUP) {
                xsink->raiseException("PROCESS-GETCOMMANDLINE-UNSUPPORTED-ERROR",
                    "getCommandLine() is not supported on this platform");
            } else {
                xsink->raiseException("PROCESS-GETCOMMANDLINE-ERROR",
                    "cannot get command line for PID %d: %s", pid, ec.message().c_str());
            }
            return nullptr;
        }

        if (!sh.empty()) {
            SimpleRefHolder<QoreStringNode> rv(new QoreStringNode(sh.argv()[0]));
            for (int i = 1; i < sh.argc(); ++i) {
                rv->concat(' ');
                rv->concat(sh.argv()[i]);
            }
            return rv.release();
        }

        // Empty result - check timeout
        auto elapsed = std::chrono::duration_cast<std::chrono::microseconds>(
            std::chrono::steady_clock::now() - start).count();
        if (elapsed >= timeout_us) {
            xsink->raiseException("PROCESS-GETCOMMANDLINE-ERROR",
                "empty command line for PID %d (timed out after %g seconds)", pid,
                static_cast<double>(elapsed) / 1'000'000.0);
            return nullptr;
        }

        // Check if the process still exists before retrying
        if (kill(pid, 0) != 0) {
            xsink->raiseException("PROCESS-GETCOMMANDLINE-ERROR",
                "cannot get command line for PID %d: process no longer exists", pid);
            return nullptr;
        }

        if (attempt < yield_attempts) {
            // Fast path: sched_yield() for the common case where exec completes in microseconds
            sched_yield();
        } else {
            // Exponential backoff: 1ms, 2ms, 4ms, ..., capped at 100ms
            int shift = std::min(attempt - yield_attempts, 20);  // cap shift to prevent UB
            int64_t sleep_us = std::min(initial_sleep_us << shift, max_sleep_us);
            int64_t remaining_us = timeout_us - elapsed;
            sleep_us = std::min(sleep_us, remaining_us);
            time_t sec = static_cast<time_t>(sleep_us / 1'000'000);
            long nsec = static_cast<long>((sleep_us % 1'000'000) * 1000);
            struct timespec ts = {sec, nsec};
            nanosleep(&ts, nullptr);
        }
        ++attempt;
    }
}

#if defined(__linux__)
QoreListNode* ProcessPriv::getPidsForPort(int port, ExceptionSink* xsink) {
    if (port <= 0 || port > 65535) {
        xsink->raiseException("PROCESS-GETPIDSFORPORT-ERROR",
            "port must be between 1 and 65535 (got %d)", port);
        return nullptr;
    }

    char hex_port[16];
    snprintf(hex_port, sizeof(hex_port), "%04X", port);

    // Collect socket inodes for LISTEN sockets on this port from /proc/net/tcp and tcp6
    std::unordered_map<std::string, bool> target_inodes;

    const char* tcp_files[] = {"/proc/net/tcp", "/proc/net/tcp6"};
    for (const char* tcp_file : tcp_files) {
        QoreFile f;
        if (f.open(tcp_file)) {
            continue;
        }

        QoreStringNodeHolder content(f.read(-1, -1, xsink));
        if (*xsink) {
            xsink->clear();
            continue;
        }
        if (!content || !content->size()) {
            continue;
        }

        // Parse each line
        const char* p = content->c_str();
        while (*p) {
            // Find end of line
            const char* eol = strchr(p, '\n');
            if (!eol) {
                eol = p + strlen(p);
            }

            // Skip header line
            const char* line = p;
            p = (*eol) ? eol + 1 : eol;

            // Skip leading whitespace
            while (line < eol && (*line == ' ' || *line == '\t')) {
                ++line;
            }
            // Skip header
            if (line < eol && (*line == 's' || *line == 'S')) {
                continue;
            }

            // Parse fields: we need field[1] (local_address), field[3] (state), field[9] (inode)
            // Fields are whitespace-separated
            const char* fields[12];
            int nfields = 0;
            const char* fp = line;
            while (fp < eol && nfields < 12) {
                // Skip whitespace
                while (fp < eol && (*fp == ' ' || *fp == '\t')) {
                    ++fp;
                }
                if (fp >= eol) {
                    break;
                }
                fields[nfields++] = fp;
                // Skip non-whitespace
                while (fp < eol && *fp != ' ' && *fp != '\t') {
                    ++fp;
                }
            }

            if (nfields < 10) {
                continue;
            }

            // Check state == "0A" (LISTEN)
            if (fields[3][0] != '0' || (fields[3][1] != 'A' && fields[3][1] != 'a')) {
                continue;
            }

            // Check local_address ends with :HEXPORT
            // local_address format: HEXIP:HEXPORT
            const char* colon = nullptr;
            {
                const char* fp2 = fields[1];
                while (fp2 < fields[2] && *fp2 != ' ' && *fp2 != '\t') {
                    if (*fp2 == ':') {
                        colon = fp2;
                    }
                    ++fp2;
                }
            }
            if (!colon) {
                continue;
            }
            // Compare hex port (case-insensitive)
            if (strncasecmp(colon + 1, hex_port, 4) != 0) {
                continue;
            }

            // Get inode (field 9)
            std::string inode(fields[9]);
            // Trim to just the field
            {
                size_t end = inode.find_first_of(" \t\n");
                if (end != std::string::npos) {
                    inode.erase(end);
                }
            }
            if (inode != "0") {
                target_inodes[inode] = true;
            }
        }
    }

    ReferenceHolder<QoreListNode> rv(new QoreListNode(bigIntTypeInfo), xsink);

    if (target_inodes.empty()) {
        return rv.release();
    }

    // Scan /proc/<pid>/fd to find PIDs with matching socket inodes
    if (check_sandbox_read("/proc", xsink)) {
        return nullptr;
    }
    DIR* procdir = opendir("/proc");
    if (!procdir) {
        xsink->raiseErrnoException("PROCESS-GETPIDSFORPORT-ERROR", errno, "cannot open /proc");
        return nullptr;
    }
    unsigned count = 0;

    std::unordered_map<int, bool> found_pids;
    struct dirent* entry;
    while ((entry = readdir(procdir)) != nullptr) {
        // Check if entry is a PID directory
        char* endptr;
        long pid_val = strtol(entry->d_name, &endptr, 10);
        if (*endptr != '\0' || pid_val <= 0) {
            continue;
        }

        // there is one entry for each process in the system
        if (!(++count % 100) && qore_check_cancel(xsink, "Process::getPidsForPort")) {
            closedir(procdir);
            return nullptr;
        }

        QoreStringMaker fd_path("/proc/%ld/fd", pid_val);
        // a sandbox can hide the descriptors of a process without failing the scan
        if (!sandbox_allows_read(fd_path.c_str())) {
            continue;
        }
        DIR* fddir = opendir(fd_path.c_str());
        if (!fddir) {
            continue;
        }

        struct dirent* fd_entry;
        bool found = false;
        while ((fd_entry = readdir(fddir)) != nullptr) {
            // a process can have many descriptors
            if (!(++count % 100) && qore_check_cancel(xsink, "Process::getPidsForPort")) {
                closedir(fddir);
                closedir(procdir);
                return nullptr;
            }
            QoreStringMaker link_path("%s/%s", fd_path.c_str(), fd_entry->d_name);
            char target[256];
            ssize_t len = readlink(link_path.c_str(), target, sizeof(target) - 1);
            if (len <= 0) {
                continue;
            }
            target[len] = '\0';

            // Check for "socket:[INODE]"
            if (strncmp(target, "socket:[", 8) != 0) {
                continue;
            }
            // Extract inode number
            char* inode_start = target + 8;
            char* inode_end = strchr(inode_start, ']');
            if (!inode_end) {
                continue;
            }
            std::string inode(inode_start, inode_end - inode_start);
            if (target_inodes.count(inode)) {
                found = true;
                break;
            }
        }
        closedir(fddir);

        if (found) {
            found_pids[(int)pid_val] = true;
        }
    }
    closedir(procdir);

    for (const auto& kv : found_pids) {
        rv->push((int64)kv.first, xsink);
    }

    return rv.release();
}
#elif defined(__APPLE__) && defined(__MACH__)
#include <sys/socket.h>
#include <sys/un.h>
#include <arpa/inet.h>
#include <sys/proc_info.h>

QoreListNode* ProcessPriv::getPidsForPort(int port, ExceptionSink* xsink) {
    if (port <= 0 || port > 65535) {
        xsink->raiseException("PROCESS-GETPIDSFORPORT-ERROR",
            "port must be between 1 and 65535 (got %d)", port);
        return nullptr;
    }

    ReferenceHolder<QoreListNode> rv(new QoreListNode(bigIntTypeInfo), xsink);

    // Get list of all PIDs
    int numPids = proc_listpids(PROC_ALL_PIDS, 0, nullptr, 0);
    if (numPids <= 0) {
        return rv.release();
    }

    std::vector<pid_t> pids(numPids);
    numPids = proc_listpids(PROC_ALL_PIDS, 0, pids.data(), numPids * sizeof(pid_t));
    numPids /= sizeof(pid_t);

    std::unordered_map<int, bool> found_pids;

    for (int i = 0; i < numPids; i++) {
        if (pids[i] == 0) {
            continue;
        }

        // Get file descriptor list for this PID
        int bufsize = proc_pidinfo(pids[i], PROC_PIDLISTFDS, 0, nullptr, 0);
        if (bufsize <= 0) {
            continue;
        }

        std::vector<char> buf(bufsize);
        int actual = proc_pidinfo(pids[i], PROC_PIDLISTFDS, 0, buf.data(), bufsize);
        if (actual <= 0) {
            continue;
        }

        int numFds = actual / sizeof(struct proc_fdinfo);
        struct proc_fdinfo* fdinfo = reinterpret_cast<struct proc_fdinfo*>(buf.data());

        for (int j = 0; j < numFds; j++) {
            if (fdinfo[j].proc_fdtype != PROX_FDTYPE_SOCKET) {
                continue;
            }

            struct socket_fdinfo si;
            int siSize = proc_pidfdinfo(pids[i], fdinfo[j].proc_fd,
                PROC_PIDFDSOCKETINFO, &si, sizeof(si));
            if (siSize != sizeof(si)) {
                continue;
            }

            // Check for TCP socket in LISTEN state on the target port
            if ((si.psi.soi_family == AF_INET || si.psi.soi_family == AF_INET6)
                && si.psi.soi_kind == SOCKINFO_TCP
                && si.psi.soi_proto.pri_tcp.tcpsi_state == TSI_S_LISTEN
                && ntohs(si.psi.soi_proto.pri_tcp.tcpsi_ini.insi_lport) == port) {
                if (!found_pids.count(pids[i])) {
                    found_pids[pids[i]] = true;
                }
                break;
            }
        }
    }

    for (const auto& kv : found_pids) {
        rv->push((int64)kv.first, xsink);
    }

    return rv.release();
}
#elif defined(__FreeBSD__) || defined(__DragonFly__)
#include <sys/types.h>
#include <sys/sysctl.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <sys/user.h>
#include <netinet/in.h>
#include <arpa/inet.h>

QoreListNode* ProcessPriv::getPidsForPort(int port, ExceptionSink* xsink) {
    if (port <= 0 || port > 65535) {
        xsink->raiseException("PROCESS-GETPIDSFORPORT-ERROR",
            "port must be between 1 and 65535 (got %d)", port);
        return nullptr;
    }

    ReferenceHolder<QoreListNode> rv(new QoreListNode(bigIntTypeInfo), xsink);

    // Get list of all processes
    int mib_procs[4] = {CTL_KERN, KERN_PROC, KERN_PROC_PROC, 0};
    size_t procs_len = 0;
    if (sysctl(mib_procs, 3, nullptr, &procs_len, nullptr, 0) < 0) {
        return rv.release();
    }

    std::vector<char> procs_buf(procs_len);
    if (sysctl(mib_procs, 3, procs_buf.data(), &procs_len, nullptr, 0) < 0) {
        return rv.release();
    }

    int num_procs = procs_len / sizeof(struct kinfo_proc);
    struct kinfo_proc* procs = reinterpret_cast<struct kinfo_proc*>(procs_buf.data());

    std::unordered_map<int, bool> found_pids;

    for (int i = 0; i < num_procs; i++) {
        pid_t pid = procs[i].ki_pid;
        if (pid <= 0) {
            continue;
        }

        // Get file descriptors for this PID
        int mib_fd[4] = {CTL_KERN, KERN_PROC, KERN_PROC_FILEDESC, pid};
        size_t fd_len = 0;
        if (sysctl(mib_fd, 4, nullptr, &fd_len, nullptr, 0) < 0) {
            continue;
        }

        std::vector<char> fd_buf(fd_len);
        if (sysctl(mib_fd, 4, fd_buf.data(), &fd_len, nullptr, 0) < 0) {
            continue;
        }

        // Iterate over kinfo_file entries (variable-length)
        char* p = fd_buf.data();
        char* end = p + fd_len;
        while (p < end) {
            struct kinfo_file* kf = reinterpret_cast<struct kinfo_file*>(p);
            if (kf->kf_structsize == 0) {
                break;
            }

            if (kf->kf_type == KF_TYPE_SOCKET
                && (kf->kf_sock_domain == AF_INET || kf->kf_sock_domain == AF_INET6)
                && kf->kf_sock_type == SOCK_STREAM) {
                // Check for LISTEN state
                // On FreeBSD, kf_sock_protocol == IPPROTO_TCP and kf_un.kf_sock.kf_sock_sendq == 0
                // for listening sockets; check local port via kf_sa_local
                struct sockaddr* sa = reinterpret_cast<struct sockaddr*>(&kf->kf_sa_local);
                int local_port = 0;
                if (sa->sa_family == AF_INET) {
                    local_port = ntohs(reinterpret_cast<struct sockaddr_in*>(sa)->sin_port);
                } else if (sa->sa_family == AF_INET6) {
                    local_port = ntohs(reinterpret_cast<struct sockaddr_in6*>(sa)->sin6_port);
                }

                if (local_port == port) {
                    // Verify this is a listening socket by checking the peer port is 0
                    struct sockaddr* peer = reinterpret_cast<struct sockaddr*>(&kf->kf_sa_peer);
                    int peer_port = -1;
                    if (peer->sa_family == AF_INET) {
                        peer_port = ntohs(reinterpret_cast<struct sockaddr_in*>(peer)->sin_port);
                    } else if (peer->sa_family == AF_INET6) {
                        peer_port = ntohs(reinterpret_cast<struct sockaddr_in6*>(peer)->sin6_port);
                    }

                    if (peer_port == 0 && !found_pids.count(pid)) {
                        found_pids[pid] = true;
                    }
                }
            }

            p += kf->kf_structsize;
        }
    }

    for (const auto& kv : found_pids) {
        rv->push((int64)kv.first, xsink);
    }

    return rv.release();
}
#else
QoreListNode* ProcessPriv::getPidsForPort(int port, ExceptionSink* xsink) {
    xsink->raiseException("PROCESS-GETPIDSFORPORT-UNSUPPORTED-ERROR",
        "getPidsForPort() is not supported on this platform");
    return nullptr;
}
#endif

#if defined(__linux__)
QoreListNode* ProcessPriv::getPidsForUnixSocket(const char* path, ExceptionSink* xsink) {
    if (!path || !*path) {
        xsink->raiseException("PROCESS-GETPIDSFORUNIXSOCKET-ERROR", "socket path must not be empty");
        return nullptr;
    }

    // Parse /proc/net/unix to find inode(s) for the target socket path
    std::unordered_map<std::string, bool> target_inodes;

    {
        QoreFile f;
        if (f.open("/proc/net/unix")) {
            // If we can't open /proc/net/unix, return empty list
            return new QoreListNode(bigIntTypeInfo);
        }

        QoreStringNodeHolder content(f.read(-1, -1, xsink));
        if (*xsink) {
            return nullptr;
        }
        if (!content || !content->size()) {
            return new QoreListNode(bigIntTypeInfo);
        }

        // Format: Num RefCount Protocol Flags Type St Inode Path
        const char* p = content->c_str();
        while (*p) {
            const char* eol = strchr(p, '\n');
            if (!eol) {
                eol = p + strlen(p);
            }

            const char* line = p;
            p = (*eol) ? eol + 1 : eol;

            // Skip leading whitespace
            while (line < eol && (*line == ' ' || *line == '\t')) {
                ++line;
            }
            // Skip header line
            if (line < eol && (*line == 'N' || *line == 'n')) {
                continue;
            }

            // Parse fields: we need field[6] (inode) and field[7] (path)
            const char* fields[8] = {};
            int nfields = 0;
            const char* fp = line;
            while (fp < eol && nfields < 8) {
                while (fp < eol && (*fp == ' ' || *fp == '\t')) {
                    ++fp;
                }
                if (fp >= eol) {
                    break;
                }
                fields[nfields++] = fp;
                while (fp < eol && *fp != ' ' && *fp != '\t') {
                    ++fp;
                }
            }

            // Need at least 8 fields (with path)
            if (nfields < 8) {
                continue;
            }

            // Extract path field (field[7] to end of line)
            std::string sock_path(fields[7], eol - fields[7]);
            // Trim trailing whitespace
            while (!sock_path.empty() && (sock_path.back() == ' ' || sock_path.back() == '\t'
                    || sock_path.back() == '\n')) {
                sock_path.pop_back();
            }

            if (sock_path == path) {
                // Extract inode (field[6])
                std::string inode(fields[6]);
                size_t end = inode.find_first_of(" \t\n");
                if (end != std::string::npos) {
                    inode.erase(end);
                }
                if (inode != "0") {
                    target_inodes[inode] = true;
                }
            }
        }
    }

    ReferenceHolder<QoreListNode> rv(new QoreListNode(bigIntTypeInfo), xsink);

    if (target_inodes.empty()) {
        return rv.release();
    }

    // Scan /proc/<pid>/fd to find PIDs with matching socket inodes
    if (check_sandbox_read("/proc", xsink)) {
        return nullptr;
    }
    DIR* procdir = opendir("/proc");
    if (!procdir) {
        xsink->raiseErrnoException("PROCESS-GETPIDSFORUNIXSOCKET-ERROR", errno, "cannot open /proc");
        return nullptr;
    }
    unsigned count = 0;

    std::unordered_map<int, bool> found_pids;
    struct dirent* entry;
    while ((entry = readdir(procdir)) != nullptr) {
        char* endptr;
        long pid_val = strtol(entry->d_name, &endptr, 10);
        if (*endptr != '\0' || pid_val <= 0) {
            continue;
        }

        // there is one entry for each process in the system
        if (!(++count % 100) && qore_check_cancel(xsink, "Process::getPidsForUnixSocket")) {
            closedir(procdir);
            return nullptr;
        }

        QoreStringMaker fd_path("/proc/%ld/fd", pid_val);
        // a sandbox can hide the descriptors of a process without failing the scan
        if (!sandbox_allows_read(fd_path.c_str())) {
            continue;
        }
        DIR* fddir = opendir(fd_path.c_str());
        if (!fddir) {
            continue;
        }

        struct dirent* fd_entry;
        bool found = false;
        while ((fd_entry = readdir(fddir)) != nullptr) {
            // a process can have many descriptors
            if (!(++count % 100) && qore_check_cancel(xsink, "Process::getPidsForUnixSocket")) {
                closedir(fddir);
                closedir(procdir);
                return nullptr;
            }
            QoreStringMaker link_path("%s/%s", fd_path.c_str(), fd_entry->d_name);
            char target[256];
            ssize_t len = readlink(link_path.c_str(), target, sizeof(target) - 1);
            if (len <= 0) {
                continue;
            }
            target[len] = '\0';

            // Check for "socket:[INODE]"
            if (strncmp(target, "socket:[", 8) != 0) {
                continue;
            }
            char* inode_start = target + 8;
            char* inode_end = strchr(inode_start, ']');
            if (!inode_end) {
                continue;
            }
            std::string inode(inode_start, inode_end - inode_start);
            if (target_inodes.count(inode)) {
                found = true;
                break;
            }
        }
        closedir(fddir);

        if (found) {
            found_pids[(int)pid_val] = true;
        }
    }
    closedir(procdir);

    for (const auto& kv : found_pids) {
        rv->push((int64)kv.first, xsink);
    }

    return rv.release();
}
#elif defined(__APPLE__) && defined(__MACH__)
QoreListNode* ProcessPriv::getPidsForUnixSocket(const char* path, ExceptionSink* xsink) {
    if (!path || !*path) {
        xsink->raiseException("PROCESS-GETPIDSFORUNIXSOCKET-ERROR", "socket path must not be empty");
        return nullptr;
    }

    ReferenceHolder<QoreListNode> rv(new QoreListNode(bigIntTypeInfo), xsink);

    // Get list of all PIDs
    int numPids = proc_listpids(PROC_ALL_PIDS, 0, nullptr, 0);
    if (numPids <= 0) {
        return rv.release();
    }

    std::vector<pid_t> pids(numPids);
    numPids = proc_listpids(PROC_ALL_PIDS, 0, pids.data(), numPids * sizeof(pid_t));
    numPids /= sizeof(pid_t);

    std::unordered_map<int, bool> found_pids;

    for (int i = 0; i < numPids; i++) {
        if (pids[i] == 0) {
            continue;
        }

        // Get file descriptor list for this PID
        int bufsize = proc_pidinfo(pids[i], PROC_PIDLISTFDS, 0, nullptr, 0);
        if (bufsize <= 0) {
            continue;
        }

        std::vector<char> buf(bufsize);
        int actual = proc_pidinfo(pids[i], PROC_PIDLISTFDS, 0, buf.data(), bufsize);
        if (actual <= 0) {
            continue;
        }

        int numFds = actual / sizeof(struct proc_fdinfo);
        struct proc_fdinfo* fdinfo = reinterpret_cast<struct proc_fdinfo*>(buf.data());

        for (int j = 0; j < numFds; j++) {
            if (fdinfo[j].proc_fdtype != PROX_FDTYPE_SOCKET) {
                continue;
            }

            struct socket_fdinfo si;
            int siSize = proc_pidfdinfo(pids[i], fdinfo[j].proc_fd,
                PROC_PIDFDSOCKETINFO, &si, sizeof(si));
            if (siSize != sizeof(si)) {
                continue;
            }

            // Check for Unix domain socket matching the target path
            if (si.psi.soi_family == AF_UNIX && si.psi.soi_kind == SOCKINFO_UN) {
                const char* sock_path = si.psi.soi_proto.pri_un.unsi_addr.ua_sun.sun_path;
                if (sock_path[0] != '\0' && strcmp(sock_path, path) == 0) {
                    if (!found_pids.count(pids[i])) {
                        found_pids[pids[i]] = true;
                    }
                    break;
                }
            }
        }
    }

    for (const auto& kv : found_pids) {
        rv->push((int64)kv.first, xsink);
    }

    return rv.release();
}
#elif defined(__FreeBSD__) || defined(__DragonFly__)
QoreListNode* ProcessPriv::getPidsForUnixSocket(const char* path, ExceptionSink* xsink) {
    if (!path || !*path) {
        xsink->raiseException("PROCESS-GETPIDSFORUNIXSOCKET-ERROR", "socket path must not be empty");
        return nullptr;
    }

    ReferenceHolder<QoreListNode> rv(new QoreListNode(bigIntTypeInfo), xsink);

    // Get list of all processes
    int mib_procs[4] = {CTL_KERN, KERN_PROC, KERN_PROC_PROC, 0};
    size_t procs_len = 0;
    if (sysctl(mib_procs, 3, nullptr, &procs_len, nullptr, 0) < 0) {
        return rv.release();
    }

    std::vector<char> procs_buf(procs_len);
    if (sysctl(mib_procs, 3, procs_buf.data(), &procs_len, nullptr, 0) < 0) {
        return rv.release();
    }

    int num_procs = procs_len / sizeof(struct kinfo_proc);
    struct kinfo_proc* procs = reinterpret_cast<struct kinfo_proc*>(procs_buf.data());

    std::unordered_map<int, bool> found_pids;

    for (int i = 0; i < num_procs; i++) {
        pid_t pid = procs[i].ki_pid;
        if (pid <= 0) {
            continue;
        }

        // Get file descriptors for this PID
        int mib_fd[4] = {CTL_KERN, KERN_PROC, KERN_PROC_FILEDESC, pid};
        size_t fd_len = 0;
        if (sysctl(mib_fd, 4, nullptr, &fd_len, nullptr, 0) < 0) {
            continue;
        }

        std::vector<char> fd_buf(fd_len);
        if (sysctl(mib_fd, 4, fd_buf.data(), &fd_len, nullptr, 0) < 0) {
            continue;
        }

        char* p = fd_buf.data();
        char* end = p + fd_len;
        while (p < end) {
            struct kinfo_file* kf = reinterpret_cast<struct kinfo_file*>(p);
            if (kf->kf_structsize == 0) {
                break;
            }

            if (kf->kf_type == KF_TYPE_SOCKET
                && kf->kf_sock_domain == AF_UNIX) {
                // Check socket path via kf_path
                if (kf->kf_path[0] != '\0' && strcmp(kf->kf_path, path) == 0) {
                    if (!found_pids.count(pid)) {
                        found_pids[pid] = true;
                    }
                    break;
                }
            }

            p += kf->kf_structsize;
        }
    }

    for (const auto& kv : found_pids) {
        rv->push((int64)kv.first, xsink);
    }

    return rv.release();
}
#else
QoreListNode* ProcessPriv::getPidsForUnixSocket(const char* path, ExceptionSink* xsink) {
    xsink->raiseException("PROCESS-GETPIDSFORUNIXSOCKET-UNSUPPORTED-ERROR",
        "getPidsForUnixSocket() is not supported on this platform");
    return nullptr;
}
#endif

QoreHashNode* ProcessPriv::run(const char* command, const QoreListNode* arguments,
        const QoreHashNode* opts, int64 timeout_ms, ExceptionSink* xsink) {
    // Create process
    ReferenceHolder<ProcessPriv> proc(new ProcessPriv(command, arguments, opts, xsink), xsink);
    if (*xsink) {
        return nullptr;
    }

    // Wait for completion
    bool finished;
    if (timeout_ms > 0) {
        finished = proc->wait(timeout_ms, xsink);
    } else {
        finished = proc->wait(xsink);
    }

    if (*xsink) {
        return nullptr;
    }

    // Collect stdout
    SimpleRefHolder<QoreStringNode> stdout_str(new QoreStringNode);
    while (true) {
        QoreStringNode* chunk = proc->readStdout(4096, xsink);
        if (*xsink) {
            return nullptr;
        }
        if (!chunk) {
            break;
        }
        stdout_str->concat(chunk->c_str(), chunk->size());
        chunk->deref();
    }

    // Collect stderr
    SimpleRefHolder<QoreStringNode> stderr_str(new QoreStringNode);
    while (true) {
        QoreStringNode* chunk = proc->readStderr(4096, xsink);
        if (*xsink) {
            return nullptr;
        }
        if (!chunk) {
            break;
        }
        stderr_str->concat(chunk->c_str(), chunk->size());
        chunk->deref();
    }

    // Build result hash
    ReferenceHolder<QoreHashNode> rv(new QoreHashNode(autoTypeInfo), xsink);
    rv->setKeyValue("stdout", stdout_str.release(), xsink);
    rv->setKeyValue("stderr", stderr_str.release(), xsink);
    rv->setKeyValue("exit_code", proc->exitCode(xsink), xsink);
    rv->setKeyValue("ok", finished, xsink);

    // If process didn't finish (timeout), terminate it
    if (!finished) {
        proc->terminate(xsink);
        if (*xsink) {
            return nullptr;
        }
        // Ensure background I/O is drained before destruction; otherwise the async thread can outlive buffers and
        // segfault during teardown.
        proc->wait(xsink);
        if (*xsink) {
            return nullptr;
        }
    }

    return rv.release();
}

QoreStringNode* ProcessPriv::getExecutablePath(int pid, ExceptionSink* xsink) {
#ifdef __linux__
    // Boost reads the /proc/PID/exe link on Linux
    {
        QoreStringMaker link("/proc/%d/exe", pid);
        if (check_sandbox_read(link.c_str(), xsink)) {
            return nullptr;
        }
    }
#endif
    // Boost reports ENOTSUP on platforms where ext::exe is not implemented
    boost::system::error_code ec;
    auto exe = boost::process::v2::ext::exe(pid, ec);
    if (ec) {
        if (ec.value() == ENOTSUP) {
            xsink->raiseException("PROCESS-GETEXECUTABLEPATH-UNSUPPORTED-ERROR",
                "getExecutablePath() is not supported on this platform");
        } else {
            xsink->raiseException("PROCESS-GETEXECUTABLEPATH-ERROR", "cannot get the executable path for PID %d: %s",
                pid, ec.message().c_str());
        }
        return nullptr;
    }
    return new QoreStringNode(exe.string());
}

QoreHashNode* ProcessPriv::getSystemMemoryInfo(ExceptionSink* xsink) {
#if defined(__linux__)
    return getSystemMemoryInfoLinux(xsink);
#elif defined(__APPLE__) && defined(__MACH__)
    return getSystemMemoryInfoDarwin(xsink);
#else
    // an implementation is required for each platform
    xsink->raiseException("PROCESS-GETSYSTEMMEMORYINFO-UNSUPPORTED-ERROR",
        "getSystemMemoryInfo() is not supported on this platform");
    return nullptr;
#endif
}

#if defined(__linux__)
#include <fstream>
#include <sstream>
#include <string>

//! Reads a numeric byte value from a cgroup file
/** @return the value, or -1 if there is none (ex: "max" or no file) or if a sandbox denies access (an exception
    is raised)
*/
static int64 read_cgroup_bytes(const std::string& path, ExceptionSink* xsink) {
    if (check_sandbox_read(path.c_str(), xsink)) {
        return -1;
    }
    std::ifstream f(path);
    std::string line;
    if (!f || !std::getline(f, line) || line.empty() || !isdigit(line[0])) {
        return -1;
    }
    return strtoll(line.c_str(), nullptr, 10);
}

//! Updates the limit and remaining memory with the memory controller of the given cgroup directory
/** @return 0 for success, -1 if a sandbox denies access (an exception is raised)
*/
static int check_cgroup(const std::string& dir, const char* limit_file, const char* usage_file, int64& limit,
        int64& remaining, ExceptionSink* xsink) {
    int64 l = read_cgroup_bytes(dir + limit_file, xsink);
    if (*xsink) {
        return -1;
    }
    // cgroup v1 reports no limit as a value close to the maximum 64-bit value
    if (l <= 0 || l >= (1LL << 60)) {
        return 0;
    }
    if (limit == -1 || l < limit) {
        limit = l;
    }
    int64 usage = read_cgroup_bytes(dir + usage_file, xsink);
    if (*xsink) {
        return -1;
    }
    int64 r = (usage >= 0 && usage < l) ? l - usage : 0;
    if (remaining == -1 || r < remaining) {
        remaining = r;
    }
    return 0;
}

QoreHashNode* ProcessPriv::getSystemMemoryInfoLinux(ExceptionSink* xsink) {
    if (check_sandbox_read("/proc/meminfo", xsink) || check_sandbox_read("/proc/self/cgroup", xsink)) {
        return nullptr;
    }
    std::ifstream meminfo("/proc/meminfo");
    if (!meminfo) {
        xsink->raiseErrnoException("PROCESS-GETSYSTEMMEMORYINFO-ERROR", errno, "cannot read /proc/meminfo");
        return nullptr;
    }
    int64 total = -1, available = -1, free_mem = 0, buffers = 0, cached = 0;
    std::string line;
    while (std::getline(meminfo, line)) {
        std::istringstream in(line);
        std::string key;
        int64 kb;
        if (!(in >> key >> kb)) {
            continue;
        }
        if (key == "MemTotal:") {
            total = kb * 1024;
        } else if (key == "MemAvailable:") {
            available = kb * 1024;
        } else if (key == "MemFree:") {
            free_mem = kb * 1024;
        } else if (key == "Buffers:") {
            buffers = kb * 1024;
        } else if (key == "Cached:") {
            cached = kb * 1024;
        }
    }
    if (total < 0) {
        xsink->raiseException("PROCESS-GETSYSTEMMEMORYINFO-ERROR", "MemTotal is missing in /proc/meminfo");
        return nullptr;
    }
    // kernels before 3.14 do not report MemAvailable
    if (available < 0) {
        available = free_mem + buffers + cached;
    }

    // apply the memory limits of the control groups of this process and their ancestors
    int64 limit = -1, remaining = -1;
    std::ifstream cgroup("/proc/self/cgroup");
    while (cgroup && std::getline(cgroup, line)) {
        // format: hierarchy-ID:controller-list:cgroup-path
        size_t p1 = line.find(':');
        size_t p2 = p1 == std::string::npos ? p1 : line.find(':', p1 + 1);
        if (p2 == std::string::npos) {
            continue;
        }
        std::string controllers = line.substr(p1 + 1, p2 - p1 - 1);
        std::string path = line.substr(p2 + 1);
        const char* root;
        const char* limit_file;
        const char* usage_file;
        if (controllers.empty()) {
            // cgroup v2
            root = "/sys/fs/cgroup";
            limit_file = "/memory.max";
            usage_file = "/memory.current";
        } else if (("," + controllers + ",").find(",memory,") != std::string::npos) {
            // cgroup v1
            root = "/sys/fs/cgroup/memory";
            limit_file = "/memory.limit_in_bytes";
            usage_file = "/memory.usage_in_bytes";
        } else {
            continue;
        }
        // in a container, the cgroup root is usually the container's own cgroup, so it is checked in any case
        if (check_cgroup(root, limit_file, usage_file, limit, remaining, xsink)) {
            return nullptr;
        }
        while (path.size() > 1) {
            if (check_cgroup(root + path, limit_file, usage_file, limit, remaining, xsink)) {
                return nullptr;
            }
            path.erase(path.rfind('/'));
        }
    }
    if (remaining != -1 && remaining < available) {
        available = remaining;
    }

    ReferenceHolder<QoreHashNode> rv(new QoreHashNode(hashdeclSystemMemoryInfo, xsink), xsink);
    rv->setKeyValue("total", total, xsink);
    rv->setKeyValue("available", available, xsink);
    if (limit != -1) {
        rv->setKeyValue("limit", limit, xsink);
    }
    return rv.release();
}
#endif

#if defined(__APPLE__) && defined(__MACH__)
#include <sys/sysctl.h>

QoreHashNode* ProcessPriv::getSystemMemoryInfoDarwin(ExceptionSink* xsink) {
    uint64_t total = 0;
    size_t len = sizeof(total);
    if (sysctlbyname("hw.memsize", &total, &len, nullptr, 0)) {
        xsink->raiseErrnoException("PROCESS-GETSYSTEMMEMORYINFO-ERROR", errno, "sysctl(hw.memsize) failed");
        return nullptr;
    }

    vm_statistics64_data_t vmstat;
    mach_msg_type_number_t count = HOST_VM_INFO64_COUNT;
    kern_return_t kr = host_statistics64(mach_host_self(), HOST_VM_INFO64, (host_info64_t)&vmstat, &count);
    if (kr != KERN_SUCCESS) {
        xsink->raiseException("PROCESS-GETSYSTEMMEMORYINFO-ERROR", "host_statistics64() returned %d: %s", (int)kr,
            mach_error_string(kr));
        return nullptr;
    }
    // free and inactive pages can be allocated without swapping
    int64 available = ((int64)vmstat.free_count + (int64)vmstat.inactive_count) * (int64)vm_kernel_page_size;

    // apply the memory limit of this process (the jetsam limit), which is enforced on the physical footprint;
    // limit_bytes_remaining is only reported by kernels supporting TASK_VM_INFO revision 4 and is 0 if there is
    // no limit
    int64 limit = -1;
    task_vm_info_data_t vminfo;
    count = TASK_VM_INFO_COUNT;
    kr = task_info(mach_task_self(), TASK_VM_INFO, reinterpret_cast<task_info_t>(&vminfo), &count);
    if (kr != KERN_SUCCESS) {
        xsink->raiseException("PROCESS-GETSYSTEMMEMORYINFO-ERROR", "task_info() returned %d: %s", static_cast<int>(kr),
            mach_error_string(kr));
        return nullptr;
    }
    if (count >= TASK_VM_INFO_REV4_COUNT && vminfo.limit_bytes_remaining > 0) {
        int64 remaining = static_cast<int64>(vminfo.limit_bytes_remaining);
        limit = static_cast<int64>(vminfo.phys_footprint) + remaining;
        if (remaining < available) {
            available = remaining;
        }
    }

    ReferenceHolder<QoreHashNode> rv(new QoreHashNode(hashdeclSystemMemoryInfo, xsink), xsink);
    rv->setKeyValue("total", (int64)total, xsink);
    rv->setKeyValue("available", available, xsink);
    if (limit != -1) {
        rv->setKeyValue("limit", limit, xsink);
    }
    return rv.release();
}
#endif
