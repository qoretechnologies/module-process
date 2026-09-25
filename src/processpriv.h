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

#ifndef PROCESSPRIV_H
#define PROCESSPRIV_H

// std
#include <chrono>
#include <condition_variable>
#include <cstddef>
#include <functional>
#include <future>
#include <mutex>
#include <string>
#include <unistd.h>
#include <vector>
#include <unordered_map>

// boost
#include <boost/asio.hpp>
#include <boost/process.hpp>
#include <boost/filesystem/path.hpp>
#include <boost/system/error_code.hpp>

// qore
#include <qore/Qore.h>
#include <qore/QoreSandboxManager.h>
#include <qore/OutputStream.h>
#include <qore/InputStream.h>

#include <sys/resource.h>

// Resource limit settings (forward declaration, defined in processpriv.cpp)
struct resource_limits;

DLLLOCAL extern qore_classid_t CID_PROCESS;
DLLLOCAL extern QoreClass* QC_PROCESS;

namespace bp = boost::process::v2;

typedef std::unordered_map<bp::environment::key, bp::environment::value> env_t;

class ProcessPriv : public AbstractPrivateData {
public:
    DLLLOCAL ProcessPriv(pid_t pid, ExceptionSink* xsink);

    DLLLOCAL ProcessPriv(const char* command, const QoreListNode* arguments, const QoreHashNode* opts, ExceptionSink* xsink);

    DLLLOCAL int destructor(ExceptionSink* xsink);

    DLLLOCAL int exitCode(ExceptionSink* xsink);

    DLLLOCAL int id(ExceptionSink* xsink);

    DLLLOCAL bool valid(ExceptionSink* xsink);

    DLLLOCAL bool running(ExceptionSink* xsink);

    DLLLOCAL bool wait(ExceptionSink* xsink);

    DLLLOCAL bool wait(int64 t, ExceptionSink* xsink);

    DLLLOCAL bool detach(ExceptionSink* xsink);

    DLLLOCAL bool terminate(ExceptionSink* xsink);

    //! Send a signal to the child process.
    DLLLOCAL bool sendSignal(int sig, ExceptionSink* xsink);

    //! Read up to \c n bytes from process's stderr.
    DLLLOCAL QoreStringNode* readStderr(size_t n, ExceptionSink* xsink);

    //! Read up to \c n bytes from process's stderr. Wait up to \c millis milliseconds if there is no data.
    DLLLOCAL QoreStringNode* readStderrTimeout(size_t n, int64 millis, ExceptionSink* xsink);

    //! Read up to \c n bytes from process's stdout.
    DLLLOCAL QoreStringNode* readStdout(size_t n, ExceptionSink* xsink);

    //! Read up to \c n bytes from process's stdout. Wait up to \c millis milliseconds if there is no data.
    DLLLOCAL QoreStringNode* readStdoutTimeout(size_t n, int64 millis, ExceptionSink* xsink);

    //! Read up to \c n bytes from process's stderr.
    DLLLOCAL BinaryNode* readStderrBinary(size_t n, ExceptionSink* xsink);

    //! Read up to \c n bytes from process's stderr. Wait up to \c millis milliseconds if there is no data.
    DLLLOCAL BinaryNode* readStderrBinaryTimeout(size_t n, int64 millis, ExceptionSink* xsink);

    //! Read up to \c n bytes from process's stdout.
    DLLLOCAL BinaryNode* readStdoutBinary(size_t n, ExceptionSink* xsink);

    //! Read up to \c n bytes from process's stdout. Wait up to \c millis milliseconds if there is no data.
    DLLLOCAL BinaryNode* readStdoutBinaryTimeout(size_t n, int64 millis, ExceptionSink* xsink);

    //! Write to child process's stdin.
    DLLLOCAL void write(const char* val, size_t n, ExceptionSink* xsink);

    //! Close stdin pipe to signal EOF to child process.
    DLLLOCAL void closeStdin(ExceptionSink* xsink);

    DLLLOCAL static boost::filesystem::path optsPath(const char* command, const QoreHashNode* opts, ExceptionSink* xsink);

    DLLLOCAL static QoreHashNode* getMemorySummaryInfo(int pid, ExceptionSink* xsink);

    DLLLOCAL static bool checkPid(int pid, ExceptionSink* xsink);

    DLLLOCAL static void terminate(int pid, ExceptionSink* xsink);

    DLLLOCAL static void waitForTermination(int pid, ExceptionSink* xsink);

    DLLLOCAL static int64 getDescriptorCount(ExceptionSink* xsink, int pid);

    //! Run a command and return stdout, stderr, and exit code
    DLLLOCAL static QoreHashNode* run(const char* command, const QoreListNode* arguments,
        const QoreHashNode* opts, int64 timeout_ms, ExceptionSink* xsink);

    //! Get resource usage for the process
    DLLLOCAL QoreHashNode* getResourceUsage(ExceptionSink* xsink);

    //! Get resource usage for a specific PID (static)
    DLLLOCAL static QoreHashNode* getResourceUsage(int pid, ExceptionSink* xsink);

    //! Get child PIDs of the process
    DLLLOCAL QoreListNode* getChildPids(ExceptionSink* xsink);

    //! Get child PIDs for a specific PID (static)
    DLLLOCAL static QoreListNode* getChildPids(int pid, ExceptionSink* xsink);

    //! Get command line for a specific PID (static)
    DLLLOCAL static QoreStringNode* getCommandLine(int pid, ExceptionSink* xsink);

    //! Get the path to the executable of a specific PID (static)
    DLLLOCAL static QoreStringNode* getExecutablePath(int pid, ExceptionSink* xsink);

    //! Get system memory information (static)
    DLLLOCAL static QoreHashNode* getSystemMemoryInfo(ExceptionSink* xsink);

    //! Get PIDs listening on a TCP port (static)
    DLLLOCAL static QoreListNode* getPidsForPort(int port, ExceptionSink* xsink);

    //! Get PIDs using a Unix domain socket (static)
    DLLLOCAL static QoreListNode* getPidsForUnixSocket(const char* path, ExceptionSink* xsink);

    //! Terminate the process and all its children
    DLLLOCAL bool terminateTree(ExceptionSink* xsink);

protected:
    DLLLOCAL virtual ~ProcessPriv();

private:
    DLLLOCAL ResolvedCallReferenceNode* optsExecutor(const char* name, const QoreHashNode* opts, ExceptionSink* xsink);

    DLLLOCAL env_t optsEnv(const QoreHashNode* opts, ExceptionSink* xsink);
    DLLLOCAL std::string optsCwd(const QoreHashNode* opts, ExceptionSink* xsink);

    DLLLOCAL void optsStdin(const QoreHashNode* opts, ExceptionSink* xsink);

    DLLLOCAL int optsStdout(const char* keyName, const QoreHashNode* opts, ExceptionSink* xsink);

    DLLLOCAL bool processCheck(ExceptionSink* xsink);

    DLLLOCAL bool processReadStdoutCheck(ExceptionSink* xsink);

    DLLLOCAL bool processReadStderrCheck(ExceptionSink* xsink);

    //! Process exe arguments passed through constructor.
    DLLLOCAL void processArgs(const QoreListNode* arguments, std::vector<std::string>& out);

    //! Prepare stdin ASIO buffer for use in async_write operation.
    DLLLOCAL void prepareStdinBuffer();

    DLLLOCAL void prepareClosures();

    DLLLOCAL void launchChild(ExceptionSink* xsink,
            boost::filesystem::path p,
            std::vector<std::string>& args,
            env_t env,
            const char* cwd,
            FILE* stdoutFile,
            FILE* stderrFile,
            const QoreHashNode* opts,
            bool setNice,
            int niceValue,
            const resource_limits& limits);

    DLLLOCAL void finalizeStreams(ExceptionSink* xsink);

    DLLLOCAL QoreStringNode* getString(QoreStringNode* str);

    DLLLOCAL void getExitCode(ExceptionSink* xsink);

#if defined(__APPLE__) && defined(__MACH__)
    DLLLOCAL static QoreHashNode* getMemorySummaryInfoDarwin(int pid, ExceptionSink* xsink);
    DLLLOCAL static QoreHashNode* getSystemMemoryInfoDarwin(ExceptionSink* xsink);
#endif

#ifdef __linux__
    DLLLOCAL static QoreHashNode* getMemorySummaryInfoLinux(int pid, ExceptionSink* xsink);
    DLLLOCAL static QoreHashNode* getSystemMemoryInfoLinux(ExceptionSink* xsink);
    DLLLOCAL static QoreHashNode* getMemorySummaryInfoLinuxSmaps(ExceptionSink* xsink, int pid, QoreFile& f,
        ReferenceHolder<QoreHashNode>& rv);
#endif

#ifdef __sun__
    DLLLOCAL static QoreHashNode* getMemorySummaryInfoSolaris(int pid, ExceptionSink* xsink);
#endif

    //! Thread-safe input buffer. Used for writing to child process's stdin.
    class InputBuffer final {
    public:
        DLLLOCAL InputBuffer(ExceptionSink* xsink) : bg_xsink(xsink), stream(bg_xsink)  {
        }

        DLLLOCAL InputBuffer(InputBuffer&& a) = delete;
        DLLLOCAL InputBuffer(const InputBuffer& a) = delete;
        DLLLOCAL InputBuffer& operator=(InputBuffer&& other) = delete;
        DLLLOCAL InputBuffer& operator=(const InputBuffer& other) = delete;
        DLLLOCAL ~InputBuffer() {}

        //! Returns true if the buffer has an input stream
        DLLLOCAL bool hasStream() const {
            return (bool)stream;
        }

        DLLLOCAL void setStream(InputStream* stream) {
            assert(stream);
            assert(!this->stream);
            this->stream = stream;
        }

        DLLLOCAL InputStream* finalize(ExceptionSink* xsink) {
            if (!stream) {
                return nullptr;
            }
            stream->reassignThread(xsink);
            return stream.release();
        }

        //! Get size of data currently in buffer.
        DLLLOCAL size_t size() {
            return m_buf.size();
        }

        //! Write data into the input buffer.
        DLLLOCAL void write(const char* src, size_t n) {
            // cannot be called if an input stream has been set already
            assert(!stream);

            if (!src || !n)
                return;

            std::lock_guard<std::mutex> lock(m_mtx);
            m_buf.append(src, n);
        }

        //! Extract data from the input buffer.
        DLLLOCAL size_t extract(std::vector<char>& dest, size_t n) {
            if (!n)
                return 0;

            if (stream) {
                // FIXME: need support for async I/O with streams
                dest.resize(n);
                int64 size = stream->read(dest.data(), n, bg_xsink);
                dest.resize(size);
                return (size_t) size;
            } else {
                std::lock_guard<std::mutex> lock(m_mtx);

                // fix the read size
                if (m_buf.size() < n)
                    n = m_buf.size();

                dest.resize(n);
                m_buf.copy(dest.data(), n, 0);
                m_buf.erase(0, n);
                return n;
            }
        }

    private:
        std::mutex m_mtx;
        std::string m_buf;

        ExceptionSink* bg_xsink;
        PrivateDataRefHolder<InputStream> stream;
    };

    //! Thread-safe output buffer. Used for storing data from child process's stdout and stderr.
    class OutputBuffer final {
    public:
        DLLLOCAL OutputBuffer(ExceptionSink* xsink) : bg_xsink(xsink), stream(bg_xsink) {
        }

        DLLLOCAL OutputBuffer(OutputBuffer&& a) = delete;
        DLLLOCAL OutputBuffer(const OutputBuffer& a) = delete;
        DLLLOCAL OutputBuffer& operator=(OutputBuffer&& other) = delete;
        DLLLOCAL OutputBuffer& operator=(const OutputBuffer& other) = delete;
        DLLLOCAL ~OutputBuffer() {
            m_timeout_sync.notify_all();
        }

        //! Returns true if the buffer has an input stream
        DLLLOCAL bool hasStream() const {
            return (bool)stream;
        }

        DLLLOCAL void setStream(OutputStream* stream) {
            assert(stream);
            assert(!this->stream);
            this->stream = stream;
        }

        DLLLOCAL OutputStream* finalize(ExceptionSink* xsink) {
            if (!stream) {
                return nullptr;
            }
            stream->reassignThread(xsink);
            return stream.release();
        }

        DLLLOCAL void reassignThread() {
            if (stream && (stream->getThreadId() != q_gettid())) {
                stream->reassignThread(bg_xsink);
                if (*bg_xsink) {
                    stream = nullptr;
                }
            }
        }

        DLLLOCAL void unassignThread() {
            if (stream && (stream->getThreadId() == q_gettid())) {
                stream->unassignThread(bg_xsink);
            }
        }

        //! Read from the buffer and return instantly if there is no data. Does not add null character at the end.
        DLLLOCAL size_t read(char* dest, size_t n) {
            // cannot be called if an output stream has been set already
            assert(!stream);

            if (!dest || !n)
                return 0;

            //std::lock_guard<std::mutex> lock(m_mutex);
            std::unique_lock<std::mutex> lock(m_mtx);

            // return immediately if there is no data
            if (m_buf.size() == 0)
                return 0;

            return doRead(dest, n);
        }

        //! Read from the buffer to a Qore string and return instantly if there is no data.
        DLLLOCAL size_t read(QoreString* dest, size_t n) {
            // cannot be called if an output stream has been set already
            assert(!stream);

            if (!dest || !n)
                return 0;

            //std::lock_guard<std::mutex> lock(m_mutex);
            std::unique_lock<std::mutex> lock(m_mtx);

            // return immediately if there is no data
            if (m_buf.size() == 0)
                return 0;

            return doRead(dest, n);
        }

        //! Read from the buffer to a Qore string and return instantly if there is no data.
        DLLLOCAL size_t read(BinaryNode* dest, size_t n) {
            // cannot be called if an output stream has been set already
            assert(!stream);

            if (!dest || !n)
                return 0;

            //std::lock_guard<std::mutex> lock(m_mutex);
            std::unique_lock<std::mutex> lock(m_mtx);

            // return immediately if there is no data
            if (m_buf.size() == 0)
                return 0;

            return doRead(dest, n);
        }

        //! Read from the buffer and return if there is no data after timeout period. Does not add null character at the end.
        DLLLOCAL size_t readTimeout(char* dest, size_t n, int64 millis) {
            // cannot be called if an output stream has been set already
            assert(!stream);

            if (!dest || !n)
                return 0;

            auto until = std::chrono::steady_clock::now() + std::chrono::milliseconds(millis);
            std::unique_lock<std::mutex> lock(m_mtx);

            // wait if there is no data
            if (m_buf.size() == 0) {
                m_timeout_sync.wait_until(lock, until, [this]{ return m_buf.size() > 0; });

                // return if there is still no data after timeout
                if (m_buf.size() == 0)
                    return 0;
            }

            return doRead(dest, n);
        }

        //! Read from the buffer and return if there is no data after timeout period.
        DLLLOCAL size_t readTimeout(QoreString* dest, size_t n, int64 millis) {
            // cannot be called if an output stream has been set already
            assert(!stream);

            if (!dest || !n)
                return 0;

            auto until = std::chrono::steady_clock::now() + std::chrono::milliseconds(millis);
            std::unique_lock<std::mutex> lock(m_mtx);

            // wait if there is no data
            if (m_buf.size() == 0) {
                m_timeout_sync.wait_until(lock, until, [this]{ return m_buf.size() > 0; });

                // return if there is still no data after timeout
                if (m_buf.size() == 0)
                    return 0;
            }

            return doRead(dest, n);
        }

        //! Read from the buffer and return if there is no data after timeout period.
        DLLLOCAL size_t readTimeout(BinaryNode* dest, size_t n, int64 millis) {
            // cannot be called if an output stream has been set already
            assert(!stream);

            if (!dest || !n)
                return 0;

            auto until = std::chrono::steady_clock::now() + std::chrono::milliseconds(millis);
            std::unique_lock<std::mutex> lock(m_mtx);

            // wait if there is no data
            if (m_buf.size() == 0) {
                m_timeout_sync.wait_until(lock, until, [this]{ return m_buf.size() > 0; });

                // return if there is still no data after timeout
                if (m_buf.size() == 0)
                    return 0;
            }

            return doRead(dest, n);
        }

        //! Append data to the buffer.
        DLLLOCAL void append(const char* src, size_t n) {
            if (!src || !n)
                return;

            if (stream) {
                stream->write(src, n, bg_xsink);
            } else {
                std::lock_guard<std::mutex> lock(m_mtx);
                m_buf.append(src, n);
            }

            // notify outside of the lock
            m_timeout_sync.notify_all();
        }

    private:
        std::mutex m_mtx;
        std::condition_variable m_timeout_sync;
        std::string m_buf;

        ExceptionSink* bg_xsink;
        PrivateDataRefHolder<OutputStream> stream;

        //! Read data from buffer in to the destination. Expects that mutex is locked.
        DLLLOCAL size_t doRead(char* dest, size_t n) {
            // fix the read size
            if (m_buf.size() < n)
                n = m_buf.size();

            m_buf.copy(dest, n, 0);
            m_buf.erase(0, n);
            return n;
        }

        //! Read data from buffer in to the destination Qore string. Expects that mutex is locked.
        DLLLOCAL size_t doRead(QoreString* dest, size_t n) {
            // fix the read size
            if (m_buf.size() < n)
                n = m_buf.size();

            dest->concat(m_buf.c_str(), n);
            m_buf.erase(0, n);
            return n;
        }

        //! Read data from buffer in to the destination Qore string. Expects that mutex is locked.
        DLLLOCAL size_t doRead(BinaryNode* dest, size_t n) {
            // fix the read size
            if (m_buf.size() < n)
                n = m_buf.size();

            dest->append(m_buf.c_str(), n);
            m_buf.erase(0, n);
            return n;
        }
    };

    DLLLOCAL void setExitCode(boost::system::error_code ec, int e);

    //! Child process.
    bp::process* m_process = nullptr;

    //! Async context required for async IO.
    boost::asio::io_context m_asio_ctx;

    //! Async context future required for running the context in new thread.
    std::future<void> m_asio_ctx_run_future;

    //! Pipe used for writing to child process's stdin.
    boost::asio::writable_pipe m_in_pipe;

    //! Pipe used for reading child process's stdout.
    boost::asio::readable_pipe m_out_pipe;

    //! Pipe used for reading child process's stderr.
    boost::asio::readable_pipe m_err_pipe;

    //! Mutex covering the @ref m_async_write_running variable.
    std::mutex m_async_write_mtx{};

    //! Used for signifying that async_write operation is running.
    /**
        Needed because we cannot allow multiple async_write operations to run at the same time.
        More info about this here: https://www.boost.org/doc/libs/1_67_0/doc/html/boost_asio/reference/async_write/overload5.html
     */
    int m_async_write_running = 0;

    //! Mutex for bg_xsink and atomic char reads
    QoreThreadLock bg_lck;

    //! Background exception sink
    ExceptionSink bg_xsink;

    //! Buffer containg data that should be written to child process's stdin.
    InputBuffer m_in_buf;

    OutputBuffer m_out_buf; //!< Buffer containg data read from child process's stdout.
    OutputBuffer m_err_buf; //!< Buffer containg data read from child process's stderr.

    //! Vector containing data currently being written to child process's stdin.
    std::vector<char> m_in_vec{};

    //! Vector where data read from child process's stdout is written before being copied to @ref m_out_buf.
    std::vector<char> m_out_vec{};

    //! Vector where data read from child process's stderr is written before being copied to @ref m_err_buf.
    std::vector<char> m_err_vec{};

    boost::asio::const_buffer m_in_asiobuf;    //!< Buffer wrapping the stdin vector.
    boost::asio::mutable_buffer m_out_asiobuf; //!< Buffer wrapping the stdout vector.
    boost::asio::mutable_buffer m_err_asiobuf; //!< Buffer wrapping the stderr vector.

    //! Closure called after stdin async_write operation is completed.
    std::function<void(const boost::system::error_code& ec, size_t n)> m_on_stdin_complete;

    //! Closure called after stdout async_read operation is completed.
    std::function<void(const boost::system::error_code& ec, size_t n)> m_on_stdout_complete;

    //! Closure called after stderr async_read operation is completed.
    std::function<void(const boost::system::error_code& ec, size_t n)> m_on_stderr_complete;

    //! Encoding for output strings
    const QoreEncoding* enc = QCS_DEFAULT;

    //! Buffer for partial multi-byte characters
    SimpleRefHolder<BinaryNode> charbuf = new BinaryNode;

    //! Counter for stream assignments
    QoreCounter stream_cnt;

    // mutex for process status
    std::mutex mtx_process_status;
    // cond var for exit_code and running_flag
    std::condition_variable cond_process_status;
    // threads waiting on the process status
    unsigned int process_status_waiting = 0;

    //! Exit code for program; lock: mtx_process_status, cond: cond_process_status
    int exit_code = -1;

    //! Running flag; lock: mtx_process_status, cond: cond_process_status
    bool running_flag = false;

    //! Detached flag
    int detached_pid = 0;
};

#endif
