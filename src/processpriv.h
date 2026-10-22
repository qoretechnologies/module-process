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
#include <memory>
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

//! The exceptions raised on the background I/O thread, rethrown in a thread that waits for the process
/** An exception is counted as active on the thread that raises it until it is handled there.  The exceptions of this
    sink are raised on the I/O thread and handled in another thread, so they are not counted on any thread: the I/O
    thread raises them in a sink of its own and hands them over with take().  Raising them here directly would leave
    them counted on the I/O thread, which ends with active exceptions (an assertion in debug builds of the library),
    while the thread that handles them would release a count that it never had.
*/
class BackgroundExceptionSink : public ExceptionSink {
public:
    DLLLOCAL BackgroundExceptionSink() {
        markExternallyManaged();
    }

    //! Takes the exceptions raised in the given sink on the current thread, which then no longer counts them
    DLLLOCAL void take(ExceptionSink& xs) {
        if (xs) {
            xs.markExternallyManaged();
            assimilate(xs);
        }
    }
};

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

    //! Returns free memory held by the allocator of the current process to the operating system (static)
    DLLLOCAL static bool releaseFreeMemory();

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

    //! Processes the \c stdout or \c stderr option
    /** @return a duplicate of the descriptor of the File object given, which the caller closes, or -1 if no File
        object was given (an OutputStream is set on the output buffer) or an exception was raised
    */
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
            int stdoutFd,
            int stderrFd,
            const QoreHashNode* opts,
            bool setNice,
            int niceValue,
            const resource_limits& limits,
            bool killOnParentExit);

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
        DLLLOCAL InputBuffer(BackgroundExceptionSink* xsink) : bg_xsink(xsink), stream(bg_xsink)  {
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
                ExceptionSink xs;
                int64 size = stream->read(dest.data(), n, &xs);
                bg_xsink->take(xs);
                if (size < 0) {
                    size = 0;
                }
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

        BackgroundExceptionSink* bg_xsink;
        PrivateDataRefHolder<InputStream> stream;
    };

    //! Thread-safe output buffer. Used for storing data from child process's stdout and stderr.
    class OutputBuffer final {
    public:
        DLLLOCAL OutputBuffer(BackgroundExceptionSink* xsink) : bg_xsink(xsink), stream(bg_xsink) {
        }

        DLLLOCAL OutputBuffer(OutputBuffer&& a) = delete;
        DLLLOCAL OutputBuffer(const OutputBuffer& a) = delete;
        DLLLOCAL OutputBuffer& operator=(OutputBuffer&& other) = delete;
        DLLLOCAL OutputBuffer& operator=(const OutputBuffer& other) = delete;
        DLLLOCAL ~OutputBuffer() {
            m_timeout_sync.notify_all();
            if (stream_obj) {
                ExceptionSink xs;
                stream_obj->deref(&xs);
            }
        }

        //! Returns true if the buffer has an input stream
        DLLLOCAL bool hasStream() const {
            return (bool)stream;
        }

        //! Sets the stream, which must be the private data of the given object
        /** The object is kept until the stream is released with finalize() and takeStreamObject(): a stream
            implemented in Qore runs the methods of its object when it is written to, so the object must exist even
            if the caller keeps no reference to it
        */
        DLLLOCAL void setStream(OutputStream* stream, QoreObject* obj) {
            assert(stream);
            assert(!this->stream);
            assert(!stream_obj);
            this->stream = stream;
            obj->ref();
            stream_obj = obj;
        }

        //! Returns the object of the stream, which the caller dereferences, or nullptr if there is none
        DLLLOCAL QoreObject* takeStreamObject() {
            QoreObject* rv = stream_obj;
            stream_obj = nullptr;
            return rv;
        }

        DLLLOCAL OutputStream* finalize(ExceptionSink* xsink) {
            if (!stream) {
                return nullptr;
            }
            stream->reassignThread(xsink);
            return stream.release();
        }

        //! Assigns the stream to the background I/O thread; called on that thread
        DLLLOCAL void reassignThread() {
            if (stream && (stream->getThreadId() != q_gettid())) {
                ExceptionSink xs;
                stream->reassignThread(&xs);
                if (xs) {
                    // the stream cannot be used on this thread
                    stream.release()->deref(&xs);
                }
                bg_xsink->take(xs);
            }
        }

        //! Releases the stream from the background I/O thread; called on that thread
        DLLLOCAL void unassignThread() {
            if (stream && (stream->getThreadId() == q_gettid())) {
                ExceptionSink xs;
                stream->unassignThread(&xs);
                bg_xsink->take(xs);
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

            // wait if there is no data, until data arrives, the output ends, or the timeout expires
            if (m_buf.size() == 0) {
                m_timeout_sync.wait_until(lock, until, [this]{ return m_buf.size() > 0 || m_ended; });

                // return if there is still no data: the timeout expired, or the output has ended
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

            // wait if there is no data, until data arrives, the output ends, or the timeout expires
            if (m_buf.size() == 0) {
                m_timeout_sync.wait_until(lock, until, [this]{ return m_buf.size() > 0 || m_ended; });

                // return if there is still no data: the timeout expired, or the output has ended
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

            // wait if there is no data, until data arrives, the output ends, or the timeout expires
            if (m_buf.size() == 0) {
                m_timeout_sync.wait_until(lock, until, [this]{ return m_buf.size() > 0 || m_ended; });

                // return if there is still no data: the timeout expired, or the output has ended
                if (m_buf.size() == 0)
                    return 0;
            }

            return doRead(dest, n);
        }

        //! Marks the end of the output: no more data will be appended, and readers waiting for data return
        /** Called when the output stream reaches its end or is no longer read (ex: the child exited), and for output
            that is never read into the buffer (redirected to a file, or a process that was not started here)
        */
        DLLLOCAL void setEnded() {
            {
                std::lock_guard<std::mutex> lock(m_mtx);
                m_ended = true;
            }
            m_timeout_sync.notify_all();
        }

        //! Append data to the buffer.
        DLLLOCAL void append(const char* src, size_t n) {
            if (!src || !n)
                return;

            if (stream) {
                ExceptionSink xs;
                stream->write(src, n, &xs);
                bg_xsink->take(xs);
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
        //! True when no more data will be appended
        bool m_ended = false;

        BackgroundExceptionSink* bg_xsink;
        PrivateDataRefHolder<OutputStream> stream;
        //! The object of the stream (referenced), or nullptr
        QoreObject* stream_obj = nullptr;

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

    //! The sandbox of the code that started the process, which governs the background I/O thread
    /** The thread is not started with q_start_thread(), so it does not inherit the sandbox of the code that starts
        it; the output streams given run Qore code on it (ex: a Qore-language OutputStream subclass).  Declared
        before @ref m_asio_ctx_run_future, so it is destroyed after the thread has been joined.
    */
    std::unique_ptr<QoreSandboxCapture> m_sandbox;

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

    //! The exceptions raised on the background I/O thread
    BackgroundExceptionSink bg_xsink;

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

    //! The PID of a detached process; 0 if the process has not been detached
    int detached_pid = 0;

    //! True if the object was created from a PID; the background handler does not report the end of such a process
    bool from_pid = false;

    //! A descriptor that becomes readable when a process whose end the background handler does not report ends
    /** A pidfd on Linux with a libqore that provides qore_cancellable_poll(), opened when the process is detached or
        attached by its PID, so that a PID reused after the process ended is never taken for it; -1 otherwise
    */
    int end_fd = -1;

    //! Opens @ref end_fd for the given process if the platform supports it
    DLLLOCAL void openEndFd(int pid);

    //! Waits until a process whose end the background handler does not report ends, or the timeout expires
    /** The background handler reports only the end of a process started by this object and not detached.  The end of
        a detached process, or of one this object was created from by its PID, is waited for on @ref end_fd, and a
        cancellation of the calling thread ends the wait at once; without @ref end_fd, the process is polled.

        @param ms the timeout in milliseconds; a negative value waits until the process ends

        @return true if the process ended; false if the timeout expired, or if an exception was raised
    */
    DLLLOCAL bool waitForEnd(int64 ms, ExceptionSink* xsink);

    //! Polls until the process ends or the timeout expires; used only where there is no @ref end_fd
    /** @param ms the timeout in milliseconds; a negative value polls until the process ends

        @return true if the process ended; false if the timeout expired, or if an exception was raised
    */
    DLLLOCAL bool pollForEnd(int64 ms, ExceptionSink* xsink);
};

#endif
