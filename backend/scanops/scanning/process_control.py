"""Own backend-launched subprocess trees for backend lifetime and worker cleanup."""
from __future__ import annotations

import os
from pathlib import Path
import select
import signal
import subprocess
import sys
import threading
import time


PARENT_FD_ENV = "SCANOPS_ENGINE_PARENT_FD"
_JOB_HANDLE_ATTR = "_scanops_backend_job_handle"
_PARENT_WRITE_ATTR = "_scanops_parent_write_fd"
_CHILD_PGID_ATTR = "_scanops_guard_child_pgid"
_CREATE_SUSPENDED = 0x00000004
_JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE = 0x00002000
_JOB_OBJECT_EXTENDED_LIMIT_INFORMATION = 9
_POSIX_GUARD_ARG = "--scanops-posix-guard"
_GUARD_START_TIMEOUT = 10.0


def popen_owned(*args, child_guards_parent: bool = False, **kwargs) -> subprocess.Popen:
    """Start a child in a backend-owned Windows job or POSIX guarded process group."""
    if os.name != "nt":
        if not child_guards_parent:
            return _popen_posix_guarded(*args, **kwargs)
        read_fd, write_fd = os.pipe()
        env = dict(kwargs.pop("env", None) or os.environ)
        env[PARENT_FD_ENV] = str(read_fd)
        pass_fds = tuple(kwargs.pop("pass_fds", ())) + (read_fd,)
        try:
            process = subprocess.Popen(
                *args, env=env, pass_fds=pass_fds, start_new_session=True, **kwargs,
            )
        except BaseException:
            os.close(write_fd)
            raise
        finally:
            os.close(read_fd)
        setattr(process, _PARENT_WRITE_ATTR, write_fd)
        return process

    creationflags = int(kwargs.pop("creationflags", 0))
    kwargs["creationflags"] = (
        creationflags | subprocess.CREATE_NEW_PROCESS_GROUP | _CREATE_SUSPENDED
    )
    process = subprocess.Popen(*args, **kwargs)
    try:
        setattr(process, _JOB_HANDLE_ATTR, _create_kill_job(process))
        _resume_process(process)
    except BaseException:
        try:
            _close_job(process)
        finally:
            if process.poll() is None:
                process.kill()
            process.wait(timeout=5)
        raise
    return process


def _popen_posix_guarded(*args, **kwargs) -> subprocess.Popen:
    """Launch through a tiny supervisor that owns the real child's private PGID."""
    if len(args) != 1:
        raise TypeError("popen_owned expects one argv sequence")
    if kwargs.pop("shell", False):
        raise ValueError("backend-owned subprocesses require shell=False")
    command = args[0]
    if isinstance(command, (str, bytes, os.PathLike)):
        argv = [os.fsdecode(command)]
    else:
        argv = [os.fsdecode(os.fspath(item)) for item in command]
    if not argv:
        raise ValueError("backend-owned subprocess command is empty")

    target_pass_fds = tuple(int(fd) for fd in kwargs.pop("pass_fds", ()))
    kwargs.pop("start_new_session", None)
    kwargs["close_fds"] = True
    owner_read_fd, owner_write_fd = os.pipe()
    status_read_fd, status_write_fd = os.pipe()
    guard_argv = [
        sys.executable,
        str(Path(__file__).resolve()),
        _POSIX_GUARD_ARG,
        str(owner_read_fd),
        str(status_write_fd),
        ",".join(str(fd) for fd in target_pass_fds),
        *argv,
    ]
    process: subprocess.Popen | None = None
    try:
        process = subprocess.Popen(
            guard_argv,
            pass_fds=(*target_pass_fds, owner_read_fd, status_write_fd),
            start_new_session=True,
            **kwargs,
        )
        os.close(owner_read_fd)
        owner_read_fd = -1
        os.close(status_write_fd)
        status_write_fd = -1
        status = _read_guard_status(status_read_fd)
        if not status.startswith("OK:"):
            if status.startswith("ERR:"):
                try:
                    error_number = int(status.split(":", 1)[1])
                except ValueError:
                    error_number = 0
                raise OSError(error_number, "backend-owned child failed to start")
            raise OSError("backend-owned child guard exited before startup")
        child_pgid = int(status.split(":", 1)[1])
        setattr(process, _PARENT_WRITE_ATTR, owner_write_fd)
        setattr(process, _CHILD_PGID_ATTR, child_pgid)
        owner_write_fd = -1
        return process
    except BaseException:
        if owner_write_fd >= 0:
            os.close(owner_write_fd)
        if process is not None:
            try:
                process.wait(timeout=2)
            except subprocess.TimeoutExpired:
                try:
                    os.killpg(process.pid, signal.SIGKILL)
                except ProcessLookupError:
                    pass
                process.wait(timeout=2)
        raise
    finally:
        for fd in (owner_read_fd, status_read_fd, status_write_fd):
            if fd >= 0:
                try:
                    os.close(fd)
                except OSError:
                    pass


def _read_guard_status(fd: int) -> str:
    deadline = time.monotonic() + _GUARD_START_TIMEOUT
    data = bytearray()
    while b"\n" not in data:
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            raise TimeoutError("backend-owned child guard startup timed out")
        readable, _, _ = select.select([fd], [], [], remaining)
        if not readable:
            raise TimeoutError("backend-owned child guard startup timed out")
        chunk = os.read(fd, 256)
        if not chunk:
            break
        data.extend(chunk)
        if len(data) > 256:
            raise OSError("invalid backend-owned child guard status")
    return bytes(data).split(b"\n", 1)[0].decode("ascii", "replace")


def close_owned(process: subprocess.Popen | None, timeout: float = 3.0) -> None:
    """Release ownership, terminating any descendants that remain."""
    if process is None:
        return
    if os.name == "nt":
        if not _close_job(process):
            return
        if process.poll() is None:
            try:
                process.wait(timeout=timeout)
            except subprocess.TimeoutExpired:
                process.kill()
                process.wait(timeout=timeout)
        return

    write_fd = getattr(process, _PARENT_WRITE_ATTR, None)
    if write_fd is None:
        return
    child_pgid = getattr(process, _CHILD_PGID_ATTR, None)
    try:
        os.close(write_fd)
    except OSError:
        pass
    setattr(process, _PARENT_WRITE_ATTR, None)
    if process.poll() is None:
        try:
            process.wait(timeout=timeout)
        except subprocess.TimeoutExpired:
            try:
                os.killpg(process.pid, signal.SIGTERM)
            except ProcessLookupError:
                pass
            try:
                process.wait(timeout=timeout)
            except subprocess.TimeoutExpired:
                pass
    # A private group can outlive its leader. Clear the real guarded child PGID as well as
    # the supervisor/engine PGID even when wait() already reaped either leader.
    for pgid in (child_pgid, process.pid):
        if not pgid:
            continue
        try:
            os.killpg(pgid, signal.SIGKILL)
        except ProcessLookupError:
            pass
    if process.poll() is None:
        process.wait(timeout=timeout)


def _guard_write_status(fd: int, value: str) -> bool:
    try:
        os.write(fd, f"{value}\n".encode("ascii", "replace"))
        return True
    except OSError:
        return False
    finally:
        try:
            os.close(fd)
        except OSError:
            pass


def _guard_kill_group(child: subprocess.Popen, timeout: float = 2.0) -> int:
    """Stop the child PGID and clear descendants even if its leader exits first."""
    try:
        os.killpg(child.pid, signal.SIGTERM)
    except ProcessLookupError:
        pass
    try:
        returncode = child.wait(timeout=timeout)
    except subprocess.TimeoutExpired:
        returncode = None
    try:
        os.killpg(child.pid, signal.SIGKILL)
    except ProcessLookupError:
        pass
    if returncode is None:
        returncode = child.wait(timeout=timeout)
    return returncode


def _guard_main(owner_fd: int, status_fd: int, target_pass_fds: tuple[int, ...],
                argv: list[str]) -> int:
    stop_requested = threading.Event()

    def request_stop(_signum=None, _frame=None) -> None:
        stop_requested.set()

    for sig in (signal.SIGTERM, signal.SIGINT, signal.SIGHUP):
        signal.signal(sig, request_stop)

    def watch_owner() -> None:
        try:
            while os.read(owner_fd, 1024):
                pass
        except OSError:
            pass
        finally:
            try:
                os.close(owner_fd)
            except OSError:
                pass
            stop_requested.set()

    threading.Thread(target=watch_owner, name="scanops-backend-guard", daemon=True).start()
    if stop_requested.is_set():
        _guard_write_status(status_fd, "ERR:125")
        return 125

    child_env = dict(os.environ)
    child_env.pop(PARENT_FD_ENV, None)
    try:
        child = subprocess.Popen(
            argv,
            env=child_env,
            pass_fds=target_pass_fds,
            start_new_session=True,
        )
    except OSError as exc:
        _guard_write_status(status_fd, f"ERR:{exc.errno or 1}")
        return 127
    if not _guard_write_status(status_fd, f"OK:{child.pid}"):
        # The backend disappeared between spawning the child and reading the handshake.
        return _guard_kill_group(child)

    while child.poll() is None and not stop_requested.wait(0.05):
        pass
    if stop_requested.is_set():
        return _guard_kill_group(child)

    returncode = child.wait()
    # A program can exit while leaving grandchildren in its session. This is still our tree.
    _guard_kill_group(child, timeout=0.25)
    return returncode


def _guard_exit(returncode: int) -> None:
    if returncode < 0:
        sig = -returncode
        signal.signal(sig, signal.SIG_DFL)
        os.kill(os.getpid(), sig)
    raise SystemExit(returncode)


def _close_job(process: subprocess.Popen) -> bool:
    handle_value = getattr(process, _JOB_HANDLE_ATTR, None)
    if not handle_value:
        return False

    import ctypes
    from ctypes import wintypes

    kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
    close_handle = kernel32.CloseHandle
    close_handle.argtypes = (wintypes.HANDLE,)
    close_handle.restype = wintypes.BOOL
    if not close_handle(wintypes.HANDLE(handle_value)):
        raise ctypes.WinError(ctypes.get_last_error())
    setattr(process, _JOB_HANDLE_ATTR, None)
    return True


def _create_kill_job(process: subprocess.Popen) -> int:
    import ctypes
    from ctypes import wintypes

    class BasicLimitInformation(ctypes.Structure):
        _fields_ = [
            ("PerProcessUserTimeLimit", ctypes.c_longlong),
            ("PerJobUserTimeLimit", ctypes.c_longlong),
            ("LimitFlags", wintypes.DWORD),
            ("MinimumWorkingSetSize", ctypes.c_size_t),
            ("MaximumWorkingSetSize", ctypes.c_size_t),
            ("ActiveProcessLimit", wintypes.DWORD),
            ("Affinity", ctypes.c_size_t),
            ("PriorityClass", wintypes.DWORD),
            ("SchedulingClass", wintypes.DWORD),
        ]

    class IoCounters(ctypes.Structure):
        _fields_ = [
            ("ReadOperationCount", ctypes.c_ulonglong),
            ("WriteOperationCount", ctypes.c_ulonglong),
            ("OtherOperationCount", ctypes.c_ulonglong),
            ("ReadTransferCount", ctypes.c_ulonglong),
            ("WriteTransferCount", ctypes.c_ulonglong),
            ("OtherTransferCount", ctypes.c_ulonglong),
        ]

    class ExtendedLimitInformation(ctypes.Structure):
        _fields_ = [
            ("BasicLimitInformation", BasicLimitInformation),
            ("IoInfo", IoCounters),
            ("ProcessMemoryLimit", ctypes.c_size_t),
            ("JobMemoryLimit", ctypes.c_size_t),
            ("PeakProcessMemoryUsed", ctypes.c_size_t),
            ("PeakJobMemoryUsed", ctypes.c_size_t),
        ]

    kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
    create_job = kernel32.CreateJobObjectW
    create_job.argtypes = (ctypes.c_void_p, wintypes.LPCWSTR)
    create_job.restype = wintypes.HANDLE
    set_information = kernel32.SetInformationJobObject
    set_information.argtypes = (
        wintypes.HANDLE, ctypes.c_int, ctypes.c_void_p, wintypes.DWORD,
    )
    set_information.restype = wintypes.BOOL
    assign_process = kernel32.AssignProcessToJobObject
    assign_process.argtypes = (wintypes.HANDLE, wintypes.HANDLE)
    assign_process.restype = wintypes.BOOL
    close_handle = kernel32.CloseHandle
    close_handle.argtypes = (wintypes.HANDLE,)
    close_handle.restype = wintypes.BOOL

    job = create_job(None, None)
    if not job:
        raise ctypes.WinError(ctypes.get_last_error())
    try:
        limits = ExtendedLimitInformation()
        limits.BasicLimitInformation.LimitFlags = _JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE
        if not set_information(
            job,
            _JOB_OBJECT_EXTENDED_LIMIT_INFORMATION,
            ctypes.byref(limits),
            ctypes.sizeof(limits),
        ):
            raise ctypes.WinError(ctypes.get_last_error())
        if not assign_process(job, wintypes.HANDLE(int(process._handle))):
            raise ctypes.WinError(ctypes.get_last_error())
        return int(job)
    except BaseException:
        close_handle(job)
        raise


def _resume_process(process: subprocess.Popen) -> None:
    import ctypes
    from ctypes import wintypes

    ntdll = ctypes.WinDLL("ntdll")
    resume_process = ntdll.NtResumeProcess
    resume_process.argtypes = (wintypes.HANDLE,)
    resume_process.restype = wintypes.LONG
    status = int(resume_process(wintypes.HANDLE(int(process._handle))))
    if status != 0:
        raise OSError(f"NtResumeProcess failed with NTSTATUS 0x{status & 0xffffffff:08x}")


if __name__ == "__main__" and os.name != "nt" and len(sys.argv) >= 6 \
        and sys.argv[1] == _POSIX_GUARD_ARG:
    inherited_fds = tuple(int(fd) for fd in sys.argv[4].split(",") if fd)
    _guard_exit(_guard_main(int(sys.argv[2]), int(sys.argv[3]), inherited_fds, sys.argv[5:]))
