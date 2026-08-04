"""Subprocess launch helpers with deterministic descendant cleanup."""
from __future__ import annotations

import os
import subprocess


_JOB_HANDLE_ATTR = "_scanops_kill_job_handle"
_CREATE_SUSPENDED = 0x00000004
_JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE = 0x00002000
_JOB_OBJECT_EXTENDED_LIMIT_INFORMATION = 9


def popen_tracked(*args, **kwargs) -> subprocess.Popen:
    """Start a process in an owned group/job before any child code can run."""
    if os.name != "nt":
        kwargs.setdefault("start_new_session", True)
        return subprocess.Popen(*args, **kwargs)

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
            close_kill_job(process)
        finally:
            if process.poll() is None:
                process.kill()
            process.wait(timeout=5)
        raise
    return process


def close_kill_job(process: subprocess.Popen | None) -> bool:
    """Close a tracked Windows job, terminating every process still inside it."""
    if process is None or os.name != "nt":
        return False
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
