"""Windows Job Object sandbox for helper processes (AC-11 / AC-12).

Only our own compile-time fixtures are ever executed; the analysed target is never
run (PLAN: static only). The sandbox caps job memory, blocks extra processes with
ActiveProcessLimit and kills the whole tree on timeout.
"""
from __future__ import annotations

import ctypes
import os
import subprocess
import sys
import time
from ctypes import wintypes
from dataclasses import dataclass
from typing import List, Optional, Sequence

IS_WINDOWS = os.name == "nt"

STARTF_USESTDHANDLES = 0x00000100
HANDLE_FLAG_INHERIT = 0x00000001

JOB_OBJECT_LIMIT_PROCESS_MEMORY = 0x00000100
JOB_OBJECT_LIMIT_JOB_MEMORY = 0x00000200
JOB_OBJECT_LIMIT_ACTIVE_PROCESS = 0x00000008
JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE = 0x00002000

JobObjectBasicLimitInformation = 1
JobObjectExtendedLimitInformation = 9

CREATE_SUSPENDED = 0x00000004
CREATE_NO_WINDOW = 0x08000000

INFINITE = 0xFFFFFFFF
WAIT_OBJECT_0 = 0x00000000
WAIT_TIMEOUT = 0x00000102


class IO_COUNTERS(ctypes.Structure):
    _fields_ = [("ReadOperationCount", ctypes.c_ulonglong),
                ("WriteOperationCount", ctypes.c_ulonglong),
                ("OtherOperationCount", ctypes.c_ulonglong),
                ("ReadTransferCount", ctypes.c_ulonglong),
                ("WriteTransferCount", ctypes.c_ulonglong),
                ("OtherTransferCount", ctypes.c_ulonglong)]


class JOBOBJECT_BASIC_LIMIT_INFORMATION(ctypes.Structure):
    _fields_ = [("PerProcessUserTimeLimit", ctypes.c_int64),
                ("PerJobUserTimeLimit", ctypes.c_int64),
                ("LimitFlags", wintypes.DWORD),
                ("MinimumWorkingSetSize", ctypes.c_size_t),
                ("MaximumWorkingSetSize", ctypes.c_size_t),
                ("ActiveProcessLimit", wintypes.DWORD),
                ("Affinity", ctypes.POINTER(ctypes.c_ulong)),
                ("PriorityClass", wintypes.DWORD),
                ("SchedulingClass", wintypes.DWORD)]


class JOBOBJECT_EXTENDED_LIMIT_INFORMATION(ctypes.Structure):
    _fields_ = [("BasicLimitInformation", JOBOBJECT_BASIC_LIMIT_INFORMATION),
                ("IoInfo", IO_COUNTERS),
                ("ProcessMemoryLimit", ctypes.c_size_t),
                ("JobMemoryLimit", ctypes.c_size_t),
                ("PeakProcessMemoryUsed", ctypes.c_size_t),
                ("PeakJobMemoryUsed", ctypes.c_size_t)]


@dataclass
class SandboxResult:
    exit_code: Optional[int]
    timed_out: bool
    killed_tree: bool
    wall_seconds: float
    peak_process_bytes: int
    peak_job_bytes: int
    stdout: str = ""
    stderr: str = ""

    def summary(self) -> dict:
        return {"exit_code": self.exit_code, "timed_out": self.timed_out,
                "killed_tree": self.killed_tree, "wall_seconds": round(self.wall_seconds, 3),
                "peak_process_bytes": self.peak_process_bytes,
                "peak_job_bytes": self.peak_job_bytes}


class STARTUPINFOW(ctypes.Structure):
    _fields_ = [("cb", wintypes.DWORD), ("lpReserved", wintypes.LPWSTR),
                ("lpDesktop", wintypes.LPWSTR), ("lpTitle", wintypes.LPWSTR),
                ("dwX", wintypes.DWORD), ("dwY", wintypes.DWORD),
                ("dwXSize", wintypes.DWORD), ("dwYSize", wintypes.DWORD),
                ("dwXCountChars", wintypes.DWORD), ("dwYCountChars", wintypes.DWORD),
                ("dwFillAttribute", wintypes.DWORD), ("dwFlags", wintypes.DWORD),
                ("wShowWindow", wintypes.WORD), ("cbReserved2", wintypes.WORD),
                ("lpReserved2", ctypes.c_void_p), ("hStdInput", wintypes.HANDLE),
                ("hStdOutput", wintypes.HANDLE), ("hStdError", wintypes.HANDLE)]


class PROCESS_INFORMATION(ctypes.Structure):
    _fields_ = [("hProcess", wintypes.HANDLE), ("hThread", wintypes.HANDLE),
                ("dwProcessId", wintypes.DWORD), ("dwThreadId", wintypes.DWORD)]


class SandboxUnavailable(RuntimeError):
    pass


def _read_pipe(kernel32, handle) -> str:
    chunks = []
    buffer = ctypes.create_string_buffer(4096)
    read = wintypes.DWORD(0)
    while True:
        ok = kernel32.ReadFile(handle, buffer, len(buffer) - 1, ctypes.byref(read), None)
        if not ok or read.value == 0:
            break
        chunks.append(buffer.raw[: read.value])
        if sum(len(c) for c in chunks) > 65536:
            break
    return b"".join(chunks).decode("utf-8", "replace")


def run_capped(argv: Sequence[str], memory_bytes: Optional[int] = None,
               wallclock_s: float = 10.0, active_process_limit: Optional[int] = None,
               kill_on_close: bool = True) -> SandboxResult:
    """Run argv inside a Job Object with memory, process-count and wall-clock caps.

    The process is created suspended, assigned to the job, then resumed, so the caps
    are in force before a single user instruction runs.
    """
    if not IS_WINDOWS:
        raise SandboxUnavailable("Job Objects are Windows only")
    kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)

    job = kernel32.CreateJobObjectW(None, None)
    if not job:
        raise SandboxUnavailable("CreateJobObject failed: %s" % ctypes.get_last_error())

    limit = JOBOBJECT_EXTENDED_LIMIT_INFORMATION()
    flags = 0
    if memory_bytes:
        flags |= JOB_OBJECT_LIMIT_PROCESS_MEMORY | JOB_OBJECT_LIMIT_JOB_MEMORY
        limit.ProcessMemoryLimit = memory_bytes
        limit.JobMemoryLimit = memory_bytes
    if active_process_limit:
        flags |= JOB_OBJECT_LIMIT_ACTIVE_PROCESS
        limit.BasicLimitInformation.ActiveProcessLimit = active_process_limit
    if kill_on_close:
        flags |= JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE
    limit.BasicLimitInformation.LimitFlags = flags
    if not kernel32.SetInformationJobObject(job, JobObjectExtendedLimitInformation,
                                            ctypes.byref(limit), ctypes.sizeof(limit)):
        kernel32.CloseHandle(job)
        raise SandboxUnavailable("SetInformationJobObject failed: %s" % ctypes.get_last_error())

    read_out, write_out = wintypes.HANDLE(), wintypes.HANDLE()
    read_err, write_err = wintypes.HANDLE(), wintypes.HANDLE()
    if not kernel32.CreatePipe(ctypes.byref(read_out), ctypes.byref(write_out), None, 0):
        kernel32.CloseHandle(job)
        raise SandboxUnavailable("CreatePipe failed")
    if not kernel32.CreatePipe(ctypes.byref(read_err), ctypes.byref(write_err), None, 0):
        kernel32.CloseHandle(job)
        raise SandboxUnavailable("CreatePipe failed")
    for handle in (write_out, write_err):
        kernel32.SetHandleInformation(handle, HANDLE_FLAG_INHERIT, HANDLE_FLAG_INHERIT)

    startup = STARTUPINFOW()
    startup.cb = ctypes.sizeof(startup)
    startup.dwFlags = STARTF_USESTDHANDLES
    startup.hStdOutput = write_out
    startup.hStdError = write_err
    info = PROCESS_INFORMATION()
    command = subprocess.list2cmdline([str(a) for a in argv])
    started = time.perf_counter()
    created = kernel32.CreateProcessW(
        None, ctypes.create_unicode_buffer(command), None, None, True,
        CREATE_SUSPENDED | CREATE_NO_WINDOW, None, None,
        ctypes.byref(startup), ctypes.byref(info),
    )
    kernel32.CloseHandle(write_out)
    kernel32.CloseHandle(write_err)
    if not created:
        kernel32.CloseHandle(job)
        raise SandboxUnavailable("CreateProcess failed: %s" % ctypes.get_last_error())

    try:
        if not kernel32.AssignProcessToJobObject(job, info.hProcess):
            raise SandboxUnavailable("AssignProcessToJobObject failed: %s" % ctypes.get_last_error())
        kernel32.ResumeThread(info.hThread)

        timeout_ms = int(max(wallclock_s, 0.05) * 1000)
        waited = kernel32.WaitForSingleObject(info.hProcess, timeout_ms)
        timed_out = waited == WAIT_TIMEOUT
        killed = False
        if timed_out:
            killed = True
            kernel32.TerminateJobObject(job, 1)
            kernel32.WaitForSingleObject(info.hProcess, 5000)

        exit_code = wintypes.DWORD(0)
        kernel32.GetExitCodeProcess(info.hProcess, ctypes.byref(exit_code))
        code = int(exit_code.value)

        snapshot = JOBOBJECT_EXTENDED_LIMIT_INFORMATION()
        returned = wintypes.DWORD(0)
        peak_process = peak_job = 0
        if kernel32.QueryInformationJobObject(job, JobObjectExtendedLimitInformation,
                                              ctypes.byref(snapshot), ctypes.sizeof(snapshot),
                                              ctypes.byref(returned)):
            peak_process = int(snapshot.PeakProcessMemoryUsed)
            peak_job = int(snapshot.PeakJobMemoryUsed)

        out_text = _read_pipe(kernel32, read_out)
        err_text = _read_pipe(kernel32, read_err)

        return SandboxResult(exit_code=code, timed_out=timed_out, killed_tree=killed,
                             wall_seconds=time.perf_counter() - started,
                             peak_process_bytes=peak_process, peak_job_bytes=peak_job,
                             stdout=out_text[:4096], stderr=err_text[:4096])
    finally:
        kernel32.CloseHandle(read_out)
        kernel32.CloseHandle(read_err)
        kernel32.CloseHandle(info.hThread)
        kernel32.CloseHandle(info.hProcess)
        kernel32.CloseHandle(job)
