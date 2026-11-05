"""R1 spike runner: run one helper inside a Job Object. stdlib ctypes only.

Safety rules (PLAN 14.3.1):
- process is created CREATE_SUSPENDED, assigned to the job, then resumed
- if assignment fails the process is terminated and nothing runs
- KILL_ON_JOB_CLOSE is set, so children die with the job handle
- the runner itself stays outside the job and enforces a wall-clock watchdog
"""
from __future__ import annotations

import argparse
import ctypes
import ctypes.wintypes as wt
import json
import os
import sys
import time

kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)

JOB_OBJECT_LIMIT_PROCESS_MEMORY = 0x00000100
JOB_OBJECT_LIMIT_ACTIVE_PROCESS = 0x00000008
JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE = 0x00002000
JobObjectExtendedLimitInformation = 9
PROCESS_TERMINATE = 0x0001
PROCESS_SET_QUOTA = 0x0100
SYNCHRONIZE = 0x00100000
CREATE_SUSPENDED = 0x00000004
INFINITE = 0xFFFFFFFF


class IO_COUNTERS(ctypes.Structure):
    _fields_ = [
        ("ReadOperationCount", ctypes.c_ulonglong),
        ("WriteOperationCount", ctypes.c_ulonglong),
        ("OtherOperationCount", ctypes.c_ulonglong),
        ("ReadTransferCount", ctypes.c_ulonglong),
        ("WriteTransferCount", ctypes.c_ulonglong),
        ("OtherTransferCount", ctypes.c_ulonglong),
    ]


class JOBOBJECT_BASIC_LIMIT_INFORMATION(ctypes.Structure):
    _fields_ = [
        ("PerProcessUserTimeLimit", ctypes.c_longlong),
        ("PerJobUserTimeLimit", ctypes.c_longlong),
        ("LimitFlags", wt.DWORD),
        ("MinimumWorkingSetSize", ctypes.c_size_t),
        ("MaximumWorkingSetSize", ctypes.c_size_t),
        ("ActiveProcessLimit", wt.DWORD),
        ("Affinity", ctypes.POINTER(wt.ULONG)),
        ("PriorityClass", wt.DWORD),
        ("SchedulingClass", wt.DWORD),
    ]


class JOBOBJECT_EXTENDED_LIMIT_INFORMATION(ctypes.Structure):
    _fields_ = [
        ("BasicLimitInformation", JOBOBJECT_BASIC_LIMIT_INFORMATION),
        ("IoInfo", IO_COUNTERS),
        ("ProcessMemoryLimit", ctypes.c_size_t),
        ("JobMemoryLimit", ctypes.c_size_t),
        ("PeakProcessMemoryUsed", ctypes.c_size_t),
        ("PeakJobMemoryUsed", ctypes.c_size_t),
    ]


class JOBOBJECT_BASIC_ACCOUNTING_INFORMATION(ctypes.Structure):
    _fields_ = [
        ("TotalUserTime", ctypes.c_longlong),
        ("TotalKernelTime", ctypes.c_longlong),
        ("ThisPeriodTotalUserTime", ctypes.c_longlong),
        ("ThisPeriodTotalKernelTime", ctypes.c_longlong),
        ("TotalPageFaultCount", wt.DWORD),
        ("TotalProcesses", wt.DWORD),
        ("ActiveProcesses", wt.DWORD),
        ("TotalTerminatedProcesses", wt.DWORD),
    ]


def _set_limits(job, mem_cap_bytes: int, active_limit: int) -> None:
    info = JOBOBJECT_EXTENDED_LIMIT_INFORMATION()
    info.BasicLimitInformation.LimitFlags = (
        JOB_OBJECT_LIMIT_PROCESS_MEMORY
        | JOB_OBJECT_LIMIT_ACTIVE_PROCESS
        | JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE
    )
    info.ProcessMemoryLimit = mem_cap_bytes
    info.BasicLimitInformation.ActiveProcessLimit = active_limit
    ok = kernel32.SetInformationJobObject(
        job, JobObjectExtendedLimitInformation, ctypes.byref(info), ctypes.sizeof(info)
    )
    if not ok:
        raise OSError(ctypes.get_last_error(), "SetInformationJobObject failed")


def _job_stats(job) -> dict:
    ext = JOBOBJECT_EXTENDED_LIMIT_INFORMATION()
    acc = JOBOBJECT_BASIC_ACCOUNTING_INFORMATION()
    kernel32.QueryInformationJobObject(
        job, JobObjectExtendedLimitInformation, ctypes.byref(ext), ctypes.sizeof(ext), None
    )
    kernel32.QueryInformationJobObject(
        job, 1, ctypes.byref(acc), ctypes.sizeof(acc), None
    )
    return {
        "active_processes": int(acc.ActiveProcesses),
        "total_processes": int(acc.TotalProcesses),
        "terminated_processes": int(acc.TotalTerminatedProcesses),
        "peak_job_memory": int(ext.PeakJobMemoryUsed),
    }


def run(helper: str, mem_cap_mb: int, watchdog_s: int) -> dict:
    job = kernel32.CreateJobObjectW(None, None)
    if not job:
        raise OSError(ctypes.get_last_error(), "CreateJobObject failed")
    _set_limits(job, mem_cap_mb * 1024 * 1024, 1)

    si = ctypes.create_string_buffer(104)
    pi = ctypes.create_string_buffer(24)
    ctypes.memset(si, 0, 104)
    ctypes.cast(si, ctypes.POINTER(wt.DWORD))[0] = 104

    cmdline = ctypes.create_unicode_buffer(helper)
    created = kernel32.CreateProcessW(
        None, cmdline, None, None, False, CREATE_SUSPENDED, None, None,
        ctypes.byref(si), ctypes.byref(pi),
    )
    if not created:
        kernel32.CloseHandle(job)
        raise OSError(ctypes.get_last_error(), "CreateProcess failed")

    hproc = ctypes.cast(pi, ctypes.POINTER(wt.HANDLE))[0]
    hthread = ctypes.cast(ctypes.byref(pi, 8), ctypes.POINTER(wt.HANDLE))[0]

    assigned = kernel32.AssignProcessToJobObject(job, hproc)
    if not assigned:
        kernel32.TerminateProcess(hproc, 1)
        kernel32.CloseHandle(hthread)
        kernel32.CloseHandle(hproc)
        kernel32.CloseHandle(job)
        raise RuntimeError("AssignProcessToJobObject failed -> aborted (helper was never resumed)")

    kernel32.ResumeThread(hthread)
    kernel32.CloseHandle(hthread)

    start = time.monotonic()
    exit_code = None
    killed = False
    while True:
        waited = kernel32.WaitForSingleObject(hproc, 250)
        if waited == 0:
            break
        if time.monotonic() - start > watchdog_s:
            kernel32.TerminateJobObject(job, 1)
            killed = True
            break

    if exit_code is None:
        code = wt.DWORD(0)
        kernel32.GetExitCodeProcess(hproc, ctypes.byref(code))
        exit_code = int(code.value)

    stats = _job_stats(job)
    t0 = time.monotonic()
    kernel32.TerminateJobObject(job, 1)
    while stats["active_processes"] > 0 and time.monotonic() - t0 < 5.0:
        time.sleep(0.05)
        stats = _job_stats(job)
    tree_clear_s = time.monotonic() - t0

    kernel32.CloseHandle(hproc)
    kernel32.CloseHandle(job)

    return {
        "helper": helper,
        "mem_cap_mb": mem_cap_mb,
        "watchdog_s": watchdog_s,
        "exit_code": exit_code,
        "killed_by_watchdog": killed,
        "elapsed_s": round(time.monotonic() - start, 3),
        "peak_job_memory_mb": round(stats["peak_job_memory"] / (1024 * 1024), 1),
        "total_processes": stats["total_processes"],
        "active_processes_after_kill": stats["active_processes"],
        "tree_clear_s": round(tree_clear_s, 3),
        "windows_build": os.sys.getwindowsversion(),
        "python": sys.version.split()[0],
    }


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("helper")
    ap.add_argument("--cap-mb", type=int, default=512)
    ap.add_argument("--watchdog", type=int, default=120)
    args = ap.parse_args()
    try:
        result = run(args.helper, args.cap_mb, args.watchdog)
    except Exception as exc:
        print(json.dumps({"error": f"{exc.__class__.__name__}: {exc}"}))
        return 6
    print(json.dumps(result))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
