from __future__ import annotations

import os
import signal
import subprocess
import sys
import time
from dataclasses import dataclass
from pathlib import Path

from .backend import port_is_open
from .config import Settings, runtime_dir


@dataclass(slots=True)
class DaemonState:
    pid: int | None
    endpoint: str
    running: bool
    source: str


def pidfile_path() -> Path:
    return runtime_dir() / "pocket-disasm.pid"


def read_pidfile(path: Path | None = None) -> int | None:
    path = path or pidfile_path()
    try:
        return int(path.read_text(encoding="utf-8").strip())
    except (OSError, ValueError):
        return None


def write_pidfile(pid: int | None = None, path: Path | None = None) -> Path:
    path = path or pidfile_path()
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(str(pid or os.getpid()), encoding="utf-8")
    return path


def remove_pidfile(path: Path | None = None) -> None:
    path = path or pidfile_path()
    try:
        path.unlink()
    except FileNotFoundError:
        return


def process_is_running(pid: int | None) -> bool:
    if not pid:
        return False
    if os.name == "nt":
        try:
            import ctypes

            kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
            kernel32.OpenProcess.argtypes = (ctypes.c_ulong, ctypes.c_bool, ctypes.c_ulong)
            kernel32.OpenProcess.restype = ctypes.c_void_p
            kernel32.GetExitCodeProcess.argtypes = (ctypes.c_void_p, ctypes.POINTER(ctypes.c_ulong))
            kernel32.GetExitCodeProcess.restype = ctypes.c_bool
            kernel32.CloseHandle.argtypes = (ctypes.c_void_p,)
            kernel32.CloseHandle.restype = ctypes.c_bool
            handle = kernel32.OpenProcess(0x1000, False, pid)
            if not handle:
                return False
            try:
                exit_code = ctypes.c_ulong()
                return bool(kernel32.GetExitCodeProcess(handle, ctypes.byref(exit_code))) and exit_code.value == 259
            finally:
                kernel32.CloseHandle(handle)
        except (AttributeError, OSError, ValueError):
            return False
    try:
        os.kill(pid, 0)
        return True
    except OSError:
        return False


def _windows_pid_for_port(port: int) -> int | None:
    if os.name != "nt":
        return None
    try:
        output = subprocess.check_output(
            ["netstat", "-ano", "-p", "tcp"],
            text=True,
            encoding="utf-8",
            errors="replace",
        )
    except (OSError, subprocess.CalledProcessError):
        return None
    needle = f":{port}"
    for line in output.splitlines():
        parts = line.split()
        if len(parts) >= 5 and parts[0].upper() == "TCP" and parts[1].endswith(needle):
            if parts[3].upper() == "LISTENING":
                try:
                    return int(parts[4])
                except ValueError:
                    return None
    return None


def inspect_daemon(settings: Settings | None = None) -> DaemonState:
    settings = settings or Settings.load()
    endpoint = f"http://{settings.host}:{settings.port}/mcp"
    pid = read_pidfile()
    if process_is_running(pid):
        return DaemonState(pid, endpoint, True, "pidfile")
    if port_is_open(settings.host, settings.port):
        return DaemonState(_windows_pid_for_port(settings.port), endpoint, True, "port")
    return DaemonState(None, endpoint, False, "none")


def stop_daemon(timeout: float = 10.0, settings: Settings | None = None) -> DaemonState:
    state = inspect_daemon(settings)
    if not state.running or not state.pid:
        return state
    if os.name == "nt":
        subprocess.call(["taskkill", "/PID", str(state.pid), "/T", "/F"], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    else:
        os.kill(state.pid, signal.SIGTERM)
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        if not process_is_running(state.pid):
            remove_pidfile()
            return DaemonState(state.pid, state.endpoint, False, state.source)
        time.sleep(0.2)
    return inspect_daemon(settings)


def start_daemon(args: list[str], log_prefix: str = "pocket-disasm") -> subprocess.Popen[bytes]:
    runtime = runtime_dir()
    runtime.mkdir(parents=True, exist_ok=True)
    command = [sys.executable, "-m", "pocket_disasm", "serve", "--no-repl", *args]
    creationflags = subprocess.CREATE_NO_WINDOW if os.name == "nt" else 0
    stdout = open(runtime / f"{log_prefix}.out.log", "ab")
    stderr = open(runtime / f"{log_prefix}.err.log", "ab")
    try:
        return subprocess.Popen(command, stdout=stdout, stderr=stderr, creationflags=creationflags)
    finally:
        stdout.close()
        stderr.close()
