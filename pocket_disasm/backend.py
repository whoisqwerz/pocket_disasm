from __future__ import annotations

import os
import socket
import subprocess
import sys
import threading
import time
from collections import deque
from pathlib import Path


class BackendError(RuntimeError):
    pass


def _friendly_startup_error(ida_dir: Path, details: str) -> str:
    if "License not yet accepted" in details:
        ida_exe = ida_dir / "ida.exe"
        return (
            "IDA license terms have not been accepted for this Windows user. "
            f'Launch "{ida_exe}" once, accept the license agreement, close IDA, '
            "and retry Pocket Disasm."
        )
    if "No module named 'idaapi'" in details:
        return (
            "IDAPython bindings were not initialized. Verify that IDADIR points "
            f'to a complete IDA installation: "{ida_dir}".'
        )
    return f"IDALib MCP exited during startup.\n{details}"


def port_is_open(host: str, port: int, timeout: float = 0.15) -> bool:
    try:
        with socket.create_connection((host, port), timeout=timeout):
            return True
    except OSError:
        return False


class BackendProcess:
    def __init__(
        self,
        ida_dir: Path,
        host: str = "127.0.0.1",
        port: int = 13400,
        *,
        unsafe: bool = False,
        verbose: bool = False,
    ) -> None:
        self.ida_dir = ida_dir
        self.host = host
        self.port = port
        self.unsafe = unsafe
        self.verbose = verbose
        self.process: subprocess.Popen[str] | None = None
        self.logs: deque[str] = deque(maxlen=300)
        self._reader: threading.Thread | None = None
        self._owned = False

    @property
    def endpoint(self) -> str:
        return f"http://{self.host}:{self.port}/mcp"

    def command(self, input_path: Path | None = None) -> list[str]:
        command = [
            sys.executable,
            "-m",
            "ida_pro_mcp.idalib_server",
            "--host",
            self.host,
            "--port",
            str(self.port),
        ]
        if self.verbose:
            command.append("--verbose")
        if self.unsafe:
            command.append("--unsafe")
        if input_path is not None:
            command.append(str(input_path.resolve()))
        return command

    def start(self, input_path: Path | None = None, timeout: float = 30.0) -> None:
        if self.process and self.process.poll() is None:
            return
        if port_is_open(self.host, self.port):
            self.logs.append(f"Adopted existing MCP server at {self.endpoint}")
            self._owned = False
            return

        env = os.environ.copy()
        env["IDADIR"] = str(self.ida_dir)
        env["PYTHONUNBUFFERED"] = "1"
        creationflags = 0
        if os.name == "nt":
            creationflags = subprocess.CREATE_NO_WINDOW
        self.process = subprocess.Popen(
            self.command(input_path),
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            text=True,
            encoding="utf-8",
            errors="replace",
            env=env,
            creationflags=creationflags,
        )
        self._owned = True
        self._reader = threading.Thread(target=self._read_logs, daemon=True)
        self._reader.start()

        deadline = time.monotonic() + timeout
        while time.monotonic() < deadline:
            if port_is_open(self.host, self.port):
                return
            if self.process.poll() is not None:
                tail = "\n".join(list(self.logs)[-12:])
                self.stop()
                raise BackendError(_friendly_startup_error(self.ida_dir, tail))
            time.sleep(0.15)
        self.stop()
        raise BackendError(f"Timed out waiting for IDALib MCP at {self.endpoint}")

    def _read_logs(self) -> None:
        process = self.process
        if process is None or process.stdout is None:
            return
        for line in process.stdout:
            self.logs.append(line.rstrip())

    def status(self) -> dict:
        running = port_is_open(self.host, self.port)
        return {
            "running": running,
            "owned": self._owned,
            "pid": self.process.pid if self.process and self.process.poll() is None else None,
            "endpoint": self.endpoint,
            "exit_code": self.process.poll() if self.process else None,
        }

    def stop(self, timeout: float = 8.0) -> None:
        if not self._owned or self.process is None:
            return
        if self.process.poll() is None:
            self.process.terminate()
            try:
                self.process.wait(timeout=timeout)
            except subprocess.TimeoutExpired:
                self.process.kill()
                self.process.wait(timeout=3)
        if self._reader and self._reader.is_alive():
            self._reader.join(timeout=1)
        if self.process.stdout is not None and not self.process.stdout.closed:
            self.process.stdout.close()
