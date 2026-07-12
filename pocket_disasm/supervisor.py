from __future__ import annotations

import concurrent.futures
import os
import re
import shutil
import socket
import threading
import time
import uuid
from dataclasses import dataclass, field
from pathlib import Path

from .backend import BackendProcess


def _safe_name(path: Path) -> str:
    value = re.sub(r"[^a-zA-Z0-9_-]+", "-", path.stem).strip("-").lower()
    return value or "binary"


def _free_port(host: str, start: int, reserved: set[int]) -> int:
    for port in range(start, 65536):
        if port in reserved:
            continue
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as probe:
                probe.bind((host, port))
                return port
        except OSError:
            continue
    raise RuntimeError("No free TCP port is available for a new IDALib worker")


@dataclass(slots=True)
class WorkerSession:
    name: str
    binary: Path | None
    port: int
    backend: BackendProcess
    workspace: Path
    analysis_path: Path | None = None
    state: str = "starting"
    error: str | None = None
    started_at: float = field(default_factory=time.time)
    cancelled: bool = False

    @property
    def endpoint(self) -> str:
        return self.backend.endpoint

    def as_dict(self) -> dict:
        return {
            "name": self.name,
            "binary": str(self.binary) if self.binary else None,
            "state": self.state,
            "endpoint": self.endpoint,
            "pid": self.backend.status().get("pid"),
            "error": self.error,
            "workspace": str(self.workspace),
        }


class MultiSessionSupervisor:
    """Own independent IDALib processes without serializing analysis calls."""

    def __init__(
        self,
        ida_dir: Path,
        *,
        host: str = "127.0.0.1",
        base_port: int = 8750,
        max_workers: int = 8,
        unsafe: bool = False,
        verbose: bool = False,
        workspace_root: Path | None = None,
    ) -> None:
        if max_workers < 1:
            raise ValueError("max_workers must be at least 1")
        self.ida_dir = ida_dir
        self.host = host
        self.base_port = base_port
        self.max_workers = max_workers
        self.unsafe = unsafe
        self.verbose = verbose
        if workspace_root is None:
            if os.name == "nt":
                workspace_root = Path(os.environ.get("LOCALAPPDATA", Path.home())) / "PocketDisasm" / "sessions"
            else:
                workspace_root = Path.home() / ".cache" / "pocket-disasm" / "sessions"
        self.workspace_root = workspace_root
        self._sessions: dict[str, WorkerSession] = {}
        self._lock = threading.RLock()
        self._executor = concurrent.futures.ThreadPoolExecutor(
            max_workers=max_workers,
            thread_name_prefix="pocket-worker-start",
        )

    def _unique_name(self, requested: str, binary: Path) -> str:
        base = _safe_name(Path(requested)) if requested else _safe_name(binary)
        candidate = base
        suffix = 2
        while candidate in self._sessions:
            candidate = f"{base}-{suffix}"
            suffix += 1
        return candidate

    def open_async(self, binary: Path | str, name: str = "") -> WorkerSession:
        path = Path(binary).expanduser().resolve()
        if not path.is_file():
            raise FileNotFoundError(f"Binary not found: {path}")
        return self._spawn(path, name)

    def _spawn(self, binary: Path | None, name: str) -> WorkerSession:
        with self._lock:
            live = [session for session in self._sessions.values() if session.state != "closed"]
            if len(live) >= self.max_workers:
                raise RuntimeError(
                    f"Worker limit reached ({self.max_workers}). Close a session or increase --max-workers."
                )
            fallback = binary or Path("slot")
            session_name = self._unique_name(name, fallback)
            reserved = {session.port for session in self._sessions.values()}
            port = _free_port(self.host, self.base_port, reserved)
            workspace = self.workspace_root / f"{session_name}-{uuid.uuid4().hex[:8]}"
            backend = BackendProcess(
                self.ida_dir,
                host=self.host,
                port=port,
                unsafe=self.unsafe,
                verbose=self.verbose,
                log_path=workspace / "worker.log",
            )
            session = WorkerSession(session_name, binary, port, backend, workspace)
            self._sessions[session_name] = session
            self._executor.submit(self._start_worker, session)
            return session

    def _start_worker(self, session: WorkerSession) -> None:
        try:
            worker_input = None
            if session.binary is not None:
                session.workspace.mkdir(parents=True, exist_ok=False)
                worker_input = session.workspace / session.binary.name
                shutil.copy2(session.binary, worker_input)
                session.analysis_path = worker_input
            session.backend.start(worker_input, timeout=180.0)
            with self._lock:
                if session.cancelled:
                    session.backend.stop()
                    session.state = "closed"
                else:
                    session.state = "ready"
        except Exception as error:
            with self._lock:
                session.state = "failed"
                session.error = str(error)

    def list_sessions(self) -> list[WorkerSession]:
        with self._lock:
            return list(self._sessions.values())

    def get_session(self, name: str) -> WorkerSession | None:
        with self._lock:
            return self._sessions.get(name)

    def wait_session(self, name: str, timeout: float = 300.0) -> WorkerSession:
        deadline = time.monotonic() + timeout
        while time.monotonic() < deadline:
            session = self.get_session(name)
            if session is None:
                raise RuntimeError(f"Session not found: {name}")
            if session.state == "ready":
                return session
            if session.state == "failed":
                raise RuntimeError(session.error or f"Session failed: {name}")
            if session.state == "closed":
                raise RuntimeError(f"Session closed: {name}")
            time.sleep(0.1)
        raise TimeoutError(f"Timed out waiting for session {name!r}")

    def close(self, name: str) -> bool:
        with self._lock:
            session = self._sessions.get(name)
            if session is None or session.state == "closed":
                return False
            session.cancelled = True
            previous_state = session.state
            session.state = "closing"
        if previous_state != "starting":
            session.backend.stop()
            with self._lock:
                session.state = "closed"
        return True

    def close_all(self) -> None:
        sessions = self.list_sessions()
        for session in sessions:
            session.cancelled = True
        for session in sessions:
            session.backend.stop()
            session.state = "closed"
        self._executor.shutdown(wait=True, cancel_futures=False)

    def wait_until_settled(self, timeout: float = 190.0) -> None:
        deadline = time.monotonic() + timeout
        while time.monotonic() < deadline:
            if all(session.state != "starting" for session in self.list_sessions()):
                return
            time.sleep(0.1)
        raise TimeoutError("Timed out waiting for IDALib workers")

    def print_status(self, *, wait_for_start: bool = False) -> None:
        if wait_for_start:
            self.wait_until_settled()
        sessions = self.list_sessions()
        if not sessions:
            print("No workers. Use: open <binary> [name]")
            return
        width = max(7, *(len(session.name) for session in sessions))
        print(f"{'SESSION':<{width}}  {'STATE':<9}  ENDPOINT / BINARY")
        print(f"{'-' * width}  {'-' * 9}  {'-' * 64}")
        for session in sessions:
            detail = session.endpoint if session.state != "failed" else (session.error or "failed")
            print(f"{session.name:<{width}}  {session.state:<9}  {detail}")
            binary = str(session.binary) if session.binary else "<empty slot; use idalib_open>"
            print(f"{'':<{width}}  {'':<9}  {binary}")
