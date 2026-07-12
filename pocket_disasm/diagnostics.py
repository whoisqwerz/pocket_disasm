from __future__ import annotations

import json
import threading
import traceback
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from .config import runtime_dir


_LOCK = threading.RLock()


def event_log_path() -> Path:
    return runtime_dir() / "events.log"


def append_event(level: str, event: str, **fields: Any) -> None:
    path = event_log_path()
    payload = {
        "time": datetime.now(timezone.utc).astimezone().isoformat(timespec="milliseconds"),
        "level": level.upper(),
        "event": event,
        **fields,
    }
    try:
        path.parent.mkdir(parents=True, exist_ok=True)
        line = json.dumps(payload, ensure_ascii=False, default=str)
        with _LOCK, path.open("a", encoding="utf-8") as stream:
            stream.write(line + "\n")
            stream.flush()
    except OSError:
        return


def append_exception(event: str, error: BaseException, **fields: Any) -> None:
    append_event(
        "error",
        event,
        error_type=type(error).__name__,
        error=str(error),
        traceback="".join(traceback.format_exception(type(error), error, error.__traceback__)),
        **fields,
    )


def tail_file(path: Path, lines: int = 40) -> list[str]:
    try:
        return path.read_text(encoding="utf-8", errors="replace").splitlines()[-lines:]
    except OSError:
        return []
