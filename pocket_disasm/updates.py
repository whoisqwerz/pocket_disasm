from __future__ import annotations

import re
import subprocess
import sys
from dataclasses import dataclass
from pathlib import Path
from urllib.request import Request, urlopen

from .config import runtime_dir


VERSION_URL = "https://raw.githubusercontent.com/whoisqwerz/pocket_disasm/main/pocket_disasm/__init__.py"
SOURCE_URL = "https://github.com/whoisqwerz/pocket_disasm/archive/refs/heads/main.zip"


@dataclass(frozen=True, slots=True)
class UpdateInfo:
    current: str
    latest: str
    available: bool


def _version_key(value: str) -> tuple[int, ...]:
    parts = tuple(int(part) for part in re.findall(r"\d+", value))
    return parts or (0,)


def check_for_update(current: str, timeout: float = 5.0) -> UpdateInfo:
    request = Request(VERSION_URL, headers={"User-Agent": f"Pocket-Disasm/{current}"})
    with urlopen(request, timeout=timeout) as response:
        source = response.read().decode("utf-8", errors="replace")
    match = re.search(r'^__version__\s*=\s*["\']([^"\']+)["\']', source, re.MULTILINE)
    if not match:
        raise RuntimeError("The update server returned no version")
    latest = match.group(1)
    return UpdateInfo(current, latest, _version_key(latest) > _version_key(current))


def install_update(timeout: float = 300.0) -> str:
    command = [
        sys.executable,
        "-m",
        "pip",
        "install",
        "--disable-pip-version-check",
        "--upgrade",
        SOURCE_URL,
    ]
    result = subprocess.run(
        command,
        capture_output=True,
        text=True,
        encoding="utf-8",
        errors="replace",
        timeout=timeout,
    )
    output = "\n".join(part.strip() for part in (result.stdout, result.stderr) if part.strip())
    log_path = runtime_dir() / "update.log"
    log_path.parent.mkdir(parents=True, exist_ok=True)
    log_path.write_text(output, encoding="utf-8")
    if result.returncode:
        raise RuntimeError(f"Update failed with exit code {result.returncode}. See {log_path}")
    return str(log_path)
