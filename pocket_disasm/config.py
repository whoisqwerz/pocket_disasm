from __future__ import annotations

import json
import os
import platform
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Iterable


def user_config_dir() -> Path:
    if platform.system() == "Windows":
        root = Path(os.environ.get("LOCALAPPDATA", Path.home() / "AppData" / "Local"))
        return root / "PocketDisasm"
    root = Path(os.environ.get("XDG_CONFIG_HOME", Path.home() / ".config"))
    return root / "pocket-disasm"


def runtime_dir() -> Path:
    if platform.system() == "Windows":
        root = Path(os.environ.get("LOCALAPPDATA", Path.home() / "AppData" / "Local"))
        return root / "PocketDisasm"
    root = Path(os.environ.get("XDG_RUNTIME_DIR", Path.home() / ".cache"))
    return root / "pocket-disasm"


@dataclass(slots=True)
class Settings:
    ida_dir: str = ""
    host: str = "127.0.0.1"
    port: int = 13339
    base_port: int = 13400
    max_workers: int = 8

    @classmethod
    def load(cls, path: Path | None = None) -> "Settings":
        path = path or (user_config_dir() / "config.json")
        if not path.exists():
            return cls()
        try:
            raw = json.loads(path.read_text(encoding="utf-8"))
        except (OSError, ValueError):
            return cls()
        allowed = {key: raw[key] for key in asdict(cls()) if key in raw}
        settings = cls(**allowed)
        if settings.port == 8745 and settings.base_port == 8750:
            settings.port = 13339
            settings.base_port = 13400
        return settings

    def save(self, path: Path | None = None) -> Path:
        path = path or (user_config_dir() / "config.json")
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(json.dumps(asdict(self), indent=2), encoding="utf-8")
        return path


def _hex_rays_config_dir() -> Path | None:
    appdata = os.environ.get("APPDATA")
    if not appdata:
        return None
    return Path(appdata) / "Hex-Rays" / "IDA Pro" / "ida-config.json"


def _ida_dir_from_hex_rays_config() -> Path | None:
    config_path = _hex_rays_config_dir()
    if config_path is None or not config_path.exists():
        return None
    try:
        raw = json.loads(config_path.read_text(encoding="utf-8"))
        value = raw.get("Paths", {}).get("ida-install-dir", "")
        return Path(value).expanduser() if value else None
    except (OSError, ValueError, TypeError):
        return None


def _registry_candidates() -> Iterable[Path]:
    if platform.system() != "Windows":
        return []
    try:
        import winreg
    except ImportError:
        return []

    roots = (
        (winreg.HKEY_LOCAL_MACHINE, r"SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall"),
        (winreg.HKEY_LOCAL_MACHINE, r"SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall"),
        (winreg.HKEY_CURRENT_USER, r"SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall"),
    )
    found: list[Path] = []
    for hive, key_name in roots:
        try:
            root = winreg.OpenKey(hive, key_name)
        except OSError:
            continue
        with root:
            for index in range(winreg.QueryInfoKey(root)[0]):
                try:
                    child_name = winreg.EnumKey(root, index)
                    with winreg.OpenKey(root, child_name) as child:
                        display, _ = winreg.QueryValueEx(child, "DisplayName")
                        if "IDA" not in str(display).upper() or "AIDA64" in str(display).upper():
                            continue
                        install, _ = winreg.QueryValueEx(child, "InstallLocation")
                        if install:
                            found.append(Path(install))
                except OSError:
                    continue
    return found


def _common_candidates() -> Iterable[Path]:
    if platform.system() == "Windows":
        roots = [
            Path(os.environ.get("ProgramFiles", r"C:\Program Files")),
            Path(os.environ.get("ProgramFiles(x86)", r"C:\Program Files (x86)")),
        ]
        names = [
            "IDA Professional 9.3",
            "IDA Professional 9.2",
            "IDA Professional 9.1",
            "IDA Professional 9.0",
            "IDA Pro 9.3",
            "IDA Pro 9.2",
            "IDA Pro 9.1",
            "IDA Pro 9.0",
        ]
        return [root / name for root in roots for name in names]
    if platform.system() == "Darwin":
        return [
            Path(f"/Applications/IDA Professional {version}.app/Contents/MacOS")
            for version in ("9.3", "9.2", "9.1", "9.0")
        ]
    return [Path(f"/opt/ida-{version}") for version in ("9.3", "9.2", "9.1", "9.0")]


def idalib_filename() -> str:
    return {
        "Windows": "idalib.dll",
        "Darwin": "libidalib.dylib",
    }.get(platform.system(), "libidalib.so")


def is_ida_dir(path: Path | str | None) -> bool:
    if not path:
        return False
    candidate = Path(path).expanduser()
    if not candidate.is_dir():
        return False
    name = idalib_filename()
    direct = (candidate / name, candidate / "idalib" / name)
    if any(item.is_file() for item in direct):
        return True
    try:
        return next(candidate.glob(f"*/{name}"), None) is not None
    except OSError:
        return False


def discover_ida_dir(explicit: str | Path | None = None, settings: Settings | None = None) -> Path | None:
    candidates: list[Path | None] = [
        Path(explicit).expanduser() if explicit else None,
        Path(os.environ["IDADIR"]).expanduser() if os.environ.get("IDADIR") else None,
        Path(settings.ida_dir).expanduser() if settings and settings.ida_dir else None,
        _ida_dir_from_hex_rays_config(),
    ]
    candidates.extend(_registry_candidates())
    candidates.extend(_common_candidates())
    seen: set[str] = set()
    for candidate in candidates:
        if candidate is None:
            continue
        key = str(candidate.resolve(strict=False)).casefold()
        if key in seen:
            continue
        seen.add(key)
        if is_ida_dir(candidate):
            return candidate.resolve()
    return None
