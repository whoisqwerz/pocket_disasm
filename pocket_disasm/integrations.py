from __future__ import annotations

import json
import os
import re
import sys
from dataclasses import dataclass
from pathlib import Path

from .config import Settings, user_config_dir


SERVER_NAME = "pocket-disasm"
APPROVED_CODEX_TOOLS = (
    "idb_open",
    "idb_list",
    "idb_select",
    "idb_health",
    "idb_wait",
    "idb_close",
    "idb_logs",
    "idb_save",
    "server_health",
    "survey_binary",
    "lookup_funcs",
    "func_query",
    "entity_query",
    "find_bytes",
    "find_regex",
    "decompile",
)


@dataclass(slots=True)
class IntegrationResult:
    target: str
    path: Path | None
    changed: bool
    message: str


def endpoint(settings: Settings | None = None) -> str:
    settings = settings or Settings.load()
    return f"http://{settings.host}:{settings.port}/mcp"


def _load_json(path: Path) -> dict:
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except FileNotFoundError:
        return {}
    except ValueError as error:
        raise RuntimeError(f"Invalid JSON in {path}: {error}") from error


def _save_json(path: Path, data: dict, *, dry_run: bool) -> bool:
    rendered = json.dumps(data, indent=2, ensure_ascii=False) + "\n"
    current = path.read_text(encoding="utf-8") if path.exists() else ""
    changed = current != rendered
    if changed and not dry_run:
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(rendered, encoding="utf-8")
    return changed


def _merge_mcp_servers(path: Path, server_entry: dict, *, dry_run: bool) -> bool:
    data = _load_json(path)
    servers = data.setdefault("mcpServers", {})
    servers[SERVER_NAME] = server_entry
    return _save_json(path, data, dry_run=dry_run)


def _project_file(project_dir: Path, relative: str) -> Path:
    return project_dir.expanduser().resolve() / relative


def integrate_claude(project_dir: Path, settings: Settings, *, dry_run: bool = False) -> IntegrationResult:
    path = _project_file(project_dir, ".mcp.json")
    changed = _merge_mcp_servers(path, {"type": "http", "url": endpoint(settings)}, dry_run=dry_run)
    return IntegrationResult("claude", path, changed, "Claude Code project MCP config")


def _claude_user_config_path() -> Path:
    return Path.home() / ".claude.json"


def integrate_claude_global(settings: Settings, *, dry_run: bool = False) -> IntegrationResult:
    path = _claude_user_config_path()
    changed = _merge_mcp_servers(path, {"type": "http", "url": endpoint(settings)}, dry_run=dry_run)
    return IntegrationResult("claude", path, changed, "Claude Code user MCP config")


def integrate_cursor(project_dir: Path, settings: Settings, *, dry_run: bool = False) -> IntegrationResult:
    path = _project_file(project_dir, ".cursor/mcp.json")
    changed = _merge_mcp_servers(path, {"url": endpoint(settings)}, dry_run=dry_run)
    return IntegrationResult("cursor", path, changed, "Cursor workspace MCP config")


def integrate_cursor_global(settings: Settings, *, dry_run: bool = False) -> IntegrationResult:
    path = Path.home() / ".cursor" / "mcp.json"
    changed = _merge_mcp_servers(path, {"url": endpoint(settings)}, dry_run=dry_run)
    return IntegrationResult("cursor", path, changed, "Cursor user MCP config")


def integrate_vscode(project_dir: Path, settings: Settings, *, dry_run: bool = False) -> IntegrationResult:
    path = _project_file(project_dir, ".vscode/mcp.json")
    data = _load_json(path)
    servers = data.setdefault("servers", {})
    servers[SERVER_NAME] = {"type": "http", "url": endpoint(settings)}
    changed = _save_json(path, data, dry_run=dry_run)
    return IntegrationResult("vscode", path, changed, "VS Code workspace MCP config")


def _vscode_user_config_path() -> Path:
    if os.name == "nt":
        return Path(os.environ.get("APPDATA", Path.home() / "AppData" / "Roaming")) / "Code" / "User" / "mcp.json"
    if sys.platform == "darwin":
        return Path.home() / "Library" / "Application Support" / "Code" / "User" / "mcp.json"
    return Path(os.environ.get("XDG_CONFIG_HOME", Path.home() / ".config")) / "Code" / "User" / "mcp.json"


def integrate_vscode_global(settings: Settings, *, dry_run: bool = False) -> IntegrationResult:
    path = _vscode_user_config_path()
    data = _load_json(path)
    data.setdefault("servers", {})[SERVER_NAME] = {"type": "http", "url": endpoint(settings)}
    changed = _save_json(path, data, dry_run=dry_run)
    return IntegrationResult("vscode", path, changed, "VS Code user-profile MCP config")


def _windsurf_config_path() -> Path:
    if os.name == "nt":
        root = Path(os.environ.get("USERPROFILE", str(Path.home())))
    else:
        root = Path.home()
    return root / ".codeium" / "windsurf" / "mcp_config.json"


def integrate_windsurf(settings: Settings, *, dry_run: bool = False) -> IntegrationResult:
    path = _windsurf_config_path()
    changed = _merge_mcp_servers(path, {"serverUrl": endpoint(settings)}, dry_run=dry_run)
    return IntegrationResult("windsurf", path, changed, "Windsurf/Cascade user MCP config")


def _codex_config_path() -> Path:
    return Path.home() / ".codex" / "config.toml"


def _codex_block(settings: Settings) -> str:
    lines = [
        f"[mcp_servers.{SERVER_NAME}]",
        f'url = "{endpoint(settings)}"',
        "",
    ]
    for tool in APPROVED_CODEX_TOOLS:
        lines.extend(
            [
                f"[mcp_servers.{SERVER_NAME}.tools.{tool}]",
                'approval_mode = "approve"',
                "",
            ]
        )
    return "\n".join(lines).rstrip() + "\n"


def _replace_codex_block(text: str, block: str) -> str:
    pattern = re.compile(
        rf"(?ms)^\[mcp_servers\.{re.escape(SERVER_NAME)}(?:\.tools\.[^\]]+)?\]\n.*?(?=^\[|\Z)"
    )
    stripped = pattern.sub("", text).rstrip()
    return (stripped + "\n\n" if stripped else "") + block


def integrate_codex(settings: Settings, *, dry_run: bool = False) -> IntegrationResult:
    path = _codex_config_path()
    text = path.read_text(encoding="utf-8") if path.exists() else ""
    updated = _replace_codex_block(text, _codex_block(settings))
    changed = text != updated
    if changed and not dry_run:
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(updated, encoding="utf-8")
    return IntegrationResult("codex", path, changed, "Codex global MCP config")


def integrate_targets(
    targets: list[str],
    settings: Settings | None = None,
    *,
    project_dir: Path | None = None,
    dry_run: bool = False,
    scope: str = "project",
) -> list[IntegrationResult]:
    settings = settings or Settings.load()
    project_dir = project_dir or Path.cwd()
    expanded = ["codex", "claude", "cursor", "vscode", "windsurf"] if "all" in targets else targets
    if scope not in ("global", "project"):
        raise ValueError(f"Unsupported integration scope: {scope}")
    results: list[IntegrationResult] = []
    for target in expanded:
        if target == "codex":
            results.append(integrate_codex(settings, dry_run=dry_run))
        elif target == "claude":
            results.append(
                integrate_claude_global(settings, dry_run=dry_run)
                if scope == "global"
                else integrate_claude(project_dir, settings, dry_run=dry_run)
            )
        elif target == "cursor":
            results.append(
                integrate_cursor_global(settings, dry_run=dry_run)
                if scope == "global"
                else integrate_cursor(project_dir, settings, dry_run=dry_run)
            )
        elif target == "vscode":
            results.append(
                integrate_vscode_global(settings, dry_run=dry_run)
                if scope == "global"
                else integrate_vscode(project_dir, settings, dry_run=dry_run)
            )
        elif target == "windsurf":
            results.append(integrate_windsurf(settings, dry_run=dry_run))
        else:
            raise ValueError(f"Unsupported integration target: {target}")
    return results


def integration_status(
    settings: Settings | None = None,
    *,
    project_dir: Path | None = None,
) -> dict[str, bool]:
    """Report whether each supported agent points at the current Pocket Disasm endpoint."""
    settings = settings or Settings.load()
    project_dir = (project_dir or Path.cwd()).expanduser().resolve()
    expected = endpoint(settings)

    def json_server(path: Path, root: str, url_key: str = "url") -> bool:
        try:
            server = _load_json(path).get(root, {}).get(SERVER_NAME, {})
        except RuntimeError:
            return False
        return server.get(url_key) == expected

    codex_path = _codex_config_path()
    try:
        codex_text = codex_path.read_text(encoding="utf-8")
    except (FileNotFoundError, OSError):
        codex_text = ""
    codex_ready = (
        f"[mcp_servers.{SERVER_NAME}]" in codex_text
        and f'url = "{expected}"' in codex_text
    )
    return {
        "codex": codex_ready,
        "claude": json_server(_claude_user_config_path(), "mcpServers")
        or json_server(_project_file(project_dir, ".mcp.json"), "mcpServers"),
        "cursor": json_server(Path.home() / ".cursor" / "mcp.json", "mcpServers")
        or json_server(_project_file(project_dir, ".cursor/mcp.json"), "mcpServers"),
        "vscode": json_server(_vscode_user_config_path(), "servers")
        or json_server(_project_file(project_dir, ".vscode/mcp.json"), "servers"),
        "windsurf": json_server(_windsurf_config_path(), "mcpServers", "serverUrl"),
    }


def _integration_registry_path() -> Path:
    return user_config_dir() / "integrations.json"


def remember_integrations(results: list[IntegrationResult], path: Path | None = None) -> Path:
    """Remember exact config files so endpoint changes can update every prior integration."""
    path = path or _integration_registry_path()
    try:
        current = json.loads(path.read_text(encoding="utf-8"))
    except (FileNotFoundError, OSError, ValueError):
        current = {"files": []}
    files = {str(Path(item).resolve()) for item in current.get("files", []) if item}
    files.update(str(result.path.resolve()) for result in results if result.path)
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps({"files": sorted(files)}, indent=2), encoding="utf-8")
    return path


def update_integration_endpoints(
    old_settings: Settings,
    new_settings: Settings,
    *,
    project_dir: Path | None = None,
    registry_path: Path | None = None,
) -> list[Path]:
    """Replace the old Pocket Disasm URL in every known MCP client config."""
    project_dir = (project_dir or Path.cwd()).expanduser().resolve()
    registry_path = registry_path or _integration_registry_path()
    try:
        registry = json.loads(registry_path.read_text(encoding="utf-8"))
        registered = [Path(item) for item in registry.get("files", [])]
    except (FileNotFoundError, OSError, ValueError):
        registered = []
    candidates = {
        _codex_config_path(),
        _windsurf_config_path(),
        _claude_user_config_path(),
        Path.home() / ".cursor" / "mcp.json",
        _vscode_user_config_path(),
        _project_file(project_dir, ".mcp.json"),
        _project_file(project_dir, ".cursor/mcp.json"),
        _project_file(project_dir, ".vscode/mcp.json"),
        *registered,
    }
    old_url = endpoint(old_settings)
    new_url = endpoint(new_settings)
    changed: list[Path] = []
    for path in candidates:
        try:
            text = path.read_text(encoding="utf-8")
        except (FileNotFoundError, OSError):
            continue
        if SERVER_NAME not in text or old_url not in text:
            continue
        path.write_text(text.replace(old_url, new_url), encoding="utf-8")
        changed.append(path)
    return sorted(changed, key=lambda item: str(item).casefold())
