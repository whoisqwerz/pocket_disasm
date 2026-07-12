from __future__ import annotations

import argparse
import importlib.metadata
import os
import subprocess
import sys
import time
from pathlib import Path

from . import __version__
from .backend import port_is_open
from .config import Settings, discover_ida_dir, is_ida_dir
from .daemon import inspect_daemon, read_pidfile, remove_pidfile, start_daemon, stop_daemon, write_pidfile
from .integrations import endpoint as integration_endpoint
from .integrations import integrate_targets, remember_integrations, update_integration_endpoints
from .supervisor import MultiSessionSupervisor
from .transport import McpHttpClient, McpTransportError


EXPECTED_MCP_VERSION = "2.0.0"


def _package_version(name: str) -> str | None:
    try:
        return importlib.metadata.version(name)
    except importlib.metadata.PackageNotFoundError:
        return None


def _resolve_ida(args: argparse.Namespace, settings: Settings) -> Path:
    ida_dir = discover_ida_dir(getattr(args, "ida_dir", None), settings)
    if ida_dir is not None:
        return ida_dir
    if sys.stdin.isatty():
        print("IDA 9.x with IDALib was not detected automatically.")
        print("Enter the IDA installation directory containing idalib.dll.")
        while True:
            value = input("IDA directory (blank to cancel): ").strip().strip('"')
            if not value:
                raise SystemExit(1)
            candidate = Path(value).expanduser().resolve()
            if is_ida_dir(candidate):
                settings.ida_dir = str(candidate)
                path = settings.save()
                print(f"Saved configuration: {path}")
                return candidate
            print(f"IDALib was not found under: {candidate}")
    raise SystemExit(
        "IDA 9.x with IDALib was not found. Pass --ida-dir PATH or run "
        "`pocket-disasm config --ida-dir PATH`."
    )


def command_doctor(args: argparse.Namespace) -> int:
    settings = Settings.load()
    ida_dir = discover_ida_dir(args.ida_dir, settings)
    mcp_version = _package_version("ida-pro-mcp")
    idapro_version = _package_version("idapro")
    state = inspect_daemon(settings)
    print(f"Pocket Disasm: {__version__}")
    print(f"Python:        {sys.version.split()[0]} ({sys.executable})")
    mcp_label = mcp_version or "not installed"
    if mcp_version and mcp_version != EXPECTED_MCP_VERSION:
        mcp_label += f" (expected {EXPECTED_MCP_VERSION})"
    print(f"ida-pro-mcp:   {mcp_label}")
    print(f"idapro:        {idapro_version or 'not installed'}")
    print("IDA plugins:   not required (headless IDALib backend)")
    print(f"IDA directory: {ida_dir or 'not found'}")
    print(f"IDALib:        {'ready' if ida_dir and is_ida_dir(ida_dir) else 'not available'}")
    print(f"MCP endpoint:  {state.endpoint}")
    print(f"Daemon:        {'running' if state.running else 'stopped'}{f' (pid {state.pid})' if state.pid else ''}")
    if mcp_version != EXPECTED_MCP_VERSION or not idapro_version or not ida_dir:
        return 1
    return 0


def command_config(args: argparse.Namespace) -> int:
    settings = Settings.load()
    if args.ida_dir:
        candidate = Path(args.ida_dir).expanduser().resolve()
        if not is_ida_dir(candidate):
            raise SystemExit(f"IDALib was not found under: {candidate}")
        settings.ida_dir = str(candidate)
    if args.base_port is not None:
        settings.base_port = args.base_port
    if args.port is not None:
        settings.port = args.port
    if args.max_workers is not None:
        settings.max_workers = args.max_workers
    path = settings.save()
    print(f"Saved configuration: {path}")
    return 0


def command_control(args: argparse.Namespace) -> int:
    from .ui import run_control_center

    art_path = Path(args.art).expanduser().resolve() if args.art else None
    return run_control_center(art_path)


def command_status(args: argparse.Namespace) -> int:
    settings = Settings.load()
    state = inspect_daemon(settings)
    print(f"Endpoint: {state.endpoint}")
    print(f"State:    {'running' if state.running else 'stopped'}")
    if state.pid:
        print(f"PID:      {state.pid} ({state.source})")
    if state.running:
        try:
            client = McpHttpClient(state.endpoint, timeout=5.0)
            client.initialize()
            tools = client.request("tools/list", {})
            print(f"Tools:    {len(tools.get('tools', []))}")
        except McpTransportError as error:
            print(f"Health:   MCP endpoint is reachable but did not answer cleanly: {error}")
            return 2
    return 0 if state.running else 1


def _serve_args_from_namespace(args: argparse.Namespace) -> list[str]:
    result: list[str] = []
    if args.ida_dir:
        result.extend(["--ida-dir", args.ida_dir])
    if args.host:
        result.extend(["--host", args.host])
    if args.port is not None:
        result.extend(["--port", str(args.port)])
    if args.base_port is not None:
        result.extend(["--base-port", str(args.base_port)])
    if args.max_workers is not None:
        result.extend(["--max-workers", str(args.max_workers)])
    if args.unsafe:
        result.append("--unsafe")
    if args.verbose:
        result.append("--verbose")
    result.extend(args.binaries)
    return result


def command_start(args: argparse.Namespace) -> int:
    settings = Settings.load()
    state = inspect_daemon(settings)
    if state.running:
        print(f"Pocket Disasm is already running at {state.endpoint}")
        return 0
    process = start_daemon(_serve_args_from_namespace(args))
    print(f"Starting Pocket Disasm daemon (pid {process.pid})...")
    deadline = time.monotonic() + args.timeout
    while time.monotonic() < deadline:
        state = inspect_daemon(settings)
        if state.running:
            print(f"Endpoint: {state.endpoint}")
            return 0
        if process.poll() is not None:
            print(f"Daemon exited early with code {process.returncode}")
            return int(process.returncode or 1)
        time.sleep(0.25)
    print(f"Daemon did not become ready within {args.timeout:.1f}s; check logs with `pocket-disasm logs`.")
    return 1


def command_stop(args: argparse.Namespace) -> int:
    state = stop_daemon(timeout=args.timeout)
    if not state.running:
        print("Pocket Disasm daemon is stopped.")
        return 0
    print(f"Could not stop daemon at {state.endpoint}")
    return 1


def command_restart(args: argparse.Namespace) -> int:
    stop_daemon(timeout=args.timeout)
    return command_start(args)


def command_logs(args: argparse.Namespace) -> int:
    from .config import runtime_dir

    root = runtime_dir()
    paths = [root / "pocket-disasm.out.log", root / "pocket-disasm.err.log"]
    print(f"Log directory: {root}")
    for path in paths:
        print(f"\n== {path.name} ==")
        if not path.exists():
            print("<missing>")
            continue
        lines = path.read_text(encoding="utf-8", errors="replace").splitlines()
        for line in lines[-args.tail :]:
            print(line)
    return 0


def command_integrate(args: argparse.Namespace) -> int:
    settings = Settings.load()
    results = integrate_targets(
        args.targets,
        settings,
        project_dir=Path(args.project_dir).expanduser().resolve(),
        dry_run=args.dry_run,
        scope=args.scope,
    )
    if not args.dry_run:
        remember_integrations(results)
    print(f"Pocket Disasm MCP endpoint: {integration_endpoint(settings)}")
    for result in results:
        action = "would update" if args.dry_run and result.changed else "updated" if result.changed else "already configured"
        path = str(result.path) if result.path else "<command>"
        print(f"{result.target}: {action}: {path}")
    print("Restart or reload the target agent after changing its MCP config.")
    return 0


def command_port(args: argparse.Namespace) -> int:
    if not 1 <= args.port <= 65535:
        raise SystemExit("Port must be between 1 and 65535")
    settings = Settings.load()
    if settings.base_port <= args.port < settings.base_port + settings.max_workers:
        raise SystemExit(
            f"Port {args.port} overlaps the internal worker range "
            f"{settings.base_port}-{settings.base_port + settings.max_workers - 1}."
        )
    if settings.port == args.port:
        print(f"Pocket Disasm already uses port {args.port}.")
        return 0
    old_settings = Settings(**{name: getattr(settings, name) for name in ("ida_dir", "host", "port", "base_port", "max_workers")})
    was_running = inspect_daemon(old_settings).running
    if was_running:
        print("Stopping the router before changing its endpoint...")
        stopped = stop_daemon(timeout=args.timeout, settings=old_settings)
        if stopped.running:
            print(f"Could not stop the router at {stopped.endpoint}")
            return 1
    settings.port = args.port
    settings.save()
    changed = update_integration_endpoints(
        old_settings,
        settings,
        project_dir=Path(args.project_dir).expanduser().resolve(),
    )
    print(f"MCP endpoint: http://{settings.host}:{settings.port}/mcp")
    if changed:
        print("Updated MCP configurations:")
        for path in changed:
            print(f"  {path}")
    else:
        print("No existing MCP client configurations required an update.")
    if was_running and not args.no_restart:
        print("Starting the router on the new port...")
        process = start_daemon([])
        deadline = time.monotonic() + args.timeout
        while time.monotonic() < deadline:
            state = inspect_daemon(settings)
            if state.running:
                print(f"Router ready (pid {state.pid})")
                return 0
            if process.poll() is not None:
                print(f"Router exited early with code {process.returncode}")
                return int(process.returncode or 1)
            time.sleep(0.25)
        print("Router did not become ready; check `pocket logs`.")
        return 1
    return 0


def command_mcp(args: argparse.Namespace) -> int:
    settings = Settings.load()
    ida_dir = _resolve_ida(args, settings)
    env = os.environ.copy()
    env["IDADIR"] = str(ida_dir)
    command = [
        sys.executable,
        "-m",
        "ida_pro_mcp.idalib_server",
        "--host",
        args.host,
        "--port",
        str(args.port),
    ]
    if args.verbose:
        command.append("--verbose")
    if args.unsafe:
        command.append("--unsafe")
    if args.binary:
        command.append(str(Path(args.binary).expanduser().resolve()))
    return subprocess.call(command, env=env)


def command_serve(args: argparse.Namespace) -> int:
    settings = Settings.load()
    host = args.host or settings.host
    public_port = args.port or settings.port
    worker_base_port = args.base_port or settings.base_port
    max_workers = args.max_workers or settings.max_workers
    if port_is_open(host, public_port):
        raise SystemExit(
            f"MCP port {host}:{public_port} is already in use. "
            "Pocket Disasm may already be running."
        )
    ida_dir = _resolve_ida(args, settings)
    os.environ["IDADIR"] = str(ida_dir)
    if worker_base_port <= public_port < worker_base_port + max_workers:
        raise SystemExit("The public --port must be outside the internal worker port range")
    supervisor = MultiSessionSupervisor(
        ida_dir,
        host=host,
        base_port=worker_base_port,
        max_workers=max_workers,
        unsafe=args.unsafe,
        verbose=args.verbose,
    )
    from .router import UnifiedMcpRouter, run_router_console

    try:
        router = UnifiedMcpRouter(supervisor)
    except Exception as error:
        supervisor.close_all()
        raise SystemExit(f"Could not initialize the unified IDA MCP router: {error}") from error
    try:
        for binary in args.binaries:
            try:
                supervisor.open_async(Path(binary).expanduser())
            except Exception as error:
                print(f"Could not open {binary}: {error}")
        router.serve(host, public_port, background=True)
        write_pidfile()
        if args.no_repl:
            print(f"Unified MCP: {router.endpoint}")
            print("The MCP client can create sessions with idb_open. Press Ctrl+C to stop.")
            while True:
                time.sleep(1)
        else:
            run_router_console(router)
    except KeyboardInterrupt:
        pass
    finally:
        router.stop()
        supervisor.close_all()
        if read_pidfile() == os.getpid():
            remove_pidfile()
    return 0


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="pocket-disasm", description="Lightweight IDALib decompiler with IDA Pro MCP compatibility")
    parser.add_argument("--version", action="version", version=__version__)
    sub = parser.add_subparsers(dest="command", required=True)

    doctor = sub.add_parser("doctor", help="Check IDA, IDALib and MCP dependencies")
    doctor.add_argument("--ida-dir")
    doctor.set_defaults(handler=command_doctor)

    config = sub.add_parser("config", help="Save local configuration")
    config.add_argument("--ida-dir")
    config.add_argument("--base-port", type=int)
    config.add_argument("--port", type=int)
    config.add_argument("--max-workers", type=int)
    config.set_defaults(handler=command_config)

    control = sub.add_parser("control", help="Open the IDA-style terminal control center")
    control.add_argument("--art", help="HTML or plain text colored ASCII art file")
    control.set_defaults(handler=command_control)

    status = sub.add_parser("status", help="Show daemon and MCP endpoint status")
    status.set_defaults(handler=command_status)

    logs = sub.add_parser("logs", help="Show daemon logs")
    logs.add_argument("--tail", type=int, default=80)
    logs.set_defaults(handler=command_logs)

    integrate = sub.add_parser("integrate", help="Configure coding agents to use the Pocket Disasm MCP endpoint")
    integrate.add_argument(
        "targets",
        nargs="+",
        choices=("codex", "claude", "cursor", "vscode", "windsurf", "all"),
        help="Agent config(s) to update",
    )
    integrate.add_argument("--project-dir", default=".", help="Project directory for workspace-scoped configs")
    integrate.add_argument(
        "--scope",
        choices=("global", "project"),
        default="global",
        help="Install for every project (default) or only the selected project",
    )
    integrate.add_argument("--dry-run", action="store_true")
    integrate.set_defaults(handler=command_integrate)

    port = sub.add_parser("port", help="Change the public MCP port everywhere")
    port.add_argument("port", type=int)
    port.add_argument("--project-dir", default=".", help="Also inspect MCP configs in this project")
    port.add_argument("--no-restart", action="store_true", help="Do not restart a running router")
    port.add_argument("--timeout", type=float, default=20.0)
    port.set_defaults(handler=command_port)

    mcp = sub.add_parser("mcp", help="Run the stock ida-pro-mcp 2.x IDALib server")
    mcp.add_argument("binary", nargs="?")
    mcp.add_argument("--ida-dir")
    mcp.add_argument("--host", default="127.0.0.1")
    mcp.add_argument("--port", type=int, default=13339)
    mcp.add_argument("--unsafe", action="store_true")
    mcp.add_argument("--verbose", action="store_true")
    mcp.set_defaults(handler=command_mcp)

    serve = sub.add_parser("serve", help="Run independent IDALib workers for multiple binaries")
    serve.add_argument("binaries", nargs="*")
    serve.add_argument("--ida-dir")
    serve.add_argument("--host")
    serve.add_argument("--port", type=int, help="Single public MCP port")
    serve.add_argument("--base-port", type=int, help="First internal worker port")
    serve.add_argument("--max-workers", type=int)
    serve.add_argument("--unsafe", action="store_true")
    serve.add_argument("--verbose", action="store_true")
    serve.add_argument("--no-repl", action="store_true")
    serve.set_defaults(handler=command_serve)

    for name, handler, help_text in (
        ("start", command_start, "Start the unified MCP daemon in the background"),
        ("restart", command_restart, "Restart the unified MCP daemon in the background"),
    ):
        item = sub.add_parser(name, help=help_text)
        item.add_argument("binaries", nargs="*")
        item.add_argument("--ida-dir")
        item.add_argument("--host")
        item.add_argument("--port", type=int)
        item.add_argument("--base-port", type=int)
        item.add_argument("--max-workers", type=int)
        item.add_argument("--unsafe", action="store_true")
        item.add_argument("--verbose", action="store_true")
        item.add_argument("--timeout", type=float, default=20.0)
        item.set_defaults(handler=handler)

    stop = sub.add_parser("stop", help="Stop the background MCP daemon")
    stop.add_argument("--timeout", type=float, default=10.0)
    stop.set_defaults(handler=command_stop)
    return parser


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    result = args.handler(args)
    return int(result) if result is not None else 0


if __name__ == "__main__":
    raise SystemExit(main())
