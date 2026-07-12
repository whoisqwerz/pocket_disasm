from __future__ import annotations

import os
import re
import sys
import time
import math
import subprocess
from io import StringIO
from html import unescape
from html.parser import HTMLParser
from importlib import resources
from pathlib import Path

from rich import box
from rich.align import Align
from rich.console import Console, Group
from rich.panel import Panel
from rich.prompt import Prompt
from rich.table import Table
from rich.text import Span, Text

from . import __version__
from .config import Settings, discover_ida_dir, is_ida_dir, runtime_dir
from .daemon import inspect_daemon, start_daemon, stop_daemon
from .diagnostics import append_event, append_exception, event_log_path
from .integrations import endpoint, integrate_targets, integration_status, remember_integrations
from .transport import McpHttpClient, McpTransportError
from .updates import UpdateInfo, check_for_update, install_update


FALLBACK_IDA_ART = """
IIIIIII  DDDDD      AAAAA
  III    DD  DD    AA   AA
  III    DD   DD   AAAAAAA
  III    DD  DD    AA   AA
IIIIIII  DDDDD     AA   AA
""".strip("\n")


class ColoredAsciiParser(HTMLParser):
    def __init__(self) -> None:
        super().__init__(convert_charrefs=False)
        self.text = Text(no_wrap=True)
        self._styles: list[str | None] = [None]

    def handle_starttag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        if tag.lower() != "span":
            self._styles.append(self._styles[-1])
            return
        style = dict(attrs).get("style") or ""
        match = re.search(r"color\s*:\s*rgb\((\d+),\s*(\d+),\s*(\d+)\)", style, re.IGNORECASE)
        if not match:
            self._styles.append(self._styles[-1])
            return
        r, g, b = (max(0, min(255, int(value))) for value in match.groups())
        self._styles.append(f"rgb({r},{g},{b})")

    def handle_endtag(self, tag: str) -> None:
        if len(self._styles) > 1:
            self._styles.pop()

    def handle_data(self, data: str) -> None:
        self._append(unescape(data))

    def handle_entityref(self, name: str) -> None:
        self._append(unescape(f"&{name};"))

    def handle_charref(self, name: str) -> None:
        self._append(unescape(f"&#{name};"))

    def _append(self, value: str) -> None:
        style = self._styles[-1]
        if style == "rgb(0,0,0)":
            value = value.replace("-", " ")
        self.text.append(value, style=style)


def parse_colored_ascii_html(html: str, *, max_width: int = 110, max_lines: int = 18) -> Text:
    parser = ColoredAsciiParser()
    parser.feed(html)
    parser.close()
    return fit_art(parser.text, max_width=max_width, max_lines=max_lines)


def crop_text(text: Text, *, max_width: int, max_lines: int) -> Text:
    lines = text.split("\n")
    cropped = Text(no_wrap=True)
    for index, line in enumerate(lines[:max_lines]):
        if index:
            cropped.append("\n")
        item = line.copy()
        item.truncate(max_width, overflow="crop")
        cropped.append_text(item)
    return cropped


def slice_text_line(text: Text, start: int, end: int | None = None) -> Text:
    plain = text.plain[start:end]
    sliced = Text(plain, style=text.style, no_wrap=True)
    stop = len(text.plain) if end is None else min(end, len(text.plain))
    for span in text.spans:
        span_start = max(span.start, start)
        span_end = min(span.end, stop)
        if span_start < span_end:
            sliced.spans.append(Span(span_start - start, span_end - start, span.style))
    return sliced


def fit_art(text: Text, *, max_width: int, max_lines: int) -> Text:
    lines = text.split("\n")
    non_empty = [index for index, line in enumerate(lines) if line.plain.strip()]
    if not non_empty:
        return Text("", no_wrap=True)
    lines = lines[non_empty[0] : non_empty[-1] + 1]
    left_edges = [len(line.plain) - len(line.plain.lstrip()) for line in lines if line.plain.strip()]
    left = min(left_edges, default=0)
    trimmed = Text(no_wrap=True)
    for index, line in enumerate(lines):
        if index:
            trimmed.append("\n")
        item = slice_text_line(line, left) if left else line.copy()
        trimmed.append_text(item)
    return crop_text(trimmed, max_width=max_width, max_lines=max_lines)


def load_art(path: Path | None = None, *, width: int = 110, lines: int = 18) -> Text:
    if path is not None:
        raw = path.read_text(encoding="utf-8", errors="replace")
    else:
        try:
            raw = resources.files("pocket_disasm").joinpath("assets/ida_compact.html").read_text(encoding="utf-8")
        except (FileNotFoundError, ModuleNotFoundError):
            raw = ""
    if "<span" in raw and "rgb(" in raw:
        return parse_colored_ascii_html(raw, max_width=width, max_lines=lines)
    if raw:
        return crop_text(Text(raw, style="bold #22a7f0", no_wrap=True), max_width=width, max_lines=lines)
    return Text(FALLBACK_IDA_ART, style="bold #22a7f0", no_wrap=True)


def compact_ida_mark() -> Text:
    """Small, complete wordmark designed for a terminal rather than cropped from the hero art."""
    rows = (
        ("██╗", "██████╗", "█████╗"),
        ("██║", "██╔══██╗", "██╔══██╗"),
        ("██║", "██║  ██║", "███████║"),
        ("██║", "██║  ██║", "██╔══██║"),
        ("██║", "██████╔╝", "██║  ██║"),
        ("╚═╝", "╚═════╝", "╚═╝  ╚═╝"),
    )
    mark = Text(no_wrap=True)
    colors = ("bold #38d9f5", "bold #f0b429", "bold #f36f45")
    for row_index, row in enumerate(rows):
        if row_index:
            mark.append("\n")
        for part_index, part in enumerate(row):
            if part_index:
                mark.append(" ")
            mark.append(part, style=colors[part_index])
    return mark


def render_halfblock_art(html: str, *, width: int = 52, rows: int = 9) -> Text:
    """Downsample the complete colored character canvas into two RGB pixels per cell."""
    parser = ColoredAsciiParser()
    parser.feed(html)
    parser.close()
    source = parser.text
    plain = source.plain
    styles: list[str | None] = [None] * len(plain)
    for span in source.spans:
        style = str(span.style)
        for index in range(span.start, min(span.end, len(styles))):
            styles[index] = style

    grid: list[list[tuple[int, int, int] | None]] = [[]]
    for index, char in enumerate(plain):
        if char == "\n":
            grid.append([])
            continue
        match = re.fullmatch(r"rgb\((\d+),(\d+),(\d+)\)", styles[index] or "")
        color = tuple(map(int, match.groups())) if match and char.strip() else None
        grid[-1].append(color)
    points = [(x, y) for y, line in enumerate(grid) for x, color in enumerate(line) if color]
    if not points:
        return Text("")
    left, right = min(x for x, _ in points), max(x for x, _ in points) + 1
    top, bottom = min(y for _, y in points), max(y for _, y in points) + 1
    pixel_height = rows * 2

    def sample(tx: int, ty: int) -> tuple[int, int, int] | None:
        x0 = left + (right - left) * tx // width
        x1 = left + (right - left) * (tx + 1) // width
        y0 = top + (bottom - top) * ty // pixel_height
        y1 = top + (bottom - top) * (ty + 1) // pixel_height
        colors = [
            grid[y][x]
            for y in range(y0, max(y0 + 1, y1))
            for x in range(x0, max(x0 + 1, x1))
            if y < len(grid) and x < len(grid[y]) and grid[y][x]
        ]
        if not colors:
            return None
        return tuple(sum(color[channel] for color in colors) // len(colors) for channel in range(3))

    result = Text(no_wrap=True)
    color_name = lambda color: "#%02x%02x%02x" % color
    for row in range(rows):
        if row:
            result.append("\n")
        for column in range(width):
            upper = sample(column, row * 2)
            lower = sample(column, row * 2 + 1)
            if upper and lower:
                result.append("▀", style=f"{color_name(upper)} on {color_name(lower)}")
            elif upper:
                result.append("▀", style=color_name(upper))
            elif lower:
                result.append("▄", style=color_name(lower))
            else:
                result.append(" ")
    return result


def load_terminal_art(path: Path | None = None, *, width: int = 52, rows: int = 9) -> Text:
    if path:
        raw = path.read_text(encoding="utf-8", errors="replace")
    else:
        raw = resources.files("pocket_disasm").joinpath("assets/ida_colored.html").read_text(encoding="utf-8")
    return render_halfblock_art(raw, width=width, rows=rows) if "<span" in raw else load_art(path, width=width, lines=rows)


def _mcp_tool_count(state_endpoint: str) -> str:
    try:
        client = McpHttpClient(state_endpoint, timeout=3.0)
        client.initialize()
        result = client.request("tools/list", {})
        return str(len(result.get("tools", [])))
    except McpTransportError:
        return "unhealthy"


def _status_table(settings: Settings) -> Table:
    state = inspect_daemon(settings)
    ida_dir = discover_ida_dir(settings=settings)
    tools = _mcp_tool_count(state.endpoint) if state.running else "-"
    status = "[green]RUNNING[/]" if state.running else "[yellow]STOPPED[/]"
    table = Table.grid(padding=(0, 2))
    table.add_column(style="dim", no_wrap=True)
    table.add_column(no_wrap=False)
    table.add_row("Version", __version__)
    table.add_row("Daemon", status)
    table.add_row("PID", str(state.pid) if state.pid else "-")
    table.add_row("Endpoint", f"[cyan]{state.endpoint}[/]")
    table.add_row("Tools", f"[green]{tools}[/]" if tools.isdigit() else f"[yellow]{tools}[/]")
    table.add_row("IDA", f"[green]{ida_dir}[/]" if ida_dir else "[yellow]not configured[/]")
    table.add_row("Runtime", f"[dim]{runtime_dir()}[/]")
    return table


def _metric(label: str, value: str, style: str, subtitle: str = "") -> Panel:
    content = Group(
        Text(value, style=f"bold {style}", justify="center"),
        Text(label, style="bold white", justify="center"),
        Text(subtitle, style="dim", justify="center") if subtitle else Text(""),
    )
    return Panel(content, border_style=style, box=box.ROUNDED, padding=(0, 1))


def _ida_label(path: Path | None) -> str:
    if not path:
        return "not configured"
    match = re.search(r"(\d+\.\d+)", path.name)
    return f"IDA {match.group(1)}" if match else "configured"


def _metrics(settings: Settings) -> Table:
    state = inspect_daemon(settings)
    tools = _mcp_tool_count(state.endpoint) if state.running else "-"
    ida_dir = discover_ida_dir(settings=settings)
    table = Table.grid(expand=True, padding=(0, 1))
    for _ in range(4):
        table.add_column(ratio=1)
    table.add_row(
        _metric("DAEMON", "ONLINE" if state.running else "OFFLINE", "green" if state.running else "yellow", f"pid {state.pid}" if state.pid else ""),
        _metric("TOOLS", tools, "cyan" if tools.isdigit() else "yellow", "IDA MCP catalog"),
        _metric("IDA", "READY" if ida_dir else "SETUP", "bright_green" if ida_dir else "yellow", _ida_label(ida_dir)),
        _metric("PORT", str(settings.port), "#ff7a18", "public MCP"),
    )
    return table


def _actions_table() -> Table:
    table = Table.grid(padding=(0, 2))
    table.add_column(no_wrap=True, ratio=1)
    table.add_column(no_wrap=True, ratio=1)
    table.add_row("[black on #ffb000] 1 [/][bold white] Start daemon[/]", "[black on #00d7ff] 2 [/][bold white] Stop daemon[/]")
    table.add_row("[black on #ff7a18] 3 [/][bold white] Restart daemon[/]", "[black on #7cff6b] 4 [/][bold white] Integrate agents[/]")
    table.add_row("[black on #22a7f0] 5 [/][bold white] Configure IDA[/]", "[black on #ff5c8a] 6 [/][bold white] Show logs[/]")
    table.add_row("[black on #8be9fd] 7 [/][bold white] Status details[/]", "[black on #f8f8f2] 8 [/][bold white] Foreground console[/]")
    table.add_row("[black on #aaaaaa] Q [/][bold white] Quit[/]", "[dim]One endpoint. Many IDALib workers.[/]")
    return table


def render_dashboard(settings: Settings | None = None, art_path: Path | None = None) -> Group:
    settings = settings or Settings.load()
    console = Console()
    terminal_width = console.size.width
    terminal_height = console.size.height
    art_width = min(88, max(54, terminal_width - 12))
    art_lines = min(9, max(6, terminal_height // 5))
    art = load_art(art_path, width=art_width, lines=art_lines)
    state = inspect_daemon(settings)
    endpoint_text = Text.assemble((" MCP  ", "black on #ffb000 bold"), (" "), (state.endpoint, "cyan"))
    return Group(
        Panel(
            Group(
                Align.center(art),
                Text("POCKET DISASM", style="bold #ffb000", justify="center"),
                Text("IDA Pro style MCP control center", style="#8be9fd", justify="center"),
                Align.center(endpoint_text),
            ),
            border_style="#ff7a18",
            box=box.DOUBLE,
            padding=(0, 1),
        ),
        "",
        _metrics(settings),
        "",
        Panel(_actions_table(), title="[bold #ffb000]Control Deck[/]", border_style="#00d7ff", box=box.HEAVY, padding=(1, 2)),
        Text("LLM clients open sessions with idb_open and route tools with database=...", style="#aaaaaa", justify="center"),
    )


def _pause(console: Console) -> None:
    Prompt.ask("\n[dim]Press Enter to continue[/]", default="", show_default=False, console=console)


def _start(console: Console) -> None:
    settings = Settings.load()
    append_event("info", "tui.daemon.start.requested", endpoint=endpoint(settings))
    state = inspect_daemon(settings)
    if state.running:
        console.print(f"[green]Already running at {state.endpoint}[/]")
        return
    process = start_daemon([])
    append_event("info", "tui.daemon.start.spawned", pid=process.pid)
    console.print(f"[cyan]Starting daemon, pid {process.pid}...[/]")
    deadline = time.monotonic() + 20.0
    while time.monotonic() < deadline:
        state = inspect_daemon(settings)
        if state.running:
            append_event("info", "tui.daemon.start.ready", endpoint=state.endpoint, pid=state.pid)
            console.print(f"[green]Ready: {state.endpoint}[/]")
            return
        exit_code = process.poll()
        if exit_code is not None:
            append_event("error", "tui.daemon.start.failed", pid=process.pid, exit_code=exit_code)
            console.print(f"[red]Daemon exited with code {exit_code}. Open Inspect logs.[/]")
            console.print(f"[dim]Diagnostic log: {event_log_path()}[/]")
            return
        time.sleep(0.25)
    append_event("error", "tui.daemon.start.timeout", pid=process.pid, timeout=20.0)
    console.print("[yellow]Daemon did not become ready within 20 seconds. Check logs.[/]")


def _stop(console: Console) -> None:
    state = stop_daemon()
    if state.running:
        console.print(f"[red]Could not stop daemon at {state.endpoint}[/]")
    else:
        console.print("[green]Daemon stopped.[/]")


def _restart(console: Console) -> None:
    stop_daemon()
    _start(console)


def _integrate(console: Console) -> None:
    raw = Prompt.ask("Targets", default="codex", console=console)
    targets = raw.split()
    project = Prompt.ask("Project dir for workspace configs", default=".", console=console)
    results = integrate_targets(targets, Settings.load(), project_dir=Path(project).expanduser().resolve())
    console.print(f"[cyan]Endpoint:[/] {endpoint(Settings.load())}")
    for result in results:
        action = "updated" if result.changed else "already configured"
        console.print(f"{result.target}: [green]{action}[/]: {result.path}")
    console.print("[dim]Restart or reload the target agent after changing MCP config.[/]")


def _configure_ida(console: Console) -> None:
    current = discover_ida_dir(settings=Settings.load())
    if current:
        console.print(f"[green]Current IDA directory:[/] {current}")
    raw = Prompt.ask("IDA directory containing idalib.dll", default="", show_default=False, console=console).strip('"')
    if not raw:
        return
    candidate = Path(raw).expanduser().resolve()
    if not is_ida_dir(candidate):
        console.print(f"[red]IDALib was not found under:[/] {candidate}")
        return
    settings = Settings.load()
    settings.ida_dir = str(candidate)
    path = settings.save()
    console.print(f"[green]Saved configuration:[/] {path}")


def _logs(console: Console) -> None:
    root = runtime_dir()
    console.print(f"[cyan]Log directory:[/] {root}")
    for path in (root / "pocket-disasm.out.log", root / "pocket-disasm.err.log", root / "update.log", event_log_path()):
        console.print(f"\n[bold]{path.name}[/]")
        if not path.exists():
            console.print("[dim]<missing>[/]")
            continue
        for line in path.read_text(encoding="utf-8", errors="replace").splitlines()[-40:]:
            console.print(line)
    worker_logs = sorted(
        (root / "sessions").glob("*/worker.log"),
        key=lambda path: path.stat().st_mtime,
        reverse=True,
    )[:4]
    for path in worker_logs:
        console.print(f"\n[bold]{path.parent.name} / worker.log[/]")
        for line in path.read_text(encoding="utf-8", errors="replace").splitlines()[-40:]:
            console.print(line)
    state = inspect_daemon(Settings.load())
    if not state.running:
        return
    try:
        client = McpHttpClient(state.endpoint, timeout=5.0)
        sessions = client.call_tool("idb_list")
        for session in sessions.get("sessions", []):
            name = session.get("name")
            if not name:
                continue
            worker = client.call_tool("idb_logs", {"database": name, "tail": 40})
            console.print(f"\n[bold]{name} worker[/]")
            for line in worker.get("lines", []):
                console.print(line)
    except (McpTransportError, AttributeError) as error:
        console.print(f"Worker logs unavailable: {error}")


def _foreground_console() -> None:
    from .cli import build_parser

    parser = build_parser()
    args = parser.parse_args(["serve"])
    raise SystemExit(args.handler(args))


def run_control_center(art_path: Path | None = None) -> int:
    if not sys.stdin.isatty():
        Console().print(render_dashboard(art_path=art_path))
        return 0
    set_console_font_once("JetBrains Mono")
    resize_console_once()
    result = PocketDisasmApp(art_path=art_path).run()
    if result == 10:
        os.execv(sys.executable, [sys.executable, "-m", "pocket_disasm", "control"])
    return int(result or 0)


def set_console_font_once(face_name: str = "JetBrains Mono") -> bool:
    """Select a TrueType font for the current classic Windows console."""
    if os.name != "nt" or not sys.stdin.isatty():
        return False
    try:
        import ctypes

        class Coord(ctypes.Structure):
            _fields_ = (("X", ctypes.c_short), ("Y", ctypes.c_short))

        class ConsoleFontInfoEx(ctypes.Structure):
            _fields_ = (
                ("cbSize", ctypes.c_ulong),
                ("nFont", ctypes.c_ulong),
                ("dwFontSize", Coord),
                ("FontFamily", ctypes.c_uint),
                ("FontWeight", ctypes.c_uint),
                ("FaceName", ctypes.c_wchar * 32),
            )

        kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
        kernel32.GetStdHandle.argtypes = (ctypes.c_ulong,)
        kernel32.GetStdHandle.restype = ctypes.c_void_p
        kernel32.GetCurrentConsoleFontEx.argtypes = (
            ctypes.c_void_p,
            ctypes.c_bool,
            ctypes.POINTER(ConsoleFontInfoEx),
        )
        kernel32.GetCurrentConsoleFontEx.restype = ctypes.c_bool
        kernel32.SetCurrentConsoleFontEx.argtypes = (
            ctypes.c_void_p,
            ctypes.c_bool,
            ctypes.POINTER(ConsoleFontInfoEx),
        )
        kernel32.SetCurrentConsoleFontEx.restype = ctypes.c_bool
        handle = kernel32.GetStdHandle(ctypes.c_ulong(-11).value)
        if handle in (None, 0, ctypes.c_void_p(-1).value):
            return False
        info = ConsoleFontInfoEx()
        info.cbSize = ctypes.sizeof(info)
        if not kernel32.GetCurrentConsoleFontEx(handle, False, ctypes.byref(info)):
            return False
        info.FaceName = face_name[:31]
        info.FontFamily = 54
        info.FontWeight = 700
        return bool(kernel32.SetCurrentConsoleFontEx(handle, False, ctypes.byref(info)))
    except (AttributeError, OSError, ValueError):
        return False


def resize_console_once(columns: int = 108, lines: int = 40) -> bool:
    """Give the classic Windows console one stable viewport before Textual starts."""
    if os.name != "nt" or not sys.stdin.isatty():
        return False
    command_processor = os.environ.get("COMSPEC", "cmd.exe")
    try:
        completed = subprocess.run(
            [command_processor, "/d", "/c", "mode", "con:", f"cols={columns}", f"lines={lines}"],
            stdin=subprocess.DEVNULL,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            check=False,
        )
    except OSError:
        return False
    return completed.returncode == 0


from textual import events, work
from textual.app import App, ComposeResult
from textual.binding import Binding
from textual.containers import Horizontal, Vertical, VerticalScroll
from textual.css.query import NoMatches
from textual.widgets import Input, Label, Static


class PocketDisasmApp(App[int]):
    CSS = """
    $bg: #000000;
    $cyan: #00ffff;
    $yellow: #d5caa1;
    $green: #35c4c0;
    $muted: #7f8b90;

    * { scrollbar-size: 0 0; }
    Screen { background: $bg; color: #d9e0e3; overflow: hidden; }
    #shell { width: 100%; height: 1fr; max-width: 86; padding: 1 4 0 4; align-horizontal: center; }
    #mark { height: 13; width: 100%; content-align: center middle; margin-bottom: 1; }
    #identity { height: 3; width: 100%; }
    #eyebrow { height: 1; color: #edf3f5; text-style: bold; text-align: center; }
    #title { height: 1; color: $muted; text-align: center; }
    #tagline { display: none; }
    #status-line { height: 2; width: 100%; margin: 1 0; }
    #daemon-dot { width: auto; color: $green; text-style: bold; margin-right: 2; }
    #endpoint { width: 1fr; color: #829096; }
    #session-hint { width: auto; color: #829096; }
    #main { height: 1fr; width: 100%; }
    #commands { width: 100%; height: 1fr; padding: 0; }
    #commands-title { height: 2; color: #c8d0d3; text-style: bold; }
    #action-menu { height: 8; color: #dfe6e8; }
    #activity-line { height: 1; margin-top: 1; }
    #output { height: 2; color: #8d999e; overflow: hidden; }
    #command-row { height: 1; margin-top: 1; }
    #input-prefix { width: 2; height: 1; color: $cyan; text-style: bold; }
    #command-input { height: 1; border: none; padding: 0; background: transparent; }
    #command-input:focus { border: none; }
    #command-input.input-mode { border: none; color: #f3f6f7; }
    #help { height: 1; color: #566267; text-align: right; }

    Screen.narrow #shell { padding: 1 1 0 1; }
    Screen.narrow #mark { height: 13; }
    Screen.short #mark { display: none; }
    Screen.short #identity { height: 2; }
    Screen.short #status-line { margin: 0; }
    """

    BINDINGS = [
        Binding("q", "quit", "Quit"),
        Binding("r", "refresh_status", "Refresh"),
        Binding("enter", "run_selected", "Run", show=True),
        Binding("escape", "cancel_input", "Cancel", show=False, priority=True),
        Binding("up", "move_selection(-1)", "Previous", show=False, priority=True),
        Binding("down", "move_selection(1)", "Next", show=False, priority=True),
        Binding("1", "run_named('start')", "Start", show=False),
        Binding("2", "run_named('stop')", "Stop", show=False),
        Binding("3", "run_named('restart')", "Restart", show=False),
        Binding("4", "run_named('integrate')", "Integrate", show=False),
        Binding("5", "run_named('configure')", "Configure", show=False),
        Binding("6", "run_named('port')", "Port", show=False),
        Binding("7", "run_named('logs')", "Logs", show=False),
    ]

    def __init__(self, art_path: Path | None = None) -> None:
        super().__init__()
        self.art_path = art_path
        self.settings = Settings.load()
        self.pending_input: str | None = None
        self.active_action: str | None = None
        self.activity_label = ""
        self.activity_hint = ""
        self.activity_waiting = False
        self.activity_frame = 0
        self.selected_action = 0
        self.action_names = ("start", "stop", "restart", "integrate", "configure", "port", "logs")
        self.update_info: UpdateInfo | None = None
        self.agent_selection: int | None = None
        self.agent_targets = ("codex", "claude", "cursor", "vscode", "windsurf", "all")
        self.scope_selection: int | None = None
        self.scope_target: str | None = None
        self.log_view = False

    def compose(self) -> ComposeResult:
        with Vertical(id="shell"):
            yield Static(load_art(self.art_path, width=52, lines=17), id="mark")
            with Vertical(id="identity"):
                yield Label("POCKET DISASM", id="eyebrow")
                yield Label("One MCP endpoint · independent IDALib sessions", id="title")
                yield Label("", id="tagline")
            with Horizontal(id="status-line"):
                yield Label("● CHECKING", id="daemon-dot")
                yield Label(endpoint(self.settings), id="endpoint")
                yield Label("IDA MCP compatible", id="session-hint")
            with Vertical(id="main"):
                with Vertical(id="commands"):
                    yield Label("What would you like to do?", id="commands-title")
                    yield Static(id="action-menu")
                    yield Static("", id="activity-line")
                    yield Static("Router control ready.", id="output")
                    with Horizontal(id="command-row"):
                        yield Label("›", id="input-prefix")
                        yield Input(placeholder="Type a command…  start · stop · restart · connect · logs", id="command-input")
            yield Label("↑↓ navigate   enter run   tab command line   q quit", id="help")

    def on_mount(self) -> None:
        self._set_responsive_classes(self.size.width, self.size.height)
        self._render_actions()
        self.set_focus(None)
        self.action_refresh_status()
        self.check_updates()
        if os.environ.pop("POCKET_DISASM_START_AFTER_UPDATE", "") == "1":
            self.call_after_refresh(self._launch_command, "start")
        self.set_interval(3.0, self.action_refresh_status)
        self.set_interval(0.09, self._animate_activity)

    def on_resize(self, event: events.Resize) -> None:
        self._set_responsive_classes(event.size.width, event.size.height)

    def on_mouse_scroll_up(self, event: events.MouseScrollUp) -> None:
        event.stop()
        event.prevent_default()

    def on_mouse_scroll_down(self, event: events.MouseScrollDown) -> None:
        event.stop()
        event.prevent_default()

    def _set_responsive_classes(self, width: int, height: int) -> None:
        self.screen.set_class(width < 78, "narrow")
        self.screen.set_class(height < 29, "short")

    def action_refresh_status(self) -> None:
        state = inspect_daemon(self.settings)
        dot = self.query_one("#daemon-dot", Label)
        dot.update(f"● {'ONLINE' if state.running else 'OFFLINE'}")
        dot.styles.color = "#35c4c0" if state.running else "#d1b990"
        self.query_one("#endpoint", Label).update(state.endpoint)
        if state.running:
            self.query_one("#session-hint", Label).update(f"pid {state.pid or '—'}  ·  MCP ready")
        else:
            self.query_one("#session-hint", Label).update("router stopped")

    @work(thread=True, exclusive=True, group="update-check")
    def check_updates(self) -> None:
        try:
            info = check_for_update(__version__)
            append_event("info", "update.checked", current=info.current, latest=info.latest, available=info.available)
            self.call_from_thread(self._show_update, info)
        except Exception as error:
            append_exception("update.check.failed", error)

    def _show_update(self, info: UpdateInfo) -> None:
        self.update_info = info
        names = [name for name in self.action_names if name != "update"]
        if info.available:
            names.append("update")
        self.action_names = tuple(names)
        self.selected_action = min(self.selected_action, len(self.action_names) - 1)
        self._render_actions()

    def action_run_selected(self) -> None:
        if self.scope_selection is not None and self.scope_target:
            scope = ("global", "project")[self.scope_selection]
            target = self.scope_target
            self.scope_selection = None
            self.scope_target = None
            self._restore_action_choices()
            self._launch_command("integrate", f"{target}|{scope}")
            return
        if self.agent_selection is not None:
            target = self.agent_targets[self.agent_selection]
            self.agent_selection = None
            if target in ("codex", "windsurf"):
                self._restore_action_choices()
                self._launch_command("integrate", f"{target}|global")
            else:
                self._request_scope_selection(target)
            return
        self.action_run_named(self.action_names[self.selected_action])

    def action_cancel_input(self) -> None:
        if not self.pending_input and self.agent_selection is None and self.scope_selection is None and not self.log_view:
            return
        self.pending_input = None
        self.agent_selection = None
        self.scope_selection = None
        self.scope_target = None
        self.log_view = False
        field = self.query_one("#command-input", Input)
        field.value = ""
        field.placeholder = "Type a command…  start · stop · restart · connect · logs"
        field.remove_class("input-mode")
        self._set_activity()
        self._restore_action_choices()

    def action_move_selection(self, delta: int) -> None:
        if self.scope_selection is not None:
            self.scope_selection = (self.scope_selection + delta) % 2
            self._render_scope_choices()
            return
        if self.agent_selection is not None:
            self.agent_selection = (self.agent_selection + delta) % len(self.agent_targets)
            self._render_agent_choices()
            return
        self.selected_action = (self.selected_action + delta) % len(self.action_names)
        self._render_actions()

    def _render_actions(self) -> None:
        agent_state = integration_status(self.settings, project_dir=Path.cwd())
        configured_agents = sum(agent_state.values())
        ida_path = discover_ida_dir(settings=self.settings)
        ida_ready = bool(ida_path and is_ida_dir(ida_path))
        rows = [
            ("Start MCP router", "bring the shared endpoint online"),
            ("Stop MCP router", "close the endpoint and workers"),
            ("Restart cleanly", "reload configuration and runtime"),
            ("Connect a coding agent", f"{configured_agents}/5 configured"),
            ("Configure IDA", str(ida_path) if ida_ready else "select the IDALib installation"),
            ("Change MCP port", str(self.settings.port)),
            ("Inspect logs", "read recent router output"),
        ]
        if "update" in self.action_names and self.update_info:
            rows.append(("Update Pocket Disasm", f"{self.update_info.current} → {self.update_info.latest}"))
        text = Text()
        for index, (title, detail) in enumerate(rows):
            if index:
                text.append("\n")
            active = index == self.selected_action
            running = self.action_names[index] == self.active_action
            marker = "◆ " if running else "› " if active else "  "
            marker_style = "bold #d5caa1" if running else "bold #00ffff" if active else "#2c2e30"
            text.append(marker, style=marker_style)
            ready = (index == 3 and configured_agents > 0) or (index == 4 and ida_ready)
            if ready:
                text.append("✓ ", style="bold #35c4c0")
            text.append(title, style="bold #f2f5f6" if active else "#aeb8bc")
            text.append(f"  {detail}", style="#7f8b90" if active else "#566267")
        self.query_one("#action-menu", Static).update(text)

    def on_input_submitted(self, event: Input.Submitted) -> None:
        if event.input.id != "command-input":
            return
        value = event.value.strip()
        event.input.value = ""
        if self.pending_input:
            pending, self.pending_input = self.pending_input, None
            event.input.placeholder = "Type a command…  start · stop · restart · connect · logs"
            self._restore_action_choices()
            if value:
                self._launch_command(pending, value)
            else:
                event.input.remove_class("input-mode")
                self._set_activity()
                self._write_inline("Cancelled.")
            return
        raw = value.lower()
        if not raw:
            self.action_run_selected()
            return
        aliases = {
            "start": "start",
            "stop": "stop",
            "restart": "restart",
            "logs": "logs",
            "log": "logs",
            "connect": "integrate",
            "integrate": "integrate",
            "ida": "configure",
            "configure": "configure",
            "update": "update",
        }
        command = aliases.get(raw.split()[0] if raw else "")
        if command:
            self.action_run_named(command)
        elif raw:
            self._write_inline(f"[yellow]Unknown command:[/] {raw}")

    def action_run_named(self, name: str) -> None:
        if name == "integrate":
            self._request_agent_selection()
        elif name == "configure":
            current = str(discover_ida_dir(settings=self.settings) or r"C:\IDA Professional 9.2")
            self._request_inline("configure", "IDA directory containing idalib.dll", current)
        elif name == "port":
            self._request_inline("port", "Public MCP port", str(self.settings.port))
        else:
            self._launch_command(name)

    def _request_agent_selection(self) -> None:
        self.agent_selection = 0
        self.pending_input = None
        self.scope_selection = None
        self.scope_target = None
        self.query_one("#commands-title", Label).update("Connect a coding agent")
        self.query_one("#commands-title", Label).display = True
        self.query_one("#action-menu", Static).display = True
        self.query_one("#output", Static).display = False
        self.query_one("#command-row", Horizontal).display = False
        self._set_activity()
        self.set_focus(None)
        self._render_agent_choices()

    def _request_scope_selection(self, target: str) -> None:
        self.scope_target = target
        self.scope_selection = 0
        self.query_one("#commands-title", Label).update("Where should it be available?")
        self._render_scope_choices()

    def _render_scope_choices(self) -> None:
        choices = (
            ("Global", "available in every project"),
            ("Current project", str(Path.cwd())),
        )
        text = Text()
        for index, (label, detail) in enumerate(choices):
            if index:
                text.append("\n")
            active = index == self.scope_selection
            text.append("› " if active else "  ", style="bold #00ffff" if active else "#2c2e30")
            text.append(label, style="bold #f2f5f6" if active else "#aeb8bc")
            text.append(f"  {detail}", style="#7f8b90" if active else "#566267")
        self.query_one("#action-menu", Static).update(text)

    def _render_agent_choices(self) -> None:
        labels = ("Codex", "Claude Code", "Cursor", "VS Code", "Windsurf", "All coding agents")
        status = integration_status(self.settings, project_dir=Path.cwd())
        text = Text()
        for index, label in enumerate(labels):
            if index:
                text.append("\n")
            active = index == self.agent_selection
            text.append("› " if active else "  ", style="bold #00ffff" if active else "#2c2e30")
            target = self.agent_targets[index]
            ready = all(status.values()) if target == "all" else status[target]
            text.append("✓ " if ready else "  ", style="bold #35c4c0" if ready else "#2c2e30")
            text.append(label, style="bold #f2f5f6" if active else "#aeb8bc")
        self.query_one("#action-menu", Static).update(text)

    def _request_inline(self, mode: str, prompt: str, default: str = "") -> None:
        self.pending_input = mode
        self.query_one("#action-menu", Static).display = False
        self.query_one("#commands-title", Label).display = False
        self.query_one("#output", Static).display = False
        field = self.query_one("#command-input", Input)
        field.placeholder = prompt
        field.value = default
        field.add_class("input-mode")
        field.focus()
        field.action_end()
        if mode == "configure":
            label = f"Configuring IDA… ({default})"
        elif mode == "port":
            label = f"Changing MCP port… ({default})"
        else:
            label = "Connecting a coding agent…"
        self._set_activity(label, waiting=True, hint="(enter to confirm · esc to cancel)")

    def _restore_action_choices(self) -> None:
        self.agent_selection = None
        self.scope_selection = None
        self.scope_target = None
        self.query_one("#action-menu", Static).display = True
        self.query_one("#commands-title", Label).display = True
        self.query_one("#commands-title", Label).update("What would you like to do?")
        self.query_one("#output", Static).display = True
        self.query_one("#output", Static).styles.height = 2
        self.query_one("#command-row", Horizontal).display = True
        self._render_actions()

    def _launch_command(self, name: str, argument: str | None = None) -> None:
        self.query_one("#command-input", Input).remove_class("input-mode")
        self.active_action = name
        self._render_actions()
        self._set_activity(f"RUNNING {name.upper()}")
        self._write_inline("Please wait…")
        self.run_command(name, argument)

    def _set_activity(self, label: str = "", *, waiting: bool = False, hint: str = "") -> None:
        self.activity_label = label
        self.activity_hint = hint
        self.activity_waiting = waiting
        self.activity_frame = 0
        self._animate_activity()

    def _animate_activity(self) -> None:
        try:
            widget = self.query_one("#activity-line", Static)
        except NoMatches:
            return
        if not self.activity_label:
            widget.update("")
            return
        line = Text("~ ", style="bold #00ffff")
        for index, char in enumerate(self.activity_label):
            wave = (math.sin(self.activity_frame * 0.14 - index * 0.32) + 1.0) / 2.0
            level = round(78 + wave * 104)
            line.append(char, style=f"bold rgb({level},{level},{level})")
        if self.activity_hint:
            line.append(f"  {self.activity_hint}", style="#666666")
        widget.update(line)
        self.activity_frame += 1

    def _write_inline(self, message: str) -> None:
        self.query_one("#output", Static).update(Text.from_markup(message))

    @work(thread=True, exclusive=True, group="command")
    def run_command(self, name: str, argument: str | None = None) -> None:
        buffer = StringIO()
        console = Console(file=buffer, force_terminal=False, color_system=None, width=100)
        try:
            if name == "start":
                _start(console)
            elif name == "stop":
                _stop(console)
            elif name == "restart":
                _restart(console)
            elif name == "logs":
                _logs(console)
            elif name == "integrate" and argument:
                target_text, _, scope = argument.lower().partition("|")
                targets = target_text.split()
                results = integrate_targets(
                    targets,
                    Settings.load(),
                    project_dir=Path.cwd(),
                    scope=scope or "global",
                )
                remember_integrations(results)
                console.print(f"Endpoint: {endpoint(Settings.load())}")
                for result in results:
                    console.print(f"{result.target}: {'updated' if result.changed else 'ready'}")
            elif name == "configure" and argument:
                candidate = Path(argument.strip('"')).expanduser().resolve()
                if not is_ida_dir(candidate):
                    raise ValueError(f"IDALib not found under {candidate}")
                settings = Settings.load()
                settings.ida_dir = str(candidate)
                settings.save()
                self.settings = settings
                console.print(f"IDA configured: {candidate}")
            elif name == "port" and argument:
                result = subprocess.run(
                    [sys.executable, "-m", "pocket_disasm", "port", argument],
                    cwd=Path.cwd(),
                    capture_output=True,
                    text=True,
                    encoding="utf-8",
                    errors="replace",
                )
                if result.stdout.strip():
                    console.print(result.stdout.strip())
                if result.returncode:
                    raise RuntimeError(result.stderr.strip() or f"Port command failed ({result.returncode})")
                self.settings = Settings.load()
            elif name == "update":
                state = inspect_daemon(Settings.load())
                if state.running:
                    stop_daemon(settings=Settings.load())
                    os.environ["POCKET_DISASM_START_AFTER_UPDATE"] = "1"
                append_event("info", "update.install.started", current=__version__)
                log_path = install_update()
                append_event("info", "update.install.finished", current=__version__, latest=self.update_info.latest if self.update_info else None)
                console.print(f"Updated to {self.update_info.latest if self.update_info else 'latest'}. Restarting…")
                console.print(f"Update log: {log_path}")
                self.call_from_thread(self.exit, 10)
            else:
                return
        except Exception as error:
            append_exception("tui.action.failed", error, action=name, argument=argument)
            console.print(f"Error: {error}")
            console.print(f"Diagnostic log: {event_log_path()}")
        output = buffer.getvalue().strip() or f"{name}: done"
        self.call_from_thread(self._show_output, name, output)

    def _show_output(self, name: str, output: str) -> None:
        if name == "logs":
            self.log_view = True
            self.query_one("#action-menu", Static).display = False
            self.query_one("#commands-title", Label).update("Recent daemon and IDALib worker logs")
            self.query_one("#command-row", Horizontal).display = False
            log_output = self.query_one("#output", Static)
            log_output.display = True
            log_output.styles.height = 14
            log_output.update(Text("\n".join(output.splitlines()[-14:]), style="#aeb8bc"))
            self.active_action = None
            self._set_activity("Logs ready", waiting=True, hint="(esc to return)")
            self._render_actions()
            return
        lines = output.splitlines()[-2:]
        result = Text(f"{name.upper()}  ", style="bold #d5caa1")
        result.append("\n".join(lines), style="#8d999e")
        self.query_one("#output", Static).update(result)
        self.active_action = None
        self._set_activity()
        self._render_actions()
        self.action_refresh_status()
