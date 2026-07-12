from __future__ import annotations

import json
import shlex
import threading
from typing import Annotated, Any

from .supervisor import MultiSessionSupervisor, WorkerSession
from .transport import McpHttpClient, McpTransportError


_ACTIVE_ROUTER: "UnifiedMcpRouter | None" = None


def _router() -> "UnifiedMcpRouter":
    if _ACTIVE_ROUTER is None:
        raise RuntimeError("Unified MCP router is not initialized")
    return _ACTIVE_ROUTER


def idb_open(
    input_path: Annotated[str, "Local path to the binary to analyze"],
    session_id: Annotated[str, "Preferred session/database identifier"] = "",
    wait: Annotated[bool, "Wait until IDA auto-analysis and MCP startup complete"] = False,
) -> dict:
    """Create an independent IDALib worker for a binary and select it for this MCP client."""
    router = _router()
    session = router.supervisor.open_async(input_path, session_id)
    router.bind_current(session.name)
    if wait:
        router.supervisor.wait_session(session.name)
    return session.as_dict()


def idb_list() -> dict:
    """List every binary session, its state, process and selected status."""
    router = _router()
    selected = router.selected_current()
    sessions = []
    for session in router.supervisor.list_sessions():
        item = session.as_dict()
        item["selected"] = session.name == selected
        sessions.append(item)
    return {"sessions": sessions, "count": len(sessions), "selected": selected}


def idb_select(
    database: Annotated[str, "Session/database identifier returned by idb_open"],
) -> dict:
    """Select the default database for subsequent tool and resource calls by this MCP client."""
    router = _router()
    session = router.require_session(database, ready=False)
    router.bind_current(session.name)
    return {"selected": session.name, "session": session.as_dict()}


def idb_close(
    database: Annotated[str, "Session/database identifier to stop"],
) -> dict:
    """Stop one IDALib worker and release its process."""
    router = _router()
    closed = router.close_session(database)
    return {"success": closed, "database": database}


def idb_health(
    database: Annotated[str, "Session/database identifier; selected database when omitted"] = "",
) -> dict:
    """Return readiness and process health for a binary session."""
    router = _router()
    session = router.require_session(database or None, ready=False)
    return session.as_dict()


def idb_wait(
    database: Annotated[str, "Session/database identifier; selected database when omitted"] = "",
    timeout: Annotated[float, "Maximum seconds to wait"] = 300.0,
) -> dict:
    """Wait for one worker to finish startup and IDA auto-analysis."""
    router = _router()
    try:
        session = router.require_session(database or None, ready=False)
        router.supervisor.wait_session(session.name, timeout=timeout)
        return session.as_dict()
    except Exception as error:
        return {"database": database or router.selected_current(), "state": "failed", "error": str(error)}


def idb_save(
    database: Annotated[str, "Session/database identifier; selected database when omitted"] = "",
    path: Annotated[str, "Optional destination IDB path"] = "",
) -> dict:
    """Save a worker's current IDA database."""
    router = _router()
    session = router.require_session(database or None, ready=True)
    result = router.client_for(session).call_tool("idalib_save", {"path": path})
    return {"database": session.name, "result": result}


def idb_logs(
    database: Annotated[str, "Session/database identifier"],
    tail: Annotated[int, "Maximum recent log lines"] = 100,
) -> dict:
    """Read recent startup and IDALib log lines for a session."""
    session = _router().require_session(database, ready=False)
    limit = max(1, min(int(tail), 300))
    return {"database": session.name, "lines": list(session.backend.logs)[-limit:]}


class UnifiedMcpRouter:
    """One public MCP endpoint routing each database to an independent IDALib process."""

    MANAGEMENT_TOOLS = {
        "idb_open",
        "idb_list",
        "idb_select",
        "idb_close",
        "idb_health",
        "idb_wait",
        "idb_save",
        "idb_logs",
    }
    WORKER_MANAGEMENT_TOOLS = {
        "idalib_open",
        "idalib_close",
        "idalib_switch",
        "idalib_unbind",
        "idalib_list",
        "idalib_current",
        "idalib_save",
        "idalib_health",
        "idalib_warmup",
    }

    def __init__(self, supervisor: MultiSessionSupervisor, server: Any | None = None) -> None:
        global _ACTIVE_ROUTER
        if server is None:
            import idapro
            from ida_pro_mcp.ida_mcp import MCP_SERVER

            server = MCP_SERVER
        self.supervisor = supervisor
        self.server = server
        self._clients: dict[str, McpHttpClient] = {}
        self._bindings: dict[str, str] = {}
        self._lock = threading.RLock()

        for function in (idb_open, idb_list, idb_select, idb_close, idb_health, idb_wait, idb_save, idb_logs):
            self.server.tool(function)

        self._original_tools_list = self.server.registry.methods["tools/list"]
        self._original_tools_call = self.server.registry.methods["tools/call"]
        self._original_resources_read = self.server.registry.methods["resources/read"]
        self.server.registry.methods["tools/list"] = self._tools_list
        self.server.registry.methods["tools/call"] = self._tools_call
        self.server.registry.methods["resources/read"] = self._resources_read
        self.server.require_streamable_http_session = True
        _ACTIVE_ROUTER = self

    @property
    def endpoint(self) -> str:
        return getattr(self, "_endpoint", "")

    def _context_id(self) -> str:
        return self.server.get_current_transport_session_id() or "shared:fallback"

    def bind_current(self, database: str) -> None:
        with self._lock:
            self._bindings[self._context_id()] = database

    def selected_current(self) -> str | None:
        with self._lock:
            return self._bindings.get(self._context_id())

    def require_session(self, database: str | None, *, ready: bool) -> WorkerSession:
        name = database or self.selected_current()
        if not name:
            raise RuntimeError("No database selected. Call idb_open or idb_select first, or pass database=...")
        session = self.supervisor.get_session(name)
        if session is None or session.state == "closed":
            raise RuntimeError(f"Database session not found: {name}")
        if session.state == "failed":
            raise RuntimeError(session.error or f"Database session failed: {name}")
        if ready and session.state != "ready":
            raise RuntimeError(f"Database session {name!r} is {session.state}; call idb_wait or idb_health")
        return session

    def client_for(self, session: WorkerSession) -> McpHttpClient:
        with self._lock:
            client = self._clients.get(session.name)
            if client is None:
                client = McpHttpClient(f"{session.endpoint}?ext=dbg")
                self._clients[session.name] = client
            return client

    def close_session(self, database: str) -> bool:
        closed = self.supervisor.close(database)
        if closed:
            with self._lock:
                self._clients.pop(database, None)
                stale = [key for key, value in self._bindings.items() if value == database]
                for key in stale:
                    self._bindings.pop(key, None)
        return closed

    @staticmethod
    def _tool_error(message: str) -> dict:
        return {"content": [{"type": "text", "text": message}], "isError": True}

    def _tools_list(self, _meta: dict | None = None) -> dict:
        result = self._original_tools_list(_meta)
        tools = []
        for tool in result.get("tools", []):
            name = tool.get("name", "")
            if name in self.WORKER_MANAGEMENT_TOOLS:
                continue
            if name not in self.MANAGEMENT_TOOLS:
                schema = tool.setdefault("inputSchema", {"type": "object", "properties": {}})
                properties = schema.setdefault("properties", {})
                properties["database"] = {
                    "type": "string",
                    "description": "Target database/session id. Omit to use the session selected by idb_open/idb_select.",
                }
            tools.append(tool)
        return {"tools": tools}

    def _tools_call(
        self,
        name: str,
        arguments: dict | None = None,
        _meta: dict | None = None,
    ) -> dict:
        if name in self.MANAGEMENT_TOOLS:
            return self._original_tools_call(name, arguments, _meta)
        if name in self.WORKER_MANAGEMENT_TOOLS:
            return self._tool_error(f"Use idb_open/idb_select/idb_close through the unified supervisor, not {name}")
        routed = dict(arguments or {})
        database = routed.pop("database", None)
        try:
            session = self.require_session(database, ready=True)
            return self.client_for(session).call_tool_raw(name, routed)
        except (RuntimeError, McpTransportError) as error:
            return self._tool_error(str(error))

    def _resources_read(self, uri: str, _meta: dict | None = None) -> dict:
        try:
            session = self.require_session(None, ready=True)
            return self.client_for(session).resource_read_raw(uri)
        except (RuntimeError, McpTransportError) as error:
            return {
                "contents": [{"uri": uri, "mimeType": "application/json", "text": json.dumps({"error": str(error)})}],
                "isError": True,
            }

    def serve(self, host: str, port: int, *, background: bool) -> None:
        self._endpoint = f"http://{host}:{port}/mcp"
        self.server.serve(host=host, port=port, background=background)

    def stop(self) -> None:
        self.server.stop()

    def codex_config(self) -> str:
        return f'[mcp_servers.pocket-disasm]\nurl = "{self.endpoint}"'

    def json_config(self) -> str:
        return json.dumps({"mcpServers": {"pocket-disasm": {"url": self.endpoint}}}, indent=2)


def run_router_console(router: UnifiedMcpRouter) -> None:
    print("Pocket Disasm unified MCP supervisor")
    print(f"Public endpoint: {router.endpoint}")
    print(f"Capacity: {router.supervisor.max_workers} independent binary sessions")
    print("The LLM can manage sessions with idb_open, idb_list, idb_select and idb_close.")
    print("Console commands: open, list, close, codex, json, logs, help, quit")
    while True:
        try:
            line = input("pocket> ").strip()
        except EOFError:
            break
        if not line:
            continue
        try:
            parts = [part.strip('"') for part in shlex.split(line, posix=False)]
            command = parts[0].lower()
            if command in ("quit", "exit"):
                break
            if command in ("list", "ls"):
                router.supervisor.print_status()
            elif command == "open":
                if len(parts) < 2:
                    print("Usage: open <binary-path> [database-id]")
                    continue
                session = router.supervisor.open_async(parts[1], parts[2] if len(parts) > 2 else "")
                print(f"Starting database {session.name} in the background")
            elif command == "close":
                if len(parts) != 2:
                    print("Usage: close <database-id>")
                else:
                    print("Closing" if router.close_session(parts[1]) else "Database not found")
            elif command == "codex":
                print(router.codex_config())
            elif command == "json":
                print(router.json_config())
            elif command == "logs":
                if len(parts) != 2:
                    print("Usage: logs <database-id>")
                    continue
                session = router.supervisor.get_session(parts[1])
                print("\n".join(session.backend.logs) if session else "Database not found")
            elif command == "help":
                print("open <path> [id]  Create an independent binary session")
                print("list              Show all session states")
                print("close <id>        Stop a session")
                print("codex             Print the single Codex MCP configuration")
                print("json              Print generic MCP client configuration")
                print("logs <id>         Show worker logs")
                print("quit              Stop the supervisor")
            else:
                print(f"Unknown command: {command}. Type help.")
        except Exception as error:
            print(f"Error: {error}")
