import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

from pocket_disasm.router import UnifiedMcpRouter
from pocket_disasm.supervisor import MultiSessionSupervisor


class FakeServer:
    def __init__(self):
        self.tools = SimpleNamespace(methods={})
        self.registry = SimpleNamespace(methods={})
        self.require_streamable_http_session = False
        self.context_id = "http:test-client"
        self.registry.methods["tools/list"] = self._tools_list
        self.registry.methods["tools/call"] = self._tools_call
        self.registry.methods["resources/read"] = lambda uri, _meta=None: {"contents": []}

    def tool(self, function):
        self.tools.methods[function.__name__] = function
        return function

    def get_current_transport_session_id(self):
        return self.context_id

    def _tools_list(self, _meta=None):
        tools = [
            {"name": "decompile", "inputSchema": {"type": "object", "properties": {"addr": {"type": "string"}}, "required": ["addr"]}},
            {"name": "idalib_open", "inputSchema": {"type": "object", "properties": {}}},
        ]
        tools.extend(
            {"name": name, "inputSchema": {"type": "object", "properties": {}}}
            for name in self.tools.methods
        )
        return {"tools": tools}

    def _tools_call(self, name, arguments=None, _meta=None):
        try:
            result = self.tools.methods[name](**(arguments or {}))
            return {"content": [{"type": "text", "text": str(result)}], "structuredContent": result, "isError": False}
        except Exception as error:
            return {"content": [{"type": "text", "text": str(error)}], "isError": True}

    def serve(self, **kwargs):
        return None

    def stop(self):
        return None


class FakeWorkerClient:
    def __init__(self):
        self.calls = []

    def call_tool_raw(self, name, arguments):
        self.calls.append((name, arguments))
        return {"content": [{"type": "text", "text": "ok"}], "structuredContent": {"ok": True}, "isError": False}


class RouterTests(unittest.TestCase):
    def test_exposes_one_catalog_with_database_routing(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            binary = root / "sample.exe"
            binary.write_bytes(b"MZ")
            supervisor = MultiSessionSupervisor(root, base_port=18300, max_workers=2, workspace_root=root / "sessions")
            with patch("pocket_disasm.backend.BackendProcess.start", return_value=None):
                session = supervisor.open_async(binary, "sample")
                supervisor.wait_until_settled(timeout=2)

            router = UnifiedMcpRouter(supervisor, server=FakeServer())
            catalog = router._tools_list()["tools"]
            decompile = next(tool for tool in catalog if tool["name"] == "decompile")
            self.assertIn("database", decompile["inputSchema"]["properties"])
            self.assertNotIn("idalib_open", {tool["name"] for tool in catalog})
            self.assertIn("idb_open", {tool["name"] for tool in catalog})

            client = FakeWorkerClient()
            router.client_for = lambda selected: client
            response = router._tools_call("decompile", {"addr": "0x401000", "database": session.name})
            self.assertFalse(response["isError"])
            self.assertEqual(client.calls, [("decompile", {"addr": "0x401000"})])
            supervisor.close_all()

    def test_selected_database_is_scoped_to_mcp_client(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            first = root / "first.exe"
            second = root / "second.exe"
            first.write_bytes(b"MZ")
            second.write_bytes(b"MZ")
            supervisor = MultiSessionSupervisor(root, base_port=18400, max_workers=2, workspace_root=root / "sessions")
            with patch("pocket_disasm.backend.BackendProcess.start", return_value=None):
                a = supervisor.open_async(first, "first")
                b = supervisor.open_async(second, "second")
                supervisor.wait_until_settled(timeout=2)
            server = FakeServer()
            router = UnifiedMcpRouter(supervisor, server=server)
            server.context_id = "http:agent-a"
            router.bind_current(a.name)
            server.context_id = "http:agent-b"
            router.bind_current(b.name)
            self.assertEqual(router.selected_current(), "second")
            server.context_id = "http:agent-a"
            self.assertEqual(router.selected_current(), "first")
            supervisor.close_all()


if __name__ == "__main__":
    unittest.main()
