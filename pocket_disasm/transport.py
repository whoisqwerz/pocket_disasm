from __future__ import annotations

import json
import threading
import urllib.error
import urllib.request
from typing import Any


class McpTransportError(RuntimeError):
    pass


def parse_mcp_response(body: bytes | str, content_type: str = "") -> dict:
    text = body.decode("utf-8", errors="replace") if isinstance(body, bytes) else body
    text = text.strip()
    if not text:
        return {}
    if "text/event-stream" in content_type or text.startswith(("event:", "data:")):
        messages = []
        for line in text.splitlines():
            if not line.startswith("data:"):
                continue
            data = line[5:].strip()
            if data and data != "[DONE]":
                messages.append(json.loads(data))
        return messages[-1] if messages else {}
    return json.loads(text)


def extract_tool_result(response: dict) -> Any:
    if response.get("isError"):
        content = response.get("content") or []
        message = content[0].get("text", "MCP tool failed") if content else "MCP tool failed"
        raise McpTransportError(message)
    structured = response.get("structuredContent")
    if structured is not None:
        if isinstance(structured, dict) and set(structured) == {"result"}:
            return structured["result"]
        return structured
    content = response.get("content") or []
    texts = [item.get("text", "") for item in content if item.get("type") == "text"]
    if len(texts) == 1:
        try:
            return json.loads(texts[0])
        except ValueError:
            return texts[0]
    return "\n".join(texts)


class McpHttpClient:
    """A persistent, per-worker MCP client. Calls are serialized per IDALib worker."""

    def __init__(self, endpoint: str, timeout: float = 300.0) -> None:
        self.endpoint = endpoint
        self.timeout = timeout
        self.session_id: str | None = None
        self._initialized = False
        self._request_id = 1
        self._lock = threading.RLock()

    def _post(self, payload: dict, *, allow_empty: bool = False) -> dict:
        headers = {
            "Accept": "application/json, text/event-stream",
            "Content-Type": "application/json",
        }
        if self.session_id:
            headers["Mcp-Session-Id"] = self.session_id
        request = urllib.request.Request(
            self.endpoint,
            data=json.dumps(payload).encode("utf-8"),
            headers=headers,
            method="POST",
        )
        try:
            with urllib.request.urlopen(request, timeout=self.timeout) as response:
                if response.headers.get("Mcp-Session-Id"):
                    self.session_id = response.headers["Mcp-Session-Id"]
                body = response.read()
                if allow_empty:
                    return {}
                return parse_mcp_response(body, response.headers.get("Content-Type", ""))
        except urllib.error.HTTPError as error:
            detail = error.read().decode("utf-8", errors="replace")
            raise McpTransportError(f"Worker MCP HTTP {error.code}: {detail}") from error
        except OSError as error:
            raise McpTransportError(f"Worker MCP unavailable at {self.endpoint}: {error}") from error

    def request(self, method: str, params: dict | None = None) -> Any:
        with self._lock:
            request_id = self._request_id
            self._request_id += 1
            payload = {"jsonrpc": "2.0", "id": request_id, "method": method}
            if params is not None:
                payload["params"] = params
            response = self._post(payload)
            if response.get("error"):
                error = response["error"]
                raise McpTransportError(error.get("message", str(error)))
            return response.get("result")

    def initialize(self) -> None:
        with self._lock:
            if self._initialized:
                return
            self.request(
                "initialize",
                {
                    "protocolVersion": "2025-06-18",
                    "capabilities": {},
                    "clientInfo": {"name": "pocket-disasm-router", "version": "0.2.0"},
                },
            )
            self._post({"jsonrpc": "2.0", "method": "notifications/initialized"}, allow_empty=True)
            self._initialized = True

    def call_tool_raw(self, name: str, arguments: dict | None = None) -> dict:
        self.initialize()
        result = self.request("tools/call", {"name": name, "arguments": arguments or {}})
        if not isinstance(result, dict):
            raise McpTransportError("Worker returned an invalid tools/call response")
        return result

    def call_tool(self, name: str, arguments: dict | None = None) -> Any:
        return extract_tool_result(self.call_tool_raw(name, arguments))

    def resource_read_raw(self, uri: str) -> dict:
        self.initialize()
        result = self.request("resources/read", {"uri": uri})
        if not isinstance(result, dict):
            raise McpTransportError("Worker returned an invalid resources/read response")
        return result
