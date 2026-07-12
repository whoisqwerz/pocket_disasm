import json
import unittest

from pocket_disasm.transport import McpTransportError, extract_tool_result, parse_mcp_response


class TransportTests(unittest.TestCase):
    def test_parses_json_and_sse(self):
        self.assertEqual(parse_mcp_response(b'{"id":1}'), {"id": 1})
        sse = 'event: message\ndata: {"id":2,"result":{}}\n\n'
        self.assertEqual(parse_mcp_response(sse, "text/event-stream")["id"], 2)

    def test_extracts_structured_tool_result(self):
        response = {
            "content": [{"type": "text", "text": json.dumps({"value": 7})}],
            "structuredContent": {"value": 7},
            "isError": False,
        }
        self.assertEqual(extract_tool_result(response), {"value": 7})

    def test_raises_worker_tool_error(self):
        with self.assertRaisesRegex(McpTransportError, "not ready"):
            extract_tool_result({"isError": True, "content": [{"type": "text", "text": "not ready"}]})


if __name__ == "__main__":
    unittest.main()
