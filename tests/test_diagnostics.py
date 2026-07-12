import json
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from pocket_disasm.diagnostics import append_event, append_exception, tail_file


class DiagnosticsTests(unittest.TestCase):
    def test_events_and_exceptions_are_persisted(self):
        with tempfile.TemporaryDirectory() as directory:
            target = Path(directory) / "events.log"
            with patch("pocket_disasm.diagnostics.event_log_path", return_value=target):
                append_event("info", "test.started", value=7)
                try:
                    raise RuntimeError("diagnostic failure")
                except RuntimeError as error:
                    append_exception("test.failed", error)
            records = [json.loads(line) for line in tail_file(target, 10)]
            self.assertEqual(records[0]["event"], "test.started")
            self.assertEqual(records[1]["error_type"], "RuntimeError")
            self.assertIn("diagnostic failure", records[1]["traceback"])


if __name__ == "__main__":
    unittest.main()
