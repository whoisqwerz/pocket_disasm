import tempfile
import unittest
from pathlib import Path
from pocket_disasm.backend import BackendProcess, _friendly_startup_error


class BackendTests(unittest.TestCase):
    def test_command_preserves_stock_idalib_server(self):
        with tempfile.TemporaryDirectory() as directory:
            backend = BackendProcess(Path(directory), port=9123, unsafe=True, verbose=True)
            command = backend.command(Path(directory) / "sample.exe")
        self.assertIn("ida_pro_mcp.idalib_server", command)
        self.assertIn("--unsafe", command)
        self.assertIn("--verbose", command)
        self.assertIn("9123", command)

    def test_license_error_has_actionable_message(self):
        message = _friendly_startup_error(Path("C:/IDA"), "License not yet accepted, cannot run in batch mode")
        self.assertIn("accept the license agreement", message)
        self.assertIn("ida.exe", message)


if __name__ == "__main__":
    unittest.main()
