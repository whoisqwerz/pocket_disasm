import os
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from pocket_disasm.daemon import process_is_running, read_pidfile, remove_pidfile, write_pidfile


class DaemonTests(unittest.TestCase):
    @unittest.skipUnless(os.name == "nt", "Windows process probe")
    def test_windows_process_probe_handles_live_and_stale_pids(self):
        self.assertTrue(process_is_running(os.getpid()))
        self.assertFalse(process_is_running(0xFFFFFFFE))

    def test_pidfile_round_trip(self):
        with tempfile.TemporaryDirectory() as directory:
            target = Path(directory) / "pocket-disasm.pid"
            write_pidfile(12345, target)
            self.assertEqual(read_pidfile(target), 12345)
            remove_pidfile(target)
            self.assertIsNone(read_pidfile(target))

    def test_write_pidfile_defaults_to_current_process(self):
        with tempfile.TemporaryDirectory() as directory:
            target = Path(directory) / "pocket-disasm.pid"
            write_pidfile(path=target)
            self.assertEqual(read_pidfile(target), os.getpid())


if __name__ == "__main__":
    unittest.main()
