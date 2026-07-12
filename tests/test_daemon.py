import os
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from pocket_disasm.daemon import read_pidfile, remove_pidfile, write_pidfile


class DaemonTests(unittest.TestCase):
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
