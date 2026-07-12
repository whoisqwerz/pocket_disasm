import os
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from pocket_disasm.config import Settings, discover_ida_dir, idalib_filename, is_ida_dir


class ConfigTests(unittest.TestCase):
    def test_settings_round_trip(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "config.json"
            original = Settings(ida_dir="X:/IDA", port=9000, base_port=9001, max_workers=12)
            original.save(path)
            self.assertEqual(Settings.load(path), original)

    def test_invalid_settings_fall_back(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "config.json"
            path.write_text("not json", encoding="utf-8")
            self.assertEqual(Settings.load(path), Settings())

    def test_migrates_reserved_legacy_ports(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "config.json"
            path.write_text('{"port":8745,"base_port":8750}', encoding="utf-8")
            settings = Settings.load(path)
            self.assertEqual(settings.port, 13339)
            self.assertEqual(settings.base_port, 13400)

    def test_discovers_idadir_environment(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / idalib_filename()).write_bytes(b"")
            with patch.dict(os.environ, {"IDADIR": str(root)}):
                self.assertEqual(discover_ida_dir(), root.resolve())

    def test_rejects_directory_without_idalib(self):
        with tempfile.TemporaryDirectory() as directory:
            self.assertFalse(is_ida_dir(directory))


if __name__ == "__main__":
    unittest.main()
