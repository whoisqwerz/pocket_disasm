import tempfile
import unittest
from pathlib import Path
from unittest.mock import MagicMock, patch

from pocket_disasm.updates import check_for_update, install_update


class UpdateTests(unittest.TestCase):
    def test_detects_newer_repository_version(self):
        response = MagicMock()
        response.__enter__.return_value.read.return_value = b'__version__ = "1.4.0"\n'
        with patch("pocket_disasm.updates.urlopen", return_value=response):
            info = check_for_update("1.3.9")
        self.assertTrue(info.available)
        self.assertEqual(info.latest, "1.4.0")

    def test_equal_version_needs_no_update(self):
        response = MagicMock()
        response.__enter__.return_value.read.return_value = b'__version__ = "1.4.0"\n'
        with patch("pocket_disasm.updates.urlopen", return_value=response):
            info = check_for_update("1.4.0")
        self.assertFalse(info.available)

    def test_installer_persists_output(self):
        result = MagicMock(returncode=0, stdout="Successfully installed pocket-disasm", stderr="")
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            with (
                patch("pocket_disasm.updates.subprocess.run", return_value=result),
                patch("pocket_disasm.updates.runtime_dir", return_value=root),
            ):
                path = Path(install_update())
            self.assertIn("Successfully installed", path.read_text(encoding="utf-8"))


if __name__ == "__main__":
    unittest.main()
