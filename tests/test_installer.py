import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]


class InstallerTests(unittest.TestCase):
    def test_windows_bootstrap_files_are_present(self):
        self.assertTrue((ROOT / "install.cmd").is_file())
        self.assertTrue((ROOT / "install.ps1").is_file())

    def test_installer_creates_global_pocket_launcher(self):
        script = (ROOT / "install.ps1").read_text(encoding="utf-8")
        self.assertIn('Join-Path $BinRoot "pocket.cmd"', script)
        self.assertIn("%LOCALAPPDATA%\\PocketDisasm\\venv\\Scripts\\python.exe", script)
        self.assertIn('Update-UserPath $BinRoot $true', script)

    def test_installer_supports_repair_headless_and_uninstall(self):
        script = (ROOT / "install.ps1").read_text(encoding="utf-8")
        self.assertIn("[switch]$NoLaunch", script)
        self.assertIn("[switch]$Uninstall", script)
        self.assertIn('[string]$IdaDir', script)


if __name__ == "__main__":
    unittest.main()
