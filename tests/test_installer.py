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
        self.assertIn('Join-Path $ProductRoot "installer.log"', script)
        self.assertIn("Start-Transcript", script)

    def test_unpublished_mcp_version_uses_pinned_upstream_archive(self):
        project = (ROOT / "pyproject.toml").read_text(encoding="utf-8")
        self.assertIn("mrexodia/ida-pro-mcp/archive/ab7a648d344d9c7a368634a88abed69fee296c09.zip", project)
        self.assertNotIn('"ida-pro-mcp==2.0.0"', project)


if __name__ == "__main__":
    unittest.main()
