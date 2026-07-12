import json
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from pocket_disasm.config import Settings
from pocket_disasm.integrations import (
    integrate_targets,
    integration_status,
    remember_integrations,
    update_integration_endpoints,
)


class IntegrationTests(unittest.TestCase):
    def test_global_scope_uses_user_config_paths(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            with patch("pathlib.Path.home", return_value=root), patch.dict(
                "os.environ",
                {"USERPROFILE": directory, "APPDATA": str(root / "AppData" / "Roaming")},
            ):
                results = integrate_targets(
                    ["claude", "cursor", "vscode"],
                    Settings(port=19999),
                    project_dir=root / "project",
                    scope="global",
                )
            paths = {result.target: result.path for result in results}
            self.assertEqual(paths["claude"], root / ".claude.json")
            self.assertEqual(paths["cursor"], root / ".cursor" / "mcp.json")
            self.assertEqual(paths["vscode"], root / "AppData" / "Roaming" / "Code" / "User" / "mcp.json")

    def test_registered_configs_follow_port_changes(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            registry = root / "integrations.json"
            old = Settings(port=13339)
            new = Settings(port=14444)
            with patch("pathlib.Path.home", return_value=root), patch.dict("os.environ", {"USERPROFILE": directory}):
                results = integrate_targets(["all"], old, project_dir=root)
                remember_integrations(results, registry)
                changed = update_integration_endpoints(
                    old,
                    new,
                    project_dir=root,
                    registry_path=registry,
                )
            self.assertEqual(len(changed), 5)
            for path in changed:
                text = path.read_text(encoding="utf-8")
                self.assertIn("http://127.0.0.1:14444/mcp", text)
                self.assertNotIn("http://127.0.0.1:13339/mcp", text)

    def test_status_reports_integrated_agents(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            settings = Settings(port=18888)
            with patch("pathlib.Path.home", return_value=root), patch.dict("os.environ", {"USERPROFILE": directory}):
                integrate_targets(["all"], settings, project_dir=root)
                status = integration_status(settings, project_dir=root)
            self.assertTrue(all(status.values()))

    def test_project_agent_configs_are_idempotent(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            settings = Settings(port=15555)
            first = integrate_targets(["claude", "cursor", "vscode"], settings, project_dir=root)
            second = integrate_targets(["claude", "cursor", "vscode"], settings, project_dir=root)

            self.assertTrue(all(result.changed for result in first))
            self.assertFalse(any(result.changed for result in second))
            self.assertEqual(
                json.loads((root / ".mcp.json").read_text(encoding="utf-8"))["mcpServers"]["pocket-disasm"],
                {"type": "http", "url": "http://127.0.0.1:15555/mcp"},
            )
            self.assertEqual(
                json.loads((root / ".vscode" / "mcp.json").read_text(encoding="utf-8"))["servers"]["pocket-disasm"],
                {"type": "http", "url": "http://127.0.0.1:15555/mcp"},
            )

    def test_windsurf_uses_user_config_file(self):
        with tempfile.TemporaryDirectory() as directory:
            with patch.dict("os.environ", {"USERPROFILE": directory}):
                result = integrate_targets(["windsurf"], Settings(port=16666))[0]
            data = json.loads(result.path.read_text(encoding="utf-8"))
            self.assertEqual(data["mcpServers"]["pocket-disasm"], {"serverUrl": "http://127.0.0.1:16666/mcp"})

    def test_codex_config_replaces_existing_block(self):
        with tempfile.TemporaryDirectory() as directory:
            home = Path(directory)
            config = home / ".codex" / "config.toml"
            config.parent.mkdir()
            config.write_text(
                '[mcp_servers.other]\nurl = "http://example/mcp"\n\n'
                '[mcp_servers.pocket-disasm]\nurl = "old"\n\n'
                '[mcp_servers.pocket-disasm.tools.idb_open]\napproval_mode = "approve"\n',
                encoding="utf-8",
            )
            with patch("pathlib.Path.home", return_value=home):
                integrate_targets(["codex"], Settings(port=17777))
            text = config.read_text(encoding="utf-8")
            self.assertIn('[mcp_servers.other]\nurl = "http://example/mcp"', text)
            self.assertEqual(text.count("[mcp_servers.pocket-disasm]"), 1)
            self.assertIn('url = "http://127.0.0.1:17777/mcp"', text)
            self.assertIn("[mcp_servers.pocket-disasm.tools.decompile]", text)


if __name__ == "__main__":
    unittest.main()
