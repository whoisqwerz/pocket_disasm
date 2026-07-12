import unittest
from io import StringIO
from importlib import resources
from types import SimpleNamespace
from unittest.mock import patch

from rich.console import Console
from textual.widgets import Input, Static

from pocket_disasm.ui import PocketDisasmApp, _start, load_art, parse_colored_ascii_html
from pocket_disasm.updates import UpdateInfo


class UiTests(unittest.TestCase):
    def test_start_action_records_startup_events(self):
        offline = SimpleNamespace(running=False, endpoint="http://127.0.0.1:13339/mcp", pid=None)
        online = SimpleNamespace(running=True, endpoint="http://127.0.0.1:13339/mcp", pid=123)
        process = SimpleNamespace(pid=123, poll=lambda: None)
        console = Console(file=StringIO(), force_terminal=False)
        with (
            patch("pocket_disasm.ui.inspect_daemon", side_effect=[offline, online]),
            patch("pocket_disasm.ui.start_daemon", return_value=process),
            patch("pocket_disasm.ui.append_event") as event,
        ):
            _start(console)
        names = [call.args[1] for call in event.call_args_list]
        self.assertEqual(names, ["tui.daemon.start.requested", "tui.daemon.start.spawned", "tui.daemon.start.ready"])

    def test_parse_colored_ascii_html_keeps_rgb_spans(self):
        text = parse_colored_ascii_html(
            '<pre><span style="color:rgb(0,0,0)">-</span>'
            '<span style="color:rgb(255,122,24)">I</span></pre>'
        )

        self.assertEqual(text.plain, "I")
        self.assertTrue(any(span.style == "rgb(255,122,24)" for span in text.spans))

    def test_parse_colored_ascii_html_crops_large_art(self):
        html = "\n".join('<span style="color:rgb(1,2,3)">abcdef</span>' for _ in range(5))
        text = parse_colored_ascii_html(html, max_width=3, max_lines=2)

        self.assertEqual(text.plain, "abc\nabc")

    def test_bundled_ascii_art_is_packaged(self):
        assets = resources.files("pocket_disasm").joinpath("assets")
        self.assertTrue(assets.joinpath("ida_colored.html").is_file())
        self.assertTrue(assets.joinpath("ida_compact.html").is_file())
        text = load_art(width=80, lines=18)
        self.assertGreater(len(text.plain.strip()), 0)
        self.assertGreater(len(text.spans), 0)
        self.assertLessEqual(max(map(len, text.plain.splitlines())), 43)


class TuiTests(unittest.IsolatedAsyncioTestCase):
    async def test_available_update_appears_as_action(self):
        app = PocketDisasmApp()
        async with app.run_test(size=(100, 32)) as pilot:
            await pilot.pause()
            app._show_update(UpdateInfo("1.0.0", "1.1.0", True))
            await pilot.pause()
            self.assertEqual(app.action_names[-1], "update")
            self.assertIn("Update Pocket Disasm", app.query_one("#action-menu", Static).render().plain)

    async def test_ctrl_q_exits_cleanly(self):
        app = PocketDisasmApp()
        async with app.run_test(size=(100, 32)) as pilot:
            await pilot.pause()
            await pilot.press("ctrl+q")
            await pilot.pause()
            self.assertFalse(app.is_running)

    async def test_logs_replace_menu_and_escape_returns(self):
        app = PocketDisasmApp()
        async with app.run_test(size=(100, 40)) as pilot:
            await pilot.pause()
            app._show_output("logs", "line one\n[MCP] >> survey_binary\n[MCP] << survey_binary")
            await pilot.pause()
            self.assertTrue(app.log_view)
            self.assertFalse(app.query_one("#action-menu", Static).display)
            self.assertIn("survey_binary", app.query_one("#output", Static).render().plain)
            await pilot.press("escape")
            await pilot.pause()
            self.assertFalse(app.log_view)
            self.assertTrue(app.query_one("#action-menu", Static).display)

    async def test_control_center_mounts_and_focuses_action_list(self):
        app = PocketDisasmApp()
        async with app.run_test(size=(100, 32)) as pilot:
            await pilot.pause()
            actions = app.query_one("#action-menu", Static)
            self.assertIn("Start MCP router", actions.render().plain)
            self.assertIs(app.focused, app.query_one("#command-input", Input))

    async def test_agent_integration_uses_selection_list(self):
        class RecordingApp(PocketDisasmApp):
            launched = None

            def _launch_command(self, name: str, argument: str | None = None) -> None:
                self.launched = (name, argument)

        app = RecordingApp()
        async with app.run_test(size=(100, 32)) as pilot:
            await pilot.pause()
            app.action_run_named("integrate")
            await pilot.pause()
            self.assertEqual(app.agent_selection, 0)
            self.assertIn("Claude Code", app.query_one("#action-menu", Static).render().plain)
            self.assertFalse(app.query_one("#command-row").display)
            self.assertEqual(len(app.screen_stack), 1)
            await pilot.press("down", "enter")
            await pilot.pause()
            self.assertEqual(app.scope_target, "claude")
            self.assertEqual(app.scope_selection, 0)
            self.assertIn("Global", app.query_one("#action-menu", Static).render().plain)
            await pilot.press("enter")
            await pilot.pause()
            self.assertEqual(app.launched, ("integrate", "claude|global"))

    async def test_configure_ida_shows_path_and_confirmation_feedback(self):
        app = PocketDisasmApp()
        async with app.run_test(size=(100, 32)) as pilot:
            await pilot.pause()
            app.action_run_named("configure")
            await pilot.pause()
            field = app.query_one("#command-input", Input)
            self.assertEqual(app.pending_input, "configure")
            self.assertTrue(field.value)
            self.assertFalse(app.query_one("#action-menu", Static).display)
            self.assertFalse(app.query_one("#commands-title", Static).display)
            activity = app.query_one("#activity-line", Static).render().plain
            self.assertIn("Configuring IDA", activity)
            self.assertIn(f"({field.value})", activity)
            self.assertIn("esc to cancel", activity)
            self.assertLess(field.region.bottom, app.size.height + 1)

    async def test_keyboard_navigation_enters_configure_mode(self):
        app = PocketDisasmApp()
        async with app.run_test(size=(100, 32)) as pilot:
            await pilot.pause()
            await pilot.press("down", "down", "down", "down", "enter")
            await pilot.pause()
            self.assertEqual(app.selected_action, 4)
            self.assertEqual(app.pending_input, "configure")
            self.assertIn("Configuring IDA", app.query_one("#activity-line", Static).render().plain)

    async def test_port_configuration_uses_current_port_and_inline_confirmation(self):
        class RecordingApp(PocketDisasmApp):
            launched = None

            def _launch_command(self, name: str, argument: str | None = None) -> None:
                self.launched = (name, argument)

        app = RecordingApp()
        async with app.run_test(size=(100, 32)) as pilot:
            await pilot.pause()
            app.action_run_named("port")
            await pilot.pause()
            field = app.query_one("#command-input", Input)
            self.assertEqual(app.pending_input, "port")
            self.assertEqual(field.value, str(app.settings.port))
            self.assertIn("Changing MCP port", app.query_one("#activity-line", Static).render().plain)
            field.value = "14444"
            await pilot.press("enter")
            await pilot.pause()
            self.assertEqual(app.launched, ("port", "14444"))

    async def test_capacity_uses_current_worker_limit(self):
        class RecordingApp(PocketDisasmApp):
            launched = None

            def _launch_command(self, name: str, argument: str | None = None) -> None:
                self.launched = (name, argument)

        app = RecordingApp()
        async with app.run_test(size=(100, 32)) as pilot:
            await pilot.pause()
            app.action_run_named("capacity")
            await pilot.pause()
            field = app.query_one("#command-input", Input)
            self.assertEqual(app.pending_input, "capacity")
            self.assertEqual(field.value, str(app.settings.max_workers))
            self.assertIn("Changing session capacity", app.query_one("#activity-line", Static).render().plain)
            field.value = "16"
            await pilot.press("enter")
            await pilot.pause()
            self.assertEqual(app.launched, ("capacity", "16"))

    async def test_escape_leaves_inline_configuration(self):
        app = PocketDisasmApp()
        async with app.run_test(size=(100, 32)) as pilot:
            await pilot.pause()
            app.action_run_named("configure")
            await pilot.pause()
            await pilot.press("escape")
            await pilot.pause()
            self.assertIsNone(app.pending_input)
            self.assertTrue(app.query_one("#action-menu", Static).display)

    async def test_activity_uses_ida_blue_tilde(self):
        app = PocketDisasmApp()
        async with app.run_test(size=(100, 32)) as pilot:
            await pilot.pause()
            app.action_run_named("configure")
            await pilot.pause()
            activity = app.query_one("#activity-line", Static).render()
            self.assertTrue(activity.plain.startswith("~ "))
            self.assertEqual(str(activity.spans[0].style), "bold #00ffff")

    async def test_empty_enter_runs_selected_action_while_input_is_focused(self):
        class RecordingApp(PocketDisasmApp):
            selected = None

            def action_run_named(self, name: str) -> None:
                self.selected = name

        app = RecordingApp()
        async with app.run_test(size=(100, 32)) as pilot:
            await pilot.pause()
            await pilot.press("enter")
            await pilot.pause()
            self.assertEqual(app.selected, "start")


if __name__ == "__main__":
    unittest.main()
