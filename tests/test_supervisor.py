import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from pocket_disasm.supervisor import MultiSessionSupervisor


class SupervisorTests(unittest.TestCase):
    def test_starts_eight_independent_workers(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            binaries = []
            for index in range(8):
                binary = root / f"sample-{index}.exe"
                binary.write_bytes(b"MZ")
                binaries.append(binary)

            supervisor = MultiSessionSupervisor(root, base_port=18000, max_workers=8, workspace_root=root / "sessions")
            with patch("pocket_disasm.backend.BackendProcess.start", return_value=None):
                sessions = [supervisor.open_async(binary) for binary in binaries]
                supervisor.wait_until_settled(timeout=2)

            self.assertEqual(len(sessions), 8)
            self.assertEqual(len({session.port for session in sessions}), 8)
            self.assertEqual(len({id(session.backend) for session in sessions}), 8)
            self.assertTrue(all(session.backend.log_path == session.workspace / "worker.log" for session in sessions))
            self.assertTrue(all(session.state == "ready" for session in sessions))
            supervisor.close_all()

    def test_enforces_worker_capacity(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            files = [root / f"sample-{index}.exe" for index in range(3)]
            for file in files:
                file.write_bytes(b"MZ")
            supervisor = MultiSessionSupervisor(root, base_port=18100, max_workers=2, workspace_root=root / "sessions")
            with patch("pocket_disasm.backend.BackendProcess.start", return_value=None):
                supervisor.open_async(files[0])
                supervisor.open_async(files[1])
                with self.assertRaisesRegex(RuntimeError, "Worker limit"):
                    supervisor.open_async(files[2])
                supervisor.wait_until_settled(timeout=2)
                supervisor.close_all()

    def test_same_source_uses_isolated_worker_copies(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            binary = root / "shared.exe"
            binary.write_bytes(b"MZ-shared")
            supervisor = MultiSessionSupervisor(
                root,
                base_port=18200,
                max_workers=2,
                workspace_root=root / "sessions",
            )
            with patch("pocket_disasm.backend.BackendProcess.start", return_value=None) as start:
                first = supervisor.open_async(binary, "first")
                second = supervisor.open_async(binary, "second")
                supervisor.wait_until_settled(timeout=2)
                worker_paths = [call.args[0] for call in start.call_args_list]
                self.assertEqual(len(set(worker_paths)), 2)
                self.assertTrue(all(path.read_bytes() == b"MZ-shared" for path in worker_paths))
                self.assertNotEqual(first.workspace, second.workspace)
                supervisor.close_all()

if __name__ == "__main__":
    unittest.main()
