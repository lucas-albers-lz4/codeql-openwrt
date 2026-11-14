"""The legacy luci oracle emitter must not overwrite union artifacts."""

from __future__ import annotations

import subprocess
import sys
import unittest
from pathlib import Path

REPO = Path(__file__).resolve().parents[2]
SHARED_ARTIFACTS = (
    REPO / "policy" / "grants.json",
    REPO / "policy" / "policy_decisions.json",
)

if str(REPO) not in sys.path:
    sys.path.insert(0, str(REPO))

from policy.oracle import emit_artifacts  # noqa: E402


class LegacyOracleEmitTests(unittest.TestCase):
    def snapshot_shared_artifacts(self) -> dict[Path, bytes]:
        return {path: path.read_bytes() for path in SHARED_ARTIFACTS}

    def assert_shared_artifacts_unchanged(self, before: dict[Path, bytes]) -> None:
        self.assertEqual(
            {path: path.read_bytes() for path in SHARED_ARTIFACTS},
            before,
        )

    def test_direct_legacy_emitter_refuses_shared_paths(self) -> None:
        before = self.snapshot_shared_artifacts()

        with self.assertRaisesRegex(RuntimeError, "python3 -m policy emit"):
            emit_artifacts()

        self.assert_shared_artifacts_unchanged(before)

    def test_legacy_module_commands_leave_shared_artifacts_unchanged(self) -> None:
        before = self.snapshot_shared_artifacts()

        for args in ("emit",):
            with self.subTest(args=args):
                result = subprocess.run(
                    [sys.executable, "-m", "policy.oracle", *args.split()],
                    cwd=REPO,
                    capture_output=True,
                    text=True,
                    check=False,
                )
                self.assertEqual(result.returncode, 2)
                self.assertIn("python3 -m policy emit", result.stderr)
                self.assert_shared_artifacts_unchanged(before)

        with self.subTest(args="<no arguments>"):
            result = subprocess.run(
                [sys.executable, "-m", "policy.oracle"],
                cwd=REPO,
                capture_output=True,
                text=True,
                check=False,
            )
            self.assertEqual(result.returncode, 2)
            self.assertIn("python3 -m policy emit", result.stderr)
            self.assert_shared_artifacts_unchanged(before)


if __name__ == "__main__":
    unittest.main()
