from pathlib import Path
import subprocess
import tempfile
import unittest

from tools.incoming_event import InvalidEvent, validate


class IncomingEventTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.root = Path(self.temp.name)
        self.repo = self.root / "source"
        self.repo.mkdir()
        self.git("init", "-q", str(self.repo))
        self.git("-C", str(self.repo), "config", "user.email", "test@example.invalid")
        self.git("-C", str(self.repo), "config", "user.name", "Test")
        self.git("-C", str(self.repo), "remote", "add", "origin",
                 "https://github.com/openwrt/openwrt.git")
        (self.repo / "sample.uc").write_text("let value = 1;\n")
        self.git("-C", str(self.repo), "add", "sample.uc")
        self.git("-C", str(self.repo), "commit", "-qm", "control")
        self.control = self.git("-C", str(self.repo), "rev-parse", "HEAD")
        (self.repo / "sample.uc").write_text("let value = 2;\n")
        self.git("-C", str(self.repo), "commit", "-qam", "incoming change")
        self.source = self.git("-C", str(self.repo), "rev-parse", "HEAD")
        self.control_repo = self.root / "control"
        subprocess.check_call(["git", "clone", "-q", str(self.repo), str(self.control_repo)])
        self.git("-C", str(self.control_repo), "remote", "set-url", "origin",
                 "https://github.com/openwrt/openwrt.git")
        self.git("-C", str(self.control_repo), "checkout", "-q", self.control)
        self.event = {
            "schema": "incoming-event-v1",
            "repository": "openwrt",
            "event_type": "manual_sha_drill",
            "pr_number": 123,
            "event_time": "2026-11-24T12:00:00Z",
            "source_sha": self.source,
            "control_sha": self.control,
        }

    def tearDown(self):
        self.temp.cleanup()

    @staticmethod
    def git(*args):
        return subprocess.check_output(["git", *args], text=True).strip()

    def test_resolves_full_commit_and_tree_and_labels_limited_status(self):
        result = validate(self.event, self.repo, self.control_repo)
        self.assertEqual(result["source"]["commit"], self.source)
        self.assertEqual(result["control"]["commit"], self.control)
        self.assertEqual(result["status"], "identities_resolved_only")
        self.assertNotEqual(result["source"]["tree"], result["control"]["tree"])

    def test_rejects_branch_name_instead_of_full_commit(self):
        bad = dict(self.event, source_sha="main")
        with self.assertRaisesRegex(InvalidEvent, "full 40-character"):
            validate(bad, self.repo, self.control_repo)

    def test_rejects_mismatched_repository_origin(self):
        bad = dict(self.event, repository="luci")
        with self.assertRaisesRegex(InvalidEvent, "origin does not match"):
            validate(bad, self.repo, self.control_repo)

    def test_rejects_same_source_and_control(self):
        bad = dict(self.event, control_sha=self.source)
        with self.assertRaisesRegex(InvalidEvent, "must differ"):
            validate(bad, self.repo, self.control_repo)

    def test_rejects_missing_commit(self):
        absent = "0" * 40
        bad = dict(self.event, source_sha=absent)
        with self.assertRaisesRegex(InvalidEvent, "git rev-parse"):
            validate(bad, self.repo, self.control_repo)

    def test_rejects_invalid_event_metadata(self):
        bad = dict(self.event, pr_number=0)
        with self.assertRaisesRegex(InvalidEvent, "positive integer"):
            validate(bad, self.repo, self.control_repo)

    def test_rejects_dirty_control(self):
        (self.control_repo / "extra").write_text("uncommitted\n")
        with self.assertRaisesRegex(InvalidEvent, "checkout is dirty"):
            validate(self.event, self.repo, self.control_repo)


if __name__ == "__main__":
    unittest.main()
