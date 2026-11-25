from pathlib import Path
import os
import subprocess
import tempfile
import unittest
from unittest.mock import patch

from tools.incoming_event import (InvalidEvent, _fetch_commit_identity,
                                  fetch_base_identity, validate)


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
            "base_sha": self.control,
            "control_sha": self.control,
        }
        self.api_pr = {
            "number": 123,
            "state": "open",
            "base": {"sha": self.control, "repo": {"full_name": "openwrt/openwrt"}},
            "head": {
                "sha": self.source,
                "repo": {"full_name": "contributor/openwrt", "fork": True},
            },
        }
        self.base_tree = self.git("-C", str(self.repo), "rev-parse", f"{self.control}^{{tree}}")
        self.base_fetch = patch("tools.incoming_event.fetch_base_identity",
                                return_value={"commit": self.control, "tree": self.base_tree})
        self.mock_base_fetch = self.base_fetch.start()

    def tearDown(self):
        self.base_fetch.stop()
        self.temp.cleanup()

    @staticmethod
    def git(*args):
        return subprocess.check_output(["git", *args], text=True).strip()

    def test_resolves_full_commit_and_tree_and_labels_limited_status(self):
        result = validate(self.event, self.api_pr, self.repo, self.control_repo)
        self.assertEqual(result["source"]["commit"], self.source)
        self.assertEqual(result["base"], {"commit": self.control, "tree": self.base_tree})
        self.mock_base_fetch.assert_called_once_with("openwrt", self.control)
        self.assertEqual(result["control"]["commit"], self.control)
        self.assertEqual(result["status"], "identities_resolved_only")
        self.assertEqual(result["head_repository"], "contributor/openwrt")
        self.assertTrue(result["head_repository_is_fork"])
        self.assertNotEqual(result["source"]["tree"], result["control"]["tree"])

    def test_rejects_branch_name_instead_of_full_commit(self):
        bad = dict(self.event, source_sha="main")
        api = {**self.api_pr, "head": {**self.api_pr["head"], "sha": "main"}}
        with self.assertRaisesRegex(InvalidEvent, "full commit SHA"):
            validate(bad, api, self.repo, self.control_repo)

    def test_rejects_mismatched_repository_origin(self):
        self.git("-C", str(self.repo), "remote", "set-url", "origin",
                 "https://github.com/attacker/openwrt.git")
        with self.assertRaisesRegex(InvalidEvent, "origin does not match"):
            validate(self.event, self.api_pr, self.repo, self.control_repo)

    def test_rejects_same_source_and_control(self):
        bad = dict(self.event, control_sha=self.source)
        with self.assertRaisesRegex(InvalidEvent, "must differ"):
            validate(bad, self.api_pr, self.repo, self.control_repo)

    def test_rejects_missing_commit(self):
        absent = "0" * 40
        bad = dict(self.event, source_sha=absent)
        api = {**self.api_pr, "head": {**self.api_pr["head"], "sha": absent}}
        with self.assertRaisesRegex(InvalidEvent, "git rev-parse"):
            validate(bad, api, self.repo, self.control_repo)

    def test_rejects_invalid_event_metadata(self):
        bad = dict(self.event, pr_number=0)
        with self.assertRaisesRegex(InvalidEvent, "positive integer"):
            validate(bad, self.api_pr, self.repo, self.control_repo)

    def test_rejects_dirty_control(self):
        (self.control_repo / "extra").write_text("uncommitted\n")
        with self.assertRaisesRegex(InvalidEvent, "checkout is dirty"):
            validate(self.event, self.api_pr, self.repo, self.control_repo)

    def test_rejects_api_response_for_another_pr(self):
        bad = dict(self.api_pr, number=124)
        with self.assertRaisesRegex(InvalidEvent, "number mismatch"):
            validate(self.event, bad, self.repo, self.control_repo)

    def test_rejects_closed_pr(self):
        bad = dict(self.api_pr, state="closed")
        with self.assertRaisesRegex(InvalidEvent, "not open"):
            validate(self.event, bad, self.repo, self.control_repo)

    def test_rejects_wrong_base_repository(self):
        bad = {**self.api_pr, "base": {"repo": {"full_name": "attacker/openwrt"}}}
        with self.assertRaisesRegex(InvalidEvent, "base repository"):
            validate(self.event, bad, self.repo, self.control_repo)

    def test_rejects_api_sha_that_differs_from_checkout_and_event(self):
        bad = {**self.api_pr, "head": {**self.api_pr["head"], "sha": self.control}}
        with self.assertRaisesRegex(InvalidEvent, "event source SHA disagrees"):
            validate(self.event, bad, self.repo, self.control_repo)

    def test_rejects_event_base_sha_that_differs_from_api(self):
        bad = dict(self.event, base_sha=self.source)
        with self.assertRaisesRegex(InvalidEvent, "base SHA disagrees"):
            validate(bad, self.api_pr, self.repo, self.control_repo)
        self.mock_base_fetch.assert_not_called()

    def test_rejects_failed_canonical_base_fetch(self):
        self.mock_base_fetch.side_effect = InvalidEvent("canonical base Git lookup failed")
        with self.assertRaisesRegex(InvalidEvent, "canonical base Git lookup failed"):
            validate(self.event, self.api_pr, self.repo, self.control_repo)

    def test_rejects_inconsistent_base_fetch_identity(self):
        self.mock_base_fetch.return_value = {"commit": self.source, "tree": self.base_tree}
        with self.assertRaisesRegex(InvalidEvent, "base commit or tree differs"):
            validate(self.event, self.api_pr, self.repo, self.control_repo)
        self.mock_base_fetch.return_value = {"commit": self.control, "tree": "bad"}
        with self.assertRaisesRegex(InvalidEvent, "base commit or tree differs"):
            validate(self.event, self.api_pr, self.repo, self.control_repo)

    def test_rejects_cross_repository_head_not_marked_as_fork(self):
        bad = {**self.api_pr, "head": {**self.api_pr["head"],
                                         "repo": {"full_name": "contributor/openwrt", "fork": False}}}
        with self.assertRaisesRegex(InvalidEvent, "not identified as a fork"):
            validate(self.event, bad, self.repo, self.control_repo)

    def test_accepts_same_repository_pull_head(self):
        same_repo = {**self.api_pr, "head": {**self.api_pr["head"],
                                              "repo": {"full_name": "openwrt/openwrt", "fork": False}}}
        result = validate(self.event, same_repo, self.repo, self.control_repo)
        self.assertEqual(result["head_repository"], "openwrt/openwrt")

    def test_production_base_url_and_transport_are_pinned(self):
        with patch("tools.incoming_event._fetch_commit_identity",
                   return_value={"commit": self.control, "tree": self.base_tree}) as fetch:
            self.assertEqual(fetch_base_identity("openwrt", self.control)["tree"], self.base_tree)
        fetch.assert_called_once_with("https://github.com/openwrt/openwrt.git",
                                      self.control, "https")

    def test_isolated_fetch_resolves_exact_local_bare_commit_and_tree(self):
        bare = self.root / "upstream.git"
        self.git("clone", "--bare", "-q", str(self.repo), str(bare))
        identity = _fetch_commit_identity(bare.as_uri(), self.control, "file")
        self.assertEqual(identity, {"commit": self.control, "tree": self.base_tree})

    def test_isolated_fetch_ignores_inherited_git_rewrite(self):
        bare = self.root / "upstream.git"
        self.git("clone", "--bare", "-q", str(self.repo), str(bare))
        malicious = self.root / "gitconfig"
        malicious.write_text(f'[url "file:///nonexistent/"]\n\tinsteadOf = {bare.as_uri()}\n')
        with patch.dict(os.environ, {"GIT_CONFIG_GLOBAL": str(malicious),
                                  "GIT_CONFIG_COUNT": "1",
                                  "GIT_CONFIG_KEY_0": "url.file:///nonexistent/.insteadOf",
                                  "GIT_CONFIG_VALUE_0": bare.as_uri()}):
            identity = _fetch_commit_identity(bare.as_uri(), self.control, "file")
        self.assertEqual(identity["tree"], self.base_tree)

    def test_isolated_fetch_rejects_missing_base_commit(self):
        bare = self.root / "upstream.git"
        self.git("clone", "--bare", "-q", str(self.repo), str(bare))
        with self.assertRaisesRegex(InvalidEvent, "canonical base Git lookup failed"):
            _fetch_commit_identity(bare.as_uri(), "0" * 40, "file")

    def test_isolated_fetch_timeout_fails_closed(self):
        with patch("tools.incoming_event.subprocess.run",
                   side_effect=subprocess.TimeoutExpired("git", 60)):
            with self.assertRaisesRegex(InvalidEvent, "canonical base Git lookup timed out"):
                _fetch_commit_identity("file:///unreachable", self.control, "file")


if __name__ == "__main__":
    unittest.main()
