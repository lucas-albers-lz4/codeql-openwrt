"""Include the incoming discovery and queue tests in the existing CI suite."""

import sys
import unittest
from pathlib import Path


def load_tests(loader, tests, pattern):
    tools_dir = str(Path(__file__).resolve().parents[2] / "tools")
    sys.path.insert(0, tools_dir)
    try:
        from tools import test_incoming_poll, test_incoming_queue
    finally:
        sys.path.remove(tools_dir)
    return unittest.TestSuite((loader.loadTestsFromModule(test_incoming_poll),
                               loader.loadTestsFromModule(test_incoming_queue)))
