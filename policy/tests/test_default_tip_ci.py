"""Run the default-tip resolver tests in the existing M2 policy CI job."""

import unittest

from tools import test_default_tip_event, test_default_tip_manifest


def load_tests(loader, tests, pattern):
    return unittest.TestSuite((loader.loadTestsFromModule(test_default_tip_event),
                               loader.loadTestsFromModule(test_default_tip_manifest)))
