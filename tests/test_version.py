import unittest
from importlib.metadata import version

import plimsoll


class VersionContractTest(unittest.TestCase):
    def test_runtime_version_matches_distribution_metadata(self):
        self.assertEqual(plimsoll.__version__, version("plimsoll"))
