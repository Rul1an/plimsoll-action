"""Parity: the Plimsoll detector's rules must match the shared secret-rules.v1.json contract fixture
(the same fixture the assay runner Redactor checks against), so the Python and Rust implementations
of ADR-034 secret detection cannot drift apart. Plain unittest."""

import json
import pathlib
import sys
import unittest

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parents[1] / "src"))
from plimsoll.secrets import _RULES  # noqa: E402


def _normalize(pattern: str) -> str:
    # Rust raw strings emit a bare " in a char class; Python raw strings emit \" for the same. Strip
    # those language-specific, semantically-irrelevant char-class quote escapes before comparing.
    return pattern.replace('\\"', '"').replace("\\'", "'")


class RulesParityTest(unittest.TestCase):
    def test_rules_match_shared_contract_fixture(self):
        fixture_path = pathlib.Path(__file__).resolve().parent / "fixtures" / "secret-rules.v1.json"
        doc = json.loads(fixture_path.read_text())
        self.assertEqual(doc["schema"], "assay.secret-rules.v1")

        fixture = {r["name"]: r["pattern"] for r in doc["rules"]}
        builtin = {name: _normalize(rx.pattern) for name, rx in _RULES}

        self.assertEqual(
            builtin,
            fixture,
            "Plimsoll secret rules drifted from secret-rules.v1.json; update the fixture AND the "
            "assay runner Redactor together so the two implementations stay in lockstep",
        )
