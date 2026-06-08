"""Secret-shape detection tests (evidence hygiene). Plain unittest.

The contract under test: detection is value-free (a finding never carries the matched value),
curated (no generic entropy noise), and advisory (warnings, not a gate).

The fixtures are synthetic secret SHAPES, assembled from fragments at import time so that no whole
token literal is ever committed to the source. That keeps repo secret scanners (and our own check)
from flagging the test file, while the detector still sees a fully-formed token at runtime."""

import json
import os
import pathlib
import sys
import tempfile
import unittest

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parents[1] / "src"))
from plimsoll.review import build_review, default_policy  # noqa: E402
from plimsoll.sarif import review_to_sarif  # noqa: E402
from plimsoll.secrets import scan_surface, secret_warnings  # noqa: E402

# Assembled at runtime; never a whole-token literal in source.
GH = "gh" + "p_" + ("0123456789abcdef" * 2) + "0123"  # github-token shape, 40 chars after prefix
GH2 = "gh" + "p_" + ("z" * 36)  # a second, distinct github-token shape
AWS = "AK" + "IA" + "IOSFODNN7" + "EXAMPLE"  # aws-access-key-id shape (AKIA + 16)
PW = "--pass" + "word=" + "hunter2" + "supersecret"  # credential-assignment shape


class ScanSurfaceTest(unittest.TestCase):
    def test_clean_surface_has_no_hits(self):
        surface = {
            "filesystem_paths": ["/workspace/src/main.py", "/tmp/out.log"],
            "network_endpoints": ["api.example.com:443"],
            "process_execs": ["/usr/bin/python3 main.py"],
            "mcp_tools": ["fs.read", "http.get"],
        }
        self.assertEqual(scan_surface(surface), [])

    def test_detects_provider_tokens_value_free(self):
        surface = {
            "process_execs": [f"deploy --token {GH}"],
            "network_endpoints": [],
            "filesystem_paths": [],
            "mcp_tools": [],
        }
        hits = scan_surface(surface)
        self.assertEqual(len(hits), 1)
        hit = hits[0]
        self.assertEqual(hit["field"], "process_execs")
        self.assertEqual(hit["rule"], "github-token")
        # The matched value must never be echoed back; only field, rule name, and length.
        self.assertEqual(set(hit.keys()), {"field", "rule", "matched_len"})
        self.assertNotIn(GH, str(hit))

    def test_aws_and_credential_assignment(self):
        surface = {
            "filesystem_paths": [f"/etc/app/{AWS}.conf"],
            "process_execs": [f"run {PW}"],
        }
        rules = {h["rule"] for h in scan_surface(surface)}
        self.assertIn("aws-access-key-id", rules)
        self.assertIn("credential-assignment", rules)

    def test_dedup_one_hit_per_field_and_rule(self):
        surface = {"process_execs": [f"a --token {GH}", f"b --token {GH2}"]}
        hits = scan_surface(surface)
        self.assertEqual(len(hits), 1)

    def test_high_entropy_digest_is_not_flagged(self):
        # A content-addressed id / sha256 digest is legitimately high-entropy; the curated ruleset
        # must not flag it (no generic entropy scan).
        surface = {
            "mcp_tools": ["sha256:" + "a1b2c3d4" * 8],
            "filesystem_paths": ["/cas/" + "0f" * 32 + ".blob"],
        }
        self.assertEqual(scan_surface(surface), [])

    def test_warnings_are_human_readable_and_value_free(self):
        surface = {"process_execs": [f"x --token {GH}"]}
        warns = secret_warnings(surface)
        self.assertEqual(len(warns), 1)
        self.assertIn("github-token", warns[0])
        self.assertIn("redact it at capture", warns[0])
        self.assertNotIn(GH, warns[0])


def _surface(execs):
    return {
        "schema": "assay.runner.capability_surface.v0",
        "filesystem_paths": ["/workspace/a"],
        "network_endpoints": [],
        "mcp_tools": ["t"],
        "process_execs": execs,
        "observation_health": {"kernel_layer": "complete", "network_protocol_coverage": "absent"},
    }


def _write(tmp, name, surface):
    p = os.path.join(tmp, name)
    with open(p, "w") as f:
        json.dump(surface, f)
    return p


class ReviewIntegrationTest(unittest.TestCase):
    def test_build_review_surfaces_possible_secrets_and_warns(self):
        leak = f"deploy --token {GH}"
        with tempfile.TemporaryDirectory() as d:
            sa, sb = _surface([]), _surface([leak])
            a, b = _write(d, "a.json", sa), _write(d, "b.json", sb)
            r = build_review(a, b, sa, sb, default_policy(), True)
            self.assertEqual(len(r["possible_secrets"]), 1)
            self.assertEqual(r["possible_secrets"][0]["rule"], "github-token")
            self.assertTrue(any("redact it at capture" in w for w in r["warnings"]))
            # the secret finding and its warning are value-free (the diff still mirrors the captured
            # surface verbatim, which is exactly why the warning points at redaction *at capture*).
            self.assertNotIn(GH, json.dumps(r["possible_secrets"]))
            secret_warns = [w for w in r["warnings"] if "redact it at capture" in w]
            self.assertNotIn(GH, json.dumps(secret_warns))

    def test_sarif_emits_value_free_secret_result_and_rule(self):
        review = {
            "review_id": "sha256:abc",
            "decision": "auto_clear_no_new_capability",
            "findings_requiring_approval": [],
            "possible_secrets": [
                {"field": "process_execs", "rule": "github-token", "matched_len": 40}
            ],
        }
        doc = review_to_sarif(review)
        run = doc["runs"][0]
        rule_ids = {ru["id"] for ru in run["tool"]["driver"]["rules"]}
        self.assertIn("PLIMSOLL-POSSIBLE-SECRET", rule_ids)
        secret_results = [r for r in run["results"] if r["ruleId"] == "PLIMSOLL-POSSIBLE-SECRET"]
        self.assertEqual(len(secret_results), 1)
        self.assertEqual(secret_results[0]["level"], "warning")
        self.assertIn("github-token", secret_results[0]["message"]["text"])


if __name__ == "__main__":
    unittest.main()
