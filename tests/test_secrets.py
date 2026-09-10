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
from plimsoll.secrets import _RULES, scan_surface, secret_warnings  # noqa: E402

# Assembled at runtime; never a whole-token literal in source.
GH = "gh" + "p_" + ("0123456789abcdef" * 2) + "0123"  # github-token shape, 40 chars after prefix
GH2 = "gh" + "p_" + ("z" * 36)  # a second, distinct github-token shape
# Stateless GitHub App installation token: ghs_<app id>_<JWT>, ~520 chars, two dots, may end in "-".
GHS = (
    "gh"
    + "s"
    + "_"
    + "1234567"
    + "_"
    + "ey"
    + "JhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9"
    + "."
    + "ey"
    + "J"
    + "QmFzZTY0VXJs" * 28
    + "."
    + "c2lnbmF0dXJl_x" * 9
    + "Zz-"
)
AWS = "AK" + "IA" + "IOSFODNN7" + "EXAMPLE"  # aws-access-key-id shape (AKIA + 16)
PW = "--pass" + "word=" + "hunter2" + "supersecret"  # credential-assignment shape
_WINDOW = 12


def _github_token_rule():
    return next(rx for name, rx in _RULES if name == "github-token")


def _assert_no_token_window(test, text, token=GHS, n=_WINDOW):
    """Fail if any n-character slice of token appears in text."""
    for i in range(len(token) - n + 1):
        test.assertNotIn(token[i : i + n], text, f"token window at offset {i} leaked into output")


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

    def test_stateless_installation_token_is_github_token_and_fully_consumed(self):
        # ghs_<app>_<JWT> must hit github-token (not jwt: "_eyJ" has no word boundary before eyJ)
        # and consume the trailing "-" so a redactor cannot leave a 12-char window behind.
        self.assertGreaterEqual(len(GHS), 500)
        self.assertEqual(GHS.count("."), 2)
        self.assertTrue(GHS.endswith("-"))

        m = _github_token_rule().search(GHS)
        self.assertIsNotNone(m)
        self.assertEqual(m.group(0), GHS)
        self.assertTrue(m.group(0).endswith("-"))

        leak = f"gh api --hostname api.github.com --token {GHS}"
        surface = {"process_execs": [leak]}
        hits = scan_surface(surface)
        self.assertEqual(len(hits), 1)
        self.assertEqual(hits[0]["rule"], "github-token")
        self.assertEqual(hits[0]["matched_len"], len(GHS))
        _assert_no_token_window(self, json.dumps(hits))

        warns = secret_warnings(surface)
        self.assertEqual(len(warns), 1)
        self.assertIn("github-token", warns[0])
        _assert_no_token_window(self, warns[0])

        redacted = _github_token_rule().sub("<redacted:github-token>", leak)
        self.assertIn("github-token", redacted)
        _assert_no_token_window(self, redacted)
        self.assertFalse(redacted.endswith("-"))


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

    def test_stateless_installation_token_is_reported_value_free_through_review_and_sarif(self):
        leak = f"deploy --token {GHS}"
        with tempfile.TemporaryDirectory() as d:
            sa, sb = _surface([]), _surface([leak])
            a, b = _write(d, "a.json", sa), _write(d, "b.json", sb)
            r = build_review(a, b, sa, sb, default_policy(), True)
            self.assertEqual(len(r["possible_secrets"]), 1)
            self.assertEqual(r["possible_secrets"][0]["rule"], "github-token")
            self.assertEqual(r["possible_secrets"][0]["matched_len"], len(GHS))
            _assert_no_token_window(self, json.dumps(r["possible_secrets"]))
            secret_warns = [w for w in r["warnings"] if "redact it at capture" in w]
            self.assertTrue(secret_warns)
            self.assertTrue(all("github-token" in w for w in secret_warns))
            _assert_no_token_window(self, json.dumps(secret_warns))

            doc = review_to_sarif(r)
            dumped = json.dumps(doc)
            secret_results = [
                res
                for res in doc["runs"][0]["results"]
                if res["ruleId"] == "PLIMSOLL-POSSIBLE-SECRET"
            ]
            self.assertEqual(len(secret_results), 1)
            self.assertIn("github-token", secret_results[0]["message"]["text"])
            _assert_no_token_window(self, dumped)

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


class RedactionReceiptTest(unittest.TestCase):
    def test_redacted_placeholder_is_not_flagged(self):
        # A value already redacted at capture must not be re-flagged (the placeholder text
        # "<redacted:github-token:...>" would otherwise trip the credential-assignment rule).
        surface = {"process_execs": ["deploy --token <redacted:github-token:ab12cd34>"]}
        self.assertEqual(scan_surface(surface), [])

    def _surface_with_redaction(self, redaction):
        s = _surface([])
        s["observation_health"]["redaction"] = redaction
        return s

    def test_build_review_surfaces_redaction_receipt(self):
        red = {
            "mode": "shape_and_flag",
            "redacted_count": 2,
            "by_rule": {"github-token": 2},
            "key_scope": "host_local",
            "key_id": "hmac-sha256:8f3a91c2",
        }
        with tempfile.TemporaryDirectory() as d:
            sa = self._surface_with_redaction(red)
            sb = self._surface_with_redaction(red)
            a, b = _write(d, "a.json", sa), _write(d, "b.json", sb)
            r = build_review(a, b, sa, sb, default_policy(), True)
            self.assertTrue(r["redaction"])
            self.assertEqual(r["redaction"][0]["key_id"], "hmac-sha256:8f3a91c2")
            self.assertTrue(any("redacted at capture" in w for w in r["warnings"]))

    def test_build_review_warns_when_redaction_disabled(self):
        red = {"mode": "disabled_unsafe", "redacted_count": 0, "key_scope": "ephemeral"}
        with tempfile.TemporaryDirectory() as d:
            sa = self._surface_with_redaction(red)
            sb = self._surface_with_redaction(red)
            a, b = _write(d, "a.json", sa), _write(d, "b.json", sb)
            r = build_review(a, b, sa, sb, default_policy(), True)
            self.assertTrue(any("redaction was disabled" in w for w in r["warnings"]))


if __name__ == "__main__":
    unittest.main()
