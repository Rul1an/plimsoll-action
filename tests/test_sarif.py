"""SARIF rendering tests (the code-scanning surface). Plain unittest."""

import pathlib
import sys
import unittest

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parents[1] / "src"))
from plimsoll.sarif import review_to_sarif  # noqa: E402


def _review(decision, findings, review_id="sha256:abc"):
    return {"review_id": review_id, "decision": decision, "findings_requiring_approval": findings}


class SarifTest(unittest.TestCase):
    def test_shape_and_version(self):
        doc = review_to_sarif(_review("auto_clear_no_new_capability", []))
        self.assertEqual(doc["version"], "2.1.0")
        self.assertEqual(doc["runs"][0]["tool"]["driver"]["name"], "Plimsoll")
        self.assertEqual(doc["runs"][0]["results"], [])

    def test_findings_become_results_with_levels(self):
        findings = [
            {"kind": "network", "item": "evil:443", "reason": "new network capability"},
            {"kind": "mcp_tool", "item": "http.post", "reason": "new mcp_tool capability"},
            {"kind": "filesystem", "item": "/home/u/.ssh/id_rsa", "reason": "outside workspace"},
        ]
        doc = review_to_sarif(_review("pending", findings))
        results = doc["runs"][0]["results"]
        self.assertEqual(len(results), 3)
        levels = {r["ruleId"]: r["level"] for r in results}
        self.assertEqual(levels["PLIMSOLL-NEW-NETWORK"], "error")
        self.assertEqual(levels["PLIMSOLL-NEW-MCP-TOOL"], "error")
        self.assertEqual(levels["PLIMSOLL-FS-OUTSIDE-WORKSPACE"], "warning")
        for r in results:
            self.assertIn("plimsollFinding", r["partialFingerprints"])
            self.assertTrue(r["locations"][0]["physicalLocation"]["artifactLocation"]["uri"])

    def test_blocked_coverage_is_a_result(self):
        doc = review_to_sarif(_review("blocked_observation_insufficient", []))
        ids = [r["ruleId"] for r in doc["runs"][0]["results"]]
        self.assertIn("PLIMSOLL-COVERAGE-INSUFFICIENT", ids)

    def test_security_severity_present_on_rules(self):
        findings = [{"kind": "network", "item": "x:443", "reason": "r"}]
        doc = review_to_sarif(_review("pending", findings))
        rule = doc["runs"][0]["tool"]["driver"]["rules"][0]
        self.assertIn("security-severity", rule["properties"])

    def test_fingerprint_is_stable(self):
        f = [{"kind": "network", "item": "x:443", "reason": "r"}]
        a = review_to_sarif(_review("pending", f))["runs"][0]["results"][0]["partialFingerprints"]
        b = review_to_sarif(_review("pending", f))["runs"][0]["results"][0]["partialFingerprints"]
        self.assertEqual(a, b)


if __name__ == "__main__":
    unittest.main()
