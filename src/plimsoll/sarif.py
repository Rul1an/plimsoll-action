"""Render a Plimsoll review into SARIF 2.1.0 so capability findings land in GitHub code scanning.

Pure and stdlib-only: `review_to_sarif(review)` takes a parsed `assay.product.evidence_review.v1`
dict (the output of `plimsoll diff`) and returns a SARIF document. This is the CodeQL-style surface:
each capability that needs approval becomes a code-scanning result with a stable fingerprint, and a
blocked (insufficient-coverage) decision becomes its own result, so an under-observed release is
visible in the Security tab rather than silently passing.
"""

import hashlib

SARIF_VERSION = "2.1.0"
SARIF_SCHEMA = (
    "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json"  # noqa: E501
)

# kind -> (ruleId, SARIF level, security-severity 0-10, short description)
_RULES = {
    "network": ("PLIMSOLL-NEW-NETWORK", "error", "8.0", "New network capability requires approval"),
    "mcp_tool": ("PLIMSOLL-NEW-MCP-TOOL", "error", "7.0", "New MCP tool requires approval"),
    "filesystem": (
        "PLIMSOLL-FS-OUTSIDE-WORKSPACE",
        "warning",
        "5.0",
        "New filesystem access outside the declared workspace",
    ),
    "process": ("PLIMSOLL-NEW-PROCESS", "warning", "3.0", "New process execution"),
}
_COVERAGE_RULE = (
    "PLIMSOLL-COVERAGE-INSUFFICIENT",
    "error",
    "7.0",
    "Observation coverage insufficient to certify the release",
)


def _fingerprint(review_id: str, kind: str, item: str) -> str:
    return hashlib.sha256(f"{review_id}|{kind}|{item}".encode()).hexdigest()[:16]


def _rule(rule_id, level, sev, short):
    return {
        "id": rule_id,
        "name": rule_id.replace("-", ""),
        "shortDescription": {"text": short},
        "fullDescription": {
            "text": (
                "Plimsoll reviews what a release's runtime capability changed, from observed "
                "effect. This marks a capability new in this release that needs a human "
                "decision before it ships."
            )
        },
        "defaultConfiguration": {"level": level},
        "properties": {"security-severity": sev, "tags": ["plimsoll", "runtime-evidence-review"]},
    }


def review_to_sarif(review: dict, surface_uri: str = "capability-surface.json") -> dict:
    review_id = review.get("review_id", "")
    findings = review.get("findings_requiring_approval", [])
    decision = review.get("decision", "")

    used_rule_ids = {}
    results = []

    for f in findings:
        kind = f.get("kind", "process")
        rule_id, level, sev, short = _RULES.get(kind, _RULES["process"])
        used_rule_ids[rule_id] = (rule_id, level, sev, short)
        item = f.get("item", "")
        results.append(
            {
                "ruleId": rule_id,
                "level": level,
                "message": {"text": f"{f.get('reason', short)}: {item}"},
                "partialFingerprints": {"plimsollFinding": _fingerprint(review_id, kind, item)},
                "locations": [
                    {
                        "physicalLocation": {
                            "artifactLocation": {"uri": surface_uri},
                            "region": {"startLine": 1},
                        }
                    }
                ],
            }
        )

    if decision in ("blocked_observation_insufficient", "inconclusive_observation_gap"):
        rid, level, sev, short = _COVERAGE_RULE
        used_rule_ids[rid] = _COVERAGE_RULE
        if decision == "blocked_observation_insufficient":
            cov_text = (
                "Release not certified: observation coverage was insufficient, so the "
                "absence of new capability cannot be trusted. See the review for detail."
            )
        else:
            cov_text = (
                "Release not certified: a relevant surface was not observed, so the absence of new "
                "capability there cannot be trusted (inconclusive_observation_gap). See the review."
            )
        results.append(
            {
                "ruleId": rid,
                "level": level,
                "message": {"text": cov_text},
                "partialFingerprints": {"plimsollFinding": _fingerprint(review_id, "coverage", "")},
                "locations": [
                    {
                        "physicalLocation": {
                            "artifactLocation": {"uri": surface_uri},
                            "region": {"startLine": 1},
                        }
                    }
                ],
            }
        )

    rules = [_rule(*v) for v in used_rule_ids.values()]

    return {
        "$schema": SARIF_SCHEMA,
        "version": SARIF_VERSION,
        "runs": [
            {
                "tool": {
                    "driver": {
                        "name": "Plimsoll",
                        "informationUri": "https://github.com/Rul1an/plimsoll",
                        "rules": rules,
                    }
                },
                "automationDetails": {"id": f"plimsoll/review/{review_id}"},
                "results": results,
            }
        ],
    }
