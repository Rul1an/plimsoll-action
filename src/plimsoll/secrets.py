"""Secret-shape detection for capability surfaces (evidence hygiene).

A clean evidence record should not carry secrets. If a recorded surface value (a process argv,
a path, a network endpoint, a tool name) looks like a credential, that is both a leak in the
artifact and a sign the capture was not redacted at source. This module is a curated, high-signal,
low-false-positive heuristic in the spirit of gitleaks-style provider rulesets: it reports a
claim-class "possible secret", never a certainty, and it NEVER echoes the matched value or decodes
it. A finding carries only the field, the rule that matched, and the matched length, so a reviewer
learns "a github-token-shaped value appeared in process_execs" without the warning re-leaking it.

This is a warning, not a gate: heuristics have false positives, so it points at redaction rather
than failing the release.
"""

import re

# (rule name, compiled pattern). High-confidence provider tokens + structural credential shapes.
# Curated for low false positives; no generic entropy scan (sha256 digests / content ids are
# legitimately high-entropy in evidence and would be noisy). Add entropy behind an opt-in if needed.
_RULES = [
    ("aws-access-key-id", re.compile(r"\b(?:AKIA|ASIA)[0-9A-Z]{16}\b")),
    ("github-token", re.compile(r"\bgh[pousr]_[A-Za-z0-9]{36,}\b")),
    ("openai-key", re.compile(r"\bsk-(?:proj-)?[A-Za-z0-9_-]{20,}\b")),
    ("slack-token", re.compile(r"\bxox[baprs]-[A-Za-z0-9-]{10,}\b")),
    ("google-api-key", re.compile(r"\bAIza[0-9A-Za-z_-]{35}\b")),
    ("stripe-key", re.compile(r"\b[sp]k_(?:live|test)_[0-9A-Za-z]{16,}\b")),
    ("private-key-pem", re.compile(r"-----BEGIN (?:[A-Z ]*)PRIVATE KEY-----")),
    (
        "jwt",
        re.compile(r"\beyJ[A-Za-z0-9_-]{10,}\.eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\b"),
    ),
    ("bearer-token", re.compile(r"(?i)\bbearer\s+[A-Za-z0-9._~+/-]{20,}=*")),
    (
        "credential-assignment",
        re.compile(
            r"(?i)\b(?:api[_-]?key|secret|token|password|passwd|access[_-]?key|client[_-]?secret)\b"
            r"\s*[=:]\s*[^\s'\"]{6,}"
        ),
    ),
]

# The recorded value fields of assay.runner.capability_surface.v0.
_SURFACE_FIELDS = ("filesystem_paths", "network_endpoints", "process_execs", "mcp_tools")


def scan_surface(surface: dict) -> list:
    """Return possible-secret hits in a capability surface. Each hit is {field, rule, matched_len};
    the matched value is never included, so consuming this does not re-leak the secret."""
    hits = []
    seen = set()
    for field in _SURFACE_FIELDS:
        for value in surface.get(field, []) or []:
            text = str(value)
            for name, pattern in _RULES:
                m = pattern.search(text)
                if m:
                    key = (field, name)
                    if key not in seen:
                        seen.add(key)
                        hits.append({"field": field, "rule": name, "matched_len": len(m.group(0))})
                    break  # one rule per value is enough to flag it
    return hits


def secret_warnings(surface: dict) -> list:
    """Human-readable, value-free warnings for a surface's possible secrets."""
    return [
        f"possible secret in a recorded {h['field']} value (looks like {h['rule']}); evidence "
        f"should not carry credentials, redact it at capture"
        for h in scan_surface(surface)
    ]
