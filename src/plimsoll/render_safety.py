"""Sink-safe rendering for public/CI-visible Plimsoll outputs (review.md, SARIF)."""

from __future__ import annotations

import hashlib

from .secrets import compiled_rule

# One definition: the github-token arm is the compiled rule from secrets.py, not a copy.
# A hand-written ghp_-only regex here would miss classic ghs_ and ghs_<app id>_<JWT>.
SECRET_RE = compiled_rule("github-token")


def _short_hash(value: str) -> str:
    return hashlib.sha256(value.encode("utf-8")).hexdigest()[:10]


def safe_render_text(value) -> str:
    """Redact github-token shapes before a public sink. Does not mutate review.json."""
    return SECRET_RE.sub(lambda m: f"<redacted:secret:{_short_hash(m.group())}>", str(value))
