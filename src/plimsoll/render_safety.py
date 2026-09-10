"""Sink-safe rendering for public/CI-visible Plimsoll outputs (review.md, SARIF)."""

from __future__ import annotations

import hashlib

from .secrets import compiled_rule

# Each arm is the compiled rule from secrets.py, not a copy.
# github-token does not match github_pat_ (third character is "t", not in [pousr]).
SECRET_RE = compiled_rule("github-token")
_RENDER_RULE_NAMES = ("github-token", "github-fine-grained-pat")


def _short_hash(value: str) -> str:
    return hashlib.sha256(value.encode("utf-8")).hexdigest()[:10]


def safe_render_text(value) -> str:
    """Redact github-token and github-fine-grained-pat shapes before a public sink."""

    def _redact(match):
        return f"<redacted:secret:{_short_hash(match.group())}>"

    text = str(value)
    for name in _RENDER_RULE_NAMES:
        text = compiled_rule(name).sub(_redact, text)
    return text
