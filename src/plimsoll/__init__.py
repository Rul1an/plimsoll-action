"""Plimsoll — the load line for agent releases.

Runtime evidence review: a coverage gate, capability diff across releases, a review policy on the
delta, human approve/reject, and a tamper-evident hash-chained audit log. Built on assay (the
open-source runtime evidence engine); this package is the review layer.
"""

from .review import (
    build_review,
    coverage_status,
    default_policy,
    diff_surfaces,
    findings,
    load_policy,
    load_surface,
    verify_chain,
)

__version__ = "0.2.0"

__all__ = [
    "__version__",
    "load_surface",
    "load_policy",
    "default_policy",
    "coverage_status",
    "diff_surfaces",
    "findings",
    "build_review",
    "verify_chain",
]
