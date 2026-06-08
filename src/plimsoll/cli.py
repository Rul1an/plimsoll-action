"""Unified `plimsoll` command line.

Routes to the review layer (diff/decide) and the capture helper (capture). Kept thin on purpose: the
real logic lives in `review` (pure, testable) and `capture` (the assay-monitor wrapper).

    plimsoll diff    --before A.json --after B.json [--policy p.yaml] --out-dir OUT
    plimsoll decide  --review OUT/review.json --decision approve|reject --reviewer NAME --reason R
    plimsoll verify  --audit OUT/audit.ndjson
    plimsoll capture --ebpf assay-ebpf.o --label release-A --out a.json -- python3 workload.py
"""

from __future__ import annotations

import sys
from collections.abc import Sequence


def main(argv: Sequence[str] | None = None) -> int:
    args = list(sys.argv[1:] if argv is None else argv)
    if args and args[0] == "capture":
        from . import capture

        return capture.main(args[1:])
    from . import review

    return review.main(args)


if __name__ == "__main__":
    raise SystemExit(main())
