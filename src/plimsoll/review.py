#!/usr/bin/env python3
"""Plimsoll — the load line for agent releases. Runtime evidence review.

Capability diff + coverage gate + review policy + human decision + tamper-evident audit, over the
open-core truth primitives. It answers: "What runtime capability changed in this agent release, and
should we approve it?" Like a ship's Plimsoll line, it makes the boundary visible and checks what a
release actually carries against what it declared, before it ships.

Flow: two capability surfaces -> coverage gate -> diff -> review policy -> decision -> audit.

Design grounded in the June-2026 SOTA this project helped shape: content-addressed records (sha256
over canonical JSON), a tamper-evident hash-chained append-only audit log (a local transparency-log
shape, RFC-9162 in spirit), receipt fields aligned with the MCP execution-receipt discussion
(issuer/digest/decision), and the coverage-honesty principle (do not certify from an incomplete
observation). The truth primitives (capture, evidence bundles, observed-vs-declared) stay open in
assay; this tool only adds the review/approval/audit decision layer an organization needs.

Subcommands:
  diff   --before A --after B [--policy p.yaml] [--no-require-coverage] --out-dir OUT
  decide --review OUT/review.json --decision approve|reject --reviewer NAME --reason R
  verify --audit OUT/audit.ndjson         -> checks the hash chain is intact
"""

from __future__ import annotations

import argparse
import datetime
import hashlib
import io
import json
import os
import sys
import tarfile

FIELDS = [
    ("filesystem_paths", "filesystem"),
    ("network_endpoints", "network"),
    ("process_execs", "process"),
    ("mcp_tools", "mcp_tool"),
]

GENESIS = "sha256:" + "0" * 64


# ----- canonical hashing (content addressing) ---------------------------------


def canonical(obj) -> bytes:
    """Deterministic JSON for content addressing (sorted keys, no whitespace)."""
    return json.dumps(obj, sort_keys=True, separators=(",", ":")).encode("utf-8")


def sha256_hex(data: bytes) -> str:
    return "sha256:" + hashlib.sha256(data).hexdigest()


def content_id(obj, *, exclude=()) -> str:
    """sha256 over the canonical form of obj with the excluded keys removed."""
    clean = {k: v for k, v in obj.items() if k not in exclude}
    return sha256_hex(canonical(clean))


def file_digest(path: str) -> str:
    with open(path, "rb") as f:
        return sha256_hex(f.read())


# ----- capability surface loading ---------------------------------------------


def _normalize(d: dict) -> dict:
    return {
        "filesystem_paths": list(d.get("filesystem_paths", d.get("fs", []))),
        "network_endpoints": list(d.get("network_endpoints", d.get("net", []))),
        "process_execs": list(d.get("process_execs", d.get("procs", []))),
        "mcp_tools": list(d.get("mcp_tools", d.get("tools", []))),
        "observation_health": d.get("observation_health", {}),
        "scenario": d.get("scenario", {}),
    }


def load_surface(path: str) -> dict:
    """Load a capability surface.

    Accepts: a capability_surface.v0 JSON, the simple {fs,net,tools,procs} shape, or an assay runner
    archive (.tar.gz) from which the structured capability-surface JSON is extracted. Preferring the
    structured artifact over scraped text is the product boundary; capture is the live bridge.
    """
    if path.endswith((".tar.gz", ".tgz")):
        return _normalize(_surface_from_archive(path))
    with open(path) as f:
        return _normalize(json.load(f))


def _surface_from_archive(path: str) -> dict:
    with tarfile.open(path, "r:gz") as tar:
        member = next(
            (
                m
                for m in tar.getmembers()
                if m.isfile()
                and m.name.split("/")[-1] in ("capability-surface.json", "capability_surface.json")
            ),
            None,
        )
        if member is None:
            raise ValueError(f"no capability-surface.json in runner archive {path!r}")
        extracted = tar.extractfile(member)
        if extracted is None:
            raise ValueError(f"could not read capability surface from {path!r}")
        return json.load(io.TextIOWrapper(extracted, encoding="utf-8"))


# ----- coverage gate (the E5A honesty principle) ------------------------------


def coverage_status(surface: dict) -> str:
    """sufficient | insufficient | unknown — never certify from an incomplete observation."""
    h = surface.get("observation_health") or {}
    if not h:
        return "unknown"
    status = h.get("status")
    if status in ("sufficient", "insufficient", "degraded"):
        return status
    kernel = h.get("kernel_layer")
    # assay's real KernelLayerStatus (assay.runner.observation_health.v0):
    if kernel == "complete":
        return "sufficient"
    if kernel == "partial_ringbuf_drops":
        # observed but lossy: dropped events make "no change" not fully interpretable, so this is
        # degraded (warned + never silently auto-cleared), not sufficient.
        return "degraded"
    if kernel == "absent":
        return "insufficient"
    # simple/legacy present|absent form:
    events = h.get("openat_events_seen", h.get("events_seen"))
    if kernel == "present" and (events is None or events > 0):
        return "sufficient"
    if events == 0:
        return "insufficient"
    return "unknown"


_NET_PROTO_OBSERVED = {
    "connect_only",
    "datagram_peer_observed",
    "connect_and_datagram_peer_observed",
}


def _network_coverage(h: dict) -> str:
    """Network is gated by its OWN observation signal (R7): 'no undeclared egress' is only certified
    when the network layer was observed. Absent the signal, coverage is unknown, not clean.

    Prefers assay's real `network_protocol_coverage` (assay.runner.observation_health.v0): `absent`
    means the network layer was not observed (insufficient); a `connect`/`datagram` observed value
    means it was (sufficient); `unknown`/missing -> unknown. Falls back to a simple
    `network_layer: present|absent` signal for non-assay inputs."""
    npc = h.get("network_protocol_coverage")
    if npc is not None:
        if npc == "absent":
            return "insufficient"
        if npc in _NET_PROTO_OBSERVED:
            return "sufficient"
        return "unknown"
    nl = h.get("network_layer")
    if nl == "present":
        return "sufficient"
    if nl == "absent":
        return "insufficient"
    return "unknown"


def coverage_by_surface(surface: dict) -> dict:
    """Per-surface observation sufficiency. filesystem/processes/tools ride the kernel signal;
    network is gated separately, so an unobserved network layer is not read as 'no egress'.
    """
    base = coverage_status(surface)
    h = surface.get("observation_health") or {}
    return {
        "filesystem": base,
        "processes": base,
        "tools": base,
        "network": _network_coverage(h),
    }


# diff field key -> coverage_by_surface label, so strict coverage can be scoped to the surfaces a
# given diff actually touched rather than every surface.
DIFF_KEY_TO_SURFACE = {
    "filesystem_paths": "filesystem",
    "network_endpoints": "network",
    "process_execs": "processes",
    "mcp_tools": "tools",
}


# ----- diff + policy ----------------------------------------------------------


def default_policy() -> dict:
    return {
        "require_approval_for": ["network", "mcp_tool"],
        "filesystem_workspace_prefixes": ["/workspace", "/app", "/data", "/tmp"],
        "require_approval_for_fs_outside_workspace": True,
        "note_only": ["process"],
    }


def load_policy(path: str) -> dict:
    if not path:
        return default_policy()
    import yaml

    with open(path) as f:
        return {**default_policy(), **(yaml.safe_load(f) or {})}


def diff_surfaces(before: dict, after: dict) -> dict:
    out = {}
    for key, _label in FIELDS:
        b = set(before.get(key, []))
        a = set(after.get(key, []))
        out[key] = {"added": sorted(a - b), "removed": sorted(b - a)}
    return out


def under_any(path: str, prefixes) -> bool:
    return any(path == p or path.startswith(p.rstrip("/") + "/") for p in prefixes)


def findings(diff: dict, policy: dict) -> list:
    req = set(policy["require_approval_for"])
    out = []
    for key, label in FIELDS:
        for item in diff[key]["added"]:
            if label == "filesystem":
                if policy["require_approval_for_fs_outside_workspace"] and not under_any(
                    item, policy["filesystem_workspace_prefixes"]
                ):
                    out.append(
                        {
                            "kind": "filesystem",
                            "item": item,
                            "reason": "new filesystem access outside the declared workspace",
                        }
                    )
            elif label in req:
                out.append(
                    {
                        "kind": label,
                        "item": item,
                        "reason": f"new {label} capability requires approval",
                    }
                )
    return out


def scenario_comparability(before: dict, after: dict) -> dict:
    sb, sa = before.get("scenario") or {}, after.get("scenario") or {}
    warnings = []
    for k in ("test_plan", "workload", "environment"):
        vb, va = sb.get(k), sa.get(k)
        if vb is None or va is None:
            warnings.append(f"scenario.{k} missing on one side; comparability unverified")
        elif vb != va:
            warnings.append(f"scenario.{k} differs ({vb!r} vs {va!r}); diff may not be comparable")
    return {"before": sb, "after": sa, "warnings": warnings}


def build_review(before_path, after_path, before, after, policy, require_coverage) -> dict:
    d = diff_surfaces(before, after)
    f = findings(d, policy)
    cov_before, cov_after = coverage_status(before), coverage_status(after)
    surf_before, surf_after = coverage_by_surface(before), coverage_by_surface(after)

    # Opt-in (default off, so existing behaviour is unchanged): require every surface observed,
    # not just the overall kernel signal. Turning this on makes an unobserved network layer block.
    strict = bool(policy.get("require_full_surface_coverage", False))
    under_observed = []
    if strict:
        # Only require coverage for surfaces this diff actually touched, on both sides (you need the
        # before AND after observed to interpret an add/remove). An unobserved surface that did not
        # change must not block the review (P2).
        changed = {
            DIFF_KEY_TO_SURFACE[key]
            for key, _label in FIELDS
            if d[key]["added"] or d[key]["removed"]
        }
        for side, surf in (("before", surf_before), ("after", surf_after)):
            for cls in sorted(changed):
                if surf.get(cls) != "sufficient":
                    under_observed.append(f"{side}:{cls}")

    coverage_blocked = require_coverage and (
        "insufficient" in (cov_before, cov_after) or bool(under_observed)
    )
    # Lossy kernel capture (ring-buffer drops -> degraded) is observed-but-incomplete: a missing
    # diff is not interpretable, so it must not silently auto-clear while coverage is required (P1).
    # It does not hard-block; it falls through to human review.
    lossy = require_coverage and ("degraded" in (cov_before, cov_after))

    if coverage_blocked:
        decision = "blocked_observation_insufficient"
    elif f or lossy:
        decision = "pending"
    else:
        decision = "auto_clear_no_new_capability"

    warnings = list(scenario_comparability(before, after)["warnings"])
    for side, cov in (("before", cov_before), ("after", cov_after)):
        if cov == "unknown":
            warnings.append(f"coverage for {side} surface is unknown (no observation_health)")
        elif cov == "degraded":
            warnings.append(
                f"kernel ring-buffer drops on the {side} surface: some events were lost, so the "
                "absence of changes is not fully interpretable; not auto-cleared"
            )
    # honesty: an unobserved surface on the after side cannot be read as "nothing undeclared there"
    for cls, st in surf_after.items():
        if st != "sufficient":
            warnings.append(
                f"cannot certify no undeclared {cls}: {cls} coverage is {st} on the after surface"
            )
    # assay says whether observed endpoints are an authoritative peer set or diagnostic only
    if (after.get("observation_health") or {}).get(
        "network_endpoint_claim_scope"
    ) == "diagnostic_only":
        warnings.append(
            "network endpoints are diagnostic-only (not an authoritative peer set); "
            "absence of an endpoint is not proof it was not contacted"
        )

    review = {
        "schema": "assay.product.evidence_review.v1",
        "before_evidence": {"path": before_path, "digest": file_digest(before_path)},
        "after_evidence": {"path": after_path, "digest": file_digest(after_path)},
        "coverage": {"before": cov_before, "after": cov_after, "required": require_coverage},
        "coverage_surfaces": {"before": surf_before, "after": surf_after},
        "scenario": scenario_comparability(before, after),
        "diff": d,
        "findings_requiring_approval": f,
        "warnings": warnings,
        "decision": decision,
    }
    review["review_id"] = content_id(review, exclude=("review_id",))
    return review


# ----- audit hash chain (tamper-evident, append-only) -------------------------


def _audit_records(audit_path: str) -> list:
    if not os.path.exists(audit_path):
        return []
    out = []
    with open(audit_path) as f:
        for line in f:
            line = line.strip()
            if line:
                out.append(json.loads(line))
    return out


def append_audit(audit_path: str, record: dict) -> dict:
    prior = _audit_records(audit_path)
    record = dict(record)
    record["seq"] = len(prior)
    record["prev_hash"] = prior[-1]["record_hash"] if prior else GENESIS
    record["record_hash"] = content_id(record, exclude=("record_hash",))
    with open(audit_path, "a") as f:
        f.write(json.dumps(record) + "\n")
    return record


def verify_chain(audit_path: str) -> dict:
    records = _audit_records(audit_path)
    prev = GENESIS
    for i, rec in enumerate(records):
        recomputed = content_id(rec, exclude=("record_hash",))
        if recomputed != rec.get("record_hash"):
            return {"ok": False, "broken_at": i, "reason": "record_hash mismatch (record altered)"}
        if rec.get("prev_hash") != prev:
            return {"ok": False, "broken_at": i, "reason": "prev_hash mismatch (chain broken)"}
        prev = rec["record_hash"]
    return {"ok": True, "records": len(records), "head": prev}


# ----- commands ---------------------------------------------------------------


def cmd_diff(args) -> int:
    before = load_surface(args.before)
    after = load_surface(args.after)
    policy = load_policy(args.policy)
    if args.workspace:
        policy["filesystem_workspace_prefixes"] = policy["filesystem_workspace_prefixes"] + list(
            args.workspace
        )
    review = build_review(
        args.before, args.after, before, after, policy, require_coverage=args.require_coverage
    )
    os.makedirs(args.out_dir, exist_ok=True)
    rp = os.path.join(args.out_dir, "review.json")
    with open(rp, "w") as fh:
        json.dump(review, fh, indent=2)
    _review_md(os.path.join(args.out_dir, "review.md"), review)
    print(
        json.dumps(
            {
                "review": rp,
                "review_id": review["review_id"],
                "findings": len(review["findings_requiring_approval"]),
                "decision": review["decision"],
            },
            indent=2,
        )
    )
    return 0


def cmd_decide(args) -> int:
    with open(args.review) as f:
        review = json.load(f)
    at = args.at or datetime.datetime.now(datetime.timezone.utc).isoformat()
    record = {
        "schema": "assay.product.review_audit.v1",
        "decision": args.decision,
        "reviewer": args.reviewer,
        "reason": args.reason,
        "at": at,
        "review_id": review.get("review_id"),
        "review_machine_decision": review.get("decision"),
        "before_digest": review["before_evidence"]["digest"],
        "after_digest": review["after_evidence"]["digest"],
        "findings_count": len(review.get("findings_requiring_approval", [])),
    }
    audit = os.path.join(os.path.dirname(os.path.abspath(args.review)), "audit.ndjson")
    written = append_audit(audit, record)
    print(json.dumps({"audit": audit, "record": written}, indent=2))
    return 0


def cmd_verify(args) -> int:
    result = verify_chain(args.audit)
    print(json.dumps(result, indent=2))
    return 0 if result["ok"] else 1


def cmd_sarif(args) -> int:
    from .sarif import review_to_sarif

    with open(args.review) as f:
        review = json.load(f)
    doc = review_to_sarif(review, surface_uri=args.surface_uri)
    with open(args.out, "w") as f:
        json.dump(doc, f, indent=2)
    n = len(doc["runs"][0]["results"])
    print(json.dumps({"sarif": args.out, "results": n}, indent=2))
    return 0


def _review_md(path: str, r: dict) -> None:
    lines = [
        "# Release capability review\n",
        f"Review id: `{r['review_id']}`",
        f"Before evidence: {r['before_evidence']['digest']} (coverage: {r['coverage']['before']})",
        f"After evidence: {r['after_evidence']['digest']} (coverage: {r['coverage']['after']})\n",
    ]
    if r["decision"] == "blocked_observation_insufficient":
        lines.append(
            "## BLOCKED: observation insufficient\n\n"
            "The capture did not observe enough to certify what changed. Plimsoll will not "
            "auto-clear or diff an incomplete observation as if it were complete. Re-run with "
            "full observation, or a reviewer must override explicitly.\n"
        )
    lines += ["## What changed\n", "| capability | added | removed |", "| --- | --- | --- |"]
    for key, label in FIELDS:
        a = ", ".join(r["diff"][key]["added"]) or "-"
        rem = ", ".join(r["diff"][key]["removed"]) or "-"
        lines.append(f"| {label} | {a} | {rem} |")
    lines.append("")
    if r["warnings"]:
        lines.append("## Warnings\n")
        lines += [f"- {w}" for w in r["warnings"]]
        lines.append("")
    if r["findings_requiring_approval"]:
        lines.append("## Requires approval before this release ships\n")
        for f in r["findings_requiring_approval"]:
            lines.append(f"- **{f['kind']}**: `{f['item']}` — {f['reason']}")
        lines.append("")
        lines.append(
            "Decision: PENDING — a reviewer must approve or reject (see `plimsoll decide`)."
        )
    elif r["decision"] == "auto_clear_no_new_capability":
        lines.append("No new capability outside policy. Decision: auto-clear (no approval needed).")
    lines.append("")
    with open(path, "w") as fh:
        fh.write("\n".join(lines))


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(
        description="Plimsoll — runtime evidence review (the load line for agent releases)"
    )
    sub = ap.add_subparsers(dest="cmd", required=True)

    d = sub.add_parser("diff", help="diff two capability surfaces and apply the review policy")
    d.add_argument("--before", required=True)
    d.add_argument("--after", required=True)
    d.add_argument("--policy", default="")
    d.add_argument(
        "--workspace",
        action="append",
        default=[],
        help="extra workspace path prefix(es) treated as in-policy (repeatable)",
    )
    d.add_argument(
        "--no-require-coverage",
        dest="require_coverage",
        action="store_false",
        help="do not block when observation coverage is insufficient (not recommended)",
    )
    d.set_defaults(require_coverage=True)
    d.add_argument("--out-dir", default="review-out")
    d.set_defaults(fn=cmd_diff)

    de = sub.add_parser("decide", help="record a human approve/reject into the audit chain")
    de.add_argument("--review", required=True)
    de.add_argument("--decision", required=True, choices=["approve", "reject"])
    de.add_argument("--reviewer", required=True)
    de.add_argument("--reason", required=True)
    de.add_argument("--at", default="")
    de.set_defaults(fn=cmd_decide)

    v = sub.add_parser("verify", help="verify the audit hash chain is intact")
    v.add_argument("--audit", required=True)
    v.set_defaults(fn=cmd_verify)

    s = sub.add_parser("sarif", help="render a review.json into SARIF 2.1.0 for code scanning")
    s.add_argument("--review", required=True)
    s.add_argument("--out", default="plimsoll.sarif")
    s.add_argument("--surface-uri", default="capability-surface.json")
    s.set_defaults(fn=cmd_sarif)

    args = ap.parse_args(argv)
    return args.fn(args)


if __name__ == "__main__":
    sys.exit(main())
