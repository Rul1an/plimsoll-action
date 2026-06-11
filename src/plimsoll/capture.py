#!/usr/bin/env python3
"""Plimsoll capture — produce a real capability surface from a live agent run via eBPF.

Wraps `assay monitor` (the open-core eBPF capture) to record what a run actually did, and emits a
capability_surface.v0 JSON that Plimsoll's review.py can diff. This turns the demo from sample JSON
into real kernel observation: capture release A, capture release B, diff, review.

Usage:
  sudo-capable host with the eBPF object:
  python3 capture.py --assay /usr/local/bin/assay --ebpf /path/assay-ebpf.o \
    --label release-A --out a.json -- python3 workload.py
"""

import argparse
import json
import os
import re
import subprocess
import sys
import tempfile
import time

# Anchored at start (the lines are stripped before matching) so .search() does not retry every
# position, and CONNECT drops the \s* that overlapped (.+); the leading space is removed by the
# existing .strip() on the capture. Removes the polynomial-ReDoS backtracking CodeQL flagged.
OPENAT = re.compile(r"^\[PID (\d+)\] openat: (.+)$")
CONNECT = re.compile(r"^\[PID (\d+)\] connect:?(.+)$")


def main(argv=None):
    ap = argparse.ArgumentParser()
    ap.add_argument("--assay", default=os.environ.get("ASSAY", "/usr/local/bin/assay"))
    ap.add_argument("--ebpf", default=os.environ.get("ASSAY_EBPF", ""))
    ap.add_argument("--label", default="run")
    ap.add_argument("--out", required=True)
    ap.add_argument("--duration", type=int, default=6)
    ap.add_argument("cmd", nargs=argparse.REMAINDER)
    args = ap.parse_args(argv)

    cmd = args.cmd[1:] if args.cmd and args.cmd[0] == "--" else args.cmd
    if not cmd:
        print("ERROR: provide a workload command after --", file=sys.stderr)
        return 2
    if not args.ebpf or not os.path.exists(args.ebpf):
        print(f"ERROR: eBPF object not found: {args.ebpf!r}", file=sys.stderr)
        return 2

    mon_file = tempfile.NamedTemporaryFile("w+", delete=False, suffix=".mon").name
    mon = subprocess.Popen(
        [
            "sudo",
            args.assay,
            "monitor",
            "--ebpf",
            args.ebpf,
            "--monitor-all",
            "--duration",
            f"{args.duration}s",
            "--print",
        ],
        stdout=open(mon_file, "w"),
        stderr=subprocess.DEVNULL,
    )
    time.sleep(1.6)  # let the eBPF programs attach
    proc = subprocess.Popen(cmd, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    pid = proc.pid
    proc.wait()
    mon.wait()

    fs, net, events = set(), set(), 0
    with open(mon_file) as f:
        for line in f:
            line = line.strip()
            m = OPENAT.search(line)
            if m:
                events += 1
                if int(m.group(1)) == pid:
                    fs.add(m.group(2))
                continue
            c = CONNECT.search(line)
            if c and int(c.group(1)) == pid:
                net.add(c.group(2).strip())
    os.remove(mon_file)

    surface = {
        "schema": "assay.runner.capability_surface.v0",
        "run_id": args.label,
        "filesystem_paths": sorted(fs),
        "network_endpoints": sorted(net),
        "process_execs": [cmd[0]],
        "mcp_tools": [],
        "observation_health": {
            "kernel_layer": "present" if events > 0 else "absent",
            "openat_events_seen": events,
            # the monitor watches connect; if egress was actually observed, report it so the review
            # does not read this surface as an unobserved network layer (R7 / inconclusive gap).
            **({"network_protocol_coverage": "connect_only"} if net else {}),
        },
    }
    with open(args.out, "w") as f:
        json.dump(surface, f, indent=2)
    print(
        json.dumps(
            {
                "out": args.out,
                "fs": len(fs),
                "net": len(net),
                "kernel_layer": surface["observation_health"]["kernel_layer"],
            },
            indent=2,
        )
    )
    return 0


if __name__ == "__main__":
    sys.exit(main())
