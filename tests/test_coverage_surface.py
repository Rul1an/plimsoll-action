"""Per-surface coverage gate tests (R7 consumer side). Plain unittest, runs without pytest."""

import json
import os
import pathlib
import sys
import tempfile
import unittest

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parents[1] / "src"))
from plimsoll.review import build_review, coverage_by_surface, default_policy  # noqa: E402

KERNEL = {"kernel_layer": "present", "openat_events_seen": 100}


def _surface(net_health):
    return {
        "schema": "assay.runner.capability_surface.v0",
        "filesystem_paths": ["/workspace/a"],
        "network_endpoints": [],
        "mcp_tools": ["t"],
        "process_execs": [],
        "observation_health": {**KERNEL, **net_health},
    }


def _write(tmp, name, surface):
    p = os.path.join(tmp, name)
    with open(p, "w") as f:
        json.dump(surface, f)
    return p


class CoverageBySurfaceTest(unittest.TestCase):
    def test_network_present_is_sufficient(self):
        cov = coverage_by_surface(_surface({"network_layer": "present"}))
        self.assertEqual(cov["network"], "sufficient")
        self.assertEqual(cov["filesystem"], "sufficient")

    def test_network_absent_is_insufficient(self):
        self.assertEqual(
            coverage_by_surface(_surface({"network_layer": "absent"}))["network"], "insufficient"
        )

    def test_no_network_signal_is_unknown_not_clean(self):
        # the runner predates R7: network was not observed, so we must not call it sufficient
        self.assertEqual(coverage_by_surface(_surface({}))["network"], "unknown")

    def test_real_assay_network_protocol_coverage_is_consumed(self):
        # assay's real field (assay.runner.observation_health.v0), captured live on the eBPF runner
        connect = {"kernel_layer": "complete", "network_protocol_coverage": "connect_only"}
        cov = coverage_by_surface({"observation_health": connect})
        self.assertEqual(cov["network"], "sufficient")
        self.assertEqual(cov["filesystem"], "sufficient")  # kernel_layer=complete
        absent = {"kernel_layer": "complete", "network_protocol_coverage": "absent"}
        self.assertEqual(
            coverage_by_surface({"observation_health": absent})["network"], "insufficient"
        )

    def test_real_assay_surface_fixture_is_fully_observed(self):
        import json as _json
        import os as _os

        p = _os.path.join(
            _os.path.dirname(__file__), "..", "samples", "real-assay-network-surface.json"
        )
        with open(p) as f:
            surface = _json.load(f)
        cov = coverage_by_surface(surface)
        self.assertEqual(
            cov, {k: "sufficient" for k in ("filesystem", "processes", "tools", "network")}
        )


class StrictGateTest(unittest.TestCase):
    def test_default_does_not_block_on_missing_network_signal(self):
        with tempfile.TemporaryDirectory() as d:
            a = _write(d, "a.json", _surface({}))
            b = _write(d, "b.json", _surface({}))
            r = build_review(a, b, _surface({}), _surface({}), default_policy(), True)
            self.assertNotEqual(r["decision"], "blocked_observation_insufficient")
            self.assertIn("coverage_surfaces", r)

    def test_strict_blocks_when_a_CHANGED_surface_is_unobserved(self):
        # network actually changed AND network was not observed -> strict must block (it cannot
        # interpret the new endpoint).
        with tempfile.TemporaryDirectory() as d:
            sa = {**_surface({}), "network_endpoints": []}
            sb = {**_surface({}), "network_endpoints": ["collector.example:443"]}
            a, b = _write(d, "a.json", sa), _write(d, "b.json", sb)
            policy = {**default_policy(), "require_full_surface_coverage": True}
            r = build_review(a, b, sa, sb, policy, True)
            self.assertEqual(r["decision"], "blocked_observation_insufficient")

    def test_strict_ignores_unchanged_unobserved_surface(self):
        # P2 repro: a filesystem-only diff must NOT be blocked just because network is unobserved,
        # when network did not change.
        with tempfile.TemporaryDirectory() as d:
            sa = {**_surface({}), "filesystem_paths": ["/workspace/a"], "network_endpoints": []}
            sb = {
                **_surface({}),
                "filesystem_paths": ["/workspace/a", "/workspace/new.txt"],
                "network_endpoints": [],
            }
            a, b = _write(d, "a.json", sa), _write(d, "b.json", sb)
            policy = {**default_policy(), "require_full_surface_coverage": True}
            r = build_review(a, b, sa, sb, policy, True)
            self.assertNotEqual(r["decision"], "blocked_observation_insufficient")

    def test_no_diff_with_unobserved_surface_is_inconclusive_not_auto_clear(self):
        # Fail-closed default: kernel observed (fs/proc/tools sufficient) but network not observed,
        # and nothing changed; cannot certify "no new network", so inconclusive, not auto-clear,
        # even with the strict gate off.
        with tempfile.TemporaryDirectory() as d:
            # _surface({}) -> kernel present (fs/proc/tools sufficient), no network signal (unknown)
            sa, sb = _surface({}), _surface({})
            a, b = _write(d, "a.json", sa), _write(d, "b.json", sb)
            r = build_review(a, b, sa, sb, default_policy(), True)
            self.assertEqual(r["decision"], "inconclusive_observation_gap")

    def test_fully_observed_no_diff_auto_clears(self):
        # All surfaces observed (kernel complete + network connect_only), no diff: clean auto-clear.
        net = {"kernel_layer": "complete", "network_protocol_coverage": "connect_only"}
        with tempfile.TemporaryDirectory() as d:
            sa, sb = _surface(net), _surface(net)
            a, b = _write(d, "a.json", sa), _write(d, "b.json", sb)
            r = build_review(a, b, sa, sb, default_policy(), True)
            self.assertEqual(r["decision"], "auto_clear_no_new_capability")

    def test_partial_ringbuf_drops_does_not_auto_clear(self):
        # P1 repro: a lossy kernel capture with no diff must not silently auto-clear under
        # require_coverage; it falls through to human review with a warning.
        with tempfile.TemporaryDirectory() as d:
            lossy = {"observation_health": {"kernel_layer": "partial_ringbuf_drops"}}
            sa = {**_surface({}), **lossy}
            sb = {**_surface({}), **lossy}
            a, b = _write(d, "a.json", sa), _write(d, "b.json", sb)
            r = build_review(a, b, sa, sb, default_policy(), True)
            self.assertNotEqual(r["decision"], "auto_clear_no_new_capability")
            self.assertEqual(r["decision"], "pending")
            self.assertTrue(any("ring-buffer drops" in w for w in r["warnings"]))
            self.assertEqual(coverage_by_surface(sa)["filesystem"], "degraded")

    def test_strict_passes_when_network_observed(self):
        with tempfile.TemporaryDirectory() as d:
            sa, sb = _surface({"network_layer": "present"}), _surface({"network_layer": "present"})
            a, b = _write(d, "a.json", sa), _write(d, "b.json", sb)
            policy = {**default_policy(), "require_full_surface_coverage": True}
            r = build_review(a, b, sa, sb, policy, True)
            self.assertNotEqual(r["decision"], "blocked_observation_insufficient")

    def test_diagnostic_only_claim_scope_warns(self):
        with tempfile.TemporaryDirectory() as d:
            net = {
                "kernel_layer": "complete",
                "network_protocol_coverage": "connect_only",
                "network_endpoint_claim_scope": "diagnostic_only",
            }
            sa, sb = _surface(net), _surface(net)
            a, b = _write(d, "a.json", sa), _write(d, "b.json", sb)
            r = build_review(a, b, sa, sb, default_policy(), True)
            self.assertTrue(any("diagnostic-only" in w for w in r["warnings"]))

    def test_after_unobserved_surface_emits_honest_warning(self):
        with tempfile.TemporaryDirectory() as d:
            sa, sb = _surface({}), _surface({})
            a, b = _write(d, "a.json", sa), _write(d, "b.json", sb)
            r = build_review(a, b, sa, sb, default_policy(), True)
            self.assertTrue(any("cannot certify no undeclared network" in w for w in r["warnings"]))


if __name__ == "__main__":
    unittest.main()
