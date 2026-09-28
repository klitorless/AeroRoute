"""Tests for modules/ping_stats.py — unified probe window, metric semantics,
and probe scheduling."""
import json

import pytest

from modules.observation import EvidenceKind, ObservationLog
from modules.ping_stats import (
    WINDOW,
    compute_metrics,
    due_targets,
    mark_inflight,
    new_target_state,
    record_result,
    successful_latencies,
)


def _state_with(*latencies, fails=0):
    s = new_target_state()
    for lat in latencies:
        record_result(s, True, lat)
    for _ in range(fails):
        record_result(s, False, 0.0)
    return s


class TestUnifiedWindow:
    def test_successes_and_failures_share_one_history(self):
        s = _state_with(10.0, 20.0, fails=2)
        assert len(s["probes"]) == 4
        assert list(s["probes"]) == [
            (True, 10.0), (True, 20.0), (False, None), (False, None)]

    def test_old_probes_leave_the_window_together(self):
        # Fill the window with successes, then push failures in: the
        # evicted entries must be the oldest successes, and loss must
        # describe exactly the 1000 probes still in the window.
        s = new_target_state()
        for _ in range(WINDOW):
            record_result(s, True, 10.0)
        record_result(s, False, 0.0)
        record_result(s, False, 0.0)
        assert len(s["probes"]) == WINDOW
        m = compute_metrics(s)
        assert m["probes"] == WINDOW
        assert m["loss"] == pytest.approx(2 / WINDOW * 100)
        assert m["avg"] == pytest.approx(10.0)  # 998 remaining successes
        assert m["samples"] == WINDOW - 2

    def test_loss_and_latency_describe_same_probes(self):
        s = _state_with(10.0, 20.0, fails=2)
        m = compute_metrics(s)
        assert m["probes"] == 4
        assert m["loss"] == 50.0
        assert m["avg"] == pytest.approx(15.0)
        assert m["min"] == 10.0
        assert m["max"] == 20.0

    def test_failures_do_not_affect_avg_min_max(self):
        s = _state_with(10.0, 20.0)
        m = record_result(s, False, 0.0)
        assert m["avg"] == pytest.approx(15.0)
        assert m["min"] == 10.0
        assert m["max"] == 20.0

    def test_jitter_uses_successful_samples(self):
        # A failure between two successes must not disturb the jitter:
        # |30 - 10| = 20, not anything involving the failed probe.
        s = new_target_state()
        record_result(s, True, 10.0)
        record_result(s, False, 0.0)
        m = record_result(s, True, 30.0)
        assert m["jitter"] == pytest.approx(20.0)

    def test_all_failure_window_has_no_latency_stats(self):
        s = new_target_state()
        m = record_result(s, False, 0.0)
        m = record_result(s, False, 0.0)
        assert m["avg"] is None
        assert m["min"] is None
        assert m["max"] is None
        assert m["last"] is None
        assert m["loss"] == 100.0

    def test_window_limit_enforced(self):
        s = new_target_state()
        for i in range(WINDOW + 200):
            if i % 2:
                record_result(s, True, float(i))
            else:
                record_result(s, False, 0.0)
        assert len(s["probes"]) == WINDOW
        m = compute_metrics(s)
        assert m["probes"] == WINDOW
        # The last 1000 probes contain exactly 500 failures.
        assert m["loss"] == 50.0


class TestMetrics:
    def test_basic_stats(self):
        m = compute_metrics(_state_with(10.0, 20.0, 30.0))
        assert m["avg"] == pytest.approx(20.0)
        assert m["min"] == 10.0
        assert m["max"] == 30.0
        assert m["loss"] == 0.0

    def test_failed_probe_does_not_invent_latency(self):
        # No fake "999 ms" placeholder: a failed probe affects loss only.
        s = _state_with(10.0, 20.0)
        m = record_result(s, False, 0.0)
        assert m["avg"] == pytest.approx(15.0)
        assert m["loss"] == pytest.approx(100 / 3)

    def test_empty_state(self):
        m = compute_metrics(new_target_state())
        assert m["avg"] is None
        assert m["loss"] == 0.0
        assert m["probes"] == 0

    def test_loss_over_mixed_probes(self):
        s = _state_with(10.0, fails=3)  # 1 success + 3 failures
        m = compute_metrics(s)
        assert m["loss"] == 75.0
        assert m["avg"] == pytest.approx(10.0)

    def test_jitter_is_consecutive_successful_delta(self):
        # Documented definition: |latest successful - previous successful|,
        # NOT RFC 3550 interarrival jitter.
        s = _state_with(10.0, 30.0)
        m = compute_metrics(s)
        assert m["jitter"] == pytest.approx(20.0)

    def test_jitter_single_sample_is_zero(self):
        m = compute_metrics(_state_with(10.0))
        assert m["jitter"] == 0.0

    def test_successful_latencies_helper(self):
        s = _state_with(10.0, 20.0, fails=1)
        assert successful_latencies(s) == [10.0, 20.0]


class TestScheduling:
    def test_due_when_active_and_free(self):
        s = new_target_state()
        assert due_targets({"1.1.1.1": s}) == ["1.1.1.1"]

    def test_not_due_when_inflight(self):
        s = new_target_state()
        assert mark_inflight({"1.1.1.1": s}, "1.1.1.1") is True
        assert due_targets({"1.1.1.1": s}) == []

    def test_result_clears_inflight(self):
        stats = {"1.1.1.1": new_target_state()}
        mark_inflight(stats, "1.1.1.1")
        record_result(stats["1.1.1.1"], True, 5.0)
        assert due_targets(stats) == ["1.1.1.1"]

    def test_not_due_when_paused(self):
        s = new_target_state()
        s["active"] = False
        assert due_targets({"1.1.1.1": s}) == []
        assert mark_inflight({"1.1.1.1": s}, "1.1.1.1") is False

    def test_mark_inflight_unknown_target(self):
        assert mark_inflight({}, "9.9.9.9") is False

    def test_no_double_claim(self):
        stats = {"1.1.1.1": new_target_state()}
        assert mark_inflight(stats, "1.1.1.1") is True
        assert mark_inflight(stats, "1.1.1.1") is False  # already outstanding


class TestPingProbeObservations:
    """Architecture Step 2: completed ping probes optionally emit one
    Observation(kind="ping.probe", evidence=OBSERVED) per outcome via an
    injected sink. Existing behavior without a sink must not change."""

    def test_no_sink_preserves_behavior(self):
        plain = new_target_state()
        observed = new_target_state()
        log = ObservationLog()
        m_plain = record_result(plain, True, 12.5)
        m_observed = record_result(observed, True, 12.5,
                                   target="10.0.0.1", sink=log.record)
        assert m_plain == m_observed
        assert list(plain["probes"]) == list(observed["probes"])
        assert len(log) == 1  # sink path only adds emission, nothing else

    def test_successful_probe_emits_observation(self):
        log = ObservationLog()
        record_result(new_target_state(), True, 12.5,
                      target="10.0.0.1", sink=log.record)
        assert len(log) == 1
        obs = log.by_kind("ping.probe")[0]
        assert obs.kind == "ping.probe"
        assert obs.source == "ping"
        assert obs.target == "10.0.0.1"
        assert obs.evidence is EvidenceKind.OBSERVED
        assert dict(obs.data) == {"success": True, "latency_ms": 12.5}
        json.dumps(dict(obs.data))  # payload stays JSON-friendly

    def test_failed_probe_emits_null_latency(self):
        log = ObservationLog()
        # Callers pass 0.0 for failed probes; the observation must still
        # carry null, never a fake latency value.
        record_result(new_target_state(), False, 0.0,
                      target="10.0.0.2", sink=log.record)
        assert len(log) == 1
        obs = log.by_kind("ping.probe")[0]
        assert obs.evidence is EvidenceKind.OBSERVED
        assert dict(obs.data) == {"success": False, "latency_ms": None}

    def test_repeated_probes_emit_in_order(self):
        log = ObservationLog()
        s = new_target_state()
        record_result(s, True, 10.0, target="10.0.0.1", sink=log.record)
        record_result(s, False, 0.0, target="10.0.0.1", sink=log.record)
        record_result(s, True, 30.0, target="10.0.0.1", sink=log.record)
        assert [dict(o.data) for o in log] == [
            {"success": True, "latency_ms": 10.0},
            {"success": False, "latency_ms": None},
            {"success": True, "latency_ms": 30.0},
        ]
        # Derived metrics still come from the unified window, unaffected
        # by the observation path.
        m = compute_metrics(s)
        assert m["avg"] == pytest.approx(20.0)
        assert m["loss"] == pytest.approx(100 / 3)

    def test_emitted_data_not_aliased_to_internal_state(self):
        log = ObservationLog()
        s = new_target_state()
        record_result(s, True, 10.0, target="10.0.0.1", sink=log.record)
        first = log.by_kind("ping.probe")[0]
        # Later probes must not alter the already-emitted observation.
        record_result(s, True, 99.0, target="10.0.0.1", sink=log.record)
        record_result(s, False, 0.0, target="10.0.0.1", sink=log.record)
        assert dict(first.data) == {"success": True, "latency_ms": 10.0}
        # Consumers cannot mutate the logged observation's top-level data.
        with pytest.raises(TypeError):
            first.data["latency_ms"] = 0.0

    def test_sink_is_caller_owned_not_global(self):
        log_a, log_b = ObservationLog(), ObservationLog()
        record_result(new_target_state(), True, 5.0,
                      target="10.0.0.1", sink=log_a.record)
        record_result(new_target_state(), True, 6.0,
                      target="10.0.0.2", sink=log_b.record)
        assert len(log_a) == 1 and log_a.by_target("10.0.0.1")
        assert len(log_b) == 1 and log_b.by_target("10.0.0.2")

    def test_target_defaults_to_empty_without_target(self):
        log = ObservationLog()
        record_result(new_target_state(), True, 5.0, sink=log.record)
        assert log.by_kind("ping.probe")[0].target == ""
