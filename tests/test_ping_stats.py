"""Tests for modules/ping_stats.py — unified probe window, metric semantics,
and probe scheduling."""
import pytest

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
