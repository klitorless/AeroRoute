"""Tests for modules/ping_stats.py — metric semantics and probe scheduling."""
import pytest

from modules.ping_stats import (
    WINDOW,
    compute_metrics,
    due_targets,
    mark_inflight,
    new_target_state,
    record_result,
)


def _state_with(*latencies, fails=0):
    s = new_target_state()
    for lat in latencies:
        record_result(s, True, lat)
    for _ in range(fails):
        record_result(s, False, 0.0)
    return s


class TestMetrics:
    def test_basic_stats(self):
        m = compute_metrics(_state_with(10.0, 20.0, 30.0))
        assert m["avg"] == pytest.approx(20.0)
        assert m["min"] == 10.0
        assert m["max"] == 30.0
        assert m["loss"] == 0.0

    def test_failed_probe_does_not_corrupt_latency(self):
        # The old code displayed avg=999 on failure. A failed probe must
        # affect loss only — latency stats come from successes alone.
        s = _state_with(10.0, 20.0)
        m = record_result(s, False, 0.0)
        assert m["avg"] == pytest.approx(15.0)
        assert m["min"] == 10.0
        assert m["max"] == 20.0
        assert m["loss"] == pytest.approx(100 / 3)

    def test_all_failed_means_no_latency_stats(self):
        s = new_target_state()
        m = record_result(s, False, 0.0)
        assert m["avg"] is None
        assert m["min"] is None
        assert m["max"] is None
        assert m["loss"] == 100.0

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

    def test_jitter_is_consecutive_delta(self):
        # Documented definition: |latest - previous| sample delta,
        # NOT RFC 3550 interarrival jitter.
        s = _state_with(10.0, 30.0)
        m = compute_metrics(s)
        assert m["jitter"] == pytest.approx(20.0)

    def test_jitter_single_sample_is_zero(self):
        m = compute_metrics(_state_with(10.0))
        assert m["jitter"] == 0.0

    def test_window_bounded(self):
        s = new_target_state()
        for i in range(WINDOW + 100):
            record_result(s, True, float(i))
        assert len(s["latencies"]) <= WINDOW


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
