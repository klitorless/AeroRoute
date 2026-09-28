"""Tests for modules/observation_query.py (Architecture Step 5).

The query layer is a read-only consumer over ObservationLog: it
selects and orders observations without mutating anything and
without knowing producer implementations. The cross-feature test
populates one log through the real ping and WHOIS producer entry
points (plus an ssl.connection observation as emitted by
perform_ssl_scan) and retrieves them together by target alone.

Target matching is exact: normalization is each producer's job, and
the query layer must not reinterpret targets.

The module is Qt-free; importing it must not pull in PyQt6.
"""
import sys
import time

import modules.observation_query as query_mod
from modules.observation import EvidenceKind, Observation, ObservationLog
from modules.observation_query import query_observations
from modules.ping_stats import new_target_state, record_result
from modules.whois_service import perform_whois


def _fake_whois_query(server, query, timeout=10):
    return f"domain: {query}\n"


def _log_with_mixed_observations():
    """One log, two targets, three producers — the Step 5 scenario."""
    log = ObservationLog()
    # ping.probe via the real producer entry point.
    state = new_target_state()
    record_result(state, True, 12.4, target="8.8.8.8", sink=log.record)
    record_result(state, False, 0.0, target="8.8.8.8", sink=log.record)
    # whois.lookup via the real producer entry point (faked network).
    perform_whois("8.8.8.8", query_fn=_fake_whois_query, sink=log.record)
    # ssl.connection as emitted by perform_ssl_scan.
    log.record(Observation(
        kind="ssl.connection",
        source="ssl",
        target="8.8.8.8",
        data={"host": "8.8.8.8", "port": 443,
              "tls_version": "TLSv1.3",
              "cipher_suite": "TLS_AES_256_GCM_SHA384",
              "cipher_bits": 256},
        evidence=EvidenceKind.OBSERVED,
    ))
    # Noise for a different target.
    log.record(Observation(kind="ping.probe", source="ping",
                           target="example.com",
                           data={"success": True, "latency_ms": 3.1},
                           evidence=EvidenceKind.OBSERVED))
    return log


class TestEmptyLog:
    def test_empty_log_returns_empty_result(self):
        assert query_observations(ObservationLog()) == []
        assert query_observations(ObservationLog(), target="8.8.8.8") == []


class TestTargetFiltering:
    def test_returns_only_matching_target(self):
        log = _log_with_mixed_observations()
        results = query_observations(log, target="8.8.8.8")
        assert len(results) == 4
        assert all(o.target == "8.8.8.8" for o in results)

    def test_unknown_target_returns_empty(self):
        log = _log_with_mixed_observations()
        assert query_observations(log, target="no.such.host") == []

    def test_matching_is_exact_not_normalized(self):
        # Normalization is the producer's job; the query layer must
        # not reinterpret targets.
        log = ObservationLog()
        log.record(Observation(kind="ping.probe", source="ping",
                               target="example.com",
                               data={"success": True},
                               evidence=EvidenceKind.OBSERVED))
        assert query_observations(log, target="Example.COM") == []
        assert len(query_observations(log, target="example.com")) == 1


class TestCrossFeature:
    def test_multiple_kinds_for_one_target_returned_together(self):
        # The consumer knows nothing about producers: one target
        # query returns ping, whois, and ssl observations together.
        log = _log_with_mixed_observations()
        kinds = sorted(o.kind for o in query_observations(log,
                                                          target="8.8.8.8"))
        assert kinds == ["ping.probe", "ping.probe",
                         "ssl.connection", "whois.lookup"]


class TestKindFiltering:
    def test_kind_filter(self):
        log = _log_with_mixed_observations()
        results = query_observations(log, kind="ping.probe")
        assert len(results) == 3
        assert all(o.kind == "ping.probe" for o in results)

    def test_kind_filter_with_target(self):
        log = _log_with_mixed_observations()
        results = query_observations(log, target="8.8.8.8",
                                     kind="whois.lookup")
        assert len(results) == 1
        assert results[0].source == "whois"


class TestSourceFiltering:
    def test_source_filter(self):
        log = _log_with_mixed_observations()
        results = query_observations(log, source="ssl")
        assert len(results) == 1
        assert results[0].kind == "ssl.connection"

    def test_combined_filters(self):
        log = _log_with_mixed_observations()
        results = query_observations(log, target="8.8.8.8",
                                     kind="ping.probe", source="ping")
        assert len(results) == 2
        assert query_observations(log, target="8.8.8.8",
                                  kind="ping.probe",
                                  source="whois") == []


class TestOrdering:
    def test_chronological_order(self):
        log = ObservationLog()
        log.record(Observation(kind="a", timestamp=30.0))
        log.record(Observation(kind="b", timestamp=10.0))
        log.record(Observation(kind="c", timestamp=20.0))
        assert [o.kind for o in query_observations(log)] == ["b", "c", "a"]

    def test_identical_timestamps_keep_insertion_order(self):
        log = ObservationLog()
        for kind in ("first", "second", "third"):
            log.record(Observation(kind=kind, timestamp=5.0))
        first = [o.kind for o in query_observations(log)]
        second = [o.kind for o in query_observations(log)]
        assert first == ["first", "second", "third"]
        assert second == first  # deterministic across queries


class TestReadOnly:
    def test_query_does_not_mutate_log(self):
        log = _log_with_mixed_observations()
        before = list(log)
        query_observations(log, target="8.8.8.8")
        query_observations(log, kind="ping.probe")
        assert list(log) == before
        assert len(log) == len(before)

    def test_mutating_result_list_does_not_affect_log(self):
        log = _log_with_mixed_observations()
        results = query_observations(log, target="8.8.8.8")
        results.clear()
        results.append("junk")
        assert len(log) == 5
        assert len(query_observations(log, target="8.8.8.8")) == 4

    def test_query_does_not_mutate_stored_data(self):
        log = _log_with_mixed_observations()
        snapshot = [(o.kind, dict(o.data)) for o in log]
        query_observations(log, target="8.8.8.8")
        query_observations(log)
        assert [(o.kind, dict(o.data)) for o in log] == snapshot
        again = query_observations(log, target="8.8.8.8",
                                   kind="ping.probe")
        assert again[0].data == {"success": True, "latency_ms": 12.4}

    def test_independent_queries_do_not_interfere(self):
        log = _log_with_mixed_observations()
        by_target = query_observations(log, target="8.8.8.8")
        by_kind = query_observations(log, kind="ssl.connection")
        assert len(by_target) == 4
        assert len(by_kind) == 1
        # Re-running either query is unaffected by the other.
        assert len(query_observations(log, target="8.8.8.8")) == 4
        assert len(query_observations(log, kind="ssl.connection")) == 1


class TestEvidencePreserved:
    def test_returns_original_observations_untouched(self):
        log = ObservationLog()
        original = Observation(
            kind="heuristic.port_scan_pattern",
            source="heuristic",
            target="192.0.2.10",
            timestamp=1234.5,
            data={"ports_touched": 87},
            evidence=EvidenceKind.INFERRED,
        )
        log.record(original)
        (found,) = query_observations(log, target="192.0.2.10")
        assert found is original
        assert found.evidence is EvidenceKind.INFERRED
        assert found.data == {"ports_touched": 87}
        assert found.timestamp == 1234.5


class TestQtFree:
    def test_import_does_not_require_qt(self):
        assert "PyQt6" not in sys.modules
        assert "modules.observation_query" in sys.modules
