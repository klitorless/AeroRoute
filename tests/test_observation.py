"""Tests for modules/observation.py (Architecture Step 1).

The Observation model must stay domain-generic: DNS is only the first
producer, and these tests prove non-DNS kinds work without model changes.
Evidence classification must stay extensible, not boolean.

The model is a foundation: observations are frozen, `data` is defensively
copied and read-only at the top level, and `kind` is required.

The module is Qt-free; importing it must not pull in PyQt6.
"""
import dataclasses
import sys
import time
from types import MappingProxyType

import pytest

import modules.observation as observation_mod
from modules.observation import EvidenceKind, Observation, ObservationLog


class TestEvidenceKind:
    def test_distinguishes_observed_derived_inferred(self):
        assert EvidenceKind.OBSERVED.value == "observed"
        assert EvidenceKind.DERIVED.value == "derived"
        assert EvidenceKind.INFERRED.value == "inferred"
        assert len({EvidenceKind.OBSERVED, EvidenceKind.DERIVED,
                    EvidenceKind.INFERRED}) == 3

    def test_is_string_valued(self):
        # Extensible classification value: compares equal to plain strings,
        # so producers can pass "observed" without importing the enum.
        assert EvidenceKind.OBSERVED == "observed"
        assert isinstance(EvidenceKind.DERIVED, str)

    def test_not_a_boolean_model(self):
        # There must be more than two states; a boolean could not hold these.
        assert len(list(EvidenceKind)) >= 3


class TestObservation:
    def test_defaults(self):
        before = time.time()
        obs = Observation(source="dns_service", kind="dns.a_record",
                          target="example.com",
                          data={"addresses": ["93.184.216.34"]})
        after = time.time()
        assert before <= obs.timestamp <= after
        assert obs.evidence is EvidenceKind.OBSERVED

    def test_kind_is_required(self):
        with pytest.raises(TypeError):
            Observation()
        with pytest.raises(TypeError):
            Observation(source="dns_service")

    def test_evidence_coerced_from_string(self):
        obs = Observation(source="ping", kind="ping.rtt_sample",
                          target="8.8.8.8", data={"rtt_ms": 12.4},
                          evidence="derived")
        assert obs.evidence is EvidenceKind.DERIVED

    def test_evidence_accepts_enum_member(self):
        obs = Observation(kind="dns.a_record", evidence=EvidenceKind.INFERRED)
        assert obs.evidence is EvidenceKind.INFERRED

    def test_unknown_evidence_rejected(self):
        with pytest.raises(ValueError):
            Observation(kind="x.y", evidence="rumored")

    def test_invalid_evidence_type_rejected(self):
        # Only EvidenceKind or its string value is accepted; unrelated
        # types must fail loudly rather than be stored silently.
        for bad in (123, None, ["observed"], {"observed"}):
            with pytest.raises(TypeError):
                Observation(kind="x.y", evidence=bad)

    def test_data_must_be_dict(self):
        with pytest.raises(TypeError):
            Observation(kind="x.y", data=["not", "a", "dict"])

    def test_data_defensively_copied(self):
        # Mutating the caller's dict after construction must not alter
        # the observation (no aliasing).
        payload = {"addresses": ["93.184.216.34"]}
        obs = Observation(kind="dns.a_record", data=payload)
        payload["addresses"] = ["10.0.0.1"]
        payload["extra"] = True
        assert obs.data["addresses"] == ["93.184.216.34"]
        assert "extra" not in obs.data

    def test_data_top_level_immutable(self):
        obs = Observation(kind="dns.a_record",
                          data={"addresses": ["93.184.216.34"]})
        assert isinstance(obs.data, MappingProxyType)
        with pytest.raises(TypeError):
            obs.data["addresses"] = []
        with pytest.raises(TypeError):
            obs.data["new_key"] = "x"
        with pytest.raises(TypeError):
            del obs.data["addresses"]

    def test_data_default_not_shared(self):
        a = Observation(kind="x.y")
        b = Observation(kind="x.y")
        assert a.data == b.data == {}
        assert a.data is not b.data

    def test_immutable(self):
        obs = Observation(kind="dns.a_record")
        with pytest.raises(dataclasses.FrozenInstanceError):
            obs.kind = "dns.aaaa_record"


class TestDomainGeneric:
    def test_dns_a_record_shape(self):
        # DNS is the first producer: kind "dns.a_record", DNS-specific
        # fields live only in `data`, never in the model.
        obs = Observation(
            source="dns_service",
            kind="dns.a_record",
            target="example.com",
            data={"record_type": "A", "addresses": ["93.184.216.34"],
                  "ttl": 300},
            evidence=EvidenceKind.OBSERVED,
        )
        assert obs.data["addresses"] == ["93.184.216.34"]

    def test_future_producer_needs_no_model_change(self):
        # A non-DNS producer emits its own kind with its own data shape.
        obs = Observation(
            source="ping_monitor",
            kind="ping.rtt_sample",
            target="8.8.8.8",
            data={"rtt_ms": 12.4, "sequence": 42},
            evidence="derived",
        )
        assert obs.kind == "ping.rtt_sample"
        assert obs.evidence is EvidenceKind.DERIVED

    def test_inferred_kind_supported(self):
        obs = Observation(
            source="heuristic",
            kind="heuristic.port_scan_pattern",
            target="192.0.2.10",
            data={"ports_touched": 87, "window_s": 60},
            evidence="inferred",
        )
        assert obs.evidence is EvidenceKind.INFERRED

    def test_flow_endpoints_live_in_data(self):
        # Multi-endpoint relationships keep endpoint details in `data`
        # until a dedicated Flow domain model exists.
        obs = Observation(
            source="flow_probe",
            kind="flow.tcp_summary",
            target="192.0.2.10",
            data={"src": "192.0.2.10:4433", "dst": "203.0.113.7:443",
                  "bytes": 1024},
            evidence="derived",
        )
        assert obs.target == "192.0.2.10"
        assert obs.data["dst"] == "203.0.113.7:443"


class TestObservationLog:
    def _log_with_three(self):
        log = ObservationLog()
        log.record(Observation(source="dns_service", kind="dns.a_record",
                               target="example.com",
                               data={"addresses": ["93.184.216.34"]},
                               evidence="observed"))
        log.record(Observation(source="dns_service", kind="dns.mx_record",
                               target="example.com",
                               data={"exchanges": ["mail.example.com"]},
                               evidence="observed"))
        log.record(Observation(source="ping_monitor", kind="ping.rtt_sample",
                               target="8.8.8.8", data={"rtt_ms": 12.4},
                               evidence="derived"))
        return log

    def test_record_returns_observation_and_grows(self):
        log = ObservationLog()
        assert len(log) == 0
        obs = Observation(kind="dns.a_record")
        assert log.record(obs) is obs
        assert len(log) == 1

    def test_logged_observation_cannot_be_mutated(self):
        # A consumer holding a logged observation cannot alter its data.
        log = ObservationLog()
        obs = log.record(Observation(kind="dns.a_record",
                                     data={"ttl": 300}))
        with pytest.raises(TypeError):
            obs.data["ttl"] = 60
        assert log.by_kind("dns.a_record")[0].data["ttl"] == 300

    def test_iteration_preserves_insertion_order(self):
        log = self._log_with_three()
        kinds = [o.kind for o in log]
        assert kinds == ["dns.a_record", "dns.mx_record", "ping.rtt_sample"]

    def test_by_kind(self):
        log = self._log_with_three()
        assert [o.kind for o in log.by_kind("dns.a_record")] == ["dns.a_record"]

    def test_by_source(self):
        log = self._log_with_three()
        assert len(log.by_source("dns_service")) == 2
        assert len(log.by_source("ping_monitor")) == 1

    def test_by_target(self):
        log = self._log_with_three()
        assert len(log.by_target("example.com")) == 2
        assert len(log.by_target("8.8.8.8")) == 1
        assert log.by_target("no.such.host") == []

    def test_clear(self):
        log = self._log_with_three()
        log.clear()
        assert len(log) == 0
        assert list(log) == []

    def test_record_rejects_non_observation(self):
        log = ObservationLog()
        with pytest.raises(TypeError):
            log.record({"kind": "dns.a_record"})

    def test_in_memory_only(self):
        # No persistence hooks: no file/db attributes on the log.
        log = ObservationLog()
        assert not hasattr(log, "save")
        assert not hasattr(log, "load")
        assert not hasattr(log, "path")


class TestQtFree:
    def test_import_does_not_require_qt(self):
        assert "PyQt6" not in sys.modules
        assert "modules.observation" in sys.modules
