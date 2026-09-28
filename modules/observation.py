"""Domain-generic observation model and in-memory observation log. Qt-free.

Architecture Step 1: producers (DNS, ping, WHOIS, ...) emit Observation
records describing what they saw or computed. The model is deliberately
domain-agnostic: no field encodes DNS-specific — or any producer-specific —
assumptions. A producer names what it emits via `kind` (for example
"dns.a_record"); future producers add their own kinds without modifying
this module.

Conventions for producers:

- `source` and `kind` use dotted namespaces where appropriate
  (for example source "dns_service", kind "dns.a_record").
- `kind` identifies the type of observation and is required: an
  Observation without a kind cannot be constructed.
- `target` identifies the primary subject of the observation
  (a hostname, IP address, URL, ...).
- Multi-endpoint relationships (for example future network flows with a
  source and a destination) keep endpoint details inside `data` until a
  dedicated Flow domain model exists.
- The ObservationLog holds curated, normalized observations — not raw
  high-rate streams. High-rate producers (for example packet capture)
  aggregate before emitting observations.

Evidence classification is an extensible value, not a boolean:

  observed — something was directly returned or witnessed
             ("DNS returned this address.")
  derived  — something computed from probe results
             ("These probe results produce this calculated metric.")
  inferred — something suggested by a pattern
             ("This pattern may indicate an anomaly.")

New classifications can be added to EvidenceKind without changing the
Observation model. No larger evidence framework is built here.

Immutability boundary: Observation instances are frozen and `data` is
defensively copied and exposed as a read-only mapping view at the top
level. Producer-side mutation (or aliasing) of the input dict after
construction cannot alter the observation, and consumers cannot mutate a
logged observation's top-level data. Nested structures inside `data` are
NOT recursively frozen — keeping nested payloads immutable remains the
producer's responsibility.
"""
from __future__ import annotations

import time
from dataclasses import dataclass, field
from enum import Enum
from types import MappingProxyType


class EvidenceKind(str, Enum):
    """How an observation's data came to be. Extensible: add members."""
    OBSERVED = "observed"
    DERIVED = "derived"
    INFERRED = "inferred"


@dataclass(frozen=True)
class Observation:
    """One domain-generic observation emitted by a producer.

    kind:      namespaced kind, e.g. "dns.a_record". Required. New kinds
               require no model changes.
    timestamp: epoch seconds (UTC); defaults to now.
    source:    producer identity, e.g. "dns_service". Optional.
    target:    the primary subject of the observation, e.g. a hostname
               or IP.
    data:      structured producer-specific payload (JSON-friendly dict).
               Defensively copied and exposed read-only at the top level;
               nested structures are the producer's responsibility.
    evidence:  EvidenceKind, or its string value; validated, not boolean.
    """
    kind: str
    timestamp: float = field(default_factory=time.time)
    source: str = ""
    target: str = ""
    data: dict = field(default_factory=dict)
    evidence: EvidenceKind = EvidenceKind.OBSERVED

    def __post_init__(self):
        evidence = self.evidence
        if isinstance(evidence, EvidenceKind):
            pass
        elif isinstance(evidence, str):
            try:
                object.__setattr__(self, "evidence", EvidenceKind(evidence))
            except ValueError:
                raise ValueError(
                    f"unknown evidence classification: {evidence!r}"
                ) from None
        else:
            raise TypeError(
                "observation evidence must be EvidenceKind or str, "
                f"got {type(evidence).__name__}"
            )
        if not isinstance(self.data, dict):
            raise TypeError(
                f"observation data must be a dict, got {type(self.data).__name__}"
            )
        # Defensive copy wrapped in a read-only view: the caller's dict
        # cannot alias-mutate the observation afterwards, and consumers
        # cannot mutate a logged observation's top-level data.
        object.__setattr__(self, "data", MappingProxyType(dict(self.data)))


class ObservationLog:
    """In-memory, append-only collection of observations.

    Deliberately not persistent: no files, no database. Holds curated,
    normalized observations — not raw high-rate streams. Query helpers are
    thin filters over the in-memory list.
    """

    def __init__(self):
        self._observations = []

    def record(self, obs):
        """Append one Observation. Returns it, for chaining."""
        if not isinstance(obs, Observation):
            raise TypeError(
                f"can only record Observation, got {type(obs).__name__}"
            )
        self._observations.append(obs)
        return obs

    def __len__(self):
        return len(self._observations)

    def __iter__(self):
        return iter(self._observations)

    def clear(self):
        """Drop all recorded observations."""
        self._observations.clear()

    def by_kind(self, kind):
        """Observations with this exact kind, oldest first."""
        return [o for o in self._observations if o.kind == kind]

    def by_source(self, source):
        """Observations from this producer, oldest first."""
        return [o for o in self._observations if o.source == source]

    def by_target(self, target):
        """Observations about this target, oldest first."""
        return [o for o in self._observations if o.target == target]
