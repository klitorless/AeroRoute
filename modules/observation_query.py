"""Read-only observation query service. Qt-free.

Architecture Step 5: validates that the Observation layer is useful as
a cross-feature data boundary. A consumer asks "what observations
exist for this target?" and receives standardized observations without
knowing which producer emitted them:

    Ping ------+
    WHOIS -----+--> ObservationLog --> query --> observations
    SSL -------+

Strictly read-only: this module never mutates the ObservationLog,
never mutates observations, never rewrites or normalizes producer
data, and performs no analysis, correlation, deduplication, or
inference. It only selects and orders. Returned observations are the
original objects, with their original kind, source, target,
timestamp, data, and evidence.

Target matching is exact. Each producer normalizes its own targets
(whois lowercases and strips, ssl normalizes hostnames, ping uses the
caller-supplied target); the query layer does not normalize,
reinterpret, or merge targets. A global target-normalization system
is deliberately out of scope.

Ordering is chronological by observation timestamp. Observations
with identical timestamps keep their log insertion order, so results
are always deterministic.
"""
from __future__ import annotations


def query_observations(log, *, target=None, kind=None, source=None):
    """Return observations from `log` matching all given filters.

    `log` is any iterable of Observation (normally an ObservationLog).
    Each of `target`, `kind`, and `source` is optional; a filter that
    is None matches everything. Matching is exact — no normalization.

    Results are a new list in chronological timestamp order; ties
    keep log insertion order. The log and its observations are never
    modified.
    """
    matches = [
        (index, obs)
        for index, obs in enumerate(log)
        if (target is None or obs.target == target)
        and (kind is None or obs.kind == kind)
        and (source is None or obs.source == source)
    ]
    matches.sort(key=lambda pair: (pair[1].timestamp, pair[0]))
    return [obs for _, obs in matches]
