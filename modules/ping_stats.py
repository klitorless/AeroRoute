"""Ping statistics and probe scheduling. Qt-free so they can be unit tested.

Metric semantics (deliberate, documented here and in the README):
  - One bounded history of probe outcomes per target: each entry is
    (success, latency-or-None). Packet loss AND latency statistics are
    always computed from this same window, so they can never describe
    different time periods.
  - A failed probe NEVER contributes a latency sample. There is no fake
    "999 ms" placeholder: average/min/max are computed over successful
    samples only, and are None when no successful sample exists.
  - packet loss = failed probes / total probes, over the bounded window.
  - jitter = |latest successful latency - previous successful latency|
    ("last-sample jitter"). This is a simple consecutive-sample delta,
    NOT RFC 3550 interarrival jitter. It is cheap to compute per tick
    and honest about what it is.

Scheduling:
  - each monitored target carries an "inflight" flag; the scheduler only
    starts a probe when the target is active and no probe is outstanding,
    so a slow target can never stack up overlapping probes.

Observation emission (Architecture Step 2):
  - record_result() accepts an optional `sink`: any callable taking one
    Observation (for example ObservationLog.record bound to a caller-owned
    log). One Observation(kind="ping.probe", evidence=OBSERVED) is emitted
    per completed probe outcome.
  - The sink is dependency-injected, never a global: ping_stats stores no
    observations and knows no log. Callers that pass no sink behave
    exactly as before.
"""
from collections import deque

from .observation import EvidenceKind, Observation

WINDOW = 1000  # max probe outcomes retained per target


def new_target_state():
    """Initial per-target bookkeeping dict used by the ping monitor."""
    return {
        "active": True,
        "inflight": False,
        "probes": deque(maxlen=WINDOW),
        "curve": None,
    }


def record_result(state, success, latency, *, target=None, sink=None):
    """Record one probe outcome. Returns the metric dict for the UI.

    `target` is the normalized ping target the probe ran against (used
    only for observation emission). `sink` is an optional callable
    accepting one Observation — e.g. ObservationLog.record on a
    caller-owned log. When given, exactly one Observation
    (kind="ping.probe", source="ping", evidence=OBSERVED,
    data={"success": bool, "latency_ms": float-or-None}) is emitted per
    completed probe. Failed probes emit latency_ms=None, mirroring the
    probe history: failures never contribute latency samples.
    Callers without a sink behave exactly as before.
    """
    ok = bool(success)
    lat = latency if ok else None
    state["probes"].append((ok, lat))
    state["inflight"] = False
    if sink is not None:
        sink(Observation(
            kind="ping.probe",
            source="ping",
            target=target if target is not None else "",
            data={"success": ok, "latency_ms": lat},
            evidence=EvidenceKind.OBSERVED,
        ))
    return compute_metrics(state)


def successful_latencies(state):
    """Latencies of successful probes in the window, oldest first."""
    return [lat for ok, lat in state["probes"] if ok]


def compute_metrics(state):
    """Derive display metrics from the unified probe history. Pure."""
    probes = list(state["probes"])
    total = len(probes)
    fails = sum(1 for ok, _ in probes if not ok)
    loss = (fails / total * 100) if total else 0.0
    lat = [l for ok, l in probes if ok]
    if lat:
        avg = sum(lat) / len(lat)
        mn, mx = min(lat), max(lat)
        jitter = abs(lat[-1] - lat[-2]) if len(lat) > 1 else 0.0
        last = lat[-1]
    else:
        avg = mn = mx = last = None
        jitter = 0.0
    return {
        "avg": avg, "min": mn, "max": mx, "jitter": jitter,
        "loss": loss, "last": last, "samples": len(lat), "probes": total,
    }


def due_targets(stats):
    """Targets eligible for a new probe: active and none outstanding."""
    return [ip for ip, s in stats.items()
            if s.get("active") and not s.get("inflight")]


def mark_inflight(stats, ip):
    """Claim the probe slot. Returns False if the target is not due."""
    s = stats.get(ip)
    if not s or not s.get("active") or s.get("inflight"):
        return False
    s["inflight"] = True
    return True
