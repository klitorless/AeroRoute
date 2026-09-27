"""Ping statistics and probe scheduling. Qt-free so they can be unit tested.

Metric semantics (deliberate, documented here and in the README):
  - A failed probe NEVER contributes a latency sample. There is no fake
    "999 ms" placeholder: average/min/max are computed over successful
    samples only, and are None when no successful sample exists.
  - packet loss = failed probes / total probes, over a bounded window.
  - jitter = |latest sample - previous sample| ("last-sample jitter").
    This is a simple consecutive-sample delta, NOT RFC 3550 interarrival
    jitter. It is cheap to compute per tick and honest about what it is.

Scheduling:
  - each monitored target carries an "inflight" flag; the scheduler only
    starts a probe when the target is active and no probe is outstanding,
    so a slow target can never stack up overlapping probes.
"""
from collections import deque

WINDOW = 1000  # max samples retained per target


def new_target_state():
    """Initial per-target bookkeeping dict used by the ping monitor."""
    return {
        "active": True,
        "inflight": False,
        "latencies": deque(maxlen=WINDOW),
        "failures": deque(maxlen=WINDOW),
        "curve": None,
    }


def record_result(state, success, latency):
    """Record one probe outcome. Returns the metric dict for the UI."""
    state["failures"].append(not success)
    if success:
        state["latencies"].append(latency)
    state["inflight"] = False
    return compute_metrics(state)


def compute_metrics(state):
    """Derive display metrics from raw samples. Pure function."""
    lat = list(state["latencies"])
    fails = list(state["failures"])
    total = len(fails)
    loss = (sum(fails) / total * 100) if total else 0.0
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
