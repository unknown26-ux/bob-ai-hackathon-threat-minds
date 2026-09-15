"""
correlator.py — Groups normalized alerts into incidents using union-find.

Correlation rules:
  1. Same src_ip within WINDOW_MINUTES  → same incident
  2. Same indicator (regardless of time) → same incident

Time window: 10 minutes (configurable via WINDOW_MINUTES).
"""

from datetime import datetime, timezone
from typing import Any, Dict, List

WINDOW_MINUTES = 10


def _parse_ts(ts_str: str) -> datetime:
    try:
        return datetime.fromisoformat(str(ts_str).replace("Z", "+00:00"))
    except (ValueError, TypeError):
        return datetime.now(timezone.utc)


def correlate(alerts: List[Dict[str, Any]]) -> List[List[Dict[str, Any]]]:
    """
    Takes a flat list of normalized alert dicts.
    Returns a list of groups — each group becomes one incident.
    """
    n = len(alerts)
    parent = list(range(n))

    def find(i: int) -> int:
        while parent[i] != i:
            parent[i] = parent[parent[i]]
            i = parent[i]
        return i

    def union(i: int, j: int) -> None:
        ri, rj = find(i), find(j)
        if ri != rj:
            parent[ri] = rj

    # Rule 1: same src_ip within time window ----------------------------------
    by_ip: Dict[str, List[int]] = {}
    for idx, alert in enumerate(alerts):
        ip = alert.get("src_ip")
        if ip:
            by_ip.setdefault(ip, []).append(idx)

    for indices in by_ip.values():
        indices.sort(key=lambda i: _parse_ts(alerts[i].get("timestamp", "")))
        for k in range(len(indices) - 1):
            ta = _parse_ts(alerts[indices[k]].get("timestamp", ""))
            tb = _parse_ts(alerts[indices[k + 1]].get("timestamp", ""))
            if abs((tb - ta).total_seconds()) / 60 <= WINDOW_MINUTES:
                union(indices[k], indices[k + 1])

    # Rule 2: same indicator --------------------------------------------------
    by_indicator: Dict[str, List[int]] = {}
    for idx, alert in enumerate(alerts):
        ind = alert.get("indicator")
        if ind:
            by_indicator.setdefault(ind, []).append(idx)

    for indices in by_indicator.values():
        for k in range(len(indices) - 1):
            union(indices[k], indices[k + 1])

    # Build groups ------------------------------------------------------------
    groups: Dict[int, List[Dict[str, Any]]] = {}
    for idx, alert in enumerate(alerts):
        groups.setdefault(find(idx), []).append(alert)

    return list(groups.values())
