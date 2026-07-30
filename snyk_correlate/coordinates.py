"""Extract last_introduced_at from Issues API coordinates (not top-level attributes)."""

from __future__ import annotations

from datetime import datetime
from typing import List, Optional


def _parse_dt(value: Optional[str]) -> Optional[datetime]:
    if not value:
        return None
    s = value.replace("Z", "+00:00")
    if "." in s:
        dot = s.index(".")
        end = dot + 1
        while end < len(s) and s[end].isdigit():
            end += 1
        frac = s[dot + 1 : end]
        if frac:
            s = s[: dot + 1] + frac.ljust(6, "0")[:6] + s[end:]
    return datetime.fromisoformat(s)


def aggregate_last_introduced_at(
    coordinates: List[dict],
    *,
    use_min: bool = True,
) -> Optional[datetime]:
    """Aggregate coordinates[].last_introduced_at (grace-period default: earliest)."""
    times: List[datetime] = []
    for coord in coordinates or []:
        dt = _parse_dt(coord.get("last_introduced_at"))
        if dt is not None:
            times.append(dt)
    if not times:
        return None
    return min(times) if use_min else max(times)
