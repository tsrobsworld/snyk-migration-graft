"""Extract last_introduced_at from Issues API coordinates (not top-level attributes)."""

from __future__ import annotations

from datetime import datetime, timezone
from typing import List, Optional, Union


def to_iso_z(value: Optional[Union[str, datetime]]) -> Optional[str]:
    """Canonical wire form for every ``issue_*`` timestamp column: UTC,
    milliseconds, ``Z`` - i.e. exactly what the Snyk API emits.

    These columns are fed from three places that disagree on format: raw API
    strings (Snyk emits a variable number of fractional digits - ``.454Z`` on
    one project, ``.41Z`` on another), and ``datetime.isoformat()`` from the
    coordinate aggregation and from the migration graft (``+00:00``, 6 digits).
    Without a single serializer, ``issue_created_at`` silently changes format
    depending on whether the row grafted.

    Sub-millisecond precision is truncated; the Issues API does not emit it.
    """
    if isinstance(value, datetime):
        dt: Optional[datetime] = value
    elif isinstance(value, str):
        dt = _parse_dt(value)
    else:
        return None  # None, NaN, NaT, anything unexpected
    if dt is None or dt != dt:  # NaT is a datetime but never equals itself
        return None
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    dt = dt.astimezone(timezone.utc)
    return f"{dt:%Y-%m-%dT%H:%M:%S}.{dt.microsecond // 1000:03d}Z"


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
