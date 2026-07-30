"""Mirrors client.go: the minimal interface Correlator needs for fetching issues."""

from __future__ import annotations

from typing import List, Protocol

from .models import Issue


class SnykIssuesClient(Protocol):
    """Implement against GET /orgs/{org_id}/issues (status=open, scan_item),
    plus GET /orgs/{org_id}/issues/detail/code/{key} per SAST issue to
    populate Issue.fingerprint (attributes.key is project-scoped for SAST
    and can't be used to match across a migration).
    """

    async def fetch_open_issues(self, org_id: str, project_id: str) -> List[Issue]: ...
