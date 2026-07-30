"""Mirrors correlate.go: produces a standalone correlation dataset for a
migrated project. Doesn't touch the new project's issues at all - their
existing pull is untouched; this only answers "if you already have an
issue's key/fingerprint, what was its real introduced date before the
migration?" so their own code can join the two datasets.
"""

from __future__ import annotations

from .client import SnykIssuesClient
from .models import SAST, CorrelatedIssue, MigrationCorrelation
from .resolver import LiveResolver


class Correlator:
    def __init__(self, issues_client: SnykIssuesClient, resolver: LiveResolver):
        self._issues_client = issues_client
        self._resolver = resolver

    async def correlate(self, org_id: str, project_id: str) -> MigrationCorrelation:
        """
        1. ask the resolver "did this project replace an older one?"
        2. if yes, pull the old project's open issues (their existing issues
           endpoint, just pointed at the old project ID)
        3. return them indexed by identity, nothing merged or assumed about
           what the caller does next.
        """
        result = MigrationCorrelation(new_org_id=org_id, new_project_id=project_id)

        match = await self._resolver.resolve_old_project(org_id, project_id)
        if match is None:
            return result

        old_org_id, old_project_id = match
        result.match_found = True
        result.old_org_id = old_org_id
        result.old_project_id = old_project_id

        old_issues = await self._issues_client.fetch_open_issues(old_org_id, old_project_id)

        for issue in old_issues:
            identity = issue.identity
            if not identity:
                continue  # no stable identity to join on (e.g. missing fingerprint) - skip
            identity_type = "fingerprint" if issue.type == SAST else "key"
            result.issues.append(
                CorrelatedIssue(
                    identity_type=identity_type,
                    identity=identity,
                    old_issue_id=issue.id,
                    old_org_id=old_org_id,
                    old_project_id=old_project_id,
                    old_created_at=issue.created_at,
                    old_last_introduced_at=issue.last_introduced_at,
                )
            )

        return result
