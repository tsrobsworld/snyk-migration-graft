"""Mirrors resolver.go: finds a project's predecessor by matching repo
identity live, every call - no precomputed report, no file dependency.
"""

from __future__ import annotations

from typing import List, Optional, Protocol, Tuple

from .matching import repo_key
from .models import ProjectSummary


class ProjectsClient(Protocol):
    """Implement against GET /orgs/{org_id}/projects (or the Targets API) -
    real Snyk API access, not a file.
    """

    async def list_projects(self, org_id: str) -> List[ProjectSummary]: ...


class LiveResolver:
    """Ports the matching rule directly: normalize attributes.url (SCM) or
    attributes.display_name (CLI) down to "org/repo", ignoring hostname,
    and look for another project in the org sharing that key *and* the same
    product (SCA vs SAST) - a repo can have both, and they migrate/version
    independently.

    NOTE: only searches within org_id today. If migrations can move a repo
    to a different org (group-scoped), extend ProjectsClient to list across
    the group and search there too - same caveat as the Go version.
    """

    def __init__(self, projects_client: ProjectsClient):
        self._projects_client = projects_client

    async def resolve_old_project(
        self, org_id: str, project_id: str
    ) -> Optional[Tuple[str, str]]:
        """Returns (old_org_id, old_project_id), or None if no predecessor found."""
        all_projects = await self._projects_client.list_projects(org_id)

        self_project = next((p for p in all_projects if p.project_id == project_id), None)
        if self_project is None:
            raise ValueError(f"project {project_id} not found in org {org_id}")

        self_key = repo_key(self_project)
        if not self_key:
            return None  # no repo/display_name to match on

        best: Optional[ProjectSummary] = None
        for candidate in all_projects:
            if candidate.project_id == project_id:
                continue
            if candidate.product != self_project.product:
                continue  # SCA and SAST migrate/version independently
            if repo_key(candidate) != self_key:
                continue
            if candidate.created_at is None or self_project.created_at is None:
                continue
            if candidate.created_at >= self_project.created_at:
                continue  # only interested in projects that predate this one
            if best is None or candidate.created_at < best.created_at:
                best = candidate

        if best is None:
            return None
        return best.org_id, best.project_id
