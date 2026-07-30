"""Resolve repo scope for a single project via Projects API + target."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Optional, TYPE_CHECKING

from .coordinates import _parse_dt
from .matching import normalize_display_name, normalize_repo_url, repo_key as matching_repo_key
from .models import ProjectSummary

if TYPE_CHECKING:
    from .snykapi import SnykClient


@dataclass
class ProjectRepoScope:
    org_id: str
    project_id: str
    product: str  # sca | sast
    repo_key: str
    display_name_query: str
    project_name: Optional[str] = None


def project_summary_from_api(org_id: str, project: dict, target_attrs: dict) -> ProjectSummary:
    attrs = project.get("attributes", {})
    project_type = attrs.get("type", "")
    product = "sast" if project_type == "sast" else "sca"
    created = _parse_dt(attrs.get("created_at") or attrs.get("created"))
    return ProjectSummary(
        org_id=org_id,
        project_id=project["id"],
        product=product,
        integration_type=attrs.get("origin"),
        repo_url=target_attrs.get("url"),
        display_name=target_attrs.get("display_name"),
        created_at=created,
    )


async def fetch_project_repo_scope(
    client: "SnykClient",
    org_id: str,
    project_id: str,
    api_version: str,
    retry: int = 3,
) -> Optional[ProjectRepoScope]:
    params = {"version": api_version, "expand": "target"}
    pages = await client.get_snyk_api_async(
        f"rest/orgs/{org_id}/projects/{project_id}",
        params,
        retry=retry,
    )
    if not pages:
        return None
    page = pages[0]
    data = page.get("data")
    if isinstance(data, list):
        project = data[0] if data else None
    else:
        project = data
    if not project:
        return None

    target_attrs = (
        project.get("relationships", {})
        .get("target", {})
        .get("data", {})
        .get("attributes", {})
    )
    if not target_attrs:
        for item in page.get("included", []):
            if item.get("type") == "target":
                target_attrs = item.get("attributes", {})
                break

    summary = project_summary_from_api(org_id, project, target_attrs)
    key = matching_repo_key(summary)
    if not key:
        name = (project.get("attributes") or {}).get("name") or ""
        key = normalize_display_name(name.split(":")[0]) if name else ""
    if not key:
        return None

    display_query = (target_attrs.get("display_name") or "").strip("/") or key
    return ProjectRepoScope(
        org_id=org_id,
        project_id=project_id,
        product=summary.product,
        repo_key=key,
        display_name_query=display_query,
        project_name=(project.get("attributes") or {}).get("name"),
    )
