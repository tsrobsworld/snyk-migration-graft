"""Batch migration cache + dataframe graft (SCA & SAST).

Maps new issue_id (live) to issue_legacy_id (predecessor project) via stable
identity (SCA key / SAST fingerprint).
"""

from __future__ import annotations

import asyncio
from dataclasses import dataclass, field
from datetime import datetime
from typing import Dict, Iterable, List, Optional, Tuple

import pandas as pd

from .models import SAST, SCA
from .project_scope import fetch_project_repo_scope
from .resolver import LiveResolver
from .snykapi import SnykApiIssuesClient, SnykApiProjectsClient, SnykClient


def _iso(dt: Optional[datetime]) -> Optional[str]:
    if dt is None:
        return None
    return dt.isoformat()


@dataclass
class OldIssueSnapshot:
    issue_id: str
    created_at: Optional[str]
    updated_at: Optional[str]
    last_introduced_at: Optional[str]


@dataclass
class ProjectMigrationIndex:
    old_org_id: str
    old_project_id: str
    by_identity: Dict[str, OldIssueSnapshot] = field(default_factory=dict)


MigrationProjectCache = Dict[Tuple[str, str], Optional[ProjectMigrationIndex]]


def is_sast_issue_type(issue_type: Optional[str]) -> bool:
    return (issue_type or "").strip().lower() in {SAST, "code", "sast"}


def migration_identity_from_row(row) -> Optional[str]:
    if is_sast_issue_type(row.get("issue_type")):
        fp = row.get("issue_fingerprint")
        return str(fp).strip() if fp else None
    key = row.get("issue_key")
    return str(key).strip() if key else None


async def build_migration_cache(
    client: SnykClient,
    project_keys: Iterable[Tuple[str, str]],
    *,
    api_version: str = "2024-10-15",
    issues_api_version: str = "2024-05-08",
    code_issue_detail_api_version: str = "2024-10-14~experimental",
    retry: int = 3,
    concurrent_projects: int = 5,
) -> MigrationProjectCache:
    unique = list({(o, p) for o, p in project_keys if o and p})
    sem = asyncio.Semaphore(concurrent_projects)
    cache: MigrationProjectCache = {}

    async def load_one(org_id: str, project_id: str) -> None:
        async with sem:
            scope = await fetch_project_repo_scope(client, org_id, project_id, api_version, retry)
            if scope is None:
                cache[(org_id, project_id)] = None
                return

            projects_client = SnykApiProjectsClient(
                client,
                api_version=api_version,
                retry=retry,
                display_name=scope.display_name_query if not scope.repo_key else None,
                repo_url=scope.repo_key or None,
            )
            resolver = LiveResolver(projects_client)
            try:
                match = await resolver.resolve_old_project(org_id, project_id)
            except ValueError:
                cache[(org_id, project_id)] = None
                return
            if match is None:
                cache[(org_id, project_id)] = None
                return

            old_org_id, old_project_id = match
            issues_client = SnykApiIssuesClient(
                client,
                issues_api_version=issues_api_version,
                code_issue_detail_api_version=code_issue_detail_api_version,
                retry=retry,
            )
            old_issues = await issues_client.fetch_open_issues(
                old_org_id, old_project_id, product=scope.product
            )
            index = ProjectMigrationIndex(old_org_id=old_org_id, old_project_id=old_project_id)
            for iss in old_issues:
                ident = iss.identity
                if not ident:
                    continue
                index.by_identity[ident] = OldIssueSnapshot(
                    issue_id=iss.id,
                    created_at=_iso(iss.created_at),
                    updated_at=_iso(iss.updated_at),
                    last_introduced_at=_iso(iss.last_introduced_at),
                )
            cache[(org_id, project_id)] = index

    await asyncio.gather(*(load_one(o, p) for o, p in unique))
    return cache


def apply_migration_graft_row(
    row,
    cache: MigrationProjectCache,
    *,
    graft_predecessor_issue_id: bool = False,
) -> dict:
    """Returns column overrides.

    Default: live ``issue_id`` unchanged; predecessor id in ``issue_legacy_id``.
    When ``graft_predecessor_issue_id=True`` on a match, ``issue_id`` becomes the
    predecessor id and the live API id is stored in ``issue_snyk_id_current``.
    """
    org_id = row.get("org_id")
    project_id = row.get("project_id")
    idx = cache.get((org_id, project_id))
    ident = migration_identity_from_row(row)
    if not idx or not ident or ident not in idx.by_identity:
        return {
            "issue_legacy_id": None,
            "issue_migration_grafted": False,
            "issue_migration_old_org_id": None,
            "issue_migration_old_project_id": None,
            "issue_migration_identity": ident,
        }

    old = idx.by_identity[ident]
    live_id = row.get("issue_id")
    out = {
        "issue_legacy_id": old.issue_id,
        "issue_created_at": old.created_at or row.get("issue_created_at"),
        "issue_updated_at": old.updated_at or row.get("issue_updated_at"),
        "issue_last_introduced_at": old.last_introduced_at or row.get("issue_last_introduced_at"),
        "issue_migration_grafted": True,
        "issue_migration_old_org_id": idx.old_org_id,
        "issue_migration_old_project_id": idx.old_project_id,
        "issue_migration_identity": ident,
    }
    if graft_predecessor_issue_id:
        out["issue_snyk_id_current"] = live_id
        out["issue_id"] = old.issue_id
    return out


_GRAFT_DATE_COLUMNS = (
    "issue_created_at",
    "issue_updated_at",
    "issue_last_introduced_at",
)


_GRAFT_ID_COLUMNS = ("issue_id",)


def enrich_dataframe_migration_graft(
    df: pd.DataFrame,
    cache: MigrationProjectCache,
    *,
    graft_predecessor_issue_id: bool = False,
) -> pd.DataFrame:
    if df.empty:
        return df
    out = df.copy()
    graft_cols = out.apply(
        lambda row: apply_migration_graft_row(
            row, cache, graft_predecessor_issue_id=graft_predecessor_issue_id
        ),
        axis=1,
        result_type="expand",
    )
    grafted = graft_cols["issue_migration_grafted"].fillna(False).astype(bool)
    for col in graft_cols.columns:
        if col in _GRAFT_DATE_COLUMNS or (graft_predecessor_issue_id and col in _GRAFT_ID_COLUMNS):
            out.loc[grafted, col] = graft_cols.loc[grafted, col]
        else:
            out[col] = graft_cols[col]
    return out


async def enrich_issues_dataframe(
    df: pd.DataFrame,
    client: SnykClient,
    *,
    api_version: str = "2024-10-15",
    issues_api_version: str = "2024-05-08",
    code_issue_detail_api_version: str = "2024-10-14~experimental",
    retry: int = 3,
    graft_predecessor_issue_id: bool = False,
) -> pd.DataFrame:
    """Build cache for unique projects in df, merge fingerprints must already be present for SAST."""
    if df.empty or "org_id" not in df.columns or "project_id" not in df.columns:
        return df
    keys = zip(df["org_id"].astype(str), df["project_id"].astype(str))
    cache = await build_migration_cache(
        client,
        keys,
        api_version=api_version,
        issues_api_version=issues_api_version,
        code_issue_detail_api_version=code_issue_detail_api_version,
        retry=retry,
    )
    return enrich_dataframe_migration_graft(
        df, cache, graft_predecessor_issue_id=graft_predecessor_issue_id
    )


def build_issue_id_map(df: pd.DataFrame) -> Dict[str, str]:
    """Live (new) issue_id -> predecessor issue_id for grafted rows."""
    if df.empty or "issue_migration_grafted" not in df.columns:
        return {}
    m: Dict[str, str] = {}
    for _, row in df.iterrows():
        if not row.get("issue_migration_grafted"):
            continue
        live = row.get("issue_snyk_id_current")
        if live:
            pred = row.get("issue_legacy_id") or row.get("issue_id")
        else:
            live = row.get("issue_id")
            pred = row.get("issue_legacy_id")
        if live and pred:
            m[str(live)] = str(pred)
    return m
