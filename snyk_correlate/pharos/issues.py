"""Pharos-compatible issues pull + parse (standalone, no ear0_pharos).

Group issues entry points match production; org issues used for validation and
local dev when SNYK_GROUP_ID is unset.
"""

from __future__ import annotations

import asyncio
import logging
import os
from typing import Dict, List, Optional, Tuple

import pandas as pd

from snyk_correlate.coordinates import aggregate_last_introduced_at
from snyk_correlate.migration_graft import enrich_issues_dataframe
from snyk_correlate.pharos.constants import CODE_ISSUE_COLUMN_LIST, ISSUE_COLUMN_LIST
from snyk_correlate.snykapi import SnykClient

logging.basicConfig()
logger = logging.getLogger(__name__)
logger.setLevel(logging.INFO)


def find_item_in_list(items: list, key: str, value: str) -> int:
    for i, item in enumerate(items):
        if item.get(key) == value:
            return i
    return -1


def parse_issues_data(data: List[List[Dict]], *, columns: Optional[List[str]] = None) -> pd.DataFrame:
    issues = []
    cols = columns or ISSUE_COLUMN_LIST

    for records in data:
        for record in records:
            for issue in record.get("data", []):
                attributes = issue.get("attributes", {})
                relationships = issue.get("relationships", {})
                coordinates = attributes.get("coordinates") or []

                temp_issue = {
                    "issue_id": issue["id"],
                    "org_id": relationships.get("organization", {}).get("data", {}).get("id"),
                    "project_id": relationships.get("scan_item", {}).get("data", {}).get("id"),
                    "issue_link": relationships.get("scan_item", {}).get("links", {}).get("related"),
                    "issue_key": attributes.get("key"),
                    "issue_type": attributes.get("type"),
                    "issue_title": attributes.get("title"),
                    "issue_status": attributes.get("status"),
                    "issue_created_at": attributes.get("created_at"),
                    "issue_updated_at": attributes.get("updated_at"),
                    "issue_last_introduced_at": _last_introduced_iso(coordinates),
                    "issue_effective_severity_level": attributes.get("effective_severity_level"),
                }
                issues.append(temp_issue)

    df = pd.DataFrame(issues)
    for c in cols:
        if c not in df.columns:
            df[c] = None
    return df[cols] if cols else df


def _last_introduced_iso(coordinates: list) -> Optional[str]:
    dt = aggregate_last_introduced_at(coordinates, use_min=True)
    return dt.isoformat() if dt else None


def parse_code_issue_details(data: List[List[Dict]]) -> pd.DataFrame:
    rows = []
    for records in data:
        for record in records:
            issue_details = record.get("data", {})
            link = record.get("links", {}).get("self", "")
            project_id = ""
            if "project_id=" in link:
                project_id = link.split("project_id=")[1].split("&")[0]
            rows.append(
                {
                    "issue_key": issue_details.get("id"),
                    "issue_fingerprint": issue_details.get("attributes", {}).get("fingerprint"),
                    "project_id": project_id,
                }
            )
    return pd.DataFrame(rows, columns=CODE_ISSUE_COLUMN_LIST)


def merge_code_issue_fingerprints(df_issues: pd.DataFrame, df_code: pd.DataFrame) -> pd.DataFrame:
    if df_issues.empty or df_code.empty:
        df_issues = df_issues.copy()
        if "issue_fingerprint" not in df_issues.columns:
            df_issues["issue_fingerprint"] = None
        return df_issues
    left = df_issues.drop(columns=["issue_fingerprint"], errors="ignore")
    return left.merge(df_code, how="left", on=["issue_key", "project_id"])


async def get_all_issues_by_organization(
    org_list: List[str],
    client: SnykClient,
    api_version: str,
    api_call_retry: int = 3,
    param_extra: Optional[Dict] = None,
    max_pages: Optional[int] = None,
) -> pd.DataFrame:
    param = {"version": api_version, "limit": "100", **(param_extra or {})}
    tasks = [
        client.get_snyk_api_async(
            f"rest/orgs/{org}/issues", param.copy(), retry=api_call_retry, max_pages=max_pages
        )
        for org in org_list
    ]
    return parse_issues_data(await asyncio.gather(*tasks))


async def get_group_issues(
    group_id: str,
    client: SnykClient,
    api_version: str,
    api_call_retry: int = 3,
    param_extra: Optional[Dict] = None,
    max_pages: Optional[int] = None,
) -> pd.DataFrame:
    param = {"version": api_version, "limit": "100", **(param_extra or {})}
    data = await client.get_snyk_api_async(
        f"rest/groups/{group_id}/issues", param, retry=api_call_retry, max_pages=max_pages
    )
    return parse_issues_data([data])


async def resolve_org_id_for_group(
    client: SnykClient,
    group_id: str,
    *,
    org_id: str = "",
    orgs_api_version: str = "2024-10-15",
    api_call_retry: int = 3,
) -> str:
    if org_id:
        return org_id
    for version in (orgs_api_version, "2024-05-08", "2023-05-29"):
        try:
            pages = await client.get_snyk_api_async(
                f"rest/groups/{group_id}/orgs",
                {"version": version, "limit": "1"},
                retry=api_call_retry,
            )
        except Exception as exc:
            logger.debug("group orgs lookup failed version=%s: %s", version, exc)
            continue
        for page in pages:
            for org in page.get("data", []):
                oid = org.get("id") or ""
                if oid:
                    return oid
    return ""


async def get_all_code_issues_detail_by_issues(
    issues: pd.DataFrame,
    client: SnykClient,
    api_version: str,
    api_call_retry: int = 3,
) -> pd.DataFrame:
    code_rows = issues[issues["issue_type"] == "code"]
    if code_rows.empty:
        return pd.DataFrame(columns=CODE_ISSUE_COLUMN_LIST)
    tasks = [
        client.get_snyk_api_async(
            f"rest/orgs/{row['org_id']}/code_issue_details/{row['issue_key']}",
            {"version": api_version, "project_id": row["project_id"]},
            retry=api_call_retry,
        )
        for _, row in code_rows.iterrows()
    ]
    return parse_code_issue_details(await asyncio.gather(*tasks))


async def validate_group_vs_org_issue_parity(
    org_id: str,
    group_id: str,
    client: SnykClient,
    api_version: str,
    *,
    sample_limit: int = 100,
) -> Tuple[pd.DataFrame, pd.DataFrame, dict]:
    """Fetch org + group issues with same limit; compare id sets (validation helper)."""
    param = {"version": api_version, "limit": str(sample_limit)}
    org_data = await client.get_snyk_api_async(
        f"rest/orgs/{org_id}/issues", param.copy(), retry=3, max_pages=1
    )
    group_data = await client.get_snyk_api_async(
        f"rest/groups/{group_id}/issues", param.copy(), retry=3, max_pages=1
    )
    df_org = parse_issues_data([org_data])
    df_group = parse_issues_data([group_data])
    org_ids = set(df_org["issue_id"].dropna())
    group_ids = set(df_group["issue_id"].dropna())
    stats = {
        "org_rows": len(df_org),
        "group_rows": len(df_group),
        "org_only": len(org_ids - group_ids),
        "group_only": len(group_ids - org_ids),
        "intersection": len(org_ids & group_ids),
    }
    logger.info("group vs org validation: %s", stats)
    return df_org, df_group, stats


async def pull_issues_for_pipeline(
    client: SnykClient,
    *,
    api_version: str = "2024-05-08",
    org_id: Optional[str] = None,
    group_id: Optional[str] = None,
    apply_migration_graft: bool = True,
    projects_api_version: str = "2024-10-15",
    code_issue_api_version: Optional[str] = None,
    issues_limit: Optional[int] = None,
) -> pd.DataFrame:
    """Primary dev entry: group if group_id set, else org. Optional migration enrich."""
    param_extra: Dict = {}
    max_pages = None
    if issues_limit is not None:
        param_extra["limit"] = str(min(issues_limit, 100))
        max_pages = 1

    if group_id:
        df = await get_group_issues(
            group_id, client, api_version, param_extra=param_extra or None, max_pages=max_pages
        )
    elif org_id:
        df = await get_all_issues_by_organization(
            [org_id], client, api_version, param_extra=param_extra or None, max_pages=max_pages
        )
    else:
        raise ValueError("org_id or group_id required")

    logger.info("issues pulled: rows=%s", len(df))

    code_version = code_issue_api_version or api_version
    code_df = await get_all_code_issues_detail_by_issues(df, client, code_version)
    df = merge_code_issue_fingerprints(df, code_df)
    for c in ISSUE_COLUMN_LIST:
        if c not in df.columns:
            df[c] = None
    df = df[ISSUE_COLUMN_LIST]

    if apply_migration_graft:
        logger.info("building migration cache for %s unique projects", df[["org_id", "project_id"]].drop_duplicates().shape[0])
        df = await enrich_issues_dataframe(
            df,
            client,
            api_version=projects_api_version,
            issues_api_version=api_version,
        )
    return df


def client_from_env() -> Tuple[SnykClient, dict]:
    token = os.environ.get("SNYK_TOKEN", "").strip()
    if not token:
        raise RuntimeError("SNYK_TOKEN is required")
    base = os.environ.get("SNYK_API", "https://api.snyk.io").strip().rstrip("/")
    cfg = {
        "org_id": os.environ.get("SNYK_ORG_ID", "").strip(),
        "group_id": os.environ.get("SNYK_GROUP_ID", "").strip(),
        "api_version": os.environ.get("SNYK_ISSUES_API_VERSION", "2024-05-08").strip(),
        "projects_api_version": os.environ.get("SNYK_API_VERSION", "2024-10-15").strip(),
    }
    client = SnykClient(
        snyk_api_url=base,
        snyk_token=token,
        timeout_seconds=int(os.environ.get("SNYK_TIMEOUT", "60")),
        concurrent_api_calls=int(os.environ.get("SNYK_CONCURRENT", "5")),
    )
    return client, cfg
