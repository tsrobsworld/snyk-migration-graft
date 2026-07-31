"""Validate group vs org issues API and optional migration graft (uses env)."""

import asyncio
import os
import sys
from typing import Optional

from snyk_correlate.pharos.issues import (
    client_from_env,
    get_group_issues,
    pull_issues_for_pipeline,
    resolve_org_id_for_group,
    validate_group_vs_org_issue_parity,
)


def _parse_issues_limit() -> Optional[int]:
    raw = os.environ.get("SNYK_ISSUES_LIMIT", "100").strip().lower()
    if raw in {"", "all", "0", "none", "full", "unlimited"}:
        return None
    return int(raw)


def _print_summary(df, apply_graft: bool) -> None:
    print(f"rows={len(df)} columns={len(df.columns)}")
    if df.empty:
        return
    print(f"unique_projects={df['project_id'].nunique()} unique_issue_ids={df['issue_id'].nunique()}")
    if "issue_type" in df.columns:
        print("issue_type_counts:")
        print(df["issue_type"].value_counts().to_string())
    if apply_graft and "issue_migration_grafted" in df.columns:
        grafted = df["issue_migration_grafted"].fillna(False)
        n = int(grafted.sum())
        print(f"grafted={n} ({100.0 * n / len(df):.2f}% of rows)")
        if n and "issue_migration_old_project_id" in df.columns:
            pairs = (
                df.loc[grafted, ["project_id", "issue_migration_old_project_id"]]
                .drop_duplicates()
                .shape[0]
            )
            print(f"grafted_project_pairs={pairs}")
    print(df.head(3).to_string())


async def main() -> int:
    client, cfg = client_from_env()
    org_id = cfg["org_id"]
    group_id = cfg["group_id"]
    api_version = cfg["api_version"]
    issues_limit = _parse_issues_limit()
    code_api_version = os.environ.get("SNYK_CODE_ISSUES_API_VERSION", "2024-10-14~experimental").strip()
    output_csv = os.environ.get("SNYK_OUTPUT_CSV", "").strip()

    if not org_id and not group_id:
        print("Set SNYK_ORG_ID and/or SNYK_GROUP_ID", file=sys.stderr)
        return 1

    mode = "full pagination" if issues_limit is None else f"limit={issues_limit} (single page)"
    target = f"org={org_id}" if org_id and not group_id else (f"group={group_id}" if group_id else f"org={org_id} group={group_id}")
    print(f"pull: {target} {mode}")

    async with client:
        if group_id and issues_limit is not None:
            org_for_parity = org_id or await resolve_org_id_for_group(
                client,
                group_id,
                orgs_api_version=cfg["projects_api_version"],
            )
            if not org_for_parity:
                preview = await get_group_issues(
                    group_id,
                    client,
                    api_version,
                    param_extra={"limit": "100"},
                    max_pages=1,
                )
                if not preview.empty and preview["org_id"].notna().any():
                    org_for_parity = str(preview["org_id"].dropna().iloc[0])
            if org_for_parity:
                await validate_group_vs_org_issue_parity(
                    org_for_parity, group_id, client, api_version, sample_limit=min(issues_limit, 100)
                )
            else:
                print("skip parity: no org_id (set SNYK_ORG_ID or ensure group has orgs)")

        graft_env = os.environ.get("SNYK_APPLY_MIGRATION_GRAFT", "1").strip().lower()
        apply_graft = graft_env not in {"0", "false", "no", "off"}
        graft_id_env = os.environ.get("SNYK_GRAFT_ISSUE_ID", "0").strip().lower()
        graft_predecessor_issue_id = graft_id_env in {"1", "true", "yes", "on"}
        print(f"migration_graft={'on' if apply_graft else 'off'} graft_predecessor_issue_id={'on' if graft_predecessor_issue_id else 'off'}")
        df = await pull_issues_for_pipeline(
            client,
            api_version=api_version,
            org_id=org_id or None,
            group_id=group_id or None,
            apply_migration_graft=apply_graft,
            projects_api_version=cfg["projects_api_version"],
            code_issue_api_version=code_api_version,
            issues_limit=issues_limit,
            graft_predecessor_issue_id=graft_predecessor_issue_id,
        )
        _print_summary(df, apply_graft)
        if output_csv:
            df.to_csv(output_csv, index=False)
            print(f"wrote {output_csv}")
    return 0


if __name__ == "__main__":
    sys.exit(asyncio.run(main()))
