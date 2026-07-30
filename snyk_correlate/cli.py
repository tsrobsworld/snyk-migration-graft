"""snyk-correlate CLI (Python port).

Standalone hand-off point: their existing issues pull on the NEW project is
untouched. This finds the predecessor project itself (matching logic runs
live, no report file) and prints old_last_introduced_at per issue identity
to stdout as JSON, for their pipeline to join in.

Usage:
    python -m snyk_correlate.cli --org-id ORG --display-name acme/widgets
    python -m snyk_correlate.cli --org-id ORG --repo-url https://github.com/acme/widgets --project-id PROJECT
"""

from __future__ import annotations

import argparse
import asyncio
import json
import os
import sys

from .correlate import Correlator
from .resolver import LiveResolver
from .snykapi import SnykApiIssuesClient, SnykApiProjectsClient, SnykClient


def build_arg_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Correlate a migrated Snyk project back to its predecessor's issue dates.")
    parser.add_argument("--org-id", required=True, help="Snyk organization UUID")
    parser.add_argument("--display-name", help="Target display_name, e.g. acme/widgets")
    parser.add_argument("--repo-url", help="Repo URL; normalized to org/repo for the Targets API query")
    parser.add_argument("--project-id", help="NEW project to correlate; must belong to the repo scope")
    parser.add_argument("--product", choices=["sca", "sast"], help="Limit to sca or sast when --project-id is omitted")
    parser.add_argument("--snyk-tenant", default=os.environ.get("SNYK_API", "https://api.snyk.io"), help="API host/region")
    parser.add_argument("--snyk-api-version", default="2024-10-15", help="REST version for targets/projects")
    parser.add_argument("--snyk-issues-api-version", default="2024-05-08", help="Issues list API version")
    parser.add_argument(
        "--snyk-code-issue-detail-api-version",
        default="2024-10-14~experimental",
        help="SAST fingerprint detail version",
    )
    return parser


async def _find_new_project_id(projects_client: SnykApiProjectsClient, org_id: str, product: str | None) -> str | None:
    """When --project-id is omitted, pick the newest project for the repo
    scope (optionally filtered to one product). Mirrors the Go CLI's
    auto-select behavior.
    """
    all_projects = await projects_client.list_projects(org_id)
    candidates = [p for p in all_projects if not product or p.product == product]
    if not candidates:
        return None
    newest = max(candidates, key=lambda p: p.created_at or "")
    return newest.project_id


async def run(args: argparse.Namespace) -> dict:
    token = os.environ.get("SNYK_TOKEN")
    if not token:
        print("SNYK_TOKEN environment variable is required", file=sys.stderr)
        sys.exit(2)

    if not args.display_name and not args.repo_url:
        print("one of --display-name or --repo-url is required", file=sys.stderr)
        sys.exit(2)

    async with SnykClient(snyk_api_url=args.snyk_tenant, snyk_token=token) as client:
        projects_client = SnykApiProjectsClient(
            client,
            api_version=args.snyk_api_version,
            display_name=args.display_name,
            repo_url=args.repo_url,
        )
        issues_client = SnykApiIssuesClient(
            client,
            issues_api_version=args.snyk_issues_api_version,
            code_issue_detail_api_version=args.snyk_code_issue_detail_api_version,
        )
        resolver = LiveResolver(projects_client)
        correlator = Correlator(issues_client, resolver)

        project_id = args.project_id
        if not project_id:
            project_id = await _find_new_project_id(projects_client, args.org_id, args.product)
            if not project_id:
                return {"error": "no project found for the given repo scope/product"}

        result = await correlator.correlate(args.org_id, project_id)
        return result.to_dict()


def main() -> None:
    parser = build_arg_parser()
    args = parser.parse_args()
    result = asyncio.run(run(args))
    print(json.dumps(result, indent=2))


if __name__ == "__main__":
    main()
