"""Real Snyk API adapter.

SnykClient below is their existing ear0_pharos.snyk.api.SnykClient, copied
as-is (same retry/pagination/proxy behavior) so this merges cleanly once
this logic moves into their actual codebase - just delete this class and
`from ear0_pharos.snyk.api import SnykClient` instead.

SnykApiProjectsClient / SnykApiIssuesClient below implement the
ProjectsClient / SnykIssuesClient Protocols from resolver.py / client.py,
so LiveResolver and Correlator never need to know these are backed by real
HTTP calls.
"""

from __future__ import annotations

import asyncio
import logging
import os
import traceback
import urllib
from datetime import datetime
from typing import Dict, List, Optional

# Snyk REST: 1620 requests/minute/API key; 429 until the 1-minute window resets.
SNYK_RATE_LIMIT_REQUESTS_PER_MINUTE = 1620

from aiohttp import ClientSession, ClientTimeout
from aiohttp.client_exceptions import (
    ClientConnectionError,
    ClientResponseError,
    ServerDisconnectedError,
    ServerTimeoutError,
)

from .coordinates import aggregate_last_introduced_at, _parse_dt
from .models import SAST, SCA, Issue, ProjectSummary

logging.basicConfig()
logger = logging.getLogger(__name__)
logger.setLevel(logging.DEBUG)


# --- verbatim copy of their SnykClient (ear0_pharos.snyk.api) ---
# pylint: disable=too-many-instance-attributes
class SnykClient:
    """Snyk client class to interact with snyk apis. Unchanged from
    ear0_pharos/snyk/api.py - copied here only so this port runs standalone
    before it's merged into their repo.
    """

    # pylint: disable=too-many-arguments
    def __init__(
        self,
        snyk_api_url: str,
        snyk_token: str,
        proxy: bool = False,
        proxy_host: str = None,
        proxy_user: str = None,
        proxy_password: str = None,
        timeout_seconds: int = 30,
        concurrent_api_calls: int = 5,
        is_proxy_secure: bool = False,
    ):
        self.snyk_api_url = snyk_api_url
        self.proxy_host = proxy_host
        self.proxy_user = proxy_user
        self.proxy_password = proxy_password
        self.timeout_seconds = timeout_seconds
        self.snyk_token = snyk_token
        self.concurrent_api_calls = concurrent_api_calls
        self.proxy = proxy
        self.is_proxy_secure = is_proxy_secure
        self.semaphore = None
        self.session = None

    async def __aenter__(self):
        self.semaphore = asyncio.Semaphore(self.concurrent_api_calls)
        self.session = ClientSession(timeout=ClientTimeout(total=self.timeout_seconds))
        return self

    async def __aexit__(self, exc_type, exc, tb):
        await self.session.close()

    # pylint: disable=too-many-locals
    async def get_snyk_api_async(
        self, api_endpoint: str, param: Dict, retry: int, retry_sleep_time: int = None, max_pages: int = None
    ):
        proxy = (
            f"{'https' if self.is_proxy_secure else 'http'}://{self.proxy_user}:"
            f"{urllib.parse.quote(self.proxy_password)}"
            f"@{self.proxy_host}"
            if self.proxy
            else ""
        )
        async with self.semaphore:
            next_page = f"{self.snyk_api_url}/{api_endpoint}"
            data_list = []
            attempt = 1
            while attempt < (retry + 1):
                try:
                    while next_page:
                        # pylint: disable=not-async-context-manager
                        async with self.session.get(
                            next_page,
                            params=param,
                            timeout=self.timeout_seconds,
                            headers={"Authorization": f"token {self.snyk_token}"},
                            ssl=False,
                            **({"proxy": proxy} if self.proxy else {}),
                        ) as response:
                            if response.status == 404:
                                logger.info("404 when accessing url %s", next_page)
                                return data_list

                            if response.status == 429:
                                retry_after = response.headers.get("Retry-After")
                                sleep_s = int(os.environ.get("SNYK_RATE_LIMIT_BACKOFF_SECONDS", "60"))
                                if retry_after:
                                    try:
                                        sleep_s = max(sleep_s, int(retry_after))
                                    except ValueError:
                                        pass
                                logger.warning(
                                    "429 Too Many Requests (limit %s/min per key); sleeping %ss then retrying %s",
                                    SNYK_RATE_LIMIT_REQUESTS_PER_MINUTE,
                                    sleep_s,
                                    next_page,
                                )
                                await asyncio.sleep(sleep_s)
                                continue

                            response.raise_for_status()
                            data = await response.json()
                            data_list.append(data.copy())
                            if len(data_list) == 1 or len(data_list) % 25 == 0:
                                logger.info(
                                    "pagination %s: page %s (%s items this page)",
                                    api_endpoint,
                                    len(data_list),
                                    len(data.get("data", [])),
                                )

                            if max_pages is not None and len(data_list) >= max_pages:
                                return data_list

                            next_page = data.get("links", {}).get("next", None)
                            if next_page:
                                attempt = 1
                                next_page = f"{self.snyk_api_url}{next_page}"
                                param = None
                    return data_list
                except (
                    ClientConnectionError,
                    ClientResponseError,
                    ServerTimeoutError,
                    ServerDisconnectedError,
                    asyncio.TimeoutError,
                ) as e:
                    logger.error(
                        "Error while getting data from API - Attempt: %s/%s - %s - %s",
                        attempt,
                        retry,
                        type(e).__name__,
                        str(e),
                    )
                    await asyncio.sleep(retry * (attempt if not retry_sleep_time else retry_sleep_time))
                    attempt += 1
                    if attempt == retry:
                        logger.error("Max retries (%s) reached trying to fetch data from %s.", retry, next_page)
                        raise
                except Exception as e:
                    logger.error(
                        "Unexpected error while getting data from API: %s-%s \n %s",
                        str(e.__class__),
                        str(e),
                        traceback.format_exc(),
                    )
                    raise


# --- new fetchers/adapters for this correlation feature ---


class SnykApiProjectsClient:
    """Implements resolver.ProjectsClient. Scopes to a single repo via the
    Targets API display_name/repo_url filter (server-side), then lists that
    target's projects - never lists every project in the org.

    NOTE: field names for target/project filtering below are best-effort
    based on Snyk REST API conventions - confirm against a real response
    (esp. how a project's product/type surfaces: attributes.type is a
    package manager name for SCA, "sast" for Snyk Code) before relying on
    this against production data.
    """

    def __init__(
        self,
        client: SnykClient,
        api_version: str = "2024-10-15",
        retry: int = 3,
        display_name: Optional[str] = None,
        repo_url: Optional[str] = None,
    ):
        self._client = client
        self._api_version = api_version
        self._retry = retry
        self._display_name = display_name
        self._repo_url = repo_url

    async def _list_target_ids(self, org_id: str) -> List[str]:
        params = {"version": self._api_version, "limit": "100"}
        pages = await self._client.get_snyk_api_async(
            f"rest/orgs/{org_id}/targets", params, retry=self._retry
        )
        target_ids = []
        for page in pages:
            for target in page.get("data", []):
                attrs = target.get("attributes", {})
                if self._display_name:
                    from .matching import normalize_display_name

                    dn = normalize_display_name(attrs.get("display_name", ""))
                    want = normalize_display_name(self._display_name)
                    if dn != want:
                        continue
                if self._repo_url:
                    from .matching import normalize_repo_url

                    if normalize_repo_url(attrs.get("url", "")) != normalize_repo_url(self._repo_url):
                        continue
                target_ids.append(target["id"])
        return target_ids

    async def list_projects(self, org_id: str) -> List[ProjectSummary]:
        target_ids = await self._list_target_ids(org_id)
        summaries: List[ProjectSummary] = []
        for target_id in target_ids:
            params = {
                "version": self._api_version,
                "limit": "100",
                "target_id": target_id,
                "expand": "target",
            }
            pages = await self._client.get_snyk_api_async(
                f"rest/orgs/{org_id}/projects", params, retry=self._retry
            )
            for page in pages:
                for project in page.get("data", []):
                    attrs = project.get("attributes", {})
                    target_attrs = (
                        project.get("relationships", {})
                        .get("target", {})
                        .get("data", {})
                        .get("attributes", {})
                    )
                    project_type = attrs.get("type", "")
                    product = "sast" if project_type == "sast" else "sca"
                    summaries.append(
                        ProjectSummary(
                            org_id=org_id,
                            project_id=project["id"],
                            product=product,
                            integration_type=attrs.get("origin"),
                            repo_url=target_attrs.get("url"),
                            display_name=target_attrs.get("display_name"),
                            created_at=_parse_dt(attrs.get("created_at") or attrs.get("created")),
                        )
                    )
        return summaries


class SnykApiIssuesClient:
    """Implements client.SnykIssuesClient against the real Issues API,
    including the SAST fingerprint enrichment call.
    """

    def __init__(
        self,
        client: SnykClient,
        issues_api_version: str = "2024-05-08",
        code_issue_detail_api_version: str = "2024-10-14~experimental",
        retry: int = 3,
    ):
        self._client = client
        self._issues_api_version = issues_api_version
        self._code_issue_detail_api_version = code_issue_detail_api_version
        self._retry = retry

    async def fetch_open_issues(
        self, org_id: str, project_id: str, product: Optional[str] = None
    ) -> List[Issue]:
        """Fetch open issues; product is sca|sast|None (both)."""
        if product == "sca":
            return await self._fetch_by_type(org_id, project_id, SCA)
        if product == "sast":
            return await self._fetch_by_type(org_id, project_id, SAST)
        sca = await self._fetch_by_type(org_id, project_id, SCA)
        sast = await self._fetch_by_type(org_id, project_id, SAST)
        return sca + sast

    async def _fetch_by_type(self, org_id: str, project_id: str, issue_type: str) -> List[Issue]:
        params = {
            "version": self._issues_api_version,
            "limit": "100",
            "status": "open",
            "type": issue_type,
            "scan_item.id": project_id,
            "scan_item.type": "project",
        }
        pages = await self._client.get_snyk_api_async(
            f"rest/orgs/{org_id}/issues", params, retry=self._retry
        )

        issues: List[Issue] = []
        for page in pages:
            for raw in page.get("data", []):
                attrs = raw.get("attributes", {})
                coordinates = attrs.get("coordinates") or []
                issues.append(
                    Issue(
                        id=raw["id"],
                        type=issue_type,
                        org_id=org_id,
                        project_id=project_id,
                        key=attrs.get("key"),
                        created_at=_parse_dt(attrs.get("created_at")),
                        updated_at=_parse_dt(attrs.get("updated_at")),
                        last_introduced_at=aggregate_last_introduced_at(coordinates),
                    )
                )

        if issue_type == SAST:
            sast_issues = issues
            if sast_issues:
                tasks = [self._fetch_fingerprint(org_id, project_id, i.key) for i in sast_issues]
                fingerprints = await asyncio.gather(*tasks)
                for issue, fingerprint in zip(sast_issues, fingerprints):
                    issue.fingerprint = fingerprint
        return issues

    async def _fetch_fingerprint(self, org_id: str, project_id: str, issue_key: str) -> Optional[str]:
        if not issue_key:
            return None
        pages = await self._client.get_snyk_api_async(
            f"rest/orgs/{org_id}/code_issue_details/{issue_key}",
            {"version": self._code_issue_detail_api_version, "project_id": project_id},
            retry=self._retry,
        )
        for page in pages:
            fingerprint = page.get("data", {}).get("attributes", {}).get("fingerprint")
            if fingerprint:
                return fingerprint
        return None
