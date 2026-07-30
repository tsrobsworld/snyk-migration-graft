import unittest
from datetime import datetime, timedelta, timezone

from snyk_correlate.models import ProjectSummary
from snyk_correlate.resolver import LiveResolver


class FakeProjectsClient:
    def __init__(self, by_org):
        self._by_org = by_org

    async def list_projects(self, org_id):
        return self._by_org.get(org_id, [])


def _dt(days_ago: int) -> datetime:
    return datetime.now(timezone.utc) - timedelta(days=days_ago)


class TestLiveResolver(unittest.IsolatedAsyncioTestCase):
    async def test_matches_across_hostname_change(self):
        client = FakeProjectsClient({
            "org1": [
                ProjectSummary(
                    org_id="org1", project_id="proj-old", product="sca",
                    repo_url="https://github-enterprise.corp.com/Acme/widgets.git",
                    created_at=_dt(400),
                ),
                ProjectSummary(
                    org_id="org1", project_id="proj-new", product="sca",
                    repo_url="https://github.com/acme/widgets",
                    created_at=_dt(2),
                ),
                ProjectSummary(
                    org_id="org1", project_id="proj-unrelated", product="sca",
                    repo_url="https://github.com/acme/some-other-repo",
                    created_at=_dt(2),
                ),
            ]
        })
        resolver = LiveResolver(client)
        result = await resolver.resolve_old_project("org1", "proj-new")
        self.assertEqual(result, ("org1", "proj-old"))

    async def test_does_not_match_across_products(self):
        # same repo, but SCA and SAST shouldn't cross-match
        client = FakeProjectsClient({
            "org1": [
                ProjectSummary(
                    org_id="org1", project_id="proj-old-sast", product="sast",
                    repo_url="https://github.com/acme/widgets", created_at=_dt(400),
                ),
                ProjectSummary(
                    org_id="org1", project_id="proj-new-sca", product="sca",
                    repo_url="https://github.com/acme/widgets", created_at=_dt(2),
                ),
            ]
        })
        resolver = LiveResolver(client)
        result = await resolver.resolve_old_project("org1", "proj-new-sca")
        self.assertIsNone(result)

    async def test_no_match_found(self):
        client = FakeProjectsClient({
            "org1": [
                ProjectSummary(
                    org_id="org1", project_id="proj-standalone", product="sca",
                    repo_url="https://github.com/acme/solo", created_at=_dt(1),
                ),
            ]
        })
        resolver = LiveResolver(client)
        result = await resolver.resolve_old_project("org1", "proj-standalone")
        self.assertIsNone(result)

    async def test_picks_oldest_among_multiple_duplicates(self):
        client = FakeProjectsClient({
            "org1": [
                ProjectSummary(org_id="org1", project_id="proj-oldest", product="sca",
                                repo_url="https://github.com/acme/widgets", created_at=_dt(1000)),
                ProjectSummary(org_id="org1", project_id="proj-middle", product="sca",
                                repo_url="https://github.com/acme/widgets", created_at=_dt(500)),
                ProjectSummary(org_id="org1", project_id="proj-newest", product="sca",
                                repo_url="https://github.com/acme/widgets", created_at=_dt(1)),
            ]
        })
        resolver = LiveResolver(client)
        result = await resolver.resolve_old_project("org1", "proj-newest")
        self.assertEqual(result, ("org1", "proj-oldest"))


if __name__ == "__main__":
    unittest.main()
