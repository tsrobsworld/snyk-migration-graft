import unittest
from datetime import datetime, timedelta, timezone

from snyk_correlate.correlate import Correlator
from snyk_correlate.models import SAST, SCA, Issue, ProjectSummary
from snyk_correlate.resolver import LiveResolver


def _dt(days_ago: int) -> datetime:
    return datetime.now(timezone.utc) - timedelta(days=days_ago)


class FakeProjectsClient:
    def __init__(self, by_org):
        self._by_org = by_org

    async def list_projects(self, org_id):
        return self._by_org.get(org_id, [])


class FakeIssuesClient:
    def __init__(self, by_project):
        self._by_project = by_project  # key: (org_id, project_id)

    async def fetch_open_issues(self, org_id, project_id):
        return self._by_project.get((org_id, project_id), [])


class TestCorrelate(unittest.IsolatedAsyncioTestCase):
    async def test_returns_old_project_issues_by_identity(self):
        old_date = _dt(45)

        projects_client = FakeProjectsClient({
            "org1": [
                ProjectSummary(org_id="org1", project_id="proj-old", product="sca",
                                repo_url="https://github.com/acme/widgets", created_at=_dt(400)),
                ProjectSummary(org_id="org1", project_id="proj-new", product="sca",
                                repo_url="https://github.com/acme/widgets", created_at=_dt(2)),
            ]
        })
        issues_client = FakeIssuesClient({
            ("org1", "proj-old"): [
                Issue(id="old-sca-1", type=SCA, org_id="org1", project_id="proj-old",
                      key="sca-key-abc", created_at=old_date, last_introduced_at=old_date),
                Issue(id="old-sast-1", type=SAST, org_id="org1", project_id="proj-old",
                      fingerprint="fp-xyz", created_at=old_date, last_introduced_at=old_date),
                Issue(id="old-no-identity", type=SAST, org_id="org1", project_id="proj-old",
                      fingerprint=None, created_at=old_date, last_introduced_at=old_date),
            ]
        })

        correlator = Correlator(issues_client, LiveResolver(projects_client))
        result = await correlator.correlate("org1", "proj-new")

        self.assertTrue(result.match_found)
        self.assertEqual(result.old_project_id, "proj-old")
        self.assertEqual(len(result.issues), 2)  # the no-identity issue is skipped

        by_identity = {i.identity: i for i in result.issues}
        self.assertEqual(by_identity["sca-key-abc"].identity_type, "key")
        self.assertEqual(by_identity["sca-key-abc"].old_last_introduced_at, old_date)
        self.assertEqual(by_identity["fp-xyz"].identity_type, "fingerprint")
        self.assertEqual(by_identity["fp-xyz"].old_last_introduced_at, old_date)

    async def test_no_known_migration(self):
        projects_client = FakeProjectsClient({
            "org1": [
                ProjectSummary(org_id="org1", project_id="proj-standalone", product="sca",
                                repo_url="https://github.com/acme/solo", created_at=_dt(1)),
            ]
        })
        issues_client = FakeIssuesClient({})

        correlator = Correlator(issues_client, LiveResolver(projects_client))
        result = await correlator.correlate("org1", "proj-standalone")

        self.assertFalse(result.match_found)
        self.assertEqual(result.issues, [])


if __name__ == "__main__":
    unittest.main()
