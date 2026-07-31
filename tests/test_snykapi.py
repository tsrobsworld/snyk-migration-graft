import unittest

from snyk_correlate.models import SAST, SCA
from snyk_correlate.snykapi import SnykApiIssuesClient, SnykApiProjectsClient


class FakeClient:
    """Records params per endpoint and replays canned pages."""

    def __init__(self, pages_by_endpoint):
        self._pages = pages_by_endpoint
        self.calls = []

    async def get_snyk_api_async(self, api_endpoint, param, retry, **kwargs):
        self.calls.append((api_endpoint, dict(param or {})))
        return self._pages.get(api_endpoint, [])


def _issue(issue_id, issue_type, key):
    return {
        "id": issue_id,
        "attributes": {"type": issue_type, "key": key, "created_at": "2026-01-01T00:00:00Z"},
    }


class TestFetchOpenIssues(unittest.IsolatedAsyncioTestCase):
    async def test_sca_project_fetch_is_not_type_filtered(self):
        # an IaC/npm project carries config and license issues too; a
        # type=package_vulnerability filter would drop them from the index
        client = FakeClient({
            "rest/orgs/o/issues": [
                {"data": [
                    _issue("i1", SCA, "SNYK-JS-VM2-1"),
                    _issue("i2", "config", "SNYK-CC-K8S-1"),
                    _issue("i3", "license", "snyk:lic:npm:foo:GPL-2.0"),
                ]}
            ]
        })
        issues = await SnykApiIssuesClient(client).fetch_open_issues("o", "p", product="sca")

        self.assertNotIn("type", client.calls[0][1])
        self.assertEqual([i.id for i in issues], ["i1", "i2", "i3"])
        self.assertEqual([i.type for i in issues], [SCA, "config", "license"])
        # all non-SAST issues identify by attributes.key
        self.assertEqual(
            [i.identity for i in issues],
            ["SNYK-JS-VM2-1", "SNYK-CC-K8S-1", "snyk:lic:npm:foo:GPL-2.0"],
        )

    async def test_sast_project_filters_by_type_and_enriches_fingerprints(self):
        client = FakeClient({
            "rest/orgs/o/issues": [{"data": [_issue("i1", SAST, "code-key-1")]}],
            "rest/orgs/o/code_issue_details/code-key-1": [
                {"data": {"attributes": {"fingerprint": "fp-1"}}}
            ],
        })
        issues = await SnykApiIssuesClient(client).fetch_open_issues("o", "p", product="sast")

        self.assertEqual(client.calls[0][1]["type"], SAST)
        self.assertEqual(issues[0].fingerprint, "fp-1")
        self.assertEqual(issues[0].identity, "fp-1")  # not the project-scoped key

    async def test_unspecified_product_enriches_only_code_issues(self):
        client = FakeClient({
            "rest/orgs/o/issues": [
                {"data": [_issue("i1", SCA, "SNYK-JS-VM2-1"), _issue("i2", SAST, "code-key-1")]}
            ],
            "rest/orgs/o/code_issue_details/code-key-1": [
                {"data": {"attributes": {"fingerprint": "fp-1"}}}
            ],
        })
        issues = await SnykApiIssuesClient(client).fetch_open_issues("o", "p")

        self.assertNotIn("type", client.calls[0][1])
        self.assertEqual([i.identity for i in issues], ["SNYK-JS-VM2-1", "fp-1"])
        detail_calls = [c for c in client.calls if "code_issue_details" in c[0]]
        self.assertEqual(len(detail_calls), 1)


class TestListProjects(unittest.IsolatedAsyncioTestCase):
    async def test_populates_project_type_and_target_file(self):
        client = FakeClient({
            "rest/orgs/o/targets": [
                {"data": [{"id": "t1", "attributes": {"display_name": "acme/widgets"}}]}
            ],
            "rest/orgs/o/projects": [
                {"data": [
                    {
                        "id": "p1",
                        "attributes": {
                            "name": "acme/widgets(main):frontend/package.json",
                            "type": "npm",
                            "target_file": "frontend/package.json",
                            "origin": "github",
                            "created": "2026-01-01T00:00:00Z",
                        },
                        "relationships": {
                            "target": {"data": {"attributes": {
                                "url": "https://github.com/acme/widgets",
                                "display_name": "acme/widgets",
                            }}}
                        },
                    }
                ]}
            ],
        })
        projects = await SnykApiProjectsClient(client).list_projects("o")

        self.assertEqual(len(projects), 1)
        self.assertEqual(projects[0].product, "sca")
        self.assertEqual(projects[0].project_type, "npm")
        self.assertEqual(projects[0].target_file, "frontend/package.json")
        self.assertIsNotNone(projects[0].created_at)


if __name__ == "__main__":
    unittest.main()
