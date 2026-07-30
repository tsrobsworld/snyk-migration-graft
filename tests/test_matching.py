import unittest

from snyk_correlate.matching import normalize_display_name, normalize_repo_url, repo_key
from snyk_correlate.models import ProjectSummary


class TestNormalizeRepoUrl(unittest.TestCase):
    def test_strips_scheme_host_git_suffix_and_case(self):
        self.assertEqual(
            normalize_repo_url("https://github-enterprise.corp.com/Acme/widgets.git"),
            "acme/widgets",
        )
        self.assertEqual(normalize_repo_url("https://github.com/acme/widgets"), "acme/widgets")

    def test_empty_string(self):
        self.assertEqual(normalize_repo_url(""), "")


class TestNormalizeDisplayName(unittest.TestCase):
    def test_strips_manifest_suffix(self):
        self.assertEqual(
            normalize_display_name("acme/widgets(main):requirements.txt"),
            "acme/widgets",
        )

    def test_no_manifest_suffix(self):
        self.assertEqual(normalize_display_name("Acme/Widgets"), "acme/widgets")


class TestRepoKey(unittest.TestCase):
    def test_prefers_repo_url(self):
        p = ProjectSummary(
            org_id="o", project_id="p", product="sca",
            repo_url="https://github.com/acme/widgets", display_name="should-be-ignored",
        )
        self.assertEqual(repo_key(p), "acme/widgets")

    def test_falls_back_to_display_name(self):
        p = ProjectSummary(org_id="o", project_id="p", product="sca", display_name="acme/widgets(main):x.txt")
        self.assertEqual(repo_key(p), "acme/widgets")

    def test_no_identity(self):
        p = ProjectSummary(org_id="o", project_id="p", product="sca")
        self.assertEqual(repo_key(p), "")


if __name__ == "__main__":
    unittest.main()
