import unittest

from snyk_correlate.matching import (
    normalize_display_name,
    normalize_repo_url,
    normalize_target_file,
    project_kind_key,
    repo_key,
)
from snyk_correlate.models import ProjectSummary
from snyk_correlate.project_scope import target_file_from_project


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


class TestNormalizeTargetFile(unittest.TestCase):
    def test_strips_leading_dot_slash_and_case(self):
        self.assertEqual(normalize_target_file("./Frontend/package.json"), "frontend/package.json")
        self.assertEqual(normalize_target_file("/package.json"), "package.json")

    def test_normalizes_backslashes(self):
        self.assertEqual(normalize_target_file("terraform\\main.tf"), "terraform/main.tf")

    def test_keeps_leading_dot_in_filename(self):
        self.assertEqual(normalize_target_file(".snyk"), ".snyk")

    def test_empty_string(self):
        self.assertEqual(normalize_target_file(""), "")


class TestProjectKindKey(unittest.TestCase):
    def test_type_and_manifest(self):
        p = ProjectSummary(
            org_id="o", project_id="p", product="sca",
            project_type="NPM", target_file="./package.json",
        )
        self.assertEqual(project_kind_key(p), ("npm", "package.json"))

    def test_distinguishes_manifests_within_one_repo(self):
        root = ProjectSummary(org_id="o", project_id="a", product="sca",
                              project_type="npm", target_file="package.json")
        frontend = ProjectSummary(org_id="o", project_id="b", product="sca",
                                  project_type="npm", target_file="frontend/package.json")
        docker = ProjectSummary(org_id="o", project_id="c", product="sca",
                                project_type="dockerfile", target_file="Dockerfile")
        self.assertNotEqual(project_kind_key(root), project_kind_key(frontend))
        self.assertNotEqual(project_kind_key(root), project_kind_key(docker))

    def test_missing_fields_are_empty(self):
        p = ProjectSummary(org_id="o", project_id="p", product="sast")
        self.assertEqual(project_kind_key(p), ("", ""))


class TestTargetFileFromProject(unittest.TestCase):
    def test_prefers_target_file_attribute(self):
        attrs = {"target_file": "package.json", "name": "acme/widgets(main):ignored.json"}
        self.assertEqual(target_file_from_project(attrs), "package.json")

    def test_falls_back_to_name_suffix(self):
        attrs = {"name": "z4ce/juice-shop-goof(master):frontend/package.json"}
        self.assertEqual(target_file_from_project(attrs), "frontend/package.json")

    def test_no_manifest_in_name(self):
        self.assertEqual(target_file_from_project({"name": "acme/widgets"}), "")
        self.assertEqual(target_file_from_project({}), "")


if __name__ == "__main__":
    unittest.main()
