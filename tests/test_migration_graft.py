import unittest
from datetime import datetime, timezone

from snyk_correlate.coordinates import aggregate_last_introduced_at
import pandas as pd

from snyk_correlate.migration_graft import (
    OldIssueSnapshot,
    ProjectMigrationIndex,
    apply_migration_graft_row,
    build_issue_id_map,
    enrich_dataframe_migration_graft,
    migration_identity_from_row,
)


from snyk_correlate.pharos.issues import merge_code_issue_fingerprints


class TestCodeFingerprintMerge(unittest.TestCase):
    def test_merge_does_not_split_fingerprint_column(self):
        issues = pd.DataFrame(
            [
                {
                    "issue_key": "code-key-1",
                    "project_id": "p1",
                    "issue_type": "code",
                    "issue_fingerprint": None,
                }
            ]
        )
        code = pd.DataFrame(
            [{"issue_key": "code-key-1", "project_id": "p1", "issue_fingerprint": "fp.abc.def"}]
        )
        out = merge_code_issue_fingerprints(issues, code)
        self.assertEqual(list(out.columns), ["issue_key", "project_id", "issue_type", "issue_fingerprint"])
        self.assertEqual(out.loc[0, "issue_fingerprint"], "fp.abc.def")
        self.assertEqual(migration_identity_from_row(out.iloc[0]), "fp.abc.def")


class TestMigrationGraft(unittest.TestCase):
    def test_sca_identity_and_graft_maps_legacy_id(self):
        cache = {
            ("org1", "proj-new"): ProjectMigrationIndex(
                old_org_id="org1",
                old_project_id="proj-old",
                by_identity={
                    "sca-key-1": OldIssueSnapshot(
                        issue_id="old-uuid",
                        created_at="2024-01-01T00:00:00+00:00",
                        updated_at="2024-06-01T00:00:00+00:00",
                        last_introduced_at="2024-01-01T00:00:00+00:00",
                    )
                },
            )
        }
        row = {
            "org_id": "org1",
            "project_id": "proj-new",
            "issue_id": "new-uuid",
            "issue_key": "sca-key-1",
            "issue_type": "package_vulnerability",
            "issue_created_at": "2026-01-01T00:00:00+00:00",
            "issue_updated_at": "2026-01-02T00:00:00+00:00",
        }
        self.assertEqual(migration_identity_from_row(row), "sca-key-1")
        graft = apply_migration_graft_row(row, cache)
        self.assertTrue(graft["issue_migration_grafted"])
        self.assertEqual(graft["issue_legacy_id"], "old-uuid")
        self.assertEqual(graft["issue_created_at"], "2024-01-01T00:00:00+00:00")
        self.assertEqual(graft["issue_updated_at"], "2024-06-01T00:00:00+00:00")
        self.assertEqual(row["issue_id"], "new-uuid")

    def test_sast_uses_fingerprint(self):
        row = {
            "issue_type": "code",
            "issue_fingerprint": "fp-abc",
            "issue_key": "proj-scoped-key",
        }
        self.assertEqual(migration_identity_from_row(row), "fp-abc")

    def test_issue_id_map(self):
        import pandas as pd

        df = pd.DataFrame(
            [
                {"issue_id": "n1", "issue_legacy_id": "o1", "issue_migration_grafted": True},
                {"issue_id": "n2", "issue_legacy_id": None, "issue_migration_grafted": False},
            ]
        )
        self.assertEqual(build_issue_id_map(df), {"n1": "o1"})

    def test_enrich_preserves_live_dates_when_not_grafted(self):
        cache = {
            ("org1", "proj-new"): ProjectMigrationIndex(
                old_org_id="org1",
                old_project_id="proj-old",
                by_identity={
                    "sca-key-1": OldIssueSnapshot(
                        issue_id="old-uuid",
                        created_at="2024-01-01T00:00:00+00:00",
                        updated_at="2024-06-01T00:00:00+00:00",
                        last_introduced_at="2024-01-01T00:00:00+00:00",
                    )
                },
            )
        }
        df = pd.DataFrame(
            [
                {
                    "org_id": "org1",
                    "project_id": "proj-new",
                    "issue_id": "new-1",
                    "issue_key": "sca-key-1",
                    "issue_type": "package_vulnerability",
                    "issue_created_at": "2026-01-01T00:00:00+00:00",
                    "issue_updated_at": "2026-01-02T00:00:00+00:00",
                    "issue_last_introduced_at": "2026-01-01T00:00:00+00:00",
                },
                {
                    "org_id": "org1",
                    "project_id": "proj-other",
                    "issue_id": "new-2",
                    "issue_key": "no-match",
                    "issue_type": "package_vulnerability",
                    "issue_created_at": "2026-02-01T00:00:00+00:00",
                    "issue_updated_at": "2026-02-02T00:00:00+00:00",
                    "issue_last_introduced_at": "2026-02-01T00:00:00+00:00",
                },
            ]
        )
        out = enrich_dataframe_migration_graft(df, cache)
        self.assertTrue(out.loc[0, "issue_migration_grafted"])
        self.assertEqual(out.loc[0, "issue_created_at"], "2024-01-01T00:00:00+00:00")
        self.assertFalse(out.loc[1, "issue_migration_grafted"])
        self.assertEqual(out.loc[1, "issue_created_at"], "2026-02-01T00:00:00+00:00")
        self.assertEqual(out.loc[1, "issue_updated_at"], "2026-02-02T00:00:00+00:00")

    def test_graft_predecessor_issue_id_replaces_issue_id(self):
        cache = {
            ("org1", "proj-new"): ProjectMigrationIndex(
                old_org_id="org1",
                old_project_id="proj-old",
                by_identity={
                    "sca-key-1": OldIssueSnapshot(
                        issue_id="old-uuid",
                        created_at="2024-01-01T00:00:00+00:00",
                        updated_at=None,
                        last_introduced_at=None,
                    )
                },
            )
        }
        df = pd.DataFrame(
            [
                {
                    "org_id": "org1",
                    "project_id": "proj-new",
                    "issue_id": "new-uuid",
                    "issue_key": "sca-key-1",
                    "issue_type": "package_vulnerability",
                    "issue_created_at": "2026-01-01T00:00:00+00:00",
                    "issue_updated_at": "2026-01-02T00:00:00+00:00",
                }
            ]
        )
        out = enrich_dataframe_migration_graft(df, cache, graft_predecessor_issue_id=True)
        self.assertEqual(out.loc[0, "issue_id"], "old-uuid")
        self.assertEqual(out.loc[0, "issue_snyk_id_current"], "new-uuid")
        self.assertEqual(out.loc[0, "issue_legacy_id"], "old-uuid")
        self.assertEqual(build_issue_id_map(out), {"new-uuid": "old-uuid"})


class TestCoordinates(unittest.TestCase):
    def test_min_last_introduced(self):
        t1 = "2024-01-01T00:00:00.000Z"
        t2 = "2025-01-01T00:00:00.000Z"
        dt = aggregate_last_introduced_at(
            [{"last_introduced_at": t2}, {"last_introduced_at": t1}],
            use_min=True,
        )
        self.assertEqual(dt, datetime(2024, 1, 1, tzinfo=timezone.utc))

    def test_two_digit_fractional_seconds(self):
        dt = aggregate_last_introduced_at(
            [{"last_introduced_at": "2025-09-04T23:51:45.01+00:00"}],
            use_min=True,
        )
        self.assertIsNotNone(dt)


if __name__ == "__main__":
    unittest.main()
