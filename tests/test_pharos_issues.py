import unittest
from unittest.mock import AsyncMock, patch

import pandas as pd

from snyk_correlate.pharos import issues as pharos_issues


class TestGroupDateWindowEntryPoints(unittest.IsolatedAsyncioTestCase):
    async def test_created_between_passes_query_params_and_enriches(self) -> None:
        raw = pd.DataFrame([{"issue_id": "a", "org_id": "o", "project_id": "p"}])
        enriched = pd.DataFrame([{"issue_id": "a", "issue_migration_grafted": False}])
        with patch.object(
            pharos_issues, "get_group_issues", new_callable=AsyncMock, return_value=raw
        ) as get_group:
            with patch.object(
                pharos_issues,
                "enrich_pulled_issues_dataframe",
                new_callable=AsyncMock,
                return_value=enriched,
            ) as enrich:
                client = object()
                out = await pharos_issues.get_all_issue_created_between_dates(
                    "group-1",
                    client,
                    "2026-01-01T00:00:00Z",
                    "2026-02-01T00:00:00Z",
                    "2024-05-08",
                    apply_migration_graft=True,
                )
        get_group.assert_awaited_once_with(
            "group-1",
            client,
            "2024-05-08",
            api_call_retry=3,
            param_extra={
                "created_after": "2026-01-01T00:00:00Z",
                "created_before": "2026-02-01T00:00:00Z",
            },
            max_pages=None,
        )
        enrich.assert_awaited_once()
        self.assertIs(out, enriched)

    async def test_updated_between_passes_query_params(self) -> None:
        with patch.object(
            pharos_issues, "get_group_issues", new_callable=AsyncMock, return_value=pd.DataFrame()
        ) as get_group:
            with patch.object(
                pharos_issues,
                "enrich_pulled_issues_dataframe",
                new_callable=AsyncMock,
                return_value=pd.DataFrame(),
            ):
                await pharos_issues.get_all_issue_updated_between_dates(
                    "g",
                    object(),
                    "2026-03-01T00:00:00Z",
                    "2026-04-01T00:00:00Z",
                    "2024-05-08",
                    apply_migration_graft=False,
                )
        get_group.assert_awaited_once()
        kwargs = get_group.await_args.kwargs
        self.assertEqual(
            kwargs["param_extra"],
            {
                "updated_after": "2026-03-01T00:00:00Z",
                "updated_before": "2026-04-01T00:00:00Z",
            },
        )


if __name__ == "__main__":
    unittest.main()
