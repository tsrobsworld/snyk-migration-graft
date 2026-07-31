"""Column lists for Pharos-style issues dataframes."""

ISSUE_COLUMN_LIST = [
    "issue_id",
    "org_id",
    "project_id",
    "issue_link",
    "issue_key",
    "issue_type",
    "issue_fingerprint",
    "issue_title",
    "issue_status",
    "issue_created_at",
    "issue_updated_at",
    "issue_last_introduced_at",
    "issue_effective_severity_level",
    "issue_snyk_id_current",
    "issue_legacy_id",
    "issue_migration_grafted",
    "issue_migration_identity",
    "issue_migration_old_org_id",
    "issue_migration_old_project_id",
]

CODE_ISSUE_COLUMN_LIST = [
    "issue_key",
    "issue_fingerprint",
    "project_id",
]
