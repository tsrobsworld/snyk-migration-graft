# Pharos reference pipeline (local mock)

This package subtree is a **stand-in for the customer’s `ear0_pharos.snyk.issues` module**. It exists so this repository can run a full **pull → parse → code fingerprints → migration graft** flow **without** importing `ear0_pharos`.

**Customers do not copy this into production.** They vendor **`snyk_correlate`** into their monorepo ([docs/VENDORING.md](../../docs/VENDORING.md)) and call **`migration_graft.enrich_issues_dataframe`** from their own `issues.py` — see the [root README](../../README.md).

Related repos (from handoff docs):

| Repo | Role |
|------|------|
| `snyk-info-sharing` | Customer Pharos — real `issues.py` to wire |
| This repo | Library + this mock for pilots |

Full design: [docs/IMPLEMENTATION_GUIDE.md](../../docs/IMPLEMENTATION_GUIDE.md)  
Pilot notes: [docs/CONTINUATION.md](../../docs/CONTINUATION.md)

---

## What lives here

| File | Role |
|------|------|
| `issues.py` | Mimics production: `parse_issues_data`, group/org issue GETs, code details merge, **`get_all_issue_created_between_dates`** / **`get_all_issue_updated_between_dates`**, **`enrich_pulled_issues_dataframe`**, **`pull_issues_for_pipeline`** (dev org/group runner) |
| `constants.py` | Column lists (`ISSUE_COLUMN_LIST`, graft/migration columns) |
| `../../scripts/run_pharos_issues.py` | Env-based dev runner (CSV export, graft summary) |

**Production-shaped group entry points** (date-window pulls + graft on by default):

- **`get_all_issue_created_between_dates(group_id, client, created_after, created_before, api_version, …)`**
- **`get_all_issue_updated_between_dates(group_id, client, updated_after, updated_before, api_version, …)`**

Both call **`enrich_pulled_issues_dataframe`** (fingerprints → columns → optional **`enrich_issues_dataframe`**). Set **`apply_migration_graft=False`** for a raw pull.

---

## How it relates to the customer’s `issues.py`

```text
Customer (production)                    This repo (mock)
─────────────────────                    ─────────────────
ear0_pharos.snyk.api.SnykClient    ≈    snykapi.SnykClient (vendored copy)
ear0_pharos.snyk.issues.*          ≈    snyk_correlate.pharos.issues.*
migration logic                    →    snyk_correlate.migration_graft (import only)
```

The mock **`pull_issues_for_pipeline`** and production **`get_all_issue_*_between_dates`** share the same post-pull step:

1. Group or org issues (paginated)
2. `parse_issues_data` (includes `issue_last_introduced_at` from coordinates)
3. **`enrich_pulled_issues_dataframe`**: code details merge + columns + optional graft

Reference implementation (graft hook inside enrich):

```python
from snyk_correlate.migration_graft import enrich_issues_dataframe

# inside enrich_pulled_issues_dataframe, after code fingerprint merge:
if apply_migration_graft:
    df = await enrich_issues_dataframe(
        df, client,
        api_version=projects_api_version,
        issues_api_version=api_version,
    )
```

---

## Run locally

From repo root:

```bash
pip install -e .
```

**Org pilot (full pagination + graft):**

```bash
SNYK_ORG_ID=<org-uuid> \
SNYK_GROUP_ID= \
SNYK_ISSUES_LIMIT=all \
SNYK_CONCURRENT=5 \
SNYK_OUTPUT_CSV=output/issues.csv \
PYTHONUNBUFFERED=1 \
PYTHONPATH=. \
python3 -u scripts/run_pharos_issues.py
```

**Group pull:** set `SNYK_GROUP_ID`; leave or clear `SNYK_ORG_ID` depending on whether you want org parity checks (script uses org when limit is capped).

### Environment variables

| Variable | Purpose |
|----------|---------|
| `SNYK_TOKEN` | Required |
| `SNYK_API` | Default `https://api.snyk.io` |
| `SNYK_ORG_ID` / `SNYK_GROUP_ID` | Org vs group pull (`pull_issues_for_pipeline` prefers group if set) |
| `SNYK_ISSUES_API_VERSION` | Issues list (default `2024-05-08`) |
| `SNYK_API_VERSION` | Projects/targets (default `2024-10-15`) |
| `SNYK_CODE_ISSUES_API_VERSION` | Code details (default `2024-10-14~experimental`) |
| `SNYK_ISSUES_LIMIT` | `all` / empty = full pagination; number = single page (dev) |
| `SNYK_APPLY_MIGRATION_GRAFT` | Default on; `0`/`false`/`off` to disable |
| `SNYK_CONCURRENT` | Parallel API calls (default 5) |
| `SNYK_TIMEOUT` | Request timeout seconds |
| `SNYK_OUTPUT_CSV` | Optional CSV path |
| `SNYK_RATE_LIMIT_BACKOFF_SECONDS` | 429 backoff (default 60; see root README) |

---

## Validation helpers

- **`validate_group_vs_org_issue_parity`** — sample compare of issue id sets (dev only).
- **`resolve_org_id_for_group`** — pick an org for parity when only group id is set.

---

## Pilot reminders

- Re-export after **code fingerprint merge** fixes; SAST graft requires non-empty `issue_fingerprint` before cache build.
- On cache miss, rows keep live ids and API dates; see root README row table.
