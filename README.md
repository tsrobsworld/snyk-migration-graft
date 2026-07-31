# snyk-migration-graft

**Pipeline enrichment source** for Snyk repo migration: after a repo moves to a new project (hostname change, re-import), adjust bulk issue rows with predecessor **dates** and optional **issue id** handling—one row per API issue, in the customer’s existing Pharos pull.

This is **not** a standalone app or service. It is **importable Python modules** (`snyk_correlate/`) that run **inside** the customer’s scheduled `issues.py` job. Recommended delivery is **vendored source** in their monorepo ([docs/VENDORING.md](docs/VENDORING.md)), not a separate deployed “application.”


|                           |                                                                                     |
| ------------------------- | ----------------------------------------------------------------------------------- |
| **What it is**            | Reusable matching + graft logic; main entry `enrich_issues_dataframe`               |
| **What it is not**        | Replacement for `issues.py`, SLA engine, or warehouse jobs                          |
| **This repo (Snyk team)** | Same modules + local mock pipeline, CLI, and tests; `pip install -e .` for dev only |
| **Customer**              | Copy `snyk_correlate/` + one hook in their `issues.py`                              |


Architecture: [docs/IMPLEMENTATION_GUIDE.md](docs/IMPLEMENTATION_GUIDE.md)  
Customer wiring: [docs/CUSTOMER_INTEGRATION_snyk-info-sharing.md](docs/CUSTOMER_INTEGRATION_snyk-info-sharing.md)  
Internal QA: [docs/INTERNAL_TESTING.md](docs/INTERNAL_TESTING.md)

---



## The problem

SLA/grace-period logic uses issue introduction and update times. After migration, Snyk assigns new issue IDs and new timestamps on the new project. There is no Issues API write for `created_at` and `updated_at`. Correction happens in your pipeline when you load issues into the warehouse.

---



## What `migration_graft` does

For each distinct `(org_id, project_id)` in a batch of **new** issue rows:

1. Resolve the **predecessor** project — oldest `created_at` before the current project among candidates matching on *all* of:
  - same normalized repo (`repo_key`: `attributes.url` / `display_name` reduced to `org/repo`, hostname-insensitive)
  - same product (SCA vs SAST)
  - same **scan type and manifest** (`attributes.type` + `attributes.target_file`) — a repo import yields one project per manifest, and they all share a repo key and the `sca` product, so without this the npm project for `package.json` resolves to the repo's Dockerfile or to `frontend/package.json` and no identity lines up
2. Fetch **open issues** on the predecessor and index them by stable identity:
  - **SAST:** `issue_fingerprint` ← code issue details (must already be on the DataFrame)
  - **everything else** (`package_vulnerability`, `license`, `config`): `issue_key` ← `attributes.key`. The predecessor fetch is deliberately *not* narrowed to `type=package_vulnerability` — an IaC or npm project also carries `config` and `license` issues.
3. **Graft** matching rows: set legacy id and predecessor `created_at`, `updated_at`, and aggregated `last_introduced_at`.

API work scales with **unique projects**, not issue count. Your existing group/org issue pull is unchanged except for the hook below.

---



## Customer implementation (Pharos / bulk pipeline)

**You do not replace their** `issues.py` **with this repo.** They keep `ear0_pharos.snyk.issues`: pagination, `parse_issues_data`, code details merge, date-window entry points.

**Recommended:** copy the `snyk_correlate` source tree into their monorepo ([docs/VENDORING.md](docs/VENDORING.md)) — no new pip/git package approval. Then call `enrich_issues_dataframe` once per pull, after SAST fingerprints are merged.

Step-by-step for the supplied `issues.py` / `api.py`: [docs/CUSTOMER_INTEGRATION_snyk-info-sharing.md](docs/CUSTOMER_INTEGRATION_snyk-info-sharing.md).

### Pipeline order (required)

```text
GET group/org issues → parse_issues_data → code details + merge fingerprints → enrich_issues_dataframe → downstream
```

SAST graft **must not** run before `issue_fingerprint` exists on code rows.

### Hook (after code-details merge)

```python
from snyk_correlate.migration_graft import enrich_issues_dataframe

if apply_migration_graft:  # default on in v4; see opt-out below
    df = await enrich_issues_dataframe(
        df,
        client,  # your existing SnykClient (aiohttp)
        api_version=projects_api_version,      # e.g. 2024-10-15
        issues_api_version=api_version,        # e.g. 2024-05-08
    )
```

Wire this at the end of:

- `get_all_issue_created_between_dates`
- `get_all_issue_updated_between_dates`
- (optional) `get_all_issues_by_organization`

Pass the same `client` instance you use for issue pulls. In this repo, `snykapi.SnykClient` is a standalone copy of your `api.py` for local runs; in production, `from ear0_pharos.snyk.api import SnykClient` is fine — `enrich_issues_dataframe` only needs that client’s `get_snyk_api_async` behavior.

### Changes in **your** `parse_issues_data`

Add `issue_last_introduced_at` from `attributes.coordinates[]` (not top-level). Use the same aggregation for new rows and for predecessor snapshots (this package uses **min** across coordinates by default — see `snyk_correlate.coordinates`).

### Opt out

- `apply_migration_graft=False` on your wrapper, or
- env `SNYK_APPLY_MIGRATION_GRAFT=0` / `false` / `off` where you map env to that flag.



### Row behavior (warehouse)

Same row count as the API pull (one row per issue). On **match**, `issue_created_at`, `issue_updated_at`, and `issue_last_introduced_at` are overwritten from the predecessor. On **no match**, those columns stay from the current pull.

#### Issue id — two options


| Mode                              | Parameter / env                                              | On match: `issue_id` | On match: also set                                                    |
| --------------------------------- | ------------------------------------------------------------ | -------------------- | --------------------------------------------------------------------- |
| **A — dual column (default)**     | `graft_predecessor_issue_id=False`                           | Live (new) Snyk id   | `issue_legacy_id` = predecessor id                                    |
| **B — predecessor in** `issue_id` | `graft_predecessor_issue_id=True` or `SNYK_GRAFT_ISSUE_ID=1` | Predecessor id       | `issue_snyk_id_current` = live id; `issue_legacy_id` = predecessor id |


**Option A** (default hook — no extra args):

```python
df = await enrich_issues_dataframe(
    df, client,
    api_version=projects_api_version,
    issues_api_version=api_version,
)
```

**Option B:**

```python
df = await enrich_issues_dataframe(
    df, client,
    api_version=projects_api_version,
    issues_api_version=api_version,
    graft_predecessor_issue_id=True,
)
```


| Outcome      | Option A                                | Option B                                    |
| ------------ | --------------------------------------- | ------------------------------------------- |
| **Match**    | `issue_id` new, `issue_legacy_id` old   | `issue_id` old, `issue_snyk_id_current` new |
| **No match** | `issue_id` new, `issue_legacy_id` empty | same as A for id columns                    |


`build_issue_id_map(df)` returns `{live_id: predecessor_id}` for grafted rows in either mode.

### Columns added by graft

Among others: `issue_legacy_id`, `issue_snyk_id_current` (option B only), `issue_migration_grafted`, `issue_migration_old_org_id`, `issue_migration_old_project_id`, `issue_migration_identity`. On match, `issue_created_at`, `issue_updated_at`, and `issue_last_introduced_at` are overwritten from the predecessor.

Optional helper: `build_issue_id_map(df)` → `{new_issue_id: legacy_issue_id}` for grafted rows only.

---



## Public API (`migration_graft.py`)


| Function                                         | Use                                                                                   |
| ------------------------------------------------ | ------------------------------------------------------------------------------------- |
| `enrich_issues_dataframe(df, client, …)`         | **Main entry** — build cache + apply graft; `graft_predecessor_issue_id` for option B |
| `build_migration_cache(client, project_keys, …)` | Cache only (advanced)                                                                 |
| `enrich_dataframe_migration_graft(df, cache)`    | Graft only when cache already built                                                   |
| `build_issue_id_map(df)`                         | Sidecar map for joins                                                                 |


Lower-level matching and fetch live in `matching.py`, `resolver.py`, `project_scope.py`, and `snykapi.py` (used internally by the cache builder).

---



## Rate limits

Snyk: **1620 requests/minute/API key**. On **429**, the bundled client sleeps `SNYK_RATE_LIMIT_BACKOFF_SECONDS` (default **60**) and retries. For large pulls, keep concurrent project cache work modest (e.g. `SNYK_CONCURRENT=5` on the client).

---



## Tests

```bash
pip install -e .
python3 -m unittest discover -s tests -v
```

No token or network required for unit tests.

---



## Local end-to-end mock (not production)

This repo includes a **Pharos-shaped reference pipeline** (`snyk_correlate/pharos/issues.py` + `scripts/run_pharos_issues.py`) so you can pilot without `ear0_pharos`. That is **not** what customers install into Pharos — see **[snyk_correlate/pharos/README.md](snyk_correlate/pharos/README.md)**.

---



## CLI (optional)

Per-project debugging and parity with Go `issuewrapper`:

```bash
export SNYK_TOKEN=...
python3 -m snyk_correlate.cli --org-id ORG --display-name acme/widgets
```

Emits predecessor issue JSON keyed by identity; bulk Pharos flows should use `enrich_issues_dataframe` instead.

---



## Known assumptions (`snykapi.py`)

Verify against real org data if something misbehaves:

1. **Targets:** do not rely on `display_name` query param (400 on some tenants); filter client-side.
2. **Product:** SAST vs SCA from project/issue type fields.
3. **Projects API** creation timestamp field name vs Issues API `created_at`.
4. **Predecessor search** is within one org (not cross-org group migrations).

---



## For Cursor / agents

See `.cursorrules` in this directory.