# Internal testing (before customer)

Hand this to a teammate to validate the library and mock pipeline **before** wiring into `snyk-info-sharing` / Pharos.

**Reference org (scale + GHE/GHEC pairs):** `57da1293-fe41-46a2-a67f-106c31cc6d3a`  
**Last full export (for comparison):** `output/issues.csv` + `output/run.log` in this repo (~32k rows, ~5.9k grafted, ~722 Code grafts, ~55 old/new project pairs).

**What you are proving:** migration graft runs end-to-end against real Snyk data, leaves one row per issue, overwrites dates only on match, and (optionally) can put the predecessor id in `issue_id` — without changing their SLA or warehouse jobs yet (those consume the DataFrame this library produces).

---

## Prerequisites

| Item | Detail |
|------|--------|
| **Token** | `SNYK_TOKEN` with read access to Issues, Projects, Targets, Code issue details for the test org |
| **Python** | 3.9+ (matches `pyproject.toml`) |
| **Repo** | Clone `snyk_correlate_py` (package name `snyk-migration-graft`, import `snyk_correlate`) |
| **Network** | Outbound HTTPS to `api.snyk.io` (or customer region URL in `SNYK_API`) |
| **Disk** | ~50–100 MB if you keep full CSV exports under `output/` |

```bash
cd snyk_correlate_py
pip install -e .
export SNYK_TOKEN=...   # never commit or paste into tickets
```

Optional env (defaults are fine for first run):

- `SNYK_API` — default `https://api.snyk.io`
- `SNYK_CONCURRENT=5` — parallel API calls during cache build
- `SNYK_TIMEOUT=60` — request timeout seconds

Do **not** commit tokens or production CSVs to git (`output/*.csv` should stay local or gitignored).

---

## Step 1 — Unit tests (no network)

**Purpose:** Confirm matching, resolver, graft apply, fingerprint merge, and Pharos date-window wrappers without a token. Catches regressions in pure logic before you spend time on API runs.

**Command:**

```bash
cd snyk_correlate_py
PYTHONPATH=. python3 -m unittest discover -s tests -v
```

**Expect:** `Ran 23 tests` … `OK` (count may increase as tests are added).

**What the suite covers (high level):**

- Repo key normalization (hostname change, manifest suffix)
- Predecessor selection (product isolation, oldest wins, no match)
- Graft row apply: legacy id, in-place dates, no NaN on non-grafted rows
- Code fingerprint merge (no `issue_fingerprint_x` / `_y` split)
- `graft_predecessor_issue_id=True` swaps id + sets `issue_snyk_id_current`
- Group `created_between` / `updated_between` pass correct query params

**If it fails:** fix in repo before any live pull; failures here are logic bugs, not Snyk/data issues.

**Time:** ~1 minute.

---

## Step 2 — Small org pull (fast smoke)

**Purpose:** Hit real Snyk with one page of org issues, run parse → code details → migration cache → graft. Validates token, API versions, and that the dev script path works.

**Command:**

```bash
SNYK_ORG_ID=57da1293-fe41-46a2-a67f-106c31cc6d3a \
SNYK_GROUP_ID= \
SNYK_ISSUES_LIMIT=100 \
SNYK_APPLY_MIGRATION_GRAFT=1 \
SNYK_CONCURRENT=5 \
PYTHONUNBUFFERED=1 \
PYTHONPATH=. \
python3 -u scripts/run_pharos_issues.py
```

**Watch the log for:**

1. `pull: org=... limit=100 (single page)` — not full pagination
2. `migration_graft=on`
3. `INFO:...pagination rest/orgs/.../issues: page 1` — then code details for `code` rows, then many `projects` / `targets` / `issues` lines during cache build (normal)
4. Final summary: `rows=`, `unique_projects=`, `grafted=`, `grafted_project_pairs=`

**Rough expectations (100-row sample — varies by sample):**

- `rows` ≈ 100 (or fewer if org has &lt;100 open issues on that page)
- `grafted` may be **0** on a bad luck sample; if 0, retry with `SNYK_ISSUES_LIMIT=500` or proceed to Step 3
- No Python traceback; exit code 0

**Failure modes:**

| Symptom | Likely cause |
|---------|----------------|
| `SNYK_TOKEN is required` | Token not exported in shell |
| 401 / 403 | Token or org access |
| 429 spam | Lower `SNYK_CONCURRENT` to 3; wait and retry |
| `grafted=0` on 100 rows only | Sample has no migrated projects — not necessarily a bug |

**Time:** ~1–5 minutes depending on code-issue count in sample.

---

## Step 3 — Full org pull (optional, ~15–45 min)

**Purpose:** Reproduce pilot scale; confirm Code grafts, graft rate, and pagination through entire org issue list + cache for all unique projects in the batch.

**Command:**

```bash
SNYK_ORG_ID=57da1293-fe41-46a2-a67f-106c31cc6d3a \
SNYK_GROUP_ID= \
SNYK_ISSUES_LIMIT=all \
SNYK_CONCURRENT=5 \
SNYK_OUTPUT_CSV=output/issues-teammate.csv \
PYTHONUNBUFFERED=1 \
PYTHONPATH=. \
python3 -u scripts/run_pharos_issues.py 2>&1 | tee output/run-teammate.log
```

**Progress cues in log:**

- Issues pagination every ~25 pages logged (`page 25`, `page 50`, … up to ~300 for ~32k issues)
- Burst of `code_issue_details` calls
- Long phase of per-project cache (`projects`, `targets`, predecessor `issues`)

**Compare to baseline (`output/issues.csv` / `output/run.log`):**

| Metric | Baseline (reference) |
|--------|----------------------|
| Rows | ~32,023 |
| Grafted | ~5,888 (~18.4%) |
| Grafted SCA | ~5,166 |
| Grafted Code | ~722 |
| Project pairs | ~55 |

Numbers need not match exactly (Snyk data changes daily) but same **order of magnitude**. **Red flag:** `grafted_code=0` at full org scale (suggests fingerprint merge regression).

**Time:** ~15–45 min; do not interrupt. Use `tee` so you can tail `output/run-teammate.log` in another terminal.

---

## Step 4 — Validate CSV

**Purpose:** Automated sanity checks on the export; catches “graft broke dates on non-matches” and missing SAST grafts.

**Command** (adjust `path` to your file):

```bash
cd snyk_correlate_py
python3 <<'PY'
import pandas as pd
path = "output/issues-teammate.csv"  # or output/issues.csv
df = pd.read_csv(path)
g = df["issue_migration_grafted"].fillna(False)
print("rows", len(df))
print("unique_projects", df["project_id"].nunique())
print("grafted", int(g.sum()), f"({100*g.mean():.1f}%)")
code = df["issue_type"] == "code"
print("grafted_code", int((g & code).sum()))
print("grafted_sca", int((g & (df["issue_type"]=="package_vulnerability")).sum()))
if g.any():
    pairs = df.loc[g, ["project_id", "issue_migration_old_project_id"]].drop_duplicates()
    print("grafted_project_pairs", len(pairs))
# Non-grafted rows must still have dates (pilot bug was NaN here)
miss = (~g) & (df["issue_created_at"].isna() | df["issue_updated_at"].isna())
print("non_grafted_missing_dates", int(miss.sum()), "expect 0")
# Grafted rows should have legacy id (option A)
if g.any():
    leg = df.loc[g, "issue_legacy_id"].notna().sum()
    print("grafted_with_legacy_id", int(leg), "expect equals grafted count")
# Code rows with fingerprint should sometimes graft
fp = code & df["issue_fingerprint"].notna()
print("code_rows_with_fingerprint", int(fp.sum()))
print("grafted_among_those", int((g & fp).sum()))
if g.any():
    r = df.loc[g].iloc[0]
    print("--- sample grafted row ---")
    print("issue_id", r["issue_id"])
    print("issue_legacy_id", r.get("issue_legacy_id"))
    print("issue_created_at", r["issue_created_at"])
    print("old_project", r.get("issue_migration_old_project_id"))
PY
```

**Manual spot-check (one SCA + one Code grafted row in Excel/CSV):**

- `issue_id` ≠ `issue_migration_old_project_id`’s issues on new project — ids should be **new** live ids (option A)
- `issue_created_at` on grafted row should look **older** than migration date (~2026-07-24 on pilot) when predecessor exists
- `issue_migration_identity` = `issue_key` (SCA) or fingerprint (Code)

**Time:** ~2 minutes.

---

## Step 5 — Issue id option B

**Purpose:** Confirm `SNYK_GRAFT_ISSUE_ID=1` / `graft_predecessor_issue_id=True` for downstream that keys on predecessor `issue_id`.

**Command:**

```bash
SNYK_ORG_ID=57da1293-fe41-46a2-a67f-106c31cc6d3a \
SNYK_ISSUES_LIMIT=100 \
SNYK_GRAFT_ISSUE_ID=1 \
SNYK_OUTPUT_CSV=output/issues-graft-id.csv \
PYTHONPATH=. python3 scripts/run_pharos_issues.py
```

Console should show: `graft_predecessor_issue_id=on`.

**Validate:**

```bash
python3 <<'PY'
import pandas as pd
df = pd.read_csv("output/issues-graft-id.csv")
g = df["issue_migration_grafted"].fillna(False)
sub = df.loc[g].head(5)
for _, r in sub.iterrows():
    assert r["issue_id"] == r["issue_legacy_id"], "option B: issue_id should be predecessor"
    assert pd.notna(r.get("issue_snyk_id_current")), "live id should be preserved"
    assert r["issue_snyk_id_current"] != r["issue_id"]
print("option B spot check OK on", len(sub), "rows")
PY
```

Non-grafted rows: `issue_id` unchanged; `issue_snyk_id_current` empty/null.

**Time:** ~2–5 minutes.

---

## Step 6 — Single-repo CLI (debug one migration)

**Purpose:** Isolate **one** repo pair without full org pull — useful when disputing “no predecessor” for a specific project.

Replace `org/repo` with a known GHE/GHEC pair from the customer (or ask for one display name from the pilot org).

```bash
export SNYK_TOKEN=...
python3 -m snyk_correlate.cli \
  --org-id 57da1293-fe41-46a2-a67f-106c31cc6d3a \
  --display-name org/repo \
  --product sca
```

**Expect JSON:**

- `match_found: true`
- `old_project_id` different from `new_project_id`
- `issues[]` with `identity`, `old_issue_id`, `old_created_at`, `old_last_introduced_at`

Repeat with `--product sast` and `--project-id <uuid>` if you have a Code project id.

**If `match_found: false`:** repo string may not match Targets filter, or no older same-product project — not always a code bug.

**Time:** ~30 seconds per repo.

---

## Sign-off checklist (before customer)

- [ ] Step 1: 23 tests OK
- [ ] Step 2: smoke completes, no traceback
- [ ] Step 3 (recommended): full org metrics in line with baseline; **grafted_code &gt; 0**
- [ ] Step 4: `non_grafted_missing_dates == 0`; grafted rows have `issue_legacy_id`
- [ ] Step 5 (if customer uses option B): id swap + `issue_snyk_id_current` verified
- [ ] Step 6: at least one known repo shows `match_found: true`
- [ ] Read [CUSTOMER_INTEGRATION_snyk-info-sharing.md](CUSTOMER_INTEGRATION_snyk-info-sharing.md) and [VENDORING.md](VENDORING.md) for customer delivery

**Sign-off record:** note date, tester name, git commit hash, and which CSV/log files you kept.

---

## After internal sign-off

1. **Deliver to customer** — vendored `snyk_correlate/` tree + PR sketch from [VENDORING.md](VENDORING.md) and [CUSTOMER_INTEGRATION_snyk-info-sharing.md](CUSTOMER_INTEGRATION_snyk-info-sharing.md) (no package registry unless they prefer it later).
2. **Customer PR** — drop tree, wire `api.SnykClient`, `enrich_issues_dataframe` after code merge in `issues.py`.
3. **Customer staging** — one group date window with graft on; compare to pre-graft row counts.
4. **Production** — graft on by default; keep `apply_migration_graft=False` for one cycle if needed.

Phase 2 (not blocking first drop): durable predecessor cache, target-scoped resolver — [CONTINUATION.md](CONTINUATION.md).
