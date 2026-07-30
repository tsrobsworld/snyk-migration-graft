# snyk-migration-graft

Python library for **Snyk repo migration**: match predecessor projects (GHE ↔ GHEC, re-imports) and enrich issue rows with `issue_legacy_id` and historical dates while keeping live `issue_id`.

**Suggested GitHub repo name:** `snyk-migration-graft`  
**Import package:** `snyk_correlate` (unchanged; pip name matches repo via `pyproject.toml`)

Install (from repo root after clone):

```bash
pip install -e .
```

Integration guide: [docs/IMPLEMENTATION_GUIDE.md](docs/IMPLEMENTATION_GUIDE.md)

---

# snyk_correlate (Python port)

## The problem

A customer's SLA/grace-period logic (e.g. 30 days to fix a critical) reads
`attributes.last_introduced_at` off a Snyk issue. When a repo migrates to a
new Snyk project (GitHub hostname change, re-import, etc.), Snyk has no
record of the old project - `last_introduced_at` resets to "just now" on
the new project, and the SLA clock silently restarts even though the
vulnerability has existed far longer.

There is **no PATCH/PUT on the Issues API** to fix this at the source
(confirmed - the Issues API is GET-only for `coordinates`/`last_introduced_at`,
which are computed by Snyk from actual scan history). So the correction has
to happen in the customer's own pipeline, not in Snyk.

## What this does

Given a project, it finds that project's **predecessor** (the project the
repo used to live at, before it migrated) by porting the same matching rule
used by a related tool, `match-snyk-projects`:

- Normalize `attributes.url` (SCM integrations) or `attributes.display_name`
  (CLI imports) down to `org/repo`, stripping scheme/host/`.git` suffix -
  this is what lets a match survive a hostname change
  (`github-enterprise.corp.com` -> `github.com`).
- Also match on **product** (SCA vs SAST) - a repo's dependency-scan
  project and its code-scan project migrate/version independently, so
  matching on repo alone isn't enough.
- Among same-repo, same-product candidates, the oldest one that predates
  the given project is the predecessor.

It then fetches that predecessor's **open issues** and returns them indexed
by the identity that's stable across a migration:
- `attributes.key` for SCA issues (dependency vulnerabilities)
- `fingerprint` for SAST issues (code issues) - `attributes.key` is
  project-scoped for SAST and does NOT survive a migration, so a second API
  call (`code_issue_details/{key}`) is needed to get the fingerprint

**This tool does not touch the new project's issues at all.** The customer's
existing issue pull stays exactly as-is; this produces a separate dataset
they join in on their end, keyed by `key`/`fingerprint`.

## Why it's built this way (architecture rationale)

The logic is split into two layers on purpose:

1. **Pure logic** (`matching.py`, `resolver.py`, `client.py`, `correlate.py`)
   depends only on `typing.Protocol` interfaces (`ProjectsClient`,
   `SnykIssuesClient`) and plain dataclasses. No `aiohttp`, no network, no
   I/O. This is what's unit tested (13 tests, all passing, no token/network
   needed) and it's what should NOT need to change once this gets wired
   into the customer's real codebase.
2. **Real API adapter** (`snykapi.py`) implements those Protocols against
   actual Snyk REST endpoints. This is the layer most likely to need
   adjustment once tested against real data (see "Known assumptions" below)
   - and it's isolated specifically so that fixing it doesn't risk breaking
   the matching logic.

This mirrors a Go prototype of the same tool (`issuewrapper` /
`snyk-issue-api-wrapper`) that preceded this port - same architecture,
same test cases, same identity/matching rules, just Python now because
that's the language of the customer's actual pipeline (`ear0_pharos`,
built on `aiohttp`).

## Where this came from / what's reused from the customer's code

Two files the customer shared (`api.py`, `issues.py`, from a package
called `ear0_pharos.snyk`) revealed the real integration surface:

- Their `SnykClient` (aiohttp-based, with retry/pagination/proxy support)
  is copied **verbatim** into `snykapi.py`. Once this is merged into their
  repo, delete that copy and `from ear0_pharos.snyk.api import SnykClient`
  instead - zero logic changes needed.
- Their `parse_issues_data` extracts `issue_id`, `org_id`, `project_id`
  (already present, from `relationships.scan_item.data.id`),
  `issue_created_at`, `issue_updated_at` - but **not**
  `last_introduced_at`. That's a one-line addition needed on their side
  regardless of how this correlation piece gets wired in.
- Their `get_all_code_issues_detail_by_issues` already does the SAST
  fingerprint enrichment call (`code_issue_details/{issue_key}` with
  `project_id`) - `SnykApiIssuesClient._fetch_fingerprint` in this port
  mirrors that exact call shape.
- Their production issue pull is **group-scoped and date-windowed**
  (`get_all_issue_updated_between_dates` / `_created_between_dates` against
  `rest/groups/{group_id}/issues`), not per-org. That's a bulk pull, so the
  integration point below (Scenario A vs B) matters for how correlation
  gets triggered per-project inside that bulk flow.

## Integration point - two scenarios (still open until their fuller pipeline is seen)

**Scenario A**: if `last_introduced_at`/grace-period logic reads directly
off the DataFrame `parse_issues_data` returns, then the natural spot is to
run `Correlator.correlate()` per distinct `(org_id, project_id)` right
after parsing, and join the result onto that DataFrame by `issue_key` (SCA)
or `issue_fingerprint` (SAST) before anything reads `last_introduced_at`.

**Scenario B**: if there's more machinery between parsing and where
`last_introduced_at` is actually consumed (a transform layer, a DB write, a
queue), the join needs to happen at that later point instead, using the
same identity keys.

**Check where `last_introduced_at` is actually *read* for the SLA decision,
not just where issues are fetched** - that's what determines which scenario
this is.

## Layout

```
snyk_correlate/
  models.py     - Issue, ProjectSummary, CorrelatedIssue, MigrationCorrelation (dataclasses)
  matching.py   - normalize_repo_url, normalize_display_name, repo_key
  resolver.py   - ProjectsClient Protocol + LiveResolver (the matching logic, live, no file dep)
  client.py     - SnykIssuesClient Protocol
  correlate.py  - Correlator.correlate() - the one call this whole thing is for
  snykapi.py    - real Snyk REST implementation of both Protocols (+ SnykClient, copied from api.py)
  cli.py        - standalone CLI wrapping all of the above
tests/
  test_matching.py    - repo-key normalization (hostname change, manifest suffix stripping)
  test_resolver.py    - predecessor matching (hostname change, product isolation, oldest-wins, no-match)
  test_correlate.py   - full correlate() flow with fake clients (no network)
```

## How to run it

```bash
pip install aiohttp

# unit tests - pure logic, no token/network required
python3 -m unittest discover -s tests -v

# real run, needs a Snyk token and real org/repo
export SNYK_TOKEN=...
python3 -m snyk_correlate.cli --org-id ORG --display-name acme/widgets
python3 -m snyk_correlate.cli --org-id ORG --repo-url https://github.com/acme/widgets --project-id PROJECT_UUID
python3 -m snyk_correlate.cli --org-id ORG --display-name acme/widgets --product sca
```

### CLI flags

| Flag | Required | Description |
|---|---|---|
| `--org-id` | yes | Snyk organization UUID |
| `--display-name` | one of repo flags | Target `display_name`, e.g. `acme/widgets` |
| `--repo-url` | one of repo flags | Repo URL; normalized to `org/repo` for the Targets API query |
| `--project-id` | no | NEW project to correlate; auto-selects newest-per-product if omitted |
| `--product` | no | `sca` or `sast`; narrows auto-selection when `--project-id` is omitted |
| `--snyk-tenant` | no | API host/region (default `https://api.snyk.io`, or `SNYK_API` env var) |
| `--snyk-api-version` | no | REST version for targets/projects (default `2024-10-15`) |
| `--snyk-issues-api-version` | no | Issues list API version (default `2024-05-08`) |
| `--snyk-code-issue-detail-api-version` | no | SAST fingerprint detail version (default `2024-10-14~experimental`) |

**Auth:** `SNYK_TOKEN` environment variable.

**Rate limits:** Snyk allows **1620 requests/minute/API key**. Over-limit calls return **429** until the **one-minute** window resets. `SnykClient` sleeps **`SNYK_RATE_LIMIT_BACKOFF_SECONDS`** (default **60**) and retries the same request (does not consume the normal 3-attempt error budget). For large org/group pulls + migration graft, keep **`SNYK_CONCURRENT`** modest (e.g. **5**) so parallel project cache builds stay under ~1620/min.


```json
{
  "new_org_id": "...",
  "new_project_id": "...",
  "match_found": true,
  "old_org_id": "...",
  "old_project_id": "...",
  "product": null,
  "issues": [
    {
      "identity_type": "key",
      "identity": "...",
      "old_issue_id": "...",
      "old_org_id": "...",
      "old_project_id": "...",
      "old_created_at": "2024-01-15T00:00:00+00:00",
      "old_last_introduced_at": "2024-01-15T00:00:00+00:00"
    }
  ]
}
```

## Known assumptions - verify against real data before trusting this

These are the parts of `snykapi.py` most likely to need a fix once run
against real Snyk responses (the pure logic in `matching.py`/`resolver.py`/
`correlate.py` is fully tested and shouldn't need to change):

1. **Targets API query param** - assumed `display_name` is a valid filter
   param on `GET /orgs/{org_id}/targets`. Confirm against a real response.
2. **How a project's product surfaces** - assumed
   `attributes.type == "sast"` marks a Snyk Code project, anything else is
   treated as SCA. Check a real SCA project's `attributes.type` (a package
   manager name like `npm`/`pip`) and a real SAST project's response to
   confirm this holds.
3. **`attributes.created` vs `attributes.created_at`** on the Projects API
   - used `created` in `snykapi.py`; the Issues API (confirmed from the
   customer's own code) uses `created_at`. These are different endpoints
   and may not share a naming convention - verify.
4. **Cross-org migrations** - `LiveResolver` only searches within one org.
   If a migration can move a repo to a different org, `ProjectsClient` needs
   to search across a group instead - not implemented here.

## For Cursor / AI agents editing this repo

See `.cursorrules` in this directory for a condensed version of the above,
written for quick context-loading rather than narrative reading.
