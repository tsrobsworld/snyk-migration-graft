"""Repo-identity normalization - mirrors resolver.go's normalizeRepoURL /
normalizeDisplayName from the Go version. Same match key: "org/repo",
ignoring hostname, so a repo matches across a hostname change
(github-enterprise -> github-cloud-app) or across CLI re-imports.
"""

from __future__ import annotations

from typing import Tuple
from urllib.parse import urlparse


def normalize_repo_url(raw: str) -> str:
    """Strip scheme, host, and .git suffix, leaving "org/repo" lowercased."""
    if not raw:
        return ""
    path = urlparse(raw).path
    if path.endswith(".git"):
        path = path[: -len(".git")]
    return path.strip("/").lower()


def normalize_display_name(raw: str) -> str:
    """Mirror normalize_repo_url for CLI-imported projects, whose
    attributes.display_name looks like "org/repo" or
    "org/repo(main):requirements.txt" - strip any manifest suffix in parens.
    """
    if not raw:
        return ""
    name = raw.split("(", 1)[0]
    return name.strip("/").lower()


def repo_key(project) -> str:
    """Normalize a ProjectSummary's identity down to "org/repo"."""
    if getattr(project, "repo_url", None):
        key = normalize_repo_url(project.repo_url)
        if key:
            return key
    if getattr(project, "display_name", None):
        return normalize_display_name(project.display_name)
    return ""


def normalize_target_file(raw: str) -> str:
    """Normalize a project's manifest path (attributes.target_file) so the same
    manifest matches across re-imports: forward slashes, no leading "./" or
    "/", lowercased.
    """
    if not raw:
        return ""
    path = raw.strip().replace("\\", "/")
    while path.startswith("./"):
        path = path[2:]
    return path.lstrip("/").lower()


def project_kind_key(project) -> Tuple[str, str]:
    """(scan type, manifest path) - what distinguishes projects sharing a repo.

    repo_key alone is not enough to identify a predecessor: one import of a repo
    produces a project per manifest (package.json, frontend/package.json,
    Dockerfile, terraform/main.tf, ...), and they all share the same repo key
    and the same "sca" product. Only a project with the same scan type *and* the
    same manifest is a candidate predecessor.
    """
    return (
        (getattr(project, "project_type", None) or "").strip().lower(),
        normalize_target_file(getattr(project, "target_file", None) or ""),
    )
