"""Core data models - mirrors pkg/issuewrapper/types.go from the Go version."""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime
from typing import List, Optional

SCA = "package_vulnerability"
SAST = "code"


@dataclass
class Issue:
    """Subset of the Issues API response needed for correlation.

    `key` is attributes.key - a stable identity for SCA issues, but
    PROJECT-SCOPED for SAST issues (doesn't survive a migration). For SAST,
    populate `fingerprint` instead (from the code issue detail endpoint).
    """

    id: str
    type: str  # SCA or SAST
    org_id: str
    project_id: str
    key: Optional[str] = None
    fingerprint: Optional[str] = None
    created_at: Optional[datetime] = None
    updated_at: Optional[datetime] = None
    last_introduced_at: Optional[datetime] = None

    @property
    def identity(self) -> Optional[str]:
        """The identity that's stable across a migration for this issue."""
        if self.type == SAST:
            return self.fingerprint
        return self.key


@dataclass
class ProjectSummary:
    """Subset of a Snyk project (+ its target) needed to find a duplicate.

    `product` is only sca-vs-sast, which is too coarse to identify a
    predecessor: one repo import yields many projects (npm, dockerfile,
    k8sconfig, terraformconfig, ...) that all collapse to "sca". Matching also
    needs `project_type` and `target_file` - see matching.project_kind_key.
    """

    org_id: str
    project_id: str
    product: str  # "sca" or "sast"
    integration_type: Optional[str] = None
    repo_url: Optional[str] = None      # target attributes.url (SCM)
    display_name: Optional[str] = None  # target attributes.display_name (CLI)
    created_at: Optional[datetime] = None
    project_type: Optional[str] = None  # attributes.type ("npm", "dockerfile", "sast", ...)
    target_file: Optional[str] = None   # attributes.target_file ("package.json", ...)


@dataclass
class CorrelatedIssue:
    """One row of the old project's issues, indexed by cross-migration identity."""

    identity_type: str  # "key" or "fingerprint"
    identity: str
    old_issue_id: str
    old_org_id: str
    old_project_id: str
    old_created_at: Optional[datetime]
    old_last_introduced_at: Optional[datetime]

    def to_dict(self) -> dict:
        return {
            "identity_type": self.identity_type,
            "identity": self.identity,
            "old_issue_id": self.old_issue_id,
            "old_org_id": self.old_org_id,
            "old_project_id": self.old_project_id,
            "old_created_at": self.old_created_at.isoformat() if self.old_created_at else None,
            "old_last_introduced_at": (
                self.old_last_introduced_at.isoformat() if self.old_last_introduced_at else None
            ),
        }


@dataclass
class MigrationCorrelation:
    """Full result for one new project: predecessor + its issues by identity."""

    new_org_id: str
    new_project_id: str
    match_found: bool = False
    old_org_id: Optional[str] = None
    old_project_id: Optional[str] = None
    product: Optional[str] = None
    issues: List[CorrelatedIssue] = field(default_factory=list)

    def to_dict(self) -> dict:
        return {
            "new_org_id": self.new_org_id,
            "new_project_id": self.new_project_id,
            "match_found": self.match_found,
            "old_org_id": self.old_org_id,
            "old_project_id": self.old_project_id,
            "product": self.product,
            "issues": [i.to_dict() for i in self.issues],
        }
