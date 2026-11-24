"""Shared vocabulary, immutable value types and decision evidence.

Only plain standard-library types are used so every record round-trips through
JSON without custom encoders.
"""

from __future__ import annotations

import dataclasses
import hashlib
import json
from dataclasses import dataclass, field
from typing import Any

# ---------------------------------------------------------------------------
# Decision / reason codes (the shared specification vocabulary)
# ---------------------------------------------------------------------------

ALLOW = "ALLOW"

DENY_RESOURCE_UNKNOWN = "DENY_RESOURCE_UNKNOWN"
DENY_NO_CREDENTIAL = "DENY_NO_CREDENTIAL"
DENY_CREDENTIAL_OWNER = "DENY_CREDENTIAL_OWNER"
DENY_TENANT_MISMATCH = "DENY_TENANT_MISMATCH"
DENY_RESOURCE_BINDING = "DENY_RESOURCE_BINDING"
DENY_PURPOSE_BINDING = "DENY_PURPOSE_BINDING"
DENY_GENERATION_FENCED = "DENY_GENERATION_FENCED"
DENY_REVOKED = "DENY_REVOKED"
DENY_LATE_WITNESS_STALE = "DENY_LATE_WITNESS_STALE"
DENY_DELEGATION_BROKEN = "DENY_DELEGATION_BROKEN"
DENY_NOT_COMMITTED = "DENY_NOT_COMMITTED"
DENY_NEW_POSTING_ABSENT = "DENY_NEW_POSTING_ABSENT"
DENY_MIGRATION_STATE = "DENY_MIGRATION_STATE"

# Command acceptance codes (state-machine preconditions).
ACCEPTED = "ACCEPTED"
REJECT_NOT_ACTUAL_CONTROLLER = "REJECT_NOT_ACTUAL_CONTROLLER"
REJECT_WRONG_ORG = "REJECT_WRONG_ORG"
REJECT_SAME_CONFIRMER = "REJECT_SAME_CONFIRMER"
REJECT_ALREADY_CONFIRMED = "REJECT_ALREADY_CONFIRMED"
REJECT_DUAL_CONFIRMATION = "REJECT_DUAL_CONFIRMATION"
REJECT_BAD_PHASE = "REJECT_BAD_PHASE"
REJECT_UNKNOWN_MIGRATION = "REJECT_UNKNOWN_MIGRATION"

# Migration phases.
P_OPEN = "OPEN"
P_DUAL_CONFIRMED = "DUAL_CONFIRMED"
P_COMMITTED = "COMMITTED"
P_OLD_REVOKED = "OLD_REVOKED"
P_COMPLETED = "COMPLETED"  # old revoked + new posted + receipt

# Credential kinds.
ORIGINAL = "original"
REPLACEMENT = "replacement"


class GateError(RuntimeError):
    """Base class for hard gate failures."""


class TamperError(GateError):
    """The durable log failed its sequence/hash-chain verification."""


class InjectedCrash(GateError):
    """Raised by tests to simulate a process kill at a named crash point."""

    def __init__(self, point: str):
        super().__init__(f"injected crash at {point}")
        self.point = point


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def canonical_json(payload: Any) -> str:
    """Deterministic compact JSON used for hashing and comparison."""
    return json.dumps(
        payload, sort_keys=True, separators=(",", ":"), ensure_ascii=False
    )


def sha256_text(text: str) -> str:
    return hashlib.sha256(text.encode("utf-8")).hexdigest()


def stable_hash(payload: Any) -> str:
    return sha256_text(canonical_json(payload))


# ---------------------------------------------------------------------------
# Core value types
# ---------------------------------------------------------------------------

@dataclass(frozen=True)
class Resource:
    resid: str
    org: str  # owning tenant

    def to_dict(self) -> dict[str, Any]:
        return {"resid": self.resid, "org": self.org}


@dataclass(frozen=True)
class Credential:
    """A credential bound to resource + purpose + authorization generation."""

    cred_id: str
    kind: str  # ORIGINAL / REPLACEMENT
    org: str  # issuing / consuming tenant
    subject: str
    resid: str
    purpose: str
    gen: int
    migration_id: str | None = None

    def to_dict(self) -> dict[str, Any]:
        return dataclasses.asdict(self)


@dataclass(frozen=True)
class Edge:
    """A single delegation edge grantor -> grantee.

    Following edges from an actual controller down to a subject proves the
    subject is authorized.  ``may_delegate`` controls whether the grantee may
    extend the chain one more hop.
    """

    edge_id: str
    org: str
    grantor: str
    grantee: str
    resid: str
    purpose: str
    gen: int
    may_delegate: bool = True

    def to_dict(self) -> dict[str, Any]:
        return dataclasses.asdict(self)


@dataclass(frozen=True)
class AccessRequest:
    subject: str
    resid: str
    purpose: str
    cred_id: str | None = None  # if None, use the subject's matching credential

    def key(self) -> tuple[str, str, str, str | None]:
        return (self.subject, self.resid, self.purpose, self.cred_id)

    def to_dict(self) -> dict[str, Any]:
        return {
            "subject": self.subject,
            "resid": self.resid,
            "purpose": self.purpose,
            "cred_id": self.cred_id,
        }


@dataclass
class Decision:
    allow: bool
    code: str
    subject: str
    resid: str
    purpose: str
    # Human/auditor readable explanation.
    because: str = ""
    # Machine-checkable evidence: decisive durable sequence numbers, chain,
    # tenant/generation checks.  Every seq here was read back from the log.
    evidence: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return {
            "allow": self.allow,
            "code": self.code,
            "subject": self.subject,
            "resid": self.resid,
            "purpose": self.purpose,
            "because": self.because,
            "evidence": self.evidence,
        }


def deny(
    code: str,
    req: AccessRequest,
    because: str,
    evidence: dict[str, Any] | None = None,
) -> Decision:
    return Decision(False, code, req.subject, req.resid, req.purpose, because,
                    evidence or {})


def allow(req: AccessRequest, because: str,
          evidence: dict[str, Any] | None = None) -> Decision:
    return Decision(True, ALLOW, req.subject, req.resid, req.purpose, because,
                    evidence or {})
