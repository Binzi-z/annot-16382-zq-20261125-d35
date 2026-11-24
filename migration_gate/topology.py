"""Tenant topology: organizations, actual controllers and resources.

A :class:`Topology` is the trusted offline root of authority.  Runtime
delegation edges / credentials / migrations live in the durable log; the
topology names the tenants and the natural persons who are *actual
controllers* (实际控制人) allowed to bind an organization.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

from .model import Resource


@dataclass(frozen=True)
class Org:
    org_id: str
    name: str
    # Natural person ids that are actual controllers of this org.
    actual_controllers: frozenset[str]

    def is_actual_controller(self, person: str) -> bool:
        return person in self.actual_controllers


@dataclass
class Topology:
    orgs: dict[str, Org] = field(default_factory=dict)
    resources: dict[str, Resource] = field(default_factory=dict)

    def add_org(self, org_id: str, actual_controllers: set[str] | frozenset[str],
                name: str | None = None) -> "Topology":
        self.orgs[org_id] = Org(org_id, name or org_id,
                                frozenset(actual_controllers))
        return self

    def add_resource(self, resid: str, org: str) -> "Topology":
        self.resources[resid] = Resource(resid, org)
        return self

    def org_of_resource(self, resid: str) -> str | None:
        r = self.resources.get(resid)
        return r.org if r else None

    def is_actual_controller(self, org: str, person: str) -> bool:
        o = self.orgs.get(org)
        return bool(o and o.is_actual_controller(person))

    def to_dict(self) -> dict[str, Any]:
        return {
            "orgs": {
                oid: {"name": o.name,
                      "actual_controllers": sorted(o.actual_controllers)}
                for oid, o in self.orgs.items()
            },
            "resources": {rid: r.to_dict()
                          for rid, r in sorted(self.resources.items())},
        }


# ---------------------------------------------------------------------------
# Standard finite scenario used by exhaustive search and the boundary proofs
# ---------------------------------------------------------------------------

# Tenant ids
OLD = "ORG_OLD"
NEW = "ORG_NEW"
THIRD = "ORG_THIRD"

# Natural persons
C_OLD = "ctrl_old_zhang"
C_NEW = "ctrl_new_li"
C_THIRD = "ctrl_third_wang"
ROGUE = "outsider_mallory"      # not an actual controller anywhere
SAME_PERSON = "ctrl_dual"       # used only in same-confirmer negative test

WORKER = "worker_zhao"

# Resources
RES_OLD = "res_old_sourcecode"
RES_OLD_WIKI = "res_old_wiki"   # same tenant, different resource (binding check)
RES_NEW = "res_new_build"
RES_THIRD = "res_third_finance"

PURPOSE = "read"

# Credential / migration ids
MID = "mig-0001"
CRED_OLD = "cred-old-0001"
CRED_NEW = "cred-new-0001"
CRED_THIRD = "cred-third-0001"

WORKER_THIRD = "worker_third"

GEN_OLD = 1
GEN_NEW = 2


def standard_topology() -> Topology:
    """Three tenants and one resource each."""
    topo = Topology()
    topo.add_org(OLD, {C_OLD})
    topo.add_org(NEW, {C_NEW})
    topo.add_org(THIRD, {C_THIRD})
    # An actual controller who happens to control both OLD and NEW is NOT in
    # the standard controller sets; SAME_PERSON is registered for both only by
    # tests that need the same-natural-person edge case.
    topo.add_resource(RES_OLD, OLD)
    topo.add_resource(RES_OLD_WIKI, OLD)
    topo.add_resource(RES_NEW, NEW)
    topo.add_resource(RES_THIRD, THIRD)
    return topo
