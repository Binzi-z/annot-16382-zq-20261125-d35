"""Independent reference oracle.

This is a deliberately separate, small set/relation implementation of the
specification.  It imports only the shared vocabulary (codes, request type,
topology fixture); it does **not** import the engine's fold or chain code.

The oracle replays the *physical* :class:`~migration_gate.durable.StoredEvent`
list (the on-disk sequence numbers) and produces the same canonical observation
as the engine.  Differential exhaustive testing and the 60k full comparison
assert engine observation == oracle observation for every case.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

from .model import (
    ALLOW,
    DENY_CREDENTIAL_OWNER,
    DENY_DELEGATION_BROKEN,
    DENY_GENERATION_FENCED,
    DENY_LATE_WITNESS_STALE,
    DENY_NEW_POSTING_ABSENT,
    DENY_NO_CREDENTIAL,
    DENY_PURPOSE_BINDING,
    DENY_RESOURCE_BINDING,
    DENY_RESOURCE_UNKNOWN,
    DENY_REVOKED,
    DENY_TENANT_MISMATCH,
    DENY_NOT_COMMITTED,
    ORIGINAL,
    REPLACEMENT,
    AccessRequest,
)
from .topology import (
    CRED_NEW,
    CRED_OLD,
    CRED_THIRD,
    MID,
    NEW,
    OLD,
    PURPOSE,
    RES_NEW,
    RES_OLD,
    RES_OLD_WIKI,
    RES_THIRD,
    THIRD,
    WORKER,
    Topology,
    standard_topology,
)


# ---------------------------------------------------------------------------
# Fixed probe battery (used by exhaustive + disk evidence)
# ---------------------------------------------------------------------------

def standard_probes() -> list[tuple[str, AccessRequest]]:
    return [
        ("old_read", AccessRequest(WORKER, RES_OLD, PURPOSE)),
        ("new_read", AccessRequest(WORKER, RES_NEW, PURPOSE)),
        ("cross_oldcred_to_third",
         AccessRequest(WORKER, RES_THIRD, PURPOSE, CRED_OLD)),
        ("cross_newcred_to_old",
         AccessRequest(WORKER, RES_OLD, PURPOSE, CRED_NEW)),
        ("purpose_bind",
         AccessRequest(WORKER, RES_OLD, "deploy", CRED_OLD)),
        ("resource_bind",
         AccessRequest(WORKER, RES_OLD_WIKI, PURPOSE, CRED_OLD)),
        ("third_own_read",
         AccessRequest("worker_third", RES_THIRD, PURPOSE)),
    ]


@dataclass
class OMigration:
    mid: str
    worker: str
    old_org: str
    new_org: str
    old_cred_id: str
    new_cred_spec: dict[str, Any]
    conf_old: tuple[str, int] | None = None
    conf_new: tuple[str, int] | None = None
    commit_seq: int | None = None
    old_revoke_seq: int | None = None
    new_post_seq: int | None = None


@dataclass
class Oracle:
    topo: Topology = field(default_factory=standard_topology)
    edges: dict[str, dict[str, Any]] = field(default_factory=dict)
    edge_rev: dict[str, int] = field(default_factory=dict)
    creds: dict[str, dict[str, Any]] = field(default_factory=dict)
    cred_rev: dict[str, int] = field(default_factory=dict)
    witnesses: list[tuple[int, str, int]] = field(default_factory=list)
    migs: dict[str, OMigration] = field(default_factory=dict)
    floors: dict[str, int] = field(default_factory=dict)

    # -- replay -------------------------------------------------------------

    @classmethod
    def replay_events(cls, topo: Topology,
                      events: list[Any]) -> "Oracle":
        o = cls(topo=topo)
        for ev in events:
            o.ingest(ev.seq, ev.kind, ev.payload)
        return o

    def ingest(self, seq: int, kind: str, p: dict[str, Any]) -> None:
        if kind == "edge_granted":
            self.edges[p["edge_id"]] = dict(p)
        elif kind == "credential_issued":
            self.creds[p["cred_id"]] = dict(p)
        elif kind == "migration_opened":
            self.migs[p["mid"]] = OMigration(
                mid=p["mid"], worker=p["worker"], old_org=p["old_org"],
                new_org=p["new_org"], old_cred_id=p["old_cred_id"],
                new_cred_spec=p["new_cred"],
            )
        elif kind == "gen_floor":
            self.floors[p["org"]] = int(p["floor"])
        elif kind == "attempt":
            self._step(seq, p.get("cmd", ""), p.get("args", {}))
        # probe / unknown do not change oracle state

    def _is_controller(self, org: str, person: str) -> bool:
        return self.topo.is_actual_controller(org, person)

    def _step(self, seq: int, cmd: str, a: dict[str, Any]) -> None:
        if cmd == "confirm":
            m = self.migs.get(a["mid"])
            if not m:
                return
            side, person = a["side"], a["person"]
            org = m.old_org if side == "old" else m.new_org
            if not self._is_controller(org, person):
                return
            slot = m.conf_old if side == "old" else m.conf_new
            if slot is not None:
                return
            other = m.conf_new if side == "old" else m.conf_old
            if other is not None and other[0] == person:
                return
            pair = (person, seq)
            if side == "old":
                m.conf_old = pair
            else:
                m.conf_new = pair
            return

        if cmd == "commit":
            m = self.migs.get(a["mid"])
            if not m or m.commit_seq is not None:
                return
            if not (m.conf_old and m.conf_new):
                return
            m.commit_seq = seq
            return

        if cmd == "revoke_old":
            m = self.migs.get(a["mid"])
            if not m:
                return
            cid = m.old_cred_id
            if cid not in self.creds or cid in self.cred_rev:
                if cid in self.cred_rev:
                    m.old_revoke_seq = self.cred_rev[cid]
                return
            self.cred_rev[cid] = seq
            m.old_revoke_seq = seq
            return

        if cmd == "witness_old":
            m = self.migs.get(a["mid"])
            cid = m.old_cred_id if m else a.get("cred_id", CRED_OLD)
            gen = int(self.creds[cid]["gen"]) if cid in self.creds \
                else int(a.get("gen", 1))
            self.witnesses.append((seq, cid, gen))
            return

        if cmd == "post_new":
            m = self.migs.get(a["mid"])
            if not m or m.new_post_seq is not None:
                return
            if m.commit_seq is None or m.commit_seq >= seq:
                return
            if m.old_revoke_seq is None:
                return
            spec = m.new_cred_spec
            self.creds[spec["cred_id"]] = {
                "cred_id": spec["cred_id"], "kind": REPLACEMENT,
                "org": m.new_org, "subject": m.worker,
                "resid": spec["resid"], "purpose": spec["purpose"],
                "gen": int(spec["gen"]), "migration_id": m.mid,
            }
            m.new_post_seq = seq
            return

        if cmd == "revoke_edge":
            eid = a["edge_id"]
            if eid in self.edges and eid not in self.edge_rev:
                self.edge_rev[eid] = seq
            return

        if cmd == "revoke_credential":
            cid = a["cred_id"]
            if cid in self.creds and cid not in self.cred_rev:
                self.cred_rev[cid] = seq
            return

        if cmd == "bump_gen_floor":
            org, floor = a["org"], int(a["floor"])
            if floor > self.floors.get(org, 0):
                self.floors[org] = floor
            return

    # -- independent chain + decision --------------------------------------

    def _chain(self, org: str, resid: str, purpose: str, gen: int,
               subject: str) -> list[dict[str, Any]] | None:
        rev = self.edge_rev
        usable = [
            e for e in self.edges.values()
            if e["edge_id"] not in rev
            and e["org"] == org and e["resid"] == resid
            and e["purpose"] == purpose and e["gen"] == gen
        ]
        out: dict[str, list[dict[str, Any]]] = {}
        for e in usable:
            out.setdefault(e["grantor"], []).append(e)
        roots = list(self.topo.orgs[org].actual_controllers)
        queue: list[tuple[str, list[dict[str, Any]]]] = [
            (r, []) for r in roots]
        seen: set[tuple[str, str]] = set()
        while queue:
            node, path = queue.pop(0)
            for e in out.get(node, []):
                key = (node, e["edge_id"])
                if key in seen:
                    continue
                seen.add(key)
                npath = path + [e]
                if e["grantee"] == subject:
                    return npath
                if e.get("may_delegate", True):
                    queue.append((e["grantee"], npath))
        return None

    def decide(self, req: AccessRequest) -> tuple[bool, str]:
        resource = self.topo.resources.get(req.resid)
        if resource is None:
            return False, DENY_RESOURCE_UNKNOWN

        cred: dict[str, Any] | None = None
        if req.cred_id is not None:
            cred = self.creds.get(req.cred_id)
        else:
            matches = [c for c in self.creds.values()
                       if c["subject"] == req.subject
                       and c["resid"] == req.resid
                       and c["purpose"] == req.purpose]
            live = [c for c in matches if c["cred_id"] not in self.cred_rev]
            pool = live or matches
            if pool:
                cred = sorted(pool, key=lambda c: c["cred_id"])[-1]
        if cred is None:
            return False, DENY_NO_CREDENTIAL

        if cred["subject"] != req.subject:
            return False, DENY_CREDENTIAL_OWNER
        if cred["org"] != resource.org:
            return False, DENY_TENANT_MISMATCH
        if cred["resid"] != req.resid:
            return False, DENY_RESOURCE_BINDING
        if cred["purpose"] != req.purpose:
            return False, DENY_PURPOSE_BINDING
        if cred["gen"] < self.floors.get(cred["org"], 0):
            return False, DENY_GENERATION_FENCED

        cid = cred["cred_id"]
        rseq = self.cred_rev.get(cid)
        if rseq is not None:
            late = any(wseq > rseq and wcid == cid and wgen == cred["gen"]
                       for (wseq, wcid, wgen) in self.witnesses)
            if late:
                return False, DENY_LATE_WITNESS_STALE
            return False, DENY_REVOKED

        if cred.get("kind") == REPLACEMENT and cred.get("migration_id"):
            m = self.migs.get(cred["migration_id"])
            if m is None or m.commit_seq is None:
                return False, DENY_NOT_COMMITTED
            if m.old_revoke_seq is None:
                return False, DENY_REVOKED
            if m.new_post_seq is None:
                return False, DENY_NEW_POSTING_ABSENT

        if self._chain(cred["org"], cred["resid"], cred["purpose"],
                       cred["gen"], cred["subject"]) is None:
            return False, DENY_DELEGATION_BROKEN
        return True, ALLOW

    # -- canonical observation ----------------------------------------------

    def observation(self, probes: list[tuple[str, AccessRequest]]
                    ) -> dict[str, Any]:
        m = self.migs.get(MID)
        decisions = {pid: list(self.decide(req)) for pid, req in probes}
        visible = {}
        for oid in self.topo.orgs:
            visible[oid] = sorted(
                cid for cid, c in self.creds.items() if c["org"] == oid)
        return {
            "decisions": decisions,
            "facts": {
                "old_conf": bool(m and m.conf_old),
                "new_conf": bool(m and m.conf_new),
                "commit_seq": m.commit_seq if m else None,
                "old_revoke_seq": m.old_revoke_seq if m else None,
                "new_post_seq": m.new_post_seq if m else None,
                # In the crash-free exhaustive model a receipt exists exactly
                # when commit + both durable effects exist.
                "receipt": bool(
                    m and m.commit_seq is not None
                    and m.old_revoke_seq is not None
                    and m.new_post_seq is not None),
            },
            "visible": visible,
        }
