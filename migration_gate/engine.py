"""The offline migration gate engine.

The engine is event sourced.  Every command is appended to a :class:`DurableLog`
and assigned its *physical on-disk sequence* before the state fold applies it.
Live handling and post-crash recovery therefore run the exact same deterministic
``fold`` over sequence numbers read back from disk.  Client-supplied sequence
numbers / wall-clock timestamps are never used for validity.
"""

from __future__ import annotations

import json
import os
import tempfile
import threading
from dataclasses import dataclass, field
from typing import Any

from .durable import DurableLog, StoredEvent
from .model import (
    ACCEPTED,
    ALLOW,
    DENY_CREDENTIAL_OWNER,
    DENY_DELEGATION_BROKEN,
    DENY_GENERATION_FENCED,
    DENY_LATE_WITNESS_STALE,
    DENY_NEW_POSTING_ABSENT,
    DENY_NO_CREDENTIAL,
    DENY_NOT_COMMITTED,
    DENY_PURPOSE_BINDING,
    DENY_RESOURCE_BINDING,
    DENY_RESOURCE_UNKNOWN,
    DENY_REVOKED,
    DENY_TENANT_MISMATCH,
    ORIGINAL,
    REPLACEMENT,
    REJECT_ALREADY_CONFIRMED,
    REJECT_BAD_PHASE,
    REJECT_DUAL_CONFIRMATION,
    REJECT_NOT_ACTUAL_CONTROLLER,
    REJECT_SAME_CONFIRMER,
    REJECT_UNKNOWN_MIGRATION,
    REJECT_WRONG_ORG,
    AccessRequest,
    Credential,
    Decision,
    Edge,
    InjectedCrash,
    allow,
    deny,
)
from .topology import (
    C_NEW,
    C_OLD,
    CRED_NEW,
    CRED_OLD,
    GEN_NEW,
    GEN_OLD,
    MID,
    NEW,
    OLD,
    PURPOSE,
    RES_NEW,
    RES_OLD,
    WORKER,
    Topology,
    standard_topology,
)


# ---------------------------------------------------------------------------
# Folded state
# ---------------------------------------------------------------------------

@dataclass
class Witness:
    seq: int
    cred_id: str
    gen: int
    claimed_seq: Any = None


@dataclass
class MigState:
    mid: str
    worker: str
    old_org: str
    new_org: str
    old_cred_id: str
    new_cred_spec: dict[str, Any]
    conf_old: tuple[str, int] | None = None   # (person, durable seq)
    conf_new: tuple[str, int] | None = None
    commit_seq: int | None = None
    old_revoke_seq: int | None = None
    new_post_seq: int | None = None
    receipt_seq: int | None = None

    @property
    def dual_confirmed(self) -> bool:
        return self.conf_old is not None and self.conf_new is not None


@dataclass
class FoldState:
    edges: dict[str, Edge] = field(default_factory=dict)
    edge_revoked_seq: dict[str, int] = field(default_factory=dict)
    credentials: dict[str, Credential] = field(default_factory=dict)
    cred_revoked_seq: dict[str, int] = field(default_factory=dict)
    witnesses: list[Witness] = field(default_factory=list)
    migrations: dict[str, MigState] = field(default_factory=dict)
    # Per-org authorization-generation floor (control relationship rotation).
    gen_floor_by_org: dict[str, int] = field(default_factory=dict)
    # Idempotency key -> first durable seq that produced the effect.
    idem: dict[str, int] = field(default_factory=dict)
    # Audit of command outcomes in seq order.
    command_results: list[dict[str, Any]] = field(default_factory=list)


# ---------------------------------------------------------------------------
# Receipt storage
# ---------------------------------------------------------------------------

class MemoryReceipts:
    def __init__(self) -> None:
        self.receipts: dict[str, dict[str, Any]] = {}

    def write(self, mid: str, data: dict[str, Any]) -> None:
        self.receipts[mid] = data

    def exists(self, mid: str) -> bool:
        return mid in self.receipts

    def read(self, mid: str) -> dict[str, Any] | None:
        return self.receipts.get(mid)


class FileReceipts:
    def __init__(self, directory: str) -> None:
        self.dir = directory
        os.makedirs(directory, exist_ok=True)

    def _path(self, mid: str) -> str:
        return os.path.join(self.dir, f"{mid}.receipt.json")

    def write(self, mid: str, data: dict[str, Any]) -> None:
        final = self._path(mid)
        fd, tmp = tempfile.mkstemp(prefix=".rcpt-", suffix=".tmp", dir=self.dir)
        try:
            with os.fdopen(fd, "w", encoding="utf-8", newline="\n") as f:
                json.dump(data, f, ensure_ascii=False, sort_keys=True, indent=2)
                f.flush()
                os.fsync(f.fileno())
            os.replace(tmp, final)  # atomic on Windows / POSIX
        except BaseException:
            try:
                os.unlink(tmp)
            except OSError:
                pass
            raise

    def exists(self, mid: str) -> bool:
        return os.path.exists(self._path(mid))

    def read(self, mid: str) -> dict[str, Any] | None:
        try:
            with open(self._path(mid), "r", encoding="utf-8") as f:
                return json.load(f)
        except FileNotFoundError:
            return None


# ---------------------------------------------------------------------------
# Engine
# ---------------------------------------------------------------------------

class GateEngine:
    def __init__(
        self,
        topology: Topology,
        log: DurableLog,
        receipts: MemoryReceipts | FileReceipts | None = None,
        sync_controls: bool = True,
        crash_after: str | None = None,
        auto_complete: bool = True,
    ) -> None:
        self.topo = topology
        self.log = log
        self.receipts = receipts if receipts is not None else MemoryReceipts()
        self.sync_controls = sync_controls
        # One-shot-ish crash point: "commit" | "receipt".
        self.crash_after = crash_after
        self._eng_lock = threading.RLock()
        self.state = FoldState()
        for ev in self.log.events():
            self._apply(ev)
        if auto_complete:
            self.complete_pending()

    def _refold(self) -> None:
        """Rebuild all in-memory state from the physical log."""
        self.state = FoldState()
        for ev in self.log.events():
            self._apply(ev)

    # -- construction helpers ----------------------------------------------

    @classmethod
    def create_memory(cls, topology: Topology | None = None,
                      shared_store: list[str] | None = None,
                      receipts: MemoryReceipts | None = None,
                      sync_controls: bool = True,
                      crash_after: str | None = None,
                      auto_complete: bool = True,
                      bootstrap_fn: Any = None) -> "GateEngine":
        topo = topology or standard_topology()
        log = DurableLog.open_memory(shared_store)
        eng = cls(topo, log, receipts=receipts or MemoryReceipts(),
                  sync_controls=sync_controls, crash_after=crash_after,
                  auto_complete=False)
        if log.last_seq() == 0:
            (bootstrap_fn or bootstrap_standard)(eng)
            eng._refold()
        if auto_complete:
            eng.complete_pending()
        return eng

    @classmethod
    def create_file(cls, directory: str,
                    topology: Topology | None = None,
                    sync_controls: bool = True,
                    crash_after: str | None = None,
                    auto_complete: bool = True,
                    bootstrap_fn: Any = None) -> "GateEngine":
        topo = topology or standard_topology()
        os.makedirs(directory, exist_ok=True)
        log = DurableLog.open_file(os.path.join(directory, "gate.jsonl"))
        receipts = FileReceipts(os.path.join(directory, "receipts"))
        eng = cls(topo, log, receipts=receipts,
                  sync_controls=sync_controls, crash_after=crash_after,
                  auto_complete=False)
        if log.last_seq() == 0:
            (bootstrap_fn or bootstrap_standard)(eng)
            eng._refold()
        if auto_complete:
            eng.complete_pending()
        return eng

    @classmethod
    def reopen_file(cls, directory: str,
                    topology: Topology | None = None,
                    crash_after: str | None = None) -> "GateEngine":
        """Simulate restart: re-read the physical log and recover."""
        topo = topology or standard_topology()
        log = DurableLog.open_file(os.path.join(directory, "gate.jsonl"))
        receipts = FileReceipts(os.path.join(directory, "receipts"))
        return cls(topo, log, receipts=receipts, crash_after=crash_after,
                   auto_complete=True)

    # -- fold ---------------------------------------------------------------

    def _apply(self, ev: StoredEvent) -> None:
        kind = ev.kind
        p = ev.payload
        s = self.state

        if kind == "edge_granted":
            e = Edge(**p)
            s.edges[e.edge_id] = e
        elif kind == "credential_issued":
            c = Credential(**p)
            s.credentials[c.cred_id] = c
        elif kind == "migration_opened":
            m = MigState(
                mid=p["mid"], worker=p["worker"], old_org=p["old_org"],
                new_org=p["new_org"], old_cred_id=p["old_cred_id"],
                new_cred_spec=p["new_cred"],
            )
            s.migrations[m.mid] = m
        elif kind == "gen_floor":
            s.gen_floor_by_org[p["org"]] = int(p["floor"])
        elif kind == "attempt":
            self._step_attempt(ev.seq, p.get("cmd", ""), p.get("args", {}))
        elif kind == "probe":
            return  # non-mutating
        else:
            # Unknown future event kinds are ignored by this offline reader.
            return

    def _step_attempt(self, seq: int, cmd: str, a: dict[str, Any]) -> dict[str, Any]:
        """Deterministic state-machine transition.  Seq is the durable seq."""
        s = self.state
        result: dict[str, Any] = {"seq": seq, "cmd": cmd, "accepted": False,
                                 "code": REJECT_BAD_PHASE}

        def done(accepted: bool, code: str, **extra: Any) -> dict[str, Any]:
            result["accepted"] = accepted
            result["code"] = code
            result.update(extra)
            s.command_results.append(
                {"seq": seq, "cmd": cmd, "accepted": accepted, "code": code}
            )
            return result

        if cmd == "confirm":
            mid = a["mid"]
            side = a["side"]
            person = a["person"]
            m = s.migrations.get(mid)
            if m is None:
                return done(False, REJECT_UNKNOWN_MIGRATION)
            org = m.old_org if side == "old" else m.new_org
            if not self.topo.is_actual_controller(org, person):
                # Distinguish a real controller of the OTHER org / wrong org.
                code = REJECT_WRONG_ORG if person in self._all_controllers() \
                    else REJECT_NOT_ACTUAL_CONTROLLER
                return done(False, code, side=side, person=person, org=org)
            slot = m.conf_old if side == "old" else m.conf_new
            if slot is not None:
                return done(True, "ACCEPTED_DUPLICATE",
                            original_seq=slot[1])
            other = m.conf_new if side == "old" else m.conf_old
            if other is not None and other[0] == person:
                return done(False, REJECT_SAME_CONFIRMER)
            if side == "old":
                m.conf_old = (person, seq)
            else:
                m.conf_new = (person, seq)
            return done(True, ACCEPTED, person=person, side=side)

        if cmd == "commit":
            m = s.migrations.get(a["mid"])
            if m is None:
                return done(False, REJECT_UNKNOWN_MIGRATION)
            if m.commit_seq is not None:
                return done(True, "ACCEPTED_DUPLICATE",
                            original_seq=m.commit_seq)
            if not m.dual_confirmed:
                return done(False, REJECT_DUAL_CONFIRMATION,
                            have_old=m.conf_old is not None,
                            have_new=m.conf_new is not None)
            m.commit_seq = seq
            s.idem[f"commit:{m.mid}"] = seq
            return done(True, ACCEPTED, commit_seq=seq)

        if cmd == "revoke_old":
            mid = a["mid"]
            m = s.migrations.get(mid)
            if m is None:
                return done(False, REJECT_UNKNOWN_MIGRATION)
            cid = m.old_cred_id
            if cid not in s.credentials:
                return done(False, DENY_NO_CREDENTIAL)
            # Idempotent: the FIRST durable revocation seq is authoritative.
            if cid in s.cred_revoked_seq:
                m.old_revoke_seq = s.cred_revoked_seq[cid]
                return done(True, "ACCEPTED_DUPLICATE",
                            original_seq=s.cred_revoked_seq[cid])
            s.cred_revoked_seq[cid] = seq
            s.idem[f"oldrev:{mid}"] = seq
            m.old_revoke_seq = seq
            return done(True, ACCEPTED, old_revoke_seq=seq)

        if cmd == "witness_old":
            mid = a["mid"]
            m = s.migrations.get(mid)
            cid = m.old_cred_id if m else a.get("cred_id", CRED_OLD)
            cred = s.credentials.get(cid)
            gen = cred.gen if cred else int(a.get("gen", 1))
            s.witnesses.append(Witness(
                seq=seq, cred_id=cid, gen=gen,
                claimed_seq=a.get("claimed_seq"),
            ))
            # A witness is evidence only; it never mutates grants.
            late = (cid in s.cred_revoked_seq
                    and seq > s.cred_revoked_seq[cid])
            return done(True, "RECORDED_WITNESS", late=late,
                        revoke_seq=s.cred_revoked_seq.get(cid))

        if cmd == "post_new":
            mid = a["mid"]
            m = s.migrations.get(mid)
            if m is None:
                return done(False, REJECT_UNKNOWN_MIGRATION)
            if m.new_post_seq is not None:
                return done(True, "ACCEPTED_DUPLICATE",
                            original_seq=m.new_post_seq)
            # Seq-decisive ordering: posting is valid only if a durable commit
            # exists at a LOWER seq (it is in the prefix being folded) AND the
            # old organization's revocation is already durable.  This is
            # break-before-make: there is no window in which both the original
            # and replacement credentials authorize at once.
            if m.commit_seq is None or m.commit_seq >= seq:
                return done(False, DENY_NOT_COMMITTED,
                            commit_seq=m.commit_seq)
            if m.old_revoke_seq is None:
                return done(False, REJECT_BAD_PHASE,
                            reason="old organization revocation not durable")
            spec = m.new_cred_spec
            cred = Credential(
                cred_id=spec["cred_id"], kind=REPLACEMENT, org=m.new_org,
                subject=m.worker, resid=spec["resid"],
                purpose=spec["purpose"], gen=int(spec["gen"]),
                migration_id=mid,
            )
            s.credentials[cred.cred_id] = cred
            m.new_post_seq = seq
            s.idem[f"newpost:{mid}"] = seq
            return done(True, ACCEPTED, new_post_seq=seq,
                        cred_id=cred.cred_id)

        if cmd == "revoke_edge":
            eid = a["edge_id"]
            if eid not in s.edges:
                return done(False, "REJECT_UNKNOWN_EDGE")
            if eid in s.edge_revoked_seq:
                return done(True, "ACCEPTED_DUPLICATE",
                            original_seq=s.edge_revoked_seq[eid])
            s.edge_revoked_seq[eid] = seq
            return done(True, ACCEPTED, edge_revoke_seq=seq)

        if cmd == "revoke_credential":
            cid = a["cred_id"]
            if cid not in s.credentials:
                return done(False, DENY_NO_CREDENTIAL)
            if cid in s.cred_revoked_seq:
                return done(True, "ACCEPTED_DUPLICATE",
                            original_seq=s.cred_revoked_seq[cid])
            s.cred_revoked_seq[cid] = seq
            return done(True, ACCEPTED, revoke_seq=seq)

        if cmd == "bump_gen_floor":
            org = a["org"]
            floor = int(a["floor"])
            cur = s.gen_floor_by_org.get(org, 0)
            if floor <= cur:
                return done(True, "ACCEPTED_DUPLICATE", floor=cur)
            s.gen_floor_by_org[org] = floor
            return done(True, ACCEPTED, floor=floor)

        return done(False, "REJECT_UNKNOWN_COMMAND")

    def _all_controllers(self) -> set[str]:
        out: set[str] = set()
        for o in self.topo.orgs.values():
            out |= set(o.actual_controllers)
        return out

    # -- command submission -------------------------------------------------

    def execute(self, cmd: str, /, **args: Any) -> dict[str, Any]:
        with self._eng_lock:
            critical = cmd in {"commit", "revoke_old", "post_new", "confirm",
                               "revoke_edge", "bump_gen_floor",
                               "revoke_credential"}
            sync = self.sync_controls and critical
            ev = self.log.append("attempt", {"cmd": cmd, "args": args},
                                 sync=sync)
            result = self._step_attempt(ev.seq, cmd, args)

            # Crash point: commit is durable + folded, receipt not yet written.
            if self.crash_after == "commit" and cmd == "commit" \
                    and result.get("accepted"):
                raise InjectedCrash("after_commit_before_receipt")

            # After a state change we may be able to emit the receipt.
            if cmd in {"revoke_old", "post_new", "commit"}:
                self._maybe_write_receipt(args.get("mid", MID))

            if self.crash_after == "receipt" and cmd in {"revoke_old",
                                                          "post_new"}:
                # Narrow window: effects durable, receipt intentionally not
                # written yet because _maybe_write_receipt saw crash flag.
                pass
            return result

    def _maybe_write_receipt(self, mid: str) -> None:
        if mid is None:
            return
        m = self.state.migrations.get(mid)
        if m is None or m.commit_seq is None:
            return
        if m.old_revoke_seq is None or m.new_post_seq is None:
            return
        if self.receipts.exists(mid):
            m.receipt_seq = m.receipt_seq or -1
            return
        if self.crash_after == "receipt":
            # Simulate kill immediately before the atomic receipt replace.
            raise InjectedCrash("before_receipt_write")
        head = self.log.events()[-1] if self.log.events() else None
        data = {
            "migration_id": mid,
            "commit_seq": m.commit_seq,
            "old_revoke_seq": m.old_revoke_seq,
            "new_post_seq": m.new_post_seq,
            "old_confirmer": m.conf_old,
            "new_confirmer": m.conf_new,
            "log_last_seq": self.log.last_seq(),
            "log_last_hash": head.hash if head else None,
        }
        self.receipts.write(mid, data)
        # A receipt is an off-log artifact; mark presence with a sentinel.
        m.receipt_seq = self.log.last_seq()

    def complete_pending(self) -> list[str]:
        """Recovery entry point: finish every committed migration exactly once."""
        actions: list[str] = []
        with self._eng_lock:
            for mid in list(self.state.migrations.keys()):
                m = self.state.migrations[mid]
                if m.commit_seq is None:
                    continue
                if m.old_revoke_seq is None:
                    self.execute("revoke_old", mid=mid, auto=True)
                    actions.append("revoke_old")
                if m.new_post_seq is None:
                    self.execute("post_new", mid=mid, auto=True)
                    actions.append("post_new")
                if not self.receipts.exists(mid):
                    self._maybe_write_receipt(mid)
                    actions.append("receipt")
        return actions

    # -- queries ------------------------------------------------------------

    def visible_credentials(self, org: str) -> list[str]:
        """Tenant-scoped visibility: only credentials owned by ``org``."""
        with self._eng_lock:
            return sorted(cid for cid, c in self.state.credentials.items()
                          if c.org == org)

    def find_chain(self, org: str, resid: str, purpose: str, gen: int,
                   subject: str, as_of: int | None = None
                   ) -> list[Edge] | None:
        s = self.state
        controllers = self.topo.orgs[org].actual_controllers
        active: list[Edge] = []
        for eid, e in s.edges.items():
            rev = s.edge_revoked_seq.get(eid)
            if rev is not None and (as_of is None or rev <= as_of):
                continue
            if e.org != org or e.resid != resid or e.purpose != purpose:
                continue
            if e.gen != gen:
                continue
            active.append(e)

        outgoing: dict[str, list[Edge]] = {}
        for e in active:
            outgoing.setdefault(e.grantor, []).append(e)

        # BFS from every actual controller root.
        queue: list[tuple[str, list[Edge]]] = [(c, []) for c in controllers]
        seen: set[tuple[str, str]] = set()
        while queue:
            node, path = queue.pop(0)
            for e in outgoing.get(node, []):
                if (node, e.edge_id) in seen:
                    continue
                seen.add((node, e.edge_id))
                npath = path + [e]
                if e.grantee == subject:
                    return npath
                if e.may_delegate:
                    queue.append((e.grantee, npath))
        return None

    def authorize(self, req: AccessRequest, as_of: int | None = None
                  ) -> Decision:
        with self._eng_lock:
            return self._authorize_unlocked(req, as_of)

    def _authorize_unlocked(self, req: AccessRequest,
                            as_of: int | None) -> Decision:
        s = self.state

        resource = self.topo.resources.get(req.resid)
        if resource is None:
            return deny(DENY_RESOURCE_UNKNOWN, req,
                        "resource is not registered in any tenant")

        # Resolve credential (by id if presented, else unique-ish match).
        cred: Credential | None = None
        if req.cred_id is not None:
            cred = s.credentials.get(req.cred_id)
        else:
            matches = [c for c in s.credentials.values()
                       if c.subject == req.subject and c.resid == req.resid
                       and c.purpose == req.purpose]
            # Prefer a non-revoked credential, else the newest durable one.
            live = [c for c in matches
                    if c.cred_id not in s.cred_revoked_seq]
            pool = live or matches
            if pool:
                cred = sorted(pool, key=lambda c: c.cred_id)[-1]
        if cred is None:
            return deny(DENY_NO_CREDENTIAL, req,
                        "no bound credential for subject/resource/purpose")

        ev: dict[str, Any] = {
            "cred_id": cred.cred_id,
            "cred_kind": cred.kind,
            "bound_resource": cred.resid,
            "bound_purpose": cred.purpose,
            "authorization_generation": cred.gen,
        }

        if cred.subject != req.subject:
            return deny(DENY_CREDENTIAL_OWNER, req,
                        "credential is bound to a different subject", ev)

        # --- Tenant boundary (uncrossable) -------------------------------
        ev["cred_org"] = cred.org
        ev["resource_org"] = resource.org
        ev["tenant_match"] = (cred.org == resource.org)
        if cred.org != resource.org:
            return deny(DENY_TENANT_MISMATCH, req,
                        "credential tenant does not own the target resource",
                        ev)

        if cred.resid != req.resid:
            return deny(DENY_RESOURCE_BINDING, req,
                        "credential is bound to another resource", ev)
        if cred.purpose != req.purpose:
            return deny(DENY_PURPOSE_BINDING, req,
                        "credential is bound to another purpose", ev)

        floor = s.gen_floor_by_org.get(cred.org, 0)
        ev["org_generation_floor"] = floor
        if cred.gen < floor:
            ev["fenced"] = True
            return deny(DENY_GENERATION_FENCED, req,
                        "credential generation was fenced by a control change",
                        ev)

        # --- Revocation vs late witness, decided by physical seq ---------
        rev_seq = s.cred_revoked_seq.get(cred.cred_id)
        if as_of is not None and rev_seq is not None and rev_seq > as_of:
            rev_seq = None
        if rev_seq is not None:
            late = [w for w in s.witnesses
                    if w.cred_id == cred.cred_id and w.gen == cred.gen
                    and w.seq > rev_seq
                    and (as_of is None or w.seq <= as_of)]
            ev["revocation_seq"] = rev_seq
            ev["witness_seqs"] = sorted(
                w.seq for w in s.witnesses if w.cred_id == cred.cred_id)
            if late:
                ev["late_witness_seq"] = max(w.seq for w in late)
                ev["effective_record"] = (
                    f"revocation@{rev_seq}")
                ev["rule"] = (
                    "terminal revocation fences this generation; a later "
                    "durable witness for the same generation is stale")
                return deny(DENY_LATE_WITNESS_STALE, req,
                            "old authorization revoked; late witness cannot "
                            "restore access", ev)
            ev["effective_record"] = f"revocation@{rev_seq}"
            return deny(DENY_REVOKED, req,
                        "credential has a durable revocation", ev)

        # --- Replacement credential must have a durable posting ----------
        if cred.kind == REPLACEMENT and cred.migration_id:
            m = s.migrations.get(cred.migration_id)
            if m is None or m.commit_seq is None:
                ev["commit_seq"] = None
                return deny(DENY_NOT_COMMITTED, req,
                            "replacement exists without a migration commit",
                            ev)
            # Defense in depth: break-before-make means the old side must also
            # be durably revoked before the replacement can authorize.
            if m.old_revoke_seq is None:
                return deny(DENY_REVOKED, req,
                            "replacement blocked until old org revocation is "
                            "durable", ev)
            if m.new_post_seq is None:
                return deny(DENY_NEW_POSTING_ABSENT, req,
                            "new organization has not posted the replacement",
                            ev)
            ev["commit_seq"] = m.commit_seq
            ev["old_revoke_seq"] = m.old_revoke_seq
            ev["new_posting_seq"] = m.new_post_seq

        # --- Multi-level delegation chain --------------------------------
        chain = self.find_chain(cred.org, cred.resid, cred.purpose, cred.gen,
                                cred.subject, as_of=as_of)
        if chain is None:
            return deny(DENY_DELEGATION_BROKEN, req,
                        "no unbroken active delegation chain from an actual "
                        "controller to the subject", ev)
        ev["delegation_chain"] = [
            {"edge": e.edge_id, "from": e.grantor, "to": e.grantee,
             "gen": e.gen}
            for e in chain
        ]
        ev["chain_length"] = len(chain)
        ev["effective_record"] = f"credential_issued({cred.cred_id})"
        return allow(req, "bound credential supported by active delegation "
                          "chain in the matching tenant/generation", ev)

    # -- bulk probe logging (60k run) --------------------------------------

    def log_probe(self, req: AccessRequest, sync: bool = False) -> Decision:
        self.log.append("probe", req.to_dict(), sync=sync)
        return self.authorize(req)

    def decision_snapshot(self, requests: list[AccessRequest]
                          ) -> list[dict[str, Any]]:
        return [self.authorize(r).to_dict() for r in requests]


# ---------------------------------------------------------------------------
# Standard bootstrap: a 3-hop OLD chain and a 3-hop NEW chain
# ---------------------------------------------------------------------------

def bootstrap_standard(eng: GateEngine) -> None:
    """Write the fixed synthetic root facts into an empty memory/file log."""
    from .topology import (
        C_NEW,
        C_OLD,
        RES_NEW,
        RES_OLD,
        THIRD,
        C_THIRD,
        RES_THIRD,
    )

    log = eng.log

    def edge(eid: str, org: str, g_from: str, g_to: str, resid: str,
             gen: int, delegate: bool) -> None:
        log.append("edge_granted", Edge(
            eid, org, g_from, g_to, resid, PURPOSE, gen, delegate
        ).to_dict())

    # OLD: actual controller -> manager -> lead -> worker (3 edges).
    edge("e-old-1", OLD, C_OLD, "mgr_old", RES_OLD, GEN_OLD, True)
    edge("e-old-2", OLD, "mgr_old", "lead_old", RES_OLD, GEN_OLD, True)
    edge("e-old-3", OLD, "lead_old", WORKER, RES_OLD, GEN_OLD, False)

    # NEW: actual controller -> manager -> lead -> worker (3 edges).
    edge("e-new-1", NEW, C_NEW, "mgr_new", RES_NEW, GEN_NEW, True)
    edge("e-new-2", NEW, "mgr_new", "lead_new", RES_NEW, GEN_NEW, True)
    edge("e-new-3", NEW, "lead_new", WORKER, RES_NEW, GEN_NEW, False)

    # THIRD tenant has its own chain ending at its own worker (never ours).
    edge("e-third-1", THIRD, C_THIRD, "mgr_third", RES_THIRD, GEN_OLD, True)
    edge("e-third-2", THIRD, "mgr_third", "worker_third", RES_THIRD,
         GEN_OLD, False)

    log.append("credential_issued", Credential(
        CRED_OLD, ORIGINAL, OLD, WORKER, RES_OLD, PURPOSE, GEN_OLD, MID
    ).to_dict())

    # Unrelated third tenant's own credential: an isolation canary.  None of
    # the migration symbols ever touch THIRD, so this must stay ALLOW.
    from .topology import CRED_THIRD, WORKER_THIRD
    log.append("credential_issued", Credential(
        CRED_THIRD, ORIGINAL, THIRD, WORKER_THIRD, RES_THIRD, PURPOSE, GEN_OLD
    ).to_dict())

    log.append("migration_opened", {
        "mid": MID,
        "worker": WORKER,
        "old_org": OLD,
        "new_org": NEW,
        "old_cred_id": CRED_OLD,
        "new_cred": {
            "cred_id": CRED_NEW, "resid": RES_NEW,
            "purpose": PURPOSE, "gen": GEN_NEW,
        },
    })
