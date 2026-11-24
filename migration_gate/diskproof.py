"""Real-disk demonstrations of the shortest evidence and the two hard edges.

Everything here uses a genuine fsync-ed JSONL log under the artifacts
directory.  Engines are closed and **recovered from the physical file** to
simulate process restart; no in-memory state is trusted for the claims.
"""

from __future__ import annotations

import os
import tempfile
from typing import Any

from .engine import GateEngine
from .exhaustive import dispatch, engine_observation
from .model import AccessRequest, InjectedCrash
from .oracle import Oracle, standard_probes
from .topology import MID, RES_OLD, WORKER


def run_file_word(word: list[str], directory: str) -> GateEngine:
    eng = GateEngine.create_file(directory)
    for sym in word:
        if sym == "cr":
            eng.log.close()
            eng = GateEngine.reopen_file(directory)
        else:
            dispatch(eng, sym)
    return eng


def _physical_tail(eng: GateEngine, n: int = 8) -> list[dict[str, Any]]:
    out = []
    for ev in eng.log.events()[-n:]:
        cmd = ev.payload.get("cmd")
        out.append({"seq": ev.seq, "kind": ev.kind,
                    "cmd": cmd, "hash8": ev.hash[:8]})
    return out


def materialize_shortest_on_disk(shortest: dict[str, dict[str, Any]],
                                 base_dir: str) -> list[dict[str, Any]]:
    """Re-run each headline shortest word on a real file log and recover."""
    os.makedirs(base_dir, exist_ok=True)
    headline = [
        "baseline_old_allow",
        "cross_tenant_deny",
        "resource_binding_deny",
        "purpose_binding_deny",
        "commit_requires_dual",
        "wrong_org_confirm_rejected",
        "revoke_denies_old",
        "late_witness_stale",
        "witness_before_revoke",
        "delegation_break",
        "dual_confirm_commit",
        "crash_recover_completes",
        "happy_explicit_completed",
    ]
    rows: list[dict[str, Any]] = []
    probes = dict(standard_probes())
    pid_for = {
        "baseline_old_allow": "old_read",
        "cross_tenant_deny": "cross_oldcred_to_third",
        "resource_binding_deny": "resource_bind",
        "purpose_binding_deny": "purpose_bind",
        "revoke_denies_old": "old_read",
        "late_witness_stale": "old_read",
        "witness_before_revoke": "old_read",
        "delegation_break": "old_read",
        "crash_recover_completes": "new_read",
        "happy_explicit_completed": "new_read",
    }
    for key in headline:
        spec = shortest.get(key)
        # NB: an EMPTY word [] is a legitimate length-0 evidence and is falsy,
        # so test "word is None", never "not word".
        if not spec or spec.get("word") is None:
            rows.append({"key": key, "missing": True})
            continue
        d = tempfile.mkdtemp(prefix=f"ev_{key}_", dir=base_dir)
        word = list(spec["word"])
        eng = run_file_word(word, d)
        # Full close + fresh recovery so the evidence is read from disk.
        eng.log.close()
        rec = GateEngine.reopen_file(d)
        obs = engine_observation(rec, standard_probes())
        ora = Oracle.replay_events(rec.topo, rec.log.events()).observation(
            standard_probes())
        pid = pid_for.get(key)
        decision = rec.authorize(probes[pid]).to_dict() if pid else None
        rows.append({
            "key": key,
            "length": spec["length"],
            "word": word,
            "dir": os.path.basename(d),
            "physical_last_seq": rec.log.last_seq(),
            "tail": _physical_tail(rec, 6),
            "observation_matches_oracle": obs == ora,
            "decision": decision,
            "facts": obs["facts"],
        })
        rec.log.close()
    return rows


def boundary_late_witness(base_dir: str) -> dict[str, Any]:
    """Boundary 1: revocation durable first, old witness arrives late."""
    os.makedirs(base_dir, exist_ok=True)
    d = tempfile.mkdtemp(prefix="boundary_late_", dir=base_dir)
    eng = GateEngine.create_file(d)
    rv = eng.execute("revoke_old", mid=MID)
    wt = eng.execute("witness_old", mid=MID, claimed_seq=1)  # bogus claim
    eng.log.close()

    rec = GateEngine.reopen_file(d)
    dec = rec.authorize(AccessRequest(WORKER, RES_OLD, "read"))
    disk = {
        "revoke_attempt_seq": rv["seq"],
        "revoke_effective_seq": rv.get("old_revoke_seq"),
        "witness_seq": wt["seq"],
        "recovered_code": dec.code,
        "recovered_allow": dec.allow,
        "evidence": dec.evidence,
        "tail": _physical_tail(rec, 4),
    }
    rec.log.close()
    disk["pass"] = (
        not dec.allow and dec.code == "DENY_LATE_WITNESS_STALE"
        and wt["seq"] > rv.get("old_revoke_seq", -1)
    )
    return disk


def boundary_commit_before_receipt(base_dir: str) -> dict[str, Any]:
    """Boundary 2a: committed (fsync) then killed before ANY completion."""
    os.makedirs(base_dir, exist_ok=True)
    d = tempfile.mkdtemp(prefix="boundary_commit_", dir=base_dir)
    eng = GateEngine.create_file(d, crash_after="commit")
    eng.execute("confirm", mid=MID, side="old", person="ctrl_old_zhang")
    eng.execute("confirm", mid=MID, side="new", person="ctrl_new_li")
    crashed_at = None
    try:
        eng.execute("commit", mid=MID)
    except InjectedCrash as c:
        crashed_at = c.point
    committed_seq = eng.state.migrations[MID].commit_seq
    receipt_before_restart = eng.receipts.exists(MID)
    eng.log.close()

    rec = GateEngine.reopen_file(d)  # auto recovery + completion
    after_recover_seq = rec.log.last_seq()
    old_dec = rec.authorize(AccessRequest(WORKER, RES_OLD, "read"))
    from .topology import RES_NEW
    new_dec = rec.authorize(AccessRequest(WORKER, RES_NEW, "read"))
    receipt = rec.receipts.read(MID)
    stable_seq = rec.log.last_seq()
    rec.complete_pending()
    idempotent = rec.log.last_seq() == stable_seq
    out = {
        "crash_point": crashed_at,
        "committed_physical_seq": committed_seq,
        "receipt_present_immediately_after_crash": receipt_before_restart,
        "recovered_old_code": old_dec.code,
        "recovered_old_allow": old_dec.allow,
        "recovered_new_code": new_dec.code,
        "recovered_new_allow": new_dec.allow,
        "receipt": receipt,
        "log_seq_after_recovery": after_recover_seq,
        "completion_idempotent_no_new_seq": idempotent,
        "tail": _physical_tail(rec, 6),
        "pass": (
            crashed_at == "after_commit_before_receipt"
            and committed_seq is not None
            and receipt_before_restart is False
            and not old_dec.allow and new_dec.allow
            and receipt is not None and idempotent
        ),
    }
    rec.log.close()
    return out


def boundary_receipt_window(base_dir: str) -> dict[str, Any]:
    """Boundary 2b: effects durable, killed in the tiny window before receipt."""
    os.makedirs(base_dir, exist_ok=True)
    d = tempfile.mkdtemp(prefix="boundary_rcpt_", dir=base_dir)
    eng = GateEngine.create_file(d)
    eng.execute("confirm", mid=MID, side="old", person="ctrl_old_zhang")
    eng.execute("confirm", mid=MID, side="new", person="ctrl_new_li")
    eng.execute("commit", mid=MID)
    eng.execute("revoke_old", mid=MID)
    eng.crash_after = "receipt"
    post_seq = None
    crashed_at = None
    try:
        r = eng.execute("post_new", mid=MID)
        post_seq = r["seq"]
    except InjectedCrash as c:
        crashed_at = c.point
        # execute() raises before its return value is assigned; read the
        # authoritative durable seq straight out of the folded migration.
        post_seq = eng.state.migrations[MID].new_post_seq
    receipt_absent = not eng.receipts.exists(MID)
    seq_at_crash = eng.log.last_seq()
    eng.log.close()

    rec = GateEngine.reopen_file(d)
    seq_after_reopen = rec.log.last_seq()
    receipt = rec.receipts.read(MID)
    old_rev_count = len([1 for c in rec.state.command_results
                         if c["cmd"] == "revoke_old" and c["accepted"]])
    post_count = len([1 for c in rec.state.command_results
                      if c["cmd"] == "post_new" and c["accepted"]])
    out = {
        "crash_point": crashed_at,
        "post_physical_seq": post_seq,
        "receipt_absent_in_window": receipt_absent,
        "seq_at_crash": seq_at_crash,
        "seq_after_reopen": seq_after_reopen,
        "accepted_revoke_effects": old_rev_count,
        "accepted_post_effects": post_count,
        "receipt_written_on_recovery": receipt is not None,
        "no_duplicate_effect_seq": seq_after_reopen == seq_at_crash,
        "pass": (
            crashed_at == "before_receipt_write" and receipt_absent
            and receipt is not None and old_rev_count == 1
            and post_count == 1 and seq_after_reopen == seq_at_crash
        ),
    }
    rec.log.close()
    return out


def run_disk_proofs(artifacts_dir: str,
                    shortest: dict[str, dict[str, Any]]) -> dict[str, Any]:
    base = os.path.join(artifacts_dir, "disk")
    evidence = materialize_shortest_on_disk(
        shortest, os.path.join(base, "shortest"))
    # Non-vacuous: there must be at least one row and EVERY headline key must
    # be present (a missing target is a failure, not something to filter out).
    evidence_all_match = bool(evidence) and all(
        (not r.get("missing")) and r.get("observation_matches_oracle") is True
        for r in evidence
    )
    late = boundary_late_witness(os.path.join(base, "late"))
    commit = boundary_commit_before_receipt(os.path.join(base, "commit"))
    window = boundary_receipt_window(os.path.join(base, "window"))
    return {
        "shortest_on_disk": evidence,
        "shortest_evidence_oracle_match": evidence_all_match,
        "boundary_late_witness": late,
        "boundary_commit_before_receipt": commit,
        "boundary_receipt_window": window,
        "pass": (evidence_all_match and late["pass"] and commit["pass"]
                 and window["pass"]),
    }
