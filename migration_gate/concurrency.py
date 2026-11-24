"""Two worker threads + barrier proof.

Two properties are demonstrated under real OS threads and a
``threading.Barrier(2)`` against a real fsync-ed JSONL log:

1. A durable old-organization revocation is *never lost* when an old witness
   races it.  Both physical sequence orders are exercised; a deterministic
   barrier ordering additionally forces the exact "revoked first, witness
   late" boundary.  Every round is then **recovered from disk in a brand-new
   engine** and must deny.

2. Two tenant worker threads hammer their own and each other's authorizations
   and visible sets behind a start barrier; cross-tenant use and visibility
   leakage must always be zero.
"""

from __future__ import annotations

import os
import tempfile
import threading
from typing import Any

from .engine import GateEngine
from .model import AccessRequest
from .topology import (
    CRED_OLD,
    CRED_THIRD,
    MID,
    RES_OLD,
    RES_THIRD,
    WORKER,
    WORKER_THIRD,
)

RACE_ROUNDS = 20
TENANT_ITERATIONS = 400
JOIN_TIMEOUT = 30.0


def _fresh_file_engine(base_dir: str, tag: str):
    d = tempfile.mkdtemp(prefix=tag + "_", dir=base_dir)
    eng = GateEngine.create_file(d)
    return d, eng


def revocation_barrier_proof(base_dir: str,
                             rounds: int = RACE_ROUNDS) -> dict[str, Any]:
    os.makedirs(base_dir, exist_ok=True)
    tally = {
        "rounds": 0,
        "revoke_first_late_witness": 0,
        "witness_first_then_revoke": 0,
    }
    recovered_rows: list[dict[str, Any]] = []
    errors: list[str] = []

    # ---- Deterministic "revoked, then late witness" with two threads ------
    d, eng = _fresh_file_engine(base_dir, "late")
    start = threading.Barrier(2)
    revoked_barrier = threading.Barrier(2)
    box: dict[str, Any] = {}

    def late_revoker() -> None:
        try:
            start.wait()
            r = eng.execute("revoke_old", mid=MID)
            box["revoke_seq"] = r.get("old_revoke_seq") or r.get("seq")
            revoked_barrier.wait()
        except Exception as exc:  # pragma: no cover
            errors.append(f"revoker: {exc!r}")
            try:
                start.abort(); revoked_barrier.abort()
            except Exception:
                pass

    def late_witness() -> None:
        try:
            start.wait()
            revoked_barrier.wait()  # do not append until revocation is durable
            r = eng.execute("witness_old", mid=MID)
            box["witness_seq"] = r.get("seq")
        except Exception as exc:  # pragma: no cover
            errors.append(f"witness: {exc!r}")
            try:
                start.abort(); revoked_barrier.abort()
            except Exception:
                pass

    t1 = threading.Thread(target=late_revoker, name="old-revoker")
    t2 = threading.Thread(target=late_witness, name="late-witness")
    t1.start(); t2.start()
    t1.join(JOIN_TIMEOUT); t2.join(JOIN_TIMEOUT)
    if t1.is_alive() or t2.is_alive():
        errors.append("deterministic barrier threads did not finish")

    eng.log.fsync()
    eng.log.close()
    reopened = GateEngine.reopen_file(d)
    dec = reopened.authorize(AccessRequest(WORKER, RES_OLD, "read"))
    rseq = reopened.state.cred_revoked_seq.get(CRED_OLD)
    wseqs = [w.seq for w in reopened.state.witnesses]
    deterministic = {
        "revoke_seq": box.get("revoke_seq"),
        "witness_seq": box.get("witness_seq"),
        "recovered_code": dec.code,
        "recovered_allow": dec.allow,
        "revocation_physical_seq": rseq,
        "witness_physical_seqs": wseqs,
        "on_disk_log_seq_count": reopened.log.last_seq(),
        "pass": (
            not dec.allow and dec.code == "DENY_LATE_WITNESS_STALE"
            and rseq is not None and box.get("witness_seq", 0) > rseq
        ),
    }
    reopened.log.close()

    # ---- Deterministic opposite order: witness durable BEFORE revocation --
    d2, eng2 = _fresh_file_engine(base_dir, "early")
    start2 = threading.Barrier(2)
    witness_done = threading.Barrier(2)
    box2: dict[str, Any] = {}

    def early_revoker() -> None:
        try:
            start2.wait()
            witness_done.wait()  # do not revoke until witness is durable
            r = eng2.execute("revoke_old", mid=MID)
            box2["revoke_seq"] = r.get("old_revoke_seq") or r.get("seq")
        except Exception as exc:  # pragma: no cover
            errors.append(f"early-revoker: {exc!r}")
            try:
                start2.abort(); witness_done.abort()
            except Exception:
                pass

    def early_witness() -> None:
        try:
            start2.wait()
            r = eng2.execute("witness_old", mid=MID)
            box2["witness_seq"] = r.get("seq")
            witness_done.wait()
        except Exception as exc:  # pragma: no cover
            errors.append(f"early-witness: {exc!r}")
            try:
                start2.abort(); witness_done.abort()
            except Exception:
                pass

    ta = threading.Thread(target=early_revoker, name="early-revoker")
    tb = threading.Thread(target=early_witness, name="early-witness")
    ta.start(); tb.start()
    ta.join(JOIN_TIMEOUT); tb.join(JOIN_TIMEOUT)
    if ta.is_alive() or tb.is_alive():
        errors.append("deterministic witness-first threads did not finish")
    eng2.log.fsync(); eng2.log.close()
    rec2 = GateEngine.reopen_file(d2)
    dec2 = rec2.authorize(AccessRequest(WORKER, RES_OLD, "read"))
    early = {
        "witness_seq": box2.get("witness_seq"),
        "revoke_seq": box2.get("revoke_seq"),
        "recovered_code": dec2.code,
        "recovered_allow": dec2.allow,
        "pass": (
            not dec2.allow and dec2.code == "DENY_REVOKED"
            and box2.get("witness_seq") is not None
            and box2.get("revoke_seq", 0) > box2.get("witness_seq", 10 ** 9)
        ),
    }
    rec2.log.close()

    # ---- Free race: one start barrier, arbitrary physical order -----------
    for i in range(rounds):
        rd, reng = _fresh_file_engine(base_dir, f"race{i}")
        barrier = threading.Barrier(2)
        seqbox: dict[str, int] = {}
        errs_before = len(errors)

        def revoker(b=barrier, e=reng, sb=seqbox) -> None:
            try:
                b.wait()
                r = e.execute("revoke_old", mid=MID)
                sb["revoke"] = int(r.get("old_revoke_seq") or r.get("seq"))
            except Exception as exc:  # pragma: no cover
                errors.append(f"race {i} revoker: {exc!r}")
                try:
                    b.abort()
                except Exception:
                    pass

        def witness(b=barrier, e=reng, sb=seqbox) -> None:
            try:
                b.wait()
                r = e.execute("witness_old", mid=MID)
                sb["witness"] = int(r["seq"])
            except Exception as exc:  # pragma: no cover
                errors.append(f"race {i} witness: {exc!r}")
                try:
                    b.abort()
                except Exception:
                    pass

        tr = threading.Thread(target=revoker, name=f"r{i}")
        tw = threading.Thread(target=witness, name=f"w{i}")
        tr.start(); tw.start()
        tr.join(JOIN_TIMEOUT); tw.join(JOIN_TIMEOUT)
        if tr.is_alive() or tw.is_alive():
            errors.append(f"race {i}: threads hung")
            continue

        # Recover purely from disk to prove persistence / no loss.
        reng.log.fsync()
        reng.log.close()
        rec = GateEngine.reopen_file(rd)
        d = rec.authorize(AccessRequest(WORKER, RES_OLD, "read"))
        rseq2 = rec.state.cred_revoked_seq.get(CRED_OLD)
        wseq_list = [w.seq for w in rec.state.witnesses]
        ok = (
            rseq2 is not None and not d.allow
            and d.code in ("DENY_REVOKED", "DENY_LATE_WITNESS_STALE")
            and len([c for c in rec.state.command_results
                     if c["cmd"] == "revoke_old" and c["accepted"]]) == 1
            and len(errors) == errs_before
        )
        order = ("revoke_first_late_witness"
                 if wseq_list and max(wseq_list) > (rseq2 or 10 ** 9)
                 else "witness_first_then_revoke")
        tally["rounds"] += 1
        tally[order] += 1
        recovered_rows.append({
            "round": i, "dir": os.path.basename(rd),
            "revoke_seq": rseq2, "witness_seqs": wseq_list,
            "code": d.code, "allow": d.allow, "order": order, "pass": ok,
        })
        if not ok:
            errors.append(f"race {i} failed safety: {d.code} {rseq2}")
        rec.log.close()

    all_race_pass = all(r["pass"] for r in recovered_rows)
    return {
        "deterministic_late_order": deterministic,
        "deterministic_witness_first": early,
        "free_race": {
            "rounds": tally["rounds"],
            "revoke_first_late_witness": tally["revoke_first_late_witness"],
            "witness_first_then_revoke": tally["witness_first_then_revoke"],
            "all_recovered_and_denied": all_race_pass,
            "rows": recovered_rows,
        },
        "errors": errors,
        "pass": (deterministic["pass"] and early["pass"]
                 and all_race_pass and not errors),
    }


def tenancy_barrier_proof(base_dir: str,
                          iterations: int = TENANT_ITERATIONS
                          ) -> dict[str, Any]:
    os.makedirs(base_dir, exist_ok=True)
    d = tempfile.mkdtemp(prefix="tenant_", dir=base_dir)
    eng = GateEngine.create_file(d)
    start = threading.Barrier(2)

    stats = {
        "old": {"own_allow": 0, "cross_denied": 0, "cross_allowed": 0,
                "visibility_checks": 0, "visibility_leaks": 0,
                "wrong_codes": []},
        "third": {"own_allow": 0, "cross_denied": 0, "cross_allowed": 0,
                  "visibility_checks": 0, "visibility_leaks": 0,
                  "wrong_codes": []},
    }
    errors: list[str] = []

    old_own = AccessRequest(WORKER, RES_OLD, "read")
    old_cross = AccessRequest(WORKER, RES_THIRD, "read", CRED_OLD)
    third_own = AccessRequest(WORKER_THIRD, RES_THIRD, "read")
    third_cross = AccessRequest(WORKER_THIRD, RES_OLD, "read", CRED_THIRD)

    def old_worker() -> None:
        try:
            start.wait()
            for _ in range(iterations):
                eng.log_probe(old_own, sync=False)
                if eng.authorize(old_own).allow:
                    stats["old"]["own_allow"] += 1
                c = eng.authorize(old_cross)
                if c.allow:
                    stats["old"]["cross_allowed"] += 1
                elif c.code == "DENY_TENANT_MISMATCH":
                    stats["old"]["cross_denied"] += 1
                else:
                    stats["old"]["wrong_codes"].append(c.code)
                vis = eng.visible_credentials("ORG_OLD")
                stats["old"]["visibility_checks"] += 1
                # Exact-set assertion (not a tautological org filter): in the
                # static tenancy world ORG_OLD owns exactly CRED_OLD.
                if vis != sorted([CRED_OLD]):
                    stats["old"]["visibility_leaks"] += 1
        except Exception as exc:  # pragma: no cover
            errors.append(f"old_worker: {exc!r}")
            try:
                start.abort()
            except Exception:
                pass

    def third_worker() -> None:
        try:
            start.wait()
            for _ in range(iterations):
                eng.log_probe(third_own, sync=False)
                if eng.authorize(third_own).allow:
                    stats["third"]["own_allow"] += 1
                c = eng.authorize(third_cross)
                if c.allow:
                    stats["third"]["cross_allowed"] += 1
                elif c.code == "DENY_TENANT_MISMATCH":
                    stats["third"]["cross_denied"] += 1
                else:
                    stats["third"]["wrong_codes"].append(c.code)
                vis = eng.visible_credentials("ORG_THIRD")
                stats["third"]["visibility_checks"] += 1
                # Exact-set assertion: ORG_THIRD owns exactly CRED_THIRD.
                if vis != sorted([CRED_THIRD]):
                    stats["third"]["visibility_leaks"] += 1
        except Exception as exc:  # pragma: no cover
            errors.append(f"third_worker: {exc!r}")
            try:
                start.abort()
            except Exception:
                pass

    t1 = threading.Thread(target=old_worker, name="tenant-old")
    t2 = threading.Thread(target=third_worker, name="tenant-third")
    t1.start(); t2.start()
    t1.join(JOIN_TIMEOUT); t2.join(JOIN_TIMEOUT)
    hung = t1.is_alive() or t2.is_alive()
    if hung:
        errors.append("tenant threads hung")

    eng.log.fsync()
    total_log_events = eng.log.last_seq()
    eng.log.close()

    # Recover from disk and re-check the full cross matrix + visible sets.
    rec = GateEngine.reopen_file(d)
    final_checks = {
        "old_own_allow": rec.authorize(old_own).allow,
        "third_own_allow": rec.authorize(third_own).allow,
        "old_cross_code": rec.authorize(old_cross).code,
        "third_cross_code": rec.authorize(third_cross).code,
        "visible_OLD": rec.visible_credentials("ORG_OLD"),
        "visible_NEW": rec.visible_credentials("ORG_NEW"),
        "visible_THIRD": rec.visible_credentials("ORG_THIRD"),
        "log_events_after_recovery": rec.log.last_seq(),
    }
    disjoint = set(final_checks["visible_OLD"]).isdisjoint(
        final_checks["visible_THIRD"])
    exact_sets = (
        final_checks["visible_OLD"] == sorted([CRED_OLD])
        and final_checks["visible_THIRD"] == sorted([CRED_THIRD])
        and final_checks["visible_NEW"] == []
    )
    rec.log.close()

    cross_allowed = (stats["old"]["cross_allowed"]
                     + stats["third"]["cross_allowed"])
    leaks = (stats["old"]["visibility_leaks"]
             + stats["third"]["visibility_leaks"])
    own_expected = iterations * 2
    own_actual = stats["old"]["own_allow"] + stats["third"]["own_allow"]
    cross_denied = (stats["old"]["cross_denied"]
                    + stats["third"]["cross_denied"])
    return {
        "iterations_per_thread": iterations,
        "worker_threads": 2,
        "barrier": "threading.Barrier(2) start rendezvous",
        "own_access_allow": own_actual,
        "own_access_expected": own_expected,
        "cross_attempts_denied_tenant_mismatch": cross_denied,
        "cross_allowed": cross_allowed,
        "visibility_set_mismatches": leaks,
        "visibility_leaks": leaks,  # back-compat report key; now exact-set
        "visible_sets_disjoint_on_disk_recovery": disjoint,
        "visible_sets_exact_on_disk_recovery": exact_sets,
        "total_durable_log_events": total_log_events,
        "stats": stats,
        "disk_recovery": final_checks,
        "errors": errors,
        "pass": (
            not hung and not errors and cross_allowed == 0 and leaks == 0
            and own_actual == own_expected and disjoint and exact_sets
            and cross_denied == iterations * 2
            and final_checks["old_own_allow"]
            and final_checks["third_own_allow"]
            and final_checks["old_cross_code"] == "DENY_TENANT_MISMATCH"
            and final_checks["third_cross_code"] == "DENY_TENANT_MISMATCH"
        ),
    }


def run_concurrency_proof(artifacts_dir: str,
                          rounds: int = RACE_ROUNDS,
                          iterations: int = TENANT_ITERATIONS
                          ) -> dict[str, Any]:
    base = os.path.join(artifacts_dir, "concurrency")
    rev = revocation_barrier_proof(os.path.join(base, "revocation"),
                                   rounds=rounds)
    ten = tenancy_barrier_proof(os.path.join(base, "tenancy"),
                                iterations=iterations)
    return {"revocation": rev, "tenancy": ten,
            "pass": rev["pass"] and ten["pass"]}
