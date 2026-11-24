"""Stdlib unittest suite for the offline migration gate.

Run from the workspace root:

    python -m unittest discover -s tests -v
"""

from __future__ import annotations

import json
import tempfile
import unittest

from migration_gate.concurrency import (
    revocation_barrier_proof,
    tenancy_barrier_proof,
)
from migration_gate.durable import DurableLog, MemorySink, TamperError
from migration_gate.engine import GateEngine
from migration_gate.exhaustive import run_exhaustive
from migration_gate.model import AccessRequest, InjectedCrash
from migration_gate.synthetic import (
    _subtree_leaves,
    build_multi_org,
    build_requests,
    diff_matrices,
    engine_matrix,
)
from migration_gate.topology import (
    C_NEW,
    C_OLD,
    MID,
    NEW,
    OLD,
    PURPOSE,
    RES_NEW,
    RES_OLD,
    SAME_PERSON,
    WORKER,
    standard_topology,
)


class TestBaseline(unittest.TestCase):
    def setUp(self) -> None:
        self.eng = GateEngine.create_memory()

    def test_pre_migration_old_allowed_new_absent(self) -> None:
        old = self.eng.authorize(AccessRequest(WORKER, RES_OLD, PURPOSE))
        new = self.eng.authorize(AccessRequest(WORKER, RES_NEW, PURPOSE))
        self.assertTrue(old.allow, old.to_dict())
        self.assertEqual(old.code, "ALLOW")
        self.assertFalse(new.allow)
        self.assertEqual(new.code, "DENY_NO_CREDENTIAL")
        # Multi-level chain really is 3 edges.
        self.assertEqual(old.evidence["chain_length"], 3)

    def test_bindings(self) -> None:
        from migration_gate.topology import CRED_OLD, RES_OLD_WIKI
        bad_purpose = self.eng.authorize(
            AccessRequest(WORKER, RES_OLD, "deploy", CRED_OLD))
        bad_resource = self.eng.authorize(
            AccessRequest(WORKER, RES_OLD_WIKI, PURPOSE, CRED_OLD))
        self.assertEqual(bad_purpose.code, "DENY_PURPOSE_BINDING")
        self.assertEqual(bad_resource.code, "DENY_RESOURCE_BINDING")

    def test_cross_tenant_denied(self) -> None:
        from migration_gate.topology import CRED_OLD, RES_THIRD
        d = self.eng.authorize(
            AccessRequest(WORKER, RES_THIRD, PURPOSE, CRED_OLD))
        self.assertFalse(d.allow)
        self.assertEqual(d.code, "DENY_TENANT_MISMATCH")


class TestDualControl(unittest.TestCase):
    def test_rogue_and_single_confirmer(self) -> None:
        eng = GateEngine.create_memory()
        # No dual confirmation -> commit rejected.
        r = eng.execute("commit", mid=MID)
        self.assertFalse(r["accepted"])
        self.assertEqual(r["code"], "REJECT_DUAL_CONFIRMATION")
        # Third-org actual controller cannot confirm the OLD side.
        bad = eng.execute("confirm", mid=MID, side="old",
                          person="ctrl_third_wang")
        self.assertFalse(bad["accepted"])
        self.assertEqual(bad["code"], "REJECT_WRONG_ORG")

    def test_non_controller_outsider_rejected(self) -> None:
        from migration_gate.topology import ROGUE
        eng = GateEngine.create_memory()
        r = eng.execute("confirm", mid=MID, side="old", person=ROGUE)
        self.assertFalse(r["accepted"])
        self.assertEqual(r["code"], "REJECT_NOT_ACTUAL_CONTROLLER")

    def test_credential_owner_binding_enforced(self) -> None:
        from migration_gate.topology import CRED_OLD
        eng = GateEngine.create_memory()
        d = eng.authorize(AccessRequest(
            "impostor_subject", RES_OLD, PURPOSE, CRED_OLD))
        self.assertFalse(d.allow)
        self.assertEqual(d.code, "DENY_CREDENTIAL_OWNER")

    def test_same_natural_person_cannot_fill_both_sides(self) -> None:
        topo = standard_topology()
        topo.add_org(OLD, {C_OLD, SAME_PERSON})
        topo.add_org(NEW, {C_NEW, SAME_PERSON})
        eng = GateEngine.create_memory(topo)
        first = eng.execute("confirm", mid=MID, side="old",
                            person=SAME_PERSON)
        second = eng.execute("confirm", mid=MID, side="new",
                             person=SAME_PERSON)
        self.assertTrue(first["accepted"])
        self.assertFalse(second["accepted"])
        self.assertEqual(second["code"], "REJECT_SAME_CONFIRMER")
        self.assertIsNone(eng.state.migrations[MID].conf_new)

    def test_full_happy_path(self) -> None:
        eng = GateEngine.create_memory()
        eng.execute("confirm", mid=MID, side="old", person=C_OLD)
        eng.execute("confirm", mid=MID, side="new", person=C_NEW)
        eng.execute("commit", mid=MID)
        eng.execute("revoke_old", mid=MID)
        eng.execute("post_new", mid=MID)
        old = eng.authorize(AccessRequest(WORKER, RES_OLD, PURPOSE))
        new = eng.authorize(AccessRequest(WORKER, RES_NEW, PURPOSE))
        self.assertFalse(old.allow)
        self.assertTrue(new.allow, new.to_dict())
        self.assertTrue(eng.receipts.exists(MID))


class TestBoundaries(unittest.TestCase):
    def test_late_witness_on_real_disk(self) -> None:
        d = tempfile.mkdtemp()
        eng = GateEngine.create_file(d)
        eng.execute("revoke_old", mid=MID)
        eng.execute("witness_old", mid=MID, claimed_seq=1)
        eng.log.close()
        rec = GateEngine.reopen_file(d)
        dec = rec.authorize(AccessRequest(WORKER, RES_OLD, PURPOSE))
        self.assertFalse(dec.allow)
        self.assertEqual(dec.code, "DENY_LATE_WITNESS_STALE")
        self.assertIn("late_witness_seq", dec.evidence)
        rec.log.close()

    def test_commit_then_crash_before_receipt(self) -> None:
        d = tempfile.mkdtemp()
        eng = GateEngine.create_file(d, crash_after="commit")
        eng.execute("confirm", mid=MID, side="old", person=C_OLD)
        eng.execute("confirm", mid=MID, side="new", person=C_NEW)
        with self.assertRaises(InjectedCrash):
            eng.execute("commit", mid=MID)
        self.assertFalse(eng.receipts.exists(MID))
        committed = eng.state.migrations[MID].commit_seq
        eng.log.close()

        rec = GateEngine.reopen_file(d)
        self.assertTrue(rec.receipts.exists(MID))
        self.assertFalse(
            rec.authorize(AccessRequest(WORKER, RES_OLD, PURPOSE)).allow)
        self.assertTrue(
            rec.authorize(AccessRequest(WORKER, RES_NEW, PURPOSE)).allow)
        self.assertIsNotNone(committed)
        seq = rec.log.last_seq()
        rec.complete_pending()
        self.assertEqual(rec.log.last_seq(), seq)  # idempotent
        rec.log.close()

    def test_crash_in_receipt_window_no_duplicate_effects(self) -> None:
        d = tempfile.mkdtemp()
        eng = GateEngine.create_file(d)
        eng.execute("confirm", mid=MID, side="old", person=C_OLD)
        eng.execute("confirm", mid=MID, side="new", person=C_NEW)
        eng.execute("commit", mid=MID)
        eng.execute("revoke_old", mid=MID)
        eng.crash_after = "receipt"
        with self.assertRaises(InjectedCrash):
            eng.execute("post_new", mid=MID)
        self.assertFalse(eng.receipts.exists(MID))
        seq_at_crash = eng.log.last_seq()
        eng.log.close()

        rec = GateEngine.reopen_file(d)
        self.assertTrue(rec.receipts.exists(MID))
        self.assertEqual(rec.log.last_seq(), seq_at_crash)
        accepted_rev = [c for c in rec.state.command_results
                        if c["cmd"] == "revoke_old" and c["accepted"]]
        accepted_post = [c for c in rec.state.command_results
                         if c["cmd"] == "post_new" and c["accepted"]]
        self.assertEqual(len(accepted_rev), 1)
        self.assertEqual(len(accepted_post), 1)
        rec.log.close()


class TestGenericCredentialRevocation(unittest.TestCase):
    """The exact generic command shape used by the 64k synthetic stream."""

    def test_generic_revoke_first_seq_idempotent(self) -> None:
        from migration_gate.topology import CRED_OLD
        eng = GateEngine.create_memory()
        first = eng.execute("revoke_credential", cred_id=CRED_OLD)
        second = eng.execute("revoke_credential", cred_id=CRED_OLD)
        self.assertTrue(first["accepted"])
        self.assertTrue(second["accepted"])
        self.assertEqual(
            eng.state.cred_revoked_seq[CRED_OLD], first["seq"])
        self.assertEqual(second["original_seq"], first["seq"])

    def test_generic_late_witness_stale(self) -> None:
        from migration_gate.topology import CRED_OLD
        eng = GateEngine.create_memory()
        eng.execute("revoke_credential", cred_id=CRED_OLD)
        # mid=None + explicit cred_id is the scale-stream witness shape.
        eng.execute("witness_old", mid=None, cred_id=CRED_OLD)
        d = eng.authorize(AccessRequest(WORKER, RES_OLD, PURPOSE))
        self.assertEqual(d.code, "DENY_LATE_WITNESS_STALE")
        self.assertFalse(d.allow)

    def test_generic_witness_before_revoke_is_revoked(self) -> None:
        from migration_gate.topology import CRED_OLD
        eng = GateEngine.create_memory()
        eng.execute("witness_old", mid=None, cred_id=CRED_OLD)
        eng.execute("revoke_credential", cred_id=CRED_OLD)
        d = eng.authorize(AccessRequest(WORKER, RES_OLD, PURPOSE))
        self.assertEqual(d.code, "DENY_REVOKED")


class TestDelegationGeneration(unittest.TestCase):
    def test_intermediate_edge_revocation_breaks_chain(self) -> None:
        eng = GateEngine.create_memory()
        eng.execute("revoke_edge", edge_id="e-old-2")
        d = eng.authorize(AccessRequest(WORKER, RES_OLD, PURPOSE))
        self.assertEqual(d.code, "DENY_DELEGATION_BROKEN")

    def test_generation_fence(self) -> None:
        eng = GateEngine.create_memory()
        self.assertTrue(
            eng.authorize(AccessRequest(WORKER, RES_OLD, PURPOSE)).allow)
        eng.execute("bump_gen_floor", org=OLD, floor=2)
        d = eng.authorize(AccessRequest(WORKER, RES_OLD, PURPOSE))
        self.assertEqual(d.code, "DENY_GENERATION_FENCED")


class TestDurableLog(unittest.TestCase):
    def test_sequences_contiguous(self) -> None:
        log = DurableLog.open_memory()
        for i in range(5):
            log.append("k", {"i": i})
        seqs = [e.seq for e in log.events()]
        self.assertEqual(seqs, [1, 2, 3, 4, 5])

    def test_middle_tamper_detected(self) -> None:
        log = DurableLog.open_memory()
        log.append("k", {"i": 1})
        log.append("k", {"i": 2})
        store = log.sink.store
        obj = json.loads(store[0])
        obj["hash"] = "0" * 64
        store[0] = json.dumps(obj)
        with self.assertRaises(TamperError):
            DurableLog(MemorySink(store))

    def test_torn_tail_truncated(self) -> None:
        store: list[str] = []
        log = DurableLog.open_memory(store)
        log.append("k", {"i": 1})
        log.append("k", {"i": 2})
        store.append("{broken torn line")
        recovered = DurableLog.open_memory(store)
        self.assertEqual(recovered.last_seq(), 2)
        self.assertEqual(len(store), 2)

    def test_last_record_hash_tamper_not_removed(self) -> None:
        # Rewriting the TERMINAL (e.g. revocation) record's hash must be
        # detected as tampering, not silently truncated as a torn write.
        log = DurableLog.open_memory()
        log.append("k", {"i": 1})
        log.append("k", {"i": 2})
        store = log.sink.store
        obj = json.loads(store[-1])
        obj["hash"] = "0" * 64
        store[-1] = json.dumps(obj)
        with self.assertRaises(TamperError):
            DurableLog(MemorySink(store))


class TestExhaustiveShort(unittest.TestCase):
    def test_depth_four_differential_and_invariants(self) -> None:
        rep = run_exhaustive(max_len=4)
        self.assertEqual(rep["oracle_mismatches"], [])
        self.assertEqual(rep["invariant_violations"], [])
        se = rep["shortest_evidence"]
        self.assertEqual(se["late_witness_stale"]["length"], 2)
        self.assertEqual(se["revoke_denies_old"]["length"], 1)
        self.assertEqual(se["delegation_break"]["length"], 1)
        self.assertEqual(se["crash_recover_completes"]["length"], 4)


class TestConcurrencySmall(unittest.TestCase):
    def test_revocation_barrier_small(self) -> None:
        d = tempfile.mkdtemp()
        rep = revocation_barrier_proof(d, rounds=2)
        self.assertTrue(rep["pass"], rep.get("errors"))

    def test_tenancy_barrier_small(self) -> None:
        d = tempfile.mkdtemp()
        rep = tenancy_barrier_proof(d, iterations=20)
        self.assertTrue(rep["pass"], rep.get("errors"))


class TestBlastRadiusMini(unittest.TestCase):
    def test_single_change_matches_lineage(self) -> None:
        topo, spec, boot = build_multi_org(n_orgs=3, branch=2, depth=3)
        eng = GateEngine.create_memory(topology=topo, bootstrap_fn=boot)
        reqs, meta = build_requests(spec)
        before = engine_matrix(eng, reqs)
        o = spec["orgs"][1]
        predicted = {
            f"R|{leaf}|{o}"
            for leaf in _subtree_leaves(spec, 1, (0,))
        }
        self.assertEqual(len(predicted), 4)  # 2^(3-1)
        eng.execute("revoke_edge", edge_id="e-1-0")
        after = engine_matrix(eng, reqs)
        changed = set(diff_matrices(before, after).keys())
        self.assertEqual(changed, predicted)
        for k in changed:
            self.assertEqual(meta[k]["source_org"], o)
            self.assertEqual(meta[k]["target_org"], o)


if __name__ == "__main__":  # pragma: no cover
    unittest.main(verbosity=2)
