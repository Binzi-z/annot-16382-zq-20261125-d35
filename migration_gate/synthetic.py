"""60k+ multi-organization synthetic corpus and single-change blast radius.

Two independent validations:

* :func:`run_blast_radius` builds 16 tenants with 4-level delegation trees and
  a complete worker x organization decision matrix.  It changes exactly ONE
  control relationship (revokes one delegation edge) and performs a **full
  before/after matrix comparison**, then repeats one edge per organization.
  Structural lineage predicts the exact downstream leaf set; the observed
  changed set must equal it and never contain another tenant.

* :func:`run_scale_stream` emits >= 60 000 deterministic multi-org events to a
  real (group-flushed, final-fsync) JSONL log, closes and recovers it from
  disk, and runs an independent oracle over every physical event plus a full
  22k-cell decision-matrix comparison.
"""

from __future__ import annotations

import itertools
import os
import random
from typing import Any, Callable

from .engine import GateEngine
from .model import AccessRequest, Credential, Edge
from .oracle import Oracle
from .topology import Topology

N_ORGS = 16
BRANCH = 3
DEPTH = 4
LEAVES_PER_ORG = BRANCH ** DEPTH          # 81
TOTAL_LEAVES = N_ORGS * LEAVES_PER_ORG    # 1296
RUNTIME_EVENTS = 64_000
SEED = 16382


# ---------------------------------------------------------------------------
# World construction
# ---------------------------------------------------------------------------

def build_multi_org(n_orgs: int = N_ORGS, branch: int = BRANCH,
                    depth: int = DEPTH) -> tuple[Topology, dict[str, Any],
                                                 Callable[[GateEngine], None]]:
    lpo = branch ** depth
    topo = Topology()
    orgs = [f"ORG{i:02d}" for i in range(n_orgs)]
    resources: dict[str, str] = {}
    controllers: dict[str, str] = {}
    for i, o in enumerate(orgs):
        c = f"ctrl-{i}"
        controllers[o] = c
        topo.add_org(o, {c})
        rid = f"res-{i}-data"
        resources[o] = rid
        topo.add_resource(rid, o)

    paths_by_depth = {
        d: list(itertools.product(range(branch), repeat=d))
        for d in range(1, depth + 1)
    }
    leaves: dict[str, list[str]] = {o: [] for o in orgs}
    cred_of: dict[str, str] = {}
    leaf_org: dict[str, str] = {}
    edge_org: list[tuple[str, str]] = []
    edge_records: list[dict[str, Any]] = []
    cred_records: list[dict[str, Any]] = []

    for i, o in enumerate(orgs):
        rid = resources[o]
        ctl = controllers[o]
        for d in range(1, depth + 1):
            for p in paths_by_depth[d]:
                pstr = "-".join(map(str, p))
                eid = f"e-{i}-{pstr}"
                node = f"n-{i}-{pstr}"
                if d == 1:
                    grantor = ctl
                else:
                    grantor = f"n-{i}-" + "-".join(map(str, p[:-1]))
                is_leaf = d == depth
                edge_records.append(Edge(
                    eid, o, grantor, node, rid, "read", 1,
                    may_delegate=not is_leaf,
                ).to_dict())
                edge_org.append((eid, o))
                if is_leaf:
                    leaves[o].append(node)
                    cid = f"cred-{i}-{pstr}"
                    cred_of[node] = cid
                    leaf_org[node] = o
                    cred_records.append(Credential(
                        cid, "original", o, node, rid, "read", 1
                    ).to_dict())

    spec: dict[str, Any] = {
        "n_orgs": n_orgs, "branch": branch, "depth": depth,
        "leaves_per_org": lpo, "orgs": orgs,
        "resources": resources, "controllers": controllers,
        "leaves": leaves, "cred_of": cred_of, "leaf_org": leaf_org,
        "edge_org": edge_org, "total_leaves": n_orgs * lpo,
    }

    def bootstrap(eng: GateEngine) -> None:
        for e in edge_records:
            eng.log.append("edge_granted", e, sync=False)
        for c in cred_records:
            eng.log.append("credential_issued", c, sync=False)
        eng.log.fsync()

    return topo, spec, bootstrap


def _subtree_leaves(spec: dict[str, Any], org_index: int,
                    edge_path: tuple[int, ...]) -> list[str]:
    """Structural lineage: depth-``len(path)`` edge -> descendant leaves."""
    prefix = edge_path
    out: list[str] = []
    # Recompute from path strings directly for clarity.
    d = spec["depth"]
    for p in itertools.product(range(spec["branch"]), repeat=d):
        if p[:len(prefix)] == prefix:
            pstr = "-".join(map(str, p))
            out.append(f"n-{org_index}-{pstr}")
    return sorted(out)


# ---------------------------------------------------------------------------
# Full matrix
# ---------------------------------------------------------------------------

def build_requests(spec: dict[str, Any]
                   ) -> tuple[list[tuple[str, AccessRequest]],
                              dict[str, dict[str, str]]]:
    reqs: list[tuple[str, AccessRequest]] = []
    meta: dict[str, dict[str, str]] = {}
    orgs = spec["orgs"]
    for o in orgs:
        for leaf in spec["leaves"][o]:
            cid = spec["cred_of"][leaf]
            for t in orgs:
                key = f"R|{leaf}|{t}"
                reqs.append((key, AccessRequest(
                    leaf, spec["resources"][t], "read", cid)))
                meta[key] = {"source_org": o, "target_org": t,
                             "leaf": leaf, "kind": "read"}
            pkey = f"P|{leaf}|{o}"
            reqs.append((pkey, AccessRequest(
                leaf, spec["resources"][o], "deploy", cid)))
            meta[pkey] = {"source_org": o, "target_org": o,
                          "leaf": leaf, "kind": "purpose"}
    return reqs, meta


def engine_matrix(eng: GateEngine,
                  reqs: list[tuple[str, AccessRequest]]) -> dict[str, list]:
    return {k: [d.allow, d.code] for k, r in reqs
            for d in [eng.authorize(r)]}


def oracle_matrix(topo: Topology, events: list[Any],
                  reqs: list[tuple[str, AccessRequest]]) -> dict[str, list]:
    ora = Oracle.replay_events(topo, events)
    return {k: list(ora.decide(r)) for k, r in reqs}


def diff_matrices(before: dict[str, list], after: dict[str, list]
                  ) -> dict[str, dict[str, Any]]:
    changed: dict[str, dict[str, Any]] = {}
    for k in before:
        if before[k] != after[k]:
            changed[k] = {"before": before[k], "after": after[k]}
    return changed


# ---------------------------------------------------------------------------
# Single control-change blast radius (+ sweep over every org)
# ---------------------------------------------------------------------------

def run_blast_radius() -> dict[str, Any]:
    topo, spec, boot = build_multi_org()
    eng = GateEngine.create_memory(topology=topo, bootstrap_fn=boot)
    reqs, meta = build_requests(spec)
    total_cells = len(reqs)

    current = engine_matrix(eng, reqs)
    oracle_before = oracle_matrix(topo, eng.log.events(), reqs)
    initial_oracle_mismatches = sum(
        1 for k in current if current[k] != oracle_before[k])

    sweep: list[dict[str, Any]] = []
    hero: dict[str, Any] | None = None
    hero_index = 7

    for oi, o in enumerate(spec["orgs"]):
        edge_id = f"e-{oi}-0"          # one depth-1 control relationship
        predicted = set(
            f"R|{leaf}|{o}" for leaf in _subtree_leaves(spec, oi, (0,)))
        res = eng.execute("revoke_edge", edge_id=edge_id)
        after = engine_matrix(eng, reqs)
        changed = diff_matrices(current, after)
        actual = set(changed.keys())

        per_org: dict[str, int] = {}
        affected_orgs: set[str] = set()
        for k in changed:
            m = meta[k]
            per_org[m["source_org"]] = per_org.get(m["source_org"], 0) + 1
            affected_orgs.add(m["source_org"])

        row = {
            "org": o, "edge_id": edge_id,
            "edge_from": spec["controllers"][o], "edge_to": f"n-{oi}-0",
            "change_seq": res.get("edge_revoke_seq") or res.get("seq"),
            "predicted_leaves": len(predicted),
            "actual_changed_cells": len(actual),
            "affected_orgs": sorted(affected_orgs),
            "only_own_org": affected_orgs == {o},
            "matches_structural_lineage": actual == predicted,
        }
        sweep.append(row)

        if oi == hero_index:
            oracle_after = oracle_matrix(topo, eng.log.events(), reqs)
            oracle_mismatch_after = sum(
                1 for k in after if after[k] != oracle_after[k])
            hero = {
                **row,
                "full_matrix_cells": total_cells,
                "changed_cells": len(changed),
                "unchanged_cells": total_cells - len(changed),
                "per_org_changed_cells": per_org,
                "changed_cell_detail": [
                    {"cell": k, "source_org": meta[k]["source_org"],
                     "before": v["before"], "after": v["after"]}
                    for k, v in sorted(changed.items())
                ],
                "oracle_matrix_mismatches_before":
                    initial_oracle_mismatches,
                "oracle_matrix_mismatches_after_hero_change":
                    oracle_mismatch_after,
            }
        current = after

    all_pass = all(r["only_own_org"] and r["matches_structural_lineage"]
                   for r in sweep) and initial_oracle_mismatches == 0
    if hero:
        all_pass = all_pass and hero[
            "oracle_matrix_mismatches_after_hero_change"] == 0

    return {
        "organizations": spec["n_orgs"],
        "delegation_depth": spec["depth"],
        "branching_factor": spec["branch"],
        "leaves_per_org": spec["leaves_per_org"],
        "total_subjects": spec["total_leaves"],
        "full_matrix_cells": total_cells,
        "hero_change": hero,
        "every_org_single_change_sweep": sweep,
        "sweep_orgs_confined": sum(1 for r in sweep if r["only_own_org"]),
        "pass": bool(all_pass),
    }


# ---------------------------------------------------------------------------
# 60k deterministic multi-org event stream on a real file log
# ---------------------------------------------------------------------------

def run_scale_stream(artifacts_dir: str,
                     n_events: int = RUNTIME_EVENTS) -> dict[str, Any]:
    directory = os.path.join(artifacts_dir, "synthetic_stream")
    os.makedirs(directory, exist_ok=True)
    topo, spec, boot = build_multi_org()
    eng = GateEngine.create_file(directory, topology=topo,
                                 sync_controls=False, bootstrap_fn=boot)

    flat_leaves: list[tuple[str, str, str]] = []  # (org, leaf, cred_id)
    for o in spec["orgs"]:
        for leaf in spec["leaves"][o]:
            flat_leaves.append((o, leaf, spec["cred_of"][leaf]))
    edge_org = spec["edge_org"]

    rng = random.Random(SEED)
    by_org: dict[str, int] = {o: 0 for o in spec["orgs"]}
    counts = {"own_probe": 0, "cross_probe": 0, "purpose_probe": 0,
              "witness": 0, "revoke_credential": 0, "revoke_edge": 0}
    cross_tenant_blocked = 0
    cross_tenant_unexpected = 0

    for _ in range(n_events):
        roll = rng.random()
        o, leaf, cid = flat_leaves[rng.randrange(len(flat_leaves))]
        by_org[o] += 1

        if roll < 0.55:
            req = AccessRequest(leaf, spec["resources"][o], "read", cid)
            eng.log_probe(req, sync=False)
            counts["own_probe"] += 1
        elif roll < 0.80:
            others = [t for t in spec["orgs"] if t != o]
            t = others[rng.randrange(len(others))]
            req = AccessRequest(leaf, spec["resources"][t], "read", cid)
            d = eng.log_probe(req, sync=False)
            counts["cross_probe"] += 1
            if d.code == "DENY_TENANT_MISMATCH" and not d.allow:
                cross_tenant_blocked += 1
            else:
                cross_tenant_unexpected += 1
        elif roll < 0.88:
            req = AccessRequest(leaf, spec["resources"][o], "deploy", cid)
            eng.log_probe(req, sync=False)
            counts["purpose_probe"] += 1
        elif roll < 0.93:
            eng.execute("witness_old", mid=None, cred_id=cid)
            counts["witness"] += 1
        elif roll < 0.97:
            eng.execute("revoke_credential", cred_id=cid)
            counts["revoke_credential"] += 1
        else:
            eid, eo = edge_org[rng.randrange(len(edge_org))]
            by_org[eo] += 1
            eng.execute("revoke_edge", edge_id=eid)
            counts["revoke_edge"] += 1

    eng.log.fsync()
    runtime_events = n_events
    total_records = eng.log.last_seq()
    eng.log.close()

    # Recover entirely from disk and run the independent oracle + full matrix.
    rec = GateEngine.reopen_file(directory, topology=topo)
    recovered_records = rec.log.last_seq()
    reqs, _meta = build_requests(spec)
    mat_engine = engine_matrix(rec, reqs)
    mat_oracle = oracle_matrix(topo, rec.log.events(), reqs)
    all_mismatches = [k for k in mat_engine
                      if mat_engine[k] != mat_oracle[k]]
    mismatch_examples = all_mismatches[:10]

    state_counts_match = (
        len(rec.state.edges) == len(spec["edge_org"])
        and len(rec.state.credentials) == spec["total_leaves"]
    )
    rec.log.close()

    touched = {o: n for o, n in by_org.items() if n > 0}
    return {
        "seed": SEED,
        "organizations": spec["n_orgs"],
        "runtime_synthetic_events": runtime_events,
        "total_durable_records_including_bootstrap": total_records,
        "recovered_records_from_disk": recovered_records,
        "events_by_kind": counts,
        "events_attributed_per_org": touched,
        "min_org_events": min(by_org.values()),
        "max_org_events": max(by_org.values()),
        "cross_tenant_probes_blocked": cross_tenant_blocked,
        "cross_tenant_probes_unexpected": cross_tenant_unexpected,
        "full_matrix_cells_compared": len(reqs),
        "engine_oracle_matrix_mismatches": len(all_mismatches),
        "matrix_mismatch_examples": mismatch_examples,
        "state_counts_match": state_counts_match,
        "pass": (
            runtime_events >= 60_000
            and recovered_records == total_records
            and cross_tenant_unexpected == 0
            and cross_tenant_blocked == counts["cross_probe"]
            and not all_mismatches and state_counts_match
        ),
    }


def run_synthetic(artifacts_dir: str) -> dict[str, Any]:
    blast = run_blast_radius()
    stream = run_scale_stream(artifacts_dir)
    return {"blast_radius": blast, "scale_stream": stream,
            "pass": blast["pass"] and stream["pass"]}
