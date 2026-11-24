"""Independent exhaustive enumeration of short event sequences.

Every word over a small finite command alphabet up to length ``MAX_LEN`` is
executed by the real engine (in-memory durable log with identical sequence /
hash / recovery rules), differentially compared against the independent
:class:`~migration_gate.oracle.Oracle`, and checked against universal safety
invariants.  Words are enumerated by increasing length then lexicographically,
so the first witness for each decision is the *shortest decision evidence*.
"""

from __future__ import annotations

import itertools
from typing import Any, Callable

from .engine import GateEngine
from .model import (
    DENY_DELEGATION_BROKEN,
    DENY_LATE_WITNESS_STALE,
    DENY_NOT_COMMITTED,
    DENY_PURPOSE_BINDING,
    DENY_RESOURCE_BINDING,
    DENY_REVOKED,
    DENY_TENANT_MISMATCH,
    REJECT_DUAL_CONFIRMATION,
)
from .oracle import Oracle, standard_probes
from .topology import (
    C_NEW,
    C_OLD,
    C_THIRD,
    MID,
    Topology,
    standard_topology,
)

# Command alphabet.  Order fixes the lexicographic tie-break.
ALPHABET: tuple[str, ...] = (
    "oc",     # valid OLD actual controller confirms
    "nc",     # valid NEW actual controller confirms
    "bad",    # actual controller of the THIRD org tries to confirm OLD side
    "cm",     # commit the migration promise
    "rv",     # durable OLD-org revocation
    "wt",     # OLD witness (may be late)
    "np",     # NEW-org posting / capitalization
    "re",     # revoke the middle delegation edge e-old-2
    "cr",     # process dies and restarts -> replay + recover pending commit
)

SYMBOL_DESCRIPTION: dict[str, str] = {
    "oc": "旧组织实际控制人确认",
    "nc": "新组织实际控制人确认",
    "bad": "第三组织实际控制人越权确认旧侧(须拒)",
    "cm": "写入迁移承诺 migration_committed",
    "rv": "旧组织回收(持久撤销原凭证)",
    "wt": "旧授权见证(可能迟到)",
    "np": "新组织入账(激活替换凭证)",
    "re": "撤销多层委托的中间边 e-old-2",
    "cr": "进程中断后重启, 按落盘序号重放并恢复",
}

MAX_LEN = 5


def dispatch(eng: GateEngine, sym: str) -> None:
    if sym == "oc":
        eng.execute("confirm", mid=MID, side="old", person=C_OLD)
    elif sym == "nc":
        eng.execute("confirm", mid=MID, side="new", person=C_NEW)
    elif sym == "bad":
        eng.execute("confirm", mid=MID, side="old", person=C_THIRD)
    elif sym == "cm":
        eng.execute("commit", mid=MID)
    elif sym == "rv":
        eng.execute("revoke_old", mid=MID)
    elif sym == "wt":
        eng.execute("witness_old", mid=MID)
    elif sym == "np":
        eng.execute("post_new", mid=MID)
    elif sym == "re":
        eng.execute("revoke_edge", edge_id="e-old-2")
    elif sym == "cr":
        raise RuntimeError("cr must be handled by run_word restart branch")
    else:  # pragma: no cover
        raise ValueError(sym)


def engine_observation(eng: GateEngine,
                       probes: list[tuple[str, Any]]) -> dict[str, Any]:
    decisions = {pid: [d.allow, d.code]
                 for pid, req in probes
                 for d in [eng.authorize(req)]}
    m = eng.state.migrations[MID]
    visible = {oid: eng.visible_credentials(oid) for oid in eng.topo.orgs}
    return {
        "decisions": decisions,
        "facts": {
            "old_conf": m.conf_old is not None,
            "new_conf": m.conf_new is not None,
            "commit_seq": m.commit_seq,
            "old_revoke_seq": m.old_revoke_seq,
            "new_post_seq": m.new_post_seq,
            "receipt": eng.receipts.exists(MID),
        },
        "visible": visible,
    }


def run_word(word: tuple[str, ...], topo: Topology,
             probes: list[tuple[str, Any]]):
    """Execute one word; ``cr`` reopens the engine from the same durable store.

    Returns ``(eng, store, receipts)`` where ``eng`` is the live (possibly
    reopened) engine at the end of the word.
    """
    eng = GateEngine.create_memory(topo)
    store = eng.log.sink.store  # type: ignore[attr-defined]
    receipts = eng.receipts
    for sym in word:
        if sym == "cr":
            # Simulate process restart: brand-new engine over the SAME physical
            # line store and SAME (durable) receipt directory/object.
            eng = GateEngine.create_memory(
                topo, shared_store=store, receipts=receipts)  # type: ignore[arg-type]
        else:
            dispatch(eng, sym)
    return eng, store, receipts


def _decision(obs: dict[str, Any], pid: str) -> tuple[bool, str]:
    allow, code = obs["decisions"][pid]
    return bool(allow), str(code)


def independent_fixedpoint_authorizes(eng: GateEngine,
                                      req: Any) -> bool:
    """Third, algorithmically different chain/authority check.

    Instead of the engine's root-to-subject BFS, propagate an authority level
    by a monotone fixed point: actual controllers start at level 2 (may
    delegate); an active matching edge from a level-2 grantor raises the
    grantee to level 2 if ``may_delegate`` else level 1 (usable only).
    The request is authorized iff its bound credential's subject reaches >=1.
    """
    s = eng.state
    topo = eng.topo
    resource = topo.resources.get(req.resid)
    if resource is None:
        return False
    cred = None
    if req.cred_id is not None:
        cred = s.credentials.get(req.cred_id)
    else:
        ms = [c for c in s.credentials.values()
              if c.subject == req.subject and c.resid == req.resid
              and c.purpose == req.purpose]
        live = [c for c in ms if c.cred_id not in s.cred_revoked_seq]
        pool = live or ms
        if pool:
            cred = sorted(pool, key=lambda c: c.cred_id)[-1]
    if cred is None or cred.org != resource.org:
        return False
    org = cred.org
    level: dict[str, int] = {c: 2 for c in topo.orgs[org].actual_controllers}
    edges = [
        e for eid, e in s.edges.items()
        if eid not in s.edge_revoked_seq
        and e.org == org and e.resid == cred.resid
        and e.purpose == cred.purpose and e.gen == cred.gen
    ]
    changed = True
    while changed:
        changed = False
        for e in edges:
            if level.get(e.grantor, 0) < 2:
                continue
            want = 2 if e.may_delegate else 1
            if level.get(e.grantee, 0) < want:
                level[e.grantee] = want
                changed = True
    return level.get(cred.subject, 0) >= 1


def check_invariants(word: tuple[str, ...], obs: dict[str, Any],
                     eng: GateEngine) -> list[str]:
    """Universal safety properties that must hold for EVERY word."""
    v: list[str] = []
    d = obs["decisions"]

    # Tenant canary: unrelated third org is always fully unaffected.
    if d["third_own_read"][0] is not True:
        v.append("third-tenant positive control was denied")

    # Cross-tenant use is never allowed, in any interleaving.
    for pid in ("cross_oldcred_to_third", "cross_newcred_to_old"):
        if d[pid][0] is not False:
            v.append(f"{pid} was ALLOWED (tenant crossing)")

    old_allow, old_code = d["old_read"]
    new_allow, new_code = d["new_read"]
    f = obs["facts"]

    # Never dual access: original and replacement cannot both allow.
    if old_allow and new_allow:
        v.append("DUAL ACCESS: old_read and new_read both ALLOW")

    # Durable revocation can never be erased, even by a late witness.
    if f["old_revoke_seq"] is not None:
        if old_allow:
            v.append("old_read ALLOWED after durable revocation")
        if old_code not in (DENY_REVOKED, DENY_LATE_WITNESS_STALE):
            v.append(f"old_read wrong code after revocation: {old_code}")
        rseq = f["old_revoke_seq"]
        late = [w for w in eng.state.witnesses
                if w.cred_id == "cred-old-0001" and w.seq > rseq]
        if late and old_code != DENY_LATE_WITNESS_STALE:
            v.append("late witness present but code is "
                     f"{old_code} (expected LATE_WITNESS_STALE)")

    # Replacement access implies full dual-control + commit + old revoke +
    # posting + receipt, and the old side stays closed.
    if new_allow:
        if not (f["old_conf"] and f["new_conf"]):
            v.append("new_read ALLOW without dual confirmation")
        if f["commit_seq"] is None:
            v.append("new_read ALLOW without commit")
        if f["old_revoke_seq"] is None or f["new_post_seq"] is None:
            v.append("new_read ALLOW without both durable effects")
        if not f["receipt"]:
            v.append("new_read ALLOW but receipt missing")
        if old_allow:
            v.append("new_read ALLOW while old_read also ALLOW")

    # Visibility is tenant partitioned.
    for oid, ids in obs["visible"].items():
        for cid in ids:
            c = eng.state.credentials[cid]
            if c.org != oid:
                v.append(f"visible credential {cid} leaks across tenant "
                          f"{oid}->{c.org}")

    # Third-algorithm cross-check on every decision.
    probe_map = dict(standard_probes())
    for pid, pair in d.items():
        al, code = bool(pair[0]), str(pair[1])
        req = probe_map[pid]
        fp = independent_fixedpoint_authorizes(eng, req)
        if al and not fp:
            v.append(f"{pid} ALLOW but independent fixed-point rejects chain")
        if (not al) and code == DENY_DELEGATION_BROKEN and fp:
            v.append(f"{pid} DELEGATION_BROKEN but fixed-point finds authority")
    return v


# ---------------------------------------------------------------------------
# Shortest-evidence targets
# ---------------------------------------------------------------------------

def _has_cmd(eng: GateEngine, cmd: str, accepted: bool | None = None,
             code: str | None = None) -> dict[str, Any] | None:
    for r in eng.state.command_results:
        if r["cmd"] != cmd:
            continue
        if accepted is not None and r["accepted"] != accepted:
            continue
        if code is not None and r["code"] != code:
            continue
        return r
    return None


def build_targets() -> list[tuple[str, str, Callable]]:
    """Return (key, human claim, predicate(word, obs, eng)->evidence-bool)."""
    T: list[tuple[str, str, Callable]] = []

    def add(key: str, claim: str, fn: Callable) -> None:
        T.append((key, claim, fn))

    add("baseline_old_allow",
        "迁移前: 原凭证+多层委托使旧资源 ALLOW",
        lambda w, o, e: _decision(o, "old_read")[0] is True)
    add("third_canary_allow",
        "无关第三租户自身访问始终 ALLOW(对照)",
        lambda w, o, e: _decision(o, "third_own_read")[0] is True)
    add("cross_tenant_deny",
        "旧凭证越界访问第三租户 -> TENANT_MISMATCH",
        lambda w, o, e: _decision(o, "cross_oldcred_to_third")[1]
        == DENY_TENANT_MISMATCH)
    add("resource_binding_deny",
        "凭证绑定资源, 换资源 -> RESOURCE_BINDING",
        lambda w, o, e: _decision(o, "resource_bind")[1]
        == DENY_RESOURCE_BINDING)
    add("purpose_binding_deny",
        "凭证绑定用途, 换用途 -> PURPOSE_BINDING",
        lambda w, o, e: _decision(o, "purpose_bind")[1]
        == DENY_PURPOSE_BINDING)
    add("wrong_org_confirm_rejected",
        "第三组织实际控制人确认旧侧 -> 拒绝(WRONG_ORG)",
        lambda w, o, e: _has_cmd(e, "confirm", False) is not None)
    add("commit_requires_dual",
        "无双重确认直接承诺 -> 拒绝 DUAL_CONFIRMATION",
        lambda w, o, e: _has_cmd(e, "commit", False,
                                 REJECT_DUAL_CONFIRMATION) is not None)
    add("single_confirm_commit_rejected",
        "仅旧侧一名控制人, 承诺仍被拒",
        lambda w, o, e: (o["facts"]["old_conf"]
                         and not o["facts"]["new_conf"]
                         and _has_cmd(e, "commit", False) is not None))
    add("revoke_denies_old",
        "旧组织回收落盘后 -> DENY_REVOKED",
        lambda w, o, e: (o["facts"]["old_revoke_seq"] is not None
                         and _decision(o, "old_read")[1] == DENY_REVOKED))
    add("late_witness_stale",
        "边界一: 已回收后旧见证迟到 -> LATE_WITNESS_STALE 且仍拒绝",
        lambda w, o, e: _decision(o, "old_read")[1]
        == DENY_LATE_WITNESS_STALE)
    add("witness_before_revoke",
        "见证先于回收落盘时, 回收序号在后 -> 回收有效 DENY_REVOKED",
        lambda w, o, e: (_decision(o, "old_read")[1] == DENY_REVOKED
                         and len(e.state.witnesses) >= 1))
    add("delegation_break",
        "多层委托中间边被回收 -> 委托链断裂 DENY_DELEGATION_BROKEN",
        lambda w, o, e: _decision(o, "old_read")[1]
        == DENY_DELEGATION_BROKEN)
    add("post_requires_commit",
        "新组织未获承诺即入账 -> 拒绝 NOT_COMMITTED",
        lambda w, o, e: _has_cmd(e, "post_new", False,
                                 DENY_NOT_COMMITTED) is not None)
    add("dual_confirm_commit",
        "旧+新各一名实际控制人 -> 承诺落盘",
        lambda w, o, e: o["facts"]["commit_seq"] is not None
        and _has_cmd(e, "commit", True) is not None)
    add("crash_recover_completes",
        "边界二: 已承诺但写回执前中断, 重启按落盘序号恢复并完成",
        lambda w, o, e: ("cr" in w
                         and _decision(o, "new_read")[0] is True
                         and o["facts"]["receipt"] is True))
    add("happy_explicit_completed",
        "显式 双确认->承诺->回收->入账: 新 ALLOW/旧 DENY/回执",
        lambda w, o, e: ("cr" not in w
                         and _decision(o, "new_read")[0] is True
                         and o["facts"]["receipt"] is True))
    return T


def _evidence_for(key: str, obs: dict[str, Any],
                  eng: GateEngine) -> dict[str, Any]:
    """Pull a compact, serializable decision evidence package."""
    pid_by_key = {
        "baseline_old_allow": "old_read",
        "revoke_denies_old": "old_read",
        "late_witness_stale": "old_read",
        "witness_before_revoke": "old_read",
        "delegation_break": "old_read",
        "happy_explicit_completed": "new_read",
        "crash_recover_completes": "new_read",
        "cross_tenant_deny": "cross_oldcred_to_third",
        "resource_binding_deny": "resource_bind",
        "purpose_binding_deny": "purpose_bind",
        "third_canary_allow": "third_own_read",
    }
    out: dict[str, Any] = {"facts": obs["facts"]}
    pid = pid_by_key.get(key)
    if pid:
        req = dict(standard_probes())[pid]
        d = eng.authorize(req)
        out["decision"] = d.to_dict()
    # Include the decisive command result where relevant.
    for cmd in ("commit", "confirm", "post_new", "revoke_old"):
        r = _has_cmd(eng, cmd)
        if r:
            out.setdefault("command_results", []).append(r)
    return out


def run_exhaustive(max_len: int = MAX_LEN,
                   topo: Topology | None = None,
                   verbose: bool = False) -> dict[str, Any]:
    topo = topo or standard_topology()
    probes = standard_probes()
    targets = build_targets()
    found: dict[str, dict[str, Any]] = {}
    mismatches: list[dict[str, Any]] = []
    invariant_violations: list[dict[str, Any]] = []
    words_checked = 0

    for length in range(0, max_len + 1):
        for word in itertools.product(ALPHABET, repeat=length):
            words_checked += 1
            eng, store, receipts = run_word(word, topo, probes)
            obs = engine_observation(eng, probes)

            # Differential against independent oracle replaying physical seqs.
            ora = Oracle.replay_events(topo, eng.log.events())
            oobs = ora.observation(probes)
            if oobs != obs:
                mismatches.append({
                    "word": word,
                    "engine": obs,
                    "oracle": oobs,
                })
                if len(mismatches) >= 5:
                    break

            # Universal invariants.
            viols = check_invariants(word, obs, eng)
            if viols:
                invariant_violations.append(
                    {"word": word, "violations": viols})
                if len(invariant_violations) >= 5:
                    break

            # Record shortest evidence (ascending length + lexicographic).
            for key, _claim, pred in targets:
                if key in found:
                    continue
                try:
                    ok = pred(word, obs, eng)
                except Exception as exc:  # pragma: no cover
                    ok = False
                    viols = [f"predicate error: {exc!r}"]
                    invariant_violations.append(
                        {"word": word, "violations": viols})
                if ok:
                    found[key] = {
                        "length": length,
                        "word": list(word),
                        "symbols": [SYMBOL_DESCRIPTION[s] for s in word],
                        "evidence": _evidence_for(key, obs, eng),
                    }

            # Physical-line recovery check for EVERY word: a brand-new engine
            # re-parses + verifies the shared physical line store.  The more
            # expensive post-recovery differential / idempotence observation is
            # only material for words that actually reached a commit/restart.
            eng2 = GateEngine.create_memory(
                topo, shared_store=store, receipts=receipts)  # type: ignore[arg-type]
            needs_closure = (obs["facts"]["commit_seq"] is not None
                             or "cr" in word)
            if needs_closure:
                obs2 = engine_observation(eng2, probes)
                ora2 = Oracle.replay_events(topo, eng2.log.events())
                if ora2.observation(probes) != obs2:
                    mismatches.append(
                        {"word": word + ("<recover>",),
                         "kind": "post-recovery oracle mismatch"})
                    if len(mismatches) >= 5:
                        break
                seq_after_reopen = eng2.log.last_seq()
                eng2.complete_pending()
                if eng2.log.last_seq() != seq_after_reopen:
                    invariant_violations.append({
                        "word": word,
                        "violations": ["completion was not idempotent "
                                       "(appended duplicate effects)"],
                    })
                # Observation after idempotent completion must be stable.
                obs3 = engine_observation(eng2, probes)
                if obs3 != obs2:
                    invariant_violations.append({
                        "word": word,
                        "violations": ["observation changed by idempotent "
                                       "complete_pending()"],
                    })

        if mismatches or invariant_violations:
            # Stop at first bad length; report it.
            break
        if verbose:
            print(f"  exhaustive length<={length}: {words_checked} words OK")

    missing = [key for key, _, _ in targets if key not in found]
    return {
        "max_len": max_len,
        "alphabet": list(ALPHABET),
        "words_checked": words_checked,
        "targets": [{"key": k, "claim": c, **(found.get(k) or {
            "length": None, "word": None})} for k, c, _ in targets],
        "shortest_evidence": {k: found[k] for k in found},
        "missing_targets": missing,
        "oracle_mismatches": mismatches,
        "invariant_violations": invariant_violations,
        "ok": not mismatches and not invariant_violations and not missing,
    }
