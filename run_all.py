"""Single-command offline verification for the migration gate.

    py -3.12 run_all.py            # full: depth-5 exhaustive + 64k events
    py -3.12 run_all.py --quick    # fast smoke (does not claim 60k)

Everything is standard library.  Writes:
  * REPORT.md                          human report with the real numbers
  * artifacts/verification_report.json full machine-readable result
  * artifacts/**                       real JSONL logs + atomic receipts
Exits 0 only when every check passes.
"""

from __future__ import annotations

import io
import json
import os
import platform
import shutil
import sys
import time
import traceback
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parent
sys.path.insert(0, str(ROOT))

from migration_gate.concurrency import run_concurrency_proof  # noqa: E402
from migration_gate.diskproof import run_disk_proofs  # noqa: E402
from migration_gate.exhaustive import run_exhaustive  # noqa: E402
from migration_gate.report import render_markdown  # noqa: E402
from migration_gate.synthetic import (  # noqa: E402
    RUNTIME_EVENTS,
    run_blast_radius,
    run_scale_stream,
)


def _guard(name, fn):
    try:
        return fn()
    except Exception:
        return {"error": traceback.format_exc(), "pass": False,
                "section": name}


def _run_unit_tests() -> dict:
    loader = unittest.TestLoader()
    suite = loader.loadTestsFromName("tests.test_gate")
    buf = io.StringIO()
    runner = unittest.TextTestRunner(stream=buf, verbosity=2)
    result = runner.run(suite)
    return {
        "run": result.testsRun,
        "failures": len(result.failures),
        "errors": len(result.errors),
        "skipped": len(result.skipped),
        "success": result.wasSuccessful(),
        "output_tail": buf.getvalue()[-6000:],
    }


def main(argv: list[str]) -> int:
    quick = "--quick" in argv
    started_wall = time.time()
    started = time.strftime("%Y-%m-%d %H:%M:%S")

    artifacts = ROOT / "artifacts"
    # artifacts/ is the git-ignored generated-output directory; clean only it.
    if artifacts.exists():
        shutil.rmtree(artifacts, ignore_errors=True)
    artifacts.mkdir(parents=True, exist_ok=True)

    print("== [1/5] exhaustive short-sequence search ==", flush=True)
    max_len = 4 if quick else 5
    exhaustive = _guard("exhaustive", lambda: run_exhaustive(max_len=max_len,
                                                             verbose=True))
    if quick and isinstance(exhaustive, dict) and "error" not in exhaustive:
        # Quick mode does not enumerate the length-5 happy path; judge only
        # differential + invariants for the depths actually covered.
        exhaustive["ok_full_claim"] = exhaustive["ok"]
        exhaustive["ok"] = (not exhaustive["oracle_mismatches"]
                           and not exhaustive["invariant_violations"])
        exhaustive["quick"] = True
    print(f"    words={exhaustive.get('words_checked')} "
          f"ok={exhaustive.get('ok')}", flush=True)

    print("== [2/5] real-disk shortest evidence + boundaries ==", flush=True)
    shortest = exhaustive.get("shortest_evidence", {}) \
        if isinstance(exhaustive, dict) else {}
    if quick and isinstance(shortest, dict):
        # Quick exhaustive depth is 4, so the length-5 explicit happy path is
        # not discovered there; supply its deterministic word so the real-disk
        # evidence section still covers every headline key non-vacuously.
        shortest.setdefault("happy_explicit_completed", {
            "length": 5, "word": ["oc", "nc", "cm", "rv", "np"]})
    disk = _guard("disk_proofs",
                  lambda: run_disk_proofs(str(artifacts), shortest))
    print(f"    pass={disk.get('pass')}", flush=True)

    print("== [3/5] two-thread + barrier proof ==", flush=True)
    if quick:
        concurrency = _guard("concurrency", lambda: run_concurrency_proof(
            str(artifacts), rounds=4, iterations=60))
    else:
        concurrency = _guard("concurrency",
                             lambda: run_concurrency_proof(str(artifacts)))
    print(f"    pass={concurrency.get('pass')}", flush=True)

    print("== [4/5] blast radius + 60k synthetic stream ==", flush=True)
    blast = _guard("blast_radius", run_blast_radius)
    n_events = 3000 if quick else RUNTIME_EVENTS
    stream = _guard("scale_stream",
                    lambda: run_scale_stream(str(artifacts), n_events))
    if quick and isinstance(stream, dict) and "error" not in stream:
        # The low-volume quick run is not a 60k claim; validate correctness
        # properties but do not fail on the volume threshold.
        stream["quick"] = True
        stream["pass"] = (
            stream["recovered_records_from_disk"]
            == stream["total_durable_records_including_bootstrap"]
            and stream["cross_tenant_probes_unexpected"] == 0
            and stream["cross_tenant_probes_blocked"]
            == stream["events_by_kind"]["cross_probe"]
            and stream["engine_oracle_matrix_mismatches"] == 0
            and stream["state_counts_match"]
        )
    synthetic = {
        "blast_radius": blast,
        "scale_stream": stream,
        "pass": bool(blast.get("pass") and stream.get("pass"))
        if isinstance(blast, dict) and isinstance(stream, dict) else False,
    }
    print(f"    blast={blast.get('pass')} stream={stream.get('pass')}",
          flush=True)

    print("== [5/5] unit tests ==", flush=True)
    unit_tests = _guard("unit_tests", _run_unit_tests)
    if isinstance(unit_tests, dict) and "error" in unit_tests:
        unit_tests = {"error": unit_tests["error"], "success": False}
    print(f"    success={unit_tests.get('success')} "
          f"run={unit_tests.get('run')}", flush=True)

    duration = round(time.time() - started_wall, 2)
    results = {
        "meta": {
            "python": sys.version.replace("\n", " "),
            "executable": sys.executable,
            "platform": platform.platform(),
            "cwd": os.getcwd(),
            "generated_at": started,
            "duration_s": duration,
            "argv": argv,
            "quick": quick,
        },
        "exhaustive": exhaustive,
        "disk_proofs": disk,
        "concurrency": concurrency,
        "synthetic": synthetic,
        "unit_tests": unit_tests,
    }
    results["overall_pass"] = all([
        bool(exhaustive.get("ok")) if isinstance(exhaustive, dict) else False,
        bool(disk.get("pass")) if isinstance(disk, dict) else False,
        bool(concurrency.get("pass"))
        if isinstance(concurrency, dict) else False,
        bool(synthetic.get("pass")),
        bool(unit_tests.get("success"))
        if isinstance(unit_tests, dict) else False,
    ])

    (artifacts / "verification_report.json").write_text(
        json.dumps(results, ensure_ascii=False, indent=2, default=str),
        encoding="utf-8")
    (ROOT / "REPORT.md").write_text(
        render_markdown(results), encoding="utf-8")

    print("", flush=True)
    print(f"report: {ROOT / 'REPORT.md'}", flush=True)
    print(f"json:   {artifacts / 'verification_report.json'}", flush=True)
    print(f"duration: {duration}s", flush=True)
    print("ALL_CHECKS_PASS" if results["overall_pass"]
          else "CHECKS_FAILED", flush=True)
    return 0 if results["overall_pass"] else 1


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
