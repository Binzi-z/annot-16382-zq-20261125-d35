"""Render the verification result as a human-readable Markdown report."""

from __future__ import annotations

from typing import Any


def _yn(v: bool) -> str:
    return "✅ PASS" if v else "❌ FAIL"


def _err(section: dict[str, Any] | None) -> str | None:
    if isinstance(section, dict) and section.get("error"):
        return str(section["error"])
    return None


def render_markdown(r: dict[str, Any]) -> str:
    L: list[str] = []
    meta = r.get("meta", {})
    overall = r.get("overall_pass", False)
    L.append("# 多组织授权迁移闸门 — 验证报告")
    L.append("")
    L.append(f"**总体结果：{_yn(overall)}**")
    L.append("")
    L.append(
        "离线、仅使用 Python 3.12 标准库的跨组织外包人员授权迁移闸门。"
        "所有关键结论均由 `python run_all.py` 实际运行生成。")
    L.append("")
    L.append("## 0. 运行环境")
    L.append("")
    L.append(f"- Python：`{meta.get('python')}`")
    L.append(f"- 平台：`{meta.get('platform')}`")
    L.append(f"- 工作目录：`{meta.get('cwd')}`")
    L.append(f"- 生成时间：`{meta.get('generated_at')}`")
    L.append(f"- 总耗时：`{meta.get('duration_s')}s`")
    if meta.get("argv"):
        L.append(f"- 参数：`{' '.join(meta['argv'])}`")
    L.append("")

    # ---- Requirements traceability ---------------------------------------
    L.append("## 1. 题面要求 → 实现/证据 对照")
    L.append("")
    L.append("| 题面要求 | 实现位置 | 证据 |")
    L.append("|---|---|---|")
    trace = [
        ("Windows + Python3.12 标准库 + 离线合成数据",
         "`migration_gate/`（仅 stdlib），`run_all.py`",
         "本报告第 0/6 节，单元测试"),
        ("迁移凭证由旧、新组织各一名实际控制人确认",
         "`engine.py: confirm`（实际控制人名册 + 同人禁止）",
         "穷举 `dual_confirm_commit`；`TestDualControl`"),
        ("授权边可多层委托",
         "`engine.py: find_chain`（控制器为根的任意深度链）",
         "3 跳标准链；`delegation_break`；16 组织×4 层树"),
        ("原凭证/替换凭证绑定资源、用途、授权代",
         "`model.Credential(resid,purpose,gen)` + `authorize` 逐项校验",
         "`resource/purpose_binding_deny`；`generation_fence` 测试"),
        ("回收/确认/入账以真正落盘序号决定有效",
         "`durable.py` 哈希链 JSONL，seq 为物理行序，重放恢复",
         "第 3 节磁盘证据；篡改/断尾测试"),
        ("边界一：已回收但旧见证迟到",
         "seq + 授权代终态回收，迟到见证判 STALE 且不恢复",
         "`late_witness_stale`；第 4 节；双线程屏障"),
        ("边界二：已承诺但写回执前中断",
         "commit 先 fsync；回执原子写；重启幂等补完",
         "`crash_recover_completes`；commit/receipt 两窗口"),
        ("两工作线程 + 屏障：回收不丢失、租户不串用",
         "`concurrency.py`（2 Thread + Barrier(2)，落盘恢复）",
         "第 5 节"),
        ("短事件序列独立穷举 + 最短决策证据",
         "`oracle.py` 独立参照 + `exhaustive.py` 全词穷举",
         "第 2 节"),
        ("≥60000 多组织事件；单控制关系变更不触达无关组织；"
         "报告实际触达 + 全量对照",
         "`synthetic.py`（64000 事件 + 全矩阵前后对照 + 世系比对）",
         "第 6 节"),
    ]
    for a, b, c in trace:
        L.append(f"| {a} | {b} | {c} |")
    L.append("")

    # ---- Exhaustive -------------------------------------------------------
    ex = r.get("exhaustive") or {}
    L.append("## 2. 短事件序列独立穷举与最短决策证据")
    L.append("")
    e = _err(ex)
    if e:
        L += ["**本节运行异常：**", "```", e, "```", ""]
    else:
        L.append(
            f"字母表 {len(ex.get('alphabet', []))} 个事件，最大长度 "
            f"{ex.get('max_len')}；按长度递增、字典序穷举 "
            f"**{ex.get('words_checked')}** 个事件序列（每个序列还做一次"
            f"共享物理行存储的重开恢复 + 幂等补完校验）。每个序列都与"
            f"**不 import 引擎 fold/链代码的第二实现 `Oracle`** 重放物理 seq "
            f"的观察结果逐项对照，并用第三种算法（权威级单调不动点）交叉校验"
            f"每条 ALLOW / DELEGATION_BROKEN，同时检查通用安全不变量。")
        L.append("")
        L.append(f"- 引擎/Oracle 不一致：`{len(ex.get('oracle_mismatches', []))}`")
        L.append(f"- 不变量违背：`{len(ex.get('invariant_violations', []))}`")
        L.append(f"- 缺失目标：`{ex.get('missing_targets')}`")
        L.append(f"- 穷举结论：**{_yn(bool(ex.get('ok')))}**")
        L.append("")
        L.append("| 决策证据 | 最短长度 | 最短事件序列 | 最终判定 | 关键落盘 seq |")
        L.append("|---|---:|---|---|---|")
        for t in ex.get("targets", []):
            if t.get("length") is None:
                L.append(f"| {t['claim']} | – | 未找到 | | |")
                continue
            word = " → ".join(t.get("word") or []) or "（空序列，初始态）"
            ev = t.get("evidence") or {}
            dec = ev.get("decision") or {}
            verdict = f"{dec.get('code','')}" if dec else "（命令型证据）"
            facts = ev.get("facts") or {}
            seqbits = []
            for k in ("commit_seq", "old_revoke_seq", "new_post_seq"):
                if facts.get(k) is not None:
                    seqbits.append(f"{k}={facts[k]}")
            L.append(
                f"| {t['claim']} | {t['length']} | `{word}` | "
                f"`{verdict}` | {', '.join(seqbits)} |")
        L.append("")
        if ex.get("oracle_mismatches"):
            L.append("### 首个不一致")
            L.append("```json")
            L.append(__import__("json").dumps(
                ex["oracle_mismatches"][0], ensure_ascii=False, default=str)
                [:3000])
            L.append("```")
        if ex.get("invariant_violations"):
            L.append("### 首个不变量违背")
            L.append("```json")
            L.append(__import__("json").dumps(
                ex["invariant_violations"][0], ensure_ascii=False, default=str)
                [:2000])
            L.append("```")
        L.append("")

    # ---- Disk proofs ------------------------------------------------------
    dp = r.get("disk_proofs") or {}
    L.append("## 3/4. 真盘序号证据与两处关键边界")
    L.append("")
    e = _err(dp)
    if e:
        L += ["**本节运行异常：**", "```", e, "```", ""]
    else:
        L.append(f"磁盘证据与 Oracle 全一致："
                 f"**{_yn(bool(dp.get('shortest_evidence_oracle_match')))}**")
        lw = dp.get("boundary_late_witness", {})
        L.append("")
        L.append("### 边界一：旧授权已回收，旧见证迟到")
        L.append("")
        L.append(f"- 回收物理 seq：`{lw.get('revoke_effective_seq')}`；"
                 f"迟到见证 seq：`{lw.get('witness_seq')}`")
        L.append(f"- 重启恢复后判定：`{lw.get('recovered_code')}` "
                 f"(allow={lw.get('recovered_allow')})")
        L.append(f"- 结论：**{_yn(bool(lw.get('pass')))}**")
        cb = dp.get("boundary_commit_before_receipt", {})
        L.append("")
        L.append("### 边界二 A：已承诺，写回执前中断")
        L.append("")
        L.append(f"- 注入崩溃点：`{cb.get('crash_point')}`；"
                 f"commit 物理 seq：`{cb.get('committed_physical_seq')}`")
        L.append(f"- 崩溃后立即检查回执存在："
                 f"`{cb.get('receipt_present_immediately_after_crash')}`（应为 False）")
        L.append(f"- 重启后：旧 `{cb.get('recovered_old_code')}` / "
                 f"新 `{cb.get('recovered_new_code')}`；"
                 f"回执已补：`{cb.get('receipt') is not None}`；"
                 f"补完幂等不新增 seq：`{cb.get('completion_idempotent_no_new_seq')}`")
        L.append(f"- 结论：**{_yn(bool(cb.get('pass')))}**")
        rw = dp.get("boundary_receipt_window", {})
        L.append("")
        L.append("### 边界二 B：效果已落盘，回执原子替换前的窄窗口中断")
        L.append("")
        L.append(f"- 崩溃点：`{rw.get('crash_point')}`；"
                 f"崩溃时 seq=`{rw.get('seq_at_crash')}`，"
                 f"重开后 seq=`{rw.get('seq_after_reopen')}`（应相等=无重复效果）")
        L.append(f"- 有效回收数=`{rw.get('accepted_revoke_effects')}`，"
                 f"有效入账数=`{rw.get('accepted_post_effects')}`（均应为 1）；"
                 f"恢复后写回执=`{rw.get('receipt_written_on_recovery')}`")
        L.append(f"- 结论：**{_yn(bool(rw.get('pass')))}**")
        L.append("")

    # ---- Concurrency ------------------------------------------------------
    cc = r.get("concurrency") or {}
    L.append("## 5. 两工作线程 + 屏障")
    L.append("")
    e = _err(cc)
    if e:
        L += ["**本节运行异常：**", "```", e, "```", ""]
    else:
        rv = cc.get("revocation", {})
        fr = rv.get("free_race", {})
        det = rv.get("deterministic_late_order", {})
        early = rv.get("deterministic_witness_first", {})
        tn = cc.get("tenancy", {})
        L.append("### 5.1 回收不丢失")
        L.append("")
        L.append(f"- 确定性屏障时序 A（先回收后见证）："
                 f"revoke_seq=`{det.get('revoke_seq')}` < "
                 f"witness_seq=`{det.get('witness_seq')}` → "
                 f"恢复判定 `{det.get('recovered_code')}`；"
                 f"**{_yn(bool(det.get('pass')))}**")
        L.append(f"- 确定性屏障时序 B（先见证后回收）："
                 f"witness_seq=`{early.get('witness_seq')}` < "
                 f"revoke_seq=`{early.get('revoke_seq')}` → "
                 f"恢复判定 `{early.get('recovered_code')}`；"
                 f"**{_yn(bool(early.get('pass')))}**")
        L.append(f"- 自由竞争 `Barrier(2)` 轮数：`{fr.get('rounds')}`；"
                 f"其中回收在前(迟到见证) `{fr.get('revoke_first_late_witness')}`，"
                 f"见证在前 `{fr.get('witness_first_then_revoke')}`")
        L.append(f"- 每轮均从真盘重开恢复并拒绝、且回收效果恰好一条："
                 f"**{_yn(bool(fr.get('all_recovered_and_denied')))}**")
        L.append("")
        L.append("### 5.2 租户不串用可见授权")
        L.append("")
        L.append(f"- 每租户工作线程迭代：`{tn.get('iterations_per_thread')}`，"
                 f"工作线程数：`{tn.get('worker_threads')}`；`{tn.get('barrier')}`")
        L.append(f"- 本租户合法访问 ALLOW：`{tn.get('own_access_allow')}/"
                 f"{tn.get('own_access_expected')}`")
        L.append(f"- 跨租户尝试被判 TENANT_MISMATCH："
                 f"`{tn.get('cross_attempts_denied_tenant_mismatch')}`；"
                 f"跨租户 ALLOW：`{tn.get('cross_allowed')}`")
        L.append(f"- 可见集精确匹配不符次数：`{tn.get('visibility_leaks')}`"
                 f"（逐次断言可见集恰为本租户那一张凭证，非恒真过滤）；"
                 f"落盘恢复后可见集不相交："
                 f"`{tn.get('visible_sets_disjoint_on_disk_recovery')}`，"
                 f"且精确等于 OLD=[cred-old-0001] / "
                 f"THIRD=[cred-third-0001] / NEW=[]："
                 f"`{tn.get('visible_sets_exact_on_disk_recovery')}`")
        L.append(f"- 双线程合计 durable 事件：`{tn.get('total_durable_log_events')}`")
        L.append(f"- 结论：**{_yn(bool(tn.get('pass')))}**")
        if cc.get("errors") or rv.get("errors") or tn.get("errors"):
            L.append("")
            L.append("错误：")
            L.append("```json")
            L.append(__import__("json").dumps(
                {"cc": cc.get("errors"), "rv": rv.get("errors"),
                 "tn": tn.get("errors")}, ensure_ascii=False, default=str)[:2000])
            L.append("```")
        L.append("")

    # ---- Synthetic --------------------------------------------------------
    sy = r.get("synthetic") or {}
    L.append("## 6. 60k+ 多组织合成事件与实际触达范围 / 全量对照")
    L.append("")
    e = _err(sy)
    if e:
        L += ["**本节运行异常：**", "```", e, "```", ""]
    else:
        br = sy.get("blast_radius", {})
        st = sy.get("scale_stream", {})
        hero = br.get("hero_change") or {}
        L.append("### 6.1 单个控制关系变更的爆炸半径（全矩阵前后对照）")
        L.append("")
        L.append(f"- 组织数：`{br.get('organizations')}`；"
                 f"委托深度：`{br.get('delegation_depth')}`；"
                 f"分支：`{br.get('branching_factor')}`；"
                 f"每组织叶子：`{br.get('leaves_per_org')}`；"
                 f"主体总数：`{br.get('total_subjects')}`")
        L.append(f"- 全量决策矩阵单元（主体 × 组织 + 用途）："
                 f"`{br.get('full_matrix_cells')}`")
        L.append(f"- 英雄变更：`{hero.get('edge_id')}` "
                 f"({hero.get('edge_from')} → {hero.get('edge_to')})，"
                 f"变更 seq=`{hero.get('change_seq')}`")
        L.append(f"- 结构世系预测受影响叶子：`{hero.get('predicted_leaves')}`")
        L.append(f"- **实际发生判定变化的单元：`{hero.get('actual_changed_cells')}`**；"
                 f"未变化单元：`{hero.get('unchanged_cells')}`")
        L.append(f"- **实际触达组织：`{hero.get('affected_orgs')}`** "
                 f"（必须且仅有变更边所属组织）")
        L.append(f"- 实际触达 == 结构世系："
                 f"`{hero.get('matches_structural_lineage')}`；"
                 f"仅触达本组织：`{hero.get('only_own_org')}`")
        L.append(f"- 英雄变更前后 Oracle 全矩阵不一致数："
                 f"`{hero.get('oracle_matrix_mismatches_before')}` / "
                 f"`{hero.get('oracle_matrix_mismatches_after_hero_change')}`")
        L.append("")
        L.append("各组织各做一次单变更的触达单元数（全 16 组织扫描）：")
        L.append("")
        L.append("| 组织 | 变更边 | 预测叶子 | 实际变化单元 | 仅本组织 | 世系一致 |")
        L.append("|---|---|---:|---:|:---:|:---:|")
        for row in br.get("every_org_single_change_sweep", []):
            L.append(
                f"| {row['org']} | `{row['edge_id']}` | "
                f"{row['predicted_leaves']} | {row['actual_changed_cells']} | "
                f"{'✅' if row['only_own_org'] else '❌'} | "
                f"{'✅' if row['matches_structural_lineage'] else '❌'} |")
        L.append("")
        L.append(f"扫描中完全隔离的组织数：`{br.get('sweep_orgs_confined')}"
                 f"/{br.get('organizations')}`；结论："
                 f"**{_yn(bool(br.get('pass')))}**")
        L.append("")
        L.append("### 6.2 ≥60000 条多组织合成事件全量对照")
        L.append("")
        L.append(f"- 随机种子：`{st.get('seed')}`")
        L.append(f"- 运行期合成事件：**`{st.get('runtime_synthetic_events')}`** "
                 f"（要求 ≥ 60000）")
        L.append(f"- 含引导的 durable 记录总数："
                 f"`{st.get('total_durable_records_including_bootstrap')}`；"
                 f"关盘后读回：`{st.get('recovered_records_from_disk')}`")
        L.append(f"- 事件类型计数：`{st.get('events_by_kind')}`")
        L.append(f"- 每组织事件数 min/max：`{st.get('min_org_events')}/"
                 f"{st.get('max_org_events')}`（16 组织均被触达）")
        L.append(f"- 跨租户探测被 TENANT_MISMATCH 拦截："
                 f"`{st.get('cross_tenant_probes_blocked')}`；"
                 f"意外放行/异码：`{st.get('cross_tenant_probes_unexpected')}`")
        L.append(f"- 全量矩阵对照单元：`{st.get('full_matrix_cells_compared')}`；"
                 f"引擎/Oracle 不一致：`{st.get('engine_oracle_matrix_mismatches')}`")
        L.append(f"- 状态计数一致：`{st.get('state_counts_match')}`")
        L.append(f"- 结论：**{_yn(bool(st.get('pass')))}**")
        if st.get("matrix_mismatch_examples"):
            L.append(f"- 不一致样例：`{st['matrix_mismatch_examples']}`")
        L.append("")

    # ---- Unit tests -------------------------------------------------------
    ut = r.get("unit_tests") or {}
    L.append("## 7. 单元测试")
    L.append("")
    if ut.get("error"):
        L += ["**测试套件运行异常：**", "```", str(ut["error"]), "```", ""]
    else:
        L.append(f"- 运行：`{ut.get('run')}`；失败：`{ut.get('failures')}`；"
                 f"错误：`{ut.get('errors')}`；跳过：`{ut.get('skipped')}`")
        L.append(f"- 结论：**{_yn(bool(ut.get('success')))}**")
        if ut.get("output_tail"):
            L.append("")
            L.append("<details><summary>测试输出尾部</summary>")
            L.append("")
            L.append("```")
            L.append(ut["output_tail"][-3000:])
            L.append("```")
            L.append("")
            L.append("</details>")
        L.append("")

    L.append("## 8. 复现方式")
    L.append("")
    L.append("```bat")
    L.append("py -3.12 run_all.py")
    L.append("REM 快速冒烟（较小穷举深度/并发/事件量，不满足 60000 全量要求）")
    L.append("py -3.12 run_all.py --quick")
    L.append("REM 仅单元测试")
    L.append("py -3.12 -m unittest discover -s tests -t . -v")
    L.append("```")
    L.append("")
    L.append("机器可读完整结果：`artifacts/verification_report.json`；"
             "真盘日志/回执/屏障现场位于 `artifacts/` 下。")
    L.append("")
    return "\n".join(L)
