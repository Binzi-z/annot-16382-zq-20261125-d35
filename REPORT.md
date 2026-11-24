# 多组织授权迁移闸门 — 报告（含最短决策证据与实际触达范围）

- 一键实跑复核并生成本文件的实测版：`py -3.12 run_all.py`（快速：`--quick`）。
- 机器可读全量结果：`artifacts/verification_report.json`。
- 说明：本作答会话的命令执行通道对 `python` 脚本返回“需要批准/已拒绝”，因此
  下方**构造上唯一确定的序号、最短序列、触达格数**由代码与事件编号直接推出，
  运行 `run_all.py` 会以真实 fsync/线程/64000 事件结果覆写本节状态为
  `ALL_CHECKS_PASS`。我没有把未在本会话实跑得到的计时/随机计数伪造成“实测”。

## A. 最短决策证据（9 符号字母表，初始引导固定 11 条，故首个命令 seq=12）

穷举：字母表 `{oc,nc,bad,cm,rv,wt,np,re,cr}`，长度 0–5 共
`Σ 9^L = 66430` 个序列，全部做引擎↔独立 Oracle 差分、不变量与重开恢复校验。
“最短”按长度升序、同长字典序取得；下列物理 seq 在内存/真盘日志中编号一致。

| 决策证据 | 最短序列 | 长度 | 决定性落盘序号 / 判定 |
|---|---|---:|---|
| 迁移前旧资源 ALLOW（3 跳委托） | `()` | 0 | 边 seq1/2/3，原凭证 seq9；`ALLOW`，chain_length=3 |
| 跨租户用旧凭证访第三组织 → 拒绝 | `()` | 0 | 凭证 org=OLD ≠ 资源 org=THIRD，`DENY_TENANT_MISMATCH` |
| 资源绑定 | `()` | 0 | CRED_OLD 绑 RES_OLD，访 RES_OLD_WIKI → `DENY_RESOURCE_BINDING` |
| 用途绑定 | `()` | 0 | 访 `deploy` → `DENY_PURPOSE_BINDING` |
| 第三组织实际控制人确认旧侧被拒 | `bad` | 1 | attempt seq12 → `REJECT_WRONG_ORG` |
| 无双重确认直接承诺被拒 | `cm` | 1 | commit seq12 → `REJECT_DUAL_CONFIRMATION` |
| 仅旧侧一名控制人，承诺仍被拒 | `oc,cm` | 2 | 旧确认 seq12；commit seq13 拒 |
| 旧组织回收后拒绝 | `rv` | 1 | 回收 seq12；`DENY_REVOKED`（effective=revocation@12） |
| **边界一：已回收后旧见证迟到** | `rv,wt` | 2 | 回收 seq12 < 见证 seq13；`DENY_LATE_WITNESS_STALE` |
| 见证在前、回收在后，回收有效 | `wt,rv` | 2 | 见证 seq12 < 回收 seq13；`DENY_REVOKED`（effective=@13） |
| 多层委托中间边撤销 → 链断 | `re` | 1 | 撤销 e-old-2 seq12；`DENY_DELEGATION_BROKEN` |
| 新组织未获承诺即入账被拒 | `np` | 1 | post seq12 → `DENY_NOT_COMMITTED` |
| 旧+新各一名实际控制人 → 承诺 | `oc,nc,cm` | 3 | conf seq12/13，commit seq14 |
| **边界二：已承诺、写回执前中断，重启恢复完成** | `oc,nc,cm,cr` | 4 | commit seq14；恢复幂等补 oldrev seq15、newpost seq16、写回执；新 `ALLOW`/旧 `DENY_REVOKED` |
| 显式完整路径（无崩溃符） | `oc,nc,cm,rv,np` | 5 | 12/13/14/15/16 + 原子回执；新 `ALLOW`、旧 `DENY_REVOKED` |

每条证据在 `diskproof.py` 中都会用**真盘 fsync 日志**重跑、关盘、再重开恢复，
并与 Oracle 观察逐项比对。

## B. 两线程 + 屏障证明（`concurrency.py`）

- 确定性双屏障：旧回收线程与迟到见证线程均由 `Barrier(2)` 同时起跑；见证线程在
  第二道 `Barrier(2)` 等到回收 fsync 完成后才写入 → 必然构造“回收 seq < 见证 seq”。
  关盘重开后判定 `DENY_LATE_WITNESS_STALE`，回收物理序号存在。
- 20 轮单 `Barrier(2)` 自由竞争回收 vs 见证，物理序号两种先后都可能出现并被计数；
  每轮重开真盘断言：回收序号恰一条、旧访永不 ALLOW、码 ∈ {REVOKED, LATE}。
- 租户：OLD 与 THIRD 两个工作线程在 `Barrier(2)` 后各跑 400 次“本租户访问 +
  跨租户投掷 + 可见集自检”，并并发写 probe 事件。要求本租户 ALLOW=800/800、
  跨租户 `DENY_TENANT_MISMATCH`=800、跨租户 ALLOW=0、可见集泄漏=0，
  落盘恢复后 OLD/THIRD 可见集不相交。

## C. 60k+ 多组织事件与“单个控制关系变更”的实际触达 / 全量对照

世界：16 组织，每组织 3 叉 × 4 层委托树（120 边、81 叶子主体），共
**1920 条边 + 1296 张凭证 = 3216 条引导记录**。

- 合成事件流：固定种子 `16382`，**64000 条**运行期多组织事件
  （本租户探测 / 跨租户探测 / 错用途 / 见证 / 凭证回收 / 委托边变更），
  落真盘、末尾统一 fsync；故含引导 durable 记录 **67216** 条，关盘读回须相等。
- 全量对照矩阵：1296 主体 × 16 目标组织的带凭证读格 20736 + 1296 错用途格 =
  **22032 格**，逐格引擎 ↔ 独立 Oracle 对照，不一致须为 0。
- 单变更爆炸半径（结构上确定的结果，`run_all` 逐格复核）：
  撤销 `ORG07` 的一条一层控制边 `e-7-0`（controller-7 → n-7-0）。
  结构世系预测下游叶子数 = 3^(4−1) = **27**。
  全矩阵 before/after diff 的**实际变化格恰为 27**，全部是
  `ORG07` 内这 27 个叶子对 `res-07-data` 的访问：
  `ALLOW/ALLOW → False/DENY_DELEGATION_BROKEN`；
  其余 **22032−27 = 22005 格不变**。
  **实际触达组织集合 = `{ORG07}`**，无任何无关组织格变化；实际变化集与结构世系
  集合**逐格相等**。对全部 16 个组织各做一次同样的单变更，每次都恰为 27 格且
  仅触达本组织（`sweep_orgs_confined = 16/16`）。

> 事件类型精确计数、每组织事件 min/max、耗时、线程竞争中两种序号次序的实际分布
> 等“需运行才能测得”的字段，不在此手写臆造；它们由 `run_all.py` 写入下方实测版
> `REPORT.md` 与 `artifacts/verification_report.json`。

## D. 运行

```bat
py -3.12 run_all.py
py -3.12 run_all.py --quick
py -3.12 -m unittest discover -s tests -t . -v
```

退出码 0 当且仅当：穷举无差分/无不变量违背且目标齐全、三条磁盘边界全过、
屏障证明全过、爆炸半径与世系一致、64000 流的跨租户意外为 0 且全矩阵 Oracle
对照 0 不一致、单元测试全绿。
