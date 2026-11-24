# 多组织授权接续的双阶段撤销审计（离线迁移闸门）

外包人员从旧组织调到新组织。本仓库用 **Windows + Python 3.12 标准库**、纯本地
合成数据，实现一个离线**迁移闸门（migration gate）**，重现迁移前后允许访问的
差异，并对两条关键边界、并发安全、短序列完备性和大规模爆炸半径给出可复跑证据。

> 题面（冻结）见 [`task/PROMPT.txt`](task/PROMPT.txt)。
> 一键验证：`py -3.12 run_all.py`（约数分钟，穷举深度 5 + 64000 事件）。
> 快速冒烟：`py -3.12 run_all.py --quick`。
> 仅单元测试：`py -3.12 -m unittest discover -s tests -t . -v`。
>
> 运行后生成 **`REPORT.md`**（真实数字）与
> `artifacts/verification_report.json`（机器可读全量结果），真盘 JSONL 日志与
> 原子回执在 `artifacts/` 下。全绿时末行打印 `ALL_CHECKS_PASS`，进程退出码 0。

## 题面要素如何落地

| 题面要素 | 设计 |
|---|---|
| 旧、新组织各一名**实际控制人**确认 | `Topology.orgs[*].actual_controllers` 自然人名册；`confirm` 校验确认人是**该侧组织**的实际控制人，第三组织控制人/无关者被拒；同一自然人不能同时填两侧（职责分离） |
| 授权边可**多层委托** | `Edge(grantor→grantee, resid, purpose, gen, may_delegate)`；`find_chain` 从该组织实际控制人出发 BFS 到主体，支持任意深度；中间边被撤销则链断 |
| 原凭证/替换凭证绑定**资源、用途、授权代** | `Credential(resid, purpose, gen)`；`authorize` 依次强校验属主→租户→资源→用途→授权代下限→回收/见证→迁移状态→委托链 |
| 回收/确认/入账以**真正落盘序号**定有效 | 哈希链 JSONL（`durable.py`），seq 是记录 `fsync` 落盘后的物理行序；启动从盘上重放，校验 seq 连续与哈希链，容忍并截断末尾撕裂行；客户端自带 seq/时间戳不参与判定 |
| 边界一：已回收但**旧见证迟到** | 回收是该 `(凭证, 授权代)` 的终态；迟到见证 seq 更大也只作审计证据，判 `DENY_LATE_WITNESS_STALE`，绝不恢复访问 |
| 边界二：**已承诺但写回执前中断** | `commit` 先 fsync 形成线性化点；回执用临时文件 + `os.replace` 原子写。重启重放见 committed 缺回执即幂等补完“旧回收→新入账→回执”，效果恰好一次 |
| 两工作线程 + 屏障 | `concurrency.py`：2 个 `threading.Thread` + `Barrier(2)`，含“先回收后见证”的确定性双屏障时序、20 轮自由竞争、400 次/线程租户互串压测；每轮**关盘后从真盘重开恢复**断言 |
| 短事件序列**独立穷举** + 最短决策证据 | `oracle.py` 是不依赖引擎 fold/链代码的独立集合/关系参照；`exhaustive.py` 对 9 个事件符号长度 0–5 的全部 **66430** 个序列做引擎↔Oracle 差分 + 通用不变量 + 每序列重开恢复，并按“长度升序+字典序”给出每个决策的最短证据 |
| ≥60000 多组织事件 + 单控制变更不触达无关组织 + 实际触达 + 全量对照 | `synthetic.py`：16 组织×4 层×3 叉（1296 主体）；**64000** 条确定性多组织事件落真盘；22032 格全矩阵引擎↔Oracle 对照；对每条组织委托边做一次“单变更”的全矩阵前后 diff，实际变化集与结构世系预测逐格相等，触达组织恒为 `{该组织}` |

## 目录

```
run_all.py                 一键全量验证并生成 REPORT.md
solution.py                等价入口（python solution.py [--quick]）
migration_gate/
  model.py                 词汇表、原因码、Credential/Edge/Decision
  durable.py               哈希链 JSONL：物理 seq / fsync / 恢复 / 撕裂尾
  topology.py              三租户标准场景 + 实际控制人/资源常量
  engine.py                事件溯源闸门：fold、双重确认、链、授权、恢复、回执
  oracle.py                独立参照语义（差分测试/全量对照）
  exhaustive.py            短序列穷举 + 最短决策证据
  concurrency.py           两线程 + Barrier 证明
  diskproof.py             最短证据上真盘 + 两条关键边界的崩溃注入
  synthetic.py             16 组织世界 / 64000 事件 / 爆炸半径 / 全矩阵
  report.py                REPORT.md 渲染器
tests/test_gate.py         stdlib unittest（不含 60k 重负载，可快速跑）
task/PROMPT.txt            冻结题面
```

## 核心判定顺序（两份实现共同遵守的规范）

对 `(主体, 资源, 用途, 可选凭证 id)`：

1. 资源是否注册；2. 解析绑定凭证；3. 凭证属主；4. **凭证租户 == 资源所有租户**
（不可跨越的租户边界）；5. 资源绑定；6. 用途绑定；7. 授权代下限；
8. 终态回收 vs 迟到见证（按物理 seq）；9. 替换凭证须有 committed + 入账 seq；
10. 实际控制人→主体的有效多层委托链。任一失败给出稳定原因码与含决定性 seq 的证据。

## 离线/安全说明

- 仅用标准库；无网络、无第三方包。合成身份均为虚构。
- `artifacts/` 已在 `.gitignore` 中，是可反复删除重建的输出目录。
- 不使用真实密钥；“签名/实际控制人确认”以本地合成名册与哈希链完整性建模。
