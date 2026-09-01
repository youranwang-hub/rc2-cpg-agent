# 第一阶段设计与验收映射

主循环由 `AnalysisRunner` 编排：读取当前状态与固定查询 → 执行 → 持久化原始结果 → 确定性提取 T1 → 确定性裁定 → 更新状态 → 判断终止。

| 老师要求 | 实现位置 |
|---|---|
| 共享状态、漏洞假设、前置条件 | `models.py` |
| 固定 CPGQL 序列 | `cases.py` |
| Joern 执行与 mock 回放 | `executors.py` |
| 原始结果、状态、耗时 | `raw/*`、`iterations.jsonl` |
| T1 与节点绑定 | `evidence.py` |
| 前置条件和进度更新 | `state_machine.py` |
| 循环与终止 | `runner.py` |
| 数据流、证据链和最终状态 | `final-state.json` |
| 图修复 T3 候选接口 | `repair.py` |

明确限制：仓库中的 fixture 是 Joern 输出契约样例，用于无 Joern 环境的可重复验收；它不能替代在目标固件 CPG 上运行真实查询。真实模式需要 Joern、uhttpd CPG 和老师后续提供的已核验查询/结果样例。

