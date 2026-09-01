# RC2 Firmware CPG Analysis Agent

这是老师要求的第一阶段最小可运行 Demo：以 uhttpd CVE-2019-19945 为固定案例，按照固定 CPGQL 查询计划执行 Think → Action → Observe → deterministic state transition 循环。

当前 Demo 默认使用版本化的 Joern JSON 样例，因此没有安装 Joern 也能复现实验；传入 `--backend joern` 后会调用真实 Joern。LLM 不参与 T1 证据认定、前置条件裁定或状态迁移。

## 运行

```powershell
python -m rc2_cpg_agent --output-dir artifacts/demo-run
$env:PYTHONPATH = "src"
python -m unittest discover -s tests -v
```

真实 Joern 模式：

```powershell
python -m rc2_cpg_agent --backend joern --joern C:\tools\joern\joern.bat --cpg D:\firmware\uhttpd.cpg
```

每次运行保存：每轮查询记录、未经修改的 stdout/stderr、执行状态、耗时、T1 证据、结构化数据流路径、完整证据链、最终状态和终止原因。

## 可信度边界

- T1：只能由确定性解析器从 Joern 原始输出提取，可参与裁定。
- T2：未来由 LLM 归纳，只能作为待验证结论。
- T3：图修复 Agent 的语义候选，只能写入候选区并生成后续查询，不能直接确认前置条件。

详细设计见 `docs/phase1-design.md`，调研摘要见 `docs/research-notes.md`。
