from __future__ import annotations

import json
from pathlib import Path

from .cases import UHTTPD_QUERY_PLAN, build_uhttpd_hypothesis
from .evidence import extract_t1
from .executors import QueryExecutor, save_raw_result
from .models import AnalysisState, QueryRecord, Verdict
from .repair import GraphRepairAgent, NoOpGraphRepairAgent, store_t3_candidates
from .state_machine import apply_verdict, should_stop


class AnalysisRunner:
    def __init__(self, executor: QueryExecutor, output_dir: Path, repair_agent: GraphRepairAgent | None = None) -> None:
        self.executor = executor
        self.output_dir = output_dir
        self.repair_agent = repair_agent or NoOpGraphRepairAgent()

    def run(self, max_iterations: int = 10) -> AnalysisState:
        state = AnalysisState("uhttpd-cve-2019-19945", build_uhttpd_hypothesis(), max_iterations)
        for spec in UHTTPD_QUERY_PLAN:
            if should_stop(state):
                break
            state.iteration += 1
            result = self.executor.execute(spec)
            save_raw_result(result, self.output_dir / "raw")
            verdict, evidence = extract_t1(spec, result)
            state.evidence.extend(evidence)
            state.query_history.append(QueryRecord(state.iteration, spec, result, verdict, [e.evidence_id for e in evidence]))
            apply_verdict(state, spec.condition_id, verdict)
            if verdict is Verdict.UNKNOWN:
                store_t3_candidates(state, self.repair_agent.propose(state, spec.condition_id))
                state.termination_reason = f"unresolved:{spec.condition_id}"
                break
        should_stop(state)
        self._build_chain(state)
        self._save(state)
        return state

    def _build_chain(self, state: AnalysisState) -> None:
        for evidence in state.evidence:
            state.evidence_chain.append({"condition_id": evidence.condition_id, "query_id": evidence.query_id, "evidence_id": evidence.evidence_id, "tier": evidence.tier, "nodes": list(evidence.cpg_node_ids)})
            if evidence.path:
                state.data_flow_path = list(evidence.path)

    def _save(self, state: AnalysisState) -> None:
        self.output_dir.mkdir(parents=True, exist_ok=True)
        (self.output_dir / "final-state.json").write_text(json.dumps(state.to_dict(), ensure_ascii=False, indent=2), encoding="utf-8")
        lines = [json.dumps({"iteration": r.iteration, "query_id": r.spec.query_id, "condition_id": r.spec.condition_id, "execution_status": r.result.status, "verdict": r.verdict, "duration_ms": r.result.duration_ms}, ensure_ascii=False) for r in state.query_history]
        (self.output_dir / "iterations.jsonl").write_text("\n".join(lines) + "\n", encoding="utf-8")

