from state import AnalysisState
from state_machine import record_condition_verdict


FIXED_STEPS = [
    {
        "query_id": "q1",
        "query": "// 固定查询 1：定位输入来源",
        "condition": "已定位输入来源",
        "raw_result": "mock result: input node found",
        "node_ids": ["100"],
        "is_verified": True,
    },
    {
        "query_id": "q2",
        "query": "// 固定查询 2：确认数据流路径",
        "condition": "已确认数据流路径",
        "raw_result": "mock result: path found",
        "node_ids": ["101", "102"],
        "is_verified": True,
    },
]


def run_fixed_demo(state: AnalysisState) -> AnalysisState:
    for step in FIXED_STEPS:
        if state["iteration"] >= state["max_iterations"]:
            break

        if state["hypothesis"]["status"] in {"confirmed", "refuted"}:
            break

        state["iteration"] += 1

        state["query_history"].append(
            {
                "query_id": step["query_id"],
                "query": step["query"],
                "raw_result": step["raw_result"],
                "execution_status": "success",
            }
        )

        state["evidence"].append(
            {
                "tier": "T1",
                "query_id": step["query_id"],
                "condition": step["condition"],
                "node_ids": step["node_ids"],
            }
        )

        record_condition_verdict(
            state,
            step["condition"],
            step["is_verified"],
        )

    return state