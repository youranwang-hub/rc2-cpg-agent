import json

from fixed_demo import run_fixed_demo


initial_state = {
    "hypothesis": {
        "id": "demo-001",
        "title": "固定数据流风险假设",
        "status": "speculative",
        "verification_needed": [
            "已定位输入来源",
            "已确认数据流路径",
        ],
        "verified_preconditions": [],
        "refuted_preconditions": [],
    },
    "query_history": [],
    "security_facts": [],
    "evidence": [],
    "iteration": 0,
    "max_iterations": 5,
}


final_state = run_fixed_demo(initial_state)

print(json.dumps(final_state, ensure_ascii=False, indent=2))