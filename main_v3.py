import json

from fixed_demo import run_fixed_demo

# 初始化状态（v3）
initial_state = {
    "hypothesis": {
        "id": "uhttpd-cve-2019-19945",
        "title": "uhttpd content_length 整数符号/转换错误导致越界读取",
        "status": "speculative",
        "verification_needed": [
            "已定位输入来源",
            "存在 content_length 上界检查",
            "已确认数据流路径",
            "跨函数数据流可达",
            "识别到协议终止边界",
        ],
        "verified_preconditions": [],
        "refuted_preconditions": [],
        "unresolved_preconditions": [],
    },
    "query_history": [],
    "security_facts": [],
    "evidence": [],
    "iteration": 0,
    "max_iterations": 10,
    "next_query": None,
    "no_progress_count": 0,
}

final_state = run_fixed_demo(initial_state)

# 打印精简版核心结果
print("最终假设状态")
print(f"  status: {final_state['hypothesis']['status']}")
print(f"  verified:   {final_state['hypothesis']['verified_preconditions']}")
print(f"  refuted:    {final_state['hypothesis']['refuted_preconditions']}")
print(f"  unresolved: {final_state['hypothesis']['unresolved_preconditions']}")
print(f"  迭代轮次: {final_state['iteration']} / {final_state['max_iterations']}")
print()
print("T1 证据（含解析出的代码锚点）")
for e in final_state["evidence"]:
    loc = e.get("location", "-")
    method = e.get("method", "-")
    snippet = (e.get("code_snippet") or "")[:40]
    print(f"  [{e['verdict']:8}] q{e['query_id']}  {e['condition']}  | {loc} {method} | {snippet}")
print()
print(json.dumps(final_state, ensure_ascii=False, indent=2))
