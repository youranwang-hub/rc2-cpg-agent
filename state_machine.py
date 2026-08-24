from state import AnalysisState, VulnerabilityHypothesis


# 状态迁移：更新漏洞猜想的状态
def refresh_hypothesis_status(hypothesis: VulnerabilityHypothesis) -> None:
    if hypothesis["refuted_preconditions"]:
        hypothesis["status"] = "refuted"
    elif hypothesis["unresolved_preconditions"]:
        # 证据不足 -> unknown，不裁决（红线）
        hypothesis["status"] = "unknown"
    elif not hypothesis["verification_needed"]:
        hypothesis["status"] = "confirmed"
    elif hypothesis["verified_preconditions"]:
        hypothesis["status"] = "likely"
    else:
        hypothesis["status"] = "speculative"


# 记录前置条件裁定（三态版本）
def record_condition_verdict(
    state: AnalysisState,
    condition: str,
    verdict: str,  # "verified" / "refuted" / "unknown"
) -> None:
    hypothesis = state["hypothesis"]

    if condition not in hypothesis["verification_needed"]:
        raise ValueError(f"条件不在待验证列表中：{condition}")

    if verdict not in {"verified", "refuted", "unknown"}:
        raise ValueError(f"非法裁定结果：{verdict}（应为 verified/refuted/unknown）")

    hypothesis["verification_needed"].remove(condition)

    if verdict == "verified":
        hypothesis["verified_preconditions"].append(condition)
    elif verdict == "refuted":
        hypothesis["refuted_preconditions"].append(condition)
    else:  # unknown
        hypothesis["unresolved_preconditions"].append(condition)

    refresh_hypothesis_status(hypothesis)


# 第 3 步：ReAct 主循环骨架 —— 决策 + 观察
# react_step(state, available_queries) -> None
# 作用：读完当前 state，决定下一步该执行哪个 query，并写回 state["next_query"]。
# 这是"Think"层：先用确定性规则（后面可替换为 LLM 决策）。

# 决策规则（确定性，先打通骨架）：
#   1. 优先挑 verification_needed 里第一个未处理的条件，找与之对应的 query；
#   2. 若没有待验证条件，但存在 unresolved（证据不足），返回一个"重新查询"意图
#      （这里用 None + 无进展，触发终止条件）；
#   3. 否则无需再查，next_query=None。

# 说明：available_queries 是一个 list[dict]，每个 dict 至少含
#       query_id / condition / query / query_script 字段，来自 FIXED_STEPS。
def react_step(state: AnalysisState, available_queries: list[dict]) -> None:
    hypothesis = state["hypothesis"]

    # 已裁决：confirmed / refuted -> 不再查询
    if hypothesis["status"] in {"confirmed", "refuted"}:
        state["next_query"] = None
        return

    # 还有待验证条件：挑第一个，找到对应 query
    if hypothesis["verification_needed"]:
        condition = hypothesis["verification_needed"][0]
        for q in available_queries:
            if q["condition"] == condition and q["query_id"] not in {
                r["query_id"] for r in state["query_history"]
            }:
                state["next_query"] = q["query_id"]
                return
        # 该条件没有可执行的新查询 -> 无法推进
        state["next_query"] = None
        return

    # 没有待验证条件但有 unresolved：证据不足，暂无更多查询可做
    state["next_query"] = None


# 终止条件判定（第 3 步）
# 返回 True 表示应终止循环：
#    已裁决（confirmed/refuted）
#    达到最大轮次
#    连续无进展超过阈值（status 未变化）
def should_terminate(state: AnalysisState, no_progress_limit: int = 3) -> bool:
    if state["hypothesis"]["status"] in {"confirmed", "refuted"}:
        return True
    if state["iteration"] >= state["max_iterations"]:
        return True
    if state.get("no_progress_count", 0) >= no_progress_limit:
        return True
    return False
