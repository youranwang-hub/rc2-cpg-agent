from state import AnalysisState, VulnerabilityHypothesis


def refresh_hypothesis_status(hypothesis: VulnerabilityHypothesis) -> None:
    if hypothesis["refuted_preconditions"]:
        hypothesis["status"] = "refuted"
    elif not hypothesis["verification_needed"]:
        hypothesis["status"] = "confirmed"
    elif hypothesis["verified_preconditions"]:
        hypothesis["status"] = "likely"
    else:
        hypothesis["status"] = "speculative"


def record_condition_verdict(
    state: AnalysisState,
    condition: str,
    is_verified: bool,
) -> None:
    hypothesis = state["hypothesis"]

    if condition not in hypothesis["verification_needed"]:
        raise ValueError(f"条件不在待验证列表中：{condition}")

    hypothesis["verification_needed"].remove(condition)

    if is_verified:
        hypothesis["verified_preconditions"].append(condition)
    else:
        hypothesis["refuted_preconditions"].append(condition)

    refresh_hypothesis_status(hypothesis)