from .models import AnalysisState, HypothesisStatus, Verdict


def apply_verdict(state: AnalysisState, condition_id: str, verdict: Verdict) -> None:
    hypothesis = state.hypothesis
    if condition_id not in hypothesis.verification_needed:
        raise ValueError(f"condition already decided or unknown: {condition_id}")
    if verdict is Verdict.VERIFIED:
        hypothesis.verified_preconditions.append(condition_id)
        hypothesis.verification_needed.remove(condition_id)
    elif verdict is Verdict.REFUTED:
        hypothesis.refuted_preconditions.append(condition_id)
        hypothesis.verification_needed.remove(condition_id)
    total = len(hypothesis.preconditions)
    hypothesis.verification_progress = len(hypothesis.verified_preconditions) / total
    if hypothesis.refuted_preconditions:
        hypothesis.status = HypothesisStatus.REFUTED
    elif not hypothesis.verification_needed and len(hypothesis.verified_preconditions) == total:
        hypothesis.status = HypothesisStatus.CONFIRMED
    elif hypothesis.verified_preconditions:
        hypothesis.status = HypothesisStatus.LIKELY
    else:
        hypothesis.status = HypothesisStatus.SPECULATIVE


def should_stop(state: AnalysisState) -> bool:
    if state.hypothesis.status in (HypothesisStatus.CONFIRMED, HypothesisStatus.REFUTED):
        state.termination_reason = state.hypothesis.status.value
        return True
    if state.iteration >= state.max_iterations:
        state.termination_reason = "max_iterations"
        return True
    return False

