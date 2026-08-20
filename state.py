from typing import Literal
from typing_extensions import TypedDict


class VulnerabilityHypothesis(TypedDict):
    id: str
    title: str
    status: Literal["speculative", "likely", "confirmed", "refuted"]

    verification_needed: list[str]
    verified_preconditions: list[str]
    refuted_preconditions: list[str]

class AnalysisState(TypedDict):
    hypothesis: VulnerabilityHypothesis

    query_history: list[dict]
    security_facts: list[str]
    evidence: list[dict]

    iteration: int
    max_iterations: int