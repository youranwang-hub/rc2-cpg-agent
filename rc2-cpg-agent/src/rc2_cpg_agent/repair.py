from __future__ import annotations

from typing import Protocol

from .models import AnalysisState, RepairCandidate


class GraphRepairAgent(Protocol):
    def propose(self, state: AnalysisState, condition_id: str) -> list[RepairCandidate]: ...


class NoOpGraphRepairAgent:
    def propose(self, state: AnalysisState, condition_id: str) -> list[RepairCandidate]:
        return []


def store_t3_candidates(state: AnalysisState, candidates: list[RepairCandidate]) -> None:
    """Store candidates only. T3 candidates never change a condition verdict."""
    for candidate in candidates:
        if candidate.tier != "T3" or candidate.validated:
            raise ValueError("repair output must enter shared state as an unvalidated T3 candidate")
        state.repair_candidates.append(candidate)

