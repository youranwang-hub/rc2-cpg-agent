from __future__ import annotations

from dataclasses import asdict, dataclass, field
from enum import StrEnum
from typing import Any


class HypothesisStatus(StrEnum):
    SPECULATIVE = "speculative"
    LIKELY = "likely"
    CONFIRMED = "confirmed"
    REFUTED = "refuted"


class ExecutionStatus(StrEnum):
    SUCCESS = "success"
    FAILED = "failed"
    TIMEOUT = "timeout"


class Verdict(StrEnum):
    VERIFIED = "verified"
    REFUTED = "refuted"
    UNKNOWN = "unknown"


@dataclass(frozen=True)
class Preconditions:
    condition_id: str
    description: str


@dataclass(frozen=True)
class QuerySpec:
    query_id: str
    condition_id: str
    purpose: str
    cpgql: str
    positive_marker: str


@dataclass
class QueryResult:
    query_id: str
    status: ExecutionStatus
    stdout: str
    stderr: str
    return_code: int | None
    duration_ms: int


@dataclass(frozen=True)
class Evidence:
    evidence_id: str
    tier: str
    query_id: str
    condition_id: str
    cpg_node_ids: tuple[int, ...]
    source_locations: tuple[str, ...]
    code: tuple[str, ...]
    path: tuple[dict[str, Any], ...] = ()


@dataclass
class QueryRecord:
    iteration: int
    spec: QuerySpec
    result: QueryResult
    verdict: Verdict
    evidence_ids: list[str] = field(default_factory=list)


@dataclass
class RepairCandidate:
    candidate_id: str
    kind: str
    value: str
    rationale: str
    source: str
    tier: str = "T3"
    validated: bool = False


@dataclass
class VulnerabilityHypothesis:
    hypothesis_id: str
    title: str
    preconditions: dict[str, Preconditions]
    status: HypothesisStatus = HypothesisStatus.SPECULATIVE
    verified_preconditions: list[str] = field(default_factory=list)
    refuted_preconditions: list[str] = field(default_factory=list)
    verification_needed: list[str] = field(default_factory=list)
    verification_progress: float = 0.0


@dataclass
class AnalysisState:
    case_id: str
    hypothesis: VulnerabilityHypothesis
    max_iterations: int
    iteration: int = 0
    query_history: list[QueryRecord] = field(default_factory=list)
    evidence: list[Evidence] = field(default_factory=list)
    security_facts: list[dict[str, Any]] = field(default_factory=list)
    repair_candidates: list[RepairCandidate] = field(default_factory=list)
    data_flow_path: list[dict[str, Any]] = field(default_factory=list)
    evidence_chain: list[dict[str, Any]] = field(default_factory=list)
    termination_reason: str | None = None

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)

