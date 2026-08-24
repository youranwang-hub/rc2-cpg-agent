from typing import Literal, Optional, TypedDict, NotRequired


# 漏洞假设
class VulnerabilityHypothesis(TypedDict):
    id: str
    title: str
    status: Literal["speculative", "likely", "confirmed", "refuted", "unknown"]

    verification_needed: list[str]   # 还需要验证的条件清单
    verified_preconditions: list[str]  # 已验证成立的前置条件
    refuted_preconditions: list[str]   # 已证伪不成立的前置条件
    unresolved_preconditions: list[str]  # 证据不足、悬而未决的前置条件


# 单条查询记录（query_history 的元素）
class QueryRecord(TypedDict):
    query_id: str
    query: str
    condition: str
    # 执行状态：success / error（查询抛错）/ empty（查无结果）/ partial（部分可达）
    execution_status: Literal["success", "error", "empty", "partial"]
    error_msg: NotRequired[Optional[str]]
    query_script: NotRequired[Optional[str]]
    raw_result: str
    node_ids: list[str]


# T1 证据（evidence 的元素）
class T1Evidence(TypedDict):
    tier: Literal["T1"]
    query_id: str          # 由哪条查询产出
    condition: str         # 验证了哪个前置条件
    verdict: Literal["verified", "refuted", "unknown"]
    node_ids: list[str]
    location: NotRequired[Optional[str]]      # 例如 "client.c:394"
    method: NotRequired[Optional[str]]        # 例如 "client_parse_header"
    code_snippet: NotRequired[Optional[str]]  # 例如 "r->content_length = strtoul(...)"


# 整体分析状态（v3：为 ReAct 主循环新增字段）
class AnalysisState(TypedDict):
    hypothesis: VulnerabilityHypothesis

    query_history: list[QueryRecord]
    security_facts: list[str]
    evidence: list[T1Evidence]

    iteration: int
    max_iterations: int

    # ReAct 循环的决策输出：本轮应执行的 query_id
    next_query: NotRequired[Optional[str]]
    # 连续无进展（status 未变化）的轮数，用于终止条件
    no_progress_count: NotRequired[int]
