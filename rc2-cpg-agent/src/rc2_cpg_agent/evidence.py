from __future__ import annotations

import json

from .models import Evidence, ExecutionStatus, QueryResult, QuerySpec, Verdict


def extract_t1(spec: QuerySpec, result: QueryResult) -> tuple[Verdict, list[Evidence]]:
    if result.status is not ExecutionStatus.SUCCESS:
        return Verdict.UNKNOWN, []
    records = []
    try:
        for line in result.stdout.splitlines():
            if line.strip():
                records.append(json.loads(line))
    except (json.JSONDecodeError, TypeError):
        return Verdict.UNKNOWN, []
    matched = [item for item in records if item.get("marker") == spec.positive_marker]
    if not matched:
        return Verdict.UNKNOWN, []
    evidence = []
    for index, item in enumerate(matched, 1):
        path = tuple(item.get("path", []))
        nodes = path or (item,)
        evidence.append(Evidence(
            evidence_id=f"{spec.query_id}-t1-{index}", tier="T1", query_id=spec.query_id,
            condition_id=spec.condition_id,
            cpg_node_ids=tuple(int(node["id"]) for node in nodes if node.get("id") is not None),
            source_locations=tuple(f'{node.get("file", "?")}:{node.get("line", "?")}' for node in nodes),
            code=tuple(str(node.get("code", "")) for node in nodes), path=path,
        ))
    return Verdict.VERIFIED, evidence

