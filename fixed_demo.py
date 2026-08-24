from typing import TypedDict, NotRequired, Literal, Optional

from state import AnalysisState
from state_machine import record_condition_verdict, react_step, should_terminate
from parsers import parse_joern_lines, anchors_to_evidence_fields, status_to_verdict



# 固定查询步骤类型（查询池元素）
class FixedStep(TypedDict):
    query_id: str
    query: str
    condition: str
    raw_result: str
    node_ids: list[str]
    execution_status: Literal["success", "error", "empty", "partial"]
    is_verified: bool
    query_script: NotRequired[str]
    error_msg: NotRequired[str]
    is_unknown: NotRequired[bool]
    location: NotRequired[str]
    method: NotRequired[str]
    code_snippet: NotRequired[str]


# 查询池：uhttpd CVE-2019-19945 真实实验结果
# 来源：experiment_report.md（Joern 4.0.550 / uhttpd commit 778ccbb）
FIXED_STEPS: list[FixedStep] = [
    # 步骤2：T1 节点定位
    {
        "query_id": "q1",
        "query": "// Q1: strtoul 返回值赋给 content_length 的所有代码点",
        "query_script": "query1_basic.sc",
        "condition": "已定位输入来源",
        "raw_result": "client.c:394 client_parse_header r->content_length = strtoul(val, &err, 10)\nclient.c:489 client_poll_post_data r->content_length = strtoul(buf + offset, &sep, 16)",
        "node_ids": ["client.c:394", "client.c:489"],
        "execution_status": "success",
        "is_verified": True,
        "location": "client.c:394",
        "method": "client_parse_header",
        "code_snippet": "r->content_length = strtoul(val, &err, 10)",
    },
    {
        "query_id": "q2",
        "query": "// Q1b: content_length 另一处赋值（poll_post_data 内）",
        "query_script": "query1_basic.sc",
        "condition": "已定位输入来源",
        "raw_result": "client.c:489 client_poll_post_data r->content_length = strtoul(buf + offset, &sep, 16)",
        "node_ids": ["client.c:489"],
        "execution_status": "success",
        "is_verified": True,
        "location": "client.c:489",
        "method": "client_poll_post_data",
        "code_snippet": "r->content_length = strtoul(buf + offset, &sep, 16)",
    },
    # 步骤3：前置条件验证（空结果 -> unknown）
    {
        "query_id": "q3",
        "query": "// Q2: client_parse_header 中是否存在 content_length 的 INT_MAX 上界检查",
        "query_script": "query1_basic.sc",
        "condition": "存在 content_length 上界检查",
        "raw_result": "(空 - 查询返回比较节点为空)",
        "node_ids": [],
        "execution_status": "empty",
        "error_msg": "查询返回空；但源码明确存在 content_length < 0 守卫，查询模板未覆盖已有检查，故不记为'缺少检查'",
        "is_verified": False,
        "is_unknown": True,
    },
    # 步骤4：反向污点追踪（函数内命中）
    {
        "query_id": "q4",
        "query": "// Q3: reachableByFlows 从 ustream_consume(arg2) 追踪到 strtoul",
        "query_script": "query2_taint.sc",
        "condition": "已确认数据流路径",
        "raw_result": "strtoul(buf+offset,&sep,16)[client.c:489]\n  -> r->content_length = strtoul(...) [489]\n  -> min(r->content_length, len) [464]\n  -> cur_len = min(...) [464]\n  -> ustream_consume(cl->us, cur_len) [473]",
        "node_ids": ["client.c:489", "client.c:464", "client.c:473"],
        "execution_status": "success",
        "is_verified": True,
        "location": "client.c:473",
        "method": "client_poll_post_data",
        "code_snippet": "ustream_consume(cl->us, cur_len)",
    },
    # 步骤4b：跨函数路径（受限 -> unknown）
    {
        "query_id": "q5",
        "query": "// Q4: 跨函数路径 client_parse_header:394 -> client_poll_post_data:473 (struct 字段)",
        "query_script": "query2_taint.sc",
        "condition": "跨函数数据流可达",
        "raw_result": "(未找到 - 跨函数 struct 别名分析超出当前静态分析能力边界)",
        "node_ids": [],
        "execution_status": "partial",
        "error_msg": "跨函数 struct 字段路径未找到；两条路径分别记录，不合并为一条已验证路径；Φ 适用范围受限而非判定不存在",
        "is_verified": False,
        "is_unknown": True,
    },
    # 步骤5：协议语义识别（终止边界）
    {
        "query_id": "q6",
        "query": "// Q5: CPG 中与 Transfer-Encoding 相关的字符串字面量",
        "query_script": "query1_basic.sc",
        "condition": "识别到协议终止边界",
        "raw_result": 'client.c:52 "Transfer-Encoding: chunked\\r\\n"\nclient.c:399 "transfer-encoding"\nclient.c:400 "chunked"',
        "node_ids": ["client.c:52", "client.c:399", "client.c:400"],
        "execution_status": "success",
        "is_verified": True,
        "location": "client.c:399",
        "method": "client_parse_header",
        "code_snippet": '"transfer-encoding"',
    },
]

# 供 react_step 使用的查询池（只含决策所需字段）
QUERY_POOL: list[dict] = [
    {
        "query_id": s["query_id"],
        "query": s["query"],
        "condition": s["condition"],
        "query_script": s.get("query_script", ""),
    }
    for s in FIXED_STEPS
]


# 执行一次查询（拿到 step 定义，返回查询结果）
# v3：真实运行中这里会执行 Joern 查询；当前用 FIXED_STEPS 的冻结结果模拟。
def execute_query(step: FixedStep) -> dict:
    return {
        "query_id": step["query_id"],
        "query": step["query"],
        "condition": step["condition"],
        "raw_result": step["raw_result"],
        "execution_status": step["execution_status"],
        "query_script": step.get("query_script", ""),
        "error_msg": step.get("error_msg"),
        "node_ids": step.get("node_ids", []),
    }


# 处理一次查询结果（第 2 步：empty/partial/error -> observation 化）
# 把 result 写入 query_history，解析成 T1 证据，并裁定前置条件。
# 记录本轮执行前的 status，供外层判断是否无进展。
def process_query_result(state: AnalysisState, result: dict) -> None:
    # 1) 写 query_history
    query_record: dict = {
        "query_id": result["query_id"],
        "query": result["query"],
        "condition": result["condition"],
        "raw_result": result["raw_result"],
        "execution_status": result["execution_status"],
    }
    if result.get("query_script"):
        query_record["query_script"] = result["query_script"]
    if result.get("error_msg"):
        query_record["error_msg"] = result["error_msg"]
    state["query_history"].append(query_record)

    # 2) 根据执行状态裁定 verdict（empty/partial/error -> unknown，observation 化）
    verdict = status_to_verdict(result["execution_status"])

    # 3) 用解析器从 raw_result 提取 T1 证据字段
    anchors = parse_joern_lines(result["raw_result"])
    ev_fields = anchors_to_evidence_fields(anchors)
    # 若解析器没提出来（空结果/受限），回退到 step 预设的 node_ids
    if not ev_fields["node_ids"]:
        ev_fields["node_ids"] = result.get("node_ids", [])

    evidence: dict = {
        "tier": "T1",
        "query_id": result["query_id"],
        "condition": result["condition"],
        "verdict": verdict,
        "node_ids": ev_fields["node_ids"],
    }
    for k in ("location", "method", "code_snippet"):
        if ev_fields.get(k):
            evidence[k] = ev_fields[k]
    state["evidence"].append(evidence)

    # 4) 同一条件只裁决一次
    if result["condition"] not in {
        e["condition"] for e in state["evidence"] if e["query_id"] != result["query_id"]
    }:
        record_condition_verdict(state, result["condition"], verdict)


# ReAct 主循环（第 3 步）
def run_fixed_demo(state: AnalysisState) -> AnalysisState:
    state.setdefault("no_progress_count", 0)
    last_status = state["hypothesis"]["status"]

    while not should_terminate(state):
        # Think：决定下一步 query
        react_step(state, QUERY_POOL)
        next_qid = state.get("next_query")

        # 没有可执行的下一步 -> 无进展，退出（或记录待办）
        if next_qid is None:
            state["no_progress_count"] = state.get("no_progress_count", 0) + 1
            if should_terminate(state):
                break
            # 兜底：若已有 unresolved 且无法推进，标记后退出
            state["no_progress_count"] = state.get("no_progress_count", 0) + 1
            break

        # 找到该 query 的定义并执行（Act）
        step = next(s for s in FIXED_STEPS if s["query_id"] == next_qid)
        state["iteration"] += 1
        result = execute_query(step)

        # Observe：写历史 + 解析证据 + 裁定
        process_query_result(state, result)

        # 判断是否无进展（status 未变化）
        cur_status = state["hypothesis"]["status"]
        if cur_status == last_status:
            state["no_progress_count"] = state.get("no_progress_count", 0) + 1
        else:
            state["no_progress_count"] = 0
        last_status = cur_status

    return state
