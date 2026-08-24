import re
from typing import Optional

# 第 1 步：T1 证据解析器
# 把 Joern 查询的 raw_result（文本）解析成 T1 证据所需的结构化字段：
#   node_ids / location(文件:行号) / method(函数名) / code_snippet(代码片段)

# 输入格式（report 真实输出）：
#   client.c:394  client_parse_header  r->content_length = strtoul(val, &err, 10)
#   client.c:489  client_poll_post_data  r->content_length = strtoul(buf + offset, &sep, 16)
# 也兼容污点路径的缩进格式：
#   strtoul(buf+offset,&sep,16)[client.c:489]
#     -> r->content_length = strtoul(...) [489]

# 返回：解析出的节点锚点列表，每个元素是 dict。
# 规则：
#    主锚点只取"声明式"行，如 `client.c:394 client_parse_header code`
#    或 `client.c:52 "Transfer-Encoding..."`（字符串字面量）。
#    污点路径的箭头行（`-> code [行号]`）是路径步骤，不作为独立 location
#    （避免产生 `?:` 这类无文件名的占位锚点）。
def parse_joern_lines(raw_result: str) -> list[dict]:
    anchors: list[dict] = []
    if not raw_result:
        return anchors

    # 模式1：形如  client.c:394  client_parse_header  <code>
    # 或      client.c:52  "Transfer-Encoding..."
    # 或      client.c:399  "transfer-encoding"
    # 兼容行号后跟函数名，或直接跟字符串字面量。
    pat_loc = re.compile(
        r"(?P<file>[A-Za-z0-9_./-]+)\.c:"      # client.c:
        r"(?P<line>\d+)"                        # 394
        r"\s+"                                  # 空格
        r"(?P<rest>.*)"                         # 剩余（函数名+代码，或字符串）
    )

    # 模式2：形如  strtoul(buf+offset,&sep,16)[client.c:489]
    # 代码后跟 [file:line] 的内联定位（带完整文件名才作为主锚点）。
    pat_inline = re.compile(r"\[(?P<file>[A-Za-z0-9_./-]+\.c:\d+)\]\s*$")

    for line in raw_result.splitlines():
        line = line.strip()
        if not line:
            continue

        # 跳过污点路径的箭头行（路径步骤，不作为独立锚点）
        if line.startswith("->") or line.startswith("|"):
            continue

        m = pat_loc.match(line)
        if not m:
            # 尝试内联 [file:line] 定位
            m_inline = pat_inline.search(line)
            if m_inline:
                anchors.append({
                    "location": m_inline.group("file"),
                    "code_snippet": line.strip(),
                })
            continue

        rest = m.group("rest").strip()
        # 尝试从 rest 分出函数名：第一个 C 标识符作为 method，其余为代码片段
        method = ""
        snippet = rest
        m_id = re.match(r"(?P<method>[A-Za-z_]\w*)\s+(?P<snippet>.*)", rest)
        if m_id:
            method = m_id.group("method")
            snippet = m_id.group("snippet").strip()

        anchors.append({
            "location": f"{m.group('file')}.c:{m.group('line')}",
            "method": method,
            "code_snippet": snippet,
        })

    return anchors


# 从解析出的锚点生成 T1Evidence 需要的字段。
# 取第一个锚点作为主位置，其余合并到 node_ids。
def anchors_to_evidence_fields(anchors: list[dict]) -> dict:
    fields: dict = {"node_ids": []}
    if not anchors:
        return fields

    head = anchors[0]
    if head.get("location"):
        fields["location"] = head["location"]
    if head.get("method"):
        fields["method"] = head["method"]
    if head.get("code_snippet"):
        fields["code_snippet"] = head["code_snippet"]

    # node_ids 收集所有锚点的 location（回映 CPG 用）
    fields["node_ids"] = [a["location"] for a in anchors if a.get("location")]
    return fields


# 根据 execution_status 判定前置条件 verdict。
# 规则（对应 report 的诚实限制）：
#   success            -> verified
#   error              -> unknown（查询抛错，证据不可靠）
#   empty              -> unknown（空结果 ≠ 判不成立）
#   partial            -> unknown（部分可达，范围受限）
def status_to_verdict(execution_status: str) -> str:
    if execution_status == "success":
        return "verified"
    # empty / partial / error 均证据不足
    return "unknown"
