from .models import Preconditions, QuerySpec, VulnerabilityHypothesis


UHTTPD_PRECONDITIONS = (
    Preconditions("attacker_input", "攻击者可控的 Content-Length 被解析"),
    Preconditions("numeric_conversion", "输入经 strtoul 转为长度值"),
    Preconditions("field_assignment", "转换结果写入 request content_length"),
    Preconditions("dataflow_to_consume", "该值沿数据流到达 ustream_consume"),
    Preconditions("dangerous_effect", "可控长度参与最终消费操作"),
)


UHTTPD_QUERY_PLAN = (
    QuerySpec("q1", "attacker_input", "定位 Content-Length 输入", 'cpg.literal.code("(?i).*content-length.*").map(n => Map("marker" -> "INPUT", "id" -> n.id, "code" -> n.code, "file" -> n.file.name, "line" -> n.lineNumber))', "INPUT"),
    QuerySpec("q2", "numeric_conversion", "定位 strtoul 数值转换", 'cpg.call.name("strtoul").map(n => Map("marker" -> "CONVERSION", "id" -> n.id, "code" -> n.code, "file" -> n.file.name, "line" -> n.lineNumber))', "CONVERSION"),
    QuerySpec("q3", "field_assignment", "确认 content_length 赋值", 'cpg.assignment.code(".*content_length.*").map(n => Map("marker" -> "ASSIGNMENT", "id" -> n.id, "code" -> n.code, "file" -> n.file.name, "line" -> n.lineNumber))', "ASSIGNMENT"),
    QuerySpec("q4", "dataflow_to_consume", "计算 source 到 sink 的数据流", 'val src=cpg.call.name("strtoul"); val sink=cpg.call.name("ustream_consume"); sink.reachableByFlows(src).map(p => Map("marker" -> "DATAFLOW", "path" -> p.elements.map(n => Map("id" -> n.id, "code" -> n.code, "file" -> n.file.name, "line" -> n.lineNumber)).l))', "DATAFLOW"),
    QuerySpec("q5", "dangerous_effect", "确认最终 ustream_consume 调用", 'cpg.call.name("ustream_consume").map(n => Map("marker" -> "SINK", "id" -> n.id, "code" -> n.code, "file" -> n.file.name, "line" -> n.lineNumber))', "SINK"),
)


def build_uhttpd_hypothesis() -> VulnerabilityHypothesis:
    conditions = {item.condition_id: item for item in UHTTPD_PRECONDITIONS}
    return VulnerabilityHypothesis(
        hypothesis_id="CVE-2019-19945-uhttpd",
        title="uhttpd attacker-controlled length reaches stream consumption",
        preconditions=conditions,
        verification_needed=list(conditions),
    )

