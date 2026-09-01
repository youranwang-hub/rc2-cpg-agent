import unittest

from rc2_cpg_agent.cases import UHTTPD_QUERY_PLAN, build_uhttpd_hypothesis
from rc2_cpg_agent.evidence import extract_t1
from rc2_cpg_agent.models import AnalysisState, ExecutionStatus, QueryResult, Verdict
from rc2_cpg_agent.repair import RepairCandidate, store_t3_candidates


class SafetyTest(unittest.TestCase):
    def test_execution_success_is_not_automatically_verified(self):
        result = QueryResult("q1", ExecutionStatus.SUCCESS, "", "", 0, 1)
        verdict, evidence = extract_t1(UHTTPD_QUERY_PLAN[0], result)
        self.assertIs(verdict, Verdict.UNKNOWN)
        self.assertEqual(evidence, [])

    def test_t3_candidate_cannot_be_trusted_fact(self):
        state = AnalysisState("case", build_uhttpd_hypothesis(), 5)
        candidate = RepairCandidate("r1", "variable_name", "content_length", "decompiler guess", "graph-repair")
        store_t3_candidates(state, [candidate])
        self.assertFalse(state.repair_candidates[0].validated)
        self.assertEqual(state.hypothesis.verified_preconditions, [])


if __name__ == "__main__":
    unittest.main()
