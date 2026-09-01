import json
import tempfile
import unittest
from pathlib import Path

from rc2_cpg_agent.executors import FixtureExecutor
from rc2_cpg_agent.models import HypothesisStatus
from rc2_cpg_agent.runner import AnalysisRunner


class DemoTest(unittest.TestCase):
    def test_uhttpd_demo_converges_to_confirmed(self):
        import rc2_cpg_agent.runner as runner
        fixture_dir = Path(runner.__file__).parent / "fixtures" / "uhttpd"
        with tempfile.TemporaryDirectory() as directory:
            output = Path(directory)
            state = AnalysisRunner(FixtureExecutor(fixture_dir), output).run()
            self.assertIs(state.hypothesis.status, HypothesisStatus.CONFIRMED)
            self.assertEqual(state.hypothesis.verification_needed, [])
            self.assertEqual(len(state.hypothesis.verified_preconditions), 5)
            self.assertEqual(state.hypothesis.verification_progress, 1.0)
            self.assertEqual([node["id"] for node in state.data_flow_path], [202, 303, 404, 505])
            self.assertEqual(len(state.evidence_chain), 5)
            final = json.loads((output / "final-state.json").read_text(encoding="utf-8"))
            self.assertEqual(final["termination_reason"], "confirmed")


if __name__ == "__main__":
    unittest.main()
