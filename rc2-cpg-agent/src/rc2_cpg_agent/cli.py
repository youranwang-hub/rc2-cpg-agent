from __future__ import annotations

import argparse
import json
from pathlib import Path

from .executors import FixtureExecutor, JoernExecutor
from .runner import AnalysisRunner


def main() -> int:
    parser = argparse.ArgumentParser(description="RC2 deterministic CPG analysis demo")
    parser.add_argument("--backend", choices=("fixture", "joern"), default="fixture")
    parser.add_argument("--output-dir", type=Path, default=Path("artifacts/demo-run"))
    parser.add_argument("--joern", type=Path)
    parser.add_argument("--cpg", type=Path)
    args = parser.parse_args()
    if args.backend == "joern":
        if not args.joern or not args.cpg:
            parser.error("--backend joern requires --joern and --cpg")
        executor = JoernExecutor(args.joern, args.cpg, args.output_dir / "scripts")
    else:
        executor = FixtureExecutor(Path(__file__).parent / "fixtures" / "uhttpd")
    state = AnalysisRunner(executor, args.output_dir).run()
    print(json.dumps({"case_id": state.case_id, "status": state.hypothesis.status, "verification_progress": state.hypothesis.verification_progress, "verification_needed": state.hypothesis.verification_needed, "termination_reason": state.termination_reason, "output_dir": str(args.output_dir.resolve())}, ensure_ascii=False, indent=2))
    return 0 if state.hypothesis.status == "confirmed" else 1

