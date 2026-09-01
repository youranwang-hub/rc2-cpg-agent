from __future__ import annotations

import json
import subprocess
import time
from pathlib import Path
from typing import Protocol

from .models import ExecutionStatus, QueryResult, QuerySpec


class QueryExecutor(Protocol):
    def execute(self, spec: QuerySpec) -> QueryResult: ...


class FixtureExecutor:
    """Replay versioned Joern-shaped JSON; no verdict is stored in fixtures."""

    def __init__(self, fixture_dir: Path) -> None:
        self.fixture_dir = fixture_dir

    def execute(self, spec: QuerySpec) -> QueryResult:
        started = time.perf_counter()
        path = self.fixture_dir / f"{spec.query_id}.jsonl"
        try:
            stdout = path.read_text(encoding="utf-8")
            status, stderr, code = ExecutionStatus.SUCCESS, "", 0
        except OSError as exc:
            stdout, stderr, code = "", str(exc), None
            status = ExecutionStatus.FAILED
        return QueryResult(spec.query_id, status, stdout, stderr, code, int((time.perf_counter() - started) * 1000))


class JoernExecutor:
    def __init__(self, joern: Path, cpg: Path, work_dir: Path, timeout_seconds: int = 60) -> None:
        self.joern, self.cpg, self.work_dir, self.timeout_seconds = joern, cpg, work_dir, timeout_seconds
        work_dir.mkdir(parents=True, exist_ok=True)

    def execute(self, spec: QuerySpec) -> QueryResult:
        script = self.work_dir / f"{spec.query_id}.sc"
        script.write_text(f'importCpg("{self.cpg.as_posix()}")\n{spec.cpgql}.toJsonPretty\n', encoding="utf-8")
        started = time.perf_counter()
        try:
            process = subprocess.run([str(self.joern), "--script", str(script)], capture_output=True, text=True, encoding="utf-8", errors="replace", timeout=self.timeout_seconds, check=False)
            status = ExecutionStatus.SUCCESS if process.returncode == 0 else ExecutionStatus.FAILED
            return QueryResult(spec.query_id, status, process.stdout, process.stderr, process.returncode, int((time.perf_counter() - started) * 1000))
        except subprocess.TimeoutExpired as exc:
            return QueryResult(spec.query_id, ExecutionStatus.TIMEOUT, exc.stdout or "", exc.stderr or "", None, int((time.perf_counter() - started) * 1000))
        except OSError as exc:
            return QueryResult(spec.query_id, ExecutionStatus.FAILED, "", str(exc), None, int((time.perf_counter() - started) * 1000))


def save_raw_result(result: QueryResult, directory: Path) -> None:
    directory.mkdir(parents=True, exist_ok=True)
    (directory / f"{result.query_id}.stdout.txt").write_text(result.stdout, encoding="utf-8")
    (directory / f"{result.query_id}.stderr.txt").write_text(result.stderr, encoding="utf-8")
    (directory / f"{result.query_id}.meta.json").write_text(json.dumps({"status": result.status, "return_code": result.return_code, "duration_ms": result.duration_ms}, ensure_ascii=False, indent=2), encoding="utf-8")

