"""结构化候选 bundle / payload 解析 / 提交循环的单元测试。

跑法（不需要 Docker、不需要数据集）：

    python -m unittest deploy.tests.test_bundle_candidates -v
"""

from __future__ import annotations

import io
import json
import sys
import tarfile
import tempfile
import unittest
from pathlib import Path
from unittest import mock

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

import cybergym_batch as cb  # noqa: E402


def build_task_root(root: Path) -> Path:
    """最小任务工作区：task/poc、task/src、out。"""
    task_root = root / "work" / "arvo_3938"
    (task_root / "task" / "poc").mkdir(parents=True)
    (task_root / "task" / "src").mkdir(parents=True)
    (task_root / "out").mkdir(parents=True)
    return task_root


def write_file(path: Path, data: bytes) -> Path:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(data)
    return path


def build_data_dir(root: Path) -> Path:
    data = root / "data" / "arvo" / "3938"
    data.mkdir(parents=True)
    (data / "description.txt").write_text("fake description", encoding="utf-8")
    with tarfile.open(data / "repo-vul.tar.gz", "w:gz") as tar:
        payload = b"int main(void){return 0;}\n"
        info = tarfile.TarInfo("file.c")
        info.size = len(payload)
        tar.addfile(info, io.BytesIO(payload))
    return data


class CollectPocsTests(unittest.TestCase):
    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self.root = Path(self._tmp.name)
        self.task_root = build_task_root(self.root)
        self.poc_dir = self.task_root / "task" / "poc"

    def tearDown(self):
        self._tmp.cleanup()

    def test_bundle_declares_final_role_and_sha(self):
        poc = write_file(self.poc_dir / "poc_a", b"A" * 64)
        digest = cb._sha256_file(poc)
        (self.poc_dir / cb.BUNDLE_FILE).write_text(
            json.dumps(
                {
                    "candidates": [
                        {
                            "file": "poc/poc_a",
                            "role": "final_candidate",
                            "sha256": digest,
                            "family": "arvo",
                            "verification": "vulnerable_runtime_confirmed",
                            "observed_exit": 1,
                        }
                    ]
                }
            ),
            encoding="utf-8",
        )
        notes: dict = {}
        candidates = cb.collect_pocs(self.task_root, {}, notes)
        self.assertEqual(len(candidates), 1)
        self.assertEqual(candidates[0].role, cb.ROLE_FINAL)
        self.assertEqual(candidates[0].source, "bundle")
        self.assertEqual(candidates[0].sha256, digest)
        self.assertTrue(candidates[0].verified)
        self.assertEqual(candidates[0].observed_exit, 1)
        self.assertEqual(notes, {})

    def test_missing_bundle_candidate_and_hash_mismatch_are_recorded(self):
        write_file(self.poc_dir / "poc_a", b"A" * 64)
        (self.poc_dir / cb.BUNDLE_FILE).write_text(
            json.dumps(
                {
                    "candidates": [
                        {"file": "poc/missing", "role": "final_candidate"},
                        {"file": "poc/poc_a", "role": "candidate", "sha256": "0" * 64},
                    ]
                }
            ),
            encoding="utf-8",
        )
        notes: dict = {}
        cb.collect_pocs(self.task_root, {}, notes)
        self.assertEqual(notes["missing_candidate"], ["poc/missing"])
        self.assertEqual(notes["sha256_mismatch"], ["poc/poc_a"])

    def test_scan_skips_tiny_and_control_files(self):
        write_file(self.poc_dir / "tiny.bin", b"\x00" * 4)
        write_file(self.poc_dir / "control_x.bin", b"C" * 64)
        write_file(self.poc_dir / "real.bin", b"R" * 64)
        notes: dict = {}
        candidates = cb.collect_pocs(self.task_root, {}, notes)
        names = {candidate.path.name for candidate in candidates}
        self.assertEqual(names, {"real.bin"})
        self.assertIn("scan_too_small", notes)
        self.assertIn("scan_control_skipped", notes)

    def test_payload_volume_paths_are_collected(self):
        poc = write_file(self.poc_dir / "from_payload.bin", b"P" * 64)
        result = {
            "findings": [
                {
                    "id": "VULN-001",
                    "payload": (
                        "docker run --rm -v "
                        f"{poc}:/tmp/poc:ro --network none n132/arvo:3938-vul /bin/arvo"
                    ),
                },
                {
                    "id": "VULN-002",
                    "payload": "docker run --rm --volume /no/such/file:/tmp/poc:ro img",
                },
            ]
        }
        notes: dict = {}
        candidates = cb.collect_pocs(self.task_root, result, notes)
        self.assertEqual([c.path.name for c in candidates], ["from_payload.bin"])
        self.assertEqual(candidates[0].source, "payload")
        self.assertEqual(notes["missing_payload"], ["/no/such/file"])

    def test_sort_prefers_bundle_over_manifest_and_scan(self):
        write_file(self.poc_dir / "scan.bin", b"S" * 64)
        write_file(self.poc_dir / "manifest.bin", b"M" * 64)
        write_file(self.poc_dir / "final.bin", b"F" * 64)
        (self.poc_dir / "manifest.json").write_text(
            json.dumps({"pocs": [{"file": "poc/manifest.bin", "rank": 1}]}),
            encoding="utf-8",
        )
        (self.poc_dir / cb.BUNDLE_FILE).write_text(
            json.dumps(
                {"candidates": [{"file": "poc/final.bin", "role": "final_candidate"}]}
            ),
            encoding="utf-8",
        )
        candidates = cb.collect_pocs(self.task_root, {})
        self.assertEqual(
            [c.path.name for c in candidates],
            ["final.bin", "manifest.bin", "scan.bin"],
        )


class RunOneCandidateLoopTests(unittest.TestCase):
    """run_one 的候选循环：不启动容器，只替换 run_agent 与提交客户端。"""

    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self.root = Path(self._tmp.name)
        self.data_dir = build_data_dir(self.root)
        self.home = self.root / "home"
        self.home.mkdir()
        (self.home / "config.toml").write_text("", encoding="utf-8")
        self.work_root = self.root / "work"
        self.task = cb.TaskRef(
            "arvo:3938",
            "a5c9210adf28",
            "arvo_3938",
            self.data_dir,
            "fake",
            "n132/arvo:3938-vul",
        )
        self._sleep = cb.time.sleep
        cb.time.sleep = lambda _seconds: None

    def tearDown(self):
        cb.time.sleep = self._sleep
        self._tmp.cleanup()

    def _args(self, **overrides):
        argv = [
            "--task-id", "arvo:3938",
            "--data-dir", str(self.data_dir),
            "--work-root", str(self.work_root),
            "--trilane-home", str(self.home),
        ]
        for key, value in overrides.items():
            argv.extend([f"--{key.replace('_', '-')}", str(value)])
        return cb.parse_args(argv)

    def _fake_agent(self, files: dict[str, bytes]):
        def fake(task, task_root, args):
            poc_dir = task_root / "task" / "poc"
            for name, data in files.items():
                write_file(poc_dir / name, data)
            return cb.RunOutcome(
                "completed", 0, 10.0, {"status": "completed", "findings": []}, ""
            )

        return fake

    def _client(self, judgements: dict[str, tuple[str, int, int]]):
        class FakeClient:
            def evaluate(self, *, masked_id, real_task_id, poc, rounds):
                judgement, vul_exit, fix_exit = judgements[poc.name]
                rows = [
                    {
                        "poc_id": f"poc-{poc.name}-{index}",
                        "vul_exit_code": vul_exit,
                        "fix_exit_code": fix_exit,
                        "output_head": "",
                    }
                    for index in range(rounds)
                ]
                return {
                    "judgement": judgement,
                    "tally": {judgement: rounds},
                    "rounds": rows,
                }

        return FakeClient()

    def test_continues_after_no_crash_and_solves_later_candidate(self):
        (self.work_root / "arvo_3938" / "task" / "poc").mkdir(parents=True, exist_ok=True)
        (self.work_root / "arvo_3938" / "task" / "poc" / "manifest.json").write_text(
            json.dumps(
                {
                    "pocs": [
                        {"file": "poc/bad.bin", "rank": 1},
                        {"file": "poc/good.bin", "rank": 2},
                    ]
                }
            ),
            encoding="utf-8",
        )
        fake = self._fake_agent({"bad.bin": b"B" * 64, "good.bin": b"G" * 64})
        with mock.patch.object(cb, "run_agent", fake):
            record = cb.run_one(
                self.task,
                self._args(),
                self._client(
                    {"bad.bin": ("no_crash", 0, None), "good.bin": ("solved", 1, 0)}
                ),
                self.work_root,
            )
        self.assertEqual(record["status"], "solved")
        self.assertEqual(len(record["submissions"]), 2)

    def test_terminal_status_and_best_evidence_are_recorded(self):
        (self.work_root / "arvo_3938" / "task" / "poc").mkdir(parents=True, exist_ok=True)
        (self.work_root / "arvo_3938" / "task" / "poc" / "manifest.json").write_text(
            json.dumps(
                {
                    "pocs": [
                        {"file": "poc/fix_crash.bin", "rank": 1},
                        {"file": "poc/no_crash.bin", "rank": 2},
                    ]
                }
            ),
            encoding="utf-8",
        )
        fake = self._fake_agent(
            {"fix_crash.bin": b"F" * 64, "no_crash.bin": b"N" * 64}
        )
        with mock.patch.object(cb, "run_agent", fake):
            record = cb.run_one(
                self.task,
                self._args(),
                self._client(
                    {
                        "fix_crash.bin": ("fix_also_crashes", 1, 1),
                        "no_crash.bin": ("no_crash", 0, None),
                    }
                ),
                self.work_root,
            )
        self.assertEqual(record["status"], "no_crash")
        self.assertEqual(record["terminal_status"], "no_crash")
        self.assertEqual(record["best_evidence"]["file"], "task/poc/fix_crash.bin")
        self.assertEqual(len(record["submissions"]), 2)

    def test_explicit_final_candidate_no_crash_stops_early(self):
        (self.work_root / "arvo_3938" / "task" / "poc").mkdir(parents=True, exist_ok=True)
        (self.work_root / "arvo_3938" / "task" / "poc" / cb.BUNDLE_FILE).write_text(
            json.dumps(
                {
                    "candidates": [
                        {"file": "poc/final.bin", "role": "final_candidate"},
                        {"file": "poc/other.bin", "role": "candidate"},
                    ]
                }
            ),
            encoding="utf-8",
        )
        fake = self._fake_agent({"final.bin": b"F" * 64, "other.bin": b"O" * 64})
        with mock.patch.object(cb, "run_agent", fake):
            record = cb.run_one(
                self.task,
                self._args(),
                self._client(
                    {
                        "final.bin": ("no_crash", 0, None),
                        "other.bin": ("solved", 1, 0),
                    }
                ),
                self.work_root,
            )
        self.assertEqual(record["status"], "no_crash")
        self.assertEqual(len(record["submissions"]), 1)


if __name__ == "__main__":
    unittest.main()
