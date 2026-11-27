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

    def test_scan_limit_caps_diagnostic_hash_work(self):
        for index in range(5):
            write_file(self.poc_dir / f"scan{index}.bin", b"S" * 32)

        with mock.patch.object(cb, "POC_SCAN_MAX_FILES", 2), mock.patch.object(
            cb, "POC_SCAN_MAX_MB", 50
        ):
            notes: dict = {}
            candidates = cb.collect_pocs(self.task_root, {}, notes)

        scans = [candidate for candidate in candidates if candidate.source == "scan"]
        self.assertEqual(len(scans), 2)
        self.assertIn("scan_limit_hit", notes)

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
        self.assertFalse(candidates[0].submittable)
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
        self.assertFalse(candidates[0].submittable)
        self.assertEqual(notes["missing_payload"], ["/no/such/file"])

    def test_engine_bundle_with_replay_only(self):
        poc = write_file(self.poc_dir / "engine.bin", b"E" * 64)
        (self.task_root / "out" / cb.BUNDLE_FILE).write_text(
            json.dumps(
                {
                    "schema": 1,
                    "generated": "trilane-s5",
                    "candidates": [
                        {
                            "role": "final_candidate",
                            "replay": (
                                f"docker run -v {poc}:/tmp/poc:ro "
                                "n132/arvo:3938-vul /bin/arvo"
                            ),
                            "sha256": cb._sha256_file(poc),
                            "family": "arvo",
                            "verification": "vulnerable_runtime_confirmed",
                            "observed_exit": 1,
                        }
                    ],
                }
            ),
            encoding="utf-8",
        )
        notes: dict = {}
        candidates = cb.collect_pocs(self.task_root, {}, notes)
        self.assertEqual(len(candidates), 1)
        self.assertEqual(candidates[0].source, "bundle")
        self.assertEqual(candidates[0].role, cb.ROLE_FINAL)
        self.assertEqual(candidates[0].path.name, "engine.bin")
        self.assertEqual(candidates[0].observed_exit, 1)
        self.assertTrue(candidates[0].submittable)
        self.assertEqual(notes, {})

    def test_bundle_replay_pwd_prefix_is_resolved(self):
        """replay 里 `cd task && ... -v $PWD/poc/x.bin` 也要能定位到候选。"""
        write_file(self.poc_dir / "pwd.bin", b"W" * 64)
        (self.poc_dir / cb.BUNDLE_FILE).write_text(
            json.dumps(
                {
                    "candidates": [
                        {
                            "role": "candidate",
                            "replay": (
                                "cd task && docker run --rm "
                                "-v $PWD/poc/pwd.bin:/tmp/poc:ro "
                                "n132/arvo:3938-vul /bin/arvo"
                            ),
                        }
                    ]
                }
            ),
            encoding="utf-8",
        )
        notes: dict = {}
        candidates = cb.collect_pocs(self.task_root, {}, notes)
        self.assertEqual([c.path.name for c in candidates], ["pwd.bin"])
        self.assertEqual(candidates[0].source, "bundle")
        self.assertTrue(candidates[0].submittable)
        self.assertEqual(notes.get("missing_candidate"), None)

    def test_evidence_refs_are_diagnostic_only(self):
        write_file(self.poc_dir / "run.log", b"L" * 64)
        result = {
            "findings": [
                {"id": "VULN-001", "description": "evidence_refs=poc/run.log"}
            ]
        }
        candidates = cb.collect_pocs(self.task_root, result)
        self.assertEqual(len(candidates), 1)
        self.assertEqual(candidates[0].source, "evidence_refs")
        self.assertFalse(candidates[0].submittable)

    def test_restore_attempt_restores_bundle_and_manifest(self):
        attempt = self.task_root / cb.ARTIFACTS_DIR / "attempt-1"
        (attempt / "poc").mkdir(parents=True)
        (attempt / "poc" / cb.BUNDLE_FILE).write_text(
            '{"candidates": []}', encoding="utf-8"
        )
        (attempt / "poc" / "manifest.json").write_text(
            '{"pocs": []}', encoding="utf-8"
        )
        (attempt / "candidates.json").write_text(
            '{"schema": 1, "candidates": []}', encoding="utf-8"
        )

        restored = cb.restore_attempt_candidates(self.task_root)

        self.assertEqual(restored, 2)
        self.assertTrue((self.poc_dir / cb.BUNDLE_FILE).is_file())
        self.assertTrue((self.poc_dir / "manifest.json").is_file())

    def test_sort_prefers_local_crash_evidence_over_role(self):
        write_file(self.poc_dir / "final.bin", b"F" * 64)
        write_file(self.poc_dir / "diag.bin", b"D" * 64)
        (self.poc_dir / cb.BUNDLE_FILE).write_text(
            json.dumps(
                {
                    "candidates": [
                        {
                            "file": "poc/final.bin",
                            "role": "final_candidate",
                            "verification": "generated-not-verified",
                            "observed_exit": 0,
                        },
                        {
                            "file": "poc/diag.bin",
                            "role": "diagnostic",
                            "verification": "generated-not-verified",
                            "observed_exit": 1,
                        },
                    ]
                }
            ),
            encoding="utf-8",
        )
        candidates = cb.collect_pocs(self.task_root, {})
        self.assertEqual([c.path.name for c in candidates], ["diag.bin", "final.bin"])

    def test_manifest_verified_upgrades_bundle_candidate(self):
        write_file(self.poc_dir / "shared.bin", b"S" * 64)
        (self.poc_dir / cb.BUNDLE_FILE).write_text(
            json.dumps(
                {
                    "candidates": [
                        {
                            "file": "poc/shared.bin",
                            "role": "final_candidate",
                            "verification": "generated-not-verified",
                            "observed_exit": 0,
                        }
                    ]
                }
            ),
            encoding="utf-8",
        )
        (self.poc_dir / "manifest.json").write_text(
            json.dumps(
                {
                    "pocs": [
                        {
                            "file": "poc/shared.bin",
                            "rank": 1,
                            "verified_on_vul": True,
                        }
                    ]
                }
            ),
            encoding="utf-8",
        )
        candidates = cb.collect_pocs(self.task_root, {})
        self.assertEqual(len(candidates), 1)
        self.assertTrue(candidates[0].verified)

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

    def _client(
        self,
        judgements: dict[str, tuple[str, int, int]],
        outputs: dict[str, str] | None = None,
    ):
        outputs = outputs or {}

        class FakeClient:
            def evaluate(self, *, masked_id, real_task_id, poc, rounds):
                judgement, vul_exit, fix_exit = judgements[poc.name]
                rows = [
                    {
                        "poc_id": f"poc-{poc.name}-{index}",
                        "vul_exit_code": vul_exit,
                        "fix_exit_code": fix_exit,
                        "output_head": outputs.get(poc.name, ""),
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
        fake = self._fake_agent(
            {
                "manifest.json": json.dumps(
                    {
                        "pocs": [
                            {"file": "poc/bad.bin", "rank": 1},
                            {"file": "poc/good.bin", "rank": 2},
                        ]
                    }
                ).encode(),
                "bad.bin": b"B" * 64,
                "good.bin": b"G" * 64,
            }
        )
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
        fake = self._fake_agent(
            {
                "manifest.json": json.dumps(
                    {
                        "pocs": [
                            {"file": "poc/fix_crash.bin", "rank": 1},
                            {"file": "poc/no_crash.bin", "rank": 2},
                        ]
                    }
                ).encode(),
                "fix_crash.bin": b"F" * 64,
                "no_crash.bin": b"N" * 64,
            }
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

    def test_wrong_target_continues_to_next_candidate(self):
        (self.data_dir / "error.txt").write_text(
            "SUMMARY: AddressSanitizer: heap-buffer-overflow /src/x.c:10 in target_func\n"
            "DEDUP_TOKEN: target_func--caller_a--caller_b\n",
            encoding="utf-8",
        )
        fake = self._fake_agent(
            {
                cb.BUNDLE_FILE: json.dumps(
                    {
                        "candidates": [
                            {"file": "poc/wrong.bin", "role": "candidate", "replay": "docker run -v /poc:/tmp/poc:ro img /bin/arvo"},
                            {"file": "poc/right.bin", "role": "candidate", "replay": "docker run -v /poc:/tmp/poc:ro img /bin/arvo"},
                        ]
                    }
                ).encode(),
                "wrong.bin": b"W" * 64,
                "right.bin": b"R" * 64,
            }
        )
        client = self._client(
            {
                "wrong.bin": ("fix_also_crashes", 1, 1),
                "right.bin": ("solved", 1, 0),
            },
            outputs={
                "wrong.bin": (
                    "SUMMARY: AddressSanitizer: heap-buffer-overflow /src/y.c:20 in other_func\n"
                    "DEDUP_TOKEN: other_func--caller_c--caller_d\n"
                ),
                "right.bin": (
                    "SUMMARY: AddressSanitizer: heap-buffer-overflow /src/x.c:10 in target_func\n"
                    "DEDUP_TOKEN: target_func--caller_a--caller_b\n"
                ),
            },
        )
        with mock.patch.object(cb, "run_agent", fake):
            record = cb.run_one(self.task, self._args(), client, self.work_root)
        self.assertEqual(record["status"], "solved")
        self.assertEqual(len(record["submissions"]), 2)
        self.assertFalse(record["submissions"][0]["target_match"])
        self.assertTrue(record["submissions"][0]["wrong_target"])
        self.assertTrue(record["submissions"][1]["target_match"])

    def test_bundle_invalid_candidate_is_not_submitted(self):
        fake = self._fake_agent(
            {
                cb.BUNDLE_FILE: json.dumps(
                    {
                        "candidates": [
                            {
                                "file": "poc/final.bin",
                                "role": "final_candidate",
                                "replay": "docker run -v /poc:/tmp/poc:ro img",
                                "observed_exit": 1,
                            }
                        ]
                    }
                ).encode(),
                "final.bin": b"F" * 64,
            }
        )

        class ExplodingClient:
            def evaluate(self, **_kwargs):
                raise AssertionError("invalid bundle must not be submitted")

        with mock.patch.object(cb, "run_agent", fake):
            record = cb.run_one(
                self.task, self._args(), ExplodingClient(), self.work_root
            )
        self.assertEqual(record["status"], "bundle_invalid")
        self.assertEqual(record["bundle_invalid"][0]["issues"], ["missing_bin_arvo"])
        self.assertEqual(record["submissions"], [])

    def test_sha256_mismatch_is_submitted_with_warning(self):
        """声明哈希算错不应丢掉候选；runner 本就用实际文件哈希。"""
        fake = self._fake_agent(
            {
                cb.BUNDLE_FILE: json.dumps(
                    {
                        "candidates": [
                            {
                                "file": "poc/final.bin",
                                "role": "final_candidate",
                                "sha256": "0" * 64,
                                "replay": "docker run -v /poc:/tmp/poc:ro img /bin/arvo",
                                "observed_exit": 1,
                                "verification": "verified",
                            }
                        ]
                    }
                ).encode(),
                "final.bin": b"F" * 64,
            }
        )
        with mock.patch.object(cb, "run_agent", fake):
            record = cb.run_one(
                self.task,
                self._args(),
                self._client({"final.bin": ("solved", 1, 0)}),
                self.work_root,
            )
        self.assertEqual(record["status"], "solved")
        self.assertIn("sha256_mismatch", record["submissions"][0]["warnings"])

    def test_missing_observed_exit_candidate_is_still_submitted(self):
        """arvo:58364/62388/63163 的回归：缺 observed_exit 不能判 invalid。"""
        fake = self._fake_agent(
            {
                cb.BUNDLE_FILE: json.dumps(
                    {
                        "candidates": [
                            {
                                "file": "poc/vuln.bin",
                                "role": "candidate",
                                "replay": "docker run -v /poc:/tmp/poc:ro img /bin/arvo",
                                "verification": "verified",
                            }
                        ]
                    }
                ).encode(),
                "vuln.bin": b"V" * 64,
            }
        )
        with mock.patch.object(cb, "run_agent", fake):
            record = cb.run_one(
                self.task,
                self._args(),
                self._client({"vuln.bin": ("solved", 1, 0)}),
                self.work_root,
            )
        self.assertEqual(record["status"], "solved")
        self.assertIn(
            "missing_observed_exit", record["submissions"][0]["warnings"]
        )

    def test_diagnostic_only_sources_are_not_submitted(self):
        """bundle invalid 时不得回退到 .log / evidence.md / corpus。"""

        def fake(task, task_root, args):
            poc_dir = task_root / "task" / "poc"
            write_file(poc_dir / "run.log", b"not a poc" * 16)
            write_file(poc_dir / "seed.bin", b"S" * 64)
            (poc_dir / cb.BUNDLE_FILE).write_text(
                json.dumps(
                    {
                        "candidates": [
                            {
                                "file": "poc/missing.bin",
                                "role": "final_candidate",
                                "replay": "docker run -v /poc:/tmp/poc:ro img /bin/arvo",
                            }
                        ]
                    }
                ),
                encoding="utf-8",
            )
            return cb.RunOutcome(
                "completed",
                0,
                10.0,
                {
                    "status": "completed",
                    "findings": [
                        {
                            "id": "VULN-001",
                            "description": "evidence_refs=poc/run.log",
                        }
                    ],
                },
                "",
            )

        class ExplodingClient:
            def evaluate(self, **_kwargs):
                raise AssertionError("diagnostic sources must not be submitted")

        with mock.patch.object(cb, "run_agent", fake):
            record = cb.run_one(
                self.task, self._args(), ExplodingClient(), self.work_root
            )
        self.assertEqual(record["status"], "bundle_invalid")
        self.assertEqual(record["submissions"], [])
        self.assertTrue(record["diagnostic_only"])

    def test_no_bundle_but_scan_candidates_reports_no_poc(self):
        fake = self._fake_agent({"seed.bin": b"S" * 64})

        class ExplodingClient:
            def evaluate(self, **_kwargs):
                raise AssertionError("scan candidates must not be submitted")

        with mock.patch.object(cb, "run_agent", fake):
            record = cb.run_one(
                self.task, self._args(), ExplodingClient(), self.work_root
            )
        self.assertEqual(record["status"], "no_poc")
        self.assertEqual(record["submissions"], [])

    def test_fix_also_crashes_retries_truncated_variant(self):
        (self.data_dir / "error.txt").write_text(
            "SUMMARY: AddressSanitizer: heap-buffer-overflow /src/x.c:10 in target_func\n"
            "DEDUP_TOKEN: target_func--caller_a--caller_b\n",
            encoding="utf-8",
        )
        fake = self._fake_agent(
            {
                cb.BUNDLE_FILE: json.dumps(
                    {
                        "candidates": [
                            {
                                "file": "poc/crash.bin",
                                "role": "final_candidate",
                                "replay": "docker run -v /poc:/tmp/poc:ro img /bin/arvo",
                                "observed_exit": 1,
                                "verification": "vulnerable_runtime_confirmed",
                            }
                        ]
                    }
                ).encode(),
                "crash.bin": b"C" * 64,
            }
        )
        output = (
            "SUMMARY: AddressSanitizer: heap-buffer-overflow /src/x.c:10 in target_func\n"
            "DEDUP_TOKEN: target_func--caller_a--caller_b\n"
        )
        client = self._client(
            {
                "crash.bin": ("fix_also_crashes", 1, 1),
                "crash.bin.min1": ("solved", 1, 0),
            },
            outputs={"crash.bin": output, "crash.bin.min1": output},
        )
        with mock.patch.object(cb, "run_agent", fake):
            record = cb.run_one(self.task, self._args(), client, self.work_root)
        self.assertEqual(record["status"], "solved")
        self.assertEqual(len(record["submissions"]), 2)
        self.assertTrue(record["submissions"][0]["minimize_hint"])
        self.assertEqual(
            record["submissions"][0]["minimized_variants"],
            ["crash.bin.min1", "crash.bin.min16"],
        )
        self.assertEqual(record["submissions"][1]["source"], "minimized")

    def test_blocked_gate_with_verified_candidate_is_submitted(self):
        def fake(task, task_root, args):
            poc_dir = task_root / "task" / "poc"
            write_file(poc_dir / "good.bin", b"G" * 64)
            (poc_dir / "manifest.json").write_text(
                json.dumps(
                    {
                        "pocs": [
                            {
                                "file": "poc/good.bin",
                                "rank": 1,
                                "verified_on_vul": True,
                            }
                        ]
                    }
                ),
                encoding="utf-8",
            )
            return cb.RunOutcome(
                "error",
                0,
                10.0,
                {"status": "error"},
                "TRILANE S1/S2 breadth gate unmet: hypothesis_pool=1/60",
            )

        with mock.patch.object(cb, "run_agent", fake):
            record = cb.run_one(
                self.task,
                self._args(),
                self._client({"good.bin": ("solved", 1, 0)}),
                self.work_root,
            )
        self.assertEqual(record["status"], "solved")
        self.assertTrue(record["submitted_from_blocked"])
        self.assertIn("breadth gate", record["blocked_reason"])

    def test_blocked_gate_without_verified_candidate_stays_failed(self):
        def fake(task, task_root, args):
            poc_dir = task_root / "task" / "poc"
            write_file(poc_dir / "guess.bin", b"U" * 64)
            return cb.RunOutcome(
                "error",
                0,
                10.0,
                {"status": "error"},
                "TRILANE S1/S2 breadth gate unmet",
            )

        with mock.patch.object(cb, "run_agent", fake):
            record = cb.run_one(
                self.task,
                self._args(),
                self._client({"guess.bin": ("solved", 1, 0)}),
                self.work_root,
            )
        self.assertEqual(record["status"], "agent_failed")
        self.assertFalse(record.get("submitted_from_blocked", False))

    def test_final_candidate_no_crash_falls_back_to_next_candidate(self):
        fake = self._fake_agent(
            {
                cb.BUNDLE_FILE: json.dumps(
                    {
                        "candidates": [
                            {"file": "poc/final.bin", "role": "final_candidate", "replay": "docker run -v /poc:/tmp/poc:ro img /bin/arvo"},
                            {"file": "poc/other.bin", "role": "candidate", "replay": "docker run -v /poc:/tmp/poc:ro img /bin/arvo"},
                        ]
                    }
                ).encode(),
                "final.bin": b"F" * 64,
                "other.bin": b"O" * 64,
            }
        )
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
        self.assertEqual(record["status"], "solved")
        self.assertEqual(len(record["submissions"]), 2)
        self.assertEqual(record["fallback_after_no_crash"], ["task/poc/final.bin"])
        self.assertEqual(record["unverified_final"], ["task/poc/final.bin"])


class CrashSignatureTests(unittest.TestCase):
    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self.task_root = build_task_root(Path(self._tmp.name))
        self.path = write_file(
            self.task_root / "task" / "poc" / "x.bin", b"X" * 64
        )

    def tearDown(self):
        self._tmp.cleanup()

    def test_parse_signature(self):
        signature = cb._parse_crash_signature(
            "==1==ERROR: AddressSanitizer: heap-buffer-overflow\n"
            "    #0 0x4a0123 in target_func /src/x.c:10:2\n"
            "    #1 0x4a0456 in caller_a /src/x.c:20:1\n"
            "SUMMARY: AddressSanitizer: heap-buffer-overflow /src/x.c:10 in target_func\n"
            "DEDUP_TOKEN: target_func--caller_a--caller_b\n"
        )
        self.assertIn("target_func", signature["summary"])
        self.assertEqual(signature["dedup"], "target_func--caller_a--caller_b")
        self.assertEqual(signature["frames"][:2], ["target_func", "caller_a"])

    def test_signature_match_and_mismatch(self):
        official = {
            "summary": "AddressSanitizer: heap-buffer-overflow /src/x.c:10 in target_func",
            "dedup": "target_func--caller_a--caller_b",
            "frames": ["target_func"],
        }
        self.assertTrue(
            cb.signature_matches(
                {"dedup": "target_func--caller_a--caller_b", "frames": []}, official
            )
        )
        self.assertFalse(
            cb.signature_matches(
                {"dedup": "other_func--caller_c--caller_d", "frames": []}, official
            )
        )
        self.assertIsNone(cb.signature_matches({"dedup": "x"}, {}))

    def test_evaluate_parses_signature_beyond_output_head(self):
        """崩溃签名在 400 字节之后也要能取到（真实输出实测在 2.5KB 处）。"""
        long_output = (
            "INFO: Running with entropic power schedule (0xFF, 100).\n"
            + "filler line\n" * 80
            + "==1==ERROR: AddressSanitizer: heap-buffer-overflow\n"
            "    #0 0x4a0123 in target_func /src/x.c:10:2\n"
            "SUMMARY: AddressSanitizer: heap-buffer-overflow /src/x.c:10 in target_func\n"
            "DEDUP_TOKEN: target_func--caller_a--caller_b\n"
        )
        self.assertGreater(long_output.find("SUMMARY:"), 400)

        class FakeResponse:
            status_code = 200

            def json(self):
                return {"poc_id": "poc-1", "exit_code": 1, "output": long_output}

        client = cb.SubmitClient(
            "http://127.0.0.1:8666", api_key="k", salt="CyberGym", agent_id="agent-1"
        )
        client.fix_verification = False  # 跳过私有 fix 侧路由
        with mock.patch.object(cb.requests, "post", return_value=FakeResponse()):
            outcome = client.evaluate(
                masked_id="masked-1",
                real_task_id="arvo:1",
                poc=self.path,
                rounds=1,
            )

        row = outcome["rounds"][0]
        self.assertEqual(len(row["output_head"]), 400)
        self.assertEqual(
            row["crash_signature"]["dedup"], "target_func--caller_a--caller_b"
        )
        self.assertEqual(row["crash_signature"]["frames"][0], "target_func")

    def _candidate(self, **overrides) -> cb.PocCandidate:
        values = {
            "path": self.path,
            "source": "bundle",
            "role": cb.ROLE_FINAL,
            "sha256": cb._sha256_file(self.path),
            "observed_exit": 1,
            "verification": "vulnerable_runtime_confirmed",
            "replay": "docker run -v /poc:/tmp/poc:ro img /bin/arvo",
        }
        values.update(overrides)
        return cb.PocCandidate(**values)

    def test_validate_arvo_candidate(self):
        task = cb.TaskRef(
            "arvo:3938", "m", "arvo_3938", Path("data"), "d", "img", "arvo"
        )
        issues, warnings = cb.validate_candidate(
            self.task_root, task, self._candidate()
        )
        self.assertEqual(issues, [])
        self.assertEqual(warnings, [])

    def test_validate_rejects_missing_mount_and_entrypoint(self):
        task = cb.TaskRef(
            "arvo:3938", "m", "arvo_3938", Path("data"), "d", "img", "arvo"
        )
        missing_mount = self._candidate(
            replay="docker run img /bin/arvo"
        )
        issues, _ = cb.validate_candidate(self.task_root, task, missing_mount)
        self.assertIn("missing_poc_mount", issues)
        missing_bin = self._candidate(
            replay="docker run -v /poc:/tmp/poc:ro img"
        )
        issues, _ = cb.validate_candidate(self.task_root, task, missing_bin)
        self.assertIn("missing_bin_arvo", issues)

    def test_validate_reads_all_mounts_not_only_first(self):
        """tracer 挂在前面、PoC 挂在后面时不能误报 missing_poc_mount（arvo:62183）。"""
        task = cb.TaskRef(
            "arvo:3938", "m", "arvo_3938", Path("data"), "d", "img", "arvo"
        )
        candidate = self._candidate(
            replay=(
                "docker run --rm -v /host/task/trace/tracer_fdiv:/trace:ro "
                "-v /host/task/poc/p.bin:/tmp/poc:ro --network none img /bin/arvo"
            )
        )
        issues, warnings = cb.validate_candidate(
            self.task_root, task, candidate
        )
        self.assertEqual(issues, [])
        self.assertEqual(warnings, [])

    def test_validate_accepts_indirect_tmp_in_cp(self):
        """arvo:62261：文件挂到 /tmp/in，再 cp 到 /tmp/poc，不能误判。"""
        task = cb.TaskRef(
            "arvo:62261", "m", "arvo_62261", Path("data"), "d", "img", "arvo"
        )
        poc = write_file(
            self.task_root / "task" / "poc" / "vuln-001.bin", b"V" * 64
        )
        replay = (
            "docker run --rm --label trilane.task=431baaa1d310 "
            "-v /host/task/poc/vuln-001.bin:/tmp/in:ro --network none "
            "n132/arvo:62261-vul /bin/sh -c "
            "'cp /tmp/in /tmp/poc && /bin/arvo'"
        )
        candidate = self._candidate(
            path=poc, sha256=cb._sha256_file(poc), replay=replay
        )
        self.assertEqual(
            cb._classify_replay(replay, candidate, self.task_root),
            "indirect_mount",
        )
        issues, warnings = cb.validate_candidate(
            self.task_root, task, candidate
        )
        self.assertEqual(issues, [])
        self.assertEqual(warnings, [])

    def test_validate_accepts_interactive_stdin_replay(self):
        """arvo:66679：docker run -i + cat 候选，经 stdin 写入 /work/poc。"""
        task = cb.TaskRef(
            "arvo:66679", "m", "arvo_66679", Path("data"), "d", "img", "arvo"
        )
        poc = write_file(
            self.task_root / "task" / "poc" / "cand_uaf_min.bin", b"U" * 64
        )
        replay = (
            "cat poc/cand_uaf_min.bin | docker run --rm "
            "--label trilane.task=30b6823e6c24 -i --network none "
            "n132/arvo:66679-vul /bin/sh -c "
            "'sed \"s#/tmp/poc#/work/poc#g\" /bin/arvo > /work/arvo_replay; "
            "chmod +x /work/arvo_replay; cat > /work/poc; /work/arvo_replay'"
        )
        candidate = self._candidate(
            path=poc, sha256=cb._sha256_file(poc), replay=replay
        )
        self.assertEqual(
            cb._classify_replay(replay, candidate, self.task_root), "stdin"
        )
        issues, warnings = cb.validate_candidate(
            self.task_root, task, candidate
        )
        self.assertEqual(issues, [])
        self.assertEqual(warnings, [])

    def test_validate_rejects_natural_language_replay(self):
        """arvo:62183：replay 写成自然语言，不能放行。"""
        task = cb.TaskRef(
            "arvo:62183", "m", "arvo_62183", Path("data"), "d", "img", "arvo"
        )
        poc = write_file(
            self.task_root / "task" / "poc" / "s5_final_eqx.bin", b"S" * 64
        )
        replay = (
            "mount poc/s5_final_eqx.bin at /tmp/poc:ro; "
            "run /bin/arvo in n132/arvo:62183-vul with --network none"
        )
        candidate = self._candidate(
            path=poc, sha256=cb._sha256_file(poc), replay=replay
        )
        self.assertEqual(
            cb._classify_replay(replay, candidate, self.task_root),
            "invalid_replay",
        )
        issues, _ = cb.validate_candidate(self.task_root, task, candidate)
        self.assertIn("invalid_replay", issues)

    def test_validate_rejects_replay_for_other_file(self):
        """replay 里出现别的文件名时，不能因为形态像就放行。"""
        task = cb.TaskRef(
            "arvo:62261", "m", "arvo_62261", Path("data"), "d", "img", "arvo"
        )
        poc = write_file(
            self.task_root / "task" / "poc" / "good.bin", b"G" * 64
        )
        replay = (
            "docker run --rm -v /host/task/poc/other.bin:/tmp/in:ro "
            "--network none n132/arvo:62261-vul /bin/sh -c "
            "'cp /tmp/in /tmp/poc && /bin/arvo'"
        )
        candidate = self._candidate(
            path=poc, sha256=cb._sha256_file(poc), replay=replay
        )
        self.assertEqual(
            cb._classify_replay(replay, candidate, self.task_root),
            "replay_input_mismatch",
        )
        issues, _ = cb.validate_candidate(self.task_root, task, candidate)
        self.assertIn("replay_input_mismatch", issues)

    def test_validate_unknown_replay_falls_back_to_verification(self):
        """形态未识别但本地已复现时，只记 warning，交给官方 verifier。"""
        task = cb.TaskRef(
            "arvo:3938", "m", "arvo_3938", Path("data"), "d", "img", "arvo"
        )
        candidate = self._candidate(
            replay="docker run -v /host/task/poc/p.bin:/mnt:ro img /bin/arvo"
        )
        issues, warnings = cb.validate_candidate(
            self.task_root, task, candidate
        )
        self.assertEqual(issues, [])
        self.assertIn("missing_poc_mount", warnings)

    def test_validate_oss_fuzz_rejects_bin_arvo(self):
        task = cb.TaskRef(
            "oss-fuzz:1", "m", "oss_fuzz_1", Path("data"), "d", "img", "oss-fuzz"
        )
        candidate = self._candidate(
            replay="docker run -v /poc:/tmp/poc:ro img /bin/arvo"
        )
        issues, _ = cb.validate_candidate(self.task_root, task, candidate)
        self.assertIn("unexpected_bin_arvo_for_oss_fuzz", issues)

    def test_missing_observed_exit_is_warning_only(self):
        """observed_exit 缺失只记警告：官方向量本来会在 vul/fix 两侧重跑。"""
        task = cb.TaskRef(
            "arvo:3938", "m", "arvo_3938", Path("data"), "d", "img", "arvo"
        )
        candidate = self._candidate(observed_exit=None)
        issues, warnings = cb.validate_candidate(
            self.task_root, task, candidate
        )
        self.assertEqual(issues, [])
        self.assertIn("missing_observed_exit", warnings)

    def test_declared_sha256_mismatch_is_warning_only(self):
        task = cb.TaskRef(
            "arvo:3938", "m", "arvo_3938", Path("data"), "d", "img", "arvo"
        )
        candidate = self._candidate(declared_sha256="0" * 64)
        issues, warnings = cb.validate_candidate(
            self.task_root, task, candidate
        )
        self.assertEqual(issues, [])
        self.assertIn("sha256_mismatch", warnings)


if __name__ == "__main__":
    unittest.main()
