"""pre-agent scout 的单元测试。

跑法（不需要 Docker、不需要数据集）：

    python -m pytest deploy/tests/test_scout.py -q
"""

from __future__ import annotations

import argparse
import json
import subprocess
import sys
import tempfile
import time
import unittest
import zipfile
from pathlib import Path
from unittest import mock

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

import cybergym_batch as cb  # noqa: E402


def _args(**overrides) -> argparse.Namespace:
    values = {
        "agent_id": "test-agent",
        "seed_corpus": "on",
        "scout_mode": "quick",
        "scout_timeout_sec": 5,
        "scout_run_timeout_sec": 1,
        "scout_max_runs": 4,
        "scout_max_output_kb": 4,
        "scout_libfuzzer_sec": 1,
        "scout_max_artifacts": 2,
        "scout_max_candidate_mb": 1,
        "scout_max_log_mb": 1,
        "force_scout": False,
    }
    values.update(overrides)
    return argparse.Namespace(**values)


class ScoutClassifyTest(unittest.TestCase):
    def test_exit_code_classes(self) -> None:
        cases = {
            0: "no_crash",
            124: "timeout",
            300: "timeout",
            999: "timeout",
            137: "killed",
            125: "docker_error",
            126: "exec_error",
            127: "exec_error",
        }
        for code, expected in cases.items():
            verdict, _ = cb._classify_scout(code, False, "")
            self.assertEqual(verdict, expected, code)

    def test_sanitizer_is_crash(self) -> None:
        verdict, sanitizer = cb._classify_scout(
            1, False, "==1==ERROR: AddressSanitizer: heap-buffer-overflow"
        )
        self.assertEqual(verdict, "crash")
        self.assertTrue(sanitizer.startswith("AddressSanitizer"))

    def test_plain_nonzero_is_not_a_crash(self) -> None:
        verdict, sanitizer = cb._classify_scout(1, False, "usage: target <file>")
        self.assertEqual(verdict, "unknown_nonzero")
        self.assertEqual(sanitizer, "")

    def test_libfuzzer_callback_scaffold_error_is_not_a_crash(self) -> None:
        output = (
            "runtime error: call to function LLVMFuzzerTestOneInput through pointer "
            "to incorrect function type\n"
            "#0 fuzzer::Fuzzer::ExecuteCallback /src/libfuzzer/FuzzerLoop.cpp:471\n"
        )
        verdict, _ = cb._classify_scout(1, False, output)
        self.assertEqual(verdict, "scaffold_error")

    def test_timeout_wins(self) -> None:
        verdict, _ = cb._classify_scout(0, True, "AddressSanitizer")
        self.assertEqual(verdict, "timeout")


class ScoutBoundaryTest(unittest.TestCase):
    def test_variants_are_deterministic_and_bounded(self) -> None:
        data = b"ABCDEFGH"
        first = list(cb._scout_boundary_variants(data, limit=100))
        second = list(cb._scout_boundary_variants(data, limit=100))
        self.assertEqual([item[0] for item in first], [item[0] for item in second])
        self.assertLessEqual(len(first), 100)
        self.assertEqual(first[0][0], b"")
        self.assertEqual(first[0][1]["kind"], "truncate")
        self.assertTrue(any(item[1]["kind"] == "append" for item in first))
        self.assertTrue(any(item[1]["kind"] == "overwrite" for item in first))

    def test_limit_stops_early(self) -> None:
        self.assertEqual(len(list(cb._scout_boundary_variants(b"ABCD", limit=3))), 3)


class ScoutSeedsTest(unittest.TestCase):
    def setUp(self) -> None:
        self._tmp = tempfile.TemporaryDirectory()
        self.root = Path(self._tmp.name)
        self.seeds = self.root / "task" / "seeds"
        self.seeds.mkdir(parents=True)

    def tearDown(self) -> None:
        self._tmp.cleanup()

    def test_reads_only_when_seed_corpus_on(self) -> None:
        with zipfile.ZipFile(self.seeds / "f_seed_corpus.zip", "w") as archive:
            archive.writestr("a.bin", b"abc")
        self.assertEqual(cb._scout_seed_blobs(self.root, _args(seed_corpus="off")), [])
        blobs = cb._scout_seed_blobs(self.root, _args(seed_corpus="on"))
        self.assertEqual(len(blobs), 1)
        self.assertEqual(blobs[0].data, b"abc")
        self.assertIn("a.bin", blobs[0].parent)

    def test_bad_zip_is_ignored(self) -> None:
        (self.seeds / "bad_seed_corpus.zip").write_bytes(b"not a zip")
        self.assertEqual(cb._scout_seed_blobs(self.root, _args()), [])


class ScoutRunTest(unittest.TestCase):
    def setUp(self) -> None:
        self._tmp = tempfile.TemporaryDirectory()
        self.root = Path(self._tmp.name)
        (self.root / "task").mkdir()
        (self.root / "task" / "TASK.md").write_text("base prompt\n", encoding="utf-8")
        self.task = cb.TaskRef(
            task_id="arvo:1065",
            masked_id="masked",
            slug="arvo_1065",
            data_dir=self.root / "data",
            description="fake",
            vul_image="n132/arvo:1065-vul",
        )

    def tearDown(self) -> None:
        self._tmp.cleanup()

    def _fake_scout(self, task, args, *, stage, mounts, command, timeout, entrypoint=None):
        return cb.ScoutResult(stage=stage, name="fake", file="", verdict="no_crash")

    def test_off_does_nothing(self) -> None:
        summary = cb.run_scouts(self.task, self.root, _args(scout_mode="off"))
        self.assertEqual(summary, {})
        self.assertFalse((self.root / "task" / "scout").exists())

    def test_quick_run_writes_log_and_brief(self) -> None:
        with mock.patch.object(cb, "_scout_run", side_effect=self._fake_scout):
            summary = cb.run_scouts(self.task, self.root, _args(scout_mode="quick"))
        self.assertEqual(summary["mode"], "quick")
        self.assertEqual(summary["candidates"], 1)
        self.assertEqual(summary["stages"]["quick_try"]["ran"], 1)
        self.assertGreaterEqual(summary["duration_sec"], 0)
        self.assertTrue((self.root / "task" / "scout" / cb.SCOUT_LOG_NAME).is_file())
        prompt = (self.root / "task" / "TASK.md").read_text(encoding="utf-8")
        self.assertIn(cb.SCOUT_BRIEF_BEGIN, prompt)
        self.assertEqual(prompt.count(cb.SCOUT_BRIEF_BEGIN), 1)

    def test_brief_is_idempotent(self) -> None:
        with mock.patch.object(cb, "_scout_run", side_effect=self._fake_scout):
            summary = cb.run_scouts(self.task, self.root, _args(scout_mode="quick"))
            cb._append_scout_brief(self.root, summary)
        prompt = (self.root / "task" / "TASK.md").read_text(encoding="utf-8")
        self.assertEqual(prompt.count(cb.SCOUT_BRIEF_BEGIN), 1)
        self.assertEqual(prompt.count(cb.SCOUT_BRIEF_END), 1)

    def test_existing_log_is_reused(self) -> None:
        with mock.patch.object(cb, "_scout_run", side_effect=self._fake_scout) as scout:
            first = cb.run_scouts(self.task, self.root, _args(scout_mode="quick"))
        self.assertEqual(scout.call_count, 1)
        with mock.patch.object(cb, "_scout_run", side_effect=self._fake_scout) as scout:
            second = cb.run_scouts(self.task, self.root, _args(scout_mode="quick"))
        self.assertEqual(scout.call_count, 0)
        self.assertEqual(first["candidates"], second["candidates"])

    def test_force_scout_reruns(self) -> None:
        with mock.patch.object(cb, "_scout_run", side_effect=self._fake_scout):
            cb.run_scouts(self.task, self.root, _args(scout_mode="quick"))
        with mock.patch.object(cb, "_scout_run", side_effect=self._fake_scout) as scout:
            cb.run_scouts(self.task, self.root, _args(scout_mode="quick", force_scout=True))
        self.assertEqual(scout.call_count, 1)

    def test_scout_exec_uses_host_docker_and_network_none(self) -> None:
        args = _args()
        calls = []

        def fake_run(cmd, *, timeout=None):
            calls.append(cmd)
            return subprocess.CompletedProcess(cmd, 0, "", "")

        candidate = self.root / "task" / "candidate.bin"
        candidate.write_bytes(b"x")
        with mock.patch.object(cb, "run", fake_run):
            cb._scout_run(
                self.task,
                args,
                stage="quick_try",
                mounts=[(candidate, "/tmp/poc", "ro")],
                command=["/bin/arvo"],
                timeout=1,
            )
        self.assertEqual(len(calls), 1)
        cmd = calls[0]
        self.assertEqual(cmd[:2], ["docker", "run"])
        self.assertNotIn("exec", cmd[:3])
        self.assertIn("--network", cmd)
        self.assertIn("none", cmd)
        self.assertIn("trilane.role=scout", cmd)
        self.assertIn("n132/arvo:1065-vul", cmd)

    def test_directory_mode_retry(self) -> None:
        args = _args()
        candidate = self.root / "task" / "candidate.bin"
        candidate.write_bytes(b"x")
        calls = []

        def fake_run(cmd, *, timeout=None):
            calls.append(cmd)
            if len(calls) == 1:
                return subprocess.CompletedProcess(
                    cmd, 1, 'ERROR: The required directory "/tmp/poc" does not exist', ""
                )
            return subprocess.CompletedProcess(cmd, 0, "ok", "")

        with mock.patch.object(cb, "run", fake_run):
            result = cb._scout_run(
                self.task,
                args,
                stage="quick_try",
                mounts=[(candidate, "/tmp/poc", "ro")],
                command=["/bin/arvo"],
                timeout=1,
            )
        self.assertEqual(result.verdict, "no_crash")
        self.assertEqual(result.note, "directory_mode_retry")
        self.assertEqual(len(calls), 2)
        corpus_dir = candidate.parent / f"dir-{candidate.name}"
        self.assertTrue((corpus_dir / candidate.name).is_file())

    def test_log_size_fallback(self) -> None:
        with mock.patch.object(cb, "_scout_run", side_effect=self._fake_scout):
            summary = cb.run_scouts(
                self.task,
                self.root,
                _args(scout_mode="quick", scout_max_log_mb=1),
            )
        payload = json.loads(
            (self.root / "task" / "scout" / cb.SCOUT_LOG_NAME).read_text(encoding="utf-8")
        )
        self.assertEqual(payload["isolation"], "host")
        self.assertEqual(payload["log"], "scout/scout_log.json")
        self.assertEqual(summary["log"], "scout/scout_log.json")


class ScoutLibFuzzerTest(unittest.TestCase):
    def setUp(self) -> None:
        self._tmp = tempfile.TemporaryDirectory()
        self.root = Path(self._tmp.name)
        self.scout = self.root / "task" / "scout"
        self.scout.mkdir(parents=True)
        self.task = cb.TaskRef(
            task_id="oss-fuzz:1",
            masked_id="masked",
            slug="oss_fuzz_1",
            data_dir=self.root / "data",
            description="fake",
            vul_image="cybergym/oss-fuzz:1-vul",
            family="oss-fuzz",
        )
        self.seeds = [cb.ScoutSeed(name="seed", data=b"AAAA", parent="seeds/x.zip#a")]

    def tearDown(self) -> None:
        self._tmp.cleanup()

    def test_skips_without_canonical_fuzzer(self) -> None:
        with mock.patch.object(cb, "_scout_canonical_fuzzers", return_value=[]):
            results, info = cb._scout_libfuzzer(
                self.task,
                _args(scout_mode="full"),
                self.scout,
                cb.ScoutBudget(4, time.monotonic() + 5),
                self.seeds,
                self.root,
            )
        self.assertEqual(results, [])
        self.assertEqual(info["reason"], "no_canonical_fuzzer")

    def test_skips_when_target_is_not_libfuzzer(self) -> None:
        probe = cb.ScoutResult(
            stage="libfuzzer", name="probe", file="", exit_code=0, output_tail="not a fuzzer"
        )
        with (
            mock.patch.object(cb, "_scout_canonical_fuzzers", return_value=["f"]),
            mock.patch.object(cb, "_scout_run", return_value=probe),
        ):
            results, info = cb._scout_libfuzzer(
                self.task,
                _args(scout_mode="full"),
                self.scout,
                cb.ScoutBudget(4, time.monotonic() + 5),
                self.seeds,
                self.root,
            )
        self.assertEqual(results, [])
        self.assertEqual(info["reason"], "not_libfuzzer")

    def test_scaffold_campaign_does_not_promote_artifact(self) -> None:
        def fake_run(task, args, *, stage, mounts, command, timeout, entrypoint=None):
            if entrypoint == "/bin/sh":
                return cb.ScoutResult(
                    stage=stage, name="probe", file="", exit_code=0,
                    output_tail="max_total_time=60",
                )
            for host, target, mode in mounts:
                if target == "/artifacts":
                    (host / "crash-1").write_bytes(b"boom")
            return cb.ScoutResult(
                stage=stage, name="campaign", file="", exit_code=1,
                verdict="scaffold_error", sanitizer="UndefinedBehaviorSanitizer",
            )

        with (
            mock.patch.object(cb, "_scout_canonical_fuzzers", return_value=["f"]),
            mock.patch.object(cb, "_scout_run", side_effect=fake_run),
        ):
            results, info = cb._scout_libfuzzer(
                self.task,
                _args(scout_mode="full", scout_libfuzzer_sec=1),
                self.scout,
                cb.ScoutBudget(4, time.monotonic() + 5),
                self.seeds,
                self.root,
            )
        self.assertEqual([item.verdict for item in results], ["scaffold_error"])
        self.assertEqual(info["crashes"], 0)
        self.assertEqual(info["reason"], "scaffold_error")

    def test_collects_artifacts(self) -> None:
        def fake_run(task, args, *, stage, mounts, command, timeout, entrypoint=None):
            if entrypoint == "/bin/sh":
                return cb.ScoutResult(
                    stage=stage,
                    name="probe",
                    file="",
                    exit_code=0,
                    output_tail="max_total_time=60",
                )
            for host, target, mode in mounts:
                if target == "/artifacts":
                    (host / "crash-1").write_bytes(b"boom")
            return cb.ScoutResult(
                stage=stage,
                name="campaign",
                file="",
                exit_code=1,
                verdict="crash",
                sanitizer="AddressSanitizer",
            )

        with (
            mock.patch.object(cb, "_scout_canonical_fuzzers", return_value=["f"]),
            mock.patch.object(cb, "_scout_run", side_effect=fake_run),
        ):
            results, info = cb._scout_libfuzzer(
                self.task,
                _args(scout_mode="full", scout_libfuzzer_sec=1),
                self.scout,
                cb.ScoutBudget(4, time.monotonic() + 5),
                self.seeds,
                self.root,
            )
        self.assertEqual(len(results), 2)
        self.assertEqual(info["crashes"], 2)
        self.assertTrue(any(item.note == "libfuzzer artifact" for item in results))



class ScoutTimingTest(unittest.TestCase):
    def test_agent_duration_excludes_scout(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / "task").mkdir()
            (root / "out").mkdir()
            (root / "out" / "result.json").write_text(
                json.dumps({"status": "completed"}), encoding="utf-8"
            )
            task = cb.TaskRef(
                task_id="arvo:1",
                masked_id="masked",
                slug="arvo_1",
                data_dir=root / "data",
                description="fake",
                vul_image="n132/arvo:1-vul",
            )
            args = _args(
                isolation="host",
                disk_check=False,
                seed_corpus="off",
                scout_mode="quick",
                agent_image="agent",
                audit_mode="lab",
                timeout_sec=10,
            )
            scout_summary = {"mode": "quick", "status": "ok", "duration_sec": 80.0}
            class FakeProc:
                returncode = 0

                def wait(self, timeout=None):
                    return 0

            # run_agent: start=0, agent_started=100, agent end=110
            with (
                mock.patch.object(cb, "provision_seed_corpora", return_value=0),
                mock.patch.object(cb, "_run_scouts_safe", return_value=scout_summary),
                mock.patch.object(cb.subprocess, "Popen", return_value=FakeProc()),
                mock.patch.object(cb.time, "monotonic", side_effect=[0.0, 100.0, 110.0]),
            ):
                outcome = cb.run_agent(task, root, args)
            self.assertEqual(outcome.duration_sec, 10.0)
            self.assertEqual(outcome.scout, scout_summary)


if __name__ == "__main__":
    unittest.main()

