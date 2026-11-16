"""撞墙钟超时后续跑逻辑的单元测试。

跑法（不需要 Docker、不需要数据集）：

    python -m unittest discover -s deploy/tests -v
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


def make_run(root: Path, stages, status: str = "Running", run_id: str = "trilane-20261115-161706") -> Path:
    """在 <root>/runs/<run_id>/ 下铺 stage 目录。root 指 state/trilane。"""
    run_dir = root / "runs" / run_id
    for stage in stages:
        d = run_dir / stage
        d.mkdir(parents=True)
        (d / "runbook.json").write_text(
            json.dumps({"current_stage": stage}), encoding="utf-8"
        )
        (d / "status.json").write_text(
            json.dumps({"status": status}), encoding="utf-8"
        )
    return run_dir


def build_data_dir(root: Path) -> Path:
    """最小的 arvo 任务数据包：description.txt + repo-vul.tar.gz。"""
    data = root / "data" / "arvo" / "3938"
    data.mkdir(parents=True)
    (data / "description.txt").write_text("fake description", encoding="utf-8")
    with tarfile.open(data / "repo-vul.tar.gz", "w:gz") as tar:
        payload = b"int main(void){return 0;}\n"
        info = tarfile.TarInfo("file.c")
        info.size = len(payload)
        tar.addfile(info, io.BytesIO(payload))
    return data


class FindResumePointTests(unittest.TestCase):
    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self.root = Path(self._tmp.name)
        self.state = self.root / "state" / "trilane"

    def tearDown(self):
        self._tmp.cleanup()

    def test_no_runs_dir(self):
        self.assertIsNone(cb.find_resume_point(self.root, {}))

    def test_stage_from_result_active(self):
        make_run(self.state, ["stage0", "stage1", "stage2", "stage3"])
        result = {
            "stages": [
                {"id": "stage0", "status": "done"},
                {"id": "stage1", "status": "done"},
                {"id": "stage2", "status": "active"},
                {"id": "stage3", "status": "pending"},
            ]
        }
        self.assertEqual(
            cb.find_resume_point(self.root, result),
            ("trilane-20261115-161706", "stage2"),
        )

    def test_stage_from_dirs_fallback(self):
        make_run(self.state, ["stage0", "stage1", "stage2"])
        self.assertEqual(
            cb.find_resume_point(self.root, {}),
            ("trilane-20261115-161706", "stage2"),
        )

    def test_completed_stage_moves_to_next(self):
        run_dir = make_run(self.state, ["stage0", "stage1", "stage2"], status="Running")
        (run_dir / "stage2" / "status.json").write_text(
            json.dumps({"status": "Completed"}), encoding="utf-8"
        )
        self.assertEqual(
            cb.find_resume_point(self.root, {}),
            ("trilane-20261115-161706", "stage3"),
        )

    def test_all_stages_done(self):
        run_dir = make_run(self.state, list(cb.STAGE_IDS), status="Running")
        (run_dir / "stage5" / "status.json").write_text(
            json.dumps({"status": "Completed"}), encoding="utf-8"
        )
        self.assertIsNone(cb.find_resume_point(self.root, {}))

    def test_corrupt_source_runbook(self):
        run_dir = make_run(self.state, ["stage0", "stage1", "stage2"])
        (run_dir / "stage1" / "runbook.json").write_text("{not json", encoding="utf-8")
        result = {"stages": [{"id": "stage2", "status": "active"}]}
        self.assertIsNone(cb.find_resume_point(self.root, result))

    def test_missing_source_runbook(self):
        run_dir = make_run(self.state, ["stage0", "stage1", "stage2"])
        (run_dir / "stage1" / "runbook.json").unlink()
        result = {"stages": [{"id": "stage2", "status": "active"}]}
        self.assertIsNone(cb.find_resume_point(self.root, result))

    def test_stage0_is_never_resumed(self):
        make_run(self.state, ["stage0"])
        self.assertIsNone(cb.find_resume_point(self.root, {}))
        self.assertIsNone(
            cb.find_resume_point(
                self.root, {"stages": [{"id": "stage0", "status": "active"}]}
            )
        )

    def test_stage1_is_resumable(self):
        make_run(self.state, ["stage0", "stage1"])
        self.assertEqual(
            cb.find_resume_point(self.root, {}),
            ("trilane-20261115-161706", "stage1"),
        )

    def test_picks_newest_run_id(self):
        make_run(self.state, ["stage0", "stage1"], run_id="trilane-20260101-000000")
        make_run(self.state, ["stage0", "stage1"], run_id="trilane-20260202-000000")
        self.assertEqual(
            cb.find_resume_point(self.root, {})[0], "trilane-20260202-000000"
        )

    def test_ignores_invalid_run_id(self):
        make_run(self.state, ["stage0", "stage1"], run_id="bad run!")
        self.assertIsNone(cb.find_resume_point(self.root, {}))


class DirectiveTests(unittest.TestCase):
    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self.root = Path(self._tmp.name)
        task_dir = self.root / "task"
        task_dir.mkdir()
        (task_dir / "TASK.md").write_text(
            "# CyberGym Level 1 task `abc`\n\nbody text\n", encoding="utf-8"
        )
        self.task_md = task_dir / "TASK.md"

    def tearDown(self):
        self._tmp.cleanup()

    def _first_line(self) -> str:
        return next(
            line
            for line in self.task_md.read_text(encoding="utf-8").splitlines()
            if line.strip()
        )

    def test_directive_is_first_line(self):
        cb.apply_resume_directive(self.root, "trilane-20261115-161706", "stage3")
        self.assertEqual(
            self._first_line(),
            "TRILANE_RESUME_RUN% run=trilane-20261115-161706 stage=stage3",
        )

    def test_body_preserved(self):
        cb.apply_resume_directive(self.root, "trilane-20261115-161706", "stage3")
        text = self.task_md.read_text(encoding="utf-8")
        self.assertIn("# CyberGym Level 1 task `abc`\n\nbody text", text)

    def test_repeated_apply_does_not_stack(self):
        for _ in range(3):
            cb.apply_resume_directive(self.root, "trilane-20261115-161706", "stage4")
        text = self.task_md.read_text(encoding="utf-8")
        directives = [
            line for line in text.splitlines() if line.startswith("TRILANE_RESUME_RUN%")
        ]
        self.assertEqual(len(directives), 1)
        self.assertEqual(
            directives[0],
            "TRILANE_RESUME_RUN% run=trilane-20261115-161706 stage=stage4",
        )


class ArchiveTests(unittest.TestCase):
    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self.root = Path(self._tmp.name)
        self.out = self.root / "out"
        self.out.mkdir()

    def tearDown(self):
        self._tmp.cleanup()

    def test_archives_previous_outputs(self):
        (self.out / "result.json").write_text("{}", encoding="utf-8")
        (self.out / "report.md").write_text("# r", encoding="utf-8")
        cb.archive_attempt_outputs(self.root, 1)
        self.assertFalse((self.out / "result.json").exists())
        self.assertTrue((self.out / "result.json.attempt1").exists())
        self.assertTrue((self.out / "report.md.attempt1").exists())

    def test_noop_when_nothing_to_archive(self):
        cb.archive_attempt_outputs(self.root, 2)  # 不应抛异常


class RunOneRetryTests(unittest.TestCase):
    """run_one 的重试决策：模拟 run_agent，不启动容器。"""

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
        cb.time.sleep = lambda _seconds: None  # 跳过重试等待

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

    def _fake_agent(self, calls: dict, *, fail_status: str = "timeout",
                    duration: float = 3600.0):
        def fake(task, task_root, args):
            calls["n"] += 1
            run_dir = (
                task_root / "state" / "trilane" / "runs" / "trilane-20261115-161706"
            )
            for stage in ("stage0", "stage1", "stage2"):
                d = run_dir / stage
                d.mkdir(parents=True, exist_ok=True)
                (d / "runbook.json").write_text("{}", encoding="utf-8")
                (d / "status.json").write_text(
                    json.dumps({"status": "Running"}), encoding="utf-8"
                )
            out = task_root / "out"
            out.mkdir(parents=True, exist_ok=True)
            (out / "result.json").write_text(
                json.dumps(
                    {
                        "status": fail_status,
                        "stages": [{"id": "stage2", "status": "active"}],
                    }
                ),
                encoding="utf-8",
            )
            if calls["n"] > 1:
                first = next(
                    line
                    for line in (task_root / "task" / "TASK.md")
                    .read_text(encoding="utf-8")
                    .splitlines()
                    if line.strip()
                )
                calls["directive"] = first
                calls["archived"] = (out / "result.json.attempt1").exists()
                return cb.RunOutcome(
                    "completed", 0, 600.0, {"status": "completed", "findings": []}, ""
                )
            return cb.RunOutcome(
                fail_status, None, duration,
                {"stages": [{"id": "stage2", "status": "active"}]}, "假失败",
            )

        return fake

    def _run(self, args, fake):
        with mock.patch.object(cb, "run_agent", fake):
            return cb.run_one(self.task, args, client=object(), out_root=self.work_root)

    def test_timeout_resumes_from_stage(self):
        calls = {"n": 0}
        record = self._run(self._args(resume="timeout", agent_retries=1),
                           self._fake_agent(calls))
        self.assertEqual(calls["n"], 2)
        self.assertEqual(
            calls["directive"],
            "TRILANE_RESUME_RUN% run=trilane-20261115-161706 stage=stage2",
        )
        self.assertTrue(calls["archived"])
        self.assertEqual(len(record["resume_attempts"]), 1)
        entry = record["resume_attempts"][0]
        self.assertEqual(entry["from_stage"], "stage2")
        self.assertEqual(entry["previous_status"], "timeout")
        self.assertEqual(entry["outcome"], "completed")
        self.assertEqual(record["agent_attempts"], 2)

    def test_resume_off_does_not_retry_timeout(self):
        calls = {"n": 0}
        record = self._run(self._args(resume="off", agent_retries=3),
                           self._fake_agent(calls))
        self.assertEqual(calls["n"], 1)
        self.assertEqual(record["resume_attempts"], [])

    def test_wall_clock_guard_stops_retry(self):
        calls = {"n": 0}
        self._run(
            self._args(resume="timeout", agent_retries=3, task_wall_clock_sec=7000),
            self._fake_agent(calls, duration=7200.0),
        )
        self.assertEqual(calls["n"], 1)

    def test_retries_until_budget(self):
        calls = {"n": 0}

        def always_timeout(task, task_root, args):
            calls["n"] += 1
            run_dir = (
                task_root / "state" / "trilane" / "runs" / "trilane-20261115-161706"
            )
            for stage in ("stage0", "stage1", "stage2"):
                d = run_dir / stage
                d.mkdir(parents=True, exist_ok=True)
                (d / "runbook.json").write_text("{}", encoding="utf-8")
                (d / "status.json").write_text(
                    json.dumps({"status": "Running"}), encoding="utf-8"
                )
            return cb.RunOutcome(
                "timeout", None, 60.0,
                {"stages": [{"id": "stage2", "status": "active"}]}, "一直超时",
            )

        self._run(self._args(resume="timeout", agent_retries=3), always_timeout)
        self.assertEqual(calls["n"], 4)  # 1 + 3 次重试

    def test_timeout_without_archive_does_not_retry(self):
        calls = {"n": 0}

        def timeout_no_archive(task, task_root, args):
            calls["n"] += 1
            return cb.RunOutcome("timeout", None, 3600.0, {}, "无存档超时")

        self._run(self._args(resume="timeout", agent_retries=3), timeout_no_archive)
        self.assertEqual(calls["n"], 1)

    def _seed_interrupted_run(self):
        """铺一份"上次进程被杀"的存档：stage2 正在跑。"""
        run_dir = (
            self.work_root
            / "arvo_3938"
            / "state"
            / "trilane"
            / "runs"
            / "trilane-20261115-161706"
        )
        for stage in ("stage0", "stage1", "stage2"):
            d = run_dir / stage
            d.mkdir(parents=True)
            (d / "runbook.json").write_text("{}", encoding="utf-8")
            (d / "status.json").write_text(
                json.dumps({"status": "Running"}), encoding="utf-8"
            )

    def _first_directive_agent(self, calls: dict):
        def fake(task, task_root, args):
            calls["n"] += 1
            calls["directive"] = next(
                line
                for line in (task_root / "task" / "TASK.md")
                .read_text(encoding="utf-8")
                .splitlines()
                if line.strip()
            )
            return cb.RunOutcome(
                "completed", 0, 600.0, {"status": "completed", "findings": []}, ""
            )

        return fake

    def test_restart_resumes_on_first_attempt(self):
        """compose 重启后首轮就带续跑指令（results.jsonl 里没有记录）。"""
        self._seed_interrupted_run()
        calls = {"n": 0}
        record = self._run(
            self._args(resume="timeout", agent_retries=1),
            self._first_directive_agent(calls),
        )
        self.assertEqual(calls["n"], 1)
        self.assertEqual(
            calls["directive"],
            "TRILANE_RESUME_RUN% run=trilane-20261115-161706 stage=stage2",
        )
        self.assertEqual(len(record["resume_attempts"]), 1)
        self.assertEqual(
            record["resume_attempts"][0]["previous_status"], "interrupted"
        )
        self.assertEqual(record["resume_attempts"][0]["outcome"], "completed")

    def test_restart_does_not_resume_when_off(self):
        self._seed_interrupted_run()
        calls = {"n": 0}
        self._run(
            self._args(resume="off", agent_retries=1),
            self._first_directive_agent(calls),
        )
        self.assertFalse(calls["directive"].startswith("TRILANE_RESUME_RUN%"))

    def test_fresh_task_has_no_directive(self):
        calls = {"n": 0}
        record = self._run(
            self._args(resume="timeout", agent_retries=1),
            self._first_directive_agent(calls),
        )
        self.assertEqual(
            record["resume_attempts"], [], "全新任务不应产生续跑记录"
        )
        self.assertFalse(calls["directive"].startswith("TRILANE_RESUME_RUN%"))


if __name__ == "__main__":
    unittest.main(verbosity=2)
