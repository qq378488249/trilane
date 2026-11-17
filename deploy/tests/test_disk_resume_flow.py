"""磁盘满 + 续跑的端到端（Python 层）回归测试。

前面的 test_disk_space.py 只测 detect_disk_space_error 这个函数本身。这里往上走一层：
真实调用 run_agent()，只把 Docker 相关的东西（start_dind / run_agent_in_dind / stop_dind）
换成假的，让**快照 → 执行 → 检测**这条完整链路真的跑一遍。

覆盖三个场景：
1. 首次执行时磁盘满 → 判 disk_space；
2. 清盘后重跑，transcript 追加了新内容但没有新的 ENOSPC → 不该再判 disk_space；
3. 续跑时引擎删掉 stage 重建（文件变小）并写入新的 ENOSPC → 必须判出来。
"""

from __future__ import annotations

import json
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

import cybergym_batch as cb  # noqa: E402

ENOSPC = "docker: Error response from daemon: write /var/lib/docker/tmp: no space left on device"
RUN_ID = "trilane-20260101-000000"


class FakeAgent:
    """替代 run_agent_in_dind：在当前 stage 的 transcript 里写字，然后返回退出码。"""

    def __init__(self, transcript: Path, writes: str, *, recreate: bool = False):
        self.transcript = transcript
        self.writes = writes
        self.recreate = recreate
        self.calls = 0

    def __call__(self, handle, *, container, image, task_slug, d_task, d_out, d_state, args, log_path):
        self.calls += 1
        self.transcript.parent.mkdir(parents=True, exist_ok=True)
        if self.recreate and self.transcript.exists():
            self.transcript.unlink()
            self.transcript.write_text("# recreated\n", encoding="utf-8")
        with self.transcript.open("a", encoding="utf-8") as handle_out:
            handle_out.write(self.writes)
        return 0


class DiskResumeFlowTests(unittest.TestCase):
    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self.root = Path(self._tmp.name)
        self.task_root = self.root / "arvo_3938"
        self.state_dir = self.task_root / "state" / "trilane"
        self.stage_dir = self.state_dir / "runs" / RUN_ID / "stage2"
        self.stage_dir.mkdir(parents=True)
        self.transcript = self.stage_dir / "transcript.md"
        (self.task_root / "out").mkdir(parents=True)
        (self.task_root / "task").mkdir(parents=True)

        self.task = cb.TaskRef(
            "arvo:3938", "a5c9210adf28", "arvo_3938",
            self.root / "data", "fake", "n132/arvo:3938-vul",
        )
        self.args = cb.parse_args([
            "--task-id", "arvo:3938",
            "--data-dir", str(self.root / "data"),
            "--work-root", str(self.root),
            "--trilane-home", str(self.root),
        ])

    def tearDown(self):
        self._tmp.cleanup()

    def _run(self, fake: FakeAgent):
        # 只替换和 Docker 交互的部分，run_agent 自身的逻辑（快照、检测）保持真实。
        with mock.patch.object(cb, "start_dind", lambda *a, **k: mock.MagicMock(name="dind")), \
             mock.patch.object(cb, "wait_dind", lambda *a, **k: True), \
             mock.patch.object(cb, "load_image_into_dind", lambda *a, **k: None), \
             mock.patch.object(cb, "stop_dind", lambda *a, **k: None), \
             mock.patch.object(cb, "run_agent_in_dind", fake):
            return cb.run_agent(self.task, self.task_root, self.args)

    def test_first_attempt_with_disk_full(self):
        """首次执行就撞 ENOSPC → 判 disk_space。"""
        self.transcript.write_text("# header\n", encoding="utf-8")
        fake = FakeAgent(self.transcript, ENOSPC + "\n")
        outcome = self._run(fake)
        self.assertEqual(outcome.status, "disk_space")
        self.assertIn("no space left on device", outcome.detail)
        self.assertEqual(fake.calls, 1)

    def test_retry_after_clearing_does_not_report_again(self):
        """清盘后重跑：旧 ENOSPC 行还在文件里，但不该再判 disk_space。"""
        # 第 1 轮：真满
        self.transcript.write_text("# header\n", encoding="utf-8")
        first = self._run(FakeAgent(self.transcript, ENOSPC + "\n"))
        self.assertEqual(first.status, "disk_space")

        # 第 2 轮：transcript 被追加（mtime 变新），但没有新的 ENOSPC
        second = self._run(FakeAgent(self.transcript, "## next turn\ntool output ok\n"))
        self.assertNotEqual(second.status, "disk_space", "清盘后的重跑不该再报磁盘满")
        self.assertNotIn("no space left", second.detail)

    def test_resume_recreating_stage_still_detects_new_error(self):
        """续跑时引擎删掉 stage 重建（文件变小），新的 ENOSPC 必须报出来。"""
        self.transcript.write_text("x" * 5000, encoding="utf-8")
        first = self._run(FakeAgent(self.transcript, "ok\n"))
        self.assertNotEqual(first.status, "disk_space")

        # 第 2 轮：引擎重建文件（变小）并写入新的 ENOSPC
        second = self._run(FakeAgent(self.transcript, ENOSPC + "\n", recreate=True))
        self.assertEqual(second.status, "disk_space", "重建后的真实错误不能被漏掉")
        self.assertIn("no space left on device", second.detail)


class DiskSpaceBatchFlowTests(unittest.TestCase):
    """disk_space 落账后，下一批次会重跑（不被跳过）。"""

    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self.path = Path(self._tmp.name) / "results.jsonl"

    def tearDown(self):
        self._tmp.cleanup()

    def _append(self, status: str):
        record = {"task_id": "arvo:3736", "status": status, "agent_status": status}
        with self.path.open("a", encoding="utf-8") as handle:
            handle.write(json.dumps(record) + "\n")

    def test_disk_space_is_retried_next_batch(self):
        self._append("disk_space")
        self.assertNotIn("arvo:3736", cb.load_done(self.path))

    def test_solved_is_skipped_next_batch(self):
        self._append("solved")
        self.assertIn("arvo:3736", cb.load_done(self.path))


if __name__ == "__main__":
    unittest.main(verbosity=2)
