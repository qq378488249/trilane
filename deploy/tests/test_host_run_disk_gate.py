"""host 模式的运行盘预检：只查 WORK_ROOT，不查镜像盘。

不碰真实 Docker：host 分支只调 subprocess.Popen，这里换成假的。
"""

from __future__ import annotations

import sys
import tempfile
import threading
import unittest
from pathlib import Path
from unittest import mock

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

import cybergym_batch as cb  # noqa: E402

GB = 1_000_000_000


class CheckRunDiskSpaceTests(unittest.TestCase):
    def _check(self, *, free=None, run_space_gb=5.0, reserved_run=0, root="/runs"):
        with mock.patch.object(cb, "free_bytes", return_value=free):
            return cb.check_run_disk_space(root, run_space_gb, reserved_run=reserved_run)

    def test_enough(self):
        ok, detail, need = self._check(free=20 * GB)
        self.assertTrue(ok)
        self.assertEqual(need, 5 * GB)
        self.assertIn("运行盘（/runs）可用 20.0GB", detail)
        self.assertIn("需要 5.0GB", detail)
        self.assertIn("运行空间 5.0GB", detail)
        self.assertNotIn("其他任务预留", detail)
        self.assertNotIn("磁盘空间不足", detail)

    def test_short(self):
        ok, detail, need = self._check(free=4 * GB)
        self.assertFalse(ok)
        self.assertEqual(need, 5 * GB)
        self.assertIn("运行盘（/runs）可用 4.0GB", detail)
        self.assertIn("需要 5.0GB", detail)

    def test_counts_other_tasks_reservation(self):
        ok, detail, _ = self._check(free=8 * GB, reserved_run=5 * GB)
        self.assertFalse(ok, "还要算上其他在跑任务的预留")
        self.assertIn("需要 10.0GB", detail)
        self.assertIn("其他任务预留 5.0GB", detail)

    def test_unreadable_skips_without_reservation(self):
        ok, detail, need = self._check(free=None)
        self.assertTrue(ok)
        self.assertIsNone(need)
        self.assertIn("运行盘检查跳过", detail)


class DiskGateRunOnlyTests(unittest.TestCase):
    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self.root = Path(self._tmp.name)
        self.task_root = self.root / "arvo_3938"
        self.task_root.mkdir()
        self.task = cb.TaskRef(
            "arvo:3938", "masked", "arvo_3938",
            self.root / "data", "fake", "n132/arvo:3938-vul",
        )
        self.args = cb.parse_args(["--task-id", "arvo:3938"])
        self.args.disk_abort = threading.Event()
        self.args.disk_reserved = 0
        self.args.run_reserved = 0
        self.args.disk_lock = threading.Lock()

    def tearDown(self):
        self._tmp.cleanup()

    def _gate(self, free):
        with mock.patch.object(cb, "free_bytes", return_value=free):
            return cb.disk_gate(
                self.task, self.task_root, self.args, None, 0.0, run_only=True
            )

    def test_pass_reserves_run_space_only(self):
        self.args.disk_reserved = 11 * GB
        blocked, reserved = self._gate(20 * GB)
        self.assertIsNone(blocked)
        self.assertEqual(reserved, (0, 5 * GB))
        self.assertEqual(self.args.run_reserved, 5 * GB)
        self.assertEqual(self.args.disk_reserved, 11 * GB, "host 模式不动镜像盘预留")

    def test_pass_adds_to_existing_reservation(self):
        self.args.run_reserved = 7 * GB
        blocked, reserved = self._gate(20 * GB)
        self.assertIsNone(blocked)
        self.assertEqual(reserved, (0, 5 * GB))
        self.assertEqual(self.args.run_reserved, 12 * GB)

    def test_short_aborts_batch(self):
        self.args.run_reserved = 3 * GB
        blocked, reserved = self._gate(4 * GB)
        self.assertIsNotNone(blocked)
        self.assertEqual(blocked.status, "disk_space")
        self.assertTrue(blocked.detail.startswith("磁盘空间不足："))
        self.assertEqual(reserved, (0, 0))
        self.assertEqual(self.args.run_reserved, 3 * GB, "不足时不该预留")
        self.assertTrue(self.args.disk_abort.is_set())

    def test_unreadable_passes_without_reservation(self):
        blocked, reserved = self._gate(None)
        self.assertIsNone(blocked)
        self.assertEqual(reserved, (0, 0))
        self.assertEqual(self.args.run_reserved, 0)
        self.assertFalse(self.args.disk_abort.is_set())


class RunAgentHostModeTests(unittest.TestCase):
    """host 模式门禁的时机：拉起容器之前；运行期间保留预留，结束后释放。"""

    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self.root = Path(self._tmp.name)
        self.task_root = self.root / "arvo_3938"
        (self.task_root / "out").mkdir(parents=True)
        (self.task_root / "task").mkdir(parents=True)
        self.task = cb.TaskRef(
            "arvo:3938", "masked", "arvo_3938",
            self.root / "data", "fake", "n132/arvo:3938-vul",
        )
        self.args = cb.parse_args([
            "--task-id", "arvo:3938",
            "--isolation", "host",
            "--data-dir", str(self.root / "data"),
            "--work-root", str(self.root),
            "--trilane-home", str(self.root),
        ])
        self.args.disk_abort = threading.Event()
        self.args.disk_reserved = 0
        self.args.run_reserved = 0
        self.args.disk_lock = threading.Lock()
        self.seen: dict = {}

    def tearDown(self):
        self._tmp.cleanup()

    def _fake_popen(self):
        args = self.args
        seen = self.seen

        class FakePopen:
            def __init__(self, cmd, **kwargs):
                seen["cmd"] = cmd
                seen["run_reserved_at_start"] = args.run_reserved
                self.returncode = 0

            def wait(self, timeout=None):
                seen["run_reserved_at_wait"] = args.run_reserved
                return 0

        return FakePopen

    def _run(self, free, *, popen=None):
        popen = popen or self._fake_popen()
        # host 模式不该走 dind 的检查
        with mock.patch.object(
            cb, "check_dind_disk_space", side_effect=AssertionError("host 模式不该查镜像盘")
        ), mock.patch.object(cb, "free_bytes", return_value=free), \
             mock.patch.object(cb.subprocess, "Popen", popen):
            return cb.run_agent(self.task, self.task_root, self.args)

    def test_short_disk_blocks_before_starting_container(self):
        def explode(*args, **kwargs):
            raise AssertionError("磁盘不足时不该启动容器")

        outcome = self._run(1 * GB, popen=explode)
        self.assertEqual(outcome.status, "disk_space")
        self.assertTrue(self.args.disk_abort.is_set())
        self.assertEqual(self.args.run_reserved, 0)
        self.assertNotIn("cmd", self.seen)

    def test_enough_disk_reserves_during_run_and_releases_after(self):
        outcome = self._run(20 * GB)
        self.assertIn("cmd", self.seen)
        self.assertEqual(
            self.seen["run_reserved_at_start"], 5 * GB, "拉起容器时本任务的预留应已生效"
        )
        self.assertEqual(self.seen["run_reserved_at_wait"], 5 * GB)
        self.assertEqual(self.args.run_reserved, 0, "任务结束后预留要释放")
        self.assertFalse(self.args.disk_abort.is_set())
        self.assertEqual(outcome.status, "container_failed")  # 假容器没有 result.json

    def test_check_sees_other_tasks_reservation(self):
        self.args.run_reserved = 3 * GB
        outcome = self._run(7 * GB)  # 3 + 5 > 7
        self.assertEqual(outcome.status, "disk_space")
        self.assertEqual(self.args.run_reserved, 3 * GB)

    def test_disabled_skips_check(self):
        self.args.disk_check = False
        with mock.patch.object(
            cb, "check_run_disk_space", side_effect=AssertionError("关闭后不该检查")
        ), mock.patch.object(cb.subprocess, "Popen", self._fake_popen()):
            outcome = cb.run_agent(self.task, self.task_root, self.args)
        self.assertEqual(self.args.run_reserved, 0)
        self.assertFalse(self.args.disk_abort.is_set())
        self.assertEqual(outcome.status, "container_failed")


if __name__ == "__main__":
    unittest.main()
