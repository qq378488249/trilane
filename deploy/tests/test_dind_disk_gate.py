"""导入 dind 前的磁盘空间预检。

不碰真实 Docker：docker 调用和 dind 生命周期都替换成假的。
"""

from __future__ import annotations

import os
import sys
import tempfile
import threading
import unittest
from pathlib import Path
from unittest import mock

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

import cybergym_batch as cb  # noqa: E402

GB = 1_000_000_000


def proc(stdout: str = "", returncode: int = 0, stderr: str = "") -> mock.Mock:
    return mock.Mock(returncode=returncode, stdout=stdout, stderr=stderr)


class DindFreeBytesTests(unittest.TestCase):
    def test_parses_available_column(self):
        handle = cb.DindHandle("dind", "data", "run")
        out = (
            "Filesystem 1024-blocks Used Available Capacity Mounted on\n"
            "/dev/sda1 1000000 400000 600000 40% /var/lib/docker\n"
        )
        with mock.patch.object(cb, "run", return_value=proc(out)):
            self.assertEqual(cb.dind_free_bytes(handle), 600_000 * 1024)

    def test_returns_none_on_failure(self):
        handle = cb.DindHandle("dind", "data", "run")
        with mock.patch.object(cb, "run", return_value=proc("", 1, "boom")):
            self.assertIsNone(cb.dind_free_bytes(handle))


class ImageSizeTests(unittest.TestCase):
    def test_reads_size(self):
        with mock.patch.object(cb, "run", return_value=proc("12345\n")):
            self.assertEqual(cb.image_size_bytes("img"), 12345)

    def test_returns_none_on_failure(self):
        with mock.patch.object(cb, "run", return_value=proc("", 1, "no such image")):
            self.assertIsNone(cb.image_size_bytes("img"))


class CheckDindDiskSpaceTests(unittest.TestCase):
    def _check(
        self,
        *,
        docker_free=20 * GB,
        dind_free=20 * GB,
        image_sizes=(10 * GB, 1 * GB),
        run_free=50 * GB,
        run_space_gb=5.0,
        reserved_docker=0,
        reserved_run=0,
        docker_root="/docker",
        run_root="/runs",
    ):
        handle = cb.DindHandle("dind", "data", "run")

        def fake_free(path):
            if path is None:
                return None
            if path == docker_root:
                return docker_free
            if path == run_root:
                return run_free
            return None

        with mock.patch.object(cb, "free_bytes", side_effect=fake_free), \
             mock.patch.object(cb, "dind_free_bytes", return_value=dind_free), \
             mock.patch.object(cb, "image_size_bytes", side_effect=list(image_sizes)):
            return cb.check_dind_disk_space(
                handle,
                ("vul", "agent"),
                run_space_gb,
                reserved_docker=reserved_docker,
                reserved_run=reserved_run,
                docker_root=docker_root,
                run_root=run_root,
            )

    def test_enough_space_passes(self):
        ok, detail, docker_need, run_need = self._check()
        self.assertTrue(ok)
        self.assertEqual(docker_need, 16 * GB)  # 镜像 11 + 运行空间 5
        self.assertEqual(run_need, 5 * GB)
        self.assertIn("镜像盘（docker_root /docker）可用 20.0GB", detail)
        self.assertIn("运行盘（/runs）可用 50.0GB", detail)

    def test_docker_root_below_need_fails(self):
        # 10 + 1 + 5 = 16GB，镜像盘只剩 14GB
        ok, detail, _, _ = self._check(docker_free=14 * GB)
        self.assertFalse(ok)
        self.assertIn("磁盘空间不足", detail)

    def test_run_root_below_need_fails(self):
        # 镜像盘够，运行盘只有 4GB < 5GB
        ok, detail, _, _ = self._check(run_free=4 * GB)
        self.assertFalse(ok)
        self.assertIn("运行盘", detail)

    def test_counts_other_tasks_reservation(self):
        # 本任务镜像盘 16GB，其他任务已预留 16GB；20GB 只够一个
        ok, detail, _, _ = self._check(reserved_docker=16 * GB)
        self.assertFalse(ok)
        self.assertIn("其他任务预留 16.0GB", detail)
        ok, _, _, _ = self._check(docker_free=32 * GB, reserved_docker=16 * GB)
        self.assertTrue(ok)

    def test_run_reservation_counts_too(self):
        ok, _, _, _ = self._check(run_free=8 * GB, reserved_run=5 * GB)
        self.assertFalse(ok)
        ok, _, _, _ = self._check(run_free=10 * GB, reserved_run=5 * GB)
        self.assertTrue(ok)

    def test_falls_back_to_dind_df_without_docker_root(self):
        ok, detail, docker_need, _ = self._check(docker_root=None, dind_free=20 * GB)
        self.assertTrue(ok)
        self.assertIn("dind /var/lib/docker", detail)
        self.assertEqual(docker_need, 16 * GB)

    def test_measurement_failure_does_not_block(self):
        ok, detail, docker_need, run_need = self._check(docker_free=None)
        self.assertTrue(ok)
        self.assertIsNone(docker_need)
        self.assertEqual(run_need, 0)
        self.assertIn("磁盘检查跳过", detail)

        ok, detail, docker_need, _ = self._check(image_sizes=(None, 1 * GB))
        self.assertTrue(ok)
        self.assertIsNone(docker_need)
        self.assertIn("镜像大小读取失败", detail)


class RunAgentDiskGateTests(unittest.TestCase):
    """run_agent 的检查时机与预留：docker_root 配了就提前到起 dind 之前。"""

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
            "--data-dir", str(self.root / "data"),
            "--work-root", str(self.root),
            "--trilane-home", str(self.root),
        ])
        self.args.disk_abort = threading.Event()
        self.args.disk_reserved = 0
        self.args.run_reserved = 0
        self.args.disk_lock = threading.Lock()
        self.starts = []

    def tearDown(self):
        self._tmp.cleanup()

    def _run(self, check, loads):
        with mock.patch.object(
                 cb, "start_dind",
                 lambda *a, **k: self.starts.append(1) or mock.MagicMock(name="dind")), \
             mock.patch.object(cb, "wait_dind", lambda *a, **k: True), \
             mock.patch.object(cb, "check_dind_disk_space", check), \
             mock.patch.object(cb, "load_image_into_dind", lambda *a, **k: loads.append(a)), \
             mock.patch.object(cb, "stop_dind", lambda *a, **k: None), \
             mock.patch.object(cb, "run_agent_in_dind", lambda *a, **k: 0):
            return cb.run_agent(self.task, self.task_root, self.args)

    def test_short_disk_after_dind_start_skips_import(self):
        """没配 docker_root：只能在 dind 起来后检查；不足则不 load。"""
        loads = []
        outcome = self._run(
            lambda *a, **k: (False, "磁盘空间不足：可用 1.0GB", 16 * GB, 5 * GB), loads
        )
        self.assertEqual(outcome.status, "disk_space")
        self.assertEqual(self.starts, [1])
        self.assertEqual(loads, [])
        self.assertTrue(self.args.disk_abort.is_set())

    def test_enough_disk_loads_both_images(self):
        loads = []
        outcome = self._run(
            lambda *a, **k: (True, "可用 20.0GB", 16 * GB, 5 * GB), loads
        )
        self.assertEqual(len(loads), 2)
        self.assertFalse(self.args.disk_abort.is_set())
        self.assertEqual(self.args.disk_reserved, 0, "任务结束后预留要释放")
        self.assertEqual(self.args.run_reserved, 0, "任务结束后预留要释放")
        self.assertEqual(outcome.status, "container_failed")  # 没有 result.json

    def test_docker_root_checks_before_starting_dind(self):
        """配了 docker_root：不足时连 dind 都不起。"""
        self.args.dind_docker_root = "/host_mnt/d"
        seen = []

        def check(handle, images, run_space_gb, **kwargs):
            seen.append(handle)
            return False, "磁盘空间不足：镜像盘", 16 * GB, 5 * GB

        outcome = self._run(check, [])
        self.assertEqual(outcome.status, "disk_space")
        self.assertEqual(seen, [None], "检查时还没有 dind")
        self.assertEqual(self.starts, [], "不足时不该启动 dind")
        self.assertTrue(self.args.disk_abort.is_set())

    def test_docker_root_present_still_loads_when_enough(self):
        self.args.dind_docker_root = "/host_mnt/d"
        loads = []
        outcome = self._run(
            lambda *a, **k: (True, "可用 40.0GB", 16 * GB, 5 * GB), loads
        )
        self.assertEqual(self.starts, [1])
        self.assertEqual(len(loads), 2)
        self.assertEqual(outcome.status, "container_failed")

    def test_check_sees_other_tasks_reservation(self):
        seen = {}

        def check(handle, images, run_space_gb, **kwargs):
            seen.update(kwargs)
            return False, "磁盘空间不足：不够", 16 * GB, 5 * GB

        self.args.disk_reserved = 16 * GB
        self.args.run_reserved = 5 * GB
        outcome = self._run(check, [])
        self.assertEqual(seen["reserved_docker"], 16 * GB)
        self.assertEqual(seen["reserved_run"], 5 * GB)
        self.assertEqual(outcome.status, "disk_space")
        self.assertEqual(self.args.disk_reserved, 16 * GB, "没预留成功就不该扣别人的")
        self.assertEqual(self.args.run_reserved, 5 * GB)

    def test_disabled_skips_check_and_loads(self):
        self.args.dind_disk_check = False
        loads = []

        def check(*args, **kwargs):
            raise AssertionError("关闭后不该调用磁盘检查")

        outcome = self._run(check, loads)
        self.assertEqual(len(loads), 2)
        self.assertEqual(self.args.disk_reserved, 0)
        self.assertFalse(self.args.disk_abort.is_set())
        self.assertEqual(outcome.status, "container_failed")


class DiskCheckSwitchTests(unittest.TestCase):
    def test_default_is_on(self):
        with mock.patch.dict(os.environ):
            os.environ.pop("TRILANE_DIND_DISK_CHECK", None)
            args = cb.parse_args(["--task-id", "arvo:3938"])
        self.assertTrue(args.dind_disk_check)

    def test_env_disables(self):
        with mock.patch.dict(os.environ, {"TRILANE_DIND_DISK_CHECK": "0"}):
            args = cb.parse_args(["--task-id", "arvo:3938"])
        self.assertFalse(args.dind_disk_check)

    def test_cli_disables(self):
        args = cb.parse_args(["--task-id", "arvo:3938", "--dind-disk-check", "0"])
        self.assertFalse(args.dind_disk_check)

    def test_docker_root_from_env(self):
        with mock.patch.dict(os.environ, {"TRILANE_DIND_DOCKER_ROOT": "/host_mnt/d"}):
            args = cb.parse_args(["--task-id", "arvo:3938"])
        self.assertEqual(args.dind_docker_root, "/host_mnt/d")


class AbortSkipsQueuedTasksTests(unittest.TestCase):
    def test_run_one_returns_disk_space_without_starting(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            args = cb.parse_args([
                "--task-id", "arvo:3938",
                "--data-dir", str(root / "data"),
                "--work-root", str(root),
                "--trilane-home", str(root),
            ])
            args.disk_abort = threading.Event()
            args.disk_abort.set()
            task = cb.TaskRef(
                "arvo:3938", "masked", "arvo_3938",
                root / "data", "fake", "n132/arvo:3938-vul",
            )
            record = cb.run_one(task, args, None, root)
            self.assertEqual(record["status"], "disk_space")
            self.assertIn("磁盘空间不足", record["error"])


if __name__ == "__main__":
    unittest.main(verbosity=2)
