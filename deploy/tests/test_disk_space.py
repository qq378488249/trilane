"""磁盘空间误报的回归测试。

场景：第 1 次尝试磁盘真满，transcript 里留下 ENOSPC 行；清盘后第 2 次重跑，
transcript 被追加写入、mtime 变新。如果只按 mtime 过滤，第 1 次的旧行会被
重新扫出来，磁盘已经空了却依然判成 disk_space。

按文件 mtime 过滤是不够的，必须用"本轮开始时的字节偏移"只扫新增内容。
"""

from __future__ import annotations

import sys
import tempfile
import time
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

import cybergym_batch as cb  # noqa: E402

ENOSPC = "docker: Error response from daemon: write /var/lib/docker/tmp: no space left on device"
BOILERPLATE = "- If the environment reports `no space left on device`, low disk space, or any"


def write_transcript(path: Path, text: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(text, encoding="utf-8")


class DiskSpaceDetectionTests(unittest.TestCase):
    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self.state = Path(self._tmp.name) / "state" / "trilane"
        self.transcript = (
            self.state / "runs" / "trilane-20260101-000000" / "stage2" / "transcript.md"
        )
        self.since = time.time() - 60

    def tearDown(self):
        self._tmp.cleanup()

    def test_old_error_line_is_ignored_after_retry(self):
        """上一次留下的 ENOSPC 行不该在本轮被扫出来。"""
        write_transcript(self.transcript, f"# header\n{ENOSPC}\n")
        sizes = cb.snapshot_transcript_sizes(self.state)

        # 本轮追加了新内容（文件 mtime 变新），但没有新的 ENOSPC
        with self.transcript.open("a", encoding="utf-8") as handle:
            handle.write("## 2026-01-01T00:00:10Z\nsome tool output\n")

        self.assertIsNone(cb.detect_disk_space_error(self.state, self.since, sizes))

    def test_new_error_line_is_detected(self):
        """本轮新增的 ENOSPC 必须报出来。"""
        write_transcript(self.transcript, "# header\n")
        sizes = cb.snapshot_transcript_sizes(self.state)

        with self.transcript.open("a", encoding="utf-8") as handle:
            handle.write(ENOSPC + "\n")

        found = cb.detect_disk_space_error(self.state, self.since, sizes)
        self.assertIsNotNone(found)
        self.assertIn("no space left on device", found)

    def test_prompt_boilerplate_is_not_a_disk_error(self):
        """阶段提示词里本身就写着这句话，不能当磁盘错误。"""
        write_transcript(self.transcript, BOILERPLATE + "\n")
        sizes = cb.snapshot_transcript_sizes(self.state)
        self.assertIsNone(cb.detect_disk_space_error(self.state, self.since, sizes))

    def test_unmodified_file_is_skipped(self):
        """本轮没动过的文件不扫（哪怕里面真有 ENOSPC）。"""
        write_transcript(self.transcript, ENOSPC + "\n")
        old = time.time() - 3600
        Path(self.transcript).touch()
        import os

        os.utime(self.transcript, (old, old))
        sizes = cb.snapshot_transcript_sizes(self.state)
        self.assertIsNone(cb.detect_disk_space_error(self.state, self.since, sizes))

    def test_snapshot_returns_sizes(self):
        write_transcript(self.transcript, "abc")
        sizes = cb.snapshot_transcript_sizes(self.state)
        self.assertEqual(sizes[self.transcript], 3)

    def test_missing_file_gives_zero_offset(self):
        """本轮新建的文件（上次不存在）从 0 开始扫。"""
        sizes = cb.snapshot_transcript_sizes(self.state)  # 此时还不存在
        write_transcript(self.transcript, ENOSPC + "\n")
        self.assertIsNotNone(cb.detect_disk_space_error(self.state, self.since, sizes))


if __name__ == "__main__":
    unittest.main(verbosity=2)
