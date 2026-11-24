"""attempt 级产物隔离与恢复的单元测试。

跑法：

    python -m unittest deploy.tests.test_attempt_artifacts -v
"""

from __future__ import annotations

import io
import json
import shutil
import sys
import tarfile
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

import cybergym_batch as cb  # noqa: E402


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


class AttemptArtifactTests(unittest.TestCase):
    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self.root = Path(self._tmp.name)
        self.task_root = self.root / "work" / "arvo_3938"
        (self.task_root / "task" / "poc").mkdir(parents=True)
        (self.task_root / "out").mkdir(parents=True)
        self.task = cb.TaskRef(
            "arvo:3938",
            "a5c9210adf28",
            "arvo_3938",
            build_data_dir(self.root),
            "fake",
            "n132/arvo:3938-vul",
        )

    def tearDown(self):
        self._tmp.cleanup()

    def test_seal_copies_poc_and_result(self):
        poc = self.task_root / "task" / "poc" / "x.bin"
        poc.write_bytes(b"X" * 64)
        (self.task_root / "out" / "result.json").write_text(
            json.dumps({"status": "completed"}), encoding="utf-8"
        )
        dest = cb.seal_attempt(self.task_root, 1, task=self.task)
        self.assertTrue((dest / "poc" / "x.bin").is_file())
        self.assertTrue((dest / "result.json").is_file())
        payload = json.loads((dest / "attempt.json").read_text(encoding="utf-8"))
        self.assertEqual(payload["task_id"], "arvo:3938")
        self.assertEqual(payload["source_status"], "completed")

    def test_second_seal_does_not_overwrite(self):
        first = cb.seal_attempt(self.task_root, 1, task=self.task)
        second = cb.seal_attempt(self.task_root, 1, task=self.task)
        self.assertNotEqual(first, second)
        self.assertTrue(first.is_dir())
        self.assertTrue(second.is_dir())

    def test_restore_copies_missing_candidate_from_latest_snapshot(self):
        poc = self.task_root / "task" / "poc" / "good.bin"
        poc.write_bytes(b"G" * 64)
        candidate = cb.PocCandidate(
            path=poc,
            role=cb.ROLE_FINAL,
            source="bundle",
            sha256=cb._sha256_file(poc),
        )
        cb.seal_attempt(self.task_root, 1, task=self.task, candidates=[candidate])
        poc.unlink()

        restored = cb.restore_attempt_candidates(self.task_root)

        self.assertEqual(restored, 1)
        self.assertEqual(poc.read_bytes(), b"G" * 64)

    def test_restore_skips_hash_mismatch(self):
        poc = self.task_root / "task" / "poc" / "good.bin"
        poc.write_bytes(b"G" * 64)
        candidate = cb.PocCandidate(
            path=poc,
            role=cb.ROLE_FINAL,
            source="bundle",
            sha256=cb._sha256_file(poc),
        )
        dest = cb.seal_attempt(
            self.task_root, 1, task=self.task, candidates=[candidate]
        )
        (dest / "poc" / "good.bin").write_bytes(b"tampered")
        poc.unlink()

        restored = cb.restore_attempt_candidates(self.task_root)

        self.assertEqual(restored, 0)
        self.assertFalse(poc.exists())

    def test_reset_poc_archives_then_clears(self):
        poc = self.task_root / "task" / "poc" / "old.bin"
        poc.write_bytes(b"O" * 64)

        orphan = cb.reset_poc_for_run(self.task_root)

        self.assertIsNotNone(orphan)
        self.assertFalse(poc.exists())
        self.assertTrue((orphan / "poc" / "old.bin").is_file())

    def test_force_rebuild_keeps_existing_poc(self):
        poc = self.task_root / "task" / "poc" / "keep.bin"
        poc.write_bytes(b"K" * 64)
        (self.task_root / "task" / ".prepared.json").write_text(
            json.dumps({"task_id": self.task.task_id}), encoding="utf-8"
        )

        cb.prepare_task_package(self.task, self.task_root, force=True)

        self.assertTrue(poc.is_file())
        self.assertEqual(poc.read_bytes(), b"K" * 64)
        self.assertTrue((self.task_root / "task" / "TASK.md").is_file())


if __name__ == "__main__":
    unittest.main()
