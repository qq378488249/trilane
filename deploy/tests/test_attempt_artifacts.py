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
from unittest import mock

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
        record: dict = {}
        dest = cb.seal_attempt(self.task_root, 1, task=self.task, record=record)
        self.assertTrue((dest / "poc" / "x.bin").is_file())
        self.assertTrue((dest / "result.json").is_file())
        payload = json.loads((dest / "attempt.json").read_text(encoding="utf-8"))
        self.assertEqual(payload["task_id"], "arvo:3938")
        self.assertEqual(payload["source_status"], "completed")
        self.assertEqual(record["poc_copy"]["files_copied"], 1)
        self.assertFalse(record["poc_copy"]["limit_hit"])

    def test_seal_caps_poc_copy_by_file_count(self):
        poc_dir = self.task_root / "task" / "poc"
        for index in range(5):
            (poc_dir / f"f{index}.bin").write_bytes(b"x" * 16)

        with mock.patch.object(cb, "POC_ARCHIVE_MAX_FILES", 2), mock.patch.object(
            cb, "POC_ARCHIVE_MAX_MB", 200
        ):
            dest = cb.seal_attempt(self.task_root, 1, task=self.task)

        copied = [path for path in (dest / "poc").rglob("*") if path.is_file()]
        self.assertEqual(len(copied), 2)
        payload = json.loads((dest / "attempt.json").read_text(encoding="utf-8"))
        self.assertEqual(payload["poc_copy"]["files_total"], 5)
        self.assertEqual(payload["poc_copy"]["files_copied"], 2)
        self.assertEqual(payload["poc_copy"]["files_skipped"], 3)
        self.assertTrue(payload["poc_copy"]["limit_hit"])

    def test_seal_keeps_metadata_when_file_limit_hit(self):
        poc_dir = self.task_root / "task" / "poc"
        (poc_dir / "bundle.json").write_text("{}", encoding="utf-8")
        (poc_dir / "manifest.json").write_text("{}", encoding="utf-8")
        for index in range(3):
            (poc_dir / f"f{index}.bin").write_bytes(b"x" * 16)

        with mock.patch.object(cb, "POC_ARCHIVE_MAX_FILES", 1), mock.patch.object(
            cb, "POC_ARCHIVE_MAX_MB", 200
        ):
            dest = cb.seal_attempt(self.task_root, 1, task=self.task)

        self.assertTrue((dest / "poc" / "bundle.json").is_file())
        self.assertTrue((dest / "poc" / "manifest.json").is_file())
        self.assertEqual(
            len([path for path in (dest / "poc").rglob("*") if path.is_file()]), 3
        )

    def test_seal_caps_poc_copy_by_bytes(self):
        poc_dir = self.task_root / "task" / "poc"
        (poc_dir / "a.bin").write_bytes(b"a" * 100)
        (poc_dir / "b.bin").write_bytes(b"b" * 100)

        with mock.patch.object(cb, "POC_ARCHIVE_MAX_FILES", 100), mock.patch.object(
            cb, "POC_ARCHIVE_MAX_MB", 0
        ):
            # 直接调用底层函数，避免把 MB 截断成 0 后走“不限制”分支。
            summary = cb._copy_poc_tree(
                self.task_root, self.task_root / "artifacts" / "attempt-bytes",
                max_files=100, max_bytes=150,
            )

        self.assertEqual(summary["files_copied"], 1)
        self.assertEqual(summary["files_skipped"], 1)
        self.assertTrue(summary["limit_hit"])

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

    def test_archive_moves_engine_bundle(self):
        (self.task_root / "out" / "bundle.json").write_text(
            json.dumps({"candidates": []}), encoding="utf-8"
        )

        cb.archive_attempt_outputs(self.task_root, 1)

        self.assertFalse((self.task_root / "out" / "bundle.json").exists())
        self.assertTrue((self.task_root / "out" / "bundle.json.attempt1").is_file())

    def _seal_verified_bundle(self) -> Path:
        poc_dir = self.task_root / "task" / "poc"
        poc = poc_dir / "good.bin"
        poc.write_bytes(b"G" * 64)
        (poc_dir / "bundle.json").write_text(
            json.dumps(
                {
                    "candidates": [
                        {
                            "file": "task/poc/good.bin",
                            "role": "candidate",
                            "verification": "verified",
                            "finding": "VULN-001",
                        }
                    ]
                }
            ),
            encoding="utf-8",
        )
        return cb.seal_attempt(self.task_root, 1, task=self.task)

    def test_restore_prior_bundle_recovers_overwritten_bundle(self):
        self._seal_verified_bundle()
        poc_dir = self.task_root / "task" / "poc"
        # 续跑把已验证的清单覆盖成 file 为空的行，候选文件也丢了。
        (poc_dir / "bundle.json").write_text(
            json.dumps(
                {"candidates": [{"file": "", "verification": "generated-not-verified"}]}
            ),
            encoding="utf-8",
        )
        (poc_dir / "good.bin").unlink()

        used = cb.restore_prior_bundle(self.task_root, 2)

        self.assertEqual(used, "attempt-1")
        self.assertEqual((poc_dir / "good.bin").read_bytes(), b"G" * 64)
        payload = json.loads((poc_dir / "bundle.json").read_text(encoding="utf-8"))
        self.assertEqual(payload["candidates"][0]["file"], "task/poc/good.bin")

    def test_restore_prior_bundle_ignores_fileless_snapshot(self):
        poc_dir = self.task_root / "task" / "poc"
        (poc_dir / "bundle.json").write_text(
            json.dumps({"candidates": [{"file": "", "role": "diagnostic"}]}),
            encoding="utf-8",
        )
        cb.seal_attempt(self.task_root, 1, task=self.task)
        current = (poc_dir / "bundle.json").read_text(encoding="utf-8")

        self.assertIsNone(cb.restore_prior_bundle(self.task_root, 2))
        self.assertEqual((poc_dir / "bundle.json").read_text(encoding="utf-8"), current)

    def test_restore_prior_bundle_never_uses_current_attempt(self):
        self._seal_verified_bundle()
        self.assertIsNone(cb.restore_prior_bundle(self.task_root, 1))

    def test_scan_skips_archived_attempt_outputs(self):
        (self.task_root / "out" / "result.json.attempt1").write_text(
            json.dumps({"status": "error"}) + " " * 32, encoding="utf-8"
        )

        candidates = cb.collect_pocs(self.task_root, {})

        self.assertFalse(
            any("result.json.attempt1" in c.path.name for c in candidates)
        )

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
