"""种子语料提取的单元测试。

跑法（不需要 Docker、不需要数据集）：

    python -m pytest deploy/tests/test_seed_corpus.py -q
"""

from __future__ import annotations

import argparse
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

import cybergym_batch as cb  # noqa: E402


class ProvisionSeedCorporaTest(unittest.TestCase):
    def setUp(self) -> None:
        self._tmp = tempfile.TemporaryDirectory()
        self.root = Path(self._tmp.name)
        self.task = cb.TaskRef(
            task_id="arvo:1065",
            masked_id="arvo:1065",
            slug="arvo_1065",
            data_dir=self.root / "data",
            description="fake",
            vul_image="n132/arvo:1065-vul",
        )

    def tearDown(self) -> None:
        self._tmp.cleanup()

    def test_off_skips_docker(self) -> None:
        args = argparse.Namespace(seed_corpus="off")
        with mock.patch.object(cb, "run") as run:
            count = cb.provision_seed_corpora(self.task, self.root, args)
        self.assertEqual(count, 0)
        run.assert_not_called()

    def test_on_copies_zip_and_counts(self) -> None:
        args = argparse.Namespace(seed_corpus="on")

        def fake_run(cmd, *, timeout=None):
            seeds = self.root / "task" / "seeds"
            seeds.mkdir(parents=True, exist_ok=True)
            (seeds / "magic_fuzzer_seed_corpus.zip").write_bytes(b"zip")
            self.assertIn("trilane.task=arvo_1065", cmd)
            self.assertIn("n132/arvo:1065-vul", cmd)
            return subprocess.CompletedProcess(cmd, 0, "", "")

        with mock.patch.object(cb, "run", fake_run):
            count = cb.provision_seed_corpora(self.task, self.root, args)
        self.assertEqual(count, 1)

    def test_on_failure_is_not_fatal(self) -> None:
        args = argparse.Namespace(seed_corpus="on")

        def fake_run(cmd, *, timeout=None):
            return subprocess.CompletedProcess(cmd, 1, "", "boom")

        with mock.patch.object(cb, "run", fake_run):
            count = cb.provision_seed_corpora(self.task, self.root, args)
        self.assertEqual(count, 0)


if __name__ == "__main__":
    unittest.main()
