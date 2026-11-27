"""Level-1 任务包扫描的回归测试（大量小文件/9p 友好）。

跑法：

    python -m pytest deploy/tests/test_level1_package.py -q
"""

from __future__ import annotations

import sys
import tarfile
import tempfile
import unittest
from pathlib import Path
from unittest import mock

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

import cybergym_batch as cb  # noqa: E402


class SourceTreeScanTest(unittest.TestCase):
    def setUp(self) -> None:
        self._tmp = tempfile.TemporaryDirectory()
        self.root = Path(self._tmp.name)
        self.src = self.root / "src"
        self.task = self.root / "task"
        self.src.mkdir()
        self.task.mkdir()

    def tearDown(self) -> None:
        self._tmp.cleanup()

    def _write(self, rel: str, data: bytes = b"x") -> Path:
        path = self.src / rel
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(data)
        return path

    def test_finds_fix_materials_anywhere(self) -> None:
        self._write("pkg/sub/patch.diff")
        self._write("pkg/repo-fix.tar.gz")
        self.assertEqual(
            sorted(cb._source_tree_violations(self.src)),
            ["pkg/repo-fix.tar.gz", "pkg/sub/patch.diff"],
        )

    def test_only_root_error_txt_is_forbidden(self) -> None:
        self._write("error.txt")
        self._write("pkg/error.txt")
        self.assertEqual(cb._source_tree_violations(self.src), ["error.txt"])

    def test_level1_check_does_not_rglob(self) -> None:
        for index in range(2000):
            self._write(f"pkg/many/{index:05d}.txt")
        with mock.patch.object(Path, "rglob", side_effect=AssertionError("rglob used")):
            cb._assert_level1_package(self.src, self.task)


class TarMemberScanTest(unittest.TestCase):
    @staticmethod
    def _member(name: str) -> tarfile.TarInfo:
        return tarfile.TarInfo(name=name)

    def test_stripped_fix_material_is_rejected_before_extract(self) -> None:
        members = [self._member("src-vul/pkg/sub/patch.diff")]
        with self.assertRaises(RuntimeError):
            cb._assert_tar_level1_members(members, True)

    def test_root_error_txt_is_rejected_but_nested_is_allowed(self) -> None:
        with self.assertRaises(RuntimeError):
            cb._assert_tar_level1_members([self._member("src-vul/error.txt")], True)
        cb._assert_tar_level1_members(
            [self._member("src-vul/pkg/error.txt")], True
        )

    def test_normal_source_is_accepted(self) -> None:
        members = [self._member("src-vul/pkg/main.c"), self._member("src-vul/README.md")]
        cb._assert_tar_level1_members(members, True)


class OfficialPathMapTest(unittest.TestCase):
    def setUp(self) -> None:
        self._tmp = tempfile.TemporaryDirectory()
        self.root = Path(self._tmp.name)
        self.src = self.root / "src"
        self.src.mkdir()

    def tearDown(self) -> None:
        self._tmp.cleanup()

    def test_direct_path_wins(self) -> None:
        target = self.src / "pkg" / "f.c"
        target.parent.mkdir(parents=True)
        target.write_text("x", encoding="utf-8")
        self.assertEqual(cb._map_official_path("/src/pkg/f.c", self.src), target)

    def test_ambiguous_suffix_returns_none_early(self) -> None:
        for rel in ("a/f.c", "b/f.c", "c/f.c"):
            path = self.src / rel
            path.parent.mkdir(parents=True)
            path.write_text("x", encoding="utf-8")
        with mock.patch.object(
            Path, "is_file", autospec=True, wraps=Path.is_file
        ) as is_file:
            self.assertIsNone(cb._map_official_path("/src/f.c", self.src))
        # 只应检查 directory 直匹配和至多两个 glob 命中，不应遍历全部文件。
        self.assertLessEqual(is_file.call_count, 6)


if __name__ == "__main__":
    unittest.main()
