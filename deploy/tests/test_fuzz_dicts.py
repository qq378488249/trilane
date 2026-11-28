"""fuzz 字典收集与 scout `-dict` 接入的单元测试。

跑法（不需要 Docker、不需要数据集）：

    python -m pytest deploy/tests/test_fuzz_dicts.py -q
"""

from __future__ import annotations

import argparse
import json
import subprocess
import sys
import tempfile
import time
import unittest
from pathlib import Path
from unittest import mock

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

import cybergym_batch as cb  # noqa: E402


def _args(**overrides) -> argparse.Namespace:
    values = {"agent_id": "test-agent", "seed_corpus": "off"}
    values.update(overrides)
    return argparse.Namespace(**values)


class ProvisionFuzzDictsTest(unittest.TestCase):
    def setUp(self) -> None:
        self._tmp = tempfile.TemporaryDirectory()
        self.root = Path(self._tmp.name)
        self.task = cb.TaskRef(
            task_id="arvo:3938",
            masked_id="arvo:3938",
            slug="arvo_3938",
            data_dir=self.root / "data",
            description="fake",
            vul_image="n132/arvo:3938-vul",
        )
        self.task_dir = self.root / "task"
        self.src_dir = self.task_dir / "src"
        self.seeds_dir = self.task_dir / "seeds"
        self.src_dir.mkdir(parents=True)
        self.seeds_dir.mkdir(parents=True)
        (self.task_dir / "TASK.md").write_text("# task\n", encoding="utf-8")
        (self.seeds_dir / "manifest.json").write_text(
            json.dumps({"canonical_fuzzers": ["rules_fuzzer"], "copied": [], "fallback_all": False}),
            encoding="utf-8",
        )

    def tearDown(self) -> None:
        self._tmp.cleanup()

    def test_source_dict_copied_selected_and_prompted(self) -> None:
        dict_path = self.src_dir / "yara" / "tests" / "oss-fuzz" / "rules_fuzzer.dict"
        dict_path.parent.mkdir(parents=True)
        dict_path.write_text('"rule"\n"condition"\n', encoding="utf-8")

        with mock.patch.object(cb, "run") as run:
            files = cb.provision_fuzz_dicts(self.task, self.root, _args())
        run.assert_not_called()

        self.assertEqual(files, ["rules_fuzzer.dict"])
        self.assertTrue((self.seeds_dir / "rules_fuzzer.dict").is_file())
        payload = json.loads(
            (self.seeds_dir / "dicts.json").read_text(encoding="utf-8")
        )
        self.assertEqual(payload["selected"], "rules_fuzzer.dict")
        self.assertEqual(payload["selected_origin"], "src")
        self.assertEqual(payload["dicts"][0]["source_path"], "src/yara/tests/oss-fuzz/rules_fuzzer.dict")
        text = (self.task_dir / "TASK.md").read_text(encoding="utf-8")
        self.assertIn(cb.DICT_BRIEF_BEGIN, text)
        self.assertIn("-dict=seeds/rules_fuzzer.dict", text)
        self.assertIn("-x seeds/rules_fuzzer.dict", text)

    def test_exact_canonical_stem_wins(self) -> None:
        for name in ("xaac_enc_fuzzer.dict", "xaac_dec_fuzzer.dict"):
            path = self.src_dir / "libxaac" / "fuzzer" / name
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_text('"aac"\n', encoding="utf-8")
        (self.seeds_dir / "manifest.json").write_text(
            json.dumps({"canonical_fuzzers": ["xaac_dec_fuzzer"]}), encoding="utf-8"
        )

        cb.provision_fuzz_dicts(self.task, self.root, _args())
        payload = json.loads(
            (self.seeds_dir / "dicts.json").read_text(encoding="utf-8")
        )
        self.assertEqual(payload["selected"], "xaac_dec_fuzzer.dict")

    def test_prompt_block_is_idempotent(self) -> None:
        dict_path = self.src_dir / "xml.dict"
        dict_path.write_text('"<root>"\n', encoding="utf-8")

        cb.provision_fuzz_dicts(self.task, self.root, _args())
        cb.provision_fuzz_dicts(self.task, self.root, _args())
        text = (self.task_dir / "TASK.md").read_text(encoding="utf-8")
        self.assertEqual(text.count(cb.DICT_BRIEF_BEGIN), 1)
        self.assertEqual(text.count(cb.DICT_BRIEF_END), 1)

    def test_no_dict_means_no_prompt_block(self) -> None:
        with mock.patch.object(cb, "run") as run:
            files = cb.provision_fuzz_dicts(self.task, self.root, _args())
        run.assert_not_called()
        self.assertEqual(files, [])
        self.assertFalse((self.seeds_dir / "dicts.json").exists())
        text = (self.task_dir / "TASK.md").read_text(encoding="utf-8")
        self.assertNotIn(cb.DICT_BRIEF_BEGIN, text)

    def test_fuzz_dict_off_skips_collection_and_prompt(self) -> None:
        dict_path = self.src_dir / "rules_fuzzer.dict"
        dict_path.write_text('"rule"\n', encoding="utf-8")
        with mock.patch.object(cb, "run") as run:
            files = cb.provision_fuzz_dicts(self.task, self.root, _args(fuzz_dict="off"))
        run.assert_not_called()
        self.assertEqual(files, [])
        self.assertFalse((self.seeds_dir / "rules_fuzzer.dict").exists())
        self.assertFalse((self.seeds_dir / "dicts.json").exists())
        text = (self.task_dir / "TASK.md").read_text(encoding="utf-8")
        self.assertNotIn(cb.DICT_BRIEF_BEGIN, text)

    def test_out_dict_only_when_seed_corpus_on(self) -> None:
        calls: list[list[str]] = []

        def fake_run(cmd, *, timeout=None):
            calls.append(cmd)
            (self.seeds_dir / "rules_fuzzer.dict").write_text('"rule"\n', encoding="utf-8")
            return subprocess.CompletedProcess(cmd, 0, "", "")

        with mock.patch.object(cb, "run", side_effect=fake_run):
            cb.provision_fuzz_dicts(self.task, self.root, _args(seed_corpus="off"))
        self.assertEqual(calls, [])

        with mock.patch.object(cb, "run", side_effect=fake_run):
            cb.provision_fuzz_dicts(self.task, self.root, _args(seed_corpus="on"))
        self.assertEqual(len(calls), 1)
        self.assertIn("/out/rules_fuzzer.dict", calls[0][-1])
        payload = json.loads(
            (self.seeds_dir / "dicts.json").read_text(encoding="utf-8")
        )
        self.assertEqual(payload["selected_origin"], "out")
        self.assertIn("vulnerable image", (self.task_dir / "TASK.md").read_text(encoding="utf-8"))

    def test_source_dict_wins_over_same_name_out_dict(self) -> None:
        (self.src_dir / "rules_fuzzer.dict").write_text('"src"\n', encoding="utf-8")

        def fake_run(cmd, *, timeout=None):
            dest = self.seeds_dir / "rules_fuzzer.dict"
            if not dest.exists():
                dest.write_text('"out"\n', encoding="utf-8")
            return subprocess.CompletedProcess(cmd, 0, "", "")

        with mock.patch.object(cb, "run", side_effect=fake_run):
            cb.provision_fuzz_dicts(self.task, self.root, _args(seed_corpus="on"))
        self.assertEqual((self.seeds_dir / "rules_fuzzer.dict").read_text(encoding="utf-8"), '"src"\n')
        payload = json.loads(
            (self.seeds_dir / "dicts.json").read_text(encoding="utf-8")
        )
        self.assertEqual(payload["dicts"][0]["origin"], "src")


class ScoutDictTest(unittest.TestCase):
    def setUp(self) -> None:
        self._tmp = tempfile.TemporaryDirectory()
        self.root = Path(self._tmp.name)
        self.scout = self.root / "task" / "scout"
        self.scout.mkdir(parents=True)
        self.seeds_dir = self.root / "task" / "seeds"
        self.seeds_dir.mkdir(parents=True)
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
        (self.seeds_dir / "rules_fuzzer.dict").write_text('"rule"\n', encoding="utf-8")
        (self.seeds_dir / "dicts.json").write_text(
            json.dumps({"selected": "rules_fuzzer.dict", "dicts": [{"file": "rules_fuzzer.dict"}]}),
            encoding="utf-8",
        )

    def tearDown(self) -> None:
        self._tmp.cleanup()

    def _run_campaign(self, probe_tail: str) -> list[dict]:
        calls: list[dict] = []

        def fake_run(task, args, *, stage, mounts, command, timeout, entrypoint=None):
            calls.append({"mounts": mounts, "command": command, "entrypoint": entrypoint})
            if entrypoint == "/bin/sh":
                return cb.ScoutResult(
                    stage=stage,
                    name="probe",
                    file="",
                    exit_code=0,
                    output_tail=probe_tail,
                )
            return cb.ScoutResult(
                stage=stage,
                name="campaign",
                file="",
                exit_code=0,
                verdict="no_crash",
            )

        with (
            mock.patch.object(cb, "_scout_canonical_fuzzers", return_value=["rules_fuzzer"]),
            mock.patch.object(cb, "_scout_run", side_effect=fake_run),
        ):
            cb._scout_libfuzzer(
                self.task,
                _args(scout_mode="full", scout_libfuzzer_sec=1),
                self.scout,
                cb.ScoutBudget(4, time.monotonic() + 5),
                self.seeds,
                self.root,
            )
        return calls

    def test_campaign_uses_dict_when_supported(self) -> None:
        calls = self._run_campaign(
            " max_total_time              0  If positive, indicates the maximal total time.\n"
            " dict                        0  Experimental. Use the dictionary file.\n"
        )
        campaign = calls[-1]
        self.assertIn("-dict=/dict/fuzz.dict", campaign["command"])
        targets = [target for _host, target, _mode in campaign["mounts"]]
        self.assertIn("/dict/fuzz.dict", targets)

    def test_campaign_skips_dict_when_probe_has_no_dict_flag(self) -> None:
        calls = self._run_campaign("max_total_time=60\n")
        campaign = calls[-1]
        self.assertNotIn("-dict=/dict/fuzz.dict", campaign["command"])
        targets = [target for _host, target, _mode in campaign["mounts"]]
        self.assertNotIn("/dict/fuzz.dict", targets)
