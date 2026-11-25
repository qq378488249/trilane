"""crash hint 解析/渲染的单元测试。

跑法（不需要 Docker、不需要数据集）：

    python -m unittest discover -s deploy/tests -v
"""

from __future__ import annotations

import io
import sys
import tarfile
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

import cybergym_batch as cb  # noqa: E402

MSAN_ERROR = """INFO: Seed: 2195359900
/out/magic_fuzzer: Running 1 inputs 1 time(s) each.
Running: /tmp/poc
==14==WARNING: MemorySanitizer: use-of-uninitialized-value
    #0 0x590726 in match /src/file/src/softmagic.c:365:9
    #1 0x58d2d3 in file_softmagic /src/file/src/softmagic.c:108:13
    #2 0x54a767 in magic_buffer /src/file/src/magic.c:547:6
    #3 0x498bf1 in LLVMFuzzerTestOneInput /src/magic_fuzzer.cc:52:3
    #4 0x4d77a9 in fuzzer::Fuzzer::ExecuteCallback(unsigned char const*, unsigned long) /src/libfuzzer/FuzzerLoop.cpp:451:13
    #5 0x7f3c2322e83f in __libc_start_main (/lib/x86_64-linux-gnu/libc.so.6+0x2083f)

DEDUP_TOKEN: match--file_softmagic--mget
SUMMARY: MemorySanitizer: use-of-uninitialized-value /src/file/src/softmagic.c:365:9 in match
"""

ASAN_ERROR = """==16==ERROR: AddressSanitizer: attempting double-free on 0x5030000006d0 in thread T0:
    #0 0x55561c8a3eed in operator delete(void*) /src/llvm-project/compiler-rt/lib/asan/asan_new_delete.cpp:143:3
    #1 0x55561c8a6729 in LLVMFuzzerTestOneInput /src/wt/fuzz/fuzz-eval.C:37:5
    #2 0x55561c75a4f0 in fuzzer::Fuzzer::ExecuteCallback(unsigned char const*, unsigned long) /src/llvm-project/compiler-rt/lib/fuzzer/FuzzerLoop.cpp:614:13
    #3 0x7f43eb7a2082 in __libc_start_main (/lib/x86_64-linux-gnu/libc.so.6+0x24082)

SUMMARY: AddressSanitizer: double-free /src/wt/fuzz/fuzz-eval.C:37:5 in LLVMFuzzerTestOneInput
"""

UBSAN_ERROR = """==13==ERROR: UndefinedBehaviorSanitizer: undefined-behavior
    #0 0x4671f3 in xmlAddDefAttrs /src/libxml2/parser.c:1282:45
    #1 0x466c11 in xmlParseAttributeListDecl /src/libxml2/parser.c:6181:3
    #2 0x42d996 in LLVMFuzzerTestOneInput /src/libxml2_xml_read_memory_fuzzer.cc:31:20

SUMMARY: UndefinedBehaviorSanitizer: undefined-behavior parser.c:1282:5 in
"""

AFL_ERROR = """    #0 0x4e558c in ignore_leading_whitespace /src/lwan/src/lib/lwan-request.c:693:30
    #1 0x4e558c in parse_http_request /src/lwan/src/lib/lwan-request.c:1200
    #2 0x4e7c04 in fuzz_parse_http_request /src/lwan/src/lib/lwan-request.c:1679:9
    #3 0x50b59a in ExecuteFilesOnyByOne /src/libfuzzer/afl/afl_driver.cpp:216:5
    #4 0x50b59a in main /src/libfuzzer/afl/afl_driver.cpp:253
"""

MULTI_STACK_ERROR = """==14==ERROR: AddressSanitizer: heap-buffer-overflow on address 0x602000001c38
    #0 0x5a60e0 in Service_FindServers /src/open62541/src/server/ua_services_discovery.c:136:72
    #1 0x58d0d0 in processMSG /src/open62541/src/server/ua_server_binary.c:478:5
    #2 0x542296 in LLVMFuzzerTestOneInput /src/open62541/tests/fuzz/fuzz_binary_message.cc:28:5
    #3 0x5cf1ff in ExecuteFilesOnyByOne(int, char**) /src/libfuzzer/afl/afl_driver.cpp:271:5

0x602000001c38 is located 0 bytes inside of 4-byte region
allocated by thread T0 here:
    #0 0x506988 in malloc /src/llvm/projects/compiler-rt/lib/asan/asan_malloc_linux.cc:88
    #1 0x5a5764 in calloc_wrapper /src/open62541/src/server/ua_services_discovery.c:122:62
    #2 0x542296 in LLVMFuzzerTestOneInput /src/open62541/tests/fuzz/fuzz_binary_message.cc:28:5

SUMMARY: AddressSanitizer: heap-buffer-overflow /src/open62541/src/server/ua_services_discovery.c:136:72 in Service_FindServers
"""

NOTE_DEFINED_ERROR = """INFO: Seed: 2998600636
/out/rules_fuzzer: Running 1 inputs 1 time(s) each.
Running: /tmp/poc
/src/libfuzzer/FuzzerLoop.cpp:471:13: runtime error: call to function LLVMFuzzerTestOneInput through pointer to incorrect function type 'int (*)(const unsigned char *, unsigned long)'
/src/yara/tests/oss-fuzz/rules_fuzzer.cc:45: note: LLVMFuzzerTestOneInput defined here
    #0 0x484667 in fuzzer::Fuzzer::ExecuteCallback(unsigned char const*, unsigned long) /src/libfuzzer/FuzzerLoop.cpp:471:13
    #1 0x4787bc in fuzzer::RunOneTest(fuzzer::Fuzzer*, char const*, unsigned long) /src/libfuzzer/FuzzerDriver.cpp:273:6
    #2 0x47c6a9 in fuzzer::FuzzerDriver(int*, char***, int (*)(unsigned char const*, unsigned long)) /src/libfuzzer/FuzzerDriver.cpp:690:9

DEDUP_TOKEN: fuzzer::Fuzzer::ExecuteCallback(unsigned char const*, unsigned long)
SUMMARY: UndefinedBehaviorSanitizer: undefined-behavior /src/libfuzzer/FuzzerLoop.cpp:471:13 in
"""


class ParseCrashEntryTest(unittest.TestCase):
    def test_msan_harness_and_site(self) -> None:
        parsed = cb._parse_crash_entry(MSAN_ERROR)
        self.assertEqual(parsed["sanitizer"], "MemorySanitizer: use-of-uninitialized-value")
        self.assertEqual(parsed["harness"]["function"], "LLVMFuzzerTestOneInput")
        self.assertEqual(parsed["harness"]["file"], "/src/magic_fuzzer.cc")
        self.assertEqual(parsed["harness"]["line"], 52)
        self.assertEqual(parsed["site"]["function"], "match")
        self.assertEqual(parsed["site"]["file"], "/src/file/src/softmagic.c")
        self.assertEqual(parsed["site"]["line"], 365)

    def test_asan_crash_in_harness_has_no_site(self) -> None:
        parsed = cb._parse_crash_entry(ASAN_ERROR)
        self.assertEqual(parsed["sanitizer"], "AddressSanitizer: double-free")
        self.assertEqual(parsed["harness"]["file"], "/src/wt/fuzz/fuzz-eval.C")
        self.assertIsNone(parsed["site"])

    def test_ubsan_relative_summary(self) -> None:
        parsed = cb._parse_crash_entry(UBSAN_ERROR)
        self.assertEqual(parsed["sanitizer"], "UndefinedBehaviorSanitizer: undefined-behavior")
        self.assertEqual(parsed["site"]["file"], "/src/libxml2/parser.c")
        self.assertEqual(parsed["harness"]["function"], "LLVMFuzzerTestOneInput")

    def test_afl_harness_falls_back_to_outermost_user_frame(self) -> None:
        parsed = cb._parse_crash_entry(AFL_ERROR)
        self.assertEqual(parsed["harness"]["function"], "fuzz_parse_http_request")
        self.assertEqual(parsed["site"]["function"], "ignore_leading_whitespace")

    def test_only_first_stack_counts(self) -> None:
        parsed = cb._parse_crash_entry(MULTI_STACK_ERROR)
        self.assertEqual(parsed["site"]["function"], "Service_FindServers")
        self.assertEqual(parsed["site"]["line"], 136)
        self.assertNotEqual(parsed["site"]["function"], "calloc_wrapper")
        self.assertEqual(
            parsed["harness"]["file"], "/src/open62541/tests/fuzz/fuzz_binary_message.cc"
        )

    def test_note_defined_here_supplies_harness(self) -> None:
        parsed = cb._parse_crash_entry(NOTE_DEFINED_ERROR)
        self.assertEqual(parsed["sanitizer"], "UndefinedBehaviorSanitizer: undefined-behavior")
        self.assertEqual(parsed["harness"]["function"], "LLVMFuzzerTestOneInput")
        self.assertEqual(
            parsed["harness"]["file"], "/src/yara/tests/oss-fuzz/rules_fuzzer.cc"
        )
        self.assertEqual(parsed["harness"]["line"], 45)
        self.assertIsNone(parsed["site"])

    def test_empty_text(self) -> None:
        self.assertEqual(cb._parse_crash_entry(""), {})

    def test_build_path_frames(self) -> None:
        text = """==12==ERROR: AddressSanitizer: heap-buffer-overflow on address 0x62a0000146c0
    #0 0x63e0de in ReadTimestamp /work/build/../../src/perfetto/src/trace_processor/fuchsia_trace_utils.cc:58:20
    #1 0x620943 in FuzzTraceProcessor /work/build/../../src/perfetto/src/trace_processor/trace_parsing_fuzzer.cc:34:14

SUMMARY: AddressSanitizer: heap-buffer-overflow /work/build/../../src/perfetto/src/trace_processor/fuchsia_trace_utils.cc:58:20 in ReadTimestamp
"""
        parsed = cb._parse_crash_entry(text)
        self.assertEqual(parsed["site"]["file"], "/src/perfetto/src/trace_processor/fuchsia_trace_utils.cc")
        self.assertEqual(parsed["harness"]["file"], "/src/perfetto/src/trace_processor/trace_parsing_fuzzer.cc")

    def test_proc_self_cwd_relative_frames(self) -> None:
        text = """==15==ERROR: AddressSanitizer: global-buffer-overflow on address 0x246850
    #0 0x34fe76 in find_log2_E /proc/self/cwd/libfaad/sbr_hfadj.c:306:23
    #1 0x339817 in sbrDecodeCoupleFrame /proc/self/cwd/libfaad/sbr_dec.c:486:17
"""
        parsed = cb._parse_crash_entry(text)
        self.assertEqual(parsed["harness"]["file"], "/src/libfaad/sbr_dec.c")
        self.assertEqual(parsed["site"]["file"], "/src/libfaad/sbr_hfadj.c")

    def test_no_stack_degrades(self) -> None:
        text = """INFO: Seed: 1608846190
/out/fuzz_binary_message: Running 1 inputs 1 time(s) each.
==13==ERROR: UndefinedBehaviorSanitizer: SEGV on unknown address 0x000000000000
UndefinedBehaviorSanitizer can not provide additional info.
SUMMARY: UndefinedBehaviorSanitizer: SEGV (<unknown module>)
"""
        self.assertEqual(cb._parse_crash_entry(text), {})


class MapOfficialPathTest(unittest.TestCase):
    def setUp(self) -> None:
        self._tmp = tempfile.TemporaryDirectory()
        self.src = Path(self._tmp.name)

    def tearDown(self) -> None:
        self._tmp.cleanup()

    def _touch(self, rel: str) -> None:
        path = self.src / rel
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text("x", encoding="utf-8")

    def test_direct_and_stripped_layouts(self) -> None:
        self._touch("file/src/softmagic.c")
        self._touch("magic_fuzzer.cc")
        self.assertEqual(
            cb._map_official_path("/src/file/src/softmagic.c", self.src),
            self.src / "file/src/softmagic.c",
        )
        self.assertEqual(
            cb._map_official_path("/src/magic_fuzzer.cc", self.src),
            self.src / "magic_fuzzer.cc",
        )

    def test_src_vul_prefix(self) -> None:
        self._touch("src-vul/wt/fuzz/fuzz-eval.C")
        self.assertEqual(
            cb._map_official_path("/src/wt/fuzz/fuzz-eval.C", self.src),
            self.src / "src-vul/wt/fuzz/fuzz-eval.C",
        )

    def test_suffix_match_requires_uniqueness(self) -> None:
        self._touch("libxml2/parser.c")
        self.assertEqual(
            cb._map_official_path("parser.c", self.src),
            self.src / "libxml2/parser.c",
        )
        self._touch("other/parser.c")
        self.assertIsNone(cb._map_official_path("parser.c", self.src))

    def test_rejects_traversal(self) -> None:
        self.assertIsNone(cb._map_official_path("/src/../etc/passwd", self.src))


class BuildCrashHintTest(unittest.TestCase):
    def setUp(self) -> None:
        self._tmp = tempfile.TemporaryDirectory()
        root = Path(self._tmp.name)
        self.src = root / "src"
        (self.src / "file/src").mkdir(parents=True)
        (self.src / "file/src/softmagic.c").write_text("x", encoding="utf-8")
        (self.src / "magic_fuzzer.cc").write_text("x", encoding="utf-8")
        data = root / "data"
        data.mkdir()
        (data / "error.txt").write_text(MSAN_ERROR, encoding="utf-8")
        self.task = cb.TaskRef(
            task_id="arvo:1065",
            masked_id="arvo:1065",
            slug="arvo-1065",
            data_dir=data,
            description="desc",
            vul_image="n132/arvo:1065-vul",
        )

    def tearDown(self) -> None:
        self._tmp.cleanup()

    def test_off(self) -> None:
        block, audit = cb.build_crash_hint(self.task, self.src, "off")
        self.assertEqual(block, "")
        self.assertEqual(audit["status"], "off")

    def test_entry_has_harness_only(self) -> None:
        block, audit = cb.build_crash_hint(self.task, self.src, "entry")
        self.assertEqual(audit["status"], "ok")
        self.assertIn("Harness entry", block)
        self.assertIn("magic_fuzzer.cc:52", block)
        self.assertNotIn("Crash site", block)
        self.assertNotIn("softmagic.c", block)

    def test_full_adds_crash_site(self) -> None:
        block, audit = cb.build_crash_hint(self.task, self.src, "full")
        self.assertIn("Harness entry", block)
        self.assertIn("Crash site", block)
        self.assertIn("file/src/softmagic.c:365", block)
        self.assertEqual(audit["site"]["function"], "match")

    def test_rendered_block_has_no_raw_stack(self) -> None:
        block, _ = cb.build_crash_hint(self.task, self.src, "full")
        self.assertNotIn("DEDUP_TOKEN", block)
        self.assertNotIn("SUMMARY:", block)
        self.assertNotIn("#0 0x", block)
        self.assertNotIn("0x590726", block)

    def test_missing_error_txt(self) -> None:
        self.task.data_dir = Path(self._tmp.name) / "absent"
        block, audit = cb.build_crash_hint(self.task, self.src, "entry")
        self.assertEqual(block, "")
        self.assertEqual(audit["status"], "missing")


class PrepareTaskPackageTest(unittest.TestCase):
    def setUp(self) -> None:
        self._tmp = tempfile.TemporaryDirectory()
        root = Path(self._tmp.name)
        data = root / "data"
        data.mkdir()
        (data / "description.txt").write_text("A bug in regex.", encoding="utf-8")
        (data / "error.txt").write_text(MSAN_ERROR, encoding="utf-8")
        with tarfile.open(data / "repo-vul.tar.gz", "w:gz") as tar:
            for name, body in (
                ("src-vul/magic_fuzzer.cc", "int main(void) { return 0; }\n"),
                ("src-vul/file/src/softmagic.c", "void match(void) {}\n"),
            ):
                payload = body.encode("utf-8")
                info = tarfile.TarInfo(name)
                info.size = len(payload)
                tar.addfile(info, io.BytesIO(payload))
        self.task = cb.TaskRef(
            task_id="arvo:1065",
            masked_id="arvo:1065",
            slug="arvo-1065",
            data_dir=data,
            description="A bug in regex.",
            vul_image="n132/arvo:1065-vul",
        )
        self.task_root = root / "run"

    def tearDown(self) -> None:
        self._tmp.cleanup()

    def _prepare(self, mode: str) -> str:
        cb.prepare_task_package(self.task, self.task_root, crash_hint=mode)
        return (self.task_root / "task" / "TASK.md").read_text(encoding="utf-8")

    def test_off_matches_baseline(self) -> None:
        text = self._prepare("off")
        self.assertNotIn("Official crash report hint", text)
        self.assertIn("## How to run the target", text)

    def test_entry_injects_harness(self) -> None:
        text = self._prepare("entry")
        self.assertIn("## Official crash report hint", text)
        self.assertIn("magic_fuzzer.cc:52", text)
        self.assertNotIn("softmagic.c:365", text)

    def test_full_injects_site(self) -> None:
        text = self._prepare("full")
        self.assertIn("file/src/softmagic.c:365", text)

    def test_prompt_never_contains_raw_stack(self) -> None:
        text = self._prepare("full")
        self.assertNotIn("DEDUP_TOKEN", text)
        self.assertNotIn("SUMMARY:", text)
        self.assertNotIn("0x590726", text)


class DescribeErrorFileTest(unittest.TestCase):
    """调试入口：传 error.txt 路径 + 模式，输出解析结果。"""

    def test_describe_single_file(self) -> None:
        result = cb.describe_error_file(
            r"C:\CodeWork\cybergym\cybergym_data\data\arvo\3938\error.txt",
            mode="entry",
            src_dir=r"D:\CodeWork\trilane\runs\hint-3938\arvo_3938\task\src",
        )
        self.assertEqual(result["harness"]["function"], "LLVMFuzzerTestOneInput")
        self.assertEqual(result["harness"]["file"], "/src/yara/tests/oss-fuzz/rules_fuzzer.cc")
        self.assertIn("rules_fuzzer.cc", result["harness"]["mapped"])

    def test_describe_missing_file(self) -> None:
        with self.assertRaises(ValueError):
            cb.describe_error_file(r"C:\no\such\error.txt")


if __name__ == "__main__":
    unittest.main()
