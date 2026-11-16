#!/usr/bin/env python3
"""跑批失败排障：把一个批次的结论、阶段进度、产物和错误线索汇总成一份报告。

用法：

    python3 deploy/triage.py runs/<批次>                     # 查全部
    python3 deploy/triage.py runs/<批次> --task arvo:1856     # 只看一个
    python3 deploy/triage.py runs/<批次> --task arvo:1856 arvo:3736   # 看多个
    python3 deploy/triage.py runs/<批次> --task-file list.txt # 从文件读任务列表
    python3 deploy/triage.py runs/<批次> --task arvo:1856 --log-errors --transcript-tail 30   # 深挖
    python3 deploy/triage.py runs/<批次> --json             # 机器可读（给 CI/告警）

--task 可传 task_id（arvo:1856）或 slug（arvo_1856）。不传 --task 就是查全部。

只读文件，不改任何东西，也不启动容器。批次跑完后、进程被杀后都可以跑。
"""

from __future__ import annotations

import argparse
import json
import re
import sys
from datetime import datetime, timezone
from pathlib import Path

STAGE_IDS = ("stage0", "stage1", "stage2", "stage3", "stage4", "stage5")

# agent.log 里的网关/网络错误特征
LLM_ERROR_PATTERNS = (
    ("503", re.compile(r"\b503\b")),
    ("429", re.compile(r"\b429\b")),
    ("401", re.compile(r"\b401\b")),
    ("5xx", re.compile(r"\b50[0-9]\b")),
    ("conn_reset", re.compile(r"connection reset|ECONNRESET", re.I)),
    ("timeout", re.compile(r"timed? ?out|timeout", re.I)),
    ("rate_limit", re.compile(r"rate.?limit", re.I)),
)

# transcript 里的环境类错误（工具输出只进 transcript，不进 agent.log）。
# 正则要和批次脚本的 DISK_SPACE_RE（cybergym_batch.py:95）一样严——阶段提示词里
# 本身就写着 "If the environment reports `no space left on device` ..."，宽松匹配会误报。
ENV_ERROR_PATTERNS = (
    (
        "disk_full",
        re.compile(
            r"(error response from daemon.*no space left on device"
            r"|no space left on device: unknown"
            r"|(?:writing|write|mkdir|open|create|copy).*no space left on device)",
            re.IGNORECASE,
        ),
    ),
    ("permission", re.compile(r"permission denied", re.I)),
    ("conn_refused", re.compile(r"connection refused", re.I)),
    ("oci_runtime", re.compile(r"OCI runtime create failed", re.I)),
    ("no_such_image", re.compile(r"no such image|manifest unknown", re.I)),
)

STATUS_HINT = {
    "solved": "成功。",
    "error": "批次层 Python 异常，看 trace 字段。",
    "agent_failed": "智能体没跑完（超时/LLM 断连/runbook 报错），不是题目解不出。",
    "timeout": "撞墙钟超时。",
    "container_failed": "容器没起来，看 agent.log 开头。",
    "disk_space": "磁盘满，永不自动重试，需人工清理。",
    "no_poc": "跑完了但没交出 PoC。",
    "unstable": "MSan 未初始化读导致结果跳变，多跑几轮再判。",
    "vul_only": "vul 崩了但没做 fix 侧校验。",
    "fix_also_crashes": "PoC 命中了别的缺陷，fix 侧也崩。",
}


def read_json(path: Path) -> dict:
    try:
        payload = json.loads(path.read_text(encoding="utf-8", errors="replace"))
    except (OSError, json.JSONDecodeError):
        return {}
    return payload if isinstance(payload, dict) else {}


def read_jsonl(path: Path) -> list[dict]:
    records: list[dict] = []
    try:
        text = path.read_text(encoding="utf-8", errors="replace")
    except OSError:
        return records
    for line in text.splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            payload = json.loads(line)
        except json.JSONDecodeError:
            continue
        if isinstance(payload, dict):
            records.append(payload)
    return records


def human_size(num: int) -> str:
    if num >= 1024 * 1024:
        return f"{num / 1024 / 1024:.1f} MB"
    if num >= 1024:
        return f"{num / 1024:.1f} KB"
    return f"{num} B"


# --log-errors 抽取用。关键约束：只认**日志行**（带时间戳前缀）。
# agent.log 里混着大量工具输出（源码、编译日志），宽松匹配会命中
# 源码里的 ERROR_SUCCESS / failed 之类，全是噪音。
LOG_LINE_PREFIX = rf"^\d{{4}}-\d{{2}}-\d{{2}}T\S+\s+"
# ERROR 级：这才是"失败原因"。WARN 单独放，因为引擎会把
# "model_messages is missing" 这类无害提示每个 turn 都刷一遍。
LOG_ERROR_PATTERNS = (
    ("level", re.compile(LOG_LINE_PREFIX + r"(?:ERROR|FATAL)")),
    (
        "error_code",
        re.compile(
            LOG_LINE_PREFIX
            + r".*(?:error code|error\.code)\s*[:=]\s*\d{3}",
            re.I,
        ),
    ),
    (
        "exception",
        re.compile(
            LOG_LINE_PREFIX
            + r".*(?:AuthenticationError|ServiceUnavailableError|RateLimitError|Traceback)",
        ),
    ),
)
LOG_WARN_PATTERNS = (("warn_level", re.compile(LOG_LINE_PREFIX + r"WARN")),)

ANSI_RE = re.compile(r"\x1b\[[0-9;]*m")


def strip_ansi(text: str) -> str:
    return ANSI_RE.sub("", text)


def tail_text(path: Path, max_bytes: int = 4_000_000) -> str:
    """只读文件末尾若干字节。agent.log 动辄十几 MB，整读会很慢。"""
    try:
        size = path.stat().st_size
        with path.open("rb") as handle:
            if size > max_bytes:
                handle.seek(size - max_bytes)
                handle.read(1)  # 丢掉被截断的半行
            data = handle.read()
    except OSError:
        return ""
    return data.decode("utf-8", errors="replace")


def grep_with_context(text: str, patterns: tuple, context: int = 2) -> list[str]:
    """在文本里找命中行，连同前后 context 行一起返回（去重）。"""
    lines = strip_ansi(text).splitlines()
    keep: set[int] = set()
    for index, line in enumerate(lines):
        if any(pattern.search(line) for _, pattern in patterns):
            for near in range(max(0, index - context), min(len(lines), index + context + 1)):
                keep.add(near)
    return [f"{index + 1}: {lines[index]}" for index in sorted(keep)]


SPAN_PREFIX_RE = re.compile(r"^[A-Za-z_][\w.]*\{[^{}]*\}\s*:?\s*")
LEVEL_RE = re.compile(
    r"^(\d{4}-\d{2}-\d{2}T\S+)\s+"
    r"(ERROR|WARN|FATAL|INFO|DEBUG|TRACE)\s+"
)


def compact_log_line(line: str) -> str:
    """压掉 span 前缀（session_loop{...}:turn{...}:），只留时间、级别、消息。"""
    match = LEVEL_RE.match(line)
    if not match:
        return line
    stamp, level = match.group(1), match.group(2)
    rest = line[match.end():]
    while True:
        trimmed = SPAN_PREFIX_RE.sub("", rest, count=1)
        if trimmed == rest:
            break
        rest = trimmed
    return f"{stamp} {level} {rest.strip()}"


def dedupe_messages(lines: list[str], limit: int = 40) -> list[str]:
    """把重复消息合并成一条并标注次数。

    引擎会把同一条 WARN（例如 "model_messages is missing"）每个 turn 刷一遍，
    一次超时任务能刷出几百行。按"级别 + 消息体"合并后通常只剩几条。
    """
    seen: dict[str, tuple[str, int]] = {}
    order: list[str] = []
    for raw in lines:
        number, _, body = raw.partition(": ")
        compact = compact_log_line(body)
        match = LEVEL_RE.match(compact)
        key = compact[match.end():] if match else compact
        level = match.group(2) if match else ""
        bucket = f"{level}|{key}"
        if bucket in seen:
            first, count = seen[bucket]
            seen[bucket] = (first, count + 1)
        else:
            seen[bucket] = (f"{number}: {compact}", 1)
            order.append(bucket)
    merged = []
    for bucket in order[:limit]:
        text, count = seen[bucket]
        merged.append(f"{text}   ×{count}" if count > 1 else text)
    return merged


def tail_lines(text: str, count: int) -> list[str]:
    if count <= 0:
        return []
    lines = [ln for ln in strip_ansi(text).splitlines() if ln.strip()]
    return [f"{len(lines) - len(tail) + i + 1}: {line}" for i, line in enumerate(tail)] if (tail := lines[-count:]) else []


def latest_by_task(records: list[dict]) -> list[dict]:
    """同一任务多行时取最后一行（与 load_done/summarize 一致）。"""
    latest: dict[str, dict] = {}
    order: list[str] = []
    for record in records:
        task_id = record.get("task_id")
        if not task_id:
            continue
        if task_id not in latest:
            order.append(task_id)
        latest[task_id] = record
    return [latest[task_id] for task_id in order]


def newest_run_dir(task_root: Path) -> Path | None:
    runs_root = task_root / "state" / "trilane" / "runs"
    if not runs_root.is_dir():
        return None
    candidates = [p for p in runs_root.iterdir() if p.is_dir() and (p / "stage0").is_dir()]
    if not candidates:
        return None
    return sorted(candidates, key=lambda p: p.name)[-1]


def stage_rows(run_dir: Path) -> list[dict]:
    rows = []
    for stage in STAGE_IDS:
        stage_dir = run_dir / stage
        if not stage_dir.is_dir():
            continue
        status = read_json(stage_dir / "status.json").get("status") or "-"
        transcript = stage_dir / "transcript.md"
        size = transcript.stat().st_size if transcript.exists() else 0
        runbook = stage_dir / "runbook.json"
        snapshot = "无"
        if runbook.exists():
            payload = read_json(runbook)
            snapshot = "有效" if "objective" in payload and "stages" in payload else "占位"
        rows.append(
            {
                "stage": stage,
                "status": status,
                "transcript_bytes": size,
                "snapshot": snapshot,
            }
        )
    return rows


DEFAULT_SCAN_LIMIT_MB = 64


def read_window(path: Path, limit_bytes: int) -> tuple[str, int, bool]:
    """读取文件内容；超过 limit_bytes 时只读末尾。

    返回 (文本, 文件总字节, 是否被截断)。服务器上的 agent.log 可能几百 MB，
    整读会吃掉同等内存，所以默认走"末尾窗口"。
    """
    try:
        total = path.stat().st_size
    except OSError:
        return "", 0, False
    if limit_bytes <= 0 or total <= limit_bytes:
        try:
            return path.read_text(encoding="utf-8", errors="replace"), total, False
        except OSError:
            return "", total, False
    return tail_text(path, limit_bytes), total, True


def _variants(needle: str) -> tuple[str, ...]:
    """常见大小写写法。不做 text.lower()，避免几百 MB 日志再复制一份。"""
    return tuple({needle, needle.capitalize(), needle.upper()})


def _is_word(ch: str) -> bool:
    return bool(ch) and (ch.isalnum() or ch == "_")


def _count_literal(text: str, needle: str, word_bounded: bool) -> int:
    r"""字面量计数，用 str.find（C 实现）。

    比正则快两个数量级：64MB 窗口下 `\b503\b` 要 1.5s，str.find 约 0.01s。
    word_bounded=True 时要求两侧都不是 \w（字母/数字/下划线），等价于正则的 \b，
    否则时间戳里的 `.401Z` 会被当成 401。
    """
    total = 0
    start = 0
    size = len(needle)
    while True:
        index = text.find(needle, start)
        if index < 0:
            return total
        if word_bounded:
            before = text[index - 1] if index > 0 else ""
            after = text[index + size] if index + size < len(text) else ""
            if _is_word(before) or _is_word(after):
                start = index + size
                continue
        total += 1
        start = index + size


# 网关错误用字面量统计（不用正则，见 _count_literal 的说明）。
# 大小写按日志里的实际写法：短语是小写，ECONNRESET 是大写。
LLM_LITERALS = (
    ("401", ("401",), True),
    ("429", ("429",), True),
    ("503", ("503",), True),
    # 排除 503：它单独成桶，否则会被重复计数（原正则交替式里 503 优先命中）
    ("5xx", tuple(str(code) for code in range(500, 510) if code != 503), True),
    ("conn_reset", _variants("connection reset") + ("ECONNRESET",), False),
    (
        "timeout",
        _variants("timeout") + _variants("timed out") + _variants("time out") + ("timedout", "Timedout", "TIMEDOUT"),
        False,
    ),
    ("rate_limit", _variants("rate limit") + _variants("rate-limit") + _variants("rate_limit"), False),
)


def count_llm_errors(path: Path, limit_bytes: int = 0) -> dict[str, int]:
    counts = {name: 0 for name, _, _ in LLM_LITERALS}
    text, _, _ = read_window(path, limit_bytes)
    if not text:
        return counts
    for name, needles, word_bounded in LLM_LITERALS:
        counts[name] = sum(
            _count_literal(text, needle, word_bounded) for needle in needles
        )
    return counts


def transcript_errors(run_dir: Path, limit_bytes: int = 0) -> dict[str, int]:
    counts = {name: 0 for name, _ in ENV_ERROR_PATTERNS}
    for stage in STAGE_IDS:
        transcript = run_dir / stage / "transcript.md"
        if not transcript.exists():
            continue
        text, _, _ = read_window(transcript, limit_bytes)
        if not text:
            continue
        for name, pattern in ENV_ERROR_PATTERNS:
            counts[name] += len(pattern.findall(text))
    return counts


def diagnose(record: dict, rows: list[dict], llm: dict, env: dict) -> list[str]:
    """给出排查结论。"""
    lines: list[str] = []
    status = record.get("status") or "unknown"

    if status == "solved":
        lines.append("任务已解出，无需排查。")
        return lines

    if status == "error":
        trace = record.get("trace")
        lines.append("批次层抛异常，异常栈在 results.jsonl 的 trace 字段。")
        if trace:
            last = [ln for ln in trace.splitlines() if ln.strip()][-1:]
            for ln in last:
                lines.append(f"  {ln.strip()}")
        return lines

    if status == "disk_space":
        lines.append("磁盘满：脚本已在 error 字段定位到具体 transcript 行。")
        lines.append(f"  {record.get('error')}")
        return lines

    # 断点是 running/active 的那个 stage；pending 只是"还没跑到"，不是断点。
    unfinished = [r for r in rows if str(r["status"]).lower() in ("running", "active")]
    if not unfinished:
        unfinished = [
            r for r in rows if str(r["status"]).lower() not in ("completed", "done")
        ]
    if unfinished:
        lines.append(
            f"断点在 {unfinished[0]['stage']}（status={unfinished[0]['status']}），"
            f"该 stage transcript {human_size(unfinished[0]['transcript_bytes'])}。"
        )
    else:
        lines.append("所有 stage 都标记为完成，但没有得出最终判定。")

    placeholders = [r["stage"] for r in rows if r["snapshot"] == "占位"]
    if placeholders:
        lines.append(
            f"注意：{', '.join(placeholders)} 的 runbook.json 还是引擎初始化的 "
            f"{{}} 占位——这些 stage 没跑出真实快照，不能作为续跑点。"
        )

    if env.get("disk_full"):
        lines.append("transcript 里出现 no space left on device：磁盘满。")
    if env.get("oci_runtime") or env.get("no_such_image"):
        lines.append("transcript 里有容器/镜像启动失败：目标镜像可能没导进 DinD。")

    gateway = sum(v for k, v in llm.items() if k in ("503", "429", "401", "5xx"))
    if gateway:
        detail = "，".join(f"{k}×{v}" for k, v in llm.items() if v and k != "5xx")
        lines.append(f"agent.log 里网关错误 {detail}：内网 LLM 不稳，重试已扛住部分。")
        if status == "agent_failed":
            lines.append("  若重试耗尽导致失败，调大 request_max_retries / stream_max_retries。")

    if status == "no_poc":
        lines.append("智能体跑完了但没产出候选：看 S2 语义审计的 findings。")
    if status in ("unstable", "vul_only", "fix_also_crashes"):
        lines.append("判定不通过：对照 rounds 里的 vul/fix 出口码看是哪种。")

    return lines


def build(
    batch_dir: Path,
    *,
    task_filter: set[str] | None = None,
    log_tail: int = 0,
    log_errors: bool = False,
    log_warnings: bool = False,
    transcript_tail: int = 0,
    scan_limit_bytes: int = DEFAULT_SCAN_LIMIT_MB * 1024 * 1024,
) -> dict:
    results_path = batch_dir / "results.jsonl"
    records = latest_by_task(read_jsonl(results_path))
    tasks = []
    wanted = task_filter or set()
    matched: set[str] = set()
    for record in records:
        slug = record.get("slug") or str(record.get("task_id", "")).replace(":", "_")
        if wanted and record.get("task_id") not in wanted and slug not in wanted:
            continue
        matched.add(record.get("task_id") or "")
        matched.add(slug)
        task_root = batch_dir / slug
        run_dir = newest_run_dir(task_root)
        rows = stage_rows(run_dir) if run_dir else []
        agent_log = task_root / "agent.log"
        llm = count_llm_errors(agent_log, scan_limit_bytes)
        env = transcript_errors(run_dir, scan_limit_bytes) if run_dir else {}
        try:
            log_bytes = agent_log.stat().st_size
        except OSError:
            log_bytes = 0

        # 单任务深挖：agent.log 末尾 / 错误行上下文 / 断点 stage 的 transcript 末尾
        detail: dict = {}
        if log_tail or log_errors or log_warnings:
            # 和计数用同一个窗口，避免几百 MB 的日志整读
            text, _, _ = read_window(agent_log, scan_limit_bytes)
            if log_tail:
                detail["log_tail"] = tail_lines(text, log_tail)
            if log_errors or log_warnings:
                patterns = LOG_ERROR_PATTERNS + (LOG_WARN_PATTERNS if log_warnings else ())
                raw_hits = grep_with_context(text, patterns, context=0)
                detail["log_errors_total"] = len(raw_hits)
                detail["log_errors"] = dedupe_messages(raw_hits)
        if transcript_tail and rows:
            breakpoint_stage = next(
                (
                    r["stage"]
                    for r in rows
                    if str(r["status"]).lower() in ("running", "active")
                ),
                rows[-1]["stage"],
            )
            text = tail_text(run_dir / breakpoint_stage / "transcript.md", 2_000_000)
            detail["breakpoint_stage"] = breakpoint_stage
            detail["transcript_tail"] = tail_lines(text, transcript_tail)

        tasks.append(
            {
                "task_id": record.get("task_id"),
                "slug": slug,
                "status": record.get("status"),
                "agent_status": record.get("agent_status"),
                "duration_sec": record.get("agent_duration_sec"),
                "attempts": record.get("agent_attempts"),
                "error": record.get("error"),
                "trace": record.get("trace"),
                "resume_attempts": record.get("resume_attempts") or [],
                "submitted": record.get("submitted"),
                "findings_count": record.get("findings_count"),
                "run_id": run_dir.name if run_dir else None,
                "stages": rows,
                "log_bytes": log_bytes,
                "llm_errors": {k: v for k, v in llm.items() if v},
                "env_errors": {k: v for k, v in env.items() if v},
                "detail": detail,
                "artifacts": {
                    name: human_size(p.stat().st_size)
                    for name, p in (
                        ("result.json", task_root / "out" / "result.json"),
                        ("agent.log", agent_log),
                        ("report.md", task_root / "out" / "report.md"),
                    )
                    if p.exists()
                },
                "findings": [
                    {
                        "id": f.get("id"),
                        "severity": f.get("severity"),
                        "title": str(f.get("title") or "")[:110],
                    }
                    for f in (read_json(task_root / "out" / "result.json").get("findings") or [])
                ],
                "diagnosis": diagnose(record, rows, llm, env),
            }
        )

    # results.jsonl 里没有的任务：state 目录里可能还有现场
    known = {t["slug"] for t in tasks}
    orphans = []
    if batch_dir.is_dir():
        for child in sorted(batch_dir.iterdir()):
            if not child.is_dir() or child.name in known:
                continue
            run_dir = newest_run_dir(child)
            if run_dir is None:
                continue
            orphans.append(
                {
                    "slug": child.name,
                    "run_id": run_dir.name,
                    "stages": stage_rows(run_dir),
                    "reason": "results.jsonl 里没有记录，但 state 里有 run 现场",
                }
            )

    return {
        "batch": str(batch_dir),
        "generated_at": datetime.now(timezone.utc).astimezone().isoformat(timespec="seconds"),
        "results_exists": results_path.exists(),
        "scan_limit_bytes": scan_limit_bytes,
        "requested": sorted(wanted) if wanted else None,
        "not_found": sorted(wanted - matched) if wanted else [],
        "tasks": tasks,
        "orphan_task_dirs": [] if wanted else orphans,
    }


def render(data: dict) -> str:
    out: list[str] = []
    line = "─" * 72
    out.append(line)
    out.append(f"批次 triage：{data['batch']}")
    out.append(f"生成时间：{data['generated_at']}")
    if not data["results_exists"]:
        out.append("!! results.jsonl 不存在 —— 批次可能未启动或进程被外部杀死")
    if data.get("requested"):
        out.append(f"查询任务：{', '.join(data['requested'])}")
        out.append(f"命中 {len(data['tasks'])} 个")
    if data.get("not_found"):
        out.append(f"!! 未找到：{', '.join(data['not_found'])}")
        out.append("   （提示：可传 task_id 如 arvo:1856，或 slug 如 arvo_1856）")
    out.append(line)

    for task in data["tasks"]:
        out.append("")
        out.append(f"── {task['task_id']} " + "─" * 40)
        out.append(f"  状态      : {task['status']}   ({STATUS_HINT.get(task['status'], '')})")
        out.append(f"  agent状态 : {task['agent_status']}")
        out.append(f"  耗时      : {task['duration_sec']}s    尝试次数: {task['attempts']}")
        if task["error"]:
            out.append(f"  错误      : {str(task['error'])[:220]}")
        if task["resume_attempts"]:
            out.append("  续跑历史  :")
            for item in task["resume_attempts"]:
                out.append(
                    f"      attempt{item.get('attempt')} 从 {item.get('from_stage')} "
                    f"({item.get('previous_status')}) -> {item.get('outcome')}"
                )
        if task["submitted"]:
            rounds = task["submitted"].get("rounds") or []
            for rnd in rounds:
                out.append(
                    f"  判定      : vul={rnd.get('vul_exit_code')} fix={rnd.get('fix_exit_code')}"
                )
            out.append(f"  提交      : {task['submitted'].get('file')}")

        if task["stages"]:
            out.append(f"  [阶段进度] run={task['run_id']}")
            for row in task["stages"]:
                out.append(
                    f"      {row['stage']:<7} {str(row['status']):<10} "
                    f"transcript={human_size(row['transcript_bytes']):<9} 快照={row['snapshot']}"
                )

        if task["llm_errors"]:
            detail = "，".join(f"{k}×{v}" for k, v in task["llm_errors"].items())
            out.append(f"  [LLM 错误] agent.log：{detail}")
        limit = data.get("scan_limit_bytes") or 0
        log_bytes = task.get("log_bytes") or 0
        if limit and log_bytes > limit:
            out.append(
                f"  [注] agent.log {human_size(log_bytes)}，统计只覆盖末尾 "
                f"{human_size(limit)}（可用 --scan-limit 调整）"
            )
        if task["env_errors"]:
            detail = "，".join(f"{k}×{v}" for k, v in task["env_errors"].items())
            out.append(f"  [环境错误] transcript：{detail}")

        if task["findings"]:
            out.append(f"  [findings] {len(task['findings'])}")
            for finding in task["findings"]:
                out.append(
                    f"      {finding['id']:<10} {str(finding['severity']):<8} {finding['title']}"
                )

        if task["artifacts"]:
            detail = "，".join(f"{k}={v}" for k, v in task["artifacts"].items())
            out.append(f"  [产物] {detail}")

        out.append("  [结论]")
        for item in task["diagnosis"]:
            out.append(f"      {item}")

        detail = task.get("detail") or {}
        if detail.get("breakpoint_stage"):
            out.append("")
            out.append(f"  [断点 transcript 末尾] stage={detail['breakpoint_stage']}")
            for ln in detail.get("transcript_tail") or []:
                out.append(f"      {ln[:200]}")
        if detail.get("log_errors"):
            raw = detail.get("log_errors_total", len(detail["log_errors"]))
            out.append("")
            out.append(
                f"  [agent.log 错误行] 原始 {raw} 行，按消息去重后 {len(detail['log_errors'])} 条"
            )
            for ln in detail["log_errors"]:
                number, _, body = ln.partition(": ")
                out.append(f"      {number}: {body[:300]}")
        if detail.get("log_tail"):
            out.append("")
            out.append("  [agent.log 末尾]")
            for ln in detail["log_tail"]:
                number, _, body = ln.partition(": ")
                out.append(f"      {number}: {compact_log_line(body)[:300]}")

    for orphan in data["orphan_task_dirs"]:
        out.append("")
        out.append(f"── {orphan['slug']} " + "─" * 40)
        out.append(f"  {orphan['reason']}")
        out.append(f"  run={orphan['run_id']}")
        for row in orphan["stages"]:
            out.append(
                f"      {row['stage']:<7} {str(row['status']):<10} "
                f"transcript={human_size(row['transcript_bytes']):<9} 快照={row['snapshot']}"
            )
        out.append("      → 重新跑批次时会自动从断点续跑（若快照有效）")

    out.append("")
    return "\n".join(out)


def main(argv: list[str]) -> int:
    parser = argparse.ArgumentParser(description="跑批失败排障")
    parser.add_argument("batch", help="批次目录，例如 runs/smoke-107")
    parser.add_argument(
        "--task",
        nargs="+",
        metavar="TASK",
        help="只看这些任务（task_id 如 arvo:1856，或 slug 如 arvo_1856）；不传则查全部",
    )
    parser.add_argument(
        "--task-file",
        metavar="FILE",
        help="任务列表文件，一行一个（# 开头的行忽略），可与 --task 同时用",
    )
    parser.add_argument("--log-tail", type=int, default=0, metavar="N", help="打印每个任务 agent.log 的末尾 N 行")
    parser.add_argument("--log-errors", action="store_true", help="打印 agent.log 里的 ERROR/FATAL 行及其上下文")
    parser.add_argument("--log-warnings", action="store_true", help="连 WARN 行一起打印（引擎有大量无害 WARN，默认不显示）")
    parser.add_argument("--transcript-tail", type=int, default=0, metavar="N", help="打印断点 stage 的 transcript 末尾 N 行")
    parser.add_argument(
        "--scan-limit",
        type=int,
        default=DEFAULT_SCAN_LIMIT_MB,
        metavar="MB",
        help=f"统计日志时最多扫描末尾多少 MB（0 = 全文）；默认 {DEFAULT_SCAN_LIMIT_MB}",
    )
    parser.add_argument("--json", action="store_true", help="输出 JSON")
    args = parser.parse_args(argv)

    wanted: set[str] = set()
    for value in args.task or []:
        wanted.add(value.strip())
    if args.task_file:
        task_file = Path(args.task_file).expanduser()
        if not task_file.is_file():
            print(f"任务列表文件不存在：{task_file}", file=sys.stderr)
            return 2
        for line in task_file.read_text(encoding="utf-8", errors="replace").splitlines():
            line = line.strip()
            if line and not line.startswith("#"):
                wanted.add(line)

    batch_dir = Path(args.batch).expanduser()
    if not batch_dir.is_dir():
        print(f"批次目录不存在：{batch_dir}", file=sys.stderr)
        return 2

    data = build(
        batch_dir,
        task_filter=wanted or None,
        log_tail=args.log_tail,
        log_errors=args.log_errors,
        log_warnings=args.log_warnings,
        scan_limit_bytes=args.scan_limit * 1024 * 1024,
        transcript_tail=args.transcript_tail,
    )
    if args.json:
        print(json.dumps(data, ensure_ascii=False, indent=2))
    else:
        print(render(data))
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
