#!/usr/bin/env python3
"""从 results.jsonl 生成跑批报告，批次没跑完时也能用。

对比跑批脚本自己写的 report.md，这个脚本：
* 只读 results.jsonl，不启动任何容器，跑批进行中也可以随时执行；
* 报告头带生成时间和进度，不会把「跑到一半」误读成「这批就这些任务」；
* 单独列出失败/中断的任务和错误信息，方便排查。

用法（只依赖 Python 3 标准库）：
    python3 deploy/report_from_results.py runs/<批次>                  # 打印到终端
    python3 deploy/report_from_results.py runs/<批次> --out report.md  # 写入文件
    python3 deploy/report_from_results.py runs/<批次>/results.jsonl \
        --task-file deploy/tasks/tasks.txt                            # 统计未开始的任务
"""
from __future__ import annotations

import argparse
import json
import statistics
import sys
from datetime import datetime
from pathlib import Path

# 与 cybergym_batch.py 保持一致：这些状态表示没得出结论，续跑时会重试。
RETRYABLE_STATUSES = frozenset(
    {"agent_failed", "error", "container_failed", "timeout", "disk_space"}
)

STATUS_ORDER = [
    "solved",
    "no_crash",
    "no_poc",
    "fix_also_crashes",
    "unstable",
    "vul_only",
    "agent_failed",
    "disk_space",
    "timeout",
    "error",
    "container_failed",
    "unknown",
]


def load_records(path: Path) -> tuple[dict[str, dict], dict[str, int], int]:
    """返回 (每任务最后一条记录, 每任务记录行数, 损坏行数)。

    同一任务多行时以最后一行为准，和跑批脚本的 summarize() 一致。
    """
    latest: dict[str, dict] = {}
    attempts: dict[str, int] = {}
    bad_lines = 0
    for line in path.read_text(encoding="utf-8", errors="replace").splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            record = json.loads(line)
        except json.JSONDecodeError:
            bad_lines += 1
            continue
        task_id = record.get("task_id")
        if not task_id:
            bad_lines += 1
            continue
        latest[task_id] = record
        attempts[task_id] = attempts.get(task_id, 0) + 1
    return latest, attempts, bad_lines


def read_task_ids(path: Path) -> list[str]:
    """读取任务列表，口径同 cybergym_batch.py：归一 n132/arvo:1065 -> arvo:1065。"""
    ids: list[str] = []
    for raw in path.read_text(encoding="utf-8", errors="replace").splitlines():
        text = raw.strip()
        if not text or text.startswith("#"):
            continue
        text = text.split("/")[-1]
        if ":" in text:
            ids.append(text)
    return ids


def _rounds_columns(record: dict) -> tuple[str, str, str, str]:
    submitted = record.get("submitted") or {}
    rounds = submitted.get("rounds") or []
    vul = "/".join(str(r.get("vul_exit_code", "")) for r in rounds)
    fix = "/".join(str(r.get("fix_exit_code", "")) for r in rounds)
    tally = ",".join(f"{k}={v}" for k, v in (submitted.get("tally") or {}).items())
    return vul, fix, str(submitted.get("file") or ""), tally


def _one_line(text: object, limit: int = 200) -> str:
    flat = " ".join(str(text or "").split())
    return flat if len(flat) <= limit else flat[: limit - 1] + "…"


def _status_order(counts: dict[str, int]) -> list[str]:
    known = [s for s in STATUS_ORDER if s in counts]
    extra = sorted(s for s in counts if s not in STATUS_ORDER)
    return known + extra


def render(
    latest: dict[str, dict],
    attempts: dict[str, int],
    bad_lines: int,
    *,
    source: Path,
    expected_ids: list[str] | None,
) -> str:
    rows = sorted(latest.values(), key=lambda r: str(r.get("task_id")))
    counts: dict[str, int] = {}
    for row in rows:
        status = row.get("status") or "unknown"
        counts[status] = counts.get(status, 0) + 1
    durations = [row["agent_duration_sec"] for row in rows if row.get("agent_duration_sec")]
    avg = round(statistics.mean(durations), 1) if durations else None
    solved = counts.get("solved", 0)
    agent_ids = sorted({str(r.get("agent_id")) for r in rows if r.get("agent_id")})

    if expected_ids:
        missing = sorted(set(expected_ids) - set(latest))
        progress = f"{len(latest)}/{len(expected_ids)} 个任务有记录，{len(missing)} 个未开始"
    else:
        missing = []
        progress = f"{len(latest)} 个任务有记录（未提供任务列表，无法判断是否跑完）"

    lines = [
        "# CyberGym batch report",
        "",
        f"- 来源: `{source}`",
        f"- generated_at: {datetime.now().astimezone().isoformat(timespec='seconds')}",
        f"- progress: {progress}",
        f"- tasks: {len(rows)}（solved {solved}）",
        f"- avg per task: {avg if avg is not None else '—'}s",
        "- status counts: "
        + ", ".join(f"{k}={counts[k]}" for k in _status_order(counts)),
    ]
    if agent_ids:
        lines.append("- agent_id: " + ", ".join(f"`{a}`" for a in agent_ids))
    if bad_lines:
        lines.append(f"- 提示: 跳过了 {bad_lines} 行无法解析的记录")
    lines += [
        "",
        "## 状态分布",
        "",
        "| status | count |",
        "| --- | --- |",
    ]
    for status in _status_order(counts):
        lines.append(f"| {status} | {counts[status]} |")

    lines += [
        "",
        "## 任务明细",
        "",
        "| task | status | vul_exit | fix_exit | poc | rounds | duration(s) | attempts |",
        "| --- | --- | --- | --- | --- | --- | --- | --- |",
    ]
    for row in rows:
        vul, fix, poc, tally = _rounds_columns(row)
        lines.append(
            f"| {row.get('task_id')} | {row.get('status') or 'unknown'} | {vul} | {fix} "
            f"| {poc} | {tally} | {row.get('agent_duration_sec', '')} "
            f"| {attempts.get(str(row.get('task_id')), 1)} |"
        )

    failed = [row for row in rows if (row.get("status") or "") in RETRYABLE_STATUSES]
    if failed:
        lines += [
            "",
            "## 失败 / 中断的任务（续跑会重试）",
            "",
            "| task | status | attempts | finished_at | error |",
            "| --- | --- | --- | --- | --- |",
        ]
        for row in failed:
            task_id = str(row.get("task_id"))
            detail = row.get("error") or row.get("agent_detail") or ""
            lines.append(
                f"| {task_id} | {row.get('status')} | {attempts.get(task_id, 1)} "
                f"| {row.get('finished_at', '')} | {_one_line(detail).replace('|', '\\|')} |"
            )

    if missing:
        lines += [
            "",
            "## 未开始的任务",
            "",
            "<br>".join(missing),
        ]

    lines += [
        "",
        "> 本报告由 results.jsonl 生成；批次运行中可随时重新执行本脚本刷新。",
        "",
    ]
    return "\n".join(lines)


def resolve_results_arg(path: Path) -> Path:
    if path.is_dir():
        candidate = path / "results.jsonl"
        if not candidate.is_file():
            raise SystemExit(f"目录下没有 results.jsonl：{path}")
        return candidate
    if not path.is_file():
        raise SystemExit(f"找不到 results.jsonl：{path}")
    return path


def main(argv: list[str] | None = None) -> int:
    # Windows 控制台默认 GBK，报告里的中文提示会乱码。
    if hasattr(sys.stdout, "reconfigure"):
        sys.stdout.reconfigure(encoding="utf-8")
    parser = argparse.ArgumentParser(
        description="从 results.jsonl 生成跑批报告（批次未完成时也可用）",
    )
    parser.add_argument(
        "path",
        help="results.jsonl 路径，或批次目录（目录下需有 results.jsonl）",
    )
    parser.add_argument("--out", help="写入文件；默认打印到 stdout")
    parser.add_argument(
        "--task-file",
        help="可选的任务列表，用于统计未开始的任务和完成进度",
    )
    args = parser.parse_args(argv)

    results_path = resolve_results_arg(Path(args.path))
    latest, attempts, bad_lines = load_records(results_path)
    if not latest:
        raise SystemExit(f"results.jsonl 里没有可解析的任务记录：{results_path}")

    expected = read_task_ids(Path(args.task_file)) if args.task_file else None
    report = render(
        latest,
        attempts,
        bad_lines,
        source=results_path,
        expected_ids=expected,
    )

    if args.out:
        out_path = Path(args.out)
        out_path.parent.mkdir(parents=True, exist_ok=True)
        out_path.write_text(report, encoding="utf-8")
        print(f"报告已写入 {out_path}（{len(latest)} 个任务）")
    else:
        sys.stdout.write(report)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
