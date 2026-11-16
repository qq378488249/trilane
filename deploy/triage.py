#!/usr/bin/env python3
"""跑批失败排障：把一个批次的结论、阶段进度、产物和错误线索汇总成一份报告。

用法：

    python3 deploy/triage.py runs/<批次>            # 人类可读
    python3 deploy/triage.py runs/<批次> --json     # 机器可读（给 CI/告警）

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


def count_patterns(path: Path, patterns) -> dict[str, int]:
    counts = {name: 0 for name, _ in patterns}
    try:
        text = path.read_text(encoding="utf-8", errors="replace")
    except OSError:
        return counts
    for name, pattern in patterns:
        counts[name] = len(pattern.findall(text))
    return counts


def transcript_errors(run_dir: Path) -> dict[str, int]:
    counts = {name: 0 for name, _ in ENV_ERROR_PATTERNS}
    for stage in STAGE_IDS:
        transcript = run_dir / stage / "transcript.md"
        if not transcript.exists():
            continue
        try:
            text = transcript.read_text(encoding="utf-8", errors="replace")
        except OSError:
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


def build(batch_dir: Path) -> dict:
    results_path = batch_dir / "results.jsonl"
    records = latest_by_task(read_jsonl(results_path))
    tasks = []
    for record in records:
        slug = record.get("slug") or str(record.get("task_id", "")).replace(":", "_")
        task_root = batch_dir / slug
        run_dir = newest_run_dir(task_root)
        rows = stage_rows(run_dir) if run_dir else []
        agent_log = task_root / "agent.log"
        llm = count_patterns(agent_log, LLM_ERROR_PATTERNS)
        env = transcript_errors(run_dir) if run_dir else {}
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
                "llm_errors": {k: v for k, v in llm.items() if v},
                "env_errors": {k: v for k, v in env.items() if v},
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
        "tasks": tasks,
        "orphan_task_dirs": orphans,
    }


def render(data: dict) -> str:
    out: list[str] = []
    line = "─" * 72
    out.append(line)
    out.append(f"批次 triage：{data['batch']}")
    out.append(f"生成时间：{data['generated_at']}")
    if not data["results_exists"]:
        out.append("!! results.jsonl 不存在 —— 批次可能未启动或进程被外部杀死")
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
    parser.add_argument("--json", action="store_true", help="输出 JSON")
    args = parser.parse_args(argv)

    batch_dir = Path(args.batch).expanduser()
    if not batch_dir.is_dir():
        print(f"批次目录不存在：{batch_dir}", file=sys.stderr)
        return 2

    data = build(batch_dir)
    if args.json:
        print(json.dumps(data, ensure_ascii=False, indent=2))
    else:
        print(render(data))
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
