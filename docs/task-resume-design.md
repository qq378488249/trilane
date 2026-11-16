# 撞墙钟超时后的阶段续跑设计

## 1. 背景与目标

CyberGym 跑批里，单个任务默认给 4 小时（`--timeout-sec 14400`），到点由编排器强杀
容器。当前这种超时是**整体丢弃**：重跑从 S0 重来，前面几十分钟的分析全部作废。

但 TriLane 本身已经按 stage 落盘了完整状态（`runbook.json` / `status.json` /
`transcript.md`），并且引擎里**已经实现了续跑入口**，只是跑批流程没有使用它。

本次改动的目标：

1. 超时后**从上次中断的 stage 继续**，而不是从 S0 重来。
2. 复用引擎现有续跑机制，**不修改 TriLane 二进制、不重建镜像**。
3. 续跑行为可配置、可关闭，默认开启；失败时安全退化到"从头跑"。
4. 所有续跑动作在 `results.jsonl` 里可审计。

非目标：

- 不做 stage 内部的细粒度 checkpoint（续跑粒度是**整个 stage**，见 §2.2）。
- 不改变提交、判定、投票逻辑。
- 不改变镜像、Dockerfile、compose。

---

## 2. 现状

### 2.1 落盘结构

每个任务有独立 state 目录（`cybergym_batch.py:521 prepare_state_dir`），容器内挂到
`/root/.trilane`，**跨容器重启持久**：

```
runs/<batch>/<task>/state/trilane/
  config.toml
  secrets.toml
  runs/
    trilane-20261115-161706/        # run_id，格式 trilane-YYYYMMDD-HHMMSS
      current_run.txt
      stage0/  prompt.md  runbook.json  status.json  transcript.md
      stage1/  ...
      stage2/  ...
      stage3/  ...
      stage4/  ...
      stage5/  ...
```

写入点：`trilane-rs/trilane-gui/src/transcript_log.rs:318 write_stage_prompt`、
`:337 write_stage_snapshot`（写 `runbook.json` + `status.json`）。

实测 stage 文件在 stage 边界和 workflow tick 时都会刷新（见
`main_workflow_runtime.inc.rs:61,127,284,649`），所以超时那一刻的
`runbook.json` 基本是最新的。

`status.json` 字段：

```json
{"stage":"stage2","status":"Completed","current_stage":"stage2",
 "revision":449,"root_claims":16,"final_findings":0,"updated_at":"..."}
```

`result.json`（headless 产出，`trilane-gui/src/main_headless.inc.rs:113`）里也有
`stages` 数组，每项含 `id` / `status` / `updated_at`，状态值取自
`StageStatus`（`Done` / `Active` / `Pending` / `Blocked`，序列化小写）。

### 2.2 引擎已有的续跑语义

入口有两套，**headless 只有一套可用**：

| 入口 | 形式 | headless 可用 |
|---|---|---|
| CLI | `--trilane-resume-run <id> --trilane-resume-stage stageN` | **否** |
| 消息指令 | 消息**第一个非空行**为 `TRILANE_RESUME_RUN% run=<id> stage=<stageN>` | **是** |

CLI 那套在 `trilane-gui/src/main.rs:219 startup_resume_request()`，但它的调用点
`main.rs:159` 在 headless 分支（`main.rs:141-145` 提前 `return`）之后，永远走不到。

headless 的路径是：

```
run_headless()                         main_headless.inc.rs:50
  └─ send_message(options.objective)   main_headless.inc.rs:66
       └─ parse_resume_run_directive() main_commands.inc.rs:215 → :311
            └─ load_resume_state()     transcript_log.rs:362
```

解析规则（`main_commands.inc.rs:311-340`）：

- 只看**第一个非空行**，必须以 `TRILANE_RESUME_RUN%` 开头；
- 同一行内以空白分隔，取 `run=<value>`（或 `run_id=`）和 `stage=<value>`；
- `stage` 接受 `stageN` 或 `sN`（`normalize_stage_arg`，`:342`）；
- 指令行之后的所有内容作为 `extra_instructions`。

恢复语义（`transcript_log.rs:362-391 load_resume_state_from_root`）：

1. `stage_idx = stage_index(stage_id)`；
2. **源状态 = `stage(stage_idx-1)/runbook.json`**（`stage_idx==0` 时读
   `stage0/runbook.json`）；
3. 依次**删除 `stageN` 及之后所有 stage 目录**（`fs::remove_dir_all`）；
4. 把 runbook 置为 `Running`、`current_stage = stageN`、`turn_id = None`。

也就是说：**续跑粒度是整个 stage**。超时发生在 S2 中间，续跑会从 S2 开头重做，
S0/S1 的成果保住；S2 内部已经完成的部分 lane 结果会随目录一起删掉。

续跑复用同一个 `run_id`（`transcript_log.rs:80 start_resume_turn` 写
`current_run.txt`），不会产生新的 run 目录。

`run_id` 字符集限制：仅 `[A-Za-z0-9._-]`（`transcript_log.rs:439 safe_run_id`）。

### 2.3 批次流程的三处缺口

**缺口一：`TASK.md` 每次都被重写**

`deploy/cybergym_batch.py:506-517`：

```python
objective = OBJECTIVE_TEMPLATE.format(...)
(task_dir / "TASK.md").write_text(objective, encoding="utf-8")
```

这段在 `prepare_task_package()` 里，无条件执行。外部手工改 `TASK.md` 加续跑指令，
下次跑批就被覆盖。

**缺口二：重试循环明确排除 timeout**

`deploy/cybergym_batch.py:1192-1200`：

```python
while (
    outcome.status in ("container_failed", "error")
    and attempts < args.agent_retries + 1
):
```

注释写着"真超时不重试（会白烧一倍预算）"。在没有续跑时这个判断是对的；续跑接上
以后，超时重试不再是白烧。

**缺口三：没有"上次停在哪"的查询**

脚本从不读 `state/trilane/runs/*/stageN/`，不知道上次的 `run_id` 和 `stage`。

### 2.4 超时的两条路径

| 路径 | 触发 | 表现 |
|---|---|---|
| 内层（引擎） | `--headless-timeout-sec` 到点 | 写 `result.json`（`status:"timeout"`，含 `stages`），`exit 3` |
| 外层（编排器） | `args.timeout_sec + 600` 到点 | 强杀容器，`RunOutcome("timeout", rc=None, ...)` |

外层比内层晚 10 分钟，是给引擎落盘 `result.json` 留的余量
（`cybergym_batch.py:871-872`）。正常情况下先走内层。

因此续跑判定**不能只依赖 `result.json`**（外层强杀时可能残留上一次尝试的旧文件），
需要同时扫 stage 目录兜底，并处理 `result.json` 陈旧问题（§6）。

---

## 3. 设计

### 3.1 触发条件

新增参数 `--resume`，三档：

| 值 | 行为 | 适用 |
|---|---|---|
| `off` | 维持现状，超时不重试 | 保守回滚 |
| `timeout`（默认） | **仅 `timeout` 且找到回放点**时续跑 | 常规跑批 |
| `always` | `timeout` / `agent_failed` / `error` 只要有回放点就续跑 | LLM 长期不稳时 |

`container_failed` / `disk_space` 永远不续跑：

- `container_failed` 说明 DinD 或容器没起来，没有可信进度；
- `disk_space` 是环境问题，重试只会再次撞墙（`cybergym_batch.py:892-902` 已有此约定）。

**首轮也查回放点**：进程被重启（`docker compose down/up`、宿主重启、手动重跑）时，
`results.jsonl` 里可能根本没有这条任务的记录，重试循环不会触发。所以 `run_one`
在第一次 `run_agent` **之前**也调用一次 `find_resume_point`：找到有效存档就注入
指令直接续跑，找不到就照常从头跑。这样"手动重启 compose"与"进程内超时重试"
行为一致。

### 3.2 回放点选择

优先级从高到低：

1. **`out/result.json` 的 `stages`**（内层超时路径已落盘）：
   - 取第一个 `status == "active"` 的 stage；
   - 否则取第一个 `status == "pending"` 的 stage；
   - 否则取第一个 `status == "blocked"` 的 stage；
   - 否则不续跑（说明所有 stage 都是 `done`，属异常收尾）。
2. **扫 `state/trilane/runs/<run_id>/stageN/runbook.json` 兜底**（外层强杀路径）：
   - 取**编号最大**且存在 `runbook.json` 的 stage；
   - 但它可能是已完成 stage，需要按 `status.json` 的 `status` 字段判断：
     `Completed` 时改用下一 stage（上限 stage5）。

`run_id` 选择：

- 取 `state/trilane/runs/` 下**目录名最大**（时间戳顺序）且满足
  `^[A-Za-z0-9._-]+$` 的目录；
- 必须存在 `stage0/` 子目录（`transcript_log.rs:119 list_runs` 的同一判定）。

可行性校验（不满足就不续跑，退回从头）：

- 目标 stage **不能是 `stage0`**（准入阶段续跑等于从头重做，且会换用带
  `RESUME_RULES` 的提示词）；
- 目标 stage 的**前一个 stage** 必须存在**有效** `runbook.json`
  （`stageN` 依赖 `stage(N-1)/runbook.json`；`stage0` 依赖自己的）；
- **`runbook.json` 不能是 `{}` 占位**：引擎初始化时给 6 个 stage 都写
  `{}`（`transcript_log.rs:251`），真实快照才有 `objective` / `stages`；
  占位文件引擎自己也解析不了（`RunbookState` 的字段没有 serde default）；
- **首轮探测**（进程重启场景）读 `out/result.json` 的 stages，而不是传空 dict：
- `run_id` 通过字符集校验。

### 3.3 指令注入

在 `prepare_task_package()` 之后、`run_agent()` 之前，把指令写到 `TASK.md`
**第一行**：

```text
TRILANE_RESUME_RUN% run=trilane-20261115-161706 stage=stage3

<原 TASK.md 内容>
```

要点：

- 必须是**第一个非空行**（`main_commands.inc.rs:312-318`）；
- 指令行之后空一行，原 objective 全文保留——引擎会把它当作
  `extra_instructions` 拼进 resume objective；
- 同一任务多次重试会重复注入，所以写入前先剥掉开头已有的指令块，避免叠加；
- 引擎最终使用的 objective 主体是 `runbook.json` 里的 `objective` 字段
  （`resume_objective`，`main_commands.inc.rs:354`），所以原 TASK.md 内容缺失也
  不影响正确性，但保留有利于审计。

### 3.4 超时预算

当前 `run_agent_in_dind` 把 `args.timeout_sec` 原样传给
`--headless-timeout-sec`（`cybergym_batch.py:737-756`），续跑时仍是**完整值**，
不是剩余时间。

含义：`--agent-retries 3` + 每次 4 小时 = 单任务最长 16 小时墙钟。

建议：

- 新增可选参数 `--task-wall-clock-sec`（默认 `0` = 不限，保持现状），
  在 `run_one` 里累计各次 `outcome.duration_sec`，超出后停止重试并记
  `status=timeout`；
- 或者更简单：把 `--agent-retries` 在启用续跑后按任务预算换算（文档里写清楚，
  不改代码）。

本次先实现前者（可选参数，默认不限）。

### 3.5 落账

`results.jsonl` 每条记录新增字段：

```json
{
  "resume_attempts": [
    {"attempt": 2, "run_id": "trilane-...", "from_stage": "stage3",
     "previous_status": "timeout", "outcome": "completed"}
  ]
}
```

同时 `report_from_results.sh` 不用改（它只认 `status` / `submitted` /
`agent_duration_sec`），新字段是纯增量的审计信息。

---

## 4. 代码改动清单

全部改动集中在 `deploy/cybergym_batch.py`，**不碰**：
`trilane-rs/**`、`docker/**`、`deploy/batch-runner.Dockerfile`、
`deploy/compose.batch.yaml`。

### 4.1 新增常量与辅助函数（插在 `prepare_state_dir` 之后，约 :545）

```python
# 续跑粒度是 stage（见 docs/task-resume-design.md §2.2）。
STAGE_IDS = ("stage0", "stage1", "stage2", "stage3", "stage4", "stage5")
RESUME_RUN_ID_RE = re.compile(r"^[A-Za-z0-9._-]+$")
RESUME_DIRECTIVE = "TRILANE_RESUME_RUN% run={run_id} stage={stage}"


def find_resume_point(task_root: Path, result: dict) -> tuple[str, str] | None:
    """返回 (run_id, stage_id)；找不到可续跑点返回 None。

    优先级：result.json.stages -> stageN 目录扫描。任何一项校验失败都返回
    None，调用方据此退回从头跑。
    """
    runs_root = task_root / "state" / "trilane" / "runs"
    if not runs_root.is_dir():
        return None

    run_ids = sorted(
        (p.name for p in runs_root.iterdir()
         if p.is_dir() and (p / "stage0").is_dir()),
        reverse=True,                      # 目录名含时间戳，字典序即时间序
    )
    run_id = next((r for r in run_ids if RESUME_RUN_ID_RE.match(r)), None)
    if run_id is None:
        return None
    run_dir = runs_root / run_id

    stage = _stage_from_result(result) or _stage_from_dirs(run_dir)
    if stage is None:
        return None
    # stage0 续跑等于从头重做，还会换用带 RESUME_RULES 的提示词。
    if stage == "stage0":
        return None

    idx = STAGE_IDS.index(stage)
    source = STAGE_IDS[max(0, idx - 1)]
    runbook = run_dir / source / "runbook.json"
    if _valid_runbook(run_dir / source) is None:
        return None
    return run_id, stage


def _valid_runbook(stage_dir: Path) -> dict | None:
    """排除引擎初始化写的 "{}" 占位：真实快照至少有 objective 和 stages。"""
    path = stage_dir / "runbook.json"
    if not path.is_file():
        return None
    try:
        payload = json.loads(path.read_text(encoding="utf-8", errors="replace"))
    except Exception:
        return None
    if not isinstance(payload, dict):
        return None
    if "objective" not in payload or "stages" not in payload:
        return None
    return payload


def _stage_from_result(result: dict) -> str | None:
    stages = result.get("stages")
    if not isinstance(stages, list):
        return None
    by_status: dict[str, list[str]] = {}
    for item in stages:
        if not isinstance(item, dict):
            continue
        sid, st = item.get("id"), str(item.get("status") or "").lower()
        if sid in STAGE_IDS:
            by_status.setdefault(st, []).append(sid)
    for want in ("active", "pending", "blocked"):
        if by_status.get(want):
            return min(by_status[want], key=STAGE_IDS.index)
    return None


def _stage_from_dirs(run_dir: Path) -> str | None:
    """外层强杀时的兜底：找编号最大的、已有 runbook.json 的 stage。

    若该 stage 的 status.json 显示 Completed，说明它已跑完，退到下一个。
    """
    for stage in reversed(STAGE_IDS):
        d = run_dir / stage
        if not (d / "runbook.json").is_file():
            continue
        status = ""
        try:
            status = str(json.loads(
                (d / "status.json").read_text(encoding="utf-8")
            ).get("status") or "")
        except Exception:
            pass
        if status.lower() in ("completed", "done"):
            nxt = STAGE_IDS.index(stage) + 1
            return STAGE_IDS[nxt] if nxt < len(STAGE_IDS) else None
        return stage
    return None


def apply_resume_directive(task_root: Path, run_id: str, stage: str) -> None:
    """把续跑指令写到 TASK.md 第一行（引擎只认第一个非空行）。"""
    task_md = task_root / "task" / "TASK.md"
    body = task_md.read_text(encoding="utf-8", errors="replace")
    directive = RESUME_DIRECTIVE.format(run_id=run_id, stage=stage)
    task_md.write_text(f"{directive}\n\n{body}", encoding="utf-8")


def archive_attempt_outputs(task_root: Path, attempt: int) -> None:
    """把上一次的 result.json / report.md 改名，避免被当成本次结果读走。

    外层强杀时引擎没机会重写 result.json，run_agent 会读到上一次的旧文件
    （cybergym_batch.py:884-890），必须隔离。
    """
    out_dir = task_root / "out"
    for name in ("result.json", "report.md"):
        src = out_dir / name
        if src.exists():
            src.replace(out_dir / f"{name}.attempt{attempt}")
```

### 4.2 改造 `run_one`（`cybergym_batch.py:1175`）

现有结构：

```python
prepare_task_package(...)      # :1185
prepare_state_dir(...)         # :1186
outcome = run_agent(...)       # :1189
attempts = 1                   # :1190
while outcome.status in ("container_failed", "error") ...:   # :1192-1200
    ...
```

改为：

```python
prepare_task_package(task, task_root, force=args.force)
prepare_state_dir(task_root, Path(args.trilane_home).expanduser())

resume_log: list[dict] = []
# 进程重启场景：results.jsonl 里没有记录，首轮之前也查一次
if args.resume != "off":
    point = find_resume_point(task_root, {})
    if point is not None:
        run_id, stage = point
        archive_attempt_outputs(task_root, 0)
        apply_resume_directive(task_root, run_id, stage)
        log(f"[{task.task_id}] 检测到上次中断于 {run_id}/{stage}，直接续跑")
        resume_log.append({"attempt": 1, "run_id": run_id, "from_stage": stage,
                           "previous_status": "interrupted"})
outcome = run_agent(task, task_root, args)
if resume_log:
    resume_log[-1]["outcome"] = outcome.status
attempts = 1
max_attempts = args.agent_retries + 1
wall_clock = outcome.duration_sec

while attempts < max_attempts:
    retryable = outcome.status in ("container_failed", "error")
    if outcome.status == "timeout" and args.resume != "off":
        retryable = True
    if not retryable:
        break

    point = None
    if args.resume != "off":
        point = find_resume_point(task_root, outcome.result)
    if outcome.status == "timeout" and point is None:
        break                                  # 没有存档，维持原语义不白烧

    if args.task_wall_clock_sec and wall_clock >= args.task_wall_clock_sec:
        log(f"[{task.task_id}] 达到任务墙钟上限 {args.task_wall_clock_sec}s，停止重试")
        break

    attempts += 1
    wait = 60 * attempts
    if point:
        run_id, stage = point
        archive_attempt_outputs(task_root, attempts - 1)
        apply_resume_directive(task_root, run_id, stage)
        log(f"[{task.task_id}] {outcome.status}（{outcome.detail}），"
            f"{wait}s 后第 {attempts} 次尝试：从 {run_id}/{stage} 续跑")
        resume_log.append({
            "attempt": attempts, "run_id": run_id, "from_stage": stage,
            "previous_status": outcome.status,
        })
    else:
        log(f"[{task.task_id}] {outcome.status}（{outcome.detail}），"
            f"{wait}s 后第 {attempts} 次尝试（从头跑）")
    time.sleep(wait)
    outcome = run_agent(task, task_root, args)
    wall_clock += outcome.duration_sec
    if resume_log and resume_log[-1]["attempt"] == attempts:
        resume_log[-1]["outcome"] = outcome.status

record["agent_attempts"] = attempts
record["resume_attempts"] = resume_log
```

注意：

- `prepare_task_package` **只调用一次**，所以续跑指令能保留到下一次 `run_agent`；
- 若第 2 次也失败，第 3 次会重新 `find_resume_point`，自然拿到更靠后的 stage；
- `archive_attempt_outputs` 在续跑前调用，避免读到上一次的 `result.json`。

### 4.3 命令行参数（`parse_args`，约 :1324 附近）

```python
parser.add_argument(
    "--resume",
    choices=("off", "timeout", "always"),
    default=os.environ.get("TRILANE_RESUME", "timeout"),
    help="超时/失败后是否从上次 stage 续跑（off/timeout/always，默认 timeout）",
)
parser.add_argument(
    "--task-wall-clock-sec",
    type=int,
    default=0,
    help="单任务累计墙钟上限（秒，含所有重试）；0 = 不限",
)
```

### 4.4 `.env.example` / `compose.batch.yaml`（可选）

若希望在 compose 里可配，在 `x-batch-args` 增加：

```yaml
- --resume
- ${RESUME:-timeout}
- --task-wall-clock-sec
- "${TASK_WALL_CLOCK_SEC:-0}"
```

`.env.example` 增加：

```ini
# 超时后的续跑策略：off / timeout / always
RESUME=timeout
# 单任务累计墙钟上限（秒），0 = 不限
TASK_WALL_CLOCK_SEC=0
```

---

## 5. 边界情况

| 情况 | 行为 |
|---|---|
| 超时发生在 stage0（有 `runbook.json`） | **不续跑**（stage0 续跑等于从头重做，且提示词会变），落账为失败，下次批次重跑 |
| 超时发生在 stage0 开始前（无 runbook.json） | 不续跑，从头跑 |
| stage0 目录不存在 | 不续跑（`find_resume_point` 返回 None） |
| `runbook.json` 损坏 | 不续跑，从头跑 |
| 上一次是 `container_failed` | 默认不续跑（`--resume always` 才续） |
| 上一次是 `disk_space` | 永不续跑 |
| 磁盘满导致引擎写不出 stage 文件 | 无回放点，从头跑（预期） |
| `--force` | 只删 `task/`，**不删 `state/`**，存档保留，续跑仍可用 |
| 同批次多次运行（非 `--force`） | state 目录复用，续跑跨批次也生效 |
| `docker compose down/up` 手动重启 | `results.jsonl` 无记录也不会跳过；**首轮即查回放点并续跑** |
| 全新任务（无任何 stage 存档） | 不注入指令，正常从头跑 |
| 续跑后再次超时 | 下一轮 `find_resume_point` 取到更靠后的 stage |
| stage5 已 `done` 但整体没到 `completed` | 不续跑（无更后 stage），按失败落账 |
| `result.json` 是上一次的旧文件 | `archive_attempt_outputs` 已隔离 |
| 多个 run 目录 | 取目录名最大的（时间戳最新） |

---

## 6. 风险与缓解

| 风险 | 影响 | 缓解 |
|---|---|---|
| 续跑删掉 stageN 及之后目录 | 当前 stage 内已完成的部分丢失 | 文档写明粒度；未来可在 stage 内做 checkpoint |
| 续跑指令格式漂移 | 引擎不识别，静默从头跑 | `apply_resume_directive` 后校验首行；日志打印 `source=resume` |
| 墙钟总时长放大 | 4h × (1+retries) | `--task-wall-clock-sec` 默认 0（不限），需要时显式设 |
| 读到陈旧 `result.json` | 误判状态 | `archive_attempt_outputs` |
| 引擎侧行为变化 | 指令不被识别 | 升级镜像后跑一次单任务续跑回归（§7） |
| 续跑仍失败 | 与现状等价 | 退回从头跑/落账为 `agent_failed` |

---

## 7. 测试计划

1. **单元级**（纯函数，无需 Docker）
   - `find_resume_point` 用构造目录测试：无 runs / 单 run / 多 run / 损坏 json /
     stage 全 done / 只有 stage0。
   - `apply_resume_directive` 断言首行为指令、原文完整保留。
2. **集成级：mock LLM**
   - `deploy/mock-llm` 起一个慢速 mock（每次请求睡 N 秒），把
     `--headless-timeout-sec` 设小（如 180s），确认任务在 S2 被超时。
   - 第二轮开 `--resume timeout`，观察日志出现
     `从 trilane-.../stage2 续跑`，且 `state/.../stage0`、`stage1` 未被删除。
3. **端到端**
   - arvo:3938 正常跑一次（约 17 分钟），人为把超时设为 10 分钟触发续跑，
     确认最终仍能 `solved`，且总耗时明显低于两次完整运行。
4. **回归**
   - `--resume off` 下行为与当前完全一致（超时不重试）。
5. **镜像升级验证**
   - 换新版本 headless 后，确认 `TRILANE_RESUME_RUN%` 仍被识别
     （看 agent.log 里是否出现 `SYS% resumed run from files`）。

---

## 8. 兼容性与回滚

- 默认 `--resume timeout` 只改变"超时"这一种情况的处理，其余路径与现状一致。
- 关闭方式：`RESUME=off`，无需改代码、无需换镜像。
- 新字段 `resume_attempts` 是增量字段，`report_from_results.sh` 忽略它。
- 不涉及协议、镜像、提交逻辑，回滚只需去掉 `--resume`。

---

## 9. 后续可做（本次不做）

1. **stage 内 checkpoint**：当前只能按 stage 重来。若 S2 这类 10 分钟级的长 stage
   经常超时，可以在引擎侧按 lane 粒度落盘并恢复，收益更大。
2. **超时时间的自适应**：按历史 `agent_duration_sec` 给每个任务设置差异化超时。
3. **续跑指令透传层**：把 `TRILANE_LANE_*` 等环境变量也传进 agent 容器
   （`run_agent_in_dind` 目前只传 `-e HOME=/root`，见 `cybergym_batch.py:749`），
   让 lane 级重试可在容器里配置。
