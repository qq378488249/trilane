# CyberGym pre-agent scout 流水线设计

## 1. 背景与目标

`docs/cybergym-submission-report.md` 描述了 TriLane 在 agent 启动前运行
pre-agent scouts：quick-try、`mini_afl`、target `libFuzzer`、结构化生成器和
boundary mutation，并把 scout 结果作为 agent 的起始状态和诊断线索。

当前 `deploy/cybergym_batch.py` 没有 scout 阶段：`run_agent()` 准备完任务包和
种子语料后直接启动 agent。报告里的 62 个 first candidate、38 个真实崩溃等
统计，在当前批跑产物中也没有对应记录。

本次目标：

1. 在 agent 启动前增加一个独立的 scout 阶段，先做三类成本最低的 scout：
   quick-try、boundary mutation、target `libFuzzer`。
2. scout 固定使用**宿主机 Docker daemon** 执行目标镜像，不进入 DinD，也不新增
   scout 专用镜像；直接复用已有的 vulnerable 镜像。
3. scout 只产生 vulnerable 侧观察和候选文件，不判 solved、不自动提交。
4. scout 结果写入 `task/scout/`，并把精简摘要追加到 `TASK.md`，供 agent
   自行决定是否采用。
5. 失败必须软降级：scout 超时、镜像不支持、入口命令失败都不能阻断 agent。
6. 独立记录 scout 耗时，且 scout 耗时不计入 agent 的运行时间，也不扣减
   agent 的 `--timeout-sec` 预算。
7. 行为可开关、可审计、可回滚；`SCOUT_MODE=off` 时与现状完全一致。

非目标（第一阶段不做）：

- 不实现 `mini_afl`。报告没有公开实现，先用现有 AFL++ 能力作为后续阶段。
- 不实现 structured generator、format-aware 字段模型和 witness chaining。
- 不改变 agent 的 S0-S5 流程、提交判定、投票和官方差分验证。
- 不让 scout 候选进入 `collect_pocs()` 的自动提交队列。
- 不追求复现报告中的 62/38 统计；先对齐能力面，统计口径另行对齐。
- 不使用 DinD 执行 scout。scout 只连宿主机 daemon。

### 1.1 边界说明

scout 使用的是与 agent 相同的 vulnerable 镜像，不读取 fixed 镜像、patch、
参考 PoC 或 fixed 侧结果。

quick-try 和 boundary mutation 的输入来自：

- `task/seeds/` 下已由 `provision_seed_corpora()` 准备好的种子语料；
- 一个空输入；
- 任务目录里已有的本地输入文件（如果后续显式加入）。

`SEED_CORPUS=off` 时，scout 不读取 `/out` 种子语料，只使用空输入；是否启用
scout 不改变现有 level-1 边界开关的含义。scout 使用的模式会记录在
`results.jsonl` 的 `scout` 字段里，便于区分实验口径。

---

## 2. 现状与插入点

现有执行链路：

```text
prepare_task_package()              # 解包源码、生成 TASK.md
prepare_state_dir()
run_agent()
  ├─ dind: start_dind → 导入镜像 → provision_seed_corpora → run_agent_in_dind
  └─ host: provision_seed_corpora → docker run 启动 agent
```

scout 要插在 **种子准备之后、agent 启动之前**，两个分支各插一次：

```text
run_agent()
  ├─ dind:
  │   start_dind → 导入镜像 → provision_seed_corpora
  │   → run_scouts(task, task_root, args)          # 宿主机 daemon
  │   → run_agent_in_dind()
  └─ host:
      provision_seed_corpora
      → run_scouts(task, task_root, args)          # 宿主机 daemon
      → docker run 启动 agent
```

设计上不依赖 DinD handle：`run_scouts()` 只接收 `task`、`task_root` 和
`args`，内部始终通过宿主机 `docker` CLI 执行。这样：

- host 隔离模式下 scout 不额外起任何东西；
- dind 隔离模式下 scout 也不需要进入 dind，agent 仍然按原方式在 dind 内运行；
- 两种模式下 scout 代码路径完全一致。

参考位置：

- `prepare_task_package()`：`deploy/cybergym_batch.py:665`
- `provision_seed_corpora()`：`deploy/cybergym_batch.py:1766`
- `run_agent()` 的 dind 分支：`deploy/cybergym_batch.py:1960`
- `run_agent()` 的 host 分支：`deploy/cybergym_batch.py:2018`
- `_write_seed_manifest()`：`deploy/cybergym_batch.py:1721`
- `_canonical_fuzzers()`：`deploy/cybergym_batch.py:1740`

---

## 3. 总体设计

```text
                 ┌─────────────────────────────┐
                 │ provisioning (existing)     │
                 │ task / seeds / manifest     │
                 └──────────────┬──────────────┘
                                │
                 ┌──────────────▼──────────────┐
                 │ run_scouts()                │
                 │  ├─ quick_try               │
                 │  ├─ boundary_mutation       │
                 │  └─ target_libfuzzer        │
                 └──────────────┬──────────────┘
                                │
        ┌───────────────────────┼───────────────────────┐
        │                       │                       │
  task/scout/*.bin      task/scout/scout_log.json   TASK.md scout 段
        │                       │                       │
        └───────────────────────┴───────────┬───────────┘
                                            │
                                  run_agent (existing)
```

组件职责：

| 组件 | 职责 |
|---|---|
| `ScoutPlanner` | 读取 seed manifest，决定跑哪些 stage、每个 stage 的候选上限 |
| `ScoutExecutor` | 统一封装宿主 `docker run --rm`、超时、输出采集和容器清理 |
| `ScoutClassifier` | 把退出码和输出分类成 crash / no_crash / timeout / exec_error |
| `ScoutReporter` | 写 `scout_log.json`、`SCOUT_LOG.md`，并注入 `TASK.md` |

所有 scout 共用同一个 `ScoutResult` 数据结构和同一个执行器，三个 stage 只负责
“生成候选”和“指定命令”。

scout 总预算默认独立于 agent：

- `SCOUT_TIMEOUT_SEC`（默认 180）：整个 scout 阶段墙钟上限；
- `SCOUT_RUN_TIMEOUT_SEC`（默认 10）：单个目标执行上限；
- `SCOUT_MAX_RUNS`（默认 40）：整个任务最多执行多少个候选；
- `SCOUT_MAX_OUTPUT_KB`（默认 32）：每个候选保留的输出尾部上限；
- `SCOUT_LIBFUZZER_SEC`（默认 60）：libFuzzer 单次 campaign 上限；
- `SCOUT_MAX_ARTIFACTS`（默认 20）：libFuzzer artifact 最多收集多少个。

scout 的预算是**独立预算**，不从 agent 的时间里扣：

- scout 自己受 `SCOUT_TIMEOUT_SEC` 限制；
- agent 仍然拿完整的 `--timeout-sec` / `TASK_TIMEOUT_SEC`；
- scout 耗时只写入 `scout.duration_sec`，不写进 `agent_duration_sec`。

### 3.1 耗时口径

实现时至少记录三个起点：

```text
task_started    run_agent() 入口
scout_started   run_scouts() 入口
agent_started   真正启动 agent 容器之前
```

对应字段：

| 字段 | 口径 |
|---|---|
| `scout.duration_sec` | `scout_started` → `run_scouts()` 结束，含所有 stage 和单个候选执行 |
| `scout.stages.<stage>.duration_sec` | 单个 stage 的耗时 |
| `agent_duration_sec` | `agent_started` → agent 退出，**不含 scout** |
| `task_total_sec` | `task_started` → 任务结束，含 dind/镜像准备、scout、agent、提交 |

`run_agent()` 现有的 `RunOutcome.duration_sec` 改为从 `agent_started` 起算；这样
`results.jsonl` 的 `agent_duration_sec` 和 `TASK_WALL_CLOCK_SEC` 的重试判断都
不会把 scout 算进去。`task_total_sec` 单独写入记录，用于看真实墙钟和容量规划。

agent 的内层超时参数、外层 `proc.wait(timeout=...)` 都保持原值，不因为 scout
而缩短。scout 结束时即使已经用满 `SCOUT_TIMEOUT_SEC`，agent 仍从完整预算开始。

scout 只在任务的**第一次** agent 启动前运行；agent 失败重试或 stage 续跑时复用
已有的 `scout/scout_log.json`，不重复执行。只有显式 `--force-scout` 才重跑。

---

## 4. 共享执行器

### 4.1 命令形态

统一走宿主机 daemon，不区分 dind：

```text
docker run --rm --name trilane-scout-<slug>-<n> \
  --network none \
  --label trilane.role=scout \
  --label trilane.task=<slug> \
  --label trilane.batch=<agent_id> \
  -v <candidate>:/tmp/poc:ro \
  <vul_image> <entry command>
```

路径统一使用 `daemon_path()`，保证 Windows Docker Desktop 下宿主 daemon 能解析。
如果 runner 本身在容器里运行，compose 已做同路径挂载，行为不变。

不做：

- 不执行 `docker system prune`、`docker rm` 等全局清理；
- 不删除 scout 以外的容器、镜像或卷；
- 不使用 `--privileged`；
- 不挂载宿主任意目录，只挂载 `task/scout/` 下的候选、语料和 artifact 目录。

### 4.2 入口命令

按任务族复用现有约定：

| 族 | 命令 |
|---|---|
| arvo | `<vul_image> /bin/arvo`，`/bin/arvo` 读取 `/tmp/poc` |
| oss-fuzz | `<vul_image>`，镜像默认 `run_poc` 读取 `/tmp/poc` |
| oss-fuzz 显式 harness | `<vul_image> /out/<fuzzer> /tmp/poc` |
| libFuzzer campaign | `<vul_image> /out/<fuzzer> -max_total_time=<N> ... /corpus` |

canonical fuzzer 从 `task/seeds/manifest.json` 的 `canonical_fuzzers` 读取；
`provision_seed_corpora()` 没有产出 manifest 时，退回 `_canonical_fuzzers()`。

### 4.3 退出码分类

不能直接用“非零即崩溃”：

| exit code | 分类 | 说明 |
|---:|---|---|
| 0 | `no_crash` | 正常返回 |
| 124 / 300 / 999 | `timeout` | 现有 `NON_CRASH_EXITS` 约定 |
| 137 | `killed` | OOM 或外部 kill |
| 125 | `docker_error` | Docker daemon 无法启动容器 |
| 126 | `exec_error` | 容器内命令不可执行 |
| 127 | `exec_error` | 入口或命令不存在；报告里大量 pre-mutation 失败属于这类 |
| 其他 | `crash` / `scaffold_error` | 有明确崩溃标记才进入 `crash`；libFuzzer callback 签名/运行时自身错误归 `scaffold_error` |

`scaffold_error` 的典型输出是：

```text
runtime error: call to function LLVMFuzzerTestOneInput through pointer
to incorrect function type
/src/libfuzzer/FuzzerLoop.cpp:...
```

它发生在候选进入目标 harness 之前，不能作为目标漏洞命中。若 libFuzzer campaign
本身是 `scaffold_error`，即使它写出了 artifact，也不把 artifact 提升为 crash 候选。
2026-11-27 的 `arvo:3938` smoke 中，空输入和全部 seed 都稳定触发这种 libFuzzer
自身 UBSan，旧分类把 42 个 scaffold 失败误记为 crash；加入该分类后 crash 计数为 0。

少数 harness（如 `arvo:52317`）把 `/tmp/poc` 当 **corpus 目录**而不是单文件。
对单文件挂载会报 `ERROR: The required directory "/tmp/poc" does not exist`。
这时 scout 只重试一次：把该候选文件复制到 `scout/dir-<name>/` 后按目录挂载，并给
结果加 `note=directory_mode_retry`。重试行仍受同一个单候选超时限制。

对“其他非零”继续解析输出：

- `AddressSanitizer` / `MemorySanitizer` / `UndefinedBehaviorSanitizer`；
- `runtime error:`；
- `SEGV` / `ABRT` / `assertion` / `stack-overflow` 等。

有明确崩溃标记才进入 `crash`；否则记 `unknown_nonzero`，保留为诊断，不当作
已验证崩溃。

### 4.4 输出和前缀

每个候选只保留：

- exit code；
- 是否超时；
- sanitizer 类型；
- 解析出的 crash signature；
- stdout/stderr 的尾部 `SCOUT_MAX_OUTPUT_KB`；
- 生成阶段、父输入和变异描述。

完整输出不落盘，避免大输出拖慢结果落账。需要深挖时由 agent 自己重跑。

---

## 5. 三个 scout

### 5.1 Quick-try

目的：确认哪些种子本来就能让 vulnerable 目标崩溃。

候选来源：

1. 一个空文件；
2. `task/seeds/*.zip` 内按名字排序的前若干个文件；
3. 可选：`task/` 下显式标记的本地输入文件。

限制：

- 每个 zip 最多解出 `SCOUT_MAX_RUNS` 个候选；
- 单文件超过 `SCOUT_MAX_CANDIDATE_MB`（默认 2MB）跳过；
- 总运行数受 `SCOUT_MAX_RUNS` 和 `SCOUT_TIMEOUT_SEC` 双重限制；
- `SEED_CORPUS=off` 时只跑空文件。

输出目录：

```text
task/scout/
  quick-try/
    empty.bin
    seed-000.bin
    ...
```

每个候选执行一次目标，记录到 `scout_log.json`。这是最便宜的一层，也是
scout 日志里最应该优先注入给 agent 的内容。

### 5.2 Boundary mutation

目的：不做完整格式理解，先用确定性小变异集试探长度、count、offset、flag
边界。

输入：quick-try 中选择的少量种子（默认最多 2 个，可通过配置调整）。

固定变异集：

- 截断：`0`、`1`、`2`、`4`、`8`、`16`、`len/4`、`len/2`、`len-1`；
- 追加：补 1/2/4 字节零；
- 头部字段覆盖：在 `0..min(15, len-1)` 内选固定偏移，按 1/2/4 字节写入
  `0`、`1`、`0x7f`、`0x80`、`0xff`、原值 ±1；
- 对明显的长度字段，额外尝试 `len`、`len ± 1`、`2 * len`。

每个变异只记录：

```text
parent
offset
width
old_value
new_value
mutation_kind
```

变异总数由 `SCOUT_MAX_RUNS` 截断；达到上限后按“截断/追加优先、字段覆盖其次”
的顺序保留，避免随机噪声抢占预算。

输出目录：

```text
task/scout/boundary/
  <seed>-trunc-<n>.bin
  <seed>-append-<n>.bin
  <seed>-field-<off>-<width>-<value>.bin
```

第一阶段不做“保持目标路径的最小化”，只做候选生成和执行。真正的
sink-preserving reduction 留给 agent 或后续阶段。

### 5.3 Target libFuzzer

目的：当 canonical target 本身支持 libFuzzer 时，用 bounded campaign 直接
收集 crash artifact。

前提：

- `SEED_CORPUS=on`；
- `task/seeds/manifest.json` 里有 `canonical_fuzzers`；
- `/out/<fuzzer>` 存在，且能力探测通过。

能力探测：

```text
docker run --rm --network none \
  --label trilane.role=scout \
  --label trilane.task=<slug> \
  --entrypoint /bin/sh \
  <vul_image> -c \
  'test -x /out/<fuzzer> && /out/<fuzzer> -help=1 2>&1 | grep -q max_total_time'
```

探测失败（不是 libFuzzer、入口不存在、镜像没有 shell）时写：

```json
{"stage": "libfuzzer", "status": "skipped", "reason": "not_libfuzzer"}
```

不把探测失败当成崩溃，也不重试到超时。

运行方式：

```text
docker run --rm --network none \
  --label trilane.role=scout \
  --label trilane.task=<slug> \
  -v <task>/scout/libfuzzer/corpus:/corpus:ro \
  -v <task>/scout/libfuzzer/artifacts:/artifacts \
  <vul_image> /out/<fuzzer> \
    -max_total_time=<SCOUT_LIBFUZZER_SEC> \
    -artifact_prefix=/artifacts/ \
    /corpus
```

- corpus 由 quick-try 解出的种子组成；
- artifacts 目录可写，最多收集 `SCOUT_MAX_ARTIFACTS` 个文件；
- 每个 artifact 记录文件名、大小、SHA-256、来源 stage；
- 不把 artifact 自动复制到 `task/poc/`，只作为 scout 候选。

---

## 6. 数据模型与产物

### 6.1 `ScoutResult`

```python
@dataclass
class ScoutResult:
    stage: str                  # quick_try | boundary | libfuzzer
    name: str                   # 稳定 id，如 quick-000
    path: Path                  # task/scout/ 下的相对路径
    command: list[str]          # 实际 docker 命令，便于复现
    exit_code: int | None
    timed_out: bool
    duration_sec: float
    verdict: str                # crash / no_crash / timeout / exec_error / ...
    sanitizer: str
    signature: dict             # dedup / summary / frames
    parent: str | None
    mutation: dict | None
    output_tail: str
```

### 6.2 `scout_log.json`

```json
{
  "schema": 1,
  "task_id": "arvo:3938",
  "mode": "boundary",
  "started_at": "2026-11-27T10:00:00+00:00",
  "duration_sec": 83.4,
  "stages": {
    "quick_try": {"status": "ok", "ran": 8, "crashes": 1, "skipped": 0},
    "boundary": {"status": "ok", "ran": 24, "crashes": 2, "skipped": 0},
    "libfuzzer": {"status": "skipped", "reason": "not_libfuzzer", "ran": 0, "crashes": 0}
  },
  "candidates": [
    {
      "id": "quick-000",
      "stage": "quick_try",
      "file": "scout/quick-try/seed-000.bin",
      "parent": "seeds/xxx.zip#seed-000",
      "mutation": null,
      "verdict": "crash",
      "exit_code": 1,
      "sanitizer": "AddressSanitizer",
      "signature": {"dedup": "...", "summary": "...", "frames": ["..."]},
      "duration_sec": 1.2
    }
  ]
}
```

约束：

- `file` 使用相对 `task/` 的路径；
- 不写宿主绝对路径；
- 每个 candidate 的 `output_tail` 截断到 `SCOUT_MAX_OUTPUT_KB`；
- `scout_log.json` 总大小不超过 `SCOUT_MAX_LOG_MB`（默认 2MB）。

### 6.3 `SCOUT_LOG.md`

给 agent 和人工排查用的精简版：

```markdown
# Pre-agent scout log

- mode: boundary
- isolation: host
- duration: 83s
- quick_try: ran=8 crash=1
- boundary: ran=24 crash=2
- libfuzzer: skipped (not_libfuzzer)

## Crashes

1. `scout/quick-try/seed-000.bin` — quick_try — exit=1 — AddressSanitizer
   - signature: ...
2. `scout/boundary/seed-000-trunc-16.bin` — boundary — exit=1 — AddressSanitizer
   - parent: seed-000
   - mutation: truncate at 16
```

不写完整栈、地址、环境变量或宿主路径。

### 6.4 `results.jsonl`

每个任务记录新增：

```json
{
  "scout": {
    "mode": "boundary",
    "isolation": "host",
    "status": "ok",
    "duration_sec": 83.4,
    "stages": {
      "quick_try": {"ran": 8, "crashes": 1, "duration_sec": 12.3},
      "boundary": {"ran": 24, "crashes": 2, "duration_sec": 71.1}
    },
    "candidates": 3,
    "log": "scout/scout_log.json"
  },
  "agent_duration_sec": 2430.0,
  "task_total_sec": 2513.4
}
```

`agent_duration_sec` 不再包含 scout；`task_total_sec` 包含 dind/镜像准备、
scout、agent 和提交。旧批次没有 `task_total_sec`，报告脚本按可选字段处理。

不把 scout 候选写进 `submitted` / `pocs`，除非后续显式增加“scout 候选回退”
策略；第一阶段保持不自动提交。

---

## 7. Agent 任务包注入

scout 结束后，在 `task/TASK.md` 末尾追加一段，使用固定标记，保证重复执行时
不会叠加：

```markdown
<!-- SCOUT_LOG_BEGIN -->
## Pre-agent scout results (vulnerable side only)

The runner executed bounded scouts before this round. These are diagnostic
starting points, not verified answers. You may inspect them, but validate any
candidate independently through the vulnerable target before submitting.

- mode: boundary
- quick_try: ran=8 crash=1
- boundary: ran=24 crash=2
- libfuzzer: skipped (not_libfuzzer)

Candidates are under `scout/`; details are in `scout/scout_log.json`.
<!-- SCOUT_LOG_END -->
```

规则：

- 已有 `<!-- SCOUT_LOG_BEGIN -->` 时整段替换，不重复追加；
- 不把原始 stdout/stderr 或 sanitizer 完整栈写进提示词；
- `SCOUT_MODE=off` 时完全不写这段，`TASK.md` 与现状一致；
- scout 候选不放进 `task/poc/`，避免被 `collect_pocs()` 误当提交候选。

---

## 8. 配置与开关

`deploy/.env.example` 新增：

```ini
# pre-agent scout：off / quick / boundary / full
#   off      = 不运行（默认，保持现状）
#   quick    = 只跑 quick-try
#   boundary = quick-try + boundary mutation
#   full     = quick-try + boundary mutation + target libFuzzer
SCOUT_MODE=off

# scout 阶段总墙钟上限（秒）
SCOUT_TIMEOUT_SEC=180
# 单个候选执行上限（秒）
SCOUT_RUN_TIMEOUT_SEC=10
# 整个任务最多执行多少个候选
SCOUT_MAX_RUNS=40
# 每个候选保留的输出尾部（KB）
SCOUT_MAX_OUTPUT_KB=32
# libFuzzer campaign 时长（秒）和 artifact 上限
SCOUT_LIBFUZZER_SEC=60
SCOUT_MAX_ARTIFACTS=20
# 单个候选文件大小上限（MB）
SCOUT_MAX_CANDIDATE_MB=2
# scout JSON 日志大小上限（MB）
SCOUT_MAX_LOG_MB=2
```

以上是 scout 自己的预算。它不从 `TASK_TIMEOUT_SEC` 中扣除，也不会缩短
`--headless-timeout-sec`；scout 结束时 agent 仍从完整超时开始。

`compose.batch.yaml` 把上述变量透传给 runner；CLI 增加对应参数：

```text
--scout-mode
--scout-timeout-sec
--scout-run-timeout-sec
--scout-max-runs
--scout-max-output-kb
--scout-libfuzzer-sec
--scout-max-artifacts
--force-scout
```

`--force-scout` 用于忽略已有 `scout/scout_log.json` 重新跑；默认续跑时如果
scout 日志存在且任务包未重建，直接复用，不重复消耗目标执行时间。

---

## 9. 失败处理与安全

### 9.1 软降级

任一 scout 失败都不能让 `run_one()` 返回 `error`：

- 镜像不存在 / docker daemon 报错：`status=skipped`，记录原因；
- 单个候选超时：`verdict=timeout`，继续下一个；
- `exit 127`：`verdict=exec_error`，记录命令和 stderr 尾部，不当作崩溃；
- seed zip 无法解压：跳过该 zip，记录 `seed_error`；
- libFuzzer 探测失败：跳过整个 stage。

scout 的异常统一收敛到 `scout.status = ok | partial | skipped | failed`，
`run_agent()` 仍然继续。

### 9.2 安全边界

- 只使用 `task.vul_image`，不接受用户传入的任意镜像；
- 目标容器 `--network none`；
- 只挂载候选文件、corpus 和 artifact 目录，不挂载宿主任意路径；
- 所有容器带 `trilane.role=scout` 和 `trilane.task=<slug>` 标签；
- 超时清理只按唯一容器名 `docker rm -f`，不使用全局 prune/rm；
- 不读取 fixed 镜像、patch、`error.txt` 原文或参考 PoC。这里指 scout 自身不读；
  现有 `CRASH_HINT` 从 `error.txt` 派生入口提示的行为另见
  `docs/cybergym-crash-hint-design.md`，两者不要混在一起；
- 不把 scout 候选直接提交。

### 9.3 并发

- 每个任务内部 scout 串行执行；
- 全局并发由现有 `--concurrency` 控制；
- 容器名包含任务 slug 和随机后缀，避免并发冲突；
- 每个任务写自己的 `task/scout/`，不共享目录。

---

## 10. 测试计划

新增 `deploy/tests/test_scout.py`，沿用现有 `import cybergym_batch as cb` 风格：

1. **退出码分类**：0 / 124 / 137 / 125 / 126 / 127 / 1 + ASan 输出，断言
   verdict 和 sanitizer。
2. **变异生成**：固定输入断言截断、追加、字段覆盖的数量、父输入和 mutation
   元数据；超过 `SCOUT_MAX_RUNS` 时正确截断。
3. **seed 解压**：构造临时 zip，断言候选数量和大小上限；损坏 zip 不影响任务。
4. **日志渲染**：`SCOUT_LOG.md` 不含绝对路径、完整栈或超长输出；JSON 满足
   schema。
5. **提示词注入**：重复调用只保留一个 `SCOUT_LOG_BEGIN` 段；`SCOUT_MODE=off`
   时 `TASK.md` 与基线完全一致。
6. **libFuzzer 探测**：mock 探测成功/失败/镜像无 shell，断言 skipped 原因。
7. **软降级**：mock docker 超时和 127，断言 `run_scouts()` 返回但不抛异常，
   `run_agent()` 继续。
8. **不提交**：跑完 scout 后 `collect_pocs()` 不包含 `scout/` 文件；`submitted`
   为 `None`。
9. **耗时隔离**：mock 一个耗时 80s 的 scout，断言 `scout.duration_sec≈80`、
   `agent_duration_sec` 不包含这 80s，且传给 agent 的 `--timeout-sec` 未被扣减。
10. **重试不重跑 scout**：agent 失败后再次调用 `run_agent()`，断言不会新增
   scout 执行；`--force-scout` 时才重跑。

端到端 smoke：

- `SCOUT_MODE=quick` + `arvo:3938`；
- `SCOUT_MODE=full` + `oss-fuzz:370689421`（如果镜像本身支持 libFuzzer）；
- 检查目标容器退出后无残留：`docker ps -a --filter label=trilane.role=scout`；
- 检查 agent 的 stage0 prompt 能看到 scout 段，但看不到原始长输出。

---

## 11. 实施顺序

1. 共享执行器 + 退出码分类 + `ScoutResult`（纯 Python，可单测）。
2. seed 解压 + quick-try + `scout_log.json` / `SCOUT_LOG.md`。
3. boundary mutation + 候选上限。
4. `TASK.md` 注入 + `results.jsonl` 的 `scout` 字段 + `task_total_sec` /
   `agent_duration_sec` 计时口径调整。
5. target libFuzzer 探测、corpus/artifact 接入。
6. `.env.example`、compose、README、设计文档同步。
7. 单任务 smoke，再开小批次验证。

第一阶段可以先只做 1–4；`SCOUT_MODE=full` 的 libFuzzer 部分单独提交。

---

## 12. 风险与取舍

| 风险 | 处理 |
|---|---|
| scout 走宿主 daemon，和目标镜像共享宿主内核 | 只用可信 CyberGym 镜像；不加 `--privileged`；需要强隔离时后续再评估 |
| scout 耗时挤占 agent | 独立 `SCOUT_TIMEOUT_SEC`，不扣减 agent 的 `--timeout-sec`；耗时分开记录，耗尽即跳过 |
| 误把 harness/loader 崩溃当目标崩溃 | 区分 125/126/127；其他非零必须结合 sanitizer；最终仍由 agent 和官方 verifier 判定 |
| seed 语料太多 | 按数量和大小限流，只取前若干个 |
| libFuzzer 目标不支持 | `-help=1` 探测，失败直接 skipped，不硬跑 |
| scout 日志过大 | 单候选输出和总 JSON 都有上限 |
| scout 候选污染提交 | 只写 `task/scout/`，`collect_pocs()` 只读 `task/poc` 与 bundle |
| 报告统计无法复现 | 文档明确不承诺复现 62/38；先对齐能力面 |

---

## 13. 兼容与回滚

- `SCOUT_MODE=off` 是默认值；关闭时不创建 `task/scout/`，不修改 `TASK.md`，
  不新增 `results.jsonl` 字段，现有测试和产物格式保持不变。
- scout 结果字段是新增键，旧报告脚本会忽略未知键。
- 回滚只需把 `SCOUT_MODE` 设回 `off` 或删掉参数。
- scout 复用任务目录，不修改 agent 镜像和 Rust 引擎。

---

## 14. 开放问题

1. `SEED_CORPUS=off` 时是否仍允许空输入 quick-try？本设计允许，因为空输入
   属于程序自带的入口测试，不依赖 `/out` 语料；如果评测要求更严格，可再关闭。
2. scout 候选在 agent 完全没有产出时是否允许作为最后回退提交？第一阶段
   **不允许**，避免绕过 agent 和归因；后续可单独设计“scout 候选回退”策略。
3. `mini_afl` 和 structured generator 是否值得实现，取决于 quick-try +
   boundary + libFuzzer 在实际批次中的命中率。
