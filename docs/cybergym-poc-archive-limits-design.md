# CyberGym PoC 快照与诊断扫描限流设计

## 1. 背景与问题

2026-11-25 的 `ap-ds4-flash-failed-22` 批次里，部分 agent 在 `task/poc/` 下生成了
大量 fuzz 语料，导致任务已经跑完、但结果迟迟不写进 `results.jsonl`：

| 任务 | `task/poc` 文件数 | 顶层文件数 | 现象 |
|---|---:|---:|---|
| `arvo:66502` | 36,002 | 13 | `seal_attempt()` 逐个复制 36k 文件，约 35 分钟仍未完成 |
| `arvo:63157` | 102,634 | 48 | 快照复制完成后，`collect_pocs()` 又逐个 `sha256` 扫描 |
| `arvo:58364` / `arvo:64522` | 数百以内 | 15 / 50 | 正常完成，未触发限流 |

根因不在 PoC 本身，而在两个**全量遍历**：

1. `run_one()` 在返回前调用 `seal_attempt()`，后者通过 `_copy_poc_tree()` 把
   `task/poc` 整棵树逐个 `copy2()` 到 `artifacts/attempt-N/poc/`；
2. `collect_pocs()` 的第 5 步会把 `task/poc` 和 `out/` 下所有文件都扫描一遍，
   对每个候选执行 `stat()` + `sha256()`。

宿主工作目录通过 9p 挂载进容器时，小文件逐个复制/哈希非常慢；而主进程只有在
`run_one()` 返回后才写 `results.jsonl`，于是表现为“任务跑完了但没有结果记录”。

实际这批 20 条汇总结果中：

- 每任务记录到的候选最多 10 个；
- 真正可提交（`submittable=true`）的候选最多 4 个，常见 1–2 个；
- 其余大量文件是 `seeds/`、`fuzzcorpus*/`、`hf_out*/` 等 fuzz 语料。

因此可以不追求“全量快照”，而是设一个足够宽松、但能防止无限遍历的上限。

---

## 2. 目标与非目标

### 2.1 目标

1. 给 attempt 快照复制设置**文件数**和**总字节数**上限，避免小文件海洋拖住 worker。
2. 给诊断用的目录扫描设置同样的上限，避免逐个哈希十万级语料。
3. `bundle.json` / `manifest.json` 是续跑和提交的可信来源，**始终复制**，不受上限影响。
4. 超限时必须可观测：批次日志、`attempt.json`、`results.jsonl` 都要留下记录。
5. 上限可配置；`0` 表示不限制，保留需要全量归档的场景。

### 2.2 非目标

- 不按目录名硬编码过滤 `seeds/`、`fuzzcorpus/` 等语料目录；这些目录里仍可能有
  真实候选或控制文件，名称过滤容易误伤。
- 不改变 Replay 校验、提交、投票、`solved` / `no_crash` 判定逻辑。
- 不改变运行中批次的已加载代码；新上限只对之后启动的 runner 生效。
- 不优化 `reset_poc_for_run()` 的全量归档（见 §6 后续项）。

---

## 3. 设计

### 3.1 归档复制上限

`_copy_poc_tree()` 改为：

1. 枚举 `task/poc` 下所有文件；
2. 按以下优先级排序：
   - `bundle.json` / `manifest.json`（最高）；
   - 路径层级越浅越优先；
   - 同层按路径字典序；
3. 逐个复制，直到达到文件数或字节数上限；
4. 元数据文件不受上限限制，始终复制；
5. 返回统计：

```json
{
  "files_total": 36002,
  "files_copied": 200,
  "bytes_copied": 123456,
  "files_skipped": 35802,
  "limit_hit": true,
  "max_files": 200,
  "max_bytes": 52428800
}
```

上限只影响 `artifacts/attempt-N/poc` 这份审计快照；原始 `task/poc` 不动，提交阶段
仍然直接使用原始候选文件。`restore_attempt_candidates()` 原本就会检查快照文件是否存在，
因此被上限跳过的文件不会被错误恢复，也不会影响本轮提交。

### 3.2 诊断扫描上限

`collect_pocs()` 的第 5 步（目录扫描）只用于诊断，产出的候选 `submittable=false`，
不进入提交队列。因此对它限流是安全的：

- 先按“浅层优先”排序；
- 超过文件数或字节数上限后不再 `stat()` / `sha256()`；
- 在 `bundle_notes.scan_limit_hit` 记录 `scanned` / `skipped` 数量。

`bundle`、`manifest`、`evidence_refs`、`payload` 等结构化来源在扫描之前已经处理，
不受扫描上限影响。

### 3.3 默认值与配置

| 变量 | 默认值 | 含义 |
|---|---:|---|
| `POC_ARCHIVE_MAX_FILES` | 200 | attempt 快照最多复制多少个数据文件；`0` = 不限 |
| `POC_ARCHIVE_MAX_MB` | 50 | attempt 快照最多复制多少 MB；`0` = 不限 |
| `POC_SCAN_MAX_FILES` | 500 | 诊断扫描最多读取多少个文件；`0` = 不限 |
| `POC_SCAN_MAX_MB` | 20 | 诊断扫描最多读取多少 MB；`0` = 不限 |

配置位置：

- `deploy/.env` / `deploy/.env.example`
- `deploy/compose.batch.yaml` 的 `x-batch-common.environment`
- `deploy/README.md` 的跑批参数说明

### 3.4 可观测性

超限时有三层记录：

1. **批次日志**（`docker logs`）：

   ```text
   [arvo_66502] poc 快照达到上限：复制 200/36002 个文件，跳过 35802 个（原 task/poc 未动）
   [arvo_63157] 诊断扫描达到上限：扫描 500 个，跳过 10123 个
   ```

2. **`artifacts/attempt-N/attempt.json`**：

   ```json
   "poc_copy": {
     "files_total": 36002,
     "files_copied": 200,
     "bytes_copied": 123456,
     "files_skipped": 35802,
     "limit_hit": true,
     "max_files": 200,
     "max_bytes": 52428800
   }
   ```

3. **`results.jsonl`**：`run_one()` 把同一个 `record` 传给 `seal_attempt()`，
   因此每条任务结果也会带 `poc_copy`；扫描超限则出现在
   `bundle_notes.scan_limit_hit`：

   ```json
   "bundle_notes": {
     "scan_limit_hit": ["scanned=500 skipped=10123"]
   }
   ```

### 3.5 与失败任务排查的关系

这批任务里有 3 个 `bundle_invalid` 卡在 `missing_poc_mount`（`62261` / `62183` / `66679`），
另有若干 `no_crash`。限流只影响快照和诊断扫描，不会改变这些任务的判定；但能让
任务更快落账，避免误以为 worker 卡死。

---

## 4. 实现位置

`deploy/cybergym_batch.py`：

- 顶部常量：`POC_ARCHIVE_MAX_FILES` / `POC_ARCHIVE_MAX_MB` / `POC_SCAN_MAX_FILES` / `POC_SCAN_MAX_MB`；
- `_env_int()`：读取环境变量，非法值回退默认值，`0` 保留为“不限制”；
- `_copy_poc_tree()`：排序、上限、元数据豁免、复制统计；
- `seal_attempt()`：接收 `record` 参数，把 `poc_copy` 写进 `attempt.json` 和任务记录；
  超限时打日志；
- `run_one()`：首次和重试的 `seal_attempt()` 调用都传入 `record`；
- `collect_pocs()`：第 5 步目录扫描按文件数/字节数限流，超限打日志并写 `notes`。

配置与文档：

- `deploy/.env`、`deploy/.env.example`
- `deploy/compose.batch.yaml`
- `deploy/README.md`

测试：

- `deploy/tests/test_attempt_artifacts.py`
  - 文件数上限；
  - 字节数上限；
  - 达到上限时元数据仍复制；
  - `poc_copy` 写入 `record`；
- `deploy/tests/test_bundle_candidates.py`
  - 诊断扫描上限与 `scan_limit_hit`。

---

## 5. 验证

- `test_attempt_artifacts` + `test_bundle_candidates` + `test_resume`：67 项全部通过。
- `py_compile deploy/cybergym_batch.py` 通过；`git diff --check` 无空白问题。
- `docker compose config` 确认四个变量已传入容器：
  `POC_ARCHIVE_MAX_FILES=200`、`POC_ARCHIVE_MAX_MB=50`、
  `POC_SCAN_MAX_FILES=500`、`POC_SCAN_MAX_MB=20`。
- 完整测试集仍有 1 个环境相关 error：`test_crash_hint` 读取固定的 Windows 路径
  `C:\CodeWork\cybergym\...\error.txt`，在 Linux 容器里不存在；与本次改动无关。

---

## 6. 风险与后续

1. **可能漏归档深层目录里的候选**：排序是浅层优先，深度很大的候选可能被跳过；
   但 `bundle.json` / `manifest.json` 始终复制，且原始 `task/poc` 不被删除，
   提交仍使用原始文件。需要完整审计时可把上限设为 `0`。
2. **仍会复制部分 seeds / fuzz 语料**：当前没有按目录名过滤，只是按上限截断。
   如果希望完全跳过语料目录，需要额外实现 skip list，并处理“候选恰好位于语料目录”
   的情况；这次没有做。
3. **`reset_poc_for_run()` 仍全量复制**：它在新一轮开始前把旧 `task/poc` 拷到
   `artifacts/orphan-poc-*`，本次未改。若旧语料很大，下一轮启动仍可能慢；
   后续可改成同文件系统 rename，或复用同一套上限。
4. **运行中的批次不会热加载**：当前批次仍执行旧逻辑；新上限只影响重启后的 runner。
5. **9p 性能仍是主因**：上限只是把最坏情况限制在有限文件数内，不能改变小文件 I/O 慢的事实。

---

## 7. 相关文档

- `docs/cybergym-replay-validation-design.md`
- `docs/cybergym-failure-governance-design.md`
- `docs/cybergym-crash-hint-design.md`
- `docs/task-resume-design.md`
