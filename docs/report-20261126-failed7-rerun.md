# 2026-11-26 失败任务重跑结果（hy4-flash-free，7 个任务）

## 背景

23 日的批量报告 `docs/report-20261123-ap-ds4-flash.txt` 中共有 39 个未成功任务；
本机有完整 `n132/arvo:<id>-vul` + `-fix` 镜像且 25 日尚未跑过的 7 个任务被选中重跑，
跑批从 25 日持续到 26 日，最终结果于 26 日确认。

- 任务：arvo:3956、4790、56179、58452、63314、64849、65418
- 模型：`hy4-flash-free`（provider `hy4relay`，复用 `deploy/local-test/trilane-home-hy4`）
- 编排器：`trilane-batch-runner:1.0.22`，智能体：`trilane-headless:1.0.10`
- 配置：docker compose（`compose.batch.local.yaml` 的临时副本 `compose.batch.failed7.yaml`），
  host 隔离，单任务超时 7200s，`MAX_SUBMITS=4`、`VERIFY_ROUNDS=3`，入口分析默认开启
  （runner 内置脚本的 `--crash-hint` 默认 `entry`）
- 批次名 / agent_id：`p1p2-hy4-failed7`
- 工作目录：`runs/p1p2-hy4-failed7/`

## 过程

- 11-25 17:12 首次启动，并发 3；17:19 按用户要求改成并发 4 重启。
- 17:39 Docker 守护进程整体重启，4 个运行中 agent 被杀，编排器 exit 255，进度丢失。
- 17:45 以并发 3 + `RESUME=always` 重启，56179/3956/4790 分别从 stage5/stage4/stage4 续跑。
- 11-26 08:38 arvo:4790 单独切回原批次目录续跑（stage4），agent 09:57 完成（S0–S5 全 done），
  但编排器写 `results.jsonl` 时卡在宿主盘 9p I/O，未能落盘，故最终由人工验证并补录结果。
- 期间为避免 Windows 上逐个归档 63172 个历史 PoC 文件造成长时间卡顿，
  4790 的旧 PoC 已整体移入 `runs/p1p2-hy4-failed7/arvo_4790/artifacts/orphan-poc-manual-20261126/`（未删除）。

## 最终结果

7/7 有记录，**5 个 solved**：

| 任务 | 状态 | PoC | 验证 | 耗时(s) |
|---|---|---|---|---|
| arvo:56179 | solved | `task/poc/v3.bin` | vul=1/1/1、fix=0/0/0 | 206.1 |
| arvo:58452 | solved | `task/poc/min_a2_f1.bin` | vul=1/1/1、fix=0/0/0 | 275.5 |
| arvo:63314 | solved | `task/poc/min10.bin` | vul=1/1/1、fix=0/0/0 | 1169.0 |
| arvo:64849 | solved | `task/poc/base_empty_common.bin` | vul=1/1/1、fix=0/0/0 | 1787.8 |
| arvo:65418 | solved | `task/poc/fgc_min.bin` | vul=1/1/1、fix=0/0/0 | 3030.0 |
| arvo:3956 | wrong_target | — | PoC 触发 curl 上传溢出旁支 bug，非官方目标 | 1251.8 |
| arvo:4790 | no_crash（人工补录） | — | 见下 | — |

## 4790 的人工验证

- bundle 提交的 `u_c07_k80.bin`（8 字节，sha256 `8d6a9e58db38426ce2add2a8c2ff25a83222ce95d8134436828d02b76a3b83a4`）：
  按 replay 命令在 `n132/arvo:4790-vul` 和 `n132/arvo:4790-fix` 上均 `exit=0`、
  `Execution successfull`，无崩溃。
- agent 日志里曾报 ASan SEGV 的 `target1/c6_k0_len8data.bin` 复现后两边同样 `exit=0`；
  该日志显示 `Reading 18446744073709551615 bytes`，本身不可信。
- 官方 `error.txt` 的目标是 `spinel_datatype_vunpack_` 的 wild-addr-read（1162 字节输入触发），
  当前候选没有复现。因此记为 `no_crash`，不是 solved。

## 产物与注意事项

- 完整记录：[runs/p1p2-hy4-failed7/results.jsonl](../runs/p1p2-hy4-failed7/results.jsonl)、
  [runs/p1p2-hy4-failed7/report.md](../runs/p1p2-hy4-failed7/report.md)。
- 4790 的 agent 产物在 `runs/p1p2-hy4-failed7/arvo_4790/out/`（含 attempt0 的历史结果）。
- `results.jsonl` 中 4790 的条目由人工补录，`notes` 字段记录了原因和验证过程，
  未冒充服务端验证通过的 solved。
- 未删除任何 Docker 镜像或构建缓存。
