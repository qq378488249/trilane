# 2026-11-25 hy4-flash-free 跑批结果（P1/P2 验证，docker compose）

模型：`hy4-flash-free`（provider `hy4relay`，`https://opencode.ai/inference/go/openai/v1`），
来自 `deploy/local-test/trilane-home-hy4/config.toml` + `secrets.toml`。每个任务的
`agent.log` 都只出现 `hy4-flash-free`，没有 deepseek / ap-ds 模型名。

## 批次一：8 个任务（p1p2-verify-hy4-compose）

运行方式：`docker compose --env-file .env.p1p2-hy4 -f compose.batch.local.yaml up -d batch`，
容器 `trilane-batch-p1p2-hy4`，host 隔离，并发 3，单任务超时 7200s，运行空间 1GB/任务，
agent 镜像 `trilane-headless:1.0.9`。工作目录 `runs/p1p2-verify-hy4-compose`。

| 任务 | 状态 | attempts | 耗时 | 最终 PoC / 备注 |
|---|---|---|---|---|
| arvo:10400 | solved | 1 | 912s | `task/poc/loop_short_oob.bin` |
| arvo:3736 | solved | 1 | 379s | `task/poc/min/nohel.bin` |
| arvo:3376 | solved | 2 | 230s | `task/poc/poc_main.bin`（第 2 次 stage5 续跑后） |
| arvo:3848 | fix_also_crashes | 1 | 511s | 3 轮 vul=1 / fix=1 |
| arvo:56037 | no_crash | 1 | 3605s | 未交出有效 PoC |
| arvo:64898 | no_crash | 1 | 5098s | 未交出有效 PoC |
| arvo:62274 | no_crash | 1 | 6840s | 未交出有效 PoC |
| arvo:65530 | agent_failed | 2 | 679s | `TRILANE produced provisional S2/S3 findings but never emitted RUNBOOK% S5 Verify` |

汇总：**3 solved / 1 fix_also_crashes / 3 no_crash / 1 agent_failed**。

该批次中途被别的会话停掉过一次（compose 编排器容器消失，但 agent 容器仍在），随后做了续跑：
任务清单去掉已 solved 的 10400，剩 7 个；`RESUME=always`、`AGENT_RETRIES=1`；3376 和
65530 都走了 stage5 续跑，因此不是一次干净的完整运行。共享的 `compose.batch.yaml`
被另一会话加了本分支不支持的 `--crash-hint` 参数，本次用临时副本
`deploy/compose.batch.local.yaml` 去掉该参数并加了 `--min-free-gb 1`，没有修改共享文件。

## 批次二：5 个失败任务重跑（p1p2-hy4-failed5）

把批次一未通过的 5 个任务（3848、56037、64898、62274、65530）用同一个 hy4 模型、
`trilane-headless:1.0.9` 重跑一次。并发 **4**，host 隔离，超时 7200s，运行空间 1GB/任务，
runner `trilane-batch-runner:1.0.22`，`RESUME=off`、`MAX_SUBMITS=4`。
编排器容器 `trilane-batch-p1p2-failed5`，工作目录 `runs/p1p2-hy4-failed5`。

| 任务 | agent_status | 状态 | attempts | 耗时 | 最终 PoC / 备注 |
|---|---|---|---|---|---|
| arvo:3848 | completed | fix_also_crashes | 1 | 1041s | vul=1 / fix=1，仍提交 `pe_parse_exports` 旁支 bug |
| arvo:65530 | completed | solved | 1 | 1394s | `task/poc/mut-keybits-3072` |
| arvo:64898 | completed | solved | 1 | 2833s | `task/poc/authentic_tokeninfo_uaf.bin` |
| arvo:56037 | completed | fix_also_crashes | 1 | 2402s | vul=1 / fix=1，未交出差分 PoC |
| arvo:62274 | timeout | agent_failed | 1 | 7213s | `workflow did not finish within 7200s` |

汇总：**2 solved / 2 fix_also_crashes / 1 agent_failed**。

## 与 deepseek-v4.1-flash 同任务对比

| 模型 / 批次 | 结果 |
|---|---|
| deepseek-v4.1-flash（直接 Python 跑批，host 模式） | 8/8 solved |
| hy4-flash-free 批次一（8 个任务） | 3 solved / 5 未通过 |
| hy4-flash-free 批次二（5 个失败任务重跑） | 2 solved / 3 未通过 |

对应文档：`docs/report-20261125-deepseek-v4.1-flash.md`。

## 结论

- hy4-flash-free 在批次一里只解出 10400/3736/3376；批次二重跑又解出 64898/65530。
- 3848 两次都提交 `pe_parse_exports`（pe.c:1019）旁支 bug。日志显示它看到了官方入口
  `wide_string_fits_in_pe`，但以“所有调用点都有 guard、路径不可达”为由 REJECTED，
  随后因为另一个候选“simplest”且有 ASan 正控而过早收敛。
- 56037 两次都未交出差分 PoC；批次二变成 fix_also_crashes。
- 62274 批次二撞 7200s 墙钟；agent 镜像实际是 `trilane-headless:1.0.9`
  （中途曾用 `20261124` tag 启动一次，随即停掉并改回 1.0.9）。
- 这些都是模型/运行稳定性差异，不是 P1/P2 代码回退：批次二用的脚本和镜像与
  deepseek 批次一致，只是模型和 runner 镜像 tag 不同。

完整记录：`runs/p1p2-verify-hy4-compose/results.jsonl`、`runs/p1p2-hy4-failed5/results.jsonl`
及各批次 `report.md`。
