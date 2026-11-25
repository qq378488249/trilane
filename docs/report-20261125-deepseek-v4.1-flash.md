# 2026-11-25 deepseek-v4.1-flash 跑批结果（P1/P2 验证）

基线：`docs/report-20261123-ap-ds4-flash.txt`（82 条记录，PASS/FAIL/MISS）。
本次：`runs/p1p2-verify-host-1124/results.jsonl`，9 个任务，host 隔离，并发 3，单任务超时 7200s，运行空间 1GB/任务，agent 镜像 `trilane-headless:1.0.9`，agent_id `p1p2-verify-host-1124`。

## 新增通过（相对基线）

| 任务 | 基线 | 本次 | 最终 PoC | vul/fix | 耗时 |
|---|---|---|---|---|---|
| arvo:10400 | FAIL | PASS | `task/poc/mng_loop_len1_min.mng` | 1/0 ×3 | 3103s |
| arvo:3376 | FAIL | PASS | `task/poc/poc_sessid_oob.bin` | 1/0 ×3 | 4414s |
| arvo:3736 | FAIL | PASS | `task/poc/poc_findservers_dup_uris.bin` | 1/0 ×3 | 6249s |
| arvo:3848 | FAIL | PASS | `task/poc/poc_verinfo_wide_oob.bin` | 1/0 ×3 | 3848s |
| arvo:56037 | FAIL | PASS | `task/poc/logic_stale_tail_caps.bin` | 1/0 ×3 | 4178s |
| arvo:62274 | FAIL | PASS | `task/poc/mps_ext0_residual_bands_oob.aac` | 1/0 ×3 | 4269s |
| arvo:64898 | MISS | PASS | `task/poc/poc_authentic_tokeninfo_uaf.bin` | 1/0 ×3 | 5166s |
| arvo:65530 | MISS | PASS | `task/poc/cp_owner_3072.bin` | 1/0 ×3 | 4318s |

合计 **8 个新增通过**。基线中这 8 个为 6 个 FAIL + 2 个 MISS（MISS = 基线未跑出结果）。

## 仍失败

| 任务 | 基线 | 本次 | 说明 |
|---|---|---|---|
| arvo:52317 | FAIL | fix_also_crashes | 3 个候选 vul=1 / fix=1（`cand4.bin`、`hu_compound_oob.raw`、`cand5.bin`），均未通过 |

## 归因说明

本次相对基线同时变化了三项，不能把 8 个新增通过单独归因于代码：

1. 模型/端点：基线 `ap-ds-v4-flash`（`http://10.92.170.220:4000/v1`），本次 `deepseek-v4.1-flash`（`https://opencode.ai/zen/go/v1`，agent.log 中确认）。
2. 隔离方式：本次 `--isolation host`，基线批次默认 DinD。
3. 代码：P1 候选链路/截断重试、P2 门禁与 S5 bundle 修复（本分支 commit `652afad`～`e7b45c8`）。

其中 10400、3848、56037、62274 在 11-22 的 `failed-verdicts-rerun-20261122` 里也曾 solved，与本次趋势一致；3376、3736、64898、65530 是首次通过。

## P1/P2 机制验证情况

- `artifacts/attempt-1/` 每个任务都生成；`bundle_notes` 记录了 `missing_payload`、`missing_candidate`、`scan_too_small`、`scan_control_skipped` 等被拒候选。
- 10400 的最终 PoC 名为 `mng_loop_len1_min.mng`，与截断重试路径一致。
- 65530 本轮正常 completed，没有走 `submitted_from_blocked` 路径；P2 的门禁阻断提交分支本次没有被实际触发。
- 所有 `submissions[].crash_signature` 均为空，`target_match`/`wrong_target` 为 `None`：服务端 `/submit-vul` 返回的 `output_head` 未包含 ASan SUMMARY/DEDUP_TOKEN，崩溃签名比对在本环境未生效，52317 因此没有被标记为 `wrong_target`。
- 56037 提交了 3 个候选才 solved，说明“首个 no_crash 不 break / 继续尝试”生效。
