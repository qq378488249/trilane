# S5 PoC bundle 字段与提交来源设计

## 1. 背景与目标

`docs/cybergym-failure-governance-design.md` 定义了从 S5 `POC%` 行生成 `out/bundle.json`、
由批次 runner 读取并调用官方 `/submit-vul` 的链路。实际跑批（arvo26 批次）暴露出
四类“找对了但交不出去”的问题：

1. **字段被截断**：`POC%` 的 detail 以 700 字符截断，`file/role/sha256/observed_exit`
   排在长文本字段之后，`target=` 很长时字段整段丢失。
2. **字段口径不一致**：agent 写 `role=positive-poc`、`observed_exit=exit=1`、只写 replay
   里的 `-v <path>:/tmp/poc` 而不写 `file=`，runner 无法消费；agent 声明的 sha256
   与实际文件不一致时被当作硬错误。
3. **诊断回退污染提交**：bundle 判 invalid 后，runner 仍按 `evidence_refs` / `payload` /
   目录扫描挑候选，交出 `.log`、`evidence.md`、corpus，结果是 `no_crash`。
4. **续跑丢元数据**：attempt 恢复只拷候选文件，`bundle.json` / `manifest.json` 没恢复，
   续跑后所有候选退化成不可提交的 scan 记录。

对应提交：`74693e2`（Fix S5 bundle fields and stop diagnostic fallback）、
`e995812`（Lock the new sha2 dependency for trilane-gui）。

本次目标：

- 把 S5 bundle 定义成**结构化契约**：字段顺序、词表、派生规则、必填条件固定；
- 缺字段时给 S5 **一次显式修复**机会，但不因字段问题阻断整条流程；
- runner **只提交 bundle / manifest 声明的候选**，诊断来源永不进入提交队列；
- 把本地一致性检查分成硬错误与警告，官方 verifier 仍是唯一成功权威。

非目标：

- 不改变 `/submit-vul` 的权威地位与投票/裁定逻辑；
- 不把 fix 侧信息回写 agent 任务包（沿用 `docs/cybergym-failure-governance-design.md` §3）；
- 不改变验证状态模型（沿用该文档 §4）；
- 不重写 S5 的质量裁决语义（合并/降级的判断规则不变）。

---

## 2. 现状链路

```
S5 POC% 行
  → RunbookState.record_agent_message() 解析成 RunbookFinding.detail（截断到 700 字符）
  → RunbookState.poc_bundle() 生成 out/task/poc/bundle.json
  → runner collect_pocs() 读取 bundle → manifest → evidence_refs → payload → scan
  → validate_candidate() 本地校验 → /submit-vul 投票 → results.jsonl
```

旧行为的问题点：

| 环节 | 旧行为 | 后果 |
|---|---|---|
| detail 顺序 | 机器字段在 `target/expected/...` 之后 | 长文本截断后 `file`/`observed_exit` 丢失 |
| role | 直接抄 agent 原文 | `positive-poc` 等写法不在 runner `VALID_ROLES` 中 |
| file | 只认 `file=` | replay 有挂载但没写 `file=` 的候选被判 missing |
| sha256 | 只认声明值；不一致即 invalid | 算错哈希的可用 PoC 被拒绝（arvo:63163） |
| observed_exit | verified 候选缺字段即 invalid | arvo:58364/62388/63163 被误判 |
| 挂载检查 | 只看第一个 `-v` | tracer 挂在前、PoC 挂在后时误报 `missing_poc_mount`（arvo:62183） |
| 提交队列 | 所有候选一视同仁 | bundle invalid 后提交日志/corpus |
| resume | 只恢复候选文件 | bundle/manifest 丢失，候选全部不可提交 |

---

## 3. 设计

### 3.1 S5 输出契约

`workflow_phases.inc.rs` 的 S5 contract/body 与 `workflow_prompts.inc.rs` 明确要求：
当 replay 是容器化 fuzz 命令（含 `-v <path>:/tmp/poc`）时，`POC%` 行必须在长文本字段
**之前**输出机器字段：

```
file=<task workspace 下的路径，优先 poc/<name>>
role=<final_candidate|candidate|diagnostic|negative_control|scan_unknown>
observed_exit=<账本里实际记录的整数退出码，不得由 expected= 推断>
sha256=<已知时给 hex，未知则省略>
family=<arvo|oss-fuzz>
```

`final_candidate` 只由 agent 显式声明：引擎**不自动**把第一个候选提升为 final，
因为引擎输出顺序不等于最优顺序（arvo:58364 的第二个候选才是官方入口）。

S5 final revision 与 advisory review lane 的提示词同样要求保留这些字段：
替换行必须继承草稿行的 `file/role/observed_exit/sha256/family`，容器化行不得在修订时
丢掉 `observed_exit`。review lane 收到结构化的 `S5_BUNDLE_JSON`，可直接指出
字段缺失或 replay 不可复制，而不必猜测文本行。

### 3.2 解析与规范化（引擎侧）

`runbook_helpers.inc.rs` 新增 helper，原则是**只做清洗与可验证派生，不猜值**：

| helper | 规则 |
|---|---|
| `clean_bundle_value` | 去引号/反引号；`none/null/n/a/na/-/unknown/tbd` 视为空 |
| `normalize_bundle_role` | 小写、`_`→`-`，同义词收敛到 runner 词表：`final/final-candidate`→`final_candidate`；`poc/positive`→`candidate`；`generated-not-verified`→`diagnostic`；`negative/control`→`negative_control`；`scan`→`scan_unknown`；未知返回空 |
| `parse_observed_exit` | 接受 `1`、`exit=1`、`rc=1`；只取整数，失败返回空 |
| `poc_file_from_replay` | 逐个 token 解析 `-v`/`--volume=` 的 `host:/tmp/poc`，取 host 路径 |
| `bundle_file_from_detail` | 优先 `file=`，缺失时从 replay 挂载反推 |
| `is_container_poc_replay` | 仅含 `:/tmp/poc` 或 ` /tmp/poc` 的 replay 才要求机器字段（web/curl 任务不受影响） |

`marker_value()` 的键表补上 `signal=`、`control=`、`size=`，避免 agent 常见的
`signal=... control=...` 被吞进前一个字段（arvo:62388 的 replay 出现过）。

`POC%` detail 的字段顺序改为：

```
POC_ENTRY
poc_id
file
role
sha256
observed_exit
family
category / target / precondition / expected / impact / verification / cleanup / evidence_refs
```

机器字段在 700 字符截断之前，长文本字段即使被截断也不影响 bundle。

`poc_bundle(workspace)`（`runbook_lifecycle.inc.rs`）：

- `file`：`file=` 优先，否则从 replay 反推；
- `sha256`：用 `workspace` 解析相对路径后读盘算 SHA-256；拿不到工作区时保留声明值，
  由 runner 以实际文件重算。为此 `trilane-gui` 增加 workspace 级 `sha2` 依赖，
  并在 `Cargo.lock` 中锁定（`e995812`），保证 `--locked` 构建可用；
- `role`：规范化后为空时，按验证状态兜底——verified 且有文件 → `candidate`，
  否则 → `diagnostic`；
- `verification`：优先 POC 声明，缺失时取 finding 的 evidence_state；
- `observed_exit`：用 `parse_observed_exit` 转整数；
- 来源集合：优先 `stage5_poc_entries`，否则取 `stage5` findings（抽成 `s5_bundle_source()`，
  与 schema 检查共用同一口径）。

### 3.3 缺字段时的一次修复

`poc_bundle_schema_issues()` 只对容器化候选做最低检查：

- `file` 为空（既无 `file=` 也无 `/tmp/poc` 挂载）；
- `role` 为空；
- verification 为 verified 但 `observed_exit` 无法解析。

`workflow_core.inc.rs` 在 `S5Adjudicate` / `S5FinalRevision` 阶段：若阶段输出已满足、
但 schema issues 非空且当前阶段修复次数未用尽，则**发起一次 repair**（`submit_current(state, true)`），
修复指令要求从已有行/账本补齐字段，而不是删行。次数用尽后仍放行——
字段不全不该阻断整条流程，最终由 runner 的真实差分回放判定。
headless 模式把 issues 打到 stderr，`results.json` 侧可观测。

### 3.4 runner 侧：可提交来源与校验分级

`PocCandidate` 增加 `submittable: bool`（默认 True）。`collect_pocs()` 的来源语义：

| 来源 | submittable | 用途 |
|---|---|---|
| `bundle.json` / `manifest.json` | 是 | 唯一提交队列 |
| `evidence_refs` | 否 | 诊断/审计 |
| `payload` 兼容解析 | 否 | 诊断/审计 |
| 目录扫描 | 否 | 诊断/审计 |

`validate_candidate()` 返回 `(issues, warnings)`：

- **硬错误（不提交）**：文件不存在、缺 replay、`missing_poc_mount`、
  arvo 缺 `/bin/arvo`、oss-fuzz 误用 `/bin/arvo`；
- **警告（继续提交并记录）**：`sha256_mismatch`（以实际文件哈希为准）、
  `missing_observed_exit`（官方 verifier 本来就会在 vul/fix 两侧真实重跑）。

`_mount_values()` 按出现顺序取**所有** `-v/--volume`，`_has_poc_mount()` 逐一检查容器目标；
`_candidate_path()` 剥掉 `$PWD/`、`${PWD}/`、`./` 等壳前缀，按 `task/` 与 task root
两级解析，解决 `cd task && docker run -v $PWD/poc/x.bin:/tmp/poc` 定位失败。

提交循环只用 `queue_all = [c for c in candidates if c.submittable]`：

- bundle 存在但没有可提交候选 → `status=bundle_invalid`，`submissions=[]`，
  诊断候选写入 `diagnostic_only`，绝不提交日志或 corpus；
- 没有 bundle/manifest 且只有诊断候选 → `status=no_poc`，`submissions=[]`；
- 提交记录与 attempt 快照的候选记录都带 `submittable`；warning 进入
  `submissions[*].warnings` / `invalid[*].warnings`。

### 3.5 续跑恢复

`restore_attempt_candidates()` 除候选二进制外，还从最新 attempt 快照的
`poc/` 恢复 `bundle.json` 与 `manifest.json`（目标已存在则不覆盖）。
只恢复二进制会让续跑后的候选全部变成不可提交的 scan 记录。

### 3.6 数据流

```
S5 POC%（机器字段前置）
  ├─ detail 解析 / 规范化 / 读盘 sha256 → bundle.json
  ├─ schema issues → 一次 repair → 重新输出 POC%
  └─ S5_BUNDLE_JSON → advisory review lane → 修订 POC%
                          ↓
runner collect_pocs()：bundle/manifest → submittable=True
                      evidence_refs/payload/scan → 诊断
       ↓
validate_candidate()：硬错误拦截 / 警告放行 → /submit-vul
       ↓
results.jsonl（status / submissions[].warnings / diagnostic_only）
```

---

## 4. 测试覆盖

- `deploy/tests/test_bundle_candidates.py`：
  - `submittable` 标记（scan/payload/evidence_refs 为 False，bundle 为 True）；
  - `$PWD` 前缀路径解析；resume 恢复 bundle/manifest；
  - bundle invalid 时不提交诊断文件（ExplodingClient 断言）；
  - sha256 不一致、缺 `observed_exit` 仍提交并记 warning；
  - 所有挂载都检查（tracer 在前、PoC 在后）；
  - 多挂载 / ARVO 入口 / oss-fuzz 入口的硬错误与警告划分。
- `runbook_tests.inc.rs`：
  - 900 字符 `target=` 下字段仍完整（截断回归）；
  - verified 缺 `observed_exit` 被 schema 检查标出；
  - web/curl replay 不受容器化字段约束。

---

## 5. 兼容性与回滚

- `bundle.json` 仍与 `manifest.json` 共存，旧任务不会被新代码拒绝；
- role 词表扩展了同义词，旧 bundle 中的合法 role 不变；
- `validate_candidate()` 返回值从 `list[str]` 改为 `(issues, warnings)`，
  调用方需同步更新；测试已覆盖。
- 回滚路径：恢复 `74693e2` 前的 `cybergym_batch.py` 与 `trilane-gui/src/*`，
  并保留 `e995812` 的 lockfile 条目（无害）。回滚后会重新出现诊断回退与截断问题。

## 6. 风险与取舍

1. **一次 repair 仍可能修不好**：次数用尽后放行，由官方 verifier 兜底；
   代价是少量任务会因字段缺失进入 `bundle_invalid`，而不是更早失败。
2. **sha256 读盘计算需要 workspace**：headless 未传工作区时保留声明值，
   由 runner 以真实文件重算；因此声明哈希错误只是警告，而非硬错误。
3. **不自动提升 `final_candidate`**：避免引擎顺序误判最优候选；
   代价是更多任务依赖 agent 显式声明 role。
4. **诊断候选不再提交**：牺牲了“万一日志恰好是 PoC”的偶发收益，
   换取不再把 `.log`/corpus 当 PoC 交给官方 verifier。

## 7. 参考

- `docs/cybergym-failure-governance-design.md` §5.1（runner 链路）、§5.2.1（S5 结构化输出）
- `deploy/README.md` 的 final-submission 排序与校验段
- `docs/cybergym-crash-hint-design.md`（同类“派生信息 + 可观测 + 可关闭”的边界处理）
- 相关提交：`74693e2`、`e995812`
